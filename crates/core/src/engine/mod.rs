//! The per-packet security pipeline.
//!
//! [`Engine`] owns every security subsystem and decides what happens to
//! each received frame. It performs no I/O of its own: replies, alerts and
//! telemetry leave through the caller's [`PacketSink`], and time comes in
//! as an argument. That keeps the whole pipeline runnable, testable and
//! fuzzable on the host.

mod report;

use crate::config::{
    DDOS_ALERT_SAMPLE_RATE, DEFAULT_BLOCKED_PORT, FLOW_LOG_SAMPLE_MASK, HEAVY_HITTER_THRESHOLD,
    IP_ADDR, IP_BAN_DURATION_CYCLES, MANAGEMENT_PORT, MAX_BPF_PROGRAM_SIZE, RATE_LIMIT_PPS,
    TOKEN_BUCKET_CAPACITY,
};
use crate::net::PacketSink;
use crate::net::constants::{IpProtocol, arp, ethernet, ipv4, tcp};
use crate::net::stack::{SynCookieSecret, process_packet};
use crate::net::tcp::TcpHeader;
use crate::security::alert::{AlertMeta, AlertReason, should_emit_ddos_alert};
use crate::security::mgmt::{ManagementMessageType, mgmt_packet};
use crate::security::vm::{Instruction, VM, VmAction, VmRuntimeError};
use crate::security::{dos, dpi, firewall, flow, heuristic, mgmt_auth, vm};

pub use report::{ALERT_FRAME_LEN, TELEMETRY_FRAME_LEN};

/// Where alerts and telemetry are sent once an operator has authenticated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OperatorAddr {
    /// Operator's Ethernet address.
    pub mac: [u8; 6],
    /// Operator's IPv4 address.
    pub ip: [u8; 4],
}

/// Per-boot secrets the engine needs before it processes traffic.
#[derive(Debug)]
pub struct BootSecrets {
    /// Keys the SYN-cookie PRF.
    pub syn_cookie: SynCookieSecret,
    /// Salts the heavy-hitter sketch.
    pub cms_seed: u64,
    /// High 32 bits of every accepted mgmt counter for this boot.
    pub mgmt_epoch: u32,
}

/// Counters for the current telemetry interval.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct IntervalStats {
    /// Frames addressed to this host (IPv4 to our address, or ARP for it).
    pub received_for_us: u64,
    /// User packets that cleared every check.
    pub passed: u64,
    /// Drops from the penalty box, heavy-hitter sketch or rate limiter.
    pub ddos: u64,
    /// Drops from the port firewall.
    pub firewall: u64,
    /// DPI signature matches.
    pub malware: u64,
    /// Drops by the installed BPF program.
    pub ebpf: u64,
    /// Heuristic anomalies.
    pub heuristic: u64,
    /// Mgmt-plane packets, authenticated or not.
    pub mgmt: u64,
}

impl IntervalStats {
    /// Total drops of every kind this interval.
    pub const fn drops(&self) -> u64 {
        self.ddos + self.firewall + self.malware + self.ebpf + self.heuristic
    }
}

/// What the engine did with one frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Cleared every check.
    Passed,
    /// Dropped by a security check; the reason matches the alert raised.
    Dropped(AlertReason),
    /// Addressed to the mgmt port.
    Management,
    /// Answered by the network stack, or carried no inspectable payload.
    Consumed,
}

/// The installed BPF filter.
#[derive(Debug)]
struct BpfSlot {
    program: [Instruction; MAX_BPF_PROGRAM_SIZE],
    len: usize,
}

/// Every security subsystem, plus the state the pipeline carries between
/// packets.
#[derive(Debug)]
pub struct Engine {
    ac: dpi::AhoCorasick,
    dyn_rules: dpi::DynamicRules,
    fw: firewall::FirewallState,
    cms: dos::CountMinSketch,
    pbox: dos::PenaltyBox,
    limiter: dos::TokenBucket,
    vm: VM,
    bpf: BpfSlot,
    flows: flow::FlowTable,
    mgmt_auth: mgmt_auth::MgmtAuth,
    operator: Option<OperatorAddr>,
    syn_secret: SynCookieSecret,
    stats: IntervalStats,
}

impl Engine {
    /// Creates an engine whose mgmt plane verifies with `mgmt_key`.
    ///
    /// [`Self::init`] must run before the first packet.
    pub const fn new(mgmt_key: [u8; 16]) -> Self {
        Self {
            ac: dpi::AhoCorasick::new(),
            dyn_rules: dpi::DynamicRules::new(),
            fw: firewall::FirewallState::new(),
            cms: dos::CountMinSketch::new(),
            pbox: dos::PenaltyBox::new(),
            limiter: dos::TokenBucket::new(TOKEN_BUCKET_CAPACITY as u64, RATE_LIMIT_PPS),
            vm: VM::new(),
            bpf: BpfSlot {
                program: [Instruction::new(0, 0, 0, 0); MAX_BPF_PROGRAM_SIZE],
                len: 0,
            },
            flows: flow::FlowTable::new(),
            mgmt_auth: mgmt_auth::MgmtAuth::new(mgmt_key),
            operator: None,
            syn_secret: SynCookieSecret::new([0; 16]),
            stats: IntervalStats {
                received_for_us: 0,
                passed: 0,
                ddos: 0,
                firewall: 0,
                malware: 0,
                ebpf: 0,
                heuristic: 0,
                mgmt: 0,
            },
        }
    }

    /// Installs per-boot secrets, the built-in signatures and the default
    /// firewall rule.
    pub fn init(&mut self, secrets: BootSecrets) {
        // 4 short patterns into a 128-node trie cannot run out of nodes.
        let _ = self.ac.insert(b"DROP TABLE");
        let _ = self.ac.insert(b"<script>");
        let _ = self.ac.insert(b"eval(");
        let _ = self.ac.insert(b"UNION SELECT");
        self.ac.build();
        let _ = self.fw.block_port(DEFAULT_BLOCKED_PORT);

        self.syn_secret = secrets.syn_cookie;
        self.cms.reseed(secrets.cms_seed);
        self.mgmt_auth.set_epoch(secrets.mgmt_epoch);
    }

    /// The boot epoch advertised in telemetry.
    pub fn mgmt_epoch(&self) -> u32 {
        self.mgmt_auth.epoch()
    }

    /// Number of flows currently tracked.
    pub const fn active_flows(&self) -> usize {
        self.flows.active_count
    }

    /// Counters accumulated since the last [`Self::start_interval`].
    pub const fn interval_stats(&self) -> &IntervalStats {
        &self.stats
    }

    /// Clears the per-interval counters.
    pub fn start_interval(&mut self) {
        self.stats = IntervalStats::default();
    }

    /// Expires flows idle for longer than `timeout`.
    pub fn prune_flows(&mut self, now: u64, timeout: u64) {
        self.flows.prune(now, timeout);
    }

    /// Starts a new heavy-hitter window, optionally under a fresh seed.
    pub fn reset_heavy_hitters(&mut self, new_seed: Option<u64>) {
        if let Some(seed) = new_seed {
            self.cms.reseed(seed);
        }
        self.cms.reset();
    }

    /// Sends the telemetry frame for the current interval: ten big-endian
    /// u64 slots holding passed, ddos, firewall, malware, ebpf and
    /// heuristic counts, `memory_used`, active flows, mgmt packets and the
    /// boot epoch.
    pub fn send_telemetry<S: PacketSink>(&self, memory_used: u64, sink: &mut S) {
        let s = &self.stats;
        let slots = [
            s.passed,
            s.ddos,
            s.firewall,
            s.malware,
            s.ebpf,
            s.heuristic,
            memory_used,
            self.flows.active_count as u64,
            s.mgmt,
            u64::from(self.mgmt_auth.epoch()),
        ];
        let mut frame = [0u8; TELEMETRY_FRAME_LEN];
        let frame = report::telemetry_frame(&mut frame, self.operator, &slots);
        sink.send(frame);
    }

    /// Runs one received frame through the pipeline.
    pub fn process<S: PacketSink>(&mut self, packet: &mut [u8], now: u64, sink: &mut S) -> Verdict {
        if is_for_us(packet) {
            self.stats.received_for_us += 1;
        }
        let mut drop = false;
        let mut meta = AlertMeta::empty();
        meta.packet_len = packet.len().min(u16::MAX as usize) as u16;

        let mut src_mac = [0u8; 6];
        if packet.len() >= ethernet::SRC_MAC_OFFSET + ethernet::MAC_ADDR_SIZE {
            src_mac.copy_from_slice(
                &packet[ethernet::SRC_MAC_OFFSET..ethernet::SRC_MAC_OFFSET + ethernet::MAC_ADDR_SIZE],
            );
        }
        let ip = parse_ipv4(packet);
        if let Some(ip) = &ip {
            meta.src_ip = ip.src_ip;
            meta.dst_ip = ip.dst_ip;
            meta.protocol = ip.protocol;
            if let Some((src_port, dst_port)) = transport_ports(packet, ip) {
                meta.src_port = src_port;
                meta.dst_port = dst_port;
            }

            if self.pbox.is_banned(&meta.src_ip, now) {
                drop = true;
            } else if self.cms.insert(&meta.src_ip) > HEAVY_HITTER_THRESHOLD {
                self.pbox.ban(&meta.src_ip, IP_BAN_DURATION_CYCLES as u64, now);
                drop = true;
            }
        }
        let dst_port = meta.dst_port;

        if drop || !self.limiter.allow(now) {
            self.stats.ddos += 1;
            if should_emit_ddos_alert(self.stats.ddos, DDOS_ALERT_SAMPLE_RATE) {
                self.alert(&meta, AlertReason::Ddos, sink);
            }
            return Verdict::Dropped(AlertReason::Ddos);
        }

        if ip.is_some() {
            self.track_flow(&meta, packet.len(), now, sink);
        }

        if let Some(flags) = ip.as_ref().and_then(|ip| tcp_flags(packet, ip))
            && heuristic::HeuristicEngine::check_tcp_flags(flags).is_some()
        {
            self.stats.heuristic += 1;
            return self.drop_with_alert(&meta, AlertReason::Heuristic, sink);
        }

        if self.bpf.len > 0 {
            let program = &self.bpf.program[..self.bpf.len];
            let drop_reason = match self.vm.execute(program, packet) {
                Ok(VmAction::Pass) => None,
                Ok(VmAction::Drop) => Some(AlertReason::Ebpf),
                Err(VmRuntimeError::Timeout) => Some(AlertReason::BpfTimeout),
                Err(VmRuntimeError::InvalidAction(_)) => Some(AlertReason::BpfInvalidAction),
            };
            if let Some(reason) = drop_reason {
                self.stats.ebpf += 1;
                return self.drop_with_alert(&meta, reason, sink);
            }
        }

        if dst_port != 0 && self.fw.is_blocked(dst_port) {
            self.stats.firewall += 1;
            return self.drop_with_alert(&meta, AlertReason::Firewall, sink);
        }

        let syn_secret = &self.syn_secret;
        let Some(payload) = process_packet(packet, sink, syn_secret) else {
            return Verdict::Consumed;
        };

        if heuristic::HeuristicEngine::check_payload(payload).is_some() {
            self.stats.heuristic += 1;
            return self.drop_with_alert(&meta, AlertReason::Heuristic, sink);
        }

        if payload.len() < 4 {
            return Verdict::Consumed;
        }

        if dst_port == MANAGEMENT_PORT {
            self.stats.mgmt += 1;
            const UDP_HEADER_LEN: usize = 8;
            if payload.len() > UDP_HEADER_LEN {
                let envelope = &payload[UDP_HEADER_LEN..];
                if let Some(body) = self.mgmt_auth.verify(envelope) {
                    self.operator = Some(OperatorAddr {
                        mac: src_mac,
                        ip: meta.src_ip,
                    });
                    self.dispatch_mgmt(body, now, &meta, sink);
                } else {
                    self.alert(&meta, AlertReason::MgmtAuthFail, sink);
                }
            }
            return Verdict::Management;
        }

        if self.ac.scan(payload) || self.dyn_rules.check(payload) {
            self.stats.malware += 1;
            self.alert(&meta, AlertReason::Malware, sink);
            Verdict::Dropped(AlertReason::Malware)
        } else {
            self.stats.passed += 1;
            Verdict::Passed
        }
    }

    /// Records the packet against its flow, alerting on a sample of new
    /// flows.
    fn track_flow<S: PacketSink>(&mut self, meta: &AlertMeta, len: usize, now: u64, sink: &mut S) {
        let is_new = self.flows.update(
            &meta.src_ip,
            &meta.dst_ip,
            meta.src_port,
            meta.dst_port,
            meta.protocol,
            len,
            now,
        );
        if is_new && (now & FLOW_LOG_SAMPLE_MASK as u64) == 0 {
            self.alert(meta, AlertReason::Flow, sink);
        }
    }

    fn drop_with_alert<S: PacketSink>(
        &self,
        meta: &AlertMeta,
        reason: AlertReason,
        sink: &mut S,
    ) -> Verdict {
        self.alert(meta, reason, sink);
        Verdict::Dropped(reason)
    }

    fn alert<S: PacketSink>(&self, meta: &AlertMeta, reason: AlertReason, sink: &mut S) {
        let mut frame = [0u8; ALERT_FRAME_LEN];
        let frame = report::alert_frame(&mut frame, self.operator, meta, reason);
        sink.send(frame);
    }

    /// Applies an authenticated mgmt body. Under-length bodies are ignored:
    /// the sender has already proven it holds the key.
    fn dispatch_mgmt<S: PacketSink>(&mut self, body: &[u8], now: u64, meta: &AlertMeta, sink: &mut S) {
        if body.len() < mgmt_packet::MIN_PAYLOAD_LEN {
            return;
        }
        match ManagementMessageType::from_u8(body[mgmt_packet::MSG_TYPE_OFFSET]) {
            Some(ManagementMessageType::BlockPort) => {
                use mgmt_packet::block_port;
                if body.len() >= block_port::MIN_PAYLOAD_LEN {
                    let p = u16::from_be_bytes([
                        body[block_port::PORT_OFFSET],
                        body[block_port::PORT_OFFSET + 1],
                    ]);
                    // Blocking the mgmt port would lock the operator out for good.
                    if p == MANAGEMENT_PORT || self.fw.block_port(p).is_err() {
                        self.alert(meta, AlertReason::MgmtRejected, sink);
                    }
                }
            }
            Some(ManagementMessageType::AddDpiPattern) => {
                use mgmt_packet::add_dpi;
                if body.len() >= add_dpi::MIN_PAYLOAD_LEN {
                    let len = body[add_dpi::LEN_OFFSET] as usize;
                    if body.len() >= add_dpi::PATTERN_OFFSET + len && len <= add_dpi::MAX_PATTERN_LEN {
                        let pattern = &body[add_dpi::PATTERN_OFFSET..add_dpi::PATTERN_OFFSET + len];
                        if self.dyn_rules.add(pattern).is_err() {
                            self.alert(meta, AlertReason::MgmtRejected, sink);
                        }
                    }
                }
            }
            Some(ManagementMessageType::UploadBpfProgram) => self.upload_bpf(body, meta, sink),
            Some(ManagementMessageType::BanIp) => {
                use mgmt_packet::ban_ip;
                if body.len() >= ban_ip::MIN_PAYLOAD_LEN {
                    let ip = &body[ban_ip::IP_OFFSET..ban_ip::IP_OFFSET + ipv4::IP_ADDR_SIZE];
                    self.pbox.ban(ip, IP_BAN_DURATION_CYCLES as u64, now);
                }
            }
            None => {}
        }
    }

    fn upload_bpf<S: PacketSink>(&mut self, body: &[u8], meta: &AlertMeta, sink: &mut S) {
        use mgmt_packet::upload_bpf;
        if body.len() < upload_bpf::MIN_PAYLOAD_LEN {
            return;
        }
        let count = body[upload_bpf::COUNT_OFFSET] as usize;
        if body.len() < upload_bpf::INSTR_OFFSET + count * upload_bpf::INSTR_SIZE
            || count > upload_bpf::MAX_INSTR_COUNT
        {
            return;
        }
        let mut staged = [Instruction::new(0, 0, 0, 0); MAX_BPF_PROGRAM_SIZE];
        let encoded = &body[upload_bpf::INSTR_OFFSET..upload_bpf::INSTR_OFFSET + count * upload_bpf::INSTR_SIZE];
        let (encoded, _) = encoded.as_chunks::<{ upload_bpf::INSTR_SIZE }>();
        for (slot, raw) in staged.iter_mut().zip(encoded) {
            let imm = u32::from_be_bytes([raw[3], raw[4], raw[5], raw[6]]);
            *slot = Instruction::new(raw[0], raw[1], raw[2], imm);
        }
        // Decode into a staging buffer so a rejected upload leaves the
        // running program untouched.
        if vm::validate(&staged[..count]).is_ok() {
            self.bpf.program[..count].copy_from_slice(&staged[..count]);
            self.bpf.len = count;
        } else {
            self.alert(meta, AlertReason::BpfReject, sink);
        }
    }
}

/// The IPv4 header fields the pipeline acts on.
#[derive(Debug, Clone, Copy)]
struct Ipv4Fields {
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    protocol: u8,
    /// Offset of the transport header within the frame.
    l4_offset: usize,
}

/// Reads the IPv4 header of an Ethernet frame, or `None` if the frame is
/// not IPv4 or too short to hold a minimal header.
fn parse_ipv4(packet: &[u8]) -> Option<Ipv4Fields> {
    let header = packet.get(ipv4::HEADER_OFFSET..ipv4::HEADER_OFFSET + ipv4::MIN_HEADER_SIZE)?;
    if packet[ethernet::TYPE_OFFSET..ethernet::TYPE_OFFSET + ethernet::TYPE_SIZE] != [0x08, 0x00] {
        return None;
    }
    let ihl = usize::from(header[0] & ipv4::IHL_MASK) * 4;
    Some(Ipv4Fields {
        src_ip: [header[12], header[13], header[14], header[15]],
        dst_ip: [header[16], header[17], header[18], header[19]],
        protocol: header[9],
        l4_offset: ipv4::HEADER_OFFSET + ihl,
    })
}

/// Source and destination ports, for TCP and UDP only: other protocols
/// have no ports, and reading their header bytes as ports would let an
/// ICMP checksum match a firewall rule.
fn transport_ports(packet: &[u8], ip: &Ipv4Fields) -> Option<(u16, u16)> {
    match IpProtocol::from_u8(ip.protocol)? {
        IpProtocol::Tcp | IpProtocol::Udp => {
            packet.get(ip.l4_offset..).and_then(TcpHeader::extract_ports)
        }
        IpProtocol::Icmp => None,
    }
}

/// The TCP flags byte, if this is a TCP segment with a full header.
fn tcp_flags(packet: &[u8], ip: &Ipv4Fields) -> Option<u8> {
    if IpProtocol::from_u8(ip.protocol) != Some(IpProtocol::Tcp)
        || packet.len() < ip.l4_offset + tcp::MIN_HEADER_SIZE
    {
        return None;
    }
    Some(packet[ip.l4_offset + tcp::FLAGS_OFFSET])
}

/// True for IPv4 frames to our address and ARP frames asking about it.
fn is_for_us(packet: &[u8]) -> bool {
    let ethertype = packet
        .get(ethernet::TYPE_OFFSET..ethernet::TYPE_OFFSET + ethernet::TYPE_SIZE)
        .map(|t| u16::from_be_bytes([t[0], t[1]]));
    let target_ip = match ethertype {
        Some(0x0800) => packet.get(ipv4::DST_IP_OFFSET..ipv4::DST_IP_OFFSET + ipv4::IP_ADDR_SIZE),
        Some(0x0806) => packet.get(arp::TARGET_IP_OFFSET..arp::TARGET_IP_OFFSET + ipv4::IP_ADDR_SIZE),
        _ => None,
    };
    target_ip == Some(&IP_ADDR[..])
}

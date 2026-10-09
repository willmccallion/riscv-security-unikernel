//! The per-packet security pipeline.
//!
//! [`Engine`] owns every security subsystem and decides what happens to
//! each received frame. It performs no I/O of its own: replies, alerts and
//! telemetry leave through the caller's [`PacketSink`], and time comes in
//! as an argument. That keeps the whole pipeline runnable, testable and
//! fuzzable on the host.

mod report;

use crate::config::{
    ALERT_BUCKET_CAPACITY, ALERT_TOKEN_COST_CYCLES, CMS_DEPTH, CMS_WIDTH,
    DDOS_ALERT_SAMPLE_RATE, DEFAULT_BLOCKED_PORT, FLOW_LOG_SAMPLE_MASK, HEAVY_HITTER_THRESHOLD,
    IP_ADDR, IP_BAN_DURATION_CYCLES, MANAGEMENT_PORT, MAX_BPF_PROGRAM_SIZE, MGMT_BUCKET_CAPACITY,
    MGMT_TOKEN_COST_CYCLES, RATE_LIMIT_TOKEN_COST_CYCLES, TELEMETRY_PORT, TOKEN_BUCKET_CAPACITY,
};
use crate::net::PacketSink;
use crate::net::constants::{IpProtocol, arp, ethernet, ipv4, tcp, udp};
use crate::net::stack::{SynCookieSecret, process_packet};
use crate::net::tcp::extract_ports;
use crate::security::alert::{AlertMeta, AlertReason, should_emit_ddos_alert};
use crate::security::mgmt::{ManagementMessageType, MgmtOutcome, mgmt_packet};
use crate::security::vm::{Instruction, VM, VmAction, VmRuntimeError};
use crate::security::{dos, dpi, firewall, flow, heuristic, mgmt_auth, report_auth, sketch, vm};

use report::{MAX_REPORT_FRAME_LEN, ReportHeader};

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
    /// Keys the heavy-hitter sketch's hash.
    pub cms_key: [u8; 16],
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
///
/// The heavy-hitter sketch's dimensions are type parameters so the kernel
/// can use a small one (the defaults) and the Linux daemon a large one.
#[derive(Debug)]
pub struct Engine<const SKETCH_WIDTH: usize = { CMS_WIDTH }, const SKETCH_DEPTH: usize = { CMS_DEPTH }> {
    ac: dpi::AhoCorasick,
    dyn_rules: dpi::DynamicRules,
    fw: firewall::FirewallState,
    cms: sketch::CountMinSketch<SKETCH_WIDTH, SKETCH_DEPTH>,
    pbox: dos::PenaltyBox,
    limiter: dos::TokenBucket,
    mgmt_limiter: dos::TokenBucket,
    alert_limiter: dos::TokenBucket,
    vm: VM,
    bpf: BpfSlot,
    flows: flow::FlowTable,
    mgmt_auth: mgmt_auth::MgmtAuth,
    report_key: [u8; 16],
    report_seq: u64,
    operator: Option<OperatorAddr>,
    syn_secret: SynCookieSecret,
    stats: IntervalStats,
}

impl<const SKETCH_WIDTH: usize, const SKETCH_DEPTH: usize> Engine<SKETCH_WIDTH, SKETCH_DEPTH> {
    /// Creates an engine whose mgmt plane verifies with `mgmt_key`.
    ///
    /// [`Self::init`] must run before the first packet.
    pub const fn new(mgmt_key: [u8; 16]) -> Self {
        Self {
            ac: dpi::AhoCorasick::new(),
            dyn_rules: dpi::DynamicRules::new(),
            fw: firewall::FirewallState::new(),
            cms: sketch::CountMinSketch::new([0; 16]),
            pbox: dos::PenaltyBox::new(),
            limiter: dos::TokenBucket::new(TOKEN_BUCKET_CAPACITY as u64, RATE_LIMIT_TOKEN_COST_CYCLES),
            mgmt_limiter: dos::TokenBucket::new(MGMT_BUCKET_CAPACITY, MGMT_TOKEN_COST_CYCLES),
            alert_limiter: dos::TokenBucket::new(ALERT_BUCKET_CAPACITY, ALERT_TOKEN_COST_CYCLES),
            vm: VM::new(),
            bpf: BpfSlot {
                program: [Instruction::new(0, 0, 0, 0); MAX_BPF_PROGRAM_SIZE],
                len: 0,
            },
            flows: flow::FlowTable::new(),
            mgmt_auth: mgmt_auth::MgmtAuth::new(mgmt_key),
            report_key: report_auth::report_key(&mgmt_key),
            report_seq: 0,
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
        self.cms.rekey(secrets.cms_key);
        self.mgmt_auth.set_epoch(secrets.mgmt_epoch);
    }

    /// The boot epoch advertised in telemetry.
    pub const fn mgmt_epoch(&self) -> u32 {
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

    /// Closes one detection interval: ages the heavy-hitter counts and lets
    /// interval-based detectors report. Call every
    /// [`CMS_DECAY_INTERVAL_CYCLES`](crate::config::CMS_DECAY_INTERVAL_CYCLES).
    pub fn end_detection_interval<S: PacketSink>(&mut self, _now: u64, _sink: &mut S) {
        self.cms.decay();
    }

    /// Sends the signed telemetry report for the current interval: ten
    /// big-endian u64 slots holding passed, ddos, firewall, malware, ebpf
    /// and heuristic counts, `memory_used`, active flows, mgmt packets and
    /// the boot epoch.
    pub fn send_telemetry<S: PacketSink>(&mut self, memory_used: u64, sink: &mut S) {
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
        self.send_report(TELEMETRY_PORT, &report::telemetry_body(&slots), sink);
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

            if let Some(envelope) = mgmt_envelope(packet, ip, meta.dst_port) {
                return self.handle_mgmt(envelope, src_mac, &meta, now, sink);
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
                self.alert(&meta, AlertReason::Ddos, now, sink);
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
            return self.drop_with_alert(&meta, AlertReason::Heuristic, now, sink);
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
                return self.drop_with_alert(&meta, reason, now, sink);
            }
        }

        if dst_port != 0 && self.fw.is_blocked(dst_port) {
            self.stats.firewall += 1;
            return self.drop_with_alert(&meta, AlertReason::Firewall, now, sink);
        }

        let syn_secret = &self.syn_secret;
        let Some(payload) = process_packet(packet, sink, syn_secret) else {
            return Verdict::Consumed;
        };

        if heuristic::HeuristicEngine::check_payload(payload).is_some() {
            self.stats.heuristic += 1;
            return self.drop_with_alert(&meta, AlertReason::Heuristic, now, sink);
        }

        if payload.len() < 4 {
            return Verdict::Consumed;
        }

        if self.ac.scan(payload) || self.dyn_rules.check(payload) {
            self.stats.malware += 1;
            self.alert(&meta, AlertReason::Malware, now, sink);
            Verdict::Dropped(AlertReason::Malware)
        } else {
            self.stats.passed += 1;
            Verdict::Passed
        }
    }

    /// Authenticates and applies a datagram addressed to the mgmt port.
    ///
    /// Runs ahead of every data-plane check so no ban, rate limit, BPF
    /// program or heuristic can cut the operator off; the mgmt plane's own
    /// token bucket bounds the verification work a flood can cause.
    fn handle_mgmt<S: PacketSink>(
        &mut self,
        envelope: MgmtEnvelope<'_>,
        src_mac: [u8; 6],
        meta: &AlertMeta,
        now: u64,
        sink: &mut S,
    ) -> Verdict {
        self.stats.mgmt += 1;
        if !self.mgmt_limiter.allow(now) {
            return Verdict::Management;
        }
        let MgmtEnvelope::Sealed(envelope) = envelope else {
            return Verdict::Management;
        };
        if let Some(command) = self.mgmt_auth.verify(envelope) {
            self.operator = Some(OperatorAddr {
                mac: src_mac,
                ip: meta.src_ip,
            });
            let outcome = self.dispatch_mgmt(command.body, now);
            self.send_ack(command.seq, command.body, outcome, sink);
        } else {
            self.alert(meta, AlertReason::MgmtAuthFail, now, sink);
        }
        Verdict::Management
    }

    /// Records the packet against its flow, alerting on a sample of new
    /// flows.
    fn track_flow<S: PacketSink>(&mut self, meta: &AlertMeta, len: usize, now: u64, sink: &mut S) {
        let key = flow::FlowKey {
            src_ip: meta.src_ip,
            dst_ip: meta.dst_ip,
            src_port: meta.src_port,
            dst_port: meta.dst_port,
            protocol: meta.protocol,
        };
        let is_new = self.flows.update(&key, len, now);
        if is_new && (now & FLOW_LOG_SAMPLE_MASK as u64) == 0 {
            self.alert(meta, AlertReason::Flow, now, sink);
        }
    }

    fn drop_with_alert<S: PacketSink>(
        &mut self,
        meta: &AlertMeta,
        reason: AlertReason,
        now: u64,
        sink: &mut S,
    ) -> Verdict {
        self.alert(meta, reason, now, sink);
        Verdict::Dropped(reason)
    }

    fn alert<S: PacketSink>(&mut self, meta: &AlertMeta, reason: AlertReason, now: u64, sink: &mut S) {
        if self.alert_limiter.allow(now) {
            self.send_report(MANAGEMENT_PORT, &report::alert_body(meta, reason), sink);
        }
    }

    fn send_ack<S: PacketSink>(&mut self, seq: u32, body: &[u8], outcome: MgmtOutcome, sink: &mut S) {
        let command = body.get(mgmt_packet::MSG_TYPE_OFFSET).copied().unwrap_or(0);
        self.send_report(MANAGEMENT_PORT, &report::ack_body(seq, command, outcome), sink);
    }

    /// Signs `body` as the next report of this boot and sends it to the
    /// operator's telemetry port.
    fn send_report<S: PacketSink>(&mut self, src_port: u16, body: &[u8], sink: &mut S) {
        self.report_seq += 1;
        let header = ReportHeader {
            operator: self.operator,
            src_port,
            dst_port: TELEMETRY_PORT,
            key: &self.report_key,
            epoch: self.mgmt_auth.epoch(),
            seq: self.report_seq,
        };
        let mut frame = [0u8; MAX_REPORT_FRAME_LEN];
        sink.send(report::report_frame(&mut frame, &header, body));
    }

    /// Applies an authenticated mgmt body and reports what happened.
    fn dispatch_mgmt(&mut self, body: &[u8], now: u64) -> MgmtOutcome {
        let Some(&msg_type) = body.get(mgmt_packet::MSG_TYPE_OFFSET) else {
            return MgmtOutcome::Invalid;
        };
        match ManagementMessageType::from_u8(msg_type) {
            Some(ManagementMessageType::BlockPort) => self.block_port(body),
            Some(ManagementMessageType::AddDpiPattern) => self.add_dpi_pattern(body),
            Some(ManagementMessageType::UploadBpfProgram) => self.upload_bpf(body),
            Some(ManagementMessageType::BanIp) => self.ban_ip(body, now),
            Some(ManagementMessageType::UnblockPort) => self.unblock_port(body),
            Some(ManagementMessageType::RemoveDpiPattern) => self.remove_dpi_pattern(body),
            Some(ManagementMessageType::UnloadBpfProgram) => {
                self.bpf.len = 0;
                MgmtOutcome::Applied
            }
            Some(ManagementMessageType::UnbanIp) => self.unban_ip(body),
            None => MgmtOutcome::Invalid,
        }
    }

    fn block_port(&mut self, body: &[u8]) -> MgmtOutcome {
        let Some(port) = port_operand(body) else {
            return MgmtOutcome::Invalid;
        };
        // Blocking the mgmt port would cut the operator off for good.
        if port == MANAGEMENT_PORT {
            return MgmtOutcome::Refused;
        }
        match self.fw.block_port(port) {
            Ok(()) => MgmtOutcome::Applied,
            Err(firewall::FirewallError::Full) => MgmtOutcome::TableFull,
        }
    }

    fn unblock_port(&mut self, body: &[u8]) -> MgmtOutcome {
        let Some(port) = port_operand(body) else {
            return MgmtOutcome::Invalid;
        };
        self.fw.unblock_port(port);
        MgmtOutcome::Applied
    }

    fn add_dpi_pattern(&mut self, body: &[u8]) -> MgmtOutcome {
        let Some(pattern) = pattern_operand(body) else {
            return MgmtOutcome::Invalid;
        };
        match self.dyn_rules.add(pattern) {
            Ok(()) => MgmtOutcome::Applied,
            Err(dpi::DynRulesError::Full) => MgmtOutcome::TableFull,
            Err(dpi::DynRulesError::TooLong | dpi::DynRulesError::Empty) => MgmtOutcome::Invalid,
        }
    }

    fn remove_dpi_pattern(&mut self, body: &[u8]) -> MgmtOutcome {
        let Some(pattern) = pattern_operand(body) else {
            return MgmtOutcome::Invalid;
        };
        self.dyn_rules.remove(pattern);
        MgmtOutcome::Applied
    }

    fn ban_ip(&mut self, body: &[u8], now: u64) -> MgmtOutcome {
        let Some(ip) = ip_operand(body) else {
            return MgmtOutcome::Invalid;
        };
        self.pbox.ban(&ip, IP_BAN_DURATION_CYCLES as u64, now);
        MgmtOutcome::Applied
    }

    fn unban_ip(&mut self, body: &[u8]) -> MgmtOutcome {
        let Some(ip) = ip_operand(body) else {
            return MgmtOutcome::Invalid;
        };
        self.pbox.unban(&ip);
        MgmtOutcome::Applied
    }

    fn upload_bpf(&mut self, body: &[u8]) -> MgmtOutcome {
        use mgmt_packet::upload_bpf;
        let Some(&count) = body.get(upload_bpf::COUNT_OFFSET) else {
            return MgmtOutcome::Invalid;
        };
        let count = usize::from(count);
        if count > upload_bpf::MAX_INSTR_COUNT {
            return MgmtOutcome::Invalid;
        }
        let Some(encoded) =
            body.get(upload_bpf::INSTR_OFFSET..upload_bpf::INSTR_OFFSET + count * upload_bpf::INSTR_SIZE)
        else {
            return MgmtOutcome::Invalid;
        };
        let mut staged = [Instruction::new(0, 0, 0, 0); MAX_BPF_PROGRAM_SIZE];
        let (encoded, _) = encoded.as_chunks::<{ upload_bpf::INSTR_SIZE }>();
        for (slot, raw) in staged.iter_mut().zip(encoded) {
            let imm = u32::from_be_bytes([raw[3], raw[4], raw[5], raw[6]]);
            *slot = Instruction::new(raw[0], raw[1], raw[2], imm);
        }
        // Decode into a staging buffer so a rejected upload leaves the
        // running program untouched.
        if vm::validate(&staged[..count]).is_err() {
            return MgmtOutcome::Invalid;
        }
        self.bpf.program[..count].copy_from_slice(&staged[..count]);
        self.bpf.len = count;
        MgmtOutcome::Applied
    }
}

/// The big-endian port operand of a (Un)BlockPort body.
fn port_operand(body: &[u8]) -> Option<u16> {
    use mgmt_packet::block_port::PORT_OFFSET;
    let port = body.get(PORT_OFFSET..PORT_OFFSET + 2)?;
    Some(u16::from_be_bytes([port[0], port[1]]))
}

/// The length-prefixed pattern operand of an Add/RemoveDpiPattern body.
fn pattern_operand(body: &[u8]) -> Option<&[u8]> {
    use mgmt_packet::add_dpi::{LEN_OFFSET, PATTERN_OFFSET};
    let len = usize::from(*body.get(LEN_OFFSET)?);
    body.get(PATTERN_OFFSET..PATTERN_OFFSET + len)
}

/// The IPv4 operand of a (Un)BanIp body.
fn ip_operand(body: &[u8]) -> Option<[u8; 4]> {
    use mgmt_packet::ban_ip::IP_OFFSET;
    body.get(IP_OFFSET..IP_OFFSET + ipv4::IP_ADDR_SIZE)?.try_into().ok()
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
            packet.get(ip.l4_offset..).and_then(extract_ports)
        }
        IpProtocol::Icmp => None,
    }
}

/// The payload of a UDP datagram addressed to the mgmt port.
#[derive(Debug, Clone, Copy)]
enum MgmtEnvelope<'a> {
    /// The UDP payload, bounded by the UDP length so Ethernet padding on
    /// short frames is not mistaken for part of the sealed envelope.
    Sealed(&'a [u8]),
    /// The UDP header is truncated or its length field is inconsistent.
    Malformed,
}

/// Returns the mgmt envelope if `packet` is UDP to our mgmt port.
fn mgmt_envelope<'a>(packet: &'a [u8], ip: &Ipv4Fields, dst_port: u16) -> Option<MgmtEnvelope<'a>> {
    if IpProtocol::from_u8(ip.protocol) != Some(IpProtocol::Udp)
        || ip.dst_ip != IP_ADDR
        || dst_port != MANAGEMENT_PORT
    {
        return None;
    }
    let payload_start = ip.l4_offset + udp::HEADER_SIZE;
    let envelope = packet
        .get(ip.l4_offset + 4..ip.l4_offset + 6)
        .map(|len| usize::from(u16::from_be_bytes([len[0], len[1]])))
        .filter(|&udp_len| udp_len >= udp::HEADER_SIZE)
        .and_then(|udp_len| packet.get(payload_start..ip.l4_offset + udp_len));
    Some(envelope.map_or(MgmtEnvelope::Malformed, MgmtEnvelope::Sealed))
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

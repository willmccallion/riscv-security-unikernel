//! The per-packet security pipeline.
//!
//! [`Engine`] owns every security subsystem and decides what happens to
//! each received frame. It performs no I/O of its own: replies, alerts and
//! telemetry leave through the caller's [`PacketSink`], and time comes in
//! as an argument. That keeps the whole pipeline runnable, testable and
//! fuzzable on the host.

use crate::time::{TickSpan, Ticks};
use core::net::Ipv4Addr;

mod report;

use crate::config::{
    ALERT_BUCKET_CAPACITY, ALERT_TOKEN_COST, CMS_DEPTH, CMS_WIDTH, DDOS_ALERT_SAMPLE_RATE,
    DEFAULT_BLOCKED_PORT, FLOW_LOG_SAMPLE_MASK, HEAVY_HITTER_THRESHOLD, IP_ADDR, IP_BAN_DURATION,
    MANAGEMENT_PORT, MGMT_BUCKET_CAPACITY, MGMT_TOKEN_COST, PREFIX_SKETCH_DEPTH,
    PREFIX_SKETCH_WIDTH, RATE_LIMIT_TOKEN_COST, SOURCE_COUNTER_REGISTERS, SOURCE_SURGE_FACTOR,
    SOURCE_SURGE_MINIMUM, SUBNET_16_THRESHOLD, SUBNET_24_THRESHOLD, TELEMETRY_PORT,
    TOKEN_BUCKET_CAPACITY,
};
use crate::net::PacketSink;
use crate::net::constants::{EthernetType, arp, ethernet, ipv4};
use crate::net::frame::{self, Frame, Ipv4Packet, Ports, Rejected, Rejection, Transport};
use crate::net::stack::{self, SynCookieSecret};
use crate::security::alert::{AlertMeta, AlertReason, should_emit_ddos_alert};
use crate::security::hash::{MgmtKey, ReportKey, SketchKey};
use crate::security::mgmt::{ManagementMessageType, MgmtOutcome, mgmt_packet};
use crate::security::mgmt_auth::OperatorAddr;
use crate::security::vm::{Program, VmAction};
use crate::security::{anomaly, dos, dpi, firewall, flow, heuristic, mgmt_auth, scan, sketch, vm};

use report::{MAX_REPORT_FRAME_LEN, ReportHeader};

/// Per-boot secrets the engine needs before it processes traffic.
#[derive(Debug, Clone, Copy)]
pub struct BootSecrets {
    /// Keys the SYN-cookie PRF.
    pub syn_cookie: SynCookieSecret,
    /// Keys the heavy-hitter sketch's hash.
    pub cms_key: SketchKey,
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
    pub bpf: u64,
    /// Heuristic anomalies.
    pub heuristic: u64,
    /// Mgmt-plane packets, authenticated or not.
    pub mgmt: u64,
}

impl IntervalStats {
    /// Total drops of every kind this interval.
    pub const fn drops(&self) -> u64 {
        self.ddos + self.firewall + self.malware + self.bpf + self.heuristic
    }

    /// Counts a drop under the counter its reason reports to. Detector
    /// alerts and unreadable packets have no counter of their own.
    const fn count_drop(&mut self, reason: AlertReason) {
        match reason {
            AlertReason::Ddos => self.ddos += 1,
            AlertReason::Firewall => self.firewall += 1,
            AlertReason::Malware => self.malware += 1,
            AlertReason::Bpf | AlertReason::BpfTimeout => self.bpf += 1,
            AlertReason::Heuristic => self.heuristic += 1,
            AlertReason::Flow
            | AlertReason::Pass
            | AlertReason::MgmtAuthFail
            | AlertReason::SourceSurge
            | AlertReason::SubnetFlood
            | AlertReason::PortScan
            | AlertReason::MalformedIp
            | AlertReason::IpFragment => {}
        }
    }
}

/// Whether a packet's source may go on through the pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Screening {
    Admit,
    Drop,
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

/// Every security subsystem, plus the state the pipeline carries between
/// packets.
///
/// The per-source and per-subnet sketches' dimensions are type parameters
/// so the kernel can use small ones (the defaults) and the Linux daemon
/// large ones.
#[derive(Debug)]
pub struct Engine<
    const SKETCH_WIDTH: usize = { CMS_WIDTH },
    const SKETCH_DEPTH: usize = { CMS_DEPTH },
    const PREFIX_WIDTH: usize = { PREFIX_SKETCH_WIDTH },
    const PREFIX_DEPTH: usize = { PREFIX_SKETCH_DEPTH },
> {
    signatures: dpi::AhoCorasick,
    runtime_signatures: dpi::DynamicRules,
    firewall: firewall::FirewallState,
    source_rates: sketch::CountMinSketch<SKETCH_WIDTH, SKETCH_DEPTH>,
    /// Keys the one hash of each source address that every per-source
    /// sketch shares.
    source_key: SketchKey,
    sources: sketch::HyperLogLog<SOURCE_COUNTER_REGISTERS>,
    /// Packet rates per /24 and /16, keyed by the prefix.
    prefixes: sketch::CountMinSketch<PREFIX_WIDTH, PREFIX_DEPTH>,
    port_scans: scan::PortScanDetector,
    source_surge: anomaly::SurgeDetector,
    penalty_box: dos::PenaltyBox,
    limiter: dos::TokenBucket,
    mgmt_failure_limiter: dos::TokenBucket,
    alert_limiter: dos::TokenBucket,
    /// The installed BPF filter, if any.
    bpf: Option<Program>,
    flows: flow::FlowTable,
    mgmt_auth: mgmt_auth::MgmtAuth,
    report_key: ReportKey,
    report_seq: u64,
    operator: Option<OperatorAddr>,
    syn_secret: SynCookieSecret,
    stats: IntervalStats,
}

impl<
    const SKETCH_WIDTH: usize,
    const SKETCH_DEPTH: usize,
    const PREFIX_WIDTH: usize,
    const PREFIX_DEPTH: usize,
> Engine<SKETCH_WIDTH, SKETCH_DEPTH, PREFIX_WIDTH, PREFIX_DEPTH>
{
    /// Creates an engine whose mgmt plane verifies with `mgmt_key`.
    ///
    /// [`Self::init`] must run before the first packet.
    pub const fn new(mgmt_key: MgmtKey) -> Self {
        Self {
            signatures: dpi::AhoCorasick::new(),
            runtime_signatures: dpi::DynamicRules::new(),
            firewall: firewall::FirewallState::new(),
            source_rates: sketch::CountMinSketch::new(SketchKey::new([0; 16])),
            source_key: SketchKey::new([0; 16]),
            sources: sketch::HyperLogLog::new(SketchKey::new([0; 16])),
            prefixes: sketch::CountMinSketch::new(SketchKey::new([0; 16])),
            port_scans: scan::PortScanDetector::new(SketchKey::new([0; 16])),
            source_surge: anomaly::SurgeDetector::new(SOURCE_SURGE_FACTOR, SOURCE_SURGE_MINIMUM),
            penalty_box: dos::PenaltyBox::new(),
            limiter: dos::TokenBucket::new(TOKEN_BUCKET_CAPACITY, RATE_LIMIT_TOKEN_COST),
            mgmt_failure_limiter: dos::TokenBucket::new(MGMT_BUCKET_CAPACITY, MGMT_TOKEN_COST),
            alert_limiter: dos::TokenBucket::new(ALERT_BUCKET_CAPACITY, ALERT_TOKEN_COST),
            bpf: None,
            flows: flow::FlowTable::new(),
            mgmt_auth: mgmt_auth::MgmtAuth::new(mgmt_key),
            report_key: ReportKey::derive(&mgmt_key),
            report_seq: 0,
            operator: None,
            syn_secret: SynCookieSecret::new([0; 16]),
            stats: IntervalStats {
                received_for_us: 0,
                passed: 0,
                ddos: 0,
                firewall: 0,
                malware: 0,
                bpf: 0,
                heuristic: 0,
                mgmt: 0,
            },
        }
    }

    /// Installs per-boot secrets, the built-in signatures and the default
    /// firewall rule.
    pub fn init(&mut self, secrets: BootSecrets) {
        for signature in dpi::BUILTIN_SIGNATURES {
            // The built-in signatures fit in an empty trie; a test checks it.
            let _ = self.signatures.insert(signature);
        }
        self.signatures.build();
        let _ = self.firewall.block_port(DEFAULT_BLOCKED_PORT);

        self.syn_secret = secrets.syn_cookie;
        self.source_rates.rekey(secrets.cms_key);
        self.source_key = secrets.cms_key;
        self.prefixes
            .rekey(secrets.cms_key.derive(b"subnet sketch"));
        self.port_scans.rekey(secrets.cms_key.derive(b"port scans"));
        self.mgmt_auth.set_epoch(secrets.mgmt_epoch);
    }

    /// The boot epoch advertised in telemetry.
    pub const fn mgmt_epoch(&self) -> u32 {
        self.mgmt_auth.epoch()
    }

    /// Number of flows currently tracked.
    pub fn active_flows(&self) -> usize {
        self.flows.active_count()
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
    pub fn prune_flows(&mut self, now: Ticks, timeout: TickSpan) {
        self.flows.prune(now, timeout);
    }

    /// Closes one detection interval: ages the heavy-hitter counts and lets
    /// interval-based detectors report. Call every
    /// [`CMS_DECAY_INTERVAL`](crate::config::CMS_DECAY_INTERVAL).
    pub fn end_detection_interval<S: PacketSink>(&mut self, sink: &mut S) {
        self.source_rates.decay();
        self.prefixes.decay();
        self.port_scans.end_interval();
        let distinct_sources = self.sources.estimate();
        self.sources.clear();
        if let Some(sources) = self.source_surge.observe(distinct_sources) {
            let meta = AlertMeta {
                prefix_len: 0,
                value: sources as u32,
                ..AlertMeta::empty()
            };
            self.detector_alert(&meta, AlertReason::SourceSurge, sink);
        }
    }

    /// Sends the signed telemetry report for the current interval: eleven
    /// big-endian u64 slots holding passed, ddos, firewall, malware, bpf
    /// and heuristic counts, `memory_used`, active flows, mgmt packets, the
    /// boot epoch and the last mgmt sequence accepted this boot.
    pub fn send_telemetry<S: PacketSink>(&mut self, memory_used: u64, sink: &mut S) {
        let s = &self.stats;
        let slots = [
            s.passed,
            s.ddos,
            s.firewall,
            s.malware,
            s.bpf,
            s.heuristic,
            memory_used,
            self.flows.active_count() as u64,
            s.mgmt,
            u64::from(self.mgmt_auth.epoch()),
            u64::from(self.mgmt_auth.last_seq()),
        ];
        self.send_report(TELEMETRY_PORT, &report::telemetry_body(&slots), sink);
    }

    /// Runs one received frame through the pipeline.
    pub fn process<S: PacketSink>(
        &mut self,
        packet: &mut [u8],
        now: Ticks,
        sink: &mut S,
    ) -> Verdict {
        if is_for_us(packet) {
            self.stats.received_for_us += 1;
        }
        let packet_len = packet.len().min(u16::MAX as usize) as u16;
        let frame = match frame::parse(packet) {
            Ok(frame) => frame,
            Err(rejected) => return self.drop_rejected_ipv4(&rejected, packet_len, now, sink),
        };
        let meta = alert_meta(&frame, packet_len);
        if let Frame::Ipv4(ip) = &frame {
            if let Some(envelope) = mgmt_envelope(ip) {
                return self.handle_mgmt(envelope, &meta, now, sink);
            }
            if self.screen_source(ip, &meta, now, sink) == Screening::Drop {
                return self.drop_for_ddos(&meta, now, sink);
            }
        }
        if !self.limiter.allow(now) {
            return self.drop_for_ddos(&meta, now, sink);
        }
        if let Frame::Ipv4(ip) = &frame {
            self.track_flow(&meta, ip.bytes().len(), now, sink);
        }
        if let Some(reason) = self.filter(&frame, meta.dst_port) {
            return self.drop_counted(&meta, reason, now, sink);
        }
        match stack::respond(frame, sink, &self.syn_secret) {
            Some(payload) => self.inspect_payload(payload, &meta, now, sink),
            None => Verdict::Consumed,
        }
    }

    /// Feeds the source to the per-source and per-subnet detectors and the
    /// port-scan detector, banning it or its subnet if one trips, and says
    /// whether the packet goes on.
    fn screen_source<S: PacketSink>(
        &mut self,
        ip: &Ipv4Packet<'_>,
        meta: &AlertMeta,
        now: Ticks,
        sink: &mut S,
    ) -> Screening {
        let source_hash = self.source_key.hash(&ip.src.octets());
        let _ = self.sources.insert_hash(source_hash);
        if self.penalty_box.is_banned(ip.src, now) {
            return Screening::Drop;
        }
        if self.source_rates.insert_hash(source_hash) > HEAVY_HITTER_THRESHOLD {
            self.penalty_box.ban(ip.src, IP_BAN_DURATION, now);
            return Screening::Drop;
        }
        if let Some(subnet) = self.count_subnets(ip.src) {
            self.ban_subnet(subnet, meta, now, sink);
            return Screening::Drop;
        }
        if let Some(scan) = self.count_connection_attempt(ip) {
            self.ban_scanner(scan, meta, now, sink);
            return Screening::Drop;
        }
        Screening::Admit
    }

    fn ban_subnet<S: PacketSink>(
        &mut self,
        subnet: HeavySubnet,
        meta: &AlertMeta,
        now: Ticks,
        sink: &mut S,
    ) {
        self.penalty_box
            .ban_prefix(subnet.prefix, IP_BAN_DURATION, now);
        let alert = AlertMeta {
            src_ip: subnet.prefix.network(),
            prefix_len: subnet.prefix.prefix_len(),
            value: u32::from(subnet.rate),
            ..*meta
        };
        self.detector_alert(&alert, AlertReason::SubnetFlood, sink);
    }

    fn ban_scanner<S: PacketSink>(
        &mut self,
        scan: scan::ConfirmedScan,
        meta: &AlertMeta,
        now: Ticks,
        sink: &mut S,
    ) {
        self.penalty_box.ban(scan.source, IP_BAN_DURATION, now);
        let alert = AlertMeta {
            value: scan.distinct_ports,
            ..*meta
        };
        self.detector_alert(&alert, AlertReason::PortScan, sink);
    }

    /// Why the header checks drop the frame, if they do: a TCP scan probe,
    /// the BPF program, or a blocked destination port.
    fn filter(&self, frame: &Frame<'_>, dst_port: u16) -> Option<AlertReason> {
        if let Frame::Ipv4(ip) = frame
            && let Transport::Tcp(tcp) = ip.transport
            && heuristic::is_scan_probe(tcp.flags)
        {
            return Some(AlertReason::Heuristic);
        }
        if let Some(reason) = self.run_bpf(frame.bytes()) {
            return Some(reason);
        }
        (dst_port != 0 && self.firewall.is_blocked(dst_port)).then_some(AlertReason::Firewall)
    }

    /// Why the installed BPF program drops `frame`, if one is installed and
    /// does.
    fn run_bpf(&self, frame: &[u8]) -> Option<AlertReason> {
        match vm::execute(self.bpf.as_ref()?, frame) {
            Ok(VmAction::Pass) => None,
            Ok(VmAction::Drop) => Some(AlertReason::Bpf),
            Err(vm::Timeout) => Some(AlertReason::BpfTimeout),
        }
    }

    /// Checks the payload the stack handed on for NOP sleds and signatures.
    fn inspect_payload<S: PacketSink>(
        &mut self,
        payload: &[u8],
        meta: &AlertMeta,
        now: Ticks,
        sink: &mut S,
    ) -> Verdict {
        if heuristic::has_nop_sled(payload) {
            return self.drop_counted(meta, AlertReason::Heuristic, now, sink);
        }
        if payload.is_empty() {
            return Verdict::Consumed;
        }
        if self.signatures.scan(payload) || self.runtime_signatures.check(payload) {
            return self.drop_counted(meta, AlertReason::Malware, now, sink);
        }
        self.stats.passed += 1;
        Verdict::Passed
    }

    /// Authenticates and applies a datagram addressed to the mgmt port.
    ///
    /// Runs ahead of every data-plane check so no ban, rate limit, BPF
    /// program or heuristic can cut the operator off. Every packet is
    /// MAC-checked, which the length cap in `MgmtAuth::verify` keeps cheap,
    /// so junk cannot crowd out a genuine command; only failures draw on
    /// the mgmt token bucket, which limits their alerts. Reports go to the
    /// address signed into the command, never the frame's own headers, so a
    /// captured command re-sent from elsewhere cannot redirect them.
    fn handle_mgmt<S: PacketSink>(
        &mut self,
        envelope: &[u8],
        meta: &AlertMeta,
        now: Ticks,
        sink: &mut S,
    ) -> Verdict {
        self.stats.mgmt += 1;
        let Some(command) = self.mgmt_auth.verify(envelope) else {
            if self.mgmt_failure_limiter.allow(now) {
                self.alert(meta, AlertReason::MgmtAuthFail, now, sink);
            }
            return Verdict::Management;
        };
        self.operator = Some(command.reply_to);
        let outcome = self.dispatch_mgmt(command.body, now);
        self.send_ack(command.seq, command.body, outcome, sink);
        Verdict::Management
    }

    /// Counts a packet from `src_ip` against its /24 and /16, returning the
    /// first that is over its threshold. Subnets containing the appliance
    /// itself are never counted: banning one would cut off its own gateway,
    /// neighbours and operators, whose hosts can still be banned singly.
    fn count_subnets(&mut self, src_ip: Ipv4Addr) -> Option<HeavySubnet> {
        let levels = [(24, SUBNET_24_THRESHOLD), (16, SUBNET_16_THRESHOLD)];
        let mut heavy = None;
        for (len, threshold) in levels {
            let prefix = dos::Ipv4Prefix::new(src_ip, len)?;
            if prefix.contains(IP_ADDR) {
                continue;
            }
            let network = prefix.network().octets();
            let rate = self
                .prefixes
                .insert(&[len, network[0], network[1], network[2]]);
            if heavy.is_none() && rate > threshold {
                heavy = Some(HeavySubnet { prefix, rate });
            }
        }
        heavy
    }

    /// Feeds a TCP connection attempt (SYN without ACK) to the port-scan
    /// detector. Replies and established traffic never count, so a server
    /// answering many client ports is not mistaken for a scanner.
    fn count_connection_attempt(&mut self, ip: &Ipv4Packet<'_>) -> Option<scan::ConfirmedScan> {
        let Transport::Tcp(tcp) = ip.transport else {
            return None;
        };
        if !tcp.flags.is_connection_attempt() {
            return None;
        }
        self.port_scans.observe(ip.src, tcp.ports.dst)
    }

    /// Records the packet against its flow, alerting on a sample of new
    /// flows.
    fn track_flow<S: PacketSink>(
        &mut self,
        meta: &AlertMeta,
        len: usize,
        now: Ticks,
        sink: &mut S,
    ) {
        let key = flow::FlowKey {
            src_ip: meta.src_ip,
            dst_ip: meta.dst_ip,
            src_port: meta.src_port,
            dst_port: meta.dst_port,
            protocol: meta.protocol,
        };
        let is_new = self.flows.update(&key, len, now);
        if is_new && now.get() & FLOW_LOG_SAMPLE_MASK == 0 {
            self.alert(meta, AlertReason::Flow, now, sink);
        }
    }

    fn drop_rejected_ipv4<S: PacketSink>(
        &mut self,
        rejected: &Rejected,
        packet_len: u16,
        now: Ticks,
        sink: &mut S,
    ) -> Verdict {
        let alert = AlertMeta {
            src_ip: rejected.src,
            dst_ip: rejected.dst,
            protocol: rejected.protocol,
            packet_len,
            ..AlertMeta::empty()
        };
        let reason = match rejected.reason {
            Rejection::Malformed => AlertReason::MalformedIp,
            Rejection::Fragment => AlertReason::IpFragment,
        };
        self.drop_with_alert(&alert, reason, now, sink)
    }

    /// Drops for the denial-of-service defences, alerting on a sample of such
    /// drops.
    fn drop_for_ddos<S: PacketSink>(
        &mut self,
        meta: &AlertMeta,
        now: Ticks,
        sink: &mut S,
    ) -> Verdict {
        self.stats.count_drop(AlertReason::Ddos);
        if should_emit_ddos_alert(self.stats.ddos, DDOS_ALERT_SAMPLE_RATE) {
            self.alert(meta, AlertReason::Ddos, now, sink);
        }
        Verdict::Dropped(AlertReason::Ddos)
    }

    /// Drops with an alert and counts the drop under `reason`'s counter.
    fn drop_counted<S: PacketSink>(
        &mut self,
        meta: &AlertMeta,
        reason: AlertReason,
        now: Ticks,
        sink: &mut S,
    ) -> Verdict {
        self.stats.count_drop(reason);
        self.drop_with_alert(meta, reason, now, sink)
    }

    fn drop_with_alert<S: PacketSink>(
        &mut self,
        meta: &AlertMeta,
        reason: AlertReason,
        now: Ticks,
        sink: &mut S,
    ) -> Verdict {
        self.alert(meta, reason, now, sink);
        Verdict::Dropped(reason)
    }

    /// Sends an alert raised at the end of a detection interval. Detectors
    /// report at most once per interval each, so these skip the per-packet
    /// alert limit, which a flood of routine alerts could otherwise drain.
    fn detector_alert<S: PacketSink>(
        &mut self,
        meta: &AlertMeta,
        reason: AlertReason,
        sink: &mut S,
    ) {
        self.send_report(MANAGEMENT_PORT, &report::alert_body(meta, reason), sink);
    }

    fn alert<S: PacketSink>(
        &mut self,
        meta: &AlertMeta,
        reason: AlertReason,
        now: Ticks,
        sink: &mut S,
    ) {
        if self.alert_limiter.allow(now) {
            self.send_report(MANAGEMENT_PORT, &report::alert_body(meta, reason), sink);
        }
    }

    fn send_ack<S: PacketSink>(
        &mut self,
        seq: u32,
        body: &[u8],
        outcome: MgmtOutcome,
        sink: &mut S,
    ) {
        let command = body.get(mgmt_packet::MSG_TYPE_OFFSET).copied().unwrap_or(0);
        self.send_report(
            MANAGEMENT_PORT,
            &report::ack_body(seq, command, outcome),
            sink,
        );
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
    fn dispatch_mgmt(&mut self, body: &[u8], now: Ticks) -> MgmtOutcome {
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
                self.bpf = None;
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
        match self.firewall.block_port(port) {
            Ok(()) => MgmtOutcome::Applied,
            Err(firewall::FirewallError::Full) => MgmtOutcome::TableFull,
        }
    }

    fn unblock_port(&mut self, body: &[u8]) -> MgmtOutcome {
        let Some(port) = port_operand(body) else {
            return MgmtOutcome::Invalid;
        };
        self.firewall.unblock_port(port);
        MgmtOutcome::Applied
    }

    fn add_dpi_pattern(&mut self, body: &[u8]) -> MgmtOutcome {
        let Some(pattern) = pattern_operand(body) else {
            return MgmtOutcome::Invalid;
        };
        match self.runtime_signatures.add(pattern) {
            Ok(()) => MgmtOutcome::Applied,
            Err(dpi::RulesFull) => MgmtOutcome::TableFull,
        }
    }

    fn remove_dpi_pattern(&mut self, body: &[u8]) -> MgmtOutcome {
        let Some(pattern) = pattern_operand(body) else {
            return MgmtOutcome::Invalid;
        };
        self.runtime_signatures.remove(&pattern);
        MgmtOutcome::Applied
    }

    fn ban_ip(&mut self, body: &[u8], now: Ticks) -> MgmtOutcome {
        let Some(ip) = ip_operand(body) else {
            return MgmtOutcome::Invalid;
        };
        match self.penalty_box.ban_by_operator(ip, IP_BAN_DURATION, now) {
            Ok(()) => MgmtOutcome::Applied,
            Err(dos::PenaltyBoxFull) => MgmtOutcome::TableFull,
        }
    }

    fn unban_ip(&mut self, body: &[u8]) -> MgmtOutcome {
        let Some(ip) = ip_operand(body) else {
            return MgmtOutcome::Invalid;
        };
        self.penalty_box.unban(ip);
        MgmtOutcome::Applied
    }

    /// Installs the uploaded program, or with no instructions removes the
    /// filter; a program that does not decode leaves the running one.
    fn upload_bpf(&mut self, body: &[u8]) -> MgmtOutcome {
        use mgmt_packet::upload_bpf::{COUNT_OFFSET, INSTR_OFFSET, INSTR_SIZE};
        let Some(&count) = body.get(COUNT_OFFSET) else {
            return MgmtOutcome::Invalid;
        };
        let Some(encoded) = body.get(INSTR_OFFSET..INSTR_OFFSET + usize::from(count) * INSTR_SIZE)
        else {
            return MgmtOutcome::Invalid;
        };
        if encoded.is_empty() {
            self.bpf = None;
            return MgmtOutcome::Applied;
        }
        match Program::decode(encoded) {
            Ok(program) => {
                self.bpf = Some(program);
                MgmtOutcome::Applied
            }
            Err(_) => MgmtOutcome::Invalid,
        }
    }
}

/// The big-endian port operand of a (Un)BlockPort body.
fn port_operand(body: &[u8]) -> Option<u16> {
    use mgmt_packet::block_port::PORT_OFFSET;
    let port = body.get(PORT_OFFSET..PORT_OFFSET + 2)?;
    Some(u16::from_be_bytes([port[0], port[1]]))
}

/// The length-prefixed pattern operand of an Add/RemoveDpiPattern body;
/// `None` when it runs past the body or is not a [`dpi::Pattern`].
fn pattern_operand(body: &[u8]) -> Option<dpi::Pattern> {
    use mgmt_packet::add_dpi::{LEN_OFFSET, PATTERN_OFFSET};
    let len = usize::from(*body.get(LEN_OFFSET)?);
    dpi::Pattern::new(body.get(PATTERN_OFFSET..PATTERN_OFFSET + len)?).ok()
}

/// The IPv4 operand of a (Un)BanIp body.
fn ip_operand(body: &[u8]) -> Option<Ipv4Addr> {
    use mgmt_packet::ban_ip::IP_OFFSET;
    let octets: [u8; 4] = body
        .get(IP_OFFSET..IP_OFFSET + ipv4::IP_ADDR_SIZE)?
        .try_into()
        .ok()?;
    Some(Ipv4Addr::from(octets))
}

/// A subnet whose packet rate passed its threshold.
#[derive(Debug, Clone, Copy)]
struct HeavySubnet {
    prefix: dos::Ipv4Prefix,
    rate: u16,
}

/// The alert fields `frame` fills: addresses, protocol and ports for IPv4.
fn alert_meta(frame: &Frame<'_>, packet_len: u16) -> AlertMeta {
    let empty = AlertMeta {
        packet_len,
        ..AlertMeta::empty()
    };
    let Frame::Ipv4(ip) = frame else {
        return empty;
    };
    let ports = ip.transport.ports().unwrap_or(Ports { src: 0, dst: 0 });
    AlertMeta {
        src_ip: ip.src,
        dst_ip: ip.dst,
        protocol: ip.transport.protocol(),
        src_port: ports.src,
        dst_port: ports.dst,
        ..empty
    }
}

/// The sealed envelope, if `ip` is a UDP datagram to our mgmt port.
fn mgmt_envelope<'a>(ip: &'a Ipv4Packet<'_>) -> Option<&'a [u8]> {
    match ip.transport {
        Transport::Udp(ports) if ip.dst == IP_ADDR && ports.dst == MANAGEMENT_PORT => {
            Some(ip.payload())
        }
        _ => None,
    }
}

/// True for IPv4 frames to our address and ARP frames asking about it.
fn is_for_us(packet: &[u8]) -> bool {
    const ETHERTYPE_IPV4: u16 = EthernetType::Ipv4 as u16;
    const ETHERTYPE_ARP: u16 = EthernetType::Arp as u16;
    let ethertype = packet
        .get(ethernet::TYPE_OFFSET..ethernet::TYPE_OFFSET + ethernet::TYPE_SIZE)
        .map(|t| u16::from_be_bytes([t[0], t[1]]));
    let target_ip = match ethertype {
        Some(ETHERTYPE_IPV4) => {
            packet.get(ipv4::DST_IP_OFFSET..ipv4::DST_IP_OFFSET + ipv4::IP_ADDR_SIZE)
        }
        Some(ETHERTYPE_ARP) => {
            packet.get(arp::TARGET_IP_OFFSET..arp::TARGET_IP_OFFSET + ipv4::IP_ADDR_SIZE)
        }
        _ => None,
    };
    target_ip == Some(&IP_ADDR.octets()[..])
}

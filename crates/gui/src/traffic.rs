//! Background network task for traffic generation and kernel communication.
//!
//! This module handles UDP communication with the security kernel, including
//! receiving telemetry data and security alerts, sending management commands,
//! and generating test traffic patterns for security testing.

use crate::acks::PendingAcks;
use crate::log::LogEvent;
use crate::netns::NsPool;
use crate::reply_addr::reply_address;
use crate::types::{
    CommandStatus, GuiCommand, LISTEN_ADDR, MGMT_ADDR, NetStats, NotSentReason, TrafficMode,
    UiEvent,
};
use anyhow::Context;
use rand::Rng;
use rand::SeedableRng;
use rand::rngs::StdRng;
use rand::seq::SliceRandom;
use sec_core::config::IP_ADDR;
use sec_core::security::alert::alert_packet;
use sec_core::security::hash::{MgmtKey, ReportKey};
use sec_core::security::mgmt::Command;
use sec_core::security::mgmt::mgmt_packet::MAX_PAYLOAD_LEN;
use sec_core::security::mgmt_auth::{MAX_PACKET_LEN, seal};
use sec_core::security::report_auth::{Report, ReportBody, ReportVerifier, Telemetry};
use std::net::{IpAddr, SocketAddr};
use std::ops::{Range, RangeInclusive};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::Sender;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::net::UdpSocket;
use tokio::sync::mpsc::UnboundedReceiver;

/// Namespace prefix used by `make setup_net_many`. Must match the
/// value in the Makefile.
const NETNS_PREFIX: &str = "sec-ns";
/// Default number of namespaces the pool expects at startup. The
/// `SEC_NS_COUNT` env var overrides it, and `make gui` sets that to the
/// `NS_COUNT` that `make setup_net_many` used.
const NETNS_DEFAULT_COUNT: usize = 200;

/// Seals `body` with the mgmt key and a fresh monotonic counter, then
/// ships the resulting authenticated packet to the kernel's mgmt port.
///
/// Every mgmt-plane command funnels through here so the counter and MAC
/// construction live in exactly one place — the kernel rejects anything
/// signed differently, so it must match `mgmt_auth::seal` byte-for-byte.
///
/// The command asks the kernel to report to this host's address on the
/// interface that routes to it, so its acks and alerts come back here.
///
/// Returns the sequence number the packet was sealed with, which the
/// kernel echoes in its ack, or why nothing was sent.
async fn send_sealed(
    sock: &UdpSocket,
    key: &MgmtKey,
    command: &Command,
) -> Result<u32, NotSentReason> {
    let reply_to = reply_address(MGMT_ADDR).map_err(|_| NotSentReason::NoReplyAddress)?;
    let counter = MGMT_COUNTER.next().ok_or(NotSentReason::KernelNotSeen)?;
    let mut body = [0u8; MAX_PAYLOAD_LEN];
    let body = command.encode(&mut body);
    let mut packet = [0u8; MAX_PACKET_LEN];
    let len =
        seal(key, counter, &reply_to, body, &mut packet).ok_or(NotSentReason::InvalidCommand)?;
    let _sent_bytes = sock
        .send_to(&packet[..len], MGMT_ADDR)
        .await
        .map_err(|e| NotSentReason::SendFailed(e.kind()))?;
    Ok(counter as u32)
}

/// Loads the mgmt key as [`mgmt_key::load`] finds it from the current
/// directory, exiting with the reason when there is none: without it the
/// dashboard can neither command the kernel nor trust its reports.
fn load_mgmt_key() -> MgmtKey {
    let loaded = std::env::current_dir()
        .context("cannot read the current directory")
        .and_then(|dir: std::path::PathBuf| Ok(mgmt_key::load(&dir)?));
    loaded.unwrap_or_else(|error| {
        eprintln!("[gui] {error:#}");
        std::process::exit(1);
    })
}

/// The mgmt counters this dashboard seals commands with.
static MGMT_COUNTER: MgmtCounter = MgmtCounter::new();

/// The last mgmt counter used, `(epoch << 32) | seq`, kept in step with the
/// kernel's own record so the next command is always one it accepts.
#[derive(Debug)]
struct MgmtCounter(AtomicU64);

impl MgmtCounter {
    const fn new() -> Self {
        Self(AtomicU64::new(0))
    }

    /// Takes in the epoch and last accepted sequence a telemetry report
    /// carries. Within one epoch the counter only moves forward, so a
    /// report older than commands already sent cannot rewind it; a new
    /// epoch (a kernel reboot) restarts it from the kernel's sequence.
    fn observe(&self, epoch: u32, last_accepted_seq: u32) {
        if epoch == 0 {
            return;
        }
        let reported = (u64::from(epoch) << 32) | u64::from(last_accepted_seq);
        let _ = self
            .0
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |last| {
                let same_epoch = last >> 32 == u64::from(epoch);
                Some(if same_epoch {
                    last.max(reported)
                } else {
                    reported
                })
            });
    }

    /// The counter for the next command, or `None` before any telemetry
    /// has announced the kernel's epoch or once this epoch's sequence is
    /// used up.
    fn next(&self) -> Option<u64> {
        self.0
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |last| {
                let has_epoch = last >> 32 != 0;
                let seq_left = last & u64::from(u32::MAX) != u64::from(u32::MAX);
                (has_epoch && seq_left).then_some(last + 1)
            })
            .ok()
            .map(|last| last + 1)
    }
}

/// Ephemeral sockets the generator sends from when no namespace pool is up.
const SOCKET_POOL_SIZE: usize = 50;

/// Enough for any report the kernel sends.
const REPORT_BUFFER_LEN: usize = 1024;

/// How often the task expires unacked commands and generates traffic.
const TICK: Duration = Duration::from_millis(1);

/// Talks to the kernel and generates test traffic for as long as the
/// dashboard runs: verifies reports into `stats` and `events`, seals and
/// sends the commands arriving on `commands`, and sends traffic in the
/// chosen mode.
///
/// # Errors
///
/// When a socket cannot be bound, such as the report port while another
/// dashboard holds it.
pub async fn start_background_task(
    stats: Arc<NetStats>,
    events: Sender<UiEvent>,
    mut commands: UnboundedReceiver<GuiCommand>,
) -> anyhow::Result<()> {
    let reports_socket = UdpSocket::bind(LISTEN_ADDR)
        .await
        .with_context(|| format!("bind {LISTEN_ADDR}"))?;
    let mgmt_socket = bind_ephemeral().await?;
    let mut generator = Generator::new(namespace_pool(), open_socket_pool().await?);
    let mgmt_key = load_mgmt_key();
    let mut reports = ReportVerifier::new(ReportKey::derive(&mgmt_key));
    let mut pending = PendingAcks::default();
    let mut mode = TrafficMode::Idle;
    let mut buf = [0u8; REPORT_BUFFER_LEN];
    loop {
        tokio::select! {
            Ok((len, _)) = reports_socket.recv_from(&mut buf) => {
                if let Some(report) = reports.verify(&buf[..len]) {
                    handle_report(report, &stats, &events, &mut pending);
                }
            }
            Some(command) = commands.recv() => match command {
                GuiCommand::SetMode(chosen) => mode = chosen,
                GuiCommand::Mgmt { id, command } => {
                    let status = match send_command(&mgmt_socket, &mgmt_key, &command, &events).await {
                        Ok(seq) => {
                            pending.sent(seq, id, Instant::now());
                            CommandStatus::Pending
                        }
                        Err(reason) => CommandStatus::NotSent(reason),
                    };
                    let _ = events.send(UiEvent::CommandStatus { id, status });
                }
            },
            () = tokio::time::sleep(TICK) => {
                for id in pending.expire(Instant::now()) {
                    let _ = events.send(UiEvent::CommandStatus { id, status: CommandStatus::NoAck });
                }
                generator.send(mode).await;
            }
        }
    }
}

/// Seals and sends `command`, logging a manual ban; the sequence the
/// kernel will ack it under, or why it was not sent.
async fn send_command(
    socket: &UdpSocket,
    key: &MgmtKey,
    command: &Command,
    events: &Sender<UiEvent>,
) -> Result<u32, NotSentReason> {
    if let Command::BanIp(ip) = *command {
        let _ = events.send(UiEvent::Log(LogEvent::ManualBan(ip)));
    }
    send_sealed(socket, key, command).await
}

async fn bind_ephemeral() -> anyhow::Result<UdpSocket> {
    UdpSocket::bind("0.0.0.0:0")
        .await
        .context("bind an ephemeral UDP socket")
}

async fn open_socket_pool() -> anyhow::Result<Vec<UdpSocket>> {
    let mut pool = Vec::with_capacity(SOCKET_POOL_SIZE);
    for _ in 0..SOCKET_POOL_SIZE {
        pool.push(bind_ephemeral().await?);
    }
    Ok(pool)
}

/// The namespaces `make setup_net_many` made, which give each packet a
/// distinct source address; `None`, with the reason printed, when they
/// cannot be used and the generator falls back to host sockets.
fn namespace_pool() -> Option<NsPool> {
    let count = std::env::var("SEC_NS_COUNT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(NETNS_DEFAULT_COUNT);
    match NsPool::try_init(NETNS_PREFIX, count) {
        Ok(pool) => {
            eprintln!("[netns] ready: {count} namespaces bound");
            Some(pool)
        }
        Err(error) => {
            eprintln!("[netns] {error}; falling back to host sockets");
            None
        }
    }
}

/// Requests to the kernel's port 80 per tick of normal traffic.
const NORMAL_REQUESTS: RangeInclusive<usize> = 1..=3;
/// Packets per tick of a DDoS burst: across 200 namespaces about 1500 pps
/// per source, well over the kernel's 100 pps ban threshold, where normal
/// traffic is about 10.
const DDOS_BURST: usize = 300;
/// The live simulation repeats every this many seconds...
const LIVE_CYCLE_SECS: u64 = 30;
/// ...and floods during these seconds of each cycle.
const LIVE_FLOOD_SECS: Range<u64> = 15..25;

/// Sends test traffic to the kernel, from namespaces when they are up.
struct Generator {
    namespaces: Option<NsPool>,
    sockets: Vec<UdpSocket>,
    rng: StdRng,
    started: Instant,
}

impl Generator {
    fn new(namespaces: Option<NsPool>, sockets: Vec<UdpSocket>) -> Self {
        Self {
            namespaces,
            sockets,
            rng: StdRng::from_entropy(),
            started: Instant::now(),
        }
    }

    /// One tick's traffic in `mode`.
    async fn send(&mut self, mode: TrafficMode) {
        match mode {
            TrafficMode::Idle => {}
            TrafficMode::Normal => self.normal_requests().await,
            TrafficMode::DDoS => self.ddos_burst().await,
            TrafficMode::Live => self.live_simulation().await,
        }
    }

    async fn normal_requests(&mut self) {
        for _ in 0..self.rng.gen_range(NORMAL_REQUESTS) {
            self.send_packet(80, b"GET / HTTP/1.1").await;
        }
    }

    /// A flood weighted toward common service ports.
    async fn ddos_burst(&mut self) {
        for _ in 0..DDOS_BURST {
            let port = match self.rng.gen_range(0..10) {
                0..=5 => 80,
                6..=7 => 443,
                8 => 53,
                _ => self.rng.gen_range(1024..65535),
            };
            self.send_packet(port, b"X").await;
        }
    }

    /// Normal traffic laced with injection attempts and NOP sleds, and a
    /// flood for part of every cycle.
    async fn live_simulation(&mut self) {
        self.normal_requests().await;
        if self.rng.gen_bool(0.10) {
            let attack: &[u8] = if self.rng.gen_bool(0.5) {
                b"UNION SELECT 1,2,3 --"
            } else {
                b"<script>alert(1)</script>"
            };
            self.send_packet(80, attack).await;
        }
        if self.rng.gen_bool(0.05) {
            let mut sled = vec![0x90; 16];
            sled.extend_from_slice(b"\xcc\xcc\xcc\xcc");
            self.send_packet(80, &sled).await;
        }
        let second = self.started.elapsed().as_secs() % LIVE_CYCLE_SECS;
        if LIVE_FLOOD_SECS.contains(&second) {
            self.ddos_burst().await;
        }
    }

    /// Sends `payload` to the kernel's `port` from a random namespace, or
    /// a random host socket without them. Test traffic, so a send that
    /// fails is just a lost packet.
    async fn send_packet(&mut self, port: u16, payload: &[u8]) {
        let target = SocketAddr::new(IpAddr::from(IP_ADDR), port);
        if let Some(pool) = &self.namespaces {
            let index = self.rng.gen_range(0..pool.len());
            pool.send(index, target, payload.to_vec());
        } else if let Some(socket) = self.sockets.choose(&mut self.rng) {
            let _ = socket.send_to(payload, target).await;
        }
    }
}

/// Applies one verified report from the kernel.
fn handle_report(
    report: Report<'_>,
    stats: &NetStats,
    events: &Sender<UiEvent>,
    pending: &mut PendingAcks,
) {
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    stats.last_seen.store(now_secs, Ordering::Relaxed);

    match ReportBody::parse(report.body) {
        Some(ReportBody::Telemetry(telemetry)) => {
            MGMT_COUNTER.observe(report.epoch, telemetry.last_mgmt_seq);
            record_telemetry(stats, &telemetry);
        }
        Some(ReportBody::Alert(alert)) => {
            let _ = events.send(UiEvent::Log(LogEvent::Alert(alert)));
        }
        Some(ReportBody::Ack(ack)) => {
            let _ = events.send(UiEvent::Log(LogEvent::Ack(ack)));
            if let Some((id, status)) = pending.acked(ack.seq, ack.outcome) {
                let _ = events.send(UiEvent::CommandStatus { id, status });
            }
        }
        None => {
            if let Some(unreadable) = unreadable_alert(report.body) {
                let _ = events.send(UiEvent::Log(unreadable));
            }
        }
    }
}

/// The log event for a report that did not decode, if it claims to be an
/// alert: a newer kernel's, say.
fn unreadable_alert(body: &[u8]) -> Option<LogEvent> {
    (body.first() == Some(&alert_packet::ALERT_MESSAGE_TYPE))
        .then_some(LogEvent::UnreadableAlert(body.len()))
}

/// Stores one interval's counters. The epoch is taken from the
/// authenticated envelope instead, and the last sequence feeds the mgmt
/// counter.
fn record_telemetry(stats: &NetStats, telemetry: &Telemetry) {
    stats.passed.store(telemetry.passed, Ordering::Relaxed);
    let _ = stats
        .total_passed
        .fetch_add(telemetry.passed, Ordering::Relaxed);
    for (gauge, value) in [
        (&stats.ddos, telemetry.ddos),
        (&stats.firewall, telemetry.firewall),
        (&stats.malware, telemetry.malware),
        (&stats.bpf, telemetry.bpf),
        (&stats.heuristic, telemetry.heuristic),
    ] {
        gauge.store(value, Ordering::Relaxed);
        let _ = stats.total_dropped.fetch_add(value, Ordering::Relaxed);
    }
    stats.flows.store(telemetry.active_flows, Ordering::Relaxed);
    stats.mgmt.store(telemetry.mgmt, Ordering::Relaxed);
}

#[cfg(test)]
mod tests {
    use super::*;
    use sec_core::security::dpi::Pattern;
    use sec_core::security::mgmt_auth::{MgmtAuth, OperatorAddr, seal, sealed_len};
    use std::net::Ipv4Addr;

    const TEST_KEY: MgmtKey = MgmtKey::new(*b"TEST-KEY-TEST!KE");
    const TEST_EPOCH: u32 = 0xABCD_1234;

    /// Seal `body` under a fresh verifier, round-trip it, and return
    /// the bytes the kernel would actually dispatch on. Failing to
    /// verify would mean the GUI is signing a packet the kernel will
    /// reject.
    fn seal_and_verify(body: &[u8]) -> Vec<u8> {
        let mut packet = vec![0u8; sealed_len(body.len())];
        let counter = ((TEST_EPOCH as u64) << 32) | 1;
        let operator = OperatorAddr {
            mac: [0x02, 0, 0, 0, 0, 0x01],
            ip: Ipv4Addr::new(192, 168, 100, 1),
        };
        let n =
            seal(&TEST_KEY, counter, &operator, body, &mut packet).expect("seal into sized buffer");
        let mut auth = MgmtAuth::new(TEST_KEY);
        auth.set_epoch(TEST_EPOCH);
        auth.verify(&packet[..n])
            .expect("sealed packet must verify with same key")
            .body
            .to_vec()
    }

    #[test]
    fn every_command_seals_into_a_body_the_kernel_parses_back() {
        let pattern = Pattern::new(b"DROP TABLE users").unwrap();
        let ip = Ipv4Addr::new(10, 0, 0, 42);
        let commands = [
            Command::BanIp(ip),
            Command::UnbanIp(ip),
            Command::BlockPort(8443),
            Command::UnblockPort(8443),
            Command::AddDpiPattern(pattern),
            Command::RemoveDpiPattern(pattern),
            Command::UploadBpf(crate::bpf::compile_bpf("BLOCK TCP DST 80").unwrap()),
            Command::UnloadBpf,
        ];
        for command in commands {
            let mut body = [0u8; MAX_PAYLOAD_LEN];

            let verified = seal_and_verify(command.encode(&mut body));

            assert_eq!(Command::parse(&verified), Ok(command));
        }
    }

    #[test]
    fn an_alert_that_does_not_decode_is_logged_as_unreadable() {
        let mut unknown_reason = [0u8; alert_packet::ALERT_BODY_LEN];
        unknown_reason[0] = alert_packet::ALERT_MESSAGE_TYPE;
        unknown_reason[alert_packet::REASON_OFFSET] = 99;

        let event = unreadable_alert(&unknown_reason);

        assert!(matches!(
            event,
            Some(LogEvent::UnreadableAlert(alert_packet::ALERT_BODY_LEN))
        ));
        assert!(unreadable_alert(&[]).is_none());
        assert!(unreadable_alert(&[0xEE; 8]).is_none());
    }

    const EPOCH: u32 = 0xDEAD_BEEF;

    fn counter(epoch: u32, seq: u32) -> u64 {
        (u64::from(epoch) << 32) | u64::from(seq)
    }

    #[test]
    fn mgmt_counter_has_nothing_to_offer_before_telemetry() {
        let mgmt = MgmtCounter::new();

        assert_eq!(mgmt.next(), None);
    }

    #[test]
    fn mgmt_counter_resumes_after_the_kernels_last_accepted_sequence() {
        let mgmt = MgmtCounter::new();

        mgmt.observe(EPOCH, 500);

        assert_eq!(mgmt.next(), Some(counter(EPOCH, 501)));
    }

    #[test]
    fn mgmt_counter_ignores_telemetry_older_than_commands_it_sent() {
        let mgmt = MgmtCounter::new();
        mgmt.observe(EPOCH, 500);
        let _ = mgmt.next();

        mgmt.observe(EPOCH, 400);

        assert_eq!(mgmt.next(), Some(counter(EPOCH, 502)));
    }

    #[test]
    fn mgmt_counter_restarts_from_the_kernels_sequence_after_a_reboot() {
        let mgmt = MgmtCounter::new();
        mgmt.observe(EPOCH, 9_000);

        mgmt.observe(EPOCH + 1, 0);

        assert_eq!(mgmt.next(), Some(counter(EPOCH + 1, 1)));
    }

    #[test]
    fn mgmt_counter_stops_when_the_epochs_sequence_is_used_up() {
        let mgmt = MgmtCounter::new();

        mgmt.observe(EPOCH, u32::MAX);

        assert_eq!(mgmt.next(), None);
    }
}

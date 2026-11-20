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
use sec_core::security::alert::alert_packet;
use sec_core::security::hash::{MgmtKey, ReportKey};
use sec_core::security::mgmt::Command;
use sec_core::security::mgmt::mgmt_packet::MAX_PAYLOAD_LEN;
use sec_core::security::mgmt_auth::{MAX_PACKET_LEN, seal};
use sec_core::security::report_auth::{Report, ReportBody, ReportVerifier, Telemetry};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::net::UdpSocket;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};

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
    let _ = sock.send_to(&packet[..len], MGMT_ADDR).await;
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

/// Main background task that runs continuously.
///
/// This function:
/// - Listens for UDP telemetry and alerts from the kernel
/// - Processes GUI commands and forwards them to the kernel
/// - Generates test traffic based on the current mode
pub async fn start_background_task(
    stats: Arc<NetStats>,
    events: UnboundedSender<UiEvent>,
    mut cmd_rx: UnboundedReceiver<GuiCommand>,
) -> anyhow::Result<()> {
    // Report bind failures (e.g. a previous GUI still holding the port)
    // instead of panicking.
    let socket = UdpSocket::bind(LISTEN_ADDR)
        .await
        .map_err(|e| anyhow::anyhow!("bind {LISTEN_ADDR}: {e}"))?;

    let mut socket_pool = Vec::new();
    for _ in 0..50 {
        let sock = UdpSocket::bind("0.0.0.0:0")
            .await
            .map_err(|e| anyhow::anyhow!("bind ephemeral: {e}"))?;
        socket_pool.push(sock);
    }

    // Namespaces from `make setup_net_many` give each packet a distinct
    // source IP; without them, fall back to the host socket pool.
    let ns_count: usize = std::env::var("SEC_NS_COUNT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(NETNS_DEFAULT_COUNT);
    let ns_pool = NsPool::try_init(NETNS_PREFIX, ns_count);

    let mut buf = vec![0u8; 1024];
    let mut mode = TrafficMode::Idle;
    let start_time = Instant::now();
    let mgmt_key = load_mgmt_key();
    let mut reports = ReportVerifier::new(ReportKey::derive(&mgmt_key));
    let mut pending = PendingAcks::default();

    let target_ip = std::net::IpAddr::from(sec_core::config::IP_ADDR);
    let target_80 = SocketAddr::new(target_ip, 80);

    let mut rng = StdRng::from_entropy();

    loop {
        tokio::select! {
            Ok((len, _)) = socket.recv_from(&mut buf) => {
                if let Some(report) = reports.verify(&buf[..len]) {
                    handle_report(report, &stats, &events, &mut pending);
                }
            }
            Some(cmd) = cmd_rx.recv() => {
                match cmd {
                    GuiCommand::SetMode(m) => mode = m,
                    GuiCommand::Mgmt { id, command } => {
                        if let Command::BanIp(ip) = *command {
                            let _ = events.send(UiEvent::Log(LogEvent::ManualBan(ip)));
                        }
                        let sent = send_sealed(&socket_pool[0], &mgmt_key, &command).await;
                        let status = match sent {
                            Ok(seq) => {
                                pending.sent(seq, id, Instant::now());
                                CommandStatus::Pending
                            }
                            Err(reason) => CommandStatus::NotSent(reason),
                        };
                        let _ = events.send(UiEvent::CommandStatus { id, status });
                    }
                }
            }
            () = tokio::time::sleep(Duration::from_millis(1)) => {
                for id in pending.expire(Instant::now()) {
                    let _ = events.send(UiEvent::CommandStatus { id, status: CommandStatus::NoAck });
                }
                // Across 200 namespaces, Normal is ~10 pps per source and DDoS
                // ~1500, either side of the kernel's 100 pps ban threshold.
                match mode {
                    TrafficMode::Normal => {
                        for _ in 0..rng.gen_range(1..=3) {
                            send_traffic(ns_pool.as_ref(), &socket_pool, &mut rng,
                                target_80, b"GET / HTTP/1.1".to_vec()).await;
                        }
                    }
                    TrafficMode::DDoS => {
                        for _ in 0..300 {
                            let port = match rng.gen_range(0..10) {
                                0..=5 => 80,
                                6..=7 => 443,
                                8 => 53,
                                _ => rng.gen_range(1024..65535)
                            };
                            let target = SocketAddr::new(target_ip, port);
                            send_traffic(ns_pool.as_ref(), &socket_pool, &mut rng,
                                target, b"X".to_vec()).await;
                        }
                    }
                    TrafficMode::Live => {
                        let elapsed = start_time.elapsed().as_secs() % 30;

                        for _ in 0..rng.gen_range(1..=3) {
                            send_traffic(ns_pool.as_ref(), &socket_pool, &mut rng,
                                target_80, b"GET / HTTP/1.1".to_vec()).await;
                        }

                        if rng.gen_bool(0.10) {
                            let payload: &[u8] = if rng.gen_bool(0.5) {
                                b"UNION SELECT 1,2,3 --"
                            } else {
                                b"<script>alert(1)</script>"
                            };
                            send_traffic(ns_pool.as_ref(), &socket_pool, &mut rng,
                                target_80, payload.to_vec()).await;
                        }

                        if rng.gen_bool(0.05) {
                            let mut payload = vec![0x90; 16];
                            payload.extend_from_slice(b"\xcc\xcc\xcc\xcc");
                            send_traffic(ns_pool.as_ref(), &socket_pool, &mut rng,
                                target_80, payload).await;
                        }

                        if (15..25).contains(&elapsed) {
                            for _ in 0..300 {
                                let port = match rng.gen_range(0..10) {
                                    0..=5 => 80,
                                    6..=7 => 443,
                                    8 => 53,
                                    _ => rng.gen_range(1024..65535)
                                };
                                let target = SocketAddr::new(target_ip, port);
                                send_traffic(ns_pool.as_ref(), &socket_pool, &mut rng,
                                    target, b"X".to_vec()).await;
                            }
                        }
                    }
                    TrafficMode::Idle => {}
                }
            }
        }
    }
}

/// Applies one verified report from the kernel.
fn handle_report(
    report: Report<'_>,
    stats: &NetStats,
    events: &UnboundedSender<UiEvent>,
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
    stats
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
        stats.total_dropped.fetch_add(value, Ordering::Relaxed);
    }
    stats.flows.store(telemetry.active_flows, Ordering::Relaxed);
    stats.mgmt.store(telemetry.mgmt, Ordering::Relaxed);
}

/// Send a test-traffic UDP packet. Prefers the per-namespace pool so
/// the packet carries a real, distinct source IP; falls back to the
/// host socket pool when netns init failed.
async fn send_traffic(
    ns_pool: Option<&NsPool>,
    socket_pool: &[UdpSocket],
    rng: &mut StdRng,
    dst: SocketAddr,
    payload: Vec<u8>,
) {
    if let Some(pool) = ns_pool {
        let idx = rng.gen_range(0..pool.len());
        pool.send(idx, dst, payload);
    } else if let Some(sock) = socket_pool.choose(rng) {
        let _ = sock.send_to(&payload, dst).await;
    }
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
            Command::UploadBpf(crate::app::compile_bpf("BLOCK TCP DST 80").unwrap()),
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

    #[test]
    fn forged_report_is_rejected() {
        let mut reports = ReportVerifier::new(ReportKey::derive(&TEST_KEY));
        let mut forged = [0u8; 64];
        let n = sec_core::security::report_auth::seal_report(
            &ReportKey::derive(&MgmtKey::new([0xAA; 16])),
            1,
            1,
            &[1],
            &mut forged,
        )
        .unwrap();

        assert!(reports.verify(&forged[..n]).is_none());
    }
}

//! Background network task for traffic generation and kernel communication.
//!
//! This module handles UDP communication with the security kernel, including
//! receiving telemetry data and security alerts, sending management commands,
//! and generating test traffic patterns for security testing.

use crate::netns::NsPool;
use crate::types::{GuiCommand, LISTEN_ADDR, LogEntry, MGMT_ADDR, NetStats, TrafficMode};
use eframe::egui;
use sec_core::security::alert::{AlertReason, alert_packet};
use sec_core::security::mgmt::ManagementMessageType;
use sec_core::security::mgmt_auth::seal;

/// Namespace prefix used by `make setup_net_many`. Must match the
/// value in the Makefile.
const NETNS_PREFIX: &str = "sec-ns";
/// Default number of namespaces the pool expects at startup. Can be
/// overridden with the `AEGIS_NS_COUNT` env var (e.g. for a lighter
/// dev setup with fewer bridges/veths). Must match the `N=` value
/// passed to `make setup_net_many`.
const NETNS_DEFAULT_COUNT: usize = 200;

/// Seals `body` with the mgmt key and a fresh monotonic counter, then
/// ships the resulting authenticated packet to the kernel's mgmt port.
///
/// Every mgmt-plane command funnels through here so the counter and MAC
/// construction live in exactly one place — the kernel rejects anything
/// signed differently, so it must match `mgmt_auth::seal` byte-for-byte.
///
/// Returns silently without sending if the boot epoch is not yet known
/// (no telemetry packet from the kernel has been seen). Sending under
/// epoch=0 is guaranteed to be rejected, so the operator would just see
/// a silently-discarded command.
async fn send_sealed(sock: &UdpSocket, key: &[u8; 16], body: &[u8]) {
    let Some(counter) = next_counter() else {
        eprintln!("[gui] dropping mgmt command: kernel epoch unknown (no telemetry yet)");
        return;
    };
    let mut packet = vec![0u8; 8 + body.len() + 8];
    if seal(key, counter, body, &mut packet).is_some() {
        let _ = sock.send_to(&packet, MGMT_ADDR).await;
    }
}
use rand::Rng;
use rand::SeedableRng;
use rand::rngs::StdRng;
use rand::seq::SliceRandom;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::net::UdpSocket;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};

/// Loads the mgmt MAC key from the first source that resolves:
///   1. `KERNEL_MGMT_KEY` env var (32 hex chars).
///   2. `.mgmt-key.local` at the workspace root (same file the kernel
///      build reads, materialised by `make dev-key`).
///
/// Exits the process on failure. The old debug-only fallback baked in a
/// constant key that was identical across every checkout — a binary
/// leaked from a developer laptop would then authenticate to any other
/// debug-built kernel on the network.
fn load_mgmt_key() -> [u8; 16] {
    if let Ok(hex) = std::env::var("KERNEL_MGMT_KEY") {
        if let Some(key) = parse_hex_key(&hex) {
            return key;
        }
        eprintln!("[gui] KERNEL_MGMT_KEY must be 32 hex chars");
    }

    if let Some(key) = read_dev_key_file() {
        return key;
    }

    eprintln!(
        "[gui] no mgmt key: set KERNEL_MGMT_KEY=<32 hex> or run `make dev-key` \
         to materialise .mgmt-key.local (shared with the kernel build)"
    );
    std::process::exit(1);
}

fn parse_hex_key(hex: &str) -> Option<[u8; 16]> {
    if hex.len() != 32 || !hex.as_bytes().iter().all(u8::is_ascii_hexdigit) {
        return None;
    }
    let mut out = [0u8; 16];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

fn read_dev_key_file() -> Option<[u8; 16]> {
    // Walk up from cwd looking for `.mgmt-key.local`. `make run` sets
    // KERNEL_MGMT_KEY directly, so this fallback only fires when the
    // dev runs `cargo run -p security-dashboard` from somewhere inside
    // the workspace.
    let mut dir = std::env::current_dir().ok()?;
    for _ in 0..5 {
        let candidate = dir.join(".mgmt-key.local");
        if candidate.exists() {
            let raw = std::fs::read_to_string(&candidate).ok()?;
            return parse_hex_key(raw.trim());
        }
        if !dir.pop() {
            break;
        }
    }
    None
}

/// Last boot epoch seen in a kernel telemetry packet. Zero means we
/// have not yet learned an epoch, in which case no mgmt packet can be
/// sealed (the kernel would reject every counter built around epoch 0).
static KERNEL_EPOCH: AtomicU32 = AtomicU32::new(0);

/// In-epoch monotonic sequence for outgoing mgmt packets. Initialised
/// from the low 32 bits of Unix-millis on first use so a GUI restart
/// within the same kernel epoch still picks a sequence above whatever
/// the previous instance sent. Reset to 0 whenever the kernel epoch
/// rotates (i.e. a kernel reboot).
static MGMT_SEQ: AtomicU32 = AtomicU32::new(0);

/// Records a kernel-advertised epoch. If it differs from what we last
/// saw, restart the in-epoch sequence so the first post-rotation packet
/// is `seq=1` and the kernel's freshly-zeroed `last_seq` accepts it.
fn observe_kernel_epoch(epoch: u32) {
    if epoch == 0 {
        return;
    }
    let prev = KERNEL_EPOCH.swap(epoch, Ordering::Relaxed);
    if prev != epoch {
        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u32)
            .unwrap_or(1);
        MGMT_SEQ.store(seed, Ordering::Relaxed);
    }
}

/// Builds the next mgmt counter as `(epoch << 32) | seq`, or returns
/// `None` if no telemetry has yet announced an epoch. The sequence
/// portion increments strictly for every packet; if it ever wraps to 0
/// (unreachable in practice — would need >4 billion mgmt commands in
/// one boot) we skip 0 so the kernel keeps accepting `seq > 0`.
fn next_counter() -> Option<u64> {
    let epoch = KERNEL_EPOCH.load(Ordering::Relaxed);
    if epoch == 0 {
        return None;
    }
    let mut seq = MGMT_SEQ.fetch_add(1, Ordering::Relaxed).wrapping_add(1);
    if seq == 0 {
        seq = MGMT_SEQ.fetch_add(1, Ordering::Relaxed).wrapping_add(1);
    }
    Some(((epoch as u64) << 32) | (seq as u64))
}

/// Main background task that runs continuously.
///
/// This function:
/// - Listens for UDP telemetry and alerts from the kernel
/// - Processes GUI commands and forwards them to the kernel
/// - Generates test traffic based on the current mode
///
/// # Arguments
///
/// * `stats` - Shared statistics structure updated with kernel telemetry
/// * `log_tx` - Channel sender for forwarding security alerts to the GUI
/// * `cmd_rx` - Channel receiver for commands from the GUI
pub async fn start_background_task(
    stats: Arc<NetStats>,
    log_tx: UnboundedSender<LogEntry>,
    mut cmd_rx: UnboundedReceiver<GuiCommand>,
) -> anyhow::Result<()> {
    // Fail loudly on bind errors — the alternative was `.unwrap()`,
    // which tips the whole dashboard over on something as common as
    // :1337 already being held by a previous GUI instance.
    let socket = UdpSocket::bind(LISTEN_ADDR)
        .await
        .map_err(|e| anyhow::anyhow!("bind {LISTEN_ADDR}: {e}"))?;
    let alert_socket = UdpSocket::bind("0.0.0.0:1337")
        .await
        .map_err(|e| anyhow::anyhow!("bind 0.0.0.0:1337: {e}"))?;

    let mut socket_pool = Vec::new();
    for _ in 0..50 {
        let sock = UdpSocket::bind("0.0.0.0:0")
            .await
            .map_err(|e| anyhow::anyhow!("bind ephemeral: {e}"))?;
        socket_pool.push(sock);
    }

    // Try to attach to the namespaces created by `make setup_net_many`.
    // When this succeeds, every generated packet's source IP is a real
    // in-kernel network stack — CMS per-source counters reflect actual
    // diversity instead of collapsing onto the handful of addresses a
    // host-bound socket pool can present. When it fails (no setup run,
    // no CAP_SYS_ADMIN), we log and fall back to `socket_pool` so the
    // GUI still starts and the user sees traffic, even if the
    // heavy-hitter behaviour is unrealistic.
    let ns_count: usize = std::env::var("AEGIS_NS_COUNT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(NETNS_DEFAULT_COUNT);
    let ns_pool = NsPool::try_init(NETNS_PREFIX, ns_count);

    let mut buf = vec![0u8; 1024];
    let mut alert_buf = vec![0u8; 1024];
    let mut mode = TrafficMode::Idle;
    let start_time = Instant::now();
    let mgmt_key = load_mgmt_key();

    let target_ip: std::net::IpAddr = "192.168.100.2".parse().unwrap();
    let target_80 = SocketAddr::new(target_ip, 80);

    let mut rng = StdRng::from_entropy();

    loop {
        tokio::select! {
            Ok((len, _)) = socket.recv_from(&mut buf) => {
                let data = &buf[..len];
                let now_secs = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
                stats.last_seen.store(now_secs, Ordering::Relaxed);

                if len >= 80 && data[0] != alert_packet::ALERT_MESSAGE_TYPE {
                    for i in 0..10 {
                        let val = u64::from_be_bytes(data[i*8..(i+1)*8].try_into().unwrap());
                        match i {
                            0 => {
                                stats.passed.store(val, Ordering::Relaxed);
                                stats.total_passed.fetch_add(val, Ordering::Relaxed);
                            }
                            1 => {
                                stats.ddos.store(val, Ordering::Relaxed);
                                stats.total_dropped.fetch_add(val, Ordering::Relaxed);
                            }
                            2 => {
                                stats.fw.store(val, Ordering::Relaxed);
                                stats.total_dropped.fetch_add(val, Ordering::Relaxed);
                            }
                            3 => {
                                stats.mal.store(val, Ordering::Relaxed);
                                stats.total_dropped.fetch_add(val, Ordering::Relaxed);
                            }
                            4 => {
                                stats.bpf.store(val, Ordering::Relaxed);
                                stats.total_dropped.fetch_add(val, Ordering::Relaxed);
                            }
                            5 => {
                                stats.heur.store(val, Ordering::Relaxed);
                                stats.total_dropped.fetch_add(val, Ordering::Relaxed);
                            }
                            6 => {
                                stats.memory.store(val, Ordering::Relaxed);
                            }
                            7 => {
                                stats.flows.store(val, Ordering::Relaxed);
                            }
                            8 => {
                                stats.mgmt.store(val, Ordering::Relaxed);
                            }
                            9 => {
                                observe_kernel_epoch(val as u32);
                            }
                            _ => {}
                        }
                    }
                } else if data[0] == alert_packet::ALERT_MESSAGE_TYPE {
                    let msg = parse_alert(data);
                    let _ = log_tx.send(msg);
                }
            }
            Ok((len, _)) = alert_socket.recv_from(&mut alert_buf) => {
                let data = &alert_buf[..len];
                if data[0] == alert_packet::ALERT_MESSAGE_TYPE {
                    let msg = parse_alert(data);
                    let _ = log_tx.send(msg);
                }
            }
            Some(cmd) = cmd_rx.recv() => {
                match cmd {
                    GuiCommand::SetMode(m) => mode = m,
                    GuiCommand::BanIp(ip_str) => {
                        if let Ok(ip) = ip_str.parse::<std::net::Ipv4Addr>() {
                            let body = build_ban_ip_body(ip);
                            send_sealed(&socket_pool[0], &mgmt_key, &body).await;

                            let entry = LogEntry {
                                timestamp: 0.0,
                                src_ip: "Localhost".to_string(),
                                dst_ip: String::new(),
                                src_port: 0,
                                dst_port: 0,
                                protocol: 0,
                                packet_len: 0,
                                msg: format!("MANUAL BAN: {ip_str}"),
                                color: egui::Color32::from_rgb(255, 0, 255),
                            };
                            let _ = log_tx.send(entry);
                        }
                    }
                    GuiCommand::BlockPort(port) => {
                        let body = build_block_port_body(port);
                        send_sealed(&socket_pool[0], &mgmt_key, &body).await;
                    }
                    GuiCommand::AddDpiPattern(pattern) => {
                        if let Some(body) = build_add_dpi_body(&pattern) {
                            send_sealed(&socket_pool[0], &mgmt_key, &body).await;
                        }
                    }
                    GuiCommand::UploadBpf(bytecode) => {
                        if let Some(body) = build_upload_bpf_body(&bytecode) {
                            send_sealed(&socket_pool[0], &mgmt_key, &body).await;
                        }
                    }
                }
            }
            () = tokio::time::sleep(Duration::from_millis(1)) => {
                // Rates are tuned against the kernel's CMS heavy-hitter
                // threshold (100 pps/source). With N real source IPs
                // (netns mode) the per-source rate is total/N:
                //   Normal 2 pkts/tick × ~1000 ticks/s ÷ 200 ns ≈ 10 pps/src
                //   DDoS 300 pkts/tick × ~1000 ticks/s ÷ 200 ns ≈ 1500 pps/src
                // So Normal passes; DDoS lights up HH on every source.
                // Fallback (host-pool) still roughly works since 50
                // sockets × 10 pps = 500 pps/src — over HH — which
                // surfaces the "you need netns for Normal" failure
                // mode loudly rather than silently.
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

/// Parses a security alert packet received from the kernel.
///
/// Alert packets contain a reason code, source IP address, and optional
/// payload data. This function extracts this information and creates a
/// LogEntry with appropriate formatting and color coding.
///
/// # Arguments
///
/// * `data` - Raw UDP payload containing the alert data
///
/// # Returns
///
/// A LogEntry with parsed alert information and formatted message.
fn parse_alert(data: &[u8]) -> LogEntry {
    // The GUI binds 0.0.0.0:1337 for alerts, so anyone on the segment
    // can send a one-byte `\x02` and reach this function. Short-circuit
    // before any fixed-offset index would panic the whole dashboard.
    if data.len() < alert_packet::ALERT_BODY_LEN {
        return LogEntry {
            timestamp: 0.0,
            src_ip: String::new(),
            dst_ip: String::new(),
            src_port: 0,
            dst_port: 0,
            protocol: 0,
            packet_len: data.len().min(u16::MAX as usize) as u16,
            msg: format!("[MALFORMED] short alert packet ({} bytes)", data.len()),
            color: egui::Color32::from_rgb(255, 80, 0),
        };
    }
    let reason_byte = data[alert_packet::REASON_OFFSET];
    let src_ip_bytes = &data[alert_packet::SRC_IP_OFFSET
        ..alert_packet::SRC_IP_OFFSET + alert_packet::SRC_IP_SIZE];
    let ip = format!(
        "{}.{}.{}.{}",
        src_ip_bytes[0], src_ip_bytes[1], src_ip_bytes[2], src_ip_bytes[3],
    );
    let dst_ip_bytes = &data[alert_packet::DST_IP_OFFSET
        ..alert_packet::DST_IP_OFFSET + alert_packet::SRC_IP_SIZE];
    let dst_ip = format!(
        "{}.{}.{}.{}",
        dst_ip_bytes[0], dst_ip_bytes[1], dst_ip_bytes[2], dst_ip_bytes[3],
    );
    let src_port = u16::from_be_bytes([
        data[alert_packet::SRC_PORT_OFFSET],
        data[alert_packet::SRC_PORT_OFFSET + 1],
    ]);
    let dst_port = u16::from_be_bytes([
        data[alert_packet::DST_PORT_OFFSET],
        data[alert_packet::DST_PORT_OFFSET + 1],
    ]);
    let protocol = data[alert_packet::PROTOCOL_OFFSET];
    let packet_len = u16::from_be_bytes([
        data[alert_packet::PACKET_LEN_OFFSET],
        data[alert_packet::PACKET_LEN_OFFSET + 1],
    ]);

    let (msg, color) = match AlertReason::from_u8(reason_byte) {
        Some(AlertReason::Ddos) => (
            format!("[DDoS] High Volume from {ip}"),
            egui::Color32::YELLOW,
        ),
        Some(AlertReason::Firewall) => (
            format!("[FIREWALL] Blocked Port access from {ip}"),
            egui::Color32::RED,
        ),
        Some(AlertReason::Malware) => (
            format!("[MALWARE] Signature Match from {ip}"),
            egui::Color32::RED,
        ),
        Some(AlertReason::Ebpf) => (
            format!("[eBPF] Custom Filter Drop from {ip}"),
            egui::Color32::LIGHT_BLUE,
        ),
        Some(AlertReason::Heuristic) => (
            format!("[HEURISTIC] Anomaly Detected from {ip}"),
            egui::Color32::from_rgb(255, 0, 255),
        ),
        Some(AlertReason::Flow) => (
            format!("[FLOW] New Connection from {ip}"),
            egui::Color32::LIGHT_BLUE,
        ),
        Some(AlertReason::Pass) => (
            format!("[PASS] Allowed from {ip}"),
            egui::Color32::from_gray(140),
        ),
        Some(AlertReason::MgmtAuthFail) => (
            format!("[MGMT AUTH] Rejected unsigned/replayed mgmt packet from {ip}"),
            egui::Color32::from_rgb(255, 80, 0),
        ),
        Some(AlertReason::BpfReject) => (
            format!("[BPF REJECT] Malformed BPF program from {ip}"),
            egui::Color32::from_rgb(255, 80, 0),
        ),
        Some(AlertReason::MgmtRejected) => (
            format!("[MGMT REJECT] Mgmt command dropped (table full) from {ip}"),
            egui::Color32::from_rgb(255, 80, 0),
        ),
        None => ("Unknown Alert".to_string(), egui::Color32::GRAY),
    };

    LogEntry {
        timestamp: 0.0,
        src_ip: ip,
        dst_ip,
        src_port,
        dst_port,
        protocol,
        packet_len,
        msg,
        color,
    }
}

/// Build the unsealed body for a `BanIp` command. The kernel reads
/// the type byte at offset 0 and the 4-byte IP at offsets 1..5.
fn build_ban_ip_body(ip: std::net::Ipv4Addr) -> [u8; 5] {
    let mut body = [0u8; 5];
    body[0] = ManagementMessageType::BanIp as u8;
    body[1..].copy_from_slice(&ip.octets());
    body
}

/// Build the unsealed body for a `BlockPort` command (type byte +
/// big-endian u16).
fn build_block_port_body(port: u16) -> [u8; 3] {
    let mut body = [0u8; 3];
    body[0] = ManagementMessageType::BlockPort as u8;
    body[1..3].copy_from_slice(&port.to_be_bytes());
    body
}

/// Build the unsealed body for an `AddDpiPattern` command, or return
/// `None` if the pattern is empty or longer than the kernel's cap.
/// Caps enforced here match `mgmt_packet::add_dpi::MAX_PATTERN_LEN`;
/// a pattern past that would be rejected by the dispatcher silently,
/// so filter here to avoid shipping a packet doomed to fail.
fn build_add_dpi_body(pattern: &[u8]) -> Option<Vec<u8>> {
    use sec_core::security::mgmt::mgmt_packet::add_dpi;
    if pattern.is_empty() || pattern.len() > add_dpi::MAX_PATTERN_LEN {
        return None;
    }
    let mut body = Vec::with_capacity(2 + pattern.len());
    body.push(ManagementMessageType::AddDpiPattern as u8);
    body.push(pattern.len() as u8);
    body.extend_from_slice(pattern);
    Some(body)
}

/// Build the unsealed body for an `UploadBpfProgram` command. Returns
/// `None` if the bytecode is empty, not a multiple of `INSTR_SIZE`,
/// or exceeds `MAX_INSTR_COUNT` — all of which the kernel would
/// reject.
fn build_upload_bpf_body(bytecode: &[u8]) -> Option<Vec<u8>> {
    use sec_core::security::mgmt::mgmt_packet::upload_bpf;
    if bytecode.is_empty()
        || bytecode.len() % upload_bpf::INSTR_SIZE != 0
        || bytecode.len() / upload_bpf::INSTR_SIZE > upload_bpf::MAX_INSTR_COUNT
    {
        return None;
    }
    let count = bytecode.len() / upload_bpf::INSTR_SIZE;
    let mut body = Vec::with_capacity(2 + bytecode.len());
    body.push(ManagementMessageType::UploadBpfProgram as u8);
    body.push(count as u8);
    body.extend_from_slice(bytecode);
    Some(body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sec_core::security::alert::{AlertReason, alert_packet};
    use sec_core::security::mgmt::{ManagementMessageType, mgmt_packet};
    use sec_core::security::mgmt_auth::{MgmtAuth, seal};

    const TEST_KEY: [u8; 16] = *b"TEST-KEY-TEST!KE";
    const TEST_EPOCH: u32 = 0xABCD_1234;

    /// Seal `body` under a fresh verifier, round-trip it, and return
    /// the bytes the kernel would actually dispatch on. Failing to
    /// verify would mean the GUI is signing a packet the kernel will
    /// reject — which was the original C1 bug.
    fn seal_and_verify(body: &[u8]) -> Vec<u8> {
        let mut packet = vec![0u8; 8 + body.len() + 8];
        let counter = ((TEST_EPOCH as u64) << 32) | 1;
        let n = seal(&TEST_KEY, counter, body, &mut packet).expect("seal into sized buffer");
        let mut auth = MgmtAuth::new(TEST_KEY);
        auth.set_epoch(TEST_EPOCH);
        auth.verify(&packet[..n])
            .expect("sealed packet must verify with same key")
            .to_vec()
    }

    // ----- mgmt packet construction (covers C1 regression) -----

    #[test]
    fn ban_ip_body_roundtrips_to_kernel_view() {
        let body = build_ban_ip_body(std::net::Ipv4Addr::new(10, 0, 0, 42));
        let verified = seal_and_verify(&body);
        assert_eq!(verified[0], ManagementMessageType::BanIp as u8);
        assert_eq!(
            &verified[mgmt_packet::ban_ip::IP_OFFSET..mgmt_packet::ban_ip::IP_OFFSET + 4],
            &[10, 0, 0, 42],
        );
    }

    #[test]
    fn block_port_body_roundtrips_to_kernel_view() {
        let body = build_block_port_body(8443);
        let verified = seal_and_verify(&body);
        assert_eq!(verified[0], ManagementMessageType::BlockPort as u8);
        let port = u16::from_be_bytes([
            verified[mgmt_packet::block_port::PORT_OFFSET],
            verified[mgmt_packet::block_port::PORT_OFFSET + 1],
        ]);
        assert_eq!(port, 8443);
    }

    #[test]
    fn add_dpi_body_roundtrips_to_kernel_view() {
        let pattern = b"DROP TABLE users";
        let body = build_add_dpi_body(pattern).expect("within cap");
        let verified = seal_and_verify(&body);
        assert_eq!(verified[0], ManagementMessageType::AddDpiPattern as u8);
        let len = verified[mgmt_packet::add_dpi::LEN_OFFSET] as usize;
        assert_eq!(len, pattern.len());
        assert_eq!(
            &verified[mgmt_packet::add_dpi::PATTERN_OFFSET
                ..mgmt_packet::add_dpi::PATTERN_OFFSET + len],
            pattern,
        );
    }

    #[test]
    fn add_dpi_rejects_empty_and_oversize() {
        assert!(build_add_dpi_body(&[]).is_none());
        let too_big =
            vec![0xAA; sec_core::security::mgmt::mgmt_packet::add_dpi::MAX_PATTERN_LEN + 1];
        assert!(build_add_dpi_body(&too_big).is_none());
    }

    #[test]
    fn upload_bpf_body_roundtrips_to_kernel_view() {
        use mgmt_packet::upload_bpf;
        // Two instructions (7 bytes each) so the count-byte and body
        // lengths are non-trivially entwined.
        let bytecode = vec![0u8; upload_bpf::INSTR_SIZE * 2];
        let body = build_upload_bpf_body(&bytecode).expect("valid bytecode");
        let verified = seal_and_verify(&body);
        assert_eq!(verified[0], ManagementMessageType::UploadBpfProgram as u8);
        let count = verified[upload_bpf::COUNT_OFFSET] as usize;
        assert_eq!(count, 2);
        assert_eq!(
            &verified[upload_bpf::INSTR_OFFSET..upload_bpf::INSTR_OFFSET + bytecode.len()],
            &bytecode[..],
        );
    }

    #[test]
    fn upload_bpf_rejects_malformed_bytecode() {
        use mgmt_packet::upload_bpf;
        assert!(build_upload_bpf_body(&[]).is_none());
        // Not a multiple of INSTR_SIZE.
        assert!(build_upload_bpf_body(&[0u8; 3]).is_none());
        // Exceeds MAX_INSTR_COUNT.
        let too_many = vec![0u8; upload_bpf::INSTR_SIZE * (upload_bpf::MAX_INSTR_COUNT + 1)];
        assert!(build_upload_bpf_body(&too_many).is_none());
    }

    // ----- alert parser (covers H3 regression) -----

    /// Build a well-formed 17-byte alert body with all metadata fields
    /// set to recognisable canary values.
    fn make_alert(reason: u8) -> Vec<u8> {
        let mut data = vec![0u8; alert_packet::ALERT_BODY_LEN];
        data[0] = alert_packet::ALERT_MESSAGE_TYPE;
        data[alert_packet::REASON_OFFSET] = reason;
        data[alert_packet::SRC_IP_OFFSET..alert_packet::SRC_IP_OFFSET + 4]
            .copy_from_slice(&[192, 168, 1, 50]);
        data[alert_packet::DST_IP_OFFSET..alert_packet::DST_IP_OFFSET + 4]
            .copy_from_slice(&[10, 0, 0, 1]);
        data[alert_packet::SRC_PORT_OFFSET..alert_packet::SRC_PORT_OFFSET + 2]
            .copy_from_slice(&1234u16.to_be_bytes());
        data[alert_packet::DST_PORT_OFFSET..alert_packet::DST_PORT_OFFSET + 2]
            .copy_from_slice(&80u16.to_be_bytes());
        data[alert_packet::PROTOCOL_OFFSET] = 6;
        data[alert_packet::PACKET_LEN_OFFSET..alert_packet::PACKET_LEN_OFFSET + 2]
            .copy_from_slice(&512u16.to_be_bytes());
        data
    }

    #[test]
    fn alert_parser_recovers_every_reason_variant() {
        let cases = [
            (AlertReason::Ddos, "[DDoS]"),
            (AlertReason::Firewall, "[FIREWALL]"),
            (AlertReason::Malware, "[MALWARE]"),
            (AlertReason::Ebpf, "[eBPF]"),
            (AlertReason::Heuristic, "[HEURISTIC]"),
            (AlertReason::Flow, "[FLOW]"),
            (AlertReason::Pass, "[PASS]"),
            (AlertReason::MgmtAuthFail, "[MGMT AUTH]"),
            (AlertReason::BpfReject, "[BPF REJECT]"),
        ];
        for (reason, tag) in cases {
            let data = make_alert(reason.as_u8());
            let entry = parse_alert(&data);
            assert!(
                entry.msg.starts_with(tag),
                "reason {reason:?} → msg {:?} should start with {tag}",
                entry.msg,
            );
            assert_eq!(entry.src_ip, "192.168.1.50");
            assert_eq!(entry.dst_ip, "10.0.0.1");
            assert_eq!(entry.src_port, 1234);
            assert_eq!(entry.dst_port, 80);
            assert_eq!(entry.protocol, 6);
            assert_eq!(entry.packet_len, 512);
        }
    }

    #[test]
    fn alert_parser_rejects_every_short_packet_length() {
        // H3 regression: the GUI binds 0.0.0.0:1337, so a one-byte UDP
        // `\x02` from anywhere on the segment would panic parse_alert
        // before the length guard. Walk every short length.
        for n in 0..alert_packet::ALERT_BODY_LEN {
            let data = vec![0x02u8; n];
            let entry = parse_alert(&data);
            assert!(
                entry.msg.starts_with("[MALFORMED]"),
                "len {n} → expected MALFORMED, got {:?}",
                entry.msg,
            );
        }
    }

    #[test]
    fn next_counter_is_none_until_kernel_epoch_observed() {
        // Run in an isolated process via a forked test would be ideal,
        // but the static atomics are process-wide. Snapshot, mutate,
        // restore so the test is independent of others' ordering.
        let saved_epoch = KERNEL_EPOCH.swap(0, Ordering::Relaxed);
        let saved_seq = MGMT_SEQ.swap(0, Ordering::Relaxed);

        assert!(next_counter().is_none(), "no telemetry seen → no counter");
        observe_kernel_epoch(0xDEAD_BEEF);
        let c = next_counter().expect("epoch known → counter available");
        assert_eq!((c >> 32) as u32, 0xDEAD_BEEF, "epoch in high 32 bits");

        KERNEL_EPOCH.store(saved_epoch, Ordering::Relaxed);
        MGMT_SEQ.store(saved_seq, Ordering::Relaxed);
    }

    #[test]
    fn alert_parser_handles_unknown_reason_byte() {
        let data = make_alert(99);
        let entry = parse_alert(&data);
        assert_eq!(entry.msg, "Unknown Alert");
    }
}

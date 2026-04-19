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
async fn send_sealed(sock: &UdpSocket, key: &[u8; 16], body: &[u8]) {
    let mut packet = vec![0u8; 8 + body.len() + 8];
    if seal(key, next_counter(), body, &mut packet).is_some() {
        let _ = sock.send_to(&packet, MGMT_ADDR).await;
    }
}
use rand::Rng;
use rand::SeedableRng;
use rand::rngs::StdRng;
use rand::seq::SliceRandom;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::net::UdpSocket;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};

/// Loads the mgmt MAC key from `KERNEL_MGMT_KEY` (32 hex chars) or
/// falls back to the dev key the kernel uses when built without one.
/// The kernel rejects mgmt packets signed with the wrong key, so this
/// must match what the kernel was built with.
fn load_mgmt_key() -> [u8; 16] {
    if let Ok(hex) = std::env::var("KERNEL_MGMT_KEY") {
        if hex.len() == 32 {
            let mut out = [0u8; 16];
            for (i, b) in out.iter_mut().enumerate() {
                let hi = u8::from_str_radix(&hex[i * 2..i * 2 + 1], 16).unwrap_or(0);
                let lo = u8::from_str_radix(&hex[i * 2 + 1..i * 2 + 2], 16).unwrap_or(0);
                *b = (hi << 4) | lo;
            }
            return out;
        }
        eprintln!("KERNEL_MGMT_KEY must be 32 hex chars");
    } else {
        eprintln!("KERNEL_MGMT_KEY not set");
    }

    // The kernel's build.rs refuses release builds without KERNEL_MGMT_KEY;
    // mirror that here so a release-built GUI can't silently sign packets
    // with the hard-coded dev key and have every mgmt command rejected
    // by the kernel at the kind of subtle distance that wastes an hour
    // of debugging.
    #[cfg(not(debug_assertions))]
    {
        eprintln!(
            "[gui] release build requires KERNEL_MGMT_KEY — refusing to use the dev-only fallback"
        );
        std::process::exit(1);
    }
    #[cfg(debug_assertions)]
    {
        eprintln!("[gui] debug build — falling back to DEV-KEY-DEV-KEY!");
        *b"DEV-KEY-DEV-KEY!"
    }
}

/// Strictly-monotonic counter for outgoing mgmt packets.
///
/// Uses Unix-nanos so we always exceed whatever the kernel saw last,
/// even across operator restarts. The kernel resets `last_counter` to
/// 0 on boot, so the GUI never has to coordinate with kernel state.
fn next_counter() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(1)
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

                if len >= 72 && data[0] != alert_packet::ALERT_MESSAGE_TYPE {
                    for i in 0..9 {
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
                            let mut body = [0u8; 5];
                            body[0] = ManagementMessageType::BanIp as u8;
                            body[1..].copy_from_slice(&ip.octets());
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
                        let mut body = [0u8; 3];
                        body[0] = ManagementMessageType::BlockPort as u8;
                        body[1..3].copy_from_slice(&port.to_be_bytes());
                        send_sealed(&socket_pool[0], &mgmt_key, &body).await;
                    }
                    GuiCommand::AddDpiPattern(pattern) => {
                        // Kernel caps patterns at add_dpi::MAX_PATTERN_LEN (32).
                        // Anything larger gets rejected silently by the
                        // dispatcher, so cap here too rather than shipping a
                        // packet that will be dropped.
                        use sec_core::security::mgmt::mgmt_packet::add_dpi;
                        if pattern.is_empty() || pattern.len() > add_dpi::MAX_PATTERN_LEN {
                            continue;
                        }
                        let mut body = Vec::with_capacity(2 + pattern.len());
                        body.push(ManagementMessageType::AddDpiPattern as u8);
                        body.push(pattern.len() as u8);
                        body.extend_from_slice(&pattern);
                        send_sealed(&socket_pool[0], &mgmt_key, &body).await;
                    }
                    GuiCommand::UploadBpf(bytecode) => {
                        // Each instruction is INSTR_SIZE bytes; the kernel
                        // accepts up to MAX_INSTR_COUNT of them. Reject
                        // anything malformed before we bother signing it.
                        use sec_core::security::mgmt::mgmt_packet::upload_bpf;
                        if bytecode.is_empty()
                            || bytecode.len() % upload_bpf::INSTR_SIZE != 0
                            || bytecode.len() / upload_bpf::INSTR_SIZE
                                > upload_bpf::MAX_INSTR_COUNT
                        {
                            continue;
                        }
                        let count = bytecode.len() / upload_bpf::INSTR_SIZE;
                        let mut body = Vec::with_capacity(2 + bytecode.len());
                        body.push(ManagementMessageType::UploadBpfProgram as u8);
                        body.push(count as u8);
                        body.extend_from_slice(&bytecode);
                        send_sealed(&socket_pool[0], &mgmt_key, &body).await;
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

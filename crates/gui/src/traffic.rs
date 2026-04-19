//! Background network task for traffic generation and kernel communication.
//!
//! This module handles UDP communication with the security kernel, including
//! receiving telemetry data and security alerts, sending management commands,
//! and generating test traffic patterns for security testing.

use crate::types::{
    GuiCommand, LISTEN_ADDR, LogEntry, MGMT_ADDR, NetStats, TARGET_ADDR, TrafficMode,
};
use eframe::egui;
use sec_core::security::alert::{AlertReason, alert_packet};
use sec_core::security::mgmt::ManagementMessageType;
use sec_core::security::mgmt_auth::seal;

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
        eprintln!("KERNEL_MGMT_KEY must be 32 hex chars; falling back to dev key");
    }
    *b"DEV-KEY-DEV-KEY!"
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
) {
    let socket = UdpSocket::bind(LISTEN_ADDR).await.unwrap();
    let alert_socket = UdpSocket::bind("0.0.0.0:1337").await.unwrap();

    let mut socket_pool = Vec::new();
    for _ in 0..50 {
        let sock = UdpSocket::bind("0.0.0.0:0").await.unwrap();
        socket_pool.push(sock);
    }

    let mut buf = vec![0u8; 1024];
    let mut alert_buf = vec![0u8; 1024];
    let mut mode = TrafficMode::Idle;
    let start_time = Instant::now();
    let mgmt_key = load_mgmt_key();

    let target_ip: std::net::IpAddr = "192.168.100.2".parse().unwrap();

    let mut rng = StdRng::from_entropy();

    let mut botnet = Vec::new();
    for _ in 0..50 {
        botnet.push([10, rng.r#gen(), rng.r#gen(), rng.r#gen()]);
    }

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
                match mode {
                    TrafficMode::Normal => {
                        let count = rng.gen_range(80..=120);
                        for _ in 0..count {
                            let payload = build_spoofed_packet(&mut rng, None, b"GET / HTTP/1.1");
                            let sock = socket_pool.choose(&mut rng).unwrap();
                            let _ = sock.send_to(&payload, TARGET_ADDR).await;
                        }
                    }
                    TrafficMode::DDoS => {
                        for _ in 0..1200 {
                            let bot_ip = botnet.choose(&mut rng).copied();
                            let payload = build_spoofed_packet(&mut rng, bot_ip, b"X");

                            let port = match rng.gen_range(0..10) {
                                0..=5 => 80,
                                6..=7 => 443,
                                8 => 53,
                                _ => rng.gen_range(1024..65535)
                            };
                            let target = SocketAddr::new(target_ip, port);

                            let sock = socket_pool.choose(&mut rng).unwrap();
                            let _ = sock.send_to(&payload, target).await;
                        }
                    }
                    TrafficMode::Live => {
                        let elapsed = start_time.elapsed().as_secs() % 30;

                        let count = rng.gen_range(60..=100);
                        for _ in 0..count {
                            let payload = build_spoofed_packet(&mut rng, None, b"GET / HTTP/1.1");
                            let sock = socket_pool.choose(&mut rng).unwrap();
                            let _ = sock.send_to(&payload, TARGET_ADDR).await;
                        }

                        if rng.gen_bool(0.10) {
                            let payload: &[u8] = if rng.gen_bool(0.5) {
                                b"UNION SELECT 1,2,3 --"
                            } else {
                                b"<script>alert(1)</script>"
                            };
                            let payload = build_spoofed_packet(&mut rng, None, payload);
                            let sock = socket_pool.choose(&mut rng).unwrap();
                            let _ = sock.send_to(&payload, TARGET_ADDR).await;
                        }

                        if rng.gen_bool(0.05) {
                            let mut payload = vec![0x90; 16];
                            payload.extend_from_slice(b"\xcc\xcc\xcc\xcc");
                            let payload = build_spoofed_packet(&mut rng, None, &payload);
                            let sock = socket_pool.choose(&mut rng).unwrap();
                            let _ = sock.send_to(&payload, TARGET_ADDR).await;
                        }

                        if (15..25).contains(&elapsed) {
                            for _ in 0..1200 {
                                let bot_ip = botnet.choose(&mut rng).copied();
                                let payload = build_spoofed_packet(&mut rng, bot_ip, b"X");

                                let port = match rng.gen_range(0..10) {
                                    0..=5 => 80,
                                    6..=7 => 443,
                                    8 => 53,
                                    _ => rng.gen_range(1024..65535)
                                };
                                let target = SocketAddr::new(target_ip, port);

                                let sock = socket_pool.choose(&mut rng).unwrap();
                                let _ = sock.send_to(&payload, target).await;
                            }
                        }
                    }
                    TrafficMode::Idle => {}
                }
            }
        }
    }
}

/// Constructs a spoofed UDP packet with custom source IP and payload.
///
/// The packet format includes a magic header (0xAE617300) followed by
/// the source IP address and the payload data. This format is recognized
/// by the kernel for testing IP spoofing detection.
///
/// # Arguments
///
/// * `rng` - Random number generator for generating random source IPs
/// * `fixed_ip` - Optional fixed source IP, otherwise randomly generated
/// * `payload` - Packet payload data
///
/// # Returns
///
/// A byte vector containing the complete spoofed packet.
fn build_spoofed_packet(rng: &mut StdRng, fixed_ip: Option<[u8; 4]>, payload: &[u8]) -> Vec<u8> {
    let mut packet = Vec::with_capacity(8 + payload.len());
    packet.extend_from_slice(&[0xAE, 0x61, 0x73, 0x00]);

    if let Some(ip) = fixed_ip {
        packet.extend_from_slice(&ip);
    } else {
        packet.push(10);
        packet.push(rng.r#gen());
        packet.push(rng.r#gen());
        packet.push(rng.r#gen());
    }
    packet.extend_from_slice(payload);
    packet
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

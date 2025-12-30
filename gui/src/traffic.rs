use crate::types::*;
use eframe::egui;
use rand::Rng;
use rand::SeedableRng;
use rand::rngs::StdRng;
use rand::seq::SliceRandom;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};

pub async fn start_background_task(
    stats: Arc<NetStats>,
    log_tx: UnboundedSender<LogEntry>,
    mut cmd_rx: UnboundedReceiver<GuiCommand>,
) {
    // Management socket
    let socket = UdpSocket::bind(LISTEN_ADDR).await.unwrap();

    // Create a pool of sockets to simulate attacks from different Source Ports
    let mut socket_pool = Vec::new();
    for _ in 0..50 {
        let sock = UdpSocket::bind("0.0.0.0:0").await.unwrap();
        socket_pool.push(sock);
    }

    let mut buf = [0u8; 1024];
    let mut mode = TrafficMode::Idle;
    let start_time = Instant::now();

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

                // Now expecting 8 u64s (64 bytes)
                if len >= 64 && data[0] != 0x02 {
                    for i in 0..8 {
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
                            _ => {}
                        }
                    }
                } else if data[0] == 0x02 {
                    let msg = parse_alert(data);
                    let _ = log_tx.send(msg);
                }
            }
            Some(cmd) = cmd_rx.recv() => {
                match cmd {
                    GuiCommand::SetMode(m) => mode = m,
                    GuiCommand::SendBytes(bytes) => {
                        // Use the first socket for management commands
                        let _ = socket_pool[0].send_to(&bytes, MGMT_ADDR).await;
                    }
                    GuiCommand::BanIp(ip_str) => {
                        if let Ok(ip) = ip_str.parse::<std::net::Ipv4Addr>() {
                            let mut packet = vec![0x04];
                            packet.extend_from_slice(&ip.octets());
                            let _ = socket_pool[0].send_to(&packet, MGMT_ADDR).await;

                            let entry = LogEntry {
                                timestamp: 0.0,
                                src_ip: "Localhost".to_string(),
                                msg: format!("MANUAL BAN: {}", ip_str),
                                payload: vec![],
                                dst_port: 0,
                                color: egui::Color32::from_rgb(255, 0, 255),
                            };
                            let _ = log_tx.send(entry);
                        }
                    }
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(1)) => {
                match mode {
                    TrafficMode::Normal => {
                        let count = rng.gen_range(80..=120);
                        for _ in 0..count {
                            let payload = build_spoofed_packet(&mut rng, None, b"GET / HTTP/1.1");
                            // Randomize source port by choosing a random socket
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

                            // Attack from different source ports
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

                        // Inject Heuristic Anomalies (NOP Sleds)
                        if rng.gen_bool(0.05) {
                            let mut payload = vec![0x90; 16]; // NOP Sled
                            payload.extend_from_slice(b"\xcc\xcc\xcc\xcc"); // Shellcode
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
                    _ => {}
                }
            }
        }
    }
}

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

fn parse_alert(data: &[u8]) -> LogEntry {
    let reason = data[1];
    let ip = format!("{}.{}.{}.{}", data[2], data[3], data[4], data[5]);

    let payload = if data.len() > 6 {
        data[6..].to_vec()
    } else {
        Vec::new()
    };

    let dst_port = match reason {
        1 | 4 | 6 => {
            // 6 is Flow
            if payload.len() >= 38 {
                u16::from_be_bytes([payload[36], payload[37]])
            } else {
                0
            }
        }
        2 | 3 | 5 => {
            // 5 is Heuristic
            if payload.len() >= 4 {
                u16::from_be_bytes([payload[2], payload[3]])
            } else {
                0
            }
        }
        _ => 0,
    };

    let (msg, color) = match reason {
        1 => (
            format!("[DDoS] High Volume from {}", ip),
            egui::Color32::YELLOW,
        ),
        2 => (
            format!("[FIREWALL] Blocked Port access from {}", ip),
            egui::Color32::RED,
        ),
        3 => (
            format!("[MALWARE] Signature Match from {}", ip),
            egui::Color32::RED,
        ),
        4 => (
            format!("[eBPF] Custom Filter Drop from {}", ip),
            egui::Color32::LIGHT_BLUE,
        ),
        5 => (
            if !payload.is_empty() && payload[0] == 0x90 {
                format!("[HEURISTIC] Shellcode Detected from {}", ip)
            } else {
                format!("[HEURISTIC] Anomaly Detected from {}", ip)
            },
            egui::Color32::from_rgb(255, 0, 255), // Magenta
        ),
        6 => (
            format!("[FLOW] New Connection from {}", ip),
            egui::Color32::LIGHT_BLUE,
        ),
        _ => ("Unknown Alert".to_string(), egui::Color32::GRAY),
    };

    LogEntry {
        timestamp: 0.0,
        src_ip: ip,
        msg,
        payload,
        dst_port,
        color,
    }
}

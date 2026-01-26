//! Security Unikernel - Main kernel entry point.
//!
//! This is a bare-metal RISC-V unikernel implementing a network security
//! appliance. It processes network packets in real-time, applying multiple
//! security mechanisms including DDoS mitigation, firewall rules, deep packet
//! inspection, heuristic analysis, and custom eBPF-like packet filters.
//!
//! The kernel operates in a polling loop, processing packets in batches
//! and periodically sending telemetry data to the control plane.

#![no_std]
#![no_main]

/// Kernel configuration constants including network identity and thresholds.
mod config;
/// Core kernel infrastructure: memory allocation, panic handling, and type definitions.
mod core;
/// Hardware device drivers for network interfaces and peripherals.
mod drivers;
/// Network protocol stack implementation for Ethernet, IP, ARP, ICMP, and TCP.
mod net;
/// Security subsystems: DDoS mitigation, DPI, firewall, flow tracking, heuristics, and VM.
mod security;

use crate::core::allocator::ALLOCATOR;
use crate::core::types::Singleton;
use crate::drivers::net_device::NetDevice;
use ::core::arch::{asm, global_asm};
use config::{
    DDOS_ALERT_SAMPLE_RATE, DEFAULT_BLOCKED_PORT, FLOW_LOG_SAMPLE_MASK, FLOW_TIMEOUT_CYCLES,
    HEAVY_HITTER_THRESHOLD, IP_ADDR, IP_BAN_DURATION_CYCLES, KERNEL_VERSION, MAC_ADDR,
    MANAGEMENT_PORT, MAX_BPF_PROGRAM_SIZE, RATE_LIMIT_PPS, SPOOF_DETECTION_IP_OFFSET,
    SPOOF_DETECTION_MAGIC, SPOOF_DETECTION_MIN_LEN, TELEMETRY_INTERVAL_CYCLES, TELEMETRY_PORT,
    TOKEN_BUCKET_CAPACITY, TOTAL_MEMORY_SIZE,
};
use security::{
    alert::{AlertReason, alert_packet},
    dos, dpi, firewall, flow, heuristic, mgmt, vm,
};

// Linker symbol marking the end of the BSS (uninitialized data) section.
//
// This symbol is provided by the linker script and represents the boundary
// between initialized and uninitialized data sections in memory. The kernel
// uses this address to calculate available RAM by subtracting the current
// stack pointer from `_ebss`. This calculation provides the amount of free
// memory available for dynamic allocation, which is reported in telemetry
// packets to the control plane.
//
// Safety: This symbol is declared as unsafe because it references memory
// layout defined by the linker script. The address is guaranteed to be
// valid only after the linker has processed the memory layout.
unsafe extern "C" {
    static _ebss: u8;
}

global_asm!(
    r#"
    .section .text.entry
    .global _start
    _start:
        la sp, _stack_top
        call kmain
    spin:
        wfi
        j spin
"#
);

/// Central security engine coordinating all security mechanisms.
///
/// This structure contains all the security subsystems including DPI,
/// firewall, DDoS mitigation, flow tracking, and the eBPF virtual machine.
struct SecurityEngine {
    /// Aho-Corasick automaton for static malware signature matching.
    ac: dpi::AhoCorasick,
    /// Dynamic rules added at runtime via management interface.
    dyn_rules: dpi::DynamicRules,
    /// Firewall state tracking blocked ports.
    fw: firewall::FirewallState,
    /// Count-Min Sketch for heavy hitter detection.
    cms: dos::CountMinSketch,
    /// Penalty box for banned IP addresses.
    pbox: dos::PenaltyBox,
    /// Token bucket rate limiter.
    limiter: dos::TokenBucket,
    /// Virtual machine for executing eBPF programs.
    vm: vm::VM,
    /// Compiled eBPF program instructions.
    bpf_prog: [vm::Instruction; MAX_BPF_PROGRAM_SIZE],
    /// Length of the active eBPF program.
    bpf_len: usize,
    /// Flow table for tracking network connections.
    flow_table: flow::FlowTable,
}

impl SecurityEngine {
    /// Creates an empty security engine with all subsystems initialized.
    const fn empty() -> Self {
        Self {
            ac: dpi::AhoCorasick::new(),
            dyn_rules: dpi::DynamicRules::new(),
            fw: firewall::FirewallState::new(),
            cms: dos::CountMinSketch::new(),
            pbox: dos::PenaltyBox::new(),
            limiter: dos::TokenBucket::new(TOKEN_BUCKET_CAPACITY as u64, RATE_LIMIT_PPS as usize),
            vm: vm::VM::new(),
            bpf_prog: [vm::Instruction::new(0, 0, 0, 0); MAX_BPF_PROGRAM_SIZE],
            bpf_len: 0,
            flow_table: flow::FlowTable::new(),
        }
    }

    /// Initializes the security engine with default rules and signatures.
    ///
    /// Sets up the Aho-Corasick automaton with common attack patterns
    /// and configures initial firewall rules.
    fn init(&mut self) {
        self.ac.insert(b"DROP TABLE");
        self.ac.insert(b"<script>");
        self.ac.insert(b"eval(");
        self.ac.insert(b"UNION SELECT");
        self.ac.build();
        self.fw.block_port(DEFAULT_BLOCKED_PORT);
    }
}

/// Global security engine instance.
static ENGINE: Singleton<SecurityEngine> = Singleton::new(SecurityEngine::empty());

/// Kernel main entry point.
///
/// Initializes all subsystems, prints boot information, and enters
/// the main packet processing loop. This function never returns.
///
/// # Safety
///
/// This function is marked as unsafe because it's called from assembly
/// code and assumes a valid stack has been set up.
#[unsafe(no_mangle)]
pub extern "C" fn kmain() -> ! {
    unsafe { (*::core::ptr::addr_of_mut!(ALLOCATOR)).init() };
    NetDevice::init();

    let engine = ENGINE.get();
    engine.init();

    crate::kprintln!("\n[ RISC-V Security Unikernel {} ]", KERNEL_VERSION);
    crate::kprintln!("[*] Architecture: RISC-V64 (Bare Metal)");
    crate::kprintln!("[*] Memory Limit: 64KB");
    crate::kprintln!(
        "[*] IP Address  : {}.{}.{}.{}",
        IP_ADDR[0],
        IP_ADDR[1],
        IP_ADDR[2],
        IP_ADDR[3]
    );
    crate::kprintln!(
        "[*] MAC Address : {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        MAC_ADDR[0],
        MAC_ADDR[1],
        MAC_ADDR[2],
        MAC_ADDR[3],
        MAC_ADDR[4],
        MAC_ADDR[5]
    );
    crate::kprintln!("[*] Management  : UDP :{}", MANAGEMENT_PORT);
    crate::kprintln!("[*] Telemetry   : UDP :{} (Broadcast)", TELEMETRY_PORT);

    let mut last_report = get_cycles();
    let mut stats = [0u64; 8];
    /// Maximum number of packets to process in a single iteration.
    ///
    /// Processing packets in batches improves cache locality and reduces
    /// overhead from per-packet function calls. This value balances
    /// throughput with latency for real-time security processing.
    const BATCH_SIZE: usize = 64;

    loop {
        let now = get_cycles();
        if now.wrapping_sub(last_report) > TELEMETRY_INTERVAL_CYCLES {
            let sp: usize;
            unsafe { asm!("mv {}, sp", out(reg) sp) };
            let ebss_addr = ::core::ptr::addr_of!(_ebss) as usize;
            let free_ram = sp.saturating_sub(ebss_addr);
            let used_ram = TOTAL_MEMORY_SIZE.saturating_sub(free_ram);

            engine.flow_table.prune(now, FLOW_TIMEOUT_CYCLES);

            stats[6] = used_ram as u64;
            stats[7] = engine.flow_table.active_count as u64;

            send_udp_report(&stats);
            engine.cms.reset();
            let mem = stats[6];
            let flows = stats[7];
            stats = [0; 8];
            stats[6] = mem;
            stats[7] = flows;

            last_report = now;
            NetDevice::flush();
        }

        let mut work_done = false;

        for _ in 0..BATCH_SIZE {
            if let Some(packet) = NetDevice::try_receive() {
                work_done = true;
                let mut drop = false;
                let mut src_ip = [0u8; 4];
                let mut dst_ip = [0u8; 4];
                let mut src_port = 0u16;
                let mut dst_port = 0u16;
                let mut protocol = 0u8;

                use crate::net::constants::{ethernet, ipv4};
                if packet.len() >= ipv4::HEADER_OFFSET + ipv4::MIN_HEADER_SIZE
                    && packet[ethernet::TYPE_OFFSET] == 0x08
                    && packet[ethernet::TYPE_OFFSET + 1] == 0x00
                {
                    src_ip.copy_from_slice(
                        &packet[ipv4::SRC_IP_OFFSET..ipv4::SRC_IP_OFFSET + ipv4::IP_ADDR_SIZE],
                    );
                    dst_ip.copy_from_slice(
                        &packet[ipv4::DST_IP_OFFSET..ipv4::DST_IP_OFFSET + ipv4::IP_ADDR_SIZE],
                    );
                    protocol = packet[ipv4::PROTOCOL_OFFSET];
                    let ihl = (packet[ipv4::VERSION_IHL_OFFSET] & ipv4::IHL_MASK) * 4;
                    let payload_offset = ipv4::HEADER_OFFSET + ihl as usize;

                    use crate::net::tcp::TcpHeader;
                    if let Some((sport, dport)) =
                        TcpHeader::extract_ports(&packet[payload_offset..])
                    {
                        src_port = sport;
                        dst_port = dport;
                    }

                    if engine.flow_table.update(
                        &src_ip,
                        &dst_ip,
                        src_port,
                        dst_port,
                        protocol,
                        packet.len(),
                        now,
                    ) {
                        if (now & FLOW_LOG_SAMPLE_MASK) == 0 {
                            send_alert(&src_ip, AlertReason::Flow.as_u8(), packet);
                        }
                    }

                    if packet.len() >= SPOOF_DETECTION_MIN_LEN
                        && packet[42..46] == SPOOF_DETECTION_MAGIC
                    {
                        src_ip.copy_from_slice(
                            &packet[SPOOF_DETECTION_IP_OFFSET
                                ..SPOOF_DETECTION_IP_OFFSET + ipv4::IP_ADDR_SIZE],
                        );
                    }

                    if engine.pbox.is_banned(&src_ip) {
                        drop = true;
                    } else {
                        let count = engine.cms.insert(&src_ip);
                        if count > HEAVY_HITTER_THRESHOLD {
                            engine.pbox.ban(&src_ip, IP_BAN_DURATION_CYCLES);
                            drop = true;
                        }
                    }
                }

                if drop || !engine.limiter.allow() {
                    stats[1] += 1;
                    if stats[1] % DDOS_ALERT_SAMPLE_RATE == 0 {
                        send_alert(&src_ip, AlertReason::Ddos.as_u8(), packet);
                    }
                    NetDevice::recycle_rx_buffer();
                    continue;
                }

                use crate::net::constants::{IpProtocol, tcp};
                if IpProtocol::from_u8(protocol) == Some(IpProtocol::Tcp) {
                    let ihl = (packet[ipv4::VERSION_IHL_OFFSET] & ipv4::IHL_MASK) * 4;
                    let tcp_offset = ipv4::HEADER_OFFSET + ihl as usize;
                    if packet.len() >= tcp_offset + tcp::MIN_HEADER_SIZE {
                        let flags = packet[tcp_offset + tcp::FLAGS_OFFSET];
                        if let Some(_reason) = heuristic::HeuristicEngine::check_tcp_flags(flags) {
                            stats[5] += 1;
                            send_alert(&src_ip, AlertReason::Heuristic.as_u8(), packet);
                            NetDevice::recycle_rx_buffer();
                            continue;
                        }
                    }
                }

                if engine.bpf_len > 0 {
                    let prog = &engine.bpf_prog[0..engine.bpf_len];
                    let result = engine.vm.execute(prog, packet);
                    if result == 0 {
                        stats[4] += 1;
                        send_alert(&src_ip, AlertReason::Ebpf.as_u8(), packet);
                        NetDevice::recycle_rx_buffer();
                        continue;
                    }
                }

                if let Some(payload) = net::stack::process_packet(packet) {
                    if let Some(_reason) = heuristic::HeuristicEngine::check_payload(payload) {
                        stats[5] += 1;
                        send_alert(&src_ip, AlertReason::Heuristic.as_u8(), payload);
                        NetDevice::recycle_rx_buffer();
                        continue;
                    }

                    use mgmt::{ManagementMessageType, mgmt_packet};
                    if payload.len() >= 4 {
                        if dst_port == MANAGEMENT_PORT
                            && payload.len() >= mgmt_packet::MIN_PAYLOAD_LEN
                        {
                            let msg_type = payload[mgmt_packet::MSG_TYPE_OFFSET];
                            match ManagementMessageType::from_u8(msg_type) {
                                Some(ManagementMessageType::BlockPort) => {
                                    use mgmt::mgmt_packet::block_port;
                                    if payload.len() >= block_port::MIN_PAYLOAD_LEN {
                                        let p = (payload[block_port::PORT_OFFSET] as u16) << 8
                                            | payload[block_port::PORT_OFFSET + 1] as u16;
                                        engine.fw.block_port(p);
                                    }
                                }
                                Some(ManagementMessageType::AddDpiPattern) => {
                                    use mgmt::mgmt_packet::add_dpi;
                                    if payload.len() >= add_dpi::MIN_PAYLOAD_LEN {
                                        let len = payload[add_dpi::LEN_OFFSET] as usize;
                                        if payload.len() >= add_dpi::PATTERN_OFFSET + len
                                            && len <= add_dpi::MAX_PATTERN_LEN
                                        {
                                            let pattern = &payload[add_dpi::PATTERN_OFFSET
                                                ..add_dpi::PATTERN_OFFSET + len];
                                            engine.dyn_rules.add(pattern);
                                        }
                                    }
                                }
                                Some(ManagementMessageType::UploadBpfProgram) => {
                                    use mgmt::mgmt_packet::upload_bpf;
                                    if payload.len() >= upload_bpf::MIN_PAYLOAD_LEN {
                                        let count = payload[upload_bpf::COUNT_OFFSET] as usize;
                                        if payload.len()
                                            >= upload_bpf::INSTR_OFFSET
                                                + (count * upload_bpf::INSTR_SIZE)
                                            && count <= upload_bpf::MAX_INSTR_COUNT
                                        {
                                            let mut cursor = upload_bpf::INSTR_OFFSET;
                                            for i in 0..count {
                                                let op = payload[cursor];
                                                let ra = payload[cursor + 1];
                                                let rb = payload[cursor + 2];
                                                let imm = (payload[cursor + 3] as u32) << 24
                                                    | (payload[cursor + 4] as u32) << 16
                                                    | (payload[cursor + 5] as u32) << 8
                                                    | (payload[cursor + 6] as u32);
                                                engine.bpf_prog[i] =
                                                    vm::Instruction::new(op, ra, rb, imm);
                                                cursor += upload_bpf::INSTR_SIZE;
                                            }
                                            engine.bpf_len = count;
                                        }
                                    }
                                }
                                Some(ManagementMessageType::BanIp) => {
                                    use mgmt::mgmt_packet::ban_ip;
                                    if payload.len() >= ban_ip::MIN_PAYLOAD_LEN {
                                        let ip_to_ban = &payload[ban_ip::IP_OFFSET
                                            ..ban_ip::IP_OFFSET + ipv4::IP_ADDR_SIZE];
                                        engine.pbox.ban(ip_to_ban, IP_BAN_DURATION_CYCLES);
                                    }
                                }
                                None => {}
                            }
                        }

                        if engine.fw.is_blocked(dst_port) {
                            stats[2] += 1;
                            send_alert(&src_ip, AlertReason::Firewall.as_u8(), payload);
                        } else if engine.ac.scan(payload) || engine.dyn_rules.check(payload) {
                            stats[3] += 1;
                            send_alert(&src_ip, AlertReason::Malware.as_u8(), payload);
                        } else {
                            stats[0] += 1;
                        }
                    }
                }
                NetDevice::recycle_rx_buffer();
            } else {
                break;
            }
        }

        if work_done {
            NetDevice::flush();
        }
    }
}

/// Reads the current cycle count from the RISC-V cycle counter.
///
/// Uses the `mcycle` CSR to get a high-resolution timestamp
/// for timing measurements and flow expiration.
///
/// # Returns
///
/// Current cycle count as a usize
fn get_cycles() -> usize {
    unsafe {
        let c: usize;
        asm!("csrr {}, mcycle", out(reg) c);
        c
    }
}

/// Calculates the Internet checksum for a data buffer.
///
/// Implements the standard one's complement checksum algorithm
/// used in IP, TCP, and UDP headers.
///
/// # Arguments
///
/// * `data` - Data buffer to checksum
///
/// # Returns
///
/// 16-bit checksum value
fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i < data.len() - 1 {
        sum += ((data[i] as u32) << 8) | (data[i + 1] as u32);
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !sum as u16
}

/// Sends a UDP telemetry report to the control plane.
///
/// Constructs a UDP packet containing 8 statistics values and broadcasts
/// it to the management network. The packet format includes:
/// - Ethernet header with broadcast destination
/// - IP header with checksum
/// - UDP header
/// - 64 bytes of statistics data (8 u64 values)
///
/// # Arguments
///
/// * `stats` - Array of 8 statistics values to transmit
fn send_udp_report(stats: &[u64; 8]) {
    use crate::net::constants::IpProtocol;
    use crate::net::constants::udp;
    use crate::net::constants::{BROADCAST_MAC, ethernet, ipv4};
    /// Size of statistics data payload in telemetry packets (8 u64 values).
    ///
    /// Each telemetry report contains 8 statistics counters, each represented
    /// as a 64-bit big-endian integer, totaling 64 bytes of payload data.
    const STATS_DATA_SIZE: usize = 64;
    /// Maximum size of telemetry UDP packet in bytes.
    ///
    /// Accommodates Ethernet header (14), IP header (20), UDP header (8),
    /// and statistics payload (64), with additional space for alignment.
    const TELEMETRY_PACKET_SIZE: usize = 150;
    let mut packet = [0u8; TELEMETRY_PACKET_SIZE];
    packet[0..ethernet::MAC_ADDR_SIZE].copy_from_slice(&BROADCAST_MAC);
    packet[ethernet::SRC_MAC_OFFSET..ethernet::SRC_MAC_OFFSET + ethernet::MAC_ADDR_SIZE]
        .copy_from_slice(&MAC_ADDR);
    packet[ethernet::TYPE_OFFSET] = 0x08;
    packet[ethernet::TYPE_OFFSET + 1] = 0x00;
    packet[ipv4::HEADER_OFFSET] = ipv4::VERSION;
    packet[ipv4::HEADER_OFFSET + 1] = 0x00;
    let ip_total_len: u16 =
        ipv4::MIN_HEADER_SIZE as u16 + udp::HEADER_SIZE as u16 + STATS_DATA_SIZE as u16;
    packet[16] = (ip_total_len >> 8) as u8;
    packet[17] = (ip_total_len & 0xFF) as u8;
    packet[18] = 0x00;
    packet[19] = 0x00;
    packet[ipv4::HEADER_OFFSET + 6] = ipv4::DEFAULT_TTL;
    packet[ipv4::HEADER_OFFSET + 7] = 0x00;
    packet[ipv4::HEADER_OFFSET + 8] = ipv4::DEFAULT_TTL;
    packet[ipv4::PROTOCOL_OFFSET] = IpProtocol::Udp as u8;
    /// Offset to IP header checksum field (bytes 24-25).
    ///
    /// The checksum field is initially set to zero before calculation,
    /// then overwritten with the computed one's complement checksum.
    const IP_CHECKSUM_OFFSET: usize = ipv4::HEADER_OFFSET + 10;
    packet[IP_CHECKSUM_OFFSET] = 0x00;
    packet[IP_CHECKSUM_OFFSET + 1] = 0x00;
    packet[ipv4::SRC_IP_OFFSET..ipv4::SRC_IP_OFFSET + ipv4::IP_ADDR_SIZE].copy_from_slice(&IP_ADDR);
    /// IPv4 broadcast address for the management network.
    ///
    /// Telemetry packets are broadcast to this address to ensure all
    /// control plane instances receive the statistics data.
    const BROADCAST_IP: [u8; 4] = [192, 168, 100, 255];
    packet[ipv4::DST_IP_OFFSET..ipv4::DST_IP_OFFSET + ipv4::IP_ADDR_SIZE]
        .copy_from_slice(&BROADCAST_IP);

    let csum = checksum(&packet[ipv4::HEADER_OFFSET..ipv4::HEADER_OFFSET + ipv4::MIN_HEADER_SIZE]);
    packet[IP_CHECKSUM_OFFSET] = (csum >> 8) as u8;
    packet[IP_CHECKSUM_OFFSET + 1] = (csum & 0xFF) as u8;

    /// Offset to UDP header within the packet.
    ///
    /// Calculated as the sum of Ethernet header size and IP header size.
    /// This marks the start of the UDP header containing source/destination
    /// ports, length, and checksum fields.
    const UDP_HEADER_OFFSET: usize = ipv4::HEADER_OFFSET + ipv4::MIN_HEADER_SIZE;
    packet[UDP_HEADER_OFFSET] = (TELEMETRY_PORT >> 8) as u8;
    packet[UDP_HEADER_OFFSET + 1] = (TELEMETRY_PORT & 0xFF) as u8;
    /// Source port for telemetry UDP packets.
    ///
    /// Arbitrary port number used as the source port when sending
    /// telemetry reports. The destination port is `TELEMETRY_PORT`.
    const UDP_SRC_PORT: u16 = 0x22B8;
    packet[UDP_HEADER_OFFSET + 2] = (UDP_SRC_PORT >> 8) as u8;
    packet[UDP_HEADER_OFFSET + 3] = (UDP_SRC_PORT & 0xFF) as u8;
    let udp_len: u16 = udp::HEADER_SIZE as u16 + STATS_DATA_SIZE as u16;
    packet[UDP_HEADER_OFFSET + 4] = (udp_len >> 8) as u8;
    packet[UDP_HEADER_OFFSET + 5] = (udp_len & 0xFF) as u8;
    packet[UDP_HEADER_OFFSET + 6] = 0x00;
    packet[UDP_HEADER_OFFSET + 7] = 0x00;

    /// Offset to statistics payload data within the packet.
    ///
    /// Marks the start of the 64-byte statistics array containing
    /// 8 u64 values in big-endian format.
    const STATS_OFFSET: usize = UDP_HEADER_OFFSET + udp::HEADER_SIZE;
    let mut offset = STATS_OFFSET;
    for &val in stats.iter() {
        packet[offset..offset + 8].copy_from_slice(&val.to_be_bytes());
        offset += 8;
    }
    NetDevice::send(&packet[0..offset]);
}

/// Sends a security alert to the control plane.
///
/// Constructs a UDP packet containing alert information including
/// the reason code, source IP address, and captured packet payload.
/// Alerts are sent to the management interface for logging and analysis.
///
/// # Arguments
///
/// * `src_ip` - Source IP address that triggered the alert
/// * `reason` - Alert reason code
/// * `payload` - Packet payload data to include in the alert
fn send_alert(src_ip: &[u8], reason: u8, payload: &[u8]) {
    use crate::net::constants::IpProtocol;
    use crate::net::constants::udp;
    use crate::net::constants::{BROADCAST_MAC, ethernet, ipv4};
    use alert_packet;
    /// Maximum size of alert UDP packet in bytes.
    ///
    /// Accommodates Ethernet header (14), IP header (20), UDP header (8),
    /// alert header (6), and payload data (up to 64 bytes).
    const ALERT_PACKET_SIZE: usize = 128;
    /// IPv4 broadcast address for the management network.
    ///
    /// Alert packets are broadcast to this address to ensure all
    /// control plane instances receive security event notifications.
    const BROADCAST_IP: [u8; 4] = [192, 168, 100, 255];
    /// Source port for alert UDP packets.
    ///
    /// Arbitrary port number used as the source port when sending
    /// security alerts. The destination port is `MANAGEMENT_PORT`.
    const UDP_SRC_PORT: u16 = 0x22B8;
    let mut packet = [0u8; ALERT_PACKET_SIZE];
    packet[0..ethernet::MAC_ADDR_SIZE].copy_from_slice(&BROADCAST_MAC);
    packet[ethernet::SRC_MAC_OFFSET..ethernet::SRC_MAC_OFFSET + ethernet::MAC_ADDR_SIZE]
        .copy_from_slice(&MAC_ADDR);
    packet[ethernet::TYPE_OFFSET] = 0x08;
    packet[ethernet::TYPE_OFFSET + 1] = 0x00;

    packet[ipv4::HEADER_OFFSET] = ipv4::VERSION;
    packet[ipv4::HEADER_OFFSET + 1] = 0x00;
    packet[ipv4::HEADER_OFFSET + 4] = 0x00;
    packet[ipv4::HEADER_OFFSET + 5] = 0x00;
    packet[ipv4::HEADER_OFFSET + 6] = ipv4::DEFAULT_TTL;
    packet[ipv4::HEADER_OFFSET + 7] = 0x00;
    packet[ipv4::HEADER_OFFSET + 8] = ipv4::DEFAULT_TTL;
    packet[ipv4::PROTOCOL_OFFSET] = IpProtocol::Udp as u8;
    /// Offset to IP header checksum field (bytes 24-25).
    ///
    /// The checksum field is initially set to zero before calculation,
    /// then overwritten with the computed one's complement checksum.
    const IP_CHECKSUM_OFFSET: usize = ipv4::HEADER_OFFSET + 10;
    packet[IP_CHECKSUM_OFFSET] = 0x00;
    packet[IP_CHECKSUM_OFFSET + 1] = 0x00;
    packet[ipv4::SRC_IP_OFFSET..ipv4::SRC_IP_OFFSET + ipv4::IP_ADDR_SIZE].copy_from_slice(&IP_ADDR);
    packet[ipv4::DST_IP_OFFSET..ipv4::DST_IP_OFFSET + ipv4::IP_ADDR_SIZE]
        .copy_from_slice(&BROADCAST_IP);

    /// Offset to UDP header within the packet.
    ///
    /// Calculated as the sum of Ethernet header size and IP header size.
    /// This marks the start of the UDP header containing source/destination
    /// ports, length, and checksum fields.
    const UDP_HEADER_OFFSET: usize = ipv4::HEADER_OFFSET + ipv4::MIN_HEADER_SIZE;
    packet[UDP_HEADER_OFFSET] = (MANAGEMENT_PORT >> 8) as u8;
    packet[UDP_HEADER_OFFSET + 1] = (MANAGEMENT_PORT & 0xFF) as u8;
    packet[UDP_HEADER_OFFSET + 2] = (UDP_SRC_PORT >> 8) as u8;
    packet[UDP_HEADER_OFFSET + 3] = (UDP_SRC_PORT & 0xFF) as u8;
    packet[UDP_HEADER_OFFSET + 6] = 0x00;
    packet[UDP_HEADER_OFFSET + 7] = 0x00;

    /// Offset to alert payload data within the packet.
    ///
    /// Marks the start of the alert message structure containing
    /// message type, reason code, source IP, and optional payload data.
    const ALERT_PAYLOAD_OFFSET: usize = UDP_HEADER_OFFSET + udp::HEADER_SIZE;
    let mut offset = ALERT_PAYLOAD_OFFSET;
    packet[offset] = alert_packet::ALERT_MESSAGE_TYPE;
    packet[offset + alert_packet::REASON_OFFSET] = reason;
    if src_ip.len() >= ipv4::IP_ADDR_SIZE {
        packet[offset + alert_packet::SRC_IP_OFFSET
            ..offset + alert_packet::SRC_IP_OFFSET + alert_packet::SRC_IP_SIZE]
            .copy_from_slice(&src_ip[0..ipv4::IP_ADDR_SIZE]);
    }
    offset += alert_packet::PAYLOAD_OFFSET;

    let copy_len = payload.len().min(alert_packet::MAX_PAYLOAD_LEN);
    packet[offset..offset + copy_len].copy_from_slice(&payload[0..copy_len]);
    offset += copy_len;

    let ip_len = (offset - ipv4::HEADER_OFFSET) as u16;
    packet[ipv4::HEADER_OFFSET + 2] = (ip_len >> 8) as u8;
    packet[ipv4::HEADER_OFFSET + 3] = (ip_len & 0xFF) as u8;
    let udp_len = (offset - UDP_HEADER_OFFSET) as u16;
    packet[UDP_HEADER_OFFSET + 4] = (udp_len >> 8) as u8;
    packet[UDP_HEADER_OFFSET + 5] = (udp_len & 0xFF) as u8;

    let csum = checksum(&packet[ipv4::HEADER_OFFSET..ipv4::HEADER_OFFSET + ipv4::MIN_HEADER_SIZE]);
    packet[IP_CHECKSUM_OFFSET] = (csum >> 8) as u8;
    packet[IP_CHECKSUM_OFFSET + 1] = (csum & 0xFF) as u8;

    NetDevice::send(&packet[0..offset]);
}

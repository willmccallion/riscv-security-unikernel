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

/// Slab allocator used during init only; the packet loop is heap-free.
mod allocator;
/// Hardware device drivers for network interfaces and peripherals.
mod drivers;
/// VirtIO-Net backed [`sec_core::net::PacketSink`] implementation.
mod net_sink;
/// Kernel panic handler: halts the core.
mod panic;
/// RISC-V `mcycle` backed [`sec_core::time::TimeSource`] implementation.
mod time_riscv;

use crate::allocator::ALLOCATOR;
use crate::drivers::net_device::NetDevice;
use crate::net_sink::VirtioNetSink;
use crate::time_riscv::MCycle;
use ::core::arch::{asm, global_asm};
use sec_core::config::{
    DDOS_ALERT_SAMPLE_RATE, DEFAULT_BLOCKED_PORT, FLOW_LOG_SAMPLE_MASK, FLOW_TIMEOUT_CYCLES,
    CMS_RESET_INTERVAL_CYCLES, HEAVY_HITTER_THRESHOLD, IP_ADDR, IP_BAN_DURATION_CYCLES,
    KERNEL_VERSION, MAC_ADDR, MANAGEMENT_PORT, MAX_BPF_PROGRAM_SIZE, RATE_LIMIT_PPS,
    TELEMETRY_INTERVAL_CYCLES,
    TELEMETRY_PORT, TOKEN_BUCKET_CAPACITY, TOTAL_MEMORY_SIZE,
};
use sec_core::net::stack::SynCookieSecret;
use sec_core::security::{
    alert::{AlertMeta, AlertReason, alert_packet, should_emit_ddos_alert},
    dos, dpi, firewall, flow, heuristic, mgmt, mgmt_auth, vm,
};
use sec_core::time::TimeSource;
use sec_core::types::Singleton;

include!(concat!(env!("OUT_DIR"), "/mgmt_key.rs"));

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
            limiter: dos::TokenBucket::new(TOKEN_BUCKET_CAPACITY as u64, RATE_LIMIT_PPS),
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
        // 4 short patterns into a 128-node trie — capacity-safe by
        // construction, so dropping the Result is sound. Runtime
        // pattern uploads (when added) must not ignore the Result.
        let _ = self.ac.insert(b"DROP TABLE");
        let _ = self.ac.insert(b"<script>");
        let _ = self.ac.insert(b"eval(");
        let _ = self.ac.insert(b"UNION SELECT");
        self.ac.build();
        self.fw.block_port(DEFAULT_BLOCKED_PORT);
    }
}

/// Global security engine instance.
static ENGINE: Singleton<SecurityEngine> = Singleton::new(SecurityEngine::empty());

/// Verifier for authenticated management commands. Stateful: tracks the
/// highest counter accepted so far, so replays are rejected.
static MGMT_AUTH: Singleton<mgmt_auth::MgmtAuth> =
    Singleton::new(mgmt_auth::MgmtAuth::new(MGMT_KEY));

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
    // SAFETY: ALLOCATOR is a mutable static only accessed here during single-threaded kernel
    // init, before the packet loop begins.
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

    let clock = MCycle;
    let mut sink = VirtioNetSink;
    let mut last_report = clock.now();
    let mut last_cms_reset = last_report;
    // Heartbeat state. We want a cheap sign-of-life on the serial
    // console without burying the boot banner: print one dot per tick
    // and switch to a single rewriting line (`[idle Nx]`) after 100
    // ticks so a long quiet period collapses to one row. Real traffic
    // or drops break out to a full stats line.
    let mut dots_on_line: u32 = 0;
    let mut idle_ticks: u32 = 0;
    let mut interval_rx: u64 = 0;
    // 60 dots fits in every terminal wider than 60 columns without
    // visual wrapping, so `\r` always returns to the start of the row
    // we actually wrote. Wider lines wrap on narrow ttys and break
    // every cursor-rewind trick below.
    const DOT_LINE_MAX: u32 = 60;
    // Stats slot layout (per-interval counters reset on each
    // telemetry tick; memory/flows/mgmt are gauges or independent
    // counters that survive the reset):
    //   0: passed user packets
    //   1: ddos drops
    //   2: firewall blocks
    //   3: malware-signature matches
    //   4: ebpf drops
    //   5: heuristic anomalies
    //   6: memory bytes used (gauge)
    //   7: active flows (gauge)
    //   8: management-plane packets (auth-success + auth-fail)
    //   9: boot epoch (gauge; lets the GUI stamp the right epoch into
    //      outgoing mgmt counters and detect kernel reboots)
    let mut stats = [0u64; 10];

    // Per-boot SYN-cookie secret. mcycle at this point is whatever the
    // hart counter reached during init — varies across boots — and we
    // mix in the MAC so two kernels booting at the same cycle still
    // diverge. SipHash inside `cookie` does the rest.
    let syn_secret = {
        let mut bytes = [0u8; 16];
        let mc = clock.now().to_le_bytes();
        bytes[..8].copy_from_slice(&mc);
        bytes[8..14].copy_from_slice(&MAC_ADDR);
        bytes[14] = mc[0] ^ MAC_ADDR[0];
        bytes[15] = mc[1] ^ MAC_ADDR[1];
        SynCookieSecret::new(bytes)
    };

    // Same per-boot material reused as the CMS salt so heavy-hitter
    // detection isn't vulnerable to precomputed 4-way collisions.
    let cms_seed = clock.now()
        ^ u64::from_le_bytes([
            MAC_ADDR[0], MAC_ADDR[1], MAC_ADDR[2], MAC_ADDR[3],
            MAC_ADDR[4], MAC_ADDR[5], 0, 0,
        ]);
    engine.cms.reseed(cms_seed);

    // Per-boot mgmt-auth epoch. Folded into the high 32 bits of every
    // accepted mgmt counter, so a packet captured under one boot can
    // never replay against another. Derived from the same per-boot
    // material as the CMS seed for consistency. A non-zero epoch is
    // required for any mgmt packet to verify, so this MUST run before
    // the packet loop.
    let mgmt_epoch = (cms_seed as u32) ^ ((cms_seed >> 32) as u32);
    let mgmt_epoch = if mgmt_epoch == 0 { 1 } else { mgmt_epoch };
    MGMT_AUTH.get().set_epoch(mgmt_epoch);
    /// Maximum number of packets to process in a single iteration.
    ///
    /// Processing packets in batches improves cache locality and reduces
    /// overhead from per-packet function calls. This value balances
    /// throughput with latency for real-time security processing.
    const BATCH_SIZE: usize = 64;

    loop {
        let now = clock.now();
        if now.wrapping_sub(last_report) > TELEMETRY_INTERVAL_CYCLES as u64 {
            let sp: usize;
            // SAFETY: Reading the stack pointer register via inline asm is safe;
            // sp is always a valid register on RISC-V.
            unsafe { asm!("mv {}, sp", out(reg) sp) };
            let ebss_addr = ::core::ptr::addr_of!(_ebss) as usize;
            let free_ram = sp.saturating_sub(ebss_addr);
            let used_ram = TOTAL_MEMORY_SIZE.saturating_sub(free_ram);

            engine.flow_table.prune(now, FLOW_TIMEOUT_CYCLES as u64);

            stats[6] = used_ram as u64;
            stats[7] = engine.flow_table.active_count as u64;

            let interval_drops =
                stats[1] + stats[2] + stats[3] + stats[4] + stats[5];
            let had_activity =
                interval_rx > 0 || interval_drops > 0 || stats[8] > 0;
            // 60 ASCII spaces — used to blank a 60-char row with
            // nothing but plain text, since `\x1b[K` is unreliable
            // when the row visually wrapped.
            const PAD: &str =
                "                                                            ";
            if had_activity {
                // Clear whatever idle display is on screen so the
                // event line lands on its own row. Two rows when an
                // idle counter has been established, one row while
                // dots are still accumulating on the first pass.
                if idle_ticks > 0 {
                    crate::kprint!("\x1b[A\r{}\r\x1b[B\r{}\r", PAD, PAD);
                } else if dots_on_line > 0 {
                    crate::kprint!("\r{}\r", PAD);
                }
                crate::kprintln!(
                    "[hb] rx={} pass={} drop(ddos={} fw={} mal={} bpf={} heur={}) flows={} mgmt={}",
                    interval_rx,
                    stats[0], stats[1], stats[2], stats[3], stats[4], stats[5], stats[7], stats[8]
                );
                dots_on_line = 0;
                idle_ticks = 0;
            } else if dots_on_line < DOT_LINE_MAX {
                crate::kprint!(".");
                dots_on_line += 1;
            } else {
                // Dots row is full — wrap without scrolling. On the
                // first wrap we overwrite the dots row with the idle
                // counter and open one new row beneath it (one-time,
                // one-line scroll). Every subsequent wrap bounces the
                // cursor between the two rows in place, so a quiet
                // kernel never occupies more than two lines.
                idle_ticks += 1;
                if idle_ticks == 1 {
                    crate::kprint!("\r[idle 1x]{}\n", &PAD[9..]);
                } else {
                    crate::kprint!(
                        "\x1b[A\r[idle {}x]{}\r\x1b[B\r{}\r",
                        idle_ticks,
                        PAD,
                        PAD
                    );
                }
                dots_on_line = 0;
            }
            interval_rx = 0;

            stats[9] = mgmt_epoch as u64;
            send_udp_report(&stats);
            let mem = stats[6];
            let flows = stats[7];
            stats = [0; 10];
            stats[6] = mem;
            stats[7] = flows;
            stats[9] = mgmt_epoch as u64;

            last_report = now;
            NetDevice::flush();
        }

        if now.wrapping_sub(last_cms_reset) > CMS_RESET_INTERVAL_CYCLES as u64 {
            engine.cms.reset();
            last_cms_reset = now;
        }

        let mut work_done = false;

        for _ in 0..BATCH_SIZE {
            if let Some(packet) = NetDevice::try_receive() {
                work_done = true;
                // Count only packets actually addressed to us so
                // stray broadcasts / host ARP probes / IPv6 multicast
                // on the tap don't trigger the heartbeat. IPv4 dst
                // must match our IP, or the frame must be an ARP
                // request/reply whose target IP matches ours.
                use sec_core::net::constants::arp;
                let for_us = {
                    use sec_core::net::constants::{ethernet, ipv4};
                    let ethertype = packet.len() >= ethernet::TYPE_OFFSET + 2
                        && packet[ethernet::TYPE_OFFSET] == 0x08;
                    let is_ipv4 = ethertype && packet[ethernet::TYPE_OFFSET + 1] == 0x00;
                    let is_arp = ethertype && packet[ethernet::TYPE_OFFSET + 1] == 0x06;
                    (is_ipv4
                        && packet.len() >= ipv4::DST_IP_OFFSET + ipv4::IP_ADDR_SIZE
                        && packet[ipv4::DST_IP_OFFSET..ipv4::DST_IP_OFFSET + ipv4::IP_ADDR_SIZE]
                            == sec_core::config::IP_ADDR)
                        || (is_arp
                            && packet.len() >= arp::TARGET_IP_OFFSET + ipv4::IP_ADDR_SIZE
                            && packet[arp::TARGET_IP_OFFSET..arp::TARGET_IP_OFFSET + ipv4::IP_ADDR_SIZE]
                                == sec_core::config::IP_ADDR)
                };
                if for_us {
                    interval_rx += 1;
                }
                let mut drop = false;
                let mut meta = AlertMeta::empty();
                meta.packet_len = packet.len().min(u16::MAX as usize) as u16;
                let dst_port;
                let protocol;

                use sec_core::net::constants::{ethernet, ipv4};
                if packet.len() >= ipv4::HEADER_OFFSET + ipv4::MIN_HEADER_SIZE
                    && packet[ethernet::TYPE_OFFSET] == 0x08
                    && packet[ethernet::TYPE_OFFSET + 1] == 0x00
                {
                    meta.src_ip.copy_from_slice(
                        &packet[ipv4::SRC_IP_OFFSET..ipv4::SRC_IP_OFFSET + ipv4::IP_ADDR_SIZE],
                    );
                    meta.dst_ip.copy_from_slice(
                        &packet[ipv4::DST_IP_OFFSET..ipv4::DST_IP_OFFSET + ipv4::IP_ADDR_SIZE],
                    );
                    meta.protocol = packet[ipv4::PROTOCOL_OFFSET];
                    let ihl = (packet[ipv4::VERSION_IHL_OFFSET] & ipv4::IHL_MASK) * 4;
                    let payload_offset = ipv4::HEADER_OFFSET + ihl as usize;

                    use sec_core::net::tcp::TcpHeader;
                    if let Some((sport, dport)) =
                        TcpHeader::extract_ports(&packet[payload_offset..])
                    {
                        meta.src_port = sport;
                        meta.dst_port = dport;
                    }

                    dst_port = meta.dst_port;
                    protocol = meta.protocol;

                    if engine.flow_table.update(
                        &meta.src_ip,
                        &meta.dst_ip,
                        meta.src_port,
                        meta.dst_port,
                        meta.protocol,
                        packet.len(),
                        now,
                    ) && (now & FLOW_LOG_SAMPLE_MASK as u64) == 0
                    {
                        send_alert(&meta, AlertReason::Flow.as_u8());
                    }

                    if engine.pbox.is_banned(&meta.src_ip, now) {
                        drop = true;
                    } else {
                        let count = engine.cms.insert(&meta.src_ip);
                        if count > HEAVY_HITTER_THRESHOLD {
                            engine.pbox.ban(&meta.src_ip, IP_BAN_DURATION_CYCLES as u64, now);
                            drop = true;
                        }
                    }
                } else {
                    dst_port = meta.dst_port;
                    protocol = meta.protocol;
                }

                if drop || !engine.limiter.allow(now) {
                    stats[1] += 1;
                    if should_emit_ddos_alert(stats[1], DDOS_ALERT_SAMPLE_RATE) {
                        send_alert(&meta, AlertReason::Ddos.as_u8());
                    }
                    NetDevice::recycle_rx_buffer();
                    continue;
                }

                use sec_core::net::constants::{IpProtocol, tcp};
                if IpProtocol::from_u8(protocol) == Some(IpProtocol::Tcp) {
                    let ihl = (packet[ipv4::VERSION_IHL_OFFSET] & ipv4::IHL_MASK) * 4;
                    let tcp_offset = ipv4::HEADER_OFFSET + ihl as usize;
                    if packet.len() >= tcp_offset + tcp::MIN_HEADER_SIZE {
                        let flags = packet[tcp_offset + tcp::FLAGS_OFFSET];
                        if let Some(_reason) = heuristic::HeuristicEngine::check_tcp_flags(flags) {
                            stats[5] += 1;
                            send_alert(&meta, AlertReason::Heuristic.as_u8());
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
                        send_alert(&meta, AlertReason::Ebpf.as_u8());
                        NetDevice::recycle_rx_buffer();
                        continue;
                    }
                }

                // Firewall gate runs *before* `process_packet` so the
                // stack never emits an ARP reply, ICMP echo, or SYN-ACK
                // for a packet headed to a blocked destination port.
                if dst_port != 0 && engine.fw.is_blocked(dst_port) {
                    stats[2] += 1;
                    send_alert(&meta, AlertReason::Firewall.as_u8());
                    NetDevice::recycle_rx_buffer();
                    continue;
                }

                if let Some(payload) =
                    sec_core::net::stack::process_packet(packet, &mut sink, &syn_secret)
                {
                    if let Some(_reason) = heuristic::HeuristicEngine::check_payload(payload) {
                        stats[5] += 1;
                        send_alert(&meta, AlertReason::Heuristic.as_u8());
                        NetDevice::recycle_rx_buffer();
                        continue;
                    }

                    if payload.len() >= 4 {
                        // Mgmt-plane traffic owns its own counter and never
                        // falls through to the user-traffic AC scan or the
                        // pass/malware counters — otherwise a flood of
                        // mgmt-auth-fail packets would inflate `passed` and
                        // hide real user traffic in the dashboard. Auth
                        // failures still fire an alert; auth successes
                        // dispatch as before.
                        if dst_port == MANAGEMENT_PORT {
                            stats[8] += 1;
                            const UDP_HEADER_LEN: usize = 8;
                            if payload.len() > UDP_HEADER_LEN {
                                let envelope = &payload[UDP_HEADER_LEN..];
                                if let Some(body) = MGMT_AUTH.get().verify(envelope) {
                                    dispatch_mgmt(body, engine, now, &meta);
                                } else {
                                    send_alert(&meta, AlertReason::MgmtAuthFail.as_u8());
                                }
                            }
                            NetDevice::recycle_rx_buffer();
                            continue;
                        }

                        if engine.ac.scan(payload) || engine.dyn_rules.check(payload) {
                            stats[3] += 1;
                            send_alert(&meta, AlertReason::Malware.as_u8());
                        } else {
                            stats[0] += 1;
                            send_alert(&meta, AlertReason::Pass.as_u8());
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

/// Dispatches an authenticated mgmt body.
///
/// `body` is the slice returned by `MgmtAuth::verify` — the auth
/// envelope (counter + MAC) has already been stripped, so offsets here
/// are body-relative. Untyped or under-length bodies are silently
/// ignored: the auth layer guarantees the sender knows the key, so
/// quiet-on-malformed is acceptable as long as the verifier itself is
/// strict.
fn dispatch_mgmt(body: &[u8], engine: &mut SecurityEngine, now: u64, meta: &AlertMeta) {
    use mgmt::mgmt_packet;
    use sec_core::net::constants::ipv4;
    if body.len() < mgmt_packet::MIN_PAYLOAD_LEN {
        return;
    }
    let msg_type = body[mgmt_packet::MSG_TYPE_OFFSET];
    match mgmt::ManagementMessageType::from_u8(msg_type) {
        Some(mgmt::ManagementMessageType::BlockPort) => {
            use mgmt::mgmt_packet::block_port;
            if body.len() >= block_port::MIN_PAYLOAD_LEN {
                let p = (body[block_port::PORT_OFFSET] as u16) << 8
                    | body[block_port::PORT_OFFSET + 1] as u16;
                engine.fw.block_port(p);
            }
        }
        Some(mgmt::ManagementMessageType::AddDpiPattern) => {
            use mgmt::mgmt_packet::add_dpi;
            if body.len() >= add_dpi::MIN_PAYLOAD_LEN {
                let len = body[add_dpi::LEN_OFFSET] as usize;
                if body.len() >= add_dpi::PATTERN_OFFSET + len && len <= add_dpi::MAX_PATTERN_LEN {
                    let pattern = &body[add_dpi::PATTERN_OFFSET..add_dpi::PATTERN_OFFSET + len];
                    engine.dyn_rules.add(pattern);
                }
            }
        }
        Some(mgmt::ManagementMessageType::UploadBpfProgram) => {
            use mgmt::mgmt_packet::upload_bpf;
            if body.len() >= upload_bpf::MIN_PAYLOAD_LEN {
                let count = body[upload_bpf::COUNT_OFFSET] as usize;
                if body.len() >= upload_bpf::INSTR_OFFSET + (count * upload_bpf::INSTR_SIZE)
                    && count <= upload_bpf::MAX_INSTR_COUNT
                {
                    let mut cursor = upload_bpf::INSTR_OFFSET;
                    for i in 0..count {
                        let op = body[cursor];
                        let ra = body[cursor + 1];
                        let rb = body[cursor + 2];
                        let imm = (body[cursor + 3] as u32) << 24
                            | (body[cursor + 4] as u32) << 16
                            | (body[cursor + 5] as u32) << 8
                            | (body[cursor + 6] as u32);
                        engine.bpf_prog[i] = vm::Instruction::new(op, ra, rb, imm);
                        cursor += upload_bpf::INSTR_SIZE;
                    }
                    // Reject programs with out-of-range register indices or
                    // jump targets before they can run on a real packet. The
                    // previous program (if any) stays active, since `bpf_len`
                    // and the slots beyond `count` are untouched.
                    if vm::validate(&engine.bpf_prog[..count]).is_ok() {
                        engine.bpf_len = count;
                    } else {
                        send_alert(meta, AlertReason::BpfReject.as_u8());
                    }
                }
            }
        }
        Some(mgmt::ManagementMessageType::BanIp) => {
            use mgmt::mgmt_packet::ban_ip;
            if body.len() >= ban_ip::MIN_PAYLOAD_LEN {
                let ip_to_ban = &body[ban_ip::IP_OFFSET..ban_ip::IP_OFFSET + ipv4::IP_ADDR_SIZE];
                engine.pbox.ban(ip_to_ban, IP_BAN_DURATION_CYCLES as u64, now);
            }
        }
        None => {}
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
    if data.is_empty() {
        return 0xFFFF;
    }
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
/// Constructs a UDP packet containing the 9-slot statistics array
/// and broadcasts it to the management network. The packet format
/// includes:
/// - Ethernet header with broadcast destination
/// - IP header with checksum
/// - UDP header
/// - 80 bytes of statistics data (10 u64 values)
///
/// # Arguments
///
/// * `stats` - Array of 10 statistics values to transmit
fn send_udp_report(stats: &[u64; 10]) {
    use sec_core::net::constants::IpProtocol;
    use sec_core::net::constants::udp;
    use sec_core::net::constants::{BROADCAST_MAC, ethernet, ipv4};
    /// Size of statistics data payload in telemetry packets (10 u64 values).
    ///
    /// Each telemetry report contains 10 statistics counters, each represented
    /// as a 64-bit big-endian integer, totaling 80 bytes of payload data.
    const STATS_DATA_SIZE: usize = 80;
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
    /// Marks the start of the 72-byte statistics array containing
    /// 9 big-endian u64 counters (see the slot comment above the
    /// `stats` declaration in `kmain`).
    const STATS_OFFSET: usize = UDP_HEADER_OFFSET + udp::HEADER_SIZE;
    let mut offset = STATS_OFFSET;
    for &val in stats {
        packet[offset..offset + 8].copy_from_slice(&val.to_be_bytes());
        offset += 8;
    }
    NetDevice::send(&packet[0..offset]);
}

/// Sends a security alert to the control plane.
///
/// Constructs a UDP packet carrying a fixed-size metadata record
/// (source/destination addresses, ports, protocol, packet length).
/// Attacker-controlled bytes from the inbound packet are deliberately
/// not echoed: the management broadcast domain must not be a vector
/// for relaying untrusted payloads to log/parser tools.
///
/// `AlertReason::Pass` is silently dropped here. Every packet that
/// clears every check would otherwise broadcast a frame, drowning
/// the management LAN under normal traffic and burying the alerts
/// that actually matter.
fn send_alert(meta: &AlertMeta, reason: u8) {
    if reason == AlertReason::Pass.as_u8() {
        return;
    }
    use sec_core::net::constants::IpProtocol;
    use sec_core::net::constants::udp;
    use sec_core::net::constants::{BROADCAST_MAC, ethernet, ipv4};
    /// Maximum size of alert UDP packet in bytes.
    ///
    /// Accommodates Ethernet header (14), IP header (20), UDP header (8),
    /// and the fixed-size alert metadata body.
    const ALERT_PACKET_SIZE: usize = 64;
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

    /// Offset to alert body within the packet.
    ///
    /// Marks the start of the alert message structure containing
    /// the message type, reason code, and metadata fields.
    const ALERT_BODY_OFFSET: usize = UDP_HEADER_OFFSET + udp::HEADER_SIZE;
    let body = ALERT_BODY_OFFSET;
    packet[body] = alert_packet::ALERT_MESSAGE_TYPE;
    packet[body + alert_packet::REASON_OFFSET] = reason;
    packet[body + alert_packet::SRC_IP_OFFSET
        ..body + alert_packet::SRC_IP_OFFSET + alert_packet::SRC_IP_SIZE]
        .copy_from_slice(&meta.src_ip);
    packet[body + alert_packet::DST_IP_OFFSET
        ..body + alert_packet::DST_IP_OFFSET + alert_packet::SRC_IP_SIZE]
        .copy_from_slice(&meta.dst_ip);
    packet[body + alert_packet::SRC_PORT_OFFSET..body + alert_packet::SRC_PORT_OFFSET + 2]
        .copy_from_slice(&meta.src_port.to_be_bytes());
    packet[body + alert_packet::DST_PORT_OFFSET..body + alert_packet::DST_PORT_OFFSET + 2]
        .copy_from_slice(&meta.dst_port.to_be_bytes());
    packet[body + alert_packet::PROTOCOL_OFFSET] = meta.protocol;
    packet[body + alert_packet::PACKET_LEN_OFFSET..body + alert_packet::PACKET_LEN_OFFSET + 2]
        .copy_from_slice(&meta.packet_len.to_be_bytes());
    let offset = body + alert_packet::ALERT_BODY_LEN;

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

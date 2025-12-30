#![no_std]
#![no_main]

mod config;
mod core;
mod drivers;
mod net;
mod security;

use crate::core::allocator::ALLOCATOR;
use crate::core::types::Singleton;
use crate::drivers::net_device::NetDevice;
use ::core::arch::{asm, global_asm};
use config::{
    HEAVY_HITTER_THRESHOLD, IP_ADDR, KERNEL_VERSION, MAC_ADDR, MANAGEMENT_PORT, RATE_LIMIT_PPS,
};
use security::{dos, dpi, firewall, flow, heuristic, vm};

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

struct SecurityEngine {
    ac: dpi::AhoCorasick,
    dyn_rules: dpi::DynamicRules,
    fw: firewall::FirewallState,
    cms: dos::CountMinSketch,
    pbox: dos::PenaltyBox,
    limiter: dos::TokenBucket,
    vm: vm::VM,
    bpf_prog: [vm::Instruction; 64],
    bpf_len: usize,
    flow_table: flow::FlowTable,
}

impl SecurityEngine {
    const fn empty() -> Self {
        Self {
            ac: dpi::AhoCorasick::new(),
            dyn_rules: dpi::DynamicRules::new(),
            fw: firewall::FirewallState::new(),
            cms: dos::CountMinSketch::new(),
            pbox: dos::PenaltyBox::new(),
            limiter: dos::TokenBucket::new(50, RATE_LIMIT_PPS as usize),
            vm: vm::VM::new(),
            bpf_prog: [vm::Instruction::new(0, 0, 0, 0); 64],
            bpf_len: 0,
            flow_table: flow::FlowTable::new(),
        }
    }

    fn init(&mut self) {
        self.ac.insert(b"DROP TABLE");
        self.ac.insert(b"<script>");
        self.ac.insert(b"eval(");
        self.ac.insert(b"UNION SELECT");
        self.ac.build();
        self.fw.block_port(23);
    }
}

static ENGINE: Singleton<SecurityEngine> = Singleton::new(SecurityEngine::empty());

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
    crate::kprintln!("[*] Telemetry   : UDP :8888 (Broadcast)");

    let mut last_report = get_cycles();
    // Stats: [Pass, DDoS, FW, Mal, BPF, Heur, Mem, Flows]
    let mut stats = [0u64; 8];
    const BATCH_SIZE: usize = 64;

    loop {
        let now = get_cycles();
        if now.wrapping_sub(last_report) > 1_000_000_000 {
            let sp: usize;
            unsafe { asm!("mv {}, sp", out(reg) sp) };
            let ebss_addr = ::core::ptr::addr_of!(_ebss) as usize;
            let free_ram = sp.saturating_sub(ebss_addr);
            let used_ram = 65536usize.saturating_sub(free_ram);

            engine.flow_table.prune(now, 10_000_000);

            stats[6] = used_ram as u64;
            stats[7] = engine.flow_table.active_count as u64;

            send_udp_report(&stats);
            engine.cms.reset();
            // Reset counters but keep memory/flow stats
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

                // Extract basic info for flow tracking
                if packet.len() >= 34 && packet[12] == 0x08 && packet[13] == 0x00 {
                    src_ip.copy_from_slice(&packet[26..30]);
                    dst_ip.copy_from_slice(&packet[30..34]);
                    protocol = packet[23];
                    let ihl = (packet[14] & 0x0F) * 4;
                    let payload_offset = 14 + ihl as usize;

                    if packet.len() >= payload_offset + 4 {
                        src_port = (packet[payload_offset] as u16) << 8
                            | packet[payload_offset + 1] as u16;
                        dst_port = (packet[payload_offset + 2] as u16) << 8
                            | packet[payload_offset + 3] as u16;
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
                        // Log new flow (Alert ID 6)
                        // Sample to prevent log flooding
                        if (now & 0x0F) == 0 {
                            send_alert(&src_ip, 6, packet);
                        }
                    }

                    // DDoS check (spoofing detection)
                    if packet.len() >= 50
                        && packet[42] == 0xAE
                        && packet[43] == 0x61
                        && packet[44] == 0x73
                        && packet[45] == 0x00
                    {
                        src_ip.copy_from_slice(&packet[46..50]);
                    }

                    if engine.pbox.is_banned(&src_ip) {
                        drop = true;
                    } else {
                        let count = engine.cms.insert(&src_ip);
                        if count > HEAVY_HITTER_THRESHOLD {
                            engine.pbox.ban(&src_ip, 10_000_000_000);
                            drop = true;
                        }
                    }
                }

                if drop || !engine.limiter.allow() {
                    stats[1] += 1;
                    if stats[1] % 50 == 0 {
                        send_alert(&src_ip, 1, packet);
                    }
                    NetDevice::recycle_rx_buffer();
                    continue;
                }

                // Heuristic analysis (TCP flags)
                if protocol == 6 {
                    let ihl = (packet[14] & 0x0F) * 4;
                    let tcp_offset = 14 + ihl as usize;
                    if packet.len() >= tcp_offset + 14 {
                        let flags = packet[tcp_offset + 13];
                        if let Some(_reason) = heuristic::HeuristicEngine::check_tcp_flags(flags) {
                            stats[5] += 1;
                            send_alert(&src_ip, 5, packet);
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
                        send_alert(&src_ip, 4, packet);
                        NetDevice::recycle_rx_buffer();
                        continue;
                    }
                }

                if let Some(payload) = net::stack::process_packet(packet) {
                    // Heuristic analysis (Payload)
                    if let Some(_reason) = heuristic::HeuristicEngine::check_payload(payload) {
                        stats[5] += 1;
                        send_alert(&src_ip, 5, payload);
                        NetDevice::recycle_rx_buffer();
                        continue;
                    }

                    if payload.len() >= 4 {
                        if dst_port == MANAGEMENT_PORT && payload.len() >= 9 {
                            let msg_type = payload[8];
                            match msg_type {
                                0x01 => {
                                    if payload.len() >= 11 {
                                        let p = (payload[9] as u16) << 8 | payload[10] as u16;
                                        engine.fw.block_port(p);
                                    }
                                }
                                0x02 => {
                                    if payload.len() >= 10 {
                                        let len = payload[9] as usize;
                                        if payload.len() >= 10 + len {
                                            let pattern = &payload[10..10 + len];
                                            engine.dyn_rules.add(pattern);
                                        }
                                    }
                                }
                                0x03 => {
                                    if payload.len() >= 10 {
                                        let count = payload[9] as usize;
                                        if payload.len() >= 10 + (count * 7) && count <= 64 {
                                            let mut cursor = 10;
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
                                                cursor += 7;
                                            }
                                            engine.bpf_len = count;
                                        }
                                    }
                                }
                                0x04 => {
                                    if payload.len() >= 13 {
                                        let ip_to_ban = &payload[9..13];
                                        engine.pbox.ban(ip_to_ban, 10_000_000_000);
                                    }
                                }
                                _ => {}
                            }
                        }

                        if engine.fw.is_blocked(dst_port) {
                            stats[2] += 1;
                            send_alert(&src_ip, 2, payload);
                        } else if engine.ac.scan(payload) || engine.dyn_rules.check(payload) {
                            stats[3] += 1;
                            send_alert(&src_ip, 3, payload);
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

fn get_cycles() -> usize {
    unsafe {
        let c: usize;
        asm!("csrr {}, mcycle", out(reg) c);
        c
    }
}

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

fn send_udp_report(stats: &[u64; 8]) {
    let mut packet = [0u8; 150];
    packet[0..6].copy_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
    packet[6..12].copy_from_slice(&MAC_ADDR);
    packet[12] = 0x08;
    packet[13] = 0x00;
    packet[14] = 0x45;
    packet[15] = 0x00;
    let ip_total_len: u16 = 20 + 8 + 64; // 8 * 8 bytes
    packet[16] = (ip_total_len >> 8) as u8;
    packet[17] = (ip_total_len & 0xFF) as u8;
    packet[18] = 0x00;
    packet[19] = 0x00;
    packet[20] = 0x40;
    packet[21] = 0x00;
    packet[22] = 0x40;
    packet[23] = 17;
    packet[24] = 0x00;
    packet[25] = 0x00;
    packet[26..30].copy_from_slice(&IP_ADDR);
    packet[30..34].copy_from_slice(&[192, 168, 100, 255]);

    let csum = checksum(&packet[14..34]);
    packet[24] = (csum >> 8) as u8;
    packet[25] = (csum & 0xFF) as u8;

    packet[34] = (MANAGEMENT_PORT >> 8) as u8;
    packet[35] = (MANAGEMENT_PORT & 0xFF) as u8;
    packet[36] = 0x22;
    packet[37] = 0xB8;
    let udp_len: u16 = 8 + 64;
    packet[38] = (udp_len >> 8) as u8;
    packet[39] = (udp_len & 0xFF) as u8;
    packet[40] = 0x00;
    packet[41] = 0x00;

    let mut offset = 42;
    for &val in stats.iter() {
        packet[offset..offset + 8].copy_from_slice(&val.to_be_bytes());
        offset += 8;
    }
    NetDevice::send(&packet[0..offset]);
}

fn send_alert(src_ip: &[u8], reason: u8, payload: &[u8]) {
    let mut packet = [0u8; 128];
    packet[0..6].copy_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
    packet[6..12].copy_from_slice(&MAC_ADDR);
    packet[12] = 0x08;
    packet[13] = 0x00;

    packet[14] = 0x45;
    packet[15] = 0x00;
    packet[18] = 0x00;
    packet[19] = 0x00;
    packet[20] = 0x40;
    packet[21] = 0x00;
    packet[22] = 0x40;
    packet[23] = 17;
    packet[24] = 0x00;
    packet[25] = 0x00;
    packet[26..30].copy_from_slice(&IP_ADDR);
    packet[30..34].copy_from_slice(&[192, 168, 100, 255]);

    packet[34] = (MANAGEMENT_PORT >> 8) as u8;
    packet[35] = (MANAGEMENT_PORT & 0xFF) as u8;
    packet[36] = 0x22;
    packet[37] = 0xB8;
    packet[40] = 0x00;
    packet[41] = 0x00;

    let mut offset = 42;
    packet[offset] = 0x02;
    packet[offset + 1] = reason;
    if src_ip.len() >= 4 {
        packet[offset + 2..offset + 6].copy_from_slice(&src_ip[0..4]);
    }
    offset += 6;

    let copy_len = payload.len().min(64);
    packet[offset..offset + copy_len].copy_from_slice(&payload[0..copy_len]);
    offset += copy_len;

    let ip_len = (offset - 14) as u16;
    packet[16] = (ip_len >> 8) as u8;
    packet[17] = (ip_len & 0xFF) as u8;
    let udp_len = (offset - 34) as u16;
    packet[38] = (udp_len >> 8) as u8;
    packet[39] = (udp_len & 0xFF) as u8;

    let csum = checksum(&packet[14..34]);
    packet[24] = (csum >> 8) as u8;
    packet[25] = (csum & 0xFF) as u8;

    NetDevice::send(&packet[0..offset]);
}

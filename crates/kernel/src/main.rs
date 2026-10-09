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
// MMIO, CSR access, linker symbols and the boot stub all need unsafe;
// each block carries a SAFETY comment.
#![allow(unsafe_code)]

/// Hardware device drivers for network interfaces and peripherals.
mod drivers;

mod entropy;
/// VirtIO-Net backed [`sec_core::net::PacketSink`] implementation.
mod net_sink;
/// Kernel panic handler: halts the core.
mod panic;
/// Physical Memory Protection setup: locks W^X across the kernel image.
mod pmp;
/// Stack-overflow detection via a sentinel region between BSS and the stack.
mod stack_guard;
/// RISC-V `mcycle` backed [`sec_core::time::TimeSource`] implementation.
mod time_riscv;
/// M-mode trap handler: prints the cause and halts.
mod trap;

use crate::drivers::net_device::NetDevice;
use crate::drivers::virtio_rng::VirtioRng;
use crate::net_sink::VirtioNetSink;
use crate::time_riscv::MCycle;
use ::core::arch::{asm, global_asm};
use sec_core::config::{
    CMS_DECAY_INTERVAL_CYCLES, FLOW_TIMEOUT_CYCLES, IP_ADDR, KERNEL_VERSION, MAC_ADDR,
    MANAGEMENT_PORT, TELEMETRY_INTERVAL_CYCLES, TELEMETRY_PORT, TOTAL_MEMORY_SIZE,
};
use sec_core::engine::{BootSecrets, Engine};
use sec_core::net::stack::SynCookieSecret;
use sec_core::security::hash::derive_key;
use sec_core::time::TimeSource;
use sec_core::types::Singleton;

include!(concat!(env!("OUT_DIR"), "/mgmt_key.rs"));

// End of BSS, from the linker script; `used_ram` measures from here up to
// the stack pointer.
unsafe extern "C" {
    static _ebss: u8;
}

// Only hart 0 runs the kernel; every statics access assumes a single
// thread. BSS is zeroed here rather than trusting the loader to.
global_asm!(
    r#"
    .section .text.entry
    .global _start
    _start:
        csrr t0, mhartid
        bnez t0, park
        la sp, _stack_top
        la t0, _sbss
        la t1, _ebss
    zero_bss:
        bgeu t0, t1, bss_done
        sd zero, 0(t0)
        addi t0, t0, 8
        j zero_bss
    bss_done:
        call kmain
    park:
        wfi
        j park
"#
);

/// Maximum number of packets to process before servicing timers again.
const BATCH_SIZE: usize = 64;

/// Global security engine instance.
static ENGINE: Singleton<Engine> = Singleton::new(Engine::new(MGMT_KEY));

/// Kernel main entry point.
///
/// Initializes all subsystems, prints boot information, and enters
/// the main packet processing loop. This function never returns.
///
/// Called only by `_start`, on hart 0, once the stack is set up and BSS
/// is zeroed.
#[unsafe(no_mangle)]
pub extern "C" fn kmain() -> ! {
    // Trap handler first so a misconfigured PMP write (or any other
    // synchronous fault from this point on) prints diagnostics and
    // halts instead of jumping to whatever value `mtvec` powered up
    // to. PMP runs immediately after to lock W^X before any driver
    // touches MMIO.
    trap::init();
    pmp::init();
    stack_guard::arm();

    NetDevice::init();
    let rng_present = VirtioRng::init();

    let engine = ENGINE.get();

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
    let mut last_cms_decay = last_report;
    let mut heartbeat = Heartbeat::new();

    // Gather 32 bytes of per-boot entropy from every source the
    // kernel can reach: Zkr (RISC-V K extension TRNG, gated on the
    // `zkr` Cargo feature), virtio-rng (QEMU and other hypervisors),
    // and `mcycle` as a degraded last resort. `gather` XOR-mixes
    // them, so as long as **any** source is unpredictable the output
    // is unpredictable.
    let mut entropy = [0u8; 32];
    let report = entropy::gather(&mut entropy, rng_present);
    crate::kprintln!(
        "[*] Entropy     : zkr={} virtio-rng={} mcycle={}",
        report.zkr,
        report.virtio_rng,
        report.mcycle
    );
    if !report.has_strong_source() {
        crate::kprintln!(
            "[!] No strong entropy source — per-boot secrets derive from mcycle alone. \
             Add virtio-rng (QEMU) or build with --features zkr (RISC-V K silicon) before deploying."
        );
    }
    engine.init(boot_secrets(&entropy));

    loop {
        let now = clock.now();
        if now.wrapping_sub(last_report) > TELEMETRY_INTERVAL_CYCLES as u64 {
            // Catch a stack overflow before we send telemetry built
            // on possibly-corrupted state. Halts on detection.
            stack_guard::check_or_halt();

            engine.prune_flows(now, FLOW_TIMEOUT_CYCLES as u64);
            heartbeat.tick(engine.interval_stats(), engine.active_flows());
            engine.send_telemetry(used_ram() as u64, &mut sink);
            engine.start_interval();

            last_report = now;
            NetDevice::flush();
        }

        if now.wrapping_sub(last_cms_decay) > CMS_DECAY_INTERVAL_CYCLES as u64 {
            engine.decay_heavy_hitters();
            last_cms_decay = now;
        }

        let mut work_done = false;
        for _ in 0..BATCH_SIZE {
            let Some(packet) = NetDevice::try_receive() else {
                break;
            };
            work_done = true;
            let _ = engine.process(packet, now, &mut sink);
            NetDevice::recycle_rx_buffer();
        }

        if work_done {
            NetDevice::flush();
        }
    }
}

/// Splits 32 bytes of boot entropy into the engine's per-boot secrets.
///
/// The epoch is broadcast in telemetry, so it and the sketch key are both
/// derived from the second half under separate labels rather than taken
/// from raw bytes, which would reveal part of the key.
fn boot_secrets(entropy: &[u8; 32]) -> BootSecrets {
    let (syn_cookie, rest) = entropy.split_first_chunk::<16>().unwrap_or((&[0; 16], &[]));
    let other = rest.first_chunk::<16>().unwrap_or(&[0; 16]);
    let epoch = derive_key(other, b"mgmt epoch");
    // 0 is the verifier's "no epoch yet" value, so never use it.
    let mgmt_epoch = u32::from_le_bytes([epoch[0], epoch[1], epoch[2], epoch[3]]).max(1);
    BootSecrets {
        syn_cookie: SynCookieSecret::new(*syn_cookie),
        cms_key: derive_key(other, b"heavy-hitter sketch"),
        mgmt_epoch,
    }
}

/// Bytes of RAM in use: everything below the current stack pointer down
/// to the end of BSS counts as free.
fn used_ram() -> usize {
    let sp: usize;
    // SAFETY: Reading the stack pointer register via inline asm is safe;
    // sp is always a valid register on RISC-V.
    unsafe { asm!("mv {}, sp", out(reg) sp) };
    let ebss_addr = ::core::ptr::addr_of!(_ebss) as usize;
    TOTAL_MEMORY_SIZE.saturating_sub(sp.saturating_sub(ebss_addr))
}

/// Serial-console sign of life: one dot per quiet telemetry tick, folded
/// into a rewriting `[idle Nx]` line once a row fills, and a full stats
/// line whenever there was traffic.
struct Heartbeat {
    dots_on_line: u32,
    idle_ticks: u32,
}

impl Heartbeat {
    /// 60 dots fit in every terminal wider than 60 columns without
    /// wrapping, so `\r` always returns to the start of the row written.
    const DOT_LINE_MAX: u32 = 60;
    /// Blanks a 60-char row; `\x1b[K` is unreliable on wrapped rows.
    const PAD: &str = "                                                            ";

    const fn new() -> Self {
        Self {
            dots_on_line: 0,
            idle_ticks: 0,
        }
    }

    fn tick(&mut self, stats: &sec_core::engine::IntervalStats, active_flows: usize) {
        let had_activity = stats.received_for_us > 0 || stats.drops() > 0 || stats.mgmt > 0;
        if had_activity {
            if self.idle_ticks > 0 {
                crate::kprint!("\x1b[A\r{}\r\x1b[B\r{}\r", Self::PAD, Self::PAD);
            } else if self.dots_on_line > 0 {
                crate::kprint!("\r{}\r", Self::PAD);
            }
            crate::kprintln!(
                "[hb] rx={} pass={} drop(ddos={} fw={} mal={} bpf={} heur={}) flows={} mgmt={}",
                stats.received_for_us,
                stats.passed,
                stats.ddos,
                stats.firewall,
                stats.malware,
                stats.ebpf,
                stats.heuristic,
                active_flows,
                stats.mgmt
            );
            self.dots_on_line = 0;
            self.idle_ticks = 0;
        } else if self.dots_on_line < Self::DOT_LINE_MAX {
            crate::kprint!(".");
            self.dots_on_line += 1;
        } else {
            // First wrap turns the dots row into the idle counter and opens
            // one row beneath it; later wraps rewrite those two rows in place.
            self.idle_ticks += 1;
            if self.idle_ticks == 1 {
                crate::kprint!("\r[idle 1x]{}\n", &Self::PAD[9..]);
            } else {
                crate::kprint!(
                    "\x1b[A\r[idle {}x]{}\r\x1b[B\r{}\r",
                    self.idle_ticks,
                    Self::PAD,
                    Self::PAD
                );
            }
            self.dots_on_line = 0;
        }
    }
}

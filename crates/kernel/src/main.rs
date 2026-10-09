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

use crate::allocator::ALLOCATOR;
use crate::drivers::net_device::NetDevice;
use crate::drivers::virtio_rng::VirtioRng;
use crate::net_sink::VirtioNetSink;
use crate::time_riscv::MCycle;
use ::core::arch::{asm, global_asm};
use sec_core::config::{
    CMS_RESET_INTERVAL_CYCLES, FLOW_TIMEOUT_CYCLES, IP_ADDR, KERNEL_VERSION, MAC_ADDR,
    MANAGEMENT_PORT, TELEMETRY_INTERVAL_CYCLES, TELEMETRY_PORT, TOTAL_MEMORY_SIZE,
};
use sec_core::engine::{BootSecrets, Engine};
use sec_core::net::stack::SynCookieSecret;
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

/// Global security engine instance.
static ENGINE: Singleton<Engine> = Singleton::new(Engine::new(MGMT_KEY));

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
    // Trap handler first so a misconfigured PMP write (or any other
    // synchronous fault from this point on) prints diagnostics and
    // halts instead of jumping to whatever value `mtvec` powered up
    // to. PMP runs immediately after to lock W^X before any driver
    // touches MMIO.
    trap::init();
    pmp::init();
    stack_guard::arm();

    // SAFETY: ALLOCATOR is a mutable static only accessed here during single-threaded kernel
    // init, before the packet loop begins.
    unsafe { (*::core::ptr::addr_of_mut!(ALLOCATOR)).init() };
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
    let mut last_cms_reset = last_report;
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

    /// Maximum number of packets to process in a single iteration.
    const BATCH_SIZE: usize = 64;

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

        if now.wrapping_sub(last_cms_reset) > CMS_RESET_INTERVAL_CYCLES as u64 {
            // Reseed from fresh entropy on every reset interval so the
            // attacker's window for collision precomputation against
            // the current seed is bounded by the interval, not by the
            // kernel's lifetime. If the RNG is absent (real hardware
            // without one configured) we keep the boot-time seed —
            // rotating it from `mcycle` would weaken, not strengthen.
            let mut buf = [0u8; 8];
            let fresh_seed = (rng_present && VirtioRng::read_into(&mut buf) == buf.len())
                .then(|| u64::from_le_bytes(buf));
            engine.reset_heavy_hitters(fresh_seed);
            last_cms_reset = now;
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
fn boot_secrets(entropy: &[u8; 32]) -> BootSecrets {
    let (syn_cookie, rest) = entropy.split_first_chunk::<16>().unwrap_or((&[0; 16], &[]));
    let (cms_seed, rest) = rest.split_first_chunk::<8>().unwrap_or((&[0; 8], &[]));
    let (epoch_a, rest) = rest.split_first_chunk::<4>().unwrap_or((&[0; 4], &[]));
    let epoch_b = rest.first_chunk::<4>().unwrap_or(&[0; 4]);
    // 0 is the verifier's "no epoch yet" value, so never use it.
    let mgmt_epoch = (u32::from_le_bytes(*epoch_a) ^ u32::from_le_bytes(*epoch_b)).max(1);
    BootSecrets {
        syn_cookie: SynCookieSecret::new(*syn_cookie),
        cms_seed: u64::from_le_bytes(*cms_seed),
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

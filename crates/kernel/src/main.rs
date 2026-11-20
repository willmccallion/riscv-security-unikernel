//! Security Unikernel - Main kernel entry point.
//!
//! This is a bare-metal RISC-V unikernel implementing a network security
//! appliance. It processes network packets in real-time, applying multiple
//! security mechanisms including DDoS mitigation, firewall rules, deep packet
//! inspection, heuristic analysis, and custom BPF-style packet filters.
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

use crate::drivers::virtio::{InitError, VirtioNet};
use crate::drivers::virtio_rng::VirtioRng;
use crate::time_riscv::MCycle;
use ::core::arch::{asm, global_asm};
use sec_core::config::{
    FLOW_TIMEOUT, IP_ADDR, KERNEL_VERSION, MAC_ADDR, MANAGEMENT_PORT, TELEMETRY_PORT,
    TOTAL_MEMORY_SIZE,
};
use sec_core::engine::{BootSecrets, Engine, Schedule};
use sec_core::security::hash::MgmtKey;
use sec_core::time::{Ticks, TimeSource};
use sec_core::types::TakeOnce;

include!(concat!(env!("OUT_DIR"), "/mgmt_key.rs"));

// End of BSS, from the linker script; `used_ram` measures from here up to
// the stack pointer.
unsafe extern "C" {
    static _ebss: u8;
}

// Only hart 0 runs the kernel; every statics access assumes a single
// thread. BSS is zeroed here rather than trusting the loader to. The trap
// vector goes in before any Rust code runs, and the FPU is switched on
// (mstatus.FS = Initial): the compiler may emit floating-point
// instructions anywhere, and they trap while FS is Off.
global_asm!(
    r#"
    .section .text.entry
    .global _start
    _start:
        csrr t0, mhartid
        bnez t0, park
        la t0, _trap_entry
        csrw mtvec, t0
        li t0, 0x2000
        csrs mstatus, t0
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

/// Stops this hart for good.
pub fn halt() -> ! {
    loop {
        // SAFETY: `wfi` is always safe in M-mode, and with interrupts never
        // enabled it does not return.
        unsafe { core::arch::asm!("wfi") };
    }
}

/// Maximum number of packets to process before servicing timers again.
const BATCH_SIZE: usize = 64;

/// Global security engine instance.
static ENGINE: TakeOnce<Engine> = TakeOnce::new(Engine::new(MgmtKey::new(MGMT_KEY)));

/// Kernel main entry point.
///
/// Initializes all subsystems, prints boot information, and enters
/// the main packet processing loop. This function never returns.
///
/// Called only by `_start`, on hart 0, once the stack is set up and BSS
/// is zeroed.
#[unsafe(no_mangle)]
pub extern "C" fn kmain() -> ! {
    // Lock W^X before any driver touches MMIO.
    pmp::init();
    stack_guard::arm();

    let mut net = match VirtioNet::init() {
        Ok(net) => net,
        Err(InitError::NotFound) => boot_failure("no VirtIO network card"),
        Err(InitError::AlreadyRunning) => boot_failure("network driver already running"),
    };
    let mut rng = VirtioRng::init();

    let Some(engine) = ENGINE.take() else {
        boot_failure("engine already in use");
    };
    print_banner();
    engine.init(BootSecrets::from_entropy(&gather_entropy(rng.as_mut())));
    run(engine, &mut net)
}

/// Reports why the kernel cannot boot and stops.
fn boot_failure(reason: &str) -> ! {
    crate::kprintln!("\n\x1b[31m[BOOT]\x1b[0m {reason}; halting.");
    halt();
}

fn print_banner() {
    crate::kprintln!("\n[ RISC-V Security Unikernel {} ]", KERNEL_VERSION);
    crate::kprintln!("[*] Architecture: RISC-V64 (Bare Metal)");
    crate::kprintln!("[*] Memory Limit: 64KB");
    // Octet by octet: Ipv4Addr's Display handles padding and costs over a
    // kilobyte of the 64 KB image.
    let [a, b, c, d] = IP_ADDR.octets();
    crate::kprintln!("[*] IP Address  : {a}.{b}.{c}.{d}");
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
}

/// 32 bytes of boot entropy, XOR-mixed from every source present so the
/// result is unpredictable if any one of them is; warns when only the
/// cycle counter was available.
fn gather_entropy(rng: Option<&mut VirtioRng>) -> [u8; 32] {
    let mut entropy = [0u8; 32];
    let report = entropy::gather(&mut entropy, rng);
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
    entropy
}

/// The packet loop: ends intervals as they fall due, then drains a batch
/// of received frames through the engine.
fn run(engine: &mut Engine, net: &mut VirtioNet) -> ! {
    let clock = MCycle;
    let mut heartbeat = Heartbeat::new();
    let mut schedule = Schedule::new(clock.now());
    loop {
        let now = clock.now();
        let due = schedule.due(now);
        if due.telemetry.is_some() {
            end_telemetry_interval(engine, &mut heartbeat, now, net);
        }
        if due.detection.is_some() {
            engine.end_detection_interval(&mut net.tx);
        }
        receive_batch(engine, now, net);
    }
}

/// Prunes idle flows, prints the heartbeat and reports the interval.
fn end_telemetry_interval(
    engine: &mut Engine,
    heartbeat: &mut Heartbeat,
    now: Ticks,
    net: &mut VirtioNet,
) {
    // Catch a stack overflow before sending telemetry built on possibly
    // corrupted state. Halts on detection.
    stack_guard::check_or_halt();
    engine.prune_flows(now, FLOW_TIMEOUT);
    heartbeat.tick(engine.interval_stats(), engine.active_flows());
    engine.send_telemetry(used_ram() as u64, &mut net.tx);
    engine.start_interval();
    net.flush();
}

/// Runs up to [`BATCH_SIZE`] received frames through the engine.
fn receive_batch(engine: &mut Engine, now: Ticks, net: &mut VirtioNet) {
    let mut work_done = false;
    for _ in 0..BATCH_SIZE {
        let processed = net
            .rx
            .receive(|packet| engine.process(packet, now, &mut net.tx));
        if processed.is_none() {
            break;
        }
        work_done = true;
    }
    if work_done {
        net.flush();
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
                stats.bpf,
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

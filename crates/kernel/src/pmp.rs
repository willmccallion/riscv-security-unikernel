//! Physical Memory Protection (PMP) setup.
//!
//! Without PMP the kernel runs in M-mode with the entire address
//! space readable, writable and executable. Any write primitive
//! (a future buffer overrun, a corrupted descriptor, a bad pointer
//! turned arbitrary by chained bugs) becomes RCE because `.text` is
//! writable and `.data` is executable.
//!
//! This module configures six PMP entries in TOR (top-of-range) mode
//! to enforce W^X across the kernel image and to confine MMIO writes
//! to the device window, plus a final entry that denies everything
//! else. Entries are locked (`L = 1`) so they apply to M-mode itself —
//! without `L`, PMP only restricts S/U-mode and the kernel would be
//! unaffected. An M-mode access that matches no entry succeeds, so the
//! deny-all entry is what makes stray accesses trap.
//!
//! Boundary entries (cfg.A = OFF) are needed because TOR derives the
//! lower bound from the previous `pmpaddr` register. They consume a
//! slot but enforce nothing.
//!
//! Layout (QEMU `virt`, also valid for most RV64 SoCs that map UART
//! and VirtIO into the 0x1000_0000 region):
//!
//! | # | Range                     | Perm | Notes                |
//! |---|---------------------------|------|----------------------|
//! | 0 | boundary at 0x1000_0000   | OFF  | TOR base for #1       |
//! | 1 | 0x1000_0000..0x1001_0000  | RW-  | UART + VirtIO MMIO    |
//! | 2 | boundary at 0x8000_0000   | OFF  | TOR base for #3       |
//! | 3 | 0x8000_0000.._etext       | R-X  | code                  |
//! | 4 | _etext.._erodata          | R--  | constants             |
//! | 5 | _erodata..end of RAM      | RW-  | data/bss/stack        |
//! | 6 | whole address space       | ---  | deny-all (NAPOT)      |
//!
//! Anything outside these windows (e.g. a stray pointer to physical
//! 0x0 or to RAM beyond 64 KB) traps to `_trap_entry`, which prints
//! the cause and halts.

use core::arch::asm;
use sec_core::config::TOTAL_MEMORY_SIZE;

const R: u8 = 1 << 0;
const W: u8 = 1 << 1;
const X: u8 = 1 << 2;
const A_TOR: u8 = 1 << 3;
const A_NAPOT: u8 = 3 << 3;
const L: u8 = 1 << 7;

const CFG_OFF: u8 = 0;
const CFG_MMIO: u8 = R | W | A_TOR | L;
const CFG_TEXT: u8 = R | X | A_TOR | L;
const CFG_RODATA: u8 = R | A_TOR | L;
const CFG_DATA: u8 = R | W | A_TOR | L;
const CFG_DENY_ALL: u8 = A_NAPOT | L;

/// Lower bound of the device-MMIO window (UART + VirtIO).
const MMIO_START: usize = 0x1000_0000;
/// Exclusive upper bound; covers `0x1000_0000..0x1001_0000` (UART at
/// 0x10000000, VirtIO MMIO devices at 0x10001000..0x10009000 on
/// QEMU `virt`).
const MMIO_END: usize = 0x1001_0000;
/// RAM base (matches `memory.x`).
const RAM_START: usize = 0x8000_0000;
/// Exclusive end of RAM.
const RAM_END: usize = RAM_START + TOTAL_MEMORY_SIZE;

/// Installs the PMP layout described in the module docstring. `_start`
/// has already installed the trap vector, so a misconfiguration that
/// faults the very next access lands in the trap handler.
pub fn init() {
    unsafe extern "C" {
        static _etext: u8;
        static _erodata: u8;
    }
    let etext = core::ptr::addr_of!(_etext) as usize;
    let erodata = core::ptr::addr_of!(_erodata) as usize;

    // PMP addresses are physical addresses shifted right by 2.
    let addrs: [usize; 6] = [
        MMIO_START >> 2,
        MMIO_END >> 2,
        RAM_START >> 2,
        etext >> 2,
        erodata >> 2,
        RAM_END >> 2,
    ];

    /// Writes `$value` to the PMP CSR `$csr`.
    macro_rules! csrw {
        ($csr:literal, $value:expr) => {
            // SAFETY: PMP CSRs exist on every RV64GC hart in M-mode. Writes
            // take effect only once pmpcfg0's A field is set, which happens
            // last, so every address register is in place before enforcement.
            unsafe { asm!(concat!("csrw ", $csr, ", {0}"), in(reg) $value) }
        };
    }
    csrw!("pmpaddr0", addrs[0]);
    csrw!("pmpaddr1", addrs[1]);
    csrw!("pmpaddr2", addrs[2]);
    csrw!("pmpaddr3", addrs[3]);
    csrw!("pmpaddr4", addrs[4]);
    csrw!("pmpaddr5", addrs[5]);
    // All-ones NAPOT encodes the largest region the hart supports.
    csrw!("pmpaddr6", usize::MAX);

    let cfg: usize = (CFG_OFF as usize)
        | ((CFG_MMIO as usize) << 8)
        | ((CFG_OFF as usize) << 16)
        | ((CFG_TEXT as usize) << 24)
        | ((CFG_RODATA as usize) << 32)
        | ((CFG_DATA as usize) << 40)
        | ((CFG_DENY_ALL as usize) << 48);
    csrw!("pmpcfg0", cfg);
    // Not architecturally required for PMP updates, but keeps aggressive
    // implementations from reordering later accesses ahead of them.
    // SAFETY: a fence has no effect beyond ordering memory accesses.
    unsafe { asm!("fence") };
}

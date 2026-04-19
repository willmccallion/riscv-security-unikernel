//! Machine-mode trap handler.
//!
//! The kernel runs in M-mode and previously had no `mtvec` installed,
//! so any synchronous fault — illegal instruction, misaligned access,
//! PMP violation — would jump to whatever value `mtvec` powered up to
//! and execute random memory as code. That made every latent bug a
//! potential RCE.
//!
//! This module installs a minimal direct-mode handler that prints the
//! three CSRs an operator needs to localise the fault (`mcause`,
//! `mepc`, `mtval`) and then halts the core in `wfi`. There is no
//! recovery path: an unexpected M-mode trap means the kernel's own
//! invariants are broken, and limping along would erase forensic
//! state. Halting and waiting for a power-cycle is the safest action
//! a single-core, no-watchdog system can take.

use core::arch::{asm, global_asm};

global_asm!(
    r#"
    .section .text
    .global _trap_entry
    .align 2
    _trap_entry:
        csrr a0, mcause
        csrr a1, mepc
        csrr a2, mtval
        call trap_report
    1:  wfi
        j 1b
"#
);

/// Decodes the cause vector and prints a one-line fault report.
///
/// Called from `_trap_entry` with the three CSRs already loaded into
/// the C-ABI argument registers. The function is `extern "C"` so the
/// assembly stub can call it without needing to know the Rust ABI.
#[unsafe(no_mangle)]
extern "C" fn trap_report(mcause: usize, mepc: usize, mtval: usize) {
    let interrupt = (mcause >> (usize::BITS as usize - 1)) != 0;
    let code = mcause & !(1usize << (usize::BITS as usize - 1));
    let kind = if interrupt {
        "interrupt"
    } else {
        match code {
            0 => "instr-misaligned",
            1 => "instr-access-fault",
            2 => "illegal-instruction",
            3 => "breakpoint",
            4 => "load-misaligned",
            5 => "load-access-fault",
            6 => "store-misaligned",
            7 => "store-access-fault",
            _ => "unknown",
        }
    };
    crate::kprintln!(
        "\n\x1b[31m[TRAP]\x1b[0m {} mcause={:#x} mepc={:#x} mtval={:#x}",
        kind,
        mcause,
        mepc,
        mtval
    );
}

/// Installs `_trap_entry` as the M-mode trap vector. Call once, early
/// in boot, before any code that could fault.
pub fn init() {
    unsafe extern "C" {
        fn _trap_entry();
    }
    let addr = _trap_entry as *const () as usize;
    // SAFETY: `mtvec` is a standard M-mode CSR. Bottom two bits are
    // mode (0 = Direct), and `_trap_entry` is `.align 2` so they're
    // already zero. Writing this CSR has no effect until a trap
    // actually fires.
    unsafe {
        asm!("csrw mtvec, {0}", in(reg) addr);
    }
}

//! Stack-overflow detection via a sentinel region.
//!
//! The kernel has no MMU and no heap. The stack grows down from
//! `_stack_top` toward `.bss`, and nothing architectural stops a deep
//! call chain from running into the security engine's state.
//!
//! A 256-byte `.stack_guard` section sits between `.bss` and the stack.
//! It is filled with a sentinel at boot and checked from the telemetry
//! tick; if any byte changed, the kernel halts instead of running on
//! corrupt state.
//!
//! This is detection, not prevention: an overflow that skips past the
//! guard is not caught. Making the guard a no-access PMP region would
//! trap instead, but it needs more PMP entries than the layout has left.

use core::ptr;

/// Sentinel byte; 0xA5 is unlikely in pointers, lengths or ASCII text.
const SENTINEL: u8 = 0xA5;

unsafe extern "C" {
    static mut _stack_guard_start: u8;
    static mut _stack_guard_end: u8;
}

fn region() -> (*mut u8, usize) {
    let start = ptr::addr_of_mut!(_stack_guard_start);
    let end = ptr::addr_of_mut!(_stack_guard_end);
    let len = end as usize - start as usize;
    (start, len)
}

/// Fills the guard region with the sentinel byte. Call once at boot;
/// `_start` has already zeroed BSS, which ends below the guard.
pub fn arm() {
    let (start, len) = region();
    // SAFETY: `_stack_guard_start` and `_stack_guard_end` are linker
    // symbols pointing at a region reserved exclusively for this
    // purpose by `memory.x`. Nothing else writes to it during normal
    // operation; an overflow that does write here is exactly what
    // the next [`check`] is meant to detect.
    unsafe {
        ptr::write_bytes(start, SENTINEL, len);
    }
}

/// Verifies the sentinel and halts the kernel with a diagnostic if
/// it has been corrupted. Once tripped, never returns: a corrupted
/// guard means the stack has overrun and any subsequent code is
/// running on a poisoned state. Cheap enough (256 byte reads) to
/// call from the telemetry tick.
pub fn check_or_halt() {
    let (start, len) = region();
    let mut intact = true;
    for i in 0..len {
        // SAFETY: Reading inside the linker-reserved guard region.
        let b = unsafe { ptr::read_volatile(start.add(i)) };
        if b != SENTINEL {
            intact = false;
            break;
        }
    }
    if intact {
        return;
    }
    crate::kprintln!(
        "\n\x1b[31m[STACK GUARD]\x1b[0m sentinel corrupted in {:#x}..{:#x}; halting.",
        start as usize,
        start as usize + len
    );
    loop {
        // SAFETY: `wfi` is always safe in M-mode; halts until the
        // next interrupt (which we never enable), effectively
        // pausing the core forever.
        unsafe { core::arch::asm!("wfi") };
    }
}

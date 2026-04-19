//! Stack-overflow detection via a sentinel region.
//!
//! The kernel has no MMU and no architectural stack-bottom check.
//! The stack grows down from `_stack_top` and the heap grows up
//! from just above `.bss`; nothing prevents a deep-recursion or
//! large-frame overflow from corrupting BSS, the security engine,
//! or the allocator.
//!
//! This module reserves a 256-byte `.stack_guard` section
//! immediately above `.bss` (so it sits between BSS and the stack
//! region), fills it with a fixed sentinel pattern at boot, and
//! verifies the pattern from the telemetry tick. If any byte has
//! changed, something has overrun into the guard and the kernel
//! halts with a clear message instead of limping on with corrupt
//! state.
//!
//! This is detection, not prevention: a write that lands above the
//! guard region still corrupts whatever it hits. Pairing the guard
//! with a PMP entry that marks it inaccessible would convert
//! corruption into an immediate trap, but the current PMP layout
//! treats the whole RAM-after-rodata window as RW; carving out the
//! guard would cost two more PMP entries and is left for later.

use core::ptr;

/// Sentinel byte. 0xA5 (10100101) has equal numbers of 0s and 1s and
/// is unlikely to appear naturally in pointer values, lengths, or
/// ASCII text, which makes accidental "the pattern is still intact"
/// false negatives improbable.
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

/// Fills the guard region with the sentinel byte. Call once at boot,
/// after the BSS clear (which on this kernel happens implicitly via
/// the linker's `NOLOAD` defaults, since `.stack_guard` reserves
/// space without a load image).
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

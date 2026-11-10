//! Heuristic-based security analysis.
//!
//! Detects suspicious patterns that don't match known signatures but
//! indicate potential attacks based on protocol anomalies and payload
//! characteristics.

use crate::net::tcp::TcpFlags;

/// The x86 NOP opcode, which shellcode pads its landing zone with.
const X86_NOP: u8 = 0x90;
/// NOP score at which a payload counts as a sled; shorter runs turn up
/// in ordinary binary data.
const MIN_X86_NOP_SLED: usize = 8;
/// RISC-V `addi x0, x0, 0`, the canonical NOP, in little-endian bytes.
const RISCV_NOP: [u8; 4] = [0x13, 0x00, 0x00, 0x00];
/// Consecutive RISC-V NOPs that count as a sled.
const MIN_RISCV_NOP_SLED: usize = 8;

/// Whether `flags` are a stealth port-scan probe: Xmas or null.
pub const fn is_scan_probe(flags: TcpFlags) -> bool {
    flags.is_xmas() || flags.is_null()
}

/// Whether `payload` carries an x86 or RISC-V NOP sled, the landing zone
/// of buffer-overflow shellcode.
pub fn has_nop_sled(payload: &[u8]) -> bool {
    has_x86_nop_sled(payload) || has_riscv_nop_sled(payload)
}

/// A decaying score rather than a run length, so junk bytes spliced between
/// NOPs (e.g. `[0x00, 0x90, 0x90]` repeated) still trip it.
fn has_x86_nop_sled(payload: &[u8]) -> bool {
    let mut nop_score: usize = 0;
    for &byte in payload {
        if byte == X86_NOP {
            nop_score += 1;
            if nop_score >= MIN_X86_NOP_SLED {
                return true;
            }
        } else {
            nop_score = nop_score.saturating_sub(1);
        }
    }
    false
}

/// A RISC-V sled need not start aligned with the payload, so this matches
/// at any offset.
fn has_riscv_nop_sled(payload: &[u8]) -> bool {
    if payload.len() < RISCV_NOP.len() * MIN_RISCV_NOP_SLED {
        return false;
    }
    let mut consecutive = 0usize;
    let mut i = 0usize;
    while i + RISCV_NOP.len() <= payload.len() {
        if payload[i..i + RISCV_NOP.len()] == RISCV_NOP {
            consecutive += 1;
            if consecutive >= MIN_RISCV_NOP_SLED {
                return true;
            }
            i += RISCV_NOP.len();
        } else {
            consecutive = 0;
            i += 1;
        }
    }
    false
}

#![no_main]
//! Fuzz the BPF VM executor with arbitrary instructions + packet.
//!
//! The first byte of input picks how many instructions to materialise
//! (capped at 64). The next `n * 7` bytes encode instructions; the rest
//! is the packet. We deliberately fuzz `execute` *without* calling
//! `validate` first, because the masking inside `execute` is supposed
//! to absorb out-of-range register indices and stale jump targets even
//! when validation is bypassed. Any panic here means defence-in-depth
//! masking is incomplete.

use libfuzzer_sys::fuzz_target;
use sec_core::security::vm::{Instruction, VM};

const INSTR_BYTES: usize = 7;
const MAX_INSTR: usize = 64;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    let n = (data[0] as usize) % (MAX_INSTR + 1);
    let bytes_needed = 1 + n * INSTR_BYTES;
    if data.len() < bytes_needed {
        return;
    }
    let mut prog = Vec::with_capacity(n);
    let mut cursor = 1;
    for _ in 0..n {
        let op = data[cursor];
        let ra = data[cursor + 1];
        let rb = data[cursor + 2];
        let imm = u32::from_be_bytes([
            data[cursor + 3],
            data[cursor + 4],
            data[cursor + 5],
            data[cursor + 6],
        ]);
        prog.push(Instruction::new(op, ra, rb, imm));
        cursor += INSTR_BYTES;
    }
    let packet = &data[bytes_needed..];
    let mut vm = VM::new();
    let _ = vm.execute(&prog, packet);
});

#![no_main]
//! Fuzz the BPF program decoder and the executor behind it.
//!
//! The first byte of input picks how many 7-byte instructions to decode
//! (up to 64); the rest is the packet. Whatever `Program::decode`
//! accepts must run on any packet without panicking: a panic means the
//! decoder let through a register, jump target or ending the executor
//! cannot handle.

use libfuzzer_sys::fuzz_target;
use sec_core::security::vm::{execute, Program};

const INSTR_BYTES: usize = 7;
const MAX_INSTR: usize = 64;

fuzz_target!(|data: &[u8]| {
    let Some((&count, rest)) = data.split_first() else {
        return;
    };
    let program_len = (usize::from(count) % (MAX_INSTR + 1)) * INSTR_BYTES;
    if rest.len() < program_len {
        return;
    }
    let (encoded, packet) = rest.split_at(program_len);
    if let Ok(program) = Program::decode(encoded) {
        let _ = execute(&program, packet);
    }
});

#![no_main]
//! Fuzz Aho-Corasick pattern insertion + haystack scanning.
//!
//! The first byte picks how many patterns to insert and the next
//! `n` bytes are pattern lengths; we then peel that many slices off
//! the front of the input and treat the remainder as the haystack.
//! Goal: find an insert/scan sequence that panics or mis-reports a
//! match. The automaton has fixed-capacity node and pattern tables,
//! so over-insertion must fail gracefully rather than crash.

use libfuzzer_sys::fuzz_target;
use sec_core::security::dpi::AhoCorasick;

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        return;
    }
    let n = (data[0] as usize) % 16;
    if data.len() < 1 + n {
        return;
    }
    let lens: Vec<usize> = data[1..1 + n].iter().map(|b| (*b as usize) % 8).collect();
    let mut cursor = 1 + n;
    let mut ac = AhoCorasick::new();
    for len in lens {
        if cursor + len > data.len() {
            break;
        }
        let _ = ac.insert(&data[cursor..cursor + len]);
        cursor += len;
    }
    let _ = ac.scan(&data[cursor..]);
});

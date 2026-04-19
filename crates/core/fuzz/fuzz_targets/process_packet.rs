#![no_main]
//! Fuzz the top-level packet processor with arbitrary input.
//!
//! `process_packet` parses Ethernet → IPv4 → TCP/UDP/ICMP/ARP and may
//! mutate the buffer in place (SYN-ACK rewrites, checksum recompute).
//! We feed it raw bytes and assert it neither panics nor reads out of
//! bounds for any input. The sink discards frames so we don't grow
//! unbounded memory inside the fuzz iteration.

use libfuzzer_sys::fuzz_target;
use sec_core::net::PacketSink;
use sec_core::net::stack::{SynCookieSecret, process_packet};

struct NullSink;
impl PacketSink for NullSink {
    fn send(&mut self, _frame: &[u8]) {}
}

fuzz_target!(|data: &[u8]| {
    let mut buf = data.to_vec();
    let secret = SynCookieSecret::new([0x42; 16]);
    let mut sink = NullSink;
    let _ = process_packet(&mut buf, &mut sink, &secret);
});

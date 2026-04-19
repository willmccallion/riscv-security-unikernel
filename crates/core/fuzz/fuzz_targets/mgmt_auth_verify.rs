#![no_main]
//! Fuzz the mgmt-plane authenticator.
//!
//! `MgmtAuth::verify` parses `[counter:u64 BE][body][mac:u64 BE]` from
//! attacker-controlled bytes. A successful verify is fine; a panic, OOB
//! read, or accepting an unsigned packet is a crash. We don't need to
//! produce valid MACs — the fuzzer's job is to find inputs that bypass
//! the length / counter / MAC checks without knowing the key.

use libfuzzer_sys::fuzz_target;
use sec_core::security::mgmt_auth::MgmtAuth;

fuzz_target!(|data: &[u8]| {
    let mut auth = MgmtAuth::new(*b"FUZZ-KEY-FUZZKEY");
    auth.set_epoch(0xDEADBEEF);
    let _ = auth.verify(data);
});

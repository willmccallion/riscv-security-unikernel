//! Any UDP payload is safely rejected or decrypted as QUIC Initials, and
//! any decrypted payload's frames parse or stop cleanly. Mutated
//! ciphertext rarely survives authentication, so the frame parser behind
//! decryption is fuzzed directly as well.

#![no_main]

use libfuzzer_sys::fuzz_target;
use security_daemon::monitor::quic::{client_initial_crypto, crypto_frames};

fuzz_target!(|data: &[u8]| {
    let _ = client_initial_crypto(data);
    for fragment in crypto_frames(data) {
        assert!(fragment.bytes.len() <= data.len());
    }
});

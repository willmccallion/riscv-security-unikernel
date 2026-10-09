//! Any byte stream, read as TLS records or as a bare handshake message,
//! yields at most a printable server name of legal length.

#![no_main]

use libfuzzer_sys::fuzz_target;
use security_daemon::monitor::tls::{Hello, parse_client_hello, parse_handshake};

fn check(hello: &Hello) {
    if let Hello::Named(name) = hello {
        assert!(!name.name.is_empty() && name.name.len() <= 253);
        assert!(name.name.bytes().all(|b| b.is_ascii_graphic()), "unprintable name {:?}", name.name);
    }
}

fuzz_target!(|data: &[u8]| {
    check(&parse_client_hello(data));
    check(&parse_handshake(data));
});

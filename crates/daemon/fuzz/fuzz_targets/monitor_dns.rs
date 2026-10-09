//! Any DNS message parses or is rejected, and every name it yields is
//! printable and of legal length.

#![no_main]

use libfuzzer_sys::fuzz_target;
use security_daemon::monitor::dns::parse_response;

fuzz_target!(|data: &[u8]| {
    let Some(response) = parse_response(data) else { return };
    let names = response.question.iter().chain(response.addresses.iter().map(|a| &a.name));
    for name in names {
        assert!(name.len() <= 253, "name too long: {}", name.len());
        assert!(name.bytes().all(|b| b.is_ascii_graphic() || b == b'.'), "unprintable name {name:?}");
    }
});

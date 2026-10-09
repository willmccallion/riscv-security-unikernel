//! Any frame, of any link type, decodes or is rejected without panicking.

#![no_main]

use libfuzzer_sys::fuzz_target;
use security_daemon::monitor::decode::{LinkType, decode};

fuzz_target!(|data: &[u8]| {
    let Some((&selector, frame)) = data.split_first() else { return };
    let link = match selector % 4 {
        0 => LinkType::Ethernet,
        1 => LinkType::RawIp,
        2 => LinkType::LinuxSll,
        _ => LinkType::LinuxSll2,
    };
    let _ = decode(link, frame);
});

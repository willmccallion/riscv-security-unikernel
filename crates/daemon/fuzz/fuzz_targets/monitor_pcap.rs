//! Any file is read as pcap or rejected, without panicking or allocating
//! more than the reader's record limit.

#![no_main]

use libfuzzer_sys::fuzz_target;
use security_daemon::monitor::pcap::PcapReader;

fuzz_target!(|data: &[u8]| {
    let Ok(mut reader) = PcapReader::new(data) else { return };
    let mut frame = Vec::new();
    while let Ok(Some(_)) = reader.next_record(&mut frame) {
        assert!(frame.len() <= 256 * 1024);
    }
});

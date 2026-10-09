//! Behaviour of the `VirtIO` driver under load.
//!
//! Ignored by default; run with `make qemu-test`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use qemu_harness::{Kernel, default_kernel_elf, frame};
use std::collections::BTreeSet;
use std::time::{Duration, Instant};

fn syn(src_ip: [u8; 4], src_port: u16) -> Vec<u8> {
    let mut tcp = vec![0u8; 20];
    tcp[0..2].copy_from_slice(&src_port.to_be_bytes());
    tcp[2..4].copy_from_slice(&80u16.to_be_bytes());
    tcp[12] = 0x50;
    tcp[13] = 0x02;
    frame::ipv4_to_kernel(src_ip, 6, &tcp)
}

fn synack_dst_port(f: &[u8]) -> Option<u16> {
    let is_synack = f.len() >= 54 && f[23] == 6 && f[26..30] == frame::KERNEL_IP;
    is_synack.then(|| u16::from_be_bytes([f[36], f[37]]))
}

/// Each new flow can emit a sampled flow alert alongside its SYN-ACK, so
/// a two-packet batch can queue more frames than the two TX descriptors.
/// Every SYN must still get its own SYN-ACK.
#[test]
#[ignore = "needs a built kernel and qemu; run via `make qemu-test`"]
fn every_syn_gets_its_own_synack_when_tx_ring_is_contended() {
    let kernel = Kernel::boot(&default_kernel_elf()).expect("kernel boots");
    kernel.drain().unwrap();
    let mut sent = BTreeSet::new();
    let mut acked = BTreeSet::new();

    for round in 0..150u16 {
        for j in 0..2u16 {
            let src_port = 10_000 + round * 2 + j;
            let src_ip = [10, 0, 1, u8::try_from(round % 200 + 1).unwrap()];
            kernel.send(&syn(src_ip, src_port)).unwrap();
            assert!(sent.insert(src_port), "source ports are unique");
        }
        let deadline = Instant::now() + Duration::from_millis(30);
        while Instant::now() < deadline {
            if let Some(port) = kernel
                .recv(Duration::from_millis(5))
                .unwrap()
                .and_then(|f| synack_dst_port(&f))
            {
                let _ = acked.insert(port);
            }
        }
    }

    let missing: Vec<_> = sent.difference(&acked).collect();
    assert!(
        missing.is_empty(),
        "no SYN-ACK for source ports {missing:?}"
    );
}

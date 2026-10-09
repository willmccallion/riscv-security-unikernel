//! End-to-end checks against the real kernel under QEMU.
//!
//! Ignored by default because they need a built kernel and
//! `qemu-system-riscv64`; run them with `make qemu-test`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use qemu_harness::{Kernel, default_kernel_elf, frame};
use std::time::Duration;

fn boot() -> Kernel {
    Kernel::boot(&default_kernel_elf()).expect("kernel boots")
}

#[test]
#[ignore = "needs a built kernel and qemu; run via `make qemu-test`"]
fn kernel_answers_arp_for_its_own_address() {
    let kernel = boot();

    let alive = kernel.is_alive().unwrap();

    assert!(alive, "no ARP reply; serial:\n{}", kernel.serial_snapshot());
}

#[test]
#[ignore = "needs a built kernel and qemu; run via `make qemu-test`"]
fn kernel_broadcasts_telemetry_before_an_operator_is_known() {
    let kernel = boot();

    let telemetry = kernel
        .recv_matching(Duration::from_secs(5), |f| {
            frame::is_udp_from_kernel_to_port(f, sec_core::config::TELEMETRY_PORT)
        })
        .unwrap();

    let telemetry = telemetry.expect("telemetry frame within 5s");
    assert_eq!(&telemetry[0..6], &[0xFF; 6], "telemetry is broadcast");
}

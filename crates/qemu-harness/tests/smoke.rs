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

#[test]
#[ignore = "needs a built kernel and qemu; run via `make qemu-test`"]
fn telemetry_is_signed_with_the_report_key() {
    let kernel = boot();
    let mgmt = qemu_harness::mgmt::MgmtClient::connect(&kernel).unwrap();

    let telemetry = kernel
        .recv_matching(Duration::from_secs(5), |f| {
            frame::telemetry_slots(f).is_some()
        })
        .unwrap()
        .expect("telemetry frame within 5s");

    assert!(
        mgmt.verify_report(&telemetry).is_some(),
        "telemetry MAC does not verify"
    );
}

#[test]
#[ignore = "needs a built kernel and qemu; run via `make qemu-test`"]
fn kernel_runs_on_one_hart_when_the_machine_has_four() {
    let kernel = Kernel::boot_with(&default_kernel_elf(), &["-smp", "4"]).expect("kernel boots");

    let alive = kernel.is_alive().unwrap();

    assert!(alive, "serial:\n{}", kernel.serial_snapshot());
    let banners = kernel
        .serial_snapshot()
        .matches("[ RISC-V Security Unikernel")
        .count();
    assert_eq!(banners, 1, "more than one hart ran kmain");
}

//! Authenticated mgmt commands against the real kernel.
//!
//! Ignored by default; run with `make qemu-test`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use qemu_harness::mgmt::MgmtClient;
use qemu_harness::{Kernel, default_kernel_elf, frame};
use sec_core::security::alert::AlertReason;
use sec_core::security::mgmt::ManagementMessageType;
use sec_core::security::vm::Opcode;
use std::time::Duration;

const ALERT_WAIT: Duration = Duration::from_secs(2);

fn instruction(op: Opcode, reg_a: u8, reg_b: u8, imm: u32) -> Vec<u8> {
    let mut bytes = vec![op as u8, reg_a, reg_b];
    bytes.extend_from_slice(&imm.to_be_bytes());
    bytes
}

fn upload_body(instructions: &[Vec<u8>]) -> Vec<u8> {
    let mut body = vec![
        ManagementMessageType::UploadBpfProgram as u8,
        u8::try_from(instructions.len()).unwrap(),
    ];
    body.extend(instructions.concat());
    body
}

/// Drops UDP to `port`; passes everything else.
fn drop_udp_port(port: u16) -> Vec<u8> {
    upload_body(&[
        instruction(Opcode::Ldh, 0, 0, 36),
        instruction(Opcode::Ldi, 1, 0, u32::from(port)),
        instruction(Opcode::Eq, 0, 1, 0),
        instruction(Opcode::Jt, 0, 0, 5),
        instruction(Opcode::Ret, 0, 0, 1),
        instruction(Opcode::Ret, 0, 0, 0),
    ])
}

#[track_caller]
fn expect_alert(kernel: &Kernel, reason: AlertReason) {
    let got = kernel
        .recv_matching(ALERT_WAIT, |f| {
            frame::alert_reason(f) == Some(reason.as_u8())
        })
        .unwrap();
    assert!(
        got.is_some(),
        "no {reason:?} alert; serial:\n{}",
        kernel.serial_snapshot()
    );
}

#[test]
#[ignore = "needs a built kernel and qemu; run via `make qemu-test`"]
fn rejected_bpf_upload_leaves_the_active_program_intact() {
    let kernel = Kernel::boot(&default_kernel_elf()).expect("kernel boots");
    let mut mgmt = MgmtClient::connect(&kernel).unwrap();
    mgmt.send(&kernel, &drop_udp_port(9999)).unwrap();
    let probe = frame::udp_to_kernel(frame::HOST_IP, 5000, 9999, b"probe");
    kernel.send(&probe).unwrap();
    expect_alert(&kernel, AlertReason::Ebpf);

    let passes_then_invalid = upload_body(&[
        instruction(Opcode::Ret, 0, 0, 1),
        vec![0xFF, 0, 0, 0, 0, 0, 0],
    ]);
    mgmt.send(&kernel, &passes_then_invalid).unwrap();
    expect_alert(&kernel, AlertReason::BpfReject);
    kernel.drain().unwrap();
    kernel.send(&probe).unwrap();

    expect_alert(&kernel, AlertReason::Ebpf);
}

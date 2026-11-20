//! Authenticated mgmt commands against the real kernel.
//!
//! Ignored by default; run with `make qemu-test`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use qemu_harness::mgmt::MgmtClient;
use qemu_harness::{Kernel, default_kernel_elf, frame};
use sec_core::security::alert::AlertReason;
use sec_core::security::mgmt::{ManagementMessageType, MgmtOutcome};
use sec_core::security::vm::{Instruction, Opcode};
use std::time::Duration;

const ALERT_WAIT: Duration = Duration::from_secs(2);

fn upload_body(instructions: &[Instruction]) -> Vec<u8> {
    let mut body = vec![
        ManagementMessageType::UploadBpfProgram as u8,
        u8::try_from(instructions.len()).unwrap(),
    ];
    body.extend(instructions.iter().flat_map(|i| i.to_bytes()));
    body
}

/// Drops UDP to `port`; passes everything else.
fn drop_udp_port(port: u16) -> Vec<u8> {
    upload_body(&[
        Instruction::new(Opcode::Ldh, 0, 0, 36),
        Instruction::new(Opcode::Ldi, 1, 0, u32::from(port)),
        Instruction::new(Opcode::Eq, 0, 1, 0),
        Instruction::new(Opcode::Jt, 0, 0, 5),
        Instruction::new(Opcode::Ret, 0, 0, 1),
        Instruction::new(Opcode::Ret, 0, 0, 0),
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
    let _ = mgmt.send(&kernel, &drop_udp_port(9999)).unwrap();
    let probe = frame::udp_to_kernel(frame::HOST_IP, 5000, 9999, b"probe");
    kernel.send(&probe).unwrap();
    expect_alert(&kernel, AlertReason::Bpf);

    let passes_then_invalid = upload_body(&[
        Instruction::new(Opcode::Ret, 0, 0, 1),
        Instruction::from_bytes(&[0xFF, 0, 0, 0, 0, 0, 0]),
    ]);
    let _ = mgmt.send(&kernel, &passes_then_invalid).unwrap();
    let ack = kernel
        .recv_matching(ALERT_WAIT, |f| frame::mgmt_ack(f).is_some())
        .unwrap()
        .and_then(|f| frame::mgmt_ack(&f));
    assert_eq!(
        ack.map(|(_, _, outcome)| outcome),
        Some(MgmtOutcome::Invalid as u8)
    );
    kernel.drain().unwrap();
    kernel.send(&probe).unwrap();

    expect_alert(&kernel, AlertReason::Bpf);
}

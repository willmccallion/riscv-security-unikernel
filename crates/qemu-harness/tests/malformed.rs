//! Malformed frames that must not take the kernel down.
//!
//! Ignored by default; run with `make qemu-test`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use qemu_harness::{Kernel, default_kernel_elf, frame};

#[test]
#[ignore = "needs a built kernel and qemu; run via `make qemu-test`"]
fn kernel_survives_ipv4_header_longer_than_the_frame() {
    let kernel = Kernel::boot(&default_kernel_elf()).expect("kernel boots");
    let mut f = frame::udp_to_kernel(frame::HOST_IP, 4000, 80, &[0; 18]);
    f[14] = 0x4F;
    assert_eq!(f.len(), 60, "IHL 15 claims 74 bytes of headers");

    kernel.send(&f).unwrap();
    let alive = kernel.is_alive().unwrap();

    assert_eq!(kernel.fatal(), None);
    assert!(alive, "serial:\n{}", kernel.serial_snapshot());
}

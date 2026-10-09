//! The real sandbox, applied by the real binary on this kernel.

use std::process::Command;

#[test]
fn each_sandbox_layer_refuses_what_it_should_on_this_kernel() {
    let output = Command::new(env!("CARGO_BIN_EXE_security-daemon"))
        .arg("sandbox-check")
        .output()
        .expect("run security-daemon");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "{stdout}\n{}", String::from_utf8_lossy(&output.stderr));
    assert_eq!(stdout.matches("blocked:").count(), 6, "{stdout}");
}

//! Build script for the security-unikernel kernel crate.
// Build scripts signal failure by panicking; unwrap/expect are the correct
// tool here since there is no meaningful recovery path in a build script.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::env;
use std::fs;
use std::path::PathBuf;

/// Build script entry point for kernel memory layout configuration.
///
/// Copies the memory layout linker script (`memory.x`) to the build output
/// directory and configures the linker to use it. This ensures the kernel's
/// memory regions (text, data, bss, heap) are placed according to the
/// embedded system's memory map.
///
/// Also emits the per-build mgmt-plane MAC key into `OUT_DIR/mgmt_key.rs`
/// from the `KERNEL_MGMT_KEY` env var (32 hex chars). Falls back to a
/// fixed development key for debug builds; refuses to produce a release
/// kernel without an explicit key, so a forgettable default never ships.
fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    println!("cargo:rerun-if-changed=memory.x");
    println!("cargo:rerun-if-env-changed=KERNEL_MGMT_KEY");

    fs::copy("memory.x", out_dir.join("memory.x")).expect("failed to copy memory.x");
    println!("cargo:rustc-link-search={}", out_dir.display());
    println!("cargo:rustc-link-arg=-Tmemory.x");

    let profile = env::var("PROFILE").unwrap_or_else(|_| "debug".into());
    let key = match env::var("KERNEL_MGMT_KEY") {
        Ok(hex) => parse_hex_key(&hex),
        Err(_) => {
            assert!(
                profile != "release",
                "KERNEL_MGMT_KEY must be set for release builds (32 hex chars). \
                 The dev key is a known constant; shipping it would mean every operator \
                 with a copy of the source can authenticate to your kernel."
            );
            println!(
                "cargo:warning=KERNEL_MGMT_KEY not set; using DEV mgmt key. Do not deploy."
            );
            *b"DEV-KEY-DEV-KEY!"
        }
    };

    let mut body = String::with_capacity(160);
    body.push_str("/// Pre-shared 16-byte key used by `MgmtAuth` to verify mgmt packets.\n");
    body.push_str("/// Generated at build time from `KERNEL_MGMT_KEY` (or the dev key in debug).\n");
    body.push_str("pub const MGMT_KEY: [u8; 16] = [");
    for (i, b) in key.iter().enumerate() {
        if i > 0 {
            body.push_str(", ");
        }
        body.push_str(&format!("0x{b:02x}"));
    }
    body.push_str("];\n");
    fs::write(out_dir.join("mgmt_key.rs"), body).expect("failed to write mgmt_key.rs");
}

fn parse_hex_key(hex: &str) -> [u8; 16] {
    assert!(
        hex.len() == 32,
        "KERNEL_MGMT_KEY must be 32 hex characters (16 bytes); got {} chars",
        hex.len()
    );
    let mut out = [0u8; 16];
    for (i, byte) in out.iter_mut().enumerate() {
        let hi = hex_nibble(hex.as_bytes()[i * 2]);
        let lo = hex_nibble(hex.as_bytes()[i * 2 + 1]);
        *byte = (hi << 4) | lo;
    }
    out
}

fn hex_nibble(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => panic!("KERNEL_MGMT_KEY contains non-hex character: {}", c as char),
    }
}

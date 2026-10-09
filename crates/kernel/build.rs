//! Build script for the security-unikernel kernel crate.
// Build scripts signal failure by panicking; unwrap/expect are the correct
// tool here since there is no meaningful recovery path in a build script.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::env;
use std::fs;
use std::io::Read;
use std::path::PathBuf;

/// Build script entry point for kernel memory layout configuration.
///
/// Copies the memory layout linker script (`memory.x`) to the build output
/// directory and configures the linker to use it. This ensures the kernel's
/// memory regions (text, data, bss, heap) are placed according to the
/// embedded system's memory map.
///
/// Also emits the per-build mgmt-plane MAC key into `OUT_DIR/mgmt_key.rs`.
/// The key comes from the first source that resolves, in order:
/// 1. `KERNEL_MGMT_KEY` env var (32 hex chars) — CI / explicit operator path.
/// 2. `.mgmt-key.local` at the workspace root — shared with the GUI so both
///    sides authenticate against the same value when the Makefile has
///    materialised a local dev key.
/// 3. A fresh 16 bytes from `/dev/urandom` — debug only; release builds
///    panic. No shared constant is ever baked into a shipped binary.
fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    println!("cargo:rerun-if-changed=memory.x");
    println!("cargo:rerun-if-env-changed=KERNEL_MGMT_KEY");

    let _ = fs::copy("memory.x", out_dir.join("memory.x")).expect("failed to copy memory.x");
    println!("cargo:rustc-link-search={}", out_dir.display());
    println!("cargo:rustc-link-arg=-Tmemory.x");

    let profile = env::var("PROFILE").unwrap_or_else(|_| "debug".into());
    let key = if let Ok(hex) = env::var("KERNEL_MGMT_KEY") {
        parse_hex_key(&hex)
    } else if let Some(key) = read_dev_key_file() {
        key
    } else {
        assert!(
            profile != "release",
            "KERNEL_MGMT_KEY must be set for release builds (32 hex chars). \
             Without an explicit key every operator with a copy of the source \
             would be able to authenticate to your kernel."
        );
        println!(
            "cargo:warning=KERNEL_MGMT_KEY not set and no .mgmt-key.local found; generated ephemeral dev key. \
             Run `make dev-key` or set KERNEL_MGMT_KEY=<32 hex> to share auth with the GUI."
        );
        random_key()
    };

    let bytes: Vec<String> = key.iter().map(|b| format!("0x{b:02x}")).collect();
    let body = format!(
        "/// Pre-shared 16-byte key used by `MgmtAuth` to verify mgmt packets.\n\
         /// Generated at build time from `KERNEL_MGMT_KEY`, `.mgmt-key.local`, or `/dev/urandom` (debug only).\n\
         pub const MGMT_KEY: [u8; 16] = [{}];\n",
        bytes.join(", ")
    );
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

fn random_key() -> [u8; 16] {
    let mut key = [0u8; 16];
    fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut key))
        .expect(
            "failed to read /dev/urandom for ephemeral dev key; \
             set KERNEL_MGMT_KEY=<32 hex> explicitly",
        );
    key
}

fn read_dev_key_file() -> Option<[u8; 16]> {
    let manifest = env::var("CARGO_MANIFEST_DIR").ok()?;
    let path = PathBuf::from(manifest).join("../../.mgmt-key.local");
    println!("cargo:rerun-if-changed={}", path.display());
    let raw = fs::read_to_string(&path).ok()?;
    let hex = raw.trim();
    if hex.len() != 32 || !hex.as_bytes().iter().all(u8::is_ascii_hexdigit) {
        println!(
            "cargo:warning={} is not 32 hex chars — ignoring",
            path.display()
        );
        return None;
    }
    Some(parse_hex_key(hex))
}

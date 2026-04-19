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
fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    println!("cargo:rerun-if-changed=memory.x");

    fs::copy("memory.x", out_dir.join("memory.x")).expect("failed to copy memory.x");
    println!("cargo:rustc-link-search={}", out_dir.display());
    println!("cargo:rustc-link-arg=-Tmemory.x");
}

//! Loads the mgmt key the engine verifies commands with.

use anyhow::{Context, Result, bail};
use sec_core::security::mgmt_auth::parse_hex_key;
use std::path::PathBuf;

/// Reads the key from `KERNEL_MGMT_KEY`, or from `.mgmt-key.local` in the
/// current directory or one of its parents (the file `make dev-key`
/// writes). There is no built-in fallback key.
pub fn load() -> Result<[u8; 16]> {
    if let Ok(hex) = std::env::var("KERNEL_MGMT_KEY") {
        return parse_hex_key(hex.trim()).context("KERNEL_MGMT_KEY must be 32 hex characters");
    }
    let mut dir: PathBuf = std::env::current_dir()?;
    loop {
        let candidate = dir.join(".mgmt-key.local");
        if candidate.exists() {
            let hex = std::fs::read_to_string(&candidate)
                .with_context(|| format!("read {}", candidate.display()))?;
            return parse_hex_key(hex.trim())
                .with_context(|| format!("{} must hold 32 hex characters", candidate.display()));
        }
        if !dir.pop() {
            bail!("no mgmt key: set KERNEL_MGMT_KEY or run `make dev-key`");
        }
    }
}

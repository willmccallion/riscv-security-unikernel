//! Sealed management commands, as the GUI sends them.

use crate::{Kernel, frame};
use anyhow::{Context, Result, bail};
use sec_core::config::MANAGEMENT_PORT;
use sec_core::security::mgmt_auth::{COUNTER_LEN, MAC_LEN, seal};
use sec_core::security::mgmt_auth::parse_hex_key;
use sec_core::security::report_auth::{ReportVerifier, report_key};
use std::path::Path;
use std::time::Duration;

/// Source port the harness sends mgmt commands from.
const MGMT_SRC_PORT: u16 = 40_000;

/// Sends mgmt commands sealed with the kernel's key and current epoch.
#[derive(Debug)]
pub struct MgmtClient {
    key: [u8; 16],
    epoch: u32,
    seq: u32,
}

impl MgmtClient {
    /// Reads the key the kernel was built with and learns the boot epoch
    /// from the kernel's telemetry.
    pub fn connect(kernel: &Kernel) -> Result<Self> {
        let key = load_key()?;
        let telemetry = kernel
            .recv_matching(Duration::from_secs(5), |f| {
                frame::telemetry_slots(f).is_some()
            })?
            .context("no telemetry frame to learn the epoch from")?;
        let slots = frame::telemetry_slots(&telemetry).context("telemetry vanished")?;
        let epoch = u32::try_from(slots[9]).context("epoch exceeds u32")?;
        Ok(Self { key, epoch, seq: 0 })
    }

    /// Verifies a report frame's signature under the key the kernel was
    /// built with, returning its body.
    pub fn verify_report<'a>(&self, frame: &'a [u8]) -> Option<&'a [u8]> {
        let mut verifier = ReportVerifier::new(report_key(&self.key));
        verifier.verify(frame.get(42..)?).map(|report| report.body)
    }

    /// Checks the kernel still runs its packet loop: sends a command of an
    /// unknown type, which changes no state but must be acknowledged. Mgmt
    /// traffic bypasses every data-plane filter, so a missing ack means the
    /// kernel is stuck, not that a rule dropped the probe.
    pub fn ping(&mut self, kernel: &Kernel) -> Result<bool> {
        const UNKNOWN_COMMAND: u8 = 0xFF;
        for _ in 0..4 {
            kernel.drain()?;
            let seq = self.send(kernel, &[UNKNOWN_COMMAND])?;
            let acked = kernel.recv_matching(Duration::from_millis(500), |f| {
                frame::mgmt_ack(f).is_some_and(|(acked, _, _)| acked == seq)
            })?;
            if acked.is_some() {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Seals `body` with the next counter, sends it to the mgmt port and
    /// returns the sequence number used.
    pub fn send(&mut self, kernel: &Kernel, body: &[u8]) -> Result<u32> {
        self.seq += 1;
        let counter = (u64::from(self.epoch) << 32) | u64::from(self.seq);
        let mut sealed = vec![0u8; COUNTER_LEN + body.len() + MAC_LEN];
        let Some(n) = seal(&self.key, counter, body, &mut sealed) else {
            bail!("sealed buffer too small");
        };
        kernel.send(&frame::udp_to_kernel(
            frame::HOST_IP,
            MGMT_SRC_PORT,
            MANAGEMENT_PORT,
            &sealed[..n],
        ))?;
        Ok(self.seq)
    }
}

fn load_key() -> Result<[u8; 16]> {
    let hex = if let Ok(hex) = std::env::var("KERNEL_MGMT_KEY") {
        hex
    } else {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.mgmt-key.local");
        std::fs::read_to_string(&path)
            .with_context(|| format!("read {}", path.display()))?
            .trim()
            .to_string()
    };
    parse_hex_key(&hex).context("mgmt key must be 32 hex characters")
}

//! Per-boot entropy gathering.
//!
//! Defines an [`EntropySource`] trait and implementations for every
//! source the kernel knows how to consume, plus a [`gather`] helper
//! that XOR-mixes every available source into the caller's buffer.
//!
//! XOR composition gives a useful property: as long as **any** of the
//! mixed sources is unpredictable, the output is unpredictable. So the
//! caller can ask for entropy without having to know which source
//! actually fed it — virtio-rng under QEMU, Zkr on real silicon with
//! the K extension, or the degraded `mcycle` fallback on bare hardware
//! without either.
//!
//! Sources NOT yet implemented (room for future hardware):
//!
//! - **SBI entropy.** No standardised SBI extension as of SBI 3.0; some
//!   vendors expose proprietary calls. Add a `SbiSource` if your
//!   firmware does.
//! - **SoC TRNG MMIO.** SiFive FU740, Allwinner D1, ESP32-C, etc. each
//!   ship a TRNG at a vendor-specific MMIO address. Add a per-SoC
//!   source gated on a board-ID probe.

use crate::drivers::virtio_rng::VirtioRng;
use crate::time_riscv::MCycle;
use sec_core::config::MAC_ADDR;
use sec_core::time::TimeSource;

/// A source of per-boot entropy. Implementations may write fewer bytes
/// than requested (e.g. virtio-rng has a small per-request cap, Zkr
/// drains 16 bits at a time); the return value tells the caller how
/// many bytes were actually filled.
pub trait EntropySource {
    /// Fills `buf` with as much entropy as the source can produce.
    /// Returns the number of bytes written.
    fn fill(&mut self, buf: &mut [u8]) -> usize;
}

/// VirtIO entropy device (the QEMU path; works under any hypervisor
/// that exposes a virtio-rng device).
pub struct VirtioRngSource;

impl EntropySource for VirtioRngSource {
    fn fill(&mut self, buf: &mut [u8]) -> usize {
        VirtioRng::read_into(buf)
    }
}

/// Zkr (CSR `seed`, address 0x015) — RISC-V K extension TRNG.
///
/// Reading `seed` returns a 32-bit value: bits 15..0 carry entropy,
/// bits 31..30 carry an `OPST` status (0=BIST, 1=WAIT, 2=ES16,
/// 3=DEAD). We accept only `OPST = ES16`, retry on WAIT, and bail on
/// DEAD or repeated WAIT.
///
/// Reading the CSR on a CPU without Zkr raises an illegal-instruction
/// exception, which the trap handler reports before halting, so this
/// source is gated behind the `zkr` Cargo feature for known-Zkr silicon.
#[cfg(feature = "zkr")]
pub struct ZkrSource;

#[cfg(feature = "zkr")]
impl EntropySource for ZkrSource {
    fn fill(&mut self, buf: &mut [u8]) -> usize {
        let mut written = 0;
        let mut wait_spins: u32 = 0;
        while written < buf.len() {
            let raw: usize;
            // SAFETY: the `zkr` feature asserts the hart implements the seed
            // CSR; reading it with x0 as the source has no other effect.
            unsafe { core::arch::asm!("csrrw {0}, 0x015, x0", out(reg) raw) };
            let opst = (raw >> 30) & 0b11;
            match opst {
                2 => {
                    // ES16 — low 16 bits are entropy.
                    wait_spins = 0;
                    let bytes = (raw as u16).to_le_bytes();
                    let n = (buf.len() - written).min(2);
                    buf[written..written + n].copy_from_slice(&bytes[..n]);
                    written += n;
                }
                3 => break, // DEAD — TRNG self-test failed; give up.
                _ => {
                    // BIST or WAIT — spin a bounded number of times so a
                    // permanently-stuck source can't hang the boot.
                    wait_spins = wait_spins.wrapping_add(1);
                    if wait_spins > 100_000 {
                        break;
                    }
                }
            }
        }
        written
    }
}

/// Degraded fallback: mcycle counter XOR-ed across the buffer with
/// the MAC. Roughly 10–13 bits of effective entropy — DO NOT rely on
/// it as the sole source. Used so even a no-RNG/no-Zkr boot diverges
/// across runs in QEMU testing rather than being byte-for-byte
/// identical, and to scramble the buffer if something else only
/// half-filled it.
pub struct McycleSource;

impl EntropySource for McycleSource {
    fn fill(&mut self, buf: &mut [u8]) -> usize {
        let mc = MCycle.now();
        for (i, b) in buf.iter_mut().enumerate() {
            *b = ((mc >> ((i % 8) * 8)) as u8) ^ MAC_ADDR[i % MAC_ADDR.len()];
        }
        buf.len()
    }
}

/// Records which sources contributed to a `gather` call. The kernel
/// logs this at boot so an operator deploying to bare hardware can see
/// whether they got real entropy or fell back to `mcycle`.
#[derive(Default, Debug)]
pub struct GatherReport {
    /// `true` if Zkr was compiled in, attempted, and produced any bytes.
    pub zkr: bool,
    /// `true` if a virtio-rng device was present and produced any bytes.
    pub virtio_rng: bool,
    /// Always `true` — mcycle is unconditionally mixed in last.
    pub mcycle: bool,
}

impl GatherReport {
    /// Returns `true` if at least one strong source contributed.
    pub const fn has_strong_source(&self) -> bool {
        self.zkr || self.virtio_rng
    }
}

/// XOR-mix every available source into `out`. Caller must zero `out`
/// before calling — XOR-into-place means a non-zero starting buffer
/// would silently bias the output.
///
/// `virtio_rng_present` is the result of [`VirtioRng::init`]; we don't
/// re-probe here because the probe already ran during driver bring-up
/// and writes side-effecting values to MMIO.
pub fn gather(out: &mut [u8], virtio_rng_present: bool) -> GatherReport {
    let mut report = GatherReport::default();
    let mut tmp = [0u8; 32];
    let want = out.len().min(tmp.len());

    #[cfg(feature = "zkr")]
    {
        let n = ZkrSource.fill(&mut tmp[..want]);
        if n > 0 {
            xor_into(&mut out[..n], &tmp[..n]);
            report.zkr = true;
        }
    }

    if virtio_rng_present {
        // Reset tmp so a partial fill from a previous source doesn't
        // leak into virtio's contribution.
        tmp.fill(0);
        let n = VirtioRngSource.fill(&mut tmp[..want]);
        if n > 0 {
            xor_into(&mut out[..n], &tmp[..n]);
            report.virtio_rng = true;
        }
    }

    tmp.fill(0);
    let _ = McycleSource.fill(&mut tmp[..want]);
    xor_into(&mut out[..want], &tmp[..want]);
    report.mcycle = true;

    report
}

fn xor_into(dst: &mut [u8], src: &[u8]) {
    for (d, s) in dst.iter_mut().zip(src.iter()) {
        *d ^= *s;
    }
}

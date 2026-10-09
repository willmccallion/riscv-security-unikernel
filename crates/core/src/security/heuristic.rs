//! Heuristic-based security analysis.
//!
//! Detects suspicious patterns that don't match known signatures but
//! indicate potential attacks based on protocol anomalies and payload
//! characteristics.

/// Heuristic analysis engine for anomaly detection.
///
/// Provides static methods for analyzing TCP flags and payload content
/// to detect suspicious patterns that may indicate attacks.
#[derive(Debug)]
pub struct HeuristicEngine;

impl HeuristicEngine {
    /// Analyzes TCP flags for suspicious patterns.
    ///
    /// Detects common port scanning techniques:
    /// - Xmas scan: FIN, URG, and PSH flags set together
    /// - Null scan: No flags set
    ///
    /// # Arguments
    ///
    /// * `flags` - TCP flags byte from the TCP header
    ///
    /// # Returns
    ///
    /// Some reason string if suspicious flags detected, None otherwise
    pub const fn check_tcp_flags(flags: u8) -> Option<&'static str> {
        use super::heuristic_constants::tcp_flags;
        if (flags & tcp_flags::XMAS_SCAN) == tcp_flags::XMAS_SCAN {
            return Some("Heuristic: Xmas Scan Detected");
        }

        if flags == tcp_flags::NULL_SCAN {
            return Some("Heuristic: Null Scan Detected");
        }

        None
    }

    /// Analyzes packet payload for suspicious patterns.
    ///
    /// Detects NOP sleds (sequences of 0x90 bytes) which are commonly
    /// used in buffer overflow attacks and shellcode injection.
    ///
    /// # Arguments
    ///
    /// * `payload` - Packet payload bytes to analyze
    ///
    /// # Returns
    ///
    /// Some reason string if suspicious pattern detected, None otherwise
    pub fn check_payload(payload: &[u8]) -> Option<&'static str> {
        use super::heuristic_constants::payload;
        // x86 0x90 NOP sled detection. The previous implementation
        // reset the counter on any non-NOP byte, so an attacker could
        // bypass with a single junk byte every few NOPs (e.g.
        // [0x00, 0x90, 0x90] repeated). Switch to a saturating-decay
        // counter: still triggers on 8 contiguous NOPs, but also on
        // payloads where NOPs strongly outnumber non-NOPs over a
        // short window.
        let mut nop_score: usize = 0;
        for &byte in payload {
            if byte == payload::NOP_OPCODE {
                nop_score += 1;
                if nop_score >= payload::MIN_NOP_SLED_LENGTH {
                    return Some("Heuristic: Shellcode (NOP Sled)");
                }
            } else {
                nop_score = nop_score.saturating_sub(1);
            }
        }

        // A RISC-V sled need not start aligned with the payload, so match at
        // any offset.
        if payload.len() >= payload::RISCV_NOP.len() * payload::MIN_RISCV_NOPS {
            let mut consec = 0usize;
            let mut i = 0usize;
            while i + payload::RISCV_NOP.len() <= payload.len() {
                if payload[i..i + payload::RISCV_NOP.len()] == payload::RISCV_NOP {
                    consec += 1;
                    if consec >= payload::MIN_RISCV_NOPS {
                        return Some("Heuristic: Shellcode (RISC-V NOP Sled)");
                    }
                    i += payload::RISCV_NOP.len();
                } else {
                    consec = 0;
                    i += 1;
                }
            }
        }

        None
    }
}

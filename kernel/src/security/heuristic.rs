//! Heuristic-based security analysis.
//!
//! Detects suspicious patterns that don't match known signatures but
//! indicate potential attacks based on protocol anomalies and payload
//! characteristics.

/// Heuristic analysis engine for anomaly detection.
///
/// Provides static methods for analyzing TCP flags and payload content
/// to detect suspicious patterns that may indicate attacks.
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
    pub fn check_tcp_flags(flags: u8) -> Option<&'static str> {
        use crate::security::heuristic_constants::tcp_flags;
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
        use crate::security::heuristic_constants::payload;
        let mut consecutive_nops = 0;
        for &byte in payload {
            if byte == payload::NOP_OPCODE {
                consecutive_nops += 1;
                if consecutive_nops >= payload::MIN_NOP_SLED_LENGTH {
                    return Some("Heuristic: Shellcode (NOP Sled)");
                }
            } else {
                consecutive_nops = 0;
            }
        }
        None
    }
}

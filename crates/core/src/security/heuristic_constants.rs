//! Heuristic detection constants.
//!
//! Defines constants used for heuristic-based anomaly detection
//! including TCP flag patterns and payload signatures.

/// TCP flag combinations for port scan detection.
pub mod tcp_flags {
    /// Xmas scan pattern: FIN, URG, and PSH flags set together.
    ///
    /// This combination is used to bypass simple firewalls and
    /// is a common port scanning technique.
    pub const XMAS_SCAN: u8 = 0x29;
    /// Null scan pattern: no flags set.
    ///
    /// Used for OS fingerprinting and stealth port scanning.
    pub const NULL_SCAN: u8 = 0x00;
}

/// Payload pattern detection constants.
pub mod payload {
    /// NOP instruction opcode (x86/x64).
    ///
    /// Sequences of this byte indicate NOP sleds commonly used
    /// in buffer overflow attacks and shellcode injection.
    pub const NOP_OPCODE: u8 = 0x90;
    /// Minimum consecutive NOP bytes to trigger detection.
    ///
    /// This threshold balances detection sensitivity with false
    /// positive rate. Shorter sequences may occur in legitimate
    /// binary data.
    pub const MIN_NOP_SLED_LENGTH: usize = 8;
    /// RISC-V `addi x0, x0, 0`, the canonical NOP, in little-endian bytes.
    pub const RISCV_NOP: [u8; 4] = [0x13, 0x00, 0x00, 0x00];
    /// Minimum consecutive RISC-V NOPs to trigger detection.
    pub const MIN_RISCV_NOPS: usize = 8;
}

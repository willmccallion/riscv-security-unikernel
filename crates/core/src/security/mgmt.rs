//! Management interface message types and constants.
//!
//! Defines the protocol for runtime configuration of the security kernel
//! via UDP management commands.
//!
//! Offsets in this module are relative to the **body** of an
//! authenticated mgmt packet — i.e. the bytes that
//! [`crate::security::mgmt_auth::MgmtAuth::verify`] returns after
//! stripping the 8-byte counter prefix and the 8-byte MAC suffix.
//! Callers (kernel, daemon, GUI) wrap and unwrap that envelope; the
//! code in here only describes the inner command layout.

/// Management message type identifiers.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManagementMessageType {
    /// Block a destination port (firewall rule).
    BlockPort = 0x01,
    /// Add a DPI signature pattern.
    AddDpiPattern = 0x02,
    /// Upload an eBPF program.
    UploadBpfProgram = 0x03,
    /// Manually ban an IP address.
    BanIp = 0x04,
    /// Remove a destination port from the firewall.
    UnblockPort = 0x05,
    /// Remove a runtime-added DPI pattern.
    RemoveDpiPattern = 0x06,
    /// Uninstall the BPF program, so every packet skips the filter.
    UnloadBpfProgram = 0x07,
    /// Lift a ban on an IP address.
    UnbanIp = 0x08,
}

impl ManagementMessageType {
    /// Converts a u8 message type to the enum variant.
    ///
    /// This method is used internally when parsing management commands
    /// from UDP payloads. Returns None if the type is not recognized.
    ///
    /// # Arguments
    ///
    /// * `value` - Raw u8 message type from packet payload
    ///
    /// # Returns
    ///
    /// Some ManagementMessageType variant if recognized, None otherwise
    pub const fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x01 => Some(Self::BlockPort),
            0x02 => Some(Self::AddDpiPattern),
            0x03 => Some(Self::UploadBpfProgram),
            0x04 => Some(Self::BanIp),
            0x05 => Some(Self::UnblockPort),
            0x06 => Some(Self::RemoveDpiPattern),
            0x07 => Some(Self::UnloadBpfProgram),
            0x08 => Some(Self::UnbanIp),
            _ => None,
        }
    }
}

/// What happened to an authenticated mgmt command, reported back to the
/// operator in an ack.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MgmtOutcome {
    /// The command took effect (including no-op duplicates).
    Applied = 0,
    /// The relevant table is full; nothing changed.
    TableFull = 1,
    /// The body was malformed or named an unknown command.
    Invalid = 2,
    /// Well-formed but refused, e.g. blocking the mgmt port itself.
    Refused = 3,
}

impl MgmtOutcome {
    /// Converts a raw outcome byte back to the enum variant.
    pub const fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Applied),
            1 => Some(Self::TableFull),
            2 => Some(Self::Invalid),
            3 => Some(Self::Refused),
            _ => None,
        }
    }
}

/// Layout of the ack the kernel sends for every authenticated command.
pub mod ack_packet {
    /// Message-type byte distinguishing acks from alerts.
    pub const ACK_MESSAGE_TYPE: u8 = 0x03;
    /// Offset of the acknowledged command's sequence (big-endian u32).
    pub const SEQ_OFFSET: usize = 1;
    /// Offset of the acknowledged command's type byte (0 if absent).
    pub const COMMAND_OFFSET: usize = 5;
    /// Offset of the [`super::MgmtOutcome`] byte.
    pub const OUTCOME_OFFSET: usize = 6;
    /// Total bytes of ack body on the wire.
    pub const ACK_BODY_LEN: usize = 7;
}

/// Management message format constants.
///
/// All offsets are body-relative — the caller has already validated
/// the auth envelope and stripped the counter + MAC.
pub mod mgmt_packet {
    /// Minimum body length: 1 byte for the message type.
    pub const MIN_PAYLOAD_LEN: usize = 1;
    /// Offset to message type field within the body.
    pub const MSG_TYPE_OFFSET: usize = 0;

    /// BlockPort and UnblockPort message format.
    pub mod block_port {
        /// Minimum body length: type byte + u16 port.
        pub const MIN_PAYLOAD_LEN: usize = 3;
        /// Offset to port number (bytes 1-2, big-endian).
        pub const PORT_OFFSET: usize = 1;
    }

    /// AddDpiPattern and RemoveDpiPattern message format.
    pub mod add_dpi {
        /// Minimum body length: type byte + length byte.
        pub const MIN_PAYLOAD_LEN: usize = 2;
        /// Offset to pattern length field.
        pub const LEN_OFFSET: usize = 1;
        /// Offset to pattern data.
        pub const PATTERN_OFFSET: usize = 2;
        /// Maximum pattern length in bytes.
        pub const MAX_PATTERN_LEN: usize = 32;
    }

    /// UploadBpfProgram message format.
    pub mod upload_bpf {
        /// Minimum body length for UploadBpfProgram: type byte + count byte.
        pub const MIN_PAYLOAD_LEN: usize = 2;
        /// Offset to instruction count field.
        pub const COUNT_OFFSET: usize = 1;
        /// Offset to instruction data.
        pub const INSTR_OFFSET: usize = 2;
        /// Size of each instruction in bytes.
        pub const INSTR_SIZE: usize = 7;
        /// Maximum number of instructions.
        pub const MAX_INSTR_COUNT: usize = 64;
    }

    /// BanIp and UnbanIp message format.
    pub mod ban_ip {
        /// Minimum body length: type byte + 4-byte IP.
        pub const MIN_PAYLOAD_LEN: usize = 5;
        /// Offset to IP address (bytes 1-4).
        pub const IP_OFFSET: usize = 1;
    }
}

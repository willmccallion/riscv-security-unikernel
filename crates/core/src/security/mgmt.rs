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
            _ => None,
        }
    }
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

    /// BlockPort message format.
    pub mod block_port {
        /// Minimum body length for BlockPort: type byte + u16 port.
        pub const MIN_PAYLOAD_LEN: usize = 3;
        /// Offset to port number (bytes 1-2, big-endian).
        pub const PORT_OFFSET: usize = 1;
    }

    /// AddDpiPattern message format.
    pub mod add_dpi {
        /// Minimum body length for AddDpiPattern: type byte + length byte.
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

    /// BanIp message format.
    pub mod ban_ip {
        /// Minimum body length for BanIp: type byte + 4-byte IP.
        pub const MIN_PAYLOAD_LEN: usize = 5;
        /// Offset to IP address (bytes 1-4).
        pub const IP_OFFSET: usize = 1;
    }
}

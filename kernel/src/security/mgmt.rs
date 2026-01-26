//! Management interface message types and constants.
//!
//! Defines the protocol for runtime configuration of the security kernel
//! via UDP management commands.

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
    pub fn from_u8(value: u8) -> Option<Self> {
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
pub mod mgmt_packet {
    /// Minimum payload length for any management message.
    pub const MIN_PAYLOAD_LEN: usize = 9;
    /// Offset to message type field.
    pub const MSG_TYPE_OFFSET: usize = 8;

    /// BlockPort message format.
    pub mod block_port {
        /// Minimum payload length for BlockPort message.
        pub const MIN_PAYLOAD_LEN: usize = 11;
        /// Offset to port number (bytes 9-10, big-endian).
        pub const PORT_OFFSET: usize = 9;
    }

    /// AddDpiPattern message format.
    pub mod add_dpi {
        /// Minimum payload length for AddDpiPattern message.
        pub const MIN_PAYLOAD_LEN: usize = 10;
        /// Offset to pattern length field.
        pub const LEN_OFFSET: usize = 9;
        /// Offset to pattern data.
        pub const PATTERN_OFFSET: usize = 10;
        /// Maximum pattern length in bytes.
        pub const MAX_PATTERN_LEN: usize = 32;
    }

    /// UploadBpfProgram message format.
    pub mod upload_bpf {
        /// Minimum payload length for UploadBpfProgram message.
        pub const MIN_PAYLOAD_LEN: usize = 10;
        /// Offset to instruction count field.
        pub const COUNT_OFFSET: usize = 9;
        /// Offset to instruction data.
        pub const INSTR_OFFSET: usize = 10;
        /// Size of each instruction in bytes.
        pub const INSTR_SIZE: usize = 7;
        /// Maximum number of instructions.
        pub const MAX_INSTR_COUNT: usize = 64;
    }

    /// BanIp message format.
    pub mod ban_ip {
        /// Minimum payload length for BanIp message.
        pub const MIN_PAYLOAD_LEN: usize = 13;
        /// Offset to IP address (bytes 9-12).
        pub const IP_OFFSET: usize = 9;
    }
}

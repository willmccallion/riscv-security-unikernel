//! Security alert reason codes and constants.
//!
//! Defines the alert reason codes used when security events are detected
//! and reported to the control plane.

/// Security alert reason codes.
///
/// Each code represents a different type of security event detected
/// by the kernel's security mechanisms.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlertReason {
    /// DDoS attack detected (high volume or heavy hitter).
    Ddos = 1,
    /// Firewall rule violation (blocked port access).
    Firewall = 2,
    /// Malware signature match detected.
    Malware = 3,
    /// eBPF filter dropped the packet.
    Ebpf = 4,
    /// Heuristic analysis detected anomaly.
    Heuristic = 5,
    /// New network flow created.
    Flow = 6,
}

impl AlertReason {
    /// Converts the enum variant to a u8 reason code.
    ///
    /// Used when constructing alert packets to encode the reason
    /// code in the packet payload. The resulting u8 value is written
    /// to the alert packet's reason field.
    ///
    /// # Returns
    ///
    /// The u8 value corresponding to this alert reason
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

/// Alert packet format constants.
pub mod alert_packet {
    /// Alert message type identifier in UDP payload.
    pub const ALERT_MESSAGE_TYPE: u8 = 0x02;
    /// Offset to reason code field in alert packet.
    pub const REASON_OFFSET: usize = 1;
    /// Offset to source IP address in alert packet.
    pub const SRC_IP_OFFSET: usize = 2;
    /// Size of source IP address field.
    pub const SRC_IP_SIZE: usize = 4;
    /// Offset to payload data in alert packet.
    pub const PAYLOAD_OFFSET: usize = 6;
    /// Maximum payload length in alert packets.
    pub const MAX_PAYLOAD_LEN: usize = 64;
}

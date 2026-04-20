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
    /// Packet passed all security checks.
    Pass = 7,
    /// Mgmt-plane packet failed authentication (bad MAC or replayed counter).
    MgmtAuthFail = 8,
    /// Authenticated mgmt packet uploaded a malformed BPF program (bad
    /// register index or out-of-range jump target). The program was not
    /// installed; the previous program (if any) remains active.
    BpfReject = 9,
    /// An authenticated mgmt command was well-formed but could not be
    /// applied because the relevant table was full (e.g. dynamic DPI
    /// rules, of which only 8 fit). Without this alert the operator
    /// would believe their pattern was loaded when it was silently
    /// discarded.
    MgmtRejected = 10,
    /// The installed BPF program burned its per-packet cycle budget
    /// without reaching a Ret instruction. The packet is dropped; the
    /// alert gives the operator a signal that the currently-loaded
    /// program is likely adversarial or buggy.
    BpfTimeout = 11,
    /// The installed BPF program executed a `Ret` whose immediate was
    /// neither 0 (drop) nor 1 (pass). The packet is dropped rather
    /// than silently passed, so future action-code extensions cannot
    /// be pre-poisoned by programs uploaded before the extension.
    BpfInvalidAction = 12,
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
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// Converts a raw u8 reason code back to the enum variant.
    ///
    /// Used by control-plane consumers (GUI, daemon) when parsing alert
    /// packets off the wire. Returns `None` for unrecognised codes.
    pub const fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Ddos),
            2 => Some(Self::Firewall),
            3 => Some(Self::Malware),
            4 => Some(Self::Ebpf),
            5 => Some(Self::Heuristic),
            6 => Some(Self::Flow),
            7 => Some(Self::Pass),
            8 => Some(Self::MgmtAuthFail),
            9 => Some(Self::BpfReject),
            10 => Some(Self::MgmtRejected),
            11 => Some(Self::BpfTimeout),
            12 => Some(Self::BpfInvalidAction),
            _ => None,
        }
    }
}

/// Whether a DDoS-drop counter value should fire a sampled alert.
///
/// Returns true on the very first drop and on every `sample_rate`-th
/// drop thereafter. Without the `count == 1` arm, operators see no
/// signal at all until `sample_rate` packets have already been
/// dropped — the attack is well underway by the time anything is
/// logged. A `sample_rate` of 0 falls back to "every drop fires".
#[must_use]
pub const fn should_emit_ddos_alert(count: u64, sample_rate: u64) -> bool {
    if sample_rate == 0 {
        return true;
    }
    count == 1 || count.is_multiple_of(sample_rate)
}

/// Alert packet format constants.
///
/// Alerts carry a fixed-size, attacker-payload-free metadata record.
/// Echoing inbound bytes onto the management broadcast domain would
/// hand attacker-controlled data to every log/parser tool listening
/// for alerts, so the wire format is metadata-only.
pub mod alert_packet {
    /// Alert message type identifier in UDP payload.
    pub const ALERT_MESSAGE_TYPE: u8 = 0x02;
    /// Offset to reason code field in alert packet.
    pub const REASON_OFFSET: usize = 1;
    /// Offset to source IP address in alert packet.
    pub const SRC_IP_OFFSET: usize = 2;
    /// Size of an IPv4 address field.
    pub const SRC_IP_SIZE: usize = 4;
    /// Offset to destination IP address in alert packet.
    pub const DST_IP_OFFSET: usize = 6;
    /// Offset to source port (big-endian u16).
    pub const SRC_PORT_OFFSET: usize = 10;
    /// Offset to destination port (big-endian u16).
    pub const DST_PORT_OFFSET: usize = 12;
    /// Offset to IP protocol number.
    pub const PROTOCOL_OFFSET: usize = 14;
    /// Offset to packet length (big-endian u16, saturated).
    pub const PACKET_LEN_OFFSET: usize = 15;
    /// Total bytes of alert body on the wire.
    pub const ALERT_BODY_LEN: usize = 17;
}

/// Fixed-size metadata included in every security alert.
///
/// Built by the kernel from already-parsed packet fields and shipped
/// across the management network in place of any attacker-controlled
/// payload bytes.
#[derive(Debug, Clone, Copy)]
pub struct AlertMeta {
    /// Source IPv4 address.
    pub src_ip: [u8; 4],
    /// Destination IPv4 address.
    pub dst_ip: [u8; 4],
    /// Source port (host byte order). Zero if unknown / non-TCP/UDP.
    pub src_port: u16,
    /// Destination port (host byte order). Zero if unknown / non-TCP/UDP.
    pub dst_port: u16,
    /// IP protocol number (6 = TCP, 17 = UDP, etc.).
    pub protocol: u8,
    /// Total packet length in bytes, saturated to `u16::MAX`.
    pub packet_len: u16,
}

impl AlertMeta {
    /// All-zero metadata, used when no per-packet context is available
    /// (e.g. an early-rejected mgmt envelope).
    pub const fn empty() -> Self {
        Self {
            src_ip: [0; 4],
            dst_ip: [0; 4],
            src_port: 0,
            dst_port: 0,
            protocol: 0,
            packet_len: 0,
        }
    }
}

//! Security alert reason codes and constants.
//!
//! Defines the alert reason codes used when security events are detected
//! and reported to the control plane.

use core::net::Ipv4Addr;

wire_enum! {
    /// Security alert reason codes.
    ///
    /// Each code represents a different type of security event detected
    /// by the kernel's security mechanisms.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum AlertReason {
        /// DDoS attack detected (high volume or heavy hitter).
        Ddos = 1,
        /// Firewall rule violation (blocked port access).
        Firewall = 2,
        /// Malware signature match detected.
        Malware = 3,
        /// BPF filter dropped the packet.
        Bpf = 4,
        /// Heuristic analysis detected anomaly.
        Heuristic = 5,
        /// New network flow created.
        Flow = 6,
        /// Packet passed all security checks.
        Pass = 7,
        /// Mgmt-plane packet failed authentication (bad MAC or replayed counter).
        MgmtAuthFail = 8,
        /// The installed BPF program burned its per-packet cycle budget
        /// without reaching a Ret instruction. The packet is dropped; the
        /// alert gives the operator a signal that the currently-loaded
        /// program is likely adversarial or buggy.
        BpfTimeout = 11,
        /// Far more distinct sources than usual arrived in one detection
        /// interval, typical of a flood from spoofed addresses. The value is
        /// the estimated number of sources; nothing is banned.
        SourceSurge = 13,
        /// A /24 or /16 sent more than its threshold, though no single host in
        /// it did; the subnet was banned. The alert's source is the network,
        /// with its prefix length, and the value its estimated packet rate.
        SubnetFlood = 14,
        /// A source opened connections to many distinct ports within one
        /// window and was banned. The value is the distinct ports counted.
        PortScan = 15,
        /// An IPv4 header whose version is not 4, whose length is under 20
        /// bytes, or whose total length is shorter than the header or longer
        /// than the frame; or a TCP, UDP or ICMP header that does not fit
        /// inside the datagram or whose own length is inconsistent. The
        /// packet is dropped unread.
        MalformedIp = 16,
        /// An IPv4 fragment. The kernel cannot reassemble, and inspecting the
        /// pieces alone would let a header or signature split across them slip
        /// past the firewall and DPI, so every fragment is dropped.
        IpFragment = 17,
    }
}

impl AlertReason {
    /// Converts the enum variant to a u8 reason code.
    ///
    /// Used when constructing alert packets to encode the reason
    /// code in the packet payload. The resulting u8 value is written
    /// to the alert packet's reason field.
    pub const fn as_u8(self) -> u8 {
        self as u8
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
    /// Offset to the prefix length of `SRC_IP`: 32 for a single address,
    /// shorter when the alert concerns a whole subnet.
    pub const PREFIX_LEN_OFFSET: usize = 17;
    /// Offset to a detector's measurement (big-endian u32), such as a
    /// subnet's packet rate or a source's distinct ports; 0 if none.
    pub const VALUE_OFFSET: usize = 18;
    /// Total bytes of alert body on the wire.
    pub const ALERT_BODY_LEN: usize = 22;
}

/// Fixed-size metadata included in every security alert.
///
/// Built by the kernel from already-parsed packet fields and shipped
/// across the management network in place of any attacker-controlled
/// payload bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AlertMeta {
    /// Source IPv4 address.
    pub src_ip: Ipv4Addr,
    /// Destination IPv4 address.
    pub dst_ip: Ipv4Addr,
    /// Source port (host byte order). Zero if unknown / non-TCP/UDP.
    pub src_port: u16,
    /// Destination port (host byte order). Zero if unknown / non-TCP/UDP.
    pub dst_port: u16,
    /// IP protocol number (6 = TCP, 17 = UDP, etc.).
    pub protocol: u8,
    /// Total packet length in bytes, saturated to `u16::MAX`.
    pub packet_len: u16,
    /// Prefix length of `src_ip`: 32 for a single address.
    pub prefix_len: u8,
    /// A detector's measurement backing the alert; 0 if none.
    pub value: u32,
}

impl AlertMeta {
    /// All-zero metadata, used when no per-packet context is available
    /// (e.g. an early-rejected mgmt envelope).
    pub const fn empty() -> Self {
        Self {
            src_ip: Ipv4Addr::UNSPECIFIED,
            dst_ip: Ipv4Addr::UNSPECIFIED,
            src_port: 0,
            dst_port: 0,
            protocol: 0,
            packet_len: 0,
            prefix_len: 32,
            value: 0,
        }
    }
}

/// A security alert as its report carries it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Alert {
    /// What raised it.
    pub reason: AlertReason,
    /// The packet or detector fields behind it.
    pub meta: AlertMeta,
}

impl Alert {
    /// The alert's report body.
    pub fn encode(&self) -> [u8; alert_packet::ALERT_BODY_LEN] {
        use alert_packet::{
            ALERT_BODY_LEN, ALERT_MESSAGE_TYPE, DST_IP_OFFSET, DST_PORT_OFFSET, PACKET_LEN_OFFSET,
            PREFIX_LEN_OFFSET, PROTOCOL_OFFSET, REASON_OFFSET, SRC_IP_OFFSET, SRC_PORT_OFFSET,
            VALUE_OFFSET,
        };
        let meta = &self.meta;
        let mut body = [0u8; ALERT_BODY_LEN];
        body[0] = ALERT_MESSAGE_TYPE;
        body[REASON_OFFSET] = self.reason.as_u8();
        body[SRC_IP_OFFSET..][..4].copy_from_slice(&meta.src_ip.octets());
        body[DST_IP_OFFSET..][..4].copy_from_slice(&meta.dst_ip.octets());
        body[SRC_PORT_OFFSET..][..2].copy_from_slice(&meta.src_port.to_be_bytes());
        body[DST_PORT_OFFSET..][..2].copy_from_slice(&meta.dst_port.to_be_bytes());
        body[PROTOCOL_OFFSET] = meta.protocol;
        body[PACKET_LEN_OFFSET..][..2].copy_from_slice(&meta.packet_len.to_be_bytes());
        body[PREFIX_LEN_OFFSET] = meta.prefix_len;
        body[VALUE_OFFSET..][..4].copy_from_slice(&meta.value.to_be_bytes());
        body
    }

    /// The alert in a report body, if it is a whole alert with a known
    /// reason.
    pub fn decode(body: &[u8]) -> Option<Self> {
        use alert_packet::{
            ALERT_BODY_LEN, ALERT_MESSAGE_TYPE, DST_IP_OFFSET, DST_PORT_OFFSET, PACKET_LEN_OFFSET,
            PREFIX_LEN_OFFSET, PROTOCOL_OFFSET, REASON_OFFSET, SRC_IP_OFFSET, SRC_PORT_OFFSET,
            VALUE_OFFSET,
        };
        let body = body.first_chunk::<ALERT_BODY_LEN>()?;
        if body[0] != ALERT_MESSAGE_TYPE {
            return None;
        }
        let u16_at = |at: usize| u16::from_be_bytes([body[at], body[at + 1]]);
        let quad_at = |at: usize| [body[at], body[at + 1], body[at + 2], body[at + 3]];
        Some(Self {
            reason: AlertReason::from_u8(body[REASON_OFFSET])?,
            meta: AlertMeta {
                src_ip: Ipv4Addr::from(quad_at(SRC_IP_OFFSET)),
                dst_ip: Ipv4Addr::from(quad_at(DST_IP_OFFSET)),
                src_port: u16_at(SRC_PORT_OFFSET),
                dst_port: u16_at(DST_PORT_OFFSET),
                protocol: body[PROTOCOL_OFFSET],
                packet_len: u16_at(PACKET_LEN_OFFSET),
                prefix_len: body[PREFIX_LEN_OFFSET],
                value: u32::from_be_bytes(quad_at(VALUE_OFFSET)),
            },
        })
    }
}

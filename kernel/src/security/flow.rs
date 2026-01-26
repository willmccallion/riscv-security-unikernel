//! Network flow tracking.
//!
//! Maintains a table of active network flows (connections) with statistics
//! including packet counts, byte counts, and timing information. Used for
//! connection tracking and flow-based security analysis.

/// Maximum number of flows that can be tracked simultaneously.
const MAX_FLOWS: usize = 74;

/// Entry in the flow table representing a single network flow.
///
/// A flow is identified by the 5-tuple: source IP, destination IP,
/// source port, destination port, and protocol. The entry tracks
/// statistics and timing for the flow.
#[derive(Copy, Clone)]
#[repr(align(8))]
pub struct FlowEntry {
    /// Total number of packets in this flow.
    pub packet_count: u64,
    /// Total number of bytes in this flow.
    pub byte_count: u64,
    /// Last time this flow was seen (cycle count).
    pub last_seen: usize,

    /// Source IP address in network byte order.
    pub src_ip: u32,
    /// Destination IP address in network byte order.
    pub dst_ip: u32,

    /// Source port in host byte order.
    pub src_port: u16,
    /// Destination port in host byte order.
    pub dst_port: u16,

    /// IP protocol number (6=TCP, 17=UDP, etc.).
    pub protocol: u8,
    /// Whether this entry is currently active.
    pub is_active: bool,
}

impl FlowEntry {
    /// Creates an empty flow entry with all fields zeroed.
    pub const fn empty() -> Self {
        Self {
            packet_count: 0,
            byte_count: 0,
            last_seen: 0,
            src_ip: 0,
            dst_ip: 0,
            src_port: 0,
            dst_port: 0,
            protocol: 0,
            is_active: false,
        }
    }
}

/// Flow table for tracking active network connections.
///
/// Maintains a fixed-size array of flow entries. When the table is full,
/// the oldest flow is evicted to make room for new flows.
pub struct FlowTable {
    /// Array of flow entries.
    entries: [FlowEntry; MAX_FLOWS],
    /// Number of currently active flows.
    pub active_count: usize,
}

impl FlowTable {
    /// Creates a new empty flow table.
    pub const fn new() -> Self {
        Self {
            entries: [FlowEntry::empty(); MAX_FLOWS],
            active_count: 0,
        }
    }

    /// Updates the flow table with a new packet.
    ///
    /// If a matching flow exists, updates its statistics. Otherwise,
    /// creates a new flow entry or reuses an expired/old entry.
    ///
    /// # Arguments
    ///
    /// * `src_ip` - Source IP address as 4 bytes
    /// * `dst_ip` - Destination IP address as 4 bytes
    /// * `src_port` - Source port number
    /// * `dst_port` - Destination port number
    /// * `proto` - IP protocol number
    /// * `len` - Packet length in bytes
    /// * `now` - Current cycle count
    ///
    /// # Returns
    ///
    /// True if a new flow was created, false if an existing flow was updated
    pub fn update(
        &mut self,
        src_ip: &[u8],
        dst_ip: &[u8],
        src_port: u16,
        dst_port: u16,
        proto: u8,
        len: usize,
        now: usize,
    ) -> bool {
        let s_ip = u32::from_be_bytes([src_ip[0], src_ip[1], src_ip[2], src_ip[3]]);
        let d_ip = u32::from_be_bytes([dst_ip[0], dst_ip[1], dst_ip[2], dst_ip[3]]);

        let mut found_idx = None;
        let mut empty_idx = None;
        let mut oldest_idx = 0;
        let mut oldest_time = usize::MAX;

        for i in 0..MAX_FLOWS {
            let e = &self.entries[i];
            if e.is_active {
                if e.src_ip == s_ip
                    && e.dst_ip == d_ip
                    && e.src_port == src_port
                    && e.dst_port == dst_port
                    && e.protocol == proto
                {
                    found_idx = Some(i);
                    break;
                }
                if e.last_seen < oldest_time {
                    oldest_time = e.last_seen;
                    oldest_idx = i;
                }
            } else if empty_idx.is_none() {
                empty_idx = Some(i);
            }
        }

        if let Some(idx) = found_idx {
            self.entries[idx].packet_count += 1;
            self.entries[idx].byte_count += len as u64;
            self.entries[idx].last_seen = now;
            false
        } else {
            let idx = if let Some(e_idx) = empty_idx {
                self.active_count += 1;
                e_idx
            } else {
                oldest_idx
            };

            self.entries[idx] = FlowEntry {
                packet_count: 1,
                byte_count: len as u64,
                last_seen: now,
                src_ip: s_ip,
                dst_ip: d_ip,
                src_port,
                dst_port,
                protocol: proto,
                is_active: true,
            };
            true
        }
    }

    /// Removes expired flows from the table.
    ///
    /// Marks flows as inactive if they haven't been seen within the
    /// specified timeout period. Updates the active count accordingly.
    ///
    /// # Arguments
    ///
    /// * `now` - Current cycle count
    /// * `timeout` - Timeout in cycles (flows older than this are pruned)
    pub fn prune(&mut self, now: usize, timeout: usize) {
        let mut removed = 0;
        for i in 0..MAX_FLOWS {
            if self.entries[i].is_active && (now.wrapping_sub(self.entries[i].last_seen) > timeout)
            {
                self.entries[i].is_active = false;
                removed += 1;
            }
        }
        self.active_count -= removed;
    }
}

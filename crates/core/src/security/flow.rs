//! Network flow tracking.
//!
//! Maintains a table of active network flows (connections) with statistics
//! including packet counts, byte counts, and timing information. Used for
//! connection tracking and flow-based security analysis.

/// Maximum number of flows that can be tracked simultaneously.
const MAX_FLOWS: usize = 74;

/// Minimum age (in time-source units) an active flow must reach before
/// it becomes eligible for eviction by a new 5-tuple. Without this, an
/// attacker who floods unique 5-tuples evicts long-lived legitimate
/// flows just by being newer; with it, the table refuses to evict any
/// flow that has been touched in the last `MIN_EVICTION_AGE` ticks and
/// instead drops the new flow on the floor. Tuned well below
/// `FLOW_TIMEOUT_CYCLES` so genuinely stale entries are still recyclable.
const MIN_EVICTION_AGE: u64 = 1_000_000;

/// The 5-tuple identifying a flow. Addresses are in network byte order,
/// ports in host byte order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlowKey {
    /// Source IPv4 address.
    pub src_ip: [u8; 4],
    /// Destination IPv4 address.
    pub dst_ip: [u8; 4],
    /// Source port, or 0 for protocols without ports.
    pub src_port: u16,
    /// Destination port, or 0 for protocols without ports.
    pub dst_port: u16,
    /// IP protocol number.
    pub protocol: u8,
}

/// Entry in the flow table representing a single network flow.
///
/// A flow is identified by the 5-tuple: source IP, destination IP,
/// source port, destination port, and protocol. The entry tracks
/// statistics and timing for the flow.
#[derive(Copy, Clone, Debug)]
#[repr(align(8))]
pub struct FlowEntry {
    /// Total number of packets in this flow.
    pub packet_count: u64,
    /// Total number of bytes in this flow.
    pub byte_count: u64,
    /// Last time this flow was seen (time-source units).
    pub last_seen: u64,

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
#[derive(Debug)]
pub struct FlowTable {
    /// Array of flow entries.
    entries: [FlowEntry; MAX_FLOWS],
    /// Number of currently active flows.
    pub active_count: usize,
}

impl Default for FlowTable {
    fn default() -> Self {
        Self::new()
    }
}

impl FlowTable {
    /// Creates a new empty flow table.
    pub const fn new() -> Self {
        Self {
            entries: [FlowEntry::empty(); MAX_FLOWS],
            active_count: 0,
        }
    }

    /// Records a packet of `len` bytes against the flow `key`.
    ///
    /// Returns `true` if a new flow was created, `false` if an existing
    /// one was updated or the table refused to evict a recent flow.
    pub fn update(&mut self, key: &FlowKey, len: usize, now: u64) -> bool {
        let s_ip = u32::from_be_bytes(key.src_ip);
        let d_ip = u32::from_be_bytes(key.dst_ip);

        let mut found_idx = None;
        let mut empty_idx = None;
        let mut oldest_idx = 0;
        let mut oldest_time = u64::MAX;

        for (i, e) in self.entries.iter().enumerate() {
            if e.is_active {
                if e.src_ip == s_ip
                    && e.dst_ip == d_ip
                    && e.src_port == key.src_port
                    && e.dst_port == key.dst_port
                    && e.protocol == key.protocol
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
            let entry = &mut self.entries[idx];
            entry.packet_count += 1;
            entry.byte_count += len as u64;
            entry.last_seen = now;
            return false;
        }

        let idx = if let Some(e_idx) = empty_idx {
            self.active_count += 1;
            e_idx
        } else {
            // Table is full and every entry is active. Refuse to evict a
            // recent flow, or a unique-5-tuple flood could churn out
            // long-lived legitimate flows simply by being newer.
            if now.wrapping_sub(oldest_time) < MIN_EVICTION_AGE {
                return false;
            }
            oldest_idx
        };

        self.entries[idx] = FlowEntry {
            packet_count: 1,
            byte_count: len as u64,
            last_seen: now,
            src_ip: s_ip,
            dst_ip: d_ip,
            src_port: key.src_port,
            dst_port: key.dst_port,
            protocol: key.protocol,
            is_active: true,
        };
        true
    }

    /// Removes expired flows from the table.
    ///
    /// Marks flows as inactive if they haven't been seen within the
    /// specified timeout period. Updates the active count accordingly.
    ///
    /// # Arguments
    ///
    /// * `now` - Current time-source value
    /// * `timeout` - Timeout in time-source units (flows older than this are pruned)
    pub fn prune(&mut self, now: u64, timeout: u64) {
        let mut removed = 0;
        for i in 0..MAX_FLOWS {
            if self.entries[i].is_active && (now.wrapping_sub(self.entries[i].last_seen) > timeout)
            {
                self.entries[i].is_active = false;
                removed += 1;
            }
        }
        // Defensive: today every `is_active = true` corresponds to an
        // `active_count += 1` so the invariant holds, but this counter
        // has no other validation and a future refactor that miscounts
        // would underflow silently. Cheap to harden.
        self.active_count = self.active_count.saturating_sub(removed);
    }
}

//! Network flow tracking.
//!
//! Maintains a table of active network flows (connections) with statistics
//! including packet counts, byte counts, and timing information. Used for
//! connection tracking and flow-based security analysis.

use core::num::NonZeroU64;

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

/// A tracked flow: its key and what it has carried.
#[derive(Copy, Clone, Debug)]
#[repr(align(8))]
struct Flow {
    key: FlowKey,
    /// Never zero: a flow is tracked from its first packet.
    packets: NonZeroU64,
    bytes: u64,
    /// Last time this flow was seen (time-source units).
    last_seen: u64,
}

impl Flow {
    const fn first(key: FlowKey, len: usize, now: u64) -> Self {
        Self {
            key,
            packets: NonZeroU64::MIN,
            bytes: len as u64,
            last_seen: now,
        }
    }

    const fn record(&mut self, len: usize, now: u64) {
        self.packets = self.packets.saturating_add(1);
        self.bytes += len as u64;
        self.last_seen = now;
    }
}

/// Where a packet's flow goes in the table.
enum Lookup {
    /// Already tracked in this slot.
    Tracked(usize),
    /// Untracked; this slot is free.
    Free(usize),
    /// Untracked and the table is full; this slot holds the flow seen
    /// least recently, at `last_seen`.
    Oldest { index: usize, last_seen: u64 },
}

/// Flow table for tracking active network connections.
///
/// A fixed-size table; when it is full, the flow seen least recently gives
/// up its slot, but only once it has been idle for a minimum age.
#[derive(Debug)]
pub struct FlowTable {
    slots: [Option<Flow>; MAX_FLOWS],
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
            slots: [None; MAX_FLOWS],
        }
    }

    /// How many flows the table tracks.
    pub fn active_count(&self) -> usize {
        self.slots.iter().flatten().count()
    }

    /// Records a packet of `len` bytes against the flow `key`.
    ///
    /// Returns `true` if a new flow was created, `false` if an existing
    /// one was updated or the table refused to evict a recent flow.
    pub fn update(&mut self, key: &FlowKey, len: usize, now: u64) -> bool {
        let index = match self.lookup(key) {
            Lookup::Tracked(index) => {
                if let Some(flow) = &mut self.slots[index] {
                    flow.record(len, now);
                }
                return false;
            }
            Lookup::Free(index) => index,
            // Refuse to evict a recent flow, or a unique-5-tuple flood could
            // churn out long-lived legitimate flows simply by being newer.
            Lookup::Oldest { last_seen, .. } if now.wrapping_sub(last_seen) < MIN_EVICTION_AGE => {
                return false;
            }
            Lookup::Oldest { index, .. } => index,
        };
        self.slots[index] = Some(Flow::first(*key, len, now));
        true
    }

    /// One pass over the table: the slot tracking `key`, else the first
    /// free slot, else the least recently seen flow's.
    fn lookup(&self, key: &FlowKey) -> Lookup {
        let mut free = None;
        let (mut oldest, mut oldest_seen) = (0, u64::MAX);
        for (index, slot) in self.slots.iter().enumerate() {
            match slot {
                Some(flow) if flow.key == *key => return Lookup::Tracked(index),
                Some(flow) if flow.last_seen < oldest_seen => {
                    (oldest, oldest_seen) = (index, flow.last_seen);
                }
                Some(_) => {}
                None if free.is_none() => free = Some(index),
                None => {}
            }
        }
        free.map_or(
            Lookup::Oldest {
                index: oldest,
                last_seen: oldest_seen,
            },
            Lookup::Free,
        )
    }

    /// Forgets the flows not seen for longer than `timeout`.
    pub fn prune(&mut self, now: u64, timeout: u64) {
        for slot in &mut self.slots {
            if slot.is_some_and(|flow| now.wrapping_sub(flow.last_seen) > timeout) {
                *slot = None;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(src_port: u16) -> FlowKey {
        FlowKey {
            src_ip: [10, 0, 0, 1],
            dst_ip: [10, 0, 0, 2],
            src_port,
            dst_port: 80,
            protocol: 6,
        }
    }

    #[test]
    fn pruning_forgets_flows_idle_past_the_timeout() {
        let mut table = FlowTable::new();
        let _ = table.update(&key(1), 60, 0);
        let _ = table.update(&key(2), 60, 900);

        table.prune(1_000, 500);

        assert_eq!(table.active_count(), 1);
        assert!(
            !table.update(&key(2), 60, 1_001),
            "the recent flow is still tracked"
        );
    }

    #[test]
    fn a_full_table_evicts_its_least_recently_seen_flow_once_old_enough() {
        let mut table = FlowTable::new();
        for port in 0..MAX_FLOWS as u16 {
            let _ = table.update(&key(port), 60, u64::from(port) + 1);
        }
        let later = MIN_EVICTION_AGE + 1;

        let created = table.update(&key(9_999), 60, later);

        assert!(created);
        assert_eq!(table.active_count(), MAX_FLOWS);
        let much_later = later + MIN_EVICTION_AGE;
        assert!(
            table.update(&key(0), 60, much_later),
            "the oldest flow was the one evicted, so it reads as new"
        );
    }
}

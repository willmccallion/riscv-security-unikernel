//! DDoS (Distributed Denial of Service) mitigation mechanisms.
//!
//! Implements the ban list and rate limiting used against DDoS attacks:
//! - Penalty box for IP address banning
//! - Token bucket rate limiting
//!
//! Heavy-hitter detection lives in [`crate::security::sketch`].
//!
//! [`PenaltyBox`](crate::security::dos::PenaltyBox) and
//! [`TokenBucket`](crate::security::dos::TokenBucket) are time-source
//! agnostic: callers pass a `now` value (cycles on the RISC-V unikernel,
//! nanoseconds on the Linux daemon) alongside the duration/cost constants,
//! which must share the same unit.

/// An IPv4 network: an address with only its first `len` bits kept.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Ipv4Prefix {
    network: u32,
    len: u8,
}

impl Ipv4Prefix {
    /// The `len`-bit prefix containing `addr`, or `None` if `len > 32`.
    pub const fn new(addr: [u8; 4], len: u8) -> Option<Self> {
        if len > 32 {
            return None;
        }
        Some(Self {
            network: u32::from_be_bytes(addr) & mask(len),
            len,
        })
    }

    /// The single-address prefix for `addr`.
    pub const fn host(addr: [u8; 4]) -> Self {
        Self {
            network: u32::from_be_bytes(addr),
            len: 32,
        }
    }

    /// The network address, with the bits past the prefix cleared.
    pub const fn network(&self) -> [u8; 4] {
        self.network.to_be_bytes()
    }

    /// The prefix length in bits.
    pub const fn prefix_len(&self) -> u8 {
        self.len
    }

    /// Whether `addr` lies inside this prefix.
    pub const fn contains(&self, addr: [u8; 4]) -> bool {
        u32::from_be_bytes(addr) & mask(self.len) == self.network
    }
}

/// The netmask with the top `len` bits set.
const fn mask(len: u8) -> u32 {
    match u32::MAX.checked_shl(32 - len as u32) {
        Some(m) => m,
        None => 0,
    }
}

/// Who imposed a ban.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum BanSource {
    /// A flood or scan detector; may be evicted when the table is full.
    Detector,
    /// An authenticated operator command; never evicted by a detector ban.
    Operator,
}

/// Entry in the penalty box tracking a banned network.
#[derive(Copy, Clone, Debug)]
struct BanEntry {
    /// Banned network; a single address is a /32.
    prefix: Ipv4Prefix,
    /// Time-source value at which the ban expires.
    expiry: u64,
    source: BanSource,
}

impl BanEntry {
    /// A ban is active until, but not including, its expiry time.
    const fn is_active(&self, now: u64) -> bool {
        self.expiry > now
    }
}

/// The penalty box refused an operator ban because every slot already holds
/// an active operator ban.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PenaltyBoxFull;

/// Penalty box for tracking banned addresses and subnets.
///
/// Maintains a fixed-size table of banned prefixes with expiration times.
/// When the table is full, a new ban evicts a detector ban in round-robin
/// order; operator bans are only lifted by the operator or by expiring.
#[derive(Debug)]
pub struct PenaltyBox {
    /// Array of ban entries, limited to [`Self::SLOTS`] for memory efficiency.
    entries: [BanEntry; Self::SLOTS],
    /// Round-robin pointer for eviction when every slot is still active.
    /// Without this, every overflow ban lands in slot 0, so an attacker
    /// who learns the table is full can pin one IP and watch every
    /// subsequent ban evict it.
    next_evict: usize,
}

impl Default for PenaltyBox {
    fn default() -> Self {
        Self::new()
    }
}

impl PenaltyBox {
    /// Number of bans the table holds at once.
    const SLOTS: usize = 16;

    /// Creates a new empty penalty box.
    pub const fn new() -> Self {
        Self {
            entries: [BanEntry {
                prefix: Ipv4Prefix::host([0; 4]),
                expiry: 0,
                source: BanSource::Detector,
            }; Self::SLOTS],
            next_evict: 0,
        }
    }

    /// Bans a single address until `now + duration` on a detector's behalf.
    pub fn ban(&mut self, ip_bytes: &[u8; 4], duration: u64, now: u64) {
        self.ban_prefix(Ipv4Prefix::host(*ip_bytes), duration, now);
    }

    /// Bans every address in `prefix` until `now + duration` on a
    /// detector's behalf. If every slot holds an operator ban, the ban is
    /// not recorded.
    pub fn ban_prefix(&mut self, prefix: Ipv4Prefix, duration: u64, now: u64) {
        let _ = self.store(prefix, BanSource::Detector, duration, now);
    }

    /// Bans a single address until `now + duration` for the operator.
    ///
    /// # Errors
    ///
    /// [`PenaltyBoxFull`] if every slot already holds an active operator ban.
    pub fn ban_by_operator(
        &mut self,
        ip_bytes: &[u8; 4],
        duration: u64,
        now: u64,
    ) -> Result<(), PenaltyBoxFull> {
        let prefix = Ipv4Prefix::host(*ip_bytes);
        self.store(prefix, BanSource::Operator, duration, now)
            .then_some(())
            .ok_or(PenaltyBoxFull)
    }

    /// Records a ban, returning whether it found a slot.
    ///
    /// Refreshes the prefix's existing ban, keeping the later expiry and the
    /// operator's claim; otherwise takes a slot whose ban has ended, and only
    /// when every slot is active evicts a detector ban in round-robin order.
    fn store(&mut self, prefix: Ipv4Prefix, source: BanSource, duration: u64, now: u64) -> bool {
        let expiry = now.saturating_add(duration);
        if let Some(entry) = self
            .entries
            .iter_mut()
            .find(|e| e.prefix == prefix && e.is_active(now))
        {
            entry.expiry = entry.expiry.max(expiry);
            if source == BanSource::Operator {
                entry.source = BanSource::Operator;
            }
            return true;
        }
        let free = self.entries.iter().position(|e| !e.is_active(now));
        let Some(idx) = free.or_else(|| self.next_evictable_detector_ban()) else {
            return false;
        };
        self.entries[idx] = BanEntry {
            prefix,
            expiry,
            source,
        };
        true
    }

    /// The next detector ban in round-robin order, advancing the pointer.
    fn next_evictable_detector_ban(&mut self) -> Option<usize> {
        let idx = (0..Self::SLOTS)
            .map(|step| (self.next_evict + step) % Self::SLOTS)
            .find(|&i| self.entries[i].source == BanSource::Detector)?;
        self.next_evict = (idx + 1) % Self::SLOTS;
        Some(idx)
    }

    /// Lifts every ban covering `ip_bytes`, whether on the address itself
    /// or on a subnet containing it.
    pub fn unban(&mut self, ip_bytes: &[u8; 4]) {
        for entry in &mut self.entries {
            if entry.prefix.contains(*ip_bytes) {
                entry.expiry = 0;
            }
        }
    }

    /// Whether an active ban covers `ip_bytes`.
    ///
    /// # Arguments
    ///
    /// * `ip_bytes` - IP address as 4 bytes in network byte order.
    /// * `now` - Current time-source value; bans with `expiry > now` are
    ///   considered active.
    pub fn is_banned(&self, ip_bytes: &[u8; 4], now: u64) -> bool {
        self.entries
            .iter()
            .any(|e| e.is_active(now) && e.prefix.contains(*ip_bytes))
    }
}

/// Token bucket rate limiter.
///
/// Implements a token bucket algorithm to limit the rate of packet
/// processing. Tokens are refilled at a fixed rate based on elapsed
/// time-source ticks; each packet consumes one token.
#[derive(Debug)]
pub struct TokenBucket {
    /// Current number of available tokens.
    tokens: u64,
    /// Maximum number of tokens (bucket capacity).
    capacity: u64,
    /// Time-source value at the last refill.
    last_time: u64,
    /// Cost (in time-source units) per token refilled.
    cost: u64,
}

impl TokenBucket {
    /// Creates a new token bucket with the specified capacity and refill cost.
    ///
    /// # Arguments
    ///
    /// * `capacity` - Maximum number of tokens.
    /// * `cost`     - Time-source units per token (higher = slower refill).
    pub const fn new(capacity: u64, cost: u64) -> Self {
        Self {
            tokens: capacity,
            capacity,
            last_time: 0,
            cost,
        }
    }

    /// Checks if a packet is allowed and consumes a token if available.
    ///
    /// Refills tokens based on time-source units elapsed since the last
    /// call, then consumes one token if available.
    ///
    /// # Arguments
    ///
    /// * `now` - Current time-source value.
    ///
    /// # Returns
    ///
    /// `true` if a token was available and consumed, `false` otherwise.
    pub fn allow(&mut self, now: u64) -> bool {
        let delta = now.wrapping_sub(self.last_time);
        if self.cost > 0 && delta >= self.cost {
            let refill = delta / self.cost;
            self.tokens = self.tokens.saturating_add(refill).min(self.capacity);
            // Carry the time already spent toward the next token, unless the
            // bucket is full and that progress would be discarded anyway.
            self.last_time = if self.tokens == self.capacity {
                now
            } else {
                self.last_time.wrapping_add(refill * self.cost)
            };
        }
        if self.tokens > 0 {
            self.tokens -= 1;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod prefix_tests {
    use super::{Ipv4Prefix, PenaltyBox};

    #[test]
    fn prefix_keeps_only_the_network_bits() {
        let prefix = Ipv4Prefix::new([10, 1, 2, 99], 24).unwrap();

        assert_eq!(prefix.network(), [10, 1, 2, 0]);
        assert!(prefix.contains([10, 1, 2, 200]));
        assert!(!prefix.contains([10, 1, 3, 1]));
    }

    #[test]
    fn zero_length_prefix_covers_everything_and_long_ones_are_rejected() {
        assert!(
            Ipv4Prefix::new([1, 2, 3, 4], 0)
                .unwrap()
                .contains([200, 0, 0, 1])
        );
        assert_eq!(Ipv4Prefix::new([1, 2, 3, 4], 33), None);
    }

    #[test]
    fn a_subnet_ban_covers_its_hosts_only() {
        let mut pbox = PenaltyBox::new();

        pbox.ban_prefix(Ipv4Prefix::new([10, 1, 2, 0], 24).unwrap(), 1_000, 0);

        assert!(pbox.is_banned(&[10, 1, 2, 77], 1));
        assert!(!pbox.is_banned(&[10, 1, 3, 77], 1));
    }

    #[test]
    fn unbanning_a_host_lifts_the_subnet_ban_covering_it() {
        let mut pbox = PenaltyBox::new();
        pbox.ban_prefix(Ipv4Prefix::new([10, 1, 0, 0], 16).unwrap(), 1_000, 0);

        pbox.unban(&[10, 1, 200, 3]);

        assert!(!pbox.is_banned(&[10, 1, 9, 9], 1));
    }
}

#[cfg(test)]
mod token_bucket_tests {
    use super::TokenBucket;

    #[test]
    fn starts_full() {
        let mut b = TokenBucket::new(5, 10);
        for _ in 0..5 {
            assert!(b.allow(0));
        }
        assert!(!b.allow(0), "6th packet at same tick must be denied");
    }

    #[test]
    fn refills_over_time() {
        let mut b = TokenBucket::new(5, 10);
        for _ in 0..5 {
            assert!(b.allow(0));
        }
        // 30 ticks elapsed → delta 30, cost 10 → 3 new tokens.
        assert!(b.allow(30));
        assert!(b.allow(30));
        assert!(b.allow(30));
        assert!(!b.allow(30));
    }

    #[test]
    fn refill_saturates_at_capacity() {
        let mut b = TokenBucket::new(5, 10);
        for _ in 0..5 {
            assert!(b.allow(0));
        }
        // Huge elapsed time — refill would be billions, must clamp to capacity.
        assert!(b.allow(u64::MAX / 2));
        for _ in 0..4 {
            assert!(b.allow(u64::MAX / 2));
        }
        assert!(!b.allow(u64::MAX / 2));
    }

    #[test]
    fn cost_zero_never_refills() {
        // Guard against division by zero. The bucket is usable up to
        // its starting capacity and then permanently empty.
        let mut b = TokenBucket::new(3, 0);
        assert!(b.allow(0));
        assert!(b.allow(100));
        assert!(b.allow(u64::MAX));
        assert!(!b.allow(u64::MAX));
    }

    #[test]
    fn wraparound_elapsed_is_handled() {
        // `now.wrapping_sub(last_time)` must tolerate the clock source
        // rolling. Seed last_time near u64::MAX, then call with a small
        // `now` — delta wraps to a positive refill amount, not to zero.
        let mut b = TokenBucket::new(1, 10);
        assert!(b.allow(u64::MAX - 5));
        assert!(!b.allow(u64::MAX - 5));
        // 10 ticks after u64::MAX - 5 = wraps to 4.
        assert!(b.allow(4));
    }

    #[test]
    fn refill_keeps_progress_toward_the_next_token() {
        // Polled every 15 ticks at cost 10, the bucket earns 1.5 tokens
        // per poll; over 3000 ticks that is 300 tokens plus capacity.
        let mut b = TokenBucket::new(10, 10);
        let mut allowed = 0;
        for poll in 0..200u64 {
            for _ in 0..3 {
                if b.allow(poll * 15) {
                    allowed += 1;
                }
            }
        }
        assert!(
            allowed >= 300,
            "only {allowed} tokens in 3000 ticks at cost 10"
        );
    }

    #[test]
    fn denies_when_drained_without_elapsed_time() {
        let mut b = TokenBucket::new(2, 100);
        assert!(b.allow(50));
        assert!(b.allow(50));
        // 50 ticks later — delta 0 from last_time (which is still 0
        // because refill never ran), cost 100, so no refill yet.
        assert!(!b.allow(50));
    }
}

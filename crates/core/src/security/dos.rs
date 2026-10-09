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

/// Entry in the penalty box tracking a banned IP address.
#[derive(Copy, Clone, Debug)]
struct BanEntry {
    /// Banned IP address in network byte order.
    ip: u32,
    /// Time-source value at which the ban expires.
    expiry: u64,
}

impl BanEntry {
    /// A ban is active until, but not including, its expiry time.
    const fn is_active(&self, now: u64) -> bool {
        self.expiry > now
    }
}

/// Penalty box for tracking banned IP addresses.
///
/// Maintains a fixed-size table of banned IPs with expiration times.
/// When the table is full, new bans overwrite the oldest entries.
#[derive(Debug)]
pub struct PenaltyBox {
    /// Array of ban entries, limited to 16 for memory efficiency.
    entries: [BanEntry; 16],
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
    /// Creates a new empty penalty box.
    pub const fn new() -> Self {
        Self {
            entries: [BanEntry { ip: 0, expiry: 0 }; 16],
            next_evict: 0,
        }
    }

    /// Bans an IP address until `now + duration`.
    ///
    /// Refreshes the IP's existing ban if it has one; otherwise takes a
    /// slot whose ban has ended, and only when every slot holds an active
    /// ban evicts one in round-robin order.
    ///
    /// # Arguments
    ///
    /// * `ip_bytes` - IP address as 4 bytes in network byte order.
    /// * `duration` - Ban duration in time-source units.
    /// * `now`      - Current time-source value.
    pub fn ban(&mut self, ip_bytes: &[u8; 4], duration: u64, now: u64) {
        let ip = u32::from_be_bytes(*ip_bytes);
        let expiry = now.saturating_add(duration);

        if let Some(entry) = self.entries.iter_mut().find(|e| e.ip == ip && e.is_active(now)) {
            entry.expiry = expiry;
            return;
        }
        if let Some(entry) = self.entries.iter_mut().find(|e| !e.is_active(now)) {
            *entry = BanEntry { ip, expiry };
            return;
        }
        let idx = self.next_evict;
        self.next_evict = (self.next_evict + 1) % 16;
        self.entries[idx] = BanEntry { ip, expiry };
    }

    /// Lifts any ban on `ip_bytes` (network byte order).
    pub fn unban(&mut self, ip_bytes: &[u8; 4]) {
        let ip = u32::from_be_bytes(*ip_bytes);
        for entry in &mut self.entries {
            if entry.ip == ip {
                entry.expiry = 0;
            }
        }
    }

    /// Checks if an IP address is currently banned.
    ///
    /// # Arguments
    ///
    /// * `ip_bytes` - IP address as 4 bytes in network byte order.
    /// * `now` - Current time-source value; bans with `expiry > now` are
    ///   considered active.
    ///
    /// # Returns
    ///
    /// `true` if the IP is banned and the ban has not expired.
    pub fn is_banned(&self, ip_bytes: &[u8; 4], now: u64) -> bool {
        let ip = u32::from_be_bytes(*ip_bytes);
        self.entries.iter().any(|e| e.ip == ip && e.is_active(now))
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
        assert!(allowed >= 300, "only {allowed} tokens in 3000 ticks at cost 10");
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

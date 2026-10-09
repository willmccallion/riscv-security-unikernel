//! Virtual HyperLogLog: distinct counts for many flows in one register pool.

use super::hyperloglog;
use crate::security::hash::{derive_key, siphash24};

/// Estimates, for any flow, how many distinct elements it has carried, e.g.
/// how many destination ports a source has touched.
///
/// Every flow owns `PER_FLOW` registers scattered through a shared pool of
/// `POOL` registers (its virtual HyperLogLog), so memory is fixed however
/// many flows appear and no flow can be pushed out of a table. Registers
/// shared with other flows add noise, which the estimate removes using the
/// pool-wide count:
/// `n_f ≈ (m·s / (m − s)) · (n_virtual / s − n_pool / m)`
/// (Xiao, Chen, Chen and Ling, "Hyper-compact virtual estimators for big
/// network data based on register sharing", SIGMETRICS 2015).
#[derive(Debug)]
pub struct VirtualHyperLogLog<const POOL: usize, const PER_FLOW: usize> {
    pool: [u8; POOL],
    flow_key: [u8; 16],
    element_key: [u8; 16],
    /// Exact `Σ 2^-register` over the pool, scaled by `2^64`, so the pool
    /// estimate costs O(1) instead of a pass over every register.
    scaled_inverse_sum: u128,
    zeros: usize,
}

impl<const POOL: usize, const PER_FLOW: usize> VirtualHyperLogLog<POOL, PER_FLOW> {
    const INDEX_BITS: u32 = PER_FLOW.trailing_zeros();
    const VALID: () = assert!(
        POOL.is_power_of_two()
            && PER_FLOW.is_power_of_two()
            && PER_FLOW >= 16
            && PER_FLOW < POOL,
        "POOL and PER_FLOW must be powers of two with 16 <= PER_FLOW < POOL"
    );

    /// An empty estimator whose hashing is keyed with `key`.
    pub const fn new(key: [u8; 16]) -> Self {
        let () = Self::VALID;
        Self {
            pool: [0; POOL],
            flow_key: derive_key(&key, b"vhll flow"),
            element_key: derive_key(&key, b"vhll element"),
            scaled_inverse_sum: (POOL as u128) << 64,
            zeros: POOL,
        }
    }

    /// Clears the estimator and switches to hashing with `key`.
    pub fn rekey(&mut self, key: [u8; 16]) {
        *self = Self {
            pool: self.pool,
            ..Self::new(key)
        };
        self.clear();
    }

    /// Records that `flow` carried `element`. Returns whether a register
    /// changed, which is the only time any estimate can change.
    pub fn insert(&mut self, flow: &[u8], element: &[u8]) -> bool {
        let element_hash = siphash24(&self.element_key, element);
        let virtual_index = (element_hash as usize) & (PER_FLOW - 1);
        let remaining_bits = 64 - Self::INDEX_BITS;
        let shifted = (element_hash >> Self::INDEX_BITS) << Self::INDEX_BITS;
        let rank = (shifted.leading_zeros().min(remaining_bits) + 1) as u8;

        let position = Self::physical(siphash24(&self.flow_key, flow), virtual_index);
        let old = self.pool[position];
        if rank <= old {
            return false;
        }
        self.pool[position] = rank;
        self.scaled_inverse_sum -= scaled_pow2_neg(old);
        self.scaled_inverse_sum += scaled_pow2_neg(rank);
        self.zeros -= usize::from(old == 0);
        true
    }

    /// The estimated number of distinct elements `flow` has carried.
    pub fn estimate(&self, flow: &[u8]) -> f64 {
        let flow_hash = siphash24(&self.flow_key, flow);
        let mut registers = [0u8; PER_FLOW];
        for (i, register) in registers.iter_mut().enumerate() {
            *register = self.pool[Self::physical(flow_hash, i)];
        }
        let virtual_estimate = hyperloglog::estimate(&registers);
        let pool_estimate = self.pool_estimate();
        let (m, s) = (POOL as f64, PER_FLOW as f64);
        (m * s / (m - s) * (virtual_estimate / s - pool_estimate / m)).max(0.0)
    }

    /// Forgets every flow.
    pub fn clear(&mut self) {
        self.pool.fill(0);
        self.scaled_inverse_sum = (POOL as u128) << 64;
        self.zeros = POOL;
    }

    /// HyperLogLog estimate over the whole pool, from the running sums.
    fn pool_estimate(&self) -> f64 {
        let m = POOL as f64;
        let inverse_sum = self.scaled_inverse_sum as f64 / 18_446_744_073_709_551_616.0;
        let raw = hyperloglog::alpha(POOL) * m * m / inverse_sum;
        if raw <= 2.5 * m && self.zeros > 0 {
            m * hyperloglog::ln(m / self.zeros as f64)
        } else {
            raw
        }
    }

    /// Pool position of the `i`th virtual register of the flow whose keyed
    /// hash is `flow_hash`.
    ///
    /// Each position is mixed independently: deriving them as
    /// `start + i·stride` would give two flows sharing `start` and `stride`
    /// every register in common, so an ordinary source could read exactly
    /// like a scanner.
    const fn physical(flow_hash: u64, i: usize) -> usize {
        splitmix64(flow_hash ^ (i as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15)) as usize & (POOL - 1)
    }
}

/// The SplitMix64 finaliser: a cheap bijection that spreads every input
/// bit across the output.
const fn splitmix64(mut x: u64) -> u64 {
    x = (x ^ (x >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    x ^ (x >> 31)
}

/// `2^(64 - exponent)`, i.e. `2^-exponent` scaled by `2^64`.
fn scaled_pow2_neg(exponent: u8) -> u128 {
    1u128 << (64 - u32::from(exponent))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_scanner_stands_out_from_ordinary_sources() {
        let mut vhll = VirtualHyperLogLog::<1024, 32>::new([4; 16]);
        for source in 0u32..300 {
            for port in [80u16, 443, 53] {
                let _ = vhll.insert(&source.to_be_bytes(), &port.to_be_bytes());
            }
        }
        let scanner = 9_999u32.to_be_bytes();
        for port in 1u16..=500 {
            let _ = vhll.insert(&scanner, &port.to_be_bytes());
        }

        let scanner_estimate = vhll.estimate(&scanner);
        let ordinary = vhll.estimate(&7u32.to_be_bytes());

        assert!((300.0..800.0).contains(&scanner_estimate), "scanner: {scanner_estimate}");
        assert!(ordinary < 40.0, "ordinary source: {ordinary}");
    }

    #[test]
    fn repeated_elements_count_once() {
        let mut vhll = VirtualHyperLogLog::<1024, 32>::new([4; 16]);
        for _ in 0..1000 {
            let _ = vhll.insert(b"src", &80u16.to_be_bytes());
        }

        assert!(vhll.estimate(b"src") < 5.0);
    }

    #[test]
    fn running_pool_estimate_matches_a_full_recount() {
        let mut vhll = VirtualHyperLogLog::<1024, 32>::new([4; 16]);
        for i in 0u32..5000 {
            let _ = vhll.insert(&(i % 97).to_be_bytes(), &i.to_be_bytes());
        }

        let recount = hyperloglog::estimate(&vhll.pool);

        assert!((vhll.pool_estimate() - recount).abs() < 1e-6 * recount);
    }

    #[test]
    fn two_flows_almost_never_share_most_registers() {
        const FLOWS: u64 = 400;
        let positions: [[usize; 32]; FLOWS as usize] = core::array::from_fn(|f| {
            core::array::from_fn(|i| VirtualHyperLogLog::<1024, 32>::physical(f as u64 * 0x1234_5678_9ABC, i))
        });

        let mut worst = 0;
        for a in 0..positions.len() {
            for b in a + 1..positions.len() {
                let shared = positions[a].iter().filter(|p| positions[b].contains(p)).count();
                worst = worst.max(shared);
            }
        }

        assert!(worst < 8, "two flows share {worst} of 32 registers");
    }

    #[test]
    fn clear_forgets_every_flow() {
        let mut vhll = VirtualHyperLogLog::<1024, 32>::new([4; 16]);
        for port in 0u16..300 {
            let _ = vhll.insert(b"src", &port.to_be_bytes());
        }

        vhll.clear();

        assert!(vhll.estimate(b"src") < 1.0);
    }
}

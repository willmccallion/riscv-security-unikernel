//! HyperLogLog: approximate count of distinct items in fixed memory.

use crate::security::hash::siphash24;

/// Estimates how many distinct items it has seen, with relative standard
/// error about `1.04 / sqrt(REGISTERS)` (6.5% for 256 registers).
///
/// Each item's keyed 64-bit hash picks a register with its low bits; the
/// register keeps the longest run of leading zeros seen in the remaining
/// bits. Many distinct items make long runs likely, and the harmonic mean
/// over registers turns that into a count. Repeats of an item change
/// nothing, and memory is one byte per register regardless of how many
/// items arrive.
#[derive(Debug)]
pub struct HyperLogLog<const REGISTERS: usize> {
    registers: [u8; REGISTERS],
    key: [u8; 16],
}

impl<const REGISTERS: usize> HyperLogLog<REGISTERS> {
    const INDEX_BITS: u32 = REGISTERS.trailing_zeros();
    const VALID: () = assert!(
        REGISTERS.is_power_of_two() && REGISTERS >= 16,
        "REGISTERS must be a power of two of at least 16"
    );

    /// An empty counter whose hashing is keyed with `key`.
    pub const fn new(key: [u8; 16]) -> Self {
        let () = Self::VALID;
        Self {
            registers: [0; REGISTERS],
            key,
        }
    }

    /// Clears the counter and switches to hashing with `key`.
    pub fn rekey(&mut self, key: [u8; 16]) {
        self.clear();
        self.key = key;
    }

    /// Records `item`. Returns whether any register changed, which is the
    /// only time the estimate can change.
    pub fn insert(&mut self, item: &[u8]) -> bool {
        self.insert_hash(siphash24(&self.key, item))
    }

    /// Records an item by its already-computed 64-bit hash.
    pub fn insert_hash(&mut self, hash: u64) -> bool {
        let index = (hash as usize) & (REGISTERS - 1);
        let rank = rank(hash >> Self::INDEX_BITS, 64 - Self::INDEX_BITS);
        if rank > self.registers[index] {
            self.registers[index] = rank;
            true
        } else {
            false
        }
    }

    /// The estimated number of distinct items seen since the last clear.
    pub fn estimate(&self) -> f64 {
        estimate(&self.registers)
    }

    /// Forgets every item.
    pub fn clear(&mut self) {
        self.registers.fill(0);
    }
}

/// Position of the first set bit, counting from 1, in the low `bits` bits
/// of `remaining` read from the top; `bits + 1` if none is set.
fn rank(remaining: u64, bits: u32) -> u8 {
    let leading = (remaining << (64 - bits)).leading_zeros().min(bits);
    (leading + 1) as u8
}

/// The HyperLogLog estimate over `registers`, with the linear-counting
/// correction for small counts (Flajolet et al., 2007).
pub(super) fn estimate(registers: &[u8]) -> f64 {
    let m = registers.len() as f64;
    let mut inverse_sum = 0.0;
    let mut zeros = 0usize;
    for &r in registers {
        inverse_sum += pow2_neg(r);
        zeros += usize::from(r == 0);
    }
    let raw = alpha(registers.len()) * m * m / inverse_sum;
    if raw <= 2.5 * m && zeros > 0 {
        m * ln(m / zeros as f64)
    } else {
        raw
    }
}

/// The bias correction constant for `m` registers.
pub(super) fn alpha(m: usize) -> f64 {
    match m {
        16 => 0.673,
        32 => 0.697,
        64 => 0.709,
        _ => 0.7213 / (1.0 + 1.079 / m as f64),
    }
}

/// `2^-exponent` for the register values HyperLogLog uses.
fn pow2_neg(exponent: u8) -> f64 {
    f64::from_bits((1023 - u64::from(exponent)) << 52)
}

/// Natural logarithm of a positive finite `x`, accurate to about 1e-12.
///
/// `core` has no `ln` without the standard library. Splits `x` into
/// `mantissa · 2^exponent` with the mantissa in `[1, 2)`, then sums the
/// `atanh` series `ln(m) = 2·(z + z³/3 + z⁵/5 + …)` with `z = (m-1)/(m+1)`,
/// which converges quickly because `z <= 1/3`.
pub(super) fn ln(x: f64) -> f64 {
    const LN_2: f64 = core::f64::consts::LN_2;
    let bits = x.to_bits();
    let exponent = ((bits >> 52) & 0x7FF) as i64 - 1023;
    let mantissa = f64::from_bits((bits & ((1 << 52) - 1)) | (1023 << 52));
    let z = (mantissa - 1.0) / (mantissa + 1.0);
    let z2 = z * z;
    let mut term = z;
    let mut series = 0.0;
    for k in (1u32..40).step_by(2) {
        series += term / f64::from(k);
        term *= z2;
    }
    exponent as f64 * LN_2 + 2.0 * series
}

#[cfg(test)]
mod tests {
    use super::*;

    fn close(a: f64, b: f64, tolerance: f64) -> bool {
        (a - b).abs() <= tolerance * b.abs().max(1.0)
    }

    #[test]
    fn ln_matches_known_values() {
        assert!(close(ln(1.0), 0.0, 1e-12));
        assert!(close(ln(core::f64::consts::E), 1.0, 1e-12));
        assert!(close(ln(10.0), core::f64::consts::LN_10, 1e-12));
        assert!(close(ln(0.001), -6.907_755_278_982_137, 1e-12));
        assert!(close(ln(65_536.0), 16.0 * core::f64::consts::LN_2, 1e-12));
    }

    #[test]
    fn empty_counter_estimates_zero() {
        let hll = HyperLogLog::<256>::new([1; 16]);

        assert!(close(hll.estimate(), 0.0, 1e-9));
    }

    #[test]
    fn repeats_do_not_change_the_estimate() {
        let mut hll = HyperLogLog::<256>::new([1; 16]);
        for i in 0u32..100 {
            let _ = hll.insert(&i.to_be_bytes());
        }
        let before = hll.estimate();

        for _ in 0..10 {
            for i in 0u32..100 {
                let _ = hll.insert(&i.to_be_bytes());
            }
        }

        assert!(close(hll.estimate(), before, 1e-12));
    }

    #[test]
    fn estimates_are_within_a_few_standard_errors() {
        // 1.04 / sqrt(256) = 6.5% standard error; allow 4 sigma.
        for (key, distinct) in [(1u8, 50u32), (2, 1_000), (3, 20_000), (4, 200_000)] {
            let mut hll = HyperLogLog::<256>::new([key; 16]);
            for i in 0..distinct {
                let _ = hll.insert(&i.to_be_bytes());
            }

            let estimate = hll.estimate();

            let error = (estimate - f64::from(distinct)).abs() / f64::from(distinct);
            assert!(error < 0.26, "{distinct} distinct estimated as {estimate}");
        }
    }

    #[test]
    fn clear_forgets_everything() {
        let mut hll = HyperLogLog::<64>::new([1; 16]);
        for i in 0u32..1000 {
            let _ = hll.insert(&i.to_be_bytes());
        }

        hll.clear();

        assert!(close(hll.estimate(), 0.0, 1e-9));
    }
}

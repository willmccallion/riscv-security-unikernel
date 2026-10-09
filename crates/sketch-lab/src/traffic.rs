//! Synthetic streams with exact ground truth.

use rand::Rng;
use rand::rngs::StdRng;
use rand::seq::SliceRandom;

/// Draws item indices from a Zipf distribution: item `k` (0-based) has
/// probability proportional to `1 / (k + 1)^exponent`.
pub struct Zipf {
    cdf: Vec<f64>,
}

impl Zipf {
    /// A Zipf distribution over `items` items.
    pub fn new(items: usize, exponent: f64) -> Self {
        let weights: Vec<f64> = (1..=items).map(|k| 1.0 / (k as f64).powf(exponent)).collect();
        let total: f64 = weights.iter().sum();
        let mut running = 0.0;
        let cdf = weights
            .iter()
            .map(|w| {
                running += w / total;
                running
            })
            .collect();
        Self { cdf }
    }

    /// One sample.
    pub fn sample(&self, rng: &mut StdRng) -> usize {
        let u: f64 = rng.r#gen();
        self.cdf.partition_point(|&p| p < u).min(self.cdf.len() - 1)
    }
}

/// A source sending at a steady rate, and whether it should be caught.
#[derive(Debug, Clone, Copy)]
pub struct Source {
    /// IPv4 address used as the sketch key.
    pub addr: [u8; 4],
    /// Mean packets per second.
    pub rate_pps: f64,
    /// True for attackers, which the detector should flag.
    pub attacker: bool,
}

/// Legitimate sources at 5–20 pps summing to about `load_pps`, plus
/// `attackers` sources at `attack_pps` each.
pub fn population(load_pps: f64, attackers: usize, attack_pps: f64, rng: &mut StdRng) -> Vec<Source> {
    const MEAN_LEGIT_PPS: f64 = 12.5;
    let legit = ((load_pps / MEAN_LEGIT_PPS).round() as usize).max(1);
    let addr = |n: usize| (u32::try_from(n).unwrap_or(u32::MAX) | 0x0A00_0000).to_be_bytes();
    let mut sources: Vec<Source> = (0..legit)
        .map(|n| Source {
            addr: addr(n),
            rate_pps: rng.gen_range(5.0..20.0),
            attacker: false,
        })
        .collect();
    sources.extend((0..attackers).map(|n| Source {
        addr: addr(legit + n),
        rate_pps: attack_pps,
        attacker: true,
    }));
    sources
}

/// The packets every source sends in one interval of `seconds`, as source
/// indices in random arrival order. Counts are the expected count rounded
/// up or down at random, keeping each source's long-run rate exact.
pub fn interval_arrivals(sources: &[Source], seconds: f64, rng: &mut StdRng) -> Vec<usize> {
    let mut arrivals = Vec::new();
    for (i, source) in sources.iter().enumerate() {
        let expected = source.rate_pps * seconds;
        let whole = expected.floor();
        let extra = usize::from(rng.gen_bool(expected - whole));
        arrivals.extend(std::iter::repeat_n(i, whole as usize + extra));
    }
    arrivals.shuffle(rng);
    arrivals
}

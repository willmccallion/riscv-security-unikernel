//! Human-readable rates and sizes.

/// A bit rate with an SI prefix, e.g. `12.4 Mb/s`.
pub fn bits_per_second(bps: f64) -> String {
    with_prefix(bps, "b/s")
}

/// A byte count with an SI prefix, e.g. `3.1 MB`.
pub fn bytes(count: u64) -> String {
    with_prefix(count as f64, "B")
}

fn with_prefix(value: f64, unit: &str) -> String {
    let (scaled, prefix) = match value {
        v if v >= 1e9 => (v / 1e9, "G"),
        v if v >= 1e6 => (v / 1e6, "M"),
        v if v >= 1e3 => (v / 1e3, "k"),
        v => (v, ""),
    };
    if prefix.is_empty() {
        format!("{scaled:.0} {unit}")
    } else {
        format!("{scaled:.1} {prefix}{unit}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rates_and_sizes_use_si_prefixes() {
        assert_eq!(bits_per_second(0.0), "0 b/s");
        assert_eq!(bits_per_second(688.0), "688 b/s");
        assert_eq!(bits_per_second(7_900_000.0), "7.9 Mb/s");
        assert_eq!(bytes(1_536), "1.5 kB");
        assert_eq!(bytes(3_100_000_000), "3.1 GB");
    }
}

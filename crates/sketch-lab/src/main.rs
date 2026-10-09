//! Accuracy studies of the `sec-core` sketches against exact ground truth.
//!
//! Writes one CSV per experiment into the directory given as the first
//! argument (default `docs/sketches/data`); `scripts/plot_sketches.py`
//! turns them into the charts in the README.

mod sketches;
mod traffic;

use anyhow::{Context, Result};
use rand::SeedableRng;
use rand::rngs::StdRng;
use sec_core::config::{
    CMS_DECAY_INTERVAL_CYCLES, HEAVY_HITTER_THRESHOLD, SUBNET_16_THRESHOLD, SUBNET_24_THRESHOLD,
};
use sec_core::security::dos::Ipv4Prefix;
use sec_core::security::scan::PortScanDetector;
use sec_core::security::sketch::HyperLogLog;
use sketches::{Aging, Cms, FrequencySketch, ScanDetector, Update, VhllThreshold};
use std::collections::HashSet;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use traffic::{Source, Zipf};

/// Builds a fresh sketch for one simulation run.
type MakeSketch = fn() -> Box<dyn FrequencySketch>;

/// Builds a fresh port-scan detector for one simulation run.
type MakeScanDetector = fn() -> Box<dyn ScanDetector>;

/// Every sketch in the studies uses this key; results do not depend on it.
const KEY: [u8; 16] = [7; 16];

fn main() -> Result<()> {
    let out = std::env::args()
        .nth(1)
        .map_or_else(|| PathBuf::from("docs/sketches/data"), PathBuf::from);
    std::fs::create_dir_all(&out).with_context(|| format!("create {}", out.display()))?;
    cms_error_vs_memory(&out.join("cms_error_vs_memory.csv"))?;
    cms_detector_vs_load(&out.join("cms_detector_vs_load.csv"))?;
    hll_error_vs_registers(&out.join("hll_error_vs_registers.csv"))?;
    port_scans_vs_load(&out.join("port_scans_vs_load.csv"))?;
    subnet_floods_vs_load(&out.join("subnet_floods_vs_load.csv"))?;
    Ok(())
}

fn write_csv(path: &Path, header: &str, rows: &[String]) -> Result<()> {
    let mut text = format!("{header}\n");
    for row in rows {
        text.push_str(row);
        text.push('\n');
    }
    std::fs::write(path, text).with_context(|| format!("write {}", path.display()))?;
    println!("wrote {}", path.display());
    Ok(())
}

fn source_key(index: usize) -> [u8; 4] {
    u32::try_from(index).unwrap_or(u32::MAX).to_be_bytes()
}

/// How far estimates overshoot on a skewed stream, per update rule and
/// size: 200k packets over 50k items drawn from Zipf(1.1).
fn cms_error_vs_memory(path: &Path) -> Result<()> {
    const PACKETS: usize = 200_000;
    const ITEMS: usize = 50_000;
    const EXPONENT: f64 = 1.1;

    let mut rng = StdRng::seed_from_u64(1);
    let zipf = Zipf::new(ITEMS, EXPONENT);
    let stream: Vec<usize> = (0..PACKETS).map(|_| zipf.sample(&mut rng)).collect();
    let mut truth = vec![0u32; ITEMS];
    for &item in &stream {
        truth[item] += 1;
    }
    let seen: Vec<usize> = (0..ITEMS).filter(|&i| truth[i] > 0).collect();

    let mut rows = Vec::new();
    for update in [Update::Classic, Update::Conservative] {
        let set = sketches!(
            update,
            Aging::Decay,
            KEY,
            (64, 3),
            (128, 3),
            (256, 3),
            (512, 3),
            (1024, 3),
            (2048, 3),
            (4096, 3),
            (8192, 3),
            (16384, 3),
            (64, 4),
            (128, 4),
            (256, 4),
            (512, 4),
            (1024, 4),
            (2048, 4),
            (4096, 4),
            (8192, 4),
            (16384, 4),
        );
        for mut sketch in set {
            for &item in &stream {
                let _ = sketch.insert(&source_key(item));
            }
            let mut errors: Vec<u32> = seen
                .iter()
                .map(|&i| u32::from(sketch.estimate(&source_key(i))).saturating_sub(truth[i]))
                .collect();
            errors.sort_unstable();
            let mean = errors.iter().map(|&e| f64::from(e)).sum::<f64>() / errors.len() as f64;
            let p99 = errors[errors.len() * 99 / 100];
            rows.push(format!(
                "{update:?},{},{},{},{mean:.3},{p99}",
                sketch.width(),
                sketch.depth(),
                sketch.memory_bytes()
            ));
        }
    }
    write_csv(
        path,
        "update,width,depth,memory_bytes,mean_abs_error,p99_abs_error",
        &rows,
    )
}

/// Heavy-hitter detection as total traffic grows: legitimate sources at
/// 5–20 pps (which must never be flagged) plus ten attackers at 300 pps
/// (which must be), simulated for ten seconds. A flagged source is
/// treated as banned and stops being counted, as in the engine.
fn cms_detector_vs_load(path: &Path) -> Result<()> {
    const SECONDS: u32 = 10;
    const ATTACKERS: usize = 10;
    const ATTACK_PPS: f64 = 300.0;
    const LOADS: [f64; 9] = [
        1_000.0, 2_000.0, 5_000.0, 10_000.0, 20_000.0, 50_000.0, 100_000.0, 200_000.0, 500_000.0,
    ];
    let interval_s = CMS_DECAY_INTERVAL_CYCLES as f64 / 1e9;
    let intervals = (f64::from(SECONDS) / interval_s).round() as u32;

    let mut rows = Vec::new();
    let mut summary = String::from("| config | memory |");
    for load in LOADS {
        let _ = write!(summary, " {}k pps |", load / 1000.0);
    }
    summary.push('\n');

    let configs: Vec<(&str, MakeSketch)> = vec![
        ("previous: 128x4 classic, 1 s reset", || {
            Box::new(Cms::<128, 4>::new(
                Update::Classic,
                Aging::Reset { intervals: 2 },
                KEY,
            ))
        }),
        ("128x4", || {
            Box::new(Cms::<128, 4>::new(Update::Conservative, Aging::Decay, KEY))
        }),
        ("512x3", || {
            Box::new(Cms::<512, 3>::new(Update::Conservative, Aging::Decay, KEY))
        }),
        ("1024x3", || {
            Box::new(Cms::<1024, 3>::new(Update::Conservative, Aging::Decay, KEY))
        }),
        ("2048x3", || {
            Box::new(Cms::<2048, 3>::new(Update::Conservative, Aging::Decay, KEY))
        }),
        ("4096x4", || {
            Box::new(Cms::<4096, 4>::new(Update::Conservative, Aging::Decay, KEY))
        }),
        ("65536x4", || {
            Box::new(Cms::<65536, 4>::new(
                Update::Conservative,
                Aging::Decay,
                KEY,
            ))
        }),
    ];
    let mut table: Vec<Vec<String>> = vec![Vec::new(); configs.len()];

    for load in LOADS {
        let mut rng = StdRng::seed_from_u64(load as u64);
        let sources = traffic::population(load, ATTACKERS, ATTACK_PPS, &mut rng);
        let schedule: Vec<Vec<usize>> = (0..intervals)
            .map(|_| traffic::interval_arrivals(&sources, interval_s, &mut rng))
            .collect();
        for (c, (label, make)) in configs.iter().enumerate() {
            let outcome = simulate(make().as_mut(), &sources, &schedule, interval_s);
            let sketch = make();
            rows.push(format!(
                "\"{label}\",{},{},{},{load},{},{:.6},{},{:.1}",
                sketch.width(),
                sketch.depth(),
                sketch.memory_bytes(),
                outcome.legit,
                outcome.false_positive_rate,
                outcome.attackers_missed,
                outcome.mean_detection_ms
            ));
            table[c].push(format!("{:.1}%", outcome.false_positive_rate * 100.0));
        }
    }
    for (c, (label, make)) in configs.iter().enumerate() {
        let _ = writeln!(
            summary,
            "| {label} | {} B | {} |",
            make().memory_bytes(),
            table[c].join(" | ")
        );
    }
    println!("false positives (legitimate sources banned) by total load:\n{summary}");
    write_csv(
        path,
        "config,width,depth,memory_bytes,load_pps,legit_sources,false_positive_rate,attackers_missed,mean_detection_ms",
        &rows,
    )
}

/// What one detector run got right and wrong.
struct Outcome {
    legit: usize,
    false_positive_rate: f64,
    attackers_missed: usize,
    mean_detection_ms: f64,
}

fn simulate(
    sketch: &mut dyn FrequencySketch,
    sources: &[Source],
    schedule: &[Vec<usize>],
    interval_s: f64,
) -> Outcome {
    let mut flagged_at: Vec<Option<f64>> = vec![None; sources.len()];
    for (interval, arrivals) in schedule.iter().enumerate() {
        let start = interval as f64 * interval_s;
        for (k, &src) in arrivals.iter().enumerate() {
            if flagged_at[src].is_some() {
                continue;
            }
            if sketch.insert(&sources[src].addr) > HEAVY_HITTER_THRESHOLD {
                flagged_at[src] = Some(start + interval_s * k as f64 / arrivals.len() as f64);
            }
        }
        sketch.end_interval(u32::try_from(interval).unwrap_or(u32::MAX));
    }

    let legit = sources.iter().filter(|s| !s.attacker).count();
    let false_positives = sources
        .iter()
        .zip(&flagged_at)
        .filter(|(s, f)| !s.attacker && f.is_some())
        .count();
    let detections: Vec<f64> = sources
        .iter()
        .zip(&flagged_at)
        .filter(|(s, _)| s.attacker)
        .filter_map(|(_, f)| *f)
        .collect();
    let attackers = sources.len() - legit;
    Outcome {
        legit,
        false_positive_rate: false_positives as f64 / legit as f64,
        attackers_missed: attackers - detections.len(),
        mean_detection_ms: if detections.is_empty() {
            f64::NAN
        } else {
            detections.iter().sum::<f64>() / detections.len() as f64 * 1000.0
        },
    }
}

/// HyperLogLog relative error by register count: 40 differently keyed
/// counters per size and true count, against the `1.04 / sqrt(m)` the
/// analysis predicts.
fn hll_error_vs_registers(path: &Path) -> Result<()> {
    let mut rows = Vec::new();
    hll_errors::<16>(&mut rows);
    hll_errors::<32>(&mut rows);
    hll_errors::<64>(&mut rows);
    hll_errors::<128>(&mut rows);
    hll_errors::<256>(&mut rows);
    hll_errors::<512>(&mut rows);
    hll_errors::<1024>(&mut rows);
    hll_errors::<2048>(&mut rows);
    hll_errors::<4096>(&mut rows);
    write_csv(
        path,
        "registers,distinct,mean_relative_error,rms_relative_error,predicted_standard_error",
        &rows,
    )
}

fn hll_errors<const REGISTERS: usize>(rows: &mut Vec<String>) {
    const TRIALS: u8 = 40;
    const DISTINCT: [u32; 4] = [100, 1_000, 10_000, 100_000];
    for distinct in DISTINCT {
        let errors: Vec<f64> = (0..TRIALS)
            .map(|trial| {
                let mut hll = HyperLogLog::<REGISTERS>::new([trial; 16]);
                for i in 0..distinct {
                    let _ = hll.insert(&i.to_be_bytes());
                }
                (hll.estimate() - f64::from(distinct)) / f64::from(distinct)
            })
            .collect();
        let mean = errors.iter().map(|e| e.abs()).sum::<f64>() / errors.len() as f64;
        let rms = (errors.iter().map(|e| e * e).sum::<f64>() / errors.len() as f64).sqrt();
        rows.push(format!(
            "{REGISTERS},{distinct},{mean:.5},{rms:.5},{:.5}",
            1.04 / (REGISTERS as f64).sqrt()
        ));
    }
}

/// Port-scan detection as the number of sources per five-second window
/// grows. Ordinary sources open connections to one to four service ports;
/// ten scanners probe 100 random ports and ten probe 300, all interleaved
/// within one window, over three seeds. Compares a virtual HyperLogLog
/// that bans as soon as its estimate passes 64 ports with the engine's
/// detector, which uses a 1 KB one only to pick suspects to count exactly.
fn port_scans_vs_load(path: &Path) -> Result<()> {
    const SEEDS: u64 = 3;
    const SMALL_SCAN: usize = 100;
    const LARGE_SCAN: usize = 300;
    const SCANNERS_EACH: usize = 10;
    const SOURCES: [usize; 7] = [100, 300, 1_000, 3_000, 10_000, 30_000, 100_000];

    let configs: Vec<(&str, MakeScanDetector)> = vec![
        ("engine: 1 KB + exact confirm", || {
            Box::new(Box::new(PortScanDetector::new(KEY)))
        }),
        ("1 KB vHLL alone", || {
            Box::new(VhllThreshold::<1024, 32>::new(KEY))
        }),
        ("4 KB vHLL alone", || {
            Box::new(VhllThreshold::<4096, 32>::new(KEY))
        }),
        ("16 KB vHLL alone", || {
            Box::new(VhllThreshold::<16384, 32>::new(KEY))
        }),
        ("64 KB vHLL alone", || {
            Box::new(VhllThreshold::<65536, 64>::new(KEY))
        }),
    ];

    let mut rows = Vec::new();
    for sources in SOURCES {
        let mut false_positives = vec![0usize; configs.len()];
        let mut small_caught = vec![0usize; configs.len()];
        let mut large_caught = vec![0usize; configs.len()];
        for seed in 0..SEEDS {
            let mut rng = StdRng::seed_from_u64(sources as u64 * 31 + seed);
            let scanners = [(SMALL_SCAN, SCANNERS_EACH), (LARGE_SCAN, SCANNERS_EACH)];
            let events = traffic::connection_attempts(sources, &scanners, &mut rng);
            for (c, (_, make)) in configs.iter().enumerate() {
                let flagged =
                    run_scan_detector(make().as_mut(), &events, sources + 2 * SCANNERS_EACH);
                false_positives[c] += flagged[..sources].iter().filter(|&&f| f).count();
                small_caught[c] += flagged[sources..sources + SCANNERS_EACH]
                    .iter()
                    .filter(|&&f| f)
                    .count();
                large_caught[c] += flagged[sources + SCANNERS_EACH..]
                    .iter()
                    .filter(|&&f| f)
                    .count();
            }
        }
        for (c, (label, make)) in configs.iter().enumerate() {
            let scanners = (SEEDS as usize * SCANNERS_EACH) as f64;
            rows.push(format!(
                "\"{label}\",{},{sources},{:.6},{:.3},{:.3}",
                make().memory_bytes(),
                false_positives[c] as f64 / (SEEDS as usize * sources) as f64,
                small_caught[c] as f64 / scanners,
                large_caught[c] as f64 / scanners,
            ));
        }
    }
    write_csv(
        path,
        "config,memory_bytes,sources_per_window,false_positive_rate,caught_100_port_scans,caught_300_port_scans",
        &rows,
    )
}

/// Which sources `detector` bans over one window of `events`.
fn run_scan_detector(
    detector: &mut dyn ScanDetector,
    events: &[(usize, u16)],
    sources: usize,
) -> Vec<bool> {
    let mut flagged = vec![false; sources];
    for &(source, port) in events {
        if !flagged[source] && detector.observe(source_key(source), port) {
            flagged[source] = true;
        }
    }
    flagged
}

/// Subnet-flood detection as total traffic grows, over six seeds:
/// legitimate clients at 5–20 pps scattered across the address space, plus
/// a /24 of 20 hosts at 80 pps each and a /16 of 100 hosts (one per /24)
/// at 60 pps each. No attacking host passes the per-host threshold, but
/// each subnet passes its subnet threshold. The detector mirrors the
/// engine: hosts and subnets already banned stop counting, a host is
/// checked before its subnets, and both sketches halve every interval.
fn subnet_floods_vs_load(path: &Path) -> Result<()> {
    const SEEDS: u64 = 6;
    const SECONDS: u32 = 10;
    const LOADS: [f64; 8] = [
        1_000.0, 5_000.0, 10_000.0, 20_000.0, 50_000.0, 100_000.0, 200_000.0, 500_000.0,
    ];
    let interval_s = CMS_DECAY_INTERVAL_CYCLES as f64 / 1e9;
    let intervals = (f64::from(SECONDS) / interval_s).round() as u32;

    let configs: Vec<(&str, MakeSketch, MakeSketch)> = vec![
        ("kernel: 256x3", kernel_host_sketch, || {
            Box::new(Cms::<256, 3>::new(Update::Conservative, Aging::Decay, KEY))
        }),
        ("256x2", kernel_host_sketch, || {
            Box::new(Cms::<256, 2>::new(Update::Conservative, Aging::Decay, KEY))
        }),
        ("512x2", kernel_host_sketch, || {
            Box::new(Cms::<512, 2>::new(Update::Conservative, Aging::Decay, KEY))
        }),
        ("1024x2", kernel_host_sketch, || {
            Box::new(Cms::<1024, 2>::new(Update::Conservative, Aging::Decay, KEY))
        }),
        (
            "daemon: 16384x4",
            || {
                Box::new(Cms::<65536, 4>::new(
                    Update::Conservative,
                    Aging::Decay,
                    KEY,
                ))
            },
            || {
                Box::new(Cms::<16384, 4>::new(
                    Update::Conservative,
                    Aging::Decay,
                    KEY,
                ))
            },
        ),
    ];

    let mut rows = Vec::new();
    for load in LOADS {
        let mut totals = vec![SubnetTotals::default(); configs.len()];
        for seed in 0..SEEDS {
            let mut rng = StdRng::seed_from_u64(load as u64 + 7 + seed * 1_000_003);
            let sources = traffic::subnet_attack(load, &mut rng);
            let schedule: Vec<Vec<usize>> = (0..intervals)
                .map(|_| traffic::interval_arrivals(&sources, interval_s, &mut rng))
                .collect();
            for (c, (_, make_hosts, make_prefixes)) in configs.iter().enumerate() {
                let outcome = simulate_subnets(
                    make_hosts().as_mut(),
                    make_prefixes().as_mut(),
                    &sources,
                    &schedule,
                    interval_s,
                );
                totals[c].add(&outcome);
            }
        }
        for (c, (label, _, make_prefixes)) in configs.iter().enumerate() {
            let prefixes = make_prefixes();
            let t = &totals[c];
            rows.push(format!(
                "\"{label}\",{},{},{},{load},{},{},{},{},{}",
                prefixes.width(),
                prefixes.depth(),
                prefixes.memory_bytes(),
                t.legit_banned_by_subnet,
                t.legit_banned_as_hosts,
                t.legit_sources,
                optional_mean(t.slash_24_ms_sum, t.slash_24_caught),
                optional_mean(t.slash_16_ms_sum, t.slash_16_caught),
            ));
        }
    }
    write_csv(
        path,
        "config,width,depth,memory_bytes,load_pps,legit_banned_by_subnet,legit_banned_as_hosts,legit_sources,\
         mean_slash_24_detection_ms,mean_slash_16_detection_ms",
        &rows,
    )
}

fn kernel_host_sketch() -> Box<dyn FrequencySketch> {
    Box::new(Cms::<1024, 3>::new(Update::Conservative, Aging::Decay, KEY))
}

/// The mean of `count` values summing to `sum`, or an empty CSV field.
fn optional_mean(sum: f64, count: usize) -> String {
    if count == 0 {
        String::new()
    } else {
        format!("{:.0}", sum / count as f64)
    }
}

/// What one subnet-detector run got right and wrong.
struct SubnetOutcome {
    legit_sources: usize,
    legit_banned_as_hosts: usize,
    legit_banned_by_subnet: usize,
    slash_24_detection_ms: Option<f64>,
    slash_16_detection_ms: Option<f64>,
}

/// [`SubnetOutcome`]s summed over seeds.
#[derive(Debug, Clone, Default)]
struct SubnetTotals {
    legit_sources: usize,
    legit_banned_as_hosts: usize,
    legit_banned_by_subnet: usize,
    slash_24_caught: usize,
    slash_24_ms_sum: f64,
    slash_16_caught: usize,
    slash_16_ms_sum: f64,
}

impl SubnetTotals {
    fn add(&mut self, outcome: &SubnetOutcome) {
        self.legit_sources += outcome.legit_sources;
        self.legit_banned_as_hosts += outcome.legit_banned_as_hosts;
        self.legit_banned_by_subnet += outcome.legit_banned_by_subnet;
        if let Some(ms) = outcome.slash_24_detection_ms {
            self.slash_24_caught += 1;
            self.slash_24_ms_sum += ms;
        }
        if let Some(ms) = outcome.slash_16_detection_ms {
            self.slash_16_caught += 1;
            self.slash_16_ms_sum += ms;
        }
    }
}

fn simulate_subnets(
    hosts: &mut dyn FrequencySketch,
    prefixes: &mut dyn FrequencySketch,
    sources: &[Source],
    schedule: &[Vec<usize>],
    interval_s: f64,
) -> SubnetOutcome {
    let mut banned_hosts: HashSet<[u8; 4]> = HashSet::new();
    let mut banned_prefixes: Vec<(Ipv4Prefix, f64)> = Vec::new();
    let covered =
        |addr: [u8; 4], bans: &[(Ipv4Prefix, f64)]| bans.iter().any(|(p, _)| p.contains(addr));
    for (interval, arrivals) in schedule.iter().enumerate() {
        let start = interval as f64 * interval_s;
        for (k, &src) in arrivals.iter().enumerate() {
            let addr = sources[src].addr;
            if banned_hosts.contains(&addr) || covered(addr, &banned_prefixes) {
                continue;
            }
            if hosts.insert(&addr) > HEAVY_HITTER_THRESHOLD {
                let _ = banned_hosts.insert(addr);
                continue;
            }
            let at = start + interval_s * k as f64 / arrivals.len() as f64;
            for (len, threshold) in [(24, SUBNET_24_THRESHOLD), (16, SUBNET_16_THRESHOLD)] {
                let Some(prefix) = Ipv4Prefix::new(addr, len) else {
                    continue;
                };
                let network = prefix.network();
                if prefixes.insert(&[len, network[0], network[1], network[2]]) > threshold
                    && !banned_prefixes.iter().any(|(p, _)| *p == prefix)
                {
                    banned_prefixes.push((prefix, at));
                }
            }
        }
        hosts.end_interval(u32::try_from(interval).unwrap_or(u32::MAX));
        prefixes.end_interval(u32::try_from(interval).unwrap_or(u32::MAX));
    }

    let legit: Vec<&Source> = sources.iter().filter(|s| !s.attacker).collect();
    let detected = |net: [u8; 4], len: u8| {
        banned_prefixes
            .iter()
            .filter(|(p, _)| p.prefix_len() <= len && p.contains(net))
            .map(|&(_, at)| at * 1000.0)
            .reduce(f64::min)
    };
    SubnetOutcome {
        legit_sources: legit.len(),
        legit_banned_as_hosts: legit
            .iter()
            .filter(|s| banned_hosts.contains(&s.addr))
            .count(),
        legit_banned_by_subnet: legit
            .iter()
            .filter(|s| !banned_hosts.contains(&s.addr) && covered(s.addr, &banned_prefixes))
            .count(),
        slash_24_detection_ms: detected(traffic::ATTACK_SLASH_24, 24),
        slash_16_detection_ms: detected(traffic::ATTACK_SLASH_16, 16),
    }
}

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
use sec_core::config::{CMS_DECAY_INTERVAL_CYCLES, HEAVY_HITTER_THRESHOLD};
use sketches::{Aging, Cms, FrequencySketch, Update};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use traffic::{Source, Zipf};

/// Builds a fresh sketch for one simulation run.
type MakeSketch = fn() -> Box<dyn FrequencySketch>;

/// Every sketch in the studies uses this key; results do not depend on it.
const KEY: [u8; 16] = [7; 16];

fn main() -> Result<()> {
    let out = std::env::args()
        .nth(1)
        .map_or_else(|| PathBuf::from("docs/sketches/data"), PathBuf::from);
    std::fs::create_dir_all(&out).with_context(|| format!("create {}", out.display()))?;
    cms_error_vs_memory(&out.join("cms_error_vs_memory.csv"))?;
    cms_detector_vs_load(&out.join("cms_detector_vs_load.csv"))?;
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
            update, Aging::Decay, KEY,
            (64, 3), (128, 3), (256, 3), (512, 3), (1024, 3), (2048, 3), (4096, 3), (8192, 3), (16384, 3),
            (64, 4), (128, 4), (256, 4), (512, 4), (1024, 4), (2048, 4), (4096, 4), (8192, 4), (16384, 4),
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
    write_csv(path, "update,width,depth,memory_bytes,mean_abs_error,p99_abs_error", &rows)
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
            Box::new(Cms::<128, 4>::new(Update::Classic, Aging::Reset { intervals: 2 }, KEY))
        }),
        ("128x4", || Box::new(Cms::<128, 4>::new(Update::Conservative, Aging::Decay, KEY))),
        ("512x3", || Box::new(Cms::<512, 3>::new(Update::Conservative, Aging::Decay, KEY))),
        ("1024x3", || Box::new(Cms::<1024, 3>::new(Update::Conservative, Aging::Decay, KEY))),
        ("2048x3", || Box::new(Cms::<2048, 3>::new(Update::Conservative, Aging::Decay, KEY))),
        ("4096x4", || Box::new(Cms::<4096, 4>::new(Update::Conservative, Aging::Decay, KEY))),
        ("65536x4", || Box::new(Cms::<65536, 4>::new(Update::Conservative, Aging::Decay, KEY))),
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
        let _ = writeln!(summary, "| {label} | {} B | {} |", make().memory_bytes(), table[c].join(" | "));
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

fn simulate(sketch: &mut dyn FrequencySketch, sources: &[Source], schedule: &[Vec<usize>], interval_s: f64) -> Outcome {
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

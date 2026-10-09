//! Linux userspace daemon running the `sec-core` pipeline.
//!
//! - `bench` pushes synthetic traffic through the engine in memory and
//!   reports throughput.
//! - `run` inspects live traffic on an interface through an `AF_PACKET`
//!   ring, answering ARP/ICMP/SYN and emitting signed reports exactly as
//!   the unikernel does, so the GUI can drive it.
//! - `flood` sends synthetic traffic out of an interface, to load-test
//!   `run` on the other end of a veth pair.

mod af_packet;
mod bench;
mod clock;
mod key;
mod monitor;
mod synth;

/// The daemon's engine: a 65536 x 4 per-source sketch (512 KB), which
/// flags no legitimate source past 500k packets per second in the
/// sketch-lab study, and a 16384 x 4 per-subnet one (128 KB).
pub type DaemonEngine = sec_core::engine::Engine<65_536, 4, 16_384, 4>;

use af_packet::{RxRing, TxSocket};
use anyhow::{Context, Result};
use bench::VerdictCounts;
use clap::{Parser, Subcommand};
use rand::SeedableRng;
use rand::rngs::StdRng;
use sec_core::config::{CMS_DECAY_INTERVAL_CYCLES, FLOW_TIMEOUT_CYCLES};
use sec_core::engine::BootSecrets;
use sec_core::net::stack::SynCookieSecret;
use sec_core::time::TimeSource;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};
use synth::Mix;

/// How often `run` prints stats and sends telemetry, in nanoseconds.
const REPORT_INTERVAL: u64 = 1_000_000_000;

#[derive(Parser, Debug)]
#[command(about = "Run the sec-core security pipeline on Linux")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Measure engine throughput on synthetic traffic, in memory.
    Bench {
        /// Traffic mix.
        #[arg(long, value_enum, default_value_t = Mix::Mixed)]
        mix: Mix,
        /// Frames each thread processes.
        #[arg(long, default_value_t = 20_000_000)]
        packets: u64,
        /// Independent engines, one per thread.
        #[arg(long, default_value_t = 1)]
        threads: u64,
        /// Packet rate the engine is told it is seeing; drives its rate
        /// limits and heavy-hitter windows, not how fast frames are fed.
        #[arg(long, default_value_t = 10_000)]
        offered_pps: u64,
    },
    /// Inspect live traffic on an interface (needs `CAP_NET_RAW`).
    Run {
        /// Interface to capture on and reply through.
        #[arg(long)]
        iface: String,
        /// Stop after this many seconds; run until killed if omitted.
        #[arg(long)]
        duration_secs: Option<u64>,
    },
    /// Send synthetic traffic out of an interface (needs `CAP_NET_RAW`).
    Flood {
        /// Interface to send on.
        #[arg(long)]
        iface: String,
        /// Traffic mix.
        #[arg(long, value_enum, default_value_t = Mix::Mixed)]
        mix: Mix,
        /// How long to send for.
        #[arg(long, default_value_t = 10)]
        duration_secs: u64,
        /// Sending threads.
        #[arg(long, default_value_t = 1)]
        threads: u64,
    },
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Bench { mix, packets, threads, offered_pps } => {
            run_bench(bench::BenchConfig {
                mix,
                packets_per_thread: packets,
                threads,
                offered_pps,
            });
            Ok(())
        }
        Command::Run { iface, duration_secs } => run_live(&iface, duration_secs.map(Duration::from_secs)),
        Command::Flood { iface, mix, duration_secs, threads } => {
            run_flood(&iface, mix, Duration::from_secs(duration_secs), threads)
        }
    }
}

// Built once at startup on the main thread's 8 MB stack.
#[allow(clippy::large_stack_frames)]
fn new_engine(key: [u8; 16]) -> Box<DaemonEngine> {
    let mut engine = Box::new(DaemonEngine::new(key));
    engine.init(BootSecrets {
        syn_cookie: SynCookieSecret::new(rand::random()),
        cms_key: rand::random(),
        mgmt_epoch: rand::random::<u32>().max(1),
    });
    engine
}

fn run_bench(config: bench::BenchConfig) {
    println!(
        "bench: {} thread(s) × {} frames of {:?} traffic, offered at {} pps",
        config.threads, config.packets_per_thread, config.mix, config.offered_pps
    );
    let results = bench::run(config);
    let mut total_pps = 0.0;
    for (i, r) in results.iter().enumerate() {
        let secs = r.elapsed.as_secs_f64();
        let pps = r.packets as f64 / secs;
        total_pps += pps;
        println!(
            "  thread {i}: {:.2} Mpps, {:.0} ns/frame\n    {}",
            pps / 1e6,
            secs * 1e9 / r.packets as f64,
            r.verdicts
        );
    }
    println!("total: {:.2} Mpps", total_pps / 1e6);
}

fn run_live(iface: &str, duration: Option<Duration>) -> Result<()> {
    let key = key::load()?;
    let clock = clock::Monotonic::new();
    let mut rx = RxRing::open(iface)?;
    let mut tx = TxSocket::open(iface)?;
    let mut engine = new_engine(key);
    let started = Instant::now();
    println!("run: inspecting {iface} (epoch {:#010x})", engine.mgmt_epoch());

    let mut counts = VerdictCounts::default();
    let mut frames = 0u64;
    let mut last_report = clock.now();
    let mut last_cms_decay = last_report;

    while duration.is_none_or(|d| started.elapsed() < d) {
        let now = clock.now();
        let seen = rx.poll(100, |frame| {
            counts.record(engine.process(frame, now, &mut tx));
        })?;
        frames += seen as u64;

        let now = clock.now();
        if now.saturating_sub(last_cms_decay) >= CMS_DECAY_INTERVAL_CYCLES as u64 {
            engine.end_detection_interval(&mut tx);
            last_cms_decay = now;
        }
        if now.saturating_sub(last_report) >= REPORT_INTERVAL {
            let secs = (now - last_report) as f64 / 1e9;
            let ring = rx.stats()?;
            let (sent, refused) = tx.counts();
            println!(
                "{:>8.3} Mpps | {counts} | ring {} drops {} | tx {} (refused {})",
                frames as f64 / secs / 1e6,
                ring.packets,
                ring.drops,
                sent,
                refused
            );
            engine.prune_flows(now, FLOW_TIMEOUT_CYCLES as u64);
            engine.send_telemetry(resident_bytes().unwrap_or(0), &mut tx);
            engine.start_interval();
            counts = VerdictCounts::default();
            frames = 0;
            last_report = now;
        }
    }
    Ok(())
}

fn run_flood(iface: &str, mix: Mix, duration: Duration, threads: u64) -> Result<()> {
    let sent = Arc::new(AtomicU64::new(0));
    let stop = Arc::new(AtomicBool::new(false));
    let workers: Vec<_> = (0..threads)
        .map(|id| {
            let mut tx = TxSocket::open(iface)?;
            let sent = Arc::clone(&sent);
            let stop = Arc::clone(&stop);
            Ok(thread::spawn(move || {
                let mut rng = StdRng::seed_from_u64(id);
                let corpus = synth::frames(mix, 65_536, &mut rng);
                for frame in corpus.iter().cycle() {
                    if stop.load(Ordering::Relaxed) {
                        break;
                    }
                    if tx.send(frame) {
                        let _ = sent.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }))
        })
        .collect::<Result<_>>()?;

    let started = Instant::now();
    let mut last = 0;
    while started.elapsed() < duration {
        thread::sleep(Duration::from_secs(1));
        let total = sent.load(Ordering::Relaxed);
        println!("flood: {:.3} Mpps", (total - last) as f64 / 1e6);
        last = total;
    }
    stop.store(true, Ordering::Relaxed);
    for worker in workers {
        worker.join().map_err(|_| anyhow::anyhow!("flood thread panicked"))?;
    }
    println!(
        "flood: sent {} frames in {:.1}s",
        sent.load(Ordering::Relaxed),
        started.elapsed().as_secs_f64()
    );
    Ok(())
}

/// Resident set size, from the `VmRSS` line of `/proc/self/status`.
fn resident_bytes() -> Result<u64> {
    let status = std::fs::read_to_string("/proc/self/status")?;
    let kib: u64 = status
        .lines()
        .find_map(|line| line.strip_prefix("VmRSS:"))
        .and_then(|rest| rest.split_whitespace().next())
        .context("no VmRSS line")?
        .parse()?;
    Ok(kib * 1024)
}

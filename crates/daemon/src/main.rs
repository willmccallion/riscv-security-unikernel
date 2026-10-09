//! Linux userspace daemon running the `sec-core` pipeline.
//!
//! - `bench` pushes synthetic traffic through the engine in memory and
//!   reports throughput.

mod bench;
mod synth;

use clap::{Parser, Subcommand};
use synth::Mix;

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
}

fn main() {
    match Cli::parse().command {
        Command::Bench { mix, packets, threads, offered_pps } => run_bench(bench::BenchConfig {
            mix,
            packets_per_thread: packets,
            threads,
            offered_pps,
        }),
    }
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

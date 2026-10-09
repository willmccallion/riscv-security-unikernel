//! In-memory throughput benchmark of the full engine pipeline.
//!
//! Each thread owns an engine and replays a pre-built set of frames
//! through it, copying every frame into a receive buffer first as a NIC
//! would. The engine sees simulated time advancing at an offered packet
//! rate, independent of how fast the CPU actually processes the frames,
//! so its rate limits and heavy-hitter windows behave as they would on a
//! link carrying that rate while the wall clock measures CPU cost.
//! Periodic maintenance (sketch resets, flow pruning) runs on the same
//! simulated schedule as in the kernel.

use crate::DaemonEngine;
use crate::synth::{self, Mix};
use rand::SeedableRng;
use rand::rngs::StdRng;
use sec_core::config::{CMS_DECAY_INTERVAL_CYCLES, FLOW_TIMEOUT_CYCLES, TELEMETRY_INTERVAL_CYCLES};
use sec_core::security::alert::AlertReason;
use sec_core::engine::{BootSecrets, Verdict};
use sec_core::net::PacketSink;
use sec_core::net::stack::SynCookieSecret;
use std::thread;
use std::time::{Duration, Instant};

/// Distinct frames each thread cycles through.
const CORPUS_SIZE: usize = 65_536;

/// What one benchmark thread measured.
#[derive(Debug, Default, Clone)]
pub struct ThreadResult {
    /// Frames processed.
    pub packets: u64,
    /// Wall time spent processing them.
    pub elapsed: Duration,
    /// How the engine classified them.
    pub verdicts: VerdictCounts,
}

/// Verdict tally.
#[derive(Debug, Default, Clone, Copy)]
pub struct VerdictCounts {
    /// Cleared every check.
    pub passed: u64,
    /// Dropped by the ban list, heavy-hitter sketch or rate limiter.
    pub ddos: u64,
    /// Dropped by the port firewall.
    pub firewall: u64,
    /// Dropped on a DPI signature match.
    pub malware: u64,
    /// Dropped by heuristics.
    pub heuristic: u64,
    /// Dropped by the BPF filter.
    pub bpf: u64,
    /// Answered by the stack or carried no payload.
    pub consumed: u64,
    /// Mgmt-port traffic.
    pub management: u64,
}

impl VerdictCounts {
    /// Counts one verdict.
    pub const fn record(&mut self, verdict: Verdict) {
        match verdict {
            Verdict::Passed => self.passed += 1,
            Verdict::Dropped(AlertReason::Ddos) => self.ddos += 1,
            Verdict::Dropped(AlertReason::Firewall) => self.firewall += 1,
            Verdict::Dropped(AlertReason::Malware) => self.malware += 1,
            Verdict::Dropped(AlertReason::Heuristic) => self.heuristic += 1,
            Verdict::Dropped(_) => self.bpf += 1,
            Verdict::Consumed => self.consumed += 1,
            Verdict::Management => self.management += 1,
        }
    }
}

impl std::fmt::Display for VerdictCounts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "passed {} | dropped: ddos {} firewall {} malware {} heuristic {} bpf {} | consumed {} mgmt {}",
            self.passed,
            self.ddos,
            self.firewall,
            self.malware,
            self.heuristic,
            self.bpf,
            self.consumed,
            self.management
        )
    }
}

/// Discards everything the engine sends.
struct NullSink;

impl PacketSink for NullSink {
    fn send(&mut self, _frame: &[u8]) {}
}

/// What to benchmark.
#[derive(Debug, Clone, Copy)]
pub struct BenchConfig {
    /// Traffic mix.
    pub mix: Mix,
    /// Frames each thread processes.
    pub packets_per_thread: u64,
    /// Independent engines, one per thread.
    pub threads: u64,
    /// Packet rate the engine is told it is seeing.
    pub offered_pps: u64,
}

/// Mgmt key for benchmark engines; no mgmt traffic is generated.
const BENCH_KEY: [u8; 16] = [0; 16];

/// Runs the configured engines and returns what every thread measured.
pub fn run(config: BenchConfig) -> Vec<ThreadResult> {
    /// Room for building a [`DaemonEngine`] on the thread's stack.
    const THREAD_STACK: usize = 16 << 20;

    // Collect first so every thread starts before any is joined.
    #[allow(clippy::needless_collect)]
    let workers: Vec<_> = (0..config.threads)
        .filter_map(|id| {
            thread::Builder::new()
                .stack_size(THREAD_STACK)
                .spawn(move || run_thread(config, id))
                .ok()
        })
        .collect();
    workers.into_iter().filter_map(|w| w.join().ok()).collect()
}

// The engine is built once per thread, which `run` gives a large stack.
#[allow(clippy::large_stack_frames)]
fn run_thread(config: BenchConfig, id: u64) -> ThreadResult {
    let mut rng = StdRng::seed_from_u64(id);
    let corpus = synth::frames(config.mix, CORPUS_SIZE, &mut rng);
    let step = 1_000_000_000 / config.offered_pps.max(1);
    let mut engine = Box::new(DaemonEngine::new(BENCH_KEY));
    engine.init(BootSecrets {
        syn_cookie: SynCookieSecret::new(rand::random()),
        cms_key: rand::random(),
        mgmt_epoch: 1,
    });

    let mut result = ThreadResult::default();
    let mut scratch = [0u8; 2048];
    let mut now: u64 = 0;
    let mut next_telemetry = TELEMETRY_INTERVAL_CYCLES as u64;
    let mut next_cms_decay = CMS_DECAY_INTERVAL_CYCLES as u64;

    let started = Instant::now();
    let packets = usize::try_from(config.packets_per_thread).unwrap_or(usize::MAX);
    for frame in corpus.iter().cycle().take(packets) {
        now += step;
        if now >= next_telemetry {
            engine.prune_flows(now, FLOW_TIMEOUT_CYCLES as u64);
            engine.start_interval();
            next_telemetry += TELEMETRY_INTERVAL_CYCLES as u64;
        }
        if now >= next_cms_decay {
            engine.end_detection_interval(&mut NullSink);
            next_cms_decay += CMS_DECAY_INTERVAL_CYCLES as u64;
        }
        let buf = &mut scratch[..frame.len()];
        buf.copy_from_slice(frame);
        result.verdicts.record(engine.process(buf, now, &mut NullSink));
        result.packets += 1;
    }
    result.elapsed = started.elapsed();
    result
}

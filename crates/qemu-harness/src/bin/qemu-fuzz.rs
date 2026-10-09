//! Full-system fuzzer: boots the real kernel under QEMU and feeds it
//! mutated frames and sealed mgmt commands, watching for panics, traps,
//! stack-guard trips and hangs.
//!
//! Black-box (no coverage feedback); it complements the libFuzzer targets
//! by exercising the VirtIO driver, boot path and kernel glue they cannot
//! reach. Failing inputs are saved and minimised by replaying them on
//! fresh kernels.

use anyhow::{Context, Result, bail};
use clap::Parser;
use qemu_harness::mgmt::MgmtClient;
use qemu_harness::mutate::{mgmt_body, mutate, seed_frame};
use qemu_harness::{Kernel, default_kernel_elf};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

#[derive(Parser, Debug)]
#[command(about = "Fuzz the unikernel end to end under QEMU")]
struct Args {
    /// How long to fuzz, in seconds.
    #[arg(long, default_value_t = 300)]
    duration_secs: u64,
    /// Kernels to fuzz in parallel.
    #[arg(long, default_value_t = 4)]
    jobs: u64,
    /// Base RNG seed; job `i` uses `seed + i`. Random if omitted.
    #[arg(long)]
    seed: Option<u64>,
    /// Where failing inputs are written.
    #[arg(long, default_value = "target/qemu-fuzz")]
    artifacts: PathBuf,
    /// Replay a saved input instead of fuzzing.
    #[arg(long)]
    replay: Option<PathBuf>,
}

/// One step of an input: a raw frame or a mgmt command body that is
/// sealed with the live kernel's epoch when it is sent.
#[derive(Debug, Clone)]
enum Event {
    Frame(Vec<u8>),
    Mgmt(Vec<u8>),
}

/// How a kernel stopped working.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Failure {
    /// Panic, trap or stack-guard trip reported on the serial console.
    Fatal(String),
    /// No ack to a mgmt ping, with nothing on the serial console.
    Hang,
}

/// Events sent between liveness checks.
const BATCH: usize = 64;
/// Events after which a kernel is rebooted to start from fresh state.
const EVENTS_PER_BOOT: usize = 20_000;
/// Time budget for minimising one failure.
const MINIMISE_BUDGET: Duration = Duration::from_secs(300);

fn main() -> Result<()> {
    let args = Args::parse();
    let kernel = default_kernel_elf();
    if let Some(path) = &args.replay {
        let events = load_events(path)?;
        if let Some(failure) = run_events(&kernel, &events)? {
            bail!("reproduced: {failure:?}");
        }
        println!("no failure");
        return Ok(());
    }

    let seed = args.seed.unwrap_or_else(rand::random);
    let deadline = Instant::now() + Duration::from_secs(args.duration_secs);
    println!(
        "qemu-fuzz: {} jobs, seed {seed}, {}s",
        args.jobs, args.duration_secs
    );
    std::fs::create_dir_all(&args.artifacts)?;

    let workers: Vec<_> = (0..args.jobs)
        .map(|job| {
            let kernel = kernel.clone();
            let artifacts = args.artifacts.clone();
            thread::spawn(move || {
                fuzz_worker(job, seed.wrapping_add(job), deadline, &kernel, &artifacts)
            })
        })
        .collect();

    let mut events_sent = 0;
    let mut failures = 0;
    for worker in workers {
        let stats = worker
            .join()
            .map_err(|_| anyhow::anyhow!("fuzz worker panicked"))??;
        events_sent += stats.events;
        failures += stats.failures;
    }
    println!("qemu-fuzz: {events_sent} events, {failures} failures");
    if failures > 0 {
        bail!("{failures} failure(s); see {}", args.artifacts.display());
    }
    Ok(())
}

#[derive(Debug, Default)]
struct WorkerStats {
    events: u64,
    failures: u64,
}

fn fuzz_worker(
    job: u64,
    seed: u64,
    deadline: Instant,
    kernel_elf: &Path,
    artifacts: &Path,
) -> Result<WorkerStats> {
    let mut rng = StdRng::seed_from_u64(seed);
    let mut stats = WorkerStats::default();
    while Instant::now() < deadline {
        let kernel = Kernel::boot(kernel_elf)?;
        let mut mgmt = MgmtClient::connect(&kernel)?;
        let mut history = Vec::new();

        let failure = loop {
            if Instant::now() >= deadline || history.len() >= EVENTS_PER_BOOT {
                break None;
            }
            for _ in 0..BATCH {
                let event = next_event(&mut rng);
                send_event(&kernel, &mut mgmt, &event)?;
                history.push(event);
            }
            stats.events += BATCH as u64;
            kernel.drain()?;
            if let Some(failure) = check(&kernel, &mut mgmt)? {
                break Some(failure);
            }
        };

        if let Some(failure) = failure {
            stats.failures += 1;
            report_failure(
                job, seed, kernel_elf, artifacts, &kernel, &history, &failure,
            )?;
        }
    }
    Ok(stats)
}

fn next_event(rng: &mut StdRng) -> Event {
    match rng.gen_range(0..100) {
        0..10 => Event::Mgmt(mgmt_body(rng)),
        10..15 => {
            let len = rng.gen_range(1..=200);
            Event::Frame((0..len).map(|_| rng.r#gen()).collect())
        }
        _ => {
            let mut frame = seed_frame(rng);
            if rng.gen_bool(0.7) {
                mutate(&mut frame, rng);
            }
            Event::Frame(frame)
        }
    }
}

fn send_event(kernel: &Kernel, mgmt: &mut MgmtClient, event: &Event) -> Result<()> {
    match event {
        Event::Frame(frame) => kernel.send(frame),
        Event::Mgmt(body) => mgmt.send(kernel, body).map(|_| ()),
    }
}

fn check(kernel: &Kernel, mgmt: &mut MgmtClient) -> Result<Option<Failure>> {
    if let Some(report) = kernel.fatal() {
        return Ok(Some(Failure::Fatal(report.0)));
    }
    if mgmt.ping(kernel)? {
        return Ok(None);
    }
    Ok(Some(
        kernel
            .fatal()
            .map_or(Failure::Hang, |report| Failure::Fatal(report.0)),
    ))
}

/// Boots a fresh kernel, sends `events` and reports whether it failed.
fn run_events(kernel_elf: &Path, events: &[Event]) -> Result<Option<Failure>> {
    let kernel = Kernel::boot(kernel_elf)?;
    let mut mgmt = MgmtClient::connect(&kernel)?;
    for chunk in events.chunks(BATCH) {
        for event in chunk {
            send_event(&kernel, &mut mgmt, event)?;
        }
        kernel.drain()?;
        if let Some(report) = kernel.fatal() {
            return Ok(Some(Failure::Fatal(report.0)));
        }
    }
    check(&kernel, &mut mgmt)
}

/// Shrinks `events` while it still reproduces a failure of the same kind,
/// by removing ever smaller chunks.
fn minimise(kernel_elf: &Path, events: Vec<Event>, failure: &Failure) -> Result<Vec<Event>> {
    let started = Instant::now();
    let same_kind = |found: &Option<Failure>| {
        matches!(
            (found, failure),
            (Some(Failure::Fatal(_)), Failure::Fatal(_)) | (Some(Failure::Hang), Failure::Hang)
        )
    };

    if let Some(last) = events.last()
        && same_kind(&run_events(kernel_elf, std::slice::from_ref(last))?)
    {
        return Ok(vec![last.clone()]);
    }

    let mut current = events;
    let mut chunk = current.len() / 2;
    while chunk >= 1 && started.elapsed() < MINIMISE_BUDGET {
        let mut start = 0;
        let mut shrunk = false;
        while start < current.len() && started.elapsed() < MINIMISE_BUDGET {
            let end = (start + chunk).min(current.len());
            let candidate: Vec<Event> = current[..start]
                .iter()
                .chain(&current[end..])
                .cloned()
                .collect();
            if !candidate.is_empty() && same_kind(&run_events(kernel_elf, &candidate)?) {
                current = candidate;
                shrunk = true;
            } else {
                start = end;
            }
        }
        if !shrunk {
            chunk /= 2;
        }
    }
    Ok(current)
}

fn report_failure(
    job: u64,
    seed: u64,
    kernel_elf: &Path,
    artifacts: &Path,
    kernel: &Kernel,
    history: &[Event],
    failure: &Failure,
) -> Result<()> {
    let dir = artifacts.join(format!("job{job}-seed{seed}-{}", history.len()));
    std::fs::create_dir_all(&dir)?;
    std::fs::write(dir.join("serial.txt"), kernel.serial_snapshot())?;
    std::fs::write(dir.join("failure.txt"), format!("{failure:?}\n"))?;
    save_events(&dir.join("events.txt"), history)?;
    eprintln!(
        "qemu-fuzz: job {job} found {failure:?}; minimising {} events",
        history.len()
    );

    let reproduced = run_events(kernel_elf, history)?;
    if reproduced.is_none() {
        eprintln!("qemu-fuzz: job {job}: did not reproduce on a fresh kernel");
        std::fs::write(dir.join("NOT_REPRODUCED"), "")?;
        return Ok(());
    }
    let minimal = minimise(kernel_elf, history.to_vec(), failure)?;
    save_events(&dir.join("minimal.txt"), &minimal)?;
    eprintln!(
        "qemu-fuzz: job {job}: minimised to {} events in {}",
        minimal.len(),
        dir.display()
    );
    Ok(())
}

/// One event per line: `F <hex>` for a frame, `M <hex>` for a mgmt body.
fn save_events(path: &Path, events: &[Event]) -> Result<()> {
    let mut out = String::new();
    for event in events {
        let (tag, bytes) = match event {
            Event::Frame(bytes) => ('F', bytes),
            Event::Mgmt(bytes) => ('M', bytes),
        };
        out.push(tag);
        out.push(' ');
        for byte in bytes {
            write!(out, "{byte:02x}")?;
        }
        out.push('\n');
    }
    std::fs::write(path, out).with_context(|| format!("write {}", path.display()))
}

fn load_events(path: &Path) -> Result<Vec<Event>> {
    let text = std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    text.lines()
        .filter(|line| !line.is_empty())
        .map(|line| {
            let (tag, hex) = line.split_once(' ').context("malformed event line")?;
            let bytes = (0..hex.len())
                .step_by(2)
                .map(|i| {
                    u8::from_str_radix(hex.get(i..i + 2).context("odd hex")?, 16).context("bad hex")
                })
                .collect::<Result<Vec<u8>>>()?;
            match tag {
                "F" => Ok(Event::Frame(bytes)),
                "M" => Ok(Event::Mgmt(bytes)),
                other => bail!("unknown event tag {other:?}"),
            }
        })
        .collect()
}

//! Security Dashboard - Control plane GUI for the security unikernel.
//!
//! This application provides a real-time monitoring and control interface
//! for the security kernel. It displays network statistics, security alerts,
//! and allows dynamic configuration of firewall rules, DPI signatures,
//! and BPF packet filters. Its live network view shows what the security
//! daemon's monitor sees on a real network; `--live` opens that view alone.

// Every egui widget call returns a Response; ignoring most of them is how
// immediate-mode UI code is written.
#![allow(unused_results)]

mod acks;
mod app;
mod live;
/// Per-namespace UDP sender pool for realistic multi-source traffic.
mod netns;
/// Background network task for kernel communication and traffic generation.
mod traffic;
/// Type definitions for statistics, log entries, and GUI commands.
mod types;

use crate::app::AegisApp;
use crate::live::view::LiveView;
use crate::types::{NetStats, UiEvent};
use clap::Parser;
use eframe::egui;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use tokio::sync::mpsc::unbounded_channel;

/// Command-line options.
#[derive(Parser, Debug)]
#[command(about = "Dashboard for the security unikernel and the network monitor")]
struct Cli {
    /// Show only the live network view: no demo kernel listener, traffic
    /// generator or management key, and no special permissions.
    #[arg(long)]
    live: bool,
    /// The monitor's socket [default:
    /// $XDG_RUNTIME_DIR/security-daemon/monitor.sock].
    #[arg(long, value_name = "PATH")]
    socket: Option<PathBuf>,
}

/// Application entry point.
///
/// With `--live`, opens the live network view alone. Otherwise initializes
/// the full dashboard: shared statistics, and the background network task
/// that communicates with the kernel.
#[tokio::main]
async fn main() -> Result<(), eframe::Error> {
    let cli = Cli::parse();
    let socket = match cli.socket.map_or_else(monitor_proto::default_socket_path, Ok) {
        Ok(socket) => socket,
        Err(e) => {
            eprintln!("[gui] cannot find the monitor's socket ({e}); pass --socket");
            std::process::exit(2);
        }
    };
    if cli.live {
        return run_live_only(socket);
    }

    let (event_tx, mut event_rx) = unbounded_channel::<UiEvent>();
    let (cmd_tx, cmd_rx) = unbounded_channel();

    let stats = Arc::new(NetStats {
        passed: AtomicU64::new(0),
        ddos: AtomicU64::new(0),
        fw: AtomicU64::new(0),
        mal: AtomicU64::new(0),
        bpf: AtomicU64::new(0),
        heur: AtomicU64::new(0),
        memory: AtomicU64::new(0),
        flows: AtomicU64::new(0),
        mgmt: AtomicU64::new(0),

        total_passed: AtomicU64::new(0),
        total_dropped: AtomicU64::new(0),

        last_seen: AtomicU64::new(0),
    });

    let stats_clone = stats.clone();
    tokio::spawn(async move {
        if let Err(e) = traffic::start_background_task(stats_clone, event_tx, cmd_rx).await {
            eprintln!("[gui] background task failed: {e}");
            std::process::exit(1);
        }
    });

    let (event_tx_sync, event_rx_sync) = std::sync::mpsc::channel();
    tokio::spawn(async move {
        while let Some(event) = event_rx.recv().await {
            let _ = event_tx_sync.send(event);
        }
    });

    let options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default().with_inner_size([1100.0, 800.0]),
        ..Default::default()
    };

    eframe::run_native(
        "Security Appliance Control Plane",
        options,
        Box::new(|cc| {
            let live = LiveView::new(socket, &cc.egui_ctx);
            Box::new(AegisApp::new(stats, event_rx_sync, cmd_tx, live))
        }),
    )
}

/// The live network view in a window of its own.
struct LiveOnly {
    view: LiveView,
}

impl eframe::App for LiveOnly {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            egui::ScrollArea::vertical().show(ui, |ui| self.view.show(ui));
        });
    }
}

fn run_live_only(socket: PathBuf) -> Result<(), eframe::Error> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([1100.0, 800.0]),
        ..Default::default()
    };
    eframe::run_native(
        "Network Monitor",
        options,
        Box::new(|cc| {
            Box::new(LiveOnly {
                view: LiveView::new(socket, &cc.egui_ctx),
            })
        }),
    )
}

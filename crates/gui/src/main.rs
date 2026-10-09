//! Security Dashboard - Control plane GUI for the security unikernel.
//!
//! This application provides a real-time monitoring and control interface
//! for the security kernel. It displays network statistics, security alerts,
//! and allows dynamic configuration of firewall rules, DPI signatures,
//! and eBPF packet filters.

mod acks;
mod app;
/// Per-namespace UDP sender pool for realistic multi-source traffic.
mod netns;
/// Background network task for kernel communication and traffic generation.
mod traffic;
/// Type definitions for statistics, log entries, and GUI commands.
mod types;

use crate::app::AegisApp;
use crate::types::{NetStats, UiEvent};
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use tokio::sync::mpsc::unbounded_channel;

/// Application entry point.
///
/// Initializes the GUI framework, creates shared statistics structures,
/// and spawns the background network task that communicates with the kernel.
#[tokio::main]
async fn main() -> Result<(), eframe::Error> {
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
        Box::new(|_cc| Box::new(AegisApp::new(stats, event_rx_sync, cmd_tx))),
    )
}

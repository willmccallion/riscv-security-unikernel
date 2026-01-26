//! Security Dashboard - Control plane GUI for the security unikernel.
//!
//! This application provides a real-time monitoring and control interface
//! for the security kernel. It displays network statistics, security alerts,
//! and allows dynamic configuration of firewall rules, DPI signatures,
//! and eBPF packet filters.

mod app;
/// Background network task for kernel communication and traffic generation.
mod traffic;
/// Type definitions for statistics, log entries, and GUI commands.
mod types;

use crate::app::AegisApp;
use crate::types::{LogEntry, NetStats};
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use tokio::sync::mpsc::unbounded_channel;

/// Application entry point.
///
/// Initializes the GUI framework, creates shared statistics structures,
/// and spawns the background network task that communicates with the kernel.
#[tokio::main]
async fn main() -> Result<(), eframe::Error> {
    let (log_tx, mut log_rx) = unbounded_channel::<LogEntry>();
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

        total_passed: AtomicU64::new(0),
        total_dropped: AtomicU64::new(0),

        last_seen: AtomicU64::new(0),
    });

    let stats_clone = stats.clone();
    tokio::spawn(async move {
        traffic::start_background_task(stats_clone, log_tx, cmd_rx).await;
    });

    let (log_tx_sync, log_rx_sync) = std::sync::mpsc::channel();
    tokio::spawn(async move {
        while let Some(msg) = log_rx.recv().await {
            let _ = log_tx_sync.send(msg);
        }
    });

    let options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default().with_inner_size([1100.0, 800.0]),
        ..Default::default()
    };

    eframe::run_native(
        "Security Appliance Control Plane",
        options,
        Box::new(|_cc| Box::new(AegisApp::new(stats, log_rx_sync, cmd_tx))),
    )
}

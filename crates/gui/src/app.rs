//! Main GUI application implementation.
//!
//! This module provides the egui-based user interface for monitoring
//! and controlling the security kernel. It includes real-time statistics
//! visualization, event logging, packet inspection, and configuration
//! interfaces for firewall rules, DPI signatures, and BPF programs.

use crate::live::view::LiveView;
use crate::log::{Description, LogEntry, LogEvent, Source};
use crate::types::{
    CommandId, CommandStatus, GuiCommand, LogMode, NetStats, NotSentReason, StatsSnapshot,
    TrafficMode, UiEvent,
};
use eframe::egui;
use egui_plot::{Line, Plot, PlotPoints};
use sec_core::net::constants::{IpProtocol, ipv4, tcp};
use sec_core::security::dpi::BUILTIN_SIGNATURES;
use sec_core::security::dpi::Pattern;
use sec_core::security::mgmt::Command;
use sec_core::security::mgmt::MgmtOutcome;
use sec_core::security::vm::{Instruction, Opcode, Program};
use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Instant;
use tokio::sync::mpsc::UnboundedSender;

/// Rows the event log keeps before dropping the oldest.
const LOG_CAPACITY: usize = 1000;

/// Points of pass and drop history the plot keeps.
const HISTORY_POINTS: usize = 1000;

/// Available tabs in the main application window.
#[derive(PartialEq)]
enum Tab {
    /// Main dashboard with statistics and event log.
    Dashboard,
    /// Software-defined networking and firewall configuration.
    Sdn,
    /// BPF program editor and compiler.
    Bpf,
    /// What the network monitor sees on the real network.
    LiveNetwork,
}

/// Where a rule shown in the UI came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Origin {
    /// Compiled into the kernel, and not removable at run time.
    Fixed,
    /// Part of the kernel's default configuration, which can be removed.
    Default,
    /// Added by this command.
    Issued(CommandId),
}

/// A rule shown in the UI, with what the kernel said about it.
#[derive(Debug)]
struct Rule<T> {
    item: T,
    origin: Origin,
    status: CommandStatus,
    /// The command removing it, while one is outstanding or failed.
    removal: Option<(CommandId, CommandStatus)>,
}

impl<T> Rule<T> {
    const fn built_in(item: T, origin: Origin) -> Self {
        Self {
            item,
            origin,
            status: CommandStatus::Applied,
            removal: None,
        }
    }

    const fn issued(item: T, command: CommandId, status: CommandStatus) -> Self {
        Self {
            item,
            origin: Origin::Issued(command),
            status,
            removal: None,
        }
    }

    /// Whether the operator may remove it now: it is in force, removable,
    /// and no removal is under way.
    fn can_remove(&self) -> bool {
        self.origin != Origin::Fixed
            && self.status == CommandStatus::Applied
            && self.removal.is_none()
    }

    /// Applies a status update; returns `true` once the rule's removal has
    /// been applied and the row should go.
    fn update(&mut self, id: CommandId, status: CommandStatus) -> bool {
        if self.origin == Origin::Issued(id) {
            self.status = status;
        }
        match &mut self.removal {
            Some((removal, _)) if *removal == id && status == CommandStatus::Applied => true,
            Some((removal, removal_status)) if *removal == id => {
                *removal_status = status;
                false
            }
            _ => false,
        }
    }
}

/// Applies a status update to every rule in `rules`, dropping removed ones.
fn update_rules<T>(rules: &mut Vec<Rule<T>>, id: CommandId, status: CommandStatus) {
    rules.retain_mut(|rule| !rule.update(id, status));
}

/// Main application state and UI implementation.
pub struct Dashboard {
    /// Shared network statistics from the kernel.
    stats: Arc<NetStats>,
    /// Receiver for log entries and command status updates.
    events: std::sync::mpsc::Receiver<UiEvent>,
    /// Log events received while the log is paused.
    held_logs: Vec<LogEvent>,
    /// Id for the next log row.
    next_log_id: u64,
    /// Next id to give a mgmt command.
    next_command: u64,
    /// Sender for commands to the background network task.
    cmd_tx: UnboundedSender<GuiCommand>,

    /// Circular buffer of recent log entries for display.
    logs: VecDeque<LogEntry>,
    /// Historical data points for passed traffic rate graph.
    history_pass: VecDeque<[f64; 2]>,
    /// Historical data points for dropped traffic rate graph.
    history_drop: VecDeque<[f64; 2]>,
    /// Application start time for relative timestamps.
    start_time: Instant,

    /// Currently selected tab in the UI.
    selected_tab: Tab,
    /// Input field for firewall port blocking.
    sdn_port: String,
    /// Input field for DPI signature patterns.
    sdn_sig: String,
    /// Input field for BPF program source code.
    bpf_code: String,
    /// Blocked ports, with the kernel's response to each.
    blocked_ports: Vec<Rule<u16>>,
    /// DPI signatures, with the kernel's response to each.
    dpi_signatures: Vec<Rule<String>>,
    /// Uploaded BPF programs, newest last.
    bpf_programs: Vec<Rule<String>>,

    /// Current log display mode.
    log_mode: LogMode,
    /// Whether the event log is paused (not auto-scrolling).
    log_paused: bool,
    /// Whether a new log entry arrived this frame (used to control scroll).
    log_new_entry: bool,
    /// Currently selected log entry for detailed inspection.
    selected_log: Option<LogEntry>,
    /// The live network view.
    live: LiveView,
}

impl Dashboard {
    /// Creates a new application instance.
    pub fn new(
        stats: Arc<NetStats>,
        events: std::sync::mpsc::Receiver<UiEvent>,
        cmd_tx: UnboundedSender<GuiCommand>,
        live: LiveView,
    ) -> Self {
        Self {
            stats,
            events,
            held_logs: Vec::new(),
            next_log_id: 0,
            next_command: 0,
            cmd_tx,
            logs: VecDeque::with_capacity(LOG_CAPACITY),
            history_pass: VecDeque::new(),
            history_drop: VecDeque::new(),
            start_time: Instant::now(),
            selected_tab: Tab::Dashboard,
            sdn_port: String::new(),
            sdn_sig: String::new(),
            bpf_code: "BLOCK TCP DST 80".to_string(),
            blocked_ports: vec![Rule::built_in(
                sec_core::config::DEFAULT_BLOCKED_PORT,
                Origin::Default,
            )],
            dpi_signatures: BUILTIN_SIGNATURES
                .iter()
                .map(|sig| Rule::built_in(String::from_utf8_lossy(sig).into_owned(), Origin::Fixed))
                .collect(),
            bpf_programs: Vec::new(),
            log_mode: LogMode::Alerts,
            log_paused: false,
            log_new_entry: false,
            selected_log: None,
            live,
        }
    }

    /// Sends a command to the background network task.
    fn send(&self, cmd: GuiCommand) {
        let _ = self.cmd_tx.send(cmd);
    }

    /// Sends a mgmt command and returns the id its status will arrive under.
    fn issue(&mut self, command: &Command) -> CommandId {
        let id = self.next_command_id();
        self.send(GuiCommand::Mgmt {
            id,
            command: Box::new(*command),
        });
        id
    }

    /// [`Self::issue`] for a command built from user input, which is not
    /// sent when the input does not make one; returns its id and status.
    fn issue_if_valid(&mut self, command: Option<&Command>) -> (CommandId, CommandStatus) {
        if let Some(command) = command {
            return (self.issue(command), CommandStatus::Pending);
        }
        let id = self.next_command_id();
        (id, CommandStatus::NotSent(NotSentReason::InvalidCommand))
    }

    const fn next_command_id(&mut self) -> CommandId {
        let id = CommandId(self.next_command);
        self.next_command += 1;
        id
    }

    fn apply_status(&mut self, id: CommandId, status: CommandStatus) {
        update_rules(&mut self.blocked_ports, id, status);
        update_rules(&mut self.dpi_signatures, id, status);
        update_rules(&mut self.bpf_programs, id, status);
    }

    fn drain_events(&mut self) {
        while let Ok(event) = self.events.try_recv() {
            match event {
                UiEvent::Log(entry) => self.held_logs.push(entry),
                UiEvent::CommandStatus { id, status } => self.apply_status(id, status),
            }
        }
        if self.log_paused {
            return;
        }
        for event in std::mem::take(&mut self.held_logs) {
            self.record(event);
        }
    }

    /// Adds this frame's pass and drop rates to the plotted history.
    fn record_history(&mut self) {
        let now = self.start_time.elapsed().as_secs_f64();
        let stats = self.stats.snapshot();
        for (history, rate) in [
            (&mut self.history_pass, stats.passed),
            (&mut self.history_drop, stats.dropped),
        ] {
            if history.len() >= HISTORY_POINTS {
                history.pop_front();
            }
            history.push_back([now, rate as f64]);
        }
    }

    /// Adds `event` to the log as its newest row.
    fn record(&mut self, event: LogEvent) {
        let entry = LogEntry {
            id: self.next_log_id,
            timestamp: self.start_time.elapsed().as_secs_f64(),
            event,
        };
        self.next_log_id += 1;
        if self.logs.len() >= LOG_CAPACITY {
            self.logs.pop_back();
        }
        self.logs.push_front(entry);
        self.log_new_entry = true;
    }

    /// Renders the main dashboard tab.
    ///
    /// Displays network statistics cards, traffic generation controls,
    /// real-time traffic rate graphs, and the security event log.
    fn ui_dashboard(&mut self, ui: &mut egui::Ui) {
        ui.add_space(5.0);
        stats_grid(ui, &self.stats.snapshot());
        ui.add_space(25.0);
        if let Some(mode) = traffic_generator_controls(ui) {
            self.send(GuiCommand::SetMode(mode));
        }
        ui.add_space(15.0);
        traffic_plot(ui, &self.history_pass, &self.history_drop);
        ui.add_space(15.0);
        ui.separator();
        self.log_header(ui);
        self.event_log(ui);
        self.show_inspector(ui.ctx());
    }

    /// The log's title, its filter and its pause button.
    fn log_header(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.label(egui::RichText::new("LIVE EVENT LOG").strong());
            ui.add_space(10.0);
            ui.selectable_value(&mut self.log_mode, LogMode::Alerts, "ALERTS ONLY");
            ui.selectable_value(&mut self.log_mode, LogMode::All, "ALL PACKETS");
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if self.log_paused {
                    if ui.button("RESUME").clicked() {
                        self.log_paused = false;
                    }
                    ui.label(egui::RichText::new("PAUSED").color(egui::Color32::YELLOW));
                } else if ui.button("PAUSE").clicked() {
                    self.log_paused = true;
                }
            });
        });
    }

    /// The log rows, newest at the bottom, following new rows unless
    /// paused; clicking a row selects it.
    fn event_log(&mut self, ui: &mut egui::Ui) {
        let snap = !self.log_paused && self.log_new_entry;
        self.log_new_entry = false;
        egui::ScrollArea::vertical()
            .stick_to_bottom(snap)
            .min_scrolled_height(150.0)
            .show(ui, |ui| {
                for entry in self.logs.iter().rev() {
                    if self.log_mode == LogMode::Alerts && entry.event.is_pass() {
                        continue;
                    }
                    let is_selected = self.selected_log.as_ref().is_some_and(|s| s.id == entry.id);
                    if log_row(ui, entry, is_selected) {
                        self.selected_log = Some(entry.clone());
                    }
                    ui.add_space(2.0);
                }
            });
    }

    /// The packet inspector for the selected row, and any ban it asks for.
    fn show_inspector(&mut self, ctx: &egui::Context) {
        let Some(entry) = &self.selected_log else {
            return;
        };
        let (open, command) = packet_inspector(ctx, entry);
        if !open {
            self.selected_log = None;
        }
        if let Some(command) = command {
            let _ = self.issue(&command);
        }
    }

    /// Renders the SDN and firewall configuration tab: blocked ports on
    /// the left, DPI signatures on the right.
    fn ui_sdn(&mut self, ui: &mut egui::Ui) {
        ui.heading("Firewall & SDN Rules");
        ui.add_space(10.0);
        let (firewall, dpi) = ui.columns(2, |cols| {
            let firewall = rule_column(
                &mut cols[0],
                &FIREWALL_COLUMN,
                &mut self.sdn_port,
                &self.blocked_ports,
                |port| format!("TCP/UDP dst:{port}"),
            );
            let dpi = rule_column(
                &mut cols[1],
                &DPI_COLUMN,
                &mut self.sdn_sig,
                &self.dpi_signatures,
                |sig| format!("\"{sig}\""),
            );
            (firewall, dpi)
        });
        match firewall {
            Some(RuleAction::Add) => self.block_port(),
            Some(RuleAction::Remove(port)) => self.unblock_port(port),
            None => {}
        }
        match dpi {
            Some(RuleAction::Add) => self.add_signature(),
            Some(RuleAction::Remove(sig)) => self.remove_signature(&sig),
            None => {}
        }
    }

    /// Blocks the port typed into the firewall column, if it is one.
    fn block_port(&mut self) {
        let Ok(port) = self.sdn_port.trim().parse::<u16>() else {
            return;
        };
        let command = self.issue(&Command::BlockPort(port));
        self.blocked_ports.retain(|r| r.item != port);
        self.blocked_ports
            .push(Rule::issued(port, command, CommandStatus::Pending));
        self.sdn_port.clear();
    }

    fn unblock_port(&mut self, port: u16) {
        let id = self.issue(&Command::UnblockPort(port));
        if let Some(rule) = self.blocked_ports.iter_mut().find(|r| r.item == port) {
            rule.removal = Some((id, CommandStatus::Pending));
        }
    }

    /// Adds the signature typed into the DPI column; one the kernel would
    /// refuse is listed as not sent.
    fn add_signature(&mut self) {
        if self.sdn_sig.is_empty() {
            return;
        }
        let sig = std::mem::take(&mut self.sdn_sig);
        let add = Pattern::new(sig.as_bytes())
            .ok()
            .map(Command::AddDpiPattern);
        let (command, status) = self.issue_if_valid(add.as_ref());
        self.dpi_signatures.retain(|r| r.item != sig);
        self.dpi_signatures.push(Rule::issued(sig, command, status));
    }

    fn remove_signature(&mut self, sig: &str) {
        let removal = Pattern::new(sig.as_bytes())
            .ok()
            .map(Command::RemoveDpiPattern);
        let removal = self.issue_if_valid(removal.as_ref());
        if let Some(rule) = self.dpi_signatures.iter_mut().find(|r| r.item == sig) {
            rule.removal = Some(removal);
        }
    }

    /// Renders the BPF tab: the program editor on the left, the uploaded
    /// programs on the right.
    fn ui_bpf(&mut self, ui: &mut egui::Ui) {
        ui.heading("BPF Packet Filter");
        ui.label("Inject custom assembly into the packet processing pipeline.");
        ui.add_space(10.0);
        ui.columns(2, |cols| {
            cols[0].group(|ui| self.bpf_editor(ui));
            cols[1].group(|ui| self.bpf_program_list(ui));
        });
    }

    fn bpf_editor(&mut self, ui: &mut egui::Ui) {
        ui.label(egui::RichText::new("Program Editor").strong());
        ui.add_space(5.0);
        ui.horizontal(|ui| {
            if ui.button("Preset: Block TCP Port 80").clicked() {
                self.bpf_code = "BLOCK TCP DST 80".to_string();
            }
            if ui.button("Preset: Block All").clicked() {
                self.bpf_code = "DROP ALL".to_string();
            }
        });
        ui.add_space(5.0);
        ui.add(
            egui::TextEdit::multiline(&mut self.bpf_code)
                .code_editor()
                .desired_rows(6),
        );
        ui.add_space(5.0);
        if ui.button("COMPILE & UPLOAD").clicked() {
            self.upload_bpf();
        }
    }

    /// Compiles the editor's program and uploads it, or logs that it did
    /// not compile.
    fn upload_bpf(&mut self) {
        let Some(program) = compile_bpf(&self.bpf_code) else {
            self.record(LogEvent::CompileFailed);
            return;
        };
        let command = self.issue(&Command::UploadBpf(program));
        let source = self.bpf_code.trim().to_string();
        self.bpf_programs
            .push(Rule::issued(source, command, CommandStatus::Pending));
    }

    fn bpf_program_list(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.label(egui::RichText::new("Uploaded Programs").strong());
            if ui.small_button("unload").clicked() {
                self.unload_bpf();
            }
        });
        ui.add_space(5.0);
        ui.separator();
        ui.add_space(5.0);
        if self.bpf_programs.is_empty() {
            ui.label(egui::RichText::new("No programs loaded").color(egui::Color32::GRAY));
        } else {
            egui::ScrollArea::vertical()
                .id_source("bpf_list")
                .max_height(200.0)
                .show(ui, |ui| {
                    let active = self
                        .bpf_programs
                        .iter()
                        .rposition(|r| r.status == CommandStatus::Applied);
                    for (i, rule) in self.bpf_programs.iter().enumerate() {
                        program_row(ui, i, rule, Some(i) == active);
                    }
                });
        }
        ui.add_space(10.0);
        ui.separator();
        ui.add_space(5.0);
        ui.label(
            egui::RichText::new("Syntax Reference")
                .color(egui::Color32::GRAY)
                .size(11.0),
        );
        ui.monospace("BLOCK <TCP|UDP> DST <port>");
        ui.monospace("DROP ALL");
    }

    /// Unloads the running program, marking the newest applied one as
    /// being removed.
    fn unload_bpf(&mut self) {
        let id = self.issue(&Command::UnloadBpf);
        if let Some(active) = self
            .bpf_programs
            .iter_mut()
            .rfind(|r| r.status == CommandStatus::Applied)
        {
            active.removal = Some((id, CommandStatus::Pending));
        }
    }
}

impl Dashboard {
    /// The title, the connection state and the tab bar.
    fn header(&mut self, ctx: &egui::Context) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let connected = is_connected(self.stats.last_seen.load(Ordering::Relaxed), now);
        egui::TopBottomPanel::top("header").show(ctx, |ui| {
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                ui.heading("Security Appliance Dashboard");
                let (state, color) = if connected {
                    ("ONLINE", egui::Color32::GREEN)
                } else {
                    ("DISCONNECTED", egui::Color32::RED)
                };
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(egui::RichText::new(state).color(color).strong());
                });
            });
            ui.add_space(8.0);
            ui.separator();
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                ui.selectable_value(&mut self.selected_tab, Tab::Dashboard, "DASHBOARD");
                ui.selectable_value(&mut self.selected_tab, Tab::Sdn, "SDN / FIREWALL");
                ui.selectable_value(&mut self.selected_tab, Tab::Bpf, "BPF STUDIO");
                ui.selectable_value(&mut self.selected_tab, Tab::LiveNetwork, "LIVE NETWORK");
            });
            ui.add_space(4.0);
        });
    }
}

/// Whether a kernel last heard from at `last_seen` counts as online at
/// `now`, both in Unix seconds: telemetry arrives every second, so a few
/// missed reports mean it is gone.
const fn is_connected(last_seen: u64, now: u64) -> bool {
    const CONNECTED_WITHIN_SECS: u64 = 3;
    now.saturating_sub(last_seen) < CONNECTED_WITHIN_SECS
}

impl eframe::App for Dashboard {
    /// Main UI update loop called every frame.
    ///
    /// Processes incoming log entries, updates statistics, maintains
    /// historical data for graphs, and renders the appropriate tab UI.
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.drain_events();

        self.record_history();

        ctx.request_repaint();

        self.header(ctx);
        egui::CentralPanel::default().show(ctx, |ui| match self.selected_tab {
            Tab::Dashboard => self.ui_dashboard(ui),
            Tab::Sdn => self.ui_sdn(ui),
            Tab::Bpf => self.ui_bpf(ui),
            Tab::LiveNetwork => {
                egui::ScrollArea::vertical().show(ui, |ui| self.live.show(ui));
            }
        });
    }
}

/// What a stat card shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CardValue {
    /// Packets per second, with a running total when it is not zero.
    Rate { pps: u64, total: u64 },
    /// A plain number.
    Count(u64),
}

/// The row of stat cards above the plot.
fn stats_grid(ui: &mut egui::Ui, stats: &StatsSnapshot) {
    let cards = [
        (
            "THROUGHPUT",
            CardValue::Rate {
                pps: stats.passed + stats.dropped,
                total: stats.total_passed + stats.total_dropped,
            },
            egui::Color32::WHITE,
        ),
        (
            "PASSED TRAFFIC",
            CardValue::Rate {
                pps: stats.passed,
                total: stats.total_passed,
            },
            egui::Color32::GREEN,
        ),
        (
            "MITIGATED ATTACKS",
            CardValue::Rate {
                pps: stats.dropped,
                total: stats.total_dropped,
            },
            egui::Color32::RED,
        ),
        (
            "ACTIVE FLOWS",
            CardValue::Count(stats.flows),
            egui::Color32::LIGHT_BLUE,
        ),
        (
            "MGMT TRAFFIC",
            CardValue::Rate {
                pps: stats.mgmt,
                total: 0,
            },
            egui::Color32::from_rgb(255, 165, 0),
        ),
    ];
    egui::Grid::new("stats_grid")
        .spacing([15.0, 15.0])
        .min_col_width(220.0)
        .show(ui, |ui| {
            for (title, value, color) in cards {
                stat_card(ui, title, value, color);
            }
            ui.end_row();
        });
}

/// One stat card: a title, its value large, and any total small beneath.
fn stat_card(ui: &mut egui::Ui, title: &str, value: CardValue, color: egui::Color32) {
    let (headline, total) = match value {
        CardValue::Rate { pps, total } => (
            format!("{} PPS", format_metric(pps)),
            (total > 0).then(|| format!("Total: {}", format_metric(total))),
        ),
        CardValue::Count(count) => (count.to_string(), None),
    };
    egui::Frame::none()
        .fill(egui::Color32::from_gray(25))
        .rounding(4.0)
        .inner_margin(15.0)
        .stroke(egui::Stroke::new(1.0_f32, egui::Color32::from_gray(45)))
        .show(ui, |ui| {
            ui.vertical_centered(|ui| {
                ui.label(
                    egui::RichText::new(title)
                        .size(12.0)
                        .color(egui::Color32::GRAY),
                );
                ui.add_space(5.0);
                ui.label(
                    egui::RichText::new(headline)
                        .size(24.0)
                        .strong()
                        .color(color),
                );
                if let Some(total) = total {
                    ui.add_space(2.0);
                    ui.label(
                        egui::RichText::new(total)
                            .size(10.0)
                            .color(egui::Color32::from_gray(150)),
                    );
                } else {
                    ui.add_space(14.0);
                }
            });
        });
}

/// The traffic generator's buttons; returns the mode chosen this frame.
fn traffic_generator_controls(ui: &mut egui::Ui) -> Option<TrafficMode> {
    const MODES: [(&str, TrafficMode); 4] = [
        ("STOP", TrafficMode::Idle),
        ("NORMAL (HTTP)", TrafficMode::Normal),
        ("DDoS ATTACK", TrafficMode::DDoS),
        ("LIVE SIMULATION", TrafficMode::Live),
    ];
    let mut chosen = None;
    ui.group(|ui| {
        ui.horizontal(|ui| {
            ui.label(
                egui::RichText::new("TRAFFIC GENERATOR:")
                    .strong()
                    .size(14.0),
            );
            ui.add_space(10.0);
            for (label, mode) in MODES {
                if ui.button(label).clicked() {
                    chosen = Some(mode);
                }
            }
        });
    });
    chosen
}

/// The passed and dropped rates over time.
fn traffic_plot(ui: &mut egui::Ui, passed: &VecDeque<[f64; 2]>, dropped: &VecDeque<[f64; 2]>) {
    let line = |history: &VecDeque<[f64; 2]>, color, name| {
        Line::new(history.iter().copied().collect::<PlotPoints>())
            .color(color)
            .name(name)
    };
    let passed = line(passed, egui::Color32::GREEN, "Passed (PPS)");
    let dropped = line(dropped, egui::Color32::RED, "Dropped (PPS)");
    Plot::new("traffic_plot")
        .height(300.0)
        .show_axes([false, true])
        .show_grid([false, true])
        .legend(egui_plot::Legend::default())
        .show(ui, |plot_ui| {
            plot_ui.line(passed);
            plot_ui.line(dropped);
        });
}

/// Draws one log row; returns whether it was clicked.
fn log_row(ui: &mut egui::Ui, entry: &LogEntry, is_selected: bool) -> bool {
    let Description { tag, detail, color } = entry.event.describe();
    let dst_port = match &entry.event {
        LogEvent::Alert(alert) => alert.meta.dst_port,
        _ => 0,
    };
    let fill = egui::Color32::from_gray(if is_selected { 40 } else { 20 });
    egui::Frame::none()
        .fill(fill)
        .rounding(4.0)
        .inner_margin(egui::Margin {
            left: 0.0,
            right: 8.0,
            top: 4.0,
            bottom: 4.0,
        })
        .stroke(egui::Stroke::new(1.0_f32, egui::Color32::from_gray(35)))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                let (accent, _) =
                    ui.allocate_exact_size(egui::vec2(4.0, 24.0), egui::Sense::hover());
                ui.painter().rect_filled(accent, 2.0, color);
                ui.add_space(6.0);
                egui::Frame::none()
                    .fill(color.gamma_multiply(0.2))
                    .rounding(3.0)
                    .inner_margin(egui::Margin::symmetric(5.0, 1.0))
                    .show(ui, |ui| {
                        ui.label(egui::RichText::new(tag).color(color).strong().size(10.0));
                    });
                ui.add_space(6.0);
                ui.label(
                    egui::RichText::new(detail)
                        .color(egui::Color32::from_gray(210))
                        .size(12.0),
                );
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(
                        egui::RichText::new(format!("T+{:.1}s", entry.timestamp))
                            .color(egui::Color32::from_gray(100))
                            .size(11.0),
                    );
                    if dst_port > 0 {
                        ui.label(
                            egui::RichText::new(format!(":{dst_port}"))
                                .color(egui::Color32::from_gray(140))
                                .size(11.0)
                                .monospace(),
                        );
                    }
                });
            });
        })
        .response
        .interact(egui::Sense::click())
        .clicked()
}

/// Shows the selected row's details in a window; returns whether the window
/// is still open and the ban or unban the operator asked for, if any.
fn packet_inspector(ctx: &egui::Context, entry: &LogEntry) -> (bool, Option<Command>) {
    let mut open = true;
    let mut command = None;
    egui::Window::new("Packet Inspector")
        .open(&mut open)
        .resizable(true)
        .default_width(400.0)
        .show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.heading("Alert Details");
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    command = ban_buttons(ui, entry.event.source());
                });
            });
            ui.add_space(5.0);
            egui::Grid::new("inspector_grid")
                .striped(true)
                .show(ui, |ui| inspector_rows(ui, entry));
        });
    (open, command)
}

/// Ban and unban buttons for an alert's source. Only a single host can be
/// banned from here; unbanning a subnet's network address lifts the ban
/// covering it.
fn ban_buttons(ui: &mut egui::Ui, source: Source) -> Option<Command> {
    let (address, can_ban) = match source {
        Source::Host(ip) => (ip, true),
        Source::Subnet { network, .. } => (network, false),
        Source::Kernel | Source::Local => return None,
    };
    let ban = can_ban
        && ui
            .button(egui::RichText::new("BAN IP").color(egui::Color32::RED))
            .clicked();
    let unban = ui.button("UNBAN").clicked();
    if ban {
        Some(Command::BanIp(address))
    } else if unban {
        Some(Command::UnbanIp(address))
    } else {
        None
    }
}

fn inspector_rows(ui: &mut egui::Ui, entry: &LogEntry) {
    let mut row = |label: &str, value: String| {
        ui.label(label);
        ui.label(value);
        ui.end_row();
    };
    row("Time:", format!("T+{:.2}s", entry.timestamp));
    row("Source:", entry.event.source().to_string());
    if let LogEvent::Alert(alert) = &entry.event {
        let meta = &alert.meta;
        row("Dest IP:", meta.dst_ip.to_string());
        row("Src Port:", meta.src_port.to_string());
        row("Dst Port:", meta.dst_port.to_string());
        row("Protocol:", meta.protocol.to_string());
        row("Packet Len:", format!("{} bytes", meta.packet_len));
        if meta.value != 0 {
            row("Measured:", meta.value.to_string());
        }
    }
    let Description { tag, detail, color } = entry.event.describe();
    ui.label("Reason:");
    ui.colored_label(color, format!("[{tag}] {detail}"));
    ui.end_row();
}

/// One uploaded program: its number, source and whether it is the one
/// running.
fn program_row(ui: &mut egui::Ui, index: usize, rule: &Rule<String>, is_active: bool) {
    ui.horizontal(|ui| {
        ui.colored_label(egui::Color32::LIGHT_BLUE, format!("[{}]", index + 1));
        ui.monospace(&rule.item);
        if rule.removal.is_some() {
            rule_status(ui, rule);
        } else if is_active {
            ui.colored_label(egui::Color32::GREEN, "ACTIVE");
        } else if rule.status == CommandStatus::Applied {
            ui.colored_label(egui::Color32::GRAY, "replaced");
        } else {
            status_badge(ui, rule.status);
        }
    });
}

/// How one of the SDN tab's rule columns is labelled.
struct RuleColumn {
    title: &'static str,
    add_label: &'static str,
    list_id: &'static str,
    badge: &'static str,
    badge_color: egui::Color32,
}

const FIREWALL_COLUMN: RuleColumn = RuleColumn {
    title: "Firewall — Blocked Ports",
    add_label: "BLOCK PORT",
    list_id: "fw_list",
    badge: "BLOCK",
    badge_color: egui::Color32::RED,
};

const DPI_COLUMN: RuleColumn = RuleColumn {
    title: "DPI — Signature Rules",
    add_label: "ADD SIGNATURE",
    list_id: "dpi_list",
    badge: "MATCH",
    badge_color: egui::Color32::from_rgb(255, 140, 0),
};

/// What the operator asked of a rule column this frame.
#[derive(Debug, Clone, PartialEq, Eq)]
enum RuleAction<T> {
    /// Add the rule typed into the column's input.
    Add,
    /// Remove this rule.
    Remove(T),
}

/// A rule column: an input with its add button, then every rule with its
/// status and, where it can go, a remove button.
fn rule_column<T: Clone>(
    ui: &mut egui::Ui,
    column: &RuleColumn,
    input: &mut String,
    rules: &[Rule<T>],
    label: impl Fn(&T) -> String,
) -> Option<RuleAction<T>> {
    let mut action = None;
    ui.group(|ui| {
        ui.label(egui::RichText::new(column.title).strong());
        ui.add_space(5.0);
        ui.horizontal(|ui| {
            ui.text_edit_singleline(input);
            if ui.button(column.add_label).clicked() {
                action = Some(RuleAction::Add);
            }
        });
        ui.add_space(8.0);
        ui.separator();
        ui.add_space(5.0);
        egui::ScrollArea::vertical()
            .id_source(column.list_id)
            .max_height(200.0)
            .show(ui, |ui| {
                for rule in rules {
                    ui.horizontal(|ui| {
                        ui.colored_label(column.badge_color, column.badge);
                        ui.monospace(label(&rule.item));
                        rule_status(ui, rule);
                        if rule.can_remove() && ui.small_button("remove").clicked() {
                            action = Some(RuleAction::Remove(rule.item.clone()));
                        }
                    });
                }
            });
    });
    action
}

/// Shows a rule's status, or its removal's while one is in flight or failed.
fn rule_status<T>(ui: &mut egui::Ui, rule: &Rule<T>) {
    match rule.removal {
        Some((_, CommandStatus::Pending)) => {
            ui.colored_label(egui::Color32::GRAY, "removing");
        }
        Some((_, failed)) => {
            ui.colored_label(egui::Color32::RED, "removal failed:");
            status_badge(ui, failed);
        }
        None => status_badge(ui, rule.status),
    }
}

/// Shows what the kernel said about a rule's command.
fn status_badge(ui: &mut egui::Ui, status: CommandStatus) {
    let orange = egui::Color32::from_rgb(255, 140, 0);
    let (text, color) = match status {
        CommandStatus::Applied => ("applied", egui::Color32::GREEN),
        CommandStatus::Pending => ("pending", egui::Color32::GRAY),
        CommandStatus::Rejected(MgmtOutcome::TableFull) => {
            ("rejected: table full", egui::Color32::RED)
        }
        CommandStatus::Rejected(MgmtOutcome::Refused) => ("refused", egui::Color32::RED),
        CommandStatus::Rejected(MgmtOutcome::Invalid | MgmtOutcome::Applied) => {
            ("rejected: invalid", egui::Color32::RED)
        }
        CommandStatus::NotSent(NotSentReason::InvalidCommand) => {
            ("not sent: invalid command", egui::Color32::RED)
        }
        CommandStatus::NotSent(NotSentReason::KernelNotSeen) => {
            ("not sent: kernel not seen yet", orange)
        }
        CommandStatus::NotSent(NotSentReason::NoReplyAddress) => {
            ("not sent: no local address reaches the kernel", orange)
        }
        CommandStatus::NoAck => ("no ack from kernel", orange),
    };
    ui.colored_label(color, text);
}

/// Formats a numeric value with metric prefixes (k, M).
///
/// Converts large numbers to a more readable format with appropriate
/// suffixes for thousands and millions.
fn format_metric(val: u64) -> String {
    if val >= 1_000_000 {
        format!("{:.1}M", val as f64 / 1_000_000.0)
    } else if val >= 1_000 {
        format!("{:.1}k", val as f64 / 1_000.0)
    } else {
        val.to_string()
    }
}

/// Compiles a simple BPF-style program to bytecode.
///
/// Supports a limited instruction set for packet filtering:
/// - `DROP ALL` - Drops all packets
/// - `BLOCK <TCP|UDP> DST <port>` - Drops packets of that protocol to a
///   destination port, wherever IPv4 options place the transport header.
pub(crate) fn compile_bpf(code: &str) -> Option<Program> {
    const PROTOCOL_OFFSET: u32 = ipv4::PROTOCOL_OFFSET as u32;
    const VERSION_IHL_OFFSET: u32 = ipv4::VERSION_IHL_OFFSET as u32;
    /// The destination port's offset past the IPv4 header; TCP and UDP
    /// share it.
    const DST_PORT_AFTER_IP_HEADER: u32 = (ipv4::HEADER_OFFSET + tcp::DST_PORT_OFFSET) as u32;
    const PASS_INDEX: u32 = 9;
    const DROP_INDEX: u32 = 10;

    if code.trim() == "DROP ALL" {
        return Program::decode(&Instruction::new(Opcode::Ret, 0, 0, 0).to_bytes()).ok();
    }

    let parts: Vec<&str> = code.split_whitespace().collect();
    let [block, protocol, dst, port] = parts.as_slice() else {
        return None;
    };
    if *block != "BLOCK" || *dst != "DST" {
        return None;
    }
    let protocol = match *protocol {
        "TCP" => IpProtocol::Tcp,
        "UDP" => IpProtocol::Udp,
        _ => return None,
    };
    let port = port.parse::<u16>().ok()?;

    let program = [
        Instruction::new(Opcode::Ldb, 0, 0, PROTOCOL_OFFSET).to_bytes(),
        Instruction::new(Opcode::Ldi, 1, 0, protocol as u32).to_bytes(),
        Instruction::new(Opcode::Eq, 0, 1, 0).to_bytes(),
        Instruction::new(Opcode::Jf, 0, 0, PASS_INDEX).to_bytes(),
        Instruction::new(Opcode::Ldmsh, 4, 0, VERSION_IHL_OFFSET).to_bytes(),
        Instruction::new(Opcode::Ldhx, 2, 4, DST_PORT_AFTER_IP_HEADER).to_bytes(),
        Instruction::new(Opcode::Ldi, 3, 0, u32::from(port)).to_bytes(),
        Instruction::new(Opcode::Eq, 2, 3, 0).to_bytes(),
        Instruction::new(Opcode::Jt, 0, 0, DROP_INDEX).to_bytes(),
        Instruction::new(Opcode::Ret, 0, 0, 1).to_bytes(),
        Instruction::new(Opcode::Ret, 0, 0, 0).to_bytes(),
    ];
    Program::decode(&program.concat()).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use sec_core::security::vm::{VmAction, execute};

    fn frame(protocol: IpProtocol, dst_port: u16) -> Vec<u8> {
        frame_with_ip_header_words(protocol, dst_port, 5)
    }

    /// A frame whose IPv4 header is `words` four-byte words long, so any
    /// beyond five are options.
    fn frame_with_ip_header_words(protocol: IpProtocol, dst_port: u16, words: u8) -> Vec<u8> {
        let port_at = 14 + usize::from(words) * 4 + 2;
        let mut f = vec![0u8; port_at + 20];
        f[12] = 0x08;
        f[14] = 0x40 | words;
        f[23] = protocol as u8;
        f[port_at..port_at + 2].copy_from_slice(&dst_port.to_be_bytes());
        f
    }

    fn run(code: &str, packet: &[u8]) -> VmAction {
        let program = compile_bpf(code).expect("compiles to a program the kernel accepts");
        execute(&program, packet).expect("program returns")
    }

    #[test]
    fn block_drops_matching_protocol_and_port() {
        let action = run("BLOCK TCP DST 80", &frame(IpProtocol::Tcp, 80));

        assert_eq!(action, VmAction::Drop);
    }

    #[test]
    fn block_drops_a_matching_port_behind_ip_options() {
        for words in [6, 15] {
            let packet = frame_with_ip_header_words(IpProtocol::Tcp, 80, words);

            let action = run("BLOCK TCP DST 80", &packet);

            assert_eq!(action, VmAction::Drop, "IPv4 header of {words} words");
        }
    }

    #[test]
    fn block_passes_another_port_behind_ip_options() {
        let packet = frame_with_ip_header_words(IpProtocol::Tcp, 443, 6);

        let action = run("BLOCK TCP DST 80", &packet);

        assert_eq!(action, VmAction::Pass);
    }

    #[test]
    fn block_passes_other_ports() {
        let action = run("BLOCK TCP DST 80", &frame(IpProtocol::Tcp, 443));

        assert_eq!(action, VmAction::Pass);
    }

    #[test]
    fn block_passes_other_protocols_on_the_same_port() {
        let action = run("BLOCK TCP DST 80", &frame(IpProtocol::Udp, 80));

        assert_eq!(action, VmAction::Pass);
    }

    #[test]
    fn block_rejects_unknown_protocol_and_out_of_range_port() {
        assert!(compile_bpf("BLOCK ICMP DST 80").is_none());
        assert!(compile_bpf("BLOCK TCP DST 70000").is_none());
    }

    const ADD: CommandId = CommandId(1);
    const REMOVE: CommandId = CommandId(2);
    const OTHER: CommandId = CommandId(3);

    fn applied_rule() -> Rule<u16> {
        let mut rule = Rule::issued(80, ADD, CommandStatus::Pending);
        let _ = rule.update(ADD, CommandStatus::Applied);
        rule
    }

    #[test]
    fn a_rule_takes_the_status_of_the_command_that_added_it() {
        let mut rule = Rule::issued(80, ADD, CommandStatus::Pending);

        let removed = rule.update(ADD, CommandStatus::Rejected(MgmtOutcome::TableFull));

        assert!(!removed);
        assert_eq!(rule.status, CommandStatus::Rejected(MgmtOutcome::TableFull));
    }

    #[test]
    fn a_rule_ignores_other_commands() {
        let mut rule = Rule::issued(80, ADD, CommandStatus::Pending);
        rule.removal = Some((REMOVE, CommandStatus::Pending));

        let removed = rule.update(OTHER, CommandStatus::Applied);

        assert!(!removed);
        assert_eq!(rule.status, CommandStatus::Pending);
        assert_eq!(rule.removal, Some((REMOVE, CommandStatus::Pending)));
    }

    #[test]
    fn an_applied_removal_drops_the_row() {
        let mut rules = vec![
            applied_rule(),
            Rule::issued(443, OTHER, CommandStatus::Pending),
        ];
        rules[0].removal = Some((REMOVE, CommandStatus::Pending));

        update_rules(&mut rules, REMOVE, CommandStatus::Applied);

        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].item, 443);
    }

    #[test]
    fn a_failed_removal_keeps_the_row_and_says_why() {
        let mut rules = vec![applied_rule()];
        rules[0].removal = Some((REMOVE, CommandStatus::Pending));

        update_rules(&mut rules, REMOVE, CommandStatus::NoAck);

        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].removal, Some((REMOVE, CommandStatus::NoAck)));
        assert!(!rules[0].can_remove());
    }

    #[test]
    fn only_applied_rules_not_fixed_in_the_kernel_can_be_removed() {
        let pending = Rule::issued(80, ADD, CommandStatus::Pending);

        assert!(applied_rule().can_remove());
        assert!(Rule::built_in(23, Origin::Default).can_remove());
        assert!(!Rule::built_in(23, Origin::Fixed).can_remove());
        assert!(!pending.can_remove());
    }

    #[test]
    fn the_kernel_is_online_until_three_seconds_pass_without_telemetry() {
        assert!(is_connected(100, 102));
        assert!(!is_connected(100, 103));
        assert!(is_connected(100, 99));
    }

    #[test]
    fn drop_all_drops_everything() {
        let action = run("DROP ALL", &frame(IpProtocol::Udp, 1337));

        assert_eq!(action, VmAction::Drop);
    }
}

//! Main GUI application implementation.
//!
//! This module provides the egui-based user interface for monitoring
//! and controlling the security kernel. It includes real-time statistics
//! visualization, event logging, packet inspection, and configuration
//! interfaces for firewall rules, DPI signatures, and BPF programs.

use crate::live::view::LiveView;
use crate::types::{
    CommandId, CommandStatus, GuiCommand, LogEntry, LogMode, MgmtCommand, NetStats, TrafficMode,
    UiEvent,
};
use sec_core::security::mgmt::MgmtOutcome;
use eframe::egui;
use sec_core::net::constants::IpProtocol;
use sec_core::security::vm::Opcode;
use egui_plot::{Line, Plot, PlotPoints};
use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Instant;
use tokio::sync::mpsc::UnboundedSender;

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

/// A rule shown in the UI, with what the kernel said about it.
struct Rule<T> {
    item: T,
    /// The command that installed it; `None` for rules built into the kernel.
    command: Option<CommandId>,
    status: CommandStatus,
    /// The command removing it, while one is outstanding or failed.
    removal: Option<(CommandId, CommandStatus)>,
}

impl<T> Rule<T> {
    const fn built_in(item: T) -> Self {
        Self {
            item,
            command: None,
            status: CommandStatus::Applied,
            removal: None,
        }
    }

    const fn issued(item: T, command: CommandId) -> Self {
        Self {
            item,
            command: Some(command),
            status: CommandStatus::Pending,
            removal: None,
        }
    }

    /// Applies a status update; returns `true` once the rule's removal has
    /// been applied and the row should go.
    fn update(&mut self, id: CommandId, status: CommandStatus) -> bool {
        if self.command == Some(id) {
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
pub struct AegisApp {
    /// Shared network statistics from the kernel.
    stats: Arc<NetStats>,
    /// Receiver for log entries and command status updates.
    events: std::sync::mpsc::Receiver<UiEvent>,
    /// Log entries received while the log is paused.
    held_logs: Vec<LogEntry>,
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

impl AegisApp {
    /// Creates a new application instance.
    ///
    /// # Arguments
    ///
    /// * `stats` - Shared statistics structure
    /// * `events` - Receiver for log entries and command status updates
    /// * `cmd_tx` - Sender for GUI commands
    /// * `live` - The live network view
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
            next_command: 0,
            cmd_tx,
            logs: VecDeque::with_capacity(1000),
            history_pass: VecDeque::new(),
            history_drop: VecDeque::new(),
            start_time: Instant::now(),
            selected_tab: Tab::Dashboard,
            sdn_port: String::new(),
            sdn_sig: String::new(),
            bpf_code: "BLOCK TCP DST 80".to_string(),
            blocked_ports: vec![Rule::built_in(sec_core::config::DEFAULT_BLOCKED_PORT)],
            dpi_signatures: ["DROP TABLE", "<script>", "eval(", "UNION SELECT"]
                .map(|sig| Rule::built_in(sig.to_string()))
                .into(),
            bpf_programs: Vec::new(),
            log_mode: LogMode::Alerts,
            log_paused: false,
            log_new_entry: false,
            selected_log: None,
            live,
        }
    }

    /// Sends a command to the background network task.
    ///
    /// # Arguments
    ///
    /// * `cmd` - Command to send
    fn send(&self, cmd: GuiCommand) {
        let _ = self.cmd_tx.send(cmd);
    }

    /// Sends a mgmt command and returns the id its status will arrive under.
    fn issue(&mut self, command: MgmtCommand) -> CommandId {
        let id = CommandId(self.next_command);
        self.next_command += 1;
        self.send(GuiCommand::Mgmt { id, command });
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
        for mut entry in self.held_logs.drain(..) {
            entry.timestamp = self.start_time.elapsed().as_secs_f64();
            if self.logs.len() >= 1000 {
                self.logs.pop_back();
            }
            self.logs.push_front(entry);
            self.log_new_entry = true;
        }
    }

    /// Renders the main dashboard tab.
    ///
    /// Displays network statistics cards, traffic generation controls,
    /// real-time traffic rate graphs, and the security event log.
    ///
    /// # Arguments
    ///
    /// * `ui` - egui UI context
    fn ui_dashboard(&mut self, ui: &mut egui::Ui) {
        let pass_pps = self.stats.passed.load(Ordering::Relaxed);
        let ddos_pps = self.stats.ddos.load(Ordering::Relaxed);
        let fw_pps = self.stats.fw.load(Ordering::Relaxed);
        let mal_pps = self.stats.mal.load(Ordering::Relaxed);
        let bpf_pps = self.stats.bpf.load(Ordering::Relaxed);
        let heur_pps = self.stats.heur.load(Ordering::Relaxed);

        let drop_pps = ddos_pps + fw_pps + mal_pps + bpf_pps + heur_pps;
        let total_pps = pass_pps + drop_pps;

        let total_pass_count = self.stats.total_passed.load(Ordering::Relaxed);
        let total_drop_count = self.stats.total_dropped.load(Ordering::Relaxed);
        let total_req_count = total_pass_count + total_drop_count;

        let flows_count = self.stats.flows.load(Ordering::Relaxed);
        let mgmt_pps = self.stats.mgmt.load(Ordering::Relaxed);

        ui.add_space(5.0);

        egui::Grid::new("stats_grid")
            .spacing([15.0, 15.0])
            .min_col_width(220.0)
            .show(ui, |ui| {
                Self::stat_card(
                    ui,
                    "THROUGHPUT",
                    total_pps,
                    total_req_count,
                    egui::Color32::WHITE,
                );
                Self::stat_card(
                    ui,
                    "PASSED TRAFFIC",
                    pass_pps,
                    total_pass_count,
                    egui::Color32::GREEN,
                );
                Self::stat_card(
                    ui,
                    "MITIGATED ATTACKS",
                    drop_pps,
                    total_drop_count,
                    egui::Color32::RED,
                );
                Self::stat_card(
                    ui,
                    "ACTIVE FLOWS",
                    flows_count,
                    0,
                    egui::Color32::LIGHT_BLUE,
                );
                Self::stat_card(
                    ui,
                    "MGMT TRAFFIC",
                    mgmt_pps,
                    0,
                    egui::Color32::from_rgb(255, 165, 0),
                );
                ui.end_row();
            });

        ui.add_space(25.0);

        ui.group(|ui| {
            ui.horizontal(|ui| {
                ui.label(
                    egui::RichText::new("TRAFFIC GENERATOR:")
                        .strong()
                        .size(14.0),
                );
                ui.add_space(10.0);
                if ui.button("STOP").clicked() {
                    self.send(GuiCommand::SetMode(TrafficMode::Idle));
                }
                if ui.button("NORMAL (HTTP)").clicked() {
                    self.send(GuiCommand::SetMode(TrafficMode::Normal));
                }
                if ui.button("DDoS ATTACK").clicked() {
                    self.send(GuiCommand::SetMode(TrafficMode::DDoS));
                }
                if ui.button("LIVE SIMULATION").clicked() {
                    self.send(GuiCommand::SetMode(TrafficMode::Live));
                }
            });
        });

        ui.add_space(15.0);

        let line_pass = Line::new(self.history_pass.iter().copied().collect::<PlotPoints>())
            .color(egui::Color32::GREEN)
            .name("Passed (PPS)");
        let line_drop = Line::new(self.history_drop.iter().copied().collect::<PlotPoints>())
            .color(egui::Color32::RED)
            .name("Dropped (PPS)");

        Plot::new("traffic_plot")
            .height(300.0)
            .show_axes([false, true])
            .show_grid([false, true])
            .legend(egui_plot::Legend::default())
            .show(ui, |plot_ui| {
                plot_ui.line(line_pass);
                plot_ui.line(line_drop);
            });

        ui.add_space(15.0);

        ui.separator();
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

        let snap = !self.log_paused && self.log_new_entry;
        self.log_new_entry = false;
        egui::ScrollArea::vertical()
            .stick_to_bottom(snap)
            .min_scrolled_height(150.0)
            .show(ui, |ui| {
                for entry in self.logs.iter().rev() {
                    if self.log_mode == LogMode::Alerts && entry.msg.starts_with("[PASS]") {
                        continue;
                    }

                    // Parse the tag and description from the message e.g. "[FIREWALL] Blocked..."
                    let (tag, detail) = if let Some(end) = entry.msg.find(']') {
                        (&entry.msg[1..end], entry.msg[end + 2..].trim())
                    } else {
                        ("INFO", entry.msg.as_str())
                    };

                    let is_selected = self.selected_log.as_ref().is_some_and(|s| {
                        s.timestamp.to_bits() == entry.timestamp.to_bits() && s.msg == entry.msg
                    });

                    let bg = if is_selected {
                        egui::Color32::from_gray(40)
                    } else {
                        egui::Color32::from_gray(20)
                    };

                    let clicked = egui::Frame::none()
                        .fill(bg)
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
                                // Colored left accent bar
                                let (rect, _) = ui.allocate_exact_size(
                                    egui::vec2(4.0, 24.0),
                                    egui::Sense::hover(),
                                );
                                ui.painter().rect_filled(rect, 2.0, entry.color);
                                ui.add_space(6.0);

                                // Tag badge
                                egui::Frame::none()
                                    .fill(entry.color.gamma_multiply(0.2))
                                    .rounding(3.0)
                                    .inner_margin(egui::Margin::symmetric(5.0, 1.0))
                                    .show(ui, |ui| {
                                        ui.label(
                                            egui::RichText::new(tag)
                                                .color(entry.color)
                                                .strong()
                                                .size(10.0),
                                        );
                                    });

                                ui.add_space(6.0);

                                // Detail text
                                ui.label(
                                    egui::RichText::new(detail)
                                        .color(egui::Color32::from_gray(210))
                                        .size(12.0),
                                );

                                ui.with_layout(
                                    egui::Layout::right_to_left(egui::Align::Center),
                                    |ui| {
                                        // Timestamp
                                        ui.label(
                                            egui::RichText::new(format!(
                                                "T+{:.1}s",
                                                entry.timestamp
                                            ))
                                            .color(egui::Color32::from_gray(100))
                                            .size(11.0),
                                        );
                                        // Port if nonzero
                                        if entry.dst_port > 0 {
                                            ui.label(
                                                egui::RichText::new(format!(":{}", entry.dst_port))
                                                    .color(egui::Color32::from_gray(140))
                                                    .size(11.0)
                                                    .monospace(),
                                            );
                                        }
                                    },
                                );
                            });
                        })
                        .response
                        .interact(egui::Sense::click())
                        .clicked();

                    if clicked {
                        self.selected_log = Some(entry.clone());
                    }

                    ui.add_space(2.0);
                }
            });

        let mut ban_target = None;
        if let Some(log) = &self.selected_log {
            let mut open = true;
            egui::Window::new("Packet Inspector")
                .open(&mut open)
                .resizable(true)
                .default_width(400.0)
                .show(ui.ctx(), |ui| {
                    ui.horizontal(|ui| {
                        ui.heading("Alert Details");
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            // BAN on a subnet alert would ban only its network address.
                            let (address, is_subnet) = match log.src_ip.split_once('/') {
                                Some((address, _)) => (address, true),
                                None => (log.src_ip.as_str(), false),
                            };
                            if !is_subnet
                                && ui
                                    .button(egui::RichText::new("BAN IP").color(egui::Color32::RED))
                                    .clicked()
                            {
                                ban_target = address.parse().ok().map(MgmtCommand::BanIp);
                            }
                            if ui.button("UNBAN").clicked() {
                                ban_target = address.parse().ok().map(MgmtCommand::UnbanIp);
                            }
                        });
                    });
                    ui.add_space(5.0);

                    egui::Grid::new("inspector_grid")
                        .striped(true)
                        .show(ui, |ui| {
                            ui.label("Time:");
                            ui.label(format!("T+{:.2}s", log.timestamp));
                            ui.end_row();

                            ui.label("Source IP:");
                            ui.label(&log.src_ip);
                            ui.end_row();

                            ui.label("Dest IP:");
                            ui.label(&log.dst_ip);
                            ui.end_row();

                            ui.label("Src Port:");
                            ui.label(format!("{}", log.src_port));
                            ui.end_row();

                            ui.label("Dst Port:");
                            ui.label(format!("{}", log.dst_port));
                            ui.end_row();

                            ui.label("Protocol:");
                            ui.label(format!("{}", log.protocol));
                            ui.end_row();

                            ui.label("Packet Len:");
                            ui.label(format!("{} bytes", log.packet_len));
                            ui.end_row();

                            if let Some(measured) = log.measured {
                                ui.label("Measured:");
                                ui.label(format!("{measured}"));
                                ui.end_row();
                            }

                            ui.label("Reason:");
                            ui.colored_label(log.color, &log.msg);
                            ui.end_row();
                        });
                });

            if !open {
                self.selected_log = None;
            }
        }
        if let Some(command) = ban_target {
            let _ = self.issue(command);
        }
    }

    /// Renders a single statistics card widget.
    ///
    /// Displays a title, current rate value, and total count in a
    /// styled card with colored text for visual distinction.
    ///
    /// # Arguments
    ///
    /// * `ui` - egui UI context
    /// * `title` - Card title text
    /// * `rate` - Current rate value (packets per second or count)
    /// * `total` - Cumulative total count
    /// * `color` - Text color for the rate value
    fn stat_card(
        ui: &mut egui::Ui,
        title: &str,
        rate: u64,
        total: u64,
        color: egui::Color32,
    ) {
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

                    let rate_text = if title == "ACTIVE FLOWS" {
                        format!("{rate}")
                    } else {
                        format!("{} PPS", format_metric(rate))
                    };

                    ui.label(
                        egui::RichText::new(rate_text)
                            .size(24.0)
                            .strong()
                            .color(color),
                    );

                    if total > 0 && title != "ACTIVE FLOWS" {
                        ui.add_space(2.0);
                        let total_text = format!("Total: {}", format_metric(total));
                        ui.label(
                            egui::RichText::new(total_text)
                                .size(10.0)
                                .color(egui::Color32::from_gray(150)),
                        );
                    } else {
                        ui.add_space(14.0);
                    }
                });
            });
    }

    /// Renders the SDN and firewall configuration tab.
    ///
    /// Provides interfaces for:
    /// - Blocking specific destination ports
    /// - Adding DPI signature patterns for deep packet inspection
    ///
    /// # Arguments
    ///
    /// * `ui` - egui UI context
    fn ui_sdn(&mut self, ui: &mut egui::Ui) {
        ui.heading("Firewall & SDN Rules");
        ui.add_space(10.0);

        ui.columns(2, |cols| {
            // Left column: Firewall
            cols[0].group(|ui| {
                ui.label(egui::RichText::new("Firewall — Blocked Ports").strong());
                ui.add_space(5.0);
                ui.horizontal(|ui| {
                    ui.text_edit_singleline(&mut self.sdn_port);
                    if ui.button("BLOCK PORT").clicked()
                        && let Ok(port) = self.sdn_port.trim().parse::<u16>()
                    {
                        let command = self.issue(MgmtCommand::BlockPort(port));
                        self.blocked_ports.retain(|r| r.item != port);
                        self.blocked_ports.push(Rule::issued(port, command));
                        self.sdn_port.clear();
                    }
                });
                ui.add_space(8.0);
                ui.separator();
                ui.add_space(5.0);
                egui::ScrollArea::vertical()
                    .id_source("fw_list")
                    .max_height(200.0)
                    .show(ui, |ui| {
                        let mut unblock = None;
                        for rule in &self.blocked_ports {
                            ui.horizontal(|ui| {
                                ui.colored_label(egui::Color32::RED, "BLOCK");
                                ui.label(format!("TCP/UDP dst:{}", rule.item));
                                rule_status(ui, rule);
                                if rule.status == CommandStatus::Applied
                                    && rule.removal.is_none()
                                    && ui.small_button("remove").clicked()
                                {
                                    unblock = Some(rule.item);
                                }
                            });
                        }
                        if let Some(port) = unblock {
                            let id = self.issue(MgmtCommand::UnblockPort(port));
                            if let Some(rule) = self.blocked_ports.iter_mut().find(|r| r.item == port) {
                                rule.removal = Some((id, CommandStatus::Pending));
                            }
                        }
                    });
            });

            // Right column: DPI signatures
            cols[1].group(|ui| {
                ui.label(egui::RichText::new("DPI — Signature Rules").strong());
                ui.add_space(5.0);
                ui.horizontal(|ui| {
                    ui.text_edit_singleline(&mut self.sdn_sig);
                    if ui.button("ADD SIGNATURE").clicked() && !self.sdn_sig.is_empty() {
                        let sig = std::mem::take(&mut self.sdn_sig);
                        let command = self.issue(MgmtCommand::AddDpiPattern(sig.as_bytes().to_vec()));
                        self.dpi_signatures.retain(|r| r.item != sig);
                        self.dpi_signatures.push(Rule::issued(sig, command));
                        self.sdn_sig.clear();
                    }
                });
                ui.add_space(8.0);
                ui.separator();
                ui.add_space(5.0);
                egui::ScrollArea::vertical()
                    .id_source("dpi_list")
                    .max_height(200.0)
                    .show(ui, |ui| {
                        let mut remove = None;
                        for rule in &self.dpi_signatures {
                            ui.horizontal(|ui| {
                                ui.colored_label(egui::Color32::from_rgb(255, 140, 0), "MATCH");
                                ui.monospace(format!("\"{}\"", rule.item));
                                rule_status(ui, rule);
                                // Built-in signatures live in the kernel's automaton
                                // and cannot be removed at runtime.
                                if rule.command.is_some()
                                    && rule.status == CommandStatus::Applied
                                    && rule.removal.is_none()
                                    && ui.small_button("remove").clicked()
                                {
                                    remove = Some(rule.item.clone());
                                }
                            });
                        }
                        if let Some(sig) = remove {
                            let id = self.issue(MgmtCommand::RemoveDpiPattern(sig.as_bytes().to_vec()));
                            if let Some(rule) = self.dpi_signatures.iter_mut().find(|r| r.item == sig) {
                                rule.removal = Some((id, CommandStatus::Pending));
                            }
                        }
                    });
            });
        });
    }

    /// Renders the BPF program editor tab.
    ///
    /// Allows users to write and compile custom packet filtering programs
    /// that are executed in the kernel's virtual machine for each packet.
    ///
    /// # Arguments
    ///
    /// * `ui` - egui UI context
    fn ui_bpf(&mut self, ui: &mut egui::Ui) {
        ui.heading("BPF Packet Filter");
        ui.label("Inject custom assembly into the packet processing pipeline.");
        ui.add_space(10.0);

        ui.columns(2, |cols| {
            // Left: editor
            cols[0].group(|ui| {
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
                    if let Some(bytecode) = compile_bpf(&self.bpf_code) {
                        let command = self.issue(MgmtCommand::UploadBpf(bytecode));
                        self.bpf_programs
                            .push(Rule::issued(self.bpf_code.trim().to_string(), command));
                    } else {
                        let entry = LogEntry {
                            timestamp: self.start_time.elapsed().as_secs_f64(),
                            src_ip: "Localhost".to_string(),
                            dst_ip: String::new(),
                            src_port: 0,
                            dst_port: 0,
                            protocol: 0,
                            packet_len: 0,
                            measured: None,
                            msg: "BPF: Compilation Failed".to_string(),
                            color: egui::Color32::RED,
                        };
                        self.logs.push_front(entry);
                    }
                }
            });

            // Right: active programs list
            cols[1].group(|ui| {
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("Uploaded Programs").strong());
                    if ui.small_button("unload").clicked() {
                        let id = self.issue(MgmtCommand::UnloadBpf);
                        if let Some(active) = self
                            .bpf_programs
                            .iter_mut()
                            .rfind(|r| r.status == CommandStatus::Applied)
                        {
                            active.removal = Some((id, CommandStatus::Pending));
                        }
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
                                ui.horizontal(|ui| {
                                    ui.colored_label(
                                        egui::Color32::LIGHT_BLUE,
                                        format!("[{}]", i + 1),
                                    );
                                    ui.monospace(&rule.item);
                                    if rule.removal.is_some() {
                                        rule_status(ui, rule);
                                    } else if Some(i) == active {
                                        ui.colored_label(egui::Color32::GREEN, "ACTIVE");
                                    } else if rule.status == CommandStatus::Applied {
                                        ui.colored_label(egui::Color32::GRAY, "replaced");
                                    } else {
                                        status_badge(ui, rule.status);
                                    }
                                });
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
            });
        });
    }
}

impl eframe::App for AegisApp {
    /// Main UI update loop called every frame.
    ///
    /// Processes incoming log entries, updates statistics, maintains
    /// historical data for graphs, and renders the appropriate tab UI.
    ///
    /// # Arguments
    ///
    /// * `ctx` - egui context for rendering
    /// * `_frame` - Application frame (unused)
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.drain_events();

        let now = self.start_time.elapsed().as_secs_f64();
        let pass_rate = self.stats.passed.load(Ordering::Relaxed) as f64;
        let ddos_rate = self.stats.ddos.load(Ordering::Relaxed) as f64;
        let fw_rate = self.stats.fw.load(Ordering::Relaxed) as f64;
        let mal_rate = self.stats.mal.load(Ordering::Relaxed) as f64;
        let bpf_rate = self.stats.bpf.load(Ordering::Relaxed) as f64;
        let heur_rate = self.stats.heur.load(Ordering::Relaxed) as f64;

        let drop_rate = ddos_rate + fw_rate + mal_rate + bpf_rate + heur_rate;

        self.history_pass.push_back([now, pass_rate]);
        self.history_drop.push_back([now, drop_rate]);
        if self.history_pass.len() > 1000 {
            self.history_pass.pop_front();
        }
        if self.history_drop.len() > 1000 {
            self.history_drop.pop_front();
        }

        ctx.request_repaint();

        egui::TopBottomPanel::top("header").show(ctx, |ui| {
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                ui.heading("Security Appliance Dashboard");
                let last = self.stats.last_seen.load(Ordering::Relaxed);
                let sys_now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| d.as_secs());
                let connected = sys_now.saturating_sub(last) < 3;
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if connected {
                        ui.label(
                            egui::RichText::new("ONLINE")
                                .color(egui::Color32::GREEN)
                                .strong(),
                        );
                    } else {
                        ui.label(
                            egui::RichText::new("DISCONNECTED")
                                .color(egui::Color32::RED)
                                .strong(),
                        );
                    }
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
        CommandStatus::Rejected(MgmtOutcome::TableFull) => ("rejected: table full", egui::Color32::RED),
        CommandStatus::Rejected(MgmtOutcome::Refused) => ("refused", egui::Color32::RED),
        CommandStatus::Rejected(MgmtOutcome::Invalid | MgmtOutcome::Applied) => {
            ("rejected: invalid", egui::Color32::RED)
        }
        CommandStatus::NotSent => ("not sent: kernel not seen yet", orange),
        CommandStatus::NoAck => ("no ack from kernel", orange),
    };
    ui.colored_label(color, text);
}

/// Formats a numeric value with metric prefixes (k, M).
///
/// Converts large numbers to a more readable format with appropriate
/// suffixes for thousands and millions.
///
/// # Arguments
///
/// * `val` - Value to format
///
/// # Returns
///
/// Formatted string with metric suffix if applicable.
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
///   destination port. Assumes a 20-byte IPv4 header; the VM has no
///   indirect loads to skip IP options.
///
/// # Arguments
///
/// * `code` - Source code string to compile
///
/// # Returns
///
/// Some bytecode vector if compilation succeeds, None otherwise.
fn compile_bpf(code: &str) -> Option<Vec<u8>> {
    const PROTOCOL_OFFSET: u32 = 23;
    const DST_PORT_OFFSET: u32 = 36;
    const PASS_INDEX: u32 = 8;
    const DROP_INDEX: u32 = 9;

    if code.trim() == "DROP ALL" {
        return Some(encode(Opcode::Ret, 0, 0, 0).to_vec());
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
        encode(Opcode::Ldb, 0, 0, PROTOCOL_OFFSET),
        encode(Opcode::Ldi, 1, 0, protocol as u32),
        encode(Opcode::Eq, 0, 1, 0),
        encode(Opcode::Jf, 0, 0, PASS_INDEX),
        encode(Opcode::Ldh, 2, 0, DST_PORT_OFFSET),
        encode(Opcode::Ldi, 3, 0, u32::from(port)),
        encode(Opcode::Eq, 2, 3, 0),
        encode(Opcode::Jt, 0, 0, DROP_INDEX),
        encode(Opcode::Ret, 0, 0, 1),
        encode(Opcode::Ret, 0, 0, 0),
    ];
    Some(program.concat())
}

/// Encodes one VM instruction in the 7-byte wire format the kernel decodes.
const fn encode(op: Opcode, reg_a: u8, reg_b: u8, imm: u32) -> [u8; 7] {
    let imm = imm.to_be_bytes();
    [op as u8, reg_a, reg_b, imm[0], imm[1], imm[2], imm[3]]
}

#[cfg(test)]
mod tests {
    use super::*;
    use sec_core::security::vm::{Instruction, VM, VmAction, validate};

    fn decode(bytecode: &[u8]) -> Vec<Instruction> {
        let (chunks, rest) = bytecode.as_chunks::<7>();
        assert!(rest.is_empty(), "bytecode is whole instructions");
        chunks
            .iter()
            .map(|c| Instruction::new(c[0], c[1], c[2], u32::from_be_bytes([c[3], c[4], c[5], c[6]])))
            .collect()
    }

    fn frame(protocol: IpProtocol, dst_port: u16) -> Vec<u8> {
        let mut f = vec![0u8; 60];
        f[12] = 0x08;
        f[14] = 0x45;
        f[23] = protocol as u8;
        f[36..38].copy_from_slice(&dst_port.to_be_bytes());
        f
    }

    fn run(code: &str, packet: &[u8]) -> VmAction {
        let program = decode(&compile_bpf(code).expect("compiles"));
        validate(&program).expect("kernel accepts the program");
        VM::new().execute(&program, packet).expect("program returns")
    }

    #[test]
    fn block_drops_matching_protocol_and_port() {
        let action = run("BLOCK TCP DST 80", &frame(IpProtocol::Tcp, 80));

        assert_eq!(action, VmAction::Drop);
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

    #[test]
    fn drop_all_drops_everything() {
        let action = run("DROP ALL", &frame(IpProtocol::Udp, 1337));

        assert_eq!(action, VmAction::Drop);
    }
}

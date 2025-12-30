use crate::types::*;
use eframe::egui;
use egui_plot::{Line, Plot, PlotPoints};
use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Instant;
use tokio::sync::mpsc::UnboundedSender;

#[derive(PartialEq)]
enum Tab {
    Dashboard,
    SDN,
    Ebpf,
}

pub struct AegisApp {
    stats: Arc<NetStats>,
    log_rx: std::sync::mpsc::Receiver<LogEntry>,
    cmd_tx: UnboundedSender<GuiCommand>,

    logs: VecDeque<LogEntry>,
    history_pass: VecDeque<[f64; 2]>,
    history_drop: VecDeque<[f64; 2]>,
    start_time: Instant,

    selected_tab: Tab,
    sdn_port: String,
    sdn_sig: String,
    ebpf_code: String,

    log_paused: bool,
    selected_log: Option<LogEntry>,
}

impl AegisApp {
    pub fn new(
        stats: Arc<NetStats>,
        log_rx: std::sync::mpsc::Receiver<LogEntry>,
        cmd_tx: UnboundedSender<GuiCommand>,
    ) -> Self {
        Self {
            stats,
            log_rx,
            cmd_tx,
            logs: VecDeque::with_capacity(100),
            history_pass: VecDeque::new(),
            history_drop: VecDeque::new(),
            start_time: Instant::now(),
            selected_tab: Tab::Dashboard,
            sdn_port: String::new(),
            sdn_sig: String::new(),
            ebpf_code: "BLOCK TCP DST 80".to_string(),
            log_paused: false,
            selected_log: None,
        }
    }

    fn send(&self, cmd: GuiCommand) {
        let _ = self.cmd_tx.send(cmd);
    }

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

        ui.add_space(5.0);

        egui::Grid::new("stats_grid")
            .spacing([15.0, 15.0])
            .min_col_width(220.0)
            .show(ui, |ui| {
                self.stat_card(
                    ui,
                    "THROUGHPUT",
                    total_pps,
                    total_req_count,
                    egui::Color32::WHITE,
                );
                self.stat_card(
                    ui,
                    "PASSED TRAFFIC",
                    pass_pps,
                    total_pass_count,
                    egui::Color32::GREEN,
                );
                self.stat_card(
                    ui,
                    "MITIGATED ATTACKS",
                    drop_pps,
                    total_drop_count,
                    egui::Color32::RED,
                );
                self.stat_card(
                    ui,
                    "ACTIVE FLOWS",
                    flows_count,
                    0,
                    egui::Color32::LIGHT_BLUE,
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

        let line_pass = Line::new(PlotPoints::from_iter(self.history_pass.iter().cloned()))
            .color(egui::Color32::GREEN)
            .name("Passed (PPS)");
        let line_drop = Line::new(PlotPoints::from_iter(self.history_drop.iter().cloned()))
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

        egui::ScrollArea::vertical()
            .stick_to_bottom(!self.log_paused)
            .min_scrolled_height(150.0)
            .show(ui, |ui| {
                for entry in self.logs.iter().rev() {
                    let text = format!("[T+{:.1}s] {}", entry.timestamp, entry.msg);
                    if ui
                        .selectable_label(false, egui::RichText::new(text).color(entry.color))
                        .clicked()
                    {
                        self.selected_log = Some(entry.clone());
                    }
                }
            });

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
                            if ui
                                .button(egui::RichText::new("BAN IP").color(egui::Color32::RED))
                                .clicked()
                            {
                                self.send(GuiCommand::BanIp(log.src_ip.clone()));
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

                            ui.label("Dst Port:");
                            ui.label(format!("{}", log.dst_port));
                            ui.end_row();

                            ui.label("Reason:");
                            ui.colored_label(log.color, &log.msg);
                            ui.end_row();
                        });

                    ui.add_space(10.0);
                    ui.separator();
                    ui.label("Captured Payload (Hex / ASCII):");

                    egui::ScrollArea::vertical()
                        .max_height(200.0)
                        .show(ui, |ui| {
                            ui.monospace(format!("{:?}", log.payload));
                            ui.add_space(5.0);

                            for (i, chunk) in log.payload.chunks(16).enumerate() {
                                let hex: String =
                                    chunk.iter().map(|b| format!("{:02X} ", b)).collect();
                                let ascii: String = chunk
                                    .iter()
                                    .map(|&b| {
                                        if (32..126).contains(&b) {
                                            b as char
                                        } else {
                                            '.'
                                        }
                                    })
                                    .collect();
                                ui.monospace(format!("{:04X}  {:48}  |{}|", i * 16, hex, ascii));
                            }
                        });
                });

            if !open {
                self.selected_log = None;
            }
        }
    }

    fn stat_card(
        &self,
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
            .stroke(egui::Stroke::new(1.0, egui::Color32::from_gray(45)))
            .show(ui, |ui| {
                ui.vertical_centered(|ui| {
                    ui.label(
                        egui::RichText::new(title)
                            .size(12.0)
                            .color(egui::Color32::GRAY),
                    );
                    ui.add_space(5.0);

                    let rate_text = if title == "ACTIVE FLOWS" {
                        format!("{}", rate)
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

    fn ui_sdn(&mut self, ui: &mut egui::Ui) {
        ui.heading("Firewall & SDN Rules");
        ui.add_space(10.0);

        ui.group(|ui| {
            ui.label("Firewall Rule (Block Port)");
            ui.horizontal(|ui| {
                ui.text_edit_singleline(&mut self.sdn_port);
                if let Ok(port) = self.sdn_port.parse::<u16>()
                    && ui.button("BLOCK PORT").clicked()
                {
                    let mut packet = vec![0x01];
                    packet.extend_from_slice(&port.to_be_bytes());
                    self.send(GuiCommand::SendBytes(packet));

                    let entry = LogEntry {
                        timestamp: self.start_time.elapsed().as_secs_f64(),
                        src_ip: "Localhost".to_string(),
                        msg: format!("SDN: Blocked Port {}", port),
                        payload: vec![],
                        dst_port: 0,
                        color: egui::Color32::YELLOW,
                    };
                    self.logs.push_front(entry);
                }
            });
        });

        ui.add_space(10.0);

        ui.group(|ui| {
            ui.label("DPI Signature (Deep Packet Inspection)");
            ui.horizontal(|ui| {
                ui.text_edit_singleline(&mut self.sdn_sig);
                if ui.button("UPLOAD SIGNATURE").clicked() {
                    let mut packet = vec![0x02];
                    let bytes = self.sdn_sig.as_bytes();
                    packet.push(bytes.len() as u8);
                    packet.extend_from_slice(bytes);
                    self.send(GuiCommand::SendBytes(packet));

                    let entry = LogEntry {
                        timestamp: self.start_time.elapsed().as_secs_f64(),
                        src_ip: "Localhost".to_string(),
                        msg: format!("SDN: Added Sig '{}'", self.sdn_sig),
                        payload: vec![],
                        dst_port: 0,
                        color: egui::Color32::YELLOW,
                    };
                    self.logs.push_front(entry);
                }
            });
        });
    }

    fn ui_ebpf(&mut self, ui: &mut egui::Ui) {
        ui.heading("eBPF Packet Filter");
        ui.label("Inject custom assembly into the packet processing pipeline.");
        ui.add_space(10.0);

        ui.horizontal(|ui| {
            if ui.button("Preset: Block TCP Port 80").clicked() {
                self.ebpf_code = "BLOCK TCP DST 80".to_string();
            }
            if ui.button("Preset: Block All Traffic").clicked() {
                self.ebpf_code = "DROP ALL".to_string();
            }
        });
        ui.add_space(5.0);

        ui.text_edit_multiline(&mut self.ebpf_code);

        if ui.button("COMPILE & UPLOAD").clicked() {
            if let Some(bytecode) = compile_ebpf(&self.ebpf_code) {
                let mut packet = vec![0x03];
                packet.push((bytecode.len() / 7) as u8);
                packet.extend_from_slice(&bytecode);
                self.send(GuiCommand::SendBytes(packet));

                let entry = LogEntry {
                    timestamp: self.start_time.elapsed().as_secs_f64(),
                    src_ip: "Localhost".to_string(),
                    msg: "eBPF: Program Uploaded".to_string(),
                    payload: vec![],
                    dst_port: 0,
                    color: egui::Color32::LIGHT_BLUE,
                };
                self.logs.push_front(entry);
            } else {
                let entry = LogEntry {
                    timestamp: self.start_time.elapsed().as_secs_f64(),
                    src_ip: "Localhost".to_string(),
                    msg: "eBPF: Compilation Failed".to_string(),
                    payload: vec![],
                    dst_port: 0,
                    color: egui::Color32::RED,
                };
                self.logs.push_front(entry);
            }
        }
    }
}

impl eframe::App for AegisApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if !self.log_paused {
            while let Ok(mut msg) = self.log_rx.try_recv() {
                if self.logs.len() >= 100 {
                    self.logs.pop_back();
                }
                msg.timestamp = self.start_time.elapsed().as_secs_f64();
                self.logs.push_front(msg);
            }
        }

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
                    .unwrap()
                    .as_secs();
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
                ui.selectable_value(&mut self.selected_tab, Tab::SDN, "SDN / FIREWALL");
                ui.selectable_value(&mut self.selected_tab, Tab::Ebpf, "eBPF STUDIO");
            });
            ui.add_space(4.0);
        });

        egui::CentralPanel::default().show(ctx, |ui| match self.selected_tab {
            Tab::Dashboard => self.ui_dashboard(ui),
            Tab::SDN => self.ui_sdn(ui),
            Tab::Ebpf => self.ui_ebpf(ui),
        });
    }
}

fn format_metric(val: u64) -> String {
    if val >= 1_000_000 {
        format!("{:.1}M", val as f64 / 1_000_000.0)
    } else if val >= 1_000 {
        format!("{:.1}k", val as f64 / 1_000.0)
    } else {
        val.to_string()
    }
}

fn compile_ebpf(code: &str) -> Option<Vec<u8>> {
    if code.trim() == "DROP ALL" {
        let mut buf = Vec::new();
        buf.extend_from_slice(&[0x0D, 0, 0]);
        buf.extend_from_slice(&0u32.to_be_bytes());
        return Some(buf);
    }

    let parts: Vec<&str> = code.split_whitespace().collect();
    if parts.len() >= 4
        && parts[0] == "BLOCK"
        && parts[2] == "DST"
        && let Ok(port) = parts[3].parse::<u32>()
    {
        let mut buf = Vec::new();
        buf.extend_from_slice(&[0x02, 0, 0]);
        buf.extend_from_slice(&36u32.to_be_bytes());
        buf.extend_from_slice(&[0x06, 0, 0]);
        buf.extend_from_slice(&port.to_be_bytes());
        buf.extend_from_slice(&[0x0B, 0, 0]);
        buf.extend_from_slice(&4u32.to_be_bytes());
        buf.extend_from_slice(&[0x0D, 0, 0]);
        buf.extend_from_slice(&1u32.to_be_bytes());
        buf.extend_from_slice(&[0x0D, 0, 0]);
        buf.extend_from_slice(&0u32.to_be_bytes());
        return Some(buf);
    }
    None
}

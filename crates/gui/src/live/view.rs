//! Drawing the live network view.

use super::format;
use super::link::{self, LinkEvent};
use super::model::{HostRow, LiveNetwork, Window};
use eframe::egui;
use egui_plot::{GridMark, Legend, Line, Plot, PlotPoints};
use monitor_proto::{Locality, NameSource};
use std::net::IpAddr;
use std::ops::RangeInclusive;
use std::path::PathBuf;
use std::sync::mpsc::Receiver;

/// Seconds of throughput the chart shows.
const CHART_SECONDS: f64 = 300.0;
/// Rows shown in each host list.
const HOST_ROWS: usize = 40;

/// Where the connection to the monitor stands.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Status {
    /// Trying for the first time.
    Connecting,
    /// Receiving summaries.
    Connected,
    /// Not connected, and why.
    Disconnected(String),
}

/// The live network view and its connection to the monitor.
pub struct LiveView {
    socket: PathBuf,
    events: Receiver<LinkEvent>,
    network: LiveNetwork,
    status: Status,
    window: Window,
    selected: Option<IpAddr>,
}

impl LiveView {
    /// Starts reading the monitor at `socket`, redrawing `ctx` as data
    /// arrives.
    pub fn new(socket: PathBuf, ctx: &egui::Context) -> Self {
        let repaint = ctx.clone();
        let events = link::spawn(socket.clone(), move || repaint.request_repaint());
        Self {
            socket,
            events,
            network: LiveNetwork::default(),
            status: Status::Connecting,
            window: Window::default(),
            selected: None,
        }
    }

    fn drain_events(&mut self) {
        while let Ok(event) = self.events.try_recv() {
            match event {
                LinkEvent::Connected(hello) => {
                    self.network.connected(hello);
                    self.status = Status::Connected;
                }
                LinkEvent::Summary(summary) => self.network.add(summary),
                LinkEvent::Disconnected(why) => self.status = Status::Disconnected(why),
            }
        }
    }

    /// Draws the view.
    pub fn show(&mut self, ui: &mut egui::Ui) {
        self.drain_events();
        self.show_status(ui);
        ui.add_space(6.0);
        self.show_rates(ui);
        ui.add_space(6.0);
        self.show_chart(ui);
        ui.add_space(6.0);
        ui.horizontal(|ui| {
            ui.label("Totals over the last");
            for window in Window::ALL {
                ui.selectable_value(&mut self.window, window, window.label());
            }
        });
        ui.add_space(4.0);
        ui.columns(2, |columns| {
            self.show_hosts(&mut columns[0], "Internet", Locality::Remote, ("from it", "to it"));
            self.show_hosts(&mut columns[1], "Your network", Locality::Local, ("sent", "received"));
        });
        if self.selected.is_some() {
            ui.separator();
            self.show_selected(ui);
        }
    }

    fn show_status(&self, ui: &mut egui::Ui) {
        match &self.status {
            Status::Connected => {
                let watched = self.network.hello().map_or_else(String::new, |h| h.interfaces.join(", "));
                ui.colored_label(egui::Color32::GREEN, format!("Watching {watched}"));
            }
            Status::Connecting => {
                ui.colored_label(egui::Color32::GRAY, format!("Connecting to {}", self.socket.display()));
            }
            Status::Disconnected(why) => {
                ui.colored_label(egui::Color32::RED, why);
                ui.label("Start the monitor with --serve, for example:");
                ui.code("security-daemon monitor --iface enp4s0 --serve");
            }
        }
    }

    fn show_rates(&self, ui: &mut egui::Ui) {
        let Some(latest) = self.network.latest() else {
            ui.label("No traffic summaries yet.");
            return;
        };
        let seconds = latest.length_ms.max(1) as f64 / 1000.0;
        let rate = |bytes: u64| format::bits_per_second(bytes as f64 * 8.0 / seconds);
        let totals = &latest.totals;
        let ip_bytes = totals.inbound.bytes + totals.outbound.bytes + totals.internal.bytes + totals.transit.bytes;
        let ipv6_share = if ip_bytes == 0 { 0.0 } else { 100.0 * totals.ipv6.bytes as f64 / ip_bytes as f64 };
        ui.horizontal(|ui| {
            stat(ui, "Internet in", &rate(totals.inbound.bytes));
            stat(ui, "Internet out", &rate(totals.outbound.bytes));
            stat(ui, "Local", &rate(totals.internal.bytes));
            stat(ui, "Connections", &latest.active_flows.to_string());
            stat(ui, "IPv6", &format!("{ipv6_share:.0}%"));
        });
        if latest.untracked > 0 {
            ui.colored_label(
                egui::Color32::YELLOW,
                format!("{} packets could not be followed: the monitor's tables are full", latest.untracked),
            );
        }
    }

    fn show_chart(&self, ui: &mut egui::Ui) {
        let points = self.network.throughput();
        let now = points.last().map_or(0.0, |p| p.at_secs);
        let recent: Vec<_> = points.iter().filter(|p| now - p.at_secs <= CHART_SECONDS).collect();
        let series = |pick: fn(&super::model::Throughput) -> f64| -> PlotPoints {
            recent.iter().map(|p| [p.at_secs - now, pick(p)]).collect::<Vec<[f64; 2]>>().into()
        };
        Plot::new("live_throughput")
            .height(200.0)
            .legend(Legend::default())
            .include_x(-CHART_SECONDS)
            .include_x(0.0)
            .include_y(0.0)
            .allow_drag(false)
            .allow_zoom(false)
            .allow_scroll(false)
            .x_axis_formatter(|mark: GridMark, _, _: &RangeInclusive<f64>| format!("{:.0} s", mark.value))
            .y_axis_formatter(|mark: GridMark, _, _: &RangeInclusive<f64>| format::bits_per_second(mark.value))
            .label_formatter(|name, point| format!("{name}\n{}", format::bits_per_second(point.y)))
            .show(ui, |plot| {
                plot.line(Line::new(series(|p| p.inbound_bps)).name("Internet in"));
                plot.line(Line::new(series(|p| p.outbound_bps)).name("Internet out"));
                plot.line(Line::new(series(|p| p.local_bps)).name("Local"));
            });
    }

    fn show_hosts(&mut self, ui: &mut egui::Ui, title: &str, locality: Locality, headings: (&str, &str)) {
        let rows = self.network.hosts(self.window, locality);
        let seconds = self.window.seconds() as f64;
        ui.heading(format!("{title} ({})", rows.len()));
        egui::ScrollArea::vertical().id_source(title).max_height(260.0).show(ui, |ui| {
            egui::Grid::new(title).striped(true).num_columns(4).show(ui, |ui| {
                ui.strong("Host");
                ui.strong(headings.0);
                ui.strong(headings.1);
                ui.strong("total");
                ui.end_row();
                for row in rows.iter().take(HOST_ROWS) {
                    let is_selected = self.selected == Some(row.addr);
                    if ui.selectable_label(is_selected, host_label(row)).clicked() {
                        self.selected = if is_selected { None } else { Some(row.addr) };
                    }
                    ui.label(format::bits_per_second(row.sent_bytes as f64 * 8.0 / seconds));
                    ui.label(format::bits_per_second(row.received_bytes as f64 * 8.0 / seconds));
                    ui.label(format::bytes(row.total_bytes()));
                    ui.end_row();
                }
            });
        });
    }

    fn show_selected(&self, ui: &mut egui::Ui) {
        let Some(addr) = self.selected else { return };
        if let Some(name) = self.network.name(addr) {
            ui.heading(&name.name);
            ui.label(format!("{addr}, named from {}", describe(name.source)));
        } else {
            ui.heading(addr.to_string());
            ui.label("No name seen yet: names come from DNS answers and handshakes when connections open.");
        }
        let history = self.network.host_history(addr);
        let now = history.last().map_or(0.0, |&(at, _, _)| at);
        let sent: Vec<[f64; 2]> = history.iter().map(|&(at, sent, _)| [at - now, sent as f64 * 8.0]).collect();
        let received: Vec<[f64; 2]> = history.iter().map(|&(at, _, received)| [at - now, received as f64 * 8.0]).collect();
        Plot::new("live_host")
            .height(140.0)
            .legend(Legend::default())
            .include_y(0.0)
            .allow_drag(false)
            .allow_zoom(false)
            .allow_scroll(false)
            .x_axis_formatter(|mark: GridMark, _, _: &RangeInclusive<f64>| format!("{:.0} s", mark.value))
            .y_axis_formatter(|mark: GridMark, _, _: &RangeInclusive<f64>| format::bits_per_second(mark.value))
            .show(ui, |plot| {
                plot.line(Line::new(PlotPoints::from(sent)).name("sent"));
                plot.line(Line::new(PlotPoints::from(received)).name("received"));
            });
    }
}

fn stat(ui: &mut egui::Ui, label: &str, value: &str) {
    ui.group(|ui| {
        ui.vertical(|ui| {
            ui.small(label);
            ui.strong(value);
        });
    });
}

fn host_label(row: &HostRow) -> String {
    match &row.name {
        Some(name) if name.source == NameSource::TlsCoverName => format!("{} (cover name)", name.name),
        Some(name) => name.name.clone(),
        None => row.addr.to_string(),
    }
}

const fn describe(source: NameSource) -> &'static str {
    match source {
        NameSource::TlsServerName => "the site name a client asked it for (TLS or QUIC)",
        NameSource::Dns => "a DNS answer",
        NameSource::Mdns => "its own mDNS announcement",
        NameSource::TlsCoverName => "an Encrypted Client Hello's shared cover name, not the real site",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use monitor_proto::{Counter, Hello, Host, HostName, PROTOCOL_VERSION, Summary, Totals};
    use std::sync::mpsc::channel;

    fn summary(second: u64) -> Summary {
        let host = |addr: &str, locality, name: Option<&str>| Host {
            addr: addr.parse().unwrap(),
            locality,
            name: name.map(|n| HostName {
                name: n.into(),
                source: NameSource::TlsServerName,
            }),
            sent: Counter { packets: 10, bytes: 9_000 },
            received: Counter { packets: 8, bytes: 700 },
            flows_opened: 1,
            flows_accepted: 0,
        };
        Summary {
            start_unix_ms: second * 1000,
            length_ms: 1000,
            totals: Totals {
                inbound: Counter { packets: 10, bytes: 9_000 },
                outbound: Counter { packets: 8, bytes: 700 },
                ipv6: Counter { packets: 4, bytes: 3_000 },
                ..Totals::default()
            },
            hosts: vec![
                host("2606:4700::1", Locality::Remote, Some("www.cloudflare.com")),
                host("192.168.1.86", Locality::Local, None),
            ],
            hosts_omitted: 0,
            active_flows: 12,
            untracked: 3,
        }
    }

    /// Lays out `view` in a headless frame, as a window would draw it.
    fn draw(view: &mut LiveView) {
        let ctx = egui::Context::default();
        for _ in 0..2 {
            let _ = ctx.run(egui::RawInput::default(), |ctx| {
                egui::CentralPanel::default().show(ctx, |ui| view.show(ui));
            });
        }
    }

    fn view_with(events: Vec<LinkEvent>) -> LiveView {
        let (sender, receiver) = channel();
        for event in events {
            sender.send(event).unwrap();
        }
        LiveView {
            socket: PathBuf::from("/nonexistent/monitor.sock"),
            events: receiver,
            network: LiveNetwork::default(),
            status: Status::Connecting,
            window: Window::default(),
            selected: None,
        }
    }

    #[test]
    fn draws_a_connected_view_with_traffic_and_a_selected_host() {
        let hello = Hello {
            protocol: PROTOCOL_VERSION,
            interfaces: vec!["enp4s0".into(), "tailscale0".into()],
            local_networks: vec![],
            interval_ms: 1000,
        };
        let mut events = vec![LinkEvent::Connected(hello)];
        events.extend((100..160).map(|s| LinkEvent::Summary(summary(s))));
        let mut view = view_with(events);
        view.selected = Some("2606:4700::1".parse().unwrap());

        draw(&mut view);

        assert_eq!(view.status, Status::Connected);
        assert_eq!(view.network.hosts(Window::OneMinute, Locality::Remote).len(), 1);
    }

    #[test]
    fn draws_a_disconnected_view_with_no_data() {
        let mut view = view_with(vec![LinkEvent::Disconnected("cannot reach the monitor".into())]);
        view.selected = Some("10.0.0.1".parse().unwrap());

        draw(&mut view);

        assert!(matches!(view.status, Status::Disconnected(_)));
    }
}

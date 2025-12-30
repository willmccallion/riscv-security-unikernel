use eframe::egui;
use std::sync::atomic::AtomicU64;

pub const MGMT_ADDR: &str = "192.168.100.2:1337";
pub const TARGET_ADDR: &str = "192.168.100.2:80";
pub const LISTEN_ADDR: &str = "0.0.0.0:8888";

#[derive(Clone, Debug)]
pub struct LogEntry {
    pub timestamp: f64,
    pub src_ip: String,
    pub msg: String,
    pub payload: Vec<u8>,
    pub dst_port: u16,
    pub color: egui::Color32,
}

pub struct NetStats {
    pub passed: AtomicU64,
    pub ddos: AtomicU64,
    pub fw: AtomicU64,
    pub mal: AtomicU64,
    pub bpf: AtomicU64,
    pub heur: AtomicU64,
    pub memory: AtomicU64,
    pub flows: AtomicU64, // Added

    pub total_passed: AtomicU64,
    pub total_dropped: AtomicU64,

    pub last_seen: AtomicU64,
}

#[derive(Clone, Copy, PartialEq)]
pub enum TrafficMode {
    Idle,
    Normal,
    DDoS,
    Live,
}

pub enum GuiCommand {
    SetMode(TrafficMode),
    SendBytes(Vec<u8>),
    BanIp(String),
}

//! Security subsystem modules.
//!
//! This module provides all security mechanisms including DDoS mitigation,
//! deep packet inspection, firewall rules, flow tracking, heuristic analysis,
//! and a virtual machine for executing custom packet filters.

/// Security alert reason codes and constants.
pub mod alert;
/// Change detection over per-interval measurements.
pub mod anomaly;
/// DDoS mitigation: the penalty box and token bucket.
pub mod dos;
/// Deep packet inspection engine using Aho-Corasick pattern matching.
pub mod dpi;
/// Firewall state management for port-based access control.
pub mod firewall;
/// Network flow tracking and connection state management.
pub mod flow;
/// Hand-rolled SipHash-2-4 keyed hash, shared by mgmt-auth and SYN cookies.
pub mod hash;
/// Heuristic-based anomaly detection for protocol and payload analysis.
pub mod heuristic;
/// Heuristic detection constants for TCP flags and payload patterns.
pub mod heuristic_constants;
/// Management interface message types and constants.
pub mod mgmt;
/// Authenticated wire format for management-plane commands.
pub mod mgmt_auth;
/// Authenticated wire format for kernel-to-operator reports.
pub mod report_auth;
/// Probabilistic stream summaries used for heavy-hitter detection.
pub mod sketch;
/// Virtual machine for executing eBPF-like packet filter programs.
pub mod vm;

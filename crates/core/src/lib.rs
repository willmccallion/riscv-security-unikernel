//! Shared `no_std` security-engine logic.
//!
//! This crate holds the pure-logic modules used by both the RISC-V
//! unikernel (`security-unikernel`) and the host-side Linux daemon
//! (`security-daemon`). It contains no platform-specific code, no
//! allocator, no panic handler, and no I/O — only algorithms, protocol
//! parsing, and constant definitions.
//!
//! ## Modules
//!
//! - [`engine`] — the per-packet pipeline tying every subsystem together.
//! - [`security`] — DDoS mitigation, DPI, firewall, flow tracking,
//!   heuristics, eBPF VM, and mgmt-protocol constants.
//! - [`net`] — Ethernet/IPv4/ARP/ICMP/TCP packet processing. The stack
//!   is generic over a [`net::PacketSink`] trait so callers supply their
//!   own send path (VirtIO on the kernel, AF_XDP/nfqueue on the daemon).
//! - [`time`] — [`time::TimeSource`] trait abstracting the cycle / wall-
//!   clock counter. The kernel implements it via the RISC-V `mcycle`
//!   CSR; the daemon via `CLOCK_MONOTONIC`.
//! - [`config`] — shared threshold and protocol constants.
//! - [`types`] — small utilities (currently the `Singleton` pattern).

#![no_std]

pub mod config;
pub mod engine;
pub mod net;
pub mod security;
pub mod time;
pub mod types;

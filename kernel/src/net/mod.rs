//! Network protocol stack implementation.
//!
//! This module provides network protocol processing including Ethernet,
//! IPv4, ARP, ICMP, and TCP handling. It processes incoming packets
//! and extracts payload data for security inspection.

/// Network protocol constants and packet layout definitions.
pub mod constants;
/// Network protocol stack for packet processing and protocol handling.
pub mod stack;
/// TCP header definitions and utilities for SYN cookie generation.
pub mod tcp;

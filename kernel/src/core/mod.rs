//! Core kernel infrastructure modules.
//!
//! This module provides fundamental kernel services including memory
//! allocation, panic handling, and type definitions for global state.

pub mod allocator;
/// Panic handler implementation for kernel error reporting and recovery.
pub mod panic;
/// Type definitions for global state management including Singleton pattern.
pub mod types;

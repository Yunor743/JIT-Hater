//! # JIT-Hater
//!
//! Behavioral memory-threat detection for Linux. Watches process memory
//! activity (via /proc scanning today, eBPF telemetry in progress) and dumps
//! suspicious memory regions to a restricted tmpfs directory for later
//! antivirus scanning.
//!
//! Library entry points:
//! - [`Config`]: YAML configuration (defaults to tmpfs dump dir)
//! - [`RuleEngine`]: modular detection rules ("dump reasons")
//! - [`Scanner`]: structural /proc scanner (one-shot)
//! - [`Dumper`]: restricted memory dumper with dedup + quotas
//! - [`run::scan_once`], [`run::run_service`]: high-level runners
//!
//! Designed to be embeddable in other Rust security tools (e.g. an EDR that
//! wants in-memory threat detection without shipping a full engine).

pub mod cli;
pub mod config;
pub mod dumper;
pub mod error;
pub mod monitor;
pub mod rules;
pub mod run;
pub mod scanner;

pub use config::{Config, Granularity};
pub use dumper::Dumper;
pub use error::{Error, Result};
pub use rules::{DetectionRule, RuleEngine, RuleOutput};
pub use scanner::Scanner;

// Re-exports from the common crate for a single-stop API.
pub use jit_hater_common::{
    DetectionEvent, DumpReason, Finding, RegionSnapshot, Severity, SyscallEvent,
};

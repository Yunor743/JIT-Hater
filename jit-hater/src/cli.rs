//! Command-line interface.

use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};


use crate::config::Granularity;

/// Options that CLI arguments can override in the config.
#[derive(Debug, Default, Clone)]
pub struct CliOptions {
    /// Dump directory override (`--dump-dir`).
    pub dump_dir: Option<PathBuf>,
    /// Dump granularity override (`--granularity`).
    pub granularity: Option<Granularity>,
    /// Fluctuation threshold override (`--fluctuation-threshold`).
    pub fluctuation_threshold: Option<u32>,
    /// Polling interval override (`--poll-interval`).
    pub poll_interval: Option<u64>,
    /// Log format override (`--log-format`).
    pub log_format: Option<String>,
    /// Tracing filter override (`--log-filter`).
    pub log_filter: Option<String>,
    /// Rules disabled via `--disable-rule` (repeatable).
    pub disable_rules: Vec<String>,
}

/// JIT-Hater — behavioral memory threat detector for Linux.
#[derive(Debug, Parser)]
#[command(
    name = "jit-hater",
    version,
    about = "Watch process memory activity and dump suspicious regions",
    after_help = "Run with --help on each subcommand for details."
)]
pub struct Cli {
    /// YAML config file.
    #[arg(short, long, global = true)]
    pub config: Option<PathBuf>,

    /// Dump directory override.
    #[arg(long, global = true, value_name = "DIR")]
    pub dump_dir: Option<PathBuf>,

    /// Dump granularity override.
    #[arg(long, global = true, value_enum)]
    pub granularity: Option<GranularityArg>,

    /// Fluctuation threshold override (exec transitions per page).
    #[arg(long, global = true, value_name = "N")]
    pub fluctuation_threshold: Option<u32>,

    /// Polling interval override (seconds, fallback mode).
    #[arg(long, global = true, value_name = "SECS")]
    pub poll_interval: Option<u64>,

    /// Log format override: json or human.
    #[arg(long, global = true, value_name = "FORMAT")]
    pub log_format: Option<String>,

    /// tracing filter override (e.g. "debug", "jit_hater=trace").
    #[arg(long, global = true, value_name = "FILTER")]
    pub log_filter: Option<String>,

    /// Disable rules by slug (repeatable).
    #[arg(long, global = true, value_name = "SLUG")]
    pub disable_rule: Vec<String>,

    /// Subcommand to run (scan, monitor, rules, status).
    #[command(subcommand)]
    pub command: Command,
}

/// Argument mirror of `Granularity` for clap.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum GranularityArg {
    /// Dump the 4KiB page where the activity was observed.
    Page,
    /// Dump the whole VMA (capped).
    Vma,
}

impl From<GranularityArg> for Granularity {
    fn from(v: GranularityArg) -> Self {
        match v {
            GranularityArg::Page => Granularity::Page,
            GranularityArg::Vma => Granularity::Vma,
        }
    }
}

/// Available commands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// One-shot structural scan of all (or selected) processes.
    Scan {
        /// Restrict the scan to this PID (repeatable).
        #[arg(short, long)]
        pid: Vec<i32>,
        /// Do not dump, only report findings on stdout.
        #[arg(long)]
        dry_run: bool,
    },
    /// Live monitor: watch memory activity (eBPF, with /proc polling fallback).
    Monitor {
        /// Force /proc polling mode even if eBPF is available.
        #[arg(long)]
        force_polling: bool,
        /// One-shot monitor run used by tests: exits after N seconds.
        #[arg(long, hide = true, value_name = "SECS")]
        auto_exit_secs: Option<u64>,
    },
    /// List detection rules and their slugs.
    Rules,
    /// Check dump directory state (size, files, dedup cache).
    Status,
}

impl Cli {
    /// Extract the CLI-overridable options.
    pub fn options(&self) -> CliOptions {
        CliOptions {
            dump_dir: self.dump_dir.clone(),
            granularity: self.granularity.map(Granularity::from),
            fluctuation_threshold: self.fluctuation_threshold,
            poll_interval: self.poll_interval,
            log_format: self.log_format.clone(),
            log_filter: self.log_filter.clone(),
            disable_rules: self.disable_rule.clone(),
        }
    }
}

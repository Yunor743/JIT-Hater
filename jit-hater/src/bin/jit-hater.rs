//! JIT-Hater CLI entry point.

use std::collections::HashSet;

use anyhow::{Context, Result};
use clap::Parser;

use jit_hater::cli::{Cli, Command};

use jit_hater::run::{self, OutputMode};

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Config: file > defaults, then CLI overrides.
    let mut config = match &cli.config {
        Some(path) => jit_hater::Config::load(path)
            .with_context(|| format!("loading config {}", path.display()))?,
        None => jit_hater::Config::default(),
    };
    config.apply_cli_overrides(&cli.options());

    // Logging init (stdout, JSON lines or human).
    let fmt = config.log.format.as_str();
    let filter = config.log.filter.as_str();
    if fmt == "human" {
        tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::try_new(filter).unwrap_or_default())
            .init();
    } else {
        tracing_subscriber::fmt()
            .json()
            .with_env_filter(tracing_subscriber::EnvFilter::try_new(filter).unwrap_or_default())
            .init();
    }

    // Reject non-tmpfs dump dirs early with a clear, actionable error.
    if let Err(e) = jit_hater::dumper::ensure_tmpfs(&config.dump.directory) {
        tracing::warn!(
            "dump directory is NOT on tmpfs: {e}\nDumps may contain secrets (browsers, keepassxc). \
             Prefer /dev/shm/jit-hater or set `dump.directory` in your config."
        );
    }

    match &cli.command {
        Command::Scan { pid, dry_run } => {
            let pids = if pid.is_empty() {
                None
            } else {
                Some(pid.iter().copied().collect::<HashSet<i32>>())
            };
            let n = run::scan_once(config, pids, *dry_run, OutputMode::Json)?;
            println!(r#"{{"event":"scan_complete","dumped":{n}}}"#);
        }
        Command::Monitor {
            force_polling,
            auto_exit_secs,
        } => {
            if *force_polling {
                config.monitor.prefer_ebpf = false;
            }
            run::run_service(config, OutputMode::Json, *auto_exit_secs)?;
        }
        Command::Rules => {
            for reason in jit_hater::DumpReason::ALL {
                let enabled = config.rule_enabled(reason.slug());
                println!(
                    "{}",
                    serde_json::json!({
                        "slug": reason.slug(),
                        "enabled": enabled,
                    })
                );
            }
        }
        Command::Status => {
            let dir = &config.dump.directory;
            let mut files = 0u64;
            let mut bytes = 0u64;
            if let Ok(entries) = std::fs::read_dir(dir) {
                for e in entries.flatten() {
                    if e.file_name().to_string_lossy().ends_with(".dump") {
                        files += 1;
                        bytes += e.metadata().map(|m| m.len()).unwrap_or(0);
                    }
                }
            }
            println!(
                "{}",
                serde_json::json!({
                    "dump_dir": dir.display().to_string(),
                    "exists": dir.exists(),
                    "files": files,
                    "bytes": bytes,
                    "tmpfs": jit_hater::dumper::ensure_tmpfs(dir).is_ok(),
                })
            );
        }
    }
    Ok(())
}

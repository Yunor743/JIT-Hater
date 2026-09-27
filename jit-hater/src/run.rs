//! High-level runners: one-shot scan and continuous service mode.

use std::collections::HashSet;

use anyhow::Result;
use jit_hater_common::events::EventSource;
use tracing::{info, warn};

use crate::config::Config;
use crate::dumper::Dumper;
use crate::monitor;
use crate::rules::RuleEngine;
use crate::scanner::Scanner;

/// Output format for findings on stdout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputMode {
    /// JSON lines (default; machine-consumable, SIEM-friendly).
    Json,
    /// Human-readable lines for terminal use.
    Human,
}

/// One-shot structural scan of all processes (or a fixed PID set).
pub fn scan_once(
    config: Config,
    pids: Option<HashSet<i32>>,
    dry_run: bool,
    output: OutputMode,
) -> Result<usize> {
    let mut engine = RuleEngine::with_defaults(config.clone());
    let scanner = Scanner::new(config.clone(), pids);
    let mut dumper = if dry_run {
        None
    } else {
        Some(Dumper::new(config.clone())?)
    };

    let findings = scanner.run_once(&mut engine)?;
    let mut dumped = 0usize;

    for out in &findings {
        match output {
            OutputMode::Json => {
                println!(
                    "{}",
                    serde_json::json!({
                        "event": "finding",
                        "source": "scanner",
                        "pid": out.finding.pid,
                        "reason": out.finding.reason.slug(),
                        "detail": out.finding.detail,
                        "region": out.finding.region.as_ref().map(|r| serde_json::json!({
                            "start": format!("{:#x}", r.start),
                            "end": format!("{:#x}", r.end),
                            "perms": r.perms_string(),
                            "pathname": r.pathname,
                        })),
                    })
                );
            }
            OutputMode::Human => {
                let region = out
                    .finding
                    .region
                    .as_ref()
                    .map(|r| format!(" {}-{} {}", r.start, r.end, r.perms_string()))
                    .unwrap_or_default();
                println!(
                    "[{}] pid={} {}{} :: {}",
                    out.finding.reason, out.finding.pid, out.rule, region, out.finding.detail
                );
            }
        }

        if let Some(dumper) = dumper.as_mut() {
            let finding = out.finding.clone();
            match dumper.dump(&finding) {
                Ok(Some(ev)) => {
                    dumped += 1;
                    let _ = EventSource::Scanner; // source already encoded in ev
                    let _ = ev;
                }
                Ok(None) => {}
                Err(e) => warn!(pid = out.finding.pid, error = %e, "dump failed"),
            }
        }
    }

    info!(findings = findings.len(), dumped, "scan complete");
    Ok(dumped)
}

/// Continuous service mode: structural scan every `scanner.interval_secs`
/// (when > 0) plus the live monitor (eBPF when available, polling fallback).
pub fn run_service(config: Config, _output: OutputMode, stop: Option<u64>) -> Result<()> {
    info!("service mode starting");
    let engine = std::sync::Arc::new(std::sync::Mutex::new(RuleEngine::with_defaults(
        config.clone(),
    )));

    // Live monitor in a worker thread (polling implementation for now;
    // eBPF integration is staged in jit-hater-ebpf later).
    let monitor_handle = {
        let config = config.clone();
        let engine = engine.clone();
        std::thread::spawn(move || {
            monitor::poll_loop(&config, &engine, stop)
        })
    };

    // Periodic structural scanner on the main thread.
    let interval = config.scanner.interval_secs;
    if interval > 0 {
        let mut dumper = Dumper::new(config.clone())?;
        loop {
            let mut engine = engine.lock().unwrap();
            let scanner = crate::scanner::Scanner::new(config.clone(), None);
            match scanner.run_once(&mut engine) {
                Ok(findings) => {
                    for out in findings {
                        if let Ok(Some(_ev)) = dumper.dump(&out.finding) {
                            let _ = EventSource::Scanner;
                        }
                    }
                }
                Err(e) => warn!(error = %e, "scan pass failed"),
            }
            drop(engine);
            if let Some(secs) = stop {
                std::thread::sleep(std::time::Duration::from_secs(secs.min(interval.max(1))));
                break;
            }
            std::thread::sleep(std::time::Duration::from_secs(interval));
        }
    } else {
        monitor_handle
            .join()
            .map_err(|_| anyhow::anyhow!("monitor thread panicked"))?;
    }
    info!("service mode stopping");
    Ok(())
}

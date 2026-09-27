//! Live monitoring: watches memory activity of running processes.
//!
//! v1 implementation: /proc polling with per-process state; the eBPF LSM
//! probes (jit-hater-ebpf) replace this hot path when the kernel supports
//! them, sharing the same rule engine interface.

use std::time::{Duration, Instant};

use jit_hater_common::events::{DetectionEvent, SyscallEvent};
use jit_hater_common::memory::{PROT_EXEC, PROT_WRITE};
use tracing::info;
use jit_hater_common::RegionSnapshot;

use crate::config::Config;
use crate::scanner::{list_processes, read_maps};

/// Previously seen executable-state per (pid, page) to emulate transition
/// tracking in polling mode (approximation of eBPF prev_prot).
#[derive(Default)]
struct PollState {
    /// (pid, page_base) -> page is currently executable.
    exec_pages: std::collections::HashMap<(i32, u64), bool>,
}

impl PollState {
    /// Track exec-state of pages; returns transitions as (page, now_exec).
    fn observe(&mut self, pid: i32, region: &RegionSnapshot) -> Vec<(u64, bool)> {
        let page = 4096u64;
        let mut transitions = Vec::new();
        let mut cursor = region.start & !(page - 1);
        while cursor < region.end {
            let now_exec = region.is_exec();
            let key = (pid, cursor);
            if let Some(prev) = self.exec_pages.get(&key) {
                if *prev != now_exec {
                    transitions.push((cursor, now_exec));
                }
            }
            self.exec_pages.insert(key, now_exec);
            cursor += page;
            if transitions.len() > 64 {
                break;
            }
        }
        transitions
    }

    fn prune(&mut self, alive: &std::collections::HashSet<i32>) {
        self.exec_pages.retain(|(pid, _), _| alive.contains(pid));
    }
}

/// Polling monitor loop. `stop_secs` bounds the run (tests / auto-exit).
pub fn poll_loop(
    config: &Config,
    engine: &std::sync::Arc<std::sync::Mutex<crate::rules::RuleEngine>>,
    stop_secs: Option<u64>,
    dumper: &mut crate::dumper::Dumper,
) {
    let interval = Duration::from_secs(config.monitor.poll_interval_secs.max(1));
    let mut state = PollState::default();
    let started = Instant::now();
    info!(
        interval_secs = config.monitor.poll_interval_secs,
        "polling monitor started (no eBPF)"
    );
    loop {
        if let Ok(procs) = list_processes() {
            let alive: std::collections::HashSet<i32> = procs.iter().map(|p| p.pid).collect();
            for proc in &procs {
                let Ok(maps) = read_maps(proc.pid) else {
                    continue;
                };
                let mut engine = engine.lock().unwrap();
                for region in &maps {
                    let ev = DetectionEvent::Region {
                        pid: proc.pid,
                        starttime: proc.starttime,
                        region: region.clone(),
                    };
                    for out in engine.evaluate(&ev) {
                        handle_finding(dumper, &out.finding);
                    }
                    // Emulated transitions feed the fluctuation rule in
                    // polling mode (approximation; eBPF gives exact events).
                    for (page, now_exec) in state.observe(proc.pid, region) {
                        let ev = DetectionEvent::Syscall {
                            pid: proc.pid,
                            starttime: proc.starttime,
                            syscall: SyscallEvent::Mprotect,
                            addr: page,
                            len: 4096,
                            prot: if now_exec { 0x1 | PROT_EXEC } else { 0x1 },
                            prev_prot: Some(if now_exec {
                                0x1 | PROT_WRITE
                            } else {
                                0x1 | PROT_EXEC
                            }),
                            path: None,
                        };
                        for out in engine.evaluate(&ev) {
                            handle_finding(dumper, &out.finding);
                        }
                    }
                }
                drop(engine);
            }
            state.prune(&alive);
        }

        if let Some(secs) = stop_secs {
            if started.elapsed() >= Duration::from_secs(secs) {
                return;
            }
        }
        std::thread::sleep(interval);
    }
}

/// Handle one finding: dump to disk (logged via tracing on stdout) and
/// report the finding line on stdout. Dump failures are logged but do not
/// suppress the finding report.
pub fn handle_finding(dumper: &mut crate::dumper::Dumper, finding: &jit_hater_common::Finding) {
    match dumper.dump(finding) {
        Ok(Some(_)) => {} // dump already logged
        Ok(None) => report_finding(finding),
        Err(e) => {
            tracing::warn!(pid = finding.pid, reason = %finding.reason, error = %e, "dump failed");
            report_finding(finding);
        }
    }
}

/// Log one finding to stdout as JSON.
pub fn report_finding(finding: &jit_hater_common::Finding) {
    println!(
        "{}",
        serde_json::json!({
            "event": "finding",
            "source": "monitor",
            "pid": finding.pid,
            "reason": finding.reason.slug(),
            "detail": finding.detail,
        })
    );
}

//! /proc structural scanner.
//!
//! Enumerates all processes (or a selected subset), parses their maps
//! (+ smaps when needed), and emits `Region` events into the rule engine.

use std::collections::HashSet;

use anyhow::Result;
use jit_hater_common::events::{DetectionEvent, SyscallEvent};
use jit_hater_common::RegionSnapshot;
use tracing::debug;

use crate::config::Config;


/// Result of enumerating a process: pid + process start time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessId {
    pub pid: i32,
    pub starttime: Option<u64>,
}

/// Read /proc/<pid>/maps as parsed regions.
pub fn read_maps(pid: i32) -> Result<Vec<RegionSnapshot>> {
    let path = format!("/proc/{pid}/maps");
    let content = std::fs::read_to_string(&path)
        .map_err(|e| crate::error::Error::ProcRead(path.clone(), e))?;
    Ok(content
        .lines()
        .filter_map(RegionSnapshot::parse_line)
        .collect())
}

/// Read the process start time (field 22 of /proc/<pid>/stat, clock ticks
/// since boot) — used as identity salt against PID reuse.
pub fn read_starttime(pid: i32) -> Option<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // comm may contain spaces and parentheses: take the part after the last ')'
    let after_comm = stat.rsplit(')').next()?;
    let fields: Vec<&str> = after_comm.split_whitespace().collect();
    // after ')': field 3 onward; starttime is field 22 => index 22 - 3 = 19
    fields.get(19)?.parse().ok()
}

/// Read the process comm name.
pub fn read_comm(pid: i32) -> Option<String> {
    let raw = std::fs::read_to_string(format!("/proc/{pid}/comm")).ok()?;
    Some(raw.trim_end_matches('\n').to_string())
}

/// Enumerate all visible processes.
pub fn list_processes() -> Result<Vec<ProcessId>> {
    let mut out = Vec::new();
    let entries = std::fs::read_dir("/proc")
        .map_err(|e| crate::error::Error::ProcRead("/proc".into(), e))?;
    for entry in entries {
        let entry = entry.map_err(|e| crate::error::Error::ProcRead("/proc".into(), e))?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if let Ok(pid) = name.parse::<i32>() {
            out.push(ProcessId {
                pid,
                starttime: read_starttime(pid),
            });
        }
    }
    Ok(out)
}

/// The structural scanner: walks processes and feeds regions to the engine.
pub struct Scanner {
    config: Config,
    pids: Option<HashSet<i32>>,
}

impl Scanner {
    /// Build a scanner over all processes (None) or a fixed set (Some).
    pub fn new(config: Config, pids: Option<HashSet<i32>>) -> Self {
        Self { config, pids }
    }

    /// Run one pass, return all findings produced by the engine.
    /// Emits synthetic syscall events for special path observations so the
    /// same rule set applies across monitor and scanner sources.
    pub fn run_once(&self, engine: &mut crate::rules::RuleEngine) -> Result<Vec<crate::rules::RuleOutput>> {
        let mut outputs = Vec::new();
        let processes = match &self.pids {
            Some(pids) => pids
                .iter()
                .map(|p| ProcessId {
                    pid: *p,
                    starttime: read_starttime(*p),
                })
                .collect(),
            None => list_processes()?,
        };

        for proc in processes_ignoring(&processes, &self.config) {
            let maps = match read_maps(proc.pid) {
                Ok(m) => m,
                Err(e) => {
                    let not_accessible = e
                        .downcast_ref::<crate::error::Error>()
                        .map(|je| {
                            matches!(
                                je.io_kind(),
                                std::io::ErrorKind::NotFound | std::io::ErrorKind::PermissionDenied
                            )
                        })
                        .unwrap_or(false);
                    if !not_accessible {
                        return Err(e);
                    }
                    debug!(pid = proc.pid, error = %e, "skipping unreadable process");
                    continue;
                }
            };

            for region in maps {
                // Synthesize the syscall-flavored events the path-based rules
                // expect (memfd presence, deleted backing, secretmem hint is
                // not visible in maps, handled by monitor path).
                if region.is_memfd() {
                    let ev = DetectionEvent::Syscall {
                        pid: proc.pid,
                        starttime: proc.starttime,
                        syscall: SyscallEvent::MemfdCreate,
                        addr: region.start,
                        len: region.len(),
                        prot: region.prot,
                        prev_prot: None,
                        path: Some(region.pathname.clone()),
                    };
                    outputs.extend(engine.evaluate(&ev));
                }
                if region.is_deleted() && region.is_exec() {
                    let ev = DetectionEvent::Syscall {
                        pid: proc.pid,
                        starttime: proc.starttime,
                        syscall: SyscallEvent::Execveat,
                        addr: region.start,
                        len: region.len(),
                        prot: region.prot,
                        prev_prot: None,
                        path: Some(region.pathname.clone()),
                    };
                    outputs.extend(engine.evaluate(&ev));
                }

                let ev = DetectionEvent::Region {
                    pid: proc.pid,
                    starttime: proc.starttime,
                    region: region.clone(),
                };
                outputs.extend(engine.evaluate(&ev));
            }
        }
        Ok(outputs)
    }
}

fn processes_ignoring<'a>(
    procs: &'a [ProcessId],
    config: &'a Config,
) -> impl Iterator<Item = &'a ProcessId> + 'a {
    procs.iter().filter(move |p| {
        let comm = read_comm(p.pid).unwrap_or_default();
        config.process_allowed(&comm)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn own_process_maps_parse() {
        let pid = std::process::id() as i32;
        let maps = read_maps(pid).unwrap();
        assert!(!maps.is_empty());
        assert!(maps.iter().any(|r| r.is_exec()));
        assert!(maps.iter().any(|r| r.pathname.contains("jit-hater")
            || r.pathname.contains("ld-linux")
            || r.pathname.contains("libc")));
    }

    #[test]
    fn starttime_of_self_is_some() {
        let pid = std::process::id() as i32;
        assert!(read_starttime(pid).is_some());
    }
}

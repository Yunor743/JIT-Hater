//! YAML configuration for JIT-Hater.
//!
//! Precedence: CLI overrides > YAML config file > built-in defaults.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// Top-level configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// Where memory dumps are written. Defaults to a tmpfs directory.
    #[serde(default)]
    pub dump: DumpConfig,
    /// Live monitor settings (eBPF + fallback polling).
    #[serde(default)]
    pub monitor: MonitorConfig,
    /// Structural scanner settings (one-shot and periodic).
    #[serde(default)]
    pub scanner: ScannerConfig,
    /// Per-rule enable/ignore configuration.
    #[serde(default)]
    pub rules: RulesConfig,
    /// Logging configuration.
    #[serde(default)]
    pub log: LogConfig,
}

/// Dump directory + quotas + dedup.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DumpConfig {
    /// Dump directory. Defaults to /dev/shm/jit-hater (tmpfs, mode 0700).
    pub directory: PathBuf,
    /// Dump granularity: single page or whole VMA (capped).
    #[serde(default)]
    pub granularity: Granularity,
    /// Max bytes per dump (applies to VMA granularity).
    pub max_dump_size: u64,
    /// Stop writing dumps after this many files in one session (0 = unlimited).
    pub max_files: u64,
    /// Total size cap for the dump directory (0 = unlimited).
    pub max_dir_size: u64,
    /// Dedup: identical (rule, content hash) dumps are skipped within this TTL.
    pub dedup_ttl_secs: u64,
}

impl Default for DumpConfig {
    fn default() -> Self {
        Self {
            directory: PathBuf::from("/dev/shm/jit-hater"),
            granularity: Granularity::Page,
            max_dump_size: 16 * 1024 * 1024,
            max_files: 10_000,
            max_dir_size: 512 * 1024 * 1024,
            dedup_ttl_secs: 3600,
        }
    }
}

/// What gets written to disk on a detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Granularity {
    /// Only the 4KiB page containing the suspicious activity (default).
    #[default]
    Page,
    /// The whole VMA, capped at `max_dump_size`.
    Vma,
}

/// Live monitor (eBPF with /proc polling fallback).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct MonitorConfig {
    /// Enable the live monitor (service mode default).
    pub enabled: bool,
    /// Prefer eBPF probes when the kernel supports them.
    pub prefer_ebpf: bool,
    /// Polling interval when eBPF is unavailable or disabled.
    pub poll_interval_secs: u64,
    /// Fluctuation threshold: executable transitions per page before dump.
    pub fluctuation_threshold: u32,
    /// Ignore self (avoid recursive dumps of our own monitor process).
    pub ignore_self: bool,
    /// Only watch processes owned by these UIDs (empty = all).
    pub watch_uids: Vec<u32>,
}

impl Default for MonitorConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            prefer_ebpf: true,
            poll_interval_secs: 5,
            fluctuation_threshold: 5,
            ignore_self: true,
            watch_uids: vec![],
        }
    }
}

/// Structural scanner.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ScannerConfig {
    /// Run a structural scan this many seconds (0 = only explicit one-shot).
    pub interval_secs: u64,
    /// Skip these executable paths during structural scans (GLOB-ish match on
    /// exact path or comm name, prefix compare).
    pub ignore_processes: Vec<String>,
    /// Cap on how many bytes of a file-backed region we hash for integrity.
    pub text_hash_cap: u64,
}

impl Default for ScannerConfig {
    fn default() -> Self {
        Self {
            interval_secs: 0,
            ignore_processes: vec![
                "gdb".into(),
                "strace".into(),
                "jit-hater".into(),
                "rustinel".into(),
                "kunai".into(),
                "tracee".into(),
            ],
            text_hash_cap: 0, // 0 = disabled (text integrity needs tuning, P2)
        }
    }
}

/// Rule enable/disable and per-rule ignores.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RulesConfig {
    /// Rules explicitly disabled (by slug).
    pub disabled: Vec<String>,
    /// Extra JIT-ish processes tolerated by the fluctuation rule.
    pub jit_allowlist: Vec<String>,
    /// Fully ignore findings for these process names (comm).
    pub process_allowlist: Vec<String>,
}

/// Logging.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LogConfig {
    /// "json" or "human".
    pub format: String,
    /// tracing filter (e.g. "info", "debug", "jit_hater=debug").
    pub filter: String,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            format: "json".into(),
            filter: "info".into(),
        }
    }
}

impl Config {
    /// Load config from a YAML file path.
    pub fn load(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("reading config file {}", path.display()))?;
        let cfg: Config = serde_yaml::from_str(&content)
            .with_context(|| format!("parsing YAML config {}", path.display()))?;
        Ok(cfg)
    }

    /// Apply CLI overrides on top of a loaded config.
    pub fn apply_cli_overrides(&mut self, opts: &crate::cli::CliOptions) {
        if let Some(dir) = &opts.dump_dir {
            self.dump.directory = dir.clone();
        }
        if let Some(g) = opts.granularity {
            self.dump.granularity = g;
        }
        if let Some(t) = opts.fluctuation_threshold {
            self.monitor.fluctuation_threshold = t;
        }
        if let Some(i) = opts.poll_interval {
            self.monitor.poll_interval_secs = i;
        }
        if let Some(f) = &opts.log_format {
            self.log.format = f.clone();
        }
        if let Some(f) = &opts.log_filter {
            self.log.filter = f.clone();
        }
        if !opts.disable_rules.is_empty() {
            self.rules.disabled.extend(opts.disable_rules.iter().cloned());
        }
    }

    /// Whether a rule slug is enabled.
    pub fn rule_enabled(&self, slug: &str) -> bool {
        !self.rules.disabled.iter().any(|d| d == slug)
    }

    /// Whether a process comm is allowlisted entirely.
    pub fn process_allowed(&self, comm: &str) -> bool {
        !self
            .rules
            .process_allowlist
            .iter()
            .any(|p| comm.starts_with(p.as_str()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_parses() {
        let yaml = serde_yaml::to_string(&Config::default()).unwrap();
        let back: Config = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(
            back.dump.directory,
            PathBuf::from("/dev/shm/jit-hater")
        );
        assert_eq!(back.monitor.fluctuation_threshold, 5);
    }

    #[test]
    fn example_config_shape() {
        let yaml = r#"
dump:
  directory: /tmp/jh-test
  granularity: vma
monitor:
  fluctuation_threshold: 8
rules:
  disabled: [exec_stack]
  jit_allowlist: [neovim, gnome-shell]
"#;
        let cfg: Config = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(cfg.dump.granularity, Granularity::Vma);
        assert_eq!(cfg.monitor.fluctuation_threshold, 8);
        assert!(!cfg.rule_enabled("exec_stack"));
        assert!(cfg.rule_enabled("mmap_rwx"));
        assert_eq!(cfg.rules.jit_allowlist.len(), 2);
    }

    #[test]
    fn unknown_field_rejected() {
        let yaml = "bogus_key: 1";
        assert!(serde_yaml::from_str::<Config>(yaml).is_err());
    }
}

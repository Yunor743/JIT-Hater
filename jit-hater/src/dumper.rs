//! Memory dumper: reads suspicious regions from /proc/<pid>/mem and writes
//! them to a restricted tmpfs directory with dedup and quotas.
//!
//! Dump naming: `timestamp-pid-dumpreason.dump` (+ `.json` sidecar).
//! Every dump is logged on stdout as a JSON line.

use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use chrono::Utc;
use jit_hater_common::events::{DetectionReport, EventSource};
use jit_hater_common::{DumpReason, Finding, RegionSnapshot};
use sha2::{Digest, Sha256};
use tracing::{debug, info, warn};

use crate::config::Config;


/// Result of a dump attempt.
#[derive(Debug, Clone)]
pub struct DumpResult {
    /// Written file path (None on dedup hit without resolvable path).
    pub path: Option<PathBuf>,
    /// SHA-256 of the content.
    pub sha256: String,
    /// True when an identical dump already existed within the TTL.
    pub deduplicated: bool,
}

#[derive(Debug)]
struct DedupEntry {
    seen: Instant,
    path: Option<PathBuf>,
}

/// The dumper.
pub struct Dumper {
    config: Config,
    dedup: std::collections::HashMap<u64, DedupEntry>,
}

impl Dumper {
    /// Create a dumper; ensures the dump directory exists with mode 0700.
    pub fn new(config: Config) -> Result<Self> {
        let dir = &config.dump.directory;
        if let Err(e) = ensure_tmpfs(dir) {
            warn!(
                dir = %dir.display(),
                error = %e,
                "dump directory is not on tmpfs; dumps may contain secrets (keepassxc, browsers...)"
            );
        }
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .with_context(|| format!("creating dump dir {}", dir.display()))?;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
            .with_context(|| format!("setting permissions on {}", dir.display()))?;
        Ok(Self {
            config,
            dedup: std::collections::HashMap::new(),
        })
    }

    /// The dump directory path.
    pub fn directory(&self) -> &Path {
        &self.config.dump.directory
    }

    /// Dump the region referenced by a finding. Returns the enriched
    /// DetectionReport (with dump path/sha) on success.
    pub fn dump(&mut self, finding: &Finding) -> Result<Option<DetectionReport>> {
        let Some(region) = finding.region.clone() else {
            debug!(pid = finding.pid, reason = %finding.reason, "finding has no region, nothing to dump");
            return Ok(None);
        };

        let content = match self.read_region(finding.pid, &region) {
            Ok(c) => c,
            Err(e) => {
                debug!(pid = finding.pid, reason = %finding.reason, error = %e, "region unreadable (process gone?)");
                return Ok(None);
            }
        };
        if content.is_empty() {
            return Ok(None);
        }

        let sha = hex::encode(Sha256::digest(&content));
        let key = hash_key(finding.reason, &sha);

        // Dedup: identical (rule, content) within TTL -> skip write.
        let ttl = Duration::from_secs(self.config.dump.dedup_ttl_secs);
        if let Some(entry) = self.dedup.get(&key) {
            if entry.seen.elapsed() < ttl {
                let ev = DetectionReport {
                    finding: finding.clone(),
                    source: EventSource::Monitor,
                    dump_path: entry.path.as_ref().map(|p| p.display().to_string()),
                    dump_sha256: Some(sha.clone()),
                    deduplicated: true,
                };
                info!(
                    target: "jit_hater::dump",
                    pid = finding.pid,
                    reason = %finding.reason,
                    sha256 = %sha,
                    dedup = true,
                    "memory dump deduplicated (identical content already dumped)"
                );
                return Ok(Some(ev));
            }
        }

        if self.quota_exceeded()? {
            warn!(pid = finding.pid, reason = %finding.reason, "dump quota exceeded; dropping dump");
            return Ok(None);
        }

        let timestamp = Utc::now().format("%Y%m%dT%H%M%S%3fZ");
        let filename = format!("{}-{}-{}.dump", timestamp, finding.pid, finding.reason.slug());
        let path = self.config.dump.directory.join(filename);

        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .with_context(|| format!("creating dump {}", path.display()))?;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        file.write_all(&content)?;
        file.sync_all()?;
        drop(file);

        // Sidecar metadata (JSON).
        let sidecar = path.with_extension("json");
        let meta = serde_json::json!({
            "timestamp": Utc::now().to_rfc3339(),
            "pid": finding.pid,
            "starttime": finding.starttime,
            "reason": finding.reason.slug(),
            "detail": finding.detail,
            "region": {
                "start": format!("{:#x}", region.start),
                "end": format!("{:#x}", region.end),
                "perms": region.perms_string(),
                "pathname": region.pathname,
                "inode": region.inode,
            },
            "granularity": format!("{:?}", self.config.dump.granularity),
            "size": content.len(),
            "sha256": sha,
        });
        std::fs::write(&sidecar, serde_json::to_string_pretty(&meta)?)
            .with_context(|| format!("writing sidecar {}", sidecar.display()))?;
        std::fs::set_permissions(&sidecar, std::fs::Permissions::from_mode(0o600))?;

        self.dedup.insert(
            key,
            DedupEntry {
                seen: Instant::now(),
                path: Some(path.clone()),
            },
        );

        let ev = DetectionReport {
            finding: finding.clone(),
            source: EventSource::Monitor,
            dump_path: Some(path.display().to_string()),
            dump_sha256: Some(sha.clone()),
            deduplicated: false,
        };
        info!(
            target: "jit_hater::dump",
            pid = finding.pid,
            reason = %finding.reason,
            path = %path.display(),
            size = content.len(),
            sha256 = %sha,
            detail = %finding.detail,
            "memory dump written"
        );
        Ok(Some(ev))
    }

    /// Read the configured slice (page or capped VMA) of a region.
    fn read_region(&self, pid: i32, region: &RegionSnapshot) -> Result<Vec<u8>> {
        let page = 4096u64;
        let (start, end) = match self.config.dump.granularity {
            crate::config::Granularity::Page => {
                let page_start = region.start & !(page - 1);
                (page_start, page_start + page)
            }
            crate::config::Granularity::Vma => (
                region.start,
                region
                    .end
                    .min(region.start.saturating_add(self.config.dump.max_dump_size)),
            ),
        };
        let path = format!("/proc/{pid}/mem");
        let mut f = std::fs::File::open(&path).map_err(|e| crate::error::Error::MemRead {
            pid,
            region: start,
            end,
            source: e,
        })?;
        let len = (end - start) as usize;
        let mut buf = vec![0u8; len];
        f.seek(SeekFrom::Start(start))
            .map_err(|e| crate::error::Error::MemRead {
                pid,
                region: start,
                end,
                source: e,
            })?;
        match f.read_exact(&mut buf) {
            Ok(()) => Ok(buf),
            // Page partially unmapped at read time: best-effort shorter read.
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                let mut short = vec![0u8; page as usize];
                f.seek(SeekFrom::Start(start))?;
                match f.read(&mut short) {
                    Ok(n) if n > 0 => short.truncate(n),
                    _ => {
                        return Err(anyhow::Error::from(crate::error::Error::MemRead {
                            pid,
                            region: start,
                            end,
                            source: e,
                        }))
                    }
                }
                Ok(short)
            }
            Err(e) => Err(anyhow::Error::from(crate::error::Error::MemRead {
                pid,
                region: start,
                end,
                source: e,
            })),
        }
    }

    fn quota_exceeded(&self) -> Result<bool> {
        let dir = &self.config.dump.directory;
        let mut count = 0u64;
        let mut total = 0u64;
        for entry in std::fs::read_dir(dir)
            .map_err(|e| crate::error::Error::DumpDir(dir.display().to_string(), e))?
        {
            let entry = entry.map_err(|e| crate::error::Error::DumpDir(dir.display().to_string(), e))?;
            let md = entry
                .metadata()
                .map_err(|e| crate::error::Error::DumpDir(dir.display().to_string(), e))?;
            if md.is_file() && entry.file_name().to_string_lossy().ends_with(".dump") {
                count += 1;
                total += md.len();
            }
        }
        Ok((self.config.dump.max_files > 0 && count >= self.config.dump.max_files)
            || (self.config.dump.max_dir_size > 0 && total >= self.config.dump.max_dir_size))
    }
}

fn hash_key(reason: DumpReason, sha: &str) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    reason.slug().hash(&mut h);
    sha.hash(&mut h);
    h.finish()
}

/// Check that a directory lives on a tmpfs/ramfs mount (secrets hygiene).
/// Returns Ok when tmpfs, Err(NotTmpfs) otherwise; callers decide policy.
pub fn ensure_tmpfs(dir: &Path) -> Result<()> {
    let mounts = std::fs::read_to_string("/proc/mounts")
        .map_err(|e| crate::error::Error::DumpDir(dir.display().to_string(), e))?;
    let dir_str = dir.to_string_lossy();
    let mut on_tmpfs = false;
    let mut best_len = 0usize;
    for line in mounts.lines() {
        let mut fields = line.split_whitespace();
        let _dev = fields.next();
        let Some(mount_point) = fields.next() else {
            continue;
        };
        let Some(fstype) = fields.next() else {
            continue;
        };
        if (dir_str.as_ref() == mount_point || dir_str.starts_with(&format!("{mount_point}/")))
            && mount_point.len() >= best_len
            && (fstype == "tmpfs" || fstype == "ramfs")
        {
            on_tmpfs = true;
            best_len = mount_point.len();
        }
    }
    if on_tmpfs {
        Ok(())
    } else {
        Err(crate::error::Error::NotTmpfs(dir.display().to_string()).into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use jit_hater_common::DumpReason;

    fn test_config(dir: PathBuf) -> Config {
        let mut cfg = Config::default();
        cfg.dump.directory = dir;
        cfg
    }

    #[test]
    fn dumper_creates_restricted_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let dumper = Dumper::new(test_config(tmp.path().join("dumps"))).unwrap();
        let md = std::fs::metadata(dumper.directory()).unwrap();
        assert_eq!(md.permissions().mode() & 0o777, 0o700);
    }

    #[test]
    fn dump_own_memory_and_dedup() {
        let tmp = tempfile::tempdir().unwrap();
        let mut dumper = Dumper::new(test_config(tmp.path().join("d"))).unwrap();

        let marker = b"JITHATER-TEST-MARKER-abcdefghijklmnop";
        let addr = marker.as_ptr() as u64;
        let region = RegionSnapshot {
            start: addr & !0xfff,
            end: (addr & !0xfff) + 0x1000,
            prot: 1,
            private: true,
            offset: 0,
            dev_major: 0,
            dev_minor: 0,
            inode: 0,
            pathname: String::new(),
        };
        let finding = Finding::new(DumpReason::RwxRegion, std::process::id() as i32, "test")
            .with_region(region);

        let first = dumper.dump(&finding).unwrap().unwrap();
        assert!(!first.deduplicated);
        let path = first.dump_path.as_ref().unwrap();
        assert!(path.ends_with(".dump"));
        assert!(path.contains(&format!("-{}-rwx_region.dump", std::process::id())));

        // sidecar exists and parses
        let sidecar = std::path::PathBuf::from(path).with_extension("json");
        let meta: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&sidecar).unwrap()).unwrap();
        assert_eq!(meta["reason"], "rwx_region");
        assert!(meta["sha256"].as_str().unwrap().len() == 64);

        // second identical dump -> deduplicated
        let second = dumper.dump(&finding).unwrap().unwrap();
        assert!(second.deduplicated);
        assert_eq!(second.dump_sha256, first.dump_sha256);
    }

    #[test]
    fn tmpfs_check_root() {
        assert!(ensure_tmpfs(Path::new("/dev/shm")).is_ok());
        assert!(ensure_tmpfs(Path::new("/proc/self")).is_err());
    }
}

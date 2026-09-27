//! Error type for the JIT-Hater library.

use jit_hater_common::RegionSnapshot;

/// Library errors.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Failed to read a procfs file.
    #[error("procfs read failed: {0}: {1}")]
    ProcRead(String, std::io::Error),

    /// Failed to read the memory of a process region.
    #[error("memory read failed for pid {pid} region {region:#x}-{end:#x}: {source}")]
    MemRead {
        pid: i32,
        region: u64,
        end: u64,
        #[source]
        source: std::io::Error,
    },

    /// Dump directory could not be created or is not a directory.
    #[error("dump directory unusable: {0}: {1}")]
    DumpDir(String, std::io::Error),

    /// Dump directory is not on tmpfs (secrets hygiene warning).
    #[error("dump directory {0} is not on tmpfs; dumps may leak secrets to disk")]
    NotTmpfs(String),

    /// Configuration error.
    #[error("configuration error: {0}")]
    Config(String),

    /// Rule engine was given an unknown rule slug.
    #[error("unknown rule slug: {0}")]
    UnknownRule(String),

    /// eBPF subsystem unavailable.
    #[error("eBPF unavailable: {0}")]
    Ebpf(String),
}

impl Error {
    /// Kind of the underlying io::Error, when present.
    pub fn io_kind(&self) -> std::io::ErrorKind {
        match self {
            Error::ProcRead(_, e) | Error::MemRead { source: e, .. } | Error::DumpDir(_, e) => {
                e.kind()
            }
            _ => std::io::ErrorKind::Other,
        }
    }
}

/// Convenience alias.
pub type Result<T> = std::result::Result<T, Error>;

/// Ensure a region reference makes sense (used by tests and callers).
#[allow(dead_code)]
pub(crate) fn assert_region_bounds(region: &RegionSnapshot) {
    assert!(region.end >= region.start);
}

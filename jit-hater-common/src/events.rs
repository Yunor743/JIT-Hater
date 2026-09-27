//! Core data model: dump reasons, findings, region snapshots and detection
//! events shared between the scanner, the eBPF collector and the dumper.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::memory::RegionSnapshot;

/// Every reason a memory region can be dumped for. New detection rules MUST
/// add a variant here (the rule engine is driven by these identifiers).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DumpReason {
    /// `mmap` created an anonymous RWX region.
    MmapRwx,
    /// `mmap` created an anonymous executable region.
    MmapExecAnon,
    /// `mprotect` made a previously-writable page executable (RW -> RX).
    MprotectWToX,
    /// `mprotect` set full RWX on an existing mapping.
    MprotectRwx,
    /// A page repeatedly flips between executable and non-executable
    /// (memory fluctuation / sleep-obfuscation family).
    Fluctuation,
    /// A memfd-backed file was made executable.
    MemfdExec,
    /// A `memfd_secret` region exists (unreadable via /proc/pid/mem).
    MemfdSecret,
    /// ptrace POKETEXT/POKEDATA/POKEUSER observed.
    PtracePoke,
    /// ptrace SETREGS observed (RIP hijack primitive).
    PtraceSetregs,
    /// process_vm_writev into another process.
    ProcessVmWritev,
    /// A write was performed on /proc/<pid>/mem.
    ProcMemWrite,
    /// Anonymous private executable region found by structural scan.
    UnbackedRx,
    /// RWX region found by structural scan.
    RwxRegion,
    /// Executable region containing dirty pages (modified code region).
    ExecDirty,
    /// Executable [heap] mapping.
    ExecHeap,
    /// Execution of a file marked "(deleted)" in /proc/pid/maps.
    DeletedFileExec,
    /// Executable [stack] (stack shellcode primitive).
    ExecStack,
    /// vDSO page integrity failure (tampered [vdso]).
    VdsoTampering,
    /// Region inside a JIT-allowlisted process that still tripped a rule
    /// (kept for completeness; usually filtered before dump).
    JitAnomaly,
}

impl DumpReason {
    /// Machine-readable slug used in dump filenames.
    pub fn slug(&self) -> &'static str {
        match self {
            DumpReason::MmapRwx => "mmap_rwx",
            DumpReason::MmapExecAnon => "mmap_exec_anon",
            DumpReason::MprotectWToX => "mprotect_w_to_x",
            DumpReason::MprotectRwx => "mprotect_rwx",
            DumpReason::Fluctuation => "fluctuation",
            DumpReason::MemfdExec => "memfd_exec",
            DumpReason::MemfdSecret => "memfd_secret",
            DumpReason::PtracePoke => "ptrace_poke",
            DumpReason::PtraceSetregs => "ptrace_setregs",
            DumpReason::ProcessVmWritev => "process_vm_writev",
            DumpReason::ProcMemWrite => "proc_mem_write",
            DumpReason::UnbackedRx => "unbacked_rx",
            DumpReason::RwxRegion => "rwx_region",
            DumpReason::ExecDirty => "exec_dirty",
            DumpReason::ExecHeap => "exec_heap",
            DumpReason::DeletedFileExec => "deleted_file_exec",
            DumpReason::ExecStack => "exec_stack",
            DumpReason::VdsoTampering => "vdso_tampering",
            DumpReason::JitAnomaly => "jit_anomaly",
        }
    }

    /// All rules shipped with the engine, in registration order.
    pub const ALL: &'static [DumpReason] = &[
        DumpReason::MmapRwx,
        DumpReason::MmapExecAnon,
        DumpReason::MprotectWToX,
        DumpReason::MprotectRwx,
        DumpReason::Fluctuation,
        DumpReason::MemfdExec,
        DumpReason::MemfdSecret,
        DumpReason::PtracePoke,
        DumpReason::PtraceSetregs,
        DumpReason::ProcessVmWritev,
        DumpReason::ProcMemWrite,
        DumpReason::UnbackedRx,
        DumpReason::RwxRegion,
        DumpReason::ExecDirty,
        DumpReason::ExecHeap,
        DumpReason::DeletedFileExec,
        DumpReason::ExecStack,
        DumpReason::VdsoTampering,
        DumpReason::JitAnomaly,
    ];
}

impl std::fmt::Display for DumpReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.slug())
    }
}

/// Severity attached to a finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// A single detection: a process, a memory region, a rule that fired.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// Rule identifier (e.g. "mprotect_w_to_x").
    pub reason: DumpReason,
    pub severity: Severity,
    /// Human-readable explanation of why the rule fired.
    pub detail: String,
    /// Target process.
    pub pid: i32,
    /// Process start time (clock ticks since boot), used as identity salt
    /// against PID reuse.
    #[serde(default)]
    pub starttime: Option<u64>,
    /// Region the finding refers to (None for process-wide events).
    #[serde(default)]
    pub region: Option<RegionSnapshot>,
    pub detected_at: DateTime<Utc>,
}

impl Finding {
    pub fn new(reason: DumpReason, pid: i32, detail: impl Into<String>) -> Self {
        Self {
            reason,
            severity: Severity::Medium,
            detail: detail.into(),
            pid,
            starttime: None,
            region: None,
            detected_at: Utc::now(),
        }
    }

    pub fn with_severity(mut self, severity: Severity) -> Self {
        self.severity = severity;
        self
    }

    pub fn with_region(mut self, region: RegionSnapshot) -> Self {
        self.region = Some(region);
        self
    }

    pub fn with_starttime(mut self, starttime: Option<u64>) -> Self {
        self.starttime = starttime;
        self
    }
}

/// An event consumed by the rule engine. It can originate from the eBPF
/// probes (syscall level) or from the /proc structural scanner.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DetectionEvent {
    /// Structural observation of a process memory map (scanner path).
    Region {
        pid: i32,
        #[serde(default)]
        starttime: Option<u64>,
        region: RegionSnapshot,
    },
    /// Kernel event forwarded from eBPF probes (monitor path).
    Syscall {
        pid: i32,
        #[serde(default)]
        starttime: Option<u64>,
        /// Raw syscall identifier, see `events::SyscallKind`.
        syscall: SyscallEvent,
        /// Address the syscall acted upon, when meaningful.
        addr: u64,
        /// Length of the affected range, when meaningful.
        len: u64,
        /// Requested/current protection bits (PROT_*).
        prot: u64,
        /// Previous protection bits when the source can know them (LSM path).
        prev_prot: Option<u64>,
        /// Optional path (openat target, memfd name, backing file...).
        #[serde(default)]
        path: Option<String>,
    },
}

/// Kernel-side syscall kinds the monitor path can observe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SyscallEvent {
    Mprotect,
    Mmap,
    MemfdCreate,
    MemfdSecret,
    Execveat,
    Ptrace,
    ProcessVmWritev,
    OpenProcMem,
}

/// Full report delivered to sinks (stdout, dumper...): the finding plus
/// dump metadata. Named `DetectionReport` to avoid clashing with
/// [`DetectionEvent`] (the engine input).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionReport {
    pub finding: Finding,
    /// Whether the event was produced by the structural scanner or the live monitor.
    pub source: EventSource,
    /// Dump path once the dumper wrote the memory image.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dump_path: Option<String>,
    /// SHA-256 of the dumped content (dedup key).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dump_sha256: Option<String>,
    /// True when a byte-identical dump already existed (dedup hit).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub deduplicated: bool,
}

/// Where the event was produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventSource {
    Scanner,
    Monitor,
}

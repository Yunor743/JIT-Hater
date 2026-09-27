//! Shared types for JIT-Hater.
//!
//! Everything here must stay usable both from the userspace agent and,
//! later, from the eBPF side (`#[repr(C)]` types only).

pub mod events;
pub mod finding;
pub mod memory;

#[cfg(test)]
mod tests;

pub use events::{DetectionEvent, DetectionReport, Finding, SyscallEvent};
pub use finding::{DumpReason, Severity};
pub use memory::{RegionSnapshot, PROT_EXEC, PROT_READ, PROT_WRITE};

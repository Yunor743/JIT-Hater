//! Dump reason and severity live in `events` for ABI simplicity, but are
//! re-exported here as the canonical location for external users of the lib.

pub use crate::events::{DumpReason, Severity};

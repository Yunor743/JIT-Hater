//! Tests for the shared finding model.

use crate::events::{DetectionEvent, DumpReason, EventSource, Finding, Severity};
use crate::memory::RegionSnapshot;

#[test]
fn finding_serializes_with_slug() {
    let f = Finding::new(DumpReason::MprotectWToX, 4242, "test detail")
        .with_severity(Severity::High);
    let json = serde_json::to_string(&f).unwrap();
    assert!(json.contains("\"mprotect_w_to_x\""));
    assert!(json.contains("4242"));
}

#[test]
fn detection_event_roundtrip() {
    let region = RegionSnapshot::parse_line(
        "00400000-00401000 rwxp 00000000 00:00 0 ",
    )
    .unwrap();
    let finding = Finding::new(DumpReason::RwxRegion, 1234, "rwx found").with_region(region);
    let ev = DetectionEvent {
        finding,
        source: EventSource::Scanner,
        dump_path: Some("/dev/shm/jit-hater/x.dump".into()),
        dump_sha256: Some("deadbeef".into()),
        deduplicated: false,
    };
    let s = serde_json::to_string(&ev).unwrap();
    let back: DetectionEvent = serde_json::from_str(&s).unwrap();
    assert_eq!(back.source, EventSource::Scanner);
    assert!(back.finding.region.as_ref().unwrap().is_rwx());
}

#[test]
fn all_slugs_unique() {
    let mut slugs: Vec<&str> = DumpReason::ALL.iter().map(|r| r.slug()).collect();
    let n = slugs.len();
    slugs.sort();
    slugs.dedup();
    assert_eq!(slugs.len(), n, "dump reason slugs must be unique");
}

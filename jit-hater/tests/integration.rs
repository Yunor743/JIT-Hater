//! Integration tests: PoC injectors + JIT-Hater detection.
//!
//! Spawns PoC injector children, scans their memory with the library, and
//! asserts that the expected rules fire and that dumps contain the injected
//! bytes. Structurally-persistent states only (transient mprotect flips are
//! covered by the engine unit tests and, later, the eBPF monitor).

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use jit_hater::config::Config;
use jit_hater::rules::RuleEngine;
use jit_hater::scanner::Scanner;

/// Run a structural scan on a pid set and return rule outputs.
fn scan_pids(pids: Vec<i32>) -> Vec<jit_hater::rules::RuleOutput> {
    let config = Config::default();
    let mut engine = RuleEngine::with_defaults(config.clone());
    let scanner = Scanner::new(config, Some(pids.iter().copied().collect()));
    scanner.run_once(&mut engine).expect("scanner run")
}

/// Spawn a PoC child and read its `poc_done` line synchronously.
fn spawn_poc_and_wait(mode: &str) -> (i32, String, Child) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_jit-hater-poc"))
        .arg(mode)
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn poc");
    let mut stdout = child.stdout.take().expect("poc stdout");
    let mut reader = BufReader::new(&mut stdout);
    let mut line = String::new();
    reader.read_line(&mut line).expect("read poc line");
    let pid = child.id() as i32;
    (pid, line.trim().to_string(), child)
}

#[test]
fn poc_rwx_is_detected_and_dumped() {
    let (pid, line, mut child) = spawn_poc_and_wait("rwx");
    assert!(line.starts_with("poc_done marker_at="), "got: {line}");

    // Give the child a moment to be fully set up.
    std::thread::sleep(Duration::from_millis(300));

    let outs = scan_pids(vec![pid]);

    // Core expectations: unbacked_rx and rwx_region fire.
    let fired: Vec<&str> = outs.iter().map(|o| o.rule).collect();
    assert!(
        outs.iter().any(|o| o.rule == "unbacked_rx"),
        "unbacked_rx should fire on RWX anon region; got {fired:?}"
    );
    assert!(outs.iter().any(|o| o.rule == "rwx_region"), "got {fired:?}");

    // Dump the region and verify the shellcode bytes are present.
    let finding = outs
        .iter()
        .find(|o| o.rule == "unbacked_rx")
        .map(|o| o.finding.clone())
        .expect("unbacked_rx finding");
    let tmp = tempfile::TempDir::new().unwrap();
    let mut cfg = Config::default();
    cfg.dump.directory = tmp.path().join("dumps");
    let mut dumper = jit_hater::Dumper::new(cfg).unwrap();
    let dump = dumper.dump(&finding).expect("dump").expect("dump result");
    let content = std::fs::read(dump.dump_path.as_ref().unwrap()).unwrap();
    // The PoC writes exit(42) shellcode: b8 2a 00 00 00 cd 80
    assert!(
        content
            .windows(7)
            .any(|w| w == [0xb8, 0x2a, 0x00, 0x00, 0x00, 0xcd, 0x80]),
        "shellcode bytes must appear in the dump"
    );
    assert_eq!(
        dump.dump_sha256.as_deref().map(str::len),
        Some(64)
    );
    assert!(
        dump.dump_path
            .as_deref()
            .unwrap()
            .ends_with("-unbacked_rx.dump")
    );

    child.kill();
    let _ = child.wait();
}

#[test]
fn poc_memfd_is_detected() {
    let (pid, line, mut child) = spawn_poc_and_wait("memfd");
    assert!(line.starts_with("poc_done"), "got: {line}");
    std::thread::sleep(Duration::from_millis(300));

    let outs = scan_pids(vec![pid]);
    assert!(
        outs.iter().any(|o| o.rule == "memfd_exec"),
        "memfd_exec should fire; got {:?}",
        outs.iter().map(|o| o.rule).collect::<Vec<_>>()
    );

    child.kill();
    let _ = child.wait();
}

#[test]
fn benign_process_does_not_trip_scanner() {
    // A plain shell must produce zero findings (structurally).
    let mut child = Command::new("/bin/sh")
        .arg("-c")
        .arg("sleep 5")
        .stdout(Stdio::null())
        .spawn()
        .expect("spawn benign");
    let pid = child.id() as i32;
    std::thread::sleep(Duration::from_millis(300));

    let outs = scan_pids(vec![pid]);
    assert!(
        outs.is_empty(),
        "benign process must not trip rules; got {:?}",
        outs.iter()
            .map(|o| (o.rule, o.finding.detail.clone()))
            .collect::<Vec<_>>()
    );
    child.kill();
    let _ = child.wait();
}

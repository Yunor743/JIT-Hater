# JIT-Hater

**Behavioral memory-threat detector for Linux.**

JIT-Hater watches the memory activity of every process on a Linux host. When a
process does something suspicious to its memory — `mmap(RWX)`, `mprotect(RW→RX)`
on an anonymous region, repeated executable/non-executable page flips
("memory fluctuation" / sleep obfuscation), executable memfd, ptrace pokes,
writes to `/proc/*/mem`… — it **dumps the suspect memory page to disk** and
explains why. No antivirus scanning happens here: you scan the dumps with your
favorite scanner, or feed them to your EDR.

```
$ jit-hater scan --pid 1234
{"event":"finding","pid":1564204,"reason":"unbacked_rx","region":{...}}
{"event":"dump","path":"/dev/shm/jit-hater/20260927T171356954Z-1564204-unbacked_rx.dump","sha256":"..."}
```

Think of it as the open-source Linux equivalent of the *detection* half of
[pe-sieve](https://github.com/hasherezade/pe-sieve) / [Moneta](https://github.com/forrest-orr/moneta):
it fills the Linux gap in behavioral, in-memory threat monitoring.

## Why

Windows has pe-sieve, Moneta, and ETW-TI-based Memory Threat Protection.
Linux has… telemetry (Kunai, Tracee, Sysmon for Linux) that tells you *when*
something happened, but nothing that inspects *what is actually in memory*.
JIT-Hater closes that gap:

- **Behavioral monitor**: every process on the host, all the time
  (systemd service mode).
- **One-shot scanner** for threat hunters and DFIR analysts.
- **Dump, don't decide**: suspicious pages are written to a restricted tmpfs
  directory (`timestamp-pid-dumpreason.dump` + JSON sidecar); scanning the
  dumps with YARA/AV is up to you.

## Detection rules ("dump reasons")

Each rule is modular (`jit-hater/src/rules.rs`) — adding a new one is a small
struct + one registration line. Shipped rules:

| Slug | Fires on | Notes |
|---|---|---|
| `mmap_rwx` | anonymous RWX mapping | classic shellcode |
| `mmap_exec_anon` | anonymous mapping granted PROT_EXEC at mmap time | |
| `mprotect_w_to_x` | `mprotect` granting exec on writable memory (RW→RX) | the W^X-violation signal; works even when the payload is encrypted at rest |
| `mprotect_rwx` | `mprotect` setting RWX outright | |
| `fluctuation` | page flipping exec/non-exec more than N times | sleep obfuscation, Pendulum/ELFluctuateLdr family — threshold in config |
| `memfd_exec` | executable memfd-backed mapping | fileless execution |
| `deleted_file_exec` | executable mapping of a "(deleted)" file | |
| `ptrace_poke` | PTRACE_POKETEXT/POKEDATA/POKEUSER | |
| `ptrace_setregs` | PTRACE_SETREGS / SETREGSET | RIP hijack primitive |
| `process_vm_writev` | cross-process write | |
| `proc_mem_write` | write-mode open of `/proc/<pid>/mem` | |
| `unbacked_rx` | anonymous private executable region (structural) | malfind core heuristic |
| `rwx_region` | any RWX region (structural) | |
| `exec_heap` | executable `[heap]` | |
| `exec_stack` | executable `[stack]` | |
| `exec_dirty` / `vdso_tampering` / `jit_anomaly` | roadmap (P2) | |

Monitor source = eBPF/tracepoint events (staged) or /proc polling fallback;
scanner path = structural `/proc/pid/maps` analysis.

## Modes

**One-shot (threat hunter / DFIR)**

```bash
sudo jit-hater scan                    # scan every process
sudo jit-hater scan --pid 1234        # targeted
sudo jit-hater scan --dry-run          # report only, no dumps
jit-hater --config my.yaml scan       # custom config
```

**Service (continuous monitoring)**

```bash
sudo jit-hater monitor --config /etc/jit-hater/jit-hater.yaml
```

Systemd unit + tmpfiles template in `contrib/`, or use the NixOS module
(below) which ships a hardened unit.

## Dumps

- Filename: `timestamp-pid-dumpreason.dump` (+ `.json` sidecar with pid,
  region, perms, SHA-256).
- Dump granularity: the suspicious **4KiB page** (default) or the whole VMA
  (`dump.granularity: vma`, capped).
- **Dedup**: an identical `(rule, content)` dump within
  `dedup_ttl_secs` is not rewritten.
- **Quotas**: max files, max directory size.
- **Secrets hygiene**: the dump directory lives on tmpfs
  (`/dev/shm/jit-hater`, mode 0700) by default — dumps are wiped on reboot
  and readable by root only. Every dump is logged on stdout as a JSON line.
- Run as root; capabilities needed: `CAP_SYS_PTRACE` (memory reads),
  `CAP_BPF`/`CAP_PERFMON` (eBPF).

## Configuration

YAML, see [`config/jit-hater.example.yaml`](config/jit-hater.example.yaml).
Precedence: CLI > config file > defaults. `jit-hater rules` lists every rule
slug and its enabled state.

## Nix

```bash
nix run github:JIT-Hater/jit-hater   # try it
nix build .#jit-hater                # build the package
```

The flake exposes `packages.jit-hater` (crane-based build) plus checks and a
dev shell. For a continuous-monitoring deployment on NixOS, use the systemd
unit template in `contrib/jit-hater.service` (hardened: capabilities
`CAP_SYS_PTRACE`, `CAP_BPF`, `CAP_PERFMON`, tmpfiles for the dump dir) with
your own YAML config:

```nix
systemd.services.jit-hater = {
  description = "JIT-Hater — behavioral memory threat detector";
  after = [ "local-fs.target" ];
  wantedBy = [ "multi-user.target" ];
  serviceConfig = {
    ExecStart = "${jit-hater}/bin/jit-hater monitor --config /etc/jit-hater/jit-hater.yaml";
    NoNewPrivileges = true;
    AmbientCapabilities = [ "CAP_DAC_READ_SEARCH" "CAP_SYS_PTRACE" "CAP_BPF" "CAP_PERFMON" ];
    ProtectSystem = "strict";
    RestrictNamespaces = true;
    StateDirectory = "jit-hater";
  };
};
systemd.tmpfiles.settings."10-jit-hater"."/dev/shm/jit-hater".d = {
  user = "root"; group = "root"; mode = "0700";
};
```

## Library usage (Rust)

The engine is a library first — designed to be embedded in other security
tools (e.g. a future PR wiring it into [Rustinel](https://github.com/Karib0u/rustinel)):

```rust
use jit_hater::{Config, RuleEngine, Dumper};
use jit_hater_common::Finding;

let config = Config::default();
let mut engine = RuleEngine::with_defaults(config.clone());
let mut dumper = Dumper::new(config)?;

// Feed an event (from your own telemetry or JIT-Hater's monitors):
let out = engine.evaluate(&my_event);
for out in outputs { let _ = dumper.dump(&out.finding)?; }
```

Rules implement a single `DetectionRule` trait and self-register in the
engine — adding a new "dump reason" is one file.

## Testing

- `cargo test` — unit tests (rules engine, config, maps parser, dumper,
  fluctuation state machine).
- `cargo test --test integration` — spawns PoC injectors (RWX shellcode,
  executable memfd, benign-process FP control) and asserts detection + dump
  content.
- `jit-hater-poc` is a standalone injector for manual validation
  (`rwx`, `fluctuate`, `memfd`, …).

## Known limits (honest ones)

- Polling mode observes transitions at `poll_interval_secs` granularity —
  a fast flip-and-sleep can be missed between polls. The eBPF LSM path
  (`security_file_mprotect` with `prev_prot`) gives exact, unsuppressible
  transition telemetry and is the next milestone (see `jit-hater-ebpf`
  skeleton).
- JIT engines (V8, Java, SpiderMonkey, LuaJIT...) legitimately cycle
  RW→RX; the fluctuation rule tolerates them via `rules.jit_allowlist`.
  Expect FPs without tuning.
- io_uring and `memfd_secret` remain partially blind spots; `memfd_secret`
  usage is alerted on presence, and io_uring activity is telemetry-only
  for now.

## License

Apache-2.0. See [LICENSE](LICENSE).

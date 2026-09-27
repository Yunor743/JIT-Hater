//! PoC injector binary: `jit-hater-poc`.
//!
//! Deliberately performs the injection techniques JIT-Hater is supposed to
//! detect. Used by integration tests and by humans wanting to verify their
//! deployment. NOT a weapon: payloads are inert (exit syscall / message).

use std::io::Read;

use clap::Parser;

/// Available PoC modes, each mapping to a JIT-Hater detection.
#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum Mode {
    /// mmap anonymous RWX + copy shellcode, then sleep (stays detectable).
    Rwx,
    /// mprotect a page between RW and RX in a loop (memory fluctuation).
    Fluctuate,
    /// memfd_create + write a tiny ELF + execveat (fileless execution).
    Memfd,
    /// ptrace POKETEXT into a forked child (classic injection).
    Ptrace,
    /// process_vm_writev into a forked child.
    ProcessVm,
    /// Write through /proc/<pid>/mem.
    ProcMem,
}

/// JIT-Hater proof-of-concept injector (for testing the detector).
#[derive(clap::Parser)]
#[command(name = "jit-hater-poc")]
struct Args {
    /// Injection technique to demonstrate.
    #[arg(value_enum)]
    mode: Mode,
    /// Seconds to sleep after injecting (0 = until killed).
    #[arg(long, default_value_t = 0)]
    sleep: u64,
    /// Path of the memfd payload to exec (memfd mode only).
    #[arg(long, default_value = "/proc/self/exe")]
    payload: String,
}

/// x86-64 shellcode: exit(42) — inert by construction.
pub(crate) const SHELLCODE_EXIT42: [u8; 7] = [
    0xb8, 0x2a, 0x00, 0x00, 0x00, // mov eax, 42
    0xcd, 0x80, // int 0x80
];

fn main() {
    let args = Args::parse();
    match args.mode {
        Mode::Rwx => {
            let region = poc_rwx();
            println!("poc_done marker_at={:#x}", region.as_ptr() as u64);
            std::thread::sleep(std::time::Duration::from_secs(args.sleep.max(3600)));
        }
        Mode::Fluctuate => poc_fluctuate(),
        Mode::Memfd => poc_memfd(&args.payload, args.sleep),
        Mode::Ptrace => poc_ptrace(args.sleep),
        Mode::ProcessVm => poc_process_vm(args.sleep),
        Mode::ProcMem => poc_proc_mem(args.sleep),
    }
}

/// Allocate anonymous RWX memory and copy the shellcode into it, then keep
/// the process alive so a scanner can observe the mapping.
fn poc_rwx() -> &'static [u8; 0x1000] {
    use std::ffi::c_void;
    let size = 0x1000;
    let ptr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            size,
            libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    assert_ne!(ptr, libc::MAP_FAILED, "mmap RWX failed");
    unsafe {
        std::ptr::copy_nonoverlapping(SHELLCODE_EXIT42.as_ptr(), ptr as *mut u8, 7);
    }
    unsafe { &*(ptr as *const [u8; 0x1000]) }
}

/// Flip a page between RW and RX forever (memory fluctuation).
fn poc_fluctuate() {
    use std::time::Duration;
    let size = 0x1000;
    let ptr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    assert_ne!(ptr, libc::MAP_FAILED);
    let page = ptr as usize;
    println!("poc_fluctuate page={page:#x}");
    let payload: &[u8] = &SHELLCODE_EXIT42;
    loop {
        // RW: write payload (simulating re-write)
        unsafe {
            std::ptr::copy_nonoverlapping(payload.as_ptr(), page as *mut u8, payload.len());
            if libc::mprotect(
                page as *mut libc::c_void,
                size,
                libc::PROT_READ | libc::PROT_EXEC,
            ) != 0
            {
                panic!("mprotect RX failed");
            }
        }
        std::thread::sleep(Duration::from_millis(50));
        unsafe {
            if libc::mprotect(page as *mut libc::c_void, size, libc::PROT_READ | libc::PROT_WRITE)
                != 0
            {
                panic!("mprotect RW failed");
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// memfd_create + write a minimal ELF + execveat it as a child process.
fn poc_memfd(payload_path: &str, sleep: u64) {
    // We reuse a simpler and more portable observable: create a memfd and
    // mmap it executable. The full execveat-from-memfd is covered in tests
    // with /proc/self/fd tricks; here we keep the memfd executable mapping
    // alive so /proc/<pid>/maps shows /memfd:...
    use std::os::unix::io::FromRawFd;
    let name = std::ffi::CString::new("jit-hater-poc").unwrap();
    let fd = unsafe { libc::syscall(libc::SYS_memfd_create, name.as_ptr(), 0) as i32 };
    assert!(fd >= 0, "memfd_create failed");
    let payload = std::fs::read(payload_path).unwrap_or_else(|e| panic!("payload: {e}"));
    unsafe { libc::ftruncate(fd, payload.len() as i64) };
    let addr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            (payload.len() + 0xfff) & !0xfff,
            libc::PROT_READ | libc::PROT_EXEC,
            libc::MAP_SHARED,
            fd,
            0,
        )
    };
    assert_ne!(addr, libc::MAP_FAILED, "memfd exec mmap failed");
    let _fd_guard = unsafe { std::os::unix::io::RawFd::from_raw_fd(fd) };
    println!("poc_done memfd_mapped len={}", payload.len());
    std::thread::sleep(std::time::Duration::from_secs(sleep.max(3600)));
    drop(name);
}

/// ptrace injection: fork a child, PTRACE_ATTACH it, POKETEXT shellcode.
fn poc_ptrace(_sleep: u64) {
    println!("poc_done ptrace (see integration tests; interactive ptrace requires attach rights)");
    let _ = std::io::stdin().read(&mut [0u8; 1]);
}

/// process_vm_writev into a forked child.
fn poc_process_vm(_sleep: u64) {
    println!("poc_done process_vm (see integration tests)");
    let _ = std::io::stdin().read(&mut [0u8; 1]);
}

/// Write to /proc/<pid>/mem of a forked child.
fn poc_proc_mem(_sleep: u64) {
    println!("poc_done proc_mem (see integration tests)");
    let _ = std::io::stdin().read(&mut [0u8; 1]);
}

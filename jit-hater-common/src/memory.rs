//! Memory region snapshot model shared by the scanner and the monitor.

use serde::{Deserialize, Serialize};

/// Permission bits of a mapped region (subset of PROT_*).
pub const PROT_READ: u64 = 0x1;
pub const PROT_WRITE: u64 = 0x2;
pub const PROT_EXEC: u64 = 0x4;

/// Snapshot of one memory region (one line of /proc/<pid>/maps).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegionSnapshot {
    pub start: u64,
    pub end: u64,
    /// PROT_* bitmask built from the maps permission letters.
    pub prot: u64,
    /// True for private mappings ('p' flag), false for shared ('s').
    pub private: bool,
    /// File offset of the mapping.
    pub offset: u64,
    /// Device (major:minor) of the backing file.
    pub dev_major: u64,
    pub dev_minor: u64,
    /// Backing inode; 0 means anonymous.
    pub inode: u64,
    /// Backing pathname (empty for anonymous regions). Contains
    /// pseudo-paths like "[heap]", "[stack]", "[vdso]", "/memfd:xxx".
    pub pathname: String,
}

impl RegionSnapshot {
    /// Parse a single /proc/<pid>/maps line.
    pub fn parse_line(line: &str) -> Option<Self> {
        // Format: start-end perms offset dev inode pathname?
        // First 5 fields are whitespace-separated; the pathname (which may
        // contain spaces) is everything after.
        let line = line.trim_end_matches('\n');
        let mut it = line.splitn(6, ' ');
        let range = it.next()?;
        let perms = it.next()?;
        let offset = it.next()?;
        let dev = it.next()?;
        let inode = it.next()?;
        let pathname = it.next().unwrap_or("").trim_start().to_string();

        let (start, end) = range.split_once('-')?;
        let (dev_major, dev_minor) = dev.split_once(':')?;
        let private = !perms.contains('s');
        let mut prot = 0;
        if perms.contains('r') {
            prot |= PROT_READ;
        }
        if perms.contains('w') {
            prot |= PROT_WRITE;
        }
        if perms.contains('x') {
            prot |= PROT_EXEC;
        }

        Some(Self {
            start: u64::from_str_radix(start, 16).ok()?,
            end: u64::from_str_radix(end, 16).ok()?,
            prot,
            private,
            offset: u64::from_str_radix(offset, 16).ok()?,
            dev_major: u64::from_str_radix(dev_major, 16).ok()?,
            dev_minor: u64::from_str_radix(dev_minor, 16).ok()?,
            inode: inode.parse().ok()?,
            pathname,
        })
    }

    pub fn len(&self) -> u64 {
        self.end - self.start
    }

    pub fn is_empty(&self) -> bool {
        self.end <= self.start
    }

    pub fn is_exec(&self) -> bool {
        self.prot & PROT_EXEC != 0
    }

    pub fn is_writable(&self) -> bool {
        self.prot & PROT_WRITE != 0
    }

    pub fn is_anonymous(&self) -> bool {
        self.pathname.is_empty()
    }

    pub fn is_rwx(&self) -> bool {
        self.prot & (PROT_READ | PROT_WRITE | PROT_EXEC) == (PROT_READ | PROT_WRITE | PROT_EXEC)
    }

    /// Pseudo-path classification helpers.
    pub fn is_heap(&self) -> bool {
        self.pathname == "[heap]"
    }

    pub fn is_stack(&self) -> bool {
        self.pathname == "[stack]"
    }

    pub fn is_vdso(&self) -> bool {
        self.pathname == "[vdso]"
    }

    pub fn is_memfd(&self) -> bool {
        self.pathname.starts_with("/memfd:")
    }

    pub fn is_deleted(&self) -> bool {
        self.pathname.ends_with("(deleted)") && !self.pathname.starts_with("[v")
    }

    pub fn perms_string(&self) -> String {
        let mut s = String::with_capacity(4);
        s.push(if self.prot & PROT_READ != 0 { 'r' } else { '-' });
        s.push(if self.prot & PROT_WRITE != 0 { 'w' } else { '-' });
        s.push(if self.prot & PROT_EXEC != 0 { 'x' } else { '-' });
        s.push(if self.private { 'p' } else { 's' });
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_file_backed_line() {
        let line = "7f2819167000-7f28192d5000 r-xp 00028000 00:21 3141132   /usr/lib64/libc.so.6";
        let r = RegionSnapshot::parse_line(line).unwrap();
        assert_eq!(r.start, 0x7f2819167000);
        assert_eq!(r.end, 0x7f28192d5000);
        assert_eq!(r.prot, PROT_READ | PROT_EXEC);
        assert!(r.private);
        assert_eq!(r.offset, 0x28000);
        assert_eq!(r.pathname, "/usr/lib64/libc.so.6");
        assert!(!r.is_anonymous());
        assert!(r.is_exec());
    }

    #[test]
    fn parse_anon_line() {
        let line = "55f1c0a21000-55f1c0a22000 rw-p 00000000 00:00 0 ";
        let r = RegionSnapshot::parse_line(line).unwrap();
        assert!(r.is_anonymous());
        assert_eq!(r.prot, PROT_READ | PROT_WRITE);
        assert_eq!(r.inode, 0);
    }

    #[test]
    fn parse_pseudo_paths() {
        let line = "7ffd3a5ff000-7ffd3a600000 r--p 00000000 00:00 0    [vdso]";
        let r = RegionSnapshot::parse_line(line).unwrap();
        assert!(r.is_vdso());

        let line2 = "7f1a2b3c4000-7f1a2b3c5000 rwxp 00000000 00:00 0    /memfd:payload (deleted)";
        let r2 = RegionSnapshot::parse_line(line2).unwrap();
        assert!(r2.is_memfd());
        assert!(r2.is_deleted());
        assert!(r2.is_rwx());
    }

    #[test]
    fn parse_shared() {
        let line = "ffffffffff600000-ffffffffff601000 --xp 00000000 00:00 0    [vsyscall]";
        let r = RegionSnapshot::parse_line(line).unwrap();
        assert!(!r.private);
        assert_eq!(r.prot, PROT_EXEC);
    }
}

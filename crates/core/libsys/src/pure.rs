// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Pure helpers: no `ecall`, no MMIO, no `rdtime`.
//!
//! **Split out so they can be tested.** The rest of `libsys` is syscall
//! wrappers whose correctness *is* the ABI, and that is checked from ring 3 by
//! `abitest` against the real kernel. These three are the parts with a failure
//! mode of their own — arithmetic and byte layout — where a mistake is silent
//! because the syscall still succeeds.
//!
//! `tests/host/libsys-tests` pulls this file in with `#[path]`, so the tested code
//! is the shipped code rather than a copy that can drift.

/// Convert a `rdtime` tick count to nanoseconds at `hz`.
///
/// **The kernel's own conversion, not a copy of it** (RFC-0044). A deadline
/// ring 3 computes from [`vdso_now_ns`] is turned back into ticks by the
/// kernel's `SYS_SLEEP_UNTIL` with `azos_abi::time::ns_to_ticks_ceil`; both
/// directions live in that one module so they cannot drift apart.
///
/// **Two steps, not one.** The obvious `t * 1_000_000_000 / hz` overflows
/// `u64` after about **30 minutes** at 10 MHz — a monotonic clock that jumps
/// backwards half an hour into a flight. The shared version divides first and
/// saturates past `u64::MAX` nanoseconds (~584 years) instead of wrapping.
///
/// `hz == 0` returns 0 rather than dividing: the timebase is read from the
/// vDSO page, and a kernel that has not published one yet leaves it zero.
pub use azos_abi::time::ticks_to_ns;

/// The vDSO page's magic (`crates/core/mm/src/vdso.rs`, `VDSO_MAGIC`).
pub const VDSO_MAGIC: u32 = 0x5644_534F;

/// vDSO `flags` bit 0: `rdtime` executes natively on this machine, so reading
/// the counter from ring 3 costs no trap (`crates/core/mm/src/vdso.rs`,
/// `VDSO_FLAG_RDTIME_NATIVE`).
pub const VDSO_FLAG_RDTIME_NATIVE: u32 = 1;

/// Does a vDSO page reading `magic` and `flags` say `rdtime` is native?
///
/// Split out of [`uptime`] for the same reason as the conversion: the rest of
/// that function is page reads and a CSR read. A page with the wrong magic is
/// not a page, and its flags mean nothing.
#[inline]
pub const fn rdtime_is_native(magic: u32, flags: u32) -> bool {
    magic == VDSO_MAGIC && flags & VDSO_FLAG_RDTIME_NATIVE != 0
}

/// Does `s` contain a NUL byte anywhere?
///
/// This is the exact predicate the kernel's `copy_cstr_from_user` needs to
/// terminate: it stops at the FIRST zero byte, so the contract is *contains*
/// a NUL, not *ends with* one. A 256-byte scratch buffer holding
/// `b"/fat/X\0"` plus trailing slack is legal and must not be rejected.
///
/// Cost: O(len), one byte-compare per byte, on paths bounded by the kernel's
/// `SYS_PATH_MAX` (256). Every caller is a filesystem or service-registry
/// syscall — none is on a control-loop hot path. Nothing in the hot path
/// (`sensor_read`, `motor_speed`, `write`) calls this.
#[inline]
pub fn has_nul(s: &[u8]) -> bool {
    let mut i = 0;
    while i < s.len() {
        if s[i] == 0 {
            return true;
        }
        i += 1;
    }
    false
}

/// Build a `sockaddr_in` in the exact 16-byte layout
/// `read_sockaddr` parses (`crates/core/syscall/src/handlers.rs:789`):
/// `family(u16 LE) | port(u16 BE) | addr(4 bytes) | 8 bytes pad`.
///
/// The kernel reads exactly 16 bytes, never `addrlen`, so handing it a
/// shorter buffer is a read past the end of the caller's object. Producing
/// the array here is what makes `&[u8; 16]` on `bind`/`connect` enforceable.
pub fn sockaddr_in(ip: [u8; 4], port: u16) -> [u8; 16] {
    /// AF_INET, as `read_sockaddr` expects it (little-endian u16).
    const AF_INET: u16 = 2;
    let mut sa = [0u8; 16];
    let fam = AF_INET.to_le_bytes();
    let p = port.to_be_bytes();
    sa[0] = fam[0];
    sa[1] = fam[1];
    sa[2] = p[0];
    sa[3] = p[1];
    sa[4] = ip[0];
    sa[5] = ip[1];
    sa[6] = ip[2];
    sa[7] = ip[3];
    sa
}

// The SPSC ring over shared memory moved to `azos_spsc` (wave 11,
// SHMRING): the kernel now produces into it too, so its layout is shared by
// both sides. `lib.rs` re-exports it, so every `azos_libsys::SpscRing`
// path still resolves.

// ── The process fd table (RFC-0055, wave 11) ────────────────────────────────

/// Small fds a process has: 0..=7, the ones a `SYS_SPAWN_EX` move list names.
pub const FD_TABLE_LEN: usize = 8;

/// What one small fd is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FdEntry {
    /// Not open.
    Closed,
    /// The console (`SYS_WRITE` for writes; there is no console read).
    Console,
    /// A capability handle (a `Cap<File>` descriptor or a `Cap<Pipe>` end).
    Handle(u32),
}

/// fds 0..=7 over capabilities, in user space: the kernel has no `dup`
/// (decision 38), so `dup`/`dup2` alias one handle here and only the LAST
/// close of a handle reaches the kernel (`SYS_CLOSE_TYPED`). Without a
/// startup block it is the old rule: 1 and 2 are the console.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FdTable {
    fds: [FdEntry; FD_TABLE_LEN],
}

impl FdTable {
    /// fd 1 and 2 the console, the rest closed.
    pub const fn new() -> Self {
        let mut fds = [FdEntry::Closed; FD_TABLE_LEN];
        fds[1] = FdEntry::Console;
        fds[2] = FdEntry::Console;
        Self { fds }
    }

    /// From a startup block's fd list (`azos_abi::ushell::FD_*`).
    pub fn fd_table_from_startup(fds: &[azos_abi::ushell::StartupFd; FD_TABLE_LEN]) -> Self {
        use azos_abi::ushell::{FD_CONSOLE, FD_HANDLE};
        let mut t = Self { fds: [FdEntry::Closed; FD_TABLE_LEN] };
        for (i, f) in fds.iter().enumerate() {
            t.fds[i] = match f.kind {
                FD_CONSOLE => FdEntry::Console,
                FD_HANDLE if f.handle != 0 => FdEntry::Handle(f.handle),
                _ => FdEntry::Closed,
            };
        }
        t
    }

    /// What `fd` is (`Closed` past the table).
    pub fn fd_slot(&self, fd: u64) -> FdEntry {
        if (fd as usize) < FD_TABLE_LEN { self.fds[fd as usize] } else { FdEntry::Closed }
    }

    fn fd_refs(&self, h: u32) -> usize {
        self.fds.iter().filter(|e| **e == FdEntry::Handle(h)).count()
    }

    /// Close `fd`. Returns the handle the kernel must now close (its last
    /// reference went), `None` otherwise.
    pub fn fd_release(&mut self, fd: u64) -> Option<u32> {
        let e = self.fd_slot(fd);
        if (fd as usize) < FD_TABLE_LEN {
            self.fds[fd as usize] = FdEntry::Closed;
        }
        match e {
            FdEntry::Handle(h) if self.fd_refs(h) == 0 => Some(h),
            _ => None,
        }
    }

    /// `dup`: the lowest closed fd now names what `fd` does. `None` when
    /// `fd` is closed or the table is full.
    pub fn fd_alias(&mut self, fd: u64) -> Option<u64> {
        let e = self.fd_slot(fd);
        if e == FdEntry::Closed {
            return None;
        }
        let free = self.fds.iter().position(|x| *x == FdEntry::Closed)?;
        self.fds[free] = e;
        Some(free as u64)
    }

    /// `dup2`: `new` names what `old` does, closing what `new` named first.
    /// Returns `Err(())` for a closed `old` or an out-of-range fd, else the
    /// handle the kernel must now close, if `new`'s old handle lost its last
    /// reference.
    #[allow(clippy::result_unit_err)]
    pub fn fd_alias_to(&mut self, old: u64, new: u64) -> Result<Option<u32>, ()> {
        let e = self.fd_slot(old);
        if e == FdEntry::Closed || new as usize >= FD_TABLE_LEN {
            return Err(());
        }
        if old == new {
            return Ok(None);
        }
        let gone = self.fd_release(new);
        self.fds[new as usize] = e;
        // `new` may have named the same handle `old` does: then it is still
        // referenced and must not be closed.
        Ok(gone.filter(|h| self.fd_refs(*h) == 0))
    }

    /// Install `h` as `fd` (a handle the program obtained itself, e.g. one end
    /// of a pipe it means to pass on). Returns the handle to close, as
    /// [`FdTable::fd_alias_to`].
    pub fn fd_put_handle(&mut self, fd: u64, h: u32) -> Option<u32> {
        if fd as usize >= FD_TABLE_LEN {
            return None;
        }
        let gone = self.fd_release(fd);
        self.fds[fd as usize] = FdEntry::Handle(h);
        gone.filter(|g| self.fd_refs(*g) == 0)
    }
}

impl Default for FdTable {
    fn default() -> Self {
        Self::new()
    }
}

/// The `i`-th of the NUL-terminated strings in `blob`.
pub fn cstr_at(blob: &[u8], i: usize) -> Option<&[u8]> {
    blob.split(|&b| b == 0).take(azos_abi::ushell::count_cstrs(blob)?).nth(i)
}

/// The value of `key` in a blob of `KEY=VALUE` strings.
pub fn env_lookup<'a>(blob: &'a [u8], key: &[u8]) -> Option<&'a [u8]> {
    let n = azos_abi::ushell::count_cstrs(blob)?;
    blob.split(|&b| b == 0).take(n).find_map(|kv| {
        kv.strip_prefix(key).and_then(|rest| rest.strip_prefix(b"="))
    })
}

/// A 16-byte port event, decoded (the layout `SYS_PORT_POLL_TYPED` and
/// `SYS_PORT_WAIT_UNTIL_TYPED` write).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PortEventInfo {
    /// The key the source was bound with.
    pub key: u64,
    /// `PORT_EVENT_*`.
    pub source_type: u8,
    /// A positive errno for a notice (`ENOSENDERS`, `EREVOKED`,
    /// `EPEERDIED`), 0 for an ordinary event.
    pub code: u16,
    /// The capability handle the source was bound with (the line for an IRQ).
    pub source_id: u32,
}

/// Decode a port event: key (bytes 0..8), source type (8), code (10..12),
/// source id (12..16), little-endian.
pub fn port_event_decode(b: &[u8; 16]) -> PortEventInfo {
    let c = azos_abi::syscall_nr::PORT_EVENT_CODE_OFFSET;
    PortEventInfo {
        key: u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]),
        source_type: b[8],
        code: u16::from_le_bytes([b[c], b[c + 1]]),
        source_id: u32::from_le_bytes([b[12], b[13], b[14], b[15]]),
    }
}

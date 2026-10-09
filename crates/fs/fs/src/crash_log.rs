// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Rotation policy and mechanism for the FAT32 crash black box,
//! `/fat/CRASH.LOG`.
//!
//! **The problem this closes.** `kernel/src/panic.rs` opened the log
//! `O_WRONLY|O_CREAT|O_APPEND` on every panic, with nothing capping how big
//! it could get. The append path loads the WHOLE existing file to build its
//! proxy inode, capped at `vfs::MAX_FAT32_PROXY_BYTES` (8 MiB) — so past that
//! ceiling the open FAILED and the panic that triggered it was never
//! recorded. A black box that stops recording exactly when the board has
//! crashed enough times to need one is not a black box.
//!
//! **The policy.** Cap the log at [`CRASH_LOG_CAP`] (128 entries of
//! `kernel/src/panic.rs`'s `CRASH_ENTRY_MAX`, 512 B, each). When an append
//! would exceed the cap, the current contents move to `/fat/CRASH.OLD`
//! (`O_CREAT|O_TRUNC`, best-effort) and `/fat/CRASH.LOG` is truncated and
//! rewritten with just the new entry. **Order matters for a black box: the
//! new entry is recorded even if the `CRASH.OLD` copy fails** — see
//! [`record_entry_with_cap`]'s doc for why and how that is enforced.
//!
//! **Why this file exists on its own, not inlined in `panic.rs`.** The
//! rotation DECISION — [`plan_rotation`] — is a pure function of two sizes
//! and a cap: no I/O, no locks. `tests/host/fs-tests` pulls this file with
//! `#[path]`, the same way it pulls `fat32.rs` and `vfs.rs`, so the decision
//! AND the real open/write/close sequence in [`record_entry_with_cap`] both
//! run against the real `vfs.rs` on the host, with no QEMU boot required.
//!
//! **Why the cap is a parameter, not baked into every function.** A test
//! that wants to see `Rotate` chosen needs a volume that holds `CRASH.LOG` at
//! its cap AND `CRASH.OLD` at the same size at once — at the real 64 KiB cap
//! that is a bigger fixture than this crate's tests build elsewhere for no
//! reason. `record_entry_with_cap` takes the cap explicitly; [`record_entry`]
//! is the one-argument call `kernel/src/panic.rs` uses, fixed at
//! [`CRASH_LOG_CAP`].

use crate::vfs::{
    self, FdTableN, O_APPEND, O_CREAT, O_RDONLY, O_TRUNC, O_WRONLY,
};

/// Path of the live crash log. Centralised here so `panic.rs` and the
/// rotation logic cannot name it two different ways.
pub const CRASH_LOG_PATH: &[u8] = b"/fat/CRASH.LOG";
/// Path the previous contents of `CRASH_LOG_PATH` are copied to on rotation.
pub const CRASH_LOG_OLD_PATH: &[u8] = b"/fat/CRASH.OLD";

/// Cap on `CRASH.LOG`'s size: 128 entries of `CRASH_ENTRY_MAX` (512 B) each.
/// Also the bound that removes the `MAX_FAT32_PROXY_BYTES` failure mode by
/// construction — every `O_APPEND` open this module performs is of a file
/// this size or smaller, always far under the 8 MiB proxy ceiling.
pub const CRASH_LOG_CAP: usize = 64 * 1024;

/// Chunk size for the best-effort `CRASH.LOG` → `CRASH.OLD` copy on
/// rotation. Matches `CRASH_ENTRY_MAX` in `kernel/src/panic.rs` — the one
/// buffer magnitude the panic path already commits to — rather than adding a
/// second, larger static for a copy that (at the real cap) is at most 128
/// chunks.
const COPY_CHUNK: usize = 512;

/// What [`record_entry_with_cap`] should do, given the log's CURRENT size and
/// the new entry's length. Pure: no I/O, no locks, no allocation — so
/// `tests/host/fs-tests` can drive it with bare integers and no mounted volume at
/// all, and the real callers below share exactly this decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RotationPlan {
    /// `current_size + entry_len` fits within `cap`: append in place.
    Append,
    /// It does not: copy `CRASH_LOG_PATH` to `CRASH_LOG_OLD_PATH`
    /// (best-effort), then truncate `CRASH_LOG_PATH` and write the new entry
    /// as its sole content.
    Rotate,
}

/// Decide the plan. `current_size + entry_len > cap` rotates; landing
/// exactly on the cap still fits and appends. Saturates rather than
/// overflowing on a pathological `current_size` (e.g. a directory entry an
/// attacker-controlled volume claims is near `u32::MAX`) — the answer is
/// still `Rotate`, which is the safe side to saturate towards.
pub fn plan_rotation(current_size: usize, entry_len: usize, cap: usize) -> RotationPlan {
    if current_size.saturating_add(entry_len) > cap {
        RotationPlan::Rotate
    } else {
        RotationPlan::Append
    }
}

/// Whether the new entry actually landed in `CRASH_LOG_PATH`, independent of
/// rotation. Mirrors the three-way distinction `kernel/src/panic.rs` already
/// prints for the plain-append case (written / FLUSH FAILED / NOT written).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteResult {
    /// Opened, written, and closed (flushed) without error.
    Written,
    /// The open succeeded and the write was accepted, but `vfs_close`'s
    /// flush to the backend failed — the bytes did not reach the device.
    FlushFailed,
    /// The open itself failed; nothing was written.
    NotWritten,
}

/// What [`record_entry_with_cap`] actually did — the write outcome for the
/// entry (always meaningful) plus whether rotation was needed and, if so,
/// whether the `CRASH.OLD` copy succeeded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordOutcome {
    pub write: WriteResult,
    pub rotated: bool,
    /// Only meaningful when `rotated` is `true`. `true` when `rotated` is
    /// `false` (nothing to report).
    pub old_copy_ok: bool,
}

/// Record one crash-log entry, rotating first if it would not fit under
/// `cap`. [`record_entry`] is the fixed-cap call `kernel/src/panic.rs` uses;
/// this one exists so tests can drive rotation with a cap small enough for a
/// cheap fixture.
///
/// **Order matters for a black box.** When [`plan_rotation`] says `Rotate`,
/// [`copy_log_to_old`] runs FIRST and its result is carried into the
/// returned [`RecordOutcome`], but a failed copy does NOT skip the
/// truncate-and-write that follows it — that call happens unconditionally on
/// the `Rotate` arm, whatever `copy_log_to_old` returned. Losing history is
/// bad; losing the panic that just happened — the one write this whole path
/// exists for — is worse.
pub fn record_entry_with_cap<const N: usize>(
    table: &mut FdTableN<N>,
    entry: &[u8],
    cap: usize,
) -> RecordOutcome {
    let current_size = vfs::vfs_file_size(CRASH_LOG_PATH).unwrap_or(0) as usize;

    match plan_rotation(current_size, entry.len(), cap) {
        RotationPlan::Append => {
            let write = write_whole(table, CRASH_LOG_PATH, O_WRONLY | O_CREAT | O_APPEND, entry);
            RecordOutcome { write, rotated: false, old_copy_ok: true }
        }
        RotationPlan::Rotate => {
            let old_copy_ok = copy_log_to_old(table);
            let write = write_whole(table, CRASH_LOG_PATH, O_WRONLY | O_CREAT | O_TRUNC, entry);
            RecordOutcome { write, rotated: true, old_copy_ok }
        }
    }
}

/// [`record_entry_with_cap`] fixed at [`CRASH_LOG_CAP`] — what
/// `kernel/src/panic.rs` calls on every panic.
pub fn record_entry<const N: usize>(table: &mut FdTableN<N>, entry: &[u8]) -> RecordOutcome {
    record_entry_with_cap(table, entry, CRASH_LOG_CAP)
}

/// Open `path` with `flags`, write the whole of `entry`, close. The one
/// open/write/close shape both the append arm and the post-rotation write
/// use — `flags` is the only thing that differs between them.
fn write_whole<const N: usize>(
    table: &mut FdTableN<N>,
    path: &[u8],
    flags: u32,
    entry: &[u8],
) -> WriteResult {
    let fd = vfs::vfs_open(table, path, flags);
    if fd < 0 {
        return WriteResult::NotWritten;
    }
    vfs::vfs_write(table, fd, entry.as_ptr(), entry.len());
    // Durable before the call returns: a close is not a durability point
    // under FAT32's write-back cache (wave 15), an fsync is.
    let synced = vfs::vfs_fsync(table, fd).is_ok();
    if vfs::vfs_close(table, fd) == 0 && synced {
        WriteResult::Written
    } else {
        WriteResult::FlushFailed
    }
}

/// Best-effort copy of the WHOLE current `CRASH_LOG_PATH` to
/// `CRASH_LOG_OLD_PATH`, in `COPY_CHUNK`-sized pieces so no buffer bigger
/// than the panic path already commits to is ever required. Returns `false`
/// on ANY failure — source open, destination open, a short read/write, or a
/// failed close on either side.
///
/// Deliberately does not touch `CRASH_LOG_PATH` itself: the caller
/// truncates and rewrites it in a separate step, regardless of what this
/// function returns.
fn copy_log_to_old<const N: usize>(table: &mut FdTableN<N>) -> bool {
    let src = vfs::vfs_open(table, CRASH_LOG_PATH, O_RDONLY);
    if src < 0 {
        return false;
    }
    let dst = vfs::vfs_open(table, CRASH_LOG_OLD_PATH, O_WRONLY | O_CREAT | O_TRUNC);
    if dst < 0 {
        vfs::vfs_close(table, src);
        return false;
    }

    static mut COPY_BUF: [u8; COPY_CHUNK] = [0u8; COPY_CHUNK];
    // Safety: the panic handler is single-threaded per hart and this
    // function has no re-entrant caller (the other harts are halted before
    // any panic-path write runs — see `kernel/src/panic.rs`'s module doc).
    // `tests/host/fs-tests` serialises its own tests with `serial()` for the
    // same reason every other static fixture in that suite is.
    let buf = unsafe { &mut *(&raw mut COPY_BUF) };
    let mut ok = true;
    loop {
        let n = vfs::vfs_read(table, src, buf.as_mut_ptr(), buf.len());
        if n < 0 {
            ok = false;
            break;
        }
        if n == 0 {
            break;
        }
        let w = vfs::vfs_write(table, dst, buf.as_ptr(), n as usize);
        if w != n {
            ok = false;
            break;
        }
    }

    let src_closed = vfs::vfs_close(table, src) == 0;
    let dst_closed = vfs::vfs_close(table, dst) == 0;
    ok && src_closed && dst_closed
}

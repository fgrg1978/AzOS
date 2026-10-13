// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `readv`/`writev`: the iovec walk, its pure half (wave 15, K2).
//!
//! Linux moves a vectored call as ONE transfer: `writev` gathers the
//! segments and makes one write, so another writer of the same open file
//! description, pipe or terminal never lands between two segments (a pipe
//! write of at most `PIPE_BUF` bytes is all-or-nothing, a regular file's
//! write runs under the description's position lock); `readv` makes one read
//! and scatters it. The translation (`crates/core/syscall/src/linux.rs`)
//! hands [`writev`] and [`readv`] one bounce buffer and one typed operation,
//! called once per call.
//!
//! The iovec array is the caller's memory and untrusted: every access goes
//! through [`IovMem`]. As Linux's `import_iovec`, every entry is read and
//! checked before any transfer: more than [`UIO_MAXIOV`] entries or a length
//! that is negative as a `ssize_t` is `-EINVAL`, an unreadable array
//! `-EFAULT`. The transfer is cut at the bounce buffer's length (the
//! personality's per-call clamp, Kconfig `LINUX_IO_MAX`): a short count, as
//! a plain `write`/`read` of more than that.

use crate::errno as le;

/// Most iovec entries one call takes (Linux `UIO_MAXIOV`).
pub const UIO_MAXIOV: u64 = 1024;
/// `sizeof(struct iovec)` on a 64-bit ISA: `iov_base`, `iov_len`.
pub const IOVEC_LEN: u64 = 16;

/// The calling thread's memory, as the walk needs it.
pub trait IovMem {
    /// The 64-bit word at `addr`; `None` if the thread cannot read it.
    fn word(&mut self, addr: u64) -> Option<u64>;
    /// `dst.len()` bytes from user `base`; false (and nothing promised in
    /// `dst`) on a fault.
    fn copy_in(&mut self, dst: &mut [u8], base: u64) -> bool;
    /// `src` to user `base`; false on a fault.
    fn copy_out(&mut self, base: u64, src: &[u8]) -> bool;
    /// May `[base, base + len)` be written? Asked before the destructive
    /// read, so a bad destination costs no consumed bytes.
    fn writable(&mut self, base: u64, len: usize) -> bool;
}

/// Entry `i`: `(base, len)`, `Err` already as the negative Linux errno.
fn entry<M: IovMem>(mem: &mut M, iov: u64, i: u64) -> Result<(u64, u64), i64> {
    let at = iov.checked_add(i * IOVEC_LEN).ok_or(-le::EFAULT)?;
    let (Some(base), Some(len)) = (mem.word(at), at.checked_add(8).and_then(|a| mem.word(a))) else {
        return Err(-le::EFAULT);
    };
    if (len as i64) < 0 {
        return Err(-le::EINVAL);
    }
    Ok((base, len))
}

/// `writev`: gather the segments, in order, into `buf` (at most its length)
/// and make ONE `write` of what was gathered. Returns the count `write`
/// returned, a negative Linux errno, or 0 for nothing to write (`write`
/// not called). A segment that faults ends the gather: the bytes before it
/// are written (Linux's short count); none, `-EFAULT`.
pub fn writev<M: IovMem>(
    mem: &mut M,
    iov: u64,
    cnt: u64,
    buf: &mut [u8],
    mut write: impl FnMut(&[u8]) -> i64,
) -> i64 {
    if cnt > UIO_MAXIOV {
        return -le::EINVAL;
    }
    let mut n = 0usize;
    let mut fault = false;
    for i in 0..cnt {
        let (base, len) = match entry(mem, iov, i) {
            Ok(e) => e,
            Err(e) => return e,
        };
        if fault || len == 0 || n == buf.len() {
            continue; // every entry is still checked
        }
        let k = (len.min((buf.len() - n) as u64)) as usize;
        if mem.copy_in(&mut buf[n..n + k], base) {
            n += k;
        } else {
            fault = true;
        }
    }
    if n == 0 {
        return if fault { -le::EFAULT } else { 0 };
    }
    if cfg!(feature = "writev-per-segment-canary") {
        // Gate canary: the per-segment loop this replaced (one write per
        // iovec, another writer free to land in between). Breaks K2.
        return per_segment(mem, iov, cnt, &buf[..n], &mut write);
    }
    write(&buf[..n])
}

/// The canary's shape: the gathered bytes, one `write` per segment.
fn per_segment<M: IovMem>(mem: &mut M, iov: u64, cnt: u64, all: &[u8], write: &mut impl FnMut(&[u8]) -> i64) -> i64 {
    let mut done = 0usize;
    for i in 0..cnt {
        let Ok((_, len)) = entry(mem, iov, i) else { break };
        let k = (len as usize).min(all.len() - done);
        if k == 0 {
            continue;
        }
        let r = write(&all[done..done + k]);
        if r < 0 {
            return if done > 0 { done as i64 } else { r };
        }
        done += r as usize;
        if (r as usize) < k || done == all.len() {
            break;
        }
    }
    done as i64
}

/// `readv`: ONE `read` of at most `buf.len()` bytes (and at most the
/// segments' writable prefix), scattered over the segments in order.
/// Returns the count scattered, a negative Linux errno, or 0 (nothing to
/// read: `read` not called). Every destination is checked writable BEFORE
/// the read; the first that is not ends the plan there (none: `-EFAULT`).
/// If the iovec array changes under the call (another thread), a segment
/// that then faults ends the scatter at the bytes already delivered.
pub fn readv<M: IovMem>(
    mem: &mut M,
    iov: u64,
    cnt: u64,
    buf: &mut [u8],
    read: impl FnOnce(&mut [u8]) -> i64,
) -> i64 {
    if cnt > UIO_MAXIOV {
        return -le::EINVAL;
    }
    let mut want = 0usize;
    let mut fault = false;
    for i in 0..cnt {
        let (base, len) = match entry(mem, iov, i) {
            Ok(e) => e,
            Err(e) => return e,
        };
        if fault || len == 0 || want == buf.len() {
            continue;
        }
        let k = (len.min((buf.len() - want) as u64)) as usize;
        if mem.writable(base, k) {
            want += k;
        } else {
            fault = true;
        }
    }
    if want == 0 {
        return if fault { -le::EFAULT } else { 0 };
    }
    let r = read(&mut buf[..want]);
    if r <= 0 {
        return r;
    }
    let got = (r as usize).min(want);
    let mut done = 0usize;
    for i in 0..cnt {
        if done == got {
            break;
        }
        let Ok((base, len)) = entry(mem, iov, i) else { break };
        let k = (len.min((got - done) as u64)) as usize;
        if k == 0 {
            continue;
        }
        if !mem.copy_out(base, &buf[done..done + k]) {
            break;
        }
        done += k;
    }
    done as i64
}

// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Anonymous memory: `SYS_MO_MAP` placed at the break, `SYS_MO_UNMAP`.
//!
//! A guard is a mapping with `prot = 0`: the kernel reserves the range and
//! maps nothing, so a touch kills the task. A body with its two guards is
//! three consecutive calls; if another thread's map came between them the
//! three are not adjacent and the set is dropped and made again.

use crate::sys::syscall6;
use azos_abi::syscall_nr::{SYS_MO_MAP, SYS_MO_UNMAP};

pub use crate::config::PAGE_SIZE;

const PROT_READ: u64 = 1;
const PROT_WRITE: u64 = 2;
const ATTEMPTS: usize = 4;

fn raw_map(len: usize, prot: u64) -> Option<usize> {
    // SAFETY: a plain call; the kernel validates every argument.
    let r = unsafe { syscall6(SYS_MO_MAP, 0, 0, len as u64, prot, 0, 0) };
    (r > 0).then_some(r as usize)
}

fn raw_unmap(base: usize, len: usize) {
    // SAFETY: as above.
    unsafe { syscall6(SYS_MO_UNMAP, 0, base as u64, len as u64, 0, 0, 0) };
}

/// Round `n` up to a page.
pub const fn page_up(n: usize) -> usize {
    (n + PAGE_SIZE - 1) & !(PAGE_SIZE - 1)
}

/// `len` bytes (a page multiple) of zeroed read-write memory at a page
/// aligned address. With `guards`, one reserved page lies before and one
/// after it. `None` when the kernel cannot place them.
pub fn map(len: usize, guards: bool) -> Option<usize> {
    if !guards {
        return raw_map(len, PROT_READ | PROT_WRITE);
    }
    for _ in 0..ATTEMPTS {
        let before = raw_map(PAGE_SIZE, 0);
        let body = raw_map(len, PROT_READ | PROT_WRITE);
        let after = raw_map(PAGE_SIZE, 0);
        match (before, body, after) {
            (Some(g0), Some(b), Some(g1)) if b == g0 + PAGE_SIZE && g1 == b + len => return Some(b),
            (_, Some(b), _) => raw_unmap(b, len),
            _ => return None,
        }
    }
    None
}

/// Give back what [`map`] returned (the guards hold no page: only the body
/// is unmapped).
pub fn unmap(base: usize, len: usize) {
    raw_unmap(base, len);
}

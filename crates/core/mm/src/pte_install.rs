// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Lock-free installs of page-table words that two writers may race for
//! (N12h).
//!
//! A user root's level-1 table in a merge slot (user code beside the kernel's
//! low device windows) has two writers: the task's own mapper (`walk`,
//! `map_mega`, under no shared lock) and the kernel-half merge
//! (`copy_kernel_entries_to_user`, `propagate_kernel_entries`, under
//! `PT_META`). Both install a word only where the slot was empty, so both do
//! it by compare-and-swap from the empty word they read: a plain store after
//! the read would overwrite the other side's table, and its mappings with it.
//! The loser adopts the winner's word. When both words are level-0 tables,
//! the merge copies the kernel's leaves into the winner's table
//! ([`fill_empty`]), so the root reaches the device and keeps its own pages.
//!
//! Plain data over `AtomicU64` words with the PTE predicates passed in: no
//! page table, no lock, no allocator, so the host tests pull this file in
//! with `#[path]` and race the real code.

use core::sync::atomic::{AtomicU64, Ordering};

/// Install `new` in `slot` if it still holds `seen`, the empty word the
/// caller read. `Ok(())`: this call installed it. `Err(cur)`: another writer
/// installed `cur` first; the caller adopts it (descends into it, merges into
/// it, or reports the slot taken) and frees anything it built for `new`.
#[inline]
pub fn install(slot: &AtomicU64, seen: u64, new: u64) -> Result<(), u64> {
    slot.compare_exchange(seen, new, Ordering::AcqRel, Ordering::Acquire)
        .map(|_| ())
}

/// Copy into `dst` every word of `src` that is valid and that `take` accepts,
/// where `dst`'s word is `empty`, each by [`install`]: a word another writer
/// installed meanwhile is kept, never overwritten, and so is an invalid word
/// that is not `empty` (a demand-paging reservation marker). Returns the
/// words written. `dst` and `src` are tables of the same level and length.
pub fn fill_empty(
    dst: &[AtomicU64],
    src: &[AtomicU64],
    empty: u64,
    valid: impl Fn(u64) -> bool,
    take: impl Fn(u64) -> bool,
) -> usize {
    let mut written = 0usize;
    for (d, s) in dst.iter().zip(src.iter()) {
        let w = s.load(Ordering::Relaxed);
        if !valid(w) || !take(w) {
            continue;
        }
        if install(d, empty, w).is_ok() {
            written += 1;
        }
    }
    written
}

/// One level of a WRITER's descent through a user root, walked in step with
/// the kernel root (N12i). `kt` is the kernel's table at this level on the
/// same path (0 once the kernel has none there), `child` the table the user
/// root's word names, the one the writer is about to follow, and `kword`
/// reads the kernel table's word at the same index.
///
/// `Err(())`: `child` IS the kernel's table, shared by every root that
/// links it; a USER leaf written below it would be mapped in every address
/// space, so the writer must stop. `Ok(next)`: the kernel's table one level
/// down (0 if none), for the next step.
///
/// The check is on the word the writer follows, read after the push could
/// have linked it, never on an earlier read: a kernel-half push only ever
/// installs a link where the root's word was empty (`install`), so once the
/// writer follows a table that is not the kernel's, nothing replaces it.
#[inline]
pub fn shadow_step(
    kt: usize,
    child: usize,
    kword: impl FnOnce() -> u64,
    is_table: impl Fn(u64) -> bool,
    phys: impl Fn(u64) -> usize,
) -> Result<usize, ()> {
    if kt == 0 {
        return Ok(0);
    }
    let w = kword();
    if !is_table(w) {
        return Ok(0);
    }
    let k = phys(w);
    if k == child { Err(()) } else { Ok(k) }
}

/// May a user unmap path clear `word` (N12i)? Not when it is the kernel's: a
/// valid leaf without USER that maps the same frame the kernel root maps at
/// that address is a device window the kernel-half merge copied into the
/// task's own table (`fill_empty`, or an L1 fill), through which the kernel
/// reaches the device while that task is current. Anything else is the
/// task's: a USER leaf, an invalid word (empty, or its own demand marker),
/// or a kernel-permission leaf only this root maps (a smoke's private page).
/// `kernel_maps_same` is asked only for a valid non-USER word.
#[inline]
pub fn user_may_modify(
    word: u64,
    valid: impl Fn(u64) -> bool,
    user: impl Fn(u64) -> bool,
    kernel_maps_same: impl FnOnce() -> bool,
) -> bool {
    !valid(word) || user(word) || !kernel_maps_same()
}

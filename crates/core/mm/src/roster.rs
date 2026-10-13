// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The merged-root roster walk, one lock hold per visited entry (FX7, FX8).
//!
//! `vmm::with_merged_roots` and `vmm::propagate_kernel_entries` visit every
//! root of the merged-root roster under `PT_META`. Held for the whole roster,
//! the hold grows with the task count: a ktest checking every root held it 140 us
//! (`LOCK_MAX_HOLD_US` 100) under -icount. [`resume_walk`] takes the lock
//! once per visited entry instead: scan from the index after the last one
//! visited, run `visit` on the first live entry, drop the lock, repeat. One
//! hold is one scan plus one `visit`, whatever the roster's length.
//!
//! Depends on `core` only: `tests/host/mm-tests` pulls this file with
//! `#[path]` and drives it with a host mutex.

/// Visit every index `i < len` for which `live(&guard, i)` holds, each under
/// its own `hold()`. An entry that becomes live or dead between two holds may
/// or may not be visited; every entry that is visited is live, under the
/// guard, for its whole `visit`. Stops at the first `Err` (the guard is
/// dropped with it); `Ok(entries visited)`.
pub fn resume_walk<G, E>(
    len: usize,
    mut hold: impl FnMut() -> G,
    live: impl Fn(&G, usize) -> bool,
    mut visit: impl FnMut(&G, usize) -> Result<(), E>,
) -> Result<usize, E> {
    let mut n = 0usize;
    let mut from = 0usize;
    while from < len {
        let g = hold();
        let Some(i) = (from..len).find(|&i| live(&g, i)) else {
            break;
        };
        visit(&g, i)?;
        drop(g);
        n += 1;
        from = i + 1;
    }
    Ok(n)
}

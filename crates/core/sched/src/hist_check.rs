// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Child module of `scheduler.rs` (pulled in with `#[path]`), moved out of it unchanged.

use super::{hist_key_of, HIST_KEY, MAX_TASKS, TASKS};
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
pub static CHECKS: AtomicU32 = AtomicU32::new(0);
pub static MISMATCH: AtomicU32 = AtomicU32::new(0);
pub static PICK_DIFF: AtomicU32 = AtomicU32::new(0);
/// Mismatching queries during which some slot's recorded key differed
/// from the key its live fields give (a transition whose re-account
/// had not run yet), and those during which none did (the scan read
/// fields mid-write, or an `apply` was between its swap and its
/// counter updates).
pub static MISMATCH_STALE_KEY: AtomicU32 = AtomicU32::new(0);
pub static MISMATCH_NO_STALE_KEY: AtomicU32 = AtomicU32::new(0);
/// Drift episodes: a slot whose recorded key differed from its live key
/// for `CONFIRM_TICKS` straight, same pair of keys throughout — a
/// transition no re-account followed. Counted once per episode.
pub static DRIFT: AtomicU32 = AtomicU32::new(0);
pub static AUDITS: AtomicU32 = AtomicU32::new(0);

const CONFIRM_TICKS: u64 = 100_000; // 10 ms at 10 MHz

static SINCE: [AtomicU64; MAX_TASKS] = [const { AtomicU64::new(0) }; MAX_TASKS];
static PAIR: [AtomicU64; MAX_TASKS] = [const { AtomicU64::new(0) }; MAX_TASKS];

/// Whether any slot's recorded key differs from its live key right now.
pub(super) fn any_stale_key() -> bool {
    (0..MAX_TASKS).any(|i| unsafe { HIST_KEY[i].load(Ordering::Relaxed) != hist_key_of(i) })
}

/// Per-tick drift audit (called from the tick's `reap_stamped_sleepers`).
pub(super) fn audit_tick(now: u64) {
    AUDITS.fetch_add(1, Ordering::Relaxed);
    for i in 0..MAX_TASKS {
        let rec = HIST_KEY[i].load(Ordering::Relaxed);
        let live = unsafe { hist_key_of(i) };
        // A timer wake of this slot in progress on another hart is
        // between its state CAS and its re-account: every hart programs
        // the same nearest deadline, so ticks land in that window
        // together. Not drift.
        #[cfg(feature = "sched-timer-heap")]
        let waking = super::timer_sleepers::inflight(i);
        #[cfg(not(feature = "sched-timer-heap"))]
        let waking = false;
        if rec == live || waking {
            SINCE[i].store(0, Ordering::Relaxed);
            continue;
        }
        let pair = (u64::from(rec) << 32) | u64::from(live);
        let since = SINCE[i].load(Ordering::Relaxed);
        if since == 0 || PAIR[i].load(Ordering::Relaxed) != pair {
            SINCE[i].store(now.max(1), Ordering::Relaxed);
            PAIR[i].store(pair, Ordering::Relaxed);
        } else if since != u64::MAX && now.saturating_sub(since) >= CONFIRM_TICKS {
            SINCE[i].store(u64::MAX, Ordering::Relaxed);
            if DRIFT.fetch_add(1, Ordering::Relaxed) < 4 {
                let t = unsafe { &*core::ptr::addr_of!(TASKS[i]) };
                let len = t.name.iter().position(|&x| x == 0).unwrap_or(t.name.len());
                azos_drv_sys::kprintln!(
                    "[SCHED] HIST_DRIFT slot={} name={} recorded={:#x} live={:#x} \
                     state={:?} prio={} affinity={} tp={} for_ticks={} ready_site={:#x}",
                    i,
                    core::str::from_utf8(&t.name[..len]).unwrap_or("<?>"),
                    rec, live, t.state(), t.priority.load(Ordering::Relaxed),
                    t.cpu_affinity, t.context.tp, now - since,
                    t.ready_site.load(Ordering::Relaxed),
                );
            }
        }
    }
}

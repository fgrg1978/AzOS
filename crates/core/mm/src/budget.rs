// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Per-task frame budget arithmetic (owner decision 102, scan unit 3 finding 3).
//!
//! **WHY THIS FILE EXISTS.** The enforcement — `mm_charge` / `mm_discharge` /
//! `mm_reset_charge` / `set_current_user_page_limit`, all in
//! `crates/core/sched/src/scheduler.rs` — now delegates to `PageBudget`, held as
//! `Task::budget` (`crates/core/sched/src/task.rs`) behind `PER_CPU[cpu].current_idx`.
//! `scheduler.rs` is RV64 context-switch machinery (asm, CSRs, PLIC, a
//! 4000-line global task table) and cannot be `#[path]`-pulled onto the host —
//! the same reason `tests/host/syscall-tests` stands up a hand-written stub for
//! `azos_sched` instead of linking the real crate. So this file is what
//! gives the arithmetic that decides "does this charge succeed" a host test of
//! the REAL code, not a transcription like
//! `tests/host/syscall-tests/shims/sched/src/lib.rs`, which says plainly it is
//! proving the WIRING in `handlers.rs`, not this decision.
//!
//! `PageBudget` is that decision, factored out to where it has no dependency on
//! a task table, a hart, or a scheduler at all — three plain counters and three
//! methods. `tests/host/mm-tests` pulls this file with `#[path]`, the same pattern
//! as `wx.rs` and `cow_table.rs`, and tests the actual shipping code: the twin
//! that used to live inline on `TASKS[idx].{user_pages, user_pages_peak,
//! user_page_limit}` is gone, replaced by the four call sites (`mm_charge`,
//! `mm_discharge`, `mm_reset_charge`, `set_current_user_page_limit`,
//! `current_user_pages`, `mm_peak_pages`, plus the four reset-on-reuse sites:
//! exit-path slot reuse, `set_current_user_info` (exec), `set_task_user_info`
//! (fork), and `mm_reset_charge` itself) all reading/writing `TASKS[idx].budget`.
//! `MM_QUOTA_REFUSALS` and `MM_PEAK_GLOBAL` stay in `scheduler.rs` — they are
//! cross-task globals, not per-task budget state.
//!
//! Semantics are a byte-for-byte transcription of the three functions above,
//! checked against them line by line:
//!   - `pages == 0` is always a no-op success, and never touches the peak.
//!   - `limit == 0` means unlimited.
//!   - the add is **saturating**: this workspace builds with
//!     `overflow-checks = true` and `panic = "abort"` (see `mm-tests`'s own
//!     `[profile.release]`, which reproduces it), so a plain `+` here would be
//!     a board reset on the target, not a caught error. Precedent:
//!     `note_stalled_tick` in `crates/core/actuation/src/watchdog.rs`.
//!   - a charge that would exceed the limit charges **nothing** — partial
//!     charges would leave the counter describing memory the caller did not
//!     get.
//!   - discharge is also saturating: an over-discharge floors at 0 instead of
//!     wrapping to `u32::MAX` and silently disabling the budget.
//!   - `reset` clears both `used` and `peak` — matching `mm_reset_charge`,
//!     which is called on `exec_user` and on exit, where the address space the
//!     peak described is gone too.

/// One task's frame accounting: how much it has charged, the high-water mark,
/// and its declared ceiling. `0` limit means unlimited — the state every task
/// whose topology row does not declare `mem_pages` starts in.
///
/// `repr(C)`: embedded directly as `Task::budget` in
/// `crates/core/sched/src/task.rs`, which is itself `repr(C, align(64))` with
/// `context_switch.S`-hardcoded offsets for the fields that precede this one.
/// Fixing this struct's own layout removes any doubt about the size the
/// three plain `u32`s occupy — same 12 bytes either way, but explicit beats
/// "the default repr happens not to add padding here".
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct PageBudget {
    used: u32,
    peak: u32,
    limit: u32,
}

impl PageBudget {
    pub const fn new() -> Self {
        Self { used: 0, peak: 0, limit: 0 }
    }

    #[must_use]
    pub fn used(&self) -> u32 { self.used }

    #[must_use]
    pub fn peak(&self) -> u32 { self.peak }

    #[must_use]
    pub fn limit(&self) -> u32 { self.limit }

    /// Declare the budget, in 4 KiB pages. `0` = no limit. Mirrors
    /// `set_current_user_page_limit`.
    pub fn set_limit(&mut self, limit: u32) {
        self.limit = limit;
    }

    /// Charge `pages` frames. Returns `false` and charges NOTHING if that would
    /// exceed a nonzero limit. Mirrors `mm_charge` exactly (the cross-task
    /// `MM_QUOTA_REFUSALS`/`MM_PEAK_GLOBAL` counters in `scheduler.rs` are the
    /// caller's job on a `false`/`true` result respectively — this struct only
    /// holds the one task's numbers).
    pub fn charge(&mut self, pages: u32) -> bool {
        if pages == 0 { return true; }
        let next = self.used.saturating_add(pages);
        if self.limit != 0 && next > self.limit {
            return false;
        }
        self.used = next;
        if next > self.peak {
            self.peak = next;
        }
        true
    }

    /// Give `pages` frames back. Mirrors `mm_discharge`.
    pub fn discharge(&mut self, pages: u32) {
        if pages == 0 { return; }
        self.used = self.used.saturating_sub(pages);
    }

    /// Forget the used count AND the peak — the address space either
    /// described is gone. Mirrors `mm_reset_charge`.
    pub fn reset(&mut self) {
        self.used = 0;
        self.peak = 0;
    }
}

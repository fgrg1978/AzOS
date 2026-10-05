// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host stand-in for `azos_sync`, used only by `tests/host/sched-wake-tests`.
//!
//! **WHY this exists.** `crates/core/sched/src/wait.rs` gained one dependency on
//! the K-C29 preemption mechanism: `task_block_outcome` reads this hart's
//! preemption depth and runs it through `voluntary_admission` to report
//! whether `block_current` will refuse to park the caller. `wait.rs` is pulled
//! into `sched-wake-tests` unmodified, so that name has to resolve here.
//!
//! **What is real and what is not — the split is deliberate.**
//!
//! * [`preempt_core`] is the kernel's own module, `#[path]`-pulled, not a
//!   copy. It is pure arithmetic over `(depth, need_resched, irqs_enabled)`
//!   with no arch dependency, which is precisely why it was split out of
//!   `preempt.rs` in the first place (see its module docs). So the
//!   *decision* `task_block_outcome` delegates to — `voluntary_admission`,
//!   `RefuseAtomic` iff `depth > 0` — is the real one. Mutate it in
//!   `crates/core/sync/src/preempt_core.rs` and these tests change.
//!
//! * [`preempt`] is a test double, and only because the real one cannot be
//!   compiled here: `preempt::depth()` reads the hart id out of `tp` via
//!   inline asm to index a per-hart slot array. `tests/host/sync-tests` covers
//!   the real module against its own arch shim; nothing about the atomics,
//!   the guard, or the `need_resched` handling is claimed by *this* crate.
//!   All that is faked is the answer to "what is this hart's depth", which
//!   the tests set explicitly.
//!
//! So a green run here says: given a depth, `task_block_outcome` reports the
//! outcome the kernel's own admission rule dictates, and blocks either way.
//! It does not say anything about how the depth got there.

/// The kernel's real pure decision logic — no stub, no copy.
#[path = "../../../../../../crates/core/sync/src/preempt_core.rs"]
pub mod preempt_core;

/// Test double for the per-hart preemption counter.
///
/// The real module (`crates/core/sync/src/preempt.rs`) indexes a `[PreemptSlot; 8]`
/// by `azos_arch::cpu::hart_id()`, which is inline asm. Here the depth is
/// just a settable cell: these tests drive `task_block_outcome` at chosen
/// depths rather than proving how a depth arises.
pub mod preempt {
    use std::sync::atomic::{AtomicU32, Ordering};

    static DEPTH: AtomicU32 = AtomicU32::new(0);

    /// Matches the real `preempt::depth()` signature exactly, so `wait.rs`
    /// compiles unchanged.
    pub fn depth() -> u32 {
        DEPTH.load(Ordering::SeqCst)
    }

    /// Test-only control surface — not part of the real `azos_sync` API.
    pub fn set_depth(d: u32) {
        DEPTH.store(d, Ordering::SeqCst);
    }
}

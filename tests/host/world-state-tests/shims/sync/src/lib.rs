// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host-buildable facade for `azos_sync`, used only by
//! `tests/host/world-state-tests`. **Not part of the kernel.**
//!
//! `domains/robot/behavior/src/world_state.rs` names `azos_sync::{critical_section,
//! PreemptGuard}` by absolute crate path (it lives in a different crate from
//! `azos_sync` itself, so it cannot use `crate::`). The real
//! `azos_sync` crate cannot be compiled on the host: `spinlock.rs` (which
//! `world_state.rs` does not even use, but the crate as a whole pulls in)
//! names `azos_arch::csr`, and the real `azos_arch` re-exports
//! nothing at all off the RISC-V target (see its own doc comment).
//!
//! This crate is `azos_sync` in name only, aliased in via Cargo (the
//! same trick `tests/host/behavior-tests` already uses for
//! `tests/host/cap-tests/shims/sync`, and `tests/host/sync-tests` uses for its own
//! `azos_arch`). It compiles the REAL `preempt.rs`/`preempt_core.rs` from
//! `crates/core/sync` via `#[path]` — not a copy — and re-exports exactly the two
//! names `world_state.rs` needs, plus the handful of test-facing functions
//! (`depth`, `force_zero_depth`, `set_resched_callback`) the test crate needs
//! to observe and reset state. The two machine reads that code needs
//! (`hart_id()`, `read_sstatus()`) come from `tests/host/sync-tests`'s own arch
//! shim, reused by path rather than duplicated.

// `pub mod`, not a private `mod`: these files carry plenty of API surface
// this crate does not itself call (`fired()`, `deferred()`,
// `set_need_resched()`, the whole `preempt_core` decision layer, ...). A
// private `mod` would make all of that genuinely dead code from rustc's
// point of view and light up `#[warn(dead_code)]` on every one of them; the
// CI gate (`tools/ci_check.sh`) fails a host suite on ANY warning. Matching
// `tests/host/sync-tests`'s own `pub mod preempt`/`pub mod preempt_core` keeps
// this facade's copy of the real modules fully public, which is what makes
// them "used" for dead-code purposes without cherry-picking re-exports.
#[path = "../../../../../../crates/core/sync/src/preempt_core.rs"]
pub mod preempt_core;

#[path = "../../../../../../crates/core/sync/src/preempt.rs"]
pub mod preempt;

pub use preempt::{critical_section, PreemptGuard, depth, disabled, force_zero_depth};

// The REAL `SeqLock`, not a stand-in. Its only dependency is
// `crate::preempt::{critical_section, PreemptGuard}`, which this shim already
// provides above — so `crates/core/channel` can be pulled in and tested against
// the same fences the kernel uses. That matters here specifically: `SeqLock`'s
// missing acquire fence was a real bug in this tree, found 2026-09-06, and a
// hand-written stand-in would have hidden it.
#[path = "../../../../../../crates/core/sync/src/seqlock.rs"]
pub mod seqlock;
pub use seqlock::{SeqLock, SeqLockWriteGuard};

/// Test-control surface, forwarded from the arch shim so `world-state-tests`
/// does not need a second, separate dependency on the same shim package
/// (`azos_arch` here vs. some other alias there) — a single package
/// pulled in two different ways in one workspace is exactly the kind of
/// thing that makes Cargo's build-std / target unification do something
/// surprising.
pub mod test_arch {
    pub use azos_arch::{
        set_hart, set_sie, clear_sstatus_hook, arm_on_sstatus_read,
        arm_on_hart_id_read, clear_hart_id_hook,
    };
}

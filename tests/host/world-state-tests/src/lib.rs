// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host-side runner for the K-C29 preemption-control fix applied to
//! `domains/robot/behavior/src/world_state.rs`'s hand-rolled seqlock
//! (`world_state_write_begin` / `WorldStateWriteGuard`).
//!
//! # What is real here and what is not
//!
//! `world_state.rs` is pulled in via `#[path]` **unmodified** — the same
//! pattern `tests/host/sync-tests` uses for `preempt.rs`. A mutation to
//! `domains/robot/behavior/src/world_state.rs` changes what this crate compiles and
//! tests. The `azos_sync` this file resolves against is a facade
//! (`shims/sync`) that itself compiles the REAL `crates/core/sync/src/preempt.rs`
//! / `preempt_core.rs` via `#[path]` — see that shim's own doc for why the
//! real `azos_sync` crate cannot be used directly on the host.
//!
//! # What is NOT proved here
//!
//! `world_state_write_begin`/`world_state_read` have zero callers anywhere in
//! the kernel tree today (see `world_state.rs`'s own module doc and
//! `WorldStateWriteGuard`'s doc) — nothing in this crate changes that. These
//! tests prove the *mechanism* is wired correctly (preemption is disabled for
//! the whole write epoch, and disabled BEFORE the epoch becomes visible to a
//! reader), not that the mechanism is exercised in production.

// `crates/core/channel` has no suite of its own and depends only on
// `azos_sync`, which this crate already shims — so the cheapest legitimate
// home for `Channel::age_us`'s test is here rather than a new crate with a
// duplicate shim. Pulled in unmodified, same as `world_state.rs` below.
// `unused_attributes` because `channel/src/lib.rs` carries its own
// `#![no_std]`, which is meaningless once the file is a module rather than a
// crate root — the same reason `tests/host/syscall-tests`'s driver_server shim
// allows it. Warnings are gate failures here, so this cannot be left.
#[allow(dead_code, unused_attributes)]
#[path = "../../../../crates/core/channel/src/lib.rs"]
pub mod channel;

#[path = "../../../../domains/robot/behavior/src/world_state.rs"]
pub mod world_state;

#[cfg(test)]
mod tests {
    use super::world_state;
    use core::sync::atomic::Ordering;
    use std::sync::atomic::{AtomicU32, Ordering as StdOrdering};
    use std::sync::{Mutex, MutexGuard, OnceLock};

    // ── Test harness ────────────────────────────────────────────────────
    //
    // The facade's `PREEMPT` slots (inside `azos_sync`, itself a
    // `#[path]`-included copy of `crates/core/sync/src/preempt.rs`) are
    // process-global statics, and `cargo test` runs tests in parallel
    // threads by default. Every test takes this lock and resets the slot it
    // uses — same pattern as `tests/host/sync-tests`' own `guard()`.

    fn test_lock() -> &'static Mutex<()> {
        static L: OnceLock<Mutex<()>> = OnceLock::new();
        L.get_or_init(|| Mutex::new(()))
    }

    fn guard() -> MutexGuard<'static, ()> {
        let g = test_lock().lock().unwrap_or_else(|e| e.into_inner());
        azos_sync::test_arch::set_hart(0);
        azos_sync::test_arch::set_sie(true);
        azos_sync::test_arch::clear_sstatus_hook();
        azos_sync::test_arch::clear_hart_id_hook();
        azos_sync::force_zero_depth();
        g
    }

    /// What `WORLD_STATE.seq`'s parity was at the instant
    /// `critical_section()` began inside `world_state_write_begin()`.
    /// `u32::MAX` is the sentinel "the hook never fired" (would itself be a
    /// test bug, not a production one — see the assertion that checks it).
    static SEQ_PARITY_AT_CS_START: AtomicU32 = AtomicU32::new(u32::MAX);

    fn record_seq_parity_at_cs_start() {
        let parity = world_state::WORLD_STATE.seq.load(Ordering::Relaxed) & 1;
        SEQ_PARITY_AT_CS_START.store(parity, StdOrdering::Relaxed);
    }

    // ── The discriminating test ──────────────────────────────────────────
    //
    // A test that only checks `depth()`/`seq` before and after
    // `world_state_write_begin()` RETURNS cannot tell "critical_section()
    // called before the odd store" from "called after" — both are fully
    // done, in either order, by the time a synchronous function call
    // returns. The K-C29 property is about ORDER inside that one call, so
    // the observation has to be injected mid-call. `arm_on_hart_id_read`
    // exists for exactly this: `critical_section()`'s very first action is
    // `cpu::hart_id()` (inside `preempt::slot()`), so hooking it records
    // what has already happened by that instant.

    #[test]
    fn write_begin_disables_preemption_before_bumping_seq_odd() {
        let _g = guard();
        SEQ_PARITY_AT_CS_START.store(u32::MAX, StdOrdering::Relaxed);
        azos_sync::test_arch::arm_on_hart_id_read(record_seq_parity_at_cs_start);

        let epoch = world_state::world_state_write_begin();

        let recorded = SEQ_PARITY_AT_CS_START.load(StdOrdering::Relaxed);
        assert_ne!(recorded, u32::MAX, "the hart_id() hook never fired — test harness bug");
        assert_eq!(
            recorded, 0,
            "critical_section() must run BEFORE `seq` goes odd — reading 1 \
             here means `seq` was ALREADY odd by the time preemption was \
             disabled, which is the exact K-C29 ordering bug: a tick could \
             land in the window between the odd store and the guard, \
             preempt the writer, and strand a higher-priority same-hart \
             reader spinning on `world_state_read()` forever"
        );

        drop(epoch);
    }

    // ── Coarser sanity checks ────────────────────────────────────────────
    //
    // These check state before/after the call, which — as above — cannot by
    // itself catch a reordering inside `world_state_write_begin()`. They
    // still earn their place: they pin that the depth genuinely goes to 1
    // and back to 0 (not e.g. leaked, or bumped by 2), and that `seq` is
    // odd for the whole visible lifetime of the guard.

    #[test]
    fn write_epoch_holds_depth_one_and_seq_odd_for_its_whole_visible_lifetime() {
        let _g = guard();
        assert_eq!(azos_sync::depth(), 0, "starts enabled");
        assert_eq!(
            world_state::WORLD_STATE.seq.load(Ordering::Relaxed) & 1, 0,
            "starts even (no epoch open)"
        );

        let epoch = world_state::world_state_write_begin();
        assert_eq!(azos_sync::depth(), 1, "preemption disabled while the epoch is open");
        assert_eq!(
            world_state::WORLD_STATE.seq.load(Ordering::Relaxed) & 1, 1,
            "seq must be odd while the epoch is open"
        );

        drop(epoch);
        assert_eq!(azos_sync::depth(), 0, "preemption re-enabled once the epoch closes");
        assert_eq!(
            world_state::WORLD_STATE.seq.load(Ordering::Relaxed) & 1, 0,
            "seq must be even again once the epoch closes"
        );
    }

    #[test]
    fn nested_guard_from_an_outer_critical_section_still_composes() {
        // Not a scenario `world_state.rs` creates on its own, but
        // `critical_section()` nests (see `preempt.rs`), and this pins that
        // `world_state_write_begin()` does not do anything that would break
        // nesting — e.g. it must not itself assume it is the outermost guard.
        let _g = guard();
        let outer = azos_sync::critical_section();
        assert_eq!(azos_sync::depth(), 1);
        let inner = world_state::world_state_write_begin();
        assert_eq!(azos_sync::depth(), 2, "the write epoch nests under an outer guard");
        drop(inner);
        assert_eq!(azos_sync::depth(), 1, "closing the epoch drops back to the outer depth");
        drop(outer);
        assert_eq!(azos_sync::depth(), 0);
    }
}

// ── Channel::age_us — the overflow that was a board reset ─────────────────

#[cfg(test)]
mod channel_age_us {
    use crate::channel::Channel;

    /// QEMU's rate; the VF2's is 4 MHz and the K1's 24 MHz. The property under
    /// test does not depend on which, and the second case below uses a
    /// different one on purpose.
    const TIMER_FREQ: u64 = 10_000_000;

    /// **An unpublished channel must not panic, and must read as maximally
    /// stale.**
    ///
    /// `age()` returns `u64::MAX` when nothing has been published — the right
    /// answer, and one that cannot be turned into microseconds by
    /// multiplying. Every call site did `age(now) * 1_000_000 / TIMER_FREQ`,
    /// and this tree builds with `overflow-checks = true` and
    /// `panic = "abort"`, so that multiply was a RESET.
    ///
    /// It was reachable on hardware and invisible in QEMU: the flight
    /// controller reads three channels this way every iteration, and
    /// `CH_RC_INPUT` is published only when `rc_read()` returns `Some` — which
    /// `RcMode::Sbus`, the mode a real receiver uses, never does.
    ///
    /// `u64::MAX` microseconds is the correct answer, not a fallback: it makes
    /// every staleness threshold fire, which is what a flight controller with
    /// no RC data must do.
    ///
    /// **Canary.** Restore the body to `self.age(now) * 1_000_000 / freq`:
    /// this test panics with an arithmetic overflow instead of failing an
    /// assertion — which is itself the demonstration, since in the kernel that
    /// panic is a reboot.
    #[test]
    fn an_unpublished_channel_is_maximally_stale_and_does_not_overflow() {
        let ch: Channel<u32> = Channel::new(0);
        assert_eq!(ch.age(1_000), u64::MAX, "precondition: never published");
        assert_eq!(ch.age_us(1_000, TIMER_FREQ), u64::MAX);
        // A different platform rate must not change the answer.
        assert_eq!(ch.age_us(1_000, 4_000_000), u64::MAX);
    }

    /// A published channel converts ticks to microseconds the ordinary way.
    ///
    /// Without this the test above passes against an `age_us` that returns
    /// `u64::MAX` unconditionally — which would make every channel read as
    /// stale and put the aircraft in permanent failsafe.
    #[test]
    fn a_published_channel_converts_ticks_to_microseconds() {
        let ch: Channel<u32> = Channel::new(0);
        ch.publish(7, 1_000);
        // 10 MHz: 1000 ticks later is 100 us.
        assert_eq!(ch.age_us(1_000 + 1_000, TIMER_FREQ), 100);
        // 4 MHz: the same 1000 ticks is 250 us.
        assert_eq!(ch.age_us(1_000 + 1_000, 4_000_000), 250);
        // Freshly published reads as zero, not as stale.
        assert_eq!(ch.age_us(1_000, TIMER_FREQ), 0);
    }

    /// A timer frequency of zero is maximally stale, not a divide by zero.
    ///
    /// `TIMER_FREQ` is a per-platform constant and cannot be 0 today. Asserted
    /// anyway because the alternative failure is the same one this function was
    /// written to remove: an arithmetic fault in the flight loop is a reset,
    /// whichever operator causes it.
    #[test]
    fn an_unknown_clock_is_stale_rather_than_a_divide_by_zero() {
        let ch: Channel<u32> = Channel::new(0);
        ch.publish(7, 1_000);
        assert_eq!(ch.age_us(2_000, 0), u64::MAX);
    }

    /// An age large enough to overflow the multiply still converts, without
    /// panicking, to something no threshold treats as fresh.
    #[test]
    fn a_huge_but_real_age_converts_without_overflowing() {
        let ch: Channel<u32> = Channel::new(0);
        ch.publish(7, 0);
        // 2^60 ticks: `* 1_000_000` overflows u64, so the fallback path runs.
        let us = ch.age_us(1u64 << 60, TIMER_FREQ);
        assert!(us > 1_000_000, "must not read as under a second old");
        assert!(us < u64::MAX, "a real age is not the unpublished sentinel");
    }
}

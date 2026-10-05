// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// Host tests for `irq_wait_ret` in `crates/core/syscall/src/handlers.rs` — the
// return-value decision for the `SYS_DRV_IRQ_WAIT` dispatch arm.
//
// WHY THIS FUNCTION EXISTS AND WHY IT IS TESTED HERE
//
// `SYS_DRV_IRQ_WAIT` used to be a bare `task_block(WaitReason::Irq(n))`
// followed by a literal `0`. `block_current` can return WITHOUT having
// blocked — and after K-C29 it does so deliberately, refusing to park a task
// that holds a spinlock. The old arm reported that refusal to ring 3 as
// "your interrupt fired". A userspace driver would then read and ack device
// registers that nothing had touched.
//
// Every other blocking syscall arm re-polls its own condition after the block
// (`lease_accept`, `port_wait_end`, `fast_ipc_collect`), so a
// non-event is indistinguishable from "nothing yet" and `-1` is honest. This
// arm cannot: nothing in the tree records that IRQ `n` fired for task `t`.
// `wake_by_irq` sweeps tasks already blocked on `WaitReason::Irq(n)` and
// consumes the fact by waking them; `irq_bind`'s `IrqTarget::WakeTask` arm is
// an explicitly empty branch that defers to that sweep. So the refusal has to
// leave through the ABI, and this function is that decision.
//
// WHAT THIS FILE PROVES AND WHAT IT DOES NOT
//
// `irq_wait_ret` is the kernel's own code, pulled whole with the rest of
// `handlers.rs` — a mutation there changes what these tests compile. The
// `BlockOutcome` values fed to it come from this crate's `shims/sched`
// (a transcribed two-variant tag; see the shim's own comment for why the real
// `wait.rs` cannot be pulled into this crate). So what is proved here is the
// MAPPING: given a refusal, what does ring 3 see.
//
// Which outcome the kernel actually produces for a given hart state — that
// `depth > 0` yields `Refused` — is a different claim, proved in
// `tests/host/sched-wake-tests` against the real `task_block_outcome`. Neither
// file proves the other's half.

use azos_abi::error::Errno;
use azos_sched::BlockOutcome;

/// **The property.** A refusal must not be reported as a fired interrupt.
///
/// This is the assertion that discriminates. The mutant to fear is the
/// original code — `Refused` mapping to `0` — and `Refused` is the single
/// input at which it differs from the fix; at `Returned` the broken and the
/// correct version agree exactly, so an assertion there would pass against
/// the mutant and prove nothing.
#[test]
fn a_refused_block_is_not_reported_as_a_fired_interrupt() {
    assert_ne!(
        irq_wait_ret(BlockOutcome::Refused),
        0,
        "SYS_DRV_IRQ_WAIT returned success for a block that never happened: \
         a driver would ack a device that raised no interrupt"
    );
}

/// The refusal is an error by the tree's `rc < 0` convention, and it is
/// specifically `EAGAIN` — "the wait did not happen, ask again".
///
/// Separate from the test above on purpose: that one fails for any mapping
/// that reports success, this one fails for a mapping that reports the wrong
/// *kind* of failure. A refusal is not a denial and not an invalid argument;
/// answering `EPERM` or `EINVAL` would tell a correct driver to give up on a
/// condition that clears by itself.
#[test]
fn a_refused_block_reports_eagain() {
    let rc = irq_wait_ret(BlockOutcome::Refused);
    assert!(rc < 0, "refusal must be negative, got {rc}");
    assert_eq!(rc, Errno::EAGAIN.to_syscall_ret());
    assert_eq!(rc, -11, "EAGAIN's frozen numeric value (crates/core/abi/src/error.rs)");
}

/// The refusal code must not collide with either "denied" code, because
/// `crates/core/libsys/src/lib.rs` documents that callers hardcode those two and
/// tells them to test `rc < 0` only when they have not checked which applies.
///
/// A mutant mapping `Refused` to `E_PERM_DISPATCH` (`-1`) is the plausible
/// wrong fix — it is negative, so the previous test's `rc < 0` half passes —
/// and it is wrong in a way that matters: `-1` from this arm already means
/// nothing at all today, and every *other* dispatch-arm rejection is `-1`, so
/// a driver could not tell "retry" from "denied".
#[test]
fn the_refusal_code_is_distinct_from_both_denied_codes() {
    let rc = irq_wait_ret(BlockOutcome::Refused);
    assert_ne!(rc, -1, "must not collide with E_PERM_DISPATCH");
    assert_ne!(rc, -99, "must not collide with E_PERM_HANDLER");
}

/// A real wake is still `0`. The change must not break drivers written
/// against the old contract on the path that was always correct.
///
/// On its own this asserts nothing about the fix — the pre-K-C29 code passes
/// it too. It is here as the compatibility half, and it is only meaningful
/// read together with `a_refused_block_is_not_reported_as_a_fired_interrupt`:
/// the pair says the two outcomes are distinguishable AND that the successful
/// one kept its value.
#[test]
fn a_completed_block_is_still_zero() {
    assert_eq!(irq_wait_ret(BlockOutcome::Returned), 0);
}

/// The two outcomes must map to different values — the minimal statement of
/// "distinguishable at the ABI", independent of which numbers were chosen.
///
/// This one survives a deliberate future renumbering of the refusal code,
/// which the two value-pinning tests above would not.
#[test]
fn the_two_outcomes_are_distinguishable() {
    assert_ne!(
        irq_wait_ret(BlockOutcome::Returned),
        irq_wait_ret(BlockOutcome::Refused),
    );
}

// ── A caller with a wake-task binding (wave 9 IRQ4 item 1) ──────────────────
//
// For the owner of a `SYS_IRQ_BIND` type-0 binding the answer is re-tested
// against the binding's pending bit (`irq_bind::irq_wait_end`), so the block
// outcome is no longer the input: `irq_wait_bound_ret(consumed)`.

/// A wait that consumed a delivery reports the fired line; one that did not
/// (a spurious return, a refused block with nothing pending) is a retry.
///
/// Canary: map `consumed == false` to 0 — the second assertion fails.
#[test]
fn a_bound_wait_is_zero_only_when_it_consumed_a_delivery() {
    assert_eq!(irq_wait_bound_ret(true), 0);
    assert_eq!(irq_wait_bound_ret(false), Errno::EAGAIN.to_syscall_ret());
}

/// The bound wait's "retry" is the same code the unbound refusal uses, so a
/// driver keeps one retry path for both.
#[test]
fn a_bound_retry_matches_the_unbound_refusal() {
    assert_eq!(irq_wait_bound_ret(false), irq_wait_ret(BlockOutcome::Refused));
}

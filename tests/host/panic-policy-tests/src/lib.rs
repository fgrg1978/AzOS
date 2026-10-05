// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host tests for `azos_common::panic_policy` (RT7, RFC-0052 §5.2): the
//! containment predicate is a pure function of captured state, so every
//! check is pinned here one at a time against a context that passes all of
//! them.

#[cfg(test)]
mod tests {
    use azos_common::panic_policy::*;

    /// A context that passes every check: a plain kernel task, no lock, no
    /// ISR, interrupts on, first panic.
    fn containable() -> PanicContext {
        PanicContext {
            in_isr: false,
            preempt_depth: 0,
            irqs_were_enabled: true,
            pi_held: 0,
            second_panic: false,
            already_panicked: false,
            culprit: Culprit::Kernel,
        }
    }

    #[test]
    fn a_clean_kernel_task_panic_is_contained_under_contain() {
        assert_eq!(decide(Policy::Contain, &containable()), Verdict::Contain);
    }

    #[test]
    fn reset_policy_never_contains() {
        assert_eq!(decide(Policy::Reset, &containable()),
                   Verdict::Reset(Reason::PolicyReset));
        // Whatever the context.
        let mut c = containable();
        c.preempt_depth = 3;
        c.culprit = Culprit::Safety;
        assert_eq!(decide(Policy::Reset, &c), Verdict::Reset(Reason::PolicyReset));
    }

    /// Each check, failed alone, takes the reset path and names itself.
    #[test]
    fn each_check_alone_selects_the_reset_path_with_its_reason() {
        type Mutate = fn(&mut PanicContext);
        let cases: [(Mutate, Reason); 10] = [
            (|c| c.in_isr = true, Reason::InIsr),
            (|c| c.preempt_depth = 1, Reason::SpinLockHeld),
            (|c| c.irqs_were_enabled = false, Reason::IrqsOff),
            (|c| c.pi_held = 1, Reason::PiMutexHeld),
            (|c| c.second_panic = true, Reason::SecondPanic),
            (|c| c.already_panicked = true, Reason::AlreadyPanicked),
            (|c| c.culprit = Culprit::NoTask, Reason::NoTask),
            (|c| c.culprit = Culprit::Idle, Reason::IdleTask),
            (|c| c.culprit = Culprit::User, Reason::UserTask),
            (|c| c.culprit = Culprit::Safety, Reason::SafetyTask),
        ];
        for (mutate, reason) in cases {
            let mut c = containable();
            mutate(&mut c);
            assert_eq!(decide(Policy::Contain, &c), Verdict::Reset(reason),
                       "context {:?}", c);
        }
    }

    /// The gate row `rt7: panic spin` takes a SpinLock with `lock()`, so
    /// interrupts stay on and ONLY the depth check fails: removing that check
    /// must make the verdict `Contain` — this test and that row go red
    /// together.
    #[test]
    fn a_spinlock_held_with_interrupts_on_fails_only_the_depth_check() {
        let mut c = containable();
        c.preempt_depth = 1;
        assert!(c.irqs_were_enabled);
        assert_eq!(decide(Policy::Contain, &c), Verdict::Reset(Reason::SpinLockHeld));
    }

    /// Several failing checks: the first in predicate order names the reason
    /// (second panic and an already-halting machine come first: nothing else
    /// about the context can be trusted then).
    #[test]
    fn the_first_failing_check_names_the_reason() {
        let mut c = containable();
        c.preempt_depth = 2;
        c.irqs_were_enabled = false;
        c.culprit = Culprit::Safety;
        assert_eq!(decide(Policy::Contain, &c), Verdict::Reset(Reason::SpinLockHeld));
        c.in_isr = true;
        assert_eq!(decide(Policy::Contain, &c), Verdict::Reset(Reason::InIsr));
        c.already_panicked = true;
        assert_eq!(decide(Policy::Contain, &c), Verdict::Reset(Reason::AlreadyPanicked));
        c.second_panic = true;
        assert_eq!(decide(Policy::Contain, &c), Verdict::Reset(Reason::SecondPanic));
    }

    /// Exhaustive over the boolean inputs and every culprit kind: `Contain`
    /// iff every check passes. Pins the predicate as a whole, so a new
    /// shortcut that contains one more case fails here.
    #[test]
    fn contain_iff_every_check_passes_exhaustively() {
        let culprits = [Culprit::NoTask, Culprit::Idle, Culprit::User,
                        Culprit::Safety, Culprit::Kernel];
        for bits in 0u32..64 {
            for &culprit in &culprits {
                let c = PanicContext {
                    in_isr: bits & 1 != 0,
                    preempt_depth: (bits >> 1) & 1,
                    irqs_were_enabled: bits & 4 != 0,
                    pi_held: (bits >> 3) & 1,
                    second_panic: bits & 16 != 0,
                    already_panicked: bits & 32 != 0,
                    culprit,
                };
                let all_pass = !c.in_isr && c.preempt_depth == 0 && c.irqs_were_enabled
                    && c.pi_held == 0 && !c.second_panic && !c.already_panicked
                    && culprit == Culprit::Kernel;
                let v = decide(Policy::Contain, &c);
                assert_eq!(v == Verdict::Contain, all_pass, "context {:?} -> {:?}", c, v);
                assert_eq!(decide(Policy::Reset, &c), Verdict::Reset(Reason::PolicyReset));
            }
        }
    }

    /// The tokens the panic handler prints and the gate rows anchor on.
    #[test]
    fn reason_tokens_are_the_ones_the_rows_read() {
        assert_eq!(Reason::SpinLockHeld.as_str(), "spinlock-held");
        assert_eq!(Reason::PolicyReset.as_str(), "policy-reset");
    }

    #[test]
    fn safety_registry_and_isolation_counter() {
        assert!(!register_safety_task(0), "TID 0 is no task");
        assert!(!is_safety_task(0));
        assert!(register_safety_task(7));
        assert!(register_safety_task(7), "registering twice is fine");
        assert!(is_safety_task(7));
        assert!(!is_safety_task(8));
        // Fill the registry: one entry (7) is in already.
        for t in 100..(100 + MAX_SAFETY_TASKS as u32 - 1) {
            assert!(register_safety_task(t));
        }
        assert!(!register_safety_task(999), "a full registry refuses, visibly");
        assert!(!is_safety_task(999));

        let before = contained_count();
        assert_eq!(note_contained(22), before + 1);
        assert_eq!(contained_count(), before + 1);
        assert_eq!(last_contained_tid(), 22);
    }

    #[test]
    fn contained_exit_status_is_128_plus_sigabrt() {
        assert_eq!(CONTAINED_EXIT_STATUS, 134);
    }
}

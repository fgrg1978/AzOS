// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! FEAT_WFxT (Kconfig `A64_WFXT`): the probe's verdict and the deadline a
//! `WFET` step carries. The instruction itself is in `spin.rs` (the wait
//! hint of `SpinWait::wait_while`), the aarch64 counterpart of x86_64's
//! UMWAIT deadline: a wait step ends at a store to the lock word, an event,
//! or the counter reaching [`deadline`], whichever is first.
//!
//! The probe is `ID_AA64ISAR2_EL1.WFxT` ([`crate::cpu::features::IdRegs::wfxt`]).
//! `WFET` is UNDEFINED on a core without it, so the instruction is reached
//! only when [`wfxt_on`] says so; a wrong claim (the `spin-ext-claim` canary
//! on a core without FEAT_WFxT) is an Undefined Instruction exception at the
//! first contended wait.

use azos_arch_api::isa::{aarch64 as policy, ExtPolicy};
use core::sync::atomic::{AtomicBool, Ordering};

/// The probe's verdict (`probe` only; `n`/`require` never read it).
static ON: AtomicBool = AtomicBool::new(false);

/// WFET in use on this boot: a constant under `n`/`require`.
#[inline(always)]
pub fn wfxt_on() -> bool {
    match policy::WFXT {
        ExtPolicy::Never => false,
        ExtPolicy::Require => true,
        ExtPolicy::Probe => ON.load(Ordering::Relaxed),
    }
}

/// Boot, the boot CPU, before the secondaries: `present` is the ID
/// register's answer (or a canary's forced claim). Returns what the wait
/// paths use.
pub fn select(present: bool) -> bool {
    ON.store(policy::WFXT.gate(present), Ordering::Relaxed);
    wfxt_on()
}

/// The counter value a WFET step started at `now` ends at, `ticks` later.
/// Saturating: a deadline past the end of the 64-bit count means "never",
/// not an immediate timeout from a wrap.
pub const fn deadline(now: u64, ticks: u64) -> u64 {
    now.saturating_add(ticks)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_deadline_is_ticks_after_now_and_never_wraps() {
        assert_eq!(deadline(1000, 2500), 3500);
        assert_eq!(deadline(0, 2500), 2500);
        assert_eq!(deadline(u64::MAX - 10, 2500), u64::MAX, "a wrap would time out at once");
        assert!(deadline(5, 1) > 5, "a step always sleeps past now");
    }

    /// `select` keeps the instruction only when the probe found it (under
    /// the default `probe` policy these tests build with).
    #[test]
    fn select_follows_the_probe_under_probe_policy() {
        if !matches!(policy::WFXT, ExtPolicy::Probe) {
            return;
        }
        assert!(select(true) && wfxt_on());
        assert!(!select(false) && !wfxt_on());
    }

    /// The configured step is a real wait: a zero or tiny tick count would
    /// make every step time out at once and turn the hint into a spin.
    #[test]
    fn the_configured_step_is_not_a_spin() {
        assert!(policy::WFET_TICKS >= 100);
    }
}

// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Power management: the system suspend entry the `Power` interface calls.
//!
//! The sequence is [`suspend`]'s; this file holds the platform the kernel
//! installs for it (`kernel/src/boot/energy.rs`, Kconfig `SYSTEM_SUSPEND`) and
//! the one function the interface calls. The idle path is not here: the idle
//! tasks enter their states through `Cpu::cpu_idle` (`azos_arch`).

#[path = "pm/suspend.rs"]
pub mod suspend;

use azos_sync::SpinLock;
use core::sync::atomic::{AtomicBool, Ordering};
use suspend::Platform;

/// A suspend is running: a second caller is refused, not queued (the first one
/// may be a long sleep).
static RUNNING: AtomicBool = AtomicBool::new(false);

/// The installed platform: written once at boot, before any ring-3 task runs.
/// The lock is held only to store or copy the reference, never across a
/// suspend.
static SLOT: SpinLock<Option<&'static (dyn Platform + Sync)>> = SpinLock::new(None);

/// Install the platform system suspend runs on (the kernel, at boot, once).
/// A build without Kconfig `SYSTEM_SUSPEND` installs none. A second call is
/// ignored.
pub fn install(p: &'static (dyn Platform + Sync)) {
    SLOT.lock().get_or_insert(p);
}

/// Write a `Rule::Suspend` record: `subject` is the domain it is about, the
/// three numbers are the record's `state`, `blockers` and `reason`.
pub fn record(subject: u32, r: &suspend::Record) {
    let verdict = match r.verdict {
        suspend::Verdict::Admit => azos_decision::Verdict::Admit,
        suspend::Verdict::Refuse => azos_decision::Verdict::Refuse,
    };
    azos_decision::record(azos_decision::Rule::Suspend, verdict, subject, [r.state, r.blockers, r.reason]);
}

/// Suspend the system for the task `caller` (of the domain `subject`) and
/// return when it has resumed. 0: it slept and is back; otherwise the
/// [`suspend::Reason`] it was refused for, with its record written.
pub fn pm_suspend(caller: u32, subject: u32) -> u32 {
    let refuse = |reason: suspend::Reason| {
        record(subject, &suspend::Record {
            verdict: suspend::Verdict::Refuse,
            state: suspend::STATE_ENTER,
            blockers: 0,
            reason: reason.code() as u64,
        });
        reason.code()
    };
    let platform = *SLOT.lock();
    // No platform: the build does not have system suspend (Kconfig
    // `SYSTEM_SUSPEND` is off, as it is on every robot, industrial and
    // automotive image).
    let Some(p) = platform else { return refuse(suspend::Reason::Disabled) };
    if RUNNING.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed).is_err() {
        return refuse(suspend::Reason::InProgress);
    }
    let code = suspend::run(p, caller, subject).code();
    RUNNING.store(false, Ordering::Release);
    code
}

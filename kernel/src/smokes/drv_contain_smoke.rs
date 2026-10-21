// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The buzzer's placement through a fault and a deadline (wave 13 RT7 and
//! Phase 4 elasticity). Feature `drv-contain-smoke`; the gate row builds it
//! with Kconfig `PANIC_POLICY_CONTAIN`, on the drivers disk, and with
//! `DRV_BUZZER_CALL_BUDGET_US` between what a call costs in the kernel and in
//! ring 3 (a few microseconds) for the deadline half.
//!
//! An observer task, from whichever host the driver starts in:
//!
//! 1. *Deadline* (starts in ring 3, budget set): it calls until the driver
//!    has moved into the kernel; the calls broke the row's budget and the
//!    kernel host's measured cost fit it.
//! 2. The kernel host does its job: a 50 ms tone, then no call for
//!    [`ENDED_WAIT_MS`] (a call would also advance it); the tone has ended
//!    only if the host task advanced it, so the PWM channel is off.
//! 3. *Fault*: the host is asked to panic (on its next step, holding no lock)
//!    and woken with a beep. The panic is contained, and the driver must come
//!    back in ring 3, behind the same endpoint, as a different task; a tone
//!    ends there too.
//! 4. *Hold-off* (budget set): ring-3 calls break the budget again and the
//!    driver is NOT moved back into the code that just faulted.
//! 5. The decisions: every move and refusal above is a `Rule::Placement`
//!    record, in the order it happened, with the cause of each refusal.
//!
//! One verdict line: `[DRVCONTAIN] PASS ...` or `[DRVCONTAIN] FAIL <why>`.
//! With the supervisor off (`sup-canary`) the fault is never acted on; with
//! the panic not contained the machine resets and prints no verdict; with
//! `placement-norecord-canary` the moves happen and step 5 fails.

use core::sync::atomic::{AtomicBool, Ordering};

use crate::buzzer::{buzzer_beep, buzzer_off, buzzer_tone, driver_tid, host};
use azos_drv_actuator::buzzer::PWM_CHANNEL as BUZZER_PWM_CHANNEL;
use azos_topology::placement::{Cause, Host, Move, Reason};
use azos_drv_sys::kprintln;
use azos_drv_sys::timebase::{now, TIMER_FREQ};

/// How long the observer waits for the host (first start, and successor).
const HOST_WAIT_MS: u64 = 5_000;
/// How long a 50 ms tone gets to end with no call made.
const ENDED_WAIT_MS: u64 = 1_500;
/// Tone length.
const TONE_MS: u32 = 50;

static PANIC_REQUEST: AtomicBool = AtomicBool::new(false);

/// The host's step asks: panic now? True once per request.
pub(crate) fn take_panic_request() -> bool {
    PANIC_REQUEST.swap(false, Ordering::AcqRel)
}

fn ms(n: u64) -> u64 {
    n * (TIMER_FREQ / 1000)
}

fn sleep_until(deadline: u64) {
    while now() < deadline {
        azos_sched::task_block(azos_sched::WaitReason::Timer(deadline));
    }
}

/// Wait until a driver serves, in the host `want` (any when `None`), as a
/// task other than `not`. Its TID.
fn serving_other_than(not: u32, want: Option<Host>) -> Option<u32> {
    let end = now() + ms(HOST_WAIT_MS);
    while now() < end {
        match driver_tid() {
            Some(t) if t != not && want.is_none_or(|w| host() == Some(w)) => return Some(t),
            _ => sleep_until(now() + ms(10)),
        }
    }
    None
}

fn pwm_on() -> bool {
    azos_drv_actuator::pwm::pwm_get(BUZZER_PWM_CHANNEL).is_some_and(|c| c.enabled)
}

/// A tone that only the serving host can end: `(started, on while playing,
/// off after ENDED_WAIT_MS)`.
fn tone_ends() -> (bool, bool, bool) {
    let started = buzzer_tone(440, TONE_MS);
    let on = pwm_on();
    sleep_until(now() + ms(ENDED_WAIT_MS));
    (started, on, !pwm_on())
}

/// Call until the driver has moved to `to`, at most `n` calls (each a timed
/// call the controller sees). Whether it did.
fn call_until(to: Host, n: u32) -> bool {
    for _ in 0..n {
        let _ = buzzer_off();
        if host() == Some(to) {
            return true;
        }
        sleep_until(now() + ms(20));
    }
    host() == Some(to)
}

/// The placement decisions from id `after`, oldest first: `(verdict, move,
/// cause)`.
fn placements(after: u64) -> ([(u8, Move, Option<Cause>); 8], usize) {
    let blank = (0u8, Move { from: Host::Kernel, to: Host::Ring3, reason: Reason::Fault }, None);
    let mut out = [blank; 8];
    let mut ids = [0u64; 8];
    let f = azos_decision::Filter { rule: Some(azos_decision::Rule::Placement as u8), after, ..azos_decision::Filter::ANY };
    let n = azos_decision::query(&f, &mut ids);
    let mut k = 0;
    for &id in &ids[..n] {
        if let Some(p) = azos_decision::lookup(id) {
            if let Some((m, c)) = Move::unpack(p.n[0]) {
                out[k] = (p.verdict, m, c);
                k += 1;
            }
        }
    }
    (out, k)
}

/// Create the observer. Called from `kernel_main` with the other smokes.
pub(crate) fn spawn() {
    azos_sched::task_create("drvcontain-obs", observer_task, 0,
        azos_sched::DEFAULT_PRIORITY);
    kprintln!("[DRVCONTAIN] observer created; policy={}",
        if azos_limits::PANIC_POLICY_CONTAIN { "contain" } else { "reset" });
}

fn observer_task(_: usize) {
    use azos_decision::Verdict;
    let Some(first) = serving_other_than(0, None) else {
        kprintln!("[DRVCONTAIN] FAIL the buzzer never started in either host");
        return;
    };
    let budget = azos_topology::get()
        .and_then(|t| t.row_place(azos_topology::builder::TASK_BUZZDRV_IMAGE))
        .map_or(0, |p| p.call_budget_us);
    let decisions0 = azos_decision::total();
    let mut want: [(u8, Move, Option<Cause>); 4] = [(0, Move { from: Host::Kernel, to: Host::Ring3, reason: Reason::Fault }, None); 4];
    let mut n_want = 0;

    // 1. Deadline: ring 3 -> kernel.
    let mut host_tid = first;
    if host() == Some(Host::Ring3) && budget > 0 {
        if !call_until(Host::Kernel, 200) {
            kprintln!("[DRVCONTAIN] FAIL ring-3 calls over the {} us budget did not move the driver into the kernel", budget);
            return;
        }
        let Some(t) = serving_other_than(first, Some(Host::Kernel)) else {
            kprintln!("[DRVCONTAIN] FAIL the kernel host never served after the promotion");
            return;
        };
        host_tid = t;
        want[n_want] = (Verdict::Place as u8, Move { from: Host::Ring3, to: Host::Kernel, reason: Reason::Deadline }, None);
        n_want += 1;
    }
    if host() != Some(Host::Kernel) {
        kprintln!("[DRVCONTAIN] FAIL the driver does not start in the kernel and no deadline moved it there \
                   (DRV_BUZZER_PLACEMENT, DRV_BUZZER_CALL_BUDGET_US)");
        return;
    }

    // 2. The kernel host does its job.
    let before = tone_ends();
    kprintln!("[DRVCONTAIN] kernel host tid={} before: started={} on={} ended={}",
        host_tid, before.0, before.1, before.2);

    // 3. Fault: kernel -> ring 3.
    let contained0 = azos_common::panic_policy::contained_count();
    PANIC_REQUEST.store(true, Ordering::Release);
    // The call wakes the host, whose next step panics.
    let _ = buzzer_beep();
    let heir = serving_other_than(host_tid, Some(Host::Ring3));
    let isolations = azos_common::panic_policy::contained_count().wrapping_sub(contained0);
    let after = if heir.is_some() { tone_ends() } else { (false, false, false) };
    kprintln!("[DRVCONTAIN] isolations={} ring-3 successor={:?} after: started={} on={} ended={}",
        isolations, heir, after.0, after.1, after.2);
    want[n_want] = (Verdict::Place as u8, Move { from: Host::Kernel, to: Host::Ring3, reason: Reason::Fault }, None);
    n_want += 1;

    // 4. Hold-off: slow ring-3 calls do not move it back.
    if budget > 0 && heir.is_some() {
        for _ in 0..40 {
            let _ = buzzer_off();
            sleep_until(now() + ms(10));
        }
        want[n_want] = (Verdict::Refuse as u8, Move { from: Host::Ring3, to: Host::Kernel, reason: Reason::Deadline }, Some(Cause::RecentFault));
        n_want += 1;
    }
    let stayed = host() == Some(Host::Ring3);

    // 5. The decisions.
    let (got, n_got) = placements(decisions0);
    let _ = azos_actuation::logger::logger_flush();
    let records_ok = n_got == n_want && got[..n_got] == want[..n_want];
    for (v, m, c) in &got[..n_got] {
        kprintln!("[DRVCONTAIN] decision: {} {:?} -> {:?} ({:?}) cause={:?}",
            if *v == Verdict::Place as u8 { "place" } else { "refuse" }, m.from, m.to, m.reason, c);
    }

    let why = if before != (true, true, true) {
        "the kernel host did not end a tone before the panic"
    } else if isolations != 1 {
        "isolations != 1"
    } else if heir.is_none() {
        "the driver was not restarted in ring 3"
    } else if after != (true, true, true) {
        "the ring-3 host did not end a tone"
    } else if !stayed {
        "the driver was moved back into the kernel within the hold-off"
    } else if !records_ok {
        "the placement decisions are not the moves that happened (a move without its record, or a record without its move)"
    } else {
        ""
    };
    if why.is_empty() {
        kprintln!("[DRVCONTAIN] PASS kernel tid={} -> ring 3 tid={}, {} placement decisions recorded",
            host_tid, heir.unwrap_or(0), n_got);
    } else {
        kprintln!("[DRVCONTAIN] FAIL {}", why);
    }
}

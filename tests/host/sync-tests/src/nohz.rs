// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `crates/core/sync/src/qsbr_nohz.rs` with `qsbr_core.rs`: a grace period
//! with a CPU that has stopped its tick (Kconfig NOHZ_FULL, rule F5).
//!
//! The rule (`user_is_eqs`) and the counter arithmetic (`qsbr_core`) are the
//! kernel's own, pulled by path. The model restates the two things
//! `qsbr.rs` does with them, which need the per-CPU table and do not compile
//! for the host: a trap guard (kernel entry, return to user) and the grace
//! period's snapshot and poll (`Gp::start`, `Gp::poll`).
//!
//! Registered in `lib.rs` by `#[cfg(test)] mod nohz;`.

use super::qsbr_core::*;

#[path = "../../../../crates/core/sync/src/qsbr_nohz.rs"]
mod subject;
use subject::user_is_eqs;

/// One CPU: the counter and the grace-period number of its last report.
struct Cpu {
    eqs: u64,
    qs: u64,
    id: usize,
    nocbs: usize,
    tickless: u64,
}

impl Cpu {
    /// A CPU running user code (even if its user mode is quiescent, else odd:
    /// it entered user mode and nothing has told RCU since).
    fn in_user(id: usize, nocbs: usize, tickless: u64) -> Self {
        let eqs = if user_is_eqs(nocbs, tickless, id) { 2 } else { 1 };
        Cpu { eqs, qs: 0, id, nocbs, tickless }
    }

    /// `TrapBoundary::exception` / `irq` entry: out of the quiescent state.
    fn trap_in(&mut self) {
        if let Some(v) = enter(self.eqs) {
            self.eqs = v;
        }
    }

    /// The guard's drop on the way to user mode: an RT CPU enters the
    /// quiescent state again; any other reports the grace period it saw (only
    /// an interrupt does, and only a tick is one).
    fn to_user(&mut self, gp_seq: u64, tick: bool) {
        if user_is_eqs(self.nocbs, self.tickless, self.id) {
            if let Some(v) = leave(self.eqs) {
                self.eqs = v;
            }
        } else if tick {
            self.qs = gp_seq;
        }
    }
}

/// `Gp::start` and `Gp::poll`, over `cpus` but the waiter's own.
struct Gp {
    seq: u64,
    snap: Vec<u64>,
}

impl Gp {
    fn start(seq: u64, waiter: usize, cpus: &[Cpu]) -> Gp {
        let snap = cpus.iter().enumerate()
            .map(|(i, c)| if i == waiter { DONE } else { snapshot(c.eqs) })
            .collect();
        Gp { seq, snap }
    }

    fn poll(&mut self, cpus: &[Cpu]) -> bool {
        for (i, e) in self.snap.iter_mut().enumerate() {
            if *e != DONE && (passed(*e, cpus[i].eqs) || cpus[i].qs >= self.seq) {
                *e = DONE;
            }
        }
        self.snap.iter().all(|&e| e == DONE)
    }

    fn waiting_on(&self) -> Vec<usize> {
        self.snap.iter().enumerate().filter(|(_, &e)| e != DONE).map(|(i, _)| i).collect()
    }
}

const TICKLESS: u64 = 1 << 2;

fn machine() -> Vec<Cpu> {
    // CPU 0 is the waiter (in the kernel), 1 an ordinary CPU in user code,
    // 2 an isolated CPU in user code with its tick stopped.
    vec![
        Cpu { eqs: 1, qs: 0, id: 0, nocbs: 0, tickless: TICKLESS },
        Cpu::in_user(1, 0, TICKLESS),
        Cpu::in_user(2, 0, TICKLESS),
    ]
}

#[test]
fn the_rule_names_the_nocbs_cpus_and_the_published_tickless_ones() {
    assert!(user_is_eqs(0b10, 0, 1), "RCU_NOCBS_CPUS");
    assert!(user_is_eqs(0, 0b100, 2), "published by the scheduler");
    assert!(!user_is_eqs(0b10, 0b100, 0));
    assert!(!user_is_eqs(0, 0, 0), "nothing published, no mask: nobody");
    assert!(!user_is_eqs(usize::MAX, u64::MAX, 64), "past both masks");
    assert!(user_is_eqs(0, 1 << 63, 63));
}

#[test]
fn a_grace_period_does_not_wait_for_a_tickless_cpu_in_user_mode() {
    let mut cpus = machine();
    let mut gp = Gp::start(1, 0, &cpus);
    // CPU 2 never takes a tick, a syscall or any other trap: it is DONE at
    // the snapshot. Only CPU 1 is waited for, and it reports at its tick.
    assert_eq!(gp.waiting_on(), vec![1]);
    assert!(!gp.poll(&cpus));
    cpus[1].trap_in();
    cpus[1].to_user(1, true);
    assert!(gp.poll(&cpus));
    assert_eq!(cpus[2].eqs, 2, "CPU 2 was never touched");
}

#[test]
fn an_ordinary_cpu_without_a_tick_holds_the_grace_period() {
    // The reason the tick may stop only on a CPU the scheduler published: the
    // same CPU 2, not published, in user mode with no tick, is waited for.
    let mut cpus = machine();
    cpus[2] = Cpu::in_user(2, 0, 0);
    let mut gp = Gp::start(1, 0, &cpus);
    assert_eq!(gp.waiting_on(), vec![1, 2]);
    cpus[1].trap_in();
    cpus[1].to_user(1, true);
    for _ in 0..1000 {
        assert!(!gp.poll(&cpus), "no tick, no trap, no report");
    }
    assert_eq!(gp.waiting_on(), vec![2]);
}

#[test]
fn a_tickless_cpu_in_the_kernel_is_waited_for_until_its_return_to_user() {
    let mut cpus = machine();
    cpus[2].trap_in(); // a syscall: the CPU is in the kernel (odd)
    assert!(!quiescent(cpus[2].eqs));
    let mut gp = Gp::start(1, 0, &cpus);
    assert_eq!(gp.waiting_on(), vec![1, 2], "a read section may be open there");
    cpus[1].trap_in();
    cpus[1].to_user(1, true);
    assert!(!gp.poll(&cpus));
    // The syscall returns: the guard puts the CPU back in the state, which
    // moved the counter since the snapshot.
    cpus[2].to_user(1, false);
    assert!(quiescent(cpus[2].eqs));
    assert!(gp.poll(&cpus));
}

#[test]
fn a_tickless_cpu_passes_through_traps_without_a_report_of_its_own() {
    // The stopped tick's residual interrupt and the syscalls of the task: each
    // leaves and re-enters the state; none sets `qs`, none is needed.
    let mut cpus = machine();
    for k in 0..10 {
        cpus[2].trap_in();
        assert!(!quiescent(cpus[2].eqs), "in the kernel for the trap {k}");
        cpus[2].to_user(k, k % 2 == 0);
        assert!(quiescent(cpus[2].eqs));
        assert_eq!(cpus[2].qs, 0);
    }
    // Several grace periods in a row complete with CPU 1 reporting alone.
    for seq in 1..=5u64 {
        let mut gp = Gp::start(seq, 0, &cpus);
        cpus[1].trap_in();
        cpus[1].to_user(seq, true);
        assert!(gp.poll(&cpus), "grace period {seq}");
    }
}

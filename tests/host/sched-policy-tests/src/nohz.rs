// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `crates/drivers/sys/src/nohz.rs`: when a busy CPU stops its periodic tick
//! (Kconfig NOHZ_FULL), on a model of one hart's comparator.
//!
//! What is the kernel's own code here: the decisions (`lone_rt`, `observe`,
//! `stop_bound`, the mask and bitmap tests) and the deadline arithmetic
//! (`timer_arm::next_event`), both pulled by path. What is the model's: the
//! glue of `timebase.rs` (which of the two caps a re-arm uses, what an
//! enqueue and a switch do to the stopped tick), which needs the comparator
//! and does not compile for the host. `Hart` below restates that glue line
//! for line; a change to it there must change it here.
//!
//! Registered in `lib.rs` by `#[cfg(test)] mod nohz;`.

#[path = "../../../../crates/drivers/sys/src/nohz.rs"]
mod subject;
#[path = "../../../../crates/drivers/sys/src/timer_arm.rs"]
#[allow(dead_code)]
mod timer_arm;

use subject::*;
use timer_arm::{next_event, Cap, NOT_ARMED};

/// 10 MHz counter, 100 Hz tick, a one-second residual, as QEMU `virt`.
const FREQ: u64 = 10_000_000;
const PERIOD: u64 = FREQ / 100;
const RESIDUAL: u64 = FREQ;
const IDLE_PRIO: u32 = 31;
const RT_THRESHOLD: u32 = 12;

/// What the scheduler reads at a tick, and the timers around it.
#[derive(Clone, Copy)]
struct Tick {
    cpu: Cpu,
    tid: u32,
    nearest: Option<u64>,
    keepalive: Option<u64>,
    poll: Option<u64>,
}

fn lone(tid: u32) -> Tick {
    Tick {
        cpu: Cpu { isolated: true, running_rt: true, other_ready: false, wake_pending: false },
        tid,
        nearest: None,
        keepalive: None,
        poll: None,
    }
}

/// One hart's comparator record and the scheduler's per-CPU tick memory.
struct Hart {
    seen: Seen,
    stopped: bool,
    programmed: u64,
}

impl Hart {
    fn new() -> Self {
        Hart { seen: Seen::default(), stopped: false, programmed: NOT_ARMED }
    }

    /// The tick handler's re-arm: `set_next_tick_smart`.
    fn tick(&mut self, now: u64, t: Tick) {
        let (s, stop) = observe(self.seen, t.tid, lone_rt(t.cpu));
        self.seen = s;
        self.programmed = if stop {
            next_event(now, t.nearest, Cap::IdleKeepalive, PERIOD,
                       stop_bound(RESIDUAL, t.keepalive, t.poll), 0)
        } else {
            next_event(now, t.nearest, Cap::Busy, PERIOD, 0, 0)
        };
        self.stopped = stop;
    }

    /// A task became ready on this hart, or its doorbell rang
    /// (`drain_remote_wakes` at the top of every IPI arm):
    /// `timebase::tick_restart`.
    fn enqueue(&mut self, now: u64) {
        if !self.stopped {
            return;
        }
        let end = now + PERIOD;
        self.programmed = if self.programmed != NOT_ARMED && self.programmed < end { self.programmed } else { end };
        self.stopped = false;
    }

    /// A switch off the lone task: the tail of `do_schedule` re-arms with the
    /// busy cap, or the idle one when the hart goes idle.
    fn switch(&mut self, now: u64, nearest: Option<u64>, to_idle: bool) {
        if !self.stopped && !to_idle {
            return;
        }
        let cap = if to_idle { Cap::IdleCeiling } else { Cap::Busy };
        self.programmed = next_event(now, nearest, cap, PERIOD, 0, 60 * FREQ);
        self.stopped = false;
        self.seen = Seen::default();
    }
}

#[test]
fn an_isolated_cpu_running_one_rt_task_stops_at_the_second_tick() {
    let mut h = Hart::new();
    h.tick(PERIOD, lone(7));
    assert!(!h.stopped, "the first tick that sees the task only counts it");
    assert_eq!(h.programmed, 2 * PERIOD, "and re-arms one period out");
    h.tick(2 * PERIOD, lone(7));
    assert!(h.stopped);
    assert_eq!(h.programmed, 2 * PERIOD + RESIDUAL, "nothing nearer: the residual");
}

#[test]
fn a_non_isolated_cpu_never_stops_its_tick() {
    // The same inputs as the stopping test, with the one bit clear.
    let mut h = Hart::new();
    let mut t = lone(7);
    t.cpu.isolated = false;
    for k in 1..=1000u64 {
        h.tick(k * PERIOD, t);
        assert!(!h.stopped, "tick {k}");
        assert_eq!(h.programmed, (k + 1) * PERIOD);
    }
}

#[test]
fn anything_else_on_the_cpu_keeps_the_tick() {
    let mut cases = [
        ("a task of a fair level or another RT task is ready", Cpu { other_ready: true, ..lone(1).cpu }),
        ("a wake is on the deferred list", Cpu { wake_pending: true, ..lone(1).cpu }),
        ("the interrupted task is not an RT task, or not running", Cpu { running_rt: false, ..lone(1).cpu }),
    ];
    for (why, cpu) in cases.iter_mut() {
        let mut h = Hart::new();
        for k in 1..=10u64 {
            h.tick(k * PERIOD, Tick { cpu: *cpu, ..lone(1) });
            assert!(!h.stopped, "{why}: tick {k}");
        }
    }
}

#[test]
fn the_count_starts_over_when_the_task_changes_or_the_cpu_stops_being_lone() {
    let mut h = Hart::new();
    h.tick(PERIOD, lone(1));
    h.tick(2 * PERIOD, lone(2));
    assert!(!h.stopped, "a different task: the first tick that sees it");
    h.tick(3 * PERIOD, lone(2));
    assert!(h.stopped);
    // Another task is ready for one tick: lone again means counting again.
    h.tick(4 * PERIOD, Tick { cpu: Cpu { other_ready: true, ..lone(2).cpu }, ..lone(2) });
    assert!(!h.stopped);
    h.tick(5 * PERIOD, lone(2));
    assert!(!h.stopped);
    h.tick(6 * PERIOD, lone(2));
    assert!(h.stopped);
}

#[test]
fn a_stopped_tick_keeps_stopping_while_the_task_stays_alone() {
    let mut h = Hart::new();
    let mut now = PERIOD;
    h.tick(now, lone(3));
    for _ in 0..50 {
        now = h.programmed;
        h.tick(now, lone(3));
        assert!(h.stopped);
        assert_eq!(h.programmed, now + RESIDUAL);
    }
}

#[test]
fn a_timer_deadline_comes_before_the_residual_and_the_stop_goes_on_after_it() {
    let mut h = Hart::new();
    h.tick(PERIOD, lone(4));
    let due = 3 * PERIOD + 123;
    h.tick(2 * PERIOD, Tick { nearest: Some(due), ..lone(4) });
    assert!(h.stopped);
    assert_eq!(h.programmed, due, "the sleeper's deadline, not the residual");
    // The timer interrupt: the sleeper is woken, nothing else pends.
    h.tick(due, lone(4));
    assert!(h.stopped);
    assert_eq!(h.programmed, due + RESIDUAL);
    // A deadline beyond the residual does not stretch the stop.
    h.tick(due + RESIDUAL, Tick { nearest: Some(due + 5 * RESIDUAL), ..lone(4) });
    assert_eq!(h.programmed, due + 2 * RESIDUAL);
}

#[test]
fn an_enqueue_restarts_the_tick_and_keeps_the_nearest_deadline() {
    let mut h = Hart::new();
    h.tick(PERIOD, lone(5));
    h.tick(2 * PERIOD, Tick { nearest: Some(2 * PERIOD + 3 * FREQ / 1000), ..lone(5) });
    assert!(h.stopped);
    let nearest = h.programmed;
    h.enqueue(2 * PERIOD + 1);
    assert!(!h.stopped, "re-armed on enqueue");
    assert_eq!(h.programmed, nearest, "a sleeper nearer than one period still wins");

    // Stopped with nothing nearer than the residual: one period out.
    let mut h = Hart::new();
    h.tick(PERIOD, lone(5));
    h.tick(2 * PERIOD, lone(5));
    assert!(h.stopped);
    h.enqueue(2 * PERIOD + 500);
    assert!(!h.stopped);
    assert_eq!(h.programmed, 3 * PERIOD + 500);
    // And an enqueue on a running tick changes nothing.
    h.enqueue(2 * PERIOD + 600);
    assert_eq!(h.programmed, 3 * PERIOD + 500);
}

#[test]
fn a_doorbell_from_another_cpu_restarts_the_tick_the_same_way() {
    // A fair task woken from another CPU onto the stopped one: no timer
    // interrupt, and the IPI's `schedule()` keeps the running RT task, so the
    // doorbell's own call is what ends the stop (and lets the band's budget
    // be charged again within one period).
    let mut h = Hart::new();
    h.tick(PERIOD, lone(5));
    h.tick(2 * PERIOD, lone(5));
    assert!(h.stopped);
    let ipi_at = 2 * PERIOD + 4_321;
    h.enqueue(ipi_at);
    assert!(!h.stopped);
    assert_eq!(h.programmed, ipi_at + PERIOD);
    // The task has company now: the next tick does not stop again.
    h.tick(ipi_at + PERIOD, Tick { cpu: Cpu { other_ready: true, ..lone(5).cpu }, ..lone(5) });
    assert!(!h.stopped);
}

#[test]
fn leaving_the_task_restarts_the_tick_and_idle_takes_the_idle_cap() {
    let mut h = Hart::new();
    h.tick(PERIOD, lone(6));
    h.tick(2 * PERIOD, lone(6));
    assert!(h.stopped);
    h.switch(2 * PERIOD + 10, None, false);
    assert!(!h.stopped);
    assert_eq!(h.programmed, 3 * PERIOD + 10, "a switch to another task: periodic again");
    // The count does not survive a switch: the next lone task starts at 1.
    h.tick(3 * PERIOD + 10, lone(8));
    assert!(!h.stopped);

    let mut h = Hart::new();
    h.tick(PERIOD, lone(6));
    h.tick(2 * PERIOD, lone(6));
    h.switch(2 * PERIOD + 10, Some(2 * PERIOD + 99), true);
    assert!(!h.stopped, "idle is tickless in its own way, not a stopped busy tick");
    assert_eq!(h.programmed, 2 * PERIOD + 99);
}

#[test]
fn hart_zero_does_not_sleep_past_its_watchdog_keepalive() {
    let keepalive = FREQ / 8; // 125 ms, as a 500 ms watchdog
    let mut h = Hart::new();
    h.tick(PERIOD, Tick { keepalive: Some(keepalive), ..lone(9) });
    h.tick(2 * PERIOD, Tick { keepalive: Some(keepalive), ..lone(9) });
    assert!(h.stopped);
    assert_eq!(h.programmed, 2 * PERIOD + keepalive);
}

#[test]
fn work_only_the_tick_observes_caps_the_stop_at_the_poll_bound() {
    let poll = FREQ / 10; // IDLE_POLL_US = 100 ms
    let mut h = Hart::new();
    h.tick(PERIOD, Tick { poll: Some(poll), ..lone(9) });
    h.tick(2 * PERIOD, Tick { poll: Some(poll), ..lone(9) });
    assert!(h.stopped);
    assert_eq!(h.programmed, 2 * PERIOD + poll);
    // Both: the shorter.
    assert_eq!(stop_bound(RESIDUAL, Some(poll / 2), Some(poll)), poll / 2);
    assert_eq!(stop_bound(RESIDUAL, None, None), RESIDUAL);
    assert_eq!(stop_bound(5, Some(10), Some(9)), 5, "never above the residual");
}

#[test]
fn the_cpu_mask_and_the_ready_bitmap_tests() {
    assert!(in_mask(0b100, 2));
    assert!(!in_mask(0b100, 1));
    assert!(!in_mask(0, 0));
    assert!(in_mask(1 << 63, 63));
    assert!(!in_mask(u64::MAX, 64), "a CPU past the mask's width is in no mask");
    assert!(!in_mask(u64::MAX, 4096));

    assert!(!others_ready(1 << IDLE_PRIO, IDLE_PRIO), "idle is always ready: it does not count");
    assert!(!others_ready(0, IDLE_PRIO));
    assert!(others_ready(1 << IDLE_PRIO | 1 << 20, IDLE_PRIO), "a fair level");
    assert!(others_ready(1 << IDLE_PRIO | 1 << 3, IDLE_PRIO), "another RT level");

    assert!(running_rt(true, 0, RT_THRESHOLD));
    assert!(running_rt(true, RT_THRESHOLD - 1, RT_THRESHOLD));
    assert!(!running_rt(true, RT_THRESHOLD, RT_THRESHOLD), "the first fair-band level");
    assert!(!running_rt(false, 0, RT_THRESHOLD), "a task that is blocking");
}

#[test]
fn the_packed_word_round_trips() {
    for s in [Seen::default(), Seen { tid: 1, ticks: 1 }, Seen { tid: u32::MAX, ticks: LONE_TICKS_TO_STOP }] {
        assert_eq!(unpack(pack(s)), s);
    }
}

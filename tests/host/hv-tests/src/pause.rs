// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Holding a vCPU: the record's two flags, the loop that stops entering the
//! guest until it is let go, and what each ISA does with the time the guest
//! was held.
//!
//! WHY. A pause that loses a register, an interrupt line or the access the
//! guest is waiting for is a guest that resumes into a hang; one that lets the
//! guest's clock run on is a guest that wakes into a time jump (a timer storm,
//! a watchdog); one that does not serve the fences other vCPUs wait for is a
//! deadlock of the whole guest. The loop is shared by the three ISAs, so it
//! runs once against a scripted guest, and then against the real entry of
//! riscv64 (`begin`, the `htimedelta` the hart loads), aarch64 (the offset of
//! the virtual count) and x86_64 (the VMCB's TSC offset).

use crate::fakes::ScriptHv;
use crate::glue::arm::inject::GuestIrq;
use crate::glue::rv::guest::{self, VcpuState};
use crate::monitor::{access, ready, table, view};
use crate::rv_enter::{ctx as rv_ctx, FakeHart, Step};
use azos_arch_api::{Exit, GuestCtx, RemoteFence, Stage2Root};
use azos_hv::run::{self, fault, PostError, RunHost, Stop};
use azos_hv::trapwire::{Completion, Trap};
use azos_hv::vcpu::{PauseError, RunState};
use azos_hv::vm::VmTable;
use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::rc::Rc;

/// The kernel's end of the loop, scripted: when the holds happen, how long
/// they last (in looks of the parked thread), and what happens meanwhile.
#[derive(Default)]
struct PHost {
    entries: u32,
    /// `(entry, looks)`: once `entry` entries were made, a pause is asked and
    /// a resume follows after `looks` looks of the held thread.
    holds: VecDeque<(u32, u32)>,
    /// Stop is asked once this many entries were made.
    stop_at_entry: Option<u32>,
    /// Stop is asked at this look (counted over all the holds).
    stop_at_look: Option<u32>,
    /// A fence from another vCPU arrives at this look.
    fence_at_look: Option<u32>,
    /// Line 5 is raised at this look.
    line_at_look: Option<u32>,
    pause: bool,
    /// Between `freeze` and `thaw`: a `park` is then a look of the hold, not
    /// the guest's own wait.
    holding: bool,
    stop: bool,
    hold_left: u32,
    looks: u32,
    waits: u32,
    clock: u64,
    per_look: u64,
    /// The host tick the current hold began at.
    since: u64,
    /// What the VM has lost: the sum of the holds.
    lost: u64,
    frozen: u32,
    thaws: u32,
    pending: u64,
    fences: VecDeque<RemoteFence>,
    /// Whether each fence handed out was taken during the hold.
    fence_taken_held: Vec<bool>,
}

impl PHost {
    fn new() -> PHost {
        PHost { per_look: 10, ..PHost::default() }
    }
}

impl RunHost for PHost {
    fn stop_requested(&mut self) -> bool {
        self.stop
    }
    fn pause_requested(&mut self) -> bool {
        self.pause
    }
    fn freeze(&mut self) {
        self.frozen += 1;
        self.holding = true;
        self.since = self.clock;
    }
    fn thaw(&mut self) {
        self.thaws += 1;
        self.holding = false;
        self.lost += self.clock - self.since;
    }
    fn lost(&mut self) -> u64 {
        self.lost
    }
    fn take_irqs(&mut self) -> u64 {
        self.entries += 1;
        if self.holds.front().is_some_and(|h| h.0 == self.entries) {
            self.hold_left = self.holds.pop_front().unwrap().1;
            self.pause = true;
        }
        if self.stop_at_entry == Some(self.entries) {
            self.stop = true;
        }
        std::mem::take(&mut self.pending)
    }
    fn take_fence(&mut self) -> Option<RemoteFence> {
        let f = self.fences.pop_front();
        if f.is_some() {
            self.fence_taken_held.push(self.holding);
        }
        f
    }
    fn next_seq(&mut self, _vcpu: u8) -> u32 {
        0
    }
    fn post(&mut self, _t: &Trap) -> Result<(), PostError> {
        Err(PostError::Gone)
    }
    fn answer(&mut self) -> Option<Completion> {
        None
    }
    fn park(&mut self) {
        if !self.holding {
            self.waits += 1;
            return;
        }
        self.looks += 1;
        self.clock += self.per_look;
        if self.fence_at_look == Some(self.looks) {
            self.fences.push_back(RemoteFence::Insn);
        }
        if self.line_at_look == Some(self.looks) {
            self.pending |= 1 << 5;
        }
        if self.stop_at_look == Some(self.looks) {
            self.stop = true;
        }
        self.hold_left -= 1;
        if self.hold_left == 0 {
            self.pause = false;
        }
    }
    fn yield_now(&mut self) {}
}

fn ctx() -> GuestCtx {
    GuestCtx::new(Stage2Root { root: 0, aux: 0 }, 1, 0, 0x8000_0000, 0)
}

fn spin(n: usize) -> Vec<(Exit, u64)> {
    let mut v = vec![(Exit::HostInterrupt, 0); n];
    v.push((Exit::Shutdown, 0));
    v
}

// ── the record ──────────────────────────────────────────────────────────

#[test]
fn a_vcpu_is_held_only_while_a_thread_runs_it_and_a_hold_is_asked_once() {
    let mut vms = table("full", 0);
    ready(&mut vms);
    let c = vms.vcpu_mut(0, 0).unwrap();
    assert_eq!(c.request_pause(), Err(PauseError::NotRunning), "nothing to hold in a stopped vCPU");
    assert_eq!(c.request_resume(), Err(PauseError::NotRunning));
    vms.start(0, 0, true, 0b1111, 0, 0).unwrap();
    let c = vms.vcpu_mut(0, 0).unwrap();
    assert_eq!(c.request_resume(), Err(PauseError::NotPaused));
    assert_eq!(c.request_pause(), Ok(()));
    assert_eq!(c.request_pause(), Err(PauseError::AlreadyPaused));
    assert!(c.pause_requested() && !c.is_paused(), "asked is not yet taken: the thread takes it");
    vms.freeze(0, 0, 100);
    let c = vms.vcpu_mut(0, 0).unwrap();
    assert!(c.is_paused());
    assert_eq!(c.run_state(), RunState::Running, "a held vCPU still has its thread: watchers do not see the guest end");
    vms.thaw(0, 0, 140);
    let c = vms.vcpu_mut(0, 0).unwrap();
    assert_eq!((c.is_paused(), vms.lost(0)), (false, 40));
    let c = vms.vcpu_mut(0, 0).unwrap();
    assert!(c.pause_requested(), "the thread leaves the hold when the host clears the request, not by itself");
    assert_eq!(c.request_resume(), Ok(()));
    assert!(!c.pause_requested());
}

#[test]
fn a_vcpu_that_ends_or_restarts_keeps_no_hold_and_the_clock_stays_the_vms() {
    let mut vms = table("full", 0);
    ready(&mut vms);
    vms.start(0, 0, true, 0b1111, 0, 0).unwrap();
    vms.vcpu_mut(0, 0).unwrap().request_pause().unwrap();
    vms.freeze(0, 0, 10);
    vms.thaw(0, 0, 35);
    assert_eq!(vms.lost(0), 25);
    // The thread ends while it holds the guest.
    vms.freeze(0, 0, 40);
    vms.ended(0, 0, None, 50);
    let c = vms.vcpu(0, 0).unwrap();
    assert_eq!((c.pause_requested(), c.is_paused()), (false, false));
    assert_eq!(vms.lost(0), 25, "no vCPU was left to read the clock: the 10 ticks held until the end are not lost time");
    // The clock is the VM's: a restarted vCPU does not begin a clock of its own.
    vms.start(0, 0, true, 0b1111, 0, 60).unwrap();
    assert_eq!(vms.lost(0), 25, "a new run finds the clock the guest has");
    // A stop asked of a held thread is served like any other.
    vms.vcpu_mut(0, 0).unwrap().request_pause().unwrap();
    vms.freeze(0, 0, 70);
    assert!(vms.stop(0, 0).is_ok());
    assert!(vms.vcpu(0, 0).unwrap().stop_requested());
    vms.thaw(0, 0, 80);
    vms.ended(0, 0, None, 80);
    // Destroying the VM gives back what admission made: a recreated guest starts a clock.
    vms.destroyed(0).unwrap();
    assert_eq!(vms.lost(0), 0);
    let c = vms.vcpu(0, 0).unwrap();
    assert_eq!((c.pause_requested(), c.is_paused()), (false, false));
}

// ── the VM's clock ──────────────────────────────────────────────────────

/// A two-vCPU VM with both running, at host tick 0.
fn running_pair() -> VmTable {
    let mut vms = table("full", 0);
    ready(&mut vms);
    vms.start(0, 0, true, 0b1111, 0, 0).unwrap();
    vms.start(0, 1, true, 0b1111, 0, 0).unwrap();
    vms
}

#[test]
fn the_guests_clock_stops_only_while_every_running_vcpu_holds_it() {
    let mut vms = running_pair();
    // One held while the other runs: a vCPU reads the clock, so it runs on.
    vms.freeze(0, 0, 100);
    vms.thaw(0, 0, 150);
    assert_eq!(vms.lost(0), 0, "the held one finds the time when it thaws, as a vCPU the host did not schedule would");
    // Both held: the interval opens when the second freezes (the first froze
    // earlier but the clock was still read until then) and closes at the
    // first thaw: nothing reads the clock inside it.
    vms.freeze(0, 0, 200);
    assert_eq!(vms.lost(0), 0);
    vms.freeze(0, 1, 230);
    vms.thaw(0, 1, 300);
    assert_eq!(vms.lost(0), 70);
    // The other thaws later: the clock runs from the first thaw, nothing more is lost.
    vms.thaw(0, 0, 320);
    assert_eq!(vms.lost(0), 70);
}

#[test]
fn a_tick_that_reaches_the_table_out_of_order_adds_nothing_instead_of_wrapping() {
    // Two threads read the clock, then take the lock in the other order: the
    // thaw carries a tick from before the freeze it follows.
    let mut vms = running_pair();
    vms.freeze(0, 0, 100);
    vms.freeze(0, 1, 101);
    vms.thaw(0, 0, 100);
    assert_eq!(vms.lost(0), 0, "not 2^64 - 1 ticks");
}

#[test]
fn a_vcpu_that_starts_while_the_others_hold_ends_the_hold() {
    let mut vms = table("full", 0);
    ready(&mut vms);
    vms.start(0, 0, true, 0b1111, 0, 0).unwrap();
    vms.freeze(0, 0, 100);
    // The monitor starts the other vCPU of a paused guest: the clock runs again.
    vms.start(0, 1, true, 0b1111, 0, 160).unwrap();
    assert_eq!(vms.lost(0), 60);
    vms.thaw(0, 0, 400);
    assert_eq!(vms.lost(0), 60);
}

#[test]
fn a_vcpu_that_ends_leaves_the_rest_holding_a_clock_that_stops() {
    let mut vms = running_pair();
    vms.freeze(0, 0, 100);
    // The one that ran ends: the one that is left is held, and the clock stops
    // from that instant.
    vms.ended(0, 1, None, 130);
    vms.thaw(0, 0, 200);
    assert_eq!(vms.lost(0), 70);
}

#[test]
fn a_clock_survives_what_ends_every_vcpu_but_not_the_vms_destruction() {
    let mut vms = running_pair();
    vms.freeze(0, 0, 10);
    vms.freeze(0, 1, 20);
    vms.thaw(0, 0, 50);
    assert_eq!(vms.lost(0), 30);
    vms.thaw(0, 1, 60);
    vms.ended(0, 0, None, 70);
    vms.ended(0, 1, None, 70);
    assert_eq!(vms.lost(0), 30);
    vms.start(0, 1, true, 0b1111, 0, 80).unwrap();
    assert_eq!(vms.lost(0), 30, "a vCPU started after both ended reads the clock they did");
    vms.ended(0, 1, None, 90);
    vms.destroyed(0).unwrap();
    assert_eq!(vms.lost(0), 0);
}

// ── the loop ────────────────────────────────────────────────────────────

#[test]
fn a_held_vcpu_does_not_enter_until_it_is_let_go_and_carries_the_time_held() {
    let hv = ScriptHv::new(spin(3));
    let mut host = PHost::new();
    host.holds.push_back((2, 5));
    let mut c = ctx();
    let stop = run::run(&hv, &mut c, &view("full"), &mut host);
    assert_eq!(stop, Stop::Fault(fault::SHUTDOWN << 56));
    let seen = hv.seen.lock().unwrap();
    assert_eq!(seen.len(), 4, "two entries before the hold, two after it: none during");
    assert_eq!(host.looks, 5, "the thread looked five times while held");
    assert_eq!((host.frozen, host.thaws, host.lost), (1, 1, 50));
    let skips: Vec<u64> = seen.iter().map(|e| e.time_skip).collect();
    assert_eq!(skips, [0, 0, 50, 0], "the first entry after the hold carries it, once");
    assert_eq!(host.waits, 0);
}

#[test]
fn every_hold_carries_its_own_time() {
    let hv = ScriptHv::new(spin(5));
    let mut host = PHost::new();
    host.holds.extend([(1, 2), (4, 3)]);
    let mut c = ctx();
    run::run(&hv, &mut c, &view("full"), &mut host);
    let skips: Vec<u64> = hv.seen.lock().unwrap().iter().map(|e| e.time_skip).collect();
    assert_eq!(skips, [0, 20, 0, 0, 30, 0]);
    assert_eq!((host.thaws, host.lost), (2, 50));
}

#[test]
fn a_vcpu_that_is_never_held_is_told_no_time_has_gone() {
    let hv = ScriptHv::new(spin(4));
    let mut host = PHost::new();
    host.clock = 12345;
    let mut c = ctx();
    run::run(&hv, &mut c, &view("full"), &mut host);
    assert!(hv.seen.lock().unwrap().iter().all(|e| e.time_skip == 0));
    assert_eq!((host.frozen, host.thaws, host.looks), (0, 0, 0));
}

#[test]
fn a_stop_ends_a_hold_and_the_guest_does_not_run_again() {
    let hv = ScriptHv::new(spin(3));
    let mut host = PHost::new();
    host.holds.push_back((2, 100));
    host.stop_at_look = Some(3);
    let mut c = ctx();
    let stop = run::run(&hv, &mut c, &view("full"), &mut host);
    assert_eq!(stop, Stop::Requested);
    assert_eq!(hv.seen.lock().unwrap().len(), 2, "nothing entered after the hold began");
    assert_eq!(host.thaws, 1, "the hold is left");
}

#[test]
fn a_fence_another_vcpu_asked_is_carried_out_while_this_one_is_held() {
    // A vCPU that asked this one for a fence waits for it: a hold that did not
    // serve it would deadlock the asker.
    let hv = ScriptHv::new(spin(3));
    let mut host = PHost::new();
    host.holds.push_back((2, 5));
    host.fence_at_look = Some(2);
    let mut c = ctx();
    run::run(&hv, &mut c, &view("full"), &mut host);
    assert_eq!(*hv.fenced.lock().unwrap(), [2], "carried out once, before the third entry");
    assert_eq!(host.fence_taken_held, [true], "taken while held: the asker does not wait for the resume");
}

#[test]
fn what_the_guest_was_in_the_middle_of_and_what_was_raised_meanwhile_wait_for_the_resume() {
    // The guest's load was answered (no device there reads 0) and the hold
    // begins before the entry that would complete it.
    let load = Exit::Mmio(access(0x10, false, 4));
    let hv = ScriptHv::new(vec![(load, 0), (Exit::HostInterrupt, 0), (Exit::Shutdown, 0)]);
    let mut host = PHost::new();
    host.holds.push_back((1, 4));
    host.line_at_look = Some(2);
    let mut c = ctx();
    c.frame[7] = 0xAB_CDEF;
    run::run(&hv, &mut c, &view("full"), &mut host);
    let seen = hv.seen.lock().unwrap();
    assert_eq!(seen.len(), 3);
    assert!(seen[1].completed.is_some(), "the access is completed at the first entry after the resume");
    assert_eq!(seen[1].irqs, 1 << 5, "the line raised during the hold is presented at that entry");
    assert_eq!(seen[0].irqs, 0);
    assert_eq!(c.frame[7], 0xAB_CDEF, "the loop does not touch the registers");
}

#[test]
fn a_guest_that_waits_for_an_interrupt_is_held_like_any_other() {
    let hv = ScriptHv::new(vec![(Exit::Wait, 0), (Exit::Wait, 0), (Exit::Shutdown, 0)]);
    let mut host = PHost::new();
    host.holds.push_back((1, 3));
    let mut c = ctx();
    run::run(&hv, &mut c, &view("full"), &mut host);
    assert_eq!(host.waits, 2, "the guest's own two waits; the three looks of the hold are counted apart");
    assert_eq!(host.looks, 3);
    assert_eq!(hv.seen.lock().unwrap().iter().map(|e| e.time_skip).collect::<Vec<_>>(), [0, 30, 0]);
}

#[test]
fn a_vcpu_started_after_a_hold_takes_all_the_lost_time_at_its_first_entry_and_no_more() {
    let hv = ScriptHv::new(spin(2));
    let mut host = PHost::new();
    // The VM lost 40 ticks before this vCPU started, and 30 more are lost while it runs.
    host.lost = 40;
    host.holds.push_back((2, 3));
    let mut c = ctx();
    run::run(&hv, &mut c, &view("full"), &mut host);
    let skips: Vec<u64> = hv.seen.lock().unwrap().iter().map(|e| e.time_skip).collect();
    assert_eq!(skips, [40, 0, 30], "all of it once at the start; what the hold added after it");
}

/// The kernel's end of the loop over a real [`VmTable`], for the vCPU `k` of
/// the VM: the table decides what is held and what the VM has lost, the clock
/// is one the test moves.
struct TblHost {
    vms: Rc<RefCell<VmTable>>,
    now: Rc<Cell<u64>>,
    k: usize,
    entries: u32,
    /// `(entry, looks)`: a pause is asked at that entry and a resume follows
    /// `looks` looks of the held thread later.
    holds: VecDeque<(u32, u32)>,
    hold_left: u32,
    holding: bool,
}

impl TblHost {
    fn new(vms: &Rc<RefCell<VmTable>>, now: &Rc<Cell<u64>>, k: usize, holds: &[(u32, u32)]) -> TblHost {
        TblHost { vms: vms.clone(), now: now.clone(), k, entries: 0, holds: holds.iter().copied().collect(), hold_left: 0, holding: false }
    }
}

impl RunHost for TblHost {
    fn stop_requested(&mut self) -> bool {
        false
    }
    fn pause_requested(&mut self) -> bool {
        self.vms.borrow().vcpu(0, self.k).unwrap().pause_requested()
    }
    fn freeze(&mut self) {
        self.holding = true;
        self.vms.borrow_mut().freeze(0, self.k, self.now.get());
    }
    fn thaw(&mut self) {
        self.holding = false;
        self.vms.borrow_mut().thaw(0, self.k, self.now.get());
    }
    fn lost(&mut self) -> u64 {
        self.vms.borrow().lost(0)
    }
    fn take_irqs(&mut self) -> u64 {
        self.entries += 1;
        if self.holds.front().is_some_and(|h| h.0 == self.entries) {
            self.hold_left = self.holds.pop_front().unwrap().1;
            self.vms.borrow_mut().vcpu_mut(0, self.k).unwrap().request_pause().unwrap();
        }
        0
    }
    fn next_seq(&mut self, _vcpu: u8) -> u32 {
        0
    }
    fn post(&mut self, _t: &Trap) -> Result<(), PostError> {
        Err(PostError::Gone)
    }
    fn answer(&mut self) -> Option<Completion> {
        None
    }
    fn park(&mut self) {
        if !self.holding {
            return;
        }
        self.now.set(self.now.get() + 10);
        self.hold_left -= 1;
        if self.hold_left == 0 {
            self.vms.borrow_mut().vcpu_mut(0, self.k).unwrap().request_resume().unwrap();
        }
    }
    fn yield_now(&mut self) {}
}

/// Run vCPU 0 of a two-vCPU guest through a hold of 40 ticks, start vCPU 1
/// while vCPU 0 still runs (a guest's `hart_start`, `CPU_ON`, SIPI), and run
/// it. What each entry of the two was told to take off its clock
/// (`GuestCtx::time_skip`), through the real loop and the real table.
pub(crate) fn skips_of_a_vcpu_started_after_a_pause() -> (Vec<u64>, Vec<u64>) {
    let vms = Rc::new(RefCell::new(table("full", 0)));
    ready(&mut vms.borrow_mut());
    let now = Rc::new(Cell::new(1000));
    vms.borrow_mut().start(0, 0, true, 0b1111, 0, now.get()).unwrap();
    let hv0 = ScriptHv::new(spin(4));
    let mut c0 = ctx();
    run::run(&hv0, &mut c0, &view("full"), &mut TblHost::new(&vms, &now, 0, &[(2, 4)]));
    assert_eq!(vms.borrow().lost(0), 40);
    // vCPU 0 ran on: the guest starts the other one a while later.
    now.set(now.get() + 500);
    vms.borrow_mut().start(0, 1, true, 0b1111, 0, now.get()).unwrap();
    let hv1 = ScriptHv::new(spin(2));
    let mut c1 = ctx();
    c1.vcpu = 1;
    run::run(&hv1, &mut c1, &view("full"), &mut TblHost::new(&vms, &now, 1, &[]));
    let skips = |hv: &ScriptHv| hv.seen.lock().unwrap().iter().map(|e| e.time_skip).collect::<Vec<_>>();
    (skips(&hv0), skips(&hv1))
}

#[test]
fn a_vcpu_started_after_a_pause_is_told_the_time_the_running_one_was_told() {
    let (first, second) = skips_of_a_vcpu_started_after_a_pause();
    assert_eq!(first, [0, 0, 40, 0, 0], "the hold of 40 ticks reaches the entry after it");
    assert_eq!(second, [40, 0, 0], "the vCPU the guest starts later takes the 40 at its first entry");
    assert_eq!(first.iter().sum::<u64>(), second.iter().sum::<u64>());
}

// ── the ISAs ────────────────────────────────────────────────────────────

#[test]
fn riscv64_takes_the_time_held_off_the_guests_time_and_keeps_it_off() {
    let steps = [Step::Wfi, Step::Wfi, Step::Wfi, Step::Wfi];
    let hv = FakeHart::new(&steps);
    let mut host = PHost::new();
    host.holds.push_back((2, 4));
    host.stop_at_entry = Some(4);
    let mut c = rv_ctx(0);
    assert_eq!(run::run(&hv, &mut c, &view("full"), &mut host), Stop::Requested);
    let delta: Vec<u64> = hv.seen.lock().unwrap().iter().map(|s| s.htimedelta).collect();
    let back = 0u64.wrapping_sub(40);
    assert_eq!(delta, [0, 0, back, back], "guest time is host time plus this: it lags by the 40 ticks held, from then on");
}

#[test]
fn riscv64_loads_the_delta_into_the_hart_and_a_restarted_vcpu_starts_from_none() {
    let mut h = Rec(vec![]);
    let mut c = rv_ctx(0);
    for skip in [0, 100, 0, 40] {
        c.time_skip = skip;
        unsafe { guest::enter_vcpu(&mut h, &mut c, 0) };
        c.started = true;
    }
    assert_eq!(h.0, [0, 0u64.wrapping_sub(100), 0u64.wrapping_sub(100), 0u64.wrapping_sub(140)]);
    // The vCPU stops and starts again: a new guest clock, then the time held.
    c.started = false;
    c.time_skip = 7;
    unsafe { guest::enter_vcpu(&mut h, &mut c, 0) };
    assert_eq!(*h.0.last().unwrap(), 0u64.wrapping_sub(7));
}

#[test]
fn aarch64_moves_the_count_offset_so_the_guests_timer_fires_later_by_the_time_held() {
    // Virtual count = physical - offset. The guest armed its timer for
    // virtual count 1000 with the offset at 5000: due at physical 6000.
    let mut g = GuestIrq::new(4, 5000);
    g.after_exit(&[], 1, 1000);
    assert_eq!(g.wake_at(), Some(6000));
    assert_eq!(g.cntvoff(), 5000);
    // Held for 500 physical counts.
    g.skip_time(500);
    assert_eq!(g.cntvoff(), 5500, "the count the guest reads resumes where it stopped");
    assert_eq!(g.wake_at(), Some(6500), "and so does the timer: later by the time held");
    // At physical 6200 the guest's count is 700: not due. Without the skip it was.
    let plan = g.pre_entry(0, 6200);
    assert!(!plan.silence_ppi, "the timer's line is not asserted");
    let mut no_hold = GuestIrq::new(4, 5000);
    no_hold.after_exit(&[], 1, 1000);
    assert!(no_hold.pre_entry(0, 6200).silence_ppi, "the same timer without the hold is due");
    // Nothing held, nothing moved.
    g.skip_time(0);
    assert_eq!(g.cntvoff(), 5500);
}

/// A hart that only records the `htimedelta` it was told to load.
struct Rec(Vec<u64>);

impl guest::Hart for Rec {
    fn irqs_off(&mut self) -> bool {
        true
    }
    fn irqs_restore(&mut self, _were_on: bool) {}
    fn hart_id(&mut self) -> u64 {
        0
    }
    unsafe fn run(&mut self, st: &mut VcpuState, _hgatp: u64, _vmid: u16, _flush: bool) {
        self.0.push(st.htimedelta);
        st.frame.scause = 22;
    }
}

/// The `htimedelta` the hart loaded at each entry of vCPU `k`, told `skips`.
fn rv_deltas(k: u8, skips: &[u64]) -> Vec<u64> {
    let mut h = Rec(vec![]);
    let mut c = rv_ctx(k);
    for &skip in skips {
        c.time_skip = skip;
        unsafe { guest::enter_vcpu(&mut h, &mut c, 0) };
        c.started = true;
    }
    h.0
}

#[test]
fn riscv64_a_vcpu_started_after_a_pause_reads_the_time_the_running_one_reads() {
    let (first, second) = skips_of_a_vcpu_started_after_a_pause();
    let (a, b) = (rv_deltas(0, &first), rv_deltas(1, &second));
    assert_eq!(*a.last().unwrap(), 0u64.wrapping_sub(40), "the running vCPU lags the host by the 40 ticks held");
    assert_eq!(b[0], *a.last().unwrap(), "so does the one the guest starts afterwards, from its first entry");
    assert!(b.iter().all(|&d| d == b[0]));
}

#[test]
fn aarch64_a_vcpu_started_after_a_pause_reads_the_count_the_running_one_reads() {
    let (first, second) = skips_of_a_vcpu_started_after_a_pause();
    // Every vCPU starts from the VM's offset (the slot of the first one).
    let at = |skips: &[u64]| {
        let mut g = GuestIrq::new(4, 5000);
        g.after_exit(&[], 1, 1000);
        skips.iter().for_each(|&s| g.skip_time(s));
        g
    };
    let (a, b) = (at(&first), at(&second));
    assert_eq!(a.cntvoff(), 5040, "the running vCPU's count lags by the 40 held");
    assert_eq!(b.cntvoff(), a.cntvoff(), "one CNTVOFF for the VM: the vCPU started later reads the same count");
    assert_eq!(b.wake_at(), a.wake_at(), "and its timer, set to the same count, is due at the same physical count");
}

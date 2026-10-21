// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The vCPU record: where it may run, which virtual interrupts wait for it and
//! whether its thread runs, or is held.
//!
//! This is the control plane the `Vcpu` interface serves. The thread that runs
//! the guest is [`crate::run`]'s loop, started by the kernel on the hart
//! [`Vcpu`]'s placement names ([`pick_hart`]) and ended by `stop`, by a fault
//! the loop cannot serve, or by the VM's destruction.
//!
//! One rule is enforced from the first boot: **real-time harts never run a
//! vCPU.** [`allowed`] removes the harts that hold a deadline reservation
//! from every affinity, whatever the caller asks for; admission applies it to
//! the topology's placement, `Vcpu::set_affinity` to a caller's mask and
//! [`pick_hart`] to the hart a started vCPU is created on.

use azos_arch_api::RemoteFence;

/// Whether a vCPU's thread runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum RunState {
    /// No thread: never started, stopped, or given back by `destroy`.
    Stopped = 0,
    /// A thread runs it (or is on its way to).
    Running = 1,
    /// The thread ended on an exit the loop does not serve; [`Vcpu::fault`]
    /// says which.
    Faulted = 2,
}

/// Why a vCPU was not paused or resumed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PauseError {
    /// No thread runs the vCPU: there is nothing to hold.
    NotRunning,
    /// A pause is already asked (or taken).
    AlreadyPaused,
    /// No pause is asked: there is nothing to resume.
    NotPaused,
}

/// One virtual CPU.
#[derive(Clone, Copy, Debug)]
pub struct Vcpu {
    /// Which VM, and which of its CPUs.
    pub vm: u8,
    pub index: u8,
    /// Harts it may run on: [`allowed`] of what the caller asked for.
    pub affinity: u64,
    /// The affinity admission gave it; [`Vcpu::reset`] restores it.
    home: u64,
    /// Virtual interrupt lines raised and not yet taken by the guest.
    pending_irqs: u64,
    run: RunState,
    /// `stop` was asked while the thread runs; the thread ends at its next exit.
    stop_req: bool,
    /// Why the thread faulted: the exit as [`crate::run::fault_code`] words it.
    fault: u64,
    /// The fences other vCPUs asked this one to carry out before its next
    /// entry: instruction fetch, translations (see [`Vcpu::request_fence`]).
    fence_insn: bool,
    fence_tlb: bool,
    /// The guest's timer: the deadline (guest ticks) and the line it asserts.
    timer: u64,
    timer_line: u8,
    /// `pause` was asked and `resume` has not been: the thread holds the guest
    /// at its next look, keeping every register.
    pause_req: bool,
    /// The thread has taken the hold: the guest is out of guest mode and will
    /// not enter again until `resume`.
    paused: bool,
}

/// A timer deadline that never comes.
pub const TIMER_NEVER: u64 = u64::MAX;

impl Vcpu {
    pub const EMPTY: Vcpu = Vcpu::new(0, 0, 0);

    pub const fn new(vm: u8, index: u8, affinity: u64) -> Vcpu {
        Vcpu {
            vm,
            index,
            affinity,
            home: affinity,
            pending_irqs: 0,
            run: RunState::Stopped,
            stop_req: false,
            fault: 0,
            fence_insn: false,
            fence_tlb: false,
            timer: TIMER_NEVER,
            timer_line: 0,
            pause_req: false,
            paused: false,
        }
    }

    /// Raise virtual interrupt line `irq` (0..64).
    pub fn inject(&mut self, irq: u32) -> Result<(), BadIrq> {
        if irq >= 64 {
            return Err(BadIrq);
        }
        self.pending_irqs |= 1 << irq;
        Ok(())
    }

    /// The lines raised and not yet taken.
    pub fn pending(&self) -> u64 {
        self.pending_irqs
    }

    /// Take the lines raised since the last entry: the thread presents them
    /// to the guest.
    pub fn take_irqs(&mut self) -> u64 {
        core::mem::take(&mut self.pending_irqs)
    }

    /// Ask this vCPU to carry out `fence` before it next enters the guest.
    /// Requests coalesce: any number of translation fences become one flush of
    /// everything (a superset of each, so never too little), and instruction
    /// fences one.
    pub fn request_fence(&mut self, fence: RemoteFence) {
        match fence {
            RemoteFence::Insn => self.fence_insn = true,
            RemoteFence::Tlb { .. } => self.fence_tlb = true,
        }
    }

    /// The next fence to carry out, if one was asked. A translation fence is
    /// the whole address space.
    pub fn take_fence(&mut self) -> Option<RemoteFence> {
        if core::mem::take(&mut self.fence_insn) {
            return Some(RemoteFence::Insn);
        }
        core::mem::take(&mut self.fence_tlb).then_some(RemoteFence::Tlb { start: 0, size: u64::MAX, asid: None })
    }

    /// Is a fence asked and not yet carried out?
    pub fn fence_pending(&self) -> bool {
        self.fence_insn || self.fence_tlb
    }

    /// Make `deadline` (guest ticks) the vCPU's only timer deadline; while the
    /// guest's time is at or past it, line `line` is asserted ([`Vcpu::levels`]).
    pub fn arm_timer(&mut self, deadline: u64, line: u32) {
        self.timer = deadline;
        self.timer_line = (line & 63) as u8;
    }

    /// The timer's deadline ([`TIMER_NEVER`]: none).
    pub fn timer_deadline(&self) -> u64 {
        self.timer
    }

    /// The lines that are asserted by a level the monitor derives, at guest
    /// time `now`: the timer's, once its deadline has passed.
    pub fn levels(&self, now: u64) -> u64 {
        if self.timer != TIMER_NEVER && now >= self.timer { 1 << self.timer_line } else { 0 }
    }

    pub fn run_state(&self) -> RunState {
        self.run
    }

    /// The exit a faulted thread ended on (0 while it has not faulted).
    pub fn fault(&self) -> u64 {
        self.fault
    }

    /// Has `stop` been asked of the running thread?
    pub fn stop_requested(&self) -> bool {
        self.stop_req
    }

    /// Ask the running thread to hold the guest at its next look: it stops
    /// entering, keeps the registers and the pending lines, and says so
    /// ([`Vcpu::freeze`]). A thread that does not run has nothing to hold.
    pub fn request_pause(&mut self) -> Result<(), PauseError> {
        if self.run != RunState::Running {
            return Err(PauseError::NotRunning);
        }
        if self.pause_req {
            return Err(PauseError::AlreadyPaused);
        }
        self.pause_req = true;
        Ok(())
    }

    /// Let the held thread enter again (or cancel a pause it has not taken).
    pub fn request_resume(&mut self) -> Result<(), PauseError> {
        if self.run != RunState::Running {
            return Err(PauseError::NotRunning);
        }
        if !self.pause_req {
            return Err(PauseError::NotPaused);
        }
        self.pause_req = false;
        Ok(())
    }

    /// Has a pause been asked and not resumed?
    pub fn pause_requested(&self) -> bool {
        self.pause_req
    }

    /// Has the thread taken the hold: is the guest out of guest mode?
    pub fn is_paused(&self) -> bool {
        self.paused
    }

    /// The thread took the hold. The VM's clock is the table's to stop
    /// ([`crate::vm::VmTable::freeze`]).
    pub(crate) fn freeze(&mut self) {
        self.paused = true;
    }

    /// The thread leaves the hold ([`crate::vm::VmTable::thaw`]).
    pub(crate) fn thaw(&mut self) {
        self.paused = false;
    }

    pub(crate) fn set_running(&mut self) {
        self.fence_insn = false;
        self.fence_tlb = false;
        self.timer = TIMER_NEVER;
        self.run = RunState::Running;
        self.stop_req = false;
        self.fault = 0;
        self.pause_req = false;
        self.paused = false;
    }

    pub(crate) fn request_stop(&mut self) {
        self.stop_req = true;
    }

    pub(crate) fn set_ended(&mut self, fault: Option<u64>) {
        self.stop_req = false;
        self.pause_req = false;
        self.paused = false;
        self.fence_insn = false;
        self.fence_tlb = false;
        self.timer = TIMER_NEVER;
        match fault {
            Some(code) => {
                self.run = RunState::Faulted;
                self.fault = code;
            }
            None => self.run = RunState::Stopped,
        }
    }

    /// Back to what admission made it: no interrupt pending, the affinity it
    /// was given. The VM's `destroy` does this, so a recreated VM inherits
    /// nothing of the one before.
    pub fn reset(&mut self) {
        self.pending_irqs = 0;
        self.fence_insn = false;
        self.fence_tlb = false;
        self.timer = TIMER_NEVER;
        self.affinity = self.home;
        self.run = RunState::Stopped;
        self.stop_req = false;
        self.pause_req = false;
        self.paused = false;
        self.fault = 0;
    }
}

/// An interrupt line past the 64 a vCPU tracks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BadIrq;

/// The harts a vCPU with `affinity` may use on a machine whose online harts
/// are `online` and whose harts holding a deadline reservation are `rt`: its
/// affinity, less the harts that are offline and less the real-time ones,
/// whatever the affinity says.
pub const fn allowed(affinity: u64, online: u64, rt: u64) -> u64 {
    if cfg!(feature = "canary-rt-hart") { affinity & online } else { affinity & online & !rt }
}

/// The hart vCPU `index` of a VM is created on: the `index`-th (modulo how
/// many) of the harts it is [`allowed`] on, so the vCPUs of one VM spread
/// over the harts it may use instead of piling on the first. `None` when no
/// hart is left: a vCPU is refused, never placed on a real-time hart.
pub fn pick_hart(affinity: u64, online: u64, rt: u64, index: u8) -> Option<u8> {
    let mask = allowed(affinity, online, rt);
    let n = mask.count_ones();
    if n == 0 {
        return None;
    }
    let mut m = mask;
    for _ in 0..(index as u32 % n) {
        m &= m.wrapping_sub(1);
    }
    Some(m.trailing_zeros() as u8)
}

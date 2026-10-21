// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The vCPU loop: enter the guest, serve what stopped it, enter again.
//!
//! One vCPU is one kernel thread running [`run`] on a hart that holds no
//! deadline reservation ([`crate::vcpu::pick_hart`]). The loop is the same on
//! the three ISAs: the entry is [`Hypervisor::enter`], which answers the exit
//! already decoded, and everything the loop needs from the kernel (the lock
//! around the monitor's tables, the ring page, the event port, sleeping) is
//! the [`RunHost`] the kernel implements, so the whole loop runs under the
//! host tests.
//!
//! # What an exit becomes
//!
//! | exit | served as |
//! |------|-----------|
//! | decoded MMIO load / store in the window of the VM's interrupt controller (riscv64: the PLIC) | served in place by [`RunHost::intc_mmio`]: no trap, no device model |
//! | decoded MMIO load / store in a registered window | a [`Trap`] posted on the ring; the vCPU waits for its [`Completion`] (the device model's answer) |
//! | decoded MMIO anywhere else | a bus that answers 0 and drops stores |
//! | a *store* to a window of a backend the VM's envelope forbids ([`crate::backend::allows`]) | refused: dropped, recorded as `Rule::GuestEgress` |
//! | `Wait` (`wfi`, `hlt`) | the thread sleeps until a virtual interrupt is raised or a stop is asked |
//! | `HostInterrupt` | the thread gives the hart up and enters again |
//! | `Hypercall` (the firmware interface a guest boots through: the SBI on riscv64) | served by the ISA through [`RunHost::hypercall_host`] ([`Hypervisor::hypercall`]): answered (the fences it asked of other vCPUs done before the guest runs on), or the vCPU ends, or the guest ends the machine |
//! | anything else | the vCPU **faults**: the thread ends and [`fault_code`] says why |
//!
//! "Anything else" is CPUID, trapped system registers, port I/O, undecoded
//! stage-2 faults, a shutdown, and a hypercall the ISA or the host does not
//! serve. Serving them is the guest-boot step's (S6); until then a guest that
//! reaches one stops where it is, visibly, instead of being answered with a
//! guess.
//!
//! A hypercall that ends the machine (SBI `system_reset`) ends the thread
//! with [`fault::SHUTDOWN`] and the reset kind and reason in the detail
//! ([`shutdown_code`]); the VM's state then reads as the end of a machine to
//! whoever polls it (vmmd), the same word a triple fault gives.
//!
//! # Stopping
//!
//! `Vcpu::stop` sets a flag the loop reads before every entry and while it
//! waits for a device model, and a host interrupt ends an entry, so a guest
//! that never exits still stops within a timer tick.
//!
//! # Pausing
//!
//! `Vcpu::pause` sets a second flag, read at the same places as the first
//! ([`RunHost::pause_requested`]). The loop holds the guest where an exit left
//! it: the context (the registers and control state the ISA keeps in it, the
//! access it has yet to complete) stays in the loop's frame untouched, the
//! virtual interrupt lines raised meanwhile stay pending with the host, and
//! the loop does not enter until `Vcpu::resume` clears the flag. A guest that
//! never exits is out of guest mode within a timer tick, the same bound as a
//! stop; one that waits for a device model's answer is held once the answer
//! landed. While held the loop carries out the fences other vCPUs ask of it (a
//! requester waits for them) and a `stop` still ends it.
//!
//! The guest does not see the time it was held. The VM has one clock: the host
//! keeps the time every running vCPU was held together ([`RunHost::lost`]; the
//! rule is `VmTable::freeze`'s), and the loop hands the ISA the part its vCPU
//! has not yet taken off its own clock as [`GuestCtx::time_skip`] (riscv64
//! `htimedelta`, aarch64 `CNTVOFF_EL2`, x86_64 the VMCB's TSC offset). The
//! first entry of a vCPU carries all of it, so a vCPU the guest starts later
//! (or one restarted after a stop) reads the clock the running ones read, and
//! the first entry after a hold carries what the hold added.

use azos_arch_api::{Exit, GuestCtx, HypercallHost, HypercallOutcome, Hypervisor, MmioAccess, MmioDone, RemoteFence};
use azos_decision::{Rule, Verdict};
use azos_topology::Envelope;

use crate::backend::{self, Backend};
use crate::trapwire::{cpl, Completion, Trap};
use crate::vm::{Space, Window, MAX_WINDOWS};

/// Why a trap was not posted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PostError {
    /// The ring holds as many traps as it can: try again after waiting.
    Full,
    /// Nobody will answer: the monitor's event port or page is gone.
    Gone,
}

/// What the loop needs of the kernel.
pub trait RunHost {
    /// Has `Vcpu::stop` been asked?
    fn stop_requested(&mut self) -> bool;
    /// Has `Vcpu::pause` been asked (and `Vcpu::resume` not)?
    fn pause_requested(&mut self) -> bool {
        false
    }
    /// The loop holds the guest: say so (`Vcpu::state` reads it). The guest's
    /// clock stops counting while every running vCPU of the VM holds.
    fn freeze(&mut self) {}
    /// The loop leaves the hold.
    fn thaw(&mut self) {}
    /// Host ticks the VM's guest clock lags the host's: the time the VM was
    /// held, as of now. It only grows within a VM's life, and only while no
    /// vCPU runs, so a running vCPU reads it again after a hold and when it
    /// starts, not at every entry.
    fn lost(&mut self) -> u64 {
        0
    }
    /// The virtual interrupt lines raised for this vCPU since the last call
    /// (taken: the next call does not repeat them).
    fn take_irqs(&mut self) -> u64;
    /// The sequence number of the next trap of vCPU `vcpu` (see
    /// [`crate::ring::Mailbox::next_seq`]): it never repeats within a VM's
    /// life, so an answer to a trap of an earlier run is not taken for the
    /// answer to this one.
    fn next_seq(&mut self, vcpu: u8) -> u32;
    /// Post `t` on the trap ring, remember that this vCPU waits for its
    /// answer, and signal the event port that wakes the device models.
    fn post(&mut self, t: &Trap) -> Result<(), PostError>;
    /// The answer to the posted trap if it is here; if not, wait a bounded
    /// time for it (the device model's `kick`, or the slice running out) and
    /// say `None`: the loop then reads [`RunHost::stop_requested`] and asks
    /// again.
    fn answer(&mut self) -> Option<Completion>;
    /// The guest waits for an interrupt: sleep until one is raised, a stop is
    /// asked, or a bounded time passes.
    fn park(&mut self);
    /// Give the hart to something else; come back.
    fn yield_now(&mut self);
    /// The VM's interrupt controller, when its guest finds one in
    /// guest-physical space (riscv64: the PLIC, [`crate::vplic`]): serve the
    /// decoded access `a` if it falls in the controller's window, and answer
    /// with the value a load reads (a store: 0; `value` is what it writes).
    /// `None`: not the controller's window, the access goes on to the device
    /// windows. The controller is the VM's, shared by its vCPUs, so it lives
    /// with the host, and so does what a change of a line asks of the other
    /// vCPUs (kick the ones whose line went up).
    fn intc_mmio(&mut self, a: &MmioAccess, value: u64) -> Option<u64> {
        let _ = (a, value);
        None
    }
    /// The VM as a hypercall sees it (the other vCPUs, interrupt lines,
    /// timer, console). `None`: this host serves none, and a hypercall
    /// faults the vCPU.
    fn hypercall_host(&mut self) -> Option<&mut dyn HypercallHost> {
        None
    }
    /// The next fence other vCPUs asked this one to carry out
    /// ([`HypercallHost::fence`]); the loop runs it before every entry.
    fn take_fence(&mut self) -> Option<RemoteFence> {
        None
    }
    /// Has a fence this vCPU asked of others in its last hypercall not been
    /// carried out yet (and its target still runs)? The loop does not resume
    /// the guest until none is outstanding.
    fn fences_outstanding(&mut self) -> bool {
        false
    }
}

/// What the loop reads of a VM, copied when the vCPU starts: the windows and
/// backends cannot change while it runs.
#[derive(Clone, Copy, Debug)]
pub struct RunView {
    /// The VM's index (its decisions' subject is `index + 1`, the badge).
    pub index: u8,
    pub envelope: Envelope,
    kinds: u64,
    devices: u8,
    windows: [Option<Window>; MAX_WINDOWS],
}

impl RunView {
    pub fn new(vm: &crate::vm::Vm) -> RunView {
        RunView {
            index: vm.index,
            envelope: vm.envelope,
            kinds: vm.kinds,
            devices: vm.devices_len() as u8,
            windows: vm.windows(),
        }
    }

    fn window_at(&self, space: Space, addr: u64) -> Option<Window> {
        self.windows.iter().flatten().copied().find(|w| w.space == space && addr >= w.base && addr - w.base < w.len)
    }

    fn backend(&self, device: u8) -> Option<Backend> {
        if device >= self.devices {
            return None;
        }
        backend::kind_at(self.kinds, device as usize)
    }
}

/// What to do with a decoded MMIO access.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Routed {
    /// Post this trap and wait for the answer.
    Post(Trap),
    /// No device: a load reads this value.
    NoDevice(u64),
    /// The envelope forbids it: dropped, and the refusal is to be recorded.
    Refused { backend: Backend, gpa: u64 },
}

/// Where a decoded MMIO access of vCPU `vcpu` goes. `value` is the value a
/// store writes; `seq` the sequence number a trap carries.
pub fn route_mmio(view: &RunView, vcpu: u8, a: &MmioAccess, value: u64, seq: u32) -> Routed {
    let Some(w) = view.window_at(Space::Mmio, a.gpa) else { return Routed::NoDevice(0) };
    let Some(b) = view.backend(w.device) else { return Routed::NoDevice(0) };
    if a.write && !backend::allows(view.envelope, b.reach()) {
        return Routed::Refused { backend: b, gpa: a.gpa };
    }
    let mask = if a.size >= 8 { u64::MAX } else { (1u64 << (a.size as u32 * 8)) - 1 };
    Routed::Post(Trap { seq, vcpu, write: a.write, len: a.size, gpa: a.gpa, data: if a.write { value & mask } else { 0 } })
}

/// Record a refused egress: VM `index`'s guest was asked for an effect of
/// `backend` past its `envelope`. Subject: the VM's badge. Numbers: the
/// backend's kind code, the guest-physical address (0 for an attach), the
/// envelope level.
pub fn record_refusal(index: u8, envelope: Envelope, backend: Backend, gpa: u64) {
    azos_decision::record(
        Rule::GuestEgress,
        Verdict::Refuse,
        crate::vm::vm_badge(index),
        [backend as u64, gpa, envelope as u64],
    );
}

/// Why the loop ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stop {
    /// `Vcpu::stop`, or the guest stopped its own vCPU (SBI `hart_stop`).
    Requested,
    /// An exit the loop does not serve; the code is [`fault_code`]'s.
    Fault(u64),
}

/// `fault_code` kinds (the top byte).
pub mod fault {
    pub const STAGE2: u64 = 1;
    pub const PIO: u64 = 2;
    pub const HYPERCALL: u64 = 3;
    pub const CPUID: u64 = 4;
    pub const SYSREG: u64 = 5;
    pub const SHUTDOWN: u64 = 6;
    pub const INVALID_STATE: u64 = 7;
    pub const OTHER: u64 = 8;
    /// The monitor's trap page or event port is gone.
    pub const MONITOR_GONE: u64 = 9;
}

/// An exit the loop does not serve, as a word: the kind in the top byte
/// ([`fault`]), what the exit carries (the guest-physical address, the ISA's
/// raw code, the port) in the rest.
pub fn fault_code(e: &Exit) -> u64 {
    let (k, d) = match *e {
        Exit::Fault { gpa, .. } => (fault::STAGE2, gpa),
        Exit::Pio(p) => (fault::PIO, p.port as u64),
        Exit::Hypercall => (fault::HYPERCALL, 0),
        Exit::Cpuid => (fault::CPUID, 0),
        Exit::SysReg { write } => (fault::SYSREG, write as u64),
        Exit::Shutdown => (fault::SHUTDOWN, 0),
        Exit::InvalidState => (fault::INVALID_STATE, 0),
        Exit::Other(c) => (fault::OTHER, c),
        // Never faults: served.
        Exit::Mmio(a) => (fault::STAGE2, a.gpa),
        Exit::Wait | Exit::HostInterrupt => (fault::OTHER, 0),
    };
    k << 56 | (d & ((1 << 56) - 1))
}

/// The [`Stop::Fault`] code of a guest that ended the machine: kind
/// [`fault::SHUTDOWN`], then the reset kind (0 shutdown, 1 cold reboot, 2 warm
/// reboot) in bits 32.. and the guest's reason in the low 32 bits.
pub const fn shutdown_code(kind: u32, reason: u32) -> u64 {
    fault::SHUTDOWN << 56 | (kind as u64) << 32 | reason as u64
}

/// Run the vCPU of `ctx` until it stops. `ctx` is the vCPU's own context,
/// `view` the VM as it was when the vCPU started.
pub fn run(hv: &dyn Hypervisor, ctx: &mut GuestCtx, view: &RunView, host: &mut dyn RunHost) -> Stop {
    // What of the VM's lost time this vCPU's clock has taken off already: none
    // at its first entry, which carries all of it.
    let mut applied = 0;
    ctx.time_skip = host.lost();
    loop {
        if host.stop_requested() {
            return Stop::Requested;
        }
        if host.pause_requested() {
            if !hold(hv, ctx, host) {
                return Stop::Requested;
            }
            ctx.time_skip = host.lost().wrapping_sub(applied);
        }
        serve_fences(hv, ctx, host);
        ctx.irqs = host.take_irqs();
        let exit = hv.enter(ctx);
        ctx.started = true;
        ctx.irqs = 0;
        applied = applied.wrapping_add(core::mem::take(&mut ctx.time_skip));
        match exit {
            Exit::HostInterrupt => host.yield_now(),
            Exit::Wait => host.park(),
            Exit::Mmio(a) => {
                if let Some(v) = host.intc_mmio(&a, ctx.mmio_value) {
                    complete(ctx, a, v);
                    continue;
                }
                match route_mmio(view, ctx.vcpu, &a, ctx.mmio_value, 0) {
                    Routed::NoDevice(v) => complete(ctx, a, v),
                    Routed::Refused { backend, gpa } => {
                        record_refusal(view.index, view.envelope, backend, gpa);
                        complete(ctx, a, 0);
                    }
                    Routed::Post(mut t) => {
                        t.seq = host.next_seq(ctx.vcpu);
                        match wait_for(host, &t) {
                            Ok(cpl) => {
                                let v = if cpl.status == cpl::OK && !a.write { cpl.data } else { 0 };
                                complete(ctx, a, v);
                            }
                            Err(stop) => return stop,
                        }
                    }
                }
            }
            Exit::Hypercall => {
                let served = match host.hypercall_host() {
                    Some(h) => hv.hypercall(ctx, h),
                    None => HypercallOutcome::Unserved,
                };
                match served {
                    HypercallOutcome::Served => {
                        // A fence the guest asked of other vCPUs is done
                        // before it runs on. Waiting, this vCPU carries out
                        // the fences asked of it, so two vCPUs that ask each
                        // other cannot wait on each other.
                        while host.fences_outstanding() {
                            serve_fences(hv, ctx, host);
                            if host.stop_requested() {
                                return Stop::Requested;
                            }
                            host.yield_now();
                        }
                    }
                    HypercallOutcome::StopVcpu => return Stop::Requested,
                    HypercallOutcome::EndGuest { kind, reason } => return Stop::Fault(shutdown_code(kind, reason)),
                    HypercallOutcome::Unserved => return Stop::Fault(fault_code(&Exit::Hypercall)),
                }
            }
            other => return Stop::Fault(fault_code(&other)),
        }
    }
}

/// Hold the guest until `Vcpu::resume`: `false` when a stop ended the hold.
///
/// The context is not touched: the registers stay where the exit left them,
/// and what the exit asked of the next entry (the access to complete) is still
/// asked of it. The caller reads the VM's clock again after the hold.
fn hold(hv: &dyn Hypervisor, ctx: &mut GuestCtx, host: &mut dyn RunHost) -> bool {
    host.freeze();
    while host.pause_requested() {
        // A vCPU that asked this one for a fence waits for it.
        serve_fences(hv, ctx, host);
        if host.stop_requested() {
            host.thaw();
            return false;
        }
        host.park();
    }
    host.thaw();
    true
}

/// Carry out the fences other vCPUs asked of this one: here, on the hart that
/// is about to run it.
fn serve_fences(hv: &dyn Hypervisor, ctx: &GuestCtx, host: &mut dyn RunHost) {
    while let Some(f) = host.take_fence() {
        hv.remote_fence(ctx, &f);
    }
}

/// The access is done as far as the guest can tell: the ISA writes a load's
/// value to its register and steps past the instruction before the next entry.
fn complete(ctx: &mut GuestCtx, access: MmioAccess, value: u64) {
    let mask = if access.size >= 8 { u64::MAX } else { (1u64 << (access.size as u32 * 8)) - 1 };
    ctx.completed = Some(MmioDone { access, value: value & mask });
}

/// Post `t` and wait for its answer, reading the stop flag between waits.
fn wait_for(host: &mut dyn RunHost, t: &Trap) -> Result<Completion, Stop> {
    loop {
        match host.post(t) {
            Ok(()) => break,
            Err(PostError::Gone) => return Err(Stop::Fault(fault::MONITOR_GONE << 56)),
            Err(PostError::Full) => {
                if host.stop_requested() {
                    return Err(Stop::Requested);
                }
                host.yield_now();
            }
        }
    }
    loop {
        if let Some(c) = host.answer() {
            return Ok(c);
        }
        if host.stop_requested() {
            return Err(Stop::Requested);
        }
    }
}

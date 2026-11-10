// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Interrupt lines as scheduled objects (L5): the binding of a hardware line
//! to an event port, and the budget that keeps a storm on it from breaking
//! admission.
//!
//! A ring-3 driver binds a line with an op of its `Device` capability
//! (`PORT_SRC_IRQ`): the line is routed to one CPU and every interrupt on
//! it queues a `PORT_EVENT_IRQ` event on the driver's port. The top half is
//! as small as it gets: the external-interrupt handler masks the line,
//! completes it, and calls [`irq_dispatch`], which queues the event and wakes
//! the port's waiter. The line stays masked until the driver's
//! `DEVICE_IRQ_ACK`; a level device that has not been quietened is not taken
//! again on the handler's return.
//!
//! # The handler is a thread with a budget (Kconfig `IRQ_THREADED`)
//!
//! The handler is the task that bound the line, and with `IRQ_THREADED` it
//! must run on a **hard reservation** (CBS, `azos_sched::rt`): the bind is
//! refused (`BindError::Budget`) for a task without one, because its time
//! would not be budgeted. The reservation is admitted like any other, so the
//! line's cost is inside the CPU's booked load, and the line is routed to the
//! CPU the reservation was admitted on, where the top half and the handler
//! share a cache. What the line adds to the reservation is the one rule of
//! this file: **a line whose handler ran out of budget stays masked until
//! the budget is replenished.**
//!
//! * `rt.rs` tells [`irq_sc_throttle`] when a reservation that serves lines
//!   is throttled (its budget ran out) and when it is replenished.
//! * Throttled, an idle line is masked at once and marked *held*; a line a
//!   delivery already masked stays masked, and its ACK does **not** unmask it
//!   ([`Ack::Held`]).
//! * Replenished, every held line is unmasked (or, if its handler still owes
//!   an ACK, left masked for that ACK to unmask).
//!
//! So a storm costs at most one top half per handler run, the handler runs
//! only inside its budget, and the budget is admitted: an interrupt source
//! cannot take time from the tasks admitted beside it. Each overrun leaves a
//! decision record (`Rule::IrqBudget`: the line, how many lines it masked,
//! the overruns so far). Without `IRQ_THREADED` the bind takes any task, the
//! ACK always unmasks, and none of this runs.
//!
//! # Message-signalled interrupts
//!
//! A line whose number has [`MSI_LINE`] set is message-signalled: the
//! capability names a **slot** (`MSI_LINE | k`), not a controller input. The
//! bind allocates the vector (x86_64: a LAPIC vector, riscv64 with AIA: an
//! IMSIC identity) from a pool and enables it on the CPU, and answers the
//! message the device must write (`Msi`: address, data). An unbind does not
//! give the vector back to the pool: the device the driver programmed may
//! still hold the message, and whoever next held the vector would receive its
//! interrupts. The vector is kept for the slot it was taken for ([`MSI_KEPT`]):
//! the next bind of that slot gets it first, so a driver that restarts does
//! not spend the pool, and no other slot ever does. An MSI
//! cannot be masked at the controller, so the budget rule is different: a
//! delivery to a binding whose handler is out of budget is **dropped** at the
//! top half (counted in [`irq_msi_drops`]) instead of the line being held, and
//! the ACK has nothing to unmask. A slot may be held by several tasks, each
//! its own binding (a vector each). Platforms without it (aarch64 here: the
//! GICv3 ITS is not exposed to ring 3) refuse the slot at the topology
//! (`msi.<k>` is not minted) and at the bind (`-ENODEV`).
//!
//! # A port binding holds an object reference
//!
//! A binding stores the port's packed `(index, generation)` reference and the
//! epoch that generation was taken under. Delivery compares both inside the
//! `PORTS` hold that queues (`port::port_queue_event_bound`); a mismatch
//! queues and wakes nothing and is counted in [`irq_port_drops`]. The epoch is
//! needed even though a port's own generation counter is per-slot: that
//! slot's targeted wrap sweep (`objref::sweep_index`) resets its generation to
//! 1 and clears `Cap<Port>` entries in cap tables only — a binding is not
//! reached by it, so the epoch (bumped once per wrap of that one slot) is what
//! tells a pre-wrap binding apart from a port that legitimately draws the same
//! post-wrap generation at the same index.

use core::sync::atomic::{AtomicU32, Ordering};

use crate::port::{port_live_epoch, port_queue_event_bound, PortCapError, PortEvent};
use azos_abi::syscall_nr::PORT_EVENT_IRQ;
use azos_decision::{Rule, Verdict};
use azos_sched::rt::IrqScRefusal;
use azos_sync::SpinLock;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of IRQ bindings system-wide.
pub const MAX_IRQ_BINDINGS: usize = 32;

/// Set in a line number that names a message-signalled slot (`msi.<k>`,
/// `MSI_LINE | k`) rather than a controller input.
pub const MSI_LINE: u32 = azos_abi::cap::IRQ_MSI_LINE;

/// The message a device writes to raise a bound MSI: `data` to the physical
/// `address` (an MSI-X table entry or the MSI capability takes both), and the
/// vector or identity `id` it lands on.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Msi {
    pub address: u64,
    pub data: u32,
    pub id: u32,
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// An IRQ binding entry: one line, one owner, one port.
#[derive(Clone, Copy)]
pub struct IrqBinding {
    /// Whether this slot is used.
    pub active: bool,
    /// The PLIC/APLIC source, GIC INTID or IOAPIC GSI.
    pub irq: u32,
    /// The task that bound the line: the handler.
    pub owner_task: u32,
    /// The port's packed reference (`objref::PORT`).
    pub port: u32,
    /// The epoch of the slot `port` was taken under.
    pub epoch: u32,
    /// The key every event of this binding carries.
    pub key: u64,
    /// The CPU the line is routed to.
    pub cpu: u32,
    /// The CPU the bind asked for: where a line that [`irq_move_cpu`] took off
    /// a stopped CPU goes back to when that CPU returns.
    pub home: u32,
    /// The owner serves the line on its reservation (counted in its SC);
    /// only with `IRQ_THREADED`.
    pub budgeted: bool,
    /// Delivered, and the owner has not ACKed yet: the delivery masked the
    /// line.
    pub in_service: bool,
    /// The owner's reservation is throttled right now.
    pub throttled: bool,
    /// The line is held masked by the budget: set when the reservation was
    /// throttled while the line was idle, or when the ACK came in while it
    /// was; cleared when it is replenished.
    pub held: bool,
    /// A message-signalled slot ([`MSI_LINE`]): `hw` is its vector.
    pub msi: bool,
    /// The vector or identity of an MSI binding, 0 otherwise.
    pub hw: u32,
}

impl IrqBinding {
    pub const fn empty() -> Self {
        Self {
            active: false,
            irq: 0,
            owner_task: 0,
            port: 0,
            epoch: 0,
            key: 0,
            cpu: 0,
            home: 0,
            budgeted: false,
            in_service: false,
            throttled: false,
            held: false,
            msi: false,
            hw: 0,
        }
    }
}

/// Why a bind was refused.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BindError {
    /// The port is not live, or the binding table is full (`PortCapError`).
    Port(PortCapError),
    /// `IRQ_THREADED`: the owner has no hard reservation to run the handler on.
    Budget(IrqScRefusal),
    /// `IRQ_THREADED`: the line was asked on a CPU other than the one the
    /// owner's reservation runs on.
    Route,
    /// Another task already binds the line.
    Busy,
    /// An MSI slot on a platform without message-signalled interrupts for ring
    /// 3, or with none left.
    NoMsi,
}

/// Where a line is routed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Route {
    /// Anywhere the caller likes: the CPU named is the default (the owner's
    /// pin, else the CPU it binds from). With `IRQ_THREADED` the reservation's
    /// CPU wins.
    Any(u32),
    /// This CPU. With `IRQ_THREADED` it must be the reservation's.
    Cpu(u32),
}

/// What a bind decided: where the line goes, and whether the owner's
/// reservation is throttled at this instant (the caller then tells
/// [`irq_sc_throttle`] once the line is routed, so the line is masked rather
/// than enabled).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Bound {
    pub cpu: u32,
    pub throttled: bool,
    /// An MSI binding: what the device must write.
    pub msi: Option<Msi>,
}

/// What an ACK found.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Ack {
    /// No task binds the line.
    NotBound,
    /// The line is delivered again from now on: unmask it.
    Unmask,
    /// The owner's budget is spent: the line stays masked until the
    /// reservation is replenished ([`irq_sc_throttle`] unmasks it).
    Held,
}

// ---------------------------------------------------------------------------
// Global state
// ---------------------------------------------------------------------------

/// Global IRQ binding table.
///
/// Protected by a single `SpinLock` (same shape as `port.rs`'s `PORTS`).
/// `irq_dispatch()` runs from the external-interrupt handler while the bind,
/// the ACK and the unbind run from syscall context on any hart, and
/// [`irq_sc_throttle`] from the scheduler's dispatch tail on the hart the
/// reservation runs on. Uses `lock_irqsave()` throughout for the same
/// same-hart-deadlock reason `PORTS` does — see its doc comment.
///
/// **Lock order.** `IRQ_BINDINGS` and `PORTS` are never nested: the bind reads
/// the port's epoch (one `PORTS` hold) before it takes this lock, and
/// `irq_dispatch` releases this lock before it queues. Nothing under this lock
/// takes a scheduler lock: the controller hooks are register writes, and the
/// SC's counter is adjusted after the hold. The scheduler's tail may take
/// this lock (through the throttle hook) with its CPU lock held, which is why
/// nothing here may take a CPU lock.
const EMPTY_IRQ_BINDING: IrqBinding = IrqBinding::empty();
static IRQ_BINDINGS: SpinLock<[IrqBinding; MAX_IRQ_BINDINGS]> =
    SpinLock::new([EMPTY_IRQ_BINDING; MAX_IRQ_BINDINGS]);

/// Port deliveries dropped because the binding's reference no longer named the
/// live port (destroyed, or its index reused). Diagnostic, relaxed.
static IRQ_PORT_DROPS: AtomicU32 = AtomicU32::new(0);

/// Times a reservation that serves lines ran out of budget since boot.
static IRQ_OVERRUNS: AtomicU32 = AtomicU32::new(0);

/// MSI deliveries dropped because their handler was out of budget.
static IRQ_MSI_DROPS: AtomicU32 = AtomicU32::new(0);

/// MSI deliveries of a kept vector, which no binding holds: a device its
/// last holder programmed still raises it.
static IRQ_MSI_STRAY: AtomicU32 = AtomicU32::new(0);

/// Runtime canary `irq-storm` (ktest `irq_storm_is_contained`, the gate's
/// canary row): the budget rule is off. A throttle leaves an idle line live
/// and an ACK unmasks a line whose owner's budget is spent, as a binding
/// without the rule would. Test builds only (Kconfig KTEST, the host suite):
/// no other image can switch storm containment off.
#[cfg(any(test, feature = "ktest"))]
static CANARY_STORM: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Arm or disarm runtime canary `irq-storm`.
#[cfg(any(test, feature = "ktest"))]
pub fn canary_storm(on: bool) {
    CANARY_STORM.store(on, Ordering::Relaxed);
}

/// Is the budget rule off (canary `irq-storm`)? The constant `false` outside
/// test builds, so the throttle and the ACK load nothing for it.
#[inline(always)]
fn storm_canary() -> bool {
    #[cfg(any(test, feature = "ktest"))]
    {
        CANARY_STORM.load(Ordering::Relaxed)
    }
    #[cfg(not(any(test, feature = "ktest")))]
    {
        false
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Bind `irq` to the port a packed reference names (the reference a
/// `Cap<Port>` stores), with user key `key`, for `owner_task`. Returns where
/// the line must be routed (the caller programs the controller).
///
/// The binding stores the reference and the epoch read from the live port.
/// With `IRQ_THREADED` the owner must hold a hard reservation
/// ([`BindError::Budget`]) and the line goes to its CPU ([`Route`]). A repeat
/// bind of `irq` by `owner_task` replaces its binding; a line another task
/// binds is [`BindError::Busy`].
pub fn irq_bind_port(
    irq: u32,
    owner_task: u32,
    port_ref: u32,
    key: u64,
    route: Route,
) -> Result<Bound, BindError> {
    bind(irq, owner_task, port_ref, key, route, azos_limits::IRQ_THREADED)
}

/// [`irq_bind_port`] on a reservation whatever `IRQ_THREADED` says: the
/// handler is a thread that holds a hard reservation by construction (the IRQ
/// thread) or by the test's own admission (ktest `irq_storm_is_contained`).
pub fn irq_bind_port_budgeted(
    irq: u32,
    owner_task: u32,
    port_ref: u32,
    key: u64,
    route: Route,
) -> Result<Bound, BindError> {
    bind(irq, owner_task, port_ref, key, route, true)
}

/// [`irq_bind_port`] with `IRQ_THREADED` as an argument (the host suite runs
/// both).
fn bind(
    irq: u32,
    owner_task: u32,
    port_ref: u32,
    key: u64,
    route: Route,
    threaded: bool,
) -> Result<Bound, BindError> {
    let epoch = port_live_epoch(port_ref).map_err(BindError::Port)?;
    let (cpu, throttled, budgeted) = if threaded {
        let (cpu, throttled) = azos_sched::rt::irq_attach(owner_task).map_err(BindError::Budget)?;
        if let Route::Cpu(want) = route {
            if want as usize != cpu {
                azos_sched::rt::irq_detach(owner_task);
                return Err(BindError::Route);
            }
        }
        (cpu as u32, throttled, true)
    } else {
        match route {
            Route::Any(cpu) | Route::Cpu(cpu) => (cpu, false, false),
        }
    };
    // An MSI slot takes its vector now, enabled on `cpu`; it goes back with
    // the binding.
    let msi = if irq & MSI_LINE != 0 {
        match msi_take(owner_task, irq, cpu) {
            Ok(m) => Some(m),
            Err(e) => {
                if budgeted {
                    azos_sched::rt::irq_detach(owner_task);
                }
                return Err(e);
            }
        }
    } else {
        None
    };
    let fresh = IrqBinding {
        active: true,
        irq,
        owner_task,
        port: port_ref,
        epoch,
        key,
        cpu,
        home: cpu,
        budgeted,
        in_service: false,
        throttled: false,
        held: false,
        msi: msi.is_some(),
        hw: msi.map_or(0, |(m, _)| m.id),
    };
    match store(fresh) {
        // A replaced binding gave up its place on the owner's SC.
        Ok(replaced) => {
            if replaced.budgeted {
                azos_sched::rt::irq_detach(owner_task);
            }
            if replaced.msi {
                msi_keep(replaced.irq, replaced.hw);
                msi_kept_note(owner_task, replaced.irq, replaced.hw);
            }
        }
        Err(e) => {
            if budgeted {
                azos_sched::rt::irq_detach(owner_task);
            }
            if let Some((m, reused)) = msi {
                // The message was never handed out, unless this vector was a
                // kept one: that one the old device may still raise.
                msi_unissue(irq, m.id, reused);
            }
            return Err(e);
        }
    }
    if msi.is_some() {
        crate::cap_store::note_msi_bound(owner_task);
    }
    Ok(Bound { cpu, throttled, msi: msi.map(|(m, _)| m) })
}

/// Store `fresh`, replacing the same owner's binding of the line (an MSI slot
/// is one binding per owner; any other line, one in all). The binding it
/// replaced, if any, is returned for the caller to give back what it held.
fn store(fresh: IrqBinding) -> Result<IrqBinding, BindError> {
    let mut bindings = IRQ_BINDINGS.lock_irqsave();
    let existing = bindings
        .iter_mut()
        .find(|b| b.active && b.irq == fresh.irq && (!fresh.msi || b.owner_task == fresh.owner_task));
    if let Some(b) = existing {
        if b.owner_task != fresh.owner_task {
            return Err(BindError::Busy);
        }
        let was = *b;
        *b = fresh;
        return Ok(was);
    }
    match bindings.iter_mut().find(|b| !b.active) {
        Some(b) => {
            *b = fresh;
            Ok(IrqBinding::empty())
        }
        None => Err(BindError::Port(PortCapError::Full)),
    }
}

/// `tid` acknowledges `irq`: the line may be delivered again. [`Ack::Held`]
/// when the owner's reservation is throttled — the line stays masked and the
/// replenishment unmasks it. Any task holding the line's capability may ACK (a
/// handler with several threads); the binding is the line's, not the thread's,
/// except for an MSI slot, which is each holder's own. The caller unmasks the
/// line on [`Ack::Unmask`] (the controller half is per ISA,
/// `handlers::arch_irq_unmask`; an MSI has none).
pub fn irq_ack(irq: u32, tid: u32) -> Ack {
    ack(irq, tid, false)
}

/// [`irq_ack`] for a handler that lives in the kernel (the IRQ thread): on
/// [`Ack::Unmask`] the line is unmasked here, through the controller hook,
/// inside the same hold, so a throttle cannot land between the decision and
/// the unmask.
pub fn irq_ack_unmask(irq: u32, tid: u32) -> Ack {
    ack(irq, tid, true)
}

fn ack(irq: u32, tid: u32, unmask: bool) -> Ack {
    let mut bindings = IRQ_BINDINGS.lock_irqsave();
    let Some(b) = bindings
        .iter_mut()
        .find(|b| b.active && b.irq == irq && (!b.msi || b.owner_task == tid))
    else {
        return Ack::NotBound;
    };
    b.in_service = false;
    if b.throttled && !b.msi && !storm_canary() {
        b.held = true;
        Ack::Held
    } else {
        if unmask && !b.msi {
            line_unmasked(irq);
        }
        Ack::Unmask
    }
}

/// `tid`'s reservation was throttled (`throttled`: its budget ran out) or
/// replenished. Called by the scheduler (`rt.rs`) on the CPU the reservation
/// runs on, only for a task whose SC serves a line.
///
/// Throttled: every budgeted line of `tid` that is idle is masked and held; a
/// line a delivery masked is left for its ACK to hold. Replenished: every
/// held line is unmasked unless its handler still owes the ACK. One
/// `Rule::IrqBudget` record per overrun.
pub fn irq_sc_throttle(tid: u32, throttled: bool) {
    sc_throttle(tid, throttled, true);
}

/// Mask `tid`'s idle lines now and hold them until its reservation is
/// replenished, without an overrun to record: a bind that found the
/// reservation throttled already ([`Bound::throttled`]).
pub fn irq_hold_lines(tid: u32) {
    sc_throttle(tid, true, false);
}

fn sc_throttle(tid: u32, throttled: bool, overrun: bool) {
    let mut first = 0u32;
    let mut masked = 0u64;
    {
        let mut bindings = IRQ_BINDINGS.lock_irqsave();
        for b in bindings.iter_mut().filter(|b| b.active && b.budgeted && b.owner_task == tid) {
            b.throttled = throttled;
            if throttled {
                if first == 0 {
                    first = b.irq;
                }
                // An MSI cannot be masked: its deliveries are dropped while
                // `throttled` ([`irq_msi_dispatch`]).
                if !b.msi && !b.in_service && !b.held && !storm_canary() {
                    b.held = true;
                    line_masked(b.irq);
                    masked += 1;
                }
            } else if b.held {
                b.held = false;
                if !b.in_service {
                    line_unmasked(b.irq);
                }
            }
        }
    }
    if throttled && overrun && first != 0 {
        let overruns = IRQ_OVERRUNS.fetch_add(1, Ordering::Relaxed) + 1;
        azos_decision::record(Rule::IrqBudget, Verdict::Deny, tid, [first as u64, masked, overruns as u64]);
    }
}

/// Unbind all IRQ bindings for a task (called on task exit).
///
/// A line whose binding goes here is handed back to the interrupt controller
/// through the release hook ([`set_line_hooks`]): masked and no longer ring-3
/// owned. The release runs inside the same `IRQ_BINDINGS` hold as the
/// removal: a bind stores under this lock and only then enables the line
/// (`arch_irq_bound`), so a release can never land after a newer binding's
/// enable — either that binding was stored first (and this line is not
/// released) or its enable follows this release.
///
/// A binding tells its port: after the hold, the port gets one
/// `PORT_EVENT_SOURCE_GONE` (code `EPEERDIED`, the binding's key, the line)
/// through `port::port_post_gone`, so a task waiting there for the line is not
/// left waiting for a source that no longer exists.
pub fn irq_unbind_all(owner_task: u32) {
    let mut gone = [(0u32, 0u32, 0u64, 0u32); MAX_IRQ_BINDINGS];
    let mut kept = [None; MAX_IRQ_BINDINGS];
    let mut n = 0usize;
    let mut budgeted = 0usize;
    {
        let mut bindings = IRQ_BINDINGS.lock_irqsave();
        for b in bindings.iter_mut().filter(|b| b.active && b.owner_task == owner_task) {
            gone[n] = (b.port, b.epoch, b.key, b.irq);
            kept[n] = b.msi.then_some(b.hw);
            n += 1;
            budgeted += b.budgeted as usize;
            release_line(b);
            *b = IrqBinding::empty();
        }
    }
    // The SC gives back the lines it counted (a task that is exiting has its
    // SC reset with its slot; this is for one that is not).
    for _ in 0..budgeted {
        azos_sched::rt::irq_detach(owner_task);
    }
    let code = azos_abi::error::Errno::EPEERDIED as u16;
    for (&(port, epoch, key, irq), vector) in gone[..n].iter().zip(&kept[..n]) {
        if let Some(hw) = *vector {
            msi_kept_note(owner_task, irq, hw);
        }
        let _ = crate::port::port_post_gone(port, epoch, crate::port::PortSourceKind::Irq(irq), key, irq, code);
    }
}

/// A task takes another row's authority (a Linux `execve` into another row):
/// its interrupt bindings go as at exit, a message-signalled slot's vector kept
/// for the slot, and its domain no longer counts as driving one. The new row
/// starts with the authority its own grants give and nothing the old row bound.
pub fn irq_release_for_new_row(owner_task: u32) {
    if !cfg!(feature = "exec-keeps-binding-canary") {
        irq_unbind_all(owner_task);
        crate::cap_store::forget_msi_bound(owner_task);
    }
}

/// Drop `owner_task`'s binding of `irq`: the undo of a bind whose line the
/// interrupt controller refused (`PORT_SRC_IRQ` answers `-ENODEV`). The
/// line goes through the release hook, as in [`irq_unbind_all`]. `false` when
/// there was no such binding.
pub fn irq_unbind(irq: u32, owner_task: u32) -> bool {
    let (budgeted, vector) = {
        let mut bindings = IRQ_BINDINGS.lock_irqsave();
        let Some(b) = bindings.iter_mut().find(|b| b.active && b.irq == irq && b.owner_task == owner_task) else {
            return false;
        };
        let (budgeted, vector) = (b.budgeted, b.msi.then_some(b.hw));
        release_line(b);
        *b = IrqBinding::empty();
        (budgeted, vector)
    };
    if let Some(hw) = vector {
        msi_kept_note(owner_task, irq, hw);
    }
    if budgeted {
        azos_sched::rt::irq_detach(owner_task);
    }
    true
}

/// The holder's own remove of its binding of `irq` (`PORT_BIND_F_REMOVE` of
/// `PORT_SRC_IRQ`): the binding goes as in [`irq_unbind`], and its port gets
/// one `PORT_EVENT_SOURCE_GONE` (code `EREVOKED`, the binding's key, the
/// line), so another thread waiting there for the line learns it is gone.
/// `false` when there was no such binding.
pub fn irq_remove(irq: u32, owner_task: u32) -> bool {
    let found = IRQ_BINDINGS
        .lock_irqsave()
        .iter()
        .find(|b| b.active && b.irq == irq && b.owner_task == owner_task)
        .map(|b| (b.port, b.epoch, b.key));
    let Some((port, epoch, key)) = found else { return false };
    if !irq_unbind(irq, owner_task) {
        return false;
    }
    let code = azos_abi::error::Errno::EREVOKED as u16;
    let _ = crate::port::port_post_gone(port, epoch, crate::port::PortSourceKind::Irq(irq), key, irq, code);
    true
}

/// A binding goes: a controller line is handed back (masked, ring-3 ownership
/// forgotten); an MSI's vector is kept for its slot ([`msi_keep`]).
fn release_line(b: &IrqBinding) {
    if b.msi {
        msi_keep(b.irq, b.hw);
    } else {
        line_released(b.irq);
    }
}

/// How many bindings of `irq` are stored (0 or 1; an MSI slot, one per
/// holder).
pub fn irq_bindings_of(irq: u32) -> usize {
    IRQ_BINDINGS.lock_irqsave().iter().filter(|b| b.active && b.irq == irq).count()
}

/// Port deliveries dropped for a stale binding reference since boot.
pub fn irq_port_drops() -> u32 {
    IRQ_PORT_DROPS.load(Ordering::Relaxed)
}

/// Overruns of a reservation that serves lines since boot.
pub fn irq_overruns() -> u32 {
    IRQ_OVERRUNS.load(Ordering::Relaxed)
}

/// MSI deliveries dropped for a handler out of budget since boot.
pub fn irq_msi_drops() -> u32 {
    IRQ_MSI_DROPS.load(Ordering::Relaxed)
}

/// Deliveries since boot of a vector kept for its slot while no binding held
/// it: a device that outlived its driver and still raises its interrupt.
pub fn irq_msi_stray() -> u32 {
    IRQ_MSI_STRAY.load(Ordering::Relaxed)
}

// ---------------------------------------------------------------------------
// The interrupt controller, behind three hooks
// ---------------------------------------------------------------------------

azos_common::ro_hook! {
    /// What the kernel does to a line, set once at boot (`kernel_main`) to the
    /// ISA's own: aarch64 masks/unmasks the SPI (`gic::disable_spi` /
    /// `enable_spi`) and `gic::user_spi_release` hands it back; riscv64 and
    /// x86_64 go through `azos_drv_irqchip::user_irq` (PLIC/APLIC and IOAPIC).
    /// Function pointers rather than direct calls so this file, which three host
    /// suites compile, stays free of interrupt-controller code. 0 = unset (host
    /// tests that do not set them).
    static LINE_RELEASE_HOOK: fn(u32);
}
azos_common::ro_hook! {
    static LINE_MASK_HOOK: fn(u32);
}
azos_common::ro_hook! {
    static LINE_UNMASK_HOOK: fn(u32);
}

/// Install the controller hooks: `release` (mask and forget the ring-3
/// ownership), `mask` and `unmask`.
pub fn set_line_hooks(release: fn(u32), mask: fn(u32), unmask: fn(u32)) {
    LINE_RELEASE_HOOK.set(release);
    LINE_MASK_HOOK.set(mask);
    LINE_UNMASK_HOOK.set(unmask);
}

fn call_hook(hook: &azos_common::hook::Hook<fn(u32)>, irq: u32) {
    if let Some(f) = hook.get() {
        f(irq);
    }
}

/// Test builds only (Kconfig KTEST, the host suite): one line no controller
/// has, answered by a mask flag here instead of the hooks, so a test can
/// drive a line while every other line still reaches the controller through
/// the hooks the boot installed (ktest `irq_storm_is_contained`). The hooks
/// are sealed before the tests run; this is a plain atomic the test sets for
/// its own duration. `u32::MAX`: no test line.
#[cfg(any(test, feature = "ktest"))]
static TEST_LINE: AtomicU32 = AtomicU32::new(u32::MAX);
#[cfg(any(test, feature = "ktest"))]
static TEST_LINE_MASKED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Make `irq` the test line, unmasked (`None`: no test line).
#[cfg(any(test, feature = "ktest"))]
pub fn set_test_line(irq: Option<u32>) {
    TEST_LINE_MASKED.store(false, Ordering::Release);
    TEST_LINE.store(irq.unwrap_or(u32::MAX), Ordering::Release);
}

/// Is the test line masked? The device behind it reads this as its
/// controller; it sets it with [`test_line_set_masked`] when it asserts.
#[cfg(any(test, feature = "ktest"))]
pub fn test_line_masked() -> bool {
    TEST_LINE_MASKED.load(Ordering::Acquire)
}

/// The test device's own top half: mask-until-ACK.
#[cfg(any(test, feature = "ktest"))]
pub fn test_line_set_masked(masked: bool) {
    TEST_LINE_MASKED.store(masked, Ordering::Release);
}

/// `irq` is the test line: record `masked` and do not reach the controller.
#[inline(always)]
fn test_line(irq: u32, masked: bool) -> bool {
    #[cfg(any(test, feature = "ktest"))]
    if irq == TEST_LINE.load(Ordering::Acquire) {
        TEST_LINE_MASKED.store(masked, Ordering::Release);
        return true;
    }
    let _ = (irq, masked);
    false
}

fn line_released(irq: u32) {
    if !test_line(irq, true) {
        call_hook(&LINE_RELEASE_HOOK, irq);
    }
}

fn line_masked(irq: u32) {
    if !test_line(irq, true) {
        call_hook(&LINE_MASK_HOOK, irq);
    }
}

fn line_unmasked(irq: u32) {
    if !test_line(irq, false) {
        call_hook(&LINE_UNMASK_HOOK, irq);
    }
}

/// What the kernel does for a message-signalled slot, per ISA, set once at
/// boot: whether the platform has MSI for ring 3, take a vector, give one
/// back, enable a vector on a CPU, and the message that raises it there.
#[derive(Clone, Copy)]
pub struct MsiOps {
    pub supported: fn() -> bool,
    pub alloc: fn() -> Option<u32>,
    pub free: fn(u32),
    /// Make vector `id` deliverable on CPU `cpu`; `false` if it cannot be
    /// there (riscv64: an IMSIC file is enabled by its own hart only).
    pub enable: fn(u32, u32) -> bool,
    /// The address and data a device writes to raise `id` on `cpu`.
    pub message: fn(u32, u32) -> Option<(u64, u32)>,
}

static MSI_OPS: SpinLock<Option<MsiOps>> = SpinLock::new(None);

/// Install the MSI ops ([`MsiOps`]). Once, at boot.
pub fn set_msi_ops(ops: MsiOps) {
    *MSI_OPS.lock_irqsave() = Some(ops);
}

fn msi_ops() -> Option<MsiOps> {
    *MSI_OPS.lock_irqsave()
}

/// Vectors a holder gave back, `(slot, vector)`: the device the holder
/// programmed may still hold the message, so a vector is reissued only to a
/// bind of the slot it was taken for ([`msi_take`]) and is never freed.
static MSI_KEPT: SpinLock<[Option<(u32, u32)>; MSI_SLOTS * azos_limits::IRQ_MSI_PER_SLOT as usize]> =
    SpinLock::new([None; MSI_SLOTS * azos_limits::IRQ_MSI_PER_SLOT as usize]);

/// Slots that hold vectors at once (Kconfig `IRQ_MSI_SLOTS`).
const MSI_SLOTS: usize = azos_limits::IRQ_MSI_SLOTS as usize;

/// Keep `vector`, given back by a holder of `slot`.
fn msi_keep(slot: u32, vector: u32) {
    if cfg!(feature = "msi-reissue-canary") {
        if let Some(ops) = msi_ops() {
            (ops.free)(vector);
        }
        msi_out_release(slot);
        return;
    }
    // Room is certain: MSI_OUT counts every vector a slot holds, live or kept,
    // and holds it to IRQ_MSI_PER_SLOT in at most MSI_SLOTS slots at once.
    if let Some(k) = MSI_KEPT.lock_irqsave().iter_mut().find(|k| k.is_none()) {
        *k = Some((slot, vector));
    }
}

/// The kept vector of `slot`, if there is one.
fn msi_reuse(slot: u32) -> Option<u32> {
    let mut kept = MSI_KEPT.lock_irqsave();
    let k = kept.iter_mut().find(|k| matches!(k, Some((s, _)) if *s == slot))?;
    k.take().map(|(_, v)| v)
}

/// A vector nobody was told about goes back to the pool; a kept one goes back
/// to the keep.
fn msi_unissue(slot: u32, vector: u32, reused: bool) {
    if reused {
        msi_keep(slot, vector);
    } else if let Some(ops) = msi_ops() {
        (ops.free)(vector);
        msi_out_release(slot);
    }
}

/// Say a vector was kept (outside every lock: the decision log may write).
fn msi_kept_note(owner: u32, slot: u32, vector: u32) {
    azos_decision::record(Rule::MsiVector, Verdict::Place, owner, [u64::from(vector), u64::from(slot), 0]);
}

/// A line grant refused: recorded (`Rule::LineGrant`, `why` as its `RuleInfo`
/// lists them).
pub(crate) fn line_refused(tid: u32, line: u32, why: u64) {
    if !cfg!(feature = "line-grant-silent-canary") {
        azos_decision::record(Rule::LineGrant, Verdict::Refuse, tid, [u64::from(line), 0, why]);
    }
}

/// Vectors issued per slot and not given back to the pool: live and kept
/// ones, `(slot, count)`. A slot never holds more than `IRQ_MSI_PER_SLOT`,
/// and an entry lasts while its slot holds any.
static MSI_OUT: SpinLock<[Option<(u32, u32)>; MSI_SLOTS]> = SpinLock::new([None; MSI_SLOTS]);

/// Why a slot may not take another vector.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OutFull {
    /// The slot holds `IRQ_MSI_PER_SLOT` already.
    Slot,
    /// `IRQ_MSI_SLOTS` other slots hold vectors.
    Table,
}

/// Room for one more vector of `slot`: counted, or refused.
fn msi_out_reserve(slot: u32) -> Result<(), OutFull> {
    let mut out = MSI_OUT.lock_irqsave();
    let limit = azos_limits::IRQ_MSI_PER_SLOT as u32;
    if let Some((_, n)) = out.iter_mut().flatten().find(|(s, _)| *s == slot) {
        if *n >= limit && !cfg!(feature = "msi-slot-unbounded-canary") {
            return Err(OutFull::Slot);
        }
        *n += 1;
        return Ok(());
    }
    let free = out.iter_mut().find(|e| e.is_none()).ok_or(OutFull::Table)?;
    *free = Some((slot, 1));
    Ok(())
}

/// A vector of `slot` went back to the pool; the slot's entry goes with its
/// last one.
fn msi_out_release(slot: u32) {
    let mut out = MSI_OUT.lock_irqsave();
    let Some(e) = out.iter_mut().find(|e| matches!(e, Some((s, _)) if *s == slot)) else { return };
    if let Some((_, n)) = e {
        *n = n.saturating_sub(1);
        if *n == 0 && !cfg!(feature = "msi-out-leak-canary") {
            *e = None;
        }
    }
}

/// Take a vector for a binding of `slot` on `cpu`, with its message, and
/// whether it is a kept one: the slot's own kept vector first, else a fresh
/// one from the pool.
fn msi_take(owner: u32, slot: u32, cpu: u32) -> Result<(Msi, bool), BindError> {
    let ops = msi_ops().ok_or(BindError::NoMsi)?;
    let kept = msi_reuse(slot);
    let id = match kept {
        Some(id) => id,
        None => {
            // A slot holds at most IRQ_MSI_PER_SLOT vectors, live and kept,
            // and at most IRQ_MSI_SLOTS slots hold any.
            if let Err(full) = msi_out_reserve(slot) {
                let why = match full {
                    OutFull::Slot => 1,
                    OutFull::Table => 2,
                };
                azos_decision::record(Rule::MsiVector, Verdict::Refuse, owner, [0, u64::from(slot), why]);
                return Err(BindError::Busy);
            }
            match (ops.alloc)() {
                Some(id) => id,
                None => {
                    msi_out_release(slot);
                    return Err(BindError::NoMsi);
                }
            }
        }
    };
    if !(ops.enable)(id, cpu) {
        msi_unissue(slot, id, kept.is_some());
        return Err(BindError::Route);
    }
    match (ops.message)(id, cpu) {
        Some((address, data)) => Ok((Msi { address, data, id }, kept.is_some())),
        None => {
            msi_unissue(slot, id, kept.is_some());
            Err(BindError::NoMsi)
        }
    }
}

/// Whether a `Cap<Irq>` may name interrupt line `irq` on this build's
/// interrupt controller: the lines `PORT_SRC_IRQ` could ever accept, so no
/// capability is minted for a line no bind takes.
///
/// * riscv64: a PLIC/APLIC source, `1..MAX_IRQS` (source 0 means "none").
/// * aarch64 kernel: an SPI, INTID 32..=1019 — exactly
///   `azos_arch::irq::gic::user_spi_in_range`, the test the bind applies
///   . The placeholder bound this replaced was 1024 with
///   a floor of 1, so it minted capabilities for the SGIs/PPIs (1..=31, the
///   kernel's IPI and timer) and for the special INTIDs 1020..=1023, all of
///   which the bind refuses.
/// * Any other target is a host test build (`aarch64-apple-darwin`): no
///   controller exists there, and the suites that pull this file grant small
///   line numbers (`irq.5`, line 7), so the host keeps the old `1..1024`.
#[cfg(target_arch = "riscv64")]
const fn irq_line_grantable(irq: u32) -> bool {
    irq != 0 && irq < azos_arch::irq::plic::MAX_IRQS
}
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
const fn irq_line_grantable(irq: u32) -> bool {
    azos_arch::irq::gic::user_spi_in_range(irq)
}
#[cfg(not(any(target_arch = "riscv64", all(target_arch = "aarch64", target_os = "none"))))]
const fn irq_line_grantable(irq: u32) -> bool {
    irq != 0 && irq < 1024
}

// The aarch64 kernel build proves its own bound: the special INTIDs and the
// per-PE lines are never grantable, the SPI range ends are.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
const _: () = {
    assert!(!irq_line_grantable(0) && !irq_line_grantable(31), "an SGI/PPI is grantable");
    assert!(!irq_line_grantable(1020) && !irq_line_grantable(1023), "a special INTID is grantable");
    assert!(irq_line_grantable(32) && irq_line_grantable(1019), "an SPI is not grantable");
};

/// Mint a `Cap<Irq>` naming interrupt line `irq`. the first
/// minter this kind has ever had, and the range check the audit asked for
/// alongside it — an out-of-range line is refused here rather than accepted
/// and left for `irq_bind`/`PORT_SRC_IRQ` to reject later against a
/// binding table that has nothing to do with whether the line exists.
/// `Cap<Irq>` is not a packed kind (`objref::layout` has no arm for it): the
/// resource is the bare line number, the same shape `motor_cap`
/// uses for a motor id.
pub fn irq_grant_cap(
    tid: u32,
    irq: u32,
    perms: crate::cap::CapPerms,
) -> Option<crate::cap::Cap<crate::cap::targets::Irq>> {
    if !irq_line_grantable(irq) {
        line_refused(tid, irq, 5);
        return None;
    }
    crate::cap_store::grant::<crate::cap::targets::Irq>(tid, perms, irq)
}


/// Mint a `Cap<Irq>` naming message-signalled slot `k` (`msi.<k>` in a
/// topology row): resource `MSI_LINE | k`. Refused where the platform has no
/// MSI for ring 3 and for a slot past 16 bits.
pub fn irq_grant_msi_cap(
    tid: u32,
    k: u32,
    perms: crate::cap::CapPerms,
) -> Option<crate::cap::Cap<crate::cap::targets::Irq>> {
    if k > 0xFFFF || !msi_ops().is_some_and(|o| (o.supported)()) {
        line_refused(tid, k, 6);
        return None;
    }
    crate::cap_store::grant::<crate::cap::targets::Irq>(tid, perms, MSI_LINE | k)
}

/// Called from the external-interrupt handler of every ISA
/// (`kernel/src/entry/riscv64/irq.rs`'s `INT_EXTERNAL_S` arm, `entry/aarch64.rs`'s
/// `handle_irq`, `entry/x86_64/irq.rs`'s `device`) after the line was masked
/// and completed: the top half's whole job. Marks the binding in service and
/// queues one `PORT_EVENT_IRQ` event on its port, waking the port's waiter.
/// A line nobody binds (the delivery raced an unbind) is dropped.
pub fn irq_dispatch(irq: u32) {
    // The binding is read under the lock and the event queued after it:
    // `port_queue_event_bound` takes `PORTS`' own lock.
    let (port, epoch, key, cpu) = {
        let mut bindings = IRQ_BINDINGS.lock_irqsave();
        let Some(b) = bindings.iter_mut().find(|b| b.active && !b.msi && b.irq == irq) else {
            return;
        };
        b.in_service = true;
        (b.port, b.epoch, b.key, b.cpu)
    };
    queue(port, epoch, key, irq, cpu);
}

/// A message-signalled interrupt on vector or identity `hw` reached the
/// external-interrupt handler (x86_64: the MSI vector; riscv64 with AIA: the
/// IMSIC identity): queue the event on the port of the binding that holds it.
/// `false` when no ring-3 binding holds `hw`, or its handler is out of budget
/// and the delivery is dropped ([`irq_msi_drops`]); an MSI cannot be masked,
/// so the top half drops instead of the line being held.
pub fn irq_msi_dispatch(hw: u32) -> bool {
    let held = {
        let bindings = IRQ_BINDINGS.lock_irqsave();
        match bindings.iter().find(|b| b.active && b.msi && b.hw == hw) {
            Some(b) if b.throttled => {
                IRQ_MSI_DROPS.fetch_add(1, Ordering::Relaxed);
                return false;
            }
            Some(b) => Some((b.port, b.epoch, b.key, b.irq, b.cpu)),
            None => None,
        }
    };
    let Some((port, epoch, key, irq, cpu)) = held else {
        if msi_is_kept(hw) && !cfg!(feature = "msi-stray-silent-canary") {
            IRQ_MSI_STRAY.fetch_add(1, Ordering::Relaxed);
        }
        return false;
    };
    queue(port, epoch, key, irq, cpu)
}

/// Is `vector` one a slot keeps?
fn msi_is_kept(vector: u32) -> bool {
    MSI_KEPT.lock_irqsave().iter().flatten().any(|&(_, v)| v == vector)
}

/// Queue the event of a delivery on its binding's port.
fn queue(port: u32, epoch: u32, key: u64, irq: u32, cpu: u32) -> bool {
    queue_coded(port, epoch, key, irq, cpu, 0)
}

fn queue_coded(port: u32, epoch: u32, key: u64, irq: u32, cpu: u32, code: u16) -> bool {
    // The event carries the CPU the line is routed to (`PortEvent::cpu`): where
    // the handler, pinned there under `IRQ_THREADED`, is woken.
    let event = PortEvent { key, source_type: PORT_EVENT_IRQ, source_id: irq, code, cpu: cpu as u8 };
    // The wakes this delivery makes are the line's: the scheduler logs them
    // with `irq` as their source (`azos_sched::wake_log`).
    azos_sched::wake_irq_enter(irq);
    // Queues and wakes the port's sleepers only when the reference and its
    // epoch still name the live port.
    let queued = port_queue_event_bound(port, epoch, event);
    azos_sched::wake_irq_leave();
    if queued {
        true
    } else {
        IRQ_PORT_DROPS.fetch_add(1, Ordering::Relaxed);
        false
    }
}

/// `PortEvent::code` of an MSI binding whose vector was moved to another CPU
/// (`irq_move_cpu`): the device still holds the old message; bind again for the
/// new one.
pub const IRQ_EVENT_MOVED: u16 = 1;

/// What [`irq_move_cpu`] did.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Moved {
    /// Controller lines routed to the new CPU.
    pub lines: usize,
    /// MSI vectors enabled on the new CPU (their owners were told).
    pub msis: usize,
    /// Bindings the controller would not move; they stay where they are.
    pub failed: usize,
}

/// CPU hotplug: take the bindings of CPU `from` to CPU `to`, so an interrupt
/// raised after `from` stopped is delivered on a CPU that runs. `route(irq, cpu)`
/// reprograms a controller line (`false`: refused). With `back`, the bindings
/// whose `home` is `from` and that sit elsewhere return to it instead, the
/// route taken when the topology asks for it. A binding on an owner's
/// reservation stays: the CPU that holds one is never taken offline.
pub fn irq_move_cpu(from: u32, to: u32, back: bool, route: fn(u32, u32) -> bool) -> Moved {
    let dest = if back { from } else { to };
    let mut pick = [(0usize, 0u32, false, 0u32); MAX_IRQ_BINDINGS];
    let mut n = 0;
    {
        let bindings = IRQ_BINDINGS.lock_irqsave();
        for (i, b) in bindings.iter().enumerate() {
            let hit = if back { b.home == from && b.cpu != from } else { b.cpu == from };
            if b.active && !b.budgeted && hit && !(canary_move_skip() && !back) {
                pick[n] = (i, b.irq, b.msi, b.hw);
                n += 1;
            }
        }
    }
    let ops = msi_ops();
    let mut out = Moved::default();
    let mut told = [(0u32, 0u32, 0u64, 0u32); MAX_IRQ_BINDINGS];
    let mut nt = 0;
    for &(i, irq, msi, hw) in &pick[..n] {
        let ok = if msi {
            ops.is_some_and(|o| (o.enable)(hw, dest))
        } else {
            test_line_owned(irq) || route(irq, dest)
        };
        if !ok {
            out.failed += 1;
            continue;
        }
        let mut bindings = IRQ_BINDINGS.lock_irqsave();
        let b = &mut bindings[i];
        if !(b.active && b.irq == irq) {
            continue;
        }
        b.cpu = dest;
        if msi {
            out.msis += 1;
            told[nt] = (b.port, b.epoch, b.key, irq);
            nt += 1;
        } else {
            out.lines += 1;
        }
    }
    for &(port, epoch, key, irq) in &told[..nt] {
        queue_coded(port, epoch, key, irq, dest, IRQ_EVENT_MOVED);
    }
    out
}

/// The CPU `irq` is routed to, `None` when no task binds it.
pub fn irq_binding_cpu(irq: u32) -> Option<u32> {
    IRQ_BINDINGS.lock_irqsave().iter().find(|b| b.active && b.irq == irq).map(|b| b.cpu)
}

/// Is `irq` the test line, which no controller routes?
#[inline(always)]
fn test_line_owned(irq: u32) -> bool {
    #[cfg(any(test, feature = "ktest"))]
    {
        irq == TEST_LINE.load(Ordering::Acquire)
    }
    #[cfg(not(any(test, feature = "ktest")))]
    {
        let _ = irq;
        false
    }
}

/// Runtime canary `irq-move-skip` (ktest `hotplug_irq_line_moves_off_the_stopped_cpu`):
/// the offline path leaves every binding on the CPU it stops.
static CANARY_MOVE_SKIP: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Arm runtime canary `irq-move-skip`.
pub fn canary_move_skip_arm() {
    CANARY_MOVE_SKIP.store(true, Ordering::Relaxed);
}

#[inline(always)]
fn canary_move_skip() -> bool {
    CANARY_MOVE_SKIP.load(Ordering::Relaxed)
}

/// Bind `irq` on `route` whatever `IRQ_THREADED` says, with no reservation
/// behind it (the ktests of CPU hotplug: a line that moves).
#[cfg(any(test, feature = "ktest"))]
pub fn irq_bind_port_plain(irq: u32, owner_task: u32, port_ref: u32, key: u64, route: Route) -> Result<Bound, BindError> {
    bind(irq, owner_task, port_ref, key, route, false)
}

/// Wipe the binding table and the counters. Host-test hygiene only.
#[cfg(test)]
pub fn __irq_bind_reset_for_tests() {
    let mut bindings = IRQ_BINDINGS.lock_irqsave();
    for b in bindings.iter_mut() {
        *b = IrqBinding::empty();
    }
    IRQ_PORT_DROPS.store(0, Ordering::Relaxed);
    IRQ_OVERRUNS.store(0, Ordering::Relaxed);
    IRQ_MSI_DROPS.store(0, Ordering::Relaxed);
    IRQ_MSI_STRAY.store(0, Ordering::Relaxed);
    *MSI_OPS.lock_irqsave() = None;
    *MSI_KEPT.lock_irqsave() = [None; MSI_SLOTS * azos_limits::IRQ_MSI_PER_SLOT as usize];
    *MSI_OUT.lock_irqsave() = [None; MSI_SLOTS];
    CANARY_STORM.store(false, Ordering::Relaxed);
    set_test_line(None);
    LINE_RELEASE_HOOK.clear_for_tests();
    LINE_MASK_HOOK.clear_for_tests();
    LINE_UNMASK_HOOK.clear_for_tests();
}

/// The stored binding of `irq` (host tests).
#[cfg(test)]
pub fn __irq_binding_for_tests(irq: u32) -> Option<IrqBinding> {
    IRQ_BINDINGS.lock_irqsave().iter().find(|b| b.active && b.irq == irq).copied()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cap::objref::PORT;
    use crate::port::{self, PortCapError};
    use azos_sched::rt::IrqScRefusal;

    const OWNER: u32 = 41;
    const OTHER: u32 = 42;
    const IRQ: u32 = 7;

    /// What the controller hooks were asked, in order: `(op, line)`.
    static CONTROLLER: std::sync::Mutex<Vec<(&'static str, u32)>> = std::sync::Mutex::new(Vec::new());
    fn on_release(irq: u32) {
        CONTROLLER.lock().unwrap_or_else(|e| e.into_inner()).push(("release", irq));
    }
    fn on_mask(irq: u32) {
        CONTROLLER.lock().unwrap_or_else(|e| e.into_inner()).push(("mask", irq));
    }
    fn on_unmask(irq: u32) {
        CONTROLLER.lock().unwrap_or_else(|e| e.into_inner()).push(("unmask", irq));
    }
    fn controller() -> Vec<(&'static str, u32)> {
        std::mem::take(&mut *CONTROLLER.lock().unwrap_or_else(|e| e.into_inner()))
    }

    /// The crate-wide serial lock (`tests/host/ipc-tests`): the port table
    /// and the scheduler shim's port-wake record are shared with port.rs's
    /// suite.
    fn setup() -> std::sync::MutexGuard<'static, ()> {
        let g = crate::harness::serial();
        port::__port_reset_for_tests();
        __irq_bind_reset_for_tests();
        azos_sched::shim_reset_port_wakes();
        azos_sched::shim_rt_reset();
        let _ = controller();
        set_line_hooks(on_release, on_mask, on_unmask);
        g
    }

    fn key_of(r: u32) -> Result<(u64, u8, u32), PortCapError> {
        port::port_poll_ref(r).map(|e| (e.key, e.source_type, e.source_id))
    }

    /// Bind as the unbudgeted build does (`IRQ_THREADED` off).
    fn bind_plain(irq: u32, owner: u32, r: u32, key: u64) -> Result<Bound, BindError> {
        bind(irq, owner, r, key, Route::Any(0), false)
    }

    /// Bind as the `IRQ_THREADED` build does.
    fn bind_budgeted(irq: u32, owner: u32, r: u32, key: u64, route: Route) -> Result<Bound, BindError> {
        bind(irq, owner, r, key, route, true)
    }

    /// An IRQ bound to a live port queues its event there and wakes the port's
    /// registered waiter by TID with the reference, and the waiter's second
    /// half returns the event. The stored binding carries the reference.
    ///
    /// **Canary.** Queue by `PORT.idx(port)` instead of the reference in
    /// `irq_dispatch`: the delivery is dropped and the poll reads `Empty`.
    #[test]
    fn an_irq_bound_to_a_live_port_queues_there_and_wakes_it() {
        let _g = setup();
        let r = port::port_create_ref(OWNER as usize).expect("create");
        assert_eq!(bind_plain(IRQ, OWNER, r, 0xAB), Ok(Bound { cpu: 0, throttled: false, msi: None }));
        let epoch = port::port_live_epoch(r).unwrap();
        let b = __irq_binding_for_tests(IRQ).expect("stored");
        assert_eq!((b.port, b.epoch, b.key, b.owner_task), (r, epoch, 0xAB, OWNER));
        let slot = match port::port_wait_begin(r, OWNER) {
            Ok(port::PortWaitStart::Registered { slot, .. }) => slot,
            _ => panic!("precondition: the owner waits"),
        };
        irq_dispatch(IRQ);
        assert_eq!(azos_sched::shim_port_waiter_wakes(), vec![(OWNER, r)]);
        assert_eq!(
            port::port_wait_end(slot, OWNER, r).map(|e| (e.key, e.source_type, e.source_id)),
            Ok((0xAB, PORT_EVENT_IRQ, IRQ))
        );
        assert_eq!(irq_port_drops(), 0);
        assert!(__irq_binding_for_tests(IRQ).unwrap().in_service, "the delivery did not mark the line in service");
    }

    /// The wakes a delivery makes are made under its line (the scheduler logs
    /// them with the line as their source), and the line is announced only for
    /// the delivery: not after it, not for a delivery that was dropped.
    ///
    /// **Canary.** Remove `wake_irq_enter` from `queue`: the waiter is woken
    /// under no line.
    #[test]
    fn the_wakes_of_a_delivery_are_made_under_its_line() {
        let _g = setup();
        let r = port::port_create_ref(OWNER as usize).expect("create");
        assert!(bind_plain(IRQ, OWNER, r, 0xAB).is_ok());
        assert!(matches!(port::port_wait_begin(r, OWNER), Ok(port::PortWaitStart::Registered { .. })));
        assert_eq!(azos_sched::shim_wake_irq_in_flight(), None);
        irq_dispatch(IRQ);
        assert_eq!(azos_sched::shim_irq_wakes(), vec![(OWNER, IRQ)], "the waiter was woken under the line");
        assert_eq!(azos_sched::shim_wake_irq_in_flight(), None, "the delivery is over");

        // A delivery to a port that is gone queues and wakes nothing, and still
        // ends its announcement.
        azos_sched::shim_reset_port_wakes();
        port::port_destroy(PORT.idx(r));
        irq_dispatch(IRQ);
        assert!(azos_sched::shim_irq_wakes().is_empty());
        assert_eq!(azos_sched::shim_wake_irq_in_flight(), None);
    }

    /// The event carries the CPU the line is routed to, for a line routed to
    /// one that is not the first, bound by an unbudgeted bind or by a
    /// reservation (`Route::Any` takes the reservation's CPU).
    ///
    /// **Canary.** Queue the event with `cpu: 0`: the poll reads CPU 0 for a
    /// line routed to CPU 3.
    #[test]
    fn an_irq_event_carries_the_cpu_its_line_is_routed_to() {
        let _g = setup();
        let r = port::port_create_ref(OWNER as usize).expect("create");
        assert_eq!(bind(IRQ, OWNER, r, 1, Route::Any(2), false), Ok(Bound { cpu: 2, throttled: false, msi: None }));
        irq_dispatch(IRQ);
        assert_eq!(port::port_poll_ref(r).map(|e| (e.source_type, e.source_id, e.cpu)), Ok((PORT_EVENT_IRQ, IRQ, 2)));
        // A budgeted bind routes to the reservation's CPU, and so does the event.
        azos_sched::shim_rt_set(OWNER, Ok((3, false)));
        assert_eq!(bind_budgeted(IRQ + 1, OWNER, r, 2, Route::Any(0)), Ok(Bound { cpu: 3, throttled: false, msi: None }));
        irq_dispatch(IRQ + 1);
        assert_eq!(port::port_poll_ref(r).map(|e| (e.source_id, e.cpu)), Ok((IRQ + 1, 3)));
    }

    /// Delivery to a destroyed-and-recreated port is dropped: nothing is queued
    /// on the port now at that index, nobody is woken, and the drop is counted.
    ///
    /// **Canary.** Queue by `PORT.idx(port)` in `irq_dispatch` (the pre-gap-1
    /// delivery): the new port receives the old binding's event.
    #[test]
    fn delivery_to_a_destroyed_and_recreated_port_is_dropped() {
        let _g = setup();
        let old = port::port_create_ref(OWNER as usize).expect("create");
        assert!(bind_plain(IRQ, OWNER, old, 0x01D).is_ok());
        port::port_destroy(PORT.idx(old));
        let new = port::port_create_ref(OTHER as usize).expect("create");
        assert_eq!(PORT.idx(new), PORT.idx(old), "precondition: the index was reused");
        let slot = match port::port_wait_begin(new, OTHER) {
            Ok(port::PortWaitStart::Registered { slot, .. }) => slot,
            _ => panic!("precondition: the new port's owner waits"),
        };
        azos_sched::shim_reset_port_wakes();

        irq_dispatch(IRQ);
        assert!(!port::port_has_events(PORT.idx(new)), "the new port received the old binding's event");
        assert!(azos_sched::shim_port_waiter_wakes().is_empty(), "the new port's waiter was woken");
        assert_eq!(irq_port_drops(), 1);

        // A binding made to the new port delivers there.
        assert!(bind_plain(IRQ, OWNER, new, 0x2E3).is_ok(), "the same owner replaces its binding");
        irq_dispatch(IRQ);
        assert_eq!(azos_sched::shim_port_waiter_wakes(), vec![(OTHER, new)]);
        assert_eq!(key_of(new), Ok((0x2E3, PORT_EVENT_IRQ, IRQ)));
        assert_eq!(port::port_wait_end(slot, OTHER, new).err(), Some(PortCapError::Empty));
    }

    /// A binding is not reached by the per-slot wrap sweep (`objref` clears
    /// `Cap<Port>` entries, not bindings), so after that slot's own wrap a
    /// later port at the same index can draw the very same packed reference;
    /// the epoch the binding recorded is what refuses it.
    ///
    /// **Canary.** Drop the epoch compare from `port_queue_event_bound`: the
    /// later port receives the event.
    #[test]
    fn a_binding_does_not_reach_a_port_that_drew_its_reference_after_a_wrap() {
        let _g = setup();
        let old = port::port_create_ref(OWNER as usize).expect("create");
        assert!(bind_plain(IRQ, OWNER, old, 0x0DD).is_ok());
        port::port_destroy(PORT.idx(old));

        port::__port_set_next_gen_for_tests(PORT.idx(old) as usize, PORT.gen_max() + 1);
        let later = port::port_create_ref(OTHER as usize).expect("create");
        assert_eq!(later, old, "precondition: the same index and generation, another epoch");

        irq_dispatch(IRQ);
        assert!(!port::port_has_events(PORT.idx(later)));
        assert_eq!(irq_port_drops(), 1);
    }

    /// Binding a port that is not live is refused, and stores nothing.
    #[test]
    fn binding_a_port_that_is_not_live_is_refused() {
        let _g = setup();
        assert_eq!(
            bind_plain(IRQ, OWNER, 3, 1),
            Err(BindError::Port(PortCapError::Cap(crate::cap::CapError::Stale))),
            "a bare index"
        );
        assert!(__irq_binding_for_tests(IRQ).is_none());
    }

    /// A line has one binding: another task's bind is refused, the same
    /// owner's replaces its own (new key, new port), and the table fills at
    /// `MAX_IRQ_BINDINGS`.
    ///
    /// **Canary.** Let `store` take any free slot: the second owner's bind
    /// answers Ok and the line has two bindings.
    #[test]
    fn a_line_has_one_binding() {
        let _g = setup();
        let r = port::port_create_ref(OWNER as usize).expect("create");
        assert!(bind_plain(IRQ, OWNER, r, 1).is_ok());
        assert_eq!(bind_plain(IRQ, OTHER, r, 2), Err(BindError::Busy));
        assert!(bind_plain(IRQ, OWNER, r, 3).is_ok());
        assert_eq!(irq_bindings_of(IRQ), 1);
        assert_eq!(__irq_binding_for_tests(IRQ).unwrap().key, 3);
        for irq in 100..100 + (MAX_IRQ_BINDINGS as u32 - 1) {
            assert!(bind_plain(irq, OWNER, r, 1).is_ok(), "binding {irq}");
        }
        assert_eq!(
            bind_plain(500, OWNER, r, 1),
            Err(BindError::Port(PortCapError::Full)),
            "a full table"
        );
        assert!(bind_plain(IRQ, OWNER, r, 4).is_ok(), "a repeat bind takes no new slot");
    }

    /// Without `IRQ_THREADED` an ACK always unmasks, and clears the delivery's
    /// in-service mark; a line nobody binds answers `NotBound`.
    #[test]
    fn an_ack_unmasks_a_line_with_no_budget() {
        let _g = setup();
        let r = port::port_create_ref(OWNER as usize).expect("create");
        assert_eq!(irq_ack(IRQ, OWNER), Ack::NotBound);
        assert!(bind_plain(IRQ, OWNER, r, 1).is_ok());
        irq_dispatch(IRQ);
        assert!(__irq_binding_for_tests(IRQ).unwrap().in_service);
        assert_eq!(irq_ack(IRQ, OWNER), Ack::Unmask);
        assert!(!__irq_binding_for_tests(IRQ).unwrap().in_service);
        assert!(controller().is_empty(), "the hooks are the caller's to call on Unmask");
    }

    /// `IRQ_THREADED`: the owner must hold a hard reservation, the line is
    /// routed to its CPU, a different CPU asked for is refused, and the SC
    /// counts the line while it is bound.
    #[test]
    fn a_budgeted_bind_needs_a_hard_reservation_and_goes_to_its_cpu() {
        let _g = setup();
        let r = port::port_create_ref(OWNER as usize).expect("create");
        assert_eq!(
            bind_budgeted(IRQ, OWNER, r, 1, Route::Any(0)),
            Err(BindError::Budget(IrqScRefusal::NoReservation))
        );
        azos_sched::shim_rt_set(OWNER, Err(IrqScRefusal::Soft));
        assert_eq!(
            bind_budgeted(IRQ, OWNER, r, 1, Route::Any(0)),
            Err(BindError::Budget(IrqScRefusal::Soft))
        );
        assert!(__irq_binding_for_tests(IRQ).is_none());

        azos_sched::shim_rt_set(OWNER, Ok((3, false)));
        assert_eq!(
            bind_budgeted(IRQ, OWNER, r, 1, Route::Cpu(1)),
            Err(BindError::Route),
            "a CPU the reservation does not run on"
        );
        assert_eq!(azos_sched::shim_rt_attached(OWNER), 0, "a refused bind left a count on the SC");
        assert_eq!(
            bind_budgeted(IRQ, OWNER, r, 1, Route::Cpu(3)),
            Ok(Bound { cpu: 3, throttled: false, msi: None })
        );
        assert_eq!(azos_sched::shim_rt_attached(OWNER), 1);
        // `Any` takes the reservation's CPU whatever the fallback.
        assert_eq!(
            bind_budgeted(IRQ + 1, OWNER, r, 1, Route::Any(0)),
            Ok(Bound { cpu: 3, throttled: false, msi: None })
        );
        assert_eq!(azos_sched::shim_rt_attached(OWNER), 2);
        // A repeat bind replaces: still two lines.
        assert!(bind_budgeted(IRQ, OWNER, r, 9, Route::Any(0)).is_ok());
        assert_eq!(azos_sched::shim_rt_attached(OWNER), 2, "a repeat bind counted twice");
        // A refused bind of a line another task has leaves no count.
        azos_sched::shim_rt_set(OTHER, Ok((3, false)));
        assert_eq!(bind_budgeted(IRQ, OTHER, r, 1, Route::Any(0)), Err(BindError::Busy));
        assert_eq!(azos_sched::shim_rt_attached(OTHER), 0);
        // The undo and the exit give the counts back.
        assert!(irq_unbind(IRQ, OWNER));
        assert_eq!(azos_sched::shim_rt_attached(OWNER), 1);
        irq_unbind_all(OWNER);
        assert_eq!(azos_sched::shim_rt_attached(OWNER), 0);
        // The bind reports a reservation that is throttled right now.
        azos_sched::shim_rt_set(OWNER, Ok((3, true)));
        assert_eq!(
            bind_budgeted(IRQ, OWNER, r, 1, Route::Any(0)),
            Ok(Bound { cpu: 3, throttled: true, msi: None })
        );
    }

    /// Without `IRQ_THREADED` a bind neither needs a reservation nor counts on
    /// an SC, and routes where it is told.
    #[test]
    fn an_unbudgeted_bind_ignores_the_reservation() {
        let _g = setup();
        let r = port::port_create_ref(OWNER as usize).expect("create");
        azos_sched::shim_rt_set(OWNER, Ok((3, false)));
        assert_eq!(bind(IRQ, OWNER, r, 1, Route::Any(2), false), Ok(Bound { cpu: 2, throttled: false, msi: None }));
        assert_eq!(azos_sched::shim_rt_attached(OWNER), 0);
        irq_unbind_all(OWNER);
        assert_eq!(azos_sched::shim_rt_attached(OWNER), 0);
    }

    /// A reservation that runs out masks its idle line at once, holds it past
    /// the ACK of a line a delivery had masked, and the replenishment unmasks
    /// both — a line whose handler still owes the ACK stays masked for that
    /// ACK. Each overrun leaves one decision record.
    ///
    /// **Canary.** `irq_ack` unmasks while throttled (`canary_storm`):
    /// the in-service line reads `Unmask` where `Held` is expected.
    #[test]
    fn a_spent_budget_holds_the_lines_until_the_replenishment() {
        let _g = setup();
        azos_sched::shim_rt_set(OWNER, Ok((0, false)));
        let r = port::port_create_ref(OWNER as usize).expect("create");
        assert!(bind_budgeted(IRQ, OWNER, r, 1, Route::Any(0)).is_ok());
        assert!(bind_budgeted(IRQ + 1, OWNER, r, 2, Route::Any(0)).is_ok());
        // IRQ is delivered (the top half masked it); IRQ + 1 is idle.
        irq_dispatch(IRQ);

        irq_sc_throttle(OWNER, true);
        assert_eq!(controller(), vec![("mask", IRQ + 1)], "only the idle line needs masking");
        assert_eq!(irq_overruns(), 1);
        assert!(__irq_binding_for_tests(IRQ + 1).unwrap().held);
        assert_eq!(irq_ack(IRQ, OWNER), Ack::Held, "the ACK unmasked a line whose budget is spent");
        assert!(controller().is_empty());

        irq_sc_throttle(OWNER, false);
        let mut ops = controller();
        ops.sort();
        assert_eq!(ops, vec![("unmask", IRQ), ("unmask", IRQ + 1)]);
        assert!(__irq_binding_for_tests(IRQ).is_some_and(|b| !b.held && !b.throttled));

        // Replenished while the handler still owes the ACK: the line stays
        // masked, and the ACK finds a budget.
        irq_dispatch(IRQ);
        irq_sc_throttle(OWNER, true);
        assert_eq!(controller(), vec![("mask", IRQ + 1)], "the delivered line was masked already");
        irq_sc_throttle(OWNER, false);
        let ops = controller();
        assert_eq!(ops, vec![("unmask", IRQ + 1)], "the line with an ACK owed was unmasked under the handler");
        assert_eq!(irq_ack(IRQ, OWNER), Ack::Unmask);
        assert_eq!(irq_overruns(), 2);
    }

    /// The throttle touches the lines of its own task, and only the budgeted
    /// ones.
    #[test]
    fn the_throttle_reaches_only_its_own_budgeted_lines() {
        let _g = setup();
        azos_sched::shim_rt_set(OWNER, Ok((0, false)));
        let r = port::port_create_ref(OWNER as usize).expect("create");
        assert!(bind_budgeted(IRQ, OWNER, r, 1, Route::Any(0)).is_ok());
        assert!(bind_plain(IRQ + 1, OWNER, r, 2).is_ok());
        assert!(bind_plain(IRQ + 2, OTHER, r, 3).is_ok());
        irq_sc_throttle(OWNER, true);
        assert_eq!(controller(), vec![("mask", IRQ)]);
        irq_sc_throttle(OTHER, true);
        assert!(controller().is_empty());
    }

    /// A bind that finds the reservation throttled holds its lines without an
    /// overrun on the books: the line is masked, nothing is counted.
    #[test]
    fn a_hold_masks_the_lines_and_records_no_overrun() {
        let _g = setup();
        azos_sched::shim_rt_set(OWNER, Ok((0, true)));
        let r = port::port_create_ref(OWNER as usize).expect("create");
        let b = bind_budgeted(IRQ, OWNER, r, 1, Route::Any(0)).expect("bound");
        assert!(b.throttled);
        irq_hold_lines(OWNER);
        assert_eq!(controller(), vec![("mask", IRQ)]);
        assert_eq!(irq_overruns(), 0, "a hold counted as an overrun");
        irq_sc_throttle(OWNER, false);
        assert_eq!(controller(), vec![("unmask", IRQ)]);
    }

    /// A throttle with no budgeted line leaves no record (the hook is told
    /// only for an SC that serves one, but a task may drop its last line
    /// between the edge and the call).
    #[test]
    fn a_throttle_with_no_lines_leaves_no_record() {
        let _g = setup();
        irq_sc_throttle(OWNER, true);
        assert_eq!(irq_overruns(), 0);
    }

    /// The controller as the hooks leave it, and the device behind the line.
    struct Storm {
        masked: bool,
        deliveries: u32,
    }

    impl Storm {
        /// Apply what the hooks were asked since the last call.
        fn settle(&mut self) {
            for (op, _) in controller() {
                match op {
                    "mask" => self.masked = true,
                    "unmask" => self.masked = false,
                    _ => {}
                }
            }
        }

        /// One round of a device that asserts the line whenever it can: a
        /// masked line is not delivered; a live one is masked by its top half
        /// and queued, and the handler ACKs at once. Returns whether it was
        /// delivered.
        fn round(&mut self) -> bool {
            if self.masked {
                return false;
            }
            self.masked = true;
            irq_dispatch(IRQ);
            self.deliveries += 1;
            true
        }

        fn ack(&mut self) {
            if irq_ack(IRQ, OWNER) == Ack::Unmask {
                self.masked = false;
            }
            self.settle();
        }
    }

    /// An IRQ storm is contained: a device that asserts the line again the
    /// moment it is unmasked, served by a handler that ACKs at once, gets a
    /// bounded number of deliveries per budget and none while the reservation
    /// is throttled; the replenishment resumes it. The controller is modelled
    /// by the hooks (a masked line is not delivered).
    ///
    /// **Canary.** `canary_storm(true)` (ktest's `irq-storm`): the ACK
    /// unmasks a spent budget and the throttled phase sees deliveries.
    #[test]
    fn a_storm_is_contained_by_the_budget() {
        let _g = setup();
        azos_sched::shim_rt_set(OWNER, Ok((0, false)));
        let r = port::port_create_ref(OWNER as usize).expect("create");
        assert!(bind_budgeted(IRQ, OWNER, r, 1, Route::Any(0)).is_ok());
        let mut dev = Storm { masked: false, deliveries: 0 };

        // The budget lasts for five handler runs; then the scheduler throttles.
        let mut runs = 0u32;
        for _ in 0..1_000 {
            if dev.round() {
                runs += 1;
                if runs == 5 {
                    irq_sc_throttle(OWNER, true);
                    dev.settle();
                }
                dev.ack();
            }
        }
        assert_eq!(dev.deliveries, 5, "the storm ran past the budget");
        assert!(dev.masked, "the line was left live with the budget spent");

        // Replenished: the storm resumes, and is contained again.
        irq_sc_throttle(OWNER, false);
        dev.settle();
        assert!(!dev.masked, "the replenishment did not unmask the line");
        let mut runs = 0u32;
        for _ in 0..1_000 {
            if dev.round() {
                runs += 1;
                if runs == 3 {
                    irq_sc_throttle(OWNER, true);
                    dev.settle();
                }
                dev.ack();
            }
        }
        assert_eq!(dev.deliveries, 5 + 3);
        assert_eq!(irq_overruns(), 2);
    }

    /// A line that is idle when the budget runs out is masked by the throttle
    /// itself (the storm's next assertion finds it masked), not by a delivery.
    #[test]
    fn an_idle_line_is_masked_when_the_budget_runs_out() {
        let _g = setup();
        azos_sched::shim_rt_set(OWNER, Ok((0, false)));
        let r = port::port_create_ref(OWNER as usize).expect("create");
        assert!(bind_budgeted(IRQ, OWNER, r, 1, Route::Any(0)).is_ok());
        let mut dev = Storm { masked: false, deliveries: 0 };
        irq_sc_throttle(OWNER, true);
        dev.settle();
        assert!(dev.masked);
        for _ in 0..100 {
            assert!(!dev.round());
        }
        irq_sc_throttle(OWNER, false);
        dev.settle();
        assert!(dev.round(), "the replenishment left the line masked");
    }

    // ── Message-signalled slots ─────────────────────────────────────────────

    /// The pool a fake platform hands MSI vectors out of: ids from 40, the
    /// ones given back first.
    static MSI_POOL: std::sync::Mutex<(u32, Vec<u32>)> = std::sync::Mutex::new((40, Vec::new()));
    fn msi_alloc() -> Option<u32> {
        let mut g = MSI_POOL.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(back) = g.1.pop() {
            return Some(back);
        }
        g.0 += 1;
        Some(g.0 - 1)
    }
    fn msi_free(id: u32) {
        MSI_POOL.lock().unwrap_or_else(|e| e.into_inner()).1.push(id);
    }
    fn msi_enable(_id: u32, cpu: u32) -> bool {
        cpu < 4
    }
    fn msi_message(id: u32, cpu: u32) -> Option<(u64, u32)> {
        Some((0xFEE0_0000 + cpu as u64 * 0x1000, id))
    }
    fn msi_ops_installed() {
        *MSI_POOL.lock().unwrap_or_else(|e| e.into_inner()) = (40, Vec::new());
        set_msi_ops(MsiOps {
            supported: || true,
            alloc: msi_alloc,
            free: msi_free,
            enable: msi_enable,
            message: msi_message,
        });
    }
    fn msi_given_back() -> Vec<u32> {
        MSI_POOL.lock().unwrap_or_else(|e| e.into_inner()).1.clone()
    }
    const SLOT: u32 = MSI_LINE | 3;
    /// The vectors kept for `slot`.
    fn kept_for(slot: u32) -> Vec<u32> {
        MSI_KEPT.lock_irqsave().iter().flatten().filter(|(s, _)| *s == slot).map(|&(_, v)| v).collect()
    }

    /// An MSI slot takes a vector when it is bound, answers the message that
    /// raises it on the CPU asked for, delivers by vector to the port with the
    /// slot as its source id, and keeps the vector when the binding goes
    /// (exit, undo, or a replacing bind): the device may still hold the
    /// message, so it is not returned to the pool. Two holders of one slot
    /// have a binding each. Without MSI ops the bind is refused, and a CPU the
    /// vector cannot be enabled on is a route error that keeps nothing.
    #[test]
    fn an_msi_slot_takes_a_vector_at_bind_and_keeps_it_when_the_binding_goes() {
        let _g = setup();
        let r = port::port_create_ref(OWNER as usize).expect("create");
        assert_eq!(bind_plain(SLOT, OWNER, r, 1), Err(BindError::NoMsi), "a platform without MSI");

        msi_ops_installed();
        let b = bind(SLOT, OWNER, r, 0x77, Route::Cpu(2), false).expect("bound");
        assert_eq!(b.cpu, 2);
        assert_eq!(b.msi, Some(Msi { address: 0xFEE0_2000, data: 40, id: 40 }));
        assert!(irq_msi_dispatch(40));
        assert_eq!(key_of(r), Ok((0x77, PORT_EVENT_IRQ, SLOT)), "the slot is the event's source id");
        assert!(!irq_msi_dispatch(99), "a vector nobody holds");

        // A second holder of the slot is its own binding, with its own vector.
        let r2 = port::port_create_ref(OTHER as usize).expect("create");
        let b2 = bind(SLOT, OTHER, r2, 0x88, Route::Cpu(1), false).expect("bound");
        assert_eq!(b2.msi.map(|m| m.id), Some(41));
        assert_eq!(irq_bindings_of(SLOT), 2);
        assert!(irq_msi_dispatch(41));
        assert_eq!(key_of(r2), Ok((0x88, PORT_EVENT_IRQ, SLOT)));
        assert!(!port::port_has_events(PORT.idx(r)), "the other holder's vector reached this port");

        // A repeat bind replaces: a new vector is taken, the old one is kept.
        let b3 = bind(SLOT, OWNER, r, 0x99, Route::Cpu(2), false).expect("bound");
        assert_eq!(b3.msi.map(|m| m.id), Some(42));
        assert_eq!(kept_for(SLOT), vec![40]);

        // A CPU the vector cannot be enabled on keeps nothing new: the kept
        // vector it tried stays kept.
        assert_eq!(bind(SLOT, OWNER, r, 1, Route::Cpu(9), false), Err(BindError::Route));
        assert_eq!(kept_for(SLOT), vec![40]);
        assert_eq!(irq_bindings_of(SLOT), 2);

        // Exit and undo keep the rest.
        irq_unbind_all(OTHER);
        assert!(irq_unbind(SLOT, OWNER));
        let mut kept = kept_for(SLOT);
        kept.sort();
        assert_eq!(kept, vec![40, 41, 42]);
        assert_eq!(msi_given_back(), Vec::<u32>::new(), "a vector the device may hold went back to the pool");
        assert!(controller().is_empty(), "an MSI is not a controller line: nothing to release");
    }

    /// **A vector a holder gave back is reissued only to a bind of the slot it
    /// was taken for.** The device the first holder programmed may still raise
    /// it; the slot's next holder is the same row's, any other slot's is not.
    ///
    /// **Canary.** `msi-reissue-canary`: the given-back vector returns to the
    /// pool, where the other slot's bind takes it.
    #[test]
    fn a_given_back_msi_vector_is_reissued_only_to_its_own_slot() {
        let _g = setup();
        let r = port::port_create_ref(OWNER as usize).expect("create");
        msi_ops_installed();
        let other_slot = MSI_LINE | 4;
        assert_eq!(bind(SLOT, OWNER, r, 1, Route::Cpu(0), false).unwrap().msi.map(|m| m.id), Some(40));
        assert!(irq_unbind(SLOT, OWNER));
        // Another slot's bind never gets it, though a pool that took it back would offer it.
        let b = bind(other_slot, OWNER, r, 2, Route::Cpu(0), false).unwrap();
        assert_ne!(b.msi.map(|m| m.id), Some(40), "another slot received a vector a device of the first may raise");
        assert!(irq_unbind(other_slot, OWNER));
        // The slot's own next bind gets it back first: a restart spends nothing.
        let again = bind(SLOT, OWNER, r, 3, Route::Cpu(1), false).unwrap();
        assert_eq!(again.msi.map(|m| m.id), Some(40));
        assert_eq!(again.msi.map(|m| m.address), Some(0xFEE0_1000), "re-enabled on the CPU asked for");
        assert!(irq_unbind(SLOT, OWNER));
        assert_eq!(msi_given_back(), Vec::<u32>::new());
    }

    /// **A slot holds at most `IRQ_MSI_PER_SLOT` vectors, live and kept, so a
    /// row that forks cannot drain the pool.** A bind past the bound is
    /// refused (`Busy`) and recorded (`msi-vector`, why 1); a kept vector is
    /// taken again before a new one; another slot is not affected.
    ///
    /// **Canary.** `msi-slot-unbounded-canary`: the slot takes the whole pool.
    #[test]
    fn a_slot_cannot_take_more_vectors_than_its_bound() {
        let _g = setup();
        msi_ops_installed();
        let limit = azos_limits::IRQ_MSI_PER_SLOT as u32;
        let r = port::port_create_ref(OWNER as usize).expect("create");
        let tasks: Vec<u32> = (0..limit + 1).map(|i| 50 + i).collect();
        for &t in &tasks[..limit as usize] {
            bind(SLOT, t, r, 1, Route::Cpu(0), false).expect("within the bound");
        }
        let over = tasks[limit as usize];
        assert_eq!(bind(SLOT, over, r, 1, Route::Cpu(0), false), Err(BindError::Busy), "past the bound");
        assert!(bind(MSI_LINE | 4, over, r, 1, Route::Cpu(0), false).is_ok(), "another slot is its own");
        // They exit: the vectors are kept, none returns to the pool, and the slot is still at its bound.
        for &t in &tasks[..limit as usize] {
            irq_unbind_all(t);
        }
        assert_eq!(msi_given_back(), Vec::<u32>::new());
        for &t in &tasks[..limit as usize] {
            bind(SLOT, t, r, 1, Route::Cpu(0), false).expect("a kept vector is taken first");
        }
        assert_eq!(bind(SLOT, over, r, 1, Route::Cpu(0), false), Err(BindError::Busy));
        let mut recorded = 0;
        azos_decision::for_each(|rec| {
            if rec.rule == Rule::MsiVector as u8 && rec.verdict == Verdict::Refuse as u8 && rec.n[2] == 1 {
                recorded += 1;
            }
        });
        assert!(recorded >= 2, "each refusal is a record");
    }

    /// Records of `rule` with `verdict` about `subject` and `why` (the third word).
    fn records(rule: Rule, verdict: Verdict, subject: u32, why: u64) -> usize {
        let mut n = 0;
        azos_decision::for_each(|r| {
            n += usize::from(r.rule == rule as u8 && r.verdict == verdict as u8 && r.subject == subject && r.n[2] == why);
        });
        n
    }

    /// **A slot that holds no vector holds no entry, so binds that failed
    /// cannot fill the table; when the table is full of slots that do hold
    /// vectors, the refusal says so (`msi-vector`, why 2), not that the slot
    /// is at its own bound (why 1).**
    ///
    /// **Canary.** `msi-out-leak-canary`: the entry of a slot whose vector
    /// went back stays, and the loop of failed binds fills the table.
    #[test]
    fn a_slot_without_vectors_takes_no_table_entry_and_a_full_table_says_so() {
        let _g = setup();
        msi_ops_installed();
        let r = port::port_create_ref(OWNER as usize).expect("create");
        // A CPU the vector cannot be enabled on: the fresh vector goes back, and with it the slot's entry.
        for k in 0..(2 * MSI_SLOTS as u32) {
            assert_eq!(bind(MSI_LINE | (100 + k), OWNER, r, 1, Route::Cpu(9), false), Err(BindError::Route));
        }
        assert_eq!(msi_given_back().len(), 1, "the one vector all those binds took went back");
        // Every slot the table has room for holds a vector; one more is refused for the table.
        let tasks: Vec<u32> = (0..MSI_SLOTS as u32 + 1).map(|i| 200 + i).collect();
        for (k, &t) in tasks[..MSI_SLOTS].iter().enumerate() {
            bind(MSI_LINE | k as u32, t, r, 1, Route::Cpu(0), false).expect("a slot with room in the table");
        }
        let over = tasks[MSI_SLOTS];
        assert_eq!(bind(MSI_LINE | 99, over, r, 1, Route::Cpu(0), false), Err(BindError::Busy));
        assert_eq!(records(Rule::MsiVector, Verdict::Refuse, over, 2), 1, "the table is full");
        assert_eq!(records(Rule::MsiVector, Verdict::Refuse, over, 1), 0, "not the slot's own bound");
        // A slot that has an entry still binds, and its own bound is the other reason.
        assert!(bind(MSI_LINE, tasks[0], r, 1, Route::Cpu(0), false).is_ok());
    }

    /// **A kept vector a device still raises, with no binding to take it, is
    /// counted; a vector nobody keeps, and a delivery a binding takes, are
    /// not.**
    ///
    /// **Canary.** `msi-stray-silent-canary`: the delivery is dropped, uncounted.
    #[test]
    fn a_delivery_of_a_kept_vector_with_no_binding_is_counted() {
        let _g = setup();
        msi_ops_installed();
        let r = port::port_create_ref(OWNER as usize).expect("create");
        bind(SLOT, OWNER, r, 1, Route::Cpu(0), false).expect("bound");
        assert!(irq_msi_dispatch(40));
        assert_eq!(irq_msi_stray(), 0, "a bound vector is delivered");
        assert!(irq_unbind(SLOT, OWNER));
        assert!(!irq_msi_dispatch(40), "no binding holds it");
        assert_eq!(irq_msi_stray(), 1, "the device that still raises it is seen");
        assert!(!irq_msi_dispatch(99));
        assert_eq!(irq_msi_stray(), 1, "a vector nobody keeps is not a stray of a slot");
    }

    /// **A device's registers or ports do not arrive in a task that holds an
    /// msi slot, by a move or by a transfer message; they arrive in one that
    /// holds none, and a slot holder keeps the registers it was granted.** The
    /// refusal is recorded (`msi-vector`, why 3).
    ///
    /// **Canary.** `msi-arrival-canary`: the registers arrive beside the slot.
    #[test]
    fn a_device_capability_does_not_arrive_in_a_task_that_holds_an_msi_slot() {
        use crate::cap::{targets, CapPerms};
        use crate::cap_store::{self, CapXfer};
        let _g = setup();
        let (giver, holder, plain) = (61, 62, 63);
        for t in [giver, holder, plain] {
            azos_sched::shim_bind(t, t as usize);
            cap_store::reset(t);
        }
        msi_ops_installed();
        let slot = irq_grant_msi_cap(holder, 5, CapPerms::READ).expect("the slot");
        let _ = slot;
        let give = || cap_store::grant::<targets::MmioRegion>(giver, CapPerms::RW.union(CapPerms::TRANSFER), 7).expect("registers").raw();
        let h = give();
        assert!(cap_store::move_cap(giver, holder, h, None).is_err(), "a move beside a slot");
        assert_eq!(records(Rule::MsiVector, Verdict::Refuse, holder, 3), 1, "the refusal is a record");
        let mut out = [crate::cap::CapHandle::from_raw(0); 1];
        assert!(cap_store::move_caps(giver, holder, &[CapXfer::new(h, false)], true, &mut out).is_err(), "a transfer message beside a slot");
        assert_eq!(records(Rule::MsiVector, Verdict::Refuse, holder, 3), 2);
        let ports = cap_store::grant::<targets::IoPorts>(giver, CapPerms::RW.union(CapPerms::TRANSFER), 0x300).expect("ports").raw();
        assert!(cap_store::move_cap(giver, holder, ports, None).is_err(), "ports beside a slot");
        assert!(cap_store::move_cap(giver, plain, h, None).is_ok(), "a task with no slot takes registers");
        let own = cap_store::grant::<targets::MmioRegion>(holder, CapPerms::RW, 8);
        assert!(own.is_some(), "a slot holder keeps the registers it was granted");
    }

    /// **A domain that still drives a message-signalled slot takes no device
    /// registers or ports, though its slot capability is gone; once its
    /// bindings are released for a new row it may.** The binding outlives the
    /// capability (a task drops it, an `execve` drops every capability), and
    /// the device that arrives could be programmed with the slot's message.
    ///
    /// **Canaries.** `msi-bound-canary`: a binding with no capability beside it
    /// is not seen. `exec-keeps-binding-canary`: the release keeps the bindings.
    #[test]
    fn a_domain_that_still_drives_a_slot_takes_no_device_capability() {
        use crate::cap::{targets, CapPerms};
        use crate::cap_store;
        let _g = setup();
        let (giver, holder) = (58, 59);
        for t in [giver, holder] {
            azos_sched::shim_bind(t, t as usize);
            cap_store::reset(t);
        }
        msi_ops_installed();
        let slot = irq_grant_msi_cap(holder, 6, CapPerms::READ).expect("the slot");
        let port = port::port_create_ref(holder as usize).expect("create");
        bind(MSI_LINE | 6, holder, port, 1, Route::Cpu(0), false).expect("bound");
        cap_store::revoke(holder, slot);
        let give = || cap_store::grant::<targets::MmioRegion>(giver, CapPerms::RW.union(CapPerms::TRANSFER), 7).expect("registers").raw();
        let h = give();
        assert!(cap_store::move_cap(giver, holder, h, None).is_err(), "the capability is gone and the binding is not");
        irq_release_for_new_row(holder);
        assert_eq!(irq_bindings_of(MSI_LINE | 6), 0, "the binding went with the old row");
        assert_eq!(kept_for(MSI_LINE | 6).len(), 1, "its vector is kept for the slot as at exit");
        assert!(cap_store::move_cap(giver, holder, h, None).is_ok(), "the new row takes its devices");
    }

    /// An `msi.<k>` slot is minted as a `Cap<Irq>` on `MSI_LINE | k` only where
    /// the platform has MSI for ring 3, and for a slot that fits 16 bits.
    ///
    /// **Canary.** Drop the `supported` test in `irq_grant_msi_cap`: the
    /// capability is minted on a platform without MSI.
    #[test]
    fn an_msi_slot_is_minted_only_where_the_platform_has_msi() {
        use crate::cap::{targets::Irq, Cap, CapPerms};
        let _g = setup();
        let tid = 12;
        azos_sched::shim_bind(tid, tid as usize);
        crate::cap_store::reset(tid);
        assert!(irq_grant_msi_cap(tid, 4, CapPerms::READ).is_none(), "no MSI ops installed");
        msi_ops_installed();
        let c = irq_grant_msi_cap(tid, 4, CapPerms::READ).expect("minted");
        assert_eq!(crate::cap_store::get(tid, Cap::<Irq>::from_raw(c.raw()), CapPerms::READ), Ok(MSI_LINE | 4));
        assert!(irq_grant_msi_cap(tid, 0x1_0000, CapPerms::READ).is_none(), "a slot past 16 bits");
        set_msi_ops(MsiOps { supported: || false, alloc: msi_alloc, free: msi_free, enable: msi_enable, message: msi_message });
        assert!(irq_grant_msi_cap(tid, 5, CapPerms::READ).is_none(), "a platform without MSI");
        // Each refusal is a record (`line-grant`, why 6), by the real minter.
        assert_eq!(records(Rule::LineGrant, Verdict::Refuse, tid, 6), 3);
    }

    /// An `irq.<N>` past the controller's lines is refused and recorded
    /// (`line-grant`, why 5) by the real minter.
    ///
    /// **Canary.** `line-grant-silent-canary`: the refusal leaves no record.
    #[test]
    fn a_line_past_the_controller_is_refused_and_recorded() {
        use crate::cap::CapPerms;
        let _g = setup();
        let tid = 13;
        azos_sched::shim_bind(tid, tid as usize);
        crate::cap_store::reset(tid);
        assert!(irq_grant_cap(tid, 0, CapPerms::READ).is_none(), "line 0 means none");
        assert!(irq_grant_cap(tid, 5000, CapPerms::READ).is_none(), "past the lines");
        assert_eq!(records(Rule::LineGrant, Verdict::Refuse, tid, 5), 2);
        assert!(irq_grant_cap(tid, 7, CapPerms::READ).is_some());
    }

    /// An MSI cannot be masked: while its handler is out of budget the
    /// delivery is dropped at the top half and counted, the throttle touches no
    /// controller hook, and the replenishment lets the next one through.
    ///
    /// **Canary.** Queue the event whatever `throttled` says in
    /// `irq_msi_dispatch`: the throttled delivery reaches the port.
    #[test]
    fn an_msi_is_dropped_while_the_handler_is_out_of_budget() {
        let _g = setup();
        msi_ops_installed();
        azos_sched::shim_rt_set(OWNER, Ok((1, false)));
        let r = port::port_create_ref(OWNER as usize).expect("create");
        let b = bind_budgeted(SLOT, OWNER, r, 5, Route::Any(0)).expect("bound");
        let id = b.msi.expect("an MSI binding").id;
        assert!(irq_msi_dispatch(id));
        assert_eq!(key_of(r), Ok((5, PORT_EVENT_IRQ, SLOT)));

        irq_sc_throttle(OWNER, true);
        assert!(controller().is_empty(), "the throttle masked an unmaskable line");
        assert!(!irq_msi_dispatch(id), "a delivery past the budget reached the handler");
        assert!(!port::port_has_events(PORT.idx(r)));
        assert_eq!(irq_msi_drops(), 1);
        assert_eq!(irq_ack(SLOT, OWNER), Ack::Unmask, "an MSI ACK has nothing to hold");

        irq_sc_throttle(OWNER, false);
        assert!(irq_msi_dispatch(id));
        assert_eq!(irq_overruns(), 1);
    }

    /// `irq_ack_unmask` unmasks through the hook on `Unmask` and not on `Held`
    /// or `NotBound`; an MSI's ACK never touches the controller.
    #[test]
    fn the_kernels_ack_unmasks_through_the_hook() {
        let _g = setup();
        azos_sched::shim_rt_set(OWNER, Ok((0, false)));
        let r = port::port_create_ref(OWNER as usize).expect("create");
        assert_eq!(irq_ack_unmask(IRQ, OWNER), Ack::NotBound);
        assert!(bind_budgeted(IRQ, OWNER, r, 1, Route::Any(0)).is_ok());
        irq_dispatch(IRQ);
        assert_eq!(irq_ack_unmask(IRQ, OWNER), Ack::Unmask);
        assert_eq!(controller(), vec![("unmask", IRQ)]);
        irq_dispatch(IRQ);
        irq_sc_throttle(OWNER, true);
        let _ = controller();
        assert_eq!(irq_ack_unmask(IRQ, OWNER), Ack::Held);
        assert!(controller().is_empty(), "a held line was unmasked");
        msi_ops_installed();
        let b = bind_budgeted(SLOT, OWNER, r, 2, Route::Any(0)).expect("bound");
        assert!(b.msi.is_some());
        irq_sc_throttle(OWNER, false);
        let _ = controller();
        assert_eq!(irq_ack_unmask(SLOT, OWNER), Ack::Unmask);
        assert!(controller().is_empty(), "an MSI ACK touched the controller");
    }

    /// The test line (ktest `irq_storm_is_contained`): its mask and unmask
    /// set the flag and never reach the hooks, and every other line still
    /// reaches them, so a test can drive a line with the boot's hooks in.
    ///
    /// **Canary.** Return `false` from `test_line` for every line: the ACK of
    /// the test line reaches the controller hooks.
    #[test]
    fn the_test_line_stands_for_the_controller_and_no_other_line() {
        let _g = setup();
        azos_sched::shim_rt_set(OWNER, Ok((0, false)));
        let r = port::port_create_ref(OWNER as usize).expect("create");
        assert!(bind_budgeted(IRQ, OWNER, r, 1, Route::Any(0)).is_ok());
        assert!(bind_budgeted(IRQ + 1, OWNER, r, 2, Route::Any(0)).is_ok());
        set_test_line(Some(IRQ));
        test_line_set_masked(true);
        irq_dispatch(IRQ);
        irq_dispatch(IRQ + 1);
        let _ = controller();
        assert_eq!(irq_ack_unmask(IRQ, OWNER), Ack::Unmask);
        assert!(controller().is_empty(), "the test line reached the controller");
        assert!(!test_line_masked(), "the ACK did not unmask the test line");
        assert_eq!(irq_ack_unmask(IRQ + 1, OWNER), Ack::Unmask);
        assert_eq!(controller(), vec![("unmask", IRQ + 1)], "another line missed its controller");
        set_test_line(None);
        irq_dispatch(IRQ);
        assert_eq!(irq_ack_unmask(IRQ, OWNER), Ack::Unmask);
        assert_eq!(controller(), vec![("unmask", IRQ)], "a cleared test line still bypassed the controller");
    }

    // ── Task exit hands the line back ───────────────────────────────────────

    /// Every line of an exiting task is released, once, and the task's port is
    /// told with one `PORT_EVENT_SOURCE_GONE` per line.
    ///
    /// **Canary.** Skip `line_released` in `irq_unbind_all`: the controller
    /// list is empty.
    #[test]
    fn an_exit_releases_every_line_of_the_task() {
        let _g = setup();
        let r = port::port_create_ref(OTHER as usize).expect("create");
        assert!(bind_plain(IRQ, OWNER, r, 1).is_ok());
        assert!(bind_plain(IRQ + 1, OWNER, r, 2).is_ok());
        assert!(bind_plain(IRQ + 2, OTHER, r, 3).is_ok());
        irq_unbind_all(OWNER);
        let mut ops = controller();
        ops.sort();
        assert_eq!(ops, vec![("release", IRQ), ("release", IRQ + 1)], "OTHER's line must stay");
        assert_eq!(irq_bindings_of(IRQ + 2), 1);
        irq_unbind_all(OWNER);
        assert!(controller().is_empty(), "a second exit released again");
    }

    /// `irq_unbind` drops exactly the caller's binding of that line (another
    /// task's binding of another line stays), releases it, and a second undo
    /// finds nothing; an undone bind gives its slot back.
    ///
    /// **Canary.** Match on `b.irq == irq` alone: the other owner's binding
    /// goes with it.
    #[test]
    fn a_refused_bind_drops_only_that_binding() {
        let _g = setup();
        let r = port::port_create_ref(OWNER as usize).expect("create");
        assert!(bind_plain(IRQ, OWNER, r, 1).is_ok());
        assert!(bind_plain(IRQ + 1, OTHER, r, 2).is_ok());
        assert!(!irq_unbind(IRQ, OTHER), "another task's undo took the binding");
        assert!(irq_unbind(IRQ, OWNER));
        assert!(__irq_binding_for_tests(IRQ).is_none());
        assert!(__irq_binding_for_tests(IRQ + 1).is_some());
        assert_eq!(controller(), vec![("release", IRQ)]);
        assert!(!irq_unbind(IRQ, OWNER), "undone twice");
        for irq in 0..(2 * MAX_IRQ_BINDINGS) as u32 {
            assert!(bind_plain(200 + irq, OWNER, r, 1).is_ok(), "binding {irq}");
            assert!(irq_unbind(200 + irq, OWNER));
        }
    }
}

// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! IRQ Binding — route PLIC interrupts to userspace tasks/ports/rings (F00.3).
//!
//! When a userspace driver binds an IRQ, the kernel's PLIC handler will
//! additionally queue an event to the bound port or ring, enabling
//! event-driven userspace driver architectures.
//!
//! # A port binding holds an object reference (RFC-0040 gap 1)
//!
//! A binding used to store the port INDEX, so a binding outlived its port and
//! delivered into whatever port was created next at that index, whoever owned
//! it. A port binding now stores the port's packed `(index, generation)`
//! reference and the epoch that generation was taken under
//! ([`IrqTarget::QueueToPortRef`]). Delivery compares both inside the `PORTS`
//! hold that queues (`port::port_queue_event_bound`); a mismatch queues and
//! wakes nothing and is counted in [`irq_port_drops`]. The epoch is still
//! needed even though a port's own generation counter is per-slot now
//! (RFC-0040 gap 1, revised 2026-09-26): that slot's own targeted wrap sweep
//! (`objref::sweep_index`) resets its generation to 1 rather than losing the
//! slot, and clears `Cap<Port>` entries in cap tables only — a binding is not
//! reached by it, so the epoch (bumped once per wrap of that one slot) is
//! what tells a pre-wrap binding apart from a port that legitimately draws
//! the same post-wrap generation at the same index.

use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

use crate::port::{port_queue_event_bound, PortEvent};
use azos_sync::SpinLock;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of IRQ bindings system-wide.
pub const MAX_IRQ_BINDINGS: usize = 32;

/// Source type constants for PortEvent.
const PORT_SOURCE_TYPE_IRQ: u8 = 3;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Target for an IRQ binding.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum IrqTarget {
    /// No binding (slot is free).
    None,
    /// Wake a specific task (same as existing wake_by_irq behavior).
    WakeTask(u32),
    /// Queue to the port at index `.0`, with user key `.1`: the form
    /// `SYS_IRQ_BIND` builds from ring-3 arguments. [`irq_bind`] converts it
    /// into [`IrqTarget::QueueToPortRef`] with the live generation and epoch of
    /// that index, or refuses (-1) when no port is live there. Never stored.
    QueueToPort(u32, u64),
    /// Queue to the port named by the packed reference `port`
    /// (`objref::PORT`), whose generation was taken under `epoch` (this
    /// slot's own wrap counter, `Port::epoch`), with user key `key`. The
    /// stored form of every port binding.
    QueueToPortRef { port: u32, epoch: u32, key: u64 },
}

/// An IRQ binding entry.
#[derive(Clone, Copy)]
pub struct IrqBinding {
    /// The PLIC IRQ number.
    pub irq: u32,
    /// Owner task that created this binding.
    pub owner_task: u32,
    /// Where to dispatch.
    pub target: IrqTarget,
    /// Whether this slot is active.
    pub active: bool,
    /// A [`IrqTarget::WakeTask`] binding only: the line fired since the
    /// owner last consumed a delivery in `SYS_DRV_IRQ_WAIT`. One bit, not a
    /// count: a ring-3 line is delivered mask-until-ACK, so at most one
    /// delivery is outstanding per ACK.
    pub pending: bool,
    /// A [`IrqTarget::WakeTask`] binding only: the owner is inside
    /// `SYS_DRV_IRQ_WAIT` ([`irq_wait_begin`] registered it and
    /// [`irq_wait_end`] has not run yet), so a delivery wakes it by TID.
    pub waiting: bool,
}

impl IrqBinding {
    pub const fn empty() -> Self {
        Self {
            irq: 0,
            owner_task: 0,
            target: IrqTarget::None,
            active: false,
            pending: false,
            waiting: false,
        }
    }
}

// ---------------------------------------------------------------------------
// Global state
// ---------------------------------------------------------------------------

/// Global IRQ binding table.
///
/// Protected by a single `SpinLock` (same shape as `port.rs`'s `PORTS`).
/// `irq_dispatch()` runs from the PLIC IRQ handler while `irq_bind()` /
/// `irq_unbind_all()` run from syscall context on any hart — was a bare
/// `static mut` with zero synchronization, so a bind/unbind racing the
/// PLIC handler mid-mutation could dispatch to a torn/half-written entry,
/// and two harts binding concurrently could both claim the same free slot.
/// Uses `lock_irqsave()` throughout for the same same-hart-deadlock reason
/// `PORTS` does — see its doc comment.
///
/// **Lock order.** `IRQ_BINDINGS` and `PORTS` are never nested: `irq_bind`
/// reads the port's generation (one `PORTS` hold) before it takes this lock,
/// and `irq_dispatch` releases this lock before it queues.
const EMPTY_IRQ_BINDING: IrqBinding = IrqBinding::empty();
static IRQ_BINDINGS: SpinLock<[IrqBinding; MAX_IRQ_BINDINGS]> =
    SpinLock::new([EMPTY_IRQ_BINDING; MAX_IRQ_BINDINGS]);

/// Port deliveries dropped because the binding's reference no longer named the
/// live port (destroyed, or its index reused). Diagnostic, relaxed.
static IRQ_PORT_DROPS: AtomicU32 = AtomicU32::new(0);

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Bind an IRQ to a target. Returns 0 on success, -1 on failure.
///
/// A port target is resolved before it is stored: [`IrqTarget::QueueToPort`]
/// (an index) takes the live generation and epoch of that index, and
/// [`IrqTarget::QueueToPortRef`] must name a live port (its `epoch` field is
/// ignored and read fresh from the port). Either answers -1 when the port is
/// not live. The resolution and the store are two holds on two locks; a port
/// destroyed between them leaves a binding whose reference matches nothing,
/// which delivery drops.
pub fn irq_bind(irq: u32, owner_task: u32, target: IrqTarget) -> i32 {
    let target = match target {
        IrqTarget::QueueToPort(port_id, key) => match crate::port::port_ref_epoch(port_id) {
            Some((port, epoch)) => IrqTarget::QueueToPortRef { port, epoch, key },
            None => return -1,
        },
        IrqTarget::QueueToPortRef { port, key, .. } => match crate::port::port_live_epoch(port) {
            Ok(epoch) => IrqTarget::QueueToPortRef { port, epoch, key },
            Err(_) => return -1,
        },
        other => other,
    };
    store(irq, owner_task, target)
}

/// Bind `irq` to the port a packed reference names (the reference a
/// `Cap<Port>` stores), with user key `key`: the binding API for
/// `SYS_PORT_BIND_TYPED` (575). The binding stores the reference and the
/// epoch read from the live port. `Err(Cap(Stale))` when `port_ref` does not
/// name a live port, `Err(Full)` when no binding slot is free; a repeat bind
/// of `irq` by `owner_task` replaces its target, as [`irq_bind`] does.
pub fn irq_bind_port(
    irq: u32,
    owner_task: u32,
    port_ref: u32,
    key: u64,
) -> Result<(), crate::port::PortCapError> {
    let epoch = crate::port::port_live_epoch(port_ref)?;
    match store(irq, owner_task, IrqTarget::QueueToPortRef { port: port_ref, epoch, key }) {
        0 => Ok(()),
        _ => Err(crate::port::PortCapError::Full),
    }
}

fn store(irq: u32, owner_task: u32, target: IrqTarget) -> i32 {
    let mut bindings = IRQ_BINDINGS.lock_irqsave();
    // Check if this IRQ is already bound by this task
    for i in 0..MAX_IRQ_BINDINGS {
        if bindings[i].active && bindings[i].irq == irq && bindings[i].owner_task == owner_task {
            // Update existing binding. A delivery still pending for a
            // wake-task binding stays pending across a repeat wake-task bind;
            // any other change of target starts clean.
            let keep = matches!(bindings[i].target, IrqTarget::WakeTask(_))
                && matches!(target, IrqTarget::WakeTask(_));
            bindings[i].pending &= keep;
            bindings[i].waiting = false;
            bindings[i].target = target;
            return 0;
        }
    }
    // Find free slot
    for i in 0..MAX_IRQ_BINDINGS {
        if !bindings[i].active {
            bindings[i] = IrqBinding {
                irq,
                owner_task,
                target,
                active: true,
                pending: false,
                waiting: false,
            };
            return 0;
        }
    }
    -1 // No free slots
}

/// Unbind all IRQ bindings for a task (called on task exit).
///
/// A line whose LAST binding goes here is handed back to the interrupt
/// controller through the release hook ([`set_line_release_hook`]): masked
/// and no longer ring-3 owned (wave 9 IRQ4 item 4). Before, the line stayed
/// ring-3 owned and enabled after its driver died, until its next delivery
/// masked it for good.
///
/// The "no binding remains" decision and the release run inside the same
/// `IRQ_BINDINGS` hold: a bind stores under this lock and only then enables
/// the line (`arch_irq_bound`), so a release can never land after a newer
/// binding's enable — either that binding was stored first (and this line is
/// not released) or its enable follows this release.
///
/// A binding to a port tells it (wave 15 N5b): after the hold, the port gets
/// one `PORT_EVENT_SOURCE_GONE` (code `EPEERDIED`, the binding's key, the
/// line) through `port::port_post_gone`, so a task waiting there for the
/// line is not left waiting for a source that no longer exists.
pub fn irq_unbind_all(owner_task: u32) {
    let mut gone = [(0u32, 0u32, 0u64, 0u32); MAX_IRQ_BINDINGS];
    let mut n = 0usize;
    {
        let mut bindings = IRQ_BINDINGS.lock_irqsave();
        for i in 0..MAX_IRQ_BINDINGS {
            if bindings[i].active && bindings[i].owner_task == owner_task {
                let irq = bindings[i].irq;
                if let IrqTarget::QueueToPortRef { port, epoch, key } = bindings[i].target {
                    gone[n] = (port, epoch, key, irq);
                    n += 1;
                }
                bindings[i] = IrqBinding::empty();
                if !bindings.iter().any(|b| b.active && b.irq == irq) {
                    line_released(irq);
                }
            }
        }
    }
    let code = azos_abi::error::Errno::EPEERDIED as u16;
    for &(port, epoch, key, irq) in &gone[..n] {
        let _ = crate::port::port_post_gone(port, epoch, crate::port::PortSourceKind::Irq(irq), key, irq, code);
    }
}

/// Drop `owner_task`'s binding of `irq`: the undo of a bind whose line the
/// interrupt controller refused (`SYS_IRQ_BIND` / `SYS_PORT_BIND_TYPED`
/// answer `-ENODEV`; wave 10 IRQ5). Before, the binding stayed stored with a
/// line nobody could deliver and the syscall answered 0. A line whose last
/// binding this was goes through the release hook, as in
/// [`irq_unbind_all`]. `false` when there was no such binding.
///
/// A refused bind that updated an existing binding in place (a repeat bind
/// of the same line by the same task) drops that binding too. It cannot have
/// been a live one: the refusals are per line (a source the controller does
/// not implement or was not delegated), so the earlier bind of that line was
/// refused and undone the same way.
pub fn irq_unbind(irq: u32, owner_task: u32) -> bool {
    let mut bindings = IRQ_BINDINGS.lock_irqsave();
    let Some(i) = bindings
        .iter()
        .position(|b| b.active && b.irq == irq && b.owner_task == owner_task)
    else {
        return false;
    };
    bindings[i] = IrqBinding::empty();
    if !bindings.iter().any(|b| b.active && b.irq == irq) {
        line_released(irq);
    }
    true
}

/// How many bindings of `irq` are stored, whoever owns them.
pub fn irq_bindings_of(irq: u32) -> usize {
    IRQ_BINDINGS.lock_irqsave().iter().filter(|b| b.active && b.irq == irq).count()
}

/// Where a line goes when its last binding does: set once at boot by the
/// kernel (`kernel_main`) to the ISA's release — aarch64 masks the SPI and
/// clears its ring-3 ownership (`gic::user_spi_release`), riscv64 masks the
/// PLIC/APLIC source and clears its ring-3 ownership
/// (`azos_drv_irqchip::user_irq::release`). A function pointer rather than a
/// direct call so this file, which three host suites compile, stays free of
/// interrupt-controller code. 0 = unset (host tests that do not set it).
static LINE_RELEASE_HOOK: AtomicUsize = AtomicUsize::new(0);

/// Install the release hook (see [`LINE_RELEASE_HOOK`]).
pub fn set_line_release_hook(hook: fn(u32)) {
    LINE_RELEASE_HOOK.store(hook as usize, Ordering::Release);
}

fn line_released(irq: u32) {
    let raw = LINE_RELEASE_HOOK.load(Ordering::Acquire);
    if raw != 0 {
        // SAFETY: the only non-zero value ever stored is a `fn(u32)` cast to
        // `usize` by `set_line_release_hook`.
        let hook: fn(u32) = unsafe { core::mem::transmute::<usize, fn(u32)>(raw) };
        hook(irq);
    }
}

// ---------------------------------------------------------------------------
// SYS_DRV_IRQ_WAIT on a wake-task binding (wave 9 IRQ4 item 1)
// ---------------------------------------------------------------------------

/// How `SYS_DRV_IRQ_WAIT` starts for the caller and line it names.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum IrqWaitStart {
    /// The caller holds no wake-task binding of this line: the old wait
    /// (block on `WaitReason::Irq`, woken only by the `wake_by_irq` sweep).
    Unbound,
    /// The line fired since the caller last waited: consumed, do not block.
    Pending,
    /// Nothing pending; the caller is registered as the binding's waiter and
    /// must block on `WaitReason::Irq(irq)`, then call [`irq_wait_end`].
    Registered,
}

/// Begin a `SYS_DRV_IRQ_WAIT` by `tid` on `irq`.
///
/// Keyed by the caller's OWN wake-task binding `(owner = tid, irq)`, never by
/// the line alone: `SYS_DRV_IRQ_WAIT` has no capability check, so any task
/// may wait on any line, and only the binding's owner may consume its
/// pending delivery.
///
/// Before this, a delivery that arrived while the driver was not yet blocked
/// was lost (`wake_by_irq` sweeps only tasks already `Blocked`), and with
/// mask-until-ACK the line then stayed masked with nobody left to ACK it.
pub fn irq_wait_begin(irq: u32, tid: u32) -> IrqWaitStart {
    let mut bindings = IRQ_BINDINGS.lock_irqsave();
    match wake_binding(&mut bindings, irq, tid) {
        None => IrqWaitStart::Unbound,
        Some(b) if b.pending => {
            b.pending = false;
            IrqWaitStart::Pending
        }
        Some(b) => {
            b.waiting = true;
            IrqWaitStart::Registered
        }
    }
}

/// End a wait [`irq_wait_begin`] registered: unregister, and consume the
/// delivery if one arrived. `true` = the line fired (report 0 to ring 3);
/// `false` = the block returned for another reason, or never happened.
pub fn irq_wait_end(irq: u32, tid: u32) -> bool {
    let mut bindings = IRQ_BINDINGS.lock_irqsave();
    match wake_binding(&mut bindings, irq, tid) {
        Some(b) => {
            b.waiting = false;
            core::mem::replace(&mut b.pending, false)
        }
        None => false,
    }
}

fn wake_binding(
    bindings: &mut [IrqBinding; MAX_IRQ_BINDINGS],
    irq: u32,
    tid: u32,
) -> Option<&mut IrqBinding> {
    bindings.iter_mut().find(|b| {
        b.active && b.irq == irq && b.owner_task == tid && matches!(b.target, IrqTarget::WakeTask(_))
    })
}

/// Port deliveries dropped for a stale binding reference since boot.
pub fn irq_port_drops() -> u32 {
    IRQ_PORT_DROPS.load(Ordering::Relaxed)
}

/// Whether a `Cap<Irq>` may name interrupt line `irq` on this build's
/// interrupt controller: the lines `SYS_IRQ_BIND` / `SYS_PORT_BIND_TYPED`
/// could ever accept, so no capability is minted for a line no bind takes.
///
/// * riscv64: a PLIC/APLIC source, `1..MAX_IRQS` (source 0 means "none").
/// * aarch64 kernel: an SPI, INTID 32..=1019 — exactly
///   `azos_arch::gic::user_spi_in_range`, the test the bind applies
///   (wave 9 IRQ4 item 5). The placeholder bound this replaced was 1024 with
///   a floor of 1, so it minted capabilities for the SGIs/PPIs (1..=31, the
///   kernel's IPI and timer) and for the special INTIDs 1020..=1023, all of
///   which the bind refuses.
/// * Any other target is a host test build (`aarch64-apple-darwin`): no
///   controller exists there, and the suites that pull this file grant small
///   line numbers (`irq.5`, line 7), so the host keeps the old `1..1024`.
#[cfg(target_arch = "riscv64")]
const fn irq_line_grantable(irq: u32) -> bool {
    irq != 0 && irq < azos_drv_irqchip::plic::MAX_IRQS
}
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
const fn irq_line_grantable(irq: u32) -> bool {
    azos_arch::gic::user_spi_in_range(irq)
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

/// Mint a `Cap<Irq>` naming interrupt line `irq`. U03-2/U03-8: the first
/// minter this kind has ever had, and the range check the audit asked for
/// alongside it — an out-of-range line is refused here rather than accepted
/// and left for `irq_bind`/`SYS_IRQ_BIND` to reject later against a
/// binding table that has nothing to do with whether the line exists.
/// `Cap<Irq>` is not a packed kind (`objref::layout` has no arm for it): the
/// resource is the bare line number, the same shape `gpio_cap`/`motor_cap`
/// use for a pin/channel id.
pub fn irq_grant_cap(
    tid: u32,
    irq: u32,
    perms: crate::cap::CapPerms,
) -> Option<crate::cap::Cap<crate::cap::targets::Irq>> {
    if !irq_line_grantable(irq) {
        return None;
    }
    crate::cap_store::grant::<crate::cap::targets::Irq>(tid, perms, irq)
}

/// Called from the external-interrupt handler of either ISA
/// (`kernel/src/trap/interrupt.rs`'s `INT_EXTERNAL_S` arm, `entry/aarch64.rs`'s
/// `handle_irq`) after an IRQ fires. Dispatches to all bindings matching this
/// IRQ number.
///
/// A wake-task binding records the delivery as pending and, when its owner
/// is registered in `SYS_DRV_IRQ_WAIT`, wakes it by TID
/// (`wait::wake_irq_waiter`): a waiter that registered but has not committed
/// to `Blocked` yet is stamped and its block consumes the stamp. The
/// registration is cleared here, so one delivery wakes a waiter once. Both
/// ISRs call this BEFORE the `wake_by_irq` sweep, so a waiter this wakes is
/// no longer `Blocked` when the sweep runs; the sweep after a TID wake would
/// instead stamp a task that is already `Ready`, and that stale stamp would
/// make its next block return at once.
pub fn irq_dispatch(irq: u32) {
    // Collect matching targets under the lock, then dispatch after releasing
    // it — port_queue_event_bound() takes PORTS' own lock, and there's no
    // reverse path (nothing under PORTS ever locks IRQ_BINDINGS), but there's
    // no reason to hold this lock any longer than needed to read the table.
    let mut targets = [IrqTarget::None; MAX_IRQ_BINDINGS];
    let mut n = 0;
    let mut waiters = [0u32; MAX_IRQ_BINDINGS];
    let mut w = 0;
    {
        let mut bindings = IRQ_BINDINGS.lock_irqsave();
        for i in 0..MAX_IRQ_BINDINGS {
            let binding = &mut bindings[i];
            if !binding.active || binding.irq != irq {
                continue;
            }
            if let IrqTarget::WakeTask(tid) = binding.target {
                #[cfg(not(feature = "irq-pending-canary"))]
                {
                    binding.pending = true;
                }
                if binding.waiting {
                    binding.waiting = false;
                    waiters[w] = tid;
                    w += 1;
                }
                continue;
            }
            targets[n] = binding.target;
            n += 1;
        }
    }
    for &tid in &waiters[..w] {
        azos_sched::wait::wake_irq_waiter(tid, irq);
    }
    for target in &targets[..n] {
        match *target {
            IrqTarget::QueueToPortRef { port, epoch, key } => {
                let event = PortEvent {
                    key,
                    source_type: PORT_SOURCE_TYPE_IRQ,
                    source_id: irq,
                    code: 0,
                };
                // Queues and wakes the port's sleepers only when the
                // reference and its epoch still name the live port.
                if !port_queue_event_bound(port, epoch, event) {
                    IRQ_PORT_DROPS.fetch_add(1, Ordering::Relaxed);
                }
            }
            // Never stored: `irq_bind` converts it. Dropped if it ever were.
            IrqTarget::QueueToPort(..) => {
                IRQ_PORT_DROPS.fetch_add(1, Ordering::Relaxed);
            }
            IrqTarget::WakeTask(_) | IrqTarget::None => {}
        }
    }
}

/// Wipe the binding table and the drop counter. Host-test hygiene only.
#[cfg(test)]
pub fn __irq_bind_reset_for_tests() {
    let mut bindings = IRQ_BINDINGS.lock_irqsave();
    for b in bindings.iter_mut() {
        *b = IrqBinding::empty();
    }
    IRQ_PORT_DROPS.store(0, Ordering::Relaxed);
    LINE_RELEASE_HOOK.store(0, Ordering::Release);
}

/// The stored target of `owner_task`'s binding of `irq` (host tests).
#[cfg(test)]
pub fn __irq_binding_for_tests(irq: u32, owner_task: u32) -> Option<IrqTarget> {
    let bindings = IRQ_BINDINGS.lock_irqsave();
    bindings
        .iter()
        .find(|b| b.active && b.irq == irq && b.owner_task == owner_task)
        .map(|b| b.target)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cap::objref::PORT;
    use crate::port::{self, PortCapError};

    const OWNER: u32 = 41;
    const OTHER: u32 = 42;
    const IRQ: u32 = 7;

    /// The crate-wide serial lock (`tests/host/ipc-lease-tests`): the port table
    /// and the scheduler shim's port-wake record are shared with port.rs's
    /// suite.
    fn setup() -> std::sync::MutexGuard<'static, ()> {
        let g = crate::harness::serial();
        port::__port_reset_for_tests();
        __irq_bind_reset_for_tests();
        azos_sched::shim_reset_port_wakes();
        g
    }

    fn key_of(r: u32) -> Result<(u64, u8, u32), PortCapError> {
        port::port_poll_ref(r).map(|e| (e.key, e.source_type, e.source_id))
    }

    /// An IRQ bound to a live port — by index, the form `SYS_IRQ_BIND` builds,
    /// and by packed reference — queues its event there and wakes the port's
    /// registered waiter by TID with the reference, and the waiter's second
    /// half returns the event. The stored binding carries the reference, not
    /// the index.
    ///
    /// **Canary.** Store `QueueToPort` unconverted in `irq_bind`: delivery
    /// drops it and the poll reads `Empty`.
    #[test]
    fn an_irq_bound_to_a_live_port_queues_there_and_wakes_it() {
        let _g = setup();
        let r = port::port_create_ref(OWNER as usize).expect("create");
        let idx = PORT.idx(r);
        assert_eq!(irq_bind(IRQ, OWNER, IrqTarget::QueueToPort(idx, 0xAB)), 0);
        let epoch = port::port_live_epoch(r).unwrap();
        assert_eq!(
            __irq_binding_for_tests(IRQ, OWNER),
            Some(IrqTarget::QueueToPortRef { port: r, epoch, key: 0xAB })
        );
        let slot = match port::port_wait_begin(r, OWNER) {
            Ok(port::PortWaitStart::Registered { slot, .. }) => slot,
            _ => panic!("precondition: the owner waits"),
        };
        irq_dispatch(IRQ);
        assert_eq!(azos_sched::shim_port_waiter_wakes(), vec![(OWNER, r)]);
        assert_eq!(
            port::port_wait_end(slot, OWNER, r).map(|e| (e.key, e.source_type, e.source_id)),
            Ok((0xAB, PORT_SOURCE_TYPE_IRQ, IRQ))
        );
        assert_eq!(irq_port_drops(), 0);

        assert_eq!(irq_bind_port(IRQ + 1, OWNER, r, 0xCD), Ok(()), "the reference form");
        irq_dispatch(IRQ + 1);
        assert_eq!(key_of(r), Ok((0xCD, PORT_SOURCE_TYPE_IRQ, IRQ + 1)));
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
        assert_eq!(irq_bind_port(IRQ, OWNER, old, 0x01D), Ok(()));
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
        assert_eq!(irq_bind_port(IRQ, OTHER, new, 0x2E3), Ok(()));
        irq_dispatch(IRQ);
        assert_eq!(azos_sched::shim_port_waiter_wakes(), vec![(OTHER, new)]);
        assert_eq!(key_of(new), Ok((0x2E3, PORT_SOURCE_TYPE_IRQ, IRQ)));
        assert_eq!(port::port_wait_end(slot, OTHER, new).err(), Some(PortCapError::Empty));
        assert_eq!(irq_port_drops(), 2, "the old binding dropped again");
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
        assert_eq!(irq_bind_port(IRQ, OWNER, old, 0x0DD), Ok(()));
        port::port_destroy(PORT.idx(old));

        port::__port_set_next_gen_for_tests(PORT.idx(old) as usize, PORT.gen_max() + 1);
        let later = port::port_create_ref(OTHER as usize).expect("create");
        assert_eq!(later, old, "precondition: the same index and generation, another epoch");

        irq_dispatch(IRQ);
        assert!(!port::port_has_events(PORT.idx(later)));
        assert_eq!(irq_port_drops(), 1);
    }

    /// Binding a port that is not live is refused in both forms.
    #[test]
    fn binding_a_port_that_is_not_live_is_refused() {
        let _g = setup();
        assert_eq!(irq_bind(IRQ, OWNER, IrqTarget::QueueToPort(3, 1)), -1, "a free index");
        assert_eq!(
            irq_bind_port(IRQ, OWNER, 3, 1),
            Err(PortCapError::Cap(crate::cap::CapError::Stale)),
            "a bare index"
        );
        assert_eq!(irq_bind(IRQ, OWNER, IrqTarget::QueueToPort(u32::MAX, 1)), -1, "out of range");
        assert_eq!(__irq_binding_for_tests(IRQ, OWNER), None);
        assert_eq!(irq_bind(IRQ, OWNER, IrqTarget::WakeTask(OWNER)), 0, "other targets are unchanged");
    }

    // ── Wake-task bindings: the pending bit (wave 9 IRQ4 item 1) ────────────

    /// A delivery that lands while the owner is not waiting is kept, consumed
    /// by the owner's next wait without blocking, and consumed once.
    ///
    /// **Canary.** `--features irq-pending-canary` (dispatch no longer sets
    /// `pending`): the first `irq_wait_begin` answers `Registered` — the
    /// driver would block on a line that fired and is now masked.
    #[test]
    fn a_delivery_before_the_wait_is_kept_and_consumed_once() {
        let _g = setup();
        assert_eq!(irq_bind(IRQ, OWNER, IrqTarget::WakeTask(OWNER)), 0);
        irq_dispatch(IRQ);
        assert!(azos_sched::shim_take_irq_waiter_wakes().is_empty(), "nobody was waiting");
        assert_eq!(irq_wait_begin(IRQ, OWNER), IrqWaitStart::Pending, "the delivery was lost");
        assert_eq!(irq_wait_begin(IRQ, OWNER), IrqWaitStart::Registered, "consumed twice");
        assert!(!irq_wait_end(IRQ, OWNER));
    }

    /// A registered waiter is woken by TID with the exact line, once per
    /// delivery, and its wait end consumes that delivery.
    ///
    /// **Canary.** Leave `waiting` set in `irq_dispatch`: the second
    /// delivery wakes the task again.
    #[test]
    fn a_registered_waiter_is_woken_by_tid_once() {
        let _g = setup();
        let _ = azos_sched::shim_take_irq_waiter_wakes();
        assert_eq!(irq_bind(IRQ, OWNER, IrqTarget::WakeTask(OWNER)), 0);
        assert_eq!(irq_wait_begin(IRQ, OWNER), IrqWaitStart::Registered);
        irq_dispatch(IRQ);
        assert_eq!(azos_sched::shim_take_irq_waiter_wakes(), vec![(OWNER, IRQ)]);
        irq_dispatch(IRQ);
        assert!(azos_sched::shim_take_irq_waiter_wakes().is_empty(), "woken twice for one wait");
        assert!(irq_wait_end(IRQ, OWNER), "the wake's delivery was not consumed");
        assert!(!irq_wait_end(IRQ, OWNER));
    }

    /// Only the binding's owner consumes its pending delivery: another task
    /// waiting on the same line (the wait has no capability check), and the
    /// owner waiting on another line, get the unbound wait. A port binding
    /// has no pending bit either.
    #[test]
    fn only_the_owner_consumes_its_pending_delivery() {
        let _g = setup();
        assert_eq!(irq_bind(IRQ, OWNER, IrqTarget::WakeTask(OWNER)), 0);
        irq_dispatch(IRQ);
        assert_eq!(irq_wait_begin(IRQ, OTHER), IrqWaitStart::Unbound);
        assert_eq!(irq_wait_begin(IRQ + 1, OWNER), IrqWaitStart::Unbound);
        assert!(!irq_wait_end(IRQ, OTHER));
        assert_eq!(irq_wait_begin(IRQ, OWNER), IrqWaitStart::Pending);

        let r = port::port_create_ref(OTHER as usize).expect("create");
        assert_eq!(irq_bind_port(IRQ + 1, OTHER, r, 1), Ok(()));
        irq_dispatch(IRQ + 1);
        assert_eq!(irq_wait_begin(IRQ + 1, OTHER), IrqWaitStart::Unbound);
    }

    // ── Task exit hands the line back (wave 9 IRQ4 item 4) ──────────────────

    static RELEASED: std::sync::Mutex<Vec<u32>> = std::sync::Mutex::new(Vec::new());
    fn record_release(irq: u32) {
        RELEASED.lock().unwrap_or_else(|e| e.into_inner()).push(irq);
    }
    fn take_released() -> Vec<u32> {
        std::mem::take(&mut *RELEASED.lock().unwrap_or_else(|e| e.into_inner()))
    }

    /// A line is released when its LAST binding goes, once, and not while
    /// another task still holds a binding of it.
    ///
    /// **Canary.** Call `line_released` for every removed binding: the first
    /// exit releases a line OTHER still holds.
    #[test]
    fn the_last_unbind_of_a_line_releases_it_once() {
        let _g = setup();
        let _ = take_released();
        set_line_release_hook(record_release);
        assert_eq!(irq_bind(IRQ, OWNER, IrqTarget::WakeTask(OWNER)), 0);
        assert_eq!(irq_bind(IRQ, OTHER, IrqTarget::WakeTask(OTHER)), 0);
        assert_eq!(irq_bind(IRQ + 1, OWNER, IrqTarget::WakeTask(OWNER)), 0);
        irq_unbind_all(OWNER);
        assert_eq!(take_released(), vec![IRQ + 1], "a line OTHER still holds was released");
        irq_unbind_all(OTHER);
        assert_eq!(take_released(), vec![IRQ]);
        irq_unbind_all(OTHER);
        assert!(take_released().is_empty());
    }

    /// The reference form tells a full binding table from a port that is not
    /// live, and a repeat bind by the same owner replaces its target in place.
    ///
    /// **Canary.** Answer `Err(Cap(Stale))` for a full table: the last
    /// assertion reads `Stale`.
    #[test]
    fn the_reference_form_answers_full_apart_from_stale() {
        let _g = setup();
        let r = port::port_create_ref(OWNER as usize).expect("create");
        for irq in 0..MAX_IRQ_BINDINGS as u32 {
            assert_eq!(irq_bind_port(irq, OWNER, r, 1), Ok(()), "binding {irq}");
        }
        assert_eq!(irq_bind_port(0, OWNER, r, 2), Ok(()), "a repeat bind takes no new slot");
        assert_eq!(
            __irq_binding_for_tests(0, OWNER),
            Some(IrqTarget::QueueToPortRef { port: r, epoch: port::port_live_epoch(r).unwrap(), key: 2 })
        );
        assert_eq!(irq_bind_port(MAX_IRQ_BINDINGS as u32, OWNER, r, 1), Err(PortCapError::Full));
    }

    // ── A refused line undoes its bind (wave 10 IRQ5) ───────────────────────

    /// `irq_unbind` drops exactly the caller's binding of that line: another
    /// task's binding of it, and the caller's binding of another line, stay;
    /// the line is released only when the dropped binding was its last; a
    /// second undo finds nothing.
    ///
    /// **Canary.** Match on `b.irq == irq` alone: OTHER's binding goes with
    /// OWNER's.
    #[test]
    fn a_refused_bind_drops_only_that_binding() {
        let _g = setup();
        let _ = take_released();
        set_line_release_hook(record_release);
        assert_eq!(irq_bind(IRQ, OWNER, IrqTarget::WakeTask(OWNER)), 0);
        assert_eq!(irq_bind(IRQ, OTHER, IrqTarget::WakeTask(OTHER)), 0);
        assert_eq!(irq_bind(IRQ + 1, OWNER, IrqTarget::WakeTask(OWNER)), 0);

        assert!(irq_unbind(IRQ, OWNER));
        assert_eq!(__irq_binding_for_tests(IRQ, OWNER), None, "the refused binding stayed");
        assert_eq!(__irq_binding_for_tests(IRQ, OTHER), Some(IrqTarget::WakeTask(OTHER)));
        assert_eq!(__irq_binding_for_tests(IRQ + 1, OWNER), Some(IrqTarget::WakeTask(OWNER)));
        assert!(take_released().is_empty(), "a line OTHER still holds was released");
        assert!(!irq_unbind(IRQ, OWNER), "undone twice");

        assert!(irq_unbind(IRQ, OTHER));
        assert_eq!(take_released(), vec![IRQ], "the last binding's undo did not release the line");
    }

    /// An undone bind gives its slot back: a table filled by binds that are
    /// each refused and undone still takes a new binding.
    ///
    /// **Canary.** Make `irq_unbind` return `true` without clearing the slot:
    /// the bind after the loop reads -1.
    #[test]
    fn undone_binds_do_not_fill_the_table() {
        let _g = setup();
        for irq in 0..(2 * MAX_IRQ_BINDINGS) as u32 {
            assert_eq!(irq_bind(irq, OWNER, IrqTarget::WakeTask(OWNER)), 0, "binding {irq}");
            assert!(irq_unbind(irq, OWNER));
        }
        assert_eq!(irq_bind(IRQ, OWNER, IrqTarget::WakeTask(OWNER)), 0, "the table filled up");
    }
}

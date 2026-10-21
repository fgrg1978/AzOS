// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Entering a guest on this CPU: the vCPU pool, the entry loop around the
//! stub's world switch, and the hypervisor calls that need a vCPU's state.
//!
//! `Hypervisor::enter` gets a `GuestCtx` whose `frame` is 48 words, and a
//! vCPU's state here is much more (the [`Block`], about 2.4 KiB, and the
//! virtual interrupt controller's list-register queue). So the state lives in
//! a pool of [`SLOTS`] ([`azos_limits::HV_MAX_VCPUS`], one per vCPU the
//! monitor can have), and the ctx holds the reference: `frame[0]` the slot
//! plus one, `frame[1]` the key (the stage-2 root and the vCPU's index) that
//! owns it. A slot is claimed by the first entry of a vCPU, reused when the
//! same vCPU enters again from scratch (`CPU_ON` after `CPU_OFF`), and given
//! back with the VM's stage-2 tables (`HvImpl::stage2_destroy`): the root
//! names the VM for as long as it exists.
//!
//! One entry ([`enter`]):
//!
//! 1. applies the answer to the device access the guest waits for
//!    ([`Block::complete`]) and lists the virtual interrupts raised since
//!    the last entry ([`GuestIrq::pre_entry`]);
//! 2. masks interrupts on this CPU (it does not unmask before the guest
//!    runs: a physical interrupt ends the run anyway, `HCR_EL2.IMO`), finds
//!    this CPU's redistributor and enables the two hypervisor lines on it
//!    once, disables the timer's PPI there when the guest's timer is
//!    asserted (it is listed instead);
//! 3. cleans the block to the point of coherency, `HVC`s into the stub
//!    ([`stub::run_guest`]), invalidates the block;
//! 4. gives PPI 27 back, restores the interrupt mask (which takes the
//!    physical interrupt that ended the run, if there was one), feeds the
//!    list registers and the timer back to [`GuestIrq::after_exit`];
//! 5. decodes the exit ([`Block::after_exit`]): the traps answered here
//!    (performance-monitor accesses) enter again, up to [`RESUME_BUDGET`]
//!    times in a row so a guest that loops on one cannot hold the thread past
//!    its stop flag; the rest go to the monitor.

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};

use azos_arch_api::{Exit, GuestCtx, HypercallHost, HypercallOutcome};

use super::inject::GuestIrq;
use super::vgic::nr_lrs_from_vtr;
use super::vtimer::{cntvoff_on_resume, VTIMER_PPI};
use super::world::{self, Block, Start, Step};
use super::{cfg_of, serve, stub};
use crate::irq::gic;

/// vCPU slots: as many as the monitor's pool has vCPUs.
const SLOTS: usize = azos_limits::HV_MAX_VCPUS as usize;

/// Entries in a row one call to [`enter`] makes without returning to the
/// monitor's loop (which checks the stop flag).
const RESUME_BUDGET: u32 = 32;

/// The EL2 physical timer's PPI: the host's deadline while a guest runs.
const PPI_HYP_TIMER: u32 = 26;

/// Harts the redistributor cache covers (the kernel's `MAX_HARTS` is 8; a
/// hart id past this refuses the entry).
const HARTS: usize = 64;

struct State {
    block: Block,
    irq: GuestIrq,
}

struct Slot {
    /// 0: free; else [`key`] of the vCPU that owns it.
    key: AtomicU64,
    state: UnsafeCell<core::mem::MaybeUninit<State>>,
}

/// The VM's `CNTVOFF_EL2`, one value for all of its vCPUs: the first vCPU to
/// enter makes it from the physical count (the guest's count starts at zero)
/// and the others read it.
struct Clock {
    root: AtomicU64,
    ready: AtomicU32,
    off: AtomicU64,
}

struct Pool {
    slots: [Slot; SLOTS],
    clocks: [Clock; SLOTS],
    /// This hart's redistributor frame, found on its first entry; 0 unknown.
    rd: [AtomicUsize; HARTS],
}

// SAFETY: a slot's `state` is touched only by the thread of the vCPU that
// holds its key (the monitor runs one thread per vCPU) and by `release`, which
// only clears the key; everything else is atomic.
unsafe impl Sync for Pool {}

static POOL: Pool = Pool {
    slots: [const { Slot { key: AtomicU64::new(0), state: UnsafeCell::new(core::mem::MaybeUninit::zeroed()) } }; SLOTS],
    clocks: [const { Clock { root: AtomicU64::new(0), ready: AtomicU32::new(0), off: AtomicU64::new(0) } }; SLOTS],
    rd: [const { AtomicUsize::new(0) }; HARTS],
};

const USED: u64 = 1 << 63;
const ROOT_MASK: u64 = (1 << 48) - 1;

/// The key of the vCPU `ctx` is: its VM's stage-2 root and its index.
const fn key(root: u64, vcpu: u8) -> u64 {
    USED | (vcpu as u64) << 48 | (root & ROOT_MASK)
}

fn claim(k: u64) -> Option<usize> {
    if let Some(i) = POOL.slots.iter().position(|s| s.key.load(Ordering::Acquire) == k) {
        return Some(i);
    }
    POOL.slots.iter().position(|s| s.key.compare_exchange(0, k, Ordering::AcqRel, Ordering::Relaxed).is_ok())
}

/// Give back every slot and the clock of the VM whose stage-2 root is `root`.
pub(super) fn release(root: u64) {
    for s in &POOL.slots {
        let k = s.key.load(Ordering::Acquire);
        if k != 0 && k & ROOT_MASK == root & ROOT_MASK {
            s.key.store(0, Ordering::Release);
        }
    }
    for c in &POOL.clocks {
        if c.root.load(Ordering::Acquire) == root {
            c.ready.store(0, Ordering::Relaxed);
            c.root.store(0, Ordering::Release);
        }
    }
}

fn read_cntpct() -> u64 {
    let v: u64;
    // SAFETY: a counter read; the host may read the physical count
    // (`CNTHCTL_EL2.EL1PCTEN`, as `_azos_drop_to_el1` leaves it).
    unsafe { core::arch::asm!("isb", "mrs {0}, CNTPCT_EL0", out(reg) v, options(nomem, nostack, preserves_flags)) };
    v
}

fn vm_cntvoff(root: u64) -> u64 {
    let now = read_cntpct();
    if let Some(c) = POOL.clocks.iter().find(|c| c.root.load(Ordering::Acquire) == root) {
        while c.ready.load(Ordering::Acquire) == 0 {
            core::hint::spin_loop();
        }
        return c.off.load(Ordering::Relaxed);
    }
    for c in &POOL.clocks {
        if c.root.compare_exchange(0, root, Ordering::AcqRel, Ordering::Relaxed).is_ok() {
            let off = cntvoff_on_resume(now, 0);
            c.off.store(off, Ordering::Relaxed);
            c.ready.store(1, Ordering::Release);
            return off;
        }
    }
    // More VMs than vCPUs cannot be: a leaked clock. The host's own clock, so
    // the guest reads one value on every vCPU at least.
    0
}

fn id_reg_features() -> u64 {
    let (isar1, pfr0, pfr1): (u64, u64, u64);
    // SAFETY: reads of ID registers.
    unsafe {
        core::arch::asm!(
            "mrs {0}, ID_AA64ISAR1_EL1",
            "mrs {1}, ID_AA64PFR0_EL1",
            "mrs {2}, ID_AA64PFR1_EL1",
            out(reg) isar1, out(reg) pfr0, out(reg) pfr1,
            options(nomem, nostack, preserves_flags),
        );
    }
    world::features_from_ids(isar1, pfr0, pfr1)
}

/// Does this CPU have what the entry needs (the virtual CPU interface of a
/// GICv3)? A GICv2 machine refuses the guest.
pub(super) fn can_enter() -> bool {
    let pfr0: u64;
    // SAFETY: a read of an ID register.
    unsafe {
        core::arch::asm!("mrs {0}, ID_AA64PFR0_EL1", out(reg) pfr0, options(nomem, nostack, preserves_flags));
    }
    super::availability() == super::Availability::Resident && world::gic_v3_sysregs(pfr0)
}

/// The state of the vCPU `ctx` is, made on its first entry.
fn state_of(ctx: &mut GuestCtx) -> Option<*mut State> {
    let k = key(ctx.s2.root, ctx.vcpu);
    if ctx.started {
        let idx = (ctx.frame[0] as usize).checked_sub(1)?;
        let slot = POOL.slots.get(idx)?;
        if ctx.frame[1] != k || slot.key.load(Ordering::Acquire) != k {
            return None;
        }
        return Some(slot.state.get().cast());
    }
    let cfg = cfg_of(&ctx.s2).ok()?;
    let vttbr = cfg.vttbr(ctx.s2.root, ctx.vmid).ok()?;
    let vtr = stub::gic_info();
    let nlr = nr_lrs_from_vtr(vtr);
    // Claiming and the VM's clock wait on other vCPUs' threads; a thread that
    // is interrupted between the two steps of either would leave the waiting
    // one to spin on a hart that thread may share.
    let daif = crate::sysregs::disable_irq_fiq();
    let (idx, cntvoff) = match claim(k) {
        Some(i) => (i, vm_cntvoff(ctx.s2.root)),
        None => {
            crate::sysregs::write_daif(daif);
            return None;
        }
    };
    crate::sysregs::write_daif(daif);
    let p: *mut State = POOL.slots[idx].state.get().cast();
    // SAFETY: the slot is this vCPU's (claimed above); an all-zero `Block` is
    // a valid one (integers), and `GuestIrq` is written whole.
    unsafe {
        core::ptr::write_bytes(core::ptr::addr_of_mut!((*p).block), 0, 1);
        core::ptr::write(core::ptr::addr_of_mut!((*p).irq), GuestIrq::new(nlr, cntvoff));
        (*p).block.start(&Start {
            vcpu: ctx.vcpu,
            entry_pc: ctx.entry_pc,
            entry_arg: ctx.entry_arg,
            vttbr,
            vtcr: cfg.value(),
            cntvoff,
            nlr,
            prebits: (vtr >> 26) & 7,
            features: id_reg_features(),
        });
    }
    // What the guest's first instruction fetch must not find: stale lines.
    crate::cache::icache_invalidate_all();
    ctx.frame[0] = idx as u64 + 1;
    ctx.frame[1] = k;
    Some(p)
}

/// This CPU's redistributor, with the host's own hypervisor line enabled on it.
fn redistributor() -> Option<usize> {
    let slot = POOL.rd.get(crate::cpu::hart_id())?;
    let known = slot.load(Ordering::Relaxed);
    if known != 0 {
        return Some(known);
    }
    let rd = gic::find_redistributor(crate::cpu::read_mpidr().affinity_key(), gic::GICR_WALK_MAX_FRAMES)?;
    // The EL2 physical timer carries the host's deadline while a guest runs
    // (the stub programs it); its PPI must reach this CPU for the tick to end
    // a run that never exits.
    gic::enable_ppi_at(rd, PPI_HYP_TIMER);
    slot.store(rd, Ordering::Relaxed);
    Some(rd)
}

/// [`Hypervisor::enter`](azos_arch_api::Hypervisor::enter).
pub(super) fn enter(ctx: &mut GuestCtx) -> Exit {
    if !can_enter() {
        return Exit::InvalidState;
    }
    let Some(st) = state_of(ctx) else { return Exit::InvalidState };
    // SAFETY: the slot is this vCPU's and this is its only thread.
    let st = unsafe { &mut *st };
    if let Some(done) = ctx.completed.take() {
        st.block.complete(done);
    }
    // The time the vCPU was held is not the guest's.
    st.irq.skip_time(ctx.time_skip);
    let mut lines = core::mem::take(&mut ctx.irqs);
    let mut resumes = 0;
    loop {
        let daif = crate::sysregs::disable_irq_fiq();
        let Some(rd) = redistributor() else {
            crate::sysregs::write_daif(daif);
            return Exit::InvalidState;
        };
        let plan = st.irq.pre_entry(lines, read_cntpct());
        lines = 0;
        let b = &mut st.block;
        b.cntv_ctl = plan.timer.ctl;
        b.cntv_cval = plan.timer.cval;
        b.ich_hcr = st.irq.hcr();
        b.cntvoff = st.irq.cntvoff();
        let n = b.nlr as usize;
        b.lr[..n].copy_from_slice(&st.irq.lrs()[..n]);
        if plan.silence_ppi {
            gic::disable_ppi_at(rd, VTIMER_PPI);
        }
        // SAFETY: the block is in the kernel's own memory (mapped, and the
        // linear map reaches it from its physical address); EL2 is resident
        // (`can_enter`); interrupts are masked on the CPU the entry was
        // prepared on.
        unsafe {
            crate::cache::dcache_clean_and_invalidate(b as *mut Block as usize, core::mem::size_of::<Block>());
            stub::run_guest(b as *mut Block);
            crate::cache::dcache_clean_and_invalidate(b as *mut Block as usize, core::mem::size_of::<Block>());
        }
        if plan.silence_ppi {
            gic::enable_ppi_at(rd, VTIMER_PPI);
        }
        // A physical interrupt that ended the run is taken here, on the way out.
        crate::sysregs::write_daif(daif);
        st.irq.after_exit(&st.block.lr[..n], st.block.cntv_ctl, st.block.cntv_cval);
        match st.block.after_exit(&mut ctx.mmio_value) {
            Step::Report(e) => return e,
            Step::Resume if resumes < RESUME_BUDGET => resumes += 1,
            Step::Resume => return Exit::HostInterrupt,
        }
    }
}

/// [`Hypervisor::hypercall`](azos_arch_api::Hypervisor::hypercall).
pub(super) fn hypercall(ctx: &mut GuestCtx, host: &mut dyn HypercallHost) -> HypercallOutcome {
    let Some(st) = state_of(ctx).filter(|_| ctx.started) else { return HypercallOutcome::Unserved };
    // SAFETY: as in `enter`: this vCPU's slot, this thread.
    let b = unsafe { &mut (*st).block };
    serve::hypercall(&mut b.gpr, &mut b.pc, b.esr, ctx.vcpu as usize, host)
}

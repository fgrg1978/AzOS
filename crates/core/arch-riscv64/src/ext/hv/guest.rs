// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! One vCPU's entry: [`super::HvImpl`]'s `Hypervisor::enter`, in two halves.
//!
//! * [`begin`] and [`finish`] are plain code on the vCPU's state. `begin`
//!   puts the first-entry registers in place, completes the emulated access
//!   the guest last stopped on, and turns the virtual interrupt lines into
//!   `hvip`; `finish` decodes the trap and sets the guest up to resume past
//!   an instruction the monitor served by stopping. They run under the host
//!   tests with a synthetic frame.
//! * [`run`] (`riscv64` only) is the CSR part: it loads the VM's control
//!   registers and the vCPU's `vs*` CSRs on this hart, enters, and takes
//!   everything the guest owned off the hart again before the host runs.
//! * [`enter_vcpu`] is the order of the two: the interrupts go off FIRST, then
//!   the hart id is read, then `begin` decides the flush from it, then `run`.
//!   A vCPU thread may be unpinned, so with the interrupts on the thread can
//!   be preempted and migrated between the id and the entry; the flush would
//!   then be decided for a hart the guest does not run on. The order is a
//!   [`Hart`] seam so a host test can move the thread.
//!
//! # State
//!
//! A vCPU's state is [`VcpuState`], laid over `GuestCtx::frame`: the register
//! frame [`super::enter::GuestFrame`] first (the SBI that reads and answers
//! the guest's registers works on the same words), then the `vs*` CSRs the
//! hart gets back when the vCPU runs again, then the hart it last ran on.
//!
//! # Entry protocol (the boot protocol the SBI documents)
//!
//! The first entry starts the guest in VS-mode at `entry_pc` with `a0` = the
//! vCPU's index (its hart id) and `a1` = the entry argument (the device tree
//! address), `satp` Bare, interrupts off. `hstatus.VTW` is set so `wfi`
//! comes back as [`CommonExit::Wait`] instead of spinning the hart.
//!
//! # Interrupts into the guest
//!
//! `GuestCtx::irqs` bit `n` below [`inject::MSI_LINE_BASE`] is `hvip` bit `n`.
//! `VSSIP` is an edge the guest clears itself; `VSTIP` and `VSEIP` are levels
//! the monitor derives, so a bit absent from `irqs` withdraws the line
//! ([`super::inject::hvip_level`]). The lines from `MSI_LINE_BASE` up are
//! IMSIC identities (line `MSI_LINE_BASE + id - 1` is identity `id`,
//! [`inject::msi_bits`]), set pending in the vCPU's guest file.
//!
//! # The guest's interrupt file (AIA)
//!
//! A vCPU that uses the IMSIC holds one of its hart's guest interrupt files
//! ([`super::inject`]): taken when the vCPU first reaches for it (a trapped
//! `siselect`/`sireg`/`stopei`) or has a message-signalled line raised for
//! it, cleared and given the raised identities before the guest runs
//! ([`Hart::file_enter`]), named in the guest's `hstatus.VGEIN`, armed for
//! the supervisor guest-external interrupt while the vCPU waits
//! ([`Hart::file_exit`]). The file is the hart's hardware: the vCPU stays on
//! that hart, and an entry on another is refused with
//! [`CommonExit::InvalidState`].
//!
//! # The guest's floating point
//!
//! Not touched: the host's `sstatus.FS` is off while a guest runs, so a guest
//! that executes a floating-point instruction takes an illegal-instruction
//! exception, which is not delegated: the vCPU faults with
//! [`CommonExit::Other`] (2). A soft-float guest kernel never does.

use core::mem::size_of;

use azos_arch_api::{Exit as CommonExit, GuestCtx, MmioAccess, MmioDone, GUEST_FRAME_WORDS};

use super::csr::{self, HSTATUS_VTW};
use super::enter::GuestFrame;
use super::fault::{self, FaultInsn};
use super::inject::{self, hvip_level, hvip_with, VsIrq};
use super::vscsr::VsCsrs;

/// What a guest finds in `hstatus` besides `SPV`: `wfi` traps.
pub const VM_HSTATUS: u64 = HSTATUS_VTW;

/// The `wfi` instruction length: 4 bytes (it has no compressed form).
const WFI_LEN: u8 = 4;

/// `last_hart` of a vCPU that has not run.
const NO_HART: u64 = u64::MAX;

/// A vCPU's state across entries.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VcpuState {
    pub frame: GuestFrame,
    pub vs: VsCsrs,
    /// The hart this vCPU last ran on: its translations are cached there.
    pub last_hart: u64,
    /// `htimedelta`: the guest's `time` is the host's plus this (wrapping).
    /// It starts at 0 and moves back by the time the VM was held
    /// ([`GuestCtx::time_skip`], all of it at the first entry), so the guest
    /// does not count it and every vCPU of the VM reads the same `time`.
    pub htimedelta: u64,
    /// The guest interrupt file this vCPU holds on `last_hart` (1..); 0: none.
    pub vsfile: u64,
}

const _: () = assert!(
    size_of::<VcpuState>() <= size_of::<[u64; GUEST_FRAME_WORDS]>()
        && core::mem::align_of::<VcpuState>() <= core::mem::align_of::<u64>()
);

/// The state a context holds. A copy: [`begin`] and [`finish`] work on it
/// beside the rest of the context, and [`store`] puts it back.
pub fn load(ctx: &GuestCtx) -> VcpuState {
    // SAFETY: `VcpuState` is `repr(C)` plain words that fit, and are no more
    // aligned than, the array (asserted above); an all-zero state is a valid
    // one (it is what `GuestCtx::new` holds).
    unsafe { core::ptr::read(ctx.frame.as_ptr() as *const VcpuState) }
}

/// Put `st` back in `ctx` (where the SBI reads the guest's registers).
pub fn store(ctx: &mut GuestCtx, st: &VcpuState) {
    // SAFETY: as in [`load`]; `ctx.frame` is exclusively borrowed.
    unsafe { core::ptr::write(ctx.frame.as_mut_ptr() as *mut VcpuState, *st) }
}

/// What [`begin`] decided the hart must do before the guest runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Prepared {
    /// Invalidate this VM's cached G-stage translations on this hart: the
    /// vCPU has not run here since the tables last changed (first entry, or
    /// it ran on another hart in between).
    pub flush: bool,
}

/// `value` as the register a load of `size` bytes writes: sign-extended for
/// `lb`/`lh`/`lw`, zero-extended for the unsigned loads and `ld`.
pub const fn load_value(value: u64, size: u8, signed: bool) -> u64 {
    if size >= 8 {
        return value;
    }
    let bits = size as u32 * 8;
    let v = value & ((1u64 << bits) - 1);
    if signed && v >> (bits - 1) & 1 != 0 { v | (u64::MAX << bits) } else { v }
}

/// Finish the emulated access the guest stopped on: a load's value goes to its
/// register (never `x0`), the guest steps past the instruction. `MmioAccess`
/// does not say whether the load extends its sign; `htinst` still holds the
/// instruction.
fn complete_mmio(f: &mut GuestFrame, done: MmioDone) {
    let a = done.access;
    if !a.write && a.reg != 0 && (a.reg as usize) < f.gpr.len() {
        let signed = matches!(fault::decode_htinst(f.htinst), FaultInsn::Mem(m) if m.signed);
        f.gpr[a.reg as usize] = load_value(done.value, a.size, signed);
    }
    f.skip_insn(a.insn_len);
}

/// Everything before the CSRs: set the vCPU up for its next entry on `hart`.
pub fn begin(st: &mut VcpuState, ctx: &mut GuestCtx, hart: u64) -> Prepared {
    if !ctx.started {
        st.frame = GuestFrame::new(ctx.entry_pc, VM_HSTATUS);
        st.frame.gpr[10] = ctx.vcpu as u64;
        st.frame.gpr[11] = ctx.entry_arg;
        st.vs = VsCsrs::reset();
        st.last_hart = NO_HART;
        st.htimedelta = 0;
        st.vsfile = 0;
    }
    st.htimedelta = st.htimedelta.wrapping_sub(ctx.time_skip);
    if let Some(done) = ctx.completed.take() {
        complete_mmio(&mut st.frame, done);
    }
    st.vs.hvip = lines_to_hvip(st.vs.hvip, ctx.irqs);
    let flush = st.last_hart != hart;
    st.last_hart = hart;
    Prepared { flush }
}

/// `hvip` after the lines in `irqs`: the software interrupt is pended when
/// raised and left alone otherwise (the guest clears it), the timer and
/// external interrupts follow their lines.
pub const fn lines_to_hvip(hvip: u64, irqs: u64) -> u64 {
    let mut h = hvip;
    if irqs & csr::VSSIP != 0 {
        h = hvip_with(h, VsIrq::Software);
    }
    h = hvip_level(h, VsIrq::Timer, irqs & csr::VSTIP != 0);
    hvip_level(h, VsIrq::External, irqs & csr::VSEIP != 0)
}

/// Decode the trap the vCPU came back with and leave it ready to resume.
pub fn finish(st: &mut VcpuState, ctx: &mut GuestCtx) -> CommonExit {
    let f = &mut st.frame;
    let raw = azos_arch_api::RawExit { code: f.scause, info: [f.stval, f.htval, f.htinst, f.hstatus] };
    let exit = super::decode_common(&raw);
    match exit {
        // The instruction the monitor "served" by sleeping: past it.
        CommonExit::Wait => f.skip_insn(WFI_LEN),
        // The access is completed by `begin` of the next entry, once the
        // device model has answered; a store hands its value over now.
        CommonExit::Mmio(MmioAccess { write: true, reg, .. }) => {
            ctx.mmio_value = if reg == 0 { 0 } else { f.gpr[reg as usize & 31] };
        }
        // Same instruction again, with the trap's leftovers off.
        CommonExit::HostInterrupt => f.rearm(),
        _ => {}
    }
    exit
}

/// What [`enter_vcpu`] needs of the hart it runs on.
pub trait Hart {
    /// Turn the interrupts off; true when they were on.
    fn irqs_off(&mut self) -> bool;
    /// Turn them back on if `were_on`.
    fn irqs_restore(&mut self, were_on: bool);
    /// The id of the hart the caller is on now. Meaningful as "the hart the
    /// guest runs on" only with the interrupts off.
    fn hart_id(&mut self) -> u64;
    /// How many guest interrupt files this hart has (GEILEN); 0: none, or
    /// the machine is not wired for guest files ([`inject::Wiring`]).
    fn guest_files(&mut self) -> u32 {
        0
    }
    /// Make guest file `gei` ready for the vCPU about to run: `clear` for a
    /// new owner (the file holds the last one's state), then identities
    /// `msi` (bit `id`) pending.
    fn file_enter(&mut self, gei: u32, clear: bool, msi: u64) {
        let _ = (gei, clear, msi);
    }
    /// The guest is out: while it `waits` an identity arriving in its file
    /// must reach the host (arm the file).
    fn file_exit(&mut self, gei: u32, waits: bool) {
        let _ = (gei, waits);
    }
    /// [`run`], whose contract this carries.
    ///
    /// # Safety
    /// As [`run`].
    unsafe fn run(&mut self, st: &mut VcpuState, hgatp: u64, vmid: u16, flush: bool);
}

/// One vCPU entry: interrupts off, then the hart id, then [`begin`], the
/// guest file if the vCPU uses one, [`run`], [`finish`], then the interrupts
/// back. The id and the flush decision are taken inside the region that cannot
/// be preempted, so `last_hart` is the hart the guest really ran on and a
/// migration always flushes.
///
/// A virtual-instruction exception that is the guest's first reach for an
/// interrupt file it has not got ([`inject::adoptable`]) gives it one and
/// enters again, once, before the exit is reported.
///
/// # Safety
/// As [`run`].
pub unsafe fn enter_vcpu<H: Hart>(h: &mut H, ctx: &mut GuestCtx, hgatp: u64) -> CommonExit {
    let irqs_were_on = h.irqs_off();
    let mut st = load(ctx);
    let hart = h.hart_id();
    // The file is the hart's: a vCPU that holds one runs only where it does.
    // Refused before anything of the vCPU is touched, so it can still run
    // where its file is.
    if st.vsfile != 0 && st.last_hart != hart {
        h.irqs_restore(irqs_were_on);
        return CommonExit::InvalidState;
    }
    let prep = begin(&mut st, ctx, hart);
    let exit = enter_loop(h, &mut st, ctx, hart, hgatp, prep);
    store(ctx, &st);
    h.irqs_restore(irqs_were_on);
    exit
}

fn enter_loop<H: Hart>(
    h: &mut H,
    st: &mut VcpuState,
    ctx: &mut GuestCtx,
    hart: u64,
    hgatp: u64,
    prep: Prepared,
) -> CommonExit {
    let mut msi = inject::msi_bits(ctx.irqs);
    let mut flush = prep.flush;
    let mut clear = false;
    let mut adopted = false;
    loop {
        if st.vsfile == 0 && msi != 0 {
            // A line only a file can present: the guest uses the IMSIC.
            match bind_file(h, st, ctx, hart) {
                Some(()) => clear = true,
                None => return CommonExit::InvalidState,
            }
        }
        let gei = st.vsfile as u32;
        if gei != 0 {
            h.file_enter(gei, core::mem::take(&mut clear), core::mem::take(&mut msi));
        }
        // SAFETY: the caller's contract.
        unsafe { h.run(st, hgatp, ctx.vmid, flush) };
        flush = false;
        let exit = finish(st, ctx);
        if gei != 0 {
            h.file_exit(gei, matches!(exit, CommonExit::Wait));
        }
        let first_reach = matches!(exit, CommonExit::Other(csr::EXC_VIRTUAL_INSTRUCTION))
            && st.vsfile == 0
            && !adopted
            && inject::adoptable(st.frame.stval);
        if first_reach && bind_file(h, st, ctx, hart).is_some() {
            adopted = true;
            clear = true;
            msi = inject::msi_bits(ctx.irqs);
            st.frame.rearm();
            continue;
        }
        return exit;
    }
}

/// Give the vCPU a guest file of this hart and name it in `hstatus`.
fn bind_file<H: Hart>(h: &mut H, st: &mut VcpuState, ctx: &GuestCtx, hart: u64) -> Option<()> {
    if h.guest_files() == 0 {
        return None;
    }
    let gei = inject::FILES.bind(hart as usize, ctx.s2.root, ctx.vcpu).ok()?;
    st.vsfile = gei as u64;
    st.frame.hstatus = inject::hstatus_with_vgein(st.frame.hstatus, gei);
    Some(())
}

/// The real hart: `sstatus.SIE` and the hart id of `crate::cpu`.
#[cfg(target_arch = "riscv64")]
pub struct Csr;

#[cfg(target_arch = "riscv64")]
impl Hart for Csr {
    fn irqs_off(&mut self) -> bool {
        csr_clear_sie()
    }
    fn irqs_restore(&mut self, were_on: bool) {
        if were_on {
            csr_set_sie();
        }
    }
    fn hart_id(&mut self) -> u64 {
        crate::cpu::hart_id() as u64
    }
    fn guest_files(&mut self) -> u32 {
        if inject::wiring().guest_ids == 0 {
            return 0;
        }
        let hart = crate::cpu::hart_id();
        if let Some(n) = inject::FILES.geilen(hart) {
            return n;
        }
        // SAFETY: a guest is being entered, so H is available; the
        // interrupts are off ([`enter_vcpu`]).
        let n = unsafe { inject::geilen_probe() };
        inject::FILES.set_geilen(hart, n);
        if n > 0 {
            // An identity arriving in an armed file of this hart interrupts it
            // (cause 12, which the kernel's trap vector hands to `sgei_take`).
            // SAFETY: as above; the handler exists in every build that has a
            // monitor to enter a guest.
            unsafe { inject::sgei_enable() };
        }
        n
    }
    fn file_enter(&mut self, gei: u32, clear: bool, msi: u64) {
        let ids = clear.then_some(inject::wiring().guest_ids);
        // SAFETY: `gei` was bound on this hart, whose GEILEN covers it (so H
        // and the AIA are there); the interrupts are off and nothing else
        // owns `vsiselect` until [`run`] restores the guest's.
        unsafe {
            inject::file_disarm(gei);
            crate::irq::imsic::vs_prepare(gei, ids, msi);
        }
    }
    fn file_exit(&mut self, gei: u32, waits: bool) {
        if waits {
            // SAFETY: as in [`Self::file_enter`].
            unsafe { inject::file_arm(gei) };
        }
    }
    unsafe fn run(&mut self, st: &mut VcpuState, hgatp: u64, vmid: u16, flush: bool) {
        // SAFETY: the caller's contract.
        unsafe { run(st, hgatp, vmid, flush) }
    }
}

/// Run the vCPU on this hart until the guest traps back; see [`begin`] and
/// [`finish`]. The interrupts are already off ([`enter_vcpu`]).
///
/// # Safety
/// H must be [`super::probe::available`]; `hgatp` names a live G-stage root
/// that stays valid while the VM runs; `sstatus.SIE` is clear.
#[cfg(target_arch = "riscv64")]
unsafe fn run(st: &mut VcpuState, hgatp: u64, vmid: u16, flush: bool) {
    use super::{enter, gstage, probe, vscsr::VmCtl};

    let caps = inject::caps(st.vsfile != 0);

    // The guest's CSRs are on this hart from the load to the save: nothing may
    // schedule another vCPU (or any task that reads `scounteren`) in between.
    let (counteren, envcfg) = (read_csr_scounteren(), read_csr_senvcfg());
    // SAFETY: the caller's contract; the hart is H-capable, `ctl` names its VM.
    unsafe {
        VmCtl::new(hgatp, st.htimedelta, caps).load();
        // A hart without VMID bits has one tag for every VM.
        if flush || probe::vmid_bits_cached() == 0 {
            gstage::hfence_gvma_vmid(vmid);
        }
        st.vs.restore(caps);
        enter::enter(&mut st.frame);
        st.vs.save(caps);
    }
    write_csr_scounteren(counteren);
    write_csr_senvcfg(envcfg);
}

#[cfg(target_arch = "riscv64")]
fn csr_clear_sie() -> bool {
    let old: u64;
    // SAFETY: clears `sstatus.SIE` and returns the old `sstatus`.
    unsafe { core::arch::asm!("csrrci {o}, sstatus, 2", o = out(reg) old, options(nomem, nostack)) };
    old & 2 != 0
}

#[cfg(target_arch = "riscv64")]
fn csr_set_sie() {
    // SAFETY: re-enables the interrupts `csr_clear_sie` found enabled.
    unsafe { core::arch::asm!("csrsi sstatus, 2", options(nomem, nostack)) };
}

#[cfg(target_arch = "riscv64")]
fn read_csr_scounteren() -> u64 {
    let v: u64;
    // SAFETY: a CSR read.
    unsafe { core::arch::asm!("csrr {v}, {a}", v = out(reg) v, a = const csr::SCOUNTEREN, options(nomem, nostack)) };
    v
}

#[cfg(target_arch = "riscv64")]
fn write_csr_scounteren(v: u64) {
    // SAFETY: a CSR write of the value read before the guest ran.
    unsafe { core::arch::asm!("csrw {a}, {v}", v = in(reg) v, a = const csr::SCOUNTEREN, options(nomem, nostack)) };
}

#[cfg(target_arch = "riscv64")]
fn read_csr_senvcfg() -> u64 {
    let v: u64;
    // SAFETY: a CSR read.
    unsafe { core::arch::asm!("csrr {v}, {a}", v = out(reg) v, a = const csr::SENVCFG, options(nomem, nostack)) };
    v
}

#[cfg(target_arch = "riscv64")]
fn write_csr_senvcfg(v: u64) {
    // SAFETY: a CSR write of the value read before the guest ran.
    unsafe { core::arch::asm!("csrw {a}, {v}", v = in(reg) v, a = const csr::SENVCFG, options(nomem, nostack)) };
}

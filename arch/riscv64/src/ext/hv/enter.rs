// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Entering a guest and the exit vector.
//!
//! [`enter`] is a function call that returns when the guest traps back. It
//! saves the host's callee-saved registers and the CSRs it is about to
//! change on the host stack, installs the exit vector as `stvec`, parks the
//! frame pointer in `sscratch`, loads the guest's registers and `sret`s with
//! `hstatus.SPV` set, which makes the hart V=1 at `sepc` in the privilege
//! `sstatus.SPP` names (1: VS, 0: VU). Any trap from the guest (an exit, or
//! a host interrupt, which is taken in HS while V=1 whatever `sie` says)
//! lands at the exit vector, which swaps the guest's `a0` with `sscratch`,
//! stores every guest register and the trap CSRs in the frame, restores the
//! host's CSRs and registers, and returns from [`enter`].
//!
//! The host comes back with its `sstatus` as it was (interrupts as the
//! caller had them), the guest runs with `SIE` clear in the HS view. The
//! guest's floating-point and vector state are not touched: the caller
//! owns them (`sstatus.FS` and `vsstatus.FS` both gate guest FP).
//!
//! The caller loads [`super::vscsr::VmCtl`] and [`super::vscsr::VsCsrs`]
//! first; both persist across [`enter`].

use core::mem::{offset_of, size_of};

use super::csr;
use super::fault::{self, Exit};

/// Guest register file and trap record. `gpr[i]` is `x<i>`; `gpr[0]` is
/// unused. The layout is fixed: the entry and exit assembly index it.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GuestFrame {
    pub gpr: [u64; 32],
    /// In: the guest PC to resume at. Out: the PC of the trapping instruction.
    pub sepc: u64,
    /// In: the `sstatus` the guest enters with ([`entry_sstatus`]; `SIE` must
    /// be clear). Out: the `sstatus` at the trap, whose `SPP` is the guest
    /// privilege to re-enter with.
    pub sstatus: u64,
    /// In: the `hstatus` the guest enters with ([`entry_hstatus`]). Out:
    /// `hstatus` after the trap (`GVA` says whether `stval` is a guest
    /// virtual address).
    pub hstatus: u64,
    /// Out: why the guest stopped.
    pub scause: u64,
    pub stval: u64,
    pub htval: u64,
    pub htinst: u64,
    /// The host stack pointer across [`enter`]; private.
    host_sp: u64,
}

// The assembly below indexes these.
const OFF_SEPC: usize = offset_of!(GuestFrame, sepc);
const OFF_SSTATUS: usize = offset_of!(GuestFrame, sstatus);
const OFF_HSTATUS: usize = offset_of!(GuestFrame, hstatus);
const OFF_SCAUSE: usize = offset_of!(GuestFrame, scause);
const OFF_STVAL: usize = offset_of!(GuestFrame, stval);
const OFF_HTVAL: usize = offset_of!(GuestFrame, htval);
const OFF_HTINST: usize = offset_of!(GuestFrame, htinst);
const OFF_HOST_SP: usize = offset_of!(GuestFrame, host_sp);
const _: () = assert!(offset_of!(GuestFrame, gpr) == 0);
const _: () = assert!(OFF_SEPC == 32 * 8 && size_of::<GuestFrame>() == 40 * 8);

/// `sstatus.SPP`: the privilege `sret` returns to (with `hstatus.SPV`: 1 is
/// VS-mode, 0 is VU-mode).
const SSTATUS_SPP: u64 = 1 << 8;

/// The `sstatus` a guest enters with: privilege `vs` (VS or VU), `SPIE` and
/// `SIE` clear.
pub const fn entry_sstatus(vs: bool) -> u64 {
    if vs { SSTATUS_SPP } else { 0 }
}

/// The `hstatus` a guest enters with: `SPV` set (return to a guest), on top
/// of the VM's own trap-control bits (`VTVM`, `VTW`, `VTSR`, `HU`, ...).
pub const fn entry_hstatus(vm_bits: u64) -> u64 {
    vm_bits | csr::HSTATUS_SPV
}

impl GuestFrame {
    /// A frame for a guest starting at `pc` in VS-mode.
    pub const fn new(pc: u64, vm_hstatus_bits: u64) -> GuestFrame {
        GuestFrame {
            gpr: [0; 32],
            sepc: pc,
            sstatus: entry_sstatus(true),
            hstatus: entry_hstatus(vm_hstatus_bits),
            scause: 0,
            stval: 0,
            htval: 0,
            htinst: 0,
            host_sp: 0,
        }
    }

    /// Why the guest stopped on the last [`enter`].
    pub const fn exit(&self) -> Exit {
        fault::decode(self.scause, self.stval, self.htval, self.htinst, self.hstatus)
    }

    /// Resume after the trapping instruction (`len` 2 or 4: the emulated
    /// access's [`super::fault::MemOp::insn_len`], 4 for `ecall`).
    pub fn skip_insn(&mut self, len: u8) {
        self.sepc = self.sepc.wrapping_add(len as u64);
        // SPV stays set for the next entry; the trap's GVA/SPVP are stale.
        self.hstatus = entry_hstatus(self.hstatus & !(csr::HSTATUS_GVA | csr::HSTATUS_SPVP));
    }

    /// Re-arm the frame for the next [`enter`] after an exit that resumes
    /// the same instruction (a refaulted access): `SPV` back on, privilege
    /// as the guest trapped with it.
    pub fn rearm(&mut self) {
        self.hstatus = entry_hstatus(self.hstatus & !csr::HSTATUS_GVA);
    }
}

#[cfg(target_arch = "riscv64")]
core::arch::global_asm!(
    ".pushsection .text.azos_hv_enter, \"ax\"",
    ".globl azos_hv_enter",
    ".p2align 2",
    // azos_hv_enter(a0 = &mut GuestFrame). Host save area on its stack:
    //   0 ra, 8 gp, 16 tp, 24..112 s0..s11, 120 sstatus, 128 hstatus,
    //   136 stvec, 144 sscratch (160 bytes).
    "azos_hv_enter:",
    "    addi   sp, sp, -160",
    "    sd     ra,   0(sp)",
    "    sd     gp,   8(sp)",
    "    sd     tp,  16(sp)",
    "    sd     s0,  24(sp)",
    "    sd     s1,  32(sp)",
    "    sd     s2,  40(sp)",
    "    sd     s3,  48(sp)",
    "    sd     s4,  56(sp)",
    "    sd     s5,  64(sp)",
    "    sd     s6,  72(sp)",
    "    sd     s7,  80(sp)",
    "    sd     s8,  88(sp)",
    "    sd     s9,  96(sp)",
    "    sd     s10, 104(sp)",
    "    sd     s11, 112(sp)",
    "    sd     sp, {host_sp}(a0)",
    // Swap in the guest's CSRs (sstatus first: SIE clear before stvec moves).
    "    ld     t0, {sstatus}(a0)",
    "    ld     t1, {hstatus}(a0)",
    "    ld     t2, {sepc}(a0)",
    "    la     t3, azos_hv_exit",
    "    csrrw  t0, sstatus, t0",
    "    csrrw  t1, {hstatus_csr}, t1",
    "    csrw   sepc, t2",
    "    csrrw  t3, stvec, t3",
    "    csrrw  t4, sscratch, a0",
    "    sd     t0, 120(sp)",
    "    sd     t1, 128(sp)",
    "    sd     t3, 136(sp)",
    "    sd     t4, 144(sp)",
    // Guest registers; a0 (x10, offset 80) last, it holds the frame.
    "    ld     ra,   8(a0)",
    "    ld     sp,  16(a0)",
    "    ld     gp,  24(a0)",
    "    ld     tp,  32(a0)",
    "    ld     t0,  40(a0)",
    "    ld     t1,  48(a0)",
    "    ld     t2,  56(a0)",
    "    ld     s0,  64(a0)",
    "    ld     s1,  72(a0)",
    "    ld     a1,  88(a0)",
    "    ld     a2,  96(a0)",
    "    ld     a3, 104(a0)",
    "    ld     a4, 112(a0)",
    "    ld     a5, 120(a0)",
    "    ld     a6, 128(a0)",
    "    ld     a7, 136(a0)",
    "    ld     s2, 144(a0)",
    "    ld     s3, 152(a0)",
    "    ld     s4, 160(a0)",
    "    ld     s5, 168(a0)",
    "    ld     s6, 176(a0)",
    "    ld     s7, 184(a0)",
    "    ld     s8, 192(a0)",
    "    ld     s9, 200(a0)",
    "    ld     s10, 208(a0)",
    "    ld     s11, 216(a0)",
    "    ld     t3, 224(a0)",
    "    ld     t4, 232(a0)",
    "    ld     t5, 240(a0)",
    "    ld     t6, 248(a0)",
    "    ld     a0,  80(a0)",
    "    sret",
    // The exit vector (stvec, direct mode: 4-byte aligned).
    ".p2align 2",
    "azos_hv_exit:",
    "    csrrw  a0, sscratch, a0",
    "    sd     ra,   8(a0)",
    "    sd     sp,  16(a0)",
    "    sd     gp,  24(a0)",
    "    sd     tp,  32(a0)",
    "    sd     t0,  40(a0)",
    "    sd     t1,  48(a0)",
    "    sd     t2,  56(a0)",
    "    sd     s0,  64(a0)",
    "    sd     s1,  72(a0)",
    "    sd     a1,  88(a0)",
    "    sd     a2,  96(a0)",
    "    sd     a3, 104(a0)",
    "    sd     a4, 112(a0)",
    "    sd     a5, 120(a0)",
    "    sd     a6, 128(a0)",
    "    sd     a7, 136(a0)",
    "    sd     s2, 144(a0)",
    "    sd     s3, 152(a0)",
    "    sd     s4, 160(a0)",
    "    sd     s5, 168(a0)",
    "    sd     s6, 176(a0)",
    "    sd     s7, 184(a0)",
    "    sd     s8, 192(a0)",
    "    sd     s9, 200(a0)",
    "    sd     s10, 208(a0)",
    "    sd     s11, 216(a0)",
    "    sd     t3, 224(a0)",
    "    sd     t4, 232(a0)",
    "    sd     t5, 240(a0)",
    "    sd     t6, 248(a0)",
    // The guest's a0 went to sscratch in the swap.
    "    csrr   t0, sscratch",
    "    sd     t0,  80(a0)",
    "    csrr   t0, sepc",
    "    sd     t0, {sepc}(a0)",
    "    csrr   t0, sstatus",
    "    sd     t0, {sstatus}(a0)",
    "    csrr   t0, {hstatus_csr}",
    "    sd     t0, {hstatus}(a0)",
    "    csrr   t0, scause",
    "    sd     t0, {scause}(a0)",
    "    csrr   t0, stval",
    "    sd     t0, {stval}(a0)",
    "    csrr   t0, {htval_csr}",
    "    sd     t0, {htval}(a0)",
    "    csrr   t0, {htinst_csr}",
    "    sd     t0, {htinst}(a0)",
    // Back to the host: stack, then its CSRs (sstatus last: it can re-enable
    // interrupts, which must find the host's stvec and sscratch).
    "    ld     sp, {host_sp}(a0)",
    "    ld     t0, 136(sp)",
    "    csrw   stvec, t0",
    "    ld     t0, 144(sp)",
    "    csrw   sscratch, t0",
    "    ld     t0, 128(sp)",
    "    csrw   {hstatus_csr}, t0",
    "    ld     t0, 120(sp)",
    "    csrw   sstatus, t0",
    "    ld     ra,   0(sp)",
    "    ld     gp,   8(sp)",
    "    ld     tp,  16(sp)",
    "    ld     s0,  24(sp)",
    "    ld     s1,  32(sp)",
    "    ld     s2,  40(sp)",
    "    ld     s3,  48(sp)",
    "    ld     s4,  56(sp)",
    "    ld     s5,  64(sp)",
    "    ld     s6,  72(sp)",
    "    ld     s7,  80(sp)",
    "    ld     s8,  88(sp)",
    "    ld     s9,  96(sp)",
    "    ld     s10, 104(sp)",
    "    ld     s11, 112(sp)",
    "    addi   sp, sp, 160",
    "    ret",
    ".popsection",
    sepc = const OFF_SEPC,
    sstatus = const OFF_SSTATUS,
    hstatus = const OFF_HSTATUS,
    scause = const OFF_SCAUSE,
    stval = const OFF_STVAL,
    htval = const OFF_HTVAL,
    htinst = const OFF_HTINST,
    host_sp = const OFF_HOST_SP,
    hstatus_csr = const csr::HSTATUS,
    htval_csr = const csr::HTVAL,
    htinst_csr = const csr::HTINST,
);

#[cfg(target_arch = "riscv64")]
unsafe extern "C" {
    fn azos_hv_enter(frame: *mut GuestFrame);
}

/// Run the guest in `frame` until it traps back to the host; the frame then
/// holds its registers and the trap record ([`GuestFrame::exit`]).
///
/// The sequence cannot be interrupted into a half-state: `sstatus.SIE` is
/// clear from the first CSR swap until the exit restores the caller's value.
///
/// # Safety
/// H must be [`super::probe::available`]; [`super::vscsr::VmCtl::load`] and
/// [`super::vscsr::VsCsrs::restore`] have run on this hart for this vCPU;
/// the G-stage root named by `hgatp` stays valid; the caller owns the
/// guest's FP state. Must run with the host's own `stvec` and `sscratch`
/// meaningful (they are restored on return).
#[cfg(target_arch = "riscv64")]
pub unsafe fn enter(frame: &mut GuestFrame) {
    // SAFETY: the contract above; the routine preserves the host's callee-saved
    // registers, `stvec`, `sscratch`, `sstatus` and `hstatus`, and `frame`
    // is exclusively borrowed for the whole call.
    unsafe { azos_hv_enter(frame) }
}

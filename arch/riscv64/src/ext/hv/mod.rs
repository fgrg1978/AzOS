// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! RISC-V hypervisor extension (H) primitives: what a hosted-guest monitor
//! on riscv64 is built from (hypervisor plan step H1; the guest boot is S6).
//!
//! The kernel runs in HS-mode (S-mode on a hart with H). A guest runs in
//! VS-mode (or VU) with two-stage translation: the guest's own `vsatp`
//! tables (VS-stage) and the hypervisor's G-stage tables ([`gstage`]) that
//! map guest-physical to host-physical memory.
//!
//! | file        | what it holds |
//! |-------------|---------------|
//! | [`csr`]     | H-extension CSR addresses and bit fields, the one source |
//! | [`probe`]   | is H usable: the device tree's ISA string and a trap-probe write to `hstatus` |
//! | [`gstage`]  | the G-stage page table: PTE encoder, `hgatp`, Sv39x4/Sv48x4 builder and walker, `hfence.gvma` |
//! | [`vscsr`]   | the guest-visible `vs*` CSRs and the per-VM control CSRs: save, restore, load |
//! | [`enter`]   | VS-mode entry (`hstatus.SPV`, `sret`) and the exit vector, the guest register frame |
//! | [`guest`]   | one vCPU's entry (`Hypervisor::enter`): first-entry registers, the completed MMIO access, `hvip` from the lines, the `vs*` CSRs on and off the hart |
//! | [`fault`]   | decode of a VM exit: `scause`, `htval`/`htinst` guest faults |
//! | [`inject`]  | `hvip` interrupt injection, the Sstc guest timer (`vstimecmp`) and the AIA guest interrupt files (`hgeie`/`hgeip`, `hstatus.VGEIN`, one IMSIC file per vCPU) |
//! | [`sbi`]     | the SBI a guest calls with `ecall`: BASE, TIME, IPI, RFENCE, HSM, SRST |
//!
//! Not here: the vCPU loop and MMIO emulation (`azos_hv::run`, `azos_hv::vplic`) and the guest memory map (vmmd). The guest's floating-point
//! state is not provided.
//!
//! Everything that is arithmetic is plain code and runs under the host tests
//! (`tests/host/arch-tests/src/hv_rv.rs`); the CSR-touching parts are
//! `cfg(target_arch = "riscv64")`.

pub mod csr;
pub mod enter;
pub mod fault;
pub mod gstage;
pub mod guest;
pub mod inject;
pub mod probe;
pub mod sbi;
pub mod vscsr;

// ── the cross-ISA surface ───────────────────────────────────────────────
use azos_arch_api::{
    Exit as CommonExit, GuestCtx, HvKind, HvStatus, HypercallHost, HypercallOutcome, Hypervisor, MmioAccess, RawExit,
    RemoteFence, Stage2Root, StageAccess, StageError, StagePerms, StageTableMem,
};

use enter::GuestFrame;
use fault::{FaultInsn, MemKind};
use gstage::{GPerms, GStage, MapError, Mode, PageSize};

/// The monitor's mode: Sv39x4, 41 bits of guest-physical space (a guest of
/// 2 TiB is not a thing a device runs). Sv48x4 is a mode `hgatp` may refuse;
/// moving to it is a [`gstage::mode_supported`] probe and a new constant.
const MODE: Mode = Mode::Sv39x4;

/// The [`Hypervisor`] of the H extension.
#[derive(Clone, Copy, Debug, Default)]
pub struct HvImpl;

/// Table memory over the cross-ISA trait: a table is addressed by its
/// host-physical base and an entry index.
struct Tables<'a>(&'a mut dyn StageTableMem);

impl gstage::TableMem for Tables<'_> {
    fn alloc(&mut self, pages: usize) -> Option<u64> {
        self.0.alloc(pages)
    }
    fn free(&mut self, pa: u64, pages: usize) {
        self.0.free(pa, pages)
    }
    fn read(&self, table: u64, index: usize) -> u64 {
        self.0.read(table + index as u64 * 8)
    }
    fn write(&mut self, table: u64, index: usize, pte: u64) {
        self.0.write(table + index as u64 * 8, pte)
    }
}

/// The read-only view a software walk needs.
struct View<'a>(&'a dyn StageTableMem);

impl gstage::TableMem for View<'_> {
    fn alloc(&mut self, _pages: usize) -> Option<u64> {
        None
    }
    fn free(&mut self, _pa: u64, _pages: usize) {}
    fn read(&self, table: u64, index: usize) -> u64 {
        self.0.read(table + index as u64 * 8)
    }
    fn write(&mut self, _table: u64, _index: usize, _pte: u64) {}
}

/// Hands out one root, once: `GStage` keeps no state but its root and mode
/// and has no constructor from them, so a table made earlier is picked up
/// again by "allocating" its root.
struct Reattach(u64);

impl gstage::TableMem for Reattach {
    fn alloc(&mut self, _pages: usize) -> Option<u64> {
        Some(self.0)
    }
    fn free(&mut self, _pa: u64, _pages: usize) {}
    fn read(&self, _table: u64, _index: usize) -> u64 {
        0
    }
    fn write(&mut self, _table: u64, _index: usize, _pte: u64) {}
}

fn stage_of(s2: &Stage2Root) -> Result<GStage, StageError> {
    let mode = Mode::from_hgatp_mode(s2.aux).ok_or(StageError::OutOfRange)?;
    GStage::new(&mut Reattach(s2.root), mode).ok_or(StageError::HostAddress)
}

fn stage_error(e: MapError) -> StageError {
    match e {
        MapError::BadSize | MapError::Misaligned => StageError::Misaligned,
        MapError::OutOfRange => StageError::OutOfRange,
        MapError::AlreadyMapped | MapError::Overlap => StageError::Overlap,
        MapError::NotMapped => StageError::NotMapped,
        MapError::NoMemory => StageError::NoMemory,
    }
}

/// A guest page is readable always; write and execute as asked.
const fn gperms(p: StagePerms) -> GPerms {
    match (p.write, p.exec) {
        (false, false) => GPerms::RO,
        (true, false) => GPerms::RW,
        (false, true) => GPerms::RX,
        (true, true) => GPerms::RWX,
    }
}

impl Hypervisor for HvImpl {
    fn kind(&self) -> HvKind {
        HvKind::RiscvH
    }

    fn status(&self) -> HvStatus {
        if probe::available() {
            HvStatus::Usable(HvKind::RiscvH)
        } else {
            HvStatus::Absent("H extension not declared, refused by policy, or hstatus unreachable")
        }
    }

    fn gpa_bits(&self) -> u8 {
        MODE.gpa_bits() as u8
    }

    fn stage2_create(&self, mem: &mut dyn StageTableMem) -> Result<Stage2Root, StageError> {
        let g = GStage::new(&mut Tables(mem), MODE).ok_or(StageError::NoMemory)?;
        Ok(Stage2Root { root: g.root(), aux: MODE.hgatp_mode() })
    }

    fn stage2_map(
        &self,
        s2: &Stage2Root,
        mem: &mut dyn StageTableMem,
        gpa: u64,
        hpa: u64,
        perms: StagePerms,
    ) -> Result<(), StageError> {
        stage_of(s2)?.map(&mut Tables(mem), gpa, hpa, PageSize::K4, gperms(perms)).map_err(stage_error)
    }

    fn stage2_unmap(&self, s2: &Stage2Root, mem: &mut dyn StageTableMem, gpa: u64) -> Result<u64, StageError> {
        stage_of(s2)?.unmap(&mut Tables(mem), gpa, PageSize::K4).map_err(stage_error)
    }

    fn stage2_translate(&self, s2: &Stage2Root, mem: &dyn StageTableMem, gpa: u64) -> Option<(u64, StagePerms)> {
        let t = stage_of(s2).ok()?.walk(&View(mem), gpa)?;
        Some((t.hpa, StagePerms { write: t.perms.writable(), exec: t.perms.executable() }))
    }

    fn stage2_flush(&self, vmid: u16) {
        #[cfg(target_arch = "riscv64")]
        gstage::hfence_gvma_vmid(vmid);
        #[cfg(not(target_arch = "riscv64"))]
        let _ = vmid;
    }

    fn stage2_destroy(&self, s2: Stage2Root, mem: &mut dyn StageTableMem) {
        // The VM's vCPUs are gone: the guest interrupt files they held are free.
        inject::FILES.release(s2.root);
        if let Ok(g) = stage_of(&s2) {
            g.destroy(&mut Tables(mem));
        }
    }

    fn hypercall(&self, ctx: &mut GuestCtx, host: &mut dyn HypercallHost) -> HypercallOutcome {
        if inject::wiring().sstc && serve_sstc_timer(ctx) {
            return HypercallOutcome::Served;
        }
        // SAFETY: `GuestFrame` is `repr(C)` plain words that fit, and are no
        // more aligned than, `ctx.frame` (asserted above); an all-zero frame
        // is a valid one.
        let frame = unsafe { &mut *(ctx.frame.as_mut_ptr() as *mut GuestFrame) };
        sbi::serve(frame, ctx.vcpu as usize, host)
    }

    fn remote_fence(&self, ctx: &GuestCtx, fence: &RemoteFence) {
        remote_fence_on(&mut sbi::Real, ctx, fence);
    }

    fn guest_holder_key(&self, s2: &Stage2Root, vcpu: u8) -> u64 {
        inject::Owner { root: s2.root, vcpu }.key()
    }

    fn guest_msi_ids(&self) -> u32 {
        inject::wiring().guest_ids
    }

    fn guest_msi_line(&self, id: u32) -> Option<u32> {
        inject::msi_line(id).filter(|_| id <= inject::wiring().guest_ids)
    }

    fn decode_exit(&self, raw: &RawExit) -> CommonExit {
        decode_common(raw)
    }

    fn can_enter(&self) -> bool {
        cfg!(target_arch = "riscv64") && probe::available()
    }

    fn enter(&self, ctx: &mut GuestCtx) -> CommonExit {
        #[cfg(target_arch = "riscv64")]
        {
            let Ok(g) = stage_of(&ctx.s2) else { return CommonExit::InvalidState };
            // SAFETY: `can_enter` is what lets a vCPU start, so H is available
            // here; `ctx.s2` names a live table (the monitor owns it for the
            // life of the VM); `enter_vcpu` keeps the interrupts off from the
            // hart id to the last CSR restore.
            unsafe { guest::enter_vcpu(&mut guest::Csr, ctx, g.hgatp(ctx.vmid)) }
        }
        #[cfg(not(target_arch = "riscv64"))]
        {
            let _ = ctx;
            CommonExit::InvalidState
        }
    }
}

/// The SBI timer call of a guest that runs on Sstc: the deadline is the
/// guest's `vstimecmp` (the register its own `stimecmp` writes reach), so the
/// hart raises `VSTIP` and the monitor keeps no timer line for it. `true`:
/// the call was that call and is answered.
fn serve_sstc_timer(ctx: &mut GuestCtx) -> bool {
    let mut st = guest::load(ctx);
    let call = sbi::SbiCall::from_frame(&st.frame);
    if call.eid != sbi::eid::TIME || call.fid != sbi::fid::TIME_SET_TIMER {
        return false;
    }
    inject::set_timer_sstc(&mut st.vs, call.args[0]);
    st.frame.gpr[10] = sbi::err::SUCCESS as u64;
    st.frame.gpr[11] = 0;
    st.frame.skip_insn(SBI_ECALL_LEN);
    guest::store(ctx, &st);
    true
}

/// The length of `ecall`: the guest resumes after it.
const SBI_ECALL_LEN: u8 = 4;

/// [`Hypervisor::decode_exit`], also the vCPU entry's own decode.
pub(crate) fn decode_common(raw: &RawExit) -> CommonExit {
    let [stval, htval, htinst, hstatus] = raw.info;
    match fault::decode(raw.code, stval, htval, htinst, hstatus) {
        fault::Exit::Interrupt(_) => CommonExit::HostInterrupt,
        fault::Exit::VsEcall => CommonExit::Hypercall,
        // `wfi` under `hstatus.VTW`; every other trapped instruction is
        // a CSR or fence access the monitor has no use to tell apart.
        fault::Exit::VirtualInstruction { insn } if insn == INSN_WFI => CommonExit::Wait,
        fault::Exit::VirtualInstruction { .. } => CommonExit::Other(csr::EXC_VIRTUAL_INSTRUCTION),
        fault::Exit::Exception(c) => CommonExit::Other(c),
        fault::Exit::GuestPageFault(f) => {
            let access = match f.access {
                gstage::Access::Fetch => StageAccess::Exec,
                gstage::Access::Load => StageAccess::Read,
                gstage::Access::Store => StageAccess::Write,
            };
            match f.insn {
                // A plain load or store: the hardware did the decoding.
                FaultInsn::Mem(m) if !m.fp && m.kind != MemKind::Atomic => CommonExit::Mmio(MmioAccess {
                    gpa: f.gpa,
                    size: m.width,
                    write: m.kind == MemKind::Store,
                    reg: if m.kind == MemKind::Store { m.rs2 } else { m.rd },
                    insn_len: m.insn_len,
                }),
                _ => CommonExit::Fault { gpa: f.gpa, access },
            }
        }
    }
}

/// [`Hypervisor::remote_fence`] on `hart`: the guest is the one `ctx` names, so
/// `hgatp` is built from its tables and VM id, not taken from whatever this
/// hart ran last.
pub fn remote_fence_on(hart: &mut dyn sbi::Hart, ctx: &GuestCtx, fence: &RemoteFence) {
    if let Ok(g) = stage_of(&ctx.s2) {
        sbi::execute_on(hart, g.hgatp(ctx.vmid), fence);
    }
}

// A vCPU's register frame is `GuestCtx::frame`, a `GuestFrame` laid over it:
// the entry primitive keeps the guest's registers there, and so does the
// SBI that reads and answers them.
const _: () = assert!(
    core::mem::size_of::<GuestFrame>() <= core::mem::size_of::<[u64; azos_arch_api::GUEST_FRAME_WORDS]>()
        && core::mem::align_of::<GuestFrame>() <= core::mem::align_of::<u64>()
);

/// `wfi`.
const INSN_WFI: u64 = 0x1050_0073;

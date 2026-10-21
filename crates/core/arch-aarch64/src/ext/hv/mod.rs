// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Hypervisor on aarch64: what the CPU's EL2 gives, and the entry of a guest.
//!
//! * [`stub`] (bare metal, cargo feature `hv`): the resident EL2 stub. The
//!   boot trampoline keeps EL2 instead of dropping it for good, so an `HVC`
//!   from EL1 returns, and the stub's world switch runs a guest.
//! * [`vcpu`] (the same): the vCPU pool, the entry loop around the stub, and
//!   the hypercalls that need a vCPU's registers.
//! * [`world`]: the block the world switch reads and writes, the traps and
//!   `HCR_EL2` of a guest, what is answered inside the entry.
//! * [`stage2`]: `VTCR_EL2` / `VTTBR_EL2` and the stage-2 tables, built over
//!   the frames of a `MemObj`.
//! * [`vgic`]: the GICv3 list-register model.
//! * [`vtimer`]: `CNTVOFF_EL2` / `CNTHCTL_EL2` and the virtual timer's state.
//! * [`inject`]: the virtual timer's PPI and the monitor's device lines into
//!   the list registers.
//! * [`psci`]: the guest's PSCI and SMCCC calls, emulated over the VM's vCPU
//!   set; [`serve`] puts the answers in the guest's registers and carries out
//!   what they ask. [`stub`] is the host's PSCI path (re-issued as `SMC` to
//!   the firmware); a guest's calls never go there.
//!
//! The modules other than `stub` and `vcpu` are pure and run in the host
//! tests (`tests/host/arch-tests`, `tests/host/hv-tests`). The guest is
//! entered with `HVC` into the stub ([`HVC_ENTER`]): `HvImpl::enter` on a
//! GICv3 machine whose boot kept EL2, and refused anywhere else
//! ([`Hypervisor::can_enter`]).
//!
//! An image built without the hypervisor (Kconfig `VIRT` none) does not keep
//! EL2 at all, and one whose boot path entered at EL1 has no EL2 to keep: the
//! hypervisor is [`Availability::Absent`] with the reason recorded, and
//! whatever asked for a role other than `none` runs as `none`.

pub mod inject;
pub mod psci;
pub mod serve;
pub mod stage2;
pub mod vgic;
pub mod vtimer;
pub mod world;

#[cfg(all(target_arch = "aarch64", target_os = "none", feature = "hv"))]
mod stub;
#[cfg(all(target_arch = "aarch64", target_os = "none", feature = "hv"))]
mod vcpu;

/// The stub's probe function id: an SMCCC fast call to the vendor-specific
/// hypervisor service (owner 6), function 0.
pub const HVC_PROBE: u32 = 0x8600_0000;
/// What the probe returns in `x0`: "AZHV".
pub const PROBE_MAGIC: u64 = 0x415A_4856;
/// What the probe returns in `x1`.
pub const ABI_VERSION: u64 = 2;
/// Run the guest of the block at `x1` (a physical address) until it stops.
/// Function numbers 1..=0xF stay unassigned (`classify_hvc` pins them).
pub const HVC_ENTER: u32 = 0x8600_0010;
/// Invalidate the translations and instruction caches of the VMID in `x1`.
pub const HVC_FLUSH: u32 = 0x8600_0011;
/// `ICH_VTR_EL2` in `x0`.
pub const HVC_INFO: u32 = 0x8600_0012;

/// How the stub treats an `HVC` function id (`x0`).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum HvcClass {
    /// [`HVC_PROBE`], answered by the stub.
    Probe,
    /// [`HVC_ENTER`]: the world switch.
    Enter,
    /// [`HVC_FLUSH`].
    Flush,
    /// [`HVC_INFO`].
    Info,
    /// A PSCI call of the **host**, re-issued as `SMC #0`. A guest's PSCI is
    /// emulated by [`psci`], not forwarded.
    Psci,
    /// Everything else: `x0 = -1`.
    Unsupported,
}

/// The stub's dispatch, written with the same tests the handler's assembly
/// makes (so the table in the host tests pins the assembly's behaviour): the
/// hypervisor service's four calls exactly; PSCI is a fast call of the standard secure service (owner
/// 4) with function number 0..31, SMC32 or SMC64.
pub const fn classify_hvc(fid: u32) -> HvcClass {
    if fid == HVC_PROBE {
        HvcClass::Probe
    } else if fid == HVC_ENTER {
        HvcClass::Enter
    } else if fid == HVC_FLUSH {
        HvcClass::Flush
    } else if fid == HVC_INFO {
        HvcClass::Info
    } else if fid & 0x00FF_FFE0 == 0 && ((fid >> 24) & !0x40) == 0x84 {
        HvcClass::Psci
    } else {
        HvcClass::Unsupported
    }
}

/// Why the hypervisor is not available.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Reason {
    /// The image is built without the hypervisor (Kconfig `VIRT` none): the
    /// trampoline dropped EL2 as it always did.
    RoleNone,
    /// Boot entered at EL1 (QEMU without `virtualization=on`, or firmware that
    /// dropped to EL1 first): there was no EL2 to keep.
    EntryEl1,
}

/// Whether EL2 is resident on this boot.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Availability {
    /// The trampoline kept EL2 with the stub's vectors.
    Resident,
    /// No EL2: the role degrades to `none`.
    Absent(Reason),
}

/// The record the boot trampoline leaves (`azos_hv_state`): 1 when it kept EL2.
pub const fn availability_from_state(state: u8) -> Availability {
    if state == 1 { Availability::Resident } else { Availability::Absent(Reason::EntryEl1) }
}

/// Whether EL2 is resident on this boot. Off bare metal there is no boot
/// trampoline: always absent.
pub fn availability() -> Availability {
    #[cfg(all(target_arch = "aarch64", target_os = "none", feature = "hv"))]
    {
        stub::availability()
    }
    #[cfg(all(target_arch = "aarch64", target_os = "none", not(feature = "hv")))]
    {
        Availability::Absent(Reason::RoleNone)
    }
    #[cfg(not(all(target_arch = "aarch64", target_os = "none")))]
    {
        availability_from_state(0)
    }
}

/// `HVC` the stub's probe from EL1: the ABI version it answers with, or `None`
/// when EL2 is not resident (no `HVC` is issued) or the answer is wrong.
pub fn probe() -> Option<u64> {
    #[cfg(all(target_arch = "aarch64", target_os = "none", feature = "hv"))]
    {
        if availability() == Availability::Resident { stub::probe() } else { None }
    }
    #[cfg(not(all(target_arch = "aarch64", target_os = "none", feature = "hv")))]
    {
        None
    }
}

/// `ESR_EL2` and `ELR_EL2` of the last trap the stub could not handle and
/// parked a PE on, if any PE is parked.
pub fn last_unhandled_trap() -> Option<(u64, u64)> {
    #[cfg(all(target_arch = "aarch64", target_os = "none", feature = "hv"))]
    {
        stub::last_trap()
    }
    #[cfg(not(all(target_arch = "aarch64", target_os = "none", feature = "hv")))]
    {
        None
    }
}

// ── the cross-ISA surface ───────────────────────────────────────────────
use azos_arch_api::{
    Exit as CommonExit, GuestCtx, HvKind, HvStatus, HypercallHost, HypercallOutcome, Hypervisor, MmioAccess, RawExit,
    Stage2Root, StageAccess, StageError, StagePerms, StageTableMem, RAW_ARM_IRQ,
};

use stage2::{MemType, S2Attrs, S2Error, Stage2, VtcrConfig};

/// Guest-physical width: 40 bits (1 TiB). Every core this runs on (A53, A55,
/// A72, A76, QEMU's models) implements a 40-bit physical space at least, so
/// `VTCR_EL2.PS` is the 40-bit encoding (`PARange` 2) without reading the ID
/// register: a smaller PS than the hardware has only caps the output size.
const IPA_BITS: u8 = 40;
const PARANGE_40: u8 = 2;

/// The [`Hypervisor`] of EL2.
#[derive(Clone, Copy, Debug, Default)]
pub struct HvImpl;

/// Table memory over the cross-ISA trait. A walk that only reads is given a
/// shared view; one that writes, the exclusive one. `reattach` is the root of
/// a table made earlier: `Stage2` keeps its memory for its whole life and has
/// no constructor from a root, so it picks the root up again by "allocating"
/// it (once).
struct Tables<'a> {
    mem: Mem<'a>,
    reattach: Option<u64>,
}

enum Mem<'a> {
    Rw(&'a mut dyn StageTableMem),
    Ro(&'a dyn StageTableMem),
}

impl stage2::TableMem for Tables<'_> {
    fn alloc_tables(&mut self, tables: u64) -> Option<u64> {
        if let Some(root) = self.reattach.take() {
            return Some(root);
        }
        match &mut self.mem {
            Mem::Rw(m) => m.alloc(tables as usize),
            Mem::Ro(_) => None,
        }
    }
    fn read(&self, entry_pa: u64) -> u64 {
        match &self.mem {
            Mem::Rw(m) => m.read(entry_pa),
            Mem::Ro(m) => m.read(entry_pa),
        }
    }
    fn write(&mut self, entry_pa: u64, desc: u64) {
        if let Mem::Rw(m) = &mut self.mem {
            m.write(entry_pa, desc)
        }
    }
}

fn cfg_of(s2: &Stage2Root) -> Result<VtcrConfig, StageError> {
    VtcrConfig::new(s2.aux as u8, PARANGE_40).map_err(stage_error)
}

fn stage_error(e: S2Error) -> StageError {
    match e {
        S2Error::Misaligned | S2Error::BadLevel => StageError::Misaligned,
        S2Error::IpaOutOfRange | S2Error::BadIpaBits | S2Error::BadParange | S2Error::VmidTooWide => {
            StageError::OutOfRange
        }
        S2Error::PaTooWide => StageError::HostAddress,
        S2Error::Overlap | S2Error::ExecWithoutRead => StageError::Overlap,
        S2Error::NotMapped => StageError::NotMapped,
        S2Error::NoMemory => StageError::NoMemory,
    }
}

/// Guest RAM: write-back, readable always.
const fn attrs(p: StagePerms) -> S2Attrs {
    S2Attrs { read: true, write: p.write, exec: p.exec, mem: MemType::NormalWb }
}

fn free_tree(mem: &mut dyn StageTableMem, table: u64, level: u8, cfg: VtcrConfig) {
    let at_root = level == cfg.start_level();
    let entries = if at_root { cfg.root_tables() * stage2::S2_ENTRIES } else { stage2::S2_ENTRIES };
    if level < 3 {
        for i in 0..entries {
            let d = mem.read(table + i * 8);
            if stage2::desc_valid(d) && stage2::desc_is_table(d, level) {
                free_tree(mem, stage2::desc_pa(d), level + 1, cfg);
            }
        }
    }
    mem.free(table, if at_root { cfg.root_tables() as usize } else { 1 });
}

impl Hypervisor for HvImpl {
    fn kind(&self) -> HvKind {
        HvKind::ArmEl2
    }

    fn status(&self) -> HvStatus {
        match availability() {
            Availability::Resident => HvStatus::Usable(HvKind::ArmEl2),
            Availability::Absent(Reason::RoleNone) => HvStatus::Absent("built without the hypervisor: EL2 was not kept"),
            Availability::Absent(Reason::EntryEl1) => HvStatus::Absent("boot entered at EL1: no EL2 to keep"),
        }
    }

    fn gpa_bits(&self) -> u8 {
        IPA_BITS
    }

    fn stage2_create(&self, mem: &mut dyn StageTableMem) -> Result<Stage2Root, StageError> {
        let cfg = VtcrConfig::new(IPA_BITS, PARANGE_40).map_err(stage_error)?;
        let mut t = Tables { mem: Mem::Rw(mem), reattach: None };
        let s = Stage2::new(cfg, &mut t).map_err(stage_error)?;
        Ok(Stage2Root { root: s.root(), aux: IPA_BITS as u64 })
    }

    fn stage2_map(
        &self,
        s2: &Stage2Root,
        mem: &mut dyn StageTableMem,
        gpa: u64,
        hpa: u64,
        perms: StagePerms,
    ) -> Result<(), StageError> {
        let mut t = Tables { mem: Mem::Rw(mem), reattach: Some(s2.root) };
        let mut s = Stage2::new(cfg_of(s2)?, &mut t).map_err(stage_error)?;
        s.map_page(gpa, hpa, attrs(perms)).map_err(stage_error)
    }

    fn stage2_unmap(&self, s2: &Stage2Root, mem: &mut dyn StageTableMem, gpa: u64) -> Result<u64, StageError> {
        let mut t = Tables { mem: Mem::Rw(mem), reattach: Some(s2.root) };
        let mut s = Stage2::new(cfg_of(s2)?, &mut t).map_err(stage_error)?;
        s.unmap_page(gpa).map_err(stage_error)
    }

    fn stage2_translate(&self, s2: &Stage2Root, mem: &dyn StageTableMem, gpa: u64) -> Option<(u64, StagePerms)> {
        let mut t = Tables { mem: Mem::Ro(mem), reattach: Some(s2.root) };
        let s = Stage2::new(cfg_of(s2).ok()?, &mut t).ok()?;
        let (pa, a) = s.translate(gpa)?;
        Some((pa, StagePerms { write: a.write, exec: a.exec }))
    }

    /// `TLBI VMALLS12E1IS` for the VMID and the instruction caches, an EL2
    /// instruction: an `HVC` into the stub. Broadcast, so it reaches the CPUs
    /// the VM's other vCPUs run on.
    fn stage2_flush(&self, vmid: u16) {
        #[cfg(all(target_arch = "aarch64", target_os = "none", feature = "hv"))]
        if availability() == Availability::Resident {
            stub::flush(vmid);
        }
        #[cfg(not(all(target_arch = "aarch64", target_os = "none", feature = "hv")))]
        let _ = vmid;
    }

    fn stage2_destroy(&self, s2: Stage2Root, mem: &mut dyn StageTableMem) {
        #[cfg(all(target_arch = "aarch64", target_os = "none", feature = "hv"))]
        vcpu::release(s2.root);
        if let Ok(cfg) = cfg_of(&s2) {
            free_tree(mem, s2.root, cfg.start_level(), cfg);
        }
    }

    fn decode_exit(&self, raw: &RawExit) -> CommonExit {
        decode_esr(raw.code, raw.info[0], raw.info[1])
    }

    /// True when the boot kept EL2 and the CPU has the GICv3 system-register
    /// interface the virtual CPU interface is driven through.
    fn can_enter(&self) -> bool {
        #[cfg(all(target_arch = "aarch64", target_os = "none", feature = "hv"))]
        {
            vcpu::can_enter()
        }
        #[cfg(not(all(target_arch = "aarch64", target_os = "none", feature = "hv")))]
        {
            false
        }
    }

    fn enter(&self, ctx: &mut GuestCtx) -> CommonExit {
        #[cfg(all(target_arch = "aarch64", target_os = "none", feature = "hv"))]
        {
            vcpu::enter(ctx)
        }
        #[cfg(not(all(target_arch = "aarch64", target_os = "none", feature = "hv")))]
        {
            let _ = ctx;
            CommonExit::InvalidState
        }
    }

    /// The guest's `HVC` / `SMC`: PSCI and SMCCC, emulated ([`serve`]).
    fn hypercall(&self, ctx: &mut GuestCtx, host: &mut dyn HypercallHost) -> HypercallOutcome {
        #[cfg(all(target_arch = "aarch64", target_os = "none", feature = "hv"))]
        {
            vcpu::hypercall(ctx, host)
        }
        #[cfg(not(all(target_arch = "aarch64", target_os = "none", feature = "hv")))]
        {
            let _ = (ctx, host);
            HypercallOutcome::Unserved
        }
    }
}

/// Exception classes (`ESR_EL2.EC`) a lower-EL guest raises to EL2.
const EC_WFX: u64 = 0x01;
const EC_HVC64: u64 = 0x16;
const EC_SMC64: u64 = 0x17;
const EC_SYSREG: u64 = 0x18;
const EC_IABT_LOWER: u64 = 0x20;
const EC_DABT_LOWER: u64 = 0x24;

/// `DFSC`/`IFSC` families of a stage-2 fault: translation (0b0001LL),
/// access flag (0b0010LL), permission (0b0011LL). The other classes
/// (alignment, synchronous external abort, TLB conflict) are not a stage-2
/// miss and are not decoded as one.
const fn is_stage2_fault(fsc: u64) -> bool {
    matches!(fsc & 0x3C, 0x04 | 0x08 | 0x0C)
}

/// Classify a trap into EL2 taken while a guest ran. `esr`, `far` and
/// `hpfar` are `ESR_EL2`, `FAR_EL2` and `HPFAR_EL2`; a physical interrupt is
/// reported by the vector stub as [`RAW_ARM_IRQ`] in place of `esr`.
pub const fn decode_esr(esr: u64, far: u64, hpfar: u64) -> CommonExit {
    if esr == RAW_ARM_IRQ {
        return CommonExit::HostInterrupt;
    }
    let ec = (esr >> 26) & 0x3F;
    let iss = esr & 0x01FF_FFFF;
    // HPFAR_EL2.FIPA holds IPA[51:12] in bits [43:4]; the offset is FAR's.
    let gpa = ((hpfar >> 4) << 12) | (far & 0xFFF);
    match ec {
        EC_WFX => CommonExit::Wait,
        EC_HVC64 | EC_SMC64 => CommonExit::Hypercall,
        // ISS bit 0 is the direction: 1 reads the register (MRS).
        EC_SYSREG => CommonExit::SysReg { write: iss & 1 == 0 },
        EC_IABT_LOWER if is_stage2_fault(iss & 0x3F) => CommonExit::Fault { gpa, access: StageAccess::Exec },
        EC_DABT_LOWER if is_stage2_fault(iss & 0x3F) => {
            let write = iss & (1 << 6) != 0;
            let isv = iss & (1 << 24) != 0;
            let s1ptw = iss & (1 << 7) != 0;
            if isv && !s1ptw {
                CommonExit::Mmio(MmioAccess {
                    gpa,
                    size: 1 << ((iss >> 22) & 3),
                    write,
                    reg: ((iss >> 16) & 0x1F) as u8,
                    // ESR.IL: 1 is a 32-bit instruction.
                    insn_len: if esr & (1 << 25) != 0 { 4 } else { 2 },
                })
            } else {
                CommonExit::Fault { gpa, access: if write { StageAccess::Write } else { StageAccess::Read } }
            }
        }
        _ => CommonExit::Other(esr),
    }
}

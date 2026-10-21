// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The x86_64 hypervisor primitives (H1): what a virtual machine monitor
//! needs from the CPU, and nothing of the monitor itself.
//!
//! * [`probe`]: is hardware virtualization usable here (AMD and Intel)? Pure decisions over
//!   CPUID and the MSRs that firmware can lock (`VM_CR.SVMDIS`,
//!   `IA32_FEATURE_CONTROL`), host-tested with fake MSRs. A CPU whose
//!   firmware turned it off is *no hypervisor, with a record*, never a boot
//!   failure (unless the Kconfig choice is `require`).
//! * [`svm`] and [`npt`]: the AMD half. The VMCB layout and its encoders, the
//!   intercept bits, the consistency checks `VMRUN` makes, nested page tables
//!   built with the kernel's own PTE builder (`crate::mmu`).
//! * [`vmx`], [`ept`] and [`vmx_hw`]: the Intel half, a second backend of the
//!   same guest entry. The VMCS field encodings, the control resolution
//!   against the capability MSRs, the translation between the VMCB image the
//!   service works on and the VMCS, the exit decode (EPT violation, I/O,
//!   CPUID, MSR, HLT, ...) into the SVM words [`exit`] already decodes, the
//!   `VMXON` / `VMLAUNCH` loop; and extended page tables, whose entries are
//!   not x86 PTEs and have their own builder. `vmx_hw` (bare-metal only) is
//!   the instructions.
//! * [`exit`]: the decode of an SVM `#VMEXIT` into the [`exit::Exit`] the
//!   monitor's loop switches on.
//! * [`entry`], [`inject`], [`cpuid`], [`msr`], [`mmio`], [`apic`] and
//!   [`serve`]: an AzOS guest on SVM. The PVH start state of the boot CPU and
//!   the INIT / startup-IPI state of the others, event injection and the
//!   interrupt window, the guest's `CPUID` (an allow list) and MSRs (the
//!   permission map and the emulated few), the decode of a device access that
//!   faulted in the nested tables, and the service that answers the exits
//!   that need no device model, over the vCPU's local APIC ([`apic`], a trait
//!   the monitor implements on `azos_hv`'s vLAPIC and vIOAPIC). Pure, so the
//!   host tests (`tests/host/hv-tests`, `x86_guest.rs`) run them against the
//!   real virtual APICs.
//! * [`hw`] (bare-metal x86_64 only): the instructions. `EFER.SVME` and
//!   `VM_HSAVE_PA`, `VMRUN` with the guest's general registers, and the CPU
//!   the entry runs on.
//! * [`vcpu`]: `Hypervisor::enter`. One call builds the vCPU on its first
//!   entry (pages from the kernel's [`vcpu::VmHost`], the PVH start state,
//!   the permission maps from [`msr::build_msrpm`]), then loops *VMRUN,
//!   decode, [`serve`]* and returns only what the monitor's loop
//!   (`azos_hv::run`) must handle: a device access, a vCPU with nothing to
//!   run, a host interrupt, an exit nothing here serves. Generic over the
//!   CPU ([`vcpu::Machine`]): `hw::Hw` on the target, a script in
//!   `tests/host/hv-tests/src/x86_enter.rs`. Its production caller is the vCPU
//!   thread of `vmmd`'s guest (`azos_syscall::vm`), and `can_enter` is true
//!   when SVM probes usable and the kernel registered its host.
//!
//! The probe picks the backend ([`probe::choose`]): SVM when it is usable (it
//! stays primary), otherwise VMX when the CPU has EPT, unrestricted guest and
//! `INVEPT` and the capability MSRs allow every control the entry needs
//! ([`vmx::Controls::resolve`]). QEMU's TCG has no VMX, so the instruction layer is
//! not exercised by the host tests; the pure half is host-tested against the
//! SDM's numbers.
//!
//! Kconfig `X86_SVM` / `X86_VMX` (never / probe / require) gate the probe and
//! with it the backend; nothing here runs a guest until the monitor above asks. Everything but
//! [`hw`] compiles on the host, which is where the encoders are tested
//! (`tests/host/arch-stub-tests`, `hv_svm.rs`): a wrong bit position in a
//! VMCB is an opaque `VMEXIT_INVALID` on hardware.

pub mod apic;
pub mod cpuid;
pub mod entry;
pub mod ept;
pub mod exit;
pub mod inject;
pub mod mmio;
pub mod msr;
pub mod npt;
pub mod probe;
pub mod serve;
pub mod svm;
pub mod vcpu;
pub mod vmx;

/// The instructions (`vmrun`, `vmsave`/`vmload`, MSR writes).
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub mod hw;
/// The VMX instructions (`vmxon`, `vmlaunch`, `vmread` / `vmwrite`, ...).
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub mod vmx_hw;

// ── the cross-ISA surface ───────────────────────────────────────────────
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
use azos_arch_api::GuestCtx;
use azos_arch_api::{
    Exit as CommonExit, HvKind, HvStatus, Hypervisor, RawExit, Stage2Root, StageError, StagePerms, StageTableMem,
};

use crate::mmu::{self, WalkError};

/// The [`Hypervisor`] of the backend the probe chose: SVM with nested page
/// tables, or VMX with extended page tables. The two are one guest entry
/// ([`vcpu::enter`]) over two CPUs ([`hw::Hw`], [`vmx_hw::VmxHw`]) and two
/// second-level table formats ([`Format`]).
#[derive(Clone, Copy, Debug, Default)]
pub struct HvImpl;

/// The format of the second-level tables a backend walks: AMD's nested page
/// tables are x86 page tables, Intel's extended page tables are not
/// ([`ept`]).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Format {
    Npt,
    Ept,
}

impl HvImpl {
    /// The format of this boot's backend ([`Format::Npt`] when none was chosen).
    pub fn format() -> Format {
        if probe::record().kind == probe::Kind::Vmx { Format::Ept } else { Format::Npt }
    }
}

/// Table memory over the cross-ISA trait: an NPT table is one 4 KiB frame.
struct Tables<'a>(&'a mut dyn StageTableMem);

impl mmu::TableMem for Tables<'_> {
    fn read(&self, table: usize, idx: usize) -> u64 {
        self.0.read(table as u64 + idx as u64 * 8)
    }
    fn write(&mut self, table: usize, idx: usize, word: u64) {
        self.0.write(table as u64 + idx as u64 * 8, word)
    }
    fn alloc_table(&mut self) -> Option<usize> {
        self.0.alloc(1).map(|pa| pa as usize)
    }
}

/// The read-only view a software walk needs.
struct View<'a>(&'a dyn StageTableMem);

impl mmu::TableMem for View<'_> {
    fn read(&self, table: usize, idx: usize) -> u64 {
        self.0.read(table as u64 + idx as u64 * 8)
    }
    fn write(&mut self, _table: usize, _idx: usize, _word: u64) {}
    fn alloc_table(&mut self) -> Option<usize> {
        None
    }
}

fn walk_error(e: WalkError) -> StageError {
    match e {
        WalkError::NotCanonical => StageError::OutOfRange,
        WalkError::Misaligned | WalkError::Mmu(_) => StageError::Misaligned,
        WalkError::NoMemory => StageError::NoMemory,
        WalkError::AlreadyMapped | WalkError::HugeLeafInTheWay => StageError::Overlap,
        WalkError::NotMapped => StageError::NotMapped,
    }
}

fn access(p: StagePerms) -> npt::GuestAccess {
    npt::GuestAccess { write: p.write, exec: p.exec }
}

fn free_tree(mem: &mut dyn StageTableMem, table: u64, level: usize) {
    if level > 0 {
        for i in 0..512u64 {
            let w = mem.read(table + i * 8);
            if mmu::is_table(w, level) {
                free_tree(mem, mmu::phys_addr(w) as u64, level - 1);
            }
        }
    }
    mem.free(table, 1);
}

impl Format {
    /// Guest-physical address bits: 47 for both. NPT is walked with the host's
    /// PTE builder, which refuses a non-canonical address (bit 47 set would be
    /// read as a sign extension); EPT keeps the same limit so the one guest
    /// memory walk (`vcpu`'s) covers both.
    pub const fn gpa_bits(self) -> u8 {
        47
    }

    /// A new, empty tree: the root frame, and the number of levels (kept in
    /// `Stage2Root::aux`; the guest memory walk reads it).
    pub fn create(self, mem: &mut dyn StageTableMem) -> Result<Stage2Root, StageError> {
        let root = mem.alloc(1).ok_or(StageError::NoMemory)?;
        let levels = match self {
            Format::Npt => mmu::levels(),
            Format::Ept => ept::LEVELS,
        };
        Ok(Stage2Root { root, aux: levels as u64 })
    }

    /// Map one 4 KiB frame.
    pub fn map(
        self,
        s2: &Stage2Root,
        mem: &mut dyn StageTableMem,
        gpa: u64,
        hpa: u64,
        perms: StagePerms,
    ) -> Result<(), StageError> {
        if gpa >> self.gpa_bits() != 0 {
            return Err(StageError::OutOfRange);
        }
        let (root, gpa, hpa) = (s2.root as usize, gpa as usize, hpa as usize);
        let r = match self {
            Format::Npt => npt::map(&mut Tables(mem), root, s2.aux as usize, gpa, hpa, 0, access(perms), false),
            Format::Ept => ept::map(&mut Tables(mem), root, gpa, hpa, access(perms)),
        };
        r.map_err(walk_error)
    }

    /// Remove one 4 KiB mapping and return the frame it named.
    pub fn unmap(self, s2: &Stage2Root, mem: &mut dyn StageTableMem, gpa: u64) -> Result<u64, StageError> {
        let (root, gpa) = (s2.root as usize, gpa as usize);
        let r = match self {
            Format::Npt => {
                match mmu::translate(&View(mem), root, s2.aux as usize, gpa) {
                    // A larger leaf covers it: unmapping part of it is not a 4 KiB unmap.
                    Some(l) if l.level != 0 => return Err(StageError::Overlap),
                    _ => {}
                }
                mmu::unmap(&mut Tables(mem), root, s2.aux as usize, gpa).map(|l| l.phys as u64)
            }
            Format::Ept => ept::unmap(&mut Tables(mem), root, gpa),
        };
        r.map_err(walk_error)
    }

    /// The frame and permissions `gpa` translates to.
    pub fn translate(self, s2: &Stage2Root, mem: &dyn StageTableMem, gpa: u64) -> Option<(u64, StagePerms)> {
        let (root, gpa) = (s2.root as usize, gpa as usize);
        let (phys, a) = match self {
            Format::Npt => {
                let l = mmu::translate(&View(mem), root, s2.aux as usize, gpa)?;
                let p = mmu::perms_of(l.word);
                (l.phys as u64, npt::GuestAccess { write: p.write, exec: p.exec })
            }
            Format::Ept => {
                let l = ept::translate(&View(mem), root, gpa)?;
                (l.phys, ept::access_of(l.word))
            }
        };
        Some((phys, StagePerms { write: a.write, exec: a.exec }))
    }
}

impl Hypervisor for HvImpl {
    fn kind(&self) -> HvKind {
        match probe::record().kind {
            probe::Kind::Vmx => HvKind::X86Vmx,
            _ => HvKind::X86Svm,
        }
    }

    fn status(&self) -> HvStatus {
        let c = probe::record();
        match c.kind {
            probe::Kind::Svm => HvStatus::Usable(HvKind::X86Svm),
            #[cfg(all(target_arch = "x86_64", target_os = "none"))]
            probe::Kind::Vmx if vmx_hw::controls().is_none() => {
                HvStatus::Absent("VMX lacks a control the guest entry needs")
            }
            probe::Kind::Vmx => HvStatus::Usable(HvKind::X86Vmx),
            probe::Kind::None => HvStatus::Absent(c.why.name()),
        }
    }

    fn gpa_bits(&self) -> u8 {
        Self::format().gpa_bits()
    }

    fn stage2_create(&self, mem: &mut dyn StageTableMem) -> Result<Stage2Root, StageError> {
        Self::format().create(mem)
    }

    fn stage2_map(
        &self,
        s2: &Stage2Root,
        mem: &mut dyn StageTableMem,
        gpa: u64,
        hpa: u64,
        perms: StagePerms,
    ) -> Result<(), StageError> {
        Self::format().map(s2, mem, gpa, hpa, perms)
    }

    fn stage2_unmap(&self, s2: &Stage2Root, mem: &mut dyn StageTableMem, gpa: u64) -> Result<u64, StageError> {
        Self::format().unmap(s2, mem, gpa)
    }

    fn stage2_translate(&self, s2: &Stage2Root, mem: &dyn StageTableMem, gpa: u64) -> Option<(u64, StagePerms)> {
        Self::format().translate(s2, mem, gpa)
    }

    /// The second-level TLB is invalidated through the control block's
    /// `TLB_CTL` at the next entry of every vCPU of the VM ([`vcpu::flush`]
    /// moves the table epoch they compare; VMX turns the same request into
    /// `INVEPT` and `INVVPID`); a CPU that is running one now is made to
    /// leave the guest first, with the reschedule IPI, and waited for.
    fn stage2_flush(&self, vmid: u16) {
        // Interrupts masked across the whole flush: `flush` leaves out the CPU
        // it runs on (`me`, never in a guest) and kicks every other one, so
        // the id must stay this CPU's until the last CPU has left its guest.
        // A task moved after reading it would skip the CPU it left, which may
        // be running a guest of this VM with the old translations. Waiting
        // for another CPU to leave needs that CPU's interrupts, not ours.
        #[cfg(all(target_arch = "x86_64", target_os = "none"))]
        {
            use azos_arch_api::Interrupts as _;
            let irq = crate::X86_64.disable_all();
            vcpu::flush(vmid, crate::cpu::percpu_id(), &mut |cpu| {
                crate::irq::apic::send_ipi(cpu, crate::irq::encode::RESCHED_VECTOR);
            });
            crate::X86_64.restore(irq);
        }
        #[cfg(not(all(target_arch = "x86_64", target_os = "none")))]
        vcpu::flush(vmid, usize::MAX, &mut |_| {});
    }

    fn stage2_destroy(&self, s2: Stage2Root, mem: &mut dyn StageTableMem) {
        if let Some(h) = vcpu::host() {
            vcpu::slots_release(h, s2.root);
        }
        free_tree(mem, s2.root, (s2.aux as usize).saturating_sub(1));
    }

    /// The exit words are SVM's on both backends: the VMX entry translates its
    /// exits ([`vmx::to_svm`]) before the service sees them.
    fn decode_exit(&self, raw: &RawExit) -> CommonExit {
        vcpu::common(exit::svm(raw.code, raw.info[0], raw.info[1]))
    }

    /// The backend is usable and the kernel gave the entry its host.
    #[cfg(all(target_arch = "x86_64", target_os = "none"))]
    fn can_enter(&self) -> bool {
        match probe::record().kind {
            probe::Kind::Svm => vcpu::host().is_some(),
            probe::Kind::Vmx => vcpu::host().is_some() && vmx_hw::controls().is_some(),
            probe::Kind::None => false,
        }
    }

    #[cfg(all(target_arch = "x86_64", target_os = "none"))]
    fn enter(&self, ctx: &mut GuestCtx) -> CommonExit {
        let Some(h) = vcpu::host() else { return CommonExit::InvalidState };
        match probe::record().kind {
            probe::Kind::Svm => vcpu::enter(&mut hw::Hw(h), h, ctx),
            probe::Kind::Vmx => vcpu::enter(&mut vmx_hw::VmxHw(hw::Hw(h)), h, ctx),
            probe::Kind::None => CommonExit::InvalidState,
        }
    }
}

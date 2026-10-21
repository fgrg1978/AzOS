// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The world switch's data: the block one vCPU's entry reads and its exit
//! writes, and everything about it that is arithmetic.
//!
//! The host kernel runs at EL1 under the resident EL2 stub ([`super::stub`]).
//! Entering a guest is an `HVC` from the host into the stub with the physical
//! address of a [`Block`]; the stub saves the host's EL1 state into the
//! block, loads the guest's, and `eret`s to the guest's EL1. Any exception
//! the guest takes to EL2 (a trap, a physical interrupt) saves the guest into
//! the block, restores the host and `eret`s back to the instruction after the
//! `HVC`. So the block is the whole interface between Rust and the assembly:
//! [`Block`]'s field offsets are the assembly's (`stub.rs` takes them with
//! `offset_of!`), and what is checked here is checked for both.
//!
//! The stub runs with its MMU off, so it reaches the block by physical
//! address and as Device memory; the host cleans the block to the point of
//! coherency before the `HVC` and invalidates it after (`vcpu.rs`). Nothing
//! in the block is shared between vCPUs or harts: it is the vCPU's, used by
//! the one thread that runs it.
//!
//! What is here is pure and runs under the host tests: building the block of
//! a vCPU that has not run ([`Block::start`]), putting the answer to an
//! emulated device access into it ([`Block::complete`]), reading why the
//! guest stopped ([`Block::after_exit`]), and the ID-register decisions
//! ([`features_from_ids`], [`gic_v3_sysregs`]).

use core::mem::{offset_of, size_of};

use azos_arch_api::{Exit, MmioDone, RAW_ARM_IRQ};

use super::vgic::MAX_LRS;
use super::vtimer::Cnthctl;
use super::{decode_esr, psci};

/// EL1 system registers, in the order `stub.rs` saves and loads
/// them (pairs, so the assembly uses `stp` / `ldp`).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct El1 {
    pub sctlr: u64,
    pub ttbr0: u64,
    pub ttbr1: u64,
    pub tcr: u64,
    pub mair: u64,
    pub amair: u64,
    pub vbar: u64,
    pub contextidr: u64,
    pub cpacr: u64,
    pub esr: u64,
    pub far: u64,
    pub afsr0: u64,
    pub afsr1: u64,
    pub par: u64,
    pub tpidr_el1: u64,
    pub tpidr_el0: u64,
    pub tpidrro_el0: u64,
    pub sp_el0: u64,
    pub sp_el1: u64,
    pub elr_el1: u64,
    pub spsr_el1: u64,
    pub csselr: u64,
    pub actlr: u64,
    pub cntkctl: u64,
    pub mdscr: u64,
    pub _pad: u64,
    /// The pointer-authentication keys (`APIA`, `APIB`, `APDA`, `APDB`, `APGA`;
    /// low then high word each), saved only on a CPU that has them
    /// ([`feat::PAUTH`]).
    pub pac: [u64; 10],
}

/// What the stub keeps of the host while a guest runs. Written and read by
/// the stub alone.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Host {
    pub el1: El1,
    /// `ELR_EL2` / `SPSR_EL2` of the `HVC`: where the host resumes.
    pub elr: u64,
    pub spsr: u64,
    pub hcr: u64,
    pub cptr: u64,
    pub mdcr: u64,
    pub cntvoff: u64,
    pub cnthctl: u64,
    pub cntv_ctl: u64,
    pub cntv_cval: u64,
    pub _pad0: u64,
    pub fpcr: u64,
    pub fpsr: u64,
    pub fp: [u128; 32],
}

/// The vCPU block. `align(64)`: a cache line, so cleaning and invalidating
/// it never touches a neighbour.
#[repr(C, align(64))]
pub struct Block {
    /// The guest's `x0`..`x30` (`gpr[31]` pads the array to whole pairs).
    pub gpr: [u64; 32],
    /// `ELR_EL2` / `SPSR_EL2` the guest resumes with, and has when it stops.
    pub pc: u64,
    pub pstate: u64,

    // ── written by the stub at an exit ─────────────────────────────────
    /// `ESR_EL2` of the trap, or [`RAW_ARM_IRQ`] for a physical interrupt.
    pub esr: u64,
    pub far: u64,
    pub hpfar: u64,
    pub _r0: u64,

    // ── controls the host sets before an entry ─────────────────────────
    pub hcr: u64,
    pub vttbr: u64,
    pub vtcr: u64,
    pub vmpidr: u64,
    pub cptr: u64,
    pub mdcr: u64,
    pub cntvoff: u64,
    pub cnthctl: u64,
    pub ich_hcr: u64,
    pub ich_vmcr: u64,
    /// List registers the CPU interface has.
    pub nlr: u64,
    /// `ICH_VTR_EL2.PREbits` (the field: bits minus one).
    pub prebits: u64,
    /// [`feat`] bits.
    pub feat: u64,
    /// The guest's virtual timer, loaded before the entry and read back at the exit.
    pub cntv_ctl: u64,
    pub cntv_cval: u64,
    pub _r1: u64,

    /// `ICH_LR<n>_EL2` and the active-priority registers: loaded before the
    /// entry, read back at the exit.
    pub lr: [u64; MAX_LRS],
    pub ap0r: [u64; 4],
    pub ap1r: [u64; 4],

    pub guest: El1,
    pub fpcr: u64,
    pub fpsr: u64,
    pub fp: [u128; 32],

    pub host: Host,
}

/// Byte offsets the assembly uses.
pub mod off {
    use super::{offset_of, Block, Host};

    pub const GPR: usize = offset_of!(Block, gpr);
    pub const PC: usize = offset_of!(Block, pc);
    pub const PSTATE: usize = offset_of!(Block, pstate);
    pub const ESR: usize = offset_of!(Block, esr);
    pub const FAR: usize = offset_of!(Block, far);
    pub const HPFAR: usize = offset_of!(Block, hpfar);
    pub const HCR: usize = offset_of!(Block, hcr);
    pub const VTTBR: usize = offset_of!(Block, vttbr);
    pub const VTCR: usize = offset_of!(Block, vtcr);
    pub const VMPIDR: usize = offset_of!(Block, vmpidr);
    pub const CPTR: usize = offset_of!(Block, cptr);
    pub const MDCR: usize = offset_of!(Block, mdcr);
    pub const CNTVOFF: usize = offset_of!(Block, cntvoff);
    pub const CNTHCTL: usize = offset_of!(Block, cnthctl);
    pub const ICH_HCR: usize = offset_of!(Block, ich_hcr);
    pub const ICH_VMCR: usize = offset_of!(Block, ich_vmcr);
    pub const NLR: usize = offset_of!(Block, nlr);
    pub const PREBITS: usize = offset_of!(Block, prebits);
    pub const FEAT: usize = offset_of!(Block, feat);
    pub const CNTV_CTL: usize = offset_of!(Block, cntv_ctl);
    pub const CNTV_CVAL: usize = offset_of!(Block, cntv_cval);
    pub const LR: usize = offset_of!(Block, lr);
    pub const AP0R: usize = offset_of!(Block, ap0r);
    pub const AP1R: usize = offset_of!(Block, ap1r);
    pub const GUEST: usize = offset_of!(Block, guest);
    pub const FPCR: usize = offset_of!(Block, fpcr);
    pub const FP: usize = offset_of!(Block, fp);
    pub const HOST: usize = offset_of!(Block, host);
    pub const HOST_EL1: usize = HOST + offset_of!(Host, el1);
    pub const HOST_ELR: usize = HOST + offset_of!(Host, elr);
    pub const HOST_HCR: usize = HOST + offset_of!(Host, hcr);
    pub const HOST_MDCR: usize = HOST + offset_of!(Host, mdcr);
    pub const HOST_CNTHCTL: usize = HOST + offset_of!(Host, cnthctl);
    pub const HOST_CNTV_CVAL: usize = HOST + offset_of!(Host, cntv_cval);
    pub const HOST_FPCR: usize = HOST + offset_of!(Host, fpcr);
    pub const HOST_FP: usize = HOST + offset_of!(Host, fp);
}

// The assembly pairs registers (`stp` / `ldp` reach 504 bytes from a base, so
// each region is addressed from its own base) and uses `add` immediates of
// at most 4095.
const _: () = {
    assert!(off::GPR == 0);
    assert!(off::PC == 32 * 8 && off::PSTATE == off::PC + 8);
    assert!(off::FAR == off::ESR + 8 && off::HPFAR == off::FAR + 8);
    assert!(off::CNTV_CVAL == off::CNTV_CTL + 8);
    assert!(off::AP1R == off::AP0R + 4 * 8);
    assert!(off::GUEST % 8 == 0 && off::HOST_EL1 % 8 == 0);
    assert!(off::FP % 16 == 0 && off::HOST_FP % 16 == 0);
    assert!(off::FPCR + 8 + 8 == off::FP);
    assert!(off::HOST_ELR == off::HOST_EL1 + size_of::<El1>());
    assert!(off::HOST_HCR == off::HOST_ELR + 16);
    assert!(off::HOST_MDCR == off::HOST_HCR + 16);
    assert!(off::HOST_CNTHCTL == off::HOST_MDCR + 16);
    assert!(off::HOST_CNTV_CVAL == off::HOST_CNTHCTL + 16);
    assert!(off::HOST_FPCR == off::HOST_CNTV_CVAL + 16 && off::HOST_FPCR % 16 == 0);
    assert!(off::FPCR % 16 == 0);
    assert!(size_of::<El1>() == 36 * 8);
    assert!(size_of::<Block>() < 4096);
    assert!(size_of::<Block>() % 64 == 0);
};

/// CPU features the stub needs and Rust reads from the ID registers
/// ([`features_from_ids`]); `Block::feat`.
pub mod feat {
    /// Pointer authentication: the keys are swapped and the guest may use them.
    pub const PAUTH: u64 = 1 << 0;
    /// SVE: the guest's use of it traps (the host keeps its state).
    pub const SVE: u64 = 1 << 1;
    /// SME: likewise.
    pub const SME: u64 = 1 << 2;
}

/// `ID_AA64ISAR1_EL1`, `ID_AA64PFR0_EL1` and `ID_AA64PFR1_EL1` to [`feat`] bits.
pub const fn features_from_ids(isar1: u64, pfr0: u64, pfr1: u64) -> u64 {
    // APA [7:4], API [11:8]: address authentication; GPA [27:24], GPI [31:28]: generic.
    let pauth = (isar1 & 0xFF0) != 0 || (isar1 & 0xFF00_0000) != 0;
    let sve = (pfr0 >> 32) & 0xF != 0;
    let sme = (pfr1 >> 24) & 0xF != 0;
    (pauth as u64) * feat::PAUTH | (sve as u64) * feat::SVE | (sme as u64) * feat::SME
}

/// Does the CPU have the GICv3 system-register interface the stub and the
/// list-register model need (`ID_AA64PFR0_EL1.GIC` is 1 or more)? A GICv2
/// machine (GIC-400) injects through memory-mapped `GICH` registers instead,
/// which this does not drive: a guest is refused there.
pub const fn gic_v3_sysregs(pfr0: u64) -> bool {
    (pfr0 >> 24) & 0xF != 0
}

/// `HCR_EL2` bits.
pub mod hcr {
    /// Stage-2 translation.
    pub const VM: u64 = 1 << 0;
    /// Set/way cache maintenance is upgraded to clean + invalidate.
    pub const SWIO: u64 = 1 << 1;
    /// Physical FIQ, IRQ and SError are taken to EL2 while the guest runs.
    pub const FMO: u64 = 1 << 3;
    pub const IMO: u64 = 1 << 4;
    pub const AMO: u64 = 1 << 5;
    /// Barriers and TLB / cache maintenance of the guest are broadcast: a
    /// vCPU moves between CPUs, so its local operations cannot stay local.
    pub const FB: u64 = 1 << 9;
    /// Barrier-shareability upgrade: inner shareable.
    pub const BSU_IS: u64 = 1 << 10;
    /// `WFI` traps (the guest's idle is the host's to schedule).
    pub const TWI: u64 = 1 << 13;
    /// `SMC` traps (the guest's PSCI is emulated, never sent to the firmware).
    pub const TSC: u64 = 1 << 19;
    /// EL1 is AArch64.
    pub const RW: u64 = 1 << 31;
    /// Pointer-authentication key access and instructions do not trap.
    pub const APK: u64 = 1 << 40;
    pub const API: u64 = 1 << 41;

    /// The host: EL1 AArch64, nothing trapped, no stage 2
    /// (what `_azos_drop_to_el1` leaves).
    pub const HOST: u64 = RW;

    /// The guest's `HCR_EL2` on a CPU with `features` ([`super::feat`]).
    pub const fn guest(features: u64) -> u64 {
        let base = RW | VM | SWIO | FMO | IMO | AMO | FB | BSU_IS | TWI | TSC;
        if features & super::feat::PAUTH != 0 { base | APK | API } else { base }
    }
}

/// `CPTR_EL2` (E2H = 0): the RES1 bits the boot trampoline writes, and the
/// traps a guest runs under.
pub mod cptr {
    /// `_azos_drop_to_el1`'s value: RES1 bits only, nothing trapped.
    pub const HOST: u64 = 0x22FF;
    /// SVE and SME accesses trap: the host keeps no state for them.
    pub const TZ: u64 = 1 << 8;
    pub const TSM: u64 = 1 << 12;

    pub const fn guest(features: u64) -> u64 {
        let mut v = HOST;
        if features & super::feat::SVE != 0 {
            v |= TZ;
        }
        if features & super::feat::SME != 0 {
            v |= TSM;
        }
        v
    }
}

/// `MDCR_EL2` for a guest: every performance-monitor register traps, because
/// the cycle counter is the host's (the wcet and trace stamps read it) and a
/// guest's write to `PMCR_EL0` or `PMCNTENCLR_EL0` would stop it. The traps
/// are answered as a PMU with no counters ([`pmu_trap`]).
pub const MDCR_GUEST: u64 = (1 << 6) | (1 << 5);

/// `PSTATE` of a guest at its first instruction: EL1h, D A I F masked.
pub const PSTATE_EL1H_MASKED: u64 = 0x3C5;

/// `SCTLR_EL1` of a vCPU that has not run: the architecture's RES1 and
/// reserved bits, MMU and caches off (what the boot trampoline gives the host).
pub const SCTLR_EL1_RESET: u64 = 0x30C5_0838;

/// `CPACR_EL1` of a vCPU that has not run: FP and SIMD usable at EL1 and EL0.
pub const CPACR_EL1_RESET: u64 = 0x30_0000;

/// Everything the first entry of a vCPU needs.
#[derive(Copy, Clone, Debug)]
pub struct Start {
    /// The vCPU's index in its VM (its MPIDR, [`psci::mpidr_of`]).
    pub vcpu: u8,
    pub entry_pc: u64,
    pub entry_arg: u64,
    /// `VTTBR_EL2` and `VTCR_EL2` of the VM.
    pub vttbr: u64,
    pub vtcr: u64,
    /// The VM's `CNTVOFF_EL2`.
    pub cntvoff: u64,
    /// List registers and `ICH_VTR_EL2.PREbits` of the CPU interface.
    pub nlr: usize,
    pub prebits: u64,
    pub features: u64,
}

impl Block {
    /// Make this the block of a vCPU about to run for the first time: the
    /// registers the architecture resets, `x0` the boot argument, the PC the
    /// entry, and the controls of a guest ([`hcr::guest`], [`cptr::guest`],
    /// stage 2, the VM's clock offset, the vCPU's MPIDR).
    pub fn start(&mut self, s: &Start) {
        // SAFETY: every field is an integer or an array of them: all-zero is valid.
        unsafe { core::ptr::write_bytes(self as *mut Block, 0, 1) };
        self.gpr[0] = s.entry_arg;
        self.pc = s.entry_pc;
        self.pstate = PSTATE_EL1H_MASKED;
        self.guest.sctlr = SCTLR_EL1_RESET;
        self.guest.cpacr = CPACR_EL1_RESET;
        self.hcr = hcr::guest(s.features);
        self.vttbr = s.vttbr;
        self.vtcr = s.vtcr;
        self.vmpidr = psci::mpidr_of(s.vcpu as usize);
        self.cptr = cptr::guest(s.features);
        self.mdcr = MDCR_GUEST;
        self.cntvoff = s.cntvoff;
        self.cnthctl = Cnthctl::GUEST.bits();
        self.nlr = s.nlr.clamp(1, MAX_LRS) as u64;
        self.prebits = s.prebits;
        self.feat = s.features;
    }

    /// The answer to the device access the guest is waiting for: a load's
    /// value goes to its register, sign-extended and width-limited as the
    /// instruction asked (`ESR_EL2.ISS` of the access that stopped it, still
    /// in [`Block::esr`]), and the guest resumes after the instruction.
    pub fn complete(&mut self, done: MmioDone) {
        let a = done.access;
        if !a.write && a.reg < 31 {
            let iss = self.esr & 0x01FF_FFFF;
            let bits = a.size as u32 * 8;
            let mut v = done.value;
            if bits < 64 {
                v &= (1u64 << bits) - 1;
                // SSE (bit 21): sign-extend the loaded value.
                if iss & (1 << 21) != 0 && v & (1u64 << (bits - 1)) != 0 {
                    v |= !0u64 << bits;
                }
            }
            // SF (bit 15) clear: a `Wt` destination, whose upper half is zero.
            if iss & (1 << 15) == 0 {
                v &= 0xFFFF_FFFF;
            }
            self.gpr[a.reg as usize] = v;
        }
        self.pc = self.pc.wrapping_add(a.insn_len as u64);
    }

    /// Read the exit the stub recorded. `Step::Resume` is an exit this layer
    /// answered itself (the guest runs on at once); `Step::Report` is the
    /// exit for the monitor, with `mmio_value` set when it is a store.
    pub fn after_exit(&mut self, mmio_value: &mut u64) -> Step {
        let exit = decode_esr(self.esr, self.far, self.hpfar);
        match exit {
            Exit::Wait => {
                // `ELR_EL2` is the `WFI` itself: the guest resumes after it.
                self.pc = self.pc.wrapping_add(4);
                Step::Report(exit)
            }
            Exit::Mmio(a) => {
                if a.write {
                    let raw = if a.reg < 31 { self.gpr[a.reg as usize] } else { 0 };
                    *mmio_value = if a.size >= 8 { raw } else { raw & ((1u64 << (a.size as u32 * 8)) - 1) };
                }
                Step::Report(exit)
            }
            Exit::SysReg { .. } => match pmu_trap(self.esr) {
                Some(t) => {
                    if t.read && t.rt < 31 {
                        self.gpr[t.rt as usize] = 0;
                    }
                    self.pc = self.pc.wrapping_add(4);
                    Step::Resume
                }
                None => Step::Report(exit),
            },
            _ => Step::Report(exit),
        }
    }

    /// Is the last exit a physical interrupt (`RAW_ARM_IRQ`)?
    pub fn exit_was_irq(&self) -> bool {
        self.esr == RAW_ARM_IRQ
    }
}

/// What the layer above does with an exit.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Step {
    /// Answered here: enter again.
    Resume,
    /// For the monitor.
    Report(Exit),
}

/// A trapped `MRS` / `MSR` (`ESR_EL2.EC` 0x18) decoded.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SysregTrap {
    pub op0: u8,
    pub op1: u8,
    pub crn: u8,
    pub crm: u8,
    pub op2: u8,
    pub rt: u8,
    /// `MRS`: the guest reads the register.
    pub read: bool,
}

/// Decode the ISS of a trapped system-register access.
pub const fn sysreg_trap(esr: u64) -> Option<SysregTrap> {
    if (esr >> 26) & 0x3F != 0x18 {
        return None;
    }
    let iss = esr & 0x01FF_FFFF;
    Some(SysregTrap {
        op0: ((iss >> 20) & 3) as u8,
        op2: ((iss >> 17) & 7) as u8,
        op1: ((iss >> 14) & 7) as u8,
        crn: ((iss >> 10) & 0xF) as u8,
        rt: ((iss >> 5) & 0x1F) as u8,
        crm: ((iss >> 1) & 0xF) as u8,
        read: iss & 1 != 0,
    })
}

/// A trapped access to a performance-monitor register ([`MDCR_GUEST`]):
/// `PMCR_EL0` .. `PMOVSSET_EL0` (`CRn` 9, `CRm` 12..14, `Op1` 3, and the
/// `EL1` interrupt-enable pair and `PMMIR_EL1` at `Op1` 0), `PMEVCNTR<n>_EL0`
/// / `PMEVTYPER<n>_EL0` / `PMCCFILTR_EL0` (`CRn` 14, `CRm` 8..15). The
/// guest sees a PMU with no counters: reads zero, writes are dropped.
pub const fn pmu_trap(esr: u64) -> Option<SysregTrap> {
    let Some(t) = sysreg_trap(esr) else { return None };
    if t.op0 != 3 {
        return None;
    }
    let pm_block = t.crn == 9 && t.crm >= 12 && t.crm <= 14 && (t.op1 == 3 || t.op1 == 0);
    let pm_events = t.crn == 14 && t.op1 == 3 && t.crm >= 8;
    if pm_block || pm_events { Some(t) } else { None }
}

/// The `ESR_EL2` of an `HVC` / `SMC`: which of the two stopped the guest
/// (`SMC` leaves `ELR_EL2` on the instruction, `HVC` after it).
pub const fn is_smc(esr: u64) -> bool {
    (esr >> 26) & 0x3F == 0x17
}

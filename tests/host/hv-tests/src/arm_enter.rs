// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The aarch64 guest entry (`ext/hv/world.rs`, `serve.rs`, the stub's HVC
//! table): the block the world switch reads and writes, what an exit becomes,
//! the traps a guest runs under, and the guest's PSCI as the vCPU loop serves it.
//!
//! WHY. The assembly of the stub cannot run on the host, so everything it is
//! told or tells back is pinned here: a block offset one word off loads the
//! wrong register into the guest, a missing `HCR_EL2` trap lets the guest's
//! `SMC` reach the firmware, a load that is not sign-extended hands a driver
//! a wrong register value, a performance-counter access that is not answered
//! stops the host's cycle counter. QEMU with `virtualization=on` is the
//! testing week's (S6); until then these are the only check.

use azos_arch_api::{
    Exit, HypercallHost, HypercallOutcome, MmioAccess, MmioDone, RemoteFence, StageAccess, VcpuStartError, RAW_ARM_IRQ,
};

use crate::glue::arm::psci::{func, index_of, mpidr_of, ret};
use crate::glue::arm::serve;
use crate::glue::arm::world::{self, cptr, feat, hcr, Block, Start, Step};
use crate::glue::arm::{classify_hvc, HvcClass, HVC_ENTER, HVC_FLUSH, HVC_INFO, HVC_PROBE};

fn block() -> Box<Block> {
    // SAFETY: a `Block` is integers: all-zero is a valid one.
    Box::new(unsafe { core::mem::zeroed() })
}

const EC_WFX: u64 = 0x01;
const EC_HVC: u64 = 0x16;
const EC_SMC: u64 = 0x17;
const EC_SYSREG: u64 = 0x18;
const EC_IABT: u64 = 0x20;
const EC_DABT: u64 = 0x24;

fn esr(ec: u64, iss: u64) -> u64 {
    ec << 26 | 1 << 25 | iss
}

/// A data abort at stage 2 with a valid syndrome: `size_log2`, the register,
/// store or load, sign-extend, 64-bit register.
fn dabt(size_log2: u64, reg: u64, write: bool, sse: bool, sf: bool) -> u64 {
    esr(
        EC_DABT,
        1 << 24 | size_log2 << 22 | (sse as u64) << 21 | reg << 16 | (sf as u64) << 15 | (write as u64) << 6 | 0x07,
    )
}

/// A trapped `MRS` / `MSR`.
fn sysreg(op0: u64, op1: u64, crn: u64, crm: u64, op2: u64, rt: u64, read: bool) -> u64 {
    esr(EC_SYSREG, op0 << 20 | op2 << 17 | op1 << 14 | crn << 10 | rt << 5 | crm << 1 | read as u64)
}

// ── the stub's HVC table ────────────────────────────────────────────────

#[test]
fn the_stub_answers_four_calls_of_its_service_and_nothing_between() {
    assert_eq!(classify_hvc(HVC_PROBE), HvcClass::Probe);
    assert_eq!(classify_hvc(HVC_ENTER), HvcClass::Enter);
    assert_eq!(classify_hvc(HVC_FLUSH), HvcClass::Flush);
    assert_eq!(classify_hvc(HVC_INFO), HvcClass::Info);
    // The numbers the old table pinned as unsupported stay so, as do the next ones.
    for n in (1..0x10).chain(0x13..0x20) {
        assert_eq!(classify_hvc(0x8600_0000 + n), HvcClass::Unsupported, "function {n:#x}");
    }
    // The same numbers of the other service owners and calling conventions.
    for fid in [0xC600_0010u32, 0x8400_0010, 0x0600_0010, 0x8700_0010] {
        assert_ne!(classify_hvc(fid), HvcClass::Enter, "{fid:#x}");
    }
}

// ── the CPU, from its ID registers ──────────────────────────────────────

#[test]
fn features_come_from_their_own_fields() {
    assert_eq!(world::features_from_ids(0, 0, 0), 0);
    // APA (bit 4), API (bit 8), GPA (bit 24), GPI (bit 28): any of the four.
    for isar1 in [1u64 << 4, 1 << 8, 1 << 24, 1 << 28] {
        assert_eq!(world::features_from_ids(isar1, 0, 0), feat::PAUTH, "{isar1:#x}");
    }
    // Neighbouring fields do not count (DPB at bit 0, LRCPC at 20, FRINTTS at 32).
    assert_eq!(world::features_from_ids(1 | 1 << 20 | 1 << 32, 0, 0), 0);
    assert_eq!(world::features_from_ids(0, 1 << 32, 0), feat::SVE);
    assert_eq!(world::features_from_ids(0, 0, 1 << 24), feat::SME);
    assert_eq!(world::features_from_ids(1 << 4, 1 << 32, 1 << 24), feat::PAUTH | feat::SVE | feat::SME);
}

#[test]
fn a_gic_without_the_system_register_interface_refuses_the_guest() {
    assert!(world::gic_v3_sysregs(1 << 24));
    assert!(world::gic_v3_sysregs(3 << 24));
    assert!(!world::gic_v3_sysregs(0));
    // ID_AA64PFR0_EL1 fields next to GIC (bits 27:24) do not count.
    assert!(!world::gic_v3_sysregs(0xF << 20 | 0xF << 28));
}

#[test]
fn off_target_there_is_no_el2_to_enter() {
    use azos_arch_api::{GuestCtx, Hypervisor, Stage2Root};
    let hv = crate::glue::arm::HvImpl;
    assert!(!hv.can_enter());
    let mut ctx = GuestCtx::new(Stage2Root { root: 0x8000, aux: 40 }, 1, 0, 0x4000_0000, 0);
    assert_eq!(hv.enter(&mut ctx), Exit::InvalidState);
    hv.stage2_flush(1);
}

// ── HCR_EL2, CPTR_EL2 ───────────────────────────────────────────────────

#[test]
fn a_guest_runs_under_the_traps_that_keep_it_off_the_host() {
    let g = hcr::guest(0);
    // Stage 2 on, EL1 AArch64, the physical interrupts come to EL2.
    for (bit, name) in [(hcr::VM, "VM"), (hcr::RW, "RW"), (hcr::IMO, "IMO"), (hcr::FMO, "FMO"), (hcr::AMO, "AMO")] {
        assert_ne!(g & bit, 0, "{name}");
    }
    // The guest's SMC (PSCI) is emulated, never sent to the firmware, and its WFI is the host's to schedule.
    assert_ne!(g & hcr::TSC, 0, "TSC");
    assert_ne!(g & hcr::TWI, 0, "TWI");
    // Its barriers and maintenance reach the CPUs it is not on.
    assert_ne!(g & hcr::FB, 0, "FB");
    assert_eq!(g & (hcr::APK | hcr::API), 0, "no pointer authentication on a CPU without it");
    // Never E2H or TGE: the host's EL1 is not folded into EL2.
    assert_eq!(g & (1 << 34 | 1 << 27), 0);
    assert_eq!(hcr::guest(feat::PAUTH) & (hcr::APK | hcr::API), hcr::APK | hcr::API);
    assert_eq!(hcr::HOST, 1 << 31, "what the boot trampoline leaves");
}

#[test]
fn only_the_state_the_host_does_not_keep_traps_in_cptr() {
    assert_eq!(cptr::guest(0), cptr::HOST);
    assert_eq!(cptr::guest(feat::SVE), cptr::HOST | 1 << 8);
    assert_eq!(cptr::guest(feat::SME), cptr::HOST | 1 << 12);
    // FP and SIMD are switched by the stub, so they never trap to EL2.
    assert_eq!(cptr::guest(feat::SVE | feat::SME) & (1 << 10), 0);
    assert_eq!(cptr::HOST, 0x22FF);
}

// ── the first entry ─────────────────────────────────────────────────────

fn start_args(vcpu: u8, features: u64) -> Start {
    Start {
        vcpu,
        entry_pc: 0x4008_0000,
        entry_arg: 0x4800_0000,
        vttbr: 0x0001_0000_0000_8000,
        vtcr: 0x8002_3558,
        cntvoff: 12345,
        nlr: 4,
        prebits: 4,
        features,
    }
}

#[test]
fn a_vcpu_starts_where_the_monitor_says_with_the_boot_argument_in_x0() {
    let mut b = block();
    b.gpr[7] = 99; // a stale block
    b.start(&start_args(0, 0));
    assert_eq!(b.pc, 0x4008_0000);
    assert_eq!(b.gpr[0], 0x4800_0000);
    assert!(b.gpr[1..].iter().all(|&x| x == 0));
    assert_eq!(b.pstate, 0x3C5, "EL1h, D A I F masked");
    assert_eq!((b.vttbr, b.vtcr, b.cntvoff), (0x0001_0000_0000_8000, 0x8002_3558, 12345));
    assert_eq!(b.hcr, hcr::guest(0));
    assert_eq!(b.cptr, cptr::HOST);
    assert_eq!(b.cnthctl, 0, "the guest has no physical counter or timer");
    assert_eq!(b.nlr, 4);
    // The MMU and caches are off, FP is usable at EL1 and EL0.
    assert_eq!(b.guest.sctlr & 1, 0);
    assert_eq!(b.guest.cpacr >> 20 & 3, 3);
}

#[test]
fn the_mpidr_is_the_one_the_guests_psci_names() {
    for v in 0..4u8 {
        let mut b = block();
        b.start(&start_args(v, 0));
        assert_eq!(b.vmpidr, mpidr_of(v as usize));
        assert_eq!(index_of(b.vmpidr, 4), Some(v as usize));
    }
}

#[test]
fn the_list_registers_are_clamped_to_what_there_are() {
    let mut b = block();
    let mut s = start_args(0, 0);
    s.nlr = 0;
    b.start(&s);
    assert_eq!(b.nlr, 1);
    s.nlr = 99;
    b.start(&s);
    assert_eq!(b.nlr, 16);
}

// ── the answer to an emulated device access ─────────────────────────────

fn done(size: u8, reg: u8, write: bool, value: u64) -> MmioDone {
    MmioDone { access: MmioAccess { gpa: 0x900_0000, size, write, reg, insn_len: 4 }, value }
}

fn with_exit(esr: u64) -> Box<Block> {
    let mut b = block();
    b.start(&start_args(0, 0));
    b.pc = 0x4008_1000;
    b.esr = esr;
    b
}

#[test]
fn a_load_reaches_its_register_and_the_guest_steps_past_it() {
    let mut b = with_exit(dabt(2, 3, false, false, false));
    b.gpr[3] = u64::MAX;
    b.complete(done(4, 3, false, 0xDEAD_BEEF));
    assert_eq!(b.gpr[3], 0xDEAD_BEEF, "a W register: the upper half is zero");
    assert_eq!(b.pc, 0x4008_1004);
}

#[test]
fn a_sign_extending_load_extends_to_the_width_of_its_register() {
    // LDRSB Xt: 0x80 -> all ones above bit 7.
    let mut b = with_exit(dabt(0, 5, false, true, true));
    b.complete(done(1, 5, false, 0x80));
    assert_eq!(b.gpr[5], 0xFFFF_FFFF_FFFF_FF80);
    // LDRSB Wt: extended into the W register only.
    let mut b = with_exit(dabt(0, 5, false, true, false));
    b.complete(done(1, 5, false, 0x80));
    assert_eq!(b.gpr[5], 0xFFFF_FF80);
    // A positive value is not extended.
    let mut b = with_exit(dabt(0, 5, false, true, true));
    b.complete(done(1, 5, false, 0x7F));
    assert_eq!(b.gpr[5], 0x7F);
    // LDRSW Xt.
    let mut b = with_exit(dabt(2, 5, false, true, true));
    b.complete(done(4, 5, false, 0x8000_0000));
    assert_eq!(b.gpr[5], 0xFFFF_FFFF_8000_0000);
    // A 64-bit load is as it is.
    let mut b = with_exit(dabt(3, 5, false, false, true));
    b.complete(done(8, 5, false, 0x1122_3344_5566_7788));
    assert_eq!(b.gpr[5], 0x1122_3344_5566_7788);
}

#[test]
fn a_load_into_xzr_and_a_store_change_no_register() {
    let mut b = with_exit(dabt(2, 31, false, false, false));
    let before = b.gpr;
    b.complete(done(4, 31, false, 0xFFFF_FFFF));
    assert_eq!(b.gpr, before, "x31 is the zero register");
    assert_eq!(b.pc, 0x4008_1004);
    let mut b = with_exit(dabt(2, 3, true, false, false));
    b.gpr[3] = 7;
    b.complete(done(4, 3, true, 0));
    assert_eq!(b.gpr[3], 7);
    assert_eq!(b.pc, 0x4008_1004);
}

// ── what an exit becomes ────────────────────────────────────────────────

fn step(b: &mut Block) -> (Step, u64) {
    let mut v = 0xAAAA;
    let s = b.after_exit(&mut v);
    (s, v)
}

#[test]
fn a_store_hands_its_register_to_the_device_model_at_the_width_of_the_access() {
    let mut b = with_exit(dabt(1, 3, true, false, false));
    b.far = 0x0000_0000_0000_0010;
    b.hpfar = 0x9000 << 4;
    b.gpr[3] = 0x1122_3344_5566_7788;
    let (s, v) = step(&mut b);
    match s {
        Step::Report(Exit::Mmio(a)) => {
            assert!(a.write);
            assert_eq!((a.size, a.reg, a.insn_len), (2, 3, 4));
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(v, 0x7788, "two bytes of it");
    assert_eq!(b.pc, 0x4008_1000, "the instruction is stepped over when the answer is applied, not before");
    // Register 31 stores zero.
    let mut b = with_exit(dabt(3, 31, true, false, true));
    assert!(matches!(step(&mut b), (Step::Report(Exit::Mmio(_)), 0)));
}

#[test]
fn a_load_leaves_the_value_slot_alone() {
    let mut b = with_exit(dabt(2, 3, false, false, false));
    let (s, v) = step(&mut b);
    assert!(matches!(s, Step::Report(Exit::Mmio(a)) if !a.write));
    assert_eq!(v, 0xAAAA);
}

#[test]
fn wfi_is_reported_and_stepped_over() {
    let mut b = with_exit(esr(EC_WFX, 0));
    assert_eq!(step(&mut b).0, Step::Report(Exit::Wait));
    assert_eq!(b.pc, 0x4008_1004, "ELR_EL2 is the WFI itself");
}

#[test]
fn a_physical_interrupt_is_the_hosts_and_moves_nothing() {
    let mut b = with_exit(RAW_ARM_IRQ);
    assert!(b.exit_was_irq());
    assert_eq!(step(&mut b).0, Step::Report(Exit::HostInterrupt));
    assert_eq!(b.pc, 0x4008_1000);
    assert!(!with_exit(esr(EC_HVC, 0)).exit_was_irq());
}

#[test]
fn hvc_and_smc_are_hypercalls_whose_pc_the_serving_side_owns() {
    for ec in [EC_HVC, EC_SMC] {
        let mut b = with_exit(esr(ec, 0));
        assert_eq!(step(&mut b).0, Step::Report(Exit::Hypercall));
        assert_eq!(b.pc, 0x4008_1000);
    }
}

#[test]
fn a_stage_2_instruction_abort_is_an_exec_fault() {
    let mut b = with_exit(esr(EC_IABT, 0x07));
    b.far = 0xABC;
    b.hpfar = 0x4008_1 << 4;
    assert_eq!(
        step(&mut b).0,
        Step::Report(Exit::Fault { gpa: 0x4008_1ABC, access: StageAccess::Exec })
    );
}

#[test]
fn performance_monitor_registers_read_as_a_pmu_with_no_counters() {
    // MRS x5, PMCCNTR_EL0 (3,3,9,13,0).
    let mut b = with_exit(sysreg(3, 3, 9, 13, 0, 5, true));
    b.gpr[5] = 0x1234;
    assert_eq!(step(&mut b).0, Step::Resume);
    assert_eq!(b.gpr[5], 0, "reads zero");
    assert_eq!(b.pc, 0x4008_1004);
    // MSR PMCR_EL0, x2 (3,3,9,12,0): dropped.
    let mut b = with_exit(sysreg(3, 3, 9, 12, 0, 2, false));
    b.gpr[2] = 0x77;
    assert_eq!(step(&mut b).0, Step::Resume);
    assert_eq!(b.gpr[2], 0x77);
    assert_eq!(b.pc, 0x4008_1004);
    // MRS xzr: no register written.
    let mut b = with_exit(sysreg(3, 3, 9, 12, 0, 31, true));
    let before = b.gpr;
    assert_eq!(step(&mut b).0, Step::Resume);
    assert_eq!(b.gpr, before);
}

#[test]
fn every_performance_monitor_register_is_that_and_nothing_else_is() {
    let pmu = [
        (3, 3, 9, 12, 0), // PMCR_EL0
        (3, 3, 9, 12, 7), // PMCEID1_EL0
        (3, 3, 9, 13, 2), // PMXEVCNTR_EL0
        (3, 3, 9, 14, 0), // PMUSERENR_EL0
        (3, 3, 9, 14, 3), // PMOVSSET_EL0
        (3, 0, 9, 14, 1), // PMINTENSET_EL1
        (3, 0, 9, 14, 6), // PMMIR_EL1
        (3, 3, 14, 8, 0), // PMEVCNTR0_EL0
        (3, 3, 14, 11, 7), // PMEVCNTR31_EL0
        (3, 3, 14, 12, 0), // PMEVTYPER0_EL0
        (3, 3, 14, 15, 7), // PMCCFILTR_EL0
    ];
    for (op0, op1, crn, crm, op2) in pmu {
        assert!(world::pmu_trap(sysreg(op0, op1, crn, crm, op2, 1, true)).is_some(), "{op0} {op1} C{crn} C{crm} {op2}");
    }
    let other = [
        (3, 3, 14, 0, 1), // CNTPCT_EL0: the physical count traps for a guest
        (3, 3, 14, 2, 0), // CNTP_TVAL_EL0
        (3, 3, 9, 15, 0), // not in the performance-monitor block
        (3, 3, 9, 11, 0),
        (3, 0, 12, 12, 5), // ICC_SGI1R_EL1-ish (CRn 12)
        (3, 0, 1, 0, 0),   // SCTLR_EL1
        (2, 3, 9, 12, 0),  // op0 != 3
    ];
    for (op0, op1, crn, crm, op2) in other {
        assert!(world::pmu_trap(sysreg(op0, op1, crn, crm, op2, 1, true)).is_none(), "{op0} {op1} C{crn} C{crm} {op2}");
    }
    // Not a system-register trap at all.
    assert!(world::pmu_trap(esr(EC_HVC, 0)).is_none());
}

#[test]
fn any_other_system_register_is_for_the_monitor() {
    // MSR CNTP_CTL_EL0 (3,3,14,2,1).
    let mut b = with_exit(sysreg(3, 3, 14, 2, 1, 4, false));
    assert_eq!(step(&mut b).0, Step::Report(Exit::SysReg { write: true }));
    assert_eq!(b.pc, 0x4008_1000);
}

// ── the guest's PSCI, served ────────────────────────────────────────────

#[derive(Default)]
struct Vm {
    running: Vec<bool>,
    started: Vec<(usize, u64, u64)>,
    refuse: Option<VcpuStartError>,
}

impl Vm {
    fn of(n: usize) -> Vm {
        let mut running = vec![false; n];
        running[0] = true;
        Vm { running, ..Default::default() }
    }
}

impl HypercallHost for Vm {
    fn vcpus(&self) -> usize {
        self.running.len()
    }
    fn vcpu_running(&self, vcpu: usize) -> bool {
        self.running.get(vcpu).copied().unwrap_or(false)
    }
    fn start_vcpu(&mut self, vcpu: usize, pc: u64, arg: u64) -> Result<(), VcpuStartError> {
        if let Some(e) = self.refuse {
            return Err(e);
        }
        self.started.push((vcpu, pc, arg));
        self.running[vcpu] = true;
        Ok(())
    }
    fn raise_irq(&mut self, _vcpu: usize, _line: u32) {}
    fn arm_timer(&mut self, _vcpu: usize, _deadline: u64, _line: u32) {}
    fn fence(&mut self, _vcpu: usize, _fence: RemoteFence) {}
}

fn call(vm: &mut Vm, ec: u64, vcpu: usize, regs: [u64; 4]) -> (HypercallOutcome, [u64; 32], u64) {
    let mut gpr = [0u64; 32];
    gpr[..4].copy_from_slice(&regs);
    let mut pc = 0x4000_2000u64;
    let o = serve::hypercall(&mut gpr, &mut pc, esr(ec, 0), vcpu, vm);
    (o, gpr, pc)
}

#[test]
fn psci_version_is_answered_in_x0_and_an_hvc_returns_after_itself() {
    let mut vm = Vm::of(1);
    let (o, gpr, pc) = call(&mut vm, EC_HVC, 0, [0x8400_0000 | func::VERSION as u64, 5, 6, 7]);
    assert_eq!(o, HypercallOutcome::Served);
    assert_eq!(gpr[0], 0x0001_0001);
    assert_eq!(&gpr[1..4], &[5, 6, 7], "the other argument registers are left alone");
    assert_eq!(pc, 0x4000_2000, "ELR_EL2 of an HVC is already the next instruction");
}

#[test]
fn an_smc_is_stepped_over_because_its_elr_is_the_smc() {
    let mut vm = Vm::of(1);
    let (o, gpr, pc) = call(&mut vm, EC_SMC, 0, [0x8400_0000 | func::VERSION as u64, 0, 0, 0]);
    assert_eq!(o, HypercallOutcome::Served);
    assert_eq!(gpr[0], 0x0001_0001);
    assert_eq!(pc, 0x4000_2004);
}

#[test]
fn a_call_from_anything_but_hvc_or_smc_is_not_served() {
    let mut vm = Vm::of(1);
    for ec in [EC_WFX, EC_SYSREG, EC_DABT] {
        let (o, gpr, pc) = call(&mut vm, ec, 0, [0x8400_0000, 0, 0, 0]);
        assert_eq!(o, HypercallOutcome::Unserved, "ec {ec:#x}");
        assert_eq!(gpr[0], 0x8400_0000);
        assert_eq!(pc, 0x4000_2000);
    }
}

#[test]
fn cpu_on_starts_the_vcpu_the_mpidr_names_at_the_entry_with_the_context() {
    let mut vm = Vm::of(4);
    let (o, gpr, _) = call(&mut vm, EC_HVC, 0, [0xC400_0000 | func::CPU_ON as u64, mpidr_of(2), 0x4010_0000, 0xC0FFEE]);
    assert_eq!(o, HypercallOutcome::Served);
    assert_eq!(gpr[0], 0, "SUCCESS");
    assert_eq!(vm.started, vec![(2, 0x4010_0000, 0xC0FFEE)]);
}

#[test]
fn cpu_on_of_a_vcpu_that_runs_is_already_on_and_starts_nothing() {
    let mut vm = Vm::of(2);
    vm.running[1] = true;
    let (_, gpr, _) = call(&mut vm, EC_HVC, 0, [0xC400_0003, mpidr_of(1), 0x4010_0000, 0]);
    assert_eq!(gpr[0] as i64, ret::ALREADY_ON as i64);
    assert!(vm.started.is_empty());
}

#[test]
fn a_start_the_monitor_refuses_is_the_psci_code_for_it_in_the_width_of_the_call() {
    for (err, want) in [
        (VcpuStartError::BadAddress, ret::INVALID_ADDRESS),
        (VcpuStartError::AlreadyRunning, ret::ALREADY_ON),
        (VcpuStartError::Failed, ret::INTERNAL_FAILURE),
    ] {
        let mut vm = Vm::of(2);
        vm.refuse = Some(err);
        // SMC64: int64 in x0.
        let (o, gpr, _) = call(&mut vm, EC_HVC, 0, [0xC400_0003, mpidr_of(1), 0x4010_0000, 0]);
        assert_eq!(o, HypercallOutcome::Served);
        assert_eq!(gpr[0], want as i64 as u64, "{err:?}");
        // SMC32: int32 in w0, the upper half zero.
        let (_, gpr, _) = call(&mut vm, EC_HVC, 0, [0x8400_0003, mpidr_of(1), 0x4010_0000, 0]);
        assert_eq!(gpr[0], want as u32 as u64, "{err:?} (32-bit)");
    }
}

#[test]
fn cpu_off_ends_the_vcpu_and_system_calls_end_the_machine() {
    let mut vm = Vm::of(2);
    assert_eq!(call(&mut vm, EC_HVC, 0, [0x8400_0002, 0, 0, 0]).0, HypercallOutcome::StopVcpu);
    assert_eq!(
        call(&mut vm, EC_HVC, 0, [0x8400_0008, 0, 0, 0]).0,
        HypercallOutcome::EndGuest { kind: 0, reason: 0 }
    );
    assert_eq!(
        call(&mut vm, EC_HVC, 0, [0x8400_0009, 0, 0, 0]).0,
        HypercallOutcome::EndGuest { kind: 1, reason: 0 }
    );
}

#[test]
fn cpu_off_is_the_callers_own_even_when_the_monitors_view_lags() {
    // The caller is always On; CPU_OFF takes no target.
    let mut vm = Vm::of(2);
    vm.running[0] = false; // the monitor's view lags: the caller still counts as on
    assert_eq!(call(&mut vm, EC_HVC, 0, [0x8400_0002, 0, 0, 0]).0, HypercallOutcome::StopVcpu);
}

#[test]
fn affinity_info_follows_the_threads_of_the_vm() {
    let mut vm = Vm::of(2);
    let (_, gpr, _) = call(&mut vm, EC_HVC, 0, [0xC400_0004, mpidr_of(1), 0, 0]);
    assert_eq!(gpr[0], 1, "OFF");
    vm.running[1] = true;
    let (_, gpr, _) = call(&mut vm, EC_HVC, 0, [0xC400_0004, mpidr_of(1), 0, 0]);
    assert_eq!(gpr[0], 0, "ON");
}

#[test]
fn a_standby_suspend_returns_and_a_power_down_one_is_refused() {
    let mut vm = Vm::of(1);
    let (o, gpr, _) = call(&mut vm, EC_HVC, 0, [0xC400_0001, 0, 0x4010_0000, 0]);
    assert_eq!((o, gpr[0]), (HypercallOutcome::Served, 0));
    let (o, gpr, _) = call(&mut vm, EC_HVC, 0, [0xC400_0001, 1 << 16, 0x4010_0000, 0]);
    assert_eq!((o, gpr[0] as i64), (HypercallOutcome::Served, ret::INVALID_PARAMETERS as i64));
}

#[test]
fn what_psci_does_not_answer_is_not_supported_and_still_served() {
    let mut vm = Vm::of(1);
    let (o, gpr, _) = call(&mut vm, EC_HVC, 0, [0x8400_0020, 0, 0, 0]);
    assert_eq!((o, gpr[0] as u32 as i32), (HypercallOutcome::Served, ret::NOT_SUPPORTED));
    // A Linux guest probes for SMCCC first.
    let (_, gpr, _) = call(&mut vm, EC_SMC, 0, [0x8000_0000, 0, 0, 0]);
    assert_eq!(gpr[0], 0x0001_0001);
}

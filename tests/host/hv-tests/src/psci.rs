// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! A guest's PSCI/SMCCC on aarch64 (`ext/hv/psci.rs`) over a set of vCPUs, and
//! the interrupts into it (`ext/hv/inject.rs`): the virtual timer's PPI and
//! the monitor's device lines through the list registers.
//!
//! WHY. A guest PSCI call that reached the firmware would power host CPUs
//! (`SYSTEM_OFF`: the machine) on behalf of a guest that owns only virtual
//! ones; a wrong return code makes Linux give up on a secondary CPU without
//! a message; a timer PPI listed twice, or taken back after the guest took
//! it, is a lost or spurious tick. No guest runs on aarch64 before the
//! guest-boot step, so these are the only check until then.

use crate::glue::arm::inject::{self, GuestIrq, TimerRegs, GUEST_PRIO, LINES, SPI_BASE};
use crate::glue::arm::psci::{self, affinity, func, ret, CpuSet, CpuState, Effect, Reply};
use crate::glue::arm::vgic::{lr_group1, lr_hw, lr_priority, lr_state, lr_vintid, LrState, VgicCpu, QUEUE_CAP};
use crate::glue::arm::vtimer::{cntvoff_on_resume, virtual_count, Vtimer, VTIMER_PPI};
use crate::glue::arm::{classify_hvc, HvcClass};

const fn f32_(num: u32) -> u32 {
    0x8400_0000 | num
}
const fn f64_(num: u32) -> u32 {
    0xC400_0000 | num
}

fn r32(c: i32) -> u64 {
    c as u32 as u64
}
fn r64(c: i32) -> u64 {
    c as i64 as u64
}

/// A VM of `n` vCPUs with vCPU 0 running, as the monitor leaves it.
fn vm(n: usize) -> CpuSet {
    let mut s = CpuSet::new(n);
    s.boot(0);
    s
}

fn call(s: &mut CpuSet, caller: usize, fid: u32, x: [u64; 3]) -> Reply {
    psci::call(s, caller, fid, x)
}

fn x0(s: &mut CpuSet, fid: u32, x: [u64; 3]) -> u64 {
    call(s, 0, fid, x).x0
}

// ── PSCI ────────────────────────────────────────────────────────────────

#[test]
fn version_and_the_discovery_calls_answer_without_touching_the_set() {
    let mut s = vm(2);
    assert_eq!(call(&mut s, 0, f32_(func::VERSION), [0; 3]), Reply { x0: 0x0001_0001, effect: Effect::None });
    assert_eq!(x0(&mut s, psci::SMCCC_VERSION, [0; 3]), 0x0001_0001);
    // MIGRATE_INFO_TYPE: no Trusted OS to migrate.
    assert_eq!(x0(&mut s, f32_(func::MIGRATE_INFO_TYPE), [0; 3]), 2);
    assert_eq!((s.state(0), s.state(1)), (Some(CpuState::On), Some(CpuState::Off)));
}

#[test]
fn features_say_yes_only_to_what_is_answered() {
    let mut s = vm(2);
    let q = |s: &mut CpuSet, fid: u32| x0(s, f32_(func::FEATURES), [fid as u64, 0, 0]);
    for f in [
        f32_(func::VERSION),
        f32_(func::CPU_SUSPEND),
        f64_(func::CPU_SUSPEND),
        f32_(func::CPU_OFF),
        f32_(func::CPU_ON),
        f64_(func::CPU_ON),
        f32_(func::AFFINITY_INFO),
        f64_(func::AFFINITY_INFO),
        f32_(func::MIGRATE_INFO_TYPE),
        f32_(func::SYSTEM_OFF),
        f32_(func::SYSTEM_RESET),
        f32_(func::FEATURES),
        psci::SMCCC_VERSION,
    ] {
        assert_eq!(q(&mut s, f), 0, "{f:#x}");
    }
    for f in [
        f32_(5),          // MIGRATE
        f32_(7),          // MIGRATE_INFO_UP_CPU
        f32_(0x0E),       // SYSTEM_SUSPEND
        f32_(0x12),       // SYSTEM_RESET2
        f64_(func::CPU_OFF), // there is no SMC64 CPU_OFF
        f64_(func::SYSTEM_OFF),
        psci::SMCCC_ARCH_FEATURES,
        0x8000_8000, // SMCCC_ARCH_WORKAROUND_1
        0x8600_0000, // the host stub's probe: not a guest service
        0x0400_0003, // a slow call
    ] {
        assert_eq!(q(&mut s, f), r32(ret::NOT_SUPPORTED), "{f:#x}");
    }
}

#[test]
fn smccc_arch_features_names_the_two_arch_calls_it_has() {
    let mut s = vm(1);
    let q = |s: &mut CpuSet, fid: u32| x0(s, psci::SMCCC_ARCH_FEATURES, [fid as u64, 0, 0]);
    assert_eq!(q(&mut s, psci::SMCCC_VERSION), 0);
    assert_eq!(q(&mut s, psci::SMCCC_ARCH_FEATURES), 0);
    assert_eq!(q(&mut s, 0x8000_8000), r32(ret::NOT_SUPPORTED));
    assert_eq!(q(&mut s, 0x8000_7FFF), r32(ret::NOT_SUPPORTED));
    assert_eq!(q(&mut s, f32_(func::CPU_ON)), r32(ret::NOT_SUPPORTED));
}

#[test]
fn what_is_not_a_supported_fast_call_is_not_supported_in_the_callers_width() {
    let mut s = vm(1);
    // Unknown owner, slow call, must-be-zero bits set, owner 4 function >= 32, SMC64 arch call.
    assert_eq!(x0(&mut s, 0x8100_0000, [0; 3]), r32(ret::NOT_SUPPORTED));
    assert_eq!(x0(&mut s, 0x0400_0000, [0; 3]), r32(ret::NOT_SUPPORTED));
    assert_eq!(x0(&mut s, 0x8401_0000, [0; 3]), r32(ret::NOT_SUPPORTED));
    assert_eq!(x0(&mut s, 0x8400_0020, [0; 3]), r32(ret::NOT_SUPPORTED));
    assert_eq!(x0(&mut s, 0xC000_0000, [0; 3]), r64(ret::NOT_SUPPORTED));
    assert_eq!(x0(&mut s, 0xC100_0000, [0; 3]), r64(ret::NOT_SUPPORTED));
    // Implemented functions that PSCI 1.1 has no use for here.
    assert_eq!(x0(&mut s, f32_(5), [0; 3]), r32(ret::NOT_SUPPORTED));
    assert_eq!(x0(&mut s, f64_(5), [0; 3]), r64(ret::NOT_SUPPORTED));
    assert_eq!(x0(&mut s, f64_(func::CPU_OFF), [0; 3]), r64(ret::NOT_SUPPORTED));
    assert_eq!(s.state(0), Some(CpuState::On), "an unsupported call changes nothing");
}

#[test]
fn cpu_on_starts_the_target_at_the_entry_with_the_context_id() {
    let mut s = vm(4);
    let r = call(&mut s, 0, f64_(func::CPU_ON), [psci::mpidr_of(2), 0x4008_0000, 0xDEAD_BEEF_0000_0001]);
    assert_eq!(r, Reply { x0: 0, effect: Effect::Start { index: 2, entry: 0x4008_0000, context: 0xDEAD_BEEF_0000_0001 } });
    assert_eq!(s.state(2), Some(CpuState::OnPending));
    // Nobody else moved.
    assert_eq!((s.state(0), s.state(1), s.state(3)), (Some(CpuState::On), Some(CpuState::Off), Some(CpuState::Off)));
}

#[test]
fn an_smc32_cpu_on_uses_only_the_low_words() {
    let mut s = vm(2);
    let junk = 0xFFFF_FFFF_0000_0000u64;
    let r = call(&mut s, 0, f32_(func::CPU_ON), [junk | psci::mpidr_of(1), junk | 0x8000_0000, junk | 7]);
    assert_eq!(r.effect, Effect::Start { index: 1, entry: 0x8000_0000, context: 7 });
    // The same bits in an SMC64 call are an address no vCPU is at: Aff3 is not zero.
    let mut s = vm(2);
    assert_eq!(x0(&mut s, f64_(func::CPU_ON), [junk | psci::mpidr_of(1), 0x8000_0000, 7]), r64(ret::INVALID_PARAMETERS));
}

#[test]
fn cpu_on_refuses_with_the_code_the_state_calls_for() {
    let mut s = vm(2);
    let on = |s: &mut CpuSet, t: u64, e: u64| call(s, 0, f64_(func::CPU_ON), [t, e, 0]);
    // No such CPU: past the set, or an affinity field that is not Aff0.
    assert_eq!(on(&mut s, psci::mpidr_of(2), 0x1000).x0, r64(ret::INVALID_PARAMETERS));
    assert_eq!(on(&mut s, psci::mpidr_of(1) | 0x100, 0x1000).x0, r64(ret::INVALID_PARAMETERS));
    assert_eq!(on(&mut s, psci::mpidr_of(1) | 1 << 16, 0x1000).x0, r64(ret::INVALID_PARAMETERS));
    assert_eq!(on(&mut s, psci::mpidr_of(1) | 1 << 32, 0x1000).x0, r64(ret::INVALID_PARAMETERS));
    // An entry that is not an instruction address.
    assert_eq!(on(&mut s, psci::mpidr_of(1), 0x1002).x0, r64(ret::INVALID_ADDRESS));
    assert_eq!(s.state(1), Some(CpuState::Off), "refusals leave it off");
    // A CPU that is on, and one that is on its way.
    assert_eq!(on(&mut s, psci::mpidr_of(0), 0x1000).x0, r64(ret::ALREADY_ON));
    assert_eq!(on(&mut s, psci::mpidr_of(1), 0x1000).effect, Effect::Start { index: 1, entry: 0x1000, context: 0 });
    let again = on(&mut s, psci::mpidr_of(1), 0x2000);
    assert_eq!(again, Reply { x0: r64(ret::ON_PENDING), effect: Effect::None });
    s.entered(1);
    assert_eq!(on(&mut s, psci::mpidr_of(1), 0x2000).x0, r64(ret::ALREADY_ON));
}

#[test]
fn the_flag_bits_of_an_mpidr_are_not_part_of_its_address() {
    let mut s = vm(3);
    // Bit 31 (RES1), U (30) and MT (24) come and go.
    for t in [1u64, 1 << 31 | 1, 1 << 30 | 1, 1 << 24 | 1, 0x8100_0001] {
        let mut set = s;
        assert_eq!(x0(&mut set, f32_(func::AFFINITY_INFO), [t, 0, 0]), affinity::OFF, "{t:#x}");
    }
    assert_eq!(x0(&mut s, f32_(func::AFFINITY_INFO), [psci::mpidr_of(0), 0, 0]), affinity::ON);
}

#[test]
fn mpidr_and_index_name_each_other() {
    for n in 1..=psci::MAX_VCPUS {
        for i in 0..n {
            assert_eq!(psci::index_of(psci::mpidr_of(i), n), Some(i));
        }
        assert_eq!(psci::index_of(psci::mpidr_of(n), n), None);
    }
    assert_eq!(psci::mpidr_of(5) & 1 << 31, 1 << 31, "MPIDR bit 31 reads as one");
    assert_eq!(psci::mpidr_of(5) & 0xFF, 5);
}

#[test]
fn affinity_info_follows_the_life_of_a_secondary() {
    let mut s = vm(2);
    let ai = |s: &mut CpuSet, t: u64, lvl: u64| call(s, 0, f64_(func::AFFINITY_INFO), [t, lvl, 0]).x0;
    let t1 = psci::mpidr_of(1);
    assert_eq!(ai(&mut s, t1, 0), affinity::OFF);
    call(&mut s, 0, f64_(func::CPU_ON), [t1, 0x1000, 0]);
    assert_eq!(ai(&mut s, t1, 0), affinity::ON_PENDING);
    s.entered(1);
    assert_eq!(ai(&mut s, t1, 0), affinity::ON);
    // The thread ends for whatever reason: off again, and CPU_ON works again.
    s.ended(1);
    assert_eq!(ai(&mut s, t1, 0), affinity::OFF);
    assert!(matches!(call(&mut s, 0, f64_(func::CPU_ON), [t1, 0x1000, 0]).effect, Effect::Start { .. }));
    // Only the CPU level exists; an unknown target is a bad parameter.
    assert_eq!(ai(&mut s, t1, 1), r64(ret::INVALID_PARAMETERS));
    assert_eq!(ai(&mut s, t1, 3), r64(ret::INVALID_PARAMETERS));
    assert_eq!(ai(&mut s, psci::mpidr_of(2), 0), r64(ret::INVALID_PARAMETERS));
}

#[test]
fn a_start_that_failed_leaves_the_target_off() {
    let mut s = vm(2);
    call(&mut s, 0, f64_(func::CPU_ON), [psci::mpidr_of(1), 0x1000, 0]);
    // The loop could not create the thread: it reports the end of the vCPU.
    s.ended(1);
    assert_eq!(s.state(1), Some(CpuState::Off));
    assert_eq!(s.state(0), Some(CpuState::On));
}

#[test]
fn cpu_off_ends_the_caller_and_does_not_return_to_a_cpu_that_is_not_on() {
    let mut s = vm(2);
    call(&mut s, 0, f64_(func::CPU_ON), [psci::mpidr_of(1), 0x1000, 0]);
    s.entered(1);
    let r = call(&mut s, 1, f32_(func::CPU_OFF), [0; 3]);
    assert_eq!(r.effect, Effect::CpuOff);
    assert_eq!(s.state(1), Some(CpuState::Off));
    assert_eq!(s.state(0), Some(CpuState::On));
    // A CPU that is already off cannot ask again.
    assert_eq!(call(&mut s, 1, f32_(func::CPU_OFF), [0; 3]), Reply { x0: r32(ret::DENIED), effect: Effect::None });
}

#[test]
fn cpu_suspend_is_a_wfi_for_standby_and_refuses_power_down() {
    let mut s = vm(1);
    let standby = call(&mut s, 0, f32_(func::CPU_SUSPEND), [0x0000_0001, 0x4000_0000, 0]);
    assert_eq!(standby, Reply { x0: 0, effect: Effect::Standby });
    let down = call(&mut s, 0, f32_(func::CPU_SUSPEND), [1 << 16 | 1, 0x4000_0000, 0]);
    assert_eq!(down, Reply { x0: r32(ret::INVALID_PARAMETERS), effect: Effect::None });
    // The SMC64 form returns a 64-bit code.
    let down64 = call(&mut s, 0, f64_(func::CPU_SUSPEND), [1 << 16, 0x4000_0000, 0]);
    assert_eq!(down64.x0, r64(ret::INVALID_PARAMETERS));
    assert_eq!(s.state(0), Some(CpuState::On));
}

#[test]
fn system_off_and_reset_end_the_guest_and_power_every_vcpu_down() {
    for (fid, effect) in [(func::SYSTEM_OFF, Effect::SystemOff), (func::SYSTEM_RESET, Effect::SystemReset)] {
        let mut s = vm(3);
        call(&mut s, 0, f64_(func::CPU_ON), [psci::mpidr_of(1), 0x1000, 0]);
        s.entered(1);
        let r = call(&mut s, 1, f32_(fid), [0; 3]);
        assert_eq!(r.effect, effect);
        for i in 0..3 {
            assert_eq!(s.state(i), Some(CpuState::Off), "vcpu {i} after {fid}");
        }
    }
}

#[test]
fn the_host_stub_still_forwards_psci_and_the_guest_path_is_not_that_class() {
    // The stub's dispatch is the host's: its table must not have moved.
    assert_eq!(classify_hvc(f32_(func::CPU_ON)), HvcClass::Psci);
    assert_eq!(classify_hvc(f64_(func::CPU_ON)), HvcClass::Psci);
    assert_eq!(classify_hvc(f32_(func::SYSTEM_OFF)), HvcClass::Psci);
    // SMCCC_VERSION is no host PSCI call; the guest path answers it itself.
    assert_eq!(classify_hvc(psci::SMCCC_VERSION), HvcClass::Unsupported);
}

#[test]
fn the_set_clamps_its_size_and_ignores_indices_it_does_not_have() {
    let mut s = CpuSet::new(0);
    assert_eq!(s.count(), 1);
    assert_eq!(CpuSet::new(1000).count(), psci::MAX_VCPUS);
    s.boot(5);
    s.entered(5);
    s.ended(5);
    assert_eq!(s.state(5), None);
    assert_eq!(s.state(0), Some(CpuState::Off));
}

// ── the virtual timer's PPI and the device lines ────────────────────────

fn timer_on(g: &mut GuestIrq, cval: u64) {
    // The registers as read at an exit: enabled, unmasked.
    g.after_exit(&[0; 4], 1, cval);
}

fn listed(g: &GuestIrq) -> Vec<u32> {
    g.lrs().iter().filter(|&&l| lr_state(l) != LrState::Invalid).map(|&l| lr_vintid(l)).collect()
}

#[test]
fn the_timer_ppi_is_listed_when_the_virtual_count_reaches_cval() {
    let mut g = GuestIrq::new(4, 5000);
    timer_on(&mut g, 1500);
    // Physical 6499 is virtual 1499: not yet.
    g.pre_entry(0, 6499);
    assert_eq!(listed(&g), Vec::<u32>::new());
    g.pre_entry(0, 6500);
    assert_eq!(listed(&g), vec![VTIMER_PPI]);
    let lr = g.lrs()[0];
    assert_eq!((lr_state(lr), lr_priority(lr), lr_group1(lr), lr_hw(lr)), (LrState::Pending, GUEST_PRIO, true, None));
}

#[test]
fn all_vcpus_of_a_vm_see_the_same_clock() {
    // One CNTVOFF per VM: the VM started when the physical count was 9000.
    let off = cntvoff_on_resume(9000, 0);
    let mut a = GuestIrq::new(4, off);
    let mut b = GuestIrq::new(4, off);
    for g in [&mut a, &mut b] {
        timer_on(g, 500);
        assert_eq!(g.cntvoff(), off);
    }
    for pcnt in [9000 + 499, 9000 + 500] {
        a.pre_entry(0, pcnt);
        b.pre_entry(0, pcnt);
        assert_eq!(listed(&a), listed(&b), "physical {pcnt}");
        assert_eq!(virtual_count(pcnt, a.cntvoff()), virtual_count(pcnt, b.cntvoff()));
    }
    assert_eq!(listed(&a), vec![VTIMER_PPI]);
    assert_eq!(a.wake_at(), Some(9500));
}

#[test]
fn a_timer_the_guest_has_masked_or_disabled_never_lists_and_never_wakes() {
    for ctl in [0u64, 2, 3] {
        let mut g = GuestIrq::new(4, 0);
        g.after_exit(&[0; 4], ctl, 10);
        g.pre_entry(0, 1_000_000);
        assert_eq!(listed(&g), Vec::<u32>::new(), "ctl {ctl}");
        assert_eq!(g.wake_at(), None, "ctl {ctl}");
    }
}

#[test]
fn the_level_is_raised_once_and_left_alone_while_the_guest_handles_it() {
    let mut g = GuestIrq::new(4, 0);
    timer_on(&mut g, 100);
    g.pre_entry(0, 200);
    assert_eq!(listed(&g), vec![27]);
    // The guest took it (Active) and exits before it reprogrammed the timer.
    let active = (LrState::Active as u64) << 62 | 27 | (GUEST_PRIO as u64) << 48 | 1 << 60;
    g.after_exit(&[active, 0, 0, 0], 1, 100);
    g.pre_entry(0, 300);
    assert_eq!(lr_state(g.lrs()[0]), LrState::Active, "not Pending and Active: it is one interrupt in service");
    assert_eq!(listed(&g), vec![27]);
    // It EOIs with the level still high: the line pends it again at the next entry.
    g.after_exit(&[0, 0, 0, 0], 1, 100);
    g.pre_entry(0, 400);
    assert_eq!(lr_state(g.lrs()[0]), LrState::Pending);
}

#[test]
fn a_ppi_the_guest_has_not_taken_is_taken_back_when_the_level_falls() {
    let mut g = GuestIrq::new(4, 0);
    timer_on(&mut g, 100);
    let regs = g.pre_entry(0, 200);
    assert_eq!(listed(&g), vec![27]);
    // The hardware timer is the guest's own; the host's PPI is what is silenced.
    assert_eq!(regs.timer, TimerRegs { ctl: 1, cval: 100 });
    // The guest ran, wrote a cval in the future before taking the interrupt, and left.
    g.after_exit(&g.lrs().to_vec(), 1, 100_000);
    assert_eq!(g.timer(), Vtimer { ctl: 1, cval: 100_000 });
    g.pre_entry(0, 300);
    assert_eq!(listed(&g), Vec::<u32>::new(), "no spurious tick");
}

#[test]
fn an_asserted_timer_is_silenced_at_the_host_and_the_guests_registers_are_left_alone() {
    let mut g = GuestIrq::new(4, 0);
    timer_on(&mut g, 100);
    let plan = g.pre_entry(0, 200);
    assert!(plan.silence_ppi, "the physical PPI would fire at the host on this entry");
    assert_eq!(plan.timer, TimerRegs { ctl: 1, cval: 100 }, "the hardware timer is the guest's own");
    assert_eq!(listed(&g), vec![27]);
    // Not asserted (before cval): nothing to silence.
    let mut g = GuestIrq::new(4, 0);
    timer_on(&mut g, 1000);
    assert!(!g.pre_entry(0, 200).silence_ppi);
    // Masked by the guest: no interrupt, nothing to silence.
    let mut g = GuestIrq::new(4, 0);
    g.after_exit(&[0; 4], 3, 100);
    assert!(!g.pre_entry(0, 200).silence_ppi);
}

#[test]
fn a_guest_that_wrote_only_cval_during_an_entry_keeps_its_timer_unmasked() {
    let mut g = GuestIrq::new(4, 0);
    timer_on(&mut g, 100);
    let plan = g.pre_entry(0, 200);
    assert_eq!(plan.timer.ctl, 1);
    // CNTV_CVAL written, CNTV_CTL not.
    g.after_exit(&g.lrs().to_vec(), 1, 100_000);
    assert_eq!(g.timer(), Vtimer { ctl: 1, cval: 100_000 });
    assert_eq!(g.wake_at(), Some(100_000), "it can still fire");
}

/// An LR as the hardware leaves it after the guest took the timer interrupt and ended it.
const FREE: [u64; 4] = [0; 4];

#[test]
fn a_guest_that_took_the_ppi_and_masked_the_timer_does_not_get_it_again() {
    let mut g = GuestIrq::new(4, 0);
    timer_on(&mut g, 100);
    g.pre_entry(0, 200);
    // Linux's handler: ack, read CTL (ISTATUS), write CTL | IMASK, EOI.
    g.after_exit(&FREE, 3 | 4, 100);
    assert_eq!(g.timer(), Vtimer { ctl: 3, cval: 100 }, "the mask is the guest's");
    assert_eq!(g.wake_at(), None, "a masked timer wakes nobody");
    let plan = g.pre_entry(0, 300);
    assert_eq!(listed(&g), Vec::<u32>::new(), "no masked interrupt is delivered");
    assert_eq!(plan.timer, TimerRegs { ctl: 3, cval: 100 });
    assert!(!plan.silence_ppi);
    // The guest unmasks and reprograms later: back in the guest's hands.
    g.after_exit(&FREE, 1, 100_000);
    assert_eq!(g.timer(), Vtimer { ctl: 1, cval: 100_000 });
}

#[test]
fn a_mask_the_guest_sets_while_its_interrupt_is_held_is_seen_at_once() {
    // The case an entry that masked the hardware timer itself could not tell from
    // its own mask: IMASK set, cval and ENABLE untouched, the interrupt neither
    // taken nor ended. The entry leaves CNTV_CTL_EL0 alone, so the readback is the guest's.
    let mut g = GuestIrq::new(4, 0);
    timer_on(&mut g, 100);
    g.pre_entry(0, 200);
    assert_eq!(listed(&g), vec![27]);
    g.after_exit(&g.lrs().to_vec(), 3, 100);
    assert_eq!(g.timer(), Vtimer { ctl: 3, cval: 100 }, "IMASK is the guest's");
    g.pre_entry(0, 210);
    assert_eq!(listed(&g), Vec::<u32>::new(), "the pending interrupt of a masked timer is taken back");
}

#[test]
fn a_mask_set_inside_the_handler_is_seen_at_once_and_the_interrupt_in_service_is_left_alone() {
    let mut g = GuestIrq::new(4, 0);
    timer_on(&mut g, 100);
    g.pre_entry(0, 200);
    // Exit after the ack and the handler's IMASK write, before the EOI.
    let active = (LrState::Active as u64) << 62 | 27 | (GUEST_PRIO as u64) << 48 | 1 << 60;
    g.after_exit(&[active, 0, 0, 0], 3 | 4, 100);
    assert_eq!(g.timer(), Vtimer { ctl: 3, cval: 100 });
    g.pre_entry(0, 210);
    assert_eq!(lr_state(g.lrs()[0]), LrState::Active, "the one in service is left alone");
    // The EOI; the timer stays masked, so nothing is raised again.
    g.after_exit(&FREE, 3 | 4, 100);
    g.pre_entry(0, 220);
    assert_eq!(listed(&g), Vec::<u32>::new());
}

#[test]
fn an_interrupt_still_pending_at_the_exit_stays_pending_while_the_timer_is_unmasked() {
    let mut g = GuestIrq::new(1, 0);
    timer_on(&mut g, 100);
    g.pre_entry(0, 200);
    assert_eq!(listed(&g), vec![27]);
    // The guest never took it (IRQs masked, or an early exit): the LR is as it was written.
    g.after_exit(&g.lrs().to_vec(), 1 | 4, 100);
    assert_eq!(g.timer(), Vtimer { ctl: 1, cval: 100 }, "nothing ended, nothing changed");
    let plan = g.pre_entry(0, 210);
    assert_eq!(listed(&g), vec![27]);
    assert!(plan.silence_ppi);
}

#[test]
fn a_timer_that_fired_while_the_guest_ran_is_listed_at_the_next_entry() {
    let mut g = GuestIrq::new(4, 0);
    timer_on(&mut g, 1000);
    let r = g.pre_entry(0, 10);
    assert_eq!(r.timer.ctl, 1, "not asserted: the hardware timer is the guest's");
    assert!(!r.silence_ppi);
    // The physical PPI ended the run; the exit reads ISTATUS (bit 2) too.
    g.after_exit(&[0; 4], 1 | 4, 1000);
    assert_eq!(g.timer().ctl, 1, "ISTATUS is not state");
    g.pre_entry(0, 1000);
    assert_eq!(listed(&g), vec![27]);
}

#[test]
fn device_lines_are_software_spis_in_ascending_order_after_the_timer() {
    let mut g = GuestIrq::new(4, 0);
    timer_on(&mut g, 0);
    // Lines 5, 0, 63, 2, 1 raised in any order arrive as bits: 0,1,2,5,63. Four LRs.
    let lines = 1 << 5 | 1 | 1 << 63 | 1 << 2 | 1 << 1;
    g.pre_entry(lines, 1);
    assert_eq!(
        g.lrs().iter().map(|&l| lr_vintid(l)).collect::<Vec<_>>(),
        vec![27, SPI_BASE, SPI_BASE + 1, SPI_BASE + 2],
        "the timer first, then lines 0, 1, 2 in the free LRs in index order"
    );
    for &l in &g.lrs()[1..] {
        assert_eq!((lr_hw(l), lr_group1(l), lr_priority(l)), (None, true, GUEST_PRIO));
    }
    assert_eq!(g.backlog(), 0);
    // The guest finished the timer and line 1; the queue (5, 63) refills the freed LRs in order.
    let lrs = g.lrs().to_vec();
    let mut back = lrs.clone();
    back[0] = 0;
    back[2] = 0;
    g.after_exit(&back, 0, 0);
    assert_eq!(
        g.lrs().iter().map(|&l| lr_vintid(l)).collect::<Vec<_>>(),
        vec![SPI_BASE + 5, SPI_BASE, SPI_BASE + 63, SPI_BASE + 2]
    );
}

#[test]
fn the_backlog_is_listed_before_the_lines_raised_since() {
    let mut g = GuestIrq::new(1, 0);
    // One LR and a full queue of 32: lines 0 (LR) and 1..=32 (queue); line 40 does not fit.
    g.pre_entry(((1u64 << 33) - 1) | 1 << 40, 0);
    assert_eq!(g.backlog(), 1 << 40);
    // The guest finishes line 0: the best queued (1) moves into the LR, one queue slot is free.
    g.after_exit(&[0], 0, 0);
    // Line 35 is raised, a lower number than the waiting 40: 40 waited longer and takes the slot.
    g.pre_entry(1 << 35, 0);
    assert_eq!(g.backlog(), 1 << 35, "40 went first; the newer 35 waits although its number is lower");
    assert_eq!(g.lrs().iter().map(|&l| lr_vintid(l)).collect::<Vec<_>>(), vec![SPI_BASE + 1]);
}

#[test]
fn a_line_raised_again_while_pending_is_one_interrupt() {
    let mut g = GuestIrq::new(4, 0);
    g.pre_entry(1 << 3, 0);
    g.pre_entry(1 << 3, 0);
    assert_eq!(listed(&g), vec![SPI_BASE + 3]);
    assert_eq!(inject::line_intid(3), SPI_BASE + 3);
    assert_eq!(LINES, 64);
}

#[test]
fn what_the_lrs_and_the_queue_cannot_hold_waits_in_order_for_the_next_entry() {
    let mut g = GuestIrq::new(2, 0);
    // 40 lines: 2 LRs + 32 queued take 34; 6 wait.
    let lines = (1u64 << 40) - 1;
    g.pre_entry(lines, 0);
    assert_eq!(g.backlog(), ((1u64 << 40) - 1) & !((1u64 << 34) - 1));
    // The guest finishes both LRs; the queue's best two move in; the backlog takes the two free queue slots.
    g.after_exit(&[0, 0], 0, 0);
    g.pre_entry(0, 0);
    assert_eq!(g.backlog().trailing_zeros(), 36, "lines 34 and 35 went first");
    assert_eq!(g.backlog(), ((1u64 << 40) - 1) & !((1u64 << 36) - 1));
    // Nothing was listed twice or lost: the LRs took lines 2 and 3 from the queue, which now holds 4..=35.
    assert_eq!(g.lrs().iter().map(|&l| lr_vintid(l)).collect::<Vec<_>>(), vec![SPI_BASE + 2, SPI_BASE + 3]);
}

#[test]
fn the_vgic_level_helpers_keep_a_queue_in_order_and_refill_on_a_retract() {
    let mut v = VgicCpu::new(1);
    v.raise_level(27, 0xA0, true).unwrap();
    v.inject(40, 0x20, true, None).unwrap(); // better priority, waits
    v.inject(41, 0xA0, true, None).unwrap();
    assert_eq!(v.queued(), 2);
    assert!(v.holds(27) && v.holds(40) && v.holds(41) && !v.holds(42));
    // Taking back the Pending 27 frees the LR for the best waiter.
    assert!(v.retract_pending(27));
    assert_eq!(lr_vintid(v.lrs()[0]), 40);
    assert_eq!(v.queued(), 1);
    // A queued one can be taken back too, and a missing one cannot.
    assert!(v.retract_pending(41));
    assert!(!v.retract_pending(41));
    assert_eq!(v.queued(), 0);
    // Raising a listed level is a no-op, even for a Pending and Active one.
    assert!(!v.retract_pending(99));
    assert_eq!(QUEUE_CAP, 32);
}

#[test]
fn a_pending_and_active_level_returns_to_active_not_to_nothing() {
    let mut v = VgicCpu::new(2);
    v.raise_level(27, 0xA0, true).unwrap();
    // The guest took it; the model sees it Active, then the edge path re-pends it.
    let mut lrs = v.lrs().to_vec();
    lrs[0] = (lrs[0] & !(3 << 62)) | (LrState::Active as u64) << 62;
    v.absorb(&lrs);
    v.inject(27, 0xA0, true, None).unwrap();
    assert_eq!(lr_state(v.lrs()[0]), LrState::PendingActive);
    assert!(v.retract_pending(27));
    assert_eq!(lr_state(v.lrs()[0]), LrState::Active);
    assert!(!v.retract_pending(27), "an Active one is the guest's to finish");
    assert_eq!(lr_state(v.lrs()[0]), LrState::Active);
}

#[test]
fn from_hw_drops_istatus_and_nothing_else() {
    let t = Vtimer::from_hw(1 | 4, 77);
    assert_eq!(t, Vtimer { ctl: 1, cval: 77 });
    assert_eq!(Vtimer::from_hw(3 | 4, 77), Vtimer { ctl: 3, cval: 77 }, "IMASK is state");
    assert_eq!(Vtimer::from_hw(0, 77).ctl, 0);
}

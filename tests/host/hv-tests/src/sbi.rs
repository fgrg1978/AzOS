// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The SBI a riscv64 guest calls (`ext/hv/sbi.rs`), against a fake VM of
//! vCPUs: every call of every extension, the argument checks the
//! specification asks for, the answer in the guest's registers, what the
//! fence primitive asks of a hart (a hart that records), and the vCPU loop
//! routing the outcomes and holding the guest back until its fences are done.
//!
//! WHY. The SBI is the first thing a guest kernel runs into: a wrong error
//! code, a hart mask off by one or a timer that is not cleared is a guest
//! that hangs in early boot with nothing to say why, and no guest runs here
//! before the S6 boot (QEMU `h=true`).

use crate::fakes::FakeHv;
use crate::glue::rv::{
    self,
    enter::GuestFrame,
    sbi::{self, eid, err, fid, hart_state, reset, Effect, Hart, SbiCall, SbiRet, Vvma},
};
use azos_arch_api::{
    Exit, GuestCtx, HvKind, HvStatus, HypercallHost, HypercallOutcome, Hypervisor, RawExit,
    RemoteFence, Stage2Root, StageError, StagePerms, StageTableMem, VcpuStartError,
};
use azos_hv::run::{self, PostError, RunHost, RunView, Stop};
use azos_hv::trapwire::{Completion, Trap};
use std::collections::VecDeque;
use std::sync::Mutex;

// ── the fake VM ─────────────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Eq)]
enum Call {
    Start { vcpu: usize, pc: u64, arg: u64 },
    Irq { vcpu: usize, line: u32 },
    Arm { vcpu: usize, deadline: u64, line: u32 },
    Fence { vcpu: usize, fence: RemoteFence },
}

struct Vm {
    running: Vec<bool>,
    calls: Vec<Call>,
    start: Result<(), VcpuStartError>,
}

impl Vm {
    /// `n` vCPUs, vCPU 0 running (a VM's boot state).
    fn new(n: usize) -> Vm {
        let mut running = vec![false; n];
        running[0] = true;
        Vm { running, calls: vec![], start: Ok(()) }
    }
}

impl HypercallHost for Vm {
    fn vcpus(&self) -> usize {
        self.running.len()
    }
    fn vcpu_running(&self, vcpu: usize) -> bool {
        self.running[vcpu]
    }
    fn start_vcpu(&mut self, vcpu: usize, pc: u64, arg: u64) -> Result<(), VcpuStartError> {
        self.calls.push(Call::Start { vcpu, pc, arg });
        if self.start.is_ok() {
            self.running[vcpu] = true;
        }
        self.start
    }
    fn raise_irq(&mut self, vcpu: usize, line: u32) {
        self.calls.push(Call::Irq { vcpu, line });
    }
    fn arm_timer(&mut self, vcpu: usize, deadline: u64, line: u32) {
        self.calls.push(Call::Arm { vcpu, deadline, line });
    }
    fn fence(&mut self, vcpu: usize, fence: RemoteFence) {
        self.calls.push(Call::Fence { vcpu, fence });
    }
}

fn call(eid: u64, fid: u64, args: &[u64]) -> SbiCall {
    let mut a = [0u64; 6];
    a[..args.len()].copy_from_slice(args);
    SbiCall { eid, fid, args: a }
}

/// Serve `c` made by vCPU `caller`; the answer and its effect.
fn go(vm: &mut Vm, caller: usize, c: SbiCall) -> (SbiRet, Effect) {
    let h = sbi::handle(&c, caller, vm);
    (h.ret, h.effect)
}

fn ok(value: u64) -> SbiRet {
    SbiRet { error: err::SUCCESS, value }
}

fn bad(error: i64) -> SbiRet {
    SbiRet { error, value: 0 }
}

// ── BASE ────────────────────────────────────────────────────────────────

#[test]
fn base_answers_version_identity_and_probes() {
    let mut vm = Vm::new(1);
    let base = |vm: &mut Vm, f, a0| go(vm, 0, call(eid::BASE, f, &[a0])).0;
    assert_eq!(base(&mut vm, fid::BASE_SPEC_VERSION, 0), ok(0x0200_0000));
    assert_eq!(base(&mut vm, fid::BASE_IMPL_ID, 0), ok(sbi::IMPL_ID));
    assert_eq!(base(&mut vm, fid::BASE_IMPL_VERSION, 0), ok(sbi::IMPL_VERSION));
    for f in [fid::BASE_MVENDORID, fid::BASE_MARCHID, fid::BASE_MIMPID] {
        assert_eq!(base(&mut vm, f, 0), ok(0), "fid {f}");
    }
    assert_eq!(base(&mut vm, 7, 0), bad(err::NOT_SUPPORTED));
    // Exactly the six it serves are there; the legacy calls, the console
    // extension (DBCN: a guest's console is a device) and a made-up extension
    // are not.
    for e in [eid::BASE, eid::TIME, eid::IPI, eid::RFENCE, eid::HSM, eid::SRST] {
        assert_eq!(base(&mut vm, fid::BASE_PROBE, e), ok(1), "probe {e:#x}");
    }
    for e in [0x00, 0x01, 0x02, 0x08, 0x0F, 0x11, 0x4442_434E, 0x4442_434F, 0x0A00_0000, u64::MAX] {
        assert_eq!(base(&mut vm, fid::BASE_PROBE, e), ok(0), "probe {e:#x}");
    }
}

#[test]
fn what_is_not_served_is_not_supported_and_touches_nothing() {
    let mut vm = Vm::new(2);
    let cases = [
        (0x00, 0), // legacy set_timer
        (0x01, 0), // legacy console_putchar
        (0x08, 0), // legacy shutdown
        (0x0A00_0000, 0), // firmware-specific
        (0x4D50_5859, 0), // PMU: not served
        (eid::TIME, 1),
        (eid::IPI, 1),
        (eid::RFENCE, 3), // remote_hfence_gvma: a nested hypervisor's
        (eid::RFENCE, 6),
        (eid::HSM, 3), // hart_suspend
        (eid::SRST, 1),
        (0x4442_434E, 0), // DBCN console_write: a console is a device
        (0x4442_434E, 2),
    ];
    for (e, f) in cases {
        assert_eq!(go(&mut vm, 0, call(e, f, &[1, 1, 1, 1, 1, 1])), (bad(err::NOT_SUPPORTED), Effect::None), "{e:#x}/{f}");
    }
    assert!(vm.calls.is_empty());
}

// ── TIME ────────────────────────────────────────────────────────────────

#[test]
fn set_timer_arms_the_monitors_timer_for_the_caller_on_the_timer_line() {
    let mut vm = Vm::new(2);
    let line = sbi::LINE_TIMER;
    assert_eq!(go(&mut vm, 1, call(eid::TIME, fid::TIME_SET_TIMER, &[12345])), (ok(0), Effect::None));
    // Never: a disarm (the arm also withdraws the pending timer line).
    assert_eq!(go(&mut vm, 0, call(eid::TIME, fid::TIME_SET_TIMER, &[u64::MAX])), (ok(0), Effect::None));
    assert_eq!(
        vm.calls,
        vec![Call::Arm { vcpu: 1, deadline: 12345, line }, Call::Arm { vcpu: 0, deadline: u64::MAX, line }]
    );
}

#[test]
fn the_timer_and_software_lines_are_the_hvip_bits() {
    assert_eq!(sbi::LINE_SOFTWARE, 2);
    assert_eq!(sbi::LINE_TIMER, 6);
}

// ── IPI ─────────────────────────────────────────────────────────────────

fn irqs(vm: &Vm) -> Vec<usize> {
    vm.calls
        .iter()
        .map(|c| match c {
            Call::Irq { vcpu, line } => {
                assert_eq!(*line, sbi::LINE_SOFTWARE);
                *vcpu
            }
            other => panic!("not an irq: {other:?}"),
        })
        .collect()
}

#[test]
fn send_ipi_raises_the_software_line_on_each_named_vcpu() {
    let mut vm = Vm::new(4);
    // Harts 1 and 3 from base 0; harts 2 and 3 from base 2 with bits 0, 1.
    assert_eq!(go(&mut vm, 0, call(eid::IPI, fid::IPI_SEND, &[0b1010, 0])).0, ok(0));
    assert_eq!(irqs(&vm), vec![1, 3]);
    vm.calls.clear();
    assert_eq!(go(&mut vm, 0, call(eid::IPI, fid::IPI_SEND, &[0b11, 2])).0, ok(0));
    assert_eq!(irqs(&vm), vec![2, 3]);
    // Itself is a target like any other.
    vm.calls.clear();
    go(&mut vm, 2, call(eid::IPI, fid::IPI_SEND, &[0b1, 2]));
    assert_eq!(irqs(&vm), vec![2]);
}

#[test]
fn send_ipi_to_all_with_base_minus_one_and_nobody_with_an_empty_mask() {
    let mut vm = Vm::new(3);
    assert_eq!(go(&mut vm, 0, call(eid::IPI, fid::IPI_SEND, &[0, u64::MAX])).0, ok(0));
    assert_eq!(irqs(&vm), vec![0, 1, 2]);
    vm.calls.clear();
    assert_eq!(go(&mut vm, 0, call(eid::IPI, fid::IPI_SEND, &[0, 0])).0, ok(0));
    assert!(vm.calls.is_empty());
}

#[test]
fn send_ipi_to_a_hart_the_vm_lacks_is_invalid_and_does_nothing() {
    let mut vm = Vm::new(2);
    // Bit 2 is hart 2 of a 2-vCPU VM, behind the valid bit 0.
    assert_eq!(go(&mut vm, 0, call(eid::IPI, fid::IPI_SEND, &[0b101, 0])).0, bad(err::INVALID_PARAM));
    assert_eq!(go(&mut vm, 0, call(eid::IPI, fid::IPI_SEND, &[1, 2])).0, bad(err::INVALID_PARAM));
    // base + i wraps the word.
    assert_eq!(go(&mut vm, 0, call(eid::IPI, fid::IPI_SEND, &[0b11, u64::MAX - 1])).0, bad(err::INVALID_PARAM));
    assert!(vm.calls.is_empty(), "no partial delivery: {:?}", vm.calls);
}

#[test]
fn hart_masks() {
    assert_eq!(sbi::targets(0b101, 0, 4), Some(0b101));
    assert_eq!(sbi::targets(0b101, 1, 4), Some(0b1010));
    assert_eq!(sbi::targets(1 << 63, 0, 64), Some(1 << 63));
    assert_eq!(sbi::targets(1 << 63, 0, 63), None);
    assert_eq!(sbi::targets(0, u64::MAX, 3), Some(0b111), "base -1 is all, mask ignored");
    assert_eq!(sbi::targets(0xFF, u64::MAX, 64), Some(u64::MAX));
    assert_eq!(sbi::targets(0, 99, 2), Some(0), "an empty mask names nobody");
    assert_eq!(sbi::targets(1, 99, 2), None);
}

// ── RFENCE ──────────────────────────────────────────────────────────────

fn fences(vm: &Vm) -> Vec<(usize, RemoteFence)> {
    vm.calls
        .iter()
        .map(|c| match c {
            Call::Fence { vcpu, fence } => (*vcpu, *fence),
            other => panic!("not a fence: {other:?}"),
        })
        .collect()
}

#[test]
fn remote_fence_i_goes_to_each_named_vcpu() {
    let mut vm = Vm::new(3);
    assert_eq!(go(&mut vm, 0, call(eid::RFENCE, fid::RFENCE_FENCE_I, &[0b110, 0])).0, ok(0));
    assert_eq!(fences(&vm), vec![(1, RemoteFence::Insn), (2, RemoteFence::Insn)]);
}

#[test]
fn remote_sfence_vma_carries_the_range_and_the_asid() {
    let mut vm = Vm::new(2);
    go(&mut vm, 0, call(eid::RFENCE, fid::RFENCE_SFENCE_VMA, &[0b10, 0, 0x4000, 0x2000]));
    assert_eq!(fences(&vm), vec![(1, RemoteFence::Tlb { start: 0x4000, size: 0x2000, asid: None })]);
    vm.calls.clear();
    go(&mut vm, 0, call(eid::RFENCE, fid::RFENCE_SFENCE_VMA_ASID, &[0, u64::MAX, 0x4000, 0x2000, 9]));
    assert_eq!(
        fences(&vm),
        vec![
            (0, RemoteFence::Tlb { start: 0x4000, size: 0x2000, asid: Some(9) }),
            (1, RemoteFence::Tlb { start: 0x4000, size: 0x2000, asid: Some(9) }),
        ]
    );
}

#[test]
fn sfence_vma_whole_space_forms() {
    let all = RemoteFence::Tlb { start: 0, size: u64::MAX, asid: None };
    // start 0, size 0: everything. size -1: everything.
    for (start, size) in [(0, 0), (0x1000, u64::MAX), (0, u64::MAX)] {
        let mut vm = Vm::new(1);
        go(&mut vm, 0, call(eid::RFENCE, fid::RFENCE_SFENCE_VMA, &[1, 0, start, size]));
        match fences(&vm)[..] {
            [(0, RemoteFence::Tlb { size: u64::MAX, asid: None, .. })] => {}
            ref other => panic!("({start:#x}, {size:#x}): {other:?} (not like {all:?})"),
        }
    }
}

#[test]
fn sfence_vma_of_an_empty_range_does_nothing_but_still_checks_the_harts() {
    let mut vm = Vm::new(2);
    assert_eq!(go(&mut vm, 0, call(eid::RFENCE, fid::RFENCE_SFENCE_VMA, &[0b11, 0, 0x1000, 0])).0, ok(0));
    assert!(vm.calls.is_empty());
    assert_eq!(go(&mut vm, 0, call(eid::RFENCE, fid::RFENCE_SFENCE_VMA_ASID, &[0b100, 0, 0x1000, 0, 1])).0, bad(err::INVALID_PARAM));
}

#[test]
fn rfence_to_a_hart_the_vm_lacks_is_invalid_and_does_nothing() {
    let mut vm = Vm::new(2);
    for (f, args) in [
        (fid::RFENCE_FENCE_I, vec![0b101, 0]),
        (fid::RFENCE_SFENCE_VMA, vec![0b101, 0, 0, 0]),
        (fid::RFENCE_SFENCE_VMA_ASID, vec![0b101, 0, 0, 0, 3]),
    ] {
        assert_eq!(go(&mut vm, 0, call(eid::RFENCE, f, &args)).0, bad(err::INVALID_PARAM), "fid {f}");
    }
    assert!(vm.calls.is_empty());
}

#[test]
fn a_ranged_translation_flush_is_pages_and_a_big_one_is_whole() {
    assert_eq!(vvma_plan(0, 0, None), None);
    assert_eq!(vvma_plan(0x1234, 1, None), Some(Vvma::Pages { first: 0x1000, count: 1, asid: None }));
    // Straddling a page boundary takes both pages.
    assert_eq!(vvma_plan(0x1fff, 2, Some(5)), Some(Vvma::Pages { first: 0x1000, count: 2, asid: Some(5) }));
    assert_eq!(vvma_plan(0x1000, 0x1000, None), Some(Vvma::Pages { first: 0x1000, count: 1, asid: None }));
    // The limit, and one past it.
    let max = sbi::RANGE_PAGES_MAX;
    assert_eq!(vvma_plan(0, max * 4096, None), Some(Vvma::Pages { first: 0, count: max, asid: None }));
    assert_eq!(vvma_plan(0, max * 4096 + 1, None), Some(Vvma::All));
    assert_eq!(vvma_plan(0, max * 4096 + 1, Some(7)), Some(Vvma::Asid(7)));
    // Everything, and a range that wraps the address space.
    assert_eq!(vvma_plan(0, u64::MAX, None), Some(Vvma::All));
    assert_eq!(vvma_plan(0, u64::MAX, Some(2)), Some(Vvma::Asid(2)));
    assert_eq!(vvma_plan(u64::MAX - 10, 100, None), Some(Vvma::All));
}

use sbi::vvma_plan;

#[test]
fn hfence_vvma_is_encoded_like_the_assembler_does() {
    // `hfence.vvma x0, x0`, `hfence.vvma a0, a1` and `hfence.vvma x0, a1`
    // (funct7 0010001, opcode SYSTEM), against the encodings of the
    // privileged specification.
    assert_eq!(sbi::hfence_vvma_word(0, 0), 0x2200_0073);
    assert_eq!(sbi::hfence_vvma_word(10, 11), 0x22B5_0073);
    assert_eq!(sbi::hfence_vvma_word(0, 11), 0x22B0_0073);
    assert_eq!(rv::gstage::HFENCE_VVMA, 0x2200_0073);
}

// ── HSM ─────────────────────────────────────────────────────────────────

#[test]
fn hart_start_runs_a_stopped_vcpu_at_the_address_with_the_opaque_word() {
    let mut vm = Vm::new(3);
    assert_eq!(go(&mut vm, 0, call(eid::HSM, fid::HSM_START, &[2, 0x8020_0000, 0xDEAD])), (ok(0), Effect::None));
    assert_eq!(vm.calls, vec![Call::Start { vcpu: 2, pc: 0x8020_0000, arg: 0xDEAD }]);
    // Started now: it reads started, and a second start is refused.
    assert_eq!(go(&mut vm, 0, call(eid::HSM, fid::HSM_STATUS, &[2])).0, ok(hart_state::STARTED));
    assert_eq!(go(&mut vm, 0, call(eid::HSM, fid::HSM_START, &[2, 0x8020_0000, 0])).0, bad(err::ALREADY_AVAILABLE));
    assert_eq!(vm.calls.len(), 1, "the second start was not even tried");
}

#[test]
fn hart_start_refusals() {
    let mut vm = Vm::new(2);
    // Itself, which runs.
    assert_eq!(go(&mut vm, 0, call(eid::HSM, fid::HSM_START, &[0, 0x1000, 0])).0, bad(err::ALREADY_AVAILABLE));
    // A hart the VM lacks, and one that does not fit a vCPU index.
    assert_eq!(go(&mut vm, 0, call(eid::HSM, fid::HSM_START, &[2, 0x1000, 0])).0, bad(err::INVALID_PARAM));
    assert_eq!(go(&mut vm, 0, call(eid::HSM, fid::HSM_START, &[1 << 40, 0x1000, 0])).0, bad(err::INVALID_PARAM));
    assert!(vm.calls.is_empty());
    // What the monitor says.
    for (e, want) in [
        (VcpuStartError::BadAddress, err::INVALID_ADDRESS),
        (VcpuStartError::AlreadyRunning, err::ALREADY_AVAILABLE),
        (VcpuStartError::Failed, err::FAILED),
    ] {
        vm.start = Err(e);
        assert_eq!(go(&mut vm, 0, call(eid::HSM, fid::HSM_START, &[1, 0x1000, 0])).0, bad(want), "{e:?}");
        assert!(!vm.running[1], "a refused start leaves it stopped");
    }
}

#[test]
fn hart_stop_ends_the_callers_vcpu_and_does_not_return() {
    let mut vm = Vm::new(2);
    assert_eq!(go(&mut vm, 1, call(eid::HSM, fid::HSM_STOP, &[])).1, Effect::StopVcpu);
    assert!(vm.calls.is_empty());
}

#[test]
fn hart_get_status() {
    let mut vm = Vm::new(2);
    assert_eq!(go(&mut vm, 1, call(eid::HSM, fid::HSM_STATUS, &[0])).0, ok(hart_state::STARTED));
    assert_eq!(go(&mut vm, 0, call(eid::HSM, fid::HSM_STATUS, &[1])).0, ok(hart_state::STOPPED));
    assert_eq!(go(&mut vm, 0, call(eid::HSM, fid::HSM_STATUS, &[2])).0, bad(err::INVALID_PARAM));
}

// ── SRST ────────────────────────────────────────────────────────────────

#[test]
fn system_reset_ends_the_guest_with_its_kind_and_reason() {
    let mut vm = Vm::new(1);
    for (t, k) in [(reset::SHUTDOWN, 0), (reset::COLD_REBOOT, 1), (reset::WARM_REBOOT, 2)] {
        assert_eq!(
            go(&mut vm, 0, call(eid::SRST, fid::SRST_RESET, &[t, 1])).1,
            Effect::EndGuest { kind: k, reason: 1 }
        );
    }
    // A type past the three is refused and the guest runs on.
    assert_eq!(go(&mut vm, 0, call(eid::SRST, fid::SRST_RESET, &[3, 0])), (bad(err::INVALID_PARAM), Effect::None));
    assert_eq!(go(&mut vm, 0, call(eid::SRST, fid::SRST_RESET, &[0x8000_0000, 0])).0, bad(err::INVALID_PARAM));
}

// ── on the register frame, through the glue ─────────────────────────────

/// A context whose frame is `frame` (the `GuestFrame` laid over it).
fn ctx_with(vcpu: u8, frame: GuestFrame) -> GuestCtx {
    let mut c = GuestCtx::new(Stage2Root { root: 0, aux: 0 }, 1, vcpu, 0x8000_0000, 0);
    put(&mut c, frame);
    c
}

fn put(c: &mut GuestCtx, f: GuestFrame) {
    // SAFETY: the frame fits and is aligned (asserted in the glue).
    unsafe { core::ptr::write(c.frame.as_mut_ptr() as *mut GuestFrame, f) };
}

fn frame(c: &GuestCtx) -> GuestFrame {
    // SAFETY: as `put`; every bit pattern of the words is a frame.
    unsafe { core::ptr::read(c.frame.as_ptr() as *const GuestFrame) }
}

fn ecall_frame(pc: u64, eid: u64, fid: u64, args: &[u64]) -> GuestFrame {
    let mut f = GuestFrame::new(pc, 0);
    f.gpr[17] = eid;
    f.gpr[16] = fid;
    f.gpr[10..10 + args.len()].copy_from_slice(args);
    f
}

#[test]
fn the_glue_reads_a7_a6_a0_to_a5_and_answers_in_a0_a1() {
    let mut vm = Vm::new(2);
    // probe_extension(HSM), from a guest at 0x8020_0000.
    let mut c = ctx_with(0, ecall_frame(0x8020_0000, eid::BASE, fid::BASE_PROBE, &[eid::HSM]));
    assert_eq!(rv::HvImpl.hypercall(&mut c, &mut vm), HypercallOutcome::Served);
    let f = frame(&c);
    assert_eq!((f.gpr[10], f.gpr[11]), (0, 1));
    assert_eq!(f.sepc, 0x8020_0004, "resumes after the ecall");
    // The other registers are the guest's own, untouched.
    assert_eq!(f.gpr[17], eid::BASE);
    // An error comes back as the signed word.
    let mut c = ctx_with(0, ecall_frame(0x1000, 0x7777, 0, &[]));
    assert_eq!(rv::HvImpl.hypercall(&mut c, &mut vm), HypercallOutcome::Served);
    assert_eq!(frame(&c).gpr[10] as i64, err::NOT_SUPPORTED);
    // Six arguments reach the handler: sfence_vma_asid's asid is a4.
    let mut c = ctx_with(1, ecall_frame(0x1000, eid::RFENCE, fid::RFENCE_SFENCE_VMA_ASID, &[0b1, 0, 0x2000, 0x1000, 77]));
    assert_eq!(rv::HvImpl.hypercall(&mut c, &mut vm), HypercallOutcome::Served);
    assert_eq!(fences(&vm), vec![(0, RemoteFence::Tlb { start: 0x2000, size: 0x1000, asid: Some(77) })]);
}

#[test]
fn the_glue_names_the_caller_by_its_vcpu_index() {
    let mut vm = Vm::new(4);
    let mut c = ctx_with(3, ecall_frame(0x1000, eid::TIME, fid::TIME_SET_TIMER, &[999]));
    rv::HvImpl.hypercall(&mut c, &mut vm);
    assert_eq!(vm.calls, vec![Call::Arm { vcpu: 3, deadline: 999, line: sbi::LINE_TIMER }]);
}

#[test]
fn a_call_that_does_not_return_leaves_the_frame_alone() {
    let mut vm = Vm::new(2);
    let before = ecall_frame(0x5000, eid::HSM, fid::HSM_STOP, &[]);
    let mut c = ctx_with(1, before);
    assert_eq!(rv::HvImpl.hypercall(&mut c, &mut vm), HypercallOutcome::StopVcpu);
    assert_eq!(frame(&c), before);
    let before = ecall_frame(0x5000, eid::SRST, fid::SRST_RESET, &[reset::COLD_REBOOT, 1]);
    let mut c = ctx_with(0, before);
    assert_eq!(rv::HvImpl.hypercall(&mut c, &mut vm), HypercallOutcome::EndGuest { kind: 1, reason: 1 });
    assert_eq!(frame(&c), before);
}

// ── the fence primitive, on a hart that records ─────────────────────────

/// What the code asked of the hart, in order.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Op {
    Guest(u64),
    FenceI,
    Vvma { va: Option<u64>, asid: Option<u64> },
}

#[derive(Default)]
struct Recorder(Vec<Op>);

impl Hart for Recorder {
    fn select_guest(&mut self, hgatp: u64) {
        self.0.push(Op::Guest(hgatp));
    }
    fn fence_i(&mut self) {
        self.0.push(Op::FenceI);
    }
    fn hfence_vvma(&mut self, va: Option<u64>, asid: Option<u64>) {
        self.0.push(Op::Vvma { va, asid });
    }
}

fn ran(f: RemoteFence) -> Vec<Op> {
    let mut h = Recorder::default();
    sbi::execute_on(&mut h, 0xAA, &f);
    h.0
}

#[test]
fn an_instruction_fence_is_one_fence_i_and_names_no_guest() {
    assert_eq!(ran(RemoteFence::Insn), vec![Op::FenceI]);
}

#[test]
fn a_translation_fence_loads_the_guest_then_flushes_the_plan() {
    let g = Op::Guest(0xAA);
    let tlb = |start, size, asid| RemoteFence::Tlb { start, size, asid };
    assert_eq!(ran(tlb(0, u64::MAX, None)), vec![g.clone(), Op::Vvma { va: None, asid: None }]);
    assert_eq!(ran(tlb(0, u64::MAX, Some(3))), vec![g.clone(), Op::Vvma { va: None, asid: Some(3) }]);
    // Two pages, per ASID and for all of them, one flush per page in order.
    assert_eq!(
        ran(tlb(0x1fff, 2, Some(5))),
        vec![
            g.clone(),
            Op::Vvma { va: Some(0x1000), asid: Some(5) },
            Op::Vvma { va: Some(0x2000), asid: Some(5) },
        ]
    );
    assert_eq!(ran(tlb(0x4000, 0x1000, None)), vec![g.clone(), Op::Vvma { va: Some(0x4000), asid: None }]);
    // Too big a range is one whole flush, not a page loop.
    let big = sbi::RANGE_PAGES_MAX * 4096 + 1;
    assert_eq!(ran(tlb(0, big, None)), vec![g, Op::Vvma { va: None, asid: None }]);
    // An empty range asks nothing of the hart, not even the guest.
    assert_eq!(ran(tlb(0x1000, 0, None)), vec![]);
}

#[test]
fn the_glue_flushes_the_guest_of_the_context_not_the_one_the_hart_ran_last() {
    // `hgatp` of the context: the mode in `aux`, the VM id, the root's page.
    let s2 = Stage2Root { root: 0x8123_4000, aux: rv::csr::HGATP_MODE_SV39X4 };
    let ctx = GuestCtx::new(s2, 7, 0, 0x8000_0000, 0);
    let want = rv::csr::HGATP_MODE_SV39X4 << rv::csr::HGATP_MODE_SHIFT
        | 7 << rv::csr::HGATP_VMID_SHIFT
        | 0x8123_4000 >> 12;
    let mut h = Recorder::default();
    rv::remote_fence_on(&mut h, &ctx, &RemoteFence::Tlb { start: 0, size: u64::MAX, asid: None });
    assert_eq!(h.0, vec![Op::Guest(want), Op::Vvma { va: None, asid: None }]);
    let mut h = Recorder::default();
    rv::remote_fence_on(&mut h, &ctx, &RemoteFence::Insn);
    assert_eq!(h.0, vec![Op::FenceI]);
}

// ── the vCPU loop ───────────────────────────────────────────────────────

/// An ISA whose guest makes the calls of a list, one per entry; it stands for
/// the riscv64 glue's hypercall and an entry that is wired, which the real
/// one is not yet. The registers the guest finds at each entry are recorded.
struct GuestSbi {
    inner: FakeHv,
    script: Mutex<VecDeque<(u64, u64, Vec<u64>)>>,
    pub seen: Mutex<Vec<GuestFrame>>,
    /// Entries and fences, in the order they happened on the hart.
    events: Mutex<Vec<Ev>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Ev {
    Enter,
    Fence(RemoteFence),
}

impl GuestSbi {
    fn new(calls: Vec<(u64, u64, Vec<u64>)>) -> GuestSbi {
        GuestSbi {
            inner: FakeHv::default(),
            script: Mutex::new(calls.into()),
            seen: Mutex::new(vec![]),
            events: Mutex::new(vec![]),
        }
    }
}

impl Hypervisor for GuestSbi {
    fn kind(&self) -> HvKind {
        self.inner.kind()
    }
    fn status(&self) -> HvStatus {
        self.inner.status()
    }
    fn gpa_bits(&self) -> u8 {
        self.inner.gpa_bits()
    }
    fn stage2_create(&self, mem: &mut dyn StageTableMem) -> Result<Stage2Root, StageError> {
        self.inner.stage2_create(mem)
    }
    fn stage2_map(&self, s2: &Stage2Root, mem: &mut dyn StageTableMem, gpa: u64, hpa: u64, p: StagePerms) -> Result<(), StageError> {
        self.inner.stage2_map(s2, mem, gpa, hpa, p)
    }
    fn stage2_unmap(&self, s2: &Stage2Root, mem: &mut dyn StageTableMem, gpa: u64) -> Result<u64, StageError> {
        self.inner.stage2_unmap(s2, mem, gpa)
    }
    fn stage2_translate(&self, s2: &Stage2Root, mem: &dyn StageTableMem, gpa: u64) -> Option<(u64, StagePerms)> {
        self.inner.stage2_translate(s2, mem, gpa)
    }
    fn stage2_flush(&self, vmid: u16) {
        self.inner.stage2_flush(vmid)
    }
    fn stage2_destroy(&self, s2: Stage2Root, mem: &mut dyn StageTableMem) {
        self.inner.stage2_destroy(s2, mem)
    }
    fn decode_exit(&self, raw: &RawExit) -> Exit {
        self.inner.decode_exit(raw)
    }
    fn can_enter(&self) -> bool {
        true
    }
    fn enter(&self, ctx: &mut GuestCtx) -> Exit {
        if !ctx.started {
            put(ctx, GuestFrame::new(ctx.entry_pc, 0));
        }
        self.events.lock().unwrap().push(Ev::Enter);
        self.seen.lock().unwrap().push(frame(ctx));
        let (e, f, args) = self.script.lock().unwrap().pop_front().expect("the script ran out: the loop entered again");
        let mut fr = frame(ctx);
        fr.gpr[17] = e;
        fr.gpr[16] = f;
        fr.gpr[10..10 + args.len()].copy_from_slice(&args);
        put(ctx, fr);
        Exit::Hypercall
    }
    fn hypercall(&self, ctx: &mut GuestCtx, host: &mut dyn HypercallHost) -> HypercallOutcome {
        rv::HvImpl.hypercall(ctx, host)
    }
    fn remote_fence(&self, _ctx: &GuestCtx, fence: &RemoteFence) {
        self.events.lock().unwrap().push(Ev::Fence(*fence));
    }
}

/// The kernel's end, reduced: a VM of fake vCPUs, no rings.
struct Rh {
    vm: Vm,
    serve: bool,
    /// Fences other vCPUs asked of this one, not yet taken.
    queue: VecDeque<RemoteFence>,
    /// `fences_outstanding` answers true this many more times.
    outstanding: u32,
    yields: u32,
}

impl Rh {
    fn new(vm: Vm, serve: bool) -> Rh {
        Rh { vm, serve, queue: VecDeque::new(), outstanding: 0, yields: 0 }
    }
}

impl RunHost for Rh {
    fn stop_requested(&mut self) -> bool {
        false
    }
    fn take_irqs(&mut self) -> u64 {
        0
    }
    fn next_seq(&mut self, _vcpu: u8) -> u32 {
        0
    }
    fn post(&mut self, _t: &Trap) -> Result<(), PostError> {
        Err(PostError::Gone)
    }
    fn answer(&mut self) -> Option<Completion> {
        None
    }
    fn park(&mut self) {}
    fn yield_now(&mut self) {
        self.yields += 1;
    }
    fn take_fence(&mut self) -> Option<RemoteFence> {
        self.queue.pop_front()
    }
    fn fences_outstanding(&mut self) -> bool {
        let o = self.outstanding > 0;
        self.outstanding = self.outstanding.saturating_sub(1);
        o
    }
    fn hypercall_host(&mut self) -> Option<&mut dyn HypercallHost> {
        if self.serve { Some(&mut self.vm) } else { None }
    }
}

/// A created VM of one guest row (no device windows: nothing here touches a
/// device), as the loop reads it.
fn view() -> RunView {
    use azos_hv::admit::{self, HostFacts, VirtRole};
    use azos_hv::VmTable;
    use azos_topology::{parse_caps, parse_sched, Topology};
    let mut t = Box::new(Topology::empty());
    parse_sched(b"[class.best_effort]\ncpu_budget_min_pct = 5\npolicy = \"cfs\"\n", &mut t).unwrap();
    let caps: &'static str = "format = 7\n[guest.g]\ncpus = 2\nmem_mib = 16\nenvelope = \"full\"\ndevices = [\"virtio-console\"]\n";
    parse_caps(caps.as_bytes(), &mut t).unwrap();
    let facts = HostFacts {
        role: VirtRole::Hosted,
        hv: HvStatus::Usable(HvKind::RiscvH),
        online: 0b1111,
        rt: 0,
        free_mib: 1024,
        max_guest_mib: 1024,
    };
    let plan = admit::admit(t.guests(), &facts).unwrap();
    let mut vms = VmTable::new();
    vms.install(t.guests(), &plan, HvKind::RiscvH).unwrap();
    vms.vm_mut(0).unwrap().created(Stage2Root { root: 0, aux: 0 }).unwrap();
    RunView::new(vms.vm(0).unwrap())
}

fn guest_ctx() -> GuestCtx {
    GuestCtx::new(Stage2Root { root: 0, aux: 0 }, 1, 0, 0x8000_0000, 0)
}

#[test]
fn the_loop_answers_calls_and_resumes_the_guest_after_each() {
    let hv = GuestSbi::new(vec![
        (eid::BASE, fid::BASE_SPEC_VERSION, vec![]),
        (eid::BASE, fid::BASE_PROBE, vec![eid::HSM]),
        (eid::HSM, fid::HSM_STOP, vec![]),
    ]);
    let mut host = Rh::new(Vm::new(1), true);
    let stop = run::run(&hv, &mut guest_ctx(), &view(), &mut host);
    // hart_stop ends the thread without a fault: it is a stopped vCPU.
    assert_eq!(stop, Stop::Requested);
    let seen = hv.seen.lock().unwrap();
    assert_eq!(seen.len(), 3);
    // At entry 1 the answer to call 0 is in the registers and the PC is past it.
    assert_eq!((seen[1].gpr[10], seen[1].gpr[11], seen[1].sepc), (0, 0x0200_0000, 0x8000_0004));
    assert_eq!((seen[2].gpr[10], seen[2].gpr[11], seen[2].sepc), (0, 1, 0x8000_0008));
}

#[test]
fn the_loop_ends_the_thread_with_the_shutdown_word_when_the_guest_resets() {
    for (t, kind) in [(reset::SHUTDOWN, 0u32), (reset::COLD_REBOOT, 1), (reset::WARM_REBOOT, 2)] {
        let hv = GuestSbi::new(vec![(eid::SRST, fid::SRST_RESET, vec![t, 1])]);
        let mut host = Rh::new(Vm::new(1), true);
        let stop = run::run(&hv, &mut guest_ctx(), &view(), &mut host);
        assert_eq!(stop, Stop::Fault(run::shutdown_code(kind, 1)));
        let Stop::Fault(code) = stop else { unreachable!() };
        assert_eq!(code >> 56, run::fault::SHUTDOWN);
        assert_eq!(code >> 32 & 0xFF_FFFF, kind as u64);
        assert_eq!(code & 0xFFFF_FFFF, 1);
    }
}

#[test]
fn the_loop_starts_other_vcpus_through_the_host_and_serves_the_calls_it_made() {
    let hv = GuestSbi::new(vec![
        (eid::HSM, fid::HSM_START, vec![1, 0x8040_0000, 0xABC]),
        (eid::IPI, fid::IPI_SEND, vec![0b10, 0]),
        (eid::TIME, fid::TIME_SET_TIMER, vec![5000]),
        (eid::HSM, fid::HSM_STOP, vec![]),
    ]);
    let mut host = Rh::new(Vm::new(2), true);
    assert_eq!(run::run(&hv, &mut guest_ctx(), &view(), &mut host), Stop::Requested);
    assert_eq!(
        host.vm.calls,
        vec![
            Call::Start { vcpu: 1, pc: 0x8040_0000, arg: 0xABC },
            Call::Irq { vcpu: 1, line: sbi::LINE_SOFTWARE },
            Call::Arm { vcpu: 0, deadline: 5000, line: sbi::LINE_TIMER },
        ]
    );
}

#[test]
fn without_a_host_that_serves_them_a_hypercall_still_faults_the_vcpu() {
    let hv = GuestSbi::new(vec![(eid::BASE, fid::BASE_SPEC_VERSION, vec![])]);
    let mut host = Rh::new(Vm::new(1), false);
    assert_eq!(run::run(&hv, &mut guest_ctx(), &view(), &mut host), Stop::Fault(run::fault::HYPERCALL << 56));
}

#[test]
fn an_isa_that_serves_no_hypercall_leaves_the_fault_as_it_was() {
    // The default of `Hypervisor::hypercall`, through a host that would serve.
    let mut vm = Vm::new(1);
    let mut c = guest_ctx();
    assert_eq!(FakeHv::default().hypercall(&mut c, &mut vm), HypercallOutcome::Unserved);
}

// ── fences in the loop ──────────────────────────────────────────────────

#[test]
fn fences_asked_of_a_vcpu_run_on_it_before_the_entry_that_follows() {
    let hv = GuestSbi::new(vec![(eid::HSM, fid::HSM_STOP, vec![])]);
    let mut host = Rh::new(Vm::new(1), true);
    let whole = RemoteFence::Tlb { start: 0, size: u64::MAX, asid: None };
    host.queue.extend([RemoteFence::Insn, whole]);
    assert_eq!(run::run(&hv, &mut guest_ctx(), &view(), &mut host), Stop::Requested);
    assert_eq!(*hv.events.lock().unwrap(), vec![Ev::Fence(RemoteFence::Insn), Ev::Fence(whole), Ev::Enter]);
}

#[test]
fn the_guest_is_not_resumed_while_a_fence_it_asked_is_outstanding() {
    let hv = GuestSbi::new(vec![
        (eid::RFENCE, fid::RFENCE_FENCE_I, vec![0b10, 0]),
        (eid::HSM, fid::HSM_STOP, vec![]),
    ]);
    // The vCPU it asked is slow: its fence stays outstanding for two looks.
    // Meanwhile it asks this one a fence of its own (the two fence each
    // other), and what it asked is done only once that one has been carried
    // out here, by the vCPU that waits.
    struct Pair {
        rh: Rh,
        looks: u32,
        theirs_taken: bool,
    }
    impl RunHost for Pair {
        fn stop_requested(&mut self) -> bool {
            false
        }
        fn take_irqs(&mut self) -> u64 {
            0
        }
        fn next_seq(&mut self, _v: u8) -> u32 {
            0
        }
        fn post(&mut self, _t: &Trap) -> Result<(), PostError> {
            Err(PostError::Gone)
        }
        fn answer(&mut self) -> Option<Completion> {
            None
        }
        fn park(&mut self) {}
        fn yield_now(&mut self) {
            self.rh.yields += 1;
        }
        fn take_fence(&mut self) -> Option<RemoteFence> {
            let f = self.rh.queue.pop_front();
            self.theirs_taken |= f.is_some();
            f
        }
        fn fences_outstanding(&mut self) -> bool {
            self.looks += 1;
            assert!(self.looks < 50, "waiting on a fence while one asked of this vCPU is never carried out");
            if self.looks == 2 {
                self.rh.queue.push_back(RemoteFence::Tlb { start: 0, size: u64::MAX, asid: None });
            }
            // Done only after the other vCPU's own fence was served here.
            !self.theirs_taken
        }
        fn hypercall_host(&mut self) -> Option<&mut dyn HypercallHost> {
            self.rh.hypercall_host()
        }
    }
    let mut host = Pair { rh: Rh::new(Vm::new(2), true), looks: 0, theirs_taken: false };
    assert_eq!(run::run(&hv, &mut guest_ctx(), &view(), &mut host), Stop::Requested);
    // Looks 1 and 2 waited, look 3 found the fence served: two yields, and the
    // guest entered again only after the fence ran.
    assert_eq!(host.rh.yields, 2);
    let whole = RemoteFence::Tlb { start: 0, size: u64::MAX, asid: None };
    assert_eq!(*hv.events.lock().unwrap(), vec![Ev::Enter, Ev::Fence(whole), Ev::Enter]);
    assert_eq!(host.rh.vm.calls, vec![Call::Fence { vcpu: 1, fence: RemoteFence::Insn }]);
}

#[test]
fn a_stop_ends_the_wait_for_a_fence() {
    struct Stopping(Rh);
    impl RunHost for Stopping {
        fn stop_requested(&mut self) -> bool {
            self.0.yields > 0
        }
        fn take_irqs(&mut self) -> u64 {
            0
        }
        fn next_seq(&mut self, _v: u8) -> u32 {
            0
        }
        fn post(&mut self, _t: &Trap) -> Result<(), PostError> {
            Err(PostError::Gone)
        }
        fn answer(&mut self) -> Option<Completion> {
            None
        }
        fn park(&mut self) {}
        fn yield_now(&mut self) {
            self.0.yields += 1;
        }
        fn fences_outstanding(&mut self) -> bool {
            true
        }
        fn hypercall_host(&mut self) -> Option<&mut dyn HypercallHost> {
            self.0.hypercall_host()
        }
    }
    let hv = GuestSbi::new(vec![(eid::RFENCE, fid::RFENCE_FENCE_I, vec![0b10, 0])]);
    let mut host = Stopping(Rh::new(Vm::new(2), true));
    assert_eq!(run::run(&hv, &mut guest_ctx(), &view(), &mut host), Stop::Requested);
    assert_eq!(hv.events.lock().unwrap().len(), 1, "no second entry");
}

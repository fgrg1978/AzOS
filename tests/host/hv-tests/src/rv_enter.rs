// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! A riscv64 vCPU's entry (`ext/hv/guest.rs`): the registers of the first
//! entry, the emulated access the guest resumes after, the virtual interrupt
//! lines as `hvip`, the decode of what stopped it, and the vCPU loop serving
//! the guest's accesses to the PLIC in place through the real `Vplic`.
//!
//! WHY. Every one of these is a guest that hangs or reads garbage in early
//! boot with nothing to say why: a load that does not sign-extend, a `wfi`
//! that is not stepped over, an external interrupt line that is never
//! withdrawn after the claim. The CSR half of the entry is the one thing
//! these cannot run (S6, QEMU `h=on`): the pure half is what is tested here,
//! with a fake hart that plays the guest from a script.

use crate::fakes::FakeHv;
use crate::glue::rv::{
    self,
    csr::{HSTATUS_SPV, HSTATUS_VTW, VSEIP, VSSIP, VSTIP},
    enter::GuestFrame,
    guest::{self, VcpuState, VM_HSTATUS},
    sbi::{eid, fid},
};
use azos_arch_api::{
    Exit, GuestCtx, HvKind, HvStatus, HypercallHost, HypercallOutcome, Hypervisor, MmioAccess, MmioDone, RawExit,
    RemoteFence, Stage2Root, StageError, StagePerms, StageTableMem, VcpuStartError,
};
use azos_hv::run::{self, PostError, RunHost, RunView, Stop};
use azos_hv::trapwire::{Completion, Trap};
use azos_hv::vplic::{Vplic, EXTERNAL_LINE, PLIC_DEFAULT_BASE};
use std::collections::VecDeque;
use std::sync::Mutex;

const PC: u64 = 0x8020_0000;

pub(crate) fn ctx(vcpu: u8) -> GuestCtx {
    GuestCtx::new(Stage2Root { root: 0, aux: 0 }, 1, vcpu, PC, 0x8700_0000)
}

fn state(c: &GuestCtx) -> VcpuState {
    guest::load(c)
}

// Instruction words, as `htinst` carries them (bits 1:0 = 0b11 for a 32-bit
// instruction; a compressed one has bit 1 clear and bit 0 set).
const fn lw(rd: u32, funct3: u32) -> u64 {
    ((funct3 << 12) | (rd << 7) | 0x03) as u64
}
const fn sw(rs2: u32) -> u64 {
    ((rs2 << 20) | (2 << 12) | 0x23) as u64
}

fn trap(f: &mut GuestFrame, scause: u64, gpa: u64, htinst: u64) {
    f.scause = scause;
    f.htval = gpa >> 2;
    f.stval = gpa & 3;
    f.htinst = htinst;
}

const LOAD_FAULT: u64 = 21;
const STORE_FAULT: u64 = 23;

// ── the order of the hart id, the flush decision and the interrupts ───────

/// A thread the scheduler moves: while its interrupts are on, it migrates to
/// the next hart right after it reads the hart id (the worst place for it).
struct Migrating {
    cur: u64,
    harts: u64,
    irqs_on: bool,
    /// The hart each `run` executed on, and whether it was asked to flush.
    ran: Vec<(u64, bool)>,
}

impl Migrating {
    fn placed_on(cur: u64) -> Migrating {
        Migrating { cur, harts: 4, irqs_on: true, ran: vec![] }
    }
}

impl guest::Hart for Migrating {
    fn irqs_off(&mut self) -> bool {
        std::mem::replace(&mut self.irqs_on, false)
    }
    fn irqs_restore(&mut self, were_on: bool) {
        self.irqs_on = were_on;
    }
    fn hart_id(&mut self) -> u64 {
        let id = self.cur;
        if self.irqs_on {
            self.cur = (self.cur + 1) % self.harts;
        }
        id
    }
    unsafe fn run(&mut self, st: &mut VcpuState, _hgatp: u64, _vmid: u16, flush: bool) {
        assert!(!self.irqs_on, "the guest must not be entered with the interrupts on");
        self.ran.push((self.cur, flush));
        st.frame.scause = 22; // a trap back; the decode is not under test
    }
}

#[test]
fn the_vcpu_moved_between_harts_flushes_on_each_move_and_records_where_it_ran() {
    let mut c = ctx(0);
    let mut h = Migrating::placed_on(0);
    // The scheduler places the thread on these harts before successive entries.
    let placed = [1u64, 1, 2, 0, 0, 3];
    for &hart in &placed {
        h.cur = hart;
        h.irqs_on = true;
        unsafe { guest::enter_vcpu(&mut h, &mut c, 0) };
        assert!(h.irqs_on, "the interrupts come back as found");
        c.started = true; // the monitor marks the vCPU after its first entry
        assert_eq!(state(&c).last_hart, h.ran.last().unwrap().0, "last_hart is the hart the guest ran on");
    }
    let ran: Vec<u64> = h.ran.iter().map(|r| r.0).collect();
    assert_eq!(ran, placed, "nothing migrated the thread inside the entry");
    let flush: Vec<bool> = h.ran.iter().map(|r| r.1).collect();
    assert_eq!(flush, [true, false, true, true, false, true], "a flush exactly when the hart changed");
}

#[test]
fn the_hart_id_is_read_with_the_interrupts_off() {
    // Discriminates: the order before the fix (id and `begin`, then the
    // interrupts off) lets the thread migrate in between, so the hart the
    // flush was decided for is not the one the guest runs on.
    let mut c = ctx(0);
    let mut st = guest::load(&c);
    let mut h = Migrating::placed_on(1);
    let hart = guest::Hart::hart_id(&mut h);
    let prep = guest::begin(&mut st, &mut c, hart);
    guest::Hart::irqs_off(&mut h);
    assert_ne!(h.cur, st.last_hart, "the old order records a hart the guest then does not run on");
    assert!(prep.flush);
    // The new order cannot be caught out the same way.
    let mut c2 = ctx(0);
    let mut h2 = Migrating::placed_on(1);
    unsafe { guest::enter_vcpu(&mut h2, &mut c2, 0) };
    assert_eq!(h2.cur, state(&c2).last_hart);
}

// ── begin ───────────────────────────────────────────────────────────────

#[test]
fn the_first_entry_starts_the_boot_vcpu_as_the_sbi_promises() {
    let mut c = ctx(3);
    let mut st = state(&c);
    let p = guest::begin(&mut st, &mut c, 1);
    assert!(p.flush, "a vCPU that never ran has nothing cached anywhere: flush");
    let f = &st.frame;
    assert_eq!(f.sepc, PC);
    // a0 = the hart id (the vCPU's index), a1 = the device tree address.
    assert_eq!((f.gpr[10], f.gpr[11]), (3, 0x8700_0000));
    // VS-mode, `wfi` traps, returns to a guest.
    assert_eq!(f.sstatus, 1 << 8);
    assert_eq!(f.hstatus & (HSTATUS_SPV | HSTATUS_VTW), HSTATUS_SPV | HSTATUS_VTW);
    assert_eq!(VM_HSTATUS, HSTATUS_VTW);
    // `satp` Bare, nothing pending.
    assert_eq!((st.vs.vsatp, st.vs.hvip), (0, 0));
}

#[test]
fn a_flush_is_asked_only_when_the_hart_changed() {
    let mut c = ctx(0);
    let mut st = state(&c);
    assert!(guest::begin(&mut st, &mut c, 2).flush);
    c.started = true;
    assert!(!guest::begin(&mut st, &mut c, 2).flush, "same hart: its cached translations are this VM's");
    assert!(guest::begin(&mut st, &mut c, 3).flush, "another hart ran it since the tables last changed");
    assert!(!guest::begin(&mut st, &mut c, 3).flush);
}

#[test]
fn a_started_vcpu_keeps_its_registers_across_entries() {
    let mut c = ctx(0);
    let mut st = state(&c);
    guest::begin(&mut st, &mut c, 0);
    st.frame.gpr[5] = 0x55;
    st.frame.gpr[11] = 0x99;
    st.frame.sepc = PC + 0x40;
    st.vs.vsatp = 0x8000_0000_0000_1234;
    guest::store(&mut c, &st);
    c.started = true;
    let mut again = state(&c);
    guest::begin(&mut again, &mut c, 0);
    assert_eq!((again.frame.gpr[5], again.frame.sepc, again.vs.vsatp), (0x55, PC + 0x40, 0x8000_0000_0000_1234));
    // The first-entry registers are not applied twice.
    assert_eq!(again.frame.gpr[11], 0x99);
}

// ── the access the guest resumes after ──────────────────────────────────

fn resume(htinst: u64, size: u8, reg: u8, insn_len: u8, value: u64, write: bool) -> GuestFrame {
    let mut c = ctx(0);
    let mut st = state(&c);
    guest::begin(&mut st, &mut c, 0);
    c.started = true;
    st.frame.htinst = htinst;
    st.frame.sepc = PC + 0x100;
    guest::store(&mut c, &st);
    c.completed = Some(MmioDone { access: MmioAccess { gpa: 0x1000_1000, size, write, reg, insn_len }, value });
    let mut st = state(&c);
    guest::begin(&mut st, &mut c, 0);
    assert!(c.completed.is_none(), "the answer is delivered once");
    st.frame
}

#[test]
fn a_signed_load_extends_the_sign_and_an_unsigned_one_does_not() {
    // lw x5: funct3 2 (signed); lwu x5: funct3 6.
    let f = resume(lw(5, 2) | 3, 4, 5, 4, 0x8000_0001, false);
    assert_eq!(f.gpr[5], 0xFFFF_FFFF_8000_0001);
    assert_eq!(f.sepc, PC + 0x104);
    let f = resume(lw(5, 6) | 3, 4, 5, 4, 0x8000_0001, false);
    assert_eq!(f.gpr[5], 0x8000_0001);
    // lb / lbu.
    assert_eq!(resume(lw(6, 0) | 3, 1, 6, 4, 0x80, false).gpr[6], 0xFFFF_FFFF_FFFF_FF80);
    assert_eq!(resume(lw(6, 4) | 3, 1, 6, 4, 0x80, false).gpr[6], 0x80);
    // ld has no extension to make.
    assert_eq!(resume(lw(7, 3) | 3, 8, 7, 4, u64::MAX - 1, false).gpr[7], u64::MAX - 1);
}

#[test]
fn a_compressed_load_steps_two_bytes_and_a_store_only_steps() {
    // c.lw: bit 1 clear, bit 0 set.
    let f = resume((lw(5, 2) & !2) | 1, 4, 5, 2, 7, false);
    assert_eq!((f.gpr[5], f.sepc), (7, PC + 0x102));
    let f = resume(sw(7) | 3, 4, 7, 4, 0, true);
    assert_eq!((f.gpr[7], f.sepc), (0, PC + 0x104), "a store writes no register");
}

#[test]
fn a_load_into_x0_changes_nothing() {
    let f = resume(lw(0, 2) | 3, 4, 0, 4, 0x1234, false);
    assert_eq!(f.gpr[0], 0, "x0 stays zero: the exit path stores it as such");
    assert_eq!(f.sepc, PC + 0x104);
}

#[test]
fn load_value_truncates_to_the_access() {
    assert_eq!(guest::load_value(0x1_FF, 1, false), 0xFF);
    assert_eq!(guest::load_value(0x1_8000, 2, true), 0xFFFF_FFFF_FFFF_8000);
    assert_eq!(guest::load_value(0x7FFF_FFFF, 4, true), 0x7FFF_FFFF);
}

// ── the lines ───────────────────────────────────────────────────────────

#[test]
fn the_levels_follow_their_lines_and_the_software_interrupt_is_an_edge() {
    let h = guest::lines_to_hvip(0, VSSIP | VSTIP | VSEIP);
    assert_eq!(h, VSSIP | VSTIP | VSEIP);
    // Timer and external withdrawn when their lines are absent...
    let h = guest::lines_to_hvip(h, 0);
    assert_eq!(h, VSSIP, "...the software interrupt stays until the guest clears it");
    // ...and other bits of `hvip` are untouched.
    assert_eq!(guest::lines_to_hvip(1 << 4, VSEIP), (1 << 4) | VSEIP);
    // Lines that are not VS interrupts are ignored.
    assert_eq!(guest::lines_to_hvip(0, 1 << 3 | 1 << 20), 0);
}

#[test]
fn external_line_is_the_vseip_bit_of_hvip() {
    assert_eq!(1u64 << EXTERNAL_LINE, VSEIP);
}

#[test]
fn the_lines_reach_hvip_on_the_next_entry() {
    let mut c = ctx(0);
    c.irqs = VSTIP | VSEIP;
    let mut st = state(&c);
    guest::begin(&mut st, &mut c, 0);
    assert_eq!(st.vs.hvip, VSTIP | VSEIP);
    guest::store(&mut c, &st);
    c.started = true;
    c.irqs = 0;
    let mut st = state(&c);
    guest::begin(&mut st, &mut c, 0);
    assert_eq!(st.vs.hvip, 0, "no longer due: withdrawn");
}

// ── finish ──────────────────────────────────────────────────────────────

fn stopped(scause: u64, stval: u64, htval: u64, htinst: u64) -> (VcpuState, GuestCtx, Exit) {
    let mut c = ctx(0);
    let mut st = state(&c);
    guest::begin(&mut st, &mut c, 0);
    st.frame.sepc = PC + 8;
    st.frame.scause = scause;
    st.frame.stval = stval;
    st.frame.htval = htval;
    st.frame.htinst = htinst;
    let e = guest::finish(&mut st, &mut c);
    (st, c, e)
}

#[test]
fn wfi_is_stepped_over_so_the_guest_does_not_trap_on_it_again() {
    let (st, _, e) = stopped(22, 0x1050_0073, 0, 0);
    assert_eq!(e, Exit::Wait);
    assert_eq!(st.frame.sepc, PC + 12);
    assert_ne!(st.frame.hstatus & HSTATUS_SPV, 0, "and returns to a guest");
}

#[test]
fn another_trapped_instruction_faults_where_it_stands() {
    let (st, _, e) = stopped(22, 0x1000_0073, 0, 0); // sret under VTSR, say
    assert_eq!(e, Exit::Other(22));
    assert_eq!(st.frame.sepc, PC + 8);
}

#[test]
fn a_store_hands_its_value_over_and_a_load_is_not_resumed_yet() {
    let mut c = ctx(0);
    let mut st = state(&c);
    guest::begin(&mut st, &mut c, 0);
    st.frame.gpr[7] = 0xABCD;
    trap(&mut st.frame, STORE_FAULT, 0x1000_1050, sw(7) | 3);
    let e = guest::finish(&mut st, &mut c);
    assert_eq!(e, Exit::Mmio(MmioAccess { gpa: 0x1000_1050, size: 4, write: true, reg: 7, insn_len: 4 }));
    assert_eq!(c.mmio_value, 0xABCD);
    assert_eq!(st.frame.sepc, PC, "the loop completes it: the PC moves with the answer");
    // x0 as the source stores 0.
    trap(&mut st.frame, STORE_FAULT, 0x1000_1050, sw(0) | 3);
    guest::finish(&mut st, &mut c);
    assert_eq!(c.mmio_value, 0);
    trap(&mut st.frame, LOAD_FAULT, 0x1000_1050, lw(9, 2) | 3);
    assert_eq!(
        guest::finish(&mut st, &mut c),
        Exit::Mmio(MmioAccess { gpa: 0x1000_1050, size: 4, write: false, reg: 9, insn_len: 4 })
    );
}

#[test]
fn a_host_interrupt_resumes_the_same_instruction() {
    let (st, _, e) = stopped(1 << 63 | 5, 0, 0, 0);
    assert_eq!(e, Exit::HostInterrupt);
    assert_eq!(st.frame.sepc, PC + 8);
    assert_ne!(st.frame.hstatus & HSTATUS_SPV, 0);
}

#[test]
fn what_the_loop_does_not_serve_faults() {
    // An undecoded fetch fault; an illegal instruction (a guest's FP).
    assert!(matches!(stopped(20, 0, 0x2_0000, 0).2, Exit::Fault { .. }));
    assert_eq!(stopped(2, 0, 0, 0).2, Exit::Other(2));
    // An FP or atomic access to a device is not one the monitor decodes.
    let fld = (3u64 << 12) | 0x07 | 3;
    assert!(matches!(stopped(LOAD_FAULT, 0, 0x4000_1000 >> 2, fld).2, Exit::Fault { .. }));
}

// ── the loop, the PLIC and the fake hart ────────────────────────────────

/// What the fake guest does at its next stop.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Step {
    Load { gpa: u64, reg: u32 },
    Store { gpa: u64, reg: u32, val: u64 },
    Wfi,
    HartStop,
}

/// A hart that plays a guest: each entry runs the real `begin`, stops the way
/// the next step says, and runs the real `finish`.
pub(crate) struct FakeHart {
    inner: FakeHv,
    script: Mutex<VecDeque<Step>>,
    /// The state the guest found at each entry.
    pub(crate) seen: Mutex<Vec<VcpuState>>,
}

impl FakeHart {
    pub(crate) fn new(steps: &[Step]) -> FakeHart {
        FakeHart { inner: FakeHv::default(), script: Mutex::new(steps.iter().copied().collect()), seen: Mutex::new(vec![]) }
    }
}

impl Hypervisor for FakeHart {
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
        rv::HvImpl.decode_exit(raw)
    }
    fn can_enter(&self) -> bool {
        true
    }
    fn enter(&self, ctx: &mut GuestCtx) -> Exit {
        let mut st = guest::load(ctx);
        guest::begin(&mut st, ctx, 0);
        self.seen.lock().unwrap().push(st);
        let step = self.script.lock().unwrap().pop_front().expect("the script ran out: the loop entered again");
        let f = &mut st.frame;
        match step {
            Step::Load { gpa, reg } => trap(f, LOAD_FAULT, gpa, lw(reg, 2) | 3),
            Step::Store { gpa, reg, val } => {
                f.gpr[reg as usize] = val;
                trap(f, STORE_FAULT, gpa, sw(reg) | 3);
            }
            Step::Wfi => {
                f.scause = 22;
                f.stval = 0x1050_0073;
            }
            Step::HartStop => {
                f.scause = 10;
                f.gpr[17] = eid::HSM;
                f.gpr[16] = fid::HSM_STOP;
            }
        }
        let e = guest::finish(&mut st, ctx);
        guest::store(ctx, &st);
        e
    }
    fn hypercall(&self, ctx: &mut GuestCtx, host: &mut dyn HypercallHost) -> HypercallOutcome {
        rv::HvImpl.hypercall(ctx, host)
    }
    fn remote_fence(&self, _ctx: &GuestCtx, _fence: &RemoteFence) {}
}

/// The kernel's end, reduced to what the PLIC path needs: one VM's PLIC and
/// the device lines that rise after given entries.
struct PlicHost {
    plic: Vplic,
    /// `(after_entries, source)`: a device raises `source` once the guest has
    /// stopped that many times.
    devices: Vec<(usize, usize)>,
    stops: usize,
    /// The lines `take_irqs` handed each entry.
    irqs: Vec<u64>,
    parks: u32,
}

impl RunHost for PlicHost {
    fn stop_requested(&mut self) -> bool {
        false
    }
    fn take_irqs(&mut self) -> u64 {
        let due: Vec<usize> = self.devices.iter().filter(|d| d.0 == self.stops).map(|d| d.1).collect();
        for s in due {
            self.plic.pulse(s);
        }
        self.stops += 1;
        let irqs = (self.plic.line(0) as u64) << EXTERNAL_LINE;
        self.irqs.push(irqs);
        irqs
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
    fn park(&mut self) {
        self.parks += 1;
    }
    fn yield_now(&mut self) {}
    fn intc_mmio(&mut self, a: &MmioAccess, value: u64) -> Option<u64> {
        self.plic.serve(a, value).map(|(v, _)| v)
    }
    fn hypercall_host(&mut self) -> Option<&mut dyn HypercallHost> {
        Some(self)
    }
}

impl HypercallHost for PlicHost {
    fn vcpus(&self) -> usize {
        1
    }
    fn vcpu_running(&self, _vcpu: usize) -> bool {
        true
    }
    fn start_vcpu(&mut self, _vcpu: usize, _pc: u64, _arg: u64) -> Result<(), VcpuStartError> {
        Err(VcpuStartError::Failed)
    }
    fn raise_irq(&mut self, _vcpu: usize, _line: u32) {}
    fn arm_timer(&mut self, _vcpu: usize, _deadline: u64, _line: u32) {}
    fn fence(&mut self, _vcpu: usize, _fence: RemoteFence) {}
}

fn view() -> RunView {
    use azos_hv::admit::{self, HostFacts, VirtRole};
    use azos_hv::VmTable;
    use azos_topology::{parse_caps, parse_sched, Topology};
    let mut t = Box::new(Topology::empty());
    parse_sched(b"[class.best_effort]\ncpu_budget_min_pct = 5\npolicy = \"cfs\"\n", &mut t).unwrap();
    let caps: &'static str = "format = 7\n[guest.g]\ncpus = 1\nmem_mib = 16\nenvelope = \"full\"\ndevices = [\"virtio-console\"]\n";
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

const P: u64 = PLIC_DEFAULT_BASE;
const PRIO3: u64 = P + 4 * 3;
const ENABLE0: u64 = P + 0x2000;
const THRESH0: u64 = P + 0x20_0000;
const CLAIM0: u64 = P + 0x20_0004;

#[test]
fn the_guest_programs_the_plic_takes_the_interrupt_and_claims_it() {
    // Priority 1 for source 3, enable it for context 0, threshold 0; a device
    // raises it after the 4th stop; the guest waits, claims, completes.
    let steps = [
        Step::Store { gpa: PRIO3, reg: 5, val: 1 },
        Step::Store { gpa: ENABLE0, reg: 6, val: 1 << 3 },
        Step::Store { gpa: THRESH0, reg: 0, val: 0 },
        Step::Wfi,
        Step::Load { gpa: CLAIM0, reg: 10 },
        Step::Store { gpa: CLAIM0, reg: 10, val: 3 },
        Step::Load { gpa: CLAIM0, reg: 11 },
        Step::HartStop,
    ];
    let hv = FakeHart::new(&steps);
    let mut host = PlicHost { plic: Vplic::new(P, 1), devices: vec![(4, 3)], stops: 0, irqs: vec![], parks: 0 };
    let mut c = ctx(0);
    let stop = run::run(&hv, &mut c, &view(), &mut host);
    assert_eq!(stop, Stop::Requested, "hart_stop ends the vCPU without a fault");

    let seen = hv.seen.lock().unwrap();
    assert_eq!(seen.len(), steps.len());
    // The device's edge lands at entry 4 (the one after the wfi): the guest
    // finds VSEIP pending there, and not before.
    assert_eq!(host.irqs, vec![0, 0, 0, 0, VSEIP, 0, 0, 0]);
    assert_eq!(seen[3].vs.hvip, 0);
    assert_eq!(seen[4].vs.hvip, VSEIP);
    // Entry 5 is after the claim read: the guest has the id in a0, and the
    // claim lowered the line, so VSEIP is withdrawn at that very entry.
    assert_eq!(seen[5].frame.gpr[10], 3, "claim returns the source");
    assert_eq!(seen[5].vs.hvip, 0);
    // A second claim finds nothing: the edge was taken.
    assert_eq!(seen[7].frame.gpr[11], 0);
    // The wfi parked the thread and was stepped over.
    assert_eq!(host.parks, 1);
}

#[test]
fn an_access_outside_the_plic_window_still_goes_to_the_bus() {
    // A load below the window and one just past it: both read 0 off the bus
    // (no device window there) and the PLIC state is untouched.
    let steps = [
        Step::Store { gpa: PRIO3, reg: 5, val: 7 },
        Step::Load { gpa: P - 4, reg: 9 },
        Step::Load { gpa: P + azos_hv::vplic::PLIC_WINDOW, reg: 9 },
        Step::Load { gpa: PRIO3, reg: 8 },
        Step::HartStop,
    ];
    let hv = FakeHart::new(&steps);
    let mut host = PlicHost { plic: Vplic::new(P, 1), devices: vec![], stops: 0, irqs: vec![], parks: 0 };
    let mut c = ctx(0);
    run::run(&hv, &mut c, &view(), &mut host);
    let seen = hv.seen.lock().unwrap();
    assert_eq!(seen[3].frame.gpr[9], 0);
    assert_eq!(seen[4].frame.gpr[8], 7, "the priority written is the one read back: in the window it is the PLIC");
}

#[test]
fn a_plic_access_that_is_not_a_word_reads_zero_and_drops_the_store() {
    use azos_arch_api::MmioAccess;
    let mut p = Vplic::new(P, 1);
    let byte = MmioAccess { gpa: PRIO3, size: 1, write: true, reg: 5, insn_len: 4 };
    assert_eq!(p.serve(&byte, 7), Some((0, azos_hv::vplic::Change::NONE)));
    let word = MmioAccess { gpa: PRIO3, size: 4, write: false, reg: 5, insn_len: 4 };
    assert_eq!(p.serve(&word, 0).map(|r| r.0), Some(0), "the byte store never landed");
    let outside = MmioAccess { gpa: 0x1000_1000, ..word };
    assert_eq!(p.serve(&outside, 0), None);
}

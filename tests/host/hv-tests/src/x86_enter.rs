// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `Hypervisor::enter` for an AzOS guest on SVM (`azos_arch_x86_64::hv::vcpu`):
//! the vCPU is built on its first entry, then the entry loops *VMRUN, decode,
//! serve* and returns to the monitor's loop only for what it has to handle.
//!
//! The function under test is the real `enter`; what is scripted is the CPU
//! (`Fake`: each `VMRUN` runs the next step of the guest, which leaves the
//! exit the hardware would) and the kernel (`Host`: pages from the allocator
//! and the VM's virtual APICs, the same `azos_hv::{vlapic, vioapic}` models
//! the kernel's host runs). WHY: `VMRUN` cannot run in QEMU's TCG for the
//! host tests, and a wrong word in the entry (the intercept list, the state a
//! restarted vCPU starts in, a TLB flush that is not asked for) is a guest
//! that dies or reads stale memory with no message.
//!
//! The entry keeps its slots, the table epoch and the per-CPU records in
//! statics, so the tests take one lock and release what they claimed.

use std::alloc::{alloc_zeroed, dealloc, Layout};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use azos_arch_api::{Exit, GuestCtx, MmioAccess, MmioDone, Stage2Root};
use azos_arch_x86_64::hv::apic::LocalApic;
use azos_arch_x86_64::hv::cpuid::Leaf;
use azos_arch_x86_64::hv::msr;
use azos_arch_x86_64::hv::probe::SvmCaps;
use azos_arch_x86_64::hv::svm::{code, ctl, icpt, off, IOPM_BYTES, MSRPM_BYTES};
use azos_arch_x86_64::hv::vcpu::{self, flush, slots_release, Claim, Machine, Ran, VcpuMem, VmHost, VmInfo, PAGE};
use azos_hv::vioapic::pulse_lines;

use crate::x86_guest::{icr_send, route, vm, x2apic_up, zen3, Port, Vm, APIC_KHZ, TSC_KHZ};

const NASID: u32 = 8;
const ENTRY: u64 = 0x20_0000;
const START_INFO: u64 = 0x6000;
const FP_BYTES: usize = 832;
const VIRTIO: u64 = 0x1000_1000;
const TSC_PER_TICK: u64 = 3;

// ── the kernel ──────────────────────────────────────────────────────────

struct Host {
    vcpus: u8,
    vm: Mutex<Option<Vm>>,
    pages: Mutex<Vec<(u64, usize)>>,
    freed: Mutex<Vec<(u64, usize)>>,
    resets: Mutex<u32>,
    released: Mutex<Vec<u16>>,
}

impl Host {
    fn new(vcpus: u8) -> Host {
        Host {
            vcpus,
            vm: Mutex::new(None),
            pages: Mutex::new(Vec::new()),
            freed: Mutex::new(Vec::new()),
            resets: Mutex::new(0),
            released: Mutex::new(Vec::new()),
        }
    }

    fn info(&self) -> VmInfo {
        VmInfo { vcpus: self.vcpus, tsc_khz: TSC_KHZ, apic_khz: APIC_KHZ }
    }

    /// The VM's interrupt controllers, for a test that plays the guest or a device.
    fn with_vm<R>(&self, f: impl FnOnce(&mut Vm) -> R) -> R {
        let mut g = self.vm.lock().unwrap();
        f(g.get_or_insert_with(|| vm(self.vcpus as u32)))
    }
}

fn layout(pages: usize) -> Layout {
    Layout::from_size_align(pages * PAGE, PAGE).unwrap()
}

impl VmHost for Host {
    fn alloc_pages(&self, pages: usize) -> Option<u64> {
        // SAFETY: a non-zero, page-aligned layout.
        let p = unsafe { alloc_zeroed(layout(pages)) };
        let pa = p as u64;
        self.pages.lock().unwrap().push((pa, pages));
        Some(pa)
    }

    fn free_pages(&self, pa: u64, pages: usize) {
        self.freed.lock().unwrap().push((pa, pages));
        // SAFETY: allocated by `alloc_pages` with the same layout; freed once.
        unsafe { dealloc(pa as *mut u8, layout(pages)) };
    }

    fn vm_info(&self, _vmid: u16) -> Option<VmInfo> {
        self.with_vm(|_| ());
        Some(self.info())
    }

    fn reset_vm(&self, _vmid: u16) -> Option<VmInfo> {
        *self.resets.lock().unwrap() += 1;
        *self.vm.lock().unwrap() = Some(vm(self.vcpus as u32));
        Some(self.info())
    }

    fn with_apic(&self, _vmid: u16, vcpu: u8, f: &mut dyn FnMut(&mut dyn LocalApic)) -> bool {
        let mut g = self.vm.lock().unwrap();
        let Some(vm) = g.as_mut() else { return false };
        if vcpu as usize >= vm.apics.len() {
            return false;
        }
        f(&mut Port { vm, idx: vcpu as usize });
        true
    }

    fn raise_lines(&self, _vmid: u16, lines: u64) {
        self.with_vm(|vm| vm.kicked |= pulse_lines(&mut vm.apics, &mut vm.io, lines));
    }

    fn release_vm(&self, vmid: u16) {
        self.released.lock().unwrap().push(vmid);
    }
}

// ── the CPU ─────────────────────────────────────────────────────────────

/// What the CPU found at a `VMRUN`.
#[derive(Clone, Copy, Debug)]
struct Seen {
    rip: u64,
    rbx: u64,
    tlb: u8,
    xcr0: u64,
    asid: u32,
    nested_cr3: u64,
    iopm: u64,
    msrpm: u64,
    w3: u32,
    event_inj: u32,
    window: bool,
    cs: (u16, u16, u32, u64),
    valid: bool,
    pa: u64,
    tsc_offset: u64,
}

type Step = Box<dyn FnOnce(&mut VcpuMem)>;

struct Fake {
    steps: VecDeque<Step>,
    seen: Vec<Seen>,
    cpu: usize,
    /// Report the thread as moved to another CPU this many times before running.
    moves: u32,
    /// What runs while the thread is between the decision and the entry, with
    /// interrupts off in the real machine (it can be preempted there).
    on_move: Option<Box<dyn FnMut()>>,
}

impl Fake {
    fn new() -> Fake {
        Fake { steps: VecDeque::new(), seen: Vec::new(), cpu: 0, moves: 0, on_move: None }
    }

    fn then(&mut self, s: impl FnOnce(&mut VcpuMem) + 'static) -> &mut Fake {
        self.steps.push_back(Box::new(s));
        self
    }
}

impl Machine for Fake {
    fn cpu(&self) -> usize {
        self.cpu
    }
    fn host_tsc(&self) -> u64 {
        1_000_000
    }
    /// Three TSC cycles to a tick, so a tick is not mistaken for a cycle.
    fn ticks_to_tsc(&self, ticks: u64) -> u64 {
        ticks * TSC_PER_TICK
    }
    fn host_cpuid(&self, leaf: u32, sub: u32) -> Leaf {
        zen3(leaf, sub)
    }
    fn svm_caps(&self) -> SvmCaps {
        SvmCaps { nasid: NASID, nrips: true, flush_by_asid: true, ..SvmCaps::default() }
    }
    fn fp_bytes(&self) -> usize {
        FP_BYTES
    }
    fn read_phys(&self, _pa: u64, _buf: &mut [u8]) -> bool {
        false
    }
    fn map(&self, pa: u64) -> *mut u8 {
        pa as *mut u8
    }
    fn vmrun(&mut self, v: &mut VcpuMem, _fp: *mut u8, guest_xcr0: u64, cpu: usize, claim: &Claim) -> Ran {
        assert_eq!(cpu, self.cpu, "the entry prepared for the CPU it asked about");
        if self.moves > 0 {
            self.moves -= 1;
            if let Some(f) = self.on_move.as_mut() {
                f();
            }
            return Ran::Moved;
        }
        claim.enter(v, cpu);
        self.seen.push(Seen {
            rip: v.vmcb.rd64(off::RIP),
            rbx: v.run.regs.rbx,
            tlb: v.vmcb.rd8(off::TLB_CTL),
            xcr0: guest_xcr0,
            asid: v.vmcb.rd32(off::GUEST_ASID),
            nested_cr3: v.vmcb.rd64(off::NESTED_CR3),
            iopm: v.vmcb.rd64(off::IOPM_BASE_PA),
            msrpm: v.vmcb.rd64(off::MSRPM_BASE_PA),
            w3: v.vmcb.rd32(off::INTERCEPT_W3),
            event_inj: v.vmcb.rd32(off::EVENT_INJ),
            window: v.vmcb.window_requested(),
            cs: v.vmcb.segment(off::CS),
            valid: v.vmcb.check(NASID).is_ok(),
            pa: v.vmcb_pa(),
            tsc_offset: v.vmcb.rd64(off::TSC_OFFSET),
        });
        let step = self.steps.pop_front().expect("the guest has nothing more to run: the entry entered again");
        step(v);
        claim.leave(cpu);
        Ran::Done
    }
}

// ── steps of the guest ──────────────────────────────────────────────────

fn exit(v: &mut VcpuMem, code: u64, info1: u64, info2: u64, next: u64) {
    v.vmcb.wr64(off::EXIT_CODE, code);
    v.vmcb.wr64(off::EXIT_INFO_1, info1);
    v.vmcb.wr64(off::EXIT_INFO_2, info2);
    v.vmcb.wr64(off::NEXT_RIP, next);
}

/// `hlt` at the current RIP.
fn hlt(v: &mut VcpuMem) {
    let at = v.vmcb.rd64(off::RIP);
    exit(v, code::HLT, 0, 0, at + 1);
}

/// `cpuid` of `leaf` at the current RIP.
fn cpuid(leaf: u64) -> impl FnOnce(&mut VcpuMem) {
    move |v| {
        let at = v.vmcb.rd64(off::RIP);
        v.vmcb.wr64(off::RAX, leaf);
        v.run.regs.rcx = 0;
        exit(v, code::CPUID, 0, 0, at + 2);
    }
}

/// `in al, dx` (or `out dx, al`) on `port` at the current RIP.
fn port_io(port: u16, write: bool, size_bits: u64, string: bool) -> impl FnOnce(&mut VcpuMem) {
    move |v| {
        let at = v.vmcb.rd64(off::RIP);
        let info1 = (port as u64) << 16 | (!write) as u64 | size_bits | (string as u64) << 2;
        exit(v, code::IOIO, info1, at + 1, at + 1);
    }
}

fn ctx_for(root: u64, vcpu: u8) -> GuestCtx {
    GuestCtx::new(Stage2Root { root, aux: 4 }, 1, vcpu, ENTRY, START_INFO)
}

/// The vCPU's pages, as the entry left them.
fn mem(ctx: &GuestCtx) -> &'static mut VcpuMem {
    // SAFETY: `frame[0]` is the address of the slot's pages, which the test's
    // `Host` allocated and keeps until `slots_release`.
    unsafe { &mut *(ctx.frame[0] as *mut VcpuMem) }
}

// ── the test bench ──────────────────────────────────────────────────────

static LOCK: Mutex<()> = Mutex::new(());
static ROOTS: AtomicU64 = AtomicU64::new(0x10_0000);

/// One test: the entry's statics are shared, so one at a time, and the slots
/// it claimed are given back when it ends.
struct Bench {
    _g: MutexGuard<'static, ()>,
    m: Fake,
    host: Host,
    roots: Vec<u64>,
}

impl Bench {
    fn new(vcpus: u8) -> Bench {
        let g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        Bench { _g: g, m: Fake::new(), host: Host::new(vcpus), roots: Vec::new() }
    }

    fn root(&mut self) -> u64 {
        let r = ROOTS.fetch_add(0x1000, Ordering::SeqCst);
        self.roots.push(r);
        r
    }

    fn enter(&mut self, ctx: &mut GuestCtx) -> Exit {
        vcpu::enter(&mut self.m, &self.host, ctx)
    }
}

impl Drop for Bench {
    fn drop(&mut self) {
        for &r in &self.roots {
            slots_release(&self.host, r);
        }
    }
}

// ── the first entry ─────────────────────────────────────────────────────

#[test]
fn the_boot_cpu_is_built_in_the_pvh_state_with_the_maps_and_intercepts_the_guest_needs() {
    let mut b = Bench::new(1);
    let root = b.root();
    let mut c = ctx_for(root, 0);
    b.m.then(hlt);
    assert_eq!(b.enter(&mut c), Exit::Wait, "an idle guest sleeps the thread");
    let s = b.m.seen[0];
    assert!(s.valid, "the VMCB passes the checks VMRUN makes");
    assert_eq!((s.rip, s.rbx), (ENTRY, START_INFO), "PVH: entry point, hvm_start_info in EBX");
    assert_eq!(s.cs.1, 0xC9B, "flat 32-bit code");
    assert_eq!(s.asid, 1, "the VM's id is its ASID");
    assert_eq!(s.nested_cr3, root, "the stage-2 tables are the nested tables");
    assert_eq!(s.tlb, ctl::TLB_FLUSH_ALL, "a first entry flushes");
    assert_eq!(s.xcr0, 1, "a guest starts with x87 only");
    let need = icpt::CPUID | icpt::NMI | icpt::INTR | icpt::IOIO_PROT | icpt::MSR_PROT | icpt::HLT | icpt::SHUTDOWN;
    assert_eq!(s.w3 & need, need);
    // The permission maps: every port exits, and the MSRs are the map the guest policy builds.
    // SAFETY: the maps are pages the host allocated for the entry and keeps.
    let (io, ms) = unsafe {
        (
            std::slice::from_raw_parts(s.iopm as *const u8, IOPM_BYTES),
            &*(s.msrpm as *const [u8; MSRPM_BYTES]),
        )
    };
    assert!(io.iter().all(|&x| x == 0xFF), "every port exits");
    assert!(msr::intercepted(ms, 0x1B, false) && msr::intercepted(ms, 0x800, true));
    assert!(!msr::intercepted(ms, msr::MSR_LSTAR, true), "what the VMCB holds runs at speed");
    assert_eq!(*b.host.resets.lock().unwrap(), 1, "the boot CPU's first entry starts the VM's APICs over");
}

#[test]
fn an_entry_that_does_not_fit_32_bits_or_a_vm_without_an_asid_is_not_run() {
    let mut b = Bench::new(1);
    let root = b.root();
    let mut c = ctx_for(root, 0);
    c.entry_pc = 1 << 32;
    assert_eq!(b.enter(&mut c), Exit::InvalidState, "PVH has 32 bits of entry");
    let mut c = ctx_for(root, 0);
    c.vmid = 0;
    assert_eq!(b.enter(&mut c), Exit::InvalidState, "ASID 0 is the host's");
    let mut c = ctx_for(root, 0);
    c.vmid = NASID as u16;
    assert_eq!(b.enter(&mut c), Exit::InvalidState, "the CPU has no such ASID");
    let mut c = ctx_for(root, 1);
    assert_eq!(b.enter(&mut c), Exit::InvalidState, "a vCPU past the VM's count");
    assert!(b.m.seen.is_empty(), "nothing ran");
}

// ── what is answered without leaving ────────────────────────────────────

#[test]
fn cpuid_is_answered_in_the_entry_and_the_guest_runs_on() {
    let mut b = Bench::new(1);
    let root = b.root();
    let mut c = ctx_for(root, 0);
    b.m.then(cpuid(0x4000_0000)).then(hlt);
    assert_eq!(b.enter(&mut c), Exit::Wait);
    assert_eq!(b.m.seen.len(), 2, "two VMRUNs for one call of enter");
    assert_eq!(b.m.seen[1].rip, ENTRY + 2, "past the CPUID");
    let r = mem(&c).run.regs;
    assert_eq!(r.rbx, 0x534F_7A41, "\"AzOS\": the guest finds the hypervisor");
}

#[test]
fn an_unclaimed_port_is_an_empty_bus() {
    let mut b = Bench::new(1);
    let root = b.root();
    let mut c = ctx_for(root, 0);
    // in al, dx on COM1 with RAX = 0x1234: the low byte reads 0xFF.
    b.m.then(|v| {
        v.vmcb.wr64(off::RAX, 0x1234);
        port_io(0x3F8, false, 1 << 4, false)(v)
    })
    .then(|v| {
        assert_eq!(v.vmcb.rd64(off::RAX), 0x12FF, "an IN reads ones");
        // out dx, al: dropped.
        port_io(0x3F8, true, 1 << 4, false)(v)
    })
    .then(|v| {
        // in eax, dx: all 32 bits, the upper half of RAX cleared.
        v.vmcb.wr64(off::RAX, 0xAAAA_BBBB_CCCC_DDDD);
        port_io(0xCF8, false, 1 << 6, false)(v)
    })
    .then(|v| {
        assert_eq!(v.vmcb.rd64(off::RAX), 0xFFFF_FFFF);
        hlt(v)
    });
    assert_eq!(b.enter(&mut c), Exit::Wait);
    assert_eq!(b.m.seen.len(), 4);
    assert_eq!(b.m.seen[1].rip, ENTRY + 1);
    assert_eq!(b.m.seen[3].rip, ENTRY + 3, "each access is stepped over");
}

#[test]
fn a_string_port_access_ends_the_vcpu_visibly() {
    let mut b = Bench::new(1);
    let root = b.root();
    let mut c = ctx_for(root, 0);
    b.m.then(port_io(0x3F8, false, 1 << 4, true));
    match b.enter(&mut c) {
        Exit::Pio(p) => assert!(p.string && p.port == 0x3F8),
        e => panic!("{e:?}"),
    }
}

#[test]
fn the_exits_the_monitor_decides_come_back_decoded_and_a_physical_interrupt_is_not_served() {
    let mut b = Bench::new(1);
    let root = b.root();
    let mut c = ctx_for(root, 0);
    b.m.then(|v| exit(v, code::VMMCALL, 0, 0, 0));
    assert_eq!(b.enter(&mut c), Exit::Hypercall);
    b.m.then(|v| exit(v, code::SHUTDOWN, 0, 0, 0));
    assert_eq!(b.enter(&mut c), Exit::Shutdown, "a triple fault");
    b.m.then(|v| exit(v, u64::MAX, 0, 0, 0));
    assert_eq!(b.enter(&mut c), Exit::InvalidState, "VMEXIT_INVALID");
    b.m.then(|v| exit(v, code::INTR, 0, 0, 0));
    assert_eq!(b.enter(&mut c), Exit::HostInterrupt);
    b.m.then(|v| exit(v, code::NMI, 0, 0, 0));
    assert_eq!(b.enter(&mut c), Exit::HostInterrupt, "a physical NMI is the host's");
}

#[test]
fn a_physical_interrupt_that_cut_an_injection_short_does_not_lose_the_vector() {
    let mut b = Bench::new(1);
    let root = b.root();
    let mut c = ctx_for(root, 0);
    // The CPU was delivering vector 0x35 (EXITINTINFO valid, type external interrupt) when the tick came.
    b.m.then(|v| {
        v.vmcb.wr32(off::EXIT_INT_INFO, 1 << 31 | 0x35);
        exit(v, code::INTR, 0, 0, 0)
    })
    .then(hlt);
    assert_eq!(b.enter(&mut c), Exit::HostInterrupt);
    assert_eq!(b.enter(&mut c), Exit::Wait);
    assert_eq!(b.m.seen[1].event_inj, 1 << 31 | 0x35, "queued again for the next entry");
}

#[test]
fn a_thread_that_moved_between_the_decision_and_the_entry_prepares_again() {
    let mut b = Bench::new(1);
    let root = b.root();
    let mut c = ctx_for(root, 0);
    b.m.moves = 2;
    b.m.then(hlt);
    assert_eq!(b.enter(&mut c), Exit::Wait);
    assert_eq!(b.m.seen.len(), 1, "it ran once, after the moves");
    assert_eq!(b.m.seen[0].tlb, ctl::TLB_FLUSH_ALL, "the flush a first entry asks for survived the retries");
}

#[test]
fn a_guest_is_not_published_as_running_before_the_entry_is_certain() {
    // A thread that is between the decision and the entry (interrupts about to
    // go off, or on again to allocate, or moved) runs no guest: a flush must
    // not kick that CPU and wait for the thread to be scheduled again.
    let mut b = Bench::new(1);
    let root = b.root();
    let mut c = ctx_for(root, 0);
    let kicked = Arc::new(AtomicBool::new(false));
    let k = kicked.clone();
    b.m.moves = 1;
    b.m.on_move = Some(Box::new(move || flush(1, usize::MAX, &mut |_| k.store(true, Ordering::SeqCst))));
    b.m.then(hlt);
    assert_eq!(b.enter(&mut c), Exit::Wait);
    assert!(!kicked.load(Ordering::SeqCst), "nothing ran, nothing to wait for");
    // And once the guest has exited, the CPU is free of it.
    flush(1, usize::MAX, &mut |_| kicked.store(true, Ordering::SeqCst));
    assert!(!kicked.load(Ordering::SeqCst), "published only while the guest runs");
}

#[test]
fn a_guest_that_exits_all_the_time_still_gives_the_hart_back() {
    let mut b = Bench::new(1);
    let root = b.root();
    let mut c = ctx_for(root, 0);
    for _ in 0..1000 {
        b.m.then(cpuid(0));
    }
    assert_eq!(b.enter(&mut c), Exit::HostInterrupt, "the thread can see a stop request");
    let ran = b.m.seen.len();
    assert!((100..1000).contains(&ran), "bounded, not one round per call: {ran}");
}

// ── device accesses ─────────────────────────────────────────────────────

/// A nested fault on `gpa` for `mov [eax], ebx` (the CPU's own copy of the bytes, as decode assists give).
fn mmio_store(gpa: u64) -> impl FnOnce(&mut VcpuMem) {
    move |v| {
        let at = v.vmcb.rd64(off::RIP);
        v.vmcb.wr8(0xD0, 2);
        v.vmcb.wr8(0xD1, 0x89);
        v.vmcb.wr8(0xD2, 0x18);
        v.run.regs.rbx = 0xDEAD_0007;
        exit(v, code::NPF, 1 << 1 | 1 << 32, gpa, at + 2);
    }
}

#[test]
fn a_device_store_goes_to_the_monitor_and_is_stepped_over_at_its_answer() {
    let mut b = Bench::new(1);
    let root = b.root();
    let mut c = ctx_for(root, 0);
    b.m.then(mmio_store(VIRTIO + 0x70)).then(hlt);
    let e = b.enter(&mut c);
    let access = MmioAccess { gpa: VIRTIO + 0x70, size: 4, write: true, reg: 3, insn_len: 2 };
    assert_eq!(e, Exit::Mmio(access));
    assert_eq!(c.mmio_value, 0xDEAD_0007, "the value the store writes");
    assert_eq!(mem(&c).vmcb.rd64(off::RIP), ENTRY, "not stepped over until the model answered");
    // The monitor answers (the loop's `complete`), and the next entry steps over it.
    c.completed = Some(MmioDone { access, value: 0 });
    assert_eq!(b.enter(&mut c), Exit::Wait);
    assert_eq!(b.m.seen[1].rip, ENTRY + 2);
    assert!(c.completed.is_none());
}

#[test]
fn a_load_from_a_device_gets_the_answer_in_its_register() {
    let mut b = Bench::new(1);
    let root = b.root();
    let mut c = ctx_for(root, 0);
    // mov ebx, [eax]
    b.m.then(|v| {
        let at = v.vmcb.rd64(off::RIP);
        v.vmcb.wr8(0xD0, 2);
        v.vmcb.wr8(0xD1, 0x8B);
        v.vmcb.wr8(0xD2, 0x18);
        exit(v, code::NPF, 1 << 32, VIRTIO, at + 2);
    })
    .then(hlt);
    let e = b.enter(&mut c);
    let Exit::Mmio(a) = e else { panic!("{e:?}") };
    assert!(!a.write && a.size == 4 && a.reg == 3);
    c.completed = Some(MmioDone { access: a, value: 0x7472_6976 });
    assert_eq!(b.enter(&mut c), Exit::Wait);
    assert_eq!(mem(&c).run.regs.rbx, 0x7472_6976, "\"virt\"");
}

// ── interrupts ──────────────────────────────────────────────────────────

#[test]
fn a_device_line_reaches_the_guest_through_the_ioapic_at_the_next_entry() {
    let mut b = Bench::new(1);
    let root = b.root();
    let mut c = ctx_for(root, 0);
    // The guest enables interrupts and halts; its OS has set the APIC up and routed pin 5.
    b.m.then(|v| {
        let f = v.vmcb.rd64(off::RFLAGS);
        v.vmcb.wr64(off::RFLAGS, f | 1 << 9);
        hlt(v)
    })
    .then(hlt);
    assert_eq!(b.enter(&mut c), Exit::Wait);
    b.host.with_vm(|vm| {
        x2apic_up(vm, 0);
        route(vm, 5, 0x35, 0);
    });
    // The device model raised line 5 (`Vcpu::inject`); the monitor's loop hands it over in `irqs`.
    c.irqs = 1 << 5;
    assert_eq!(b.enter(&mut c), Exit::Wait);
    assert_eq!(c.irqs, 0, "taken");
    let s = b.m.seen[1];
    assert_eq!(s.event_inj & 0xFF, 0x35, "the vector is injected");
    assert_ne!(s.event_inj & ctl::EVENT_VALID, 0);
}

#[test]
fn an_interrupt_the_guest_cannot_take_yet_asks_for_the_window() {
    let mut b = Bench::new(1);
    let root = b.root();
    let mut c = ctx_for(root, 0);
    // The PVH start state has interrupts off. (A `hlt` there would be served as
    // a wake-up, with a vector requested; a tick ends the second entry.)
    b.m.then(hlt).then(|v| exit(v, code::INTR, 0, 0, 0));
    assert_eq!(b.enter(&mut c), Exit::Wait);
    b.host.with_vm(|vm| {
        x2apic_up(vm, 0);
        route(vm, 5, 0x35, 0);
    });
    c.irqs = 1 << 5;
    assert_eq!(b.enter(&mut c), Exit::HostInterrupt);
    let s = b.m.seen[1];
    assert_eq!(s.event_inj & ctl::EVENT_VALID, 0, "nothing injected into a guest with IF clear");
    assert!(s.window, "the exit when it can");
}

// ── the other processors ────────────────────────────────────────────────

#[test]
fn an_application_processor_waits_for_its_startup_ipi_and_then_runs_in_real_mode() {
    let mut b = Bench::new(2);
    let root = b.root();
    let mut bsp = ctx_for(root, 0);
    let mut ap = ctx_for(root, 1);
    b.m.then(hlt);
    assert_eq!(b.enter(&mut bsp), Exit::Wait);
    // No VMRUN for the AP: it has no state to run in.
    assert_eq!(b.enter(&mut ap), Exit::Wait);
    assert_eq!(b.m.seen.len(), 1);
    assert_eq!(*b.host.resets.lock().unwrap(), 1, "only the boot CPU resets the VM's APICs");
    b.host.with_vm(|vm| {
        x2apic_up(vm, 0);
        x2apic_up(vm, 1);
        icr_send(vm, 0, 1 << 32 | 5 << 8 | 1 << 14);
        icr_send(vm, 0, 1 << 32 | 6 << 8 | 1 << 14 | 0x9A);
    });
    b.m.then(hlt);
    assert_eq!(b.enter(&mut ap), Exit::Wait);
    let s = b.m.seen[1];
    assert_eq!((s.rip, s.cs), (0, (0x9A00, 0x9B, 0xFFFF, 0x9A000)), "real mode at vector << 12");
    assert!(s.valid);
    assert_ne!(s.pa, b.m.seen[0].pa, "its own VMCB");
    assert_eq!(s.w3 & icpt::CPUID, icpt::CPUID, "the intercepts the start state resets are still there");
}

#[test]
fn x86_64_an_application_processor_started_after_a_pause_has_the_tsc_the_running_cpu_has() {
    let (first, second) = crate::pause::skips_of_a_vcpu_started_after_a_pause();
    let mut b = Bench::new(2);
    let root = b.root();
    let (mut bsp, mut ap) = (ctx_for(root, 0), ctx_for(root, 1));
    for _ in 0..first.len() + second.len() {
        b.m.then(hlt);
    }
    for &skip in &first {
        bsp.time_skip = skip;
        assert_eq!(b.enter(&mut bsp), Exit::Wait);
        bsp.started = true;
    }
    let bsp_runs = b.m.seen.len();
    // The AP waits for its SIPI with the skip already on its VMCB.
    ap.time_skip = second[0];
    assert_eq!(b.enter(&mut ap), Exit::Wait);
    ap.started = true;
    b.host.with_vm(|vm| {
        x2apic_up(vm, 0);
        x2apic_up(vm, 1);
        icr_send(vm, 0, 1 << 32 | 5 << 8 | 1 << 14);
        icr_send(vm, 0, 1 << 32 | 6 << 8 | 1 << 14 | 0x9A);
    });
    for &skip in &second[1..] {
        ap.time_skip = skip;
        assert_eq!(b.enter(&mut ap), Exit::Wait);
    }
    let offsets: Vec<u64> = b.m.seen.iter().map(|s| s.tsc_offset).collect();
    let held = 0u64.wrapping_sub(40 * TSC_PER_TICK);
    assert_eq!(offsets[bsp_runs - 1], held, "the running CPU's TSC lags by the 40 ticks held");
    assert!(offsets[bsp_runs..].iter().all(|&o| o == held), "the AP started afterwards runs on the same TSC");
    assert_eq!(offsets.len(), first.len() + second.len() - 1);
}

// ── the nested TLB ──────────────────────────────────────────────────────

#[test]
fn the_nested_tlb_is_flushed_when_the_tables_changed_or_another_guest_ran_on_the_cpu() {
    let mut b = Bench::new(2);
    let (r0, r1) = (b.root(), b.root());
    let mut a = ctx_for(r0, 0);
    let mut other = ctx_for(r1, 0);
    b.m.then(hlt).then(hlt).then(hlt).then(hlt).then(hlt).then(hlt);
    assert_eq!(b.enter(&mut a), Exit::Wait);
    assert_eq!(b.m.seen[0].tlb, ctl::TLB_FLUSH_ALL, "the first entry");
    assert_eq!(b.enter(&mut a), Exit::Wait);
    assert_eq!(b.m.seen[1].tlb, ctl::TLB_DO_NOTHING, "same guest, same CPU, same tables: no flush");
    // `stage2_flush` after an unmap.
    flush(1, usize::MAX, &mut |_| {});
    assert_eq!(b.enter(&mut a), Exit::Wait);
    assert_eq!(b.m.seen[2].tlb, ctl::TLB_FLUSH_ASID, "the CPU can flush by ASID");
    assert_eq!(b.enter(&mut a), Exit::Wait);
    assert_eq!(b.m.seen[3].tlb, ctl::TLB_DO_NOTHING, "once");
    // Another guest's vCPU ran here, and this one comes back.
    assert_eq!(b.enter(&mut other), Exit::Wait);
    assert_eq!(b.enter(&mut a), Exit::Wait);
    let last = b.m.seen.len() - 1;
    assert_eq!(b.m.seen[last].tlb, ctl::TLB_FLUSH_ASID, "its translations may be another guest's");
}

#[test]
fn a_flush_makes_the_cpu_that_runs_the_guest_leave_it_and_waits_for_that() {
    let mut b = Bench::new(1);
    let root = b.root();
    let mut c = ctx_for(root, 0);
    let done = Arc::new(AtomicBool::new(false));
    let thread = Arc::new(Mutex::new(None));
    let (done2, thread2) = (done.clone(), thread.clone());
    // While the guest runs on CPU 0, CPU 1 unmaps and flushes.
    b.m.then(move |v| {
        let (tx, rx) = std::sync::mpsc::channel();
        let done3 = done2.clone();
        let t = std::thread::spawn(move || {
            flush(1, 1, &mut |cpu| tx.send(cpu).unwrap());
            done3.store(true, Ordering::SeqCst);
        });
        assert_eq!(rx.recv().unwrap(), 0, "the CPU that runs the guest is the one kicked");
        assert!(!done2.load(Ordering::SeqCst), "the flush waits for the guest to leave");
        *thread2.lock().unwrap() = Some(t);
        // The kick has landed: the guest exits.
        hlt(v)
    });
    assert_eq!(b.enter(&mut c), Exit::Wait);
    thread.lock().unwrap().take().unwrap().join().unwrap();
    assert!(done.load(Ordering::SeqCst), "and returns once it has");
}

// ── lifetime ────────────────────────────────────────────────────────────

#[test]
fn a_vcpu_that_starts_again_reuses_its_pages_and_starts_over() {
    let mut b = Bench::new(1);
    let root = b.root();
    let mut c = ctx_for(root, 0);
    b.m.then(|v| {
        v.vmcb.wr64(off::RIP, 0x7777);
        hlt(v)
    });
    assert_eq!(b.enter(&mut c), Exit::Wait);
    let pages = b.host.pages.lock().unwrap().len();
    let first = c.frame[0];
    // The monitor starts the vCPU again: a new context, the same stage-2 root.
    let mut again = ctx_for(root, 0);
    b.m.then(hlt);
    assert_eq!(b.enter(&mut again), Exit::Wait);
    assert_eq!(again.frame[0], first, "the slot is the vCPU's");
    assert_eq!(b.host.pages.lock().unwrap().len(), pages, "nothing allocated");
    assert_eq!(b.m.seen[1].rip, ENTRY, "the start state, not where the last run stopped");
}

#[test]
fn destroying_the_vm_gives_back_its_pages_and_its_interrupt_controllers() {
    let mut b = Bench::new(1);
    let root = b.root();
    let mut c = ctx_for(root, 0);
    b.m.then(hlt);
    assert_eq!(b.enter(&mut c), Exit::Wait);
    let pa = c.frame[0];
    slots_release(&b.host, root);
    let freed = b.host.freed.lock().unwrap().clone();
    assert_eq!(freed, vec![(pa, vcpu::vcpu_pages(FP_BYTES))]);
    assert_eq!(*b.host.released.lock().unwrap(), vec![1]);
    // Released once: a second destroy finds nothing.
    slots_release(&b.host, root);
    assert_eq!(b.host.freed.lock().unwrap().len(), 1);
}

// ── the FP state and XCR0 ───────────────────────────────────────────────

#[test]
fn the_guests_xcr0_is_what_it_set_and_nothing_else_the_host_offers() {
    let mut b = Bench::new(1);
    let root = b.root();
    let mut c = ctx_for(root, 0);
    b.m.then(|v| {
        // XSETBV to 7 (x87, SSE, AVX) with CR4.OSXSAVE set.
        let at = v.vmcb.rd64(off::CR4);
        v.vmcb.wr64(off::CR4, at | 1 << 18);
        v.vmcb.wr64(off::RAX, 7);
        v.run.regs.rdx = 0;
        v.run.regs.rcx = 0;
        let rip = v.vmcb.rd64(off::RIP);
        exit(v, code::XSETBV, 0, 0, rip + 3);
    })
    .then(|v| {
        // And a write the CPUID does not offer (AVX-512 components) is a #GP.
        v.vmcb.wr64(off::RAX, 0xE7);
        v.run.regs.rcx = 0;
        let rip = v.vmcb.rd64(off::RIP);
        exit(v, code::XSETBV, 0, 0, rip + 3)
    })
    .then(hlt);
    assert_eq!(b.enter(&mut c), Exit::Wait);
    assert_eq!(b.m.seen[0].xcr0, 1);
    assert_eq!(b.m.seen[1].xcr0, 7, "loaded around the next VMRUN");
    assert_eq!(b.m.seen[2].xcr0, 7, "the refused write changed nothing");
    assert_eq!(b.m.seen[2].event_inj & 0xFF, 13, "#GP");
}

#[test]
fn the_vcpu_is_one_run_of_pages_with_the_fp_area_behind_the_state() {
    // The slot is the VMCB page, the host-save page, the state page, then the FP area.
    assert_eq!(vcpu::fp_offset(), 3 * PAGE);
    assert_eq!(vcpu::vcpu_pages(FP_BYTES), 4);
    assert_eq!(vcpu::vcpu_pages(PAGE), 4);
    assert_eq!(vcpu::vcpu_pages(PAGE + 1), 5);
    assert_eq!(std::mem::offset_of!(VcpuMem, host_save), PAGE);
}

#[test]
fn the_time_a_vcpu_was_held_comes_off_its_tsc_on_top_of_what_the_guest_set() {
    let mut b = Bench::new(1);
    let root = b.root();
    let mut c = ctx_for(root, 0);
    // The guest writes its TSC after the second entry (`WRMSR`): the offset is its own then.
    b.m.then(hlt).then(hlt).then(|v| {
        v.vmcb.wr64(off::TSC_OFFSET, 5000);
        hlt(v)
    });
    b.m.then(hlt).then(hlt);
    assert_eq!(b.enter(&mut c), Exit::Wait);
    c.started = true;
    c.time_skip = 100;
    assert_eq!(b.enter(&mut c), Exit::Wait);
    c.time_skip = 0;
    assert_eq!(b.enter(&mut c), Exit::Wait);
    c.time_skip = 10;
    assert_eq!(b.enter(&mut c), Exit::Wait);
    c.time_skip = 0;
    assert_eq!(b.enter(&mut c), Exit::Wait);
    let seen: Vec<u64> = b.m.seen.iter().map(|s| s.tsc_offset).collect();
    assert_eq!(
        seen,
        [0, 0u64.wrapping_sub(100 * TSC_PER_TICK), 0u64.wrapping_sub(100 * TSC_PER_TICK), 5000 - 10 * TSC_PER_TICK, 5000 - 10 * TSC_PER_TICK],
        "ticks become TSC cycles; the offset keeps what the guest wrote; nothing held, nothing moved"
    );
}

// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The running half of the monitor: RAM and the trap page attached to a VM,
//! the start and stop of its vCPUs, the vCPU loop, the routing of a guest's
//! device access to the trap ring, and the envelope's ceiling on what a guest
//! may cause.
//!
//! The guest is a script (`ScriptHv`): each entry answers the next exit. The
//! device model is the far end of a page this file writes out from the layout
//! (`Page::model_*`), not the monitor's own code; the real device models are
//! tested against the real monitor in `tests/host/vmmd-tests`.

use crate::fakes::{Page, ScriptHv};
use azos_arch_api::{Exit, GuestCtx, HvKind, HvStatus, MmioAccess, MmioDone, Stage2Root};
use azos_decision::{Rule, Verdict};
use azos_hv::admit::{self, HostFacts, VirtRole};
use azos_hv::backend::{self, Backend, Reach};
use azos_hv::ring::{seq_of, seq_vcpu, Full, Mailbox, RawPage};
use azos_hv::run::{self, fault, route_mmio, PostError, RunHost, RunView, Routed, Stop};
use azos_hv::trapwire::{cpl, Completion, Trap, TRAPS};
use azos_hv::vcpu::{pick_hart, RunState};
use azos_hv::vm::{RamError, RamSeg, Space, StartError, VmState, VmTable};
use azos_topology::{parse_caps, parse_sched, Envelope, Topology};
use std::collections::VecDeque;

const MIB: u64 = 1 << 20;
const BLK: u64 = 0x1000_1000;
const NET: u64 = 0x1000_2000;
const CON: u64 = 0x1000_3000;

fn topology(body: &str) -> Box<Topology<'static>> {
    let sched: &'static str = "[class.best_effort]\ncpu_budget_min_pct = 5\npolicy = \"fair\"\n";
    let caps: &'static str = Box::leak(format!("format = 7\n{body}").into_boxed_str());
    let mut t = Box::new(Topology::empty());
    parse_sched(sched.as_bytes(), &mut t).unwrap();
    parse_caps(caps.as_bytes(), &mut t).unwrap_or_else(|e| panic!("{e:?}\n{body}"));
    t
}

/// One guest (2 CPUs, 16 MiB, blk / net / console) on a 4-hart machine with
/// `rt` real-time harts; admitted, not created.
pub(crate) fn table(envelope: &str, rt: u64) -> VmTable {
    let t = topology(&format!(
        "[guest.g]\ncpus = 2\nmem_mib = 16\nenvelope = \"{envelope}\"\ndevices = [\"virtio-blk\", \"virtio-net\", \"virtio-console\"]\n"
    ));
    let facts = HostFacts {
        role: VirtRole::Hosted,
        hv: HvStatus::Usable(HvKind::RiscvH),
        online: 0b1111,
        rt,
        free_mib: 1024,
        max_guest_mib: 1024,
    };
    let plan = admit::admit(t.guests(), &facts).unwrap();
    let mut vms = VmTable::new();
    vms.install(t.guests(), &plan, HvKind::RiscvH).unwrap();
    vms
}

fn create(vms: &mut VmTable) {
    vms.vm_mut(0).unwrap().created(Stage2Root { root: 0, aux: 0 }).unwrap();
}

/// All of a created VM's RAM attached and its trap page there: it may start.
pub(crate) fn ready(vms: &mut VmTable) {
    create(vms);
    let (base, bytes) = {
        let v = vms.vm(0).unwrap();
        (v.ram_base, v.ram_bytes())
    };
    vms.check_ram(0, &[], base, bytes).unwrap();
    vms.ram_added(0, bytes);
    vms.traps_attached(0).unwrap();
}

fn windows(vms: &mut VmTable) {
    for (i, base) in [BLK, NET, CON].into_iter().enumerate() {
        vms.add_window(0, Space::Mmio, base, 0x200, i as u8).unwrap();
    }
}

#[test]
fn a_fence_or_timer_left_on_a_vcpu_does_not_outlive_its_thread_or_its_start() {
    use azos_arch_api::RemoteFence;
    use azos_hv::vcpu::TIMER_NEVER;
    let whole = RemoteFence::Tlb { start: 0, size: u64::MAX, asid: None };
    let mut vms = table("full", 0);
    ready(&mut vms);
    vms.start(0, 1, true, 0b1111, 0, 0).unwrap();
    // The thread ends with a fence asked of it and a timer armed: a sender
    // waiting on it is released (not Running), and nothing is left over.
    let c = vms.vcpu_mut(0, 1).unwrap();
    c.request_fence(whole);
    c.arm_timer(5, 6);
    vms.ended(0, 1, None, 0);
    let c = vms.vcpu(0, 1).unwrap();
    assert!(!c.fence_pending());
    assert_eq!((c.timer_deadline(), c.levels(u64::MAX - 1)), (TIMER_NEVER, 0));
    // One asked while it was stopped (it had ended, the sender had not seen)
    // is not carried into the next start.
    let c = vms.vcpu_mut(0, 1).unwrap();
    c.request_fence(whole);
    c.arm_timer(5, 6);
    vms.start(0, 1, true, 0b1111, 0, 0).unwrap();
    let c = vms.vcpu(0, 1).unwrap();
    assert!(!c.fence_pending());
    assert_eq!(c.timer_deadline(), TIMER_NEVER);
}

// ── the backends a row names ────────────────────────────────────────────

#[test]
fn the_row_names_which_backend_sits_at_which_index() {
    let vms = table("full", 0);
    let v = vms.vm(0).unwrap();
    assert_eq!(v.backend(0), Some(Backend::Blk));
    assert_eq!(v.backend(1), Some(Backend::Net));
    assert_eq!(v.backend(2), Some(Backend::Console));
    assert_eq!(v.backend(3), None, "the row lists three");
    // The word `Vm::config` hands the monitor: 4 bits a backend, device 0 lowest.
    assert_eq!(v.kinds, 1 | 2 << 4 | 3 << 8);
    assert_eq!(backend::kind_at(v.kinds, 2), Some(Backend::Console));
    assert_eq!(backend::kind_at(v.kinds, 3), None);
    assert_eq!(backend::kind_at(v.kinds, 16), None);
    for b in Backend::ALL {
        assert_eq!(Backend::from_name(b.name().as_bytes()), Some(b));
        assert_eq!(Backend::from_code(b as u8), Some(b));
    }
    assert_eq!(Backend::from_name(b"virtio-gpu"), None);
    assert_eq!(Backend::from_code(0), None);
}

#[test]
fn the_envelope_is_a_ceiling_on_how_far_a_backend_reaches() {
    use Reach::*;
    // (envelope, reaches allowed, reaches refused)
    let rows: [(Envelope, &[Reach], &[Reach]); 4] = [
        (Envelope::Full, &[Inert, Console, Disk, Net, Physical], &[]),
        (Envelope::Cautious, &[Inert, Console, Disk, Net], &[Physical]),
        (Envelope::Slow, &[Inert, Console, Disk], &[Net, Physical]),
        (Envelope::Contained, &[Inert], &[Console, Disk, Net, Physical]),
    ];
    for (e, yes, no) in rows {
        for r in yes {
            assert!(backend::allows(e, *r), "{e:?} allows {r:?}");
        }
        for r in no {
            assert!(!backend::allows(e, *r), "{e:?} refuses {r:?}");
        }
    }
    assert_eq!(Backend::Blk.reach(), Disk);
    assert_eq!(Backend::Net.reach(), Net);
    assert_eq!(Backend::Gpio.reach(), Physical);
    assert_eq!(Backend::Rng.reach(), Inert);
}

// ── RAM and the trap page ───────────────────────────────────────────────

#[test]
fn ram_attaches_inside_the_vm_window_and_never_twice() {
    let mut vms = table("full", 0);
    let (base, total) = {
        let v = vms.vm(0).unwrap();
        (v.ram_base, v.ram_bytes())
    };
    assert_eq!(total, 16 * MIB);
    assert_eq!(vms.check_ram(0, &[], base, MIB), Err(RamError::NotCreated), "an admitted VM has no tables to map into");
    create(&mut vms);
    let mut segs = Vec::new();
    // Two chunks, out of order, then the rest.
    for (gpa, bytes) in [(base + 4 * MIB, MIB), (base, MIB)] {
        vms.check_ram(0, &segs, gpa, bytes).unwrap();
        vms.ram_added(0, bytes);
        segs.push(RamSeg { gpa, bytes });
    }
    assert_eq!(vms.vm(0).unwrap().ram_attached, 2 * MIB);
    // Overlap, by one page, either way round.
    assert_eq!(vms.check_ram(0, &segs, base + MIB - 4096, 8192), Err(RamError::Overlap));
    assert_eq!(vms.check_ram(0, &segs, base + 3 * MIB, 2 * MIB), Err(RamError::Overlap));
    // Outside the window: below, past the end, straddling it, wrapping.
    assert_eq!(vms.check_ram(0, &segs, base - 4096, 4096), Err(RamError::OutOfRange));
    assert_eq!(vms.check_ram(0, &segs, base + total, 4096), Err(RamError::OutOfRange));
    assert_eq!(vms.check_ram(0, &segs, base + total - 4096, 8192), Err(RamError::OutOfRange));
    assert_eq!(vms.check_ram(0, &segs, u64::MAX - 4095, 8192), Err(RamError::OutOfRange));
    // Whole pages.
    assert_eq!(vms.check_ram(0, &segs, base + 8 * MIB + 1, 4096), Err(RamError::Misaligned));
    assert_eq!(vms.check_ram(0, &segs, base + 8 * MIB, 100), Err(RamError::Misaligned));
    assert_eq!(vms.check_ram(0, &segs, base + 8 * MIB, 0), Err(RamError::Misaligned));
    assert_eq!(vms.check_ram(3, &segs, base, 4096), Err(RamError::NoSuchVm));
}

#[test]
fn the_trap_page_attaches_once_and_only_to_a_created_vm() {
    use azos_hv::vm::BadState;
    let mut vms = table("full", 0);
    assert!(vms.traps_attached(0).is_err(), "an admitted VM has no tables");
    create(&mut vms);
    vms.traps_attached(0).unwrap();
    assert_eq!(vms.traps_attached(0), Err(BadState { from: VmState::Created }), "a second page would orphan the first");
    assert!(vms.vm(0).unwrap().traps);
}

#[test]
fn windows_are_closed_to_changes_while_a_vcpu_runs() {
    use azos_hv::vm::WindowError;
    let mut vms = table("full", 0);
    ready(&mut vms);
    vms.add_window(0, Space::Mmio, BLK, 0x200, 0).unwrap();
    vms.start(0, 0, true, 0b1111, 0, 0).unwrap();
    assert_eq!(vms.add_window(0, Space::Mmio, NET, 0x200, 1), Err(WindowError::Running));
    vms.ended(0, 0, None, 0);
    vms.add_window(0, Space::Mmio, NET, 0x200, 1).unwrap();
}

// ── starting and stopping a vCPU ────────────────────────────────────────

#[test]
fn a_vcpu_starts_only_when_the_vm_is_whole_and_the_isa_can_run_it() {
    let mut vms = table("full", 0);
    assert_eq!(vms.start(0, 0, true, 0b1111, 0, 0), Err(StartError::NotCreated));
    create(&mut vms);
    // The ISA's entry is not wired: nothing starts, whatever else is there.
    assert_eq!(vms.start(0, 0, false, 0b1111, 0, 0), Err(StartError::NoEntry));
    // No RAM, no trap page.
    assert_eq!(vms.start(0, 0, true, 0b1111, 0, 0), Err(StartError::NotReady));
    let (base, total) = (vms.vm(0).unwrap().ram_base, vms.vm(0).unwrap().ram_bytes());
    vms.check_ram(0, &[], base, total - 4096).unwrap();
    vms.ram_added(0, total - 4096);
    vms.traps_attached(0).unwrap();
    assert_eq!(vms.start(0, 0, true, 0b1111, 0, 0), Err(StartError::NotReady), "a page of RAM short");
    vms.ram_added(0, 4096);
    assert_eq!(vms.start(0, 5, true, 0b1111, 0, 0), Err(StartError::NoSuchVcpu));
    assert!(vms.start(0, 0, true, 0b1111, 0, 0).is_ok());
    assert_eq!(vms.vcpu(0, 0).unwrap().run_state(), RunState::Running);
    assert_eq!(vms.vcpu(0, 1).unwrap().run_state(), RunState::Stopped, "the other vCPU waits for its own start");
    assert_eq!(vms.start(0, 0, true, 0b1111, 0, 0), Err(StartError::Running));
}

#[test]
fn a_vcpu_is_never_placed_on_a_real_time_hart() {
    // Harts 0..3; hart 1 and 2 hold deadline reservations.
    let rt = 0b0110;
    let mut vms = table("full", rt);
    ready(&mut vms);
    // Admission already took them out of the affinity.
    assert_eq!(vms.vcpu(0, 0).unwrap().affinity, 0b1001);
    // A vCPU whose affinity names only reserved harts has nowhere to go.
    vms.vcpu_mut(0, 0).unwrap().affinity = 0b0110;
    assert_eq!(vms.start(0, 0, true, 0b1111, rt, 0), Err(StartError::NoHart));
    assert_eq!(vms.vcpu(0, 0).unwrap().run_state(), RunState::Stopped, "a refused start leaves it stopped");
    // One reserved, one free: the free one.
    vms.vcpu_mut(0, 0).unwrap().affinity = 0b1010;
    assert_eq!(vms.start(0, 0, true, 0b1111, rt, 0), Ok(3));
    // The offline ones do not count either.
    vms.vcpu_mut(0, 1).unwrap().affinity = 0b1000;
    assert_eq!(vms.start(0, 1, true, 0b0111, rt, 0), Err(StartError::NoHart));
}

#[test]
fn the_vcpus_of_a_vm_spread_over_the_harts_it_may_use() {
    // Harts 0 and 3 are free; vCPU 0 takes the first, vCPU 1 the second,
    // vCPU 2 starts over.
    let (aff, online, rt) = (0b1111, 0b1111, 0b0110);
    assert_eq!(pick_hart(aff, online, rt, 0), Some(0));
    assert_eq!(pick_hart(aff, online, rt, 1), Some(3));
    assert_eq!(pick_hart(aff, online, rt, 2), Some(0));
    assert_eq!(pick_hart(0b0110, online, rt, 0), None);
    assert_eq!(pick_hart(0, online, rt, 0), None);
}

#[test]
fn stop_is_a_request_the_thread_answers_and_a_running_vm_cannot_be_destroyed() {
    let mut vms = table("full", 0);
    ready(&mut vms);
    assert_eq!(vms.stop(0, 0), Err(StartError::NotRunning));
    vms.start(0, 0, true, 0b1111, 0, 0).unwrap();
    assert!(vms.any_running(0));
    assert!(vms.destroyed(0).is_err(), "the guest's memory is mapped under a thread");
    vms.stop(0, 0).unwrap();
    assert!(vms.vcpu(0, 0).unwrap().stop_requested());
    assert_eq!(vms.vcpu(0, 0).unwrap().run_state(), RunState::Running, "until the thread says so");
    vms.ended(0, 0, None, 0);
    assert_eq!(vms.vcpu(0, 0).unwrap().run_state(), RunState::Stopped);
    assert!(!vms.vcpu(0, 0).unwrap().stop_requested());
    // A fault is a stop that says why, and the vCPU may be started again.
    vms.start(0, 0, true, 0b1111, 0, 0).unwrap();
    vms.ended(0, 0, Some(run::fault_code(&Exit::Hypercall)), 0);
    let c = vms.vcpu(0, 0).unwrap();
    assert_eq!((c.run_state(), c.fault() >> 56), (RunState::Faulted, fault::HYPERCALL));
    vms.start(0, 0, true, 0b1111, 0, 0).unwrap();
    assert_eq!(vms.vcpu(0, 0).unwrap().fault(), 0);
    vms.ended(0, 0, None, 0);
    // Now it can go; everything attached goes with it.
    vms.destroyed(0).unwrap();
    let v = vms.vm(0).unwrap();
    assert_eq!((v.state, v.ram_attached, v.traps, v.nic), (VmState::Admitted, 0, false, false));
}

#[test]
fn the_nic_ring_attaches_once() {
    let mut vms = table("cautious", 0);
    assert!(vms.nic_attached(0).is_err());
    create(&mut vms);
    assert!(vms.egress_allowed(0, Reach::Net));
    vms.nic_attached(0).unwrap();
    assert!(vms.nic_attached(0).is_err());
    assert!(!table("slow", 0).egress_allowed(0, Reach::Net), "the caller asks before it attaches");
    assert!(!table("contained", 0).egress_allowed(0, Reach::Console));
}

// ── the rings ───────────────────────────────────────────────────────────

fn trap(seq: u32, vcpu: u8, write: bool, gpa: u64, data: u64) -> Trap {
    Trap { seq, vcpu, write, len: 4, gpa, data }
}

#[test]
fn a_trap_posted_is_the_record_the_far_end_reads() {
    let mut page = Page::new();
    let mut raw = unsafe { RawPage::new(page.ptr()) };
    let t = trap(seq_of(5, 1), 1, true, BLK + 0x50, 0xAB);
    raw.post_trap(&t).unwrap();
    drop(raw);
    // The far end reads it by the layout, not by the monitor's code.
    assert_eq!(page.model_pop_trap(), Some(t));
    assert_eq!(page.model_pop_trap(), None);
    assert_eq!(seq_vcpu(t.seq), 1);
}

#[test]
fn the_ring_is_full_at_traps_and_a_hostile_consumer_index_is_full_too() {
    let mut page = Page::new();
    let mut raw = unsafe { RawPage::new(page.ptr()) };
    for i in 0..TRAPS {
        raw.post_trap(&trap(i, 0, false, BLK, 0)).unwrap();
    }
    assert_eq!(raw.post_trap(&trap(99, 0, false, BLK, 0)), Err(Full));
    drop(raw);
    // The far end takes one: room for exactly one.
    page.model_pop_trap().unwrap();
    let mut raw = unsafe { RawPage::new(page.ptr()) };
    raw.post_trap(&trap(100, 0, false, BLK, 0)).unwrap();
    assert_eq!(raw.post_trap(&trap(101, 0, false, BLK, 0)), Err(Full));
    drop(raw);
    // A head that ran ahead of the tail is nonsense; nothing is overwritten.
    let tail = page.word(azos_hv::trapwire::TRAP_TAIL);
    page.set_word(azos_hv::trapwire::TRAP_HEAD, tail.wrapping_add(10));
    let mut raw = unsafe { RawPage::new(page.ptr()) };
    assert_eq!(raw.post_trap(&trap(102, 0, false, BLK, 0)), Err(Full));
}

#[test]
fn completions_go_to_the_vcpu_they_answer_whatever_order_they_come_in() {
    let mut page = Page::new();
    let mut mb = Mailbox::new();
    let (s0, s1) = (mb.next_seq(0, 0), mb.next_seq(0, 1));
    assert_ne!(s0, s1);
    assert_eq!((seq_vcpu(s0), seq_vcpu(s1)), (0, 1));
    mb.expect(0, s0);
    mb.expect(1, s1);
    // vCPU 1's answer first; one for a sequence nobody waits for; then vCPU 0's.
    page.model_push_completion(&Completion { seq: s1, status: cpl::OK, data: 11 });
    page.model_push_completion(&Completion { seq: seq_of(77, 0), status: cpl::OK, data: 99 });
    page.model_push_completion(&Completion { seq: s0, status: cpl::OK, data: 10 });
    let mut raw = unsafe { RawPage::new(page.ptr()) };
    assert_eq!(mb.take(0), None, "nothing is taken until the ring is read");
    mb.fill(&mut raw, 0, 2);
    assert_eq!(mb.take(0).map(|c| c.data), Some(10), "the stray one did not replace it");
    assert_eq!(mb.take(1).map(|c| c.data), Some(11));
    assert_eq!(mb.take(0), None);
    // A vCPU that stopped while it waited takes nothing that comes late.
    let s = mb.next_seq(0, 0);
    mb.expect(0, s);
    mb.forget(0);
    drop(raw);
    page.model_push_completion(&Completion { seq: s, status: cpl::OK, data: 5 });
    let mut raw = unsafe { RawPage::new(page.ptr()) };
    mb.fill(&mut raw, 0, 2);
    assert_eq!(mb.take(0), None);
    // The next trap of that vCPU has a number no earlier answer can match.
    assert_ne!(mb.next_seq(0, 0), s);
}

/// The vCPU byte of a completion is written by the ring-3 monitor. One that
/// names a vCPU past the VM's own is dropped even when the slot it lands on
/// (`base + byte`, the next VM's) happens to wait for exactly that number.
#[test]
fn a_completion_naming_a_vcpu_past_the_vm_is_dropped() {
    let mut page = Page::new();
    let mut mb = Mailbox::new();
    // A VM of one vCPU at slot 0; slot 1 belongs to the next VM, and waits for
    // a number whose vCPU byte is 1.
    let past = seq_of(7, 1);
    mb.expect(1, past);
    page.model_push_completion(&Completion { seq: past, status: cpl::OK, data: 66 });
    let mut raw = unsafe { RawPage::new(page.ptr()) };
    mb.fill(&mut raw, 0, 1);
    assert_eq!(mb.take(1), None, "the byte past the VM's vCPUs reached the next VM's slot");
    // The same completion, from a VM that does own vCPU 1, is delivered: the
    // bound is the count, not a blanket refusal.
    drop(raw);
    page.model_push_completion(&Completion { seq: past, status: cpl::OK, data: 67 });
    let mut raw = unsafe { RawPage::new(page.ptr()) };
    mb.fill(&mut raw, 0, 2);
    assert_eq!(mb.take(1).map(|c| c.data), Some(67));
}

#[test]
fn the_tables_mailbox_numbers_and_delivers_by_vm_and_vcpu() {
    let mut vms = table("full", 0);
    ready(&mut vms);
    let mut page = Page::new();
    let (s0, s1) = (vms.next_seq(0, 0), vms.next_seq(0, 1));
    assert_ne!(s0, s1);
    assert_eq!((seq_vcpu(s0), seq_vcpu(s1)), (0, 1));
    assert_eq!(vms.next_seq(0, 2), 0, "a VM of two vCPUs has no third");
    assert_eq!(vms.next_seq(5, 0), 0, "nor a sixth VM");
    vms.expect(0, 0, s0);
    vms.expect(0, 1, s1);
    page.model_push_completion(&Completion { seq: s1, status: cpl::OK, data: 21 });
    let mut raw = unsafe { RawPage::new(page.ptr()) };
    vms.collect(0, &mut raw);
    assert_eq!(vms.answer(0, 0), None);
    assert_eq!(vms.answer(0, 1).map(|c| c.data), Some(21));
    assert_eq!(vms.answer(0, 1), None, "taken once");
    // Taking the VM apart forgets the numbering and what anyone waited for.
    vms.expect(0, 0, s0);
    vms.destroyed(0).unwrap();
    assert!(vms.next_seq(0, 0) <= s0, "numbering starts over with the VM");
}

// ── the route of a decoded access ───────────────────────────────────────

pub(crate) fn view(envelope: &str) -> RunView {
    let mut vms = table(envelope, 0);
    create(&mut vms);
    windows(&mut vms);
    RunView::new(vms.vm(0).unwrap())
}

pub(crate) fn access(gpa: u64, write: bool, size: u8) -> MmioAccess {
    MmioAccess { gpa, size, write, reg: 10, insn_len: 4 }
}

#[test]
fn an_access_in_a_window_becomes_a_trap_with_the_value_the_guest_stored() {
    let v = view("full");
    let r = route_mmio(&v, 1, &access(BLK + 0x50, true, 4), 0xDEAD_BEEF_1234_5678, 9);
    assert_eq!(r, Routed::Post(Trap { seq: 9, vcpu: 1, write: true, len: 4, gpa: BLK + 0x50, data: 0x1234_5678 }));
    // A load carries no data; a byte store only its byte.
    assert_eq!(
        route_mmio(&v, 0, &access(NET, false, 4), 0xFFFF, 1),
        Routed::Post(Trap { seq: 1, vcpu: 0, write: false, len: 4, gpa: NET, data: 0 })
    );
    let Routed::Post(t) = route_mmio(&v, 0, &access(CON, true, 1), 0x1FF, 2) else { panic!() };
    assert_eq!(t.data, 0xFF);
    let Routed::Post(t) = route_mmio(&v, 0, &access(CON, true, 8), u64::MAX, 2) else { panic!() };
    assert_eq!(t.data, u64::MAX);
}

#[test]
fn an_access_outside_every_window_reads_zero_and_posts_nothing() {
    let v = view("full");
    for gpa in [0, BLK - 1, BLK + 0x200, CON + 0x200, 0x8000_0000] {
        assert_eq!(route_mmio(&v, 0, &access(gpa, false, 4), 0, 1), Routed::NoDevice(0), "{gpa:#x}");
        assert_eq!(route_mmio(&v, 0, &access(gpa, true, 4), 7, 1), Routed::NoDevice(0), "{gpa:#x}");
    }
    // The last byte of a window is inside it.
    assert!(matches!(route_mmio(&v, 0, &access(BLK + 0x1FF, false, 1), 0, 1), Routed::Post(_)));
}

#[test]
fn a_store_past_the_envelope_is_refused_and_a_load_is_not() {
    // (envelope, windows whose stores are refused)
    let rows = [("full", &[][..]), ("cautious", &[][..]), ("slow", &[NET][..]), ("contained", &[BLK, NET, CON][..])];
    for (env, refused) in rows {
        let v = view(env);
        for (gpa, b) in [(BLK, Backend::Blk), (NET, Backend::Net), (CON, Backend::Console)] {
            let store = route_mmio(&v, 0, &access(gpa, true, 4), 1, 1);
            if refused.contains(&gpa) {
                assert_eq!(store, Routed::Refused { backend: b, gpa }, "{env}: store to {b:?}");
            } else {
                assert!(matches!(store, Routed::Post(_)), "{env}: store to {b:?} passes");
            }
            // Reading the device causes nothing outside the guest.
            assert!(matches!(route_mmio(&v, 0, &access(gpa, false, 4), 0, 1), Routed::Post(_)), "{env}: load from {b:?}");
        }
    }
}

// ── the loop ────────────────────────────────────────────────────────────

/// The kernel as the loop sees it, over a page and a scripted device model.
struct Host {
    page: Page,
    mailbox: Mailbox,
    /// Wake-ups the event port has been signalled for.
    events: u32,
    /// `stop_requested` answers true from this many calls on.
    stop_after: Option<u32>,
    calls: u32,
    irqs: VecDeque<u64>,
    parks: u32,
    yields: u32,
    /// What the device model answers a trap with (None: nothing yet).
    model: Box<dyn FnMut(&Trap) -> Option<Completion>>,
    /// Traps the model has seen, in order.
    seen: Vec<Trap>,
    gone: bool,
}

impl Host {
    fn new(model: impl FnMut(&Trap) -> Option<Completion> + 'static) -> Host {
        Host {
            page: Page::new(),
            mailbox: Mailbox::new(),
            events: 0,
            stop_after: None,
            calls: 0,
            irqs: VecDeque::new(),
            parks: 0,
            yields: 0,
            model: Box::new(model),
            seen: Vec::new(),
            gone: false,
        }
    }

    /// A model that serves every load with `0x1000 + gpa offset` and every
    /// store with OK.
    fn echo() -> Host {
        Host::new(|t| Some(Completion { seq: t.seq, status: cpl::OK, data: if t.write { 0 } else { 0x1000 + (t.gpa & 0xFFF) } }))
    }
}

impl RunHost for Host {
    fn stop_requested(&mut self) -> bool {
        self.calls += 1;
        self.stop_after.is_some_and(|n| self.calls > n)
    }
    fn take_irqs(&mut self) -> u64 {
        self.irqs.pop_front().unwrap_or(0)
    }
    fn next_seq(&mut self, vcpu: u8) -> u32 {
        self.mailbox.next_seq(0, vcpu)
    }
    fn post(&mut self, t: &Trap) -> Result<(), PostError> {
        if self.gone {
            return Err(PostError::Gone);
        }
        let mut raw = unsafe { RawPage::new(self.page.ptr()) };
        raw.post_trap(t).map_err(|Full| PostError::Full)?;
        self.mailbox.expect(t.vcpu as usize, t.seq);
        self.events += 1;
        Ok(())
    }
    fn answer(&mut self) -> Option<Completion> {
        // The device model runs when the vCPU sleeps.
        while let Some(t) = self.page.model_pop_trap() {
            self.seen.push(t);
            if let Some(c) = (self.model)(&t) {
                self.page.model_push_completion(&c);
            }
        }
        let mut raw = unsafe { RawPage::new(self.page.ptr()) };
        self.mailbox.fill(&mut raw, 0, 1);
        // One vCPU in these tests.
        self.mailbox.take(0)
    }
    fn park(&mut self) {
        self.parks += 1;
    }
    fn yield_now(&mut self) {
        self.yields += 1;
    }
}

fn ctx() -> GuestCtx {
    GuestCtx::new(Stage2Root { root: 0, aux: 0 }, 1, 0, 0x8000_0000, 0)
}

fn mmio(gpa: u64, write: bool) -> Exit {
    Exit::Mmio(access(gpa, write, 4))
}

#[test]
fn a_device_access_reaches_the_model_and_its_answer_reaches_the_guest() {
    // The guest stores 0x77 to the block device, loads from the console, then
    // calls the firmware (which nothing serves yet).
    let hv = ScriptHv::new(vec![(mmio(BLK + 0x50, true), 0x77), (mmio(CON + 4, false), 0), (Exit::Hypercall, 0)]);
    let mut host = Host::echo();
    let mut c = ctx();
    let stop = run::run(&hv, &mut c, &view("full"), &mut host);
    assert_eq!(stop, Stop::Fault(fault::HYPERCALL << 56));
    // The model saw both, in order, with the store's value.
    assert_eq!(host.seen.len(), 2);
    assert_eq!((host.seen[0].write, host.seen[0].gpa, host.seen[0].data, host.seen[0].len), (true, BLK + 0x50, 0x77, 4));
    assert_eq!((host.seen[1].write, host.seen[1].gpa), (false, CON + 4));
    assert_eq!(host.events, 2, "the port is signalled once a trap");
    // What the ISA was told at each entry: nothing the first time; the store
    // done; the load done, with the model's value.
    let seen = hv.seen.lock().unwrap();
    assert_eq!(seen.len(), 3);
    assert_eq!((seen[0].completed, seen[0].started), (None, false));
    let store = access(BLK + 0x50, true, 4);
    assert_eq!(seen[1].completed, Some(MmioDone { access: store, value: 0 }));
    assert!(seen[1].started);
    let load = access(CON + 4, false, 4);
    assert_eq!(seen[2].completed, Some(MmioDone { access: load, value: 0x1004 }));
}

#[test]
fn a_load_is_truncated_to_the_width_the_guest_asked() {
    let hv = ScriptHv::new(vec![(Exit::Mmio(access(BLK, false, 1)), 0), (Exit::Cpuid, 0)]);
    let mut host = Host::new(|t| Some(Completion { seq: t.seq, status: cpl::OK, data: 0x1122_3344_5566_7788 }));
    let stop = run::run(&hv, &mut ctx(), &view("full"), &mut host);
    assert_eq!(stop, Stop::Fault(fault::CPUID << 56));
    assert_eq!(hv.seen.lock().unwrap()[1].completed.unwrap().value, 0x88);
}

#[test]
fn a_model_that_says_no_device_reads_zero() {
    let hv = ScriptHv::new(vec![(mmio(BLK, false), 0), (Exit::Shutdown, 0)]);
    let mut host = Host::new(|t| Some(Completion { seq: t.seq, status: cpl::NO_DEVICE, data: 0xFFFF }));
    run::run(&hv, &mut ctx(), &view("full"), &mut host);
    assert_eq!(hv.seen.lock().unwrap()[1].completed.unwrap().value, 0);
}

#[test]
fn an_access_in_no_window_is_answered_without_the_model() {
    let hv = ScriptHv::new(vec![(mmio(0x2000_0000, false), 0), (mmio(0x2000_0000, true), 5), (Exit::Hypercall, 0)]);
    let mut host = Host::echo();
    run::run(&hv, &mut ctx(), &view("full"), &mut host);
    assert!(host.seen.is_empty());
    assert_eq!(host.events, 0, "the model is not woken for it");
    let seen = hv.seen.lock().unwrap();
    assert_eq!(seen[1].completed.unwrap().value, 0);
    assert!(seen[2].completed.is_some());
}

#[test]
fn a_store_the_envelope_refuses_is_recorded_and_never_reaches_the_model() {
    // The guest of a `slow` VM stores to its NIC, then reads it, then stores
    // to its disk. Unique addresses tell this test's records from the others'.
    let (nic, hole) = (NET + 0x44, NET + 0x48);
    let hv = ScriptHv::new(vec![(mmio(nic, true), 1), (mmio(hole, false), 0), (mmio(BLK + 8, true), 2), (Exit::Hypercall, 0)]);
    let mut host = Host::echo();
    let before = azos_decision::total();
    run::run(&hv, &mut ctx(), &view("slow"), &mut host);
    // The load of the NIC and the store to the disk went to the model; the
    // store to the NIC did not.
    let gpas: Vec<u64> = host.seen.iter().map(|t| t.gpa).collect();
    assert_eq!(gpas, vec![hole, BLK + 8]);
    // The guest was told its store was done.
    assert!(hv.seen.lock().unwrap()[1].completed.is_some());
    // And the refusal is a decision of its own rule, about this VM.
    let mut found = Vec::new();
    azos_decision::for_each(|r| {
        if r.seq > before && r.rule == Rule::GuestEgress as u8 && r.n[1] == nic {
            found.push(*r);
        }
    });
    assert_eq!(found.len(), 1);
    let r = found[0];
    assert_eq!((r.verdict, r.subject), (Verdict::Refuse as u8, 1), "refused, under the VM's badge");
    assert_eq!(r.n, [Backend::Net as u64, nic, Envelope::Slow as u64]);
    assert_eq!(r.rule_info().map(|i| i.name), Some("guest-egress"));
}

#[test]
fn a_contained_guest_causes_nothing_and_a_full_one_is_not_recorded() {
    let hv = ScriptHv::new(vec![(mmio(CON + 0x10, true), 1), (Exit::Hypercall, 0)]);
    let mut host = Host::echo();
    run::run(&hv, &mut ctx(), &view("contained"), &mut host);
    assert!(host.seen.is_empty(), "not even the console");
    let hv = ScriptHv::new(vec![(mmio(CON + 0x14, true), 1), (Exit::Hypercall, 0)]);
    let mut host = Host::echo();
    let before = azos_decision::total();
    run::run(&hv, &mut ctx(), &view("full"), &mut host);
    assert_eq!(host.seen.len(), 1);
    let mut n = 0;
    azos_decision::for_each(|r| n += (r.seq > before && r.rule == Rule::GuestEgress as u8 && r.n[1] == CON + 0x14) as u32);
    assert_eq!(n, 0, "an allowed effect writes no refusal");
}

#[test]
fn the_loop_waits_for_the_model_and_a_stop_ends_the_wait() {
    // The model never answers; the stop comes while the vCPU waits.
    let hv = ScriptHv::new(vec![(mmio(BLK, false), 0)]);
    let mut host = Host::new(|_| None);
    host.stop_after = Some(3);
    let stop = run::run(&hv, &mut ctx(), &view("full"), &mut host);
    assert_eq!(stop, Stop::Requested);
    assert_eq!(host.seen.len(), 1);
    // The stop is read before the first entry, too.
    let hv = ScriptHv::new(vec![]);
    let mut host = Host::echo();
    host.stop_after = Some(0);
    assert_eq!(run::run(&hv, &mut ctx(), &view("full"), &mut host), Stop::Requested);
    assert!(hv.seen.lock().unwrap().is_empty(), "the guest never ran");
}

#[test]
fn waiting_for_an_interrupt_parks_and_a_host_interrupt_gives_the_hart_up() {
    let hv = ScriptHv::new(vec![(Exit::HostInterrupt, 0), (Exit::Wait, 0), (Exit::HostInterrupt, 0), (Exit::Wait, 0), (Exit::Shutdown, 0)]);
    let mut host = Host::echo();
    host.irqs = VecDeque::from([0, 0, 1 << 33, 0]);
    let stop = run::run(&hv, &mut ctx(), &view("full"), &mut host);
    assert_eq!(stop, Stop::Fault(fault::SHUTDOWN << 56));
    assert_eq!((host.parks, host.yields), (2, 2));
    // The lines raised for the vCPU are what the ISA presents at the entry
    // after they were raised.
    let irqs: Vec<u64> = hv.seen.lock().unwrap().iter().map(|e| e.irqs).collect();
    assert_eq!(irqs, vec![0, 0, 1 << 33, 0, 0]);
}

#[test]
fn an_exit_nothing_serves_stops_the_vcpu_and_says_which() {
    use azos_arch_api::{PioAccess, StageAccess};
    let pio = PioAccess { port: 0x3F8, size: 1, write: false, string: false, rep: false };
    for (exit, kind, detail) in [
        (Exit::Fault { gpa: 0x9000_0000, access: StageAccess::Exec }, fault::STAGE2, 0x9000_0000),
        (Exit::Pio(pio), fault::PIO, 0x3F8),
        (Exit::Hypercall, fault::HYPERCALL, 0),
        (Exit::SysReg { write: true }, fault::SYSREG, 1),
        (Exit::InvalidState, fault::INVALID_STATE, 0),
        (Exit::Other(0x2A), fault::OTHER, 0x2A),
    ] {
        let hv = ScriptHv::new(vec![(exit, 0)]);
        let mut host = Host::echo();
        assert_eq!(run::run(&hv, &mut ctx(), &view("full"), &mut host), Stop::Fault(kind << 56 | detail), "{exit:?}");
    }
}

#[test]
fn a_gone_monitor_page_faults_the_vcpu_instead_of_waiting_for_ever() {
    let hv = ScriptHv::new(vec![(mmio(BLK, false), 0)]);
    let mut host = Host::echo();
    host.gone = true;
    assert_eq!(run::run(&hv, &mut ctx(), &view("full"), &mut host), Stop::Fault(fault::MONITOR_GONE << 56));
}

#[test]
fn a_full_ring_is_waited_out_not_lost() {
    // TRAPS traps already waiting: the next post is refused until the model
    // takes some, which it does when the vCPU gives the hart up.
    struct Slow(Host);
    impl RunHost for Slow {
        fn stop_requested(&mut self) -> bool {
            self.0.stop_requested()
        }
        fn take_irqs(&mut self) -> u64 {
            0
        }
        fn next_seq(&mut self, v: u8) -> u32 {
            self.0.next_seq(v)
        }
        fn post(&mut self, t: &Trap) -> Result<(), PostError> {
            self.0.post(t)
        }
        fn answer(&mut self) -> Option<Completion> {
            self.0.answer()
        }
        fn park(&mut self) {}
        fn yield_now(&mut self) {
            // The model catches up.
            while let Some(t) = self.0.page.model_pop_trap() {
                self.0.seen.push(t);
            }
        }
    }
    let mut host = Slow(Host::echo());
    for i in 0..TRAPS {
        host.0.post(&trap(seq_of(1000 + i, 5), 5, false, BLK, 0)).unwrap();
    }
    let hv = ScriptHv::new(vec![(mmio(BLK + 0x10, false), 0), (Exit::Shutdown, 0)]);
    let stop = run::run(&hv, &mut ctx(), &view("full"), &mut host);
    assert_eq!(stop, Stop::Fault(fault::SHUTDOWN << 56));
    assert_eq!(host.0.seen.last().map(|t| t.gpa), Some(BLK + 0x10), "the trap went in once there was room");
}

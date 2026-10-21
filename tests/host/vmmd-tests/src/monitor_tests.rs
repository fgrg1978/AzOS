// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The kernel's end of the rings (`crates/core/hv`) against this program's
//! device models: the monitor's tables, a guest that follows a script, the
//! trap ring over a shared page and the event port in between.
//!
//! What is real here is the code of both sides: `azos_hv::run` (the vCPU
//! loop and the route of a decoded access), `azos_hv::ring` (the page), the
//! monitor's table (`VmTable`: what is attached, what may start), and vmmd's
//! `Machine`, `Rings`, `SegRam` and `attach_all`. What stands in for the
//! kernel is the port (a queue of events: the wake of a task blocked in
//! `SYS_PORT_WAIT` is the kernel's and a QEMU row's) and the guest (a script
//! of the accesses a driver makes).

use std::collections::VecDeque;

use crate::fakes::ScriptHv;
use crate::guest::{attach_all, AttachStop, GuestMem, SegRam};
use crate::harness::{MemStore, Ram, TestLink, TestTerm};
use crate::blk::Blk;
use crate::console::Console;
use crate::model::{irq_line, kinds_of, window_base, Kind, Machine, CODE_BLK, CODE_CONSOLE, CODE_NET};
use crate::net::Net;
use crate::trap::{Rings, PAGE_BYTES};
use azos_arch_api::{Exit, GuestCtx, HvKind, HvStatus, MmioAccess, MmioDone, Stage2Root};
use azos_hv::admit::{self, HostFacts, VirtRole};
use azos_hv::backend::Backend;
use azos_hv::ring::{Mailbox, RawPage};
use azos_hv::run::{self, PostError, RunHost, RunView, Stop};
use azos_hv::trapwire::{Completion, Trap};
use azos_hv::vm::{RamSeg, Space, StartError, VmTable};
use azos_topology::{parse_caps, parse_sched, Topology};

fn topology(body: &str) -> Box<Topology<'static>> {
    let sched: &'static str = "[class.best_effort]\ncpu_budget_min_pct = 5\npolicy = \"cfs\"\n";
    let caps: &'static str = Box::leak(format!("format = 7\n{body}").into_boxed_str());
    let mut t = Box::new(Topology::empty());
    parse_sched(sched.as_bytes(), &mut t).unwrap();
    parse_caps(caps.as_bytes(), &mut t).unwrap_or_else(|e| panic!("{e:?}\n{body}"));
    t
}

/// A table with one guest of 1 MiB whose row lists console, disk and NIC.
fn table(envelope: &str) -> VmTable {
    let t = topology(&format!(
        "[guest.g]\ncpus = 1\nmem_mib = 1\nenvelope = \"{envelope}\"\ndevices = [\"virtio-console\", \"virtio-blk\", \"virtio-net\"]\n"
    ));
    let facts = HostFacts {
        role: VirtRole::Hosted,
        hv: HvStatus::Usable(HvKind::RiscvH),
        online: 0b11,
        rt: 0,
        free_mib: 1024,
        max_guest_mib: 1024,
    };
    let plan = admit::admit(t.guests(), &facts).unwrap();
    let mut vms = VmTable::new();
    vms.install(t.guests(), &plan, HvKind::RiscvH).unwrap();
    vms.vm_mut(0).unwrap().created(Stage2Root { root: 0, aux: 0 }).unwrap();
    vms
}

// ── the RAM and the row, as `Vm::config` tells them ─────────────────────

#[test]
fn the_backends_word_of_the_row_is_what_vmmd_builds_its_models_from() {
    // The codes vmmd decodes are the codes the monitor encodes.
    assert_eq!((CODE_BLK, CODE_NET, CODE_CONSOLE), (Backend::Blk as u8, Backend::Net as u8, Backend::Console as u8));
    let vms = table("full");
    let word = vms.vm(0).unwrap().kinds;
    let k = kinds_of(word, vms.vm(0).unwrap().devices_len());
    assert_eq!(&k[..4], &[Some(Kind::Console), Some(Kind::Blk), Some(Kind::Net), None]);
    // A row in another order, with a backend vmmd has no model for.
    let t = topology("[guest.h]\ncpus = 1\nmem_mib = 1\nenvelope = \"full\"\ndevices = [\"virtio-net\", \"virtio-rng\", \"virtio-blk\"]\n");
    let word = azos_hv::backend::pack(t.guests()[0].devices());
    let k = kinds_of(word, 3);
    assert_eq!(&k[..4], &[Some(Kind::Net), None, Some(Kind::Blk), None], "rng has no model");
}

#[test]
fn attached_ram_is_the_range_vmmd_sees_and_the_vm_starts_only_then() {
    let mut vms = table("full");
    let (base, bytes) = (vms.vm(0).unwrap().ram_base, vms.vm(0).unwrap().ram_bytes());
    assert_eq!(bytes, 1 << 20);
    // vmmd's loop, with the kernel's side of each `Vm::ram` in the closure: the
    // object is made (a Vec here), the table checks and records the range.
    let mut objects: Vec<Vec<u8>> = Vec::new();
    let mut segs: Vec<RamSeg> = Vec::new();
    let mut ram = SegRam::new();
    let chunk = 256 << 10;
    // SAFETY: each pointer answered is a Vec kept in `objects` for the test.
    let r = unsafe {
        attach_all(&mut ram, base, bytes, chunk, |gpa, len| {
            vms.check_ram(0, &segs, gpa, len).ok()?;
            vms.ram_added(0, len);
            segs.push(RamSeg { gpa, bytes: len });
            objects.push(vec![0u8; len as usize]);
            Some(objects.last_mut().unwrap().as_mut_ptr())
        })
    };
    assert_eq!(r, Ok(()));
    assert_eq!(objects.len(), 4);
    // The monitor's table and vmmd agree on the range.
    assert_eq!(ram.range(), (base, bytes));
    assert_eq!(vms.vm(0).unwrap().ram_attached, bytes);
    // With the RAM in place the vCPU still waits for the trap page ...
    assert_eq!(vms.start(0, 0, true, 0b11, 0, 0), Err(StartError::NotReady));
    vms.traps_attached(0).unwrap();
    // ... and then starts.
    assert_eq!(vms.start(0, 0, true, 0b11, 0, 0), Ok(0));
    // What the guest writes in its RAM is what vmmd reads.
    ram.write(base + chunk - 2, &[1, 2, 3, 4]).unwrap();
    let mut b = [0u8; 4];
    ram.read(base + chunk - 2, &mut b).unwrap();
    assert_eq!(b, [1, 2, 3, 4]);
    assert_eq!(&objects[0][objects[0].len() - 2..], &[1, 2]);
    assert_eq!(&objects[1][..2], &[3, 4]);
}

#[test]
fn a_range_the_vm_refuses_stops_the_attach_and_leaves_the_ram_partial() {
    let mut vms = table("full");
    let (base, bytes) = (vms.vm(0).unwrap().ram_base, vms.vm(0).unwrap().ram_bytes());
    let mut objects: Vec<Vec<u8>> = Vec::new();
    let mut segs: Vec<RamSeg> = Vec::new();
    let mut ram = SegRam::new();
    let mut n = 0;
    // SAFETY: as above.
    let r = unsafe {
        attach_all(&mut ram, base, bytes, 256 << 10, |gpa, len| {
            n += 1;
            if n == 3 {
                return None; // the kernel or the quota said no
            }
            vms.check_ram(0, &segs, gpa, len).ok()?;
            vms.ram_added(0, len);
            segs.push(RamSeg { gpa, bytes: len });
            objects.push(vec![0u8; len as usize]);
            Some(objects.last_mut().unwrap().as_mut_ptr())
        })
    };
    assert_eq!(r, Err(AttachStop::Make { at: base + (512 << 10) }));
    assert_eq!(ram.range(), (0, 0), "a guest with memory missing has no queue to trust");
    assert_eq!(ram.attached(), 512 << 10);
    vms.traps_attached(0).unwrap();
    assert_eq!(vms.start(0, 0, true, 0b11, 0, 0), Err(StartError::NotReady), "and no vCPU starts on it");
}

// ── a device access through the port ────────────────────────────────────

type M = Machine<MemStore, TestLink, TestTerm>;

/// The kernel's trap page and port, and vmmd behind them.
struct Rig {
    page: Vec<u64>,
    mailbox: Mailbox,
    /// The events on the port: one per trap posted, until vmmd takes it.
    port: VecDeque<u64>,
    machine: M,
    ram: Ram,
    /// Times vmmd woke (took an event and ran a pass).
    woke: u32,
    /// vCPUs vmmd kicked.
    kicks: Vec<u8>,
    /// Interrupt lines vmmd raised, waiting for the vCPU to take them.
    irqs: u64,
    calls: u32,
}

impl Rig {
    fn new(m: M) -> Rig {
        Rig {
            page: vec![0; PAGE_BYTES.div_ceil(8)],
            mailbox: Mailbox::new(),
            port: VecDeque::new(),
            machine: m,
            ram: Ram::new(),
            woke: 0,
            kicks: Vec::new(),
            irqs: 0,
            calls: 0,
        }
    }

    fn raw(&mut self) -> RawPage {
        // SAFETY: the page is a live 8-aligned Vec of PAGE_BYTES, which only
        // this rig reads and writes.
        unsafe { RawPage::new(self.page.as_mut_ptr() as *mut u8) }
    }

    /// vmmd's loop body, run when its port has an event.
    fn vmmd_pass(&mut self) {
        // SAFETY: as `raw`.
        let mut rings = unsafe { Rings::new(self.page.as_mut_ptr() as *mut u8) };
        let served = self.machine.serve(&mut rings, &mut self.ram);
        for k in 0..64u8 {
            if served.answered & (1 << k) != 0 {
                self.kicks.push(k);
            }
        }
        for i in 0..16 {
            if served.raised & (1 << i) != 0 {
                self.irqs |= 1 << irq_line(i);
            }
        }
        self.woke += 1;
    }
}

impl RunHost for Rig {
    fn stop_requested(&mut self) -> bool {
        self.calls += 1;
        assert!(self.calls < 10_000, "the loop is waiting for an answer that cannot come");
        false
    }
    fn take_irqs(&mut self) -> u64 {
        std::mem::take(&mut self.irqs)
    }
    fn next_seq(&mut self, vcpu: u8) -> u32 {
        self.mailbox.next_seq(0, vcpu)
    }
    fn post(&mut self, t: &Trap) -> Result<(), PostError> {
        let mut raw = self.raw();
        raw.post_trap(t).map_err(|_| PostError::Full)?;
        self.mailbox.expect(t.vcpu as usize, t.seq);
        self.port.push_back(0xE0E0);
        Ok(())
    }
    fn answer(&mut self) -> Option<Completion> {
        // vmmd sleeps on the port: it runs only if the port has an event.
        if self.port.pop_front().is_some() {
            self.port.clear();
            self.vmmd_pass();
        }
        let mut raw = self.raw();
        self.mailbox.fill(&mut raw, 0, azos_hv::vm::MAX_VCPUS);
        self.mailbox.take(0)
    }
    fn park(&mut self) {}
    fn yield_now(&mut self) {}
}

fn rig(vms: &mut VmTable) -> (Rig, RunView) {
    let (devices, kinds) = (vms.vm(0).unwrap().devices_len(), vms.vm(0).unwrap().kinds);
    let machine: M = Machine::new(
        kinds_of(kinds, devices),
        Some(Console::new(TestTerm::default())),
        Some(Blk::new(MemStore::new(16))),
        Some(Net::new(TestLink::default(), [2, 0x41, 0x7A, 0x4F, 0x53, 1])),
    );
    // vmmd registers a window per backend it has a model for.
    for (base, len, dev) in machine.windows() {
        vms.add_window(0, Space::Mmio, base, len, dev as u8).unwrap();
    }
    (Rig::new(machine), RunView::new(vms.vm(0).unwrap()))
}

fn load(gpa: u64) -> (Exit, u64) {
    (Exit::Mmio(MmioAccess { gpa, size: 4, write: false, reg: 10, insn_len: 4 }), 0)
}

fn store(gpa: u64, v: u64) -> (Exit, u64) {
    (Exit::Mmio(MmioAccess { gpa, size: 4, write: true, reg: 10, insn_len: 4 }), v)
}

fn ctx() -> GuestCtx {
    GuestCtx::new(Stage2Root { root: 0, aux: 0 }, 1, 0, 0x8000_0000, 0)
}

/// Offsets of the virtio-mmio registers the guest reads first.
const MAGIC: u64 = 0x000;
const VERSION: u64 = 0x004;
const DEVICE_ID: u64 = 0x008;
const STATUS: u64 = 0x070;

#[test]
fn a_guests_probe_of_its_devices_reaches_vmmd_through_the_port_and_comes_back() {
    let mut vms = table("full");
    let (mut rig, view) = rig(&mut vms);
    let console = window_base(0);
    let net = window_base(2);
    let hv = ScriptHv::new(vec![
        load(console + MAGIC),
        load(console + VERSION),
        load(console + DEVICE_ID),
        store(console + STATUS, 1),
        load(console + STATUS),
        load(net + DEVICE_ID),
        (Exit::Shutdown, 0),
    ]);
    let stop = run::run(&hv, &mut ctx(), &view, &mut rig);
    assert_eq!(stop, Stop::Fault(run::fault::SHUTDOWN << 56));
    // What the guest's registers received: the answers of vmmd's devices.
    let seen = hv.seen.lock().unwrap();
    let got: Vec<u64> = seen.iter().filter_map(|e| e.completed).filter(|d: &MmioDone| !d.access.write).map(|d| d.value).collect();
    assert_eq!(got, vec![0x7472_6976, 2, 3, 1, 1], "magic 'virt', version 2, console id 3, status written back, net id 1");
    // The store is complete from the guest's side too.
    assert!(seen.iter().filter_map(|e| e.completed).any(|d| d.access.write));
    // vmmd woke once per trap, because of an event each, and never otherwise.
    assert_eq!(rig.woke, 6);
    assert!(rig.port.is_empty());
    // It kicked the vCPU it answered each time.
    assert_eq!(rig.kicks, vec![0; 6]);
}

#[test]
fn an_access_outside_every_window_never_wakes_vmmd() {
    let mut vms = table("full");
    let (mut rig, view) = rig(&mut vms);
    let hv = ScriptHv::new(vec![load(window_base(3)), load(0x1000), store(0x2000_0000, 5), (Exit::Cpuid, 0)]);
    assert_eq!(run::run(&hv, &mut ctx(), &view, &mut rig), Stop::Fault(run::fault::CPUID << 56));
    assert_eq!(rig.woke, 0);
    let seen = hv.seen.lock().unwrap();
    assert!(seen[1].completed.is_some() && seen[3].completed.is_some());
}

#[test]
fn a_store_the_envelope_refuses_never_reaches_vmmd_but_a_load_does() {
    // `slow` allows the console and the disk, not the network.
    let mut vms = table("slow");
    let (mut rig, view) = rig(&mut vms);
    let net = window_base(2);
    let blk = window_base(1);
    let hv = ScriptHv::new(vec![
        store(net + 0x44, 7),
        load(net + DEVICE_ID),
        store(blk + STATUS, 1),
        (Exit::Hypercall, 0),
    ]);
    let before = azos_decision::total();
    run::run(&hv, &mut ctx(), &view, &mut rig);
    // The refused store woke nothing; the load and the disk store did.
    assert_eq!(rig.woke, 2);
    let mut refused = 0;
    azos_decision::for_each(|r| {
        refused += (r.seq > before && r.rule == azos_decision::Rule::GuestEgress as u8 && r.n[1] == net + 0x44) as u32;
    });
    assert_eq!(refused, 1);
    let seen = hv.seen.lock().unwrap();
    let net_id = seen[2].completed.unwrap().value;
    assert_eq!(net_id, 1, "reading the NIC is not egress");
}

#[test]
fn a_line_vmmd_raises_is_presented_to_the_vcpu_at_its_next_entry() {
    // The console boot of the recorded traps, as a guest would replay it, is
    // in machine_tests; here the line itself: a used buffer on the console.
    let mut vms = table("full");
    let (mut rig, view) = rig(&mut vms);
    rig.irqs = 1 << irq_line(0);
    let hv = ScriptHv::new(vec![(Exit::Wait, 0), (Exit::Shutdown, 0)]);
    run::run(&hv, &mut ctx(), &view, &mut rig);
    let irqs: Vec<u64> = hv.seen.lock().unwrap().iter().map(|e| e.irqs).collect();
    assert_eq!(irqs, vec![1 << irq_line(0), 0], "taken once, then clear");
}

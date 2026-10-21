// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The per-VM loop on recorded MMIO traps: a guest's driver is replayed as
//! the stream of traps the monitor would post, through the trap ring and the
//! completion ring, and the machine answers.

use crate::blk::Blk;
use crate::console::Console;
use crate::harness::*;
use crate::mmio::{status, WINDOW};
use crate::model::{irq_line, kinds_of, window_base, Kind, Machine, MMIO_BASE};
use crate::net::Net;
use crate::trap::{cpl, Completion, Rings, Trap, PAGE_BYTES, TRAPS};

type M = Machine<MemStore, TestLink, TestTerm>;

const MAC: [u8; 6] = [0x02, 0x41, 0x7A, 0x4F, 0x53, 0x01];

/// The row: console, then disk, then NIC, in `Vm::config`'s backends word
/// (4 bits each; 3 console, 1 blk, 2 net).
const ROW: u64 = 3 | 1 << 4 | 2 << 8;

fn machine(count: usize) -> M {
    machine_of(ROW, count)
}

fn machine_of(row: u64, count: usize) -> M {
    Machine::new(
        kinds_of(row, count),
        Some(Console::new(TestTerm::default())),
        Some(Blk::new(MemStore::new(16))),
        Some(Net::new(TestLink::default(), MAC)),
    )
}

/// The monitor's end of the two rings, over a page shared with vmmd's.
struct Monitor {
    page: Vec<u64>,
    seq: u32,
}

impl Monitor {
    fn new() -> Monitor {
        Monitor { page: vec![0; PAGE_BYTES.div_ceil(8)], seq: 0 }
    }

    fn rings(&mut self) -> Rings {
        // SAFETY: the page is a live, 8-aligned Vec of PAGE_BYTES.
        unsafe { Rings::new(self.page.as_mut_ptr() as *mut u8) }
    }

    fn bytes(&mut self) -> &mut [u8] {
        // SAFETY: as above.
        unsafe { std::slice::from_raw_parts_mut(self.page.as_mut_ptr() as *mut u8, PAGE_BYTES) }
    }

    fn u32_at(&mut self, off: usize) -> u32 {
        let b = self.bytes();
        u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
    }

    fn set_u32(&mut self, off: usize, v: u32) {
        self.bytes()[off..off + 4].copy_from_slice(&v.to_le_bytes());
    }

    /// Post a trap; its sequence number.
    fn post(&mut self, mut t: Trap) -> u32 {
        t.seq = self.seq;
        self.seq += 1;
        let tail = self.u32_at(4);
        assert!(tail.wrapping_sub(self.u32_at(0)) < TRAPS, "the test posted more traps than the ring holds");
        let at = 0x40 + (tail % TRAPS) as usize * 32;
        let enc = t.encode();
        self.bytes()[at..at + 32].copy_from_slice(&enc);
        self.set_u32(4, tail.wrapping_add(1));
        t.seq
    }

    /// Take every completion posted.
    fn completions(&mut self) -> Vec<Completion> {
        let mut out = vec![];
        let tail = self.u32_at(12);
        let mut head = self.u32_at(8);
        while head != tail {
            let at = 0x40 + TRAPS as usize * 32 + (head % TRAPS) as usize * 16;
            let mut b = [0u8; 16];
            b.copy_from_slice(&self.bytes()[at..at + 16]);
            out.push(Completion::decode(&b));
            head = head.wrapping_add(1);
        }
        self.set_u32(8, head);
        out
    }

    fn load(&mut self, gpa: u64) -> u32 {
        self.post(Trap { seq: 0, vcpu: 0, write: false, len: 4, gpa, data: 0 })
    }

    fn store(&mut self, gpa: u64, v: u32) -> u32 {
        self.post(Trap { seq: 0, vcpu: 0, write: true, len: 4, gpa, data: v as u64 })
    }
}

/// Serve what is posted; the completions and the lines raised.
fn run(mon: &mut Monitor, m: &mut M, ram: &mut Ram) -> (Vec<Completion>, u16) {
    let mut rings = mon.rings();
    let raised = m.serve(&mut rings, ram).raised;
    (mon.completions(), raised)
}

#[test]
fn every_window_answers_its_own_device_id() {
    let (mut mon, mut m, mut ram) = (Monitor::new(), machine(3), Ram::new());
    for i in 0..3 {
        mon.load(window_base(i));
        mon.load(window_base(i) + r::VERSION);
        mon.load(window_base(i) + r::DEVICE_ID);
    }
    let (c, raised) = run(&mut mon, &mut m, &mut ram);
    assert_eq!(raised, 0);
    assert_eq!(c.len(), 9);
    for (i, ch) in c.chunks(3).enumerate() {
        let want_id = match kinds_of(ROW, 3)[i] {
            Some(Kind::Console) => 3,
            Some(Kind::Blk) => 2,
            Some(Kind::Net) => 1,
            None => panic!("device {i} has a model"),
        };
        assert_eq!(ch.iter().map(|c| c.status).collect::<Vec<_>>(), vec![cpl::OK; 3]);
        assert_eq!(ch.iter().map(|c| c.data).collect::<Vec<_>>(), vec![0x7472_6976, 2, want_id], "window {i}");
    }
    // The answers carry the sequence numbers of their traps, in order.
    assert!(c.iter().enumerate().all(|(i, c)| c.seq == i as u32));
}

#[test]
fn windows_are_what_the_vm_is_asked_for() {
    let m = machine(3);
    let w: Vec<_> = m.windows().collect();
    assert_eq!(w, vec![(window_base(0), WINDOW, 0), (window_base(1), WINDOW, 1), (window_base(2), WINDOW, 2)]);
    assert_eq!(w[0].0, MMIO_BASE);
    assert!(w.windows(2).all(|p| p[0].0 + p[0].1 <= p[1].0), "no overlap");
    assert_eq!(machine(1).windows().count(), 1);
    assert_eq!(machine(9).windows().count(), 3, "a device past the three the row names has no model");
    let lines: Vec<_> = (0..3).map(irq_line).collect();
    assert!(lines.windows(2).all(|p| p[0] != p[1]) && lines.iter().all(|&l| l < 64));
}

#[test]
fn the_row_decides_which_kind_sits_at_which_window() {
    // Disk first, then a backend vmmd has no model for (rng), then the NIC.
    let mut m = machine_of(1 | 4 << 4 | 2 << 8, 3);
    let w: Vec<_> = m.windows().map(|w| w.2).collect();
    assert_eq!(w, vec![0, 2], "no window for the device without a model");
    let (mut mon, mut ram) = (Monitor::new(), Ram::new());
    for i in 0..3 {
        mon.load(window_base(i) + r::DEVICE_ID);
    }
    let (c, _) = run(&mut mon, &mut m, &mut ram);
    assert_eq!((c[0].status, c[0].data), (cpl::OK, 2), "the disk");
    assert_eq!((c[1].status, c[1].data), (cpl::NO_DEVICE, 0), "rng: an empty bus");
    assert_eq!((c[2].status, c[2].data), (cpl::OK, 1), "the NIC");
}

#[test]
fn the_vcpus_answered_are_told_to_the_loop_so_it_can_kick_them() {
    let (mut mon, mut m, mut ram) = (Monitor::new(), machine(3), Ram::new());
    for vcpu in [0u8, 2, 2, 63, 64, 200] {
        mon.post(Trap { seq: 0, vcpu, write: false, len: 4, gpa: window_base(0), data: 0 });
    }
    let served = m.serve(&mut mon.rings(), &mut ram);
    assert_eq!(served.answered, 1 | 1 << 2 | 1 << 63, "a vCPU past 64 is not named (its thread looks on its own)");
    // Nothing posted, nobody answered.
    assert_eq!(m.serve(&mut mon.rings(), &mut ram).answered, 0);
}

#[test]
fn nothing_answers_outside_the_registered_windows() {
    let (mut mon, mut m, mut ram) = (Monitor::new(), machine(2), Ram::new());
    for gpa in [0, MMIO_BASE - 4, window_base(2), window_base(2) + r::DEVICE_ID, MMIO_BASE + 0x10_0000, u64::MAX - 3] {
        mon.load(gpa);
        mon.store(gpa, 0xFFFF_FFFF);
    }
    let (c, raised) = run(&mut mon, &mut m, &mut ram);
    assert_eq!(raised, 0);
    assert_eq!(c.len(), 12);
    assert!(c.iter().all(|c| c.status == cpl::NO_DEVICE && c.data == 0), "{c:?}");
}

#[test]
fn a_backend_vmmd_could_not_set_up_reads_as_an_empty_bus() {
    let (mut mon, mut m, mut ram) = (Monitor::new(), machine(3), Ram::new());
    m.blk = None;
    mon.load(window_base(1));
    mon.load(window_base(0));
    let (c, _) = run(&mut mon, &mut m, &mut ram);
    assert_eq!((c[0].status, c[0].data), (cpl::NO_DEVICE, 0));
    assert_eq!((c[1].status, c[1].data), (cpl::OK, 0x7472_6976));
}

#[test]
fn an_access_size_the_bus_does_not_decode_is_refused() {
    let (mut mon, mut m, mut ram) = (Monitor::new(), machine(3), Ram::new());
    for len in [0u8, 3, 5, 16, 255] {
        mon.post(Trap { seq: 0, vcpu: 0, write: false, len, gpa: window_base(0), data: 0 });
    }
    let (c, _) = run(&mut mon, &mut m, &mut ram);
    assert!(c.iter().all(|c| c.status == cpl::BAD_ACCESS), "{c:?}");
}

/// A recorded guest boot of the console device, from the probe to the first
/// line of output, as traps. The queues are in guest RAM, written by the
/// guest without trapping; the register traffic is what the monitor sees.
fn console_boot(mon: &mut Monitor, ram: &mut Ram, b: u64) -> (u32, u32, u32) {
    let (rx, mut tx) = (Queue::new(0, 8), Queue::new(1, 8));
    let msg = ram.put(b"hello from the guest\n");
    tx.post(ram, &[(msg, 21, false)]);
    mon.load(b + r::MAGIC);
    mon.load(b + r::DEVICE_ID);
    mon.store(b + r::STATUS, ACK);
    mon.store(b + r::STATUS, ACK | DRIVER);
    mon.store(b + r::DRIVER_FEATURES_SEL, 1);
    mon.store(b + r::DRIVER_FEATURES, 1); // VERSION_1 is bit 0 of the high word
    mon.store(b + r::STATUS, ACK | DRIVER | status::FEATURES_OK);
    let features_ok = mon.load(b + r::STATUS);
    // The RAM sits below 4 GiB, so the high halves stay 0.
    for (sel, q) in [(0u32, &rx), (1, &tx)] {
        mon.store(b + r::QUEUE_SEL, sel);
        mon.store(b + r::QUEUE_NUM, 8);
        mon.store(b + r::QUEUE_DESC_LOW, q.desc as u32);
        mon.store(b + r::QUEUE_DRIVER_LOW, q.avail as u32);
        mon.store(b + r::QUEUE_DEVICE_LOW, q.used as u32);
        mon.store(b + r::QUEUE_READY, 1);
    }
    mon.store(b + r::STATUS, ACK | DRIVER | status::FEATURES_OK | status::DRIVER_OK);
    mon.store(b + r::QUEUE_NOTIFY, 1);
    let isr = mon.load(b + r::INTERRUPT_STATUS);
    mon.store(b + r::INTERRUPT_ACK, 1);
    let isr_after = mon.load(b + r::INTERRUPT_STATUS);
    (features_ok, isr, isr_after)
}

#[test]
fn a_recorded_console_boot_prints_the_guests_line() {
    let (mut mon, mut m, mut ram) = (Monitor::new(), machine(3), Ram::new());
    let (features_ok, isr, isr_after) = console_boot(&mut mon, &mut ram, window_base(0));
    let (c, raised) = run(&mut mon, &mut m, &mut ram);
    assert!(c.iter().all(|c| c.status == cpl::OK));
    assert_eq!(c[features_ok as usize].data as u32 & status::FEATURES_OK, status::FEATURES_OK);
    assert_eq!(c[isr as usize].data, 1, "used-buffer interrupt");
    assert_eq!(c[isr_after as usize].data, 0, "acknowledged");
    assert_eq!(m.console.as_ref().unwrap().dev.term.out, b"hello from the guest\n");
    assert_eq!(raised, 1, "the console's line went up once");
}

/// The line is raised on the way up, not on every access while it is high.
#[test]
fn a_line_is_raised_once_until_the_guest_acknowledges_it() {
    let (mut mon, mut m, mut ram) = (Monitor::new(), machine(3), Ram::new());
    let b = window_base(0);
    console_boot(&mut mon, &mut ram, b);
    let (_, raised) = run(&mut mon, &mut m, &mut ram);
    assert_eq!(raised, 1);
    // The guest queues more output behind the same transmit queue.
    let tx = Queue::new(1, 8);
    let mut tx = tx;
    // Resume where the boot left the ring: one entry consumed.
    tx.skip(1);
    for (n, ack, want) in [(1, false, 1), (2, true, 0), (3, false, 1)] {
        let msg = ram.put(format!("line {n}\n").as_bytes());
        tx.post(&mut ram, &[(msg, 7, false)]);
        mon.store(b + r::QUEUE_NOTIFY, 1);
        let (_, raised) = run(&mut mon, &mut m, &mut ram);
        assert_eq!(raised & 1, want, "notify {n}");
        if ack {
            mon.store(b + r::INTERRUPT_ACK, 1);
            run(&mut mon, &mut m, &mut ram);
        }
    }
    let out = String::from_utf8(m.console.as_ref().unwrap().dev.term.out.clone()).unwrap();
    assert!(out.ends_with("line 1\nline 2\nline 3\n"), "{out:?}");
}

#[test]
fn host_side_events_raise_their_devices_line() {
    let (mut mon, mut m, mut ram) = (Monitor::new(), machine(3), Ram::new());
    let (b0, b2) = (window_base(0), window_base(2));
    console_boot(&mut mon, &mut ram, b0);
    run(&mut mon, &mut m, &mut ram);
    // The net device up, with one receive buffer offered.
    let (mut rx, tx) = (Queue::new(4, 8), Queue::new(5, 8));
    let buf = ram.put(&[0u8; 2048]);
    rx.post(&mut ram, &[(buf, 2048, true)]);
    mon.store(b2 + r::STATUS, ACK | DRIVER);
    mon.store(b2 + r::DRIVER_FEATURES_SEL, 1);
    mon.store(b2 + r::DRIVER_FEATURES, 1);
    mon.store(b2 + r::STATUS, ACK | DRIVER | status::FEATURES_OK);
    for (sel, q) in [(0u32, &rx), (1, &tx)] {
        mon.store(b2 + r::QUEUE_SEL, sel);
        mon.store(b2 + r::QUEUE_NUM, 8);
        mon.store(b2 + r::QUEUE_DESC_LOW, q.desc as u32);
        mon.store(b2 + r::QUEUE_DRIVER_LOW, q.avail as u32);
        mon.store(b2 + r::QUEUE_DEVICE_LOW, q.used as u32);
        mon.store(b2 + r::QUEUE_READY, 1);
    }
    mon.store(b2 + r::STATUS, ACK | DRIVER | status::FEATURES_OK | status::DRIVER_OK);
    let (_, raised) = run(&mut mon, &mut m, &mut ram);
    assert_eq!(raised, 0, "bring-up raises nothing");

    // A frame arrives for the guest.
    let f: Vec<u8> = [&MAC[..], &[2, 0, 0, 0, 0, 9, 8, 0], &[0u8; 40]].concat();
    m.net.as_mut().unwrap().dev.link.inbox.push_back(f.clone());
    assert_eq!(m.poll(&mut ram), 1 << 2, "only the net line");
    assert_eq!(ram.get(buf + 12, f.len()), f);
    // Nothing more to say: no second raise.
    assert_eq!(m.poll(&mut ram), 0);
}

#[test]
fn a_device_gone_bad_does_not_take_the_others_down() {
    let (mut mon, mut m, mut ram) = (Monitor::new(), machine(3), Ram::new());
    // The disk's guest driver publishes garbage.
    let b = window_base(1);
    let mut q = Queue::new(2, 8);
    mon.store(b + r::STATUS, ACK | DRIVER);
    mon.store(b + r::DRIVER_FEATURES_SEL, 1);
    mon.store(b + r::DRIVER_FEATURES, 1);
    mon.store(b + r::STATUS, ACK | DRIVER | status::FEATURES_OK);
    mon.store(b + r::QUEUE_NUM, 8);
    mon.store(b + r::QUEUE_DESC_LOW, q.desc as u32);
    mon.store(b + r::QUEUE_DRIVER_LOW, q.avail as u32);
    mon.store(b + r::QUEUE_DEVICE_LOW, q.used as u32);
    mon.store(b + r::QUEUE_READY, 1);
    mon.store(b + r::STATUS, ACK | DRIVER | status::FEATURES_OK | status::DRIVER_OK);
    q.publish(&mut ram, 77);
    mon.store(b + r::QUEUE_NOTIFY, 0);
    let st = mon.load(b + r::STATUS);
    let (c, raised) = run(&mut mon, &mut m, &mut ram);
    assert_ne!(c[st as usize].data as u32 & status::NEEDS_RESET, 0);
    assert_eq!(raised, 1 << 1, "the disk's own line");
    assert_eq!(m.blk.as_ref().unwrap().dev.errors, 0);
    // The console next door still boots and prints.
    console_boot(&mut mon, &mut ram, window_base(0));
    let (_, raised) = run(&mut mon, &mut m, &mut ram);
    assert_eq!(raised, 1);
    assert_eq!(m.console.as_ref().unwrap().dev.term.out, b"hello from the guest\n");
}

#[test]
fn more_traps_than_the_ring_holds_are_served_over_several_passes() {
    let (mut mon, mut m, mut ram) = (Monitor::new(), machine(3), Ram::new());
    let mut seen = vec![];
    for round in 0..5u32 {
        for _ in 0..TRAPS {
            mon.load(window_base(0) + r::DEVICE_ID);
        }
        let (c, _) = run(&mut mon, &mut m, &mut ram);
        assert_eq!(c.len(), TRAPS as usize, "round {round}");
        seen.extend(c.iter().map(|c| c.seq));
    }
    assert!(seen.windows(2).all(|p| p[1] == p[0] + 1), "answers keep the order of the traps");
}

#[test]
fn irq_lines_are_the_platforms_plus_the_device_index() {
    assert_eq!(irq_line(1), irq_line(0) + 1);
    assert_eq!(irq_line(2), irq_line(0) + 2);
}

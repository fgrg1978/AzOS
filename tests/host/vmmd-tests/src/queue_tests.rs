// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The split virtqueue against a guest that writes whatever it likes.

use crate::guest::GuestMem;
use crate::harness::*;
use crate::virtq::{Virtq, VqError, MAX_CHAIN};

/// A ready queue over `q`, as the transport would configure it.
fn vq(q: &Queue) -> Virtq {
    let mut v = Virtq::EMPTY;
    v.num = q.num;
    v.desc = q.desc;
    v.avail = q.avail;
    v.used = q.used;
    v.ready = true;
    v
}

#[test]
fn chains_come_off_in_order_and_go_back_on_the_used_ring() {
    let mut ram = Ram::new();
    let mut q = Queue::new(0, 8);
    let mut v = vq(&q);
    let a = ram.put(b"hello");
    let b = ram.alloc(16);
    let h0 = q.post(&mut ram, &[(a, 5, false), (b, 16, true)]);
    let h1 = q.post(&mut ram, &[(a, 5, false)]);
    let c0 = v.pop(&ram).unwrap().unwrap();
    assert_eq!((c0.head, c0.descs().len(), c0.readable(), c0.writable()), (h0, 2, 5, 16));
    let c1 = v.pop(&ram).unwrap().unwrap();
    assert_eq!(c1.head, h1);
    assert!(v.pop(&ram).unwrap().is_none());
    v.push_used(&mut ram, &c0, 7).unwrap();
    v.push_used(&mut ram, &c1, 0).unwrap();
    assert_eq!(q.used_idx(&ram), 2);
    assert_eq!(q.used(&ram, 0), (h0 as u32, 7));
    assert_eq!(q.used(&ram, 1), (h1 as u32, 0));
}

#[test]
fn a_chain_is_read_and_written_across_its_descriptors() {
    let mut ram = Ram::new();
    let mut q = Queue::new(0, 8);
    let mut v = vq(&q);
    let (a, b) = (ram.put(b"abc"), ram.put(b"defgh"));
    let (x, y) = (ram.alloc(2), ram.alloc(6));
    q.post(&mut ram, &[(a, 3, false), (b, 5, false), (x, 2, true), (y, 6, true)]);
    let c = v.pop(&ram).unwrap().unwrap();
    let mut out = [0u8; 6];
    c.read_at(&ram, 2, &mut out).unwrap();
    assert_eq!(&out, b"cdefgh");
    assert!(c.read_at(&ram, 3, &mut [0u8; 6]).is_err(), "past the end of the readable run");
    c.write_at(&mut ram, 1, b"12345").unwrap();
    assert_eq!(ram.get(x, 2), [0, b'1']);
    assert_eq!(ram.get(y, 4), *b"2345");
    assert!(c.write_at(&mut ram, 6, b"xyz").is_err());
}

#[test]
fn an_avail_index_ahead_of_the_queue_is_refused() {
    let mut ram = Ram::new();
    let q = Queue::new(0, 8);
    let mut v = vq(&q);
    // The driver claims 9 entries on a queue of 8.
    ram.write(q.avail + 2, &9u16.to_le_bytes()).unwrap();
    assert_eq!(v.pop(&ram).unwrap_err(), VqError::Overrun);
}

#[test]
fn a_head_or_next_past_the_table_is_refused() {
    let mut ram = Ram::new();
    let mut q = Queue::new(0, 8);
    let mut v = vq(&q);
    let buf = ram.alloc(16);
    q.publish(&mut ram, 8);
    assert_eq!(v.pop(&ram).unwrap_err(), VqError::BadIndex);
    let mut ram = Ram::new();
    let mut q = Queue::new(0, 8);
    let mut v = vq(&q);
    q.set_desc(&mut ram, 0, buf, 16, F_NEXT, 200);
    q.publish(&mut ram, 0);
    assert_eq!(v.pop(&ram).unwrap_err(), VqError::BadIndex);
}

#[test]
fn a_loop_in_a_chain_is_cut_off() {
    let mut ram = Ram::new();
    let mut q = Queue::new(0, 8);
    let mut v = vq(&q);
    let buf = ram.alloc(16);
    q.set_desc(&mut ram, 0, buf, 16, F_NEXT, 1);
    q.set_desc(&mut ram, 1, buf, 16, F_NEXT, 0);
    q.publish(&mut ram, 0);
    assert_eq!(v.pop(&ram).unwrap_err(), VqError::TooLong);
    // And a legitimate chain of exactly MAX_CHAIN descriptors is served.
    let mut ram = Ram::new();
    let mut q = Queue::new(0, 32);
    let mut v = vq(&q);
    let buf = ram.alloc(16);
    let bufs: Vec<_> = (0..MAX_CHAIN).map(|_| (buf, 1, false)).collect();
    q.post(&mut ram, &bufs);
    assert_eq!(v.pop(&ram).unwrap().unwrap().descs().len(), MAX_CHAIN);
    let bufs: Vec<_> = (0..MAX_CHAIN + 1).map(|_| (buf, 1, false)).collect();
    q.post(&mut ram, &bufs);
    assert_eq!(v.pop(&ram).unwrap_err(), VqError::TooLong);
}

#[test]
fn indirect_descriptors_and_a_readable_after_a_writable_are_refused() {
    let mut ram = Ram::new();
    let mut q = Queue::new(0, 8);
    let mut v = vq(&q);
    let buf = ram.alloc(16);
    q.set_desc(&mut ram, 0, buf, 16, 4, 0);
    q.publish(&mut ram, 0);
    assert_eq!(v.pop(&ram).unwrap_err(), VqError::Indirect);
    let mut ram = Ram::new();
    let mut q = Queue::new(0, 8);
    let mut v = vq(&q);
    let buf = ram.alloc(16);
    q.post(&mut ram, &[(buf, 4, true), (buf, 4, false)]);
    assert_eq!(v.pop(&ram).unwrap_err(), VqError::Order);
}

/// The guest-chosen address and length are range-checked before any model
/// touches them, and a sum that wraps is outside RAM, not inside it.
#[test]
fn a_descriptor_outside_ram_is_refused_before_it_is_touched() {
    for (addr, len) in [
        (0u64, 16u32),                       // below RAM
        (RAM_BASE + RAM_BYTES as u64, 1),    // just past it
        (RAM_BASE + RAM_BYTES as u64 - 8, 16), // straddling the end
        (u64::MAX - 7, 64),                  // addr + len wraps past zero
        (u64::MAX, u32::MAX),
    ] {
        let mut ram = Ram::new();
        let mut q = Queue::new(0, 8);
        let mut v = vq(&q);
        q.post(&mut ram, &[(addr, len, true)]);
        assert_eq!(v.pop(&ram).unwrap_err(), VqError::Ram, "descriptor {addr:#x}+{len}");
        assert_eq!(ram.violations.get(), 0, "RAM was asked for {addr:#x}+{len}");
    }
}

#[test]
fn a_queue_the_driver_misplaces_cannot_be_turned_on() {
    let ram = Ram::new();
    let q = Queue::new(0, 8);
    let mut v = Virtq::EMPTY;
    assert!(!v.valid(&ram), "no size set");
    v.num = 8;
    v.desc = q.desc;
    v.avail = q.avail;
    v.used = q.used;
    assert!(v.valid(&ram));
    for bad in [0u16, 3, 6, 256] {
        let mut b = v;
        b.num = bad;
        assert!(!b.valid(&ram), "size {bad}");
    }
    for (name, edit) in [
        ("desc misaligned", (|b: &mut Virtq| b.desc += 8) as fn(&mut Virtq)),
        ("avail odd", |b| b.avail += 1),
        ("used misaligned", |b| b.used += 2),
        ("desc outside RAM", |b| b.desc = 0x1000),
        ("used past RAM", |b| b.used = RAM_BASE + RAM_BYTES as u64 - 4),
        ("avail wraps", |b| b.avail = u64::MAX - 1),
    ] {
        let mut b = v;
        edit(&mut b);
        assert!(!b.valid(&ram), "{name}");
    }
}

#[test]
fn a_queue_that_is_not_ready_yields_nothing() {
    let mut ram = Ram::new();
    let mut q = Queue::new(0, 8);
    let mut v = vq(&q);
    let buf = ram.alloc(8);
    q.post(&mut ram, &[(buf, 8, true)]);
    v.ready = false;
    assert!(v.pop(&ram).unwrap().is_none());
    v.ready = true;
    assert!(v.pop(&ram).unwrap().is_some());
}

#[test]
fn indexes_wrap_at_sixteen_bits() {
    let mut ram = Ram::new();
    let mut q = Queue::new(0, 4);
    let mut v = vq(&q);
    let buf = ram.alloc(8);
    // 70_000 round trips push both free-running indexes through 65_535 -> 0.
    for i in 0..70_000u32 {
        let h = q.post(&mut ram, &[(buf, 8, true)]);
        let c = v.pop(&ram).unwrap().unwrap_or_else(|| panic!("round {i}"));
        assert_eq!(c.head, h);
        v.push_used(&mut ram, &c, 8).unwrap();
        assert_eq!(q.used_idx(&ram), (i + 1) as u16);
    }
}

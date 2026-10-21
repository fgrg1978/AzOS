// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The virtio-mmio register file, through a block device.

use crate::blk::Blk;
use crate::harness::*;
use crate::mmio::{status, Transport, F_VERSION_1, WINDOW};

fn blk(sectors: usize) -> Transport<Blk<MemStore>> {
    Transport::new(Blk::new(MemStore::new(sectors)))
}

#[test]
fn the_identity_registers_say_a_modern_block_device() {
    let mut ram = Ram::new();
    let mut t = blk(8);
    assert_eq!(rd(&mut t, &mut ram, r::MAGIC), 0x7472_6976);
    assert_eq!(rd(&mut t, &mut ram, r::VERSION), 2);
    assert_eq!(rd(&mut t, &mut ram, r::DEVICE_ID), 2);
    assert_eq!(rd(&mut t, &mut ram, r::VENDOR_ID), 0x534F_7A41);
    w(&mut t, &mut ram, r::DEVICE_FEATURES_SEL, 1);
    assert_eq!(rd(&mut t, &mut ram, r::DEVICE_FEATURES), (F_VERSION_1 >> 32) as u32);
    w(&mut t, &mut ram, r::DEVICE_FEATURES_SEL, 0);
    let low = rd(&mut t, &mut ram, r::DEVICE_FEATURES);
    assert_eq!(low & (1 << 5), 0, "a writable disk does not offer RO");
    assert_ne!(low & (1 << 9), 0, "FLUSH is offered");
    // Selecting any other word reads word 0 or 1 (bit 0 of the selector), never garbage.
    w(&mut t, &mut ram, r::DEVICE_FEATURES_SEL, 3);
    assert_eq!(rd(&mut t, &mut ram, r::DEVICE_FEATURES), (F_VERSION_1 >> 32) as u32);
}

#[test]
fn a_read_only_store_offers_ro() {
    let mut ram = Ram::new();
    let mut s = MemStore::new(8);
    s.ro = true;
    let mut t = Transport::new(Blk::new(s));
    assert_ne!(rd(&mut t, &mut ram, r::DEVICE_FEATURES) & (1 << 5), 0);
}

#[test]
fn features_ok_needs_version_1_and_nothing_unoffered() {
    for (name, feats, ok) in [
        ("version 1 alone", F_VERSION_1, true),
        ("version 1 and flush", F_VERSION_1 | 1 << 9, true),
        ("legacy driver", 1 << 9, false),
        ("none", 0, false),
        ("an unoffered bit", F_VERSION_1 | 1 << 20, false),
        ("an unoffered high bit", F_VERSION_1 | 1 << 40, false),
    ] {
        let mut ram = Ram::new();
        let mut t = blk(8);
        w(&mut t, &mut ram, r::STATUS, ACK | DRIVER);
        w(&mut t, &mut ram, r::DRIVER_FEATURES_SEL, 0);
        w(&mut t, &mut ram, r::DRIVER_FEATURES, feats as u32);
        w(&mut t, &mut ram, r::DRIVER_FEATURES_SEL, 1);
        w(&mut t, &mut ram, r::DRIVER_FEATURES, (feats >> 32) as u32);
        w(&mut t, &mut ram, r::STATUS, ACK | DRIVER | status::FEATURES_OK);
        let got = rd(&mut t, &mut ram, r::STATUS) & status::FEATURES_OK != 0;
        assert_eq!(got, ok, "{name}");
    }
}

#[test]
fn features_cannot_change_after_features_ok() {
    let mut ram = Ram::new();
    let mut t = blk(8);
    let s = bring_up(&mut t, &mut ram, 0, &[]);
    assert_eq!(s & status::FEATURES_OK, status::FEATURES_OK);
    // A late write of an unoffered bit does not take; the device is still sound.
    w(&mut t, &mut ram, r::DRIVER_FEATURES_SEL, 0);
    w(&mut t, &mut ram, r::DRIVER_FEATURES, 1 << 20);
    w(&mut t, &mut ram, r::STATUS, s);
    assert_eq!(rd(&mut t, &mut ram, r::STATUS) & status::FEATURES_OK, status::FEATURES_OK);
}

#[test]
fn queues_exist_as_the_device_has_them() {
    let mut ram = Ram::new();
    let mut t = blk(8);
    w(&mut t, &mut ram, r::QUEUE_SEL, 0);
    assert_eq!(rd(&mut t, &mut ram, r::QUEUE_NUM_MAX), 128);
    w(&mut t, &mut ram, r::QUEUE_SEL, 1);
    assert_eq!(rd(&mut t, &mut ram, r::QUEUE_NUM_MAX), 0, "block has one queue");
    // Programming a queue that does not exist changes nothing.
    w(&mut t, &mut ram, r::QUEUE_NUM, 8);
    w(&mut t, &mut ram, r::QUEUE_READY, 1);
    assert_eq!(rd(&mut t, &mut ram, r::QUEUE_READY), 0);
}

#[test]
fn a_queue_is_ready_only_when_it_is_valid() {
    let mut ram = Ram::new();
    let q = Queue::new(0, 8);
    let mut t = blk(8);
    set_queue(&mut t, &mut ram, 0, &q);
    w(&mut t, &mut ram, r::QUEUE_SEL, 0);
    w(&mut t, &mut ram, r::QUEUE_READY, 1);
    assert_eq!(rd(&mut t, &mut ram, r::QUEUE_READY), 1);
    // Not a power of two.
    let mut t = blk(8);
    set_queue(&mut t, &mut ram, 0, &q);
    w(&mut t, &mut ram, r::QUEUE_NUM, 7);
    w(&mut t, &mut ram, r::QUEUE_READY, 1);
    assert_eq!(rd(&mut t, &mut ram, r::QUEUE_READY), 0);
    // A ring outside RAM.
    let mut t = blk(8);
    set_queue(&mut t, &mut ram, 0, &q);
    w(&mut t, &mut ram, r::QUEUE_DEVICE_HIGH, 1);
    w(&mut t, &mut ram, r::QUEUE_READY, 1);
    assert_eq!(rd(&mut t, &mut ram, r::QUEUE_READY), 0);
}

#[test]
fn a_ready_queue_cannot_be_moved_under_the_device() {
    let mut ram = Ram::new();
    let q = Queue::new(0, 8);
    let mut t = blk(8);
    bring_up(&mut t, &mut ram, 0, &[&q]);
    w(&mut t, &mut ram, r::QUEUE_SEL, 0);
    w(&mut t, &mut ram, r::QUEUE_DESC_LOW, 0x1234);
    w(&mut t, &mut ram, r::QUEUE_NUM, 4);
    // Still served from where it was.
    let mut q = q;
    let buf = ram.alloc(512 + 1);
    let hdr = ram.put(&[0u8; 16]);
    q.post(&mut ram, &[(hdr, 16, false), (buf, 513, true)]);
    kick(&mut t, &mut ram, 0);
    assert_eq!(q.used_idx(&ram), 1);
}

#[test]
fn a_kick_before_driver_ok_does_nothing() {
    let mut ram = Ram::new();
    let mut q = Queue::new(0, 8);
    let mut t = blk(8);
    w(&mut t, &mut ram, r::STATUS, ACK | DRIVER);
    set_queue(&mut t, &mut ram, 0, &q);
    w(&mut t, &mut ram, r::QUEUE_READY, 1);
    let (hdr, st) = (ram.put(&[0u8; 16]), ram.alloc(1));
    q.post(&mut ram, &[(hdr, 16, false), (st, 1, true)]);
    kick(&mut t, &mut ram, 0);
    assert_eq!(q.used_idx(&ram), 0);
    assert!(!t.irq_level());
}

#[test]
fn a_corrupt_queue_needs_a_reset_and_a_reset_cures_it() {
    let mut ram = Ram::new();
    let mut q = Queue::new(0, 8);
    let mut t = blk(8);
    bring_up(&mut t, &mut ram, 0, &[&q]);
    q.publish(&mut ram, 99);
    kick(&mut t, &mut ram, 0);
    let s = rd(&mut t, &mut ram, r::STATUS);
    assert_ne!(s & status::NEEDS_RESET, 0);
    assert_eq!(rd(&mut t, &mut ram, r::INTERRUPT_STATUS), 2, "configuration change");
    assert!(t.irq_level());
    // The driver cannot clear the flag by writing the status back without it.
    w(&mut t, &mut ram, r::STATUS, s & !status::NEEDS_RESET);
    assert_ne!(rd(&mut t, &mut ram, r::STATUS) & status::NEEDS_RESET, 0);
    // Nothing is served while flagged, even a good request.
    let mut q2 = Queue::new(1, 8);
    let (hdr, st) = (ram.put(&[0u8; 16]), ram.alloc(1));
    q2.post(&mut ram, &[(hdr, 16, false), (st, 1, true)]);
    kick(&mut t, &mut ram, 0);
    assert_eq!(q2.used_idx(&ram), 0);
    // Reset, and the device comes back.
    w(&mut t, &mut ram, r::STATUS, 0);
    assert_eq!(rd(&mut t, &mut ram, r::STATUS), 0);
    assert!(!t.irq_level());
    let s = bring_up(&mut t, &mut ram, 0, &[&q2]);
    assert_eq!(s & status::NEEDS_RESET, 0);
    kick(&mut t, &mut ram, 0);
    assert_eq!(q2.used_idx(&ram), 1);
}

#[test]
fn reset_forgets_the_queues() {
    let mut ram = Ram::new();
    let q = Queue::new(0, 8);
    let mut t = blk(8);
    bring_up(&mut t, &mut ram, 0, &[&q]);
    w(&mut t, &mut ram, r::STATUS, 0);
    w(&mut t, &mut ram, r::QUEUE_SEL, 0);
    assert_eq!(rd(&mut t, &mut ram, r::QUEUE_READY), 0);
}

#[test]
fn interrupt_status_is_acknowledged_bit_by_bit() {
    let mut ram = Ram::new();
    let mut q = Queue::new(0, 8);
    let mut t = blk(8);
    bring_up(&mut t, &mut ram, 0, &[&q]);
    let (hdr, st) = (ram.put(&[0u8; 16]), ram.alloc(1));
    q.post(&mut ram, &[(hdr, 16, false), (st, 1, true)]);
    kick(&mut t, &mut ram, 0);
    assert_eq!(rd(&mut t, &mut ram, r::INTERRUPT_STATUS), 1);
    w(&mut t, &mut ram, r::INTERRUPT_ACK, 2);
    assert!(t.irq_level(), "acknowledging another bit leaves it");
    w(&mut t, &mut ram, r::INTERRUPT_ACK, 1);
    assert!(!t.irq_level());
}

#[test]
fn registers_take_only_aligned_32_bit_accesses() {
    let mut ram = Ram::new();
    let mut t = blk(8);
    assert_eq!(t.access(r::MAGIC, false, 2, 0, &mut ram), 0);
    assert_eq!(t.access(r::MAGIC, false, 1, 0, &mut ram), 0);
    assert_eq!(t.access(r::MAGIC, false, 8, 0, &mut ram), 0);
    assert_eq!(t.access(r::MAGIC + 2, false, 4, 0, &mut ram), 0);
    assert_eq!(t.bad_accesses, 4);
    // A write of the wrong width does not reach the register.
    t.access(r::STATUS, true, 1, ACK as u64, &mut ram);
    assert_eq!(rd(&mut t, &mut ram, r::STATUS), 0);
    // Unknown registers read 0 and write to nothing.
    assert_eq!(rd(&mut t, &mut ram, 0x0f0), 0);
    w(&mut t, &mut ram, 0x0f0, 7);
}

#[test]
fn config_space_reads_at_every_width_and_cannot_be_written() {
    let mut ram = Ram::new();
    let mut t = blk(8);
    let cap = t.access(r::CONFIG, false, 8, 0, &mut ram);
    assert_eq!(cap, 8);
    assert_eq!(t.access(r::CONFIG, false, 4, 0, &mut ram), 8);
    assert_eq!(t.access(r::CONFIG + 4, false, 4, 0, &mut ram), 0);
    assert_eq!(t.access(r::CONFIG, false, 1, 0, &mut ram), 8);
    assert_eq!(t.access(r::CONFIG, false, 2, 0, &mut ram), 8);
    // seg_max at 12, past it zero.
    assert_eq!(t.access(r::CONFIG + 12, false, 4, 0, &mut ram), 14);
    assert_eq!(t.access(r::CONFIG + 0x80, false, 4, 0, &mut ram), 0);
    // Misaligned or odd-sized: dropped.
    assert_eq!(t.access(r::CONFIG + 1, false, 4, 0, &mut ram), 0);
    assert_eq!(t.access(r::CONFIG, false, 3, 0, &mut ram), 0);
    t.access(r::CONFIG, true, 8, 99, &mut ram);
    assert_eq!(t.access(r::CONFIG, false, 8, 0, &mut ram), 8, "capacity is the host's");
    assert_eq!(WINDOW, 0x200);
}

/// A disk with one read posted and the queue ready, but no feature
/// negotiation: the driver's status writes are the test's.
fn posted() -> (Transport<Blk<MemStore>>, Ram, Queue, u64) {
    let mut ram = Ram::new();
    let mut t = blk(8);
    let mut q = Queue::new(0, 8);
    set_queue(&mut t, &mut ram, 0, &q);
    w(&mut t, &mut ram, r::QUEUE_SEL, 0);
    w(&mut t, &mut ram, r::QUEUE_READY, 1);
    let mut h = [0u8; 16];
    h[8..16].copy_from_slice(&1u64.to_le_bytes());
    let (hdr, data, st) = (ram.put(&h), ram.put(&[0xAA; 512]), ram.put(&[0xEE]));
    q.post(&mut ram, &[(hdr, 16, false), (data, 512, true), (st, 1, true)]);
    (t, ram, q, data)
}

fn offer(t: &mut Transport<Blk<MemStore>>, ram: &mut Ram, feats: u64) {
    w(t, ram, r::DRIVER_FEATURES_SEL, 0);
    w(t, ram, r::DRIVER_FEATURES, feats as u32);
    w(t, ram, r::DRIVER_FEATURES_SEL, 1);
    w(t, ram, r::DRIVER_FEATURES, (feats >> 32) as u32);
}

#[test]
fn driver_ok_written_first_serves_nothing() {
    let (mut t, mut ram, q, data) = posted();
    // No ACK, no DRIVER, no features: a bare DRIVER_OK.
    w(&mut t, &mut ram, r::STATUS, status::DRIVER_OK);
    assert_eq!(rd(&mut t, &mut ram, r::STATUS) & status::DRIVER_OK, 0, "the device did not take DRIVER_OK");
    kick(&mut t, &mut ram, 0);
    assert_eq!(q.used_idx(&ram), 0, "no request was served");
    assert_eq!(ram.get(data, 4), [0xAA; 4]);
    assert!(t.dev.store.reads.is_empty());
}

#[test]
fn driver_ok_after_a_refused_features_ok_serves_nothing() {
    let (mut t, mut ram, q, _) = posted();
    // A legacy driver: no VERSION_1, so FEATURES_OK is refused.
    w(&mut t, &mut ram, r::STATUS, ACK | DRIVER);
    offer(&mut t, &mut ram, 1 << 9);
    // Everything at once: FEATURES_OK is refused, DRIVER_OK rides along.
    w(&mut t, &mut ram, r::STATUS, ACK | DRIVER | status::FEATURES_OK | status::DRIVER_OK);
    let s = rd(&mut t, &mut ram, r::STATUS);
    assert_eq!(s & (status::FEATURES_OK | status::DRIVER_OK), 0, "status {s:#x}");
    kick(&mut t, &mut ram, 0);
    // The driver writes back what it read plus DRIVER_OK, the way the spec's
    // "clear FEATURES_OK" mistake looks from the device.
    w(&mut t, &mut ram, r::STATUS, (s | status::DRIVER_OK) & !status::FEATURES_OK);
    kick(&mut t, &mut ram, 0);
    assert_eq!(rd(&mut t, &mut ram, r::STATUS) & status::DRIVER_OK, 0);
    assert_eq!(q.used_idx(&ram), 0, "no request was served");
    assert!(t.dev.store.reads.is_empty());
}

#[test]
fn driver_ok_with_the_granted_features_serves() {
    let (mut t, mut ram, q, _) = posted();
    w(&mut t, &mut ram, r::STATUS, ACK | DRIVER);
    offer(&mut t, &mut ram, F_VERSION_1);
    w(&mut t, &mut ram, r::STATUS, ACK | DRIVER | status::FEATURES_OK);
    w(&mut t, &mut ram, r::STATUS, ACK | DRIVER | status::FEATURES_OK | status::DRIVER_OK);
    assert_eq!(rd(&mut t, &mut ram, r::STATUS) & status::DRIVER_OK, status::DRIVER_OK);
    kick(&mut t, &mut ram, 0);
    assert_eq!(q.used_idx(&ram), 1);
}

#[test]
fn granted_features_stay_granted_until_a_reset() {
    let (mut t, mut ram, _, _) = posted();
    w(&mut t, &mut ram, r::STATUS, ACK | DRIVER);
    offer(&mut t, &mut ram, F_VERSION_1);
    w(&mut t, &mut ram, r::STATUS, ACK | DRIVER | status::FEATURES_OK);
    // A write that leaves FEATURES_OK out does not take it back: the features
    // are frozen under the queues.
    w(&mut t, &mut ram, r::STATUS, ACK | DRIVER);
    assert_eq!(rd(&mut t, &mut ram, r::STATUS) & status::FEATURES_OK, status::FEATURES_OK);
    w(&mut t, &mut ram, r::STATUS, 0);
    assert_eq!(rd(&mut t, &mut ram, r::STATUS), 0);
}

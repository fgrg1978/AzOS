// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The net backend: frames out of the transmit queue, frames into the
//! receive queue, with the modern 12-byte header.

use crate::harness::*;
use crate::mmio::Transport;
use crate::net::{Net, FRAME_MAX, HDR};

const MAC: [u8; 6] = [0x02, 0x41, 0x7A, 0x4F, 0x53, 0x01];
const PEER: [u8; 6] = [0x02, 0, 0, 0, 0, 0x99];

struct Nic {
    t: Transport<Net<TestLink>>,
    ram: Ram,
    rx: Queue,
    tx: Queue,
}

fn nic() -> Nic {
    let mut ram = Ram::new();
    let (rx, tx) = (Queue::new(0, 16), Queue::new(1, 16));
    let mut t = Transport::new(Net::new(TestLink::default(), MAC));
    bring_up(&mut t, &mut ram, 1 << 5 | 1 << 16, &[&rx, &tx]);
    Nic { t, ram, rx, tx }
}

/// An Ethernet frame from `src` to `dst` carrying `payload` bytes.
fn frame(dst: [u8; 6], src: [u8; 6], payload: usize) -> Vec<u8> {
    let mut f = Vec::new();
    f.extend_from_slice(&dst);
    f.extend_from_slice(&src);
    f.extend_from_slice(&[0x08, 0x00]);
    f.extend((0..payload).map(|i| (i % 253) as u8));
    f
}

impl Nic {
    /// The guest sends `frame` behind a header, in one buffer.
    fn send(&mut self, frame: &[u8]) {
        let mut buf = vec![0u8; HDR];
        buf.extend_from_slice(frame);
        let a = self.ram.put(&buf);
        self.tx.post(&mut self.ram, &[(a, buf.len() as u32, false)]);
        kick(&mut self.t, &mut self.ram, 1);
    }

    /// The guest offers a receive buffer of `len` bytes.
    fn offer(&mut self, len: u32) -> u64 {
        let a = self.ram.put(&vec![0xCC; len as usize]);
        self.rx.post(&mut self.ram, &[(a, len, true)]);
        a
    }
}

#[test]
fn identity_and_config() {
    let mut n = nic();
    assert_eq!(rd(&mut n.t, &mut n.ram, r::DEVICE_ID), 1);
    let cfg = n.t.access(r::CONFIG, false, 8, 0, &mut n.ram).to_le_bytes();
    assert_eq!(cfg[..6], MAC);
    assert_eq!(u16::from_le_bytes([cfg[6], cfg[7]]), 1, "link up");
    w(&mut n.t, &mut n.ram, r::QUEUE_SEL, 1);
    assert_eq!(rd(&mut n.t, &mut n.ram, r::QUEUE_NUM_MAX), 128);
    w(&mut n.t, &mut n.ram, r::QUEUE_SEL, 2);
    assert_eq!(rd(&mut n.t, &mut n.ram, r::QUEUE_NUM_MAX), 0);
}

#[test]
fn a_transmitted_frame_reaches_the_link_without_the_header() {
    let mut n = nic();
    let f = frame(PEER, MAC, 100);
    n.send(&f);
    assert_eq!(n.t.dev.link.sent, vec![f]);
    assert_eq!(n.tx.used_idx(&n.ram), 1);
    assert_eq!(n.tx.used(&n.ram, 0).1, 0);
    assert!(n.t.irq_level());
}

#[test]
fn a_frame_spread_over_descriptors_is_gathered() {
    let mut n = nic();
    let f = frame(PEER, MAC, 1000);
    let mut buf = vec![0u8; HDR];
    buf.extend_from_slice(&f);
    let parts: Vec<(u64, u32, bool)> = buf.chunks(300).map(|c| (n.ram.put(c), c.len() as u32, false)).collect();
    n.tx.post(&mut n.ram, &parts);
    kick(&mut n.t, &mut n.ram, 1);
    assert_eq!(n.t.dev.link.sent, vec![f]);
}

#[test]
fn a_frame_from_another_station_is_not_sent() {
    let mut n = nic();
    n.send(&frame(PEER, PEER, 50));
    n.send(&frame(PEER, [0xFF; 6], 50));
    assert!(n.t.dev.link.sent.is_empty());
    assert_eq!(n.t.dev.dropped_tx, 2);
    // The buffers are still returned: a dropped frame is not a stuck queue.
    assert_eq!(n.tx.used_idx(&n.ram), 2);
    n.send(&frame(PEER, MAC, 50));
    assert_eq!(n.t.dev.link.sent.len(), 1);
}

#[test]
fn frames_that_are_too_short_or_too_long_are_dropped() {
    let mut n = nic();
    n.send(&frame(PEER, MAC, 0)[..10]);
    n.send(&frame(PEER, MAC, FRAME_MAX)); // 14 + FRAME_MAX bytes
    assert!(n.t.dev.link.sent.is_empty());
    assert_eq!(n.t.dev.dropped_tx, 2);
    n.send(&frame(PEER, MAC, FRAME_MAX - 14));
    assert_eq!(n.t.dev.link.sent.len(), 1, "the largest frame goes");
    // A buffer without even a header.
    let a = n.ram.put(&[1, 2, 3]);
    n.tx.post(&mut n.ram, &[(a, 3, false)]);
    kick(&mut n.t, &mut n.ram, 1);
    assert_eq!(n.t.dev.dropped_tx, 3);
}

#[test]
fn a_link_that_refuses_a_frame_drops_it_and_counts() {
    let mut n = nic();
    n.t.dev.link.refuse = true;
    n.send(&frame(PEER, MAC, 60));
    assert_eq!((n.t.dev.sent, n.t.dev.dropped_tx), (0, 1));
}

#[test]
fn a_received_frame_lands_behind_a_header_with_one_buffer() {
    let mut n = nic();
    let f = frame(MAC, PEER, 200);
    n.t.dev.link.inbox.push_back(f.clone());
    let a = n.offer(2048);
    n.t.poll(&mut n.ram);
    assert_eq!(n.rx.used_idx(&n.ram), 1);
    assert_eq!(n.rx.used(&n.ram, 0).1 as usize, HDR + f.len());
    let got = n.ram.get(a, HDR + f.len());
    assert_eq!(got[..10], [0u8; 10]);
    assert_eq!(u16::from_le_bytes([got[10], got[11]]), 1, "num_buffers");
    assert_eq!(got[HDR..], f[..]);
    assert!(n.t.irq_level());
}

#[test]
fn a_frame_waits_for_a_buffer_and_then_arrives() {
    let mut n = nic();
    let f = frame(MAC, PEER, 64);
    n.t.dev.link.inbox.push_back(f.clone());
    n.t.poll(&mut n.ram);
    assert_eq!(n.rx.used_idx(&n.ram), 0, "no buffer, nothing delivered");
    let a = n.offer(1600);
    // The guest kicks the receive queue after refilling it.
    kick(&mut n.t, &mut n.ram, 0);
    assert_eq!(n.rx.used_idx(&n.ram), 1);
    assert_eq!(n.ram.get(a + HDR as u64, f.len()), f);
    assert_eq!(n.t.dev.received, 1);
}

#[test]
fn a_buffer_too_small_for_the_frame_is_returned_empty() {
    let mut n = nic();
    n.t.dev.link.inbox.push_back(frame(MAC, PEER, 500));
    n.t.dev.link.inbox.push_back(frame(MAC, PEER, 20));
    n.offer(100);
    n.offer(100);
    n.t.poll(&mut n.ram);
    assert_eq!(n.t.dev.dropped_rx, 1);
    assert_eq!(n.t.dev.received, 1);
    assert_eq!(n.rx.used(&n.ram, 0).1, 0);
    assert_eq!(n.rx.used(&n.ram, 1).1 as usize, HDR + 34);
}

#[test]
fn several_frames_fill_several_buffers() {
    let mut n = nic();
    for i in 0..3 {
        n.t.dev.link.inbox.push_back(frame(MAC, PEER, 30 + i));
        n.offer(256);
    }
    n.t.poll(&mut n.ram);
    assert_eq!(n.rx.used_idx(&n.ram), 3);
    for i in 0..3u16 {
        assert_eq!(n.rx.used(&n.ram, i).1 as usize, HDR + 44 + i as usize);
    }
}

#[test]
fn polling_before_the_driver_is_ready_takes_nothing() {
    let mut ram = Ram::new();
    let mut t = Transport::new(Net::new(TestLink::default(), MAC));
    t.dev.link.inbox.push_back(frame(MAC, PEER, 20));
    t.poll(&mut ram);
    assert_eq!(t.dev.link.inbox.len(), 1);
}

/// The guest's NIC joined to a virtual interface: the virtio-net device on
/// one end of a ring pair, whoever bridges it on the other.
mod joined {
    use super::*;
    use crate::ringlink::{Peer, RingLink, REGION_BYTES};

    struct Joined {
        t: Transport<Net<RingLink>>,
        ram: Ram,
        rx: Queue,
        tx: Queue,
        peer: Peer,
        _mem: Vec<u64>,
    }

    fn joined() -> Joined {
        let mut mem = vec![0u64; REGION_BYTES.div_ceil(8)];
        // SAFETY: a live, 8-aligned Vec of REGION_BYTES that outlives both ends
        // (it is a field of the struct that holds them).
        let (a, b) = unsafe { (RingLink::new(mem.as_mut_ptr() as *mut u8), RingLink::new(mem.as_mut_ptr() as *mut u8)) };
        let mut ram = Ram::new();
        let (rx, tx) = (Queue::new(0, 16), Queue::new(1, 16));
        let mut t = Transport::new(Net::new(a, MAC));
        bring_up(&mut t, &mut ram, 1 << 5 | 1 << 16, &[&rx, &tx]);
        Joined { t, ram, rx, tx, peer: Peer(b), _mem: mem }
    }

    #[test]
    fn a_frame_the_guest_sends_arrives_at_the_other_end_of_the_interface() {
        let mut j = joined();
        let f = frame(PEER, MAC, 300);
        let mut buf = vec![0u8; HDR];
        buf.extend_from_slice(&f);
        let a = j.ram.put(&buf);
        j.tx.post(&mut j.ram, &[(a, buf.len() as u32, false)]);
        kick(&mut j.t, &mut j.ram, 1);
        let mut got = [0u8; FRAME_MAX];
        assert_eq!(j.peer.take(&mut got), Some(f.len()));
        assert_eq!(got[..f.len()], f[..]);
        assert_eq!(j.peer.take(&mut got), None);
        assert_eq!(j.tx.used_idx(&j.ram), 1, "the buffer went back to the guest");
    }

    #[test]
    fn a_frame_the_bridge_delivers_reaches_the_guest_behind_a_header() {
        let mut j = joined();
        let f = frame(MAC, PEER, 120);
        assert!(j.peer.give(&f));
        let a = j.ram.put(&vec![0xCC; 2048]);
        j.rx.post(&mut j.ram, &[(a, 2048, true)]);
        j.t.poll(&mut j.ram);
        assert_eq!(j.rx.used_idx(&j.ram), 1);
        assert_eq!(j.ram.get(a + HDR as u64, f.len()), f);
        assert!(j.t.irq_level());
    }

    #[test]
    fn a_bridge_that_lies_in_a_slot_or_floods_the_ring_cannot_reach_guest_memory() {
        let mut j = joined();
        // The guest gets a buffer smaller than the frame, then a good one.
        assert!(j.peer.give(&frame(MAC, PEER, 1400)));
        assert!(j.peer.give(&frame(MAC, PEER, 20)));
        let small = j.ram.put(&vec![0xCC; 64]);
        j.rx.post(&mut j.ram, &[(small, 64, true)]);
        j.t.poll(&mut j.ram);
        assert_eq!(j.t.dev.dropped_rx, 1);
        assert_eq!(j.ram.get(small + 64 - 4, 4), [0xCC; 4], "nothing written past the buffer");
        let big = j.ram.put(&vec![0xCC; 2048]);
        j.rx.post(&mut j.ram, &[(big, 2048, true)]);
        j.t.poll(&mut j.ram);
        assert_eq!(j.t.dev.received, 1);
        assert_eq!(j.ram.violations.get(), 0);
    }

    #[test]
    fn a_guest_that_floods_the_interface_fills_its_ring_and_not_vmmd() {
        let mut j = joined();
        for _ in 0..16 {
            let mut buf = vec![0u8; HDR];
            buf.extend_from_slice(&frame(PEER, MAC, 100));
            let a = j.ram.put(&buf);
            j.tx.post(&mut j.ram, &[(a, buf.len() as u32, false)]);
        }
        kick(&mut j.t, &mut j.ram, 1);
        // Eight slots hold; the rest are dropped and counted, every buffer comes back.
        assert_eq!(j.t.dev.sent, crate::ringlink::SLOTS);
        assert_eq!(j.t.dev.dropped_tx, 16 - crate::ringlink::SLOTS);
        assert_eq!(j.tx.used_idx(&j.ram), 16);
    }
}

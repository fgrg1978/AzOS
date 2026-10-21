// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The trap records and rings, the NIC ring pair, and the disk over a file
//! that cannot seek.

use crate::blk::{Blk, BlockStore, IoError, SECTOR};
use crate::harness::*;
use crate::mmio::Transport;
use crate::net::{Link, FRAME_MAX};
use crate::ringlink::{Peer, RingLink, REGION_BYTES, SLOTS, SLOT_BYTES};
use crate::store::{SeqFile, SeqStore, WORK_BYTES};
use crate::trap::{Completion, Rings, Trap, PAGE_BYTES, TRAPS};

fn trap(seq: u32) -> Trap {
    Trap { seq, vcpu: 3, write: seq % 2 == 0, len: 4, gpa: 0x1000_1070 + seq as u64, data: 0xDEAD_0000 + seq as u64 }
}

#[test]
fn the_records_round_trip_and_have_the_documented_layout() {
    let t = trap(7);
    let b = t.encode();
    assert_eq!(Trap::decode(&b), t);
    assert_eq!(&b[0..4], &7u32.to_le_bytes());
    assert_eq!((b[4], b[5], b[6]), (3, 0, 4));
    assert_eq!(&b[8..16], &t.gpa.to_le_bytes());
    let c = Completion { seq: 9, status: 2, data: u64::MAX - 1 };
    let e = c.encode();
    assert_eq!(Completion::decode(&e), c);
    assert_eq!(&e[4..8], &2u32.to_le_bytes());
    assert!(PAGE_BYTES <= 4096);
}

struct Page(Vec<u64>);

impl Page {
    fn new() -> Page {
        Page(vec![0; 512])
    }

    fn rings(&mut self) -> Rings {
        // SAFETY: a live, 8-aligned 4096-byte Vec.
        unsafe { Rings::new(self.0.as_mut_ptr() as *mut u8) }
    }

    fn set(&mut self, off: usize, v: u32) {
        let b = unsafe { std::slice::from_raw_parts_mut(self.0.as_mut_ptr() as *mut u8, 4096) };
        b[off..off + 4].copy_from_slice(&v.to_le_bytes());
    }

    fn put_trap(&mut self, slot: u32, t: &Trap) {
        let b = unsafe { std::slice::from_raw_parts_mut(self.0.as_mut_ptr() as *mut u8, 4096) };
        let at = 0x40 + (slot % TRAPS) as usize * 32;
        b[at..at + 32].copy_from_slice(&t.encode());
    }
}

#[test]
fn traps_come_off_the_ring_in_order() {
    let mut p = Page::new();
    for i in 0..5 {
        p.put_trap(i, &trap(i));
    }
    p.set(4, 5);
    let mut r = p.rings();
    for i in 0..5 {
        assert_eq!(r.pop_trap(), Some(trap(i)));
    }
    assert_eq!(r.pop_trap(), None);
}

#[test]
fn a_monitor_that_claims_more_traps_than_the_ring_holds_is_not_believed() {
    let mut p = Page::new();
    p.set(4, TRAPS + 1);
    assert_eq!(p.rings().pop_trap(), None);
    // And a tail behind the head (wrapped garbage) reads as too many, not as a trap.
    let mut p = Page::new();
    p.set(0, 10);
    p.set(4, 3);
    assert_eq!(p.rings().pop_trap(), None);
}

#[test]
fn the_ring_wraps_its_free_running_indexes() {
    let mut p = Page::new();
    p.set(0, u32::MAX - 1);
    p.set(4, u32::MAX - 1);
    let mut r = p.rings();
    for i in 0..4u32 {
        let slot = (u32::MAX - 1).wrapping_add(i);
        let tail = slot.wrapping_add(1);
        p.put_trap(slot, &trap(i));
        p.set(4, tail);
        assert_eq!(r.pop_trap(), Some(trap(i)), "step {i}");
    }
}

#[test]
fn completions_are_posted_until_the_ring_is_full() {
    let mut p = Page::new();
    let mut r = p.rings();
    for i in 0..TRAPS {
        assert!(r.push_completion(&Completion { seq: i, status: 0, data: i as u64 }), "{i}");
    }
    assert!(!r.push_completion(&Completion { seq: 99, status: 0, data: 0 }), "full");
    // The monitor takes two; room for two.
    p.set(8, 2);
    assert!(r.push_completion(&Completion { seq: 100, status: 0, data: 0 }));
    assert!(r.push_completion(&Completion { seq: 101, status: 0, data: 0 }));
    assert!(!r.push_completion(&Completion { seq: 102, status: 0, data: 0 }));
}

fn link() -> (Vec<u64>, RingLink, Peer) {
    let mut mem = vec![0u64; REGION_BYTES.div_ceil(8)];
    // SAFETY: a live, 8-aligned Vec of REGION_BYTES (it outlives both ends here).
    let (a, b) = unsafe { (RingLink::new(mem.as_mut_ptr() as *mut u8), RingLink::new(mem.as_mut_ptr() as *mut u8)) };
    (mem, a, Peer(b))
}

#[test]
fn frames_cross_the_ring_pair_in_both_directions() {
    let (_m, mut guest, peer) = link();
    assert!(guest.send(&[1, 2, 3, 4, 5]));
    assert!(guest.send(&[9; 1500]));
    let mut buf = [0u8; FRAME_MAX];
    assert_eq!(peer.take(&mut buf), Some(5));
    assert_eq!(buf[..5], [1, 2, 3, 4, 5]);
    assert_eq!(peer.take(&mut buf), Some(1500));
    assert_eq!(peer.take(&mut buf), None);
    assert!(peer.give(&[7; 60]));
    assert_eq!(guest.recv(&mut buf), Some(60));
    assert_eq!(guest.recv(&mut buf), None);
}

#[test]
fn the_ring_pair_is_bounded() {
    let (_m, mut guest, peer) = link();
    for _ in 0..SLOTS {
        assert!(guest.send(&[0u8; 64]));
    }
    assert!(!guest.send(&[0u8; 64]), "full: the frame is dropped, not queued without limit");
    let mut buf = [0u8; FRAME_MAX];
    assert!(peer.take(&mut buf).is_some());
    assert!(guest.send(&[0u8; 64]));
    assert!(!guest.send(&vec![0u8; FRAME_MAX + 1]), "larger than a frame");
    assert!(SLOT_BYTES >= FRAME_MAX + 4);
}

#[test]
fn a_length_the_other_end_lied_about_is_skipped_not_read() {
    let (mut mem, mut guest, peer) = link();
    assert!(peer.give(&[1; 40]));
    assert!(peer.give(&[2; 40]));
    // Corrupt the first slot's length to more than a frame (in-ring at SLOTS * SLOT_BYTES).
    let bytes = unsafe { std::slice::from_raw_parts_mut(mem.as_mut_ptr() as *mut u8, REGION_BYTES) };
    let first_in = 0x1000 + SLOTS as usize * SLOT_BYTES;
    bytes[first_in..first_in + 2].copy_from_slice(&60_000u16.to_le_bytes());
    let mut buf = [0u8; FRAME_MAX];
    assert_eq!(guest.recv(&mut buf), Some(40));
    assert_eq!(buf[..40], [2; 40], "the good frame behind it is delivered");
    assert_eq!(guest.recv(&mut buf), None);
}

/// A file with a position and no seek, over a Vec; it counts what happens.
struct Seq {
    data: Vec<u8>,
    pos: usize,
    reads: u32,
    rewinds: u32,
    syncs: u32,
    fail_after: Option<u32>,
    /// Bytes read from the file so far, skipped or not.
    bytes_read: usize,
    /// Writes fail with this.
    refuse_writes: Option<IoError>,
}

impl Seq {
    fn new(sectors: usize) -> Seq {
        let data = (0..sectors * SECTOR).map(|i| (i / SECTOR) as u8 ^ (i % 13) as u8).collect();
        Seq { data, pos: 0, reads: 0, rewinds: 0, syncs: 0, fail_after: None, bytes_read: 0, refuse_writes: None }
    }

    fn tick(&mut self) -> Result<(), IoError> {
        match self.fail_after.as_mut() {
            Some(0) => Err(IoError::Device),
            Some(n) => Ok(*n -= 1),
            None => Ok(()),
        }
    }
}

impl SeqFile for Seq {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, IoError> {
        self.tick()?;
        self.reads += 1;
        let n = buf.len().min(self.data.len() - self.pos).min(1000); // short reads happen
        self.bytes_read += n;
        buf[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }

    fn write(&mut self, data: &[u8]) -> Result<usize, IoError> {
        self.tick()?;
        if let Some(e) = self.refuse_writes {
            return Err(e);
        }
        let n = data.len().min(self.data.len() - self.pos).min(700);
        self.data[self.pos..self.pos + n].copy_from_slice(&data[..n]);
        self.pos += n;
        Ok(n)
    }

    fn rewind(&mut self) -> Result<(), IoError> {
        self.rewinds += 1;
        self.pos = 0;
        Ok(())
    }

    fn sync(&mut self) -> Result<(), IoError> {
        self.syncs += 1;
        Ok(())
    }
}

fn store(sectors: usize) -> SeqStore<Seq> {
    SeqStore::new(Seq::new(sectors), (sectors * SECTOR) as u64, false)
}

#[test]
fn a_sequential_scan_never_rewinds() {
    let mut s = store(32);
    let want = Seq::new(32).data;
    let mut buf = vec![0u8; 2 * SECTOR];
    for sec in (0..32).step_by(2) {
        s.read(sec, &mut buf).unwrap();
        assert_eq!(buf, want[sec as usize * SECTOR..][..2 * SECTOR]);
    }
    assert_eq!(s.rewinds, 0);
}

#[test]
fn going_backward_reopens_and_going_forward_reads_through() {
    let mut s = store(32);
    let want = Seq::new(32).data;
    let mut buf = vec![0u8; SECTOR];
    for sec in [20u64, 3, 3, 30, 0, 31] {
        s.read(sec, &mut buf).unwrap();
        assert_eq!(buf, want[sec as usize * SECTOR..][..SECTOR], "sector {sec}");
    }
    // 20 -> 3 (back), 3 -> 3 (back: the read consumed it), 3 -> 30 (fwd), 30 -> 0 (back), 0 -> 31 (fwd).
    assert_eq!(s.rewinds, 3);
}

#[test]
fn writes_land_where_asked_and_are_read_back() {
    let mut s = store(16);
    let pat: Vec<u8> = (0..2 * SECTOR as u32).map(|i| (i * 3) as u8).collect();
    s.write(5, &pat).unwrap();
    let mut back = vec![0u8; 2 * SECTOR];
    s.read(5, &mut back).unwrap();
    assert_eq!(back, pat);
    // And the neighbours are as they were.
    let want = Seq::new(16).data;
    let mut n = vec![0u8; SECTOR];
    s.read(4, &mut n).unwrap();
    assert_eq!(n, want[4 * SECTOR..5 * SECTOR]);
    s.read(7, &mut n).unwrap();
    assert_eq!(n, want[7 * SECTOR..8 * SECTOR]);
}

#[test]
fn a_failure_leaves_the_position_unknown_and_the_next_access_starts_over() {
    let mut s = store(16);
    let mut buf = vec![0u8; SECTOR];
    s.read(2, &mut buf).unwrap();
    s.file_mut().fail_after = Some(0);
    assert_eq!(s.read(4, &mut buf), Err(IoError::Device));
    s.file_mut().fail_after = None;
    let want = Seq::new(16).data;
    s.read(6, &mut buf).unwrap();
    assert_eq!(buf, want[6 * SECTOR..7 * SECTOR]);
    assert_eq!(s.rewinds, 1, "rewound once, from an unknown position");
}

#[test]
fn reading_past_the_end_of_the_file_is_an_error_not_zeros() {
    // The disk claims 16 sectors but the file has 8.
    let mut s = SeqStore::new(Seq::new(8), (16 * SECTOR) as u64, false);
    let mut buf = vec![0u8; SECTOR];
    assert_eq!(s.read(12, &mut buf), Err(IoError::Device));
    assert_eq!(s.capacity(), 16);
}

#[test]
fn capacity_drops_a_partial_last_sector_and_flush_syncs() {
    let mut s = SeqStore::new(Seq::new(4), (3 * SECTOR + 100) as u64, true);
    assert_eq!(s.capacity(), 3);
    assert!(s.read_only());
    s.flush().unwrap();
    assert_eq!(s.file_mut().syncs, 1);
}

#[test]
fn errno_results_mean_what_the_authority_and_the_medium_mean() {
    for (rc, want) in [
        (-1, IoError::Denied),
        (-13, IoError::Denied),
        (-201, IoError::Denied),
        (-11, IoError::Contained),
        (-5, IoError::Device),
        (-2, IoError::Device),
    ] {
        assert_eq!(IoError::from_errno(rc), want, "rc {rc}");
    }
}

#[test]
fn the_store_stops_at_its_budget_and_goes_on_from_there() {
    let mut s = store(1024); // 512 KiB
    let want = Seq::new(1024).data;
    let mut buf = vec![0u8; SECTOR];
    // Sector 1000 is 125 chunks in; one budget is 16.
    let mut calls = 0;
    loop {
        calls += 1;
        let before = s.file_mut().bytes_read;
        let r = s.read(1000, &mut buf);
        let moved = s.file_mut().bytes_read - before;
        assert!(moved <= WORK_BYTES + 2 * 4096, "a call did {moved} bytes of file work");
        match r {
            Ok(()) => break,
            Err(IoError::Again) => s.refill(),
            Err(e) => panic!("{e:?}"),
        }
        assert!(calls < 20, "the seek never ends");
    }
    assert!(calls >= 7, "{calls} calls: the budget was not what bounded the work");
    assert_eq!(buf, want[1000 * SECTOR..1001 * SECTOR]);
    assert_eq!(s.rewinds, 0, "going on from where it got to is not going back");
}

#[test]
fn a_budget_that_ends_in_a_backward_jump_does_not_rewind_twice() {
    let mut s = store(1024);
    let mut buf = vec![0u8; SECTOR];
    s.read(900, &mut buf).ok(); // may take several calls; finish it
    while s.read(900, &mut buf) == Err(IoError::Again) {
        s.refill();
    }
    let before = s.rewinds;
    // Back to 10: one reopen, then forward in pieces.
    while s.read(10, &mut buf) == Err(IoError::Again) {
        s.refill();
    }
    assert_eq!(s.rewinds, before + 1);
    assert_eq!(buf, Seq::new(1024).data[10 * SECTOR..11 * SECTOR]);
}

/// A disk over a [`Seq`] file, driven through the transport.
struct SeqDisk {
    t: Transport<Blk<SeqStore<Seq>>>,
    ram: Ram,
    q: Queue,
}

fn seq_disk(sectors: usize) -> SeqDisk {
    let mut ram = Ram::new();
    let q = Queue::new(0, 16);
    let mut t = Transport::new(Blk::new(store(sectors)));
    bring_up(&mut t, &mut ram, 0, &[&q]);
    SeqDisk { t, ram, q }
}

impl SeqDisk {
    /// Post a read of one sector; `(status byte address, data address)`.
    fn post_read(&mut self, sector: u64) -> (u64, u64) {
        let mut h = [0u8; 16];
        h[8..16].copy_from_slice(&sector.to_le_bytes());
        let (hdr, data, st) = (self.ram.put(&h), self.ram.put(&[0xAA; SECTOR]), self.ram.put(&[0xEE]));
        self.q.post(&mut self.ram, &[(hdr, 16, false), (data, SECTOR as u32, true), (st, 1, true)]);
        (st, data)
    }
}

#[test]
fn a_far_request_does_not_hold_the_loop_and_those_behind_it_wait_their_turn() {
    let mut d = seq_disk(1024);
    let want = Seq::new(1024).data;
    let (st_far, data_far) = d.post_read(1000);
    let (st_near, data_near) = d.post_read(2);
    kick(&mut d.t, &mut d.ram, 0);
    let bytes = d.t.dev.store.file_mut().bytes_read;
    assert!(bytes <= WORK_BYTES + 2 * 4096, "the kick did {bytes} bytes of file work");
    assert_eq!(d.q.used_idx(&d.ram), 0, "the far request is still being worked on");
    assert!(d.t.busy());
    assert_eq!(d.ram.get(st_far, 1), [0xEE], "no status is written before the data is there");
    let mut passes = 0;
    while d.t.busy() {
        passes += 1;
        let before = d.t.dev.store.file_mut().bytes_read;
        d.t.poll(&mut d.ram);
        assert!(d.t.dev.store.file_mut().bytes_read - before <= WORK_BYTES + 2 * 4096);
        assert!(passes < 20);
    }
    assert!(passes >= 5, "{passes} passes");
    // Both are answered, the far one first.
    assert_eq!(d.q.used_idx(&d.ram), 2);
    assert_eq!(d.q.used(&d.ram, 0).0, 0, "the far request was the first chain");
    assert_eq!(d.ram.get(st_far, 1), [0]);
    assert_eq!(d.ram.get(data_far, SECTOR), want[1000 * SECTOR..1001 * SECTOR]);
    assert_eq!(d.ram.get(st_near, 1), [0]);
    assert_eq!(d.ram.get(data_near, SECTOR), want[2 * SECTOR..3 * SECTOR]);
    assert_eq!(d.ram.violations.get(), 0);
}

#[test]
fn a_reset_drops_the_parked_request() {
    let mut d = seq_disk(1024);
    let (st, _) = d.post_read(1000);
    kick(&mut d.t, &mut d.ram, 0);
    assert!(d.t.dev.store.file_mut().bytes_read > 0);
    w(&mut d.t, &mut d.ram, r::STATUS, 0);
    assert!(!d.t.busy());
    d.t.poll(&mut d.ram);
    assert_eq!(d.ram.get(st, 1), [0xEE], "a dropped request is never answered");
    assert_eq!(d.q.used_idx(&d.ram), 0);
}

#[test]
fn containment_is_counted_apart_from_a_failing_medium() {
    let mut d = seq_disk(16);
    let buf = d.ram.put(&[7u8; SECTOR]);
    let mut h = [0u8; 16];
    h[0..4].copy_from_slice(&1u32.to_le_bytes());
    let (hdr, st) = (d.ram.put(&h), d.ram.put(&[0xEE]));
    d.t.dev.store.file_mut().refuse_writes = Some(IoError::Contained);
    d.q.post(&mut d.ram, &[(hdr, 16, false), (buf, SECTOR as u32, false), (st, 1, true)]);
    kick(&mut d.t, &mut d.ram, 0);
    assert_eq!(d.ram.get(st, 1), [1], "the guest sees IOERR");
    assert_eq!((d.t.dev.contained, d.t.dev.errors), (1, 0));
    // A medium that fails is an error and not containment.
    d.t.dev.store.file_mut().refuse_writes = Some(IoError::Device);
    let st2 = d.ram.put(&[0xEE]);
    d.q.post(&mut d.ram, &[(hdr, 16, false), (buf, SECTOR as u32, false), (st2, 1, true)]);
    kick(&mut d.t, &mut d.ram, 0);
    assert_eq!(d.ram.get(st2, 1), [1]);
    assert_eq!((d.t.dev.contained, d.t.dev.errors), (1, 1));
}

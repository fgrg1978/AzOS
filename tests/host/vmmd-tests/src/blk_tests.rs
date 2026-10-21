// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The block backend, through the transport, driven the way a guest driver
//! does: a header, data, a status byte.

use crate::blk::{Blk, IoError, SECTOR};
use crate::harness::*;
use crate::mmio::Transport;

const IN: u32 = 0;
const OUT: u32 = 1;
const FLUSH: u32 = 4;
const GET_ID: u32 = 8;

struct Disk {
    t: Transport<Blk<MemStore>>,
    ram: Ram,
    q: Queue,
}

fn disk(sectors: usize) -> Disk {
    disk_of(MemStore::new(sectors))
}

fn disk_of(store: MemStore) -> Disk {
    let mut ram = Ram::new();
    let q = Queue::new(0, 16);
    let mut t = Transport::new(Blk::new(store));
    bring_up(&mut t, &mut ram, 0, &[&q]);
    Disk { t, ram, q }
}

fn header(ty: u32, sector: u64) -> [u8; 16] {
    let mut h = [0u8; 16];
    h[0..4].copy_from_slice(&ty.to_le_bytes());
    h[8..16].copy_from_slice(&sector.to_le_bytes());
    h
}

impl Disk {
    /// Post one request: `data` buffers (device-writable for a read), then a
    /// status byte. Returns `(status, used length)` after a kick.
    fn request(&mut self, ty: u32, sector: u64, data: &[(u64, u32)], writable: bool) -> (u8, u32) {
        let hdr = self.ram.put(&header(ty, sector));
        let st = self.ram.put(&[0xEE]);
        let mut bufs = vec![(hdr, 16u32, false)];
        bufs.extend(data.iter().map(|&(a, l)| (a, l, writable)));
        bufs.push((st, 1, true));
        let n = self.q.used_idx(&self.ram);
        self.q.post(&mut self.ram, &bufs);
        kick(&mut self.t, &mut self.ram, 0);
        assert_eq!(self.q.used_idx(&self.ram), n.wrapping_add(1), "the request was completed");
        (self.ram.get(st, 1)[0], self.q.used(&self.ram, n).1)
    }

    fn read(&mut self, sector: u64, bytes: u32) -> (u8, Vec<u8>, u32) {
        let buf = self.ram.put(&vec![0xAA; bytes as usize]);
        let (s, used) = self.request(IN, sector, &[(buf, bytes)], true);
        (s, self.ram.get(buf, bytes as usize), used)
    }

    fn write(&mut self, sector: u64, data: &[u8]) -> (u8, u32) {
        let buf = self.ram.put(data);
        self.request(OUT, sector, &[(buf, data.len() as u32)], false)
    }
}

#[test]
fn a_read_returns_the_stores_bytes_and_counts_the_status() {
    let mut d = disk(16);
    let (s, data, used) = d.read(3, 1024);
    assert_eq!(s, 0);
    assert_eq!(data, d.t.dev.store.data[3 * SECTOR..5 * SECTOR]);
    assert_eq!(used, 1024 + 1);
    assert!(d.t.irq_level());
}

#[test]
fn a_write_reaches_the_store_and_only_there() {
    let mut d = disk(16);
    let pat: Vec<u8> = (0..1024u32).map(|i| (i * 7) as u8).collect();
    let (s, used) = d.write(9, &pat);
    assert_eq!(s, 0);
    assert_eq!(used, 1);
    assert_eq!(d.t.dev.store.data[9 * SECTOR..11 * SECTOR], pat[..]);
    assert_eq!(d.t.dev.store.writes, vec![(9, 1024)]);
    let (_, back, _) = d.read(9, 1024);
    assert_eq!(back, pat);
}

#[test]
fn data_split_over_several_descriptors_is_one_request() {
    let mut d = disk(16);
    let want: Vec<u8> = d.t.dev.store.data[2 * SECTOR..4 * SECTOR].to_vec();
    let parts: Vec<(u64, u32)> = [100u32, 412, 300, 212].iter().map(|&l| (d.ram.alloc(l as usize), l)).collect();
    let (s, used) = d.request(IN, 2, &parts, true);
    assert_eq!((s, used), (0, 1025));
    let got: Vec<u8> = parts.iter().flat_map(|&(a, l)| d.ram.get(a, l as usize)).collect();
    assert_eq!(got, want);
    // And a write gathered the same way.
    let pat: Vec<u8> = (0..1024u32).map(|i| i as u8).collect();
    let parts: Vec<(u64, u32)> = [512u32, 1, 511].iter().scan(0usize, |at, &l| {
        let a = d.ram.put(&pat[*at..*at + l as usize]);
        *at += l as usize;
        Some((a, l))
    }).collect();
    assert_eq!(d.request(OUT, 6, &parts, false).0, 0);
    assert_eq!(d.t.dev.store.data[6 * SECTOR..8 * SECTOR], pat[..]);
}

#[test]
fn big_transfers_reach_the_store_in_bounded_pieces() {
    let mut d = disk(256);
    let (s, data, _) = d.read(0, 64 * 1024);
    assert_eq!(s, 0);
    assert_eq!(data, d.t.dev.store.data[..64 * 1024]);
    assert!(d.t.dev.store.reads.iter().all(|&(_, n)| n <= 4096), "{:?}", d.t.dev.store.reads);
    assert_eq!(d.t.dev.store.reads.len(), 16);
}

#[test]
fn flush_and_get_id() {
    let mut d = disk(4);
    assert_eq!(d.request(FLUSH, 0, &[], true), (0, 1));
    assert_eq!(d.t.dev.store.flushes, 1);
    let id = d.ram.put(&[0u8; 20]);
    let (s, used) = d.request(GET_ID, 0, &[(id, 20)], true);
    assert_eq!((s, used), (0, 21));
    assert_eq!(&d.ram.get(id, 9), b"azos-vmmd");
}

#[test]
fn a_type_the_device_does_not_know_is_unsupported_and_touches_nothing() {
    let mut d = disk(4);
    assert_eq!(d.request(99, 0, &[], true), (2, 1));
    assert!(d.t.dev.store.reads.is_empty() && d.t.dev.store.writes.is_empty());
    assert_eq!(d.t.dev.errors, 0, "unsupported is not an I/O error");
}

/// The guest picks the sector: a request that runs past the end must not
/// reach the store (a write there would grow the file the disk lives in).
#[test]
fn a_request_past_the_end_of_the_disk_never_reaches_the_store() {
    let mut d = disk(8);
    for (sector, bytes) in [(8u64, 512u32), (7, 1024), (u64::MAX, 512), (u64::MAX / 512 + 1, 512), (1 << 55, 512)] {
        let (s, _, used) = d.read(sector, bytes);
        assert_eq!((s, used), (1, 1), "read {sector}+{bytes}");
        let (s, _) = d.write(sector, &vec![0x55; bytes as usize]);
        assert_eq!(s, 1, "write {sector}+{bytes}");
    }
    assert!(d.t.dev.store.reads.is_empty(), "{:?}", d.t.dev.store.reads);
    assert!(d.t.dev.store.writes.is_empty(), "{:?}", d.t.dev.store.writes);
    // The last whole sector is in range.
    assert_eq!(d.read(7, 512).0, 0);
}

#[test]
fn lengths_that_are_not_whole_sectors_are_errors() {
    let mut d = disk(8);
    assert_eq!(d.read(0, 100).0, 1);
    assert_eq!(d.write(0, &[1u8; 513]).0, 1);
    assert!(d.t.dev.store.reads.is_empty() && d.t.dev.store.writes.is_empty());
}

/// `RO` is offered, but a driver may ignore it: the device refuses anyway.
#[test]
fn a_write_to_a_read_only_disk_is_refused_whatever_the_driver_negotiated() {
    let mut s = MemStore::new(8);
    s.ro = true;
    let mut d = disk_of(s);
    let before = d.t.dev.store.data.clone();
    let (st, _) = d.write(1, &[0x77; 512]);
    assert_eq!(st, 1);
    assert!(d.t.dev.store.writes.is_empty(), "{:?}", d.t.dev.store.writes);
    assert_eq!(d.t.dev.store.data, before);
    // Reads still work.
    assert_eq!(d.read(1, 512).0, 0);
}

/// The store is refused by the authority behind it (a `Cap<Dir>` without
/// write, a medium that failed): the guest sees an I/O error, its buffer is
/// left alone, and the device serves the next request.
#[test]
fn a_store_that_is_refused_is_an_io_error_not_a_success() {
    for e in [IoError::Denied, IoError::Device] {
        let mut d = disk(8);
        d.t.dev.store.fail = Some(e);
        let (s, data, used) = d.read(0, 512);
        assert_eq!((s, used), (1, 1), "{e:?}");
        assert_eq!(data, vec![0xAA; 512], "the buffer is untouched");
        assert_eq!(d.write(0, &[1u8; 512]).0, 1);
        assert_eq!(d.request(FLUSH, 0, &[], true).0, 1);
        assert_eq!(d.t.dev.errors, 3);
        d.t.dev.store.fail = None;
        assert_eq!(d.read(0, 512).0, 0, "the next request is served");
    }
}

#[test]
fn a_header_the_guest_cut_short_is_an_error() {
    let mut d = disk(4);
    let (hdr, st) = (d.ram.put(&[0u8; 8]), d.ram.put(&[0xEE]));
    d.q.post(&mut d.ram, &[(hdr, 8, false), (st, 1, true)]);
    kick(&mut d.t, &mut d.ram, 0);
    assert_eq!(d.ram.get(st, 1)[0], 1);
    assert!(d.t.dev.store.reads.is_empty());
}

#[test]
fn a_request_with_nowhere_to_put_a_status_is_dropped_and_the_next_is_served() {
    let mut d = disk(4);
    let hdr = d.ram.put(&header(IN, 0));
    d.q.post(&mut d.ram, &[(hdr, 16, false)]);
    d.q.post(&mut d.ram, &[(hdr, 16, false)]);
    kick(&mut d.t, &mut d.ram, 0);
    assert_eq!(d.q.used_idx(&d.ram), 2);
    assert_eq!(d.q.used(&d.ram, 0).1, 0);
    assert!(d.t.dev.store.reads.is_empty());
    assert_eq!(d.read(0, 512).0, 0);
}

#[test]
fn several_requests_in_one_kick_are_all_completed() {
    let mut d = disk(16);
    let mut sts = vec![];
    for sector in 0..5u64 {
        let hdr = d.ram.put(&header(IN, sector));
        let (buf, st) = (d.ram.alloc(512), d.ram.put(&[0xEE]));
        d.q.post(&mut d.ram, &[(hdr, 16, false), (buf, 512, true), (st, 1, true)]);
        sts.push((buf, st, sector));
    }
    kick(&mut d.t, &mut d.ram, 0);
    assert_eq!(d.q.used_idx(&d.ram), 5);
    for (buf, st, sector) in sts {
        assert_eq!(d.ram.get(st, 1)[0], 0);
        assert_eq!(d.ram.get(buf, 512), d.t.dev.store.data[sector as usize * SECTOR..][..512]);
    }
}

#[test]
fn capacity_in_the_config_space_is_the_stores() {
    let mut d = disk(40);
    assert_eq!(d.t.access(r::CONFIG, false, 8, 0, &mut d.ram), 40);
}

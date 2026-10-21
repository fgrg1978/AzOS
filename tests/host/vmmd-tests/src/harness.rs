// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! A guest to test against: RAM that checks, a virtio driver in miniature,
//! and recording doubles for the backends' hosts.

use std::collections::VecDeque;

use crate::blk::{BlockStore, IoError, SECTOR};
use crate::console::Term;
use crate::guest::{GuestMem, OutOfRam};
use crate::mmio::{status, Device, Transport, F_VERSION_1};
use crate::net::Link;

pub const RAM_BASE: u64 = 0x8000_0000;
pub const RAM_BYTES: usize = 1 << 20;

/// Guest RAM that counts every access outside it (the models are to make none).
pub struct Ram {
    pub bytes: Vec<u8>,
    pub violations: std::cell::Cell<u32>,
    next: u64,
}

impl Ram {
    pub fn new() -> Ram {
        // The first 0x10000 bytes are the queues'; buffers are allocated above.
        Ram { bytes: vec![0; RAM_BYTES], violations: Default::default(), next: RAM_BASE + 0x1_0000 }
    }

    /// A fresh buffer of `len` bytes.
    pub fn alloc(&mut self, len: usize) -> u64 {
        let at = self.next;
        self.next += (len as u64 + 15) & !15;
        assert!(self.next <= RAM_BASE + RAM_BYTES as u64, "test RAM exhausted");
        at
    }

    /// A buffer holding `data`.
    pub fn put(&mut self, data: &[u8]) -> u64 {
        let at = self.alloc(data.len());
        self.write(at, data).unwrap();
        at
    }

    pub fn get(&self, gpa: u64, len: usize) -> Vec<u8> {
        let mut v = vec![0; len];
        self.read(gpa, &mut v).unwrap();
        v
    }

    fn span(&self, gpa: u64, len: usize) -> Option<usize> {
        let end = gpa.checked_add(len as u64)?;
        (gpa >= RAM_BASE && end <= RAM_BASE + RAM_BYTES as u64).then(|| (gpa - RAM_BASE) as usize)
    }
}

impl GuestMem for Ram {
    fn range(&self) -> (u64, u64) {
        (RAM_BASE, RAM_BYTES as u64)
    }

    fn read(&self, gpa: u64, out: &mut [u8]) -> Result<(), OutOfRam> {
        match self.span(gpa, out.len()) {
            Some(o) => Ok(out.copy_from_slice(&self.bytes[o..o + out.len()])),
            None => {
                self.violations.set(self.violations.get() + 1);
                Err(OutOfRam)
            }
        }
    }

    fn write(&mut self, gpa: u64, data: &[u8]) -> Result<(), OutOfRam> {
        match self.span(gpa, data.len()) {
            Some(o) => Ok(self.bytes[o..o + data.len()].copy_from_slice(data)),
            None => {
                self.violations.set(self.violations.get() + 1);
                Err(OutOfRam)
            }
        }
    }
}

/// The guest side of one virtqueue.
pub struct Queue {
    pub num: u16,
    pub desc: u64,
    pub avail: u64,
    pub used: u64,
    next_desc: u16,
    avail_idx: u16,
}

pub const F_NEXT: u16 = 1;
pub const F_WRITE: u16 = 2;

impl Queue {
    /// A queue of `num` entries in the page-aligned slot `slot` of the first
    /// 64 KiB of RAM.
    pub fn new(slot: u64, num: u16) -> Queue {
        let base = RAM_BASE + slot * 0x2000;
        Queue { num, desc: base, avail: base + 0x800, used: base + 0x1000, next_desc: 0, avail_idx: 0 }
    }

    /// Write descriptor `i` raw (the hostile cases build chains by hand).
    pub fn set_desc(&self, ram: &mut Ram, i: u16, addr: u64, len: u32, flags: u16, next: u16) {
        let mut d = [0u8; 16];
        d[0..8].copy_from_slice(&addr.to_le_bytes());
        d[8..12].copy_from_slice(&len.to_le_bytes());
        d[12..14].copy_from_slice(&flags.to_le_bytes());
        d[14..16].copy_from_slice(&next.to_le_bytes());
        ram.write(self.desc + 16 * i as u64, &d).unwrap();
    }

    /// Publish `head` on the avail ring.
    pub fn publish(&mut self, ram: &mut Ram, head: u16) {
        let slot = (self.avail_idx % self.num) as u64;
        ram.write(self.avail + 4 + 2 * slot, &head.to_le_bytes()).unwrap();
        self.avail_idx = self.avail_idx.wrapping_add(1);
        ram.write(self.avail + 2, &self.avail_idx.to_le_bytes()).unwrap();
    }

    /// Make a chain of `(addr, len, device writes)` buffers available; the head.
    pub fn post(&mut self, ram: &mut Ram, bufs: &[(u64, u32, bool)]) -> u16 {
        let head = self.next_desc;
        for (k, &(addr, len, w)) in bufs.iter().enumerate() {
            let i = self.next_desc;
            self.next_desc = (self.next_desc + 1) % self.num;
            let last = k + 1 == bufs.len();
            let flags = (if w { F_WRITE } else { 0 }) | if last { 0 } else { F_NEXT };
            self.set_desc(ram, i, addr, len, flags, if last { 0 } else { self.next_desc });
        }
        self.publish(ram, head);
        head
    }

    /// Pretend `n` chains were already posted (a queue another driver used first).
    pub fn skip(&mut self, n: u16) {
        self.avail_idx = self.avail_idx.wrapping_add(n);
        self.next_desc = (self.next_desc + n) % self.num;
    }

    pub fn used_idx(&self, ram: &Ram) -> u16 {
        crate::guest::read_u16(ram, self.used + 2).unwrap()
    }

    /// The `n`-th used entry: `(head, written)`.
    pub fn used(&self, ram: &Ram, n: u16) -> (u32, u32) {
        let at = self.used + 4 + 8 * (n % self.num) as u64;
        (crate::guest::read_u32(ram, at).unwrap(), crate::guest::read_u32(ram, at + 4).unwrap())
    }
}

pub mod r {
    pub const MAGIC: u64 = 0x000;
    pub const VERSION: u64 = 0x004;
    pub const DEVICE_ID: u64 = 0x008;
    pub const VENDOR_ID: u64 = 0x00c;
    pub const DEVICE_FEATURES: u64 = 0x010;
    pub const DEVICE_FEATURES_SEL: u64 = 0x014;
    pub const DRIVER_FEATURES: u64 = 0x020;
    pub const DRIVER_FEATURES_SEL: u64 = 0x024;
    pub const QUEUE_SEL: u64 = 0x030;
    pub const QUEUE_NUM_MAX: u64 = 0x034;
    pub const QUEUE_NUM: u64 = 0x038;
    pub const QUEUE_READY: u64 = 0x044;
    pub const QUEUE_NOTIFY: u64 = 0x050;
    pub const INTERRUPT_STATUS: u64 = 0x060;
    pub const INTERRUPT_ACK: u64 = 0x064;
    pub const STATUS: u64 = 0x070;
    pub const QUEUE_DESC_LOW: u64 = 0x080;
    pub const QUEUE_DESC_HIGH: u64 = 0x084;
    pub const QUEUE_DRIVER_LOW: u64 = 0x090;
    pub const QUEUE_DRIVER_HIGH: u64 = 0x094;
    pub const QUEUE_DEVICE_LOW: u64 = 0x0a0;
    pub const QUEUE_DEVICE_HIGH: u64 = 0x0a4;
    pub const CONFIG: u64 = 0x100;
}

pub const ACK: u32 = 1;
pub const DRIVER: u32 = 2;

/// A 32-bit register write.
pub fn w<D: Device>(t: &mut Transport<D>, ram: &mut Ram, off: u64, v: u32) {
    t.access(off, true, 4, v as u64, ram);
}

/// A 32-bit register read.
pub fn rd<D: Device>(t: &mut Transport<D>, ram: &mut Ram, off: u64) -> u32 {
    t.access(off, false, 4, 0, ram) as u32
}

/// Program queue `sel` with the addresses of `q` (not yet ready).
pub fn set_queue<D: Device>(t: &mut Transport<D>, ram: &mut Ram, sel: u32, q: &Queue) {
    w(t, ram, r::QUEUE_SEL, sel);
    w(t, ram, r::QUEUE_NUM, q.num as u32);
    w(t, ram, r::QUEUE_DESC_LOW, q.desc as u32);
    w(t, ram, r::QUEUE_DESC_HIGH, (q.desc >> 32) as u32);
    w(t, ram, r::QUEUE_DRIVER_LOW, q.avail as u32);
    w(t, ram, r::QUEUE_DRIVER_HIGH, (q.avail >> 32) as u32);
    w(t, ram, r::QUEUE_DEVICE_LOW, q.used as u32);
    w(t, ram, r::QUEUE_DEVICE_HIGH, (q.used >> 32) as u32);
}

/// Bring a device up the way a driver does: features (`extra` beside
/// `VERSION_1`), the queues, `DRIVER_OK`. Returns the status read back.
pub fn bring_up<D: Device>(t: &mut Transport<D>, ram: &mut Ram, extra: u64, queues: &[&Queue]) -> u32 {
    w(t, ram, r::STATUS, ACK);
    w(t, ram, r::STATUS, ACK | DRIVER);
    let f = F_VERSION_1 | extra;
    w(t, ram, r::DRIVER_FEATURES_SEL, 0);
    w(t, ram, r::DRIVER_FEATURES, f as u32);
    w(t, ram, r::DRIVER_FEATURES_SEL, 1);
    w(t, ram, r::DRIVER_FEATURES, (f >> 32) as u32);
    w(t, ram, r::STATUS, ACK | DRIVER | status::FEATURES_OK);
    for (i, q) in queues.iter().enumerate() {
        set_queue(t, ram, i as u32, q);
        w(t, ram, r::QUEUE_SEL, i as u32);
        w(t, ram, r::QUEUE_READY, 1);
    }
    w(t, ram, r::STATUS, ACK | DRIVER | status::FEATURES_OK | status::DRIVER_OK);
    rd(t, ram, r::STATUS)
}

pub fn kick<D: Device>(t: &mut Transport<D>, ram: &mut Ram, q: u32) {
    w(t, ram, r::QUEUE_NOTIFY, q);
}

/// A disk in memory that records what reached it.
pub struct MemStore {
    pub data: Vec<u8>,
    pub ro: bool,
    pub reads: Vec<(u64, usize)>,
    pub writes: Vec<(u64, usize)>,
    pub flushes: u32,
    pub fail: Option<IoError>,
}

impl MemStore {
    pub fn new(sectors: usize) -> MemStore {
        let mut data = vec![0u8; sectors * SECTOR];
        for (i, b) in data.iter_mut().enumerate() {
            *b = (i / SECTOR) as u8 ^ (i % 251) as u8;
        }
        MemStore { data, ro: false, reads: vec![], writes: vec![], flushes: 0, fail: None }
    }
}

impl BlockStore for MemStore {
    fn capacity(&self) -> u64 {
        (self.data.len() / SECTOR) as u64
    }

    fn read_only(&self) -> bool {
        self.ro
    }

    fn read(&mut self, sector: u64, buf: &mut [u8]) -> Result<(), IoError> {
        self.reads.push((sector, buf.len()));
        if let Some(e) = self.fail {
            return Err(e);
        }
        let o = sector as usize * SECTOR;
        buf.copy_from_slice(self.data.get(o..o + buf.len()).ok_or(IoError::Device)?);
        Ok(())
    }

    fn write(&mut self, sector: u64, data: &[u8]) -> Result<(), IoError> {
        self.writes.push((sector, data.len()));
        if let Some(e) = self.fail {
            return Err(e);
        }
        let o = sector as usize * SECTOR;
        self.data.get_mut(o..o + data.len()).ok_or(IoError::Device)?.copy_from_slice(data);
        Ok(())
    }

    fn flush(&mut self) -> Result<(), IoError> {
        self.flushes += 1;
        self.fail.map_or(Ok(()), Err)
    }
}

/// A link that records what the guest sent and hands back what it is given.
#[derive(Default)]
pub struct TestLink {
    pub sent: Vec<Vec<u8>>,
    pub inbox: VecDeque<Vec<u8>>,
    pub refuse: bool,
}

impl Link for TestLink {
    fn send(&mut self, frame: &[u8]) -> bool {
        if self.refuse {
            return false;
        }
        self.sent.push(frame.to_vec());
        true
    }

    fn recv(&mut self, buf: &mut [u8]) -> Option<usize> {
        let f = self.inbox.pop_front()?;
        buf[..f.len()].copy_from_slice(&f);
        Some(f.len())
    }
}

/// A console that records the guest's output and serves scripted input.
#[derive(Default)]
pub struct TestTerm {
    pub out: Vec<u8>,
    pub input: VecDeque<u8>,
}

impl Term for TestTerm {
    fn write(&mut self, bytes: &[u8]) {
        self.out.extend_from_slice(bytes);
    }

    fn read(&mut self, buf: &mut [u8]) -> usize {
        let n = buf.len().min(self.input.len());
        for b in buf[..n].iter_mut() {
            *b = self.input.pop_front().unwrap();
        }
        n
    }
}

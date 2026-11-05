// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The host-test side of the kit: a register file, a port space and a clock a
//! driver is run against, each logging what the driver did.

use crate::{Mmio, PortIo, Ticks, Width};
use alloc::vec::Vec;
use core::cell::{Cell, RefCell};

/// One access a driver made.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Access {
    Read { off: usize, width: u8, val: u64 },
    Write { off: usize, width: u8, val: u64 },
}

/// `N` bytes of registers that hold what is written to them, little-endian
/// like every ISA of the tree. An access wider than a byte is that many bytes
/// at consecutive offsets, so a driver that reads a register at the wrong
/// width, offset or byte order sees it. `poke*` and `peek*` are the test's
/// side: they do not log.
pub struct FakeMmio<const N: usize> {
    base: usize,
    bytes: [Cell<u8>; N],
    log: RefCell<Vec<Access>>,
}

impl<const N: usize> FakeMmio<N> {
    pub fn new() -> Self {
        Self::at(0)
    }

    /// The block as mapped at `base`.
    pub fn at(base: usize) -> Self {
        FakeMmio { base, bytes: [const { Cell::new(0) }; N], log: RefCell::new(Vec::new()) }
    }

    fn get(&self, off: usize, width: usize) -> u64 {
        (0..width).fold(0u64, |v, i| v | (self.bytes[off + i].get() as u64) << (8 * i))
    }

    fn put(&self, off: usize, width: usize, v: u64) {
        for i in 0..width {
            self.bytes[off + i].set((v >> (8 * i)) as u8);
        }
    }

    pub fn poke8(&self, off: usize, v: u8) {
        self.put(off, 1, v as u64)
    }
    pub fn poke32(&self, off: usize, v: u32) {
        self.put(off, 4, v as u64)
    }
    pub fn peek8(&self, off: usize) -> u8 {
        self.get(off, 1) as u8
    }
    pub fn peek32(&self, off: usize) -> u32 {
        self.get(off, 4) as u32
    }

    /// Everything the driver did, in order, and forget it.
    pub fn take_log(&self) -> Vec<Access> {
        core::mem::take(&mut *self.log.borrow_mut())
    }

    /// The offsets and values the driver wrote, in order, and forget the log.
    pub fn take_writes(&self) -> Vec<(usize, u64)> {
        self.take_log()
            .into_iter()
            .filter_map(|a| match a {
                Access::Write { off, val, .. } => Some((off, val)),
                Access::Read { .. } => None,
            })
            .collect()
    }
}

impl<const N: usize> Default for FakeMmio<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> Mmio for FakeMmio<N> {
    fn load(&self, off: usize, w: Width) -> u64 {
        let n = w.bytes();
        assert!(off % n == 0 && off + n <= N, "{n}-byte read at {off:#x} outside the {N:#x}-byte block");
        let val = self.get(off, n);
        self.log.borrow_mut().push(Access::Read { off, width: n as u8, val });
        val
    }

    fn base(&self) -> usize {
        self.base
    }

    fn store(&self, off: usize, w: Width, v: u64) {
        let n = w.bytes();
        assert!(off % n == 0 && off + n <= N, "{n}-byte write at {off:#x} outside the {N:#x}-byte block");
        let val = if n == 8 { v } else { v & ((1u64 << (8 * n)) - 1) };
        self.log.borrow_mut().push(Access::Write { off, width: n as u8, val });
        self.put(off, n, val);
    }
}

/// A port space where each port holds the last byte written to it, unless the
/// test queued bytes to read: a port with a queue answers from it (the last
/// byte then repeats), which scripts a status port that changes.
pub struct FakePorts {
    held: RefCell<Vec<(u16, u8)>>,
    queued: RefCell<Vec<(u16, Vec<u8>)>>,
    log: RefCell<Vec<PortAccess>>,
}

/// One port access a driver made.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PortAccess {
    In { port: u16, val: u8 },
    Out { port: u16, val: u8 },
}

impl FakePorts {
    pub fn new() -> Self {
        FakePorts { held: RefCell::new(Vec::new()), queued: RefCell::new(Vec::new()), log: RefCell::new(Vec::new()) }
    }

    /// The next reads of `port` give `bytes` in order, then the last one for good.
    pub fn queue(&self, port: u16, bytes: &[u8]) {
        self.queued.borrow_mut().push((port, bytes.to_vec()));
    }

    pub fn take_log(&self) -> Vec<PortAccess> {
        core::mem::take(&mut *self.log.borrow_mut())
    }
}

impl Default for FakePorts {
    fn default() -> Self {
        Self::new()
    }
}

impl PortIo for FakePorts {
    fn inb(&self, port: u16) -> u8 {
        let mut queued = self.queued.borrow_mut();
        let val = match queued.iter_mut().find(|(p, q)| *p == port && !q.is_empty()) {
            Some((_, q)) if q.len() > 1 => q.remove(0),
            Some((_, q)) => q[0],
            None => self.held.borrow().iter().find(|(p, _)| *p == port).map_or(0xff, |&(_, v)| v),
        };
        self.log.borrow_mut().push(PortAccess::In { port, val });
        val
    }

    fn outb(&self, port: u16, val: u8) {
        self.log.borrow_mut().push(PortAccess::Out { port, val });
        let mut held = self.held.borrow_mut();
        match held.iter_mut().find(|(p, _)| *p == port) {
            Some(slot) => slot.1 = val,
            None => held.push((port, val)),
        }
    }
}

/// A clock that has moved `step` ticks further each time it is read, so a
/// bounded wait on the host ends after a known number of polls.
pub struct FakeTicks {
    now: Cell<u64>,
    step: u64,
    freq: u64,
}

impl FakeTicks {
    pub fn new(freq_hz: u64, step: u64) -> Self {
        FakeTicks { now: Cell::new(0), step, freq: freq_hz }
    }

    pub fn advance(&self, ticks: u64) {
        self.now.set(self.now.get() + ticks);
    }
}

impl Ticks for FakeTicks {
    fn now(&self) -> u64 {
        let v = self.now.get();
        self.now.set(v + self.step);
        v
    }
    fn freq_hz(&self) -> u64 {
        self.freq
    }
}

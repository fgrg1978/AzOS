// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The NIC queue the daemon's row may grant it (`nicq.eth<N>.0`, Kconfig
//! `PTPD_NIC_QUEUE`): the two rings it makes, the attach that takes the queue
//! from the kernel's stack (`azos_abi::nic_queue`), and the send and receive
//! the Ethernet transport runs on.
//!
//! Every frame comes with the queue's stamp, read where the frame crossed the
//! driver (or the NIC's own, where the driver reads it): the daemon's poll
//! period no longer lands in the measurement, as it does over UDP. A send
//! asks for its departure stamp; the kernel's kick sends the frame and puts
//! the stamp on the receive ring before it returns, behind any frame that
//! arrived meanwhile, which waits in [`Stash`] for the next drain.

use azos_abi::cap::ty;
use azos_abi::nic_queue::{self as nq, Desc};
use azos_abi::syscall_nr::{SHM_CREATE_KIND_SHIFT, SHM_KIND_CONTIG};
use azos_libsys as sys;
use sys::{BytesProducer, Publish, RingSleep, RingStep, SpscBytes};

/// The longest frame the daemon reads or sends: a PTP message and its
/// Ethernet header (and a VLAN tag).
pub const FRAME_MAX: usize = crate::RX_MAX + crate::l2::HDR + 4;
/// Frames held while a send waits for its stamp.
const STASH: usize = 4;

/// Frames popped while a send looked for its stamp, oldest first.
struct Stash {
    frames: [[u8; FRAME_MAX]; STASH],
    lens: [usize; STASH],
    stamps: [u64; STASH],
    head: usize,
    n: usize,
}

impl Stash {
    const fn new() -> Self {
        Stash { frames: [[0; FRAME_MAX]; STASH], lens: [0; STASH], stamps: [0; STASH], head: 0, n: 0 }
    }

    /// Keep a frame; dropped when full (the receive ring's own policy).
    fn put(&mut self, f: &[u8], stamp: u64) {
        if self.n == STASH {
            return;
        }
        let i = (self.head + self.n) % STASH;
        let k = f.len().min(FRAME_MAX);
        self.frames[i][..k].copy_from_slice(&f[..k]);
        self.lens[i] = k;
        self.stamps[i] = stamp;
        self.n += 1;
    }

    fn take(&mut self, out: &mut [u8]) -> Option<(usize, u64)> {
        if self.n == 0 {
            return None;
        }
        let i = self.head;
        let k = self.lens[i].min(out.len());
        out[..k].copy_from_slice(&self.frames[i][..k]);
        self.head = (self.head + 1) % STASH;
        self.n -= 1;
        Some((k, self.stamps[i]))
    }
}

/// One popped item of the receive ring.
enum Item {
    Frame(usize, u64),
    Done(Desc, u64),
}

/// The attached queue.
pub struct Queue {
    cap: u32,
    rx: SpscBytes,
    tx: BytesProducer,
    /// The interface's MAC: the source of every frame sent.
    pub mac: [u8; 6],
    stash: Stash,
    slot: [u8; nq::SLOT_PAYLOAD],
}

/// Why the row's queue is not in use.
pub enum Unused {
    /// The row grants none.
    NotGranted,
    /// A ring region could not be made or mapped.
    NoMemory,
    /// The kernel refused the attach (`-Errno`).
    Refused(isize),
}

/// A ring region of `slots` frames, read-write and contiguous, mapped here:
/// its handle, its address and its size.
fn region(slots: u32) -> Option<(u32, usize, usize)> {
    let pages = nq::ring_bytes(slots).div_ceil(sys::PAGE_SIZE);
    let cap = sys::shm_create_typed(pages as u64, sys::SHM_RW | SHM_KIND_CONTIG << SHM_CREATE_KIND_SHIFT);
    if cap <= 0 {
        return None;
    }
    let va = sys::shm_map_typed(cap as u32);
    if va <= 0 {
        let _ = sys::shm_release_typed(cap as u32);
        return None;
    }
    Some((cap as u32, va as usize, pages * sys::PAGE_SIZE))
}

impl Queue {
    /// The first interface whose queue 0 the row grants, attached on two rings
    /// of `slots` frames.
    pub fn open(slots: u32) -> Result<Queue, Unused> {
        let cap = (1..=azos_limits::NET_MAX_INTERFACES as u8)
            .map(|ifx| sys::cap_lookup(ty::NIC_QUEUE.raw(), nq::resource(ifx, 0)))
            .find(|h| *h >= 0)
            .ok_or(Unused::NotGranted)? as u32;
        let (Some(rx), Some(tx)) = (region(slots), region(slots)) else { return Err(Unused::NoMemory) };
        let att = sys::nicq_attach(cap, rx.0, tx.0).map_err(Unused::Refused)?;
        let views = SpscBytes::from_header(rx.1, rx.2).zip(SpscBytes::from_header(tx.1, tx.2));
        let Some((rxv, txv)) = views else { return Err(Unused::NoMemory) };
        Ok(Queue { cap, rx: rxv, tx: BytesProducer::new(txv), mac: att.mac, stash: Stash::new(), slot: [0; nq::SLOT_PAYLOAD] })
    }

    /// Pop one item of the receive ring into `out` (a frame) or its
    /// descriptor (a completion); `None` when it is empty.
    fn pop(&mut self, out: &mut [u8]) -> Option<Item> {
        let (step, info) = self.rx.try_pop(&mut self.slot);
        if step == RingStep::Blocked {
            return None;
        }
        let n = (info.len as usize).min(nq::SLOT_PAYLOAD);
        let d = Desc::decode(&self.slot[..n]).unwrap_or_default();
        if d.kind != nq::DESC_RX {
            return Some(Item::Done(d, info.acq_ns));
        }
        let f = &self.slot[nq::DESC_BYTES.min(n)..n];
        let k = f.len().min(out.len());
        out[..k].copy_from_slice(&f[..k]);
        Some(Item::Frame(k, info.acq_ns))
    }

    /// Send `msg` in a frame to the PTP group; its departure stamp (ns of the
    /// monotonic clock), or `None` when it did not leave.
    pub fn send(&mut self, msg: &[u8]) -> Option<u64> {
        let mut item = [0u8; nq::DESC_BYTES + FRAME_MAX];
        item[..nq::DESC_BYTES].copy_from_slice(&Desc { kind: nq::DESC_TX, flags: nq::TX_STAMP, tx_seq: 0 }.encode());
        let n = crate::l2::frame(self.mac, msg, &mut item[nq::DESC_BYTES..])?;
        let seq = self.tx.seq();
        if self.tx.push(0, &item[..nq::DESC_BYTES + n]) == Publish::Dropped {
            return None;
        }
        if sys::nicq_kick(self.cap) < 0 {
            return None;
        }
        // The kick answered our slot on the receive ring before it returned;
        // what arrived meanwhile is ahead of it and is kept for the drain.
        let mut f = [0u8; FRAME_MAX];
        loop {
            match self.pop(&mut f)? {
                Item::Frame(k, stamp) => self.stash.put(&f[..k], stamp),
                Item::Done(d, stamp) if d.kind == nq::DESC_TX_DONE && d.tx_seq == seq => {
                    let stamped = d.flags & (nq::STAMP_HW | nq::STAMP_SW) != 0 && d.flags & nq::TX_REFUSED == 0;
                    return stamped.then_some(stamp);
                }
                Item::Done(..) => {}
            }
        }
    }

    /// The next frame that arrived, into `out`: its length and its arrival
    /// stamp (ns of the monotonic clock).
    pub fn recv(&mut self, out: &mut [u8]) -> Option<(usize, u64)> {
        if let Some(f) = self.stash.take(out) {
            return Some(f);
        }
        loop {
            match self.pop(out)? {
                Item::Frame(k, stamp) => return Some((k, stamp)),
                // A completion nobody waits for any more.
                Item::Done(..) => {}
            }
        }
    }

    /// Sleep until a frame arrives or `ms` pass.
    pub fn wait(&mut self, ms: u64) {
        if self.stash.n != 0 {
            return;
        }
        if let RingSleep::Wait { addr, expected } = self.rx.consumer_sleep() {
            let _ = sys::futex_wait_addr(addr, expected, ms * 1_000_000);
        }
        self.rx.consumer_woke();
    }
}

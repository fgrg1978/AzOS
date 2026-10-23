// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The `DEVICE_NICQ_*` ops (`azos_abi::invoke`): a NIC queue taken from the
//! kernel's stack and run from ring 3 on a pair of rings the program made
//! (`azos_abi::nic_queue`, the netmap and AF_XDP shape).
//!
//! # The rings
//!
//! Each ring is a region the program made (zero-filled, read-write,
//! physically contiguous: `SHM_KIND_CONTIG`), resolved in place like every
//! queue a client hands the kernel (`crate::devices::ring_region`): the kernel
//! keeps the packed reference and the geometry it chose from the region's
//! size, never an address, and asks the region table again for every ring
//! step (`memobj_with_span_ref`), so a region freed after the attach is a
//! refused step, which ends the attachment, and never a write into a frame
//! that belongs to someone else. The layout is `azos_rings::region::SpscBytes`
//! with [`SLOT_BYTES`] slots, written by the attach into each region's header
//! so the program builds its views from the mapping.
//!
//! * **Receive** (kernel producer): the receive pass hands every frame of the
//!   taken queue to [`rx_sink`] with the stamp read at the driver boundary
//!   (`azos_net::nic_queue::pass`); the frame is pushed behind a `DESC_RX`
//!   descriptor. A full ring drops the newest frame and counts it (the
//!   producer never waits for ring 3). The reader is rung once per pass, at
//!   [`rx_end`], when it said it may be asleep.
//! * **Transmit** (program producer): [`DEVICE_NICQ_KICK`] pops every slot,
//!   checks it and sends it; a slot that asked for it gets a `DESC_TX_DONE` on
//!   the receive ring with the departure stamp.
//!
//! The region is the program's: every index and word in it is untrusted. The
//! receive producer keeps its own head and reads only the tail, as a number;
//! the transmit pop masks both indices into the ring and clamps the length
//! to a slot (`SpscBytes::try_pop`), and the frame is checked whole before it
//! is sent.
//!
//! # Locks
//!
//! The attachment table's lock is taken before the region table's (a push, a
//! pop), never the other way round, and is never held while a NIC driver
//! works: a kick copies a frame out under the region lock, sends it with no
//! lock of this module held, and takes the table again for the completion,
//! which it publishes only if the attachment is still the one it started from
//! (`gen`). Wakes run after both locks are released.
//!
//! # Ownership
//!
//! An attachment belongs to the task that made it: only it kicks and detaches,
//! and its exit ends it ([`release_all`], from the kernel's task-exit hook).

use azos_abi::cap::{ty, CapHandle, CapPerms};
use azos_abi::error::Errno;
use azos_abi::invoke::{DEVICE_NICQ_ATTACH, DEVICE_NICQ_DETACH, DEVICE_NICQ_KICK};
use azos_abi::nic_queue::{self as nq, Desc};
use azos_ipc::cap::{targets, Cap, CapError};
use azos_net::nic_queue::{self as taken, Refusal};
use azos_net::{IfIndex, MAX_IFS};
use azos_rings::region::{BytesProducer, Publish, RingStep, SpscBytes, RING_HEAD, RING_SLOTS, SLOT_HDR_BYTES};
use azos_sync::SpinLock;

use crate::devices::{ring_region, RegionRefusal};
use crate::invoke::{errno_cap, Call};

/// Bytes of one slot of either ring (`nic_queue::SLOT_BYTES`): the slot
/// header, the descriptor and the longest frame, a multiple of 8.
pub const SLOT_BYTES: u32 = nq::SLOT_BYTES;
const _: () = assert!(
    SLOT_HDR_BYTES + nq::SLOT_PAYLOAD <= SLOT_BYTES as usize && SLOT_BYTES % 8 == 0 && nq::RING_HEADER_BYTES == RING_SLOTS,
    "the slot geometry the ABI states is not the ring code's"
);

/// The kernel's end of one ring: the region and the slot count its size
/// implies. Holds no address (module doc).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Ring {
    region: u32,
    cap: u32,
}

impl Ring {
    /// The ring a region of `bytes` holds: the most slots a power of two fits,
    /// `None` below two.
    fn of(region: u32, bytes: usize) -> Option<Ring> {
        let room = bytes.checked_sub(SpscBytes::bytes(0, SLOT_BYTES))? / SLOT_BYTES as usize;
        if room < 2 {
            return None;
        }
        let cap = 1u32 << (usize::BITS - 1 - room.leading_zeros()).min(30);
        Some(Ring { region, cap })
    }

    fn bytes(&self) -> usize {
        SpscBytes::bytes(self.cap, SLOT_BYTES)
    }

    fn view(&self, base: usize) -> SpscBytes {
        SpscBytes { base, cap: self.cap, slot_bytes: SLOT_BYTES }
    }
}

/// One taken queue.
struct Attachment {
    /// The task that attached.
    owner: u32,
    /// Which attachment of the interface this is (bumped by every attach).
    gen: u32,
    mac: [u8; 6],
    rx: Ring,
    /// The receive ring's producer: its own head, sequence and counts.
    rx_prod: BytesProducer,
    /// A push asked for the reader's doorbell since the last ring.
    rx_wake: bool,
    tx: Ring,
    /// A kick is draining the transmit ring.
    draining: bool,
}

/// The attachments, by `ifindex - 1`, and the last generation each slot gave.
static ATTACHED: SpinLock<[(Option<Attachment>, u32); MAX_IFS]> = SpinLock::new([const { (None, 0) }; MAX_IFS]);

fn index(ifindex: IfIndex) -> Option<usize> {
    (ifindex as usize).checked_sub(1).filter(|i| *i < MAX_IFS)
}

/// The ops on a `ty::NIC_QUEUE` handle.
pub(crate) fn nicq_op(c: &mut Call) -> i64 {
    let (need, contained_ok) = match c.op {
        DEVICE_NICQ_ATTACH => (CapPerms::RW, false),
        DEVICE_NICQ_KICK => (CapPerms::WRITE, false),
        // Letting go is never an effect outside: a contained program may.
        DEVICE_NICQ_DETACH => (CapPerms::WRITE, true),
        _ => return Errno::EINVAL.to_syscall_ret(),
    };
    let cap: Cap<targets::NicQueue> = Cap::from_raw(CapHandle::from_raw(c.handle));
    let r = azos_ipc::cap_store::read_table(c.tid, |t| {
        if contained_ok { t.get_op_uncontained(cap, need, c.op) } else { t.get_op(cap, need, c.op) }
    });
    let resource = match r.unwrap_or(Err(CapError::Stale)) {
        Ok(res) => res,
        Err(e) => {
            crate::handlers::note_typed_denial_for(c.tid, ty::NIC_QUEUE, e);
            return errno_cap(e);
        }
    };
    if !azos_limits::NET_NIC_QUEUES {
        return Errno::ENOSYS.to_syscall_ret();
    }
    let (ifindex, queue) = (nq::ifindex_of(resource), nq::queue_of(resource));
    match c.op {
        DEVICE_NICQ_ATTACH => match attach(c.tid, ifindex, queue, c.w[0], c.w[1]) {
            Ok(mac) => {
                c.rep[..3].copy_from_slice(&[nq::mac_word(mac), nq::FRAME_MAX as u64, nq::STAMP_SW as u64]);
                c.nrep = 3;
                0
            }
            Err(e) => e,
        },
        DEVICE_NICQ_KICK => kick(c.tid, ifindex),
        _ => detach(c.tid, ifindex),
    }
}

/// The errno of a region refusal.
fn errno_region(e: RegionRefusal) -> i64 {
    match e {
        RegionRefusal::NotARegion => Errno::ECAPKIND.to_syscall_ret(),
        RegionRefusal::Denied => Errno::ECAPPERMS.to_syscall_ret(),
    }
}

/// The errno of a refused take.
fn errno_refusal(e: Refusal) -> i64 {
    match e {
        Refusal::NoNic | Refusal::NoQueue => Errno::ENODEV.to_syscall_ret(),
        Refusal::Taken => Errno::EBUSY.to_syscall_ret(),
        Refusal::Primary | Refusal::LinkPath => Errno::EPERM.to_syscall_ret(),
    }
}

/// [`DEVICE_NICQ_ATTACH`]: the interface's MAC, or the errno.
fn attach(tid: u32, ifindex: IfIndex, queue: u8, rx_raw: u64, tx_raw: u64) -> Result<[u8; 6], i64> {
    let Some(i) = index(ifindex) else { return Err(Errno::ENODEV.to_syscall_ret()) };
    let (Ok(rx_raw), Ok(tx_raw)) = (u32::try_from(rx_raw), u32::try_from(tx_raw)) else {
        return Err(Errno::EINVAL.to_syscall_ret());
    };
    let (rx_region, rx_bytes) = ring_region(tid, rx_raw, CapPerms::WRITE).map_err(errno_region)?;
    let (tx_region, tx_bytes) = ring_region(tid, tx_raw, CapPerms::READ).map_err(errno_region)?;
    if rx_region == tx_region {
        return Err(Errno::EINVAL.to_syscall_ret());
    }
    let (Some(rx), Some(tx)) = (Ring::of(rx_region, rx_bytes), Ring::of(tx_region, tx_bytes)) else {
        return Err(Errno::EINVAL.to_syscall_ret());
    };
    // Lay both rings out (header zeroed, geometry written), each in one step
    // of its region; a region the kernel cannot touch as one piece is refused.
    let rx_prod = azos_ipc::memobj::memobj_with_span_ref(rx.region, rx.bytes(), |base| BytesProducer::new(rx.view(base)));
    let Ok(Some(rx_prod)) = rx_prod else { return Err(Errno::EINVAL.to_syscall_ret()) };
    let tx_ok = azos_ipc::memobj::memobj_with_span_ref(tx.region, tx.bytes(), |base| tx.view(base).init());
    if !matches!(tx_ok, Ok(Some(()))) {
        return Err(Errno::EINVAL.to_syscall_ret());
    }
    // Booked before the take: the receive pass finds the attachment as soon as
    // the queue is taken, and no frame of it is lost to an empty slot.
    {
        let mut t = ATTACHED.lock();
        let (slot, last) = &mut t[i];
        if slot.is_some() {
            return Err(Errno::EBUSY.to_syscall_ret());
        }
        *last = last.wrapping_add(1);
        *slot = Some(Attachment {
            owner: tid, gen: *last, mac: [0; 6], rx, rx_prod, rx_wake: false, tx, draining: false,
        });
    }
    match taken::take(tid, ifindex, queue) {
        Ok(mac) => {
            if let Some(a) = ATTACHED.lock()[i].0.as_mut() {
                a.mac = mac;
            }
            Ok(mac)
        }
        Err(e) => {
            ATTACHED.lock()[i].0 = None;
            Err(errno_refusal(e))
        }
    }
}

/// End the attachment of `ifindex` (when `gen` is given, only if it is still
/// that one): the queue goes back to the stack.
fn end(ifindex: IfIndex, gen: Option<u32>) {
    let Some(i) = index(ifindex) else { return };
    let ended = {
        let mut t = ATTACHED.lock();
        let slot = &mut t[i].0;
        match slot {
            Some(a) if gen.map_or(true, |g| g == a.gen) => slot.take().is_some(),
            _ => false,
        }
    };
    if ended {
        taken::give_back(ifindex);
    }
}

/// Push one item on the receive ring of attachment `a`: `desc`, then `frame`
/// (cut to a slot). `Err` when the region can no longer be touched.
fn push_rx(a: &mut Attachment, desc: Desc, frame: &[u8], stamp_ns: u64) -> Result<(), ()> {
    let mut item = [0u8; nq::SLOT_PAYLOAD];
    let n = frame.len().min(nq::FRAME_MAX);
    item[..nq::DESC_BYTES].copy_from_slice(&desc.encode());
    item[nq::DESC_BYTES..nq::DESC_BYTES + n].copy_from_slice(&frame[..n]);
    let rx = a.rx;
    let prod = &mut a.rx_prod;
    let step = azos_ipc::memobj::memobj_with_span_ref(rx.region, rx.bytes(), |base| {
        prod.rebase(base);
        prod.push(stamp_ns, &item[..nq::DESC_BYTES + n])
    });
    match step {
        Ok(Some(Publish::Wake)) => {
            a.rx_wake = true;
            Ok(())
        }
        Ok(Some(_)) => Ok(()),
        _ => Err(()),
    }
}

/// The receive pass's sink (`azos_net::nic_queue::Sink`): one frame of a
/// taken queue, stamped at the driver boundary.
pub fn rx_sink(ifindex: IfIndex, frame: &[u8], stamp_ns: u64) {
    let Some(i) = index(ifindex) else { return };
    let gone = {
        let mut t = ATTACHED.lock();
        match t[i].0.as_mut() {
            Some(a) => push_rx(a, Desc { kind: nq::DESC_RX, flags: nq::STAMP_SW, tx_seq: 0 }, frame, stamp_ns)
                .is_err()
                .then_some(a.gen),
            None => None,
        }
    };
    if let Some(g) = gone {
        end(ifindex, Some(g));
    }
}

/// The receive pass is done with `ifindex` for now
/// (`azos_net::nic_queue::SinkEnd`): ring the reader if a push asked for it.
pub fn rx_end(ifindex: IfIndex) {
    let Some(i) = index(ifindex) else { return };
    let ring = {
        let mut t = ATTACHED.lock();
        t[i].0.as_mut().and_then(|a| core::mem::take(&mut a.rx_wake).then_some(a.rx.region))
    };
    if let Some(region) = ring {
        crate::vdso_notify::notify_wake_kernel(region, RING_HEAD as u32, 1);
    }
}

/// [`DEVICE_NICQ_KICK`]: drain the transmit ring of `tid`'s attachment on
/// `ifindex` into the NIC.
fn kick(tid: u32, ifindex: IfIndex) -> i64 {
    let Some(i) = index(ifindex) else { return Errno::ENOENT.to_syscall_ret() };
    let (gen, tx, mac) = {
        let mut t = ATTACHED.lock();
        match t[i].0.as_mut() {
            Some(a) if a.owner == tid => {
                if a.draining {
                    return Errno::EBUSY.to_syscall_ret();
                }
                a.draining = true;
                (a.gen, a.tx, a.mac)
            }
            _ => return Errno::ENOENT.to_syscall_ret(),
        }
    };
    let mut sent = 0i64;
    let mut wake_producer = None;
    let mut gone = false;
    let mut buf = [0u8; nq::SLOT_PAYLOAD];
    // At most one ring's worth: a producer that keeps pushing cannot hold the
    // caller here.
    for _ in 0..tx.cap {
        let step = azos_ipc::memobj::memobj_with_span_ref(tx.region, tx.bytes(), |base| {
            let (step, info) = tx.view(base).try_pop(&mut buf);
            let wake = match step {
                RingStep::DoneWake { addr } => Some(addr - base),
                _ => None,
            };
            (step != RingStep::Blocked, wake, info)
        });
        let (popped, wake, info) = match step {
            Ok(Some(s)) => s,
            _ => {
                gone = true;
                break;
            }
        };
        if !popped {
            break;
        }
        if wake.is_some() {
            wake_producer = wake;
        }
        let n = (info.len as usize).min(nq::SLOT_PAYLOAD);
        let desc = Desc::decode(&buf[..n]).unwrap_or_default();
        let frame = &buf[nq::DESC_BYTES.min(n)..n];
        let shaped = desc.kind == nq::DESC_TX
            && (nq::FRAME_MIN..=nq::FRAME_MAX).contains(&frame.len())
            && frame[6..12] == mac;
        let stamp = taken::stamp_now();
        let ok = shaped && azos_net::nic_queue_send(ifindex, frame);
        sent += ok as i64;
        if desc.flags & nq::TX_STAMP != 0 {
            let done = Desc {
                kind: nq::DESC_TX_DONE,
                flags: if ok { nq::STAMP_SW } else { nq::TX_REFUSED },
                tx_seq: info.seq,
            };
            let mut t = ATTACHED.lock();
            if let Some(a) = t[i].0.as_mut().filter(|a| a.gen == gen) {
                gone |= push_rx(a, done, &[], stamp).is_err();
            }
        }
        if gone {
            break;
        }
    }
    let rx_ring = {
        let mut t = ATTACHED.lock();
        t[i].0.as_mut().filter(|a| a.gen == gen).and_then(|a| {
            a.draining = false;
            core::mem::take(&mut a.rx_wake).then_some(a.rx.region)
        })
    };
    if gone {
        end(ifindex, Some(gen));
    }
    if let Some(off) = wake_producer {
        crate::vdso_notify::notify_wake_kernel(tx.region, off as u32, 1);
    }
    if let Some(region) = rx_ring {
        crate::vdso_notify::notify_wake_kernel(region, RING_HEAD as u32, 1);
    }
    sent
}

/// [`DEVICE_NICQ_DETACH`]: give `tid`'s attachment on `ifindex` back.
fn detach(tid: u32, ifindex: IfIndex) -> i64 {
    let Some(i) = index(ifindex) else { return Errno::ENOENT.to_syscall_ret() };
    let gen = match ATTACHED.lock()[i].0.as_ref() {
        Some(a) if a.owner == tid => a.gen,
        _ => return Errno::ENOENT.to_syscall_ret(),
    };
    end(ifindex, Some(gen));
    0
}

/// The task `tid` is gone: every queue it held goes back to the stack.
pub fn release_all(tid: u32) {
    for i in 0..MAX_IFS {
        let gen = ATTACHED.lock()[i].0.as_ref().filter(|a| a.owner == tid).map(|a| a.gen);
        if let Some(g) = gen {
            end((i + 1) as IfIndex, Some(g));
        }
    }
}

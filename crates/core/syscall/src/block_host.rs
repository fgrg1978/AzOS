// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The `Block` interface the kernel hosts (`endpoint = "block.part.<n>"`):
//! raw sector access to ONE partition of the boot medium. It
//! replaces `SYS_DISK_READ`, `SYS_DISK_WRITE`, `SYS_DISK_SIZE` and
//! `SYS_DISK_INFO` and the partition-scoped `Cap<Disk>`.
//!
//! The endpoint is the authority: the badge is the partition (`n + 1`), `READ`
//! reads, `WRITE` writes. The question a client asks over the call is
//! [`sectors`](azos_devif::Block::sectors); the data moves through the
//! io_ring's `OP_BLOCK_READ` / `OP_BLOCK_WRITE` (a sector is 512 bytes, a reply
//! 64), whose op-table entry is [`block_io`]. The caller names sectors
//! RELATIVE to its partition: the kernel adds the
//! partition's start, so a sector outside it cannot even be spelled, and a run
//! past its end, or one that overflows, is **refused and recorded**.

use azos_abi::cap::ty;
use azos_abi::cap::{CapPerms};
use azos_abi::error::Errno;
use azos_devif::block::{PARTS, SECTOR_BYTES};
use azos_devif::{outcome, Out};
use azos_ipc::io_ring::{OpResult, IO_ERR_PERM};
use core::sync::atomic::{AtomicU32, Ordering};

use crate::khost::Caller;

/// Block requests refused because they reached outside the caller's partition.
/// Read by host tests and diagnostics; the durable trace is
/// the `SAFETY_CAP_DENIED` record each refusal also makes.
pub static BLOCK_SCOPE_REFUSALS: AtomicU32 = AtomicU32::new(0);

/// The partition a badge names (`n + 1`); badge 0 is the whole medium, which
/// no capability names.
const fn partition_of(badge: u32) -> Option<u32> {
    if badge >= 1 && badge <= PARTS { Some(badge - 1) } else { None }
}

/// The `Block` interface served for one caller.
pub struct BlockServer(pub Caller);

impl azos_devif::Block for BlockServer {
    fn sectors(&self) -> Out<u64> {
        if let Err(o) = self.0.gate::<u64>(CapPerms::READ) {
            return o;
        }
        let Some(part) = partition_of(self.0.badge) else {
            return Out::err(outcome::BAD_ARGUMENT);
        };
        match azos_drv_block::partition::partition(part) {
            Some((_, len)) => Out::ok(len),
            // A capability can name only a published partition, and the table
            // is published once: a missing one is not an answer to guess.
            None => Out::err(outcome::NOT_READY),
        }
    }
}

/// This call's own bounce buffer: `len` zeroed bytes owned by the call and
/// shared with nobody, or `None` when the heap cannot give them (the call then
/// fails; nothing panics).
///
/// The disk calls used to share one static buffer each, behind a sleeping lock
/// held across the driver call, because a buffer two harts shared was
/// overwritten between the DMA and the copy (A's sectors landed, B overwrote
/// the whole buffer, A copied B's data to its caller; on the write side B's
/// bytes reached A's sector, and the sectors below the partition table are the
/// flight recorder and the boot image: the user-pointer audit). A
/// buffer per call has no such race, needs no lock, and takes no `.bss` while
/// no block call is in flight.
pub(crate) fn bounce(len: usize) -> Option<alloc::vec::Vec<u8>> {
    let mut v = alloc::vec::Vec::new();
    v.try_reserve_exact(len).ok()?;
    v.resize(len, 0);
    Some(v)
}

/// A bounce buffer billed to a Domain's kernel-memory ledger (class `Bounce`)
/// for as long as it lives: `len` bytes of kernel heap held for a call that a
/// ring-3 caller chose the size of, now bounded by its row's `kmem_kib` like the
/// other classes. Dereferences to the bytes; the bill goes back when it drops
/// (a queued request holds it until the request is collected).
#[derive(Default)]
pub(crate) struct BilledBounce {
    buf: alloc::vec::Vec<u8>,
    key: u32,
    /// The bytes charged, which a drop gives back whatever the buffer has become.
    billed: u32,
}

impl BilledBounce {
    /// No buffer, nothing billed: a free pending slot's.
    pub(crate) const EMPTY: BilledBounce = BilledBounce { buf: alloc::vec::Vec::new(), key: 0, billed: 0 };

    /// `len` zeroed bytes charged to the Domain of task `tid`; `None` when the
    /// ledger refuses them (the caller answers `ENOMEM`) or the heap cannot give them.
    /// `atomic`: the caller is a submit that may be real time or hold a lock: the
    /// refusal is recorded in the lock-free ring only, never flushed.
    /// Canary `block-bounce-unbilled-canary`: the bytes are not billed.
    pub(crate) fn new(tid: u32, len: usize, atomic: bool) -> Option<BilledBounce> {
        // A bounce is at most the ring's data window (2048 bytes), far inside a u32.
        let billed = u32::try_from(len).ok()?;
        let key = if cfg!(feature = "block-bounce-unbilled-canary") { 0 } else { crate::block_host::domain_key(tid) };
        let class = azos_ipc::cap_store::KMEM_BOUNCE;
        // Canary `block-bounce-plain-on-rt-canary`: the submit path charges like a call that may sleep.
        let atomic = atomic && !cfg!(feature = "block-bounce-plain-on-rt-canary");
        let ok = if atomic {
            azos_ipc::cap_store::kmem_charge_atomic(key, class, len as u64)
        } else {
            azos_ipc::cap_store::kmem_charge(key, class, len as u64)
        };
        if !ok {
            return None;
        }
        match bounce(len) {
            Some(buf) => Some(BilledBounce { buf, key, billed }),
            None => {
                azos_ipc::cap_store::kmem_discharge(key, class, len as u64);
                None
            }
        }
    }
}

impl core::ops::Deref for BilledBounce {
    type Target = alloc::vec::Vec<u8>;
    fn deref(&self) -> &Self::Target { &self.buf }
}

impl core::ops::DerefMut for BilledBounce {
    fn deref_mut(&mut self) -> &mut Self::Target { &mut self.buf }
}

impl Drop for BilledBounce {
    fn drop(&mut self) {
        if self.key != 0 && self.billed != 0 {
            azos_ipc::cap_store::kmem_discharge(self.key, azos_ipc::cap_store::KMEM_BOUNCE, u64::from(self.billed));
        }
    }
}

/// The Domain task `tid` runs in; `0` (nothing billed) for none.
fn domain_key(tid: u32) -> u32 {
    azos_ipc::cap_store::domain_key_of(tid)
}

/// The scope of one block entry, shared by the inline ([`block_io`]) and the
/// queued ([`crate::ioring_ops`]) paths: partition `badge - 1`, `len` bytes
/// (whole sectors) from the partition-relative `sector`, resolved to the
/// absolute `(lba, sector count)`. A run that does not fit the partition (or
/// overflows) is **refused and recorded**: the counter, the cap-denial record
/// and, for the first few, a console line (a ring-3 loop must not be able to
/// flood the UART; the record has its own limiter and the counter keeps every
/// one). `Err` is the negative errno the entry completes with.
pub(crate) fn scope(badge: u32, write: bool, sector: u64, len: usize) -> Result<(u64, u32), i32> {
    let Some(part) = partition_of(badge) else {
        return Err(Errno::EINVAL.to_syscall_ret() as i32);
    };
    let count = (len / SECTOR_BYTES) as u64;
    if len == 0 || len % SECTOR_BYTES != 0 {
        return Err(Errno::EINVAL.to_syscall_ret() as i32);
    }
    let resolved = if cfg!(feature = "block-scope-canary") {
        // CANARY, never in a real build: the start is added, the end is not checked.
        azos_drv_block::partition::partition(part).map(|(start, _)| start.wrapping_add(sector))
    } else {
        azos_drv_block::partition::resolve(part, sector, count)
    };
    let Some(lba) = resolved else {
        let prior = BLOCK_SCOPE_REFUSALS.fetch_add(1, Ordering::Relaxed);
        crate::handlers::record_cap_denial(ty::ENDPOINT, badge, write);
        if prior < 8 {
            azos_drv_sys::kwarn!(
                "[BLOCK] scope: tid {} partition {} refused {} sector {}+{}",
                azos_sched::current_task_tid(), part,
                if write { "write" } else { "read" }, sector, count);
        }
        return Err(IO_ERR_PERM);
    };
    // `resolve` bounds `count` by the partition, which fits a u32 request.
    Ok((lba, count as u32))
}

/// The io_ring op-table entry of `OP_BLOCK_READ` / `OP_BLOCK_WRITE` for a
/// block entry that cannot be queued (`IORING_ASYNC` off, a board whose disk is
/// not behind the request layer, a full queue, a run longer than one device
/// command): move `len` bytes (whole sectors, bounded to the ring's window by
/// the caller) between partition `badge - 1` and `buf`, starting at the
/// partition-relative `sector`, and wait for the device. The capability, its op
/// class and containment were checked by `dispatch_sqe`; the scope is
/// [`scope`]'s. `Ok(len)`, or the refusal.
///
/// `buf` is a window of the ring's data page, which ring 3 maps RW: it is
/// copied once, through this call's own bounce buffer, and the device never
/// sees it.
pub fn block_io(badge: u32, write: bool, sector: u64, buf: *mut u8, len: usize) -> OpResult {
    let (lba, count) = scope(badge, write, sector, len)?;
    let Some(mut kbuf) = BilledBounce::new(azos_sched::current_task_tid(), len, false) else {
        return Err(Errno::ENOMEM.to_syscall_ret() as i32);
    };
    azos_drv_block::blkdev::rt_io_check();
    if write {
        // SAFETY: `dispatch_sqe` bounded `[buf, buf + len)` inside the ring's
        // data buffer; copied once, as payload.
        unsafe { core::ptr::copy_nonoverlapping(buf as *const u8, kbuf.as_mut_ptr(), len) };
        let r = azos_drv_block::blkdev::write_raw(lba, count, &kbuf);
        // The FAT32 block cache may hold these sectors (a partition holder can
        // write the mounted volume's own partition): tell it, after the device
        // answered and whatever it answered. Takes only the cache's leaf lock.
        azos_drv_block::blkdev::note_external_write(lba, count);
        r.map(|()| len as i32).map_err(|()| Errno::EIO.to_syscall_ret() as i32)
    } else {
        // FAT32's write-back cache writes any queued sector of this range first.
        azos_drv_block::blkdev::note_external_read(lba, count);
        match azos_drv_block::blkdev::read_raw(lba, count, &mut kbuf) {
            Ok(()) => {
                // SAFETY: as above.
                unsafe { core::ptr::copy_nonoverlapping(kbuf.as_ptr(), buf, len) };
                Ok(len as i32)
            }
            Err(()) => Err(Errno::EIO.to_syscall_ret() as i32),
        }
    }
}

// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! K1 (IO-QUEUES-AUDIT): an io_ring `OP_FSYNC` never waits in the submit.
//!
//! A probe task (real-time when no disk is mounted) submits `N_WRITES` `OP_FILE_WRITE` entries, the
//! last one linked (`SQE_F_LINK`) to an `OP_FSYNC`, in ONE submit, and
//! returns: the writes complete `CQE_F_QUEUED`, the fsync does not complete
//! in the submit. Its completion is posted later, `CQE_F_DURABLE`, by the
//! flush path (`io_ring_flush_posted`), never by the submitter.
//!
//! With a FAT32 volume mounted (a boot with a disk) the writes are real
//! queued FAT32 writes (`fat32_write_file_queued`) and the fsync is a real
//! `fs-wb` flush ticket; the ktest boots carry no disk, so there the file
//! layer is a stand-in whose flush the test itself completes. The ring, the
//! park, the link and the posting are the kernel's either way.
//!
//! The submit's cost is printed (`[IORING-K1]`, timebase ns; instructions
//! under `-icount shift=0`). Runtime canary `ioring-fsync-inline`: the fsync
//! is done inline, the submitter waiting on the device (the pre-K1 answer):
//! the fsync completes in the submit and the test goes `not ok`.

use crate::kprintln;
use core::sync::atomic::{AtomicI32, AtomicU32, AtomicU64, Ordering::SeqCst};
use azos_ipc::io_ring::{
    self as ring, IoRing, IoRingOps, OpResult, OpResult64, SqEntry, CQE_F_DURABLE, CQE_F_QUEUED,
    OP_FILE_WRITE, OP_FSYNC, RING_CQ_SIZE, RING_SQ_SIZE, SQE_F_LINK,
};

/// Writes in the batch (one fsync follows them): 32 = the SQ less one.
const N_WRITES: usize = RING_SQ_SIZE - 1;
/// The file the disk path writes (8.3).
const NAME: &[u8; 11] = b"IORINGK1BIN";

static RING_ID: AtomicU32 = AtomicU32::new(u32::MAX);
static RING_PHYS: AtomicU64 = AtomicU64::new(0);
static SUBMIT_N: AtomicI32 = AtomicI32::new(i32::MIN);
static SUBMIT_TICKS: AtomicU64 = AtomicU64::new(0);
static QUEUED_OK: AtomicU32 = AtomicU32::new(0);
/// The stand-in flusher's tickets (no disk).
static ASKED: AtomicU64 = AtomicU64::new(0);
/// The test is done with the ring: the probe may exit (its exit frees it).
static RELEASE: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
static SUBMITTED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
static DONE: AtomicU64 = AtomicU64::new(0);

fn disk() -> bool {
    azos_fs::fat32_mounted()
}

fn k1_file_io(_owner: u32, _cap: u32, write: bool, buf: *mut u8, len: usize) -> OpResult {
    if !write {
        return Ok(-1);
    }
    if disk() {
        // SAFETY: `dispatch_sqe` bounded the window inside the ring's buffer.
        let data = unsafe { core::slice::from_raw_parts(buf, len) };
        if azos_fs::fat32_write_file_queued(NAME, data).is_err() {
            return Ok(-5);
        }
    }
    Ok(len as i32)
}

fn k1_file_fsync(_owner: u32, _cap: u32) -> OpResult64 {
    if canary!("ioring-fsync-inline") {
        // The synchronous answer: wait for the device here, ticket done.
        if disk() {
            let _ = azos_fs::fat32_sync();
        }
        return Ok(0);
    }
    if disk() {
        Ok(azos_fs::fat32_flush_request())
    } else {
        Ok(ASKED.fetch_add(1, SeqCst) + 1)
    }
}

fn k1_fsync_done(ticket: u64) -> Option<i32> {
    if ticket == 0 {
        return Some(0);
    }
    if disk() {
        azos_fs::fat32_flush_done(ticket).map(|r| if r.is_ok() { 0 } else { -5 })
    } else {
        (DONE.load(SeqCst) >= ticket).then_some(0)
    }
}

static K1_OPS: IoRingOps = IoRingOps {
    file_io: k1_file_io,
    file_fsync: k1_file_fsync,
    fsync_done: k1_fsync_done,
    ..azos_syscall::ioring_ops::KERNEL_IORING_OPS_TABLE
};

/// The RT probe: one submit of the whole batch, then return. Never waits.
fn k1_probe(_: usize) {
    let tid = azos_sched::current_task_tid();
    let Some((id, phys)) = ring::io_ring_create(tid as usize) else { return };
    RING_ID.store(id, SeqCst);
    RING_PHYS.store(phys as u64, SeqCst);
    let r = azos_mm::addr::phys_to_virt(phys) as *mut IoRing;
    // SAFETY: a fresh ring this task owns; nothing else submits to it.
    unsafe {
        for i in 0..N_WRITES {
            (*r).data_buf[i] = b'a' + (i % 26) as u8;
            (*r).sq_entries[i] = SqEntry {
                opcode: OP_FILE_WRITE,
                flags: if i + 1 == N_WRITES { SQE_F_LINK } else { 0 },
                param0: 0,
                param1: 0,
                param2: 64,
                addr: 0,
                reg: 0,
                user_data: i as u64,
            };
        }
        (*r).sq_entries[N_WRITES] = SqEntry {
            opcode: OP_FSYNC, flags: 0, param0: 0, param1: 0, param2: 0, addr: 0, reg: 0, user_data: 0xF5,
        };
        (*r).sq_tail.store((N_WRITES + 1) as u32, SeqCst);
    }
    let t0 = azos_drv_sys::timebase::now();
    let n = ring::io_ring_submit(id);
    let t1 = azos_drv_sys::timebase::now();
    SUBMIT_TICKS.store(t1 - t0, SeqCst);
    SUBMIT_N.store(n, SeqCst);
    let mut ok = 0;
    // SAFETY: as above.
    unsafe {
        for i in 0..(n.max(0) as usize).min(RING_CQ_SIZE) {
            let c = (*r).cq_entries[i];
            if c.user_data == i as u64 && c.result == 64 && c.flags == CQE_F_QUEUED {
                ok += 1;
            }
        }
    }
    QUEUED_OK.store(ok, SeqCst);
    // The ring dies with its owner: report done, then stay until the test
    // has read the fsync's completion (a timer sleep, not a device wait).
    // Its own task, not `ktest::probe`: that trampoline's done mark would
    // land in the NEXT test's probe when this task exits.
    SUBMITTED.store(true, SeqCst);
    while !RELEASE.load(SeqCst) {
        azos_syscall::sleep::sleep_ms(10);
    }
}

/// The fsync's completion, once posted: `(result, flags)`.
fn fsync_cqe() -> Option<(i32, u32)> {
    let r = azos_mm::addr::phys_to_virt(RING_PHYS.load(SeqCst) as usize) as *mut IoRing;
    // SAFETY: the ring outlives the test (destroyed at its end).
    unsafe {
        let tail = (*r).cq_tail.load(SeqCst) as usize;
        (0..tail.min(RING_CQ_SIZE)).map(|i| (*r).cq_entries[i]).find(|c| c.user_data == 0xF5)
            .map(|c| (c.result, c.flags))
    }
}

azos_ktest::ktest_late! {
    fn ioring_fsync_completes_after_flush() {
        ASKED.store(0, SeqCst);
        DONE.store(0, SeqCst);
        RELEASE.store(false, SeqCst);
        SUBMITTED.store(false, SeqCst);
        ring::io_ring_register_ops(&K1_OPS);
        // RT without a disk. With one, a queued FAT32 write can still read the
        // device (a FAT or directory sector the cache misses), which the
        // owner rule forbids an RT task (`RT_BLOCK_IO_CHECK` panics): the
        // disk run is the measurement, from a normal-priority task.
        let prio = if disk() { azos_sched::DEFAULT_PRIORITY } else { azos_sched::RT_MOTOR_PRIORITY };
        azos_sched::task_create_affinity("ioring-k1", k1_probe, 0, prio, -1);
        let r = crate::ktest::wait("the RT submitter did not finish its submit", || SUBMITTED.load(SeqCst));
        let n = SUBMIT_N.load(SeqCst);
        let early = fsync_cqe();
        let per_us = (azos_drv_sys::timebase::TIMER_FREQ / 1_000_000).max(1);
        let ns = SUBMIT_TICKS.load(SeqCst) * 1000 / per_us;
        let t_flush = azos_drv_sys::timebase::now();
        // The flush path: the `fs-wb` task with a disk; the test without.
        if !disk() {
            DONE.store(ASKED.load(SeqCst), SeqCst);
            ring::io_ring_flush_posted();
        }
        let posted = crate::ktest::wait("the fsync CQE was never posted", || fsync_cqe().is_some());
        let after_ns = (azos_drv_sys::timebase::now() - t_flush) * 1000 / per_us;
        kprintln!(
            "[IORING-K1] submit {} writes + fsync: {} ns ({} completions, fsync {}), fsync CQE {} ns later, disk={}",
            N_WRITES, ns, n, if early.is_some() { "in the submit" } else { "parked" }, after_ns, disk() as u8);
        let late = fsync_cqe();
        ring::io_ring_register_ops(&azos_syscall::ioring_ops::KERNEL_IORING_OPS);
        // The probe's exit releases its ring (`io_ring_release_all`).
        RING_ID.store(u32::MAX, SeqCst);
        RELEASE.store(true, SeqCst);
        r?;
        if n != N_WRITES as i32 {
            Err("the submit did not complete exactly the writes")
        } else if QUEUED_OK.load(SeqCst) != N_WRITES as u32 {
            Err("a write did not complete CQE_F_QUEUED")
        } else if early.is_some() {
            Err("the fsync completed in the submit (the submitter waited)")
        } else {
            posted?;
            match late {
                Some((0, f)) if f == CQE_F_DURABLE => Ok(()),
                _ => Err("the fsync completed without CQE_F_DURABLE"),
            }
        }
    }
}

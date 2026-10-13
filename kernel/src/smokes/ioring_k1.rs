// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! K1 (IO-QUEUES-AUDIT): an io_ring submitter never waits on the disk.
//!
//! A REAL-TIME task submits `N_WRITES` `OP_FILE_WRITE` entries, the last one
//! linked (`SQE_F_LINK`) to an `OP_FSYNC`, in ONE submit, and returns. Owner
//! rule: an RT task only enqueues. Its pass hands the file entries to the
//! io_ring worker (`ioring-wk`, outside the RT band), which runs them in SQ
//! order: the writes complete `CQE_F_QUEUED`, the fsync parks, and its
//! completion is posted `CQE_F_DURABLE` by the flush path
//! (`io_ring_flush_posted`), never by the submitter.
//!
//! With a FAT32 volume mounted (a boot with a disk; the gate's `ktest disk`
//! rows) the writes are real queued FAT32 writes (`fat32_write_file_queued`)
//! and the fsync a real `fs-wb` flush ticket, and Kconfig
//! `RT_BLOCK_IO_CHECK` panics if the RT task ever enters the block layer.
//! Without a disk the file layer is a stand-in whose flush the test itself
//! completes. A kernel task's descriptor carries no owner TID, so the real
//! `Cap<File>` path (`write_as`) cannot serve a kernel-owned ring: the
//! stand-in sits below `IoRingOps`, the hand-off and the queues above it are
//! the kernel's.
//!
//! A second round runs the same batch from a normal-priority task (inline
//! unless Kconfig `IORING_FILE_HANDOFF_ALL`) and both rounds print their cost
//! (`[IORING-K1]`, timebase ns: instructions under `-icount shift=0`, plus the
//! time the CPU idled on the disk): the submit, and submit to the fsync's
//! completion.
//!
//! Runtime canaries: `ioring-fsync-inline` (the fsync completes where it runs,
//! before the flush: `not ok` without a disk); `ioring-rt-inline` (an RT
//! submitter runs file entries inline: `not ok`, and with a disk the RT check
//! panics and the test bails out).

use crate::kprintln;
use core::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, AtomicU64, Ordering::SeqCst};
use azos_ipc::io_ring::{
    self as ring, IoRing, IoRingOps, OpResult, OpResult64, SqEntry, CQE_F_DURABLE, CQE_F_QUEUED,
    OP_FILE_WRITE, OP_FSYNC, RING_CQ_SIZE, RING_SQ_SIZE, SQE_F_LINK,
};

/// Writes in the batch (one fsync follows them): the SQ less one.
const N_WRITES: usize = RING_SQ_SIZE - 1;
/// The file the disk path writes (8.3).
const NAME: &[u8; 11] = b"IORINGK1BIN";
/// The fsync's `user_data`.
const FSYNC_UD: u64 = 0xF5;

static RING_PHYS: AtomicU64 = AtomicU64::new(0);
static SUBMIT_N: AtomicI32 = AtomicI32::new(i32::MIN);
static T_SUBMIT0: AtomicU64 = AtomicU64::new(0);
static T_SUBMIT1: AtomicU64 = AtomicU64::new(0);
/// When the fsync's completion was posted (the reaper saw its flush done).
static T_POSTED: AtomicU64 = AtomicU64::new(0);
/// Set by the probe after its submit; the test then owns the timing.
static SUBMITTED: AtomicBool = AtomicBool::new(false);
/// The test is done with the ring: the probe may exit (its exit frees it).
static RELEASE: AtomicBool = AtomicBool::new(false);
static EXITED: AtomicBool = AtomicBool::new(false);
/// The stand-in flusher's tickets (no disk).
static ASKED: AtomicU64 = AtomicU64::new(0);
static DONE: AtomicU64 = AtomicU64::new(0);
/// A file entry ran on an RT task (the hand-off failed): the property.
static RAN_ON_RT: AtomicU32 = AtomicU32::new(0);

fn disk() -> bool {
    azos_fs::fat32_mounted()
}

fn on_rt() -> bool {
    azos_sched::scheduler::current_task_base_priority() < azos_sched::RT_PRIORITY_THRESHOLD
}

fn k1_file_io(_owner: u32, _cap: u32, write: bool, buf: *mut u8, len: usize) -> OpResult {
    if on_rt() {
        RAN_ON_RT.fetch_add(1, SeqCst);
    }
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
    if on_rt() {
        RAN_ON_RT.fetch_add(1, SeqCst);
    }
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
    let r = if ticket == 0 {
        Some(0)
    } else if disk() {
        azos_fs::fat32_flush_done(ticket).map(|r| if r.is_ok() { 0 } else { -5 })
    } else {
        (DONE.load(SeqCst) >= ticket).then_some(0)
    };
    if r.is_some() {
        let _ = T_POSTED.compare_exchange(0, azos_drv_sys::timebase::now(), SeqCst, SeqCst);
    }
    r
}

static K1_OPS: IoRingOps = IoRingOps {
    file_io: k1_file_io,
    file_fsync: k1_file_fsync,
    fsync_done: k1_fsync_done,
    ..azos_syscall::ioring_ops::KERNEL_IORING_OPS_TABLE
};

/// The submitter: one submit of the whole batch, then stay (the ring dies
/// with its owner) until the test is done. Its own task, not `ktest::probe`:
/// that trampoline's done mark would land in the NEXT test's probe.
fn k1_probe(_: usize) {
    let tid = azos_sched::current_task_tid();
    if let Some((id, phys)) = ring::io_ring_create(tid as usize) {
        RING_PHYS.store(phys as u64, SeqCst);
        let r = azos_mm::addr::phys_to_virt(phys) as *mut IoRing;
        // SAFETY: a fresh ring this task owns; nothing else submits to it.
        unsafe {
            for i in 0..N_WRITES {
                (*r).data_buf[i] = b'a' + (i % 26) as u8;
                (*r).sq_entries[i] = SqEntry {
                    opcode: OP_FILE_WRITE,
                    flags: if i + 1 == N_WRITES { SQE_F_LINK } else { 0 },
                    param0: 0, param1: 0, param2: 64, addr: 0, reg: 0,
                    user_data: i as u64,
                };
            }
            (*r).sq_entries[N_WRITES] = SqEntry {
                opcode: OP_FSYNC, flags: 0, param0: 0, param1: 0, param2: 0, addr: 0, reg: 0,
                user_data: FSYNC_UD,
            };
            (*r).sq_tail.store((N_WRITES + 1) as u32, SeqCst);
        }
        T_SUBMIT0.store(azos_drv_sys::timebase::now(), SeqCst);
        let n = ring::io_ring_submit(id);
        T_SUBMIT1.store(azos_drv_sys::timebase::now(), SeqCst);
        SUBMIT_N.store(n, SeqCst);
    }
    SUBMITTED.store(true, SeqCst);
    while !RELEASE.load(SeqCst) {
        azos_syscall::sleep::sleep_ms(10);
    }
    EXITED.store(true, SeqCst);
}

/// Completions on the ring so far: `(writes QUEUED, fsync's (result, flags))`.
fn cqes() -> (u32, Option<(i32, u32)>) {
    let r = azos_mm::addr::phys_to_virt(RING_PHYS.load(SeqCst) as usize) as *mut IoRing;
    // SAFETY: the ring outlives every look (its owner waits for RELEASE).
    unsafe {
        let tail = ((*r).cq_tail.load(SeqCst) as usize).min(RING_CQ_SIZE);
        let mut queued = 0;
        let mut fsync = None;
        for i in 0..tail {
            let c = (*r).cq_entries[i];
            if c.user_data == FSYNC_UD {
                fsync = Some((c.result, c.flags));
            } else if c.result == 64 && c.flags == CQE_F_QUEUED {
                queued += 1;
            }
        }
        (queued, fsync)
    }
}

/// What one round saw.
struct Round {
    n: i32,
    submit_ns: u64,
    posted_ns: u64,
    /// The fsync had completed before the test's stand-in flush.
    early: bool,
    queued: u32,
    fsync: Option<(i32, u32)>,
}

fn round(prio: u32) -> Result<Round, &'static str> {
    for f in [&SUBMITTED, &RELEASE, &EXITED] {
        f.store(false, SeqCst);
    }
    for v in [&T_SUBMIT0, &T_SUBMIT1, &T_POSTED, &RING_PHYS] {
        v.store(0, SeqCst);
    }
    SUBMIT_N.store(i32::MIN, SeqCst);
    azos_sched::task_create_affinity("ioring-k1", k1_probe, 0, prio, -1);
    crate::ktest::wait("the submitter did not finish its submit", || SUBMITTED.load(SeqCst))?;
    let mut r = Round { n: SUBMIT_N.load(SeqCst), submit_ns: 0, posted_ns: 0, early: false, queued: 0, fsync: None };
    if RING_PHYS.load(SeqCst) == 0 {
        RELEASE.store(true, SeqCst);
        return Err("io_ring_create failed");
    }
    let waited = (|| {
        // Every write completes first (inline or by the worker) ...
        crate::ktest::wait("the writes never completed", || cqes().0 == N_WRITES as u32)?;
        if !disk() {
            // ... and without a disk the fsync must still be parked: the
            // test is its flusher.
            r.early = cqes().1.is_some();
            DONE.store(ASKED.load(SeqCst), SeqCst);
            ring::io_ring_flush_posted();
        }
        crate::ktest::wait("the fsync CQE was never posted", || cqes().1.is_some())
    })();
    let per_us = (azos_drv_sys::timebase::TIMER_FREQ / 1_000_000).max(1);
    let t0 = T_SUBMIT0.load(SeqCst);
    r.submit_ns = T_SUBMIT1.load(SeqCst).saturating_sub(t0) * 1000 / per_us;
    r.posted_ns = T_POSTED.load(SeqCst).saturating_sub(t0) * 1000 / per_us;
    (r.queued, r.fsync) = cqes();
    RELEASE.store(true, SeqCst);
    // The owner's exit releases the ring (`io_ring_release_all`).
    crate::ktest::wait("the submitter did not exit", || EXITED.load(SeqCst))?;
    waited.map(|()| r)
}

azos_ktest::ktest_late! {
    fn ioring_fsync_completes_after_flush() {
        if disk() && !azos_limits::RT_BLOCK_IO_CHECK {
            return Err("a disk boot without Kconfig RT_BLOCK_IO_CHECK proves nothing");
        }
        ASKED.store(0, SeqCst);
        DONE.store(0, SeqCst);
        RAN_ON_RT.store(0, SeqCst);
        ring::io_ring_register_ops(&K1_OPS);
        let rt = round(azos_sched::RT_MOTOR_PRIORITY);
        let ran_on_rt = RAN_ON_RT.load(SeqCst);
        let normal = round(azos_sched::DEFAULT_PRIORITY);
        ring::io_ring_register_ops(&azos_syscall::ioring_ops::KERNEL_IORING_OPS);
        let rt = rt?;
        let normal = normal?;
        for (who, r) in [("rt (hand-off)", &rt), ("normal", &normal)] {
            kprintln!(
                "[IORING-K1] {} {} writes + fsync: submit {} ns ({} completions), fsync DURABLE {} ns after the submit began, disk={}",
                who, N_WRITES, r.submit_ns, r.n, r.posted_ns, disk() as u8);
        }
        if ran_on_rt != 0 {
            Err("a file entry ran on the RT submitter (no hand-off)")
        } else if rt.n != 0 {
            Err("the RT submit completed an entry it must hand off")
        } else if rt.queued != N_WRITES as u32 {
            Err("a handed-off write did not complete CQE_F_QUEUED")
        } else if rt.early {
            Err("the fsync completed before its flush (the submitter's pass waited)")
        } else {
            match rt.fsync {
                Some((0, f)) if f == CQE_F_DURABLE => Ok(()),
                _ => Err("the fsync completed without CQE_F_DURABLE"),
            }
        }
    }
}

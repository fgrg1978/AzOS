// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// The `block` endpoint scoped to one partition.
//
// The stage-0 gate row: "a partition cap writing one LBA
// outside it is refused AND recorded". The io_ring op-table entry
// (`block_host::block_io`) and the `Block` interface's `sectors` are driven
// with a partition table published through the REAL
// `azos_drv_block::partition` (pulled by the drivers shim) and the device
// stood in by a probe (`shims/drivers`, `set_blk_probe`) that records the
// ABSOLUTE sector and the count it was asked for. The capability and op-class
// checks in front of it are the ring's (`ioring_ops_guards.rs`, and the ring's
// own tests in `crates/core/ipc`); this file is the scope.

use super::harness::serial;
use crate::block_host::{block_io, BlockServer, BLOCK_SCOPE_REFUSALS};
use crate::khost::Caller;
use azos_abi::cap::{CapKind, CapPerms, ty};
use azos_abi::error::Errno;
use azos_devif::{outcome, Block};
use azos_drv_block::blkdev::set_blk_probe;
use azos_drv_block::partition::{self, Partition, Scheme, Table, MAX_PARTS};
use azos_ipc::io_ring::IO_ERR_PERM;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Mutex;

static NEXT_TID: AtomicU32 = AtomicU32::new(0x7600_0001);
fn fresh_tid() -> u32 {
    NEXT_TID.fetch_add(1, Ordering::SeqCst)
}

/// Shared with `hw_cap_guards.rs`; every test resets the table it binds.
const SLOT: usize = 58;

static SEEN: Mutex<Vec<(u8, u32, bool)>> = Mutex::new(Vec::new());
/// Every request that reached the device: `(write, absolute sector, count)`.
static DEVICE: Mutex<Vec<(bool, u64, u32)>> = Mutex::new(Vec::new());

fn recorder(kind_code: u8, target: u32, need_write: bool) {
    SEEN.lock().unwrap_or_else(|e| e.into_inner()).push((kind_code, target, need_write));
}

fn seen() -> Vec<(u8, u32, bool)> {
    SEEN.lock().unwrap_or_else(|e| e.into_inner()).clone()
}

fn device() -> Vec<(bool, u64, u32)> {
    DEVICE.lock().unwrap_or_else(|e| e.into_inner()).clone()
}

/// A device that fills a read with the sector number's low byte and notes the
/// request; a write is only noted.
fn probe(write: bool, sector: u64, count: u32, buf: &mut [u8]) -> Result<(), ()> {
    DEVICE.lock().unwrap_or_else(|e| e.into_inner()).push((write, sector, count));
    if !write {
        for (i, b) in buf.iter_mut().enumerate() {
            *b = (sector as u8).wrapping_add((i / 512) as u8);
        }
    }
    Ok(())
}

/// The endpoint's recorder code (`CapKind::denial_code`).
const ENDPOINT_CODE: u8 = ty::ENDPOINT.denial_code();

/// Two partitions: 0 = LBA 2048 + 4096 (badge 1), 1 = LBA 8192 + 1024 (badge 2).
fn publish_two() {
    partition::reset_for_tests();
    let none = Partition { start: 0, sectors: 0, mbr_type: 0 };
    let mut parts = [none; MAX_PARTS];
    parts[0] = Partition { start: 2048, sectors: 4096, mbr_type: 0x83 };
    parts[1] = Partition { start: 8192, sectors: 1024, mbr_type: 0x83 };
    assert!(partition::publish(&Table { scheme: Scheme::Mbr, parts, count: 2 }));
}

fn scene() {
    publish_two();
    let tid = fresh_tid();
    ipc_task_pool::shim_bind(tid, SLOT);
    azos_ipc::cap_store::reset(tid);
    SEEN.lock().unwrap_or_else(|e| e.into_inner()).clear();
    DEVICE.lock().unwrap_or_else(|e| e.into_inner()).clear();
    set_cap_deny_recorder(recorder);
    set_blk_probe(Some(probe));
    azos_sched::set_current_user_pt(0xBAD0_0000);
    azos_sched::set_current_task_tid(tid);
}

fn done() {
    set_blk_probe(None);
    partition::reset_for_tests();
}

fn refusals() -> u32 {
    BLOCK_SCOPE_REFUSALS.load(Ordering::SeqCst)
}

fn run(badge: u32, write: bool, sector: u64, sectors: usize) -> Result<i32, i32> {
    let mut buf = vec![0u8; sectors * 512];
    block_io(badge, write, sector, buf.as_mut_ptr(), buf.len())
}

/// **The stage-0 canary, with RELATIVE sectors.** A write-capable endpoint for
/// partition 0 (LBA 2048 + 4096, badge 1) names its sectors from 0: it is
/// admitted at relative 0 and relative 4095, and refused at relative 4096 (one
/// past its end), for a run that starts inside and ends outside, for relative
/// 8192 (partition 1's ABSOLUTE start, now just a sector past the end of
/// partition 0) and for an overflowing run; every refusal is recorded (the
/// endpoint kind, the badge, the write bit as asked) and counted, and never
/// reaches the device. "One sector before the start" can no longer be spelled:
/// a relative sector is unsigned.
///
/// **Canary.** Make `partition::resolve` accept every run, or build with
/// `block-scope-canary` (a gate row: `scope` drops the end check): the refusal
/// lines read `Ok`. Delete the `record_cap_denial` call in `block_io`: `seen()`
/// stays empty.
#[test]
fn a_partition_endpoint_writing_one_sector_outside_is_refused_and_recorded() {
    let _g = serial();
    scene();
    let before = refusals();

    assert_eq!(run(1, true, 0, 1), Ok(512), "relative first sector");
    assert_eq!(run(1, true, 4095, 1), Ok(512), "relative last sector");
    assert_eq!(run(1, false, 3000, 4), Ok(2048), "a read inside");
    assert_eq!(seen(), vec![], "an admitted request was recorded");
    let admitted = device().len();
    assert_eq!(admitted, 3);

    for (sector, sectors, what) in [
        (4096u64, 1usize, "one sector past the end"),
        (4095, 2, "a run crossing the end"),
        (8192, 1, "another partition's absolute start"),
        (u64::MAX, 2, "an overflowing run"),
        (2048 + 4095, 1, "the partition's own ABSOLUTE last sector (it is relative 6143)"),
    ] {
        assert_eq!(run(1, true, sector, sectors), Err(IO_ERR_PERM), "{what} admitted");
    }
    assert_eq!(run(1, false, u64::MAX, 1), Err(IO_ERR_PERM), "a read past the end admitted");

    assert_eq!(refusals() - before, 6, "every refusal is counted");
    let rec = seen();
    assert_eq!(rec.len(), 6, "every refusal is recorded: {rec:?}");
    assert!(rec[..5].iter().all(|&r| r == (ENDPOINT_CODE, 1, true)), "{rec:?}");
    assert_eq!(rec[5], (ENDPOINT_CODE, 1, false), "the read refusal must not carry the write bit");
    assert_eq!(device().len(), admitted, "a refused run reached the device");
    done();
}

/// **The kernel adds the partition's start.** The device is handed
/// `start + relative`: partition 0's relative 0 is absolute 2048 and its
/// relative 4095 is 6143; partition 1's relative 5 is 8197, for the run's
/// whole count. This is what the admissions above cannot show by themselves.
///
/// **Canary.** Make `partition::resolve` return `Some(rel)` (drop the
/// `start +`): the first device line reads sector 0.
#[test]
fn an_admitted_relative_sector_reaches_the_device_at_start_plus_relative() {
    let _g = serial();
    scene();
    assert_eq!(run(1, true, 0, 1), Ok(512));
    assert_eq!(run(1, false, 4095, 1), Ok(512));
    assert_eq!(run(2, true, 5, 3), Ok(1536));
    assert_eq!(run(2, false, 1023, 1), Ok(512));
    assert_eq!(
        device(),
        vec![(true, 2048, 1), (false, 6143, 1), (true, 8197, 3), (false, 9215, 1)]
    );
    done();
}

/// **The bytes cross the bounce buffer in the right direction.** A read lands
/// what the device produced in the caller's window, sector by sector; a write
/// hands the device what the window held. A failing device is an `EIO`, not a
/// success.
///
/// **Canary.** Skip the copy back in the read arm of `block_io`: the window
/// stays zero.
#[test]
fn a_read_fills_the_window_and_a_write_hands_the_device_its_bytes() {
    let _g = serial();
    scene();
    let mut buf = vec![0u8; 1024];
    assert_eq!(block_io(1, false, 7, buf.as_mut_ptr(), buf.len()), Ok(1024));
    // The probe filled each sector with `absolute sector + index` (2048 + 7).
    let first = (2055u64 as u8, 2056u64 as u8);
    assert!(buf[..512].iter().all(|&b| b == first.0), "first sector");
    assert!(buf[512..].iter().all(|&b| b == first.1), "second sector");

    static GOT: Mutex<Vec<u8>> = Mutex::new(Vec::new());
    fn write_probe(write: bool, _s: u64, _c: u32, buf: &mut [u8]) -> Result<(), ()> {
        assert!(write);
        *GOT.lock().unwrap_or_else(|e| e.into_inner()) = buf.to_vec();
        Ok(())
    }
    set_blk_probe(Some(write_probe));
    let mut out = vec![0xC3u8; 512];
    assert_eq!(block_io(1, true, 0, out.as_mut_ptr(), out.len()), Ok(512));
    assert_eq!(*GOT.lock().unwrap(), vec![0xC3u8; 512]);

    fn failing(_w: bool, _s: u64, _c: u32, _b: &mut [u8]) -> Result<(), ()> {
        Err(())
    }
    set_blk_probe(Some(failing));
    assert_eq!(block_io(1, false, 0, buf.as_mut_ptr(), 512), Err(Errno::EIO.to_syscall_ret() as i32));
    assert_eq!(block_io(1, true, 0, out.as_mut_ptr(), 512), Err(Errno::EIO.to_syscall_ret() as i32));
    done();
}

/// **A run is whole sectors, and the badge names a partition.** An empty or
/// ragged length and a badge that is the whole medium (0) or past the table
/// (17) are `EINVAL` and reach neither the device nor the recorder.
#[test]
fn a_ragged_run_or_a_bad_badge_is_refused_before_the_device() {
    let _g = serial();
    scene();
    let einval = Errno::EINVAL.to_syscall_ret() as i32;
    let mut b = vec![0u8; 1024];
    for len in [0usize, 1, 511, 513, 1000] {
        assert_eq!(block_io(1, false, 0, b.as_mut_ptr(), len), Err(einval), "len {len}");
    }
    for badge in [0u32, 17, u32::MAX] {
        assert_eq!(block_io(badge, false, 0, b.as_mut_ptr(), 512), Err(einval), "badge {badge}");
    }
    assert_eq!(device(), vec![]);
    assert_eq!(seen(), vec![]);
    done();
}

/// **`sectors` is the partition's length, and a read-class question.** Badge 1
/// is 4096, badge 2 is 1024; badge 0 (the whole medium) and one past the table
/// are `BAD_ARGUMENT`; a partition the kernel did not publish is `NOT_READY`;
/// without `READ` the call is `DENIED`.
///
/// **Canary.** Return the medium's capacity for a partition: the first line
/// reads the disk's size.
#[test]
fn sectors_is_the_partitions_length_for_a_holder_of_read() {
    let _g = serial();
    scene();
    let who = |badge, rights| BlockServer(Caller { tid: azos_sched::current_task_tid(), badge, rights });
    assert_eq!(who(1, CapPerms::READ).sectors().value, 4096);
    assert_eq!(who(2, CapPerms::RW).sectors().value, 1024);
    assert_eq!(who(0, CapPerms::READ).sectors().code, outcome::BAD_ARGUMENT);
    assert_eq!(who(17, CapPerms::READ).sectors().code, outcome::BAD_ARGUMENT);
    assert_eq!(who(3, CapPerms::READ).sectors().code, outcome::NOT_READY, "partition 2 is not published");
    assert_eq!(who(1, CapPerms::WRITE).sectors().code, outcome::DENIED, "a read op needs READ");
    assert_eq!(who(1, CapPerms::NONE).sectors().code, outcome::DENIED);
    done();
}

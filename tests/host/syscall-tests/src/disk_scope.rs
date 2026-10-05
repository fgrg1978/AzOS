// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// RFC-0048 P3: a `Cap<Disk>` scoped to one partition.
//
// The stage-0 gate row of RFC-0048 §5: "a partition cap writing one LBA
// outside it is refused AND recorded". `sys_disk_read`/`sys_disk_write` are
// driven with a partition table published through the REAL
// `azos_drv_block::partition` (pulled by the drivers shim) and a capability
// minted by the REAL `disk_cap::disk_part_grant_cap`. An admitted request is
// observed as the `-1` of the zero-count argument check that follows the
// gate (the device call after it is the shim's `todo!()`), a refused one as
// `E_PERM` plus a record through the recorder hook.

use super::harness::serial;
use azos_abi::cap::{CapKind, CapPerms};
use azos_drv_block::partition::{self, Partition, Scheme, Table, MAX_PARTS};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Mutex;

static NEXT_TID: AtomicU32 = AtomicU32::new(0x7600_0001);
fn fresh_tid() -> u32 {
    NEXT_TID.fetch_add(1, Ordering::SeqCst)
}

/// Shared with `hw_cap_guards.rs`; every test resets the table it binds.
const SLOT: usize = 58;

static SEEN: Mutex<Vec<(u8, u32, bool)>> = Mutex::new(Vec::new());

fn recorder(kind_code: u8, target: u32, need_write: bool) {
    SEEN.lock().unwrap_or_else(|e| e.into_inner()).push((kind_code, target, need_write));
}

fn seen() -> Vec<(u8, u32, bool)> {
    SEEN.lock().unwrap_or_else(|e| e.into_inner()).clone()
}

/// The `Disk` denial code (`CapKind::denial_code`, frozen in the recording).
const DISK_CODE: u8 = 11;

/// Two partitions: 0 = LBA 2048 + 4096, 1 = LBA 8192 + 1024.
fn publish_two() {
    partition::reset_for_tests();
    let none = Partition { start: 0, sectors: 0, mbr_type: 0 };
    let mut parts = [none; MAX_PARTS];
    parts[0] = Partition { start: 2048, sectors: 4096, mbr_type: 0x83 };
    parts[1] = Partition { start: 8192, sectors: 1024, mbr_type: 0x83 };
    assert!(partition::publish(&Table { scheme: Scheme::Mbr, parts, count: 2 }));
}

fn as_user(tid: u32) {
    ipc_task_pool::shim_bind(tid, SLOT);
    azos_ipc::cap_store::reset(tid);
    SEEN.lock().unwrap_or_else(|e| e.into_inner()).clear();
    set_cap_deny_recorder(recorder);
    azos_sched::set_current_user_pt(0xBAD0_0000);
    azos_sched::set_current_task_tid(tid);
}

fn refusals() -> u32 {
    DISK_SCOPE_REFUSALS.load(Ordering::SeqCst)
}

/// **The stage-0 canary, with RELATIVE sectors.** A write-capable
/// capability for partition 0 (LBA 2048 + 4096) names its sectors from 0: it
/// is admitted at relative 0 and relative 4095, and refused at relative 4096
/// (one past its end), for a run that starts inside and ends outside, for
/// relative 8192 (partition 1's ABSOLUTE start — now just a sector past the
/// end of partition 0) and for an overflowing run; every refusal is recorded
/// (kind `Disk`, write bit set) and counted. "One sector before the start"
/// can no longer be spelled: a relative sector is unsigned.
///
/// **Canary.** Make `disk_lba` return `Ok(sector)` on its partition path
/// instead of refusing: every `E_PERM` line reads `-1`. **Canary.** Delete
/// the `record_cap_denial` call on that path: `seen()` stays empty.
#[test]
fn a_partition_capability_writing_one_lba_outside_is_refused_and_recorded() {
    let _g = serial();
    publish_two();
    let tid = fresh_tid();
    as_user(tid);
    let cap = azos_ipc::disk_cap::disk_part_grant_cap(tid, 0, CapPerms::RW);
    assert!(cap.is_some(), "partition 0 is published and must be mintable");
    let before = refusals();

    assert_eq!(sys_disk_write(0, 0, 0, 0), -1, "relative first sector refused");
    assert_eq!(sys_disk_write(4095, 0, 0, 0), -1, "relative last sector refused");
    assert_eq!(sys_disk_read(3000, 0, 0, 0), -1, "a read inside refused");
    assert_eq!(seen(), vec![], "an admitted request was recorded");

    assert_eq!(sys_disk_write(4096, 1, 0, 0), E_PERM, "one LBA past the end admitted");
    assert_eq!(sys_disk_write(4095, 2, 0, 0), E_PERM, "a run crossing the end admitted");
    assert_eq!(sys_disk_write(8192, 1, 0, 0), E_PERM, "another partition's absolute LBA admitted");
    assert_eq!(sys_disk_write(u64::MAX, 2, 0, 0), E_PERM, "an overflowing run admitted");
    assert_eq!(sys_disk_write(2048 + 4095, 1, 0, 0), E_PERM,
               "the partition's own ABSOLUTE last sector admitted (it is relative 6143)");
    assert_eq!(sys_disk_read(u64::MAX, 1, 0, 0), E_PERM, "a read past the end admitted");

    assert_eq!(refusals() - before, 6, "every refusal is counted");
    let rec = seen();
    assert_eq!(rec.len(), 6, "every refusal is recorded: {rec:?}");
    assert!(rec[..5].iter().all(|&r| r == (DISK_CODE, 0, true)), "{rec:?}");
    assert_eq!(rec[5], (DISK_CODE, 0, false), "the read refusal must not carry the write bit");
    partition::reset_for_tests();
}

/// **The kernel adds the partition's start.** The resolver hands the device
/// `start + relative`: partition 0's relative 0 is absolute 2048 and its
/// relative 4095 is 6143; partition 1's relative 5 is 8197. A whole-disk
/// caller's sector is passed through untouched. This is what the admitted
/// `-1`s above cannot show (the device call after them is never reached).
///
/// **Canary.** Make `partition::resolve` return `Some(rel)` (drop the
/// `start +`): the first assertion reads `Some(0)`.
#[test]
fn an_admitted_relative_sector_reaches_the_device_at_start_plus_relative() {
    let _g = serial();
    publish_two();
    let tid = fresh_tid();
    as_user(tid);
    azos_ipc::disk_cap::disk_part_grant_cap(tid, 0, CapPerms::RW).expect("mint");
    assert_eq!(disk_lba(0, 0, 1, true), Ok(2048), "relative 0 of partition 0");
    assert_eq!(disk_lba(0, 4095, 1, false), Ok(6143), "relative 4095 of partition 0");
    assert_eq!(disk_lba(0, 4096, 1, false), Err(E_PERM), "relative 4096 is past partition 0");

    let tid = fresh_tid();
    as_user(tid);
    azos_ipc::disk_cap::disk_part_grant_cap(tid, 1, CapPerms::RW).expect("mint");
    assert_eq!(disk_lba(0, 5, 3, true), Ok(8197), "relative 5 of partition 1");
    assert_eq!(disk_lba(0, 1023, 1, true), Ok(9215), "relative last of partition 1");
    assert_eq!(disk_lba(0, 1023, 2, true), Err(E_PERM));

    let tid = fresh_tid();
    as_user(tid);
    assert!(azos_ipc::cap_store::with_table(tid, |t| t.grant_raw(CapKind::Disk, CapPerms::RW, 0))
        .flatten()
        .is_some());
    assert_eq!(disk_lba(0, 2048, 1, true), Ok(2048), "whole disk: absolute, untouched");
    partition::reset_for_tests();
}

/// **Two partitions held: a relative sector is ambiguous, and refused.** A
/// task holding write capabilities for partitions 0 and 1 cannot say which
/// one relative 0 means; the kernel refuses and records rather than pick.
/// Holding the second one READ-only does not make a WRITE ambiguous: only
/// capabilities with the needed permission count.
///
/// **Canary.** Drop the `other != 0` branch in `disk_scope`: the read
/// resolves into partition 0 (`Ok(2048)`) instead of `Err(E_PERM)`.
#[test]
fn two_partitions_held_make_a_relative_sector_ambiguous_and_refused() {
    let _g = serial();
    publish_two();
    let tid = fresh_tid();
    as_user(tid);
    azos_ipc::disk_cap::disk_part_grant_cap(tid, 0, CapPerms::RW).expect("mint 0");
    azos_ipc::disk_cap::disk_part_grant_cap(tid, 1, CapPerms::READ).expect("mint 1");
    let before = refusals();
    assert_eq!(disk_lba(0, 0, 1, true), Ok(2048), "only partition 0 can write: not ambiguous");
    assert_eq!(disk_lba(0, 0, 1, false), Err(E_PERM), "two readable partitions: ambiguous");
    assert_eq!(refusals() - before, 1);
    assert_eq!(seen(), vec![(DISK_CODE, 0, false)]);
    partition::reset_for_tests();
}

/// **Permission still counts inside the partition.** A READ-only partition
/// capability may not write even inside its range; that refusal is the
/// ordinary no-capability one (recorded by `cap_check`), not a scope one.
#[test]
fn a_read_only_partition_capability_cannot_write_inside_it() {
    let _g = serial();
    publish_two();
    let tid = fresh_tid();
    as_user(tid);
    azos_ipc::disk_cap::disk_part_grant_cap(tid, 1, CapPerms::READ).expect("mint");
    let before = refusals();
    assert_eq!(sys_disk_read(0, 0, 0, 0), -1, "relative 0 of partition 1 refused");
    assert_eq!(sys_disk_write(0, 1, 0, 0), E_PERM);
    assert_eq!(refusals(), before, "a permission refusal is not a scope refusal");
    assert_eq!(seen(), vec![(DISK_CODE, 0, true)]);
    partition::reset_for_tests();
}

/// **Nothing changes for the callers that existed before P3.** The whole-
/// disk resource 0 is admitted anywhere; no capability at all is refused and
/// recorded by `cap_check` without touching the scope counter.
#[test]
fn whole_disk_and_no_capability_behave_as_before() {
    let _g = serial();
    publish_two();
    let tid = fresh_tid();
    as_user(tid);
    let before = refusals();
    assert_eq!(sys_disk_write(0, 1, 0, 0), E_PERM);
    assert_eq!(seen(), vec![(DISK_CODE, 0, true)]);
    assert!(azos_ipc::cap_store::with_table(tid, |t| t.grant_raw(CapKind::Disk, CapPerms::RW, 0))
        .flatten()
        .is_some());
    assert_eq!(sys_disk_write(0, 0, 0, 0), -1, "the whole-disk capability was refused LBA 0");
    assert_eq!(sys_disk_write(1 << 40, 0, 0, 0), -1);
    assert_eq!(refusals(), before);
    partition::reset_for_tests();
}

/// **Only a published partition can be minted**, and only read/write.
///
/// **Canary.** Drop the `partition(index)?` line in `disk_part_grant_cap`:
/// the unpublished partition 2 is minted.
#[test]
fn only_a_published_partition_can_be_minted() {
    let _g = serial();
    partition::reset_for_tests();
    let tid = fresh_tid();
    as_user(tid);
    assert!(azos_ipc::disk_cap::disk_part_grant_cap(tid, 0, CapPerms::RW).is_none(),
            "minted before any table was published");
    publish_two();
    assert!(azos_ipc::disk_cap::disk_part_grant_cap(tid, 2, CapPerms::RW).is_none(),
            "minted a partition the table does not have");
    assert!(azos_ipc::disk_cap::disk_part_grant_cap(tid, u32::MAX, CapPerms::RW).is_none());
    assert!(azos_ipc::disk_cap::disk_part_grant_cap(tid, 1, CapPerms::NONE).is_none());
    let c = azos_ipc::disk_cap::disk_part_grant_cap(tid, 1, CapPerms::WRITE).expect("mint");
    assert_eq!(azos_ipc::cap_store::get(tid, c, CapPerms::WRITE), Ok(2),
               "partition 1 is resource 2");
    partition::reset_for_tests();
}

// ── Wave 10: the partition selector (a3 / a0) and SYS_DISK_SIZE ──────────

static TYPED: Mutex<Vec<(u8, u32)>> = Mutex::new(Vec::new());

fn typed_recorder(kind_code: u8, reason: u32) {
    TYPED.lock().unwrap_or_else(|e| e.into_inner()).push((kind_code, reason));
}

fn typed_seen() -> Vec<(u8, u32)> {
    TYPED.lock().unwrap_or_else(|e| e.into_inner()).clone()
}

fn as_user_typed(tid: u32) {
    as_user(tid);
    TYPED.lock().unwrap_or_else(|e| e.into_inner()).clear();
    set_cap_deny_typed_recorder(typed_recorder);
}

fn part_cap(tid: u32, index: u32, perms: CapPerms) -> u64 {
    azos_ipc::disk_cap::disk_part_grant_cap(tid, index, perms)
        .expect("mint")
        .raw()
        .as_raw() as u64
}

/// **A caller holding two partitions names one, and is admitted.** The same
/// task that the sentinel refuses as ambiguous writes relative 0 of
/// partition 1 (absolute 8192) and of partition 0 (absolute 2048) by passing
/// the handle, and a run past the NAMED partition is refused and recorded
/// exactly as the sentinel path's is.
///
/// **Canary.** Make `disk_scope` ignore `sel` (always take the sentinel
/// path): both named resolutions read `Err(-99)`, the ambiguous refusal.
#[test]
fn a_named_partition_resolves_where_the_sentinel_is_ambiguous() {
    let _g = serial();
    publish_two();
    let tid = fresh_tid();
    as_user_typed(tid);
    let p0 = part_cap(tid, 0, CapPerms::RW);
    let p1 = part_cap(tid, 1, CapPerms::RW);
    assert_eq!(disk_lba(DISK_SEL_ONLY, 0, 1, true), Err(E_PERM), "sentinel with two: ambiguous");
    assert_eq!(disk_lba(p1, 0, 1, true), Ok(8192), "relative 0 of the named partition 1");
    assert_eq!(disk_lba(p0, 0, 1, true), Ok(2048), "relative 0 of the named partition 0");
    assert_eq!(disk_lba(p1, 1023, 1, false), Ok(9215));
    let before = refusals();
    assert_eq!(disk_lba(p1, 1024, 1, true), Err(E_PERM), "one past the named partition");
    assert_eq!(refusals() - before, 1);
    assert_eq!(sys_disk_write(0, 0, 0, p1), -1, "admitted: the zero-count check answers");
    assert_eq!(typed_seen(), vec![], "an admitted handle was recorded");
    partition::reset_for_tests();
}

/// **A bad handle gets the typed refusals, recorded.** Forged: `-ECAPSTALE`.
/// A READ-only partition capability asked to write: `-ECAPPERMS`. A live
/// handle of another kind: `-ECAPKIND`. A selector above `u32::MAX`:
/// `-EINVAL`, not truncated.
///
/// **Canary.** Delete `if sel > u32::MAX as u64 { return Err(EINVAL) }`
/// (the `sel as u32` truncation stays): `1 << 32` is read as handle 0 and
/// answers `Err(-202)` (stale) instead of `Err(-22)`.
#[test]
fn a_bad_selector_is_refused_with_the_typed_errnos_and_recorded() {
    use azos_abi::error::Errno;
    let _g = serial();
    publish_two();
    let tid = fresh_tid();
    as_user_typed(tid);
    let ro = part_cap(tid, 0, CapPerms::READ);
    assert_eq!(disk_lba(0x7FFF_FFF1, 0, 1, false), Err(Errno::ECAPSTALE.to_syscall_ret()));
    assert_eq!(disk_lba(ro, 0, 1, true), Err(Errno::ECAPPERMS.to_syscall_ret()));
    let other = azos_ipc::cap_store::with_table(tid, |t| t.grant_raw(CapKind::Sensor, CapPerms::READ, 0))
        .flatten()
        .expect("a sensor capability")
        .as_raw() as u64;
    assert_eq!(disk_lba(other, 0, 1, false), Err(Errno::ECAPKIND.to_syscall_ret()));
    assert_eq!(typed_seen().len(), 3, "each refusal is recorded: {:?}", typed_seen());
    assert!(typed_seen().iter().all(|&(k, _)| k == DISK_CODE));
    assert_eq!(disk_lba(1 << 32, 0, 1, false), Err(Errno::EINVAL.to_syscall_ret()));
    assert_eq!(disk_lba(ro, 0, 1, false), Ok(2048), "the READ handle still reads");
    partition::reset_for_tests();
}

/// **`SYS_DISK_SIZE` needs the capability and reports the partition.** No
/// capability: `E_PERM`, recorded. A holder of partition 1 alone: 1024 (its
/// length) through the sentinel and through its handle; a holder of two:
/// ambiguous through the sentinel, each partition's own length through its
/// handle.
///
/// **Canary.** Return `capacity_sectors()` for `DiskScope::Part` as for
/// `Whole`: the first partition answer is the device's count, not 1024 (the
/// shim device is armed with 131,072 sectors so the canary fails on the
/// value, not on a missing stub).
#[test]
fn disk_size_needs_the_capability_and_reports_the_partition() {
    let _g = serial();
    publish_two();
    syscall_test_drivers::shim_fwd::arm(syscall_test_drivers::shim_fwd::Fwd { sectors: 131_072, ..Default::default() });
    let tid = fresh_tid();
    as_user_typed(tid);
    assert_eq!(sys_disk_size(DISK_SEL_ONLY), E_PERM, "no capability");
    assert_eq!(seen(), vec![(DISK_CODE, 0, false)], "the refusal is recorded");

    let tid = fresh_tid();
    as_user_typed(tid);
    let p1 = part_cap(tid, 1, CapPerms::READ);
    assert_eq!(sys_disk_size(DISK_SEL_ONLY), 1024, "the only partition's length");
    assert_eq!(sys_disk_size(p1), 1024);

    let p0 = part_cap(tid, 0, CapPerms::READ);
    assert_eq!(sys_disk_size(DISK_SEL_ONLY), E_PERM, "two partitions: ambiguous");
    assert_eq!(sys_disk_size(p0), 4096);
    assert_eq!(sys_disk_size(p1), 1024);

    let tid = fresh_tid();
    as_user_typed(tid);
    assert!(azos_ipc::cap_store::with_table(tid, |t| t.grant_raw(CapKind::Disk, CapPerms::READ, 0))
        .flatten()
        .is_some());
    assert_eq!(sys_disk_size(DISK_SEL_ONLY), 131_072, "whole disk: the medium");
    let _ = syscall_test_drivers::shim_fwd::disarm();
    partition::reset_for_tests();
}

/// **A ring-3 write through the sentinel is contained like one through a
/// handle.** Degraded mode armed: the partition holder gets `-EAGAIN` on
/// both paths and its read stays live; a caller with no capability still
/// gets `E_PERM`, the authority answer first.
///
/// **Canary.** Delete the `need_write && untyped_write_contained()` check in
/// `disk_scope`: the sentinel write reads `Ok(2048)`.
#[test]
fn a_sentinel_write_is_contained_like_a_handle_write() {
    use azos_abi::error::Errno;
    let _g = serial();
    publish_two();
    let tid = fresh_tid();
    as_user_typed(tid);
    let p0 = part_cap(tid, 0, CapPerms::RW);
    azos_ipc::cap::degraded_set(true);
    let sentinel = disk_lba(DISK_SEL_ONLY, 0, 1, true);
    let named = disk_lba(p0, 0, 1, true);
    let read = disk_lba(DISK_SEL_ONLY, 0, 1, false);
    let tid2 = fresh_tid();
    as_user_typed(tid2);
    let none = disk_lba(DISK_SEL_ONLY, 0, 1, true);
    azos_ipc::cap::degraded_set(false);
    assert_eq!(sentinel, Err(Errno::EAGAIN.to_syscall_ret()));
    assert_eq!(named, Err(Errno::EAGAIN.to_syscall_ret()));
    assert_eq!(read, Ok(2048), "a read is not contained");
    assert_eq!(none, Err(E_PERM), "no capability: the authority answer");
    partition::reset_for_tests();
}

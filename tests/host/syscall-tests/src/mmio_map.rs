// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// `SYS_MMIO_MAP` (509, RFC-0043): the one way ring 3 maps device registers.
// No test reached it before this file.
//
// Real on this path: the handler (`crates/core/syscall/src/mmio.rs`), the argument
// check (`crates/core/ipc/src/mmio_cap.rs`), the capability table, the board's
// region table (`crates/drivers/base/src/platform.rs`, QEMU `virt`: 0 is the RTC,
// read-only; 1 is a writable page of the platform bus) and the Sv39 walker.
// Transcribed: `process::mmio_map_user` (see `shims/sched`), whose PTEs are
// read back here through the real `translate_user`.
//
// What a refusal must leave behind is nothing: every refused call below is
// followed by a check that the task's MMIO window is still empty.

use super::harness::serial;
use azos_abi::cap::{CapKind, CapPerms};
use azos_abi::error::Errno;

/// The cap-store pool slot this file binds its caller to (unused elsewhere).
const SLOT: usize = 30;
const TID: u32 = 0x5100_0001;

const READ: u64 = CapPerms::READ.bits() as u64;
const RW: u64 = CapPerms::RW.bits() as u64;

const RTC: u32 = 0; // read-only region
const BUS: u32 = 1; // writable region

/// Ring 3, an empty capability table and a real user page table.
fn ring3() -> usize {
    ipc_task_pool::shim_bind(TID, SLOT);
    azos_ipc::cap_store::reset(TID);
    let pt = azos_mm::pmm::alloc_page().expect("arena exhausted").as_usize();
    azos_sched::set_current_user_pt(pt);
    azos_sched::set_current_task_tid(TID);
    pt
}

fn hold(index: u32, perms: CapPerms) {
    assert!(
        azos_ipc::cap_store::with_table(TID, |t| t.grant_raw(CapKind::MmioRegion, perms, index))
            .flatten()
            .is_some(),
        "could not grant mmio {index}"
    );
}

/// The first page of the MMIO window: where the first mapping lands.
fn window_base() -> usize {
    azos_sched::user_shm_window().0
}

fn window_is_empty(pt: usize) -> bool {
    azos_mm::vmm::translate_user(pt, window_base(), false).is_none()
}

fn map(index: u64, access: u64) -> i64 {
    crate::mmio::sys_mmio_map(index, access)
}

fn einval() -> i64 { Errno::EINVAL.to_syscall_ret() }
fn eacces() -> i64 { Errno::EACCES.to_syscall_ret() }

/// Admitted: a READ capability on the RTC maps exactly the RTC's frame,
/// readable and NOT writable.
#[test]
fn a_read_capability_maps_the_region_read_only() {
    let _g = serial();
    let pt = ring3();
    hold(RTC, CapPerms::READ);
    let va = map(RTC as u64, READ);
    assert_eq!(va, window_base() as i64, "did not map at the window");
    let va = va as usize;
    assert_eq!(azos_mm::vmm::translate_user(pt, va, false), Some(0x0010_1000), "wrong frame");
    assert_eq!(azos_mm::vmm::user_write_would_be_permitted(pt, va), false, "RTC mapped writable");
    assert!(azos_mm::vmm::translate_user(pt, va + 0x1000, false).is_none(), "mapped past the region");
}

/// Admitted: RW on the writable region with an RW capability is writable.
#[test]
fn a_read_write_capability_maps_a_writable_region_writable() {
    let _g = serial();
    let pt = ring3();
    hold(BUS, CapPerms::RW);
    let va = map(BUS as u64, RW) as usize;
    assert_eq!(azos_mm::vmm::translate_user(pt, va, false), Some(0x0400_0000));
    assert!(azos_mm::vmm::user_write_would_be_permitted(pt, va), "RW mapping is not writable");
}

/// Refusal: no capability. `-1` (the dispatch-level `E_PERM`), nothing mapped.
#[test]
fn no_capability_is_refused_and_maps_nothing() {
    let _g = serial();
    let pt = ring3();
    assert_eq!(map(RTC as u64, READ), -1);
    assert_eq!(map(BUS as u64, RW), -1);
    assert!(window_is_empty(pt));
}

/// Refusal: a capability for ANOTHER index, or a READ capability asked for
/// RW, does not admit.
#[test]
fn a_capability_admits_only_its_own_index_and_access() {
    let _g = serial();
    let pt = ring3();
    hold(BUS, CapPerms::READ);
    assert_eq!(map(RTC as u64, READ), -1, "a Cap for region 1 mapped region 0");
    assert_eq!(map(BUS as u64, RW), -1, "a READ Cap mapped RW");
    assert!(window_is_empty(pt));
}

/// Refusal before the capability check: an access word other than READ or
/// READ|WRITE is `EINVAL` even while holding RW on the region.
#[test]
fn an_access_word_other_than_read_or_read_write_is_einval() {
    let _g = serial();
    let pt = ring3();
    hold(BUS, CapPerms::RW);
    for access in [0u64, CapPerms::WRITE.bits() as u64, 4, RW | 4, u64::MAX, 1 << 32 | READ] {
        assert_eq!(map(BUS as u64, access), einval(), "access {access:#x}");
    }
    assert!(window_is_empty(pt));
}

/// Refusal: an index outside the table, and one wider than `u32` that would
/// NARROW to a held index (`1 << 32` is 0 as a `u32`), are `EINVAL` — the
/// holder of region 0 must not reach it through a wide register.
#[test]
fn an_index_outside_the_table_or_wider_than_u32_is_einval() {
    let _g = serial();
    let pt = ring3();
    hold(RTC, CapPerms::READ);
    // Index 2 is the RTC's writable alias (wave 9 IRQ4); 3 is past the table.
    for index in [3u64, u32::MAX as u64, 1 << 32, (1 << 32) | RTC as u64, u64::MAX] {
        assert_eq!(map(index, READ), einval(), "index {index:#x}");
    }
    assert!(window_is_empty(pt));
}

/// Refusal: WRITE on a read-only region is `EACCES`, even for a caller whose
/// table somehow holds RW on it (`grant_raw` bypasses the minter's rule).
#[test]
fn write_on_a_read_only_region_is_eacces_whatever_is_held() {
    let _g = serial();
    let pt = ring3();
    hold(RTC, CapPerms::RW);
    assert_eq!(map(RTC as u64, RW), eacces());
    assert!(window_is_empty(pt));
}

/// A kernel caller has no user page table: admitted by `cap_check`, refused
/// by the mapper, `-1`.
#[test]
fn a_kernel_caller_gets_minus_one() {
    let _g = serial();
    assert_eq!(map(RTC as u64, READ), -1);
}

// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// Host tests for `sys_taskinfo` (`SYS_TASKINFO`, 241): the blob layout ring 3
// reads, and the short-buffer refusal.
//
// The layout is an ABI: `userspace/bench/vsbench` reads the switch counts from slots
// 2 and 3 and the hart from slot 4, by offset. A field moved, dropped or left
// unwritten reads as a plausible number on the other side, so every slot is
// pinned to the shim value it must carry — none of them zero.

use azos_abi::syscall_nr::TASKINFO_BYTES;

fn slot(blob: &[u8], i: usize) -> u64 {
    u64::from_le_bytes(blob[i * 8..(i + 1) * 8].try_into().unwrap())
}

#[test]
fn the_blob_is_five_slots_in_the_documented_order() {
    let _g = harness::serial();
    azos_sched::set_current_task_tid(9);

    let mut blob = [0u8; TASKINFO_BYTES];
    let rc = sys_taskinfo(blob.as_mut_ptr() as u64, blob.len() as u64);

    assert_eq!(rc, TASKINFO_BYTES as i64, "returns the byte count it wrote");
    assert_eq!(TASKINFO_BYTES, 40, "five u64 slots");
    assert_eq!(slot(&blob, 0), 9, "slot 0: tid");
    assert_eq!(slot(&blob, 1), 16, "slot 1: priority");
    assert_eq!(slot(&blob, 2), 7, "slot 2: voluntary switches");
    assert_eq!(slot(&blob, 3), 3, "slot 3: preempted switches");
    assert_eq!(slot(&blob, 4), 2, "slot 4: the hart the caller is on");
}

#[test]
fn a_buffer_one_byte_short_is_refused_and_left_untouched() {
    let _g = harness::serial();

    let mut blob = [0xAAu8; TASKINFO_BYTES];
    let rc = sys_taskinfo(blob.as_mut_ptr() as u64, (TASKINFO_BYTES - 1) as u64);

    assert_eq!(rc, azos_abi::error::Errno::EINVAL.to_syscall_ret());
    assert!(blob.iter().all(|&b| b == 0xAA), "a refused call writes nothing");
}

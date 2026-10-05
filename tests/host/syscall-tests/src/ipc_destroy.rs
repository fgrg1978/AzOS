// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// `SYS_CLOSE_TYPED` (566) on a `Cap<Channel>`: how ring 3 destroys a channel
// since RFC-0040 gap 1 retired `SYS_IPC_DESTROY` (107). This file pinned two
// properties of 107, and both carry over to the typed close:
//
// - a task that may not destroy the channel is refused and the channel
//   survives, while the holder's close frees it (for 107, `channel_destroy`'s
//   owner refusal had to reach ring 3 as -1 instead of a reported success);
// - every close that names nothing gets one answer (for 107, out of range, a
//   free slot and another task's channel all answered -1, owner decision
//   2026-09-14), so a sweep says nothing about which channels exist.
//
// The channel-layer decisions are covered in `tests/host/ipc-chan-tests`; what these
// tests pin is the syscall's answer, so they call the handlers. `channel.rs` is
// compiled here as a dependency and reads its caller through `shims/ipc_sched`,
// which forwards to the same `shims/sched` registers set below: one caller
// identity, as in the kernel.

use super::harness::serial;
use crate::ipc_handlers::*;
use azos_abi::cap::{CapHandle, CapPerms};
use azos_abi::error::Errno;
use azos_ipc::cap::objref::CHANNEL;
use azos_ipc::cap::targets::Channel;
use azos_ipc::cap::Cap;
use azos_ipc::channel::{channel_owner, channel_ref, MAX_CHANNELS};

const OWNER: u32 = 0x7710_0001;
const STRANGER: u32 = 0x7710_0002;
/// Task-pool slots nothing else in the crate binds.
const SLOT_OWNER: usize = 55;
const SLOT_STRANGER: usize = 56;
/// A non-zero page-table root: ring 3 as far as every check here is concerned.
/// No handler here dereferences it.
const USER_PT: usize = 0xBAD0_0000;

fn stale() -> i64 {
    Errno::ECAPSTALE.to_syscall_ret()
}

fn as_ring3(tid: u32) {
    azos_sched::set_current_user_pt(USER_PT);
    azos_sched::set_current_task_tid(tid);
}

/// Binds both tasks with empty tables and frees every channel as the kernel,
/// on entry and again on drop, panic or not: the pool is a process static with
/// no per-test reset in this crate.
struct Scene;

fn scene() -> Scene {
    for (tid, slot) in [(OWNER, SLOT_OWNER), (STRANGER, SLOT_STRANGER)] {
        ipc_task_pool::shim_bind(tid, slot);
        azos_ipc::cap_store::reset(tid);
    }
    free_channels_now();
    Scene
}

fn free_channels_now() {
    azos_sched::set_current_user_pt(0);
    azos_sched::set_current_task_tid(0);
    for ch in 0..MAX_CHANNELS {
        let _ = azos_ipc::channel_destroy(ch);
    }
}

impl Drop for Scene {
    fn drop(&mut self) {
        free_channels_now();
        for tid in [OWNER, STRANGER] {
            azos_ipc::cap_store::reset(tid);
        }
    }
}

/// The channel index `tid`'s handle `h` names.
fn channel_of(tid: u32, h: i64) -> usize {
    let cap: Cap<Channel> = Cap::from_raw(CapHandle::from_raw(h as u32));
    CHANNEL.idx(azos_ipc::cap_store::get(tid, cap, CapPerms::NONE).expect("a live capability")) as usize
}

/// A `Cap<Channel>` with `perms` on channel `ch`, straight into `tid`'s table.
fn grant_to(tid: u32, ch: usize, perms: CapPerms) -> u64 {
    let r = channel_ref(ch).expect("a live channel");
    azos_ipc::cap_store::grant::<Channel>(tid, perms, r)
        .expect("cap table full")
        .raw()
        .as_raw() as u64
}

/// **A task that may not destroy the channel is refused, and the channel
/// survives; the holder's close frees it.** The stranger first presents the
/// owner's handle value, which names nothing in its own table, then a
/// READ-only capability to the same channel.
///
/// **Canary.** Resolve `channel_destroy_cap` asking `NONE` instead of `WRITE`:
/// the READ-only close frees the channel.
#[test]
fn a_task_without_a_write_capability_is_refused_and_the_channel_survives() {
    let _g = serial();
    let _s = scene();

    as_ring3(OWNER);
    let h = sys_chan_create_typed();
    assert!(h > 0, "create returned {h}");
    let ch = channel_of(OWNER, h);
    assert_eq!(channel_owner(ch), Some(OWNER), "precondition: the creator owns it");

    as_ring3(STRANGER);
    assert_eq!(sys_close_typed(h as u64), stale(), "the owner's handle value in the stranger's table");
    let ro = grant_to(STRANGER, ch, CapPerms::READ);
    assert_eq!(sys_close_typed(ro), Errno::ECAPPERMS.to_syscall_ret(), "a READ-only capability");
    assert_eq!(channel_owner(ch), Some(OWNER), "a refused close freed the channel");

    as_ring3(OWNER);
    assert_eq!(sys_close_typed(h as u64), 0, "the holder's close");
    assert_eq!(channel_owner(ch), None, "the holder's close did not free the slot");
}

/// **Every close that names nothing gets one answer.** To a ring-3 stranger, a
/// forged handle, a capability to a channel its owner already closed, and the
/// value of another task's live handle all answer `-ECAPSTALE`, asserted as one
/// array so a later edit cannot make one of them differ quietly. The owner's
/// second close and a kernel-context close of a forged handle answer the same.
///
/// **Canary.** Answer `-EBADF` for `ChannelCapError::Cap(CapError::Stale)` in
/// `errno_for_channel_err`: the closed-channel answer differs from the others.
#[test]
fn every_close_that_names_nothing_gives_one_answer() {
    let _g = serial();
    let _s = scene();

    as_ring3(OWNER);
    let live = sys_chan_create_typed();
    let doomed = sys_chan_create_typed();
    assert!(live > 0 && doomed > 0, "creates returned {live} and {doomed}");
    let theirs = channel_of(OWNER, live);
    let left = grant_to(STRANGER, channel_of(OWNER, doomed), CapPerms::RW);
    assert_eq!(sys_close_typed(doomed as u64), 0, "the owner closes one channel");

    as_ring3(STRANGER);
    let answers = [sys_close_typed(0), sys_close_typed(left), sys_close_typed(live as u64)];
    assert_eq!(
        answers,
        [stale(); 3],
        "[a forged handle, a capability to a closed channel, another task's live handle]"
    );
    assert_eq!(channel_owner(theirs), Some(OWNER), "a refused close freed the channel");

    as_ring3(OWNER);
    assert_eq!(sys_close_typed(doomed as u64), stale(), "the owner's second close");
    azos_sched::set_current_user_pt(0);
    assert_eq!(sys_close_typed(0), stale(), "a kernel-context close of a forged handle");
    as_ring3(OWNER);
    assert_eq!(sys_close_typed(live as u64), 0);
}

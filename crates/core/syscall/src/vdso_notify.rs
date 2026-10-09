// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Wave 6, front V: the per-task vDSO page (`SYS_VDSO_TASK_MAP` 594,
//! `SYS_VDSO_SENSOR_BIND` 595), its timer-interrupt publisher, and the
//! notify/wait pair (`SYS_NOTIFY_WAIT` 592, `SYS_NOTIFY_WAKE` 593).
//!
//! In its own file for the reason `link_key.rs` and `motor_cmd.rs` are:
//! `dispatch.rs` carries only the four arms.
//!
//! The page itself, its layout and its scoping rules are in
//! `crates/core/mm/src/vdso.rs`; the waiter table and the lost-wakeup argument are
//! in `crates/core/ipc/src/notify.rs`. This file is the syscall edge: argument
//! checks, the capability check for a sensor binding, and turning a user
//! address into a (region, offset) key.

#[cfg(not(feature = "domain-robot"))]
use crate::no_robot::{robot as azos_robot};
use core::sync::atomic::{AtomicU64, Ordering};
use azos_abi::error::Errno;

use crate::handlers::{SENSOR_TYPE_ENCODER, SENSOR_TYPE_ODOM};

// ── Per-task vDSO page ──────────────────────────────────────────────────────

/// Harts whose previous-interrupt time is kept for the CPU-time charge. A
/// hart past this charges nothing (its tasks' `cpu_time` stays 0) rather
/// than indexing out of bounds.
const TICK_HARTS: usize = 8;
static LAST_TICK: [AtomicU64; TICK_HARTS] = [const { AtomicU64::new(0) }; TICK_HARTS];

/// The sensor types the timer interrupt can sample: the two whose source is
/// a pair of lock-free atomics (`azos_robot::{encoder_read, odom_get}`).
/// Every other type is read over I2C/UART/CSI by its syscall and cannot be
/// read from an interrupt; its slot is never published.
fn isr_sampled(t: u32) -> bool {
    matches!(t as u64, SENSOR_TYPE_ENCODER | SENSOR_TYPE_ODOM)
}

/// Fill `buf` with sensor type `t` in `SYS_SENSOR_READ_TYPED`'s byte format,
/// from interrupt context, with its acquisition time (vDSO-clock ns, the stamp
/// `SYS_SENSOR_READ_TS` reports for the same read: the encoder counters are
/// read here, so their stamp is this read; odometry carries `odom_task`'s).
/// `None` for a type [`isr_sampled`] refuses.
fn sample_isr(t: u32, buf: &mut [u8; azos_mm::vdso::VDSO_SENSOR_DATA_MAX]) -> Option<(usize, u64)> {
    let ((a, b), acq) = match t as u64 {
        SENSOR_TYPE_ENCODER => azos_robot::encoder_read_stamped(),
        SENSOR_TYPE_ODOM => azos_robot::odom_get_stamped(),
        _ => return None,
    };
    buf[0..8].copy_from_slice(&a.to_le_bytes());
    buf[8..16].copy_from_slice(&b.to_le_bytes());
    Some((16, crate::handlers::SampleMeta::at_ticks(acq, 0).acq_ns))
}

/// Refresh the per-task page of the task running on this hart. Called from
/// the timer interrupt on every hart, next to `vdso_update`.
///
/// Charges the interval since this hart's previous interrupt to the task it
/// finds running — sampled accounting, exact only to a tick — and copies the
/// scheduler's counters and the bound sensors. A task that never mapped its
/// page costs one table load here.
pub fn vdso_task_tick(now: u64) {
    let Some(f) = azos_sched::scheduler::current_task_vdso_facts() else { return };
    let last = match LAST_TICK.get(f.hart) {
        Some(a) => a.swap(now, Ordering::Relaxed),
        None => now,
    };
    let cpu_delta = if last == 0 || now < last { 0 } else { now - last };
    azos_mm::vdso::task_page_publish(
        &azos_mm::vdso::TaskFacts {
            idx: f.idx,
            tid: f.tid,
            cpu_delta,
            switches_voluntary: f.switches_voluntary,
            switches_preempted: f.switches_preempted,
            ready_site: f.ready_site as u32,
            now,
        },
        &sample_isr,
    );
}

/// `SYS_VDSO_TASK_MAP` (594): map the caller's per-task page read-only and
/// return its user address. Idempotent while the mapping stands.
pub fn sys_vdso_task_map() -> i64 {
    let Some(f) = azos_sched::scheduler::current_task_vdso_facts() else {
        return Errno::EINVAL.to_syscall_ret();
    };
    let user_pt = azos_sched::current_user_pt();
    if user_pt == 0 {
        return Errno::EINVAL.to_syscall_ret();
    }
    let Some(claim) = azos_mm::vdso::task_page_claim(f.idx, f.tid) else {
        return Errno::ENOMEM.to_syscall_ret();
    };
    if let Some(va) = claim.mapped_va {
        // Still mapped in THIS address space (an exec replaced it otherwise).
        if azos_mm::vmm::translate(user_pt, va) == Some(claim.phys) {
            return va as i64;
        }
    }
    match azos_sched::process::shm_map_user(&[claim.phys], false) {
        Some(va) => {
            azos_mm::vdso::task_page_set_va(f.idx, f.tid, va);
            va as i64
        }
        None => Errno::ENOMEM.to_syscall_ret(),
    }
}

/// `SYS_VDSO_SENSOR_BIND` (595): publish sensor `t` into the caller's page,
/// where `t` is what `a0`, a `Cap<Sensor>` with `READ` in the caller's own
/// table, names — the check `SYS_SENSOR_READ_TYPED` makes.
///
/// Returns 1 when the type is published at every timer interrupt, 0 when it
/// is bound but has no interrupt-safe source (its slot stays unpublished),
/// `-ENOENT` when the caller has not mapped its page, and the capability's
/// `-ECAPSTALE`/`-ECAPKIND`/`-ECAPPERMS`.
pub fn sys_vdso_sensor_bind(cap_raw: u64) -> i64 {
    use azos_abi::cap::CapHandle;
    use azos_ipc::cap::{targets::Sensor, Cap};
    // A wider a0 is refused, never truncated onto a handle the caller holds.
    let Ok(raw) = u32::try_from(cap_raw) else {
        return Errno::ECAPSTALE.to_syscall_ret();
    };
    let cap: Cap<Sensor> = Cap::from_raw(CapHandle::from_raw(raw));
    let tid = azos_sched::current_task_tid();
    let t = match azos_ipc::cap_store::with_table(tid, |tab| {
        azos_ipc::sensor_cap::sensor_type_of(tab, cap)
    }) {
        Some(Ok(t)) => t,
        Some(Err(e)) => return crate::handlers::errno_for_cap_err(azos_abi::cap::CapKind::Sensor, e),
        None => return Errno::EINVAL.to_syscall_ret(),
    };
    let Some(f) = azos_sched::scheduler::current_task_vdso_facts() else {
        return Errno::EINVAL.to_syscall_ret();
    };
    if !azos_mm::vdso::task_page_bind_sensor(f.idx, tid, t) {
        return Errno::ENOENT.to_syscall_ret();
    }
    if isr_sampled(t) { 1 } else { 0 }
}

// ── Notify / wait ───────────────────────────────────────────────────────────

/// The kernel side of `azos_ipc::notify::NotifyEnv`: block on
/// `WaitReason::Timer(deadline)` (the path the timer interrupt already serves:
/// the sleeper heap, or the sweep without `sched-timer-heap`), wake by TID with the predicate
/// `Timer(d) if d == deadline`. `wake_task_by_tid` is already reached from
/// the PLIC handler (`wait::wake_port_waiter`), so [`notify_wake_kernel`] is
/// callable from an interrupt.
pub struct KernelNotifyEnv;

impl azos_ipc::notify::NotifyEnv for KernelNotifyEnv {
    fn now(&self) -> u64 {
        azos_drv_sys::timebase::now()
    }
    fn block(&self, deadline: u64) -> bool {
        // Killable: a forced kill ends a wait with no deadline (plan item 7).
        use azos_sched::{task_block_killable, BlockOutcome, WaitReason};
        task_block_killable(WaitReason::Timer(deadline)) == BlockOutcome::Refused
    }
    fn wake(&self, tid: u32, deadline: u64) {
        azos_sched::scheduler::wake_task_by_tid(
            tid,
            &|r| matches!(r, azos_sched::WaitReason::Timer(d) if *d == deadline),
        );
    }
}

/// Wake up to `n` waiters on (`region`, `offset`) from kernel code, an
/// interrupt handler included — for a kernel producer of a shm ring. The
/// region is the packed reference `Cap<Shm>` stores.
pub fn notify_wake_kernel(region: u32, offset: u32, n: u32) -> u32 {
    azos_ipc::notify::notify_wake_key(&KernelNotifyEnv, region, offset, n)
}

/// Resolve a user address to the (region, offset, physical byte) of a shm
/// region the caller has mapped. `-EINVAL` for a misaligned word, `-EFAULT`
/// for an address in no mapping of the caller's.
fn notify_key(uaddr: u64) -> Result<(u32, u32, usize), i64> {
    if uaddr & 3 != 0 {
        return Err(Errno::EINVAL.to_syscall_ret());
    }
    // The mapping is the process's (wave 15, plan 4a), whichever thread asks.
    let tid = azos_sched::current_proc_tid();
    match azos_ipc::shm::shm_resolve_mapped(tid, uaddr as usize) {
        Some((region, off, phys)) => Ok((region, off as u32, phys)),
        None => Err(Errno::EFAULT.to_syscall_ret()),
    }
}

/// `SYS_NOTIFY_WAIT` (592): `a0 = uaddr` (a 4-byte-aligned word in a shm
/// region the caller has mapped), `a1 = expected`, `a2 = timeout_ns`
/// (`u64::MAX` = none, `0` = do not block).
///
/// `0` woken by a `SYS_NOTIFY_WAKE` on the same word; `1` the timeout
/// passed; `-EAGAIN` the word did not hold `expected` (nothing blocked);
/// `-EINVAL` misaligned or `expected` wider than 32 bits; `-EFAULT` not in a
/// mapping of the caller's; `-ENOSPC` no waiter row; `-EBUSY` the scheduler
/// refused to block (preemption disabled).
///
/// `a1[32..]` must be 0 (`-EINVAL`): the robust ops that rode there for one
/// integration round are [`sys_notify_robust`] (612) now. A wait ended by the
/// exit sweep of the word's robust owner answers `2`
/// (`NOTIFY_WAIT_OWNER_DIED`).
pub fn sys_notify_wait(uaddr: u64, expected: u64, timeout_ns: u64) -> i64 {
    let Ok(expected) = u32::try_from(expected) else {
        return Errno::EINVAL.to_syscall_ret();
    };
    let (region, off, phys) = match notify_key(uaddr) {
        Ok(k) => k,
        Err(e) => return e,
    };
    let kva = azos_mm::addr::phys_to_virt(phys);
    if timeout_ns == 0 {
        // SAFETY: `phys` is a byte of a region the caller maps (hence holds a
        // reference on), 4-byte aligned per `notify_key`.
        let v = unsafe { &*(kva as *const core::sync::atomic::AtomicU32) }.load(Ordering::Acquire);
        return if v == expected { 1 } else { Errno::EAGAIN.to_syscall_ret() };
    }
    let deadline = if timeout_ns == azos_ipc::notify::NOTIFY_FOREVER {
        u64::MAX
    } else {
        let ticks = azos_abi::time::ns_to_ticks_ceil(timeout_ns, azos_drv_sys::timebase::TIMER_FREQ);
        azos_drv_sys::timebase::now().saturating_add(ticks)
    };
    let tid = azos_sched::current_task_tid();
    use azos_ipc::notify::WaitResult;
    // SAFETY: as above; the caller's mapping holds the region for the call.
    match unsafe { azos_ipc::notify::notify_wait_key(&KernelNotifyEnv, tid, region, off, kva, expected, deadline) } {
        WaitResult::Woken => 0,
        WaitResult::OwnerDied => azos_abi::syscall_nr::NOTIFY_WAIT_OWNER_DIED,
        WaitResult::TimedOut => 1,
        WaitResult::ValueChanged => Errno::EAGAIN.to_syscall_ret(),
        WaitResult::Refused => Errno::EBUSY.to_syscall_ret(),
        WaitResult::NoSpace => Errno::ENOSPC.to_syscall_ret(),
    }
}

/// `SYS_NOTIFY_WAKE` (593): `a0 = uaddr`, `a1 = n`. Wakes up to `n` waiters
/// on the word and returns how many; `-EINVAL`/`-EFAULT` as
/// [`sys_notify_wait`].
pub fn sys_notify_wake(uaddr: u64, n: u64) -> i64 {
    let (region, off, _) = match notify_key(uaddr) {
        Ok(k) => k,
        Err(e) => return e,
    };
    let n = u32::try_from(n).unwrap_or(u32::MAX);
    notify_wake_kernel(region, off, n) as i64
}

// ── Robust words (owner-died, wave 11) ──────────────────────────────────────

/// `SYS_NOTIFY_ROBUST` (612): `a0 = uaddr`, `a1 = op` — `NOTIFY_ROBUST_ADD`
/// (1) registers the word at `uaddr` as a robust lock word of the caller,
/// `NOTIFY_ROBUST_DEL` (2) drops that registration; any other `op` is
/// `-EINVAL`.
///
/// The key is resolved from the caller's recorded mapping, as a wait's is,
/// and the region must be writable: the exit sweep WRITES the word, and a task
/// that may only read a region must not be able to make the kernel write it.
/// The sweep also writes only a word whose TID bits are the dying task's own,
/// so a registration can never alter a word another live task holds.
pub fn sys_notify_robust(uaddr: u64, op: u64) -> i64 {
    use azos_abi::syscall_nr::{NOTIFY_ROBUST_ADD, NOTIFY_ROBUST_DEL};
    use azos_ipc::notify::RobustError;
    if op != NOTIFY_ROBUST_ADD && op != NOTIFY_ROBUST_DEL {
        return Errno::EINVAL.to_syscall_ret();
    }
    let (region, off, _) = match notify_key(uaddr) {
        Ok(k) => k,
        Err(e) => return e,
    };
    let tid = azos_sched::current_task_tid();
    match op {
        NOTIFY_ROBUST_ADD => {
            match azos_ipc::shm::shm_perms_ref(region) {
                Ok(azos_ipc::shm::ShmPerms::ReadWrite) => {}
                Ok(_) => return Errno::EACCES.to_syscall_ret(),
                Err(_) => return Errno::EFAULT.to_syscall_ret(),
            }
            match azos_ipc::notify::robust_add(tid, region, off) {
                Ok(()) => 0,
                Err(RobustError::Quota) => Errno::EQUOTA.to_syscall_ret(),
                Err(RobustError::Full) => Errno::ENOSPC.to_syscall_ret(),
                Err(RobustError::BadTid) => Errno::EINVAL.to_syscall_ret(),
            }
        }
        NOTIFY_ROBUST_DEL => {
            if azos_ipc::notify::robust_remove(tid, region, off) {
                0
            } else {
                Errno::ENOENT.to_syscall_ret()
            }
        }
        _ => Errno::EINVAL.to_syscall_ret(),
    }
}

/// The robust sweep for `tid`, from the task-exit hook and from `exec`: every
/// word `tid` registered and still holds (its TID in the low 30 bits) becomes
/// `OWNER_DIED` (WAITERS kept) and every waiter on it is woken with
/// `NOTIFY_WAIT_OWNER_DIED`. Returns how many words were marked.
///
/// Must run while `tid` still maps the regions: on exit, before
/// `azos_ipc::task_release_all` gives its shared-memory references back
/// (`kernel/src/boot/sched.rs`). A word in a region `tid` no longer maps is
/// skipped — its registration goes, nothing is written.
pub fn notify_robust_exit(tid: u32) -> u32 {
    use azos_ipc::shm;
    let page = azos_arch::PAGE_SIZE;
    let resolve = |region: u32, off: u32| -> Option<usize> {
        // The words live in the process's mappings (a thread's robust list
        // is its own, the regions are its process's).
        if !matches!(shm::shm_has_mapping_ref(azos_sched::group::proc_tid(tid), region), Ok(true)) {
            return None;
        }
        let off = off as usize;
        let phys = shm::shm_page_phys_ref(region, off / page).ok().flatten()?;
        Some(azos_mm::addr::phys_to_virt(phys + off % page))
    };
    // SAFETY: `resolve` answers only for a region `tid` still maps, so the
    // page is held by `tid`'s own reference until `task_release_all` (which
    // the caller runs after this) gives it back; offsets were 4-aligned when
    // registered (`notify_key`).
    unsafe { azos_ipc::notify::notify_robust_exit(&KernelNotifyEnv, tid, resolve) }
}

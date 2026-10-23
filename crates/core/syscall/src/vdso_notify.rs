// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Wave 6, front V: the per-task vDSO page (`DOMAIN_VDSO_MAP` 594,
//! the sensor bind of the `Sensor` interface) and its timer-interrupt
//! publisher; and the native futex calls (`SYS_FUTEX_WAIT`, `SYS_FUTEX_WAKE`).
//!
//! The page itself, its layout and its scoping rules are in
//! `crates/core/mm/src/vdso.rs`; the waiter table and the lost-wakeup argument are
//! in `crates/core/sched/src/futex_table.rs`. This file is the syscall edge:
//! argument checks, the capability check for a sensor binding, and turning a
//! user address into a futex key (a shm word by its region and offset).

#[cfg(not(feature = "use-robot"))]
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

/// Fill `buf` with sensor type `t` in the `Sensor` interface's record format,
/// from interrupt context, with its acquisition time (vDSO-clock ns, the stamp
/// the interface reports for the same read: the encoder counters are
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

/// Refresh the per-task page of the task running on this hart, and give the
/// clock discipline its tick. Called from the timer interrupt on every hart,
/// next to `vdso_update`.
///
/// Charges the interval since this hart's previous interrupt to the task it
/// finds running — sampled accounting, exact only to a tick — and copies the
/// scheduler's counters and the bound sensors. A task that never mapped its
/// page costs one table load here.
pub fn vdso_task_tick(now: u64) {
    // The clock discipline's slice of the wall clock's slew (a flag read when
    // nothing is standing), whatever runs on this hart.
    crate::clock::tick();
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

/// `DOMAIN_VDSO_MAP`: map the caller's per-task page read-only and
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

/// Publish sensor type `t` into the caller's page (the `Sensor` interface's
/// `bind_vdso`; the capability question is the server's). `Ok(true)` when the
/// type is published at every timer interrupt, `Ok(false)` when it is bound
/// but has no interrupt-safe source (its slot stays unpublished), `Err` when
/// the caller has not mapped its page (`ENOENT`) or is no task (`EINVAL`).
pub fn bind_sensor(tid: u32, t: u32) -> Result<bool, Errno> {
    let Some(f) = azos_sched::scheduler::current_task_vdso_facts() else {
        return Err(Errno::EINVAL);
    };
    if !azos_mm::vdso::task_page_bind_sensor(f.idx, tid, t) {
        return Err(Errno::ENOENT);
    }
    Ok(isr_sampled(t))
}

// ── Futex words ─────────────────────────────────────────────────────────────

/// Wake up to `n` waiters on (`region`, `offset`) from kernel code, an
/// interrupt handler included: a kernel producer of a shm ring (the table
/// is only ever locked with interrupts off, and the wake is by TID). The
/// region is the packed reference `Cap<Shm>` stores; the key is the one
/// [`SYS_FUTEX_WAIT`](azos_abi::syscall_nr::SYS_FUTEX_WAIT) files a word of
/// that region under.
pub fn notify_wake_kernel(region: u32, offset: u32, n: u32) -> u32 {
    let key = azos_sched::futex::Key::Shared { obj: region, offset };
    azos_sched::futex::wake_key(key, n).max(0) as u32
}

/// The futex key of the aligned word at `uaddr`, and whether the word lives
/// in a shm region the caller's process maps. The key of such a word is
/// (region, offset), never an address, so two tasks that map the region at
/// different addresses meet on it; any other word is keyed by the process
/// (what its threads share).
///
/// The region is found from the process's RECORDED MAPPING of it
/// (`memobj_resolve_mapped`), not from a `Cap<Shm>` handle: a mapping is
/// only ever recorded by `SYS_MO_MAP`, which demands `READ` on the
/// capability, so the authority is the same; and capabilities MOVE
/// (`cap_store::move_cap`), so a creator that gives its region to a peer
/// keeps the mapping and loses the handle. Asked on every call, so a
/// released mapping stops resolving at once.
///
/// For the calls that check nothing at the word (a wake, a requeue's target);
/// a call that compares the word takes its key from [`futex_look`].
fn futex_word(uaddr: u64) -> Result<(azos_sched::futex::Key, bool), i64> {
    if uaddr & 3 != 0 {
        return Err(Errno::EINVAL.to_syscall_ret());
    }
    // The mapping is the process's, whichever thread asks.
    let tid = azos_sched::current_proc_tid();
    if let Some((region, off)) = azos_ipc::memobj::memobj_resolve_mapped(tid, uaddr as usize) {
        return Ok((azos_sched::futex::Key::Shared { obj: region, offset: off as u32 }, true));
    }
    azos_sched::futex::private_key(uaddr)
        .map(|key| (key, false))
        .ok_or(Errno::EFAULT.to_syscall_ret())
}

/// The key AND the value of the 4-aligned futex word at `uaddr`, from ONE look
/// (`azos_sched::futex::Look`; front futex-single-section): with `shared`, a
/// word of a shm region the caller's process maps is keyed as [`futex_word`]
/// keys it and read through the kernel's map of its frame, both from one
/// lookup with the region table held across the load
/// (`memobj_with_mapped_word`: the frame cannot go back to the PMM under the
/// load); any other word, and every word without `shared` (a Linux futex with
/// `FUTEX_PRIVATE_FLAG`), is the process's private key and a user read.
/// `None`: the word cannot be read.
///
/// One look, not a key and then a read: between two lookups another thread
/// may map another region at `uaddr`, and a waiter would then be filed under
/// the first region's key against the second region's value, where no waker
/// of the word it checked looks.
pub fn futex_look(uaddr: u64, shared: bool) -> Option<(azos_sched::futex::Key, u32)> {
    use azos_sched::futex::Key;
    if shared {
        let tid = azos_sched::current_proc_tid();
        let shm = azos_ipc::memobj::memobj_with_mapped_word(tid, uaddr as usize, false, |obj, off, w| {
            (Key::Shared { obj, offset: off as u32 }, w.load(Ordering::Acquire))
        });
        if shm.is_some() {
            return shm;
        }
    }
    let key = azos_sched::futex::private_key(uaddr)?;
    azos_sched::UserPtr::<u32>::new(uaddr).read().ok().map(|v| (key, v))
}

/// Run `f` on the shm futex word at `uaddr` (process `tid`'s mapping) while it
/// is still the word of `key`, the (region, offset) an earlier lookup gave
/// the operation's key: with the region table held across `f`, as
/// [`azos_ipc::memobj::memobj_with_mapped_word`] (and its `write` checks).
/// `None` when the mapping at `uaddr` now names another word, or none: a PI
/// step under its key's table hold reads and swaps that key's word or
/// nothing, never the word of a region mapped there since.
///
/// Canary `futex-key-outside-canary`: the identity is not checked.
pub fn with_keyed_shm_word<R>(
    tid: u32, uaddr: u64, key: (u32, usize), write: bool, f: impl FnOnce(&core::sync::atomic::AtomicU32) -> R,
) -> Option<R> {
    let any = cfg!(feature = "futex-key-outside-canary");
    azos_ipc::memobj::memobj_with_mapped_word(tid, uaddr as usize, write, |obj, off, w| {
        (any || (obj, off) == key).then(|| f(w))
    })
    .flatten()
}

/// One read of the futex word at `uaddr` through the caller's own mapping
/// before a wait takes the futex table (`azos_sched::futex::wait`): a word
/// that cannot be read is refused (`-EFAULT`) and one that does not hold
/// `expected` answered (`-EAGAIN`: it did not at a point of the call, all
/// `-EAGAIN` promises) with neither the table nor a look at the mappings,
/// and a word that matches is then at a resolved page for the look under the
/// lock, the look that decides. A shm word is read here through the user's
/// mapping as any other word: which word it is, is the look's to decide.
pub fn futex_precheck(uaddr: u64, expected: u32) -> Result<(), i64> {
    match azos_sched::UserPtr::<u32>::new(uaddr).read() {
        Err(_) => Err(Errno::EFAULT.to_syscall_ret()),
        Ok(v) if v != expected => Err(Errno::EAGAIN.to_syscall_ret()),
        Ok(_) => Ok(()),
    }
}

/// `SYS_FUTEX_WAIT`: `a0 = uaddr`, `a1 = expected`, `a2 = timeout_ns`
/// (0: none). `0` woken by a `SYS_FUTEX_WAKE` on the same word; `-EAGAIN` the
/// word did not hold `expected` (nothing blocked); `-ETIMEDOUT`; `-EINTR` a
/// stop, or the scheduler refused to block (preemption disabled);
/// `-EINVAL` misaligned; `-EFAULT` unreadable.
pub fn sys_futex_wait(uaddr: u64, expected: u64, timeout_ns: u64) -> i64 {
    if uaddr & 3 != 0 {
        return Errno::EINVAL.to_syscall_ret();
    }
    if let Err(e) = futex_precheck(uaddr, expected as u32) {
        return e;
    }
    let deadline = (timeout_ns != 0).then(|| {
        azos_drv_sys::timebase::now().saturating_add(azos_abi::time::ns_to_ticks_ceil(
            timeout_ns,
            azos_drv_sys::timebase::TIMER_FREQ,
        ))
    });
    // Canary `futex-key-outside-canary`: the key from a lookup before the
    // table's section (the shape before front futex-single-section), the
    // value from the look inside it.
    let early = if cfg!(feature = "futex-key-outside-canary") { futex_word(uaddr).ok().map(|w| w.0) } else { None };
    let look = || futex_look(uaddr, true).map(|(k, v)| (early.unwrap_or(k), v));
    azos_sched::futex::wait(&look, expected as u32, deadline)
}

/// `SYS_FUTEX_WAKE`: `a0 = uaddr`, `a1 = n`. Wakes up to `n` waiters on the
/// word and returns how many; `-EINVAL`/`-EFAULT` as [`sys_futex_wait`] (a
/// word nobody can read is no futex).
pub fn sys_futex_wake(uaddr: u64, n: u64) -> i64 {
    let (key, shm) = match futex_word(uaddr) {
        Ok(w) => w,
        Err(e) => return e,
    };
    if !shm && azos_sched::UserPtr::<u32>::new(uaddr).read().is_err() {
        return Errno::EFAULT.to_syscall_ret();
    }
    azos_sched::futex::wake_key(key, n.min(u32::MAX as u64) as u32)
}

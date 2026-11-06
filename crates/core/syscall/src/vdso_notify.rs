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

use azos_drv_base::sensors::board::{ENCODER, ODOM};

// ── Per-task vDSO page ──────────────────────────────────────────────────────

/// Harts whose previous-interrupt time is kept for the CPU-time charge: every
/// CPU the kernel is built for. A hart past this (a stray id) charges nothing
/// rather than indexing out of bounds. Gate canary `vdso-8cpu-canary`: eight,
/// so the tasks of every later CPU keep a `cpu_time` of 0.
const TICK_HARTS: usize = if cfg!(feature = "vdso-8cpu-canary") { 8 } else { azos_limits::NR_CPUS };
static LAST_TICK: [AtomicU64; TICK_HARTS] = [const { AtomicU64::new(0) }; TICK_HARTS];

/// The time since `hart`'s previous timer interrupt, which becomes the CPU time
/// of the task found running; 0 for the first interrupt of a hart and for a
/// clock that went back.
pub fn tick_interval(hart: usize, now: u64) -> u64 {
    let last = match LAST_TICK.get(hart) {
        Some(a) => a.swap(now, Ordering::Relaxed),
        None => now,
    };
    if last == 0 || now < last { 0 } else { now - last }
}

/// The sensor types the timer interrupt can sample: the two whose source is
/// a pair of lock-free atomics (`azos_robot::{encoder_read, odom_get}`).
/// Every other type is read over I2C/UART/CSI by its syscall and cannot be
/// read from an interrupt; its slot is never published.
fn isr_sampled(t: u32) -> bool {
    matches!(t, ENCODER | ODOM)
}

/// Fill `buf` with sensor type `t` in the `Sensor` interface's record format,
/// from interrupt context, with its acquisition time (vDSO-clock ns, the stamp
/// the interface reports for the same read: the encoder counters are
/// read here, so their stamp is this read; odometry carries `odom_task`'s).
/// `None` for a type [`isr_sampled`] refuses.
fn sample_isr(t: u32, buf: &mut [u8; azos_mm::vdso::VDSO_SENSOR_DATA_MAX]) -> Option<(usize, u64)> {
    let ((a, b), acq) = match t {
        ENCODER => azos_robot::encoder_read_stamped(),
        ODOM => azos_robot::odom_get_stamped(),
        _ => return None,
    };
    buf[0..8].copy_from_slice(&a.to_le_bytes());
    buf[8..16].copy_from_slice(&b.to_le_bytes());
    Some((16, azos_drv_sys::timebase::vdso_ns(acq)))
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
    let cpu_delta = tick_interval(f.hart, now);
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
    wake_word(azos_sched::futex::Key::Shared { obj: region, offset }, n).max(0) as u32
}

/// Wake up to `n` waiters on `key` (`azos_sched::futex::wake_key`), and, for
/// a word of a shm region, the port sources bound to it as a doorbell
/// (`PORT_SRC_DOORBELL`), after the futex table is released. Every futex wake
/// of a shared word that ring 3 or a kernel producer makes comes here.
pub fn wake_word(key: azos_sched::futex::Key, n: u32) -> i64 {
    let woken = azos_sched::futex::wake_key(key, n);
    ring_word(key);
    woken
}

/// The doorbell half of a wake of `key` made some other way (a requeue's
/// wake): the port sources bound to it, for a word of a shm region.
pub fn ring_word(key: azos_sched::futex::Key) {
    if let azos_sched::futex::Key::Shared { obj, offset } = key {
        azos_ipc::port::port_ring_doorbell(obj, offset);
    }
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
        let shm = azos_ipc::memobj::memobj_try_with_mapped_word(tid, uaddr as usize, false, |obj, off, w| {
            (Key::Shared { obj, offset: off as u32 }, w.load(Ordering::Acquire))
        });
        match shm {
            Ok(Some(l)) => return Some(l),
            Ok(None) => {}
            Err(_) => return None,
        }
    }
    let key = azos_sched::futex::private_key(uaddr)?;
    let word = azos_sched::UserPtr::<u32>::new(uaddr);
    // Canary `futex-look-faults-canary`: the look faults the page in under the
    // table lock.
    let v = if cfg!(feature = "futex-look-faults-canary") { word.read() } else { word.read_resident() };
    v.ok().map(|v| (key, v))
}

/// [`futex_look`] answered `None`: with no lock held, wait for the region
/// table and fault the page in. `false` when the word cannot be read at all
/// (`azos_sched::futex::Settle`).
pub fn futex_settle(uaddr: u64) -> bool {
    azos_ipc::memobj::memobj_wait_unlocked();
    azos_sched::futex::private_key(uaddr).is_some() && azos_sched::UserPtr::<u32>::new(uaddr).read().is_ok()
}

/// Run `f` on the shm futex word at `uaddr` (process `tid`'s mapping) while it
/// is still the word of `key`, the (region, offset) an earlier lookup gave
/// the operation's key: with the region table held across `f`, as
/// [`azos_ipc::memobj::memobj_with_mapped_word`] (and its `write` checks).
/// `None` when the mapping at `uaddr` now names another word, or none, or the
/// region table is busy ([`keyed_shm_word_settle`] tells them apart with no
/// lock held): a PI step under its key's table hold reads and swaps that key's
/// word or nothing, never the word of a region mapped there since.
///
/// Canary `futex-key-outside-canary`: the identity is not checked.
pub fn with_keyed_shm_word<R>(
    tid: u32, uaddr: u64, key: (u32, usize), write: bool, f: impl FnOnce(&core::sync::atomic::AtomicU32) -> R,
) -> Option<R> {
    let any = cfg!(feature = "futex-key-outside-canary");
    azos_ipc::memobj::memobj_try_with_mapped_word(tid, uaddr as usize, write, |obj, off, w| {
        (any || (obj, off) == key).then(|| f(w))
    })
    .ok()
    .flatten()
    .flatten()
}

/// A [`with_keyed_shm_word`] that answered `None` under the futex table, with
/// no lock held: can it succeed if tried again? `false` when the mapping at
/// `uaddr` names another word or none, or (for `write`) is not writable.
pub fn keyed_shm_word_settle(tid: u32, uaddr: u64, key: (u32, usize), write: bool) -> bool {
    let any = cfg!(feature = "futex-key-outside-canary");
    azos_ipc::memobj::memobj_with_mapped_word(tid, uaddr as usize, write, |obj, off, _| any || (obj, off) == key)
        == Some(true)
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
pub fn sys_futex_wait(uaddr: u64, a1: u64, timeout_ns: u64) -> i64 {
    use azos_abi::syscall_nr::{futex_op, FUTEX_OP_PI_LOCK, FUTEX_OP_PI_TRYLOCK};
    use azos_sync::pi_futex::PiCmd;
    if uaddr & 3 != 0 {
        return Errno::EINVAL.to_syscall_ret();
    }
    let (op, expected) = futex_op(a1);
    match op {
        0 => {}
        FUTEX_OP_PI_LOCK => return futex_pi(uaddr, true, PiCmd::Lock { deadline: deadline_after(timeout_ns) }),
        FUTEX_OP_PI_TRYLOCK => return futex_pi(uaddr, true, PiCmd::TryLock),
        _ => return Errno::EINVAL.to_syscall_ret(),
    }
    if let Err(e) = futex_precheck(uaddr, expected) {
        return e;
    }
    let deadline = deadline_after(timeout_ns);
    // Canary `futex-key-outside-canary`: the key from a lookup before the
    // table's section (the shape before front futex-single-section), the
    // value from the look inside it.
    let early = if cfg!(feature = "futex-key-outside-canary") { futex_word(uaddr).ok().map(|w| w.0) } else { None };
    let look = || futex_look(uaddr, true).map(|(k, v)| (early.unwrap_or(k), v));
    azos_sched::futex::wait(&look, &|| futex_settle(uaddr), expected, deadline)
}

/// The absolute deadline `timeout_ns` from now, in timer ticks (0: none).
fn deadline_after(timeout_ns: u64) -> Option<u64> {
    (timeout_ns != 0).then(|| {
        azos_drv_sys::timebase::now().saturating_add(azos_abi::time::ns_to_ticks_ceil(
            timeout_ns,
            azos_drv_sys::timebase::TIMER_FREQ,
        ))
    })
}

/// A priority-inheritance call on the PI word at `uaddr` (aligned): the
/// native `FUTEX_OP_PI_*` operations and the Linux personality's
/// `FUTEX_*_PI`. `shared`: a word of a shm region the caller maps is keyed
/// by the region (N10b), so two processes sharing it share one pi_state;
/// any other word by the process.
pub(crate) fn futex_pi(uaddr: u64, shared: bool, cmd: azos_sync::pi_futex::PiCmd) -> i64 {
    if shared && azos_sched::futex_table::SHARED {
        let tid = azos_sched::current_proc_tid();
        if let Some((region, off)) = azos_ipc::memobj::memobj_resolve_mapped(tid, uaddr as usize) {
            let key = azos_sched::futex::Key::Shared { obj: region, offset: off as u32 };
            return azos_sched::futex::pi_call_key(key, &ShmPiWord { tid, uaddr, key: (region, off) }, cmd);
        }
    }
    azos_sync::pi_futex::sys_futex_pi(uaddr, cmd)
}

/// A PI word of a shm region, resolved through the caller's process mapping
/// on every access (N10b): a relock after the sleep never trusts a page
/// taken before it, and an unmapped region answers `EFAULT`. Each access runs
/// with the region table held (`vdso_notify::with_keyed_shm_word`), so the
/// frame cannot change owner under it, and only while the mapping still names
/// the word of `key` (the region and offset the call is keyed by): a region
/// mapped at `uaddr` since answers `EFAULT`, so the PI state of one key never
/// reads or swaps another key's word. The swap also needs the mapping writable
/// now, a writable object and a page no clone shares, else `EFAULT`. Its only
/// fault-in is waiting for the region table: only the owner's `SYS_MO_MAP`
/// protect changes a shm mapping's access (no kernel path write-protects one
/// for a while), and a writable mapping has no clone-shared page (the map and
/// the protect break them).
pub(crate) struct ShmPiWord {
    pub(crate) tid: u32,
    pub(crate) uaddr: u64,
    /// `(region, offset)`: the word's identity when the call was keyed.
    pub(crate) key: (u32, usize),
}

impl azos_sched::futex::PiWord for ShmPiWord {
    fn read(&self) -> Result<u32, azos_sync::pi_futex::UserFault> {
        use core::sync::atomic::Ordering::Acquire;
        with_keyed_shm_word(self.tid, self.uaddr, self.key, false, |w| w.load(Acquire))
            .ok_or(azos_sync::pi_futex::UserFault)
    }
    fn cmpxchg(&self, expected: u32, new: u32) -> Result<u32, azos_sync::pi_futex::UserFault> {
        use core::sync::atomic::Ordering::{AcqRel, Acquire};
        with_keyed_shm_word(self.tid, self.uaddr, self.key, true, |w| {
            match w.compare_exchange(expected, new, AcqRel, Acquire) {
                Ok(v) | Err(v) => v,
            }
        })
        .ok_or(azos_sync::pi_futex::UserFault)
    }
    fn fault_in(&self) -> bool {
        keyed_shm_word_settle(self.tid, self.uaddr, self.key, true)
    }
}

/// `SYS_FUTEX_WAKE`: `a0 = uaddr`, `a1 = n`. Wakes up to `n` waiters on the
/// word and returns how many; `-EINVAL`/`-EFAULT` as [`sys_futex_wait`] (a
/// word nobody can read is no futex).
pub fn sys_futex_wake(uaddr: u64, a1: u64) -> i64 {
    use azos_abi::syscall_nr::{futex_op, FUTEX_OP_PI_UNLOCK};
    let (op, n) = futex_op(a1);
    match op {
        0 => {}
        FUTEX_OP_PI_UNLOCK if uaddr & 3 == 0 => return futex_pi(uaddr, true, azos_sync::pi_futex::PiCmd::Unlock),
        _ => return Errno::EINVAL.to_syscall_ret(),
    }
    let (key, shm) = match futex_word(uaddr) {
        Ok(w) => w,
        Err(e) => return e,
    };
    if !shm && azos_sched::UserPtr::<u32>::new(uaddr).read().is_err() {
        return Errno::EFAULT.to_syscall_ret();
    }
    wake_word(key, n)
}

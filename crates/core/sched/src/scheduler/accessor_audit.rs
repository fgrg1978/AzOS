// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! ktest only: the contract of the accessors of "the task running here".
//!
//! Every one of them reads the hart id and then a per-hart table; a tick
//! between the two moves the task to another hart and the second read
//! returns what the FIRST hart runs (found 2026-10-20: a kernel page fault
//! copying to a user VA). They all go through [`on_this_hart`], which masks
//! interrupts across the pair. This module counts, in a ktest build, how
//! often that window is opened by a task and how often it was open to
//! interrupts at the point between the two reads.
//!
//! Canary `percpu-accessor-race-canary` (cargo feature, gate only): the
//! window takes no mask, as before; the open count rises and
//! `percpu_accessors_read_masked` is `not ok`.

use super::*;

/// Windows opened by a task, per hart.
static WINDOWS: [AtomicU32; MAX_CPUS] = [const { AtomicU32::new(0) }; MAX_CPUS];
/// Windows that were open to interrupts between the id read and the table read.
static OPEN: AtomicU32 = AtomicU32::new(0);

/// Called by [`on_this_hart`] between the two reads. A window an interrupt
/// handler opens is masked by hardware and says nothing about the accessor.
pub(super) fn note(cpu: usize) {
    if cpu >= MAX_CPUS || azos_sync::isr_depth::in_isr(cpu) {
        return;
    }
    WINDOWS[cpu].fetch_add(1, Ordering::Relaxed);
    if azos_arch::ARCH.interrupts_enabled() {
        OPEN.fetch_add(1, Ordering::Relaxed);
    }
}

/// Run `f` and require that it opened at least one window on this hart and
/// that no window anywhere was open to interrupts. The caller holds
/// preemption off, so `cpu` is the hart for the whole call.
fn windowed<R>(f: impl FnOnce() -> R, no_window: &'static str, open: &'static str) -> Result<R, &'static str> {
    let cpu = current_cpu_id();
    let before = WINDOWS[cpu].load(Ordering::Relaxed);
    let r = f();
    if WINDOWS[cpu].load(Ordering::Relaxed) == before {
        return Err(no_window);
    }
    if OPEN.load(Ordering::Relaxed) != 0 {
        return Err(open);
    }
    Ok(r)
}

macro_rules! win {
    ($name:literal, $e:expr) => {
        windowed(
            || $e,
            concat!($name, " reads its slot without the masked window"),
            concat!($name, " reads the hart id and its slot with interrupts on"),
        )?
    };
}

/// The late runner (a kernel task) calls every accessor of the running task's slot
/// and its translation-word writer, and checks what each returns against the slot
/// the runner owns.
pub fn ktest_accessor_contracts() -> Result<(), &'static str> {
    // The runner stays on this hart, so the per-hart window count is its own.
    let _stay = azos_sync::preempt::critical_section();
    OPEN.store(0, Ordering::Relaxed);

    let Some((idx, tid)) = win!("current_task_slot", current_task_slot()) else {
        return Err("the late runner is not a task");
    };
    if tid == 0 || idx_for_tid(tid) != Some(idx) {
        return Err("current_task_slot names a slot that does not hold the caller's TID");
    }
    if win!("current_task_tid", current_task_tid()) != tid {
        return Err("current_task_tid is not the caller's TID");
    }
    if win!("current_slot", current_slot()) != Some(idx) {
        return Err("current_slot is not the caller's slot");
    }
    // A kernel task is its own process.
    if win!("current_proc_tid", current_proc_tid()) != tid {
        return Err("current_proc_tid is not the caller's process");
    }
    if win!("current_task_parent_tid", current_task_parent_tid()) != parent_of_tid(tid) {
        return Err("current_task_parent_tid is not the caller's parent");
    }
    let r0 = win!("current_runtime", current_runtime());
    let r1 = win!("current_runtime", current_runtime());
    if r1 < r0 {
        return Err("current_runtime went backwards");
    }
    // SAFETY: `idx` is the caller's own live slot.
    let (satp, user_pt, name0, prio, stack_top) = unsafe {
        let t = task_ref(idx);
        (t.task_satp, t.user_pt, t.name[0], t.base_priority.load(Ordering::Relaxed), task_stack_top(t.stack_idx))
    };
    let top = win!("current_task_stack_top", current_task_stack_top());
    let here_sp = core::ptr::addr_of!(r0) as usize;
    if top != stack_top || top < here_sp || top - here_sp > crate::task::STACK_SIZE {
        return Err("current_task_stack_top is not the top of the stack the caller runs on");
    }
    if win!("current_user_pt", current_user_pt()) != user_pt as usize {
        return Err("current_user_pt is not the caller's page table");
    }
    if win!("current_task_satp", current_task_satp()) != satp {
        return Err("current_task_satp is not the caller's translation word");
    }
    if name0 != 0 && win!("current_task_name", current_task_name()).as_bytes().first() != Some(&name0) {
        return Err("current_task_name is not the caller's name");
    }
    if win!("current_task_base_priority", current_task_base_priority()) != prio {
        return Err("current_task_base_priority is not the caller's");
    }
    let Some(f) = win!("current_task_vdso_facts", current_task_vdso_facts()) else {
        return Err("current_task_vdso_facts found no task");
    };
    if f.idx != idx || f.tid != tid || f.hart != current_cpu_id() {
        return Err("current_task_vdso_facts describes another task or hart");
    }
    let _ = win!("current_syscall_verdict", current_syscall_verdict(0));
    let _ = win!("current_iface_verdict", current_iface_verdict(0));
    let _ = win!("current_op_verdict", current_op_verdict(0, 0));

    // The writer of the translation word acts through the slot: rewriting the
    // caller's own value changes nothing it can see, and opens its window.
    // `set_current_user_info` is not called on the live runner (it draws new
    // PAC keys and resets the Domain's budget); the host test
    // `the_writers_act_through_a_slot_read_in_the_window` pins that it takes
    // its slot from `my_idx()` like the writer called here.
    win!("set_current_task_satp", set_current_task_satp(satp));
    // SAFETY: the runner's own live slot.
    if unsafe { task_ref(idx).task_satp } != satp {
        return Err("set_current_task_satp did not leave the runner's own value as it was");
    }
    Ok(())
}

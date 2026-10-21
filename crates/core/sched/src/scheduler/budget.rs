// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Task-state queries and the accounting kept beside them: the `current_task_*`
//! readers, the Domain accessors, the per-task frame budget and the
//! per-process row counters, the task census / task-list rows, and the syscall
//! filter accessors (AQ11). Child of `scheduler` (moved out of
//! `scheduler/mod.rs` unchanged). The accounting statics live here, with the
//! budget they count.

use super::*;

// ---- Query functions ----

/// Returns the name of the currently running task on this CPU.
pub fn current_task_name() -> &'static str {
    let idx = my_idx();
    unsafe {
        if idx == usize::MAX {
            return "<none>";
        }
        let task = &TASKS[idx];
        let len = task.name.iter().position(|&b| b == 0).unwrap_or(TASK_NAME_MAX_LEN);
        core::str::from_utf8(&task.name[..len]).unwrap_or("<?>")
    }
}

/// Returns the TID of the currently running task (0 if none).
/// `(voluntary, preempted)` context switches for the calling task.
///
/// Counted where the switch happens, so a `task_yield` that found nothing
/// better to run is not in either number. See `Task::switches_voluntary`.
pub fn current_task_switches() -> (u64, u64) {
    let idx = my_idx();
    unsafe {
        if idx == usize::MAX { return (0, 0); }
        (
            TASKS[idx].switches_voluntary.load(Ordering::Relaxed),
            TASKS[idx].switches_preempted.load(Ordering::Relaxed),
        )
    }
}

/// What the per-task vDSO page publishes about the task running on this
/// hart (`azos_mm::vdso::task_page_publish`, wave 6), read in one pass
/// from the same `PER_CPU[cpu].current_idx` cache as
/// [`current_task_switches`]: O(1), no TID scan. `None` when no task is
/// current. Called from the timer interrupt and from the page's own syscalls.
///
/// `ready_site` is `Task::ready_site`, the only record of why the task last
/// became runnable: `wait_reason` is reset on every dispatch, so which wait
/// the last wake satisfied is not kept anywhere.
#[derive(Clone, Copy)]
pub struct VdsoFacts {
    pub idx: usize,
    pub tid: u32,
    pub switches_voluntary: u64,
    pub switches_preempted: u64,
    pub ready_site: u8,
    pub hart: usize,
}

pub fn current_task_vdso_facts() -> Option<VdsoFacts> {
    let (cpu, idx) = here();
    unsafe {
        if idx == usize::MAX { return None; }
        let t = &TASKS[idx];
        Some(VdsoFacts {
            idx,
            tid: t.tid,
            switches_voluntary: t.switches_voluntary.load(Ordering::Relaxed),
            switches_preempted: t.switches_preempted.load(Ordering::Relaxed),
            ready_site: t.ready_site.load(Ordering::Relaxed),
            hart: cpu,
        })
    }
}

/// The hart the calling task is running on, for `DOMAIN_TASKINFO`.
///
/// A placement fact, not a scheduling promise: an unpinned task is placed when
/// it is created and again when it wakes from a block, and `do_schedule`
/// re-enqueues a task that only yields on the hart it yielded from. So for a
/// task that never blocks — the `switch-loaded` peers — this is the hart it
/// had for its whole life.
pub fn current_task_hart() -> usize {
    current_cpu_id()
}

/// Is `tid` the task RUNNING on a hart other than the caller's, right now?
///
/// The user-driver proxy's bounded spin (wave 9) asks this before each block:
/// spinning for a reply only pays when the driver is executing elsewhere at
/// that moment. A snapshot of `PER_CPU[..].current_idx`, unsynchronised — a
/// stale answer costs at most one bounded spin or one block, never a missed
/// reply, because the caller re-tests the reply either way.
pub fn task_running_on_other_hart(tid: u32) -> bool {
    let Some(idx) = idx_for_tid(tid) else { return false };
    let me = current_cpu_id();
    let online = NUM_ONLINE_CPUS.load(Ordering::Relaxed).clamp(1, MAX_CPUS);
    unsafe {
        (0..online).any(|cpu| cpu != me && PER_CPU[cpu].current_idx.load(Ordering::Relaxed) == idx)
    }
}

pub fn current_task_tid() -> u32 {
    let idx = my_idx();
    unsafe {
        if idx == usize::MAX { 0 } else { TASKS[idx].tid }
    }
}

/// The pool slot and TID of the task running on this CPU, or `None` when
/// none is current: [`current_task_tid`] plus the slot it read, so a caller
/// keyed by slot (the capability tables, N4) need not find it again with
/// [`idx_for_tid`].
#[inline]
pub fn current_task_slot() -> Option<(usize, u32)> {
    let idx = my_idx();
    unsafe {
        if idx < MAX_TASKS { Some((idx, TASKS[idx].tid)) } else { None }
    }
}

/// Base priority (no donation) of the task running on this CPU, or
/// `IDLE_PRIORITY` if none is current: the task's own class, which is what
/// the owner rule "an RT task never does block I/O" is about
/// (`RT_BLOCK_IO_CHECK`). Per CPU like [`current_task_tid`].
pub fn current_task_base_priority() -> u32 {
    let idx = my_idx();
    unsafe {
        if idx == usize::MAX {
            crate::task::IDLE_PRIORITY
        } else {
            TASKS[idx].base_priority.load(Ordering::Relaxed)
        }
    }
}

/// Parent TID of the task running on this CPU, or `0` if none is current (or
/// it has no recorded parent). Mirrors [`current_task_tid`] exactly: the same
/// `PER_CPU[cpu].current_idx` cache, O(1), no `idx_for_tid` scan — a scan is
/// what a caller on the fast-IPC CALL path cannot afford.
///
/// Parentage is [`PARENT_TID`], not a `Task` field — see that static's doc
/// comment for why (`Task` is layout-frozen against `TASK_SATP_OFFSET`,
/// which `task.rs` computes with `offset_of!` and feeds to
/// `context_switch.S` at the injection site — not a value hand-copied
/// into the assembly; `set_parent` is the writer, called from
/// `sys_fork_impl`).
pub fn current_task_parent_tid() -> u32 {
    let idx = my_idx();
    // Wave 13: a thread's parent is its process's (the leader's).
    if idx == usize::MAX { 0 } else { PARENT_TID[proc_slot(idx)].load(Ordering::Relaxed) }
}

/// Returns the clean (pre-prologue, ABI-aligned) stack top of the task running
/// on this CPU, or 0 if none.
///
/// Used by the I-13 transactional control-tick restart: on a
/// recoverable fault the trap handler resets SP to this known-good base before
/// re-entering the control task, rather than to a mid-function SP — so the
/// entry prologue runs exactly once per restart and the stack does not descend
/// one frame on every rollback.
pub fn current_task_stack_top() -> usize {
    let idx = my_idx();
    unsafe {
        if idx == usize::MAX {
            return 0;
        }
        task_stack_top(TASKS[idx].stack_idx)
    }
}

/// Returns total runtime ticks of the currently running task.
pub fn current_runtime() -> u64 {
    let idx = my_idx();
    unsafe {
        if idx == usize::MAX { 0 } else { TASKS[idx].total_runtime }
    }
}

/// Returns the user page-table physical address for the current task
/// (0 = kernel task / no user address space).
///
/// The slot is read by [`my_idx`], i.e. inside `scheduler::on_this_hart`'s
/// window (interrupts masked across the hart id and that hart's
/// `current_idx`): a task is preemptible anywhere in the kernel (a syscall
/// handler included) and may resume on another hart, and a tick between the
/// two steps would read the OLD hart's slot, so a ring-3 task could read `0`
/// (a kernel task's or an idle hart's) and a kernel task a user page table.
/// Every copy helper branches on this value, so the wrong answer is either a
/// refused copy for a legitimate user task or a raw store through a user VA
/// the hart's root does not map. The `cpuid-probe` gate row counts, inside the
/// window, any call that is no longer on the hart it read (`foreign`): the mask
/// is what keeps that at 0.
pub fn current_user_pt() -> usize {
    let idx = my_idx();
    unsafe {
        if idx == usize::MAX { 0 } else { TASKS[idx].user_pt as usize }
    }
}

/// The current task's translation root word (`satp` / TTBR0 with its ASID):
/// what a new member of its thread group runs on (wave 13).
pub fn current_task_satp() -> u64 {
    match current_slot() {
        Some(idx) => unsafe { TASKS[idx].task_satp },
        None => 0,
    }
}

/// The slot holding the per-process memory state (break, window
/// reservations, frame budget) of the task in slot `idx`: its thread group
/// leader's, or its own (wave 13). The leader's slot outlives every member.
#[inline]
pub(crate) fn proc_slot(idx: usize) -> usize {
    let l = crate::group::lead_of_idx(idx);
    if l == 0 {
        return idx;
    }
    idx_for_tid(l).unwrap_or(idx)
}

/// The domain of the task in slot `idx` (`crate::domain::NONE` for a slot
/// out of range or a task that has left it). What the capability store
/// resolves a TID's table through.
#[inline(always)]
pub fn task_domain(idx: usize) -> crate::domain::Key {
    if idx < MAX_TASKS {
        // SAFETY: only reads the task table, as `idx_for_tid` does.
        unsafe { TASKS[idx].domain() }
    } else {
        crate::domain::NONE
    }
}

/// Does live task `tid` share its domain with another task? Its capability
/// table is then the domain's, and its exit must not release it.
pub fn domain_shared(tid: u32) -> bool {
    idx_for_tid(tid).is_some_and(|idx| crate::domain::shared(task_domain(idx)))
}

/// Live-update swap (handover Level 1): task `tid` leaves its own domain for
/// the one task `of` belongs to, so it has `of`'s capability table (and frame
/// budget) from now on, handle for handle, with nothing moved.
///
/// The caller wipes `tid`'s own table first (`cap_store::reset`, while `tid`
/// is still alone in its domain) and must be sure `tid` takes no capability
/// call meanwhile (a successor still parked in `successor_task`). Pages
/// charged to `tid`'s old domain are charged to the new one best effort: a
/// refusal at the limit leaves them uncharged, and the budget's discharge
/// saturates. `false`, nothing changed, when either task is gone or `of`'s
/// domain is not live.
pub fn task_adopt_domain(tid: u32, of: u32) -> bool {
    let (Some(idx), Some(of_idx)) = (idx_for_tid(tid), idx_for_tid(of)) else { return false };
    let key = task_domain(of_idx);
    if idx == of_idx || !crate::domain::join(key) {
        return false;
    }
    // SAFETY: `idx` names a live task (`idx_for_tid`); the key is an atomic.
    let old = unsafe { TASKS[idx].domain.swap(key, Ordering::Relaxed) };
    let (used, _) = crate::domain::used_limit(old);
    if used != 0 {
        let _ = crate::domain::charge(key, used);
    }
    crate::domain::leave(old);
    true
}

/// The current task's process id: its thread group leader's TID, or its own
/// (wave 13). What owns its descriptors and keys its personality state.
///
/// `#[inline]` with `my_idx` (an `#[inline(always)]` masked window) spelled
/// out: it is the whole of `getpid`, the syscall-floor call, and a call to a
/// non-inline `current_slot` from another crate cost a call, a return and a
/// second bounds check (SYSFLOOR).
#[inline]
pub fn current_proc_tid() -> u32 {
    let idx = my_idx();
    if idx < MAX_TASKS {
        crate::group::proc_of(idx, unsafe { TASKS[idx].tid })
    } else {
        0
    }
}

// ── Owner decision 102 — per-task frame budget ────────────────────────────
//
// Scan unit 3 finding 3: CPU had quotas and
// memory had none. `sys_brk_impl` stops at `USER_LOW_MAX`, a VA ceiling, not a
// frame budget — and on the QEMU linker window that ceiling (32 MiB) is the
// whole arena. One ring-3 task could empty the page allocator, and then the
// kernel heap, the copy-on-write break and every allocating safety path fail
// with it.
//
// The budget is declared per task in the topology, beside the capabilities and
// the seccomp profile, and lands here through `set_current_user_page_limit`.

/// Charge `pages` frames to the current task.
///
/// Returns `false` and charges **nothing** when the task would go over its
/// budget — partial charges would leave the counter describing memory the
/// caller did not get. A limit of `0` means no limit, which is what every task
/// whose topology row does not declare one gets.
///
/// Kernel tasks (no current task) are never charged: they are the TCB, and a
/// budget on them would be a budget on the kernel.
pub fn mm_charge(pages: u32) -> bool {
    // Preserved from the inline original: a `pages == 0` charge never even
    // looks up the current task, let alone touches `MM_PEAK_GLOBAL`.
    // `PageBudget::charge` has the identical no-op internally, but that path
    // is unreachable here because of this early return, exactly as before.
    if pages == 0 { return true; }
    let idx = my_idx();
    unsafe {
        if idx == usize::MAX { return true; }
        // D2: the budget is the domain's, whichever of its threads charges.
        // `domain::charge` runs `PageBudget::charge`
        // (`crates/core/mm/src/budget.rs`), a compare-and-swap loop, so a
        // refusal is decided on what the domain holds now even when other
        // harts or other Domains (`mm_discharge_tid`) change it meanwhile: the add is
        // saturating (`overflow-checks = true` makes a plain `+` a board
        // reset), and a charge that would exceed a nonzero limit charges
        // NOTHING.
        if let Some(used) = crate::domain::charge(TASKS[idx].domain(), pages) {
            // And a mark that OUTLIVES the task.
            //
            // The per-task peak alone measured nothing: every ring-3 program
            // in this tree runs and exits, its slot goes invalid, and the
            // census dump three seconds later reported 0 for vsbench, abitest
            // and gpio_drv alike. Three very different programs answering
            // identically is the instrument, not the data — so the number
            // that sizes a budget has to survive the task that set it.
            MM_PEAK_GLOBAL.fetch_max(used, Ordering::Relaxed);
            true
        } else {
            MM_QUOTA_REFUSALS.fetch_add(1, Ordering::Relaxed);
            false
        }
    }
}

/// Give `pages` frames back. Saturating, so an over-discharge floors at 0
/// rather than wrapping to four billion and disabling the budget silently.
///
/// **Not optional bookkeeping.** Over-counting is the dangerous direction: it
/// refuses a task memory it is entitled to, and on this board that task may be
/// the one driving the motors. A `munmap` that forgot to discharge would
/// ratchet a long-lived task to a standstill.
pub fn mm_discharge(pages: u32) {
    if pages == 0 { return; }
    let idx = my_idx();
    unsafe {
        if idx == usize::MAX { return; }
        crate::domain::discharge(TASKS[idx].domain(), pages);
    }
}

/// Give `pages` frames back to the task `tid` from ANOTHER
/// task's context — the last holder of a shared-memory region `tid` created
/// freeing its frames, an io_ring torn down by someone else.
///
/// Applied at once (the budget is atomic). A `tid` that no longer exists needs
/// nothing (its budget went with its domain); TIDs are not reused before
/// `NEXT_TID` wraps at 2^32, so the discharge cannot reach a stranger.
pub fn mm_discharge_tid(tid: u32, pages: u32) {
    if pages == 0 { return; }
    unsafe {
        if let Some(idx) = idx_for_tid(tid) {
            crate::domain::discharge(TASKS[idx].domain(), pages);
        }
    }
}

/// Charge `pages` to the current task if it is `tid`, the
/// creator of the object being allocated. `true` (nothing charged) when the
/// creator is not the current task: a kernel caller allocating on a task's
/// behalf, whose frames the kernel reserve covers.
pub fn mm_charge_if_current(tid: u32, pages: u32) -> bool {
    if current_task_tid() != tid { return true; }
    mm_charge(pages)
}

/// The page-table hook `azos_mm::vmm` calls before (and,
/// on a failed allocation, after) it allocates a table under root `root`.
///
/// A table under the current task's OWN root is charged to it now, and a
/// refusal makes the mapping fail. A table under any other root belongs to an
/// address space this task is building for exec, spawn or fork: it is counted
/// in `mem.pt_build` and charged, with the rest of that address space, to the
/// task that receives it. No current task (boot, the kernel's own tables): not
/// charged.
fn table_hook(root: usize, charge: bool) -> bool {
    let idx = my_idx();
    unsafe {
        if idx >= MAX_TASKS { return true; }
        // Wave 13: a member's root is its group's; `mm_charge` charges the
        // leader.
        if TASKS[idx].user_pt as usize == root {
            // KMEM-CHARGE: a table the Domain's own mappings grow is a frame
            // (the frame budget, above) AND kernel memory kept for it (the
            // ledger's page-table class, bounded by the row's `kmem_kib`).
            // Either refusal fails the mapping; a frame charged before the
            // ledger refused goes back. The mapping paths may hold a spinlock,
            // so the ledger's refusal is recorded without the durable sink.
            let page = azos_arch_api::PAGE_SIZE as u64;
            let d = TASKS[idx].domain();
            if charge {
                if !mm_charge(1) { return false; }
                if !crate::domain::kmem_charge_atomic(d, crate::domain::KmemClass::PageTable, page) {
                    mm_discharge(1);
                    return false;
                }
                return true;
            }
            mm_discharge(1);
            crate::domain::kmem_discharge(d, crate::domain::KmemClass::PageTable, page);
            return true;
        }
        let b = &mut TASKS[idx].mem.pt_build;
        *b = if charge { b.saturating_add(1) } else { b.saturating_sub(1) };
        true
    }
}

/// The fault hook — one user page fault resolved (COW break or
/// demand fault) for the current task.
fn fault_hook() {
    let idx = my_idx();
    unsafe {
        if idx < MAX_TASKS {
            TASKS[idx].mem.faults = TASKS[idx].mem.faults.saturating_add(1);
        }
    }
}

/// Install [`table_hook`] and [`fault_hook`] into `azos_mm::vmm`. Once,
/// at boot, before the first user address space is built.
pub fn install_mm_hooks() {
    azos_mm::vmm::set_table_hook(table_hook);
    azos_mm::vmm::set_fault_hook(fault_hook);
}

/// Take (and zero) the page-table frames the current task allocated for an
/// address space that is not yet installed. See [`TaskMem::pt_build`].
pub fn take_current_pt_build() -> u32 {
    let idx = my_idx();
    unsafe {
        if idx >= MAX_TASKS { return 0; }
        core::mem::take(&mut TASKS[idx].mem.pt_build)
    }
}

/// The current task's `(limit, locked)`.
pub fn current_mem_policy() -> (u32, bool) {
    let idx = my_idx();
    unsafe {
        if idx >= MAX_TASKS { return (0, false); }
        let d = TASKS[idx].domain();
        (crate::domain::used_limit(d).1, crate::domain::mem_locked(d))
    }
}

/// Is the current task `mem = "locked"`?
pub fn current_mem_locked() -> bool {
    current_mem_policy().1
}

/// `(faults, peak, locked)` of the current task, for the exit report.
pub fn current_mem_report() -> (u32, u32, bool) {
    let idx = my_idx();
    unsafe {
        if idx >= MAX_TASKS { return (0, 0, false); }
        let d = TASKS[idx].domain();
        (TASKS[proc_slot(idx)].mem.faults, crate::domain::peak(d), crate::domain::mem_locked(d))
    }
}

/// Give the CURRENT task the budget `limit` and lock `locked`,
/// and charge it `frames` — what its freshly installed address space already
/// holds. Called by exec right after `set_current_user_info`. The caller has
/// already checked `frames` against `limit` (exec refuses an image that does
/// not fit), so this charge cannot be refused.
pub fn mm_install_frames(limit: u32, locked: bool, frames: u32) {
    let idx = my_idx();
    unsafe {
        if idx >= MAX_TASKS { return; }
        install_domain_mem(TASKS[idx].domain(), limit, locked, frames);
    }
}

/// Give the domain `d` the budget `limit` and lock `locked`, and charge it
/// `frames` (what its freshly built address space already holds).
fn install_domain_mem(d: crate::domain::Key, limit: u32, locked: bool, frames: u32) {
    crate::domain::set_limit(d, limit);
    crate::domain::set_mem_locked(d, locked);
    if let Some(used) = crate::domain::charge(d, frames) {
        MM_PEAK_GLOBAL.fetch_max(used, Ordering::Relaxed);
    }
}

/// KMEM-CHARGE: the kernel-memory limit (KiB, 0 = none) of the CURRENT task's
/// Domain.
pub fn current_kmem_kib() -> u32 {
    let idx = my_idx();
    unsafe {
        if idx >= MAX_TASKS { return 0; }
        crate::domain::kmem_limit_kib(TASKS[idx].domain())
    }
}

/// KMEM-CHARGE: declare the kernel-memory limit (KiB, 0 = none) of the
/// CURRENT task's Domain: an exec installing its row's `kmem_kib`.
pub fn set_current_kmem_kib(kib: u32) {
    let idx = my_idx();
    unsafe {
        if idx < MAX_TASKS { crate::domain::set_kmem_limit_kib(TASKS[idx].domain(), kib); }
    }
}

/// KMEM-CHARGE: [`set_current_kmem_kib`] for a task that is not running yet
/// (a spawned or forked child, by pool index, before it is released).
pub fn set_task_kmem_kib(idx: usize, kib: u32) {
    unsafe {
        if idx >= MAX_TASKS || !TASK_VALID[idx].load(Ordering::Relaxed) { return; }
        crate::domain::set_kmem_limit_kib(TASKS[idx].domain(), kib);
    }
}

/// The row's resource partition (`TaskSpec::partition_id`, `MemSpec::partition`)
/// for the Domain `d`: `0` declares nothing and leaves the Domain where it is
/// (a child Domain starts in its creator's partition, `domain::create_child`);
/// otherwise the Domain is put there, or in the default partition with a
/// console line when the hardware cannot tag it (`qos::fit`).
fn install_partition(d: crate::domain::Key, partition: u16) {
    use azos_arch::Cpu;
    if partition == 0 {
        return;
    }
    let max = azos_arch::ARCH.qos_max_partition();
    let fitted = crate::qos::fit(partition, max);
    if fitted != partition {
        azos_drv_sys::kwarn!(
            "[QOS] partition {} is above the {} this hart can tag: the Domain runs in partition 0",
            partition, max
        );
    }
    crate::domain::set_partition(d, fitted);
}

/// Declare the resource partition of the CURRENT task's Domain: an exec
/// installing its row's `partition_id`. The task keeps running on this hart,
/// so the hart's tag is brought up to date here, not at the next switch.
pub fn set_current_partition(partition: u16) {
    use azos_arch::Interrupts;
    if partition == 0 {
        return;
    }
    // Interrupts masked: the CPU id the tag is cached under must stay this
    // hart's from the read to the write.
    let saved = azos_arch::ARCH.disable_all();
    let cpu = current_cpu_id();
    unsafe {
        let idx = PER_CPU[cpu].current_idx.load(Ordering::Relaxed);
        if idx < MAX_TASKS {
            install_partition(TASKS[idx].domain(), partition);
            crate::asid::qos_switch_in(&TASKS[idx]);
        }
    }
    azos_arch::ARCH.restore(saved);
}

/// [`set_current_partition`] for a task that is not running yet (a spawned
/// child, by pool index, before it is released): its first switch-in tags it.
pub fn set_task_partition(idx: usize, partition: u16) {
    unsafe {
        if idx >= MAX_TASKS || !TASK_VALID[idx].load(Ordering::Relaxed) { return; }
        install_partition(TASKS[idx].domain(), partition);
    }
}

/// [`mm_install_frames`] for a task that is not running yet
/// (a spawned or forked child, by pool index, before it is released).
/// `false`, and nothing changed, if `frames` exceeds a nonzero `limit`.
pub fn set_task_mem(idx: usize, limit: u32, locked: bool, frames: u32) -> bool {
    if limit != 0 && frames > limit {
        MM_QUOTA_REFUSALS.fetch_add(1, Ordering::Relaxed);
        return false;
    }
    unsafe {
        if idx >= MAX_TASKS || !TASK_VALID[idx].load(Ordering::Relaxed) { return false; }
        install_domain_mem(TASKS[idx].domain(), limit, locked, frames);
    }
    true
}

/// Count one budget refusal that happened outside `mm_charge` (an exec whose
/// image does not fit its row's budget).
pub fn note_mm_quota_refusal() {
    MM_QUOTA_REFUSALS.fetch_add(1, Ordering::Relaxed);
}

// ── Wave 9: live instances per topology row ──────────────────────────────────
//
// A row declares `instances = N` (default 1) and memory admission counted N
// copies of its budget (plus one COW copy each when its image may fork). This
// count keeps the running system inside what was counted: at most N live
// spawned (or exec'd) instances of a row. Fork children are NOT instances
// (owner decision, wave 9): they are bounded by the memory budget, and the
// COW copy admission charges a forking row is what pays for them. A task
// holds at most one count (`TaskMem::row`) and gives it back at exit. Rows
// are identified by index + 1, as `TaskMem::row` stores them.
//
// A gate, not a statistic: every claim is a compare-exchange against the cap,
// so two harts cannot both take the last instance.

const ROW_SLOTS: usize = azos_limits::MAX_TASKS;

static ROW_LIVE: [AtomicU32; ROW_SLOTS] = [const { AtomicU32::new(0) }; ROW_SLOTS];
static MM_INSTANCE_REFUSALS: AtomicU32 = AtomicU32::new(0);

/// Take one live-instance count of `row` (index + 1) whose `instances` is
/// `cap`. `true` for row 0 (no row: nothing is counted). `false`, and
/// nothing taken, when `cap` instances are already live.
pub fn row_claim(row: u16, cap: u16) -> bool {
    let i = row as usize;
    if i == 0 || i > ROW_SLOTS {
        return true;
    }
    let live = &ROW_LIVE[i - 1];
    let mut cur = live.load(Ordering::Relaxed);
    loop {
        if cur >= cap as u32 {
            return false;
        }
        match live.compare_exchange_weak(cur, cur + 1, Ordering::AcqRel, Ordering::Relaxed) {
            Ok(_) => return true,
            Err(now) => cur = now,
        }
    }
}

/// Give back a count taken by [`row_claim`]. Saturates at 0.
pub fn row_release(row: u16) {
    let i = row as usize;
    if i == 0 || i > ROW_SLOTS {
        return;
    }
    let _ = ROW_LIVE[i - 1].fetch_update(Ordering::AcqRel, Ordering::Relaxed, |v| v.checked_sub(1));
}

/// Instances of `row` (index + 1) live now.
pub fn row_live(row: u16) -> u32 {
    let i = row as usize;
    if i == 0 || i > ROW_SLOTS {
        return 0;
    }
    ROW_LIVE[i - 1].load(Ordering::Relaxed)
}

/// The row whose count the current task holds ([`crate::task::TaskMem::row`]).
pub fn current_mem_row() -> u16 {
    let idx = my_idx();
    unsafe {
        if idx >= MAX_TASKS { return 0; }
        TASKS[idx].mem.row
    }
}

/// The row whose count the current task's process holds (its leader's
/// [`crate::task::TaskMem::row`]; a thread's own is 0). What an exec from
/// any thread compares its image's row with.
pub fn current_proc_mem_row() -> u16 {
    let idx = my_idx();
    unsafe {
        if idx >= MAX_TASKS { return 0; }
        TASKS[proc_slot(idx)].mem.row
    }
}

/// Record on the current task the count it now holds (exec, after the claim).
pub fn set_current_mem_row(row: u16) {
    let idx = my_idx();
    unsafe {
        if idx >= MAX_TASKS { return; }
        TASKS[idx].mem.row = row;
    }
}

/// Record on a task that is not running yet (a spawned child, by pool index,
/// before it is released) the count taken for it.
pub fn set_task_mem_row(idx: usize, row: u16) {
    unsafe {
        if idx >= MAX_TASKS || !TASK_VALID[idx].load(Ordering::Relaxed) { return; }
        TASKS[idx].mem.row = row;
    }
}

/// Count one refusal of a spawn or exec past its row's `instances`; returns
/// the count since boot, this one included.
pub fn note_mm_instance_refusal() -> u32 {
    MM_INSTANCE_REFUSALS.fetch_add(1, Ordering::Relaxed).saturating_add(1)
}

/// Refusals counted by [`note_mm_instance_refusal`] since boot.
pub fn mm_instance_refusals() -> u32 {
    MM_INSTANCE_REFUSALS.load(Ordering::Relaxed)
}


/// Forget the current task's frame count — the address space it described is
/// gone.
///
/// **Dead code as of this audit: zero callers anywhere in the tree**
/// (`grep -rn "mm_reset_charge(" crates kernel` finds only this
/// definition). The doc used to claim `exec_user` and the exit path both
/// called it; neither does. `owner decision 102` (see the comment on
/// the fresh domain a created task gets) covers the address-space
/// discard case a different way, which may be why nothing calls this —
/// left as a finding, not removed, since deleting a `pub fn` in a
/// scheduler this size is an owner call.
pub fn mm_reset_charge() {
    let idx = my_idx();
    unsafe {
        if idx != usize::MAX { crate::domain::reset_budget(TASKS[idx].domain()); }
    }
}

/// Charge `pages` to the budget of `tid`'s process, all or nothing, like
/// [`mm_charge`] for the current task. Wave 14 (DEMANDPAGE): a fork's child
/// is charged the uncommitted reservation it inherits, before it runs, under
/// the reserve-time model. `false` when `tid` is not live or
/// would go over its budget; nothing is charged then.
pub fn mm_charge_tid(tid: u32, pages: u32) -> bool {
    if pages == 0 { return true; }
    unsafe {
        let Some(idx) = idx_for_tid(tid) else { return false };
        if let Some(used) = crate::domain::charge(TASKS[idx].domain(), pages) {
            MM_PEAK_GLOBAL.fetch_max(used, Ordering::Relaxed);
            true
        } else {
            MM_QUOTA_REFUSALS.fetch_add(1, Ordering::Relaxed);
            false
        }
    }
}

/// Charge `pages` to the Domain `key` names, all or nothing, like
/// [`mm_charge`] for the current task: a MemObj (`azos_ipc::memobj`) charges
/// the Domain that holds its owning reference, whichever task makes the call.
/// `false`, nothing charged, when the Domain would go over its budget or the
/// key names none.
pub fn mm_charge_domain(key: crate::domain::Key, pages: u32) -> bool {
    if pages == 0 { return true; }
    if let Some(used) = crate::domain::charge(key, pages) {
        MM_PEAK_GLOBAL.fetch_max(used, Ordering::Relaxed);
        true
    } else {
        MM_QUOTA_REFUSALS.fetch_add(1, Ordering::Relaxed);
        false
    }
}

/// Give `pages` back to the Domain `key` names from any context, at once (the
/// budget is atomic). A key that names no live Domain needs nothing.
pub fn mm_discharge_domain(key: crate::domain::Key, pages: u32) {
    if pages != 0 {
        crate::domain::discharge(key, pages);
    }
}

/// Declare the current task's budget, in 4 KiB pages. `0` = no limit.
pub fn set_current_user_page_limit(limit: u32) {
    let idx = my_idx();
    unsafe {
        if idx != usize::MAX { crate::domain::set_limit(TASKS[idx].domain(), limit); }
    }
}

/// `(used, limit)` for the current task — diagnostics and the gate row.
#[must_use]
pub fn current_user_pages() -> (u32, u32) {
    let idx = my_idx();
    unsafe {
        if idx == usize::MAX { return (0, 0); }
        crate::domain::used_limit(TASKS[idx].domain())
    }
}

/// The largest frame count any task has EVER held, live or exited.
///
/// See the note in `mm_charge`: the per-task peak dies with the task, and
/// every ring-3 program here exits long before anything reads it.
static MM_PEAK_GLOBAL: AtomicU32 = AtomicU32::new(0);

/// See [`MM_PEAK_GLOBAL`].
#[must_use]
pub fn mm_peak_global() -> u32 {
    MM_PEAK_GLOBAL.load(Ordering::Relaxed)
}

/// The largest frame high-water mark any live task has reached, and its tid.
///
/// This is the number that sizes a budget. `autorun`'s 2048 pages was picked
/// with headroom because no peak had ever been measured — the owner chose to
/// implement before measuring — and this is what lets the guess be replaced by
/// evidence.
///
/// Reported as a maximum rather than per task on purpose: the `autorun`
/// topology row is shared by every ring-3 program in the tree, so the budget
/// has to clear the hungriest of them, and that is exactly the maximum.
///
/// Lock-free read of `TASKS`, like `top_runtime` above: a diagnostic that
/// takes a lock on the timer ISR's path would be a worse bug than the number
/// being one allocation stale.
#[must_use]
pub fn mm_peak_pages() -> (u32, u32) {
    let mut best_tid = 0u32;
    let mut best = 0u32;
    unsafe {
        for i in 0..MAX_TASKS {
            if !TASK_VALID[i].load(Ordering::Relaxed) { continue; }
            let t = task_ref(i);
            let peak = crate::domain::peak(t.domain());
            if peak > best {
                best = peak;
                best_tid = t.tid;
            }
        }
    }
    (best_tid, best)
}

/// How many allocations the budget has refused, over all tasks.
///
/// The gate asserts this is non-zero in the scenario that provokes it: a
/// quota that never refuses anything is indistinguishable from no quota, and
/// every functional test passes either way.
static MM_QUOTA_REFUSALS: AtomicU32 = AtomicU32::new(0);

/// See [`MM_QUOTA_REFUSALS`].
#[must_use]
pub fn mm_quota_refusals() -> u32 {
    MM_QUOTA_REFUSALS.load(Ordering::Relaxed)
}

/// Current priority of a task by TID, or `None` if no such task.
/// Diagnostic census of the task pool: `(ready, blocked, running)`, plus how
/// many `Ready` tasks sit on each CPU's queues.
///
/// **WHY this exists.** When a fast-IPC exchange wedges with the reply already
/// deposited in its slot, there are two very different explanations and the
/// logs cannot tell them apart: the client is `Blocked` and its wake was lost,
/// or the client is `Ready` and never gets picked. The second is starvation —
/// the residual K-C12 explicitly left open, since `find_best_cpu` is placement,
/// not an anti-starvation guarantee. One is a synchronisation bug, the other a
/// scheduling policy gap, and they need opposite fixes.
///
/// Unsynchronised on purpose: this is a diagnostic, it must not perturb the
/// race it is measuring, and an approximate count is enough to tell `Ready`
/// from `Blocked`.
/// Identify every task blocked on fast IPC: `(tid, is_client, payload,
/// state_word_raw, context_saving)`, where `payload` is the slot index for a
/// client and the server's own TID for a server. Returns how many were filled.
///
/// `state_word_raw` and `context_saving` are the two halves of the K-C24 wake
/// gate, read verbatim: bit 3 of the raw word is `WAKE_STAMP`, and a task
/// showing `Blocked` + `context_saving == true` for longer than a switch takes
/// is exactly the "wakes can only stamp, nobody sweeps" wedge this diagnostic
/// exists to catch — see `sched_word::wake_transition`'s `!saved` arm.
///
/// The other half of [`crate::scheduler::task_census`]'s story — see
/// `fastcall::slot_ids` for why the identities, not the counts, are what decide
/// between a lost wake and a coincidence.
pub fn blocked_fastipc_ids(out: &mut [(u32, bool, u32, u32, bool)]) -> usize {
    let mut n = 0usize;
    unsafe {
        for i in 0..MAX_TASKS {
            if n >= out.len() { break; }
            if !TASK_VALID[i].load(Ordering::Relaxed) { continue; }
            let t = task_ref(i);
            // Acquire: seeing Blocked must make the published wait_reason
            // visible (K-C17 pairing, now via the Release commit CAS).
            if t.state_acquire() != TaskState::Blocked { continue; }
            let word = t.state_word.load(Ordering::Acquire);
            let saving = t.context_saving.load(Ordering::Acquire);
            match t.wait_reason {
                // The low 6 bits of the handle are the caller's call record
                // (its task slot) by `ep_queue.rs`'s encoding, on a board of
                // at most 64 tasks — this diagnostic reports the seat;
                // duplicating the mask here is display-only and cannot
                // corrupt anything.
                WaitReason::FastIpcClient(handle) => {
                    out[n] = (t.tid, true, (handle & 0x3F) as u32, word, saving);
                    n += 1;
                }
                WaitReason::FastIpcServer(tid)  => {
                    out[n] = (t.tid, false, tid, word, saving);
                    n += 1;
                }
                _ => {}
            }
        }
    }
    n
}

/// One task, as [`task_rows`] reports it (the introspection tree's admin
/// task list).
#[derive(Clone, Copy)]
pub struct TaskRow {
    /// The task's TID.
    pub tid: u32,
    /// Its parent's TID, 0 for none.
    pub parent: u32,
    /// Its effective priority (0 most urgent).
    pub priority: u32,
    /// `R` ready or running, `S` blocked, `Z` exited and not yet freed.
    pub state: u8,
    /// Its name, NUL-padded (the first 16 bytes).
    pub name: [u8; 16],
}

/// Wave 12 (the introspection tree's admin task list, the user shell's `ps`): the live task slots, in
/// slot order, into `out`; how many were written. A racy snapshot read the
/// way [`task_census`] reads (no pool lock, atomics per field): a task that
/// is created or exits meanwhile may be missed or seen twice. Slots past
/// `out.len()` are not reported.
pub fn task_rows(out: &mut [TaskRow]) -> usize {
    let mut n = 0;
    for i in 0..MAX_TASKS {
        if n >= out.len() { break; }
        if let Some(r) = task_row_at(i) {
            out[n] = r;
            n += 1;
        }
    }
    n
}

/// One live task's row, as [`task_rows`] reports it; `None` when `tid` is
/// not live, without a snapshot of every row.
pub fn task_row(tid: u32) -> Option<TaskRow> {
    let r = task_row_at(idx_for_tid(tid)?)?;
    if r.tid == tid { Some(r) } else { None }
}

/// `(tid, voluntary, preempted)` context switches of the live task in slot
/// `i`; `None` for a free slot. Read without a lock, like [`task_rows`]; the
/// introspection tree's switch counters (`metrics/sched`) sum the growth of
/// each slot, so a task's counts need not outlive it.
pub fn task_switches_at(i: usize) -> Option<(u32, u64, u64)> {
    if i >= MAX_TASKS {
        return None;
    }
    unsafe {
        if !TASK_VALID[i].load(Ordering::Acquire) {
            return None;
        }
        let t = task_ref(i);
        Some((
            t.tid,
            t.switches_voluntary.load(Ordering::Relaxed),
            t.switches_preempted.load(Ordering::Relaxed),
        ))
    }
}

fn task_row_at(i: usize) -> Option<TaskRow> {
    unsafe {
        if !TASK_VALID[i].load(Ordering::Acquire) {
            return None;
        }
        let t = task_ref(i);
        let state = match t.state_acquire() {
            TaskState::Ready | TaskState::Running => b'R',
            TaskState::Blocked => b'S',
            TaskState::Zombie => b'Z',
            TaskState::Invalid => return None,
        };
        let mut name = [0u8; 16];
        let len = t.name.iter().position(|&b| b == 0).unwrap_or(t.name.len()).min(16);
        name[..len].copy_from_slice(&t.name[..len]);
        Some(TaskRow {
            tid: t.tid,
            // Wave 13: a thread's parent is its process's (the leader's).
            parent: PARENT_TID[proc_slot(i)].load(Ordering::Relaxed),
            priority: t.priority.load(Ordering::Relaxed),
            state,
            name,
        })
    }
}

pub fn task_census() -> (u32, u32, u32, [u32; MAX_CPUS], u32, u32, [u32; 5]) {
    let mut ready = 0u32;
    let mut blocked = 0u32;
    let mut running = 0u32;
    let mut per_cpu = [0u32; MAX_CPUS];
    // Two states that must never occur, and that are exactly the failure modes
    // the `Task::queued` invariant can produce if it ever gets out of step:
    //
    //  * `Ready` with `queued == false` — the task is runnable and sits in no
    //    queue at all. Nothing will ever pick it. Lost.
    //  * `Blocked` with `queued == true` — a stale claim. `cpu_enqueue` will
    //    answer `AlreadyQueued` to the next wake and silently drop it, leaving
    //    the task asleep on a condition that has already been satisfied.
    //
    // Both are counted rather than asserted: this runs from a diagnostic task,
    // and a panic here would reset the board over a reporting bug.
    let mut ready_unqueued = 0u32;
    let mut blocked_queued = 0u32;
    // [FastIpcClient, FastIpcServer, Timer, WaitQueue, otros]
    let mut by_reason = [0u32; 5];
    unsafe {
        for i in 0..MAX_TASKS {
            if !TASK_VALID[i].load(Ordering::Relaxed) { continue; }
            let t = task_ref(i);
            match t.state_acquire() {
                TaskState::Ready => {
                    ready += 1;
                    if !t.queued.load(Ordering::Acquire) { ready_unqueued += 1; }
                    let c = if t.cpu_affinity >= 0 {
                        (t.cpu_affinity as usize).min(ncpu() - 1)
                    } else {
                        (t.context.tp as usize).min(ncpu() - 1)
                    };
                    per_cpu[c] += 1;
                }
                TaskState::Blocked => {
                    blocked += 1;
                    if t.queued.load(Ordering::Acquire) { blocked_queued += 1; }
                    // Which wait is holding them matters more than the count:
                    // a client asleep on `FastIpcClient` with its reply already
                    // deposited is a lost wake; asleep on anything else means
                    // the model of the failure is wrong.
                    match t.wait_reason {
                        WaitReason::FastIpcClient(_) => by_reason[0] += 1,
                        WaitReason::FastIpcServer(_) => by_reason[1] += 1,
                        WaitReason::Timer(_)         => by_reason[2] += 1,
                        WaitReason::WaitQueue        => by_reason[3] += 1,
                        _                            => by_reason[4] += 1,
                    }
                }
                TaskState::Running => running += 1,
                _ => {}
            }
        }
    }
    (ready, blocked, running, per_cpu, ready_unqueued, blocked_queued, by_reason)
}

/// Diagnostic twin of [`task_census`]'s `ready_unqueued` counter: WHO is in
/// the impossible state, not just how many. Fills `(tid, priority, home_cpu,
/// name[0..8])` per victim; unsynchronised like the census, for the same
/// reason (must not perturb the race it measures).
pub fn ready_unqueued_ids(out: &mut [(u32, u32, u32, [u8; 8], u8)]) -> usize {
    let mut n = 0usize;
    unsafe {
        for i in 0..MAX_TASKS {
            if n >= out.len() { break; }
            if !TASK_VALID[i].load(Ordering::Relaxed) { continue; }
            let t = task_ref(i);
            if t.state() != TaskState::Ready { continue; }
            if t.queued.load(Ordering::Acquire) { continue; }
            let home = if t.cpu_affinity >= 0 {
                t.cpu_affinity as u32
            } else {
                t.context.tp as u32
            };
            let mut name = [0u8; 8];
            for (d, s) in name.iter_mut().zip(t.name.iter()) { *d = *s; }
            // K-C26: who published this task `Ready`, and on which hart.
            // With several simultaneous victims of different priority and home,
            // a shared site is the whole answer.
            out[n] = (t.tid, t.priority.load(Ordering::Relaxed), home, name,
                      t.ready_site.load(Ordering::Relaxed));
            n += 1;
        }
    }
    n
}

pub fn task_priority(tid: u32) -> Option<u32> {
    unsafe { idx_for_tid(tid).map(|i| task_mut(i).priority.load(Ordering::Relaxed)) }
}

/// The hart a task is pinned to (`-1` = any), or `None` if no such task.
pub fn task_cpu_affinity(tid: u32) -> Option<i8> {
    unsafe { idx_for_tid(tid).map(|i| task_ref(i).cpu_affinity) }
}

// ---- AQ11: Syscall filter accessor ----

/// What the dispatcher does with syscall `nr` from the current task, answered
/// on the task slot in place.
///
/// **This replaces a 132-byte copy per filtered syscall.** The dispatcher used
/// to ask [`current_syscall_filter_enabled`] and then [`current_syscall_filter`],
/// which returns the whole `SyscallFilter` (`{ enabled: bool, allowed: [u16; 64],
/// count: u8, audit: bool }`, 132 bytes) **by value** — a `memcpy` — and scanned
/// the copy. Once every shipped ring-3 binary ran under an image profile, that
/// copy sat on every ring-3 syscall. This reads `TASKS[idx].syscall_filter`
/// where it lies: the same fields, the same answer, no copy. The instruction
/// counts of both versions, from the release disassembly, are in the S3
/// follow-up note of 2026-09-14.
///
/// `num` is the full number from `a7`: `SyscallFilter::verdict_for` refuses one
/// past `u16::MAX` rather than narrowing it. A slot index past the pool (no
/// current task) is `Allow`, as the enabled check it replaces answered `false`
/// there.
#[inline]
pub fn current_syscall_verdict(num: u64) -> crate::filter::FilterVerdict {
    // SAFETY: `cpu` is this hart's id, read with interrupts masked
    // ([`on_this_hart`]): the word is the running task's own, not whatever a
    // hart the task has since left is running.
    let filter = on_this_hart(|cpu| unsafe { PER_CPU[cpu].current_filter.load(Ordering::Relaxed) });
    unsafe {
        // One load, because `set_current_task` already did this arithmetic at
        // the context switch that made this task current. Deriving the address
        // here instead cost a `MAX_TASKS` bounds check, the task stride (×1152 on riscv64)
        // and the `TASKS` base — 8 instructions on every syscall in the system,
        // to recompute a value that only changes when the running task does.
        if filter == 0 {
            // A Linux task's word is 0. `Linux` sends the call to
            // the personality's entry, which tells a Linux task from the
            // other 0-word cases (`zero_word_native_verdict`) out of line, so
            // the native path keeps its shape. Without `LINUX_ABI`, Allow as
            // before.
            return if azos_limits::LINUX_ABI {
                crate::filter::FilterVerdict::Linux
            } else {
                crate::filter::FilterVerdict::Allow
            };
        }
        (*(filter as *const SyscallFilter)).verdict_for(num)
    }
}

/// May the current task call the kernel-hosted endpoint with host key `key`
/// (`SyscallFilter::iface_verdict`)? Read on the published filter in place, as
/// [`current_syscall_verdict`]; a task with no filter word (a kernel task, or
/// a Linux task: the personality asks per native call) is `Allow`.
#[inline]
pub fn current_iface_verdict(key: u16) -> crate::filter::FilterVerdict {
    // SAFETY: as in [`current_syscall_verdict`].
    let filter = on_this_hart(|cpu| unsafe { PER_CPU[cpu].current_filter.load(Ordering::Relaxed) });
    unsafe {
        if filter == 0 {
            return crate::filter::FilterVerdict::Allow;
        }
        (*(filter as *const SyscallFilter)).iface_verdict(key)
    }
}

/// What the current task's filter says of an `invoke` on a handle of `kind`
/// with an op of class `class`: [`current_iface_verdict`]'s counterpart for the
/// op classes of `SYS_INVOKE`. A task with no filter word is `Allow`.
#[inline]
pub fn current_op_verdict(kind: u8, class: u8) -> crate::filter::FilterVerdict {
    // SAFETY: as in [`current_syscall_verdict`].
    let filter = on_this_hart(|cpu| unsafe { PER_CPU[cpu].current_filter.load(Ordering::Relaxed) });
    unsafe {
        if filter == 0 {
            return crate::filter::FilterVerdict::Allow;
        }
        (*(filter as *const SyscallFilter)).op_verdict(kind, class)
    }
}

/// [`current_iface_verdict`] for task `tid` (the ring's owner, which need not
/// be the task running): `None` when the task is gone.
pub fn task_iface_verdict(tid: u32, key: u16) -> Option<crate::filter::FilterVerdict> {
    let idx = idx_for_tid(tid)?;
    // SAFETY: `idx` is a valid slot index from `idx_for_tid`; the copy is
    // validated by the re-check below before it is used.
    let filter = unsafe { TASKS[idx].syscall_filter };
    core::sync::atomic::fence(Ordering::Acquire);
    if tid_for_idx(idx) != Some(tid) {
        return None;
    }
    Some(filter.iface_verdict(key))
}

/// [`current_op_verdict`] for task `tid` (the ring's owner, which need not be
/// the task running): `None` when the task is gone.
pub fn task_op_verdict(tid: u32, kind: u8, class: u8) -> Option<crate::filter::FilterVerdict> {
    let idx = idx_for_tid(tid)?;
    // SAFETY: `idx` is a valid slot index from `idx_for_tid`; the copy is
    // validated by the re-check below before it is used.
    let filter = unsafe { TASKS[idx].syscall_filter };
    core::sync::atomic::fence(Ordering::Acquire);
    if tid_for_idx(idx) != Some(tid) {
        return None;
    }
    Some(filter.op_verdict(kind, class))
}

/// For a call whose filter word was 0: `None` when the current
/// task is a Linux task; else the verdict the native path gives it: the
/// slot's own filter for a native task whose word was not published (never
/// expected; answered correctly all the same), `Allow` when no task is
/// current, as before.
pub fn zero_word_native_verdict(num: u64) -> Option<crate::filter::FilterVerdict> {
    let Some(idx) = current_slot() else { return Some(crate::filter::FilterVerdict::Allow) };
    if slot_is_linux(idx) {
        return None;
    }
    // SAFETY: the current task's own slot; its filter is read in place, as
    // the native path reads it through the word.
    Some(unsafe { (*core::ptr::addr_of!(TASKS[idx].syscall_filter)).verdict_for(num) })
}

/// The verdict the current task's filter gives NATIVE call `num`, whatever
/// its ABI: what the Linux personality asks for each native call a Linux
/// call reaches ("seccomp after translation"). Never answers
/// [`crate::filter::FilterVerdict::Linux`].
pub fn current_native_verdict(num: u64) -> crate::filter::FilterVerdict {
    let Some(idx) = current_slot() else { return crate::filter::FilterVerdict::Allow };
    // SAFETY: the current task's own slot, its filter read in place.
    unsafe { (*core::ptr::addr_of!(TASKS[idx].syscall_filter)).verdict_for(num) }
}

/// Is the task in slot `idx` a Linux task? For the per-switch
/// state (`crate::fp`), with `idx < MAX_TASKS`.
pub(crate) fn slot_is_linux(idx: usize) -> bool {
    // SAFETY: a byte of a slot, written only at slot creation under
    // POOL_LOCK; a stale read names a task that is not switching here.
    !cfg!(feature = "linux-abi-tag-canary") && unsafe { TASKS[idx].abi } == crate::task::ABI_LINUX
}

/// Is the current task a Linux task?
pub fn current_is_linux() -> bool {
    azos_limits::LINUX_ABI && current_slot().is_some_and(slot_is_linux)
}

/// Does the task in slot `idx` carry a foreign ABI's per-thread CPU state
/// (the riscv64 F/D file, the aarch64 thread pointer)? A
/// Linux task of the in-kernel personality does, and so does a task hosted
/// by a ring-3 runtime (`task::ABI_HOSTED`), whichever mode it is in.
pub(crate) fn slot_is_foreign(idx: usize) -> bool {
    // SAFETY: as `slot_is_linux`.
    !cfg!(feature = "linux-abi-tag-canary") && unsafe { TASKS[idx].abi } != crate::task::ABI_NATIVE
}

/// Is the current task foreign in that sense (see [`slot_is_foreign`])?
pub fn current_is_foreign() -> bool {
    azos_limits::LINUX_ABI && current_slot().is_some_and(slot_is_foreign)
}

/// The current task's `abi` (`task::ABI_*`), for a child it creates to
/// inherit.
pub(crate) fn current_abi() -> u8 {
    match current_slot() {
        // SAFETY: as `slot_is_linux`.
        Some(idx) if azos_limits::LINUX_ABI => unsafe { TASKS[idx].abi },
        _ => crate::task::ABI_NATIVE,
    }
}


/// The verdict task `tid`'s own filter gives syscall `num`, read from its
/// slot; `None` when `tid` names no live task.
///
/// For a kernel context acting on a task's behalf — the io_ring SQ poller runs
/// the ring owner's entries, and each must be decided by the OWNER's profile,
/// not the poller's (`crates/core/syscall/src/ioring_ops.rs`). The filter is copied
/// out and the slot re-checked to still carry `tid` afterwards, so a slot
/// freed and reused mid-read answers `None` rather than another task's row.
/// `sys_exec` rewrites a task's filter in place; a verdict read here is the
/// filter in force at the read, as `current_syscall_verdict` is for a trap.
pub fn task_syscall_verdict(tid: u32, num: u64) -> Option<crate::filter::FilterVerdict> {
    let idx = idx_for_tid(tid)?;
    // SAFETY: `idx` is a valid slot index from `idx_for_tid`; the copy is
    // validated by the re-check below before it is used.
    let filter = unsafe { TASKS[idx].syscall_filter };
    core::sync::atomic::fence(Ordering::Acquire);
    if tid_for_idx(idx) != Some(tid) {
        return None;
    }
    Some(filter.verdict_for(num))
}

/// Does the current task have a syscall filter installed? One `bool` read on
/// the slot, for callers that need no more than that. The dispatcher asks
/// [`current_syscall_verdict`] instead.
pub fn current_syscall_filter_enabled() -> bool {
    let idx = my_idx();
    unsafe {
        if idx >= MAX_TASKS { return false; }
        TASKS[idx].syscall_filter.enabled
    }
}

pub fn current_syscall_filter() -> SyscallFilter {
    let idx = my_idx();
    unsafe {
        if idx == usize::MAX { return SyscallFilter::disabled(); }
        TASKS[idx].syscall_filter
    }
}

/// Set the syscall filter for the current task.
pub fn set_current_syscall_filter(filter: SyscallFilter) {
    let idx = my_idx();
    unsafe {
        if idx != usize::MAX {
            TASKS[idx].syscall_filter = filter;
        }
    }
}

/// Set the syscall filter for a specific task by pool index (fork inheritance).
pub fn set_task_syscall_filter(idx: usize, filter: SyscallFilter) {
    unsafe {
        if idx < MAX_TASKS && TASK_VALID[idx].load(Ordering::Relaxed) {
            TASKS[idx].syscall_filter = filter;
        }
    }
}

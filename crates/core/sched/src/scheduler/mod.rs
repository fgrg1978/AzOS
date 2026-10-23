// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
/// Scheduler for AzOS — Priority-based with RT support and hart affinity.
///
/// Design:
/// - Global task pool: `TASKS[MAX_TASKS]` protected by `POOL_LOCK`
/// - Per-CPU multi-level priority queues: 32 FIFOs + bitmap for O(1) dequeue
/// - Hard real-time: priorities 0..RT_PRIORITY_THRESHOLD are never preempted by timer
/// - Hart affinity: tasks can be pinned to a specific CPU
/// - Task assignment: at creation time (unless pinned) to the CPU where a
///   task of that priority will actually be dispatched — see `find_best_cpu`
/// - Context switch: saves/restores callee-saved registers only (ra, sp, s0-s11, pc)
///
/// Invariants:
/// - `do_schedule()` is always called with interrupts disabled on the calling CPU
///   (either explicitly, or because it runs inside a trap handler where hardware
///   already disabled them)
/// - Cross-CPU ready-queue access is expected and routine — task creation
///   (priority-aware placement / explicit affinity), task wake-up
///   (`try_wake_task`, `wq_wake_by_tid`) and even `do_schedule()`'s own
///   same-CPU re-enqueue race the same target queue from other harts. Every
///   ready-queue read/write goes through `cpu_dequeue_locked` /
///   `cpu_enqueue_locked`, which take `CPU_LOCKS[cpu]` (the queue-owning
///   CPU's lock, IRQ-safe) for the duration of the single operation — never
///   held across `context_switch()`, including `boost_ready_task`/
///   `restore_ready_task` — they used to bypass `CPU_LOCKS` entirely (a
///   real, since-fixed bug; see `cpu_remove_anywhere`'s doc), but now go
///   through the same locked search as everything else. They still skip
///   `POOL_LOCK`, which is fine: they only touch a slot's `priority` and
///   ready-queue membership, not `TASKS[]`/`TASK_VALID[]` allocation
///   (`task.rs`'s doc on the field has the detail).
/// - `POOL_LOCK` protects `TASKS[]`, `TASK_VALID[]`, `NEXT_TID` during task creation
/// - `rebalance_from_offline_cpus` is boot-only (see its doc comment for the
///   exact window): it still goes through the same locked wrappers as
///   everything else above, it just runs before any task has been dispatched.

use core::sync::atomic::{AtomicBool, AtomicU16, AtomicU32, AtomicU64, AtomicUsize, Ordering};
// The cross-ISA interrupt contract. In scope for the method calls on
// `azos_arch::ARCH`, which replaced 37 hand-written reads and writes of
// `sstatus.SIE` in this file on 2026-09-21 — see `crates/core/arch-api`.
use azos_arch::Interrupts;
use crate::task::{
    Task, TaskContext, TaskState, CtxReg, MAX_TASKS, STACK_SIZE,
    NUM_PRIORITIES, is_rt_priority,
    WaitReason, SyscallFilter, TaskInit, TASK_NAME_CAPACITY,
    CpuLoad, EnqueueOutcome, enqueue_decision, pick_cpu_by_load,
};
use crate::smp::{current_cpu_id, NUM_ONLINE_CPUS};
use crate::topo::{self, Claim, CorePick, Level};
use wcet_macro::wcet;

/// Compile-time ceiling on CPUs, and the size of every per-CPU array here.
///
/// **8, not 4, and it must not drop below `MAX_HARTS`.** The kernel declares
/// `MAX_HARTS = 8` and injects it into `boot.S`, which range-checks SECONDARY
/// harts against it and parks anything higher. Nothing checked the BOOT hart
/// at all — it is whoever wins `boot_lock` — and `PER_CPU` is indexed by
/// `current_cpu_id()` with no clamp. So on the VF2, whose harts are S7 as 0
/// and four U74s as 1..4, a boot hart of 4 indexed a four-entry array out of
/// bounds: under `panic = "abort"` that is a board reset at boot, and a
/// nondeterministic one, since it depends on which hart wins the lock.
///
/// The second cost was quieter. `kernel_main` clamps the DTB's CPU count with
/// `min(MAX_CPUS, info.num_cpus)`, so 4 also meant *parking working cores*:
/// one U74 on the VF2, and four of the eight X60s the K1's `platform.rs`
/// declares.
///
/// Measured before raising it: `PerCpuSched` is ~16.8 KiB (32 priority queues
/// of `[AtomicUsize; MAX_TASKS]`), so four more CPUs cost about 67 KiB —
/// 0.05 % of the 128 MiB the kernel assumes when the DTB tells it nothing.
///
/// The mirrored assert below is what keeps the two in step; `crates/core/sched`
/// cannot see the kernel's constant, which is why it is asserted there rather
/// than derived here.
pub const MAX_CPUS: usize = azos_percpu::NR_CPUS;

// The narrow places a CPU id is stored, each the reason the Kconfig `NR_CPUS`
// range stops where it does: `Task::cpu_affinity` is an `i8` (-1 = any), the
// online-prefix bookkeeping is one `u64` (`hart_set`), and the resident
// histogram packs a CPU under `CPU_MASK` (asserted in its own file).
const _: () = assert!(MAX_CPUS <= i8::MAX as usize + 1, "cpu_affinity is an i8");
const _: () = assert!(MAX_CPUS <= crate::smp::hart_set::HART_MASK_BITS, "hart_set's liveness mask is a u64");

/// One past the highest CPU this boot can run (`azos_percpu::nr_cpu_ids`, the
/// DTB's count cut to `MAX_CPUS`). The bound of every walk over CPUs and of
/// every clamp of a CPU id: a CPU at or past it has no per-CPU area, so no
/// ready queue, and its slots in the `MAX_CPUS`-long static tables are never
/// used. Possible CPUs are exactly `0..ncpu()` (`boot::discover_cpus`).
#[inline(always)]
pub(crate) fn ncpu() -> usize {
    azos_percpu::nr_cpu_ids()
}

/// Pure O(`NUM_PRIORITIES`) resident-placement histogram (U02-3, task
/// 3a), in its own file only so the host test runner
/// (`tests/host/sched-wake-tests`) can compile it — the rest of this module
/// cannot leave the target. Same pattern as `exit_note` / `tid_alloc` /
/// `process::elf_bounds` / `smp::hart_set`.
#[path = "../resident_histogram.rs"]
pub mod resident_histogram;

/// Eligibility rule for the fast-IPC same-hart direct switch
/// ([`ipc_wake_then_block`]), in its own file so the host test runner
/// (`tests/host/sched-wake-tests`) can compile and test it.
#[path = "../ipc_direct.rs"]
pub mod ipc_direct;

/// Wave 11 SCHED-RT: the per-hart RT-band budget and EDF + CBS on this
/// dispatch path. A child module so it reaches the
/// ready queues without widening their visibility.
#[path = "../rt.rs"]
pub mod rt;

/// N6: the five dispatch classes (stop > DL > RT > fair > idle) and the
/// per-task scheduling context, over the queues above (`sc.rs` is the model).
#[path = "../classes.rs"]
pub mod classes;

/// The fair class's run queue: EEVDF (`eevdf_core.rs` is the model) over the
/// fair levels' ready lists.
#[path = "../fairq.rs"]
pub mod fairq;

/// Load balancing of the fair class between CPUs (`SCHED_BALANCE`): the
/// policy, pure and host-tested. `fairq.rs` is its queue side.
mod balance;

/// E1/E2 (kernel feature `energy`): utilisation signals updated on
/// this dispatch path, and the energy model installed at boot.
#[cfg(feature = "energy")]
#[path = "../energy.rs"]
pub mod energy;

const _: () = assert!(
    ipc_direct::BITMAP_BUCKETS == crate::task::NUM_PRIORITIES,
    "ipc_direct::BITMAP_BUCKETS drifted from task::NUM_PRIORITIES",
);

// `resident_histogram.rs` cannot name `scheduler::MAX_CPUS` (it is
// pulled into a host crate that never compiles this file) and keeps its
// own copy instead — this ties the two so a change to one without the
// other is a build error here, not a silently wrong array size there.
const _: () = assert!(
    resident_histogram::MAX_CPUS == MAX_CPUS,
    "resident_histogram::MAX_CPUS drifted from scheduler::MAX_CPUS",
);

/// U02-3 task 3a: the one real instance `find_best_cpu` consults instead of
/// scanning `MAX_TASKS` when `sched-o1-placement` is on. Lock-free (relaxed
/// atomics) by design — see `resident_histogram`'s module doc.
#[cfg(feature = "sched-o1-placement")]
static RESIDENT_HIST: resident_histogram::ResidentHistogram =
    resident_histogram::ResidentHistogram::new();

/// What each pool slot is currently accounted as in `RESIDENT_HIST`
/// (`resident_histogram::key`). `NONE` (zero) for a free slot or a Zombie.
/// Swapped, never stored, so every key value is credited once and debited
/// once whatever the interleaving (see the module doc).
#[cfg(feature = "sched-o1-placement")]
static HIST_KEY: [AtomicU32; MAX_TASKS] = [const { AtomicU32::new(0) }; MAX_TASKS];

/// A resident's home CPU, the rule `find_best_cpu_scan` uses: `cpu_affinity`
/// when pinned, else the saved `context.tp` (the CPU whose queue every wake
/// path keeps it on — not where it is executing right now).
#[cfg(feature = "sched-o1-placement")]
#[inline]
fn resident_home(task: &Task) -> usize {
    if task.cpu_affinity >= 0 {
        (task.cpu_affinity as usize).min(ncpu() - 1)
    } else {
        (task.context.tp as usize).min(ncpu() - 1)
    }
}

/// The key slot `idx`'s live fields say it should be accounted as — the
/// same filter `find_best_cpu_scan` applies (`TASK_VALID`, not `Zombie`).
#[cfg(feature = "sched-o1-placement")]
#[inline]
unsafe fn hist_key_of(idx: usize) -> u32 {
    if !TASK_VALID[idx].load(Ordering::Relaxed) {
        return resident_histogram::key::NONE;
    }
    let t = &TASKS[idx];
    let state = t.state();
    if state == TaskState::Zombie {
        return resident_histogram::key::NONE;
    }
    resident_histogram::key::pack(
        resident_home(t),
        prio_bucket(t.priority.load(Ordering::Relaxed)),
        crate::task::resident_competes(state),
    )
}

/// Re-account slot `idx` after a write to any field its placement score
/// depends on (`state_word`, `priority`, `cpu_affinity`, `context.tp`,
/// `TASK_VALID`). The caller does not describe the transition; the delta is
/// from whatever the slot was last accounted as. A field another hart
/// changes between our read and our swap leaves a stale key until that
/// slot's next re-account corrects it (no re-read loop: it cost ~20
/// instructions on every block and wake, measured on vsbench ipc-roundtrip).
/// A compare-exchange with an install count in the recorded word closes
/// that window, but measured +42/+62 instructions on ipc-roundtrip
/// (aarch64/riscv64) and did not change the `ipc-census` drift audit's
/// count, so it is not applied.
#[cfg(feature = "sched-o1-placement")]
#[inline]
unsafe fn hist_reaccount(idx: usize) {
    if idx >= MAX_TASKS {
        return;
    }
    let new = hist_key_of(idx);
    let old = HIST_KEY[idx].swap(new, Ordering::Relaxed);
    RESIDENT_HIST.apply(old, new);
}

/// [`hist_reaccount`] for two slots whose changes may cancel: the fast-IPC
/// direct switch, where the waker goes `Running` -> `Blocked` and the woken
/// task `Blocked` -> `Running` on the same hart. Both keys are swapped as two
/// separate re-accounts would swap them; the histogram itself is touched only
/// when the swapped-out pair is not the swapped-in pair in some order — when
/// it is, the two `apply` deltas sum to zero and are skipped. Exact, not an
/// approximation: the histogram stays the sum of the recorded keys.
///
/// Inline, with the full re-account out of line (`hist_reaccount_pair_full`):
/// the usual case is a few loads and two compare-exchanges, and called out
/// of line it cost the IPC fast path's hand-off a call and its register
/// saves on every switch.
#[cfg_attr(not(feature = "sched-ipc-affinity"), allow(dead_code))]
#[cfg(feature = "sched-o1-placement")]
#[inline(always)]
unsafe fn hist_reaccount_pair(a: usize, b: usize) {
    if a >= MAX_TASKS || b >= MAX_TASKS {
        return;
    }
    // Chain E, commit 3: the hand-off's usual case, from the recorded keys
    // alone (`ipc_direct::handoff_swaps`): store them crosswise, with no
    // `hist_key_of` and no histogram write. Compare-exchange, not stores: a
    // re-account of either slot from another hart in between makes the CAS
    // fail and the full path below run. If only `b`'s fails, `a`'s new key
    // is applied on its own and `b` is re-accounted from scratch.
    let (oa, ob) = (HIST_KEY[a].load(Ordering::Relaxed), HIST_KEY[b].load(Ordering::Relaxed));
    if ipc_direct::handoff_swaps(oa, ob)
        && HIST_KEY[a].compare_exchange(oa, ob, Ordering::Relaxed, Ordering::Relaxed).is_ok()
    {
        if HIST_KEY[b].compare_exchange(ob, oa, Ordering::Relaxed, Ordering::Relaxed).is_err() {
            // SAFETY: `b < MAX_TASKS`, checked above.
            unsafe { hist_pair_b_moved(oa, ob, b) };
        }
        return;
    }
    // SAFETY: both checked above.
    unsafe { hist_reaccount_pair_full(a, b) };
}

/// [`hist_reaccount_pair`]'s crosswise store landed for `a` but `b` was
/// re-accounted meanwhile: apply `a`'s new key alone, re-account `b`.
#[cfg_attr(not(feature = "sched-ipc-affinity"), allow(dead_code))]
#[cfg(feature = "sched-o1-placement")]
#[inline(never)]
unsafe fn hist_pair_b_moved(oa: u32, ob: u32, b: usize) {
    RESIDENT_HIST.apply(oa, ob);
    hist_reaccount(b);
}

/// [`hist_reaccount_pair`] when the keys are not the hand-off's swap: both
/// re-accounted, the histogram touched unless the two deltas cancel.
#[cfg_attr(not(feature = "sched-ipc-affinity"), allow(dead_code))]
#[cfg(feature = "sched-o1-placement")]
#[inline(never)]
unsafe fn hist_reaccount_pair_full(a: usize, b: usize) {
    let (na, nb) = (hist_key_of(a), hist_key_of(b));
    let oa = HIST_KEY[a].swap(na, Ordering::Relaxed);
    let ob = HIST_KEY[b].swap(nb, Ordering::Relaxed);
    if ipc_direct::pair_cancels(oa, ob, na, nb) {
        return;
    }
    RESIDENT_HIST.apply(oa, na);
    RESIDENT_HIST.apply(ob, nb);
}

#[cfg_attr(not(feature = "sched-ipc-affinity"), allow(dead_code))]
#[cfg(not(feature = "sched-o1-placement"))]
#[inline(always)]
unsafe fn hist_reaccount_pair(_a: usize, _b: usize) {}

/// Without `sched-o1-placement` nothing reads the histogram, so nothing
/// maintains it: every call site compiles to nothing.
#[cfg(not(feature = "sched-o1-placement"))]
#[inline(always)]
unsafe fn hist_reaccount(_idx: usize) {}

/// Longest printable task name: `Task::name` is null-terminated, so a name
/// that fills the array leaves `TASK_NAME_CAPACITY - 1` usable bytes. Used as
/// the fallback length when no terminator is found (malformed name).
const TASK_NAME_MAX_LEN: usize = TASK_NAME_CAPACITY - 1;

// ASIDs, generations and the switch-time TLB decision: `crate::asid`
// (Kconfig `TLB_RETAIN`, `ASID_BITS`).
pub use crate::asid::{alloc_asid, asid_rollovers, set_hw_asid_bits};

/// Magic value written at the bottom of each task stack (lowest address).
///
/// Stack grows downward — this 8-byte value is the first to be overwritten on
/// overflow.  Written during `task_create`; verified by `stack_canary_check()`.
///
/// This is the canary while the kernel entropy pool is unseeded (the boards
/// today). A seeded boot replaces it once, before the first task, through
/// `set_stack_canary`; `stack_canary()` is the value in force.
pub const STACK_CANARY: u64 = 0xDEAD_BEEF_CAFE_1234;

/// The canary in force. Starts at `STACK_CANARY`; replaced at most once.
static STACK_CANARY_VALUE: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(STACK_CANARY);

/// Latched by the first `set_stack_canary` call, accepted or not.
static STACK_CANARY_LOCKED: AtomicBool = AtomicBool::new(false);

/// The stack canary in force.
pub fn stack_canary() -> u64 {
    STACK_CANARY_VALUE.load(Ordering::Acquire)
}

/// Replace the stack canary. Accepted only on the first call, only for a
/// nonzero value, and only while no task slot is valid; returns whether it
/// was accepted.
///
/// **Why once, and before any task.** Each live stack carries the canary in
/// force at its `task_create`, and `stack_canary_check` compares against the
/// canary in force now: a change with a task alive reports that task's stack
/// as overflowed. The first call closes the window whether or not it is
/// accepted, so no later call can reopen it. Boot-only: the task-slot scan
/// and the store are not atomic against a concurrent `task_create`.
///
/// Zero is refused because a stack bottom that was never written reads zero.
pub fn set_stack_canary(value: u64) -> bool {
    if STACK_CANARY_LOCKED.swap(true, Ordering::AcqRel) || value == 0 {
        return false;
    }
    unsafe {
        for i in 0..MAX_TASKS {
            if TASK_VALID[i].load(Ordering::Acquire) {
                return false;
            }
        }
    }
    STACK_CANARY_VALUE.store(value, Ordering::Release);
    true
}

/// A 24-bit fingerprint of the canary in force, for the boot log: SHA-256
/// over a domain label and the value, top 24 bits. Two boots with different
/// canaries print different fingerprints (a collision is 1 in 2^24), and a
/// reader of the log still has 2^40 candidate values per fingerprint.
pub fn stack_canary_fingerprint() -> u32 {
    let mut h = azos_crypto::sha256::Sha256::new();
    h.update(b"AZOS-CANARY-FP-V1");
    h.update(&stack_canary().to_le_bytes());
    let d = h.finalize();
    u32::from_be_bytes([0, d[0], d[1], d[2]])
}

/// Whether stack guard pages replaced the canary: when true, `task_create`
/// does not write it and `stack_canary_check` does not compare it.
pub fn stack_guard_pages_active() -> bool {
    GUARD_PAGES_ACTIVE.load(Ordering::Acquire)
}

// ---- Global task pool (shared across all CPUs) ----

/// Task descriptors — valid slots tracked by TASK_VALID.
static mut TASKS: [Task; MAX_TASKS] = unsafe { core::mem::zeroed() };

/// Which slots in TASKS[] are in use.
///
/// `AtomicBool`, `Relaxed` — same treatment as `Task::queued` and the
/// `PrioQueue` fields, and for the same reason. Every write is already under
/// `POOL_LOCK` (`alloc_slot`'s publish, and the two free sites under
/// `PoolGuard`), so this buys those writers nothing. What it buys is the
/// READERS: `idx_for_tid`, `ring_claim_audit`, `current_snapshot`,
/// `task_census`, `find_best_cpu`, and a dozen more
/// all scan this array with no lock, by design (`idx_for_tid` is on the
/// lock-free cap-resolution path; the rest are ISR-reachable diagnostics or
/// placement heuristics that must not take `POOL_LOCK` from a timer tick). A
/// plain `bool` read on one hart racing a plain `bool` write on another is
/// undefined behaviour regardless of the outcome; `Relaxed` makes the load
/// legal without changing what any of these callers do with the answer — a
/// stale read costs one iteration's worth of staleness, exactly as it did
/// before, just now as defined behaviour instead of licensed-to-miscompile.
///
/// **This also repairs the fence half of the `alloc_slot`/`idx_for_tid`
/// sentinel protocol — the ordering, not the whole race.** That protocol is a
/// standalone `fence(Release)` before the publish and `fence(Acquire)` before
/// the re-check match — but a standalone fence only synchronises-with another
/// fence through an intervening atomic operation on the *same* memory; paired
/// across a PLAIN `bool` store/load it established no happens-before edge at
/// all, so the two fences were ships passing in the night. With `TASK_VALID`
/// atomic, the classic release-fence-then-relaxed-store /
/// relaxed-load-then-acquire-fence idiom is exactly the pattern the memory
/// model defines: the Release fence orders `TASKS[i].tid = 0` before the
/// `store(true, Relaxed)` that follows it, and a reader whose `load(Relaxed)`
/// observes `true` (or later) has its Acquire fence pair with that Release
/// fence, making the zeroed `tid` write happen-before the re-check that reads
/// it. That is the *ordering* fixed.
///
/// It is not the whole race: `TASKS[i].tid` itself is still a plain `u32`,
/// stored by `alloc_slot`/the free sites and read by `idx_for_tid`'s first,
/// unsynchronised probe (`if TASK_VALID[i].load(..) && TASKS[i].tid == tid`)
/// through no atomic operation of its own — a plain read racing a plain write
/// on a different slot's concurrent (re)allocation. Fixing the ordering
/// removed the failure mode the fences were written to fix (a stale `tid`
/// match past a re-check); it did not make that first racy read itself
/// defined. `tid`'s own conversion is deliberately not done here — see
/// `ring_claim_audit`'s doc for why leaving it is a judgement call, not
/// another instance of this same gap. Cost of what IS done here: zero — same
/// `lb`/`sb` on RV64, no new fence or AMO, matching the ring's write-path
/// result.
static mut TASK_VALID: [AtomicBool; MAX_TASKS] =
    [const { AtomicBool::new(false) }; MAX_TASKS];

/// Stack storage — each stack[i] is exclusively owned by TASKS[i].
/// Aligned to PAGE_SIZE (4 KiB, or the aarch64 granule) so that guard pages
/// can unmap exact page boundaries without affecting adjacent BSS data —
/// which also needs `STACK_SIZE` to be a whole number of pages (asserted).
#[repr(C)]
struct StackStorage([[u8; STACK_SIZE]; MAX_TASKS], [azos_arch_api::PageAlign; 0]);
static mut TASK_STACKS: StackStorage = StackStorage([[0u8; STACK_SIZE]; MAX_TASKS], []);
const _: () = assert!(
    STACK_SIZE % azos_arch_api::PAGE_SIZE == 0,
    "KERNEL_STACK_SIZE_KB must be a whole number of pages: the bottom page of each stack is unmapped as its guard",
);

/// RISC-V calling convention requires the stack pointer 16-byte aligned.
const STACK_ALIGN_BYTES: usize = 16;

/// Clean (pre-prologue, ABI-aligned) top of the stack at `stack_idx`.
///
/// This is the value a freshly dispatched task starts with, i.e. *before* any
/// function prologue has decremented SP. Used both at task creation and by the
/// I-13 transactional restart (`current_task_stack_top`).
///
/// SAFETY: `stack_idx` must be a valid task-pool index (`< MAX_TASKS`).
unsafe fn task_stack_top(stack_idx: usize) -> usize {
    let top = TASK_STACKS.0[stack_idx].as_mut_ptr() as usize + STACK_SIZE;
    top & !(STACK_ALIGN_BYTES - 1)
}

/// Monotonically increasing task ID counter.
static mut NEXT_TID: u32 = 1;

/// `true` once [`alloc_tid`] has wrapped `NEXT_TID` at least once (2^32
/// task creations). U02-6, second half: pre-wrap this is `false` forever
/// on every real board, and `alloc_tid` skips its liveness check entirely
/// while it is — the fork/spawn path pays nothing extra, which matters
/// because it is the same lane `vsbench`'s `fork+exit` measures. Only
/// past the first wrap can `NEXT_TID` repeat a value some ancient,
/// still-alive task holds, which is when the check has to start earning
/// its cost.
static TID_HAS_WRAPPED: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

/// Pure candidate-search logic behind [`alloc_tid`], in its own file only
/// so the host test runner (`tests/host/sched-wake-tests`) can compile it —
/// the rest of this module cannot leave the target. Same pattern as
/// `exit_note` / `process::elf_bounds` / `smp::hart_set`.
#[path = "../tid_alloc.rs"]
pub mod tid_alloc;

/// Allocate the next task ID.
///
/// **Pre-wrap (every board, in practice, forever): identical to the
/// original code** — `NEXT_TID`, then `wrapping_add(1)` skipping 0 (with
/// `overflow-checks = true` a bare `+= 1` would panic — a board reset —
/// at the 2^32nd task creation, reachable on a long-lived robot under
/// fork churn; TID 0 stays a sentinel `idle`/`NO_TID` conventions treat
/// specially).
///
/// **Post-wrap: skip any candidate `idx_for_tid` still resolves.**
/// Before this fix a wrapped counter could hand out a TID some live task
/// already holds — `idx_for_tid`, `wake_task_by_tid`, `EXIT_NOTE` and
/// every other TID-keyed lookup assume uniqueness among valid slots, so
/// a collision means two different tasks answer to the same identity.
/// `idx_for_tid` is the same O(1)-on-hint-hit lookup already used on
/// every wake, so this costs one lookup per creation, only after the
/// first wrap.
///
/// Bounded by `MAX_TASKS + 1`: at most `MAX_TASKS` TIDs can be live at
/// once, so among that many consecutive candidates at least one is free
/// (pigeonhole) — the search cannot spin longer than that even if every
/// live task happens to sit on consecutive TIDs exactly where the
/// counter wrapped back to.
///
/// # Safety
/// Caller must hold `POOL_LOCK` with interrupts disabled — same
/// requirement as the two static muts this reads and writes.
unsafe fn alloc_tid() -> u32 {
    let candidate = if TID_HAS_WRAPPED.load(Ordering::Relaxed) {
        tid_alloc::first_free(NEXT_TID, MAX_TASKS + 1, |t| idx_for_tid(t).is_some())
    } else {
        NEXT_TID
    };
    let next = tid_alloc::next_after(candidate);
    if next == 1 && candidate == u32::MAX {
        // `next_after` folded `u32::MAX + 1` back to the skip-zero
        // value: this IS the wrap.
        TID_HAS_WRAPPED.store(true, Ordering::Relaxed);
    }
    NEXT_TID = next;
    candidate
}

/// Where each live TID's slot was published, indexed by `tid % TID_SLOT_LEN`.
///
/// `idx_for_tid` and four wake/priority paths used to find a task by scanning
/// all `MAX_TASKS` slots (about 400 instructions at 64, each slot a 1,088-byte
/// stride apart), twice per wake and two wakes per IPC round trip. TIDs are
/// issued sequentially, so `tid % LEN` spreads live tasks across the table; a
/// slot is written once, when the TID is issued, and READ ONLY AS A HINT: every
/// lookup re-checks `TASK_VALID[slot] && TASKS[slot].tid == tid`, and a miss
/// falls back to the scan, which is what the code did before.
///
/// Four times `MAX_TASKS` (rounded up to a power of two) keeps two live tasks
/// from sharing a cell unless their TIDs differ by a multiple of that, which
/// long-lived tasks under heavy fork churn can still do. Then the older one takes
/// the scan, correctly, and (wave 13) the scan writes the cell back for it, so
/// it pays the scan once and not on every lookup for the rest of its life: a
/// short-lived task that took the cell leaves it pointing at a slot that soon
/// stops matching. Two writers then, issue and repair; both only ever cost time.
const TID_SLOT_LEN: usize = MAX_TASKS.next_power_of_two() * 4;
const _: () = assert!(MAX_TASKS < u16::MAX as usize, "TID_SLOT stores slot indices as u16");
static TID_SLOT: [AtomicU16; TID_SLOT_LEN] = [const { AtomicU16::new(u16::MAX) }; TID_SLOT_LEN];

/// Spinlock protecting TASKS[], TASK_VALID[], and NEXT_TID.
static POOL_LOCK: AtomicBool = AtomicBool::new(false);

// ---- Per-CPU scheduler state (multi-level priority queue) ----

/// Per-priority-level FIFO queue (circular buffer of task indices).
///
/// **Every field is atomic, and none of them is atomic for mutual exclusion.**
/// The ring is still owned by `CPU_LOCKS[cpu]` — the atomics carry `Relaxed`
/// ordering and buy no synchronisation whatsoever. They exist because
/// [`ring_claim_audit`] reads this struct from the timer ISR *without* that
/// lock, deliberately (taking it there deadlocks against a hart interrupted
/// while holding it), and in Rust a plain load racing a plain store is
/// undefined behaviour no matter how the result is treated afterwards. UB is
/// a licence granted to the compiler, not a description of a symptom: the
/// old `read_volatile` removed the compiler's ability to *exploit* the race
/// (re-read, re-materialise, assume-away) but left the program ill-formed.
/// A `Relaxed` load makes the read legal — that is the entire purpose.
///
/// **Cost on the write path: zero instructions.** On RV64 an aligned
/// `AtomicUsize::load(Relaxed)` is `ld` and `store(Relaxed)` is `sd`, the
/// same instructions the plain fields compiled to; no `fence`, no `amo*`.
/// What *does* change is that the compiler may no longer keep a field in a
/// register across unrelated code, so the mutators below hoist `head`/`count`
/// into locals by hand where the old code relied on that hoisting (see
/// `cpu_remove`, whose inner loop would otherwise reload `head` `count`
/// times). Never use `fetch_add` here: it emits a real AMO, and it would buy
/// nothing — where the lock is held it is redundant, and where it is not
/// (`boost_ready_task`) a per-field AMO does not make a multi-field
/// mutation atomic anyway.
///
/// **Lists, not rings** (wave 15, NRCPUS-FLEET-AREA): see `ready_list`. The
/// queues were `MAX_TASKS`-slot rings, 32 per CPU; they are now intrusive
/// lists threaded through [`RQ_NEXT`], one link per task slot for every queue
/// of every CPU, so a CPU's 32 queues are 512 bytes in every profile instead
/// of 32 x `MAX_TASKS` words (1 MiB a CPU at fleet's 4096 tasks). A walk is
/// bounded by `count` and by `MAX_TASKS` and stops at an out-of-range link,
/// which is what keeps a raced read (the audit) from looping or panicking.
pub(crate) type PrioQueue = crate::ready_list::ReadyList;

/// The ready-queue links: `RQ_NEXT[i]` is the successor of slot `i` in
/// whichever ready queue holds it (a list ends at its count, not at a link). One table for every queue of
/// every CPU, because a slot is in at most one queue at a time (the `queued`
/// claim, K-C12). Written under the owning CPU's lock. `MAX_TASKS` x 4 B,
/// static: it is sized by the task table, not by the CPUs.
pub(crate) static RQ_NEXT: [AtomicU32; MAX_TASKS] = [const { AtomicU32::new(0) }; MAX_TASKS];

// Slots are stored as `u32` and read sign-extended (`ready_list::rd`).
const _: () = assert!(MAX_TASKS < i32::MAX as usize, "ready-list links are u32 slots, read sign-extended");

/// Per-CPU scheduling state with 32-level priority queue.
///
/// `current_idx = usize::MAX` means "no task running" (initial state, also after task_exit).
/// `ready_bitmap` bit `i` is set when `ready_queues[i]` is non-empty.
/// `trailing_zeros()` on the bitmap gives the highest-priority non-empty level in O(1).
///
/// `ready_bitmap` is atomic for the same reason as the `PrioQueue` fields and
/// with the same `Relaxed` ordering: `cpu_peek_highest_prio` reads it without
/// `CPU_LOCKS[cpu]` on purpose. Its doc used to justify that with "the bitmap
/// write itself is always lock-protected, so this can observe an old-but-
/// consistent value, never a torn one" — true of the *hardware* and beside
/// the point of the *language* rule, which is what the compiler optimises
/// against.
///
/// `current_idx` is now `AtomicUsize`, `Relaxed`, for the same reason as
/// `ready_bitmap`. It is written by `start()`/`do_schedule()` under IRQ-disable
/// on the OWNING hart only — same-hart reads while interrupts are off (every
/// site inside `do_schedule()` itself, `task_entry_wrapper`) were never
/// racing anything. What was racing: `current_snapshot()` and
/// `reap_stamped_sleepers()` both read `PER_CPU[cpu].current_idx` for every
/// `cpu`, including harts other than the caller's, with no lock — a plain
/// `usize` load on one hart against a plain `usize` store on another is a
/// data race regardless of how the value is used afterwards. `Relaxed` makes
/// that legal without adding synchronisation the readers do not need: both
/// are diagnostics that tolerate a stale value (`current_snapshot` is
/// display-only, and `reap_stamped_sleepers`'s ABA guard already treats "not
/// current anywhere" as advisory — see its call site). It was not part of
/// what `ring_claim_audit` reads, which is why the ring's conversion left it
/// named rather than folding it in as an unrelated change; it is closed now.
/// `align(32)` is load-bearing, not cosmetic. The struct's three fields are 20
/// bytes, which would round to 24 and turn `&PER_CPU[cpu]` into a `×24` the
/// compiler emits as `slli`/`slli`/`add`. At 32 the index stays the single
/// `slli 0x5` the 16-byte version had, so `current_filter` is reached for the
/// same address arithmetic the old two-field struct paid. The cost is 8 CPUs ×
/// 12 bytes of padding, and it halves rather than worsens per-line sharing
/// (2 structs per 64-byte line instead of 4).
#[repr(align(32))]
struct PerCpuSched {
    current_idx:  AtomicUsize,
    ready_bitmap: AtomicU32,
    /// `&TASKS[current_idx].syscall_filter` as a `usize`, or 0 when no task is
    /// current — the syscall path's reason for existing, so the filter check
    /// does not re-derive this address from `current_idx` on every syscall.
    ///
    /// **Never written on its own.** [`set_current_task`] derives it FROM
    /// `current_idx` in the same breath as storing that index, which is what
    /// makes the two incapable of disagreeing; a writer that set only one of
    /// them would hand a task another task's whitelist, which is a containment
    /// failure with no crash to notice it by. `seccomp-tests` fails the build
    /// if `current_idx.store(` appears anywhere but that setter.
    ///
    /// The one other writer is [`set_current_foreign_mode`], which swaps this
    /// CPU's cached copy between the slot's filter and 0 for the task that is
    /// running here, with interrupts off, and writes the slot's own word the
    /// same way: the pair stays one value.
    current_filter: AtomicUsize,
    /// Does the task this CPU runs carry per-thread CPU state a switch must
    /// move (`SLOW_SWITCH`)? The previous task's answer, so a switch away
    /// from such a task takes the out-of-line path. Written only by
    /// [`set_current_task`].
    cur_slow: core::sync::atomic::AtomicBool,
}

/// Const initializer for PerCpuSched.
const EMPTY_CPU: PerCpuSched = PerCpuSched {
    current_idx:  AtomicUsize::new(usize::MAX),
    ready_bitmap: AtomicU32::new(0),
    current_filter: AtomicUsize::new(0),
    cur_slow: core::sync::atomic::AtomicBool::new(false),
};

/// The ONLY way to change which task a CPU is running.
///
/// Stores `next_idx` and the address of that slot's syscall filter together,
/// deriving the second from the first so they cannot drift. `next_idx` past the
/// pool stores a null filter, which [`current_syscall_verdict`] reads as
/// `Allow` — the same answer the bounds check it replaces used to give.
///
/// Two invariants hold this up, both checked by hand on 2026-09-18 and worth
/// re-checking before adding a third caller:
///
///  * **Every switch comes through here.** `context_switch` has exactly two
///    call sites and each is immediately preceded by this function, with no
///    `return`, `?` or panic between the two — so a task never starts running
///    against the previous task's cached filter. `trap_resched`/`NEED_RESCHED`
///    are not a third path: they reach `schedule()`, which is one of the two.
///  * **A hart only ever writes its OWN slot.** Both call sites pass the `cpu`
///    they are running on, so `Ordering::Relaxed` is sound here and on the read
///    in `current_syscall_verdict`; nothing publishes this pointer to another
///    hart. A future cross-hart writer would need more than `Relaxed`, and
///    would be writing a containment-critical field from off-hart, which is
///    reason enough to stop and think rather than to reach for `SeqCst`.
///
/// # Safety
/// Caller holds whatever the scheduler's own invariants require for touching
/// `PER_CPU[cpu]`, and `cpu` is a real hart index.
#[inline]
unsafe fn set_current_task(cpu: usize, next_idx: usize) {
    unsafe {
        let (filter, slow) = if next_idx < MAX_TASKS {
            if azos_limits::LINUX_ABI {
                // The word published at the slot's creation
                // (`publish_filter_word`) and flipped by the foreign-ABI
                // mode (`set_current_foreign_mode`): its filter's address, or
                // 0 for a task whose traps are foreign. One load in place of
                // the address arithmetic.
                (
                    FILTER_WORD[next_idx].load(Ordering::Relaxed),
                    crate::fp::SWITCH_STATE && SLOW_SWITCH[next_idx].load(Ordering::Relaxed),
                )
            } else {
                (core::ptr::addr_of!(TASKS[next_idx].syscall_filter) as usize, false)
            }
        } else {
            (0, false)
        };
        // Written only here, by this hart: one load serves every hook below.
        let prev = PER_CPU[cpu].current_idx.load(Ordering::Relaxed);
        // EVERY task's thread pointer follows it (aarch64 TPIDR_EL0, x86_64
        // FS base; riscv64's `tp` is in its trap frame): see
        // `fp::switch_thread_pointer` for why a native task needs it too.
        crate::fp::switch_thread_pointer(cpu, prev, next_idx);
        // The incoming thread's open I/O ports (nothing where the ISA has no
        // port space; two loads and a test between port-less tasks).
        crate::ioport::switch(cpu, next_idx);
        // A foreign task's riscv64 F/D file follows it, whichever mode it is
        // in. Only a switch from or to such a task takes the out-of-line
        // path; a native switch pays two loads and two tests.
        if crate::fp::SWITCH_STATE && (slow || PER_CPU[cpu].cur_slow.load(Ordering::Relaxed)) {
            crate::fp::switch_slow(prev, next_idx);
        }
        // N7b: the SC's `on_cpu` follows the switch (WAIT_GRAPH only; n
        // compiles nothing here and `classes::on_cpu` keeps its scan).
        if azos_sync::waitgraph::ENABLED {
            classes::on_switch(cpu, prev, next_idx);
        }
        // EEVDF: the task that stops is charged for its run, the one that
        // starts is stamped (a fair task only; every dispatch path, the IPC
        // hand-off included, comes through here).
        fairq::on_switch(prev, next_idx);
        PER_CPU[cpu].current_idx.store(next_idx, Ordering::Relaxed);
        PER_CPU[cpu].current_filter.store(filter, Ordering::Relaxed);
        if crate::fp::SWITCH_STATE {
            PER_CPU[cpu].cur_slow.store(slow, Ordering::Relaxed);
        }
    }
}

/// Run `read` with this hart's id and interrupts masked: the single place a
/// task asks a per-hart table about itself.
///
/// `current_cpu_id()` followed by `PER_CPU[cpu].field` is two steps, and with
/// interrupts on a tick can land between them and move the task to another
/// hart: the second read then returns what the FIRST hart is running. Found
/// 2026-10-20 as a kernel page fault copying to a user VA (`current_user_pt`
/// returned another hart's `user_pt`); the same two steps stood in every
/// `current_*` accessor and in the two writers that act through the slot
/// (`set_current_user_info`, `set_current_task_satp`).
///
/// Masked, nothing can move the task between the id and the read. What
/// `read` returns about the task itself (its slot, its filter address) stays
/// right after the mask is lifted, however the task migrates later: a slot
/// is the task's, not the hart's. A hart id returned is only this task's hart
/// at this instant.
///
/// Every accessor of the running task goes through here ([`here`],
/// [`my_idx`], [`current_slot`], the filter verdicts); a new one must too. A
/// caller that already has interrupts masked (the tick, `do_schedule`, a
/// `disable_all` section) keeps its own `current_cpu_id()`.
///
/// Cost: three instructions on riscv64 (`csrrci`, `andi`, `csrs`) and on
/// aarch64 (`mrs`, `msr DAIFSet`, `msr DAIF`).
#[inline(always)]
pub(crate) fn on_this_hart<R>(read: impl FnOnce(usize) -> R) -> R {
    // Gate canary `percpu-accessor-race-canary`: no mask, the old two steps.
    #[cfg(not(feature = "percpu-accessor-race-canary"))]
    let t = azos_mm::kheap::irq_off();
    let cpu = current_cpu_id();
    #[cfg(feature = "cpuid-probe")]
    crate::cpuid_probe::note_accessor(cpu);
    #[cfg(feature = "ktest")]
    accessor_audit::note(cpu);
    let r = read(cpu);
    #[cfg(not(feature = "percpu-accessor-race-canary"))]
    azos_mm::kheap::irq_restore(t);
    r
}

/// This hart and the slot of the task running on it (`usize::MAX`: none),
/// from one [`on_this_hart`] window.
#[inline(always)]
pub(crate) fn here() -> (usize, usize) {
    // SAFETY: `cpu` is this hart's id, which indexes `PER_CPU`; a relaxed
    // load of an atomic.
    on_this_hart(|cpu| (cpu, unsafe { PER_CPU[cpu].current_idx.load(Ordering::Relaxed) }))
}

/// The slot of the task running on this hart, `usize::MAX` when none: [`here`]
/// without the hart.
#[inline(always)]
pub(crate) fn my_idx() -> usize {
    here().1
}

/// Per slot, the word `set_current_task` publishes for it: the
/// address of the slot's syscall filter, or 0 while the task's traps are
/// foreign (a Linux task of the in-kernel personality, always; a hosted task
/// between a `SYS_FOREIGN_RESUME` and its next reflected trap). The syscall
/// path then takes the zero-word branch, where native tasks never go.
/// Written whenever a slot is (re)filled (`publish_filter_word`) and by
/// [`set_current_foreign_mode`]; a slot never filled reads 0, and the
/// zero-word branch answers from the slot itself, so a missing write costs
/// time, never containment.
static FILTER_WORD: [AtomicUsize; MAX_TASKS] = [const { AtomicUsize::new(0) }; MAX_TASKS];

/// Per slot: does the task carry per-thread CPU state a context switch must
/// move (`fp::switch_slow`)? True for every task whose `abi` is not native,
/// in either mode. Written with [`FILTER_WORD`].
static SLOW_SWITCH: [core::sync::atomic::AtomicBool; MAX_TASKS] =
    [const { core::sync::atomic::AtomicBool::new(false) }; MAX_TASKS];

/// Publish slot `idx`'s word ([`FILTER_WORD`]) from its `abi`. Called where a
/// slot is filled, before it is runnable.
fn publish_filter_word(idx: usize) {
    if idx >= MAX_TASKS {
        return;
    }
    // Wave 13: a new occupant has not been signalled.
    signal::clear_slot_signalled(idx);
    // A new occupant has registered no foreign entry and has nothing pending.
    crate::foreign::clear_slot(idx);
    // SAFETY: the slot is being filled under POOL_LOCK (or restored before
    // it is published); only its address and one byte are read.
    let (word, slow) = unsafe {
        let abi = TASKS[idx].abi;
        let w = if abi == crate::task::ABI_LINUX && !cfg!(feature = "linux-abi-tag-canary") {
            0
        } else {
            core::ptr::addr_of!(TASKS[idx].syscall_filter) as usize
        };
        (w, abi != crate::task::ABI_NATIVE)
    };
    FILTER_WORD[idx].store(word, Ordering::Relaxed);
    // Read only where the out-of-line path exists (`fp::SWITCH_STATE`).
    if crate::fp::SWITCH_STATE {
        SLOW_SWITCH[idx].store(slow, Ordering::Relaxed);
    }
}

/// Put the current task's traps in foreign mode (`foreign`: its syscall word
/// becomes 0, so the next trap is reflected) or in runtime mode (the word is
/// its filter's address, so the next trap is a native call), for
/// `azos_abi::foreign`.
///
/// This is the one writer of a CPU's `current_filter` other than
/// [`set_current_task`], and it keeps that function's invariant by writing
/// the slot's own word and this CPU's cached copy together with interrupts
/// off, so a preemption cannot leave the two disagreeing or write another
/// CPU's cache after a migration.
pub(crate) fn set_current_foreign_mode(foreign: bool) {
    let irqs = azos_arch::ARCH.disable_all();
    if let Some(idx) = current_slot() {
        let cpu = current_cpu_id();
        // SAFETY: the current task's own slot, read for its address.
        let word = if foreign {
            0
        } else {
            unsafe { core::ptr::addr_of!(TASKS[idx].syscall_filter) as usize }
        };
        FILTER_WORD[idx].store(word, Ordering::Relaxed);
        // SAFETY: this CPU's own entry, interrupts off.
        unsafe { PER_CPU[cpu].current_filter.store(word, Ordering::Relaxed) };
    }
    azos_arch::ARCH.restore(irqs);
}

/// Per-CPU ready queues and current task index.
static mut PER_CPU: [PerCpuSched; MAX_CPUS] = [const { EMPTY_CPU }; MAX_CPUS];

/// The ready queues, split out of `PerCpuSched` (2026-09-16; measured with
/// `tools/vsbench_compare.sh VSBENCH_ICOUNT=1`).
///
/// `current_idx` is read on every syscall (`current_syscall_verdict`, the
/// seccomp check) and every wake. While `ready_queues` lived next to it,
/// `size_of::<PerCpuSched>()` was `NUM_PRIORITIES * size_of::<PrioQueue>()`
/// plus change — 17,168 B on the qemu profile, not a power of two, so
/// `&raw PER_CPU[cpu]` cost a `mul`. `size_of::<PerCpuSched>()` is now 16 B
/// (an `AtomicUsize` and an `AtomicU32`, padded): indexing by `cpu` is a
/// shift, and the whole hot struct for every hart fits in two cache lines
/// instead of one apart per hart — the same reason Linux keeps
/// `thread_info` small and separate from `task_struct`.
///
/// Same shape as the `CPU_LOCKS` split above, and the same answer to "why
/// not just fold it back in": every site here already used `PER_CPU[cpu]`
/// or `PER_CPU[cpu].ready_queues[prio]`, so the two arrays read exactly like
/// one did before, and re-merging them would undo the point of the split
/// for no gain.
///
/// **In the per-CPU areas** (wave 15, NRCPUS): `NUM_PRIORITIES` list heads
/// of 16 bytes per CPU, the same in every profile (the links are in
/// [`RQ_NEXT`]). Allocated at boot for the possible CPUs only (all-zero is the
/// empty list) and reached through [`cpu_queues`].
///
/// Scope: a bare `PerCpuRemote` for now; with its per-CPU lock array it is
/// the `CpuOwned` shape (wakeups enqueue on another CPU's queue).
pub(crate) static PER_CPU_QUEUES: azos_percpu::PerCpuRemote<[PrioQueue; NUM_PRIORITIES]> =
    // SAFETY: a `ReadyList` is atomics only; all-zero is the empty list.
    unsafe { azos_percpu::PerCpuRemote::zeroed() };

/// `cpu`'s ready queues, in its per-CPU area. `cpu` must be below [`ncpu`]
/// (a CPU past it holds `azos_percpu::POISON`, and the access faults there).
#[inline(always)]
pub(crate) fn cpu_queues(cpu: usize) -> &'static [PrioQueue; NUM_PRIORITIES] {
    // SAFETY: attached at boot, before any task exists, for every CPU below
    // `ncpu()`, and never freed; a `PrioQueue` is atomics, shared by `&`.
    unsafe { &*PER_CPU_QUEUES.ptr(cpu) }
}

/// Per-CPU spinlocks for ready queue access.
///
/// Kept as a separate array rather than a field of `PerCpuSched`. (The
/// original reason — "AtomicBool is not Copy" — expired when the ring fields
/// became atomics and `PerCpuSched` stopped being `Copy`; the split stays
/// because moving it now would touch every `CpuLockGuard` site for no gain.)
///
/// `MAX_CPUS`, not a literal: `PER_CPU` is `[_; MAX_CPUS]` and every index
/// used on one is used on the other — a hand-written 4 here compiled clean
/// while growing `MAX_CPUS` (the VF2 5-hart case is already documented) and
/// then indexed out of bounds. Same duplicated-constant class as the
/// `MAX_HARTS` injection into the asm.
///
/// **Locks that may be held when one of these is taken** (a CPU lock is the
/// innermost lock of the scheduler): a task's donation lock
/// (`DONATION_LOCKS`, the boost/restore re-bucketing). The chain is
/// donation lock -> `CPU_LOCKS[cpu]`. Never take a donation lock while
/// holding a CPU lock.
///
/// Words, not `AtomicBool` (wave 15, SWITCH): RV64 has no sub-word AMO, so
/// a byte lock's compare-and-swap compiled to a masked `amoor.w` sequence
/// (nine instructions); a word lock is one `amoswap.w.aq` to take and one
/// store to give back. Two of these per context switch.
static CPU_LOCKS: [AtomicU32; MAX_CPUS] =
    [const { AtomicU32::new(0) }; MAX_CPUS];

// ---- FFI: context_switch assembly ----

unsafe extern "C" {
    /// Switch from `old` task context to `new` task context.
    /// If `old` is null, just restores `new` (used for the very first task).
    fn context_switch(old: *mut Task, new: *mut Task);
}

// K-C23: `context_saving` used to be cleared by a `mark_context_saved`
// helper here, `call`ed from `context_switch.S` between saving `old`'s
// registers and restoring `new`'s. That call ran ON THE OLD TASK'S STACK,
// and the Release store inside it is precisely what publishes that stack as
// up for grabs — the helper only worked because rustc happened to compile it
// as a frameless leaf. Any future prologue/epilogue in it (a kprintln, a
// wcet probe, a dev-profile build) would have its epilogue racing the hart
// that already dispatched `old` and restored its sp. The clear now lives in
// the asm itself (`fence rw, w` + `sb zero` in `context_switch.S`, offset
// injected via `offset_of!` from kernel main.rs), where "no frame, last
// touch of the old stack" is true by construction instead of by accident.

// ---- Lock RAII guards ----

/// K-A13: IRQ-safe by construction (mirrors `CpuLockGuard` below): disables
/// `sstatus.SIE` before spinning for `POOL_LOCK` and restores the previous
/// interrupt state on drop. Without this, a timer tick on the same hart
/// while `task_exit()` holds this lock (it used to acquire it with
/// interrupts still enabled) could dispatch another task on that same hart
/// that then calls `task_create` (e.g. `fork()`) and spins on `POOL_LOCK`
/// forever with interrupts disabled — a same-hart deadlock, since only the
/// original holder (now preempted) could ever release it. Composes safely
/// with callers that already disable SIE themselves (`task_create_affinity`):
/// this guard just captures/restores whatever SIE was already at entry.
struct PoolGuard {
    prev_sstatus: azos_arch::InterruptState,
}

impl PoolGuard {
    fn acquire() -> Self {
        let prev_sstatus = azos_arch::ARCH.disable_all();

        while POOL_LOCK
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
        PoolGuard { prev_sstatus }
    }
}

impl Drop for PoolGuard {
    fn drop(&mut self) {
        POOL_LOCK.store(false, Ordering::Release);
        azos_arch::ARCH.restore(self.prev_sstatus);
    }
}

/// RAII guard for `CPU_LOCKS[cpu]`.
///
/// IRQ-safe by construction (mirrors `azos_sync::spinlock::lock_irqsave`):
/// disables `sstatus.SIE` on the local hart before spinning for the lock, and
/// restores the previous interrupt state on drop (lock released first, then
/// interrupts restored — a pending IRQ that fires right after re-enable must
/// see the lock as free).
///
/// This is the *only* acquisition path for `CPU_LOCKS`; every ready-queue
/// touch — same-CPU (`do_schedule`) or cross-CPU (`try_wake_task`,
/// `wq_wake_by_tid`, task creation) — goes through it. That is deliberate:
/// mixing a plain spin (`lock()`-style) with an irqsave spin on the *same*
/// lock reopens the deadlock this guard exists to close (an IRQ on the local
/// hart could preempt a plain-spin holder and then spin forever waiting for
/// itself). `do_schedule()` is reachable both from task context (interrupts
/// live) and from the timer ISR (`schedule()`), so plain `lock()` here would
/// not be safe.
struct CpuLockGuard {
    cpu: usize,
    prev_sstatus: azos_arch::InterruptState,
}

impl CpuLockGuard {
    fn acquire(cpu: usize) -> Self {
        let prev_sstatus = azos_arch::ARCH.disable_all();

        cpu_lock_spin(cpu);
        CpuLockGuard { cpu, prev_sstatus }
    }
}

impl Drop for CpuLockGuard {
    fn drop(&mut self) {
        CPU_LOCKS[self.cpu].store(0, Ordering::Release);
        // Restore only the SIE bit from the saved sstatus (same ordering
        // rationale as `IrqSaveGuard::drop` in crates/core/sync/src/spinlock.rs).
        azos_arch::ARCH.restore(self.prev_sstatus);
    }
}

// ---- Internal helpers ----

/// Clamp a task's priority to a valid ready-queue bucket.
///
/// `ready_queues` has `NUM_PRIORITIES` (32) buckets and `ready_bitmap` is a
/// `u32`, so an out-of-range priority is an array index panic *and* a shift
/// overflow — under `panic = "abort"` that is a board reset, i.e. the loudest
/// possible failure for what is only ever a bad literal at a call site
/// (`task_create` takes `priority: u32` and never validates it). Clamping to
/// the lowest bucket degrades the task's scheduling instead of resetting the
/// board.
/// Take `CPU_LOCKS[cpu]`: test-and-set, spinning on a plain load while it
/// is held (no AMO traffic from the waiters).
#[inline(always)]
fn cpu_lock_spin(cpu: usize) {
    while CPU_LOCKS[cpu].swap(1, Ordering::Acquire) != 0 {
        while CPU_LOCKS[cpu].load(Ordering::Relaxed) != 0 {
            core::hint::spin_loop();
        }
    }
}

/// `CPU_LOCKS[cpu]` for a caller whose interrupts are ALREADY masked:
/// `do_schedule`, whose every caller masks them (`yield_as`, the tick, the
/// block path, `task_exit`'s idle). Saves the `sstatus` save, mask and
/// restore that [`CpuLockGuard`] does, twice per context switch.
struct CpuLockIrqsOff {
    cpu: usize,
}

impl CpuLockIrqsOff {
    #[inline(always)]
    fn acquire(cpu: usize) -> Self {
        cpu_lock_spin(cpu);
        CpuLockIrqsOff { cpu }
    }
}

impl Drop for CpuLockIrqsOff {
    #[inline(always)]
    fn drop(&mut self) {
        CPU_LOCKS[self.cpu].store(0, Ordering::Release);
    }
}

#[inline]
fn prio_bucket(priority: u32) -> usize {
    (priority as usize).min(NUM_PRIORITIES - 1)
}

/// Enqueue task `idx` at its priority level on CPU `cpu`.
/// Caller must hold `CPU_LOCKS[cpu]` or guarantee single-CPU access.
///
/// Returns `true` when this call put the task on the queue. `false` means
/// **this call** added nothing — see [`EnqueueOutcome`] for the two reasons
/// and why only one of them can lose work.
///
/// K-C12: the ring overflow used to be guarded by `debug_assert!`, which is
/// compiled out of the release profile this kernel ships. A full queue then
/// overwrote `q.buf[q.tail]` — silently discarding a *different* ready task —
/// and drove `q.count` past the ring so it no longer described the buffer.
/// Ready tasks disappeared with no error anywhere. See the `Task::queued`
/// doc for the invariant that now makes the full case unreachable, and
/// `enqueue_decision` for the policy itself.
unsafe fn cpu_enqueue(cpu: usize, idx: usize) -> bool {
    cpu_enqueue_as(cpu, idx, false)
}

/// [`cpu_enqueue`]; `requeue`: `idx` is the task that was just running (or a
/// pick put back), which keeps its place in the fair order (`fairq::place`).
unsafe fn cpu_enqueue_as(cpu: usize, idx: usize, requeue: bool) -> bool {
    let task = task_mut(idx);
    let prio = prio_bucket(task.priority.load(Ordering::Relaxed));
    // CLAIM, don't test-then-set. `CPU_LOCKS[cpu]` serializes enqueues onto
    // *one* CPU and nothing more, so two harts enqueueing the SAME task onto
    // DIFFERENT CPUs hold different locks and never exclude each other — and
    // that pair is reachable: `try_wake_task` and `wq_wake_by_tid` both flip
    // `state` without POOL_LOCK, and `wake_target_cpu` is deliberately
    // unlocked and approximate, so two concurrent wakers can legitimately
    // choose different targets for the same task. A plain load-then-store
    // would let both observe `false`, both append, and put the task in two
    // rings at once — which is exactly the duplicate this flag exists to
    // forbid, and it would void the counting argument that makes `Full`
    // unreachable. The atomic swap makes the claim itself the arbitration:
    // the loser reads `true` and refuses.
    let already = task.queued.swap(true, Ordering::AcqRel);
    // Read once and thread the value through to the `Append` arm below: the
    // atomic field cannot be kept in a register across `enqueue_decision`, so
    // re-reading it there would cost an extra `ld` on the hot path for a
    // value the lock guarantees has not changed.
    let q = &cpu_queues(cpu)[prio];
    let count = q.count();

    match enqueue_decision(already, count, MAX_TASKS) {
        // Still queued (elsewhere, or by the hart that won the swap) — leave
        // the claim standing, it belongs to that entry.
        // Still queued (elsewhere, or by the hart that won the swap) — leave
        // the claim standing, it belongs to that entry.
        //
        // MEASURED, not hypothetical (ring-3 ipctest, `-smp 4`): this fires
        // steadily for the periodic kernel tasks — `imu`, `odom`,
        // `sensor-slow`. The source is `wake_expired_timers`, which runs in
        // EVERY hart's timer ISR and reaches `try_wake_task`, whose
        // `state != Blocked` test and its `state = Ready` write have nothing
        // between them: two harts firing close together both see `Blocked`
        // and both enqueue. A probe that scanned every ready queue on each
        // refusal reported `present=true` 20 times out of 20 — the task
        // really was already queued, so refusing loses nothing — and
        // `user=false` every time, i.e. no ring-3 task was ever refused.
        //
        // Before `queued`, each of those duplicates added an entry and
        // incremented `count` toward the ring size. That is the second half
        // of K-C12: a queue that fills with duplicates starts overwriting
        // live entries, and the tasks it overwrites disappear in silence.
        EnqueueOutcome::AlreadyQueued => false,
        EnqueueOutcome::Full => {
            // We won the claim but cannot honour it: release it, or the task
            // becomes permanently un-enqueueable.
            task.queued.store(false, Ordering::Release);
            // Unreachable while the `queued` invariant holds; if it ever
            // fires, the invariant broke and that is worth a line in the log.
            // The task stays `Ready` and un-queued: whoever next wakes or
            // preempts it will enqueue it then. That is a delay; overwriting
            // a live entry, which is what the old code did here, was a
            // permanent, silent loss of somebody else's task.
            enqueue_full_report(cpu, prio, count, task.tid);
            false
        }
        EnqueueOutcome::Append => {
            // The claim was taken by the swap above.
            //
            // `&`, not `&mut`. A `&mut` to this ring is an aliasing violation
            // on its own — `ring_claim_audit` holds a shared reference to the
            // very same bytes from another hart's timer ISR — and that half of
            // the UB survives converting the fields. Interior mutability
            // through the atomics is what removes it.
            // `count` was loaded above under the same lock and is passed on,
            // so the list does not load it twice; plain stores, no AMO.
            fairq::place(cpu, idx, requeue);
            q.push_back(&RQ_NEXT, idx, count);
            let bm = &PER_CPU[cpu].ready_bitmap;
            bm.store(bm.load(Ordering::Relaxed) | (1 << prio), Ordering::Relaxed);
            true
        }
    }
}

/// Dequeue the highest-priority ready task from CPU `cpu`.
/// Caller must hold `CPU_LOCKS[cpu]` or guarantee single-CPU access.
/// The K-C12 "queue full" report, out of line: formatting it inline gave
/// every enqueue a stack frame and six saved registers it never uses on the
/// path that runs.
#[cold]
#[inline(never)]
fn enqueue_full_report(cpu: usize, prio: usize, count: usize, tid: u32) {
    azos_drv_sys::kerr!(
        "[SCHED] BUG: ready queue cpu{} prio{} full ({} entries) — task {} not enqueued",
        cpu, prio, count, tid,
    );
}

unsafe fn cpu_dequeue(cpu: usize) -> Option<usize> {
    let bm = &PER_CPU[cpu].ready_bitmap;
    let bitmap = bm.load(Ordering::Relaxed);
    // The levels the list pop below may take (the fair ones are not, when the
    // EEVDF pick found only reservations there).
    let mut pickable = bitmap;
    if bitmap == 0 {
        return None;
    }
    // The most urgent level is a fair one: the fair levels are one EEVDF
    // queue (`fairq.rs`), with the running task a candidate, so the pick is
    // not the head of that level's list.
    if bitmap & rt::LEVELS_BAND == 0 && bitmap & rt::LEVELS_NONBAND != 0 {
        match fairq::pick(cpu) {
            fairq::Fair::Task(idx) => {
                return if cpu_remove(cpu, idx) { Some(idx) } else { None };
            }
            // The running task is still the best: the caller keeps it.
            fairq::Fair::Keep => return None,
            // Only reservations queued at these levels: past them.
            fairq::Fair::Empty => {
                pickable &= !rt::LEVELS_NONBAND;
                if pickable == 0 {
                    return None;
                }
            }
        }
    }
    let prio = pickable.trailing_zeros() as usize;
    if prio >= NUM_PRIORITIES {
        return None; // Impossible for a u32 bitmap; keeps the index provably safe.
    }
    // `&`, not `&mut`: the audit holds a shared reference to these same bytes
    // from another hart's timer ISR, so a `&mut` here is an aliasing
    // violation regardless of what the fields' types are.
    let q = &cpu_queues(cpu)[prio];
    let count = q.count();
    if count == 0 {
        // Bitmap says occupied, ring says empty: they disagree. `count -= 1`
        // here would underflow, and `overflow-checks = true` turns that into
        // a board reset. Re-sync the bitmap and report "nothing ready".
        bm.store(bitmap & !(1 << prio), Ordering::Relaxed);
        return None;
    }
    let Some(idx) = q.pop_front(&RQ_NEXT, count) else {
        // A head link out of range: the list reset itself to empty. Same
        // answer as the count/bitmap disagreement above.
        bm.store(bitmap & !(1 << prio), Ordering::Relaxed);
        return None;
    };
    let count = count - 1;
    if count == 0 {
        // `bitmap`, not a second load. Re-reading an atomic the compiler is no
        // longer free to keep in a register is the one way this conversion
        // could cost instructions, and with the lock held nothing has written
        // the bitmap since it was read, so the two are the same value.
        //
        // They differ only against the unlocked writers
        // (`boost_ready_task`/`restore_ready_task`) — and there the reloading
        // form is no safer: `&=` is a load-modify-store, not an atomic RMW, so
        // it loses a concurrent update just the same. Both forms are wrong in
        // that case, and the fix is to lock those two, not to reload here.
        bm.store(bitmap & !(1 << prio), Ordering::Relaxed);
    }
    // K-C12: this is the only pop, so it is the only place the `queued`
    // invariant is released. Leaving it set here would make the task
    // permanently un-enqueueable — silent starvation, the exact failure the
    // flag exists to prevent.
    if idx < MAX_TASKS {
        task_mut(idx).queued.store(false, Ordering::Release);
    }
    Some(idx)
}

// ── Core scheduling (`SCHED_CORE`, policy: `topo::CoreSched`) ────────────────

/// `cpu`'s SMT siblings and itself, or 0 when the pick is not core-scheduled
/// (the option is off, or `cpu` has no sibling in the installed topology).
#[inline(always)]
fn core_smt(cpu: usize) -> topo::Mask {
    if !azos_limits::SCHED_CORE {
        return 0;
    }
    let m = topo::mask(Level::Smt, cpu);
    if m.count_ones() > 1 { m } else { 0 }
}

/// The claim of task `idx` as a candidate for `cpu`: its Domain, strong for
/// the band and for a reservation; the idle task claims nothing.
unsafe fn core_claim_of(cpu: usize, idx: usize) -> Claim {
    let t = task_ref(idx);
    let prio = t.priority.load(Ordering::Relaxed);
    if prio == crate::task::IDLE_PRIORITY {
        return Claim::IDLE;
    }
    Claim::task(t.domain(), is_rt_priority(prio) || rt::reserved_here(cpu, idx))
}

/// The scheduler clock of the core pick: nonzero, as `topo::CoreSched` needs.
#[inline(always)]
fn core_now() -> u64 {
    azos_drv_sys::timebase::now() | 1
}

/// `SCHED_CORE_PATIENCE_US` in timer counts.
const CORE_PATIENCE: u64 =
    azos_drv_sys::timebase::TIMER_FREQ * azos_limits::SCHED_CORE_PATIENCE_US / 1_000_000;

/// May the IPC hand-off switch `cpu` from `cur` straight to `ti`? On a
/// core-scheduled hart only when both hold the same claim: the switch does
/// not go through the pick that admits a claim, so one that changes it would
/// run `ti` beside a sibling of another Domain.
#[inline(always)]
unsafe fn core_direct_ok(cpu: usize, cur: usize, ti: usize) -> bool {
    core_smt(cpu) == 0 || core_claim_of(cpu, cur) == core_claim_of(cpu, ti)
}

/// The first task of `cpu` is running (`start`): record its claim. Nothing
/// can be refused in favour of anything yet, so it is not asked.
unsafe fn core_started(cpu: usize, idx: usize) {
    let smt = core_smt(cpu);
    if smt != 0 {
        topo::CORE.force(smt, cpu, core_claim_of(cpu, idx));
    }
}

/// The idle task of `cpu`, off its queue, if it is there (it is not while it
/// is the running task).
unsafe fn cpu_take_idle(cpu: usize) -> Option<usize> {
    let _g = CpuLockIrqsOff::acquire(cpu);
    let prio = crate::task::IDLE_PRIORITY as usize;
    let bm = &PER_CPU[cpu].ready_bitmap;
    let q = &cpu_queues(cpu)[prio];
    let count = q.count();
    if count == 0 {
        return None;
    }
    let idx = q.pop_front(&RQ_NEXT, count);
    if idx.is_none() || count == 1 {
        bm.store(bm.load(Ordering::Relaxed) & !(1 << prio), Ordering::Relaxed);
    }
    let idx = idx?;
    if idx < MAX_TASKS {
        task_mut(idx).queued.store(false, Ordering::Release);
    }
    Some(idx)
}

/// Return the priority of the highest-priority ready task on `cpu`, or None.
///
/// Intentionally lock-free: called from `schedule()` as a preemption *hint*
/// (RT-task check) on `cpu == current_cpu_id()`. A stale read here (racing a
/// concurrent cross-CPU `cpu_enqueue_locked` targeting this CPU) only delays
/// or advances a preemption decision by up to one timer tick.
///
/// The old justification for the plain read was "the bitmap write itself is
/// always lock-protected, so this can observe an old-but-consistent value,
/// never a torn one". That is a claim about the hardware and it is true; it
/// is not the rule the compiler follows. A plain load racing a plain store is
/// UB in the abstract machine, and UB is a licence the optimiser may act on
/// however it likes — including, in principle, deleting the branch below
/// because a well-defined program could never reach it with a racing value.
/// `Relaxed` costs the same `lw` and makes the read legal.
unsafe fn cpu_peek_highest_prio(cpu: usize) -> Option<u32> {
    let bitmap = PER_CPU[cpu].ready_bitmap.load(Ordering::Relaxed);
    if bitmap == 0 { None } else { Some(bitmap.trailing_zeros()) }
}

/// Dequeue the highest-priority ready task from CPU `cpu`, taking
/// `CPU_LOCKS[cpu]` for the duration of the operation.
///
/// This is the cross-CPU-safe entry point — use this (never the raw
/// `cpu_dequeue`) from anywhere that isn't already holding `CPU_LOCKS[cpu]`.
/// The lock is released before returning, so it is never held across a
/// `context_switch()` call.
unsafe fn cpu_dequeue_locked(cpu: usize) -> Option<usize> {
    let _g = CpuLockGuard::acquire(cpu);
    cpu_dequeue(cpu)
}

/// [`cpu_dequeue_locked`] for `do_schedule`, whose interrupts are masked.
#[inline(always)]
unsafe fn cpu_dequeue_irqs_off(cpu: usize) -> Option<usize> {
    let _g = CpuLockIrqsOff::acquire(cpu);
    cpu_dequeue(cpu)
}

/// `do_schedule` putting a task back on ITS OWN hart's queue, interrupts
/// masked: [`cpu_enqueue_locked`] without the `sstatus` save/restore and
/// without the doorbell, which only a remote enqueue rings (`cpu` is this
/// hart, awake by definition).
#[inline(always)]
unsafe fn cpu_requeue_self(cpu: usize, idx: usize) -> bool {
    let _g = CpuLockIrqsOff::acquire(cpu);
    cpu_enqueue_as(cpu, idx, true)
}

/// Enqueue task `idx` on CPU `cpu`'s ready queue, taking `CPU_LOCKS[cpu]`
/// for the duration of the operation.
///
/// This is the cross-CPU-safe entry point — use this (never the raw
/// `cpu_enqueue`) from anywhere that isn't already holding `CPU_LOCKS[cpu]`.
/// Callers include waking a task pinned to (or placement-assigned to) a
/// CPU other than the caller's own — `try_wake_task`, `wq_wake_by_tid`,
/// `task_create_affinity` — as well as `do_schedule()` re-enqueuing the
/// outgoing task on its own CPU, which races the very same cross-CPU wakers.
unsafe fn cpu_enqueue_locked(cpu: usize, idx: usize) -> bool {
    let appended = {
        let _g = CpuLockGuard::acquire(cpu);
        cpu_enqueue(cpu, idx)
    }; // guard dropped before the SBI call below — never ecall holding a lock.
    ring_doorbell(cpu, idx, appended);
    // NOHZ_FULL: a task became ready on the CPU this runs on, so a tick it
    // stopped for want of one starts again. Another CPU's is restored by the
    // doorbell above: its interrupt arm calls `drain_remote_wakes`, which does.
    if azos_limits::NOHZ_FULL && appended && cpu == current_cpu_id() {
        azos_drv_sys::timebase::tick_restart();
    }
    appended
}

// ── Tickless busy CPUs (Kconfig NOHZ_FULL) ──────────────────────────────────
//
// An isolated CPU (`[sched] isolcpus`) that runs one real-time task alone
// stops its periodic tick. The decision is taken at the tick itself: the
// handlers re-arm through `timebase`, which asks `nohz_tick_hook` (registered
// when the isolated CPUs are published) whether the tick may stop, and
// programs `timebase::stop_bound` ahead instead of one period. It cannot be
// taken in `do_schedule`: a tick that finds a real-time task running and
// nothing better ready returns from `schedule()` without reaching it. The
// tick comes back by `timebase::tick_restart` (an enqueue on the CPU), by the
// tail of `do_schedule` (a switch off the task), or by the stopped tick's own
// interrupt finding the CPU no longer lone. Timer sleepers and RT enforcement
// instants are compared against the stop deadline, never rounded to it
// (`timebase::arm_if_earlier`, the comparator's earlier-wins rule).
//
// The pure parts (what "lone" is, the second-tick rule, the bound) are
// `azos_drv_sys::timebase::nohz`, host-tested; RCU's side is
// `azos_sync::qsbr::set_tickless_cpus`.

/// The CPUs that may run tickless: `isolcpus` under NOHZ_FULL, a mask.
static NOHZ_CPUS: AtomicU64 = AtomicU64::new(0);

/// Per CPU: the task the last tick saw alone and for how many ticks
/// (`nohz::pack`). Written only by that CPU's tick.
static NOHZ_SEEN: [AtomicU64; MAX_CPUS] = [const { AtomicU64::new(0) }; MAX_CPUS];

/// Publish the isolated CPUs (`fairq::set_isolated_cpus`, at boot after the
/// topology is installed). RCU first: a CPU must count its user mode as
/// quiescent before any tick may stop.
pub(crate) fn nohz_publish(mask: u64) {
    if !azos_limits::NOHZ_FULL {
        return;
    }
    azos_sync::qsbr::set_tickless_cpus(mask);
    NOHZ_CPUS.store(mask, Ordering::Release);
    if mask != 0 {
        azos_drv_sys::timebase::set_tick_stop_hook(nohz_tick_hook);
    }
}

/// May the tick of the CPU this runs on stop now? Called from the tick
/// handler, interrupts off, by `timebase`'s re-arm.
fn nohz_tick_hook() -> bool {
    use azos_drv_sys::timebase::nohz;
    let cpu = current_cpu_id();
    if !nohz::in_mask(NOHZ_CPUS.load(Ordering::Acquire), cpu) {
        return false;
    }
    let Some(seen) = NOHZ_SEEN.get(cpu) else { return false };
    // SAFETY: the tables are static; a tick reads the interrupted task as
    // `current_task_vdso_facts` does, and a stale answer only delays or
    // hastens a stop that the next tick revises.
    let (tid, lone) = unsafe {
        let idx = PER_CPU[cpu].current_idx.load(Ordering::Relaxed);
        if idx >= MAX_TASKS {
            (0, false)
        } else {
            let t = task_ref(idx);
            let c = nohz::Cpu {
                isolated: true,
                running_rt: nohz::running_rt(
                    t.state() == TaskState::Running,
                    t.priority.load(Ordering::Relaxed),
                    crate::task::RT_PRIORITY_THRESHOLD,
                ),
                other_ready: nohz::others_ready(
                    PER_CPU[cpu].ready_bitmap.load(Ordering::Relaxed),
                    crate::task::IDLE_PRIORITY,
                ),
                wake_pending: !crate::wake_list::is_empty(&REMOTE_WAKE_HEAD[cpu]),
            };
            (t.tid, nohz::lone_rt(c))
        }
    };
    let (now_seen, stop) = nohz::observe(nohz::unpack(seen.load(Ordering::Relaxed)), tid, lone);
    seen.store(nohz::pack(now_seen), Ordering::Relaxed);
    stop
}

/// The K-C15 doorbell of [`cpu_enqueue_locked`], shared with the deferred
/// remote wake (`SCHED_REMOTE_WAKE_DEFER`, [`remote_wake_try`]).
#[inline(always)]
unsafe fn ring_doorbell(cpu: usize, idx: usize, appended: bool) {
    let _ = idx;

    // K-C15: tell the target hart it has work.
    //
    // **WHY the enqueue alone was not enough.** A hart with nothing ready runs
    // `idle_task`, which is `loop { wfi() }`, and the only thing that ever
    // preempts it is a timer interrupt. This kernel is *tickless*
    // (`nearest_timer_deadline` programs `mtimecmp` at the next real deadline
    // rather than at a fixed rate), so "the next tick" on an idle hart can be
    // arbitrarily far away. Making a task `Ready` on another hart's queue
    // therefore did not make it *run* — it made it eligible to run whenever
    // that hart happened to wake for some unrelated reason.
    //
    // Measured before this: a ring-3 fast-IPC round trip took on the order of
    // seconds per exchange, with both peers correct, awake and enqueued. It
    // reads as a hang and is a missing doorbell.
    //
    // `send_ipi` (`crates/core/arch-riscv64/src/api_impl.rs`) and the
    // `INT_SOFTWARE_S` trap arm both already existed; the arm was used only
    // for TLB shootdown and nothing ever called the sender. `cpu` is the
    // logical CPU id (`tp`); `firmware::send_ipi` maps it to the hart's
    // hardware id for the SBI.
    //
    // Self-enqueue needs no doorbell: this hart is by definition awake, and it
    // reaches `do_schedule` on its own path out. Sending to a hart that never
    // came up is harmless — SBI reports an error we deliberately ignore.
    // Only ring the doorbell when this call actually made the hart's queue
    // longer. A refused enqueue (K-C12: the task was already queued) has
    // nothing new to announce.
    if appended && cpu != current_cpu_id() {
        #[cfg(target_arch = "riscv64")]
        let rc = azos_arch::firmware::send_ipi(cpu);
        // aarch64: GICv3 SGI (`arch-api`'s `Interrupts::send_ipi`,
        // `ICC_SGI1R_EL1`) is a fire-and-forget system-register write with
        // no completion status to read back — unlike SBI's synchronous
        // ecall return code, there is no `rc` here. `0` stands for "the
        // write was issued", exactly what arch-riscv64's own
        // `Interrupts::send_ipi` impl already reports for this same call
        // shape (`firmware::send_ipi(target_hart)`, `rc` discarded via
        // `let _ =`) — not a claim the target hart was confirmed reached.
        #[cfg(not(target_arch = "riscv64"))]
        let rc: isize = {
            use azos_arch::Interrupts;
            azos_arch::ARCH.send_ipi(cpu);
            0
        };
        let _ = rc;
        #[cfg(feature = "ipc-census")]
        {
            wakelat::rang(idx);
            wakelat::ipi_sent(rc != 0);
        }
    }
}

// ── Deferred remote wakes (`SCHED_REMOTE_WAKE_DEFER`) ──────────────────────
//
// Owner decision (wave 15, VW): a wake of a task on ANOTHER CPU never spins
// on that CPU's queue lock. The waker tries the lock once; if it is held it
// pushes the slot onto the target's lock-free list (`wake_list`) and rings
// the doorbell, and the target queues it under its own lock in the
// doorbell's interrupt arm. Measured (riscv64 `-icount`, rt7): this path
// is taken 0-2 times a boot, and every `try_wake_task` stage stays under
// 3 us; the ~50 ms timer-ISR stall rt7 hit was the global timer-heap lock
// (now per CPU, `SCHED_TIMER_HEAP_PER_CPU`).

/// Each CPU's deferred-wake list head (`wake_list::NIL` when empty).
static REMOTE_WAKE_HEAD: [AtomicU32; MAX_CPUS] =
    [const { AtomicU32::new(crate::wake_list::NIL) }; MAX_CPUS];
/// The intrusive link of each task slot while it waits in a list.
static REMOTE_WAKE_NEXT: [AtomicU32; MAX_TASKS] =
    [const { AtomicU32::new(crate::wake_list::NIL) }; MAX_TASKS];
/// Wakes deferred / drained / dropped at the drain (slot no longer valid).
static REMOTE_WAKE_DEFERRED: AtomicU32 = AtomicU32::new(0);
static REMOTE_WAKE_DRAINED: AtomicU32 = AtomicU32::new(0);
static REMOTE_WAKE_STALE: AtomicU32 = AtomicU32::new(0);

/// (deferred, drained, stale) since boot: the evidence the path ran.
pub fn remote_wake_counts() -> (u32, u32, u32) {
    (
        REMOTE_WAKE_DEFERRED.load(Ordering::Relaxed),
        REMOTE_WAKE_DRAINED.load(Ordering::Relaxed),
        REMOTE_WAKE_STALE.load(Ordering::Relaxed),
    )
}

/// A remote wake's enqueue without the spin: `Some(appended)` when the
/// target's lock was free and its deferred list empty (queued here, exactly
/// as [`cpu_enqueue_locked`] would have); `None` when the caller must defer.
/// The list is tested under the lock, and the drain empties it under the
/// same lock, so a direct wake never overtakes a deferred one.
///
/// A target past the online prefix keeps the direct path: nothing runs its
/// `do_schedule` to drain, and `rebalance_from_offline_cpus` rescues only
/// what is in its queue.
#[inline(always)]
unsafe fn remote_wake_try(cpu: usize, idx: usize) -> Option<bool> {
    if cpu >= NUM_ONLINE_CPUS.load(Ordering::Relaxed) {
        return Some(cpu_enqueue_locked(cpu, idx));
    }
    let prev = azos_arch::ARCH.disable_all();
    if CPU_LOCKS[cpu].swap(1, Ordering::Acquire) != 0 {
        azos_arch::ARCH.restore(prev);
        return None;
    }
    if !crate::wake_list::is_empty(&REMOTE_WAKE_HEAD[cpu]) {
        CPU_LOCKS[cpu].store(0, Ordering::Release);
        azos_arch::ARCH.restore(prev);
        return None;
    }
    let appended = cpu_enqueue(cpu, idx);
    CPU_LOCKS[cpu].store(0, Ordering::Release);
    azos_arch::ARCH.restore(prev);
    ring_doorbell(cpu, idx, appended);
    Some(appended)
}

/// Queue this CPU's deferred wakes, oldest first. Called only from the
/// doorbell's interrupt arm on each ISA (owner decision: not at
/// `do_schedule` entry, which every context switch would pay). No wake is
/// lost before idle: every push is followed by the doorbell, and a pending
/// doorbell both ends `wfi` and is taken as soon as interrupts are
/// unmasked, whatever the hart was doing. One relaxed load when empty.
#[inline(always)]
unsafe fn remote_wake_drain_on(cpu: usize) {
    if azos_limits::SCHED_REMOTE_WAKE_DEFER
        && !crate::wake_list::is_empty(&REMOTE_WAKE_HEAD[cpu])
    {
        remote_wake_drain_slow(cpu);
    }
}

/// [`remote_wake_drain_on`] for the calling CPU, from any context (the IPI
/// arms of `kernel/src/entry/riscv64/irq.rs` and `kernel/src/entry/aarch64/trap.rs`).
pub fn drain_remote_wakes() {
    // NOHZ_FULL: every doorbell means a task was queued, or is about to be, on
    // this CPU. A tick stopped for want of one restarts here: the interrupt's
    // `schedule()` returns without `do_schedule` when the running RT task
    // keeps the CPU, and nothing else would end the stop before the residual
    // (the RT band's budget is charged only by a tick). A no-op when the tick
    // is running.
    if azos_limits::NOHZ_FULL {
        azos_drv_sys::timebase::tick_restart();
    }
    unsafe { remote_wake_drain_on(current_cpu_id()) }
}

#[inline(never)]
unsafe fn remote_wake_drain_slow(cpu: usize) {
    let valid = |i: usize| i < MAX_TASKS && TASK_VALID[i].load(Ordering::Relaxed);
    let _g = CpuLockGuard::acquire(cpu);
    let n = crate::wake_list::drain(&REMOTE_WAKE_HEAD[cpu], &REMOTE_WAKE_NEXT, |i| {
        if !valid(i) {
            REMOTE_WAKE_STALE.fetch_add(1, Ordering::Relaxed);
        } else if !cpu_enqueue(cpu, i) {
            WAKE_ENQ_REFUSED.fetch_add(1, Ordering::Relaxed);
        }
    });
    REMOTE_WAKE_DRAINED.fetch_add(n as u32, Ordering::Relaxed);
}

/// `cpu_enqueue_locked` for the wake paths (`try_wake_task`,
/// `wq_wake_by_tid`, `wake_task_by_tid`, `reap_stamped_sleepers`), with the
/// remote-wake deferral and the wakeup trace record. `false` means the queue
/// refused the enqueue (K-C26 discriminator 2), which callers that check it
/// count as `WAKE_ENQ_REFUSED`.
#[inline]
unsafe fn wake_enqueue_locked(cpu: usize, idx: usize) -> bool {
    let appended = enqueue_remote_aware(cpu, idx);
    // Wave 15 (TRACE): every wake that queues a task passes here.
    if azos_trace::sched_on() {
        azos_trace::raw::sched_wakeup(task_ref(idx).tid, cpu as u32, current_task_tid());
    }
    appended
}

/// [`cpu_enqueue_locked`] for a task that goes to another CPU's queue, with
/// the remote-wake deferral (`SCHED_REMOTE_WAKE_DEFER`): the wake paths'
/// enqueue without their trace record, and the one a balancing move uses.
/// `true` when the task is queued, or deferred and so certain to be.
#[inline(always)]
unsafe fn enqueue_remote_aware(cpu: usize, idx: usize) -> bool {
    // `SCHED_REMOTE_WAKE_DEFER`: another CPU's queue is never spun on — a
    // held lock defers the wake to that CPU (see `remote_wake_try`). Its own
    // queue keeps the direct path.
    if azos_limits::SCHED_REMOTE_WAKE_DEFER && cpu != current_cpu_id() {
        match remote_wake_try(cpu, idx) {
            Some(appended) => appended,
            None => {
                crate::wake_list::push(&REMOTE_WAKE_HEAD[cpu], &REMOTE_WAKE_NEXT, idx);
                REMOTE_WAKE_DEFERRED.fetch_add(1, Ordering::Relaxed);
                ring_doorbell(cpu, idx, true);
                // The refusal, if any, is counted by the drain.
                true
            }
        }
    } else {
        cpu_enqueue_locked(cpu, idx)
    }
}

/// Times the `context_saving` spin-gate hit its deadline and handed the task
/// back instead of dispatching it.
///
/// **Must stay zero.** A non-zero value means a task reached the gate with its
/// save still outstanding for over a millisecond, which is the IPC wedge —
/// now survivable, but still a defect.
/// Unlike the counters behind `ipc-census`, this one is always compiled: a
/// diagnostic that only exists in the instrumented build cannot report the
/// failure that happens on the board.
pub static SPIN_GATE_EXPIRED: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(0);

/// Reads [`SPIN_GATE_EXPIRED`].
pub fn spin_gate_expired() -> u32 {
    SPIN_GATE_EXPIRED.load(Ordering::Relaxed)
}

/// Times the priority guard sent a pick back rather than preempting a Running
/// task with a strictly worse one.
///
/// Instrumented because its absence hid a wedge. A captured hang showed
/// `do_schedule calls=2023433 switches=13026` with EVERY `unswitched` reason
/// reading zero — two million returns that no counter explained, because this
/// arm was the one return out of `do_schedule` that bumped nothing. A
/// breakdown with an unlabelled majority is worse than none: it reads as "all
/// paths accounted for" while the interesting one is invisible.
///
/// Always compiled, for the same reason as `SPIN_GATE_EXPIRED`: the failure it
/// reports is one that happens on the board, not only in the instrumented
/// build.
pub static PRIO_GUARD_NO_SWITCH: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(0);

/// Reads [`PRIO_GUARD_NO_SWITCH`].
pub fn prio_guard_no_switch() -> u32 {
    PRIO_GUARD_NO_SWITCH.load(Ordering::Relaxed)
}

// The audit below represents slot sets as bitmaps over task slots, sized from
// `MAX_TASKS`: one 64-bit word per 64 slots, so one word at the edge value (64)
// and 64 words at the fleet value (4096). `slot_bitmap.rs` depends on `core`
// alone, so `tests/host/sched-policy-tests` runs it on the host with slots past 63.
#[path = "../slot_bitmap.rs"]
mod slot_bitmap;

/// Words of the audit's slot bitmaps.
const SLOT_WORDS: usize = slot_bitmap::words_for(MAX_TASKS);

const _: () = assert!(
    slot_bitmap::SlotBitmap::<SLOT_WORDS>::capacity() >= MAX_TASKS,
    "ring_claim_audit's slot bitmap must hold a bit for every task slot (MAX_TASKS)",
);

/// Previous sample's `claim_no_entry` set, one word of 64 slots per entry, for
/// the persistence test below.
static PREV_CLAIM_NO_ENTRY: [core::sync::atomic::AtomicU64; SLOT_WORDS] =
    [const { core::sync::atomic::AtomicU64::new(0) }; SLOT_WORDS];

/// Ground truth for the `queued` claim: walk the rings and ask whether they
/// agree with the flag.
///
/// **Nothing else in this kernel checks this.** `queued` is the claim that
/// makes `cpu_enqueue` refuse a duplicate, and every diagnostic we have trusts
/// it — the census reports `READY-UNQUEUED` as `Ready && !queued`, so a task
/// whose claim says "queued" while no ring holds an entry for it is counted as
/// **healthy** and is invisible to every existing probe. That cousin would
/// wedge exactly like the shape we hunt, and would show `ready_unqueued=0`
/// while doing it.
///
/// Returns `(claim_no_entry, entry_no_claim, duplicate_entries, persistent)`,
/// all counts of task slots; each persistent slot is also printed by name
/// below. `persistent` was a `u64` mask of slots until the slot sets became
/// bitmaps sized from `MAX_TASKS`: a mask cannot name slot 64 and up, a count
/// can.
///
/// **Read without the CPU locks, deliberately.** This runs from the timer ISR
/// — the one context that still runs when tasks have stopped being scheduled,
/// which is the whole point — and taking `CPU_LOCKS` there can deadlock
/// against a hart interrupted while holding one. The cost is that a single
/// sample races the enqueue/dequeue windows and can disagree for a few
/// instructions. Hence `persistent`: the set of slots that claimed a queue
/// entry they did not have in **two consecutive samples**. A transient reads
/// as noise; only the persistent set is evidence.
///
/// **The walk must not be able to panic, and the first version could.**
/// It seeded the cursor straight from `q.head` and then did
/// `h = (h + 1) % MAX_TASKS`. A coherent `head` is always below `MAX_TASKS`,
/// so that add looks safe — but this read is unsynchronised, which is a data
/// race, and a racing read has no coherent value to reason about. Twice in a
/// hundred 8-way-concurrent runs the add overflowed and, with `panic = "abort"`
/// and `overflow-checks = true`, took the board down **from inside the timer
/// ISR**. A diagnostic that resets the machine it is diagnosing is worse than
/// no diagnostic; under this project's rules a reachable panic is a security
/// finding, and this one was reachable from the most privileged context there
/// is.
///
/// So every value that crosses the race boundary is read **once** and is
/// **clamped into range before it is used in arithmetic**. The cursor is
/// reduced mod `MAX_TASKS` before the loop rather than inside it, which alone
/// makes the increment unable to overflow; `wrapping_add` on top means the
/// no-panic property can be seen locally without having to trust the clamp
/// (`crate::task::ring_walk_bounds`, host-tested against `usize::MAX`).
/// (Wave 15: the queues are lists now; the walk is `ReadyList::iter`, bounded
/// by `count` and `MAX_TASKS`, every link range-checked before it is used, no
/// arithmetic on a raced value — the same no-panic property, host-tested in
/// `sched-wake-tests` against garbage links.)
/// Garbage samples still enter the result, and that is fine — absorbing them is
/// exactly what the two-sample `persistent` filter is for.
///
/// **The race itself is now well-defined, which it was not.** The reads used
/// to be `read_volatile` on plain `usize` fields, and volatile is not
/// synchronisation: it removes the compiler's licence to re-read or
/// re-materialise a value, not the language-level data race. The fields are
/// now `AtomicUsize`/`AtomicU32` read `Relaxed` (see [`PrioQueue`]), which
/// costs the write path zero instructions on RV64 — the same `ld`/`sd`, no
/// fence, no AMO — and makes an unsynchronised read a legal operation instead
/// of one the optimiser is entitled to assume never happens.
///
/// A seqlock was rejected, twice over. the former `azos_sync::SeqLock` (since
/// deleted) required a single writer, and this ring has documented multi-writer paths
/// (`boost_ready_task`/`restore_ready_task` mutate it with no `CPU_LOCKS` at
/// all, reachable from the donation paths), so the odd/even counter
/// could be left permanently odd. Worse, its `read()` spun until the
/// counter goes even — and the timer ISR fires on the *writing* hart between
/// the two `fetch_add`s, at which point the audit would spin inside the ISR
/// on a counter only the interrupted hart can advance. That is a guaranteed
/// self-deadlock, not a rare one, and it is the same hazard as taking the
/// lock here.
///
/// **What is still not fixed, stated rather than implied.** `Relaxed` fields
/// make each read legal; they do not give the reader a consistent *snapshot*,
/// and they do not repair the unlocked writers above — two harts storing
/// `count` concurrently is now defined behaviour that still loses an update
/// and still desynchronises `count` from `buf`. Both are exactly what the
/// two-sample `persistent` filter exists to absorb, and both are why it must
/// stay. Separately, this function also reads `TASK_VALID[i]` and, in the
/// reporting branch, `t.tid` / `t.name` / `t.priority`.
///
/// `TASK_VALID` and `t.priority` are now closed (see their docs). Both turned
/// out to be reachable only from within `crates/core/sched/` — checked, not
/// assumed: neither is used outside this crate under any name, and nothing
/// in the tree names `azos_sched::task::Task` at all even though it is,
/// technically, a public path. The "read from four other crates" in the
/// earlier version of this comment was true of the *concept* (`idx_for_tid`
/// et al. are called from `cap_store.rs`/`fastcall.rs`) but not of the
/// *fields*, which those crates never touch directly — they only ever see a
/// `u32`/`Option<u32>` already copied out by a function in this file.
///
/// `t.tid` and `t.name` remain open, for two different reasons.
///
/// `t.name` is a plain `[u8; 32]`: every use (`copy_from_slice`,
/// `iter().position`, `core::str::from_utf8`) needs a contiguous `&[u8]`,
/// which `[AtomicU8; 32]` cannot give without rewriting each of those call
/// sites as a byte-at-a-time loop. That is not "add `.load()`" — it is a
/// second change wearing this one's clothes, so it stays a plain field.
///
/// `t.tid` is reachability-clean the same way `priority` was (same crate-only
/// check, same result), so leaving it is a judgement call, not a constraint —
/// and the call is to leave it. `tid` is the payload of the `alloc_slot`/
/// `idx_for_tid` sentinel protocol documented on `TASK_VALID` and on
/// `alloc_slot` itself: `tid` is zeroed, a fence orders that write before the
/// slot is published, and a reader that observes the publish re-checks `tid`
/// behind a paired fence. Converting `TASK_VALID` closed the fence↔fence edge
/// (a standalone fence only synchronises through an atomic operation, and now
/// one exists) — but it did not touch the payload: `TASKS[i].tid` is still a
/// plain `u32`, still stored by `alloc_slot`/the free sites and read by
/// `idx_for_tid`'s unsynchronised scan with no atomic operation of its own, so
/// the ordering is fixed and the data race on the value itself is not. That
/// residual is exactly what makes converting it more than mechanical: the
/// sentinel protocol exists because a stale `tid` match let `cap_store`'s
/// owner-mismatch wipe hit the wrong task's capability table, so touching its
/// type means re-arguing that protocol's correctness, not appending
/// `.load()`/`.store()`. `priority` had no such protocol riding on it — its
/// unlocked writers are independent, order-insensitive donations (see its own
/// doc) — which is the actual reason it converted cleanly and `tid` does not.
pub fn ring_claim_audit() -> (u32, u32, u32, u32) {
    // On the stack, not in a static: every hart's timer interrupt can run this
    // at once. The trap runs on the interrupted task's kernel stack
    // (`trap_entry.S`: from U-mode `sscratch` holds it, from S-mode the stack
    // is already the kernel's), `KERNEL_STACK_SIZE_KB` = 32 KiB on RV64, 16 on
    // embedded. The
    // bitmap is `SLOT_WORDS` × 8 B: 8 B at the edge value, 512 B at fleet's.
    let mut present = slot_bitmap::SlotBitmap::<SLOT_WORDS>::new();
    let mut dup: u32 = 0;
    unsafe {
        for cpu in 0..ncpu() {
            // This walk runs from the timer ISR (`ipc-census`), and the first
            // tick can land before `setup_per_cpu_areas`: interrupts are on
            // from "[IRQ] Traps + interrupts active", the areas come after.
            // A CPU with no area yet holds POISON (gate, wave 15 integration:
            // `mem quota: refusals>0 (N)` took a kernel load fault at
            // 0xdeadc0de00000000 on its first census dump). Skip it, as
            // `azos_trace` does for its producers.
            if !PER_CPU_QUEUES.attached(cpu) {
                continue;
            }
            for prio in 0..NUM_PRIORITIES {
                let q = &cpu_queues(cpu)[prio];
                // Without the lock (see `PrioQueue`): the walk is bounded by
                // `count` and `MAX_TASKS` and stops at an out-of-range link, so
                // a raced list ends the walk early or shows a stale slot — the
                // same torn-sample shape the ring's racy reads had, absorbed
                // the same way (two-sample filter for missing entries).
                for idx in q.iter(&RQ_NEXT) {
                    if idx < MAX_TASKS && present.insert(idx) {
                        dup += 1;
                    }
                }
            }
        }

        // `slot_bitmap::claim_pass` compares each slot's claim with `present`
        // one word of 64 slots at a time, and `swap`s each word of this
        // sample's claim-without-entry set into `PREV_CLAIM_NO_ENTRY`, so a
        // slot that is clean for one tick starts its two-sample count over.
        // The intersection is `task.rs`'s pure function, applied per word;
        // the pass itself is host-tested with 4096 slots.
        //
        // One `swap` per word, where there used to be one: a sample is stored
        // word by word, and a hart running the audit concurrently can read
        // some words of this sample beside words of the previous one. That is
        // the same torn-sample shape as the ring reads above, and the
        // two-sample filter absorbs it the same way; at the edge value there
        // is one word, as before.
        let counts = slot_bitmap::claim_pass(
            &present,
            MAX_TASKS,
            |i| {
                if i < MAX_TASKS && TASK_VALID[i].load(Ordering::Relaxed) {
                    Some(TASKS[i].queued.load(Ordering::Acquire))
                } else {
                    None
                }
            },
            |w, mask| match PREV_CLAIM_NO_ENTRY.get(w) {
                Some(prev) => prev.swap(mask, Ordering::Relaxed),
                None => 0,
            },
            crate::task::claim_audit_persistent,
            |i| {
                if i >= MAX_TASKS { return; }
                let t = &TASKS[i];
                let len = t.name.iter().position(|&b| b == 0)
                    .unwrap_or(TASK_NAME_MAX_LEN);
                let name = core::str::from_utf8(&t.name[..len]).unwrap_or("<?>");
                azos_drv_sys::kprintln!(
                    "[SCHED] CLAIM-NO-ENTRY tid={} name={} state={:?} prio={} \
                     — claims a queue slot that no ring holds, twice running",
                    t.tid, name, t.state(), t.priority.load(Ordering::Relaxed),
                );
            },
        );

        (counts.claim_no_entry, counts.entry_no_claim, dup, counts.persistent)
    }
}

/// Allocate a free slot in TASKS[].
/// Caller must hold POOL_LOCK.
///
/// **The tid sentinel protocol (root fix for the `idx_for_tid` race).**
/// `TASK_VALID[i] = true` used to publish the slot while `TASKS[i].tid`
/// still carried the PREVIOUS occupant's TID; an unsynchronised scan
/// (`idx_for_tid` — cap_store's resolution path runs it without any lock)
/// could match a dead TID against a slot that now belongs to a brand-new
/// task, and the operation attributed to the dead TID then WIPED the live
/// task's cap table (`cap_store::claim_slot`'s owner-mismatch wipe). The
/// contained version (`resolve_only_untrusted`'s double scan) narrowed the
/// window; this closes it at the source: `tid` is cleared to 0 — the
/// "no task" sentinel `NEXT_TID` never issues — BEFORE the slot becomes
/// visible, with a Release fence ordering the plain `tid` store before the
/// `TASK_VALID` publish (RVWMO allows store-store reordering; without the
/// fence the fix is fiction). The free sites do the mirror image
/// (VALID=false, fence, tid=0), and `idx_for_tid` revalidates a match behind
/// an Acquire fence. See `TASK_VALID`'s own doc for why this pairing needs
/// `TASK_VALID` to be the atomic half of the pair — a fence has nothing to
/// synchronise-with through a plain store.
unsafe fn alloc_slot() -> Option<usize> {
    for i in 0..MAX_TASKS {
        if !TASK_VALID[i].load(Ordering::Relaxed) {
            TASKS[i].tid = 0;
            // U04-2 route (b): clear the previous occupant's "exiting"
            // publication before this slot is handed to a brand-new task
            // — see `TASK_EXITING`'s doc. Ordered by the same Release
            // fence as the tid clear, before `TASK_VALID` publishes the
            // slot.
            TASK_EXITING[i].store(false, Ordering::Relaxed);
            SUBREAPER[i].store(false, Ordering::Relaxed);
            EXIT_REPARENTS[i].store(false, Ordering::Relaxed);
            // A forced stop its previous occupant left counted is settled.
            stop_policy::forced_clear(&FORCED_ACCT[i], &FORCED_PENDING);
            core::sync::atomic::fence(Ordering::Release);
            TASK_VALID[i].store(true, Ordering::Relaxed);
            return Some(i);
        }
    }
    None
}

/// Get a mutable reference to TASKS[idx].
unsafe fn task_mut(idx: usize) -> &'static mut Task {
    &mut TASKS[idx]
}

/// K-C12 · Pick the CPU on which a task of priority `prio` will actually be
/// dispatched. Replaces the old `find_least_loaded_cpu()`.
///
/// See [`crate::task::pick_cpu_by_load`] for the policy and the ring-3
/// measurement behind it. Two things about *this* function are load-bearing
/// and were both learned the hard way:
///
/// **It scores residency, not the instantaneous queue state.** The first
/// version of this fix sampled `PER_CPU[c].ready_queues[..]` plus the task
/// running on `c`. That halved the loss rate and no more: `rt-motor` and
/// `flight-ctrl` are periodic, so there are windows in which both are
/// `Blocked` and hart 0 samples as completely idle. A child placed in one of
/// those windows is stuck behind them microseconds later, forever. What makes
/// a hart hostile to low-priority work is *which tasks live there*, not which
/// of them happen to be runnable at the instant of the sample.
///
/// **The ordering is `(rt_blocking, blocking, total)`, and the first key is
/// not decoration.** Ranking on `(blocking, total)` alone regressed once the
/// unpinned mid-priority tasks had spread out and every hart carried two
/// outranking residents: `total` then chose hart 0 — the hart dedicated to
/// `rt-motor` and `flight-ctrl` — precisely because all the earlier children
/// had gone elsewhere. See [`crate::task::pick_cpu_by_load`] for the measured
/// trace.
///
/// **`total` only breaks ties.** A hart with fifty same-priority tasks still
/// dispatches a newcomer (the fair queue gives every task its weighted share);
/// a hart with one permanently runnable higher-priority task never does.
/// Liveness therefore outranks balance, and on this kernel's default layout that means
/// unpinned work concentrates on the harts without real-time residents. That
/// is the correct trade: an unbalanced-but-running task beats a
/// balanced-and-starved one.
///
/// A task's home is its pin (`cpu_affinity`) when it has one, otherwise the
/// saved `tp` (`context.tp`, the CPU it last ran on or is queued for) — the
/// same value every wake path keeps in sync with the queue the task sits in.
///
/// `exclude` is the pool index of the task being placed, so it does not score
/// against its own placement. Pass `usize::MAX` for none.
///
/// **Cost, since this also runs from the timer ISR** (`wake_expired_timers` →
/// `try_wake_task` → `wake_target_cpu`, and `schedule()` carries
/// `#[wcet(30_us)]`): it is not a step up from what it replaces. The old
/// metric read `PER_CPU[c].ready_queues[p].count` for every `c` and every `p`
/// — `MAX_CPUS * NUM_PRIORITIES` = 128 reads, each `size_of::<PrioQueue>()`
/// (536 B) apart, i.e. 128 distinct cache lines. This reads at most
/// `MAX_TASKS` = 64 task slots, and everything it needs
/// (`state`/`priority`/`cpu_affinity` at offsets 132..145, `context.tp` at
/// 120) sits in two lines per slot — the same 128. Unlocked, exactly as the
/// old metric was: a stale sample costs one suboptimal placement, never
/// correctness.
///
/// Uses NUM_ONLINE_CPUS to limit the search. Acquire load pairs with the
/// SeqCst stores in kernel_main: the pre-wake_harts store (so secondaries
/// observe the published task pool) and the post-wake_harts correction (so a
/// hart that never started is excluded instead of looking permanently idle).
/// The O(`MAX_TASKS`) full scan (U02-3's finding: paid from the timer ISR
/// on every wake, and under `POOL_LOCK` on every fork). Kept unconditionally:
/// it is the whole algorithm when `sched-o1-placement` is off, and (under
/// `ipc-census`) the ground truth the histogram path below cross-checks
/// itself against on every call, live, in a real boot — not only on the
/// host's synthetic replay.
#[cfg_attr(
    all(feature = "sched-o1-placement", not(feature = "ipc-census")),
    allow(dead_code)
)]
unsafe fn find_best_cpu_scan(prio: u32, exclude: usize, num_online: usize) -> [CpuLoad; MAX_CPUS] {
    let bucket = prio_bucket(prio);
    let mut loads = [CpuLoad { rt_blocking: 0, blocking: 0, total: 0 }; MAX_CPUS];
    for i in 0..MAX_TASKS {
        if i == exclude || !TASK_VALID[i].load(Ordering::Relaxed) {
            continue;
        }
        let t = &TASKS[i];
        // A Zombie is on its way out and will never contend again.
        if t.state() == TaskState::Zombie {
            continue;
        }
        let home = if t.cpu_affinity >= 0 {
            (t.cpu_affinity as usize).min(ncpu() - 1)
        } else {
            (t.context.tp as usize).min(ncpu() - 1)
        };
        if home >= num_online {
            continue;
        }
        // The whole rule lives in `task::resident_load_contribution`, which is
        // pure and host-tested; this loop only sums it.
        //
        // Hoisted into a local for the same reason `cpu_remove` hoists
        // `head`/`count`: an atomic load, unlike the plain field it replaced,
        // is not something the compiler may CSE across two uses on its own —
        // it must observe a value that was actually stored, so two `load`s
        // are two loads. This runs in the timer-ISR path (`find_best_cpu` is
        // reachable from `wake_expired_timers` → `try_wake_task` →
        // `wake_target_cpu`, and `schedule()` above it carries
        // `#[wcet(30_us)]`), so paying for a second `lw` per resident, once
        // per invocation, instead of once, is the wrong default.
        let t_prio = t.priority.load(Ordering::Relaxed);
        let (rt, blk, tot) = crate::task::resident_load_contribution(
            t.state(),
            prio_bucket(t_prio),
            is_rt_priority(t_prio),
            bucket,
        );
        loads[home].total       = loads[home].total.saturating_add(tot);
        loads[home].blocking    = loads[home].blocking.saturating_add(blk);
        loads[home].rt_blocking = loads[home].rt_blocking.saturating_add(rt);
    }
    loads
}

#[cfg(not(feature = "sched-o1-placement"))]
unsafe fn find_best_cpu(prio: u32, exclude: usize) -> usize {
    let num_online = NUM_ONLINE_CPUS.load(Ordering::Acquire).min(MAX_CPUS);
    if num_online <= 1 {
        return 0;
    }
    let loads = find_best_cpu_scan(prio, exclude, num_online);
    pick_cpu_by_load(&loads[..num_online])
}

/// `ipc-census` cross-check of the histogram against `find_best_cpu_scan`,
/// run on every placement query: how many queries were checked, how many
/// disagreed on any online CPU's score, and how many of those changed the
/// CPU picked. A wiring bug drifts the histogram permanently, so it shows
/// as a mismatch on nearly every query after the first; a query racing a
/// transition on another hart shows as a rare one.
#[cfg(all(feature = "sched-o1-placement", feature = "ipc-census"))]
#[path = "../hist_check.rs"]
pub mod hist_check;

/// U02-3 task 3a: `find_best_cpu` via the O(`NUM_PRIORITIES`) histogram
/// instead of the O(`MAX_TASKS`) scan above. `exclude`'s recorded key is
/// subtracted (`load_excluding`) — the histogram equivalent of the scan's
/// `if i == exclude { continue }`.
#[cfg(feature = "sched-o1-placement")]
unsafe fn find_best_cpu(prio: u32, exclude: usize) -> usize {
    let num_online = NUM_ONLINE_CPUS.load(Ordering::Acquire).min(MAX_CPUS);
    if num_online <= 1 {
        return 0;
    }
    let bucket = prio_bucket(prio);
    let excluded_key = if exclude < MAX_TASKS {
        HIST_KEY[exclude].load(Ordering::Relaxed)
    } else {
        resident_histogram::key::NONE
    };
    let rt_threshold = crate::task::RT_PRIORITY_THRESHOLD as usize;
    let mut loads = [CpuLoad { rt_blocking: 0, blocking: 0, total: 0 }; MAX_CPUS];
    for (cpu, slot) in loads.iter_mut().enumerate().take(num_online) {
        *slot = RESIDENT_HIST.load_excluding(cpu, bucket, rt_threshold, &[excluded_key]);
    }
    let pick = pick_cpu_by_load(&loads[..num_online]);

    #[cfg(feature = "ipc-census")]
    {
        use hist_check::{CHECKS, MISMATCH, PICK_DIFF};
        let n = CHECKS.fetch_add(1, Ordering::Relaxed).wrapping_add(1);
        let scanned = find_best_cpu_scan(prio, exclude, num_online);
        if scanned[..num_online] != loads[..num_online] {
            let m = MISMATCH.fetch_add(1, Ordering::Relaxed);
            if hist_check::any_stale_key() {
                hist_check::MISMATCH_STALE_KEY.fetch_add(1, Ordering::Relaxed);
            } else {
                hist_check::MISMATCH_NO_STALE_KEY.fetch_add(1, Ordering::Relaxed);
            }
            if pick_cpu_by_load(&scanned[..num_online]) != pick {
                PICK_DIFF.fetch_add(1, Ordering::Relaxed);
            }
            // First mismatch only, in detail (this runs from the tick ISR:
            // an unbounded print would make the console the bottleneck).
            if m == 0 {
                if let Some(c) = (0..num_online).find(|&c| scanned[c] != loads[c]) {
                    azos_drv_sys::kprintln!(
                        "[SCHED] HISTOGRAM_MISMATCH first: prio={} exclude={} xkey={:#x} \
                         cpu={} hist=({},{},{}) scan=({},{},{})",
                        prio, exclude, excluded_key, c,
                        loads[c].rt_blocking, loads[c].blocking, loads[c].total,
                        scanned[c].rt_blocking, scanned[c].blocking, scanned[c].total,
                    );
                }
            }
        }
        // Running tally at powers of two from 64 on: a bounded number of
        // lines, and the rate is readable from any one of them.
        if n >= 64 && n.is_power_of_two() {
            azos_drv_sys::kprintln!(
                "[SCHED] hist-check checks={} mismatches={} pick_diff={} stale_key={} \
                 no_stale_key={} drift={} audits={}",
                n, MISMATCH.load(Ordering::Relaxed), PICK_DIFF.load(Ordering::Relaxed),
                hist_check::MISMATCH_STALE_KEY.load(Ordering::Relaxed),
                hist_check::MISMATCH_NO_STALE_KEY.load(Ordering::Relaxed),
                hist_check::DRIFT.load(Ordering::Relaxed),
                hist_check::AUDITS.load(Ordering::Relaxed),
            );
        }
    }

    pick
}

/// Pick target CPU respecting affinity.
/// If affinity >= 0, returns that hart directly; otherwise the hart where a
/// task of priority `prio` will actually get dispatched (K-C12).
unsafe fn pick_target_cpu(affinity: i8, prio: u32, exclude: usize) -> usize {
    if affinity >= 0 {
        // K-A13: clamp — an out-of-range affinity (a bad literal at a call
        // site; not reachable from userspace today) must not index
        // CPU_LOCKS/PER_CPU out of bounds and panic.
        (affinity as usize).min(ncpu() - 1)
    } else {
        find_best_cpu(prio, exclude)
    }
}

// ---- Task entry wrapper ----

/// Entry point for every new task (called from context_switch assembly).
///
/// Reads `entry_fn` and `entry_arg` from the current task struct, calls them.
/// When entry_fn returns, calls `task_exit()`.
///
/// # Safety
/// Called from assembly with C ABI. No arguments passed via registers.
/// `tp` must contain the current hart_id.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn task_entry_wrapper() {
    let cpu = current_cpu_id();
    let idx = PER_CPU[cpu].current_idx.load(Ordering::Relaxed);
    // A task's first instructions after the switch that started it.
    finish_switch(task_mut(idx) as *mut Task);

    // Enable interrupts — required when first entered from a timer ISR
    // (hardware clears SIE on interrupt entry; sret would restore it, but we
    // jumped here via context_switch instead of returning via sret).
    // Also harmless when entered from start() which is not in interrupt context.
    azos_arch::ARCH.enable_all();

    let entry_fn: fn(usize) = core::mem::transmute(task_mut(idx).entry_fn);
    let arg = task_mut(idx).entry_arg;
    entry_fn(arg);

    // Task function returned — clean up.
    task_exit();
}

unsafe fn do_schedule(why: SwitchReason) {
    // The hart is read HERE, with interrupts off, never taken from the
    // caller (CTXHUNT, 2026-10-08). `task_exit_with_code` read its `cpu` on
    // entry, then waited in `group_exit` (a leader waits for its threads)
    // and could be woken on another hart: its `do_schedule(cpu)` then ran
    // there with the old hart's id, read that hart's `current_idx` as `old`,
    // dequeued from its queue and published a task there while switching
    // on this one. Measured with `ctx-probe`: every fault of the fork +
    // thread exit storm began as "`cpu` is not this hart" in a
    // `do_schedule` called from the exit path. A caller can no longer hand
    // it a stale id.
    let cpu = current_cpu_id();
    #[cfg(feature = "exit-stale-hart-canary")]
    let cpu = stale_hart_canary::take(cpu);
    #[cfg(feature = "ctx-probe")]
    {
        ctx_probe::check_running(ctx_probe::ENTRY);
        if azos_arch::Interrupts::interrupts_enabled(&azos_arch::ARCH) {
            ctx_probe::fail(ctx_probe::ENTRY, cpu, PER_CPU[cpu].current_idx.load(Ordering::Relaxed), usize::MAX, "irqs_on_at_entry", 0);
        }
    }
    #[cfg(feature = "ipc-census")]
    {
        unswitched::bump(&unswitched::CALLS);
        let ci = PER_CPU[cpu].current_idx.load(Ordering::Relaxed);
        if ci < MAX_TASKS { SCHED_BY_TASK[ci].fetch_add(1, Ordering::Relaxed); }
    }
    // EEVDF: a running fair task is charged to now, so that the pick sees its
    // true virtual runtime, and one that yields moves its deadline a slice on.
    fairq::begin(cpu, matches!(why, SwitchReason::Voluntary));
    // SCHED_BALANCE: a CPU left with nothing to run but idle takes work from
    // another one before it picks.
    fairq::balance_idle(cpu, PER_CPU[cpu].current_idx.load(Ordering::Relaxed));
    // The RT pick says the running task must yield even to a worse priority
    // (its band is exhausted, or its reservation is throttled).
    let mut rt_force = false;
    // SCHED_CORE: a sibling that reserved the core for another Domain (a band
    // task, or a fair one that waited) displaces what this hart runs: the pick
    // is its idle task.
    let smt = core_smt(cpu);
    let core_idle = if smt != 0 && topo::CORE.must_yield(smt, cpu, core_now()) {
        cpu_take_idle(cpu)
    } else {
        None
    };
    let next_idx = {
        // Bitmap-based priority queue. A hart with RT state (`rt::active`)
        // picks through `rt::pick` instead: the band levels skipped while the
        // band is exhausted and something else is ready, reservation tasks
        // first in their level by deadline, throttled reservations skipped.
        // `Keep` is "nothing better than the running task", the same answer
        // an empty queue gives.
        let picked = if core_idle.is_some() {
            core_idle
        } else if rt::active(cpu) {
            match rt::pick(cpu, PER_CPU[cpu].current_idx.load(Ordering::Relaxed)) {
                rt::Pick::Task { idx, force } => { rt_force = force; Some(idx) }
                rt::Pick::Keep => None,
            }
        } else {
            cpu_dequeue_irqs_off(cpu)
        };
        match picked {
            Some(idx) => idx,
            // "caller will idle" is true for the timer-tick caller. It is NOT
            // true for `block_current`, which returns to the syscall and then
            // to ring 3 — with this task's state already published `Blocked`.
            None => {
                #[cfg(feature = "ipc-census")]
                unsafe {
                    unswitched::bump(if current_is_blocked(cpu) {
                        &unswitched::QUEUE_EMPTY_BLOCKED
                    } else { &unswitched::QUEUE_EMPTY_OK });
                }
                tickless_rearm_if_idle(cpu);
                clear_saving_on_no_switch(cpu);
                return;
            }
        }
    };

    crate::swcensus::picked();
    let old_idx = PER_CPU[cpu].current_idx.load(Ordering::Relaxed);
    // Wave 15 (SWITCH): each task's slot is computed once for the whole
    // switch (bounds check and index arithmetic), not at every use. Raw
    // pointers: `next` and `old` may be the same slot until the self-pick
    // test below, and the Zombie arm frees `old`'s slot (`old_slot_freed`).
    // (Deferring `old_t` past the self-pick measured worse on both ISAs.)
    let next_t: *mut Task = task_mut(next_idx);
    let old_t: *mut Task = if old_idx != usize::MAX {
        task_mut(old_idx) as *mut Task
    } else {
        core::ptr::null_mut()
    };

    // A strictly WORSE-priority pick must not preempt a Running current.
    //
    // **WHY this is needed at all.** This function picks `next` *before* it
    // re-enqueues `old`, so the outgoing task is not a candidate in its own
    // selection. While every hart's queue was empty that never showed: the
    // pick failed and the early return kept the current task running. Adding
    // one idle task per hart made the queue never-empty, and suddenly every
    // voluntary `yield` switched to `idle` — which WFIs, so the hart then sat
    // until the next 100 Hz tick. Measured: `sched-yield` went from ~4 us to
    // ~14 ms, a 3500x regression, with the doorbell working correctly (a
    // self-enqueue rings no doorbell, by design, because "this hart is awake"
    // — an assumption that breaks the moment the hart switches to idle).
    //
    // The guard is about priority, not about idle: idle is simply the first
    // task low-priority enough to expose it. Between two fair tasks it does
    // not apply: their order is EEVDF's (a weight, not a priority), and the
    // pick already weighed the running one.
    // Not when the RT pick forces the switch (`rt_force`): a band task past its
    // budget, or a throttled reservation, must yield to a worse priority —
    // that is the whole point of the budget.
    if !rt_force && core_idle.is_none() && old_idx < MAX_TASKS && next_idx != old_idx {
        let old = &*old_t;
        let (op, np) = (old.priority.load(Ordering::Relaxed), (*next_t).priority.load(Ordering::Relaxed));
        if old.state() == TaskState::Running
            && np > op
            && !(fairq::is_fair(op) && fairq::is_fair(np))
        {
            // Put the pick back: the selection above consumed a queue entry,
            // and dropping it here would leak the task out of every run queue
            // while leaving it Ready — the exact K-C26 shape guarded below.
            if !cpu_requeue_self(cpu, next_idx) {
                SCHED_ENQ_REFUSED.fetch_add(1, Ordering::Relaxed);
            }
            PRIO_GUARD_NO_SWITCH.fetch_add(1, Ordering::Relaxed);
            clear_saving_on_no_switch(cpu);
            return;
        }
    }

    // Don't switch if we'd switch to ourselves.
    if next_idx == old_idx {
        // K-C26: put it back. The pick above **consumed** a queue entry
        // (`cpu_dequeue_locked` pops and clears `queued`), so returning here
        // without re-enqueueing leaks the task out of every run queue while
        // leaving it `Ready`.
        //
        // On its own that looked harmless — the task is still `current_idx` on
        // this hart, so it simply keeps running. It is the *second* step that
        // makes it terminal: the re-enqueue arm below only puts the outgoing
        // task back `if old.state() == TaskState::Running`, and this one is
        // `Ready`. So the next `do_schedule` on this hart picks somebody else,
        // moves `current_idx` away, and the task is left **Ready, in no queue,
        // and current on no hart** — with nothing that will ever look at it
        // again. That is the K-C26 terminal signature exactly.
        //
        // Measured genesis: the victim's `ready_site` reads `wake` — a waker
        // had legitimately dispatched and enqueued it — and `sched_enq_refused`
        // is 0, so no enqueue was ever refused. The entry was not rejected; it
        // was consumed here and dropped.
        //
        // Re-enqueueing restores the invariant the rest of the file assumes:
        // every dequeue is matched by either a dispatch or a re-enqueue.
        // Re-enqueue ONLY if this task is still runnable. Putting a `Blocked`
        // task back into a ready queue is how it gets dequeued again on the
        // next pass, matched as `next_idx == old_idx`, and re-enqueued once
        // more -- a self-feeding loop that keeps a blocked task circulating
        // through the run queue. Measured at 12906 iterations in one run
        // before this check; `blocked_queued` in the census is the same shape
        // seen from the other side.
        // **The predicate is "not Blocked", NOT "is Running".** A first cut
        // used `== Running` and that silently reintroduced K-C26 genesis 1:
        // the task reaching this arm is frequently `Ready` (it was dequeued a
        // moment ago and has not been dispatched yet), so `== Running` skips
        // the re-enqueue and leaks it out of every run queue while leaving it
        // `Ready` — nothing will ever look at it again. That is the exact
        // shape the census reports as `READY-UNQUEUED ... by=create`.
        //
        // `Blocked` must NOT go back: a blocked task in a ready queue gets
        // dequeued next pass, matches `next_idx == old_idx` again, and is
        // re-enqueued once more — a self-feeding loop measured at 12906
        // iterations in one run.
        match (*next_t).state() {
            TaskState::Blocked | TaskState::Zombie => {}
            _ => {
                if !cpu_requeue_self(cpu, next_idx) {
                    SCHED_ENQ_REFUSED.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
        #[cfg(feature = "ipc-census")]
        {
            wakelat::measure(next_idx);
            unswitched::bump(if current_is_blocked(cpu) {
                &unswitched::SELF_PICK_BLOCKED
            } else { &unswitched::SELF_PICK_OK });
        }

        // M04 tickless hook (1 of 2) — self-pick.
        //
        // This is the path the idle task's OWN loop hits on every single
        // wakeup: `idle_task`/`aarch64_idle_task` (`kernel/src/tasks/system.rs`,
        // outside this wave's file ownership) is `loop { wfi();
        // task_yield(); }`, `task_yield()` calls `do_schedule()`
        // unconditionally, and with nothing else ready `cpu_dequeue_locked`
        // re-finds idle itself — `next_idx == old_idx`, this arm. A REAL
        // (non-idle) task alone on its own ready queue self-picks here too
        // (an ordinary voluntary yield with nobody else to hand the CPU
        // to), which is why this is gated on `IDLE_PRIORITY` specifically:
        // ungated, every lone-task `task_yield()` would pay a hardware
        // timer write it does not need, on the exact path `sched-yield`
        // measures.
        //
        // "No runnable task" test: `task_ref(next_idx).priority ==
        // IDLE_PRIORITY`. Not a `ready_bitmap` peek — `cpu_dequeue_locked`
        // just proved nothing higher-priority was ready by finding idle
        // itself here; a second peek would be redundant, not more correct.
        if (*next_t).priority.load(Ordering::Relaxed) == crate::task::IDLE_PRIORITY {
            azos_drv_sys::timebase::set_next_tick_tickless(
                cpu as u32, nearest_timer_deadline(), true,
            );
            rt::rearm(cpu);
        }

        clear_saving_on_no_switch(cpu);
        return;
    }

    // SCHED_CORE: the pick must fit the siblings' Domains (`topo::core_pick`).
    // A candidate that does not goes back to the queue and the next best is
    // taken; with none that fits the running task keeps the hart, or the
    // hart idles. The running task is not kept when the RT pick forces it
    // off, nor when a sibling is displaced for a refused candidate.
    let (next_idx, next_t) = if smt != 0 {
        let old_runs = !rt_force
            && core_idle.is_none()
            && old_idx < MAX_TASKS
            && (*old_t).state() == TaskState::Running;
        let old_prio = if old_runs { (*old_t).priority.load(Ordering::Relaxed) } else { 0 };
        let mut stash = [usize::MAX; azos_limits::SCHED_CORE_SCAN as usize];
        let pick = topo::core_pick(
            &topo::CORE,
            &CorePick {
                smt,
                cpu,
                now: core_now(),
                patience: CORE_PATIENCE,
                old_runs,
                old_idle: old_runs && old_prio == crate::task::IDLE_PRIORITY,
            },
            next_idx,
            &mut stash,
            |i| core_claim_of(cpu, i),
            || cpu_dequeue_irqs_off(cpu),
            // The guard above, for a redrawn candidate.
            |i| {
                let np = (*task_mut(i)).priority.load(Ordering::Relaxed);
                np > old_prio && !(fairq::is_fair(old_prio) && fairq::is_fair(np))
            },
            || cpu_take_idle(cpu),
        );
        for &i in &stash[..pick.stashed] {
            if !cpu_requeue_self(cpu, i) {
                SCHED_ENQ_REFUSED.fetch_add(1, Ordering::Relaxed);
            }
        }
        let mut sib = pick.kick;
        while sib != 0 {
            kick_hart(sib.trailing_zeros() as usize);
            sib &= sib - 1;
        }
        match pick.run {
            Some(i) => (i, task_mut(i) as *mut Task),
            None => {
                clear_saving_on_no_switch(cpu);
                return;
            }
        }
    } else {
        (next_idx, next_t)
    };

    // Re-enqueue old task if it is still runnable.
    // Set for a Zombie (the arm below): its context is not saved, and its
    // slot is freed after the switch (`finish_switch`), so nothing here may
    // write to it — see the `old_ptr` selection at the bottom.
    let mut old_slot_freed = false;
    // `old` is a Zombie whose slot `next` frees when it resumes.
    let mut old_zombie = false;
    if old_idx != usize::MAX {
        let old = &mut *old_t;
        if old.state() == TaskState::Running {
            // Same protection as block_current(): mark in-transit before
            // this task becomes visible/dispatchable via the ready queue.
            old.context_saving.store(true, Ordering::Relaxed);
            old.set_state(TaskState::Ready);
            old.ready_site.store(
                crate::task::ready_site::PREEMPT | ((cpu as u8) << 4),
                Ordering::Relaxed,
            );
            // K-C26 discriminator 2: `set_state(Ready)` above already happened,
            // so a refusal here leaves this task Ready and in no queue — the
            // terminal signature. Counted, not ignored.
            if !cpu_requeue_self(cpu, old_idx) { // enqueues at old.priority level
                SCHED_ENQ_REFUSED.fetch_add(1, Ordering::Relaxed);
            }
        } else if old.state() == TaskState::Zombie {
            // The slot is freed only once this hart is off its stack, by
            // the task switched to (`finish_switch`). Gate canary only: free
            // it here, as before, and hold the hart on the freed stack 2 ms.
            // A hand-out of the slot inside the hold (`alloc_slot` on another
            // hart: two harts on one stack) panics at once, by name. Waiting
            // for a corruption to fault instead made the canary a race: on
            // aarch64 `-smp 2` it left the kernel working in 2 of 3 quiet
            // boots (FX6, gate 8cd61b5a).
            if cfg!(feature = "reap-window-canary") {
                reap_zombie_on_switch(old_idx);
                let until = azos_drv_sys::timebase::now() + azos_drv_sys::timebase::TIMER_FREQ / 500;
                while azos_drv_sys::timebase::now() < until {
                    if TASK_VALID[old_idx].load(Ordering::Acquire) {
                        panic!("reap-window-canary: slot {} handed to a new task while its hart still runs on its stack", old_idx);
                    }
                    core::hint::spin_loop();
                }
            } else {
                // Its reservation leaves the hart's set now, as it did when
                // the reap ran here: the dispatch tail below (`rt::on_switch_prio`)
                // must not see it. `reap_zombie_on_switch` repeats it (a no-op).
                rt::release(old_idx);
                old_zombie = true;
            }
            old_slot_freed = true;
        } else if old.state() == TaskState::Blocked {
            // EEVDF: a fair task that blocks keeps its lag (`fairq::sleep`).
            fairq::sleep(cpu, old_idx);
            // K-C24 tail: a stamp that landed while this task ran past an
            // unswitched block (see `sched_word::wake_transition`) is a
            // DELIVERED wake — parking the task asleep with it would lose
            // it forever, because no waker will fire again for a condition
            // it already announced. Convert stamp → Ready + enqueue as we
            // switch away: `context_saving` is already true (block_current
            // set it), so a hart that dequeues this task spins until our
            // context_switch below finishes the save — the gate's original
            // purpose. CAS loop because K-C24 stampers race this window.
            loop {
                use crate::task::sched_word::{pack, WAKE_STAMP};
                let curw = old.state_word.load(Ordering::Acquire);
                if curw & WAKE_STAMP == 0
                    || crate::task::sched_word::state_of(curw) != TaskState::Blocked
                {
                    break;
                }
                if old.state_word.compare_exchange_weak(
                    curw, pack(TaskState::Ready),
                    Ordering::AcqRel, Ordering::Relaxed,
                ).is_ok() {
                    hist_reaccount(old_idx);
                    old.wait_reason = WaitReason::None;
                    old.ready_site.store(
                        crate::task::ready_site::KC24_RESCUE | ((cpu as u8) << 4),
                        Ordering::Relaxed,
                    );
                    // K-C26 discriminator 2, SECOND arm. The first pass
                    // instrumented only the Running re-enqueue below and
                    // reported "answered NO" on half the evidence — this arm
                    // was named in the same discriminator and was missed.
                    // Same hazard, same shape: the CAS above already published
                    // `Ready`, so a refusal here strands the task in no queue.
                    if !cpu_enqueue_locked(cpu, old_idx) {
                        SCHED_ENQ_REFUSED.fetch_add(1, Ordering::Relaxed);
                    } else {
                        // Wave 13 (RT7): the enqueue's "self-enqueue needs no
                        // doorbell" premise does not hold HERE. This hart
                        // picked `next` above, before the rescue — with an
                        // empty queue that is idle, which goes back to `wfi`
                        // on a tickless hart (comparator at u64::MAX), and
                        // nothing ever looks at the queue again: the rescued
                        // task sits Ready forever. Found as the vsbench
                        // spawn+wait hang (2 in ~105 heap-on boots): gdb
                        // showed autorun `Ready`, `ready_site` KC24_RESCUE on
                        // hart 3, every hart in `wfi`, harts 1-3 at u64::MAX.
                        // A doorbell to this hart is pending across the
                        // switch: idle's `wfi` returns at once and its
                        // `task_yield` dequeues the task.
                        kick_hart(cpu);
                        KC24_RESCUE_KICKS.fetch_add(1, Ordering::Relaxed);
                    }
                    break;
                }
            }
        }
    }

    crate::swcensus::requeued();
    // Activate next task.
    let next = &mut *next_t;
    // If `next` is mid-transition (context_saving == true — e.g. this
    // exact task was just preempted/blocked on another hart and its
    // context_switch.S save hasn't finished yet), wait for it. The
    // window is a handful of instructions in the common case; see the
    // fence+store tail of the save path in context_switch.S / the
    // context_saving field doc.
    //
    // **This used to be compiled out under `--features rvv`**, because
    // context_switch_rvv.S never cleared `context_saving` and the gate would
    // have spun forever. That file now clears it with the same fence+sb tail
    // (K-C23), so the exemption is gone and both builds take this path — the
    // twelve divergent `cfg` sites this comment was the largest of are all
    // deleted. An rvv build is a scheduler-identical build again.
    {
        // **Bounded.** This gate used to spin forever, and the audit recorded
        // the risk honestly: a `Blocked` task keeps `context_saving` set (see
        // `clear_saving_on_no_switch`, where clearing it unconditionally is a
        // worse bug), so if such a task ever became selectable the hart picking
        // it would spin until the board was power-cycled. It was unreachable
        // "by construction, not by defence" -- and a construction argument is
        // exactly what a hardware bring-up invalidates.
        //
        // **A wall-clock deadline, not a spin count**, for the reason the
        // virtio-blk timeout was rewritten: a spin count buys a different
        // amount of real time on QEMU, the VF2 and the K1, so it is the kind
        // of budget that works on the desk and fails on the board. 1 ms (the
        // SCHED_SAVING_GATE_US default) is ~100x any legitimate wait here
        // (the save tail is a handful of instructions) and 10x below the
        // 100 Hz tick, so it cannot fire on a healthy switch and cannot hide
        // a wedge for a whole tick.
        //
        // The clock is read once per 256 spins: `get_time` on the CLINT is a
        // device read, and putting one in a tight retry loop would make the
        // gate expensive in the common case, which is the case that matters.
        // Wave 15 (SWITCH): and not at all when the flag is already clear,
        // which is every switch on one hart — the wait is out of line.
        let expired = next.context_saving.load(Ordering::Acquire)
            && !wait_context_saved(next);
        if expired {
            // **Give the task back rather than dispatching it.** Restoring a
            // context nobody has finished saving is the double-dispatch
            // corruption this gate exists to prevent, so waiting it out is not
            // optional -- but neither is hanging. Put it back where the
            // ordinary machinery will find it again and return without
            // switching; the hart idles or takes its next tick, and the task
            // is retried with the flag presumably settled.
            //
            // Safe: the pick dequeued it, so it is nowhere, and
            // `Ready` + enqueue is the one state that is legal.
            // `cpu_enqueue_locked` refuses a task that is somehow still
            // queued, so this cannot double-list it.
            // The RT pick (`rt::pick`) removes its task from the ring with
            // `cpu_remove` under the CPU lock, so the same holds for it. (The
            // old EDF pick claimed `Running` without leaving its ring, U02-4;
            // it is deleted.)
            SPIN_GATE_EXPIRED.fetch_add(1, Ordering::Relaxed);
            next.set_state(TaskState::Ready);
            if !cpu_requeue_self(cpu, next_idx) {
                SCHED_ENQ_REFUSED.fetch_add(1, Ordering::Relaxed);
            }
            clear_saving_on_no_switch(cpu);
            return;
        }
    }
    crate::swcensus::gated();
    #[cfg(feature = "ipc-census")]
    wakelat::measure(next_idx);
    next.set_state(TaskState::Running);
    set_current_task(cpu, next_idx);
    // The hart that dispatches a task records itself in the task's saved
    // `tp` (wave 13, RT7), the CPU the task last ran on, which the wake and
    // balance paths read as its home. Every enqueue path is meant to have set
    // it already (`context.tp = target_cpu`), but a store made while the
    // task's previous hart was still saving it is overwritten by that save
    // (`sd tp, CTX_TP`). Here the dispatch gate above has seen the save
    // finish, so this store is the last word. Bookkeeping only since K1 M2:
    // no switch loads the word into the hart's `tp` (riscv64's used to, and a
    // stale one made the hart run as another CPU).
    next.context.tp = cpu as CtxReg;
    if old_zombie {
        next.reap_on_resume = old_idx + 1;
    }

    // A zombie whose slot was just freed gets NULL, exactly like "no old
    // task": its registers are dead by definition (the task can never run
    // again), and the slot is already claimable — `context_switch`'s save
    // path would write 128 bytes of registers plus the `context_saving`
    // clear into memory a concurrent `task_create` may be initializing.
    // The asm's `beqz a0, restore_new_task` skips the save entirely, which
    // also shrinks the K-C6 tail (this hart still runs on the zombie's
    // stack until the new sp is loaded) from the full save path to a few
    // instructions. With NULL the call never returns to this frame — there
    // is nothing after it, and no live state on this stack to return to.
    let old_ptr = if old_idx != usize::MAX && !old_slot_freed {
        old_t
    } else {
        // No old task to save: first run, post-task_exit idle hand-off, or
        // a freed zombie slot (see above).
        core::ptr::null_mut()
    };

    #[cfg(feature = "ipc-census")]
    unswitched::bump(&unswitched::SWITCHED);

    // K-C29: the last gate before the switch actually happens. Every path into
    // *this* `context_switch` is supposed to have been admitted by
    // `tick_admit`, `voluntary_admission`, or the exit override — this proves
    // it rather than assuming it. (The other `context_switch` call site,
    // `start()`'s `context_switch(null_mut(), next)`, runs once at boot before
    // any task exists and so cannot have a guard open; it is deliberately not
    // gated.) **Always compiled**, unlike the census counters: an
    // invariant nobody checks in the shipping build is an invariant nobody
    // has. The forced zero is damage limitation, not a fix: switching away
    // with a stale depth would leave the incoming task's hart permanently
    // non-preemptible, so leaking one critical section is strictly better than
    // wedging the hart. A non-zero counter means a caller was missed.
    if azos_sync::preempt::disabled() {
        preempt_audit::bump(&preempt_audit::SWITCH_WHILE_ATOMIC);
        azos_sync::preempt::force_zero_depth();
    }

    // Counted HERE and nowhere else: this is the one place a task actually
    // loses the CPU, so a counter anywhere else would drift from reality. In
    // particular a `task_yield` that finds nothing better never reaches this
    // line, and must not be counted — Linux's `voluntary_ctxt_switches` counts
    // switches, not yield calls, and a number that is not comparable is not
    // worth exposing.
    //
    // Relaxed, and on the outgoing task: only the hart that is running it
    // writes these, and the reader is that same task asking about itself.
    // Kconfig SCHED_SWITCH_COUNTERS (off in the embedded profile).
    if azos_limits::SCHED_SWITCH_COUNTERS && !old_ptr.is_null() {
        let old = &*old_ptr;
        match why {
            SwitchReason::Voluntary => &old.switches_voluntary,
            SwitchReason::Preempted => &old.switches_preempted,
        }
        .fetch_add(1, Ordering::Relaxed);
    }

    // M04 tickless hook (2 of 2) — a real switch, not a self-pick.
    //
    // Covers both directions of the idle boundary a real `context_switch`
    // crosses: `old` was busy and `next` is idle (the hart is ABOUT to go
    // idle — a task just blocked, exited, or was preempted with nothing else
    // ready) and `old` was idle and `next` is a real task (an IPI-driven
    // wake dispatched a task onto a hart whose timer may still be armed at
    // the sparse idle cap or the non-hart-0 ceiling from the LAST time it
    // went idle — the periodic quantum clamp has to be restored here, not
    // left to wait for whatever that stale far-future deadline happens to
    // be, or RR/quantum preemption on the newly-dispatched task is silently
    // disabled until it fires).
    //
    // Gated on `next_is_idle || old_was_idle` specifically so an ordinary
    // real-task-to-real-task switch (context switch storms, `ipc-roundtrip`,
    // a preemption between two RT tasks) pays nothing extra — no hardware
    // timer write outside the two cases that actually need one. `old_idx`
    // guards `usize::MAX` (first-ever dispatch, `start()`'s own
    // `context_switch(null_mut(), next)` at this same function's other call
    // site never reaches here — this is `do_schedule()`, not `start()`).
    // `next`'s priority, loaded once for the idle test and the RT hook (they
    // used to re-derive `next` from its index, bounds check included).
    let next_prio = next.priority.load(Ordering::Relaxed);
    {
        let next_is_idle = next_prio == crate::task::IDLE_PRIORITY;
        let old_was_idle = old_idx != usize::MAX
            && (*old_t).priority.load(Ordering::Relaxed) == crate::task::IDLE_PRIORITY;
        // NOHZ_FULL: the CPU leaves the task it stopped its tick for, so the
        // tick starts again (the next one may stop it for the next task).
        if next_is_idle || old_was_idle
            || (azos_limits::NOHZ_FULL && azos_drv_sys::timebase::tick_stopped())
        {
            azos_drv_sys::timebase::set_next_tick_tickless(
                cpu as u32, nearest_timer_deadline(), next_is_idle,
            );
        }
    }

    // SCHED-RT dispatch tail: charge what stopped, stamp what starts, arm the
    // next enforcement instant — after the tickless write above, so that
    // write cannot move the comparator past it. One per-hart load and the
    // next task's priority when neither side is a band task and the hart
    // holds no reservation.
    rt::on_switch_prio(cpu, next_idx, next_prio);

    // The outgoing task stops and `next` starts accruing
    // utilisation (a freed or first-run `old` has no signal to close).
    #[cfg(feature = "energy")]
    energy::on_switch(cpu, if old_ptr.is_null() { usize::MAX } else { old_idx }, next_idx);

    crate::swcensus::before_switch(next_idx);
    #[cfg(feature = "ctx-probe")]
    {
        ctx_probe::check_dispatch(ctx_probe::DISPATCH, cpu, next_idx);
        // The hart is still on the outgoing task's stack.
        let on = ctx_probe::stack_slot_of(ctx_probe::sp_now());
        if old_idx != usize::MAX && on != usize::MAX && on != old_idx {
            ctx_probe::fail(ctx_probe::TAIL, cpu, old_idx, on, "tail_not_on_old_stack", ctx_probe::sp_now());
        }
    }
    // Wave 15 (TRACE): the sched class's switch record (Kconfig
    // `KTRACE_CLASS_SCHED`; no instruction when compiled out).
    if azos_trace::sched_on() {
        let (prev, prev_state) = if old_ptr.is_null() { (0, 0) } else { ((*old_ptr).tid, (*old_ptr).state() as u32) };
        azos_trace::raw::sched_switch(prev, next.tid, prev_state, why as u32);
    }
    // Lockdep (Kconfig LOCKDEP, N1): this CPU's held locks go with `old`
    // and `next`'s come back. An exiting task (no saved context, or a
    // zombie) must hold none. No instruction with lockdep off.
    if azos_sync::lockdep::ON {
        let keep = !old_ptr.is_null() && (*old_ptr).state() != TaskState::Zombie;
        azos_sync::lockdep::switch(if keep { Some(old_idx) } else { None }, next_idx);
    }
    // QSBR (Kconfig RCU_QSBR, N4): a context switch is a quiescent state.
    // One store; nothing with the option off.
    azos_sync::qsbr::switch();
    // N12: re-tag `next`'s ASID if a rollover took it; set the flush word.
    crate::asid::prepare_switch(next as *mut Task);
    context_switch(old_ptr, next as *mut Task);
    // Returns here when the old task is rescheduled: `old_t` is this task.
    finish_switch(old_t);
    crate::swcensus::after_switch();
}

/// A new thread-group member in slot `idx` runs on its creator's address
/// space: the same root and translation word, nothing reset (the budget and
/// the break stay the leader's, `proc_slot`).
pub(crate) fn set_task_thread_info(idx: usize, task_satp: u64, user_pt: u64) {
    unsafe {
        if idx < MAX_TASKS && TASK_VALID[idx].load(Ordering::Relaxed) {
            TASKS[idx].task_satp = task_satp;
            TASKS[idx].user_pt = user_pt;
            TASKS[idx].user_brk = 0;
            TASKS[idx].user_mmap_low = 0;
        }
    }
}

/// Rewrite the current task's translation word only (exec's re-tag in
/// `asid::install_exec_root`: same root, the space's ASID).
pub(crate) fn set_current_task_satp(task_satp: u64) {
    let idx = my_idx();
    unsafe {
        if idx != usize::MAX {
            TASKS[idx].task_satp = task_satp;
        }
    }
}

/// Update the task_satp, user_pt and user_brk of the current task (and
/// start its mmap cursor over: a new address space has handed nothing out).
/// Called by exec_user after a new user page table has been built.
pub fn set_current_user_info(task_satp: u64, user_pt: u64, brk: u64) {
    let idx = my_idx();
    unsafe {
        if idx != usize::MAX {
            TASKS[idx].task_satp = task_satp;
            TASKS[idx].user_pt   = user_pt;
            TASKS[idx].user_brk  = brk;
            TASKS[idx].user_mmap_low = 0;
            // A new image starts from nothing: new PAC keys (installed by
            // `take_current_task_exec_slots` when the hand-off is consumed).
            crate::pac::draw(idx);
            // Owner decision 102 — a new address space starts from zero. Both
            // writers of this budget are "this task now has that page
            // table", so both reset here (see `set_task_user_info` below for
            // the other writer, fork's and spawn's).
            //
            // The image, stack and page tables of the new address
            // space ARE charged -- by the caller, right after this, through
            // `mm_install_frames` with the count `load_elf` returned.
            crate::domain::reset_budget(TASKS[idx].domain());
        }
    }
}

/// Give the CURRENT task the class and base priority its topology row asks
/// for (wave 7). Returns the base priority it had before.
///
/// Called by the autorun loader once the image it is about to run is known —
/// the loader task becomes the ring-3 process, so this is that process's
/// priority. The current task is not in a ready queue while it runs, so no
/// bucket needs moving; interrupts are off so a tick cannot re-enqueue it
/// half-way between the two stores.
///
/// A donation in progress (`donation_count > 0`) keeps the boosted
/// `priority`: only `base_priority` changes, and the last restore lands on
/// the new base.
///
pub fn set_current_sched_params(priority: u32, class_raw: u8) -> u32 {
    let sstatus = azos_arch::ARCH.disable_all();
    let cpu = current_cpu_id();
    let mut before = priority;
    let mut changed = usize::MAX;
    unsafe {
        let idx = PER_CPU[cpu].current_idx.load(Ordering::Relaxed);
        if idx < MAX_TASKS {
            changed = idx;
            let task = task_mut(idx);
            before = task.base_priority.load(Ordering::Relaxed);
            task.sched_class_raw = class_raw;
            classes::on_row_class(idx, class_raw);
            task.base_priority.store(priority, Ordering::Relaxed);
            classes::on_base_priority(idx, priority);
            if task.donation_count.load(Ordering::Relaxed) == 0 {
                task.priority.store(priority, Ordering::Relaxed);
                hist_reaccount(idx);
            }
        }
    }
    azos_arch::ARCH.restore(sstatus);
    // N7: re-apply a wait-graph boost over the new base, and re-sort.
    classes::pi_attr_changed(changed);
    before
}

/// The current task's `(base priority, sched_class_raw)` — what a fork child
/// inherits.
pub fn current_sched_params() -> (u32, u8) {
    let idx = my_idx();
    unsafe {
        if idx >= MAX_TASKS {
            return (crate::DEFAULT_PRIORITY, crate::task::DEFAULT_SCHED_CLASS_RAW);
        }
        let task = task_ref(idx);
        (task.base_priority.load(Ordering::Relaxed), task.sched_class_raw)
    }
}

/// The class discriminant of the task `tid`, if it is live.
pub fn task_class_raw(tid: u32) -> Option<u8> {
    unsafe { idx_for_tid(tid).map(|i| task_ref(i).sched_class_raw) }
}

/// The page-table root of the task `tid`, if it is live (0: a kernel task).
/// Wave 14 (DEMANDPAGE): a fork hands the child's root to the region table.
pub fn task_user_pt(tid: u32) -> Option<usize> {
    unsafe { idx_for_tid(tid).map(|i| task_ref(i).user_pt as usize) }
}

/// Read + update user_brk for the current task (sys_brk).
/// Returns new brk value, or old brk if addr == 0.
pub fn update_user_brk(addr: u64) -> u64 {
    update_group_word(addr, |t| &mut t.user_brk)
}

/// Read + update the current task's mmap cursor (`Task::user_mmap_low`), as
/// [`update_user_brk`] does the break: `addr == 0` reads it (0: nothing
/// handed out yet), anything else stores it.
pub fn update_user_mmap_low(addr: u64) -> u64 {
    update_group_word(addr, |t| &mut t.user_mmap_low)
}

/// The word `pick` names in the current thread group's slot (wave 13: one
/// break and one mmap cursor per group, on the leader's slot): `addr == 0`
/// reads it, anything else stores it; the value is returned either way.
fn update_group_word(addr: u64, pick: fn(&mut Task) -> &mut u64) -> u64 {
    let idx = my_idx();
    unsafe {
        if idx == usize::MAX { return 0; }
        let w = pick(task_mut(proc_slot(idx)));
        if addr != 0 {
            *w = addr;
        }
        *w
    }
}

/// Reserve `span` bytes of the current task's shm/MMIO window `[lo, hi)`
/// ([`crate::user_window::reserve`]). `None` when no task is current.
///
/// Unlocked, like [`update_user_brk`]: a task's reservations are written only
/// by its own syscalls, and by the slot reuse that clears them after it has
/// exited.
pub fn reserve_current_user_window(lo: usize, hi: usize, span: usize) -> Option<usize> {
    let idx = my_idx();
    unsafe {
        if idx == usize::MAX { return None; }
        crate::user_window::reserve(&mut task_mut(proc_slot(idx)).user_window, lo, hi, span)
    }
}

/// Give back the current task's reservation `[base, base + span)`
/// ([`crate::user_window::release`]). `false` when no task is current or the
/// task holds no such reservation.
pub fn release_current_user_window(base: usize, span: usize) -> bool {
    let idx = my_idx();
    unsafe {
        if idx == usize::MAX { return false; }
        crate::user_window::release(&mut task_mut(proc_slot(idx)).user_window, base, span)
    }
}

/// Reserve exactly `[base, base + span)` of the shm/MMIO window of the task
/// `tid` (a fork child that inherits a shared-memory mapping at its parent's
/// address, before it runs). `false` when the task is gone or the range is
/// taken ([`crate::user_window::reserve_at`]).
pub fn reserve_user_window_at(tid: u32, base: usize, span: usize) -> bool {
    unsafe {
        match idx_for_tid(tid) {
            Some(i) => crate::user_window::reserve_at(&mut task_mut(proc_slot(i)).user_window, base, span),
            None => false,
        }
    }
}

/// Give back what [`reserve_user_window_at`] reserved for `tid`.
pub fn release_user_window_of(tid: u32, base: usize, span: usize) -> bool {
    unsafe {
        match idx_for_tid(tid) {
            Some(i) => crate::user_window::release(&mut task_mut(proc_slot(i)).user_window, base, span),
            None => false,
        }
    }
}

/// Set user info for a specific task by pool index (used by fork, whose child
/// copies the parent's break and mmap cursor with its address space, and by
/// spawn, whose new address space has handed nothing out: cursor 0).
pub fn set_task_user_info(idx: usize, task_satp: u64, user_pt: u64, brk: u64, mmap_low: u64) {
    unsafe {
        if idx < MAX_TASKS && TASK_VALID[idx].load(Ordering::Relaxed) {
            TASKS[idx].task_satp = task_satp;
            TASKS[idx].user_pt   = user_pt;
            TASKS[idx].user_brk  = brk;
            TASKS[idx].user_mmap_low = mmap_low;
            // Owner decision 102 — a new address space starts from zero. Both
            // writers of this budget are "this task now has that page
            // table", so both reset here (see `set_current_user_info` above
            // for the other writer, exec's).
            //
            // What the new address space already holds (image,
            // stack and tables for spawn; the child's own tables for fork) is
            // charged by the caller through `set_task_mem`, right after this.
            crate::domain::reset_budget(TASKS[idx].domain());
        }
    }
}

/// K-A15: publish the fork hand-off context on the *child's* own task slot
/// (by pool index — unambiguous even with multiple concurrent forks).
/// Called once by the parent, as the last step of `sys_fork_impl()`. Writes
/// the payload fields first, then the `Release`-ordered ready flag — see
/// the `fork_ctx_ready` doc on `Task` for why the ordering matters.
///
/// `expected_tid` guards against slot reuse: a bare `TASK_VALID[idx]` check
/// would let a delayed parent publish another process's entry/user_sp/satp
/// onto whatever task now occupies the slot (if that task is itself a fork
/// child, it would SRET into the wrong address space). The check + payload
/// write happen under `POOL_LOCK` so they cannot interleave with
/// `do_schedule()` freeing the slot / `alloc_slot()` reusing it. Returns
/// `false` if the slot no longer belongs to `expected_tid` (i.e. the child
/// is gone) — nothing is written in that case.
pub fn set_task_fork_ctx(
    idx: usize,
    expected_tid: u32,
    entry: u64,
    user_sp: u64,
    satp: u64,
    regs: &crate::task::UserRegs,
) -> bool {
    if idx >= MAX_TASKS {
        return false;
    }
    // Chain E commit 8: the snapshot of a native caller (fork, a thread,
    // spawn: each publishes from its creator's own syscall) holds, in the
    // registers the native syscall path neither stores nor restores, what an
    // earlier trap left in the frame. The contract clobbers them; the child
    // starts with them zero, as its creator got them back. A Linux caller's
    // frame was saved whole and is copied whole.
    let clear = azos_limits::SYSCALL_LEAN_ENTRY && !current_is_foreign();
    unsafe {
        let _pool = PoolGuard::acquire();
        if !TASK_VALID[idx].load(Ordering::Relaxed) || TASKS[idx].tid != expected_tid {
            return false;
        }
        let task = task_mut(idx);
        task.fork_entry   = entry;
        task.fork_user_sp = user_sp;
        task.fork_satp    = satp;
        // K-C11: the parent's full user register file. Written before the
        // publish flag below, like the other three payload fields — the child
        // reads all of it under the same Acquire/Release pairing.
        task.fork_regs    = *regs;
        if clear {
            clear_syscall_clobbers(&mut task.fork_regs);
        }
        task.fork_ctx_ready.store(true, Ordering::Release);
        true
    }
}

/// Zero, in a fork snapshot, the registers a native syscall clobbers and the
/// lean trap path (Kconfig `SYSCALL_LEAN_ENTRY`) never stores: see
/// [`set_task_fork_ctx`].
#[inline]
fn clear_syscall_clobbers(r: &mut crate::task::UserRegs) {
    #[cfg(target_arch = "riscv64")]
    for i in azos_arch::trap::SYSCALL_CLOBBERED {
        r[i] = 0;
    }
    #[cfg(all(any(target_arch = "aarch64", target_arch = "x86_64"), target_os = "none"))]
    for i in azos_arch::fork_regs::SYSCALL_CLOBBERED {
        r.gpr[i] = 0;
    }
    #[cfg(not(any(target_arch = "riscv64", all(any(target_arch = "aarch64", target_arch = "x86_64"), target_os = "none"))))]
    let _ = r;
}

/// K-A15: consume (read-and-clear) the fork hand-off context for whichever
/// task is currently running on this CPU. Called only by `fork_child_entry`,
/// about itself — `Acquire` pairs with the `Release` in
/// [`set_task_fork_ctx`] so once this observes the flag set, the payload
/// fields it reads are guaranteed to be the parent's finished writes.
/// Returns `None` if the parent hasn't published it yet (caller retries).
///
/// **K-C11: the register file is returned by value, on purpose.** It lands on
/// the caller's (kernel) stack, and `fork_child_entry` hands the asm a pointer
/// to *that* copy rather than to `TASKS[idx].fork_regs`. The restore sequence
/// runs after `csrw satp` has already switched to the child's page table, and
/// while `copy_kernel_entries_to_user` does splice the kernel's entries into
/// every user PT, "the kernel's `.bss` is reachable through the child's PT" is
/// an assumption this code would then depend on silently — and getting it wrong
/// means an S-mode fault under `panic = "abort"`, i.e. a board reset on every
/// single fork. The kernel *stack* is unambiguously reachable after the switch;
/// the pre-existing `csrw sscratch, sp` already relies on exactly that. Copying
/// costs 256 bytes of stack on a path that runs once per fork.
pub fn take_current_task_fork_ctx() -> Option<(u64, u64, u64, crate::task::UserRegs)> {
    let idx = my_idx();
    unsafe {
        if idx == usize::MAX { return None; }
        let task = task_mut(idx);
        if !task.fork_ctx_ready.swap(false, Ordering::Acquire) {
            return None;
        }
        // The keys of this child's image are final: they go to the hart that
        // is about to `eret` (a spawn child was switched in before its draw).
        crate::pac::install_current();
        Some((task.fork_entry, task.fork_user_sp, task.fork_satp, task.fork_regs))
    }
}

/// K-C21: publish the exec hand-off on the CURRENT task's own slot. Called
/// by `exec_user()` as its last step. Payload fields first, `Release`-ordered
/// ready flag last — same publish protocol as [`set_task_fork_ctx`].
///
/// No pool lock and no identity check, deliberately: unlike fork this never
/// writes across tasks — the writer IS the current task, its slot cannot be
/// freed or reused while it is still executing this function, and the only
/// reader is the same task later in the same syscall/trap. See the
/// `exec_ctx_ready` doc on `Task`.
pub(crate) fn set_current_task_exec_slots(
    entry: u64,
    user_sp: u64,
    sstatus: u64,
    satp: u64,
    old_pt: u64,
) {
    let idx = my_idx();
    unsafe {
        if idx == usize::MAX { return; }
        let task = task_mut(idx);
        task.exec_entry   = entry;
        task.exec_user_sp = user_sp;
        task.exec_sstatus = sstatus;
        task.exec_satp    = satp;
        task.exec_old_pt  = old_pt;
        if !task.exec_ctx_ready.swap(true, Ordering::Release) {
            EXEC_HANDOFFS.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Exec hand-offs published and not yet consumed or discarded, all tasks
/// (wave 15, SWITCH). Every syscall's return path tests for a pending
/// hand-off; this one global load answers "none anywhere" for all of them
/// but a successful exec's, instead of the per-task lookup (current slot,
/// bounds check, `TASKS` index, flag: 13 instructions on every syscall).
/// Written at the three places the per-task flag flips (publish here, the
/// consume below, the reuse/exit discards), each only when the flag really
/// changed. The publisher reads it back later in the same trap on the same
/// task, so its own increment is visible to it, migration included (a
/// switch orders through the queue lock). A count left high can only send
/// a syscall to the per-task test, never skip a real hand-off.
pub(crate) static EXEC_HANDOFFS: AtomicU32 = AtomicU32::new(0);

/// K-C21 fast test: is an exec hand-off pending for the task running on this
/// CPU? A plain load, so the syscall return path pays no atomic
/// read-modify-write when nothing is pending (every syscall but a
/// successful exec). Equivalent to the swap it guards: the publisher is this
/// same task earlier in this same trap, so a `false` here means nothing was
/// published, and a reuse/exit-time swap that races in between leaves the
/// slow path's own swap answering `None`, exactly as before.
#[inline(always)]
pub(crate) fn current_task_exec_ctx_pending() -> bool {
    if EXEC_HANDOFFS.load(Ordering::Relaxed) == 0 {
        return false;
    }
    let idx = my_idx();
    unsafe {
        if idx == usize::MAX { return false; }
        (*core::ptr::addr_of!(TASKS[idx].exec_ctx_ready)).load(Ordering::Relaxed)
    }
}

/// K-C21: consume (read-and-clear) the exec hand-off of the task currently
/// running on this CPU. Returns `(entry, user_sp, sstatus, satp, old_pt)`.
/// The `Acquire` swap pairs with the `Release` in
/// [`set_current_task_exec_slots`] — on this design it is belt-and-braces
/// (same task, same hart), but it keeps the protocol identical to fork's and
/// costs nothing. Callers must go through
/// `process::take_current_task_exec_ctx`, which owns the satp-switch /
/// destroy-old ordering (K-C22).
pub(crate) fn take_current_task_exec_slots() -> Option<(u64, u64, u64, u64, u64)> {
    let idx = my_idx();
    unsafe {
        if idx == usize::MAX { return None; }
        let task = task_mut(idx);
        if !task.exec_ctx_ready.swap(false, Ordering::Acquire) {
            return None;
        }
        EXEC_HANDOFFS.fetch_sub(1, Ordering::Relaxed);
        // The new image's keys (`set_current_user_info`) go to this hart.
        crate::pac::install_current();
        Some((
            task.exec_entry,
            task.exec_user_sp,
            task.exec_sstatus,
            task.exec_satp,
            task.exec_old_pt,
        ))
    }
}

/// One donation lock per task slot (wave 9). Serialises every boost and
/// restore of that slot's `donation_count` + `priority` pair — see
/// `donation::DonationCell` for the race it closes. Taken with interrupts
/// masked and held across `cpu_remove_anywhere`/`cpu_enqueue_locked`, so the
/// lock order is: donation lock → `CPU_LOCKS`. Nothing
/// takes a donation lock while holding a CPU lock.
static DONATION_LOCKS: [AtomicBool; MAX_TASKS] = {
    const F: AtomicBool = AtomicBool::new(false);
    [F; MAX_TASKS]
};

/// Remove a specific task `idx` from its current ready bucket, if present.
/// O(bucket length). Returns `true` if it was found and removed.
unsafe fn cpu_remove(cpu: usize, idx: usize) -> bool {
    let prio = prio_bucket(task_mut(idx).priority.load(Ordering::Relaxed));
    // `&`, not `&mut` — see `cpu_dequeue`.
    let q = &cpu_queues(cpu)[prio];
    // O(position): the list is walked from its head, under the lock, for at
    // most `count` (and at most `MAX_TASKS`) links. No scratch copy.
    let removed = q.remove(&RQ_NEXT, idx);
    let found = removed.is_some();
    if let Some(k) = removed {
        if k == 0 {
            let bm = &PER_CPU[cpu].ready_bitmap;
            bm.store(bm.load(Ordering::Relaxed) & !(1 << prio), Ordering::Relaxed);
        }
        // K-C12: the task no longer occupies a queue slot, so release the
        // invariant — otherwise the re-enqueue at its new priority (the whole
        // point of this call) is refused as a duplicate and the task is lost.
        task_mut(idx).queued.store(false, Ordering::Release);
    }
    found
}

/// Remove `idx` from whichever CPU's ready queue holds it, under that CPU's
/// lock. Returns the CPU it came off, or `None` if it was in no queue.
///
/// **Scan unit 4 finding: the priority-donation pair was the one live
/// `CPU_LOCKS` bypass, and it had the wrong CPU as well as no lock.**
/// `boost_ready_task` and `restore_ready_task` called the RAW `cpu_remove` /
/// `cpu_enqueue` on `current_cpu_id()` — the *donor's* hart, not the boosted
/// task's. Two defects for the price of one:
///
///  1. **Unlocked.** Those two mutate the ring buffer, its head/tail/count and
///     the ready bitmap. Another hart inside `cpu_dequeue_locked` on the same
///     queue is a torn run queue.
///  2. **Wrong queue.** An unpinned task sits in whichever hart enqueued it. On
///     any other hart, `cpu_remove(donor_cpu, idx)` simply misses — and then the
///     code wrote `priority` anyway and skipped the re-enqueue. The task is left
///     queued in ANOTHER CPU's bucket keyed by its OLD priority while its
///     `priority` field says something else. `cpu_remove` derives the bucket
///     from `priority`, so the next removal looks in the wrong bucket and
///     misses too: the task is stuck in a queue nothing can take it out of.
///     That is worse than the inversion the donation exists to prevent.
///
/// A search, because nothing records which queue a task is in: `cpu_affinity`
/// says where it *may* run, not where it *is*. Four harts, one lock at a time,
/// acquired and dropped before the next — no nesting, so no new ordering
/// obligation. And the callers hold no other lock, which is what keeps this from
/// becoming the first edge in a lock graph that has none.
unsafe fn cpu_remove_anywhere(idx: usize) -> Option<usize> {
    for cpu in 0..ncpu() {
        let _g = CpuLockGuard::acquire(cpu);
        if cpu_remove(cpu, idx) {
            // It leaves the fair order keeping its lag (a priority change,
            // a move to the hart its reservation was admitted on).
            fairq::left(cpu, idx);
            return Some(cpu);
        }
    }
    None
}

#[cfg(feature = "ktest")]
static KTEST_RING3_SLOT: AtomicUsize = AtomicUsize::new(usize::MAX);

/// The last donation [`donate_priority`] made: `target_tid << 32 | priority`.
/// Telemetry for the `proxy-pi-smoke` floor check, which reads the priority
/// the donation actually applied rather than sampling for it.
pub static LAST_DONATION: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Donations raised to the ring-3 floor, since boot. Telemetry; the
/// `proxy-pi-smoke` floor check reads it across one call.
pub static DONATIONS_FLOORED: AtomicU32 = AtomicU32::new(0);

azos_common::ro_hook! {
    /// Where a floored donation is recorded (the kernel installs a flight-recorder
    /// writer: `SAFETY_TOPO_CLASS_REFUSED`, site `SITE_DONATION_FLOOR`). This
    /// crate does not depend on the recorder, the arrangement `topo_sched` uses.
    static DONATION_FLOOR_RECORDER: fn(u32);
}

/// The TID whose floored donation slot `i` last recorded: one record per
/// target task, not per donation — a kernel RT client calling a ring-3 driver
/// in a loop would otherwise write the recorder on every call.
static FLOOR_RECORDED_TID: [AtomicU32; MAX_TASKS] = [const { AtomicU32::new(0) }; MAX_TASKS];

/// Whether guard pages have been set up (after vmm paging is enabled).
static GUARD_PAGES_ACTIVE: AtomicBool = AtomicBool::new(false);

/// Set up guard pages for all task stacks.
///
/// Unmaps the bottom page (4 KiB) of each stack slot so that stack overflow
/// triggers an immediate page fault instead of silently corrupting adjacent
/// stacks.  Must be called AFTER `vmm::enable_paging()`.
///
/// After this call, the effective usable stack per task is `STACK_SIZE - 4096`.
/// Stack canary checks are skipped when guard pages are active (the page fault
/// is a stronger guarantee than polling).
pub fn setup_stack_guard_pages() {
    let kpt = azos_mm::vmm::kernel_pagetable();
    for i in 0..MAX_TASKS {
        let stack_bottom = unsafe { TASK_STACKS.0[i].as_ptr() as usize };
        azos_mm::vmm::unmap_kernel(kpt, stack_bottom);
    }
    GUARD_PAGES_ACTIVE.store(true, Ordering::Release);
}

/// Read back whether [`setup_stack_guard_pages`] actually left every stack's
/// guard byte unmapped, rather than trusting that call's return — the same
/// principle `crates/core/mm::vmm`'s `verify_wx`/`verify_no_exec_outside_image`
/// already apply to W^X/NX. Walks `vmm::translate` (a fresh page-table read,
/// not the cached `GUARD_PAGES_ACTIVE` flag) against every stack slot's
/// bottom address and counts how many come back `None` (unmapped).
///
/// Returns `(unmapped, total)` — `total` is `MAX_TASKS`, read back here
/// rather than hardcoded elsewhere so a `MAX_TASKS` change cannot silently
/// stop the caller's check from meaning anything.
pub fn stack_guard_readback() -> (usize, usize) {
    let kpt = azos_mm::vmm::kernel_pagetable();
    let mut unmapped = 0usize;
    for i in 0..MAX_TASKS {
        let stack_bottom = unsafe { TASK_STACKS.0[i].as_ptr() as usize };
        if azos_mm::vmm::translate(kpt, stack_bottom).is_none() {
            unmapped += 1;
        }
    }
    (unmapped, MAX_TASKS)
}

/// The exact address [`setup_stack_guard_pages`] unmaps for task slot `idx` —
/// the bottom of its kernel stack. Exists so a fault probe (or gate tooling
/// reading the probe's own log) can name the address it is about to touch
/// instead of recomputing the stack layout by hand. Panics on an
/// out-of-range `idx`, same as the array index it wraps — the right failure
/// for a caller bug, not something to hide behind an `Option`.
pub fn stack_guard_addr(idx: usize) -> usize {
    unsafe { TASK_STACKS.0[idx].as_ptr() as usize }
}

/// Check stack canaries for all currently-valid task slots.
///
/// Returns `(intact, total)`:
/// - `intact` — slots where the canary in force (`stack_canary()`) is still at
///   the stack bottom.
/// - `total`  — number of valid slots inspected.
///
/// Called by the system watchdog task every ~1 s (Phase 16).
/// When guard pages are active, skips the check (page fault is stronger).
pub fn stack_canary_check() -> (usize, usize) {
    if GUARD_PAGES_ACTIVE.load(Ordering::Acquire) {
        // Guard pages active — overflow triggers immediate page fault.
        // Return (total, total) to indicate "all OK" to watchdog.
        let mut total = 0usize;
        unsafe {
            for i in 0..MAX_TASKS {
                if TASK_VALID[i].load(Ordering::Relaxed) { total += 1; }
            }
        }
        return (total, total);
    }
    let mut ok    = 0usize;
    let mut total = 0usize;
    unsafe {
        for i in 0..MAX_TASKS {
            if TASK_VALID[i].load(Ordering::Relaxed) {
                total += 1;
                let ptr = TASK_STACKS.0[i].as_ptr() as *const u64;
                if ptr.read_volatile() == stack_canary() {
                    ok += 1;
                }
            }
        }
    }
    (ok, total)
}

// The block / wake API, the IPC fast hand-off, the task lifecycle, the
// task-state queries with the frame budget, and priority donation live in
// child modules; their items stay reachable as `crate::scheduler::X`.
mod wake;
mod ipc_fast;
mod lifecycle;
mod budget;
mod donation;
#[cfg(feature = "ktest")]
pub mod accessor_audit;
pub use wake::*;
pub use ipc_fast::*;
pub use lifecycle::*;
pub use budget::*;
pub use donation::*;

/// `ipc-census`: where IPC hand-off wakes were placed relative to the
/// waker's hart — the before/after evidence for the affinity exception
/// (the counters exist, and count, with or without `sched-ipc-affinity`).
/// Tallies print at powers of two.
#[cfg(feature = "ipc-census")]
#[path = "../ipc_placement.rs"]
pub mod ipc_placement;

/// `sched-reap-event`: the K-C25 reaper visits only slots a waker stamped
/// while they were still switching away, instead of all `MAX_TASKS` slots
/// on every tick.
///
/// `Blocked + WAKE_STAMP` — the only state the reaper acts on — is made in
/// exactly one place: `sched_word::wake_transition`'s `!saved` arm (the
/// commit CAS requires the stamp clear, and no other writer stores
/// `Blocked`). Its three callers (`try_wake_task`, `wq_wake_by_tid`,
/// `wake_task_by_tid`) call [`note_unsaved_stamp`] after it, which marks
/// the slot here. The tick takes each word whole (`swap(0)`) before looking
/// at its slots, and re-marks a slot `reap_one` says is not ready yet, so a
/// mark made after the take is kept for the next tick and a mark made before
/// it is looked at with its stamp visible (Release mark / Acquire take).
///
/// Under `ipc-census` the full sweep still runs after the marked pass and
/// counts the slots IT had to reap because no mark named them
/// (`reap_pending::UNMARKED`): each is a stamp that, without the sweep,
/// only a later mark could have recovered. A waker preempted between its
/// stamp CAS and its mark while the target parks also lands there; that
/// window is a few instructions.
#[cfg(feature = "sched-reap-event")]
#[path = "../reap_pending.rs"]
mod reap_pending;

/// K-C24 rescues that rang this hart's own doorbell (`do_schedule`'s Blocked
/// arm, wave 13). Diagnostic: shows the path is exercised.
pub static KC24_RESCUE_KICKS: AtomicU32 = AtomicU32::new(0);

/// Ring `cpu`'s scheduler doorbell (the software IPI `cpu_enqueue_locked`
/// rings for a remote hart). Also valid for the calling hart: the interrupt
/// stays pending until it is taken, whatever runs next.
fn kick_hart(cpu: usize) {
    // riscv64: SBI IPI to `cpu` (its error code ignored, as before);
    // aarch64: SGI 0.
    azos_arch::Interrupts::send_ipi(&azos_arch::ARCH, cpu);
}

/// Kconfig CHAOS, asked once per timer sweep (`wait::wake_expired_timers`),
/// off the wake decisions themselves. Point `spurious-irq` rings an
/// unsolicited doorbell ([`chaos_spurious_ipi`]); point `timer-wake` returns
/// a clock `CHAOS_TIMER_DELAY_US` behind, so a sleeper due in that window
/// wakes on a later sweep (late, not lost). Off: `now_ticks`.
#[inline(always)]
pub(crate) fn chaos_sweep_now(now_ticks: u64) -> u64 {
    if azos_chaos::fire(azos_chaos::Point::SpuriousIrq) {
        chaos_spurious_ipi();
    }
    if azos_chaos::fire(azos_chaos::Point::TimerWake) {
        let per_us = (azos_drv_sys::timebase::TIMER_FREQ / 1_000_000).max(1);
        now_ticks.saturating_sub(azos_limits::CHAOS_TIMER_DELAY_US * per_us)
    } else {
        now_ticks
    }
}

/// Kconfig CHAOS, point `spurious-irq`: ring the next online CPU's doorbell
/// with nothing queued for it, so that CPU takes an interrupt it finds no
/// cause for. Called from the timer sweep only when the point fires.
#[cold]
pub(crate) fn chaos_spurious_ipi() {
    let n = NUM_ONLINE_CPUS.load(Ordering::Acquire).min(MAX_CPUS);
    if n > 1 {
        kick_hart((current_cpu_id() + 1) % n);
    }
}


/// U02-3: timer sleepers in an indexed min-heap (`crate::timer_heap`) instead
/// of being found by sweeping every slot on every tick.
///
/// * **Arm**: `block_current`, after its commit CAS leaves the task `Blocked`
///   on `WaitReason::Timer(d)` — never before: an entry popped by another
///   hart's tick before the commit would find the task not yet `Blocked`
///   (`NotBlocked`, no stamp for a broadcast wake) and the sleep would be
///   lost. `wait_reason` has exactly one writer (`block_current`), so every
///   timer sleep passes through here.
/// * **Fire**: `wake_expired_timers` pops the due entries under the lock,
///   drops it, then runs the same `try_wake_task` + `Timer(d) if now >= d`
///   predicate the sweep ran on each popped slot. A stale entry (the sleeper
///   was woken another way, exited, or re-armed later) meets `Mismatch` /
///   `NotBlocked` there and does nothing. A sleeper still `Blocked` on that
///   timer afterwards — it was mid-switch (`context_saving`), so the wake
///   could only stamp it — is re-armed: the sweep retried it every tick
///   until it was parked or the K-C25 reaper took the stamp, and a
///   popped-and-forgotten entry would also vanish from
///   `nearest_timer_deadline`, letting a tickless hart sleep past it (a
///   `-smp 4` census boot without the re-arm counted 333 such sleepers).
///   The re-arm reads the deadline under the lock (`timer_heap::wake_due`).
///   It used to arm a deadline read before the lock was taken; between
///   that read and the arm, the stamped sleeper could be dispatched, run,
///   block again on a later timer and arm it, and the re-arm then
///   overwrote the new deadline with the old one. `nearest` found the slot
///   not asleep on the entry's deadline and popped it, and the sleeper
///   was left with no entry: no tick woke it again (rt-motor and imu on
///   the `-smp 4` camera-link boot, heap ON).
/// * **Nearest**: the top entry, fixed up against the live task first
///   (`TimerHeap::peek_live`): an entry whose slot is no longer asleep on
///   a timer is popped, so a stale entry cannot make the tickless path
///   program an early interrupt; an entry whose slot is asleep on a
///   different deadline is moved to that deadline, never popped.
///
/// The lock is a leaf (nothing else is taken under it) and masks interrupts
/// on every acquisition, like `DeadlinePickGuard` — it is taken from the
/// tick ISR and from `block_current`.
#[cfg(feature = "sched-timer-heap")]
#[path = "../timer_sleepers.rs"]
pub mod timer_sleepers;


/// Read-only reference to task via raw pointer (avoids aliasing with task_mut).
/// # Safety
/// Caller must not hold a mutable reference to the same slot simultaneously.
#[inline(always)]
unsafe fn task_ref(idx: usize) -> &'static Task {
    unsafe { &*(core::ptr::addr_of!(TASKS[idx])) }
}

// ── Preemption control (K-C29) ───────────────────────────────────────────────
//
// The mechanism lives in `azos_sync::preempt` — per-hart depth, per-hart
// need-resched, RAII guard, `sstatus.SIE`-gated deferred fire. This module
// only decides what the scheduler does about it, and counts what it saw.
//
// WHAT WAS DELETED HERE, AND WHY (F03.4's `PREEMPT_COUNT`). The old stub had
// zero callers in the whole tree and three defects, all three confirmed
// against the code before removal:
//
//   1. `schedule()` consulted it as its FIRST statement, before
//      `task.total_runtime += 1`, before the
//      deadline replenish, and before `DEADLINE_TICK_COUNTER.fetch_add`. Its
//      own comment claimed it would "still let the caller's bookkeeping run";
//      it did not. A task holding a lock would have gone invisible to runtime
//      accounting, and the monotonic tick counter would have stalled for
//      every hart in a critical section.
//   2. No need-resched memory. A tick that arrived with preemption disabled
//      was simply dropped: nothing recorded the debt, nothing paid it.
//   3. `preempt_enable()` called `schedule()` whenever the count hit zero,
//      from any context — and `preempt_disable()`'s own doc advertised "may
//      be called from any context (task or IRQ handler)". Re-entering the
//      scheduler from inside an ISR is the K-A12 hazard `task_yield` and
//      `block_current` both clear SIE to avoid.
//
//   (4, not in the original charge sheet: it indexed `[AtomicI32; MAX_CPUS]`
//   with `hart.min(ncpu() - 1)`. `MAX_CPUS` is 4, `MAX_HARTS` is 8, so
//   harts 3..7 all shared slot 3 — a lock on hart 5 would have disabled
//   preemption on hart 3.)

/// Preemption-audit counters. **Always compiled** — these prove the
/// invariants rather than assuming them, so they must not be behind
/// `ipc-census` like the diagnostic census is.
///
/// Read them from `kernel/src/entry/riscv64/irq.rs`'s `[SCHED-DBG]` line via
/// [`preempt_audit::read`].
#[path = "../preempt_audit.rs"]
pub mod preempt_audit;

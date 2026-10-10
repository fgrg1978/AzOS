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

use core::sync::atomic::{AtomicBool, AtomicU16, AtomicU32, AtomicUsize, Ordering};
// The cross-ISA interrupt contract. In scope for the method calls on
// `azos_arch::ARCH`, which replaced 37 hand-written reads and writes of
// `sstatus.SIE` in this file on 2026-09-21 — see `crates/core/arch-api`.
use azos_arch::Interrupts;
use crate::task::{
    Task, TaskContext, TaskState, CtxReg, MAX_TASKS, STACK_SIZE,
    TIME_SLICE_TICKS, RT_TIME_SLICE_TICKS, NUM_PRIORITIES, is_rt_priority,
    WaitReason, SyscallFilter, TaskInit, TASK_NAME_CAPACITY,
    CpuLoad, EnqueueOutcome, enqueue_decision, pick_cpu_by_load,
};
use crate::smp::{current_cpu_id, NUM_ONLINE_CPUS};
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
#[path = "resident_histogram.rs"]
pub mod resident_histogram;

/// Eligibility rule for the fast-IPC same-hart direct switch
/// ([`ipc_wake_then_block`]), in its own file so the host test runner
/// (`tests/host/sched-wake-tests`) can compile and test it.
#[path = "ipc_direct.rs"]
pub mod ipc_direct;

/// Wave 11 SCHED-RT: the per-hart RT-band budget and EDF + CBS on this
/// dispatch path (RFC-0052 §4.3–§4.4). A child module so it reaches the
/// ready queues without widening their visibility.
#[path = "rt.rs"]
pub mod rt;

/// N6: the five dispatch classes (stop > DL > RT > fair > idle) and the
/// per-task scheduling context, over the queues above (`sc.rs` is the model).
#[path = "classes.rs"]
pub mod classes;

/// RFC-0051 E1/E2 (kernel feature `energy`): utilisation signals updated on
/// this dispatch path, and the energy model installed at boot.
#[cfg(feature = "energy")]
#[path = "energy.rs"]
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
#[cfg_attr(not(feature = "sched-ipc-affinity"), allow(dead_code))]
#[cfg(feature = "sched-o1-placement")]
#[inline]
unsafe fn hist_reaccount_pair(a: usize, b: usize) {
    if a >= MAX_TASKS || b >= MAX_TASKS {
        return;
    }
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
#[path = "tid_alloc.rs"]
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
    current_filter: AtomicUsize,
}

/// Const initializer for PerCpuSched.
const EMPTY_CPU: PerCpuSched = PerCpuSched {
    current_idx:  AtomicUsize::new(usize::MAX),
    ready_bitmap: AtomicU32::new(0),
    current_filter: AtomicUsize::new(0),
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
        let filter = if next_idx < MAX_TASKS {
            if azos_limits::LINUX_ABI {
                // RFC-0047: the word published at the slot's creation
                // (`publish_filter_word`): its filter's address, or 0 for a
                // Linux task. One load in place of the address arithmetic.
                FILTER_WORD[next_idx].load(Ordering::Relaxed)
            } else {
                core::ptr::addr_of!(TASKS[next_idx].syscall_filter) as usize
            }
        } else {
            0
        };
        // RFC-0047 stage 3: a Linux task's per-task CPU state (riscv64 F/D
        // file, aarch64 TPIDR_EL0) follows it. Only a switch from or to a
        // Linux task (a 0 word) takes the out-of-line path; a native switch
        // pays one load and two tests.
        if azos_limits::LINUX_ABI
            && (filter == 0 || PER_CPU[cpu].current_filter.load(Ordering::Relaxed) == 0)
        {
            crate::fp::switch_slow(PER_CPU[cpu].current_idx.load(Ordering::Relaxed), next_idx);
        }
        PER_CPU[cpu].current_idx.store(next_idx, Ordering::Relaxed);
        PER_CPU[cpu].current_filter.store(filter, Ordering::Relaxed);
    }
}

/// RFC-0047: per slot, the word `set_current_task` publishes for it: the
/// address of the slot's syscall filter, or 0 for a Linux task (the syscall
/// path then takes `zero_word_verdict`, where native tasks never go).
/// Written whenever a slot is (re)filled (`publish_filter_word`); a slot
/// never filled reads 0, and `zero_word_verdict` answers from the slot
/// itself, so a missing write costs time, never containment.
static FILTER_WORD: [AtomicUsize; MAX_TASKS] = [const { AtomicUsize::new(0) }; MAX_TASKS];

/// Publish slot `idx`'s word ([`FILTER_WORD`]) from its `abi`. Called where a
/// slot is filled, before it is runnable.
fn publish_filter_word(idx: usize) {
    if idx >= MAX_TASKS {
        return;
    }
    // Wave 13: a new occupant has not been signalled.
    signal::clear_slot_signalled(idx);
    // SAFETY: the slot is being filled under POOL_LOCK (or restored before
    // it is published); only its address and one byte are read.
    let word = unsafe {
        if TASKS[idx].abi == crate::task::ABI_LINUX && !cfg!(feature = "linux-abi-tag-canary") {
            0
        } else {
            core::ptr::addr_of!(TASKS[idx].syscall_filter) as usize
        }
    };
    FILTER_WORD[idx].store(word, Ordering::Relaxed);
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
/// (`DONATION_LOCKS`, the boost/restore re-bucketing), and under it
/// `PiMutex::pi_state`, since a PiMutex waiter's boost runs inside that
/// state lock. The full chain is `PiMutex::pi_state` -> donation lock ->
/// `CPU_LOCKS[cpu]`. Never take a donation lock or lock a `PiMutex` while
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
    if bitmap == 0 {
        return None;
    }
    let prio = bitmap.trailing_zeros() as usize;
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
    cpu_enqueue(cpu, idx)
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
    appended
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
    // for TLB shootdown and nothing ever called the sender. `tp` is the hart
    // id (`boot.S:30`), and CPU indices are hart ids, so `cpu` addresses the
    // hart directly.
    //
    // Self-enqueue needs no doorbell: this hart is by definition awake, and it
    // reaches `do_schedule` on its own path out. Sending to a hart that never
    // came up is harmless — SBI reports an error we deliberately ignore.
    // Only ring the doorbell when this call actually made the hart's queue
    // longer. A refused enqueue (K-C12: the task was already queued) has
    // nothing new to announce.
    if appended && cpu != current_cpu_id() {
        #[cfg(target_arch = "riscv64")]
        let rc = azos_arch::sbi::send_ipi(1, cpu);
        // aarch64: GICv3 SGI (`arch-api`'s `Interrupts::send_ipi`,
        // `ICC_SGI1R_EL1`) is a fire-and-forget system-register write with
        // no completion status to read back — unlike SBI's synchronous
        // ecall return code, there is no `rc` here. `0` stands for "the
        // write was issued", exactly what arch-riscv64's own
        // `Interrupts::send_ipi` impl already reports for this same call
        // shape (`sbi::send_ipi(1, target_hart)`, `rc` discarded via
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
/// arms of `kernel/src/trap/interrupt.rs` and `kernel/src/entry/aarch64.rs`).
pub fn drain_remote_wakes() {
    unsafe { remote_wake_drain_on(current_cpu_id()) }
}

#[inline(never)]
unsafe fn remote_wake_drain_slow(cpu: usize) {
    let valid = |i: usize| i < MAX_TASKS && TASK_VALID[i].load(Ordering::Relaxed);
    // With the APS backend live each entry also needs its policy mirror,
    // which takes the policy's own lock: queue them one by one, outside
    // `CPU_LOCKS`, like a direct wake does.
    if aps_dispatch_enabled() {
        let n = crate::wake_list::drain(&REMOTE_WAKE_HEAD[cpu], &REMOTE_WAKE_NEXT, |i| {
            if !valid(i) {
                REMOTE_WAKE_STALE.fetch_add(1, Ordering::Relaxed);
            } else if !wake_enqueue_post(cpu, i, cpu_enqueue_locked(cpu, i)) {
                WAKE_ENQ_REFUSED.fetch_add(1, Ordering::Relaxed);
            }
        });
        REMOTE_WAKE_DRAINED.fetch_add(n as u32, Ordering::Relaxed);
        return;
    }
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

/// U02-1 fix. `cpu_enqueue_locked` plus the APS mirror, for the four wake
/// paths (`try_wake_task`, `wq_wake_by_tid`, `wake_task_by_tid`,
/// `reap_stamped_sleepers`).
///
/// **The bug this closes.** The policy runqueues used to be fed at exactly
/// two sites: task creation (`enqueue_task_for_class` a few hundred lines
/// up) and the preempt re-enqueue in `do_schedule`. No wake path touched a
/// policy — they all called `cpu_enqueue_locked` directly. With
/// `aps_dispatch_enabled()` true, `do_schedule` consults the policies
/// first and only falls back to the legacy ring when every policy is
/// empty, so a CPU-bound task that keeps re-enqueuing itself via the
/// preempt site starves every task that has ever blocked — every IPC, I/O
/// and timer wait. Routing all four wake paths through this one function
/// closes it: every `Ready` publisher now feeds both structures.
///
/// **Gating on `aps_dispatch_enabled()`, not unconditional.** The
/// creation-time mirror is unconditional on purpose (a later flip to APS
/// must find tasks created while APS was off already populated). This one
/// follows the *preempt*-site precedent instead: mirroring a wake while
/// the backend is off would populate a runqueue nothing will ever drain
/// (`do_schedule`'s legacy branch never calls `pick_next`), for the cost of
/// one extra `with_cpu` lock on every wake. A task that blocks-then-wakes
/// while APS is off and is still alive when APS is switched on later is
/// covered the same way preempted tasks are: `aps_seed_current_classes`
/// only seeds the *running* task per CPU, so a task parked in the legacy
/// ring at flip time is picked up by the legacy fallback until it is next
/// preempted or woken with APS already active — a pre-existing gap in the
/// flip path, not one this fix introduces or is scoped to close.
///
/// **Why the return value still matters to callers.** Same contract as
/// `cpu_enqueue_locked`: `false` means the legacy ring refused the
/// enqueue (K-C26 discriminator 2), which callers that check it
/// (`wake_task_by_tid`, `reap_stamped_sleepers`) count as
/// `WAKE_ENQ_REFUSED`. On a refusal this function does not mirror into the
/// policy either — there is nothing to dispatch, so a policy entry for it
/// would itself be the stale kind `aps_pick_ready` exists to clean up.
#[inline]
unsafe fn wake_enqueue_locked(cpu: usize, idx: usize) -> bool {
    // `SCHED_REMOTE_WAKE_DEFER`: another CPU's queue is never spun on — a
    // held lock defers the wake to that CPU (see `remote_wake_try`). Its own
    // queue keeps the direct path.
    let appended = if azos_limits::SCHED_REMOTE_WAKE_DEFER && cpu != current_cpu_id() {
        match remote_wake_try(cpu, idx) {
            Some(appended) => appended,
            None => {
                crate::wake_list::push(&REMOTE_WAKE_HEAD[cpu], &REMOTE_WAKE_NEXT, idx);
                REMOTE_WAKE_DEFERRED.fetch_add(1, Ordering::Relaxed);
                ring_doorbell(cpu, idx, true);
                if azos_trace::sched_on() {
                    azos_trace::raw::sched_wakeup(task_ref(idx).tid, cpu as u32, current_task_tid());
                }
                // The refusal, if any, is counted by the drain.
                return true;
            }
        }
    } else {
        cpu_enqueue_locked(cpu, idx)
    };
    // Wave 15 (TRACE): every wake that queues a task passes here.
    if azos_trace::sched_on() {
        azos_trace::raw::sched_wakeup(task_ref(idx).tid, cpu as u32, current_task_tid());
    }
    wake_enqueue_post(cpu, idx, appended)
}

/// The APS mirror of a wake that `appended` to `cpu`'s legacy queue.
#[inline(always)]
unsafe fn wake_enqueue_post(cpu: usize, idx: usize, appended: bool) -> bool {
    let _ = (cpu, idx);
    #[cfg(feature = "sched-aps")]
    if appended && aps_dispatch_enabled() {
        let task = task_mut(idx);
        crate::aps_state::enqueue_task_for_class(
            cpu,
            task.tid,
            task.sched_class_raw,
            task.priority.load(Ordering::Relaxed).min(255) as u8,
            task.sched_time_slice_us,
            task.sched_deadline_us,
        );
        // QEMU observable for U02-1 (task 1's ask: a row proving a woken
        // task actually re-enters APS dispatch, not just the legacy
        // ring). `main.rs` is not this front's file; see the diff handed
        // to its owner for the `[APS] wake-dispatch count=N` print this
        // counter feeds.
        APS_WAKE_DISPATCH.fetch_add(1, Ordering::Relaxed);
    }
    appended
}

/// U02-1 fix, second half. Validate an APS pick before committing to it.
///
/// `Policy::pick_next` only *peeks* — the entry is removed from the
/// runqueue only when `do_schedule` actually commits to dispatching it
/// (`dequeue_task_for_class`, a few hundred lines down). A task mirrored
/// into a policy on wake can therefore go stale before this hart ever
/// picks it: it can block again, or (unpinned) be dispatched by a
/// different hart first. `idx_for_tid` still resolves a stale entry's slot
/// — the slot is valid and still carries that TID — but the task's state
/// is no longer `Ready`. The code this replaces dispatched whatever
/// `idx_for_tid` returned unconditionally
/// (`match aps_pick { Some(idx) => idx, .. }`), which would context-switch
/// onto a `Blocked` task's unswitched register state, or a `Zombie`
/// slot's.
///
/// Fix is lazy and self-healing: loop, and every non-`Ready` pick is
/// dropped from its policy (`dequeue_task_for_class` — a no-op if some
/// other path already removed it) before trying again. This is
/// deliberately NOT fixed by making `block_current` or the exit path
/// eagerly dequeue itself from its policy: that needs the enqueue CPU
/// recorded on the task (wake can target a different hart than the one
/// that blocked it) and a second lock acquisition on the hot block path,
/// for a case the dispatcher can just as well discover and shed here, at
/// the one place that was going to take the policy lock anyway.
///
/// Bounded by `policies::TOTAL_CAPACITY`: each iteration either returns a
/// validated `Some` or removes exactly one entry from exactly one policy's
/// bounded runqueue, so the loop cannot run longer than the combined
/// capacity of all five policies before every runqueue is provably empty.
#[cfg(feature = "sched-aps")]
unsafe fn aps_pick_ready(cpu: usize) -> Option<usize> {
    for _ in 0..crate::policies::TOTAL_CAPACITY {
        let meta = crate::aps_state::pick_next(cpu, 0)?;
        match idx_for_tid(meta.tid) {
            Some(idx) if task_ref(idx).state() == TaskState::Ready => return Some(idx),
            _ => {
                crate::aps_state::dequeue_task_for_class(cpu, meta.tid, meta.class as u8);
            }
        }
    }
    None
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
#[path = "slot_bitmap.rs"]
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
/// A seqlock was rejected, twice over. `crates/core/sync/src/seqlock.rs` requires
/// a single writer, and this ring has documented multi-writer paths
/// (`boost_ready_task`/`restore_ready_task` mutate it with no `CPU_LOCKS` at
/// all, reachable from `crates/core/ipc/src/lease.rs`), so the odd/even counter
/// could be left permanently odd. Worse, `SeqLock::read()` spins until the
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
/// assumed: neither is used outside this crate under any name, `policies/*`
/// and `aps_state.rs` read their own unrelated `TaskMeta` struct, and nothing
/// in the tree names `azos_sched::task::Task` at all even though it is,
/// technically, a public path. The "read from four other crates" in the
/// earlier version of this comment was true of the *concept* (`idx_for_tid`
/// et al. are called from `cap_store.rs`/`fast_ipc.rs`) but not of the
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
/// dispatches a newcomer (the ready queues are round-robin within a level);
/// a hart with one permanently runnable higher-priority task never does.
/// Liveness therefore outranks balance, and on this kernel's default layout that means
/// unpinned work concentrates on the harts without real-time residents. That
/// is the correct trade: an unbalanced-but-running task beats a
/// balanced-and-starved one.
///
/// A task's home is its pin (`cpu_affinity`) when it has one, otherwise the
/// saved `tp` that `context_switch` will restore — the same value every wake
/// path keeps in sync with the queue the task sits in.
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
pub mod hist_check {
    use super::{hist_key_of, HIST_KEY, MAX_TASKS, TASKS};
    use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
    pub static CHECKS: AtomicU32 = AtomicU32::new(0);
    pub static MISMATCH: AtomicU32 = AtomicU32::new(0);
    pub static PICK_DIFF: AtomicU32 = AtomicU32::new(0);
    /// Mismatching queries during which some slot's recorded key differed
    /// from the key its live fields give (a transition whose re-account
    /// had not run yet), and those during which none did (the scan read
    /// fields mid-write, or an `apply` was between its swap and its
    /// counter updates).
    pub static MISMATCH_STALE_KEY: AtomicU32 = AtomicU32::new(0);
    pub static MISMATCH_NO_STALE_KEY: AtomicU32 = AtomicU32::new(0);
    /// Drift episodes: a slot whose recorded key differed from its live key
    /// for `CONFIRM_TICKS` straight, same pair of keys throughout — a
    /// transition no re-account followed. Counted once per episode.
    pub static DRIFT: AtomicU32 = AtomicU32::new(0);
    pub static AUDITS: AtomicU32 = AtomicU32::new(0);

    const CONFIRM_TICKS: u64 = 100_000; // 10 ms at 10 MHz

    static SINCE: [AtomicU64; MAX_TASKS] = [const { AtomicU64::new(0) }; MAX_TASKS];
    static PAIR: [AtomicU64; MAX_TASKS] = [const { AtomicU64::new(0) }; MAX_TASKS];

    /// Whether any slot's recorded key differs from its live key right now.
    pub(super) fn any_stale_key() -> bool {
        (0..MAX_TASKS).any(|i| unsafe { HIST_KEY[i].load(Ordering::Relaxed) != hist_key_of(i) })
    }

    /// Per-tick drift audit (called from the tick's `reap_stamped_sleepers`).
    pub(super) fn audit_tick(now: u64) {
        AUDITS.fetch_add(1, Ordering::Relaxed);
        for i in 0..MAX_TASKS {
            let rec = HIST_KEY[i].load(Ordering::Relaxed);
            let live = unsafe { hist_key_of(i) };
            // A timer wake of this slot in progress on another hart is
            // between its state CAS and its re-account: every hart programs
            // the same nearest deadline, so ticks land in that window
            // together. Not drift.
            #[cfg(feature = "sched-timer-heap")]
            let waking = super::timer_sleepers::inflight(i);
            #[cfg(not(feature = "sched-timer-heap"))]
            let waking = false;
            if rec == live || waking {
                SINCE[i].store(0, Ordering::Relaxed);
                continue;
            }
            let pair = (u64::from(rec) << 32) | u64::from(live);
            let since = SINCE[i].load(Ordering::Relaxed);
            if since == 0 || PAIR[i].load(Ordering::Relaxed) != pair {
                SINCE[i].store(now.max(1), Ordering::Relaxed);
                PAIR[i].store(pair, Ordering::Relaxed);
            } else if since != u64::MAX && now.saturating_sub(since) >= CONFIRM_TICKS {
                SINCE[i].store(u64::MAX, Ordering::Relaxed);
                if DRIFT.fetch_add(1, Ordering::Relaxed) < 4 {
                    let t = unsafe { &*core::ptr::addr_of!(TASKS[i]) };
                    let len = t.name.iter().position(|&x| x == 0).unwrap_or(t.name.len());
                    azos_drv_sys::kprintln!(
                        "[SCHED] HIST_DRIFT slot={} name={} recorded={:#x} live={:#x} \
                         state={:?} prio={} affinity={} tp={} for_ticks={} ready_site={:#x}",
                        i,
                        core::str::from_utf8(&t.name[..len]).unwrap_or("<?>"),
                        rec, live, t.state(), t.priority.load(Ordering::Relaxed),
                        t.cpu_affinity, t.context.tp, now - since,
                        t.ready_site.load(Ordering::Relaxed),
                    );
                }
            }
        }
    }
}

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

// ---- Public API ----

/// AZOS Phase 1 W4-int.2 — global flag controlling dispatch path.
///
/// `false` (default) ⇒ legacy priority-queue scheduler picks tasks.
/// `true` ⇒ Adaptive Partitioning + per-class policies pick tasks.
///
/// Toggle at runtime via [`use_aps_dispatch`]. The legacy queue is
/// always maintained, so flipping the flag back to `false` returns
/// to legacy behaviour without loss of state.
///
/// Only exists with the `sched-aps` feature: a build without it has no APS
/// dispatch path to select, and `aps_dispatch_enabled()` answers `false` as
/// a compile-time constant instead of loading this atomic.
#[cfg(feature = "sched-aps")]
static SCHED_USE_APS: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

/// Enable (`true`) or disable (`false`) the W4 Adaptive Partitioning
/// dispatch. Returns the previous value.
///
/// Also mirrors the new state into the typed
/// [`crate::runtime::registry`] so consumers using the typed API
/// see a consistent value. The boolean here remains the hot-path
/// source for `aps_dispatch_enabled()`; the registry holds the
/// same fact in typed form for `procfs` + future hot-swap.
#[cfg(feature = "sched-aps")]
pub fn use_aps_dispatch(enable: bool) -> bool {
    let prev = SCHED_USE_APS.swap(enable, core::sync::atomic::Ordering::AcqRel);
    // `do_schedule` stops telling APS what is running while APS is off, so on the
    // way in every CPU is told once. A hart that switches between this read and
    // its own `set_current` leaves a stale class until its next switch, which
    // costs one time slice of mis-credited budget and self-corrects.
    if enable && !prev {
        aps_seed_current_classes();
    }
    // Mirror into the typed registry. The unwrap is sound because
    // Legacy and Aps are both `is_supported_now()`.
    let _ = crate::runtime::registry::set_active(if enable {
        crate::runtime::registry::SchedulerHandle::Aps
    } else {
        crate::runtime::registry::SchedulerHandle::Legacy
    });
    prev
}

/// Tell the APS combinator which class each CPU is running right now.
///
/// The state `do_schedule` keeps up to date while APS is in use, rebuilt from the
/// per-CPU current task for the moment APS is switched on.
#[cfg(feature = "sched-aps")]
fn aps_seed_current_classes() {
    unsafe {
        for cpu in 0..ncpu() {
            let idx = PER_CPU[cpu].current_idx.load(Ordering::Relaxed);
            if idx >= MAX_TASKS {
                let _ = crate::aps_state::with_cpu(cpu, |state| state.aps.set_idle());
                continue;
            }
            let (raw, tid) = (TASKS[idx].sched_class_raw, TASKS[idx].tid);
            if let Some(class) = crate::class::SchedClass::from_raw(raw) {
                let _ = crate::aps_state::with_cpu(cpu, |state| state.aps.set_current(class, tid));
            }
        }
    }
}

/// Returns the current state of the APS-dispatch flag.
#[cfg(feature = "sched-aps")]
#[inline]
pub fn aps_dispatch_enabled() -> bool {
    SCHED_USE_APS.load(core::sync::atomic::Ordering::Acquire)
}

/// Legacy build: the APS backend is not compiled in, so the answer is a
/// compile-time `false`. Kept as a real function (rather than deleting the
/// call sites) so every `if aps_dispatch_enabled()` guard below reads the
/// same in both builds — the guards are what the source-text tests in
/// `tests/host/sched-policy-tests` assert on, and constant-folding removes the
/// branch entirely here.
#[cfg(not(feature = "sched-aps"))]
#[inline(always)]
pub const fn aps_dispatch_enabled() -> bool {
    false
}

/// Initialize the scheduler. Call once before `task_create` / `start`.
pub fn init() {
    // PER_CPU is initialized via EMPTY_CPU const (current_idx = usize::MAX).
    // Static storage is already zero-initialized (BSS).

    // AZOS Phase 1 W4-int.2 — mark the per-CPU APS state as ready
    // for use. The window stays anchored at 0; `Aps::tick` catches
    // up in one step when the first real timer tick arrives, so we
    // don't need a time-read dep in this crate. The dispatch path is
    // *not* yet driven by APS (`SCHED_USE_APS` is false); flipping
    // the flag later activates it without touching boot init.
    #[cfg(feature = "sched-aps")]
    crate::aps_state::mark_initialised();

    // U02-3 measurement (owner order 4-1): decide the timer wheel by a
    // number, not a guess. Runs here — before any real task exists, so
    // filling the pool cannot collide with anything else — self-
    // contained, no `main.rs` edit needed.
    #[cfg(feature = "sched-tick-probe")]
    {
        run_tick_sweep_probe(false);
        run_tick_sweep_probe(true);
    }

    // The placement query's own cost, which `run_tick_sweep_probe` never
    // reaches (nothing there is dispatched). Two fill levels: the scan
    // scales with the resident count, the histogram should not.
    #[cfg(feature = "sched-tick-probe")]
    {
        run_placement_probe(15);
        run_placement_probe(MAX_TASKS);
    }
}

/// U02-3 measurement. Fills the task pool to `MAX_TASKS - 1` with
/// synthetic `Blocked` tasks, runs one `wake_expired_timers` +
/// `reap_stamped_sleepers` pass — the two O(`MAX_TASKS`) sweeps a real
/// timer tick pays — and prints `[SCHED] tick instr=N`.
///
/// **Never dispatched, never enqueued, never visible past this
/// function.** Each synthetic slot is `Blocked` on `WaitReason::WaitQueue`
/// — NOT `Timer`, so `wake_expired_timers`'s predicate (`WaitReason::Timer
/// if expired`) never matches and `try_wake_task` returns at the
/// `Mismatch`/no-op arm for every one of them: the full per-slot cost
/// (`TASK_VALID` check, `task_mut` deref, `context_saving` load, the
/// `wake_transition` CAS attempt, the predicate call) runs exactly as it
/// would for a real tick with many tasks asleep on something else, but
/// nothing is ever transitioned to `Ready` or `cpu_enqueue_locked`'d — a
/// synthetic slot has no valid `TaskContext`, so dispatching one would
/// context-switch into garbage. `reap_stamped_sleepers` short-circuits
/// even faster per slot (no `WAKE_STAMP` bit set), which is the realistic
/// common case for that sweep too.
///
/// Every slot this function marks `TASK_VALID` it restores to invalid
/// before returning, so nothing about the pool's state survives the call
/// — a diagnostic, not a boot-time side effect.
///
/// Meaningful only under `-icount shift=0,sleep=off`: outside that mode
/// `timebase::now()` (`rdtime`, wall-clock ticks) is not an instruction
/// count.
#[cfg(feature = "sched-tick-probe")]
fn run_tick_sweep_probe(on_timer: bool) {
    use crate::task::sched_word;
    unsafe {
        let sstatus = azos_arch::ARCH.disable_all();
        let _pool = PoolGuard::acquire();

        let target = MAX_TASKS.saturating_sub(1);
        let mut filled = [false; MAX_TASKS];
        let mut filled_count = 0usize;
        for i in 0..MAX_TASKS {
            if filled_count >= target {
                break;
            }
            if TASK_VALID[i].load(Ordering::Relaxed) {
                continue;
            }
            let t = task_mut(i);
            t.tid = 0; // never a live TID; `idx_for_tid` never matches 0.
            // `on_timer`: asleep on a timer that is never due in this probe
            // (`u64::MAX - 1`), so the timer path's per-sleeper cost is
            // paid without anything being woken.
            t.wait_reason = if on_timer {
                WaitReason::Timer(u64::MAX - 1)
            } else {
                WaitReason::WaitQueue
            };
            t.context_saving.store(false, Ordering::Relaxed);
            t.state_word.store(sched_word::pack(TaskState::Blocked), Ordering::Relaxed);
            publish_filter_word(i);
            core::sync::atomic::fence(Ordering::Release);
            TASK_VALID[i].store(true, Ordering::Relaxed);
            #[cfg(feature = "sched-timer-heap")]
            if on_timer {
                timer_sleepers::arm(i, u64::MAX - 1);
            }
            filled[i] = true;
            filled_count += 1;
        }

        let before = azos_drv_sys::timebase::now();
        crate::wait::wake_expired_timers(before);
        let mid = azos_drv_sys::timebase::now();
        reap_stamped_sleepers();
        let after = azos_drv_sys::timebase::now();
        let _ = nearest_timer_deadline();
        let near_ticks = azos_drv_sys::timebase::now().saturating_sub(after);

        for i in 0..MAX_TASKS {
            if filled[i] {
                #[cfg(feature = "sched-timer-heap")]
                timer_sleepers::cancel(i);
                TASK_VALID[i].store(false, Ordering::Relaxed);
                TASKS[i].wait_reason = WaitReason::None;
                TASKS[i].tid = 0;
            }
        }
        core::sync::atomic::fence(Ordering::Release);

        azos_arch::ARCH.restore(sstatus);

        let ticks = after.saturating_sub(before);
        // `-icount shift=0` advances the virtual clock one nanosecond per
        // instruction (vsbench's own convention); `TIMER_FREQ` converts
        // this device's ticks to real time. instr ≈ ticks * (1e9 / freq).
        let instr = ticks.saturating_mul(1_000_000_000)
            / (azos_drv_sys::timebase::TIMER_FREQ as u64).max(1);
        let per = |t: u64| t.saturating_mul(1_000_000_000)
            / (azos_drv_sys::timebase::TIMER_FREQ as u64).max(1);
        azos_drv_sys::kprintln!(
            "[SCHED] tick{} instr={} (ticks={} at {} filled slots, TIMER_FREQ={}) \
             wake_expired_timers={} reap_stamped_sleepers={} nearest_timer_deadline={} heap={}",
            if on_timer { "-timer" } else { "" },
            instr, ticks, filled_count, azos_drv_sys::timebase::TIMER_FREQ,
            per(mid.saturating_sub(before)), per(after.saturating_sub(mid)),
            per(near_ticks), cfg!(feature = "sched-timer-heap"),
        );
    }
}

/// U02-3 task 3a measurement, sibling of [`run_tick_sweep_probe`]: the cost
/// of ONE placement query — what every fork (`pick_target_cpu`) and every
/// real wake of an unpinned task (`wake_target_cpu`) pays — with `fill`
/// synthetic `Ready` residents spread across `MAX_CPUS` harts and most
/// priority buckets. Prints `find_best_cpu` (whichever build is active)
/// and, separately, the O(`MAX_TASKS`) scan, so one boot shows both.
///
/// `NUM_ONLINE_CPUS` is 1 this early in boot and `find_best_cpu` returns
/// `0` without looking at anything when it is `<= 1`, so this overrides it
/// to `MAX_CPUS` for the duration. Every slot it fills is freed (and, under
/// `sched-o1-placement`, re-accounted back to `NONE`) before it returns.
///
/// Meaningful only under `-icount shift=0,sleep=off` (one instruction per
/// virtual nanosecond); the resolution is one timer tick (100 instructions
/// at `TIMER_FREQ` = 10 MHz).
#[cfg(feature = "sched-tick-probe")]
fn run_placement_probe(fill: usize) {
    unsafe {
        let sstatus = azos_arch::ARCH.disable_all();
        let _pool = PoolGuard::acquire();

        let saved_online = NUM_ONLINE_CPUS.load(Ordering::Relaxed);
        NUM_ONLINE_CPUS.store(MAX_CPUS, Ordering::Relaxed);

        let target = fill.min(MAX_TASKS.saturating_sub(1));
        let mut filled = [false; MAX_TASKS];
        let mut filled_count = 0usize;
        for i in 0..MAX_TASKS {
            if filled_count >= target {
                break;
            }
            if TASK_VALID[i].load(Ordering::Relaxed) {
                continue;
            }
            let cpu = filled_count % MAX_CPUS;
            let prio = (filled_count * 7) as u32 % NUM_PRIORITIES as u32;
            let t = task_mut(i);
            t.tid = 0; // never a live TID; `idx_for_tid` never matches 0.
            t.cpu_affinity = -1;
            t.context.tp = cpu as CtxReg;
            t.priority.store(prio, Ordering::Relaxed);
            t.state_word.store(
                crate::task::sched_word::pack(TaskState::Ready),
                Ordering::Relaxed,
            );
            publish_filter_word(i);
            core::sync::atomic::fence(Ordering::Release);
            TASK_VALID[i].store(true, Ordering::Relaxed);
            hist_reaccount(i);
            filled[i] = true;
            filled_count += 1;
        }

        // `exclude = MAX_TASKS` matches no slot (a creation-time query);
        // prio 16 so a meaningful share of the residents outrank it.
        let t0 = azos_drv_sys::timebase::now();
        let pick = find_best_cpu(16, MAX_TASKS);
        let t1 = azos_drv_sys::timebase::now();
        let scan = find_best_cpu_scan(16, MAX_TASKS, MAX_CPUS);
        let t2 = azos_drv_sys::timebase::now();
        let scan_pick = pick_cpu_by_load(&scan[..MAX_CPUS]);

        for i in 0..MAX_TASKS {
            if filled[i] {
                TASK_VALID[i].store(false, Ordering::Relaxed);
                hist_reaccount(i);
                TASKS[i].tid = 0;
                TASKS[i].cpu_affinity = -1;
            }
        }
        core::sync::atomic::fence(Ordering::Release);
        NUM_ONLINE_CPUS.store(saved_online, Ordering::Relaxed);

        azos_arch::ARCH.restore(sstatus);

        let per = |ticks: u64| ticks.saturating_mul(1_000_000_000)
            / (azos_drv_sys::timebase::TIMER_FREQ as u64).max(1);
        azos_drv_sys::kprintln!(
            "[SCHED] placement fill={} find_best_cpu instr={} scan-only instr={} pick={} scan_pick={} o1={}",
            filled_count,
            per(t1.saturating_sub(t0)),
            per(t2.saturating_sub(t1)),
            pick,
            scan_pick,
            cfg!(feature = "sched-o1-placement"),
        );
    }
}

/// Create a new kernel task with CPU affinity.
///
/// `affinity`: -1 = auto-assign via `find_best_cpu`, 0..3 = pin to that hart.
/// Returns the task pool index.
///
/// Panics if the task pool is exhausted. Every existing caller of this
/// function is kernel-internal (boot-time or otherwise trusted), so pool
/// exhaustion here is a genuine system misconfiguration worth crashing
/// loudly for. **Any task-creation path reachable by unprivileged
/// userspace (e.g. `fork()`) MUST use [`try_task_create_affinity`]
/// instead** — with `panic = "abort"` in this profile a panic here is a
/// full board reset, so letting a user fork-bomb the pool would be a
/// remote/local DoS. K-A13.
/// Names that survive a `bench-minimal` boot. Everything else is skipped.
///
/// `idle` keeps a hart from falling out of `do_schedule` with nothing to run;
/// `autorun` is the measured program itself. Nothing else is needed to execute
/// a ring-3 ELF.
/// `ipc-census` is in the list even though it is a diagnostic, not something
/// the benchmark needs: gating it behind a cross-crate feature was tried and
/// the feature did not propagate, so the printer stayed parked and the counters
/// it exists to print never reached the console. The task is only *created* in
/// builds that enable `ipc-census` in the kernel, so naming it here costs a
/// string comparison and nothing else in a normal bench-minimal build.
///
/// Numbers taken with the census running are for **hunting**, not for
/// measuring: the printer competes for CPU and is not comparable with a
/// vsbench run.
#[cfg(feature = "bench-minimal")]
/// `fs-wb` (wave 15) is the FAT32 write-back cache's own flusher: parked, a
/// disk lane's writer would do every write-back itself, which is not the
/// file system being measured (Linux's flusher threads run on its side).
const BENCH_MINIMAL_KEEP: [&str; 4] = ["idle", "autorun", "ipc-census", "fs-wb"];

/// Entry point substituted for every non-allowlisted task under
/// `bench-minimal`: block forever and never consume a cycle.
///
/// **WHY substitute the entry instead of skipping the creation.** Skipping was
/// tried first and panicked during boot: the task pool's slots, names and
/// indices are load-bearing for code that runs later (topology install, the APS
/// smoke, the driver registry), and refusing to create a task quietly breaks
/// invariants far from the refusal. Creating the task and parking it keeps
/// every one of those intact — the slot exists, the name resolves, the index is
/// valid — while removing the only thing the benchmark cares about: the task
/// competing for CPU while a measurement is running.
///
/// `Timer(u64::MAX)` is a deadline no `wake_expired_timers` sweep will ever
/// reach, so the task is `Blocked` from its first instruction and is never
/// dispatched again.
#[cfg(feature = "bench-minimal")]
static BENCH_MINIMAL_ANNOUNCED: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

/// `Timer(u64::MAX)` is safe against `overflow-checks = true`: every consumer
/// of a `Timer` deadline in this tree either compares it (`now >= deadline`,
/// `wait.rs`) or folds it with `min` (`nearest_timer_deadline`, and
/// `set_next_tick_smart`, where `u64::MAX.min(tick)` yields the ordinary
/// periodic tick). None of them adds to it. Audited 2026-08-28 — a panic here
/// would reset the board.
#[cfg(feature = "bench-minimal")]
fn bench_minimal_park(_: usize) {
    loop {
        crate::task_block(crate::WaitReason::Timer(u64::MAX));
    }
}

pub fn task_create_affinity(
    name: &str,
    entry_fn: fn(usize),
    arg: usize,
    priority: u32,
    affinity: i8,
) -> usize {
    // A pin to a CPU this boot does not have (at or past `nr_cpu_ids`: the
    // DTB named fewer CPUs, or the Kconfig ceiling NR_CPUS cut them) has no
    // ready queue to go to — that CPU has no per-CPU area. Re-pin it, loudly,
    // where `rebalance_from_offline_cpus` used to after the fact, when every
    // CPU of the ceiling still had a static queue. The pin is rewritten, not
    // just clamped at each use: a pin that names another CPU than the one
    // the task runs on refuses the IPC direct switch (`ipc_direct::allowed`),
    // which cost the ipc-roundtrip lane 16 % when only the uses were clamped.
    let affinity = if affinity >= 0 && affinity as usize >= ncpu() {
        // SAFETY: a racy load scan, as at every other call site.
        let to = unsafe { find_best_cpu(priority, MAX_TASKS) }.min(ncpu() - 1);
        azos_drv_sys::kwarn!(
            "[SMP] task '{}' pinned to CPU {}, which this boot does not have (nr_cpu_ids {}) — pinned to CPU {} instead",
            name, affinity, ncpu(), to
        );
        to as i8
    } else {
        affinity
    };
    // `bench-minimal`: boot only what the measurement needs.
    //
    // **WHY this exists.** Comparing this kernel against Linux under the same
    // emulator was measuring two unequal machines: a normal boot brings up
    // ~20 tasks (rt-motor, flight-ctrl, behaviour, net-poll, telemetry,
    // watchdog, the io-ring worker…) that all compete while the benchmark
    // runs, while the Linux guest ran a single process as PID 1. It showed up
    // as noise, not as a slowdown: the syscall floor drifted 22 % between the
    // first and last batch of one run, against 2 % on the Linux side. That
    // spread is not measurement error, it is the rest of the OS working.
    //
    // **WHY the gate is here and not at the 37 call sites.** One place to
    // reason about, one place to audit, and — since the whole thing is
    // `cfg`'d out by default — literally no code in a normal build. Gating
    // each call site would have meant 30-odd edits in `main.rs`, every one of
    // them a chance to skip a task that the kernel actually needs.
    //
    // **Forked children are deliberately NOT parked.** `fork()` builds its
    // child through `try_task_create_affinity` directly (see
    // `process.rs`, where it passes the name "forked"), so it never reaches
    // this gate. That is the semantics we want -- the gate exists to silence
    // boot-time daemons, not to break `fork()` -- and it is load-bearing for
    // the IPC round-trip benchmark, whose client and server are a forked pair.
    // If `fork()` is ever rerouted through `task_create_affinity`, that
    // benchmark will hang with the child parked and the parent blocked on a
    // reply that never comes.
    //
    // This is a measurement aid, never a production configuration: a robot
    // without `rt-motor` is not a robot.
    #[cfg(feature = "bench-minimal")]
    let entry_fn = if BENCH_MINIMAL_KEEP.contains(&name) {
        entry_fn
    } else {
        // Announce once. This banner is not decoration: `vsbench_compare.sh`
        // refuses its bench-minimal (gate) column unless this line is in that
        // boot's log, so a kernel built without the feature cannot put
        // full-boot numbers under the bench-minimal label, where they would
        // read as a 5x regression. The script matches the text exactly
        // (`BENCH_MINIMAL_BANNER`): change both together.
        if !BENCH_MINIMAL_ANNOUNCED.swap(true, Ordering::Relaxed) {
            azos_drv_sys::kwarn!("[BENCH] bench-minimal: only idle+autorun run; all other tasks parked");
        }
        bench_minimal_park as fn(usize)
    };

    try_task_create_affinity(name, entry_fn, arg, priority, affinity)
        .expect("sched: task pool full")
}

/// Task-pool slots not in use right now (a racy snapshot: a creation or exit
/// on another hart can move it by one). For callers that size optional work
/// to what is left, such as the boot's stress workers on a small profile.
pub fn free_task_slots() -> usize {
    // SAFETY: an atomic load per slot, the same unsynchronised probe the
    // census helpers use; the result is advisory.
    (0..MAX_TASKS).filter(|&i| unsafe { !TASK_VALID[i].load(Ordering::Relaxed) }).count()
}

/// Fallible variant of [`task_create_affinity`] — returns `None` instead of
/// panicking when the task pool is exhausted. See that function's doc for
/// when to use this one. K-A13.
pub fn try_task_create_affinity(
    name: &str,
    entry_fn: fn(usize),
    arg: usize,
    priority: u32,
    affinity: i8,
) -> Option<usize> {
    try_task_create_init(name, entry_fn, arg, priority, affinity, TaskInit::default())
}

/// The address-space value (`Task::task_satp`) of a task that has no user
/// address space: the kernel's own root.
///
/// **riscv64**: the `satp` word `vmm::enable_paging` installed
/// (`switch_kernel_pt` = `make_satp(kernel_pagetable(), 0)`), i.e. the value
/// every boot-created kernel task already carries, so `context_switch.S`'s
/// "same satp, skip the switch" test keeps working between kernel tasks.
/// Cached: `kernel_pagetable()` takes a lock, and this runs under `POOL_LOCK`
/// on every task creation. With no kernel root built (`no-mmu`, or before
/// `vmm::init`) it is the live `satp`, what the creator's read gave before.
///
/// **aarch64**: `0`, the sentinel `context_switch.S` resolves to
/// `AARCH64_KERNEL_TTBR0` (the device-only low-half root); the kernel itself
/// lives in `TTBR1_EL1`.
///
/// **x86_64**: the CR3 word of the kernel's PML4 (PCID 0), cached as on
/// riscv64; 0 before `vmm::init` (`context_switch.S` keeps the live root).
#[inline]
pub fn kernel_task_satp() -> u64 {
    #[cfg(target_arch = "riscv64")]
    {
        static KERNEL_SATP: core::sync::atomic::AtomicU64 =
            core::sync::atomic::AtomicU64::new(0);
        let cached = KERNEL_SATP.load(Ordering::Relaxed);
        if cached != 0 {
            return cached;
        }
        let kpt = azos_mm::vmm::kernel_pagetable();
        if kpt == 0 {
            return azos_arch::csr::read_satp() as u64;
        }
        let satp = azos_arch::mmu::make_satp(kpt, 0) as u64;
        KERNEL_SATP.store(satp, Ordering::Relaxed);
        satp
    }
    // x86_64: the kernel's PML4 word, so a kernel task does not keep the
    // last user root live in CR3 (published, that root could never be torn
    // down: `root_holders` would refuse it while this CPU names it).
    #[cfg(all(target_arch = "x86_64", target_os = "none"))]
    {
        use azos_arch::ArchPlatform;
        static KERNEL_CR3: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
        let cached = KERNEL_CR3.load(Ordering::Relaxed);
        if cached != 0 {
            return cached;
        }
        let kpt = azos_mm::vmm::kernel_pagetable();
        if kpt == 0 {
            return 0;
        }
        let w = azos_arch::ARCH.user_root_word(kpt, 0) as u64;
        KERNEL_CR3.store(w, Ordering::Relaxed);
        w
    }
    #[cfg(not(any(target_arch = "riscv64", all(target_arch = "x86_64", target_os = "none"))))]
    { 0 }
}

/// Create a task with its security and scheduling identity already installed.
///
/// This is the only correct way to create a task that must not be observed
/// in a half-initialised state. Everything in `init` is written inside the
/// same `POOL_LOCK` section that fills the rest of the slot, i.e. strictly
/// before `cpu_enqueue_locked` publishes the task and rings the target
/// hart's doorbell IPI. See [`TaskInit`] for what went wrong when callers
/// patched these fields after creation instead.
pub fn try_task_create_init(
    name: &str,
    entry_fn: fn(usize),
    arg: usize,
    priority: u32,
    affinity: i8,
    init: TaskInit,
) -> Option<usize> {
    // Disable interrupts during task creation to prevent races on NEXT_TID.
    let sstatus = azos_arch::ARCH.disable_all();

    // K-C22(B): address spaces the claimed slot's PREVIOUS occupant left
    // behind, captured under POOL_LOCK and destroyed after interrupts are
    // back on (a full teardown walks and frees hundreds of frames — not
    // something to do with SIE off on an RT hart). See the reuse-time
    // comment at the capture site for why destroying here is safe at all.
    let mut stale_user_pt: u64 = 0;
    let mut stale_exec_old_pt: u64 = 0;

    let result = unsafe {
        // --- Allocate and initialize task under pool lock ---
        let alloc = {
            let _pool = PoolGuard::acquire();

            // Wave 12 (EXIT2): a child whose exit will be reported needs room
            // for its notice — see `exit_note::admits`. One atomic load when
            // no notice is queued; a slot count only while some are.
            let admitted = init.parent == 0 || {
                let notices = EXIT_NOTICES_QUEUED.load(Ordering::Acquire) as usize;
                notices == 0 || exit_note::admits(free_task_slots(), notices)
            };
            if !admitted {
                EXIT_NOTICE_REFUSALS.fetch_add(1, Ordering::Relaxed);
            }

            match if admitted { alloc_slot() } else { None } {
                None => None,
                Some(idx) => {
                    PARENT_TID[idx].store(init.parent, Ordering::Relaxed);
                    let task = task_mut(idx);

                    // U02-6 (second half): `alloc_tid` is the old
                    // wrapping-counter dance, now also skipping any
                    // candidate a live task still holds once the counter
                    // has wrapped once — see its doc.
                    let tid = alloc_tid();
                    task.tid = tid;
                    TID_SLOT[tid as usize & (TID_SLOT_LEN - 1)].store(idx as u16, Ordering::Relaxed);

                    let name_bytes = name.as_bytes();
                    let len = name_bytes.len().min(31);
                    task.name[..len].copy_from_slice(&name_bytes[..len]);
                    task.name[len] = 0;

                    task.priority.store(priority, Ordering::Relaxed);
                    task.base_priority.store(priority, Ordering::Relaxed);
                    // Pool slots are reused: a stale count from the previous
                    // occupant would keep this task permanently "donated to".
                    task.donation_count.store(0, Ordering::Relaxed);
                    // Same slot-reuse hazard for the other cross-hart flags.
                    // A stale `wake_pending` (a wake that raced the previous
                    // occupant's exit and was never consumed) would hand this
                    // task a phantom wakeup on its first block. A stale
                    // `fork_ctx_ready` (previous occupant was a fork child
                    // that died without consuming its context) is far worse:
                    // a new fork child in this slot would swap it, read the
                    // PREVIOUS process's entry/user_sp/satp, and SRET into a
                    // freed address space. `context_saving` should already be
                    // false on every exit path; clearing it is free insurance
                    // against a future path that Zombifies mid-transition.
                    // (The wake stamp lives in `state_word` now — cleared
                    // together with the state reset below, atomically.)
                    // K-C12: a stale `queued` (previous occupant died while
                    // an entry of its own still sat in a ready queue) would
                    // make this brand-new task permanently un-enqueueable —
                    // `cpu_enqueue` would refuse it forever as a duplicate.
                    // That is the same silent starvation the flag prevents,
                    // inverted.
                    task.queued.store(false, Ordering::Relaxed);
                    task.fork_ctx_ready.store(false, Ordering::Relaxed);
                    task.fork_entry   = 0;
                    task.fork_user_sp = 0;
                    task.fork_satp    = 0;
                    // K-C21: same hygiene for the exec hand-off. A stale
                    // `exec_ctx_ready` (previous occupant published an exec
                    // it never consumed — no such path exists today, but the
                    // flag must not be the thing that assumption hangs on)
                    // would make this task's next ecall SRET into the dead
                    // process's image. If one IS pending, its `exec_old_pt`
                    // is an address space nothing else references any more —
                    // hand it to the same reuse-time reclaim as `user_pt`
                    // below instead of leaking it.
                    if task.exec_ctx_ready.swap(false, Ordering::Relaxed) {
                        EXEC_HANDOFFS.fetch_sub(1, Ordering::Relaxed);
                        stale_exec_old_pt = task.exec_old_pt;
                    }
                    task.exec_entry   = 0;
                    task.exec_user_sp = 0;
                    task.exec_sstatus = 0;
                    task.exec_satp    = 0;
                    task.exec_old_pt  = 0;
                    task.context_saving.store(false, Ordering::Relaxed);
                    task.time_slice    = if is_rt_priority(priority) {
                        RT_TIME_SLICE_TICKS
                    } else {
                        TIME_SLICE_TICKS
                    };
                    task.cpu_affinity  = affinity;
                    // One plain store resets state AND clears any stale wake
                    // stamp from the slot's previous occupant — the only
                    // place a plain (non-CAS) store of the word is correct,
                    // because the slot is not yet visible to any waker.
                    task.state_word.store(
                        crate::task::sched_word::pack(TaskState::Ready),
                        Ordering::Relaxed,
                    );
                    // K-C26 provenance — see `Task::ready_site`.
                    task.ready_site.store(
                        crate::task::ready_site::CREATE
                            | ((current_cpu_id() as u8) << 4),
                        Ordering::Relaxed,
                    );
                    task.wait_reason    = WaitReason::None;
                    // The slot is being reused: a reservation its previous
                    // occupant still held (one that died without passing the
                    // dispatch tail's reap) leaves its hart's set and ledger.
                    rt::release(idx);
                    // N6: the slot's SC starts over in its priority's class.
                    classes::on_slot_reset(idx, priority);
                    // Wave 13: a reused slot is in no thread group.
                    crate::group::slot_reset(idx);
                    // The slot reset installs `disabled()` — which means
                    // ALLOW EVERYTHING. A caller that wants this task
                    // confined must have its filter land here, under
                    // POOL_LOCK, and not after the enqueue below has already
                    // made the task dispatchable on another hart.
                    task.syscall_filter = match init.syscall_filter {
                        Some(f) => f,
                        None => SyscallFilter::disabled(),
                    };
                    task.stack_idx      = idx;
                    task.entry_fn       = entry_fn as usize;
                    task.entry_arg      = arg;

                    // AZOS Phase 1 W4-int — multi-policy scheduler defaults.
                    // The legacy entry points (`task_create`, `task_create_affinity`)
                    // default to `BestEffort` to preserve current behaviour. The
                    // new fields are not yet consulted by the dispatch core; W4-int.2
                    // will wire them through `Aps::pick_class`.
                    task.sched_class_raw     = init
                        .class_raw
                        .unwrap_or(crate::task::DEFAULT_SCHED_CLASS_RAW);
                    task._sched_pad          = [0u8; 2];
                    crate::fp::reset(idx);
                    // RFC-0047: native unless the creator asked for the Linux
                    // personality; in place before the enqueue publishes the
                    // task (a spawned child is switched to while it waits for
                    // its hand-off, and its filter word is cached then).
                    task.abi = if azos_limits::LINUX_ABI { init.abi } else { crate::task::ABI_NATIVE };
                    publish_filter_word(idx);
                    task.sched_time_slice_us = init.time_slice_us;
                    // `NO_DEADLINE` is 0 today, so this reads as an identity —
                    // it is the `TaskInit` contract ("0 means keep the default")
                    // written where it survives that constant changing.
                    task.sched_deadline_us   = if init.deadline_us == 0 {
                        crate::task::NO_DEADLINE
                    } else {
                        init.deadline_us
                    };

                    // Stack grows down; top is the (ABI-aligned) end of the slice.
                    let stack_top = task_stack_top(idx);
                    // x86_64: `context_switch` jumps to the entry, which the
                    // SysV ABI enters with RSP = 8 mod 16, as after a `call`.
                    // arch-only: the other ISAs enter at the slice's aligned end.
                    #[cfg(all(target_arch = "x86_64", target_os = "none"))]
                    let stack_top = stack_top - 8;

                    let entry_addr = task_entry_wrapper as *const () as usize as CtxReg;
                    let target_cpu = pick_target_cpu(affinity, priority, idx);
                    task.context = TaskContext {
                        sp: stack_top as CtxReg,
                        pc: entry_addr,
                        ra: entry_addr,
                        tp: target_cpu as CtxReg,
                        ..Default::default()
                    };
                    // Placement histogram: the slot's home is now known.
                    // Until here its recorded key was `NONE` (freed slots
                    // are re-accounted to `NONE`), which is also what
                    // `pick_target_cpu(.., idx)` above excluded.
                    hist_reaccount(idx);

                    // Phase 7: per-task SATP and user-space fields (requires MMU).
                    //
                    // K-C22(B), now the FALLBACK: `task_exit()` frees the
                    // dying task's address space itself since K-C22(C) — it
                    // first moves its own hart onto the kernel root (see
                    // `release_address_space_at_exit`), which is what the
                    // original deferral to REUSE time, i.e. right here, was
                    // working around: the exiting hart used to stay on that
                    // satp until `do_schedule()` switched away. A `user_pt`
                    // still found here belongs to a task that never ran that
                    // path with it (a fork/spawn child published after it
                    // exited). K-C6 frees the slot only in the
                    // `do_schedule()` call that is about to context-switch
                    // off the dying task's stack. Zeroing without destroying
                    // (the old code) leaked the whole address space. Capture
                    // under POOL_LOCK, destroy after SIE is restored (see
                    // `stale_user_pt` above).
                    //
                    // Residual window, argued exactly: the Zombie arm clears
                    // TASK_VALID a few dozen instructions BEFORE its
                    // `context_switch()` reaches `csrw satp`, so a claim can
                    // land while the freeing hart is still on the dying PT.
                    // In that tail the freeing hart runs straight-line,
                    // IRQ-off kernel code (spin-gate, a handful of stores,
                    // the register restore) touching only kernel text /
                    // stacks / .bss — all of which resolve through the
                    // kernel L1 tables the teardown BORROWS and never frees
                    // (`destroy_user_pagetable_skip_range` skips
                    // `k_l1 == u_l1`). The only frame that hart still needs
                    // is the PT ROOT, which the teardown frees LAST — after
                    // this claim finishes slot init + enqueue under two more
                    // locks, restores SIE, and walks all 512 L2 slots (a
                    // deliberate, load-bearing property; noted on the vmm
                    // fn). "Orders of magnitude" of guest instructions was
                    // the argument, and it does not hold once the host
                    // deschedules the dying hart's vCPU inside those few
                    // instructions: on 5c805b9, where every exit took this
                    // path, 3 of 119 probed abitest boots freed a root
                    // another hart still had published, and one boot of an
                    // earlier run took the kernel page fault (the trap
                    // vector fetched through the freed root, with idle's
                    // registers already restored by `context_switch`).
                    // The teardown now refuses a root any hart still
                    // publishes (`Mmu::root_holders`); here that turns the
                    // race into a leaked address space.
                    {
                        // Every new task starts on the KERNEL's root; a task
                        // that gets a user address space (fork, spawn, exec)
                        // has it installed later by `set_task_user_info` /
                        // `set_current_user_info`. This used to be the
                        // CREATOR's live `satp`: a kernel task created from a
                        // user context (the io_ring SQ poller, created inside
                        // its owner's submit syscall) ran on that user's page
                        // table, which the owner's exit frees. See
                        // `kernel_task_satp`.
                        task.task_satp = kernel_task_satp();
                        stale_user_pt  = task.user_pt;
                        task.user_pt   = 0;
                        task.user_brk  = 0;
                        // Owner decision 102 — the address space this counted
                        // is being discarded, so the count goes with it. A
                        // slot that kept a dead task's frame count would hand
                        // the next task to occupy it a budget already spent.
                        //
                        // The WHOLE budget, limit included (RFC-0049 M1):
                        // `reset()` keeps the limit, so a slot used to hand
                        // its next tenant -- a fork child, a spawned image, a
                        // kernel task -- the previous occupant's ceiling. Every
                        // path that gives a task a budget now sets it.
                        task.budget = azos_mm::budget::PageBudget::new();
                        task.mem = crate::task::TaskMem::new();
                        task.user_window = [[0; 2]; crate::user_window::USER_WINDOW_RANGES];
                        task.reap_on_resume = 0;
                    }

                    // Phase 16: write stack canary at the bottom of the stack (lowest
                    // address).  Stack grows downward, so this is the first location
                    // overwritten on overflow.  Checked by `stack_canary_check()`.
                    // Skip when guard pages are active — the bottom page is unmapped
                    // and writing the canary would page fault.
                    if !GUARD_PAGES_ACTIVE.load(Ordering::Acquire) {
                        (TASK_STACKS.0[idx].as_mut_ptr() as *mut u64).write_volatile(stack_canary());
                    }

                    Some((idx, target_cpu))
                }
            }
        }; // pool lock released here

        match alloc {
            None => None,
            Some((idx, target_cpu)) => {
                // --- Enqueue to target CPU under CPU lock ---
                // `target_cpu` may differ from the creating CPU (priority-aware
                // assignment or explicit affinity) — always go through the locked
                // wrapper.
                // K-C12: a brand-new task can never be a duplicate (its
                // `queued` flag was just cleared), so a refusal here can only
                // mean the ring is genuinely full. Fail the creation instead
                // of returning a task index for something that is in no ready
                // queue and will never run: `fork()` reports -1, which its
                // caller already handles, and the pool slot goes back.
                if !cpu_enqueue_locked(target_cpu, idx) {
                    // Inner scope on purpose: `PoolGuard::drop` re-applies the
                    // SIE bit it captured (interrupts already off here), so it
                    // MUST run before the caller's `sstatus` is restored —
                    // otherwise the guard drops last and leaves this hart with
                    // interrupts disabled all the way back up the stack.
                    {
                        let _pool = PoolGuard::acquire();
                        TASK_VALID[idx].store(false, Ordering::Relaxed);
                        hist_reaccount(idx);
                        // Mirror of alloc_slot's sentinel protocol: unpublish,
                        // fence, then clear the tid so no unsynchronised scan
                        // can ever again match this task's TID against the
                        // slot's next life.
                        core::sync::atomic::fence(Ordering::Release);
                        TASKS[idx].tid = 0;
                    }
                    azos_arch::ARCH.restore(sstatus);
                    // K-C22(B): the claim already zeroed the slot's `user_pt`
                    // — the captured stale address spaces must be destroyed
                    // on THIS exit too, or they become unreachable forever.
                    if (stale_user_pt | stale_exec_old_pt) != 0 {
                        REUSE_TEARDOWNS.fetch_add(1, Ordering::Relaxed);
                        reclaim_stale_user_pts(stale_user_pt, stale_exec_old_pt);
                    }
                    return None;
                }

                // AZOS Phase 1 W4-int.2 — mirror into the per-class policy
                // runqueue so flipping `SCHED_USE_APS` later finds tasks
                // already populated. The class is read from task fields
                // (defaults to BestEffort for legacy callers).
                //
                // Unguarded by `aps_dispatch_enabled()` on purpose — the
                // mirror is what makes a later flip find a populated
                // runqueue. A Legacy-only build has no runqueue to mirror
                // into, so the whole block goes with the backend.
                #[cfg(feature = "sched-aps")]
                {
                    let task = task_mut(idx);
                    crate::aps_state::enqueue_task_for_class(
                        target_cpu,
                        task.tid,
                        task.sched_class_raw,
                        task.priority.load(Ordering::Relaxed).min(255) as u8,
                        task.sched_time_slice_us,
                        task.sched_deadline_us,
                    );
                }

                Some(idx)
            }
        }
    };

    // Restore interrupts.
    azos_arch::ARCH.restore(sstatus);
    // Wave 15 (TRACE): the proc class's spawn record (every task, kernel or
    // user, fork or spawn, is created here).
    if azos_trace::proc_on() {
        if let Some(idx) = result {
            azos_trace::raw::proc_spawn(unsafe { task_ref(idx).tid }, current_task_tid());
        }
    }
    // K-C22(B): reuse-time reclaim of the previous occupant's address
    // space(s), with interrupts back on. Runs before the caller learns the
    // new index, but after the new task is enqueued — harmless: the new task
    // holds `user_pt = 0` and never references what is being freed. A
    // fallback since K-C22(C): the exit path frees its own, so this finds
    // something only in the cases `release_address_space_at_exit` lists.
    if (stale_user_pt | stale_exec_old_pt) != 0 {
        REUSE_TEARDOWNS.fetch_add(1, Ordering::Relaxed);
        reclaim_stale_user_pts(stale_user_pt, stale_exec_old_pt);
    }
    result
}

/// K-C22(B)/(C): destroy address spaces recovered from an exiting task
/// ([`release_address_space_at_exit`]) or from a reused task slot.
///
/// Callable ONLY with page tables no hart can still hold in satp/TLB: the
/// exit path's switch-then-free argument, or the reuse-time argument in
/// `try_task_create_affinity`.
/// Goes through `process::destroy_user_address_space` — not bare
/// `vmm::destroy_user_pagetable` — so shm/MMIO frames mapped into the dead
/// address space are spared (they are owned by the shm registry / the
/// hardware, not by the page table; see that function).
fn reclaim_stale_user_pts(user_pt: u64, exec_old_pt: u64) {
    if user_pt != 0 {
        crate::process::destroy_user_address_space(user_pt);
    }
    if exec_old_pt != 0 {
        crate::process::destroy_user_address_space(exec_old_pt);
    }
}

/// Create a new kernel task, auto-assigned to the CPU where a task of this
/// priority will actually get dispatched (K-C12 — see [`find_best_cpu`]).
///
/// Returns the task pool index (for debugging; rarely needed by callers).
pub fn task_create(name: &str, entry_fn: fn(usize), arg: usize, priority: u32) -> usize {
    task_create_affinity(name, entry_fn, arg, priority, -1)
}

/// AZOS Phase 1 W4-int — create a task with explicit scheduler-class
/// metadata (RFC-0004).
///
/// - `class_raw` — `SchedClass` discriminant (see
///   `azos_sched::class::SchedClass`).
/// - `deadline_us` — absolute monotonic-time deadline in microseconds.
///   Pass `crate::task::NO_DEADLINE` (= 0) for non-EDF tasks.
/// - `time_slice_us` — quantum for `Rr` / CBS budget seed. `0` ⇒
///   policy default.
///
/// The new fields are stored on the task; the live scheduler does not
/// yet consult them (W4-int.2). Callers can use this entry point
/// today so existing initialisation code is forward-compatible.
pub fn task_create_with_class(
    name: &str,
    entry_fn: fn(usize),
    arg: usize,
    priority: u32,
    affinity: i8,
    class_raw: u8,
    deadline_us: u64,
    time_slice_us: u32,
) -> usize {
    // The class metadata travels INTO the creation, so the task is mirrored
    // into the right policy runqueue the first time. The previous version
    // created the task under the default `BestEffort` class, let
    // `cpu_enqueue_locked` publish it (doorbell IPI included), and only then
    // moved it with a `dequeue_task_for_class`/`enqueue_task_for_class`
    // pair — a window in which the task could be dispatched from the wrong
    // policy queue, and in which the dequeue could run against a task that
    // was already executing. See [`TaskInit`].
    try_task_create_init(
        name, entry_fn, arg, priority, affinity,
        TaskInit {
            syscall_filter: None,
            class_raw: Some(class_raw),
            deadline_us,
            time_slice_us,
            parent: 0,
            abi: crate::task::ABI_NATIVE,
        },
    )
    .unwrap_or(MAX_TASKS)
}

/// Translate a `tid` to a slot index in the global `TASKS[]` array.
///
/// O(1) on a `TID_SLOT` hint hit (the common case: every publisher of a
/// tid records the hint at the same time), falling back to an
/// O(`MAX_TASKS`) scan only on a hint miss (stale, colliding, or never
/// set) — this doc used to describe only the fallback, before the hint
/// existed. Used well beyond the APS dispatch path now: every wake path,
/// `EXIT_NOTE`'s orphan check, and `alloc_tid`'s post-wrap search all
/// depend on the hint-hit case staying cheap.
pub fn idx_for_tid(tid: u32) -> Option<usize> {
    // TID 0 is the sentinel `alloc_slot` parks in a slot before publishing
    // it (and the free sites park after unpublishing) — it never names a
    // task, so it must never match one.
    if tid == 0 {
        return None;
    }
    unsafe {
        // The published slot for this TID, verified exactly as the scan below
        // verifies a match. A hint that is stale, collides with another live
        // TID, or was never set fails the check and falls through to the scan,
        // so it can only cost time.
        let hint = TID_SLOT[tid as usize & (TID_SLOT_LEN - 1)].load(Ordering::Relaxed) as usize;
        if hint < MAX_TASKS
            && TASK_VALID[hint].load(Ordering::Relaxed)
            && TASKS[hint].tid == tid
        {
            core::sync::atomic::fence(Ordering::Acquire);
            if TASK_VALID[hint].load(Ordering::Relaxed) && TASKS[hint].tid == tid {
                return Some(hint);
            }
        }
        for i in 0..MAX_TASKS {
            if TASK_VALID[i].load(Ordering::Relaxed) && TASKS[i].tid == tid {
                // Pairs with the Release fences in `alloc_slot` and the free
                // sites: having (tentatively) observed a match, order the
                // re-reads after everything the publisher wrote before its
                // fence. A mid-allocation slot re-reads as tid 0 and is
                // rejected; only a slot whose tid was genuinely published
                // (or a torn first read that the re-read corrects) survives.
                // Fence-per-MATCH, not per-iteration — a resolution walks up
                // to 64 slots and this path is on every cap operation.
                core::sync::atomic::fence(Ordering::Acquire);
                if TASK_VALID[i].load(Ordering::Relaxed) && TASKS[i].tid == tid {
                    // Re-publish the hint (wave 13). A later TID sharing this
                    // bucket overwrote it at its creation, and nothing put it
                    // back when that task exited: every lookup of this TID
                    // then walked the table (measured: +156 instructions on
                    // each typed call of a long-lived task after 256 task
                    // creations, the thread lanes' churn). A stale or racing
                    // hint is verified like any other, so this only saves time.
                    TID_SLOT[tid as usize & (TID_SLOT_LEN - 1)].store(i as u16, Ordering::Relaxed);
                    return Some(i);
                }
            }
        }
    }
    None
}

/// Translate a slot index in `TASKS[]` to its `tid`. Inverse of
/// [`idx_for_tid`]. Returns `None` if the slot is not a valid task.
pub fn tid_for_idx(idx: usize) -> Option<u32> {
    if idx >= MAX_TASKS {
        return None;
    }
    unsafe {
        if TASK_VALID[idx].load(Ordering::Relaxed) {
            Some(TASKS[idx].tid)
        } else {
            None
        }
    }
}

/// Update the scheduler-class metadata of an existing task. Intended
/// for tests and the topology-bind path (W5+). The live dispatch core
/// does not yet consult these fields.
pub fn task_set_class(idx: usize, class_raw: u8, deadline_us: u64, time_slice_us: u32) {
    if idx >= MAX_TASKS {
        return;
    }
    unsafe {
        if !TASK_VALID[idx].load(Ordering::Relaxed) {
            return;
        }
        let task = task_mut(idx);
        task.sched_class_raw     = class_raw;
        task.sched_deadline_us   = deadline_us;
        task.sched_time_slice_us = time_slice_us;
    }
}

/// Create a task with a security profile pre-applied.
///
/// The filter is set before the task ever runs — it cannot call any
/// unauthorized syscall, not even during initialization.
///
/// An unknown `profile_id` FAILS CLOSED to `PROFILE_MINIMAL` (exit/yield/
/// sleep/write/brk only) and logs. This function returns a task index with
/// no error channel, so the old behaviour — `profile_to_filter` handing
/// back a disabled filter for any unrecognised id — created a fully
/// *unrestricted* child while the caller believed it had sandboxed one,
/// with no return code that could have revealed the difference. A child
/// that is too confined to work fails loudly during bring-up; a child that
/// is silently unconfined does not fail at all until it matters.
pub fn task_create_filtered(
    name: &str, entry_fn: fn(usize), arg: usize,
    priority: u32, profile_id: u64,
) -> usize {
    // Resolve the profile BEFORE creating anything: a task must never exist,
    // however briefly, in a state its creator did not ask for.
    let filter = match crate::seccomp::profile_to_filter(profile_id) {
        Some(f) => f,
        None => {
            azos_drv_sys::kwarn!(
                "[SECCOMP] unknown profile {} for task '{}' — failing closed to MINIMAL",
                profile_id, name
            );
            // `PROFILE_MINIMAL` is a known-good id, so the `None` arm is
            // unreachable — but it must not be `unwrap()` (panic = board
            // reset) nor `SyscallFilter::disabled()` (that is the exact
            // silent-unrestricted bug being fixed). Deny-everything is the
            // only fallback that stays fail-closed without panicking.
            crate::seccomp::profile_to_filter(crate::seccomp::PROFILE_MINIMAL)
                .unwrap_or_else(|| {
                    let mut deny_all = crate::task::SyscallFilter::disabled();
                    deny_all.enabled = true;
                    deny_all
                })
        }
    };
    // The filter is installed under POOL_LOCK, before the task is enqueued.
    //
    // It used to be written after `task_create` returned — and `task_create`
    // returns only once `cpu_enqueue_locked` has put the task in a ready
    // queue AND rung the target hart's doorbell IPI. The slot reset leaves
    // `SyscallFilter::disabled()` behind, and `disabled` is allow-everything,
    // so a task created to be sandboxed was dispatchable unconfined for the
    // length of that window — one the kernel actively signals another CPU to
    // come and use. See [`TaskInit`].
    try_task_create_init(
        name, entry_fn, arg, priority, -1,
        TaskInit { syscall_filter: Some(filter), ..TaskInit::default() },
    )
    .unwrap_or(MAX_TASKS)
}

/// Called when a task's entry function returns.
///
/// Marks the task as zombie and immediately tries to reschedule. If no tasks
/// are ready, enters a WFI idle loop (timer interrupts will call
/// `schedule()` to pick up future tasks).
///
/// K-C6: deliberately does NOT free the task's pool slot (`TASK_VALID`) or
/// clear `PER_CPU[cpu].current_idx` — this function is still executing ON
/// the exiting task's own stack, so doing either here would let another
/// hart's `alloc_slot()` (e.g. via `fork()`) reuse and dispatch a brand new
/// task onto that same physical stack while this hart is still running on
/// it. `do_schedule()` frees the slot itself, in the same call that
/// `context_switch()`s away from it — see its `old.state == Zombie` arm.
///
/// Hook invoked with the dying task's TID from [`task_exit`].
///
/// `crates/core/ipc` depends on `crates/core/sched`, so `sched` cannot call into it
/// directly without a dependency cycle — hence the same registered-callback
/// shape already used for priority inheritance (`pi_set_callbacks`). The
/// kernel registers `task_release_all_resources` (which calls
/// `azos_ipc::task_release_all`) here at boot.
///
/// Stored as `AtomicUsize` (pointer-sized), like the PI callbacks.
static TASK_EXIT_HOOK: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(0);

/// Register the [`TASK_EXIT_HOOK`]. Call once, during boot.
pub fn set_task_exit_hook(f: fn(u32)) {
    TASK_EXIT_HOOK.store(f as usize, Ordering::Release);
}

/// Wave 15 (plan 4a): called when an exec'ing thread takes its process's
/// identity from the leader (`exec_take_over`) with `(from_idx, to_idx, tid)`:
/// what other crates keep per pool slot for the process (`azos_ipc`'s
/// capability table, the seed row `natfork` recorded) moves from the
/// leader's slot to the thread's, which the TID swap right after names
/// `tid`. Called with interrupts off, before that swap. Registered by the
/// kernel at boot, as [`TASK_EXIT_HOOK`].
static TASK_IDENTITY_HOOK: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(0);

/// Register the [`TASK_IDENTITY_HOOK`]. Call once, during boot.
pub fn set_task_identity_hook(f: fn(usize, usize, u32)) {
    TASK_IDENTITY_HOOK.store(f as usize, Ordering::Release);
}

/// Called with the exiting task's TID after its address space is torn down
/// (`release_address_space_at_exit`) and before its exit notice: for what
/// must not happen while the dying task still holds memory (wave 12: the
/// driver supervisor's wake). Registered by the kernel at boot, as
/// [`TASK_EXIT_HOOK`].
static TASK_EXIT_LATE_HOOK: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(0);

/// Register the [`TASK_EXIT_LATE_HOOK`]. Call once, during boot.
pub fn set_task_exit_late_hook(f: fn(u32)) {
    TASK_EXIT_LATE_HOOK.store(f as usize, Ordering::Release);
}

/// Does the live task `tid` still hold a user address space? `false` for a
/// kernel task, for a task whose exit has torn its space down, and for a TID
/// with no slot. For ordering checks on the exit path (wave 12).
pub fn tid_holds_address_space(tid: u32) -> bool {
    match idx_for_tid(tid) {
        // SAFETY: a valid slot index; one word read, as `note_exit` does.
        Some(idx) => unsafe { task_ref(idx).user_pt != 0 },
        None => false,
    }
}

/// Fork-time bootstrap capability grant (RFC-0040 gap 3), mirroring
/// [`TASK_EXIT_HOOK`] above for the same reason: `crates/core/ipc` depends on
/// `crates/core/sched`, so this crate cannot call `azos_ipc::task_fork_grant`
/// directly without a dependency cycle. `kernel/src/boot/sched.rs`'s
/// `install_sched_hooks` registers it alongside `set_task_exit_hook`.
///
/// `fn(u32, u32)` is `(parent_tid, child_tid)` — unlike the exit hook, both
/// identities are needed, and the caller (`sys_fork_impl`, still running as
/// the parent) already has both without a lookup, so the signature carries
/// them rather than making the callee re-derive one.
///
/// Stored as `AtomicUsize` (pointer-sized), like [`TASK_EXIT_HOOK`].
static TASK_FORK_HOOK: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(0);

/// Register the [`TASK_FORK_HOOK`]. Call once, during boot.
pub fn set_task_fork_hook(f: fn(u32, u32)) {
    TASK_FORK_HOOK.store(f as usize, Ordering::Release);
}

/// Invoke the registered [`TASK_FORK_HOOK`], if one was registered.
///
/// A no-op before boot registration — same convention as `TASK_EXIT_HOOK`'s
/// call site: a missing hook is a silent no-grant, not a panic, because a
/// host-side unit test or an early-boot fork must not crash for lacking a
/// capability subsystem it never asked for.
pub(crate) fn invoke_task_fork_hook(parent_tid: u32, child_tid: u32) {
    let raw = TASK_FORK_HOOK.load(Ordering::Acquire);
    if raw != 0 {
        let f: fn(u32, u32) = unsafe { core::mem::transmute(raw) };
        f(parent_tid, child_tid);
    }
}

/// K-C22(C): tear down the exiting task's address space on its own exit path.
///
/// Called by [`task_exit_with_code`] for the task running on this hart (slot
/// `idx`), after the exit hook and before the Zombie mark. The order inside is
/// load-bearing, because interrupts are ON here and a tick may switch this
/// task out and back in at any point:
///
///  1. `task_satp` becomes the kernel's root and `user_pt` is taken (zeroed)
///     FIRST. A switch back into this task after that installs the kernel
///     root, never the table being freed.
///  2. This hart leaves the user table: riscv64 `csrw satp` to the kernel root
///     (`csr::write_satp`: publishes the root for the shootdown scan, full
///     `sfence.vma`); aarch64 `TTBR0_EL1` to the kernel's device-only low-half
///     root (`AARCH64_KERNEL_TTBR0`) plus a local `tlbi vmalle1`. Kernel
///     text, data and stacks resolve through the kernel root on riscv64 and
///     through `TTBR1_EL1` on aarch64, so execution continues unchanged.
///  3. Only then the teardown. No hart holds the table any more: this one
///     just left it, and any other that ran it flushed when it switched
///     away (every address-space switch is a full local flush on both ISAs),
///     so nothing can walk the frames the allocator is about to reissue. It
///     runs with interrupts on, like the reuse-time reclaim it replaces.
///     The teardown checks that rather than trusting it
///     (`Mmu::root_holders`): a hart still on the table gets the address
///     space refused and leaked, never freed under it.
///
/// A pending exec hand-off (published, never consumed — no path does that
/// today, see `try_task_create_init`) leaves the replaced table in
/// `exec_old_pt`; it is freed here too.
///
/// K-C22(B)'s reuse-time reclaim stays as the fallback for a table that is
/// published on a slot after its task already passed this point (a fork or
/// spawn child that died before its parent's `set_task_user_info`), and for
/// aarch64 before the kernel root is published (never, after boot): then
/// nothing is switched or freed here and the claim frees it.
unsafe fn release_address_space_at_exit(idx: usize) {
    let task = task_mut(idx);
    if task.user_pt == 0 && !task.exec_ctx_ready.load(Ordering::Relaxed) {
        return; // a kernel task: nothing to release, nothing to switch
    }

    // arch-only: aarch64's device-only low-half root (TTBR0); riscv64 and an
    // x86_64 port keep the kernel in every user table and switch to the
    // kernel task's own root below.
    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    let kernel_root = {
        unsafe extern "C" {
            // `kernel/src/entry/aarch64.rs`: the device-only low-half root
            // `context_switch.S` installs for `task_satp == 0`.
            static AARCH64_KERNEL_TTBR0: core::sync::atomic::AtomicU64;
        }
        let root = unsafe { AARCH64_KERNEL_TTBR0.load(Ordering::Acquire) };
        if root == 0 {
            return; // not published: leave both tables to the reuse fallback
        }
        root
    };

    // Step 1.
    task.task_satp = kernel_task_satp();
    let user_pt = core::mem::replace(&mut task.user_pt, 0);
    task.user_brk = 0;
    let exec_old_pt = if task.exec_ctx_ready.swap(false, Ordering::Relaxed) {
        EXEC_HANDOFFS.fetch_sub(1, Ordering::Relaxed);
        core::mem::replace(&mut task.exec_old_pt, 0)
    } else {
        0
    };
    // The switch below must not be hoisted above the stores that tell a
    // context switch which root to install for this task.
    core::sync::atomic::compiler_fence(Ordering::SeqCst);

    // Step 2. `exit-satp-canary` (gate canary) skips it: the teardown then
    // finds this hart still on the table and must refuse it (see step 3).
    #[cfg(all(target_arch = "riscv64", not(feature = "exit-satp-canary")))]
    azos_arch::csr::write_satp(task.task_satp as usize);
    #[cfg(all(target_arch = "aarch64", target_os = "none", not(feature = "exit-satp-canary")))]
    azos_arch::sysregs::install_ttbr0_flush_local(kernel_root as usize);
    #[cfg(all(target_arch = "aarch64", target_os = "none", feature = "exit-satp-canary"))]
    let _ = kernel_root;
    // Any other ISA (the x86_64 skeleton): the contract's local root install
    // (riscv64's arm above is that same call: `write_satp`).
    #[cfg(all(target_os = "none", not(any(target_arch = "riscv64", target_arch = "aarch64")), not(feature = "exit-satp-canary")))]
    azos_arch::ArchPlatform::install_user_root_local(&azos_arch::ARCH, task.task_satp as usize);

    // Step 3.
    EXIT_TEARDOWNS.fetch_add(1, Ordering::Relaxed);
    reclaim_stale_user_pts(user_pt, exec_old_pt);
}

/// Address spaces torn down on the exit path ([`release_address_space_at_exit`]).
pub static EXIT_TEARDOWNS: AtomicU32 = AtomicU32::new(0);

/// Address spaces the slot-reuse fallback (K-C22(B)) found and tore down.
/// Zero on a run where every exit released its own.
pub static REUSE_TEARDOWNS: AtomicU32 = AtomicU32::new(0);

/// Exit notices published while the exiting task still held its address
/// space ([`note_exit`]). Zero while `task_exit_with_code` notifies after
/// the teardown; any other count means a parent could reap a child whose
/// memory was not back yet.
pub static EARLY_EXIT_NOTICES: AtomicU32 = AtomicU32::new(0);

/// `SYS_EXIT_STATS` (605): the exit-path counter `which` names
/// (`azos_abi::syscall_nr::EXIT_STAT_*`), or `None` for any other value.
/// Totals since boot, for every task.
pub fn exit_stat(which: u64) -> Option<u32> {
    use azos_abi::syscall_nr::{
        EXIT_STAT_EARLY_NOTICES, EXIT_STAT_EXIT_TEARDOWNS, EXIT_STAT_NOTICE_DROPS,
        EXIT_STAT_NOTICE_REFUSALS, EXIT_STAT_REUSE_TEARDOWNS,
    };
    let c = match which {
        EXIT_STAT_EXIT_TEARDOWNS => &EXIT_TEARDOWNS,
        EXIT_STAT_REUSE_TEARDOWNS => &REUSE_TEARDOWNS,
        EXIT_STAT_EARLY_NOTICES => &EARLY_EXIT_NOTICES,
        EXIT_STAT_NOTICE_DROPS => &EXIT_NOTICE_DROPS,
        EXIT_STAT_NOTICE_REFUSALS => &EXIT_NOTICE_REFUSALS,
        _ => return None,
    };
    Some(c.load(Ordering::Relaxed))
}

/// Never returns.
pub fn task_exit() -> ! { task_exit_with_code(0) }

/// Wave 13: end the current task by a signal: exit code `code` (`128 + n`,
/// what native waiters read, unchanged), and the signal recorded so a Linux
/// parent's `wait4` reports the child killed by `n` (`WIFSIGNALED`), as
/// Linux does. A code outside `129..=192` is an ordinary exit.
pub fn task_exit_by_signal(code: i32) -> ! {
    if (129..=192).contains(&code) {
        signal::mark_current_signalled((code - 128) as u32);
    }
    task_exit_with_code(code)
}

/// End only the calling thread (Linux `exit`, the native thread exit; wave
/// 13). For a task in no thread group it is [`task_exit_with_code`]. A group
/// leader waits in its exit path until it is the group's last member.
pub fn thread_exit(code: i32) -> ! {
    if let Some(idx) = current_slot() {
        crate::group::mark_thread_only(idx);
    }
    task_exit_with_code(code)
}

/// Why [`exec_end_other_threads`] refused.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ExecDethreadError {
    /// The process is ending (`exit_group`, a fault, a forced stop), or
    /// another of its threads is already exec'ing.
    Ending,
}

/// Wave 15 (plan 4a): the first half of an exec's commit from a process with
/// threads, POSIX's "all other threads are terminated" (Linux `de_thread`).
/// Called once the new image is admitted (`process::exec_prepare_*`): an
/// exec that fails before this point leaves every thread running.
///
/// Every other thread of the caller's process is stopped and this waits until
/// it has gone: each ends only itself (`group::begin_exit` refuses while the
/// group is exec'ing), clears and wakes its clear-tid word on the old image,
/// and leaves the shared root before the exec replaces it, so no thread ever
/// returns to user mode on an address space that is about to be torn down.
/// The last one's exit dissolves the group: the caller is a plain process
/// again, and the commit that follows is the single-threaded one.
///
/// A caller that is not the leader takes the process's identity: the
/// leader, stopped like the others, hands it over on its way out
/// ([`exec_take_over`]) and ends as a thread under the caller's old TID.
/// The caller then IS the process (its TID is the process id the parent
/// waits for and `/proc` and signals name), as Linux's PID swap makes it.
///
/// Returns how many threads were ended (0 for a process with none: one
/// load, `group::lead_of_idx`). It waits as the leader's own exit does
/// (`group_exit`): each member's exit wakes the leader's TID, which the
/// caller holds once the hand-over is done, and the 10 ms deadline is the
/// backstop. Members are stopped by slot, under the pool lock, so a stop
/// meant for the leader cannot land on the caller once it holds the
/// leader's TID; each slot once, and the slots are scanned again on every
/// pass, so one a sibling admitted just before the group was marked is
/// stopped too.
pub fn exec_end_other_threads() -> Result<u32, ExecDethreadError> {
    let Some(idx) = current_slot() else { return Ok(0) };
    let lead = crate::group::lead_of_idx(idx);
    if lead == 0 {
        return Ok(0);
    }
    let me = unsafe { TASKS[idx].tid };
    // Gate canaries only: a thread that is not the leader is refused, as
    // before the PID hand-over; or the other threads keep running across
    // the exec.
    if cfg!(feature = "exec-no-pid-swap-canary") && lead != me {
        return Err(ExecDethreadError::Ending);
    }
    if cfg!(feature = "exec-no-dethread-canary") {
        return Ok(0);
    }
    if !crate::group::begin_exec(lead, me) {
        return Err(ExecDethreadError::Ending);
    }
    let ended = crate::group::live_members(lead).saturating_sub(1);
    // Each slot is stopped once. A member that has exited keeps its slot
    // (and its group mark) until the slot is reused, and a second stop on it
    // would count a forced stop nobody consumes (`FORCED_PENDING`), putting
    // every timer tick from user mode, machine-wide, on the slow path.
    let mut stopped = [0u64; MAX_TASKS.div_ceil(64)];
    while crate::group::live_members(lead) > 1 {
        // The caller itself is being stopped: its exec must not run. The
        // members are already asked; their exits dissolve the group. Once
        // the leader has begun handing it the process, it waits for that.
        if current_forced_exit().is_some() && crate::group::abandon_exec(lead, me) {
            return Err(ExecDethreadError::Ending);
        }
        for i in 0..MAX_TASKS {
            let bit = 1u64 << (i % 64);
            if i != idx && stopped[i / 64] & bit == 0 && crate::group::lead_of_idx(i) == lead {
                stopped[i / 64] |= bit;
                stop_slot(i);
            }
        }
        let deadline = azos_drv_sys::timebase::now()
            .saturating_add(azos_drv_sys::timebase::TIMER_FREQ / 100);
        crate::task_block(WaitReason::Timer(deadline));
    }
    Ok(ended)
}

/// Force-stop (signal 9) whatever task holds slot `idx` now, checked and
/// recorded under the pool lock, which [`exec_take_over`] also holds while
/// it swaps two slots' TIDs: the stop lands on the slot it was meant for.
fn stop_slot(idx: usize) {
    let tid = {
        let _pool = PoolGuard::acquire();
        // SAFETY: under the pool lock, a valid index.
        unsafe {
            if !TASK_VALID[idx].load(Ordering::Relaxed) {
                return;
            }
            let tid = TASKS[idx].tid;
            if tid == 0 {
                return;
            }
            record_stop(idx, tid, stop_policy::Stop { force: true, signo: 9 });
            tid
        }
    };
    wake_stopped(tid, true);
}

/// Wave 15 (plan 4a): the leader's half of an exec by another of its
/// threads. Called on the leader's exit path (`group_exit`, slot `idx`,
/// TID `lead`) while its group is exec'ing by thread `by`: the two slots
/// swap TIDs, and the process's state on the leader's slot moves to the
/// exec'ing thread's — the break, the page budget, the address-space
/// window, the memory row and lock, the name, the parent link, the
/// subreaper and die-with-parent marks, the signal words, and (through
/// [`TASK_IDENTITY_HOOK`]) the capability table and the seed row. Returns
/// the leader slot's new TID (`by`'s old one): it then ends as a thread of
/// the group, whose leader TID is unchanged. `None` when there is nothing to
/// hand over (no exec, or the leader is the one exec'ing).
///
/// It runs only when the two are the group's last live members
/// (`group::claim_handover`), so no other thread of the process runs; the
/// exec'ing thread is in [`exec_end_other_threads`], which touches nothing
/// of its slot but under the pool lock this holds. A stop already recorded
/// on the leader's slot is dropped (the slot is ending).
unsafe fn exec_take_over(idx: usize, lead: u32) -> Option<u32> {
    // Only once every other member has gone: nothing else of the process
    // still runs (a sibling's fault would charge the budget being moved).
    let by = crate::group::claim_handover(lead)?;
    let to = idx_for_tid(by)?;
    // Interrupts off from the table move to the TID swap, on this hart: the
    // hook moves the capability table first, and until the swap below the
    // process id still names this slot, so every grant into the process
    // meanwhile resolves again and waits (`cap_store::claim_slot`,
    // `still_owned`). Off, nothing can stretch that wait on this hart, and a
    // grantor here cannot spin on a swap that cannot run.
    let irqs = azos_arch::ARCH.disable_all();
    let raw = TASK_IDENTITY_HOOK.load(Ordering::Acquire);
    if raw != 0 {
        // SAFETY: registered by `set_task_identity_hook` from a `fn(usize, usize, u32)`.
        let f: fn(usize, usize, u32) = unsafe { core::mem::transmute(raw) };
        f(idx, to, lead);
    }
    {
        let _pool = PoolGuard::acquire();
        // SAFETY: both slots valid under the pool lock; the thread in `to`
        // is parked, the leader in `idx` is the caller.
        unsafe {
            let (a, b) = (task_mut(idx) as *mut Task, task_mut(to) as *mut Task);
            let (a, b) = (&mut *a, &mut *b);
            core::mem::swap(&mut a.tid, &mut b.tid);
            core::mem::swap(&mut a.name, &mut b.name);
            core::mem::swap(&mut a.user_brk, &mut b.user_brk);
            core::mem::swap(&mut a.budget, &mut b.budget);
            core::mem::swap(&mut a.user_window, &mut b.user_window);
            core::mem::swap(&mut a.mem, &mut b.mem);
            for arr in [&PARENT_TID, &DWP_TID] {
                let v = arr[idx].swap(arr[to].load(Ordering::Relaxed), Ordering::AcqRel);
                arr[to].store(v, Ordering::Release);
            }
            let v = SUBREAPER[idx].swap(SUBREAPER[to].load(Ordering::Relaxed), Ordering::AcqRel);
            SUBREAPER[to].store(v, Ordering::Release);
            STOP_TID[idx].store(0, Ordering::Release);
            stop_policy::forced_clear(&FORCED_ACCT[idx], &FORCED_PENDING);
            // The two TIDs' lookup hints now name the other slot; the scan
            // in `idx_for_tid` finds and repairs them on first use.
        }
    }
    azos_arch::ARCH.restore(irqs);
    signal::hand_over(idx, to);
    Some(by)
}

/// Wave 13 (THREADS): the thread-group half of an exit, run first.
///
/// A whole-process exit (anything but [`thread_exit`]) marks the group ending
/// with `code` and stops every other member. A member (not the leader) then
/// ends here, alone: its clear-tid word cleared and woken while its address
/// space is still installed, its own objects released by the exit hook (the
/// shared tables are skipped there, `group::shares_tables`), its slot moved
/// off the shared root WITHOUT destroying it, and no exit notice (a thread
/// is nobody's child). The leader waits until it is the last member and then
/// returns the code its exit reports (the group's, when the group ended);
/// the rest of its exit releases what the group shared.
unsafe fn group_exit(idx: usize, tid: u32, code: i32) -> i32 {
    let lead = crate::group::lead_of_idx(idx);
    if lead == 0 {
        let _ = crate::group::take_thread_only(idx);
        // A process with no other thread: nobody of its own can wait on its
        // robust words, but they are marked as Linux marks them.
        robust_list_exit(idx, tid, tid);
        return code;
    }
    // The leader's robust words go before it waits to be alone: the
    // siblings it outlives in that wait may be the ones blocked on them
    // (a member walks its own in `member_exit`).
    if lead == tid {
        robust_list_exit(idx, tid, lead);
    }
    if !crate::group::take_thread_only(idx) && crate::group::begin_exit(lead, code) {
        let mut members = [0u32; crate::group::GROUP_THREADS_MAX as usize];
        let n = crate::group::members_of(lead, tid, &mut members).min(members.len());
        for &m in &members[..n] {
            let _ = task_stop(m, true, 9);
        }
    }
    if lead != tid {
        member_exit(idx, tid, lead, code);
    }
    // Wave 15 (COHERENCE-AUDIT): the leader's own clear-tid word (Linux
    // `set_tid_address`; musl's start code passes its thread-list lock) is
    // cleared and woken as a member's is, while the address space is still
    // installed, and, as Linux `mm_release` does, only while another thread
    // shares that address space (`mm_users > 1`): alone, nobody can observe
    // it. A leader ending by `pthread_exit` while its threads run is the
    // case: musl holds its thread-list lock across that exit and relies on
    // this clear to release it, so without it the next `pthread_create` or
    // `pthread_exit` in the process waits forever.
    if crate::group::live_members(lead) > 1 && !cfg!(feature = "leader-cleartid-canary") {
        clear_tid_word(idx, lead);
    }
    // The leader: wait to be alone. Each member's exit wakes it; the
    // deadline is a backstop against a wake that found it not yet asleep and
    // a stamp already consumed.
    while crate::group::live_members(lead) > 1 {
        // Wave 15 (plan 4a): another thread is exec'ing. The leader hands
        // it the process and ends as a thread under its old TID.
        if let Some(t) = unsafe { exec_take_over(idx, lead) } {
            member_exit(idx, t, lead, code);
        }
        let deadline = azos_drv_sys::timebase::now()
            .saturating_add(azos_drv_sys::timebase::TIMER_FREQ / 100);
        crate::task_block(WaitReason::Timer(deadline));
    }
    let code = crate::group::exiting(lead).unwrap_or(code);
    crate::group::dissolve(lead, idx);
    code
}

/// Clear and wake the clear-tid word of the task in slot `idx` (process
/// `proc_id`), while its address space is installed. Best effort: a word
/// that cannot be written is skipped.
unsafe fn clear_tid_word(idx: usize, proc_id: u32) {
    let addr = crate::group::take_clear_tid(idx);
    // Gate canary only: the word is never cleared (a join never returns).
    if cfg!(feature = "threads-no-cleartid-canary") {
        return;
    }
    if addr == 0 || addr & 3 != 0 {
        return;
    }
    let zero = 0u32.to_ne_bytes();
    if crate::process::copy_to_user(addr as usize, zero.as_ptr(), zero.len()) {
        let _ = crate::futex::wake_in(proc_id, addr, 1);
    }
}

/// Walk the robust futex list of the task in slot `idx` (thread `tid` of
/// process `proc_id`; Linux `set_robust_list`) while its address space is
/// installed: each lock word it still owns becomes `FUTEX_OWNER_DIED` and
/// one waiter on it is woken (`azos_linux_abi::robust`). Bounded by Kconfig
/// `LINUX_ROBUST_LIST_LIMIT`. Run before the clear-tid wake: a joiner may
/// free the thread's stack, where musl keeps the list head, once that word
/// is cleared.
fn robust_list_exit(idx: usize, tid: u32, proc_id: u32) {
    let head = crate::group::take_robust_list(idx);
    // Gate canary only: the list is never walked (a lock its owner died
    // holding stays held; the next locker sleeps).
    if head == 0 || cfg!(feature = "robust-list-canary") {
        return;
    }
    struct Mem(u32);
    impl azos_linux_abi::robust::RobustMem for Mem {
        fn read_u64(&mut self, addr: u64) -> Option<u64> {
            let mut b = [0u8; 8];
            crate::process::copy_from_user(b.as_mut_ptr(), addr as usize, 8).then(|| u64::from_ne_bytes(b))
        }
        fn read_u32(&mut self, addr: u64) -> Option<u32> {
            let mut b = [0u8; 4];
            crate::process::copy_from_user(b.as_mut_ptr(), addr as usize, 4).then(|| u32::from_ne_bytes(b))
        }
        fn cas_u32(&mut self, addr: u64, old: u32, new: u32) -> Result<(), Option<u32>> {
            crate::process::user_cas_u32(addr as usize, old, new)
        }
        fn wake_one(&mut self, addr: u64) {
            let _ = crate::futex::wake_in(self.0, addr, 1);
        }
    }
    let limit = azos_limits::LINUX_ROBUST_LIST_LIMIT as u32;
    let _ = azos_linux_abi::robust::exit_robust_list(&mut Mem(proc_id), head, tid, limit);
}

/// The exit of a thread-group member that is not the leader (see
/// [`group_exit`]). Never returns.
unsafe fn member_exit(idx: usize, tid: u32, lead: u32, code: i32) -> ! {
    TASK_EXITING[idx].store(true, Ordering::Release);
    robust_list_exit(idx, tid, lead);
    clear_tid_word(idx, lead);
    TASK_EXIT_CODE[idx].store(code, Ordering::Relaxed);
    {
        let raw = TASK_EXIT_HOOK.load(Ordering::Acquire);
        if raw != 0 {
            let f: fn(u32) = core::mem::transmute(raw);
            f(tid);
        }
    }
    // Off the shared root, never destroying it: a slot reused with
    // `user_pt` still set would tear the group's address space down
    // (K-C22(B)).
    {
        let task = task_mut(idx);
        // arch-only: aarch64's device-only low-half root (see
        // release_address_space_at_exit).
        #[cfg(all(target_arch = "aarch64", target_os = "none"))]
        let kernel_root = {
            unsafe extern "C" {
                static AARCH64_KERNEL_TTBR0: core::sync::atomic::AtomicU64;
            }
            unsafe { AARCH64_KERNEL_TTBR0.load(Ordering::Acquire) }
        };
        task.task_satp = kernel_task_satp();
        task.user_pt = 0;
        task.user_brk = 0;
        core::sync::atomic::compiler_fence(Ordering::SeqCst);
        #[cfg(target_arch = "riscv64")]
        azos_arch::csr::write_satp(task.task_satp as usize);
        #[cfg(all(target_arch = "aarch64", target_os = "none"))]
        if kernel_root != 0 {
            azos_arch::sysregs::install_ttbr0_flush_local(kernel_root as usize);
        }
        #[cfg(all(target_os = "none", not(any(target_arch = "riscv64", target_arch = "aarch64"))))]
        azos_arch::ArchPlatform::install_user_root_local(&azos_arch::ARCH, task.task_satp as usize);
    }
    let _ = crate::group::member_gone(lead, tid);
    wake_task_by_tid(lead, &|r| matches!(r, WaitReason::Timer(_)));
    {
        let _pool = PoolGuard::acquire();
        task_mut(idx).set_state(TaskState::Zombie);
        hist_reaccount(idx);
    }
    let _ = azos_arch::ARCH.disable_all();
    do_schedule(SwitchReason::Voluntary);
    loop {
        azos_arch::ARCH.enable_all();
        azos_arch::Cpu::wfi(&azos_arch::ARCH);
    }
}

/// Same as [`task_exit`] but preserving the exit code for the parent.
///
/// **It used to be lost.** `sys_exit(_code)` discarded its argument and called
/// `task_exit()`, which never took one: there was nobody to notify and nothing
/// to notify with.
pub fn task_exit_with_code(code: i32) -> ! {
    // K-C29: exit cannot be refused and cannot be deferred. A task exiting
    // inside a critical section is a bug in that task — it is not coming back
    // to drop its guard — but refusing to switch away from a Zombie strands
    // the hart, which is worse. Force the depth to 0 and continue; the counter
    // is the record that it happened. This is the one caller of
    // `force_zero_depth`, and it can only ever ENABLE preemption, so it can
    // never itself be the cause of a hang.
    if azos_sync::preempt::disabled() {
        preempt_audit::bump(&preempt_audit::EXIT_WHILE_ATOMIC);
        azos_sync::preempt::force_zero_depth();
    }
    let t_exit = crate::prof::t();
    // Wave 15 (TRACE): the proc class's exit record.
    if azos_trace::proc_on() {
        azos_trace::raw::proc_exit(current_task_tid(), code);
    }
    unsafe {
        let cpu = current_cpu_id();
        let idx = PER_CPU[cpu].current_idx.load(Ordering::Relaxed);
        #[cfg(feature = "exit-stale-hart-canary")]
        stale_hart_canary::arm(cpu, idx);
        // Wave 13: a thread group's member ends here alone; its leader
        // waits to be the last and exits with the group's code. So the
        // re-parenting below (`note_exit`) runs once, for the whole process,
        // when its last thread is gone: a member never re-parents (it posts
        // no notice and has no children of its own: a fork from it is its
        // process's child, `current_proc_tid`), and is never re-parented (a
        // thread's parent link is 0).
        let code = if idx != usize::MAX { group_exit(idx, TASKS[idx].tid, code) } else { code };
        // U04-2 route (b): publish "exiting" before ANYTHING else below —
        // `note_exit`, the driver-crash notice, the APS dequeue and
        // especially the `TASK_EXIT_HOOK` (`task_release_all`) all run
        // after this. See `TASK_EXITING`'s doc for why `tid_exists` alone
        // is not a safe "OK to newly target this tid" answer during that
        // window.
        if idx != usize::MAX {
            // Wave 13: whether `note_exit` re-parents this task's children,
            // published with (before) the exiting mark that readers pair it with.
            EXIT_REPARENTS[idx].store(
                task_ref(idx).user_pt != 0 && !cfg!(feature = "orphan-reparent-canary"),
                Ordering::Relaxed,
            );
            TASK_EXITING[idx].store(true, Ordering::Release);
        }
        // RFC-0049 M1, wave 9: give back the row instance this task held,
        // BEFORE the exit notice: a parent woken by `note_exit` may spawn
        // again at once, and must find the count already returned.
        // Taken to 0 first, so it is returned exactly once.
        if idx != usize::MAX {
            let t = task_mut(idx);
            let row = t.mem.row;
            t.mem.row = 0;
            row_release(row);
        }
        if idx != usize::MAX {
            // Read the dying task's identity BEFORE anything else touches it.
            // `exit_tid` — not `idx` — is what the driver manager and the
            // exit hook are keyed on: pool slots are recycled (`alloc_slot`
            // reuses the first free index, `do_schedule` frees this one), so
            // a slot number identifies "whoever sits here now", not the task
            // that is dying.
            let (exit_tid, exit_class) = {
                let t = task_mut(idx);
                (t.tid, t.sched_class_raw)
            };
            // `exit_class` has exactly one consumer, the APS mirror below.
            // Read it here anyway in a Legacy build so the tuple above stays
            // one statement in both, rather than a cfg'd pair that could
            // drift.
            #[cfg(not(feature = "sched-aps"))]
            let _ = exit_class;

            // AQ2: Notify driver manager — if this task was a registered driver,
            // record the crash so auto-restart can kick in. Keyed on the TID:
            // passing `idx` used to blame the crash on whichever driver last
            // occupied this pool slot.
            crate::driver::driver_on_crash(exit_tid);

            // AZOS Phase 1 W4-int.3b — remove the dying task from
            // its policy runqueue so APS pick_next never sees a Zombie.
            #[cfg(feature = "sched-aps")]
            crate::aps_state::dequeue_task_for_class(current_cpu_id(), exit_tid, exit_class);

            // Release resources keyed by this TID before the slot can be
            // reused: a resource left behind by a dead task is otherwise
            // inherited by the next task that draws the same pool slot.
            //
            // ORDERING — DO NOT MOVE THIS BLOCK (W3-F7). The hook the kernel
            // registers is `azos_ipc::task_release_all`, which calls
            // `cap_store::reset`. That resolves the TID back to a pool slot
            // and only succeeds while `TASK_VALID[idx]` is still true. It
            // therefore MUST run before the `Zombie` marking below and long
            // before `do_schedule()` frees the slot. Move it later and typed
            // capabilities stop being revoked on exit — silently, with no
            // error and no failing test.
            TASK_EXIT_CODE[idx].store(code, Ordering::Relaxed);
            let t_ph = crate::prof::t();
            {
                let raw = TASK_EXIT_HOOK.load(Ordering::Acquire);
                if raw != 0 {
                    let f: fn(u32) = core::mem::transmute(raw);
                    f(exit_tid);
                }
            }

            // K-C22(C): the address space goes HERE, in the exiting task's
            // own context — after the exit hook (whose shm/io_ring unmaps walk
            // `current_user_pt()`), before the Zombie mark. It
            // used to wait for the slot's reuse (K-C22(B)), so an unrelated
            // later `fork` paid ~47k instructions to free a dead process's
            // tables and frames, and they stayed allocated until then.
            crate::prof::add(12, t_ph);
            let t_ph = crate::prof::t();
            release_address_space_at_exit(idx);
            crate::prof::add(13, t_ph);
            let t_ph = crate::prof::t();

            // Wave 12 (EXIT2): the post-teardown hook — the kernel wakes the
            // driver supervisor here, not from `TASK_EXIT_HOOK`, so a restart
            // it decides never runs beside the dead driver's address space.
            // Same place in the sequence as the exit notice just below.
            {
                let raw = TASK_EXIT_LATE_HOOK.load(Ordering::Acquire);
                if raw != 0 {
                    let f: fn(u32) = core::mem::transmute(raw);
                    f(exit_tid);
                }
            }

            // The exit notice goes out HERE, after the exit hook and the
            // address-space teardown — Linux's order (`exit_mm`/`exit_files`
            // before `exit_notify`): a parent's `wait`/`waitpid` returns only
            // once this task's capabilities, handles and memory are back, so
            // a parent that reaps and at once forks or spawns again never
            // competes with a half-torn-down child for them. Before the Zombie
            // mark: from there on the slot may be freed on any context switch.
            //
            // It used to sit at the top of this function, because a parent
            // polling `wait` with `yield` at a HIGHER priority than this task,
            // on this hart, never lets it run again once a tick preempts it,
            // and every instruction before the notice was a window for that
            // stall (tried in wave 9: abitest's `waitpid(epsrv)` gave up in 5
            // of 9 `-smp 4` boots). The cure is on the waiting side: a poll
            // SLEEPS between looks, so the hart goes to whatever is ready.
            // `note_exit` counts a notice published while this task still
            // holds its address space (`EARLY_EXIT_NOTICES`, syscall 605).
            crate::prof::add(15, t_ph);
            let t_ph = crate::prof::t();
            note_exit(idx, code);
            crate::prof::add(14, t_ph);

            // K-C6: mark Zombie only — TASK_VALID stays true and
            // PER_CPU[cpu].current_idx keeps pointing at `idx` (see the
            // function doc above) until do_schedule() can safely free it.
            {
                let _pool = PoolGuard::acquire();
                task_mut(idx).set_state(TaskState::Zombie);
                hist_reaccount(idx);
            } // pool lock released
        }

        // AZOS Phase 1 W4-int.4 — clear the APS current_class so
        // subsequent timer ticks don't keep crediting a dead task's
        // class until the next dispatch.
        #[cfg(feature = "sched-aps")]
        if aps_dispatch_enabled() {
            // Not the `cpu` read on entry: `group_exit` may have blocked.
            let _ = crate::aps_state::with_cpu(current_cpu_id(), |state| {
                state.aps.set_idle();
            });
        }

        crate::prof::add(11, t_exit);
        crate::prof::report(11, 40);
        // Disable interrupts and try an immediate reschedule.
        let _ = azos_arch::ARCH.disable_all();
        do_schedule(SwitchReason::Voluntary);
        // do_schedule() only returns when there are no ready tasks on this CPU.
    }

    // No tasks remaining — idle until timer brings more work.
    loop {
        azos_arch::ARCH.enable_all();
        azos_arch::Cpu::wfi(&azos_arch::ARCH);
        // Timer interrupt → schedule() → do_schedule() → may context-switch away.
        // If not, we just loop again.
    }
}

/// Voluntarily yield the CPU to the next ready task.
///
/// K-C29: a yield issued inside a critical section is refused, not deferred.
/// Yielding while holding a spinlock cannot make progress by yielding — the
/// hart is being asked to stop running the only task that can release the
/// lock. Keeping the holder on the hart is what frees it. This is also the
/// function registered as the deferred-reschedule callback, and the refusal is
/// what stops a guard drop nested inside another critical section from
/// switching early.
#[inline]
pub fn task_yield() {
    yield_as(SwitchReason::Voluntary);
}

/// The deferred-reschedule callback (`preempt::set_resched_callback`): a
/// timer tick that found this hart inside a critical section recorded a debt
/// (`tick_admit`'s `Defer` arm, the only caller of `set_need_resched`), and
/// the outermost guard's drop pays it here. That switch is the timer taking
/// the CPU, so it counts as `Preempted`, as Linux counts a preemption taken
/// on the way out of a syscall in `nivcsw`. Wave 13: it was `task_yield` and
/// counted `Voluntary`, so `SYS_TASKINFO`'s preempted count missed every tick
/// that landed in a lock — vsbench's `drvring-batch8` saw an extra round
/// (65+64 / 64+65) with "preempted 0" on both sides.
pub fn task_preempt_deferred() {
    yield_as(SwitchReason::Preempted);
}

#[inline(always)]
fn yield_as(why: SwitchReason) {
    use azos_sync::preempt_core::VoluntaryAdmission;
    if azos_sync::preempt_core::voluntary_admission(azos_sync::preempt::depth())
        == VoluntaryAdmission::RefuseAtomic
    {
        preempt_audit::bump(&preempt_audit::YIELD_WHILE_ATOMIC);
        return;
    }
    crate::swcensus::yield_enter();

    let sstatus = azos_arch::ARCH.disable_all();

    unsafe { do_schedule(why); }

    azos_arch::ARCH.restore(sstatus);
}

/// AZOS Phase 1 W4-int.4 — microseconds per scheduler tick.
///
/// Matches the 100 Hz default in `crates/drivers/irqchip/src/clint.rs::SCHED_HZ`
/// (10 ms per tick = 10 000 µs). The APS account path multiplies the
/// `APS_TICK_COUNTER` by this to get a monotonic-µs proxy without
/// adding a `drivers` dependency to this crate.
///
/// That account path is the only reader, so the const goes with the backend.
#[cfg(feature = "sched-aps")]
const SCHED_TICK_US: u32 = 10_000;

/// Called from the timer interrupt handler (interrupts already disabled by hardware).
///
/// RT tasks: never preempted by timer — only by a strictly higher-priority ready task.
/// Normal tasks: preempted when time slice expires (standard round-robin).
/// On a hart with RT state (`rt::active`: a band task running, an exhausted
/// band window, or reservations), `rt::tick` charges and may preempt first:
/// band budget, CBS budget, EDF order inside a level.
#[wcet(30_us)]
pub fn schedule() {
    let cpu = current_cpu_id();
    // K-C29: the preemption check is NOT here. It sits at each of the two
    // `do_schedule` sites below, *after* the tick bookkeeping — runtime
    // accounting, APS class credit and the RT band / CBS charge all have to
    // happen whether or not this hart is in
    // a critical section. The deleted F03.4 stub returned from right here and
    // lost all of it; see the deletion note further down this file.
    unsafe {
        let current_idx = PER_CPU[cpu].current_idx.load(Ordering::Relaxed);
        // K-C6: a lingering Zombie — task_exit() found no ready task and is
        // idling in its own WFI loop, still on its own stack — must not be
        // treated as "the task currently running" here. Crediting a dead
        // task's runtime/deadline stats is wrong, and worse: the RT/time-
        // slice preemption-avoidance branches below can `return` without
        // ever calling do_schedule(), which would permanently starve this
        // CPU of new dispatches once its last task happened to be
        // RT-priority. Treat it exactly like the genuinely-idle
        // (current_idx == MAX) case; do_schedule() frees the Zombie's slot
        // once it finds a real next task to switch to (see its `old.state
        // == TaskState::Zombie` arm).
        let current_idx = if current_idx != usize::MAX
            && task_mut(current_idx).state() == TaskState::Zombie
        {
            usize::MAX
        } else {
            current_idx
        };
        // RFC-0051 E1: the tick updates the running task's and this CPU's
        // utilisation (an idle tick, the CPU's alone).
        #[cfg(feature = "energy")]
        energy::on_tick(cpu, current_idx);
        if current_idx != usize::MAX {
            let task = task_mut(current_idx);
            task.total_runtime += 1;

            // AZOS Phase 1 W4-int.4 — credit the APS class running on
            // this CPU. Drives per-class budget consumption and window
            // roll-over inside `Aps::tick`. Uses APS_TICK_COUNTER
            // (monotonic, one per tick) × SCHED_TICK_US as
            // a microsecond proxy — exact enough for budget bookkeeping
            // without needing a `drivers` dep here. The call is cheap: one
            // `with_cpu` SpinLock acquire/release (`account` takes the
            // per-CPU `V2_STATE` lock once and calls every policy's
            // `tick` inside that single hold) plus a few atomic ops.
            //
            // Unguarded by `aps_dispatch_enabled()`: it credits budget so a
            // later flip starts from a live window. A Legacy-only build has
            // no window, so that one SpinLock acquire/release pair leaves
            // the timer ISR entirely with the backend.
            #[cfg(feature = "sched-aps")]
            {
                let tid_snapshot = task.tid;
                let now_us = APS_TICK_COUNTER.fetch_add(1, Ordering::Relaxed)
                    * SCHED_TICK_US as u64;
                crate::aps_state::account(cpu, now_us, SCHED_TICK_US, tid_snapshot);
            }

            // Wave 11 SCHED-RT: band budget, CBS budget and EDF order. A
            // hart with none of them pays one per-hart load here.
            if rt::active(cpu) && rt::tick(cpu, current_idx) {
                RT_TICK_PREEMPTS.fetch_add(1, Ordering::Relaxed);
                if tick_admit() { do_schedule(SwitchReason::Preempted); }
                return;
            }

            // Hoisted: same reason as `find_best_cpu`'s `t_prio` — an atomic
            // load is not free for the compiler to CSE across these two uses
            // the way the plain field it replaced was, and this runs on
            // every timer tick on every hart.
            let task_prio = task.priority.load(Ordering::Relaxed);
            if is_rt_priority(task_prio) {
                // RT task: only preempt if a higher-priority task is waiting.
                match cpu_peek_highest_prio(cpu) {
                    Some(ready_prio) if ready_prio < task_prio => {
                        // Higher-priority task ready — preempt.
                    }
                    _ => {
                        return; // No higher-priority task — keep running.
                    }
                }
            } else {
                // Normal task: standard time-slice expiry.
                if task.time_slice > 0 {
                    task.time_slice -= 1;
                    if task.time_slice > 0 {
                        return; // Still has remaining time — don't preempt.
                    }
                }
            }
        } else if rt::active(cpu) && rt::tick(cpu, usize::MAX) {
            // Nothing real runs (idle-equivalent): a replenished reservation
            // or a rolled band window is dispatched below like any tick.
            RT_TICK_PREEMPTS.fetch_add(1, Ordering::Relaxed);
        }
        if tick_admit() { do_schedule(SwitchReason::Preempted); }
    }
}

/// K-C29 involuntary-preemption admission for the tick / reschedule-IPI path.
///
/// Returns `true` if this tick may enter `do_schedule`. **Call it after the
/// tick bookkeeping and immediately before the switch** — the accounting is
/// not preemption and must run in a critical section too.
///
/// The `Defer` arm records a debt instead of dropping the tick. The debt is
/// paid by the drop of the outermost `PreemptGuard`, which calls the
/// registered resched callback once interrupts are enabled again.
///
/// The `Switch` arm *clears* the debt: a later tick that actually reached the
/// scheduler has served whatever an earlier deferred tick was owed, and
/// leaving the flag set would make the next guard drop fire a redundant
/// reschedule.
#[inline]
fn tick_admit() -> bool {
    use azos_sync::preempt_core::TickDispatch;
    match azos_sync::preempt_core::tick_dispatch(azos_sync::preempt::depth()) {
        TickDispatch::Defer => {
            azos_sync::preempt::set_need_resched();
            false
        }
        TickDispatch::Switch => {
            azos_sync::preempt::clear_need_resched();
            true
        }
    }
}

/// Monotonic tick counter for the APS account path (one per tick with a
/// current task). Only that backend reads it.
#[cfg(feature = "sched-aps")]
static APS_TICK_COUNTER: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);

/// Ticks on which `rt::tick` asked for a preemption (band or CBS budget, EDF
/// order). Read by the SCHED-RT rows.
pub static RT_TICK_PREEMPTS: AtomicU32 = AtomicU32::new(0);

/// Start the scheduler on the calling CPU (boot CPU).
///
/// Picks the first ready task from this CPU's queue and switches to it.
/// Never returns.
pub fn start() -> ! {
    let cpu = current_cpu_id();
    // K-A12: SSTATUS.SIE is already on by the time start() runs (enabled
    // earlier in boot), so a timer tick firing in the window below would
    // enter schedule() → do_schedule() and mutate this same CPU's ready
    // queue / PER_CPU.current_idx concurrently with the dequeue+dispatch
    // this function is doing inline — corrupting the dispatch, or racing
    // `current_idx` between the dequeue and the assignment below. Not
    // restored here: task_entry_wrapper (the entry point of the task we're
    // about to switch to) unconditionally re-enables SIE.
    //
    // Hence `let _`: the saved-state token is deliberately dropped, and
    // saying so is the point — this function never returns, so a token bound
    // to a name would read like a restore that someone forgot to write.
    let _ = azos_arch::ARCH.disable_all();
    unsafe {
        // Locked: another hart may be racing us via `task_create` (least-
        // loaded assignment can still target a CPU that hasn't called
        // `start()` yet) or, in principle, a very early cross-CPU wake.
        let next_idx = match cpu_dequeue_locked(cpu) {
            Some(idx) => idx,
            None => panic!("sched_start: no tasks for CPU {}", cpu),
        };
        let next = task_mut(next_idx);
        next.set_state(TaskState::Running);
        next.time_slice = if is_rt_priority(next.priority.load(Ordering::Relaxed)) {
            RT_TIME_SLICE_TICKS
        } else {
            TIME_SLICE_TICKS
        };
        set_current_task(cpu, next_idx);
        // A band task dispatched first is charged from here (SCHED-RT).
        rt::on_switch(cpu, next_idx);
        // And accrues utilisation from here (RFC-0051 E1).
        #[cfg(feature = "energy")]
        energy::on_switch(cpu, usize::MAX, next_idx);

        // Lockdep: the boot context hands over holding nothing.
        azos_sync::lockdep::switch(None, next_idx);
        // QSBR (Kconfig RCU_QSBR, N4): a context switch is a quiescent state.
        azos_sync::qsbr::switch();
        // N12: re-tag `next`'s ASID if a rollover took it; set the flush word.
        crate::asid::prepare_switch(next as *mut Task);
        // Switch to first task (no current task to save).
        context_switch(core::ptr::null_mut(), next as *mut Task);
    }
    unreachable!()
}

// ---- Boot-time offline-hart rescue ----

/// Move every ready task stranded on a hart that failed to start during SMP
/// bring-up onto a hart that actually came up.
///
/// Call exactly once, from the boot hart, strictly *after* `wake_harts()` has
/// returned and [`crate::smp::NUM_ONLINE_CPUS`] has been corrected to the
/// real `online` count, and strictly *before* the boot hart calls
/// [`start()`] (or enables its own timer interrupt). Returns the number of
/// tasks moved.
///
/// # Why this needs no extra synchronization on the *source* side
///
/// `task_create`/`task_create_affinity` calls made earlier in boot (before
/// `wake_harts()`) spread tasks across `0..num_cpus` using the *optimistic*
/// pre-boot `NUM_ONLINE_CPUS` estimate — some may have landed on a hart that
/// then failed `hart_start`. Those per-CPU ready queues
/// (`PER_CPU[online..total]`) are, by construction, never touched by anyone
/// but the boot hart: a hart that failed to start never executes a single
/// instruction, so it can never call `schedule()` / `do_schedule()` or
/// enqueue/dequeue anything on its own queue. That is not a narrow timing
/// window — it holds for as long as the kernel runs.
///
/// # Why the *destination* side still goes through the locked wrappers
///
/// A hart that *did* start runs `secondary_main()` immediately and
/// independently of how far the boot hart has gotten through the rest of
/// `kernel_main` — it enables its own local timer right there and will call
/// `schedule()` on its first tick, which can land before the boot hart
/// reaches `start()`. So, unlike the source side, a lock-free enqueue onto
/// an *alive* CPU's queue here would not be provably race-free without also
/// reasoning about exactly how much boot-time code runs in between. Rather
/// than depend on that, every queue touch below — source and destination —
/// goes through `cpu_dequeue_locked` / `cpu_enqueue_locked` (never the raw
/// `cpu_dequeue`/`cpu_enqueue`), same as every other cross-CPU path in this
/// file. The extra lock cost is negligible: boot-time only, at most
/// `MAX_TASKS` operations total.
///
/// # Algorithm
///
/// For each dead hart `online..total`, repeatedly dequeue its
/// highest-priority ready task (this drains every priority level, via the
/// same bitmap dequeue used everywhere else) and hand it to
/// [`find_best_cpu`] — the same priority-aware balancer `task_create`
/// uses, not a bitmap popcount. It is naturally bounded to
/// `0..online` because the caller has already corrected `NUM_ONLINE_CPUS`
/// before calling this function.
///
/// Both the task's saved `tp` (`context.tp`, restored into the hardware
/// `tp` register by `context_switch` on dispatch — see its field doc) and,
/// if the task was pinned (`cpu_affinity >= 0`), its affinity are rewritten
/// to the new CPU. Skipping this would leave a moved task either running
/// with a stale `current_cpu_id()` (every `PER_CPU[current_cpu_id()]`
/// access inside it would then hit the wrong slot) or, once it blocks and
/// is later woken (`try_wake_task` / `wq_wake_by_tid` route pinned tasks
/// straight back to `cpu_affinity`), silently re-stranded on the dead hart.
/// Breaking an explicit pin is a decision the operator must see, so it is
/// logged per task.
///
/// No work-stealing is added at runtime — this is a one-shot rescue that
/// only ever runs during this boot-time window.
pub fn rebalance_from_offline_cpus(online: usize, _total: usize) -> usize {
    // **Sweep up to `nr_cpu_ids`, not up to the DTB count.** (Every CPU
    // below it has a queue; a pin past it was cut to it at creation.)
    //
    // This function used to take `total` (the harts the DTB said exist) and
    // drained only `online..total`. That looks reasonable and strands tasks:
    // several are created with **explicit affinity** to a specific hart, and
    // that affinity is not bounded by the DTB count. With `-smp 1`, `total` is
    // 1 and the loop `for dead_cpu in 1..1` never runs a single iteration --
    // while the queues of CPUs 1, 2 and 3 have tasks in them.
    //
    // Measured before this change, with `-smp 1`: `per_cpu_queues = [0, 3, 1, 2]`.
    // Six tasks, `autorun` among them, queued on harts that do not exist.
    // The result is that **the user program never starts** with the kernel
    // apparently healthy: the loops keep running, the daemons talk, and the
    // ring-3 ELF executes not one instruction.
    //
    // Every queue above `online` must be drained, whether the task got there
    // by load balancing or by an explicit pin. `total` is kept in the
    // signature for caller compatibility and is deliberately unused.
    let total = ncpu();
    if online == 0 || online >= total {
        return 0; // Nothing offline, or nothing online to rescue onto.
    }

    let mut moved = 0usize;
    let mut moved_per_dead = [0usize; MAX_CPUS];

    unsafe {
        for dead_cpu in online..total {
            loop {
                let idx = match cpu_dequeue_locked(dead_cpu) {
                    Some(idx) => idx,
                    None => break, // This dead hart's queue is fully drained.
                };

                let task = task_mut(idx);
                let target_cpu = find_best_cpu(task.priority.load(Ordering::Relaxed), idx);

                if task.cpu_affinity >= 0 {
                    // Pinned task stranded on a hart that never came up —
                    // the pin cannot be honored without leaving it stuck
                    // forever, so move it anyway and make that visible.
                    let len = task.name.iter().position(|&b| b == 0).unwrap_or(TASK_NAME_MAX_LEN);
                    let name = core::str::from_utf8(&task.name[..len]).unwrap_or("<?>");
                    azos_drv_sys::kwarn!(
                        "[SMP] task '{}' (tid {}) was pinned to dead hart {} — \
                         reassigning to hart {} (affinity broken: hart never started)",
                        name, task.tid, dead_cpu, target_cpu
                    );
                    task.cpu_affinity = target_cpu as i8;
                }

                // Keep the saved tp consistent with the queue the task now
                // lives on: context_switch loads this straight into the
                // hardware tp register on dispatch, and current_cpu_id()
                // (hence every PER_CPU[current_cpu_id()] access inside the
                // task) trusts it completely.
                task.context.tp = target_cpu as CtxReg;
                hist_reaccount(idx);

                // K-C26 discriminator 2: the task is already `Ready`; a
                // refusal here strands it in no queue. Counted, not ignored.
                task.ready_site.store(
                    crate::task::ready_site::REBALANCE | ((target_cpu as u8) << 4),
                    Ordering::Relaxed,
                );
                if !cpu_enqueue_locked(target_cpu, idx) {
                    SCHED_ENQ_REFUSED.fetch_add(1, Ordering::Relaxed);
                }
                moved_per_dead[dead_cpu] += 1;
                moved += 1;
            }
        }
    }

    if moved > 0 {
        for dead_cpu in online..total {
            if moved_per_dead[dead_cpu] > 0 {
                azos_drv_sys::kprintln!(
                    "[SMP] rebalanced {} boot task(s) off dead hart {}",
                    moved_per_dead[dead_cpu], dead_cpu
                );
            }
        }
        azos_drv_sys::kprintln!(
            "[SMP] rebalance summary: {} task(s) moved off {} dead hart(s) onto {} online hart(s)",
            moved, total - online, online
        );
    }

    moved
}

/// Parent of each pool slot, for `wait`. 0 = no parent.
///
/// **Deliberately outside `Task`.** Adding a field to `Task` shifts the offset
/// of `satp` (`TASK_SATP_OFFSET`, `task.rs`) that `context_switch.S` is fed
/// via `offset_of!` — not hand-copied, but still layout-frozen: a
/// compile-time assertion checks it and the build refuses. Touching the
/// context-switch assembly's injection site to hang a `u32` off it is not
/// worth the risk, so the relation lives here, indexed by slot.
static PARENT_TID: [core::sync::atomic::AtomicU32; MAX_TASKS] =
    [const { core::sync::atomic::AtomicU32::new(0) }; MAX_TASKS];

/// U04-2 route (b). `true` from the earliest instant of
/// `task_exit_with_code` — BEFORE `note_exit`, the driver-crash notice,
/// the APS dequeue, and above all before the registered
/// [`TASK_EXIT_HOOK`] (`azos_ipc::task_release_all`) run — until the
/// slot is freed and reused.
///
/// **Why this exists: `tid_exists` alone is not "safe to target".** The
/// caps/ipc front's `sched_seam::tid_exists` (`crates/core/ipc/src/fast_ipc.rs`)
/// is `idx_for_tid(tid).is_some()`, which stays `true` for the entire
/// teardown window — `TASK_VALID` and the tid are not cleared until
/// `do_schedule()` frees the slot, long after `task_release_all` has run.
/// A `fast_ipc_call`/`fast_ipc_accept` on another hart that checks only
/// `tid_exists` can start a NEW interaction with a tid whose capabilities
/// `cap_store::reset` is concurrently revoking — a race between "does a
/// slot exist" and "is anyone allowed to newly rely on it". Publishing
/// this flag first gives the ipc side a cheap second check
/// (`tid_is_exiting`) to refuse that window instead of racing it.
///
/// **Deliberately OUTSIDE `Task`, like [`PARENT_TID`].** Adding a field to
/// `Task` shifts `TASK_SATP_OFFSET`, layout-frozen by a compile-time
/// assertion even though `context_switch.S` gets it via `offset_of!`
/// rather than a hand-copied number. Indexed by slot for the same reason
/// `PARENT_TID` is.
///
/// **A plain `Release` store, not a compare-exchange, is the right
/// primitive.** Exactly one hart — the task exiting itself — ever writes
/// its own slot's entry `true` (and only `alloc_slot`, under
/// `POOL_LOCK`, ever writes it back to `false`), so there is no writer
/// race to arbitrate; a CAS here would cost more and prove nothing a
/// `Release` store does not already give a `tid_is_exiting` reader
/// paired with `Acquire`.
static TASK_EXITING: [core::sync::atomic::AtomicBool; MAX_TASKS] =
    [const { core::sync::atomic::AtomicBool::new(false) }; MAX_TASKS];

/// The code the task in this slot is exiting with, stored by
/// [`task_exit_with_code`] before the exit hook runs, so the hook (a
/// `fn(u32)`) can tell a clean `exit(0)` from a failure: the supervisor
/// restarts a driver only on the second (RFC-0049 M4, owner decision
/// 2026-09-28). Written only by the exiting task, for its own slot.
static TASK_EXIT_CODE: [core::sync::atomic::AtomicI32; MAX_TASKS] =
    [const { core::sync::atomic::AtomicI32::new(0) }; MAX_TASKS];

/// The exit code of the CURRENT task, for the exit hook it runs.
/// Meaningful only from inside that hook (before, it is a stale value).
pub fn current_exit_code() -> i32 {
    let idx = unsafe { PER_CPU[current_cpu_id()].current_idx.load(Ordering::Relaxed) };
    if idx >= MAX_TASKS { return 0; }
    TASK_EXIT_CODE[idx].load(Ordering::Relaxed)
}

/// Is `tid` mid-exit (or already fully gone)? `false` for a tid with no
/// valid slot at all (nothing to be mid-exit FROM) as well as for one
/// whose slot exists but has not started exiting — i.e. `true` is the
/// answer callers should treat as "do not start a new interaction with
/// this tid", and `false` alone is not yet a promise the tid is alive
/// (pair with `idx_for_tid`/`tid_exists` for that).
pub fn tid_is_exiting(tid: u32) -> bool {
    match idx_for_tid(tid) {
        Some(idx) => TASK_EXITING[idx].load(Ordering::Acquire),
        None => false,
    }
}

/// Exit notices waiting to be reaped: `(parent, child, code)`.
///
/// **Decoupled from the zombie's slot, and that is the design, not a
/// shortcut.** A POSIX `wait` keeps the child's slot alive until the parent
/// reaps it; here `do_schedule` frees them as soon as it switches, and
/// changing that means touching task lifetime — exactly where K-C6 and K-C26
/// lived. The notice outlives the slot, so the parent finds out without
/// anything in the scheduler changing.
///
/// **Kept until reaped, as Linux keeps zombies** (wave 12, EXIT2). One entry
/// per task slot, and the creation of a child with a parent is refused while
/// the queued notices could use up the slots still free
/// (`exit_note::admits`, under `POOL_LOCK`): the notice a child leaves holds
/// the place its slot would have held. So the table never fills with live
/// parents' notices and none is dropped; a parent that never waits makes its
/// own `fork`/`spawn` fail instead. A parent's exit releases its notices
/// (`exit_note::purge_parent` in [`note_exit`]). Until wave 12 this was a
/// 32-entry Kconfig table (`SCHED_EXIT_NOTES`) that evicted the oldest live
/// notice when full.
const EXIT_NOTES: usize = MAX_TASKS;
static EXIT_NOTE: azos_sync::SpinLock<[(u32, u32, i32); EXIT_NOTES]> =
    azos_sync::SpinLock::new([(0, 0, 0); EXIT_NOTES]);
/// Entries of [`EXIT_NOTE`] in use. Written only under its lock; read
/// without it by the creation admission and to skip the scans when 0.
static EXIT_NOTICES_QUEUED: AtomicU32 = AtomicU32::new(0);
/// Notices `exit_note::insert` could not place. Zero unless the admission is
/// broken: the table is sized so it cannot fill (`SYS_EXIT_STATS`).
pub static EXIT_NOTICE_DROPS: AtomicU32 = AtomicU32::new(0);
/// Creations of a child refused because queued notices hold the slots that
/// were free (`SYS_EXIT_STATS`).
pub static EXIT_NOTICE_REFUSALS: AtomicU32 = AtomicU32::new(0);

/// Pure `EXIT_NOTE` insertion/orphan-eviction logic, in its own file only
/// so the host test runner (`tests/host/sched-wake-tests`) can compile it —
/// the rest of this module cannot leave the target. Same pattern as
/// `process::elf_bounds` / `smp::hart_set`.
#[path = "exit_note.rs"]
pub mod exit_note;

/// Wave 13 (orphans): the slot's task is a child subreaper — Linux's
/// `PR_SET_CHILD_SUBREAPER` — so orphaned descendants are re-parented to it
/// rather than to [`INIT_TID`]. Written only by the task itself
/// ([`task_subreaper`]); cleared when its slot is claimed.
static SUBREAPER: [core::sync::atomic::AtomicBool; MAX_TASKS] =
    [const { core::sync::atomic::AtomicBool::new(false) }; MAX_TASKS];

/// Wave 13 (orphans): the reaper of last resort, Linux's init — the task the
/// autorun row's image runs as (`set_init_tid`, called by the kernel's
/// autorun loader at its exec; a supervised successor sets its own). 0: none,
/// and an orphan with no subreaper ancestor is left with no parent.
static INIT_TID: AtomicU32 = AtomicU32::new(0);

/// Make `tid` the reaper of last resort ([`INIT_TID`]).
pub fn set_init_tid(tid: u32) {
    INIT_TID.store(tid, Ordering::Release);
}

/// The reaper of last resort, 0 for none.
pub fn init_tid() -> u32 {
    INIT_TID.load(Ordering::Acquire)
}

/// `SYS_TASK_SUBREAPER` / Linux `prctl(PR_{SET,GET}_CHILD_SUBREAPER)` for the
/// current task: `Some(on)` sets or clears the mark, `None` only reads it.
/// Returns the mark afterwards; `false` for a context with no task.
pub fn task_subreaper(set: Option<bool>) -> bool {
    let idx = unsafe { PER_CPU[current_cpu_id()].current_idx.load(Ordering::Relaxed) };
    if idx >= MAX_TASKS {
        return false;
    }
    // Wave 13: the mark is the process's (its group leader's slot), as on
    // Linux, whichever thread sets it: a process's children name the leader.
    let idx = proc_slot(idx);
    if let Some(on) = set {
        // `subreaper-mark-canary`: the mark is never set (the shell's
        // orphan rows must go red: its jobs' orphans get no parent).
        let on = on && !cfg!(feature = "subreaper-mark-canary");
        SUBREAPER[idx].store(on, Ordering::Release);
    }
    SUBREAPER[idx].load(Ordering::Acquire)
}

/// Who adopts the children of the task in `idx` (TID `dying`), which is
/// exiting: `exit_note::reaper_for` over the live slots. Called under
/// `EXIT_NOTE`, which serialises every exiting task's re-parenting.
fn reaper_of(idx: usize, dying: u32) -> u32 {
    let look = |tid: u32| {
        let i = idx_for_tid(tid)?;
        Some(exit_note::Ancestor {
            parent: PARENT_TID[i].load(Ordering::Relaxed),
            subreaper: SUBREAPER[i].load(Ordering::Acquire),
            can_adopt: !TASK_EXITING[i].load(Ordering::Acquire),
        })
    };
    exit_note::reaper_for(
        dying,
        PARENT_TID[idx].load(Ordering::Relaxed),
        INIT_TID.load(Ordering::Acquire),
        look,
        stop_policy::MAX_ANCESTRY,
    )
}

/// Wave 13 (orphans): the slot's task, now exiting, will re-parent its
/// children in [`note_exit`]: it ran a user address space and the canary is
/// off. Written by the exiting task just before it publishes
/// [`TASK_EXITING`] (so a reader that sees the latter sees this); only a
/// user task's children are re-parented. A kernel task's children — the
/// ring-3 drivers and the user shell the boot launcher starts, the
/// supervisor's successors — are the kernel's, as Linux's kthreadd children
/// are, and keep the link they had.
static EXIT_REPARENTS: [core::sync::atomic::AtomicBool; MAX_TASKS] =
    [const { core::sync::atomic::AtomicBool::new(false) }; MAX_TASKS];

/// Wake `tid` if it is parked waiting for a child's exit notice.
fn wake_child_waiter(tid: u32) {
    // RFC-0055: a parent parked in `SYS_CONSOLE_WAIT` is waiting for exactly
    // this. One load when nobody waits; the wake stamps a parent that has
    // not blocked yet, and its loop re-tests `has_exit_note`.
    if let Some(pidx) = idx_for_tid(tid) {
        if WAITS_CHILD[pidx].load(Ordering::Acquire) {
            wake_task_by_tid(tid, &|r| matches!(r, WaitReason::Timer(_)));
        }
    }
}

/// Records that the task in `idx` finished with `code`.
pub fn note_exit(idx: usize, code: i32) {
    if idx >= MAX_TASKS { return; }
    let (child, still_mapped) = unsafe {
        let t = task_ref(idx);
        (t.tid, t.user_pt != 0)
    };
    // Called by the exiting task for its own slot, after
    // `release_address_space_at_exit` zeroed `user_pt`: a table still here
    // means the notice is going out ahead of the teardown.
    if still_mapped {
        EARLY_EXIT_NOTICES.fetch_add(1, Ordering::Relaxed);
    }
    // **The lock is taken BEFORE the parent link is cleared, and that ordering
    // is the fix for a real race.** The clear used to happen first, leaving a
    // window in which the link said "no parent" and no notice existed yet.
    // `take_exit_note_for` reads both, and in that window it concluded the
    // caller was not the child's parent — answering `ECHILD`, "this will never
    // resolve", for a child that was in the middle of exiting.
    //
    // Measured, not reasoned: `userspace/bench/vsbench`'s life-cycle lane hit it on
    // the FIRST poll in 2 of 40 iterations, needing the child to exit on
    // another hart at exactly that instant. `SYS_WAIT` never saw it because it
    // does not consult the parent link at all.
    //
    // Holding `EXIT_NOTE` across both makes the transition atomic against
    // `take_exit_note_for`, which does its own parent-link check under the
    // same lock.
    let mut t = EXIT_NOTE.lock();
    // Wave 13 (orphans, Linux's model): this task's children go to the
    // nearest live ancestor marked a child subreaper, else to init
    // (`reaper_of`), and the notices of its children that exited unreaped go
    // with them. With nobody to adopt them they are left with no parent and
    // the notices are dropped, as wave 12 dropped them all: nothing would
    // ever reap them (TIDs are never reused). Under this lock, which every
    // exit takes: after it no live task names this one as its parent, so a
    // child that still reads this task in its link (below, under the same
    // lock) does so before this point, and its notice is moved here.
    // A kernel task's children, and `orphan-reparent-canary`, keep wave 12's
    // purge with no re-link (`EXIT_REPARENTS`).
    let reparent = EXIT_REPARENTS[idx].load(Ordering::Relaxed);
    let reaper = if reparent { reaper_of(idx, child) } else { 0 };
    if reparent {
        for i in 0..MAX_TASKS {
            if i != idx && tid_for_idx(i).is_some() && PARENT_TID[i].load(Ordering::Relaxed) == child {
                PARENT_TID[i].store(reaper, Ordering::Relaxed);
                #[cfg(feature = "orphan-late-adopter-canary")]
                LATE_ADOPTER_TID.store(child, Ordering::Relaxed);
            }
        }
    }
    let mut adopted = 0;
    if EXIT_NOTICES_QUEUED.load(Ordering::Relaxed) != 0 {
        adopted = exit_note::readdress(&mut *t, child, reaper);
        if adopted == 0 {
            let purged = exit_note::purge_parent(&mut *t, child);
            if purged > 0 {
                EXIT_NOTICES_QUEUED.fetch_sub(purged as u32, Ordering::Release);
            }
        }
    }
    let parent = PARENT_TID[idx].swap(0, Ordering::Relaxed);
    // Wave 13: how the child ended (a signal, for a Linux parent's `wait4`),
    // recorded BEFORE its notice can be taken: a parent polling `wait4` on
    // another hart takes the notice the instant it is queued below.
    if azos_limits::LINUX_ABI {
        signal::note_child_end(idx, child, parent);
    }
    // U02-6 fix. `PARENT_TID` used to be cleared only when the CHILD
    // exits — nothing ran when the PARENT died — so every child of a
    // parent that already exited (its slot freed, its TID permanently
    // retired: TIDs are never reused, see `NEXT_TID`'s doc) queued a
    // notice addressed to a TID no `wait`/`waitpid` will ever present
    // again, and once 32 such orphans accumulated the FIFO eviction in
    // `exit_note::insert` started discarding a LIVE parent's real notice
    // instead. `exit_note::should_queue`/`insert` hold the fixed
    // decision logic (host-tested in `sched-wake-tests`); `idx_for_tid`
    // — the same O(1)-on-hint-hit lookup every wake path already uses —
    // is the `is_alive` predicate, so the common case (parent alive)
    // costs nothing extra.
    // A parent mid-exit that re-parents (`EXIT_REPARENTS`) has not done so
    // yet, or this task would no longer name it: it will move this notice
    // to its reaper, so it counts as alive. One that does not re-parent
    // counts as gone, as in wave 12: its purge may already have run.
    let parent_alive = |tid: u32| match idx_for_tid(tid) {
        Some(p) => !TASK_EXITING[p].load(Ordering::Acquire) || EXIT_REPARENTS[p].load(Ordering::Relaxed),
        None => false,
    };
    let queued = exit_note::should_queue(parent, parent_alive);
    if queued {
        match exit_note::insert(&mut *t, (parent, child, code), parent_alive) {
            exit_note::Placed::Empty => {
                EXIT_NOTICES_QUEUED.fetch_add(1, Ordering::Release);
            }
            exit_note::Placed::Orphan => {}
            exit_note::Placed::Full => {
                EXIT_NOTICE_DROPS.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
    drop(t);
    if queued {
        wake_child_waiter(parent);
    }
    if adopted > 0 {
        wake_child_waiter(reaper);
    }
    // Wave 13: `SIGCHLD` to a Linux parent (a native parent has no signal
    // state: `NotLinux`, nothing done). Discarded unless it set a handler.
    if azos_limits::LINUX_ABI && !cfg!(feature = "linux-sigchld-canary") {
        let _ = signal::post(parent, 17, child);
    }
}

/// Take the exit notice for ONE named child of `parent_tid`.
///
/// The targeted form of [`take_exit_note`]. Returns `Some((child_tid, code))`
/// when that child has finished and its notice is still queued;
/// [`WaitpidMiss::NotYet`] when `child_tid` is a live child of this parent, and
/// [`WaitpidMiss::NotOurs`] otherwise.
///
/// # Why the two misses are different answers
///
/// `take_exit_note` cannot express either. It returns the FIRST notice for the
/// parent, so a task with several children learns that *a* child died and never
/// which — and a caller waiting for one particular child must consume, and
/// discard, notices belonging to its siblings. `userspace/bench/vsbench`'s life-cycle
/// lane had to do exactly that, and its first version treated a sibling's
/// notice as an error and failed on a real boot.
///
/// Collapsing the two misses into one would put the caller back in that
/// position: "not finished yet" is a reason to poll again, and "not your child"
/// never becomes true however long you wait.
///
/// # How a live child is distinguished from a stranger
///
/// `PARENT_TID[idx]` holds the parent while the child lives and is cleared by
/// `note_exit` on the way out, so after a successful reap the same query
/// answers `NotOurs` — which is correct: the notice is spent and the child is
/// gone. That also makes a second reap of one child indistinguishable from a
/// TID that was never ours, deliberately: neither is ever going to produce a
/// notice, and telling them apart would need a record of dead children that
/// nothing here keeps.
pub fn take_exit_note_for(parent_tid: u32, child_tid: u32) -> Result<(u32, i32), WaitpidMiss> {
    // Both reads under ONE hold of `EXIT_NOTE`. Releasing between them left a
    // window in which `note_exit` had cleared the parent link and not yet
    // published the notice, so a child in the middle of exiting read as "not
    // yours" — see `note_exit`, which now clears the link under this same lock.
    let mut t = EXIT_NOTE.lock();
    for e in t.iter_mut() {
        if e.0 == parent_tid && e.1 == child_tid {
            let r = (e.1, e.2);
            *e = (0, 0, 0);
            EXIT_NOTICES_QUEUED.fetch_sub(1, Ordering::Release);
            #[cfg(feature = "orphan-late-adopter-canary")]
            {
                drop(t);
                late_adopter_delay(child_tid);
            }
            return Ok(r);
        }
    }
    // No notice. Is it a child of ours that simply has not exited?
    match idx_for_tid(child_tid) {
        Some(idx) if PARENT_TID[idx].load(Ordering::Relaxed) == parent_tid => {
            Err(WaitpidMiss::NotYet)
        }
        _ => Err(WaitpidMiss::NotOurs),
    }
}

/// Why [`take_exit_note_for`] found no notice.
/// Gate canary (`orphan-late-adopter-canary`): the last task whose exit
/// re-parented a child of its own.
#[cfg(feature = "orphan-late-adopter-canary")]
static LATE_ADOPTER_TID: AtomicU32 = AtomicU32::new(0);

/// Gate canary: the reap of that task returns 1.5 s late, as on a loaded
/// host, so its orphan's adopter lists it late.
#[cfg(feature = "orphan-late-adopter-canary")]
fn late_adopter_delay(child_tid: u32) {
    if child_tid == 0 || LATE_ADOPTER_TID.compare_exchange(child_tid, 0, Ordering::AcqRel, Ordering::Relaxed).is_err() {
        return;
    }
    let until = azos_drv_sys::timebase::now()
        .saturating_add(azos_drv_sys::timebase::TIMER_FREQ * 3 / 2);
    while azos_drv_sys::timebase::now() < until {
        crate::task_block(WaitReason::Timer(until));
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum WaitpidMiss {
    /// A live child of this parent that has not exited. Poll again.
    NotYet,
    /// Not a child of this parent, or already reaped. Polling will not help.
    NotOurs,
}

/// Take an exit notice for `parent_tid`. Returns the child's TID, or `None`
/// if none has finished.
///
/// **`WNOHANG` semantics, not POSIX `wait`**: it does not block. Blocking
/// would need a wait queue and a wake of the parent from the exit path, and
/// that *does* touch the scheduler. The caller polls, which is what it already
/// does with `recv`.
pub fn take_exit_note(parent_tid: u32) -> Option<(u32, i32)> {
    if parent_tid == 0 || EXIT_NOTICES_QUEUED.load(Ordering::Acquire) == 0 {
        return None;
    }
    let mut t = EXIT_NOTE.lock();
    for e in t.iter_mut() {
        if e.0 == parent_tid {
            let r = (e.1, e.2);
            *e = (0, 0, 0);
            EXIT_NOTICES_QUEUED.fetch_sub(1, Ordering::Release);
            return Some(r);
        }
    }
    None
}

// ── RFC-0055: child-exit waits and stop requests ───────────────────────────
//
// Per slot, beside `PARENT_TID` and for the same reason (not in `Task`, whose
// layout is frozen). Each entry that names a task carries the task's TID, so
// a slot reused by another task never inherits a stale request: no clearing
// on creation is needed, a mismatch reads as "none".

/// Slots whose task blocks in `SYS_CONSOLE_WAIT` and wants a child's exit
/// notice to wake it ([`note_exit`]).
static WAITS_CHILD: [core::sync::atomic::AtomicBool; MAX_TASKS] =
    [const { core::sync::atomic::AtomicBool::new(false) }; MAX_TASKS];
/// The TID a pending stop request in [`STOP_WORD`] is for; 0 = none.
static STOP_TID: [core::sync::atomic::AtomicU32; MAX_TASKS] =
    [const { core::sync::atomic::AtomicU32::new(0) }; MAX_TASKS];
/// The pending stop request (`stop_policy::Stop::encode`).
static STOP_WORD: [core::sync::atomic::AtomicU32; MAX_TASKS] =
    [const { core::sync::atomic::AtomicU32::new(0) }; MAX_TASKS];
/// The TID of a child spawned with `SPAWN_F_DIE_WITH_PARENT` in this slot;
/// 0 = none.
static DWP_TID: [core::sync::atomic::AtomicU32; MAX_TASKS] =
    [const { core::sync::atomic::AtomicU32::new(0) }; MAX_TASKS];
/// Forced stops issued that have not ended their task yet, machine-wide:
/// what the timer tick from user mode tests before looking at its own slot.
/// Changed only through `stop_policy::forced_*` on [`FORCED_ACCT`], so it is
/// always the number of slots whose word is `counted`.
static FORCED_PENDING: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
/// Per slot: the forced-stop accounting word (`stop_policy::forced_count`).
static FORCED_ACCT: [core::sync::atomic::AtomicU64; MAX_TASKS] =
    [const { core::sync::atomic::AtomicU64::new(stop_policy::ACCT_NONE) }; MAX_TASKS];

/// The pure half: the ancestor relation and the request word.
#[path = "stop_policy.rs"]
pub mod stop_policy;

/// Wave 13: the per-task signal words of Linux tasks (RFC-0047 P3).
#[path = "signal_state.rs"]
pub mod signal;

pub(crate) fn current_slot() -> Option<usize> {
    let idx = unsafe { PER_CPU[current_cpu_id()].current_idx.load(Ordering::Relaxed) };
    (idx < MAX_TASKS).then_some(idx)
}

/// The current task does (or no longer does) want a child's exit notice to
/// wake it.
pub fn set_current_waits_child(on: bool) {
    if let Some(idx) = current_slot() {
        WAITS_CHILD[idx].store(on, Ordering::Release);
    }
}

/// Is an exit notice queued for `parent_tid`? Does not take it.
pub fn has_exit_note(parent_tid: u32) -> bool {
    parent_tid != 0
        && EXIT_NOTICES_QUEUED.load(Ordering::Acquire) != 0
        && EXIT_NOTE.lock().iter().any(|e| e.0 == parent_tid)
}

/// Has `parent` a child it could still reap: a live one, or an exit notice
/// not taken yet? What a Linux `wait4(-1)` needs to tell `ECHILD` from "not
/// yet" (RFC-0047); the native waits answer `-1` for both.
pub fn has_reapable_child(parent: u32) -> bool {
    if parent == 0 {
        return false;
    }
    if has_exit_note(parent) {
        return true;
    }
    (0..MAX_TASKS).any(|idx| {
        tid_for_idx(idx).is_some() && PARENT_TID[idx].load(Ordering::Relaxed) == parent
    })
}

/// The parent of live task `tid`, 0 when it has none or is gone.
pub fn parent_of_tid(tid: u32) -> u32 {
    match idx_for_tid(tid) {
        Some(idx) => PARENT_TID[idx].load(Ordering::Relaxed),
        None => 0,
    }
}

/// Is `caller` an ancestor of live task `target` (at most
/// `stop_policy::MAX_ANCESTRY` steps up)?
pub fn task_is_ancestor(caller: u32, target: u32) -> bool {
    stop_policy::is_ancestor(caller, target, parent_of_tid, stop_policy::MAX_ANCESTRY)
}

/// The live descendants of `root` (within the ancestry bound), into `out`.
/// Returns how many were found (it may exceed `out.len()`; only that many are
/// written). A bounded scan of the task table.
pub fn descendants_of(root: u32, out: &mut [u32]) -> usize {
    let mut n = 0;
    for idx in 0..MAX_TASKS {
        let Some(tid) = tid_for_idx(idx) else { continue };
        if task_is_ancestor(root, tid) {
            if n < out.len() {
                out[n] = tid;
            }
            n += 1;
        }
    }
    n
}

/// Ask live task `tid` to stop (`force`: end it), with `signo`. Wakes any
/// `Timer` wait it is parked in (the console, pipe and sleep waits), so a
/// blocked target sees `-EINTR` or dies at the wake. A forced stop also
/// empties the target's syscall filter: its next syscall is refused, and the
/// refusal path (`seccomp_deny_kill`) ends it with `128 + signo` — the exit
/// path a user-mode fault takes, at a syscall boundary, never inside a
/// syscall. Returns `false` for a TID with no live task.
pub fn task_stop(tid: u32, force: bool, signo: u8) -> bool {
    let Some(idx) = idx_for_tid(tid) else { return false };
    // Wave 13: a Linux task is asked by its signal, not by the sticky stop
    // word: its handler (or default action) answers it, and a task that
    // handles `SIGINT` (an interactive shell) must not find every later
    // wait interrupted. A forced stop stays the forced path for both ABIs.
    // A request to a thread of a Linux process is its process's signal,
    // posted once: a subtree stop names the process and each of its threads,
    // and only the process (its leader) posts.
    if !force && azos_limits::LINUX_ABI {
        let p = crate::group::proc_tid(tid);
        if p != tid && signal::post(p, signo as u32, 0) != signal::Posted::NotLinux {
            return true;
        }
        match signal::post(tid, signo as u32, current_proc_tid()) {
            signal::Posted::NotLinux => {}
            _ => return true,
        }
    }
    record_stop(idx, tid, stop_policy::Stop { force, signo });
    wake_stopped(tid, force);
    true
}

/// Wake a task just asked to stop. A request wakes the `Timer` waits that
/// answer `-EINTR` (the console, pipe and sleep waits). A forced stop wakes
/// it out of ANY wait (plan item 7): every wait a task makes in its own
/// syscall blocks through `wait::task_block_killable`, which refuses to block
/// again once the stop is pending, so the task returns and ends; woken from a
/// `Timer` wait only, a task parked on a port, a fast-IPC exchange or a lease
/// stayed parked, and its exit hook, which releases everything it held, never
/// ran.
fn wake_stopped(tid: u32, force: bool) {
    #[cfg(not(feature = "kill-wake-timer-only-canary"))]
    wake_task_by_tid(tid, &|r| force || matches!(r, WaitReason::Timer(_)));
    #[cfg(feature = "kill-wake-timer-only-canary")]
    { let _ = force; wake_task_by_tid(tid, &|r| matches!(r, WaitReason::Timer(_))); }
}

/// Record stop request `new` for task `tid` in slot `idx` (merged with one
/// already pending): the request word, the machine-wide forced count, and a
/// forced stop's empty filter. The caller wakes the task.
fn record_stop(idx: usize, tid: u32, new: stop_policy::Stop) {
    let old = if STOP_TID[idx].load(Ordering::Acquire) == tid {
        stop_policy::Stop::decode(STOP_WORD[idx].load(Ordering::Acquire))
    } else {
        None
    };
    let merged = stop_policy::Stop::merge(old, new);
    STOP_WORD[idx].store(merged.encode(), Ordering::Release);
    STOP_TID[idx].store(tid, Ordering::Release);
    if merged.force {
        // Counted once per task, never after its exit hook sealed the slot.
        let _ = stop_policy::forced_count(&FORCED_ACCT[idx], &FORCED_PENDING, tid);
    }
    if merged.force && !old.is_some_and(|o| o.force) {
        // SAFETY: the slot holds `tid` (checked above); the filter is plain
        // data read by `current_syscall_verdict` through a pointer into this
        // same slot. A verdict racing these stores reads either filter, and
        // either answer is harmless: the next syscall after them is refused.
        unsafe {
            let t = task_mut(idx);
            if t.tid == tid {
                let f = &mut t.syscall_filter;
                f.count = 0;
                f.audit = false;
                f.bits = [0; crate::filter::SYSCALL_FILTER_BITMAP_BITS / 32];
                f.enabled = true;
            }
        }
    }
}

/// The stop request pending for the current task, if any. Sticky: a task
/// asked to stop stays asked, so every interruptible wait it enters after
/// answers `-EINTR`.
pub fn current_stop_request() -> Option<stop_policy::Stop> {
    let idx = current_slot()?;
    let tid = unsafe { TASKS[idx].tid };
    if STOP_TID[idx].load(Ordering::Acquire) != tid {
        return None;
    }
    stop_policy::Stop::decode(STOP_WORD[idx].load(Ordering::Acquire))
}

/// The exit code the current task must end with now, if a forced stop is
/// pending for it.
pub fn current_forced_exit() -> Option<i32> {
    current_stop_request().filter(|s| s.force).map(|s| s.exit_code())
}

/// Is a forced stop pending anywhere? One load: what the timer tick from
/// user mode asks before [`current_forced_exit`].
#[inline]
pub fn forced_stop_pending() -> bool {
    FORCED_PENDING.load(Ordering::Relaxed) != 0
}

/// End the current task now if a forced stop is pending for it. Call only at
/// a safe point: no lock held, not inside a syscall that holds the console
/// (a return to user mode, a timer interrupt taken from user mode).
pub fn exit_if_forced() {
    if let Some(code) = take_current_forced_exit() {
        // Wave 13: a thread group's member stopped because its group is
        // ending (`exit_group`, a fault) is not news.
        if !crate::group::current_group_ending() {
            azos_drv_sys::kprintln!(
                "[KILL] tid={} stopped by an ancestor: exit {}", current_task_tid(), code,
            );
            task_exit_by_signal(code);
        }
        task_exit_with_code(code);
    }
}

/// Consume the current task's forced stop, if one is pending: it is taken off
/// the machine-wide count and the slot's request is cleared, so a second call
/// (the exit hook after `seccomp_deny_kill`) finds nothing. Returns its exit
/// code. The caller is about to end the task.
pub fn take_current_forced_exit() -> Option<i32> {
    let idx = current_slot()?;
    let code = current_forced_exit()?;
    let tid = STOP_TID[idx].swap(0, Ordering::AcqRel);
    if tid != 0 {
        let _ = stop_policy::forced_uncount(&FORCED_ACCT[idx], &FORCED_PENDING, tid);
    }
    Some(code)
}

/// Task `tid`, in slot `idx`, is exiting (the exit hook, after
/// [`take_current_forced_exit`]):
/// a forced stop still counted for it is settled, and none recorded for it
/// from now on is counted. Without the seal, a stop that lands after the
/// hook — the task stays valid until its slot is freed — kept the
/// machine-wide count up for good, and every user-mode tick on every hart
/// took the slow path ([`forced_stop_pending`]).
pub fn seal_forced_stop(idx: usize, tid: u32) {
    if let Some(w) = FORCED_ACCT.get(idx) {
        stop_policy::forced_seal(w, &FORCED_PENDING, tid);
    }
}

/// Forced stops counted and not consumed, machine-wide (ktest, procfs).
pub fn forced_stops_pending() -> u32 {
    FORCED_PENDING.load(Ordering::Relaxed)
}

/// `tid` (a child just spawned, still parked) dies with its parent.
pub fn set_die_with_parent(tid: u32) {
    if let Some(idx) = idx_for_tid(tid) {
        DWP_TID[idx].store(tid, Ordering::Release);
    }
}

/// `dead` is exiting: force-stop (signal 1) every live child of it that was
/// spawned with `SPAWN_F_DIE_WITH_PARENT`. Returns how many. Called from the
/// exit hook, while `dead`'s slot is still valid.
pub fn stop_die_with_parent_children(dead: u32) -> usize {
    let mut n = 0;
    for idx in 0..MAX_TASKS {
        let Some(tid) = tid_for_idx(idx) else { continue };
        if DWP_TID[idx].load(Ordering::Acquire) == tid
            && PARENT_TID[idx].load(Ordering::Relaxed) == dead
            && task_stop(tid, true, 1)
        {
            n += 1;
        }
    }
    n
}

/// Core scheduling logic: pick next task for `cpu` and context-switch to it.
///
/// Scheduling order: strict priority over the per-CPU bitmap queues; on a
/// hart with RT state, `rt::pick` (band budget, EDF + CBS inside a level).
///
/// # Safety
/// Should be called with interrupts disabled on the calling CPU (all current
/// callers do, or run inside a trap handler where hardware already disabled
/// them) — but every ready-queue touch below goes through the IRQ-safe
/// `cpu_dequeue_locked` / `cpu_enqueue_locked` wrappers regardless, so this
/// function no longer *depends* on that invariant for correctness against
/// `CPU_LOCKS[cpu]`.
/// No `CPU_LOCKS` guard is held across `context_switch()` — each locked
/// helper acquires and releases `CPU_LOCKS[cpu]` internally, before
/// returning, so nothing is held when `context_switch` (which may not
/// return) is reached further down.

/// Clear the outgoing task's `context_saving` when `do_schedule` is about to
/// return **without switching**.
///
/// `context_saving` means "this task's registers are being saved right now —
/// do not dispatch it yet", and it is normally cleared by the save tail in
/// `context_switch.S`. `block_current` sets it *before* committing to
/// `Blocked`, so every path where `do_schedule` returns instead of switching
/// leaves it set on a task that nothing is saving.
///
/// The consequence is not subtle: `do_schedule` spin-gates on
/// `next.context_saving` before switching to a task, so a stuck flag makes
/// every hart that picks that task spin forever. Observed directly in the
/// census as `blocked tid=21 client=false saving=true` with phase A of
/// `ipctest` stalled — 369 of 1600 calls served and every client stuck.
///
/// Safe on the switching paths too, which is why it is called at the returns
/// rather than being conditional on state: if we are not switching away from
/// this task, nobody is saving it.
#[inline(always)]
unsafe fn clear_saving_on_no_switch(cpu: usize) {
    let idx = unsafe { PER_CPU[cpu].current_idx.load(Ordering::Relaxed) };
    if idx >= MAX_TASKS { return; }
    let task = unsafe { task_ref(idx) };
    // **Only for a `Running` current, and the restriction is load-bearing.**
    //
    // Clearing it unconditionally was tried and is a far worse bug than the
    // wedge it cures. For a `Blocked` current at a no-switch return the task
    // keeps executing on this hart with live registers; clearing the flag lets
    // a waker take it Blocked -> Ready -> enqueued, another hart dequeue it,
    // pass the spin-gate, and restore a **stale** saved context while this
    // hart is still running the real one. Two harts, one register file.
    //
    // Not hypothetical: the counters measured that path firing **12906 times**
    // in a single `ipctest` run (`self` arm, current Blocked), against 216
    // with the current Running. The dangerous case was the dominant one.
    //
    // A `Blocked` current at a no-switch return keeps the flag set and the
    // hart that picks it spins -- the IPC wedge. That is the lesser evil, and the real fix
    // is to never return to a `Blocked` current at all.
    if task.state() == TaskState::Running {
        task.context_saving.store(false, Ordering::Release);
    }
}



/// Early-return accounting for [`do_schedule`], split by whether the *current*
/// task had already committed to `Blocked`.
///
/// **WHY the split is the whole point.** `do_schedule` returning without
/// switching is perfectly normal when the current task is `Running` — there is
/// simply nothing better to run, so it keeps running. The same return with the
/// current task `Blocked` is a defect: `block_current` has already published
/// `Blocked` and does not idle, so control goes back through the syscall to
/// ring 3 and a task that the whole system believes is asleep keeps executing.
/// Every subsequent `task_block` then takes the "already Blocked, unswitched"
/// arm of `commit_blocked_or_consume_wake`, calls `do_schedule` again, and
/// returns again — which is exactly the signature measured in
/// on the IPC wedge: eight turns, zero wakes, 15 us.
///
/// The three sites are the three early returns, so a single run names the line.
pub mod unswitched {
    use core::sync::atomic::{AtomicU32, Ordering};

    /// `block_current` returned **without blocking**: the commit CAS reported
    /// a consumed wake stamp.
    /// How many times `do_schedule` is ENTERED, and how many times it gets as
    /// far as switching. Without these two, zeroed "returned without
    /// switching" counters are ambiguous: it may always switch, or it may
    /// never be entered at all.
    pub static CALLS: AtomicU32 = AtomicU32::new(0);
    pub static SWITCHED: AtomicU32 = AtomicU32::new(0);
    pub static BLOCK_SKIPPED: AtomicU32 = AtomicU32::new(0);
    /// `block_current` committed to `Blocked` and called `do_schedule`, which
    /// eventually returned — i.e. the task really did yield the hart and came
    /// back.
    pub static BLOCK_SLEPT: AtomicU32 = AtomicU32::new(0);

    /// APS enabled, its pick empty, and the per-CPU queue empty too.
    pub static APS_EMPTY_BLOCKED: AtomicU32 = AtomicU32::new(0);
    /// Priority-queue path with an empty per-CPU ready queue.
    pub static QUEUE_EMPTY_BLOCKED: AtomicU32 = AtomicU32::new(0);
    /// Picked ourselves (`next_idx == old_idx`).
    pub static SELF_PICK_BLOCKED: AtomicU32 = AtomicU32::new(0);
    /// Same three, with the current task still `Running` — the benign case,
    /// kept so the ratio is visible rather than assumed.
    pub static APS_EMPTY_OK: AtomicU32 = AtomicU32::new(0);
    pub static QUEUE_EMPTY_OK: AtomicU32 = AtomicU32::new(0);
    pub static SELF_PICK_OK: AtomicU32 = AtomicU32::new(0);

    /// Canary: this module is only compiled when the feature reaches THIS
    /// crate. If `kernel/Cargo.toml` stops forwarding
    /// `azos_sched/ipc-census`, the counters vanish and `read()` answers
    /// zeros for code that does not exist — which already invalidated two
    /// measurements in this investigation. `CANARY` is checked by the caller
    /// so that failure is loud instead of a convincing row of zeros.
    pub static CANARY: u32 = 0xC0FFEE;

    /// `(skipped, slept)` — the fundamental fork in `block_current`, which
    /// every other counter here is downstream of. Measured last, which was a
    /// mistake: two hypotheses died before this one was even instrumented.
    /// `(calls, switched)`
    pub fn call_split() -> (u32, u32) {
        (CALLS.load(Ordering::Relaxed), SWITCHED.load(Ordering::Relaxed))
    }

    pub fn block_split() -> (u32, u32) {
        (BLOCK_SKIPPED.load(Ordering::Relaxed), BLOCK_SLEPT.load(Ordering::Relaxed))
    }

    /// `(aps_blk, q_blk, self_blk, aps_ok, q_ok, self_ok)`
    pub fn read() -> (u32, u32, u32, u32, u32, u32) {
        (APS_EMPTY_BLOCKED.load(Ordering::Relaxed),
         QUEUE_EMPTY_BLOCKED.load(Ordering::Relaxed),
         SELF_PICK_BLOCKED.load(Ordering::Relaxed),
         APS_EMPTY_OK.load(Ordering::Relaxed),
         QUEUE_EMPTY_OK.load(Ordering::Relaxed),
         SELF_PICK_OK.load(Ordering::Relaxed))
    }

    #[inline(always)]
    pub fn bump(c: &AtomicU32) { c.fetch_add(1, Ordering::Relaxed); }
}

/// Wake latency: how long a task sat `Ready` before a hart actually ran it,
/// and **whether the doorbell was rung for it**.
///
/// **The question this exists to answer.** `vsbench` measures an `ipc-rt` worst
/// case of 5–15 ms in 7 runs of 8, against 276–417 us for Linux on the same
/// host (vsbench). Two discriminators localised it: the stall vanishes
/// at `-smp 1`, and it shrinks by 10x when the tick goes from 100 Hz to
/// 1000 Hz. So a task is made runnable, nobody dispatches it, and the timer
/// eventually rescues it.
///
/// That leaves exactly two shapes, and they need opposite fixes:
///   * the bell was **rung and did not help** — the IPI is delivered and
///     something on the target hart swallows it;
///   * the bell was **never rung** — the enqueue path skipped it, e.g.
///     `cpu_enqueue_locked` only rings `if appended`.
///
/// Global wake counters cannot separate them: they are cumulative, and one lost
/// wake among thousands does not move them. This records the delay per task and
/// splits the long ones by whether a doorbell accompanied that enqueue.
///
/// Side arrays, not `Task` fields, deliberately: a compile-time assertion ties
/// `satp`'s offset to `TASK_SATP_OFFSET`, the value `context_switch.S` is fed
/// via `offset_of!` (not hand-copied) — layout-frozen all the same, and
/// adding fields to `Task` has already broken this build once.
#[cfg(feature = "ipc-census")]
pub mod wakelat {
    use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
    use crate::task::MAX_TASKS;

    /// Same role as `unswitched::CANARY`: a row of zeros from a module that was
    /// never compiled is indistinguishable from a real measurement.
    pub static CANARY: u32 = 0x5EED;

    /// A wake is "long" past this many CLINT ticks. 10 MHz on QEMU, so 10_000
    /// ticks = **1 ms** — two orders of magnitude above the ~10 us a healthy
    /// cross-hart wake takes, and an order below the 10 ms tick, so it cannot
    /// catch ordinary scheduling jitter and cannot miss a tick-length stall.
    pub const LONG_TICKS: u64 = 10_000;

    /// CLINT time when this slot was last made `Ready`. 0 = not armed.
    pub static READY_AT: [AtomicU64; MAX_TASKS] =
        [const { AtomicU64::new(0) }; MAX_TASKS];
    /// Whether a doorbell was rung for the enqueue that armed `READY_AT`.
    pub static RANG: [AtomicBool; MAX_TASKS] =
        [const { AtomicBool::new(false) }; MAX_TASKS];

    /// Dispatches whose Ready->Running delay exceeded `LONG_TICKS`, and how
    /// many of those had a doorbell rung for them.
    pub static LONG: AtomicU32 = AtomicU32::new(0);
    pub static LONG_RANG: AtomicU32 = AtomicU32::new(0);
    /// Worst delay seen, in CLINT ticks.
    pub static MAX_DELAY: AtomicU64 = AtomicU64::new(0);
    /// Identity of the worst case: tid, the `ready_site` byte (site | hart<<4)
    /// that armed it, and the hart that finally dispatched it.
    ///
    /// A bare maximum says a wake was slow; it does not say whether the same
    /// task is always the victim, whether one hart is always the culprit, or
    /// which of the six `Ready` publishers armed it. Without that the next
    /// hypothesis is a guess -- and in this investigation every guess that
    /// explained the average failed on the tail.
    pub static MAX_TID:  AtomicU32 = AtomicU32::new(0);
    pub static MAX_SITE: AtomicU32 = AtomicU32::new(0);
    pub static MAX_HART: AtomicU32 = AtomicU32::new(0);
    /// Coarse histogram of long waits, so the shape is visible rather than
    /// only its extreme: 1-2 ms, 2-4 ms, 4-8 ms, >8 ms.
    pub static B1: AtomicU32 = AtomicU32::new(0);
    pub static B2: AtomicU32 = AtomicU32::new(0);
    pub static B4: AtomicU32 = AtomicU32::new(0);
    pub static B8: AtomicU32 = AtomicU32::new(0);
    /// Total dispatches measured, so `LONG` has a denominator.
    pub static MEASURED: AtomicU32 = AtomicU32::new(0);

    /// Arm the stopwatch: called right after a task is published `Ready`.
    #[inline]
    pub fn arm(idx: usize) {
        if idx < MAX_TASKS {
            READY_AT[idx].store(azos_drv_sys::timebase::now(), Ordering::Relaxed);
            RANG[idx].store(false, Ordering::Relaxed);
        }
    }

    /// Record that a doorbell was rung for this slot's enqueue.
    #[inline]
    pub fn rang(idx: usize) {
        if idx < MAX_TASKS { RANG[idx].store(true, Ordering::Relaxed); }
    }

    /// Stop the stopwatch: called when the task is actually set `Running`.
    #[inline]
    pub fn measure(idx: usize) {
        if idx >= MAX_TASKS { return; }
        let armed = READY_AT[idx].swap(0, Ordering::Relaxed);
        if armed == 0 { return; }   // not armed, or already measured
        let now = azos_drv_sys::timebase::now();
        let delay = now.saturating_sub(armed);
        MEASURED.fetch_add(1, Ordering::Relaxed);
        MAX_DELAY.fetch_max(delay, Ordering::Relaxed);
        if delay > LONG_TICKS {
            LONG.fetch_add(1, Ordering::Relaxed);
            if RANG[idx].load(Ordering::Relaxed) {
                LONG_RANG.fetch_add(1, Ordering::Relaxed);
            }
            let ms = delay / 10_000;
            if      ms < 2 { B1.fetch_add(1, Ordering::Relaxed); }
            else if ms < 4 { B2.fetch_add(1, Ordering::Relaxed); }
            else if ms < 8 { B4.fetch_add(1, Ordering::Relaxed); }
            else           { B8.fetch_add(1, Ordering::Relaxed); }
            // Racy against a concurrent worse case; acceptable because these
            // are read only after the fact and a torn identity would show as
            // an impossible combination rather than a plausible wrong one.
            if delay >= MAX_DELAY.load(Ordering::Relaxed) {
                // SAFETY: `idx < MAX_TASKS` was checked at entry, and this runs
                // on the dispatch path where the slot is live by construction —
                // the caller is about to make it `Running`.
                let t = unsafe { crate::scheduler::task_ref(idx) };
                MAX_TID.store(t.tid, Ordering::Relaxed);
                MAX_SITE.store(t.ready_site.load(Ordering::Relaxed) as u32, Ordering::Relaxed);
                MAX_HART.store(crate::scheduler::current_cpu_id() as u32, Ordering::Relaxed);
            }
        }
    }

    /// `(tid, ready_site_byte, dispatching_hart, b1, b2, b4, b8)`
    pub fn worst() -> (u32, u32, u32, u32, u32, u32, u32) {
        (MAX_TID.load(Ordering::Relaxed),
         MAX_SITE.load(Ordering::Relaxed),
         MAX_HART.load(Ordering::Relaxed),
         B1.load(Ordering::Relaxed), B2.load(Ordering::Relaxed),
         B4.load(Ordering::Relaxed), B8.load(Ordering::Relaxed))
    }

    /// Doorbells sent, and how many of those SBI refused.
    ///
    /// The send site discards the return value on purpose -- ringing a hart
    /// that never came up is harmless -- but "harmless when the hart is dead"
    /// and "silently dropped for a live hart" look identical from there.
    pub static IPI_SENT: AtomicU32 = AtomicU32::new(0);
    pub static IPI_ERR:  AtomicU32 = AtomicU32::new(0);
    /// Doorbells actually taken by a hart, counted in the `INT_SOFTWARE_S`
    /// trap arm. If this trails `IPI_SENT`, the IPI is being lost between
    /// SBI and the target; if it tracks it, the IPI arrives and the target's
    /// `schedule()` is what fails to dispatch.
    pub static IPI_RECV: AtomicU32 = AtomicU32::new(0);

    #[inline]
    pub fn ipi_sent(err: bool) {
        IPI_SENT.fetch_add(1, Ordering::Relaxed);
        if err { IPI_ERR.fetch_add(1, Ordering::Relaxed); }
    }

    #[inline]
    pub fn ipi_recv() { IPI_RECV.fetch_add(1, Ordering::Relaxed); }

    /// `(sent, err, recv)`
    pub fn ipi_read() -> (u32, u32, u32) {
        (IPI_SENT.load(Ordering::Relaxed),
         IPI_ERR.load(Ordering::Relaxed),
         IPI_RECV.load(Ordering::Relaxed))
    }

    /// `(long, long_with_bell, max_delay_ticks, measured)`
    pub fn read() -> (u32, u32, u64, u32) {
        (LONG.load(Ordering::Relaxed),
         LONG_RANG.load(Ordering::Relaxed),
         MAX_DELAY.load(Ordering::Relaxed),
         MEASURED.load(Ordering::Relaxed))
    }
}

/// The tasks with the most `total_runtime`, to name whoever is hogging a hart.
///
/// `schedule()` bumps the current task's `total_runtime` on every tick, so the
/// ranking says who is really running — which is the question global switch
/// counters cannot answer.
#[cfg(feature = "ipc-census")]
static SCHED_BY_TASK: [core::sync::atomic::AtomicU32; MAX_TASKS] =
    [const { core::sync::atomic::AtomicU32::new(0) }; MAX_TASKS];

/// Who ENTERS `do_schedule`, per task. The global counters say how many times
/// a switch happens; only this says **who asks for it**, which is the
/// difference between "the scheduler has gone mad" and "this task yields in a
/// loop".
#[cfg(feature = "ipc-census")]
pub fn top_sched_callers(out: &mut [(u32, u32, [u8; 8])]) -> usize {
    let mut n = 0usize;
    unsafe {
        for i in 0..MAX_TASKS {
            if !TASK_VALID[i].load(Ordering::Relaxed) { continue; }
            let c = SCHED_BY_TASK[i].load(Ordering::Relaxed);
            if c == 0 { continue; }
            let t = task_ref(i);
            let mut nm = [0u8; 8];
            for (k, b) in t.name.iter().take(8).enumerate() { nm[k] = *b; }
            let e = (t.tid, c, nm);
            if n < out.len() { out[n] = e; n += 1; }
            else {
                let mut worst = 0usize;
                for k in 1..out.len() { if out[k].1 < out[worst].1 { worst = k; } }
                if out[worst].1 < e.1 { out[worst] = e; }
            }
        }
    }
    out[..n].sort_unstable_by(|a, b| b.1.cmp(&a.1));
    n
}

pub fn top_runtime(out: &mut [(u32, u64, [u8; 8], u8)]) -> usize {
    let mut n = 0usize;
    unsafe {
        for i in 0..MAX_TASKS {
            if !TASK_VALID[i].load(Ordering::Relaxed) { continue; }
            let t = task_ref(i);
            let mut nm = [0u8; 8];
            for (k, b) in t.name.iter().take(8).enumerate() { nm[k] = *b; }
            let e = (t.tid, t.total_runtime, nm, t.state() as u8);
            if n < out.len() { out[n] = e; n += 1; }
            else {
                let mut worst = 0usize;
                for k in 1..out.len() { if out[k].1 < out[worst].1 { worst = k; } }
                if out[worst].1 < e.1 { out[worst] = e; }
            }
        }
    }
    out[..n].sort_unstable_by(|a, b| b.1.cmp(&a.1));
    n
}

/// Is the task currently on `cpu` already committed to `Blocked`?
#[cfg(feature = "ipc-census")]
#[inline(always)]
unsafe fn current_is_blocked(cpu: usize) -> bool {
    let idx = unsafe { PER_CPU[cpu].current_idx.load(Ordering::Relaxed) };
    if idx >= MAX_TASKS { return false; }
    unsafe { task_ref(idx).state() == TaskState::Blocked }
}

/// Why a task is giving up the CPU.
///
/// **Travels with the call, not in a per-CPU flag.** The reason is known at
/// the call site and nowhere else; a flag set beside the call is a flag
/// somebody eventually forgets to clear, and it would be wrong in exactly the
/// case that matters — a tick arriving while a voluntary schedule is in
/// flight. As an argument it cannot desynchronise from the call it describes.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SwitchReason {
    /// The task asked: `task_yield`, `task_block`, `task_exit`.
    Voluntary,
    /// The timer took the CPU away.
    Preempted,
}

/// Q3.2 (tickless idle) — the re-arm for an idle hart whose run queue is
/// EMPTY. `do_schedule()` reaches the two "nothing to pick" early returns
/// below in exactly that state (APS: `aps_pick_ready` → None →
/// `cpu_dequeue_locked` → None; legacy: the same dequeue → None), and
/// neither carried the re-arm the self-pick path further down does — the
/// idle task is never IN the queue, so an idle hart never self-picks. The
/// timer ISR's `set_next_tick_smart` (periodic 1/sched_hz clamp) therefore
/// stood on every tick: measured 74/74/75 wakeups/s over three 30 s windows
/// (`riscv64: idle wakeups/s (tickless)` row body by hand, -smp 1
/// bench-minimal), with a histogram of `set_next_tick_tickless(.., true)`
/// calls read over GDB showing ONE call per boot. The row's author measured
/// 43.6/s on a tree where the pick path still went through the self-pick
/// arm. Same arming as that arm; only when the current task is idle.
#[inline]
unsafe fn tickless_rearm_if_idle(cpu: usize) {
    let ci = PER_CPU[cpu].current_idx.load(Ordering::Relaxed);
    if ci < MAX_TASKS
        && task_ref(ci).priority.load(Ordering::Relaxed) == crate::task::IDLE_PRIORITY
    {
        azos_drv_sys::timebase::set_next_tick_tickless(
            cpu as u32, nearest_timer_deadline(), true,
        );
        // A throttled reservation or an exhausted band window on this hart
        // must not be slept past (SCHED-RT).
        rt::rearm(cpu);
    }
}

/// The context-saving gate's wait (see `do_schedule`): spin until `next`'s
/// save has finished, with a wall-clock bound (SCHED_SAVING_GATE_US). `false` when the bound
/// ran out. Out of line: the flag is clear on every switch that finds its
/// task saved, and the deadline needs a clock read only when it is not.
#[inline(never)]
fn wait_context_saved(next: &Task) -> bool {
    // Kconfig SCHED_SAVING_GATE_US (1000) and SCHED_SAVING_GATE_CLOCK_EVERY
    // (256): the bound and how often the clock is read while waiting.
    let deadline = azos_drv_sys::timebase::now()
        + (azos_drv_sys::timebase::TIMER_FREQ as u64)
            * azos_limits::SCHED_SAVING_GATE_US as u64 / 1_000_000;
    let every = (azos_limits::SCHED_SAVING_GATE_CLOCK_EVERY as u32).max(1);
    let mut spins: u32 = 0;
    while next.context_saving.load(Ordering::Acquire) {
        core::hint::spin_loop();
        spins = spins.wrapping_add(1);
        if spins % every == 0 && azos_drv_sys::timebase::now() >= deadline {
            return false;
        }
    }
    true
}


/// Gate-only probe (`ctx-probe`, CTXHUNT 2026-10-08): the invariants a
/// switch relies on, checked where they must hold. The first violation is
/// printed (`[CTXPROBE]`, both task ids, the hart, the site) and the kernel
/// panics; a second hart that fails meanwhile spins, so the line is whole.
/// - every `do_schedule` entry and every resume: `tp` is this hart (riscv64:
///   the id under its `stvec` slot) and `sp` is on the current task's stack;
/// - every dispatch: the task's saved `sp` is on its own stack, its `ra` is
///   not 0, its slot is valid, it is current on no other hart, and the
///   switching hart is still on the outgoing task's stack;
/// - every reap: no hart runs on the slot being freed.
///
/// It found the stale hart id of the exit path (see `do_schedule`) on its
/// first loaded boot.
#[cfg(feature = "ctx-probe")]
pub(crate) mod ctx_probe {
    use super::*;
    pub const DISPATCH: u8 = 1;
    pub const RESUME: u8 = 2;
    pub const REAP: u8 = 3;
    pub const DIRECT: u8 = 4;
    pub const ENTRY: u8 = 5;
    pub const TAIL: u8 = 6;

    #[inline(always)]
    pub fn sp_now() -> usize {
        let sp: usize;
        #[cfg(target_arch = "riscv64")]
        unsafe { core::arch::asm!("mv {}, sp", out(reg) sp) };
        #[cfg(target_arch = "aarch64")]
        unsafe { core::arch::asm!("mov {}, sp", out(reg) sp) };
        #[cfg(not(any(target_arch = "riscv64", target_arch = "aarch64")))]
        { sp = 0; }
        sp
    }

    /// The hart the trap entry would name (riscv64: the word under this
    /// hart's `stvec` slot, -1 for the boot hart's generic vector).
    /// `usize::MAX` where the ISA gives no independent answer.
    pub fn true_hart() -> usize {
        #[cfg(all(target_arch = "riscv64", target_os = "none"))]
        {
            let v: usize;
            unsafe { core::arch::asm!("csrr {}, stvec", out(reg) v) };
            let w = unsafe { core::ptr::read_volatile((v - 4) as *const i32) };
            if w < 0 {
                unsafe extern "C" { static boot_hart_id: usize; }
                unsafe { core::ptr::read_volatile(core::ptr::addr_of!(boot_hart_id)) }
            } else {
                w as usize
            }
        }
        #[cfg(not(all(target_arch = "riscv64", target_os = "none")))]
        { usize::MAX }
    }

    /// The task slot whose kernel stack holds `sp`, or `usize::MAX`.
    pub fn stack_slot_of(sp: usize) -> usize {
        let base = core::ptr::addr_of!(TASK_STACKS) as usize;
        if sp <= base || sp > base + STACK_SIZE * MAX_TASKS { return usize::MAX; }
        (sp - 1 - base) / STACK_SIZE
    }

    #[cold]
    #[inline(never)]
    pub fn fail(site: u8, cpu: usize, idx: usize, other: usize, what: &str, val: usize) -> ! {
        static FIRST: AtomicBool = AtomicBool::new(false);
        if FIRST.swap(true, Ordering::AcqRel) {
            loop { core::hint::spin_loop(); }
        }
        let name = |i: usize| -> &'static str {
            if i >= MAX_TASKS { return "-"; }
            let t = unsafe { task_ref(i) };
            let n = t.name.iter().position(|&b| b == 0).unwrap_or(TASK_NAME_MAX_LEN);
            core::str::from_utf8(&t.name[..n]).unwrap_or("?")
        };
        let (tid, st, rs, ra, ssp) = if idx < MAX_TASKS {
            let t = unsafe { task_ref(idx) };
            (t.tid, t.state() as u32, t.ready_site.load(Ordering::Relaxed),
             t.context.ra as usize, t.context.sp as usize)
        } else { (0, 0, 0, 0, 0) };
        let otid = if other < MAX_TASKS { unsafe { task_ref(other).tid } } else { 0 };
        azos_drv_sys::uart::console_bypass_for_halt();
        azos_drv_sys::kerr!(
            "[CTXPROBE] site={} cpu={} slot={} tid={} ({}) state={} ready_site={:#x} saved ra={:#x} sp={:#x}; other slot={} tid={} ({}); {}={:#x}",
            site, cpu, idx, tid, name(idx), st, rs, ra, ssp, other, otid, name(other), what, val);
        panic!("ctx-probe");
    }

    /// `idx` is current on `cpu`: on no other hart.
    pub fn check_unique(site: u8, cpu: usize, idx: usize) {
        for c in 0..ncpu() {
            if c != cpu && unsafe { PER_CPU[c].current_idx.load(Ordering::Acquire) } == idx {
                fail(site, cpu, idx, usize::MAX, "also_current_on_cpu", c);
            }
        }
    }

    /// Before a switch to `next_idx` on `cpu`.
    pub fn check_dispatch(site: u8, cpu: usize, next_idx: usize) {
        if next_idx >= MAX_TASKS { return; }
        let t = unsafe { task_ref(next_idx) };
        if !unsafe { TASK_VALID[next_idx].load(Ordering::Acquire) } {
            fail(site, cpu, next_idx, usize::MAX, "invalid_slot", 0);
        }
        let sp = t.context.sp as usize;
        let owner = stack_slot_of(sp);
        if owner != next_idx && owner != usize::MAX {
            fail(site, cpu, next_idx, owner, "saved_sp_on_other_stack", sp);
        }
        if t.context.ra == 0 {
            fail(site, cpu, next_idx, usize::MAX, "saved_ra_zero", 0);
        }
        check_unique(site, cpu, next_idx);
    }

    /// Code running on this hart: `tp` names it, `sp` is the current task's.
    pub fn check_running(site: u8) {
        let cpu = current_cpu_id();
        if cpu >= MAX_CPUS { return; }
        let idx = unsafe { PER_CPU[cpu].current_idx.load(Ordering::Relaxed) };
        let th = true_hart();
        if th != usize::MAX && th != cpu {
            fail(site, cpu, idx, usize::MAX, "tp_is_not_this_hart_which_is", th);
        }
        let owner = stack_slot_of(sp_now());
        if idx < MAX_TASKS && owner != usize::MAX && owner != idx {
            fail(site, cpu, idx, owner, "running_on_other_stack", sp_now());
        }
        if idx < MAX_TASKS {
            check_unique(site, cpu, idx);
        }
    }

    /// `idx` is about to be freed by `cpu`: nobody runs on it.
    pub fn check_reap(cpu: usize, idx: usize) {
        if stack_slot_of(sp_now()) == idx {
            fail(REAP, cpu, idx, idx, "reaping_own_stack", sp_now());
        }
        for c in 0..ncpu() {
            if unsafe { PER_CPU[c].current_idx.load(Ordering::Acquire) } == idx {
                fail(REAP, cpu, idx, usize::MAX, "reaping_current_of_cpu", c);
            }
        }
    }
}

/// Gate canary (`exit-stale-hart-canary`): the exit path's stale hart id,
/// made certain. An exiting task first sleeps 1 ms with its affinity on the
/// next hart, so it wakes there, then its next `do_schedule` is handed the
/// hart it entered the exit on, as `task_exit_with_code` used to hand it.
#[cfg(feature = "exit-stale-hart-canary")]
mod stale_hart_canary {
    use super::*;
    static ENTRY_CPU: [AtomicUsize; MAX_TASKS] = [const { AtomicUsize::new(usize::MAX) }; MAX_TASKS];

    pub unsafe fn arm(cpu: usize, idx: usize) {
        if idx >= MAX_TASKS || ncpu() < 2 { return; }
        let saved = task_ref(idx).cpu_affinity;
        task_mut(idx).cpu_affinity = ((cpu + 1) % ncpu()) as i8;
        let until = azos_drv_sys::timebase::now() + azos_drv_sys::timebase::TIMER_FREQ / 1000;
        crate::task_block(WaitReason::Timer(until));
        task_mut(idx).cpu_affinity = saved;
        ENTRY_CPU[idx].store(cpu, Ordering::Release);
    }

    pub unsafe fn take(cpu: usize) -> usize {
        let idx = PER_CPU[cpu].current_idx.load(Ordering::Relaxed);
        if idx < MAX_TASKS {
            let c = ENTRY_CPU[idx].swap(usize::MAX, Ordering::AcqRel);
            if c != usize::MAX { return c; }
        }
        cpu
    }
}

/// **A Zombie's slot is freed only after the switch away from it**
/// (CTXHUNT, 2026-10-08), by the task switched to, on its own stack: the
/// hart that switches from the Zombie stores the slot in the next task's
/// `reap_on_resume`, and that task frees it first thing when it runs
/// (`finish_switch`, after every `context_switch` that resumes a task and at
/// the top of `task_entry_wrapper`). It used to be freed in `do_schedule`'s
/// Zombie arm, BEFORE `context_switch`, while the hart still ran on the
/// Zombie's kernel stack through the dispatch tail (the context-saving gate's
/// spin of up to SCHED_SAVING_GATE_US, the tickless write, tracing): from
/// `TASK_VALID` false on, another hart could hand the slot, and its stack, to
/// a new fork or thread and run it. Two harts on one stack. With the stale
/// hart id of the exit path fixed (see `do_schedule`), the old order still
/// faulted the kernel in 4 of 8 loaded boots of abitest's thread storm;
/// `reap-window-canary` (the old order plus 2 ms on the freed stack) faults
/// it in the storm's first round. Linux frees a dead task's stack in
/// `finish_task_switch`, on the next task's stack; this is the same rule.
///
/// The store is made after the dispatch gate, so a `do_schedule` that gives
/// its pick back (and stays on the Zombie) leaves nothing to free.
#[inline(always)]
pub(crate) unsafe fn finish_switch(me: *mut Task) {
    #[cfg(feature = "ctx-probe")]
    ctx_probe::check_running(ctx_probe::RESUME);
    let r = unsafe { (*me).reap_on_resume };
    if r != 0 {
        finish_switch_slow(me, r - 1);
    }
}

#[inline(never)]
#[cold]
unsafe fn finish_switch_slow(me: *mut Task, idx: usize) {
    unsafe {
        (*me).reap_on_resume = 0;
        // SAFETY: `idx` is the Zombie the hart switched from to resume
        // `me`; nothing runs on its stack any more and its slot is still
        // valid (`TASK_VALID` true until this reap).
        reap_zombie_on_switch(idx);
    }
}

/// `do_schedule`'s reap of a Zombie it is switching away from, out of line
/// (wave 15, SWITCH): a rare arm with a lock, two prints and a TTBR1 probe,
/// inline it made every switch's prologue save registers only it needs.
/// The slot is free when this returns; the caller must not touch it again.
/// Called from [`finish_switch`], once this hart is off the Zombie's stack
/// (the K-C6 note below predates that: "about to leave" was not left yet).
#[inline(never)]
unsafe fn reap_zombie_on_switch(old_idx: usize) {
    #[cfg(feature = "ctx-probe")]
    ctx_probe::check_reap(current_cpu_id(), old_idx);
    let old = task_mut(old_idx);
    // K-C6: `task_exit()` marks the task Zombie but deliberately does
    // NOT free its pool slot (TASK_VALID) or clear
    // PER_CPU[cpu].current_idx itself — at that point it is still
    // executing ON this exact task's own stack (task_exit() calls
    // do_schedule() directly, and if no task was ready yet, idles in
    // its own WFI loop on that same stack). Freeing the slot there
    // would let another hart's alloc_slot() (e.g. via fork()) reuse
    // and dispatch a brand new task onto that same physical stack
    // while this hart is still running on it.
    //
    // This is therefore the correct, and only safe, place to free
    // it: right here, in the SAME do_schedule() call that is about
    // to `context_switch()` away from it below — whether that
    // happens on the very tick task_exit() called us (a ready task
    // was immediately available) or many ticks later (task_exit()
    // idled in WFI until one appeared; schedule() treats a lingering
    // Zombie exactly like "nothing running" in the meantime, see its
    // K-C6 comment, so it keeps calling us every tick until we get
    // here). Either way, by the time this line runs we are
    // unconditionally about to leave `old`'s stack for good via the
    // context_switch() call below — no other hart can have reused
    // this slot in the interim, since TASK_VALID stayed true.
    let _pool = PoolGuard::acquire();
    // aarch64 Phase 6 marker: this is the actual reap — the pool slot
    // is freed right here, immediately (no second task_create needed
    // to trigger it, unlike the lazy claim-time reset in
    // `try_task_create_init`) — so it is the honest place to prove
    // "the kernel reaps it" for the `hello`/`syscall_test` gate row.
    // `#[cfg]`'d to the real aarch64 kernel target only — NOT plain
    // `target_arch = "aarch64"`, which is also this crate's OWN host
    // test target (`aarch64-apple-darwin`, since these tests run on
    // Apple Silicon). That plain form shipped once and broke
    // `tests/host/syscall-tests`' `exec_binding` suite: this arm ran
    // during a host test through the very same `#[path]`-pulled
    // source (`shims/sched`), calling a `kprintln!` that assumes a
    // live UART driver. `target_os = "none"` is what is actually
    // true only for the real bare-metal build. RISC-V's console
    // output must not change either way (this task's own
    // constraint) — riscv64 already proves this same path via its
    // own scenarios' exit-code checks.
    // arch-only: an aarch64 bring-up trace line.
    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    azos_drv_sys::kprintln!(
        "[SCHED] aarch64 reaped tid={} slot={}", old.tid, old_idx);
    // TTBR1 split proof, second half (aarch64 parity program): the
    // boot-time marker in `kernel_main` (`[AARCH64-TTBR1]`) proves
    // the alias table is configured correctly at boot; this proves
    // it STAYS that way after real user-task activity has forced
    // real `TTBR0_EL1` switches (fork/exec/exit, all upstream of
    // every reap). First reap ON HART 0 only.
    //
    // **Must be hart 0, not merely "the first reap".** `TTBR1_EL1`
    // is a per-CPU banked register, and this wave's
    // `aarch64_early_ttbr1_alias` (`boot.S`) runs on the PRIMARY
    // ONLY — a secondary's own `TTBR1_EL1` was never written and
    // reads back whatever its reset state happens to be (0 on
    // QEMU). Gating on "first reap, any hart" measured this
    // directly on `-smp 2` ipctest: 8 of 10 runs printed FAILED
    // with `now=0x0` whenever hart 1 (not hart 0) reaped first —
    // a false positive from comparing hart 0's boot-time value
    // against hart 1's own never-initialized register, not a real
    // write to anything. Every row this runs in reaps many tasks
    // across the run, so waiting specifically for a hart-0 reap
    // still fires reliably without needing every secondary to
    // also run the alias setup (out of scope for this wave — see
    // `enable_ttbr1_alias`'s own doc).
    // arch-only: the TTBR1 split proof; no other ISA splits its tables so.
    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    if crate::smp::current_cpu_id() == 0 {
        static CHECKED: AtomicBool = AtomicBool::new(false);
        if !CHECKED.swap(true, Ordering::AcqRel) {
            // What this asserts changed when the kernel moved into the
            // upper half: TTBR1 no longer holds the boot-time alias,
            // it holds the kernel's REAL page table. So the invariant
            // is "TTBR1 still points at the kernel's table after user
            // tasks have been switching TTBR0", which is the property
            // the split exists for — comparing against the boot alias
            // would now fail on a correct kernel.
            let kpt = azos_mm::vmm::kernel_pagetable();
            if kpt != 0 {
                let now = azos_arch::sysregs::read_ttbr1_el1() as usize & !0xFFF;
                if now == kpt {
                    azos_drv_sys::kprintln!(
                        "[AARCH64-TTBR1-POST] after a user task's own TTBR0_EL1 \
                         switches: TTBR1_EL1 still the kernel table on hart 0 ({:#x})", now);
                } else {
                    azos_drv_sys::kerr!(
                        "[AARCH64-TTBR1-POST] FAILED: hart 0's TTBR1_EL1 is not the \
                         kernel table after user activity — kernel PT {:#x}, TTBR1 {:#x}",
                        kpt, now);
                }
            }
        }
    }
    // Its reservation, if any, leaves the hart's set and ledger before
    // the slot can be claimed again.
    rt::release(old_idx);
    TASK_VALID[old_idx].store(false, Ordering::Relaxed);
    hist_reaccount(old_idx);
    // Sentinel protocol (see alloc_slot): unpublish, fence, clear the
    // tid, so a dead TID can never be matched against this slot's
    // next occupant by the lock-free `idx_for_tid` scan.
    core::sync::atomic::fence(Ordering::Release);
    old.tid = 0;
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
    // AZOS Phase 1 W4-int.2 — if APS dispatch is enabled, consult
    // the per-class policies first. On any error (empty policies, tid
    // not in pool) fall back to the legacy bitmap queue so we never
    // wedge the kernel. While SCHED_USE_APS is false (default), the
    // branch is a single atomic load and the legacy path runs.
    #[cfg(feature = "ipc-census")]
    {
        unswitched::bump(&unswitched::CALLS);
        let ci = PER_CPU[cpu].current_idx.load(Ordering::Relaxed);
        if ci < MAX_TASKS { SCHED_BY_TASK[ci].fetch_add(1, Ordering::Relaxed); }
    }
    let mut from_prio_queue = false;
    // The RT pick says the running task must yield even to a worse priority
    // (its band is exhausted, or its reservation is throttled).
    let mut rt_force = false;
    let next_idx = if aps_dispatch_enabled() {
        // U02-1 fix: `aps_pick_ready` validates the pick against the
        // task's live state and drops stale entries — see its doc for why
        // a bare `pick_next().and_then(idx_for_tid)` (the code this
        // replaced) is unsafe to dispatch unconditionally now that wakes
        // feed the policies too.
        #[cfg(feature = "sched-aps")]
        let aps_pick = aps_pick_ready(cpu);
        // Legacy: the guard above is a compile-time `false`, so this arm is
        // folded out. Only the binding has to typecheck.
        #[cfg(not(feature = "sched-aps"))]
        let aps_pick: Option<usize> = None;
        match aps_pick {
            Some(idx) => idx,
            None => match cpu_dequeue_irqs_off(cpu) {
                Some(idx) => idx,
                None => {
                    #[cfg(feature = "ipc-census")]
                    unsafe {
                        unswitched::bump(if current_is_blocked(cpu) {
                            &unswitched::APS_EMPTY_BLOCKED
                        } else { &unswitched::APS_EMPTY_OK });
                    }
                    tickless_rearm_if_idle(cpu);
                    clear_saving_on_no_switch(cpu);
                    return;
                }
            },
        }
    } else {
        // Bitmap-based priority queue. A hart with RT state (`rt::active`)
        // picks through `rt::pick` instead: the band levels skipped while the
        // band is exhausted and something else is ready, reservation tasks
        // first in their level by deadline, throttled reservations skipped.
        // `Keep` is "nothing better than the running task", the same answer
        // an empty queue gives.
        let picked = if rt::active(cpu) {
            match rt::pick(cpu, PER_CPU[cpu].current_idx.load(Ordering::Relaxed)) {
                rt::Pick::Task { idx, force } => { rt_force = force; Some(idx) }
                rt::Pick::Keep => None,
            }
        } else {
            cpu_dequeue_irqs_off(cpu)
        };
        match picked {
            Some(idx) => { from_prio_queue = true; idx }
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
    // task low-priority enough to expose it. `>` and not `>=` so equal
    // priorities still round-robin.
    // **Only the priority-queue pick.** The APS pick is left alone: it is a
    // peek its policy commits below, not a queue entry to put back. And not
    // when the RT pick forces the switch (`rt_force`): a band task past its
    // budget, or a throttled reservation, must yield to a worse priority —
    // that is the whole point of the budget.
    if from_prio_queue && !rt_force && old_idx < MAX_TASKS && next_idx != old_idx {
        let old = &*old_t;
        if old.state() == TaskState::Running
            && (*next_t).priority.load(Ordering::Relaxed) > old.priority.load(Ordering::Relaxed)
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

    // AZOS Phase 1 W4-int.3a — if APS dispatch is active, the
    // picked task was a *peek*; commit by removing it from its
    // policy runqueue. (Mirrors the legacy `cpu_dequeue` which
    // already removed from the bitmap queue.)
    #[cfg(feature = "sched-aps")]
    let aps_active = aps_dispatch_enabled();
    #[cfg(feature = "sched-aps")]
    if aps_active {
        let next = task_mut(next_idx);
        crate::aps_state::dequeue_task_for_class(
            cpu,
            next.tid,
            next.sched_class_raw,
        );
    }

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

            // AZOS Phase 1 W4-int.3a — also re-enqueue into the
            // matching policy so APS can pick it next time. Mirrors
            // the legacy cpu_enqueue above.
            #[cfg(feature = "sched-aps")]
            if aps_active {
                crate::aps_state::enqueue_task_for_class(
                    cpu,
                    old.tid,
                    old.sched_class_raw,
                    old.priority.load(Ordering::Relaxed).min(255) as u8,
                    old.sched_time_slice_us,
                    old.sched_deadline_us,
                );
            }
        } else if old.state() == TaskState::Zombie {
            // The slot is freed only once this hart is off its stack, by
            // the task switched to (`finish_switch`). Gate canary only: free
            // it here, as before, and hold the hart on the freed stack 2 ms.
            if cfg!(feature = "reap-window-canary") {
                reap_zombie_on_switch(old_idx);
                let until = azos_drv_sys::timebase::now() + azos_drv_sys::timebase::TIMER_FREQ / 500;
                while azos_drv_sys::timebase::now() < until { core::hint::spin_loop(); }
            } else {
                // Its reservation leaves the hart's set now, as it did when
                // the reap ran here: the dispatch tail below (`rt::on_switch_prio`)
                // must not see it. `reap_zombie_on_switch` repeats it (a no-op).
                rt::release(old_idx);
                old_zombie = true;
            }
            old_slot_freed = true;
        } else if old.state() == TaskState::Blocked {
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
            // Safe for the APS and priority pick paths: the APS commit is
            // above, the priority path dequeued it, so it is nowhere, and
            // `Ready` + enqueue is the one state that is legal for both.
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
    next.time_slice = if is_rt_priority(next.priority.load(Ordering::Relaxed)) {
        RT_TIME_SLICE_TICKS
    } else {
        TIME_SLICE_TICKS
    };
    set_current_task(cpu, next_idx);
    // The hart that restores a task writes its own id into the `tp` the
    // restore loads (wave 13, RT7). Every enqueue path is meant to have set
    // it already (`context.tp = target_cpu`), but a store made while the
    // task's previous hart was still saving it is overwritten by that save
    // (`sd tp, CTX_TP`), and a task that runs with another hart's id in `tp`
    // makes its next `do_schedule` rewrite that hart's `current_idx`. Here
    // the dispatch gate above has seen the save finish, so this store is the
    // last word.
    next.context.tp = cpu as CtxReg;
    if old_zombie {
        next.reap_on_resume = old_idx + 1;
    }

    // AZOS Phase 1 W4-int.4 — tell the APS combinator which class
    // is now running on this CPU so subsequent timer ticks credit the
    // right budget.
    //
    // Only while APS drives dispatch. This used to run on every switch "so a
    // future flip-to-true sees accurate counters", taking the per-CPU APS lock
    // (~100 instructions) on the hottest path in the kernel for a scheduler that
    // nothing in the tree enables: `use_aps_dispatch` has no caller. Flipping it
    // on now re-seeds every CPU's current class itself
    // (`aps_seed_current_classes`), so the state a later flip sees is the same;
    // what is not kept is the consumption accrued to a class while APS was off,
    // which nothing could have read. Measured 2026-09-18: 198 of a 3,700
    // instruction IPC round trip.
    #[cfg(feature = "sched-aps")]
    if aps_dispatch_enabled() {
        if let Some(class) =
            crate::class::SchedClass::from_raw(next.sched_class_raw)
        {
            let _ = crate::aps_state::with_cpu(cpu, |state| {
                state.aps.set_current(class, next.tid);
            });
        }
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

    // Update PI mutex identity so priority inheritance knows who we are.
    // One release fence for both stores (each was a `Release` store, i.e. a
    // fence of its own); the readers load them `Relaxed`.
    core::sync::atomic::fence(Ordering::Release);
    azos_sync::pi_mutex::CURRENT_TID.store(next.tid, Ordering::Relaxed);
    azos_sync::pi_mutex::CURRENT_PRIO.store(next.priority.load(Ordering::Relaxed), Ordering::Relaxed);

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
        if next_is_idle || old_was_idle {
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

    // RFC-0051 E1: the outgoing task stops and `next` starts accruing
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

// ---- Query functions ----

/// Returns the name of the currently running task on this CPU.
pub fn current_task_name() -> &'static str {
    let cpu = current_cpu_id();
    unsafe {
        let idx = PER_CPU[cpu].current_idx.load(Ordering::Relaxed);
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
    let cpu = current_cpu_id();
    unsafe {
        let idx = PER_CPU[cpu].current_idx.load(Ordering::Relaxed);
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
    let cpu = current_cpu_id();
    unsafe {
        let idx = PER_CPU[cpu].current_idx.load(Ordering::Relaxed);
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

/// The hart the calling task is running on, for `SYS_TASKINFO`.
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
    let cpu = current_cpu_id();
    unsafe {
        let idx = PER_CPU[cpu].current_idx.load(Ordering::Relaxed);
        if idx == usize::MAX { 0 } else { TASKS[idx].tid }
    }
}

/// The pool slot and TID of the task running on this CPU, or `None` when
/// none is current: [`current_task_tid`] plus the slot it read, so a caller
/// keyed by slot (the capability tables, N4) need not find it again with
/// [`idx_for_tid`].
#[inline]
pub fn current_task_slot() -> Option<(usize, u32)> {
    let cpu = current_cpu_id();
    unsafe {
        let idx = PER_CPU[cpu].current_idx.load(Ordering::Relaxed);
        if idx < MAX_TASKS { Some((idx, TASKS[idx].tid)) } else { None }
    }
}

/// Current priority (a donation included) of the task running on this CPU, or
/// `IDLE_PRIORITY` if none is current. Per CPU like [`current_task_tid`]: the
/// `PiMutex` identity accessor, replacing the single global
/// `pi_mutex::CURRENT_PRIO` that any hart's switch overwrote.
pub fn current_task_priority() -> u32 {
    let cpu = current_cpu_id();
    unsafe {
        let idx = PER_CPU[cpu].current_idx.load(Ordering::Relaxed);
        if idx == usize::MAX {
            crate::task::IDLE_PRIORITY
        } else {
            TASKS[idx].priority.load(Ordering::Relaxed)
        }
    }
}

/// Base priority (no donation) of the task running on this CPU, or
/// `IDLE_PRIORITY` if none is current: the task's own class, which is what
/// the owner rule "an RT task never does block I/O" is about
/// (`RT_BLOCK_IO_CHECK`). Per CPU like [`current_task_priority`].
pub fn current_task_base_priority() -> u32 {
    let cpu = current_cpu_id();
    unsafe {
        let idx = PER_CPU[cpu].current_idx.load(Ordering::Relaxed);
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
    let cpu = current_cpu_id();
    unsafe {
        let idx = PER_CPU[cpu].current_idx.load(Ordering::Relaxed);
        // Wave 13: a thread's parent is its process's (the leader's).
        if idx == usize::MAX { 0 } else { PARENT_TID[proc_slot(idx)].load(Ordering::Relaxed) }
    }
}

/// Returns the clean (pre-prologue, ABI-aligned) stack top of the task running
/// on this CPU, or 0 if none.
///
/// Used by the I-13 transactional control-tick restart (RFC-0029): on a
/// recoverable fault the trap handler resets SP to this known-good base before
/// re-entering the control task, rather than to a mid-function SP — so the
/// entry prologue runs exactly once per restart and the stack does not descend
/// one frame on every rollback.
pub fn current_task_stack_top() -> usize {
    let cpu = current_cpu_id();
    unsafe {
        let idx = PER_CPU[cpu].current_idx.load(Ordering::Relaxed);
        if idx == usize::MAX {
            return 0;
        }
        task_stack_top(TASKS[idx].stack_idx)
    }
}

/// Returns total runtime ticks of the currently running task.
pub fn current_runtime() -> u64 {
    let cpu = current_cpu_id();
    unsafe {
        let idx = PER_CPU[cpu].current_idx.load(Ordering::Relaxed);
        if idx == usize::MAX { 0 } else { TASKS[idx].total_runtime }
    }
}

/// Returns the user page-table physical address for the current task
/// (0 = kernel task / no user address space).
pub fn current_user_pt() -> usize {
    let cpu = current_cpu_id();
    unsafe {
        let idx = PER_CPU[cpu].current_idx.load(Ordering::Relaxed);
        #[cfg(feature = "cpuid-probe")]
        crate::cpuid_probe::note_accessor(cpu);
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

/// The current task's process id: its thread group leader's TID, or its own
/// (wave 13). What owns its descriptors and keys its personality state.
///
/// `#[inline]` with `current_slot` spelled out: it is the whole of `getpid`,
/// the syscall-floor call, and a call to the non-inline `current_slot` from
/// another crate cost a call, a return and a second bounds check (SYSFLOOR).
#[inline]
pub fn current_proc_tid() -> u32 {
    let idx = unsafe { PER_CPU[current_cpu_id()].current_idx.load(Ordering::Relaxed) };
    if idx < MAX_TASKS {
        crate::group::proc_of(idx, unsafe { TASKS[idx].tid })
    } else {
        0
    }
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
        }
    }
}

/// Update the task_satp, user_pt and user_brk of the current task.
/// Called by exec_user after a new user page table has been built.
pub fn set_current_user_info(task_satp: u64, user_pt: u64, brk: u64) {
    let cpu = current_cpu_id();
    unsafe {
        let idx = PER_CPU[cpu].current_idx.load(Ordering::Relaxed);
        if idx != usize::MAX {
            TASKS[idx].task_satp = task_satp;
            TASKS[idx].user_pt   = user_pt;
            TASKS[idx].user_brk  = brk;
            // Owner decision 102 — a new address space starts from zero. Both
            // writers of this budget are "this task now has that page
            // table", so both reset here (see `set_task_user_info` below for
            // the other writer, fork's and spawn's).
            //
            // RFC-0049 M1: the image, stack and page tables of the new address
            // space ARE charged -- by the caller, right after this, through
            // `mm_install_frames` with the count `load_elf` returned.
            TASKS[idx].budget.reset();
        }
    }
}

// ── Owner decision 102 — per-task frame budget ────────────────────────────
//
// Scan unit 3 finding 3: CPU has quotas (`partitions.rs`, `class.rs`) and
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
    let cpu = current_cpu_id();
    unsafe {
        let idx = PER_CPU[cpu].current_idx.load(Ordering::Relaxed);
        if idx == usize::MAX { return true; }
        // Wave 13: a thread group's budget is its leader's.
        let idx = proc_slot(idx);
        // RFC-0049 M1: frames another task freed on this one's behalf since
        // its last charge (`mm_discharge_tid`) come off first, so a refusal
        // is decided on what the task holds now.
        fold_pending_discharge(idx);
        // `PageBudget::charge` (`crates/core/mm/src/budget.rs`) is the
        // byte-for-byte transcription this used to inline: the add is
        // saturating (`overflow-checks = true` makes a plain `+` a board
        // reset), and a charge that would exceed a nonzero limit charges
        // NOTHING.
        if TASKS[idx].budget.charge(pages) {
            // And a mark that OUTLIVES the task.
            //
            // The per-task peak alone measured nothing: every ring-3 program
            // in this tree runs and exits, its slot goes invalid, and the
            // census dump three seconds later reported 0 for vsbench, abitest
            // and gpio_drv alike. Three very different programs answering
            // identically is the instrument, not the data — so the number
            // that sizes a budget has to survive the task that set it.
            MM_PEAK_GLOBAL.fetch_max(TASKS[idx].budget.used(), Ordering::Relaxed);
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
    let cpu = current_cpu_id();
    unsafe {
        let idx = PER_CPU[cpu].current_idx.load(Ordering::Relaxed);
        if idx == usize::MAX { return; }
        TASKS[proc_slot(idx)].budget.discharge(pages);
    }
}

/// Take `pages` off task `idx`'s budget for frames another task freed.
#[inline]
unsafe fn fold_pending_discharge(idx: usize) {
    let pending = TASKS[idx].mem.pending_discharge.swap(0, Ordering::Relaxed);
    if pending != 0 {
        TASKS[idx].budget.discharge(pending);
    }
}

/// RFC-0049 M1: give `pages` frames back to the task `tid` from ANOTHER
/// task's context — the last holder of a shared-memory region `tid` created
/// freeing its frames, an io_ring torn down by someone else.
///
/// Posted, not applied: `tid`'s budget has one writer, `tid` itself, and it
/// folds the posting in at its next charge. A `tid` that no longer exists
/// needs nothing (its budget went with its slot); TIDs are not reused before
/// `NEXT_TID` wraps at 2^32, so the posting cannot reach a stranger.
pub fn mm_discharge_tid(tid: u32, pages: u32) {
    if pages == 0 { return; }
    unsafe {
        if let Some(idx) = idx_for_tid(tid) {
            TASKS[idx].mem.pending_discharge.fetch_add(pages, Ordering::Relaxed);
        }
    }
}

/// RFC-0049 M1: charge `pages` to the current task if it is `tid`, the
/// creator of the object being allocated. `true` (nothing charged) when the
/// creator is not the current task: a kernel caller allocating on a task's
/// behalf, whose frames the kernel reserve covers.
pub fn mm_charge_if_current(tid: u32, pages: u32) -> bool {
    if current_task_tid() != tid { return true; }
    mm_charge(pages)
}

/// RFC-0049 M1: the page-table hook `azos_mm::vmm` calls before (and,
/// on a failed allocation, after) it allocates a table under root `root`.
///
/// A table under the current task's OWN root is charged to it now, and a
/// refusal makes the mapping fail. A table under any other root belongs to an
/// address space this task is building for exec, spawn or fork: it is counted
/// in `mem.pt_build` and charged, with the rest of that address space, to the
/// task that receives it. No current task (boot, the kernel's own tables): not
/// charged.
fn table_hook(root: usize, charge: bool) -> bool {
    let cpu = current_cpu_id();
    unsafe {
        let idx = PER_CPU[cpu].current_idx.load(Ordering::Relaxed);
        if idx >= MAX_TASKS { return true; }
        // Wave 13: a member's root is its group's; `mm_charge` charges the
        // leader.
        if TASKS[idx].user_pt as usize == root {
            if charge { return mm_charge(1); }
            mm_discharge(1);
            return true;
        }
        let b = &mut TASKS[idx].mem.pt_build;
        *b = if charge { b.saturating_add(1) } else { b.saturating_sub(1) };
        true
    }
}

/// RFC-0049 M1: the fault hook — one user page fault resolved (COW break or
/// demand fault) for the current task.
fn fault_hook() {
    let cpu = current_cpu_id();
    unsafe {
        let idx = PER_CPU[cpu].current_idx.load(Ordering::Relaxed);
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
    let cpu = current_cpu_id();
    unsafe {
        let idx = PER_CPU[cpu].current_idx.load(Ordering::Relaxed);
        if idx >= MAX_TASKS { return 0; }
        core::mem::take(&mut TASKS[idx].mem.pt_build)
    }
}

/// RFC-0049 M1: the current task's `(limit, locked)`.
pub fn current_mem_policy() -> (u32, bool) {
    let cpu = current_cpu_id();
    unsafe {
        let idx = PER_CPU[cpu].current_idx.load(Ordering::Relaxed);
        if idx >= MAX_TASKS { return (0, false); }
        let idx = proc_slot(idx);
        (TASKS[idx].budget.limit(), TASKS[idx].mem.locked)
    }
}

/// Is the current task `mem = "locked"`?
pub fn current_mem_locked() -> bool {
    current_mem_policy().1
}

/// `(faults, peak, locked)` of the current task, for the exit report.
pub fn current_mem_report() -> (u32, u32, bool) {
    let cpu = current_cpu_id();
    unsafe {
        let idx = PER_CPU[cpu].current_idx.load(Ordering::Relaxed);
        if idx >= MAX_TASKS { return (0, 0, false); }
        let idx = proc_slot(idx);
        (TASKS[idx].mem.faults, TASKS[idx].budget.peak(), TASKS[idx].mem.locked)
    }
}

/// RFC-0049 M1: give the CURRENT task the budget `limit` and lock `locked`,
/// and charge it `frames` — what its freshly installed address space already
/// holds. Called by exec right after `set_current_user_info`. The caller has
/// already checked `frames` against `limit` (exec refuses an image that does
/// not fit), so this charge cannot be refused.
pub fn mm_install_frames(limit: u32, locked: bool, frames: u32) {
    let cpu = current_cpu_id();
    unsafe {
        let idx = PER_CPU[cpu].current_idx.load(Ordering::Relaxed);
        if idx >= MAX_TASKS { return; }
        let t = &mut TASKS[idx];
        t.budget.set_limit(limit);
        t.mem.locked = locked;
        let _ = t.budget.charge(frames);
        MM_PEAK_GLOBAL.fetch_max(t.budget.used(), Ordering::Relaxed);
    }
}

/// RFC-0049 M1: [`mm_install_frames`] for a task that is not running yet
/// (a spawned or forked child, by pool index, before it is released).
/// `false`, and nothing changed, if `frames` exceeds a nonzero `limit`.
pub fn set_task_mem(idx: usize, limit: u32, locked: bool, frames: u32) -> bool {
    if limit != 0 && frames > limit {
        MM_QUOTA_REFUSALS.fetch_add(1, Ordering::Relaxed);
        return false;
    }
    unsafe {
        if idx >= MAX_TASKS || !TASK_VALID[idx].load(Ordering::Relaxed) { return false; }
        let t = &mut TASKS[idx];
        t.budget.set_limit(limit);
        t.mem.locked = locked;
        let _ = t.budget.charge(frames);
        MM_PEAK_GLOBAL.fetch_max(t.budget.used(), Ordering::Relaxed);
    }
    true
}

/// Count one budget refusal that happened outside `mm_charge` (an exec whose
/// image does not fit its row's budget).
pub fn note_mm_quota_refusal() {
    MM_QUOTA_REFUSALS.fetch_add(1, Ordering::Relaxed);
}

// ── RFC-0049 M1, wave 9: live instances per topology row ─────────────────────
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
    let cpu = current_cpu_id();
    unsafe {
        let idx = PER_CPU[cpu].current_idx.load(Ordering::Relaxed);
        if idx >= MAX_TASKS { return 0; }
        TASKS[idx].mem.row
    }
}

/// The row whose count the current task's process holds (its leader's
/// [`crate::task::TaskMem::row`]; a thread's own is 0). What an exec from
/// any thread compares its image's row with.
pub fn current_proc_mem_row() -> u16 {
    let cpu = current_cpu_id();
    unsafe {
        let idx = PER_CPU[cpu].current_idx.load(Ordering::Relaxed);
        if idx >= MAX_TASKS { return 0; }
        TASKS[proc_slot(idx)].mem.row
    }
}

/// Record on the current task the count it now holds (exec, after the claim).
pub fn set_current_mem_row(row: u16) {
    let cpu = current_cpu_id();
    unsafe {
        let idx = PER_CPU[cpu].current_idx.load(Ordering::Relaxed);
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
/// `task.budget.reset()` at task-creation reuse) covers the address-space
/// discard case a different way, which may be why nothing calls this —
/// left as a finding, not removed, since deleting a `pub fn` in a
/// scheduler this size is an owner call.
pub fn mm_reset_charge() {
    let cpu = current_cpu_id();
    unsafe {
        let idx = PER_CPU[cpu].current_idx.load(Ordering::Relaxed);
        if idx != usize::MAX { TASKS[idx].budget.reset(); }
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
/// Under `sched-aps` the task was mirrored into its creation-time class's
/// policy queue; that entry is dropped on every CPU before the class changes,
/// so the exit path's dequeue (by the NEW class) cannot leave it behind.
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
            #[cfg(feature = "sched-aps")]
            if task.sched_class_raw != class_raw {
                for c in 0..ncpu() {
                    crate::aps_state::dequeue_task_for_class(c, task.tid, task.sched_class_raw);
                }
            }
            task.sched_class_raw = class_raw;
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
    let cpu = current_cpu_id();
    unsafe {
        let idx = PER_CPU[cpu].current_idx.load(Ordering::Relaxed);
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

/// Charge `pages` to the budget of `tid`'s process, all or nothing, like
/// [`mm_charge`] for the current task. Wave 14 (DEMANDPAGE): a fork's child
/// is charged the uncommitted reservation it inherits, before it runs, under
/// the reserve-time model (RFC-0049 M1). `false` when `tid` is not live or
/// would go over its budget; nothing is charged then.
pub fn mm_charge_tid(tid: u32, pages: u32) -> bool {
    if pages == 0 { return true; }
    unsafe {
        let Some(idx) = idx_for_tid(tid) else { return false };
        let idx = proc_slot(idx);
        if TASKS[idx].budget.charge(pages) {
            MM_PEAK_GLOBAL.fetch_max(TASKS[idx].budget.used(), Ordering::Relaxed);
            true
        } else {
            MM_QUOTA_REFUSALS.fetch_add(1, Ordering::Relaxed);
            false
        }
    }
}

/// Declare the current task's budget, in 4 KiB pages. `0` = no limit.
pub fn set_current_user_page_limit(limit: u32) {
    let cpu = current_cpu_id();
    unsafe {
        let idx = PER_CPU[cpu].current_idx.load(Ordering::Relaxed);
        if idx != usize::MAX { TASKS[idx].budget.set_limit(limit); }
    }
}

/// `(used, limit)` for the current task — diagnostics and the gate row.
#[must_use]
pub fn current_user_pages() -> (u32, u32) {
    let cpu = current_cpu_id();
    unsafe {
        let idx = PER_CPU[cpu].current_idx.load(Ordering::Relaxed);
        if idx == usize::MAX { return (0, 0); }
        (TASKS[idx].budget.used(), TASKS[idx].budget.limit())
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
            if t.budget.peak() > best {
                best = t.budget.peak();
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

/// Read + update user_brk for the current task (sys_brk).
/// Returns new brk value, or old brk if addr == 0.
pub fn update_user_brk(addr: u64) -> u64 {
    let cpu = current_cpu_id();
    unsafe {
        let idx = PER_CPU[cpu].current_idx.load(Ordering::Relaxed);
        if idx == usize::MAX { return 0; }
        // Wave 13: one break per thread group, on the leader's slot.
        let idx = proc_slot(idx);
        if addr == 0 {
            TASKS[idx].user_brk
        } else {
            TASKS[idx].user_brk = addr;
            addr
        }
    }
}

/// Reserve `span` bytes of the current task's shm/MMIO window `[lo, hi)`
/// ([`crate::user_window::reserve`]). `None` when no task is current.
///
/// Unlocked, like [`update_user_brk`]: a task's reservations are written only
/// by its own syscalls, and by the slot reuse that clears them after it has
/// exited.
pub fn reserve_current_user_window(lo: usize, hi: usize, span: usize) -> Option<usize> {
    let cpu = current_cpu_id();
    unsafe {
        let idx = PER_CPU[cpu].current_idx.load(Ordering::Relaxed);
        if idx == usize::MAX { return None; }
        crate::user_window::reserve(&mut task_mut(proc_slot(idx)).user_window, lo, hi, span)
    }
}

/// Give back the current task's reservation `[base, base + span)`
/// ([`crate::user_window::release`]). `false` when no task is current or the
/// task holds no such reservation.
pub fn release_current_user_window(base: usize, span: usize) -> bool {
    let cpu = current_cpu_id();
    unsafe {
        let idx = PER_CPU[cpu].current_idx.load(Ordering::Relaxed);
        if idx == usize::MAX { return false; }
        crate::user_window::release(&mut task_mut(proc_slot(idx)).user_window, base, span)
    }
}

/// Set user info for a specific task by pool index (used by fork).
pub fn set_task_user_info(idx: usize, task_satp: u64, user_pt: u64, brk: u64) {
    unsafe {
        if idx < MAX_TASKS && TASK_VALID[idx].load(Ordering::Relaxed) {
            TASKS[idx].task_satp = task_satp;
            TASKS[idx].user_pt   = user_pt;
            TASKS[idx].user_brk  = brk;
            // Owner decision 102 — a new address space starts from zero. Both
            // writers of this budget are "this task now has that page
            // table", so both reset here (see `set_current_user_info` above
            // for the other writer, exec's).
            //
            // RFC-0049 M1: what the new address space already holds (image,
            // stack and tables for spawn; the child's own tables for fork) is
            // charged by the caller through `set_task_mem`, right after this.
            TASKS[idx].budget.reset();
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
        task.fork_ctx_ready.store(true, Ordering::Release);
        true
    }
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
    let cpu = current_cpu_id();
    unsafe {
        let idx = PER_CPU[cpu].current_idx.load(Ordering::Relaxed);
        if idx == usize::MAX { return None; }
        let task = task_mut(idx);
        if !task.fork_ctx_ready.swap(false, Ordering::Acquire) {
            return None;
        }
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
    let cpu = current_cpu_id();
    unsafe {
        let idx = PER_CPU[cpu].current_idx.load(Ordering::Relaxed);
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
    let cpu = current_cpu_id();
    unsafe {
        let idx = PER_CPU[cpu].current_idx.load(Ordering::Relaxed);
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
    let cpu = current_cpu_id();
    unsafe {
        let idx = PER_CPU[cpu].current_idx.load(Ordering::Relaxed);
        if idx == usize::MAX { return None; }
        let task = task_mut(idx);
        if !task.exec_ctx_ready.swap(false, Ordering::Acquire) {
            return None;
        }
        EXEC_HANDOFFS.fetch_sub(1, Ordering::Relaxed);
        Some((
            task.exec_entry,
            task.exec_user_sp,
            task.exec_sstatus,
            task.exec_satp,
            task.exec_old_pt,
        ))
    }
}

/// Boost a task's priority by TID (for priority inheritance).
/// Only boosts if `new_prio` is higher (lower number) than current priority.
///
/// Counted, like the lease path. This is safe only because PiMutex's protocol
/// is edge-triggered: each waiter donates at most once per acquisition and
/// `PiMutex::release()` issues exactly one restore per donation. If anyone
/// reintroduces re-assertion, the counter drifts upward without bound and the
/// owner never returns to base priority.
///
/// Wave 9: the same locked protocol as the other donors
/// (`donation::boost_locked`, see `TaskDonation`), so the two sources share
/// one lock as well as one counter, and a Ready owner is re-bucketed at its
/// new priority instead of staying in the bucket of the old one.
pub fn pi_boost_task(tid: u32, new_prio: u32) {
    boost_ready_task(tid, new_prio);
}

/// Restore a task's original priority by TID (after PI mutex release).
/// Uses `base_priority` from the task struct instead of the parameter for
/// robustness. Symmetric with [`pi_boost_task`]: one donation leaves, and the
/// base comes back only when the LAST one has — shared with the lease and
/// proxy donors through `donation_count`.
pub fn pi_restore_task(tid: u32, _orig_prio: u32) {
    restore_ready_task(tid);
}

/// One donation lock per task slot (wave 9). Serialises every boost and
/// restore of that slot's `donation_count` + `priority` pair — see
/// `donation::DonationCell` for the race it closes. Taken with interrupts
/// masked and held across `cpu_remove_anywhere`/`cpu_enqueue_locked`, so the
/// lock order is: `PiMutex::pi_state` → donation lock → `CPU_LOCKS`. Nothing
/// takes a donation lock while holding a CPU lock.
static DONATION_LOCKS: [AtomicBool; MAX_TASKS] = {
    const F: AtomicBool = AtomicBool::new(false);
    [F; MAX_TASKS]
};

/// Donation target: task slot `idx`, through its donation lock.
struct TaskDonation {
    idx: usize,
    irq: core::cell::Cell<Option<azos_arch::InterruptState>>,
}

impl TaskDonation {
    fn new(idx: usize) -> Self {
        TaskDonation { idx, irq: core::cell::Cell::new(None) }
    }
}

impl crate::donation::DonationCell for TaskDonation {
    fn lock(&self) {
        let prev = azos_arch::ARCH.disable_all();
        while DONATION_LOCKS[self.idx]
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
        self.irq.set(Some(prev));
    }
    fn unlock(&self) {
        DONATION_LOCKS[self.idx].store(false, Ordering::Release);
        if let Some(prev) = self.irq.take() {
            azos_arch::ARCH.restore(prev);
        }
    }
    fn count(&self) -> u32 {
        unsafe { task_mut(self.idx).donation_count.load(Ordering::Relaxed) }
    }
    fn set_count(&self, c: u32) {
        unsafe { task_mut(self.idx).donation_count.store(c, Ordering::Relaxed) }
    }
    fn prio(&self) -> u32 {
        unsafe { task_mut(self.idx).priority.load(Ordering::Relaxed) }
    }
    /// The base, held up by the wait graph's boost (`classes::pi_floor`, a
    /// constant `u32::MAX` without `WAIT_GRAPH`).
    fn base(&self) -> u32 {
        let b = unsafe { task_mut(self.idx).base_priority.load(Ordering::Relaxed) };
        b.min(classes::pi_floor(self.idx))
    }
    fn apply_prio(&self, p: u32) {
        unsafe {
            let idx = self.idx;
            // Only a Ready task sits in a run queue keyed by priority, so only
            // that case needs the remove/re-enqueue dance. Blocked and Running
            // tasks still need the field written: a blocked lessee must wake
            // at the donated priority, otherwise donation silently does
            // nothing in the most common case (lessee waiting on I/O).
            let removed_from = if task_mut(idx).state() == TaskState::Ready {
                cpu_remove_anywhere(idx)
            } else {
                None
            };
            task_mut(idx).priority.store(p, Ordering::Relaxed);
            hist_reaccount(idx);
            if let Some(q) = removed_from {
                // Back onto the SAME queue it came off, under that queue's
                // lock — `cpu_enqueue_locked` also wakes that hart, which is
                // what a donation is for.
                if !cpu_enqueue_locked(q, idx) {
                    SCHED_ENQ_REFUSED.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    }
}

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
/// obligation. And the callers hold no other lock: `lease.rs` drops its
/// `LEASES` guard before the priority-inheritance block, which is what keeps
/// this from becoming the first edge in a lock graph that has none.
unsafe fn cpu_remove_anywhere(idx: usize) -> Option<usize> {
    for cpu in 0..ncpu() {
        let _g = CpuLockGuard::acquire(cpu);
        if cpu_remove(cpu, idx) {
            return Some(cpu);
        }
    }
    None
}

pub fn boost_ready_task(tid: u32, new_prio: u32) {
    // No `current_cpu_id()` here any more, and its absence is the fix: the
    // donor's hart was never the right queue to touch. See
    // `cpu_remove_anywhere`. Count, priority and re-bucketing all happen under
    // the target's donation lock (`donation::boost_locked`).
    if let Some(idx) = idx_for_tid(tid) {
        crate::donation::boost_locked(&TaskDonation::new(idx), new_prio);
    }
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
/// `fast_ipc_slot_ids` for why the identities, not the counts, are what decide
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
                // The low 6 bits of the handle are the slot index by the
                // encoding contract in crates/core/ipc/src/fast_ipc.rs
                // (FAST_IPC_SLOT_BITS = 6) — this diagnostic reports the seat
                // so it can be correlated with the slot table; duplicating
                // the mask here is display-only and cannot corrupt anything.
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

/// May `viewer` see `tid` in `/proc/tasks` and by `/proc/<tid>` (wave 12,
/// owner round 48)? `full`: the viewer holds the full-view grant (the caller
/// looks it up; this crate does not see capability tables). The relation is
/// [`stop_policy::may_see`] over the live parent links.
///
/// Under `proc-hidepid-canary` the filter is compiled out: every viewer sees
/// every task, and the gate rows that expect a foreign task to be hidden go
/// red.
pub fn task_visible_to(viewer: u32, tid: u32, full: bool) -> bool {
    if cfg!(feature = "proc-hidepid-canary") {
        return tid != 0;
    }
    // Wave 13: visibility is a process's. A thread sees what its process
    // sees (its group and the group's descendants), and is seen by whoever
    // sees its process.
    let v = crate::group::proc_tid(viewer);
    let t = crate::group::proc_tid(tid);
    stop_policy::may_see(v, t, full, parent_of_tid, stop_policy::MAX_ANCESTRY)
}

/// One task, as [`task_rows`] reports it (wave 12, `/proc/tasks`).
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

/// Wave 12 (`/proc/tasks`, the user shell's `ps`): the live task slots, in
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
/// not live. Wave 13 (DEBTS): `/proc/<tid>` used to snapshot all 96 rows
/// (3 KiB of stack) to print one.
pub fn task_row(tid: u32) -> Option<TaskRow> {
    let r = task_row_at(idx_for_tid(tid)?)?;
    if r.tid == tid { Some(r) } else { None }
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

/// Donate `donor`'s live priority to `target` for the span of a wait, when
/// [`crate::donation::donation_for`] allows it. `true` = a donation was made
/// and exactly one [`return_donation`]`(target)` is owed.
///
/// The one entry point both waiting donors use: lease priority inheritance
/// (`lease_wait_return`) and the user-driver proxy waiting on a ring-3
/// driver's reply. Both therefore share one rule and one counter
/// (`donation_count`), which is what lets them stack on the same target.
///
/// **The ring-3 floor (wave 9).** A ring-3 target (one with a user page table)
/// is never donated a priority more urgent than `RT_PRIORITY_THRESHOLD` (12),
/// the floor the topology gives every ring-3 row: a kernel real-time client
/// (say 8) waiting on a ring-3 driver lends it 12, not 8. The clamp is
/// counted ([`DONATIONS_FLOORED`]) and recorded once per target task through
/// the recorder the kernel installs ([`set_donation_floor_recorder`]).
///
/// A target that exits between the priority read and the boost is a no-op in
/// `boost_ready_task`, and its `return_donation` is a no-op too.
pub fn donate_priority(donor: u32, target: u32) -> bool {
    let floor = ring3_donation_floor(target);
    match crate::donation::donation_for(
        donor, task_priority(donor), target, task_priority(target), floor,
    ) {
        Some((prio, floored)) => {
            boost_ready_task(target, prio);
            LAST_DONATION.store(((target as u64) << 32) | prio as u64, Ordering::Relaxed);
            if floored {
                note_floored_donation(target);
            }
            true
        }
        None => false,
    }
}

/// The floor [`donate_priority`] applies to `target`: `RT_PRIORITY_THRESHOLD`
/// for a ring-3 task, 0 (none) for a kernel task. `donation-floor-canary`
/// removes it, so the proxy smoke sees the driver at the client's 8.
fn ring3_donation_floor(target: u32) -> u32 {
    if cfg!(feature = "donation-floor-canary") {
        return 0;
    }
    match idx_for_tid(target) {
        Some(i) if unsafe { task_ref(i).user_pt } != 0 => crate::task::RT_PRIORITY_THRESHOLD,
        _ => 0,
    }
}

/// The last donation [`donate_priority`] made: `target_tid << 32 | priority`.
/// Telemetry for the `proxy-pi-smoke` floor check, which reads the priority
/// the donation actually applied rather than sampling for it.
pub static LAST_DONATION: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Donations raised to the ring-3 floor, since boot. Telemetry; the
/// `proxy-pi-smoke` floor check reads it across one call.
pub static DONATIONS_FLOORED: AtomicU32 = AtomicU32::new(0);

/// Where a floored donation is recorded (the kernel installs a flight-recorder
/// writer: `SAFETY_TOPO_CLASS_REFUSED`, site `SITE_DONATION_FLOOR`). This
/// crate does not depend on the recorder, the arrangement `topo_sched` uses.
static DONATION_FLOOR_RECORDER: AtomicUsize = AtomicUsize::new(0);

/// The TID whose floored donation slot `i` last recorded: one record per
/// target task, not per donation — a kernel RT client calling a ring-3 driver
/// in a loop would otherwise write the recorder on every call.
static FLOOR_RECORDED_TID: [AtomicU32; MAX_TASKS] = [const { AtomicU32::new(0) }; MAX_TASKS];

/// Install the floored-donation recorder. Called once at boot.
pub fn set_donation_floor_recorder(f: fn(target_tid: u32)) {
    DONATION_FLOOR_RECORDER.store(f as usize, Ordering::Release);
}

fn note_floored_donation(target: u32) {
    DONATIONS_FLOORED.fetch_add(1, Ordering::Relaxed);
    let Some(i) = idx_for_tid(target) else { return };
    if FLOOR_RECORDED_TID[i].swap(target, Ordering::Relaxed) == target {
        return;
    }
    let f = DONATION_FLOOR_RECORDER.load(Ordering::Acquire);
    if f != 0 {
        // SAFETY: only ever stored from a `fn(u32)` in `set_donation_floor_recorder`.
        let f: fn(u32) = unsafe { core::mem::transmute::<usize, fn(u32)>(f) };
        f(target);
    }
}

/// Undo one donation made by [`donate_priority`].
pub fn return_donation(target: u32) {
    restore_ready_task(target);
}

/// Fast-IPC donation (wave 11 PIFAST): the CURRENT task, about to block on a
/// call to the task in slot `ti` (TID `target`, both from the caller's own
/// existence check), lends it its live priority for the span of the call.
/// `true` = a donation was made and exactly one [`return_donation`]`(target)`
/// is owed — by the reply, the caller's collect or withdrawal, or the exit
/// sweep (`azos_ipc::fast_ipc`).
///
/// Differs from [`donate_priority`] on purpose:
///  * the rule is [`crate::donation::donation_for_call`], against the
///    target's BASE priority (two callers of one server; see there);
///  * it runs on EVERY fast call, so the decision is `#[inline]` and takes no
///    TID lookup of its own: the donor is this hart's current task
///    (`syscall::dispatch` runs inside the caller's own trap) and the target
///    slot comes from the caller. The boost, only when one is due, is out of
///    line. Measured on `ipc-roundtrip` (no donation due, equal priorities).
///
/// Same counted boost, same ring-3 floor and floor recording as
/// [`donate_priority`], so it stacks with the lease and proxy donations. A
/// target that exits between the lookup and the boost: the same window
/// [`donate_priority`] has (`boost_ready_task` re-looks-up, this does not;
/// the slot's count is zeroed when it is reused).
#[inline]
pub fn donate_priority_for_call_at(ti: usize, target: u32) -> bool {
    let cpu = current_cpu_id();
    if cpu >= MAX_CPUS || ti >= MAX_TASKS {
        return false;
    }
    // SAFETY: `ti < MAX_TASKS` checked above; `cur` is bounds-checked.
    let (donor_tid, donor_prio, base, ring3) = unsafe {
        let cur = PER_CPU[cpu].current_idx.load(Ordering::Relaxed);
        if cur >= MAX_TASKS {
            return false;
        }
        let d = task_ref(cur);
        let t = task_ref(ti);
        if t.tid != target {
            return false;
        }
        (d.tid, d.priority.load(Ordering::Relaxed), t.base_priority.load(Ordering::Relaxed),
         t.user_pt != 0)
    };
    let floor = if ring3 && !cfg!(feature = "donation-floor-canary") {
        crate::task::RT_PRIORITY_THRESHOLD
    } else {
        0
    };
    match crate::donation::donation_for_call(donor_tid, Some(donor_prio), target, Some(base), floor) {
        Some((prio, floored)) => {
            donate_for_call_boost(ti, target, prio, floored);
            true
        }
        None => false,
    }
}

/// The boost half of [`donate_priority_for_call_at`], out of line so the
/// no-donation path carries none of its register saves.
#[inline(never)]
fn donate_for_call_boost(ti: usize, target: u32, prio: u32, floored: bool) {
    crate::donation::boost_locked(&TaskDonation::new(ti), prio);
    LAST_DONATION.store(((target as u64) << 32) | prio as u64, Ordering::Relaxed);
    if floored {
        note_floored_donation(target);
    }
}

/// Restore a (possibly ready) task's priority to `prio` and re-position it in
/// the ready queue if needed. Counterpart of [`boost_ready_task`] used to undo
/// an inherited boost (RFC-0031). Unlike [`pi_restore_task`] (field-only), this
/// re-buckets a task that is still sitting in the ready queue.
pub fn restore_ready_task(tid: u32) {
    // As in `boost_ready_task`: the donor's hart is not this task's queue.
    // Saturating count (an unbalanced restore must not wrap and pin the task
    // at a donated priority), base only when the LAST donor leaves, and the
    // whole of it under the target's donation lock — a boost can no longer
    // land between the count reaching 0 and the base being written.
    if let Some(idx) = idx_for_tid(tid) {
        crate::donation::restore_locked(&TaskDonation::new(idx), || {});
    }
}

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
#[cfg(not(feature = "no-mmu"))]
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
#[cfg(not(feature = "no-mmu"))]
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
#[cfg(not(feature = "no-mmu"))]
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
    let cpu = current_cpu_id();
    unsafe {
        // One load, because `set_current_task` already did this arithmetic at
        // the context switch that made this task current. Deriving the address
        // here instead cost a `MAX_TASKS` bounds check, the task stride (×1152 on riscv64)
        // and the `TASKS` base — 8 instructions on every syscall in the system,
        // to recompute a value that only changes when the running task does.
        let filter = PER_CPU[cpu].current_filter.load(Ordering::Relaxed);
        if filter == 0 {
            // RFC-0047: a Linux task's word is 0. `Linux` sends the call to
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

/// For a call whose filter word was 0 (RFC-0047): `None` when the current
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
/// call reaches (RFC-0047 P5, "seccomp after translation"). Never answers
/// [`crate::filter::FilterVerdict::Linux`].
pub fn current_native_verdict(num: u64) -> crate::filter::FilterVerdict {
    let Some(idx) = current_slot() else { return crate::filter::FilterVerdict::Allow };
    // SAFETY: the current task's own slot, its filter read in place.
    unsafe { (*core::ptr::addr_of!(TASKS[idx].syscall_filter)).verdict_for(num) }
}

/// Is the task in slot `idx` a Linux task (RFC-0047)? For the per-switch
/// state (`crate::fp`), with `idx < MAX_TASKS`.
pub(crate) fn slot_is_linux(idx: usize) -> bool {
    // SAFETY: a byte of a slot, written only at slot creation under
    // POOL_LOCK; a stale read names a task that is not switching here.
    !cfg!(feature = "linux-abi-tag-canary") && unsafe { TASKS[idx].abi } == crate::task::ABI_LINUX
}

/// Is the current task a Linux task (RFC-0047)?
pub fn current_is_linux() -> bool {
    azos_limits::LINUX_ABI && current_slot().is_some_and(slot_is_linux)
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
    let cpu = current_cpu_id();
    unsafe {
        let idx = PER_CPU[cpu].current_idx.load(Ordering::Relaxed);
        if idx >= MAX_TASKS { return false; }
        TASKS[idx].syscall_filter.enabled
    }
}

pub fn current_syscall_filter() -> SyscallFilter {
    let cpu = current_cpu_id();
    unsafe {
        let idx = PER_CPU[cpu].current_idx.load(Ordering::Relaxed);
        if idx == usize::MAX { return SyscallFilter::disabled(); }
        TASKS[idx].syscall_filter
    }
}

/// Set the syscall filter for the current task.
pub fn set_current_syscall_filter(filter: SyscallFilter) {
    let cpu = current_cpu_id();
    unsafe {
        let idx = PER_CPU[cpu].current_idx.load(Ordering::Relaxed);
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

// ---- AQ0: Block / Wake API (used by wait.rs) ----

/// Stable one-byte tag for a [`WaitReason`], for packing into the K-C29
/// last-offender word. Only the variant matters there — the payload
/// (handle, deadline, TID) would not fit and is not what identifies the
/// offending call site.
#[inline]
fn wait_reason_tag(r: WaitReason) -> u8 {
    match r {
        WaitReason::None => 0,
        WaitReason::Irq(_) => 1,
        WaitReason::Channel(_) => 2,
        WaitReason::Ring(_) => 3,
        WaitReason::Timer(_) => 4,
        WaitReason::Port(_) => 5,
        WaitReason::WaitQueue => 6,
        // 7 was `Rpc`, removed with the synchronous RPC path (RFC-0040 gap 1):
        // not reused, so a recorded tag keeps its meaning.
        WaitReason::FastIpcServer(_) => 8,
        WaitReason::FastIpcClient(_) => 9,
        WaitReason::LeaseAccept(_, _) => 10,
    }
}

/// Block the current task on `cpu` with the given reason.
/// Moves it from Running → Blocked, then reschedules.
pub fn block_current(cpu: usize, reason: WaitReason) {
    if cpu >= MAX_CPUS { return; }
    // Lockdep (Kconfig LOCKDEP, N1): every task sleep (timed, WaitQueue,
    // IPC) passes here; a SpinLock held, IRQs off or interrupt context is
    // reported with the lock's class and site. No instruction when off.
    azos_sync::lockdep::might_sleep("scheduler block");

    // K-C29: refuse to park a task that is inside a critical section.
    //
    // CHECKED FIRST, on purpose — before the `sstatus` write below, before
    // `context_saving` is set, before `wait_reason` is published, and before
    // the commit CAS. Every one of those is a step that makes this task
    // visible to wakers as "going to sleep"; a refusal has to happen while
    // none of it has been done, or the task is left half-parked.
    //
    // Refuse, do not defer, and do not switch. Parking a task that holds a
    // spinlock converts a priority-dependent hang into a certain one: nobody
    // can release the lock, and unlike a deferred tick there is no later
    // moment at which sleeping becomes the right answer.
    //
    // ── STEP-2 PREREQUISITE — the caller contract is NOT uniform ──
    //
    // Returning without blocking is the same outcome the `!committed`
    // (wake-already-stamped) arm below already produces, so it is not a new
    // shape of return. But the claim in that arm's comment — "every caller
    // re-checks its condition in a loop" — was checked against the callers and
    // is **only true of the path it names**:
    //
    //   * `lease.rs`'s `while !lease_is_returned(id) { wq_block_current(); }`
    //     re-checks. Correct under a refusal.
    //   * `dispatch.rs`'s `SYS_DRV_IRQ_WAIT` is a bare single `task_block`
    //     followed by `0`. Under a refusal it would report "your IRQ fired"
    //     when it did not.
    //   * the `WaitReason::Timer` sleeps in `main.rs` are bare calls inside an
    //     outer loop: a refusal turns one timed sleep into a hot spin for that
    //     iteration, not a correctness break.
    //
    // **This branch IS reachable, and the note that used to sit here saying it
    // was not is why that matters.** It read "UNREACHABLE today — nothing
    // takes a `PreemptGuard` … before step 2 makes `SpinLockGuard` carry one".
    // Step 2 landed: `crates/core/sync/src/spinlock.rs:64` takes
    // `critical_section()` and `:66` stores it in the guard, so
    // `preempt::disabled()` is TRUE for the whole of any `SpinLock` hold.
    //
    // What that means for a caller: **blocking while holding a spinlock does
    // not block.** It returns here, having neither slept nor published any
    // state, and the caller sees an ordinary wake. A loop that re-tests a
    // condition only another task can change then spins to its bound and
    // reports failure — which is exactly what RFC-0040 gap 2 stage 3 (a direct
    // hand-off from a client holding `FAST_IPC` to a waiting server) would do
    // if it blocked with that lock held. Read this before writing that.
    //
    // `SYS_DRV_IRQ_WAIT` still needs the re-check loop the old note asked for,
    // or this refusal needs a distinguishable status.
    if azos_sync::preempt::disabled() {
        let depth = azos_sync::preempt::depth();
        preempt_audit::bump(&preempt_audit::BLOCK_WHILE_ATOMIC);
        // SAFETY: `cpu < MAX_CPUS` was just checked; `current_idx` is either
        // `usize::MAX` or a valid pool index, and only read here.
        let tid = unsafe {
            let idx = PER_CPU[cpu].current_idx.load(Ordering::Relaxed);
            if idx < MAX_TASKS { task_ref(idx).tid } else { 0 }
        };
        preempt_audit::record_block_offender(tid, depth, wait_reason_tag(reason));
        // Rate-limited: a hart refusing on every IPC round trip must not turn
        // the UART into the bottleneck. The counter keeps rising after the
        // budget runs out.
        let n = preempt_audit::BLOCK_WHILE_ATOMIC.load(Ordering::Relaxed);
        if n <= preempt_audit::BLOCK_LOG_BUDGET {
            azos_drv_sys::kprintln!(
                "[K-C29] block_current refused: tid={} depth={} reason_tag={} (#{}/{})",
                tid, depth, wait_reason_tag(reason), n,
                preempt_audit::BLOCK_LOG_BUDGET
            );
        }
        return;
    }

    // K-A12: do_schedule() is not safe to reenter — a timer tick firing on
    // this hart mid-call would race this call's own queue/PER_CPU mutations
    // (the outer call's dequeued `next_idx` and this task's Blocked state get
    // corrupted by a nested dispatch). This is the exact hazard task_yield()
    // already guards against; block_current() was missing the same guard.
    // Disable SIE before do_schedule() and restore it only after it returns
    // (i.e. once this task has been rescheduled back in) — same pattern as
    // task_yield(), and both the "have a task to block" and early-return
    // paths below converge on the same restore.
    let sstatus = azos_arch::ARCH.disable_all();
    // This hart, read with interrupts off: the caller's `cpu` may predate a
    // block that moved the task (see `do_schedule`).
    let cpu = current_cpu_id();
    unsafe {
        let idx = PER_CPU[cpu].current_idx.load(Ordering::Relaxed);
        // `< MAX_TASKS`, not `!= usize::MAX`: the scheduler only ever writes
        // in-range indices or MAX here, so the two are equivalent — but only
        // this form lets LLVM prove the `TASKS[idx]` index below in range.
        // With the sentinel comparison it emitted a `panic_bounds_check`
        // call, i.e. a board reset under `panic = "abort"` sitting on the
        // block path. Same provable-guard trick as `lease_tick`'s
        // `count < MAX_LEASES`.
        if idx < MAX_TASKS {
            let task = task_mut(idx);

            // Mark in-transit BEFORE the state change that makes this task
            // visible to wakers — closes the race where a waker sees Blocked
            // and redispatches before context_switch.S has actually saved
            // this task's registers (the save tail in context_switch.S clears
            // it).
            task.context_saving.store(true, Ordering::Relaxed);

            // K-C17: publish the REASON before the state. A waker only reads
            // `wait_reason` after observing `Blocked` with Acquire, and
            // `Blocked` is only ever published by the Release CAS inside
            // `commit_blocked_or_consume_wake` below — that pairing is what
            // guarantees the reason a waker reads is this one, not the stale
            // value from when we were running (the mismatch path drops the
            // wake without stamping, so a torn read here was a permanent
            // sleep). The old explicit fence pair moved into the CAS
            // orderings.
            task.wait_reason = reason;

            // K-C9 + K-C19 — one conditional CAS replaces "consume the stamp,
            // then mark Blocked" (two independently-ordered cells, a measured
            // ~1-in-3 hang):
            //
            //  * If a wake is already stamped, the commit fails, the stamp is
            //    consumed, and we skip blocking entirely — the condition this
            //    caller is about to sleep on is already satisfied, and every
            //    caller re-checks its condition in a loop, so returning is
            //    exactly "wait() returned because we were woken".
            //
            //    That last clause used to say "every caller", and it was not
            //    true. An enumeration of all 22 production call sites (2026-09-04)
            //    found three shapes, not one: eighteen loop on a real condition
            //    or on a deadline and are safe; two re-poll but cannot tell a
            //    spurious wake from an empty queue, so they answer -1 after a
            //    bounded number of turns; and `SYS_DRV_IRQ_WAIT` had nothing to
            //    re-test at all and returned 0 -- "your interrupt fired" -- to a
            //    driver whose interrupt had not. It now answers -EAGAIN, which
            //    is the only shape that works when the caller has no condition
            //    to check.
            //
            //    Two of the loops were added for the same reason: `SYS_IPC_CALL`
            //    and `SYS_IPC_LEASE_ACCEPT` blocked once and answered -1, while
            //    their wakers stamp `wake_pending` -- so a caller that was
            //    merely early already got a failure, before K-C29 existed.
            //  * A waker can no longer stamp *after* we passed the check: its
            //    stamp CAS requires `state != Blocked`, our commit CAS
            //    requires the stamp clear. Whoever loses the CAS retries
            //    against the other's result. The double-check handshake that
            //    was tried and REVERTED (it could enqueue a task that was
            //    still "current", freezing boot) is unnecessary under this
            //    scheme — see `sched_word` in task.rs for the full history.
            #[allow(unused_variables)]
            let committed = crate::task::sched_word::commit_blocked_or_consume_wake(&task.state_word);
            // Placement histogram, on BOTH outcomes: the commit may have
            // taken Running -> Blocked, or consumed a stamp on a task still
            // `Blocked` from an unswitched block (-> Running), or changed
            // nothing (re-entry while already `Blocked`). The key tells.
            hist_reaccount(idx);
            // Timer sleepers are armed only once `Blocked` is committed —
            // see `timer_sleepers` for why never before.
            #[cfg(feature = "sched-timer-heap")]
            if committed {
                if let WaitReason::Timer(deadline) = reason {
                    timer_sleepers::arm(idx, deadline);
                }
            }
            // Wave 11 ONESHOT (RFC-0052 §4.5): a timer sleeper moves this
            // hart's comparator when its deadline is earlier than what is
            // programmed. Without it a hart that switches to another busy
            // task kept the next scheduler tick programmed, and the deadline
            // was seen up to one period late (the `lat:` rows' worst case).
            // After the commit, for the same reason as the heap arm above: a
            // sleeper the interrupt can find. Interrupts are masked here, so
            // the interrupt this programs runs once `do_schedule` has
            // switched away. `oneshot-canary` compiles it out (gate canary).
            // `u64::MAX` is "no deadline" (notify waits, `NOTIFY_FOREVER`):
            // never earlier than anything, so it skips even the record read.
            #[cfg(not(feature = "oneshot-canary"))]
            if committed {
                if let WaitReason::Timer(deadline) = reason {
                    if deadline != u64::MAX {
                        azos_drv_sys::timebase::arm_if_earlier(deadline);
                    }
                }
            }
            if !committed {
                #[cfg(feature = "ipc-census")]
                unswitched::bump(&unswitched::BLOCK_SKIPPED);
                // We never became Blocked, so no waker can be dispatching
                // us — undo the in-transit mark and return to the caller's
                // condition re-check.
                task.context_saving.store(false, Ordering::Relaxed);
                azos_arch::ARCH.restore(sstatus);
                return;
            }

            // Don't re-enqueue — blocked tasks leave the ready queue.
            do_schedule(SwitchReason::Voluntary);
            // Returns here when woken and rescheduled.
            #[cfg(feature = "ipc-census")]
            unswitched::bump(&unswitched::BLOCK_SLEPT);
        }
    }
    azos_arch::ARCH.restore(sstatus);
}

/// Try to wake task `idx` if it matches the predicate.
/// Called from wait.rs wake_matching() — reachable from IRQ context (the
/// timer ISR and external-IRQ path in `kernel/src/trap/interrupt.rs` call
/// `wake_expired_timers()` / `wake_by_irq()`, which fan out here), and the
/// target CPU is frequently *not* the calling CPU (affinity-pinned task, or
/// the `0` fallback for unpinned tasks). Goes through `cpu_enqueue_locked` —
/// IRQ-safe and takes `CPU_LOCKS[target_cpu]`, so it can't race the target
/// CPU's own `do_schedule()`.
/// Which CPU should a task being woken be enqueued on?
///
/// **WHY this is not just `0` (K-C14).** All three wake paths
/// (`try_wake_task`, `wq_wake_by_tid`, `wake_task_by_tid`) used to send every
/// unpinned task to **CPU 0**, unconditionally. `find_least_loaded_cpu()` had
/// existed in this file all along and none of them called it.
///
/// The result is not "slightly unbalanced": it is starvation with a
/// reproducible victim. `cpu_dequeue` picks by `ready_bitmap.trailing_zeros()`,
/// i.e. strictly by priority, and on this kernel's default boot CPU 0 is where
/// the RT tasks live (`rt-motor` and `flight-ctrl` are both created with
/// affinity to hart 0). So every unpinned task that ever blocks and is woken —
/// which is every userspace task doing IPC, I/O or sleeping — is permanently
/// relocated behind two real-time tasks on a single hart, no matter how idle
/// the other three are.
///
/// Measured: a ring-3 fast-IPC round trip (`userspace/tests/ipctest` phase A, 8
/// forked clients under `-smp 4`) completes exactly as many exchanges as there
/// were clients still sitting on their post-fork CPUs — four — and then wedges
/// forever. The kernel stays healthy throughout, RT tasks keep meeting their
/// deadlines, and nothing reports an error: the clients are `Ready`, correctly
/// enqueued, and simply never picked. That is why this reads as a lost wakeup
/// and is not one.
///
/// Pinned tasks (`cpu_affinity >= 0`) keep going exactly where they are
/// pinned; the operator asked for that.
///
/// `idx` is the waking task's own pool slot, so it does not score against its
/// own placement.
///
/// RFC-0051 E0: every wake-up placement goes through the `Placement` seam.
/// The selection is a `const` and `Legacy` is its one variant, so the `match`
/// has no discriminant to test and the code is what it was before the seam
/// existed (the arm holds the body in place: a helper function per variant
/// moved LLVM's inlining of `find_best_cpu` and changed seven functions).
#[inline]
unsafe fn wake_target_cpu(idx: usize, task: &Task) -> usize {
    match azos_energy::seams::PLACEMENT {
        azos_energy::Placement::Legacy => if task.cpu_affinity >= 0 {
            (task.cpu_affinity as usize).min(ncpu() - 1)
        } else {
            // K-C12: "emptiest hart" is not the same question as "hart that will
            // dispatch this task". A woken task parked behind permanently
            // higher-priority work is a lost task, not a slow one — the same
            // defect K-C14 half-fixed by moving off the hardcoded CPU 0.
            // Approximate and unlocked, like the metric it replaces: a stale
            // sample costs one suboptimal placement, never correctness.
            let prio = task.priority.load(Ordering::Relaxed);
            let cpu = find_best_cpu(prio, idx).min(ncpu() - 1);
            // Kconfig DECISION_RECORDS: a move off the task's last CPU is
            // explained (the rejected alternative is staying). Off: nothing.
            if azos_decision::ON {
                note_wake_move(task, cpu, prio);
            }
            cpu
        },
    }
}

/// The wake-placement record of [`wake_target_cpu`]: only a migration.
#[inline(never)]
fn note_wake_move(task: &Task, cpu: usize, prio: u32) {
    let last = task.context.tp as usize;
    if last != cpu && last < ncpu() {
        azos_decision::record(
            azos_decision::Rule::WakePlacement,
            azos_decision::Verdict::Place,
            task.tid,
            [cpu as u64, last as u64, prio as u64],
        );
    }
}

/// The IPC-affinity exception to `find_best_cpu`'s placement
/// (`sched-ipc-affinity`; without it this is [`wake_target_cpu`]).
///
/// A synchronous IPC hand-off wakes a task whose waker blocks on the answer
/// right after: the call wakes the server and the client waits for the
/// reply; the reply wakes the client and the server goes back to accept.
/// The waker's hart is about to have nothing of the waker's to run, so the
/// woken task goes THERE — the seL4-style co-location that keeps a call/
/// reply pair on one hart (no cross-hart enqueue, no IPI, warm caches) —
/// instead of wherever `find_best_cpu` ranks best.
///
/// Liveness still outranks affinity, the same rule `find_best_cpu` keeps:
/// co-location is taken only if no competing resident of this hart other
/// than the woken task and the waker outranks the woken task (the waker is
/// left out because it is about to block; `pick_cpu_by_load`'s first two
/// keys would be zero). Otherwise, and for a pinned task, the ordinary
/// placement decides.
///
/// RFC-0051 E0: through the `Placement` seam, like [`wake_target_cpu`]; the
/// co-location exception is part of `Legacy`. The irrefutable `let` is the
/// seam: it compiles only while `Legacy` is the one variant, so the stage
/// that adds `EnergyAware` (E5) must decide this path explicitly.
#[inline]
unsafe fn ipc_wake_target_cpu(idx: usize, task: &Task) -> usize {
    let azos_energy::Placement::Legacy = azos_energy::seams::PLACEMENT;
    #[cfg(feature = "sched-ipc-affinity")]
    if task.cpu_affinity < 0 {
        let num_online = NUM_ONLINE_CPUS.load(Ordering::Acquire).min(MAX_CPUS);
        if num_online > 1 {
            let here = current_cpu_id();
            if here < num_online {
                let waker = PER_CPU[here].current_idx.load(Ordering::Relaxed);
                if !outranked_on(here, task.priority.load(Ordering::Relaxed), idx, waker) {
                    return here;
                }
            }
        }
    }
    wake_target_cpu(idx, task)
}

/// Whether any competing resident of `cpu`, other than slots `a` and `b`,
/// outranks a task of priority `prio` (strictly lower bucket) — the
/// `blocking` key of `find_best_cpu`'s score for that one CPU.
#[cfg(all(feature = "sched-ipc-affinity", feature = "sched-o1-placement"))]
#[inline]
unsafe fn outranked_on(cpu: usize, prio: u32, a: usize, b: usize) -> bool {
    let key_of = |s: usize| if s < MAX_TASKS {
        HIST_KEY[s].load(Ordering::Relaxed)
    } else {
        resident_histogram::key::NONE
    };
    let (ka, kb) = (key_of(a), if b == a { resident_histogram::key::NONE } else { key_of(b) });
    RESIDENT_HIST
        .load_excluding(
            cpu,
            prio_bucket(prio),
            crate::task::RT_PRIORITY_THRESHOLD as usize,
            &[ka, kb],
        )
        .blocking
        > 0
}

/// Scan form of the above: stops at the first outranking resident.
#[cfg(all(feature = "sched-ipc-affinity", not(feature = "sched-o1-placement")))]
#[inline]
unsafe fn outranked_on(cpu: usize, prio: u32, a: usize, b: usize) -> bool {
    let bucket = prio_bucket(prio);
    for i in 0..MAX_TASKS {
        if i == a || i == b || !TASK_VALID[i].load(Ordering::Relaxed) {
            continue;
        }
        let t = &*core::ptr::addr_of!(TASKS[i]);
        let home = if t.cpu_affinity >= 0 {
            (t.cpu_affinity as usize).min(ncpu() - 1)
        } else {
            (t.context.tp as usize).min(ncpu() - 1)
        };
        if home != cpu || !crate::task::resident_competes(t.state()) {
            continue;
        }
        if prio_bucket(t.priority.load(Ordering::Relaxed)) < bucket {
            return true;
        }
    }
    false
}

/// `ipc-census`: where IPC hand-off wakes were placed relative to the
/// waker's hart — the before/after evidence for the affinity exception
/// (the counters exist, and count, with or without `sched-ipc-affinity`).
/// Tallies print at powers of two.
#[cfg(feature = "ipc-census")]
pub mod ipc_placement {
    use core::sync::atomic::{AtomicU32, Ordering};
    pub static SAME_HART: AtomicU32 = AtomicU32::new(0);
    pub static OTHER_HART: AtomicU32 = AtomicU32::new(0);

    #[inline]
    pub(super) fn record(target_cpu: usize) {
        let same = target_cpu == crate::smp::current_cpu_id();
        let (s, o) = if same {
            (SAME_HART.fetch_add(1, Ordering::Relaxed) + 1, OTHER_HART.load(Ordering::Relaxed))
        } else {
            (SAME_HART.load(Ordering::Relaxed), OTHER_HART.fetch_add(1, Ordering::Relaxed) + 1)
        };
        let n = s.wrapping_add(o);
        if n >= 64 && n.is_power_of_two() {
            azos_drv_sys::kprintln!(
                "[SCHED] ipc-placement wakes={} same_hart={} other_hart={} affinity={}",
                n, s, o, cfg!(feature = "sched-ipc-affinity"),
            );
        }
    }
}

pub fn try_wake_task(idx: usize, pred: &dyn Fn(&WaitReason) -> bool) {
    use crate::task::sched_word::{wake_transition, WakeTransition};
    if idx >= MAX_TASKS { return; }
    unsafe {
        if !TASK_VALID[idx].load(Ordering::Relaxed) { return; }
        let task = task_mut(idx);
        // K-C19: the Blocked→Ready transition is a CAS — exactly one waker
        // can win it, and the Acquire/Release pairing inside guarantees the
        // `wait_reason` the predicate reads is the one the blocker published
        // (K-C17). `stamp_if_unblocked = false`: this is the broadcast path;
        // a sweep cannot tell its addressee from any other task about to
        // sleep, so it must never stamp (see wait.rs).
        // K-C24: `saved` gates dispatch — a Blocked task whose context is
        // not yet saved is still RUNNING (unswitched block) and must be
        // stamped, never enqueued. See `sched_word::wake_transition`.
        // `saved` read after `Blocked` is seen (inside the transition).
        let saved_seen = core::cell::Cell::new(true);
        let wt = wake_transition(&task.state_word, || pred(&task.wait_reason), false, || {
            let s = !task.context_saving.load(Ordering::Acquire);
            saved_seen.set(s);
            s
        });
        let saved = saved_seen.get();
        note_unsaved_stamp(idx, saved, wt);
        if wt != WakeTransition::Dispatched { return; }
        task.ready_site.store(
            crate::task::ready_site::WAKE | ((current_cpu_id() as u8) << 4),
            Ordering::Relaxed,
        );
        #[cfg(feature = "ipc-census")]
        wakelat::arm(idx);

        task.wait_reason = WaitReason::None;
        let target_cpu = wake_target_cpu(idx, task);
        // K-A11: keep the saved tp consistent with the CPU this task is enqueued
        // on (mirrors rebalance_from_offline_cpus): context_switch restores it
        // into the hardware tp and current_cpu_id() trusts it — a stale tp would
        // make the woken task corrupt another CPU's PER_CPU state.
        task.context.tp = target_cpu as CtxReg;
        hist_reaccount(idx);
        // U02-1 fix: mirror into the target's policy runqueue too — see
        // `wake_enqueue_locked`'s doc for why this used to be a bare
        // `cpu_enqueue_locked` and what that starved under APS.
        wake_enqueue_locked(target_cpu, idx);
    }
}


// ── WaitQueue support ───────────────────────────────────────────────────────

/// Block the current task on a WaitQueue.
/// Called via function pointer from `azos_sync::waitqueue`.
pub fn wq_block_current() {
    let cpu = current_cpu_id();
    block_current(cpu, WaitReason::WaitQueue);
}

/// Wake a blocked task by TID (used by WaitQueue/Completion).
/// Scans the task pool for a matching TID in WaitQueue-blocked state.
///
/// Reachable from IRQ context (timer ISR's lease-expiry path in
/// `kernel/src/trap/interrupt.rs` calls this directly) and, like `try_wake_task`, the
/// target CPU is often not the caller's own. See `try_wake_task` doc for the
/// locking rationale — same `cpu_enqueue_locked` wrapper, same guarantees.
pub fn wq_wake_by_tid(tid: u32) {
    use crate::task::sched_word::{wake_transition, WakeTransition};
    unsafe {
        if let Some(i) = idx_for_tid(tid) {
            let task = task_mut(i);
            // K-C9 + K-C19, in one transition:
            //  * Not Blocked yet (the caller — WaitQueue::wait() /
            //    lease_wait_return() — registered itself as wake-able and is
            //    mid-way to wq_block_current()): stamp the wake so its
            //    commit consumes it. The stamp is a CAS conditioned on
            //    `state != Blocked`, so it can no longer land *after* the
            //    task committed (the old lost-wake half-window).
            //  * Blocked on WaitQueue: dispatch (CAS Blocked→Ready; the
            //    Acquire pairing guarantees the reason read is the published
            //    one — K-C17).
            //  * Blocked on something else (e.g. a Timer): genuine mismatch,
            //    not the K-C9 race — no stamp, this is not our task anymore.
            // K-C24: see try_wake_task — an unsaved Blocked target is still
            // running and gets a stamp, not an enqueue.
            let saved_seen = core::cell::Cell::new(true);
            let wt = wake_transition(
                &task.state_word,
                || task.wait_reason == WaitReason::WaitQueue,
                true,
                || {
                    let s = !task.context_saving.load(Ordering::Acquire);
                    saved_seen.set(s);
                    s
                },
            );
            let saved = saved_seen.get();
            note_unsaved_stamp(i, saved, wt);
            if wt != WakeTransition::Dispatched { return; }
            task.ready_site.store(
                crate::task::ready_site::WAKE | ((current_cpu_id() as u8) << 4),
                Ordering::Relaxed,
            );
            #[cfg(feature = "ipc-census")]
            wakelat::arm(i);

            task.wait_reason = WaitReason::None;
            let target_cpu = wake_target_cpu(i, task);
            // K-A11: keep saved tp consistent with the enqueue CPU (see try_wake_task).
            task.context.tp = target_cpu as CtxReg;
            hist_reaccount(i);
            // U02-1 fix: see try_wake_task / wake_enqueue_locked.
            wake_enqueue_locked(target_cpu, i);
        }
    }
}

// ── K-C10: TID-directed wake with K-C9 pending-wake treatment ───────────────

/// Wake the task whose TID is `tid`, if its `wait_reason` satisfies `pred`.
///
/// Returns `true` **only** when this call actually transitioned the target
/// Blocked → Ready and enqueued it. The "stamped `wake_pending` instead"
/// path returns `false`: nothing was dispatched here, the target will
/// short-circuit its own `block_current()` instead. Callers must not read
/// `false` as "the wake was lost".
///
/// # K-C10: why this exists next to `try_wake_task`
///
/// `try_wake_task` selects tasks by a **predicate over `wait_reason`** and
/// bails out early when `state != Blocked`. That early exit is a lost-wakeup
/// bug for every wake whose target is a specific task that is still *on its
/// way* to `Blocked`. The concrete case is `SYS_IPC_FAST_CALL`
/// (`crates/core/syscall/src/dispatch.rs`), whose sequence is:
///
///   1. reserve a fast-IPC slot (now visible to the server),
///   2. `wake_fast_ipc_server(server_tid)`,
///   3. `task_block(WaitReason::FastIpcClient(slot))`.
///
/// On SMP the server can wake, accept and reply **between 2 and 3**. Its
/// `wake_fast_ipc_client*` then finds the client not yet `Blocked`,
/// `try_wake_task` returns early, and the client proceeds to block on a wake
/// that will never come again — sleeping forever while pinning the slot.
/// `SYS_IPC_FAST_ACCEPT` is symmetric.
///
/// # Why this cannot be fixed inside `try_wake_task`
///
/// Stamping `wake_pending` from `try_wake_task` when the state is not
/// `Blocked` is **wrong** and must never be "simplified" into that. A task
/// that has not blocked yet has `wait_reason == WaitReason::None`, so the
/// predicate cannot possibly identify it: `try_wake_task` is called in a
/// sweep over all `MAX_TASKS` slots, so it would have to stamp *every*
/// not-yet-blocked task in the pool. That would make unrelated tasks skip
/// their next, entirely unrelated block — trading a hang for silent
/// cross-task corruption, which is strictly worse.
///
/// This function is safe to stamp because it selects by **TID**, which is
/// known independently of `state` and `wait_reason`. That is the invariant
/// to preserve: never widen this to a state-dependent selector. It is also
/// exactly why the broadcast wakes (`wake_by_irq`, `wake_by_channel`,
/// `wake_by_ring`, `wake_by_port`, `wake_expired_timers`) must NOT be
/// routed through here — they have no addressee TID.
///
/// # `pred` is a *cross-check*, not the selector
///
/// For all current callers the predicate is redundant with the TID by
/// construction: `WaitReason::FastIpcServer(t)` carries the blocked task's
/// own TID, and `FastIpcClient(slot)` names a
/// slot whose owner is that TID. `pred` therefore only distinguishes "this
/// task is blocked where I expect" from "this task is blocked on something
/// else entirely", i.e. it detects a genuine mismatch.
///
/// # Genuine mismatch: `break` without stamping (same rule as `wq_wake_by_tid`)
///
/// If the task is `Blocked` but `pred` rejects its `wait_reason`, we leave
/// `wake_pending` untouched. Rationale specific to these callers: between
/// making itself wake-able and calling `task_block`, the target is running
/// a straight-line stretch of its own syscall — it can be preempted to
/// `Ready`, but it cannot become `Blocked` on a *different* reason, because
/// there is no other block in that stretch. So `Blocked` + non-matching
/// reason means this is not the task we are addressing at all (stale TID,
/// TID reuse after exit, or a confused/malicious replier). Stamping there
/// would make an unrelated task skip an unrelated block. Same conclusion as
/// `wq_wake_by_tid`, reached for the same reason.
///
/// # Spurious `wake_pending` — bounded, and audited per call site
///
/// If the target was simply running unrelated work, the stamp survives and
/// makes its *next* `block_current()` return immediately. `block_current`
/// documents this as acceptable because waiters re-check their condition.
/// The caveat:
///   * the fast-IPC syscall path re-checks **once** and returns `-1`
///     rather than looping, so a stale stamp surfaces as a bogus `-1` to
///     userspace, not as a hang or as corruption (see the K-C10 report).
///
/// No lease path reaches this function for a lessor: `lease_return`, the
/// task-exit sweep and the timer ISR's expiry drain wake a lessor with
/// `wq_wake_by_tid` alone (2026-09-14).
///
/// # First TID match wins — why that is safe
///
/// The scan stops at the first valid slot carrying `tid`. That is only
/// correct because TIDs are unique among valid slots: `NEXT_TID` increments
/// monotonically under `POOL_LOCK` and is never recycled (it wraps only after
/// 2^32 task creations, skipping 0). A `Zombie` slot does keep both
/// `TASK_VALID` and its TID until `do_schedule()` frees it — but its TID is
/// distinct from every live task's, so it can only be hit when the addressee
/// itself has exited. In that case it takes a `StampPending` on a slot that
/// is about to be released, which is inert: the old sweep also skipped
/// Zombies (`state != Blocked`), so this is not a regression.
///
/// # The selector invariant this depends on
///
/// Replacing "task blocked on reason R" with "task whose TID is `tid`" is
/// only sound while every `WaitReason` carrying a TID carries the *blocking
/// task's own* TID. Verified for the three construction sites in
/// `crates/core/syscall/src/dispatch.rs`: `FastIpcServer(server_tid)` and the
/// first field of `LeaseAccept(lessee, lessor)` are each
/// `current_task_tid()` of the task that is about to block (the second field
/// names another task and is matched, never used to select), and
/// `FastIpcClient(slot)`'s slot was reserved by
/// `fast_ipc_call(caller_tid, ..)` for that same caller. If a future caller
/// blocks a task on another task's TID, it must NOT be woken through here.
///
/// # IRQ context and reentrancy
///
/// Safe to call from IRQ context, like `try_wake_task` and `wq_wake_by_tid`
/// (the timer ISR's lease-expiry drain calls `wq_wake_by_tid`; since
/// 2026-09-14 it no longer calls `wake_fast_ipc_server`, and no IRQ-context
/// caller of this function remains). It is safe there for the same reasons —
/// it never calls `do_schedule()`, it
/// touches the ready queue only via `cpu_enqueue_locked` (IRQ-safe, takes
/// `CPU_LOCKS[target_cpu]`, so it cannot race the target CPU's own
/// `do_schedule()`), and the target CPU is routinely not the caller's. The
/// stamp is a lock-free CAS on the task's own `state_word` (K-C19), so it
/// cannot deadlock against an interrupted critical section.
///
/// The policy lives in `wait::wake_action()` — a pure function with the full
/// truth table next to it — and since K-C19 the *transition* that enforces it
/// is host-tested too: `task::sched_word::wake_transition` is free code over
/// an `AtomicU32`, exercised directly by `sched-wake-tests`. Everything below
/// is the addressee scan plus the dispatch bookkeeping around that verdict.
/// Diagnostic counters for [`wake_task_by_tid`]: `(dispatched, stamped,
/// mismatched, absent)`.
///
/// `mismatched` is the one that matters. That branch drops a wake **without**
/// stamping, on the grounds that a blocked task whose reason does not match
/// is no longer the task the waker meant. If it ever fires for a wake that
/// WAS meant for that task, the result is a permanent sleep — the signature
/// K-C17/K-C19 chased (reply deposited, client blocked, nothing ready). Both
/// are closed; the counter stays because a nonzero value here under a hang is
/// still the fastest way to tell "predicate wrong" from "wake never sent".
///
/// `absent` counts wakes addressed to a TID with no valid task at all.
pub fn wake_counters() -> (u32, u32, u32, u32, u32, u32, u32) {
    (
        WAKE_DISPATCHED.load(Ordering::Relaxed),
        WAKE_STAMPED.load(Ordering::Relaxed),
        WAKE_MISMATCHED.load(Ordering::Relaxed),
        WAKE_ABSENT.load(Ordering::Relaxed),
        WAKE_ENQ_REFUSED.load(Ordering::Relaxed),
        WAKE_LATE_DISPATCH.load(Ordering::Relaxed),
        SCHED_ENQ_REFUSED.load(Ordering::Relaxed),
    )
}

static WAKE_DISPATCHED: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
static WAKE_STAMPED: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
static WAKE_MISMATCHED: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
static WAKE_ABSENT: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
static WAKE_ENQ_REFUSED: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
static WAKE_LATE_DISPATCH: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// U02-1 fix. Counts every wake that `wake_enqueue_locked` mirrored into a
/// policy runqueue (i.e. every wake that happened while the APS backend was
/// active and actually got a task back onto the legacy ring). Before this
/// fix the count was definitionally zero forever — no wake path fed a
/// policy at all — so a nonzero reading is itself the proof the bug is
/// closed. `main.rs` (not this front's file) is expected to print this as
/// `[APS] wake-dispatch count=N` after a task has slept and woken under
/// `--features sched-aps` with the backend selected; see the diff handed
/// to its owner.
#[cfg(feature = "sched-aps")]
static APS_WAKE_DISPATCH: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// Read [`APS_WAKE_DISPATCH`]. Only exists in a `sched-aps` build — a
/// Legacy build has no policy runqueue for a wake to ever reach.
#[cfg(feature = "sched-aps")]
pub fn aps_wake_dispatch_count() -> u32 {
    APS_WAKE_DISPATCH.load(Ordering::Relaxed)
}
/// Enqueues refused at the two `do_schedule`/rebalance sites that historically
/// ignored `cpu_enqueue_locked`'s answer (K-C26 discriminator 2).
///
/// **WHY it is counted rather than handled.** Both sites set the task `Ready`
/// *before* enqueuing it, so a refusal leaves it `Ready` in no queue at all —
/// which is precisely the K-C26 terminal signature (a task Ready, unqueued and
/// current on no hart). Reading the code says it cannot happen: `Full` is
/// unreachable while the `queued` invariant holds and would log `[SCHED] BUG`,
/// and `AlreadyQueued` needs someone to have enqueued a task that is Running,
/// which no path does — `boost_ready_task` checks the state first.
///
/// That argument is exactly the kind K-C26 has already defeated twice. Until a
/// run with the real signature is captured, the honest move is to make the
/// silent case *audible*: if this counter is ever non-zero, discriminator 2 is
/// answered and the genesis is here. Zero cost — one relaxed increment on a
/// path that is supposed never to run.
static SCHED_ENQ_REFUSED: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// Diagnostic snapshot of what each hart is running right now: fills
/// `(tid, raw state_word, name)` per CPU (tid 0 = no current). Racy by
/// nature — reads without locks, display-only, same license as the rest of
/// the ipc-census family.
pub fn current_snapshot(out: &mut [(u32, u32, [u8; 8]); MAX_CPUS]) {
    unsafe {
        for cpu in 0..ncpu() {
            let idx = PER_CPU[cpu].current_idx.load(Ordering::Relaxed);
            out[cpu] = if idx < MAX_TASKS && TASK_VALID[idx].load(Ordering::Relaxed) {
                let t = task_ref(idx);
                let mut name = [0u8; 8];
                let src = t.name;
                let n = src.iter().position(|&b| b == 0).unwrap_or(src.len()).min(8);
                name[..n].copy_from_slice(&src[..n]);
                (t.tid, t.state_word.load(Ordering::Acquire), name)
            } else {
                (0, 0, [0u8; 8])
            };
        }
    }
}

/// K-C25 reaper: deliver wakes that were stamped onto a task which then
/// parked (see `sched_word::reap_orphaned_stamp` for the full mechanism and
/// the measured wedge). Walks the pool once; called from the timer tick right
/// after `wake_expired_timers`, which already pays the same O(MAX_TASKS) walk
/// every tick — this adds one atomic load per valid task in the common case.
///
/// `Blocked + WAKE_STAMP` with `context_saving == false` is unambiguously an
/// orphaned delivered wake: with the context saved the target cannot consume
/// the stamp itself (it is not executing), `do_schedule`'s switch-away sweep
/// already ran (that is how the context got saved), and `wake_transition`
/// never stamps a saved task — so the stamp can only have landed in the
/// window between the sweep's check and context_switch.S clearing the flag.
/// While the flag is still true the target may be executing an unswitched
/// block and its own `commit_blocked_or_consume_wake` owns the stamp — those
/// are skipped and, if they park, caught on a later tick.
///
/// The walk runs only when [`STAMP_PENDING`] was set (w14 RTMAX). Every
/// `Blocked + WAKE_STAMP` comes from `wake_transition`'s `!saved` arm, and
/// each of its three callers stores the flag right after, in
/// [`note_unsaved_stamp`]. A tick landing between a waker's stamp CAS and its
/// flag store skips that stamp; the store sets the flag and the next tick
/// reaps it: one tick later than an unconditional walk, the same window
/// `sched-reap-event` has between its CAS and its mark. With no stamp
/// anywhere, the tick pays one swap instead of the 64-slot walk.
///
/// Recovery counts as `late_dispatch` in [`wake_counters`] — the counter has
/// been reserved (declared, read, never incremented) since K-C19 for exactly
/// this: a wake delivered later than its waker intended, by a third party.
pub fn reap_stamped_sleepers() {
    // Taken before the walk: a stamp made after this swap sets it again, and
    // one made before is seen by the walk (Release in the waker, AcqRel here).
    let _pending = STAMP_PENDING.swap(false, Ordering::AcqRel);
    // w14 RTMAX: no stamp was flagged since the last pass, so there is
    // nothing to reap; see the doc above for the one-tick window.
    #[cfg(not(feature = "sched-reap-event"))]
    if _pending {
        reap_sweep();
    }
    #[cfg(feature = "sched-reap-event")]
    {
        reap_pending::reap_marked();
        if reap_pending::any() {
            STAMP_PENDING.store(true, Ordering::Release);
        }
    }
    #[cfg(all(feature = "sched-o1-placement", feature = "ipc-census"))]
    hist_check::audit_tick(azos_drv_sys::timebase::now());
}

/// The walk of [`reap_stamped_sleepers`], out of line so the tick's common
/// case (nothing flagged) does not pay its register saves.
#[cfg(not(feature = "sched-reap-event"))]
#[inline(never)]
fn reap_sweep() {
    for i in 0..MAX_TASKS {
        // SAFETY: as `reap_one`'s callers always were: the tick ISR.
        if unsafe { reap_one(i) } == Reap::Again {
            STAMP_PENDING.store(true, Ordering::Release);
        }
    }
}

/// The safety net behind the tick's flag gate (owner decision, w14): a full
/// K-C25 walk run by the idle task, never by the tick, so a stamp whose waker
/// forgot `note_unsaved_stamp` is still delivered once the hart has nothing
/// else to do, and the tick never pays the walk.
///
/// * **Skip:** one load. `sched_word::REAPABLE_STAMPS` counts every
///   `Blocked + WAKE_STAMP` made (inside `wake_transition`, so a caller cannot
///   forget it); unchanged since the last complete walk means nothing new to
///   find. With `STAMP_PENDING` set the tick's walk owns the stamps, and idle
///   leaves them to it.
/// * **Same rules as the tick:** each `reap_one` runs with this hart's
///   interrupts masked, as in the ISR, so the tick's walk on this hart cannot
///   interleave with a slot here; walks on other harts already race each other
///   today and are settled by `reap_orphaned_stamp`'s CAS. Interrupts open
///   between slots, so a wake for a real task preempts the walk (the masked
///   window is one slot, not 64).
/// * **Bounded:** at most `MAX_TASKS` slots, once per change of the count. A
///   slot still switching away (`Reap::Again`) leaves the count unseen, so the
///   next idle pass looks again.
///
/// Returns true when it made a task ready: the idle loop must yield before
/// `wfi`. A hart that is never idle never runs this; another hart's idle does
/// (the walk covers every slot).
pub fn reap_idle_sweep() -> bool {
    let seen = crate::task::sched_word::reapable_stamps();
    if seen == IDLE_SWEPT.load(Ordering::Relaxed) || STAMP_PENDING.load(Ordering::Acquire) {
        return false;
    }
    reap_idle_walk(seen)
}

/// Last `REAPABLE_STAMPS` value a complete idle walk covered.
static IDLE_SWEPT: AtomicU32 = AtomicU32::new(0);

#[inline(never)]
fn reap_idle_walk(seen: u32) -> bool {
    let mut again = false;
    let mut reaped = false;
    for i in 0..MAX_TASKS {
        // Unmasked look first (reap_one's own first test, read-only): most
        // slots end here, and only a stamped one pays the masked window. A
        // stamp made after this look moves the count past `seen`, so the
        // next idle pass walks again.
        if !looks_reapable(i) {
            continue;
        }
        let s = azos_arch::ARCH.disable_all();
        // SAFETY: interrupts masked on this hart, as in the tick ISR.
        let r = unsafe { reap_one(i) };
        azos_arch::ARCH.restore(s);
        match r {
            Reap::Done => {}
            Reap::Again => again = true,
            Reap::Reaped => {
                reaped = true;
                #[cfg(feature = "ipc-census")]
                if REAP_IDLE.fetch_add(1, Ordering::Relaxed) == 0 {
                    azos_drv_sys::kprintln!("[SCHED] REAP_IDLE first: slot={}", i);
                }
            }
        }
    }
    if !again {
        IDLE_SWEPT.store(seen, Ordering::Relaxed);
    }
    reaped
}

/// `Blocked + WAKE_STAMP` on a valid slot: what `reap_one` acts on.
#[inline(always)]
fn looks_reapable(i: usize) -> bool {
    use crate::task::sched_word::{state_of, WAKE_STAMP};
    // SAFETY: atomic loads of the slot's valid flag and state word, the same
    // reads `reap_one` starts with.
    unsafe {
        if !TASK_VALID[i].load(Ordering::Relaxed) {
            return false;
        }
        let w = task_ref(i).state_word.load(Ordering::Acquire);
        w & WAKE_STAMP != 0 && state_of(w) == TaskState::Blocked
    }
}

/// `ipc-census`: wakes delivered by [`reap_idle_sweep`]. Each is a stamp no
/// flagged tick walk had reaped by the time its hart went idle: a stamp site
/// that forgets the flag shows here on every boot that reaches it. A waker
/// caught between its stamp CAS and its flag store also lands here (the
/// window `sched-reap-event`'s `UNMARKED` has).
#[cfg(feature = "ipc-census")]
pub static REAP_IDLE: AtomicU32 = AtomicU32::new(0);

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
mod reap_pending {
    use super::{reap_one, Reap, MAX_TASKS, SLOT_WORDS};
    use core::sync::atomic::{AtomicU64, Ordering};

    static PENDING: [AtomicU64; SLOT_WORDS] = [const { AtomicU64::new(0) }; SLOT_WORDS];

    #[inline]
    pub(super) fn mark(idx: usize) {
        if let Some(w) = PENDING.get(idx / 64) {
            w.fetch_or(1u64 << (idx % 64), Ordering::Release);
        }
    }

    /// Whether `idx` is marked (census cross-check only).
    #[cfg(feature = "ipc-census")]
    fn marked(idx: usize) -> bool {
        PENDING.get(idx / 64).is_some_and(|w| w.load(Ordering::Acquire) & (1u64 << (idx % 64)) != 0)
    }

    /// Whether any slot is still marked (a stamp `reap_one` said to retry).
    pub(super) fn any() -> bool {
        PENDING.iter().any(|w| w.load(Ordering::Acquire) != 0)
    }

    pub(super) fn reap_marked() {
        for (wi, word) in PENDING.iter().enumerate() {
            let mut bits = word.swap(0, Ordering::Acquire);
            while bits != 0 {
                let i = wi * 64 + bits.trailing_zeros() as usize;
                bits &= bits - 1;
                if i >= MAX_TASKS {
                    continue;
                }
                // SAFETY: the tick ISR, as for the sweep.
                match unsafe { reap_one(i) } {
                    Reap::Again => mark(i),
                    Reap::Done => {}
                    Reap::Reaped => {
                        #[cfg(feature = "ipc-census")]
                        MARKED_REAPED.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        }
        #[cfg(feature = "ipc-census")]
        census_sweep();
    }

    #[cfg(feature = "ipc-census")]
    pub static UNMARKED: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
    #[cfg(feature = "ipc-census")]
    pub static MARKED_REAPED: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
    #[cfg(feature = "ipc-census")]
    static PASSES: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

    /// What the sweep would still do after the marked pass: a slot it reaps
    /// here that carried no mark is a stamp site `note_unsaved_stamp` missed.
    #[cfg(feature = "ipc-census")]
    fn census_sweep() {
        use crate::task::sched_word::{state_of, WAKE_STAMP};
        let n = PASSES.fetch_add(1, Ordering::Relaxed).wrapping_add(1);
        if n >= 1024 && n.is_power_of_two() {
            azos_drv_sys::kprintln!(
                "[SCHED] reap-check ticks={} marked_reaped={} unmarked={}",
                n, MARKED_REAPED.load(Ordering::Relaxed), UNMARKED.load(Ordering::Relaxed),
            );
        }
        for i in 0..MAX_TASKS {
            let reapable = unsafe {
                let t = &*core::ptr::addr_of!(super::TASKS[i]);
                let w = t.state_word.load(Ordering::Acquire);
                super::TASK_VALID[i].load(Ordering::Relaxed)
                    && w & WAKE_STAMP != 0
                    && state_of(w) == super::TaskState::Blocked
            };
            if !reapable || marked(i) {
                continue;
            }
            // SAFETY: the tick ISR.
            match unsafe { reap_one(i) } {
                // Unmarked but not reapable yet: most likely a waker between
                // its stamp CAS and its mark. Leave it to that mark.
                Reap::Again | Reap::Done => {}
                Reap::Reaped => {
                    if UNMARKED.fetch_add(1, Ordering::Relaxed) == 0 {
                        azos_drv_sys::kprintln!("[SCHED] REAP_UNMARKED first: slot={}", i);
                    }
                }
            }
        }
    }
}

/// `sched-reap-event`: mark `idx` for the reaper if this wake left a stamp
/// on a target that was still switching away. Compiles to nothing without
/// the feature.
#[inline(always)]
#[allow(unused_variables)]
fn note_unsaved_stamp(idx: usize, saved: bool, wt: crate::task::sched_word::WakeTransition) {
    if !saved && wt == crate::task::sched_word::WakeTransition::Stamped {
        #[cfg(feature = "sched-reap-event")]
        reap_pending::mark(idx);
        STAMP_PENDING.store(true, Ordering::Release);
    }
}

/// A wake was stamped onto a task still switching away, and no tick has
/// reaped it yet (K-C25). Only a timer interrupt runs the reaper, so while
/// this is set an idle hart must not sleep to its ceiling: the kernel's
/// idle-poll hook (`timebase::set_idle_poll_hook`) reads [`stamp_pending`].
/// Before wave 13 hart 0's fixed 100 ms keepalive was the reaper's last
/// resort on an idle machine; the keepalive now runs only while a hardware
/// watchdog is armed.
static STAMP_PENDING: AtomicBool = AtomicBool::new(false);

/// See [`STAMP_PENDING`].
#[inline]
pub fn stamp_pending() -> bool {
    STAMP_PENDING.load(Ordering::Acquire)
}

/// What [`reap_one`] did with a slot.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Reap {
    /// Nothing to do for this stamp: no stamp, not `Blocked`, or another
    /// waker delivered it first.
    Done,
    /// `Blocked` with the stamp set but still switching away
    /// (`context_saving`) or current on some hart: look again next tick.
    Again,
    /// Recovered here: `Ready` and enqueued.
    Reaped,
}

/// One slot of [`reap_stamped_sleepers`].
unsafe fn reap_one(i: usize) -> Reap {
    use crate::task::sched_word::{state_of, WAKE_STAMP};
    unsafe {
        {
            if !TASK_VALID[i].load(Ordering::Relaxed) { return Reap::Done; }
            let task = task_mut(i);
            let w = task.state_word.load(Ordering::Acquire);
            if w & WAKE_STAMP == 0 || state_of(w) != TaskState::Blocked {
                return Reap::Done;
            }
            // K-C24 gate, same read the wakers use. Stale note removed
            // 2026-09-26: this used to claim `rvv` never maintained the
            // flag, from when `context_switch_rvv.S` never cleared
            // `context_saving` — see the fix note a few hundred lines up
            // at the `do_schedule` gate. `Cargo.toml` dropped the `rvv`
            // feature entirely on 2026-09-24, so there is no such build
            // left to describe either way.
            if task.context_saving.load(Ordering::Acquire) {
                return Reap::Again;
            }
            // ABA guard (measured 2026-08-24, first reaper version): the
            // state word has no generation, so "Blocked+STAMP" can be the
            // SAME bit pattern twice with a full consume→run→re-block→
            // re-stamp cycle in between — and `context_saving` sampled in
            // that window reads false. A CAS alone then reaps a task that is
            // EXECUTING its unswitched-block loop, enqueueing a running task
            // (census signature: `READY-UNQUEUED name=autorun`, the exact
            // state K-C24 exists to prevent — the commit's defensive arm
            // then parks it Ready-in-no-queue forever). The discriminator a
            // recycled bit pattern cannot fake: a PARKED task is current on
            // no hart. A parked Blocked task can only become current again
            // by first leaving Blocked (dispatch CAS → our CAS fails), so
            // checking currency before the CAS closes the ABA.
            let mut is_current = false;
            for cpu in 0..ncpu() {
                if PER_CPU[cpu].current_idx.load(Ordering::Relaxed) == i {
                    is_current = true;
                    break;
                }
            }
            if is_current {
                return Reap::Again;
            }
            if crate::task::sched_word::reap_orphaned_stamp(&task.state_word) {
                WAKE_LATE_DISPATCH.fetch_add(1, Ordering::Relaxed);
                task.ready_site.store(
                    crate::task::ready_site::REAP | ((current_cpu_id() as u8) << 4),
                    Ordering::Relaxed,
                );
                // Same dispatch-ownership contract as `wake_task_by_tid`'s
                // Dispatched arm: winner clears the reason and enqueues,
                // keeping tp consistent with the enqueue CPU (K-A11).
                task.wait_reason = WaitReason::None;
                let target_cpu = wake_target_cpu(i, task);
                task.context.tp = target_cpu as CtxReg;
                hist_reaccount(i);
                // U02-1 fix: see try_wake_task / wake_enqueue_locked.
                if !wake_enqueue_locked(target_cpu, i) {
                    WAKE_ENQ_REFUSED.fetch_add(1, Ordering::Relaxed);
                }
                return Reap::Reaped;
            }
        }
    }
    Reap::Done
}

pub fn wake_task_by_tid(tid: u32, pred: &dyn Fn(&WaitReason) -> bool) -> bool {
    wake_task_by_tid_placed(idx_for_tid(tid), pred, false)
}

/// [`wake_task_by_tid`] for a synchronous IPC hand-off — the fast-IPC call
/// waking its server, the reply waking its client — where the waker is about
/// to block on the answer. Placement goes through [`ipc_wake_target_cpu`]
/// (the IPC-affinity exception) instead of [`wake_target_cpu`].
pub fn wake_task_by_tid_ipc(tid: u32, pred: &dyn Fn(&WaitReason) -> bool) -> bool {
    wake_task_by_tid_placed(idx_for_tid(tid), pred, true)
}

/// Fast-IPC hand-off: wake `tid` (blocked on a reason `pred` accepts), then
/// block the current task on `reason` — **switching straight to `tid` on this
/// hart when that is exactly what `do_schedule` would have done.**
///
/// Observably the same as `wake_task_by_tid_ipc(tid, pred)` followed by
/// `task_block(reason)`, which is what it does whenever the direct path does
/// not apply. The direct path skips three things and nothing else: enqueueing
/// the woken task, `do_schedule`'s pick (deadline check, dequeue, priority
/// guard), and the spin gate on the woken task's `context_saving`. The gate is
/// replaced by a refusal: the claim re-reads `context_saving` with `Acquire`
/// AFTER its dispatch CAS and does not claim a task still being saved. The
/// `saved` flag `wake_transition` is given is read BEFORE that CAS and is NOT
/// proof — a server that blocked on another hart an instant earlier is
/// `Blocked` while that hart is still storing its registers. Trusting it was
/// measured: 1 aarch64 `ipctest -smp 4` run in 10 died with a jump into
/// `_text_end + 0x3e01` (a half-saved context resumed). A task that is
/// `Ready` and in no queue cannot start saving again, so one check suffices.
///
/// # The four outcomes, and why each is the old sequence
///
/// 1. The wake does not dispatch (stamped / mismatch / absent): nothing was
///    claimed; `block_current` runs exactly as before.
/// 2. The wake dispatches but [`ipc_direct::allowed`] refuses: the wake
///    enqueued the task itself (`WakeOut::Enqueued`); `block_current` as before.
/// 3. The wake claims the task, but the caller's own commit to `Blocked`
///    fails because a wake was already stamped on it: the caller does not
///    sleep, so the claimed task is enqueued where the ordinary IPC wake puts
///    it and the caller returns to re-check its condition — the same
///    `!committed` return `block_current` makes.
/// 4. Claimed and committed: the caller is switched out and the claimed task
///    in, with every step of `do_schedule`'s dispatch tail repeated here.
///
/// # Lock order ([`crate::wait`]'s K-C10 notes, and the direct hand-off that
/// was reverted)
///
/// The caller must hold no lock: `FAST_IPC` in particular is released before
/// this is called (the switched-to server's first act is to take it). A
/// held spinlock shows as `preempt::disabled()`, which sends this down the
/// old path, where `block_current`'s K-C29 refusal handles it as before. No
/// scheduler lock is taken on the direct path: the claim is the
/// `wake_transition` CAS, and `ready_bitmap` is read unlocked — a task
/// enqueued here by another hart after that read raises this hart's IPI and
/// preempts on its arrival, exactly as if it had been enqueued a moment later.
pub fn ipc_wake_then_block(
    tid: u32,
    pred: &dyn Fn(&WaitReason) -> bool,
    reason: WaitReason,
) {
    let cpu = current_cpu_id();
    #[cfg(feature = "sched-ipc-affinity")]
    if cpu < MAX_CPUS && !azos_sync::preempt::disabled() {
        // IRQs off from the claim to the switch: a tick in between would run
        // `do_schedule` on this hart with the claimed task in no queue.
        let sstatus = azos_arch::ARCH.disable_all();
        match wake_by_slot(idx_for_tid(tid), pred, true, cpu) {
            // SAFETY: `cpu < MAX_CPUS`; `ti` came from `idx_for_tid` and was
            // just claimed by this hart's CAS, so nothing else dispatches it.
            WakeOut::Claimed(ti) => unsafe { direct_switch_block(cpu, ti, reason) },
            WakeOut::Enqueued | WakeOut::NotWoken => {
                azos_arch::ARCH.restore(sstatus);
                block_current(cpu, reason);
                return;
            }
        }
        azos_arch::ARCH.restore(sstatus);
        return;
    }
    wake_task_by_tid_ipc(tid, pred);
    block_current(cpu, reason);
}

/// `SYS_IPC_FAST_CALL`'s hand-off: wake the server blocked in accept, then
/// sleep on the reply to `handle`. The two predicates are the ones
/// `wait::wake_fast_ipc_server` and the caller's own `task_block` use.
pub fn fast_ipc_call_handoff(server_tid: u32, handle: u64) {
    // Kconfig IPC_DIRECT_HANDOFF (N13): the one direct-switch helper. n folds
    // this away and the path below is the one N5 measured.
    if azos_sync::handoff::ENABLED {
        ipc_handoff(
            server_tid,
            WaitReason::FastIpcServer(server_tid),
            WaitReason::FastIpcClient(handle),
            azos_sync::handoff::HandoffReason::IpcCall,
        );
        return;
    }
    ipc_wake_then_block(
        server_tid,
        &|r| matches!(r, WaitReason::FastIpcServer(tid) if *tid == server_tid),
        WaitReason::FastIpcClient(handle),
    );
}

/// `SYS_IPC_FAST_REPLY_ACCEPT`'s hand-off: wake the client whose exchange
/// `handle` was just answered, then sleep as `server_tid` waiting for the next
/// call. The predicates are `wait::wake_fast_ipc_client_tid`'s and the
/// accept's own `task_block`.
pub fn fast_ipc_reply_handoff(caller_tid: u32, handle: u64, server_tid: u32) {
    if azos_sync::handoff::ENABLED {
        ipc_handoff(
            caller_tid,
            WaitReason::FastIpcClient(handle),
            WaitReason::FastIpcServer(server_tid),
            azos_sync::handoff::HandoffReason::IpcReplyRecv,
        );
        return;
    }
    ipc_wake_then_block(
        caller_tid,
        &|r| matches!(r, WaitReason::FastIpcClient(h) if *h == handle),
        WaitReason::FastIpcServer(server_tid),
    );
}

/// Kconfig IPC_DIRECT_HANDOFF (wave 15 N13): wake `tid` (blocked on exactly
/// `expect`) and block the current task on `reason`, through the one
/// direct-switch helper, `azos_sync::handoff::switch_to_direct`.
///
/// The helper's fixed signature carries the target and the reason only, not
/// the exchange key, so the two wait reasons are staged for this CPU in
/// [`HANDOFF_INTENT`] with interrupts masked from the staging to the switch;
/// [`SchedHandoff`] reads them back. The predicate stays exact (by TID, then
/// the exchange), never `FastIpcClient(_)`: a looser one could wake a caller
/// already blocked on its NEXT call.
///
/// No lock is held here: the endpoint queue lock was released before the
/// syscall arm called this (`ep_queue::call` / `reply_then_accept`), and the
/// helper refuses with preemption disabled (a held `SpinLock`).
///
/// Refusals, and what is left to do for each (the old outcomes 1 and 2):
/// `Disabled` / `LowerPriority` are decided before the wake, so the ordinary
/// wake + block runs; `PeerNotWaiting` (stamped or mismatched), `OtherCpu`
/// and `Preempted` (enqueued) come after the wake, so only the block is left.
#[inline(never)]
fn ipc_handoff(tid: u32, expect: WaitReason, reason: WaitReason, why: azos_sync::handoff::HandoffReason) {
    use azos_sync::handoff::HandoffRefused as R;
    // The CPU is read with interrupts masked: the intent slot is indexed by it.
    let sstatus = azos_arch::ARCH.disable_all();
    let cpu = current_cpu_id();
    if cpu < MAX_CPUS {
        // SAFETY: this CPU's slot, interrupts masked until the helper returns.
        unsafe { (*HANDOFF_INTENT.0.get())[cpu] = (expect, reason) };
        let r = azos_sync::handoff::switch_to_direct(tid, why);
        azos_arch::ARCH.restore(sstatus);
        match r {
            Ok(()) => return,
            Err(R::PeerNotWaiting | R::OtherCpu | R::Preempted) => {
                block_current(cpu, reason);
                return;
            }
            Err(R::Disabled | R::LowerPriority) => {}
        }
    } else {
        azos_arch::ARCH.restore(sstatus);
    }
    wake_task_by_tid_ipc(tid, &|r| *r == expect);
    block_current(cpu, reason);
}

/// Per CPU: `(target's wait reason, caller's block reason)` staged by
/// [`ipc_handoff`] for [`SchedHandoff`]. Written and read only by the owning
/// CPU with interrupts masked.
struct HandoffIntent(core::cell::UnsafeCell<[(WaitReason, WaitReason); MAX_CPUS]>);
// SAFETY: each CPU touches only its own slot, with interrupts masked.
unsafe impl Sync for HandoffIntent {}
static HANDOFF_INTENT: HandoffIntent =
    HandoffIntent(core::cell::UnsafeCell::new([(WaitReason::None, WaitReason::None); MAX_CPUS]));

/// `canary=handoff-any-prio`: [`SchedHandoff`] skips its "not less urgent"
/// check (ktest `ipc_handoff_refuses_less_urgent_peer`). Read only when the
/// target is less urgent, never on the taken path.
static HANDOFF_ANY_PRIO: AtomicBool = AtomicBool::new(false);

/// Arm the `handoff-any-prio` canary (boot, once).
pub fn canary_handoff_any_prio() {
    HANDOFF_ANY_PRIO.store(true, Ordering::Relaxed);
}

/// [`ipc_handoff`]'s staging and [`SchedHandoff`]'s switch, without the
/// Kconfig gate and the counters, so ktest `ipc_handoff_refuses_less_urgent_peer`
/// judges the implementation in a kernel built with IPC_DIRECT_HANDOFF n.
/// Same preconditions as the production path. Not for production callers.
#[doc(hidden)]
pub fn handoff_try_for_test(
    tid: u32,
    expect: WaitReason,
    reason: WaitReason,
    why: azos_sync::handoff::HandoffReason,
) -> Result<(), azos_sync::handoff::HandoffRefused> {
    use azos_sync::handoff::DirectSwitch;
    let sstatus = azos_arch::ARCH.disable_all();
    let cpu = current_cpu_id();
    if cpu >= MAX_CPUS {
        azos_arch::ARCH.restore(sstatus);
        return Err(azos_sync::handoff::HandoffRefused::Disabled);
    }
    // SAFETY: this CPU's slot, interrupts masked until the switch returns.
    unsafe { (*HANDOFF_INTENT.0.get())[cpu] = (expect, reason) };
    let r = SCHED_HANDOFF.switch_to_direct(tid, why);
    azos_arch::ARCH.restore(sstatus);
    r
}

/// The scheduler's [`azos_sync::handoff::DirectSwitch`] (wave 15 N13),
/// registered at boot (`kernel/src/boot/sched.rs`); with Kconfig
/// IPC_DIRECT_HANDOFF n the registration stores nothing and this is dropped.
///
/// The switch is the fast-IPC claim and dispatch tail
/// (`wake_by_slot` claim + `direct_switch_block`, the same steps
/// `ipc_wake_then_block` takes with `sched-ipc-affinity`): the target is
/// claimed by the dispatch CAS, kept out of every queue only when
/// [`ipc_direct::allowed`] says `do_schedule` would have picked it here, and
/// the caller commits to `Blocked` with the K-C24 rescue before switching.
/// Without `sched-ipc-affinity` (and for `FutexWake`, N9's experiment, not
/// wired yet) it refuses with `Disabled` before any wake.
pub struct SchedHandoff;

/// The registered instance.
pub static SCHED_HANDOFF: SchedHandoff = SchedHandoff;

impl azos_sync::handoff::DirectSwitch for SchedHandoff {
    fn switch_to_direct(
        &self,
        target: u32,
        why: azos_sync::handoff::HandoffReason,
    ) -> Result<(), azos_sync::handoff::HandoffRefused> {
        use azos_sync::handoff::HandoffRefused as R;
        #[cfg(not(feature = "sched-ipc-affinity"))]
        {
            let _ = (target, why);
            Err(R::Disabled)
        }
        #[cfg(feature = "sched-ipc-affinity")]
        // SAFETY: `PER_CPU[cpu]` with `cpu < MAX_CPUS`; `task_ref` of
        // `idx_for_tid`'s answer and of this CPU's current (`< MAX_TASKS`).
        unsafe {
            use azos_sync::handoff::HandoffReason as W;
            let cpu = current_cpu_id();
            // Preconditions: task context with preemption on (no SpinLock
            // held), interrupts masked by the stager, IPC reasons only.
            if why == W::FutexWake || cpu >= MAX_CPUS || azos_sync::preempt::disabled() {
                return Err(R::Disabled);
            }
            // Staged by `ipc_handoff` on this CPU, interrupts masked.
            let (expect, reason) = (*HANDOFF_INTENT.0.get())[cpu];
            let Some(ti) = idx_for_tid(target) else { return Err(R::PeerNotWaiting) };
            let cur = PER_CPU[cpu].current_idx.load(Ordering::Relaxed);
            if cur >= MAX_TASKS {
                return Err(R::Disabled);
            }
            // Not less urgent than the caller (lower number = more urgent).
            // The effective priority number, not `waitgraph::PiAttr` as §5
            // says: no SC -> PiAttr conversion exists in the scheduler yet.
            // Runtime canary `handoff-any-prio` skips this check.
            if task_ref(ti).priority.load(Ordering::Relaxed)
                > task_ref(cur).priority.load(Ordering::Relaxed)
                && !HANDOFF_ANY_PRIO.load(Ordering::Relaxed)
            {
                return Err(R::LowerPriority);
            }
            match wake_by_slot(Some(ti), &|r| *r == expect, true, cpu) {
                // SAFETY: `cpu < MAX_CPUS`; `ti` was just claimed by this
                // CPU's dispatch CAS, so nothing else dispatches it.
                // `Ok` also when the caller's own commit found a wake
                // already stamped (outcome 3: the target was enqueued, the
                // caller must not block again), so the helper's `taken`
                // count exceeds `IPC_DIRECT_SWITCHES` by those.
                WakeOut::Claimed(ti) => {
                    direct_switch_block(cpu, ti, reason);
                    Ok(())
                }
                WakeOut::Enqueued => {
                    let a = task_ref(ti).cpu_affinity;
                    Err(if a >= 0 && a as usize != cpu { R::OtherCpu } else { R::Preempted })
                }
                WakeOut::NotWoken => Err(R::PeerNotWaiting),
            }
        }
    }
}

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

/// Times [`ipc_wake_then_block`] switched directly (census builds only).
#[cfg(feature = "ipc-census")]
pub static IPC_DIRECT_SWITCHES: AtomicU32 = AtomicU32::new(0);

/// Claims [`ipc_wake_then_block`] declined because the woken task's
/// registers were still being saved on another hart (census builds only).
/// Non-zero proves the window the post-CAS re-read closes is really hit.
#[cfg(feature = "ipc-census")]
pub static IPC_DIRECT_UNSAVED: AtomicU32 = AtomicU32::new(0);

/// See [`IPC_DIRECT_SWITCHES`]; `0` on a kernel without `ipc-census`.
pub fn ipc_direct_switches() -> u32 {
    #[cfg(feature = "ipc-census")]
    { IPC_DIRECT_SWITCHES.load(Ordering::Relaxed) }
    #[cfg(not(feature = "ipc-census"))]
    { 0 }
}

/// See [`IPC_DIRECT_UNSAVED`]; `0` on a kernel without `ipc-census`.
pub fn ipc_direct_unsaved() -> u32 {
    #[cfg(feature = "ipc-census")]
    { IPC_DIRECT_UNSAVED.load(Ordering::Relaxed) }
    #[cfg(not(feature = "ipc-census"))]
    { 0 }
}

/// Outcomes 3 and 4 of [`ipc_wake_then_block`]. Called with IRQs masked and
/// `ti` claimed (`Ready`, `wait_reason` cleared, `tp == cpu`, in no queue,
/// histogram key not yet re-accounted).
#[cfg(feature = "sched-ipc-affinity")]
#[inline(always)]
unsafe fn direct_switch_block(cpu: usize, ti: usize, reason: WaitReason) {
    unsafe {
        let cur = PER_CPU[cpu].current_idx.load(Ordering::Relaxed);
        // `wake_by_slot` only claims with a valid current (it read its
        // priority); `< MAX_TASKS` again lets the index below be proven.
        if cur >= MAX_TASKS {
            direct_claim_enqueue(ti);
            return;
        }
        let task = task_mut(cur);
        // Same three steps, same order, as `block_current`: in-transit mark,
        // reason, then the commit CAS that publishes `Blocked`.
        task.context_saving.store(true, Ordering::Relaxed);
        task.wait_reason = reason;
        let committed = crate::task::sched_word::commit_blocked_or_consume_wake(&task.state_word);
        if !committed {
            hist_reaccount(cur);
            // Outcome 3. We never became Blocked; undo the mark, and give the
            // claimed task to the run queue the ordinary wake would have used.
            #[cfg(feature = "ipc-census")]
            unswitched::bump(&unswitched::BLOCK_SKIPPED);
            task.context_saving.store(false, Ordering::Relaxed);
            direct_claim_enqueue(ti);
            return;
        }

        // K-C24 rescue, as in `do_schedule`'s `Blocked` arm: a waker on
        // another hart that saw us `Blocked` with `context_saving` still set
        // stamped instead of dispatching. Consume that stamp into a normal
        // `Ready` + enqueue here, or it waits for the periodic reaper.
        loop {
            use crate::task::sched_word::{pack, WAKE_STAMP};
            let curw = task.state_word.load(Ordering::Acquire);
            if curw & WAKE_STAMP == 0
                || crate::task::sched_word::state_of(curw) != TaskState::Blocked
            {
                break;
            }
            if task.state_word.compare_exchange_weak(
                curw, pack(TaskState::Ready),
                Ordering::AcqRel, Ordering::Relaxed,
            ).is_ok() {
                hist_reaccount(cur);
                task.wait_reason = WaitReason::None;
                task.ready_site.store(
                    crate::task::ready_site::KC24_RESCUE | ((cpu as u8) << 4),
                    Ordering::Relaxed,
                );
                if !cpu_enqueue_locked(cpu, cur) {
                    SCHED_ENQ_REFUSED.fetch_add(1, Ordering::Relaxed);
                }
                break;
            }
        }

        // Outcome 4: `do_schedule`'s dispatch tail for `next = ti`. The steps
        // it has that are absent here are excluded by `ipc_direct::allowed`
        // (APS `set_current`, the tickless re-arm on an idle switch) or do
        // not apply (the old task is not `Running` or `Zombie`).
        let next = task_mut(ti);
        #[cfg(feature = "ipc-census")]
        {
            wakelat::measure(ti);
            IPC_DIRECT_SWITCHES.fetch_add(1, Ordering::Relaxed);
            unswitched::bump(&unswitched::BLOCK_SLEPT);
            unswitched::bump(&unswitched::SWITCHED);
        }
        next.set_state(TaskState::Running);
        // One paired re-account for both transitions (this task's `Blocked`
        // commit above, the claimed task's `Running` here): on a same-hart,
        // same-bucket hand-off they cancel and the histogram is not touched.
        hist_reaccount_pair(cur, ti);
        next.time_slice = if is_rt_priority(next.priority.load(Ordering::Relaxed)) {
            RT_TIME_SLICE_TICKS
        } else {
            TIME_SLICE_TICKS
        };
        set_current_task(cpu, ti);
        // As in `do_schedule`: the switching hart's id is the last `tp` store.
        next.context.tp = cpu as CtxReg;
        azos_sync::pi_mutex::CURRENT_TID.store(next.tid, Ordering::Release);
        azos_sync::pi_mutex::CURRENT_PRIO.store(
            next.priority.load(Ordering::Relaxed), Ordering::Release);
        if azos_sync::preempt::disabled() {
            preempt_audit::bump(&preempt_audit::SWITCH_WHILE_ATOMIC);
            azos_sync::preempt::force_zero_depth();
        }
        if azos_limits::SCHED_SWITCH_COUNTERS {
            task.switches_voluntary.fetch_add(1, Ordering::Relaxed);
        }
        // RFC-0051 E1: this hand-off bypasses `do_schedule`'s dispatch tail,
        // so it closes and opens the two signals itself.
        #[cfg(feature = "energy")]
        energy::on_switch(cpu, cur, ti);
        // Wave 15 (TRACE): the direct IPC hand-off is a switch too (reason 2).
        // The state is an atomic load: read it only when recording, or the
        // compiled-out build would still pay it.
        if azos_trace::sched_on() {
            azos_trace::raw::sched_switch(task.tid, next.tid, task.state() as u32, 2);
        }
        #[cfg(feature = "ctx-probe")]
        ctx_probe::check_dispatch(ctx_probe::DIRECT, cpu, ti);
        // Lockdep: as in `do_schedule`'s tail (the blocked task runs again).
        azos_sync::lockdep::switch(Some(cur), ti);
        azos_sync::qsbr::switch();
        // N12: as in `do_schedule`'s tail.
        crate::asid::prepare_switch(next as *mut Task);
        context_switch(task as *mut Task, next as *mut Task);
        // Resumed: woken and dispatched like any other blocked task.
        finish_switch(task as *mut Task);
    }
}

/// Hand a claimed-but-unused task to the queue the ordinary IPC wake would
/// have chosen (outcome 3 of [`ipc_wake_then_block`]).
#[cfg(feature = "sched-ipc-affinity")]
#[inline(never)]
unsafe fn direct_claim_enqueue(ti: usize) {
    unsafe {
        let t = task_mut(ti);
        let target_cpu = ipc_wake_target_cpu(ti, t);
        t.context.tp = target_cpu as CtxReg;
        hist_reaccount(ti);
        if !wake_enqueue_locked(target_cpu, ti) {
            WAKE_ENQ_REFUSED.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// The body of both: `slot` is `idx_for_tid(tid)`, resolved by the caller
/// so every TID lookup stays visibly in the public entry points.
#[inline(always)]
fn wake_task_by_tid_placed(slot: Option<usize>, pred: &dyn Fn(&WaitReason) -> bool, ipc: bool) -> bool {
    // `NO_CLAIM`: a constant, so the claim branch in `wake_by_slot` folds away
    // and this compiles to the same wake it always was.
    !matches!(wake_by_slot(slot, pred, ipc, NO_CLAIM), WakeOut::NotWoken)
}

/// `claim_cpu` value meaning "never claim, always enqueue".
const NO_CLAIM: usize = usize::MAX;

/// What [`wake_by_slot`] did with the addressee.
enum WakeOut {
    /// Stamped, mismatched, or no such task: nothing was dispatched.
    NotWoken,
    /// Dispatched through a run queue, exactly as every wake did before.
    Enqueued,
    /// Dispatched (`Blocked` -> `Ready`, `wait_reason` cleared) but left in
    /// NO queue: the caller owns it and must either switch to it or enqueue it.
    /// Only returned when `claim_cpu != NO_CLAIM` and [`ipc_direct::allowed`]
    /// said yes for that hart. Only `ipc_wake_then_block` asks for a claim,
    /// and only with `sched-ipc-affinity`.
    #[cfg_attr(not(feature = "sched-ipc-affinity"), allow(dead_code))]
    Claimed(usize),
}

/// The body of every TID-directed wake. With `claim_cpu == NO_CLAIM` it is the
/// ordinary wake; otherwise a dispatched addressee that
/// [`ipc_direct::allowed`] clears for `claim_cpu` is handed back as
/// [`WakeOut::Claimed`] instead of being enqueued.
#[inline(always)]
fn wake_by_slot(
    slot: Option<usize>,
    pred: &dyn Fn(&WaitReason) -> bool,
    ipc: bool,
    claim_cpu: usize,
) -> WakeOut {
    use crate::task::sched_word::{wake_transition, WakeTransition};
    unsafe {
        // `idx_for_tid` answers only for a slot that is valid AND carries this
        // TID, so an invalid slot's stale `Task` is never read and `pred` is
        // never evaluated for a non-addressee. It used to be a 64-slot scan
        // written out here (~490 instructions per wake, two wakes per IPC round
        // trip); TID 0, which never names a task, no longer matches a slot that
        // is mid-allocation.
        if let Some(i) = slot {
            let task = task_mut(i);

            // K-C19: decision and transition are one CAS protocol now —
            // `wake_transition` enforces the `wait::wake_action` truth table
            // (its doc still holds), with the two windows closed:
            // a stamp can no longer land after the addressee committed to
            // Blocked, and a dispatch CAS can be won by exactly one waker.
            // The Acquire pairing inside replaces the old K-C17 fence.
            // K-C24: `saved` keeps an unswitched-block target (Blocked but
            // still executing) out of the ready queues — stamp instead.
            let saved_seen = core::cell::Cell::new(true);
            let wt = wake_transition(&task.state_word, || pred(&task.wait_reason), true, || {
                let s = !task.context_saving.load(Ordering::Acquire);
                saved_seen.set(s);
                s
            });
            let saved = saved_seen.get();
            match wt {
                WakeTransition::Stamped => {
                    note_unsaved_stamp(i, saved, WakeTransition::Stamped);
                    WAKE_STAMPED.fetch_add(1, Ordering::Relaxed);
                    // K-C9/K-C10: the addressee had not committed to Blocked
                    // yet; its commit CAS will now fail, consume the stamp,
                    // and skip the block.
                    return WakeOut::NotWoken;
                }
                // Genuine mismatch: no stamp, and do NOT keep scanning —
                // TIDs are unique among valid tasks.
                WakeTransition::Mismatch => {
                    WAKE_MISMATCHED.fetch_add(1, Ordering::Relaxed);
                    return WakeOut::NotWoken;
                }
                WakeTransition::Dispatched => {
                    task.ready_site.store(
                        crate::task::ready_site::WAKE | ((current_cpu_id() as u8) << 4),
                        Ordering::Relaxed,
                    );
                    #[cfg(feature = "ipc-census")]
                    wakelat::arm(i);
                    WAKE_DISPATCHED.fetch_add(1, Ordering::Relaxed);
                    task.wait_reason = WaitReason::None;
                    // Direct-switch claim: keep the task out of every queue and
                    // hand it to the caller, who switches to it on `claim_cpu`
                    // without a trip through `do_schedule`'s pick.
                    if claim_cpu != NO_CLAIM {
                        let prio = task.priority.load(Ordering::Relaxed);
                        let cur = PER_CPU[claim_cpu].current_idx.load(Ordering::Relaxed);
                        let cur_idle = cur < MAX_TASKS
                            && task_ref(cur).priority.load(Ordering::Relaxed)
                                == crate::task::IDLE_PRIORITY;
                        let target_saved = !task.context_saving.load(Ordering::Acquire);
                        #[cfg(feature = "ipc-census")]
                        if !target_saved {
                            IPC_DIRECT_UNSAVED.fetch_add(1, Ordering::Relaxed);
                        }
                        if cur < MAX_TASKS && ipc_direct::allowed(ipc_direct::DirectSwitch {
                            ready_bitmap: PER_CPU[claim_cpu].ready_bitmap.load(Ordering::Relaxed),
                            target_bucket: prio_bucket(prio),
                            target_affinity: task.cpu_affinity,
                            cpu: claim_cpu,
                            target_is_idle: prio == crate::task::IDLE_PRIORITY,
                            current_is_idle: cur_idle,
                            deadline_live: rt::holds_direct_switch(
                                claim_cpu, prio, task_ref(cur).priority.load(Ordering::Relaxed)),
                            aps: aps_dispatch_enabled(),
                            // Read after the CAS, not the `saved` read before
                            // it — see the field's doc.
                            target_saved,
                        }) {
                            task.context.tp = claim_cpu as CtxReg;
                            // Wave 15 (TRACE): a claimed wake never queues.
                            if azos_trace::sched_on() {
                                azos_trace::raw::sched_wakeup(task.tid, claim_cpu as u32, current_task_tid());
                            }
                            return WakeOut::Claimed(i);
                        }
                    }
                    let target_cpu = if ipc {
                        ipc_wake_target_cpu(i, task)
                    } else {
                        wake_target_cpu(i, task)
                    };
                    #[cfg(feature = "ipc-census")]
                    if ipc {
                        ipc_placement::record(target_cpu);
                    }
                    // K-A11: keep the saved tp consistent with the enqueue CPU
                    // — context_switch restores it into hw tp and
                    // current_cpu_id() trusts it; a stale tp would corrupt
                    // another CPU's PER_CPU state.
                    task.context.tp = target_cpu as CtxReg;
                    hist_reaccount(i);
                    // The return value matters: a refused enqueue leaves the
                    // task `Ready` and in no queue at all, which is worse than
                    // the sleep it was meant to end. Counted, not ignored.
                    // U02-1 fix: see try_wake_task / wake_enqueue_locked.
                    if !wake_enqueue_locked(target_cpu, i) {
                        WAKE_ENQ_REFUSED.fetch_add(1, Ordering::Relaxed);
                    }
                    return WakeOut::Enqueued;
                }
                // Unreachable with `stamp_if_unblocked = true`; kept so the
                // match stays exhaustive against the transition's contract.
                WakeTransition::NotBlocked => return WakeOut::NotWoken,
            }
        }
        // Every arm above returns, so reaching here means no valid slot
        // carried this TID.
        WAKE_ABSENT.fetch_add(1, Ordering::Relaxed);
    }
    WakeOut::NotWoken
}

// ── M03: Tickless scheduling helpers ────────────────────────────────────────

/// Return the nearest pending timer deadline across all blocked tasks.
///
/// Used by the tickless scheduler to program mtimecmp at the exact tick needed
/// rather than firing at a fixed periodic rate.  Returns `None` if no tasks
/// are currently sleeping on a timer.
///
/// With `sched-timer-heap` this is the heap's top after dropping stale
/// entries (see [`timer_sleepers`]); without it, the O(`MAX_TASKS`) sweep
/// below. Under `ipc-census` the heap build also runs the sweep and counts
/// disagreements (`timer_sleepers::NEAREST_MISMATCH`).
pub fn nearest_timer_deadline() -> Option<u64> {
    #[cfg(feature = "sched-timer-heap")]
    {
        let got = timer_sleepers::nearest();
        #[cfg(feature = "ipc-census")]
        timer_sleepers::check_nearest(got, nearest_timer_deadline_sweep_where(timer_sleepers::owned_here));
        got
    }
    #[cfg(not(feature = "sched-timer-heap"))]
    nearest_timer_deadline_sweep()
}

/// The O(`MAX_TASKS`) sweep: the whole of `nearest_timer_deadline` without
/// `sched-timer-heap` (its census cross-check sweeps this CPU's slots only).
#[cfg_attr(feature = "sched-timer-heap", allow(dead_code))]
fn nearest_timer_deadline_sweep() -> Option<u64> {
    nearest_timer_deadline_sweep_where(|_| true)
}

/// The sweep over the slots `keep` selects (the census: this CPU's heap's).
#[cfg_attr(
    all(feature = "sched-timer-heap", not(feature = "ipc-census")),
    allow(dead_code)
)]
#[inline(always)]
fn nearest_timer_deadline_sweep_where(keep: impl Fn(usize) -> bool) -> Option<u64> {
    let mut min_deadline: Option<u64> = None;
    unsafe {
        for i in 0..MAX_TASKS {
            if !TASK_VALID[i].load(Ordering::Relaxed) || !keep(i) { continue; }
            let task = task_ref(i);
            // Acquire pairs with block_current's Release commit: it publishes
            // the `wait_reason` (and deadline) we read next (K-C17).
            if task.state_acquire() != TaskState::Blocked { continue; }
            if let WaitReason::Timer(deadline) = task.wait_reason {
                min_deadline = Some(match min_deadline {
                    Some(cur) => cur.min(deadline),
                    None      => deadline,
                });
            }
        }
    }
    min_deadline
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
pub mod timer_sleepers {
    use super::{TaskState, WaitReason, MAX_TASKS, TASKS, TASK_VALID};
    use crate::timer_heap::TimerHeap;
    use azos_arch::Interrupts;
    use core::sync::atomic::{AtomicBool, Ordering};

    // `SCHED_TIMER_HEAP_PER_CPU` (owner decision, wave 15 VW): one heap per
    // CPU, like Linux's per-CPU hrtimer bases. A sleeper is armed on the
    // heap of the CPU it blocks on, and only that CPU's tick pops it and
    // programs its comparator from it, so each lock below is taken only by
    // its own CPU (interrupts masked) and never waits on another hart.
    // Before (one global lock): 28 contended acquires a boot on riscv64
    // `-icount -smp 2`, the longest spin 50 ms inside the tick ISR, its
    // holder a hart `-icount` was not running. Off, there is one heap
    // (index 0) and the old global lock.
    const PER_CPU: bool = azos_limits::SCHED_TIMER_HEAP_PER_CPU;
    const NHEAPS: usize = if PER_CPU { super::MAX_CPUS } else { 1 };

    /// The heaps, in the per-CPU areas (allocated at boot from the frame
    /// allocator, for the possible CPUs only): RAM scales with the CPUs the
    /// board has, not with `NR_CPUS`. Before `setup_per_cpu_areas` no CPU
    /// has one, and no task can sleep yet; a tick in that window finds no
    /// heap and does nothing (see [`attached`]). Off, only CPU 0's is used.
    ///
    /// Scope `PerCpu` (`azos_sync::scope`, the first instance of the owner's
    /// scope types): each heap is touched by its own CPU only, interrupts
    /// masked; lockdep checks both at each access. Off
    /// (SCHED_TIMER_HEAP_PER_CPU=n) the one heap every CPU uses is CPU 0's
    /// instance behind the global lock: a Global scope, reached through
    /// `PerCpu::storage`.
    pub(crate) static TIMER_HEAPS: azos_sync::scope::PerCpu<TimerHeap<MAX_TASKS>> =
        azos_sync::scope::PerCpu::with_init(init_heap);

    unsafe fn init_heap(p: *mut TimerHeap<MAX_TASKS>) {
        // SAFETY: `PerCpuVar::attach`'s contract: zeroed, aligned, ours.
        unsafe { TimerHeap::init_zeroed(p) }
    }

    /// Has heap `h` its per-CPU instance yet?
    #[inline(always)]
    fn attached(h: usize) -> bool {
        TIMER_HEAPS.attached(h)
    }

    static LOCKS: [AtomicBool; NHEAPS] = [const { AtomicBool::new(false) }; NHEAPS];
    /// The heap that holds each slot's live entry: written at every arm,
    /// under that heap's lock. An entry left in another heap by an earlier
    /// sleep is stale there: that heap drops it instead of waking or
    /// re-arming it.
    static OWNER: [core::sync::atomic::AtomicU8; MAX_TASKS] =
        [const { core::sync::atomic::AtomicU8::new(0) }; MAX_TASKS];
    const _: () = assert!(NHEAPS <= u8::MAX as usize);

    /// This CPU's heap. Interrupts must be masked (the hart cannot change).
    #[inline(always)]
    fn here() -> usize {
        if PER_CPU { crate::smp::current_cpu_id().min(NHEAPS - 1) } else { 0 }
    }

    struct Guard {
        h: usize,
        prev: azos_arch::InterruptState,
    }

    impl Guard {
        /// This CPU's heap: interrupts masked BEFORE the hart id is read.
        #[inline]
        fn local() -> Self {
            let prev = azos_arch::ARCH.disable_all();
            Self::take(here(), prev)
        }

        /// Heap `h`, read by a caller already masked on that CPU.
        #[inline]
        fn on(h: usize) -> Self {
            let prev = azos_arch::ARCH.disable_all();
            Self::take(h, prev)
        }

        #[inline(always)]
        fn take(h: usize, prev: azos_arch::InterruptState) -> Self {
            while LOCKS[h]
                .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
                .is_err()
            {
                core::hint::spin_loop();
            }
            Guard { h, prev }
        }

        #[inline]
        fn heap(&mut self) -> &mut TimerHeap<MAX_TASKS> {
            let p: *mut TimerHeap<MAX_TASKS> = if PER_CPU {
                // SAFETY: the guard masked interrupts before it read `h`
                // (`local`, `on`): this CPU's heap. Lockdep checks both.
                let irq = unsafe { azos_sync::scope::IrqOff::assume() };
                TIMER_HEAPS.with_mut_on(&irq, self.h, |t| t as *mut _)
            } else {
                // SAFETY: the one shared heap, under the global `LOCKS[0]`.
                unsafe { TIMER_HEAPS.storage() }.ptr(self.h)
            };
            // SAFETY: `LOCKS[h]` is held for the guard's lifetime, the
            // returned borrow cannot outlive `&mut self`, and every caller
            // checked `attached(h)` (the instance is never freed).
            unsafe { &mut *p }
        }
    }

    impl Drop for Guard {
        #[inline]
        fn drop(&mut self) {
            LOCKS[self.h].store(false, Ordering::Release);
            azos_arch::ARCH.restore(self.prev);
        }
    }

    /// `slot`'s live deadline, if heap `h` owns it.
    #[inline]
    fn live_on(h: usize, slot: usize) -> Option<u64> {
        if OWNER[slot].load(Ordering::Relaxed) as usize != h {
            return None;
        }
        still_sleeping(slot)
    }

    /// Does this CPU's heap own `slot`? (Census cross-checks.)
    #[cfg(feature = "ipc-census")]
    pub(super) fn owned_here(slot: usize) -> bool {
        OWNER[slot].load(Ordering::Relaxed) as usize == here()
    }

    /// `block_current`'s arm, after the commit left `idx` `Blocked`: on the
    /// heap of the CPU it blocks on.
    #[inline]
    pub(super) fn arm(idx: usize, deadline: u64) {
        let mut g = Guard::local();
        if !attached(g.h) {
            return; // no task sleeps before the per-CPU areas exist
        }
        OWNER[idx].store(g.h as u8, Ordering::Relaxed);
        g.heap().arm(idx, deadline);
    }

    /// The deadline `slot` still sleeps on, if it is `Blocked` on a timer.
    #[inline]
    pub(super) fn still_sleeping(slot: usize) -> Option<u64> {
        unsafe {
            if !TASK_VALID[slot].load(Ordering::Relaxed) {
                return None;
            }
            let t = &*core::ptr::addr_of!(TASKS[slot]);
            if t.state_acquire() != TaskState::Blocked {
                return None;
            }
            match t.wait_reason {
                WaitReason::Timer(d) => Some(d),
                _ => None,
            }
        }
    }

    /// Drop `idx`'s entry (tick-probe cleanup).
    #[allow(dead_code)]
    pub(super) fn cancel(idx: usize) {
        let mut g = Guard::local();
        if attached(g.h) {
            g.heap().cancel(idx);
        }
    }

    /// `ipc-census`: per slot, ticks that popped it and are not yet
    /// through their wake-or-re-arm step — the pop -> re-arm window, named
    /// so a mismatch that falls in it can be told from one that does not.
    /// A count, not a flag: a slot popped, woken, re-blocked and popped
    /// again by another hart's tick is in two windows at once, and the
    /// first tick to finish must not clear the second one's.
    #[cfg(feature = "ipc-census")]
    static INFLIGHT: [core::sync::atomic::AtomicU32; MAX_TASKS] =
        [const { core::sync::atomic::AtomicU32::new(0) }; MAX_TASKS];

    /// Whether a tick has `slot` popped and not yet woken or re-armed.
    #[cfg(feature = "ipc-census")]
    pub(super) fn inflight(slot: usize) -> bool {
        INFLIGHT.get(slot).is_some_and(|c| c.load(Ordering::Relaxed) != 0)
    }

    #[cfg(feature = "ipc-census")]
    pub(super) fn landed(slot: usize) {
        // Release: a census reader that sees the count drop (Acquire) also
        // sees the wake this tick made before it.
        INFLIGHT[slot].fetch_sub(1, Ordering::Release);
    }

    /// The top of the heap after fixing it up against the live tasks
    /// (`TimerHeap::peek_live` with `still_sleeping`): stale entries are
    /// dropped so a woken sleeper cannot make the tickless path program an
    /// early interrupt, and an entry whose slot sleeps on a different
    /// deadline is moved to it, not dropped.
    pub(super) fn nearest() -> Option<u64> {
        let mut g = Guard::local();
        let h = g.h;
        if !attached(h) {
            return None;
        }
        g.heap().peek_live(|s| live_on(h, s))
    }

    /// The live heap and task table as `timer_heap::wake_due` sees them.
    /// A tick's pass over the heap `h` of the CPU taking the tick.
    pub(super) struct Due {
        h: usize,
    }

    impl Due {
        /// For the calling CPU, whose interrupts are masked (the tick ISR).
        #[inline]
        pub(super) fn here() -> Self {
            Due { h: here() }
        }

        /// Has this pass's heap its instance yet (a tick before
        /// `setup_per_cpu_areas` has nothing to pop)?
        #[inline]
        pub(super) fn ready(&self) -> bool {
            attached(self.h)
        }
    }

    impl crate::timer_heap::DueSleepers<MAX_TASKS> for Due {
        #[inline]
        fn locked<R>(&self, f: impl FnOnce(&mut TimerHeap<MAX_TASKS>) -> R) -> R {
            f(Guard::on(self.h).heap())
        }

        #[inline]
        fn live(&self, slot: usize) -> Option<u64> {
            live_on(self.h, slot)
        }

        #[inline]
        fn wake(&self, slot: usize, now: u64) {
            // Stale here: the slot slept again on another CPU's heap since.
            if OWNER[slot].load(Ordering::Relaxed) as usize != self.h {
                return;
            }
            super::try_wake_task(slot, &|r: &WaitReason| {
                matches!(r, WaitReason::Timer(d) if now >= *d)
            });
        }

        #[cfg(feature = "ipc-census")]
        #[inline]
        fn popped(&self, slot: usize) {
            INFLIGHT[slot].fetch_add(1, Ordering::Relaxed);
            POPS[slot].fetch_add(1, Ordering::Relaxed);
        }

        #[cfg(feature = "ipc-census")]
        #[inline]
        fn landed(&self, slot: usize) {
            landed(slot);
        }
    }

    /// `ipc-census`: heap vs sweep, counted per `nearest_timer_deadline`
    /// call, and sleepers the sweep would still wake after the heap's tick
    /// pass (a missed arm shows here). Tallies print at powers of two.
    #[cfg(feature = "ipc-census")]
    pub static NEAREST_CHECKS: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
    #[cfg(feature = "ipc-census")]
    pub static NEAREST_MISMATCH: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
    #[cfg(feature = "ipc-census")]
    pub static TICK_CHECKS: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
    #[cfg(feature = "ipc-census")]
    pub static MISSED: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

    #[cfg(feature = "ipc-census")]
    pub(super) fn check_nearest(heap: Option<u64>, sweep: Option<u64>) {
        let n = NEAREST_CHECKS.fetch_add(1, Ordering::Relaxed).wrapping_add(1);
        if heap != sweep {
            let (class, note) = classify_mismatch(heap, sweep);
            if let Some(n) = note {
                n.print("UNEXPLAINED", sweep.unwrap_or(0));
            }
            MISMATCH_BY[class as usize].fetch_add(1, Ordering::Relaxed);
            if NEAREST_MISMATCH.fetch_add(1, Ordering::Relaxed) == 0 {
                azos_drv_sys::kprintln!(
                    "[SCHED] TIMER_NEAREST_MISMATCH first: heap={:?} sweep={:?} class={}",
                    heap, sweep, class as usize,
                );
            }
            if class == Mismatch::Unexplained
                && MISMATCH_BY[Mismatch::Unexplained as usize].load(Ordering::Relaxed) == 1
            {
                azos_drv_sys::kprintln!(
                    "[SCHED] TIMER_NEAREST_UNEXPLAINED first: heap={:?} sweep={:?}", heap, sweep,
                );
            }
        }
        if n >= 64 && n.is_power_of_two() {
            let by = |c: Mismatch| MISMATCH_BY[c as usize].load(Ordering::Relaxed);
            azos_drv_sys::kprintln!(
                "[SCHED] timer-check nearest={} mismatches={} (early={} gone={} armed={} \
                 pop_rearm={} commit_arm={} unexplained={}) ticks={} missed={} \
                 (inflight={} saving={} current={} lost={})",
                n,
                NEAREST_MISMATCH.load(Ordering::Relaxed),
                by(Mismatch::HeapEarlier), by(Mismatch::Gone), by(Mismatch::ArmedSince),
                by(Mismatch::PopRearm), by(Mismatch::CommitArm), by(Mismatch::Unexplained),
                TICK_CHECKS.load(Ordering::Relaxed),
                MISSED.load(Ordering::Relaxed),
                MISSED_BY[0].load(Ordering::Relaxed), MISSED_BY[1].load(Ordering::Relaxed),
                MISSED_BY[2].load(Ordering::Relaxed), MISSED_BY[3].load(Ordering::Relaxed),
            );
        }
    }

    /// Why the heap's nearest deadline and the sweep's differed, judged
    /// right after both were read (the classification itself races the
    /// same transitions, which is what `Gone` / `ArmedSince` absorb).
    #[cfg(feature = "ipc-census")]
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Mismatch {
        /// Heap earlier than the sweep: its top was live when read and
        /// was woken before the sweep ran.
        HeapEarlier = 0,
        /// No slot sleeps on the sweep's deadline any more.
        Gone = 1,
        /// The sleeper is armed at that deadline now (its arm landed
        /// between the two reads).
        ArmedSince = 2,
        /// Popped by a tick, not yet re-armed or woken.
        PopRearm = 3,
        /// Committed `Blocked` and still on its hart (`context_saving`
        /// set, or current): the arm is pending or it is an unswitched block.
        CommitArm = 4,
        /// None of the above: a sleeper with no entry and no reason.
        Unexplained = 5,
    }

    #[cfg(feature = "ipc-census")]
    static MISMATCH_BY: [core::sync::atomic::AtomicU32; 6] =
        [const { core::sync::atomic::AtomicU32::new(0) }; 6];

    #[cfg(feature = "ipc-census")]
    fn classify_mismatch(heap: Option<u64>, sweep: Option<u64>) -> (Mismatch, Option<LostNote>) {
        let Some(sd) = sweep else { return (Mismatch::HeapEarlier, None) };
        if matches!(heap, Some(hd) if hd < sd) {
            return (Mismatch::HeapEarlier, None);
        }
        let mut g = Guard::local();
        let h = g.heap();
        let mut class = Mismatch::Gone;
        let mut note = None;
        for i in 0..MAX_TASKS {
            if still_sleeping(i) != Some(sd) {
                continue;
            }
            let c = if h.armed_deadline(i) == Some(sd) {
                Mismatch::ArmedSince
            } else {
                match sleeper_why(i, sd) {
                    SleeperWhy::InFlight => Mismatch::PopRearm,
                    SleeperWhy::Saving | SleeperWhy::Current => Mismatch::CommitArm,
                    SleeperWhy::Woken => Mismatch::Gone,
                    SleeperWhy::Lost => Mismatch::Unexplained,
                }
            };
            if c == Mismatch::Unexplained && note.is_none() {
                note = Some(LostNote::take(i, sd, h.armed_deadline(i)));
            }
            // The least benign explanation of any sleeper on `sd` wins.
            if (c as u8) > (class as u8) {
                class = c;
            }
        }
        (class, note)
    }

    /// First tick (`now`) at which each slot was seen `Blocked` on a due
    /// `Timer(d)` without being armed at `d`, and that `d`; 0 = not suspect.
    #[cfg(feature = "ipc-census")]
    static SUSPECT_SINCE: [core::sync::atomic::AtomicU64; MAX_TASKS] =
        [const { core::sync::atomic::AtomicU64::new(0) }; MAX_TASKS];
    #[cfg(feature = "ipc-census")]
    static SUSPECT_DEADLINE: [core::sync::atomic::AtomicU64; MAX_TASKS] =
        [const { core::sync::atomic::AtomicU64::new(0) }; MAX_TASKS];

    /// After the heap pass: a slot `Blocked` on a `Timer(d)` due at `now`
    /// and not armed at `d` is one no later tick will visit either — lost —
    /// provided it STAYS that way. A sleeper whose `block_current` has
    /// committed but not yet armed (it may be spinning on this very lock,
    /// which this check holds) looks the same for a few microseconds, so a
    /// slot counts as missed only when seen in that state on the same `d`
    /// at least `CONFIRM_TICKS` (1 ms at 10 MHz) after it was first seen.
    #[cfg(feature = "ipc-census")]
    pub(super) fn check_tick(now: u64) {
        const CONFIRM_TICKS: u64 = 10_000;
        TICK_CHECKS.fetch_add(1, Ordering::Relaxed);
        // Printed after the guard drops: `LOCK` stays a leaf (no UART_LOCK
        // under it), census build included.
        let mut first: Option<(usize, u64, u64, SleeperWhy)> = None;
        let mut opened: Option<LostNote> = None;
        let mut closed: Option<LostNote> = None;
        let mut g = Guard::local();
        let h = g.heap();
        unsafe {
            for i in 0..MAX_TASKS {
                let mut suspect = None;
                if TASK_VALID[i].load(Ordering::Relaxed) {
                    let t = &*core::ptr::addr_of!(TASKS[i]);
                    if t.state_acquire() == TaskState::Blocked {
                        if let WaitReason::Timer(d) = t.wait_reason {
                            if now >= d && owned_here(i) && h.armed_deadline(i) != Some(d) {
                                suspect = Some(d);
                            }
                        }
                    }
                }
                let Some(d) = suspect else {
                    SUSPECT_SINCE[i].store(0, Ordering::Relaxed);
                    let open = LOST_OPEN[i].swap(0, Ordering::Relaxed);
                    if open != 0 && closed.is_none() {
                        closed = Some(LostNote::take(i, now.saturating_sub(open), h.armed_deadline(i)));
                    }
                    continue;
                };
                let since = SUSPECT_SINCE[i].load(Ordering::Relaxed);
                if since == 0 || SUSPECT_DEADLINE[i].load(Ordering::Relaxed) != d {
                    SUSPECT_SINCE[i].store(now.max(1), Ordering::Relaxed);
                    SUSPECT_DEADLINE[i].store(d, Ordering::Relaxed);
                } else if since != u64::MAX && now.saturating_sub(since) >= CONFIRM_TICKS {
                    // Count once per suspect episode, by what the sleeper
                    // is doing when confirmed.
                    SUSPECT_SINCE[i].store(u64::MAX, Ordering::Relaxed);
                    let why = sleeper_why(i, d);
                    if why == SleeperWhy::Woken {
                        // Woken while being classified: not a sleeper
                        // the heap left behind (see `sleeper_why`).
                        SUSPECT_SINCE[i].store(0, Ordering::Relaxed);
                        continue;
                    }
                    if why == SleeperWhy::Lost {
                        LOST_OPEN[i].store(now.max(1), Ordering::Relaxed);
                        LOST_POPS[i].store(POPS[i].load(Ordering::Relaxed), Ordering::Relaxed);
                        if opened.is_none() {
                            opened = Some(LostNote::take(i, d, h.armed_deadline(i)));
                        }
                    }
                    if MISSED_BY[why as usize].fetch_add(1, Ordering::Relaxed) == 0 && first.is_none() {
                        first = Some((i, d, since, why));
                    }
                    MISSED.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
        drop(g);
        if let Some((i, d, since, why)) = first {
            azos_drv_sys::kprintln!(
                "[SCHED] TIMER_MISSED first of class {}: slot={} deadline={} now={} since={}",
                why as usize, i, d, now, since,
            );
        }
        if let Some(n) = opened {
            n.print("LOST_OPEN", now);
        }
        if let Some(n) = closed {
            n.print("LOST_CLOSE", now);
        }
    }

    /// Per slot, entries `pop_due` has popped (census). A `Lost` episode
    /// that ends with this count moved was found by the heap again (a
    /// delay); one that ends without it was ended by another waker.
    #[cfg(feature = "ipc-census")]
    static POPS: [core::sync::atomic::AtomicU32; MAX_TASKS] =
        [const { core::sync::atomic::AtomicU32::new(0) }; MAX_TASKS];
    /// `now` at which a `Lost` episode was confirmed for the slot, 0 = none.
    #[cfg(feature = "ipc-census")]
    static LOST_OPEN: [core::sync::atomic::AtomicU64; MAX_TASKS] =
        [const { core::sync::atomic::AtomicU64::new(0) }; MAX_TASKS];
    /// `POPS[slot]` when the open episode was confirmed.
    #[cfg(feature = "ipc-census")]
    static LOST_POPS: [core::sync::atomic::AtomicU32; MAX_TASKS] =
        [const { core::sync::atomic::AtomicU32::new(0) }; MAX_TASKS];
    #[cfg(feature = "ipc-census")]
    static LOST_PRINTS: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

    /// A snapshot of one slot for the `Lost` episode lines, taken under
    /// `LOCK` and printed after it is released.
    #[cfg(feature = "ipc-census")]
    #[derive(Clone, Copy)]
    struct LostNote {
        slot: usize,
        /// Deadline slept on (open) or episode length in ticks (close).
        val: u64,
        armed: Option<u64>,
        word: u32,
        reason: Option<u64>,
        site: u8,
        pops: u32,
        name: [u8; 16],
    }

    #[cfg(feature = "ipc-census")]
    impl LostNote {
        fn take(i: usize, val: u64, armed: Option<u64>) -> Self {
            let t = unsafe { &*core::ptr::addr_of!(TASKS[i]) };
            let mut name = [0u8; 16];
            let n = t.name.len().min(16);
            name[..n].copy_from_slice(&t.name[..n]);
            LostNote {
                slot: i,
                val,
                armed,
                word: t.state_word.load(Ordering::Acquire),
                reason: match t.wait_reason {
                    WaitReason::Timer(d) => Some(d),
                    _ => None,
                },
                site: t.ready_site.load(Ordering::Relaxed),
                pops: POPS[i].load(Ordering::Relaxed).wrapping_sub(LOST_POPS[i].load(Ordering::Relaxed)),
                name,
            }
        }

        fn print(&self, what: &str, now: u64) {
            if LOST_PRINTS.fetch_add(1, Ordering::Relaxed) >= 64 {
                return;
            }
            let end = self.name.iter().position(|&b| b == 0).unwrap_or(16);
            let name = core::str::from_utf8(&self.name[..end]).unwrap_or("?");
            azos_drv_sys::kprintln!(
                "[SCHED] {} slot={} name={} val={} now={} armed={:?} word={:#x} timer={:?} \
                 ready_site={:#x} pops_since_open={}",
                what, self.slot, name, self.val, now, self.armed, self.word, self.reason,
                self.site, self.pops,
            );
        }
    }

    /// What a `Blocked`-on-a-timer sleeper with no heap entry at its
    /// deadline is doing (census classification of `MISSED`).
    #[cfg(feature = "ipc-census")]
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum SleeperWhy {
        /// Popped by a tick that has not re-armed or woken it yet.
        InFlight = 0,
        /// `context_saving` set: switching away, or an unswitched block.
        Saving = 1,
        /// Current on some hart with `context_saving` clear.
        Current = 2,
        /// Parked, not popped, no entry: lost.
        Lost = 3,
        /// No longer asleep on the deadline by the end of the check: a
        /// waker (a tick that had popped it, typically) finished while the
        /// check ran. Never counted in `MISSED_BY`.
        Woken = 4,
    }

    #[cfg(feature = "ipc-census")]
    pub static MISSED_BY: [core::sync::atomic::AtomicU32; 4] =
        [const { core::sync::atomic::AtomicU32::new(0) }; 4];

    #[cfg(feature = "ipc-census")]
    ///
    /// `d` is the deadline the caller saw slot `i` asleep on. That read and
    /// the `INFLIGHT` read below are two instants, and a tick that popped
    /// the entry before the caller took `LOCK` needs no lock to finish its
    /// wake: it can move the task to `Ready` and drop `INFLIGHT` in between,
    /// which read as "asleep, no entry, nothing in flight". So `Lost` is
    /// only returned if the slot is STILL asleep on `d` after `INFLIGHT`
    /// was read as zero; a slot that is not was woken during the check.
    /// (Census builds before wave 8 lacked the re-read: every `unexplained`
    /// they printed that was followed up was this race.)
    fn sleeper_why(i: usize, d: u64) -> SleeperWhy {
        if INFLIGHT[i].load(Ordering::Acquire) != 0 {
            return SleeperWhy::InFlight;
        }
        let t = unsafe { &*core::ptr::addr_of!(TASKS[i]) };
        if t.context_saving.load(Ordering::Acquire) {
            return SleeperWhy::Saving;
        }
        let current = (0..super::ncpu())
            .any(|c| unsafe { super::PER_CPU[c].current_idx.load(Ordering::Relaxed) } == i);
        if current {
            SleeperWhy::Current
        } else if still_sleeping(i) != Some(d) {
            SleeperWhy::Woken
        } else {
            SleeperWhy::Lost
        }
    }
}

/// `wait::wake_expired_timers` with `sched-timer-heap`: the pure pass
/// `timer_heap::wake_due` (batches of `SCHED_TIMER_WAKE_BATCH`, the lock
/// never held across a wake, the retry re-armed with a deadline read under
/// the lock) over the live heap, waking each popped slot with the sweep's
/// own predicate. The host runner drives the same pass under a model of
/// another hart (`timer_heap`'s `wake_due_*` tests).
#[cfg(feature = "sched-timer-heap")]
pub(crate) fn wake_expired_timers_heap(now_ticks: u64) {
    let due = timer_sleepers::Due::here();
    if !due.ready() {
        return;
    }
    crate::timer_heap::wake_due::<MAX_TASKS, { azos_limits::SCHED_TIMER_WAKE_BATCH }, _>(
        &due,
        now_ticks,
    );
    #[cfg(feature = "ipc-census")]
    timer_sleepers::check_tick(now_ticks);
}

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
//      `task.total_runtime += 1`, before `aps_state::account`, before the
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
/// Read them from `kernel/src/trap/interrupt.rs`'s `[SCHED-DBG]` line via
/// [`preempt_audit::read`].
pub mod preempt_audit {
    use core::sync::atomic::{AtomicU32, Ordering};

    /// `task_yield()` calls refused because a critical section was open.
    pub static YIELD_WHILE_ATOMIC: AtomicU32 = AtomicU32::new(0);
    /// `block_current()` calls refused because a critical section was open.
    /// Any non-zero value names a caller that would sleep holding a spinlock.
    pub static BLOCK_WHILE_ATOMIC: AtomicU32 = AtomicU32::new(0);
    /// `task_exit_with_code()` calls that had to force the depth to 0.
    pub static EXIT_WHILE_ATOMIC: AtomicU32 = AtomicU32::new(0);
    /// Context switches reached with depth != 0. **Must stay zero**: every
    /// path into `context_switch` is supposed to be gated by one of the checks
    /// above. This one is the proof, not the assumption.
    pub static SWITCH_WHILE_ATOMIC: AtomicU32 = AtomicU32::new(0);

    /// Last `block_current` offender: `(tid, depth, wait-reason discriminant)`.
    /// Packed into one word so it can be read without a lock: tid in the low
    /// 16 bits, depth in the next 8, reason tag in the top 8.
    pub static LAST_BLOCK_OFFENDER: AtomicU32 = AtomicU32::new(0);

    /// How many `block_current` refusals still get a console line. After this
    /// many the counter keeps rising silently — a hart that is refusing on
    /// every IPC must not turn the UART into the bottleneck.
    pub const BLOCK_LOG_BUDGET: u32 = 8;

    /// Saturating bump: a diagnostic counter that wraps to zero reads as
    /// "clean" on a board that is anything but.
    #[inline]
    pub(crate) fn bump(c: &AtomicU32) {
        let _ = c.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
            Some(v.saturating_add(1))
        });
    }

    #[inline]
    pub(crate) fn record_block_offender(tid: u32, depth: u32, reason_tag: u8) {
        let packed = (tid & 0xFFFF)
            | ((depth.min(0xFF)) << 16)
            | ((reason_tag as u32) << 24);
        LAST_BLOCK_OFFENDER.store(packed, Ordering::Relaxed);
    }

    /// `(deferred, fired, yield_atomic, block_atomic, exit_atomic,
    ///   switch_atomic, last_block_offender_packed)`.
    ///
    /// `deferred` and `fired` are read straight from `azos_sync::preempt`,
    /// which is the single owner of both. This module briefly kept a shadow
    /// `RESCHED_DEFERRED` that nothing read; it is gone. See
    /// `azos_sync::preempt::FIRED`'s doc for what the pair does and does
    /// NOT tell you about outstanding debt. `underflow`/`hart_oor` stay a separate call
    /// (`azos_sync::preempt::audit_counters()`) rather than folding into
    /// this tuple: those two are must-stay-zero invariants about this
    /// mechanism's own bookkeeping, and `deferred`/`fired` are expected to
    /// grow — mixing the two kinds defeats eyeballing either one.
    pub fn read() -> (u32, u32, u32, u32, u32, u32, u32) {
        (
            azos_sync::preempt::deferred(),
            azos_sync::preempt::fired(),
            YIELD_WHILE_ATOMIC.load(Ordering::Relaxed),
            BLOCK_WHILE_ATOMIC.load(Ordering::Relaxed),
            EXIT_WHILE_ATOMIC.load(Ordering::Relaxed),
            SWITCH_WHILE_ATOMIC.load(Ordering::Relaxed),
            LAST_BLOCK_OFFENDER.load(Ordering::Relaxed),
        )
    }
}

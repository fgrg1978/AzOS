// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
/// Task definitions for the AzOS scheduler.
///
/// Ported from kernel/include/sched.h

pub use azos_limits::MAX_TASKS;

/// The `fork()` hand-off register-file type — ISA-shaped, not one snapshot
/// format smuggled across both.
///
/// riscv64: a plain type ALIAS for `[u64; 32]` — RISC-V's whole
/// user-visible register file (`sp` included, at `x2`) already fits one
/// array, and this is the exact type `arch-riscv64::trap::TrapFrame::regs`
/// itself has, so every existing riscv64 call site (`&frame.regs`,
/// `sret_to_user_forked`'s asm, `set_task_fork_ctx`'s signature) keeps
/// compiling — and generating — byte-for-byte unchanged: a type alias
/// introduces no new nominal type, so nothing here can widen or reshape
/// what riscv64 already had.
///
/// aarch64: [`azos_arch::fork_regs::ForkRegs`] — see that struct's
/// module doc for why AArch64 cannot reuse `[u64; 32]` (SP_EL0, SPSR_EL1,
/// TPIDR_EL0 and the FP/SIMD file are none of them GPRs, and a padded
/// `[u64; 32]` used to silently drop all four on every aarch64 fork).
///
/// Any OTHER target (every host build: this file is `#[path]`-pulled
/// unmodified into `sched-wake-tests` and friends, compiled for the dev
/// machine — `target_os = "none"` excludes that host the same way it
/// already excludes `TaskContext`'s aarch64 fields a few dozen lines below,
/// see that field's own comment) falls back to `[u64; 32]`: no host test
/// exercises the real fork asm, so the RISC-V-shaped array is simply a
/// buildable placeholder there, exactly as riscv64 itself uses.
#[cfg(target_arch = "riscv64")]
pub type UserRegs = [u64; 32];
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub type UserRegs = azos_arch::fork_regs::ForkRegs;
/// x86_64: the 15 GPRs, RSP, RFLAGS, FS/GS bases and an XSAVE image
/// (Kconfig `X86_XSAVE_AREA_BYTES`), see that struct's module doc.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub type UserRegs = azos_arch::fork_regs::ForkRegs<{ azos_limits::X86_XSAVE_AREA_BYTES }>;
#[cfg(not(any(
    target_arch = "riscv64",
    all(target_arch = "aarch64", target_os = "none"),
    all(target_arch = "x86_64", target_os = "none"),
)))]
pub type UserRegs = [u64; 32];

pub const NUM_PRIORITIES: usize = 32;
pub const DEFAULT_PRIORITY: u32 = 16;
pub const IDLE_PRIORITY: u32 = 31;

/// Size of `Task::name`, in bytes. Names are null-terminated ASCII, so the
/// longest storable name is `TASK_NAME_CAPACITY - 1` characters.
pub const TASK_NAME_CAPACITY: usize = 32;

/// High priority for real-time motor control (PID loop).
/// Must run promptly to maintain control loop timing.
pub const RT_MOTOR_PRIORITY: u32 = 8;

/// Priority for the network polling task.
/// Slightly above default so incoming packets are processed promptly.
pub const NET_POLL_PRIORITY: u32 = 12;

/// Priority for the behavior engine (sensor→decision→motor).
/// Above default since it drives the robot's actions.
pub const BEHAVIOR_PRIORITY: u32 = 14;

/// Priority for sensor fusion / AHRS task (~100 Hz).
/// Matches behavior priority — both are critical for control.
pub const SENSOR_AHRS_PRIORITY: u32 = 14;

/// Priority for the flight controller (PID→mixer→ESC).
/// Same as rt-motor — real-time critical.
pub const FLIGHT_CTRL_PRIORITY: u32 = 8;

/// Priority for the system watchdog task.
///
/// **Was 20, and at 20 with default placement the task never ran under load.**
/// Measured 2026-09-10, probe verified present in the binary: on an idle boot
/// `sys-wdt` entered and iterated; with the brain link, a disk and a NIC
/// attached it did not execute one instruction in 50 s. The six things it
/// carries — stack canaries, timer liveness, the physical kill-switch poll,
/// the flight-recorder flush, driver health and the OTA boot-good mark — were
/// all dead exactly when the machine was busy, which is when a watchdog is
/// for.
///
/// **The cause was the COMBINATION, not the priority alone**, and the four
/// runs say so:
///
/// | priority | placement | ran under load |
/// |----------|-----------|----------------|
/// | 20       | default   | **no**         |
/// | 20       | hart 2    | yes            |
/// | 11       | default   | yes            |
/// | 11       | hart 2    | yes            |
///
/// Either change alone breaks the combination. Both are kept so that neither
/// is load-bearing on its own: a watchdog whose survival depends on which hart
/// the placer happened to pick, or on hart 2 staying quiet, is one scheduling
/// change away from being dead again — and it would be dead silently, exactly
/// as it was.
///
/// 11 is chosen, not comfortable: inside the RT band
/// (< `RT_PRIORITY_THRESHOLD`) so a canary sweep is not interrupted by the
/// tick half-way through, and still BELOW the two hard control loops
/// (`RT_MOTOR_PRIORITY` / `FLIGHT_CTRL_PRIORITY` = 8) so the watchdog can
/// never preempt the actuation it supervises.
///
/// And the priority is only half of it: at RT priority the old body — a 500 ms
/// spin on `task_yield` — would starve its own hart, the defect K-C27 closed
/// for the other daemons. It blocks on a timer instead. See
/// `system_wdt_task`.
pub const WATCHDOG_PRIORITY: u32 = 11;
/// Priority threshold separating real-time from normal tasks.
/// Priorities 0..RT_PRIORITY_THRESHOLD are hard real-time (not preempted by timer).
/// Priorities RT_PRIORITY_THRESHOLD..31 are normal (time-sliced round-robin).
pub const RT_PRIORITY_THRESHOLD: u32 = 12;

/// Time slice for RT tasks: 0 means "run until yield or preemption by
/// a higher-priority RT task".  RT tasks are never preempted by the timer.
pub const RT_TIME_SLICE_TICKS: u32 = 0;

/// Each timer tick is 10ms; one tick per time slice (normal tasks only).
pub const TIME_SLICE_TICKS: u32 = 1;

/// Returns true if the given priority is in the hard real-time range.
#[inline]
pub const fn is_rt_priority(prio: u32) -> bool {
    prio < RT_PRIORITY_THRESHOLD
}

/// Stack size for kernel tasks.
/// Sourced from Kconfig `KERNEL_STACK_SIZE_KB` (see config/Kconfig.limits) — with
/// guard page (4 KiB unmapped at bottom), usable size is this minus 4 KiB.
/// Rust kernel tasks with nested calls (PID, flight controller, kprintln
/// formatting) need substantial stack space.
pub const STACK_SIZE: usize = azos_limits::KERNEL_STACK_SIZE_BYTES;

// ---- Register-width type for context ----

pub type CtxReg = u64;

// ---- Task context (callee-saved registers for context switch) ----

/// Saved CPU state during a context switch.
///
/// **MUST be the first field of `Task`** (at offset 0) because
/// `context_switch.S` (per ISA — riscv64's `entry/riscv64/asm/context_switch.S`,
/// aarch64's `entry/aarch64/asm/context_switch.S`) accesses these fields
/// directly from the task pointer.
///
/// **`ra`/`sp`/`pc`/`tp` are cross-ISA and always present** — generic code
/// (`try_task_create_init` in `scheduler.rs`) initialises a fresh task with
/// `TaskContext { sp: stack_top, pc: entry_addr, ra: entry_addr, tp:
/// target_cpu, .. }` with no `#[cfg]` of its own, so every target this
/// struct compiles for must have all four. `ra` is the register a plain
/// `ret`/function-return sequence would use (`x30`/LR on aarch64, `ra` on
/// riscv64); `pc` is the address the asm jumps to on restore — the two
/// coincide except for a never-yet-switched-out fresh task, where both are
/// set to `entry_addr` (`task_entry_wrapper`) so either path lands there.
/// `tp` is NOT a literal GPR on aarch64, and the asm does NOT save/restore
/// it through `TPIDR_EL1` the way it used to (a fixed hazard — see below).
/// `current_cpu_id()` reads `TPIDR_EL1`, an
/// EL1 system register published ONCE per hart by `boot.S` and never
/// written again; `tp` here is pure scheduler bookkeeping ("which CPU this
/// task is logically enqueued on" — `find_best_cpu`/`wake_target_cpu`'s
/// placement heuristic), read and written as plain memory by
/// `crates/core/sched/src/scheduler.rs`. The two used to be conflated —
/// `context_switch.S` treated `TPIDR_EL1` as this ISA's `tp`-equivalent GPR
/// and `mrs`/`msr`'d it on every switch — which let an unpinned task's
/// stale placement record overwrite a physical hart's own identity the
/// first time it was ever dispatched on a hart other than the one its `tp`
/// named. See `entry/aarch64/asm/context_switch.S`'s header comment for the
/// full mechanism and how it was measured.
///
/// **The remaining fields are the ISA's own callee-saved set (AAPCS64 /
/// the RISC-V calling convention), `#[cfg]`-gated so each target's struct
/// carries only its own registers — nothing here changes riscv64's layout
/// or size.** riscv64: `s0..s11` (unchanged from before this struct grew a
/// second ISA). aarch64: `x19..x28` + `x29` (frame pointer; AAPCS64 also
/// makes it callee-saved) as the integer set, plus `d8..d15` — this kernel
/// is hard-float (owner decision 97), so a task's FP/vector state in the
/// callee-saved half of v8-v15 must survive an ordinary function-call-shaped
/// switch exactly like its GPRs do. This is a narrower save than the trap
/// path's (`entry::aarch64::TrapFrame`, V0-V31 + FPSR/FPCR): a trap can
/// interrupt code carrying ANY vector register, but `context_switch` is a
/// plain AAPCS64 call, so only the ABI's callee-saved subset is this
/// function's responsibility — the caller-saved half (v0-v7, v16-v31) is
/// already on the caller's own stack, by the same C-ABI reasoning riscv64's
/// header comment gives for its own caller-saved regs.
///
/// riscv64 offsets (8 bytes each): ra=0, sp=8, ..., pc=112, tp=120 (128
/// bytes total). aarch64 offsets differ (184 bytes total) — both are
/// injected into their own asm via `offset_of!`, never hand-copied; see the
/// `global_asm!` blocks in `kernel/src/main.rs`.
#[repr(C)]
#[derive(Default)]
pub struct TaskContext {
    pub ra:  CtxReg,
    pub sp:  CtxReg,

    #[cfg(target_arch = "riscv64")]
    pub s0:  CtxReg,
    #[cfg(target_arch = "riscv64")]
    pub s1:  CtxReg,
    #[cfg(target_arch = "riscv64")]
    pub s2:  CtxReg,
    #[cfg(target_arch = "riscv64")]
    pub s3:  CtxReg,
    #[cfg(target_arch = "riscv64")]
    pub s4:  CtxReg,
    #[cfg(target_arch = "riscv64")]
    pub s5:  CtxReg,
    #[cfg(target_arch = "riscv64")]
    pub s6:  CtxReg,
    #[cfg(target_arch = "riscv64")]
    pub s7:  CtxReg,
    #[cfg(target_arch = "riscv64")]
    pub s8:  CtxReg,
    #[cfg(target_arch = "riscv64")]
    pub s9:  CtxReg,
    #[cfg(target_arch = "riscv64")]
    pub s10: CtxReg,
    #[cfg(target_arch = "riscv64")]
    pub s11: CtxReg,

    // aarch64 (bare metal only — `target_os = "none"` excludes this host's
    // own aarch64-apple-darwin build, which has no context-switch asm to
    // agree with; see `crates/core/arch-aarch64/src/features.rs` for the same
    // guard used for the same reason).
    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    pub x19: CtxReg,
    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    pub x20: CtxReg,
    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    pub x21: CtxReg,
    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    pub x22: CtxReg,
    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    pub x23: CtxReg,
    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    pub x24: CtxReg,
    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    pub x25: CtxReg,
    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    pub x26: CtxReg,
    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    pub x27: CtxReg,
    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    pub x28: CtxReg,
    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    pub x29: CtxReg,  // frame pointer — callee-saved per AAPCS64

    // x86_64 skeleton (and any further ISA): the SysV callee-saved set,
    // in the order its `context_switch.S` must save it.
    #[cfg(all(target_os = "none", not(any(target_arch = "riscv64", target_arch = "aarch64"))))]
    pub rbx: CtxReg,
    #[cfg(all(target_os = "none", not(any(target_arch = "riscv64", target_arch = "aarch64"))))]
    pub rbp: CtxReg,  // frame pointer
    #[cfg(all(target_os = "none", not(any(target_arch = "riscv64", target_arch = "aarch64"))))]
    pub r12: CtxReg,
    #[cfg(all(target_os = "none", not(any(target_arch = "riscv64", target_arch = "aarch64"))))]
    pub r13: CtxReg,
    #[cfg(all(target_os = "none", not(any(target_arch = "riscv64", target_arch = "aarch64"))))]
    pub r14: CtxReg,
    #[cfg(all(target_os = "none", not(any(target_arch = "riscv64", target_arch = "aarch64"))))]
    pub r15: CtxReg,

    pub pc:  CtxReg,
    pub tp:  CtxReg,  // preserved across context switches so current_cpu_id() stays correct

    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    pub d8:  CtxReg,   // low 64 bits of v8  — the callee-saved half (AAPCS64 §5.1.2)
    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    pub d9:  CtxReg,
    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    pub d10: CtxReg,
    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    pub d11: CtxReg,
    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    pub d12: CtxReg,
    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    pub d13: CtxReg,
    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    pub d14: CtxReg,
    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    pub d15: CtxReg,
    // x86_64 SysV has no callee-saved FP/SIMD register: the ring-3 XMM/YMM
    // state is the FPU path's (saved at the switch, restored on the way to
    // ring 3, never by a #NM trap: FP_XSAVE_EAGER, entry/x86_64/fp.rs).
    #[cfg(all(target_os = "none", not(any(target_arch = "riscv64", target_arch = "aarch64"))))]
    pub _no_callee_saved_fp: [CtxReg; 0],
}

// Compile-time check: TaskContext is 16 fields × register_width (ra,sp,s0-s11,pc,tp)
#[cfg(target_arch = "riscv64")]
const _: () = assert!(core::mem::size_of::<TaskContext>() == 128);

// aarch64: ra,sp (2) + x19..x28 (10) + x29 (1) + pc,tp (2) + d8..d15 (8) = 23
// fields = 184 bytes.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
const _: () = assert!(core::mem::size_of::<TaskContext>() == 184);

// x86_64: ra,sp (2) + rbx,rbp,r12..r15 (6) + pc,tp (2) = 10 fields = 80
// bytes; its context_switch.S takes every offset from `offset_of!`.
#[cfg(all(target_os = "none", not(any(target_arch = "riscv64", target_arch = "aarch64"))))]
const _: () = assert!(core::mem::size_of::<TaskContext>() == 80);

// `context_switch.S` uses `stp`/`ldp` (one instruction moves a REGISTER
// PAIR to/from `[base, base+8]`) for the x19..x28 and d8..d15 runs — cheaper
// than 10+8 separate `str`/`ldr`, and correct only if each pair really is
// 8 bytes apart in `TaskContext`. `#[repr(C)]` with every field the same
// primitive width (`CtxReg = u64`) already guarantees that by construction
// (no reordering, no inter-field padding), but the guarantee is implicit —
// this pins it the same way the size asserts above pin the struct's overall
// shape, so a future field inserted between a pair fails the build instead
// of silently mis-pairing two unrelated registers at runtime.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
const _: () = {
    macro_rules! assert_adjacent {
        ($a:ident, $b:ident) => {
            assert!(
                core::mem::offset_of!(TaskContext, $b)
                    - core::mem::offset_of!(TaskContext, $a)
                    == 8
            );
        };
    }
    assert_adjacent!(x19, x20);
    assert_adjacent!(x21, x22);
    assert_adjacent!(x23, x24);
    assert_adjacent!(x25, x26);
    assert_adjacent!(x27, x28);
    assert_adjacent!(d8,  d9);
    assert_adjacent!(d10, d11);
    assert_adjacent!(d12, d13);
    assert_adjacent!(d14, d15);
};

/// [`Task::queued`]: an `AtomicBool`'s interface over a word (wave 15,
/// SWITCH). RV64 has no sub-word AMO, so a byte flag's `swap` compiled to an
/// aligned-word `amoor`/`amoand` with shift and mask (eight instructions);
/// the claim runs on every enqueue, twice per context switch counting the
/// pick. Zero is `false`, so `mem::zeroed()` stays a valid initial state.
#[repr(transparent)]
pub struct QueuedFlag(core::sync::atomic::AtomicU32);

impl QueuedFlag {
    #[inline(always)]
    pub fn load(&self, order: core::sync::atomic::Ordering) -> bool {
        self.0.load(order) != 0
    }
    #[inline(always)]
    pub fn store(&self, v: bool, order: core::sync::atomic::Ordering) {
        self.0.store(v as u32, order)
    }
    #[inline(always)]
    pub fn swap(&self, v: bool, order: core::sync::atomic::Ordering) -> bool {
        self.0.swap(v as u32, order) != 0
    }
}

// ---- Task state ----

#[repr(u32)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TaskState {
    Ready   = 0,
    Running = 1,
    Blocked = 2,
    Zombie  = 3,
    Invalid = 4,
}

/// K-C26 site tags for [`Task::ready_site`]. Kept next to the field so a new
/// `Ready` writer cannot be added without seeing that it must tag itself.
pub mod ready_site {
    /// `task_create`: fresh slot, plain store (slot not yet visible to wakers).
    pub const CREATE: u8 = 1;
    /// `do_schedule`: the preempted task re-enqueued at its own priority.
    pub const PREEMPT: u8 = 2;
    /// `do_schedule`: K-C24 arm — committed-but-stamped task rescued.
    pub const KC24_RESCUE: u8 = 3;
    /// `wake_transition`: the ordinary Blocked→Ready dispatch.
    pub const WAKE: u8 = 4;
    /// `reap_orphaned_stamp`: the K-C25 reaper.
    pub const REAP: u8 = 5;
    /// `rebalance_from_offline_cpus`: task moved off a dead hart.
    pub const REBALANCE: u8 = 6;

    pub fn name(tag: u8) -> &'static str {
        match tag & 0x0f {
            CREATE => "create", PREEMPT => "preempt", KC24_RESCUE => "kc24",
            WAKE => "wake", REAP => "reap", REBALANCE => "rebalance",
            _ => "none",
        }
    }
}

// ---- K-C19: state + wake stamp, one atomic word ----

/// The scheduling state word: [`TaskState`] and the K-C9 wake stamp packed
/// into one `AtomicU32`, so the two are read and written under the same
/// exclusion — a CAS — instead of as two independently-ordered cells.
///
/// # WHY one word (K-C19)
///
/// With `state: TaskState` and `wake_pending: AtomicBool` as separate cells
/// there were two windows, one per direction, and both were measured hangs:
///
///  * **Blocker side.** `block_current()` consumed the stamp and *then*
///    marked `Blocked`. A waker reading `Running` between those two
///    operations stamped a wake the blocker had already passed by; nobody
///    ever consumed it. Permanent sleep with the wake emitted and counted —
///    the K-C19 signature: a fast-IPC slot `Replied`, addressed to exactly
///    the client sleeping on it, ~1 in 3 runs.
///  * **Waker side.** The double-check handshake (re-check the stamp after
///    `Blocked`, re-read state after stamping) was tried and REVERTED: when
///    the waker wins the stamp `swap` and enqueues while the blocker, having
///    lost that `swap`, continues into `do_schedule`, the task is both
///    "current" and queued — observed as a boot-time freeze. Hanging the
///    board is worse than losing a wake.
///
/// With one word both transitions become *conditional* and *atomic*:
///
///  * Committing `Blocked` is a CAS that requires the stamp bit to be clear.
///    A stamp that lands first makes the CAS fail; the retry consumes it and
///    the block is skipped. It is structurally impossible to commit to
///    `Blocked` past a pending wake.
///  * Stamping is a CAS that requires `state != Blocked`. A commit that
///    lands first makes the CAS fail; the retry observes `Blocked` and
///    dispatches. It is structurally impossible to stamp a task that has
///    already committed.
///
/// Each side's CAS only fails because the other side's succeeded, so the
/// retry loops are bounded in practice by one extra iteration.
///
/// The invariant documented in `wait.rs` — "`Blocked` with the stamp set
/// does not occur" — is enforced by construction here, not by protocol
/// discipline at the call sites.
///
/// These are free functions over `&AtomicU32` (no statics, no CSRs) so the
/// host suite (`tests/host/sched-wake-tests`) exercises the *real* transition
/// code, not a hand-written replica of it.
pub mod sched_word {
    use core::sync::atomic::{AtomicU32, Ordering};
    use super::TaskState;

    /// Bits 0..=2: the `TaskState` discriminant (0..=4).
    pub const STATE_MASK: u32 = 0b0111;
    /// Bit 3: the K-C9 wake stamp ("a wake arrived before you blocked").
    pub const WAKE_STAMP: u32 = 0b1000;

    /// Count of `Blocked + WAKE_STAMP` words made (wrapping): bumped by
    /// [`wake_transition`]'s `!saved` arm after its CAS, Release, so a reader
    /// that sees a new value also sees the stamp. The idle reaper compares it
    /// with the value it last swept at and skips the walk when it has not
    /// moved (w14 RTMAX). Rare path: an unswitched block caught by a wake.
    pub static REAPABLE_STAMPS: AtomicU32 = AtomicU32::new(0);

    /// See [`REAPABLE_STAMPS`].
    #[inline]
    pub fn reapable_stamps() -> u32 {
        REAPABLE_STAMPS.load(Ordering::Acquire)
    }

    #[inline]
    pub const fn pack(s: TaskState) -> u32 { s as u32 }

    /// Decode the state field. Never panics: an out-of-range discriminant
    /// (impossible unless the word is corrupted) decodes to `Invalid`, which
    /// every consumer already treats as "not schedulable".
    #[inline]
    pub const fn state_of(w: u32) -> TaskState {
        match w & STATE_MASK {
            0 => TaskState::Ready,
            1 => TaskState::Running,
            2 => TaskState::Blocked,
            3 => TaskState::Zombie,
            _ => TaskState::Invalid,
        }
    }

    /// What a wake attempt did. The scheduler maps these onto
    /// `wait::WakeAction` bookkeeping; `Skip` has no equivalent here because
    /// addressee selection happens before the word is touched.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub enum WakeTransition {
        /// `Blocked` + matching reason: transitioned to `Ready` — the caller
        /// must now clear `wait_reason` and enqueue.
        Dispatched,
        /// Not `Blocked`: the stamp bit is now set; its imminent
        /// `block_current()` will consume it. (Only when stamping was
        /// requested.)
        Stamped,
        /// `Blocked` on a non-matching reason. Untouched — deliberately no
        /// stamp; see `wait::wake_action`'s Mismatch rationale.
        Mismatch,
        /// Not `Blocked` and stamping was not requested (broadcast wakes).
        /// Untouched.
        NotBlocked,
    }

    /// Blocker side. Called by `block_current()` **after** `wait_reason` is
    /// written; the Release CAS publishes that write to whoever sees
    /// `Blocked` (Acquire) — this pairing replaces the old K-C17 fences.
    ///
    /// Returns `true` if the task committed to `Blocked` (caller proceeds to
    /// `do_schedule`), `false` if a pending wake was consumed instead (caller
    /// must skip blocking — the condition it was about to sleep on is already
    /// satisfied, and every caller re-checks its condition in a loop).
    ///
    /// Defensive arm: if the state is somehow not `Running` (a concurrent
    /// remote transition — no such path exists today), it refuses to
    /// overwrite and lets the caller fall through to `do_schedule`, which
    /// already handles every non-Running current state. The old plain store
    /// would have clobbered e.g. `Zombie` with `Blocked` and leaked the slot.
    #[inline]
    pub fn commit_blocked_or_consume_wake(w: &AtomicU32) -> bool {
        loop {
            let cur = w.load(Ordering::Relaxed);
            if cur & WAKE_STAMP != 0 {
                // Consume AND normalize in one CAS (K-C24). The caller is
                // the current task, so `Running` is the truth; leaving a
                // stale `Blocked` behind on the skip path would let a waker
                // dispatch-and-enqueue a task that is executing — the
                // Ready-in-no-queue starvation this protocol exists to make
                // impossible. Reachable with `Blocked` here: an unswitched
                // block (do_schedule found nothing, we kept running) loops
                // back into a fresh block attempt while the word still says
                // `Blocked`, and a K-C24 stamp may have landed on it.
                // Acquire pairs with the waker's Release stamp: everything
                // the waker published before waking is visible on return.
                if w.compare_exchange_weak(
                    cur, pack(TaskState::Running),
                    Ordering::Acquire, Ordering::Relaxed,
                ).is_ok() {
                    return false;
                }
                continue;
            }
            match state_of(cur) {
                TaskState::Running => {
                    if w.compare_exchange_weak(
                        cur, pack(TaskState::Blocked),
                        Ordering::Release, Ordering::Relaxed,
                    ).is_ok() {
                        return true;
                    }
                    // CAS failed ⇒ a waker just stamped us ⇒ next iteration
                    // consumes the stamp and skips the block.
                }
                // Already `Blocked` (unswitched block looping back in) with
                // no stamp: the commit stands as-is — proceed to
                // do_schedule and keep trying to yield the hart.
                TaskState::Blocked => return true,
                // Defensive (no such remote transition exists today): don't
                // clobber Zombie/Ready — fall through to do_schedule, which
                // handles every non-Running current.
                _ => return true,
            }
        }
    }

    /// Waker side — the one transition every wake path goes through.
    ///
    /// `reason_matches` is evaluated only under an observed-`Blocked`
    /// snapshot; the Acquire load guarantees the `wait_reason` it reads is
    /// the one the blocker published before its Release commit (K-C17).
    /// `stamp_if_unblocked` distinguishes the TID-directed wakes (which may
    /// stamp, K-C9/K-C10) from the broadcast sweeps (which must not — a
    /// sweep cannot tell its addressee from any other task about to sleep;
    /// see `wait.rs`).
    ///
    /// `saved` is the K-C24 gate: `Blocked` alone does NOT mean parked. When
    /// `block_current`'s `do_schedule` finds nothing to run it RETURNS, and
    /// the task keeps executing its caller's retry loop with `state ==
    /// Blocked` and `context_saving == true`. Dispatching it then enqueues a
    /// RUNNING task: its own hart can dequeue it as `next == old` (entry
    /// consumed, no switch), and the next tick's re-enqueue arm only saves
    /// `Running` currents — the task is left `Ready` in no queue, forever.
    /// Measured: the phase-A server (`autorun`) starved exactly this way,
    /// and the 2026-08-22 "Replied + client asleep" residue is the same
    /// mechanism hitting a client. So: `Blocked` + matching reason + NOT
    /// saved ⇒ **stamp, never dispatch** — the target is still running, its
    /// next commit attempt consumes the stamp. If it instead gets parked
    /// with the stamp set (the stamp landed after `do_schedule`'s
    /// switch-away sweep checked), the dispatch CAS below WOULD sweep stamp
    /// and state together on the next wake — but the one-shot wakes have no
    /// next wake, which is why [`reap_orphaned_stamp`] (K-C25) exists: the
    /// timer tick reaps `Blocked + stamp + saved` back to `Ready`. Callers
    /// derive `saved` from `!context_saving` (Acquire); the flag's store
    /// precedes the Release commit in program order, so a waker that READS
    /// THE FLAG AFTER seeing `Blocked` sees the true flag — which is why
    /// `saved` is a closure, called here only once `Blocked` has been
    /// observed. Wave 13 (RT7): it was a `bool` the callers read before the
    /// state; a waker that read `context_saving` before the blocker set it and
    /// `Blocked` after the commit dispatched a task still running on its
    /// hart. The dispatch gate kept its registers safe, but the waker's
    /// `context.tp` store was overwritten by that hart's save: the task then
    /// ran on the waker's target with the old hart's id in `tp`, and its
    /// next `do_schedule` rewrote the OTHER hart's `current_idx` (a task
    /// "Running" on a hart executing idle; a kernel task's name on a hart
    /// executing ring 3). 1 in 10-40 boots of a loaded host. Under `rvv` (which never maintains the flag)
    /// callers pass `true`, keeping that build's documented pre-existing gap
    /// unchanged rather than silently different.
    ///
    /// On `Dispatched` the caller owns the task's dispatch: it must clear
    /// `wait_reason` and enqueue. Exactly one waker can win the CAS, so the
    /// ownership is exclusive.
    #[inline]
    pub fn wake_transition(
        w: &AtomicU32,
        mut reason_matches: impl FnMut() -> bool,
        stamp_if_unblocked: bool,
        mut saved: impl FnMut() -> bool,
    ) -> WakeTransition {
        loop {
            let cur = w.load(Ordering::Acquire);
            if state_of(cur) == TaskState::Blocked {
                if !reason_matches() {
                    return WakeTransition::Mismatch;
                }
                if !saved() {
                    // K-C24: committed but still running (unswitched block).
                    // Stamp — even for broadcast sweeps: having matched the
                    // reason under Blocked, this IS the addressee. CAS, not
                    // fetch_or, so a concurrent commit-consume retries
                    // against us and the pairing stays exact.
                    if w.compare_exchange_weak(
                        cur, cur | WAKE_STAMP,
                        Ordering::Release, Ordering::Relaxed,
                    ).is_ok() {
                        // The only producer of `Blocked + WAKE_STAMP`: count
                        // it here, not in the callers, so the idle reaper's
                        // safety net sees a stamp whose caller forgot the
                        // flag (`scheduler::reap_idle_sweep`).
                        REAPABLE_STAMPS.fetch_add(1, Ordering::Release);
                        return WakeTransition::Stamped;
                    }
                    continue;
                }
                // AcqRel: Acquire so the dispatch bookkeeping after the win
                // sees the blocker's writes; Release so the Ready transition
                // is ordered before the enqueue that publishes it.
                if w.compare_exchange_weak(
                    cur, pack(TaskState::Ready),
                    Ordering::AcqRel, Ordering::Relaxed,
                ).is_ok() {
                    return WakeTransition::Dispatched;
                }
                // Lost to a competing waker (state moved on) — retry.
            } else if stamp_if_unblocked {
                // Idempotent by re-CAS: if the stamp is already set this
                // rewrites the same value. Release pairs with the blocker's
                // Acquire consume.
                if w.compare_exchange_weak(
                    cur, cur | WAKE_STAMP,
                    Ordering::Release, Ordering::Relaxed,
                ).is_ok() {
                    return WakeTransition::Stamped;
                }
                // CAS failed ⇒ the blocker just committed `Blocked` ⇒ the
                // retry observes it and dispatches. This is the exact
                // closure of K-C19's waker-side half.
            } else {
                return WakeTransition::NotBlocked;
            }
        }
    }

    /// Reaper side (K-C25) — recover a *parked* task whose wake was delivered
    /// as a K-C24 stamp and then orphaned.
    ///
    /// `wake_transition`'s `!saved` arm stamps a `Blocked` task that is still
    /// executing (unswitched block). Its doc argued the stamp is consumed
    /// either by the target's next commit, by `do_schedule`'s switch-away
    /// sweep, or by "the next wake's dispatch CAS, which sweeps stamp and
    /// state together". That last leg silently assumed a next wake exists.
    /// For the one-shot wakes (`fast_ipc_reply`'s client wake, the FAST_CALL
    /// doorbell once every client is asleep, lease returns)
    /// there is none: a stamp that lands in the window between the sweep's
    /// check and context_switch.S clearing `context_saving` parks the task as
    /// `Blocked + WAKE_STAMP` with the context fully saved — a state no
    /// commit will consume (not running), no sweep will convert (not
    /// switching), and no wake will dispatch (none is coming). Measured on
    /// QEMU `-icount`: phase A of `ipctest` wedges with the reply deposited
    /// and the client in exactly this state (2026-08-24).
    ///
    /// This transition is the missing consumer: `Blocked + WAKE_STAMP` →
    /// `Ready` (stamp cleared) in one CAS. The caller must verify TWO things
    /// first, and the CAS is only sound with both:
    ///
    ///  * `context_saving == false` — while the flag is true the target may
    ///    still be executing its retry loop, and its own
    ///    `commit_blocked_or_consume_wake` or the switch-away sweep still
    ///    owns the stamp.
    ///  * the task is **current on no hart** — the word has no generation,
    ///    so `Blocked+STAMP` can recur as the same bit pattern across a full
    ///    consume→run→re-block→re-stamp cycle, and `context_saving` sampled
    ///    in that window reads false (ABA, measured 2026-08-24: the first
    ///    reaper version enqueued the still-executing phase-A server, which
    ///    then parked `Ready` in no queue). Non-currency is what a recycled
    ///    pattern cannot fake: a parked `Blocked` task only becomes current
    ///    again by first leaving `Blocked`, which fails this CAS.
    ///
    /// With both checks a lost race here just means someone else delivered
    /// the wake, which the `false` return reports.
    ///
    /// Returns `true` if this call performed the recovery (the caller now
    /// owns the dispatch: clear `wait_reason`, enqueue — same contract as
    /// `WakeTransition::Dispatched`).
    #[inline]
    pub fn reap_orphaned_stamp(w: &AtomicU32) -> bool {
        loop {
            let cur = w.load(Ordering::Acquire);
            if cur & WAKE_STAMP == 0 || state_of(cur) != TaskState::Blocked {
                return false;
            }
            // AcqRel for the same reasons as the dispatch CAS in
            // `wake_transition`: Acquire so the dispatch bookkeeping sees the
            // blocker's writes, Release so Ready is ordered before the
            // enqueue that publishes it.
            if w.compare_exchange_weak(
                cur, pack(TaskState::Ready),
                Ordering::AcqRel, Ordering::Relaxed,
            ).is_ok() {
                return true;
            }
        }
    }

    /// Scheduler-side state change (Running/Ready/Zombie transitions made by
    /// the owning hart or under a queue lock). Preserves the stamp bit — a
    /// wake stamped while a task is Ready or Running must survive until its
    /// next `block_current()` consumes it, exactly as the separate
    /// `wake_pending` cell used to.
    #[inline]
    pub fn set_state(w: &AtomicU32, s: TaskState) {
        // `Ready` packs to 0, so its transition is `cur & WAKE_STAMP`: one
        // atomic AND (`amoand.w` / `ldclr`) instead of a load and a CAS loop
        // — wave 15 (SWITCH), once per context switch. Exact: the word holds
        // only the state bits and the stamp.
        const _: () = assert!(pack(TaskState::Ready) == 0 && STATE_MASK | WAKE_STAMP == 0xF);
        if s == TaskState::Ready {
            w.fetch_and(WAKE_STAMP, Ordering::Relaxed);
            return;
        }
        let mut cur = w.load(Ordering::Relaxed);
        loop {
            match w.compare_exchange_weak(
                cur, (cur & WAKE_STAMP) | pack(s),
                Ordering::Relaxed, Ordering::Relaxed,
            ) {
                Ok(_) => return,
                Err(now) => cur = now,
            }
        }
    }
}

// ---- Wait reason (AQ0: IO-wait scheduler) ----

/// Why a task is blocked. Used by wake functions to selectively unblock.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum WaitReason {
    /// Not waiting (task is Ready/Running).
    None,
    /// Waiting for a specific IRQ from the PLIC.
    Irq(u32),
    /// Waiting for data on a channel handle.
    Channel(u32),
    /// Waiting for data on a ring buffer.
    Ring(u32),
    /// Waiting until a timestamp (CLINT ticks).
    Timer(u64),
    /// Waiting on an event port (any bound source).
    Port(u32),
    /// Waiting on a WaitQueue/Completion (woken by TID).
    WaitQueue,
    /// Waiting for a fast IPC call to arrive (server side).
    /// u32 = this server's own TID (for targeted wake).
    FastIpcServer(u32),
    /// Waiting for a fast IPC reply from the server (client side).
    /// u64 = the generation-tagged exchange HANDLE (57-bit generation +
    /// 6-bit slot index, bit 63 clear — the encoding lives in
    /// `crates/core/ipc/src/fast_ipc.rs`), NOT a bare slot index. Carrying the
    /// handle is the client-side half of the slot-ABA closure: a wake for
    /// the exchange that died in a seat can never match the client of the
    /// exchange that re-let it.
    FastIpcClient(u64),
    /// Waiting in `SYS_IPC_LEASE_ACCEPT` for a lease (lessee side).
    /// `(lessee, lessor)`: the first field is this task's own TID (the
    /// addressee of `wait::wake_lease_acceptor`, as `wake_task_by_tid`'s
    /// selector invariant requires); the second is the lessor the accept
    /// names, so a grant from any other lessor does not dispatch it.
    LeaseAccept(u32, u32),
}

// Syscall filter (AQ11) and creation-time init parameters live in
// `filter.rs` so host tests can reach them without the TCB. Re-exported
// here because the whole tree refers to them as `crate::task::…`.
pub use crate::filter::{SyscallFilter, TaskInit, SYSCALL_FILTER_MAX};

// ---- Task Control Block (TCB) ----

/// Task Control Block.
///
/// `#[repr(C, align(64))]` ensures deterministic field layout and
/// cache-line alignment for performance.
///
/// `context` MUST remain at offset 0.
#[repr(C, align(64))]
pub struct Task {
    // == offset 0: context (MUST be first for context_switch.S) ==
    // 128 bytes on riscv64, 184 on aarch64 (bare metal) — see
    // `TaskContext`'s own doc comment for why the two ISAs differ and the
    // tripwire asserts a few dozen lines below this struct for the exact
    // per-target `tid` / `TASK_SATP_OFFSET` numbers that follow from it.
    pub context:    TaskContext,

    // == task metadata (offset 128 on riscv64; see the struct-level note
    // on `context` above for why this shifts on aarch64) ==
    pub tid:        u32,
    /// K-C19: [`TaskState`] + wake stamp, packed — see [`sched_word`].
    /// Same size and alignment as the plain `TaskState` field it replaced
    /// (`repr(u32)` enum → `AtomicU32`), so the `repr(C)` layout is
    /// unchanged. Zero-initialized = `Ready` + no stamp, which is the same
    /// default the two separate fields had.
    pub state_word: core::sync::atomic::AtomicU32,
    /// `AtomicU32`, `Relaxed` — same treatment as `TASK_VALID` and the ring,
    /// and for the same reason: `pi_boost_task`, `pi_restore_task`,
    /// `boost_ready_task` and `restore_ready_task` all write this field with
    /// no `POOL_LOCK` or `CPU_LOCKS[cpu]` held (see their doc comments — the
    /// donation protocol is deliberately lock-free), while `ring_claim_audit`,
    /// `current_snapshot`, `task_census`, `ready_unqueued_ids`,
    /// `find_best_cpu` and the SCHED-RT pick (`rt.rs`) all read it with no lock
    /// either, several from the timer ISR. A plain `u32` read racing a plain
    /// `u32` write is undefined behaviour regardless of outcome; `Relaxed`
    /// legalises it without changing any caller's behaviour — every reader
    /// already tolerated a stale value (this is a scheduling *hint* raced
    /// against a live donation, not a value anything synchronises on), and
    /// `AtomicU32::load/store(Relaxed)` compiles to the same `lw`/`sw` as the
    /// plain field on RV64. Same size and alignment as `u32`, so this does
    /// not move `base_priority` or anything declared after it.
    ///
    /// Unlike `TASK_VALID`, converting this stayed inside `scheduler.rs`/
    /// `task.rs` for a documented reason, not an assumption: `priority` is a
    /// `pub` field, but nothing outside this crate ever names `Task` at all
    /// (`azos_sched::task::Task` is reachable in principle — `task` is a
    /// `pub mod` — but grepping the tree turns up zero uses of it outside
    /// `crates/core/sched/`), and the other modules of this crate that look like
    /// they touch a task's priority (`policies/*.rs`, `aps_state.rs`) operate
    /// on their own `TaskMeta` struct (`policies/mod.rs`), not this one.
    /// Everything that reads a task's priority from outside `scheduler.rs`
    /// goes through a function here that already returns a plain `u32`
    /// (`task_priority`, `pi_mutex`'s registered callbacks) or a `kprintln!`
    /// argument — no caller's signature changes.
    pub priority:      core::sync::atomic::AtomicU32,
    /// `AtomicU32` for the same reason as `priority`, and specifically
    /// because of `priority`: `pi_restore_task` reads this field with no lock
    /// to feed `priority`'s own atomic store (`TASKS[i].priority.store(
    /// TASKS[i].base_priority, ..)`), and `restore_ready_task` does the same.
    /// Both calls are on the unlocked donation path documented on `priority`.
    /// Leaving `base_priority` a plain field would have meant `priority`'s
    /// store — now legal in isolation — was still fed by a racing plain read
    /// one expression to its right; converting `priority` without this one
    /// would have moved the UB sideways rather than removed it. Written at
    /// task creation (`task.base_priority = priority` in
    /// `try_task_create_init`, under `POOL_LOCK`, before the slot is
    /// published) and, since wave 7, once more by the task ITSELF when the
    /// autorun loader applies its topology row
    /// (`scheduler::set_current_sched_params`, interrupts off). Neither write
    /// has a concurrent writer: the donation paths only READ this field.
    pub base_priority: core::sync::atomic::AtomicU32,  // original priority (for PI restore)
    pub time_slice:    u32,      // remaining ticks for current slice
    pub cpu_affinity:  i8,       // -1 = any CPU, 0..NR_CPUS-1 = pinned to that hart
    pub _pad:          [u8; 3],  // explicit padding for repr(C) alignment

    // == name ==
    pub name: [u8; TASK_NAME_CAPACITY],  // null-terminated ASCII

    // == stack info ==
    pub stack_idx:  usize,       // index into TASK_STACKS[]

    // == entry point ==
    pub entry_fn:  usize,        // fn ptr cast to usize
    pub entry_arg: usize,        // argument (raw pointer or integer)

    // == statistics ==
    pub total_runtime: u64,      // total timer ticks consumed

    // == IO-wait reason (AQ0) ==
    pub wait_reason: WaitReason,

    // == Syscall filter (AQ11) ==
    pub syscall_filter: SyscallFilter,

    // == user-space state (Phase 7 — requires MMU) ==
    pub task_satp: u64,
    pub user_pt:   u64,
    pub user_brk:  u64,

    /// Owner decision 102 — frames this task currently owns, in 4 KiB pages,
    /// the budget it may not exceed (`0` = no limit), and the high-water
    /// mark since this address space was created.
    ///
    /// Scan unit 3 finding 3: CPU has quotas and memory had none, so a single
    /// ring-3 task could walk `brk` until the allocator was empty and take
    /// the kernel heap, the copy-on-write break and every allocating safety
    /// path down with it.
    ///
    /// **`used` is charged where a frame becomes this task's, and discharged
    /// where it stops being.** Over-counting is the dangerous direction — a
    /// task that is refused memory it is entitled to — so the discharge side
    /// (`sys_munmap`, and the wholesale reset at exec and exit) is not
    /// optional bookkeeping, it is what keeps the quota from ratcheting a
    /// long-lived task to a standstill.
    ///
    /// `peak` exists because `autorun`'s 2048 pages was chosen with headroom
    /// precisely because no peak had ever been measured; it survives
    /// `munmap`/`free` so it answers "how much did this task ever need at
    /// once", which is the number a budget has to clear. Reset together with
    /// `used` at exec and exit — a peak from a previous image says nothing
    /// about this one.
    ///
    /// [`azos_mm::budget::PageBudget`] — the arithmetic itself, with host
    /// test coverage in `tests/host/mm-tests` (`#[path]`-pulls `budget.rs`
    /// unmodified). Plain fields, not atomic: every writer is the task
    /// itself, running on one hart inside a syscall, exactly like `user_brk`
    /// beside it — so no `unsafe`/layout hazard from embedding a non-`repr(C)`
    /// struct here, and `TASKS: [Task; MAX_TASKS]`'s `core::mem::zeroed()`
    /// init stays valid (`PageBudget`'s all-zero pattern is its `Default`).
    pub budget: azos_mm::budget::PageBudget,

    // == AZOS Phase 1 W4-int — multi-policy scheduler metadata ==
    //
    // Appended at the end of the struct so the auto-injected
    // TASK_SATP_OFFSET used by context_switch.S stays stable.
    //
    // Stored as raw bytes (no `SchedClass` type import here) to keep
    // `task.rs` free of dependencies on the policy module hierarchy.
    // Helpers below convert to/from the typed enum.
    /// RFC-0004 scheduler-class discriminant. Defaults to
    /// `SchedClass::BestEffort` (= 3) so existing `task_create` calls
    /// continue to behave like CFS-style fair-share.
    pub sched_class_raw: u8,
    /// RFC-0047: the syscall table this task's numbers are read against,
    /// [`ABI_NATIVE`] (0, the all-zero initial state) or [`ABI_LINUX`]. Set
    /// at slot creation from `TaskInit::abi` (a spawn whose topology row
    /// says `abi = "linux"`), under `POOL_LOCK` and before the task is
    /// runnable; never changed after. A Linux task cannot fork yet (no
    /// `clone` translation), so no fork path copies it.
    /// `scheduler::set_current_task` folds it into the per-CPU filter word.
    /// Taken from what was padding: no offset and not the size moves.
    pub abi: u8,
    /// Explicit padding for repr(C) alignment.
    pub _sched_pad: [u8; 2],
    /// Per-task round-robin / CBS quantum in microseconds. `0` ⇒ use
    /// the policy's default quantum.
    pub sched_time_slice_us: u32,
    /// Absolute deadline in monotonic microseconds. `0` ⇒ "no
    /// deadline" (sentinel; real deadlines after boot are never 0).
    /// Read by the EDF + CBS policy.
    pub sched_deadline_us: u64,

    // == SMP context-switch safety (task-lifecycle race fix) ==
    //
    // `true` while this task's `context` field is mid-transition: its
    // state was just changed away from Running (blocked, or preempted
    // and re-enqueued) but `context_switch.S` has not yet finished
    // saving its registers. A waker on another hart must not dispatch
    // this task while `true` — cleared by the `fence rw, w` + `sb zero`
    // tail of the save path in `context_switch.S` (K-C23: the clear must
    // not be a Rust call, because a call runs on the OLD task's stack
    // after the store has published that stack as reusable); see the
    // spin-gate in `do_schedule()`.
    //
    // The static `TASKS` array is zero-initialized via
    // `core::mem::zeroed()` (see scheduler.rs), so `false` MUST be the
    // safe/default value — a freshly created task has never been
    // "saved" by context_switch.S and must still be dispatchable.
    pub context_saving: core::sync::atomic::AtomicBool,

    // == K-C9 note: the wake stamp lives in `state_word` now ==
    //
    // The lost-wakeup stamp ("a wake arrived between becoming wake-able and
    // committing to Blocked") used to be a separate `wake_pending:
    // AtomicBool` here. K-C19 showed that two independently-ordered cells
    // cannot close the race in either direction — the stamp and the state
    // must move under one CAS. It is now bit 3 of `state_word`; see
    // [`sched_word`] for the full protocol and the history.

    // == K-A15: fork() child hand-off, per-task instead of one global slot ==
    //
    // `sys_fork_impl()` (parent) writes where the newly created child should
    // resume in userspace (entry PC + user SP + child's own SATP);
    // `fork_child_entry()` (child, on whatever hart it gets dispatched to)
    // reads it back and SRETs there. This used to be a single global
    // `Option<ForkChildCtx>` slot: two concurrent forks (different parent
    // tasks, different harts) could overwrite each other's context before
    // either child read it back — a child could SRET with a *different*
    // process's SATP. Storing it on the CHILD's own Task struct (indexed by
    // its own, exclusively-owned pool slot) removes any cross-fork
    // ambiguity: only the one parent that created this child ever writes
    // these fields, and only this child ever reads them.
    //
    // `fork_ctx_ready` is the publish flag: the parent writes
    // entry/user_sp/satp first, then stores `true` here (Release); the
    // child polls it (Acquire) and only reads the payload fields once it
    // observes `true` — same publish protocol as `context_saving`. This
    // closes the residual window where the child is dispatched (e.g. on an
    // idle hart) before the parent — still running the tail of
    // sys_fork_impl() — has finished writing: instead of finding `None` and
    // silently exiting (the old bug), the child yields and retries a
    // bounded number of times.
    pub fork_ctx_ready:  core::sync::atomic::AtomicBool,
    pub fork_entry:      u64,
    pub fork_user_sp:    u64,
    pub fork_satp:       u64,
    /// The parent's complete user register file at the moment of its `ecall`
    /// (`x0..x31`, in trap-frame order) — [`UserRegs`], an ISA-shaped type:
    /// on riscv64 a plain `[u64; 32]` alias (RISC-V's whole user-visible
    /// register file, `sp` included, fits in that array — the same one
    /// `arch-riscv64::trap::TrapFrame::regs` uses, so this field and that
    /// trap frame share a type, not just a shape); on aarch64
    /// [`azos_arch::fork_regs::ForkRegs`] — 31 GPRs plus `SP_EL0`,
    /// `SPSR_EL1`, `TPIDR_EL0` and the full FP/SIMD file, none of which fit
    /// in `[u64; 32]` (see that struct's module doc for why aarch64 cannot
    /// reuse RISC-V's shape: an EARLIER version of this field did — a
    /// zero-padded `[u64; 32]` that silently dropped the FP file and
    /// `TPIDR_EL0` on every aarch64 fork).
    ///
    /// **WHY the whole file and not just entry/sp (K-C11).** The child used to
    /// enter user mode through `sret_to_user`, which writes `sepc`, `sstatus`,
    /// `sscratch`, `satp` and `sp`, and zeroes `a0..a7`. Nothing restored `ra`,
    /// `gp`, `tp`, `t0..t6` or `s0..s11`, so the child resumed *the parent's
    /// own code* holding whatever the kernel task that dispatched it had left
    /// in those registers. Two consequences, both observed from ring 3:
    ///
    ///  * **Correctness.** `fork()` returns into the middle of a function, and
    ///    the compiler keeps live values in callee-saved registers across the
    ///    `ecall`. A loop counter, a base address, a captured TID — all garbage
    ///    in the child. Measured: with the child index held in an `s` register,
    ///    every one of eight children believed it was child 0.
    ///  * **Disclosure.** The garbage is *kernel* state. `ra` was observed
    ///    arriving in user mode holding `0x8020198a`, a kernel text address —
    ///    a layout oracle handed to an unprivileged task on every fork.
    ///
    /// Costs 256 bytes per task slot on riscv64 (16 KiB at `MAX_TASKS` = 64),
    /// 800 bytes on aarch64 (50 KiB at `MAX_TASKS` = 64 — the FP/SIMD file
    /// alone is 528 of those bytes), in BSS.
    ///
    /// Only the fork path uses this. A fresh `exec` still goes through
    /// `sret_to_user` and still zeroes the argument registers, which is both
    /// correct (the ELF entry ABI defines nothing) and what keeps that path
    /// from leaking the same kernel state.
    pub fork_regs:       UserRegs,

    // == K-C21: exec() hand-off, per-task instead of one global slot ==
    //
    // `exec_user()` writes where the CURRENT task's fresh address space
    // starts (entry PC, user SP, initial SSTATUS, new SATP); the same task
    // consumes it moments later — at the tail of its own ecall arm (ring-3
    // callers) or straight after `exec_user` returns (kernel tasks: shell,
    // autorun). This used to be one global `SpinLock<Option<ExecContext>>`
    // drained at the end of EVERY U-mode ecall on EVERY hart: any other hart
    // finishing any syscall inside the window stole the context and SRET'd
    // into an address space that was never its own, while the real exec'er —
    // whose `task_satp` had already been switched — resumed its old sepc
    // under the new page table. Two concurrent SYS_EXECs also overwrote the
    // slot and leaked the first page table. Same shared-slot class K-A15
    // removed for fork; exec had been left behind.
    //
    // Unlike the fork trio there is no identity check: fork's writer
    // (parent) and reader (child) are different tasks on possibly different
    // harts, with a slot-reuse window in between — here writer and reader
    // are the SAME task inside the SAME syscall/trap, so the slot cannot be
    // reused or read by anyone else mid-flight. `exec_ctx_ready` still
    // publishes with Release/Acquire like `fork_ctx_ready` (cheap, and it
    // keeps the protocol uniform), and `task_create` clears it on slot
    // reuse. Zero-init (`false`) MUST stay the safe default: a fresh task
    // has no pending exec.
    pub exec_ctx_ready:  core::sync::atomic::AtomicBool,
    pub exec_entry:      u64,
    pub exec_user_sp:    u64,
    pub exec_sstatus:    u64,
    pub exec_satp:       u64,
    /// K-C22: the address space this task is abandoning (its pre-exec
    /// `user_pt`; 0 when a kernel task execs for the first time). Carried
    /// through the hand-off because only the CONSUMER may destroy it — after
    /// the hart's satp points at the new page table, never before. See
    /// `process::take_current_task_exec_ctx` for the full safety argument.
    pub exec_old_pt:     u64,

    // == priority-inheritance donation count ==
    //
    // Number of LEASE donations currently active on this task. Incremented by
    // every `boost_ready_task`, decremented by the matching
    // `restore_ready_task` — that pair is strictly balanced (one boost, one
    // restore, per donor: a `lease_wait_return` lessor or a user-driver proxy
    // client, both through `donate_priority`/`return_donation`). `priority`
    // returns to `base_priority` only when this reaches 0.
    //
    // The PiMutex path (`pi_boost_task`/`pi_restore_task`) counts too, since
    // `PiMutex` became edge-triggered (one donation per waiter per
    // acquisition, one restore per donation — see `pi_boost_task`'s own
    // comment). It used to re-assert its boost on a timer, and while it did,
    // counting would have drifted the counter upward without bound.
    //
    // Without it, restores clobber each other. Two lessors donating to the same
    // lessee (`ipc/lease.rs`) each remember the priority they *observed* before
    // boosting, and nothing forces them to restore in LIFO order — each blocks
    // on its own lease id, and leases can be returned in any order. If the
    // outer donor restores first it drops the lessee below the inner donor's
    // level (reopening the very inversion that donation paid to avoid), and the
    // inner donor then restores to a stale value, leaving the task boosted
    // forever. Counting makes restore order irrelevant.
    //
    // The trade is deliberate: a task stays at the *highest* donation until the
    // last donor leaves, so it can be over-boosted briefly. That is bounded and
    // harmless; under-boosting reopens priority inversion and a leaked boost is
    // permanent. Fail towards over-boosting.
    //
    // Atomic because `boost_ready_task`/`restore_ready_task` are a documented
    // exception to this crate's POOL_LOCK discipline (see the module header):
    // they touch `TASKS[]` without holding it. A plain `u32` read-modify-write
    // would let two harts donating to the same task concurrently lose an
    // increment, and an undercounted task restores early — reintroducing the
    // exact clobber this field exists to prevent. It stays atomic (readers
    // outside the donation lock), but since wave 9 its read-modify-write
    // happens under the slot's donation lock, together with `priority`'s.
    //
    // `priority` is `AtomicU32` too (see its own doc), which closes the DATA
    // RACE next to this one — the individual load and the individual store
    // are each legal. Two donors racing each other are serialised by the
    // donation lock, so both land: the task ends at the more urgent of the two.
    //
    // The window that used to stay open — a boost racing the LAST restore,
    // landing between the restore's count-to-0 and its base-priority store
    // and being overwritten by the base — is closed since wave 9: every boost
    // and restore of this pair (lease, proxy and PiMutex donors alike) runs
    // under the slot's donation lock (`scheduler::DONATION_LOCKS`, protocol in
    // `donation::boost_locked`/`restore_locked`), held across the run-queue
    // re-bucketing and its IPI. The host suite forces that interleaving
    // (`tests/host/sched-wake-tests`, `donation_race_tests`).
    //
    // Declared last by convention, not by necessity — and the difference
    // matters, because the version of this note that said "everything above
    // `task_satp` is layout-frozen against `TASK_SATP_OFFSET` in
    // context_switch.S" was FALSE and caused a wrong fix on 2026-09-07. The
    // assembly is handed that offset by `offset_of!` at the injection site
    // (the `global_asm!` blocks in `kernel/src/main.rs`), so it cannot go stale. What the assert
    // at the bottom of this file does is make a layout change deliberate.
    // Appending is still the right habit: it keeps the diff of a new field to
    // one place and the tripwire to one number. `AtomicU32` matches `u32` in
    // size and alignment, and zero-init via `mem::zeroed()` is valid for it.
    pub donation_count: core::sync::atomic::AtomicU32,

    /// K-C12 · `true` while this task occupies **exactly one** slot in
    /// **exactly one** per-CPU ready queue.
    ///
    /// **WHY.** `PrioQueue` is a fixed ring of `MAX_TASKS` entries and
    /// `cpu_enqueue` used to guard it with a `debug_assert!`, which release
    /// builds compile away: a full queue silently overwrote a live entry and
    /// pushed `count` past the ring, so ready tasks vanished with no error and
    /// `count` stopped describing the buffer. Under `panic = "abort"` the
    /// alternative — asserting for real — is a board reset, which on a robot
    /// is a physical-safety event, so neither "corrupt" nor "panic" is an
    /// acceptable answer.
    ///
    /// This flag removes the question instead of answering it. There are only
    /// `MAX_TASKS` task slots, so as long as no task is queued twice, the
    /// ready queues of one CPU can hold at most `MAX_TASKS` entries in total
    /// and a single-priority ring of that size **cannot** overflow. The flag
    /// is what enforces "no task queued twice" in O(1): `cpu_enqueue` *claims*
    /// it with an atomic swap and refuses when it was already set. A claim and
    /// not a test-then-set, because `CPU_LOCKS` only serializes enqueues onto
    /// one CPU — two harts enqueueing the same task onto two different CPUs
    /// hold different locks, so the swap is the only thing arbitrating between
    /// them.
    ///
    /// Refusing a duplicate never loses a wakeup, and that is the whole
    /// safety argument: the flag is only set while an entry for this task is
    /// actually sitting in a queue, so a refused enqueue is refused *because
    /// the task is already dispatchable*. Cleared by `cpu_dequeue` (the only
    /// pop), by `cpu_remove` (the priority re-bucketing path) and at slot
    /// allocation, since pool slots are recycled and a stale `true` would
    /// make the new occupant permanently un-enqueueable — i.e. exactly the
    /// silent starvation this field exists to prevent.
    ///
    /// Zero-init via `mem::zeroed()` gives `false`, which is correct: a fresh
    /// task is in no queue. Declared after `donation_count` for the same
    /// layout-freeze reason documented there. A word ([`QueuedFlag`]) since
    /// wave 15: the claim is one `amoswap.w` instead of a masked byte AMO.
    pub queued: QueuedFlag,

    /// K-C26 provenance: who last set this task `Ready`, and on which hart.
    ///
    /// Low nibble = site tag (see `ready_site`), high nibble = hart id. Written
    /// with a relaxed store right after every transition to `Ready`; read only
    /// by the census when it finds a task Ready-in-no-queue.
    ///
    /// **WHY.** Four unrelated tasks — different priorities, different home
    /// harts, one of them real-time — were observed Ready-and-unqueued in the
    /// same census sample. Every candidate genesis so far has been eliminated
    /// (the reap, refused enqueues, the unlocked donation path), so the next
    /// question is not *which* mechanism but *which writer*: there are only
    /// five places in the tree that publish `Ready`, and a common one across
    /// four simultaneous victims would be conclusive. Relaxed is deliberate —
    /// this must not add ordering to the paths it observes.
    pub ready_site: core::sync::atomic::AtomicU8,

    /// Context switches this task gave up voluntarily — it yielded, blocked
    /// or exited — counted only when a switch ACTUALLY happened.
    ///
    /// The pair mirrors Linux's `voluntary_ctxt_switches` /
    /// `nonvoluntary_ctxt_switches` in `/proc/self/status`, deliberately: the
    /// only reason to expose a number is so it can be compared with the number
    /// it is measured against, and a yield that found nothing better to run is
    /// not a context switch on either system.
    pub switches_voluntary: core::sync::atomic::AtomicU64,
    /// Context switches the timer took from it.
    pub switches_preempted: core::sync::atomic::AtomicU64,

    /// This task's reservations in the shm/MMIO VA window, as `[base, span]`
    /// pairs ([`crate::user_window`]; `span == 0` is a free pair, so the
    /// zeroed pool starts empty). Written by the task's own shm and MMIO map
    /// and release calls, and cleared when the slot is reused, next to
    /// `user_brk`. Exec leaves it alone: a shm mapping record survives exec
    /// with its address, and the release that names that address must not
    /// find it handed to another mapping. Appended at the end so
    /// `TASK_SATP_OFFSET` stays stable.
    pub user_window: [[usize; 2]; crate::user_window::USER_WINDOW_RANGES],

    /// RFC-0049 M1 (wave 8): the memory state beside `budget` that the
    /// charging paths and the locked-row policy need. Appended at the end so
    /// `TASK_SATP_OFFSET` stays stable; all-zero is its initial state.
    pub mem: TaskMem,

    /// A Zombie slot this task frees when it next resumes, plus one (0:
    /// none). Set by the hart that switches from that Zombie to this task,
    /// read and cleared by this task right after the switch, on its own
    /// stack (`scheduler::finish_switch`). Appended at the end so
    /// `TASK_SATP_OFFSET` stays stable; 0 is its initial state.
    pub reap_on_resume: usize,
}

/// [`Task::abi`]: the native AzOS syscall table.
pub const ABI_NATIVE: u8 = 0;
/// [`Task::abi`]: Linux syscall numbers, translated (RFC-0047).
pub const ABI_LINUX: u8 = 1;

/// RFC-0049 M1: per-task memory accounting that is not the budget itself.
#[derive(Debug, Default)]
#[repr(C)]
pub struct TaskMem {
    /// Page-table frames this task allocated for an address space that is
    /// NOT its own yet (exec, spawn and fork build the new one before it is
    /// installed). Taken and charged to the task that receives the address
    /// space (`scheduler::take_current_pt_build`); written only by this task.
    pub pt_build: u32,
    /// Page faults resolved for this task in user mode (COW breaks and
    /// demand faults). A `locked` task must end with 0; the gate reads it.
    pub faults: u32,
    /// Frames freed on this task's behalf by ANOTHER task (the last holder
    /// of a shared-memory region it created, say), not yet taken off
    /// `budget`. Posted with `fetch_add` by that task and folded in by this
    /// task at its next charge, so `budget` keeps a single writer.
    pub pending_discharge: core::sync::atomic::AtomicU32,
    /// `mem = "locked"`: refused `SYS_FORK`/`SYS_FORK_COW`/`SYS_ALLOC_DEMAND`.
    pub locked: bool,
    /// RFC-0049 M1, wave 9: the topology row whose live-instance count this
    /// task holds one of, as row index + 1; `0` holds none (a kernel task, or
    /// a program with no row of its own, a fork child). Released once, at
    /// exit (`scheduler::task_exit_with_code`).
    pub row: u16,
}

impl TaskMem {
    /// The state of a slot that has never held a task.
    pub const fn new() -> Self {
        Self {
            pt_build: 0,
            faults: 0,
            pending_discharge: core::sync::atomic::AtomicU32::new(0),
            locked: false,
            row: 0,
        }
    }
}

impl Task {
    /// Current [`TaskState`] (Relaxed). For scans and same-hart decisions.
    /// Wakers must not use this — they go through
    /// [`sched_word::wake_transition`], which couples the read to the CAS.
    #[inline]
    pub fn state(&self) -> TaskState {
        sched_word::state_of(self.state_word.load(core::sync::atomic::Ordering::Relaxed))
    }

    /// Current [`TaskState`] with Acquire: seeing `Blocked` here guarantees
    /// the `wait_reason` that task published is visible (pairs with the
    /// Release commit in [`sched_word::commit_blocked_or_consume_wake`]).
    /// K-C17's fence pairing, expressed as a load ordering.
    #[inline]
    pub fn state_acquire(&self) -> TaskState {
        sched_word::state_of(self.state_word.load(core::sync::atomic::Ordering::Acquire))
    }

    /// Scheduler-side state change; preserves the wake stamp. See
    /// [`sched_word::set_state`].
    #[inline]
    pub fn set_state(&self, s: TaskState) {
        sched_word::set_state(&self.state_word, s);
    }
}

// ---- K-C12: placement policy, isolated as pure logic ----

/// One CPU's load as seen by the placement policy.
///
/// Both counts are over the tasks *resident* on that hart — everything whose
/// home is that CPU, whatever state it is in right now — not over its ready
/// queue. That distinction is the fix; see [`pick_cpu_by_load`].
///
/// Approximate by design (sampled without the per-CPU queue locks); a stale
/// sample costs at worst one suboptimal placement, never correctness.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CpuLoad {
    /// Outranking residents that are in the **hard real-time band**
    /// ([`is_rt_priority`]). Ranked ahead of everything else because this
    /// scheduler never lets the timer preempt them (`RT_TIME_SLICE_TICKS` is
    /// 0 and `schedule()` skips them) — they run until they block, by design,
    /// and on a hart dedicated to them (`rt-motor` and `flight-ctrl` are both
    /// pinned to hart 0 "to avoid jitter") they are the whole point of that
    /// hart. Best-effort work does not belong there.
    pub rt_blocking: u32,
    /// All resident tasks on this CPU that **outrank** the task being placed
    /// (strictly lower priority number), real-time band included. Dispatch is
    /// strict priority with no aging, so even a time-sliced higher-priority
    /// task that never blocks starves the newcomer — time slicing only
    /// rotates *within* one priority level.
    pub blocking: u32,
    /// Total resident tasks on this CPU, at any priority.
    pub total: u32,
}

/// Pick the CPU a task of a given priority should be placed on.
///
/// # K-C12: why "fewest queued tasks" was the wrong question
///
/// The previous policy (`find_least_loaded_cpu`) minimised the number of
/// *queued* tasks. That metric is blind in the two ways that matter:
///
///  * It counts only what is queued **right now**. A task that is `Running`,
///    or a periodic real-time task that happens to be `Blocked` between
///    activations, is in no ready queue — so the harts most hostile to
///    low-priority work sample as the emptiest ones.
///  * It ignores **priority** entirely, while dispatch
///    (`cpu_dequeue` → `ready_bitmap.trailing_zeros()`) is strict priority
///    with no aging. A task placed behind a higher-priority task that never
///    stops being runnable is not "slower": it never runs at all.
///
/// Measured, not argued (ring-3 probe `userspace/tests/ipctest`, `-smp 4`): of 104
/// `fork()`s, 98 children were placed on a hart with no higher-priority work
/// and **all 98 ran**; 3 landed on hart 0 (`rt-motor` + `flight-ctrl`, both
/// priority 8) and 2 on hart 1 (`imu` priority 8), and **all 5 never executed
/// a single instruction** — no fault, no log line, `fork()` having already
/// returned a positive TID to the parent. That is K-C12, and the correlation
/// was 5 of 5.
///
/// So the question is not "which hart is emptiest" but "which hart will
/// actually dispatch this task": order by `(rt_blocking, blocking, total)`.
/// Ties resolve to the lowest index so the choice is deterministic and
/// reproducible in tests.
///
/// **Why `rt_blocking` is a separate key, and not just part of `blocking`.**
/// The first version of this ranked on `(blocking, total)`. It worked until
/// the unpinned mid-priority tasks (`shell` p13, `behavior`/`odom`/
/// `sensor-ahrs` p14) had migrated around and every hart carried two
/// outranking residents — at which point `total` decided, and hart 0 won it,
/// because all the forked children had gone elsewhere and it looked lightly
/// loaded. Measured, from the probe: `online=4 best_for_p16=0 cpu0.blk=2
/// cpu2.blk=2`, with the children that landed there sitting `Ready` and
/// un-dispatched for the rest of the run. Two blockers at priority 8 on a
/// hart dedicated to real-time control are not the same hazard as two at
/// priority 13/14 that sleep between activations, and a count that cannot
/// tell them apart hands best-effort work to the one hart guaranteed never
/// to run it.
///
/// **Residual, deliberately not fixed here.** This is placement, not a
/// starvation guarantee. If *every* hart is saturated by higher-priority
/// work, a low-priority task still starves — that is inherent to strict
/// priority without aging, and adding aging changes the dispatch guarantees
/// the RT and PiMutex scenarios depend on. It belongs in its own pass.
///
/// **K-C27 (2026-09-03): the saturation itself was the workload's defect,
/// and is fixed at the workload.** The daemons that made harts 0, 1 and 3
/// permanently hostile (`rt-motor`, `flight-ctrl`, `sensor-ahrs`,
/// `net-poll`, plus the best-effort spinners `io-ring-worker` (since
/// deleted), `telemetry` and the idle `shell`) yield-polled instead of
/// sleeping — measured at
/// ~215,000 scheduler entries per second per RT daemon, 32M entries each in
/// one 150 s QEMU run. They now block on `WaitReason::Timer` at their
/// design rates (`kernel/src/main.rs`, K-C27), which is what ci_check.sh's
/// disabled `-smp 1` scenario had already concluded: "the scheduler does
/// the right thing; the workload is wrong." Placement is deliberately
/// untouched: residents still count whether blocked or not (see K-C12
/// above), so best-effort work still concentrates on the no-RT hart — but
/// that hart is no longer shared with band-mates that never block, and a
/// task placed behind a *sleeping* RT resident now actually runs. Neither
/// aging nor work stealing was added; if stealing is ever wanted, it is
/// only safe now that a stolen task on an RT hart gets the hart's sleep
/// gaps instead of nothing (the measured p16-on-hart-0 incident above).
///
/// **Known consequence, measured.** On this kernel's default boot layout
/// harts 2 and 3 have no real-time residents (hart 0 carries `rt-motor` and
/// `flight-ctrl` at 8, hart 1 carries `imu` at 8; hart 2 has `behavior` at 14
/// and hart 3 `net-poll` at 12 and `autorun` at 16 — all outside the band).
/// Unpinned best-effort work concentrates there: all 105 `fork()` children of
/// a `-smp 4` ipctest run landed on hart 2. Liveness is worth that, but note what it does to
/// cross-hart coverage. `ci_check.sh` says in its own comment that `-smp 4`
/// is not decorative for the `userspace: IPC` scenario, because phase A
/// exists to open the window between `wake_fast_ipc_server()` and
/// `task_block()`. That window is still opened today only because the phase-A
/// *server* is the `autorun` parent, pinned to hart 3, while its clients sit
/// on hart 2 — measured, `tid=17 tp=3` against `tid=12x tp=2`. It used to be
/// created at priority 10 as well; that is not true any more, and it was never
/// the reason it stays on hart 3 (the affinity is). Priority 10 put a ring-3
/// program inside the real-time band and starved `net-poll` off that same
/// hart — see the `AUTORUN_PRIORITY` block in `kernel/src/main.rs`. Two peers that are both unpinned best-effort tasks would now share
/// a hart, and a scenario that needs them apart must pin them rather than
/// rely on placement scattering them.
///
/// Returns 0 for an empty slice (there is always at least hart 0).
pub fn pick_cpu_by_load(loads: &[CpuLoad]) -> usize {
    let mut best = 0usize;
    let mut best_load = match loads.first() {
        Some(l) => *l,
        None => return 0,
    };
    for (i, l) in loads.iter().enumerate().skip(1) {
        if (l.rt_blocking, l.blocking, l.total)
            < (best_load.rt_blocking, best_load.blocking, best_load.total)
        {
            best = i;
            best_load = *l;
        }
    }
    best
}

// ---- K-C12: ready-queue admission policy, isolated as pure logic ----

/// What `cpu_enqueue` must do with one enqueue request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnqueueOutcome {
    /// Append the task to the ring and mark it queued.
    Append,
    /// The task is already in a ready queue. Do nothing: an entry for it
    /// already exists, so nothing is lost and the ring stays consistent.
    AlreadyQueued,
    /// The ring is full. Do **not** write — the old code overwrote a live
    /// entry here — and report the refusal to the caller.
    ///
    /// Unreachable while `Task::queued` holds (`MAX_TASKS` distinct tasks
    /// cannot fill an `MAX_TASKS`-entry ring and still have one left over),
    /// which is exactly why it may log loudly instead of trying to recover.
    Full,
}

/// The `cpu_enqueue` admission decision, free of statics and assembly so the
/// host suite can exercise it (`tests/host/sched-wake-tests`).
///
/// `capacity` is the ring size (`MAX_TASKS`); `count` is its current
/// occupancy.
#[inline]
pub fn enqueue_decision(already_queued: bool, count: usize, capacity: usize) -> EnqueueOutcome {
    if already_queued {
        EnqueueOutcome::AlreadyQueued
    } else if count >= capacity {
        EnqueueOutcome::Full
    } else {
        EnqueueOutcome::Append
    }
}

// ---- Ring-walk bounds for an unsynchronised reader, isolated as pure logic ----

/// Whether a resident of a hart is competing for it *now*.
///
/// `find_best_cpu` scores a candidate hart by how many residents outrank the
/// task being placed. It used to count every resident regardless of state, and
/// while the real-time daemons yield-polled that was right: a task that never
/// blocks does occupy its hart permanently.
///
/// K-C27 stopped them polling. `rt-motor` and `flight-ctrl` now sleep on a
/// timer between activations, so for almost all of every period they are
/// `Blocked` and their hart is idle — yet they still scored as full blockers,
/// and every unpinned `fork()` child kept going to the one hart with no
/// real-time residents. Measured after K-C27, at the moment `ipctest` failed:
/// `per_cpu_queues = [0, 2, 50, 4]`. Two harts with an *empty* ready queue and
/// one with fifty tasks waiting, because placement was still scoring the empty
/// ones as busy.
///
/// A `Blocked` resident is therefore not counted. It still counts toward
/// `total`, which breaks ties, so a hart does not become infinitely attractive
/// just because its residents are asleep — it simply stops being treated as
/// hostile.
///
/// **What this gives up.** A resident sleeping at this instant will wake, and a
/// 1 kHz daemon wakes often; the newcomer will be preempted briefly each
/// period. That is the trade `pick_cpu_by_load` documents in the other
/// direction, and the measured incident behind it — mid-priority children
/// placed on hart 0 that "sat Ready and un-dispatched for the rest of the run"
/// — happened when hart 0's residents never blocked at all. They do now, so
/// the newcomer gets the gaps between activations rather than nothing.
pub fn resident_competes(state: TaskState) -> bool {
    !matches!(state, TaskState::Blocked | TaskState::Zombie)
}

/// What one resident adds to its hart's score, as `(rt_blocking, blocking,
/// total)`.
///
/// This is the body of `find_best_cpu`'s scan, lifted out so the rule can be
/// tested rather than only described. The first version of the change above
/// left the scan inline and tested `resident_competes` on its own; two of the
/// three tests written for it then built `CpuLoad` values by hand and passed
/// under a deliberately broken predicate, which makes them documentation, not
/// guards. Folding the whole contribution into one pure function is what makes
/// the canary bite.
///
/// `resident_bucket` and `target_bucket` are priority buckets — lower is
/// better, so a resident outranks the newcomer when its bucket is strictly
/// smaller. `resident_is_rt` is [`is_rt_priority`] of the resident.
pub fn resident_load_contribution(
    state: TaskState,
    resident_bucket: usize,
    resident_is_rt: bool,
    target_bucket: usize,
) -> (u32, u32, u32) {
    // A resident counts toward `total` whatever it is doing: it lives here,
    // and `total` is what breaks ties so a hart cannot look infinitely
    // attractive merely because everyone on it is asleep.
    let outranks = resident_competes(state) && resident_bucket < target_bucket;
    (
        u32::from(outranks && resident_is_rt),
        u32::from(outranks),
        1,
    )
}

/// Turn a `(head, count)` pair read **without the ring's lock** into a cursor
/// and a length that a walk cannot panic on.
///
/// `ring_claim_audit` reads the ready queues from the timer ISR without taking
/// `CPU_LOCKS`, because taking them there can deadlock against a hart that was
/// interrupted holding one. That makes the read a data race, and a racing read
/// has no coherent value to reason about — "head is always below capacity" is
/// true of every value the ring ever *stores* and says nothing about what an
/// unsynchronised load returns.
///
/// The first version of that walk seeded its cursor straight from `head` and
/// then did `h = (h + 1) % capacity`. Twice in a hundred 8-way-concurrent QEMU
/// runs the add overflowed and, with `panic = "abort"` and
/// `overflow-checks = true`, reset the board from inside the ISR.
///
/// Extracted rather than fixed in place for the same reason `enqueue_decision`
/// is: the property that matters — *no input can make the walk panic or index
/// out of range* — is a statement about arithmetic, and arithmetic can be
/// proved on the host against adversarial inputs instead of hoped for across a
/// hundred QEMU runs. Absence of a crash in a sample is not the same claim.
///
/// Returns `(start, len)` with `start < capacity` and `len <= capacity`, for
/// every possible input including `usize::MAX`. `capacity == 0` yields
/// `(0, 0)`: a zero-length walk, not a division by zero.
pub fn ring_walk_bounds(raw_head: usize, raw_count: usize, capacity: usize) -> (usize, usize) {
    if capacity == 0 {
        return (0, 0);
    }
    (raw_head % capacity, raw_count.min(capacity))
}

/// The two-sample filter that turns a racy `ring_claim_audit` observation into
/// evidence: a slot is reported only if it claimed a queue entry it did not
/// have in **two consecutive samples**.
///
/// `prev` is the `claim_no_entry` bitmask from the previous tick, `cur` the
/// one just computed. The result is the set to report.
///
/// Extracted from `scheduler::ring_claim_audit` for the same reason
/// [`ring_walk_bounds`] and [`enqueue_decision`] were: the audit reads the
/// ready-queue rings without `CPU_LOCKS`, so a single sample can catch an
/// enqueue or a dequeue half-done and disagree with the `queued` flag for a
/// few instructions. Making the atomic fields `Relaxed` legalised those reads;
/// it did **not** give the reader a consistent snapshot, and it did not repair
/// the two documented unlocked writers. This filter is the whole of what stops
/// that torn view from being printed as a fault, so it is the piece that has
/// to be proved rather than described — and it can only be proved on the host,
/// because `scheduler.rs` does not compile here.
///
/// The rule has to bite in **both** directions, which is why the host tests
/// assert both: a filter that reported every sample (`cur`) would turn every
/// enqueue window into a false CLAIM-NO-ENTRY report, and one that reported
/// nothing (`0`) would make the audit — the only check on the `queued` claim
/// anywhere in this kernel — silently useless. A test that pinned only one
/// direction would pass against the mutant for the other.
///
/// Intersection, not union: the caller *replaces* its stored mask with `cur`
/// on every call (a `swap`), so a slot that is clean for one tick starts over.
/// A sticky `prev | cur` would report a slot forever after a single transient.
#[inline]
pub fn claim_audit_persistent(prev: u64, cur: u64) -> u64 {
    prev & cur
}

// ---- W4-int helpers around the new fields ----

/// Default scheduler class for the legacy `task_create()` path. Maps
/// to `SchedClass::BestEffort` so existing tasks keep their old
/// behaviour even after the multi-policy machinery is wired in.
pub const DEFAULT_SCHED_CLASS_RAW: u8 = 3; // SchedClass::BestEffort

/// Sentinel value for "no deadline".
pub const NO_DEADLINE: u64 = 0;

// TaskContext at offset 0; tid follows immediately after. Three targets,
// three sizes for `TaskContext` (see its own doc comment): riscv64 (128
// bytes, unchanged), aarch64 bare metal (184 — Phase 3 grew this: x19-x28 +
// x29 + d8-d15 on top of the always-present ra/sp/pc/tp), and everything
// else (the host: ra/sp/pc/tp only, 32 bytes — no context-switch asm to
// agree with on that target, see `TaskContext`'s `x19` field comment).
#[cfg(target_arch = "riscv64")]
const _: () = assert!(core::mem::offset_of!(Task, tid) == 128);
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
const _: () = assert!(core::mem::offset_of!(Task, tid) == 184);
#[cfg(not(any(target_arch = "riscv64", target_os = "none")))]
const _: () = assert!(core::mem::offset_of!(Task, tid) == 32);
// x86_64 skeleton: its 80-byte TaskContext.
#[cfg(all(target_os = "none", not(any(target_arch = "riscv64", target_arch = "aarch64"))))]
const _: () = assert!(core::mem::offset_of!(Task, tid) == 80);

pub const TASK_SATP_OFFSET: usize = core::mem::offset_of!(Task, task_satp);

// **The comment that stood here was wrong, and it cost a wrong fix before it
// was checked.** It said this offset "MUST match TASK_SATP_OFFSET in
// context_switch.S" and that a failure means editing the `.S`. It does not:
// the `global_asm!` blocks in `kernel/src/main.rs` inject `task_satp_off` into both
// `context_switch.S` and `context_switch_rvv.S` with
// `const offset_of!(Task, task_satp)` — the same expression as above. The
// assembly cannot disagree with the struct, because it is told.
//
// Acting on the old comment led to moving `syscall_filter` below `task_satp`
// to "protect" the assembly from a layout shift the assembly is immune to.
// That move was reverted; this comment is what stops it being made again.
//
// The assert is kept, with its real job stated: it is a TRIPWIRE, so that
// reordering the TCB or resizing a field inside it is a deliberate act with a
// number to update, rather than something that happens by accident to a
// structure `context_switch.S` walks. It guards nothing on its own.
//
// 512 as of wave 11 (SCHED-RT): -32 when the dead EDF path's
// `DeadlineParams` (4 x u64) left the TCB; reservations live per hart now
// (`scheduler::rt`).
// 544 as of wave 9: +64 when `SYSCALL_FILTER_MAX` went from 64 to 96 entries
// of `u16` (filter 212 -> 276 bytes).
// 480 as of wave 7: +80 for the 640-bit seccomp bitmap `SyscallFilter::bits` (filter
// 132 -> 212 bytes). 400 as of 2026-09-07: was 336, +64 when `SYSCALL_FILTER_MAX` went from 32
// to 64 entries of `u16`. riscv64 only — see the three-way split below for
// why aarch64 (bare metal) and the host each need their own number: every
// field from `tid` onward is unmoved, so the whole delta between targets is
// exactly `TaskContext`'s own size delta (same reasoning as the `tid`
// tripwire a few lines up).
#[cfg(target_arch = "riscv64")]
const _: () = assert!(
    TASK_SATP_OFFSET == 512,
    "Task layout changed. Nothing in the assembly needs editing — it derives \
     this offset. Update the number here once you have confirmed the change \
     was intended."
);
// aarch64 bare metal: 512 + (184 - 128) = 568.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
const _: () = assert!(
    TASK_SATP_OFFSET == 568,
    "Task layout changed. Nothing in the assembly needs editing — it derives \
     this offset. Update the number here once you have confirmed the change \
     was intended."
);
// Host: 512 + (32 - 128) = 416.
#[cfg(not(any(target_arch = "riscv64", target_os = "none")))]
const _: () = assert!(
    TASK_SATP_OFFSET == 416,
    "Task layout changed. Nothing in the assembly needs editing — it derives \
     this offset. Update the number here once you have confirmed the change \
     was intended."
);
#[cfg(all(target_os = "none", not(any(target_arch = "riscv64", target_arch = "aarch64"))))]
const _: () = assert!(
    TASK_SATP_OFFSET == 464,
    "Task layout changed. Nothing in the assembly needs editing — it derives \
     this offset. Update the number here once you have confirmed the change \
     was intended."
);

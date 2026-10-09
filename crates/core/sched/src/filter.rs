// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Pure, dependency-free task-policy types: the seccomp whitelist and the
//! creation-time initialisation parameters.
//!
//! **WHY these live outside `task.rs`.** They are the security policy of a
//! task and carry no reference to the TCB, the scheduler, or any hardware
//! type — but `task.rs` pulls in the whole kernel. Keeping them here lets
//! `tests/host/seccomp-tests` `#[path]`-include and exercise the *real* code on
//! the host rather than a copy of it that can drift.

// ---- Syscall filter (AQ11) ----

/// Maximum number of allowed syscalls per process.
///
/// **Widened from 32 to 64 on 2026-09-07 (owner decision), and the reason is
/// the migration rather than any profile being full today.** Every family
/// moving to capability-typed syscalls doubles its entries in a profile for
/// as long as both paths stay live: `PROFILE_MOTOR` went from 9 to 17 extras
/// by gaining the typed twins of what it already allowed, and it still cannot
/// carry `SYS_MOTOR_TICK/SET_GAINS/RESET_TYPED` — the three with no untyped
/// twin — without reaching 30 of 32. Rationing slots per migration is how a
/// security filter ends up shaped by an array bound instead of by policy.
///
/// **What made this worth fixing rather than tracking**: [`Self::allow`]
/// drops entries past the bound **in silence**. The direction is fail-closed
/// — a dropped `allow` leaves the syscall denied, never permitted — so the
/// failure is a task discovering it cannot make a call its profile lists,
/// with nothing anywhere saying why.
///
/// Cost: 32 extra `u16` per `Task`, i.e. 64 bytes, times `MAX_TASKS` (64) =
/// 4 KiB of static task pool. The `offset_of!` assertions in `task.rs` are
/// what prove this did not move a field `context_switch.S` reaches by
/// hard-coded offset.
///
/// 96 since wave 9 (owner decision): the widest image profile (ABITEST.ELF,
/// audit mode) listed 62 of 64. A Kconfig int since wave 15
/// (`CONFIG_SYSCALL_FILTER_MAX`, default 128): ABITEST.ELF reached 74 of 96,
/// past the quarter-free margin `tests/host/seccomp-tests` keeps. Since wave 7 the dispatcher answers from the
/// bitmap ([`SYSCALL_FILTER_BITMAP_BITS`]), so the list length costs no
/// syscall; it is kept for the audit and spawn-plan comparisons and costs
/// another 64 bytes per `Task` (4 KiB of task pool).
pub const SYSCALL_FILTER_MAX: usize = azos_limits::SYSCALL_FILTER_MAX;

/// Syscall numbers the membership bitmap covers: `0..SYSCALL_FILTER_BITMAP_BITS`.
///
/// Every number the ABI assigns sits below `SYS_NR_RESERVED_UPPER` (615), and
/// `seccomp.rs` asserts that bound stays below this one at compile time, so a
/// real syscall is always answered from the bitmap. A number at or past this
/// bound (never a real syscall) takes the list scan, which is the only way a
/// filter that lists such a number through [`SyscallFilter::allow`] keeps the
/// answer it has always given.
///
/// 640, not 1024 (owner decision, wave 7): 640 bits = 80 bytes per
/// `SyscallFilter`, one embedded in each `Task` slot (`MAX_TASKS` = 64).
/// `Task` itself grows by 64 bytes (1088 -> 1152 on
/// riscv64, 1728 -> 1792 on aarch64: 16 of the 80 land in tail padding it
/// already had), so the task pool grows by 4 KiB (`.bss`). The bound
/// is a multiple of 32, so it is a whole number of `u32` words.
pub const SYSCALL_FILTER_BITMAP_BITS: usize = 640;

/// `u32` words in [`SyscallFilter::bits`]. `u32`, not `u64`: the struct keeps
/// the 2-byte fields where they were and needs no padding before the words,
/// and both `srlw` (riscv64) and `lsr w` (aarch64) take the shift amount mod
/// 32, so the bit test needs no mask instruction either way.
const BITMAP_WORDS: usize = SYSCALL_FILTER_BITMAP_BITS / 32;
const _: () = assert!(SYSCALL_FILTER_BITMAP_BITS % 32 == 0, "the bitmap is whole u32 words");

/// Per-task syscall whitelist. If `enabled`, only listed syscalls are allowed,
/// unless `audit` is set, in which case an unlisted syscall is let through and
/// recorded instead of refused.
///
/// **Two representations of one set.** `allowed[..count]` is the list, in the
/// order it was built, which the tests and the spawn-plan comparison read.
/// `bits` is the same set as a bitmap over `0..SYSCALL_FILTER_BITMAP_BITS`,
/// which is what the dispatcher reads: one word load and a bit test instead
/// of a scan of up to `SYSCALL_FILTER_MAX` entries on every filtered syscall (owner decision,
/// round 8). [`Self::allow`] is the only writer of either and writes both in
/// the same guarded step, so every filter built through it — the role
/// profiles, the image profiles, the fail-closed deny-all — carries the two
/// in agreement from the moment it exists. Installing (`activate_profile`,
/// exec, `install_image_profile`) and fork copy the whole struct, bitmap
/// included; nothing recomputes it. `tests/host/seccomp-tests`
/// (`mod bitmap_equivalence`) checks the bitmap verdict against the old
/// linear scan for every profile and every `u16` number.
///
/// **Exec keeps it, as Linux keeps a seccomp filter across `execve`.**
/// `exec_user` (`process.rs`) replaces the address space, keeps the task slot
/// and never writes this field, so a confined task that execs another image
/// runs that image under the filter it already had. The kernel exec sites that
/// start a program on an unconfined kernel task (the autorun loader, the
/// shell's `exec`) install the image's own profile with
/// `seccomp::install_image_profile`, which never replaces a filter already in
/// force. Fork copies the parent's filter onto the child (`sys_fork_impl`).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SyscallFilter {
    pub enabled: bool,
    pub allowed: [u16; SYSCALL_FILTER_MAX],
    pub count: u8,
    /// Allow-and-record: an unlisted syscall is let through and recorded,
    /// bounded per task, rather than refused. Meaningless while `enabled` is
    /// false. Set only from an image profile marked `audit` in `seccomp.rs`.
    pub audit: bool,
    /// Bit `n % 32` of word `n / 32` is set iff `n` is in `allowed[..count]`,
    /// for `n < SYSCALL_FILTER_BITMAP_BITS`. Written only by [`Self::allow`].
    /// Not `pub`: a writer outside this file could set one representation and
    /// not the other, and the dispatcher would then answer from a set the list
    /// does not show.
    pub(crate) bits: [u32; BITMAP_WORDS],
}

// The layout, derived from `SYSCALL_FILTER_MAX` (Kconfig, default 128) rather
// than restated as numbers, so resizing the list is a `make config` choice and
// not an edit here. `enabled` at 0, `allowed` at 2 (`SYSCALL_FILTER_MAX` x
// u16), `count` right after the list, `audit` in the byte after `count`, and
// `bits` at the next 4-byte boundary. With 128 entries: count 258, audit 259,
// bits 260, size 340 (96 entries: 194/195/196/276). The `Task` tripwires in
// `task.rs` add `SYSCALL_FILTER_SIZE` to the frozen offset of
// `syscall_filter`, and the context-switch assembly is fed `task_satp`'s
// offset by `offset_of!`, so nothing else has a number to update.
pub const SYSCALL_FILTER_COUNT_OFFSET: usize = 2 + 2 * SYSCALL_FILTER_MAX;
pub const SYSCALL_FILTER_AUDIT_OFFSET: usize = SYSCALL_FILTER_COUNT_OFFSET + 1;
pub const SYSCALL_FILTER_BITS_OFFSET: usize = (SYSCALL_FILTER_AUDIT_OFFSET + 1 + 3) & !3;
pub const SYSCALL_FILTER_SIZE: usize = SYSCALL_FILTER_BITS_OFFSET + 4 * BITMAP_WORDS;
const _: () = assert!(
    core::mem::size_of::<SyscallFilter>() == SYSCALL_FILTER_SIZE,
    "SyscallFilter changed size: every Task offset after syscall_filter moves",
);
const _: () = assert!(
    core::mem::offset_of!(SyscallFilter, count) == SYSCALL_FILTER_COUNT_OFFSET,
    "`count` follows the list",
);
const _: () = assert!(
    core::mem::offset_of!(SyscallFilter, audit) == SYSCALL_FILTER_AUDIT_OFFSET,
    "`audit` must sit in the byte after `count`",
);
const _: () = assert!(
    core::mem::offset_of!(SyscallFilter, bits) == SYSCALL_FILTER_BITS_OFFSET,
    "`bits` is appended after `audit`; the other fields must not move",
);
// `count` is a `u8`: the list must stay addressable by it.
const _: () = assert!(SYSCALL_FILTER_MAX <= u8::MAX as usize);

/// What the dispatcher does with one syscall of the current task.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FilterVerdict {
    /// No filter is in force, or the number is listed.
    Allow,
    /// Unlisted, and the filter is in audit mode: let through and recorded.
    Audit,
    /// Unlisted: refused.
    Deny,
    /// The current task runs under the Linux personality (RFC-0047): the
    /// number is a LINUX number and goes to the translation table, which
    /// asks the filter about each NATIVE call it reaches
    /// (`scheduler::current_native_verdict`). Only
    /// `scheduler::current_syscall_verdict` answers it, and only when
    /// Kconfig `LINUX_ABI` is on; [`SyscallFilter::verdict_for`] never does.
    Linux,
}

impl SyscallFilter {
    pub const fn disabled() -> Self {
        Self {
            enabled: false,
            allowed: [0; SYSCALL_FILTER_MAX],
            count: 0,
            audit: false,
            bits: [0; BITMAP_WORDS],
        }
    }

    /// [`Self::verdict_for`] for a number already narrowed to `u16`. Callers on
    /// the syscall path have the raw `a7` value and want that one instead; this
    /// form is for tests and for callers that never held anything wider.
    #[inline]
    pub fn verdict(&self, syscall_num: u16) -> FilterVerdict {
        // Delegates to the u64 form, not the other way round: see its comment
        // on why wide numbers are never narrowed. A `u16` widened here can
        // never trip that function's `> u16::MAX` refusal, so this is the same
        // answer this function has always given.
        self.verdict_for(syscall_num as u64)
    }

    /// The dispatcher's question, for the syscall number exactly as the task
    /// put it in `a7`, before any narrowing. A number past `u16::MAX` is
    /// refused by any filter in force, audit mode included, instead of being
    /// compared by its low 16 bits, where `65536 + n` would pass as a listed
    /// `n`.
    ///
    /// Every number below [`SYSCALL_FILTER_BITMAP_BITS`] — every real syscall —
    /// is answered by one bit of `bits`: a word load and a shift, whatever the
    /// profile's length. The index is `num / 32 < BITMAP_WORDS` by the range
    /// test, so the load carries no bounds check.
    #[inline]
    pub fn verdict_for(&self, num: u64) -> FilterVerdict {
        if !self.enabled {
            return FilterVerdict::Allow;
        }
        let listed = if num < SYSCALL_FILTER_BITMAP_BITS as u64 {
            // `& 31` is what `srlw`/`lsr w` do to the amount anyway, so it
            // costs nothing; it is written out because the release profile
            // has `overflow-checks = true`, which would otherwise add a check
            // that a shift below 32 cannot fail.
            (self.bits[(num / 32) as usize] >> (num as u32 & 31)) & 1 != 0
        } else if num > u16::MAX as u64 {
            return FilterVerdict::Deny;
        } else {
            self.listed_past_bitmap(num)
        };
        if listed {
            FilterVerdict::Allow
        } else if self.audit {
            FilterVerdict::Audit
        } else {
            FilterVerdict::Deny
        }
    }

    /// Is `num` (at or past the bitmap, at most `u16::MAX`) in the list? No
    /// real syscall reaches this; it keeps a wide number `allow` accepted
    /// allowed, as it always was.
    ///
    /// The scan runs over `allowed[..count]` with `count` clamped to the array,
    /// so the loop carries no per-entry bounds check. `allow` never lets
    /// `count` pass the array; the clamp only changes what a corrupted `count`
    /// could read, which is nothing past `allowed`.
    #[inline(always)]
    fn listed_past_bitmap(&self, num: u64) -> bool {
        let n = (self.count as usize).min(SYSCALL_FILTER_MAX);
        self.allowed[..n].iter().any(|&listed| listed as u64 == num)
    }

    /// The linear scan `verdict_for` was until the bitmap replaced it, kept
    /// verbatim as the reference the bitmap is checked against
    /// (`tests/host/seccomp-tests`, `mod bitmap_equivalence`). Never compiled into
    /// the kernel.
    #[cfg(test)]
    pub fn verdict_for_linear_scan_reference(&self, num: u64) -> FilterVerdict {
        if !self.enabled {
            return FilterVerdict::Allow;
        }
        if num > u16::MAX as u64 {
            return FilterVerdict::Deny;
        }
        let n = (self.count as usize).min(SYSCALL_FILTER_MAX);
        for &listed in &self.allowed[..n] {
            if listed as u64 == num {
                return FilterVerdict::Allow;
            }
        }
        if self.audit { FilterVerdict::Audit } else { FilterVerdict::Deny }
    }

    /// Is `syscall_num` listed, or the filter off? Blind to `audit`: an unlisted
    /// call under an audit filter is `false` here and [`FilterVerdict::Audit`]
    /// from [`Self::verdict`], which is what the dispatcher asks. Answered from
    /// the same lookup as the dispatcher's, so the two cannot disagree.
    pub fn is_allowed(&self, syscall_num: u16) -> bool {
        if !self.enabled { return true; }
        let n = syscall_num as usize;
        if n < SYSCALL_FILTER_BITMAP_BITS {
            (self.bits[n / 32] >> (n as u32 & 31)) & 1 != 0
        } else {
            self.listed_past_bitmap(n as u64)
        }
    }

    /// Add `syscall_num` to the whitelist: the builder of both representations.
    ///
    /// The bit is set inside the same capacity guard as the list entry, so an
    /// entry dropped past `SYSCALL_FILTER_MAX` is missing from both and stays
    /// denied (fail-closed) whichever one is asked.
    pub fn allow(&mut self, syscall_num: u16) {
        if (self.count as usize) < SYSCALL_FILTER_MAX {
            self.allowed[self.count as usize] = syscall_num;
            self.count += 1;
            let n = syscall_num as usize;
            if n < SYSCALL_FILTER_BITMAP_BITS {
                self.bits[n / 32] |= 1u32 << (n as u32 & 31);
            }
        }
    }
}

// ---- Task initialisation parameters ----

/// Fields that MUST be installed on a task **before** it becomes runnable.
///
/// **WHY this type exists.** `try_task_create_affinity` publishes the new
/// task in three steps: it stores `state_word = Ready` and fills the slot
/// under `POOL_LOCK`, then calls `cpu_enqueue_locked`, which puts the task
/// in a ready queue **and rings the doorbell IPI** on the target hart. From
/// that instant the task is dispatchable on another CPU. Anything the
/// creator writes onto the slot *after* the call returns is a race against
/// a hart the kernel has just gone out of its way to wake.
///
/// Two entry points used to do exactly that:
///
///  * `task_create_filtered` applied the seccomp profile after creation, so
///    a task meant to be confined was briefly running with the
///    `SyscallFilter::disabled()` the slot reset installs — and `disabled`
///    means *allow everything*, not *allow nothing*.
///  * `task_create_with_class` let the task be published under the default
///    `BestEffort` class and then moved it between policy runqueues.
///
/// Both carried a comment claiming "the slot is exclusively owned for the
/// brief moment between its return and the task first running". It is not:
/// the enqueue is the publication, and it precedes the return.
///
/// The fix is the one Linux uses in `copy_process`/`wake_up_new_task` —
/// build the task completely, *then* make it runnable. Passing the fields
/// in through this struct puts every one of them inside the same
/// `POOL_LOCK` section that fills the rest of the slot, so "initialised"
/// and "runnable" cannot be observed out of order.
///
/// `None` / `0` fields mean "keep the creation-time default", which is what
/// the legacy entry points ([`super::scheduler::task_create`] and friends)
/// pass.
#[derive(Clone, Copy, Default)]
pub struct TaskInit {
    /// Seccomp profile to install before the task can issue an `ecall`.
    pub syscall_filter: Option<SyscallFilter>,
    /// `SchedClass` discriminant (RFC-0004). `None` ⇒ `DEFAULT_SCHED_CLASS_RAW`.
    pub class_raw: Option<u8>,
    /// Absolute monotonic deadline in µs; `NO_DEADLINE` (0) for non-EDF tasks.
    pub deadline_us: u64,
    /// Quantum for `Rr` / CBS budget seed; `0` ⇒ policy default.
    pub time_slice_us: u32,
    /// The creating task's TID for a child whose exit is reported to it
    /// (`fork`, `spawn`); `0` for none. Set under the same `POOL_LOCK`
    /// section, after the exit-notice admission (`exit_note::admits`).
    pub parent: u32,
    /// RFC-0047: `Task::abi` (`ABI_NATIVE` 0, the default, or `ABI_LINUX`).
    /// In place before the task is runnable, for the reason the filter is: a
    /// spawned child is switched to (and its filter word cached) while it
    /// waits in `fork_child_entry`, before its hand-off is published.
    pub abi: u8,
}

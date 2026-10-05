// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
/// Signal subsystem — port of kernel/core/signal.c + kernel/include/signal.h

pub const SIGHUP:    u32 = 1;
pub const SIGINT:    u32 = 2;
pub const SIGQUIT:   u32 = 3;
pub const SIGILL:    u32 = 4;
pub const SIGTRAP:   u32 = 5;
pub const SIGABRT:   u32 = 6;
pub const SIGBUS:    u32 = 7;
pub const SIGFPE:    u32 = 8;
pub const SIGKILL:   u32 = 9;
pub const SIGUSR1:   u32 = 10;
pub const SIGSEGV:   u32 = 11;
pub const SIGUSR2:   u32 = 12;
pub const SIGPIPE:   u32 = 13;
pub const SIGALRM:   u32 = 14;
pub const SIGTERM:   u32 = 15;
pub const SIGSTKFLT: u32 = 16;
pub const SIGCHLD:   u32 = 17;
pub const SIGCONT:   u32 = 18;
pub const SIGSTOP:   u32 = 19;
pub const SIGTSTP:   u32 = 20;
pub const NSIG:      u32 = 32;

pub const SIG_DFL: usize = 0;   // Default action
pub const SIG_IGN: usize = 1;   // Ignore signal

#[derive(Clone, Copy)]
pub enum SigDefaultAction {
    Term,   // Terminate process
    Ignore, // Ignore
    Core,   // Dump core (we just terminate)
    Stop,   // Stop process
    Cont,   // Continue if stopped
}

pub fn signal_default_action(signum: u32) -> SigDefaultAction {
    match signum {
        SIGHUP | SIGINT | SIGQUIT | SIGBUS | SIGFPE |
        SIGPIPE | SIGALRM | SIGTERM => SigDefaultAction::Term,

        SIGKILL  => SigDefaultAction::Term,
        SIGILL | SIGSEGV | SIGTRAP => SigDefaultAction::Core,
        SIGSTOP | SIGTSTP  => SigDefaultAction::Stop,
        SIGCONT  => SigDefaultAction::Cont,
        SIGCHLD | SIGUSR1 | SIGUSR2 => SigDefaultAction::Ignore,
        _ => SigDefaultAction::Term,
    }
}

pub fn signal_valid(signum: u32) -> bool {
    signum >= 1 && signum < NSIG
}

pub fn signal_catchable(signum: u32) -> bool {
    signum != SIGKILL && signum != SIGSTOP
}

// ── Per-task signal state (indexed by task ID) ──────────────────────────────

use azos_sync::SpinLock;

// U03-5: derived from Kconfig, not restated. This used to hardcode 64,
// which fails closed but silently: the edge profile's 65th live task's
// `signal_set_mask`/`signal_set_handler` would answer as if the table were
// exhausted while `MAX_TASKS` (the real per-profile ceiling) had room, and
// the fleet profile carried a table twice its configured task count.
use azos_limits::MAX_TASKS;

// ── Caller attribution ───────────────────────────────────────────────────────

/// Returns `(caller_tid, privileged)`. Kernel tasks (`current_user_pt() == 0`)
/// bypass the send policy, the same convention `cap_store`'s typed callers
/// use.
#[cfg(not(test))]
#[inline(always)]
fn caller_ctx() -> (u32, bool) {
    (
        azos_sched::current_task_tid(),
        azos_sched::current_user_pt() == 0,
    )
}

/// Host-test stand-in for [`caller_ctx`]; never compiled into the kernel.
#[cfg(test)]
pub mod test_ctx {
    use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
    pub static TID: AtomicU32 = AtomicU32::new(0);
    pub static PRIVILEGED: AtomicBool = AtomicBool::new(true);

    pub fn set(tid: u32, privileged: bool) {
        TID.store(tid, Ordering::SeqCst);
        PRIVILEGED.store(privileged, Ordering::SeqCst);
    }
}

#[cfg(test)]
#[inline(always)]
fn caller_ctx() -> (u32, bool) {
    use core::sync::atomic::Ordering;
    (
        test_ctx::TID.load(Ordering::SeqCst),
        test_ctx::PRIVILEGED.load(Ordering::SeqCst),
    )
}

#[inline(always)]
fn caller_tid() -> u32 {
    caller_ctx().0
}

#[derive(Clone, Copy)]
struct SigState {
    pending:  u32,   // Bitmask of pending signals
    mask:     u32,   // Blocked signals mask
    handlers: [usize; NSIG as usize],  // Handler fn pointers (SIG_DFL/SIG_IGN/fn)
}

impl SigState {
    const fn new() -> Self {
        SigState { pending: 0, mask: 0, handlers: [SIG_DFL; NSIG as usize] }
    }
}

struct SigTable {
    tids:  [u32; MAX_TASKS],
    state: [SigState; MAX_TASKS],
    count: usize,
}

impl SigTable {
    const fn new() -> Self {
        SigTable {
            tids:  [0u32; MAX_TASKS],
            state: [SigState::new(); MAX_TASKS],
            count: 0,
        }
    }

    fn find(&self, tid: u32) -> Option<usize> {
        for i in 0..self.count {
            if self.tids[i] == tid { return Some(i); }
        }
        None
    }

    /// Find `tid`'s slot, allocating one if it has none.
    ///
    /// # WHY this returns `Option` (the aliasing bug it closes)
    ///
    /// This used to return a bare `usize` and, **when the table was full,
    /// returned index 0** — the slot belonging to whichever task registered
    /// first. Every caller then wrote through that index, so once the table
    /// filled:
    ///
    ///   * `signal_set_mask` from task B silently rewrote task A's mask;
    ///   * `signal_set_handler` from task B overwrote task A's handler table;
    ///   * `signal_send` marked A's signals pending for a signal aimed at B.
    ///
    /// That is cross-task state corruption in the *fail-open* direction, and
    /// it needed no attacker at all: `count` only ever increments and nothing
    /// released entries on task exit, so 64 task lifetimes on a
    /// long-running robot reached it on their own. It was also directly
    /// reachable from ring 3, because the old `signal_send` accepted any
    /// `tid` — 64 `kill()` calls with made-up TIDs filled the table on
    /// demand.
    ///
    /// Now it fails **closed**: callers return an error rather than scribble
    /// on a stranger's state. [`signal_release`] plus the self-only send
    /// policy keep the table from filling in the first place.
    fn get_or_create(&mut self, tid: u32) -> Option<usize> {
        if let Some(idx) = self.find(tid) { return Some(idx); }
        if self.count < MAX_TASKS {
            let idx = self.count;
            self.tids[idx]  = tid;
            self.state[idx] = SigState::new();
            self.count += 1;
            Some(idx)
        } else {
            None
        }
    }

    /// Drop `tid`'s entry, compacting the last live entry into the hole so
    /// [`SigTable::find`]'s `0..count` scan stays correct.
    fn release(&mut self, tid: u32) -> bool {
        let Some(idx) = self.find(tid) else { return false; };
        let last = self.count - 1;   // `find` only returns idx < count ≥ 1
        self.tids[idx]  = self.tids[last];
        self.state[idx] = self.state[last];
        self.tids[last]  = 0;
        self.state[last] = SigState::new();
        self.count = last;
        true
    }
}

static SIG_TABLE: SpinLock<SigTable> = SpinLock::new(SigTable::new());

pub fn signal_init() {
    // Nothing to do — SIG_TABLE is zero-initialized.
}

/// Send signal `signum` to task `tid`.
///
/// Returns 0 on success, -1 if the signal number is invalid, the policy
/// denies the send, or the signal table is full.
///
/// # Policy: ring 3 may signal only itself; kernel tasks bypass
///
/// The old code accepted any `(tid, signum)` from anyone. Two consequences,
/// both reachable from `SYS_KILL`:
///
///  1. **Table exhaustion → cross-task aliasing.** Each unknown `tid`
///     allocated a `SigTable` entry, so 64 calls with invented TIDs filled a
///     table that nothing ever drains, after which every task's signal state
///     aliased onto slot 0. See [`SigTable::get_or_create`]. This is the
///     serious half, and the self-only rule closes it at the source: a task
///     can only ever create its own entry.
///  2. **Cross-task signalling.** Any ring-3 task could set pending bits on
///     any other task, kernel tasks included. Today nothing in the tree
///     *delivers* signals — `pending` is read only by `sys_sigpending` and
///     `sys_pause` (`handlers.rs:529`, `:1252`), and there is no code that
///     terminates a task or jumps to a handler — so the impact is currently
///     a spurious `pause()` wakeup, not a kill. That is precisely why this
///     is the right moment to fix it: the check is cheap now and would be a
///     remote-kill primitive the day delivery lands.
///
/// # Why *self-only* and not something more POSIX-shaped
///
/// POSIX gates `kill()` on uid and session; this kernel has neither. The two
/// alternatives were considered and rejected on evidence:
///
///  * **Parent/child.** `crates/core/sched/src/task.rs` has no parent field —
///    `fork` never records one. The relation does not exist to check.
///  * **"Deny ring 3 → kernel task".** Requires reading the target's
///    `user_pt`, but `TASKS` is private to `crates/core/sched/src/scheduler.rs:78`
///    and there is no per-TID accessor. Adding one is a change to another
///    crate, outside this lane.
///
/// Self-only is therefore the strongest policy implementable here, and it
/// costs nothing real: every live sender already targets itself —
/// `sys_alarm` sends to `current_task_tid()` (`handlers.rs:1268`), the kernel
/// demo sends to `my_tid` (`kernel/src/smokes/selftest.rs`), and no userspace
/// program calls `kill` at all. When a delivery path and a task-relation
/// accessor exist, this is the one place to widen.
pub fn signal_send(tid: u32, signum: u32) -> i32 {
    if !signal_valid(signum) { return -1; }
    let (caller, privileged) = caller_ctx();
    if !privileged && tid != caller { return -1; }
    let mut t = SIG_TABLE.lock();
    let Some(idx) = t.get_or_create(tid) else { return -1; };
    // `signum < NSIG == 32`, guaranteed by `signal_valid`, so this shift can
    // never overflow a u32 — which matters because `overflow-checks = true`
    // turns an over-shift into a panic, and `panic = "abort"` turns that
    // into a board reset.
    t.state[idx].pending |= 1u32 << signum;
    0
}

/// Drop every trace of `tid` from the signal table.
///
/// **WHY it exists:** nothing released signal entries on task exit, so
/// `SigTable::count` was monotonically increasing for the life of the board.
/// After 64 task lifetimes — ordinary operation on a long-running robot, no
/// attacker needed — the table is full and every further
/// `signal_set_handler` / `signal_set_mask` fails closed (previously: aliased
/// onto slot 0). Wired into `crate::task_release_all` alongside
/// `cap_store::reset` / `shm_release_all`.
///
/// Returns `true` if an entry was actually removed.
pub fn signal_release(tid: u32) -> bool {
    SIG_TABLE.lock().release(tid)
}

/// Number of live entries in the signal table. Diagnostic + test hook for
/// the exhaustion bug above.
pub fn signal_table_len() -> usize {
    SIG_TABLE.lock().count
}

/// Empty the signal table. Host-test hygiene only; never built into the
/// kernel — see the equivalent note in `channel.rs`.
#[cfg(test)]
pub fn __signal_reset_for_tests() {
    let mut t = SIG_TABLE.lock();
    for i in 0..MAX_TASKS {
        t.tids[i]  = 0;
        t.state[i] = SigState::new();
    }
    t.count = 0;
}

/// Check if any signals are pending for the current task.
pub fn signal_pending() -> u32 {
    let tid = caller_tid();
    let t = SIG_TABLE.lock();
    match t.find(tid) {
        Some(idx) => t.state[idx].pending & !t.state[idx].mask,
        None      => 0,
    }
}

/// Set signal handler for the current task. Returns the previous handler, or
/// `SIG_DFL` if the signal number is invalid or the table is full.
///
/// # The handler pointer is stored and never used (audited 2026-08-22)
///
/// `handler` arrives raw from ring 3 via `SYS_SIGNAL`
/// (`crates/core/syscall/src/handlers.rs:524`) and is written straight into
/// `SigState::handlers`. That array is **read by nothing** anywhere in the
/// tree: there is no signal-delivery path, and `sys_sigreturn` is a stub that
/// returns 0. So the kernel does not jump to this address, and today the
/// field is inert storage — no control-flow risk, and no reason to reject a
/// value here either (a would-be validation would only be checked against the
/// address space live at *registration* time, which is not the one delivery
/// would run in).
///
/// **Whoever implements delivery owns this:** before transferring control,
/// the address must be validated against the target's page table with
/// `vmm::translate_user` demanding VALID+USER+EXEC, and the jump must land in
/// U-mode via `sret`, never as an S-mode call. Handing S-mode control to a
/// ring-3-supplied pointer is a straight privilege escalation, and this field
/// is where it would come from.
pub fn signal_set_handler(signum: u32, handler: usize) -> usize {
    if !signal_valid(signum) { return SIG_DFL; }
    let tid = caller_tid();
    let mut t = SIG_TABLE.lock();
    let Some(idx) = t.get_or_create(tid) else { return SIG_DFL; };
    let old = t.state[idx].handlers[signum as usize];
    if signal_catchable(signum) {
        t.state[idx].handlers[signum as usize] = handler;
    }
    old
}

/// Get signal mask for current task.
pub fn signal_get_mask() -> u32 {
    let tid = caller_tid();
    let t = SIG_TABLE.lock();
    match t.find(tid) {
        Some(idx) => t.state[idx].mask,
        None      => 0,
    }
}

/// Set signal mask for current task. Returns 0 on success, -1 if no slot
/// could be allocated.
///
/// Signature changed from `()` to `i32`: silently doing nothing on a full
/// table is how the old aliasing bug hid. A caller that cannot mask a signal
/// must be able to find out.
pub fn signal_set_mask(mask: u32) -> i32 {
    let tid = caller_tid();
    let mut t = SIG_TABLE.lock();
    let Some(idx) = t.get_or_create(tid) else { return -1; };
    // SIGKILL and SIGSTOP cannot be masked
    t.state[idx].mask = mask & !((1u32 << SIGKILL) | (1u32 << SIGSTOP));
    0
}

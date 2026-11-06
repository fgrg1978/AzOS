// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
/// Syscall handlers — port of kernel/core/syscall.c
///
/// Each function corresponds to one syscall.  Handlers for subsystems that
/// are not yet fully implemented return -1.
///
/// Security (AQ6): Hardware-access syscalls check the caller's capability table
/// when the caller is a user-space process (user_pt != 0). Kernel tasks bypass
/// the check (they have full access); user tasks hold what the topology seeds.

use azos_abi::cap::{ty, CapType};
#[cfg(not(feature = "use-robot"))]
use crate::no_robot::robot as azos_robot;
use crate::file_ops::{cstr_to_bytes, file_ops};
use azos_net::{
    socket_create_owned,
    socket_recv, socket_close,
    SockAddr, net_get_ip,
};

// ── The capability check of the untyped calls ────────────────────────────────
//
// An untyped call names its object by id, so the check is a presence test over
// the caller's own capability table. Kernel tasks (user_pt == 0) bypass it.

/// Does the calling task hold a capability of `kind` for `resource`, with
/// `WRITE` when `need_write` and `READ` otherwise? Kernel tasks always pass. A
/// refusal writes one `SAFETY_CAP_DENIED` record.
///
/// # The one authority
///
/// The answer comes from the caller's `cap_store` table, the table every typed
/// call resolves against. Before, it came from the
/// global `HANDLES` table, filled at boot beside the typed seed, so a task's
/// authority was written twice and could disagree.
///
/// # No containment here
///
/// `holds_kind_resource_uncontained`, not `holds_kind_resource_with`. Each
/// untyped write that containment refuses asks `untyped_write_contained` after
/// this check, so a caller that does not hold the object keeps `E_PERM` and a
/// holder gets `-EAGAIN` without a denial record. The bus scan and the motor
/// binding are not contained here at all. Asking containment in this function
/// would turn each of those into a refusal and a spurious record.
///
/// # `resource`
///
/// The value the call's typed twin stores for the object, with the call's
/// argument narrowed the way the check always narrowed it; see each call site.
/// No packed kind (Port, Shm, IoRing) is asked here: the presence
/// check refuses those.
pub fn cap_check(kind: azos_abi::cap::CapType, resource: u32, need_write: bool) -> bool {
    // Kernel tasks have full access.
    if azos_sched::current_user_pt() == 0 {
        return true;
    }
    use azos_abi::cap::CapPerms;
    let need = if need_write { CapPerms::WRITE } else { CapPerms::READ };
    let tid = azos_sched::current_task_tid();
    // `None`: the TID names no live task, which holds nothing.
    let allowed = azos_ipc::cap_store::with_table(tid, |t| {
        t.holds_kind_resource_uncontained(kind, resource, need)
    })
    .unwrap_or(false);
    if !allowed {
        record_cap_denial(kind, resource, need_write);
    }
    allowed
}

azos_common::ro_hook! {
    /// Where a capability denial goes, installed by the kernel at boot.
    ///
    /// # Why a hook and not a call
    ///
    /// The flight recorder lives in `crates/domains/robot/behavior` and this crate does not
    /// depend on it — `behavior` is above `syscall` in the graph, and the edge
    /// would close a cycle. Same seam, same reason, as `MotorGate` in
    /// `crates/domains/robot/robot` and `FileOps` for the TCB split: the kernel is the one place
    /// that can see both sides, so it is the place that wires them.
    ///
    /// `None` until `set_cap_deny_recorder` runs, which makes the pre-boot window
    /// silent rather than a null call.
    static CAP_DENY_RECORDER: fn(u8, u32, bool);
}
/// Install the capability-denial recorder. Called once at boot.
pub fn set_cap_deny_recorder(f: fn(kind_code: u8, target: u32, need_write: bool)) {
    CAP_DENY_RECORDER.set(f);
}

azos_common::ro_hook! {
    /// Where a ring-3 emergency stop is carried out, installed by the kernel at
    /// boot.
    ///
    /// Same seam and the same reason as `CAP_DENY_RECORDER` above: latching the
    /// e-stop lives in `crates/domains/robot/behavior`, disarming the ESC in `crates/drivers/rc-esc`,
    /// and the durable record in the flight recorder — all above this crate in the
    /// graph, so the kernel is the one place that can see both sides.
    ///
    /// **`None` fails CLOSED here, not silently.** A missing denial recorder costs
    /// a log line; a missing e-stop handler would mean returning success for an
    /// emergency that nothing carried out, which is the worst answer this call can
    /// give. `MotorServer::estop` reports the failure to the caller instead.
    static ESTOP_HANDLER: fn();
}
/// Install the emergency-stop handler. Called once at boot.
pub fn set_estop_handler(f: fn()) {
    ESTOP_HANDLER.set(f);
}

/// Test-only: forget the installed handler.
#[cfg(test)]
pub fn __estop_handler_clear_for_tests() {
    ESTOP_HANDLER.clear_for_tests();
}

/// Run the installed emergency-stop handler (the `Motor` interface's `estop`,
/// after its authority check). `false` when none is installed: the stop was
/// not carried out, and the caller must say so.
pub(crate) fn run_estop_handler() -> bool {
    let h = ESTOP_HANDLER.get();
    match h {
        Some(f) => {
            f();
            true
        }
        None => false,
    }
}

/// Report one denial.
///
/// # Why this exists at all
///
/// `SAFETY_CAP_DENIED` has been a defined event code in the flight recorder
/// since the recorder was written and had **no production call site** — only a
/// host test referenced it. So the owner's rule for the black box ("security
/// events, all of them") was missing the event that says an untrusted program
/// asked for an actuator and was refused. The refusal worked; nothing recorded
/// that it had happened, which is exactly the evidence an incident review
/// needs and the one thing a denied caller cannot be trusted to report.
///
/// The lock is released before the call, so nothing is held while the recorder
/// runs — same rule as `gate_speed`.
///
/// # Cost
///
/// On the granted path this is not reached at all, which matters: `cap_check`
/// is on every hardware syscall and was deliberately rewritten for latency
/// (one locked pass instead of up to 256 lock/unlock pairs). A denial is by
/// definition the exceptional path, and the recorder's `log_safety_violation`
/// only touches the in-memory ring — no block device, no flush.
///
/// # Bounded per task
///
/// That ring is also why a denial cannot be recorded unconditionally: see
/// [`admit_denial_record`]. Past its bound a task's denials are counted, not
/// pushed, and the count is written as one summary record.
#[inline]
pub(crate) fn record_cap_denial(kind: azos_abi::cap::CapType, resource: u32, need_write: bool) {
    let r = CAP_DENY_RECORDER.get();
    if let Some(f) = r {
        let code = kind.denial_code();
        // Only spent when there is a recorder to spend it on.
        if admit_denial_record(code) {
            f(code, resource, need_write);
            note_denial_recorded(azos_sched::current_task_tid());
        }
    }
}

/// The TID of the last task whose capability denial reached the flight
/// recorder (0: none since it was last taken). The Linux personality takes it
/// after a native call it translated was refused, to report whether the
/// refusal was recorded ("a Linux call outside the image's caps is
/// refused and recorded"). A hint for that report only, never a decision.
static LAST_DENIAL_RECORDED_TID: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

fn note_denial_recorded(tid: u32) {
    LAST_DENIAL_RECORDED_TID.store(tid, core::sync::atomic::Ordering::Relaxed);
}

/// Was the last recorded capability denial task `tid`'s? Clears the mark.
#[cfg(feature = "linux-abi")]
pub(crate) fn take_denial_recorded_for(tid: u32) -> bool {
    LAST_DENIAL_RECORDED_TID
        .compare_exchange(tid, 0, core::sync::atomic::Ordering::Relaxed, core::sync::atomic::Ordering::Relaxed)
        .is_ok()
}

azos_common::ro_hook! {
    /// Where a TYPED capability denial goes, installed by the kernel at boot.
    ///
    /// A second hook rather than a second argument on the first: the two records
    /// carry different things (`SAFETY_CAP_DENIED` a measured object and write
    /// bit, `SAFETY_CAP_DENIED_TYPED` a reason) and giving them one signature
    /// would mean every call site passing a placeholder for the half it does not
    /// have. See `crates/core/actuation/src/logger.rs`.
    static CAP_DENY_TYPED_RECORDER: fn(u8, u32);
}
/// Install the typed-capability-denial recorder. Called once at boot.
pub fn set_cap_deny_typed_recorder(f: fn(kind_code: u8, reason_code: u32)) {
    CAP_DENY_TYPED_RECORDER.set(f);
}

/// Record one typed capability refusal, and return `e` so this can be dropped
/// into an `errno_for_*` arm without restructuring it.
///
/// # Why this exists at all
///
/// `record_cap_denial` has exactly one caller, `cap_check` — the UNTYPED path.
/// No `*_TYPED` handler goes through `cap_check`, so until this function every
/// typed refusal was recorded nowhere. Left alone, the endpoint of migrating
/// each family to `Cap<T>` was a kernel where capability denials had quietly
/// stopped reaching the flight recorder, one family at a time, with the green
/// gate saying nothing.
///
/// # Why here and not at the 25 dereference sites
///
/// Every typed refusal in this file funnels through one of the twelve
/// `errno_for_*_err` functions — verified by grepping for `ECAPSTALE`,
/// `ECAPKIND` and `ECAPPERMS` and finding no return outside them. Each of
/// those knows its family's `CapKind` statically, so the kind code is exact
/// with no argument threaded through the call sites.
///
/// # `Contained` is not a denial
///
/// It is degraded mode refusing a write from a task that HOLDS the capability
/// — the safety system working, not a program reaching past its authority.
/// `is_denial()` is what keeps a containment episode from burying the real
/// records under thousands of its own. It is filtered before the per-task
/// bound as well, so a task retrying a contained write does not spend the
/// budget its real denials are counted against.
///
/// # One thing this cannot attribute
///
/// The typed handlers have no `current_user_pt() == 0` bypass — unlike
/// `cap_check`, they gate the kernel too. So a kernel-context caller
/// presenting a stale handle would log a safety violation attributable to no
/// ring-3 program. Nothing does that today (every typed handler is reached
/// from the syscall dispatch), but it is cheaper written down than
/// rediscovered from a recording.
#[inline]
pub(crate) fn note_typed_denial(kind: azos_abi::cap::CapType, e: azos_ipc::cap::CapError) {
    note_typed_denial_for(azos_sched::current_task_tid(), kind, e);
}

/// [`note_typed_denial`] on behalf of task `tid`, whose per-task bound the
/// record is charged to.
///
/// For the io_ring op table (`crate::ioring_ops`): an entry is authorized by
/// the ring's OWNER, so its refusal is the owner's, whichever context runs the
/// pass. The record itself is the same record; only the bound it counts
/// against is named explicitly instead of read from the running task.
pub(crate) fn note_typed_denial_for(tid: u32, kind: azos_abi::cap::CapType, e: azos_ipc::cap::CapError) {
    let _ = note_typed_denial_recorded(tid, kind, e);
}

/// The durable bucket of a task's caller-paced records: its Domain's key (the
/// threads of one process share one), the TID only when the task is gone.
pub(crate) fn durable_bucket(tid: u32) -> u32 {
    let dom = azos_sched::idx_for_tid(tid).map_or(0, azos_sched::task_domain);
    if dom != 0 { dom } else { tid }
}

/// [`note_typed_denial_for`], answering whether a record was handed to the
/// recorder: `false` for a non-denial, no recorder installed, or a record
/// the per-task bound suppressed (it is counted in the window's summary
/// instead). A caller that prints "recorded" prints it only on `true`.
pub(crate) fn note_typed_denial_recorded(tid: u32, kind: azos_abi::cap::CapType, e: azos_ipc::cap::CapError) -> bool {
    if !e.is_denial() {
        return false;
    }
    let r = CAP_DENY_TYPED_RECORDER.get();
    if let Some(f) = r {
        if admit_denial_record_for(tid, kind.denial_code()) {
            f(kind.denial_code(), e.code());
            // Kconfig DECISION_RECORDS_DEV: the same denial, under the same
            // per-task bound, as an explained decision. Off: nothing.
            azos_decision::record_keyed(
                azos_decision::Rule::CapDenial,
                azos_decision::Verdict::Deny,
                tid,
                durable_bucket(tid),
                [kind.denial_code() as u64, e.code() as u64, 0],
            );
            note_denial_recorded(tid);
            return true;
        }
    }
    false
}

// ── The per-task bound on denial records ──────────────────────────────────
//
// Both recorders above end in `log_safety_violation`, which reaches only the
// in-memory ring: 128 records, the oldest overwritten, and `LOG_DROPPED` counts
// none of what is overwritten. A ring-3 loop presenting forged handles pushed
// one record per syscall, and between two watchdog flushes (~0.5 s) that is
// enough to evict the ring-only records next to it — degrade-level changes,
// sys-wdt events, `SAFETY_UNKNOWN_PKT`. Only the e-stop, which flushes as it
// records, was out of reach. Audit finding, 2026-09-13.
//
// So a task may put at most `DENIAL_RECORDS_PER_WINDOW` records of each class
// into the ring per window (capability denials, seccomp audit records, ring-3
// exec refusals: `denial_class`). What it asks for beyond that is counted, and
// each class's count is written as ONE `SAFETY_CAP_DENIED_SUPPRESSED` record
// once the window is over: the flood stays in the black box as its size rather
// than its length, and a flood of one class leaves the other classes their
// budget.
//
// **Per task, never global.** A shared budget would hand the flooding task a
// way to silence every other task's denials, which is a better attack than
// the flood it replaces.
//
// **Keyed by TID, not by task-pool slot.** `NEXT_TID` is monotone and skips 0
// (`crates/core/sched/src/scheduler.rs`), so a TID names one task until the counter
// wraps and equality alone is reuse-safe; a pool slot is handed to the next
// task and would need `cap_store`'s owner check on top. The table is fixed at
// `DENIAL_BUCKETS` entries whatever the TIDs are: a TID with no entry takes a
// free one, else one whose window is over, else the oldest — and a count the
// evicted entry was holding is written out first, so no path drops one.
//
// **Where a count comes out.** On the task's next denial after its window;
// from `cap_denial_flush_pending`, which the kernel calls on its periodic
// flush, for a flood that simply stopped; and from `cap_denial_task_exit` for
// a task that dies holding one.
//
// **Installed, not built in.** The clock and the summary recorder arrive
// together through `set_cap_deny_limiter`: a bound whose counts had nowhere to
// go would be a silencer, so one is never installed without the other. The
// clock is a hook rather than a direct `timebase::now` for the host tests,
// which drive the window by hand. Until the kernel installs it every denial is
// recorded as before — a missing hook costs the old flood, never silence.

/// How many records of one class one task may put into the ring per window.
///
/// **Per class**, not per task alone: capability denials, seccomp audit records
/// and ring-3 exec refusals each get this many ([`denial_class`]). One budget
/// shared by the three let one class silence another: `captest` spends 13
/// capability denial admits before it issues its one audited call (116), and
/// with a shared budget of four that audit record was never written (gate 40).
/// A loop is cut off after the fourth record of its class, and the classes it
/// does not flood keep their own four.
const DENIAL_RECORDS_PER_WINDOW: u32 = 4;

/// The record classes a task's entry keeps a separate budget for.
const DENIAL_CLASSES: usize = 3;

/// The budget a record of `kind_code` spends: 0 for a capability denial (every
/// code of the frozen kind numbering, typed and untyped alike), 1 for a seccomp
/// audit record, 2 for a ring-3 exec refusal.
#[inline]
fn denial_class(kind_code: u8) -> usize {
    match kind_code {
        DENIAL_KIND_SECCOMP_AUDIT => 1,
        DENIAL_KIND_EXEC_REFUSED => 2,
        _ => 0,
    }
}

/// Entries in the per-task table: `MAX_TASKS` on default builds. Written out
/// rather than taken from `azos_sched::task::MAX_TASKS` because the host
/// harness's `azos_sched` shim (`tests/host/syscall-tests/shims/sched`) does
/// not export it. The eviction rule keeps the table correct at any size — a
/// smaller one only evicts sooner.
const DENIAL_BUCKETS: usize = 64;

/// The action code of a `SAFETY_CAP_DENIED_SUPPRESSED` record whose suppressed
/// denials were of more than one kind. No kind code reaches it: the frozen
/// `CapKind::denial_code` numbering ends in the twenties.
pub const DENIAL_KIND_MIXED: u8 = 0xFF;

/// One class's budget inside a task's entry.
#[derive(Clone, Copy)]
struct ClassBudget {
    /// Records of this class admitted in the current window.
    recorded: u32,
    /// Records of this class refused in the current window.
    suppressed: u32,
    /// The kind those were of, or `DENIAL_KIND_MIXED`. Meaningless while
    /// `suppressed == 0`.
    kind: u8,
}

impl ClassBudget {
    const FRESH: Self = Self { recorded: 0, suppressed: 0, kind: 0 };
}

#[derive(Clone, Copy)]
struct DenialBucket {
    used: bool,
    tid: u32,
    /// Clock value at which the current window opened. One window for every
    /// class: the classes differ in budget, not in time.
    start: u64,
    /// Indexed by [`denial_class`].
    class: [ClassBudget; DENIAL_CLASSES],
}

/// The summaries one entry owes: at most one per class.
#[derive(Clone, Copy)]
struct Owed {
    items: [(u8, u32); DENIAL_CLASSES],
    n: usize,
}

impl Owed {
    const NONE: Self = Self { items: [(0, 0); DENIAL_CLASSES], n: 0 };

    fn push(&mut self, owed: (u8, u32)) {
        // At most one summary per class reaches one `Owed`: an entry is either
        // claimed (its evicted owner's counts) or expired (its own), never both
        // in one admit, so `n` stays within `DENIAL_CLASSES`.
        if self.n < DENIAL_CLASSES {
            self.items[self.n] = owed;
            self.n += 1;
        }
    }

    fn as_slice(&self) -> &[(u8, u32)] {
        &self.items[..self.n]
    }
}

impl DenialBucket {
    const FREE: Self = Self { used: false, tid: 0, start: 0, class: [ClassBudget::FRESH; DENIAL_CLASSES] };

    #[inline]
    fn expired(&self, now: u64, window: u64) -> bool {
        now.wrapping_sub(self.start) >= window
    }

    /// The summaries this entry owes, one per class that suppressed anything,
    /// in class order, and forget them.
    fn take_pending(&mut self) -> Owed {
        let mut owed = Owed::NONE;
        if !self.used {
            return owed;
        }
        for c in self.class.iter_mut() {
            if c.suppressed != 0 {
                owed.push((c.kind, c.suppressed));
                c.suppressed = 0;
            }
        }
        owed
    }
}

#[derive(Clone, Copy)]
struct DenialLimiter {
    now: fn() -> u64,
    window: u64,
    summary: fn(u8, u32),
}

static CAP_DENY_LIMITER: azos_sync::SpinLock<Option<DenialLimiter>> =
    azos_sync::SpinLock::new(None);

static DENIAL_TABLE: azos_sync::SpinLock<[DenialBucket; DENIAL_BUCKETS]> =
    azos_sync::SpinLock::new([DenialBucket::FREE; DENIAL_BUCKETS]);

/// Install the per-task bound on denial records. Called once at boot.
///
/// `now` is the clock a window is measured on and `window_ticks` its length in
/// that clock's units — the kernel passes `timebase::now` and
/// `timebase::TIMER_FREQ`, one second. `summary` writes one
/// `SAFETY_CAP_DENIED_SUPPRESSED` record, `kind_code` as its action code and
/// `count` as its detail.
pub fn set_cap_deny_limiter(
    now: fn() -> u64,
    window_ticks: u64,
    summary: fn(kind_code: u8, count: u32),
) {
    *CAP_DENY_LIMITER.lock() = Some(DenialLimiter { now, window: window_ticks, summary });
}

/// Uninstall the bound and forget every window. Host tests only: both are
/// process statics the next test would inherit.
#[cfg(test)]
pub fn __cap_deny_limiter_clear_for_tests() {
    *CAP_DENY_LIMITER.lock() = None;
    *DENIAL_TABLE.lock() = [DenialBucket::FREE; DENIAL_BUCKETS];
}

/// The entry whose window opened longest ago.
fn oldest_bucket(table: &[DenialBucket; DENIAL_BUCKETS], now: u64) -> usize {
    let mut best = 0;
    for (i, b) in table.iter().enumerate() {
        if now.wrapping_sub(b.start) > now.wrapping_sub(table[best].start) {
            best = i;
        }
    }
    best
}

/// May the calling task put one more denial record of `kind_code` into the
/// ring? The denial is counted either way.
///
/// The table lock is released before a summary is written, the rule every hook
/// in this file follows. A summary owed by the window this call closes is
/// written BEFORE the caller writes its own record, so the ring reads in the
/// order things happened.
fn admit_denial_record(kind_code: u8) -> bool {
    admit_denial_record_for(azos_sched::current_task_tid(), kind_code)
}

/// [`admit_denial_record`] for task `tid` rather than the running task.
fn admit_denial_record_for(tid: u32, kind_code: u8) -> bool {
    let lim = match *CAP_DENY_LIMITER.lock() {
        Some(l) => l,
        None => return true,
    };
    let now = (lim.now)();
    let class = denial_class(kind_code);
    let (admit, owed) = {
        let mut table = DENIAL_TABLE.lock();
        let (idx, mut owed) = match table.iter().position(|b| b.used && b.tid == tid) {
            Some(i) => (i, Owed::NONE),
            None => {
                let i = table
                    .iter()
                    .position(|b| !b.used)
                    .or_else(|| table.iter().position(|b| b.expired(now, lim.window)))
                    .unwrap_or_else(|| oldest_bucket(&table, now));
                let owed = table[i].take_pending();
                table[i] = DenialBucket { used: true, tid, start: now, ..DenialBucket::FREE };
                (i, owed)
            }
        };
        let b = &mut table[idx];
        if b.expired(now, lim.window) {
            // Merged, not assigned: an entry claimed just above holds its
            // evicted owner's counts in `owed` and has none of its own.
            let mine = b.take_pending();
            for &o in mine.as_slice() {
                owed.push(o);
            }
            b.start = now;
            for c in b.class.iter_mut() {
                c.recorded = 0;
            }
        }
        let c = &mut b.class[class];
        let admit = if c.recorded < DENIAL_RECORDS_PER_WINDOW {
            c.recorded += 1;
            true
        } else {
            c.kind = if c.suppressed == 0 || c.kind == kind_code { kind_code } else { DENIAL_KIND_MIXED };
            c.suppressed = c.suppressed.saturating_add(1);
            false
        };
        (admit, owed)
    };
    for &(kind, count) in owed.as_slice() {
        (lim.summary)(kind, count);
    }
    admit
}

/// Write out every count a closed window is still holding, and free the entries
/// whose windows are over.
///
/// For the flood that stops: its task makes no further denial to close the
/// window, so without this the count would wait for that task's next mistake,
/// possibly forever. The kernel calls it from `system_wdt_task` just before
/// `logger_flush`, so the summary reaches the disk on the same pass. A window
/// still open is left alone — its count is not final.
pub fn cap_denial_flush_pending() {
    let lim = match *CAP_DENY_LIMITER.lock() {
        Some(l) => l,
        None => return,
    };
    let now = (lim.now)();
    // One summary per class per entry at most: 64 entries x 3 classes x 8 bytes,
    // 1.5 KiB on the watchdog's stack.
    let mut owed = [(0u8, 0u32); DENIAL_BUCKETS * DENIAL_CLASSES];
    let mut n = 0;
    {
        let mut table = DENIAL_TABLE.lock();
        for b in table.iter_mut() {
            if b.used && b.expired(now, lim.window) {
                let mine = b.take_pending();
                for &o in mine.as_slice() {
                    owed[n] = o;
                    n += 1;
                }
                *b = DenialBucket::FREE;
            }
        }
    }
    for &(kind, count) in &owed[..n] {
        (lim.summary)(kind, count);
    }
}

/// Write out the counts `tid` is holding, whatever its window, and free its
/// entry. The kernel calls it from the task-exit hook: a task killed mid-flood
/// must not take its counts with it.
pub fn cap_denial_task_exit(tid: u32) {
    let lim = match *CAP_DENY_LIMITER.lock() {
        Some(l) => l,
        None => return,
    };
    let owed = {
        let mut table = DENIAL_TABLE.lock();
        match table.iter().position(|b| b.used && b.tid == tid) {
            Some(i) => {
                let o = table[i].take_pending();
                table[i] = DenialBucket::FREE;
                o
            }
            None => Owed::NONE,
        }
    };
    for &(kind, count) in owed.as_slice() {
        (lim.summary)(kind, count);
    }
}

// ── Seccomp audit records ─────────────────────────────────────────────────
//
// An image profile in audit mode (`ImageProfile::audit`,
// `crates/core/sched/src/seccomp.rs`) lets a syscall outside its row through instead
// of refusing it, and the dispatcher reports each one here. The record takes
// the per-task bound above with a budget of its own (`denial_class`): a ring-3
// loop of unlisted calls cannot evict the records beside it in the ring, a
// task's capability denials cannot use up its audit records or the reverse,
// and what it asks for past the bound comes out as one
// `SAFETY_CAP_DENIED_SUPPRESSED` with action `DENIAL_KIND_SECCOMP_AUDIT`.

/// The action code of a `SAFETY_CAP_DENIED_SUPPRESSED` record for suppressed
/// seccomp audit records. Outside the frozen kind numbering, like
/// `DENIAL_KIND_MIXED`. Audit records are summarised apart from capability
/// denials, never folded into `DENIAL_KIND_MIXED`.
pub const DENIAL_KIND_SECCOMP_AUDIT: u8 = 0xFE;

azos_common::ro_hook! {
    /// Where an audited syscall is recorded, installed by the kernel at boot. A hook
    /// for the reason `CAP_DENY_RECORDER` is one.
    static SECCOMP_AUDIT_RECORDER: fn(u16);
}
/// Install the seccomp audit recorder. Called once at boot.
pub fn set_seccomp_audit_recorder(f: fn(syscall_nr: u16)) {
    SECCOMP_AUDIT_RECORDER.set(f);
}

/// Uninstall the seccomp audit recorder. Host tests only: it is a process static
/// the next test would inherit.
#[cfg(test)]
pub fn __seccomp_audit_recorder_clear_for_tests() {
    SECCOMP_AUDIT_RECORDER.clear_for_tests();
}

/// Record one syscall an audit-mode filter let through.
///
/// `syscall_dispatch_out` calls it on `FilterVerdict::Audit` only: a listed
/// syscall, or one from a task with no filter, never reaches it. Cold and out of
/// line, so the filter check on the dispatch path stays a few instructions. The
/// lock is released before the recorder runs, as in every hook in this file.
/// With no recorder installed nothing is recorded and nothing is counted.
#[cold]
#[inline(never)]
pub fn record_seccomp_audit(syscall_nr: u16) {
    record_seccomp_audit_for(azos_sched::current_task_tid(), syscall_nr);
}

/// [`record_seccomp_audit`] charged to task `tid`'s bound: an io_ring entry
/// audited on its owner's profile, whichever context runs the pass.
pub fn record_seccomp_audit_for(tid: u32, syscall_nr: u16) {
    let r = SECCOMP_AUDIT_RECORDER.get();
    if let Some(f) = r {
        if admit_denial_record_for(tid, DENIAL_KIND_SECCOMP_AUDIT) {
            f(syscall_nr);
        }
    }
}

/// V1.8 (owner decision, 2026-09-26): what `dispatch.rs`'s `FilterVerdict::
/// Deny` arm does — Linux strict-mode `SECCOMP_RET_KILL_PROCESS` semantics
/// for an unlisted syscall from a confined task, in place of the old `-1`
/// (`E_PERM`) return. U07-6 named that `-1` as indistinguishable from a
/// generic failure (libsys reads a denied 581 as "posted", a denied 580 as
/// `Ok(None)`) and numerically identical to `Errno::EPERM.to_syscall_ret()`;
/// killing removes the ambiguity instead of adding a third code to
/// disambiguate it.
///
/// **Lives here, not in `dispatch.rs`,** so a host test can call it directly:
/// `dispatch.rs` is `include_str!`'d as text by this crate's test suite
/// (U14-8), never compiled, so nothing there can be driven or observed by a
/// real test — only string-matched. `dispatch.rs`'s `Deny` arm calls this
/// and nothing else (`both_the_deny_arm_and_this_function_agree` below pins
/// that by source text).
///
/// The record is written BEFORE the kill: an unauditable kill defeats the
/// point of recording the denial at all, and this function never returns,
/// so there is no later point at which the record could still land.
///
/// `159 = 128 + 31`: Linux's own "killed by signal N" exit-status
/// convention, borrowed as a documented sentinel. This ABI has no signals
/// (350-356 are retired), so nothing else can collide with it, and 31 is
/// SIGSYS on Linux — the signal a real strict-mode kill delivers.
pub const SECCOMP_KILL_EXIT_CODE: i32 = 159;

// NOT `#[cold]`: measured +18/+8 instr on every syscall's floor when it was —
// the attribute reshapes the caller (`dispatch`), not just this function.
#[inline(never)]
pub(crate) fn seccomp_deny_kill(num: u64) -> ! {
    // A forced stop (`SYS_ALERT`) empties the target's filter so
    // that its next syscall lands here. That is a stop, not a profile breach:
    // it ends with the code the stop asked for (`128 + signo`) and says so,
    // instead of 159 and a `[SECCOMP]` line.
    if let Some(code) = azos_sched::scheduler::take_current_forced_exit() {
        forced_stop_exit(num, code)
    }
    azos_ipc::trace_event(
        azos_ipc::TRACE_SYSCALL,
        num as u32, 0xDEAD, 0, 0, // 0xDEAD = denied marker, same as before V1.8
    );
    // Operator-visible and gate-greppable: before V1.8, `uhello`'s own
    // userspace probe (`userspace/tests/uhello/src/main.rs`) observed the `-1`
    // `getpid` returned and printed the refusal itself. It cannot do that
    // anymore — the syscall that would have told it never returns — so the
    // console line moves here, the one place on this path that still runs.
    // `tools/gate/ci_check.sh`'s three seccomp rows key on `uhello`'s old line
    // and need a new one to grep; this is the replacement (see the report
    // for the exact rows and why this line's shape was chosen to be
    // greppable per-row: tid identifies WHICH task, `num` WHICH syscall).
    azos_drv_sys::kwarn!(
        "[SECCOMP] tid={} killed: syscall {} not in its profile",
        azos_sched::current_task_tid(), num,
    );
    azos_sched::scheduler::task_exit_by_signal(SECCOMP_KILL_EXIT_CODE)
}

/// [`seccomp_deny_kill`] for a call to a kernel-hosted endpoint whose interface
/// (host key `key`, `azos_devif::key`) is not in the image's profile
/// (`ImageProfile::ifaces`): the same breach, the same exit code, a line that
/// names the interface because the call number (`SYS_IPC_CALL`) is listed.
#[inline(never)]
pub(crate) fn seccomp_deny_iface_kill(key: u16) -> ! {
    let num = azos_abi::syscall_nr::SYS_IPC_CALL;
    if let Some(code) = azos_sched::scheduler::take_current_forced_exit() {
        forced_stop_exit(num, code)
    }
    azos_ipc::trace_event(azos_ipc::TRACE_SYSCALL, num as u32, 0xDEAD, 0, 0);
    azos_drv_sys::kwarn!(
        "[SECCOMP] tid={} killed: endpoint interface {} not in its profile",
        azos_sched::current_task_tid(), key,
    );
    azos_sched::scheduler::task_exit_by_signal(SECCOMP_KILL_EXIT_CODE)
}

/// What `SYS_INVOKE` does with an op whose class the image's profile does not
/// list (`ImageProfile::ops`): the same breach as an unlisted syscall number,
/// the same exit code, a line that names the op because the number
/// (`SYS_INVOKE`) is listed.
#[inline(never)]
pub(crate) fn seccomp_deny_op_kill(op: u16) -> ! {
    let num = azos_abi::syscall_nr::SYS_INVOKE;
    if let Some(code) = azos_sched::scheduler::take_current_forced_exit() {
        forced_stop_exit(num, code)
    }
    azos_ipc::trace_event(azos_ipc::TRACE_SYSCALL, num as u32, 0xDEAD, 0, 0);
    azos_drv_sys::kwarn!(
        "[SECCOMP] tid={} killed: invoke op {:#06x} (kind {}, class {}) not in its profile",
        azos_sched::current_task_tid(), op, azos_abi::invoke::op_kind(op), azos_abi::invoke::op_class(op),
    );
    azos_sched::scheduler::task_exit_by_signal(SECCOMP_KILL_EXIT_CODE)
}

/// The forced-stop half of [`seccomp_deny_kill`]: end the task
/// with the code the stop asked for, and say who did it.
#[inline(never)]
fn forced_stop_exit(num: u64, code: i32) -> ! {
    // Wave 13: a member of an ending thread group is stopped by its own
    // process, not by an ancestor; nothing to say.
    if azos_sched::group::current_group_ending() {
        azos_sched::task_exit_with_code(code)
    }
    azos_drv_sys::kprintln!(
        "[KILL] tid={} stopped by an ancestor at syscall {}: exit {}",
        azos_sched::current_task_tid(), num, code,
    );
    azos_sched::scheduler::task_exit_by_signal(code)
}

// ── Degraded-mode containment on the untyped path ─────────────────────────

/// What an untyped write returns while degraded-mode containment refuses it.
///
/// The errno every typed twin returns for `CapError::Contained`, so a program
/// learns the same thing whichever door it used: the authority is suspended,
/// not gone — ask again. Every untyped contract below is "negative on error",
/// and `-EAGAIN` is distinct from both `-1` and `E_PERM`, which is the
/// distinction a caller needs.
pub(crate) const E_CONTAINED: i64 = azos_abi::error::Errno::EAGAIN.to_syscall_ret();

/// Is this untyped write refused by degraded-mode containment?
///
/// # Why the untyped calls need it
///
/// Containment lives in `CapTable::get` and `holds_kind_resource_with`, so it
/// only ever reached the typed path. The untyped twins answer from
/// `cap_check`'s uncontained presence test, a socket's owner stamp or a
/// descriptor table, and none of those consults degraded mode — so while
/// contained, a task whose `send_typed` was refused sent the same bytes with
/// `send` on the same socket. Owner decision 2026-09-13: containment refuses
/// every WRITE through a capability, files and sockets included.
/// Receiving and closing stay live, and so does releasing — destroying a port
/// or an io_ring, unregistering a driver, all on the typed side — which still
/// needs its capability. Motor direction changes are refused in the motor
/// layer instead (`MOTOR_REFUSED_HALTED`). The twins are listed in
/// `tests/host/syscall-tests/src/unit6_contain.rs`.
///
/// # Ring 3 only
///
/// A kernel task holds no capabilities — `cap_check` and `socket_access_ok`
/// both let `user_pt == 0` through — so "a write through a capability" does not
/// describe it. The kernel's own brain link, which carries the order that ends
/// containment, does not traverse these handlers (`socket_access_ok`'s doc);
/// this keeps a refusal off that link if it ever starts to.
///
/// # Where each caller puts it
///
/// After the arguments and the caller's authority are checked, so a task that
/// does not hold the object still gets its usual refusal and learns nothing
/// from containment; before anything is copied or written. A containment
/// refusal is not recorded: the caller holds the capability, the reason
/// `note_typed_denial` drops `Contained`.
#[inline]
pub(crate) fn untyped_write_contained() -> bool {
    azos_sched::current_user_pt() != 0 && azos_ipc::cap::degraded_active()
}

/// Permission denied error code.
pub(crate) const E_PERM: i64 = -99;

// ── User virtual-address ceiling ─────────────────────────────────────────────
//
// Was a hardcoded `0x8000_0000` copy of `USER_STACK_TOP` in
// `crates/core/sched/src/process.rs`, kept in sync by hand because that constant
// used to be private and could not be imported. It is `pub` now (and derived
// from the platform's `RAM_BASE` rather than a literal — VF2's `RAM_BASE =
// 0x4000_0000` sits inside the old `0x8000_0000` ceiling, which put the user
// stack and MMIO window inside kernel-owned RAM there and made
// `vmm::kernel_entry_collision` refuse every `exec`; see the derivation's own
// doc comment in `process.rs`), so this is now the same value by
// construction instead of two literals someone has to remember to move
// together.
//
// WHY a syscall-side copy exists at all: user and kernel page tables **share
// their L1/L0 tables** (`vmm::copy_kernel_entries_to_user` splices the kernel
// and MMIO entries into every user PT).  A VA-taking syscall that walks the
// "user" page table above this line is therefore editing the *kernel's* page
// table.  `sys_munmap(0x1000_0000, 4096)` used to zero the UART PTE for every
// hart; the next `kprintln!` faulted in S-mode and, with `panic = "abort"`,
// reset the board.  On a robot that is a physical-safety event, so any syscall
// that takes a raw VA range must reject addresses at or above this bound
// before touching a PTE.
pub(crate) const USER_VA_TOP: usize = azos_sched::process::USER_STACK_TOP;

// ── ELF bounce buffer for SYS_SPAWN_EX and the Linux execve ────────────────────────────
//
// Largest ELF the tree currently produces is ~12.5 KiB (`$AZOS_OUT/build/brain_client.elf`);
// 128 KiB leaves an order of magnitude of headroom while staying far cheaper in
// `.bss` than the shell's 256 KiB buffer (which VF2/K1 linker scripts also pay
// for).
const EXEC_MAX_BYTES: usize = 128 * 1024;

/// Shared kernel bounce buffer for the Linux `execve` and `SYS_SPAWN_EX`.
///
/// WHY it exists: an image is read through the file seam, whole, into a fixed
/// static. An earlier version grew an unbounded `Vec` for the file; a large
/// file on the FAT32 image exhausted the kernel heap, and the allocation error
/// path panics, which `panic = "abort"` turns into a reset. A fixed static
/// cannot exhaust anything, and a file that does not fit is refused (or
/// streamed), never read as a prefix.
///
/// A [`Claim`](azos_sync::claim::Claim), not a lock held across a device wait
/// (owner rule F1): the Linux `execve` and `SYS_SPAWN_EX` own it across the file
/// read that fills it, a device wait, and a `Mutex` held there boosts a task
/// that is waiting on the disk. A claim's exchange mutex is held for the
/// instant of taking and giving it; a contender sleeps with nothing held.
/// Real-time tasks never read a file (`RT_BLOCK_IO_CHECK`), so no RT waiter
/// needs a boost from its owner.
/// Never a `SpinLock`: see below. Gate canary `exec-bounce-pi-canary` (kernel
/// feature): the claim keeps its exchange mutex for as long as it is owned, so
/// a `Mutex` is held across the read (the `lat-fat` smoke's `pi_io_site` names
/// it).
///
/// What it protects, and for how long: exactly the shared BUFFER — two harts
/// exec'ing at once must not interleave their ELF bytes; the hand-off itself
/// is per-task since K-C21 and needs no serialisation here. Both callers hold
/// it across the image load (the spawn across `spawn_prepare`), which returns
/// normally (it publishes the exec hand-off on the caller's own task rather
/// than switching away), so the guard always drops. That hold duration is not the problem, and is orthogonal to
/// the lock type: what the section must not be is non-preemptible while it
/// lasts.
///
/// Held across the file read of up to 128 KiB AND the whole image load, which
/// parses the ELF and builds the new address space — nesting `PMM`'s own lock
/// once per mapped page. Since K-C29 step 2 (`eeda7c4`) a `SpinLock` section is
/// non-preemptible, so holding one here would make a process start a real-time
/// latency floor measured in whole ELF loads.
///
/// Bounded rather than unbounded — but bounded at 128 KiB of copying plus a page-table build is not a bound worth
/// having on a hart that also runs a 1 kHz loop.
///
/// 8-aligned (wave 14): the image is hashed in place, and SHA-256 takes word
/// loads only from an aligned start (Zbb: ~190 instructions a block fewer
/// than byte loads). As a bare `[u8; N]` inside the mutex its start had no
/// alignment, and the spawn census measured the odd-start rate.
pub(crate) static EXEC_BOUNCE: azos_sync::claim::Claim<BounceBuf> =
    azos_sync::claim::Claim::new(BounceBuf(core::ptr::null_mut()));

/// The claim's payload: the buffer, taken from [`BOUNCE_CACHE`] by the first
/// [`exec_bounce`].
pub(crate) struct BounceBuf(*mut ExecBounce);

// SAFETY: the pointer is reached only through the claim's guard.
unsafe impl Send for BounceBuf {}

impl core::ops::Deref for BounceBuf {
    type Target = [u8; EXEC_MAX_BYTES];
    fn deref(&self) -> &Self::Target {
        assert!(!self.0.is_null());
        // SAFETY: non-null, and owned for the life of the kernel.
        unsafe { &(*self.0).0 }
    }
}

impl core::ops::DerefMut for BounceBuf {
    fn deref_mut(&mut self) -> &mut Self::Target {
        assert!(!self.0.is_null());
        // SAFETY: as above, and the guard is exclusive.
        unsafe { &mut (*self.0).0 }
    }
}

static BOUNCE_CACHE: azos_mm::cache::Cache<ExecBounce> = azos_mm::cache::Cache::new();

/// Own the bounce buffer; `None` when its memory cannot be had.
pub(crate) fn exec_bounce() -> Option<azos_sync::claim::ClaimGuard<'static, BounceBuf>> {
    let mut g = EXEC_BOUNCE.acquire();
    if g.0.is_null() {
        let p = BOUNCE_CACHE.alloc_zeroed();
        if p.is_null() { return None; }
        g.0 = p;
    }
    Some(g)
}

/// Fill and seal the buffer's cache (Kconfig `MM_PRELOAD_CACHES`).
pub fn preload_exec_bounce() -> bool { BOUNCE_CACHE.preload(1) }

pub fn exec_bounce_sealed() -> bool { BOUNCE_CACHE.is_sealed() }

/// Where `EXEC_BOUNCE` lives (diagnostics: the `lat-fat` smoke's F1 report
/// names the lock by its address).
pub fn exec_bounce_addr() -> usize {
    &EXEC_BOUNCE as *const _ as usize
}

/// The exec bounce buffer's bytes, 8-aligned; derefs to the array.
#[repr(C, align(8))]
pub(crate) struct ExecBounce(pub [u8; EXEC_MAX_BYTES]);

impl core::ops::Deref for ExecBounce {
    type Target = [u8; EXEC_MAX_BYTES];
    fn deref(&self) -> &Self::Target { &self.0 }
}

impl core::ops::DerefMut for ExecBounce {
    fn deref_mut(&mut self) -> &mut Self::Target { &mut self.0 }
}

// ── Where the FD table went ───────────────────────────────────────────────────
//
// It used to live here, as `static KERNEL_FD_TABLE: Mutex<FdTable>`. It now
// lives in `kernel/src/boot/seams.rs` inside `KernelFileOps`, together with the doc
// comment explaining why it is a `Mutex` and not a `SpinLock` — that
// reasoning is about holding a lock across a real FAT32 read, which is the
// implementation's problem and not this crate's.
//
// This crate no longer knows that descriptors are indices into a table, or
// that a table exists. That is the point: a `FileOps` in a signature here
// would have kept the filesystem's descriptor model inside the TCB behind an
// interface, which satisfies `tcb_check.sh` without making the partition true.

// ── Console I/O ───────────────────────────────────────────────────────────────

// ── Process ───────────────────────────────────────────────────────────────────

pub fn sys_exit(code: u64) -> i64 {
    // The code is preserved: it used to be discarded right here (`_code`) and
    // the parent had no way to learn how its child finished.
    azos_sched::task_exit_with_code(code as i32)
}

#[inline]
pub fn sys_getpid() -> i64 {
    // Wave 13: a thread's process id is its group leader's TID.
    azos_sched::current_proc_tid() as i64
}

pub fn sys_yield() -> i64 {
    azos_sched::task_yield();
    0
}

pub fn sys_fork(sepc: u64, user_sp: u64, regs: &azos_sched::UserRegs) -> i64 {
    // **The child inherits descriptors and is seeded from its own row**
    // (owner decision, round 49). Its files
    // and pipe ends are duplicates sharing the parent's open descriptions, at
    // the parent's exact handles; its other capabilities are minted from the
    // topology row its parent was seeded from, never copied from the
    // parent's table. See `crate::natfork`.
    //
    // A verbatim copy of the parent's table was built here on 2026-09-21 and
    // reverted the same day: `userspace/tests/ipctest` phase C caught a child
    // resolving its parent's runtime port and destroying it. Runtime objects
    // (ports, shared memory, rings, channels, sockets) are still not
    // inherited; a parent's handle on one is stale in the child. The
    // parent-owned endpoint bootstrap (`endpoint_inherit_at_fork`) is
    // unchanged and runs after this.
    // Wave 13: a fork from a thread group copies its shared address space
    // with no other member changing its layout meanwhile, and the
    // descriptors it duplicates are owned by the process, not the thread.
    let _mm = azos_sched::group::mm_lock();
    let parent = azos_sched::current_proc_tid();
    azos_sched::process::sys_fork_impl_hooked(sepc, user_sp, regs, &mut |child| {
        if !fork_regions_to_child(child) {
            return Err(azos_abi::error::Errno::ENOMEM.to_syscall_ret());
        }
        crate::natfork::native_child_setup(parent, child).map_err(|e| e.to_syscall_ret())
    })
}
/// `DOMAIN_WAIT`: a0 = child TID, a1 = `*mut i32` for the exit code, or 0.
///
/// Reaps THAT child. Returns its TID; `-1` if it is alive; `-ECHILD` if it is
/// not a child of the caller or was already reaped; `-EFAULT` if the status
/// pointer is unwritable.
///
/// # The three answers are three answers
///
/// `DOMAIN_WAIT` and `DOMAIN_WAIT` return the first finished child, so `-1`
/// there means "none of mine has finished". Here `-1` means "this one has not"
/// and `ECHILD` means "asking again will never help" — a caller polling on
/// `-1` would otherwise spin to its own bound against a TID that was never
/// going to answer.
///
/// # The note is consumed before the pointer is validated
///
/// Same shape and same cost as `sys_wait_status`: `take_exit_note_for` is a
/// destructive read, so an unwritable pointer loses the code. Reported as
/// `EFAULT` rather than swallowed — "the child was reaped and the code is
/// gone" is recoverable knowledge; `-1` would say "still running", which the
/// caller cannot detect as false.
pub fn sys_waitpid(child_tid: u64, status_ptr: u64) -> i64 {
    use azos_abi::error::Errno;
    use azos_sched::WaitpidMiss;

    if child_tid > u32::MAX as u64 {
        // Cannot name a TID, so it cannot be one of ours.
        return Errno::ECHILD.to_syscall_ret();
    }
    let me = azos_sched::current_proc_tid(); // wave 13: the process's children
    let (reaped, code) =
        match azos_sched::take_exit_note_for(me, child_tid as u32) {
            Ok(v) => v,
            Err(WaitpidMiss::NotYet) => return -1,
            Err(WaitpidMiss::NotOurs) => return Errno::ECHILD.to_syscall_ret(),
        };
    if status_ptr == 0 {
        return reaped as i64;
    }
    if azos_sched::UserPtr::<i32>::new(status_ptr).write(&code.to_le()).is_err() {
        return Errno::EFAULT.to_syscall_ret();
    }
    reaped as i64
}

/// `DOMAIN_WAIT`: `child` (0: any), `status_ptr`, and how long to wait
/// (`timeout_ns`, 0: not at all). The task is marked as waiting for a child
/// before each look, so an exit between the look and the sleep wakes it; the
/// sleep is also bounded to 10 ms, the in-kernel personality's bound, against
/// a wake that misses it.
pub fn sys_domain_wait(child: u64, status_ptr: u64, timeout_ns: u64) -> i64 {
    use azos_abi::error::Errno;
    let deadline = azos_drv_sys::timebase::now().saturating_add(azos_abi::time::ns_to_ticks_ceil(
        timeout_ns,
        azos_drv_sys::timebase::TIMER_FREQ,
    ));
    let me = azos_sched::current_proc_tid();
    loop {
        if timeout_ns != 0 {
            azos_sched::scheduler::set_current_waits_child(true);
        }
        let r = if child == 0 { sys_wait_status(status_ptr) } else { sys_waitpid(child, status_ptr) };
        let now = azos_drv_sys::timebase::now();
        let again = r == -1 && timeout_ns != 0 && now < deadline;
        let r = if again && child == 0 && !azos_sched::scheduler::has_reapable_child(me) {
            Errno::ECHILD.to_syscall_ret()
        } else if again && crate::ushell::stop_requested() {
            Errno::EINTR.to_syscall_ret()
        } else {
            r
        };
        if r != -1 || !again {
            azos_sched::scheduler::set_current_waits_child(false);
            return r;
        }
        crate::ushell::park_until(deadline.min(now.saturating_add(crate::ushell::ms_ticks(10))));
    }
}

/// `DOMAIN_EXIT_STATS`: a0 = an `EXIT_STAT_*` selector. Returns that
/// exit-path counter (`azos_sched::exit_stat`), or `-EINVAL`.
pub fn sys_exit_stats(which: u64) -> i64 {
    match azos_sched::exit_stat(which) {
        Some(n) => n as i64,
        None => azos_abi::error::Errno::EINVAL.to_syscall_ret(),
    }
}

/// `DOMAIN_WAIT`: a0 = `*mut i32` for the exit code, or 0.
///
/// Reaps one finished child, writes its exit code through `a0` when that
/// pointer is non-null, and returns the child's TID. `-1` when nothing has
/// finished — `WNOHANG`, exactly like `DOMAIN_WAIT`.
///
/// # The note is consumed before the pointer is validated, and that is a real
/// # cost, taken with eyes open
///
/// `take_exit_note` is a DESTRUCTIVE read: the notice is removed from the
/// table by the act of reading it. So a caller that passes an unwritable
/// pointer loses the notice — the child stays reaped and its code is gone.
/// The same shape as the driver-server handlers that pop before validating,
/// which is a known and documented class in this tree.
///
/// It is done this way anyway because the alternative is worse: validating
/// first means a window in which the notice is still in the table and this
/// call has already decided to take it, and two harts polling the same parent
/// would both pass validation and race to consume one notice. The write is
/// therefore attempted and its failure REPORTED, rather than silently
/// swallowed: `EFAULT` tells the caller the child was reaped and the code was
/// lost, which is recoverable knowledge. A `-1` would have said "no child
/// finished", which is a lie the caller cannot detect.
pub fn sys_wait_status(status_ptr: u64) -> i64 {
    use azos_abi::error::Errno;
    let me = azos_sched::current_proc_tid(); // wave 13: the process's children
    let (child_tid, code) = match azos_sched::take_exit_note(me) {
        Some(v) => v,
        None => return -1,
    };
    // A null pointer is "reap, do not report the code" — the documented way
    // to get `DOMAIN_WAIT`'s behaviour from this number.
    if status_ptr == 0 {
        return child_tid as i64;
    }
    if azos_sched::UserPtr::<i32>::new(status_ptr).write(&code.to_le()).is_err() {
        return Errno::EFAULT.to_syscall_ret();
    }
    child_tid as i64
}

// ── Exec: only images a seccomp profile is bound to ───────────────────────
//
// The seccomp image table (`crates/core/sched/src/seccomp.rs`, `IMAGE_SHA256`) is a
// whitelist of user images (owner decision 2026-09-14): an image whose SHA-256
// no profile is bound to is not started on any path. The autorun loader and the
// shell refuse it in the kernel; `SYS_SPAWN_EX` and the Linux `execve` refuse it
// for ring 3, with `EACCES`.

/// `SAFETY_EXEC_REFUSED` action code for an image no profile is bound to that
/// ring 3 asked to start (`SYS_SPAWN_EX`, the Linux `execve`). The autorun
/// loader writes 0, the shell 1.
pub const EXEC_REFUSED_ACTION_RING3: u8 = 2;

/// The action code of a `SAFETY_CAP_DENIED_SUPPRESSED` record whose suppressed
/// records were all ring-3 exec refusals. Outside the frozen kind numbering,
/// like `DENIAL_KIND_MIXED`.
pub const DENIAL_KIND_EXEC_REFUSED: u8 = 0xFD;

azos_common::ro_hook! {
    /// Where a refused ring-3 exec is recorded, installed by the kernel at boot. A
    /// hook for the reason `CAP_DENY_RECORDER` is one.
    static EXEC_REFUSED_RECORDER: fn(u8, u32);
}
/// Install the exec-refusal recorder. Called once at boot.
pub fn set_exec_refused_recorder(f: fn(action_code: u8, digest_head: u32)) {
    EXEC_REFUSED_RECORDER.set(f);
}

/// Uninstall the exec-refusal recorder. Host tests only.
#[cfg(test)]
pub fn __exec_refused_recorder_clear_for_tests() {
    EXEC_REFUSED_RECORDER.clear_for_tests();
}

/// Is `elf` an image a seccomp image profile is bound to? When it is not, the
/// refusal is recorded and the answer is no.
///
/// The record takes the per-task bound the capability denials use, under
/// `DENIAL_KIND_EXEC_REFUSED`, and reaches the ring only: a ring-3 loop of
/// refused execs is cut at the bound and gets no synchronous write per call.
/// `detail` is the first four bytes of the digest, big-endian, as the autorun
/// loader and the shell write it.
// Used by `tests/host/syscall-tests`; the spawn path checks by digest.
#[cfg_attr(target_os = "none", allow(dead_code))]
pub(crate) fn exec_image_is_bound(elf: &[u8]) -> bool {
    exec_image_is_bound_by_digest(&azos_sched::seccomp::image_digest(elf))
}

/// Same check as [`exec_image_is_bound`], for a digest the caller already
/// computed: the image is read and hashed in one pass
/// (`image_cache::read_verified`), so hashing it again here would be a second
/// SHA-256 pass over up to `EXEC_MAX_BYTES` of image with `EXEC_BOUNCE` owned.
pub(crate) fn exec_image_is_bound_by_digest(digest: &[u8; 32]) -> bool {
    if azos_sched::seccomp::image_for_digest(digest).is_some() {
        return true;
    }
    let head = u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]);
    record_exec_refused(EXEC_REFUSED_ACTION_RING3, head);
    false
}

/// Record one ring-3 image refusal under `action_code`: through the
/// installed recorder, under the per-task bound the capability denials use
/// (`DENIAL_KIND_EXEC_REFUSED`), ring only.
pub(crate) fn record_exec_refused(action_code: u8, digest_head: u32) {
    let _ = record_exec_refused_recorded(action_code, digest_head);
}

/// [`record_exec_refused`], answering whether the record reached the
/// recorder (for a console line that says so).
pub(crate) fn record_exec_refused_recorded(action_code: u8, digest_head: u32) -> bool {
    let r = EXEC_REFUSED_RECORDER.get();
    if let Some(f) = r {
        if admit_denial_record(DENIAL_KIND_EXEC_REFUSED) {
            f(action_code, digest_head);
            return true;
        }
    }
    false
}

/// After an `execve`'s commit: the current task slot's endpoint resolve cache
/// (Kconfig `IPC_RESOLVE_CACHE`) is the old image's, and goes.
#[cfg(feature = "linux-abi")]
pub(crate) fn exec_forget_resolves() {
    azos_ipc::endpoint::resolve_cache::clear_task(azos_sched::current_task_tid());
}

/// Wave 15 (plan 4a): an exec from a process with threads ends every other
/// thread and waits until they have gone (`scheduler::exec_end_other_threads`),
/// so none runs on the image being replaced; the exec'ing thread goes on as
/// the whole process, under the process's TID when it was not the leader.
/// The Linux `execve` calls it once the new image is read, checked (bound profile, rows) and admitted
/// (`process::exec_prepare_*`), and after dropping `EXEC_BOUNCE`: a refused
/// exec leaves every thread running, as Linux validates before `de_thread`.
///
/// `Err(Ending)` when the process is ending (or another of its threads is
/// already exec'ing). A process with no threads pays one load.
#[cfg(feature = "linux-abi")]
pub(crate) fn exec_end_other_threads() -> Result<(), azos_sched::scheduler::ExecDethreadError> {
    let n = azos_sched::scheduler::exec_end_other_threads()?;
    if n != 0 {
        azos_drv_sys::kprintln!(
            "[EXEC] tid={} ended {} other thread(s) before replacing its image",
            azos_sched::current_task_tid(), n,
        );
    }
    Ok(())
}

// `SYS_SLEEP_UNTIL` and `SYS_SLEEP_UNTIL`: `crate::sleep`.

// ── File I/O ──────────────────────────────────────────────────────────────────

/// `vfs_open`'s flag bits (`crates/fs/src/vfs.rs`), the ones that make an
/// `open` change the tree or a file: access mode in the low two bits.
const OPEN_ACCMODE: u64 = 0x3;
const OPEN_CREAT: u64 = 0x40;
const OPEN_TRUNC: u64 = 0x200;

/// Does an open with `flags` change what the named calls ([`fs_tree_gate`])
/// guard? `open` creates the file on `O_CREAT` and truncates it on `O_TRUNC`
/// inside the open itself, and a descriptor opened for writing rewrites the
/// file's bytes: all three need write authority over the result (security
/// survey, 2026-09-29; Storage L12). Linux closed the same gap in Landlock ABI
/// v3 (`LANDLOCK_ACCESS_FS_TRUNCATE`, 6.2): an open-time truncate had bypassed
/// a sandbox that forbade `truncate`.
const fn open_changes_tree(flags: u64) -> bool {
    flags & (OPEN_CREAT | OPEN_TRUNC | OPEN_ACCMODE) != 0
}

// ── Cap<File> typed handlers (563-566) ───────────────────────────────────────

/// The permissions a `Cap<File>` is minted with: the access mode of the `open`
/// flags (`O_RDONLY` 0, `O_WRONLY` 1, `O_RDWR` 2 — `crates/fs/src/vfs.rs`).
/// Mode 3 means nothing, and is refused before anything is opened.
const fn file_perms_for_flags(flags: u64) -> Option<azos_abi::cap::CapPerms> {
    use azos_abi::cap::CapPerms;
    match flags & 3 {
        0 => Some(CapPerms::READ),
        1 => Some(CapPerms::WRITE),
        2 => Some(CapPerms::RW),
        _ => None,
    }
}

/// Resolve a `SYS_IPC_CALL` destination, recording a capability
/// denial the way every other typed family records one.
///
/// The resolution itself lives in `azos_ipc::endpoint::endpoint_dest_for`,
/// next to the object and its tests. What this adds is the half that can only
/// live here: `note_typed_denial` is `pub(crate)` to this crate, so a forged
/// or stale endpoint handle would otherwise be refused correctly and recorded
/// **nowhere** — which is exactly the hole that function's own doc describes,
/// one family at a time, with the gate saying nothing.
///
/// `Unserved` is deliberately not recorded: the caller holds a real
/// capability and the service simply has not started, which is not a program
/// reaching past its authority. Recording it would bury the real denials under
/// every call made during a boot race.
pub fn endpoint_dest_recording(caller_tid: u32, cap_raw: u32) -> Option<azos_ipc::endpoint::Dest> {
    use azos_ipc::endpoint::EndpointCapError;
    match azos_ipc::endpoint::endpoint_resolve(caller_tid, cap_raw) {
        Ok(d) => Some(d),
        Err(EndpointCapError::Cap(e)) => {
            note_typed_denial(azos_abi::cap::ty::ENDPOINT, e);
            None
        }
        Err(_) => None,
    }
}

/// [`endpoint_dest_recording`] for the task `caller_tid` in task slot
/// `caller_idx` (the current one), through its resolve cache
/// (`azos_ipc::endpoint::resolve_cache`, Kconfig `IPC_RESOLVE_CACHE`): a
/// hit answers from the cache; a miss is the full resolution, recording a
/// refusal as before, and keeps what it accepted.
#[inline(always)]
pub fn endpoint_dest_at(caller_idx: usize, caller_tid: u32, cap_raw: u32) -> Option<azos_ipc::endpoint::Dest> {
    match azos_ipc::endpoint::resolve_cache::hit(caller_idx, caller_tid, cap_raw) {
        Some(d) => Some(d),
        None => endpoint_dest_miss(caller_idx, caller_tid, cap_raw),
    }
}

/// [`endpoint_dest_at`], with the serving task's slot as a hint (the IPC
/// fast path's): the resolve cache's on a hit (`resolve_cache::hit_at`,
/// unchecked), `usize::MAX` on a miss.
#[inline(always)]
pub fn endpoint_dest_slot_at(caller_idx: usize, caller_tid: u32, cap_raw: u32) -> Option<(azos_ipc::endpoint::Dest, usize)> {
    match azos_ipc::endpoint::resolve_cache::hit_at(caller_idx, caller_tid, cap_raw) {
        Some((d, s)) => Some((d, s as usize)),
        None => endpoint_dest_miss(caller_idx, caller_tid, cap_raw).map(|d| (d, usize::MAX)),
    }
}

/// [`endpoint_dest_at`]'s miss, out of line: the hit path keeps a small
/// frame.
#[inline(never)]
fn endpoint_dest_miss(caller_idx: usize, caller_tid: u32, cap_raw: u32) -> Option<azos_ipc::endpoint::Dest> {
    let d = endpoint_dest_recording(caller_tid, cap_raw)?;
    azos_ipc::endpoint::resolve_cache::fill(caller_idx, caller_tid, cap_raw, d);
    Some(d)
}

/// `SYS_CAP_DERIVE`'s capability step (wave 15 N11b): mint, in
/// `tid`'s table, a copy of the unbadged endpoint capability `cap_raw`
/// carrying `badge` with `rights` (`CapTable::mint_badged`'s rules, and only
/// of an endpoint a task serves: `azos_ipc::endpoint::mint_badged`). A
/// refusal is recorded under `ty::ENDPOINT`, here, where the
/// capability is resolved (the arm in `crate::ipc_v2` only maps codes).
pub fn mint_badged_recording(
    tid: u32,
    cap_raw: u32,
    badge: u32,
    rights: azos_abi::cap::CapPerms,
    expiry_ns: u64,
) -> Result<azos_abi::cap::CapHandle, azos_ipc::cap::CapError> {
    let r = azos_ipc::endpoint::mint_badged_until(tid, azos_abi::cap::CapHandle(cap_raw), badge, rights, expiry_ns);
    if let Err(e) = r {
        note_typed_denial(azos_abi::cap::ty::ENDPOINT, e);
    }
    r
}

/// `SYS_SCHEDCTL`'s capability step (N6b): `cap_raw` names, in `tid`'s own
/// table, a live capability to the kernel-hosted `time` endpoint with `WRITE`.
/// A refusal is recorded under `ty::ENDPOINT`, here, where the capability
/// is resolved (the arm in `crate::schedctl` only maps codes).
pub fn time_warrant_recording(tid: u32, cap_raw: u32) -> Result<(), azos_ipc::cap::CapError> {
    use azos_abi::cap::{CapHandle, CapPerms};
    use azos_ipc::cap::CapError;
    let h = CapHandle::from_raw(cap_raw);
    let r = azos_ipc::cap_store::read_table(tid, |t| {
        let Some((kind, rights, res)) = t.peek_raw(h) else { return Err(CapError::Stale) };
        if kind != ty::ENDPOINT
            || azos_ipc::endpoint::host_key_of_ref(res) != Some(azos_devif::key::TIME)
        {
            return Err(CapError::WrongKind);
        }
        if !rights.contains(CapPerms::WRITE) {
            return Err(CapError::MissingPerms);
        }
        // `peek_raw` reads the slot as it is stored; a warrant past its
        // deadline, or derived from one revoked and not yet swept, fails as
        // `get` fails it.
        if t.is_void(h) {
            return Err(CapError::Revoked);
        }
        if azos_ipc::cap::degraded_active() {
            return Err(CapError::Contained);
        }
        Ok(())
    })
    .unwrap_or(Err(CapError::Stale));
    if let Err(e) = r {
        if note_typed_denial_recorded(tid, ty::ENDPOINT, e) {
            azos_drv_sys::kwarn!(
                "[SCHED] schedctl REFUSED: tid {} lacks the time endpoint WRITE (recorded)", tid);
        }
    }
    r
}

fn errno_for_file_err(e: azos_ipc::cap::CapError) -> i64 {
    use azos_abi::error::Errno;
    use azos_ipc::cap::CapError;
    // Every typed refusal in this file reaches the recorder here — the one
    // choke point all twelve of these functions share. `Contained` is filtered
    // inside `note_typed_denial`, not here.
    note_typed_denial(azos_abi::cap::ty::FILE, e);
    match e {
        CapError::Stale | CapError::Revoked => Errno::ECAPSTALE.to_syscall_ret(),
        CapError::WrongKind => Errno::ECAPKIND.to_syscall_ret(),
        CapError::MissingPerms => Errno::ECAPPERMS.to_syscall_ret(),
        CapError::Contained => Errno::EAGAIN.to_syscall_ret(),
        CapError::NoSpace => Errno::EMFILE.to_syscall_ret(),
    }
}

/// `NODE_OPENAT`: a0 = the directory (a `Cap<Dir>`, a tree `Cap<File>`),
/// a1 = a NUL-terminated name relative to it, a2 = the flags. Opens the name
/// beneath the directory's root ([`FileOps::open_at`] joins them and refuses
/// every escape) and mints a `Cap<File>` naming the descriptor into the
/// caller's own table. Returns the raw handle, `-1` if the open fails,
/// `-EINVAL` for access mode 3, `-EMFILE` if the cap table is full, the
/// directory's capability error (`-ECAPKIND` for a handle that is not a
/// directory), `-ECAPPERMS` when the flags change the tree and no held tree
/// with `WRITE` covers the result ([`write_tree_covers_open`]).
pub fn sys_file_openat_typed(dir_raw: u64, rel_ptr: u64, flags: u64) -> i64 {
    use azos_abi::error::Errno;

    let perms = match file_perms_for_flags(flags) {
        Some(p) => p,
        None => return Errno::EINVAL.to_syscall_ret(),
    };
    let mut root = [0u8; azos_ipc::file_cap::TREE_PATH_MAX];
    // `READ` names the directory: the right to look names up beneath it.
    let root_len = match dir_root_for(dir_raw, azos_abi::cap::CapPerms::READ, azos_abi::invoke::NODE_OPENAT, &mut root) {
        Ok(n) => n,
        Err(e) => return e,
    };
    let mut buf = [0u8; SYS_PATH_MAX];
    let rel = match copy_path_from_user(&mut buf, rel_ptr) { Ok(p) => p, Err(e) => return e };
    if open_changes_tree(flags) {
        if let Err(e) = write_tree_covers_open(&root[..root_len], rel) {
            return e;
        }
    }
    open_beneath(&root[..root_len], rel, flags, perms)
}

/// Write authority for an open that changes the tree: a held tree
/// `Cap<File>` with `WRITE` that covers the path the join of `root` and `rel`
/// names, whichever directory the open was made through. This is the wave 10
/// rule (a tree grant is the authority for the calls that change the tree)
/// applied to the open, so a directory handle that only NAMES a wide
/// directory (the root `Cap<Dir>`, read-only) lets a task write exactly where
/// its row granted a write tree, and a directory it holds with `WRITE` is its
/// own covering tree. The join is the filesystem's own
/// (`azos_common::path::join_beneath`); a name that does not join is left to
/// the filesystem, which refuses it the same way.
fn write_tree_covers_open(root: &[u8], rel: &[u8]) -> Result<(), i64> {
    let mut joined = [0u8; azos_common::path::MAX_PATH];
    let Ok(n) = azos_common::path::join_beneath(root, rel, &mut joined) else { return Ok(()) };
    match held_tree_for(&joined[..n], true, azos_abi::cap::CapPerms::WRITE, azos_abi::invoke::NODE_OPENAT) {
        Some(Ok(_)) => Ok(()),
        Some(Err(e)) => Err(errno_for_file_err(e)),
        None => Err(errno_for_file_err(azos_ipc::cap::CapError::MissingPerms)),
    }
}

/// A tree `Cap<File>` the caller holds that covers `path` (`strict`: `path`
/// is an entry of the tree, not its root) and resolves for `op` with `need`
/// (`get_op`: every caveat of the warrant, an op mask against `op`'s class,
/// a quota, a receipt), and the resource it names. Every covering tree is
/// tried in turn, so a masked one does not hide an unmasked one; `Some(Err)`
/// is the refusal of the last that was tried. `None`: no held tree covers the
/// path with the right.
fn held_tree_for(
    path: &[u8],
    strict: bool,
    need: azos_abi::cap::CapPerms,
    op: u16,
) -> Option<Result<u32, azos_ipc::cap::CapError>> {
    use azos_abi::cap::ty;
    use azos_ipc::cap::{targets::File, Cap};
    // The covering trees first, under the tree table's lock alone; then the
    // caller's capability table, under its own. Never both at once.
    let mask = azos_ipc::file_cap::trees_covering(path, strict);
    if mask == 0 {
        return None;
    }
    let tid = azos_sched::current_task_tid();
    azos_ipc::cap_store::with_table(tid, |t| {
        let mut last = None;
        for h in t.handles_where(ty::FILE, |r, _, p| azos_ipc::file_cap::tree_in(r, mask) && p.contains(need)) {
            match t.get_op(Cap::<File>::from_raw(h), need, op) {
                Ok(r) => return Some(Ok(r)),
                Err(e) => last = Some(Err(e)),
            }
        }
        last
    })
    .flatten()
}

/// The root path of the directory capability `cap_raw`, written to `root`:
/// a tree `Cap<File>` holding `need`, checked for `op` (its op mask names
/// the op's class). A `Cap<File>` that names a descriptor is not a directory
/// (`-ECAPKIND`), as a tree is not a descriptor ([`file_fd_for`]).
fn dir_root_for(
    cap_raw: u64,
    need: azos_abi::cap::CapPerms,
    op: u16,
    root: &mut [u8; azos_ipc::file_cap::TREE_PATH_MAX],
) -> Result<usize, i64> {
    use azos_abi::cap::CapHandle;
    use azos_abi::error::Errno;
    use azos_ipc::cap::{targets::File, Cap};

    let cap: Cap<File> = Cap::from_raw(CapHandle::from_raw(cap_raw as u32));
    let tid = azos_sched::current_task_tid();
    match azos_ipc::cap_store::with_table(tid, |t| t.get_op(cap, need, op)) {
        Some(Ok(res)) if azos_ipc::file_cap::is_tree_resource(res) => {
            azos_ipc::file_cap::tree_path(res, root).ok_or_else(|| Errno::ECAPSTALE.to_syscall_ret())
        }
        Some(Ok(_)) => Err(errno_for_file_err(azos_ipc::cap::CapError::WrongKind)),
        Some(Err(e)) => Err(errno_for_file_err(e)),
        None => Err(Errno::EINVAL.to_syscall_ret()),
    }
}

/// Open `rel` beneath `root` and mint the `Cap<File>` for it: the one place a
/// ring-3 file open reaches the filesystem.
fn open_beneath(root: &[u8], rel: &[u8], flags: u64, perms: azos_abi::cap::CapPerms) -> i64 {
    let ops = match file_ops() { Some(o) => o, None => return -1 };
    let fd = ops.open_at(root, rel, flags as u32);
    if fd < 0 {
        return fd;
    }
    grant_opened_file(fd, perms)
}

/// Mint the `Cap<File>` naming descriptor `fd`, just opened by the caller, or
/// close it again. The second half of an open ([`open_beneath`]).
fn grant_opened_file(fd: i64, perms: azos_abi::cap::CapPerms) -> i64 {
    use azos_abi::error::Errno;
    use azos_ipc::cap::targets::File;
    let tid = azos_sched::current_task_tid();
    // O3.4: a file the task opened itself is giftable (DELEGATE), like a socket.
    match azos_ipc::cap_store::grant::<File>(tid, perms.union(azos_abi::cap::CapPerms::DELEGATE), fd as u32) {
        Some(cap) => cap.raw().as_raw() as i64,
        None => {
            // Undo the open. A descriptor no capability names would hold one
            // of the task's `MAX_FDS_PER_TASK` slots until it exited. Nothing
            // names it yet, so the plain close is the right one.
            if let Some(o) = file_ops() { let _ = o.close(fd as i32); }
            Errno::EMFILE.to_syscall_ret()
        }
    }
}

/// The open of a path the Linux personality already holds (it joined
/// the guest's name onto the task's working directory). The directory it is
/// opened beneath is the held tree capability that covers the path with the
/// rights the flags need; a path no held tree covers is refused (recorded),
/// as an open through a handle the task does not hold would be. Ring 3 only.
#[cfg(feature = "linux-abi")]
pub(crate) fn file_open_typed_kpath(path: &[u8], flags: u64) -> i64 {
    use azos_abi::error::Errno;
    let perms = match file_perms_for_flags(flags) {
        Some(p) => p,
        None => return Errno::EINVAL.to_syscall_ret(),
    };
    if azos_sched::current_user_pt() == 0 {
        return -1;
    }
    if !azos_ipc::file_cap::path_is_plain(path) {
        return Errno::EINVAL.to_syscall_ret();
    }
    let need = if open_changes_tree(flags) {
        azos_abi::cap::CapPerms::RW
    } else {
        azos_abi::cap::CapPerms::READ
    };
    let mut root = [0u8; azos_ipc::file_cap::TREE_PATH_MAX];
    let root_len = match held_tree_for(path, true, need, azos_abi::invoke::NODE_OPENAT) {
        Some(Ok(res)) => azos_ipc::file_cap::tree_path(res, &mut root),
        // A holder while degraded mode is armed: a WRITE through a
        // capability is contained as the others are.
        Some(Err(e)) => return errno_for_file_err(e),
        None => None,
    };
    let Some(root_len) = root_len else {
        record_cap_denial(ty::FILE, 0, true);
        return Errno::EACCES.to_syscall_ret();
    };
    // The tree covers the path strictly: what is left after the root's
    // components is a plain relative name.
    let skip = root[..root_len].split(|&b| b == b'/').filter(|c| !c.is_empty()).count();
    open_beneath(&root[..root_len], rel_below(path, skip), flags, perms)
}

/// `path` without its first `skip` components (and the slashes before the
/// rest): the part of an absolute path that lies below a directory `skip`
/// components deep.
#[cfg(feature = "linux-abi")]
fn rel_below(path: &[u8], skip: usize) -> &[u8] {
    let mut rest = path;
    for _ in 0..skip {
        while rest.first() == Some(&b'/') { rest = &rest[1..]; }
        let end = rest.iter().position(|&b| b == b'/').unwrap_or(rest.len());
        rest = &rest[end..];
    }
    while rest.first() == Some(&b'/') { rest = &rest[1..]; }
    rest
}

/// The descriptor a `Cap<File>` the caller holds names, checked
/// and recorded as the typed calls check it (no right needed: the
/// personality reads its size and moves its offset).
#[cfg(feature = "linux-abi")]
pub(crate) fn file_desc_of(cap_raw: u64) -> Result<u64, i64> {
    file_fd_for(cap_raw, azos_abi::cap::CapPerms::NONE, crate::invoke::class_op(azos_abi::cap::ty::FILE, azos_abi::invoke::CLASS_READ))
}

/// Resolve a `Cap<File>` to its descriptor under the caller's table lock, and
/// release the lock before any file I/O — the same shape as
/// `sys_gpio_read_typed`, so a FAT32 read never holds a cap table.
///
/// The descriptor is always 3 or above (`vfs_open` never hands out 0-2), so
/// passing it on to `sys_read`/`sys_write` never meets their stdio arm.
///
/// `op` is the op the use performs (`NODE_READ`, `NODE_WRITE`, ...): it
/// discharges an `OP_MASK` caveat of the capability.
pub(crate) fn file_fd_for(cap_raw: u64, need: azos_abi::cap::CapPerms, op: u16) -> Result<u64, i64> {
    use azos_abi::cap::CapHandle;
    use azos_abi::error::Errno;
    use azos_ipc::cap::{targets::File, Cap};

    let cap: Cap<File> = Cap::from_raw(CapHandle::from_raw(cap_raw as u32));
    let tid = azos_sched::current_task_tid();
    match azos_ipc::cap_store::with_table(tid, |t| t.get_op(cap, need, op)) {
        // A `Cap<File>` naming a directory TREE (wave 10,
        // `azos_ipc::file_cap`) names no descriptor: refused as the wrong
        // kind of object, never handed on as a descriptor number.
        Some(Ok(fd)) if azos_ipc::file_cap::is_tree_resource(fd) => {
            Err(errno_for_file_err(azos_ipc::cap::CapError::WrongKind))
        }
        Some(Ok(fd)) => Ok(fd as u64),
        Some(Err(e)) => Err(errno_for_file_err(e)),
        None => Err(Errno::EINVAL.to_syscall_ret()),
    }
}

/// `NODE_READ`: a0=cap, a1=buf, a2=count. Requires `READ`.
pub fn sys_file_read_typed(cap_raw: u64, buf: u64, count: u64) -> i64 {
    match file_fd_for(cap_raw, azos_abi::cap::CapPerms::READ, azos_abi::invoke::NODE_READ) {
        Ok(fd) => sys_read(fd, buf, count),
        Err(e) => e,
    }
}

/// `NODE_WRITE`: a0=cap, a1=buf, a2=count. Requires `WRITE`.
pub fn sys_file_write_typed(cap_raw: u64, buf: u64, count: u64) -> i64 {
    match file_fd_for(cap_raw, azos_abi::cap::CapPerms::WRITE, azos_abi::invoke::NODE_WRITE) {
        Ok(fd) => sys_write(fd, buf, count),
        Err(e) => e,
    }
}

/// The typed file write over bytes already in a kernel buffer (the Linux
/// personality's `writev` gather, K2): the same `WRITE` check and the same
/// containment refusal as [`sys_file_write_typed`] from ring 3, then ONE
/// `write` of all of it (one hold of the description's position lock).
#[cfg(feature = "linux-abi")]
pub(crate) fn file_write_typed_kbuf(cap_raw: u64, src: &[u8]) -> i64 {
    match file_fd_for(cap_raw, azos_abi::cap::CapPerms::WRITE, azos_abi::invoke::NODE_WRITE) {
        Ok(fd) => {
            if untyped_write_contained() { return E_CONTAINED; }
            match file_ops() { Some(o) => o.write(fd as i32, src), None => -1 }
        }
        Err(e) => e,
    }
}

/// The typed file read into a kernel buffer (the Linux `readv` scatter
/// source, K2): the `READ` check of [`sys_file_read_typed`], ONE `read`.
#[cfg(feature = "linux-abi")]
pub(crate) fn file_read_typed_kbuf(cap_raw: u64, dst: &mut [u8]) -> i64 {
    match file_fd_for(cap_raw, azos_abi::cap::CapPerms::READ, azos_abi::invoke::NODE_READ) {
        Ok(fd) => match file_ops() { Some(o) => o.read(fd as i32, dst), None => -1 },
        Err(e) => e,
    }
}

/// `SYS_CAP_CLOSE`: a0=cap. Revoke the capability and release what it
/// names, chosen by the handle's kind.
///
/// Revocation happens under the table lock and the release after it, so a
/// second close of the same handle is refused as stale rather than closing a
/// descriptor the task has since reopened under the same number.
///
/// A handle whose kind bits name nothing, or name `Null`, goes down the File
/// arm on purpose: `get` calls it stale, which is the answer every other typed
/// call gives a forged handle, and the refusal is recorded. A real kind with no
/// close here is refused with `ECAPKIND` and not recorded — the caller holds
/// that capability; it asked for an operation the kind does not have. An
/// `Endpoint` closes by [`close_endpoint`]: its slot is deleted, and the last
/// serving (`READ`) grant also ends the role.
pub fn sys_close_typed(cap_raw: u64) -> i64 {
    use azos_abi::cap::{CapHandle, CapPerms};
    use azos_abi::error::Errno;
    use azos_abi::invoke::CLASS_CTL;
    use azos_ipc::cap::{targets::{File, Socket}, Cap};

    let raw = CapHandle::from_raw(cap_raw as u32);
    match CapType::from_raw(raw.kind()) {
        Some(ty::FILE) | Some(CapType::NULL) | None => {
            let cap: Cap<File> = Cap::from_raw(raw);
            let tid = azos_sched::current_task_tid();
            let fd = match azos_ipc::cap_store::with_table(tid, |t| {
                let fd = t.get_op(cap, CapPerms::NONE, crate::invoke::class_op(ty::FILE, CLASS_CTL))?;
                // A directory-tree `Cap<File>` has no descriptor to close
                // Wave 10: refused, and the grant stays.
                if azos_ipc::file_cap::is_tree_resource(fd) {
                    return Err(azos_ipc::cap::CapError::WrongKind);
                }
                t.delete(cap);
                Ok(fd)
            }) {
                Some(Ok(fd)) => fd,
                Some(Err(e)) => return errno_for_file_err(e),
                None => return Errno::EINVAL.to_syscall_ret(),
            };
            match file_ops() { Some(o) => o.close(fd as i32), None => -1 }
        }
        Some(ty::SOCKET) => {
            let cap: Cap<Socket> = Cap::from_raw(raw);
            let tid = azos_sched::current_task_tid();
            let fd = match azos_ipc::cap_store::with_table(tid, |t| {
                let fd = t.get_op(cap, CapPerms::NONE, crate::invoke::class_op(ty::SOCKET, CLASS_CTL))?;
                t.delete(cap);
                Ok(fd)
            }) {
                Some(Ok(fd)) => fd,
                Some(Err(e)) => return errno_for_socket_err(e),
                None => return Errno::EINVAL.to_syscall_ret(),
            };
            // The handle is released either way; the SOCKET is closed only
            // if it is the caller's. A `Cap<Socket>` holds a bare socket index
            // and a move copies it into another table without re-stamping the
            // owner, so "the capability is the proof of ownership" stopped
            // being true once sockets could be moved: a moved handle named
            // the sender's live socket, and once the sender closed it or
            // exited, whichever socket next took the index (OVSwrap review F2).
            // Send and receive already ask `socket_access_ok`; close now does
            // too, as `sys_sock_close` does. A handle naming someone else's
            // socket is dropped and the socket stays with its owner.
            if socket_access_ok(u64::from(fd)) {
                socket_close(fd as i32);
            }
            0
        }
        Some(ty::ENDPOINT) => close_endpoint(CapHandle::from_raw(cap_raw as u32)),
        // A port range: revoked, and the ports its threads opened close.
        Some(ty::IOPORT) => crate::ioport::ioport_close(raw),
        Some(kind) => {
            // A kind with no close here is `ECAPKIND` for a handle the caller
            // holds, but a handle that names no live slot is stale whatever
            // kind it claims: the same answer every other typed call gives a
            // forged handle, and the refusal is recorded.
            let tid = azos_sched::current_task_tid();
            let live = azos_ipc::cap_store::read_table(tid, |t| t.peek_raw(raw).is_some()).unwrap_or(false);
            if live {
                Errno::ECAPKIND.to_syscall_ret()
            } else {
                note_typed_denial(kind, azos_ipc::cap::CapError::Stale);
                Errno::ECAPSTALE.to_syscall_ret()
            }
        }
    }
}

/// `SYS_CAP_CLOSE` of an `Endpoint` capability: the slot is deleted, which is
/// all a send right (`WRITE`) or a call right has to release. A badged copy
/// the caller derived (`ENDPOINT_DERIVE`) goes the same way; copies made from
/// it stay, hung under its own parent (a delete is not a revoke).
///
/// No op class, expiry or caveat is asked: a close calls nothing, and dropping
/// authority is never an escalation, so a copy whose warrant has run out, or
/// whose op mask lists no control op, can still be let go. The slot must be
/// live: a handle that names none is stale, whatever kind it claims.
///
/// **A serving grant.** The server of an endpoint is the task the endpoint
/// names (`owner_tid`), and the `READ` capability is its proof of the role
/// (`endpoint_named_cap`). Closing the LAST `READ` capability the caller's
/// table holds to an endpoint the caller serves ends the role, by the path a
/// server's death takes (`endpoint_orphan_ref`, the body of
/// `endpoint_orphan_all`): every call queued on it or in service end
/// `PEER_DIED`; a named endpoint stays, unclaimed, for the successor the signed
/// topology grants it to; an anonymous one is freed. Leaving the role in place
/// with nothing able to accept would queue every caller forever. While another
/// `READ` capability to it remains (a derived copy, a second grant) the role
/// stays and only the slot goes. A `READ` grant of an endpoint the caller does
/// not serve (a swap's successor, the kernel's own) releases only the slot.
///
/// Serving is stamped on one thread (the image's main one): a close from
/// another thread of the image releases the slot and leaves the role.
fn close_endpoint(raw: azos_abi::cap::CapHandle) -> i64 {
    use azos_abi::cap::CapPerms;
    use azos_abi::error::Errno;
    let tid = azos_sched::current_task_tid();
    // The slot is read, and removed, under the one table lock; the endpoint
    // pool is touched after it (`endpoint_create_cap`: never under a table
    // lock).
    let closed = azos_ipc::cap_store::with_table(tid, |t| {
        let (kind, perms, r) = t.peek_stored(raw)?;
        if kind != ty::ENDPOINT || !t.delete_raw(raw) {
            return None;
        }
        let last_server = perms.contains(CapPerms::READ) && !t.holds_packed_ref(ty::ENDPOINT, r, CapPerms::READ);
        Some((r, last_server))
    })
    .flatten();
    match closed {
        Some((r, last_server)) => {
            if last_server {
                let _ = azos_ipc::endpoint::endpoint_orphan_ref(r, tid);
            }
            0
        }
        None => {
            note_typed_denial(ty::ENDPOINT, azos_ipc::cap::CapError::Stale);
            Errno::ECAPSTALE.to_syscall_ret()
        }
    }
}

/// The first `len` bytes of a bounce buffer, zeroed; the rest is never
/// touched. Wave 13 (DEBTS): the syscall bounce buffers were `[0u8; 4096]`,
/// and zeroing 4 KiB cost ~1,570 instructions on EVERY read, whatever its
/// length — a 64-byte `NODE_READ` paid more for the memset than for
/// the read (vsbench `tmp-ord`, `-icount`, windowed per-function count).
/// Only the bytes handed out are initialised, so the slice is sound.
#[inline(always)]
pub(crate) fn bounce_zeroed<const N: usize>(b: &mut core::mem::MaybeUninit<[u8; N]>, len: usize) -> &mut [u8] {
    let len = len.min(N);
    let p = b.as_mut_ptr() as *mut u8;
    // SAFETY: `p` is valid for `N >= len` bytes; the `len` bytes the slice
    // covers are written (zeroed) before it is made.
    unsafe {
        core::ptr::write_bytes(p, 0, len);
        core::slice::from_raw_parts_mut(p, len)
    }
}

/// `len` bytes copied from user address `user` into a bounce buffer, as a
/// slice; `None` when the copy faults. Like [`bounce_zeroed`], nothing past
/// `len` is written.
#[inline(always)]
pub(crate) fn bounce_from_user<const N: usize>(
    b: &mut core::mem::MaybeUninit<[u8; N]>,
    user: u64,
    len: usize,
) -> Option<&[u8]> {
    let len = len.min(N);
    // SAFETY: `MaybeUninit<[u8; N]>` and `[MaybeUninit<u8>; N]` have one layout.
    let b = unsafe { &mut *(b as *mut core::mem::MaybeUninit<[u8; N]> as *mut [core::mem::MaybeUninit<u8>; N]) };
    azos_sched::UserSlice::<u8>::new(user, len).read_uninit(&mut b[..len]).ok().map(|s| &*s)
}

pub fn sys_read(fd: u64, buf: u64, count: u64) -> i64 {
    let count = count as usize;
    let ops = match file_ops() { Some(o) => o, None => return -1 };
    if azos_sched::current_user_pt() != 0 {
        // Read into a kernel temp buffer, then copy_to_user.
        const MAX: usize = azos_abi::syscall_nr::IO_MAX_BYTES;
        let chunk = count.min(MAX);
        // U07-2 (audit unit-07): validate the destination BEFORE the
        // destructive `ops.read` — a read consumes from the file/socket
        // (advances the offset, or for a socket takes the bytes off the
        // wire); discovering the destination is bad only after the read
        // succeeded would lose those bytes for good, with the caller told
        // `-EFAULT` and no way to get the data back.
        if !azos_sched::user_range_prepare_write(buf as usize, chunk) {
            return -1;
        }
        let mut tmp = core::mem::MaybeUninit::<[u8; MAX]>::uninit();
        let tmp = bounce_zeroed(&mut tmp, chunk);
        let n = ops.read(fd as i32, tmp);
        if n > 0 {
            let m = (n as usize).min(chunk);
            if azos_sched::UserSlice::<u8>::new(buf, m).write_from(&tmp[..m]).is_err() {
                return -1;
            }
        }
        n
    } else {
        // Kernel context: `buf` is a kernel pointer the caller vouches for.
        // The slice is built here rather than passed as a raw pointer so the
        // trait stays safe; the unsafety is identical to the raw write this
        // replaces, and stays at the one call site that has the information to
        // justify it.
        let dst = unsafe { core::slice::from_raw_parts_mut(buf as *mut u8, count) };
        ops.read(fd as i32, dst)
    }
}

/// Bytes from the user address `buf` to the console, at most
/// `invoke::LOG_CONSOLE_WRITE_MAX` of them; the count taken. The console arm of
/// [`sys_write`] (fd 1 and 2) and the `WRITE` op of the console handle.
pub(crate) fn console_write_user(buf: u64, count: u64) -> i64 {
    const MAX: usize = azos_abi::invoke::LOG_CONSOLE_WRITE_MAX as usize;
    let chunk = (count as usize).min(MAX);
    let mut tmp = core::mem::MaybeUninit::<[u8; MAX]>::uninit();
    let Some(tmp) = bounce_from_user(&mut tmp, buf, chunk) else {
        return -1;
    };
    // Write directly to the UART.
    // U07-1 (audit unit-07): this used to hold ONE `uart::acquire()`
    // (SIE off) across the whole polled transmit, up to `MAX` = 4096
    // B — ≈15 ms (QEMU) / ≈360 ms (115200 baud) of masked interrupts
    // per call, from ring 3, on every image row that grants
    // a console write. `console_write_ring3` bounds that:
    //
    // 1. Line atomicity: ring-3 writers are ordered by a preemptible
    //    `Mutex` held for the whole call, and the writer OWNS the
    //    console while its bytes go out: a kernel line from any hart
    //    or interrupt handler is deferred meanwhile and put on the
    //    wire after the ring-3 line (wave 9 — a timer-ISR line had
    //    landed inside `[IPCTEST] ALL PASSED`). See that function.
    //
    // 2. FIFO-batched transmit (measured from ring 3,
    //    `userspace/bench/latbench`: 241 us / 64 B, almost all MMIO
    //    polling), now with interrupts ON: the masked window is the
    //    ownership flip and each ≤128-byte copy of deferred kernel
    //    output, never wire time.
    //
    // 3. `console_write_ring3`, not `write_str_translated`: goes to
    //    whichever device boot registered as the `Console`
    //    (`azos_drv_sys::uart::console_register`), so "which
    //    device is the console" is a boot-time choice rather than a
    //    hardcoded call into the platform UART. The kernel's own
    //    diagnostics (`kprintln!`) and the panic path deliberately
    //    stay on the direct `write_str_translated` path — see that
    //    function's doc. Unregistered, this falls back to the direct
    //    path, so this cannot lose early output.
    azos_drv_sys::uart::console_write_ring3(tmp);
    chunk as i64
}

pub fn sys_write(fd: u64, buf: u64, count: u64) -> i64 {
    let count = count as usize;
    if azos_sched::current_user_pt() != 0 {
        // fd 1 (stdout) and fd 2 (stderr) are the console.
        // The kernel FD table does not pre-open stdio for user processes.
        if fd == 1 || fd == 2 {
            return console_write_user(buf, count as u64);
        }
        // Copy user buffer into kernel temp buffer.
        const MAX: usize = azos_abi::syscall_nr::IO_MAX_BYTES;
        let chunk = count.min(MAX);
        let mut tmp = core::mem::MaybeUninit::<[u8; MAX]>::uninit();
        let Some(tmp) = bounce_from_user(&mut tmp, buf, chunk) else {
            return -1;
        };
        // Below the console arm on purpose. A write to fd 1/2 is logging, and a
        // contained program reporting what it sees is exactly what containment
        // wants to keep; a write that reaches `file_ops` is the WRITE
        // `NODE_WRITE` refuses — see `untyped_write_contained`.
        if untyped_write_contained() { return E_CONTAINED; }
        match file_ops() { Some(o) => o.write(fd as i32, tmp), None => -1 }
    } else {
        // Kernel context, as in `sys_read`. Note the asymmetry preserved from
        // before this change: this branch has no fd 1/2 special case, so a
        // kernel task writing to fd 1 goes to the filesystem on an unopened
        // descriptor. That is left exactly as it was — fixing it is a separate
        // change, and mixing it in here would make this seam's behaviour diff
        // unreadable.
        let src = unsafe { core::slice::from_raw_parts(buf as *const u8, count) };
        match file_ops() { Some(o) => o.write(fd as i32, src), None => -1 }
    }
}

pub fn sys_lseek(fd: u64, offset: u64, whence: u64) -> i64 {
    match file_ops() {
        // The whole register: offsets are 64-bit (a
        // negative one is the two's complement the caller passed).
        Some(o) => o.lseek(fd as i32, offset as i64, whence as i32),
        None => -1,
    }
}

// ── Filesystem ────────────────────────────────────────────────────────────────

/// Maximum filesystem path length copied from userspace, NUL included: a
/// `NAME_MAX` (255-byte) name under a mount point and a few directories
/// (was 256, which one such name under `/fat/` overflowed).
/// [`sys_file_openat_typed`] uses it too.
const SYS_PATH_MAX: usize = 512;

/// Copy a NUL-terminated name from a user pointer into `dst`, returning the
/// name slice, so a malformed/kernel pointer can't
/// drive the FS code via raw `cstr_to_bytes`. `-ENAMETOOLONG` for readable
/// bytes with no NUL within `dst`, `-EFAULT` for a name the caller cannot
/// read. Every caller joins the name beneath a directory (`join_beneath`),
/// which gives the check and the filesystem one spelling.
fn copy_path_from_user<'a>(dst: &'a mut [u8], path_ptr: u64) -> Result<&'a [u8], i64> {
    use azos_abi::error::Errno;
    if azos_sched::current_user_pt() != 0 {
        match azos_sched::UserCStr::new(path_ptr).read_into(dst) {
            Ok(len) => Ok(&dst[..len]),
            Err(_) if azos_sched::UserSlice::<u8>::new(path_ptr, dst.len()).read_into(dst).is_ok() => {
                Err(Errno::ENAMETOOLONG.to_syscall_ret())
            }
            Err(_) => Err(Errno::EFAULT.to_syscall_ret()),
        }
    } else {
        Ok(unsafe { cstr_to_bytes(path_ptr as *const u8) })
    }
}

/// The authority for the ops that change the tree (`NODE_MKDIRAT`,
/// `NODE_UNLINKAT`, `NODE_RENAMEAT`, `NODE_TRUNCATEAT`), asked of the path
/// the name joins to beneath its directory. A ring-3 caller must hold a `Cap<File>` with `WRITE`
/// naming a directory tree that covers `path` (`azos_ipc::file_cap`,
/// minted only by the topology) and resolves for `op`: the tree's own caveats
/// (an op mask, a quota) hold against the op, as an open's do. `strict`:
/// `path` is an ENTRY of the tree (create, remove, rename — the directory it
/// is in is what changes); otherwise the tree's root counts too (truncate —
/// the file itself).
///
/// Asked after the path is copied and before the filesystem sees it, so a
/// refusal says nothing about whether the path exists. `-EINVAL` for a path
/// that is relative or has a `.`/`..` component (the check does not resolve
/// them, so it does not accept them); `-EACCES` (recorded, as `cap_check`
/// records) for no covering capability; the capability refusal (recorded) for
/// a covering tree whose caveats refuse `op`; `-EAGAIN` for a holder while
/// degraded mode is armed — a WRITE through a capability, contained as the
/// others are. Kernel tasks pass, as they pass `cap_check`.
fn fs_tree_gate(path: &[u8], strict: bool, op: u16) -> Result<(), i64> {
    use azos_abi::cap::CapPerms;
    use azos_abi::error::Errno;
    if azos_sched::current_user_pt() == 0 {
        return Ok(());
    }
    if !azos_ipc::file_cap::path_is_plain(path) {
        return Err(Errno::EINVAL.to_syscall_ret());
    }
    match held_tree_for(path, strict, CapPerms::WRITE, op) {
        Some(Ok(_)) => {}
        // A holder while degraded mode is armed is contained (`-EAGAIN`, not
        // recorded); a caveat that refuses `op` is that refusal, recorded.
        Some(Err(e)) => return Err(errno_for_file_err(e)),
        None => {
            record_cap_denial(ty::FILE, 0, true);
            return Err(Errno::EACCES.to_syscall_ret());
        }
    }
    if untyped_write_contained() {
        return Err(Errno::EAGAIN.to_syscall_ret());
    }
    Ok(())
}

/// The name `name_ptr` beneath the directory the `Cap<Dir>` `dir_raw` names,
/// joined into `out`: what every `*at` op acts on. `READ` on the directory
/// (checked under `op`, so its op mask is the op's class) names beneath it.
/// The name stays beneath (`join_beneath`, `RESOLVE_BENEATH`): an absolute
/// name, or a `..` that climbs above the directory, is `-EINVAL` before the
/// filesystem sees anything. An `entry` (the name an op creates, removes,
/// renames or truncates) whose last component is `.` or `..` is `-EINVAL`
/// too: it names a directory by the way to it, not an entry of one.
/// `-EFAULT` for a name the caller cannot read, `-ENAMETOOLONG` for one
/// longer than the copy.
fn name_beneath(
    dir_raw: u64,
    op: u16,
    name_ptr: u64,
    entry: bool,
    out: &mut [u8; azos_common::path::MAX_PATH],
) -> Result<usize, i64> {
    use azos_abi::error::Errno;
    let mut root = [0u8; azos_ipc::file_cap::TREE_PATH_MAX];
    let root_len = dir_root_for(dir_raw, azos_abi::cap::CapPerms::READ, op, &mut root)?;
    if name_ptr == 0 {
        return Err(Errno::EFAULT.to_syscall_ret());
    }
    let mut buf = [0u8; SYS_PATH_MAX];
    let name = copy_path_from_user(&mut buf, name_ptr)?;
    if entry && matches!(name.split(|&b| b == b'/').filter(|c| !c.is_empty()).last(), Some(b".") | Some(b"..")) {
        return Err(Errno::EINVAL.to_syscall_ret());
    }
    match azos_common::path::join_beneath(&root[..root_len], name, out) {
        Ok(n) => Ok(n),
        Err(azos_common::path::JoinError::TooLong) => Err(Errno::ENAMETOOLONG.to_syscall_ret()),
        Err(azos_common::path::JoinError::Invalid) => Err(Errno::EINVAL.to_syscall_ret()),
    }
}

/// The filesystem behind the seam, or `-ENOSYS` when none is installed.
fn fs_or_nosys() -> Result<&'static dyn crate::file_ops::FileOps, i64> {
    file_ops().ok_or_else(|| azos_abi::error::Errno::ENOSYS.to_syscall_ret())
}

/// A `*at` op that changes the tree: the name beneath the directory, the
/// write authority over the result ([`fs_tree_gate`]: `strict` for an entry
/// of a tree, as an open that changes the tree), then `f` on the joined path.
fn mutate_at(dir_raw: u64, op: u16, name_ptr: u64, strict: bool, f: impl FnOnce(&dyn crate::file_ops::FileOps, &[u8]) -> i64) -> i64 {
    let mut path = [0u8; azos_common::path::MAX_PATH];
    let n = match name_beneath(dir_raw, op, name_ptr, true, &mut path) { Ok(n) => n, Err(e) => return e };
    if let Err(e) = fs_tree_gate(&path[..n], strict, op) { return e; }
    match fs_or_nosys() { Ok(o) => f(o, &path[..n]), Err(e) => e }
}

/// `NODE_MKDIRAT`: make the directory `name` beneath `dir`.
pub fn sys_mkdirat(dir_raw: u64, name_ptr: u64) -> i64 {
    mutate_at(dir_raw, azos_abi::invoke::NODE_MKDIRAT, name_ptr, true, |o, p| o.mkdir(p))
}

/// `NODE_UNLINKAT`: remove the entry `name` beneath `dir`; with
/// `UNLINK_DIR`, the empty directory (`-ENOTEMPTY` otherwise).
pub fn sys_unlinkat(dir_raw: u64, name_ptr: u64, flags: u64) -> i64 {
    use azos_abi::invoke::{NODE_UNLINKAT, UNLINK_DIR};
    if flags & !UNLINK_DIR != 0 {
        return azos_abi::error::Errno::EINVAL.to_syscall_ret();
    }
    mutate_at(dir_raw, NODE_UNLINKAT, name_ptr, true, |o, p| if flags & UNLINK_DIR != 0 { o.rmdir(p) } else { o.unlink(p) })
}

/// `NODE_RENAMEAT`: rename `from` to `to`, both beneath `dir`, within one
/// mounted filesystem. Each end needs the write authority over its entry.
pub fn sys_renameat(dir_raw: u64, from_ptr: u64, to_ptr: u64) -> i64 {
    use azos_abi::invoke::NODE_RENAMEAT;
    let mut from = [0u8; azos_common::path::MAX_PATH];
    let mut to = [0u8; azos_common::path::MAX_PATH];
    let nf = match name_beneath(dir_raw, NODE_RENAMEAT, from_ptr, true, &mut from) { Ok(n) => n, Err(e) => return e };
    let nt = match name_beneath(dir_raw, NODE_RENAMEAT, to_ptr, true, &mut to) { Ok(n) => n, Err(e) => return e };
    if let Err(e) = fs_tree_gate(&from[..nf], true, NODE_RENAMEAT) { return e; }
    if let Err(e) = fs_tree_gate(&to[..nt], true, NODE_RENAMEAT) { return e; }
    match fs_or_nosys() { Ok(o) => o.rename(&from[..nf], &to[..nt]), Err(e) => e }
}

/// `NODE_TRUNCATEAT`: set the size of the file `name` beneath `dir` to
/// `len`. The write authority covers the file itself (a tree's root counts).
pub fn sys_truncateat(dir_raw: u64, name_ptr: u64, len: u64) -> i64 {
    mutate_at(dir_raw, azos_abi::invoke::NODE_TRUNCATEAT, name_ptr, false, |o, p| o.truncate(p, len))
}

/// `NODE_READDIR`: entry `index` of the directory `name` beneath `dir`. The
/// name is written into `name_out` (`name_len`, at least
/// `READDIR_NAME_BYTES`: exactly that many bytes, zero-padded, always), the
/// size, the is-directory flag and whether the name was cut to fit are the
/// reply words. `None` past the last entry.
///
/// A buffer shorter than the record is refused rather than written short: a
/// name truncated in silence is a filename the caller then acts on.
pub fn sys_readdirat(dir_raw: u64, name_ptr: u64, index: u64, name_out: u64, name_len: u64) -> Result<Option<(u32, bool, bool)>, i64> {
    use azos_abi::error::Errno;
    use azos_abi::syscall_nr::READDIR_NAME_BYTES;
    if name_len < READDIR_NAME_BYTES as u64 || index > u32::MAX as u64 {
        return Err(Errno::EINVAL.to_syscall_ret());
    }
    if name_out == 0 {
        return Err(Errno::EFAULT.to_syscall_ret());
    }
    let mut path = [0u8; azos_common::path::MAX_PATH];
    let n = name_beneath(dir_raw, azos_abi::invoke::NODE_READDIR, name_ptr, false, &mut path)?;
    let ops = fs_or_nosys()?;
    let Some((name, size, is_dir)) = ops.readdir(&path[..n], index as u32) else { return Ok(None) };
    // The seam fills all of `name` with no NUL for a name that does not fit.
    let full = name.iter().position(|&b| b == 0).unwrap_or(name.len());
    let len = full.min(READDIR_NAME_BYTES - 1);
    let mut rec = [0u8; READDIR_NAME_BYTES];
    rec[..len].copy_from_slice(&name[..len]);
    if azos_sched::current_user_pt() != 0 {
        azos_sched::UserSlice::<u8>::new(name_out, READDIR_NAME_BYTES).write_from(&rec).map_err(|_| Errno::EFAULT.to_syscall_ret())?;
    } else {
        unsafe { core::ptr::copy_nonoverlapping(rec.as_ptr(), name_out as *mut u8, READDIR_NAME_BYTES); }
    }
    Ok(Some((size, is_dir, full > len)))
}

/// Write `bytes` to the caller's `ptr` (a user pointer from ring 3, a kernel
/// one from a kernel task).
fn record_to_caller(ptr: u64, bytes: &[u8]) -> Result<(), i64> {
    if azos_sched::current_user_pt() != 0 {
        azos_sched::UserSlice::<u8>::new(ptr, bytes.len())
            .write_from(bytes)
            .map_err(|_| azos_abi::error::Errno::EFAULT.to_syscall_ret())
    } else {
        unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), ptr as *mut u8, bytes.len()); }
        Ok(())
    }
}

/// `NODE_STATAT`: the record of `name` beneath `dir` (`.` the directory
/// itself) into `out`, at least `STAT_BYTES` long: the layout `STAT_BYTES`
/// documents. `0`, `-ENOENT` for no such entry, `-EFAULT` for a buffer the
/// caller cannot write. No write authority: it reports what an open would
/// find.
pub fn sys_statat(dir_raw: u64, name_ptr: u64, out: u64) -> i64 {
    use azos_abi::syscall_nr::STAT_BYTES;
    if out == 0 { return azos_abi::error::Errno::EFAULT.to_syscall_ret(); }
    let mut path = [0u8; azos_common::path::MAX_PATH];
    let n = match name_beneath(dir_raw, azos_abi::invoke::NODE_STATAT, name_ptr, false, &mut path) { Ok(n) => n, Err(e) => return e };
    let ops = match fs_or_nosys() { Ok(o) => o, Err(e) => return e };
    let st = match ops.stat(&path[..n]) { Ok(st) => st, Err(e) => return e };
    match record_to_caller(out, &st.to_bytes()[..STAT_BYTES]) { Ok(()) => 0, Err(e) => e }
}

/// `NODE_STATFS`: capacity and free space of the filesystem `name` beneath
/// `dir` is on, into `out` of `out_len` bytes (at least `STATFS_BYTES`; a
/// shorter one is `-EINVAL` and nothing is written).
pub fn sys_statfsat(dir_raw: u64, name_ptr: u64, out: u64, out_len: u64) -> i64 {
    use azos_abi::error::Errno;
    use azos_abi::syscall_nr::STATFS_BYTES;
    if out_len < STATFS_BYTES as u64 { return Errno::EINVAL.to_syscall_ret(); }
    if out == 0 { return Errno::EFAULT.to_syscall_ret(); }
    let mut path = [0u8; azos_common::path::MAX_PATH];
    let n = match name_beneath(dir_raw, azos_abi::invoke::NODE_STATFS, name_ptr, false, &mut path) { Ok(n) => n, Err(e) => return e };
    let ops = match fs_or_nosys() { Ok(o) => o, Err(e) => return e };
    let st = match ops.statfs(&path[..n]) { Ok(st) => st, Err(e) => return e };
    match record_to_caller(out, &st.to_bytes()[..STATFS_BYTES]) { Ok(()) => 0, Err(e) => e }
}

/// `NODE_FSYNC`: a0 = `Cap<File>`, any permission (Linux's
/// `fsync` works on a read-only descriptor too). The handle is resolved and
/// refused exactly as `NODE_READ`'s is — stale, wrong kind, and the
/// refusal recorded — and the descriptor it names is synced. `0` or a
/// negative errno (owner round 23).
pub fn sys_fsync_typed(cap_raw: u64) -> i64 {
    match file_fd_for(cap_raw, azos_abi::cap::CapPerms::NONE, azos_abi::invoke::NODE_FSYNC) {
        Ok(fd) => {
            // The file's mapped pages first: they are part of what it holds.
            if let Err(e) = crate::file_map::flush_fd(fd as i32) { return e; }
            match file_ops() { Some(o) => o.fsync(fd as i32), None => -1 }
        }
        Err(e) => e,
    }
}

/// `NODE_SEEK`: reposition the descriptor a `Cap<File>` names (any permission).
/// The new offset or a negative errno.
pub fn sys_file_seek_typed(cap_raw: u64, offset: i64, whence: u64) -> i64 {
    use azos_abi::error::Errno;
    if whence > 2 {
        return Errno::EINVAL.to_syscall_ret();
    }
    match file_fd_for(cap_raw, azos_abi::cap::CapPerms::NONE, azos_abi::invoke::NODE_SEEK) {
        Ok(fd) => match file_ops() {
            Some(o) => o.lseek(fd as i32, offset, whence as i32),
            None => -1,
        },
        Err(e) => e,
    }
}

// ── System info ───────────────────────────────────────────────────────────────

pub fn sys_meminfo() -> i64 {
    azos_mm::pmm::free_pages() as i64
}

/// `DOMAIN_TASKINFO`: a0 = out_ptr, a1 = out_len. See the ABI constant for
/// the layout.
///
/// **Was `-> 0` and wrote nothing.** Another declared-and-empty slot, like
/// `motor.estop` was: the number existed, `libsys` exposed it, and a
/// caller got a silent success and an untouched buffer. It is implemented now
/// because the scheduler finally has something worth reporting — switch
/// counts that can be compared with Linux's, which is what a benchmark needs
/// to know whether a number means what its label says.
pub fn sys_taskinfo(out_ptr: u64, out_len: u64) -> i64 {
    azos_sched::swcensus::dump_window();
    use azos_abi::error::Errno;
    use azos_abi::syscall_nr::TASKINFO_BYTES;

    if out_ptr == 0 || (out_len as usize) < TASKINFO_BYTES {
        return Errno::EINVAL.to_syscall_ret();
    }

    let tid = azos_sched::current_task_tid();
    let (vol, pre) = azos_sched::current_task_switches();
    let fields: [u64; 5] = [
        tid as u64,
        azos_sched::task_priority(tid).unwrap_or(0) as u64,
        vol,
        pre,
        azos_sched::current_task_hart() as u64,
    ];

    let mut blob = [0u8; TASKINFO_BYTES];
    for (i, v) in fields.iter().enumerate() {
        blob[i * 8..(i + 1) * 8].copy_from_slice(&v.to_le_bytes());
    }
    // The user path goes through the checked copy, the kernel path writes
    // directly.
    if azos_sched::current_user_pt() != 0 {
        if azos_sched::UserPtr::<[u8; TASKINFO_BYTES]>::new(out_ptr).write(&blob).is_err() {
            return Errno::EFAULT.to_syscall_ret();
        }
    } else {
        unsafe {
            core::ptr::copy_nonoverlapping(blob.as_ptr(), out_ptr as *mut u8, TASKINFO_BYTES);
        }
    }
    TASKINFO_BYTES as i64
}

pub fn sys_uptime() -> i64 {
    azos_drv_sys::timebase::now() as i64
}

// ── System control ────────────────────────────────────────────────────────────

azos_common::ro_hook! {
    /// What runs before an ORDERLY power-off or reboot (`power_off_orderly`,
    /// `reboot_orderly`), installed by the kernel at boot: OTA's void of this boot's
    /// unconfirmed mark, so a deliberate shutdown is not counted as a crash (owner
    /// decision 2026-09-28). `crates/core/syscall` cannot name `crates/core/ota`, hence a
    /// hook, like the recorders above. Never called on a crash path.
    static ORDERLY_POWER_HOOK: fn();
}

azos_common::ro_hook! {
    /// The devices the kernel holds that an orderly power-off or reboot shuts
    /// down after the boot disk (`orderly_storage_down`): a USB disk's
    /// SYNCHRONIZE CACHE, then TPM2_Shutdown(STATE), the last command the TPM
    /// gets. Installed by the kernel at boot: this crate names neither driver.
    static ORDERLY_DEVICES_HOOK: fn();
}

/// Install the orderly power-off hook. Called once at boot.
pub fn set_orderly_power_hook(f: fn()) {
    ORDERLY_POWER_HOOK.set(f);
}

/// Install the kernel-held devices' shutdown hook. Called once at boot.
pub fn set_orderly_devices_hook(f: fn()) {
    ORDERLY_DEVICES_HOOK.set(f);
}

/// Run the orderly power-off hook, if installed.
fn orderly_power_off() {
    if let Some(f) = ORDERLY_POWER_HOOK.get() { f(); }
}

/// Make the data durable before the power goes (owner decision 2026-10-23,
/// Q1), whoever asked for the power-off or reboot: every mounted filesystem
/// written back (`FileOps::sync_all`), then the boot disk flushed and its
/// controller shut down (`blkdev::shutdown`: NVMe CC.SHN), then the kernel-held
/// devices ([`ORDERLY_DEVICES_HOOK`]). The power service syncs first through
/// `Power::sync`; this is the net under it and under the callers that have no
/// service (the thermal critical trip). Each step is bounded (Kconfig
/// `POWER_OFF_STEP_TIMEOUT_MS`, the devices' own command budgets) and the
/// power-off goes on after it, whatever it answered.
///
/// After the hook of this boot's records ([`orderly_power_off`]): OTA's void
/// and the entropy seed are writes, and this makes them durable too.
fn orderly_storage_down() {
    let ms = |t0: u64| {
        (azos_drv_sys::timebase::now().saturating_sub(t0)) * 1000 / azos_drv_sys::timebase::TIMER_FREQ.max(1)
    };
    let t0 = azos_drv_sys::timebase::now();
    let fs = crate::file_ops::file_ops().map(|o| o.sync_all()).unwrap_or_default();
    azos_drv_sys::kprintln!("[ORDERLY] filesystems: {} volume(s) synced, {} failed, {} timed out ({} ms)",
        fs.volumes, fs.failed, fs.timed_out, ms(t0));
    // The boot volume's clean mark, the mount's last write: without it every
    // boot after an orderly power-off would check /fat again, and a check that
    // misreads a settled volume would serve it read-only (FS_CHECK_FAILED).
    let clean = crate::file_ops::file_ops().is_some_and(|o| o.clean_unmount());
    azos_drv_sys::kprintln!("[ORDERLY] boot volume: {}",
        if clean { "unmounted, marked clean" } else { "not unmounted (the next mount checks it)" });
    azos_drv_block::blkdev::shutdown();
    if let Some(f) = ORDERLY_DEVICES_HOOK.get() { f(); }
}

/// An orderly power-off: the `power` interface's `shutdown`
/// (`crate::power`), after it checked the caller's `WRITE`, and the kernel's
/// thermal task when a critical trip latched the shutdown request.
pub fn power_off_orderly() -> ! {
    // Authorised: an orderly power-off. Not a crash; say so on the volume.
    orderly_power_off();
    orderly_storage_down();
    // Deferred kernel lines reach the wire before the power-off (see
    // `reboot_orderly`).
    azos_drv_sys::uart::console_flush_for_reboot();
    // riscv64: SBI SRST shutdown; aarch64: PSCI `SYSTEM_OFF`. The host shim
    // of `tests/host/syscall-tests` implements `Boot` with `todo!()` bodies
    // (never reached by its tests).
    azos_arch::Boot::shutdown(&azos_arch::ARCH)
}

/// An orderly reboot: the `power` interface's `reboot` (`crate::power`), after
/// it checked the caller's `WRITE`, and the kernel's own smokes.
pub fn reboot_orderly() -> ! {
    orderly_power_off();
    orderly_storage_down();
    // Deferred kernel lines (ring 3 may own the console on another hart)
    // reach the wire before the reset, not never.
    azos_drv_sys::uart::console_flush_for_reboot();
    // riscv64: SBI SRST cold reboot; aarch64: PSCI `SYSTEM_RESET`.
    azos_arch::Boot::reboot(&azos_arch::ARCH)
}

// ── PWM ───────────────────────────────────────────────────────────────────────

/// Is this PWM channel wired to a motor?
///
/// A motor's PWM channel must not be reachable through the PWM API at all: the
/// motor path runs every command through `gate_speed` — the e-stop latch and
/// the safety-monitor envelope — and a duty written straight to the channel arrives
/// below both. That is the actuation gate bypassed, on the exact hardware the
/// gate exists to hold.
///
/// `sys_pwm_dispatch_inner` (the shared helper behind all five
/// `SYS_PWM_*_TYPED`) checks it, and so does `sys_drv_invoke`. The topology
/// declares `pwm.4` for autorun, and `pwm.0` under `cap-refusal-canary`, which
/// is channel 0 and motor 0's: the guard is what keeps that grant off the wheel.
#[cfg(feature = "board-io")]
pub(crate) fn pwm_channel_is_motor_bound(ch: u32) -> bool {
    azos_robot::motor::pwm_channel_motor_id(ch).is_some()
}

/// Does a CONTROL-register write named for `ch` reach a motor-bound channel?
///
/// **The named channel is not the reach, and that difference is a hole three
/// call sites had in three different shapes.** On a `vf2` build, `PWM_DOMAIN`
/// is `PWM_DOMAIN_VF2_DRIVER`, the shape the compiled driver programs
/// (the real part, `PWM_DOMAIN_INDEPENDENT_8`, is 8 independent channels; the
/// SiFive-layout driver is not): `(4 channels, shared_control = true)`:
/// enable, disable and set-period all
/// write one `PWMCFG` that reaches EVERY channel of the instance. Motors 0 and
/// 1 sit on channels 0 and 1. So a control write named for channel 2 — a
/// channel no motor owns — changes the timing of both wheels.
///
/// Found by audit 2026-09-11, and the three shapes were:
///   · `SYS_DRV_INVOKE` had this right, inline;
///   · the untyped `sys_pwm_*` checked authority over the whole reach
///     (`pwm_control_cap_ok`) but motor-binding only on the NAMED channel;
///   · the typed `sys_pwm_*_typed` checked neither — strictly weaker than the
///     driver path on the identical operation.
///
/// One predicate now, used by the driver bridge and the typed calls (the
/// untyped PWM calls were retired with the move to generation-stamped handles). Duty is
/// deliberately NOT routed through here: `PWMCMP` is genuinely per-channel on this part, so a duty
/// write reaches only what it names — see `pwm_control_reach`'s own doc.
/// The domain is a PARAMETER, not the build's constant, and that is what
/// makes this property testable at all.
///
/// Under QEMU `PWM_DOMAIN_INDEPENDENT_8` is `(8, shared_control = false)`, so the reach
/// IS the named channel and this function cannot behave differently from the
/// check it replaced. The behaviour it exists for appears only on
/// `PWM_DOMAIN_VF2_DRIVER` `(4, shared_control = true)` — a board no scenario can
/// boot. Naming the domain lets a host test state both, which is the only way
/// this fix is anything more than an assertion about code nobody ran.
/// `pwm_control_allowed` already takes its domain the same way.
#[cfg(feature = "board-io")]
pub(crate) fn pwm_control_reaches_a_motor(
    domain: azos_drv_actuator::pwm_domain::PwmDomain,
    ch: u32,
) -> bool {
    let reach = azos_drv_actuator::pwm_domain::pwm_control_reach(domain, ch);
    (0..domain.channels).any(|c| reach & (1u32 << c) != 0 && pwm_channel_is_motor_bound(c))
}

/// The GPIO half of the same rule, and it was missing entirely.
///
/// `pwm_channel_is_motor_bound` above stops a bare PWM capability reaching the
/// H-bridge's duty. Nothing stopped a bare GPIO capability reaching its
/// DIRECTION pins — not the typed handlers, not the untyped ones — so a task
/// holding `Gpio(0)` could brake, reverse or float a wheel with the envelope
/// and the e-stop latch both out of the loop. Same class, and the instance
/// left open is the one that changes which way the robot goes.
pub(crate) fn gpio_pin_is_motor_bound(pin: u32) -> bool {
    azos_robot::motor::gpio_pin_motor_id(pin).is_some()
}

/// Is board pin `pin` a line the safety core reads? The kill switch's input
/// (CONFIG.INI `estop_gpio_pin`, the value `azos_kill_switch` arms, read
/// again on every call as it does), and every input the device tree
/// describes as a `gpio-keys` line of the controller (the switch's polarity
/// and window come from there). A holder that turned one into an output, or
/// drove it, would make the switch read what the holder drives.
pub(crate) fn gpio_pin_is_safety_line(pin: u32) -> bool {
    pin == azos_config::CFG_ESTOP_GPIO_PIN.load(core::sync::atomic::Ordering::Acquire)
        || azos_drv_gpio::gpio::gpio_key(pin).is_some()
}

// ── Memory management (Phase 7) ───────────────────────────────────────────────

/// The Linux personality's `brk` (`linux.rs`, `nr::BRK`): a0 = new break
/// address (0 = query the current one). Returns the new (or current) break.
/// Native programs have no program break: they map memory through `MemObj`
/// (`SYS_MO_MAP`), and the ring-3 Linux runtime builds its own break on it.
///
/// The heap is an anonymous mapping like a private `mmap`'s: a growth reserves
/// `[page_up(brk), page_up(addr))`, which folds into the mapping below it (one
/// record and one object for the whole heap), and the pages are faulted in on
/// first touch, or committed at once where [`mmap_precommit`] says so. The
/// whole growth is charged before anything is made, and a growth that cannot
/// be had in full (the charge, a range that is not vacant, no memory) leaves
/// the break where it was, as Linux does. A shrink is not supported: the break
/// stays. The break stops below the mmap area (`azos_sched::user_mmap_area`),
/// which is above every image and below every kernel window.
pub fn sys_brk(addr: u64) -> i64 {
    // Wave 13: one layout change at a time per thread group.
    let _mm = azos_sched::group::mm_lock();
    let Some(space) = azos_sched::current_aspace() else { return -1 }; // kernel task
    let cur = azos_sched::update_user_brk(0);
    if addr <= cur {
        return cur as i64;
    }
    let page = azos_arch::PAGE_SIZE as u64;
    let up = |a: u64| a.saturating_add(page - 1) & !(page - 1);
    let (start, end) = (up(cur) as usize, up(addr) as usize);
    if end > azos_sched::user_mmap_area().0 || start < azos_mm::vmm::USER_GUARD_LIMIT {
        return cur as i64;
    }
    let pages = (end - start) / page as usize;
    if pages == 0 {
        return azos_sched::update_user_brk(end as u64) as i64;
    }
    if !azos_sched::mm_charge_request(pages as u32, request_may_grow()) {
        return cur as i64;
    }
    if !mmap_precommit(0) {
        match azos_mm::pager::reserve(space, start, end, true) {
            Ok(()) => return azos_sched::update_user_brk(end as u64) as i64,
            Err(azos_mm::pager::MapError::Full) => {}
            Err(_) => {
                azos_sched::mm_discharge(pages as u32);
                return cur as i64;
            }
        }
    }
    if !commit_now(space.root(), start, pages, true) {
        azos_sched::mm_discharge(pages as u32);
        return cur as i64;
    }
    azos_sched::update_user_brk(end as u64) as i64
}

// ── Network (Phase 9) ─────────────────────────────────────────────────────────

/// Owner stamp to record for a socket created by the *current* caller.
///
/// Kernel tasks get [`azos_net::SOCK_OWNER_KERNEL`]; a user task gets its
/// own TID. Returns `None` when a user task has no resolvable TID, in which
/// case the caller must refuse to create the socket rather than stamp it with
/// 0 — a socket stamped 0 is owned by nobody, so its creator could never use
/// it and the exit hook would never reclaim it: a permanently leaked slot out
/// of only 16.
#[inline]
fn socket_owner_for_caller() -> Option<u32> {
    if azos_sched::current_user_pt() == 0 {
        return Some(azos_net::SOCK_OWNER_KERNEL);
    }
    // Wave 15 (plan 4a): the process, so a thread's socket is its process's
    // (every thread may use it, and it outlives the thread).
    match azos_sched::current_proc_tid() {
        0   => None, // 0 means "no current task"; NEXT_TID never issues it.
        tid => Some(tid),
    }
}

/// May the current task touch socket `fd`?
///
/// **WHY this exists:** `azos_net::SOCKS` is one flat 16-entry array and
/// the fd *is* the userspace-chosen index into it. Every `socket_*` entry
/// point validated only `fd < MAX_SOCKETS`, and the syscalls passed the raw
/// register straight through with no per-task fd table in between — so any
/// task could enumerate fd 0..15 and read another task's inbound TCP stream,
/// inject bytes into its outbound stream, or tear down its connection. That
/// includes the OTA channel and the brain link. Sixteen guesses covered the
/// whole table.
///
/// Same shape as the owner-stamp gates of the untyped port and shared-memory
/// calls (retired with the move to generation-stamped handles): the owner is stamped
/// at create/accept
/// time and checked here, rather than
/// asking "who is running now" at use time — kernel-side poll paths and
/// workers run with `user_pt == 0`, where a current-task check enforces
/// nothing at all.
///
/// Kernel callers (`user_pt == 0`) bypass. In practice the bypass is
/// structural rather than conditional: `kernel/src/main.rs` and
/// `crates/core/shell` call `azos_net::socket_*` directly and never traverse
/// these handlers.
///
/// `socket_owner` returns `None` for an out-of-range, free or unowned slot,
/// and a real TID is never 0 or `SOCK_OWNER_KERNEL`, so denial is the
/// default for anything a user task did not create.
#[inline]
fn socket_access_ok(fd: u64) -> bool {
    if azos_sched::current_user_pt() == 0 {
        return true;
    }
    // Range-check before narrowing: `fd` is a raw register, and `fd as i32`
    // on a large value wraps (possibly negative). Bounding it here also
    // makes `fd as u16` safe for the ephemeral-port arithmetic in
    // `sys_connect_syscall`.
    if fd >= azos_net::MAX_SOCKETS as u64 {
        return false;
    }
    let tid = azos_sched::current_proc_tid();
    if tid == 0 {
        return false;
    }
    azos_net::socket_owner(fd as i32) == Some(tid)
}

/// Parse a `sockaddr_in` from a (kernel or user-space) pointer.
/// Layout: family(u16 LE), port(u16 BE), addr(4 bytes), 8 bytes pad.
fn read_sockaddr(ptr: u64) -> Option<SockAddr> {
    if ptr == 0 { return None; }
    let mut raw = [0u8; 16];
    if !copy_in(&mut raw, ptr) {
        return None;
    }
    let family = u16::from_le_bytes([raw[0], raw[1]]);
    let port   = u16::from_be_bytes([raw[2], raw[3]]);
    let addr   = [raw[4], raw[5], raw[6], raw[7]];
    Some(SockAddr { family, port, addr })
}

/// Copy `dst.len()` bytes at `ptr` from the caller (user memory through its
/// page tables; a kernel caller's pointer as is).
fn copy_in(dst: &mut [u8], ptr: u64) -> bool {
    if azos_sched::current_user_pt() != 0 {
        return azos_sched::UserSlice::<u8>::new(ptr, dst.len()).read_into(dst).is_ok();
    }
    // SAFETY: a kernel caller passes a buffer of at least the length it named.
    dst.copy_from_slice(unsafe { core::slice::from_raw_parts(ptr as *const u8, dst.len()) });
    true
}

/// Read the `sockaddr` of `NODE_BIND` / `NODE_CONNECT`: the 16-byte
/// `sockaddr_in`, or for `AF_INET6` the 28-byte `sockaddr_in6` when `addrlen`
/// says the caller passed one (no byte past the length it named is read).
fn read_sockaddr_wire(ptr: u64, addrlen: u64) -> Option<azos_net::socket::WireAddr> {
    use azos_net::socket::{WireAddr, SOCKADDR_IN6_LEN, SOCKADDR_IN_LEN};
    if ptr == 0 { return None; }
    let mut raw = [0u8; SOCKADDR_IN6_LEN];
    if !copy_in(&mut raw[..SOCKADDR_IN_LEN], ptr) {
        return None;
    }
    let v6 = u16::from_le_bytes([raw[0], raw[1]]) == azos_net::socket::AF_INET6 as u16;
    let n = if v6 && addrlen >= SOCKADDR_IN6_LEN as u64 { SOCKADDR_IN6_LEN } else { SOCKADDR_IN_LEN };
    if n > SOCKADDR_IN_LEN && !copy_in(&mut raw[SOCKADDR_IN_LEN..n], ptr + SOCKADDR_IN_LEN as u64) {
        return None;
    }
    WireAddr::parse(&raw[..n])
}

/// DOMAIN_SOCKET: a0=domain, a1=type, a2=proto. Returns socket fd or -1.
///
/// Stamps the new socket with the caller's TID. That stamp is the only thing
/// standing between a user task and every other task's connection — see
/// [`socket_access_ok`].
pub fn sys_socket(domain: u64, sock_type: u64, proto: u64) -> i64 {
    let owner = match socket_owner_for_caller() {
        Some(o) => o,
        None    => return -1,
    };
    socket_create_owned(domain as u32, sock_type as u32, proto as u32, owner) as i64
}

/// NODE_BIND: a0=fd, a1=sockaddr_ptr, a2=addrlen (a `sockaddr_in`, or a
/// `sockaddr_in6` for an `AF_INET6` socket). Returns 0 or -1.
pub fn sys_bind(fd: u64, addr_ptr: u64, addrlen: u64) -> i64 {
    // Ownership gate: binding another task's socket would let an attacker
    // steer the port it is about to listen on.
    if !socket_access_ok(fd) { return -1; }
    match read_sockaddr_wire(addr_ptr, addrlen) {
        Some(addr) => azos_net::socket::socket_bind_wire(fd as i32, &addr) as i64,
        None       => -1,
    }
}

/// NODE_CONNECT: a0=fd, a1=sockaddr_ptr, a2=addrlen.
///
/// `-1` for a socket the caller does not own; `-EAGAIN` while degraded mode is
/// contained, as `SYS_CONNECT_TYPED` answers — choosing where a socket talks
/// to is a write to it.
pub fn sys_connect_syscall(fd: u64, addr_ptr: u64, addrlen: u64) -> i64 {
    // Ownership gate FIRST — before `fd` is used for anything at all:
    // connecting another task's socket redirects its stream to an
    // attacker-chosen peer.
    if !socket_access_ok(fd) { return -1; }
    // Before the address is read: it is copied from user memory.
    if untyped_write_contained() { return E_CONTAINED; }
    // Local port 0: the TCP layer picks a free one from the ephemeral range
    // (`CONFIG_TCP_EPHEMERAL_PORT_*`) under the lock that takes the slot. It
    // was `0xC000 + fd`: a second connect on the same fd named the previous
    // connection's 4-tuple, which the peer may still hold (TIME-WAIT) and
    // answer with a RST.
    let src_port = 0;
    // A `sockaddr_in`, or a `sockaddr_in6` for an `AF_INET6` socket.
    match read_sockaddr_wire(addr_ptr, addrlen) {
        // Yield-aware: connect must not report success until the handshake
        // completes, and waiting without yielding would burn the hart.
        Some(addr) => azos_net::socket::socket_connect_wire_with_yield(
            fd as i32, &addr, src_port,
            || crate::sleep::sleep_ms(1),
        ) as i64,
        None       => -1,
    }
}

/// NODE_SEND / NODE_SENDTO: a0=fd, a1=buf_ptr, a2=len, a3=flags (ignored).
///
/// Gated here rather than in `dispatch.rs` because `NODE_SEND` and
/// `NODE_SENDTO` both land on this one handler: one check covers both arms.
/// `NODE_SENDTO`: like `send`, but with an **explicit destination address**.
///
/// **This completes a reserved number, it does not break an existing one.**
/// `NODE_SENDTO` dispatched to the same `sys_send_syscall` as `NODE_SEND`, and
/// `libsys` documented it as "identical to `send`, kept only because the
/// number is claimed". Nobody used the address form, because it did not exist.
///
/// What it unblocks: **unconnected UDP**. Until now a UDP socket could only
/// send after a `connect`, because there was no way to name a destination per
/// call. The machinery below already supported it — `udp::sendto` has taken
/// `dst_ip` and `dst_port` all along — and this layer threw it away.
///
/// `-EAGAIN` while degraded mode is contained, with or without an address —
/// the same refusal `NODE_SEND` gives, checked before either copy.
pub fn sys_sendto_syscall(fd: u64, buf_ptr: u64, len: u64, addr_ptr: u64) -> i64 {
    if !socket_access_ok(fd) { return -1; }
    let empty = len == 0 && azos_net::socket::socket_is_datagram(fd as i32);
    if (buf_ptr == 0 || len == 0) && !empty { return -1; }
    if untyped_write_contained() { return E_CONTAINED; }
    // With no address it behaves as `send`: that is what it did before, and a
    // caller passing 0 must not start failing because of this change.
    if addr_ptr == 0 { return sys_send_syscall(fd, buf_ptr, len, 0); }
    let addr = match read_sockaddr(addr_ptr) { Some(a) => a, None => return -1 };
    let count = (len as usize).min(1460);
    let mut tmp = [0u8; 1460];
    if !empty
        && azos_sched::UserSlice::<u8>::new(buf_ptr, count).read_into(&mut tmp[..count]).is_err()
    {
        return -1;
    }
    azos_net::socket::socket_sendto(fd as i32, &tmp[..count], &addr) as i64
}

/// `NODE_RECVFROM`: like `recv`, but **reporting the sender**.
///
/// Same story as `sendto`: `udp::recvfrom` has filled `src_ip` and `src_port`
/// all along, and this layer discarded it. A UDP server that does not know who
/// spoke to it cannot answer.
pub fn sys_recvfrom_syscall(fd: u64, buf_ptr: u64, len: u64, addr_ptr: u64) -> i64 {
    if !socket_access_ok(fd) { return -1; }
    if buf_ptr == 0 || len == 0 { return -1; }
    if addr_ptr == 0 { return sys_recv_syscall(fd, buf_ptr, len, 0); }
    recvfrom_bounced(fd, buf_ptr, (len as usize).min(4096), addr_ptr)
}

/// [`sys_recvfrom_syscall`]'s copy, in a frame of its own.
///
/// The buffer used to be declared in the caller, and LLVM reserves a frame at
/// function entry, not at the declaration: the `addr_ptr == 0` branch above
/// therefore called `sys_recv_syscall` -- which has a 4 KiB bounce of its own
/// -- from underneath 4 KiB that the call could never use. 8.3 KiB of the
/// deepest chain in the image, for one `recvfrom` (tools/lint/stack_chain.py,
/// 2026-09-16). Same shape as [`recv_bounced`], same `inline(never)` for the
/// same reason: inlined, the buffer is back in the caller's frame.
#[inline(never)]
fn recvfrom_bounced(fd: u64, buf_ptr: u64, count: usize, addr_ptr: u64) -> i64 {
    {
        // U07-2: both destinations validated BEFORE the destructive
        // `socket_recvfrom` — it takes the datagram off the socket's queue,
        // so discovering `buf_ptr` or `addr_ptr` is bad only afterwards
        // would drop the datagram for good with the caller told `-EFAULT`.
        if !azos_sched::user_range_prepare_write(buf_ptr as usize, count)
            || !azos_sched::user_range_prepare_write(addr_ptr as usize, 16)
        {
            return -1;
        }
        let mut tmp = [0u8; 4096];
        let mut src = azos_net::socket::SockAddr { family: 0, port: 0, addr: [0; 4] };
        let n = azos_net::socket::socket_recvfrom(fd as i32, &mut tmp[..count], &mut src);
        if n == -1 && azos_net::socket::socket_stream_ended(fd as i32) {
            return end_of_stream();
        }
        if n < 0 { return n as i64; }
        // A zero is an empty datagram only when the stack named a sender; on a
        // stream it is "nothing yet" and the caller's address stays as it was.
        if n == 0 && src.family == 0 { return 0; }
        if n > 0
            && azos_sched::UserSlice::<u8>::new(buf_ptr, n as usize).write_from(&tmp[..n as usize]).is_err()
        {
            return -1;
        }
        // The address is written AFTER the data: if copying the sender out
        // fails, the caller already holds the datagram and loses only the
        // return address, instead of losing both.
        let mut raw = [0u8; 16];
        raw[0..2].copy_from_slice(&src.family.to_le_bytes());
        raw[2..4].copy_from_slice(&src.port.to_be_bytes());
        raw[4..8].copy_from_slice(&src.addr);
        if azos_sched::UserPtr::<[u8; 16]>::new(addr_ptr).write(&raw).is_err() {
            return -1;
        }
        n as i64
    }
}

/// NODE_SEND: a0=fd, a1=buf_ptr, a2=len, a3=flags (ignored).
///
/// `-1` for a socket the caller does not own or an empty buffer; `-EAGAIN`
/// while degraded mode is contained, as `NODE_SEND` answers.
pub fn sys_send_syscall(fd: u64, buf_ptr: u64, len: u64, _flags: u64) -> i64 {
    // Ownership gate: this is the byte-injection half of the finding — an
    // ungated send lets any task write into another task's outbound stream,
    // e.g. forging commands on the brain link or corrupting an OTA image.
    if !socket_access_ok(fd) { return -1; }
    // An empty datagram is a message; an empty write to a stream is nothing.
    let empty = len == 0 && azos_net::socket::socket_is_datagram(fd as i32);
    if (buf_ptr == 0 || len == 0) && !empty { return -1; }
    if untyped_write_contained() { return E_CONTAINED; }
    if empty {
        return azos_net::socket::socket_send(fd as i32, &[]) as i64;
    }
    let count = (len as usize).min(1460);
    // Yield-aware, exactly as `sys_connect_syscall` is: on an ARP cache miss
    // the TCP layer resolves the peer's MAC before the segment goes out,
    // instead of letting `ip::send`'s -1 reach ring 3 as a fatal error over a
    // connection that is perfectly healthy. Owner decision, 2026-09-08.
    //
    // The common case costs one cache lookup — the yield loop is entered only
    // on a miss, and its budget (`SEND_ARP_MAX_YIELDS`) is 20x smaller than
    // connect's because this call sits on the actuation path.
    if azos_sched::current_user_pt() != 0 {
        let mut tmp = [0u8; 1460];
        if azos_sched::UserSlice::<u8>::new(buf_ptr, count).read_into(&mut tmp[..count]).is_err() {
            return -1;
        }
        azos_net::socket::socket_send_with_yield(
            fd as i32, &tmp[..count], azos_sched::task_yield) as i64
    } else {
        let data = unsafe { core::slice::from_raw_parts(buf_ptr as *const u8, count) };
        azos_net::socket::socket_send_with_yield(
            fd as i32, data, azos_sched::task_yield) as i64
    }
}

/// NODE_RECV / NODE_RECVFROM: a0=fd, a1=buf_ptr, a2=len, a3=flags (ignored). Non-blocking.
///
/// Gated here rather than in `dispatch.rs` because `NODE_RECV` and
/// `NODE_RECVFROM` both land on this one handler: one check covers both arms.
pub fn sys_recv_syscall(fd: u64, buf_ptr: u64, len: u64, _flags: u64) -> i64 {
    // Ownership gate: this is the disclosure half of the finding — an
    // ungated recv drains another task's inbound stream, both reading its
    // traffic and stealing the bytes from the rightful owner.
    if !socket_access_ok(fd) { return -1; }
    if buf_ptr == 0 || len == 0 { return -1; }
    // The poll runs from this frame, not from under the 4 KiB bounce buffer.
    // Declared in this function, the buffer was part of this frame for the
    // whole call, and `net_poll` → `tcp::handle_checked` →
    // `send_segment_opts` → `ip::send_flags` below it, with a nested trap on
    // top, ran past the 12 KiB a kernel task stack has above its guard page:
    // every ring-3 e-stop boot ended in a kernel page fault.
    //
    // N8: only when no net-poll task runs. When it does, it is the receive
    // path's consumer (RX interrupt or its poll period), and a drain from
    // here would only queue a request on its pass (`azos_net::rx_owner`).
    if !azos_net::poller_running() {
        azos_net::net_poll();
    }
    recv_bounced(fd, buf_ptr, (len as usize).min(4096))
}

/// What a receive on a TCP socket answers once the connection has ended and
/// nothing is left to read: `-EEOF`, the end of the stream, where every other
/// refusal stays a bare `-1`. The `std` port reads the difference; a caller
/// that only tests for a negative result sees no change.
fn end_of_stream() -> i64 {
    azos_abi::error::Errno::EEOF.to_syscall_ret()
}

/// [`sys_recv_syscall`]'s copy, in a frame of its own so that the bounce
/// buffer does not exist while `net_poll` runs. `inline(never)` is what makes
/// that hold: inlined, the buffer is back in the caller's frame.
#[inline(never)]
fn recv_bounced(fd: u64, buf_ptr: u64, count: usize) -> i64 {
    // U07-2: validated BEFORE the destructive `socket_recv` — it dequeues
    // from the socket's receive buffer, so a bad `buf_ptr` discovered only
    // after the recv succeeded would lose the data for good.
    if azos_sched::current_user_pt() != 0
        && !azos_sched::user_range_prepare_write(buf_ptr as usize, count)
    {
        return -1;
    }
    let mut tmp = [0u8; 4096];
    let n = socket_recv(fd as i32, &mut tmp[..count]);
    if n == -1 && azos_net::socket::socket_stream_ended(fd as i32) {
        return end_of_stream();
    }
    if n > 0 {
        if azos_sched::current_user_pt() != 0 {
            if azos_sched::UserSlice::<u8>::new(buf_ptr, n as usize).write_from(&tmp[..n as usize]).is_err() {
                return -1;
            }
        } else {
            unsafe { core::ptr::copy_nonoverlapping(tmp.as_ptr(), buf_ptr as *mut u8, n as usize); }
        }
    }
    n as i64
}

// ── Cap<Socket> typed handlers (567-570) ─────────────────────────────────────

fn errno_for_socket_err(e: azos_ipc::cap::CapError) -> i64 {
    use azos_abi::error::Errno;
    use azos_ipc::cap::CapError;
    // Every typed refusal in this file reaches the recorder here — the one
    // choke point all twelve of these functions share. `Contained` is filtered
    // inside `note_typed_denial`, not here.
    note_typed_denial(azos_abi::cap::ty::SOCKET, e);
    match e {
        CapError::Stale | CapError::Revoked => Errno::ECAPSTALE.to_syscall_ret(),
        CapError::WrongKind => Errno::ECAPKIND.to_syscall_ret(),
        CapError::MissingPerms => Errno::ECAPPERMS.to_syscall_ret(),
        CapError::Contained => Errno::EAGAIN.to_syscall_ret(),
        CapError::NoSpace => Errno::EMFILE.to_syscall_ret(),
    }
}

/// `DOMAIN_SOCKET`: a0=domain, a1=type, a2=proto. Creates a socket
/// like [`sys_socket`] and mints a `Cap<Socket>` with `READ | WRITE` naming it
/// into the caller's own table. Returns the raw handle, `-1` if the socket
/// could not be created, `-EMFILE` if the cap table is full.
pub fn sys_socket_typed(domain: u64, sock_type: u64, proto: u64) -> i64 {
    use azos_abi::cap::CapPerms;
    use azos_abi::error::Errno;
    use azos_ipc::cap::targets::Socket;

    let fd = sys_socket(domain, sock_type, proto);
    if fd < 0 {
        return fd;
    }
    let tid = azos_sched::current_task_tid();
    // O3.4 (2026-09-26): a socket the task opened itself is giftable
    // (DELEGATE); abitest moves one to epsrv over the 582 exchange.
    match azos_ipc::cap_store::grant::<Socket>(tid, CapPerms::RW_DELEGATE, fd as u32) {
        Some(cap) => cap.raw().as_raw() as i64,
        None => {
            // Undo the create. A socket no capability names would hold one of
            // the task's `MAX_SOCKETS_PER_TASK` slots until it exited.
            socket_close(fd as i32);
            Errno::EMFILE.to_syscall_ret()
        }
    }
}

/// Resolve a `Cap<Socket>` to its socket index under the caller's table lock,
/// released before any network I/O — the shape of [`file_fd_for`].
///
/// The untyped handler it is passed to still runs `socket_access_ok`, and that
/// check is load-bearing: a `Cap<Socket>` CAN be moved to another task (582's
/// `a5`, `TRANSFER`-gated) and keeps naming the sender's socket index, so the
/// receiver's handle resolves here but the socket is not the receiver's.
///
/// `op` is the op the use performs (`NODE_SEND`, `NODE_RECV`, ...): it
/// discharges an `OP_MASK` caveat of the capability.
fn socket_fd_for(cap_raw: u64, need: azos_abi::cap::CapPerms, op: u16) -> Result<u64, i64> {
    use azos_abi::cap::CapHandle;
    use azos_abi::error::Errno;
    use azos_ipc::cap::{targets::Socket, Cap};

    let cap: Cap<Socket> = Cap::from_raw(CapHandle::from_raw(cap_raw as u32));
    let tid = azos_sched::current_task_tid();
    match azos_ipc::cap_store::with_table(tid, |t| t.get_op(cap, need, op)) {
        Some(Ok(fd)) => Ok(fd as u64),
        Some(Err(e)) => Err(errno_for_socket_err(e)),
        None => Err(Errno::EINVAL.to_syscall_ret()),
    }
}

/// `SYS_CONNECT_TYPED`: a0=cap, a1=sockaddr_ptr, a2=addrlen. Requires
/// `WRITE`: choosing where a socket talks to is a write to it.
pub fn sys_connect_typed(cap_raw: u64, addr_ptr: u64, addrlen: u64) -> i64 {
    match socket_fd_for(cap_raw, azos_abi::cap::CapPerms::WRITE, azos_abi::invoke::NODE_CONNECT) {
        Ok(fd) => sys_connect_syscall(fd, addr_ptr, addrlen),
        Err(e) => e,
    }
}

/// `NODE_SEND`: a0=cap, a1=buf, a2=len. Requires `WRITE`.
pub fn sys_send_typed(cap_raw: u64, buf_ptr: u64, len: u64) -> i64 {
    match socket_fd_for(cap_raw, azos_abi::cap::CapPerms::WRITE, azos_abi::invoke::NODE_SEND) {
        Ok(fd) => sys_send_syscall(fd, buf_ptr, len, 0),
        Err(e) => e,
    }
}

/// Bind a `Cap<Socket>` to the local sockaddr at `addr_ptr` (`addrlen`
/// bytes). Requires `WRITE`.
pub fn sys_bind_typed(cap_raw: u64, addr_ptr: u64, addrlen: u64) -> i64 {
    match socket_fd_for(cap_raw, azos_abi::cap::CapPerms::WRITE, azos_abi::invoke::NODE_BIND) {
        Ok(fd) => sys_bind(fd, addr_ptr, addrlen),
        Err(e) => e,
    }
}

/// `NODE_LISTEN`: a0=cap. Requires `WRITE`: a listener takes a port, and the
/// connections that arrive on it. The socket is the one `NODE_BIND` gave a
/// port; the check of ownership is the untyped calls', and containment refuses
/// with `-EAGAIN` as `NODE_CONNECT` does.
pub fn sys_listen_typed(cap_raw: u64) -> i64 {
    let fd = match socket_fd_for(cap_raw, azos_abi::cap::CapPerms::WRITE, azos_abi::invoke::NODE_LISTEN) {
        Ok(fd) => fd,
        Err(e) => return e,
    };
    if !socket_access_ok(fd) {
        return -1;
    }
    if untyped_write_contained() {
        return E_CONTAINED;
    }
    azos_net::socket_listen_bound(fd as i32) as i64
}

/// `NODE_ACCEPT`: a0=cap of a listening socket. Requires `READ`. Takes one
/// established connection and mints a `Cap<Socket>` for it, as
/// [`sys_socket_typed`] does for a socket the task made: owned by the caller
/// (the stamp every other socket call is gated on), `READ | WRITE | DELEGATE`.
/// `-EAGAIN` when none is waiting, and while containment is armed (a new
/// connection is a new write capability); `-EMFILE` when the table is full, the
/// connection then closed.
pub fn sys_accept_typed(cap_raw: u64) -> i64 {
    use azos_abi::cap::CapPerms;
    use azos_abi::error::Errno;
    use azos_ipc::cap::targets::Socket;

    let fd = match socket_fd_for(cap_raw, CapPerms::READ, azos_abi::invoke::NODE_ACCEPT) {
        Ok(fd) => fd,
        Err(e) => return e,
    };
    if !socket_access_ok(fd) {
        return -1;
    }
    if untyped_write_contained() {
        return E_CONTAINED;
    }
    let Some(owner) = socket_owner_for_caller() else { return -1 };
    let conn = azos_net::socket_accept_owned(fd as i32, owner);
    if conn < 0 {
        return Errno::EAGAIN.to_syscall_ret();
    }
    let tid = azos_sched::current_task_tid();
    match azos_ipc::cap_store::grant::<Socket>(tid, CapPerms::RW_DELEGATE, conn as u32) {
        Some(cap) => cap.raw().as_raw() as i64,
        None => {
            socket_close(conn);
            Errno::EMFILE.to_syscall_ret()
        }
    }
}

/// Send on a `Cap<Socket>` to the sockaddr at `addr_ptr` (0: the connected
/// peer). Requires `WRITE`.
pub fn sys_sendto_typed(cap_raw: u64, buf_ptr: u64, len: u64, addr_ptr: u64) -> i64 {
    match socket_fd_for(cap_raw, azos_abi::cap::CapPerms::WRITE, azos_abi::invoke::NODE_SENDTO) {
        Ok(fd) => sys_sendto_syscall(fd, buf_ptr, len, addr_ptr),
        Err(e) => e,
    }
}

/// Receive on a `Cap<Socket>`, the sender's sockaddr into `addr_ptr` (0:
/// none). Requires `READ`.
pub fn sys_recvfrom_typed(cap_raw: u64, buf_ptr: u64, len: u64, addr_ptr: u64) -> i64 {
    match socket_fd_for(cap_raw, azos_abi::cap::CapPerms::READ, azos_abi::invoke::NODE_RECVFROM) {
        Ok(fd) => sys_recvfrom_syscall(fd, buf_ptr, len, addr_ptr),
        Err(e) => e,
    }
}

/// `SYS_RECV_TYPED`: a0=cap, a1=buf, a2=len. Requires `READ`.
pub fn sys_recv_typed(cap_raw: u64, buf_ptr: u64, len: u64) -> i64 {
    match socket_fd_for(cap_raw, azos_abi::cap::CapPerms::READ, azos_abi::invoke::NODE_RECV) {
        Ok(fd) => sys_recv_syscall(fd, buf_ptr, len, 0),
        Err(e) => e,
    }
}

// ── Cap<Socket> multicast (571-572) ──────────────────────────────────────────

/// A refusal from the socket layer's multicast calls, as the errno the ABI
/// documents for `NODE_MCAST_JOIN` / `NODE_MCAST_LEAVE`.
///
/// Records nothing, unlike [`errno_for_socket_err`]: the caller holds the
/// capability, and asked for a group or a socket the operation does not take.
fn errno_for_mcast_err(e: azos_net::socket::McastError) -> i64 {
    use azos_abi::error::Errno;
    use azos_net::socket::McastError;
    match e {
        McastError::BadGroup | McastError::NotUdp | McastError::NotJoined => {
            Errno::EINVAL.to_syscall_ret()
        }
        McastError::SocketFull => Errno::EQUOTA.to_syscall_ret(),
        McastError::TableFull => Errno::ENOSPC.to_syscall_ret(),
        McastError::BadSocket => Errno::EBADF.to_syscall_ret(),
    }
}

/// `a1` as an IPv4 group in network byte order, or `None` for a value wider
/// than 32 bits — truncating it would act on a group the caller did not name.
fn mcast_group_arg(a1: u64) -> Option<[u8; 4]> {
    if a1 > u32::MAX as u64 {
        return None;
    }
    Some((a1 as u32).to_be_bytes())
}

/// `NODE_MCAST_JOIN`: a0=cap, a1=group. Requires `WRITE`: a join
/// changes what the socket receives and puts a Membership Report on the wire.
///
/// The capability is resolved before the group is read, so a forged or
/// contained handle gets the capability's answer whatever group it names —
/// the order the rest of the family keeps with its buffers. Then the socket's
/// owner stamp, as every other socket call checks it (`socket_access_ok`): a
/// `Cap<Socket>` holds a bare socket index, so a handle that outlived its
/// socket, or was moved out of its owner's table, names whatever socket took
/// the index since, and is refused with -1 as `NODE_LISTEN` refuses it.
pub fn sys_mcast_join_typed(cap_raw: u64, group: u64) -> i64 {
    let fd = match socket_fd_for(cap_raw, azos_abi::cap::CapPerms::WRITE, azos_abi::invoke::NODE_MCAST_JOIN) {
        Ok(fd) => fd,
        Err(e) => return e,
    };
    if !socket_access_ok(fd) {
        return -1;
    }
    let Some(g) = mcast_group_arg(group) else {
        return azos_abi::error::Errno::EINVAL.to_syscall_ret();
    };
    match azos_net::socket::socket_mcast_join(fd as i32, &g) {
        Ok(()) => 0,
        Err(e) => errno_for_mcast_err(e),
    }
}

/// `NODE_MCAST_LEAVE`: a0=cap, a1=group. Needs only a live
/// `Cap<Socket>` (`CapPerms::NONE`), like `SYS_CAP_CLOSE`: giving a membership
/// back is cleanup, and containment must not keep a group joined. The owner
/// stamp is checked as for the join: a stale handle must not drop another
/// task's membership.
pub fn sys_mcast_leave_typed(cap_raw: u64, group: u64) -> i64 {
    let fd = match socket_fd_for(cap_raw, azos_abi::cap::CapPerms::NONE, azos_abi::invoke::NODE_MCAST_LEAVE) {
        Ok(fd) => fd,
        Err(e) => return e,
    };
    if !socket_access_ok(fd) {
        return -1;
    }
    let Some(g) = mcast_group_arg(group) else {
        return azos_abi::error::Errno::EINVAL.to_syscall_ret();
    };
    match azos_net::socket::socket_mcast_leave(fd as i32, &g) {
        Ok(()) => 0,
        Err(e) => errno_for_mcast_err(e),
    }
}

/// DOMAIN_NET_GETIP: return IP address as u32 (big-endian).
pub fn sys_net_getip() -> i64 {
    let ip = net_get_ip();
    u32::from_be_bytes(ip) as i64
}

// ── MMAP / MUNMAP ────────────────────────────────────────────────────────────

/// `PROT_EXEC` in `sys_mmap`'s `prot`, the POSIX bit value (`PROT_READ` 1,
/// `PROT_WRITE` 2).
pub const MMAP_PROT_EXEC: u64 = 4;
/// `prot` bits `sys_mmap`/`sys_mprotect` honour (wave 13), Linux's values.
pub const MMAP_PROT_READ: u64 = 1;
pub const MMAP_PROT_WRITE: u64 = 2;
/// `flags` bits `sys_mmap` honours (wave 14, DEMANDPAGE), Linux's values:
/// commit every page now instead of on first touch. `MAP_LOCKED` implies it
/// (a locked mapping must take no fault).
pub const MMAP_MAP_POPULATE: u64 = 0x8000;
pub const MMAP_MAP_LOCKED: u64 = 0x2000;
/// `flags` bit `sys_mmap` honours for a Linux task, Linux's value: place the
/// mapping exactly at `addr`, or answer `-EEXIST` and leave everything as it
/// was. Never over another mapping. Plain `MAP_FIXED`, which replaces what
/// the range holds, has no bit here: the personalities refuse it. A native
/// task's is its module window's (`crate::module_window`). The ABI's one
/// constant.
pub use azos_abi::syscall_nr::MMAP_MAP_FIXED_NOREPLACE;
/// Highest real-time `SchedClass` discriminant (SafetyCritical 0, HardRT 1,
/// SoftRT 2).
pub(crate) const RT_CLASS_MAX: u8 = 2;

/// Does this mapping commit every page at map time (wave 14, DEMANDPAGE)?
/// Yes with demand paging off, with `MAP_POPULATE`/`MAP_LOCKED`, for a
/// `mem = "locked"` task (it must take no page fault), and with
/// `MM_PRECOMMIT_RT` for a real-time-class task (a control loop never takes a
/// demand fault inside its period).
fn mmap_precommit(flags: u64) -> bool {
    !azos_mm::pager::DEMAND_PAGING
        || flags & (MMAP_MAP_POPULATE | MMAP_MAP_LOCKED) != 0
        || azos_sched::current_mem_locked()
        || (azos_mm::pager::PRECOMMIT_RT && azos_sched::current_sched_params().1 <= RT_CLASS_MAX)
}

/// May a request of the current task grow its Domain's budget past the base
/// (`azos_sched::mm_charge_request`)? Not a locked or real-time task's: its
/// memory is sized at admission.
fn request_may_grow() -> bool {
    !azos_sched::current_mem_locked() && azos_sched::current_sched_params().1 > RT_CLASS_MAX
}

/// Where a new mapping of `span` bytes (a page multiple) goes: `sys_mmap`'s
/// and a private file mapping's (`crate::file_map`). The start, or the
/// value to return (`-1` or a negative errno). [`mmap_placed`] records it once
/// the mapping is made.
///
/// * **A native task** (and a task the ring-3 Linux runtime hosts): at its
///   break, which the mapping then moves past, as always. `ualloc`'s guard
///   pages count on that bump. The hint is not consulted. Its
///   `MAP_FIXED_NOREPLACE` is the module window of a Linux driver server
///   (`crate::module_window`), which `sys_mmap` hands the request to before
///   any placement: exact and committed there, the break untouched, so it
///   never reaches this arm.
/// * **A Linux task**: in its mmap area (`azos_sched::user_mmap_area`),
///   top-down from the cursor (`azos_sched::update_user_mmap_low`, the lowest
///   address handed out), as Linux places mappings below its mmap base. The
///   area starts where the break stops, so the two never meet. Everything
///   between the floor and the cursor is vacant, so:
///   - a hint is honoured when its range lies there (and the page table has
///     nothing in it); otherwise the mapping goes below the cursor, as
///     Linux falls back. A libc that grows its heap downward by hints (zig's
///     `PageAllocator`, BusyBox's) gets one contiguous run, one region record.
///   - `MAP_FIXED_NOREPLACE` takes exactly that range or nothing: `-EINVAL`
///     for an unaligned address, `-ENOMEM` outside the area, `-EEXIST` when
///     the range reaches the cursor. Above the cursor a `PROT_NONE` mapping
///     leaves no record to tell it from a hole, so it is never presumed free.
pub(crate) fn mmap_place(user_pt: usize, addr: u64, span: usize, flags: u64) -> Result<usize, i64> {
    let page = azos_arch::PAGE_SIZE;
    if mmap_at_break() {
        // **WHY the brk itself has to be checked (null-guard follow-up).**
        // A task whose brk was never initialised reports **0** (`scheduler.rs`
        // zeroes `user_brk` at task creation). The range was then reserved
        // starting at VA 0 and the syscall answered `0` — a *successful*
        // allocation whose base is the null pointer. Callers cannot tell that
        // apart from a real address. `vmm::USER_GUARD_LIMIT` makes the first
        // access to such a pointer kill the task, but the allocation itself is
        // nonsense: refused here, at the only place that can tell.
        let base = azos_sched::update_user_brk(0) as usize;
        if base < azos_mm::vmm::USER_GUARD_LIMIT { return Err(-1); }
        let aligned = base.saturating_add(page - 1) & !(page - 1);
        // The mapping must end at or below the shm/MMIO window (and so
        // strictly below the user VA ceiling: above it the "user" page table is
        // the kernel's): `shm_map_user` and `mmio_map_user` hand out addresses
        // there, and `sys_munmap` and teardown never free a frame there, so an
        // anonymous page placed in it would never be freed.
        let at_break = aligned
            .checked_add(span)
            .is_some_and(|end| end <= azos_sched::user_shm_window().0 && azos_mm::vmm::user_range_vacant(user_pt, aligned, end));
        if at_break {
            return Ok(aligned);
        }
        // The break runs into the first device window the kernel keeps in low
        // user space (32 MiB up on riscv64, 128 MiB on aarch64 QEMU virt): the
        // rest of the address space is no less the task's, so the mapping goes
        // in the mmap area a Linux task places in.
        if cfg!(feature = "mmap-break-only-canary") {
            return Err(-1);
        }
    }
    place_in_area(user_pt, addr, span, flags)
}

/// Where a shared mapping (a shared object, a shared file window) of `span`
/// bytes goes: in the mmap area, top-down from the cursor, whatever the task
/// is. The break stays where it is. [`mmap_area_placed`] records it.
pub(crate) fn mmap_place_shared(user_pt: usize, span: usize) -> Result<usize, i64> {
    place_in_area(user_pt, 0, span, 0)
}

/// Move the cursor of the mmap area down to a mapping [`mmap_place_shared`] placed.
pub(crate) fn mmap_area_placed(start: usize) {
    let low = azos_sched::update_user_mmap_low(0) as usize;
    if low == 0 || start < low {
        azos_sched::update_user_mmap_low(start as u64);
    }
}

/// The mmap area's placement: the second half of [`mmap_place`].
fn place_in_area(user_pt: usize, addr: u64, span: usize, flags: u64) -> Result<usize, i64> {
    use azos_abi::error::Errno;
    let page = azos_arch::PAGE_SIZE;
    let addr = if mmap_at_break() { 0 } else { addr };
    let (floor, ceiling) = azos_sched::user_mmap_area();
    let low = match azos_sched::update_user_mmap_low(0) as usize {
        0 => ceiling,
        c => c,
    };
    let fits = |s: usize| {
        cfg!(feature = "mmap-hint-window-canary")
            || (s >= floor && s.checked_add(span).is_some_and(|e| e <= low))
    };
    let vacant = |s: usize| azos_mm::vmm::user_range_vacant(user_pt, s, s + span);
    if flags & MMAP_MAP_FIXED_NOREPLACE != 0 && !cfg!(feature = "mmap-noreplace-canary") {
        let s = addr as usize;
        if s & (page - 1) != 0 {
            return Err(Errno::EINVAL.to_syscall_ret());
        }
        if s < floor || s.checked_add(span).is_none_or(|e| e > ceiling) {
            return Err(Errno::ENOMEM.to_syscall_ret());
        }
        return if fits(s) && vacant(s) { Ok(s) } else { Err(Errno::EEXIST.to_syscall_ret()) };
    }
    if addr != 0 && !cfg!(feature = "mmap-hint-canary") {
        if let Some(s) = (addr as usize).checked_add(page - 1).map(|a| a & !(page - 1)) {
            if fits(s) && vacant(s) {
                return Ok(s);
            }
        }
    }
    // Top-down below the cursor, stepping under whatever the page table holds
    // there (a slot the kernel shares on this board).
    let mut end = low;
    while end >= floor.saturating_add(span) {
        let s = end - span;
        if vacant(s) {
            return Ok(s);
        }
        let mut p = end - page;
        while p > s && azos_mm::vmm::user_range_vacant(user_pt, p, p + page) {
            p -= page;
        }
        end = p;
    }
    Err(-1)
}

/// Does the calling task's mmap go at its break first (a native or hosted
/// task), not straight in the mmap area? [`mmap_place`]'s two arms.
fn mmap_at_break() -> bool {
    !azos_sched::scheduler::current_is_linux() || cfg!(feature = "mmap-brk-apart-canary")
}

/// Record a mapping [`mmap_place`] placed at `[start, end)`: a native task's
/// break moves past it when it went at the break, the cursor of the mmap area
/// down to it when it went there, as every Linux task's.
pub(crate) fn mmap_placed(start: usize, end: usize) {
    if mmap_at_break() {
        let page = azos_arch::PAGE_SIZE;
        let brk = azos_sched::update_user_brk(0) as usize;
        if start == brk.saturating_add(page - 1) & !(page - 1) {
            azos_sched::update_user_brk(end as u64);
            return;
        }
    }
    let low = azos_sched::update_user_mmap_low(0) as usize;
    if low == 0 || start < low {
        azos_sched::update_user_mmap_low(start as u64);
    }
}

/// `sys_munmap` emptied `[start, end)`: a Linux task's cursor climbs back over
/// it when the range began at or below the cursor, so the area below the
/// cursor stays vacant and a range given back next to it is placed again
/// (zig's allocator trims each slab's head, just below the cursor).
pub(crate) fn mmap_unmapped(start: usize, end: usize) {
    let (_, ceiling) = azos_sched::user_mmap_area();
    let low = azos_sched::update_user_mmap_low(0) as usize;
    if low != 0 && start <= low && end > low {
        azos_sched::update_user_mmap_low(end.min(ceiling) as u64);
    }
}

/// Is `va` in the part of a Linux task's mmap area its mmaps handed out
/// (`[cursor, ceiling)`)? `sys_mprotect` maps a missing page there, as it does
/// below the break: musl reserves a thread stack `PROT_NONE` and opens it.
fn mmap_handed_out(va: usize) -> bool {
    if !azos_sched::scheduler::current_is_linux() {
        return false;
    }
    let (_, ceiling) = azos_sched::user_mmap_area();
    let low = azos_sched::update_user_mmap_low(0) as usize;
    low != 0 && va >= low && va < ceiling
}

/// SYS_MO_MAP: anonymous memory mapping.
/// a0=addr (hint, 0=any), a1=length, a2=prot, a3=flags, a4=fd (-1 anon), a5=offset.
/// Placement: [`mmap_place`] (a native task's hint is not consulted).
/// Returns mapped virtual address, `-EINVAL` for `PROT_EXEC`, a Linux task's
/// `MAP_FIXED_NOREPLACE` refusal (`-EEXIST`, `-ENOMEM`, `-EINVAL`), or -1 on
/// any other error.
///
/// Wave 14 (DEMANDPAGE): the range is reserved (a region record) and each
/// page committed on its first touch, unless [`mmap_precommit`] says
/// otherwise or the address space has no free record, in which case every
/// page is committed now, as before. Either way the whole request is charged
/// here (reserve-time charging).
pub fn sys_mmap(addr: u64, length: u64, prot: u64, flags: u64, fd: u64, _offset: u64) -> i64 {
    // Wave 13: one layout change at a time per thread group.
    let _mm = azos_sched::group::mm_lock();
    crate::ipc_handlers::reap_stale_mappings();
    // **No executable anonymous memory.** Every page below is mapped USER_RW
    // and never X, so a `PROT_EXEC` request could only be answered with a
    // mapping that does not do what was asked. Refused before anything else,
    // so the answer does not depend on the caller's break or page table: W^X
    // holds for ring 3 by construction, not by the flags a caller forgot.
    if prot & MMAP_PROT_EXEC != 0 {
        return azos_abi::error::Errno::EINVAL.to_syscall_ret();
    }
    // Only support anonymous mappings (fd == -1 or fd == u64::MAX)
    if fd != u64::MAX && fd as i64 != -1 { return -1; }
    let Some(space) = azos_sched::current_aspace() else { return -1 }; // kernel task
    let user_pt = space.root();

    let len = length as usize;
    if len == 0 { return -1; }
    // Cap the request.  `length` used to be unbounded, so a single
    // `mmap(0, u64::MAX, ..)` from ring 3 drained every free physical page —
    // and because the OOM path below returned without unwinding, the pages
    // already mapped stayed lost for the lifetime of the boot.
    if len > azos_mm::pager::MAX_MAP_BYTES { return -1; }
    // A native task's `MAP_FIXED_NOREPLACE`: a Linux driver server's module
    // memory, an exact address inside its module window, the break untouched
    // (module_window.rs). A Linux task's is placed in its mmap area below.
    if flags & MMAP_MAP_FIXED_NOREPLACE != 0 && mmap_at_break() {
        return crate::module_window::map_fixed(user_pt, addr, len, prot, crate::module_window::caller_may_place());
    }

    let page_size = azos_arch::PAGE_SIZE;
    let num_pages = len.saturating_add(page_size - 1) / page_size;

    let span = match num_pages.checked_mul(page_size) {
        Some(s) => s,
        None    => return -1,
    };
    let aligned_base = match mmap_place(user_pt, addr, span, flags) {
        Ok(b) => b,
        Err(e) => return e,
    };
    let end_va = aligned_base + span;

    // Owner decision 102 — charge the whole request before taking one frame.
    //
    // All or nothing, as `brk`: a caller that asked for 64 pages cannot use 40.
    // Charging first also means a refusal leaves the allocator untouched.
    // Wave 13 (security): `prot` is honoured. PROT_NONE reserves the range
    // (the break moves past it) and maps nothing; `mprotect` maps it later.
    // Anything else maps readable pages, writable only with PROT_WRITE: a
    // store to a PROT_READ mapping faults (128+SIGSEGV), as on Linux. It
    // used to be read-write whatever `prot` said. Gate canary
    // `mmap-prot-canary` brings that back.
    let canary = cfg!(feature = "mmap-prot-canary");
    let writable = canary || prot & MMAP_PROT_WRITE != 0;
    if prot & (MMAP_PROT_READ | MMAP_PROT_WRITE) == 0 && !canary {
        mmap_placed(aligned_base, end_va);
        return aligned_base as i64;
    }

    if !azos_sched::mm_charge_request(num_pages as u32, request_may_grow()) { return -1; }

    // Wave 14 (DEMANDPAGE): reserve; the fault path commits each page from
    // the region's pager with exactly these permissions (never executable).
    if !mmap_precommit(flags)
        && azos_mm::pager::reserve(space, aligned_base, end_va, writable).is_ok()
    {
        mmap_placed(aligned_base, end_va);
        return aligned_base as i64;
    }
    if !commit_now(user_pt, aligned_base, num_pages, writable) {
        // The whole request was charged up front and none of it survives.
        azos_sched::mm_discharge(num_pages as u32);
        return -1;
    }
    mmap_placed(aligned_base, end_va);
    aligned_base as i64
}

/// Map `pages` zeroed frames from `base` on, writable iff `writable`: the
/// committed form of an anonymous mapping (`sys_mmap`, `sys_brk`) for a task
/// whose pages are never faulted in ([`mmap_precommit`]), or a space with no
/// record left. All or nothing: on `false` every frame mapped here is unmapped
/// and freed again. The caller charged the pages.
pub(crate) fn commit_now(user_pt: usize, base: usize, pages: usize, writable: bool) -> bool {
    let page_size = azos_arch::PAGE_SIZE;
    let flags = azos_arch_api::PagePerms {
        accessed: true, dirty: writable, write: writable,
        ..azos_arch_api::PagePerms::USER_RW
    };
    let mut va = base;
    for _ in 0..pages {
        let Ok(page) = azos_mm::pmm::alloc_page() else {
            mmap_unwind(user_pt, base, va);
            return false;
        };
        if azos_mm::vmm::map(user_pt, va, page.as_usize(), flags).is_err() {
            let _ = azos_mm::pmm::free_page(page);
            mmap_unwind(user_pt, base, va);
            return false;
        }
        va += page_size;
    }
    true
}

/// Free and unmap the pages `sys_mmap` installed in `[base, end)` after a
/// mid-loop failure.  No side table is needed: every page in that range was
/// allocated by this call and mapped USER_RW, so `translate_user` resolves it
/// and the physical page is exclusively ours to release.  `vmm::unmap` shoots
/// the address down on every hart that may hold it before it returns, so no
/// stale TLB entry survives the free.
fn mmap_unwind(user_pt: usize, base: usize, end: usize) {
    let page_size = azos_arch::PAGE_SIZE;
    let mut v = base;
    while v < end {
        if let Some(pa) = azos_mm::vmm::translate_user(user_pt, v, false) {
            azos_mm::vmm::unmap(user_pt, v);
            let _ = azos_mm::pmm::free_page(azos_mm::addr::PhysAddr(pa & !(page_size - 1)));
        }
        v = v.saturating_add(page_size);
    }
}

/// SYS_MO_UNMAP: unmap pages.  Simplified: just marks pages as unmapped.
/// `mprotect(addr, len, prot)` (wave 13, security): give the pages of
/// `[addr, addr + len)` exactly `prot`'s read and write permissions. The
/// Linux personality's `mprotect` (no native number: it is the memory
/// authority `SYS_MO_MAP` already grants).
///
/// * `PROT_EXEC`: refused, `-EACCES` (W^X: no writable-then-executable path
///   exists for user pages), as is adding write to an executable page.
/// * `PROT_NONE`: the pages are unmapped and freed (their contents are lost:
///   a divergence from Linux, which keeps them for a later `mprotect`).
/// * Read or read-write: present pages and demand reservations change
///   permission; a page with nothing behind it below the break, or in the
///   part of a Linux task's mmap area its mmaps handed out (a `PROT_NONE`
///   mapping's, or an unmapped one), is mapped zeroed and charged.
///   Copy-on-write pages keep their sharing (`vmm::protect_user_range`).
///
/// `-EINVAL` for a misaligned or empty range or unknown bits, `-ENOMEM` for a
/// page past those or one the kernel owns (shm/MMIO window, a kernel
/// mapping, a locked region). Nothing changes on a refusal.
pub fn sys_mprotect(addr: u64, length: u64, prot: u64) -> i64 {
    use azos_abi::error::Errno;
    let _mm = azos_sched::group::mm_lock();
    let page_size = azos_arch::PAGE_SIZE;
    if prot & !(MMAP_PROT_READ | MMAP_PROT_WRITE | MMAP_PROT_EXEC) != 0
        || addr as usize & (page_size - 1) != 0 || length == 0
    {
        return Errno::EINVAL.to_syscall_ret();
    }
    if prot & MMAP_PROT_EXEC != 0 {
        return Errno::EACCES.to_syscall_ret();
    }
    let Some(space) = azos_sched::current_aspace() else { return -1 };
    let user_pt = space.root();
    let start = addr as usize;
    let rounded = (length as usize).saturating_add(page_size - 1) & !(page_size - 1);
    let (shm_lo, shm_hi) = azos_sched::user_shm_window();
    let end = match start.checked_add(rounded) {
        Some(e) if start >= azos_mm::vmm::USER_GUARD_LIMIT && e <= shm_lo => e,
        _ => return Errno::ENOMEM.to_syscall_ret(),
    };
    let _ = shm_hi;
    if azos_mm::vmm::locked_region_in_range(user_pt, start, end) {
        return Errno::ENOMEM.to_syscall_ret();
    }
    // A file mapping keeps the permission it was made with: a shared one's
    // dirty record in the page cache is made from it (`crate::file_map`). A
    // shared object's mapping changes it through `SYS_MO_MAP`'s protect form,
    // which keeps the object's record and the leaves together.
    if azos_mm::pager::has_whole(space, start, end) {
        return Errno::EINVAL.to_syscall_ret();
    }
    let none = prot & (MMAP_PROT_READ | MMAP_PROT_WRITE) == 0;
    let write = prot & MMAP_PROT_WRITE != 0;
    let brk = azos_sched::update_user_brk(0) as usize;
    // Pass 1: refuse before anything changes.
    let mut missing = 0u32;
    let mut va = start;
    while va < end {
        if azos_mm::vmm::va_is_kernel_mapped(va) { return Errno::ENOMEM.to_syscall_ret(); }
        match azos_mm::vmm::user_page(user_pt, va) {
            azos_mm::vmm::UserPage::Other => return Errno::ENOMEM.to_syscall_ret(),
            azos_mm::vmm::UserPage::Leaf { exec: true } if write => {
                return Errno::EACCES.to_syscall_ret();
            }
            // Wave 15: the vDSO and signal-trampoline frames are the
            // kernel's, one for every address space; never writable.
            azos_mm::vmm::UserPage::Leaf { .. }
                if write && azos_mm::vmm::user_leaf_is_kernel_shared(user_pt, va) =>
            {
                return Errno::EACCES.to_syscall_ret();
            }
            // Wave 14: a reserved page is not missing (it is charged and
            // committed on first touch); its region takes the new `prot`.
            azos_mm::vmm::UserPage::Missing if !none && !azos_mm::pager::contains(space, va) => {
                if va >= brk && !mmap_handed_out(va) { return Errno::ENOMEM.to_syscall_ret(); }
                missing += 1;
            }
            _ => {}
        }
        va += page_size;
    }
    if cfg!(feature = "mmap-prot-canary") {
        return 0; // gate canary: permissions never change
    }
    if none {
        // Wave 14: a `PROT_NONE` range stops being reserved, before the
        // sweep (as in `sys_munmap`); its uncommitted pages are discharged.
        let reserved = match azos_mm::pager::release_range(space, start, end) {
            Ok(n) => n as u32,
            Err(_) => return Errno::ENOMEM.to_syscall_ret(),
        };
        let freed = azos_mm::vmm::unmap_user_range_and_free(user_pt, start, end, shm_lo, shm_hi)
            .saturating_add(reserved);
        azos_sched::mm_discharge(freed);
        return 0;
    }
    // Pass 2: back what has nothing behind it, then set the permission.
    // The reclaimer takes no page of the space meanwhile: a leaf it swapped
    // out under the rewrite would be written back as a valid leaf on a frame
    // it is about to free, and a store that fails restores the old permission.
    let _reclaim_off = azos_mm::pager::reclaim_pause(space);
    // Wave 14: regions first. It is the step that can refuse for want of a
    // record, and a refusal here leaves everything as it was.
    if azos_mm::pager::protect_range(space, start, end, write).is_err() {
        return Errno::ENOMEM.to_syscall_ret();
    }
    if missing != 0 {
        if !azos_sched::mm_charge(missing) { return Errno::ENOMEM.to_syscall_ret(); }
        let flags = azos_arch_api::PagePerms {
            accessed: true, dirty: write, write,
            ..azos_arch_api::PagePerms::USER_RW
        };
        let mut v = start;
        while v < end {
            if azos_mm::vmm::user_page(user_pt, v) == azos_mm::vmm::UserPage::Missing
                && !azos_mm::pager::contains(space, v)
            {
                let ok = match azos_mm::pmm::alloc_page() {
                    Ok(page) => {
                        let r = azos_mm::vmm::map(user_pt, v, page.as_usize(), flags).is_ok();
                        if !r { let _ = azos_mm::pmm::free_page(page); }
                        r
                    }
                    Err(_) => false,
                };
                if !ok {
                    // What was mapped stays (and stays charged); the rest is not.
                    let mut left = 0u32;
                    let mut w = v;
                    while w < end {
                        if azos_mm::vmm::user_page(user_pt, w) == azos_mm::vmm::UserPage::Missing
                            && !azos_mm::pager::contains(space, w)
                        {
                            left += 1;
                        }
                        w += page_size;
                    }
                    azos_sched::mm_discharge(left);
                    return Errno::ENOMEM.to_syscall_ret();
                }
            }
            v += page_size;
        }
    }
    let _ = azos_mm::vmm::protect_user_range(user_pt, start, end, write);
    0
}

pub fn sys_munmap(addr: u64, length: u64) -> i64 {
    // Wave 13: one layout change at a time per thread group.
    let _mm = azos_sched::group::mm_lock();
    crate::ipc_handlers::reap_stale_mappings();
    let Some(space) = azos_sched::current_aspace() else { return -1 };
    let user_pt = space.root();

    let page_size = azos_arch::PAGE_SIZE;
    let len = length as usize;
    if len == 0 { return -1; }

    // Bound the request to the user half of the address space, and bound its
    // size.  Both checks are load-bearing:
    //
    //   * User and kernel page tables share their L1/L0 tables, so unmapping a
    //     VA at or above `USER_VA_TOP` zeroes a PTE the *kernel* is using.
    //     `munmap(0x1000_0000, 4096)` cleared the UART mapping for every hart;
    //     the next `kprintln!` took a fatal S-mode store fault and, with
    //     `panic = "abort"`, reset the board.  Kernel text at vpn2 = 2 also got
    //     its megapage split by `vmm::unmap` on the way through.
    //   * `length = u64::MAX` made the old `saturating_add` clamp `end` to
    //     `usize::MAX`, so the loop below ran ~2^52 iterations inside the
    //     kernel with interrupts on but no way out — an unkillable hang.
    //
    // Rejecting (rather than clamping) keeps the failure visible to the caller
    // instead of silently unmapping a different range than it asked for.
    let start = addr as usize & !(page_size - 1);
    if start >= USER_VA_TOP { return -1; }
    if len > azos_mm::pager::MAX_MAP_BYTES { return -1; }
    let rounded = len.saturating_add(page_size - 1) & !(page_size - 1);
    let end = match start.checked_add(rounded) {
        Some(e) if e <= USER_VA_TOP => e,
        _ => return -1,
    };

    // The ceiling above is NOT what keeps ring 3 out of the kernel's page
    // table, and the incident recorded in this comment happened with it in
    // place. `USER_VA_TOP` is at least 1 GiB on every board this OS targets
    // (2 GiB on QEMU/K1, 1 GiB on VF2 -- see its derivation in `process.rs`);
    // CLINT (32 MiB), PLIC (192 MiB) and UART (256 MiB) are all below it on
    // every one of them and all inside the region every user page table
    // SHARES with the kernel -- shares, not copies: the merge writes the
    // kernel's non-leaf PTE, a pointer to the kernel's own next-level table.
    // So `vmm::unmap` walking a user root reaches the kernel's L0 entry and
    // clears it there. Losing the UART kills `kprintln!`; the next one takes a
    // fatal S-mode store fault and, with `panic = "abort"`, resets the board.
    //
    // Demonstrated from ring 3 with no capability and no privilege: three
    // calls, and the console stopped mid-line on the third.
    //
    // Checked here rather than by lowering the ceiling to the CLINT, because a
    // constant encoding where a board's MMIO starts is one port away from
    // being wrong in the direction that loses the console. Asking the kernel's
    // own page table cannot drift from the board, and a new window is covered
    // the moment it is mapped.
    //
    // Refused whole, not clamped: unmapping "the part you were allowed to"
    // leaves the caller believing a range is gone when it is not.
    let mut va = start;
    while va < end {
        if azos_mm::vmm::va_is_kernel_mapped(va) { return -1; }
        va += page_size;
    }
    // Kconfig LOCKED_HUGE_LEAVES: a locked row's region is mapped with
    // level-1 leaves for the task's whole life. Unmapping part of it would
    // need a split the region exists to avoid, and the frame release below
    // skips such leaves, so "success" would remove nothing: refused whole.
    // Compiled out (a constant `false`, inlined) when the option is off.
    if azos_mm::vmm::locked_region_in_range(user_pt, start, end) {
        return -1;
    }

    // Release the frames, do not merely forget them.
    //
    // This loop used to call `vmm::unmap`, which clears the PTE and frees
    // nothing. There is no per-task frame list and exit teardown only frees
    // what is still mapped, so every `mmap` + `munmap` pair leaked its frames
    // for the rest of the boot -- and a fork+exec loop repeated it with a fresh
    // break each time. The end state is a PMM with nothing left: no further
    // fork, exec, mmap or page-table allocation. On a robot that is not a
    // crash, it is a machine that cannot respawn its controller, which is
    // worse, because it looks like it is still running.
    //
    // The rule for "the task's own frame" is `vmm`'s, shared with the exit
    // path rather than restated here: a `USER` leaf, outside the shared-memory
    // window, not the vDSO page, and with no other COW holder. The window
    // bounds come from `sched`, where they are defined.
    let (shm_lo, shm_hi) = azos_sched::user_shm_window();
    // Owner decision 102 — discharge exactly what was FREED, not what was
    // asked for. `unmap_user_range_and_free` counts exactly that: nothing for a VA
    // that held nothing of ours, a shared-memory page, the vDSO, or a frame
    // another COW holder still owns. Discharging the requested length instead
    // would credit a task for frames it never had, which is the direction that
    // silently disables the budget.
    //
    // Wave 8: one TLB shootdown per batch of `vmm::UNMAP_BATCH_PAGES` pages,
    // not one per page; each batch's frames are freed only after its
    // shootdown, so no hart can still read a frame the PMM has reissued.
    //
    // Wave 14 (DEMANDPAGE): the range leaves its regions BEFORE the sweep,
    // so no fault can commit a page in it afterwards. The reserved pages
    // never committed were charged at mmap and come back here; the sweep
    // frees and counts the committed ones.
    // A cut with no free record is refused with `-ENOMEM`, not the `-1` of
    // the refusals above: it is Linux's answer past its map count, and the
    // Linux personality passes an errno through (it turns `-1` into EINVAL).
    // The file mappings the range holds (a file region goes whole or not at
    // all), listed first: the sweep below clears their PTEs, and only then may
    // their pages go back to the file and their bookings be given up.
    // A shared object's mapping ends with the object's release (`SYS_MO_UNMAP`),
    // which gives back the booking and the references it holds.
    if azos_mm::pager::has_obj(space, start, end) {
        return azos_abi::error::Errno::EINVAL.to_syscall_ret();
    }
    let mut files = [azos_mm::pager::FileRegion::NONE; crate::file_map::MUNMAP_FILES];
    let nfiles = match azos_mm::pager::file_regions_in(space, start, end, &mut files) {
        Ok(n) => n,
        Err(_) => return azos_abi::error::Errno::ENOMEM.to_syscall_ret(),
    };
    let reserved = match azos_mm::pager::release_range(space, start, end) {
        Ok(n) => n as u32,
        Err(_) => return azos_abi::error::Errno::ENOMEM.to_syscall_ret(),
    };
    let freed: u32 = azos_mm::vmm::unmap_user_range_and_free(user_pt, start, end, shm_lo, shm_hi)
        .saturating_add(reserved);
    crate::file_map::unmap_finish(&files[..nfiles]);
    azos_sched::mm_discharge(freed);
    mmap_unmapped(start, end);
    0
}

/// Wave 14 (DEMANDPAGE), a fork's `before_release` step: the child gets
/// the parent's mappings, its anonymous objects cloned (their resident pages
/// shared copy-on-write, their compressed ones a share of the pool), and is
/// charged for the part not committed yet, under the same reserve-time model
/// as `sys_mmap`, plus the page tables and slot chunks the clone built for it,
/// all as one request. `false` (the fork is refused) when the child's budget
/// cannot take it.
/// Called with the group's `mm_lock` held, before the child can run.
pub(crate) fn fork_regions_to_child(child: u32) -> bool {
    let (Some(parent), Some(child_space)) = (azos_sched::current_aspace(), azos_sched::task_aspace(child)) else {
        return true;
    };
    let cloned = azos_mm::pager::fork_clone(parent, child_space);
    let built = azos_sched::take_current_pt_build();
    let owed = match cloned {
        Ok(n) => n.min(u32::MAX as usize) as u32,
        Err(e) => {
            // Not memory pressure: the parent's own records disagree.
            // Canary `clone-invariant-silent-canary`: it is not reported.
            if e == azos_mm::mapping::MapError::Invalid && !cfg!(feature = "clone-invariant-silent-canary") {
                azos_sched::note_clone_invariant();
            }
            return false;
        }
    };
    // The reservation and the tables and slot chunks built for it are one
    // request: the child starts from the row's base limit, and a parent that
    // grew past it must still be able to fork. Canary
    // `fork-chunks-within-base-canary`: the tables and chunks must fit the base.
    let within_base = cfg!(feature = "fork-chunks-within-base-canary");
    if within_base && !azos_sched::mm_charge_request_tid(child, built, false) {
        azos_mm::pager::forget(child_space);
        return false;
    }
    let request = if within_base { owed } else { owed.saturating_add(built) };
    if !azos_sched::mm_charge_request_tid(child, request, request_may_grow()) {
        if within_base {
            azos_sched::mm_discharge_tid(child, built);
        }
        azos_mm::pager::forget(child_space);
        return false;
    }
    true
}

// ── Network utility syscalls ─────────────────────────────────────────────────

/// `SYS_CAP_INFO`: a0 = `CapKind` as u8, a1 = resource index.
///
/// Returns the caller's own handle as a non-negative value, `-ENOENT` if it
/// holds no such capability, `-EINVAL` for a kind byte that is not a
/// `CapKind`.
///
/// # Three things this deliberately does not do
///
/// **It does not take a TID.** The table is always `current_task_tid()`'s, so
/// there is no argument by which a caller could ask about another task.
///
/// **It does not bypass for the kernel.** `cap_check` returns true for
/// `user_pt == 0`; there is nothing to bypass here, because the answer for a
/// kernel task is its own table's contents, same as anyone's.
///
/// **It does not consult degraded mode.** Naming a capability is not using
/// one. `CapTable::get` returns `Contained` for a write while containment is
/// armed, which is where that belongs; refusing the lookup would tell a task
/// its authority was revoked when it was only suspended.
///
/// `CapKind::from_raw` has no catch-all arm, so an unknown kind byte is
/// `EINVAL` rather than aliasing onto a real kind — fail-closed at the ABI
/// edge, which is the point of that match having stayed exhaustive.
pub fn sys_cap_lookup(kind_raw: u64, resource: u64) -> i64 {
    use azos_abi::error::Errno;

    if kind_raw > u8::MAX as u64 {
        return Errno::EINVAL.to_syscall_ret();
    }
    let kind = match CapType::from_raw(kind_raw as u8) {
        Some(k) => k,
        None => return Errno::EINVAL.to_syscall_ret(),
    };
    // An endpoint the kernel hosts is asked for by interface and resource:
    // `resource = host_key << 32 | badge` (`azos_devif::key`, the badge the
    // topology row stamped: a pin, a bus and an address, a wheel pair...).
    // The pool reference the table stores is the kernel's.
    if kind == ty::ENDPOINT && resource > u32::MAX as u64 {
        return cap_lookup_kernel_endpoint((resource >> 32) as u16, resource as u32);
    }
    if resource > u32::MAX as u64 {
        return Errno::EINVAL.to_syscall_ret();
    }
    // A `Shm` lookup may name a kernel-owned region by its key
    // (`SHM_INSPECT_*`, `SHM_INPUT_EVENTS`, `SHM_INPUT_FOCUS`, `SHM_CONSOLE_SCREEN`), since the
    // consumer cannot know the region's packed
    // reference; the table is then asked about that region.
    if kind == ty::SHM {
        return cap_lookup_shm(resource as u32);
    }
    cap_lookup_in_own_table(kind, resource as u32)
}

/// SYS_CAP_INFO of a kernel-hosted `Endpoint`: this task's capability to the
/// interface with host key `key` that carries `badge`.
#[inline(never)]
fn cap_lookup_kernel_endpoint(key: u16, badge: u32) -> i64 {
    use azos_abi::error::Errno;
    if key == 0 || (key as u64) >= azos_ipc::endpoint::KERNEL_HOST_KEYS as u64 {
        return Errno::EINVAL.to_syscall_ret();
    }
    let found = azos_ipc::cap_store::read_own_table(|t| {
        t.lookup_where(azos_abi::cap::ty::ENDPOINT, |r, b, _| {
            b == badge && azos_ipc::endpoint::host_key_of_ref(r) == Some(key)
        })
    });
    match found {
        Some(Some(h)) => h.as_raw() as i64,
        Some(None) => Errno::ENOENT.to_syscall_ret(),
        None => Errno::EINVAL.to_syscall_ret(),
    }
}

/// SYS_CAP_INFO of a `Shm`: the key may name a kernel-owned region. Out of
/// line so the common lookup keeps a small frame.
#[inline(never)]
fn cap_lookup_shm(resource: u32) -> i64 {
    let resource = azos_ipc::kregion::lookup_resource(azos_ipc::inspect_region::lookup_resource(resource));
    cap_lookup_in_own_table(azos_abi::cap::ty::SHM, resource)
}

#[inline(always)]
fn cap_lookup_in_own_table(kind: azos_abi::cap::CapType, resource: u32) -> i64 {
    use azos_abi::error::Errno;
    // N4: lock-free with Kconfig RCU_QSBR (`cap_store::read_own_table`).
    match azos_ipc::cap_store::read_own_table(|t| t.lookup(kind, resource)) {
        Some(Some(h)) => h.as_raw() as i64,
        // Holds no such capability. NOT recorded as a capability denial: a
        // program asking what it has is not a program reaching for what it
        // has not, and recording every miss would bury the real events under
        // ordinary discovery traffic — the same reasoning that keeps
        // `Contained` out of the recorder.
        Some(None) => Errno::ENOENT.to_syscall_ret(),
        None => Errno::EINVAL.to_syscall_ret(),
    }
}

// ── Former inline dispatch arms (wave 7) ─────────────────────────────────────
//
// The syscalls below were implemented inside `dispatch.rs`'s `match`, which no
// host test compiles. Their bodies moved here unchanged (owner decision round
// 7): same checks in the same order, same narrowing of each argument, same
// return codes. The ABI of each call is still documented at its arm.

// ── DNS (F05), 266 ───────────────────────────────────────────────────────────

// ── Device interrupts ─────────────────────────────────────────────────────────

/// `DEVICE_IRQ_ACK`: the line `irq` (its capability was checked) is
/// acknowledged by `tid`: the handler quietened its device, and the line may be
/// delivered again. 0 when it is, 1 when the handler's budget is spent and
/// the line stays masked until its reservation is replenished
/// (`irq_bind::irq_sc_throttle` unmasks it), `-ENOENT` when nobody binds it.
///
/// The unmask is the interrupt controller's, per ISA:
/// * riscv64: a line ring 3 bound was masked and completed by the
///   external-interrupt handler when it delivered it (mask-until-ACK,
///   `azos_drv_irqchip::user_irq`); the ACK is the unmask, and a level line
///   the driver has not quietened is delivered again at once.
/// * aarch64: `handle_irq` already EOId the line and masked it at the
///   distributor when it delivered it (mask-until-ACK, see `azos_arch::irq::gic`'s
///   ring-3 ownership section); the ACK is the unmask.
/// * x86_64: the IOAPIC entry `device` masked (`user_irq::unmask`).
pub fn sys_irq_ack(tid: u32, irq: u32) -> i64 {
    use azos_ipc::irq_bind::{irq_ack, Ack, MSI_LINE};
    match irq_ack(irq, tid) {
        Ack::NotBound => azos_abi::error::Errno::ENOENT.to_syscall_ret(),
        Ack::Held => 1,
        Ack::Unmask => {
            // A message-signalled slot has no controller input to unmask.
            if irq & MSI_LINE == 0 {
                arch_irq_unmask(irq);
            }
            0
        }
    }
}

/// The controller half of [`sys_irq_ack`].
fn arch_irq_unmask(irq: u32) {
    #[cfg(target_arch = "riscv64")]
    {
        if azos_drv_irqchip::user_irq::owned(irq) {
            // The hart that took the line's first delivery since its bind
            // (wave 10 IRQ5), once per bind: the `riscv64 ring-3 irq` row
            // compares it with the route and the owner's pin.
            if let Some(taken) = azos_drv_irqchip::user_irq::first_delivery(irq) {
                azos_drv_sys::kprintln!(
                    "[IRQ] ring-3 line {} taken on hart {} (routed to hart {})",
                    irq, taken,
                    azos_drv_irqchip::user_irq::routed_hart(irq).map_or(-1, |h| h as i64));
            }
            // Canary: an ACK that does not unmask (see the aarch64 arm).
            #[cfg(not(feature = "irq-ack-canary"))]
            azos_drv_irqchip::user_irq::unmask(irq);
        }
    }
    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    {
        if azos_arch::irq::gic::user_spi_owned(irq) {
            // Canary: an ACK that does not unmask. The second interrupt of
            // `userspace/tests/captest`'s IRQ section never arrives.
            #[cfg(not(feature = "irq-ack-canary"))]
            azos_arch::irq::gic::enable_spi(irq);
        }
    }
    #[cfg(all(target_os = "none", not(any(target_arch = "riscv64", target_arch = "aarch64"))))]
    {
        if azos_drv_irqchip::user_irq::owned(irq) {
            #[cfg(not(feature = "irq-ack-canary"))]
            azos_drv_irqchip::user_irq::unmask(irq);
        }
    }
    #[cfg(not(any(target_arch = "riscv64", target_os = "none")))]
    {
        let _ = irq;
    }
}

/// Whether this ISA's interrupt controller can hand `irq` to ring 3, checked
/// before a binding is stored. aarch64: an SPI the kernel did not route for
/// itself (`azos_arch::irq::gic::user_spi_bindable`). riscv64: a source the
/// kernel did not enable for itself (`azos_drv_irqchip::user_irq::bindable`;
/// wave 9 IRQ4 — it used to take any line the capability named, the
/// console's included). Host test builds take any line.
#[inline]
pub(crate) fn arch_irq_bindable(irq: u32) -> bool {
    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    {
        azos_arch::irq::gic::user_spi_bindable(irq)
    }
    #[cfg(target_arch = "riscv64")]
    {
        azos_drv_irqchip::user_irq::bindable(irq)
    }
    #[cfg(not(any(target_arch = "riscv64", all(target_arch = "aarch64", target_os = "none"))))]
    {
        let _ = irq;
        true
    }
}

/// After a binding of `irq` was stored: route/enable the line on CPU `cpu`
/// with the trigger the device tree gave it, and from then on the
/// external-interrupt handler delivers it mask-until-ACK. `false` when the
/// interrupt controller cannot deliver the line; the caller then undoes the
/// binding ([`route_stored_binding`]).
///
/// aarch64: GIC SPI (`gic::user_spi_bind`) routed to the affinity of CPU
/// `cpu` (`azos_arch::cpu::cpu_mpidr`; a CPU that has not come up falls
/// back to the binding PE); refused for an SPI past the distributor's
/// `GICD_TYPER.ITLinesNumber`.
///
/// riscv64 (wave 10 IRQ5): hart `cpu` if it takes external interrupts, else
/// the boot hart (`user_irq::target_hart`); a line bound before on another
/// hart moves (`user_irq::bind`). Refused for a PLIC source the boot probe
/// found unimplemented, an APLIC source past `riscv,num-sources`, or one the
/// firmware did not delegate.
///
/// x86_64: the IOAPIC entry, delivered to CPU `cpu`'s LAPIC.
#[inline]
pub(crate) fn arch_irq_bound(irq: u32, cpu: u32) -> bool {
    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    {
        let mpidr = azos_arch::cpu::cpu_mpidr(cpu as usize)
            .unwrap_or_else(|| azos_arch::cpu::read_mpidr().raw);
        azos_arch::irq::gic::user_spi_bind(irq, mpidr)
    }
    #[cfg(target_arch = "riscv64")]
    {
        use azos_drv_irqchip::user_irq;
        let tid = azos_sched::current_task_tid();
        let here = azos_arch::Cpu::hart_id(&azos_arch::ARCH) as u32;
        #[cfg(not(feature = "irq-route-canary"))]
        let hart = user_irq::target_hart(cpu.min(i8::MAX as u32) as i8, here);
        // Canary: the old rule, every ring-3 line on the boot hart.
        #[cfg(feature = "irq-route-canary")]
        let hart = {
            let _ = (cpu, here);
            user_irq::boot_hart()
        };
        let before = user_irq::routed_hart(irq);
        if !user_irq::bind(irq, hart, user_irq::dtb_trigger(irq)) {
            return false;
        }
        if before != Some(hart) {
            azos_drv_sys::kprintln!(
                "[IRQ] ring-3 line {} -> hart {} (owner tid {}, pinned {}, was {})",
                irq, hart, tid, azos_sched::task_cpu_affinity(tid).unwrap_or(-1),
                before.map_or(-1, |h| h as i64));
        }
        true
    }
    #[cfg(all(target_os = "none", not(any(target_arch = "riscv64", target_arch = "aarch64"))))]
    {
        azos_drv_irqchip::user_irq::bind(irq, cpu, azos_drv_irqchip::user_irq::dtb_trigger(irq))
    }
    #[cfg(not(target_os = "none"))]
    {
        let _ = (irq, cpu);
        true
    }
}

/// CPU hotplug (`azos_sched::smp::set_irq_move_hook`): the interrupts bound to
/// CPU `from` go to `to` through the same controller programming a bind uses
/// ([`arch_irq_bound`]), or, with `back`, return to `from` when the topology's
/// `[sched] irq_return` asks. Answers lines, MSI vectors and refusals.
pub fn irq_move_hook(from: u32, to: u32, back: bool) -> (usize, usize, usize) {
    if back && !azos_topology::get().is_some_and(|t| t.sched_config().irq_return) {
        return (0, 0, 0);
    }
    let m = azos_ipc::irq_bind::irq_move_cpu(from, to, back, arch_irq_bound);
    (m.lines, m.msis, m.failed)
}

/// Route the binding of `irq` that `tid` just stored ([`arch_irq_bound`]);
/// when the controller refuses the line, drop that binding again
/// (`irq_bind::irq_unbind`) and answer `false`: the bind (`PORT_SRC_IRQ`) then returns
/// `-ENODEV`. The store comes first and the route after it for the release
/// ordering `irq_unbind_all` documents.
pub(crate) fn route_stored_binding(irq: u32, tid: u32, cpu: u32) -> bool {
    route_stored_binding_with(irq, tid, |irq| arch_irq_bound(irq, cpu))
}

fn route_stored_binding_with(irq: u32, tid: u32, route: impl FnOnce(u32) -> bool) -> bool {
    if route(irq) {
        return true;
    }
    let _ = azos_ipc::irq_bind::irq_unbind(irq, tid);
    // Read back after the undo, not assumed: captest's refusal row checks 0.
    azos_drv_sys::kwarn!(
        "[IRQ] ring-3 line {} refused by the interrupt controller (tid {}): -ENODEV, bindings left on the line: {}",
        irq, tid, azos_ipc::irq_bind::irq_bindings_of(irq));
    false
}

// ── IRQ binding (L5) ─────────────────────────────────────────────────────────

/// `PORT_BIND_F_REMOVE` of an interrupt line: `tid`'s binding of `irq` (its
/// capability was checked) goes, the line is handed back masked, and the port
/// gets a `PORT_EVENT_SOURCE_GONE`. 0, or `-ENOENT` when `tid` binds none.
pub fn sys_irq_unbind(tid: u32, irq: u32) -> i64 {
    if azos_ipc::irq_bind::irq_remove(irq, tid) {
        0
    } else {
        azos_abi::error::Errno::ENOENT.to_syscall_ret()
    }
}

/// The CPU a line bound to a port (`PORT_SRC_IRQ`) is routed to when the caller does not say:
/// the task's pin, else the CPU it binds from.
fn default_irq_cpu(tid: u32) -> u32 {
    match azos_sched::task_cpu_affinity(tid) {
        Some(pin) if pin >= 0 => pin as u32,
        // percpu-hint: the CPU a ring-3 line is routed to when the caller does not say: a placement default, the line can be rebound
        _ => azos_sched::smp::current_cpu_id() as u32,
    }
}

/// `PORT_BIND` of a line (`PORT_SRC_IRQ`): the caller `tid` binds line `irq` (its capability was
/// checked) to the port the packed reference `port_ref` names (its
/// capability was checked, `WRITE`), with event key `key`, routed to CPU
/// `cpu_word` ([`DEVICE_IRQ_CPU_ANY`](azos_abi::invoke::DEVICE_IRQ_CPU_ANY):
/// let the kernel choose). Returns the CPU the line goes to, or a negative
/// errno: `-EINVAL` for a line this ISA cannot hand to ring 3 or a CPU that
/// is not online (or, with `IRQ_THREADED`, not the one the reservation runs
/// on), `-EPERM` for a handler with no hard reservation (`IRQ_THREADED`),
/// `-EBUSY` for a line another task binds, `-ECAPSTALE` when the port was
/// destroyed since its capability was read, `-EMFILE` when the binding table
/// is full, and `-ENODEV` (nothing bound) when the interrupt controller
/// cannot deliver the line ([`route_stored_binding`]) or the platform has no
/// MSI for an `msi.<k>` slot. A message-signalled slot also fills `msg` with
/// the message the device must write.
pub fn sys_irq_bind(
    tid: u32, irq: u32, port_ref: u32, key: u64, cpu_word: u64,
    msg: &mut Option<azos_ipc::irq_bind::Msi>,
) -> i64 {
    use azos_abi::error::Errno;
    use azos_ipc::irq_bind::{irq_bind_port, irq_hold_lines, BindError, Route, MSI_LINE};
    // A message-signalled slot has no controller input to check or route.
    let msi = irq & MSI_LINE != 0;
    if !msi && !arch_irq_bindable(irq) {
        return Errno::EINVAL.to_syscall_ret();
    }
    let route = if cpu_word == azos_abi::invoke::DEVICE_IRQ_CPU_ANY {
        Route::Any(default_irq_cpu(tid))
    } else if cpu_word < azos_sched::smp::NUM_ONLINE_CPUS.load(core::sync::atomic::Ordering::Acquire) as u64 {
        Route::Cpu(cpu_word as u32)
    } else {
        return Errno::EINVAL.to_syscall_ret();
    };
    match irq_bind_port(irq, tid, port_ref, key, route) {
        Ok(bound) => {
            if !msi && !route_stored_binding(irq, tid, bound.cpu) {
                return Errno::ENODEV.to_syscall_ret();
            }
            // The reservation was throttled while the bind ran: the line is
            // masked now that it is routed, not left live (no overrun to
            // record: it happened before the bind).
            if bound.throttled {
                irq_hold_lines(tid);
            }
            *msg = bound.msi;
            bound.cpu as i64
        }
        Err(BindError::Port(e)) => crate::ipc_handlers::errno_for_port_err(e),
        Err(BindError::Budget(_)) => Errno::EPERM.to_syscall_ret(),
        Err(BindError::Route) => Errno::EINVAL.to_syscall_ret(),
        Err(BindError::Busy) => Errno::EBUSY.to_syscall_ret(),
        Err(BindError::NoMsi) => Errno::ENODEV.to_syscall_ret(),
    }
}

// ── Trace (AQ8), 518 ─────────────────────────────────────────────────────────

// ── Stubs for unimplemented subsystems ───────────────────────────────────────

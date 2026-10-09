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

#[cfg(not(feature = "domain-robot"))]
use crate::no_robot::{robot as azos_robot, imu as azos_imu, gps as azos_gps};
use crate::file_ops::{cstr_to_bytes, file_ops};
use azos_sync::pi_mutex::PiMutex;
use azos_ipc::{signal_send, signal_pending, signal_set_handler, signal_get_mask, signal_set_mask,
                   pipe_create};
use azos_service::{service_register, service_discover, service_stop_as, service_heartbeat_as,
    SERVICE_NOT_OWNER};
use azos_drv_gpio::gpio::{gpio_read, gpio_write, gpio_set_direction, gpio_info, GpioDir};
use azos_drv_actuator::pwm::pwm_info;
use azos_drv_bus::i2c::{i2c_scan, i2c_info};
use azos_robot::{motor_init, motor_info, MotorDir, motor_set_reporting, motor_stop_reporting};
use azos_net::{
    socket_bind,
    socket_listen_bound,
    socket_create_owned, socket_accept_owned,
    socket_recv, socket_close,
    SockAddr, net_info, net_get_ip,
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
/// call resolves against (RFC-0040 gap 1, stage 2). Before, it came from the
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
/// No packed kind (Channel, Port, Shm, IoRing) is asked here: the presence
/// check refuses those.
pub fn cap_check(kind: azos_abi::cap::CapKind, resource: u32, need_write: bool) -> bool {
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

/// The object a `SAFETY_CAP_DENIED` record names, as one number.
///
/// The record format is frozen: a recording made by an older build must still
/// decode. So this reproduces what the record has always carried. An I2C
/// capability stores `bus << 8 | addr` (`i2c_cap.rs`) and the record keeps the
/// bus alone; the kinds that name no object (Buzzer, Power, Disk, NetConfig)
/// record 0; an MmioRegion capability stores an index into the board's MMIO
/// region table (RFC-0043) and the record keeps the region's base, 0 for an
/// index outside the table; every other kind records its resource.
pub(crate) const fn denial_target(kind: azos_abi::cap::CapKind, resource: u32) -> u32 {
    use azos_abi::cap::CapKind;
    match kind {
        CapKind::I2c => resource >> 8,
        CapKind::MmioRegion => azos_drv_base::platform::mmio_region_record_base(resource),
        CapKind::Buzzer | CapKind::Power | CapKind::Disk | CapKind::NetConfig => 0,
        _ => resource,
    }
}

/// Where a capability denial goes, installed by the kernel at boot.
///
/// # Why a hook and not a call
///
/// The flight recorder lives in `domains/robot/behavior` and this crate does not
/// depend on it — `behavior` is above `syscall` in the graph, and the edge
/// would close a cycle. Same seam, same reason, as `MotorGate` in
/// `domains/robot/robot` and `FileOps` for the TCB split: the kernel is the one place
/// that can see both sides, so it is the place that wires them.
///
/// `None` until `set_cap_deny_recorder` runs, which makes the pre-boot window
/// silent rather than a null call.
static CAP_DENY_RECORDER: azos_sync::SpinLock<Option<fn(u8, u32, bool)>> =
    azos_sync::SpinLock::new(None);

/// Install the capability-denial recorder. Called once at boot.
pub fn set_cap_deny_recorder(f: fn(kind_code: u8, target: u32, need_write: bool)) {
    *CAP_DENY_RECORDER.lock() = Some(f);
}

/// Where a ring-3 emergency stop is carried out, installed by the kernel at
/// boot.
///
/// Same seam and the same reason as `CAP_DENY_RECORDER` above: latching the
/// e-stop lives in `domains/robot/behavior`, disarming the ESC in `domains/robot/drivers`,
/// and the durable record in the flight recorder — all above this crate in the
/// graph, so the kernel is the one place that can see both sides.
///
/// **`None` fails CLOSED here, not silently.** A missing denial recorder costs
/// a log line; a missing e-stop handler would mean returning success for an
/// emergency that nothing carried out, which is the worst answer this call can
/// give. `sys_robot_estop` reports the failure to the caller instead.
static ESTOP_HANDLER: azos_sync::SpinLock<Option<fn()>> =
    azos_sync::SpinLock::new(None);

/// Install the emergency-stop handler. Called once at boot.
pub fn set_estop_handler(f: fn()) {
    *ESTOP_HANDLER.lock() = Some(f);
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
fn record_cap_denial(kind: azos_abi::cap::CapKind, resource: u32, need_write: bool) {
    let r = *CAP_DENY_RECORDER.lock();
    if let Some(f) = r {
        let code = kind.denial_code();
        // Only spent when there is a recorder to spend it on.
        if admit_denial_record(code) {
            f(code, denial_target(kind, resource), need_write);
            note_denial_recorded(azos_sched::current_task_tid());
        }
    }
}

/// The TID of the last task whose capability denial reached the flight
/// recorder (0: none since it was last taken). The Linux personality takes it
/// after a native call it translated was refused, to report whether the
/// refusal was recorded (RFC-0047: "a Linux call outside the image's caps is
/// refused and recorded"). A hint for that report only, never a decision.
static LAST_DENIAL_RECORDED_TID: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

fn note_denial_recorded(tid: u32) {
    LAST_DENIAL_RECORDED_TID.store(tid, core::sync::atomic::Ordering::Relaxed);
}

/// Was the last recorded capability denial task `tid`'s? Clears the mark.
pub(crate) fn take_denial_recorded_for(tid: u32) -> bool {
    LAST_DENIAL_RECORDED_TID
        .compare_exchange(tid, 0, core::sync::atomic::Ordering::Relaxed, core::sync::atomic::Ordering::Relaxed)
        .is_ok()
}

/// Where a TYPED capability denial goes, installed by the kernel at boot.
///
/// A second hook rather than a second argument on the first: the two records
/// carry different things (`SAFETY_CAP_DENIED` a measured object and write
/// bit, `SAFETY_CAP_DENIED_TYPED` a reason) and giving them one signature
/// would mean every call site passing a placeholder for the half it does not
/// have. See `crates/core/actuation/src/logger.rs`.
static CAP_DENY_TYPED_RECORDER: azos_sync::SpinLock<Option<fn(u8, u32)>> =
    azos_sync::SpinLock::new(None);

/// RFC-0049 M1: the budget of the topology row named after an image, if it
/// has one (`topo_sched::exec_mem_for`), installed by the kernel at boot. A
/// seam rather than a direct call so this file carries no topology lookup of
/// its own; unset, a ring-3 exec keeps the caller's budget.
static EXEC_MEM_RESOLVER: azos_sync::SpinLock<Option<fn(&'static str) -> Option<azos_sched::MemSpec>>> =
    azos_sync::SpinLock::new(None);

/// RFC-0047: does the topology row named after an image say `abi = "linux"`
/// (`crate::linux::row_is_linux`), installed by the kernel at boot. A seam
/// for the reason `EXEC_MEM_RESOLVER` is one; unset, exec refuses no image
/// for its ABI (no topology, so no Linux row either).
static EXEC_LINUX_ROW: azos_sync::SpinLock<Option<fn(&str) -> bool>> =
    azos_sync::SpinLock::new(None);

/// Install the Linux-row check exec applies. Called once at boot.
pub fn set_exec_linux_row(f: fn(&str) -> bool) {
    *EXEC_LINUX_ROW.lock() = Some(f);
}

/// Install the exec budget resolver. Called once at boot.
pub fn set_exec_mem_resolver(f: fn(&'static str) -> Option<azos_sched::MemSpec>) {
    *EXEC_MEM_RESOLVER.lock() = Some(f);
}

/// Install the typed-capability-denial recorder. Called once at boot.
pub fn set_cap_deny_typed_recorder(f: fn(kind_code: u8, reason_code: u32)) {
    *CAP_DENY_TYPED_RECORDER.lock() = Some(f);
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
pub(crate) fn note_typed_denial(kind: azos_abi::cap::CapKind, e: azos_ipc::cap::CapError) {
    note_typed_denial_for(azos_sched::current_task_tid(), kind, e);
}

/// [`note_typed_denial`] on behalf of task `tid`, whose per-task bound the
/// record is charged to.
///
/// For the io_ring op table (`crate::ioring_ops`): an entry is authorized by
/// the ring's OWNER, so its refusal is the owner's, whichever context runs the
/// pass. The record itself is the same record; only the bound it counts
/// against is named explicitly instead of read from the running task.
pub(crate) fn note_typed_denial_for(tid: u32, kind: azos_abi::cap::CapKind, e: azos_ipc::cap::CapError) {
    let _ = note_typed_denial_recorded(tid, kind, e);
}

/// [`note_typed_denial_for`], answering whether a record was handed to the
/// recorder: `false` for a non-denial, no recorder installed, or a record
/// the per-task bound suppressed (it is counted in the window's summary
/// instead). A caller that prints "recorded" prints it only on `true`.
pub(crate) fn note_typed_denial_recorded(tid: u32, kind: azos_abi::cap::CapKind, e: azos_ipc::cap::CapError) -> bool {
    if !e.is_denial() {
        return false;
    }
    let r = *CAP_DENY_TYPED_RECORDER.lock();
    if let Some(f) = r {
        if admit_denial_record_for(tid, kind.denial_code()) {
            f(kind.denial_code(), e.code());
            // Kconfig DECISION_RECORDS: the same denial, under the same
            // per-task bound, as an explained decision. Off: nothing.
            azos_decision::record(
                azos_decision::Rule::CapDenial,
                azos_decision::Verdict::Deny,
                tid,
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

/// Where an audited syscall is recorded, installed by the kernel at boot. A hook
/// for the reason `CAP_DENY_RECORDER` is one.
static SECCOMP_AUDIT_RECORDER: azos_sync::SpinLock<Option<fn(u16)>> =
    azos_sync::SpinLock::new(None);

/// Install the seccomp audit recorder. Called once at boot.
pub fn set_seccomp_audit_recorder(f: fn(syscall_nr: u16)) {
    *SECCOMP_AUDIT_RECORDER.lock() = Some(f);
}

/// Uninstall the seccomp audit recorder. Host tests only: it is a process static
/// the next test would inherit.
#[cfg(test)]
pub fn __seccomp_audit_recorder_clear_for_tests() {
    *SECCOMP_AUDIT_RECORDER.lock() = None;
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
    let r = *SECCOMP_AUDIT_RECORDER.lock();
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
/// that by source text, the same pattern `exec_binding.rs` already uses for
/// `sys_exec`/`sys_execpath`).
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
    // RFC-0055: a forced stop (`SYS_TASK_KILL`) empties the target's filter so
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
    // `tools/ci_check.sh`'s three seccomp rows key on `uhello`'s old line
    // and need a new one to grep; this is the replacement (see the report
    // for the exact rows and why this line's shape was chosen to be
    // greppable per-row: tid identifies WHICH task, `num` WHICH syscall).
    azos_drv_sys::kwarn!(
        "[SECCOMP] tid={} killed: syscall {} not in its profile",
        azos_sched::current_task_tid(), num,
    );
    azos_sched::scheduler::task_exit_by_signal(SECCOMP_KILL_EXIT_CODE)
}

/// The forced-stop half of [`seccomp_deny_kill`] (RFC-0055): end the task
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

/// Is this untyped write refused by degraded-mode containment (RFC-0036)?
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
/// layer instead (`motor_rc_ret`). The twins are listed in
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

/// `SYS_DRV_IRQ_WAIT`'s return value, as a pure function of whether the block
/// actually happened.
///
/// # Why this is a function and not two lines in the dispatch arm
///
/// `dispatch.rs` cannot be compiled on the host (see this crate's own test
/// runner in `tests/host/syscall-tests`, which pulls *this* file). The decision
/// that matters — "a refusal must not be reported as a fired interrupt" — is
/// pure, so it lives here where a host test can call it with both inputs and
/// see the two answers differ. Same split, and the same reason, as
/// `wait.rs`'s `wake_action` and `preempt_core.rs`'s `voluntary_admission`.
///
/// # Why `EAGAIN` and not a new errno
///
/// `SYS_DRV_IRQ_WAIT` has nothing to re-test. There is no per-`(tid, irq)`
/// pending count anywhere in the tree: `wake_by_irq` sweeps for tasks already
/// blocked on `WaitReason::Irq(n)` and `irq_bind`'s `WakeTask` arm is an
/// explicit no-op that defers to that sweep. So when K-C29 refuses to park the
/// caller, the kernel cannot answer "did my interrupt fire" at all — the only
/// honest answer is "the wait did not happen, ask again", which is exactly
/// `EAGAIN`. It is already in the frozen table (`azos_abi::error::Errno`),
/// so this introduces no new number and cannot drift from it.
///
/// **`Returned` must map to 0 and `Refused` must not.** Reporting 0 on a
/// refusal tells a userspace driver its device raised an interrupt when
/// nothing did; the driver then reads and acks hardware state that never
/// changed. That is the whole point of this function.
#[inline]
pub(crate) const fn irq_wait_ret(outcome: azos_sched::BlockOutcome) -> i64 {
    match outcome {
        azos_sched::BlockOutcome::Returned => 0,
        azos_sched::BlockOutcome::Refused => {
            azos_abi::error::Errno::EAGAIN.to_syscall_ret()
        }
    }
}

/// `SYS_DRV_IRQ_WAIT`'s return value for a caller that holds a wake-task
/// binding of the line: 0 exactly when the wait consumed a delivery
/// (`irq_bind::irq_wait_end`), -EAGAIN otherwise.
///
/// Unlike [`irq_wait_ret`] this does not look at the block's outcome. The
/// binding's pending bit IS the per-`(tid, irq)` record that function says
/// the tree lacks, so the answer is re-tested rather than inferred: a block
/// the kernel refused (K-C29) after the line fired still reports the fired
/// line, and a block that returned for another reason (a stale stamp) is a
/// retry, not a false "your interrupt fired".
#[inline]
pub(crate) const fn irq_wait_bound_ret(consumed: bool) -> i64 {
    if consumed {
        0
    } else {
        azos_abi::error::Errno::EAGAIN.to_syscall_ret()
    }
}

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

// ── ELF bounce buffer for SYS_EXEC / SYS_EXECPATH ────────────────────────────
//
// Largest ELF the tree currently produces is ~12.5 KiB (`build/brain_client.elf`);
// 128 KiB leaves an order of magnitude of headroom while staying far cheaper in
// `.bss` than the shell's 256 KiB buffer (which VF2/K1 linker scripts also pay
// for).
const EXEC_MAX_BYTES: usize = 128 * 1024;

/// Shared kernel bounce buffer for both exec syscalls and SYS_SPAWN.
///
/// WHY it exists:
///   - `SYS_EXEC` used to build a slice straight off the user-supplied
///     `(ptr, len)` pair with `from_raw_parts`.  `sstatus.SUM` is never set in
///     this tree, so S-mode cannot read a USER page at all: the old code was
///     only ever "functional" for kernel/MMIO addresses (an ELF-parser oracle
///     over kernel memory) and took a fatal, unrecoverable S-mode load fault —
///     i.e. a board reset — for any honest user pointer.  Routing through
///     `copy_from_user` walks `vmm::translate_user`, which enforces
///     VALID+USER+READ at every leaf level and rejects kernel/MMIO outright.
///   - `SYS_EXECPATH` used to `Vec::extend_from_slice` the whole file with no
///     total cap.  A large file on the FAT32 image exhausted the kernel heap;
///     the allocation error path panics, and `panic = "abort"` turns that into
///     a reset.  A fixed static cannot exhaust anything.
///
/// A `PiMutex`, same reasoning as `KERNEL_FD_TABLE` and as `CAM_BUF` in
/// `sensor_read_dispatch`.
///
/// What it protects, and for how long: exactly the shared BUFFER — two harts
/// exec'ing at once must not interleave their ELF bytes; the hand-off itself
/// is per-task since K-C21 and needs no serialisation here. Both callers hold
/// it across `exec_user` (SYS_SPAWN across `spawn_prepare`), which returns normally (it publishes the exec
/// hand-off on the caller's own task rather than switching away), so the guard
/// always drops. That hold duration is not the problem, and is orthogonal to
/// the lock type: what the section must not be is non-preemptible while it
/// lasts.
///
/// Held across `copy_from_user` of up to 128 KiB AND the whole of `exec_user`,
/// which parses the ELF and builds the new address space — nesting `PMM`'s own
/// lock once per mapped page. Since K-C29 step 2 (`eeda7c4`) a `SpinLock`
/// section is non-preemptible, so holding one here would make `SYS_EXEC` and
/// `SYS_EXECPATH` a real-time latency floor measured in whole ELF loads.
///
/// Bounded rather than unbounded — there is no disk I/O inside this particular
/// section, `sys_execpath` having already read the file before taking it — but
/// bounded at 128 KiB of copying plus a page-table build is not a bound worth
/// having on a hart that also runs a 1 kHz loop.
///
/// 8-aligned (wave 14): the image is hashed in place, and SHA-256 takes word
/// loads only from an aligned start (Zbb: ~190 instructions a block fewer
/// than byte loads). As a bare `[u8; N]` inside the mutex its start had no
/// alignment, and the spawn census measured the odd-start rate.
pub(crate) static EXEC_BOUNCE: PiMutex<ExecBounce> = PiMutex::new(ExecBounce([0u8; EXEC_MAX_BYTES]));

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
// It used to live here, as `static KERNEL_FD_TABLE: PiMutex<FdTable>`. It now
// lives in `kernel/src/boot/seams.rs` inside `KernelFileOps`, together with the doc
// comment explaining why it is a `PiMutex` and not a `SpinLock` — that
// reasoning is about holding a lock across a real FAT32 read, which is the
// implementation's problem and not this crate's.
//
// This crate no longer knows that descriptors are indices into a table, or
// that a table exists. That is the point: a `FileOps` in a signature here
// would have kept the filesystem's descriptor model inside the TCB behind an
// interface, which satisfies `tcb_check.sh` without making the partition true.

// ── Console I/O ───────────────────────────────────────────────────────────────

pub fn sys_test() -> i64 {
    azos_drv_sys::uart::puts_locked("[SYSCALL] test ok\n");
    0
}

/// One byte from ring 3: the same console path as `sys_write` to fd 1/2
/// (line lock, ownership, TX ring), not the lock-free `uart::putc` it used
/// to be, which could land inside another writer's line.
pub fn sys_putchar(c: u64) -> i64 {
    azos_drv_sys::uart::console_write_ring3(&[c as u8]);
    0
}

pub fn sys_getchar() -> i64 {
    if azos_drv_sys::uart::can_read() {
        azos_drv_sys::uart::getc() as i64
    } else {
        -1
    }
}

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
    // (owner decision, round 49; RFC-0040 gap 3 for descriptors). Its files
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
        fork_regions_to_child(child) && crate::natfork::native_child_setup(parent, child)
    })
}
/// Reap a finished child. Returns its TID, or -1 if none has finished.
///
/// **`WNOHANG` semantics, not POSIX `wait`.** It does not block: the caller
/// polls. Blocking would need a wait queue and a wake of the parent from the
/// exit path, and that touches the scheduler; this version delivers the useful
/// half — knowing a child finished — without that risk.
///
/// **The exit code is not returned by THIS call**, which is a different
/// statement from the one that stood here. That version read "the exit code
/// is not returned yet ... adding one is an ABI change and a separate
/// decision" — and the decision was taken and implemented on 2026-09-07, four
/// lines below, as [`sys_wait_status`] (`SYS_WAIT_STATUS`, 559). A doc comment
/// describing a gap that the next function in the file closes is how a reader
/// concludes the capability does not exist.
pub fn sys_wait() -> i64 {
    let me = azos_sched::current_proc_tid(); // wave 13: the process's children
    match azos_sched::take_exit_note(me) {
        // The exit code is available here and deliberately dropped: this
        // syscall's return value is one `i64` and it already carries the TID.
        // `SYS_WAIT_STATUS` (559) is the form that reports both.
        Some((child_tid, _code)) => child_tid as i64,
        None => -1,
    }
}

/// `SYS_WAITPID` (562): a0 = child TID, a1 = `*mut i32` for the exit code, or 0.
///
/// Reaps THAT child. Returns its TID; `-1` if it is alive; `-ECHILD` if it is
/// not a child of the caller or was already reaped; `-EFAULT` if the status
/// pointer is unwritable.
///
/// # The three answers are three answers
///
/// `SYS_WAIT` and `SYS_WAIT_STATUS` return the first finished child, so `-1`
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
    let bytes = code.to_le_bytes();
    if !azos_sched::copy_to_user(status_ptr as usize, bytes.as_ptr(), 4) {
        return Errno::EFAULT.to_syscall_ret();
    }
    reaped as i64
}

/// `SYS_EXIT_STATS` (605): a0 = an `EXIT_STAT_*` selector. Returns that
/// exit-path counter (`azos_sched::exit_stat`), or `-EINVAL`.
pub fn sys_exit_stats(which: u64) -> i64 {
    if which == azos_abi::syscall_nr::EXIT_STAT_LEASE_REVOKED_FAULTS {
        return azos_ipc::lease::lease_revoked_faults() as i64;
    }
    if which == azos_abi::syscall_nr::EXIT_STAT_LEASE_SEAL_FAULTS {
        return azos_ipc::lease::lease_seal_faults() as i64;
    }
    match azos_sched::exit_stat(which) {
        Some(n) => n as i64,
        None => azos_abi::error::Errno::EINVAL.to_syscall_ret(),
    }
}

/// `SYS_WAIT_STATUS` (559): a0 = `*mut i32` for the exit code, or 0.
///
/// Reaps one finished child, writes its exit code through `a0` when that
/// pointer is non-null, and returns the child's TID. `-1` when nothing has
/// finished — `WNOHANG`, exactly like `SYS_WAIT`.
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
    // to get `SYS_WAIT`'s behaviour from this number.
    if status_ptr == 0 {
        return child_tid as i64;
    }
    let bytes = code.to_le_bytes();
    if !azos_sched::copy_to_user(status_ptr as usize, bytes.as_ptr(), 4) {
        return Errno::EFAULT.to_syscall_ret();
    }
    child_tid as i64
}

// ── Exec: only images a seccomp profile is bound to ───────────────────────
//
// The seccomp image table (`crates/core/sched/src/seccomp.rs`, `IMAGE_SHA256`) is a
// whitelist of user images (owner decision 2026-09-14): an image whose SHA-256
// no profile is bound to is not exec'd on any path. The autorun loader and the
// shell refuse it in the kernel; `sys_exec` and `sys_execpath` refuse it for
// ring 3, with `EACCES`. Neither handler writes the caller's filter: a confined
// task that execs a bound image keeps the filter it had (`exec_user` never
// writes it either).

/// `SAFETY_EXEC_REFUSED` action code for a refused ring-3 `SYS_EXEC` or
/// `SYS_EXECPATH`. The autorun loader writes 0, the shell 1.
pub const EXEC_REFUSED_ACTION_RING3: u8 = 2;

/// The action code of a `SAFETY_CAP_DENIED_SUPPRESSED` record whose suppressed
/// records were all ring-3 exec refusals. Outside the frozen kind numbering,
/// like `DENIAL_KIND_MIXED`.
pub const DENIAL_KIND_EXEC_REFUSED: u8 = 0xFD;

/// Where a refused ring-3 exec is recorded, installed by the kernel at boot. A
/// hook for the reason `CAP_DENY_RECORDER` is one.
static EXEC_REFUSED_RECORDER: azos_sync::SpinLock<Option<fn(u8, u32)>> =
    azos_sync::SpinLock::new(None);

/// Install the exec-refusal recorder. Called once at boot.
pub fn set_exec_refused_recorder(f: fn(action_code: u8, digest_head: u32)) {
    *EXEC_REFUSED_RECORDER.lock() = Some(f);
}

/// Uninstall the exec-refusal recorder. Host tests only.
#[cfg(test)]
pub fn __exec_refused_recorder_clear_for_tests() {
    *EXEC_REFUSED_RECORDER.lock() = None;
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
/// computed. `exec_bound_image` needs the digest again after a successful
/// exec (U07-3, to look up the image's own filter) — without this split it
/// would call `seccomp::image_digest` (one SHA-256 pass over up to
/// `EXEC_MAX_BYTES` of image, `EXEC_BOUNCE.lock()` held, preemption off per
/// K-C29) TWICE per exec instead of once. `exec_image_is_bound`'s signature
/// stays `(elf) -> bool` so its other two callers (`spawn.rs:56`, the host
/// test at `unit6_contain.rs:852`) do not move.
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
    let r = *EXEC_REFUSED_RECORDER.lock();
    if let Some(f) = r {
        if admit_denial_record(DENIAL_KIND_EXEC_REFUSED) {
            f(action_code, digest_head);
            return true;
        }
    }
    false
}

/// SYS_EXEC: a0 = pointer to ELF data in kernel memory (for now).
///
/// In a real system a0 would be a user-space path string, but for Phase 7 we
/// accept a raw `(ptr, len)` pair: a0 = data pointer, a1 = byte length.
/// The ELF is loaded into a new user address space.  On success the
/// trap_handler will switch to U-mode on SRET. An image no seccomp profile is
/// bound to is refused with `EACCES` before it is parsed.
pub fn sys_exec(data_ptr: u64, len: u64) -> i64 {
    if data_ptr == 0 || len == 0 { return -1; }
    // Reject before copying rather than truncating: a silently-clipped ELF
    // would be parsed as a corrupt image and the failure would be reported as
    // "bad ELF" instead of "too large".
    let len = len as usize;
    if len > EXEC_MAX_BYTES { return -1; }
    if let Err(e) = exec_validate_late_canary() { return e; }

    let mut buf = EXEC_BOUNCE.lock();
    // `copy_from_user` validates the whole range page by page through
    // `vmm::translate_user` (VALID+USER+READ), so a kernel/MMIO pointer is
    // rejected here instead of being dereferenced.  See EXEC_BOUNCE above.
    if !azos_sched::copy_from_user(buf.as_mut_ptr(), data_ptr as usize, len) {
        return -1;
    }
    let prepared = exec_bound_image(&buf[..len]);
    drop(buf);
    match prepared {
        Ok((p, digest)) => exec_finish(p, &digest),
        Err(e) => e,
    }
}

/// Gate canary `exec-validate-late-canary` only: the other threads are ended
/// before the image is read and checked, as before wave 15's follow-up, so a
/// failing exec leaves the process with one thread.
fn exec_validate_late_canary() -> Result<(), i64> {
    if cfg!(feature = "exec-validate-late-canary") {
        exec_end_other_threads().map_err(exec_dethread_errno)?;
    }
    Ok(())
}

/// The commit of a native exec that passed every check
/// (`exec_bound_image_digest`): end the other threads, switch to the new
/// image, install its row's filter, and let go of what the old image held in
/// user space. `EINTR` (the new image given back, the process untouched but
/// for the threads already asked to stop) when the process is ending.
fn exec_finish(prepared: azos_sched::process::PreparedExec, digest: &[u8; 32]) -> i64 {
    if let Err(e) = exec_end_other_threads() {
        azos_sched::process::exec_abort(prepared);
        return exec_dethread_errno(e);
    }
    let r = azos_sched::process::exec_commit(prepared);
    // U07-3 (audit unit-07): `exec_user` never touches the filter — by
    // design, matching Linux's "seccomp survives execve"
    // (`process.rs::exec_user`'s own doc). That is the wrong default
    // for THIS project's own guarantee, which `seccomp.rs:327-332`
    // states as fact: every image's row is bound to its digest, so an
    // already-confined task (e.g. ABITEST, whose row grants
    // `SYS_EXEC`/`SYS_EXECPATH` with 53 syscalls, `seccomp.rs:581`)
    // executing a narrower-profiled image must land on THAT image's
    // row, not keep its own, wider one.
    //
    // `install_image_profile` — what the autorun loader and the shell
    // call — will not do this: it is documented one-way and refuses
    // when a filter is already enabled, which is exactly the state a
    // confined ring-3 caller is always in. This installs the executed
    // image's row unconditionally instead, only after the commit — a
    // failed exec leaves the caller's own filter and its own
    // still-running image untouched, so there is no wrong-filter/old-image
    // window to unwind.
    if let Some(profile) = azos_sched::seccomp::image_for_digest(digest) {
        azos_sched::set_current_syscall_filter(
            azos_sched::seccomp::image_filter(profile),
        );
    }
    // Wave 11 (LEASE2): the old image is gone, so is everything it held
    // in user space. Robust words it held become OWNER_DIED and their
    // waiters are woken (Linux runs the robust list at exec too), and its
    // lease mappings are dropped BEFORE the old address space is torn
    // down by the exec hand-off's consumer — a lease revoke edits the
    // lessee's page table from another task, and it must never find a
    // root that no longer exists (`lease.rs`, "Page-table lifetime").
    // Read now: a thread that was not the leader holds the process's TID
    // since `exec_end_other_threads`.
    let me = azos_sched::current_task_tid();
    let _ = crate::vdso_notify::notify_robust_exit(me);
    azos_ipc::lease::lease_exec(me);
    r
}

/// Wave 15 (plan 4a): an exec from a process with threads ends every other
/// thread and waits until they have gone (`scheduler::exec_end_other_threads`),
/// so none runs on the image being replaced; the exec'ing thread goes on as
/// the whole process, under the process's TID when it was not the leader.
/// Every exec handler (native `exec`/`execpath`, Linux `execve`) calls it
/// once the new image is read, checked (bound profile, rows) and admitted
/// (`process::exec_prepare_*`), and after dropping `EXEC_BOUNCE`: a refused
/// exec leaves every thread running, as Linux validates before `de_thread`.
///
/// `Err(Ending)` when the process is ending (or another of its threads is
/// already exec'ing). A process with no threads pays one load.
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

/// The native exec calls' answer to an [`exec_end_other_threads`] refusal:
/// `EINTR` (the process is ending).
fn exec_dethread_errno(e: azos_sched::scheduler::ExecDethreadError) -> i64 {
    match e {
        azos_sched::scheduler::ExecDethreadError::Ending => azos_abi::error::Errno::EINTR.to_syscall_ret(),
    }
}

/// Hand `elf` to the loader if a seccomp image profile is bound to it;
/// otherwise record the refusal and return `EACCES`.
///
/// The one way both ring-3 exec handlers load an image. They call it with the
/// slice of `EXEC_BOUNCE` they filled, while still holding its lock, so the
/// bytes hashed are the bytes loaded.
fn exec_bound_image(elf: &[u8]) -> Result<(azos_sched::process::PreparedExec, [u8; 32]), i64> {
    // Hashed once (see `exec_image_is_bound_by_digest`'s doc: hashing twice
    // under `EXEC_BOUNCE.lock()` was the alternative) and reused below for
    // the U07-3 filter install, so this is the same one SHA-256 pass the
    // pre-V1.8 code always paid, not two.
    exec_bound_image_digest(elf, &azos_sched::seccomp::image_digest(elf))
}

/// [`exec_bound_image`] for bytes whose digest the caller holds: `digest`
/// MUST be the SHA-256 of exactly `elf` (`image_cache::read_verified`'s
/// answer for the bytes it read into the buffer `elf` is).
fn exec_bound_image_digest(
    elf: &[u8],
    digest: &[u8; 32],
) -> Result<(azos_sched::process::PreparedExec, [u8; 32]), i64> {
    let digest = *digest;
    if !exec_image_is_bound_by_digest(&digest) {
        return Err(azos_abi::error::Errno::EACCES.to_syscall_ret());
    }
    // RFC-0047: an image whose row says `abi = "linux"` starts only by spawn,
    // which tags it before it runs. Exec'd, it would read its Linux numbers
    // against the native table (under its own profile, but meaningless).
    let linux_row = *EXEC_LINUX_ROW.lock();
    if let (Some(profile), Some(is_linux)) = (azos_sched::seccomp::image_for_digest(&digest), linux_row) {
        if is_linux(profile.image) {
            azos_drv_sys::kwarn!(
                "[EXEC] REFUSED: {} is a Linux image; it starts only by spawn under its row",
                profile.image,
            );
            return Err(azos_abi::error::Errno::EACCES.to_syscall_ret());
        }
    }
    // RFC-0049 M1: an image with a topology row of its own runs under that
    // row's budget; one without keeps the caller's. A locked task stays
    // locked whatever it execs (exec is the only birth a locked row allows,
    // and it must not be a way out), and a locked row whose image could fork
    // or ask for demand pages is refused (P2).
    let resolver = *EXEC_MEM_RESOLVER.lock();
    let mem = azos_sched::seccomp::image_for_digest(&digest).and_then(|profile| {
        let row = resolver?(profile.image)?;
        Some((profile, azos_sched::MemSpec {
            locked: row.locked || azos_sched::current_mem_locked(),
            ..row
        }))
    });
    if let Some((profile, spec)) = mem {
        if spec.locked && !azos_sched::seccomp::locked_compatible(profile) {
            azos_drv_sys::kwarn!(
                "[MEM] exec REFUSED: {} runs under a locked row but its profile can fork or demand-page",
                profile.image,
            );
            return Err(azos_abi::error::Errno::EACCES.to_syscall_ret());
        }
    }
    // Wave 15 (plan 4a): admitted, not committed. The caller drops
    // `EXEC_BOUNCE` and then commits (`exec_finish`), which ends the other
    // threads first: a stopped thread waiting for that lock would never
    // reach the return to user mode where a stop ends it.
    match azos_sched::process::exec_prepare_mem(elf, mem.map(|(_, m)| m)) {
        Some(p) => Ok((p, digest)),
        None => Err(-1),
    }
}

pub fn sys_execpath(path_ptr: u64) -> i64 {
    if path_ptr == 0 { return -1; }

    // Copy the path from user space.
    let mut path_buf = [0u8; 256];
    if azos_sched::copy_cstr_from_user(&mut path_buf, path_ptr as usize).is_none() {
        return -1;
    }
    let path_len = path_buf.iter().position(|&b| b == 0).unwrap_or(0);
    if path_len == 0 { return -1; }
    let path = &path_buf[..path_len];
    if let Err(e) = exec_validate_late_canary() { return e; }

    // Read the ELF into the fixed kernel bounce buffer. An earlier version grew
    // an unbounded `Vec` on the kernel heap: a large file on the mounted FAT32
    // image exhausted it, and the allocation-error path panics — which, under
    // `panic = "abort"`, resets the board. A fixed buffer with an explicit cap
    // cannot do that.
    //
    // `read_whole` rather than open/read/close because the cap has to be
    // enforced as a whole-file property: a file that does not fit must be
    // refused, not exec'd as a prefix and then misreported as a corrupt ELF.
    // Pushing the loop behind the seam is also what lets the throwaway
    // descriptor-table copy this function used to make disappear entirely.
    //
    // Wave 14 (SPAWNCACHE): through the verified-image cache, which hashes
    // in the same pass as the read or reuses the digest of these same bytes.
    let ops = match file_ops() { Some(o) => o, None => return -1 };
    let mut buf = EXEC_BOUNCE.lock();
    let v = match crate::image_cache::read_verified(ops, path, &mut buf[..]) {
        Ok(v) => v,
        Err(_) => return -1,
    };
    let prepared = exec_bound_image_digest(&buf[..v.total], &v.digest);
    drop(buf);
    match prepared {
        Ok((p, digest)) => exec_finish(p, &digest),
        Err(e) => e,
    }
}

// `SYS_SLEEP` and `SYS_SLEEP_UNTIL`: `crate::sleep` (RFC-0044).

// ── File I/O ──────────────────────────────────────────────────────────────────

/// `vfs_open`'s flag bits (`crates/fs/fs/src/vfs.rs`), the ones that make an
/// `open` change the tree or a file: access mode in the low two bits.
const OPEN_ACCMODE: u64 = 0x3;
const OPEN_CREAT: u64 = 0x40;
const OPEN_TRUNC: u64 = 0x200;

/// The tree authority for `open` (security survey, 2026-09-29).
///
/// `vfs_open` creates the file on `O_CREAT` and truncates it on `O_TRUNC`
/// inside the open itself, and a descriptor opened for writing rewrites the
/// file's bytes: all three change what the named calls ([`fs_tree_gate`])
/// guard, so they need the same capability. `O_CREAT` asks for the entry's
/// directory, as `SYS_MKDIR` does (`strict`); `O_TRUNC` or a write access
/// mode asks for the file itself, as `SYS_TRUNCATE` does. A read-only open
/// needs nothing new. Linux closed the same gap in Landlock ABI v3
/// (`LANDLOCK_ACCESS_FS_TRUNCATE`, 6.2): an open-time truncate had bypassed
/// a sandbox that forbade `truncate`.
fn open_tree_gate(path: &[u8], flags: u64) -> Result<(), i64> {
    if flags & OPEN_CREAT != 0 {
        fs_tree_gate(path, true)?;
    }
    if flags & OPEN_TRUNC != 0 || flags & OPEN_ACCMODE != 0 {
        fs_tree_gate(path, false)?;
    }
    Ok(())
}

pub fn sys_open(path_ptr: u64, flags: u64) -> i64 {
    let ops = match file_ops() { Some(o) => o, None => return -1 };
    // When called from user space, copy the path string safely.
    if azos_sched::current_user_pt() != 0 {
        let mut path_buf = [0u8; SYS_PATH_MAX];
        match azos_sched::copy_cstr_from_user(&mut path_buf, path_ptr as usize) {
            Some(_) => {
                let path_len = path_buf.iter().position(|&b| b == 0).unwrap_or(0);
                if let Err(e) = open_tree_gate(&path_buf[..path_len], flags) { return e; }
                ops.open(&path_buf[..path_len], flags as u32)
            }
            None => -1,
        }
    } else {
        let path = unsafe { cstr_to_bytes(path_ptr as *const u8) };
        ops.open(path, flags as u32)
    }
}

pub fn sys_close(fd: u64) -> i64 {
    // A descriptor a `Cap<File>` still names closes only through
    // `SYS_CLOSE_TYPED` — see [`fd_named_by_file_cap`].
    if fd_named_by_file_cap(fd) { return -1; }
    match file_ops() { Some(o) => o.close(fd as i32), None => -1 }
}

// ── Cap<File> typed handlers (563-566) ───────────────────────────────────────

/// Does the calling ring-3 task still name `fd` through a `Cap<File>`?
///
/// The descriptor calls and the typed calls share one descriptor table, and a
/// `Cap<File>`'s resource IS the descriptor. An untyped `close(fd)` — or a
/// `dup2` onto `fd` — behind a live capability would free the slot while the
/// capability still named it, and the task's next `open` would reuse the
/// number: the capability would then be a handle on a different file. Refusing
/// those two calls keeps a `Cap<File>` naming the file it was minted for.
///
/// `NONE` rather than `READ`: `holds_kind_resource_with` answers "no" for any
/// `WRITE` query while degraded mode is armed, and whether the slot is taken
/// must not depend on that. Kernel callers hold no capabilities and are not
/// asked.
fn fd_named_by_file_cap(fd: u64) -> bool {
    use azos_abi::cap::{CapKind, CapPerms};
    if azos_sched::current_user_pt() == 0 || fd > u32::MAX as u64 {
        return false;
    }
    let tid = azos_sched::current_task_tid();
    azos_ipc::cap_store::with_table(tid, |t| {
        t.holds_kind_resource_with(CapKind::File, fd as u32, CapPerms::NONE)
    })
    .unwrap_or(false)
}

/// The permissions a `Cap<File>` is minted with: the access mode of the `open`
/// flags (`O_RDONLY` 0, `O_WRONLY` 1, `O_RDWR` 2 — `crates/fs/fs/src/vfs.rs`).
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

/// Resolve a `SYS_IPC_FAST_CALL_EP` destination, recording a capability
/// denial the way every other typed family records one (RFC-0040 gap 2).
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
pub fn endpoint_dest_recording(caller_tid: u32, cap_raw: u32) -> Option<u32> {
    use azos_ipc::endpoint::EndpointCapError;
    match azos_ipc::endpoint::endpoint_dest_for(caller_tid, cap_raw) {
        Ok(tid) => Some(tid),
        Err(EndpointCapError::Cap(e)) => {
            note_typed_denial(azos_abi::cap::CapKind::Endpoint, e);
            None
        }
        Err(_) => None,
    }
}

fn errno_for_file_err(e: azos_ipc::cap::CapError) -> i64 {
    use azos_abi::error::Errno;
    use azos_ipc::cap::CapError;
    // Every typed refusal in this file reaches the recorder here — the one
    // choke point all twelve of these functions share. `Contained` is filtered
    // inside `note_typed_denial`, not here.
    note_typed_denial(azos_abi::cap::CapKind::File, e);
    match e {
        CapError::Stale => Errno::ECAPSTALE.to_syscall_ret(),
        CapError::WrongKind => Errno::ECAPKIND.to_syscall_ret(),
        CapError::MissingPerms => Errno::ECAPPERMS.to_syscall_ret(),
        CapError::Contained => Errno::EAGAIN.to_syscall_ret(),
        CapError::NoSpace => Errno::EMFILE.to_syscall_ret(),
    }
}

/// `SYS_FILE_OPEN_TYPED` (563): a0=path_ptr, a1=flags. Opens like
/// [`sys_open`] and mints a `Cap<File>` naming the descriptor into the
/// caller's own table. Returns the raw handle, `-1` if the open fails,
/// `-EINVAL` for access mode 3, `-EMFILE` if the cap table is full.
pub fn sys_file_open_typed(path_ptr: u64, flags: u64) -> i64 {
    use azos_abi::error::Errno;

    let perms = match file_perms_for_flags(flags) {
        Some(p) => p,
        None => return Errno::EINVAL.to_syscall_ret(),
    };
    let fd = sys_open(path_ptr, flags);
    if fd < 0 {
        return fd;
    }
    grant_opened_file(fd, perms)
}

/// Mint the `Cap<File>` naming descriptor `fd`, just opened by the caller, or
/// close it again. The second half of [`sys_file_open_typed`].
fn grant_opened_file(fd: i64, perms: azos_abi::cap::CapPerms) -> i64 {
    use azos_abi::error::Errno;
    use azos_ipc::cap::targets::File;
    let tid = azos_sched::current_task_tid();
    // O3.4: a file the task opened itself is giftable (DUP), like a socket.
    match azos_ipc::cap_store::grant::<File>(tid, perms.union(azos_abi::cap::CapPerms::DUP), fd as u32) {
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

/// RFC-0047: [`sys_file_open_typed`] for a path the kernel already holds (the
/// Linux personality joined it onto the task's working directory). The same
/// tree gate, the same open, the same grant; ring 3 only.
pub(crate) fn file_open_typed_kpath(path: &[u8], flags: u64) -> i64 {
    use azos_abi::error::Errno;
    let perms = match file_perms_for_flags(flags) {
        Some(p) => p,
        None => return Errno::EINVAL.to_syscall_ret(),
    };
    let ops = match file_ops() { Some(o) => o, None => return -1 };
    if azos_sched::current_user_pt() == 0 {
        return -1;
    }
    if let Err(e) = open_tree_gate(path, flags) { return e; }
    let fd = ops.open(path, flags as u32);
    if fd < 0 {
        return fd;
    }
    grant_opened_file(fd, perms)
}

/// RFC-0047: the descriptor a `Cap<File>` the caller holds names, checked
/// and recorded as the typed calls check it (no right needed: the
/// personality reads its size and moves its offset).
pub(crate) fn file_desc_of(cap_raw: u64) -> Result<u64, i64> {
    file_fd_for(cap_raw, azos_abi::cap::CapPerms::NONE)
}

/// Resolve a `Cap<File>` to its descriptor under the caller's table lock, and
/// release the lock before any file I/O — the same shape as
/// `sys_gpio_read_typed`, so a FAT32 read never holds a cap table.
///
/// The descriptor is always 3 or above (`vfs_open` never hands out 0-2), so
/// passing it on to `sys_read`/`sys_write` never meets their stdio arm.
fn file_fd_for(cap_raw: u64, need: azos_abi::cap::CapPerms) -> Result<u64, i64> {
    use azos_abi::cap::CapHandle;
    use azos_abi::error::Errno;
    use azos_ipc::cap::{targets::File, Cap};

    let cap: Cap<File> = Cap::from_raw(CapHandle::from_raw(cap_raw as u32));
    let tid = azos_sched::current_task_tid();
    match azos_ipc::cap_store::with_table(tid, |t| t.get(cap, need)) {
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

/// `SYS_FILE_READ_TYPED` (564): a0=cap, a1=buf, a2=count. Requires `READ`.
pub fn sys_file_read_typed(cap_raw: u64, buf: u64, count: u64) -> i64 {
    match file_fd_for(cap_raw, azos_abi::cap::CapPerms::READ) {
        Ok(fd) => sys_read(fd, buf, count),
        Err(e) => e,
    }
}

/// `SYS_FILE_WRITE_TYPED` (565): a0=cap, a1=buf, a2=count. Requires `WRITE`.
pub fn sys_file_write_typed(cap_raw: u64, buf: u64, count: u64) -> i64 {
    match file_fd_for(cap_raw, azos_abi::cap::CapPerms::WRITE) {
        Ok(fd) => sys_write(fd, buf, count),
        Err(e) => e,
    }
}

/// `SYS_CLOSE_TYPED` (566): a0=cap. Revoke the capability and release what it
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
/// that capability; it asked for an operation the kind does not have.
pub fn sys_close_typed(cap_raw: u64) -> i64 {
    use azos_abi::cap::{CapHandle, CapKind, CapPerms};
    use azos_abi::error::Errno;
    use azos_ipc::cap::{targets::{Channel, File, Socket}, Cap};

    let raw = CapHandle::from_raw(cap_raw as u32);
    match CapKind::from_raw(raw.kind()) {
        Some(CapKind::File) | Some(CapKind::Null) | None => {
            let cap: Cap<File> = Cap::from_raw(raw);
            let tid = azos_sched::current_task_tid();
            let fd = match azos_ipc::cap_store::with_table(tid, |t| {
                let fd = t.get(cap, CapPerms::NONE)?;
                // A directory-tree `Cap<File>` has no descriptor to close
                // (wave 10): refused, and the grant stays.
                if azos_ipc::file_cap::is_tree_resource(fd) {
                    return Err(azos_ipc::cap::CapError::WrongKind);
                }
                t.revoke(cap);
                Ok(fd)
            }) {
                Some(Ok(fd)) => fd,
                Some(Err(e)) => return errno_for_file_err(e),
                None => return Errno::EINVAL.to_syscall_ret(),
            };
            match file_ops() { Some(o) => o.close(fd as i32), None => -1 }
        }
        Some(CapKind::Socket) => {
            let cap: Cap<Socket> = Cap::from_raw(raw);
            let tid = azos_sched::current_task_tid();
            let fd = match azos_ipc::cap_store::with_table(tid, |t| {
                let fd = t.get(cap, CapPerms::NONE)?;
                t.revoke(cap);
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
        // RFC-0040 gap 1: the channel a `SYS_CHAN_CREATE_TYPED` handle names.
        // A release, so `channel_destroy_cap` resolves it uncontained with
        // `WRITE`, as `port_destroy_cap` does; it destroys through the
        // generation, ends the calls registered against that incarnation, and
        // revokes the capability, `Stale` included.
        Some(CapKind::Channel) => {
            let cap: Cap<Channel> = Cap::from_raw(raw);
            let tid = azos_sched::current_task_tid();
            match azos_ipc::cap_store::with_table(tid, |t| {
                azos_ipc::channel::channel_destroy_cap(t, cap)
            }) {
                Some(Ok(())) => 0,
                Some(Err(e)) => crate::ipc_handlers::errno_for_channel_err(e),
                None => Errno::EINVAL.to_syscall_ret(),
            }
        }
        Some(_) => Errno::ECAPKIND.to_syscall_ret(),
    }
}

/// The first `len` bytes of a bounce buffer, zeroed; the rest is never
/// touched. Wave 13 (DEBTS): the syscall bounce buffers were `[0u8; 4096]`,
/// and zeroing 4 KiB cost ~1,570 instructions on EVERY read, whatever its
/// length — a 64-byte `SYS_FILE_READ_TYPED` paid more for the memset than for
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
    let p = b.as_mut_ptr() as *mut u8;
    if !azos_sched::copy_from_user(p, user as usize, len) {
        return None;
    }
    // SAFETY: `copy_from_user` returned true, so it wrote all `len` bytes.
    Some(unsafe { core::slice::from_raw_parts(p, len) })
}

pub fn sys_read(fd: u64, buf: u64, count: u64) -> i64 {
    let count = count as usize;
    let ops = match file_ops() { Some(o) => o, None => return -1 };
    if azos_sched::current_user_pt() != 0 {
        // Read into a kernel temp buffer, then copy_to_user.
        const MAX: usize = 4096;
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
            if !azos_sched::copy_to_user(buf as usize, tmp.as_ptr(), (n as usize).min(chunk)) {
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

pub fn sys_write(fd: u64, buf: u64, count: u64) -> i64 {
    let count = count as usize;
    if azos_sched::current_user_pt() != 0 {
        // Copy user buffer into kernel temp buffer.
        const MAX: usize = 4096;
        let chunk = count.min(MAX);
        let mut tmp = core::mem::MaybeUninit::<[u8; MAX]>::uninit();
        let Some(tmp) = bounce_from_user(&mut tmp, buf, chunk) else {
            return -1;
        };
        // fd 1 (stdout) and fd 2 (stderr): write directly to UART.
        // The kernel FD table does not pre-open stdio for user processes.
        if fd == 1 || fd == 2 {
            // U07-1 (audit unit-07): this used to hold ONE `uart::acquire()`
            // (SIE off) across the whole polled transmit, up to `MAX` = 4096
            // B — ≈15 ms (QEMU) / ≈360 ms (115200 baud) of masked interrupts
            // per call, from ring 3, on every image row that grants
            // `SYS_WRITE`. `console_write_ring3` bounds that:
            //
            // 1. Line atomicity: ring-3 writers are ordered by a preemptible
            //    `PiMutex` held for the whole call, and the writer OWNS the
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
            return chunk as i64;
        }
        // Below the console arm on purpose. A write to fd 1/2 is logging, and a
        // contained program reporting what it sees is exactly what containment
        // wants to keep; a write that reaches `file_ops` is the WRITE
        // `SYS_FILE_WRITE_TYPED` refuses — see `untyped_write_contained`.
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
        // The whole register: offsets are 64-bit since RFC-0048 P2 (a
        // negative one is the two's complement the caller passed).
        Some(o) => o.lseek(fd as i32, offset as i64, whence as i32),
        None => -1,
    }
}

// ── Filesystem ────────────────────────────────────────────────────────────────

/// Maximum filesystem path length copied from userspace, NUL included: a
/// `NAME_MAX` (255-byte) name under a mount point and a few directories
/// (RFC-0048 P2; was 256, which one such name under `/fat/` overflowed).
/// `sys_open` uses it too.
const SYS_PATH_MAX: usize = 512;

/// Copy a NUL-terminated path from a user pointer into `dst`, returning the
/// path slice. Mirrors `sys_open`'s pattern so a malformed/kernel pointer can't
/// drive the FS code via raw `cstr_to_bytes`.
fn copy_path_from_user<'a>(dst: &'a mut [u8], path_ptr: u64) -> Option<&'a [u8]> {
    if azos_sched::current_user_pt() != 0 {
        azos_sched::copy_cstr_from_user(dst, path_ptr as usize)?;
        let len = dst.iter().position(|&b| b == 0).unwrap_or(dst.len());
        Some(&dst[..len])
    } else {
        Some(unsafe { cstr_to_bytes(path_ptr as *const u8) })
    }
}

/// The authority for the calls that change the tree (wave 10, owner
/// decision): `SYS_MKDIR`, `SYS_UNLINK`, `SYS_RMDIR`, `SYS_RENAME`,
/// `SYS_TRUNCATE`. A ring-3 caller must hold a `Cap<File>` with `WRITE`
/// naming a directory tree that covers `path` (`azos_ipc::file_cap`,
/// minted only by the topology). `strict`: `path` is an ENTRY of the tree
/// (create, remove, rename — the directory it is in is what changes);
/// otherwise the tree's root counts too (truncate — the file itself).
///
/// Asked after the path is copied and before the filesystem sees it, so a
/// refusal says nothing about whether the path exists. `-EINVAL` for a path
/// that is relative or has a `.`/`..` component (the check does not resolve
/// them, so it does not accept them); `-EACCES` (recorded, as `cap_check`
/// records) for no covering capability; `-EAGAIN` for a holder while
/// degraded mode is armed — a WRITE through a capability, contained as the
/// others are. Kernel tasks pass, as they pass `cap_check`.
fn fs_tree_gate(path: &[u8], strict: bool) -> Result<(), i64> {
    use azos_abi::cap::{CapKind, CapPerms};
    use azos_abi::error::Errno;
    if azos_sched::current_user_pt() == 0 {
        return Ok(());
    }
    if !azos_ipc::file_cap::path_is_plain(path) {
        return Err(Errno::EINVAL.to_syscall_ret());
    }
    // The covering trees first, under the tree table's lock alone; then the
    // caller's capability table, under its own. Never both at once.
    let mask = azos_ipc::file_cap::trees_covering(path, strict);
    let tid = azos_sched::current_task_tid();
    let held = mask != 0
        && azos_ipc::cap_store::with_table(tid, |t| {
            t.holds_kind_where(CapKind::File, CapPerms::WRITE, |r| {
                azos_ipc::file_cap::tree_in(r, mask)
            })
        })
        .unwrap_or(false);
    if !held {
        record_cap_denial(CapKind::File, 0, true);
        return Err(Errno::EACCES.to_syscall_ret());
    }
    if untyped_write_contained() {
        return Err(Errno::EAGAIN.to_syscall_ret());
    }
    Ok(())
}

/// `SYS_MKDIR` (252): a0 = path. Needs a tree capability covering the new
/// directory's parent ([`fs_tree_gate`]).
pub fn sys_mkdir(path_ptr: u64) -> i64 {
    let mut buf = [0u8; SYS_PATH_MAX];
    let path = match copy_path_from_user(&mut buf, path_ptr) { Some(p) => p, None => return -1 };
    if let Err(e) = fs_tree_gate(path, true) { return e; }
    match file_ops() { Some(o) => o.mkdir(path), None => -1 }
}

/// `SYS_UNLINK` (253): a0 = path. Needs a tree capability covering the
/// entry's directory ([`fs_tree_gate`]).
pub fn sys_unlink(path_ptr: u64) -> i64 {
    let mut buf = [0u8; SYS_PATH_MAX];
    let path = match copy_path_from_user(&mut buf, path_ptr) { Some(p) => p, None => return -1 };
    if let Err(e) = fs_tree_gate(path, true) { return e; }
    match file_ops() { Some(o) => o.unlink(path), None => -1 }
}

/// SYS_READDIR: read directory entry at `index`.
/// a0=path_ptr, a1=index, a2=name_out (64-byte buf), a3=size_out (*u32), a4=is_dir_out (*u32).
/// Returns 0 on success, -1 if out of range or error.
pub fn sys_readdir(
    path_ptr: u64, index: u64, name_out: u64, size_out: u64, is_dir_out: u64,
    name_len: u64,
) -> i64 {
    if path_ptr == 0 || name_out == 0 { return -1; }

    // **The caller declares its buffer** (owner decision 100b). This writes
    // `READDIR_NAME_BYTES` bytes ALWAYS, zero-padding a short name, and until
    // 2026-09-19 it learned no length at all: the size was enforced only by
    // `libsys::readdir` typing the parameter as `&mut [u8; 64]`. That holds
    // for a Rust caller going through libsys and for nothing else — a raw
    // `ecall` with a 16-byte buffer got 64 bytes written into it, and
    // `copy_to_user` would not object because it validates PAGES, not the
    // length the caller had in mind.
    //
    // Refuses rather than writing fewer bytes: a name truncated in silence is
    // a filename the caller then acts on, and it has no way to know.
    if name_len < azos_abi::syscall_nr::READDIR_NAME_BYTES as u64 {
        return -1;
    }

    let ops = match file_ops() { Some(o) => o, None => return -1 };

    // Path resolution and entry lookup are one operation behind the seam. The
    // old code split them — `path_lookup` here, `dir_entry_at` below — which
    // is what put the filesystem's inode indices in this crate's vocabulary.
    //
    // The path passed on is trimmed at its NUL, where before this branch
    // handed over the whole 256-byte NUL-padded buffer. No behaviour changes:
    // `path_lookup` trims its own argument first. It was still worth
    // normalising, because it was the one place where the file syscalls
    // disagreed with each other about what a path is.
    let mut path_buf = [0u8; 256];
    let path: &[u8] = if azos_sched::current_user_pt() != 0 {
        match azos_sched::copy_cstr_from_user(&mut path_buf, path_ptr as usize) {
            Some(_) => {
                let len = path_buf.iter().position(|&b| b == 0).unwrap_or(path_buf.len());
                &path_buf[..len]
            }
            None => return -1,
        }
    } else {
        unsafe { cstr_to_bytes(path_ptr as *const u8) }
    };

    match ops.readdir(path, index as u32) {
        Some((name, size, is_dir)) => {
            let name_len = name.iter().position(|&b| b == 0).unwrap_or(name.len());
            let copy_len = name_len.min(63); // leave room for NUL
            if azos_sched::current_user_pt() != 0 {
                let mut tmp = [0u8; 64];
                tmp[..copy_len].copy_from_slice(&name[..copy_len]);
                if !azos_sched::copy_to_user(name_out as usize, tmp.as_ptr(), 64) {
                    return -1;
                }
                // Checked like `name_out` above: returning 0 with these
                // fields unwritten would be a silent partial success the
                // caller cannot detect.
                if size_out != 0 {
                    let sb = (size as u32).to_le_bytes();
                    if !azos_sched::copy_to_user(size_out as usize, sb.as_ptr(), 4) {
                        return -1;
                    }
                }
                if is_dir_out != 0 {
                    let db = (is_dir as u32).to_le_bytes();
                    if !azos_sched::copy_to_user(is_dir_out as usize, db.as_ptr(), 4) {
                        return -1;
                    }
                }
            } else {
                unsafe {
                    let out = name_out as *mut u8;
                    core::ptr::write_bytes(out, 0, 64);
                    core::ptr::copy_nonoverlapping(name.as_ptr(), out, copy_len);
                    if size_out != 0 {
                        *(size_out as *mut u32) = size;
                    }
                    if is_dir_out != 0 {
                        *(is_dir_out as *mut u32) = is_dir as u32;
                    }
                }
            }
            0
        }
        None => -1,
    }
}

/// `SYS_MOUNT` (256): mount a filesystem of type `fs` at `tgt`
/// (RFC-0048 P2). a0 = source, a1 = target, a2 = type, all NUL-terminated.
///
/// **Gated before anything is read**: a mount changes what every task's
/// paths reach, so it needs the whole-disk `Cap<Disk>` with WRITE — which a
/// kernel task passes and nothing mints for ring 3 (a partition capability
/// does not qualify). Refusals are recorded as `cap_check`'s are. Past the
/// gate the three strings are copied and the installed filesystem decides:
/// `0`, or a negative errno.
pub fn sys_mount(src: u64, tgt: u64, fs: u64) -> i64 {
    if !cap_check(azos_abi::cap::CapKind::Disk, 0, true) { return E_PERM; }
    use azos_abi::error::Errno;
    if src == 0 || tgt == 0 || fs == 0 { return Errno::EFAULT.to_syscall_ret(); }
    let mut sb = [0u8; SYS_PATH_MAX];
    let mut tb = [0u8; SYS_PATH_MAX];
    let mut fb = [0u8; 32];
    let src = match copy_path_from_user(&mut sb, src) { Some(p) => p, None => return Errno::EFAULT.to_syscall_ret() };
    let tgt = match copy_path_from_user(&mut tb, tgt) { Some(p) => p, None => return Errno::EFAULT.to_syscall_ret() };
    let fs = match copy_path_from_user(&mut fb, fs) { Some(p) => p, None => return Errno::EFAULT.to_syscall_ret() };
    match file_ops() { Some(o) => o.mount(src, tgt, fs), None => -1 }
}
pub fn sys_umount(_tgt: u64) -> i64                       { -1 }

/// `SYS_SYNC` (258): make every write the mounted filesystem has completed
/// durable and return the device's answer, through the `FileOps` seam (the
/// kernel's implementation settles the FAT32 journal and flushes the block
/// device). Was `{ 0 }`: it did nothing and reported success.
///
/// `0` the device confirmed the flush; `-ENOSYS` the block device cannot
/// flush; `-EIO` the flush failed; `-ENODEV` no volume is mounted; `-1`
/// when no filesystem is installed, as for every other file syscall.
pub fn sys_sync() -> i64 {
    match file_ops() { Some(o) => o.sync(), None => -1 }
}

/// `SYS_STAT` (250): a0 = path, a1 = buffer of at least `STAT_BYTES`
/// (RFC-0048 P2; was `{ -1 }`). Writes the layout `STAT_BYTES` documents
/// and returns `0`; `-ENOENT` for no such file, `-EFAULT` for an unreadable
/// path or an unwritable buffer, `-1` with no filesystem installed.
///
/// No capability: it reports what `open` would find, and `open` needs none.
pub fn sys_stat(path_ptr: u64, stat_ptr: u64) -> i64 {
    use azos_abi::error::Errno;
    use azos_abi::syscall_nr::STAT_BYTES;
    if path_ptr == 0 || stat_ptr == 0 { return Errno::EFAULT.to_syscall_ret(); }
    let mut buf = [0u8; SYS_PATH_MAX];
    let path = match copy_path_from_user(&mut buf, path_ptr) {
        Some(p) => p,
        None => return Errno::EFAULT.to_syscall_ret(),
    };
    let ops = match file_ops() { Some(o) => o, None => return -1 };
    let st = match ops.stat(path) { Ok(st) => st, Err(e) => return e };
    let bytes = st.to_bytes();
    if azos_sched::current_user_pt() != 0 {
        if !azos_sched::copy_to_user(stat_ptr as usize, bytes.as_ptr(), STAT_BYTES) {
            return Errno::EFAULT.to_syscall_ret();
        }
    } else {
        unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), stat_ptr as *mut u8, STAT_BYTES); }
    }
    0
}

/// `SYS_RMDIR` (597): a0 = path. Remove an empty directory; `0` or a
/// negative errno (owner round 23). Needs a tree capability covering the
/// directory's parent, as `SYS_MKDIR` ([`fs_tree_gate`], wave 10).
pub fn sys_rmdir(path_ptr: u64) -> i64 {
    use azos_abi::error::Errno;
    if path_ptr == 0 { return Errno::EFAULT.to_syscall_ret(); }
    let mut buf = [0u8; SYS_PATH_MAX];
    let path = match copy_path_from_user(&mut buf, path_ptr) {
        Some(p) => p,
        None => return Errno::EFAULT.to_syscall_ret(),
    };
    if let Err(e) = fs_tree_gate(path, true) { return e; }
    match file_ops() { Some(o) => o.rmdir(path), None => -1 }
}

/// `SYS_RENAME` (598): a0 = from, a1 = to. Within one mounted filesystem;
/// `0` or a negative errno (owner round 23). Both ends need a tree
/// capability covering their directory ([`fs_tree_gate`], wave 10).
pub fn sys_rename(from_ptr: u64, to_ptr: u64) -> i64 {
    use azos_abi::error::Errno;
    if from_ptr == 0 || to_ptr == 0 { return Errno::EFAULT.to_syscall_ret(); }
    let mut fb = [0u8; SYS_PATH_MAX];
    let mut tb = [0u8; SYS_PATH_MAX];
    let from = match copy_path_from_user(&mut fb, from_ptr) {
        Some(p) => p,
        None => return Errno::EFAULT.to_syscall_ret(),
    };
    let to = match copy_path_from_user(&mut tb, to_ptr) {
        Some(p) => p,
        None => return Errno::EFAULT.to_syscall_ret(),
    };
    if let Err(e) = fs_tree_gate(from, true) { return e; }
    if let Err(e) = fs_tree_gate(to, true) { return e; }
    match file_ops() { Some(o) => o.rename(from, to), None => -1 }
}

/// `SYS_TRUNCATE` (599): a0 = path, a1 = length (the whole register). `0` or
/// a negative errno (owner round 23). Needs a tree capability covering the
/// file itself ([`fs_tree_gate`], wave 10).
pub fn sys_truncate(path_ptr: u64, len: u64) -> i64 {
    use azos_abi::error::Errno;
    if path_ptr == 0 { return Errno::EFAULT.to_syscall_ret(); }
    let mut buf = [0u8; SYS_PATH_MAX];
    let path = match copy_path_from_user(&mut buf, path_ptr) {
        Some(p) => p,
        None => return Errno::EFAULT.to_syscall_ret(),
    };
    if let Err(e) = fs_tree_gate(path, false) { return e; }
    match file_ops() { Some(o) => o.truncate(path, len), None => -1 }
}

/// `SYS_FSYNC_TYPED` (600): a0 = `Cap<File>`, any permission (Linux's
/// `fsync` works on a read-only descriptor too). The handle is resolved and
/// refused exactly as `SYS_FILE_READ_TYPED`'s is — stale, wrong kind, and the
/// refusal recorded — and the descriptor it names is synced. `0` or a
/// negative errno (owner round 23).
pub fn sys_fsync_typed(cap_raw: u64) -> i64 {
    match file_fd_for(cap_raw, azos_abi::cap::CapPerms::NONE) {
        Ok(fd) => match file_ops() { Some(o) => o.fsync(fd as i32), None => -1 },
        Err(e) => e,
    }
}

/// `SYS_STATFS` (601): a0 = path, a1 = buffer, a2 = its length (at least
/// `STATFS_BYTES`). Writes the layout `STATFS_BYTES` documents and returns
/// `0`; `-EINVAL` for a short buffer (nothing written), `-EFAULT` for an
/// unreadable path or an unwritable buffer, the filesystem's errno otherwise
/// (owner round 23). No capability: it reports what `stat` would, per volume.
pub fn sys_statfs(path_ptr: u64, buf_ptr: u64, buf_len: u64) -> i64 {
    use azos_abi::error::Errno;
    use azos_abi::syscall_nr::STATFS_BYTES;
    if path_ptr == 0 || buf_ptr == 0 { return Errno::EFAULT.to_syscall_ret(); }
    if buf_len < STATFS_BYTES as u64 { return Errno::EINVAL.to_syscall_ret(); }
    let mut buf = [0u8; SYS_PATH_MAX];
    let path = match copy_path_from_user(&mut buf, path_ptr) {
        Some(p) => p,
        None => return Errno::EFAULT.to_syscall_ret(),
    };
    let ops = match file_ops() { Some(o) => o, None => return -1 };
    let st = match ops.statfs(path) { Ok(st) => st, Err(e) => return e };
    let bytes = st.to_bytes();
    if azos_sched::current_user_pt() != 0 {
        if !azos_sched::copy_to_user(buf_ptr as usize, bytes.as_ptr(), STATFS_BYTES) {
            return Errno::EFAULT.to_syscall_ret();
        }
    } else {
        unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), buf_ptr as *mut u8, STATFS_BYTES); }
    }
    0
}

// ── System info ───────────────────────────────────────────────────────────────

pub fn sys_meminfo() -> i64 {
    azos_mm::pmm::free_pages() as i64
}

/// `SYS_TASKINFO` (241): a0 = out_ptr, a1 = out_len. See the ABI constant for
/// the layout.
///
/// **Was `-> 0` and wrote nothing.** Another declared-and-empty slot, like
/// `SYS_ROBOT_ESTOP` was: the number existed, `libsys` exposed it, and a
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
    // Same two-arm copy as `sys_motor_tick_typed`: the user path goes through
    // the checked copy, the kernel path writes directly.
    if azos_sched::current_user_pt() != 0 {
        if !azos_sched::copy_to_user(out_ptr as usize, blob.as_ptr(), TASKINFO_BYTES) {
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

/// What runs before an ORDERLY power-off or reboot (`sys_shutdown`,
/// `sys_reboot`), installed by the kernel at boot: OTA's void of this boot's
/// unconfirmed mark, so a deliberate shutdown is not counted as a crash (owner
/// decision 2026-09-28). `crates/core/syscall` cannot name `crates/core/ota`, hence a
/// hook, like the recorders above. Never called on a crash path.
static ORDERLY_POWER_HOOK: azos_sync::SpinLock<Option<fn()>> =
    azos_sync::SpinLock::new(None);

/// Install the orderly power-off hook. Called once at boot.
pub fn set_orderly_power_hook(f: fn()) {
    *ORDERLY_POWER_HOOK.lock() = Some(f);
}

/// Run the orderly power-off hook, if installed. The lock is released first.
fn orderly_power_off() {
    let h = *ORDERLY_POWER_HOOK.lock();
    if let Some(f) = h { f(); }
}

pub fn sys_shutdown() -> i64 {
    // Gate FIRST, as every gated sibling does. There is nothing else in this
    // handler to do after it — which is the point: until 2026-09-05 there was
    // nothing at all, and one `ecall` with a7=270 from any ring-3 task powered
    // the board off. `cap_check` returns true for kernel tasks, so the shell
    // and the OTA path are unaffected.
    if !cap_check(azos_abi::cap::CapKind::Power, 0, true) { return E_PERM; }
    power_off_orderly()
}

/// The authorised half of a power-off, shared by syscall 270 and
/// `SYS_POWER_TYPED` (RFC-0055 S5). The caller has checked `Cap<Power>`.
pub(crate) fn power_off_orderly() -> ! {
    // Authorised: an orderly power-off. Not a crash; say so on the volume.
    orderly_power_off();
    // Deferred kernel lines reach the wire before the power-off (see
    // `sys_reboot`).
    azos_drv_sys::uart::console_flush_for_reboot();
    // riscv64: SBI SRST shutdown; aarch64: PSCI `SYSTEM_OFF`. The host shim
    // of `tests/host/syscall-tests` implements `Boot` with `todo!()` bodies
    // (never reached by its tests).
    azos_arch::Boot::shutdown(&azos_arch::ARCH)
}

pub fn sys_reboot() -> i64 {
    if !cap_check(azos_abi::cap::CapKind::Power, 0, true) { return E_PERM; }
    reboot_orderly()
}

/// The authorised half of a reboot, shared by syscall 271 and
/// `SYS_POWER_TYPED`. The caller has checked `Cap<Power>`.
pub(crate) fn reboot_orderly() -> ! {
    orderly_power_off();
    // Deferred kernel lines (ring 3 may own the console on another hart)
    // reach the wire before the reset, not never.
    azos_drv_sys::uart::console_flush_for_reboot();
    // riscv64: SBI SRST cold reboot; aarch64: PSCI `SYSTEM_RESET`.
    azos_arch::Boot::reboot(&azos_arch::ARCH)
}

// ── Disk ─────────────────────────────────────────────────────────────────────

/// Maximum sectors per disk syscall (= 64 KiB at 512 B/sector).
/// Sized to fit the kernel-stack bounce buffer below.
const DISK_MAX_SECTORS: u64 = 128;
const DISK_BOUNCE_BYTES: usize = (DISK_MAX_SECTORS as usize) * 512;

/// Disk requests refused because they reached outside the caller's partition
/// (RFC-0048 P3). Read by host tests and diagnostics; the durable trace is
/// the `SAFETY_CAP_DENIED` record each refusal also makes.
pub static DISK_SCOPE_REFUSALS: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(0);

/// What the caller's disk authority names: the whole medium (absolute
/// sectors) or one partition of the table the kernel published (sectors
/// relative to its start).
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
enum DiskScope {
    Whole,
    Part(u32),
}

/// Resolve a disk syscall's partition selector (wave 10, owner decision:
/// the disk calls NAME their partition rather than refuse a caller holding
/// several). `a3` of `SYS_DISK_READ`/`SYS_DISK_WRITE`, `a0` of
/// `SYS_DISK_SIZE`.
///
/// * `sel` = a raw `Cap<Disk>` handle in the caller's own table. It is
///   resolved as every typed handle is ([`CapTable::get`]): a stale, forged
///   or wrong-kind handle, or one without the needed permission, is refused
///   with `-ECAPSTALE`/`-ECAPKIND`/`-ECAPPERMS` and recorded; a WRITE while
///   degraded mode is armed answers `-EAGAIN`. Resource 0 is the whole
///   medium, `n + 1` partition `n` (`crates/core/ipc/src/disk_cap.rs`).
/// * `sel` = [`DISK_SEL_ONLY`] (0, `CAP_NULL`, which no handle can be): the
///   caller's ONLY disk authority, exactly as before the argument existed —
///   a kernel task or a whole-disk holder is `Whole`; a holder of exactly
///   one partition capability with the needed permission is that partition;
///   no capability is `cap_check`'s refusal (`E_PERM`, recorded); **two or
///   more partitions are still refused as ambiguous** (`E_PERM`, recorded,
///   counted, and the `[DISK] scope:` console line), because 0 does not say
///   which one is meant. That caller passes a handle instead.
/// * `sel` above `u32::MAX` is no handle at all: `-EINVAL`, rather than
///   truncated into one (`1 << 32` would be read as handle 0).
///
/// A ring-3 WRITE through the sentinel is contained like one through a
/// handle (`-EAGAIN` while degraded mode is armed), after the authority
/// check, so a caller without the capability still gets `E_PERM`.
fn disk_scope(sel: u64, need_write: bool, what: Option<(u64, u64)>) -> Result<DiskScope, i64> {
    use azos_abi::cap::{CapHandle, CapKind, CapPerms};
    use azos_abi::error::Errno;
    let need = if need_write { CapPerms::WRITE } else { CapPerms::READ };
    let tid = azos_sched::current_task_tid();
    if sel != DISK_SEL_ONLY {
        use azos_ipc::cap::{targets::Disk, Cap};
        if sel > u32::MAX as u64 { return Err(Errno::EINVAL.to_syscall_ret()); }
        let cap: Cap<Disk> = Cap::from_raw(CapHandle::from_raw(sel as u32));
        return match azos_ipc::cap_store::with_table(tid, |t| t.get(cap, need)) {
            Some(Ok(r)) => Ok(match azos_ipc::disk_cap::resource_partition(r) {
                None => DiskScope::Whole,
                Some(p) => DiskScope::Part(p),
            }),
            Some(Err(e)) => Err(errno_for_cap_err(CapKind::Disk, e)),
            None => Err(Errno::EINVAL.to_syscall_ret()),
        };
    }
    if azos_sched::current_user_pt() == 0 {
        return Ok(DiskScope::Whole);
    }
    // (whole disk, first partition resource held, a second distinct one)
    let (whole, held, other) = azos_ipc::cap_store::with_table(tid, |t| {
        if t.holds_kind_resource_uncontained(CapKind::Disk, 0, need) {
            return (true, 0, 0);
        }
        let (mut held, mut other) = (0u32, 0u32);
        t.holds_kind_where(CapKind::Disk, need, |r| {
            if azos_ipc::disk_cap::resource_partition(r).is_some() {
                if held == 0 {
                    held = r;
                } else if r != held {
                    other = r;
                }
            }
            false
        });
        (false, held, other)
    })
    .unwrap_or((false, 0, 0));
    let scope = if whole {
        DiskScope::Whole
    } else if held == 0 {
        // No partition capability: the pre-P3 check, refusal and record.
        if !cap_check(CapKind::Disk, 0, need_write) { return Err(E_PERM); }
        DiskScope::Whole
    } else if other != 0 {
        let prior = DISK_SCOPE_REFUSALS.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        record_cap_denial(CapKind::Disk, held, need_write);
        if prior < 8 {
            let op = if need_write { "write" } else { "read" };
            match what {
                Some((sector, count)) => azos_drv_sys::kwarn!(
            "[DISK] scope: tid {} holds partitions {} and {}: refused ambiguous {} LBA {}+{}",
                    tid, held - 1, other - 1, op, sector, count),
                None => azos_drv_sys::kwarn!(
            "[DISK] scope: tid {} holds partitions {} and {}: refused ambiguous size",
                    tid, held - 1, other - 1),
            }
        }
        return Err(E_PERM);
    } else {
        DiskScope::Part(held - 1)
    };
    if need_write && untyped_write_contained() {
        return Err(Errno::EAGAIN.to_syscall_ret());
    }
    Ok(scope)
}

// The partition selector that means "my only disk capability" (see
// `disk_scope`). `CAP_NULL`: no handle a table issues is 0.
use azos_abi::syscall_nr::DISK_SEL_ONLY;
const _: () = assert!(DISK_SEL_ONLY == azos_abi::cap::CAP_NULL.as_raw() as u64);

/// Which absolute sectors does the caller's `[sector, sector + count)` name,
/// and may it touch them? `Ok(lba)` is the absolute first sector to hand the
/// device; `Err(errno)` a refusal, already recorded where one is due.
///
/// The authority comes from [`disk_scope`] (the selector `sel`). Then:
///
/// * `Whole` — a kernel task, or a holder of the whole-disk resource 0:
///   `sector` is an absolute LBA and is admitted, exactly as before RFC-0048
///   P3;
/// * `Part(n)` — a partition-scoped `Cap<Disk>` (resource `n + 1`, minted
///   only by topology — `crates/core/ipc/src/disk_cap.rs`): `sector` is RELATIVE
///   to that partition (owner decision, round 23) — the kernel adds the
///   partition's start, so the holder cannot even name a sector outside it.
///   A run that reaches past the partition's length, or overflows, is
///   **refused and recorded** — a `SAFETY_CAP_DENIED` record for `Disk`
///   through the same recorder `cap_check` uses (its target stays 0, the
///   frozen record format), a count in `DISK_SCOPE_REFUSALS`, and a console
///   line that only this path prints — with `E_PERM`.
fn disk_lba(sel: u64, sector: u64, count: u64, need_write: bool) -> Result<u64, i64> {
    let part = match disk_scope(sel, need_write, Some((sector, count)))? {
        DiskScope::Whole => return Ok(sector),
        DiskScope::Part(p) => p,
    };
    if let Some(lba) = azos_drv_block::partition::resolve(part, sector, count) {
        return Ok(lba);
    }
    let prior = DISK_SCOPE_REFUSALS.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    record_cap_denial(azos_abi::cap::CapKind::Disk, part.saturating_add(1), need_write);
    // The console line is for the first few only: a ring-3 loop must not be
    // able to flood the UART. The record (rate-limited by its own limiter)
    // and the counter keep every one.
    if prior < 8 {
        azos_drv_sys::kwarn!(
        "[DISK] scope: tid {} partition {} refused {} LBA {}+{}",
            azos_sched::current_task_tid(), part,
            if need_write { "write" } else { "read" }, sector, count);
    }
    Err(E_PERM)
}

/// `SYS_DISK_READ` (281): a0 = sector, a1 = sector count, a2 = buffer,
/// a3 = partition selector ([`disk_scope`]: a `Cap<Disk>` handle, or 0 for
/// the caller's only disk capability).
pub fn sys_disk_read(sector: u64, count: u64, buf: u64, sel: u64) -> i64 {
    // Gate before the bounds checks, not after: an unauthorised caller must
    // not learn the medium's geometry from the difference between -1 and
    // E_PERM. This handler was bounds-checked and never permission-checked,
    // so any task could read every sector on the disk.
    let sector = match disk_lba(sel, sector, count, false) { Ok(l) => l, Err(e) => return e };
    // Validate: null pointer, sane count, overflow.
    if buf == 0 || count == 0 || count > DISK_MAX_SECTORS { return -1; }
    let byte_len = (count as usize).checked_mul(512).unwrap_or(0);
    if byte_len == 0 || byte_len > DISK_BOUNCE_BYTES { return -1; }
    // Bounce: read into kernel stack first, copy_to_user validates user ptr.
    // Without this, a malicious user could pass a kernel address and the
    // VirtIO driver would DMA-write into kernel memory.
    // A `PiMutex`, same reasoning as `CAM_BUF` below, and held across BOTH the
    // driver call and the copy out.
    //
    // It was a `static mut` taken by `addr_of_mut!`, justified by a SAFETY
    // comment claiming "only one disk syscall in flight per CPU (syscalls run
    // with preemption disabled in the kernel half)". **Nothing disables
    // preemption on the ecall path** — grep `kernel/src/main.rs`; there is no
    // such guard — and `blk::read` scopes `BLK_LOCK` to its own body, so the
    // lock is already released when the copy below runs. Two harts therefore
    // raced here: A's sectors landed in the buffer, B overwrote the whole
    // buffer, and A copied B's data into A's caller. Two `&mut` from
    // `addr_of_mut!` alive at once is also aliasing UB. `sys_disk_write` was
    // worse: A filled the buffer, B overwrote it, and A wrote B's bytes to A's
    // sector — the sectors below the partition table are the flight recorder
    // and the boot image. Found by the 2026-09-19 user-pointer audit.
    static DISK_RD_BUF: PiMutex<[u8; DISK_BOUNCE_BYTES]> =
        PiMutex::new([0u8; DISK_BOUNCE_BYTES]);
    let mut kbuf = DISK_RD_BUF.lock();
    match azos_drv_virtio::virtio::blk::read(sector, count as u32, &mut kbuf[..byte_len]) {
        Ok(()) => {
            if !azos_sched::copy_to_user(buf as usize, kbuf.as_ptr(), byte_len) {
                return -1;
            }
            0
        }
        Err(()) => -1,
    }
}

/// `SYS_DISK_WRITE` (282): a0 = sector, a1 = sector count, a2 = buffer,
/// a3 = partition selector, as [`sys_disk_read`].
pub fn sys_disk_write(sector: u64, count: u64, buf: u64, sel: u64) -> i64 {
    // `need_write`, and gated first. Sector 0 is the partition table; below it
    // is the filesystem the flight recorder writes to and the loader boots
    // from. Ungated, one call destroyed all three.
    let sector = match disk_lba(sel, sector, count, true) { Ok(l) => l, Err(e) => return e };
    if buf == 0 || count == 0 || count > DISK_MAX_SECTORS { return -1; }
    let byte_len = (count as usize).checked_mul(512).unwrap_or(0);
    if byte_len == 0 || byte_len > DISK_BOUNCE_BYTES { return -1; }
    // Held across the copy in AND the driver call: see `sys_disk_read`'s buffer
    // for the race this closes, which on the write side corrupted the sector.
    static DISK_WR_BUF: PiMutex<[u8; DISK_BOUNCE_BYTES]> =
        PiMutex::new([0u8; DISK_BOUNCE_BYTES]);
    let mut kbuf = DISK_WR_BUF.lock();
    if !azos_sched::copy_from_user(kbuf.as_mut_ptr(), buf as usize, byte_len) {
        return -1;
    }
    let r = azos_drv_virtio::virtio::blk::write(sector, count as u32, &kbuf[..byte_len]);
    // The FAT32 block cache may hold these sectors (a partition holder can
    // write the mounted volume's own partition): tell it, after the device
    // answered and whatever it answered. `virtio::blk` is called directly
    // here, so `blkdev::write`'s own report does not happen. Takes only the
    // cache's leaf lock, under `DISK_WR_BUF`.
    azos_drv_block::blkdev::note_external_write(sector, count as u32);
    match r {
        Ok(()) => 0,
        Err(()) => -1,
    }
}

/// `SYS_DISK_SIZE` (283): a0 = partition selector ([`disk_scope`]). The
/// size, in 512-byte sectors, of what the selector names: the whole medium
/// for a kernel task or a whole-disk holder, the PARTITION for a partition
/// holder (wave 10, owner decision: it was ungated and reported the whole
/// medium to everyone). Needs READ; refused as the disk reads are refused.
pub fn sys_disk_size(sel: u64) -> i64 {
    match disk_scope(sel, false, None) {
        Ok(DiskScope::Whole) => azos_drv_virtio::virtio::blk::capacity_sectors() as i64,
        Ok(DiskScope::Part(p)) => match azos_drv_block::partition::partition(p) {
            Some((_, len)) => len as i64,
            // A capability can name only a published partition, and the table
            // is published once; a missing one is not an answer to guess.
            None => azos_abi::error::Errno::ENODEV.to_syscall_ret(),
        },
        Err(e) => e,
    }
}

pub fn sys_disk_info() -> i64 {
    let secs = azos_drv_virtio::virtio::blk::capacity_sectors();
    azos_drv_sys::kconsoleln!("[DISK] {} sectors ({} MB)", secs, secs / 2048);
    0
}

// ── Signals ───────────────────────────────────────────────────────────────────

/// SYS_KILL: send signal `signum` to task `tid`.
pub fn sys_kill(tid: u64, signum: u64) -> i64 {
    signal_send(tid as u32, signum as u32) as i64
}

/// SYS_SIGNAL: set signal handler for current task.
/// a0 = signum, a1 = handler fn ptr (SIG_DFL=0, SIG_IGN=1, or fn addr).
pub fn sys_signal(signum: u64, handler: u64) -> i64 {
    signal_set_handler(signum as u32, handler as usize) as i64
}

/// SYS_SIGPENDING: return bitmask of pending (unblocked) signals.
pub fn sys_sigpending() -> i64 {
    signal_pending() as i64
}

/// SYS_SIGPROCMASK: get/set signal mask.
/// a0 = how (0=GET, 1=SET, 2=BLOCK, 3=UNBLOCK), a1 = mask, returns old mask.
pub fn sys_sigprocmask(how: u64, mask: u64) -> i64 {
    let old = signal_get_mask();
    match how {
        0 => { /* GET — return old mask, no change */ }
        1 => { signal_set_mask(mask as u32); }
        2 => { signal_set_mask(old | mask as u32); }    // SIG_BLOCK
        3 => { signal_set_mask(old & !(mask as u32)); } // SIG_UNBLOCK
        _ => {}
    }
    old as i64
}

// ── Pipes ─────────────────────────────────────────────────────────────────────

/// SYS_PIPE: create a pipe.  a0 = pointer to int[2] { read_fd, write_fd }.
/// Returns 0 on success, -1 on failure.
pub fn sys_pipe(pipefd_ptr: u64) -> i64 {
    match pipe_create() {
        None => -1,
        Some((ridx, widx)) => {
            if pipefd_ptr != 0 {
                // Boundary rule: write the two fds through copy_to_user when a
                // user process is calling. A raw write would bypass SUM and
                // pointer validation (the user could pass a kernel VA).
                let fds: [u32; 2] = [ridx as u32, widx as u32];
                let bytes = unsafe {
                    core::slice::from_raw_parts(fds.as_ptr() as *const u8,
                                                core::mem::size_of_val(&fds))
                };
                if azos_sched::current_user_pt() != 0 {
                    if !azos_sched::copy_to_user(pipefd_ptr as usize,
                                                    bytes.as_ptr(), bytes.len()) {
                        // Pipe was already created; we leak the two fds rather
                        // than half-undo. Returning -1 is honest about the
                        // copy-out failure.
                        return -1;
                    }
                } else {
                    let ptr = pipefd_ptr as *mut u32;
                    unsafe {
                        core::ptr::write(ptr,        ridx as u32);
                        core::ptr::write(ptr.add(1), widx as u32);
                    }
                }
            }
            0
        }
    }
}

// ── Service manager ───────────────────────────────────────────────────────────

/// Max service-name length copied from userspace.
const SYS_SERVICE_NAME_MAX: usize = 64;

/// `SAFETY_SERVICE_REFUSED` action codes.
pub const SERVICE_OP_REGISTER: u8 = 1;
pub const SERVICE_OP_STOP: u8 = 2;
pub const SERVICE_OP_HEARTBEAT: u8 = 3;

/// The kind code a service refusal spends the per-task denial budget under.
/// Outside the frozen `CapKind` numbering like the other `DENIAL_KIND_*`, and
/// in the capability class (`denial_class`'s default arm): it is an authority
/// denial, and a fourth class would widen every task's budget entry.
pub const DENIAL_KIND_SERVICE: u8 = 0xFC;

static SERVICE_REFUSED_RECORDER: azos_sync::SpinLock<Option<fn(u8, u32)>> =
    azos_sync::SpinLock::new(None);

/// Install the service-refusal recorder. Called once at boot.
pub fn set_service_refused_recorder(f: fn(op: u8, detail: u32)) {
    *SERVICE_REFUSED_RECORDER.lock() = Some(f);
}

/// Record one refused service call (bounded per task) and return `E_PERM`.
fn refuse_service(op: u8, detail: u32) -> i64 {
    let r = *SERVICE_REFUSED_RECORDER.lock();
    if let Some(f) = r {
        if admit_denial_record(DENIAL_KIND_SERVICE) {
            f(op, detail);
        }
    }
    E_PERM
}

/// SYS_SERVICE_REGISTER: a0 = name_ptr, a1 = tid, a2 = ipc_channel.
///
/// The service is registered to the CALLER. `a1` must be the caller's own TID
/// or 0; anything else is refused and recorded. It used to be registered
/// as-is, so any task could publish a name that `discover` then resolved to
/// another task — every client of that name routed to a TID of the caller's
/// choosing.
pub fn sys_service_register(name_ptr: u64, tid: u64, channel: u64) -> i64 {
    if name_ptr == 0 { return -1; }
    let caller = azos_sched::current_task_tid();
    if tid != 0 && tid != caller as u64 {
        return refuse_service(SERVICE_OP_REGISTER, tid as u32);
    }
    let mut buf = [0u8; SYS_SERVICE_NAME_MAX];
    let name = match copy_path_from_user(&mut buf, name_ptr) { Some(n) => n, None => return -1 };
    service_register(name, caller, channel as u32) as i64
}

/// SYS_SERVICE_DISCOVER: a0 = name_ptr.  Returns tid on success, -1 if not found.
pub fn sys_service_discover(name_ptr: u64) -> i64 {
    if name_ptr == 0 { return -1; }
    let mut buf = [0u8; SYS_SERVICE_NAME_MAX];
    let name = match copy_path_from_user(&mut buf, name_ptr) { Some(n) => n, None => return -1 };
    match service_discover(name) {
        Some(entry) => entry.tid as i64,
        None        => -1,
    }
}

/// SYS_SERVICE_HEARTBEAT: a0 = name_ptr. Owner only — see `service_heartbeat_as`.
pub fn sys_service_heartbeat(name_ptr: u64) -> i64 {
    if name_ptr == 0 { return -1; }
    let mut buf = [0u8; SYS_SERVICE_NAME_MAX];
    let name = match copy_path_from_user(&mut buf, name_ptr) { Some(n) => n, None => return -1 };
    match service_heartbeat_as(name, azos_sched::current_task_tid()) {
        (SERVICE_NOT_OWNER, owner) => refuse_service(SERVICE_OP_HEARTBEAT, owner),
        (rc, _) => rc as i64,
    }
}

/// SYS_SERVICE_STOP: a0 = name_ptr. Owner only: it used to stop any service
/// by name, so any task could take down any other's.
pub fn sys_service_stop_handler(name_ptr: u64) -> i64 {
    if name_ptr == 0 { return -1; }
    let mut buf = [0u8; SYS_SERVICE_NAME_MAX];
    let name = match copy_path_from_user(&mut buf, name_ptr) { Some(n) => n, None => return -1 };
    match service_stop_as(name, azos_sched::current_task_tid()) {
        (SERVICE_NOT_OWNER, owner) => refuse_service(SERVICE_OP_STOP, owner),
        (rc, _) => rc as i64,
    }
}

// ── GPIO ──────────────────────────────────────────────────────────────────────

pub fn sys_gpio_info() -> i64 {
    gpio_info(); 0
}

// ── PWM ───────────────────────────────────────────────────────────────────────

/// Is this PWM channel wired to a motor?
///
/// A motor's PWM channel must not be reachable through the PWM API at all: the
/// motor path runs every command through `gate_speed` — the e-stop latch and
/// the RFC-0033 envelope — and a duty written straight to the channel arrives
/// below both. That is the actuation gate bypassed, on the exact hardware the
/// gate exists to hold.
///
/// `sys_pwm_dispatch_inner` (the shared helper behind all five
/// `SYS_PWM_*_TYPED`) checks it, and so does `sys_drv_invoke`. The topology
/// declares `pwm.4` for autorun, and `pwm.0` under `cap-refusal-canary`, which
/// is channel 0 and motor 0's: the guard is what keeps that grant off the wheel.
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
/// untyped PWM calls were retired in RFC-0040 gap 1). Duty is deliberately NOT routed
/// through here: `PWMCMP` is genuinely per-channel on this part, so a duty
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

pub fn sys_pwm_info() -> i64 {
    pwm_info(); 0
}

// ── I2C ───────────────────────────────────────────────────────────────────────

pub fn sys_i2c_scan(bus: u64) -> i64 {
    // SC-1: require an I2C cap on the bus to enumerate it; an ungated scan
    // lets an unprivileged process probe the bus.
    if !cap_check(azos_abi::cap::CapKind::I2c, i2c_resource(bus, 0), true) { return E_PERM; }
    i2c_scan(bus as u8); 0
}

/// The resource a `Cap<I2c>` stores for `(bus, addr)`: `bus << 8 | addr`, the
/// packing `i2c_grant_cap` writes (`crates/core/ipc/src/i2c_cap.rs`, private there).
/// Both arguments narrowed to `u8` first, as the driver call narrows them, so
/// the capability checked is the one for the bus and address actually used.
#[inline]
const fn i2c_resource(bus: u64, addr: u64) -> u32 {
    ((bus as u8 as u32) << azos_ipc::i2c_cap::I2C_RES_BUS_SHIFT) | addr as u8 as u32
}

pub fn sys_i2c_info() -> i64 {
    i2c_info(); 0
}

// ── Motor ─────────────────────────────────────────────────────────────────────

/// SYS_MOTOR_CREATE: a0=id, a1=pwm_ch, a2=dir_pin_a, a3=dir_pin_b.
///
/// **Kernel callers only bind a motor.** A ring-3 caller gets `E_PERM` whatever
/// its table holds: `Motor(id)` is checked first, and a holder is then refused
/// on the PWM channel with the record that refusal has always written.
pub fn sys_motor_create(id: u64, pwm_ch: u64, dir_a: u64, dir_b: u64) -> i64 {
    use azos_abi::cap::CapKind;
    if !cap_check(CapKind::Motor, id as u32, true) { return E_PERM; }
    // The `Motor` capability authorises driving motor `id`. It does NOT
    // authorise picking which PWM channel and which two GPIO pins that motor
    // is wired to. Until 2026-09-05 this handler let the caller choose all
    // three freely; then it asked for write capabilities on the channel and
    // both pins.
    //
    // **Why ring 3 is refused here and not asked for those three.** A
    // capability over a channel or a pin does not make binding a motor to it
    // safe. `motor_init` rebinds with no check, and the binding is what
    // `pwm_channel_motor_id` and `gpio_pin_motor_id` answer from, so rebinding
    // motor 0 away from its channel takes that channel out of the motor-bound
    // guard: a PWM duty write would then reach the H-bridge below
    // `gate_speed`, the e-stop latch and the envelope. The topology grants
    // autorun `pwm.4` and `gpio.20`, and `pwm.0` and `gpio.0` under
    // `cap-refusal-canary`, so answering from the capability table would open
    // exactly that. The old handle table never held a PWM or GPIO entry for
    // ring 3, so every ring-3 call was refused before; this keeps the refusal
    // and its record. No ring-3 program binds a motor: the kernel binds both
    // wheels at boot (`robot_init`).
    if azos_sched::current_user_pt() != 0 {
        record_cap_denial(CapKind::Pwm, pwm_ch as u8 as u32, true);
        return E_PERM;
    }
    motor_init(id as u32, pwm_ch as u32, dir_a as u32, dir_b as u32) as i64
}

/// `motor_set_reporting`'s return code as a syscall answer.
///
/// A forward or backward command refused while an e-stop is latched or
/// containment is armed (`MOTOR_REFUSED_HALTED`) answers `E_CONTAINED`, the
/// answer every contained write gives; any other code passes through. The
/// refusal itself is made in the motor layer, which the typed motor handlers
/// below reach, so the answer for one physical request does not depend on the
/// call that made it.
#[inline]
fn motor_rc_ret(rc: i32) -> i64 {
    if rc == azos_robot::MOTOR_REFUSED_HALTED { E_CONTAINED } else { rc as i64 }
}

/// Set wheel `id`'s direction at 50 % duty, and print the readback marker.
///
/// The body of `SYS_MOTOR_DIRECTION_TYPED` (576) below its authority check.
/// Direction 0 forward, 1 backward, 2 brake, 3 coast; any other value answers
/// `-EINVAL` before anything reaches the motor layer (owner decision, gap 1
/// Q5), so no pin is written and no marker printed. While an e-stop is latched
/// or containment is armed the motor layer carries out brake and coast and
/// refuses forward and backward (`motor_rc_ret`).
fn motor_direction_reporting(id: u32, dir: u64) -> i64 {
    let d = match dir {
        0 => MotorDir::Forward,
        1 => MotorDir::Backward,
        2 => MotorDir::Brake,
        3 => MotorDir::Coast,
        _ => return azos_abi::error::Errno::EINVAL.to_syscall_ret(),
    };
    let (rc, applied) = motor_set_reporting(id, d, 50);  // default 50% speed
    crate::motor_commander::note_current(id, applied);
    let r = motor_rc_ret(rc);

    // Same readback marker as `sys_motor_speed_typed`, and reflex is why it
    // has to be HERE too.
    //
    // `userspace/services/reflex` reacts to an obstacle by BACKING UP, and reverse is a
    // direction command: `apply_motor_cmd` and `motor_backup` send it down this
    // path, because `SYS_MOTOR_ENABLE_TYPED` is `motor_pid_enable`, an
    // unrelated operation despite the name. So the speed marker sees only
    // reflex's stops — measured 2026-09-09, and every one of them reads
    // `ask=0 duty=0`, which a handler stubbed to do nothing prints
    // identically. The actuation that scenario exists to prove is the reverse,
    // and it lands here.
    //
    // The duty is what `motor_set_reporting` says the write left on the
    // channel, not the 50 above: `motor_set` clamps through `gate_speed`, so a
    // latched e-stop or a tightened envelope shows up as a smaller number
    // rather than as a missing line.
    //
    // Reachable only by `ecall`, like its typed sibling, so the marker cannot
    // be produced by a kernel task. One call prints one line.
    #[cfg(feature = "actuation-smoke")]
    {
        let duty = applied.map(|d| d as i64).unwrap_or(-1);
        azos_drv_sys::kprintln!(
            "[ACTSMOKE] ring3 motor id={} dir={} duty={} rc={}", id, dir, duty, r);
    }
    #[cfg(not(feature = "actuation-smoke"))]
    let _ = applied;
    r
}

/// `SYS_MOTOR_SPEED_TYPED` (560): a0=cap, a1=speed_pct (0 stops).
///
/// The typed form of the retired `SYS_MOTOR_SPEED` (232), and its mirror below
/// the capability check: `motor_stop_reporting` / `motor_set_reporting`, which
/// also hand back the applied duty, `MotorDir::Forward`, the same return.
/// What makes it safe — `motor_set`'s panic refusal, `gate_speed`'s e-stop
/// latch and envelope — is on the motor layer's path and is not restated here.
///
/// **The wheel comes from the capability.** There is no id argument, so
/// commanding a wheel the caller does not hold is not expressible. Same shape
/// as `SYS_DRIVER_REGISTER_TYPED` having no kind argument.
///
/// **No pair rule, and that is the point rather than an omission.** The five
/// PID calls (550-555) demand WRITE on both wheels because they command the
/// drivetrain in one operation. This one commands one wheel, exactly as 232
/// did; requiring both would have made the typed path stricter than the
/// untyped path it replaced — an authority change smuggled inside a
/// migration.
pub fn sys_motor_speed_typed(cap_raw: u64, speed_pct: u64) -> i64 {
    use azos_abi::cap::CapHandle;
    use azos_abi::error::Errno;
    use azos_ipc::cap::{targets::Motor, Cap};

    let cap: Cap<Motor> = Cap::from_raw(CapHandle::from_raw(cap_raw as u32));
    let tid = azos_sched::current_task_tid();
    let id = match azos_ipc::cap_store::with_table(tid, |t| {
        azos_ipc::motor_cap::motor_speed_cap_id(t, cap)
    }) {
        Some(Ok(id)) => id,
        Some(Err(e)) => return errno_for_motor_err(e),
        None => return Errno::EINVAL.to_syscall_ret(),
    };
    let (rc, applied) = if speed_pct == 0 {
        motor_stop_reporting(id)
    } else {
        motor_set_reporting(id, MotorDir::Forward, speed_pct as u32)
    };
    crate::motor_commander::note(id, tid, applied);
    let r = motor_rc_ret(rc);

    // The marker that says ring 3 COMMANDED a motor, not merely that it ran.
    //
    // **It reports the duty the write itself left on the channel, not the
    // value that was asked for.** A first version printed `id`, `speed` and
    // the return code, and it had exactly the defect this whole feature exists
    // to avoid: those three are all known before the actuation, so a handler
    // stubbed to return 0 without driving anything would print an identical
    // line. That is the same shape as the marker tried on 2026-09-07 at the
    // actuation gate, which fired ~2300 times a boot whether or not the typed
    // call did anything (2328 baseline vs 2308 stubbed).
    //
    // **And it comes out of the call, not from reading the channel back
    // afterwards.** A `pwm_get` here would be a second acquisition, and these
    // channels have a second writer: `rt_motor_task` drives the same two
    // wheels every control tick, so between the write and the read its duty
    // can be what comes back. `motor_set_reporting` reads inside the critical
    // section that performs the write, which is the only way `ask` and `duty`
    // can be asserted to AGREE without the assertion itself being a race.
    //
    // The gap between the two is also where the safety envelope shows up,
    // since `gate_speed` clamps before the duty write.
    //
    // Only under `actuation-smoke`, and off in every shipped build: this is on
    // the actuation path and a UART write costs ~160 us per 64 bytes under
    // QEMU.
    #[cfg(feature = "actuation-smoke")]
    {
        let duty = applied.map(|d| d as i64).unwrap_or(-1);
        azos_drv_sys::kprintln!(
            "[ACTSMOKE] ring3 motor id={} ask={} duty={} rc={}",
            id, speed_pct, duty, r);
    }
    #[cfg(not(feature = "actuation-smoke"))]
    let _ = applied;
    r
}

/// `SYS_MOTOR_DIRECTION_TYPED` (576): a0=cap (`Cap<Motor>`), a1=direction
/// (0 forward, 1 backward, 2 brake, 3 coast).
///
/// The typed form of the retired `SYS_MOTOR_ENABLE` (231). **The wheel comes
/// from the capability**, which needs `WRITE`, resolved without a containment
/// step and with no pair rule, as `sys_motor_speed_typed` (560) resolves it:
/// the motor layer's halt rule decides, so while an e-stop is latched or
/// containment is armed a brake or coast is carried out and a forward or
/// backward answers `-EAGAIN`. Below the capability it is
/// `motor_direction_reporting`, the `[ACTSMOKE] ring3 motor id= dir=` marker
/// included.
///
/// In order: a refused capability answers `-ECAPSTALE`, `-ECAPKIND` or
/// `-ECAPPERMS` and writes one `SAFETY_CAP_DENIED_TYPED` record; a direction
/// of 4 or more answers `-EINVAL` with no record, no pin written and no marker
/// (231 coasted there); once admitted, 0, `-EAGAIN` for a direction refused
/// while halted, or the motor layer's negative code.
pub fn sys_motor_direction_typed(cap_raw: u64, dir: u64) -> i64 {
    use azos_abi::cap::CapHandle;
    use azos_abi::error::Errno;
    use azos_ipc::cap::{targets::Motor, Cap};

    let cap: Cap<Motor> = Cap::from_raw(CapHandle::from_raw(cap_raw as u32));
    let tid = azos_sched::current_task_tid();
    let id = match azos_ipc::cap_store::with_table(tid, |t| {
        azos_ipc::motor_cap::motor_speed_cap_id(t, cap)
    }) {
        Some(Ok(id)) => id,
        Some(Err(e)) => return errno_for_motor_err(e),
        None => return Errno::EINVAL.to_syscall_ret(),
    };
    motor_direction_reporting(id, dir)
}

/// `SYS_MOTOR_ANGLE_TYPED` (578): a0=cap (`Cap<Motor>`), a1=out_ptr.
///
/// The typed form of the retired `SYS_MOTOR_ANGLE` (233). The wheel comes from
/// the capability, which needs `READ`; containment leaves a read live. The
/// wheel's accumulated encoder ticks are written through `out_ptr` as 8 bytes,
/// `i64` little-endian, and the return is 0 or `-errno`, so a refusal cannot be
/// read as a tick count the way 233's `-1` and `-99` could.
///
/// In order: the capability (`-ECAPSTALE` / `-ECAPKIND` / `-ECAPPERMS`, one
/// `SAFETY_CAP_DENIED_TYPED` record), a wheel with no encoder (`-EINVAL`: only
/// 0 and 1 have one), then the pointer (`-EFAULT` unless all 8 bytes are a
/// mapped user-writable range; nothing is read from the encoders before the
/// capability and the wheel are known). The capability is resolved before the
/// pointer so a forged handle is one record, whatever pointer it came with.
pub fn sys_motor_angle_typed(cap_raw: u64, out_ptr: u64) -> i64 {
    use azos_abi::cap::{CapHandle, CapPerms};
    use azos_abi::error::Errno;
    use azos_ipc::cap::{targets::Motor, Cap};
    use azos_ipc::motor_cap::MotorCapError;

    let cap: Cap<Motor> = Cap::from_raw(CapHandle::from_raw(cap_raw as u32));
    let tid = azos_sched::current_task_tid();
    let wheel = match azos_ipc::cap_store::with_table(tid, |t| t.get(cap, CapPerms::READ)) {
        Some(Ok(w)) => w,
        Some(Err(e)) => return errno_for_motor_err(MotorCapError::Cap(e)),
        None => return Errno::EINVAL.to_syscall_ret(),
    };
    if wheel > 1 {
        return Errno::EINVAL.to_syscall_ret();
    }
    if out_ptr == 0 {
        return Errno::EFAULT.to_syscall_ret();
    }
    let (ticks_l, ticks_r) = azos_robot::encoder_read();
    let ticks = if wheel == 0 { ticks_l } else { ticks_r };
    let bytes = ticks.to_le_bytes();
    if !azos_sched::copy_to_user(out_ptr as usize, bytes.as_ptr(), bytes.len()) {
        return Errno::EFAULT.to_syscall_ret();
    }
    0
}

pub fn sys_motor_info() -> i64 {
    motor_info(); 0
}

/// `SYS_ROBOT_ESTOP` (325): emergency stop from ring 3. No arguments.
///
/// **This was a stub until 2026-09-10, and the stub WAS the hole.** The ABI
/// has declared the call since the robot block was written and `libsys`
/// exposes it as `robot_estop()`, but `dispatch` collapsed the whole
/// `SYS_ROBOT_INIT ..= SYS_SENSOR_ADD` range into `sys_stub()` — so the one
/// call a userspace program had for "stop everything, now" returned -1 and did
/// nothing. `userspace/services/brain_client` consequently mapped the brain's
/// `FLAG_EMERGENCY` onto two ordinary `motor_speed_typed(cap, 0)` calls, which
/// the kernel cannot tell apart from "please go at 0%". Measured on the ring-3
/// product path: the emergency arrived, the wheels went to zero, and the whole
/// boot log contained no e-stop record of any kind — no latch, no ESC disarm,
/// nothing in the black box. The same intent arriving as `PKT_ESTOP` on the
/// kernel's own link latched, disarmed and wrote a durable record. An
/// emergency must not depend on which door it came through.
///
/// **What it does now is what `PKT_ESTOP` does**: latch the e-stop (so
/// `motor_envelope` returns `(0,0)` for every later command, from any path),
/// stop both wheels, disarm the ESC, and write a DURABLE `SAFETY_ESTOP`
/// record. Rearming stays an operator action — `MODE_ID_ESTOP_RESET` — exactly
/// as for the other three sources: a program that can stop the machine still
/// does not get to decide it is safe to resume.
///
/// **The capability rule: stopping must never demand more authority than
/// driving.** WRITE on ANY motor is enough — not all of them, and not a
/// separate e-stop capability. Whoever is entitled to spin a wheel is entitled
/// to stop the drivetrain; the opposite rule builds a machine a program can
/// start and cannot stop.
///
/// Returns 0 only when the stop was carried out, `E_PERM` when the caller
/// holds no motor at all, and -1 when no handler is installed (the pre-boot
/// window). It never returns success for a stop that did not happen — a
/// missing denial recorder costs a log line, a missing e-stop would be a lie
/// about the one thing this call exists to promise.
pub fn sys_robot_estop() -> i64 {
    // One presence test over the caller's table for WRITE on ANY motor, not a
    // `cap_check` per wheel: `cap_check` records a denial on every miss, so a
    // caller holding only wheel 1 would write a spurious `SAFETY_CAP_DENIED`
    // for wheel 0 into the black box on its way to being ALLOWED. One record,
    // and only if nothing matched.
    //
    // `holds_kind_with`, which consults no containment and no resource. An
    // e-stop is issued exactly when something has gone wrong, which is when
    // degraded mode is likely armed; asking containment would refuse the stop
    // to the task entitled to drive. And a per-resource test would tie the
    // stop to the wheel ids a caller happens to name.
    if azos_sched::current_user_pt() != 0 {
        use azos_abi::cap::{CapKind, CapPerms};
        let tid = azos_sched::current_task_tid();
        let holds = azos_ipc::cap_store::with_table(tid, |t| {
            t.holds_kind_with(CapKind::Motor, CapPerms::WRITE)
        })
        .unwrap_or(false);
        if !holds {
            // Wheel 0 stands for the drivetrain in the record because the call
            // has no id argument to name a better one — the same reason
            // `sys_motor_speed_typed` takes its wheel from the capability
            // instead of from `a0`.
            record_cap_denial(CapKind::Motor, 0, true);
            return E_PERM;
        }
    }
    let h = *ESTOP_HANDLER.lock();
    match h {
        Some(f) => { f(); 0 }
        None    => -1,
    }
}

// ── Memory management (Phase 7) ───────────────────────────────────────────────

/// SYS_BRK: a0 = new brk address (0 = query current brk).
/// Returns the new (or current) brk address.
pub fn sys_brk(addr: u64) -> i64 {
    // Wave 13: one layout change at a time per thread group.
    let _mm = azos_sched::group::mm_lock();
    azos_sched::sys_brk_impl(addr)
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
/// calls (retired in RFC-0040 gap 1): the owner is stamped at create/accept
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
    // For user-space callers, copy via page tables; kernel callers use raw ptr.
    let mut raw = [0u8; 16];
    if azos_sched::current_user_pt() != 0 {
        if !azos_sched::copy_from_user(raw.as_mut_ptr(), ptr as usize, 16) {
            return None;
        }
    } else {
        let src = unsafe { core::slice::from_raw_parts(ptr as *const u8, 16) };
        raw.copy_from_slice(src);
    }
    let family = u16::from_le_bytes([raw[0], raw[1]]);
    let port   = u16::from_be_bytes([raw[2], raw[3]]);
    let addr   = [raw[4], raw[5], raw[6], raw[7]];
    Some(SockAddr { family, port, addr })
}

/// SYS_SOCKET: a0=domain, a1=type, a2=proto. Returns socket fd or -1.
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

/// SYS_BIND: a0=fd, a1=sockaddr_ptr, a2=addrlen. Returns 0 or -1.
pub fn sys_bind(fd: u64, addr_ptr: u64, _addrlen: u64) -> i64 {
    // Ownership gate: binding another task's socket would let an attacker
    // steer the port it is about to listen on.
    if !socket_access_ok(fd) { return -1; }
    match read_sockaddr(addr_ptr) {
        Some(addr) => socket_bind(fd as i32, &addr) as i64,
        None       => -1,
    }
}

/// SYS_LISTEN: a0=fd, a1=backlog (ignored). Returns 0 or -1.
pub fn sys_listen_syscall(fd: u64, _backlog: u64) -> i64 {
    // Ownership gate: without it a task could make another task's socket
    // listen on the port it had bound, hijacking inbound connections.
    if !socket_access_ok(fd) { return -1; }
    socket_listen_bound(fd as i32) as i64
}

/// How long `SYS_ACCEPT` waits for an Established connection before it
/// answers -1, in milliseconds of counter time.
pub(crate) const ACCEPT_WAIT_MS: u64 = 10_000;

/// SYS_ACCEPT: a0=fd, a1=addr_out (ignored), a2=addrlen_out (ignored).
/// Polls until an Established connection is ready, sleeping 1 ms between
/// looks, for at most [`ACCEPT_WAIT_MS`]; returns new fd or -1.
///
/// The bound used to be 50,000 `task_yield()` calls: a count of how much CPU
/// the host gave the guest, not a time, and a yield never hands the hart to a
/// lower-priority task.
pub fn sys_accept(fd: u64, _addr_out: u64, _addrlen_out: u64) -> i64 {
    // Gate + resolve owner ONCE, outside the retry loop: the loop runs up to
    // `ACCEPT_WAIT_MS` looks and each one would otherwise take the `SOCKS` lock
    // just to re-answer a question that cannot change, contending with
    // `net_poll` on every iteration.
    //
    // Denying here stops a task from accepting on a listening fd it does not
    // own, which is the fd-enumeration path this gate exists to close.
    //
    // SCOPE — what this does NOT close (separate, still-open finding):
    // `socket_accept_owned` resolves the listener's `local.port` and calls
    // `tcp::accept(port)`, which is keyed on the **port**, not on the fd or
    // the owner. `socket_bind`'s TCP arm only records the port and
    // `tcp::listen` does not reject a second listener on an already-listening
    // port. So a task can bind a socket it legitimately owns to a port the
    // kernel is already listening on and race for inbound connections — the
    // ownership gate passes because it owns every fd it touches. Closing
    // that needs port-space arbitration in `tcp::listen`, which is a
    // different mechanism and deliberately not attempted here.
    if !socket_access_ok(fd) { return -1; }
    let owner = match socket_owner_for_caller() {
        Some(o) => o,
        None    => return -1,
    };
    let mut accepted = -1i64;
    crate::sleep::wait_until_ms(ACCEPT_WAIT_MS, 1, || {
        azos_net::net_poll();
        // The accepted connection is stamped to the *accepting* task, so the
        // new fd is reachable by this caller and nobody else.
        let r = socket_accept_owned(fd as i32, owner);
        if r >= 0 { accepted = r as i64; }
        r >= 0
    });
    accepted
}

/// SYS_CONNECT: a0=fd, a1=sockaddr_ptr, a2=addrlen.
///
/// `-1` for a socket the caller does not own; `-EAGAIN` while degraded mode is
/// contained, as `SYS_CONNECT_TYPED` answers — choosing where a socket talks
/// to is a write to it.
pub fn sys_connect_syscall(fd: u64, addr_ptr: u64, _addrlen: u64) -> i64 {
    // Ownership gate FIRST — before `fd` is used for anything at all.
    // Two things depend on that ordering:
    //   1. Security: connecting another task's socket redirects its stream
    //      to an attacker-chosen peer.
    //   2. Liveness: the ephemeral source port below is derived from `fd`.
    //      With `overflow-checks = true` and `panic = "abort"`, an
    //      out-of-range `fd` (e.g. 16384, giving 0xC000 + 0x4000 = 65536)
    //      used to overflow the u16 and abort — a full board reset, i.e. a
    //      physical-safety event, reachable by one syscall from any task.
    if !socket_access_ok(fd) { return -1; }
    // Before the address is read: it is copied from user memory.
    if untyped_write_contained() { return E_CONTAINED; }
    // Belt and braces on the port arithmetic: the gate above already bounds
    // `fd` to 0..MAX_SOCKETS, but `saturating_add` means a future reordering
    // of this function cannot reintroduce the panic.
    let src_port = 0xC000u16.saturating_add(fd as u16);
    match read_sockaddr(addr_ptr) {
        // Yield-aware: connect must not report success until the handshake
        // completes, and waiting without yielding would burn the hart.
        Some(addr) => azos_net::socket::socket_connect_with_yield(
            fd as i32, &addr, src_port,
            || crate::sleep::sleep_ms(1),
        ) as i64,
        None       => -1,
    }
}

/// SYS_SEND / SYS_SENDTO: a0=fd, a1=buf_ptr, a2=len, a3=flags (ignored).
///
/// Gated here rather than in `dispatch.rs` because `SYS_SEND` and
/// `SYS_SENDTO` both land on this one handler: one check covers both arms.
/// `SYS_SENDTO`: like `send`, but with an **explicit destination address**.
///
/// **This completes a reserved number, it does not break an existing one.**
/// `SYS_SENDTO` dispatched to the same `sys_send_syscall` as `SYS_SEND`, and
/// `libsys` documented it as "identical to `send`, kept only because the
/// number is claimed". Nobody used the address form, because it did not exist.
///
/// What it unblocks: **unconnected UDP**. Until now a UDP socket could only
/// send after a `connect`, because there was no way to name a destination per
/// call. The machinery below already supported it — `udp::sendto` has taken
/// `dst_ip` and `dst_port` all along — and this layer threw it away.
///
/// `-EAGAIN` while degraded mode is contained, with or without an address —
/// the same refusal `SYS_SEND_TYPED` gives, checked before either copy.
pub fn sys_sendto_syscall(fd: u64, buf_ptr: u64, len: u64, addr_ptr: u64) -> i64 {
    if !socket_access_ok(fd) { return -1; }
    if buf_ptr == 0 || len == 0 { return -1; }
    if untyped_write_contained() { return E_CONTAINED; }
    // With no address it behaves as `send`: that is what it did before, and a
    // caller passing 0 must not start failing because of this change.
    if addr_ptr == 0 { return sys_send_syscall(fd, buf_ptr, len, 0); }
    let addr = match read_sockaddr(addr_ptr) { Some(a) => a, None => return -1 };
    let count = (len as usize).min(1460);
    let mut tmp = [0u8; 1460];
    if !azos_sched::copy_from_user(tmp.as_mut_ptr(), buf_ptr as usize, count) {
        return -1;
    }
    azos_net::socket::socket_sendto(fd as i32, &tmp[..count], &addr) as i64
}

/// `SYS_RECVFROM`: like `recv`, but **reporting the sender**.
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
/// deepest chain in the image, for one `recvfrom` (tools/stack_chain.py,
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
        let mut src = azos_net::socket::SockAddr { family: 2, port: 0, addr: [0; 4] };
        let n = azos_net::socket::socket_recvfrom(fd as i32, &mut tmp[..count], &mut src);
        if n <= 0 { return n as i64; }
        if !azos_sched::copy_to_user(buf_ptr as usize, tmp.as_ptr(), n as usize) {
            return -1;
        }
        // The address is written AFTER the data: if copying the sender out
        // fails, the caller already holds the datagram and loses only the
        // return address, instead of losing both.
        let mut raw = [0u8; 16];
        raw[0..2].copy_from_slice(&src.family.to_le_bytes());
        raw[2..4].copy_from_slice(&src.port.to_be_bytes());
        raw[4..8].copy_from_slice(&src.addr);
        if !azos_sched::copy_to_user(addr_ptr as usize, raw.as_ptr(), 16) {
            return -1;
        }
        n as i64
    }
}

/// SYS_SEND: a0=fd, a1=buf_ptr, a2=len, a3=flags (ignored).
///
/// `-1` for a socket the caller does not own or an empty buffer; `-EAGAIN`
/// while degraded mode is contained, as `SYS_SEND_TYPED` answers.
pub fn sys_send_syscall(fd: u64, buf_ptr: u64, len: u64, _flags: u64) -> i64 {
    // Ownership gate: this is the byte-injection half of the finding — an
    // ungated send lets any task write into another task's outbound stream,
    // e.g. forging commands on the brain link or corrupting an OTA image.
    if !socket_access_ok(fd) { return -1; }
    if buf_ptr == 0 || len == 0 { return -1; }
    if untyped_write_contained() { return E_CONTAINED; }
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
        if !azos_sched::copy_from_user(tmp.as_mut_ptr(), buf_ptr as usize, count) {
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

/// SYS_RECV / SYS_RECVFROM: a0=fd, a1=buf_ptr, a2=len, a3=flags (ignored). Non-blocking.
///
/// Gated here rather than in `dispatch.rs` because `SYS_RECV` and
/// `SYS_RECVFROM` both land on this one handler: one check covers both arms.
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
    azos_net::net_poll();
    recv_bounced(fd, buf_ptr, (len as usize).min(4096))
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
    if n > 0 {
        if azos_sched::current_user_pt() != 0 {
            if !azos_sched::copy_to_user(buf_ptr as usize, tmp.as_ptr(), n as usize) {
                return -1;
            }
        } else {
            unsafe { core::ptr::copy_nonoverlapping(tmp.as_ptr(), buf_ptr as *mut u8, n as usize); }
        }
    }
    n as i64
}

/// SYS_SOCK_SHUTDOWN / close a socket fd. Returns 0, or -1 if the caller
/// does not own `fd`.
pub fn sys_sock_close(fd: u64) -> i64 {
    // Ownership gate: this is the denial-of-service half of the finding — an
    // ungated close tears down another task's connection, and closing the
    // brain link or the OTA channel mid-transfer is a control-plane outage.
    //
    // NOTE the return value: this used to be unconditionally 0. A denied
    // close must report -1, otherwise the caller is told "closed" when
    // nothing happened.
    if !socket_access_ok(fd) { return -1; }
    // A socket a `Cap<Socket>` still names closes only through
    // `SYS_CLOSE_TYPED` — see [`socket_named_by_cap`].
    if socket_named_by_cap(fd) { return -1; }
    socket_close(fd as i32);
    0
}

// ── Cap<Socket> typed handlers (567-570) ─────────────────────────────────────

/// Does the calling ring-3 task still name socket `fd` through a
/// `Cap<Socket>`?
///
/// The same hazard as [`fd_named_by_file_cap`], on the socket table: the
/// capability's resource is the socket index, and an untyped close behind a
/// live capability would free the index for the next socket to take while the
/// capability still named it. Kernel callers hold no capabilities and are not
/// asked.
fn socket_named_by_cap(fd: u64) -> bool {
    use azos_abi::cap::{CapKind, CapPerms};
    if azos_sched::current_user_pt() == 0 || fd > u32::MAX as u64 {
        return false;
    }
    let tid = azos_sched::current_task_tid();
    azos_ipc::cap_store::with_table(tid, |t| {
        t.holds_kind_resource_with(CapKind::Socket, fd as u32, CapPerms::NONE)
    })
    .unwrap_or(false)
}

fn errno_for_socket_err(e: azos_ipc::cap::CapError) -> i64 {
    use azos_abi::error::Errno;
    use azos_ipc::cap::CapError;
    // Every typed refusal in this file reaches the recorder here — the one
    // choke point all twelve of these functions share. `Contained` is filtered
    // inside `note_typed_denial`, not here.
    note_typed_denial(azos_abi::cap::CapKind::Socket, e);
    match e {
        CapError::Stale => Errno::ECAPSTALE.to_syscall_ret(),
        CapError::WrongKind => Errno::ECAPKIND.to_syscall_ret(),
        CapError::MissingPerms => Errno::ECAPPERMS.to_syscall_ret(),
        CapError::Contained => Errno::EAGAIN.to_syscall_ret(),
        CapError::NoSpace => Errno::EMFILE.to_syscall_ret(),
    }
}

/// `SYS_SOCKET_TYPED` (567): a0=domain, a1=type, a2=proto. Creates a socket
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
    // O3.4 (2026-09-26): a socket the task opened itself is giftable (DUP);
    // abitest moves one to epsrv over the 582 exchange.
    match azos_ipc::cap_store::grant::<Socket>(tid, CapPerms::RW.union(CapPerms::DUP), fd as u32) {
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
/// `a5`, `DUP`-gated) and keeps naming the sender's socket index, so the
/// receiver's handle resolves here but the socket is not the receiver's.
fn socket_fd_for(cap_raw: u64, need: azos_abi::cap::CapPerms) -> Result<u64, i64> {
    use azos_abi::cap::CapHandle;
    use azos_abi::error::Errno;
    use azos_ipc::cap::{targets::Socket, Cap};

    let cap: Cap<Socket> = Cap::from_raw(CapHandle::from_raw(cap_raw as u32));
    let tid = azos_sched::current_task_tid();
    match azos_ipc::cap_store::with_table(tid, |t| t.get(cap, need)) {
        Some(Ok(fd)) => Ok(fd as u64),
        Some(Err(e)) => Err(errno_for_socket_err(e)),
        None => Err(Errno::EINVAL.to_syscall_ret()),
    }
}

/// `SYS_CONNECT_TYPED` (568): a0=cap, a1=sockaddr_ptr, a2=addrlen. Requires
/// `WRITE`: choosing where a socket talks to is a write to it.
pub fn sys_connect_typed(cap_raw: u64, addr_ptr: u64, addrlen: u64) -> i64 {
    match socket_fd_for(cap_raw, azos_abi::cap::CapPerms::WRITE) {
        Ok(fd) => sys_connect_syscall(fd, addr_ptr, addrlen),
        Err(e) => e,
    }
}

/// `SYS_SEND_TYPED` (569): a0=cap, a1=buf, a2=len. Requires `WRITE`.
pub fn sys_send_typed(cap_raw: u64, buf_ptr: u64, len: u64) -> i64 {
    match socket_fd_for(cap_raw, azos_abi::cap::CapPerms::WRITE) {
        Ok(fd) => sys_send_syscall(fd, buf_ptr, len, 0),
        Err(e) => e,
    }
}

/// `SYS_RECV_TYPED` (570): a0=cap, a1=buf, a2=len. Requires `READ`.
pub fn sys_recv_typed(cap_raw: u64, buf_ptr: u64, len: u64) -> i64 {
    match socket_fd_for(cap_raw, azos_abi::cap::CapPerms::READ) {
        Ok(fd) => sys_recv_syscall(fd, buf_ptr, len, 0),
        Err(e) => e,
    }
}

// ── Cap<Socket> multicast (571-572) ──────────────────────────────────────────

/// A refusal from the socket layer's multicast calls, as the errno the ABI
/// documents for `SYS_MCAST_JOIN_TYPED` / `SYS_MCAST_LEAVE_TYPED`.
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

/// `SYS_MCAST_JOIN_TYPED` (571): a0=cap, a1=group. Requires `WRITE`: a join
/// changes what the socket receives and puts a Membership Report on the wire.
///
/// The capability is resolved before the group is read, so a forged or
/// contained handle gets the capability's answer whatever group it names —
/// the order the rest of the family keeps with its buffers.
pub fn sys_mcast_join_typed(cap_raw: u64, group: u64) -> i64 {
    let fd = match socket_fd_for(cap_raw, azos_abi::cap::CapPerms::WRITE) {
        Ok(fd) => fd,
        Err(e) => return e,
    };
    let Some(g) = mcast_group_arg(group) else {
        return azos_abi::error::Errno::EINVAL.to_syscall_ret();
    };
    match azos_net::socket::socket_mcast_join(fd as i32, &g) {
        Ok(()) => 0,
        Err(e) => errno_for_mcast_err(e),
    }
}

/// `SYS_MCAST_LEAVE_TYPED` (572): a0=cap, a1=group. Needs only a live
/// `Cap<Socket>` (`CapPerms::NONE`), like `SYS_CLOSE_TYPED`: giving a membership
/// back is cleanup, and containment must not keep a group joined.
pub fn sys_mcast_leave_typed(cap_raw: u64, group: u64) -> i64 {
    let fd = match socket_fd_for(cap_raw, azos_abi::cap::CapPerms::NONE) {
        Ok(fd) => fd,
        Err(e) => return e,
    };
    let Some(g) = mcast_group_arg(group) else {
        return azos_abi::error::Errno::EINVAL.to_syscall_ret();
    };
    match azos_net::socket::socket_mcast_leave(fd as i32, &g) {
        Ok(()) => 0,
        Err(e) => errno_for_mcast_err(e),
    }
}

/// SYS_NET_INFO: print network interface info.
pub fn sys_net_info() -> i64 {
    net_info(); 0
}

/// SYS_NET_GETIP: return IP address as u32 (big-endian).
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
/// Highest real-time `SchedClass` discriminant (SafetyCritical 0, HardRT 1,
/// SoftRT 2).
const RT_CLASS_MAX: u8 = 2;

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

/// SYS_MMAP: anonymous memory mapping.
/// a0=addr (hint, 0=any), a1=length, a2=prot, a3=flags, a4=fd (-1 anon), a5=offset.
/// Returns mapped virtual address, `-EINVAL` for `PROT_EXEC`, or -1 on any
/// other error.
///
/// Wave 14 (DEMANDPAGE): the range is reserved (a region record) and each
/// page committed on its first touch, unless [`mmap_precommit`] says
/// otherwise or the address space has no free record, in which case every
/// page is committed now, as before. Either way the whole request is charged
/// here (reserve-time charging, RFC-0049 M1).
pub fn sys_mmap(addr: u64, length: u64, prot: u64, flags: u64, fd: u64, _offset: u64) -> i64 {
    // Wave 13: one layout change at a time per thread group.
    let _mm = azos_sched::group::mm_lock();
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
    let user_pt = azos_sched::current_user_pt();
    if user_pt == 0 { return -1; } // kernel task

    let len = length as usize;
    if len == 0 { return -1; }
    // Cap the request.  `length` used to be unbounded, so a single
    // `mmap(0, u64::MAX, ..)` from ring 3 drained every free physical page —
    // and because the OOM path below returned without unwinding, the pages
    // already mapped stayed lost for the lifetime of the boot.  Same ceiling
    // `sys_alloc_demand` already enforces, so the two allocators agree on how
    // much one call may claim.
    if len > azos_mm::demand::MAX_DEMAND_ALLOC_BYTES { return -1; }

    let page_size = azos_arch::PAGE_SIZE;
    let num_pages = len.saturating_add(page_size - 1) / page_size;

    // Use brk as base for anonymous mappings, then advance brk
    // **WHY the brk itself has to be checked (null-guard follow-up).** Both
    // brk-based allocators take `update_user_brk(0)` as their base, and a task
    // whose brk was never initialised reports **0** (`scheduler.rs` zeroes
    // `user_brk` at task creation). The range was then reserved starting at VA
    // 0 and the syscall answered `0` — a *successful* allocation whose base is
    // the null pointer. Callers cannot tell that apart from a real address.
    //
    // `vmm::USER_GUARD_LIMIT` now makes the first access to such a pointer kill
    // the task instead of quietly succeeding on a zero page, which turns a
    // silent corruption into a loud death — but the allocation itself is still
    // nonsense, and handing out a null base is the actual defect. Refuse it
    // here, at the only place that can tell the difference.
    let base = azos_sched::update_user_brk(0) as usize;
    if base < azos_mm::vmm::USER_GUARD_LIMIT { return -1; }
    let aligned_base = base.saturating_add(page_size - 1) & !(page_size - 1);
    // The mapping must stay strictly below the user VA ceiling: above it the
    // "user" page table is the kernel's (shared L1/L0 tables), so mapping
    // there would install USER_RW pages into kernel address space. It must
    // also end at or below the shm/MMIO window, which lies below that
    // ceiling: `shm_map_user` and `mmio_map_user` hand out addresses there,
    // and `sys_munmap` and teardown never free a frame there, so an anonymous
    // page placed in it would never be freed.
    let span = match num_pages.checked_mul(page_size) {
        Some(s) => s,
        None    => return -1,
    };
    let end_va = match aligned_base.checked_add(span) {
        Some(e) => e,
        None    => return -1,
    };
    if end_va > azos_sched::user_shm_window().0 { return -1; }

    // Owner decision 102 — charge the whole request before taking one frame.
    //
    // All-or-nothing here, unlike `brk`: `mmap` hands back a single contiguous
    // range and a caller that asked for 64 pages cannot use 40. Charging first
    // also means a refusal leaves the allocator untouched.
    // Wave 13 (security): `prot` is honoured. PROT_NONE reserves the range
    // (the break moves past it) and maps nothing; `mprotect` maps it later.
    // Anything else maps readable pages, writable only with PROT_WRITE: a
    // store to a PROT_READ mapping faults (128+SIGSEGV), as on Linux. It
    // used to be read-write whatever `prot` said. Gate canary
    // `mmap-prot-canary` brings that back.
    let canary = cfg!(feature = "mmap-prot-canary");
    let writable = canary || prot & MMAP_PROT_WRITE != 0;
    if prot & (MMAP_PROT_READ | MMAP_PROT_WRITE) == 0 && !canary {
        azos_sched::update_user_brk(end_va as u64);
        return aligned_base as i64;
    }

    if !azos_sched::mm_charge(num_pages as u32) { return -1; }

    // Wave 14 (DEMANDPAGE): reserve; the fault path commits each page from
    // the region's pager with exactly these permissions (never executable).
    if !mmap_precommit(flags)
        && azos_mm::pager::reserve(user_pt, aligned_base, end_va, writable).is_ok()
    {
        azos_sched::update_user_brk(end_va as u64);
        let _ = addr;
        return aligned_base as i64;
    }

    let mut va = aligned_base;
    for _ in 0..num_pages {
        match azos_mm::pmm::alloc_page() {
            Ok(page) => {
                let flags = azos_arch_api::PagePerms {
                    accessed: true, dirty: writable, write: writable,
                    ..azos_arch_api::PagePerms::USER_RW
                };
                if azos_mm::vmm::map(user_pt, va, page.as_usize(), flags).is_err() {
                    // This page never made it into the PT — free it directly,
                    // then unwind everything mapped so far.
                    let _ = azos_mm::pmm::free_page(page);
                    mmap_unwind(user_pt, aligned_base, va);
                    // The whole request was charged up front and none of it
                    // survives — give all of it back, not the part that had
                    // been mapped.
                    azos_sched::mm_discharge(num_pages as u32);
                    return -1;
                }
            }
            Err(_) => {
                // OOM part-way through.  Without this the caller got -1 while
                // the kernel silently kept every page already mapped.
                mmap_unwind(user_pt, aligned_base, va);
                azos_sched::mm_discharge(num_pages as u32);
                return -1;
            }
        }
        va += page_size;
    }

    // Advance brk past the mapped region
    azos_sched::update_user_brk(va as u64);

    // If caller specified an addr hint, we ignore it (simplified). Of
    // `flags`, only the pre-commit bits are consulted (`mmap_precommit`).
    let _ = addr;
    aligned_base as i64
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

/// SYS_MUNMAP: unmap pages.  Simplified: just marks pages as unmapped.
/// `mprotect(addr, len, prot)` (wave 13, security): give the pages of
/// `[addr, addr + len)` exactly `prot`'s read and write permissions. The
/// Linux personality's `mprotect` (no native number: it is the memory
/// authority `SYS_MMAP` already grants).
///
/// * `PROT_EXEC`: refused, `-EACCES` (W^X: no writable-then-executable path
///   exists for user pages), as is adding write to an executable page.
/// * `PROT_NONE`: the pages are unmapped and freed (their contents are lost:
///   a divergence from Linux, which keeps them for a later `mprotect`).
/// * Read or read-write: present pages and demand reservations change
///   permission; a page with nothing behind it below the break (a
///   `PROT_NONE` mapping's, or an unmapped one) is mapped zeroed and charged.
///   Copy-on-write pages keep their sharing (`vmm::protect_user_range`).
///
/// `-EINVAL` for a misaligned or empty range or unknown bits, `-ENOMEM` for a
/// page past the break or one the kernel owns (shm/MMIO window, a kernel
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
    let user_pt = azos_sched::current_user_pt();
    if user_pt == 0 { return -1; }
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
            azos_mm::vmm::UserPage::Missing if !none && !azos_mm::pager::contains(user_pt, va) => {
                if va >= brk { return Errno::ENOMEM.to_syscall_ret(); }
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
        let reserved = match azos_mm::pager::release_range(user_pt, start, end) {
            Ok(n) => n as u32,
            Err(_) => return Errno::ENOMEM.to_syscall_ret(),
        };
        let mut freed = azos_mm::vmm::unmap_user_range_and_free(user_pt, start, end, shm_lo, shm_hi)
            .saturating_add(reserved);
        let mut v = start;
        while v < end {
            if azos_mm::demand::clear_demand_marker(user_pt, v) { freed = freed.saturating_add(1); }
            v += page_size;
        }
        azos_sched::mm_discharge(freed);
        return 0;
    }
    // Pass 2: back what has nothing behind it, then set the permission.
    // Wave 14: regions first. It is the step that can refuse for want of a
    // record, and a refusal here leaves everything as it was.
    if azos_mm::pager::protect_range(user_pt, start, end, write).is_err() {
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
                && !azos_mm::pager::contains(user_pt, v)
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
                            && !azos_mm::pager::contains(user_pt, w)
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
    let user_pt = azos_sched::current_user_pt();
    if user_pt == 0 { return -1; }

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
    if len > azos_mm::demand::MAX_DEMAND_ALLOC_BYTES { return -1; }
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
    let reserved = match azos_mm::pager::release_range(user_pt, start, end) {
        Ok(n) => n as u32,
        Err(_) => return azos_abi::error::Errno::ENOMEM.to_syscall_ret(),
    };
    let mut freed: u32 = azos_mm::vmm::unmap_user_range_and_free(user_pt, start, end, shm_lo, shm_hi)
        .saturating_add(reserved);
    // RFC-0049 M1: a demand-reserved page never touched holds no frame but was
    // charged at reservation; clearing its marker gives it back. The batch
    // above skips it (`take_user_leaf` only takes VALID leaves), and an
    // invalid PTE is never cached in a TLB, so this pass needs no shootdown.
    let mut va = start;
    while va < end {
        if azos_mm::demand::clear_demand_marker(user_pt, va) {
            freed = freed.saturating_add(1);
        }
        va += page_size;
    }
    azos_sched::mm_discharge(freed);
    0
}

// ── E11 / AQ10: Demand-paging allocator ─────────────────────────────────────
//
// SYS_ALLOC_DEMAND reserves a user virtual range without consuming any
// physical memory up front; the pages materialize on first access.
//
// a0 = size in bytes (rounded up to PAGE_SIZE).  Returns base VA or -1.

/// Minimum size a demand allocation must request (one page).
const DEMAND_ALLOC_MIN_BYTES: usize = 1;

/// Wave 14 (DEMANDPAGE), a fork's `before_release` step: the child inherits
/// the parent's `mmap` reservation (region records, not pages; committed
/// pages reach it through the copy-on-write fork) and is charged for the
/// part not committed yet, under the same reserve-time model as `sys_mmap`.
/// `false` (the fork is refused) when the child's budget cannot take it.
/// Called with the group's `mm_lock` held, before the child can run.
pub(crate) fn fork_regions_to_child(child: u32) -> bool {
    let parent_pt = azos_sched::current_user_pt();
    let child_pt = azos_sched::task_user_pt(child).unwrap_or(0);
    if parent_pt == 0 || child_pt == 0 {
        return true;
    }
    match azos_mm::pager::fork_clone(parent_pt, child_pt) {
        Ok(0) => true,
        Ok(n) => {
            if azos_sched::mm_charge_tid(child, n.min(u32::MAX as usize) as u32) {
                true
            } else {
                azos_mm::pager::forget(child_pt);
                false
            }
        }
        Err(_) => false,
    }
}

pub fn sys_alloc_demand(size: u64) -> i64 {
    // Wave 13: one layout change at a time per thread group.
    let _mm = azos_sched::group::mm_lock();
    let user_pt = azos_sched::current_user_pt();
    if user_pt == 0 { return -1; } // kernel task

    // RFC-0049 P2: a `mem = "locked"` task takes no page fault, and every
    // page of a demand reservation is one. Refused here whatever its seccomp
    // profile says (an audit-mode profile lets an unlisted call run).
    if azos_sched::current_mem_locked() {
        azos_sched::note_mm_quota_refusal();
        return azos_abi::error::Errno::EPERM.to_syscall_ret();
    }

    let size = size as usize;
    if size < DEMAND_ALLOC_MIN_BYTES {
        return -1;
    }
    if size > azos_mm::demand::MAX_DEMAND_ALLOC_BYTES {
        return -1;
    }

    let page_size = azos_arch::PAGE_SIZE;
    let num_pages = (size + page_size - 1) / page_size;

    // Use the user brk as the allocation base (same convention as sys_mmap),
    // page-aligned upward. Same null-brk refusal as `sys_mmap` — see the
    // comment there for why a base of 0 is a defect and not just an oddity.
    let base = azos_sched::update_user_brk(0) as usize;
    if base < azos_mm::vmm::USER_GUARD_LIMIT { return -1; }

    // `sys_mmap` got `saturating_add` here and this sibling did not. Rust groups
    // `base + page_size - 1` as `(base + page_size) - 1`, so a break anywhere in
    // the last page of the address space overflows -- and with
    // `overflow-checks = true` and `panic = "abort"`, an arithmetic overflow in
    // a syscall handler is a board reset, not a wrong answer.
    //
    // There were TWO sites, which is why fixing only this one is not enough:
    // `end_va` below multiplies and adds against the same base. Both are
    // checked, and the range has the ceiling `sys_mmap` has, the base of the
    // shm/MMIO window -- without one a demand reservation could be placed on
    // top of the shared kernel region, where `sys_munmap` has just been taught
    // nothing from ring 3 may go, or inside the window (see `sys_mmap`).
    let aligned_base = match base.checked_add(page_size - 1) {
        Some(v) => v & !(page_size - 1),
        None    => return -1,
    };
    let end_va = match num_pages.checked_mul(page_size)
                                .and_then(|bytes| aligned_base.checked_add(bytes)) {
        Some(e) if e <= azos_sched::user_shm_window().0 => e,
        _ => return -1,
    };

    // RFC-0049 M1: charge the whole reservation now, as Linux's strict
    // overcommit does, not the frames as they fault in. The fault path can
    // then never be refused for budget -- a refusal there would kill the task
    // on a load it was promised -- and the task's budget already says what it
    // may come to hold.
    if !azos_sched::mm_charge(num_pages as u32) { return -1; }

    // Reserve the range.  map_demand_range returns on first failure; the
    // markers already written are cleared again, with the charge.
    if azos_mm::demand::map_demand_range(user_pt, aligned_base, num_pages).is_err() {
        let mut va = aligned_base;
        for _ in 0..num_pages {
            let _ = azos_mm::demand::clear_demand_marker(user_pt, va);
            va += page_size;
        }
        azos_sched::mm_discharge(num_pages as u32);
        return -1;
    }

    // Advance brk past the reservation so subsequent sys_mmap / sys_brk
    // calls don't collide.
    azos_sched::update_user_brk(end_va as u64);

    aligned_base as i64
}

// ── E11 / AQ9: COW fork (alias) ─────────────────────────────────────────────
//
// SYS_FORK_COW is semantically identical to SYS_FORK — the existing
// SYS_FORK implementation already forwards to `vmm::fork_cow` internally
// (see `sched::process::sys_fork_impl`).  Exposed separately so userspace
// can probe for COW support or request it explicitly.

pub fn sys_fork_cow(sepc: u64, user_sp: u64, regs: &azos_sched::UserRegs) -> i64 {
    sys_fork(sepc, user_sp, regs)
}

// ── DUP / DUP2 ──────────────────────────────────────────────────────────────

/// SYS_DUP: duplicate a file descriptor.  Returns new fd or -1.
pub fn sys_dup(fd: u64) -> i64 {
    match file_ops() { Some(o) => o.dup(fd as i32), None => -1 }
}

/// SYS_DUP2: duplicate fd `old` to fd `new`.  Returns `new` or -1.
pub fn sys_dup2(oldfd: u64, newfd: u64) -> i64 {
    // `dup2` closes `newfd` first when it is open, which is the untyped close
    // [`sys_close`] refuses behind a live `Cap<File>`. `dup` needs no such
    // check: it allocates a fresh number and closes nothing.
    if fd_named_by_file_cap(newfd) { return -1; }
    match file_ops() { Some(o) => o.dup2(oldfd as i32, newfd as i32), None => -1 }
}

// ── PAUSE / ALARM ────────────────────────────────────────────────────────────

/// How long `sys_pause` waits for a signal before it answers -1, in
/// milliseconds of counter time.
pub(crate) const PAUSE_WAIT_MS: u64 = 10_000;

/// SYS_PAUSE: suspend until a signal is delivered.
/// Simplified: sleeps 1 ms between looks at the pending set, for at most
/// [`PAUSE_WAIT_MS`] (it was 1000 `task_yield()` calls, a count rather than
/// a time). 0 when a signal is pending, -1 on timeout.
pub fn sys_pause() -> i64 {
    if crate::sleep::wait_until_ms(PAUSE_WAIT_MS, 1, || signal_pending() != 0) {
        0
    } else {
        -1 // timeout (no signal received)
    }
}

/// SYS_ALARM: set a timer that sends SIGALRM after `seconds`.
/// Simplified: immediate SIGALRM if seconds > 0 (no real timer integration).
pub fn sys_alarm(seconds: u64) -> i64 {
    if seconds == 0 { return 0; } // cancel (no-op)
    // Approximate: sleep, then send SIGALRM to self. The sleep converts at the
    // BOARD's mtime rate (`TIMER_FREQ`), not QEMU's: this read `10_000_000`
    // until 2026-09-18, so `alarm(1)` waited 2.5 s on the VisionFive 2 (4 MHz)
    // and 0.42 s on the K1 (24 MHz). It used to yield in a loop until the
    // counter passed, which hands the hart only to tasks at the caller's
    // priority or above.
    crate::sleep::sleep_ms(seconds.saturating_mul(1000));
    let tid = azos_sched::current_task_tid();
    signal_send(tid, azos_ipc::SIGALRM);
    0
}

/// SYS_SIGRETURN: return from signal handler (restore context).
/// Simplified: just return 0 (full signal frame restore requires trap frame plumbing).
pub fn sys_sigreturn() -> i64 { 0 }

// ── Network utility syscalls ─────────────────────────────────────────────────

/// SYS_NET_SETIP: a0=ip_u32 (big-endian), a1=mask_u32, a2=gw_u32.
pub fn sys_net_setip(ip: u64, mask: u64, gw: u64) -> i64 {
    // Readdressing the interface was ungated and unvalidated. It is worse than
    // a configuration change: the local address is dual-sourced (`NET_CFG` and
    // `tcp.rs`), so a change here can leave TCP checksumming against an address
    // the interface no longer has — on the link that carries the e-stop.
    if !cap_check(azos_abi::cap::CapKind::NetConfig, 0, true) { return E_PERM; }
    let ip_bytes = (ip as u32).to_be_bytes();
    let mask_bytes = (mask as u32).to_be_bytes();
    let gw_bytes = (gw as u32).to_be_bytes();
    azos_net::net_set_ip(ip_bytes, mask_bytes, gw_bytes);
    0
}

/// SYS_NET_PING: a0 = destination IP as u32 (big-endian).
pub fn sys_net_ping(dst_ip: u64) -> i64 {
    let ip = (dst_ip as u32).to_be_bytes();
    azos_net::net_ping(ip) as i64
}

/// SYS_NET_GETMAC: returns MAC as u64 (lower 6 bytes).
pub fn sys_net_getmac() -> i64 {
    let mac = azos_net::net_get_mac();
    let mut val = 0u64;
    for i in 0..6 { val |= (mac[i] as u64) << (i * 8); }
    val as i64
}

/// SYS_NET_STATS: print network statistics.
pub fn sys_net_stats() -> i64 {
    azos_net::net_info();
    0
}

// ── Cap<Gpio> typed handlers — RFC-0003 W5 batch 5.1 ──────────────────────

pub(crate) fn errno_for_gpio_err(e: azos_ipc::gpio_cap::GpioCapError) -> i64 {
    use azos_abi::error::Errno;
    use azos_ipc::cap::CapError;
    use azos_ipc::gpio_cap::GpioCapError;
    // Every typed refusal in this file reaches the recorder here — the one
    // choke point all twelve of these functions share. `Contained` is filtered
    // inside `note_typed_denial`, not here.
    if let GpioCapError::Cap(c) = e {
        note_typed_denial(azos_abi::cap::CapKind::Gpio, c);
    }
    match e {
        GpioCapError::Cap(CapError::Stale) => Errno::ECAPSTALE.to_syscall_ret(),
        GpioCapError::Cap(CapError::WrongKind) => Errno::ECAPKIND.to_syscall_ret(),
        GpioCapError::Cap(CapError::MissingPerms) => Errno::ECAPPERMS.to_syscall_ret(),
        GpioCapError::Cap(CapError::Contained) => Errno::EAGAIN.to_syscall_ret(),
        GpioCapError::Cap(CapError::NoSpace) => Errno::EMFILE.to_syscall_ret(),
        GpioCapError::BadPin => Errno::EINVAL.to_syscall_ret(),
        GpioCapError::BadDirValue => Errno::EINVAL.to_syscall_ret(),
        GpioCapError::DriverFault => Errno::EIO.to_syscall_ret(),
    }
}

/// A GPIO driver return code, as the typed path reports it.
///
/// The three drivers below all answer `0` for success and non-zero for
/// refusal. One helper rather than three copies of the same `if`, so the
/// three call sites cannot drift on what counts as a fault.
pub(crate) fn gpio_rc_to_result(rc: i32) -> Result<(), azos_ipc::gpio_cap::GpioCapError> {
    if rc == 0 {
        Ok(())
    } else {
        Err(azos_ipc::gpio_cap::GpioCapError::DriverFault)
    }
}

// **Why the driver calls are here and not in `gpio_cap.rs`.**
//
// `cap_store::with_table` holds the task's cap-table `SpinLock` for the whole
// closure, and `SpinLock::lock` disables preemption before it spins
// (`crates/core/sync/src/spinlock.rs`). A driver transfer inside that closure runs
// with preemption off, and nests the GPIO backend's own lock
// (`crates/drivers/gpio/src/gpio.rs:38` sim, `:151` MMIO) inside the cap-table one.
// So each of the three handlers below resolves the capability to a pin inside
// the closure — where the permission check, the RFC-0036 containment check and
// the range check belong, because they read the table — and touches the
// hardware only after `with_table` has returned and the guard has been dropped.

/// `SYS_GPIO_READ_TYPED` (539): a0=cap_handle. Returns 0/1 or `-Errno`.
pub fn sys_gpio_read_typed(cap_raw: u64) -> i64 {
    use azos_abi::cap::CapHandle;
    use azos_abi::error::Errno;
    use azos_ipc::cap::{targets::Gpio, Cap};

    let cap: Cap<Gpio> = Cap::from_raw(CapHandle::from_raw(cap_raw as u32));
    let tid = azos_sched::current_task_tid();
    let pin = match azos_ipc::cap_store::with_table(tid, |table| {
        azos_ipc::gpio_cap::gpio_pin_for_read(table, cap)
    }) {
        Some(Ok(pin)) => pin,
        Some(Err(e)) => return errno_for_gpio_err(e),
        None => return Errno::EINVAL.to_syscall_ret(),
    };
    // Table lock released.
    let v = gpio_read(pin);
    if v < 0 {
        errno_for_gpio_err(azos_ipc::gpio_cap::GpioCapError::DriverFault)
    } else {
        v as i64
    }
}

/// `SYS_GPIO_WRITE_TYPED` (540): a0=cap_handle, a1=val. Returns 0 or `-Errno`.
pub fn sys_gpio_write_typed(cap_raw: u64, val: u64) -> i64 {
    use azos_abi::cap::CapHandle;
    use azos_abi::error::Errno;
    use azos_ipc::cap::{targets::Gpio, Cap};

    let cap: Cap<Gpio> = Cap::from_raw(CapHandle::from_raw(cap_raw as u32));
    let tid = azos_sched::current_task_tid();
    let pin = match azos_ipc::cap_store::with_table(tid, |table| {
        azos_ipc::gpio_cap::gpio_pin_for_write(table, cap)
    }) {
        Some(Ok(pin)) => pin,
        Some(Err(e)) => return errno_for_gpio_err(e),
        None => return Errno::EINVAL.to_syscall_ret(),
    };
    // Table lock released.
    // Checked AFTER the cap resolves, mirroring the typed PWM guard: a cap
    // that fails to resolve must report its real capability error rather than
    // have this check mask it.
    if gpio_pin_is_motor_bound(pin) { return E_PERM; }
    match gpio_rc_to_result(gpio_write(pin, (val as u32) & 1)) {
        Ok(()) => 0,
        Err(e) => errno_for_gpio_err(e),
    }
}

/// `SYS_GPIO_SET_DIR_TYPED` (541): a0=cap_handle, a1=dir. Returns 0 or `-Errno`.
///
/// `dir = 0` ⇒ Input, `dir = 1` ⇒ Output; anything else is
/// `GpioCapError::BadDirValue`. The order is capability, then pin range, then
/// `dir` — unchanged from when all three lived in `gpio_cap.rs`, so a caller
/// that passes a bad `dir` through a cap it does not hold WRITE on still gets
/// `ECAPPERMS` and learns nothing about its argument.
pub fn sys_gpio_set_dir_typed(cap_raw: u64, dir: u64) -> i64 {
    use azos_abi::cap::CapHandle;
    use azos_abi::error::Errno;
    use azos_ipc::cap::{targets::Gpio, Cap};
    use azos_ipc::gpio_cap::GpioCapError;

    let cap: Cap<Gpio> = Cap::from_raw(CapHandle::from_raw(cap_raw as u32));
    let tid = azos_sched::current_task_tid();
    let pin = match azos_ipc::cap_store::with_table(tid, |table| {
        azos_ipc::gpio_cap::gpio_pin_for_write(table, cap)
    }) {
        Some(Ok(pin)) => pin,
        Some(Err(e)) => return errno_for_gpio_err(e),
        None => return Errno::EINVAL.to_syscall_ret(),
    };
    // Table lock released.
    if gpio_pin_is_motor_bound(pin) { return E_PERM; }
    let dir = match dir {
        0 => GpioDir::Input,
        1 => GpioDir::Output,
        _ => return errno_for_gpio_err(GpioCapError::BadDirValue),
    };
    match gpio_rc_to_result(gpio_set_direction(pin, dir)) {
        Ok(()) => 0,
        Err(e) => errno_for_gpio_err(e),
    }
}

// ── Cap<I2c> typed handlers — RFC-0003 W5 batch 5.2 ──────────────────────

fn errno_for_i2c_err(e: azos_ipc::i2c_cap::I2cCapError) -> i64 {
    use azos_abi::error::Errno;
    use azos_ipc::cap::CapError;
    use azos_ipc::i2c_cap::I2cCapError;
    // Every typed refusal in this file reaches the recorder here — the one
    // choke point all twelve of these functions share. `Contained` is filtered
    // inside `note_typed_denial`, not here.
    if let I2cCapError::Cap(c) = e {
        note_typed_denial(azos_abi::cap::CapKind::I2c, c);
    }
    match e {
        I2cCapError::Cap(CapError::Stale) => Errno::ECAPSTALE.to_syscall_ret(),
        I2cCapError::Cap(CapError::WrongKind) => Errno::ECAPKIND.to_syscall_ret(),
        I2cCapError::Cap(CapError::MissingPerms) => Errno::ECAPPERMS.to_syscall_ret(),
        I2cCapError::Cap(CapError::Contained) => Errno::EAGAIN.to_syscall_ret(),
        I2cCapError::Cap(CapError::NoSpace) => Errno::EMFILE.to_syscall_ret(),
        I2cCapError::BadLen => Errno::EINVAL.to_syscall_ret(),
        I2cCapError::DriverFault => Errno::EIO.to_syscall_ret(),
    }
}

/// `SYS_I2C_READ_TYPED` (542): a0=cap, a1=reg, a2=buf_ptr, a3=buf_len.
pub fn sys_i2c_read_typed(
    cap_raw: u64,
    reg: u64,
    out_ptr: u64,
    out_len: u64,
) -> i64 {
    use azos_abi::cap::CapHandle;
    use azos_abi::error::Errno;
    use azos_abi::syscall_nr::I2C_TYPED_MAX_BYTES;
    use azos_ipc::cap::{targets::I2c, Cap};

    let n = out_len as usize;
    if n == 0 || n > I2C_TYPED_MAX_BYTES || out_ptr == 0 {
        return Errno::EINVAL.to_syscall_ret();
    }

    let mut buf = [0u8; I2C_TYPED_MAX_BYTES];
    let cap: Cap<I2c> = Cap::from_raw(CapHandle::from_raw(cap_raw as u32));
    let tid = azos_sched::current_task_tid();
    let result = azos_ipc::cap_store::with_table(tid, |table| {
        azos_ipc::i2c_cap::i2c_read_cap(table, cap, reg as u8, &mut buf[..n])
    });
    let got = match result {
        Some(Ok(v)) => v,
        Some(Err(e)) => return errno_for_i2c_err(e),
        None => return Errno::EINVAL.to_syscall_ret(),
    };

    if got > 0 {
        if azos_sched::current_user_pt() != 0 {
            if !azos_sched::copy_to_user(out_ptr as usize, buf.as_ptr(), got) {
                return Errno::EFAULT.to_syscall_ret();
            }
        } else {
            unsafe {
                core::ptr::copy_nonoverlapping(buf.as_ptr(), out_ptr as *mut u8, got);
            }
        }
    }
    got as i64
}

/// `SYS_I2C_WRITE_TYPED` (543): a0=cap, a1=data_ptr, a2=data_len.
pub fn sys_i2c_write_typed(cap_raw: u64, in_ptr: u64, in_len: u64) -> i64 {
    use azos_abi::cap::CapHandle;
    use azos_abi::error::Errno;
    use azos_abi::syscall_nr::I2C_TYPED_MAX_BYTES;
    use azos_ipc::cap::{targets::I2c, Cap};

    let n = in_len as usize;
    if n == 0 || n > I2C_TYPED_MAX_BYTES || in_ptr == 0 {
        return Errno::EINVAL.to_syscall_ret();
    }

    let mut buf = [0u8; I2C_TYPED_MAX_BYTES];
    if azos_sched::current_user_pt() != 0 {
        if !azos_sched::copy_from_user(buf.as_mut_ptr(), in_ptr as usize, n) {
            return Errno::EFAULT.to_syscall_ret();
        }
    } else {
        unsafe {
            core::ptr::copy_nonoverlapping(in_ptr as *const u8, buf.as_mut_ptr(), n);
        }
    }

    let cap: Cap<I2c> = Cap::from_raw(CapHandle::from_raw(cap_raw as u32));
    let tid = azos_sched::current_task_tid();
    let result = azos_ipc::cap_store::with_table(tid, |table| {
        azos_ipc::i2c_cap::i2c_write_cap(table, cap, &buf[..n])
    });
    match result {
        Some(Ok(())) => 0,
        Some(Err(e)) => errno_for_i2c_err(e),
        None => Errno::EINVAL.to_syscall_ret(),
    }
}

/// `SYS_I2C_DETECT_TYPED` (544): a0=cap. Returns 0/1 or `-Errno`.
pub fn sys_i2c_detect_typed(cap_raw: u64) -> i64 {
    use azos_abi::cap::CapHandle;
    use azos_abi::error::Errno;
    use azos_ipc::cap::{targets::I2c, Cap};

    let cap: Cap<I2c> = Cap::from_raw(CapHandle::from_raw(cap_raw as u32));
    let tid = azos_sched::current_task_tid();
    let result = azos_ipc::cap_store::with_table(tid, |table| {
        azos_ipc::i2c_cap::i2c_detect_cap(table, cap)
    });
    match result {
        Some(Ok(v)) => v as i64,
        Some(Err(e)) => errno_for_i2c_err(e),
        None => Errno::EINVAL.to_syscall_ret(),
    }
}

// ── Cap<Pwm> typed handlers — RFC-0003 W5 batch 5.3 ──────────────────────

fn errno_for_pwm_err(e: azos_ipc::pwm_cap::PwmCapError) -> i64 {
    use azos_abi::error::Errno;
    use azos_ipc::cap::CapError;
    use azos_ipc::pwm_cap::PwmCapError;
    // Every typed refusal in this file reaches the recorder here — the one
    // choke point all twelve of these functions share. `Contained` is filtered
    // inside `note_typed_denial`, not here.
    if let PwmCapError::Cap(c) = e {
        note_typed_denial(azos_abi::cap::CapKind::Pwm, c);
    }
    match e {
        PwmCapError::Cap(CapError::Stale) => Errno::ECAPSTALE.to_syscall_ret(),
        PwmCapError::Cap(CapError::WrongKind) => Errno::ECAPKIND.to_syscall_ret(),
        PwmCapError::Cap(CapError::MissingPerms) => Errno::ECAPPERMS.to_syscall_ret(),
        PwmCapError::Cap(CapError::Contained) => Errno::EAGAIN.to_syscall_ret(),
        PwmCapError::Cap(CapError::NoSpace) => Errno::EMFILE.to_syscall_ret(),
        PwmCapError::BadChannel => Errno::EINVAL.to_syscall_ret(),
        PwmCapError::DriverFault => Errno::EIO.to_syscall_ret(),
    }
}

/// Generic helper for the 5 PWM ops that all take
/// `(cap, payload) -> Result<(), PwmCapError>` shape.
/// What a PWM operation actually reaches, declared by the caller.
///
/// Passed as an argument rather than inferred, for the same reason as
/// `SwitchReason` in the scheduler: only the call site knows, and a table
/// mapping ops to reaches elsewhere is a table that drifts from the ops.
#[derive(Clone, Copy, PartialEq, Eq)]
enum PwmOpReach {
    /// Writes the shared control register — reaches every channel of the
    /// instance on hardware that shares it. Enable, disable, set-period.
    Control,
    /// Writes this channel's own `PWMCMP`. Duty only.
    DutyOnly,
}

/// U03-4: `op` now runs the driver call, and `sys_pwm_dispatch_inner` calls it
/// only AFTER the cap-table lock (`with_table`) is released — `op` takes the
/// already-resolved channel, not the table+cap. See `pwm_cap::pwm_channel_for_write`'s
/// doc for why: the driver call used to run inside the same `with_table`
/// closure that resolved the capability, a hardware MMIO read-modify-write (or
/// the sim backend's lock) under a preemption-disabling `SpinLock` guard.
fn sys_pwm_dispatch_inner<F>(cap_raw: u64, reach: PwmOpReach, op: F) -> i64
where
    F: FnOnce(u32) -> i32,
{
    use azos_abi::cap::CapHandle;
    use azos_abi::error::Errno;
    use azos_ipc::cap::{targets::Pwm, Cap};
    use azos_ipc::pwm_cap::{pwm_channel_for_write, PwmCapError};
    let cap: Cap<Pwm> = Cap::from_raw(CapHandle::from_raw(cap_raw as u32));
    let tid = azos_sched::current_task_tid();

    // **A PWM channel bound to a motor is not reachable through here either.**
    //
    // Every op in this family writes, and they all bottom out in the same
    // compare register `motor_set` writes — one level below the actuation
    // gate, so a typed `Cap<Pwm>` for a wheel's channel could spin it through
    // a latched e-stop. Same refusal, same reasoning and the same owner
    // decision as the `SYS_DRV_INVOKE` path: refuse rather than clamp,
    // because this is the raw interface and `SYS_MOTOR_*` is the gated one.
    //
    // Resolved in its own borrow of the table rather than inside the op
    // closure: the closure returns `PwmCapError`, which has no variant for
    // "forbidden", and reusing `BadChannel` would tell the caller the channel
    // does not exist when the truth is that it does and is spoken for.
    //
    // A cap that fails to resolve falls through to `op`, which fails on the
    // same lookup and reports the real capability error — stale, wrong kind,
    // missing perms — instead of this check masking it.
    // Resolve ONCE, and deny when the cap does not resolve.
    //
    // This used to answer `Err(_) => false` — "could not prove it is bound"
    // read as "not bound" — and then let `op` re-resolve the same handle in a
    // second `with_table`. Both halves were wrong in the same direction: a
    // check that fails open, and a window between check and use in which the
    // handle could resolve to something else. Audit finding, 2026-09-11.
    let resolved = azos_ipc::cap_store::with_table(tid, |table| {
        pwm_channel_for_write(table, cap).ok()
    })
    .flatten();
    let ch = match resolved {
        Some(ch) => ch,
        // Report the REAL capability error — stale, wrong kind, missing
        // perms — rather than masking it with E_PERM here. Re-resolves and
        // fails on the same lookup; no driver call is reached.
        None => return match azos_ipc::cap_store::with_table(tid, |table| {
            pwm_channel_for_write(table, cap)
        }) {
            Some(Ok(_)) => 0, // unreachable: `resolved` above already found it Ok
            Some(Err(e)) => errno_for_pwm_err(e),
            None => azos_abi::error::Errno::EINVAL.to_syscall_ret(),
        },
    };

    // CONTROL ops are refused by REACH, duty by the named channel. The typed
    // path checked neither until 2026-09-11, which made it strictly weaker
    // than both the untyped path and `SYS_DRV_INVOKE` on the same operation.
    let blocked = match reach {
        PwmOpReach::Control  => pwm_control_reaches_a_motor(azos_drv_actuator::pwm_domain::PWM_DOMAIN, ch),
        PwmOpReach::DutyOnly => pwm_channel_is_motor_bound(ch),
    };
    if blocked { return E_PERM; }

    // Re-resolve under the lock, right before the driver call: `ch` above
    // was for the reach check, and re-deriving it here (rather than trusting
    // it blind across the gap) keeps this consistent with `get`'s own
    // generation/perms re-check on every use. One more O(1) lookup.
    let ch = match azos_ipc::cap_store::with_table(tid, |table| pwm_channel_for_write(table, cap)) {
        Some(Ok(ch)) => ch,
        Some(Err(e)) => return errno_for_pwm_err(e),
        None => return Errno::EINVAL.to_syscall_ret(),
    };

    // U03-4: the driver call — a hardware MMIO read-modify-write, or the sim
    // backend's own lock — now runs with NO cap-table lock held.
    let rc = op(ch);
    if rc == 0 {
        0
    } else {
        errno_for_pwm_err(PwmCapError::DriverFault)
    }
}

pub fn sys_pwm_enable_typed(cap_raw: u64) -> i64 {
    sys_pwm_dispatch_inner(cap_raw, PwmOpReach::Control, azos_drv_actuator::pwm::pwm_enable)
}

pub fn sys_pwm_disable_typed(cap_raw: u64) -> i64 {
    sys_pwm_dispatch_inner(cap_raw, PwmOpReach::Control, azos_drv_actuator::pwm::pwm_disable)
}

pub fn sys_pwm_set_period_typed(cap_raw: u64, period_ns: u64) -> i64 {
    sys_pwm_dispatch_inner(cap_raw, PwmOpReach::Control, |ch| {
        azos_drv_actuator::pwm::pwm_set_period(ch, period_ns as u32)
    })
}

pub fn sys_pwm_set_duty_typed(cap_raw: u64, duty_ns: u64) -> i64 {
    sys_pwm_dispatch_inner(cap_raw, PwmOpReach::DutyOnly, |ch| {
        azos_drv_actuator::pwm::pwm_set_duty(ch, duty_ns as u32)
    })
}

pub fn sys_pwm_set_duty_pct_typed(cap_raw: u64, pct: u64) -> i64 {
    sys_pwm_dispatch_inner(cap_raw, PwmOpReach::DutyOnly, |ch| {
        azos_drv_actuator::pwm::pwm_set_duty_pct(ch, pct as u32)
    })
}

// ── Cap<Motor> typed handlers — RFC-0003 W5 batch 5.4 ────────────────────

fn errno_for_motor_err(e: azos_ipc::motor_cap::MotorCapError) -> i64 {
    use azos_abi::error::Errno;
    use azos_ipc::cap::CapError;
    use azos_ipc::motor_cap::MotorCapError;
    // Every typed refusal in this file reaches the recorder here — the one
    // choke point all twelve of these functions share. `Contained` is filtered
    // inside `note_typed_denial`, not here.
    // `let`, not `if let`: `MotorCapError` has exactly one variant, so an
    // `if let` here is irrefutable and rustc says so — and a warning is a gate
    // failure in this tree. If the enum ever grows a second variant this stops
    // compiling, which is the right way to be told.
    let MotorCapError::Cap(c) = e;
    note_typed_denial(azos_abi::cap::CapKind::Motor, c);
    match e {
        MotorCapError::Cap(CapError::Stale) => Errno::ECAPSTALE.to_syscall_ret(),
        MotorCapError::Cap(CapError::WrongKind) => Errno::ECAPKIND.to_syscall_ret(),
        MotorCapError::Cap(CapError::MissingPerms) => Errno::ECAPPERMS.to_syscall_ret(),
        MotorCapError::Cap(CapError::Contained) => Errno::EAGAIN.to_syscall_ret(),
        MotorCapError::Cap(CapError::NoSpace) => Errno::EMFILE.to_syscall_ret(),
    }
}

pub fn sys_motor_set_target_typed(cap_raw: u64, speed_l: u64, speed_r: u64) -> i64 {
    use azos_abi::cap::CapHandle;
    use azos_abi::error::Errno;
    use azos_ipc::cap::{targets::Motor, Cap};
    let cap: Cap<Motor> = Cap::from_raw(CapHandle::from_raw(cap_raw as u32));
    let tid = azos_sched::current_task_tid();
    let result = azos_ipc::cap_store::with_table(tid, |t| {
        azos_ipc::motor_cap::motor_set_target_cap(
            t, cap, speed_l as i16, speed_r as i16,
        )
    });
    match result {
        Some(Ok(())) => 0,
        Some(Err(e)) => errno_for_motor_err(e),
        None => Errno::EINVAL.to_syscall_ret(),
    }
}

pub fn sys_motor_tick_typed(
    cap_raw: u64,
    ticks_l: u64,
    ticks_r: u64,
    now: u64,
    out_ptr: u64,
) -> i64 {
    use azos_abi::cap::CapHandle;
    use azos_abi::error::Errno;
    use azos_abi::syscall_nr::MOTOR_TICK_OUT_BYTES;
    use azos_ipc::cap::{targets::Motor, Cap};
    if out_ptr == 0 {
        return Errno::EINVAL.to_syscall_ret();
    }
    let cap: Cap<Motor> = Cap::from_raw(CapHandle::from_raw(cap_raw as u32));
    let tid = azos_sched::current_task_tid();
    let result = azos_ipc::cap_store::with_table(tid, |t| {
        azos_ipc::motor_cap::motor_tick_cap(
            t, cap, ticks_l as i64, ticks_r as i64, now,
        )
    });
    let (pwm_l, pwm_r) = match result {
        Some(Ok(v)) => v,
        Some(Err(e)) => return errno_for_motor_err(e),
        None => return Errno::EINVAL.to_syscall_ret(),
    };
    let mut buf = [0u8; MOTOR_TICK_OUT_BYTES];
    buf[0..4].copy_from_slice(&pwm_l.to_le_bytes());
    buf[4..8].copy_from_slice(&pwm_r.to_le_bytes());
    if azos_sched::current_user_pt() != 0 {
        if !azos_sched::copy_to_user(
            out_ptr as usize,
            buf.as_ptr(),
            MOTOR_TICK_OUT_BYTES,
        ) {
            return Errno::EFAULT.to_syscall_ret();
        }
    } else {
        unsafe {
            core::ptr::copy_nonoverlapping(
                buf.as_ptr(),
                out_ptr as *mut u8,
                MOTOR_TICK_OUT_BYTES,
            );
        }
    }
    MOTOR_TICK_OUT_BYTES as i64
}

pub fn sys_motor_enable_typed(cap_raw: u64, en: u64) -> i64 {
    use azos_abi::cap::CapHandle;
    use azos_abi::error::Errno;
    use azos_ipc::cap::{targets::Motor, Cap};
    let cap: Cap<Motor> = Cap::from_raw(CapHandle::from_raw(cap_raw as u32));
    let tid = azos_sched::current_task_tid();
    let result = azos_ipc::cap_store::with_table(tid, |t| {
        azos_ipc::motor_cap::motor_enable_cap(t, cap, en != 0)
    });
    match result {
        Some(Ok(())) => 0,
        Some(Err(e)) => errno_for_motor_err(e),
        None => Errno::EINVAL.to_syscall_ret(),
    }
}

pub fn sys_motor_enabled_typed(cap_raw: u64) -> i64 {
    use azos_abi::cap::CapHandle;
    use azos_abi::error::Errno;
    use azos_ipc::cap::{targets::Motor, Cap};
    let cap: Cap<Motor> = Cap::from_raw(CapHandle::from_raw(cap_raw as u32));
    let tid = azos_sched::current_task_tid();
    let result = azos_ipc::cap_store::with_table(tid, |t| {
        azos_ipc::motor_cap::motor_enabled_cap(t, cap)
    });
    match result {
        Some(Ok(v)) => i64::from(v),
        Some(Err(e)) => errno_for_motor_err(e),
        None => Errno::EINVAL.to_syscall_ret(),
    }
}

pub fn sys_motor_set_gains_typed(cap_raw: u64, kp: u64, ki: u64, kd: u64) -> i64 {
    use azos_abi::cap::CapHandle;
    use azos_abi::error::Errno;
    use azos_ipc::cap::{targets::Motor, Cap};
    let cap: Cap<Motor> = Cap::from_raw(CapHandle::from_raw(cap_raw as u32));
    let tid = azos_sched::current_task_tid();
    let result = azos_ipc::cap_store::with_table(tid, |t| {
        azos_ipc::motor_cap::motor_set_gains_cap(
            t, cap, kp as i32, ki as i32, kd as i32,
        )
    });
    match result {
        Some(Ok(())) => 0,
        Some(Err(e)) => errno_for_motor_err(e),
        None => Errno::EINVAL.to_syscall_ret(),
    }
}

pub fn sys_motor_reset_typed(cap_raw: u64) -> i64 {
    use azos_abi::cap::CapHandle;
    use azos_abi::error::Errno;
    use azos_ipc::cap::{targets::Motor, Cap};
    let cap: Cap<Motor> = Cap::from_raw(CapHandle::from_raw(cap_raw as u32));
    let tid = azos_sched::current_task_tid();
    let result = azos_ipc::cap_store::with_table(tid, |t| {
        azos_ipc::motor_cap::motor_reset_cap(t, cap)
    });
    match result {
        Some(Ok(())) => 0,
        Some(Err(e)) => errno_for_motor_err(e),
        None => Errno::EINVAL.to_syscall_ret(),
    }
}

// ── SYS_DRV_INVOKE — RFC-0002 Driver registry bridge ──────────────────────

fn errno_for_driver_err(e: azos_drv_api::DriverError) -> i64 {
    use azos_abi::error::Errno;
    use azos_drv_api::DriverError;
    match e {
        DriverError::NotInitialized => Errno::ENODEV.to_syscall_ret(),
        DriverError::BadOp => Errno::ENOSYS.to_syscall_ret(),
        DriverError::BadInput => Errno::EINVAL.to_syscall_ret(),
        DriverError::BadOutput => Errno::EINVAL.to_syscall_ret(),
        DriverError::Busy => Errno::EAGAIN.to_syscall_ret(),
        DriverError::IoFault => Errno::EIO.to_syscall_ret(),
        DriverError::Unsupported => Errno::ENOSYS.to_syscall_ret(),
        DriverError::NoMem => Errno::ENOMEM.to_syscall_ret(),
        DriverError::Other(_) => Errno::EIO.to_syscall_ret(),
    }
}

/// Translate a `DRV_KIND_*` value into the `CapKind` that represents
/// authority over that subsystem, or `None` when no such cap kind exists.
///
/// Only four driver kinds have a capability analogue today. The rest —
/// UART, SPI, DMA, CSI camera, LiDAR, IMU, GPS, ADC, NPU, CAN, xHCI — have
/// no `CapKind`, so there is nothing a client could be asked to hold, and
/// [`drv_invoke_authorized`] denies them to userspace. See the report:
/// closing that gap means extending `CapKind`, which is a wire-format
/// (`crates/core/abi`) change.
fn cap_kind_for_driver(kind: u32) -> Option<azos_ipc::cap::CapKind> {
    use azos_driver_server::{
        DRV_KIND_GPIO, DRV_KIND_I2C, DRV_KIND_MOTOR_PID, DRV_KIND_PWM,
    };
    use azos_ipc::cap::CapKind;
    match kind {
        DRV_KIND_GPIO => Some(CapKind::Gpio),
        DRV_KIND_I2C => Some(CapKind::I2c),
        DRV_KIND_PWM => Some(CapKind::Pwm),
        DRV_KIND_MOTOR_PID => Some(CapKind::Motor),
        // `None` for every other kind, which DENIES ring 3 — read the doc
        // below: this is fail-closed by design, not an unfinished table.
        //
        // `CapKind::Adc` exists as of 2026-09-06, so adding
        // `DRV_KIND_ADC => Some(CapKind::Adc)` here now compiles. Do not.
        // Nothing grants an ADC capability, so the arm would not tighten an
        // existing check — it would replace a blanket refusal with a check
        // that can be satisfied, i.e. open the ADC driver-invoke path to ring
        // 3. Same for CAN, NPU and USB_XHCI. An arm here is a decision to
        // allow a family, and belongs with that family's minter.
        _ => None,
    }
}

/// May the current task invoke `drv`?
///
/// **WHY this exists (W3-F9):** `DriverManifest::required_perms` is
/// documented as "cap-table permissions a client must hold to call this
/// driver", and a tree-wide grep found it referenced only in its own
/// definition and two *display* sites (`crates/core/shell`, `kernel/src/main.rs`
/// both just print it). `SYS_DRV_INVOKE` dispatched `handle_request` with no
/// check at all — so ring 3 reached the GPIO / I2C / PWM / motor drivers
/// directly, bypassing exactly the capability requirement the manifest
/// advertises, while the typed syscalls next door (`sys_motor_set_target_typed`
/// and friends) all demand a `Cap<T>`. A field that claims a protection the
/// code never applies is the bug class this whole batch is about.
///
/// Kernel callers (`user_pt == 0`) bypass, as everywhere else. Userspace is
/// denied for any driver kind with no `CapKind` analogue — fail-closed, and
/// nothing in `userspace/` invokes this syscall today, so no working path
/// regresses.
fn drv_invoke_authorized(
    drv: &&'static dyn azos_drv_api::Driver,
    op: u32,
    input: &[u8],
) -> bool {
    if azos_sched::current_user_pt() == 0 {
        return true;
    }
    let manifest = drv.manifest();
    let cap_kind = match cap_kind_for_driver(manifest.kind) {
        Some(k) => k,
        None => return false,
    };
    let tid = azos_sched::current_task_tid();
    // **Which resource, not just which kind.**
    //
    // This asked `holds_kind_with`, which compares the kind and the
    // permissions and never the resource index — a distinction the driver
    // registry erases and the driver itself restores. `GpioDriver` decodes
    // its pin from the caller's own payload, so a task holding
    // `Cap<Gpio>(5)` reached pin 40 through this syscall while
    // `sys_gpio_write` next door checked the pin correctly. That driver is
    // registered at boot: it was live, not latent.
    //
    // `None` means the call names no single resource, and the kind-wide
    // check is then the honest answer — see each driver's
    // `request_resource` for why it says what it says. It is NOT a default:
    // the trait has no default implementation, so a driver added later
    // cannot inherit "names nothing" by omission.
    //
    // Note the resource-aware check is also stricter in a second way:
    // `holds_kind_resource_with` refuses a WRITE while containment is
    // armed. Reaching a pin through the driver bridge now obeys degraded
    // mode, which the kind-wide check never did.
    // The one kind whose ops name no resource AND still reach an actuator.
    //
    // `motor_driver::request_resource` returns `None` for every op, because
    // the PID driver's input carries a left/right target rather than a motor
    // id — no single index describes what it reaches. The kind-wide fallback
    // below is resource-blind, so `Cap<Motor>(0)` alone passed it and then
    // drove both wheels; `motor_driver.rs`'s own comment said exactly that and
    // named this as the fix.
    //
    // The rule mirrors the typed path exactly — including its exception,
    // `MOTOR_OP_ENABLED`, which is READ-only there and must not become
    // pair-wide here. `motor_bridge_op_needs_pair` is the pure predicate and
    // `table_holds_drivetrain_write` is the same function
    // `motor_cap::require_pair_write` uses, so the two paths cannot drift.
    if manifest.kind == azos_driver_server::DRV_KIND_MOTOR_PID
        && azos_drv_base::drv_resource::motor_bridge_op_needs_pair(op)
    {
        return azos_ipc::cap_store::with_table(tid, |table| {
            azos_ipc::motor_cap::table_holds_drivetrain_write(table)
        })
        .unwrap_or(false);
    }

    let resource = drv.request_resource(op, input);
    azos_ipc::cap_store::with_table(tid, |table| match resource {
        Some(r) => table.holds_kind_resource_with(cap_kind, r, manifest.required_perms),
        // **Contained here too, by what the op does.** `holds_kind_with` does
        // not consult degraded mode, so while contained every op that names no
        // resource — PWM enable, disable and set-period on every call, any op
        // of a userspace-served driver — went through while the typed twin of
        // the same write was refused. Audit finding, 2026-09-13.
        //
        // By the OP rather than by `required_perms`: every manifest asks for
        // `RW`, so keying on the manifest would refuse reads as well, where the
        // typed family leaves them live. The resource-named arm above cannot
        // make that distinction — `holds_kind_resource_with` refuses any query
        // containing WRITE — so a GPIO read naming a pin is still refused
        // while contained. Stricter than the typed path, never looser.
        None => {
            table.holds_kind_with(cap_kind, manifest.required_perms)
                && !(drv_op_writes(manifest.kind, op) && azos_ipc::cap::degraded_active())
        }
    })
    .unwrap_or(false)
}

/// Does driver-bridge op `op` of driver kind `kind` write?
///
/// The line the typed syscalls draw, restated per op so the bridge's
/// containment matches it: a read is what the typed twin resolves with `READ`.
///
/// Numbers rather than the `*_OP_*` constants, as in `drv_resource`: the GPIO,
/// I2C and motor driver modules are not visible to this crate's host tests.
///
/// * GPIO — `GPIO_OP_READ` (1) reads a level, like `SYS_GPIO_READ_TYPED`.
///   `SET_DIR` (0), `WRITE` (2) and `TOGGLE` (3) change the pin.
/// * I2C — `I2C_OP_READ` (1) and `I2C_OP_DETECT` (2) read, like
///   `SYS_I2C_READ_TYPED` / `SYS_I2C_DETECT_TYPED` (both `READ`,
///   `i2c_cap.rs`). `I2C_OP_WRITE` (0) writes a device register.
/// * PWM — every op writes the controller: enable, disable, period, duty.
/// * Motor PID — `MOTOR_OP_ENABLED` (3) reads the loop's state, like
///   `SYS_MOTOR_ENABLED_TYPED`. The other five go through the drivetrain rule
///   before reaching here.
///
/// Anything else is a write: an op number this table does not know has no
/// effect the kernel can show to be a read, and a userspace-served driver's
/// ops are opaque to it.
const fn drv_op_writes(kind: u32, op: u32) -> bool {
    use azos_driver_server::{DRV_KIND_GPIO, DRV_KIND_I2C, DRV_KIND_MOTOR_PID};
    match kind {
        DRV_KIND_GPIO => op != 1,
        DRV_KIND_I2C => !matches!(op, 1 | 2),
        DRV_KIND_MOTOR_PID => op != 3,
        _ => true,
    }
}

/// `SYS_DRV_INVOKE` (311): userspace bridge into the RFC-0002
/// Driver registry. `a0=kind, a1=op, a2=in_ptr, a3=in_len,
/// a4=out_ptr, a5=out_cap`. Returns bytes written to `out_ptr`
/// (≥ 0) or `-Errno`. Userspace callers must hold a capability of the
/// matching kind carrying the manifest's `required_perms` — see
/// [`drv_invoke_authorized`].
pub fn sys_drv_invoke(
    kind: u64,
    op: u64,
    in_ptr: u64,
    in_len: u64,
    out_ptr: u64,
    out_cap: u64,
) -> i64 {
    use azos_abi::error::Errno;
    use azos_abi::syscall_nr::{
        DRIVER_INVOKE_MAX_INPUT_BYTES, DRIVER_INVOKE_MAX_OUTPUT_BYTES,
    };

    let in_len_u = in_len as usize;
    let out_cap_u = out_cap as usize;
    if in_len_u > DRIVER_INVOKE_MAX_INPUT_BYTES
        || out_cap_u > DRIVER_INVOKE_MAX_OUTPUT_BYTES
    {
        return Errno::EINVAL.to_syscall_ret();
    }

    // Per-call stack buffers — bounded by the consts above so the
    // syscall stack frame stays small.
    let mut in_buf = [0u8; DRIVER_INVOKE_MAX_INPUT_BYTES];
    let mut out_buf = [0u8; DRIVER_INVOKE_MAX_OUTPUT_BYTES];

    // Copy input from userspace.
    if in_len_u > 0 {
        if in_ptr == 0 {
            return Errno::EINVAL.to_syscall_ret();
        }
        if azos_sched::current_user_pt() != 0 {
            if !azos_sched::copy_from_user(
                in_buf.as_mut_ptr(),
                in_ptr as usize,
                in_len_u,
            ) {
                return Errno::EFAULT.to_syscall_ret();
            }
        } else {
            unsafe {
                core::ptr::copy_nonoverlapping(
                    in_ptr as *const u8,
                    in_buf.as_mut_ptr(),
                    in_len_u,
                );
            }
        }
    }

    // **A PWM channel bound to a motor is not reachable through here.**
    //
    // `PwmDriver::handle_request` decodes the channel from `input[0..4]` and
    // calls `pwm::pwm_set_duty_pct` directly — one level BELOW the actuation
    // gate in `motor_set`, which is where the e-stop and the motor envelope
    // are applied. On a board where motors 0 and 1 are PWM channels 0 and 1,
    // this path could spin a wheel through a latched e-stop.
    //
    // Refused rather than clamped: this is the raw PWM interface, and a caller
    // that wants to drive a motor has `SYS_MOTOR_*`, which goes through the
    // gate. Silently clamping here would let a driver believe it had set a
    // duty it did not set.
    //
    // Channel-bound, not blanket: a channel no initialised motor claims —
    // the buzzer's, for instance — passes as before.
    //
    // Closing this route one-by-one rather than putting the gate at
    // `pwm_set_duty_pct` is the owner's call, made 2026-09-06. The cost is
    // that a fourth route added later will not be covered and nothing here
    // will notice; the benefit is no new seam into the driver crates.
    //
    // AMENDED 2026-09-06: this guard asked about the channel the caller
    // NAMED, which is the right question only for duty. `PWM_OP_ENABLE`,
    // `PWM_OP_DISABLE` and `PWM_OP_SET_PERIOD` write the shared `PWMCFG` on
    // the JH7110 and reach every channel of the instance, so naming an
    // unbound channel (2 or 3) passed this check and then stopped — or
    // re-armed — the motors on channels 0 and 1. Same defect the `sys_pwm_*`
    // handlers had, in the route built to contain it. `pwm_domain` supplies
    // the reach; `pwm_channel_motor_id` still supplies the binding.
    // **The guard below needs 4 bytes to decode a channel; a shorter payload
    // must not simply skip it.** `in_len_u` is caller-controlled and only
    // bounded from above, so `0..=3` reaches here — and `in_len_u == 0` skips
    // the copy block entirely. That was safe only because `PwmDriver::decode`
    // rejects anything under 8 bytes two calls later, in another crate: the
    // guard's precondition was being met by a fact it does not state and
    // cannot see. Refused here instead, so this frame is self-contained.
    if kind as u32 == azos_driver_server::DRV_KIND_PWM && in_len_u < 4 {
        return Errno::EINVAL.to_syscall_ret();
    }
    if kind as u32 == azos_driver_server::DRV_KIND_PWM {
        use azos_drv_actuator::pwm_driver::{
            PWM_OP_DISABLE, PWM_OP_ENABLE, PWM_OP_SET_PERIOD,
        };
        let ch = u32::from_le_bytes([in_buf[0], in_buf[1], in_buf[2], in_buf[3]]);
        // Same predicate as the typed and untyped paths — see
        // `pwm_control_reaches_a_motor`. This site had the reach logic right
        // and inline; the other two had it wrong in two different ways, which
        // is exactly the argument for there being one of it.
        let touches_a_motor = match op as u32 {
            // Duty lands in this channel's own `PWMCMP`: named is reached.
            PWM_OP_ENABLE | PWM_OP_DISABLE | PWM_OP_SET_PERIOD =>
                pwm_control_reaches_a_motor(azos_drv_actuator::pwm_domain::PWM_DOMAIN, ch),
            _ => pwm_channel_is_motor_bound(ch),
        };
        if touches_a_motor {
            return E_PERM;
        }
    }

    // Look up + dispatch. We hold the registry lock only across
    // the find — `handle_request` runs without the registry lock
    // so per-driver locks (e.g. UART SMP lock) won't deadlock
    // against the registry mutex.
    let drv = match azos_drv_base::runtime::registry::REGISTRY
        .lock()
        .find_by_kind(kind as u32)
    {
        Some(d) => d,
        None => return Errno::ENODEV.to_syscall_ret(),
    };

    // W3-F9: enforce the manifest's declared client requirement.
    if !drv_invoke_authorized(&drv, op as u32, &in_buf[..in_len_u]) {
        return Errno::EPERM.to_syscall_ret();
    }

    let result = drv.handle_request(
        op as u32,
        &in_buf[..in_len_u],
        &mut out_buf[..out_cap_u],
    );

    let n = match result {
        Ok(n) => n,
        Err(e) => return errno_for_driver_err(e),
    };

    // **`n` comes from the driver, and a driver is not always kernel code.**
    //
    // `handle_request` gets `&mut out_buf[..out_cap_u]`, so it cannot WRITE
    // past what the caller asked for — but the length it returns is its own
    // number, and the copy below uses it to read `out_buf`, which is
    // `DRIVER_INVOKE_MAX_OUTPUT_BYTES` long. An `n` above `out_cap_u` would
    // hand the caller bytes of this stack frame it never asked for and
    // overrun its own buffer.
    //
    // `DriverIsolation::UserProcess` is the reason this is a boundary and not
    // an internal invariant: `UserDriverProxy` forwards a length a RING-3
    // driver process chose. That file bounds it correctly today, and so do the
    // five in-kernel drivers — this is the same bound asserted in the frame
    // that owns the buffer, rather than delegated to six callees. Refused
    // rather than clamped: a truncated reply read as a complete one is how a
    // sensor value becomes half a sensor value.
    if n > out_cap_u {
        return Errno::EIO.to_syscall_ret();
    }

    // Copy output back to userspace.
    if n > 0 {
        if out_ptr == 0 {
            return Errno::EINVAL.to_syscall_ret();
        }
        if azos_sched::current_user_pt() != 0 {
            if !azos_sched::copy_to_user(
                out_ptr as usize,
                out_buf.as_ptr(),
                n,
            ) {
                return Errno::EFAULT.to_syscall_ret();
            }
        } else {
            unsafe {
                core::ptr::copy_nonoverlapping(
                    out_buf.as_ptr(),
                    out_ptr as *mut u8,
                    n,
                );
            }
        }
    }
    n as i64
}

// ── Sensor read (Phase S) ────────────────────────────────────────────────────

/// Sensor types for SYS_SENSOR_READ.
pub const SENSOR_TYPE_IMU:       u64 = 0;  // 24 bytes: accel[3] + gyro[3] as i32 LE
pub const SENSOR_TYPE_ODOM:      u64 = 1;  // 16 bytes: dist_mm(i64) + heading_cdeg(i64)
pub const SENSOR_TYPE_ENCODER:   u64 = 2;  // 16 bytes: enc_l(i64) + enc_r(i64)
pub const SENSOR_TYPE_RANGE:     u64 = 3;  //  4 bytes: front_mm(u16) + right_mm(u16)
pub const SENSOR_TYPE_BATTERY:   u64 = 4;  //  2 bytes: mv(u16)
pub const SENSOR_TYPE_GPS:       u64 = 5;  // 16 bytes: lat_deg7(i32) + lon_deg7(i32) + alt_cm(i32) + fix(u8) + sats(u8) + pad(u16)
pub const SENSOR_TYPE_LIDAR:     u64 = 6;  // N×4 bytes: [angle_cdeg(u16) + distance_mm(u16)] per point
pub const SENSOR_TYPE_GPIO_FLAGS: u64 = 7; // 2 bytes: u16 LE — PIR(0x0001) | SOUND(0x0002) | IR(0x0004)
pub const SENSOR_TYPE_CAMERA:    u64 = 8; // Variable: JPEG bytes from csi_capture_jpeg()
pub const SENSOR_TYPE_POWER:     u64 = 9; // 12 bytes: voltage_mv(u16) + current_ma(u16) + mah_used(u32) + pct(u8) + sag(u8) + failsafe(u8) + pad(u8)

// GPIO pins for digital sensors (must match guard mode pin assignment)
const GPIO_PIN_PIR: u32 = 13;
const GPIO_PIN_IR: u32 = 14;
const GPIO_PIN_SOUND: u32 = 15;

// Sensor flag bits (must match brain_protocol.rs)
const SENSOR_FLAG_PIR: u16   = 0x0001;
const SENSOR_FLAG_SOUND: u16 = 0x0002;
const SENSOR_FLAG_IR: u16    = 0x0004;

/// Helper: write sensor data to user buffer (handles both kernel and user-space callers).
/// Builds data in a kernel-side tmp buffer, then copies to user via copy_to_user if needed.
fn sensor_write_to_user(buf_ptr: u64, buf_len: u64, data: &[u8]) -> i64 {
    // **The bound lives here, not only in the caller** (owner decision 100).
    //
    // Every arm of `sensor_read_into` already refuses `buf_len < SIZE` before
    // calling this — all nine of them, checked. That is nine copies of one
    // rule, and the tenth sensor type is the one that forgets: this function
    // would then write `data.len()` bytes into a buffer the caller said was
    // smaller, through `copy_to_user`, which validates the PAGES and not the
    // caller's declared length.
    //
    // So the check is made local to the write. The per-arm checks stay — they
    // return early before reading a device — but the write is no longer
    // correct only by their grace. Refuses rather than truncates: a short
    // sensor reading silently cut in half is worse than an error, because the
    // caller cannot tell it happened.
    if data.len() as u64 > buf_len {
        return -1;
    }
    if azos_sched::current_user_pt() != 0 {
        // User-space caller — safe copy via page table walk
        if azos_sched::copy_to_user(buf_ptr as usize, data.as_ptr(), data.len()) {
            data.len() as i64
        } else {
            -1
        }
    } else {
        // Kernel caller — direct copy
        let out = unsafe {
            core::slice::from_raw_parts_mut(buf_ptr as *mut u8, data.len())
        };
        out.copy_from_slice(data);
        data.len() as i64
    }
}

/// `SYS_SENSOR_READ_TYPED` (561): a0=cap, a1=out_ptr, a2=out_len.
///
/// The sensor TYPE comes from the capability. There is no type argument, so
/// reading a sensor the caller does not hold is not a request this ABI can
/// express. The read itself is `sensor_read_dispatch` below.
pub fn sys_sensor_read_typed(cap_raw: u64, out_ptr: u64, out_len: u64) -> i64 {
    let sensor_type = match sensor_type_of_cap(cap_raw) {
        Ok(t) => t,
        Err(e) => return e,
    };
    sensor_read_dispatch(sensor_type, out_ptr, out_len)
}

/// The sensor type a `Cap<Sensor>` with `READ` in the caller's own table
/// names, or the errno to return — the one capability check 561 and 606
/// share, so a refusal is recorded once, under `Sensor`, by either.
fn sensor_type_of_cap(cap_raw: u64) -> Result<u64, i64> {
    use azos_abi::cap::CapHandle;
    use azos_abi::error::Errno;
    use azos_ipc::cap::{targets::Sensor, Cap};

    let cap: Cap<Sensor> = Cap::from_raw(CapHandle::from_raw(cap_raw as u32));
    let tid = azos_sched::current_task_tid();
    match azos_ipc::cap_store::with_table(tid, |t| {
        azos_ipc::sensor_cap::sensor_type_of(t, cap)
    }) {
        Some(Ok(t)) => Ok(t as u64),
        // One record, under Sensor: the mapper records, so nothing here does.
        Some(Err(e)) => Err(errno_for_cap_err(azos_abi::cap::CapKind::Sensor, e)),
        None => Err(Errno::EINVAL.to_syscall_ret()),
    }
}

/// `SYS_SENSOR_READ_TS` (606): a0=cap, a1=out_ptr, a2=out_len.
///
/// The read 561 makes, behind a `azos_abi::sensor_sample` header that
/// carries the value's acquisition time. A fixed-size record is copied out
/// with its header in one copy; a LiDAR scan or a camera frame goes to
/// `out_ptr + SENSOR_SAMPLE_HDR_LEN` and the header to `out_ptr` by two: the
/// frame is 19,200 bytes and is never assembled with its header in a kernel
/// buffer (see `CAM_BUF`). `out_len` must hold both —
/// refused, never truncated, as 561 refuses a short buffer. An arm that has
/// no data returns 0 and nothing is written, as through 561.
pub fn sys_sensor_read_ts(cap_raw: u64, out_ptr: u64, out_len: u64) -> i64 {
    use azos_abi::sensor_sample::{SensorSampleHdr, SENSOR_SAMPLE_HDR_LEN};
    let sensor_type = match sensor_type_of_cap(cap_raw) {
        Ok(t) => t,
        Err(e) => return e,
    };
    const HDR: u64 = SENSOR_SAMPLE_HDR_LEN as u64;
    if out_ptr == 0 || out_len < HDR { return -1; }
    let Some(payload_ptr) = out_ptr.checked_add(HDR) else { return -1 };
    let payload_cap = out_len - HDR;
    sensor_read_into(sensor_type, payload_cap, |data, meta| {
        let hdr = SensorSampleHdr::new(meta.flags, data.len() as u32, meta.acq_ns).to_bytes();
        // Every fixed-size record (24 bytes at most) goes out with its header
        // in ONE copy — one walk of the caller's page table, not two.
        const SMALL: usize = 64;
        if data.len() <= SMALL - SENSOR_SAMPLE_HDR_LEN {
            if data.len() as u64 > payload_cap { return -1; }
            let mut one = [0u8; SMALL];
            one[..SENSOR_SAMPLE_HDR_LEN].copy_from_slice(&hdr);
            one[SENSOR_SAMPLE_HDR_LEN..SENSOR_SAMPLE_HDR_LEN + data.len()].copy_from_slice(data);
            let total = SENSOR_SAMPLE_HDR_LEN + data.len();
            return sensor_write_to_user(out_ptr, out_len, &one[..total]);
        }
        let n = sensor_write_to_user(payload_ptr, payload_cap, data);
        if n < 0 { return n; }
        if sensor_write_to_user(out_ptr, HDR, &hdr) < 0 { return -1; }
        n + HDR as i64
    })
}

/// What an arm of [`sensor_read_into`] knows about its value besides the
/// bytes: when it was acquired and how. `acq_ns` is on the vDSO clock
/// (`azos_abi::sensor_sample`); 0 = unknown.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SampleMeta {
    pub acq_ns: u64,
    /// `azos_abi::sensor_sample::SENSOR_SAMPLE_FLAG_*`.
    pub flags: u16,
}

impl SampleMeta {
    /// From an acquisition stamp in timebase ticks (0 stays 0, "unknown"),
    /// converted exactly as the vDSO reader converts its own counter
    /// (`ticks_to_ns` at the frequency the page publishes), so a ring-3
    /// reader compares it with `vdso_now_ns()` directly.
    pub(crate) fn at_ticks(ticks: u64, flags: u16) -> Self {
        let acq_ns = if ticks == 0 {
            0
        } else {
            azos_abi::time::ticks_to_ns(ticks, azos_drv_sys::timebase::TIMER_FREQ)
        };
        Self { acq_ns, flags }
    }
}

/// `SENSOR_SAMPLE_FLAG_SYNTHETIC`, under a short name for the arms below.
const SYNTHETIC: u16 = azos_abi::sensor_sample::SENSOR_SAMPLE_FLAG_SYNTHETIC;

/// The sensor read itself, with the capability question already settled.
///
/// Called by `sys_sensor_read_typed` (type from the capability). Callers MUST
/// have authorised `sensor_type` before calling: this function performs no
/// capability check of any kind.
fn sensor_read_dispatch(sensor_type: u64, buf_ptr: u64, buf_len: u64) -> i64 {
    if buf_ptr == 0 { return -1; }
    sensor_read_into(sensor_type, buf_len, |data, _| sensor_write_to_user(buf_ptr, buf_len, data))
}

/// The sensor read with its destination left to the caller: the arm for
/// `sensor_type` builds the bytes and hands them to `sink` once, with the
/// value's [`SampleMeta`], and `sink`'s answer is the call's.
///
/// Three doors reach it: `sensor_read_dispatch` (561; its sink copies to the
/// caller's pointer and drops the meta), [`sys_sensor_read_ts`] (606; header
/// and payload) and the kernel's io_ring op table (`crate::ioring_ops`; its
/// sink copies into the ring's data buffer). One function, so a sensor reads
/// the same through all three. Callers MUST have authorised `sensor_type`:
/// this performs no capability check of any kind.
///
/// **Where each stamp comes from** (`azos_abi::sensor_sample` states the
/// rule): the IMU, LiDAR, GPS and camera stamps are taken in their drivers;
/// odometry carries the time `odom_task` read the encoder counts it
/// integrated; the encoder, rangefinder, battery ADC and GPIO lines are read
/// here, and the counter is read right after the first device read returns.
pub(crate) fn sensor_read_into<F: FnOnce(&[u8], SampleMeta) -> i64>(sensor_type: u64, buf_len: u64, sink: F) -> i64 {
    // Without the Robot domain the IMU, odometry, encoder and GPS do not
    // exist (`crate::no_robot`): refused like a sensor that is not ready.
    #[cfg(not(feature = "domain-robot"))]
    if matches!(sensor_type, SENSOR_TYPE_IMU | SENSOR_TYPE_ODOM | SENSOR_TYPE_ENCODER | SENSOR_TYPE_GPS) {
        return -1;
    }
    match sensor_type {
        SENSOR_TYPE_IMU => {
            const IMU_DATA_SIZE: usize = 24; // 6 × i32
            if (buf_len as usize) < IMU_DATA_SIZE { return -1; }
            if let Some((imu, acq)) = azos_imu::imu_read_scaled_stamped() {
                let mut tmp = [0u8; IMU_DATA_SIZE];
                for i in 0..3 {
                    let b = imu.accel_mg[i].to_le_bytes();
                    tmp[i * 4..i * 4 + 4].copy_from_slice(&b);
                }
                for i in 0..3 {
                    let b = imu.gyro_mdps[i].to_le_bytes();
                    tmp[12 + i * 4..12 + i * 4 + 4].copy_from_slice(&b);
                }
                sink(&tmp, SampleMeta::at_ticks(acq, 0))
            } else {
                -1 // IMU not ready
            }
        }
        SENSOR_TYPE_ODOM => {
            const ODOM_DATA_SIZE: usize = 16; // 2 × i64
            if (buf_len as usize) < ODOM_DATA_SIZE { return -1; }
            let ((dist_mm, heading_cdeg), acq) = azos_robot::odom_get_stamped();
            let mut tmp = [0u8; ODOM_DATA_SIZE];
            tmp[0..8].copy_from_slice(&dist_mm.to_le_bytes());
            tmp[8..16].copy_from_slice(&heading_cdeg.to_le_bytes());
            sink(&tmp, SampleMeta::at_ticks(acq, 0))
        }
        SENSOR_TYPE_ENCODER => {
            const ENC_DATA_SIZE: usize = 16; // 2 × i64
            if (buf_len as usize) < ENC_DATA_SIZE { return -1; }
            let ((enc_l, enc_r), acq) = azos_robot::encoder_read_stamped();
            let mut tmp = [0u8; ENC_DATA_SIZE];
            tmp[0..8].copy_from_slice(&enc_l.to_le_bytes());
            tmp[8..16].copy_from_slice(&enc_r.to_le_bytes());
            sink(&tmp, SampleMeta::at_ticks(acq, 0))
        }
        SENSOR_TYPE_RANGE => {
            const RANGE_DATA_SIZE: usize = 4; // 2 × u16
            if (buf_len as usize) < RANGE_DATA_SIZE { return -1; }
            let front = azos_drv_sensor::rangefinder::us_read_mm(0).unwrap_or(0) as u16;
            let acq = azos_drv_sys::timebase::now();
            let right = azos_drv_sensor::rangefinder::us_read_mm(1).unwrap_or(0) as u16;
            let mut tmp = [0u8; RANGE_DATA_SIZE];
            tmp[0..2].copy_from_slice(&front.to_le_bytes());
            tmp[2..4].copy_from_slice(&right.to_le_bytes());
            // The rangefinder driver only simulates its sensors (its own doc):
            // the read is the measurement, and it is not a device's.
            sink(&tmp, SampleMeta::at_ticks(acq, SYNTHETIC))
        }
        SENSOR_TYPE_BATTERY => {
            const BATT_DATA_SIZE: usize = 2; // u16
            if (buf_len as usize) < BATT_DATA_SIZE { return -1; }
            const SIMULATED_BATTERY_MV: u16 = 3700;
            const BATTERY_ADC_CHANNEL: u8 = 0;
            const BATTERY_DIVIDER_RATIO: u32 = 2; // 1:1 voltage divider halves Vbat
            let measured = if azos_drv_sensor::ads1115::ads1115_is_initialized() {
                azos_drv_sensor::ads1115::ads1115_read_battery_mv(
                    BATTERY_ADC_CHANNEL, BATTERY_DIVIDER_RATIO
                )
            } else {
                None
            };
            let acq = azos_drv_sys::timebase::now();
            let (mv, flags) = match measured {
                Some(mv) => (mv as u16, 0),
                None => (SIMULATED_BATTERY_MV, SYNTHETIC),
            };
            sink(&mv.to_le_bytes(), SampleMeta::at_ticks(acq, flags))
        }
        SENSOR_TYPE_GPS => {
            const GPS_DATA_SIZE: usize = 16;
            if (buf_len as usize) < GPS_DATA_SIZE { return -1; }
            let mut tmp = [0u8; GPS_DATA_SIZE];
            // No fix: zeros, stamped "unknown" (nothing was acquired).
            let mut meta = SampleMeta::at_ticks(0, 0);
            if let Some(fix) = azos_gps::gps_read_stamped() {
                let pos = fix.pos;
                meta = SampleMeta::at_ticks(fix.acq, if fix.synthetic { SYNTHETIC } else { 0 });
                tmp[0..4].copy_from_slice(&pos.lat_deg7.to_le_bytes());
                tmp[4..8].copy_from_slice(&pos.lon_deg7.to_le_bytes());
                tmp[8..12].copy_from_slice(&pos.alt_mm.to_le_bytes());
                tmp[12] = pos.fix;
                tmp[13] = pos.sats;
                tmp[14..16].copy_from_slice(&0u16.to_le_bytes());
            }
            sink(&tmp, meta)
        }
        SENSOR_TYPE_LIDAR => {
            // Read latest LiDAR scan into user buffer
            // Data format: N × [angle_cdeg(u16 LE) + distance_mm(u16 LE)]
            let count = azos_drv_sensor::lidar::lidar_scan_count();
            if count == 0 { return 0; } // no scan available
            let needed = count * azos_drv_sensor::lidar::SCAN_POINT_SIZE;
            if (buf_len as usize) < needed { return -1; }
            // Read into kernel tmp buffer, then copy to user
            let mut tmp = [0u8; azos_drv_sensor::lidar::SCAN_DATA_MAX_BYTES];
            let (bytes, acq) = azos_drv_sensor::lidar::lidar_read_scan_stamped(&mut tmp);
            if bytes == 0 { return 0; }
            sink(&tmp[..bytes], SampleMeta::at_ticks(acq, 0))
        }
        SENSOR_TYPE_GPIO_FLAGS => {
            const FLAGS_DATA_SIZE: usize = 2; // u16
            if (buf_len as usize) < FLAGS_DATA_SIZE { return -1; }
            let mut flags: u16 = 0;
            if azos_drv_gpio::gpio::gpio_read(GPIO_PIN_PIR) == 1 {
                flags |= SENSOR_FLAG_PIR;
            }
            let acq = azos_drv_sys::timebase::now();
            if azos_drv_gpio::gpio::gpio_read(GPIO_PIN_SOUND) == 1 {
                flags |= SENSOR_FLAG_SOUND;
            }
            if azos_drv_gpio::gpio::gpio_read(GPIO_PIN_IR) == 1 {
                flags |= SENSOR_FLAG_IR;
            }
            sink(&flags.to_le_bytes(), SampleMeta::at_ticks(acq, 0))
        }
        SENSOR_TYPE_POWER => {
            const PWR_SIZE: usize = azos_drv_sensor::ina219::POWER_DATA_SIZE;
            if (buf_len as usize) < PWR_SIZE { return -1; }
            let mut tmp = [0u8; PWR_SIZE];
            // The ring-3 driver stamps its own register reads, on the vDSO
            // clock already (`power_op::READ_TS`).
            let (n, acq_ns) = azos_drv_sensor::ina219::ina219_read_power_stamped(&mut tmp);
            if n == 0 { return 0; }
            sink(&tmp[..n], SampleMeta { acq_ns, flags: 0 })
        }
        SENSOR_TYPE_CAMERA => {
            // The JPEG frame lives in a static, not on the kernel stack.
            //
            // WHY: `JPEG_MAX_SIZE` is 19,200 bytes and a task's kernel stack is
            // 16 KiB with the bottom 4 KiB as a guard page — 12 KiB usable.
            // Rust emits no stack probes, so the prologue of this handler moved
            // `sp` *past* the guard page in one step and landed in the adjacent
            // task's stack.  The guard never fires; the result is silent
            // cross-task memory corruption instead of a clean fault.  Same
            // bounce-buffer shape `sys_disk_read`/`sys_disk_write` already use.
            //
            // A `PiMutex`, not a `SpinLock`, and for the same reason as
            // `KERNEL_FD_TABLE` above. This guard is held across
            // `csi_capture_jpeg` — itself a ~300-block JPEG encode — AND the
            // `sensor_write_to_user` copy that follows, so it nests the exact
            // cost `JPEG_RAW` inside `crates/drivers/sensor/src/csi.rs` was written
            // to keep preemptible. Under a `SpinLock` this whole
            // encode-plus-copy became non-preemptible with K-C29 step 2
            // (`eeda7c4`), on top of whatever `JPEG_RAW`'s own lock cost.
            // `PiMutexGuard` takes no preempt count, so the 1 kHz tick can
            // still land here, and a second caller contending for the
            // buffer is boosted-and-yields instead of spinning blind for
            // the encode's duration.
            static CAM_BUF: PiMutex<[u8; azos_drv_sensor::csi::JPEG_MAX_SIZE]> =
                PiMutex::new([0u8; azos_drv_sensor::csi::JPEG_MAX_SIZE]);
            let mut jpeg_buf = CAM_BUF.lock();
            let (jpeg_len, acq) = azos_drv_sensor::csi::csi_capture_jpeg_stamped(&mut jpeg_buf[..]);
            if jpeg_len == 0 { return 0; }
            // Clamp before slicing: a driver reporting more than the buffer
            // holds must not panic here (`panic = "abort"` → board reset).
            let jpeg_len = jpeg_len.min(azos_drv_sensor::csi::JPEG_MAX_SIZE);
            if (buf_len as usize) < jpeg_len { return -1; }
            // The CSI frames are a generated test pattern (`csi.rs`).
            sink(&jpeg_buf[..jpeg_len], SampleMeta::at_ticks(acq, SYNTHETIC))
        }
        _ => -1,
    }
}

// ── ADC (ADS1115) ────────────────────────────────────────────────────────────

/// Read ADC channel in millivolts.  a0 = channel (0-3), returns mv or -1.
pub fn sys_adc_read(channel: u64) -> i64 {
    // Gate FIRST, like every sibling in this family. After the range check it
    // would still close the hole, but an unauthorised caller would learn which
    // channels exist from the difference between -1 and E_PERM, and the
    // ordering would be the one thing about this handler that did not match
    // its neighbours.
    // `CapKind::Adc` has no minter and no topology name, so no ring-3 table
    // holds it: every ring-3 call is refused and recorded.
    if !cap_check(azos_abi::cap::CapKind::Adc, channel as u8 as u32, false) { return E_PERM; }
    if channel > 3 { return -1; }
    match azos_drv_sensor::ads1115::ads1115_read_mv(channel as u8) {
        Some(mv) => mv as i64,
        None => -1,
    }
}

// ── Buzzer ───────────────────────────────────────────────────────────────────

/// Play a tone.  a0 = frequency in Hz, a1 = duration in ms.
///
/// Returns once the tone has STARTED: the ring-3 buzzer driver plays it
/// against its own clock (wave 9). The in-kernel driver busy-waited here for
/// the whole duration.
pub fn sys_buzzer_tone(freq_hz: u64, duration_ms: u64) -> i64 {
    if !cap_check(azos_abi::cap::CapKind::Buzzer, 0, true) { return E_PERM; }
    const MAX_BUZZER_FREQ_HZ: u16 = 20_000;
    const MAX_BUZZER_DURATION_MS: u32 = 10_000;
    // Clamp in u64, THEN narrow. `(freq_hz as u16).min(..)` cannot clamp what
    // the cast already wrapped: `freq_hz = 0x1_0000` became 0 Hz and was
    // reported as success (2026-09-19 audit).
    let freq = freq_hz.min(MAX_BUZZER_FREQ_HZ as u64) as u16;
    let dur = (duration_ms as u32).min(MAX_BUZZER_DURATION_MS);
    azos_drv_actuator::buzzer::buzzer_tone(freq, dur);
    0
}

/// Stop buzzer.
pub fn sys_buzzer_off() -> i64 {
    if !cap_check(azos_abi::cap::CapKind::Buzzer, 0, true) { return E_PERM; }
    azos_drv_actuator::buzzer::buzzer_off();
    0
}

// ── E11.AQ3 — Userspace driver framework ─────────────────────────────────────
//
// Each syscall forwards to crates/drivers/driver_server. The caller_tid is the
// current task id (from sched), used to route replies and block the
// right waiter.

fn driver_caller_tid() -> u32 {
    azos_sched::current_task_tid()
}

/// `SYS_CAP_LOOKUP` (558): a0 = `CapKind` as u8, a1 = resource index.
///
/// Returns the caller's own handle as a non-negative value, `-ENOENT` if it
/// holds no such capability, `-EINVAL` for a kind byte that is not a
/// `CapKind`.
///
/// # Three things this deliberately does not do
///
/// **It does not take a TID.** The table is always `current_task_tid()`'s, so
/// there is no argument by which a caller could ask about another task — the
/// same shape as `SYS_DRIVER_REGISTER_TYPED` having no kind argument.
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
    use azos_abi::cap::CapKind;
    use azos_abi::error::Errno;

    if kind_raw > u8::MAX as u64 {
        return Errno::EINVAL.to_syscall_ret();
    }
    let kind = match CapKind::from_raw(kind_raw as u8) {
        Some(k) => k,
        None => return Errno::EINVAL.to_syscall_ret(),
    };
    if resource > u32::MAX as u64 {
        return Errno::EINVAL.to_syscall_ret();
    }
    let tid = azos_sched::current_task_tid();
    // Wave 11 (SHMRING): a `Shm` lookup may name a kernel stream by its key
    // (`SHM_STREAM_*`), since the consumer cannot know the region's packed
    // reference; the table is then asked about that region.
    let resource = if kind == CapKind::Shm {
        azos_ipc::stream_ring::stream_lookup_resource(resource as u32) as u64
    } else {
        resource
    };
    match azos_ipc::cap_store::with_table(tid, |t| t.lookup(kind, resource as u32)) {
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

// ── Cap<DriverRegistry> typed handlers — RFC-0003, 2026-09-06 ─────────────

/// The errno for a bare `CapError`, recorded under `kind`.
///
/// **The kind is an argument because this mapper is shared.** It used to write
/// every refusal as `DriverRegistry`, which was right for the two registry
/// handlers and wrong for `sys_sensor_read_typed` — which therefore recorded
/// its own `Sensor` denial and then called this, so one typed sensor denial
/// put TWO records in the ring, the second under the wrong device. A mapper
/// that decides the kind for its callers is how that happens; one that is told
/// cannot. Audit finding, 2026-09-13: it was the only double path — every
/// other family has a mapper of its own and no caller that also records.
pub(crate) fn errno_for_cap_err(kind: azos_abi::cap::CapKind, e: azos_ipc::cap::CapError) -> i64 {
    use azos_abi::error::Errno;
    use azos_ipc::cap::CapError;
    // Every typed refusal in this file reaches the recorder here — the one
    // choke point all twelve of these functions share. `Contained` is filtered
    // inside `note_typed_denial`, not here.
    note_typed_denial(kind, e);
    match e {
        CapError::Stale => Errno::ECAPSTALE.to_syscall_ret(),
        CapError::WrongKind => Errno::ECAPKIND.to_syscall_ret(),
        CapError::MissingPerms => Errno::ECAPPERMS.to_syscall_ret(),
        CapError::Contained => Errno::EAGAIN.to_syscall_ret(),
        CapError::NoSpace => Errno::EMFILE.to_syscall_ret(),
    }
}

/// `SYS_DRIVER_REGISTER_TYPED` (556): a0=cap, a1=mmio_base, a2=mmio_size,
/// a3=irq. Returns 0, or `-Errno`.
///
/// The registered kind comes from the capability, never from an argument —
/// see `SYS_DRIVER_REGISTER_TYPED`'s doc in `crates/core/abi/src/syscall_nr.rs`.
/// Registration claims exclusive identity as the driver for a device, which
/// is why it needs the capability. `mmio_base`/`mmio_size` are inert (ring 3
/// maps MMIO only through `SYS_MMIO_MAP`, gated on `MmioRegion`); they are
/// carried because the registry stores them.
pub fn sys_driver_register_typed(cap_raw: u64, mmio_base: u64, mmio_size: u64, irq: u64) -> i64 {
    use azos_abi::cap::CapHandle;
    use azos_abi::error::Errno;
    use azos_ipc::cap::{targets::DriverRegistry, Cap};

    let cap: Cap<DriverRegistry> = Cap::from_raw(CapHandle::from_raw(cap_raw as u32));
    let tid = azos_sched::current_task_tid();
    let kind = match azos_ipc::cap_store::with_table(tid, |table| {
        azos_ipc::drvreg_cap::drvreg_kind_of(table, cap)
    }) {
        Some(Ok(k)) => k,
        Some(Err(e)) => return errno_for_cap_err(azos_abi::cap::CapKind::DriverRegistry, e),
        None => return Errno::EINVAL.to_syscall_ret(),
    };
    // `driver_caller_tid()` is `current_task_tid()` — the same identity the
    // cap table was just keyed on. Verified rather than assumed, because a
    // divergence here would authorise one task and register another.
    let ok = azos_driver_server::driver_register(
        kind,
        driver_caller_tid(),
        mmio_base,
        mmio_size,
        irq as u32,
    );
    // `driver_register` returns false for "already registered" and for "no
    // free slot" without distinguishing them, so neither can be reported
    // precisely. EBUSY is the honest one of the two: a caller holding a valid
    // cap that is refused is being told the kind is taken, which is true in
    // both cases from its side.
    if !ok {
        return Errno::EBUSY.to_syscall_ret();
    }
    driver_supervise_bind(kind, tid);
    0
}

/// RFC-0049 M4: a task the autorun loader started from an image has just
/// registered `kind`. From here on the kernel restarts it when it dies
/// (`azos_sched::supervisor`). A task the loader did not start (a fork
/// child, a `SYS_SPAWN` child) is not supervised and nothing changes for it.
fn driver_supervise_bind(kind: u32, tid: u32) {
    use azos_sched::supervisor::{sup_bind, BindOutcome};
    let now = azos_drv_sys::timebase::now();
    match sup_bind(kind, tid, now) {
        BindOutcome::First { .. } => azos_drv_sys::kprintln!(
            "[SUP] tid={} serves driver kind {:#x}: supervised, restarted on failure",
            tid, kind,
        ),
        BindOutcome::Restored { attempt, since_death, .. } => {
            let per_ms = (azos_drv_sys::timebase::TIMER_FREQ / 1000).max(1);
            azos_drv_sys::kprintln!(
                "[SUP] tid={} serves driver kind {:#x} again: restart {} of its window \
                 registered {} ms after the death",
                tid, kind, attempt, since_death / per_ms,
            );
        }
        BindOutcome::AlreadyServing { .. } | BindOutcome::NotSupervised => {}
    }
}

/// RFC-0049 M4: the one place a driver the kernel asked to stop
/// (`azos_driver_server::driver_request_stop`) exits.
///
/// Called first in the driver-side calls a serve loop is made of — fetch,
/// reply, reply+fetch, reply+wait (and after each of its wakes) and poll — so
/// a driver that is serving, idling in its loop or parked, ends at its next
/// call. It costs one atomic load while no stop is
/// pending anywhere (`driver_stop_pending`), and it is not on the syscall
/// dispatcher's path: only these five handlers call it. Kernel callers are
/// never stopped here: they are not the driver.
fn driver_stop_point(kind: u64) {
    if !azos_driver_server::driver_stop_pending() {
        return;
    }
    if azos_sched::current_user_pt() == 0 {
        return;
    }
    let tid = driver_caller_tid();
    if let Some(code) = azos_driver_server::driver_take_stop_code(kind as u32, tid) {
        azos_drv_sys::kwarn!(
            "[SUP] tid={} stopped by the kernel at its driver call (kind {:#x}, exit {})",
            tid, kind, code,
        );
        azos_sched::task_exit_with_code(code);
    }
}

/// `SYS_DRIVER_UNREGISTER_TYPED` (557): a0=cap. Returns 0, or `-Errno`.
pub fn sys_driver_unregister_typed(cap_raw: u64) -> i64 {
    use azos_abi::cap::CapHandle;
    use azos_abi::error::Errno;
    use azos_ipc::cap::{targets::DriverRegistry, Cap};

    let cap: Cap<DriverRegistry> = Cap::from_raw(CapHandle::from_raw(cap_raw as u32));
    let tid = azos_sched::current_task_tid();
    // A release: `WRITE`, without the containment step (owner decision
    // 2026-09-13) — see `drvreg_kind_for_release`.
    let kind = match azos_ipc::cap_store::with_table(tid, |table| {
        azos_ipc::drvreg_cap::drvreg_kind_for_release(table, cap)
    }) {
        Some(Ok(k)) => k,
        Some(Err(e)) => return errno_for_cap_err(azos_abi::cap::CapKind::DriverRegistry, e),
        None => return Errno::EINVAL.to_syscall_ret(),
    };
    if azos_driver_server::driver_unregister(kind) { 0 } else { Errno::EINVAL.to_syscall_ret() }
}

/// Poll for the next event for this driver kind. a0=kind, a1=user_out_ptr.
pub fn sys_driver_poll_event(kind: u64, user_out_ptr: u64) -> i64 {
    driver_stop_point(kind);
    // Only the task that registered this kind may touch its traffic.
    //
    // `driver_tid` was recorded at registration and read nowhere, so any task
    // could drain another driver's queue — `fetch` POPS, so the real driver
    // never saw the request — or write its reply. Kernel callers (`user_pt`
    // 0) are exempt as everywhere else in this file.
    if azos_sched::current_user_pt() != 0
        && !azos_driver_server::driver_is_owner(kind as u32, driver_caller_tid())
    {
        return E_PERM;
    }
    // Same order-of-operations defect as `sys_driver_fetch_request`, and the
    // same fix: `driver_poll_event` CONSUMES the latched IRQ -- it swaps the
    // pending flag to false -- so a copy that fails afterwards drops an
    // interrupt that will never be signalled again. The driver waits on an
    // event that already happened.
    //
    // Validated up front rather than after, because there is no way to put a
    // latched interrupt back.
    if user_out_ptr != 0
        && !azos_sched::user_range_prepare_write(user_out_ptr as usize, 8)
    {
        return -1;
    }
    let (evt, payload) = azos_driver_server::driver_poll_event(kind as u32);
    if user_out_ptr != 0 {
        // Same boundary rule as fetch/reply — raw write_volatile to a user VA
        // faults (no SUM bit, no pointer validation). Go through copy_to_user
        // when called from a user process.
        let bytes = payload.to_ne_bytes();
        if azos_sched::current_user_pt() != 0 {
            if !azos_sched::copy_to_user(user_out_ptr as usize, bytes.as_ptr(), bytes.len()) {
                return -1;
            }
        } else {
            unsafe { core::ptr::write_volatile(user_out_ptr as *mut u64, payload); }
        }
    }
    evt as i64
}

/// Only the task that registered `kind` may touch its traffic.
///
/// `driver_tid` was recorded at registration and read nowhere, so any task
/// could drain another driver's queue — `fetch` POPS, so the real driver
/// never saw the request — or write its reply. Kernel callers (`user_pt`
/// 0) are exempt as everywhere else in this file.
pub(crate) fn driver_traffic_allowed(kind: u64) -> bool {
    azos_sched::current_user_pt() == 0
        || azos_driver_server::driver_is_owner(kind as u32, driver_caller_tid())
}

/// Whether a whole `DriverRequest` fits at `user_buf_ptr`.
///
/// Checked BEFORE popping. `driver_fetch_request` removes the request from
/// the queue, and until this check existed a destination whose base was
/// mapped but whose tail ran into an unmapped page -- the narrowest possible
/// bad pointer, and one a buggy driver hits by accident -- made the copy
/// fail, the fetch return -1, and the request vanish. No other consumer would
/// ever see it, and the client that submitted it waited forever. Answering
/// "-1" while silently eating the caller's work is worse than either
/// succeeding or failing cleanly.
fn driver_request_buf_writable(user_buf_ptr: u64) -> bool {
    azos_sched::user_range_prepare_write(
        user_buf_ptr as usize,
        core::mem::size_of::<azos_driver_server::DriverRequest>(),
    )
}

/// Read the caller's `DriverReply`, or `None` when the copy fails.
fn driver_read_reply(user_reply_ptr: u64) -> Option<azos_driver_server::DriverReply> {
    // Same boundary rule as fetch: read the reply via copy_from_user.
    let mut reply = azos_driver_server::DriverReply::zeroed();
    let n = core::mem::size_of::<azos_driver_server::DriverReply>();
    if azos_sched::current_user_pt() != 0 {
        if !azos_sched::copy_from_user(
            &mut reply as *mut azos_driver_server::DriverReply as *mut u8,
            user_reply_ptr as usize,
            n,
        ) {
            return None;
        }
    } else {
        reply = unsafe {
            core::ptr::read_volatile(
                user_reply_ptr as *const azos_driver_server::DriverReply,
            )
        };
    }
    Some(reply)
}

/// Fetch the next pending DriverRequest. a0=kind, a1=user_buf_ptr.
pub fn sys_driver_fetch_request(kind: u64, user_buf_ptr: u64) -> i64 {
    driver_stop_point(kind);
    if !driver_traffic_allowed(kind) {
        return E_PERM;
    }
    if user_buf_ptr == 0 { return -1; }
    if !driver_request_buf_writable(user_buf_ptr) {
        return -1;
    }
    driver_pop_request_into(kind, user_buf_ptr)
}

/// Publish a reply and fetch the next request, in one trap (RFC-0041 §D).
/// a0=kind, a1=user_reply_ptr (0: no reply owed), a2=user_buf_ptr.
///
/// `0`: the reply, if any, was published and a request was written. `-1`: the
/// reply, if any, was published and the queue is empty. Every other return
/// did nothing: `E_PERM` for a task that is not the kind's driver, `-4` for a
/// request buffer that is null or not writable, `-3` for a reply that cannot
/// be read or published.
///
/// **Why every refusal runs before the reply is published.** A driver told
/// "failed" must be able to trust that its reply did not go out, or it cannot
/// decide whether to send it again. Sending one twice is not harmless: a
/// duplicate for a token whose polling client has not read it yet replaces
/// that token's entry in the kind's reply ring (an armed kernel client's row
/// keeps the first). So the request buffer is
/// checked first, the reply is published second, and the fetch runs only
/// after a publish that happened.
pub fn sys_driver_reply_fetch(kind: u64, user_reply_ptr: u64, user_buf_ptr: u64) -> i64 {
    driver_stop_point(kind);
    if !driver_traffic_allowed(kind) {
        return E_PERM;
    }
    if user_buf_ptr == 0 || !driver_request_buf_writable(user_buf_ptr) {
        return -4;
    }
    if user_reply_ptr != 0 {
        let reply = match driver_read_reply(user_reply_ptr) {
            Some(r) => r,
            None => return -3,
        };
        if !azos_driver_server::driver_reply(kind as u32, reply) {
            return -3;
        }
    }
    driver_pop_request_into(kind, user_buf_ptr)
}

/// Longest park `SYS_DRIVER_REPLY_WAIT` takes when the caller passes 0.
const DRIVER_PARK_DEFAULT_MS: u64 = 1000;

/// `SYS_DRIVER_REPLY_WAIT` (610): [`sys_driver_reply_fetch`], except that an
/// empty queue parks the driver until a request is queued or `park_ms`
/// (0 = [`DRIVER_PARK_DEFAULT_MS`], at most that) passes.
///
/// A driver on 581 has to poll its queue, so it is runnable for as long as it
/// lives, and the hart it sits on never idles. This call lets a service that
/// answers ten requests a second be blocked the rest of the time. Every ring-3
/// driver in the tree serves on it (wave 10: `gpio_drv`, `buzz_drv` and
/// `ina_drv` moved off 581's poll; `mlsrv` started on it). The wake is the
/// submit path's (`driver_fetch_or_park`'s doc has the lost-wake argument);
/// a proxy client donates its priority to the driver after that wake, as it
/// did to a polling one (`UserDriverProxy::call_timeout_us`).
///
/// Every refusal runs before the reply is published, exactly as 581's.
pub fn sys_driver_reply_wait(kind: u64, user_reply_ptr: u64, user_buf_ptr: u64, park_ms: u64) -> i64 {
    driver_stop_point(kind);
    if !driver_traffic_allowed(kind) {
        return E_PERM;
    }
    if user_buf_ptr == 0 || !driver_request_buf_writable(user_buf_ptr) {
        return -4;
    }
    if user_reply_ptr != 0 {
        let reply = match driver_read_reply(user_reply_ptr) {
            Some(r) => r,
            None => return -3,
        };
        if !azos_driver_server::driver_reply(kind as u32, reply) {
            return -3;
        }
    }
    // No hooks installed, nothing could wake a park; and a kernel-context
    // caller is not the kind's registered task, so it cannot be the one a
    // submit wakes. Both answer as 581 does.
    let Some(hooks) = azos_driver_server::reply_wait::proxy_hooks() else {
        return driver_pop_request_into(kind, user_buf_ptr);
    };
    if azos_sched::current_user_pt() == 0 {
        return driver_pop_request_into(kind, user_buf_ptr);
    }
    let ms = if park_ms == 0 { DRIVER_PARK_DEFAULT_MS } else { park_ms.min(DRIVER_PARK_DEFAULT_MS) };
    let me = driver_caller_tid();
    let deadline = azos_drv_sys::timebase::now().saturating_add(
        azos_drv_sys::timebase::TIMER_FREQ.saturating_mul(ms) / 1000,
    );
    use azos_driver_server::FetchOrPark;
    loop {
        match azos_driver_server::driver_fetch_or_park(kind as u32, me, deadline) {
            FetchOrPark::Request(req) => return driver_copy_request_out(req, user_buf_ptr),
            // Released between the check above and here (the kind was
            // unregistered): nothing parked, nothing taken.
            FetchOrPark::NotOwner => return -1,
            FetchOrPark::Parked => {}
        }
        if azos_drv_sys::timebase::now() >= deadline || (hooks.block)(deadline) {
            // The park ended with no wake (deadline, or a refused block):
            // withdraw it, then one last look, so a request queued in between
            // is taken now rather than on the next call.
            let _ = azos_driver_server::driver_unpark(kind as u32, me);
            return match azos_driver_server::driver_fetch_after_park(kind as u32) {
                Some(req) => driver_copy_request_out(req, user_buf_ptr),
                None => -1,
            };
        }
        // Woken (a request, an early stamp, the deadline, or a stop request
        // — `driver_request_stop` wakes a parked driver): stop here if asked,
        // else look again.
        driver_stop_point(kind);
        // Woken by the deadline itself: end the park as above rather than
        // re-parking on a deadline already past (one more `REGISTRY` hold,
        // and a second idle pass counted for one park).
        if azos_drv_sys::timebase::now() >= deadline {
            let _ = azos_driver_server::driver_unpark(kind as u32, me);
            return match azos_driver_server::driver_fetch_after_park(kind as u32) {
                Some(req) => driver_copy_request_out(req, user_buf_ptr),
                None => -1,
            };
        }
    }
}

/// Pop `kind`'s next request into `user_buf_ptr`, which the caller has
/// already checked with [`driver_request_buf_writable`]. 0, or -1 when the
/// queue is empty.
fn driver_pop_request_into(kind: u64, user_buf_ptr: u64) -> i64 {
    match azos_driver_server::driver_fetch_request(kind as u32) {
        Some(req) => driver_copy_request_out(req, user_buf_ptr),
        None => -1,
    }
}

/// Copy a request already taken off the queue to `user_buf_ptr` (checked
/// with [`driver_request_buf_writable`]). 0, or -1 when the copy failed.
fn driver_copy_request_out(req: azos_driver_server::DriverRequest, user_buf_ptr: u64) -> i64 {
    // The userspace driver's buffer must be written via copy_to_user:
    // a raw write_volatile to the user VA faults (no SUM bit, no
    // pointer validation). DriverRequest is #[repr(C)] so its byte
    // image is identical to the userspace mirror.
    let n = core::mem::size_of::<azos_driver_server::DriverRequest>();
    let ok = if azos_sched::current_user_pt() != 0 {
        azos_sched::copy_to_user(
            user_buf_ptr as usize,
            &req as *const azos_driver_server::DriverRequest as *const u8,
            n,
        )
    } else {
        unsafe {
            core::ptr::write_volatile(
                user_buf_ptr as *mut azos_driver_server::DriverRequest,
                req,
            );
        }
        true
    };
    if !ok { return -1; }
    azos_driver_server::TOTAL_REQUESTS
        .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    0
}

/// Publish a DriverReply. a0=kind, a1=user_reply_ptr.
pub fn sys_driver_reply(kind: u64, user_reply_ptr: u64) -> i64 {
    driver_stop_point(kind);
    if !driver_traffic_allowed(kind) {
        return E_PERM;
    }
    if user_reply_ptr == 0 { return -1; }
    let reply = match driver_read_reply(user_reply_ptr) {
        Some(r) => r,
        None => return -1,
    };
    if azos_driver_server::driver_reply(kind as u32, reply) { 0 } else { -1 }
}

// 525/526 (`sys_driver_request`, `sys_driver_try_reply`) were retired in
// wave 11 (OVSwrap review F3): no capability, no ownership, guessable reply
// tokens. See `azos_abi::syscall_nr::RETIRED_SYSCALLS`.
/// Copy DriverServerStats into user buffer.
pub fn sys_driver_stats(user_out_ptr: u64) -> i64 {
    if user_out_ptr == 0 { return -1; }
    let s = azos_driver_server::stats();
    let n = core::mem::size_of::<azos_driver_server::DriverServerStats>();
    let ok = if azos_sched::current_user_pt() != 0 {
        azos_sched::copy_to_user(
            user_out_ptr as usize,
            &s as *const azos_driver_server::DriverServerStats as *const u8,
            n,
        )
    } else {
        unsafe {
            core::ptr::write_volatile(
                user_out_ptr as *mut azos_driver_server::DriverServerStats, s,
            );
        }
        true
    };
    if ok { 0 } else { -1 }
}

// ── Former inline dispatch arms (wave 7) ─────────────────────────────────────
//
// The syscalls below were implemented inside `dispatch.rs`'s `match`, which no
// host test compiles. Their bodies moved here unchanged (owner decision round
// 7): same checks in the same order, same narrowing of each argument, same
// return codes. The ABI of each call is still documented at its arm.

/// The refusal code these calls returned from `dispatch.rs`, where the local
/// `E_PERM` is -1 and shadows this file's [`E_PERM`] (-99). Kept at -1: moving
/// a body must not change what ring 3 reads.
const E_PERM_DISPATCH: i64 = -1;

// ── Lease IPC (M04), 112-114, 602, 603 ───────────────────────────────────────

/// The grant by raw region id, once `SYS_IPC_LEASE_GRANT` (111, retired
/// 2026-09-28): a0 = shm_id, a1 = lessee TID (narrowed with `as u32`), a2 =
/// expire_ticks. No dispatch arm reaches it with a raw id any more:
/// [`sys_ipc_lease_grant_typed`] (603) calls it with the id its `Cap<Shm>`
/// resolves to, and the host suite calls it directly.
pub fn sys_ipc_lease_grant(shm_id: u64, lessee: u64, expire_ticks: u64) -> i64 {
    sys_ipc_lease_grant_opts(shm_id, lessee, expire_ticks, false)
}

/// [`sys_ipc_lease_grant`] with the producer-side seal when `seal` (wave 11,
/// LEASE3): the caller's recorded mapping of the region, if it has one, is
/// made read-only in the hold that allocates the lease
/// (`lease::lease_grant_sealed_as`). A kernel caller has no mapping to seal;
/// its grant is recorded as sealed with nothing to restore.
pub fn sys_ipc_lease_grant_opts(shm_id: u64, lessee: u64, expire_ticks: u64, seal: bool) -> i64 {
    let lessor = azos_sched::current_task_tid();
    let lessee = lessee as u32;
    let root = azos_sched::current_user_pt();
    let privileged = root == 0;
    let seal = seal.then(|| {
        let mapping = u32::try_from(shm_id).ok()
            .and_then(azos_ipc::shm::shm_ref)
            // The mapping is the process's (wave 15, plan 4a).
            .and_then(|r| azos_ipc::shm::shm_mapping_of_ref(azos_sched::current_proc_tid(), r).ok().flatten());
        match mapping {
            Some((va, pages)) if root != 0 => azos_ipc::lease::SealMap { root, va, pages },
            _ => azos_ipc::lease::SealMap::NONE,
        }
    });
    // The quota is counted, and the lessee woken, inside
    // `lease_grant_as`: the count in the same `LEASES` hold as the
    // allocation, the wake after the hold through
    // `wait::wake_lease_acceptor(lessee, lessor)`. That wake exists
    // because ACCEPT below sleeps until a grant (K-C10 audit: before
    // it, an ACCEPT that ran before its GRANT never woke), it stamps
    // `wake_pending` for a lessee that has not blocked yet, and it
    // dispatches only a task blocked on `LeaseAccept(lessee, lessor)`,
    // never one blocked as a fast-IPC server on the same TID.
    match azos_ipc::lease::lease_grant_sealed_as(shm_id as usize, lessor, lessee, expire_ticks, privileged, seal) {
        Ok(lease_id) => {
            // Wave 9: a ring-3 lessor gets the `Cap<Lease>` that
            // `SYS_IPC_LEASE_WAIT` checks. No room in its table: the grant
            // is undone rather than handing out a lease its lessor cannot
            // wait on (and the lessee is left with nothing to accept).
            if !privileged
                && azos_ipc::cap_store::grant::<azos_ipc::cap::targets::Lease>(
                    lessor, azos_ipc::cap::CapPerms::READ, lease_id as u32,
                ).is_none()
            {
                let _ = azos_ipc::lease_free(lease_id, lessor, false);
                return -1;
            }
            lease_id as i64
        }
        Err(e) => e.syscall_ret(),
    }
}

/// `SYS_IPC_LEASE_GRANT_TYPED` (603): a0 = `Cap<Shm>` (`READ`), a1 = lessee
/// TID in the low half and grant flags in the high half, a2 = expire_ticks.
/// The capability is resolved in the caller's own table and its region checked
/// live; the grant itself is [`sys_ipc_lease_grant_opts`]'s — same quota, same
/// `Cap<Lease>` mint, same codes — with the region index the capability names.
/// A refused capability answers `-ECAPSTALE`/`-ECAPKIND`/`-ECAPPERMS` and is
/// recorded once, under `Shm`.
///
/// Flags (wave 11, LEASE3): `LEASE_GRANT_SEAL` asks for the producer-side
/// write seal; any other bit is `-EINVAL`. A ring-3 caller whose topology row
/// says `lease_seal = true` must ask for it (`-EACCES` otherwise), checked
/// before anything is resolved or granted.
pub fn sys_ipc_lease_grant_typed(cap_raw: u64, lessee: u64, expire_ticks: u64) -> i64 {
    use azos_abi::cap::{CapHandle, CapKind};
    use azos_abi::error::Errno;
    use azos_abi::syscall_nr::LEASE_GRANT_SEAL;
    use azos_ipc::cap::{targets::Shm, Cap, CapPerms};
    let flags = lessee & !u64::from(u32::MAX);
    if flags & !LEASE_GRANT_SEAL != 0 {
        return Errno::EINVAL.to_syscall_ret();
    }
    let seal = flags & LEASE_GRANT_SEAL != 0;
    if !seal && azos_sched::current_user_pt() != 0 && lease_seal_required() {
        return Errno::EACCES.to_syscall_ret();
    }
    let caller = azos_sched::current_task_tid();
    let cap: Cap<Shm> = Cap::from_raw(CapHandle::from_raw(cap_raw as u32));
    let r = match azos_ipc::cap_store::get(caller, cap, CapPerms::READ) {
        Ok(r) => r,
        Err(e) => return errno_for_cap_err(CapKind::Shm, e),
    };
    let shm_id = match azos_ipc::shm::shm_index_ref(r) {
        Ok(i) => i,
        Err(e) => return crate::ipc_handlers::errno_for_shm_err(e),
    };
    sys_ipc_lease_grant_opts(shm_id as u64, lessee & u64::from(u32::MAX), expire_ticks, seal)
}

/// Does the calling task's topology row require sealed grants
/// (`lease_seal = true`, wave 11, LEASE3)? Resolved through the resolver the
/// kernel installs at boot ([`set_lease_seal_resolver`]); `false` without one
/// (no topology, the host suites).
fn lease_seal_required() -> bool {
    let raw = LEASE_SEAL_RESOLVER.load(core::sync::atomic::Ordering::Acquire);
    if raw == 0 {
        return false;
    }
    // SAFETY: only `set_lease_seal_resolver` stores here, and it stores a
    // `fn(&str) -> bool`.
    let f: fn(&str) -> bool = unsafe { core::mem::transmute::<usize, fn(&str) -> bool>(raw) };
    f(azos_sched::current_task_name())
}

static LEASE_SEAL_RESOLVER: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

/// Install the topology lookup [`sys_ipc_lease_grant_typed`] asks whether the
/// caller's row requires the seal (`topo_sched::lease_seal_required_for`).
/// Boot, once; host suites per test.
pub fn set_lease_seal_resolver(f: fn(&str) -> bool) {
    LEASE_SEAL_RESOLVER.store(f as usize, core::sync::atomic::Ordering::Release);
}

/// `SYS_IPC_LEASE_ACCEPT` (112): a0 = lessor TID. Blocks until a lease from
/// that lessor arrives.
///
/// `a0` bit 32 (`LEASE_ACCEPT_RETIRED_MAP_BIT`), the accept-and-map flag of
/// one integration round, is `-EINVAL`: accept-and-map is
/// [`sys_ipc_lease_accept_map`] (613).
pub fn sys_ipc_lease_accept(lessor: u64) -> i64 {
    if lessor & azos_abi::syscall_nr::LEASE_ACCEPT_RETIRED_MAP_BIT != 0 {
        return azos_abi::error::Errno::EINVAL.to_syscall_ret();
    }
    let lessee = azos_sched::current_task_tid();
    // Refused rather than truncated, as `lease_grant_as` treats a
    // region id: `0x1_0000_0005` must not stand for lessor 5. The
    // refusal is -1, the value of this arm's other refusals (owner
    // decision 2026-09-14), not -EINVAL.
    let lessor = match u32::try_from(lessor) {
        Ok(t) => t,
        Err(_) => return -1,
    };
    // The wait lives in `lease_accept_wait` so the host suite drives
    // it: the poll registers `(lessee, lessor)` in the same `LEASES`
    // hold, the loop blocks at most `LEASE_ACCEPT_TURNS` (8) times on
    // the reason `wake_lease_acceptor(lessee, lessor)` matches, and
    // the registration is dropped on the way out. The loop is bounded
    // because a return from `task_block` need not carry a lease: a
    // concurrent grant's stamp, a grant from another lessor landing
    // before the block (owner decision 2026-09-14: that costs a turn)
    // and a K-C29 refusal all come back with nothing from `lessor`.
    // When `lessor` exits, `lease_release_all` marks the registration
    // before its TID-directed wake, so the next poll answers at once
    // (owner decision 2026-09-14, replacing a wake without a mark,
    // after which the woken lessee blocked again).
    match azos_ipc::lease::lease_accept_wait(lessee, lessor, || {
        azos_sched::task_block_unless_killed(azos_sched::WaitReason::LeaseAccept(lessee, lessor));
    }) {
        Ok((lease_id, _shm_id)) => lease_id as i64,
        Err(_) => -1,
    }
}

/// `SYS_IPC_LEASE_ACCEPT_MAP` (613; wave 11, LEASE2/LEASE3): accept a
/// lease from `lessor` as the plain accept does, then map its region into the
/// caller for the life of the lease and write the address through `out_va`.
/// Returns the lease id.
///
/// The mapping is the LEASE's (`azos_ipc::lease`, "Leases that bite"):
/// its region reference is booked under `lease_holder_tid(id)`, never the
/// caller's TID, and the lease's end removes it from this task's page table
/// with a shootdown on every hart. Writable only when the lessor could write
/// (`LeaseEntry::writable`) and degraded-mode containment is off — containment
/// keeps READ live and refuses writes, so a contained lessee gets a read-only
/// mapping rather than none.
///
/// Before mapping, the windows of this task's earlier lease mappings that were
/// revoked by somebody else are given back (`lease_take_revoked`): only the
/// task itself can release its own window addresses.
///
/// `-EFAULT` `out_va` unwritable (checked before accepting, so nothing is
/// taken); `-EINVAL` a kernel caller or `a0` wider than a TID; `-1` as the
/// plain accept, or the lease ended before its mapping could be recorded (the
/// mapping is undone); `-ENOMEM` no holder or address room — the lease is
/// returned, so its lessor is not left waiting on a buffer nobody can read.
pub fn sys_ipc_lease_accept_map(lessor: u64, out_va: u64) -> i64 {
    use azos_abi::error::Errno;
    use azos_ipc::lease;
    use azos_ipc::shm::{self, MAX_SHM_PAGES};
    let lessee = azos_sched::current_task_tid();
    let root = azos_sched::current_user_pt();
    if root == 0 {
        return Errno::EINVAL.to_syscall_ret();
    }
    let Ok(lessor) = u32::try_from(lessor) else {
        return Errno::EINVAL.to_syscall_ret();
    };
    // Writable before anything is taken: a lease accepted and then refused
    // over a bad pointer would leave its lessor waiting for nothing.
    let zero = 0u64.to_ne_bytes();
    if !azos_sched::copy_to_user(out_va as usize, zero.as_ptr(), 8) {
        return Errno::EFAULT.to_syscall_ret();
    }
    let lease_id = match lease::lease_accept_wait(lessee, lessor, || {
        azos_sched::task_block_unless_killed(azos_sched::WaitReason::LeaseAccept(lessee, lessor));
    }) {
        Ok((id, _)) => id,
        Err(_) => return -1,
    };
    // Reap the windows of lease mappings revoked behind this task's back.
    let mut reaped = [(0usize, 0usize); 8];
    loop {
        let n = lease::lease_take_revoked(lessee, &mut reaped);
        for &(va, pages) in &reaped[..n] {
            let _ = azos_sched::process::release_user_window(va, pages);
        }
        if n < reaped.len() {
            break;
        }
    }
    let give_back = |code: i64| -> i64 {
        let _ = azos_ipc::lease_return(lease_id, lessee, false);
        code
    };
    let Some((r, writable)) = lease::lease_map_target(lease_id, lessee) else {
        return give_back(Errno::ENOMEM.to_syscall_ret());
    };
    let holder = lease::lease_holder_tid(lease_id);
    let page_count = match shm::shm_acquire_ref(holder, r) {
        Ok((n, _)) => n,
        Err(_) => return give_back(Errno::ENOMEM.to_syscall_ret()),
    };
    let mut pages = [0usize; MAX_SHM_PAGES];
    for (i, page) in pages.iter_mut().enumerate().take(page_count) {
        match shm::shm_page_phys_ref(r, i) {
            Ok(Some(p)) => *page = p,
            _ => {
                let _ = shm::shm_release_ref(holder, r);
                return give_back(Errno::ENOMEM.to_syscall_ret());
            }
        }
    }
    let rw = writable && !azos_ipc::cap::degraded_active();
    let Some(va) = azos_sched::process::shm_map_user(&pages[..page_count], rw) else {
        // A partial mapping may have left PTEs no record names: the booked
        // reference is kept for good (the `SYS_SHM_MAP_TYPED` pin rule), so
        // no frame returns to the allocator under them.
        return give_back(Errno::ENOMEM.to_syscall_ret());
    };
    if !lease::lease_note_map(lease_id, lessee, r, root, va, page_count) {
        // The lease ended (expired, freed) between the accept and here: undo.
        crate::ipc_handlers::unmap_user_pages(va, page_count);
        let _ = azos_sched::process::release_user_window(va, page_count);
        let _ = shm::shm_release_ref(holder, r);
        return -1;
    }
    let bytes = (va as u64).to_ne_bytes();
    // Checked writable above, and this task's page table only changed in the
    // shm window since.
    let _ = azos_sched::copy_to_user(out_va as usize, bytes.as_ptr(), 8);
    lease_id as i64
}

/// `SYS_IPC_LEASE_RETURN` (113): a0 = lease_id. The caller must be the
/// lessee (IPC-6); its identity comes from the scheduler, never a register.
pub fn sys_ipc_lease_return(lease_id: u64) -> i64 {
    let caller = azos_sched::current_task_tid();
    let privileged = azos_sched::current_user_pt() == 0;
    match azos_ipc::lease_return(lease_id as usize, caller, privileged) {
        Some(_lessor_tid) => 0,
        None => -1,
    }
}

/// `SYS_IPC_LEASE_WAIT` (602): a0 = `Cap<Lease>` (`READ`). The lessor blocks
/// until the lease is returned (0) or expires (1), donating its priority to
/// the lessee meanwhile (`lease::lease_wait_return_as`); `-EINTR` when a
/// forced stop ends the wait (the caller is being killed). -1: the lease is
/// free or the caller is not its lessor. A capability refusal is its errno,
/// recorded like every typed denial.
pub fn sys_ipc_lease_wait(cap_raw: u64) -> i64 {
    use azos_abi::cap::CapHandle;
    use azos_ipc::cap::{targets::Lease, Cap, CapPerms};
    use azos_ipc::lease::LeaseWaitEnd;
    let caller = azos_sched::current_task_tid();
    let privileged = azos_sched::current_user_pt() == 0;
    let cap: Cap<Lease> = Cap::from_raw(CapHandle::from_raw(cap_raw as u32));
    let lease_id = match azos_ipc::cap_store::get(caller, cap, CapPerms::READ) {
        Ok(id) => id as usize,
        Err(e) => return errno_for_cap_err(azos_abi::cap::CapKind::Lease, e),
    };
    match azos_ipc::lease::lease_wait_return_as(lease_id, caller, privileged) {
        LeaseWaitEnd::Returned => 0,
        LeaseWaitEnd::Expired => 1,
        LeaseWaitEnd::NoLease | LeaseWaitEnd::NotLessor => -1,
        LeaseWaitEnd::Killed => azos_abi::error::Errno::EINTR.to_syscall_ret(),
    }
}

/// `SYS_IPC_LEASE_FREE` (114): a0 = lease_id. The caller must be the lessor.
pub fn sys_ipc_lease_free(lease_id: u64) -> i64 {
    let caller = azos_sched::current_task_tid();
    let privileged = azos_sched::current_user_pt() == 0;
    // Now reports refusal instead of silently answering success: a task
    // that is told 0 for a lease it does not own learns nothing and
    // moves on believing it freed something.
    if azos_ipc::lease_free(lease_id as usize, caller, privileged) { 0 } else { -1 }
}

// ── DNS (F05), 266 ───────────────────────────────────────────────────────────

/// `SYS_DNS_RESOLVE` (266): a0 = hostname pointer, a1 = hostname length
/// (capped at 64), a2 = where to store the IPv4 address (0 for nowhere).
/// Returns the address as a u32 in network byte order, or -1.
pub fn sys_dns_resolve(name_ptr: u64, name_len: u64, out_ptr: u64) -> i64 {
    let mut name_buf = [0u8; 64];
    let name_len = (name_len as usize).min(name_buf.len());
    if name_len == 0 || name_ptr == 0 { return -1; }
    // The ABI here is (ptr, len), not a NUL-terminated string — there
    // is no libsys wrapper guaranteeing a terminator — so this uses
    // `copy_from_user` rather than `copy_cstr_from_user`, which would
    // change the calling convention.  Either way the point is the same:
    // the old raw read dereferenced an unvalidated address, and since
    // `sstatus.SUM` is never set it could only ever succeed against
    // kernel/MMIO memory, turning the hostname argument into a
    // 64-byte kernel-memory read (an MMIO read here can also have side
    // effects on device registers).
    if !azos_sched::copy_from_user(name_buf.as_mut_ptr(), name_ptr as usize, name_len) {
        return -1;
    }
    let hostname = match core::str::from_utf8(&name_buf[..name_len]) {
        Ok(s) => s,
        Err(_) => return -1,
    };
    // M24: this used to busy-spin `net_poll()` from ring 3 for
    // 2-9 s with no yield — `resolve_with_yield` calls
    // `azos_sched::task_yield` between polls instead.
    match azos_net::dns::resolve_with_yield(hostname, azos_sched::task_yield) {
        Some(ip) => {
            if out_ptr != 0 {
                // `a2` was an unchecked destination for a 4-byte store
                // whose value the attacker influences by controlling
                // the DNS answer — i.e. a targeted 4-byte write to any
                // kernel address or MMIO register.  `copy_to_user`
                // enforces VALID+USER+WRITE on the destination page.
                if !azos_sched::copy_to_user(out_ptr as usize, ip.as_ptr(), 4) {
                    return -1;
                }
            }
            // Return IP as u32 (network byte order)
            i64::from(u32::from_be_bytes(ip))
        }
        None => -1,
    }
}

// ── F06 driver server, 300-310 ───────────────────────────────────────────────

/// `SYS_DRV_REGISTER` (300): a0 = name pointer, a1 = name length (capped at
/// 32). Returns the driver id, or -1.
pub fn sys_drv_register(name_ptr: u64, name_len: u64) -> i64 {
    let mut name = [0u8; 32];
    let name_len = (name_len as usize).min(32);
    // `copy_from_user` answers `true` for `len == 0` before walking
    // anything, so without this a null pointer and a zero length
    // registered a driver under an empty name and reported success.
    // `SYS_DNS_RESOLVE` has had this guard all along.
    if name_len == 0 || name_ptr == 0 { return -1; }
    if azos_sched::copy_from_user(name.as_mut_ptr(), name_ptr as usize, name_len) {
        match azos_sched::driver_register(&name[..name_len]) {
            Some(id) => id as i64,
            None     => -1,
        }
    } else { -1 }
}

/// `SYS_DRV_IRQ_WAIT` (304): a0 = IRQ line (narrowed with `as u32`). 0 when
/// the line fired, -EAGAIN when it did not (see [`irq_wait_ret`] and
/// [`irq_wait_bound_ret`]).
///
/// A caller holding a wake-task binding of the line (`SYS_IRQ_BIND` type 0)
/// consumes the binding's pending delivery (`irq_bind::irq_wait_begin`): a
/// delivery that landed before this call returns 0 at once instead of being
/// lost with the line left masked. Otherwise the caller registers, blocks,
/// and reports what `irq_wait_end` found. Any other caller keeps the old
/// wait: block, woken only by the `wake_by_irq` sweep.
pub fn sys_drv_irq_wait(irq: u64) -> i64 {
    use azos_ipc::irq_bind::{irq_wait_begin, irq_wait_end, IrqWaitStart};
    let irq = irq as u32;
    let tid = azos_sched::current_task_tid();
    match irq_wait_begin(irq, tid) {
        IrqWaitStart::Pending => 0,
        IrqWaitStart::Registered => {
            let _ = azos_sched::task_block_killable(azos_sched::WaitReason::Irq(irq));
            irq_wait_bound_ret(irq_wait_end(irq, tid))
        }
        IrqWaitStart::Unbound => irq_wait_ret(azos_sched::task_block_killable(
            azos_sched::WaitReason::Irq(irq),
        )),
    }
}

/// `SYS_DRV_IRQ_ACK` (305): a0 = IRQ line. 0, or -1 without `Cap<Irq>`.
pub fn sys_drv_irq_ack(irq: u64) -> i64 {
    {
        // Require the same `Irq(n)` capability SYS_IRQ_BIND demands.
        // Without it any task could send PLIC completion for any
        // enabled IRQ, stealing another driver's completion and
        // letting the line re-arm while that driver is still handling
        // it.  `plic::complete` is itself bounds- and enable-checked,
        // so this closes the ownership hole rather than a memory one.
        let irq = irq as u32;
        if !cap_check(azos_abi::cap::CapKind::Irq, irq, false) {
            return E_PERM_DISPATCH;
        }
        // riscv64: a line ring 3 bound was masked and completed by the
        // external-interrupt handler when it delivered it (mask-until-ACK,
        // `azos_drv_irqchip::user_irq`); the ACK is the unmask, and a level
        // line the driver has not quietened is delivered again at once. Any
        // other line keeps the old completion write, which the handler has
        // already made (a no-op at the PLIC).
        #[cfg(target_arch = "riscv64")]
        {
            if azos_drv_irqchip::user_irq::owned(irq) {
                // The hart that took the line's first delivery since its bind
                // (wave 10 IRQ5), once per bind: the `riscv64 ring-3 irq`
                // row compares it with the route and the owner's pin.
                if let Some(taken) = azos_drv_irqchip::user_irq::first_delivery(irq) {
                    azos_drv_sys::kprintln!(
                        "[IRQ] ring-3 line {} taken on hart {} (routed to hart {})",
                        irq, taken,
                        azos_drv_irqchip::user_irq::routed_hart(irq).map_or(-1, |h| h as i64));
                }
                // Canary: an ACK that does not unmask (see the aarch64 arm).
                #[cfg(not(feature = "irq-ack-canary"))]
                azos_drv_irqchip::user_irq::unmask(irq);
            } else {
                let hart = azos_arch::Cpu::hart_id(&azos_arch::ARCH) as u32;
                azos_drv_irqchip::irqchip::complete_if_enabled(hart, irq);
            }
        }
        // aarch64: `handle_irq` already EOId the line and masked it at the
        // distributor when it delivered it (mask-until-ACK, see
        // `azos_arch::gic`'s ring-3 ownership section); the ACK is the
        // unmask. Only a line ring 3 bound: a `Cap<Irq>` naming a line the
        // kernel routed for itself (the console) never reaches the GIC here.
        // A level line the driver has not quietened fires again at once.
        #[cfg(all(target_arch = "aarch64", target_os = "none"))]
        {
            if azos_arch::gic::user_spi_owned(irq) {
                // Canary: an ACK that does not unmask. The second interrupt
                // of `userspace/tests/captest`'s IRQ section never arrives.
                #[cfg(not(feature = "irq-ack-canary"))]
                azos_arch::gic::enable_spi(irq);
            }
        }
        #[cfg(not(any(target_arch = "riscv64", all(target_arch = "aarch64", target_os = "none"))))]
        {
            let _ = irq;
        }
    }
    0
}

/// Whether this ISA's interrupt controller can hand `irq` to ring 3, checked
/// before a binding is stored. aarch64: an SPI the kernel did not route for
/// itself (`azos_arch::gic::user_spi_bindable`). riscv64: a source the
/// kernel did not enable for itself (`azos_drv_irqchip::user_irq::bindable`;
/// wave 9 IRQ4 — it used to take any line the capability named, the
/// console's included). Host test builds take any line.
#[inline]
pub(crate) fn arch_irq_bindable(irq: u32) -> bool {
    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    {
        azos_arch::gic::user_spi_bindable(irq)
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

/// After a binding of `irq` was stored: route/enable the line with the
/// trigger the device tree gave it, and from then on the external-interrupt
/// handler delivers it mask-until-ACK. `false` when the interrupt controller
/// cannot deliver the line; the caller then undoes the binding
/// ([`route_stored_binding`]).
///
/// aarch64: GIC SPI (`gic::user_spi_bind`) routed to the binding PE; refused
/// for an SPI past the distributor's `GICD_TYPER.ITLinesNumber`.
///
/// riscv64 (wave 10 IRQ5): the hart the binding task is pinned to, or the
/// hart it binds from when unpinned, if that hart takes external interrupts,
/// else the boot hart (`user_irq::target_hart`); a line bound before on
/// another hart moves (`user_irq::bind`). Refused for a PLIC source the
/// boot probe found unimplemented, an APLIC source past `riscv,num-sources`,
/// or one the firmware did not delegate.
#[inline]
pub(crate) fn arch_irq_bound(irq: u32) -> bool {
    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    {
        let mpidr = azos_arch::mpidr::read_mpidr().raw;
        azos_arch::gic::user_spi_bind(irq, mpidr)
    }
    #[cfg(target_arch = "riscv64")]
    {
        use azos_drv_irqchip::user_irq;
        let tid = azos_sched::current_task_tid();
        let pin = azos_sched::task_cpu_affinity(tid).unwrap_or(-1);
        #[cfg(not(feature = "irq-route-canary"))]
        let hart = user_irq::target_hart(pin, azos_arch::Cpu::hart_id(&azos_arch::ARCH) as u32);
        // Canary: the old rule, every ring-3 line on the boot hart.
        #[cfg(feature = "irq-route-canary")]
        let hart = user_irq::boot_hart();
        let before = user_irq::routed_hart(irq);
        if !user_irq::bind(irq, hart, user_irq::dtb_trigger(irq)) {
            return false;
        }
        if before != Some(hart) {
            azos_drv_sys::kprintln!(
                "[IRQ] ring-3 line {} -> hart {} (owner tid {}, pinned {}, was {})",
                irq, hart, tid, pin, before.map_or(-1, |h| h as i64));
        }
        true
    }
    #[cfg(not(any(target_arch = "riscv64", all(target_arch = "aarch64", target_os = "none"))))]
    {
        let _ = irq;
        true
    }
}

/// Route the binding of `irq` that `tid` just stored ([`arch_irq_bound`]);
/// when the controller refuses the line, drop that binding again
/// (`irq_bind::irq_unbind`) and answer `false`: `SYS_IRQ_BIND` and
/// `SYS_PORT_BIND_TYPED` then return `-ENODEV`. Before, the refusal was
/// ignored and both answered 0 with a binding no interrupt could ever reach
/// (wave 10 IRQ5). The store comes first and the route after it for the
/// release ordering `irq_unbind_all` documents.
pub(crate) fn route_stored_binding(irq: u32, tid: u32) -> bool {
    route_stored_binding_with(irq, tid, arch_irq_bound)
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

/// `SYS_DRV_DMA_ALLOC` (306): a0 = size in bytes. Kernel callers only.
/// Returns the physical address of one 4 KiB page, or -1.
pub fn sys_drv_dma_alloc(size: u64) -> i64 {
    // KERNEL-ONLY.  See `sys_drv_dma_free` below: the pair has no
    // ownership model, and this call is the aiming aid — it hands a raw
    // physical address straight to the caller.  Nothing in
    // `crates/core/libsys` or `userspace/` invokes it, so gating costs
    // nothing today; re-opening it to ring 3 requires a per-TID
    // provenance table *and* a DMA capability kind, neither of which
    // exists yet.
    if azos_sched::current_user_pt() != 0 {
        return E_PERM_DISPATCH;
    }
    const DMA_MAX_SINGLE_ALLOC: usize = 65536; // 64 KiB = 16 pages
    let size = size as usize;
    if size == 0 || size > DMA_MAX_SINGLE_ALLOC {
        -1
    } else {
        // NOTE (pre-existing, unrelated to the gate): this returns a
        // single 4 KiB page no matter what `size` asked for.
        match azos_mm::pmm::alloc_page() {
            Ok(phys) => phys.0 as i64,
            Err(_)   => -1,
        }
    }
}

/// `SYS_DRV_DMA_FREE` (307): a0 = physical address. Kernel callers only.
pub fn sys_drv_dma_free(phys: u64) -> i64 {
    // KERNEL-ONLY.  This call used to free an arbitrary, fully
    // user-controlled physical address with no capability check and no
    // allocation provenance.  `pmm::init` marks kernel pages as
    // allocated, so the bitmap's double-free guard *passes* for them:
    // `ecall(SYS_DRV_DMA_FREE, 0x8020_0000)` returned kernel text to
    // the free list.  The next `alloc_page` handed that page out and
    // zeroed it — or the attacker claimed it via brk/mmap and got it
    // mapped USER_RW, i.e. arbitrary kernel read/write from ring 3.
    //
    // A correct fix needs per-TID DMA-page ownership so a free can
    // only release a page the caller allocated; that table also needs
    // a task-exit cleanup hook and a quota, which is more machinery
    // than this lane should introduce for a syscall with zero callers.
    // Gated to kernel tasks instead: an unreachable syscall cannot be
    // an escape primitive.
    if azos_sched::current_user_pt() != 0 {
        return E_PERM_DISPATCH;
    }
    use azos_mm::addr::PhysAddr;
    let _ = azos_mm::pmm::free_page(PhysAddr(phys as usize));
    0
}

/// `SYS_DRV_DMA_SYNC` (308): a0 = physical address, a1 = size. A full fence.
pub fn sys_drv_dma_sync() -> i64 {
    // On VF2/K1 hardware this would issue a RISC-V fence instruction.
    // QEMU has coherent caches so no action is needed.
    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
    0
}

/// `SYS_DRV_HEARTBEAT` (309): a0 = driver id. 0, or -1 for a caller that is
/// not the driver.
///
/// U07-5 (audit unit-07): this refreshed ANY driver's watchdog with no
/// owner check — `driver_check_health` only marks a driver crashed
/// once its heartbeat goes stale, so a holder of this number could
/// keep a hung driver "Running" forever. Same guard as
/// `sys_driver_poll_event`'s (`driver_traffic_allowed`, kernel
/// callers exempt).
pub fn sys_drv_heartbeat(drv_id: u64) -> i64 {
    if !driver_traffic_allowed(drv_id) {
        return E_PERM_DISPATCH;
    }
    let now_ms = azos_drv_sys::timebase::now()
        / (azos_drv_sys::timebase::TIMER_FREQ / 1000);
    azos_sched::driver_heartbeat_with_time(drv_id as usize, now_ms);
    0
}

/// `SYS_DRV_GET_DEVICE` (310): a0 = driver id, a1 = out pointer, a2 = out
/// length. Copies the driver's name; returns the bytes written, or -1.
pub fn sys_drv_get_device(drv_id: u64, out_ptr: u64, out_len: u64) -> i64 {
    match azos_sched::driver_info(drv_id as usize) {
        Some(info) => {
            // Copy driver name to userspace (out_ptr, out_len bytes)
            let name_len = info.name.iter().position(|&b| b == 0)
                .unwrap_or(info.name.len());
            let copy_len = name_len.min(out_len as usize);
            if azos_sched::copy_to_user(
                out_ptr as usize, info.name.as_ptr(), copy_len)
            {
                copy_len as i64
            } else { -1 }
        }
        None => -1,
    }
}

// ── IRQ binding (F00.3), 510 ─────────────────────────────────────────────────

/// `SYS_IRQ_BIND` (510): a0 = IRQ line, a1 = target type (0 wake the caller,
/// 1 queue to a port), a2 = port index, a3 = user key. 0, or -1; `-ENODEV`
/// (and no binding) when the interrupt controller cannot deliver the line
/// ([`route_stored_binding`]).
pub fn sys_irq_bind(irq: u64, target_type: u64, port_id: u64, user_key: u64) -> i64 {
    let irq = irq as u32;
    // Capability check: the caller must hold an Irq capability for it.
    if !cap_check(azos_abi::cap::CapKind::Irq, irq, false) {
        return E_PERM_DISPATCH;
    }
    if !arch_irq_bindable(irq) {
        return -1;
    }
    let tid = azos_sched::current_task_tid();
    let target = match target_type {
        0 => azos_ipc::IrqTarget::WakeTask(tid),
        1 => azos_ipc::IrqTarget::QueueToPort(port_id as u32, user_key),
        _ => return -1,
    };
    let rc = azos_ipc::irq_bind(irq, tid, target);
    if rc == 0 && !route_stored_binding(irq, tid) {
        return azos_abi::error::Errno::ENODEV.to_syscall_ret();
    }
    rc as i64
}

// ── Trace (AQ8), 518 ─────────────────────────────────────────────────────────

/// `SYS_TRACE_DUMP` (518): a0 = entries to print, 0 for the default (50).
pub fn sys_trace_dump(count: u64) -> i64 {
    /// Default number of trace entries to dump.
    const TRACE_DUMP_DEFAULT_COUNT: usize = 50;
    let count = if count == 0 { TRACE_DUMP_DEFAULT_COUNT } else { count as usize };
    azos_ipc::trace_dump(count);
    0
}

// ── Stubs for unimplemented subsystems ───────────────────────────────────────

pub fn sys_stub() -> i64 { -1 }

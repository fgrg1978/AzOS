// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! E06 — Mission logging / replay / analytics.
//!
//! Compact safety records in RAM, one queue per CPU, flushed to FAT32 in the
//! order they were pushed for post-mortem analysis: the e-stop latch, the
//! release floors, an effect's write-ahead record, the other safety
//! violations. All records are fixed-size
//! (32 bytes on-wire) so that replay readers don't have to parse variable-length
//! records.
//!
//! The telemetry events (a motor command, a mode change, a skill, a waypoint,
//! an error, a sensor snapshot) are not in these queues: they are loss-tolerant
//! and go to their own ring of the record region (`azos_records`), which
//! `logd` writes to its files.
//!
//! File layout on disk:
//!   /LOG/LOGNNNNN.BIN          N = monotonic session serial (5 digits)
//!   Header 16B:  b"RBL1" | version u16 LE | state records u8 | reserved u8
//!                | session serial u32 LE | open_ts low word u32 LE
//!   Records 32B each: see LogRecord below.
//!
//! File rotation: when the current file exceeds LOG_FILE_ROTATE_BYTES, it is
//! fsynced + closed and a new file is opened with the next serial number.
//! The header is written together with the state records it counts (the
//! e-stop latch, the release nonce floor, the release-key pin, as of the
//! open), so a boot reads the newest file and not the history behind it. The
//! serial in the header lets a boot find the newest file once the names have
//! wrapped at LOG_SERIAL_WRAP.
//!
//! Analytics counters (in RAM, reset at init):
//!   - total_distance_mm      (from odometry events)
//!   - mission_duration_ticks (CLINT ticks since logger_init)
//!   - battery_mah_used       (INA219 integration, caller feeds microamp-hours)
//!   - safety_violations      (incremented per SafetyViolation event)
//!   - events_dropped         (records a full queue refused)
//!   - flush_errors           (storage errors during flush)

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use azos_common::hook::{AtomicFn, Install};
use azos_sync::waitqueue::WaitQueue;
use azos_sync::SpinLock;

// ---------------------------------------------------------------------------
// Storage seam — the flight recorder's only contact with a filesystem.
// ---------------------------------------------------------------------------
//
// `crates/domains/robot/behavior` is core (the actuation authority) and `crates/fs` is
// scaffolding (FAT32 is the only filesystem this OS has, but nothing in it
// can move or stop a motor). This module used to call `fat32_mount_volume`/
// `mkdir`/`open`/`write`/`fsync`/`close`/`file_stat` directly, which put a
// hard dependency edge from core onto scaffolding (`tools/lint/tcb_check.sh`).
//
// That turned out to be seven calls, not "the full FAT32 API": the recorder
// never reads, seeks, lists a directory, or looks a path back up —
// `fat32_read`, `fat32_seek`, `fat32_opendir`, `fat32_unlink_*` and
// `fat32_ls_root` have no caller here. One of the seven did nothing at all —
// `fat32_file_stat`'s `(pos, size)` was bound and immediately discarded,
// because `bytes_written` was already tracked from `fat32_write`'s own
// return value — so it is dropped rather than carried into the seam below.
// What is left is: open a destination for a session serial, append bytes to
// it, fsync it, close it. That is the `LogStorage` trait — the smallest
// interface that serves "somewhere durable to put records" and "start a new
// file when the old one wraps", not a mirror of FAT32's own API.
//
// The kernel supplies the implementation over `azos_fs` at boot, the
// same shape `crates/net/tftp`'s `UdpTransport` uses to take its UDP operations
// from `crates/net/stack` through the kernel rather than depending on it.

/// Opaque handle to one open log destination. Assigned and interpreted only
/// by the [`LogStorage`] implementation that issued it — the recorder never
/// inspects it, and never holds more than one at a time (the current file is
/// always closed before the next is opened, on rotation or on wrap).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LogHandle(pub u32);

/// Failure modes a [`LogStorage`] implementation can report.
///
/// Deliberately not `azos_fs::FsError` re-exported under a new name —
/// that would still couple this crate to `fs`'s enum shape, just without the
/// `Cargo.toml` edge to show it. The recorder only ever branches on
/// success/failure (`logger_flush`'s retry loop, `log_safety_violation_durable`'s
/// best-effort return), so two variants are enough: there is nowhere to
/// write, or the medium accepted the call but did not complete it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LogStorageError {
    /// No storage is registered, the medium is not mounted, or it refused
    /// the operation outright (a failed mount, or "no file is open").
    Unavailable,
    /// The medium accepted the operation but it did not complete —
    /// write/fsync/close error from the underlying device.
    Io,
    /// The caller is a real-time task, which never does block I/O (owner
    /// rule, wave 15): its records are queued and the log flusher task
    /// has been woken to write them. Not durable yet when this returns.
    Deferred,
}

/// The durable-storage seam the flight recorder writes through.
///
/// Four operations, matched one-for-one to what this module actually does:
/// open a destination for a session serial (creating whatever directory
/// structure it needs), append bytes to it, fsync it, close it. No read, no
/// seek, no directory listing, no path lookup — a seam that mirrored the
/// whole filesystem interface would have moved the dependency, not broken
/// it.
pub trait LogStorage: Sync {
    /// Open (creating/truncating as needed) the destination for session
    /// `serial`. The implementation owns the mapping from serial to a real
    /// path/volume; [`make_log_path`] is exposed so it does not have to
    /// invent a naming scheme that could drift from this module's own
    /// on-disk format.
    ///
    /// TRUNCATE is still correct to request here (`open_flags::TRUNCATE` in
    /// the kernel's implementation) — this module never calls `open` twice
    /// on the same `serial` within one boot lineage except at the
    /// `LOG_SERIAL_WRAP` reuse point, which the wrap notice
    /// (`SAFETY_LOG_WRAPPED`) exists to make an event rather than a silent
    /// loss. See [`logger_seed_next_serial`] for why every OTHER `open` now
    /// lands on a serial that has never been written this lineage, making
    /// the truncate a no-op in practice rather than the every-boot data-loss
    /// it used to be before 2026-09-26 (U08-3).
    fn open(&self, serial: u32) -> Result<LogHandle, LogStorageError>;

    /// Append `buf` to `handle`. Must return the number of bytes actually
    /// written — same contract `fat32_write` had: a short write is valid,
    /// and `logger_flush` retries the remainder rather than treating it as
    /// torn.
    fn write(&self, handle: LogHandle, buf: &[u8]) -> Result<usize, LogStorageError>;

    /// Force `handle`'s data durably to the medium.
    fn fsync(&self, handle: LogHandle) -> Result<(), LogStorageError>;

    /// Close `handle`. This module never inspects the result — closing stays
    /// part of the seam because what happens on failure is the
    /// implementation's decision, not something to paper over silently here.
    fn close(&self, handle: LogHandle) -> Result<(), LogStorageError>;
}

/// The registered storage implementation. `None` until [`logger_set_storage`]
/// runs (normally once, at boot, before `logger_init`); every public entry
/// point below treats "no storage registered" the same as a failed mount —
/// `LogStorageError::Unavailable`.
///
/// A `SpinLock`, not a `Mutex`: this only ever guards a pointer copy.
/// Unlike `LOG_FILE`, nothing is held across real I/O here.
///
/// Lock order, relevant since K-C29: `logger_flush` takes and releases this
/// BEFORE taking `LOG_FILE` (they never overlap there); `logger_shutdown`
/// takes this WHILE `LOG_FILE` is held, but only ever for the instant of a
/// pointer copy inside `current_storage()`, never across the `fsync`/`close`
/// calls that follow. So `LOG_STORAGE` is never held while a caller tries to
/// acquire `LOG_FILE` — the one direction that would matter for a deadlock —
/// on either path. `RING` is unaffected: nothing here ever touches it.
static LOG_STORAGE: SpinLock<Option<&'static dyn LogStorage>> = SpinLock::new(None);

/// Register the storage implementation the recorder writes through. The
/// kernel is the composition root, so it calls this once at boot — see the
/// module doc above.
pub fn logger_set_storage(storage: &'static dyn LogStorage) {
    *LOG_STORAGE.lock() = Some(storage);
}

fn current_storage() -> Result<&'static dyn LogStorage, LogStorageError> {
    LOG_STORAGE.lock().ok_or(LogStorageError::Unavailable)
}

// ---------------------------------------------------------------------------
// Event kinds — one u8 per record.
// ---------------------------------------------------------------------------

/// Periodic sensor snapshot (~1 Hz).
pub const LOG_EVT_SENSOR_SNAPSHOT: u8 = 0x01;
/// Actuator command issued to motors.
pub const LOG_EVT_ACTUATOR_CMD: u8 = 0x02;
/// Safety violation detected (see `safety::SafetyViolation`).
pub const LOG_EVT_SAFETY_VIOLATION: u8 = 0x03;
/// Mode change (idle / autonomous / teleop / return-to-home).
pub const LOG_EVT_MODE_CHANGE: u8 = 0x04;
/// Skill started.
pub const LOG_EVT_SKILL_START: u8 = 0x05;
/// Skill ended.
pub const LOG_EVT_SKILL_END: u8 = 0x06;
/// Waypoint reached or updated.
pub const LOG_EVT_WAYPOINT: u8 = 0x07;
/// Error condition (sensor fault, comms loss, etc.).
pub const LOG_EVT_ERROR: u8 = 0x08;
/// `flags` of a [`LOG_EVT_ACTUATOR_CMD`] record that is a write-ahead effect
/// record (`effect_gate`): committed before the device op it describes. Its
/// payload is the effect's, not `log_actuator_cmd`'s channel values.
pub const LOG_FLAG_EFFECT: u8 = 0x01;
/// `flags` of a [`LOG_EVT_SAFETY_VIOLATION`] latch or release written into a
/// file whose opening state records are newer than it (a record carried
/// across a rotation): history, which the boot replay does not decide the
/// latch from.
pub const LOG_FLAG_HISTORY: u8 = 0x02;

// ── Safety-event codes for `log_safety_violation` ────────────────────────────
//
// The product thesis says no motor moves outside a safety envelope, without an
// explicit capability, and **without a record**. These are that record's
// vocabulary. They are deliberately few: the recorder is wired for safety
// events only, not for general logging, so a code here has to earn its place by
// naming something a person would be asked about after an incident.
//
// `violation_code` says WHAT happened; `action_code` says which of several
// sources or outcomes; `detail` carries the numbers.

/// The motor envelope refused a command. `action_code` 0 = clamping began,
/// 1 = the command came back inside bounds. `detail` packs the left-wheel pair
/// as `(asked as u16) << 16 | (applied as u16)`, which is what an investigator
/// asks first: what was requested, and what actually reached the wheels.
pub const SAFETY_ENVELOPE_REFUSED: u8 = 0x01;

/// Emergency stop. `action_code` names the source, because they do not mean
/// the same thing to whoever reads the log afterwards: 0 = brain over TCP,
/// 1 = brain over UART, 2 = the physical GPIO kill switch, 3 = cleared by an
/// operator MODE command, 4 = a refused MODE clear, the refusal ordinal in
/// `detail` (and, in records written before 6 existed, a ring-3 stop), 5 =
/// restored at boot from the previous session's record
/// ([`ESTOP_ACTION_RESTORED`]), 6 = a ring-3 program through `motor.estop`,
/// `detail` the latching tid with the top bit set when it re-latched within
/// 10 s of an operator clear (`safety::ring3_estop_record`).
/// (7 is not a source: it is the boot self-check's synthetic record, which
/// carries `detail = 0xE5700000` so it cannot be mistaken for a real stop.)
/// 8 = a geofence breach (`safety::ESTOP_ACTION_GEOFENCE`), `detail` the
/// overshoot in metres. 9 = `sys-wdt`'s stack-canary check
/// (`safety::ESTOP_ACTION_STACK_OVERFLOW`, U08-1), `detail` the count of
/// overwritten canaries. 10 = `sys-wdt`'s timer-liveness check
/// (`safety::ESTOP_ACTION_TIMER_FROZEN`, U08-1), `detail` the stall count.
/// 11 = the config authority this device had is gone at boot
/// (`safety::ESTOP_ACTION_CONFIG_AUTHORITY`, wave 11), `detail` the
/// `azos_config::AuthorityLoss` code.
/// 15 = the hung-task or stuck-CPU detector's safe stop (`safety::ESTOP_ACTION_HANG`),
/// `detail` the task's tid or the CPU's id with the top bit set.
pub const SAFETY_ESTOP: u8 = 0x02;

/// Degraded mode entered, changed or left. `action_code` is the level that is
/// now in force (0 = full authority), `detail` the reason the brain gave.
pub const SAFETY_DEGRADE: u8 = 0x03;

/// An untyped capability check (`cap_check`) refused an operation.
/// `action_code` is the kind of object asked for (`CapKind::denial_code`, the
/// same number on the typed path), `detail` the target —
/// pin, channel, id — with the top bit set when the refused access was a write.
pub const SAFETY_CAP_DENIED: u8 = 0x04;

/// The log serial wrapped and an older file was overwritten.
///
/// `make_log_path` takes `serial % 100_000` and opens with TRUNCATE, so the
/// hundred-thousand-and-first file overwrites the first. **Circular is the
/// right behaviour for a flight recorder** — keeping the most recent history is
/// the point, and refusing to record would silence the machine exactly when it
/// has been running longest. What was wrong is that it happened in silence.
/// Now the wrap is itself an event: history was discarded, here is when.
/// `detail` carries the serial that was reused.
pub const SAFETY_LOG_WRAPPED: u8 = 0x05;

/// The brain changed the graded degrade level.
///
/// `action_code` carries the new level (0 = FULL … 3 = CONTAINED); `detail`
/// carries the level it replaced, so a reader can see the transition and not
/// just the destination.
///
/// Every change is recorded, including the intermediate CAUTIOUS and SLOW
/// levels — owner decision, 2026-09-05. `SAFETY_DEGRADE` already records the
/// one-bit degraded-mode view on both arm and clear; recording only CONTAINED here
/// would have left the same gap the graded levels exist to close, namely why
/// the robot was moving slowly rather than merely whether it had stopped.
///
/// A change to the SAME level is not recorded. The brain may resend a standing
/// level at any cadence it likes — the level is sticky by design — and a
/// recorder that logged every repeat would fill the medium with the fact that
/// nothing happened.
pub const SAFETY_SEMANTIC_LEVEL: u8 = 0x06;

/// A `PKT_SEMANTIC_LEVEL` arrived with no payload byte and was treated as
/// CONTAINED.
///
/// Separate from `SAFETY_SEMANTIC_LEVEL` on purpose. That code says the brain
/// asked for a level; this one says the kernel could not tell what was asked
/// and stopped the robot. They are different events with different causes — a
/// truncated packet is a link fault or a hostile sender, not a decision — and
/// collapsing them would make the fail-closed path invisible in the record at
/// exactly the moment it mattered.
pub const SAFETY_SEMANTIC_MALFORMED: u8 = 0x07;

/// A brain packet arrived whose type this build does not act on.
///
/// `action_code` carries the packet type; `detail` the payload length.
///
/// The dispatch chains for both the network path and the UART bridge end
/// without an `else`, so an unrecognised type was counted as received and
/// dropped — no log line, and no counter separating "handled" from "ignored".
/// A brain that put the robot into `CONTAINED` with `PKT_SEMANTIC_LEVEL`
/// against a kernel built before the graded levels therefore got no error at all, and
/// the robot kept running at `FULL` while the brain's own record said it was
/// contained. Fail-open by omission, and every future packet type inherits it.
///
/// This is the cheapest half of the brain-link capability handshake and it stands
/// alone: it does not make
/// the two sides agree, but it turns a silence into a record. The full
/// capability handshake is the other half.
///
/// Recorded for a type the kernel PARSES but does not act on as well —
/// `PKT_WAYPOINT` and the three OTA types are decoded by `brain_protocol.rs`
/// and dispatched nowhere — because from the sender's side those are exactly
/// as ineffective as a type that does not exist.
pub const SAFETY_UNKNOWN_PKT: u8 = 0x08;

/// `estop_gpio_pin` names a pin the kernel cannot poll, so the physical kill
/// switch is not armed. `detail` carries the configured value.
///
/// The poll is `if pin < 64 && gpio_read(pin) == 0`, which skips a malformed or
/// out-of-range value in exactly the same silence as a deliberate absence. An
/// operator who typed `estop_gpio_pin=GPIO5` got a robot with no kill switch
/// and nothing to tell them. Recorded rather than only printed: a boot log
/// scrolls past, the recorder does not.
pub const SAFETY_ESTOP_PIN_INVALID: u8 = 0x09;

/// A **typed** capability dereference was refused: `Cap<T>` was stale, of the
/// wrong kind, or lacked the permission asked for.
///
/// ## Why a second code and not `SAFETY_CAP_DENIED`
///
/// The two records cannot share a shape. `SAFETY_CAP_DENIED`'s `detail` is the
/// object that was refused, with the write bit in bit 31 — both measured, both
/// meaningful. A typed refusal has neither: the dereference FAILED, so no
/// object was ever resolved, and `CapError` does not carry the permission that
/// was asked for. Writing `detail = 0` on this path would be indistinguishable
/// from a real record, because the untyped target (`handlers::denial_target`) is 0 for `Disk` —
/// an untyped Disk denial on the read path IS `detail = 0`. So reuse would make an unmeasured value forge a measured
/// one.
///
/// With its own code, `detail` is free to carry what this path actually knows
/// and the untyped one does not: WHY. See `CapError::code()`.
///
/// ## What is shared, deliberately
///
/// `action_code` is the SAME frozen kind numbering as `SAFETY_CAP_DENIED` —
/// GPIO is 2 whichever syscall was used (`CapKind::denial_code`). During the
/// dual-mode migration the same physical event arrives by either path, and an
/// analyst grouping by device must not have to know which one the program
/// happened to call.
///
/// ## What is deliberately NOT recorded
///
/// `CapError::Contained` never reaches here. That refusal is degraded mode
/// working as designed against a task that HOLDS the capability, not a program
/// reaching for authority it lacks. Recording it would bury every real denial
/// under the flood of a containment episode — which is the one moment the
/// recording matters most.
pub const SAFETY_CAP_DENIED_TYPED: u8 = 0x0A;

/// Capability denials a task was refused a record for, written as one record.
///
/// `action_code` is the kind of the suppressed denials — the same frozen
/// numbering `SAFETY_CAP_DENIED` and `SAFETY_CAP_DENIED_TYPED` use — or `0xFF`
/// when they were of more than one kind. `detail` is how many were suppressed.
/// Typed and untyped denials share one count: they are one task reaching for
/// one kind of object, whichever syscall it used.
///
/// Two other records use the same per-task entry and window, each with a budget
/// of its own: `SAFETY_SECCOMP_AUDIT`, summarised under `action_code` `0xFE`
/// (`DENIAL_KIND_SECCOMP_AUDIT` in `handlers.rs`), and ring-3
/// `SAFETY_EXEC_REFUSED`, under `0xFD` (`DENIAL_KIND_EXEC_REFUSED`). Each class
/// that suppressed anything writes its own summary, so a flood of one class
/// neither silences another nor merges with it (a shared budget let `captest`'s
/// capability denials suppress its audit record, gate 40); `0xFF` marks
/// capability denials of more than one kind.
///
/// ## Why denials are bounded at all
///
/// Both denial codes above only reach the in-memory queue of their CPU, which
/// holds a bounded number of records. A ring-3 loop presenting forged handles
/// wrote one record per syscall, which between two watchdog flushes took the
/// room of the queue-only records next to it — degrade-level changes, sys-wdt
/// events, `SAFETY_UNKNOWN_PKT`. So `crates/core/syscall` admits a few denial records per
/// task per window and counts the rest (`admit_denial_record` in
/// `handlers.rs`). Per task, so one task's flood cannot silence another's
/// denials.
///
/// ## Why a summary rather than a silence
///
/// A recording that stopped at the bound would make the loudest program look
/// like the quietest one. This record is how a flood stays in the black box:
/// as its size rather than its length. It is written when the window closes —
/// on the task's next denial, on the watchdog's flush, or at the task's exit —
/// and carries no TID, like the records it stands for.
pub const SAFETY_CAP_DENIED_SUPPRESSED: u8 = 0x0B;

/// A syscall outside the running image's seccomp profile was LET THROUGH, and
/// this is the record of it.
///
/// Only an image profile in audit mode does that (`ImageProfile::audit` in
/// `crates/core/sched/src/seccomp.rs`: `CAPTEST.ELF` and `ABITEST.ELF`, the two test
/// binaries that probe the kernel with calls it must refuse on its own). Every
/// other image profile refuses such a call with `-1` and marks it only in the
/// in-memory trace ring. `action_code` is 0; `detail` is the syscall number,
/// narrowed to the 16 bits the filter compares.
///
/// Recorded the way the capability denials are: into the queue, through their
/// per-task bound (`admit_denial_record` in `crates/core/syscall/src/handlers.rs`)
/// with a budget of its own, onto the disk with the watchdog's flush. A loop of
/// unlisted calls writes at most four of these per task per window and one
/// `SAFETY_CAP_DENIED_SUPPRESSED` summary with `action_code` `0xFE`, cannot push
/// the records beside it out of the queue, and cannot be silenced by the same
/// task's capability denials.
pub const SAFETY_SECCOMP_AUDIT: u8 = 0x0C;

/// An exec was refused because no seccomp image profile is bound to the image.
///
/// Each image profile is bound to the SHA-256 of the exact ELF the build copies
/// onto the disk image (`crates/core/sched/src/seccomp.rs`), and the table is a
/// whitelist: every exec path hashes the bytes it is about to load and does not
/// load an image that matches none, so a replaced binary, one rebuilt after the
/// kernel, or one nobody profiled does not run. `action_code` names the path:
/// 0 = the autorun loader, 1 = the shell's `exec`, 2 = a ring-3 `SYS_SPAWN_EX` or
/// Linux `execve`, 3 = the shell's `spawn`. `detail` is the first four bytes
/// of the image's SHA-256, big-endian, so the record says which bytes were
/// refused.
///
/// Action 4 is the one refusal of a BOUND image: a `SYS_SPAWN_EX` of an image the
/// signed topology has no row for (`crates/core/syscall/src/spawn.rs`,
/// `SPAWN_REFUSED_ACTION_NO_ROW`, owner decision 2026-09-28).
/// Action 5 is a `SYS_SPAWN_EX` without the launch grant. Action
/// 6 is a streamed image (larger than the exec bounce buffer) whose
/// bytes at load did not hash to the digest it was planned by: the file
/// changed between the two reads. Action 7 is the autorun loader's refusal to
/// stage an image (`kernel/src/tasks/loader.rs`): it needs more frames than the
/// loading Domain's budget, than the allocator forms in one run, or than are
/// free; `detail` is the frames it needed, not a digest. Action 8 is a
/// `SYS_SPAWN_EX` or `execve` of a program of a package installed below its
/// security floor (Kconfig `PKG_SEC_FLOOR_ENFORCE`).
///
/// The autorun loader and the shell write it durably: a refused autorun is a
/// robot that did not start its program, and the likely next event is a person
/// power-cycling it. The ring-3 refusal goes through the capability denials'
/// per-task bound, on a budget of its own, into the queue (summary `action_code`
/// `0xFD`), so a program
/// retrying exec in a loop gets neither a synchronous write per call nor a way
/// to push other records out.
pub const SAFETY_EXEC_REFUSED: u8 = 0x0D;

/// A capability the signed topology declares was REFUSED by its minter, so the
/// task started without it. `detail` carries the
/// `CapKind` discriminant.
///
/// **Not the same event as a kind with no minter at all.** That one is a
/// documented gap in the kernel and says nothing about this topology; both used
/// to print the same "no typed minter yet" line, so a real refusal — a second
/// server declared on one endpoint name, an exhausted pool, a target that does
/// not parse — was reported under a cause that was not true.
///
/// Written durably, and for the same reason `SAFETY_EXEC_REFUSED` is: the
/// consequence shows up later and somewhere else, as an actuation denied or a
/// service that answers nobody, and by then the console line is long gone. The
/// question it has to answer is "why was this refused", and the honest answer
/// is that the program never held the capability.
pub const SAFETY_CAP_SEED_REFUSED: u8 = 0x0E;

/// A task was killed because the page allocator was empty when it wrote to one
/// of its own copy-on-write pages.
///
/// **The one page fault where the program did nothing wrong.**
/// `handle_cow_fault` has four failure paths and three of them mean "this was
/// never a copy-on-write fault": a null dereference, an unmapped address, a
/// write to a page that is not COW. Those are program bugs and the kill is
/// correct. `OutOfMemory` is the innocent one, and until this code existed it
/// printed the same `[PAGE FAULT]` block as a null dereference — sending
/// whoever read the log hunting a pointer bug that was not there.
///
/// Durable for the reason `SAFETY_EXEC_REFUSED` is: the consequence surfaces
/// later and elsewhere, as a controller that stopped answering, and by then
/// the console line is gone. `detail` carries the faulting address.
pub const SAFETY_COW_OOM: u8 = 0x0F;

/// Boot refused to start the first ring-3 program because the actuation gate
/// (`azos_robot::motor::set_motor_gate`) was not installed yet.
///
/// Owner decision 2026-09-25 (Q1.4): the motor write path already fails
/// closed with no gate installed (`gate_speed` in `crates/domains/robot/robot/src/
/// motor.rs` now returns 0, not the requested speed), and this is the
/// second, independent layer — boot refuses to hand a user program the CPU
/// at all while that is true, rather than trusting the fail-closed default
/// alone. At `f2abbe4`, `azos_safety_core::actuation::install()`
/// (`kernel/src/boot/seams.rs`, inside the unconditional
/// `install_ring3_seams()`) always runs before `autorun_task` ever reaches
/// `exec_user`, so this should never fire in a shipped boot — it exists for
/// the ordering bug a future refactor could introduce, not one known to
/// exist today. `action_code`/`detail` are unused (0): there is exactly one
/// cause, unlike `SAFETY_EXEC_REFUSED`'s three.
pub const SAFETY_ACTUATION_GATE_ABSENT: u8 = 0x10;

/// A durable record of the operator-release nonce floor
/// `safety::verify_operator_release` just advanced to. Not a `SAFETY_ESTOP`
/// variant: `estop_action_latches`'s scan filters on `payload[0] ==
/// SAFETY_ESTOP` exactly so the latch replay never has to reason about this
/// record, and [`scan_open_log_file_for_boot`] filters on this code
/// separately in the same pass.
///
/// `detail`'s usual 4-byte slot cannot hold a `u64` nonce, so this record
/// widens: `payload[4..8]` is the nonce's low 32 bits (the same offset
/// `log_safety_violation`'s `detail` uses), `payload[8..12]` the high 32 —
/// the one record in this file whose shape is not "violation/action/detail".
/// See [`log_release_nonce_floor_durable`].
pub const SAFETY_RELEASE_NONCE: u8 = 0x11;

/// The fingerprint of the e-stop release key a boot provisioned from the
/// signed topology (G1): the key that boot, and every later one, must offer
/// again. `payload[4..20]` is [`OPERATOR_KEY_FP_BYTES`] bytes of
/// `estop::operator_key_fp`. Written by `estop::operator_key_pin_install`,
/// through [`log_operator_key_pin_durable`], on EVERY boot that installs the
/// key, and re-emitted into every file a rotation opens (see
/// [`KEY_PIN_CARRY`]): the serials wrap at [`LOG_SERIAL_WRAP`] and the wrap
/// overwrites the oldest files, so a pin written once would eventually be
/// overwritten and the next boot would take a changed key for the first one.
/// [`replay_boot`] finds the newest.
///
/// The carried copy is part of the open: it is in the same write as the
/// header, so no file has a header without it.
pub const SAFETY_OPERATOR_KEY: u8 = 0x1D;

/// I-13 rolled a recoverable fault of the control task back
/// (`azos_safety_core::txn`): the motor command was zeroed and the task
/// restarted at its entry, which writes this record. `action_code` 0,
/// `detail` the boot's rollback count so far. Not a latch: the loop runs on.
pub const SAFETY_TXN_ROLLBACK: u8 = 0x1E;

/// A ring-3 task was killed because the first touch of a page it had reserved
/// needed kernel memory (the page's slot words, `azos_mm::anon_obj`) its
/// Domain's limit refused. The task did nothing wrong with a pointer: it was
/// at its limit. `action_code` 0 = the page-fault arm of the trap policy,
/// `detail` the faulting address. The task exits with SIGKILL's status
/// (`azos_abi::exit_status::KILLED_KILL`).
pub const SAFETY_MM_QUOTA_FAULT: u8 = 0x1F;

/// Bytes of a release-key fingerprint: what fits a record's payload after the
/// kind and its three reserved bytes.
pub const OPERATOR_KEY_FP_BYTES: usize = LOG_PAYLOAD_BYTES - 4;

/// The IMU has been invalid/stale for longer than `safety::
/// IMU_INCOHERENT_AFTER_TICKS` (owner decision, 2026-09-26, V1.6). Written
/// ONCE per stretch of invalidity by `safety::check_common`, not once per
/// tick the condition continues. `action_code` is unused (0); `detail`
/// carries the elapsed tick count at the moment it latched.
pub const SAFETY_SENSOR_INCOHERENT: u8 = 0x12;

/// A payload command (spray pump, gripper, camera shutter) was refused
/// because the e-stop latch holds (H22, coordinator audit, 2026-09-26).
/// Before this decision `payload_exec` had no e-stop check at all — a 12 V
/// spray pump kept running through a latched e-stop, and a gripper/shutter
/// command was silently applied too. `action_code` carries the
/// `PayloadCmd::payload_type` refused; `detail` is unused (0).
pub const SAFETY_PAYLOAD_REFUSED: u8 = 0x13;

/// A brain-link handshake was REFUSED because the entropy pool was unseeded
/// on a `link-provisioning-enforced` build (owner decision, 2026-09-26, V1.2 —
/// U09-8 / security finding #26). `action_code`/`detail` unused (0) — which
/// side initiated (dial vs. accept) is already in the console line next to
/// this record's timestamp, and is not safety-relevant on its own.
pub const SAFETY_ENTROPY_UNSEEDED_REFUSED: u8 = 0x14;

/// A ring-3 task's topology row names a scheduling class this build's
/// scheduler does not have (wave 7), so its class and priority were NOT
/// applied: the task runs at the priority it was created with instead of the
/// one the signed topology declares. `action_code` is the site (0 = autorun,
/// 1 = `SYS_SPAWN_EX`), `detail` the task's TID.
///
/// Also written (sites 2 = autorun, 3 = `SYS_SPAWN_EX`) when the row WAS applied
/// but asked for a priority below the ring-3 floor (`RT_PRIORITY_THRESHOLD`,
/// 12) and was raised to it: the task runs less urgently than its row says.
///
/// Site 4: an io_ring's `sqpoll` permit refused on a one-hart machine (the
/// poller would share its owner's hart); `detail` is the owner's TID.
///
/// Site 5 (wave 9): a priority donation to a ring-3 task was raised to the
/// ring-3 floor — the donor (a kernel real-time task) was more urgent than a
/// ring-3 task may run; `detail` is the target's TID, once per target task.
pub const SAFETY_TOPO_CLASS_REFUSED: u8 = 0x16;

/// A supervised task was restarted, given up on, or ended under its topology
/// row's `restart = no`: one the kernel keeps up (the component manager, the
/// ML service, a kernel host) or a child of the component manager (its
/// death with its endpoints held, the successor the manager started, the
/// manager's give-up). `action_code` is one of the `SUP_ACTION_*` below;
/// `detail` packs the image's topology row (high 16 bits, `0xFFFF` for none)
/// and a count (low 16): the attempt number for a restart, the spent budget
/// for a give-up, the restarts before for an end, the deaths so far for a
/// child's death.
///
/// One code with four actions rather than four codes: the supervisor's
/// whole history for one driver is one filter on the recorder.
pub const SAFETY_DRIVER_SUPERVISOR: u8 = 0x17;
/// A successor task was created for a supervised driver that died.
pub const SUP_ACTION_RESTART: u8 = 1;
/// The driver died with its restart budget spent: everything it held was
/// released and it stays down.
pub const SUP_ACTION_GAVE_UP: u8 = 2;
/// No successor could be created (task pool full): released and down, as a
/// give-up.
pub const SUP_ACTION_RESPAWN_FAILED: u8 = 3;
/// The driver ended (any exit code) under its topology row's `restart = no`:
/// released and not restarted, by policy rather than by a spent budget
/// (wave 11). Recorded as a give-up is, so a driver that is gone for good is
/// always on the recorder, whichever rule ended it.
pub const SUP_ACTION_NO_RESTART: u8 = 4;
/// A child of the component manager died with its named endpoints held for
/// the manager's restart (the restart, when it comes, is `SUP_ACTION_RESTART`;
/// the manager's give-up `SUP_ACTION_GAVE_UP`).
pub const SUP_ACTION_CHILD_DIED: u8 = 5;

/// The `detail` word of a [`SAFETY_DRIVER_SUPERVISOR`] record.
pub const fn sup_record_detail(row: u16, count: u8) -> u32 {
    (row as u32) << 16 | count as u32
}

/// The behavior loop has held STOP through L1 for
/// `ml_link::ABSENT_RECORD_CYCLES` consecutive cycles because the ML verdict
/// it acts on is missing: the ring-3 ML service never started, died and is not
/// back, or stopped answering (owner decision 2026-09-28: fail closed).
/// `action_code` is the outcome of the cycle the record was written on
/// (`ml_link::ABSENT_*`), `detail` the service's TID (0: never started).
///
/// One record per episode; an episode ends at the next verdict.
pub const SAFETY_ML_ABSENT: u8 = 0x18;

/// The rt-motor task's motor-command watchdog (`crates/domains/robot/safety-core/
/// src/rt_motor.rs`): no motor command for 500 ms holds SAFE STOP until one
/// arrives. `action_code` is one of the `RTWD_ACTION_*` below.
///
/// Transitions, never one record per flap: with no brain sending, the
/// watchdog flaps every couple of seconds, and a record each time would fill
/// the medium with the same fact. [`RtWatchdogReports`] decides, for the
/// console line and this record alike: the first SAFE STOP and the first
/// clear, then one [`RTWD_ACTION_REPEATS`] record per window that saw more
/// (none for a window that saw none), and a quiet window re-arms the first
/// two. At most three records a window, whatever the watchdog does.
pub const SAFETY_RT_WATCHDOG: u8 = 0x19;
/// SAFE STOP entered (motors stopped, PID reset). Written durably: it is the
/// one likely to be followed by a reset. `detail` 0.
pub const RTWD_ACTION_STOP: u8 = 1;
/// SAFE STOP cleared: commands arrive again. `detail` 0.
pub const RTWD_ACTION_CLEAR: u8 = 2;
/// The window's transitions after the first two, counted: `detail` is
/// [`rtwd_repeats_detail`] (the count, and whether the window ended in SAFE
/// STOP).
pub const RTWD_ACTION_REPEATS: u8 = 3;
/// `detail` bit of an [`RTWD_ACTION_REPEATS`] record: the window ended in
/// SAFE STOP. The low 31 bits are the count.
pub const RTWD_DETAIL_STOPPED: u32 = 1 << 31;

/// The boot did not install the signed capability topology from the volume
/// (Kconfig `TOPOLOGY_SOURCE`, `kernel/src/boot/topology.rs`, wave 15).
/// Durable, once per boot, written before the built-in topology is installed
/// or the boot hart halts. `action_code` is one of the `TOPO_ACTION_*`
/// below; `detail` is `azos_topology::signed::SignedRefusal::code()` for an
/// invalid set (step in bits 28..31, file in 24..27), 0 for a missing one.
pub const SAFETY_TOPO_SOURCE: u8 = 0x1A;
/// None of the four files on the volume: the built-in topology is installed.
pub const TOPO_ACTION_FALLBACK_MISSING: u8 = 1;
/// The set on the volume was refused: the built-in topology is installed.
pub const TOPO_ACTION_FALLBACK_INVALID: u8 = 2;
/// No set under `TOPOLOGY_SOURCE_SIGNED_REQUIRED`: the boot halts.
pub const TOPO_ACTION_HALT_MISSING: u8 = 3;
/// The set was refused and the policy halts: the boot halts.
pub const TOPO_ACTION_HALT_INVALID: u8 = 4;

/// A refusal went through `azos_decision` (Kconfig `DECISION_REFUSALS_DURABLE`):
/// boot deadline or memory admission, the real-time band cap, or the run-time
/// `rt::reserve`. Durable: the refusal is the event the machine will be asked
/// about after the reset. Written by [`log_decision_refusal_durable`]; the
/// payload is not the usual `action_code`/`detail` pair but the decision
/// record itself, see [`decision_refusal_payload`].
pub const SAFETY_DECISION_REFUSED: u8 = 0x1B;

/// The extension of a [`SAFETY_DECISION_REFUSED`] record (versioned provenance,
/// `azos_decision::ProvenanceRecord`): written right after it, and only when
/// it carries something the base does not (the subject's `image_hash_prefix`
/// or the `topology_row_id`). It repeats the base's rule, verdict and subject
/// so a reader pairs them even when another record landed between the two.
pub const SAFETY_DECISION_PROVENANCE: u8 = 0x1C;

// The compact v1 form lives in `azos_decision` (it is the decoder's too); the
// codes and the payload size must be the recorder's.
const _: () = assert!(azos_decision::COMPACT_BASE_CODE == SAFETY_DECISION_REFUSED);
const _: () = assert!(azos_decision::COMPACT_EXT_CODE == SAFETY_DECISION_PROVENANCE);
const _: () = assert!(azos_decision::COMPACT_BYTES == LOG_PAYLOAD_BYTES);

/// The 20-byte payload of a [`SAFETY_DECISION_REFUSED`] record
/// (`azos_decision::compact_base`; its table is the layout):
/// code, rule, verdict, bits 32..39 of the third number, the subject, the
/// first two numbers saturated to `u32::MAX`, the low 32 bits of the third.
///
/// The third number carries a packed field for the run-time reservation
/// (`rt_core::refusal_numbers`: the budget still available in its low 32 bits,
/// the refusal reason in bits 32..39), which is why it is cut, not saturated.
pub const fn decision_refusal_payload(rule: u8, verdict: u8, subject: u32, n: [u64; 3]) -> [u8; LOG_PAYLOAD_BYTES] {
    azos_decision::compact_base(rule, verdict, subject, n)
}

/// Record a refusal and push it toward the disk: the decision crate's durable
/// sink (`azos_decision::set_durable_sink`, installed by the kernel).
///
/// The base payload always; the provenance extension after it when the record
/// has an `image_hash_prefix` or a `topology_row_id` (`cap_slot`,
/// `parent_cap`, `node_id`, `session_id` and `seq` do not fit 20 bytes and are
/// not durable in v1: see `azos_decision::ProvenanceRecord`).
///
/// A real-time caller, and one that may not block, does not flush: the record
/// is queued for the log flusher (`logger_flush`'s rule, through
/// `push_durable`); only a queue at its limit drops it, and that is the `Err`.
/// Any other caller flushes itself. Does not count
/// as a safety violation (`LOG_SAFETY_COUNT` is the e-stop path's).
pub fn log_decision_provenance_durable(p: &azos_decision::ProvenanceRecord) -> Result<usize, LogStorageError> {
    push_durable(decision_refusal_payload(p.rule, p.verdict, p.subject, p.n))?;
    if let Some(ext) = p.compact_ext() {
        push_durable(ext)?;
    }
    logger_flush()
}

/// [`log_decision_provenance_durable`] for a refusal with no provenance beyond
/// its rule, verdict, subject and numbers.
pub fn log_decision_refusal_durable(
    rule: u8, verdict: u8, subject: u32, n: [u64; 3],
) -> Result<usize, LogStorageError> {
    log_decision_provenance_durable(&azos_decision::ProvenanceRecord::new(rule, verdict, subject, n))
}

/// [`log_decision_provenance_durable`] as `azos_decision`'s sink: best effort,
/// the refusal itself has already been returned to its caller.
pub fn decision_refusal_sink(p: &azos_decision::ProvenanceRecord) {
    let _ = log_decision_provenance_durable(p);
}

/// The `detail` word of an [`RTWD_ACTION_REPEATS`] record.
pub const fn rtwd_repeats_detail(repeats: u32, stopped: bool) -> u32 {
    let n = if repeats > !RTWD_DETAIL_STOPPED { !RTWD_DETAIL_STOPPED } else { repeats };
    n | if stopped { RTWD_DETAIL_STOPPED } else { 0 }
}

/// `(repeats, stopped)` back out of an [`RTWD_ACTION_REPEATS`] `detail`.
pub const fn rtwd_repeats_from_detail(detail: u32) -> (u32, bool) {
    (detail & !RTWD_DETAIL_STOPPED, detail & RTWD_DETAIL_STOPPED != 0)
}

/// Which motor-watchdog transitions get a console line and a
/// [`SAFETY_RT_WATCHDOG`] record (see its doc). No clock and no I/O in it:
/// the caller passes the time, prints, records, and the policy is
/// host-tested (`tests/host/behavior-tests`).
pub struct RtWatchdogReports {
    window_ticks: u64,
    window_start: u64,
    stop_shown: bool,
    clear_shown: bool,
    repeats: u32,
}

impl RtWatchdogReports {
    /// A first window opening at `now`, `window_ticks` long.
    pub const fn new(now: u64, window_ticks: u64) -> Self {
        Self { window_ticks, window_start: now, stop_shown: false, clear_shown: false, repeats: 0 }
    }

    /// SAFE STOP entered: `Some((action, detail))` to print and record,
    /// `None` when it is a repeat (counted).
    pub fn stop(&mut self) -> Option<(u8, u32)> {
        if self.stop_shown {
            self.repeats = self.repeats.saturating_add(1);
            None
        } else {
            self.stop_shown = true;
            Some((RTWD_ACTION_STOP, 0))
        }
    }

    /// SAFE STOP cleared: as [`Self::stop`].
    pub fn clear(&mut self) -> Option<(u8, u32)> {
        if self.clear_shown {
            self.repeats = self.repeats.saturating_add(1);
            None
        } else {
            self.clear_shown = true;
            Some((RTWD_ACTION_CLEAR, 0))
        }
    }

    /// Once per window, at its end: the repeats record when there were any;
    /// a window with none re-arms the first-transition reports.
    pub fn tick(&mut self, now: u64, safe_mode: bool) -> Option<(u8, u32)> {
        if now.wrapping_sub(self.window_start) < self.window_ticks {
            return None;
        }
        self.window_start = now;
        if self.repeats > 0 {
            let detail = rtwd_repeats_detail(self.repeats, safe_mode);
            self.repeats = 0;
            Some((RTWD_ACTION_REPEATS, detail))
        } else {
            self.stop_shown = false;
            self.clear_shown = false;
            None
        }
    }
}

/// Decide what a `PKT_SEMANTIC_LEVEL` arrival should put in the recorder.
///
/// Returns `Some((violation_code, action_code, detail))` for
/// [`log_safety_violation`], or `None` when nothing should be written.
///
/// A pure function, and deliberately not left inline in the handler. The
/// kernel takes this packet on two paths — the network link and the UART
/// bridge — and both need the same answer. Two copies of a safety policy in
/// two `else if` arms is how they drift, and neither one is reachable from a
/// host test. This is.
///
/// Three decisions live here, and each is one an inline version got to make
/// implicitly:
///
/// * **`effective`, not the requested byte.** `degrade_level_set` clamps an
///   out-of-range index to CONTAINED. Recording the wire value would put a
///   level in the log that the kernel never actually entered.
/// * **`previous` in `detail`.** The record carries the transition, not just
///   the destination, so a reader can see what was in force before. The caller
///   has to sample it *before* the store; after it, it is gone.
/// * **Malformed wins over unchanged.** A truncated packet is recorded even
///   when it changes nothing — the robot may already be CONTAINED — because
///   the event being recorded is that the kernel could not tell what was asked
///   and stopped, which is a link fault or a hostile sender, not a decision.
///   Checking "did the level change" first would hide exactly that case.
///
/// And one non-event: a well-formed packet that re-states the level already in
/// force writes nothing. The level is sticky by design and the brain may
/// resend it at any cadence, so logging repeats would fill the medium with the
/// fact that nothing happened.
pub const fn semantic_level_record(
    malformed: bool,
    effective: u8,
    previous: u8,
) -> Option<(u8, u8, u32)> {
    if malformed {
        Some((SAFETY_SEMANTIC_MALFORMED, effective, previous as u32))
    } else if effective != previous {
        Some((SAFETY_SEMANTIC_LEVEL, effective, previous as u32))
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Record layout — 32 bytes fixed.
// ---------------------------------------------------------------------------

/// Size of a log record on disk (bytes).
pub const LOG_RECORD_SIZE: usize = 32;
/// Payload bytes per record (after fixed 12-byte header).
pub const LOG_PAYLOAD_BYTES: usize = 20;

/// One log event. The on-wire representation is:
///   [ts u64 LE] [kind u8] [flags u8] [_pad u16] [payload 20B]
#[derive(Clone, Copy)]
pub struct LogRecord {
    pub ts:      u64,
    pub kind:    u8,
    pub flags:   u8,
    pub payload: [u8; LOG_PAYLOAD_BYTES],
}

impl LogRecord {
    pub const fn zeroed() -> Self {
        Self { ts: 0, kind: 0, flags: 0, payload: [0; LOG_PAYLOAD_BYTES] }
    }

    /// Encode into a 32-byte buffer (little-endian).
    pub fn encode(&self, out: &mut [u8; LOG_RECORD_SIZE]) {
        out[0..8].copy_from_slice(&self.ts.to_le_bytes());
        out[8]  = self.kind;
        out[9]  = self.flags;
        out[10] = 0;
        out[11] = 0;
        out[12..32].copy_from_slice(&self.payload);
    }

    /// Decode from a 32-byte buffer.
    pub fn decode(buf: &[u8; LOG_RECORD_SIZE]) -> Self {
        let mut ts = [0u8; 8];
        ts.copy_from_slice(&buf[0..8]);
        let mut payload = [0u8; LOG_PAYLOAD_BYTES];
        payload.copy_from_slice(&buf[12..32]);
        Self { ts: u64::from_le_bytes(ts), kind: buf[8], flags: buf[9], payload }
    }
}

// ---------------------------------------------------------------------------
// Durable queues: one per CPU, one producer each, never evicted.
// ---------------------------------------------------------------------------
//
// Owner rule (wave 15): a real-time task never does block I/O, and never
// waits for a task that does. Every encoder below runs in whatever task logs
// the event (the 1 kHz motor loop, the RT watchdog, the syscall path, a fault
// handler), so the queue it pushes into takes no lock. Each CPU has its own
// `azos_rings::Queue`: single producer, single consumer, every record taken
// exactly once. The producer handle is the queue's one writer (`producer()`
// hands it out once, it is not `Clone`); a push takes it with interrupts off
// on its CPU, so no other context of that CPU can be its second writer, and
// a context that finds it out (a CPU sharing the queue past `LOG_QUEUES`)
// takes the next queue's.
//
// Nothing is evicted. A queue at its limit for the record's class refuses the
// record ([`Admit`]): an effect is refused with a receipt, any other record
// is counted lost (`events_dropped`; a latching e-stop also in
// `logger_latch_stats` and on the console). So a record the recorder took is
// on the medium after the flusher's pass, or still in RAM.
//
// Order across CPUs: a push takes a number from one counter (`NEXT_SEQ`)
// while it holds the writer handle and after it checked the room, so the push
// that follows cannot fail and every number taken is pushed. The flusher (the
// one consumer, under the flush claim `LOG_FILE`) writes the records in that
// order: the next number is at the front of one of the queues, or its
// producer is between taking it and publishing it (a few stores with
// interrupts off) and the flusher waits for it.

/// Records one CPU's queue holds before the flusher writes them (Kconfig
/// `LOG_QUEUE_ENTRIES`, a power of two).
pub const LOG_QUEUE_CAPACITY: usize = azos_limits::LOG_QUEUE_ENTRIES as usize;
const _: () = assert!(LOG_QUEUE_CAPACITY.is_power_of_two() && LOG_QUEUE_CAPACITY >= 2);

/// Queues (Kconfig `LOG_QUEUES`, at most `NR_CPUS`): a CPU past them shares
/// the queue of its number modulo this.
pub const LOG_QUEUES: usize = {
    let (q, cpus) = (azos_limits::LOG_QUEUES as usize, azos_limits::NR_CPUS as usize);
    if q < cpus { q } else { cpus }
};
const _: () = assert!(LOG_QUEUES >= 1 && LOG_QUEUES <= 64);

/// One queued record and its place in the order of every push.
#[derive(Clone, Copy)]
struct Queued {
    seq: u64,
    rec: LogRecord,
}

impl Queued {
    const EMPTY: Queued = Queued { seq: 0, rec: LogRecord::zeroed() };
}

type DurableQueue = azos_rings::Queue<Queued, LOG_QUEUE_CAPACITY>;

static QUEUES: [DurableQueue; LOG_QUEUES] =
    [const { azos_rings::Queue::new(azos_rings::Full::Backpressure) }; LOG_QUEUES];

/// The number the next push takes; every number below it was pushed, is
/// being published, or is a hole. A line of its own: every push on every CPU
/// takes it.
static NEXT_SEQ: azos_rings::Pad<AtomicU64> = azos_rings::Pad(AtomicU64::new(0));

/// Records the recorder holds in RAM: pushed, and not yet covered by an `Ok`
/// fsync of a file that holds them (queued, or with the flusher).
static HELD: azos_rings::Pad<AtomicU64> = azos_rings::Pad(AtomicU64::new(0));

/// What a record may do in its queue.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Admit {
    /// An ordinary record: admitted while fewer than [`ORDINARY_QUEUE_LIMIT`]
    /// records are queued, else lost (counted).
    Ordinary,
    /// A safety record (a latching or releasing `SAFETY_ESTOP`, the release
    /// nonce floor, the release-key pin): it may take any free slot, the
    /// reserve included.
    Safety,
    /// A write-ahead effect record: refused while [`ORDINARY_QUEUE_LIMIT`]
    /// records are queued.
    Commit,
    /// The record of a stop (an effect toward a device's safe state, never
    /// refused): it may take the reserve's slots down to the last
    /// [`STOP_KEEPS_FREE`]; past that it is lost and counted.
    Stop,
}

/// Slots of each queue only a safety record may use (Kconfig
/// `LOG_QUEUE_SAFETY_RESERVE`): a latching or releasing `SAFETY_ESTOP`, the
/// restore record of the boot replay, the release nonce floor, the key pin.
/// Nothing else queues into them, so such a record finds a slot with every
/// other record already queued.
pub const QUEUE_SAFETY_RESERVE: usize = azos_limits::LOG_QUEUE_SAFETY_RESERVE as usize;
const _: () = assert!(QUEUE_SAFETY_RESERVE >= 1 && QUEUE_SAFETY_RESERVE <= LOG_QUEUE_CAPACITY / 2);
/// Records an ordinary record or an effect record may leave queued: the queue
/// minus the reserve. (Canary `ring-reserve-canary`, host suites only: the
/// reserve is open to everyone, so a full queue has no slot for a safety
/// record.)
#[cfg(not(feature = "ring-reserve-canary"))]
pub const ORDINARY_QUEUE_LIMIT: usize = LOG_QUEUE_CAPACITY - QUEUE_SAFETY_RESERVE;
#[cfg(feature = "ring-reserve-canary")]
pub const ORDINARY_QUEUE_LIMIT: usize = LOG_QUEUE_CAPACITY;
/// Reserve slots a stop's record leaves to the safety records proper (half of
/// them): a stop is recorded in the reserve, but a loop of stops (a task that
/// holds a wheel may stop it at any rate) cannot fill the slots the latching
/// e-stop needs.
#[cfg(not(feature = "ring-reserve-canary"))]
pub const STOP_KEEPS_FREE: usize = QUEUE_SAFETY_RESERVE / 2;
#[cfg(feature = "ring-reserve-canary")]
pub const STOP_KEEPS_FREE: usize = 0;

impl Admit {
    const fn limit(self) -> usize {
        match self {
            Admit::Safety => LOG_QUEUE_CAPACITY,
            Admit::Stop => LOG_QUEUE_CAPACITY - STOP_KEEPS_FREE,
            Admit::Ordinary | Admit::Commit => ORDINARY_QUEUE_LIMIT,
        }
    }
}

/// Why a push took no slot.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Refused {
    /// Queue `queue` holds `queued` records, the record's limit
    /// ([`Admit::limit`]); for a record that spills, every queue was full.
    Full { queue: usize, queued: usize },
    /// The writer handles were held by other CPUs for as long as the record's
    /// class waits ([`BUSY_ROUNDS`]).
    Busy,
}

/// Where a push went.
#[derive(Clone, Copy)]
struct Pushed {
    seq: u64,
    /// Records in that queue after it.
    queued: usize,
}

/// What one queue did with a push.
enum Into {
    Pushed(Pushed),
    Full(usize),
    Busy,
}

/// Rounds over every queue a safety, stop or effect record waits for a writer
/// handle another CPU holds (an ordinary record: two), and the time it waits
/// at most (50 us), whichever ends first. A holder has interrupts off for a
/// few stores, so a handle frees in well under a round; the bound is for a
/// holder that never lets go.
const BUSY_ROUNDS: usize = 1 << 12;
const BUSY_WAIT_TICKS: u64 = azos_drv_sys::timebase::TIMER_FREQ / 20_000;

/// The CPU whose queue a push tries first.
fn home_queue() -> usize {
    #[cfg(test)]
    if let Some(cpu) = CPU_FOR_TEST.with(|c| c.get()) {
        return cpu % LOG_QUEUES;
    }
    // percpu-hint: a placement hint under the caller's interrupt mask; the
    // writer handle, not the CPU number, is what keeps one producer per queue
    azos_drv_sys::klog::cpu_tag() as usize % LOG_QUEUES
}

/// Runtime canary `log-queue-full-drops` (the kernel arms it at boot) and the
/// host suites' `durable-full-canary`: a full queue answers as if it took the
/// record, and keeps nothing.
static LOG_CANARY_FULL_DROPS: AtomicBool = AtomicBool::new(false);

/// Arm `canary=log-queue-full-drops` (boot, once).
pub fn logger_canary_full_drops() {
    LOG_CANARY_FULL_DROPS.store(true, Ordering::Relaxed);
}

/// Set by a queue's producer from before it takes its number until the record
/// is published: the flusher waits for a number it cannot find only while a
/// producer is between the two. One line each: every CPU stores its own.
static WRITING: [azos_rings::Pad<AtomicBool>; LOG_QUEUES] =
    [const { azos_rings::Pad(AtomicBool::new(false)) }; LOG_QUEUES];

/// Records lost because every writer handle stayed taken (counted in
/// `events_dropped` too), and rounds a push waited for one.
static LOG_BUSY: AtomicU32 = AtomicU32::new(0);
static LOG_BUSY_WAITS: AtomicU64 = AtomicU64::new(0);

/// Push one record into this CPU's queue. Never blocks, takes no lock and
/// evicts nothing.
///
/// A safety record or a stop whose own queue is full goes to the next queue
/// that has room (its number keeps its place in the order). A busy writer
/// handle is never a full queue: the push tries the other queues, and a
/// safety, stop or effect record keeps going round them for [`BUSY_ROUNDS`].
fn queue_push(rec: &LogRecord, admit: Admit) -> Result<Pushed, Refused> {
    // Interrupts off: a handler on this CPU cannot become a second writer of
    // the queue in the middle of the push, and the producer is not moved to
    // another CPU between the two.
    let _irq = azos_sync::scope::IrqOff::new();
    let home = home_queue();
    let spill = matches!(admit, Admit::Safety | Admit::Stop) && !cfg!(feature = "durable-spill-canary");
    let rounds = if admit == Admit::Ordinary || cfg!(feature = "durable-busy-canary") { 2 } else { BUSY_ROUNDS };
    let all = if LOG_QUEUES == 64 { u64::MAX } else { (1u64 << LOG_QUEUES) - 1 };
    let mut full = 0u64;
    let mut home_queued = 0;
    let start = now_ticks();
    for _ in 0..rounds {
        let mut busy = false;
        for i in 0..LOG_QUEUES {
            let at = (home + i) % LOG_QUEUES;
            if full & 1 << at != 0 {
                continue;
            }
            match push_into(at, rec, admit) {
                Into::Pushed(p) => return Ok(p),
                Into::Busy => busy = true,
                // Only the record's own queue decides a refusal, unless it
                // spills: a queue it reached because its own was busy does not.
                Into::Full(queued) if !spill && (at == home || cfg!(feature = "durable-full-mask-canary")) => {
                    return Err(Refused::Full { queue: at, queued });
                }
                Into::Full(queued) => {
                    #[cfg(test)]
                    if let Some(f) = FULL_HOOK.take() {
                        f(at);
                    }
                    if !cfg!(feature = "durable-full-mask-canary") {
                        full |= 1 << at;
                    }
                    if at == home {
                        home_queued = queued;
                    }
                }
            }
        }
        if full == all || (cfg!(feature = "durable-full-mask-canary") && !busy) {
            return Err(Refused::Full { queue: home, queued: home_queued });
        }
        if now_ticks().wrapping_sub(start) > BUSY_WAIT_TICKS {
            break;
        }
        LOG_BUSY_WAITS.fetch_add(1, Ordering::Relaxed);
        core::hint::spin_loop();
    }
    Err(Refused::Busy)
}

/// Push into queue `at`, if its writer handle is free and it has room.
fn push_into(at: usize, rec: &LogRecord, admit: Admit) -> Into {
    let q = &QUEUES[at];
    let Some(mut w) = q.producer() else { return Into::Busy };
    // The consumer only takes records out, so the room this sees stays.
    let queued = q.len();
    if queued >= admit.limit() {
        if !cfg!(feature = "durable-full-canary") && !LOG_CANARY_FULL_DROPS.load(Ordering::Relaxed) {
            return Into::Full(queued);
        }
        // Canary: the full queue takes a number and keeps nothing, and
        // answers as if it had the record.
        return Into::Pushed(Pushed { seq: NEXT_SEQ.0.fetch_add(1, Ordering::SeqCst), queued });
    }
    WRITING[at].0.store(true, Ordering::SeqCst);
    let seq = NEXT_SEQ.0.fetch_add(1, Ordering::SeqCst);
    #[cfg(test)]
    if let Some(f) = PUSH_GAP_HOOK.take() {
        f();
    }
    HELD.0.fetch_add(1, Ordering::AcqRel);
    let pushed = matches!(w.push(Queued { seq, rec: *rec }), azos_rings::Push::Pushed);
    WRITING[at].0.store(false, Ordering::SeqCst);
    if pushed {
        return Into::Pushed(Pushed { seq, queued: queued + 1 });
    }
    // Not reached: the room was checked with the one writer handle held.
    // The number is a hole the flusher steps over.
    HELD.0.fetch_sub(1, Ordering::AcqRel);
    Into::Full(queued)
}

/// A pushed record filled its queue to the flush watermark: wake the flusher,
/// or, in a context that may not block (the wake takes the scheduler's
/// locks), leave the request for its next pass.
fn nudge_flusher(queued: usize) {
    if queued < LOG_FLUSH_WATERMARK || cfg!(feature = "durable-nowake-canary") {
        return;
    }
    if azos_sync::preempt::may_block() {
        logger_request_flush();
    } else {
        FLUSH_REQ.fetch_add(1, Ordering::SeqCst);
    }
}

/// Records the recorder holds in RAM (queued, or taken by the flusher and not
/// yet by the medium).
fn ring_len() -> usize {
    HELD.0.load(Ordering::Acquire) as usize
}

// ---------------------------------------------------------------------------
// Global state (atomics for counters/flags; the flush lock).
// ---------------------------------------------------------------------------

/// True after successful `logger_init`.
static LOG_ACTIVE: AtomicBool = AtomicBool::new(false);
/// Monotonic session serial number.
///
/// **Not persisted by this static — it cannot survive a reboot on its own,
/// being a plain in-process integer.** Owner decision, 2026-09-26 (U08-3):
/// the kernel seeds this from [`replay_boot`]'s `next_serial` (a real
/// filesystem scan of the previous session's tail, via
/// [`logger_seed_next_serial`]) BEFORE calling [`logger_init`]. Before this
/// decision every boot left this at its default `0`, and `logger_init`
/// opened serial 0 with TRUNCATE — so the second boot's first act was to
/// erase the first boot's record. A boot that skips the seed (a test that
/// calls `logger_init` directly, or a future caller that forgets) gets that
/// same old behaviour back: serial 0, TRUNCATE, silently. There is no way to
/// make forgetting the seed anything other than silent from inside this
/// file alone — the seam is [`logger_seed_next_serial`], and getting it
/// called is the caller's responsibility, same as `logger_set_storage`
/// already is.
static LOG_SERIAL: AtomicU32 = AtomicU32::new(0);

/// The release-key fingerprint every file this logger opens must carry (G1),
/// set when a boot installs the key and cleared by [`logger_shutdown`] (it
/// lives as long as the logger session). A file opened by a
/// rotation writes it with its header ([`write_file_header`]), so the newest
/// file always holds the pin and the wrap, which overwrites the OLDEST file,
/// cannot take the only copy. A `SpinLock`: it guards a 16-byte copy.
static KEY_PIN_CARRY: SpinLock<Option<[u8; OPERATOR_KEY_FP_BYTES]>> = SpinLock::new(None);
/// The e-stop latch as of the newest `SAFETY_ESTOP` logged: 0 released,
/// [`LATCH_SET`] or'd with the action that latched it. Written into every file
/// a rotation opens, so a boot reads the newest file and not the history.
static LATCH_CARRY: AtomicU32 = AtomicU32::new(0);
const LATCH_SET: u32 = 0x100;
/// The highest release nonce durably recorded, carried like [`LATCH_CARRY`].
static NONCE_CARRY: AtomicU64 = AtomicU64::new(0);

/// What the one consumer holds: the open file and the records it took off the
/// queues and the medium has not taken yet.
///
/// The flush claim: owned for the WHOLE flush, which is a loop of
/// `LogStorage::write` calls plus an `fsync` — real disk I/O on the other
/// side of the seam. Owning it is what serialises two flushers and makes the
/// queues' consumer single. It is a [`Claim`](azos_sync::claim::Claim), not a
/// `Mutex` (owner rule F1: no `Mutex` across device I/O; the claim's exchange
/// mutex is held for the instant of taking and giving it): no real-time task
/// ever takes it — an RT caller of [`logger_flush`] wakes the log flusher
/// instead — so there is no RT waiter whose priority an owner would need to
/// inherit, and a waiter sleeps rather than spinning.
///
/// Every caller is task context: the log flusher, `logger_shutdown`, and
/// non-RT `*_durable` callers. No interrupt handler touches this. Its owner
/// is counted for the panic path by `azos_sync::claim::held_by`.
static LOG_FILE: azos_sync::claim::Claim<Flush> = azos_sync::claim::Claim::new(Flush::EMPTY);

/// The consumer's side of the queues.
struct Flush {
    /// The open file (`None` if not yet opened or rotation in progress).
    file: Option<OpenLogFile>,
    /// A record taken off each queue that is not the next to stage yet.
    fronts: [Option<Queued>; LOG_QUEUES],
    /// The number of the next record to stage.
    next: u64,
    /// Records taken off the queues, in their order, that no `Ok` fsync of a
    /// file holding them has covered: a failed or short write, a failed sync
    /// or a cut anywhere keeps them, and they are written again.
    staged: [Queued; LOG_FLUSH_BATCH_MAX],
    staged_n: usize,
    /// The first this many staged records are whole in the open file.
    taken: usize,
    /// The last fsync of the batch failed and the batch was not written again.
    sync_failed: bool,
    /// The lowest number stepped over while its producer was still writing:
    /// `DURABLE_POS` stays below it until it is written.
    stalled: Option<u64>,
}

impl Flush {
    const EMPTY: Flush = Flush {
        file: None,
        fronts: [None; LOG_QUEUES],
        next: 0,
        staged: [Queued::EMPTY; LOG_FLUSH_BATCH_MAX],
        staged_n: 0,
        taken: 0,
        sync_failed: false,
        stalled: None,
    };
}

// ---------------------------------------------------------------------------
// The log flusher: the one place RT tasks' records reach the medium.
// ---------------------------------------------------------------------------
//
// Owner rule (wave 15): a real-time task never does block I/O. An RT caller
// of `logger_flush` (the RT watchdog's periodic flush, a `*_durable` record
// from the motor loop after its SAFE STOP) bumps `FLUSH_REQ` and wakes the
// flusher, a kernel task at `LOG_FLUSHER_PRIORITY` (outside the RT band),
// which flushes every queue — records in push order, the RT caller's
// included — and runs any deferred I/O job (`defer_io`). The RT caller
// returns at once.
//
// Durability bound for an RT caller's record: it is on the medium (fsync'd)
// once the flusher has run one flush after the request — the time for the
// scheduler to run the flusher (the highest priority outside the RT band
// unless configured otherwise; the RT band's own budget, `RT_BAND_*`,
// guarantees it a share) plus one flush. The trigger is the request itself,
// not the watermark or the watchdog's cadence. A non-RT caller still
// flushes synchronously, so its `Ok` keeps meaning "fsync confirmed".

/// Bumped by every flush request; the flusher sleeps while it is unchanged.
static FLUSH_REQ: AtomicU32 = AtomicU32::new(0);

// ---------------------------------------------------------------------------
// The latch record's durability (FX11). An e-stop latch is a safety
// property: the next boot starts latched only if the latching `SAFETY_ESTOP`
// reached the medium, so the system says "durable" only after a flush whose
// `fsync` (a device flush on the kernel's storage) covered that record's
// number — the marker follows the write, from the task that wrote. Until then
// the record is in RAM: in its queue or with the flusher, never evicted.
// ---------------------------------------------------------------------------

/// Number + 1 of the newest latching `SAFETY_ESTOP` not yet known durable; 0:
/// none pending.
static LATCH_PENDING: AtomicU64 = AtomicU64::new(0);
/// Its action code, for the marker.
static LATCH_PENDING_ACTION: AtomicU32 = AtomicU32::new(0);
/// Records numbered below this were written AND covered by an `Ok` fsync.
static DURABLE_POS: AtomicU64 = AtomicU64::new(0);
/// Number + 1 of the newest record a `*_durable` call pushed
/// ([`push_durable`]); the records below it are durable once [`DURABLE_POS`]
/// reaches it.
static DURABLE_WANT: AtomicU64 = AtomicU64::new(0);

/// Is a record pushed by a `*_durable` call (an e-stop, the operator-release
/// nonce floor, a decision refusal) still waiting for the medium: queued or
/// written, and not yet covered by an `Ok` fsync?
///
/// The condition of the block request layer's real-time class (Kconfig
/// `BLK_IOSCHED_RT_DEADLINE`), with [`rt_request_class_now`] and the FAT32
/// write-back passes the kernel adds. A failed fsync leaves it `true` until a
/// later flush's fsync covers the record.
pub fn durable_record_pending() -> bool {
    LOG_ACTIVE.load(Ordering::Acquire)
        && DURABLE_WANT.load(Ordering::Acquire) > DURABLE_POS.load(Ordering::Acquire)
}

/// The task inside a flush ([`logger_flush_locked`]) while it runs, else 0:
/// the one task whose block requests carry the records.
static FLUSHING_TID: AtomicU32 = AtomicU32::new(0);

/// Marks the calling task as the flusher until dropped.
struct FlushingHere(u32);

impl FlushingHere {
    fn enter() -> Self {
        let tid = azos_sync::waitqueue::caller_tid();
        FLUSHING_TID.store(tid, Ordering::Release);
        FlushingHere(tid)
    }
}

impl Drop for FlushingHere {
    fn drop(&mut self) {
        // Cleared only if still ours: a flush that rotated the file let go of
        // the claim before it finished.
        let _ = FLUSHING_TID.compare_exchange(self.0, 0, Ordering::AcqRel, Ordering::Relaxed);
    }
}

/// Does the calling task's block request carry a durable record: is it inside
/// a flush ([`logger_flush`], the log flusher's pass or a non-real-time
/// `*_durable` caller's own) while a record pushed by a `*_durable` call
/// still waits for the medium ([`durable_record_pending`])?
///
/// The request layer's real-time class asks this at every submit
/// (`azos_drv_block::queue::set_rt_class_source`): the flush's writes and its
/// fsync go first and may take the slot kept for them, whichever Domain's
/// context the flush runs in. A property of the request, not of a task kind:
/// the same task's requests are ordinary once the record is durable, and a
/// real-time task that pushes a record still does no block I/O
/// ([`logger_flush`] defers to the flusher).
pub fn rt_request_class_now() -> bool {
    let tid = azos_sync::waitqueue::caller_tid();
    tid != 0 && FLUSHING_TID.load(Ordering::Acquire) == tid && durable_record_pending()
}
/// Latching records announced durable / refused by a full queue.
static LATCH_DURABLE: AtomicU32 = AtomicU32::new(0);
static LATCH_LOST: AtomicU32 = AtomicU32::new(0);

/// Runtime gate canary `log-latch-defer` (`canary=log-latch-defer`, armed
/// by the kernel at boot): every flush is held back while a latching record
/// is pending, so its durable write is deferred past any kill: no durable
/// marker, and the next boot starts released. `safety: kill switch (gpio)` and `safety: latch survives
/// reboot` must both go red under it.
static LOG_CANARY_LATCH_DEFER: AtomicBool = AtomicBool::new(false);

/// Arm `canary=log-latch-defer` (boot, once).
pub fn logger_canary_latch_defer() {
    LOG_CANARY_LATCH_DEFER.store(true, Ordering::Relaxed);
}

/// `(announced durable, lost, pending)` latching records: diagnostics.
pub fn logger_latch_stats() -> (u32, u32, bool) {
    (
        LATCH_DURABLE.load(Ordering::Relaxed),
        LATCH_LOST.load(Ordering::Relaxed),
        LATCH_PENDING.load(Ordering::Acquire) != 0,
    )
}

/// After a flush: if an `Ok` fsync has covered the pending latch record,
/// clear it and print the durable marker (the row keys on this line).
fn announce_latch_durable() {
    let pend = LATCH_PENDING.load(Ordering::Acquire);
    if pend == 0 || DURABLE_POS.load(Ordering::Acquire) < pend {
        return;
    }
    if LATCH_PENDING.compare_exchange(pend, 0, Ordering::AcqRel, Ordering::Relaxed).is_ok() {
        LATCH_DURABLE.fetch_add(1, Ordering::Relaxed);
        azos_drv_sys::kwarn!(
            "[SAFETY] ESTOP record durable (action {}): fsync confirmed",
            LATCH_PENDING_ACTION.load(Ordering::Relaxed),
        );
    }
}
/// Bumped by the flusher after each pass (requests up to the value it read
/// before the pass are done).
static FLUSH_DONE: AtomicU32 = AtomicU32::new(0);
static FLUSH_WQ: WaitQueue = WaitQueue::new();

/// Deferred I/O jobs posted by RT tasks (one-shot `fn()`s the flusher runs).
/// Slots claimed with a CAS from 0; a full table refuses the job.
static DEFERRED_IO: [AtomicFn<fn()>; LOG_FLUSHER_JOBS] = [const { AtomicFn::new() }; LOG_FLUSHER_JOBS];
/// Kconfig `LOG_FLUSHER_JOBS`: deferred I/O job slots.
pub const LOG_FLUSHER_JOBS: usize = azos_limits::LOG_FLUSHER_JOBS as usize;

azos_common::ro_hook! {
    /// Kernel hook: "is the calling task real-time?" (base priority in the RT
    /// band). Unset on the host and before the scheduler exists: every
    /// caller then flushes itself, as before the rule.
    static RT_CALLER_FN: fn() -> bool;
}

/// Register the RT-caller probe (the kernel, at boot).
pub fn logger_set_rt_probe(f: fn() -> bool) {
    RT_CALLER_FN.set(f);
}

fn rt_caller() -> bool {
    if cfg!(feature = "rt-flush-canary") {
        return false;
    }
    match RT_CALLER_FN.get() {
        Some(f) => f(),
        None => false,
    }
}

/// Runtime canary `log-atomic-flush`: a caller that may not block flushes
/// itself again, the sleep under a SpinLock the rule below exists to prevent.
static LOG_CANARY_ATOMIC_FLUSH: AtomicBool = AtomicBool::new(false);

/// Arm or disarm the runtime canary `log-atomic-flush`.
pub fn logger_canary_atomic_flush(armed: bool) {
    LOG_CANARY_ATOMIC_FLUSH.store(armed, Ordering::Relaxed);
}

/// Is the caller a task that holds a SpinLock or has interrupts masked? A boot
/// path is no task: it has no flusher to hand to and its wait does not sleep
/// (`WaitQueue::wait_if_for`), so it keeps writing its record itself.
fn atomic_caller() -> bool {
    !matches!(azos_sync::waitqueue::caller_tid(), 0 | u32::MAX)
        && !azos_sync::preempt::may_block()
        && !LOG_CANARY_ATOMIC_FLUSH.load(Ordering::Relaxed)
}

/// Set by the gate's `orderly-drain-smoke`: a flusher pass leaves the queues
/// alone until [`logger_drain`], so only the drain can write what is queued.
static LOG_FLUSHER_HELD: AtomicBool = AtomicBool::new(false);

/// See [`LOG_FLUSHER_HELD`].
pub fn logger_hold_flusher() {
    LOG_FLUSHER_HELD.store(true, Ordering::Release);
}

/// Hand every durable record still owed to the medium to the flusher and wait
/// for it, `pause` between looks, until `expired`. `false`: some are still
/// owed. The flusher does the write: the caller may be an RT task, and a stuck
/// medium must not hold it past `expired`.
pub fn logger_drain(expired: &dyn Fn() -> bool, pause: &dyn Fn()) -> bool {
    LOG_FLUSHER_HELD.store(false, Ordering::Release);
    logger_request_flush();
    while durable_record_pending() && !expired() {
        pause();
    }
    !durable_record_pending()
}

/// Who writes a record the caller just pushed.
#[derive(Clone, Copy, PartialEq, Eq)]
enum FlushBy {
    Caller,
    /// A real-time task: woken at once.
    FlusherNow,
    /// A context that may not block: no wake, because the wake takes the
    /// scheduler's locks and the caller may hold anything. The watchdog's
    /// periodic request runs the pass within its ~500 ms cadence.
    FlusherNextPass,
}

fn flush_by() -> FlushBy {
    if atomic_caller() {
        FlushBy::FlusherNextPass
    } else if rt_caller() {
        FlushBy::FlusherNow
    } else {
        FlushBy::Caller
    }
}

/// Ask the flusher for a flush. Never blocks: an atomic add and a wake.
pub fn logger_request_flush() {
    FLUSH_REQ.fetch_add(1, Ordering::SeqCst);
    FLUSH_WQ.wake_all();
}

/// Run `job` (block I/O an RT task must not do itself, e.g. the OTA
/// boot-good mark) on the flusher, after the next flush. `false` when every
/// slot is taken (the caller retries on its next pass). Never blocks.
pub fn logger_defer_io(job: fn()) -> bool {
    for slot in DEFERRED_IO.iter() {
        if slot.install(job) == Install::Stored {
            logger_request_flush();
            return true;
        }
    }
    false
}

azos_common::ro_hook! {
    /// A function the flusher runs at the end of every pass (unset: none): the
    /// kernel's printer of what must never print from where it happened
    /// (lockdep's reports, Kconfig LOCKDEP=y outside ktest; read only when
    /// `lockdep::DRAIN_IN_LOG`).
    static PASS_HOOK: fn();
}

/// Run `f` at the end of every flusher pass (task context, no lock held;
/// the periodic flush request makes that about twice a second).
pub fn logger_set_pass_hook(f: fn()) {
    PASS_HOOK.set(f);
}

/// The log flusher task body: sleep until a request, flush the queues, run the
/// deferred jobs, repeat. Spawned by the kernel at `LOG_FLUSHER_PRIORITY`.
pub fn logger_flusher_task(_: usize) {
    loop {
        let seen = logger_flusher_pass();
        // No deadline (`wait_if`, not `wait_if_for`): the wake cannot be lost.
        // A requester adds to `FLUSH_REQ` and only then `wake_all`s; `seen`
        // was read before the pass, so a request that came during it makes
        // `FLUSH_REQ != seen`, and the check runs under the queue's lock after
        // this task is listed: either it sees the new count and does not
        // sleep, or the requester's `wake_all` finds this task listed. This is
        // the idle wait of a worker, which nothing else wakes (the periodic
        // flush request aside); a slice would keep an idle machine awake.
        FLUSH_WQ.wait_if(|| FLUSH_REQ.load(Ordering::SeqCst) == seen);
    }
}

/// One pass of the flusher: flush the queues, then run the deferred jobs.
/// Returns the request count read before the pass (every request up to it
/// is served). The task body, and what a host test drives in its place.
pub fn logger_flusher_pass() -> u32 {
    let seen = FLUSH_REQ.load(Ordering::SeqCst);
    let pass = FLUSHER_PASSES.fetch_add(1, Ordering::Relaxed);
    azos_decision::flush_limited();
    if LOG_ACTIVE.load(Ordering::Acquire)
        && ring_len() > 0
        && !LOG_FLUSHER_HELD.load(Ordering::Acquire)
        && sync_retry_due(pass)
    {
        let _ = logger_flush_now();
    }
    // A pass that ran before a durable call marked its latch record pending
    // may have written and synced it: say so now, not at an unrelated flush.
    announce_latch_durable();
    for slot in DEFERRED_IO.iter() {
        if let Some(job) = slot.take() {
            job();
        }
    }
    // Only lockdep's printer uses it (LOCKDEP=y outside ktest); otherwise
    // compiled out.
    if azos_sync::lockdep::DRAIN_IN_LOG {
        if let Some(hook) = PASS_HOOK.get() {
            hook();
        }
    }
    FLUSH_DONE.store(seen, Ordering::Release);
    seen
}

/// Passes the flusher began.
static FLUSHER_PASSES: AtomicU32 = AtomicU32::new(0);
/// Fsyncs that failed in a row (0 after an `Ok` one).
static LOG_SYNC_FAILS: AtomicU32 = AtomicU32::new(0);

/// After the medium's fsync failed four times in a row, the flusher retries
/// the staged batch on every 2nd, 4th, ... 64th pass, not on each: a medium
/// that has failed for good is not asked again twice a second in the block
/// layer's real-time class. A durable call still flushes itself every time.
fn sync_retry_due(pass: u32) -> bool {
    let fails = LOG_SYNC_FAILS.load(Ordering::Relaxed);
    fails < 4 || pass % (1u32 << (fails - 3).min(6)) == 0
}

/// Flush passes the flusher completed (diagnostic: the request count it had
/// seen when its last pass began).
pub fn logger_flusher_passes() -> u32 {
    FLUSH_DONE.load(Ordering::Acquire)
}

/// Analytics counters.
static LOG_DISTANCE_MM:     AtomicU64 = AtomicU64::new(0);
static LOG_INIT_TS:         AtomicU64 = AtomicU64::new(0);
static LOG_BATTERY_UAH:     AtomicU64 = AtomicU64::new(0);
static LOG_SAFETY_COUNT:    AtomicU32 = AtomicU32::new(0);
static LOG_DROPPED:         AtomicU32 = AtomicU32::new(0);
static LOG_FLUSH_ERRORS:    AtomicU32 = AtomicU32::new(0);

struct OpenLogFile {
    handle:        LogHandle,
    bytes_written: u32,
    serial:        u32,
    /// Push numbers below this were taken before the file's opening state
    /// records were read (`write_file_header`).
    snap:          u64,
}

// ---------------------------------------------------------------------------
// Logger configuration.
// ---------------------------------------------------------------------------

/// Rotate the log file when it exceeds this many bytes.
pub const LOG_FILE_ROTATE_BYTES: u32 = 1024 * 1024;
/// Flush to disk when this many records are queued (one queue's, or the
/// recorder's in all for [`logger_tick`]).
pub const LOG_FLUSH_WATERMARK: usize = LOG_QUEUE_CAPACITY / 2;
/// Log directory (always ASCII uppercase for FAT32 8.3).
pub const LOG_DIR_PATH: &[u8] = b"/LOG";
/// File magic identifying a azos log file.
pub const LOG_FILE_MAGIC: &[u8; 4] = b"RBL1";
/// Log file format version.
pub const LOG_FILE_VERSION: u16 = 2;
/// State records a file opens with, at most: the latch, the release nonce
/// floor and the release-key pin ([`write_file_header`]).
const SNAPSHOT_MAX: usize = 3;
/// Files a boot's replay reads at most. A file of version 2 opens with the
/// latch, nonce floor and key pin as of its open, so the walk ends at the
/// first such file; this bound is what a run of older files costs, and a
/// walk that spends it without finding a snapshot cannot rule a latch out.
pub const REPLAY_MAX_FILES: u32 = 64;
/// Size of the on-disk file header.
pub const LOG_FILE_HEADER_BYTES: usize = 16;
/// Records encoded per write inside a flush (tune for WCET).
///
/// **Not the queue capacity.** It used to be, which put a 128-record batch
/// (4 KiB) and a 4 KiB encode buffer in one `logger_flush` frame — 8 KiB on a
/// kernel stack of 16 KiB, which is what `CONFIG_KERNEL_STACK_SIZE_KB` was
/// everywhere until 2026-09-16 and still is on embedded, with the FAT32
/// write path and its own sector buffering called from underneath it. A flush
/// now loops over chunks, so the queues still empty in one call but the frame
/// stays small: 16 records is 512 B of encode buffer, exactly one sector.
pub const LOG_FLUSH_BATCH_MAX: usize = 16;

// ---------------------------------------------------------------------------
// Public API — lifecycle.
// ---------------------------------------------------------------------------

/// Seed the serial [`logger_init`] will open next. **Call BEFORE
/// `logger_init`** — that call reads the stored serial the moment it runs,
/// not lazily.
///
/// Owner decision, 2026-09-26 (U08-3): the caller is expected to pass
/// [`BootReplay::next_serial`], from a [`replay_boot`] scan of the medium
/// this boot is about to write to — one past the previous session's
/// highest serial, so the new session never reuses (and, per that scan
/// having found it via [`replay_tail_serial`]'s existence check rather than
/// its own rotation state, never truncates) a serial that may already hold
/// bytes. A caller with no medium to scan (a blank one, or one
/// `replay_boot` could not read — both fold to `next_serial: 0` already)
/// passes `0` and gets today's fresh-boot behaviour unchanged.
pub fn logger_seed_next_serial(next: u32) {
    LOG_SERIAL.store(next, Ordering::Relaxed);
}

/// Seed the recorder with what the previous boots left ([`replay_boot`]): the
/// serial to open, and the latch, release nonce floor and key pin that the
/// first file this boot opens carries forward, so a boot that crashes before
/// recording anything of its own still hands them to the next one. **Call
/// BEFORE `logger_init`**, as [`logger_seed_next_serial`].
pub fn logger_seed_boot_state(r: &BootReplay) {
    logger_seed_next_serial(r.next_serial);
    let carried = match r.latch {
        BootLatch::Armed(action) => LATCH_SET | action as u32,
        BootLatch::Unreadable => LATCH_SET | ESTOP_ACTION_RESTORED as u32,
        BootLatch::NoRecord | BootLatch::Released => 0,
    };
    LATCH_CARRY.store(carried, Ordering::Relaxed);
    NONCE_CARRY.fetch_max(r.release_nonce_floor, Ordering::Relaxed);
    if let Some(fp) = r.operator_key_pin {
        *KEY_PIN_CARRY.lock() = Some(fp);
    }
}

/// Initialise the logger. Idempotent: a second call returns immediately.
///
/// Opens the first log destination through the registered [`LogStorage`]
/// (mounting the medium and creating `/LOG` are the implementation's
/// concern, not this module's) and writes the header. Returns `Err` if that
/// fails; the logger stays inactive in that case and event calls become
/// no-ops.
///
/// Opens whatever serial is currently stored — see
/// [`logger_seed_next_serial`] for how the kernel arranges for that to be
/// the right one, not always `0`.
pub fn logger_init() -> Result<(), LogStorageError> {
    if LOG_ACTIVE.load(Ordering::Acquire) { return Ok(()); }

    let serial = LOG_SERIAL.fetch_add(1, Ordering::Relaxed);
    open_log_file(serial)?;

    LOG_INIT_TS.store(now_ticks(), Ordering::Relaxed);
    LOG_ACTIVE.store(true, Ordering::Release);
    Ok(())
}

/// Gracefully shut down the logger: flush remaining records, fsync+close file.
pub fn logger_shutdown() {
    if !LOG_ACTIVE.swap(false, Ordering::AcqRel) { return; }
    *KEY_PIN_CARRY.lock() = None;
    LATCH_CARRY.store(0, Ordering::Relaxed);
    NONCE_CARRY.store(0, Ordering::Relaxed);
    let _ = logger_flush();
    let mut guard = LOG_FILE.acquire();
    if let Some(open) = guard.file.take() {
        if let Ok(storage) = current_storage() {
            let _ = storage.fsync(open.handle);
            let _ = storage.close(open.handle);
        }
    }
}

/// Periodic tick — call from a kernel timer (~1 Hz). Flushes when the recorder
/// watermark is reached.
pub fn logger_tick() {
    if !LOG_ACTIVE.load(Ordering::Acquire) { return; }
    let should_flush = ring_len() >= LOG_FLUSH_WATERMARK;
    if should_flush { let _ = logger_flush(); }
}

/// Force a flush of the queues to disk. Returns the number of records
/// written (can be 0 if they were empty), or `Err` when a write failed OR
/// when records were written but the storage's `fsync` did not confirm them
/// durable (see `flush_one_batch`).
///
/// A real-time caller does not flush (owner rule: an RT task never does
/// block I/O), and neither does a task in a SpinLock section or with
/// interrupts masked: `block_current` refuses its sleep, and the wait for the
/// disk would spin with preemption off. Both get `Err(Deferred)` at once and
/// the record stays queued for the flusher ([`FlushBy`]).
pub fn logger_flush() -> Result<usize, LogStorageError> {
    match flush_by() {
        FlushBy::Caller => logger_flush_now(),
        FlushBy::FlusherNow => {
            logger_request_flush();
            Err(LogStorageError::Deferred)
        }
        FlushBy::FlusherNextPass => {
            FLUSH_REQ.fetch_add(1, Ordering::SeqCst);
            Err(LogStorageError::Deferred)
        }
    }
}

/// The flush itself, in the calling task (never an RT one: see
/// [`logger_flush`]).
fn logger_flush_now() -> Result<usize, LogStorageError> {
    if LOG_CANARY_LATCH_DEFER.load(Ordering::Relaxed) && LATCH_PENDING.load(Ordering::Acquire) != 0 {
        return Err(LogStorageError::Deferred);
    }
    let r = logger_flush_locked();
    announce_latch_durable();
    r
}

/// The flush proper, under `LOG_FILE` ([`logger_flush_now`]).
fn logger_flush_locked() -> Result<usize, LogStorageError> {
    // Fetched once, up front: it is a pointer copy behind a `SpinLock`, not
    // the storage doing any I/O, so nothing about K-C29's "don't hold a
    // spinlock across I/O" concern applies to grabbing it here.
    //
    // Counted the same way as the "no file open" branch just below: both are
    // "this flush could not write anywhere", and `flush_errors` is the one
    // counter an operator has for "the recorder tried and failed" — it must
    // not go quiet just because the reason was a missing seam instead of a
    // missing file.
    let storage = match current_storage() {
        Ok(s) => s,
        Err(e) => {
            LOG_FLUSH_ERRORS.fetch_add(1, Ordering::Relaxed);
            return Err(e);
        }
    };

    // The claim is held for the whole flush, which is what serialises two
    // flushers (a timer tick and `logger_shutdown` on another hart) and makes
    // the queues' consumer single.
    //
    // LOCK ORDER: there is one lock left. The queues take none (a producer
    // takes its queue's writer handle with an atomic), so pushing a record
    // while `LOG_FILE` is held — the wrap notice below does — cannot invert
    // anything. Host-checked under real thread contention by
    // `behavior-tests::flight_recorder::concurrent_flush_and_push_never_invert_the_file_ring_order`.
    let mut guard = LOG_FILE.acquire();
    let st: &mut Flush = &mut guard;
    if st.file.is_none() {
        LOG_FLUSH_ERRORS.fetch_add(1, Ordering::Relaxed);
        return Err(LogStorageError::Unavailable);
    }
    let _flushing = FlushingHere::enter();

    let mut total = 0usize;
    let mut torn = false;
    let mut failure: Option<LogStorageError> = None;

    loop {
        let r = flush_one_batch(storage, st);
        total += r.consumed;
        torn |= r.torn;
        if failure.is_none() { failure = r.failure; }
        if r.stop { break; }
    }

    // ── The wrap notice belongs in the file whose ending it describes ──────
    //
    // It used to be emitted inside `open_log_file`, which runs AFTER the old
    // handle is closed below — so the record stayed queued and reached
    // disk inside the NEXT file, the one that had just truncated the history
    // the notice was about. `open_log_file`'s own comment said so and called
    // the fix "real work, not attempted here". This is that work.
    //
    // Decide the rotation first, then, if the serial about to be used is past
    // the wrap point, push the notice and drain ONE more batch while the old
    // handle is still open. `open_log_file` is told not to emit it again, so
    // it is written exactly once.
    //
    // `log_safety_violation` takes no lock (the queues are lock-free), so
    // pushing it while FILE is held here orders nothing.
    let rotate = torn || st.file.as_ref().is_some_and(|f| f.bytes_written >= LOG_FILE_ROTATE_BYTES);
    // One read, used for both the decision and the record: `fetch_add` below
    // returns this same value as `next_serial` (it returns the OLD one), and
    // no other hart can be between the two — a concurrent flusher finds
    // `LOG_FILE` already `None` and returns `Unavailable` without rotating.
    let next_serial = LOG_SERIAL.load(Ordering::Relaxed);
    let wrapping = rotate && next_serial >= LOG_SERIAL_WRAP;
    if wrapping {
        log_safety_violation(SAFETY_LOG_WRAPPED, 0, next_serial);
        // Drain, not one pass. The notice is the newest record while
        // `flush_one_batch` takes at most `LOG_FLUSH_BATCH_MAX` (16) in
        // order, so a single pass only reaches it when fewer than 16 records
        // are queued ahead of it. That is true after a clean drain and false
        // exactly where it matters: the loop above stops early on a torn or
        // failed write WITHOUT consuming, so the queues can still hold many
        // records at this point — and the notice would ride them into the
        // new file, which is the defect this whole branch exists to fix.
        // `stop` still terminates on failure or on no progress, so this
        // cannot spin.
        loop {
            let r = flush_one_batch(storage, st);
            total += r.consumed;
            if r.stop { break; }
        }
        // Neither `torn` nor `failure` is folded in from these passes, and both
        // omissions are deliberate. `torn` only ever decides `rotate`, which
        // is already true here — the file is being closed either way, so a
        // partial record at its very end changes nothing. And a failure
        // writing the NOTICE must not turn a flush whose actual records
        // landed into an `Err` for its caller (`log_safety_violation_durable`
        // reads that as "your record is not durable", which would be a lie).
        // It is not swallowed: `flush_one_batch` bumps `LOG_FLUSH_ERRORS` on
        // any short or failed write, notice included.
    }

    if rotate {
        if let Some(open) = st.file.take() {
            // The old file's last word on the records it took: those of the
            // staged batch are durable only if this sync succeeds; otherwise
            // they stay staged and go into the new file again.
            // A batch whose own fsync failed and was not written again since
            // is not made durable by a later `Ok` (a failed device flush
            // followed by one that succeeds proves nothing about the first).
            let synced = storage.fsync(open.handle);
            let trusted = !st.sync_failed || cfg!(feature = "durable-rotate-trust-canary");
            if (synced.is_ok() && trusted) || cfg!(feature = "durable-rotate-sync-canary") {
                total += staged_durable(st, st.taken);
                LOG_SYNC_FAILS.store(0, Ordering::Relaxed);
            } else if synced.is_err() {
                LOG_FLUSH_ERRORS.fetch_add(1, Ordering::Relaxed);
            }
            st.taken = 0;
            st.sync_failed = false;
            let _ = storage.close(open.handle);
        }
        // Evaluate the bump on its own line: `debug_assert_eq!` does NOT
        // evaluate its arguments in a release build, and the gate builds
        // everything `--release` — putting the `fetch_add` inside it would
        // silently stop the serial from ever advancing.
        let advanced = LOG_SERIAL.fetch_add(1, Ordering::Relaxed);
        debug_assert_eq!(advanced, next_serial);
        // Opened under the claim: no other flusher finds the recorder without
        // a file in between.
        st.file = open_file(next_serial, wrapping).ok();
    }

    match failure {
        Some(e) => Err(e),
        None => Ok(total),
    }
}

/// What one pass of the flush loop did.
struct BatchOutcome {
    /// Records the medium actually took, and which therefore left RAM.
    consumed: usize,
    /// The write stopped mid-record: the file now ends with a partial record,
    /// so the caller must rotate.
    torn: bool,
    failure: Option<LogStorageError>,
    /// No more work, or no more progress — the caller must stop looping.
    stop: bool,
}

/// Spins the flusher waits for a number whose producer is publishing it before
/// it gives up on the producer and steps over the number. A producer has
/// interrupts off for a few stores; this is for one that never finishes.
const GAP_SPINS: u32 = 1 << 22;

/// Numbers the flusher stepped over: taken and never published (or published
/// after [`GAP_SPINS`], then written late). Not a lost record, a defect.
static LOG_HOLES: AtomicU32 = AtomicU32::new(0);

/// The next record in push order: off a queue's front, or `None` once every
/// number taken so far is staged, written or stepped over. Consumer only
/// (flush claim held).
fn next_record(st: &mut Flush) -> Option<Queued> {
    let mut rescanned = false;
    let mut spins = 0u32;
    loop {
        let mut lowest: Option<(usize, u64)> = None;
        for (i, front) in st.fronts.iter_mut().enumerate() {
            if front.is_none() {
                *front = QUEUES[i].consumer().and_then(|mut c| c.pop());
            }
            if let Some(f) = front {
                if lowest.is_none_or(|(_, seq)| f.seq < seq) {
                    lowest = Some((i, f.seq));
                }
                // Canary: the queues are written one after another, not
                // merged in push order.
                if cfg!(feature = "durable-merge-canary") {
                    break;
                }
            }
        }
        if let Some((i, seq)) = lowest {
            if seq <= st.next || cfg!(feature = "durable-merge-canary") {
                if seq < st.next {
                    // A number stepped over after the wait, published late.
                    azos_drv_sys::kwarn!("[LOG] record {} written after its successors", seq);
                }
                st.next = st.next.max(seq + 1);
                return st.fronts[i].take();
            }
        }
        // The next number is at no front.
        if NEXT_SEQ.0.load(Ordering::SeqCst) <= st.next {
            return None;
        }
        let writing = WRITING.iter().any(|w| w.0.load(Ordering::SeqCst))
            && !cfg!(feature = "durable-gap-skip-canary");
        if writing && spins < GAP_SPINS {
            // Its producer is publishing it (interrupts off, a few stores).
            #[cfg(test)]
            GAP_WAITS.fetch_add(1, Ordering::Relaxed);
            spins += 1;
            rescanned = false;
            core::hint::spin_loop();
            continue;
        }
        if !writing && !rescanned {
            // No producer is between taking a number and publishing it, so
            // a record published since the scan is at a front now.
            rescanned = true;
            continue;
        }
        if LOG_HOLES.fetch_add(1, Ordering::Relaxed) == 0 {
            azos_drv_sys::kwarn!(
                "[LOG] record {} was never published ({}): stepped over",
                st.next, if writing { "its producer did not finish" } else { "not pushed" });
        }
        if writing {
            // It may still come: nothing above it is durable until it is.
            st.stalled = Some(st.stalled.map_or(st.next, |h| h.min(st.next)));
        }
        st.next += 1;
        rescanned = false;
        spins = 0;
    }
}

/// The first `n` staged records are on the medium, covered by an `Ok` fsync:
/// they leave RAM. Returns `n`.
fn staged_durable(st: &mut Flush, n: usize) -> usize {
    if n == 0 {
        return 0;
    }
    if st.stalled.is_some_and(|h| st.staged[..n].iter().any(|q| q.seq == h)) {
        st.stalled = None;
    }
    let end = st.staged[n - 1].seq + 1;
    let cap = match st.stalled {
        Some(h) if !cfg!(feature = "durable-stall-cap-canary") => end.min(h),
        _ => end,
    };
    DURABLE_POS.fetch_max(cap, Ordering::AcqRel);
    st.staged.copy_within(n..st.staged_n, 0);
    st.staged_n -= n;
    st.taken = st.taken.saturating_sub(n);
    HELD.0.fetch_sub(n as u64, Ordering::AcqRel);
    n
}

/// Encode and write the staged batch, topped up from the queues, into the
/// open file, retrying a short write, then fsync it. Records leave RAM only
/// once an `Ok` fsync of a file that holds them covered them: a failed or
/// short write, a failed fsync or a cut anywhere keeps them staged, and the
/// next pass writes them again (into the next file, after a rotation). A
/// record written twice is harmless: the replay keeps the last latch, the
/// highest nonce floor and the last key pin, all in number order.
///
/// Extracted from `logger_flush` so the wrap notice can be carried to disk by
/// **one more pass over the same code** rather than a second copy of it. A
/// duplicate of this logic is how the short-write bug it already contains
/// would come back: a storage write returns a count and nothing promises it
/// equals `buf.len()`, and adding that count to `bytes_written` and moving on
/// leaves a torn 32-byte record that misframes every record after it — the
/// whole rest of the file, not just the tail.
fn flush_one_batch(storage: &'static dyn LogStorage, st: &mut Flush) -> BatchOutcome {
    while st.staged_n < LOG_FLUSH_BATCH_MAX {
        let Some(q) = next_record(st) else { break };
        st.staged[st.staged_n] = q;
        st.staged_n += 1;
    }
    let n = st.staged_n;
    let Some(open) = st.file.as_mut() else {
        return BatchOutcome { consumed: 0, torn: false, failure: Some(LogStorageError::Unavailable), stop: true };
    };
    if n == 0 {
        return BatchOutcome { consumed: 0, torn: false, failure: None, stop: true };
    }
    // A latch or release pushed before this file opened is already in its
    // opening state records, and those are newer: as the file's last word on
    // the latch it would be older than the truth whenever a power loss cut off
    // what came after it. It is written as history (`LOG_FLAG_HISTORY`), which
    // the replay does not take the latch from.
    let mut out = [0u8; LOG_FLUSH_BATCH_MAX * LOG_RECORD_SIZE];
    for (q, raw) in st.staged[..n].iter().zip(out.chunks_exact_mut(LOG_RECORD_SIZE)) {
        let mut rec = q.rec;
        if q.seq < open.snap && latch_record(&rec) && !cfg!(feature = "durable-resnap-canary") {
            rec.flags |= LOG_FLAG_HISTORY;
        }
        let mut buf = [0u8; LOG_RECORD_SIZE];
        rec.encode(&mut buf);
        raw.copy_from_slice(&buf);
    }
    let end = st.staged[n - 1].seq + 1;
    // Canary: the batch leaves RAM before the medium took it.
    if cfg!(feature = "durable-staging-canary") {
        st.staged_n = 0;
        st.taken = 0;
        HELD.0.fetch_sub(n as u64, Ordering::AcqRel);
    }

    // Write the whole chunk, retrying the remainder. A short write is a
    // transient; the correct response is to write the rest.
    let len = n * LOG_RECORD_SIZE;
    let mut off = 0usize;
    let mut failure: Option<LogStorageError> = None;
    st.sync_failed = false;
    while off < len {
        match storage.write(open.handle, &out[off..len]) {
            Ok(0) => break,                  // no progress: stop, don't spin
            Ok(w) => off += w,
            Err(e) => { failure = Some(e); break; }
        }
    }
    open.bytes_written = open.bytes_written.saturating_add(off as u32);
    // The whole records this file took, of the batch.
    let whole = off / LOG_RECORD_SIZE;
    if !cfg!(feature = "durable-staging-canary") {
        st.taken = whole;
    }

    if off != len {
        // Either the device stopped making progress or it errored. If it
        // stopped mid-record the file now ends with a partial record, so the
        // caller rotates: the damage stays at EOF of a closed file and the
        // next one starts on a record boundary.
        LOG_FLUSH_ERRORS.fetch_add(1, Ordering::Relaxed);
        return BatchOutcome {
            consumed: 0,
            torn: off % LOG_RECORD_SIZE != 0,
            failure: Some(failure.unwrap_or(LogStorageError::Io)),
            stop: true,
        };
    }

    // The records are written; `fsync` is what makes them durable (the
    // kernel's implementation ends in a device flush). Its failure ends the
    // flush and is its result: `logger_flush` -- and through it every
    // `*_durable` call -- answers `Err`, and the batch stays staged.
    if let Err(e) = storage.fsync(open.handle) {
        LOG_FLUSH_ERRORS.fetch_add(1, Ordering::Relaxed);
        LOG_SYNC_FAILS.fetch_add(1, Ordering::Relaxed);
        st.sync_failed = true;
        return BatchOutcome { consumed: 0, torn: false, failure: Some(e), stop: true };
    }
    LOG_SYNC_FAILS.store(0, Ordering::Relaxed);
    let consumed = if cfg!(feature = "durable-staging-canary") {
        DURABLE_POS.fetch_max(end, Ordering::AcqRel);
        n
    } else {
        staged_durable(st, n)
    };
    BatchOutcome { consumed, torn: false, failure: None, stop: n < LOG_FLUSH_BATCH_MAX }
}

// ---------------------------------------------------------------------------
// Telemetry encoders — each wraps `telemetry()`, the record region's ring.
// ---------------------------------------------------------------------------

/// Log an odometry/sensor snapshot. Also updates the distance counter if
/// `distance_delta_mm > 0`.
pub fn log_sensor_snapshot(
    battery_mv: u16,
    velocity_mm_s: i16,
    distance_delta_mm: u32,
    heading_cdeg: i32,
) {
    if distance_delta_mm > 0 {
        LOG_DISTANCE_MM.fetch_add(distance_delta_mm as u64, Ordering::Relaxed);
    }
    let mut payload = [0u8; LOG_PAYLOAD_BYTES];
    payload[0..2].copy_from_slice(&battery_mv.to_le_bytes());
    payload[2..4].copy_from_slice(&velocity_mm_s.to_le_bytes());
    payload[4..8].copy_from_slice(&distance_delta_mm.to_le_bytes());
    payload[8..12].copy_from_slice(&heading_cdeg.to_le_bytes());
    telemetry(LOG_EVT_SENSOR_SNAPSHOT, payload);
}

/// Log an actuator command (speed_l, speed_r for wheeled; channel/value generic).
pub fn log_actuator_cmd(actuator_type: u8, ch0: i16, ch1: i16, ch2: i16, ch3: i16) {
    let mut payload = [0u8; LOG_PAYLOAD_BYTES];
    payload[0] = actuator_type;
    payload[2..4].copy_from_slice(&ch0.to_le_bytes());
    payload[4..6].copy_from_slice(&ch1.to_le_bytes());
    payload[6..8].copy_from_slice(&ch2.to_le_bytes());
    payload[8..10].copy_from_slice(&ch3.to_le_bytes());
    telemetry(LOG_EVT_ACTUATOR_CMD, payload);
}

/// How [`commit_effect_record`] fared.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum EffectCommit {
    /// In this CPU's queue, with this number in the order of every push; it
    /// leaves RAM only when the medium took it.
    Committed(u64),
    /// Not queued: the queue is at its limit ([`ORDINARY_QUEUE_LIMIT`]
    /// records for an effect, the [`QUEUE_SAFETY_RESERVE`] slots above stay
    /// free; down to [`STOP_KEEPS_FREE`] free slots for a stop). Nothing was
    /// evicted; a stop's lost record is counted dropped. `queue` is the
    /// queue that refused it, holding `queued` records.
    Full { queue: u32, queued: u32 },
    /// Not queued: every queue's writer handle stayed held by other CPUs for
    /// as long as an effect waits ([`BUSY_ROUNDS`]). A stop's lost record is
    /// counted dropped and busy.
    Busy,
    /// The logger is off (no medium opened): there is nowhere to commit to.
    Inactive,
}

// ---------------------------------------------------------------------------
// Receipt index (innovation B3): what the device last did, in O(1)
// ---------------------------------------------------------------------------
//
// A committed effect record is the device's receipt: the effect gate issues
// the op only after it. A warrant can be conditioned on one (the `RECEIPT`
// caveat, `azos_ipc::cap::caveat::receipt`), and the resolve asks here, so the
// question "did this device stop in the last 200 ms, and has nothing moved it
// since" is two loads, not a walk of the queues (which are bounded and
// flushed, and are no index).
//
// A receipt is named by a device and a kind. The device is `effect kind << 8 |
// subject` (`effect_gate::Effect`: the wheel for a motor); the kind is the
// effect's class byte (0 toward the safe state, 1 reversible). The contrary of
// a kind is the other one (`kind ^ 1`): a drive receipt is contradicted by a
// later stop, and the reverse. The index keeps the time of the newest receipt
// of each (device, kind), one word each, written by whoever commits the
// record (`fetch_max`, lock-free) and read lock-free; it is not durable and
// not replayed (a reboot leaves no receipts, so a conditioned warrant
// refuses until the device acts again: fail closed).
//
// The bounds are `safe_state::MAX_KINDS` and `MAX_SUBJECTS` (that module is
// not linked with this one in every host suite, hence the copies).

/// Effect kinds the index holds.
const RECEIPT_EFFECT_KINDS: usize = 4;
/// Devices of one effect kind.
const RECEIPT_SUBJECTS: usize = 32;
/// Receipt kinds of a device: the effect classes.
const RECEIPT_KINDS: usize = 2;

/// The age [`receipt_ages`] answers for a kind the device has left no receipt
/// of (`azos_ipc::cap::NO_RECEIPT`).
pub const NO_RECEIPT_AGE: u64 = u64::MAX;

/// Time (timebase ticks, at least 1) of the newest receipt of each (device,
/// kind); 0: none.
static RECEIPT_AT: [AtomicU64; RECEIPT_EFFECT_KINDS * RECEIPT_SUBJECTS * RECEIPT_KINDS] =
    [const { AtomicU64::new(0) }; RECEIPT_EFFECT_KINDS * RECEIPT_SUBJECTS * RECEIPT_KINDS];

/// The cell of (`device`, `kind`), `None` for a coordinate the index does not
/// hold (a kind past the classes, a device past its bounds).
fn receipt_cell(device: u16, kind: u8) -> Option<&'static AtomicU64> {
    let (ek, subject) = ((device >> 8) as usize, (device & 0xff) as usize);
    if ek >= RECEIPT_EFFECT_KINDS || subject >= RECEIPT_SUBJECTS || kind as usize >= RECEIPT_KINDS {
        return None;
    }
    RECEIPT_AT.get((ek * RECEIPT_SUBJECTS + subject) * RECEIPT_KINDS + kind as usize)
}

/// Note the receipt of the effect record `payload` (`effect_gate::Effect::payload`:
/// kind, class, subject) committed at `ts`. A coordinate the index does not
/// hold leaves no receipt: a caveat on it is refused.
fn receipt_note(payload: &[u8; LOG_PAYLOAD_BYTES], ts: u64) {
    let device = (payload[0] as u16) << 8 | u16::from_le_bytes([payload[2], payload[3]]);
    if let Some(cell) = receipt_cell(device, payload[1]) {
        cell.fetch_max(ts.max(1), Ordering::Release);
    }
}

/// Milliseconds from `ts` to `now`, both timebase ticks; 0 for a `ts` ahead
/// of `now` (another hart's clock read a moment later). Exact and free of
/// overflow for any tick count.
fn receipt_ms(ts: u64, now: u64) -> u64 {
    let (t, f) = (now.saturating_sub(ts), azos_drv_sys::timebase::TIMER_FREQ);
    (t / f).saturating_mul(1000).saturating_add((t % f) * 1000 / f)
}

/// [`receipt_ages`] at the instant `now` (timebase ticks).
fn receipt_ages_at(device: u16, kind: u8, now: u64) -> (u64, u64) {
    let age = |k: u8| match receipt_cell(device, k).map(|c| c.load(Ordering::Acquire)) {
        Some(ts) if ts != 0 => receipt_ms(ts, now),
        _ => NO_RECEIPT_AGE,
    };
    if receipt_cell(device, kind).is_none() {
        return (NO_RECEIPT_AGE, NO_RECEIPT_AGE);
    }
    (age(kind), age(kind ^ 1))
}

/// What the index knows of `device` and receipt `kind`: the age in
/// milliseconds of the newest receipt of that kind and of the newest of its
/// contrary kind, [`NO_RECEIPT_AGE`] for one it holds none of. This is the
/// probe the capability resolve evaluates a `RECEIPT` caveat with
/// (`azos_ipc::cap::set_receipt_probe`): a use is valid while the first is
/// within the caveat's limit and the contrary one is older than it (equal
/// ages count as contradicted: the clock cannot order them).
pub fn receipt_ages(device: u16, kind: u8) -> (u64, u64) {
    receipt_ages_at(device, kind, now_ticks())
}

/// Commit a write-ahead effect record (`effect_gate`) to this CPU's queue.
///
/// `refusable`: the record may be refused (`EffectCommit::Full`, nothing
/// counted). Not `refusable` (an effect that moves toward a safe state, which
/// is never refused): the record is [`Admit::Stop`]: it uses the safety
/// reserve (owner decision 16-10: a stop is always recorded) down to
/// [`STOP_KEEPS_FREE`] free slots; past that `Full` means this one was lost
/// (counted dropped, and by the gate as unrecorded).
///
/// Lock-free, no I/O: a commit that fills its queue past the flush watermark
/// also wakes the log flusher (as every push does), so the record waits for
/// the medium for the flusher's pass, not for the watchdog's cadence. A stop
/// whose own queue is full goes to another queue's reserve.
pub fn commit_effect_record(payload: [u8; LOG_PAYLOAD_BYTES], refusable: bool) -> EffectCommit {
    if !LOG_ACTIVE.load(Ordering::Acquire) {
        return EffectCommit::Inactive;
    }
    let rec = LogRecord { ts: now_ticks(), kind: LOG_EVT_ACTUATOR_CMD, flags: LOG_FLAG_EFFECT, payload };
    match queue_push(&rec, if refusable { Admit::Commit } else { Admit::Stop }) {
        Ok(p) => {
            receipt_note(&payload, rec.ts);
            nudge_flusher(p.queued);
            EffectCommit::Committed(p.seq)
        }
        Err(why) => {
            if !refusable {
                count_lost(why);
            }
            match why {
                Refused::Full { queue, queued } => EffectCommit::Full { queue: queue as u32, queued: queued as u32 },
                Refused::Busy => EffectCommit::Busy,
            }
        }
    }
}

/// What the latch will be once this record is on the medium: a stop latches,
/// the operator clear releases, the rest leave it.
fn latch_carry_note(violation_code: u8, action_code: u8) {
    if violation_code != SAFETY_ESTOP {
        return;
    }
    match estop_action_latches(action_code) {
        Some(true) => LATCH_CARRY.store(LATCH_SET | action_code as u32, Ordering::Relaxed),
        Some(false) => LATCH_CARRY.store(0, Ordering::Relaxed),
        None => {}
    }
}

/// Log a safety violation. Bumps the violation counter.
pub fn log_safety_violation(violation_code: u8, action_code: u8, detail: u32) {
    let _ = log_safety_violation_admitted(violation_code, action_code, detail);
}

/// [`log_safety_violation`], saying whether a queue took the record (never
/// while the recorder is inactive: no volume).
pub fn log_safety_violation_admitted(violation_code: u8, action_code: u8, detail: u32) -> bool {
    LOG_SAFETY_COUNT.fetch_add(1, Ordering::Relaxed);
    latch_carry_note(violation_code, action_code);
    let mut payload = [0u8; LOG_PAYLOAD_BYTES];
    payload[0] = violation_code;
    payload[1] = action_code;
    payload[4..8].copy_from_slice(&detail.to_le_bytes());
    match push_event_at(LOG_EVT_SAFETY_VIOLATION, 0, payload, reserve_admit(&payload)) {
        Ok(_) => true,
        Err(why) => {
            if let Some(why) = why {
                note_latch_lost(&payload, why);
            }
            false
        }
    }
}

/// Record a safety violation AND push it to disk before returning.
///
/// `log_safety_violation` alone only reaches the in-memory queue; durability
/// waits for the watchdog's periodic flush, roughly half a second away. For
/// most events that is the right trade -- a flush blocks on the block device,
/// and the watchdog is the one task that already does I/O-shaped work on a
/// cadence where the cost buys nothing back from the control loop.
///
/// An e-stop is the exception, and it is the exception the log exists for. It
/// is the event most likely to be followed within milliseconds by a reset, a
/// power cut, or a human pulling the plug -- so leaving it in RAM for half a
/// second means the record of the incident is lost to the incident. The
/// periodic flush is a throughput mechanism; this is a durability one, and the
/// two are not interchangeable.
///
/// Safe to block here because every caller has ALREADY stopped the motors and
/// disarmed the ESC before reaching this line. There is no control loop left
/// to starve: the machine is stationary, and the only thing left to get right
/// is the account of why.
///
/// Best-effort by design. It returns the flush result so a caller can count
/// failures, but a log that cannot be written must never stop an e-stop from
/// completing. `Ok` means the storage's `fsync` confirmed the record durable;
/// a record that was written but whose `fsync` failed (on the kernel's
/// storage: the device could not flush, or the flush failed) is an `Err`.
pub fn log_safety_violation_durable(
    violation_code: u8, action_code: u8, detail: u32,
) -> Result<usize, LogStorageError> {
    LOG_SAFETY_COUNT.fetch_add(1, Ordering::Relaxed);
    latch_carry_note(violation_code, action_code);
    let mut payload = [0u8; LOG_PAYLOAD_BYTES];
    payload[0] = violation_code;
    payload[1] = action_code;
    payload[4..8].copy_from_slice(&detail.to_le_bytes());
    let pos = push_durable(payload)?;
    // A latching e-stop is tracked to the medium: pending until a flush whose
    // fsync covered its number, which then prints the durable marker
    // (`announce_latch_durable`), from whichever task did the write — the
    // log flusher for an RT caller, the caller itself otherwise.
    if violation_code == SAFETY_ESTOP && estop_action_latches(action_code) == Some(true) {
        match pos {
            Some(p) => {
                LATCH_PENDING_ACTION.store(action_code as u32, Ordering::Relaxed);
                LATCH_PENDING.fetch_max(p + 1, Ordering::AcqRel);
            }
            None => {}
        }
    }
    logger_flush()
}

/// Durably record the operator-release nonce floor `verify_operator_release`
/// just accepted (owner decision, 2026-09-26 — persistence closes the replay
/// window a captured signed release has across a reset; no TRNG on any
/// target board to seed a fresh, unpredictable challenge instead).
///
/// Durable for the same reason [`log_safety_violation_durable`] is: the
/// event most likely to be followed within milliseconds by a reset is
/// exactly the one whose record must survive it. `safety::
/// verify_operator_release` calls this BEFORE it advances its own in-memory
/// floor — see that function's doc — so a crash between the two leaves the
/// in-memory floor behind the disk's, never ahead of it; [`replay_boot`]'s
/// scan is what a later boot uses to catch it back up.
///
/// Not folded into `log_safety_violation` (a `SAFETY_ESTOP`-shaped record):
/// this event's payload needs a `u64`, not a `u32` `detail` — see
/// [`SAFETY_RELEASE_NONCE`]'s doc for the layout.
pub fn log_release_nonce_floor_durable(nonce: u64) -> Result<usize, LogStorageError> {
    let mut payload = [0u8; LOG_PAYLOAD_BYTES];
    payload[0] = SAFETY_RELEASE_NONCE;
    payload[4..8].copy_from_slice(&(nonce as u32).to_le_bytes());
    payload[8..12].copy_from_slice(&((nonce >> 32) as u32).to_le_bytes());
    push_durable(payload)?;
    NONCE_CARRY.fetch_max(nonce, Ordering::Relaxed);
    logger_flush()
}

/// Durably record the release-key fingerprint a boot provisioned (G1): the
/// next boot's [`replay_boot`] hands it back, and a different key is refused.
/// Durable for the reason [`log_release_nonce_floor_durable`] is: the pin is
/// worthless if a reset can lose it between the key being installed and the
/// first release.
///
/// On success the fingerprint is also carried into every file a later
/// rotation opens ([`KEY_PIN_CARRY`]); on failure nothing is carried, so a
/// pin that did not land is not written by a later rotation either.
pub fn log_operator_key_pin_durable(
    fp: &[u8; OPERATOR_KEY_FP_BYTES],
) -> Result<usize, LogStorageError> {
    let mut payload = [0u8; LOG_PAYLOAD_BYTES];
    payload[0] = SAFETY_OPERATOR_KEY;
    payload[4..].copy_from_slice(fp);
    push_durable(payload)?;
    let flushed = logger_flush()?;
    *KEY_PIN_CARRY.lock() = Some(*fp);
    Ok(flushed)
}

/// Carry a pin an EARLIER boot wrote into this boot's files: set by
/// `estop::operator_key_pin_install` when the topology's key matches the
/// replayed pin, so the rotations of this boot keep it in the newest file
/// ([`KEY_PIN_CARRY`]) even if this boot's own re-emit through
/// [`log_operator_key_pin_durable`] is refused.
pub fn logger_carry_key_pin(fp: &[u8; OPERATOR_KEY_FP_BYTES]) {
    *KEY_PIN_CARRY.lock() = Some(*fp);
}

/// Push a `SAFETY_VIOLATION` record a `*_durable` caller is about to call
/// durable. An ordinary record is refused while this CPU's queue holds
/// [`ORDINARY_QUEUE_LIMIT`] records; a record that uses the safety reserve
/// ([`reserve_admit`]) only when the reserve is full as well. A caller
/// [`FlushBy::Caller`] names then drains the queues itself and pushes again;
/// any other does not drain, and the flush it requested runs after it
/// returns. A record still refused is `Err`: the flush after it would answer
/// `Ok` for OTHER records (for the release nonce floor that `Ok` would
/// advance the in-memory floor with nothing on disk;
/// `verify_operator_release` refuses on `Err`). `Ok(None)`: the logger is
/// off, as before (the flush reports it).
fn push_durable(payload: [u8; LOG_PAYLOAD_BYTES]) -> Result<Option<u64>, LogStorageError> {
    let admit = reserve_admit(&payload);
    let by = flush_by();
    // A caller that drains and pushes again counts only a record that is
    // still refused after the drain.
    let first = if by == FlushBy::Caller { push_record } else { push_event_at };
    let mut why = match first(LOG_EVT_SAFETY_VIOLATION, 0, payload, admit) {
        Ok(p) => {
            DURABLE_WANT.fetch_max(p + 1, Ordering::AcqRel);
            return Ok(Some(p));
        }
        Err(None) => return Ok(None),
        Err(Some(why)) => why,
    };
    if by == FlushBy::Caller {
        let _ = logger_flush_now();
        match push_event_at(LOG_EVT_SAFETY_VIOLATION, 0, payload, admit) {
            Ok(p) => {
                DURABLE_WANT.fetch_max(p + 1, Ordering::AcqRel);
                return Ok(Some(p));
            }
            Err(None) => return Ok(None),
            Err(Some(again)) => why = again,
        }
    }
    note_latch_lost(&payload, why);
    // Dropped, not deferred: nothing of this call is queued.
    match by {
        FlushBy::Caller => {}
        FlushBy::FlusherNow => logger_request_flush(),
        FlushBy::FlusherNextPass => { FLUSH_REQ.fetch_add(1, Ordering::SeqCst); }
    }
    Err(LogStorageError::Io)
}

/// Whether the logger is currently active (`logger_init` has succeeded and
/// `logger_shutdown` has not run since). Exposed so a caller outside this
/// crate that needs to know whether a durable write has anywhere to land —
/// `safety::verify_operator_release`'s persistence guard is the one that
/// exists for — can ask without reaching into `LOG_ACTIVE` directly.
pub fn logger_active() -> bool {
    LOG_ACTIVE.load(Ordering::Acquire)
}

/// Log a mode transition (old_mode → new_mode).
pub fn log_mode_change(old_mode: u8, new_mode: u8) {
    let mut payload = [0u8; LOG_PAYLOAD_BYTES];
    payload[0] = old_mode;
    payload[1] = new_mode;
    telemetry(LOG_EVT_MODE_CHANGE, payload);
}

/// Log skill start.
pub fn log_skill_start(skill_id: u16) {
    let mut payload = [0u8; LOG_PAYLOAD_BYTES];
    payload[0..2].copy_from_slice(&skill_id.to_le_bytes());
    telemetry(LOG_EVT_SKILL_START, payload);
}

/// Log skill end with a result code.
pub fn log_skill_end(skill_id: u16, result_code: u8) {
    let mut payload = [0u8; LOG_PAYLOAD_BYTES];
    payload[0..2].copy_from_slice(&skill_id.to_le_bytes());
    payload[2] = result_code;
    telemetry(LOG_EVT_SKILL_END, payload);
}

/// Log a waypoint event (reached / updated).
pub fn log_waypoint(x_mm: i32, y_mm: i32, index: u16, kind: u8) {
    let mut payload = [0u8; LOG_PAYLOAD_BYTES];
    payload[0..4].copy_from_slice(&x_mm.to_le_bytes());
    payload[4..8].copy_from_slice(&y_mm.to_le_bytes());
    payload[8..10].copy_from_slice(&index.to_le_bytes());
    payload[10] = kind;
    telemetry(LOG_EVT_WAYPOINT, payload);
}

/// Log an error condition.
pub fn log_error(subsystem: u8, error_code: u16, detail: u32) {
    let mut payload = [0u8; LOG_PAYLOAD_BYTES];
    payload[0] = subsystem;
    payload[1..3].copy_from_slice(&error_code.to_le_bytes());
    payload[4..8].copy_from_slice(&detail.to_le_bytes());
    telemetry(LOG_EVT_ERROR, payload);
}

// ---------------------------------------------------------------------------
// Analytics view.
// ---------------------------------------------------------------------------

/// Snapshot of the in-memory analytics counters.
#[derive(Clone, Copy, Debug)]
pub struct LoggerAnalytics {
    pub total_distance_mm:     u64,
    pub mission_duration_ticks: u64,
    pub battery_mah_used:      u32,
    pub safety_violations:     u32,
    pub events_dropped:        u32,
    pub flush_errors:          u32,
    /// Of `events_dropped`, the records lost because every writer handle
    /// stayed taken (not a full queue).
    pub events_busy:           u32,
    /// Rounds a push waited for a writer handle another CPU held.
    pub busy_waits:            u64,
    /// Push numbers the flusher stepped over (a defect, see `GAP_SPINS`).
    pub holes:                 u32,
}

/// Read the current analytics counters.
pub fn logger_analytics() -> LoggerAnalytics {
    let init_ts = LOG_INIT_TS.load(Ordering::Relaxed);
    let duration = now_ticks().saturating_sub(init_ts);
    let battery_uah = LOG_BATTERY_UAH.load(Ordering::Relaxed);
    // mAh = uAh / 1000 (integer division, conservative for low usage).
    let battery_mah = (battery_uah / 1000) as u32;
    LoggerAnalytics {
        total_distance_mm:      LOG_DISTANCE_MM.load(Ordering::Relaxed),
        mission_duration_ticks: duration,
        battery_mah_used:       battery_mah,
        safety_violations:      LOG_SAFETY_COUNT.load(Ordering::Relaxed),
        events_dropped:         LOG_DROPPED.load(Ordering::Relaxed),
        flush_errors:           LOG_FLUSH_ERRORS.load(Ordering::Relaxed),
        events_busy:            LOG_BUSY.load(Ordering::Relaxed),
        busy_waits:             LOG_BUSY_WAITS.load(Ordering::Relaxed),
        holes:                  LOG_HOLES.load(Ordering::Relaxed),
    }
}

/// Accumulate battery usage in microamp-hours — caller integrates INA219 reads.
pub fn logger_add_battery_uah(uah: u32) {
    LOG_BATTERY_UAH.fetch_add(uah as u64, Ordering::Relaxed);
}

/// Reset the analytics counters (typically called on a new mission start).
pub fn logger_analytics_reset() {
    LOG_DISTANCE_MM.store(0, Ordering::Relaxed);
    LOG_BATTERY_UAH.store(0, Ordering::Relaxed);
    LOG_SAFETY_COUNT.store(0, Ordering::Relaxed);
    LOG_DROPPED.store(0, Ordering::Relaxed);
    LOG_FLUSH_ERRORS.store(0, Ordering::Relaxed);
    LOG_BUSY.store(0, Ordering::Relaxed);
    LOG_BUSY_WAITS.store(0, Ordering::Relaxed);
    LOG_HOLES.store(0, Ordering::Relaxed);
    LOG_INIT_TS.store(now_ticks(), Ordering::Relaxed);
}

// ---------------------------------------------------------------------------
// Internals.
// ---------------------------------------------------------------------------

/// Record one telemetry event in its ring of the record region. No lock, no
/// allocation and no console: the real-time motor loop and a fault handler
/// call it. A build with no region (Kconfig `KLOG` off), or a boot before the
/// handover, records nothing.
fn telemetry(kind: u8, payload: [u8; LOG_PAYLOAD_BYTES]) {
    // Gate canary: telemetry takes the safety records' queues, where a flood
    // of it takes the room they exist to keep.
    if cfg!(feature = "telemetry-ring-canary") {
        let _ = push_event_at(kind, 0, payload, Admit::Ordinary);
        return;
    }
    // Host suites: the encoders are also the generators of ordinary records
    // for the queues' own tests (their limits, their reserve, their flush).
    #[cfg(test)]
    if TELEMETRY_ON_RING.with(|c| c.get()) {
        let _ = push_event_at(kind, 0, payload, Admit::Ordinary);
        return;
    }
    let Some(w) = azos_records::writer(azos_records::SOURCE_TELEMETRY) else { return };
    let h = azos_records::Head {
        ts: now_ticks(),
        clock: azos_records::CLOCK_TIMEBASE,
        kind: kind as u16,
        len: LOG_PAYLOAD_BYTES as u16,
        cpu: azos_drv_sys::klog::cpu_tag(),
        flags: azos_drv_sys::timebase::stamp_flags(),
    };
    w.publish(&h, |p| p.bytes(0, &payload));
}

/// Telemetry records taken so far, the sequence of the next (0 without a
/// telemetry ring).
pub fn telemetry_recorded() -> u64 {
    azos_records::reader(azos_records::SOURCE_TELEMETRY).map_or(0, |r| r.head())
}

/// Push a record into this CPU's queue, returning its number; `Err(None)`: the
/// logger is off; `Err(Some(why))`: refused, counted dropped.
fn push_event_at(kind: u8, flags: u8, payload: [u8; LOG_PAYLOAD_BYTES], admit: Admit) -> Result<u64, Option<Refused>> {
    let r = push_record(kind, flags, payload, admit);
    if let Err(Some(why)) = r {
        count_lost(why);
    }
    r
}

/// [`push_event_at`] without counting a refusal.
fn push_record(kind: u8, flags: u8, payload: [u8; LOG_PAYLOAD_BYTES], admit: Admit) -> Result<u64, Option<Refused>> {
    if !LOG_ACTIVE.load(Ordering::Acquire) { return Err(None); }
    let rec = LogRecord { ts: now_ticks(), kind, flags, payload };
    let p = queue_push(&rec, admit).map_err(Some)?;
    nudge_flusher(p.queued);
    Ok(p.seq)
}

/// Count a record a push did not keep.
fn count_lost(why: Refused) {
    LOG_DROPPED.fetch_add(1, Ordering::Relaxed);
    if why == Refused::Busy {
        LOG_BUSY.fetch_add(1, Ordering::Relaxed);
    }
}

/// How a `SAFETY_VIOLATION` payload is admitted: [`Admit::Safety`], the
/// records that may use the reserve, for a `SAFETY_ESTOP` that latches or
/// releases (the next boot's latch is decided by it), for the release nonce
/// floor (a replayed signed release is refused by it) and for the release-key
/// pin (a swapped key is refused by it); [`Admit::Ordinary`]
/// for every other record, a commander-lost stop and the boot self-check's
/// synthetic record included.
fn reserve_admit(payload: &[u8; LOG_PAYLOAD_BYTES]) -> Admit {
    let latch = payload[0] == SAFETY_ESTOP && estop_action_latches(payload[1]).is_some();
    if latch || payload[0] == SAFETY_RELEASE_NONCE || payload[0] == SAFETY_OPERATOR_KEY {
        Admit::Safety
    } else {
        Admit::Ordinary
    }
}

/// A `SAFETY_ESTOP` that latches or releases: the state a file's opening
/// records carry.
fn latch_record(rec: &LogRecord) -> bool {
    rec.kind == LOG_EVT_SAFETY_VIOLATION && rec.payload[0] == SAFETY_ESTOP && estop_action_latches(rec.payload[1]).is_some()
}

/// A record that uses the reserve found no slot: count a latching e-stop as
/// lost (`logger_latch_stats`) and say why. Only possible with every queue's
/// reserve full of safety records the flusher has not taken yet, or with
/// every writer handle held by other CPUs for [`BUSY_ROUNDS`].
fn note_latch_lost(payload: &[u8; LOG_PAYLOAD_BYTES], why: Refused) {
    if payload[0] == SAFETY_ESTOP && estop_action_latches(payload[1]) == Some(true) {
        LATCH_LOST.fetch_add(1, Ordering::Relaxed);
        match why {
            Refused::Busy => azos_drv_sys::kwarn!(
                "[SAFETY] ESTOP record LOST (action {}): every recorder queue's writer stayed taken", payload[1]),
            Refused::Full { .. } => azos_drv_sys::kwarn!(
                "[SAFETY] ESTOP record LOST (action {}): every recorder queue is full (the safety reserve too)", payload[1]),
        }
    }
}

fn now_ticks() -> u64 {
    azos_drv_sys::timebase::now()
}

/// Build a path `/LOG/LOGNNNNN.BIN` for the given serial.
///
/// Public so a [`LogStorage`] implementation can derive the same path this
/// module's own on-disk format promises, instead of inventing a naming
/// scheme that could drift from it.
pub fn make_log_path(serial: u32, out: &mut [u8; 17]) {
    // "/LOG/LOG00000.BIN"  = 17 bytes.
    out.copy_from_slice(b"/LOG/LOG00000.BIN");
    let mut n = serial % LOG_SERIAL_WRAP;
    let digits_start = 8; // "/LOG/LOG" is 8 chars, then 5 digits.
    for i in (0..5).rev() {
        out[digits_start + i] = b'0' + (n % 10) as u8;
        n /= 10;
    }
}

/// The serial at which `make_log_path` starts reusing filenames.
///
/// Named rather than inlined so the wrap notice and the path builder cannot
/// drift apart: `make_log_path` takes `serial % LOG_SERIAL_WRAP`.
pub const LOG_SERIAL_WRAP: u32 = 100_000;

// ---------------------------------------------------------------------------
// Boot replay — the e-stop latch (and the release-nonce floor) survive a
// reset.
// ---------------------------------------------------------------------------
//
// Owner decision, 2026-09-13: at boot, the last `SAFETY_ESTOP` in the durable
// record decides whether the machine starts latched. A session that ended
// latched starts latched; a log file that exists but cannot be read also starts
// latched (fail safe); no volume and no log file is a fresh boot. A latch that a
// power cycle clears is a latch anyone within reach of the plug can clear, and
// the durable e-stop write exists for exactly the reset that follows it.
//
// **It must still run BEFORE `logger_init` — for a different reason now.**
// Until 2026-09-26 every boot started at serial 0 and opened it with
// TRUNCATE, so running after `logger_init` would have erased the very file
// this reads. `logger_init` no longer reuses a serial that might hold bytes
// (see `logger_seed_next_serial`/`BootReplay::next_serial`), so a `logger_
// init` first would no longer destroy anything — but it does not know
// `next_serial` unless something already ran this scan, and the scan is
// this replay. The ordering is now "the seed depends on this having run
// first", not "this must beat a truncation".
//
// Read-only, and deliberately not part of `LogStorage`: the recorder's seam
// stays append-only. Replay is one pass at boot through its own four
// operations, and the decision (`replay_boot`) is a pure function of what
// they return, so the host suite can hand it every shape of disk it has to
// read correctly.

/// `SAFETY_ESTOP` action code of the record written when boot replay restores
/// the latch. `detail` carries the action code that was replayed, or
/// [`ESTOP_RESTORED_UNREADABLE`]. It latches like any source, so a machine that
/// is reset again before anyone clears it stays stopped.
pub const ESTOP_ACTION_RESTORED: u8 = 5;

/// `detail` of a restore record whose cause was a recorder that could not be
/// read, rather than a recorded stop.
pub const ESTOP_RESTORED_UNREADABLE: u32 = 0xFFFF_FFFF;

/// What one `SAFETY_ESTOP` record says about the latch after it: `Some(true)`
/// latched, `Some(false)` released, `None` nothing at all.
///
/// 3 is the operator clear and 7 the boot self-check's synthetic record, which
/// is not a stop. Everything else latches: 0/1/2 are the sources, 4 is a
/// refused clear and, in records written before 6 existed, the ring-3 stop
/// (both are only written while the latch holds), 5 is a restore, 6 is the
/// ring-3 stop, 14 (`ESTOP_ACTION_COMMANDER_LOST`) is a dead motor
/// commander's SAFE STOP, recorded and never latched, and a code added later
/// is a stop until someone says otherwise.
pub const fn estop_action_latches(action: u8) -> Option<bool> {
    match action {
        3 => Some(false),
        7 => None,
        // The SAFE STOP of a dead motor commander: recorded, never latched.
        crate::estop::ESTOP_ACTION_COMMANDER_LOST => None,
        _ => Some(true),
    }
}

/// The last name of the run of session files that starts at name 0, or
/// `Ok(None)` on a blank medium: a galloping probe, then a bisection, so the
/// directory lookups of a boot are two per doubling of the history and not one
/// per file. The run is contiguous (a rotation whose open failed part-way
/// through a full disk leaves a gap the search may land on either side of;
/// the files above it are older attempts). Never past `LOG_SERIAL_WRAP - 1`.
///
/// Before the serials wrap the name is the serial. After, every name exists
/// and [`replay_newest`] finds the newest by the serial in the header.
pub fn replay_tail_serial(
    mut size_of: impl FnMut(u32) -> Result<Option<u32>, LogStorageError>,
) -> Result<Option<u32>, LogStorageError> {
    let mut exists = |name: u32| size_of(name).map(|s| s.is_some());
    if !exists(0)? {
        return Ok(None);
    }
    let (mut lo, mut probe) = (0u32, 1u32);
    while probe < LOG_SERIAL_WRAP && exists(probe)? {
        lo = probe;
        probe = probe.saturating_mul(2);
    }
    let mut hi = probe.min(LOG_SERIAL_WRAP);
    while hi - lo > 1 {
        let mid = lo + (hi - lo) / 2;
        if exists(mid)? {
            lo = mid;
        } else {
            hi = mid;
        }
    }
    Ok(Some(lo))
}

/// The serial a file's header names (version 2), or its own name for a file
/// of version 1, which has none; `Ok(None)` for an empty file (a crash
/// between creating it and its header).
fn header_serial(src: &mut dyn LogReplaySource, name: u32) -> Result<Option<u32>, LogStorageError> {
    src.open(name)?;
    let mut hdr = [0u8; LOG_FILE_HEADER_BYTES];
    let got = read_full(src, &mut hdr);
    src.close();
    let got = got?;
    if got == 0 {
        return Ok(None);
    }
    if got != LOG_FILE_HEADER_BYTES || &hdr[0..4] != LOG_FILE_MAGIC {
        return Err(LogStorageError::Io);
    }
    let version = u16::from_le_bytes([hdr[4], hdr[5]]);
    Ok(Some(if version >= 2 { u32::from_le_bytes([hdr[8], hdr[9], hdr[10], hdr[11]]) } else { name }))
}

/// The newest session's serial on the medium, or `Ok(None)` on a blank one.
///
/// Until the serials reach [`LOG_SERIAL_WRAP`] it is the last name of the run
/// from 0. Once every name exists the files are two laps of one sequence cut
/// at the newest file: names below the cut hold the newer lap, so the serials
/// in the headers fall at the cut and a bisection on "not below file 0's
/// serial" finds it in `log2(LOG_SERIAL_WRAP)` header reads. An empty file
/// counts as the newest (it is the one being opened).
fn replay_newest(src: &mut dyn LogReplaySource) -> Result<Option<u32>, LogStorageError> {
    let Some(last) = replay_tail_serial(|name| src.size(name))? else { return Ok(None) };
    if last + 1 < LOG_SERIAL_WRAP || cfg!(feature = "wrap-tail-canary") {
        return Ok(Some(last));
    }
    let first = header_serial(src, 0)?.unwrap_or(u32::MAX);
    let (mut lo, mut hi) = (0u32, LOG_SERIAL_WRAP);
    while hi - lo > 1 {
        let mid = lo + (hi - lo) / 2;
        if header_serial(src, mid)?.is_none_or(|s| s >= first) {
            lo = mid;
        } else {
            hi = mid;
        }
    }
    match header_serial(src, lo)? {
        Some(serial) => Ok(Some(serial)),
        None => {
            let before = header_serial(src, (lo + LOG_SERIAL_WRAP - 1) % LOG_SERIAL_WRAP)?;
            Ok(Some(before.map_or(lo, |s| s.wrapping_add(1))))
        }
    }
}

/// Read-only access to the previous session's files, for [`replay_boot_latch`].
pub trait LogReplaySource {
    /// Size in bytes of session `serial`'s file, or `Ok(None)` if it does not
    /// exist. Any other failure is an `Err`: a file that may exist and cannot
    /// be looked at is not a blank medium.
    fn size(&mut self, serial: u32) -> Result<Option<u32>, LogStorageError>;
    /// Open `serial`'s file for reading from its first byte.
    fn open(&mut self, serial: u32) -> Result<(), LogStorageError>;
    /// Read from the open file into `buf`. A short read is valid; `Ok(0)` only
    /// at end of file.
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, LogStorageError>;
    /// Close the open file, if any.
    fn close(&mut self);
}

/// What boot replay found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BootLatch {
    /// No log file at all: a blank medium. Boot released.
    NoRecord,
    /// The record holds no e-stop, or its last one was cleared. Boot released.
    Released,
    /// The last e-stop was never cleared; carries its action code. Boot latched.
    Armed(u8),
    /// A log file exists and could not be read. Boot latched.
    Unreadable,
}

impl BootLatch {
    /// Whether this boot must start with the e-stop latched.
    pub const fn latches(self) -> bool {
        matches!(self, BootLatch::Armed(_) | BootLatch::Unreadable)
    }
}

/// Everything one boot needs from the durable record, found in a SINGLE walk
/// over the files — the owner decision of 2026-09-26 (U08-3 + the
/// operator-release nonce floor) that replaces the old "every session starts
/// at serial 0 and truncates it" scheme.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BootReplay {
    /// Whether this boot must start with the e-stop latched, and why.
    pub latch: BootLatch,
    /// The serial the NEW session's `logger_init` must open — one past the
    /// highest serial found on the medium, so a new session never reuses,
    /// and therefore never truncates, a serial that may still hold a
    /// previous session's bytes. `0` on a blank medium.
    pub next_serial: u32,
    /// The highest operator-release nonce durably recorded before this
    /// boot, or `0` when none was ever recorded (including a blank or
    /// unreadable medium) — the same starting value
    /// `safety::RELEASE_NONCE_FLOOR` already has for a fresh process, so
    /// seeding with `0` is a no-op rather than a special case.
    pub release_nonce_floor: u64,
    /// The newest release-key fingerprint durably recorded before this boot
    /// ([`SAFETY_OPERATOR_KEY`]), or `None` when no boot ever pinned one.
    pub operator_key_pin: Option<[u8; OPERATOR_KEY_FP_BYTES]>,
}

/// What one log file holds that a boot replay needs.
struct FileScan {
    /// The last latch-relevant `SAFETY_ESTOP` action.
    estop: Option<u8>,
    /// The last `SAFETY_RELEASE_NONCE` value.
    nonce: Option<u64>,
    /// The last `SAFETY_OPERATOR_KEY` fingerprint.
    key_pin: Option<[u8; OPERATOR_KEY_FP_BYTES]>,
    /// The serial the header names (version 2).
    serial: Option<u32>,
    /// The file opens with the state it carried forward and all of it is on
    /// the medium: nothing in an older file can change what this one says.
    snapshot: bool,
}

impl FileScan {
    const EMPTY: FileScan =
        FileScan { estop: None, nonce: None, key_pin: None, serial: None, snapshot: false };
}

impl BootReplay {
    /// The replay of a medium that yielded no file to walk: `latch`, serial 0,
    /// no nonce floor, no pinned key.
    pub const fn blank(latch: BootLatch) -> BootReplay {
        BootReplay { latch, next_serial: 0, release_nonce_floor: 0, operator_key_pin: None }
    }
}

/// Decide the boot latch, the next session's serial, and the operator-release
/// nonce floor from the previous session(s)' record, in one walk down from
/// the highest existing serial.
///
/// Newest file first. The questions this answers do not always resolve in the
/// same file, so the walk goes on past whichever resolves first until all
/// three are answered, or a file opens with the state it carried forward
/// (`FileScan::snapshot`): that file says what the older ones would have, so
/// the walk ends there. Every file the recorder writes opens that way, and the
/// walk is the newest file or two however long the history is. Files without
/// it are read down to [`REPLAY_MAX_FILES`], and a latch that walk has not
/// ruled out is held.
pub fn replay_boot(src: &mut dyn LogReplaySource) -> BootReplay {
    let tail = match replay_newest(src) {
        Ok(Some(tail)) => tail,
        Ok(None) => return BootReplay::blank(BootLatch::NoRecord),
        Err(_) => return BootReplay::blank(BootLatch::Unreadable),
    };
    let next_serial = tail.wrapping_add(1);
    let mut serial = tail;
    let mut walked = 0u32;
    let mut latch: Option<BootLatch> = None;
    let mut nonce_floor: Option<u64> = None;
    let mut key_pin: Option<[u8; OPERATOR_KEY_FP_BYTES]> = None;
    loop {
        walked += 1;
        match scan_open_log_file_for_boot(src, serial) {
            // A genuinely corrupt or unreadable file (bad magic, a short
            // header, an I/O failure) fails the LATCH safe, exactly as
            // before. It does not touch the nonce or key answers: an
            // unreadable file's own release history was never trusted to
            // begin with, and a nonce this walk cannot see is a nonce that
            // cannot be replayed against by an attacker who could not read
            // it either.
            Err(_) if latch.is_none() => latch = Some(BootLatch::Unreadable),
            Err(_) => {}
            // A file of an older lap of the names: the history this lineage
            // owns ends above it. (The newest file is found by its name.)
            Ok(file) if walked > 1 && file.serial.is_some_and(|s| s != serial) => break,
            Ok(file) => {
                if latch.is_none() {
                    if let Some(action) = file.estop {
                        latch = Some(match estop_action_latches(action) {
                            Some(true) => BootLatch::Armed(action),
                            _ => BootLatch::Released,
                        });
                    }
                }
                nonce_floor = nonce_floor.or(file.nonce);
                key_pin = key_pin.or(file.key_pin);
                if file.snapshot && !cfg!(feature = "replay-snapshot-canary") { break; }
            }
        }
        if latch.is_some() && nonce_floor.is_some() && key_pin.is_some() { break; }
        if serial == 0 { break; }
        if walked >= REPLAY_MAX_FILES {
            // No snapshot in the newest files: the latch may be in a file this
            // walk will not read, so it cannot be ruled out.
            latch = latch.or(Some(BootLatch::Unreadable));
            break;
        }
        serial -= 1;
    }
    BootReplay {
        latch: latch.unwrap_or(BootLatch::Released),
        next_serial,
        release_nonce_floor: nonce_floor.unwrap_or(0),
        operator_key_pin: key_pin,
    }
}

/// Decide the boot latch alone — a thin wrapper over [`replay_boot`] kept for
/// every existing caller (production and the host suite) that only ever
/// needed the latch half of this answer.
pub fn replay_boot_latch(src: &mut dyn LogReplaySource) -> BootLatch {
    replay_boot(src).latch
}

/// The last latch-relevant `SAFETY_ESTOP` action, the last
/// `SAFETY_RELEASE_NONCE` value and the last `SAFETY_OPERATOR_KEY` pin found
/// in `serial`'s file — one read pass answering all, since [`replay_boot`] needs both from every file it
/// visits anyway.
fn scan_open_log_file_for_boot(
    src: &mut dyn LogReplaySource, serial: u32,
) -> Result<FileScan, LogStorageError> {
    src.open(serial)?;
    let found = scan_open_log_file_body(src);
    src.close();
    found
}

fn scan_open_log_file_body(
    src: &mut dyn LogReplaySource,
) -> Result<FileScan, LogStorageError> {
    let mut hdr = [0u8; LOG_FILE_HEADER_BYTES];
    let got = read_full(src, &mut hdr)?;
    if got == 0 {
        // A file that exists but holds nothing at all — a crash between
        // `open` and the header write, the ONLY way a file this module
        // creates can be completely empty. Under the append-only numbering
        // this replaces TRUNCATE-at-serial-0 with, nothing was erased to
        // produce this: the file below it (if any) still holds whatever it
        // held before this boot's aborted attempt. So this is not evidence
        // of corruption and must not fail the latch safe on its own — it
        // answers "nothing found here", identical to a file that opened
        // fine and simply never recorded an estop or a release, and the
        // walk in `replay_boot` falls through to the file below it.
        return Ok(FileScan::EMPTY);
    }
    if got != LOG_FILE_HEADER_BYTES || &hdr[0..4] != LOG_FILE_MAGIC {
        // Non-empty but short, or the wrong magic: real corruption, not a
        // benign empty stub. This DOES fail safe — see the `Err` arm above.
        return Err(LogStorageError::Io);
    }
    // Sixteen records per read, not one: a full tail is 32 768 records, and a
    // read per record is a block-device round trip per record at boot.
    let mut chunk = [0u8; LOG_RECORD_SIZE * 16];
    let mut scan = FileScan::EMPTY;
    let version = u16::from_le_bytes([hdr[4], hdr[5]]);
    let carried = hdr[6] as usize;
    if version >= 2 {
        scan.serial = Some(u32::from_le_bytes([hdr[8], hdr[9], hdr[10], hdr[11]]));
    }
    let mut seen = 0usize;
    loop {
        let got = read_full(src, &mut chunk)?;
        // `chunks_exact` drops a trailing partial record: the write a reset cut
        // short. The decision rests on the last whole one.
        for raw in chunk[..got].chunks_exact(LOG_RECORD_SIZE) {
            seen += 1;
            let mut buf = [0u8; LOG_RECORD_SIZE];
            buf.copy_from_slice(raw);
            let rec = LogRecord::decode(&buf);
            if rec.kind != LOG_EVT_SAFETY_VIOLATION { continue; }
            if rec.payload[0] == SAFETY_ESTOP && estop_action_latches(rec.payload[1]).is_some() {
                if rec.flags & LOG_FLAG_HISTORY != 0 {
                    continue;
                }
                scan.estop = Some(rec.payload[1]);
            } else if rec.payload[0] == SAFETY_RELEASE_NONCE {
                let lo = u32::from_le_bytes(rec.payload[4..8].try_into().unwrap()) as u64;
                let hi = u32::from_le_bytes(rec.payload[8..12].try_into().unwrap()) as u64;
                scan.nonce = Some(scan.nonce.unwrap_or(0).max((hi << 32) | lo));
            } else if rec.payload[0] == SAFETY_OPERATOR_KEY {
                scan.key_pin = Some(rec.payload[4..].try_into().unwrap());
            }
        }
        if got < chunk.len() {
            scan.snapshot = version >= 2 && seen >= carried;
            return Ok(scan);
        }
    }
}

/// Fill `buf`, retrying short reads. Fewer bytes only at end of file.
fn read_full(src: &mut dyn LogReplaySource, buf: &mut [u8]) -> Result<usize, LogStorageError> {
    let mut got = 0;
    while got < buf.len() {
        let n = src.read(&mut buf[got..])?;
        if n == 0 {
            break;
        }
        got += n;
    }
    Ok(got)
}

fn open_log_file(serial: u32) -> Result<(), LogStorageError> {
    let file = open_file(serial, false)?;
    LOG_FILE.acquire().file = Some(file);
    Ok(())
}

/// Open session `serial`'s file and write its header; the caller stores it in
/// the flush claim. `notice_already_written` is set by `logger_flush`'s rotate branch when it
/// has already queued AND flushed the wrap notice into the outgoing file — the
/// only place that can, because it is the only place still holding the old
/// handle. Everyone else passes `false` and this function emits it, which
/// keeps the cold-`logger_init` path (below) covered.
fn open_file(serial: u32, notice_already_written: bool) -> Result<OpenLogFile, LogStorageError> {
    // The serial wrapped, so this open is about to TRUNCATE a file that already
    // holds history. Circular is correct for a flight recorder — the most
    // recent record is the one an investigator wants, and refusing to log
    // would silence the machine precisely when it has been running longest.
    // Doing it in silence was not correct: whoever reads the logs afterwards
    // has no way to tell "nothing happened before this" from "the beginning
    // was overwritten". So the discard is itself an event.
    //
    // WHERE THE BYTES LAND. This used to emit the notice here and then call
    // `logger_flush` (through a wrapper) to push it out, which pinned the
    // call ORDER (notice before truncate) but not the DESTINATION. On the
    // realistic path — a rotation from `logger_flush` — that flush found
    // `LOG_FILE` already `None`, so it was a no-op and the record reached
    // disk inside the file this call was about to open: the notice about a
    // discarded history sat in the file that had just discarded it, saying
    // nothing an investigator can use.
    //
    // The rotate branch of `logger_flush` now does it upstream, while the
    // old handle is still open, and passes `notice_already_written = true`.
    // Its one boundary: the notice has to REACH a queue. If this CPU's queue
    // is at its limit when the rotation triggers, `push_event_at` drops it and
    // bumps `LOG_DROPPED`, and no amount of flushing recovers it — the drain
    // that would have made room is the thing that just failed. That case
    // leaves the `LOG_SAFETY_COUNT` bump as the only trace, same as the cold
    // path below.
    // What is left here is the cold path: `logger_init` at a serial already
    // past the wrap point, where there is no old file to land in anyway.
    // (`LOG_ACTIVE` is still false there, so `push_event_at` drops the record
    // before any queue while `LOG_SAFETY_COUNT` still moves —
    // `log_safety_violation` bumps that counter unconditionally. The counter
    // is the only durable trace on that path; it is only reachable via
    // `set_serial_for_test`, since `LOG_SERIAL` does not survive a boot.)
    //
    // Order is still pinned and tested by
    // `the_wrap_notice_is_logged_before_the_truncating_open`, which now also
    // asserts the destination.
    if serial >= LOG_SERIAL_WRAP && !notice_already_written {
        log_safety_violation(SAFETY_LOG_WRAPPED, 0, serial);
    }

    let storage = current_storage()?;
    let handle = storage.open(serial)?;

    let mut buf = [0u8; LOG_FILE_HEADER_BYTES + SNAPSHOT_MAX * LOG_RECORD_SIZE];
    let (len, snap) = write_file_header(serial, &mut buf);
    let mut off = 0;
    while off < len {
        match storage.write(handle, &buf[off..len])? {
            0 => return Err(LogStorageError::Io),
            w => off += w,
        }
    }
    let _ = storage.fsync(handle);

    Ok(OpenLogFile { handle, bytes_written: len as u32, serial, snap })
}

/// The header of session `serial`'s file and, right behind it in the same
/// write, the state a boot must not have to look further back for: the
/// e-stop latch, the release nonce floor and the release-key pin as of this
/// open, one record each when set. Written whole before anything else, so a
/// file that has them is complete in them: [`FileScan::snapshot`] holds only
/// when the header's count of records is on the medium. Returns the bytes and
/// the push number the state was read at.
fn write_file_header(serial: u32, buf: &mut [u8; LOG_FILE_HEADER_BYTES + SNAPSHOT_MAX * LOG_RECORD_SIZE]) -> (usize, u64) {
    // Read before the carries: a push numbered below it noted its latch
    // before it took the number, so the state below is at least that new.
    let snap = NEXT_SEQ.0.load(Ordering::SeqCst);
    let ts = now_ticks();
    let mut n = 0usize;
    let mut put = |payload: [u8; LOG_PAYLOAD_BYTES]| {
        let at = LOG_FILE_HEADER_BYTES + n * LOG_RECORD_SIZE;
        let rec = LogRecord { ts, kind: LOG_EVT_SAFETY_VIOLATION, flags: 0, payload };
        let mut raw = [0u8; LOG_RECORD_SIZE];
        rec.encode(&mut raw);
        buf[at..at + LOG_RECORD_SIZE].copy_from_slice(&raw);
        n += 1;
    };
    let latch = LATCH_CARRY.load(Ordering::Relaxed);
    if latch & LATCH_SET != 0 && !cfg!(feature = "rotate-latch-canary") {
        let mut p = [0u8; LOG_PAYLOAD_BYTES];
        p[0] = SAFETY_ESTOP;
        p[1] = latch as u8;
        put(p);
    }
    let nonce = NONCE_CARRY.load(Ordering::Relaxed);
    if nonce != 0 {
        let mut p = [0u8; LOG_PAYLOAD_BYTES];
        p[0] = SAFETY_RELEASE_NONCE;
        p[4..8].copy_from_slice(&(nonce as u32).to_le_bytes());
        p[8..12].copy_from_slice(&((nonce >> 32) as u32).to_le_bytes());
        put(p);
    }
    if let Some(fp) = *KEY_PIN_CARRY.lock() {
        let mut p = [0u8; LOG_PAYLOAD_BYTES];
        p[0] = SAFETY_OPERATOR_KEY;
        p[4..].copy_from_slice(&fp);
        put(p);
    }
    buf[..LOG_FILE_HEADER_BYTES].fill(0);
    buf[0..4].copy_from_slice(LOG_FILE_MAGIC);
    buf[4..6].copy_from_slice(&LOG_FILE_VERSION.to_le_bytes());
    buf[6] = n as u8;
    buf[8..12].copy_from_slice(&serial.to_le_bytes());
    buf[12..16].copy_from_slice(&(ts as u32).to_le_bytes());
    (LOG_FILE_HEADER_BYTES + n * LOG_RECORD_SIZE, snap)
}

// ---------------------------------------------------------------------------
// Helpful test-friendly accessors.
// ---------------------------------------------------------------------------

/// Records the recorder holds in RAM, every queue's and the flusher's (for
/// tests / diagnostics).
pub fn logger_ring_len() -> usize {
    ring_len()
}

/// Current session serial number (mostly for tests).
pub fn logger_current_serial() -> u32 {
    LOG_FILE.acquire().file.as_ref().map(|f| f.serial).unwrap_or(0)
}

#[cfg(test)]
std::thread_local! {
    static TELEMETRY_ON_RING: core::cell::Cell<bool> = const { core::cell::Cell::new(false) };
}

/// Host suites, per thread: the telemetry encoders push into the flight
/// recorder's queues (`on`: the queues' own tests use them to generate
/// ordinary records) or, by default, into the record region's telemetry ring.
#[cfg(test)]
pub fn telemetry_on_ring_for_test(on: bool) {
    TELEMETRY_ON_RING.with(|c| c.set(on));
}

/// Force the serial counter. Test-only: exercising the wrap path
/// (`LOG_SERIAL_WRAP`) through the public API alone would mean looping
/// through 100,000 real rotations, which no host suite can afford. Compiled
/// out of every non-test build (`cfg(test)` is crate-wide, so this vanishes
/// from the real `azos_behavior` the kernel links).
#[cfg(test)]
pub fn set_serial_for_test(n: u32) {
    LOG_SERIAL.store(n, Ordering::Relaxed);
}

#[cfg(test)]
std::thread_local! {
    static CPU_FOR_TEST: core::cell::Cell<Option<usize>> = const { core::cell::Cell::new(None) };
}

/// Run once by the next push, between taking its number and publishing the
/// record: the window in which the flusher must wait for that number.
/// Test-only, compiled out like [`set_serial_for_test`].
#[cfg(test)]
static PUSH_GAP_HOOK: AtomicFn<fn()> = AtomicFn::new();

#[cfg(test)]
pub fn set_push_gap_hook_for_test(f: Option<fn()>) {
    PUSH_GAP_HOOK.set(f);
}

/// Run once by the next push that finds a queue full (and spills), with that
/// queue: a test takes its writer handle there, as another CPU pushing into it.
#[cfg(test)]
static FULL_HOOK: AtomicFn<fn(usize)> = AtomicFn::new();

#[cfg(test)]
pub fn set_full_hook_for_test(f: Option<fn(usize)>) {
    FULL_HOOK.set(f);
}

/// Queue `q`'s writer handle, held until dropped.
#[cfg(test)]
pub fn hold_writer_for_test(q: usize) -> HeldWriters {
    HeldWriters {
        _writers: std::vec![loop {
            if let Some(w) = QUEUES[q].producer() {
                break w;
            }
            std::thread::yield_now();
        }],
    }
}

/// Spins the flusher spent waiting for a number a producer was publishing.
#[cfg(test)]
static GAP_WAITS: AtomicU64 = AtomicU64::new(0);

#[cfg(test)]
pub fn gap_waits_for_test() -> u64 {
    GAP_WAITS.load(Ordering::Relaxed)
}

/// Every queue's writer handle, held by the caller until dropped: other
/// CPUs' pushes in flight, as long as the test likes.
#[cfg(test)]
pub struct HeldWriters {
    _writers: std::vec::Vec<azos_rings::Producer<'static, Queued, LOG_QUEUE_CAPACITY>>,
}

#[cfg(test)]
pub fn hold_writers_for_test() -> HeldWriters {
    HeldWriters {
        _writers: QUEUES.iter().map(|q| loop {
            if let Some(w) = q.producer() {
                break w;
            }
            std::thread::yield_now();
        }).collect(),
    }
}

/// Flush requests made so far (`FLUSH_REQ`).
#[cfg(test)]
pub fn flush_requests_for_test() -> u32 {
    FLUSH_REQ.load(Ordering::SeqCst)
}

/// Host suites, per thread: the CPU whose queue this thread's pushes try
/// first (`None`: the build's `cpu_tag`, 0 on the host).
#[cfg(test)]
pub fn cpu_for_test(cpu: Option<usize>) {
    CPU_FOR_TEST.with(|c| c.set(cpu));
}

/// The receipt index (B3). Each test takes its own device, so the statics the
/// suites share do not interleave.
#[cfg(test)]
mod receipt_index_tests {
    use super::*;

    /// Timebase ticks in `ms` milliseconds.
    fn ms(n: u64) -> u64 {
        n * (azos_drv_sys::timebase::TIMER_FREQ / 1000)
    }

    /// An effect payload: kind, class, subject.
    fn payload(kind: u8, class: u8, subject: u16) -> [u8; LOG_PAYLOAD_BYTES] {
        let mut p = [0u8; LOG_PAYLOAD_BYTES];
        p[0] = kind;
        p[1] = class;
        p[2..4].copy_from_slice(&subject.to_le_bytes());
        p
    }

    const DRIVE: u8 = 1;
    const STOP: u8 = 0;

    /// A receipt is found by its device and kind, aged against the instant
    /// asked, with the contrary kind's age beside it. **Canary.** Key the
    /// cell by `subject` alone in `receipt_cell`: the second device below
    /// answers the first one's receipt, red.
    #[test]
    fn a_receipt_is_found_by_device_and_kind() {
        let (a, b) = ((1u16 << 8) | 5, (1u16 << 8) | 6);
        assert_eq!(receipt_ages_at(a, DRIVE, ms(1000)), (NO_RECEIPT_AGE, NO_RECEIPT_AGE), "no receipt yet");
        receipt_note(&payload(1, DRIVE, 5), ms(100));
        assert_eq!(receipt_ages_at(a, DRIVE, ms(350)), (250, NO_RECEIPT_AGE));
        assert_eq!(receipt_ages_at(a, STOP, ms(350)), (NO_RECEIPT_AGE, 250), "the other kind sees it as its contrary");
        assert_eq!(receipt_ages_at(b, DRIVE, ms(350)), (NO_RECEIPT_AGE, NO_RECEIPT_AGE), "another wheel");
    }

    /// A later receipt of the contrary kind is younger than the receipt it
    /// contradicts, and a newer receipt of the kind itself replaces the age.
    /// A late-noted older receipt (a slower hart) does not take the cell back.
    /// **Canary.** Store instead of `fetch_max` in `receipt_note`: the stale
    /// note below turns the age back, red.
    #[test]
    fn the_newest_receipt_of_each_kind_is_kept() {
        let d = (2u16 << 8) | 1;
        receipt_note(&payload(2, DRIVE, 1), ms(100));
        receipt_note(&payload(2, STOP, 1), ms(200));
        assert_eq!(receipt_ages_at(d, DRIVE, ms(300)), (200, 100), "stopped after it was driven");
        receipt_note(&payload(2, DRIVE, 1), ms(250));
        assert_eq!(receipt_ages_at(d, DRIVE, ms(300)), (50, 100), "driven again after the stop");
        receipt_note(&payload(2, DRIVE, 1), ms(120));
        assert_eq!(receipt_ages_at(d, DRIVE, ms(300)), (50, 100), "a stale note does not regress it");
    }

    /// A coordinate the index does not hold has no receipt, and noting one
    /// writes nothing anywhere else. **Canary.** Drop the bound on `subject`
    /// in `receipt_cell`: the note lands in the next kind's cells, red.
    #[test]
    fn coordinates_outside_the_index_leave_no_receipt() {
        let edge = (3u16 << 8) | (RECEIPT_SUBJECTS as u16 - 1);
        receipt_note(&payload(2, DRIVE, RECEIPT_SUBJECTS as u16), ms(10));
        receipt_note(&payload(RECEIPT_EFFECT_KINDS as u8, DRIVE, 0), ms(10));
        receipt_note(&payload(3, 2, 0), ms(10));
        assert_eq!(receipt_ages_at(edge, DRIVE, ms(20)), (NO_RECEIPT_AGE, NO_RECEIPT_AGE));
        assert_eq!(receipt_ages_at(3 << 8, DRIVE, ms(20)), (NO_RECEIPT_AGE, NO_RECEIPT_AGE), "not the next kind's first device");
        assert_eq!(receipt_ages_at(3 << 8, 2, ms(20)), (NO_RECEIPT_AGE, NO_RECEIPT_AGE), "a kind past the classes");
        assert_eq!(receipt_ages_at((RECEIPT_EFFECT_KINDS as u16) << 8, DRIVE, ms(20)), (NO_RECEIPT_AGE, NO_RECEIPT_AGE));
        receipt_note(&payload(3, DRIVE, RECEIPT_SUBJECTS as u16 - 1), ms(10));
        assert_eq!(receipt_ages_at(edge, DRIVE, ms(20)), (10, NO_RECEIPT_AGE), "the last device is held");
    }

    /// The tick-to-millisecond conversion is exact, rounds down, never
    /// overflows and reads a receipt from the future as age 0.
    #[test]
    fn age_is_exact_and_bounded() {
        let f = azos_drv_sys::timebase::TIMER_FREQ;
        assert_eq!(receipt_ms(0, f), 1000);
        assert_eq!(receipt_ms(0, f / 1000 - 1), 0);
        assert_eq!(receipt_ms(7, 7 + 3 * f + f / 2), 3500);
        assert_eq!(receipt_ms(1, u64::MAX) / 1000, (u64::MAX - 1) / f);
        assert_eq!(receipt_ms(100, 50), 0);
    }
}

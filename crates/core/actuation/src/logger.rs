// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! E06 — Mission logging / replay / analytics.
//!
//! Ring buffer of compact event records in RAM, periodically flushed to FAT32
//! for post-mortem analysis. All events are fixed-size (32 bytes on-wire) so
//! that replay readers don't have to parse variable-length records.
//!
//! File layout on disk:
//!   /LOG/LOGNNNNN.BIN          N = monotonic session serial (5 digits)
//!   Header 16B:  b"RBL1" | version u16 LE | reserved u16 | open_ts u64 LE
//!   Records 32B each: see LogRecord below.
//!
//! File rotation: when the current file exceeds LOG_FILE_ROTATE_BYTES, it is
//! fsynced + closed and a new file is opened with the next serial number.
//!
//! Analytics counters (in RAM, reset at init):
//!   - total_distance_mm      (from odometry events)
//!   - mission_duration_ticks (CLINT ticks since logger_init)
//!   - battery_mah_used       (INA219 integration, caller feeds microamp-hours)
//!   - safety_violations      (incremented per SafetyViolation event)
//!   - events_dropped         (ring-buffer overflow counter)
//!   - flush_errors           (storage errors during flush)

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use azos_sync::waitqueue::WaitQueue;
use azos_sync::SpinLock;

// ---------------------------------------------------------------------------
// Storage seam — the flight recorder's only contact with a filesystem.
// ---------------------------------------------------------------------------
//
// `domains/robot/behavior` is core (the actuation authority) and `crates/fs/fs` is
// scaffolding (FAT32 is the only filesystem this OS has, but nothing in it
// can move or stop a motor). This module used to call `fat32_mount_volume`/
// `mkdir`/`open`/`write`/`fsync`/`close`/`file_stat` directly, which put a
// hard dependency edge from core onto scaffolding (`tools/tcb_check.sh`).
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
// from `crates/net/net` through the kernel rather than depending on it.

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
    /// rule, wave 15): its records are on the ring and the log flusher task
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
/// A `SpinLock`, not a `PiMutex`: this only ever guards a pointer copy.
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
/// ([`ESTOP_ACTION_RESTORED`]), 6 = a ring-3 program through `SYS_ROBOT_ESTOP`,
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

/// The brain changed the graded degrade level (RFC-0037).
///
/// `action_code` carries the new level (0 = FULL … 3 = CONTAINED); `detail`
/// carries the level it replaced, so a reader can see the transition and not
/// just the destination.
///
/// Every change is recorded, including the intermediate CAUTIOUS and SLOW
/// levels — owner decision, 2026-09-05. `SAFETY_DEGRADE` already records the
/// one-bit RFC-0036 view on both arm and clear; recording only CONTAINED here
/// would have left the same gap the graded levels exist to close, namely why
/// the robot was moving slowly rather than merely whether it had stopped.
///
/// A change to the SAME level is not recorded. The brain may resend a standing
/// level at any cadence it likes — the level is sticky by design — and a
/// recorder that logged every repeat would fill the medium with the fact that
/// nothing happened.
pub const SAFETY_SEMANTIC_LEVEL: u8 = 0x06;

/// A `PKT_SEMANTIC_LEVEL` arrived with no payload byte and was treated as
/// CONTAINED (RFC-0037).
///
/// Separate from `SAFETY_SEMANTIC_LEVEL` on purpose. That code says the brain
/// asked for a level; this one says the kernel could not tell what was asked
/// and stopped the robot. They are different events with different causes — a
/// truncated packet is a link fault or a hostile sender, not a decision — and
/// collapsing them would make the fail-closed path invisible in the record at
/// exactly the moment it mattered.
pub const SAFETY_SEMANTIC_MALFORMED: u8 = 0x07;

/// A brain packet arrived whose type this build does not act on (RFC-0039).
///
/// `action_code` carries the packet type; `detail` the payload length.
///
/// The dispatch chains for both the network path and the UART bridge end
/// without an `else`, so an unrecognised type was counted as received and
/// dropped — no log line, and no counter separating "handled" from "ignored".
/// A brain that put the robot into `CONTAINED` with `PKT_SEMANTIC_LEVEL`
/// against a kernel built before RFC-0037 therefore got no error at all, and
/// the robot kept running at `FULL` while the brain's own record said it was
/// contained. Fail-open by omission, and every future packet type inherits it.
///
/// This is the cheapest half of RFC-0039 and it stands alone: it does not make
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
/// from a real record, because the untyped target (`handlers::denial_target`) is 0 for `Buzzer`,
/// `Power`, `Disk` and `NetConfig` — an untyped Power denial on the read path
/// IS `detail = 0`. So reuse would make an unmeasured value forge a measured
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
/// Both denial codes above only reach the in-memory ring, and the ring
/// overwrites its oldest record. A ring-3 loop presenting forged handles wrote
/// one record per syscall, which between two watchdog flushes evicted the
/// ring-only records next to it — degrade-level changes, sys-wdt events,
/// `SAFETY_UNKNOWN_PKT`. So `crates/core/syscall` admits a few denial records per
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
/// Recorded the way the capability denials are: into the ring, through their
/// per-task bound (`admit_denial_record` in `crates/core/syscall/src/handlers.rs`)
/// with a budget of its own, onto the disk with the watchdog's flush. A loop of
/// unlisted calls writes at most four of these per task per window and one
/// `SAFETY_CAP_DENIED_SUPPRESSED` summary with `action_code` `0xFE`, cannot push
/// the records beside it out of the ring, and cannot be silenced by the same
/// task's capability denials.
pub const SAFETY_SECCOMP_AUDIT: u8 = 0x0C;

/// An exec was refused because no seccomp image profile is bound to the image.
///
/// Each image profile is bound to the SHA-256 of the exact ELF the build copies
/// onto the disk image (`crates/core/sched/src/seccomp.rs`), and the table is a
/// whitelist: every exec path hashes the bytes it is about to load and does not
/// load an image that matches none, so a replaced binary, one rebuilt after the
/// kernel, or one nobody profiled does not run. `action_code` names the path:
/// 0 = the autorun loader, 1 = the shell's `exec`, 2 = a ring-3 `SYS_EXEC` or
/// `SYS_EXECPATH`, 3 = the shell's `spawn`. `detail` is the first four bytes
/// of the image's SHA-256, big-endian, so the record says which bytes were
/// refused.
///
/// Action 4 is the one refusal of a BOUND image: a `SYS_SPAWN` of an image the
/// signed topology has no row for (`crates/core/syscall/src/spawn.rs`,
/// `SPAWN_REFUSED_ACTION_NO_ROW`, owner decision 2026-09-28).
/// Action 5 is a `SYS_SPAWN_EX` without the launch grant (RFC-0055). Action
/// 6 is a streamed image (larger than the exec bounce buffer, RFC-0047) whose
/// bytes at load did not hash to the digest it was planned by: the file
/// changed between the two reads.
///
/// The autorun loader and the shell write it durably: a refused autorun is a
/// robot that did not start its program, and the likely next event is a person
/// power-cycling it. The ring-3 refusal goes through the capability denials'
/// per-task bound, on a budget of its own, into the ring (summary `action_code`
/// `0xFD`), so a program
/// retrying exec in a loop gets neither a synchronous write per call nor a way
/// to push other records out.
pub const SAFETY_EXEC_REFUSED: u8 = 0x0D;

/// A capability the signed topology declares was REFUSED by its minter, so the
/// task started without it (RFC-0040 gap 2, 2026-09-19). `detail` carries the
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
/// closed with no gate installed (`gate_speed` in `domains/robot/robot/src/
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
/// on a `link-encrypt-enforced` build (owner decision, 2026-09-26, V1.2 —
/// U09-8 / security finding #26). `action_code`/`detail` unused (0) — which
/// side initiated (dial vs. accept) is already in the console line next to
/// this record's timestamp, and is not safety-relevant on its own.
pub const SAFETY_ENTROPY_UNSEEDED_REFUSED: u8 = 0x14;

/// A ring-3 service-registry call was REFUSED for authority (owner decision
/// 2026-09-27, round 7): registering a service under another task's TID, or
/// stopping / heartbeating a service registered to another task.
/// `action_code` is the operation (`SERVICE_OP_*` in `crates/core/syscall`),
/// `detail` the TID the caller reached for (the claimed TID on register, the
/// service's owner on stop/heartbeat).
pub const SAFETY_SERVICE_REFUSED: u8 = 0x15;

/// A ring-3 task's topology row names a scheduling class this build's
/// scheduler does not have (wave 7), so its class and priority were NOT
/// applied: the task runs at the priority it was created with instead of the
/// one the signed topology declares. `action_code` is the site (0 = autorun,
/// 1 = `SYS_SPAWN`), `detail` the task's TID.
///
/// Also written (sites 2 = autorun, 3 = `SYS_SPAWN`) when the row WAS applied
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

/// The RFC-0049 M4 supervisor restarted a ring-3 driver, gave up on it, or
/// saw it end under its topology row's `restart = no`. `action_code` is one
/// of the `SUP_ACTION_*` below; `detail` packs the driver-server kind (high 16
/// bits) and the restart count so far (low 16): the attempt number for a
/// restart, the spent budget for a give-up, the restarts before for an end.
///
/// One code with four actions rather than four codes: the supervisor's
/// whole history for one driver is one filter on the recorder.
pub const SAFETY_DRIVER_SUPERVISOR: u8 = 0x17;
/// A successor task was created for a supervised driver that died.
pub const SUP_ACTION_RESTART: u8 = 1;
/// The driver died with its restart budget spent: everything it held was
/// released and its kind stays down.
pub const SUP_ACTION_GAVE_UP: u8 = 2;
/// No successor could be created (task pool full): released and down, as a
/// give-up.
pub const SUP_ACTION_RESPAWN_FAILED: u8 = 3;
/// The driver ended (any exit code) under its topology row's `restart = no`:
/// released and not restarted, by policy rather than by a spent budget
/// (wave 11). Recorded as a give-up is, so a driver that is gone for good is
/// always on the recorder, whichever rule ended it.
pub const SUP_ACTION_NO_RESTART: u8 = 4;

/// The `detail` word of a [`SAFETY_DRIVER_SUPERVISOR`] record.
pub const fn sup_record_detail(kind: u32, count: u8) -> u32 {
    ((kind & 0xFFFF) << 16) | count as u32
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

/// The rt-motor task's motor-command watchdog (`domains/robot/safety-core/
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

/// Size of a log record on-disk and in-ring (bytes).
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
// Ring buffer: lock-free, bounded, many producers, one consumer.
// ---------------------------------------------------------------------------
//
// Owner rule (wave 15): a real-time task never does block I/O, and never
// waits for a task that does. Every encoder below runs in whatever task logs
// the event (the 1 kHz motor loop, the RT watchdog, the syscall path), so the
// ring they push into takes no lock. Positions only grow (u64); slot
// `pos % CAPACITY` carries a sequence word:
//
//   seq == pos       free for the producer of position `pos`
//   seq == pos + 1   holds position `pos`'s record (published)
//
// A producer claims `RING_HEAD` with a compare-and-swap, stores the encoded
// record and publishes it (D. Vyukov's bounded queue). When the ring is full
// it EVICTS the oldest record — a compare-and-swap of `RING_TAIL` from that
// record's position, counted in `LOG_DROPPED` — and frees its slot: the
// newest events are the ones that explain a crash. It never sleeps and never
// waits for a lock; the only wait is for a producer of the same slot that
// claimed it and has not published yet, which runs with preemption off.
//
// The consumer (whoever holds the flush lock `LOG_FILE`: the log flusher, or
// a non-RT `*_durable` caller) copies records without removing them
// (`ring_peek`), writes them, and removes only what the medium took
// (`ring_consume`). A record evicted while it was being copied is detected
// by its sequence word (a seqlock read) and not written.

/// Records held in RAM before flushing (Kconfig `LOG_RING_ENTRIES`, a power
/// of two).
pub const LOG_RING_CAPACITY: usize = azos_limits::LOG_RING_ENTRIES as usize;
const _: () = assert!(LOG_RING_CAPACITY.is_power_of_two() && LOG_RING_CAPACITY >= 2);
const RING_CAP: u64 = LOG_RING_CAPACITY as u64;
const RING_MASK: u64 = RING_CAP - 1;
const RING_WORDS: usize = LOG_RECORD_SIZE / 8;

/// One slot. The record is stored encoded, as words, so a reader never
/// touches a non-atomic byte a writer might be storing.
struct RingSlot {
    seq: AtomicU64,
    w:   [AtomicU64; RING_WORDS],
}

static RING_SLOTS: [RingSlot; LOG_RING_CAPACITY] = {
    let mut slots = [const { RingSlot { seq: AtomicU64::new(0), w: [const { AtomicU64::new(0) }; RING_WORDS] } };
        LOG_RING_CAPACITY];
    let mut i = 0;
    while i < LOG_RING_CAPACITY {
        slots[i].seq = AtomicU64::new(i as u64);
        i += 1;
    }
    slots
};
/// Next position a producer claims.
static RING_HEAD: AtomicU64 = AtomicU64::new(0);
/// Oldest position still in the ring. Advanced one position at a time, by
/// compare-and-swap, by the consumer (consumed) or a producer (evicted);
/// whoever wins position `p` frees its slot (`seq = p + CAPACITY`).
static RING_TAIL: AtomicU64 = AtomicU64::new(0);

#[inline(always)]
fn ring_slot(pos: u64) -> &'static RingSlot {
    &RING_SLOTS[(pos & RING_MASK) as usize]
}

/// Records queued (claimed, published or not, and not yet removed).
fn ring_len() -> usize {
    let tail = RING_TAIL.load(Ordering::Acquire);
    let head = RING_HEAD.load(Ordering::Acquire);
    head.saturating_sub(tail).min(RING_CAP) as usize
}

/// Push one record; `false` when it had to evict the oldest record to fit
/// (the caller counts the loss). Never blocks.
fn ring_push(rec: &LogRecord) -> bool {
    let mut buf = [0u8; LOG_RECORD_SIZE];
    rec.encode(&mut buf);
    let mut evicted = false;
    // Claim and publish without being preempted: a consumer or a lapping
    // producer that finds this slot claimed-but-unpublished waits for it
    // (`ring_peek`, the `seq == old` arm below), and that wait must stay a
    // few stores long.
    let _np = azos_sync::preempt::critical_section();
    let mut pos = RING_HEAD.load(Ordering::Relaxed);
    loop {
        let slot = ring_slot(pos);
        let seq = slot.seq.load(Ordering::Acquire);
        if seq == pos {
            match RING_HEAD.compare_exchange_weak(pos, pos + 1, Ordering::Relaxed, Ordering::Relaxed) {
                Ok(_) => {
                    // Seqlock writer side: the slot's last sequence change
                    // (its release, which this thread acquired above) is
                    // ordered before the data a racing reader may see.
                    core::sync::atomic::fence(Ordering::Release);
                    for (i, w) in slot.w.iter().enumerate() {
                        let mut b = [0u8; 8];
                        b.copy_from_slice(&buf[i * 8..i * 8 + 8]);
                        w.store(u64::from_le_bytes(b), Ordering::Relaxed);
                    }
                    slot.seq.store(pos + 1, Ordering::Release);
                    return !evicted;
                }
                Err(now) => pos = now,
            }
        } else if seq < pos {
            // Full: the slot still holds position `old`. Published: evict it
            // (whoever wins the tail CAS frees the slot). Claimed but not
            // published: its producer runs with preemption off; wait.
            let old = pos - RING_CAP;
            if seq == old + 1 {
                if RING_TAIL.compare_exchange(old, old + 1, Ordering::AcqRel, Ordering::Relaxed).is_ok() {
                    slot.seq.store(pos, Ordering::Release);
                    evicted = true;
                }
            } else {
                core::hint::spin_loop();
            }
            pos = RING_HEAD.load(Ordering::Relaxed);
        } else {
            pos = RING_HEAD.load(Ordering::Relaxed);
        }
    }
}

/// Copy up to `out.len() / LOG_RECORD_SIZE` encoded records from the oldest
/// WITHOUT removing them; returns `(first position, count)`. Consumer only
/// (flush lock held).
///
/// Records leave the ring only through [`ring_consume`], once the medium
/// took them: the destructive drain this replaces destroyed exactly the
/// records around a failed write — the ones a flight recorder exists to keep.
/// A position claimed but not yet published is waited for (its producer runs
/// with preemption off), so a record pushed before a flush began is in it.
fn ring_peek(out: &mut [u8]) -> (u64, usize) {
    let max = out.len() / LOG_RECORD_SIZE;
    'restart: loop {
        let first = RING_TAIL.load(Ordering::Acquire);
        let mut n = 0;
        while n < max {
            let pos = first + n as u64;
            if pos >= RING_HEAD.load(Ordering::Acquire) {
                break;
            }
            let slot = ring_slot(pos);
            loop {
                let seq = slot.seq.load(Ordering::Acquire);
                if seq == pos + 1 {
                    break;
                }
                if seq != pos {
                    // Evicted (and maybe rewritten) since `first` was read.
                    if n == 0 { continue 'restart; }
                    return (first, n);
                }
                core::hint::spin_loop();
            }
            let o = n * LOG_RECORD_SIZE;
            for (i, w) in slot.w.iter().enumerate() {
                out[o + i * 8..o + i * 8 + 8].copy_from_slice(&w.load(Ordering::Relaxed).to_le_bytes());
            }
            // Seqlock reader side: a record evicted while it was copied is
            // not this position's record.
            core::sync::atomic::fence(Ordering::Acquire);
            if slot.seq.load(Ordering::Relaxed) != pos + 1 {
                if n == 0 { continue 'restart; }
                return (first, n);
            }
            n += 1;
        }
        return (first, n);
    }
}

/// Remove positions `first .. first + n` — records the medium accepted.
/// Consumer only. A position a producer evicted meanwhile is already gone
/// (and counted dropped, although it reached the medium).
fn ring_consume(first: u64, n: usize) {
    for pos in first..first + n as u64 {
        if RING_TAIL.compare_exchange(pos, pos + 1, Ordering::AcqRel, Ordering::Relaxed).is_ok() {
            ring_slot(pos).seq.store(pos + RING_CAP, Ordering::Release);
        }
    }
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

/// Currently-open logfile (None if not yet opened or rotation in progress).
///
/// The flush lock: held for the WHOLE flush, which is a loop of
/// `LogStorage::write` calls plus an `fsync` — real disk I/O on the other
/// side of the seam. Holding it is what serialises two flushers (and makes
/// the ring's consumer single). It is a `SleepLock`, not a `PiMutex`
/// (owner rule F1, wave 15: no `PiMutex` across device I/O): no real-time
/// task ever takes it — an RT caller of [`logger_flush`] wakes the log
/// flusher instead — so there is no RT waiter whose priority a holder
/// would need to inherit, and a waiter sleeps rather than spinning.
///
/// Every caller is task context: the log flusher, `logger_shutdown`, and
/// non-RT `*_durable` callers. No interrupt handler touches this.
static LOG_FILE: azos_sync::SleepLock<Option<OpenLogFile>> = azos_sync::SleepLock::new(None);

// Its holder is counted for the panic path by `azos_sync::sleep_lock::held_by`.

// ---------------------------------------------------------------------------
// The log flusher: the one place RT tasks' records reach the medium.
// ---------------------------------------------------------------------------
//
// Owner rule (wave 15): a real-time task never does block I/O. An RT caller
// of `logger_flush` (the RT watchdog's periodic flush, a `*_durable` record
// from the motor loop after its SAFE STOP) bumps `FLUSH_REQ` and wakes the
// flusher, a kernel task at `LOG_FLUSHER_PRIORITY` (outside the RT band),
// which flushes the whole ring — records in push order, the RT caller's
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
/// Bumped by the flusher after each pass (requests up to the value it read
/// before the pass are done).
static FLUSH_DONE: AtomicU32 = AtomicU32::new(0);
static FLUSH_WQ: WaitQueue = WaitQueue::new();

/// Deferred I/O jobs posted by RT tasks (one-shot `fn()`s the flusher runs).
/// Slots claimed with a CAS from 0; a full table refuses the job.
static DEFERRED_IO: [AtomicUsize; LOG_FLUSHER_JOBS] = [const { AtomicUsize::new(0) }; LOG_FLUSHER_JOBS];
/// Kconfig `LOG_FLUSHER_JOBS`: deferred I/O job slots.
pub const LOG_FLUSHER_JOBS: usize = azos_limits::LOG_FLUSHER_JOBS as usize;

/// Kernel hook: "is the calling task real-time?" (base priority in the RT
/// band). `0` (none) on the host and before the scheduler exists: every
/// caller then flushes itself, as before the rule.
static RT_CALLER_FN: AtomicUsize = AtomicUsize::new(0);

/// Register the RT-caller probe (the kernel, at boot).
pub fn logger_set_rt_probe(f: fn() -> bool) {
    RT_CALLER_FN.store(f as usize, Ordering::Release);
}

fn rt_caller() -> bool {
    if cfg!(feature = "rt-flush-canary") {
        return false;
    }
    let f = RT_CALLER_FN.load(Ordering::Acquire);
    if f == 0 {
        return false;
    }
    // SAFETY: only `logger_set_rt_probe` stores here, and it stores a `fn() -> bool`.
    let f: fn() -> bool = unsafe { core::mem::transmute::<usize, fn() -> bool>(f) };
    f()
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
        if slot.compare_exchange(0, job as usize, Ordering::AcqRel, Ordering::Relaxed).is_ok() {
            logger_request_flush();
            return true;
        }
    }
    false
}

/// A function the flusher runs at the end of every pass (0: none): the
/// kernel's printer of what must never print from where it happened
/// (lockdep's reports, Kconfig LOCKDEP=y outside ktest).
static PASS_HOOK: AtomicUsize = AtomicUsize::new(0);

/// Run `f` at the end of every flusher pass (task context, no lock held;
/// the periodic flush request makes that about twice a second).
pub fn logger_set_pass_hook(f: fn()) {
    PASS_HOOK.store(f as usize, Ordering::Release);
}

/// The log flusher task body: sleep until a request, flush the ring, run the
/// deferred jobs, repeat. Spawned by the kernel at `LOG_FLUSHER_PRIORITY`.
pub fn logger_flusher_task(_: usize) {
    loop {
        let seen = logger_flusher_pass();
        FLUSH_WQ.wait_if(|| FLUSH_REQ.load(Ordering::SeqCst) == seen);
    }
}

/// One pass of the flusher: flush the ring, then run the deferred jobs.
/// Returns the request count read before the pass (every request up to it
/// is served). The task body, and what a host test drives in its place.
pub fn logger_flusher_pass() -> u32 {
    let seen = FLUSH_REQ.load(Ordering::SeqCst);
    if LOG_ACTIVE.load(Ordering::Acquire) && ring_len() > 0 {
        let _ = logger_flush_now();
    }
    for slot in DEFERRED_IO.iter() {
        let job = slot.swap(0, Ordering::AcqRel);
        if job != 0 {
            // SAFETY: only `logger_defer_io` stores here, and it stores a `fn()`.
            let job: fn() = unsafe { core::mem::transmute::<usize, fn()>(job) };
            job();
        }
    }
    let hook = PASS_HOOK.load(Ordering::Acquire);
    if hook != 0 {
        // SAFETY: only `logger_set_pass_hook` stores here, and it stores a `fn()`.
        let hook: fn() = unsafe { core::mem::transmute::<usize, fn()>(hook) };
        hook();
    }
    FLUSH_DONE.store(seen, Ordering::Release);
    seen
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
}

// ---------------------------------------------------------------------------
// Logger configuration.
// ---------------------------------------------------------------------------

/// Rotate the log file when it exceeds this many bytes.
pub const LOG_FILE_ROTATE_BYTES: u32 = 1024 * 1024;
/// Flush the ring to disk when this many records are queued.
pub const LOG_FLUSH_WATERMARK: usize = LOG_RING_CAPACITY / 2;
/// Log directory (always ASCII uppercase for FAT32 8.3).
pub const LOG_DIR_PATH: &[u8] = b"/LOG";
/// File magic identifying a azos log file.
pub const LOG_FILE_MAGIC: &[u8; 4] = b"RBL1";
/// Log file format version.
pub const LOG_FILE_VERSION: u16 = 1;
/// Size of the on-disk file header.
pub const LOG_FILE_HEADER_BYTES: usize = 16;
/// Records encoded per write inside a flush (tune for WCET).
///
/// **Not the ring capacity.** It used to be, which put a 128-record batch
/// (4 KiB) and a 4 KiB encode buffer in one `logger_flush` frame — 8 KiB on a
/// kernel stack of 16 KiB, which is what `CONFIG_KERNEL_STACK_SIZE_KB` was
/// everywhere until 2026-09-16 and still is on embedded, with the FAT32
/// write path and its own sector buffering called from underneath it. A flush
/// now loops over chunks, so the ring still empties in one call but the frame
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
    let _ = logger_flush();
    let mut guard = LOG_FILE.lock();
    if let Some(open) = guard.take() {
        if let Ok(storage) = current_storage() {
            let _ = storage.fsync(open.handle);
            let _ = storage.close(open.handle);
        }
    }
}

/// Periodic tick — call from a kernel timer (~1 Hz). Flushes when the ring
/// watermark is reached.
pub fn logger_tick() {
    if !LOG_ACTIVE.load(Ordering::Acquire) { return; }
    let should_flush = ring_len() >= LOG_FLUSH_WATERMARK;
    if should_flush { let _ = logger_flush(); }
}

/// Force a flush of the ring buffer to disk. Returns the number of records
/// written (can be 0 if the ring was empty), or `Err` when a write failed OR
/// when records were written but the storage's `fsync` did not confirm them
/// durable (see `flush_one_batch`).
///
/// A real-time caller does not flush (owner rule: an RT task never does
/// block I/O): it wakes the log flusher and gets `Err(Deferred)` at once.
pub fn logger_flush() -> Result<usize, LogStorageError> {
    if rt_caller() {
        logger_request_flush();
        return Err(LogStorageError::Deferred);
    }
    logger_flush_now()
}

/// The flush itself, in the calling task (never an RT one: see
/// [`logger_flush`]).
fn logger_flush_now() -> Result<usize, LogStorageError> {
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

    // The file lock is held for the whole flush, which is what serialises two
    // flushers (a timer tick and `logger_shutdown` on another hart) now that
    // records are no longer removed from the ring up front: without it both
    // would peek the same records and write them twice.
    //
    // LOCK ORDER: there is one lock left. The ring takes none (producers
    // claim a slot with a CAS), so pushing a record while `LOG_FILE` is held
    // — the wrap notice below does — cannot invert anything. Host-checked
    // under real thread contention by
    // `behavior-tests::flight_recorder::concurrent_flush_and_push_never_invert_the_file_ring_order`.
    let mut guard = LOG_FILE.lock();
    let open = match guard.as_mut() {
        Some(o) => o,
        None => {
            LOG_FLUSH_ERRORS.fetch_add(1, Ordering::Relaxed);
            return Err(LogStorageError::Unavailable);
        }
    };

    let mut total = 0usize;
    let mut torn = false;
    let mut failure: Option<LogStorageError> = None;

    loop {
        let r = flush_one_batch(storage, open);
        total += r.consumed;
        torn |= r.torn;
        if failure.is_none() { failure = r.failure; }
        if r.stop { break; }
    }

    // ── The wrap notice belongs in the file whose ending it describes ──────
    //
    // It used to be emitted inside `open_log_file`, which runs AFTER the old
    // handle is closed below — so the record stayed on the ring and reached
    // disk inside the NEXT file, the one that had just truncated the history
    // the notice was about. `open_log_file`'s own comment said so and called
    // the fix "real work, not attempted here". This is that work.
    //
    // Decide the rotation first, then, if the serial about to be used is past
    // the wrap point, push the notice and drain ONE more batch while the old
    // handle is still open. `open_log_file` is told not to emit it again, so
    // it is written exactly once.
    //
    // `log_safety_violation` takes no lock (the ring is lock-free), so pushing
    // it while FILE is held here orders nothing.
    let rotate = torn || open.bytes_written >= LOG_FILE_ROTATE_BYTES;
    // One read, used for both the decision and the record: `fetch_add` below
    // returns this same value as `next_serial` (it returns the OLD one), and
    // no other hart can be between the two — a concurrent flusher finds
    // `LOG_FILE` already `None` and returns `Unavailable` without rotating.
    let next_serial = LOG_SERIAL.load(Ordering::Relaxed);
    let wrapping = rotate && next_serial >= LOG_SERIAL_WRAP;
    if wrapping {
        log_safety_violation(SAFETY_LOG_WRAPPED, 0, next_serial);
        // Drain, not one pass. The notice goes to the TAIL of the ring while
        // `flush_one_batch` takes at most `LOG_FLUSH_BATCH_MAX` (16) from the
        // head, so a single pass only reaches it when fewer than 16 records
        // are queued ahead of it. That is true after a clean drain and false
        // exactly where it matters: the loop above stops early on a torn or
        // failed write WITHOUT consuming, so the ring can still hold a full
        // 128 records at this point — and the notice would ride them into
        // the new file, which is the defect this whole branch exists to fix.
        // `stop` still terminates on failure or on no progress, so this
        // cannot spin.
        loop {
            let r = flush_one_batch(storage, open);
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
        let handle = open.handle;
        let _ = storage.fsync(handle);
        let _ = storage.close(handle);
        *guard = None;
        drop(guard);
        // Evaluate the bump on its own line: `debug_assert_eq!` does NOT
        // evaluate its arguments in a release build, and the gate builds
        // everything `--release` — putting the `fetch_add` inside it would
        // silently stop the serial from ever advancing.
        let advanced = LOG_SERIAL.fetch_add(1, Ordering::Relaxed);
        debug_assert_eq!(advanced, next_serial);
        let _ = open_log_file_inner(next_serial, wrapping);
    }

    match failure {
        Some(e) => Err(e),
        None => Ok(total),
    }
}

/// What one pass of the flush loop did.
struct BatchOutcome {
    /// Records the medium actually took, and which therefore left the ring.
    consumed: usize,
    /// The write stopped mid-record: the file now ends with a partial record,
    /// so the caller must rotate.
    torn: bool,
    failure: Option<LogStorageError>,
    /// No more work, or no more progress — the caller must stop looping.
    stop: bool,
}

/// Encode and write one batch from the ring into `open`, retrying a short
/// write, and consume from the ring only what the medium took.
///
/// Extracted from `logger_flush` so the wrap notice can be carried to disk by
/// **one more pass over the same code** rather than a second copy of it. A
/// duplicate of this logic is how the short-write bug it already contains
/// would come back: a storage write returns a count and nothing promises it
/// equals `buf.len()`, and adding that count to `bytes_written` and moving on
/// leaves a torn 32-byte record that misframes every record after it — the
/// whole rest of the file, not just the tail.
fn flush_one_batch(storage: &'static dyn LogStorage, open: &mut OpenLogFile) -> BatchOutcome {
    // The ring stores records encoded: peek straight into the write buffer.
    let mut out = [0u8; LOG_FLUSH_BATCH_MAX * LOG_RECORD_SIZE];
    let (first, n) = ring_peek(&mut out);
    if n == 0 {
        return BatchOutcome { consumed: 0, torn: false, failure: None, stop: true };
    }

    // Write the whole chunk, retrying the remainder. A short write is a
    // transient; the correct response is to write the rest.
    let len = n * LOG_RECORD_SIZE;
    let mut off = 0usize;
    let mut failure: Option<LogStorageError> = None;
    while off < len {
        match storage.write(open.handle, &out[off..len]) {
            Ok(0) => break,                  // no progress: stop, don't spin
            Ok(w) => off += w,
            Err(e) => { failure = Some(e); break; }
        }
    }

    open.bytes_written = open.bytes_written.saturating_add(off as u32);
    // Only records the medium actually took leave the ring.
    let whole = off / LOG_RECORD_SIZE;
    ring_consume(first, whole);

    if off != len {
        // Either the device stopped making progress or it errored. If it
        // stopped mid-record the file now ends with a partial record, so the
        // caller rotates: the damage stays at EOF of a closed file and the
        // next one starts on a record boundary.
        LOG_FLUSH_ERRORS.fetch_add(1, Ordering::Relaxed);
        return BatchOutcome {
            consumed: whole,
            torn: off % LOG_RECORD_SIZE != 0,
            failure: Some(failure.unwrap_or(LogStorageError::Io)),
            stop: true,
        };
    }

    // The records are written; `fsync` is what makes them durable (the
    // kernel's implementation ends in a device flush). Its failure does not
    // stop the drain: the records have already left the ring, and writing
    // them again would not make them any more durable. It IS this batch's
    // result, so `logger_flush` -- and through it every `*_durable` call --
    // answers `Err` for records that are written but not known durable.
    let synced = storage.fsync(open.handle);
    if synced.is_err() {
        LOG_FLUSH_ERRORS.fetch_add(1, Ordering::Relaxed);
    }
    BatchOutcome {
        consumed: whole,
        torn: false,
        failure: synced.err(),
        stop: n < LOG_FLUSH_BATCH_MAX,
    }
}

// ---------------------------------------------------------------------------
// Event encoders — each wraps `push_event()`.
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
    push_event(LOG_EVT_SENSOR_SNAPSHOT, 0, payload);
}

/// Log an actuator command (speed_l, speed_r for wheeled; channel/value generic).
pub fn log_actuator_cmd(actuator_type: u8, ch0: i16, ch1: i16, ch2: i16, ch3: i16) {
    let mut payload = [0u8; LOG_PAYLOAD_BYTES];
    payload[0] = actuator_type;
    payload[2..4].copy_from_slice(&ch0.to_le_bytes());
    payload[4..6].copy_from_slice(&ch1.to_le_bytes());
    payload[6..8].copy_from_slice(&ch2.to_le_bytes());
    payload[8..10].copy_from_slice(&ch3.to_le_bytes());
    push_event(LOG_EVT_ACTUATOR_CMD, 0, payload);
}

/// Log a safety violation. Bumps the violation counter.
pub fn log_safety_violation(violation_code: u8, action_code: u8, detail: u32) {
    LOG_SAFETY_COUNT.fetch_add(1, Ordering::Relaxed);
    let mut payload = [0u8; LOG_PAYLOAD_BYTES];
    payload[0] = violation_code;
    payload[1] = action_code;
    payload[4..8].copy_from_slice(&detail.to_le_bytes());
    push_event(LOG_EVT_SAFETY_VIOLATION, 0, payload);
}

/// Record a safety violation AND push it to disk before returning.
///
/// `log_safety_violation` alone only reaches the in-memory ring; durability
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
    log_safety_violation(violation_code, action_code, detail);
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
    push_event(LOG_EVT_SAFETY_VIOLATION, 0, payload);
    logger_flush()
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
    push_event(LOG_EVT_MODE_CHANGE, 0, payload);
}

/// Log skill start.
pub fn log_skill_start(skill_id: u16) {
    let mut payload = [0u8; LOG_PAYLOAD_BYTES];
    payload[0..2].copy_from_slice(&skill_id.to_le_bytes());
    push_event(LOG_EVT_SKILL_START, 0, payload);
}

/// Log skill end with a result code.
pub fn log_skill_end(skill_id: u16, result_code: u8) {
    let mut payload = [0u8; LOG_PAYLOAD_BYTES];
    payload[0..2].copy_from_slice(&skill_id.to_le_bytes());
    payload[2] = result_code;
    push_event(LOG_EVT_SKILL_END, 0, payload);
}

/// Log a waypoint event (reached / updated).
pub fn log_waypoint(x_mm: i32, y_mm: i32, index: u16, kind: u8) {
    let mut payload = [0u8; LOG_PAYLOAD_BYTES];
    payload[0..4].copy_from_slice(&x_mm.to_le_bytes());
    payload[4..8].copy_from_slice(&y_mm.to_le_bytes());
    payload[8..10].copy_from_slice(&index.to_le_bytes());
    payload[10] = kind;
    push_event(LOG_EVT_WAYPOINT, 0, payload);
}

/// Log an error condition.
pub fn log_error(subsystem: u8, error_code: u16, detail: u32) {
    let mut payload = [0u8; LOG_PAYLOAD_BYTES];
    payload[0] = subsystem;
    payload[1..3].copy_from_slice(&error_code.to_le_bytes());
    payload[4..8].copy_from_slice(&detail.to_le_bytes());
    push_event(LOG_EVT_ERROR, 0, payload);
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
    LOG_INIT_TS.store(now_ticks(), Ordering::Relaxed);
}

// ---------------------------------------------------------------------------
// Internals.
// ---------------------------------------------------------------------------

fn push_event(kind: u8, flags: u8, payload: [u8; LOG_PAYLOAD_BYTES]) {
    if !LOG_ACTIVE.load(Ordering::Acquire) { return; }
    let rec = LogRecord { ts: now_ticks(), kind, flags, payload };
    let accepted = ring_push(&rec);
    if !accepted {
        LOG_DROPPED.fetch_add(1, Ordering::Relaxed);
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

/// The highest existing session-file serial on the medium, or `Ok(None)` on
/// a blank one.
///
/// **Owner decision, 2026-09-26 (U08-3).** Until this decision, `logger_init`
/// always opened serial 0 with TRUNCATE, so this function's job was to find
/// "where THIS session's own rotation left off among files that all start
/// from 0" — it walked up from 0 and stopped at the first file that had not
/// been closed by a rotation, because every session started fresh at 0 and
/// anything above that point had to be a STALE file an older, longer session
/// left behind.
///
/// Now a new session opens at `next_serial` from the boot's own
/// [`replay_boot`], one past whatever the previous session's tail was — so
/// serials are contiguous across reboots, never reused, and there is no such
/// thing as a "stale file left by a longer session" any more (see
/// `boot_numbering_is_contiguous_across_reboots_not_reset_to_zero` in the
/// host suite for the property this replaces). The question this function
/// answers is now simply "how far up does the medium's file sequence go" —
/// walk up from 0 while a file exists, and the first gap is one past the
/// answer.
///
/// Read wrong in one bounded case, same as before: a rotation (or a boot's
/// very first open) whose write failed part-way through the medium (a full
/// disk) can leave a gap followed by a stale file from an even older
/// attempt; this walk stops at the first gap and never looks past it.
pub fn replay_tail_serial(
    mut size_of: impl FnMut(u32) -> Result<Option<u32>, LogStorageError>,
) -> Result<Option<u32>, LogStorageError> {
    let mut serial = 0u32;
    loop {
        match size_of(serial)? {
            None => return Ok(serial.checked_sub(1)),
            Some(_) if serial + 1 >= LOG_SERIAL_WRAP => return Ok(Some(serial)),
            Some(_) => serial += 1,
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
}

/// Decide the boot latch, the next session's serial, and the operator-release
/// nonce floor from the previous session(s)' record, in one walk down from
/// the highest existing serial.
///
/// Newest file first. The two questions this answers do not always resolve
/// in the same file — a stop from something OTHER than an operator release
/// (the GPIO kill switch, a stale sensor) can be the newest decisive record
/// with the last actual release several files further back — so the walk
/// continues past whichever decision resolves first, down to serial 0 if
/// it has to, until BOTH are answered. This costs a full walk on a boot
/// where no release was ever recorded (the common case for a robot with no
/// provisioned operator key), which is the same shape of cost
/// `replay_boot_latch` already paid for "no e-stop ever recorded" before
/// this change — bounded by this boot-numbering lineage's total file count,
/// not unbounded.
pub fn replay_boot(src: &mut dyn LogReplaySource) -> BootReplay {
    let tail = match replay_tail_serial(|serial| src.size(serial)) {
        Ok(Some(tail)) => tail,
        Ok(None) => return BootReplay { latch: BootLatch::NoRecord, next_serial: 0, release_nonce_floor: 0 },
        Err(_) => return BootReplay { latch: BootLatch::Unreadable, next_serial: 0, release_nonce_floor: 0 },
    };
    let next_serial = tail.wrapping_add(1);
    let mut serial = tail;
    let mut latch: Option<BootLatch> = None;
    let mut nonce_floor: u64 = 0;
    let mut nonce_found = false;
    loop {
        match scan_open_log_file_for_boot(src, serial) {
            // A genuinely corrupt or unreadable file (bad magic, a short
            // header, an I/O failure) fails the LATCH safe, exactly as
            // before. It does not touch the nonce answer: an unreadable
            // file's own release history was never trusted to begin with,
            // and a nonce this walk cannot see is a nonce that cannot be
            // replayed against by an attacker who could not read it either.
            Err(_) if latch.is_none() => latch = Some(BootLatch::Unreadable),
            Err(_) => {}
            Ok((estop_action, file_nonce)) => {
                if latch.is_none() {
                    if let Some(action) = estop_action {
                        latch = Some(match estop_action_latches(action) {
                            Some(true) => BootLatch::Armed(action),
                            _ => BootLatch::Released,
                        });
                    }
                }
                if !nonce_found {
                    if let Some(n) = file_nonce {
                        nonce_floor = n;
                        nonce_found = true;
                    }
                }
            }
        }
        if latch.is_some() && nonce_found { break; }
        if serial == 0 { break; }
        serial -= 1;
    }
    BootReplay {
        latch: latch.unwrap_or(BootLatch::Released),
        next_serial,
        release_nonce_floor: nonce_floor,
    }
}

/// Decide the boot latch alone — a thin wrapper over [`replay_boot`] kept for
/// every existing caller (production and the host suite) that only ever
/// needed the latch half of this answer.
pub fn replay_boot_latch(src: &mut dyn LogReplaySource) -> BootLatch {
    replay_boot(src).latch
}

/// The last latch-relevant `SAFETY_ESTOP` action, and the last
/// `SAFETY_RELEASE_NONCE` value, found in `serial`'s file — one read pass
/// answering both, since [`replay_boot`] needs both from every file it
/// visits anyway.
fn scan_open_log_file_for_boot(
    src: &mut dyn LogReplaySource, serial: u32,
) -> Result<(Option<u8>, Option<u64>), LogStorageError> {
    src.open(serial)?;
    let found = scan_open_log_file_body(src);
    src.close();
    found
}

fn scan_open_log_file_body(
    src: &mut dyn LogReplaySource,
) -> Result<(Option<u8>, Option<u64>), LogStorageError> {
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
        return Ok((None, None));
    }
    if got != LOG_FILE_HEADER_BYTES || &hdr[0..4] != LOG_FILE_MAGIC {
        // Non-empty but short, or the wrong magic: real corruption, not a
        // benign empty stub. This DOES fail safe — see the `Err` arm above.
        return Err(LogStorageError::Io);
    }
    // Sixteen records per read, not one: a full tail is 32 768 records, and a
    // read per record is a block-device round trip per record at boot.
    let mut chunk = [0u8; LOG_RECORD_SIZE * 16];
    let mut last_estop = None;
    let mut last_nonce = None;
    loop {
        let got = read_full(src, &mut chunk)?;
        // `chunks_exact` drops a trailing partial record: the write a reset cut
        // short. The decision rests on the last whole one.
        for raw in chunk[..got].chunks_exact(LOG_RECORD_SIZE) {
            let mut buf = [0u8; LOG_RECORD_SIZE];
            buf.copy_from_slice(raw);
            let rec = LogRecord::decode(&buf);
            if rec.kind != LOG_EVT_SAFETY_VIOLATION { continue; }
            if rec.payload[0] == SAFETY_ESTOP && estop_action_latches(rec.payload[1]).is_some() {
                last_estop = Some(rec.payload[1]);
            } else if rec.payload[0] == SAFETY_RELEASE_NONCE {
                let lo = u32::from_le_bytes(rec.payload[4..8].try_into().unwrap()) as u64;
                let hi = u32::from_le_bytes(rec.payload[8..12].try_into().unwrap()) as u64;
                last_nonce = Some((hi << 32) | lo);
            }
        }
        if got < chunk.len() {
            return Ok((last_estop, last_nonce));
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
    open_log_file_inner(serial, false)
}

/// `notice_already_written` is set by `logger_flush`'s rotate branch when it
/// has already queued AND flushed the wrap notice into the outgoing file — the
/// only place that can, because it is the only place still holding the old
/// handle. Everyone else passes `false` and this function emits it, which
/// keeps the cold-`logger_init` path (below) covered.
fn open_log_file_inner(serial: u32, notice_already_written: bool) -> Result<(), LogStorageError> {
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
    // Its one boundary: the notice has to REACH the ring. If the ring is
    // exactly full when the rotation triggers, `push_event` drops it and
    // bumps `LOG_DROPPED`, and no amount of flushing recovers it — the drain
    // that would have made room is the thing that just failed. That case
    // leaves the `LOG_SAFETY_COUNT` bump as the only trace, same as the cold
    // path below.
    // What is left here is the cold path: `logger_init` at a serial already
    // past the wrap point, where there is no old file to land in anyway.
    // (`LOG_ACTIVE` is still false there, so `push_event` drops the record
    // before the ring while `LOG_SAFETY_COUNT` still moves —
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

    // Write header.
    let mut hdr = [0u8; LOG_FILE_HEADER_BYTES];
    hdr[0..4].copy_from_slice(LOG_FILE_MAGIC);
    hdr[4..6].copy_from_slice(&LOG_FILE_VERSION.to_le_bytes());
    hdr[6..8].copy_from_slice(&0u16.to_le_bytes());
    hdr[8..16].copy_from_slice(&now_ticks().to_le_bytes());
    let written = storage.write(handle, &hdr)?;
    let _ = storage.fsync(handle);

    *LOG_FILE.lock() = Some(OpenLogFile {
        handle,
        bytes_written: written as u32,
        serial,
    });
    Ok(())
}

// ---------------------------------------------------------------------------
// Helpful test-friendly accessors.
// ---------------------------------------------------------------------------

/// Number of records currently in the ring (for tests / diagnostics).
pub fn logger_ring_len() -> usize {
    ring_len()
}

/// Current session serial number (mostly for tests).
pub fn logger_current_serial() -> u32 {
    LOG_FILE.lock().as_ref().map(|f| f.serial).unwrap_or(0)
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

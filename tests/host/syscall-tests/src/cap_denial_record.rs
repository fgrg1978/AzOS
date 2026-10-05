// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// The capability layer's refusals, and whether anything hears them.
//
// `SAFETY_CAP_DENIED` was a defined flight-recorder event code with NO
// production call site: only `tests/host/behavior-tests` ever named it. So the
// refusal worked and nothing recorded that it had happened — on a machine
// whose black box is specified to hold security events, the event saying "an
// untrusted program reached for an actuator and was refused" was the one
// missing. It is also the one event the denied caller has every reason not to
// report itself.
//
// `cap_check` now calls an installed hook on the deny path. These tests drive
// the real `cap_check` (this crate `include!`s `handlers.rs`, so it is the
// shipping function, not a copy) and observe the hook.
//
// **The negative half is the point.** A test that only asserts "a denial is
// recorded" passes just as happily against a hook fired on every check,
// granted or not — which would fill the recorder with routine traffic and
// bury the events it exists for. So the grant case is asserted to produce
// NOTHING, and both halves run against the same installed hook.

use super::harness::serial;
use azos_abi::cap::{CapKind, CapPerms};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Mutex;

/// The cap-store pool slot the callers here are bound to. 22 and 51-58 are
/// taken by other files in this crate.
const SLOT: usize = 59;

/// Every denial the hook saw, in order: (kind code, detail word).
static SEEN: Mutex<Vec<(u8, u32)>> = Mutex::new(Vec::new());

fn recorder(kind_code: u8, target: u32, need_write: bool) {
    SEEN.lock()
        .unwrap_or_else(|e| e.into_inner())
        .push((kind_code, target | if need_write { 0x8000_0000 } else { 0 }));
}

/// TIDs no other test in this crate uses, so a table one test filled is never
/// read by another.
static NEXT_TID: AtomicU32 = AtomicU32::new(0x7300_0001);
fn fresh_tid() -> u32 {
    NEXT_TID.fetch_add(1, Ordering::SeqCst)
}

/// Install `tid` as an unprivileged caller with an empty capability table, and
/// arm the recorder.
///
/// `set_current_user_pt(0)` means "kernel task" to `cap_check`, which returns
/// true before looking at any table — so a non-zero sentinel is required for
/// these tests to reach the code under test at all. Nothing dereferences it.
fn as_user_with_recorder(tid: u32) {
    ipc_task_pool::shim_bind(tid, SLOT);
    azos_ipc::cap_store::reset(tid);
    SEEN.lock().unwrap_or_else(|e| e.into_inner()).clear();
    set_cap_deny_recorder(recorder);
    azos_sched::set_current_user_pt(0xBAD0_0000);
    azos_sched::set_current_task_tid(tid);
}

fn seen() -> Vec<(u8, u32)> {
    SEEN.lock().unwrap_or_else(|e| e.into_inner()).clone()
}

#[test]
fn a_denied_capability_is_recorded_with_its_kind_and_target() {
    let _g = serial();
    let tid = fresh_tid();
    as_user_with_recorder(tid);

    assert!(!cap_check(CapKind::Motor, 3, true), "no grant, must be denied");

    // Motor is kind code 5 (`CapKind::denial_code`, frozen because it is
    // written into the recording); the detail word carries the motor id with
    // the write bit set, because a refused WRITE to a motor is a refused
    // command and a refused read is not.
    assert_eq!(seen(), vec![(5u8, 3u32 | 0x8000_0000)]);
}

#[test]
fn the_write_bit_separates_a_refused_command_from_a_refused_read() {
    let _g = serial();
    let tid = fresh_tid();
    as_user_with_recorder(tid);

    assert!(!cap_check(CapKind::Gpio, 7, false));
    assert_eq!(seen(), vec![(2u8, 7u32)], "read denial must NOT set the top bit");
}

#[test]
fn a_granted_capability_records_nothing() {
    let _g = serial();
    let tid = fresh_tid();
    as_user_with_recorder(tid);
    assert!(azos_ipc::cap_store::with_table(tid, |t| t.grant_raw(CapKind::Motor, CapPerms::RW, 3))
        .flatten()
        .is_some());

    assert!(cap_check(CapKind::Motor, 3, true), "granted, must be allowed");

    // The half that discriminates: a hook wired to every check rather than to
    // the deny arm would put an entry here, and the test above would still
    // pass. The recorder exists to hold security events, and a granted motor
    // write is the most ordinary thing this kernel does.
    assert_eq!(seen(), Vec::new());
}

#[test]
fn a_kernel_caller_records_nothing_because_it_is_never_denied() {
    let _g = serial();
    SEEN.lock().unwrap_or_else(|e| e.into_inner()).clear();
    set_cap_deny_recorder(recorder);
    // `user_pt == 0` is how `cap_check` recognises an in-kernel caller.
    azos_sched::set_current_user_pt(0);

    assert!(cap_check(CapKind::Motor, 3, true));
    assert_eq!(seen(), Vec::new());
}

/// **A caller whose TID names no live task is refused and recorded**, like a
/// caller holding nothing: `cap_store::with_table` answers `None` and the
/// refusal still reaches the black box.
///
/// **Canary.** Return before `record_cap_denial` when `with_table` is `None`:
/// `seen()` is empty.
#[test]
fn a_caller_with_no_capability_table_is_refused_and_recorded() {
    let _g = serial();
    let tid = fresh_tid();
    as_user_with_recorder(tid);
    ipc_task_pool::shim_kill(tid);

    assert!(!cap_check(CapKind::Sensor, 4, false));
    assert_eq!(seen(), vec![(1u8, 4u32)]);
}

/// The `SAFETY_CAP_DENIED` record format, frozen: a recording made by an older
/// build must still decode. `(kind, kind code, resource the capability table
/// stores, target the record carries)`, transcribed from the retired handle
/// table's `code()` and `target()` (RFC-0040 gap 1): the I2C record keeps the
/// bus of `bus << 8 | addr`, the objectless kinds record 0, the MMIO record a
/// region's base, every other kind its id. Literals on purpose: computed
/// values would move with the code they pin.
///
/// The MMIO row changed resource, not target (RFC-0043, decision 72): the
/// capability stores an index into the board's MMIO region table and the
/// record carries the base looked up from it. This crate builds no board
/// feature, so index 0 is QEMU's goldfish RTC at `0x0010_1000`.
const FROZEN_RECORD_FORMAT: [(CapKind, u8, u32, u32); 13] = [
    (CapKind::Sensor, 1, 7, 7),
    (CapKind::Gpio, 2, 20, 20),
    (CapKind::I2c, 3, 3 << 8 | 0x68, 3),
    (CapKind::Pwm, 4, 4, 4),
    (CapKind::Motor, 5, 1, 1),
    (CapKind::Irq, 6, 9, 9),
    (CapKind::MmioRegion, 7, 0, 0x0010_1000),
    (CapKind::Adc, 8, 2, 2),
    (CapKind::Buzzer, 9, 0, 0),
    (CapKind::Power, 10, 0, 0),
    (CapKind::Disk, 11, 0, 0),
    (CapKind::NetConfig, 12, 0, 0),
    (CapKind::DriverRegistry, 13, 1, 1),
];

/// **The record names what it always named.** `denial_target` gives the
/// frozen target for the resource the capability table stores, for every kind
/// the untyped record has carried.
///
/// **Canary.** Drop the `I2c` arm from `denial_target`: the I2C line reads
/// `0x368`.
#[test]
fn the_denial_target_is_the_frozen_record_target_for_every_kind() {
    for (kind, _, resource, target) in FROZEN_RECORD_FORMAT {
        assert_eq!(denial_target(kind, resource), target, "{kind:?}: target");
    }
}

/// An I2C refusal through `cap_check` records the bus alone, end to end.
#[test]
fn an_i2c_denial_records_the_bus() {
    let _g = serial();
    let tid = fresh_tid();
    as_user_with_recorder(tid);
    assert!(!cap_check(CapKind::I2c, 3 << 8 | 0x68, false));
    assert_eq!(seen(), vec![(3u8, 3u32)]);
}

/// **An MMIO refusal records the region's base, not the index the call
/// named** (decision 72), end to end through `cap_check`, the check
/// `SYS_MMIO_MAP` makes. An index outside the board's table records 0: the
/// syscall refuses one with `EINVAL` before it reaches `cap_check`, and the
/// record stays total for any other caller.
///
/// **Canary.** Drop the `MmioRegion` arm from `denial_target`: the records
/// carry the indices, `1`, `0` and `2`.
#[test]
fn an_mmio_denial_records_the_regions_base_not_its_index() {
    let _g = serial();
    let tid = fresh_tid();
    as_user_with_recorder(tid);

    assert!(!cap_check(CapKind::MmioRegion, 1, true));
    assert!(!cap_check(CapKind::MmioRegion, 0, false));
    assert!(!cap_check(CapKind::MmioRegion, 3, false));
    assert_eq!(
        seen(),
        vec![(7u8, 0x0400_0000u32 | 0x8000_0000), (7, 0x0010_1000), (7, 0)],
        "index 1 is the writable page at 0x0400_0000, index 0 the RTC, 3 is outside the table \
         (2 is the RTC's writable alias, wave 9)"
    );
    assert_eq!(denial_target(CapKind::MmioRegion, u32::MAX), 0);
}

// ── The TYPED path: `SAFETY_CAP_DENIED_TYPED` ─────────────────────────────
//
// `cap_check` above is the ONLY caller of the untyped recorder, and no
// `*_TYPED` handler goes through `cap_check`. So every refusal of a `Cap<T>`
// used to be recorded nowhere — an errno and silence. As each family migrates
// to `Cap<T>` that silence widens, one family at a time, and the gate stays
// green the whole way. These tests are what stops that.

/// Every typed denial the hook saw, in order: (kind code, reason code).
static SEEN_TYPED: Mutex<Vec<(u8, u32)>> = Mutex::new(Vec::new());

fn typed_recorder(kind_code: u8, reason_code: u32) {
    SEEN_TYPED
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .push((kind_code, reason_code));
}

fn arm_typed() {
    SEEN_TYPED.lock().unwrap_or_else(|e| e.into_inner()).clear();
    set_cap_deny_typed_recorder(typed_recorder);
}

fn seen_typed() -> Vec<(u8, u32)> {
    SEEN_TYPED.lock().unwrap_or_else(|e| e.into_inner()).clone()
}

/// A typed refusal reaches the recorder, tagged with the family it was for and
/// why it failed.
///
/// Driven through `errno_for_gpio_err` — the shipping function, since this
/// crate `include!`s `handlers.rs` — because that is the choke point the
/// production path actually takes.
#[test]
fn a_typed_denial_is_recorded_with_its_kind_and_reason() {
    use azos_ipc::cap::CapError;
    use azos_ipc::gpio_cap::GpioCapError;

    let _g = serial();
    arm_typed();

    let _ = errno_for_gpio_err(GpioCapError::Cap(CapError::Stale));
    let _ = errno_for_gpio_err(GpioCapError::Cap(CapError::WrongKind));
    let _ = errno_for_gpio_err(GpioCapError::Cap(CapError::MissingPerms));

    assert_eq!(
        seen_typed(),
        vec![(2, 1), (2, 2), (2, 3)],
        "GPIO must record as kind code 2 — the SAME code the untyped path uses \
         — with one distinct reason per CapError"
    );
}

/// **The one that matters most, and it is a negative.**
///
/// `CapKind::Gpio` is discriminant 8; its recorder code is 2. Writing the
/// discriminant would make every typed GPIO denial decode as an ADC one —
/// silently, in a file whose whole purpose is to be read after the fact, by a
/// build that no longer exists. The codes are the frozen ones the untyped
/// record has always carried, so a recording cannot tell which syscall the
/// program happened to call; `Null` is 0, "no object".
///
/// **Canary.** Make `CapKind::denial_code` return `self as u8`: this test must
/// go red, and `a_typed_denial_is_recorded_with_its_kind_and_reason` with it.
#[test]
fn typed_and_untyped_agree_on_the_frozen_kind_code_for_every_shared_family() {
    use azos_abi::cap::CapKind;

    assert_eq!(CapKind::Null.denial_code(), 0, "Null");
    for (kind, code, _, _) in FROZEN_RECORD_FORMAT {
        assert_eq!(kind.denial_code(), code, "{kind:?} records under a code other than its frozen one");
    }
}

/// No two `CapKind`s share a recorder code — including the eight that have no
/// untyped twin and were appended from 14.
#[test]
fn every_cap_kind_has_its_own_recorder_code() {
    use azos_abi::cap::CapKind;
    let kinds = [
        CapKind::Null, CapKind::Channel, CapKind::Shm, CapKind::Port,
        CapKind::Irq, CapKind::MmioRegion, CapKind::IoRing, CapKind::Sensor,
        CapKind::Gpio, CapKind::I2c, CapKind::Pwm, CapKind::Motor,
        CapKind::File, CapKind::Socket, CapKind::Task, CapKind::AiSession,
        CapKind::Adc, CapKind::Buzzer, CapKind::Power, CapKind::Disk,
        CapKind::NetConfig, CapKind::DriverRegistry,
    ];
    assert_eq!(kinds.len(), 22, "a CapKind variant was added without a code here");
    let mut codes: Vec<u8> = kinds.iter().map(|k| k.denial_code()).collect();
    let total = codes.len();
    codes.sort_unstable();
    codes.dedup();
    assert_eq!(codes.len(), total, "two CapKind variants share a recorder code");
}

/// **Containment is not a denial, and recording it would be net-negative.**
///
/// `CapTable::get` returns `Contained` when degraded mode is armed and the
/// caller asks for WRITE — a refusal aimed at a task that HOLDS the
/// capability. It is the safety system working. Recorded as a denial, one
/// containment episode would bury every real record under thousands of its
/// own, at the exact moment the recording matters most.
///
/// This is new surface, not inherited: `cap_check`'s presence test never
/// consults degraded mode, so the untyped path cannot produce this event at all.
///
/// **Canary.** Delete the `is_denial()` guard in `note_typed_denial`: this
/// must go red while the test above stays green.
#[test]
fn containment_is_not_recorded_as_a_capability_denial() {
    use azos_ipc::cap::CapError;
    use azos_ipc::motor_cap::MotorCapError;

    let _g = serial();
    arm_typed();

    let _ = errno_for_motor_err(MotorCapError::Cap(CapError::Contained));
    assert_eq!(
        seen_typed(),
        vec![],
        "degraded mode refusing a write from a capability HOLDER is not a denial"
    );

    // Positive control on the same family and the same installed hook, so a
    // green above cannot mean "the hook was never armed".
    let _ = errno_for_motor_err(MotorCapError::Cap(CapError::MissingPerms));
    assert_eq!(seen_typed(), vec![(5, 3)], "the hook was not armed");
}

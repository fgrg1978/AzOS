// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// Host tests for the reach of a control write, a sample's bounds and the
// console flush before a reset. The untyped hardware calls were retired in
// RFC-0040 gap 1 and D6; the endpoint ops that replaced them are covered in
// `device_guards.rs`, `motor_guards.rs` and `sensor_guards.rs`.
//
// (The untyped `cap_check` tests of the raw disk calls left with them: the
// partition block is the `block` endpoint, covered in `block_guards.rs`, and
// the table-level properties `cap_check` relies on in `cap_denial_record.rs`.)

use super::harness::serial;
use azos_abi::cap::{CapKind, CapPerms};
use std::sync::atomic::{AtomicU32, Ordering};

/// Hands out TIDs no other test in this file (or elsewhere in the crate)
/// uses, so a table one test filled is never read by another.
static NEXT_TID: AtomicU32 = AtomicU32::new(0x7000_0001);
fn fresh_tid() -> u32 {
    NEXT_TID.fetch_add(1, Ordering::SeqCst)
}

/// The cap-store pool slot every caller in this file is bound to. 22 and 51-57
/// are taken by other files in this crate.
const SLOT: usize = 58;

/// Install `tid` as an unprivileged (`user_pt != 0`) current task with an
/// empty capability table.
///
/// Two task tables: `cap_store` resolves TIDs through `ipc_task_pool`, the
/// handlers ask this crate's `shims/sched` (see `gpio_typed_lock.rs`). No test
/// here copies through a user page table, so a bare non-zero sentinel is
/// enough.
fn as_user(tid: u32) {
    ipc_task_pool::shim_bind(tid, SLOT);
    azos_ipc::cap_store::reset(tid);
    azos_sched::set_current_user_pt(0xBAD0_0000);
    azos_sched::set_current_task_tid(tid);
}

/// Grant `tid` a capability of `kind` for `resource` straight into its table.
fn hold(tid: u32, kind: CapType, resource: u32, perms: CapPerms) {
    assert!(
        azos_ipc::cap_store::with_table(tid, |t| t.grant_raw(kind, perms, resource))
            .flatten()
            .is_some(),
        "could not grant {kind:?} {resource:#x} to {tid:#x}"
    );
}

// ── The reach of a CONTROL write, which is not (in general) the channel it
// names ──────────────────────────────────────────────────────────────────
//
// Stated on the host because no scenario can show it either way. Two
// domains are live: `PWM_DOMAIN_INDEPENDENT_8` (the QEMU/K1 simulation and
// the real JH7110 part, `(8, shared_control = false)`), where the reach IS
// the named channel; and `PWM_DOMAIN_VF2_DRIVER` (`(4, true)`), what a `vf2`
// build gates on because its SiFive-layout driver writes one `PWMCFG` for
// all four channels (owner decisions 2026-09-26, `pwm_domain.rs`).

/// **On an independent-channel domain, a control write named for a free
/// channel reaches no motor.** Motor 0 is on channel 0, the caller names
/// channel 2 or 3. Fails if `PWM_DOMAIN_INDEPENDENT_8` is ever given a
/// shared control register.
#[test]
fn a_control_write_on_a_free_channel_reaches_no_motor_on_independent_hardware() {
    let _g = serial();
    azos_robot::motor::shim_clear_motor_channels();
    azos_robot::motor::shim_bind_motor_channel(0);   // motor 0 -> PWM channel 0

    use azos_drv_actuator::pwm_domain::PWM_DOMAIN_INDEPENDENT_8;

    assert!(
        !pwm_control_reaches_a_motor(PWM_DOMAIN_INDEPENDENT_8, 2),
        "the OpenCores core gives channel 2 its own register block, so a \
         control write named for it cannot change motor 0's timing"
    );
    assert!(
        !pwm_control_reaches_a_motor(PWM_DOMAIN_INDEPENDENT_8, 3),
        "same independence, any channel of the instance"
    );
    azos_robot::motor::shim_clear_motor_channels();
}

/// **On the domain a `vf2` build gates on, a control write named for a free
/// channel DOES reach the motor**, because the SiFive-layout driver writes one
/// `PWMCFG` for all four channels. Uses the live `PWM_DOMAIN_VF2_DRIVER`, so it
/// fails if that constant ever stops describing the shared register while
/// the driver still has one.
#[test]
fn a_control_write_on_a_free_channel_reaches_the_motor_on_the_vf2_driver_domain() {
    let _g = serial();
    azos_robot::motor::shim_clear_motor_channels();
    azos_robot::motor::shim_bind_motor_channel(0);   // motor 0 -> PWM channel 0

    // The live constant a `vf2` build gates on (SiFive-layout driver, one
    // shared PWMCFG), not a synthetic domain.
    use azos_drv_actuator::pwm_domain::PwmDomain;
    const SHARED_TEST_DOMAIN: PwmDomain = azos_drv_actuator::pwm_domain::PWM_DOMAIN_VF2_DRIVER;

    assert!(
        pwm_control_reaches_a_motor(SHARED_TEST_DOMAIN, 2),
        "one shared control register serves all four channels, so a write \
         named for channel 2 changes motor 0's timing"
    );
    assert!(
        pwm_control_reaches_a_motor(SHARED_TEST_DOMAIN, 3),
        "same register, any channel of the instance"
    );
    azos_robot::motor::shim_clear_motor_channels();
}

/// The named channel still counts, on either domain: a control write on the
/// motor's OWN channel is refused whether or not the register is shared.
#[test]
fn a_control_write_on_the_motors_own_channel_is_always_refused() {
    let _g = serial();
    azos_robot::motor::shim_clear_motor_channels();
    azos_robot::motor::shim_bind_motor_channel(0);
    use azos_drv_actuator::pwm_domain::{PWM_DOMAIN_INDEPENDENT_8, PWM_DOMAIN_VF2_DRIVER};
    assert!(pwm_control_reaches_a_motor(PWM_DOMAIN_INDEPENDENT_8, 0));
    assert!(pwm_control_reaches_a_motor(PWM_DOMAIN_VF2_DRIVER, 0));
    azos_robot::motor::shim_clear_motor_channels();
}

/// With no motor bound to any channel, nothing is reached — so the guard
/// refuses because of the BINDING, not because it refuses everything. Without
/// this the two tests above pass on a predicate hard-coded to `true`.
#[test]
fn with_no_motor_bound_a_control_write_reaches_nothing() {
    let _g = serial();
    azos_robot::motor::shim_clear_motor_channels();
    use azos_drv_actuator::pwm_domain::{PWM_DOMAIN_INDEPENDENT_8, PWM_DOMAIN_VF2_DRIVER};
    assert!(!pwm_control_reaches_a_motor(PWM_DOMAIN_INDEPENDENT_8, 2));
    assert!(!pwm_control_reaches_a_motor(PWM_DOMAIN_VF2_DRIVER, 2));
}


// ── A sample bounds itself (owner decision 100) ────────────────────────────

/// **A sample must not out-write the buffer it is copied into, and must not
/// carry more than its reply holds.**
///
/// The sensor write used to take only `(buf_ptr, data)` and copy
/// `data.len()` bytes, so the caller's declared length was enforced solely by
/// the nine per-type `if buf_len < SIZE` checks in `sensor_read_into`: one rule
/// written nine times. The record now travels in a `Sample` of at most
/// `SAMPLE_BYTES` and `copy_to` takes the destination slice, so the bound is
/// the slice's own length: a short buffer gets a prefix (the sample's `len`
/// still says how long the record is), never a write past it.
///
/// **Canary.** Copy `self.len` bytes instead of `min(len, out.len())` in
/// `Sample::copy_to`: the sentinel bytes are overwritten.
#[test]
fn a_sample_never_copies_past_the_callers_buffer() {
    use azos_devif::sensor::{Sample, SAMPLE_BYTES};
    let data = [0xA5u8; 8];
    let s = Sample::new(&data, 0, 0);

    // 8 bytes of destination followed by 8 bytes of sentinel: an over-long
    // write lands in the sentinel, so the test fails on the DAMAGE and not
    // only on the return count.
    let mut dst = [0u8; 16];
    dst[8..].copy_from_slice(&[0x5Au8; 8]);

    // Exactly fits: written, and the bytes land.
    assert_eq!(s.copy_to(&mut dst[..8]), 8);
    assert_eq!(&dst[..8], &data[..], "the fitting copy did not land");
    assert_eq!(&dst[8..], &[0x5Au8; 8], "the fitting copy ran past its own length");

    // A destination shorter than the record: a prefix, and nothing past it.
    for declared in [0usize, 1, 7] {
        let mut probe = [0u8; 16];
        probe[8..].copy_from_slice(&[0x5Au8; 8]);
        assert_eq!(s.copy_to(&mut probe[..declared]), declared, "declared {declared}");
        assert!(probe[declared..8].iter().all(|&b| b == 0), "declared {declared}: bytes past the slice");
        assert_eq!(&probe[8..], &[0x5Au8; 8], "declared {declared}: the sentinel was touched");
    }

    // A buffer larger than the record is fine -- the copy is one-sided.
    let mut big = [0u8; 64];
    assert_eq!(s.copy_to(&mut big), 8);

    // A record longer than a reply holds is cut at SAMPLE_BYTES, and says so.
    let long = [1u8; 100];
    let c = Sample::new(&long, 0, 0);
    assert_eq!(c.len as usize, SAMPLE_BYTES);
}

// ── Console flush before a reset (wave 10) ───────────────────────────────────

/// A reboot or power-off that passed its right first (`Power::reboot`,
/// `Power::shutdown`; the right is `power_guards.rs`'s) puts every deferred
/// kernel console line on the wire (`uart::console_flush_for_reboot`): a
/// line printed just before the reset while ring 3 owned the console used
/// to be lost with the RAM that held it. Kernel context passes the gate
/// (`serial()` leaves `user_pt == 0`); the SBI stand-in then panics, so a
/// recorded flush was made BEFORE the reset call.
///
/// **Canary.** Delete the flush from `reboot_orderly`: the log is empty.
#[test]
fn power_control_flushes_the_console_before_the_reset() {
    let _g = serial();
    let calls: [(&str, fn() -> i64); 2] = [
        ("reboot", || crate::handlers::reboot_orderly()),
        ("shutdown", || crate::handlers::power_off_orderly()),
    ];
    for (name, call) in calls {
        syscall_test_drivers::shim_fwd::arm(Default::default());
        let r = std::panic::catch_unwind(call);
        let log = syscall_test_drivers::shim_fwd::disarm().expect("recorder armed").log;
        assert!(r.is_err(), "{name}: the reset stand-in was not reached");
        assert_eq!(log, vec!["console_flush_for_reboot".to_string()], "{name}");
    }
}

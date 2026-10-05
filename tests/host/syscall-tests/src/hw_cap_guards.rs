// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// Host tests for `cap_check` on the untyped hardware and system calls that
// keep a dispatch arm (`crates/core/syscall/src/handlers.rs`): `sys_i2c_scan` (222),
// `sys_motor_create` (230), `sys_adc_read` (410), `sys_buzzer_*` (420/421),
// `sys_shutdown`/`sys_reboot` (270/271), `sys_disk_read`/`_write` (281/282)
// and `sys_net_setip` (262). The GPIO, PWM, I2C read/write, motor
// enable/speed/angle, sensor and driver-registry calls were retired in
// RFC-0040 gap 1; their typed twins are covered in `gpio_typed_lock.rs`,
// `typed_twin_guards.rs`, `unit6_contain.rs`, `motor_angle_gate.rs` and
// `driver_server_guards.rs`.
//
// **Setup.** `cap_check` answers from the caller's `cap_store` table
// (`holds_kind_resource_uncontained`). Each caller here is bound to one
// task-pool slot (`SLOT`) and granted straight into that table with
// `CapTable::grant_raw`, the kind and resource the handler's check names.
//
// **Isolation.** Every test uses a TID nothing else in the process uses
// (`fresh_tid`). A fresh TID claiming `SLOT` finds an empty table:
// `cap_store` wipes a slot's table when a TID other than its last occupant
// resolves it, and `as_user` resets it besides.
//
// **Observing "admitted" on a host.** Most of these calls reach a `todo!()`
// driver stand-in right after the check, so a refusal is asserted as `E_PERM`
// and an admission is observed only where a real argument check sits between
// the capability check and the driver (`sys_disk_read`'s zero count).
//
// **The seccomp filter is opt-in and self-imposed.** `SyscallFilter::disabled()`
// means allow everything, and a task installs a restrictive profile on itself.
// So "which profile grants this number" is not a defence against a program
// that never restricts itself; `cap_check` is, which is why it is on the first
// line of each handler here.

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
fn hold(tid: u32, kind: CapKind, resource: u32, perms: CapPerms) {
    assert!(
        azos_ipc::cap_store::with_table(tid, |t| t.grant_raw(kind, perms, resource))
            .flatten()
            .is_some(),
        "could not grant {kind:?} {resource:#x} to {tid:#x}"
    );
}

// ── I2C bus scan and motor binding ───────────────────────────────────────────

#[test]
fn i2c_scan_refuses_an_unprivileged_caller_with_no_capability() {
    let _g = serial();
    as_user(fresh_tid());
    assert_eq!(sys_i2c_scan(0), E_PERM);
}

#[test]
fn motor_create_refuses_an_unprivileged_caller_with_no_capability() {
    let _g = serial();
    as_user(fresh_tid());
    assert_eq!(sys_motor_create(0, 0, 1, 2), E_PERM);
}

// The admitted side of `sys_i2c_scan` reaches `i2c_scan` (`todo!()`) with no
// argument check in between; `unit6_contain.rs`'s `i2c_scan_is_not_contained`
// observes it through that panic. `sys_motor_create`'s kernel-caller bind is
// covered there too (`motor_create_is_refused_to_ring3_whatever_it_holds`).

// ── The capability table is the authority (RFC-0040 gap 1, stage 2) ───────

/// **A read needs `READ`.** The handle table asked no read bit; the capability
/// table does, as every typed read does. A WRITE-only `Disk` capability is
/// refused a disk read; the READ one is admitted past the check and stops at
/// the zero-count argument check's `-1`.
///
/// **Canary.** Ask `CapPerms::NONE` for a read in `cap_check`: the WRITE-only
/// line reads `-1`.
#[test]
fn an_untyped_read_needs_a_read_capability() {
    let _g = serial();
    let tid = fresh_tid();
    as_user(tid);
    hold(tid, CapKind::Disk, 0, CapPerms::WRITE);
    assert_eq!(sys_disk_read(0, 0, 0, 0), E_PERM, "a WRITE-only capability opened a read");
    hold(tid, CapKind::Disk, 0, CapPerms::READ);
    assert_eq!(sys_disk_read(0, 0, 0, 0), -1, "the READ capability was refused");
}

/// **The I2C resource is packed as the minter packs it**, `bus << 8 | addr`,
/// with both arguments narrowed to `u8` as the driver call narrows them, so
/// the capability `cap_check` asks for is the one `i2c_grant_cap` mints. The
/// bus scan asks `(bus, 0)`, so a capability for another address on the bus
/// does not open it.
///
/// **Canary.** Pack `addr << 8 | bus` in `i2c_resource`: the first assertion
/// fails.
#[test]
fn the_i2c_resource_is_packed_as_the_minter_packs_it() {
    let _g = serial();
    let tid = fresh_tid();
    as_user(tid);
    let cap = azos_ipc::i2c_cap::i2c_grant_cap(tid, 1, 0x40, CapPerms::RW).expect("capability table full");
    let minted = azos_ipc::cap_store::get(tid, cap, CapPerms::READ).expect("a live capability");

    assert_eq!(i2c_resource(1, 0x40), minted, "the minted (bus, addr) is not the resource the check asks");
    assert_ne!(i2c_resource(0x40, 1), minted, "bus and address swapped name the same resource");
    assert_eq!(i2c_resource(0x101, 0x140), minted, "the check must narrow as the driver call does");
    assert_eq!(sys_i2c_scan(1), E_PERM, "a (1, 0x40) capability opened the scan of bus 1");
}

/// **A TID that names no live task holds nothing**, whatever its slot's table
/// held while it lived.
///
/// **Canary.** `unwrap_or(true)` in `cap_check`: the call reads `-1`.
#[test]
fn a_caller_whose_tid_names_no_task_is_refused() {
    let _g = serial();
    let tid = fresh_tid();
    as_user(tid);
    hold(tid, CapKind::Disk, 0, CapPerms::READ);
    assert_eq!(sys_disk_read(0, 0, 0, 0), -1, "precondition: the live holder is admitted");
    ipc_task_pool::shim_kill(tid);
    assert_eq!(sys_disk_read(0, 0, 0, 0), E_PERM, "a dead TID's table still opened a read");
}

/// Grant `tid` what the topology seeds the autorun task with
/// (`crates/core/topology/src/builder.rs`), `cap-refusal-canary` grants included:
/// the widest table a ring-3 program has in any image.
fn hold_the_autorun_seed(tid: u32) {
    for m in 0..2 {
        hold(tid, CapKind::Motor, m, CapPerms::RW);
    }
    hold(tid, CapKind::DriverRegistry, 1, CapPerms::RW);
    for ch in [4, 0] {
        hold(tid, CapKind::Pwm, ch, CapPerms::RW);
    }
    for pin in [20, 0] {
        hold(tid, CapKind::Gpio, pin, CapPerms::RW);
    }
    hold(tid, CapKind::I2c, 0x0068, CapPerms::READ);
    for st in 0..=9 {
        hold(tid, CapKind::Sensor, st, CapPerms::READ);
    }
}

/// **The kept calls whose kind has no minter stay refused to the widest
/// ring-3 table there is.** Power, disk, network configuration, ADC and the
/// buzzer have no typed minter and no topology name, and the bus scan asks
/// `(bus, 0)` with WRITE, which no seed grants. Each of these returned `E_PERM`
/// to ring 3 under the handle table, and must still. `cap_check` on a seeded
/// sensor is the positive control: the table is live, the refusals are about
/// what it holds.
///
/// **Canary.** Drop `s.kind == kind` from `holds_kind_resource_uncontained`:
/// `sys_shutdown` reaches the SBI stand-in and panics.
#[test]
fn calls_with_no_minter_stay_refused_to_the_whole_autorun_seed() {
    let _g = serial();
    let tid = fresh_tid();
    as_user(tid);
    hold_the_autorun_seed(tid);
    let mut buf = [0u8; 512];

    assert_eq!(sys_shutdown(), E_PERM, "shutdown");
    assert_eq!(sys_reboot(), E_PERM, "reboot");
    assert_eq!(sys_disk_read(0, 1, buf.as_mut_ptr() as u64, 0), E_PERM, "disk read");
    assert_eq!(sys_disk_write(0, 1, buf.as_ptr() as u64, 0), E_PERM, "disk write");
    assert_eq!(sys_net_setip(0x0A00_0001, 0xFFFF_FF00, 0x0A00_00FE), E_PERM, "net_setip");
    assert_eq!(sys_adc_read(0), E_PERM, "adc_read");
    assert_eq!(sys_buzzer_tone(440, 10), E_PERM, "buzzer_tone");
    assert_eq!(sys_buzzer_off(), E_PERM, "buzzer_off");
    assert_eq!(sys_i2c_scan(0), E_PERM, "i2c_scan");
    assert!(cap_check(CapKind::Sensor, 3, false), "the seeded sensor was refused: the table is not live");
}

// ── The unguarded family, now gated ──────────────────────────────────────────

/// The gap this test was written to document, now closed.
///
/// `sys_adc_read` was dispatched to ring 3 and read real hardware with no
/// `cap_check` anywhere in its body. The channel is deliberately out of range:
/// the gate runs BEFORE the range check, so an unauthorised caller cannot learn
/// which channels exist from the difference between `-1` and `E_PERM` — and
/// that ordering is what this test pins.
#[test]
fn adc_read_refuses_a_caller_holding_no_capability() {
    let _g = serial();
    as_user(fresh_tid()); // zero capabilities of any kind held by this tid
    assert_eq!(
        sys_adc_read(99), E_PERM,
        "an unprivileged caller reached past the capability gate. If this reads \
         -1, the gate is running after the range check and an unauthorised \
         caller can map the channel space by probing."
    );
}

// ── System control, disk, network config ─────────────────────────────────────
//
// Added 2026-09-05, after a sweep found handlers reachable from ring 3 with no
// capability check at all. None of them touches an actuator — and every one
// of them is worse.

/// `SYS_SHUTDOWN` and `SYS_REBOOT` had **no gate of any kind**. One `ecall`
/// with a7=270 or 271 from any ring-3 task powered the board off or reset it.
///
/// These two return `!` on success, so a passing test is one where the call
/// RETURNS at all: reaching the SBI call would diverge and never come back.
#[test]
fn power_control_refuses_a_caller_holding_no_capability() {
    let _g = serial();
    as_user(fresh_tid());
    assert_eq!(sys_shutdown(), E_PERM, "an unprivileged task powered the board off");
    assert_eq!(sys_reboot(), E_PERM, "an unprivileged task reset the board");
}

/// Both disk syscalls were bounds-checked and neither was permission-checked.
///
/// The arguments here are deliberately VALID — sector 0, one sector, a
/// plausible buffer — because the bug was never about bad arguments. E_PERM
/// rather than -1 is the assertion that matters: -1 would mean the gate runs
/// after the bounds checks, which lets an unauthorised caller map the medium's
/// geometry by probing for the boundary between the two answers.
#[test]
fn disk_access_refuses_a_caller_holding_no_capability() {
    let _g = serial();
    as_user(fresh_tid());
    let mut buf = [0u8; 512];
    assert_eq!(
        sys_disk_read(0, 1, buf.as_mut_ptr() as u64, 0), E_PERM,
        "an unprivileged task read a disk sector"
    );
    assert_eq!(
        sys_disk_write(0, 1, buf.as_ptr() as u64, 0), E_PERM,
        "an unprivileged task wrote sector 0 — the partition table"
    );
}

/// Readdressing the interface was ungated and unvalidated.
///
/// The local address is dual-sourced (`NET_CFG` and `tcp.rs`), so a silent
/// change can leave TCP checksumming against an address the interface no
/// longer has — on the link that carries the e-stop.
#[test]
fn net_setip_refuses_a_caller_holding_no_capability() {
    let _g = serial();
    as_user(fresh_tid());
    assert_eq!(
        sys_net_setip(0x0A00_0001, 0xFFFF_FF00, 0x0A00_00FE), E_PERM,
        "an unprivileged task readdressed the interface"
    );
}

// ── The actuation gate's other two routes ──────────────────────────────────
//
// The gate (e-stop + motor envelope) lives in `motor_set`. Two other paths
// reach `pwm_set_duty_pct` — the same compare register — one level below it:
// `SYS_DRV_INVOKE`'s PWM driver, and the typed `Cap<Pwm>` family. On a board
// where motors 0 and 1 are PWM channels 0 and 1, either could spin a wheel
// through a latched e-stop.
//
// Owner decision 2026-09-06: close the routes individually rather than move
// the gate down to `pwm_set_duty_pct`. Both refuse a channel an initialised
// motor claims — refuse, not clamp, since these are the raw interfaces and
// the motor calls are the gated ones. The typed half is in
// `typed_twin_guards.rs`.

/// A channel no motor claims is unaffected; one a motor claims is refused.
///
/// Both halves matter. Refusing every channel would break the buzzer, which
/// owns its own PWM channel and is not an actuator the envelope has an opinion
/// about; refusing none is the hole.
#[test]
fn the_raw_pwm_routes_refuse_a_channel_a_motor_claims() {
    // Kernel context deliberately: `serial()` resets `user_pt` to 0, so the
    // handler copies the input with `copy_nonoverlapping` from the raw pointer
    // instead of walking a user page table for a host address. The guard under
    // test does not branch on context — it refuses a motor-bound channel for
    // any caller — so kernel context is the cheapest place to observe it, and
    // it also removes the capability check as a confound: a kernel caller is
    // already authorised, so E_PERM here can only come from this guard.
    let _g = serial();
    azos_robot::motor::shim_clear_motor_channels();

    // `SYS_DRV_INVOKE`, kind = DRV_KIND_PWM (5), channel in input[0..4] LE.
    let free_ch = 5u32.to_le_bytes();
    let motor_ch = 2u32.to_le_bytes();

    // Nothing claims channel 2 yet, so this call fails for its own reasons —
    // no capability, no registered driver — but NOT with E_PERM from the
    // motor guard. Recorded so the assertion below is a change, not a
    // coincidence.
    let before = sys_drv_invoke(5, 4, motor_ch.as_ptr() as u64, 4, 0, 0);

    azos_robot::motor::shim_bind_motor_channel(2);
    assert_eq!(
        sys_drv_invoke(5, 4, motor_ch.as_ptr() as u64, 4, 0, 0), E_PERM,
        "a PWM channel bound to a motor was reachable through SYS_DRV_INVOKE, \
         one level below the e-stop and the motor envelope"
    );
    assert_ne!(
        before, E_PERM,
        "the guard cannot be shown to be doing the work: this call already \
         returned E_PERM before any motor claimed the channel"
    );

    // And a channel no motor claims is still refused for its own reasons, not
    // this one — same return as before the binding.
    assert_eq!(
        sys_drv_invoke(5, 4, free_ch.as_ptr() as u64, 4, 0, 0), before,
        "binding channel 2 changed the answer for channel 5"
    );

    azos_robot::motor::shim_clear_motor_channels();
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


// ── The sensor write bounds itself (owner decision 100) ────────────────────

/// **A sink must not out-write the buffer it was given.**
///
/// `sensor_write_to_user` used to take only `(buf_ptr, data)` and copy
/// `data.len()` bytes, so the caller's declared length was enforced solely by
/// the nine per-type `if buf_len < SIZE` checks in `sensor_read_into`. All
/// nine were present — the defect was structural, not live: one rule written
/// nine times, and a tenth sensor type added without it would write past the
/// caller's buffer through `copy_to_user`, which validates PAGES and not the
/// declared length.
///
/// It refuses rather than truncates: a sensor reading silently cut in half is
/// worse than an error, because the caller cannot tell it happened.
///
/// Driven through the KERNEL-caller branch (`current_user_pt() == 0`), which
/// copies straight to `buf_ptr` — so the destination is a local array and this
/// test needs no page table. The bound being tested runs before that branch is
/// chosen, so it is the same check either way.
///
/// **Canary.** Delete the `data.len() as u64 > buf_len` arm: every over-long
/// case below returns the byte count instead of -1, and the guard bytes are
/// overwritten.
#[test]
fn the_sensor_write_refuses_data_longer_than_the_callers_buffer() {
    let _g = serial();
    azos_sched::set_current_user_pt(0);

    let data = [0xA5u8; 8];
    // 8 bytes of destination followed by 8 bytes of sentinel: an over-long
    // write lands in the sentinel, so the test fails on the DAMAGE and not
    // only on the return code.
    let mut dst = [0u8; 16];
    dst[8..].copy_from_slice(&[0x5Au8; 8]);
    let ptr = dst.as_mut_ptr() as u64;

    // Exactly fits: written, and the bytes land.
    assert_eq!(super::sensor_write_to_user(ptr, 8, &data), 8);
    assert_eq!(&dst[..8], &data[..], "the fitting write did not land");
    assert_eq!(&dst[8..], &[0x5Au8; 8], "the fitting write ran past its own length");

    // Declared shorter than the data: refused, and nothing is written.
    for declared in [0u64, 1, 7] {
        let mut probe = [0u8; 16];
        probe[8..].copy_from_slice(&[0x5Au8; 8]);
        let pp = probe.as_mut_ptr() as u64;
        assert_eq!(
            super::sensor_write_to_user(pp, declared, &data),
            -1,
            "8 bytes into a buffer declared {declared} must be refused",
        );
        assert_eq!(
            &probe[..], &[0u8, 0, 0, 0, 0, 0, 0, 0, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A][..],
            "a refused write still touched the buffer (declared {declared})",
        );
    }

    // A buffer larger than the data is fine — the check is one-sided.
    assert_eq!(super::sensor_write_to_user(ptr, 4096, &data), 8);
}

// ── Console flush before a reset (wave 10) ───────────────────────────────────

/// A reboot or power-off that passes the gate first puts every deferred
/// kernel console line on the wire (`uart::console_flush_for_reboot`): a
/// line printed just before the reset while ring 3 owned the console used
/// to be lost with the RAM that held it. Kernel context passes the gate
/// (`serial()` leaves `user_pt == 0`); the SBI stand-in then panics, so a
/// recorded flush was made BEFORE the reset call.
///
/// **Canary.** Delete the flush from `sys_reboot`: the log is empty.
/// Move it above the `cap_check`: the unprivileged-caller tests above reach
/// the unarmed recorder's `todo!()` and fail.
#[test]
fn power_control_flushes_the_console_before_the_reset() {
    let _g = serial();
    let calls: [(&str, fn() -> i64); 2] = [("reboot", sys_reboot), ("shutdown", sys_shutdown)];
    for (name, call) in calls {
        syscall_test_drivers::shim_fwd::arm(Default::default());
        let r = std::panic::catch_unwind(call);
        let log = syscall_test_drivers::shim_fwd::disarm().expect("recorder armed").log;
        assert!(r.is_err(), "{name}: the reset stand-in was not reached");
        assert_eq!(log, vec!["console_flush_for_reboot".to_string()], "{name}");
    }
}

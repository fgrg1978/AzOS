// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Which resource does a driver call actually reach?
//!
//! Pure decoding, no dependencies, so `tests/host/drivers-tests` can pull it in
//! with `#[path]` and no shim — the same arrangement as `pwm_domain`. The
//! `Driver::request_resource` implementations are one-line delegations to
//! these, because the driver files themselves name hardware modules that a
//! host test cannot compile.
//!
//! # What this is for
//!
//! `SYS_DRV_INVOKE` authorised a caller with `CapTable::holds_kind_with`,
//! which compares the capability's KIND and permissions and **never its
//! resource index**. Drivers decode a resource out of the caller's own
//! payload, so a task holding `Cap<Gpio>(5)` reached pin 40 through the driver
//! bridge, while `sys_gpio_write` next door checked the pin correctly.
//! `GpioDriver` is registered at boot: that one was live.
//!
//! # The rule these functions follow
//!
//! Report the resource the hardware write **lands on**, not the one the caller
//! named. Where an op reaches more than one resource — a shared enable bit, a
//! shared clock divider — return `None` rather than the named one. `None`
//! falls back to the kind-wide check, which is weaker but honest; returning
//! the named index would authorise a narrow claim for a wide write, which is
//! the failure this module exists to prevent.

/// Every GPIO op carries its pin as `u32` little-endian in `input[0..4]`, and
/// `Cap<Gpio>`'s resource IS the pin number, so the mapping is the identity.
///
/// A payload too short to carry a pin returns `None`, which denies rather than
/// guesses: `handle_request` rejects it a moment later anyway, and authorising
/// on an index decoded from bytes we are about to call malformed is the wrong
/// order.
#[inline]
pub fn gpio_request_resource(input: &[u8]) -> Option<u32> {
    if input.len() < 4 {
        return None;
    }
    Some(u32::from_le_bytes([input[0], input[1], input[2], input[3]]))
}

/// `Cap<I2c>`'s resource packs `bus << 8 | addr` (see `ipc::i2c_cap`), and the
/// header this driver decodes carries both in that order.
///
/// The packing is restated here rather than imported because the driver crates
/// must not depend on `crates/core/ipc`. Getting it wrong would not fail loudly —
/// the comparison would simply never match, and a gate that always refuses
/// looks like a working gate until something legitimate is denied. Hence the
/// test that pins the exact encoding.
#[inline]
pub fn i2c_request_resource(input: &[u8]) -> Option<u32> {
    if input.len() < 2 {
        return None;
    }
    Some(((input[0] as u32) << 8) | input[1] as u32)
}

/// PWM ops, split by what they actually reach.
///
/// `enable`, `disable` and `set_period` touch bits that are instance-wide on
/// vf2 — `PWMCFG`'s enable bit and its scale field — so an op naming channel 2
/// reaches 0, 1 and 3 as well. Those return `None` and are gated separately by
/// `pwm_domain::pwm_control_allowed`, which demands the caller hold every
/// channel reached.
///
/// The duty ops write the per-channel `PWMCMP` and are genuinely narrow.
///
/// `op` values are the `PWM_OP_*` constants in `pwm_driver`; they are matched
/// numerically here to keep this module free of that file's imports, and the
/// caller passes them straight through.
#[inline]
pub fn pwm_request_resource(op: u32, input: &[u8]) -> Option<u32> {
    const PWM_OP_SET_DUTY: u32 = 3;
    const PWM_OP_SET_DUTY_PCT: u32 = 4;
    match op {
        PWM_OP_SET_DUTY | PWM_OP_SET_DUTY_PCT => {
            if input.len() < 4 {
                return None;
            }
            Some(u32::from_le_bytes([input[0], input[1], input[2], input[3]]))
        }
        _ => None,
    }
}


// ── Motor PID: which bridge ops command the drivetrain ─────────────────────

/// Does this `DRV_KIND_MOTOR_PID` op need WRITE on BOTH wheels?
///
/// The PID driver's ops act on the whole differential pair — the input
/// carries a left/right target, not a motor id — so `request_resource`
/// returns `None` for all of them and the bridge falls back to a kind-wide
/// check. That check is resource-blind: a task holding `Cap<Motor>(0)` alone
/// passed it and then drove both wheels. `motor_driver.rs`'s own comment says
/// so in as many words.
///
/// This is the predicate that closes it, and it exists as a pure function
/// because the alternative — testing it through `drv_invoke_authorized` —
/// needs a `&'static dyn Driver` the host shims do not provide. Same idiom,
/// and the same reason, as `pwm_control_allowed` next door.
///
/// **`MOTOR_OP_ENABLED` (3) is excluded, and that is not an oversight.** Its
/// typed twin `SYS_MOTOR_ENABLED_TYPED` (553) is documented as READ-only and
/// explicitly NOT pair-wide, and its handler takes the `READ` path with no
/// pair call. Including it here would make the bridge STRICTER than the typed
/// syscall it mirrors — a new divergence introduced while closing one. The
/// point of this function is that the two paths agree.
///
/// Numbers rather than the `MOTOR_OP_*` constants: this module is
/// dependency-free by design (see the file header) and `motor_driver.rs`
/// pulls in the PID driver. `tests/host/drivers-tests` asserts the two agree.
pub const fn motor_bridge_op_needs_pair(op: u32) -> bool {
    matches!(op, 0 | 1 | 2 | 4 | 5)
}

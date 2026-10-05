// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Cap<Gpio> typed wrappers — RFC-0003 W5 batch 5.1.
//!
//! Unlike Channel/Port/Shm/IoRing (which are *created* by user
//! syscalls), GPIO pins are physical resources that already
//! exist on the board. There is no `gpio_create_cap` syscall —
//! the topology loader (RFC-0005) grants `Cap<Gpio>(pin)` to
//! the task that owns the pin during boot. Userspace only sees
//! the per-op syscalls below; the grant is privileged.
//!
//! ## Why the pin operations are not here
//!
//! This module used to call `azos_drv_gpio::gpio::{gpio_read, gpio_write,
//! gpio_set_direction}` directly. Its callers reach it through
//! `crate::cap_store::with_table`, which holds `CAP_TABLES[slot].lock()` for
//! the whole closure — and `SpinLock::lock` disables preemption before it
//! spins (`crates/core/sync/src/spinlock.rs`; the guard carries the
//! `PreemptGuard`). So the driver transfer ran with preemption off, and it
//! also nested a second lock inside the first: both GPIO backends take one of
//! their own (`crates/drivers/gpio/src/gpio.rs:38` for the QEMU simulation,
//! `crates/drivers/gpio/src/gpio.rs:151` for the JH7110 MMIO read-modify-write).
//! On a machine whose actuation deadlines are the product, a hardware
//! transfer inside a preemption-off window is a latency hole, and a lock
//! order that only exists because of where a call was written is a hazard
//! nobody chose.
//!
//! So this module now holds the mint and the **dereference** — pure,
//! dependency-light, host-testable — and the driver call lives in
//! `crates/core/syscall/src/handlers.rs`, which runs it *after* `with_table` has
//! returned and the table lock has been dropped. Same split, and the same
//! reason, as `sensor_cap.rs` and `drvreg_cap.rs`.
//!
//! Still lives in `crates/core/ipc/` (not `crates/drivers/gpio/`) because
//! `drivers → ipc` would create a Cargo dependency cycle. The remaining
//! `azos_drv_gpio` reference is [`GPIO_MAX_PINS`], a constant.

use crate::cap::{Cap, CapError, CapPerms, CapTable};
use azos_drv_gpio::gpio::GPIO_MAX_PINS;

/// Errors returned by the typed GPIO path.
///
/// The whole enum stays here, including the two variants this module no
/// longer constructs ([`GpioCapError::DriverFault`] and
/// [`GpioCapError::BadDirValue`], now raised by the handler that owns the
/// driver call). `errno_for_gpio_err` in `crates/core/syscall/src/handlers.rs` is
/// the single choke point where a GPIO refusal becomes an errno *and* reaches
/// the flight recorder via `note_typed_denial`; keeping one error type means
/// every refusal on this path still goes through it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum GpioCapError {
    /// Capability dereference failed (stale / wrong kind / missing perms /
    /// RFC-0036 containment).
    Cap(CapError),
    /// Resource ID stored in the cap is out of [`GPIO_MAX_PINS`] range —
    /// indicates a corrupt cap-table or a wrongly-granted slot.
    BadPin,
    /// Underlying driver rejected the operation (pin invalid / not
    /// configured for the requested direction).
    DriverFault,
    /// `set_dir` got a value other than 0 (input) or 1 (output).
    BadDirValue,
}

impl From<CapError> for GpioCapError {
    fn from(e: CapError) -> Self {
        Self::Cap(e)
    }
}

/// Topology-loader entry: grant `tid` a `Cap<Gpio>` for `pin`.
/// `perms` controls whether the holder may read (`READ`), write
/// (`WRITE`), or set direction (encoded as `WRITE` — direction
/// changes ARE writes from a capability standpoint).
///
/// Returns `None` if `tid` or `pin` is invalid, or the cap-table
/// is full.
pub fn gpio_grant_cap(
    tid: u32,
    pin: u32,
    perms: CapPerms,
) -> Option<Cap<crate::cap::targets::Gpio>> {
    if (pin as usize) >= GPIO_MAX_PINS {
        return None;
    }
    crate::cap_store::grant::<crate::cap::targets::Gpio>(tid, perms, pin)
}

/// Dereference a `Cap<Gpio>` to the pin it names, demanding `need`.
///
/// The range check is deliberately on this side of the table lock, with the
/// dereference, and the reason is the **errno**, not layering. Both GPIO
/// backends already reject an out-of-range pin themselves
/// (`crates/drivers/gpio/src/gpio.rs:43`/`51`/`58` for the simulation,
/// `:175`/`:188`/`:194` for the JH7110 MMIO path), so moving the check out to
/// the driver call site would still fail closed — but it would answer `EIO`
/// (`DriverFault`) where the caller used to get `EINVAL` (`BadPin`). Keeping
/// it here keeps the ABI identical, and it makes this function total: what it
/// returns is always a pin the driver will accept, so the outside half never
/// has to re-reason about it.
///
/// Private so that the per-operation permission cannot be chosen by a caller;
/// the two wrappers below are the only ways in.
fn gpio_pin_of(
    table: &CapTable,
    cap: Cap<crate::cap::targets::Gpio>,
    need: CapPerms,
) -> Result<u32, GpioCapError> {
    let pin = table.get(cap, need)?;
    if (pin as usize) >= GPIO_MAX_PINS {
        return Err(GpioCapError::BadPin);
    }
    Ok(pin)
}

/// Resolve the pin for a **read**: requires `READ`.
pub fn gpio_pin_for_read(
    table: &CapTable,
    cap: Cap<crate::cap::targets::Gpio>,
) -> Result<u32, GpioCapError> {
    gpio_pin_of(table, cap, CapPerms::READ)
}

/// Resolve the pin for a **write or a direction change**: requires `WRITE`.
///
/// One function for both operations, not two, because they demand the same
/// permission and always have — a direction change is a write from a
/// capability standpoint (see [`gpio_grant_cap`]). Sharing the resolver
/// leaves exactly one place where that could ever be weakened, the way
/// `pwm_cap.rs`'s `resolve_channel` does for its five operations.
pub fn gpio_pin_for_write(
    table: &CapTable,
    cap: Cap<crate::cap::targets::Gpio>,
) -> Result<u32, GpioCapError> {
    gpio_pin_of(table, cap, CapPerms::WRITE)
}

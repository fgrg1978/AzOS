// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Cap<Pwm> typed wrappers — RFC-0003 W5 batch 5.3.
//!
//! `Cap<Pwm>` identifies one PWM channel. The `resource_id` is
//! the channel number directly (0..[`PWM_MAX_CHANNELS`]).

use crate::cap::{Cap, CapError, CapPerms, CapTable};
use azos_drv_actuator::pwm::PWM_MAX_CHANNELS;

/// Errors returned by the typed `pwm_*_cap` functions.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PwmCapError {
    Cap(CapError),
    BadChannel,
    DriverFault,
}

impl From<CapError> for PwmCapError {
    fn from(e: CapError) -> Self {
        Self::Cap(e)
    }
}

/// Topology-loader entry: grant `tid` a `Cap<Pwm>` for `channel`.
pub fn pwm_grant_cap(
    tid: u32,
    channel: u32,
    perms: CapPerms,
) -> Option<Cap<crate::cap::targets::Pwm>> {
    // Bound by the DOMAIN this build drives, not by the simulator's array.
    //
    // `PWM_MAX_CHANNELS` is 8 — the size of the in-memory `sim` backend. The
    // VF2 driver programs FOUR (`PWM_DOMAIN_VF2_DRIVER`), so on a board build this used to
    // mint capabilities for channels 4-7 that no register backs: the cap was
    // grantable, every operation on it returned -1, and the topology's
    // "free channel" was `pwm.4` — meaningless on the hardware it was chosen
    // for. Found by audit 2026-09-11.
    if channel >= azos_drv_actuator::pwm_domain::PWM_DOMAIN.channels {
        return None;
    }
    crate::cap_store::grant::<crate::cap::targets::Pwm>(tid, perms, channel)
}

/// Resolve a `Cap<Pwm>` to its channel, requiring `WRITE` (every PWM op
/// writes — enable/disable/period/duty are all actuation, the same rule
/// `gpio_cap::gpio_pin_for_write` states for GPIO).
///
/// **U03-4: resolve only — call the driver AFTER the cap-table lock is
/// released.** This used to be paired 1:1 with a driver call inside the same
/// function (`pwm_enable_cap`, `pwm_disable_cap`, ... each did
/// `resolve_channel` then called into `azos_drv_actuator::pwm` before
/// returning), and the caller (`crates/core/syscall/src/handlers.rs`'s
/// `sys_pwm_dispatch_inner`) ran that whole function inside
/// `cap_store::with_table` — a hardware MMIO read-modify-write (or the sim
/// backend's own lock) under a `SpinLock` guard that disables preemption.
/// `gpio_cap.rs` moved its driver call out from under the table lock for the
/// same reason; this follows it. The caller now does: resolve through this
/// function under the lock, drop the lock, then call the driver directly.
pub fn pwm_channel_for_write(
    table: &CapTable,
    cap: Cap<crate::cap::targets::Pwm>,
) -> Result<u32, PwmCapError> {
    let ch = table.get(cap, CapPerms::WRITE)?;
    if (ch as usize) >= PWM_MAX_CHANNELS {
        return Err(PwmCapError::BadChannel);
    }
    Ok(ch)
}

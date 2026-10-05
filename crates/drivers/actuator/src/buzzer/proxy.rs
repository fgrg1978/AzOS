// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Buzzer, ring-3 placement — the kernel's client of the ring-3 buzzer
//! driver (Kconfig `DRV_BUZZER_PLACEMENT = ring3`, the default).
//!
//! The driver is `userspace/drivers/buzz_drv` (`BUZZDRV.ELF`), started at boot with
//! its own topology row; RFC-0040 places the buzzer in user space (rule 3: a
//! bounded, recoverable failure, and no safety decision reads it). What stays
//! here is the call: each function below is one [`UserDriverProxy`] request,
//! answered before the sound finishes — the driver plays tones and patterns
//! against its own clock, so no caller waits for a melody (the in-kernel
//! driver busy-waited for the whole tone, up to 10 s inside `SYS_BUZZER_TONE`).
//!
//! No driver registered (a volume without `BUZZDRV.ELF`, or the driver
//! exited): the request is refused at submit, without waiting, and the call
//! returns `false`. The in-kernel driver was silent in that case too — its
//! `buzzer_init` had no caller.
//!
//! Blocks the caller for the reply: never call from an interrupt handler or
//! with a lock held (the proxy then refuses and nothing is played).

use azos_drv_api::{DriverIsolation, DriverManifest};
use azos_drv_sys::user_driver_proxy::UserDriverProxy;
use azos_abi::cap::CapPerms;
use azos_abi::drv_kind::{buzzer_op, DRV_KIND_BUZZER};

static PROXY: UserDriverProxy = UserDriverProxy::new(DriverManifest::new(
    DRV_KIND_BUZZER,
    "buzzer-user",
    // Routing is by kind; the TID is informational.
    DriverIsolation::UserProcess { tid: 0 },
    CapPerms::RW,
));

/// One request; `true` when the driver answered and its PWM writes were
/// accepted (reply byte 0).
fn call(op: u32, input: &[u8]) -> bool {
    let mut out = [0u8; 1];
    matches!(PROXY.call(op, input, &mut out), Ok(1)) && out[0] == 1
}

/// Is a ring-3 buzzer driver registered?
pub fn buzzer_driver_tid() -> Option<u32> {
    azos_driver_server::driver_owner_tid(DRV_KIND_BUZZER)
}

/// Play `freq_hz` for `duration_ms`. Returns once the tone has STARTED.
pub fn buzzer_tone(freq_hz: u16, duration_ms: u32) -> bool {
    let f = freq_hz.to_le_bytes();
    let d = duration_ms.to_le_bytes();
    call(buzzer_op::TONE, &[f[0], f[1], d[0], d[1], d[2], d[3]])
}

/// Start a continuous tone; `0` stops.
pub fn buzzer_on(freq_hz: u16) -> bool {
    call(buzzer_op::ON, &freq_hz.to_le_bytes())
}

/// Stop whatever is playing.
pub fn buzzer_off() -> bool {
    call(buzzer_op::OFF, &[])
}

/// A 100 ms beep at `TONE_OK`.
pub fn buzzer_beep() -> bool {
    call(buzzer_op::BEEP, &[])
}

/// Three 80 ms beeps at `TONE_ALERT`, 60 ms apart.
pub fn buzzer_alert() -> bool {
    call(buzzer_op::ALERT, &[])
}

/// C4 - E4 - G4 - C5.
pub fn buzzer_startup() -> bool {
    call(buzzer_op::STARTUP, &[])
}

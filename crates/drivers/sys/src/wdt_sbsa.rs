// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The Arm SBSA Generic Watchdog (Kconfig `WDT_SBSA`): the register logic,
//! over two frames the caller maps. `wdt.rs` holds the windows and hands this
//! module to the system watchdog.
//!
//! Found as a device-tree node `arm,sbsa-gwdt` whose `reg` is the control
//! frame first and the refresh frame second (Linux `sbsa_gwdt.c`:
//! platform resources 0 and 1). The ACPI description (GTDT watchdog entries)
//! needs an aarch64 ACPI table walk the kernel does not have yet.
//!
//! **Two stages, one reset.** The counter compares the system counter
//! against `WCV`; an expiry raises WS0 and reloads `WCV` with `WOR` more
//! ticks, and a second expiry without a refresh raises WS1, which the
//! platform wires to its reset. Nothing here takes the WS0 interrupt, so the
//! reset comes two `WOR` periods after the last refresh: `WOR` is half the
//! timeout (Linux's single-stage mode, `action=0`, the default).
//!
//! **The counter runs at the system counter's rate**, `CNTFRQ_EL0`, read
//! live by the caller (`timebase::freq`), never the Kconfig `TIMER_FREQ`.
//!
//! Control frame:
//!
//! ```text
//! 0x000  WCS     bit 0 EN, bit 1 WS0, bit 2 WS1 (status)
//! 0x008  WOR     offset: 32 bits (architecture version 0), 48 bits over
//!                0x008/0x00C (version 1, low word first); a write refreshes
//! 0xFCC  W_IIDR  bits 19:16 the architecture version
//! ```
//!
//! Refresh frame: `0x000 WRR`, any write refreshes.

/// The two frames of one watchdog.
pub trait Frames {
    fn ctrl_read32(&self, off: usize) -> u32;
    fn ctrl_write32(&self, off: usize, val: u32);
    fn refresh_write32(&self, off: usize, val: u32);
}

pub const WCS: usize = 0x000;
pub const WOR: usize = 0x008;
pub const W_IIDR: usize = 0xFCC;
pub const WRR: usize = 0x000;

pub const WCS_EN: u32 = 1 << 0;

/// The smallest window either frame must have: `W_IIDR` sits at 0xFCC.
pub const FRAME_BYTES: u64 = 0x1000;

/// The architecture version (`W_IIDR` bits 19:16): 0 has a 32-bit `WOR`,
/// 1 and later a 48-bit one.
pub fn version(f: &impl Frames) -> u32 {
    (f.ctrl_read32(W_IIDR) >> 16) & 0xF
}

/// The largest `WOR` the version holds.
pub const fn wor_max(version: u32) -> u64 {
    if version == 0 { u32::MAX as u64 } else { (1 << 48) - 1 }
}

/// `WOR` for a reset `timeout_ms` after the last refresh at `cntfrq` Hz
/// (half the timeout, see the module note), and the timeout that `WOR`
/// actually gives, ms: the request clamped to what the version's `WOR` can
/// hold. At least one tick.
pub fn wor_for_ms(timeout_ms: u32, cntfrq: u64, version: u32) -> (u64, u32) {
    let max = wor_max(version);
    let wor = (cntfrq.saturating_mul(timeout_ms as u64) / 2000).clamp(1, max);
    let armed = (wor.saturating_mul(2000) / cntfrq.max(1)).min(u32::MAX as u64) as u32;
    (wor, armed)
}

/// Arm: stop, load `WOR` (which refreshes), refresh, enable.
pub fn arm(f: &impl Frames, wor: u64, version: u32) {
    f.ctrl_write32(WCS, 0);
    f.ctrl_write32(WOR, wor as u32);
    if version != 0 {
        f.ctrl_write32(WOR + 4, (wor >> 32) as u32);
    }
    f.refresh_write32(WRR, 0);
    f.ctrl_write32(WCS, WCS_EN);
}

/// Refresh: the counter starts a new first stage.
pub fn kick(f: &impl Frames) {
    f.refresh_write32(WRR, 0);
}

/// Stop the counter.
pub fn disarm(f: &impl Frames) {
    f.ctrl_write32(WCS, 0);
}

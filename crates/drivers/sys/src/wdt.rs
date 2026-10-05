// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Hardware watchdog timer driver — Phase D.
//!
//! # Platform mapping
//!
//! | Platform | Hardware | Base address | Kick sequence |
//! |----------|----------|--------------|---------------|
//! | QEMU     | none (soft only) | — | no-op |
//! | VF2 (JH7110) | `starfive,jh7110-wdt` (WDT-L, NOT DesignWare) | `0x1307_0000` | unlock → `INTCLR=1` → lock |
//! | K1 (SpacemiT) | **none** — no watchdog node anywhere in mainline `k1.dtsi` | — | [`wdt_has_hardware`] is `false` |
//!
//! **U05-3 correction (2026-09-26).** This file used to model a Synopsys
//! DesignWare WDT (`CR`/`TORR`/`CCVR`/`CRR`) at `platform::hw::WDT_BASE`,
//! which the header above claimed was `0x1301_0000`. Nothing at that
//! address is a watchdog: mainline `jh7110.dtsi` has no node there at all.
//! The real device is `watchdog@13070000`, `compatible =
//! "starfive,jh7110-wdt"` — a different IP (StarFive's own "WDT-L"), with a
//! different register map (`LOAD`/`VALUE`/`CONTROL`/`INTCLR`/`LOCK`, a
//! lock/unlock gate, and a plain tick-count `LOAD` register instead of a
//! `TOP`-exponent timeout scale), confirmed against Linux mainline
//! `drivers/watchdog/starfive-wdt.c`'s `starfive_wdt_jh7110_variant`. Every
//! `wdt_init`/`wdt_kick`/`wdt_disable` call before this fix wrote to an
//! address with no watchdog behind it: the DW-WDT sequence below armed
//! nothing, and `wdt_has_hardware()` claimed a real watchdog `crates/
//! core/actuation/src/watchdog.rs`'s boot-loop protection depends on.
//!
//! K1 has no watchdog node in mainline `k1.dtsi` at all (`0xD401_5000`,
//! this file's old K1 target, is `syscon_apbc`, not a WDT — see
//! `platform.rs::hw::WDT_BASE`'s K1 doc). [`wdt_has_hardware`] now says so
//! honestly instead of arming the same (wrong) DW-WDT sequence against that
//! address.
//!
//! ## Usage
//!
//! ```text
//! // Boot:
//! wdt_init(WDT_TIMEOUT_MS);   // configure & start watchdog
//!
//! // In RT tick handler (~1 ms):
//! wdt_kick();                  // reset the counter before timeout
//!
//! // Watchdog fires if wdt_kick() is not called within WDT_TIMEOUT_MS.
//! ```
//!
//! ## WDT-L register map (VF2 only — see [`wdt_has_hardware`] for K1)
//!
//! All registers are 32-bit, base from `platform::hw::WDT_BASE`. Confirmed
//! against `drivers/watchdog/starfive-wdt.c`'s JH7110 variant, 2026-09-26.
//!
//! ```text
//! 0x000  LOAD    — down-counter reload value: ticks = timeout_s * WDT_CLK_HZ
//! 0x004  VALUE   — current counter value (read-only)
//! 0x008  CONTROL — bit0 = EN, bit1 = RST_EN (reset-on-timeout)
//! 0x00C  INTCLR  — write 1 to clear the interrupt AND reload the counter
//! 0xC00  LOCK    — write UNLOCK_KEY (0x1ACC_E551) to unlock registers
//!                  above for one access window; write !UNLOCK_KEY to
//!                  re-lock. Every write to LOAD/CONTROL/INTCLR must sit
//!                  between an unlock and a lock.
//! ```

#![allow(dead_code)]

const WDT_LOAD:    usize = 0x000;
const WDT_VALUE:   usize = 0x004;
const WDT_CONTROL: usize = 0x008;
const WDT_INTCLR:  usize = 0x00C;
const WDT_LOCK:    usize = 0xC00;

const WDT_CTRL_EN:      u32 = 1 << 0;
const WDT_CTRL_RST_EN:  u32 = 1 << 1;
const WDT_UNLOCK_KEY:   u32 = 0x1ACC_E551;

/// Pure arithmetic, host-tested (see the bottom of this file):
/// `starfive_wdt_lock` writes the bitwise NOT of the unlock key to re-lock —
/// confirmed against `starfive-wdt.c`'s `writel(~wdt->variant->unlock_key,
/// ...)`. Any other post-unlock write is documented nowhere as re-locking,
/// so this is the one value this driver may write to `WDT_LOCK` to close
/// the access window.
#[inline(always)]
const fn wdt_lock_value() -> u32 {
    !WDT_UNLOCK_KEY
}

// ── MMIO helpers ──────────────────────────────────────────────────────────────

#[inline(always)]
#[cfg(any(feature = "vf2", feature = "k1"))]
fn rd32(base: usize, off: usize) -> u32 {
    unsafe { core::ptr::read_volatile((base + off) as *const u32) }
}

#[inline(always)]
#[cfg(any(feature = "vf2", feature = "k1"))]
fn wr32(base: usize, off: usize, val: u32) {
    unsafe { core::ptr::write_volatile((base + off) as *mut u32, val) }
}

#[cfg(feature = "vf2")]
#[inline(always)]
fn wdt_unlock(base: usize) {
    wr32(base, WDT_LOCK, WDT_UNLOCK_KEY);
}

#[cfg(feature = "vf2")]
#[inline(always)]
fn wdt_lock(base: usize) {
    wr32(base, WDT_LOCK, wdt_lock_value());
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Initialise the hardware watchdog with the given timeout in milliseconds.
///
/// On QEMU and K1 (no hardware WDT — see [`wdt_has_hardware`]) this is a
/// no-op; the software watchdog in the kernel scheduler provides equivalent
/// protection.
pub fn wdt_init(timeout_ms: u32) {
    #[cfg(feature = "vf2")]
    hw_wdt_init(timeout_ms);
    if wdt_has_hardware() || cfg!(feature = "wdt-sim") {
        ARMED_MS.store(timeout_ms, Ordering::Release);
    }
}

/// The timeout of the armed watchdog, ms; 0 while none is armed (QEMU, K1,
/// before [`wdt_init`], after [`wdt_disable`]). `timebase` derives hart 0's
/// idle keepalive from it: with nothing armed an idle hart 0 takes no
/// periodic interrupt. Feature `wdt-sim` (gate row only) records the timeout
/// on a machine with no watchdog, so QEMU can show the keepalive.
static ARMED_MS: AtomicU32 = AtomicU32::new(0);

/// See [`ARMED_MS`].
#[inline]
pub fn armed_timeout_ms() -> u32 {
    ARMED_MS.load(Ordering::Acquire)
}

/// Kick (restart) the watchdog counter.
///
/// Call from the real-time tick handler at ≤ `timeout_ms / 2` intervals.
#[inline(always)]
pub fn wdt_kick() {
    #[cfg(feature = "vf2")]
    hw_wdt_kick();
}

/// Disable the watchdog (use only during graceful shutdown).
pub fn wdt_disable() {
    #[cfg(feature = "vf2")]
    hw_wdt_disable();
    ARMED_MS.store(0, Ordering::Release);
}

/// Returns true if the platform has a hardware watchdog this driver can
/// actually arm.
///
/// **K1 corrected 2026-09-26 (U05-3): always `false`.** Mainline `k1.dtsi`
/// has no watchdog node at all (`grep -i "watchdog\|wdt" k1.dtsi` → no
/// match) — the address this file used to arm under `feature = "k1"`
/// (`platform::hw::WDT_BASE`, `0xD401_5000`) is `syscon_apbc`, an unrelated
/// system controller. Claiming hardware that does not exist is worse than
/// claiming none: `crates/core/actuation/src/watchdog.rs`'s boot-loop
/// protection would otherwise trust a kick that reaches nothing.
pub const fn wdt_has_hardware() -> bool {
    cfg!(feature = "vf2")
}

// ── StarFive WDT-L implementation (VF2 only — see `wdt_has_hardware`) ───────

#[cfg(feature = "vf2")]
fn hw_wdt_init(timeout_ms: u32) {
    let base = azos_drv_base::platform::hw::WDT_BASE;
    let count = wdt_count_for_ms(timeout_ms, azos_drv_base::platform::hw::WDT_CLK_HZ);
    LAST_TIMEOUT_MS.store(timeout_ms, Ordering::Relaxed);

    wdt_unlock(base);
    // Disable first so we can safely reconfigure (starfive_wdt_start does
    // the same: unlock, disable, enable_reset, clear int, set count, enable).
    let ctrl = rd32(base, WDT_CONTROL) & !WDT_CTRL_EN;
    wr32(base, WDT_CONTROL, ctrl | WDT_CTRL_RST_EN);
    wr32(base, WDT_INTCLR, 1);
    wr32(base, WDT_LOAD, count);
    let ctrl = rd32(base, WDT_CONTROL) | WDT_CTRL_EN;
    wr32(base, WDT_CONTROL, ctrl);
    wdt_lock(base);
}

#[cfg(feature = "vf2")]
#[inline(always)]
fn hw_wdt_kick() {
    let base = azos_drv_base::platform::hw::WDT_BASE;
    let count = wdt_count_for_ms(LAST_TIMEOUT_MS.load(Ordering::Relaxed), azos_drv_base::platform::hw::WDT_CLK_HZ);
    wdt_unlock(base);
    // INTCLR also reloads the down-counter on this variant (starfive-wdt.c's
    // `starfive_wdt_keepalive`: unlock, int_clr, set_reload_count, lock).
    wr32(base, WDT_INTCLR, 1);
    wr32(base, WDT_LOAD, count);
    wdt_lock(base);
}

#[cfg(feature = "vf2")]
fn hw_wdt_disable() {
    let base = azos_drv_base::platform::hw::WDT_BASE;
    wdt_unlock(base);
    let ctrl = rd32(base, WDT_CONTROL) & !WDT_CTRL_EN;
    wr32(base, WDT_CONTROL, ctrl);
    wdt_lock(base);
}

/// `timeout_ms` remembered across `wdt_init`→`wdt_kick` calls: the WDT-L
/// `LOAD` register must be rewritten with the SAME tick count on every kick
/// (it is a plain down-counter, not a "reload from TOP" scheme like the
/// DW-WDT this file used to model), and `wdt_kick` takes no argument.
#[cfg(feature = "vf2")]
static LAST_TIMEOUT_MS: AtomicU32 = AtomicU32::new(0);

/// `ticks = timeout_ms/1000 * clk_hz`, confirmed against `starfive-
/// wdt.c`'s `starfive_wdt_set_timeout` (`count = timeout * wdt->freq`,
/// `wdt->freq` = the `core` clock this file's `WDT_CLK_HZ` already models).
/// Saturating: a `timeout_ms` large enough to overflow u64 arithmetic here
/// would need `clk_hz` in the GHz range, which no board declares.
#[cfg(feature = "vf2")]
const fn wdt_count_for_ms(timeout_ms: u32, clk_hz: u64) -> u32 {
    let ticks = (timeout_ms as u64).saturating_mul(clk_hz) / 1000;
    if ticks > u32::MAX as u64 { u32::MAX } else { ticks as u32 }
}

/// Current watchdog counter value (hardware only; 0 on QEMU/K1).
#[cfg(feature = "vf2")]
pub fn wdt_counter() -> u32 {
    rd32(azos_drv_base::platform::hw::WDT_BASE, WDT_VALUE)
}

#[cfg(not(feature = "vf2"))]
pub fn wdt_counter() -> u32 { 0 }

// ── F11.3: Crash counter (boot-loop detection) ──────────────────────────
//
// `CRASH_COUNTER` counts consecutive boots that were never marked good. It
// is `.bss`, so with `panic = "abort"` it is zeroed by every reset; the
// durable copy is OTA BOOTMETA's `boot_count` (`crates/core/ota`), the one
// unconfirmed-boot counter on the device. `ota_boot_validate` reads it and
// writes it + 1 back (this boot is unconfirmed), and `kernel/src/boot/ota.rs`
// loads the value read here with `crash_counter_set`. `ota_mark_boot_good`
// (sys-wdt, after `OTA_BOOT_GOOD_DELAY_S` of uptime) writes 0 and calls
// `crash_counter_reset`. A boot that panics, hangs or loses power in between
// leaves the incremented value for the next boot. The panic handler only
// increments this in-memory copy, for its own log line; it writes nothing.
//
// A board with no FAT32 volume has no durable copy: the counter then starts
// at 0 on every boot, as before.

use core::sync::atomic::{AtomicU32, Ordering};

/// In-memory crash counter: loaded from BOOTMETA's `boot_count` at boot,
/// incremented on panic, reset when OTA marks the boot good.
pub static CRASH_COUNTER: AtomicU32 = AtomicU32::new(0);

/// Number of consecutive crashes that trigger safe mode.
const CRASH_BOOT_LOOP_THRESHOLD: u32 = 3;

/// Increment the crash counter. Called from the panic handler.
///
/// Returns the new counter value. If it equals or exceeds
/// `CRASH_BOOT_LOOP_THRESHOLD`, the caller should enter safe mode.
pub fn crash_counter_increment() -> u32 {
    CRASH_COUNTER.fetch_add(1, Ordering::Relaxed) + 1
}

/// Reset the crash counter. Called by `ota_mark_boot_good` (clean boot).
pub fn crash_counter_reset() {
    CRASH_COUNTER.store(0, Ordering::Relaxed);
}

/// Load the persisted count of unconfirmed boots. Called once per boot, when
/// BOOTMETA has been read (`ota_boot_validate`).
pub fn crash_counter_set(count: u32) {
    CRASH_COUNTER.store(count, Ordering::Relaxed);
}

/// Read the current crash counter value.
pub fn crash_counter_get() -> u32 {
    CRASH_COUNTER.load(Ordering::Relaxed)
}

/// Returns true if the boot-loop threshold has been reached.
pub fn crash_counter_is_boot_loop() -> bool {
    CRASH_COUNTER.load(Ordering::Relaxed) >= CRASH_BOOT_LOOP_THRESHOLD
}

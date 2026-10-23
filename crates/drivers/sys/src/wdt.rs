// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Hardware watchdog timer driver — Phase D.
//!
//! # Platform mapping
//!
//! | Platform | Hardware | Base address | Kick sequence |
//! |----------|----------|--------------|---------------|
//! | QEMU     | none (soft only) | — | no-op |
//! | VF2 (JH7110) | `starfive,jh7110-wdt` (WDT-L, NOT DesignWare) | the node's `reg` (`0x1307_0000` on the stock tree), handed over by [`wdt_attach`] | unlock → `INTCLR=1` → lock |
//! | K1 (SpacemiT) | **none** — no watchdog node anywhere in mainline `k1.dtsi` | — | [`wdt_has_hardware`] is `false` |
//! | Arm SBSA/BSA machines | the Generic Watchdog, `arm,sbsa-gwdt` (Kconfig `WDT_SBSA`) | the node's two `reg` frames, handed over by [`sbsa_attach`] | write `WRR` (`wdt_sbsa`) |
//! | Raspberry Pi (BCM2835/6/7) | the PM block, `brcm,bcm2835-pm` / `brcm,bcm2835-pm-wdt` (Kconfig `WDT_BCM2835_PM`) | the node's first `reg`, handed over by [`pm_attach`] | `WDOG` rewritten, `RSTC.WRCFG` = full reset (`azos_drv_power::bcm2835_pm`) |
//! | AMD Zen (FCH) | the FCH watchdog ("SP5100 TCO"), found by its SMBus function `1022:790b` (Kconfig `WDT_SP5100_TCO`) | the FCH's own window, decoded by [`sp5100_decode`], handed over by [`sp5100_attach`] | `CONTROL.trigger` (`wdt_sp5100`) |
//!
//! The SBSA, FCH and Raspberry Pi PM watchdogs are [`Found`] backends: the
//! bus finds at most one, and the public calls below drive it besides the
//! VF2's own path. No board selects one: the device tree or the PCI bus says
//! which is there.
//!
//! The PM block is also how a Pi reboots and powers off: its firmware has no
//! PSCI, so [`pm_reset`] is the reset handler the kernel installs for the arch
//! layer when the bus binds the node (`kernel/src/boot/hwbus.rs`).
//!
//! The window is the hardware bus's: the kernel binds the `wdt` driver to the
//! `starfive,jh7110-wdt` node right after the SoC frameworks (so its clocks
//! and reset are on), long before [`wdt_init`] arms it. A tree without the
//! node leaves the window unbound: [`wdt_has_hardware`] is `false`, the
//! software watchdog is all there is, and nothing is written.
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
//! the K1 block of `platform.rs`). [`wdt_has_hardware`] now says so
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
//! All registers are 32-bit, base from the bound node ([`wdt_attach`]). Confirmed
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

/// The `starfive,jh7110-wdt` window, attached when the hardware bus binds the
/// node ([`wdt_attach`]). Unbound: no hardware watchdog.
#[cfg(feature = "vf2")]
static WINDOW: azos_drv_base::window::Window = azos_drv_base::window::Window::new();

/// Hand the driver the watchdog the hardware bus bound at `base`. Nothing is
/// written: the counter stays as the firmware left it until [`wdt_init`] arms
/// it. `Err` when a watchdog is already attached.
#[cfg(feature = "vf2")]
pub fn wdt_attach(base: usize) -> Result<(), azos_drv_base::window::Taken> {
    WINDOW.attach(base)
}

// ── Watchdogs the hardware bus found (SBSA, AMD FCH) ────────────────────────

/// A hardware watchdog the bus found and handed over: what [`wdt_init`],
/// [`wdt_kick`] and [`wdt_disable`] drive.
pub struct Found {
    /// The driver, for the boot log.
    pub name: &'static str,
    /// Arm for a timeout in ms; the timeout actually armed (the counter's
    /// range clamps the request), which the idle keepalive follows.
    arm: fn(u32) -> u32,
    /// Restart the count. The timer interrupt calls it.
    kick: fn(),
    /// Stop the count.
    disarm: fn(),
}

/// The backends this image compiles, in a fixed order: [`FOUND`] holds one
/// plus the index of the one the bus found, 0 for none.
static BACKENDS: &[&Found] = &[
    #[cfg(feature = "wdt-sbsa")]
    &sbsa::FOUND,
    #[cfg(feature = "wdt-sp5100")]
    &sp5100::FOUND,
    #[cfg(feature = "bcm2835-pm")]
    &pm::FOUND,
];

static FOUND: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(0);

/// The backend the bus found, if any.
#[inline(always)]
pub fn found() -> Option<&'static Found> {
    match FOUND.load(Ordering::Acquire) as usize {
        0 => None,
        i => BACKENDS.get(i - 1).copied(),
    }
}

/// Make `w` the hardware watchdog. Refused when one is already installed:
/// the bus found a second.
#[cfg(any(feature = "wdt-sbsa", feature = "wdt-sp5100", feature = "bcm2835-pm"))]
fn install(w: &'static Found) -> Result<(), azos_drv_base::window::Taken> {
    let i = BACKENDS.iter().position(|b| core::ptr::eq(*b, w)).ok_or(azos_drv_base::window::Taken)? + 1;
    FOUND.compare_exchange(0, i as u8, Ordering::AcqRel, Ordering::Acquire)
        .map(|_| ()).map_err(|_| azos_drv_base::window::Taken)
}

/// The SBSA Generic Watchdog (`wdt_sbsa`): its two frames.
#[cfg(feature = "wdt-sbsa")]
mod sbsa {
    use super::Ordering;
    use crate::wdt_sbsa as g;
    use azos_drv_base::window::Window;

    pub(super) static CTRL: Window = Window::new();
    pub(super) static REFRESH: Window = Window::new();

    struct Mmio { ctrl: usize, refresh: usize }

    impl g::Frames for Mmio {
        fn ctrl_read32(&self, off: usize) -> u32 {
            // SAFETY: `ctrl` is the control frame the bus mapped
            // (`sbsa_attach`, at least `FRAME_BYTES`); `off` is a register in it.
            unsafe { core::ptr::read_volatile((self.ctrl + off) as *const u32) }
        }
        fn ctrl_write32(&self, off: usize, val: u32) {
            // SAFETY: as for `ctrl_read32`.
            unsafe { core::ptr::write_volatile((self.ctrl + off) as *mut u32, val) }
        }
        fn refresh_write32(&self, off: usize, val: u32) {
            // SAFETY: `refresh` is the mapped refresh frame, as above.
            unsafe { core::ptr::write_volatile((self.refresh + off) as *mut u32, val) }
        }
    }

    fn frames() -> Option<Mmio> {
        Some(Mmio { ctrl: CTRL.base()?, refresh: REFRESH.base()? })
    }

    /// The architecture version, read once at attach.
    pub(super) static VERSION: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

    fn arm(ms: u32) -> u32 {
        let Some(f) = frames() else { return 0 };
        let v = VERSION.load(Ordering::Relaxed);
        let (wor, armed) = g::wor_for_ms(ms, crate::timebase::freq(), v);
        g::arm(&f, wor, v);
        armed
    }

    fn kick() {
        if let Some(f) = frames() {
            g::kick(&f);
        }
    }

    fn disarm() {
        if let Some(f) = frames() {
            g::disarm(&f);
        }
    }

    pub(super) static FOUND: super::Found = super::Found { name: "sbsa-gwdt", arm, kick, disarm };

    pub(super) fn version_of(ctrl: usize, refresh: usize) -> u32 {
        g::version(&Mmio { ctrl, refresh })
    }
}

/// Hand the driver the SBSA Generic Watchdog the bus bound: `ctrl` and
/// `refresh`, the node's two frames, mapped. Nothing is armed until
/// [`wdt_init`]. Refused when either window is 0 or a watchdog is already
/// installed. The architecture version, for the boot log.
#[cfg(feature = "wdt-sbsa")]
pub fn sbsa_attach(ctrl: usize, refresh: usize) -> Result<u32, azos_drv_base::window::Taken> {
    if ctrl == 0 || refresh == 0 || found().is_some() {
        return Err(azos_drv_base::window::Taken);
    }
    let v = sbsa::version_of(ctrl, refresh);
    sbsa::VERSION.store(v, Ordering::Relaxed);
    sbsa::CTRL.attach(ctrl)?;
    sbsa::REFRESH.attach(refresh)?;
    install(&sbsa::FOUND)?;
    Ok(v)
}

/// The AMD FCH watchdog (`wdt_sp5100`): its window.
#[cfg(feature = "wdt-sp5100")]
mod sp5100 {
    use crate::wdt_sp5100 as t;
    use azos_drv_base::window::Window;

    pub(super) static WINDOW: Window = Window::new();

    pub(super) struct Mmio(pub(super) usize);

    impl t::Regs for Mmio {
        fn read32(&self, off: usize) -> u32 {
            // SAFETY: the watchdog window the kernel mapped (`sp5100_attach`,
            // `WDT_BYTES`); `off` is one of its two registers.
            unsafe { core::ptr::read_volatile((self.0 + off) as *const u32) }
        }
        fn write32(&self, off: usize, val: u32) {
            // SAFETY: as for `read32`.
            unsafe { core::ptr::write_volatile((self.0 + off) as *mut u32, val) }
        }
    }

    pub(super) struct PmMmio(pub(super) usize);

    impl t::Pm for PmMmio {
        fn read8(&self, off: usize) -> u8 {
            // SAFETY: the FCH PM window the kernel mapped (`PM_BYTES`); `off`
            // is one of its byte registers.
            unsafe { core::ptr::read_volatile((self.0 + off) as *const u8) }
        }
        fn write8(&self, off: usize, val: u8) {
            // SAFETY: as for `read8`.
            unsafe { core::ptr::write_volatile((self.0 + off) as *mut u8, val) }
        }
    }

    fn arm(ms: u32) -> u32 {
        let Some(b) = WINDOW.base() else { return 0 };
        let (s, armed) = t::seconds_for_ms(ms);
        t::arm(&Mmio(b), s);
        armed
    }

    fn kick() {
        if let Some(b) = WINDOW.base() {
            t::kick(&Mmio(b));
        }
    }

    fn disarm() {
        if let Some(b) = WINDOW.base() {
            t::disarm(&Mmio(b));
        }
    }

    pub(super) static FOUND: super::Found = super::Found { name: "sp5100-tco", arm, kick, disarm };
}

/// Turn on the decode of the FCH watchdog's window through the PM registers
/// at `pm` (mapped `wdt_sp5100::PM_PHYS`, `PM_BYTES`). `Ok`: the kernel may
/// map `wdt_sp5100::WDT_PHYS` and call [`sp5100_attach`].
#[cfg(feature = "wdt-sp5100")]
pub fn sp5100_decode(pm: usize) -> Result<(), crate::wdt_sp5100::Refused> {
    crate::wdt_sp5100::enable_decode(&sp5100::PmMmio(pm))
}

/// Set the FCH watchdog up (1 s resolution, reset action, stopped) and hand it
/// to the driver: `pm` and `wdt`, both mapped. `Ok(fired)`: whether the last
/// reset was the watchdog's. Nothing is armed until [`wdt_init`].
#[cfg(feature = "wdt-sp5100")]
pub fn sp5100_attach(pm: usize, wdt: usize) -> Result<bool, crate::wdt_sp5100::Refused> {
    use crate::wdt_sp5100::Refused;
    if wdt == 0 || found().is_some() {
        return Err(Refused::Busy);
    }
    let fired = crate::wdt_sp5100::setup(&sp5100::PmMmio(pm), &sp5100::Mmio(wdt))?;
    sp5100::WINDOW.attach(wdt).map_err(|_| Refused::Busy)?;
    install(&sp5100::FOUND).map_err(|_| Refused::Busy)?;
    Ok(fired)
}

// ── BCM2835 PM block (the Raspberry Pis, Kconfig WDT_BCM2835_PM) ────────────

/// The PM block (`azos_drv_power::bcm2835_pm`): its window, and the countdown
/// [`wdt_init`] armed, in watchdog ticks (every kick reloads it).
#[cfg(feature = "bcm2835-pm")]
mod pm {
    use super::{AtomicU32, Ordering};
    use azos_drv_base::window::Window;
    use azos_drv_power::bcm2835_pm as pm;

    /// The `brcm,bcm2835-pm` window, attached when the hardware bus binds the
    /// node ([`super::pm_attach`]). Unbound: no PM block, nothing is written.
    pub(super) static WINDOW: Window = Window::new();
    static TICKS: AtomicU32 = AtomicU32::new(0);

    /// The bound PM block's registers.
    pub(super) struct Mmio(pub(super) usize);

    impl pm::PmRegs for Mmio {
        fn read32(&self, off: usize) -> u32 {
            // SAFETY: `self.0` is the window the bus mapped for the node
            // (`pm_attach`); `off` is one of the block's registers, inside
            // `bcm2835_pm::MIN_WINDOW`, which the probe checked.
            unsafe { core::ptr::read_volatile((self.0 + off) as *const u32) }
        }
        fn write32(&self, off: usize, val: u32) {
            // SAFETY: as for `read32`.
            unsafe { core::ptr::write_volatile((self.0 + off) as *mut u32, val) }
        }
    }

    /// Arm for `ms` (clamped to the 16 s the counter holds); the timeout armed.
    fn arm(ms: u32) -> u32 {
        let Some(base) = WINDOW.base() else { return 0 };
        let ms = ms.min(pm::MAX_TIMEOUT_MS);
        let ticks = pm::ticks_for_ms(ms);
        TICKS.store(ticks, Ordering::Relaxed);
        pm::arm(&Mmio(base), ticks);
        ms
    }

    /// The timer interrupt calls this: a watchdog `wdt_init` never armed is a
    /// plain return.
    fn kick() {
        if let (Some(base), t @ 1..) = (WINDOW.base(), TICKS.load(Ordering::Relaxed)) {
            pm::arm(&Mmio(base), t);
        }
    }

    fn disarm() {
        if let Some(base) = WINDOW.base() {
            TICKS.store(0, Ordering::Relaxed);
            pm::disarm(&Mmio(base));
        }
    }

    pub(super) static FOUND: super::Found = super::Found { name: "bcm2835-pm", arm, kick, disarm };
}

/// Hand the driver the PM block the hardware bus bound at `base`. Nothing is
/// written: the watchdog stays as the firmware left it until [`wdt_init`] arms
/// it, and only with Kconfig WDT_BCM2835_PM_ARM. `Err` when a block is already
/// attached or another watchdog was found.
#[cfg(feature = "bcm2835-pm")]
pub fn pm_attach(base: usize) -> Result<(), azos_drv_base::window::Taken> {
    if found().is_some() {
        return Err(azos_drv_base::window::Taken);
    }
    pm::WINDOW.attach(base)?;
    // Kconfig WDT_BCM2835_PM_ARM = n: the block is the reset handler only, and
    // no hardware watchdog is armed (QEMU raspi3b resets on the arming write).
    if cfg!(feature = "bcm2835-pm-arm") {
        install(&pm::FOUND)
    } else {
        Ok(())
    }
}

/// Reset the SoC through the PM block: `halt` false reboots, true leaves the
/// firmware halted (boot partition 63), which is a Pi's power-off. The reset
/// comes about 150 us after the write; the call waits a millisecond for it
/// and returns only when no block is bound or the reset did not come, so the
/// caller can try the next way.
#[cfg(feature = "bcm2835-pm")]
pub fn pm_reset(halt: bool) {
    use azos_drv_power::bcm2835_pm as p;
    let Some(base) = pm::WINDOW.base() else { return };
    p::restart(&pm::Mmio(base), if halt { p::PARTITION_HALT } else { 0 });
    let start = crate::timebase::now();
    let wait = crate::timebase::freq() / 1000;
    while crate::timebase::now().wrapping_sub(start) < wait {
        core::hint::spin_loop();
    }
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
    // A found watchdog's counter may hold less: what is armed is what the
    // keepalive follows.
    let timeout_ms = found().map_or(timeout_ms, |w| (w.arm)(timeout_ms));
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
    if let Some(w) = found() {
        (w.kick)();
    }
}

/// Disable the watchdog (use only during graceful shutdown).
pub fn wdt_disable() {
    #[cfg(feature = "vf2")]
    hw_wdt_disable();
    if let Some(w) = found() {
        (w.disarm)();
    }
    ARMED_MS.store(0, Ordering::Release);
}

/// Returns true if the platform has a hardware watchdog this driver can
/// actually arm: a VF2 whose tree has the `starfive,jh7110-wdt` node (bound
/// by the hardware bus, [`wdt_attach`]), or a [`Found`] watchdog (SBSA, AMD
/// FCH). A machine without one is the software watchdog alone, not a fault.
///
/// **K1 corrected 2026-09-26 (U05-3): always `false`.** Mainline `k1.dtsi`
/// has no watchdog node at all (`grep -i "watchdog\|wdt" k1.dtsi` → no
/// match) — the address this file used to arm under `feature = "k1"`
/// (`platform::hw::WDT_BASE`, `0xD401_5000`) is `syscon_apbc`, an unrelated
/// system controller. Claiming hardware that does not exist is worse than
/// claiming none: `crates/core/actuation/src/watchdog.rs`'s boot-loop
/// protection would otherwise trust a kick that reaches nothing.
pub fn wdt_has_hardware() -> bool {
    #[cfg(feature = "vf2")]
    if WINDOW.base().is_some() {
        return true;
    }
    found().is_some()
}

// ── StarFive WDT-L implementation (VF2 only — see `wdt_has_hardware`) ───────

#[cfg(feature = "vf2")]
fn hw_wdt_init(timeout_ms: u32) {
    let Some(base) = WINDOW.base() else { return };
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
    // The timer interrupt calls this: an unbound window (no node) is a plain
    // return, never an address.
    let Some(base) = WINDOW.base() else { return };
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
    let Some(base) = WINDOW.base() else { return };
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
    WINDOW.base().map_or(0, |base| rd32(base, WDT_VALUE))
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

// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The BCM2835 power-management block (`brcm,bcm2835-pm`,
//! `brcm,bcm2835-pm-wdt`): the Raspberry Pi's watchdog, and through it the
//! Pi's reboot and power-off.
//!
//! The 32-bit Pis (BCM2835/6/7, the Pi 3 B among them) boot through the
//! VideoCore firmware's spin table: there is no PSCI, so `SYSTEM_RESET` and
//! `SYSTEM_OFF` have nobody to answer them. The PM block's watchdog is what
//! resets the SoC, and the boot partition it leaves in `RSTS` is what the
//! firmware reads on the way back up: partition 63 makes it halt, which is the
//! Pi's power-off (the board stays powered with everything stopped, as on
//! Linux). The register layout and the reset sequence are those of the
//! datasheet's PM block as Linux `drivers/watchdog/bcm2835_wdt.c` drives it
//! (`__bcm2835_restart`, `bcm2835_wdt_start`/`stop`); the code is our own.
//!
//! Every write carries the block's password in bits 31:24; a write without it
//! is ignored by the hardware. The watchdog counts down at 65 536 Hz from the
//! 20-bit `WDOG` value (16 s at most) and, with `RSTC.WRCFG` set to full
//! reset, resets the SoC when it reaches 0.
//!
//! Pure: the registers are reached through [`PmRegs`], so tests/host/power-tests
//! drives the sequences against a fake block. The kernel half (the window the
//! hardware bus binds, the watchdog entry points, the reset handler) is
//! `azos_drv_sys::wdt`.

/// Reset control: the watchdog's reset configuration.
pub const RSTC: usize = 0x1c;
/// Reset status: the boot partition the firmware reads after a reset.
pub const RSTS: usize = 0x20;
/// Watchdog counter (20 bits, 65 536 ticks per second).
pub const WDOG: usize = 0x24;
/// The smallest window that holds the three.
pub const MIN_WINDOW: u64 = WDOG as u64 + 4;

/// Bits 31:24 of every write.
pub const PASSWORD: u32 = 0x5a00_0000;
/// The counter field of `WDOG`.
pub const WDOG_TIME_MASK: u32 = 0x000f_ffff;
/// `RSTC` with the WRCFG field (bits 5:4) cleared.
pub const RSTC_WRCFG_CLR: u32 = 0xffff_ffcf;
/// WRCFG = full reset when the watchdog expires.
pub const RSTC_WRCFG_FULL_RESET: u32 = 0x0000_0020;
/// The value that stops the watchdog (WRCFG cleared, reset cleared).
pub const RSTC_RESET: u32 = 0x0000_0102;
/// `RSTS` with the partition bits (0, 2, 4, 6, 8, 10) cleared.
pub const RSTS_PARTITION_CLR: u32 = 0xffff_faaa;
/// The partition the firmware halts on: the Pi's power-off.
pub const PARTITION_HALT: u8 = 63;
/// Watchdog ticks per second.
pub const TICKS_PER_S: u32 = 1 << 16;
/// The countdown of a reset asked for now: 10 ticks, about 150 us.
pub const RESET_TICKS: u32 = 10;

/// The block's register window.
pub trait PmRegs {
    fn read32(&self, off: usize) -> u32;
    fn write32(&self, off: usize, val: u32);
}

/// The `RSTS` bits that name boot partition `p` (0..=63): its six bits spread
/// over the even bit positions 0..=10.
pub const fn partition_bits(p: u8) -> u32 {
    let p = p as u32 & 0x3f;
    let mut out = 0;
    let mut i = 0;
    while i < 6 {
        out |= (p >> i & 1) << (2 * i);
        i += 1;
    }
    out
}

/// Watchdog ticks for a timeout of `ms`, clamped to what the counter holds
/// (0 would reset at once, so at least 1).
pub const fn ticks_for_ms(ms: u32) -> u32 {
    let t = (ms as u64 * TICKS_PER_S as u64) / 1000;
    if t > WDOG_TIME_MASK as u64 {
        WDOG_TIME_MASK
    } else if t == 0 {
        1
    } else {
        t as u32
    }
}

/// The longest timeout the counter holds, ms.
pub const MAX_TIMEOUT_MS: u32 = (WDOG_TIME_MASK as u64 * 1000 / TICKS_PER_S as u64) as u32;

/// Load the counter with `ticks` and arm a full reset on expiry. This is
/// both the start and the kick: writing `WDOG` restarts the countdown.
pub fn arm<R: PmRegs>(r: &R, ticks: u32) {
    r.write32(WDOG, PASSWORD | (ticks & WDOG_TIME_MASK));
    let cur = r.read32(RSTC);
    r.write32(RSTC, PASSWORD | (cur & RSTC_WRCFG_CLR) | RSTC_WRCFG_FULL_RESET);
}

/// Stop the watchdog.
pub fn disarm<R: PmRegs>(r: &R) {
    r.write32(RSTC, PASSWORD | RSTC_RESET);
}

/// Reset the SoC into boot partition `partition` (0: a plain reboot,
/// [`PARTITION_HALT`]: the firmware halts). The reset comes [`RESET_TICKS`]
/// after the call; the caller waits for it.
pub fn restart<R: PmRegs>(r: &R, partition: u8) {
    #[cfg(not(feature = "pm-partition-canary"))]
    let bits = partition_bits(partition);
    // Canary: the partition number written as it is, not spread over the
    // even bits (partition 63 then reads back as 21: the firmware boots).
    #[cfg(feature = "pm-partition-canary")]
    let bits = partition as u32;
    let rsts = r.read32(RSTS);
    r.write32(RSTS, PASSWORD | (rsts & RSTS_PARTITION_CLR) | bits);
    arm(r, RESET_TICKS);
}

/// Is the watchdog armed (WRCFG = full reset)?
pub fn armed<R: PmRegs>(r: &R) -> bool {
    r.read32(RSTC) & !RSTC_WRCFG_CLR == RSTC_WRCFG_FULL_RESET
}

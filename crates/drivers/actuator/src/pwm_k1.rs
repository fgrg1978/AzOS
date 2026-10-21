// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! SpacemiT K1 PWM (`spacemit,k1-pwm` with the `marvell,pxa910-pwm` fallback)
//! over a register trait.
//!
//! The K1 has 20 PWM controllers, each one output with a register window of
//! its own (`pwm@d401a000` + `n * 0x400` for `n` in 0..8, `pwm@d4020000` +
//! `(n - 8) * 0x400` for 8..20, `k1.dtsi`; `reg` is 0x10 long). The block is
//! the PXA PWM, whose driver is Linux v7.2.9 `drivers/pwm/pwm-pxa.c`
//! (binding: `marvell,pxa-pwm.yaml`); every register and bit below is from it:
//!
//! | register | offset | fields |
//! |----------|--------|--------|
//! | `PWMCR`  | 0x00 | prescale `[5:0]` (`prescale | PWMCR_SD` is what `pxa_pwm_config` writes), `PWMCR_SD` bit 6 |
//! | `PWMDCR` | 0x04 | duty count `dc`; `PWMDCR_FD` bit 10 = full duty (output always active) |
//! | `PWMPCR` | 0x08 | period count `pv` |
//!
//! ```text
//! period_ns = 10^9 * (prescale + 1) * (pv + 1) / clk
//! duty_ns   = 10^9 * (prescale + 1) * dc       / clk
//! ```
//!
//! There is **no enable bit**: the output runs whenever the function clock
//! runs. Linux "disables" a PWM by writing duty 0 (`duty_cycle =
//! state->enabled ? duty_cycle : 0`) and then gating the clock. This driver
//! has no clock to gate (see below), so a disabled channel is a channel whose
//! `PWMDCR` is 0: the output sits inactive.
//!
//! # The function clock is the platform's, and the period range follows
//!
//! The function clock of PWM `n` is `CLK_PWMn` of the APBC controller
//! (`ccu-k1.c`: `CCU_MUX_GATE_DEFINE(pwmN_clk, pwm_parents, APBC_PWMN_CLK_RST,
//! 4, 3, BIT(1), 0)`): a 3-bit mux at bits `[6:4]` of `APBC_PWMn_CLK_RST`
//! (`APBC_PWM0_CLK_RST` = 0x0c in the APBC block at 0xd4015000, one word per
//! PWM), parents `{ pll1_d192_12p8, osc }` = 12.8 MHz or 32.768 kHz, gate
//! bit 1; the bus clock gate is bit 0 (`pwmN_bus_clk`). The APBC controller has
//! no provider in AzOS (the SoC frameworks model the APMU, the PLLs and the
//! MPMU), so the hardware bus skips these clocks and resets as unmodelled:
//! the state the firmware left is the state this driver runs on.
//! [`FUNC_CLK_HZ`] is the mux's reset selection (12.8 MHz); a channel whose
//! mux or gate the firmware left otherwise needs the APBC controller modelled
//! (or a different constant) before its periods mean what they say. This is
//! the first thing to confirm on the board.
//!
//! The consequence is the period range: `prescale` has 6 bits and `pv` 10, so
//! at 12.8 MHz the longest period is `64 * 1024` cycles = 5.12 ms (a 195 Hz
//! floor) and the shortest is 78 ns. The motor loop (1 ms) and the buzzer's
//! tones fit; a 50 Hz servo/ESC period (20 ms) does not, and
//! [`timing_for`] refuses it (`pwm_set_period` answers -1, as
//! `pxa_pwm_config` answers -EINVAL for `prescale > 63`).
//!
//! The register access is the [`PxaPwmBus`] trait, so the host suite
//! (`tests/host/drivers-tests`, `pwm_k1_tests`) runs the driver against a
//! register-level model of the part.

/// Register access to one controller's window, supplied by the board.
pub trait PxaPwmBus {
    /// Read the register at byte offset `off`.
    fn read32(&mut self, off: usize) -> u32;
    /// Write the register at byte offset `off`.
    fn write32(&mut self, off: usize, v: u32);
}

/// `PWMCR`, `PWMDCR`, `PWMPCR` of `pwm-pxa.c`.
mod reg {
    pub const PWMCR: usize = 0x00;
    pub const PWMDCR: usize = 0x04;
    pub const PWMPCR: usize = 0x08;
    /// `PWMCR_SD`.
    pub const CR_SD: u32 = 1 << 6;
    /// The prescale field of `PWMCR`: `prescale > 63` is refused.
    pub const CR_PRESCALE_MASK: u32 = 0x3f;
    /// `PWMDCR_FD`.
    pub const DCR_FD: u32 = 1 << 10;
}

/// Function clock of a PWM at the mux's reset selection (`pll1_d192_12p8`),
/// Hz. See the module doc: the APBC controller that selects and gates it is
/// not modelled, so this is the board's to confirm.
pub const FUNC_CLK_HZ: u64 = 12_800_000;

/// First controller's window (`pwm0`), and the step between the first eight
/// (`pwm0`..`pwm7` are contiguous; `pwm8` starts a second block at
/// 0xd4020000, which this driver does not drive). `k1.dtsi`.
pub const PWM0_BASE: usize = 0xD401_A000;
pub const PWM_STRIDE: usize = 0x400;
/// Controllers in the contiguous block.
pub const BLOCK_CHANNELS: usize = 8;

/// The channel (hardware PWM number) whose window starts at `base`, if it is
/// one of the contiguous block. The kernel's channel numbers ARE the hardware
/// numbers, so a channel keeps its number whichever nodes the tree enables.
pub const fn channel_of(base: usize) -> Option<usize> {
    if base < PWM0_BASE {
        return None;
    }
    let off = base - PWM0_BASE;
    if off % PWM_STRIDE != 0 || off / PWM_STRIDE >= BLOCK_CHANNELS {
        return None;
    }
    Some(off / PWM_STRIDE)
}

/// The two counters that make a period: `period = (prescale + 1) * (pv + 1)`
/// function-clock cycles.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Timing {
    pub prescale: u32,
    pub pv: u32,
}

/// `pxa_pwm_config`'s period arithmetic: the counters for `period_ns` at
/// [`FUNC_CLK_HZ`], `None` when it needs `prescale > 63` (or is 0).
pub fn timing_for(period_ns: u32) -> Option<Timing> {
    if period_ns == 0 {
        return None;
    }
    let cycles = (FUNC_CLK_HZ * period_ns as u64 / 1_000_000_000).max(1);
    let prescale = (cycles - 1) / 1024;
    if prescale > reg::CR_PRESCALE_MASK as u64 {
        return None;
    }
    let pv = cycles / (prescale + 1) - 1;
    Some(Timing { prescale: prescale as u32, pv: pv as u32 })
}

/// The `PWMDCR` value for `duty_ns` of a `period_ns` period built from `t`:
/// `PWMDCR_FD` for a full period (or more), otherwise `(pv + 1) * duty /
/// period` counts.
pub fn duty_count(t: Timing, duty_ns: u32, period_ns: u32) -> u32 {
    if period_ns == 0 || duty_ns >= period_ns {
        return reg::DCR_FD;
    }
    ((t.pv as u64 + 1) * duty_ns as u64 / period_ns as u64) as u32
}

/// The duty percentage (0..=100, rounded) a `PWMDCR`/`PWMPCR` pair describes:
/// what the part will do, decoded with its own definition.
pub fn duty_pct_of(dcr: u32, pcr: u32) -> u32 {
    if dcr & reg::DCR_FD != 0 {
        return 100;
    }
    let pv = pcr as u64;
    ((dcr as u64 * 100 + (pv + 1) / 2) / (pv + 1)).min(100) as u32
}

/// One PXA PWM controller.
pub struct PxaPwm<B> {
    bus: B,
}

impl<B: PxaPwmBus> PxaPwm<B> {
    /// Wrap the bus. Nothing is written.
    pub const fn new(bus: B) -> Self {
        Self { bus }
    }

    /// Program the whole configuration in the order `pxa_pwm_config` does:
    /// `PWMCR` (prescale and `PWMCR_SD`), `PWMDCR`, `PWMPCR`. `dcr` is the raw
    /// duty register value ([`duty_count`], or 0 for an inactive output).
    pub fn configure(&mut self, t: Timing, dcr: u32) {
        self.bus.write32(reg::PWMCR, t.prescale | reg::CR_SD);
        self.bus.write32(reg::PWMDCR, dcr);
        self.bus.write32(reg::PWMPCR, t.pv);
    }

    /// Change the duty only: ONE store to `PWMDCR`. This is the stop path
    /// (duty 0) and what a duty write that leaves the period alone needs.
    pub fn set_duty_reg(&mut self, dcr: u32) {
        self.bus.write32(reg::PWMDCR, dcr);
    }

    /// The duty percentage the part is programmed for now, decoded from the
    /// registers ([`duty_pct_of`]).
    pub fn duty_pct(&mut self) -> u32 {
        let dcr = self.bus.read32(reg::PWMDCR);
        let pcr = self.bus.read32(reg::PWMPCR);
        duty_pct_of(dcr, pcr)
    }
}

// ── The channel: what it was told, and what that makes the registers hold ──

use core::sync::atomic::{fence, AtomicBool, AtomicU32, Ordering};

/// `ChanState::stop_pct` while no stop is pending.
const NO_STOP: u32 = u32::MAX;

/// What one channel was last told. The kernel keeps one per channel beside
/// the controller's window (`pwm.rs`, `k1`).
///
/// The fields are atomics so the stop path ([`ChanState::stop_to`]) reads the
/// period and the enable flag without a lock, while the multi-register
/// writers ([`enable`](ChanState::enable), [`set_period`](ChanState::set_period),
/// [`set_duty`](ChanState::set_duty), [`set_duty_pct`](ChanState::set_duty_pct))
/// are serialised by the caller, per channel.
///
/// # The stop is remembered
///
/// The stop is one lock-free store to `PWMDCR`, but a configuration is three
/// stores (`PWMCR`, `PWMDCR`, `PWMPCR`) computed from the cache beforehand, so
/// a writer on another hart that is inside [`PxaPwm::configure`] (or whose
/// duty was read before the stop) would write its stale duty AFTER the stop,
/// and a later `enable`/`set_period` would re-apply the pre-stop duty from the
/// cache. So the stop is recorded here (`stop_pct`, set BEFORE the store, as
/// the GPIO side's `STOP_PENDING` is): the cached duty becomes the stop duty,
/// and every configuration re-asserts the pending stop after its own stores,
/// still under the caller's lock. Only a new duty command
/// ([`set_duty`](ChanState::set_duty), [`set_duty_pct`](ChanState::set_duty_pct))
/// supersedes it; `enable`, `disable` and `set_period` keep it.
pub struct ChanState {
    enabled: AtomicBool,
    period_ns: AtomicU32,
    duty_ns: AtomicU32,
    /// The duty percentage of the pending stop, or [`NO_STOP`].
    stop_pct: AtomicU32,
}

impl ChanState {
    /// A channel nobody configured: disabled, the motors' 1 ms period, duty
    /// 0, so enabling it before any duty leaves the output low.
    pub const fn new() -> Self {
        Self {
            enabled: AtomicBool::new(false),
            period_ns: AtomicU32::new(1_000_000),
            duty_ns: AtomicU32::new(0),
            stop_pct: AtomicU32::new(NO_STOP),
        }
    }

    /// `(enabled, period_ns, duty_ns)` as last told.
    pub fn snapshot(&self) -> (bool, u32, u32) {
        (self.enabled.load(Ordering::Acquire), self.period_ns.load(Ordering::Acquire), self.duty_ns.load(Ordering::Acquire))
    }

    /// The counters and the `PWMDCR` value the part should hold: the duty
    /// while enabled, 0 while disabled. `None` when the period is outside the
    /// clock's range.
    fn programmed(&self) -> Option<(Timing, u32)> {
        let (enabled, period_ns, duty_ns) = self.snapshot();
        let t = timing_for(period_ns)?;
        Some((t, if enabled { duty_count(t, duty_ns, period_ns) } else { 0 }))
    }

    /// The `PWMDCR` value of a stop to `pct` %: the duty while enabled, 0
    /// while disabled or when the period is outside the clock's range, so a
    /// stop can never start an output.
    fn stop_dcr(&self, pct: u32) -> u32 {
        let (enabled, period_ns, _) = self.snapshot();
        match timing_for(period_ns) {
            Some(t) if enabled => duty_count(t, (period_ns as u64 * pct.min(100) as u64 / 100) as u32, period_ns),
            _ => 0,
        }
    }

    /// Write the whole configuration, then re-assert a pending stop (a stop
    /// that landed between this writer's computation and its stores would
    /// otherwise be overwritten with the stale duty). -1 when the period is
    /// out of range.
    fn apply<B: PxaPwmBus>(&self, pwm: &mut PxaPwm<B>) -> i32 {
        match self.programmed() {
            Some((t, dcr)) => {
                pwm.configure(t, dcr);
                fence(Ordering::SeqCst);
                let pct = self.stop_pct.load(Ordering::Acquire);
                if pct != NO_STOP {
                    pwm.set_duty_reg(self.stop_dcr(pct));
                }
                0
            }
            None => -1,
        }
    }

    /// A new duty command: the pending stop is superseded.
    fn supersede_stop(&self) {
        self.stop_pct.store(NO_STOP, Ordering::Release);
    }

    /// Start driving the duty. A channel nobody gave a duty stays low.
    pub fn enable<B: PxaPwmBus>(&self, pwm: &mut PxaPwm<B>) -> i32 {
        self.enabled.store(true, Ordering::Release);
        self.apply(pwm)
    }

    /// Stop driving: ONE store, `PWMDCR` = 0, the output sits inactive. The
    /// period and duty are kept for the next [`enable`](ChanState::enable).
    pub fn disable<B: PxaPwmBus>(&self, pwm: &mut PxaPwm<B>) -> i32 {
        self.enabled.store(false, Ordering::Release);
        pwm.set_duty_reg(0);
        0
    }

    /// Set the period. -1, and nothing changes, when it is outside the clock's
    /// range ([`timing_for`]). The duty keeps its nanoseconds, clamped to the
    /// new period.
    pub fn set_period<B: PxaPwmBus>(&self, pwm: &mut PxaPwm<B>, period_ns: u32) -> i32 {
        if timing_for(period_ns).is_none() {
            return -1;
        }
        self.period_ns.store(period_ns, Ordering::Release);
        self.duty_ns.store(self.duty_ns.load(Ordering::Acquire).min(period_ns), Ordering::Release);
        self.apply(pwm)
    }

    /// Set the duty in nanoseconds (clamped to the period).
    pub fn set_duty<B: PxaPwmBus>(&self, pwm: &mut PxaPwm<B>, duty_ns: u32) -> i32 {
        self.supersede_stop();
        self.duty_ns.store(duty_ns.min(self.period_ns.load(Ordering::Acquire)), Ordering::Release);
        self.apply(pwm)
    }

    /// Set the duty as a percentage of the period (clamped to 100).
    pub fn set_duty_pct<B: PxaPwmBus>(&self, pwm: &mut PxaPwm<B>, pct: u32) -> i32 {
        self.set_duty_pct_reporting(pwm, pct).map_or(-1, |_| 0)
    }

    /// [`set_duty_pct`](ChanState::set_duty_pct), plus the duty percentage the
    /// registers describe after the write, read straight back
    /// ([`PxaPwm::duty_pct`]): a write that did not land, or a disabled
    /// channel, shows up as a different number. `None` when the period is out
    /// of range.
    pub fn set_duty_pct_reporting<B: PxaPwmBus>(&self, pwm: &mut PxaPwm<B>, pct: u32) -> Option<u32> {
        self.supersede_stop();
        let period_ns = self.period_ns.load(Ordering::Acquire);
        self.duty_ns.store((period_ns as u64 * pct.min(100) as u64 / 100) as u32, Ordering::Release);
        if self.apply(pwm) != 0 {
            return None;
        }
        Some(pwm.duty_pct())
    }

    /// The emergency duty write for the panic handler and the kernel's
    /// safe-state drive: no lock and ONE store to `PWMDCR`, after the stop is
    /// recorded (see the type's doc): the cached duty becomes the stop duty
    /// and a writer inside [`PxaPwm::configure`] re-asserts it when it is
    /// done. A disabled channel (or one whose period is out of range) is
    /// recorded as a stop to 0 whatever `pct` asks, so the stop path can never
    /// start an output, not even through a later `enable`.
    pub fn stop_to<B: PxaPwmBus>(&self, pwm: &mut PxaPwm<B>, pct: u32) {
        let (enabled, period_ns, _) = self.snapshot();
        let pct = if enabled { pct.min(100) } else { 0 };
        self.stop_pct.store(pct, Ordering::Release);
        self.duty_ns.store((period_ns as u64 * pct as u64 / 100) as u32, Ordering::Release);
        fence(Ordering::SeqCst);
        pwm.set_duty_reg(self.stop_dcr(pct));
        // A `disable` that landed between the read of `enabled` and the store
        // has already written its 0: do not leave a disabled channel driven.
        if enabled && !self.enabled.load(Ordering::Acquire) {
            pwm.set_duty_reg(0);
        }
    }
}

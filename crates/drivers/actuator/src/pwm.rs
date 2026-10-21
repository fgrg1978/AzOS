// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
/// PWM driver — port of kernel/drivers/pwm.c + kernel/include/pwm.h
///
/// QEMU: in-memory simulation.
/// VF2:  JH7110 SiFive-compatible PWM controller — real MMIO.
/// K1:   SpacemiT `spacemit,k1-pwm` (the PXA PWM), one controller per
///       channel — real MMIO, register-level core in [`crate::pwm_k1`].
pub const PWM_MAX_CHANNELS: usize = 8;

// `pwm_domain` describes the ownership shape of each instance so the
// capability layer can ask "do you hold every channel this write reaches?".
// It cannot `use` the constants below (it is pulled standalone into
// `tests/host/drivers-tests`), so the two are tied together here instead: if
// either channel count ever moves, this fails the build rather than leaving
// the domain silently describing a shape the driver no longer has.
const _: () = assert!(
    crate::pwm_domain::PWM_DOMAIN_INDEPENDENT_8.channels as usize == PWM_MAX_CHANNELS,
    "pwm_domain::PWM_DOMAIN_INDEPENDENT_8.channels must equal PWM_MAX_CHANNELS"
);

#[derive(Clone, Copy)]
pub struct PwmChannel {
    pub enabled:    bool,
    pub period_ns:  u32,
    pub duty_ns:    u32,
}

impl PwmChannel {
    pub const fn new() -> Self {
        PwmChannel { enabled: false, period_ns: 1_000_000, duty_ns: 500_000 }
    }

    pub fn duty_pct(&self) -> u32 {
        if self.period_ns == 0 { return 0; }
        (self.duty_ns as u64 * 100 / self.period_ns as u64) as u32
    }
}

// ── QEMU: in-memory simulation ────────────────────────────────────────────────

#[cfg(not(any(feature = "vf2", feature = "k1")))]
mod sim {
    use super::*;
    use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

    // One set of atomics per channel: a duty write is one store, so the
    // kernel's own stop (`pwm_set_duty_pct_panic`, used by the panic handler
    // and by the motor layer's safe-state entry) needs no lock and cannot
    // tear a concurrent writer's update of the same channel.
    struct Chan { enabled: AtomicBool, period_ns: AtomicU32, duty_ns: AtomicU32 }

    impl Chan {
        const fn new() -> Chan {
            let d = PwmChannel::new();
            Chan {
                enabled: AtomicBool::new(d.enabled),
                period_ns: AtomicU32::new(d.period_ns),
                duty_ns: AtomicU32::new(d.duty_ns),
            }
        }
    }

    static CHANNELS: [Chan; PWM_MAX_CHANNELS] = [const { Chan::new() }; PWM_MAX_CHANNELS];

    pub fn pwm_enable(ch: u32) -> i32 {
        if ch as usize >= PWM_MAX_CHANNELS { return -1; }
        CHANNELS[ch as usize].enabled.store(true, Ordering::Release); 0
    }

    pub fn pwm_disable(ch: u32) -> i32 {
        if ch as usize >= PWM_MAX_CHANNELS { return -1; }
        CHANNELS[ch as usize].enabled.store(false, Ordering::Release); 0
    }

    pub fn pwm_set_period(ch: u32, period_ns: u32) -> i32 {
        if ch as usize >= PWM_MAX_CHANNELS { return -1; }
        CHANNELS[ch as usize].period_ns.store(period_ns, Ordering::Release); 0
    }

    pub fn pwm_set_duty(ch: u32, duty_ns: u32) -> i32 {
        if ch as usize >= PWM_MAX_CHANNELS { return -1; }
        let c = &CHANNELS[ch as usize];
        c.duty_ns.store(duty_ns.min(c.period_ns.load(Ordering::Acquire)), Ordering::Release); 0
    }

    pub fn pwm_set_duty_pct(ch: u32, pct: u32) -> i32 {
        if pwm_set_duty_pct_reporting(ch, pct).is_some() { 0 } else { -1 }
    }

    /// `pwm_set_duty_pct`, plus the duty the channel holds **as of that very
    /// write**: the percentage of the duty this call stored, not a separate
    /// read of the channel. `None` means the channel does not exist, so a
    /// caller can never read "no such channel" as "0%".
    ///
    /// The readback belongs in here, not at the call site. These channels have
    /// more than one writer — `rt_motor_task` runs the control loop over the
    /// same wheels a syscall commands — so a write followed by a separate
    /// `pwm_get` leaves a window in which another writer's duty is what comes
    /// back. Anything asserting on that pair is then racy in both directions:
    /// red when the other writer wins the window, green when it happens to
    /// write the same number. Computing it from the value stored closes it.
    pub fn pwm_set_duty_pct_reporting(ch: u32, pct: u32) -> Option<u32> {
        if ch as usize >= PWM_MAX_CHANNELS { return None; }
        let c = &CHANNELS[ch as usize];
        let period_ns = c.period_ns.load(Ordering::Acquire);
        let duty_ns = (period_ns as u64 * pct.min(100) as u64 / 100) as u32;
        c.duty_ns.store(duty_ns, Ordering::Release);
        Some(PwmChannel { enabled: true, period_ns, duty_ns }.duty_pct())
    }

    /// Emergency duty-cycle write for the panic handler and the kernel's
    /// safe-state drive: one store to the channel's own atomic, no lock, so
    /// it never waits on a writer that is stalled and never tears another
    /// field's state.
    pub fn pwm_set_duty_pct_panic(ch: u32, pct: u32) -> i32 {
        if pwm_set_duty_pct_reporting(ch, pct).is_some() { 0 } else { -1 }
    }

    pub fn pwm_get(ch: u32) -> Option<PwmChannel> {
        if ch as usize >= PWM_MAX_CHANNELS { return None; }
        let c = &CHANNELS[ch as usize];
        Some(PwmChannel {
            enabled: c.enabled.load(Ordering::Acquire),
            period_ns: c.period_ns.load(Ordering::Acquire),
            duty_ns: c.duty_ns.load(Ordering::Acquire),
        })
    }

}

#[cfg(not(any(feature = "vf2", feature = "k1")))]
pub use sim::*;

// ── VisionFive 2 / JH7110: register model UNVERIFIED (U05-1, 2026-09-26) ────
//
// **This module models the wrong IP.** It implements the SiFive PWM v0
// register layout (`drivers/pwm/pwm-sifive.c`: one shared `PWMCFG` +
// per-channel `PWMCMP`), but the JH7110 PWM's real DT compatible is
// `"starfive,jh7110-pwm", "opencores,pwm-v1"` — an OpenCores PTC core, a
// different IP with independent per-channel `CNTR`/`HRC`/`LRC`/`CTRL`
// blocks and NO shared control register (see `pwm_domain.rs`'s
// `PWM_DOMAIN_INDEPENDENT_8` doc, corrected to match). There is also no *merged*
// Linux mainline driver for `opencores,pwm-v1` to confirm exact register
// behaviour against yet (only a pending, not-yet-accepted patch as of this
// fetch) — porting this module for real needs that driver to land (or the
// OpenCores PTC datasheet directly) plus the PWM APB clock rate, neither
// available this pass. Left in place, unchanged below this comment, as
// **known-wrong** rather than silently "confirmed": the base the bus hands
// `pwm_attach` (the `pwm@120d0000` node's `reg`) is the right address,
// everything downstream of it in this module is not. Do not trust `pwm_control_reach`/`pwm_control_allowed` callers
// that assume this module's shared-`PWMCFG` shape — the domain now says
// (correctly) that the real hardware has none; this module still writes as
// if it did.
//
//   +0x00        PWMCFG    — shared: scale bitfield [3:0], sticky (8),
//                             zero-cmp (9), deglitch (10), en-always (12),
//                             en-once (13)
//   +0x08        PWMCOUNT  — shared free-running counter (unused here)
//   +0x10        PWMS      — shared scaled counter, read-only (unused here)
//   +0x20+4*i    PWMCMP(i) — per-channel compare/duty value, i = 0..3

#[cfg(feature = "vf2")]
mod mmio {
    use super::*;
    use azos_drv_base::window::{Taken, Window};

    /// The `starfive,jh7110-pwm` window, attached when the hardware bus binds
    /// the node (`pwm_attach`). Unbound: no PWM, every entry point answers
    /// -1 / `None`, the registers are not touched.
    static WINDOW: Window = Window::new();

    // Real JH7110 SiFive PWM v0 register map — confirmed against Linux
    // mainline drivers/pwm/pwm-sifive.c (PWM_SIFIVE_PWMCFG/PWMCOUNT/PWMS/
    // PWMCMP + PWM_SIFIVE_PWMCFG_* bitfield macros), 2026-08. Corrects the
    // earlier per-channel-block model (base + ch*stride) this file
    // used, which does not match real hardware: PWMCFG is ONE shared
    // register for the whole 4-channel instance (not per-channel), and its
    // "scale" is a bitfield within PWMCFG, not a separate PWMSCALE
    // register. Only PWMCMP is genuinely per-channel, and only for
    // indices 0-3 — there are 4 real channels here, not 8.
    const PWMCFG:   usize = 0x00; // shared: enable + scale bitfield
    // PWMCOUNT/PWMS documented for completeness (full real register map)
    // but not read by this driver today — nothing here needs the raw
    // free-running counter or its scaled read-only view.
    #[allow(dead_code)]
    const PWMCOUNT: usize = 0x08; // shared free-running counter
    #[allow(dead_code)]
    const PWMS:     usize = 0x10; // shared scaled counter, read-only

    #[inline(always)]
    fn pwmcmp_offset(ch: u32) -> usize { 0x20 + 4 * ch as usize }

    // PWMCFG bitfield (PWM_SIFIVE_PWMCFG_* in the Linux driver).
    const CFG_SCALE_MASK:  u32 = 0x0F;      // bits [3:0] — prescaler
    const CFG_ZERO_CMP:    u32 = 1 << 9;    // reset counter on compare match
    const CFG_EN_ALWAYS:   u32 = 1 << 12;   // continuous PWM output

    /// Real hardware channel count — only PWMCMP0..3 exist. Deliberately
    /// separate from the module-level `PWM_MAX_CHANNELS` (8), which is
    /// shared with the `sim` module used by QEMU/K1 and out of scope here.
    const PWM_MMIO_CHANNELS: usize = 4;

    // The capability layer gates this driver's writes against
    // `pwm_domain::PWM_DOMAIN`, which on `vf2` is `PWM_DOMAIN_VF2_DRIVER`:
    // the shape THIS module programs (SiFive layout, one `PWMCFG` for the
    // instance). The real part is `PWM_DOMAIN_INDEPENDENT_8` (8 independent
    // channels); these asserts keep the gate describing the driver that is
    // compiled, not the hardware it should eventually become, so a holder
    // of a free channel cannot reach the motors through the shared `PWMCFG`.
    const _: () = assert!(
        crate::pwm_domain::PWM_DOMAIN.channels as usize == PWM_MMIO_CHANNELS,
        "pwm_domain::PWM_DOMAIN must describe the channels this driver programs"
    );
    const _: () = assert!(
        crate::pwm_domain::PWM_DOMAIN.shared_control,
        "this driver writes one PWMCFG for the whole instance - the gate's domain must say so"
    );

    // PWM counter max (16-bit compare) — unverified against real hardware
    // counter width, kept as-is from the prior model pending real hardware
    // access; not part of this fix's scope.
    const CMP_MAX: u32 = 0xFFFF;

    // JH7110 PWM8's only clock input is "apb" (JH7110_SYSCLK_PWM_APB in
    // clk-starfive-jh7110-sys.c), gated from APB_BUS = STG_AXIAHB / 8.
    // Unlike WDT_CLK_HZ (crates/drivers/base/src/platform.rs — gated directly
    // off the 24 MHz crystal, no divider chain), STG_AXIAHB is supplied
    // externally by boot firmware and isn't a statically-defined rate in
    // the Linux clock driver — traced this as far as mainline source
    // allows and hit a genuine dead end pending real hardware/TRM access.
    // Still assumed 24 MHz (unconfirmed) pending that.
    const PWM_CLK_HZ: u64 = 24_000_000;

    /// An unbound read is 0 and an unbound write goes nowhere; the entry
    /// points check `bound()` first and answer "absent".
    #[inline(always)]
    fn reg_read(off: usize) -> u32 {
        match WINDOW.base() {
            // SAFETY: the base the bus bound and the kernel mapped.
            Some(b) => unsafe { core::ptr::read_volatile((b + off) as *const u32) },
            None => 0,
        }
    }

    #[inline(always)]
    fn reg_write(off: usize, val: u32) {
        if let Some(b) = WINDOW.base() {
            // SAFETY: as `reg_read`.
            unsafe { core::ptr::write_volatile((b + off) as *mut u32, val) }
        }
    }

    #[inline(always)]
    fn bound() -> bool {
        WINDOW.base().is_some()
    }

    /// Whether a controller is attached (the tree had the node, the bus bound it).
    pub fn pwm_has_hardware() -> bool {
        bound()
    }

    /// Bring the PWM up on the controller the bus bound at `base`: stopped.
    /// `Err` when a controller is already attached.
    pub fn pwm_attach(base: usize) -> Result<(), Taken> {
        WINDOW.attach(base)?;
        // One shared instance — disable once, not per channel.
        reg_write(PWMCFG, 0);
        Ok(())
    }

    // On this (vf2) part the enable bit and the scale field live in ONE
    // `PWMCFG` shared by all four channels, so `pwm_enable`, `pwm_disable` and
    // `pwm_set_period` are instance-wide whatever channel they name, and
    // `PWMCMP` (the per-channel duty register) is untouched by them: whatever
    // duty was last latched for another channel becomes live again the
    // instant the shared bit flips.
    //
    // The `Pwm` interface the kernel hosts refuses such a control write by its
    // REACH, not by the channel the caller named: `pwm_domain` states that a
    // write named for any channel reaches all four, and the op is refused if
    // any channel it reaches is a motor's (`pwm_control_reaches_a_motor`).
    //
    // STILL OPEN, and deliberately not papered over here: the calls below
    // remain instance-wide for any in-kernel caller, because this driver
    // cannot see the caller's capability table. The buzzer's channel is
    // reached through the `Pwm` interface; its reach check reads
    // `pwm_domain::PWM_DOMAIN`. That domain says the channels are independent,
    // and this module (the SiFive model) writes a shared `PWMCFG` for enable,
    // disable and period, so on vf2 the two still disagree for every holder of
    // a `pwm` endpoint (`autorun`'s `pwm.4` as well as the buzzer's `pwm.5`)
    // until this module models the real IP.
    pub fn pwm_enable(ch: u32) -> i32 {
        if ch as usize >= PWM_MMIO_CHANNELS || !bound() { return -1; }
        // Enable is instance-wide (PWMCFG is shared) — read-modify-write so
        // enabling one channel doesn't disturb the scale bits or another
        // already-configured channel's comparator (PWMCMP is independent
        // per channel and untouched by this write). See the block comment
        // above: "instance-wide" is exactly the property that breaks the
        // per-channel capability model's isolation assumption.
        let cfg = reg_read(PWMCFG) | CFG_EN_ALWAYS | CFG_ZERO_CMP;
        reg_write(PWMCFG, cfg);
        0
    }

    pub fn pwm_disable(ch: u32) -> i32 {
        if ch as usize >= PWM_MMIO_CHANNELS || !bound() { return -1; }
        // This disables the WHOLE instance (all 4 channels), since enable
        // is instance-wide on real hardware — there is no way to disable
        // just one channel's output while leaving another running. See the
        // block comment above `pwm_enable`: this is reachable from ring 3
        // for any channel the caller holds a `Pwm` capability for, which is
        // not the same authority as holding a `Motor` capability for the
        // channels this write actually reaches.
        let cfg = reg_read(PWMCFG) & !CFG_EN_ALWAYS;
        reg_write(PWMCFG, cfg);
        0
    }

    /// Set the SHARED period (nanoseconds) for the whole PWM instance —
    /// programs PWMCFG's scale bitfield. `ch` is accepted for API
    /// compatibility with the per-channel call sites in motor.rs but is
    /// otherwise unused: all channels on this instance share one period.
    /// Today's real usage (2 motors, channels 0-1, both configured with
    /// the same `MOTOR_PWM_PERIOD_NS`) never actually needs two different
    /// periods, so this is not a behavior change for this codebase — it's
    /// the model finally matching what the hardware always did.
    pub fn pwm_set_period(ch: u32, period_ns: u32) -> i32 {
        if ch as usize >= PWM_MMIO_CHANNELS || period_ns == 0 || !bound() { return -1; }
        let period_cycles = PWM_CLK_HZ * period_ns as u64 / 1_000_000_000;
        let mut scale = 0u32;
        let mut counts = period_cycles;
        while counts > CMP_MAX as u64 && scale < 15 {
            scale += 1;
            counts >>= 1;
        }
        let cfg = (reg_read(PWMCFG) & !CFG_SCALE_MASK) | (scale & CFG_SCALE_MASK);
        reg_write(PWMCFG, cfg);
        let _ = counts; // no separate per-channel period register to write further
        0
    }

    /// UNIMPLEMENTED — absolute-nanosecond duty needs the shared period
    /// (see `pwm_set_period`) to convert to a percentage or a raw
    /// comparator count; no software-side period cache exists to do that
    /// conversion correctly today. Use `pwm_set_duty_pct` instead — it no
    /// longer aliases with `pwm_set_period` now that PWMCMP is correctly
    /// modeled as per-channel-only (that was the actual root cause of the
    /// previous aliasing bug, now fixed).
    pub fn pwm_set_duty(_ch: u32, _duty_ns: u32) -> i32 {
        -1
    }

    /// Sets duty as a percentage of CMP_MAX. Writes ONLY this channel's
    /// PWMCMP — no longer touches PWMCFG/scale, so it can no longer
    /// corrupt the period (the bug this file previously documented at
    /// length is fixed by this register-model correction).
    pub fn pwm_set_duty_pct(ch: u32, pct: u32) -> i32 {
        if pwm_set_duty_pct_reporting(ch, pct).is_some() { 0 } else { -1 }
    }

    /// `pwm_set_duty_pct`, plus the duty PWMCMP holds after the write, read
    /// straight back off the register. `None` means the channel does not
    /// exist.
    ///
    /// The percentage is recovered from the compare value, so it is the
    /// hardware's number and not the argument echoed back: a scale change
    /// that clamps CMP, or a write that does not land, shows up as a
    /// different percentage rather than as a missing line.
    ///
    /// **Not atomic with the write on this backend**, unlike the simulated
    /// one, because no software lock guards this MMIO path (see
    /// `pwm_set_duty_pct_panic`). A concurrent writer to the same channel can
    /// still land between the two register accesses; on a board, PWMCMP has
    /// one owner per wheel and this is a readback, not a mutual-exclusion
    /// claim.
    pub fn pwm_set_duty_pct_reporting(ch: u32, pct: u32) -> Option<u32> {
        if ch as usize >= PWM_MMIO_CHANNELS || !bound() { return None; }
        let duty = (CMP_MAX as u64 * pct.min(100) as u64 / 100) as u32;
        reg_write(pwmcmp_offset(ch), duty);
        let back = reg_read(pwmcmp_offset(ch)).min(CMP_MAX);
        Some(((back as u64 * 100 + CMP_MAX as u64 / 2) / CMP_MAX as u64) as u32)
    }

    /// Emergency duty-cycle write for the panic handler — same rationale
    /// as `gpio::gpio_write_panic` (see its doc comment): no software lock
    /// exists on this MMIO path today (same as before this fix), so this
    /// is already non-blocking; kept as a distinct name purely so callers
    /// don't need a `cfg` branch at the call site.
    pub fn pwm_set_duty_pct_panic(ch: u32, pct: u32) -> i32 {
        pwm_set_duty_pct(ch, pct)
    }

    pub fn pwm_get(ch: u32) -> Option<PwmChannel> {
        if ch as usize >= PWM_MMIO_CHANNELS || !bound() { return None; }
        let cfg = reg_read(PWMCFG);
        Some(PwmChannel {
            enabled:   cfg & CFG_EN_ALWAYS != 0,
            period_ns: 0, // would need to reverse-compute from the scale bitfield
            duty_ns:   0,
        })
    }

}

#[cfg(feature = "vf2")]
pub use mmio::*;

// ── SpacemiT K1: `spacemit,k1-pwm` ───────────────────────────────────────────
//
// One device-tree node per channel, each a PXA PWM with a window of its own
// (`pwm_k1.rs`: registers, the period arithmetic, and what is the platform's:
// the function clock). The channel number IS the hardware PWM number, taken
// from the node's address (`pwm_k1::channel_of`), so a channel keeps its
// number whichever nodes the tree enables: the motors' channels 0-1, the
// gripper's 4 and the buzzer's 5 are `pwm0`, `pwm1`, `pwm4` and `pwm5`. The
// kernel drives the first `PWM_MAX_CHANNELS` (the contiguous block `pwm0`..
// `pwm7`); a node outside it is refused at attach.
//
// Differences from the VF2 module, all of them the hardware's:
//
// * the channels are independent: `PWM_DOMAIN_INDEPENDENT_8` is the shape
//   this module programs (no shared control register), so a `Pwm` capability
//   over channel `n` reaches channel `n` only;
// * there is no enable bit. A channel is *enabled* when its `PWMDCR` holds
//   the duty and *disabled* when it holds 0 (what Linux's `pxa_pwm_apply`
//   does for a disabled state): the output sits inactive. A channel starts
//   disabled with duty 0, so `pwm_enable` before any duty leaves it low;
// * `pwm_set_duty` (absolute nanoseconds) works: the period is cached per
//   channel, which is what the VF2 module lacks;
// * the period range is the function clock's: 78 ns..5.12 ms. Longer
//   periods (a 50 Hz servo) are refused with -1; see `pwm_k1.rs`.

#[cfg(feature = "k1")]
mod k1 {
    use super::*;
    use crate::pwm_k1::{self, ChanState, PxaPwm, PxaPwmBus};
    use azos_drv_base::window::{Taken, Window};
    use azos_sync::SpinLock;

    // The channels this module drives are the contiguous block's.
    const _: () = assert!(PWM_MAX_CHANNELS <= pwm_k1::BLOCK_CHANNELS, "PWM_MAX_CHANNELS exceeds pwm0..pwm7");
    // The K1 block of `platform::hw` and the core agree on where the block is.
    const _: () = assert!(
        azos_drv_base::platform::hw::PWM_BASE == pwm_k1::PWM0_BASE
            && azos_drv_base::platform::hw::PWM_STRIDE == pwm_k1::PWM_STRIDE,
        "platform::hw::PWM_BASE/PWM_STRIDE and pwm_k1::PWM0_BASE/PWM_STRIDE name different windows"
    );
    // The domain the capability layer gates against is the independent one.
    const _: () = assert!(
        !crate::pwm_domain::PWM_DOMAIN.shared_control
            && crate::pwm_domain::PWM_DOMAIN.channels as usize == PWM_MAX_CHANNELS,
        "pwm_domain::PWM_DOMAIN must describe independent channels: each K1 PWM has its own registers"
    );

    /// The window of each channel's controller, attached when the hardware
    /// bus binds the node (`pwm_attach`). Unbound: the channel is absent,
    /// every entry point answers -1 / `None`, no register is touched.
    static WINDOWS: [Window; PWM_MAX_CHANNELS] = [const { Window::new() }; PWM_MAX_CHANNELS];

    /// What each channel was told (`pwm_k1::ChanState`).
    static CHANNELS: [ChanState; PWM_MAX_CHANNELS] = [const { ChanState::new() }; PWM_MAX_CHANNELS];

    /// Serialises the multi-register configuration of one channel (a period
    /// and a duty change are three stores). The stop path does not take it.
    static CONFIG_LOCKS: [SpinLock<()>; PWM_MAX_CHANNELS] = [const { SpinLock::new(()) }; PWM_MAX_CHANNELS];

    /// One controller's registers over its mapped window.
    struct Mmio(usize);

    impl PxaPwmBus for Mmio {
        #[inline(always)]
        fn read32(&mut self, off: usize) -> u32 {
            // SAFETY: the base the bus bound and the kernel mapped; `off` is
            // one of the block's three registers (below 0x10).
            unsafe { core::ptr::read_volatile((self.0 + off) as *const u32) }
        }
        #[inline(always)]
        fn write32(&mut self, off: usize, v: u32) {
            // SAFETY: as `read32`.
            unsafe { core::ptr::write_volatile((self.0 + off) as *mut u32, v) }
        }
    }

    /// Channel `ch`'s controller, `None` when `ch` does not exist or no node
    /// is bound to it.
    #[inline(always)]
    fn controller(ch: u32) -> Option<PxaPwm<Mmio>> {
        WINDOWS.get(ch as usize)?.base().map(|b| PxaPwm::new(Mmio(b)))
    }

    /// Whether any controller is attached (the tree had a PWM node the bus
    /// bound).
    pub fn pwm_has_hardware() -> bool {
        WINDOWS.iter().any(|w| w.base().is_some())
    }

    /// Bring the PWM up on the controller the bus bound at `base`: stopped
    /// (`PWMDCR` 0). `Err` when `base` is not one of the block's windows, or
    /// the channel it names is already attached.
    pub fn pwm_attach(base: usize) -> Result<(), Taken> {
        let ch = pwm_k1::channel_of(base).filter(|&c| c < PWM_MAX_CHANNELS).ok_or(Taken)?;
        WINDOWS[ch].attach(base)?;
        PxaPwm::new(Mmio(base)).set_duty_reg(0);
        azos_drv_sys::kprintln!("[PWM] channel {} on SpacemiT K1 controller @ {:#010x}", ch, base);
        Ok(())
    }

    pub fn pwm_enable(ch: u32) -> i32 {
        let Some(mut pwm) = controller(ch) else { return -1 };
        let _guard = CONFIG_LOCKS[ch as usize].lock();
        CHANNELS[ch as usize].enable(&mut pwm)
    }

    pub fn pwm_disable(ch: u32) -> i32 {
        let Some(mut pwm) = controller(ch) else { return -1 };
        let _guard = CONFIG_LOCKS[ch as usize].lock();
        CHANNELS[ch as usize].disable(&mut pwm)
    }

    /// Set the channel's period. Refused (-1) when it needs a prescale past
    /// the 6-bit field: the range is 78 ns..5.12 ms at the 12.8 MHz function
    /// clock (`pwm_k1`).
    pub fn pwm_set_period(ch: u32, period_ns: u32) -> i32 {
        let Some(mut pwm) = controller(ch) else { return -1 };
        let _guard = CONFIG_LOCKS[ch as usize].lock();
        CHANNELS[ch as usize].set_period(&mut pwm, period_ns)
    }

    pub fn pwm_set_duty(ch: u32, duty_ns: u32) -> i32 {
        let Some(mut pwm) = controller(ch) else { return -1 };
        let _guard = CONFIG_LOCKS[ch as usize].lock();
        CHANNELS[ch as usize].set_duty(&mut pwm, duty_ns)
    }

    pub fn pwm_set_duty_pct(ch: u32, pct: u32) -> i32 {
        let Some(mut pwm) = controller(ch) else { return -1 };
        let _guard = CONFIG_LOCKS[ch as usize].lock();
        CHANNELS[ch as usize].set_duty_pct(&mut pwm, pct)
    }

    /// `pwm_set_duty_pct`, plus the duty percentage the controller's
    /// registers describe after the write (`ChanState::set_duty_pct_reporting`).
    /// `None`: the channel does not exist, has no controller, or its period is
    /// outside the clock's range.
    ///
    /// **Not atomic with the write**: a concurrent writer of the same channel
    /// can land between the two register accesses (the config lock orders
    /// writers, not the readback).
    pub fn pwm_set_duty_pct_reporting(ch: u32, pct: u32) -> Option<u32> {
        let mut pwm = controller(ch)?;
        let _guard = CONFIG_LOCKS[ch as usize].lock();
        CHANNELS[ch as usize].set_duty_pct_reporting(&mut pwm, pct)
    }

    /// Emergency duty write for the panic handler and the kernel's safe-state
    /// drive: no lock (a stalled writer, or a panic on another hart, would
    /// make it wait forever) and ONE register store (`ChanState::stop_to`).
    /// The stop is recorded in the channel first, so a writer inside the
    /// locked `configure` re-asserts it and a later `pwm_enable` /
    /// `pwm_set_period` does not restart the pre-stop duty.
    pub fn pwm_set_duty_pct_panic(ch: u32, pct: u32) -> i32 {
        let Some(mut pwm) = controller(ch) else { return -1 };
        CHANNELS[ch as usize].stop_to(&mut pwm, pct);
        0
    }

    pub fn pwm_get(ch: u32) -> Option<PwmChannel> {
        controller(ch)?;
        let (enabled, period_ns, duty_ns) = CHANNELS[ch as usize].snapshot();
        Some(PwmChannel { enabled, period_ns, duty_ns })
    }
}

#[cfg(feature = "k1")]
pub use k1::*;

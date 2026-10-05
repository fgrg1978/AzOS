// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// U05-4 (2026-09-26): same class as `gpio.rs` — a `k1` build fell through
// to the QEMU sim below while `pwm_driver.rs`/`platform::hw` advertise real
// K1 PWM MMIO (`spacemit,k1-pwm`, see `platform.rs`). `rc.rs`'s
// compile-time refusal, applied here per U05-4/§5 Q2 [rec]. Placed before
// the module doc for the same `unused_doc_comments` reason as `gpio.rs`.
#[cfg(feature = "k1")]
compile_error!(
    "crates/drivers/actuator/src/pwm.rs: no real K1 PWM driver exists yet — a `k1` \
     build must not silently drive the QEMU simulation while advertising \
     real MMIO. See U05-4."
);

/// PWM driver — port of kernel/drivers/pwm.c + kernel/include/pwm.h
///
/// QEMU: in-memory simulation.
/// VF2:  JH7110 SiFive-compatible PWM controller — real MMIO.
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
//
// NOTE (scope gap, not fixed here — out of scope for this pass, flagged for
// follow-up): this module is gated `not(feature = "vf2")`, so a `k1` build
// falls through to the in-memory simulation below, NOT to real MMIO. Yet
// `pwm_driver.rs` advertises an MMIO range under `any(vf2, k1)` and
// `platform::hw` defines a K1 `PWM_BASE`/`PWM_STRIDE`, implying a real path
// was intended. There is no such path: on BananaPi K1 today, motor/gripper
// PWM writes silently land in the QEMU simulation and never reach hardware.
// Do NOT fix by widening `mmio` below to `any(vf2, k1)` — K1 is
// `spacemit,k1x-pwm`, a different IP block from the JH7110 SiFive PWM
// modelled below; that would silently mis-program K1 hardware.

#[cfg(not(feature = "vf2"))]
mod sim {
    use super::*;
    use azos_sync::SpinLock;

    struct PwmState { channels: [PwmChannel; PWM_MAX_CHANNELS] }
    impl PwmState { const fn new() -> Self { PwmState { channels: [PwmChannel::new(); PWM_MAX_CHANNELS] } } }

    static PWM: SpinLock<PwmState> = SpinLock::new(PwmState::new());

    pub fn pwm_init() {}

    pub fn pwm_enable(ch: u32) -> i32 {
        if ch as usize >= PWM_MAX_CHANNELS { return -1; }
        PWM.lock().channels[ch as usize].enabled = true; 0
    }

    pub fn pwm_disable(ch: u32) -> i32 {
        if ch as usize >= PWM_MAX_CHANNELS { return -1; }
        PWM.lock().channels[ch as usize].enabled = false; 0
    }

    pub fn pwm_set_period(ch: u32, period_ns: u32) -> i32 {
        if ch as usize >= PWM_MAX_CHANNELS { return -1; }
        PWM.lock().channels[ch as usize].period_ns = period_ns; 0
    }

    pub fn pwm_set_duty(ch: u32, duty_ns: u32) -> i32 {
        if ch as usize >= PWM_MAX_CHANNELS { return -1; }
        let mut p = PWM.lock();
        p.channels[ch as usize].duty_ns = duty_ns.min(p.channels[ch as usize].period_ns); 0
    }

    pub fn pwm_set_duty_pct(ch: u32, pct: u32) -> i32 {
        if pwm_set_duty_pct_reporting(ch, pct).is_some() { 0 } else { -1 }
    }

    /// `pwm_set_duty_pct`, plus the duty the channel holds **as of that very
    /// write**, read back inside the one `PWM` critical section the write
    /// takes. `None` means the channel does not exist, so a caller can never
    /// read "no such channel" as "0%".
    ///
    /// The readback belongs in here, not at the call site. These channels have
    /// more than one writer — `rt_motor_task` runs the control loop over the
    /// same wheels a syscall commands — so a write followed by a separate
    /// `pwm_get` leaves a window in which another writer's duty is what comes
    /// back. Anything asserting on that pair is then racy in both directions:
    /// red when the other writer wins the window, green when it happens to
    /// write the same number. Holding the lock across both closes it.
    pub fn pwm_set_duty_pct_reporting(ch: u32, pct: u32) -> Option<u32> {
        if ch as usize >= PWM_MAX_CHANNELS { return None; }
        let mut p = PWM.lock();
        let c = &mut p.channels[ch as usize];
        c.duty_ns = (c.period_ns as u64 * pct.min(100) as u64 / 100) as u32;
        Some(c.duty_pct())
    }

    /// Emergency duty-cycle write for the panic handler — bypasses the
    /// `PWM` spinlock entirely instead of calling `.lock()`.
    ///
    /// Deliberately sacrifices mutual exclusion: same rationale as
    /// `gpio::gpio_write_panic` (see its doc comment). If another hart
    /// holds `PWM` at panic time, `.lock()` would spin forever here and
    /// the panic message would never reach UART — stopping the motor and
    /// printing the crash reason matters more than a torn write to the
    /// simulated PWM state. Conscious trade-off, not an oversight.
    ///
    /// # Safety
    /// May race with a concurrent `pwm_set_duty`/`pwm_set_duty_pct`/
    /// `pwm_set_period` on another hart, producing a torn read-modify-write
    /// of `PwmState`. Only call this from the panic handler.
    pub fn pwm_set_duty_pct_panic(ch: u32, pct: u32) -> i32 {
        if ch as usize >= PWM_MAX_CHANNELS { return -1; }
        let p = unsafe { PWM.get_mut_unchecked() };
        let period = p.channels[ch as usize].period_ns;
        p.channels[ch as usize].duty_ns = (period as u64 * pct.min(100) as u64 / 100) as u32; 0
    }

    pub fn pwm_get(ch: u32) -> Option<PwmChannel> {
        if ch as usize >= PWM_MAX_CHANNELS { return None; }
        Some(PWM.lock().channels[ch as usize])
    }

    pub fn pwm_info() {
        azos_drv_sys::kconsoleln!("[PWM] Simulated PWM — {} channels", PWM_MAX_CHANNELS);
        let p = PWM.lock();
        for i in 0..PWM_MAX_CHANNELS {
            let ch = &p.channels[i];
            if ch.enabled {
                azos_drv_sys::kconsoleln!("[PWM]   ch{}: enabled, period={}ns, duty={}ns ({}%)",
                    i, ch.period_ns, ch.duty_ns, ch.duty_pct());
            } else {
                azos_drv_sys::kconsoleln!("[PWM]   ch{}: disabled", i);
            }
        }
    }
}

#[cfg(not(feature = "vf2"))]
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
// **known-wrong** rather than silently "confirmed": `PWM_BASE` is the right
// address (see `platform::hw`), everything downstream of it in this module
// is not. Do not trust `pwm_control_reach`/`pwm_control_allowed` callers
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
    use azos_drv_base::platform::hw::PWM_BASE;

    // Real JH7110 SiFive PWM v0 register map — confirmed against Linux
    // mainline drivers/pwm/pwm-sifive.c (PWM_SIFIVE_PWMCFG/PWMCOUNT/PWMS/
    // PWMCMP + PWM_SIFIVE_PWMCFG_* bitfield macros), 2026-08. Corrects the
    // earlier per-channel-block model (PWM_BASE + ch*PWM_STRIDE) this file
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

    #[inline(always)]
    fn reg_read(off: usize) -> u32 {
        unsafe { core::ptr::read_volatile((PWM_BASE + off) as *const u32) }
    }

    #[inline(always)]
    fn reg_write(off: usize, val: u32) {
        unsafe { core::ptr::write_volatile((PWM_BASE + off) as *mut u32, val) }
    }

    pub fn pwm_init() {
        // One shared instance — disable once, not per channel.
        reg_write(PWMCFG, 0);
    }

    // SAFETY CLAIM CORRECTED 2026-09-06 (claims_check audit) — read this
    // before touching `pwm_enable`/`pwm_disable` or the PWM capability
    // model. The previous comment here asserted "this is not a live bug"
    // on the grounds that "today's only two callers (motor.rs, PWM
    // channels 0 and 1) always disable in a stop-everything context." That
    // inventory is wrong: `pwm_enable`/`pwm_disable` are also reachable
    // directly from ring 3 via `sys_pwm_enable`/`sys_pwm_disable`
    // (`crates/core/syscall/src/handlers.rs`), gated only by
    // `cap_check(HandleKind::Pwm(ch), true)` — a per-channel capability
    // that is a distinct, independently grantable object from
    // `HandleKind::Motor(id)` (see the topology-loader entry point at
    // `crates/core/ipc/src/pwm_cap.rs::grant`, "grant `tid` a `Cap<Pwm>` for
    // `channel`"). Nothing in that capability model knows that on this
    // (vf2) target the enable line is instance-wide, not per-channel.
    //
    // Concrete break: a task that holds ONLY `Pwm(2)` or `Pwm(3)` (no
    // `Motor(0)`/`Motor(1)`, no motor capability of any kind) can call
    // `sys_pwm_disable(2)` — which the cap check legitimately allows — and
    // silently kill channels 0 and 1 too, since all four channels share
    // one `PWMCFG` enable bit (see `pwm_disable` below). The same task can
    // later call `sys_pwm_enable(2)` to turn that shared bit back on.
    // `PWMCMP` (the per-channel duty register) is untouched by either call,
    // so whatever duty was last latched for channels 0/1 becomes live
    // again the instant the shared bit flips — and this path does not go
    // through `domains/robot/robot::motor::motor_set`'s e-stop/envelope gate
    // (installed in `52eeea7` for the duty-write path only): `sys_pwm_
    // enable`/`sys_pwm_disable` call straight into this driver.
    //
    // STATUS 2026-09-06: the syscall half of this is now CLOSED, and the
    // paragraph that used to stand here — "not fixed, needs an owner
    // decision" — is superseded. `sys_pwm_enable`/`sys_pwm_disable`/
    // `sys_pwm_set_freq` no longer ask "do you hold the channel you named?"
    // but "do you hold every channel this write reaches?", answered from
    // `crates/drivers/actuator/src/pwm_domain.rs`, which states that on this instance
    // a control write named for any channel reaches all four. A caller
    // holding only `Pwm(2)` is refused. It was LATENT rather than live:
    // `cap_check` fails closed for ring 3 (`handlers.rs`,
    // `handle_owned_by`), `SYS_HANDLE_GRANT` refuses any caller with a user
    // page table, and no in-tree config grants a bare `Pwm(ch)` — but the
    // topology loader exists to make such a grant possible, which is why
    // this is gated rather than argued away.
    //
    // STILL OPEN, and deliberately not papered over here: `pwm_enable`,
    // `pwm_disable` and `pwm_set_period` remain instance-wide for any
    // in-kernel caller, because this driver cannot see the caller's
    // capability table and `crates/drivers/actuator` must not depend on
    // `crates/core/ipc`. The buzzer no longer calls in here (wave 9): it runs in
    // ring 3 and reaches its channel only through the typed `Cap<Pwm>`
    // syscalls, whose reach check reads `pwm_domain::PWM_DOMAIN`. That
    // domain says the channels are independent, and this module (the SiFive
    // model, U05-1 above) writes a shared `PWMCFG` for enable, disable and
    // period — so on vf2 the two still disagree for every `Cap<Pwm>` holder
    // (`autorun`'s `pwm.4` as well as the buzzer's `pwm.5`) until this
    // module models the real IP.
    pub fn pwm_enable(ch: u32) -> i32 {
        if ch as usize >= PWM_MMIO_CHANNELS { return -1; }
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
        if ch as usize >= PWM_MMIO_CHANNELS { return -1; }
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
        if ch as usize >= PWM_MMIO_CHANNELS || period_ns == 0 { return -1; }
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
        if ch as usize >= PWM_MMIO_CHANNELS { return None; }
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
        if ch as usize >= PWM_MMIO_CHANNELS { return None; }
        let cfg = reg_read(PWMCFG);
        Some(PwmChannel {
            enabled:   cfg & CFG_EN_ALWAYS != 0,
            period_ns: 0, // would need to reverse-compute from the scale bitfield
            duty_ns:   0,
        })
    }

    pub fn pwm_info() {
        azos_drv_sys::kconsoleln!("[PWM] JH7110 SiFive PWM @ {:#010x} ({} channels, shared period)",
            PWM_BASE, PWM_MMIO_CHANNELS);
        let cfg = reg_read(PWMCFG);
        azos_drv_sys::kconsoleln!("[PWM]   shared CFG={:#010x} (scale={})", cfg, cfg & CFG_SCALE_MASK);
        for ch in 0..PWM_MMIO_CHANNELS as u32 {
            let cmp = reg_read(pwmcmp_offset(ch));
            azos_drv_sys::kconsoleln!("[PWM]   ch{}: CMP={:#06x}", ch, cmp);
        }
    }
}

#[cfg(feature = "vf2")]
pub use mmio::*;

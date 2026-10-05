// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Which PWM channels one control-register write actually reaches.
//!
//! # Why this module exists, and why it is separate from `pwm.rs`
//!
//! The capability model names a channel — `HandleKind::Pwm(ch)`,
//! `Cap<Pwm>` over a `resource_id` that is the channel number. The JH7110
//! hardware does not agree: `PWMCFG` is ONE register for the whole
//! four-channel instance, holding both the enable bit (`EN_ALWAYS`) and the
//! prescaler (`scale[3:0]`). So on `vf2`, `pwm_enable(2)`, `pwm_disable(2)`
//! and `pwm_set_period(2, _)` each reach channels 0, 1 and 3 as well.
//!
//! A per-object capability over a resource whose control register is shared
//! is not a per-object capability. This module states the hardware's actual
//! ownership domain so that the layer holding the caller's identity can ask
//! the right question: *not* "do you hold the channel you named?" but "do you
//! hold every channel this write will reach?".
//!
//! It is a separate file, and not a block at the top of `pwm.rs`, for one
//! concrete reason: `pwm.rs` calls `SpinLock::get_mut_unchecked` on its panic
//! path, and the host stand-in in `tests/host/cap-tests/shims/sync` deliberately
//! does not provide it (see the NOTE there — a faithful version would be UB
//! on the host). `tests/host/drivers-tests` pulls modules in with `#[path]`, so a
//! predicate living in `pwm.rs` would be unreachable from a host test. Here it
//! has no dependencies at all, and both hardware shapes are testable as plain
//! values with no feature gymnastics.
//!
//! Nothing in here touches MMIO. It is arithmetic over a description of the
//! hardware, which is exactly the part that is ours to get right.

/// The ownership shape of one PWM instance.
///
/// `shared_control` is the whole point: when it is true, the enable bit and
/// the prescaler live in a single register covering every channel of the
/// instance, so a write named for one channel is a write to all of them.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PwmDomain {
    /// Channels this instance actually has. Not the number a capability may
    /// *name* — see `PWM_DOMAIN_VF2_DRIVER` below, where those two differ.
    pub channels: u32,
    /// True when enable/period are one register shared by all `channels`.
    pub shared_control: bool,
}

impl PwmDomain {
    pub const fn new(channels: u32, shared_control: bool) -> Self {
        PwmDomain { channels, shared_control }
    }
}

/// Eight channels, each its own independent register block: a control
/// write named for one channel reaches only that channel. Two things have
/// this shape, and owner decision 2026-09-26 gave them ONE constant:
///
/// * **The JH7110 PWM (VisionFive 2), as hardware.** Its DT compatible is
///   `"starfive,jh7110-pwm", "opencores,pwm-v1"`, not any SiFive PWM (see
///   `platform::hw::PWM_BASE`'s doc and `pwm.rs`'s module doc). The
///   OpenCores PTC core that name points to (per the out-of-tree
///   `pwm-ocores.c` driver, not merged to Linux mainline as of this fetch)
///   gives each of 8 channels its own `CNTR`/`HRC`/`LRC`/`CTRL` block; there
///   is no instance-wide `PWMCFG`. This is the hardware fact, NOT what a
///   `vf2` build gates on today — see [`PWM_DOMAIN_VF2_DRIVER`].
/// * **The QEMU/K1 simulation in `pwm::sim`**: 8 `PwmChannel` records, a
///   write to one reaches only it. That is a claim about the code a `k1`
///   build compiles, not about K1 hardware. If a real `spacemit,k1x-pwm`
///   path is ever written, or the JH7110 turns out to differ on the board,
///   split this constant again: the two stopped being one fact.
pub const PWM_DOMAIN_INDEPENDENT_8: PwmDomain = PwmDomain::new(8, false);

/// The shape the `vf2` driver in THIS tree programs: `pwm.rs`'s SiFive-layout
/// model, 4 channels sharing one `PWMCFG`, so enable/disable/set-period named
/// for any channel reach all four. This is the domain a `vf2` build gates
/// capabilities against until `pwm.rs` implements the OpenCores PTC layout of
/// [`PWM_DOMAIN_INDEPENDENT_8`]; `pwm.rs` asserts at compile time that the two
/// agree, so the driver cannot change shape without this constant following.
/// When the OpenCores driver lands, `PWM_DOMAIN` below switches to
/// `PWM_DOMAIN_INDEPENDENT_8` and this constant goes.
pub const PWM_DOMAIN_VF2_DRIVER: PwmDomain = PwmDomain::new(4, true);

/// The domain of the instance this build actually drives.
#[cfg(feature = "vf2")]
pub const PWM_DOMAIN: PwmDomain = PWM_DOMAIN_VF2_DRIVER;
/// The domain of the instance this build actually drives.
#[cfg(not(feature = "vf2"))]
pub const PWM_DOMAIN: PwmDomain = PWM_DOMAIN_INDEPENDENT_8;

/// Bitmask of the channels that a control-register write named for `ch`
/// actually reaches.
///
/// "Control register" means enable/disable and period — the ones that live in
/// the shared `PWMCFG` on real hardware. It does **not** describe duty:
/// `PWMCMP` is genuinely per-channel on the JH7110, and `pwm_set_duty_pct`
/// writes only `pwmcmp_offset(ch)`.
///
/// Out-of-range `ch` reaches nothing and returns 0. That is deliberate rather
/// than an error: the driver entry points bound-check `ch` themselves and
/// return -1, and making this refuse instead would turn that -1 into an
/// `E_PERM` and hand a caller a way to map which channels exist by the
/// difference between the two.
pub fn pwm_control_reach(domain: PwmDomain, ch: u32) -> u32 {
    if ch >= domain.channels {
        return 0;
    }
    if domain.shared_control {
        // Every channel on the instance. `channels` is 4 or 8, so the shift
        // cannot reach 32 and this cannot overflow.
        (1u32 << domain.channels) - 1
    } else {
        1u32 << ch
    }
}

/// May a caller perform a control write named for `ch`?
///
/// `holds(c)` answers "does this caller hold write authority over channel
/// `c`?". The answer is yes only if it holds **every** channel the write
/// reaches — which on a shared-control instance means the whole instance, and
/// on an independent one means just `ch` itself.
///
/// An empty reach (out-of-range `ch`) is allowed for the reason given on
/// `pwm_control_reach`: nothing is reached, so nothing needs authority, and
/// the driver's own bound check produces the -1.
pub fn pwm_control_allowed<F: Fn(u32) -> bool>(domain: PwmDomain, ch: u32, holds: F) -> bool {
    let reach = pwm_control_reach(domain, ch);
    let mut c = 0u32;
    while c < domain.channels {
        if reach & (1u32 << c) != 0 && !holds(c) {
            return false;
        }
        c += 1;
    }
    true
}

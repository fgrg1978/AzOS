// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The effect kinds and classes on the gate's wire
//! (`crate::effect_gate::Effect`), in every build: a provider names its kind,
//! and a refusal its class, whether or not the image has the gate (Kconfig
//! `EFFECT_WRITE_AHEAD`).

/// How much an effect may be refused.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum Class {
    /// Toward the device's safe state; never refused.
    Safe = 0,
    /// Undoable by a later effect; refused when it cannot be recorded.
    Reversible = 1,
}

/// Effect kind: one wheel of the drivetrain (`motor_host.rs`).
pub const KIND_MOTOR: u8 = 1;

// The SoC resource frameworks (`azos_soc`): every clock, reset, rail, pin-mux
// and power-domain change is an effect of one of these kinds. The numbers are
// reserved here and equal `azos_soc::effect::KIND_*` (the kernel's adapter,
// `kernel/src/boot/soc.rs`, asserts it at compile time). For them `subject` is
// the framework's wire word (provider index in the high byte, op in the low
// byte), `a0` the clock, reset or domain id and `a1` the new value saturated
// to 32 bits (`azos_soc::effect::Effect::wire`). None has a deadline, a safe
// state or an inverse op: they are recorded, not watched.
/// Effect kind: a clock gate or rate.
pub const KIND_CLOCK: u8 = 2;
/// Effect kind: a reset line.
pub const KIND_RESET: u8 = 3;
/// Effect kind: a regulator rail.
pub const KIND_REGULATOR: u8 = 4;
/// Effect kind: a pin mux or bias.
pub const KIND_PINCTRL: u8 = 5;
/// Effect kind: a power domain.
pub const KIND_POWER_DOMAIN: u8 = 6;

/// Effect kind: a delete on a volume (an unlink, a rename over a file, a cut
/// below a file's size, the drop of a snapshot). Held to the Domain's `delete`
/// envelope row; see `crate::effect_gate`.
pub const KIND_STORAGE_DELETE: u8 = 7;
/// Effect kind: a Domain's first packet to a destination that is not this node.
/// Held to the Domain's `egress` envelope row; see `crate::effect_gate`.
pub const KIND_NET_EGRESS: u8 = 8;

/// Effect kind: a write of a configuration key. Held to the Domain's `config`
/// envelope row; see `crate::effect_gate`.
pub const KIND_CONFIG_WRITE: u8 = 9;
/// Effect kind: a step of applying an update (stage, switch). Held to the
/// Domain's `ota` envelope row; see `crate::effect_gate`.
pub const KIND_OTA_APPLY: u8 = 10;
/// Effect kind: a real-time reservation. Held to the Domain's `rt_time`
/// envelope row; see `crate::effect_gate`.
pub const KIND_RT_TIME: u8 = 11;

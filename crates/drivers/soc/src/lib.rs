// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! SoC resource frameworks (HAL H2): what a driver asks the SoC for before it
//! can touch its device. Five frameworks, one shape each:
//!
//! | framework | consumer property | provider trait | manager |
//! |---|---|---|---|
//! | clock tree | `clocks` / `clock-names` | [`clk::ClockOps`] | [`clk::ClockTree`] |
//! | reset lines | `resets` / `reset-names` | [`reset::ResetOps`] | [`reset::Resets`] |
//! | regulators | `<name>-supply` | [`regulator::RegulatorOps`] | [`regulator::Regulators`] |
//! | pin control | `pinctrl-names`, `pinctrl-N` | [`pinctrl::PinctrlOps`] | [`pinctrl::Pinctrl`] |
//! | power domains | `power-domains` / `power-domain-names` | [`pd::PowerDomainOps`] | [`pd::PowerDomains`] |
//!
//! A provider is the hardware half: it knows its registers and nothing about
//! reference counts. A manager is the policy half: it resolves the consumer's
//! phandle properties to a provider ([`consumer`]), counts users, walks the
//! parent chain parents-first, and commits every change to an
//! [`effect::EffectSink`] before the register write.
//!
//! Providers here: [`fixed`] (`fixed-clock`, `regulator-fixed`), the
//! StarFive [`jh7110`] system clock and reset controller, power-management
//! unit and system/always-on pad controllers, and the SpacemiT [`k1`] CPU
//! cluster clocks (with the PLL tree under them) and P1 PMIC bucks.
//!
//! Register access is one trait, [`Bus`], over physical addresses; the
//! kernel implements it with volatile accesses, the tests with a trace. A
//! rail behind a PMIC is reached over [`I2cMasters`] instead, through the
//! regulator framework's [`regulator::Io`].
//!
//! No allocator, no locks, no statics: the caller owns the providers and the
//! managers and serialises access to them (every operation takes `&mut`).

#![no_std]
#![forbid(unsafe_code)]

pub mod bind;
pub mod boot;
pub mod clk;
pub mod consumer;
pub mod effect;
pub mod fdt;
pub mod fixed;
pub mod jh7110;
pub mod k1;
pub mod pd;
pub mod pinctrl;
pub mod regulator;
pub mod reset;

pub use effect::{Class, Effect, EffectSink, Op, Refused};
pub use fdt::{Fdt, NodeId};

/// 32-bit register access at a physical address.
pub trait Bus {
    fn read32(&mut self, addr: u64) -> u32;
    fn write32(&mut self, addr: u64, val: u32);
}

/// The I2C devices the providers that are not memory-mapped (a PMIC) reach:
/// a device is found by its master and its address, and the chip logic talks
/// to the [`azos_devif::I2cCall`] it gets, one-byte registers at one-byte
/// addresses. The frameworks do not fake it as a [`Bus`] word at some address,
/// because a transfer can fail (no acknowledge, a wedged bus, a timeout) and
/// takes time.
///
/// `ctrl` names the master by the physical base of its register window (the
/// `reg` of its device-tree node), which is how the node is identified in the
/// tree; the implementation maps it to its own controller. A transfer that
/// the device did not acknowledge or that did not finish is
/// [`Error::Hardware`] (the call's refusal), a master the image does not have
/// or has not attached is [`Error::Unsupported`] (no device).
pub trait I2cMasters {
    /// Is there a master for `ctrl` now? `false` before the kernel has
    /// attached it (a rail behind it is deferred, not failed, see
    /// [`regulator::Regulators::enable_always_on`], pinned later by
    /// `boot::Soc::retry_always_on`) and for a master the image
    /// does not have.
    fn present(&self, ctrl: u64) -> bool;
    /// The call bound to the device at 7-bit address `addr` behind `ctrl`;
    /// `None` when [`I2cMasters::present`] is false.
    fn device(&mut self, ctrl: u64, addr: u8) -> Option<&mut dyn azos_devif::I2cCall>;
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Error {
    /// The property, name or phandle is not in the tree.
    NotFound,
    /// A specifier that does not fit its provider's `#...-cells`, or a
    /// number the provider does not have.
    BadSpec,
    /// The node a phandle names has no provider registered.
    NoProvider,
    /// A manager has no free slot (providers, or a clock number past the
    /// table).
    Full,
    /// The provider cannot do that.
    Unsupported,
    /// A release without a matching acquire.
    Unbalanced,
    /// The request is outside the DT constraints.
    Constraint,
    /// The hardware did not settle within the poll budget.
    Timeout,
    /// The hardware reported a failure or an impossible state.
    Hardware,
    /// A clock's parent chain is deeper than the bound, or loops.
    Depth,
    /// The effect sink refused (the receipt).
    Refused(u64),
}

pub type Result<T> = core::result::Result<T, Error>;

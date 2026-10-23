// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! StarFive JH7110 (VisionFive 2): the system clock and reset controller
//! (`starfive,jh7110-syscrg`, the same node serves clocks and resets), the
//! PLLs that feed it (`starfive,jh7110-pll`), the power-management unit (`starfive,jh7110-pmu`), and the pad controllers of
//! the system and always-on blocks (`starfive,jh7110-sys-pinctrl`,
//! `starfive,jh7110-aon-pinctrl`).
//!
//! The register models are checked line by line against the JH7110 Technical
//! Reference Manual (StarFive, Preliminary V2): "System Control Registers"
//! (SYS CRG, STG CRG, AON CRG, SYS IOMUX CFG, AON IOMUX CFG) and "Power
//! Management" (PMU). Each module says which tables confirm what; what the
//! TRM does not settle carries a `[verify]` tag next to the number and needs
//! a board. The register sequences are tested against a hand-written trace
//! of what the model must write, not against a board.

pub mod clk;
pub mod iomux;
pub mod pll;
pub mod pmu;
pub mod rst;

pub use clk::{Jh7110Clk, SYSCRG_COMPATIBLE};
pub use pll::{Jh7110Pll, PLL_COMPATIBLE};
pub use iomux::{Jh7110Iomux, AON_IOMUX_COMPATIBLE, SYS_IOMUX_COMPATIBLE};
pub use pmu::{Jh7110Pmu, PMU_COMPATIBLE};
pub use rst::Jh7110Reset;

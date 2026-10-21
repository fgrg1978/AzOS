// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! SpacemiT K1 (BananaPi BPI-F3, Milk-V Jupiter): the providers the CPU
//! clusters' DVFS needs, and nothing more.
//!
//! * [`clk`]: the APMU CPU cluster clocks and the PLL tree under them
//!   (`spacemit,k1-syscon-apmu`, with the PLL block `spacemit,k1-pll` and the
//!   MPMU lock register behind it). One provider: the parents of a cluster
//!   clock are not DT `clocks` (Linux wires them by pointer), so they are
//!   local clocks of the one provider.
//! * [`p1`]: the buck converters of the SpacemiT P1 PMIC
//!   (`spacemit,p1` on I2C, `regulators/buckN`), over [`crate::I2cBus`].
//!
//! Reference (read for facts, no code copied): Linux v7.3,
//! `drivers/clk/spacemit/{ccu-k1.c,ccu_pll.c,ccu_mix.c,ccu_common.c}`,
//! `drivers/regulator/spacemit-p1.c`, `include/soc/spacemit/k1-syscon.h`,
//! `include/dt-bindings/clock/spacemit,k1-syscon.h` and
//! `arch/riscv/boot/dts/spacemit/{k1.dtsi,k1-opp.dtsi,k1-milkv-jupiter.dts}`.
//! Every register, bit and value in these files names the file it came from.
//! What those files do not settle carries a `[verify]` tag and is listed in
//! `Documentation/energy.md` for the board.

pub mod clk;
pub mod p1;

pub use clk::{K1Clk, APMU_COMPATIBLE, PLL_COMPATIBLE};
pub use p1::{P1Buck, P1_COMPATIBLE};

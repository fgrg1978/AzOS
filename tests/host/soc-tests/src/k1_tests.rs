// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The SpacemiT K1 providers (`azos_soc::k1`) on the Milk-V Jupiter tree
//! (`fixtures/k1-jupiter.dts`): the CPU cluster clocks and the PLL tree under
//! them against a register model that behaves the way `ccu_mix.c` and
//! `ccu_pll.c` say the hardware does (the FC bit clears itself, the PLL lock
//! bits are in another block), the P1 bucks against a PMIC that holds
//! registers, and the whole DVFS path (`azos_thermal::k1`) over both.
//!
//! The registers are the Linux v7.3 ones the provider files cite; this file
//! pins the provider to them, it does not confirm them on a board.
//!
//! Canaries, one property broken each (the named rows must FAIL):
//! * take `CORE_FC` out of `K1Clk::set_rate` (`crates/drivers/soc/src/k1/clk.rs`):
//!   `a_cluster_switch_selects_then_triggers_the_frequency_change`;
//! * let `best` skip the `running` test: `an_input_that_is_not_running_is_never_selected`;
//! * drop the readback in `P1Buck::set_voltage`: `a_buck_that_ignores_the_write_is_a_hardware_error`.
use crate::support::*;
use azos_dtb::dtb_energy;
use azos_energy::model::Opp;
use azos_energy::opp::{ActuateError, OppActuator};
use azos_soc::bind;
use azos_soc::boot::{Families, Soc, Storage};
use azos_soc::clk::Clk;
use azos_soc::consumer::Sel;
use azos_soc::effect::{KIND_CLOCK, KIND_REGULATOR};
use azos_soc::fdt::Fdt;
use azos_soc::k1::p1::{sel_to_uv, uv_to_sel};
use azos_soc::regulator::Io;
use azos_soc::{Error, I2cBus, Result};
use azos_thermal::k1::{K1Opp, MAX_K1_DOMAINS};
use azos_thermal::k1_soc::{k1_plan, K1Clocks, SocK1Hw};
use std::cell::Cell;
use std::rc::Rc;

const K1: Families = Families { jh7110: false, k1: true };

const APMU: u64 = 0xd428_2800;
const MPMU: u64 = 0xd405_0000;
const PLL: u64 = 0xd409_0000;
const I2C8: u64 = 0xd401_d800;
const C0_CTRL: u64 = APMU + 0x38c;
const C1_CTRL: u64 = APMU + 0x390;
const FC: u32 = 1 << 12;
const POSR: u64 = MPMU + 0x10;
const ACGR: u64 = MPMU + 0x1024;
const PMIC: u8 = 0x41;
/// Tags a P1 register in the shared log: `1 << 40 | addr << 8 | reg`.
const I2C_TAG: u64 = 1 << 40;

fn jupiter() -> Vec<u8> {
    include_bytes!("../fixtures/k1-jupiter.dtb").to_vec()
}

/// The machine as the firmware leaves it (all values from `ccu-k1.c`):
/// PLL1 2457.6 MHz, PLL2 3 GHz, PLL3 3.2 GHz, all enabled and locked, the
/// `pll1_dN` gates and the five MPMU gates open, `pll2_d3` and `pll3_d1..3`
/// open; cluster 0 on `pll1_d2` (1228.8 MHz), cluster 1 on HI = `pll3_d2`
/// (1.6 GHz).
fn booted(log: &Rc<Log>) -> TraceBus {
    TraceBus::new(log)
        .with(POSR, (1 << 27) | (1 << 28) | (1 << 29))
        .with(PLL + 0x100, 0x0050_dd64)
        .with(PLL + 0x104, 0b11_1110)
        .with(PLL + 0x108, 0x330c_cccd | 1 << 31)
        .with(PLL + 0x118, 0x0050_dd66)
        .with(PLL + 0x11c, 1 << 2)
        .with(PLL + 0x120, 0x3fe0_0000 | 1 << 31)
        .with(PLL + 0x124, 0x0050_dd67)
        .with(PLL + 0x128, 0b111)
        .with(PLL + 0x12c, 0x43ea_aaab | 1 << 31)
        .with(ACGR, (1 << 0) | (1 << 14) | (1 << 15) | (1 << 16) | (1 << 21))
        .with(C0_CTRL, 4)
        .with(C1_CTRL, 7)
        // The frequency-change bit clears itself (`ccu_mix_trigger_fc` polls it).
        .hook(Box::new(|regs, addr, val| {
            if (addr == C0_CTRL || addr == C1_CTRL) && val & FC != 0 {
                regs.insert(addr, val & !FC);
            }
        }))
}

/// The P1: 256 byte registers behind the I2C master of `i2c@d401d800`, every
/// access in the shared log.
struct P1Chip {
    regs: [u8; 256],
    log: Rc<Log>,
    /// The device does not acknowledge.
    nak: bool,
    /// Writes are acknowledged and dropped.
    deaf: bool,
    /// The master is not attached yet (the kernel attaches it after the
    /// frameworks come up).
    unattached: bool,
    transfers: Rc<Cell<u32>>,
}

impl P1Chip {
    /// Buck 1 at 1.05 V and enabled, buck 2 at 0.95 V enabled, the rest at
    /// 1.8 V enabled (bucks 3..6: the selectors do not matter here).
    fn booted(log: &Rc<Log>) -> Self {
        let mut regs = [0u8; 256];
        for n in 0..6u8 {
            regs[0x47 + 3 * n as usize] = 1;
            regs[0x48 + 3 * n as usize] = 140;
        }
        regs[0x48] = 110; // 1_050_000
        regs[0x4b] = 90; // 950_000
        P1Chip { regs, log: log.clone(), nak: false, deaf: false, unattached: false, transfers: Rc::new(Cell::new(0)) }
    }
    fn at(&self, reg: u8) -> u64 {
        I2C_TAG | (PMIC as u64) << 8 | reg as u64
    }
    fn check(&self, ctrl: u64, addr: u8) -> Result<()> {
        if self.unattached {
            return Err(Error::Unsupported);
        }
        if ctrl != I2C8 || addr != PMIC || self.nak {
            return Err(Error::Hardware);
        }
        Ok(())
    }
}

impl I2cBus for P1Chip {
    fn present(&self, ctrl: u64) -> bool {
        ctrl == I2C8 && !self.unattached
    }
    fn read_reg(&mut self, ctrl: u64, addr: u8, reg: u8) -> Result<u8> {
        self.check(ctrl, addr)?;
        self.transfers.set(self.transfers.get() + 1);
        self.log.0.borrow_mut().push(Ev::R(self.at(reg)));
        Ok(self.regs[reg as usize])
    }
    fn write_reg(&mut self, ctrl: u64, addr: u8, reg: u8, val: u8) -> Result<()> {
        self.check(ctrl, addr)?;
        self.transfers.set(self.transfers.get() + 1);
        self.log.0.borrow_mut().push(Ev::W(self.at(reg), val as u32));
        if !self.deaf {
            self.regs[reg as usize] = val;
        }
        Ok(())
    }
}

fn cpu_core(fdt: &Fdt<'_>, soc: &Soc<'_>, cpu: usize) -> Clk {
    let node = by_path(fdt, &format!("/cpus/cpu@{cpu}")).unwrap();
    soc.clocks.get(fdt, node, Sel::Index(0)).unwrap()
}

macro_rules! rig {
    ($blob:ident, $fdt:ident, $log:ident, $st:ident, $bus:ident, $fx:ident, $chip:ident, $soc:ident) => {
        let $blob = jupiter();
        let $fdt = Fdt::parse(&$blob).unwrap();
        let $log = Log::new();
        let mut $st = Storage::new();
        $st.scan(&$fdt, K1);
        let mut $bus = booted(&$log);
        let mut $fx = Sink::new(&$log);
        let mut $chip = P1Chip::booted(&$log);
        #[allow(unused_mut)]
        let mut $soc = Soc::build(&mut $st, &$fdt, &mut Io { bus: &mut $bus, i2c: Some(&mut $chip) }, &mut $fx);
    };
}

// ---- what the boot step registers ----

#[test]
fn the_tree_gives_one_clock_complex_with_three_windows_and_the_pmic_bucks() {
    let blob = jupiter();
    let fdt = Fdt::parse(&blob).unwrap();
    let mut st = Storage::new();
    st.scan(&fdt, K1);
    let mut mapped = Vec::new();
    let w = st.map_windows(&fdt, |base, size| {
        mapped.push((base, size));
        true
    });
    // APMU (the node), the PLL block and the MPMU the PLL node names: every
    // register the CPU clock path touches, and nothing else (the I2C master's
    // window belongs to whoever drives the master).
    assert_eq!(mapped, [(APMU, 0x400), (PLL, 0x1000), (MPMU, 0x209c)]);
    assert_eq!(w.failed, 0);

    let log = Log::new();
    let mut bus = booted(&log);
    let mut fx = Sink::new(&log);
    let mut chip = P1Chip::booted(&log);
    let soc = Soc::build(&mut st, &fdt, &mut Io { bus: &mut bus, i2c: Some(&mut chip) }, &mut fx);
    let r = soc.report;
    // K1 complex + the four board crystals; two fixed rails + six bucks (the
    // LDO is not a provider).
    assert_eq!((r.clocks, r.regulators, r.dropped, r.no_transport), (5, 8, 0, 0), "{r:?}");
    assert_eq!(r.always_on, Ok(8));
}

#[test]
fn a_provider_whose_window_is_refused_takes_the_whole_complex_with_it() {
    let blob = jupiter();
    let fdt = Fdt::parse(&blob).unwrap();
    let mut st = Storage::new();
    st.scan(&fdt, K1);
    // The MPMU (the lock register) is the third window.
    let w = st.map_windows(&fdt, |base, _| base != MPMU);
    assert_eq!(w.failed, 1);
    let log = Log::new();
    let mut bus = booted(&log);
    let mut fx = Sink::new(&log);
    let soc = Soc::build(&mut st, &fdt, &mut Io { bus: &mut bus, i2c: None }, &mut fx);
    // The four crystals stay; the complex does not.
    assert_eq!(soc.report.clocks, 4);
    assert_eq!(soc.report.dropped, 1);
}

#[test]
fn without_an_i2c_master_the_pmic_rails_are_not_providers() {
    let blob = jupiter();
    let fdt = Fdt::parse(&blob).unwrap();
    let log = Log::new();
    let mut st = Storage::new();
    st.scan(&fdt, K1);
    let mut bus = booted(&log);
    let mut fx = Sink::new(&log);
    let mut soc = Soc::build(&mut st, &fdt, &mut Io { bus: &mut bus, i2c: None }, &mut fx);
    let r = soc.report;
    // Only the two fixed rails; the six bucks are counted, and the
    // always-on pass did not trip on them.
    assert_eq!((r.regulators, r.no_transport), (2, 6));
    assert_eq!(r.always_on, Ok(2));
    let cpu = by_path(&fdt, "/cpus/cpu@0").unwrap();
    assert_eq!(soc.regulators.get_supply(&fdt, cpu, "cpu"), Err(Error::NoProvider));
    let _ = &mut soc;
}

// ---- the clocks ----

#[test]
fn the_cluster_clocks_read_back_what_the_registers_select() {
    rig!(blob, fdt, log, st, bus, fx, chip, soc);
    let c0 = cpu_core(&fdt, &soc, 0);
    let c1 = cpu_core(&fdt, &soc, 4);
    // Device-tree ids 2 and 6 (`CLK_CPU_C0_CORE`, `CLK_CPU_C1_CORE`), provider 1... whichever slot:
    assert_eq!((c0.id, c1.id), (2, 6));
    assert_eq!(soc.clocks.rate(&mut bus, c0), Ok(1_228_800_000), "pll1_d2_1228p8");
    assert_eq!(soc.clocks.rate(&mut bus, c1), Ok(1_600_000_000), "HI = pll3_d2 of 3.2 GHz");
    // The chain, leaf to root: core, gate, factor-gate, PLL, crystal.
    let g = soc.clocks.parent(&mut bus, c0).unwrap().unwrap();
    let d = soc.clocks.parent(&mut bus, g).unwrap().unwrap();
    let p = soc.clocks.parent(&mut bus, d).unwrap().unwrap();
    let x = soc.clocks.parent(&mut bus, p).unwrap().unwrap();
    assert_eq!((g.id, d.id, p.id), (64 + 12, 64 + 3, 64), "pll1_d2_1228p8 <- pll1_d2 <- pll1");
    assert_eq!(soc.clocks.rate(&mut bus, x), Ok(24_000_000), "the crystal");
    // HI is a clock of its own with its own select.
    let hi = soc.clocks.parent(&mut bus, c1).unwrap().unwrap();
    assert_eq!(hi.id, 5);
    let _ = (&mut fx, &log);
}

#[test]
fn a_pll_that_matches_no_table_row_reports_rate_zero() {
    rig!(blob, fdt, log, st, bus, fx, chip, soc);
    bus.regs.insert(PLL + 0x124, 0x1234_5678);
    let c1 = cpu_core(&fdt, &soc, 4);
    assert_eq!(soc.clocks.rate(&mut bus, c1), Ok(0));
    let _ = (&mut fx, &log);
}

#[test]
fn a_cluster_switch_selects_then_triggers_the_frequency_change() {
    rig!(blob, fdt, log, st, bus, fx, chip, soc);
    let c0 = cpu_core(&fdt, &soc, 0);
    log.clear();
    // 1 GHz is exactly `pll2_d3` (select 6).
    assert_eq!(soc.clocks.set_rate(&mut bus, &mut fx, c0, 1_000_000_000), Ok(1_000_000_000));
    let writes = log.writes();
    assert_eq!(writes, [(C0_CTRL, 6), (C0_CTRL, 6 | FC)], "the select field first, then FC");
    // The record is on the ring before the first register write.
    let all = log.all();
    let first_w = all.iter().position(|e| matches!(e, Ev::W(..))).unwrap();
    let rec = all.iter().position(|e| matches!(e, Ev::E(x) if x.kind == KIND_CLOCK)).unwrap();
    assert!(rec < first_w, "{all:?}");
    // The hardware cleared FC; the clock now reads 1 GHz.
    assert_eq!(bus.regs[&C0_CTRL], 6);
    assert_eq!(soc.clocks.rate(&mut bus, c0), Ok(1_000_000_000));
}

#[test]
fn the_request_goes_to_the_closest_running_input_and_ties_go_low() {
    rig!(blob, fdt, log, st, bus, fx, chip, soc);
    let c0 = cpu_core(&fdt, &soc, 0);
    // 819 MHz (the DT's number) is `pll1_d3_819p2`: 0.2 MHz away.
    assert_eq!(soc.clocks.round_rate(&mut bus, c0, 819_000_000), Ok(819_200_000));
    assert_eq!(soc.clocks.set_rate(&mut bus, &mut fx, c0, 819_000_000), Ok(819_200_000));
    assert_eq!(soc.clocks.rate(&mut bus, c0), Ok(819_200_000));
    // 1.6 GHz: HI.
    assert_eq!(soc.clocks.set_rate(&mut bus, &mut fx, c0, 1_600_000_000), Ok(1_600_000_000));
    assert_eq!(bus.regs[&C0_CTRL] & 7, 7);
    // Exactly between 491.52 (sel 3) and 614.4 (sel 0) is not in the table,
    // but 552.96 MHz is: the lower one wins.
    assert_eq!(soc.clocks.round_rate(&mut bus, c0, 552_960_000), Ok(491_520_000));
    let _ = &chip;
}

#[test]
fn a_rate_already_selected_writes_nothing() {
    rig!(blob, fdt, log, st, bus, fx, chip, soc);
    let c0 = cpu_core(&fdt, &soc, 0);
    log.clear();
    assert_eq!(soc.clocks.set_rate(&mut bus, &mut fx, c0, 1_228_800_000), Ok(1_228_800_000));
    assert!(log.writes().is_empty(), "{:?}", log.writes());
    // Rounding writes nothing either, and records nothing.
    log.clear();
    assert_eq!(soc.clocks.round_rate(&mut bus, c0, 614_400_000), Ok(614_400_000));
    assert!(log.writes().is_empty() && log.effects().is_empty());
    let _ = &chip;
}

#[test]
fn an_input_that_is_not_running_is_never_selected() {
    rig!(blob, fdt, log, st, bus, fx, chip, soc);
    let c0 = cpu_core(&fdt, &soc, 0);
    // The 819.2 MHz gate closes: 819 MHz is now 1 GHz (181 MHz) not 614.4 (204.6).
    bus.regs.insert(ACGR, bus.regs[&ACGR] & !(1 << 14));
    assert_eq!(soc.clocks.round_rate(&mut bus, c0, 819_000_000), Ok(1_000_000_000));
    // PLL2 goes unlocked: 1 GHz is gone with it, 614.4 is next.
    bus.regs.insert(POSR, bus.regs[&POSR] & !(1 << 28));
    assert_eq!(soc.clocks.round_rate(&mut bus, c0, 819_000_000), Ok(614_400_000));
    // The factor-gate of PLL1's /4 closes under the MPMU gate: 614.4 is gone,
    // and `pll3_d3` (3.2 GHz / 3) is the nearest that runs.
    bus.regs.insert(PLL + 0x104, bus.regs[&(PLL + 0x104)] & !(1 << 3));
    assert_eq!(soc.clocks.round_rate(&mut bus, c0, 819_000_000), Ok(1_066_666_666));
    let _ = (&mut fx, &chip, &log);
}

#[test]
fn with_no_input_running_the_request_is_refused_and_nothing_is_written() {
    rig!(blob, fdt, log, st, bus, fx, chip, soc);
    let c0 = cpu_core(&fdt, &soc, 0);
    for off in [0x108u64, 0x120, 0x12c] {
        bus.regs.insert(PLL + off, bus.regs[&(PLL + off)] & !(1 << 31));
    }
    log.clear();
    assert_eq!(soc.clocks.set_rate(&mut bus, &mut fx, c0, 1_000_000_000), Err(Error::Constraint));
    assert!(log.writes().is_empty());
    let _ = &chip;
}

#[test]
fn a_frequency_change_that_never_completes_times_out() {
    rig!(blob, fdt, log, st, bus, fx, chip, soc);
    // A bus whose FC bit never clears.
    let mut stuck = booted(&log).hook(Box::new(|_, _, _| {}));
    let c0 = cpu_core(&fdt, &soc, 0);
    assert_eq!(soc.clocks.set_rate(&mut stuck, &mut fx, c0, 1_000_000_000), Err(Error::Timeout));
    let _ = (&mut bus, &chip);
}

#[test]
fn a_pll_enable_waits_for_the_lock_bit_in_the_other_block() {
    rig!(blob, fdt, log, st, bus, fx, chip, soc);
    // PLL2 off and unlocked; the lock bit comes up when the enable bit is set.
    let mut b = booted(&log).hook(Box::new(|regs, addr, val| {
        if addr == PLL + 0x120 && val & (1 << 31) != 0 {
            let p = regs[&POSR];
            regs.insert(POSR, p | 1 << 28);
        }
    }));
    b.regs.insert(PLL + 0x120, 0x3fe0_0000);
    b.regs.insert(POSR, (1 << 27) | (1 << 29));
    let c0 = cpu_core(&fdt, &soc, 0);
    let pll2 = Clk { prov: c0.prov, id: 65 };
    assert_eq!(soc.clocks.is_enabled(&mut b, pll2), Ok(false));
    soc.clocks.enable(&mut b, &mut fx, pll2).unwrap();
    assert_eq!(soc.clocks.is_enabled(&mut b, pll2), Ok(true));
    assert!(b.regs[&POSR] & (1 << 28) != 0);
    // A PLL that never locks is a timeout and nothing is counted.
    let pll3 = Clk { prov: c0.prov, id: 66 };
    let mut dead = booted(&log);
    dead.regs.insert(PLL + 0x12c, 0x43ea_aaab);
    dead.regs.insert(POSR, 0);
    assert_eq!(soc.clocks.enable(&mut dead, &mut fx, pll3), Err(Error::Timeout));
    assert_eq!(soc.clocks.refs(pll3), 0);
    let _ = (&mut bus, &chip);
}

#[test]
fn a_consumer_of_a_clock_the_provider_does_not_model_is_skipped_not_failed() {
    rig!(blob, fdt, log, st, bus, fx, chip, soc);
    let usb = by_path(&fdt, "/soc/usb@c0a00000").unwrap();
    // `clocks = <&syscon_apmu 16>` (CLK_USB30): the controller is a provider,
    // the clock is not modelled.
    let a = bind::bind(&mut soc, &fdt, &mut bus, &mut fx, usb).unwrap();
    assert_eq!((a.clocks, a.unmodelled), (0, 1));
    let _ = (&chip, &log);
}

#[test]
fn the_tsensor_binds_with_its_apbc_resources_left_to_the_firmware() {
    rig!(blob, fdt, log, st, bus, fx, chip, soc);
    // `clocks = <&syscon_apbc 48>, <&syscon_apbc 98>` and `resets = <&syscon_apbc 48>`:
    // the APBC controller has no provider, so all three are "not modelled"
    // and the bind succeeds without touching a register. That is the contract
    // the kernel's `k1-tsensor` probe relies on (its clock and reset are the
    // firmware's, Documentation/energy.md).
    let node = by_path(&fdt, "/soc/thermal@d4018000").unwrap();
    log.clear();
    let a = bind::bind(&mut soc, &fdt, &mut bus, &mut fx, node).unwrap();
    assert_eq!(a, bind::Applied { unmodelled: 3, ..Default::default() });
    assert!(log.all().is_empty(), "{:?}", log.all());
    let _ = &chip;
}

// ---- the P1 ----

#[test]
fn the_buck_selectors_follow_the_two_linear_ranges() {
    assert_eq!(sel_to_uv(0), Some(500_000));
    assert_eq!(sel_to_uv(90), Some(950_000));
    assert_eq!(sel_to_uv(110), Some(1_050_000));
    assert_eq!(sel_to_uv(170), Some(1_350_000));
    assert_eq!(sel_to_uv(171), Some(1_375_000));
    assert_eq!(sel_to_uv(254), Some(3_450_000));
    assert_eq!(sel_to_uv(255), None, "255 disables the buck in sleep");
    for sel in 0..=254u8 {
        assert_eq!(uv_to_sel(sel_to_uv(sel).unwrap()), Some(sel));
    }
    // Between the grid points, below the floor, in the gap, over the top.
    for uv in [952_500, 499_999, 1_360_000, 1_380_000, 3_475_000, 0] {
        assert_eq!(uv_to_sel(uv), None, "{uv}");
    }
}

#[test]
fn a_buck_reads_its_selector_and_its_ramp_comes_from_the_node() {
    rig!(blob, fdt, log, st, bus, fx, chip, soc);
    let cpu = by_path(&fdt, "/cpus/cpu@0").unwrap();
    let rail = soc.regulators.get_supply(&fdt, cpu, "cpu").unwrap();
    let c = soc.regulators.constraints(rail).unwrap();
    assert_eq!((c.min_uv, c.max_uv, c.ramp_uv_per_us, c.always_on), (500_000, 1_050_000, 5_000, true));
    log.clear();
    let mut io = Io { bus: &mut bus, i2c: Some(&mut chip) };
    assert_eq!(soc.regulators.voltage(&mut io, rail), Ok(1_050_000));
    assert_eq!(log.all(), [Ev::R(I2C_TAG | 0x41 << 8 | 0x48)], "one register read at 0x48");
    // The selector 255 is not a voltage.
    io.i2c.as_mut().unwrap().write_reg(I2C8, PMIC, 0x48, 255).unwrap();
    assert_eq!(soc.regulators.voltage(&mut io, rail), Err(Error::Hardware));
    let _ = &mut fx;
}

#[test]
fn a_voltage_is_written_to_the_selector_and_read_back() {
    rig!(blob, fdt, log, st, bus, fx, chip, soc);
    let cpu = by_path(&fdt, "/cpus/cpu@0").unwrap();
    let rail = soc.regulators.get_supply(&fdt, cpu, "cpu").unwrap();
    log.clear();
    let mut io = Io { bus: &mut bus, i2c: Some(&mut chip) };
    assert_eq!(soc.regulators.set_voltage(&mut io, &mut fx, rail, 950_000, 950_000), Ok(950_000));
    let all = log.all();
    // Record, selector write, readback.
    assert!(matches!(all[0], Ev::E(e) if e.kind == KIND_REGULATOR), "{all:?}");
    assert_eq!(all[1], Ev::W(I2C_TAG | 0x41 << 8 | 0x48, 90));
    assert_eq!(all[2], Ev::R(I2C_TAG | 0x41 << 8 | 0x48));
    // Off the 5 mV grid: the provider refuses, the register is untouched.
    log.clear();
    assert_eq!(soc.regulators.set_voltage(&mut io, &mut fx, rail, 952_500, 952_500), Err(Error::Constraint));
    assert!(log.writes().is_empty());
    // Over the node's maximum: the framework refuses before the provider is asked.
    assert_eq!(soc.regulators.set_voltage(&mut io, &mut fx, rail, 1_100_000, 1_100_000), Err(Error::Constraint));
    assert!(log.writes().is_empty());
}

#[test]
fn a_buck_that_ignores_the_write_is_a_hardware_error() {
    rig!(blob, fdt, log, st, bus, fx, chip, soc);
    let cpu = by_path(&fdt, "/cpus/cpu@0").unwrap();
    let rail = soc.regulators.get_supply(&fdt, cpu, "cpu").unwrap();
    chip.deaf = true;
    let mut io = Io { bus: &mut bus, i2c: Some(&mut chip) };
    assert_eq!(soc.regulators.set_voltage(&mut io, &mut fx, rail, 950_000, 950_000), Err(Error::Hardware));
    let _ = &log;
}

#[test]
fn a_pmic_that_does_not_answer_is_a_hardware_error_and_nothing_else_moves() {
    rig!(blob, fdt, log, st, bus, fx, chip, soc);
    let cpu = by_path(&fdt, "/cpus/cpu@0").unwrap();
    let rail = soc.regulators.get_supply(&fdt, cpu, "cpu").unwrap();
    chip.nak = true;
    let mut io = Io { bus: &mut bus, i2c: Some(&mut chip) };
    assert_eq!(soc.regulators.voltage(&mut io, rail), Err(Error::Hardware));
    assert_eq!(soc.regulators.is_enabled(&mut io, rail), Err(Error::Hardware));
    let _ = (&mut fx, &log);
}

#[test]
fn the_always_on_pass_does_not_write_a_buck_the_firmware_left_on() {
    let blob = jupiter();
    let fdt = Fdt::parse(&blob).unwrap();
    let log = Log::new();
    let mut st = Storage::new();
    st.scan(&fdt, K1);
    let mut bus = booted(&log);
    let mut fx = Sink::new(&log);
    let mut chip = P1Chip::booted(&log);
    log.clear();
    let soc = Soc::build(&mut st, &fdt, &mut Io { bus: &mut bus, i2c: Some(&mut chip) }, &mut fx);
    assert_eq!(soc.report.always_on, Ok(8));
    // Six bucks read, none written (the enable bit is already set).
    assert!(log.writes().is_empty(), "{:?}", log.writes());
    assert_eq!(log.reads().len(), 6);
    // And one that was off is switched on with one read-modify-write.
    let mut st = Storage::new();
    st.scan(&fdt, K1);
    let mut chip = P1Chip::booted(&log);
    chip.regs[0x47] = 0;
    log.clear();
    let soc = Soc::build(&mut st, &fdt, &mut Io { bus: &mut bus, i2c: Some(&mut chip) }, &mut fx);
    assert_eq!(soc.report.always_on, Ok(8));
    assert_eq!(log.writes(), [(I2C_TAG | 0x41 << 8 | 0x47, 1)]);
}

#[test]
fn one_dead_rail_does_not_keep_the_others_off() {
    let blob = jupiter();
    let fdt = Fdt::parse(&blob).unwrap();
    let log = Log::new();
    let mut st = Storage::new();
    st.scan(&fdt, K1);
    let mut bus = booted(&log);
    let mut fx = Sink::new(&log);
    let mut chip = P1Chip::booted(&log);
    chip.nak = true;
    let soc = Soc::build(&mut st, &fdt, &mut Io { bus: &mut bus, i2c: Some(&mut chip) }, &mut fx);
    // The six bucks fail; the two fixed rails still came on, and the first
    // error is what the report says.
    assert_eq!(soc.report.always_on, Err(Error::Hardware));
    let dc = soc.regulators.get_supply(&fdt, by_path(&fdt, "/regulator-vcc-4v").unwrap(), "vin").unwrap();
    assert_eq!(soc.regulators.refs(dc), 1);
}

#[test]
fn rails_behind_a_master_not_attached_yet_are_deferred_not_failed_and_pinned_later() {
    let blob = jupiter();
    let fdt = Fdt::parse(&blob).unwrap();
    let log = Log::new();
    let mut st = Storage::new();
    st.scan(&fdt, K1);
    let mut bus = booted(&log);
    let mut fx = Sink::new(&log);
    let mut chip = P1Chip::booted(&log);
    chip.unattached = true;
    log.clear();
    let mut soc = Soc::build(&mut st, &fdt, &mut Io { bus: &mut bus, i2c: Some(&mut chip) }, &mut fx);
    let r = soc.report;
    // The bucks are providers (a consumer finds `cpu-supply`), the always-on
    // pass did not try them, and no transfer was made or recorded as an effect.
    assert_eq!((r.regulators, r.no_transport, r.always_on, r.always_on_pending), (8, 0, Ok(2), 6), "{r:?}");
    assert_eq!(chip.transfers.get(), 0);
    assert!(log.writes().is_empty() && log.reads().is_empty(), "{:?} {:?}", log.writes(), log.reads());
    let cpu = by_path(&fdt, "/cpus/cpu@0").unwrap();
    let buck1 = soc.regulators.get_supply(&fdt, cpu, "cpu").expect("a provider");
    assert_eq!(soc.regulators.refs(buck1), 0, "not pinned yet");
    // The master is attached: the pass pins them (six reads, no write: they
    // are on), and a second pass has nothing left.
    chip.unattached = false;
    log.clear();
    let mut io = Io { bus: &mut bus, i2c: Some(&mut chip) };
    soc.retry_always_on(&mut io, &mut fx);
    assert_eq!((soc.report.always_on, soc.report.always_on_pending), (Ok(8), 0), "{:?}", soc.report);
    assert_eq!(soc.regulators.refs(buck1), 1);
    assert_eq!(soc.regulators.enable_always_on(&mut io, &mut fx), Ok(0));
    assert!(log.writes().is_empty(), "{:?}", log.writes());
}

#[test]
fn the_window_the_hardware_bus_attaches_is_the_master_the_buck_names() {
    // The kernel's transport names a master by the base the bus bound it at
    // (the device's `base`, from `azos_dtb`) and the buck by the `reg` of its
    // master's node (from this crate's reader). If the two ever differed (a
    // `ranges` translation applied by one reader and not the other) no rail
    // would be reachable and nothing would say why.
    let mut blob = jupiter();
    let fdt = Fdt::parse(&blob).unwrap();
    let mut buck1 = None;
    fdt.walk(|n| {
        if fdt.name(n) == Some("buck1") {
            buck1 = Some(n);
        }
    });
    let buck1 = buck1.expect("the tree has buck1");
    let buck = azos_soc::k1::P1Buck::from_dt(&fdt, buck1).expect("a P1 buck");
    blob.extend_from_slice(&[0; 8]);
    let mut i2c_bases = Vec::new();
    // SAFETY: a well-formed tree, padded.
    unsafe {
        azos_dtb::dtb_devices(blob.as_ptr(), &mut |d: &azos_dtb::DtDevice<'_>| {
            if d.compatible.starts_with(b"spacemit,k1-i2c") {
                i2c_bases.push(d.base);
            }
        })
        .unwrap();
    }
    assert!(i2c_bases.contains(&buck.ctrl()), "the buck's master {:#x} is not among the buses {i2c_bases:#x?}", buck.ctrl());
    assert_eq!(buck.ctrl(), I2C8);
}

// ---- the whole DVFS path ----

fn energy(blob: &[u8]) -> azos_dtb::DtEnergy {
    let mut v = blob.to_vec();
    v.extend_from_slice(&[0; 8]);
    unsafe { dtb_energy(v.as_ptr()) }.expect("readable blob")
}

/// The energy model the tree describes: one domain per cluster, in CPU order.
fn model(dt: &azos_dtb::DtEnergy) -> azos_energy::model::EnergyModel {
    azos_energy::dt::from_dt(dt, &|reg| Some(reg as usize)).expect("CPUs name OPP tables").expect("a model")
}

thread_local! {
    static WAITED_US: Cell<u32> = const { Cell::new(0) };
}
fn wait(us: u32) {
    WAITED_US.with(|w| w.set(w.get() + us));
}

fn opp(khz: u32) -> Opp {
    Opp { freq_khz: khz, capacity: 1, power_mw: 1 }
}

/// The register-level trace of a move, without the reads and the records:
/// the APMU writes as `c<N>:<sel>[+fc]`, the P1 selector writes as `p1:<uv>`.
fn trace(log: &Log) -> Vec<String> {
    log.writes()
        .iter()
        .map(|&(a, v)| match a {
            _ if a == C0_CTRL => format!("c0:{}{}", v & 7, if v & FC != 0 { "+fc" } else { "" }),
            _ if a == C1_CTRL => format!("c1:{}{}", v & 7, if v & FC != 0 { "+fc" } else { "" }),
            _ if a & I2C_TAG != 0 => format!("p1:{}", sel_to_uv(v as u8).unwrap()),
            _ => format!("?{a:#x}"),
        })
        .collect()
}

#[test]
fn the_plan_reads_two_clusters_one_rail_and_the_real_opp_table() {
    rig!(blob, fdt, log, st, bus, fx, chip, soc);
    let dt = energy(&blob);
    let plan = k1_plan(&fdt, &dt, &model(&dt), &soc.clocks, &soc.regulators);
    assert_eq!(plan.left_out, 0);
    let w0 = plan.wires[0].unwrap();
    let w1 = plan.wires[1].unwrap();
    assert_eq!((w0.clk.id, w1.clk.id), (2, 6));
    assert_eq!(w0.rail, w1.rail, "all eight CPUs have cpu-supply = buck1: one rail");
    let rows = |d: usize| plan.tables[d].unwrap().rows().iter().map(|r| (r.freq_khz, r.uv)).collect::<Vec<_>>();
    let expect = [(614_400, 950_000), (819_000, 950_000), (1_000_000, 950_000), (1_228_800, 950_000), (1_600_000, 1_050_000)];
    assert_eq!(rows(0), expect);
    assert_eq!(rows(1), expect);
    let t = plan.tables[0].unwrap();
    assert_eq!((t.ceiling_uv(), t.dropped()), (1_050_000, 0));
    // The model is the tree's: every OPP of it has its row. The buck is the
    // one behind `cpu-supply`, on the master the bus binds.
    assert_eq!(plan.unmatched, [0, 0]);
    assert_eq!((w0.buck.ctrl(), w0.min_uv, w0.max_uv), (I2C8, 500_000, 1_050_000));
    let _ = (&mut bus, &mut fx, &chip, &log);
}

#[test]
fn a_model_whose_frequencies_are_not_the_trees_is_counted_not_silently_refused() {
    use azos_energy::model::{EnergyModel, ModelSource, Opp, PerfDomain};
    rig!(blob, fdt, log, st, bus, fx, chip, soc);
    let dt = energy(&blob);
    // A topology's model: cluster 0 with the tree's 614.4 MHz row one kHz off
    // and its 1.6 GHz right; cluster 1 as the tree has it.
    let mut m = EnergyModel::from_source(ModelSource::Topology);
    for (mask, khz) in [(0x0f, [614_401, 1_600_000]), (0xf0, [614_400, 1_600_000])] {
        let mut d = PerfDomain::new(mask);
        for (i, f) in khz.into_iter().enumerate() {
            d.push_opp(Opp { freq_khz: f, capacity: 100 * (i as u16 + 1), power_mw: 10 * (i as u32 + 1) }).unwrap();
        }
        m.push_domain(d).unwrap();
    }
    let plan = k1_plan(&fdt, &dt, &m, &soc.clocks, &soc.regulators);
    assert_eq!((plan.left_out, plan.unmatched), (0, [1, 0]));
    // And no domain at all is a plan with nothing in it, and nothing left out.
    let none = EnergyModel::from_source(ModelSource::Topology);
    let plan = k1_plan(&fdt, &dt, &none, &soc.clocks, &soc.regulators);
    assert_eq!((plan.left_out, plan.wires.iter().flatten().count()), (0, 0));
    let _ = (&mut bus, &mut fx, &chip, &log);
}

#[test]
fn a_cluster_with_no_rail_is_left_out_and_untouched() {
    // The same tree with the PMIC's bus not available: no buck provider, so
    // no `cpu-supply` resolves and no cluster can be driven.
    let blob = jupiter();
    let fdt = Fdt::parse(&blob).unwrap();
    let log = Log::new();
    let mut st = Storage::new();
    st.scan(&fdt, K1);
    let mut bus = booted(&log);
    let mut fx = Sink::new(&log);
    let soc = Soc::build(&mut st, &fdt, &mut Io { bus: &mut bus, i2c: None }, &mut fx);
    let plan = k1_plan(&fdt, &energy(&blob), &model(&energy(&blob)), &soc.clocks, &soc.regulators);
    assert_eq!(plan.left_out, 2);
    assert!(plan.wires.iter().all(Option::is_none) && plan.tables.iter().all(Option::is_none));
}

#[test]
fn the_shared_buck_holds_the_higher_clusters_voltage_and_the_order_is_rail_then_clock() {
    rig!(blob, fdt, log, st, bus, fx, chip, soc);
    let dt = energy(&blob);
    let plan = k1_plan(&fdt, &dt, &model(&dt), &soc.clocks, &soc.regulators);
    let mut fx_rail = Sink::new(&log);
    let hw = SocK1Hw {
        clocks: Direct { tree: &mut soc.clocks, bus: &mut bus, fx: &mut fx },
        i2c: &mut chip,
        fx: &mut fx_rail,
        wires: plan.wires,
        delay: wait,
    };
    let mut a = K1Opp::new(hw);
    for d in 0..MAX_K1_DOMAINS {
        assert!(a.bind(d, plan.tables[d].unwrap()));
    }
    WAITED_US.with(|w| w.set(0));

    // Cluster 1 runs 1.6 GHz at 1.05 V; cluster 0 drops to 614.4 MHz: the
    // clock moves, the rail stays (cluster 1 still needs it).
    log.clear();
    assert_eq!(a.set_opp(0, &opp(614_400)), Ok(()));
    assert_eq!(trace(&log), ["c0:0", "c0:0+fc"]);
    assert_eq!(WAITED_US.with(Cell::get), 0);

    // Cluster 1 drops to 1 GHz (`pll2_d3`): the clock first, then the rail
    // falls to 0.95 V, which both clusters now carry.
    log.clear();
    assert_eq!(a.set_opp(1, &opp(1_000_000)), Ok(()));
    assert_eq!(trace(&log), ["c1:6", "c1:6+fc", "p1:950000"]);
    let all = log.all();
    // Each register write is preceded by its record.
    for (i, e) in all.iter().enumerate() {
        if matches!(e, Ev::W(..)) {
            assert!(
                all[..i].iter().rev().find(|x| !matches!(x, Ev::R(_))).is_some_and(|x| matches!(x, Ev::E(_) | Ev::W(..))),
                "{all:?}"
            );
        }
    }
    let effects: Vec<(u8, u64)> = log.effects().iter().map(|e| (e.kind, e.value)).collect();
    assert_eq!(effects, [(KIND_CLOCK, 1_000_000_000), (KIND_REGULATOR, 950_000)]);

    // Cluster 0 back up to 1.6 GHz: the rail first (100 mV at 5000 uV/us is
    // 20 us), cluster 1 at 1 GHz needs only 0.95 V so the 1.05 V is cluster
    // 0's alone; then the clock.
    log.clear();
    assert_eq!(a.set_opp(0, &opp(1_600_000)), Ok(()));
    assert_eq!(trace(&log), ["p1:1050000", "c0:7", "c0:7+fc"]);
    assert_eq!(WAITED_US.with(Cell::get), 20);

    // Cluster 1 up to 1.2288 GHz while cluster 0 holds 1.6 GHz: the rail is
    // already high enough and is not touched.
    log.clear();
    assert_eq!(a.set_opp(1, &opp(1_228_800)), Ok(()));
    assert_eq!(trace(&log), ["c1:4", "c1:4+fc"]);

    // Cluster 0 leaves 1.6 GHz for 1 GHz: the rail falls to 0.95 V only
    // because cluster 1 (1.2288 GHz) needs no more.
    log.clear();
    assert_eq!(a.set_opp(0, &opp(1_000_000)), Ok(()));
    assert_eq!(trace(&log), ["c0:6", "c0:6+fc", "p1:950000"]);
}

#[test]
fn a_dt_frequency_the_clock_rounds_up_does_not_repeat_forever() {
    rig!(blob, fdt, log, st, bus, fx, chip, soc);
    let dt = energy(&blob);
    let plan = k1_plan(&fdt, &dt, &model(&dt), &soc.clocks, &soc.regulators);
    let mut fx_rail = Sink::new(&log);
    let hw = SocK1Hw {
        clocks: Direct { tree: &mut soc.clocks, bus: &mut bus, fx: &mut fx },
        i2c: &mut chip,
        fx: &mut fx_rail,
        wires: plan.wires,
        delay: wait,
    };
    let mut a = K1Opp::new(hw);
    for d in 0..MAX_K1_DOMAINS {
        a.bind(d, plan.tables[d].unwrap());
    }
    // The DT row says 819 MHz; the divider makes 819.2.
    assert_eq!(a.set_opp(0, &opp(819_000)), Ok(()));
    let clk = a.hw.wires[0].unwrap().clk;
    assert_eq!(a.hw.clocks.rate(clk), Ok(819_200_000));
    // The same request again is the same operating point: nothing is written.
    log.clear();
    assert_eq!(a.set_opp(0, &opp(819_000)), Ok(()));
    assert!(log.writes().is_empty(), "{:?}", trace(&log));
}

#[test]
fn a_pmic_that_stops_answering_leaves_the_clock_where_it_was() {
    rig!(blob, fdt, log, st, bus, fx, chip, soc);
    let dt = energy(&blob);
    let plan = k1_plan(&fdt, &dt, &model(&dt), &soc.clocks, &soc.regulators);
    chip.nak = true;
    let mut fx_rail = Sink::new(&log);
    let hw = SocK1Hw {
        clocks: Direct { tree: &mut soc.clocks, bus: &mut bus, fx: &mut fx },
        i2c: &mut chip,
        fx: &mut fx_rail,
        wires: plan.wires,
        delay: wait,
    };
    let mut a = K1Opp::new(hw);
    for d in 0..MAX_K1_DOMAINS {
        a.bind(d, plan.tables[d].unwrap());
    }
    log.clear();
    // Neither a fall nor a rise gets to the clock: the rail is read first,
    // and a rail that cannot be read is a transport fault (-EIO).
    assert_eq!(a.set_opp(0, &opp(614_400)), Err(ActuateError::Fault(-5)));
    assert_eq!(a.set_opp(0, &opp(1_600_000)), Err(ActuateError::Fault(-5)));
    assert!(log.writes().is_empty(), "{:?}", trace(&log));
}

#[test]
fn a_clock_that_will_not_switch_puts_the_raised_rail_back() {
    rig!(blob, fdt, log, st, bus, fx, chip, soc);
    let dt = energy(&blob);
    let plan = k1_plan(&fdt, &dt, &model(&dt), &soc.clocks, &soc.regulators);
    // The rail sits at 0.95 V (cluster 1 was parked low by an earlier move).
    chip.regs[0x48] = 90;
    bus.regs.insert(C1_CTRL, 6);
    // The sink refuses the clock record: the switch never happens.
    let mut deny = Sink::new(&log).refusing(|e| e.kind == KIND_CLOCK);
    let mut fx_rail = Sink::new(&log);
    let hw = SocK1Hw {
        clocks: Direct { tree: &mut soc.clocks, bus: &mut bus, fx: &mut deny },
        i2c: &mut chip,
        fx: &mut fx_rail,
        wires: plan.wires,
        delay: wait,
    };
    let mut a = K1Opp::new(hw);
    for d in 0..MAX_K1_DOMAINS {
        a.bind(d, plan.tables[d].unwrap());
    }
    log.clear();
    assert_eq!(a.set_opp(0, &opp(1_600_000)), Err(ActuateError::Refused));
    // Up to 1.05 V and back to 0.95 V, no clock register touched.
    assert_eq!(trace(&log), ["p1:1050000", "p1:950000"]);
}

#[test]
fn without_a_master_a_voltage_move_is_refused_and_the_clock_stays() {
    rig!(blob, fdt, log, st, bus, fx, chip, soc);
    let dt = energy(&blob);
    let plan = k1_plan(&fdt, &dt, &model(&dt), &soc.clocks, &soc.regulators);
    chip.unattached = true;
    let mut fx_rail = Sink::new(&log);
    let hw = SocK1Hw {
        clocks: Direct { tree: &mut soc.clocks, bus: &mut bus, fx: &mut fx },
        i2c: &mut chip,
        fx: &mut fx_rail,
        wires: plan.wires,
        delay: wait,
    };
    let mut a = K1Opp::new(hw);
    for d in 0..MAX_K1_DOMAINS {
        a.bind(d, plan.tables[d].unwrap());
    }
    log.clear();
    assert_eq!(a.set_opp(0, &opp(614_400)), Err(ActuateError::Refused));
    assert!(log.writes().is_empty(), "the cluster is read before it is moved: {:?}", trace(&log));
    let _ = &chip;
}

#[test]
fn the_gpio_and_pwm_nodes_bind_with_their_apbc_resources_left_to_the_firmware() {
    // What the hardware bus asks for when it gives the K1's `gpio` and `pwm`
    // nodes their resources (`wants_resources` in kernel/src/boot/hwbus.rs
    // no longer exempts the K1's `gpio`): every clock and reset is the APBC
    // controller's, which has no provider, so the call is a no-op that
    // succeeds. Canary: a bind that failed on `NoProvider` here would refuse
    // the e-stop line's controller (`ProbeError::Resources`) at every K1 boot.
    for (path, unmodelled) in [("/soc/gpio@d4019000", 2), ("/soc/pwm@d401a000", 2)] {
        rig!(blob, fdt, log, st, bus, fx, chip, soc);
        let _ = &chip;
        let node = by_path(&fdt, path).unwrap();
        log.clear();
        let a = bind::bind(&mut soc, &fdt, &mut bus, &mut fx, node).unwrap();
        assert_eq!(a, bind::Applied { unmodelled, ..Default::default() }, "{path}");
        assert!(log.all().is_empty(), "{path}: {:?}", log.all());
        // And the release the bus runs when a probe fails balances it.
        bind::unbind(&mut soc, &fdt, &mut bus, &mut fx, node).unwrap();
        assert!(log.all().is_empty(), "{path} unbind: {:?}", log.all());
    }
}

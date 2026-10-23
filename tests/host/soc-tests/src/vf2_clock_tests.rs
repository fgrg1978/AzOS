// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The VisionFive 2's device clocks, end to end: a tree shaped like mainline
//! `jh7110.dtsi` (the oscillator, the system clock generator fed by the PLL
//! block inside the system syscon, and the devices the kernel binds through
//! the hardware bus: an I2C controller, the watchdog, the PWM, the
//! temperature sensor, the two SD/eMMC controllers, each with the `clocks`,
//! `resets` and assigned rates of mainline), built the way the kernel builds
//! it (`Storage::scan`, `Soc::build`), with the registers as U-Boot's SPL
//! leaves them. Each device binds; the I2C one then feeds the DesignWare
//! bring-up (`i2c_dw.rs`, pulled in by path) the rate the tree resolves, as
//! `kernel/src/boot/hwbus.rs` (`dw_i2c_timing`) feeds it.
use crate::bind_tests::model;
use crate::i2c_dw::{init_master, Counts, Timing};
use crate::i2c_txn::{DwRegs, IC_ENABLE, IC_ENABLE_STATUS};
use crate::support::*;
use azos_soc::bind::{self, Applied};
use azos_soc::boot::{Families, Soc, Storage};
use azos_soc::clk::Clk;
use azos_soc::consumer::Sel;
use azos_soc::fdt::Fdt;
use azos_soc::regulator::Io;
use azos_soc::Error;
use std::cell::RefCell;
use std::collections::BTreeMap;

const OSC: u32 = 1;
const GMAC1_RMII_REFIN: u32 = 2;
const SYSCRG: u32 = 3;
const PLLCLK: u32 = 4;

const SYSCON_BASE: u64 = 0x1303_0000;
const I2C0: &str = "/soc/i2c@10030000";
/// `JH7110_SYSCLK_I2C0_APB` and `JH7110_SYSRST_I2C0_APB` (the mainline
/// dt-bindings headers).
const I2C0_APB: u32 = 138;
const I2C0_RST: u32 = 76;
/// The other devices' `JH7110_SYSCLK_*` (the reset ids are written in the
/// nodes): SDIO0/1 AHB 91/92, SDCARD 93/94, PWM APB 121, WDT APB/CORE
/// 122/123, TEMP APB/CORE 129/130.
const SDIO0_AHB: u32 = 91;
const SDIO0_SDCARD: u32 = 93;
const PWM_APB: u32 = 121;
const WDT_APB: u32 = 122;
const WDT_CORE: u32 = 123;
const TEMP_APB: u32 = 129;
const TEMP_CORE: u32 = 130;

/// The clock and reset nodes of mainline `jh7110.dtsi`, `i2c0` with the
/// VisionFive 2's properties (`jh7110-common.dtsi`), and the watchdog, PWM,
/// temperature sensor and SD/eMMC nodes with their `clocks`, `resets` and
/// (SD/eMMC) `assigned-clock-rates` of mainline. The syscrg's `clocks` keeps
/// a board input before the PLLs, as the real list does, so the inputs are
/// found by name.
fn vf2_tree() -> Vec<u8> {
    let mut b = Builder::new();
    b.cells("#address-cells", &[2]).cells("#size-cells", &[2]);
    b.begin("oscillator")
        .str("compatible", "fixed-clock")
        .cells("#clock-cells", &[0])
        .cells("clock-frequency", &[24_000_000])
        .ph(OSC)
        .end();
    b.begin("gmac1-rmii-refin-clock")
        .str("compatible", "fixed-clock")
        .cells("#clock-cells", &[0])
        .cells("clock-frequency", &[50_000_000])
        .ph(GMAC1_RMII_REFIN)
        .end();
    b.begin("soc").cells("#address-cells", &[2]).cells("#size-cells", &[2]).flag("ranges");
    b.begin("i2c@10030000")
        .str("compatible", "snps,designware-i2c")
        .cells("reg", &[0, 0x1003_0000, 0, 0x10000])
        .cells("clocks", &[SYSCRG, I2C0_APB])
        .strs("clock-names", &["ref"])
        .cells("resets", &[SYSCRG, I2C0_RST])
        .cells("clock-frequency", &[100_000])
        .cells("i2c-sda-hold-time-ns", &[300])
        .cells("i2c-sda-falling-time-ns", &[510])
        .cells("i2c-scl-falling-time-ns", &[510])
        .end();
    b.begin("pwm@120d0000")
        .strs("compatible", &["starfive,jh7110-pwm", "opencores,pwm-v1"])
        .cells("reg", &[0, 0x120d_0000, 0, 0x10000])
        .cells("clocks", &[SYSCRG, PWM_APB])
        .cells("resets", &[SYSCRG, 108])
        .end();
    b.begin("temperature-sensor@120e0000")
        .str("compatible", "starfive,jh7110-temp")
        .cells("reg", &[0, 0x120e_0000, 0, 0x10000])
        .cells("clocks", &[SYSCRG, TEMP_CORE, SYSCRG, TEMP_APB])
        .strs("clock-names", &["sense", "bus"])
        .cells("resets", &[SYSCRG, 124, SYSCRG, 123])
        .strs("reset-names", &["sense", "bus"])
        .end();
    b.begin("clock-controller@13020000")
        .str("compatible", "starfive,jh7110-syscrg")
        .cells("reg", &[0, 0x1302_0000, 0, 0x10000])
        .cells("clocks", &[OSC, GMAC1_RMII_REFIN, PLLCLK, 0, PLLCLK, 1, PLLCLK, 2])
        .strs("clock-names", &["osc", "gmac1_rmii_refin", "pll0_out", "pll1_out", "pll2_out"])
        .cells("#clock-cells", &[1])
        .cells("#reset-cells", &[1])
        .ph(SYSCRG)
        .end();
    b.begin("syscon@13030000")
        .strs("compatible", &["starfive,jh7110-sys-syscon", "syscon", "simple-mfd"])
        .cells("reg", &[0, 0x1303_0000, 0, 0x1000]);
    b.begin("clock-controller")
        .str("compatible", "starfive,jh7110-pll")
        .cells("clocks", &[OSC])
        .cells("#clock-cells", &[1])
        .ph(PLLCLK)
        .end();
    b.end();
    b.begin("watchdog@13070000")
        .str("compatible", "starfive,jh7110-wdt")
        .cells("reg", &[0, 0x1307_0000, 0, 0x10000])
        .cells("clocks", &[SYSCRG, WDT_APB, SYSCRG, WDT_CORE])
        .strs("clock-names", &["apb", "core"])
        .cells("resets", &[SYSCRG, 109, SYSCRG, 110])
        .end();
    for (k, base) in [(0u32, 0x1601_0000u32), (1, 0x1602_0000)] {
        b.begin(&format!("mmc@{base:x}"))
            .str("compatible", "starfive,jh7110-mmc")
            .cells("reg", &[0, base, 0, 0x10000])
            .cells("clocks", &[SYSCRG, SDIO0_AHB + k, SYSCRG, SDIO0_SDCARD + k])
            .strs("clock-names", &["biu", "ciu"])
            .cells("resets", &[SYSCRG, 64 + k])
            .strs("reset-names", &["reset"])
            .cells("assigned-clocks", &[SYSCRG, SDIO0_SDCARD + k])
            .cells("assigned-clock-rates", &[50_000_000])
            .end();
    }
    b.end(); // soc
    b.finish()
}

fn sys(id: u32) -> u64 {
    SYSCRG_BASE + 4 * id as u64
}

fn pll(off: u64) -> u64 {
    SYSCON_BASE + off
}

/// What U-Boot's SPL programs (`clk-jh7110-pll.c`: PLL0 1 GHz, PLL2
/// 1188 MHz, integer mode; PLL1, the DDR's, at 1066 MHz from its table) and
/// the bus chain the module doc of `jh7110/clk.rs` gives: bus_root on PLL2,
/// axi_cfg0 /3, stg_axiahb /2, apb_bus /4. PLL1's prediv and PLL2's
/// fbdiv share the word at 0x2c, PLL0's prediv and PLL1's fbdiv the one at
/// 0x24.
fn seed_firmware(bus: &mut TraceBus) {
    const INT: u32 = (1 << 15) | (1 << 16); // dacpd, dsmpd of PLL1/PLL2
    bus.regs.insert(pll(0x18), (1 << 24) | (1 << 25));
    bus.regs.insert(pll(0x1c), 125);
    bus.regs.insert(pll(0x24), 3 | INT | (533 << 17));
    bus.regs.insert(pll(0x2c), 12 | INT | (99 << 17));
    bus.regs.insert(pll(0x34), 2);
    bus.regs.insert(sys(5), 1 << 24);
    bus.regs.insert(sys(7), 3);
    bus.regs.insert(sys(8), 2);
    bus.regs.insert(sys(11), 4);
}

struct Rig<'p> {
    soc: Soc<'p>,
    bus: TraceBus,
    fx: Sink,
    log: std::rc::Rc<Log>,
}

fn rig<'p>(st: &'p mut Storage, fdt: &Fdt<'_>) -> Rig<'p> {
    st.scan(fdt, Families { jh7110: true, k1: false });
    let w = st.map_windows(fdt, |_, _| true);
    assert_eq!(w.failed, 0);
    let log = Log::new();
    let mut bus = TraceBus::new(&log).hook(model());
    let mut fx = Sink::new(&log);
    let soc = Soc::build(st, fdt, &mut Io { bus: &mut bus, i2c: None }, &mut fx);
    // syscrg, the PLLs, the two fixed clocks: inside the six clock slots.
    assert_eq!((soc.report.clocks, soc.report.dropped), (4, 0));
    seed_firmware(&mut bus);
    log.clear();
    Rig { soc, bus, fx, log }
}

#[test]
fn the_plls_read_what_the_firmware_programmed() {
    let blob = vf2_tree();
    let fdt = Fdt::parse(&blob).unwrap();
    let mut st = Storage::new();
    let mut r = rig(&mut st, &fdt);
    let crg = fdt.by_phandle(SYSCRG).unwrap();
    for (name, hz) in [("pll0_out", 1_000_000_000), ("pll1_out", 1_066_000_000), ("pll2_out", 1_188_000_000)] {
        let c = r.soc.clocks.get(&fdt, crg, Sel::Name(name)).unwrap();
        assert_eq!(r.soc.clocks.rate(&mut r.bus, c).unwrap(), hz, "{name}");
    }
    // The block is read, never written.
    assert!(r.log.writes().is_empty());
}

#[test]
fn a_pll_in_fractional_mode_powered_down_or_unknown() {
    let blob = vf2_tree();
    let fdt = Fdt::parse(&blob).unwrap();
    let mut st = Storage::new();
    let mut r = rig(&mut st, &fdt);
    let crg = fdt.by_phandle(SYSCRG).unwrap();
    let pll2 = r.soc.clocks.get(&fdt, crg, Sel::Name("pll2_out")).unwrap();
    // dacpd = dsmpd = 0: fbdiv 99 + frac 0.5 (0x80_0000 / 2^24), prediv 2.
    r.bus.regs.insert(pll(0x2c), 12 | (99 << 17));
    r.bus.regs.insert(pll(0x30), 0x80_0000);
    assert_eq!(r.soc.clocks.rate(&mut r.bus, pll2).unwrap(), 1_194_000_000);
    // postdiv1 (bits 29:28) divides by 2^n.
    r.bus.regs.insert(pll(0x30), 0x80_0000 | (1 << 28));
    assert_eq!(r.soc.clocks.rate(&mut r.bus, pll2).unwrap(), 597_000_000);
    // pd (bit 27) set: stopped.
    r.bus.regs.insert(pll(0x30), 1 << 27);
    assert_eq!(r.soc.clocks.rate(&mut r.bus, pll2).unwrap(), 0);
    // dacpd without dsmpd: no mode the formula covers.
    r.bus.regs.insert(pll(0x30), 0);
    r.bus.regs.insert(pll(0x2c), 12 | (1 << 15) | (99 << 17));
    assert_eq!(r.soc.clocks.rate(&mut r.bus, pll2), Err(Error::Hardware));
    // prediv 0 (M is 1..63).
    r.bus.regs.insert(pll(0x2c), 12 | (3 << 15) | (99 << 17));
    r.bus.regs.insert(pll(0x34), 0);
    assert_eq!(r.soc.clocks.rate(&mut r.bus, pll2), Err(Error::Hardware));
}

#[test]
fn the_vf2_i2c_node_resolves_a_rate_and_binds() {
    let blob = vf2_tree();
    let fdt = Fdt::parse(&blob).unwrap();
    let mut st = Storage::new();
    let mut r = rig(&mut st, &fdt);
    let i2c = by_path(&fdt, I2C0).unwrap();
    let c = r.soc.clocks.get(&fdt, i2c, Sel::Index(0)).unwrap();
    assert_eq!(c.id as u32, I2C0_APB);
    // 1188 MHz / 3 / 2 / 4.
    assert_eq!(r.soc.clocks.rate(&mut r.bus, c).unwrap(), 49_500_000);

    let a = bind::bind(&mut r.soc, &fdt, &mut r.bus, &mut r.fx, i2c).unwrap();
    assert_eq!(a, Applied { domains: 0, rates: 0, clocks: 1, resets: 1, pins: false, unmodelled: 0 });
    // apb0 then the I2C's own gate, root first; nothing written in the PLLs.
    let gates: Vec<_> = r.log.writes().into_iter().filter(|(a, v)| *a < SYSCON_BASE && v & (1 << 31) != 0).collect();
    assert_eq!(gates, [(sys(12), 0x8000_0000), (sys(I2C0_APB), 0x8000_0000)]);
    assert!(r.log.writes().iter().all(|(a, _)| !(SYSCON_BASE..SYSCON_BASE + 0x1000).contains(a)));
    assert_eq!(r.soc.clocks.refs(Clk { prov: c.prov, id: 12 }), 1);
}

/// A DesignWare 2.01a with 8-entry FIFOs, fast mode, encoded parameters;
/// `IC_ENABLE_STATUS` follows `IC_ENABLE`. Every write is kept.
struct Dw {
    regs: RefCell<BTreeMap<usize, u32>>,
}

impl Dw {
    fn new() -> Self {
        use crate::i2c_dw::{COMP_TYPE_DW, IC_COMP_PARAM_1, IC_COMP_TYPE, IC_COMP_VERSION};
        let regs = BTreeMap::from([
            (IC_COMP_TYPE, COMP_TYPE_DW),
            (IC_COMP_PARAM_1, (7 << 16) | (7 << 8) | (1 << 7) | (2 << 2) | 2),
            (IC_COMP_VERSION, 0x3230_312A),
        ]);
        Dw { regs: RefCell::new(regs) }
    }
    fn get(&self, off: usize) -> u32 {
        self.regs.borrow().get(&off).copied().unwrap_or(0)
    }
}

impl DwRegs for Dw {
    fn rd(&self, off: usize) -> u32 {
        if off == IC_ENABLE_STATUS {
            return self.get(IC_ENABLE) & 1;
        }
        self.get(off)
    }
    fn wr(&self, off: usize, val: u32) {
        self.regs.borrow_mut().insert(off, val);
    }
}

/// What `dw_i2c_timing` (kernel/src/boot/hwbus.rs) reads for a node: the
/// clock tree's rate of its first clock, `clock-frequency`, the fall and
/// hold times.
fn timing(r: &mut Rig<'_>, fdt: &Fdt<'_>, n: azos_soc::NodeId) -> Timing {
    let cell = |name: &str| fdt.u32_prop(n, name);
    let live = r.soc.clocks.get(fdt, n, Sel::Index(0)).ok().and_then(|c| r.soc.clocks.rate(&mut r.bus, c).ok());
    Timing {
        ic_clk_hz: live.filter(|&hz| hz != 0),
        bus_hz: cell("clock-frequency").unwrap(),
        scl_fall_ns: cell("i2c-scl-falling-time-ns"),
        sda_fall_ns: cell("i2c-sda-falling-time-ns"),
        sda_hold_ns: cell("i2c-sda-hold-time-ns"),
    }
}

#[test]
fn the_designware_driver_computes_its_counts_from_that_rate() {
    use crate::i2c_dw::{IC_SDA_HOLD, IC_SS_SCL_HCNT, IC_SS_SCL_LCNT};
    let blob = vf2_tree();
    let fdt = Fdt::parse(&blob).unwrap();
    let mut st = Storage::new();
    let mut r = rig(&mut st, &fdt);
    let i2c = by_path(&fdt, I2C0).unwrap();
    bind::bind(&mut r.soc, &fdt, &mut r.bus, &mut r.fx, i2c).unwrap();
    let t = timing(&mut r, &fdt, i2c);
    assert_eq!(t.ic_clk_hz, Some(49_500_000));

    let dw = Dw::new();
    let s = init_master(&dw, &t, 8).unwrap();
    assert_eq!(s.counts, Counts::Computed);
    // Standard mode at 49_500 kHz, by hand (Linux i2c_dw_scl_hcnt/lcnt):
    // HCNT = round(49_500 * (4000 + 510) / 1e6) - 3 = 223 - 3;
    // LCNT = round(49_500 * (4700 + 510) / 1e6) - 1 = 258 - 1.
    assert_eq!((s.hcnt, s.lcnt), (220, 257));
    assert_eq!((dw.get(IC_SS_SCL_HCNT), dw.get(IC_SS_SCL_LCNT)), (220, 257));
    // SDA hold: round(49_500 * 300 / 1e6) = 15 cycles TX, RX hold forced to 1.
    assert_eq!(dw.get(IC_SDA_HOLD), (1 << 16) | 15);
}

/// Bind the node at `path` on a fresh board; what it applied and the gates it
/// opened (the syscrg writes that set bit 31), in order.
fn bind_on_board(path: &str) -> (Applied, Vec<(u64, u32)>, u64) {
    let blob = vf2_tree();
    let fdt = Fdt::parse(&blob).unwrap();
    let mut st = Storage::new();
    let mut r = rig(&mut st, &fdt);
    let n = by_path(&fdt, path).unwrap();
    let a = bind::bind(&mut r.soc, &fdt, &mut r.bus, &mut r.fx, n).unwrap_or_else(|e| panic!("{path}: bind refused: {e:?}"));
    let writes = r.log.writes();
    assert!(writes.iter().all(|(a, _)| !(SYSCON_BASE..SYSCON_BASE + 0x1000).contains(a)), "{path} wrote a PLL");
    let gates = writes.iter().copied().filter(|(a, v)| (SYSCRG_BASE..SYSCRG_BASE + 0x2f8).contains(a) && v & (1 << 31) != 0).collect();
    // The rate of the node's last clock, as a driver would read it.
    let last = consumer_count(&fdt, n) - 1;
    let c = r.soc.clocks.get(&fdt, n, Sel::Index(last)).unwrap();
    let hz = r.soc.clocks.rate(&mut r.bus, c).unwrap();
    (a, gates, hz)
}

fn consumer_count(fdt: &Fdt<'_>, n: azos_soc::NodeId) -> usize {
    azos_soc::consumer::count(fdt, n, "clocks", "#clock-cells").unwrap()
}

const GATE: u32 = 1 << 31;

#[test]
fn the_watchdog_binds_with_its_apb_and_core_gates() {
    let (a, gates, core_hz) = bind_on_board("/soc/watchdog@13070000");
    assert_eq!(a, Applied { domains: 0, rates: 0, clocks: 2, resets: 2, pins: false, unmodelled: 0 });
    assert_eq!(gates, [(sys(12), GATE), (sys(WDT_APB), GATE), (sys(WDT_CORE), GATE)]);
    // The core counts the oscillator.
    assert_eq!(core_hz, 24_000_000);
}

#[test]
fn the_pwm_binds_with_its_apb_gate() {
    let (a, gates, hz) = bind_on_board("/soc/pwm@120d0000");
    assert_eq!(a, Applied { domains: 0, rates: 0, clocks: 1, resets: 1, pins: false, unmodelled: 0 });
    assert_eq!(gates, [(sys(12), GATE), (sys(PWM_APB), GATE)]);
    assert_eq!(hz, 49_500_000);
}

#[test]
fn the_temperature_sensor_binds_and_its_sense_clock_has_no_gate() {
    let (a, gates, bus_hz) = bind_on_board("/soc/temperature-sensor@120e0000");
    assert_eq!(a, Applied { domains: 0, rates: 0, clocks: 2, resets: 2, pins: false, unmodelled: 0 });
    // temp_core (130) is a divider of the oscillator: nothing to open.
    assert_eq!(gates, [(sys(12), GATE), (sys(TEMP_APB), GATE)]);
    assert_eq!(bus_hz, 49_500_000);
}

#[test]
fn the_sd_controllers_bind_at_their_assigned_card_rate() {
    for k in 0..2u32 {
        let path = format!("/soc/mmc@{:x}", 0x1601_0000 + 0x1_0000 * k);
        let (a, gates, ciu_hz) = bind_on_board(&path);
        assert_eq!(a, Applied { domains: 0, rates: 1, clocks: 2, resets: 1, pins: false, unmodelled: 0 }, "{path}");
        // ahb0 (9), the AHB gate, then the card clock's gate over the
        // divider the assigned rate wrote: 396 MHz (axi_cfg0) / 8.
        assert_eq!(
            gates,
            [(sys(9), GATE), (sys(SDIO0_AHB + k), GATE), (sys(SDIO0_SDCARD + k), GATE | 8)],
            "{path}"
        );
        assert_eq!(ciu_hz, 49_500_000, "{path}");
    }
}

/// Every clock of the table resolves a rate on the board: each chain fits
/// `clk::MAX_DEPTH` (the APB gates' are the longest: gate, apb0, apb_bus,
/// stg_axiahb, axi_cfg0, bus_root, pll2, osc = 8) and every parent exists.
#[test]
fn every_table_clock_resolves_within_the_depth_limit() {
    let blob = vf2_tree();
    let fdt = Fdt::parse(&blob).unwrap();
    let mut st = Storage::new();
    let mut r = rig(&mut st, &fdt);
    let prov = r.soc.clocks.get(&fdt, by_path(&fdt, I2C0).unwrap(), Sel::Index(0)).unwrap().prov;
    // The dividers the firmware seed leaves alone read 0 (stopped): the CPU
    // ones, the card clocks, the sensing clock.
    for id in [1u32, 2, 93, 94, 130] {
        r.bus.regs.insert(sys(id), 1);
    }
    for d in azos_soc::jh7110::clk::SYS_CLOCKS {
        let c = Clk { prov, id: d.id as u16 };
        let hz = r.soc.clocks.rate(&mut r.bus, c).unwrap_or_else(|e| panic!("{} ({}): {e:?}", d.name, d.id));
        assert!(hz > 0, "{} ({})", d.name, d.id);
    }
}

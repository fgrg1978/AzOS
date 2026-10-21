// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The JH7110 SYS and AON pad controllers against hand-written register
//! traces. Register positions are the ones of TRM 2.8.7 / 2.8.8 (doen T2-579..
//! T2-594, dout T2-595..T2-610, sig_in T2-611..T2-633, pad configuration
//! T2-651.., function select T2-746..T2-751; AON T2-753..T2-755, T2-765..
//! T2-772, T2-787); the worked examples are TRM 2.7.6.3.2's (UART0 RX on
//! GPIO11 with GPI 14, SDIO1 data 0 on GPIO12 with GPO 58, GPEN 20, GPI 45).
use crate::support::*;
use azos_soc::consumer::Sel;
use azos_soc::effect::{Class, Effect, Op, KIND_PINCTRL};
use azos_soc::fdt::Fdt;
use azos_soc::jh7110::iomux::{funcsel, gpiomux, DOUT_NONE, GPI_NONE};
use azos_soc::jh7110::Jh7110Iomux;
use azos_soc::pinctrl::{Bias, Conf, Pinctrl, PinctrlOps};
use azos_soc::Error;

const SYS: u64 = 0x1304_0000;
const AON: u64 = 0x1702_0000;

const SYS_PH: u32 = 20;
const AON_PH: u32 = 21;
const UART_CFG: u32 = 22;
const AON_CFG: u32 = 23;

fn blob() -> Vec<u8> {
    let mut b = Builder::new();
    b.cells("#address-cells", &[2]).cells("#size-cells", &[2]);
    b.begin("soc").cells("#address-cells", &[2]).cells("#size-cells", &[2]).flag("ranges");
    b.begin("pinctrl@13040000")
        .strs("compatible", &["starfive,jh7110-sys-pinctrl"])
        .cells("reg", &[0, 0x1304_0000, 0, 0x10000])
        .ph(SYS_PH);
    b.begin("uart0-0").ph(UART_CFG);
    // TX on GPIO5: GPO 20 (U0 UART SOUT), no GPEN, no GPI.
    b.begin("tx")
        .cells("pinmux", &[gpiomux(5, 20, 0, GPI_NONE)])
        .flag("bias-disable")
        .cells("drive-strength", &[8])
        .flag("input-schmitt-enable")
        .end();
    // RX on GPIO11: GPI 14, GPEN fixed to 1, no GPO.
    b.begin("rx").cells("pinmux", &[gpiomux(11, DOUT_NONE, 1, 14)]).flag("bias-pull-up").flag("input-enable").end();
    b.end();
    b.end();
    b.begin("pinctrl@17020000")
        .strs("compatible", &["starfive,jh7110-aon-pinctrl"])
        .cells("reg", &[0, 0x1702_0000, 0, 0x10000])
        .ph(AON_PH);
    b.begin("aon-0").ph(AON_CFG);
    b.begin("rgpio2").cells("pinmux", &[gpiomux(3, 4, 5, 1)]).flag("bias-pull-down").end();
    b.end();
    b.end();
    b.begin("serial@10000000")
        .strs("pinctrl-names", &["default"])
        .cells("pinctrl-0", &[UART_CFG, AON_CFG])
        .end();
    b.end();
    b.finish()
}

fn pe(op: Op, provider: u8, id: u32, value: u64) -> Ev {
    Ev::E(Effect { kind: KIND_PINCTRL, op, class: Class::Reversible, provider, id, value })
}

fn rig() -> (std::rc::Rc<Log>, TraceBus) {
    let log = Log::new();
    let bus = TraceBus::new(&log);
    (log, bus)
}

#[test]
fn the_dt_nodes_become_the_blocks_their_compatible_names() {
    let blob = blob();
    let fdt = Fdt::parse(&blob).unwrap();
    assert!(Jh7110Iomux::from_dt(&fdt, fdt.by_phandle(SYS_PH).unwrap()).is_some());
    assert!(Jh7110Iomux::from_dt(&fdt, fdt.by_phandle(AON_PH).unwrap()).is_some());
    // Only the pad-controller compatibles.
    assert!(Jh7110Iomux::from_dt(&fdt, by_path(&fdt, "/soc/serial@10000000").unwrap()).is_none());
}

#[test]
fn the_default_state_programs_both_blocks_in_the_trace_the_tables_give() {
    let blob = blob();
    let fdt = Fdt::parse(&blob).unwrap();
    let (log, mut bus) = rig();
    let mut fx = Sink::new(&log);
    // Registers as the hardware leaves them: the TX pad's doen field is set,
    // GPIO5 pad config is the reset value of GPIO1..3-like pads (IE, PU).
    bus.regs.insert(SYS + 0x04, 0x0000_3f00);
    bus.regs.insert(SYS + 0x120 + 4 * 5, 0x0000_0009);
    let mut sys = Jh7110Iomux::from_dt(&fdt, fdt.by_phandle(SYS_PH).unwrap()).unwrap();
    let mut aon = Jh7110Iomux::from_dt(&fdt, fdt.by_phandle(AON_PH).unwrap()).unwrap();
    let mut pc = Pinctrl::new();
    pc.add(fdt.by_phandle(SYS_PH).unwrap(), &mut sys).unwrap();
    pc.add(fdt.by_phandle(AON_PH).unwrap(), &mut aon).unwrap();
    pc.select(&mut bus, &mut fx, &fdt, by_path(&fdt, "/soc/serial@10000000").unwrap(), Sel::Name("default")).unwrap();
    let tx = gpiomux(5, 20, 0, GPI_NONE);
    let rx = gpiomux(11, DOUT_NONE, 1, 14);
    let rg = gpiomux(3, 4, 5, 1);
    assert_eq!(
        log.all(),
        [
            // GPIO5 TX. dout: reg 0x40 + 4 * (5 / 4), byte lane 1, 7 bits.
            pe(Op::SetMux, 0, tx, 0),
            Ev::R(SYS + 0x44),
            Ev::W(SYS + 0x44, 20 << 8),
            // No GPI. doen: reg 0x00 + 4 * (5 / 4), lane 1, 6 bits, cleared.
            Ev::R(SYS + 0x04),
            Ev::W(SYS + 0x04, 0),
            // bias-disable: PU (bit 3) and PD (bit 4) clear in the pad register.
            pe(Op::SetBias, 0, 5, Bias::Disable as u64),
            Ev::R(SYS + 0x134),
            Ev::W(SYS + 0x134, 0x0000_0001),
            // drive-strength 8 mA: DS [2:1] = 0b10; Schmitt: bit 6.
            pe(Op::SetConf, 0, 5, Conf::DriveStrength(8).wire()),
            Ev::R(SYS + 0x134),
            Ev::W(SYS + 0x134, 0x0000_0005),
            pe(Op::SetConf, 0, 5, Conf::Schmitt(true).wire()),
            Ev::R(SYS + 0x134),
            Ev::W(SYS + 0x134, 0x0000_0045),
            // GPIO11 RX. No GPO. sig_in of GPI 14: reg 0x80 + 4 * (14 / 4),
            // lane 2, 7 bits, value pad + 2 = 13 (TRM 2.7.6.3.2).
            pe(Op::SetMux, 0, rx, 0),
            Ev::R(SYS + 0x8c),
            Ev::W(SYS + 0x8c, 13 << 16),
            // doen of GPIO11: reg 0x08, lane 3, value 1 ("input without a
            // GPEN signal is fixed to 1").
            Ev::R(SYS + 0x08),
            Ev::W(SYS + 0x08, 1 << 24),
            pe(Op::SetBias, 0, 11, Bias::PullUp as u64),
            Ev::R(SYS + 0x120 + 4 * 11),
            Ev::W(SYS + 0x120 + 4 * 11, 0x0000_0008),
            pe(Op::SetConf, 0, 11, Conf::InputEnable(true).wire()),
            Ev::R(SYS + 0x120 + 4 * 11),
            Ev::W(SYS + 0x120 + 4 * 11, 0x0000_0009),
            // AON RGPIO2 (pin 3, index 2): dout reg 0x4 lane 2 (4 bits), GPI 1
            // reg 0x8 lane 1 (3 bits) value 2 + 2, doen reg 0x0 lane 2 (3 bits).
            pe(Op::SetMux, 1, rg, 0),
            Ev::R(AON + 0x4),
            Ev::W(AON + 0x4, 4 << 16),
            Ev::R(AON + 0x8),
            Ev::W(AON + 0x8, 4 << 8),
            Ev::R(AON + 0x0),
            Ev::W(AON + 0x0, 5 << 16),
            // bias-pull-down on the AON pad: pad register at 0x30 + 4 * 3.
            pe(Op::SetBias, 1, 3, Bias::PullDown as u64),
            Ev::R(AON + 0x3c),
            Ev::W(AON + 0x3c, 0x0000_0010),
        ]
    );
}

#[test]
fn the_sdio_example_of_the_trm_lands_in_the_registers_it_names() {
    // GPIO12 as SDIO1 data 0: GPI 45, GPO 58, GPEN 20.
    let (log, mut bus) = rig();
    let mut sys = Jh7110Iomux::sys(SYS);
    sys.set_mux(&mut bus, gpiomux(12, 58, 20, 45)).unwrap();
    assert_eq!(
        log.writes(),
        [
            (SYS + 0x4c, 58),            // dout: 0x40 + 4 * (12 / 4), lane 0
            (SYS + 0xac, 14 << 8),       // sig_in: 0x80 + 4 * (45 / 4), lane 1, 12 + 2
            (SYS + 0x0c, 20),            // doen: 0x00 + 4 * (12 / 4), lane 0
        ]
    );
    // The other lanes of a shared register survive.
    let (log, mut bus) = rig();
    bus.regs.insert(SYS + 0x4c, 0x7f7f_7f00);
    sys.set_mux(&mut bus, gpiomux(12, 58, 20, GPI_NONE)).unwrap();
    assert_eq!(log.writes()[0], (SYS + 0x4c, 0x7f7f_7f00 | 58));
}

#[test]
fn a_word_the_blocks_do_not_have_is_a_bad_spec_and_writes_nothing() {
    let (log, mut bus) = rig();
    let mut sys = Jh7110Iomux::sys(SYS);
    let mut aon = Jh7110Iomux::aon(AON);
    // Pin 64 is an SD0 pad: it has a pad register but no mux.
    assert_eq!(sys.set_mux(&mut bus, gpiomux(64, 0, 0, GPI_NONE)), Err(Error::BadSpec));
    assert_eq!(sys.set_mux(&mut bus, gpiomux(5, 108, 0, GPI_NONE)), Err(Error::BadSpec)); // GPO 0..=107
    assert_eq!(sys.set_mux(&mut bus, gpiomux(5, 0, 50, GPI_NONE)), Err(Error::BadSpec)); // GPEN 0..=49
    assert_eq!(sys.set_mux(&mut bus, gpiomux(5, 0, 0, 91)), Err(Error::BadSpec)); // GPI 0..=90
    // AON: pins 1..=4 are muxable, TESTEN (0) and RSTN (5) are not.
    assert_eq!(aon.set_mux(&mut bus, gpiomux(0, 0, 0, GPI_NONE)), Err(Error::BadSpec));
    assert_eq!(aon.set_mux(&mut bus, gpiomux(5, 0, 0, GPI_NONE)), Err(Error::BadSpec));
    assert_eq!(aon.set_mux(&mut bus, gpiomux(1, 10, 0, GPI_NONE)), Err(Error::BadSpec)); // GPO 0..=9
    assert_eq!(aon.set_mux(&mut bus, gpiomux(1, 0, 6, GPI_NONE)), Err(Error::BadSpec)); // GPEN 0..=5
    assert_eq!(aon.set_mux(&mut bus, gpiomux(1, 0, 0, 4)), Err(Error::BadSpec)); // GPI 0..=3
    assert!(log.all().is_empty());
}

#[test]
fn bias_is_one_write_that_never_has_both_pulls_on() {
    let (log, mut bus) = rig();
    let mut sys = Jh7110Iomux::sys(SYS);
    let pad = SYS + 0x120; // GPIO0, reset value 0x11: IE and PD
    bus.regs.insert(pad, 0x11);
    sys.set_bias(&mut bus, 0, Bias::PullUp).unwrap();
    assert_eq!(bus.regs[&pad], 0x09);
    sys.set_bias(&mut bus, 0, Bias::PullDown).unwrap();
    assert_eq!(bus.regs[&pad], 0x11);
    sys.set_bias(&mut bus, 0, Bias::Disable).unwrap();
    assert_eq!(bus.regs[&pad], 0x01);
    // Every change is one write of the register.
    assert_eq!(log.writes().len(), 3);
    // The pad has no bus-hold.
    assert_eq!(sys.set_bias(&mut bus, 0, Bias::BusHold), Err(Error::Unsupported));
    assert_eq!(log.writes().len(), 3);
}

#[test]
fn drive_strength_input_enable_and_schmitt_are_their_own_fields() {
    let (_log, mut bus) = rig();
    let mut sys = Jh7110Iomux::sys(SYS);
    let pad = SYS + 0x120 + 4 * 20; // GPIO20
    bus.regs.insert(pad, 0xff); // everything on, DS = 0b11
    for (ma, ds) in [(2u32, 0u32), (4, 1), (8, 2), (12, 3)] {
        sys.set_conf(&mut bus, 20, Conf::DriveStrength(ma)).unwrap();
        assert_eq!(bus.regs[&pad], (0xff & !0x6) | ds << 1, "{ma} mA");
    }
    // Only the four values of Table 2-651 exist.
    assert_eq!(sys.set_conf(&mut bus, 20, Conf::DriveStrength(6)), Err(Error::BadSpec));
    sys.set_conf(&mut bus, 20, Conf::InputEnable(false)).unwrap();
    assert_eq!(bus.regs[&pad] & 1, 0);
    sys.set_conf(&mut bus, 20, Conf::Schmitt(false)).unwrap();
    assert_eq!(bus.regs[&pad] & 0x40, 0);
    sys.set_conf(&mut bus, 20, Conf::Schmitt(true)).unwrap();
    assert_eq!(bus.regs[&pad] & 0x40, 0x40);
    // The SLEW (bit 5) and POS (bit 7) bits are not touched.
    assert_eq!(bus.regs[&pad] & 0xa0, 0xa0);
}

#[test]
fn pads_that_are_not_full_pads_take_only_what_their_register_has() {
    let (log, mut bus) = rig();
    let mut sys = Jh7110Iomux::sys(SYS);
    let mut aon = Jh7110Iomux::aon(AON);
    // SD0 (64..=74) and QSPI (89..=94) have the full register.
    sys.set_conf(&mut bus, 64, Conf::InputEnable(true)).unwrap();
    sys.set_conf(&mut bus, 94, Conf::InputEnable(true)).unwrap();
    assert_eq!(log.writes(), [(SYS + 0x120 + 4 * 64, 1), (SYS + 0x120 + 4 * 94, 1)]);
    // GMAC1 (75..=88) only has an IO-voltage select: no pad properties.
    assert_eq!(sys.set_bias(&mut bus, 80, Bias::PullUp), Err(Error::Unsupported));
    assert_eq!(sys.set_conf(&mut bus, 80, Conf::Schmitt(true)), Err(Error::Unsupported));
    // Past the last pad of the table.
    assert_eq!(sys.set_bias(&mut bus, 95, Bias::PullUp), Err(Error::BadSpec));
    log.clear();
    // AON RSTN (5): SMT is bit 0 (T2-770), nothing else.
    aon.set_conf(&mut bus, 5, Conf::Schmitt(true)).unwrap();
    assert_eq!(log.writes(), [(AON + 0x44, 1)]);
    assert_eq!(aon.set_conf(&mut bus, 5, Conf::InputEnable(true)), Err(Error::Unsupported));
    assert_eq!(aon.set_bias(&mut bus, 5, Bias::PullUp), Err(Error::Unsupported));
    // AON RTC (7) and OSC (9): DS is [1:0] (T2-771, T2-772), nothing else.
    log.clear();
    aon.set_conf(&mut bus, 7, Conf::DriveStrength(12)).unwrap();
    aon.set_conf(&mut bus, 9, Conf::DriveStrength(4)).unwrap();
    assert_eq!(log.writes(), [(AON + 0x4c, 3), (AON + 0x54, 1)]);
    assert_eq!(aon.set_conf(&mut bus, 7, Conf::Schmitt(true)), Err(Error::Unsupported));
    // TESTEN (0) has only POS; the gaps at 6 and 8 are not in the TRM.
    assert_eq!(aon.set_conf(&mut bus, 0, Conf::Schmitt(true)), Err(Error::Unsupported));
    assert_eq!(aon.set_conf(&mut bus, 6, Conf::Schmitt(true)), Err(Error::BadSpec));
    assert_eq!(aon.set_conf(&mut bus, 8, Conf::Schmitt(true)), Err(Error::BadSpec));
    // GMAC0 (10..=23) only has the voltage select.
    assert_eq!(aon.set_bias(&mut bus, 12, Bias::PullUp), Err(Error::Unsupported));
}

#[test]
fn function_select_is_a_field_at_the_place_the_tables_give() {
    let (log, mut bus) = rig();
    let mut sys = Jh7110Iomux::sys(SYS);
    // GPIO10 is [4:2] of 0x29c; bits [1:0] there are GMAC1_RXC's (pin 82).
    bus.regs.insert(SYS + 0x29c, 0xffff_ffff);
    sys.set_mux(&mut bus, funcsel(10, 2)).unwrap();
    assert_eq!(bus.regs[&(SYS + 0x29c)], 0xffff_ffe3 | 2 << 2);
    sys.set_mux(&mut bus, funcsel(82, 1)).unwrap();
    assert_eq!(bus.regs[&(SYS + 0x29c)] & 3, 1);
    // GPIO35 is a 2-bit field at [16:15] of 0x2a4 (T2-748).
    bus.regs.insert(SYS + 0x2a4, 0);
    sys.set_mux(&mut bus, funcsel(35, 3)).unwrap();
    assert_eq!(bus.regs[&(SYS + 0x2a4)], 3 << 15);
    // GPIO6 is [1:0] of 0x2b0, GPIO7 [4:2] (T2-751).
    bus.regs.insert(SYS + 0x2b0, 0);
    sys.set_mux(&mut bus, funcsel(7, 3)).unwrap();
    sys.set_mux(&mut bus, funcsel(6, 2)).unwrap();
    assert_eq!(bus.regs[&(SYS + 0x2b0)], 3 << 2 | 2);
    // AON GMAC0_RXC (pin 17): [1:0] of 0x90 (T2-787).
    let mut aon = Jh7110Iomux::aon(AON);
    log.clear();
    aon.set_mux(&mut bus, funcsel(17, 1)).unwrap();
    assert_eq!(log.writes(), [(AON + 0x90, 1)]);
    // GPIO0..5 have none; "Function 4" does not exist; neither does a pin past the table.
    log.clear();
    assert_eq!(sys.set_mux(&mut bus, funcsel(3, 1)), Err(Error::BadSpec));
    assert_eq!(sys.set_mux(&mut bus, funcsel(10, 4)), Err(Error::BadSpec));
    assert_eq!(sys.set_mux(&mut bus, funcsel(90, 1)), Err(Error::BadSpec));
    assert!(log.writes().is_empty());
}

/// A controller that implements only what the trait requires.
struct Bare;
impl PinctrlOps for Bare {
    fn pin_of(&self, word: u32) -> u32 {
        word & 0xff
    }
    fn set_mux(&mut self, _bus: &mut dyn azos_soc::Bus, _word: u32) -> azos_soc::Result<()> {
        Ok(())
    }
    fn set_bias(&mut self, _bus: &mut dyn azos_soc::Bus, _pin: u32, _bias: Bias) -> azos_soc::Result<()> {
        Ok(())
    }
}

#[test]
fn a_controller_without_the_property_stops_the_walk_after_the_record() {
    let blob = blob();
    let fdt = Fdt::parse(&blob).unwrap();
    let (log, mut bus) = rig();
    let mut fx = Sink::new(&log);
    let mut bare = Bare;
    let mut pc = Pinctrl::new();
    pc.add(fdt.by_phandle(SYS_PH).unwrap(), &mut bare).unwrap();
    let r = pc.select(&mut bus, &mut fx, &fdt, by_path(&fdt, "/soc/serial@10000000").unwrap(), Sel::Name("default"));
    // The TX group's drive-strength is the first property the controller lacks.
    assert_eq!(r, Err(Error::Unsupported));
    assert_eq!(log.effects().last().unwrap().op, Op::SetConf);
    assert_eq!(log.effects().len(), 3); // mux, bias, the failed conf
}

#[test]
fn a_refused_configuration_writes_nothing() {
    let blob = blob();
    let fdt = Fdt::parse(&blob).unwrap();
    let (log, mut bus) = rig();
    let mut fx = Sink::new(&log).refusing(|e| e.op == Op::SetConf);
    let mut sys = Jh7110Iomux::from_dt(&fdt, fdt.by_phandle(SYS_PH).unwrap()).unwrap();
    let mut pc = Pinctrl::new();
    pc.add(fdt.by_phandle(SYS_PH).unwrap(), &mut sys).unwrap();
    let r = pc.select(&mut bus, &mut fx, &fdt, by_path(&fdt, "/soc/serial@10000000").unwrap(), Sel::Index(0));
    assert_eq!(r, Err(Error::Refused(77)));
    // The mux (dout, doen) and the bias of the TX pad went ahead; nothing
    // was written for the refused drive strength or anything after it.
    assert_eq!(log.writes(), [(SYS + 0x44, 20 << 8), (SYS + 0x04, 0), (SYS + 0x134, 0)]);
}

// ---- the boot step ----

mod boot {
    use super::*;
    use azos_soc::boot::{Families, Soc, Storage};

    #[test]
    fn the_boot_step_registers_the_pad_controllers_and_drops_one_whose_window_is_refused() {
        let blob = blob();
        let fdt = Fdt::parse(&blob).unwrap();
        let u = by_path(&fdt, "/soc/serial@10000000").unwrap();
        let (log, mut bus) = rig();
        let mut fx = Sink::new(&log);

        let mut st = Storage::new();
        st.scan(&fdt, Families { jh7110: true, k1: false });
        let mut windows = Vec::new();
        let w = st.map_windows(&fdt, |base, _| {
            windows.push(base);
            true
        });
        assert_eq!((w.mapped, w.failed), (2, 0));
        assert_eq!(windows, [SYS, AON]);
        let mut soc = Soc::build(&mut st, &fdt, &mut azos_soc::regulator::Io { bus: &mut bus, i2c: None }, &mut fx);
        assert_eq!((soc.report.pin_controllers, soc.report.dropped), (2, 0), "{:?}", soc.report);
        // The manager the boot step built selects the consumer's state.
        soc.pins.select(&mut bus, &mut fx, &fdt, u, Sel::Name("default")).unwrap();
        assert!(log.writes().contains(&(SYS + 0x44, 20 << 8)));
        assert!(log.writes().contains(&(AON + 0x0, 5 << 16)));

        // The always-on window refused: that controller is dropped, and the
        // state that needs it no longer resolves.
        let mut st = Storage::new();
        st.scan(&fdt, Families { jh7110: true, k1: false });
        let w = st.map_windows(&fdt, |base, _| base != AON);
        assert_eq!((w.mapped, w.failed), (1, 1));
        let (log, mut bus) = rig();
        let mut fx = Sink::new(&log);
        let mut soc = Soc::build(&mut st, &fdt, &mut azos_soc::regulator::Io { bus: &mut bus, i2c: None }, &mut fx);
        assert_eq!((soc.report.pin_controllers, soc.report.dropped), (1, 1), "{:?}", soc.report);
        assert_eq!(soc.pins.select(&mut bus, &mut fx, &fdt, u, Sel::Name("default")), Err(Error::NoProvider));

        // An image without the family has no pad controller.
        let mut st = Storage::new();
        st.scan(&fdt, Families { jh7110: false, k1: false });
        let (log, mut bus) = rig();
        let mut fx = Sink::new(&log);
        let soc = Soc::build(&mut st, &fdt, &mut azos_soc::regulator::Io { bus: &mut bus, i2c: None }, &mut fx);
        assert_eq!(soc.report.pin_controllers, 0);
    }
}

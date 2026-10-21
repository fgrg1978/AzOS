// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The SoC frameworks in the kernel: what the hardware bus hands a driver
//! (the node offset), what the boot step builds from the device tree, how a
//! change reaches the effect gate, and how the thermal cap reaches a clock.

use crate::support::*;
use azos_soc::fdt::Fdt;
use azos_soc::NodeId;

// ---- the bus records the node ----

/// `dtb_devices` reports the offset `azos_soc::NodeId` is, for every node it
/// lists, so `Device::with_dt_node` is a lookup key and not a guess.
#[test]
fn every_device_the_enumerator_lists_names_its_own_node() {
    let blob = board();
    let fdt = Fdt::parse(&blob).unwrap();
    let mut seen = 0;
    // SAFETY: `blob` is a complete tree the builder wrote.
    let n = unsafe {
        azos_dtb::dtb_devices(blob.as_ptr(), &mut |d: &azos_dtb::DtDevice<'_>| {
            let node = NodeId(d.dt_node);
            assert_eq!(fdt.name(node).map(str::as_bytes), Some(d.name), "node {} is not {:?}", d.dt_node, d.name);
            seen += 1;
        })
    };
    assert_eq!(n, Some(seen));
    assert!(seen >= 4, "the fixture lists the UART, the clock controller, the PMU and the pad controller");
}

#[test]
fn the_uart_device_resolves_its_clock_from_the_node_the_enumerator_reported() {
    use azos_soc::clk::ClockTree;
    use azos_soc::consumer::Sel;
    let blob = board();
    let fdt = Fdt::parse(&blob).unwrap();
    let mut node = None;
    // SAFETY: as above.
    unsafe {
        azos_dtb::dtb_devices(blob.as_ptr(), &mut |d: &azos_dtb::DtDevice<'_>| {
            if d.name == b"serial@10000000" {
                node = Some(NodeId(d.dt_node));
            }
        })
    };
    assert_eq!(node, Some(uart(&fdt)));
    // The consumer lookup works from it (the provider is not registered here:
    // `NoProvider`, not `NotFound`, says the property was read).
    let tree = ClockTree::new();
    assert_eq!(tree.get(&fdt, node.unwrap(), Sel::Name("baudclk")).unwrap_err(), azos_soc::Error::NoProvider);
}

// ---- the boot builder over a VisionFive-2-shaped tree ----

use azos_soc::boot::{Families, Soc, Storage, Windows};
use azos_soc::regulator::Io;
use azos_soc::consumer::Sel;
use azos_soc::effect::{Class, Op, KIND_CLOCK, KIND_POWER_DOMAIN, KIND_REGULATOR, KIND_RESET};
use azos_soc::Error;
use std::rc::Rc;

const JH: Families = Families { jh7110: true, k1: false };
const GENERIC: Families = Families { jh7110: false, k1: false };

/// `board()` plus what the real tree has around it: `extra` fixed clocks
/// that come BEFORE the oscillator in document order (the board has dozens),
/// the always-on and storage clock-and-reset blocks, and the four CPUs.
fn vf2(extra: u32) -> Vec<u8> {
    let mut b = Builder::new();
    b.cells("#address-cells", &[2]).cells("#size-cells", &[2]);
    for i in 0..extra {
        b.begin(&format!("ext-clock-{i}")).str("compatible", "fixed-clock").cells("#clock-cells", &[0])
            .cells("clock-frequency", &[1_000_000 + i]).ph(100 + i).end();
    }
    for (name, ph, hz) in [("oscillator", OSC, 24_000_000), ("pll0", PLL0, 1_500_000_000), ("pll2", PLL2, 1_188_000_000)] {
        b.begin(name).str("compatible", "fixed-clock").cells("#clock-cells", &[0]).cells("clock-frequency", &[hz]).ph(ph).end();
    }
    b.begin("cpus").cells("#address-cells", &[1]).cells("#size-cells", &[0]);
    for c in 0..4u32 {
        b.begin(&format!("cpu@{c}")).str("device_type", "cpu").cells("reg", &[c]).cells("clocks", &[SYSCRG, 1]).end();
    }
    b.end();
    b.begin("soc").cells("#address-cells", &[2]).cells("#size-cells", &[2]).flag("ranges");
    b.begin("clock-controller@13020000")
        .strs("compatible", &["starfive,jh7110-syscrg"])
        .cells("reg", &[0, 0x1302_0000, 0, 0x10000])
        .cells("clocks", &[OSC, PLL0, PLL2])
        .strs("clock-names", &["osc", "pll0_out", "pll2_out"])
        .cells("#clock-cells", &[1])
        .cells("#reset-cells", &[1])
        .ph(SYSCRG)
        .end();
    b.begin("clock-controller@17000000")
        .strs("compatible", &["starfive,jh7110-aoncrg"])
        .cells("reg", &[0, 0x1700_0000, 0, 0x10000])
        .cells("#reset-cells", &[1])
        .ph(AON)
        .end();
    b.begin("clock-controller@10230000")
        .strs("compatible", &["starfive,jh7110-stgcrg"])
        .cells("reg", &[0, 0x1023_0000, 0, 0x10000])
        .cells("#reset-cells", &[1])
        .ph(STG)
        .end();
    b.begin("power-controller@17030000")
        .strs("compatible", &["starfive,jh7110-pmu"])
        .cells("reg", &[0, 0x1703_0000, 0, 0x10000])
        .cells("#power-domain-cells", &[1])
        .ph(PMU)
        .end();
    b.begin("regulator-vdd")
        .str("compatible", "regulator-fixed")
        .cells("regulator-min-microvolt", &[1_800_000])
        .cells("regulator-max-microvolt", &[1_800_000])
        .flag("regulator-always-on")
        .ph(VDD)
        .end();
    b.begin("serial@10000000")
        .str("compatible", "snps,dw-apb-uart")
        .cells("reg", &[0, 0x1000_0000, 0, 0x10000])
        .cells("clocks", &[SYSCRG, 146, SYSCRG, 145])
        .strs("clock-names", &["baudclk", "apb_pclk"])
        .cells("resets", &[SYSCRG, 74, AON, 3])
        .strs("reset-names", &["apb", "core"])
        .cells("power-domains", &[PMU, 2])
        .cells("vdd-supply", &[VDD])
        .end();
    b.end();
    b.finish()
}

const AON: u32 = 40;
const STG: u32 = 41;

fn soc_over<'p>(st: &'p mut Storage, fdt: &Fdt<'_>, log: &Rc<Log>, fam: Families) -> (Soc<'p>, TraceBus, Sink) {
    st.scan(fdt, fam);
    let mut bus = TraceBus::new(log);
    let mut fx = Sink::new(log);
    let soc = Soc::build(st, fdt, &mut Io { bus: &mut bus, i2c: None }, &mut fx);
    (soc, bus, fx)
}

#[test]
fn the_boot_builder_registers_every_framework_the_tree_describes() {
    let blob = vf2(0);
    let fdt = Fdt::parse(&blob).unwrap();
    let log = Log::new();
    let mut st = Storage::new();
    let (mut soc, mut bus, _fx) = soc_over(&mut st, &fdt, &log, JH);
    let r = soc.report;
    // osc, pll0, pll2 and the system controller; the three reset banks; the
    // PMU; the one fixed rail, switched on because its node says always-on.
    assert_eq!((r.clocks, r.resets, r.regulators, r.domains, r.dropped), (4, 3, 1, 1, 0), "{r:?}");
    assert_eq!(r.always_on, Ok(1));

    // The UART's properties resolve against what was registered.
    let u = uart(&fdt);
    let clk = soc.clocks.get(&fdt, u, Sel::Name("baudclk")).unwrap();
    assert_eq!((clk.prov, clk.id), (0, 146), "the system controller is first in the tree, its inputs follow");
    assert_eq!(soc.clocks.rate(&mut bus, azos_soc::clk::Clk { prov: 1, id: 0 }).unwrap(), 24_000_000);
    // And the UART's own clock gets its rate through the resolved input.
    assert_eq!(soc.clocks.rate(&mut bus, clk).unwrap(), 24_000_000);
    let apb = soc.resets.get(&fdt, u, Sel::Name("apb")).unwrap();
    let core = soc.resets.get(&fdt, u, Sel::Name("core")).unwrap();
    assert_ne!(apb.prov, core.prov, "the second line is the always-on block's bank");
    assert!(soc.domains.get(&fdt, u, Sel::Index(0)).is_ok());
    let vdd = soc.regulators.get_supply(&fdt, u, "vdd").unwrap();
    assert_eq!(soc.regulators.refs(vdd), 1);
}

#[test]
fn an_image_without_the_family_builds_only_the_generic_providers() {
    let blob = vf2(0);
    let fdt = Fdt::parse(&blob).unwrap();
    let log = Log::new();
    let mut st = Storage::new();
    let (soc, _bus, _fx) = soc_over(&mut st, &fdt, &log, GENERIC);
    let r = soc.report;
    assert_eq!((r.clocks, r.resets, r.regulators, r.domains), (3, 0, 1, 0), "{r:?}");
    let err = soc.clocks.get(&fdt, uart(&fdt), Sel::Name("baudclk")).unwrap_err();
    assert_eq!(err, Error::NoProvider);
}

#[test]
fn the_inputs_of_a_controller_get_slots_before_unrelated_fixed_clocks() {
    // Fixed clocks sit ahead of the oscillator, more than the tree has room
    // for. The three inputs and the system controller come first; the
    // strangers fill what is left, and the rest are counted as dropped, not
    // silently lost.
    let room = azos_soc::clk::MAX_PROVIDERS - 4;
    let strangers = (room + 6) as u32;
    let blob = vf2(strangers);
    let fdt = Fdt::parse(&blob).unwrap();
    let log = Log::new();
    let mut st = Storage::new();
    let (mut soc, mut bus, _fx) = soc_over(&mut st, &fdt, &log, JH);
    assert_eq!(soc.report.clocks as usize, azos_soc::clk::MAX_PROVIDERS);
    assert_eq!(soc.report.dropped, 6, "{:?}", soc.report);
    let clk = soc.clocks.get(&fdt, uart(&fdt), Sel::Name("baudclk")).unwrap();
    // The gate's parent chain reaches the oscillator through the resolved input.
    assert!(soc.clocks.rate(&mut bus, clk).is_ok());
}

#[test]
fn the_register_windows_are_mapped_once_each_and_a_generic_image_maps_none() {
    let blob = vf2(0);
    let fdt = Fdt::parse(&blob).unwrap();
    let mut st = Storage::new();
    st.scan(&fdt, JH);
    let mut asked = Vec::new();
    let w = st.map_windows(&fdt, |base, size| {
        asked.push((base, size));
        true
    });
    // The system controller serves clocks and resets and appears once.
    assert_eq!(asked, [(0x1302_0000, 0x1_0000), (0x1700_0000, 0x1_0000), (0x1023_0000, 0x1_0000), (0x1703_0000, 0x1_0000)]);
    assert_eq!(w, Windows { mapped: 4, failed: 0 });
    assert!(asked.len() <= azos_soc::boot::MAX_WINDOWS);
    let mut none = Storage::new();
    none.scan(&fdt, GENERIC);
    assert_eq!(none.map_windows(&fdt, |_, _| panic!("a generic image has no register window")), Windows { mapped: 0, failed: 0 });
}

#[test]
fn a_provider_whose_window_was_refused_is_dropped_and_no_register_of_it_is_touched() {
    let blob = vf2(0);
    let fdt = Fdt::parse(&blob).unwrap();
    let log = Log::new();
    let mut st = Storage::new();
    st.scan(&fdt, JH);
    // The system controller's window is refused: it is both a clock and a
    // reset provider, so two providers go; the always-on block, the storage
    // block and the PMU keep theirs.
    let w = st.map_windows(&fdt, |base, _| base != 0x1302_0000);
    assert_eq!(w, Windows { mapped: 3, failed: 1 });
    let mut bus = TraceBus::new(&log);
    let mut fx = Sink::new(&log);
    let soc = Soc::build(&mut st, &fdt, &mut Io { bus: &mut bus, i2c: None }, &mut fx);
    let r = soc.report;
    assert_eq!((r.clocks, r.resets, r.regulators, r.domains, r.dropped), (3, 2, 1, 1, 2), "{r:?}");
    log.clear();
    // The UART's clocks were the system controller's: no provider, and not one
    // register access in the unmapped window.
    let u = uart(&fdt);
    assert!(soc.clocks.get(&fdt, u, Sel::Name("baudclk")).is_err());
    assert!(soc.clocks.get(&fdt, u, Sel::Name("apb_pclk")).is_err());
    assert!(log.all().is_empty(), "{:?}", log.all());
    assert!(log.reads().iter().chain(log.writes().iter().map(|(a, _)| a)).all(|a| !(0x1302_0000..0x1303_0000).contains(a)));
}

#[test]
fn the_always_on_rail_is_recorded_before_anything_else_and_no_register_is_touched() {
    let blob = vf2(0);
    let fdt = Fdt::parse(&blob).unwrap();
    let log = Log::new();
    let mut st = Storage::new();
    let (_soc, _bus, _fx) = soc_over(&mut st, &fdt, &log, JH);
    let all = log.all();
    assert_eq!(all.len(), 1, "boot builds the managers and changes one thing: {all:?}");
    match &all[0] {
        Ev::E(e) => assert_eq!((e.kind, e.op, e.class), (KIND_REGULATOR, Op::Enable, Class::Reversible)),
        other => panic!("the first event is a register access: {other:?}"),
    }
    assert!(log.writes().is_empty());
}

#[test]
fn a_consumer_change_after_boot_is_recorded_before_the_register_write() {
    let blob = vf2(0);
    let fdt = Fdt::parse(&blob).unwrap();
    let log = Log::new();
    let mut st = Storage::new();
    let (mut soc, mut bus, mut fx) = soc_over(&mut st, &fdt, &log, JH);
    let u = uart(&fdt);
    // Every register write is preceded by a record made since the previous
    // write (reads of the state may come between), and the change's first
    // record is of its kind.
    let check = |what: &str, want: u8| {
        let ev = log.all();
        let mut armed = false;
        let mut writes = 0;
        for e in &ev {
            match e {
                Ev::E(_) => armed = true,
                Ev::W(a, _) => {
                    assert!(armed, "{what}: write to {a:#x} with no record since the last write: {ev:?}");
                    armed = false;
                    writes += 1;
                }
                Ev::R(_) => {}
            }
        }
        assert!(writes > 0, "{what} wrote nothing: the row would pass for nothing");
        assert!(matches!(ev.iter().find(|e| matches!(e, Ev::E(_))), Some(Ev::E(e)) if e.kind == want), "{what}: {ev:?}");
        log.clear();
    };
    log.clear();
    let clk = soc.clocks.get(&fdt, u, Sel::Name("apb_pclk")).unwrap();
    soc.clocks.enable(&mut bus, &mut fx, clk).unwrap();
    check("clock enable", KIND_CLOCK);
    let rst = soc.resets.get(&fdt, u, Sel::Name("apb")).unwrap();
    soc.resets.assert(&mut bus, &mut fx, rst).unwrap();
    check("reset assert", KIND_RESET);
    let pd = soc.domains.get(&fdt, u, Sel::Index(0)).unwrap();
    // The sequencer reports done.
    bus.regs.insert(0x1703_0000 + 0x8c, 1);
    soc.domains.on(&mut bus, &mut fx, pd).unwrap();
    // The PMU reads the domain's state before it switches; the record comes
    // before the first register WRITE, and the sink is asked first.
    let ev = log.all();
    let rec = ev.iter().position(|e| matches!(e, Ev::E(x) if x.kind == KIND_POWER_DOMAIN)).unwrap();
    let wr = ev.iter().position(|e| matches!(e, Ev::W(..))).unwrap();
    assert!(rec < wr, "{ev:?}");
}

#[test]
fn a_refused_effect_leaves_the_hardware_alone() {
    let blob = vf2(0);
    let fdt = Fdt::parse(&blob).unwrap();
    let log = Log::new();
    let mut st = Storage::new();
    st.scan(&fdt, JH);
    let mut bus = TraceBus::new(&log);
    let mut fx = Sink::new(&log).refusing(|e| e.kind == KIND_CLOCK);
    let mut soc = Soc::build(&mut st, &fdt, &mut Io { bus: &mut bus, i2c: None }, &mut fx);
    log.clear();
    let clk = soc.clocks.get(&fdt, uart(&fdt), Sel::Name("apb_pclk")).unwrap();
    assert_eq!(soc.clocks.enable(&mut bus, &mut fx, clk).unwrap_err(), Error::Refused(77));
    assert!(log.writes().is_empty(), "no register was written for a refused enable");
}

// ---- the thermal cap reaches the clock through the frameworks ----

mod thermal {
    use super::*;
    use azos_energy::model::{EnergyModel, ModelSource, Opp, PerfDomain};
    use azos_energy::opp::OppActuator;
    use azos_energy::thermal::{CoolingMap, Thermal, Trip, TripKind, Zone};
    use azos_soc::clk::Clk;
    use azos_thermal::jh7110::CpuClock;
    use azos_thermal::runtime::{Inputs, Runtime};
    use azos_thermal::sensor::{SensorBank, SensorError};
    use azos_thermal::soc::SocCpuClock;

    const PASSIVE: i32 = 80_000;
    const SYS: u64 = 0x1302_0000;
    /// The system controller's `cpu_core` divider.
    const CPU_CORE: Clk = Clk { prov: 0, id: 1 };

    /// The VisionFive 2's cluster: 375, 500, 750 MHz and 1.5 GHz.
    fn model() -> EnergyModel {
        let mut m = EnergyModel::from_source(ModelSource::Topology);
        let mut d = PerfDomain::new(0b1111);
        // The slowest OPP is the one the real-time work was measured at: the
        // safety floor, so heat may cap all the way down (0 would mean
        // "undeclared", and the floor would hold the top OPP).
        d.wcet_ref_khz = 375_000;
        for (f, c, p) in [(375_000, 64, 100), (500_000, 128, 150), (750_000, 256, 300), (1_500_000, 1024, 1000)] {
            d.push_opp(Opp { freq_khz: f, capacity: c, power_mw: p }).unwrap();
        }
        m.push_domain(d).unwrap();
        m
    }

    fn runtime(m: &EnergyModel) -> Runtime {
        let mut z = Zone::new(b"cpu-thermal", 0);
        z.poll_ms = 100;
        z.poll_passive_ms = 100;
        z.push_trip(Trip { temp_mdeg: PASSIVE, hyst_mdeg: 2_000, kind: TripKind::Passive }).unwrap();
        z.push_map(CoolingMap { trip: 0, domain: 0, min_state: 0, max_state: 3 }, m).unwrap();
        let mut t = Thermal::new();
        t.push_zone(z).unwrap();
        let mut r = Runtime::new(t);
        // The firmware left the cluster at its top OPP.
        r.dvfs.assume(0, 3);
        r
    }

    struct Temp(i32);
    impl SensorBank for Temp {
        fn read_mdeg(&mut self, _: u8) -> Result<i32, SensorError> { Ok(self.0) }
    }

    /// The thermal board object: a sensor and the SoC clock.
    struct Board<'a, 'p> {
        temp: Temp,
        clock: SocCpuClock<'a, 'p>,
    }
    impl SensorBank for Board<'_, '_> {
        fn read_mdeg(&mut self, s: u8) -> Result<i32, SensorError> { self.temp.read_mdeg(s) }
    }
    impl OppActuator for Board<'_, '_> {
        fn set_opp(&mut self, _d: usize, o: &Opp) -> Result<(), azos_energy::opp::ActuateError> {
            self.clock.set_cpu_khz(o.freq_khz)
        }
    }

    fn want_top() -> Inputs {
        let mut i = Inputs::IDLE;
        i.want[0] = Some(3);
        i
    }

    /// `cpu_root` selects PLL0 (1.5 GHz in the fixture), `cpu_core` divides by 1.
    fn running_at_the_top(bus: &mut TraceBus) {
        bus.regs.insert(SYS, 1 << 24);
        bus.regs.insert(SYS + 4, 1);
    }

    #[test]
    fn the_cluster_clock_is_the_one_the_first_cpu_node_names() {
        let blob = vf2(0);
        let fdt = Fdt::parse(&blob).unwrap();
        let log = Log::new();
        let mut st = Storage::new();
        let (soc, _bus, _fx) = soc_over(&mut st, &fdt, &log, JH);
        assert_eq!(azos_thermal::soc::cpu_clock(&fdt, &soc.clocks), Some(CPU_CORE));
    }

    #[test]
    fn heat_pulls_the_cluster_down_through_the_clock_framework_and_each_step_is_recorded_first() {
        let blob = vf2(0);
        let fdt = Fdt::parse(&blob).unwrap();
        let log = Log::new();
        let mut st = Storage::new();
        let (mut soc, mut bus, mut fx) = soc_over(&mut st, &fdt, &log, JH);
        running_at_the_top(&mut bus);
        log.clear();
        let m = model();
        let mut rt = runtime(&m);
        let mut board = Board {
            temp: Temp(PASSIVE + 1_000),
            clock: SocCpuClock {
                tree: &mut soc.clocks,
                bus: &mut bus,
                fx: &mut fx,
                clk: CPU_CORE,
                ceiling_khz: 1_500_000,
            },
        };
        // One OPP step down per read: 750, 500, 375 MHz.
        for k in 0..3 {
            rt.tick(&mut board, &m, k * 100, &want_top());
        }
        drop(board);
        // The divider of `cpu_core`: 1.5 GHz / 2, / 3, / 4.
        assert_eq!(log.writes(), vec![(SYS + 4, 2), (SYS + 4, 3), (SYS + 4, 4)]);
        let ev = log.all();
        let mut armed = false;
        for e in &ev {
            match e {
                Ev::E(x) => {
                    assert_eq!((x.kind, x.op, x.class, x.id), (KIND_CLOCK, Op::SetRate, Class::Reversible, 1));
                    armed = true;
                }
                Ev::W(..) => {
                    assert!(armed, "a clock write with no record before it: {ev:?}");
                    armed = false;
                }
                Ev::R(_) => {}
            }
        }
        assert_eq!(log.effects().iter().map(|e| e.value).collect::<Vec<_>>(), vec![750_000_000, 500_000_000, 375_000_000]);
    }

    #[test]
    fn a_sink_that_refuses_the_cap_leaves_the_clock_alone_and_the_runtime_raises_the_level() {
        let blob = vf2(0);
        let fdt = Fdt::parse(&blob).unwrap();
        let log = Log::new();
        let mut st = Storage::new();
        let (mut soc, mut bus, _fx) = soc_over(&mut st, &fdt, &log, JH);
        running_at_the_top(&mut bus);
        let mut fx = Sink::new(&log).refusing(|e| e.kind == KIND_CLOCK);
        log.clear();
        let m = model();
        let mut rt = runtime(&m);
        let mut board = Board {
            temp: Temp(PASSIVE + 1_000),
            clock: SocCpuClock {
                tree: &mut soc.clocks,
                bus: &mut bus,
                fx: &mut fx,
                clk: CPU_CORE,
                ceiling_khz: 1_500_000,
            },
        };
        let s = rt.tick(&mut board, &m, 0, &want_top());
        drop(board);
        assert!(log.writes().is_empty());
        assert!(s.level > 0, "heat that could not be answered must be announced, not ignored: {s:?}");
    }

    #[test]
    fn an_unmoved_supply_never_carries_a_clock_above_the_boot_rate() {
        let blob = vf2(0);
        let fdt = Fdt::parse(&blob).unwrap();
        let log = Log::new();
        let mut st = Storage::new();
        let (mut soc, mut bus, mut fx) = soc_over(&mut st, &fdt, &log, JH);
        running_at_the_top(&mut bus);
        let mut c = SocCpuClock {
            tree: &mut soc.clocks,
            bus: &mut bus,
            fx: &mut fx,
            clk: CPU_CORE,
            ceiling_khz: 750_000,
        };
        log.clear();
        assert_eq!(c.set_cpu_khz(1_500_000), Err(azos_energy::opp::ActuateError::Refused));
        assert!(log.all().is_empty(), "a refused request records nothing and writes nothing");
        assert_eq!(c.set_cpu_khz(750_000), Ok(()));
        assert_eq!(log.writes(), vec![(SYS + 4, 2)]);
    }
}

// ---- the K1 actuator reaches a clock and a rail through the frameworks ----

mod k1 {
    use super::*;
    use azos_dtb::{DtOpp, DtOppTable};
    use azos_energy::model::Opp;
    use azos_energy::opp::{ActuateError, OppActuator};
    use azos_soc::clk::Clk;
    use azos_soc::k1::p1::sel_to_uv;
    use azos_soc::k1::P1Buck;
    use azos_soc::regulator::Reg;
    use azos_soc::{I2cBus, Result};
    use azos_thermal::k1::{K1Opp, K1Table};
    use azos_thermal::k1_soc::{K1Clocks, K1Wires, SocK1Hw};
    use azos_soc::Error;
    use std::cell::Cell;

    const SYS: u64 = 0x1302_0000;
    const I2C: u64 = 0xd401_d800;
    const PMIC: u8 = 0x41;
    /// The JH7110 `cpu_core` divider stands in for a K1 cluster's rate clock:
    /// the framework path is the same, the provider is the one the tree has.
    const CPU_CORE: Clk = Clk { prov: 0, id: 1 };

    thread_local! {
        static WAITED_US: Cell<u32> = const { Cell::new(0) };
    }
    fn wait(us: u32) {
        WAITED_US.with(|w| w.set(w.get() + us));
    }

    /// The P1 behind the master: byte registers, every write in the shared log
    /// next to the clock's (the write's address is tagged `I2C_TAG`).
    struct Chip {
        regs: [u8; 256],
        log: Rc<Log>,
    }
    const I2C_TAG: u64 = 1 << 40;

    impl I2cBus for Chip {
        fn present(&self, ctrl: u64) -> bool {
            ctrl == I2C
        }
        fn read_reg(&mut self, _: u64, _: u8, reg: u8) -> Result<u8> {
            Ok(self.regs[reg as usize])
        }
        fn write_reg(&mut self, _: u64, _: u8, reg: u8, val: u8) -> Result<()> {
            self.log.0.borrow_mut().push(Ev::W(I2C_TAG | reg as u64, val as u32));
            self.regs[reg as usize] = val;
            Ok(())
        }
    }

    /// Buck 1: enable 0x47, selector 0x48. 1.1 V at the start.
    fn chip(log: &Rc<Log>, uv: u32) -> Chip {
        let mut regs = [0u8; 256];
        regs[0x47] = 1;
        regs[0x48] = azos_soc::k1::p1::uv_to_sel(uv).unwrap();
        Chip { regs, log: log.clone() }
    }

    fn uv_of(c: &Chip) -> u32 {
        sel_to_uv(c.regs[0x48]).unwrap()
    }

    fn wires(max_uv: u32) -> [Option<K1Wires>; 2] {
        [Some(K1Wires { clk: CPU_CORE, rail: Reg(0), buck: P1Buck::new(I2C, PMIC, 1).unwrap(), min_uv: 500_000, max_uv }), None]
    }

    /// 375 / 500 / 750 MHz and 1.5 GHz (the dividers of a 1.5 GHz root), with
    /// the voltage each is run at (invented).
    fn table(rail_max: u32, rows: &[(u64, u32)]) -> K1Table {
        let mut t = DtOppTable {
            phandle: 1,
            shared: true,
            opps: [DtOpp::EMPTY; azos_dtb::DT_ENERGY_OPPS],
            n_opps: rows.len() as u8,
            truncated: false,
        };
        for (i, &(hz, uv)) in rows.iter().enumerate() {
            t.opps[i] = DtOpp { hz, microwatt: 1, uv, uv_max: uv };
        }
        K1Table::from_dt(&t, rail_max, 5_000).unwrap()
    }

    /// The JH7110 clock model stands in for a cluster clock here, and it does
    /// not round (nothing in the kernel asks it to: only the K1's does). Every
    /// row of `ROWS` is an exact divider of the 1.5 GHz parent, so the rate
    /// asked for is the rate reached.
    struct ExactDiv<'a, 'p>(Direct<'a, 'p>);

    impl K1Clocks for ExactDiv<'_, '_> {
        fn rate(&mut self, clk: Clk) -> core::result::Result<u64, Error> {
            self.0.rate(clk)
        }
        fn round_rate(&mut self, _: Clk, hz: u64) -> core::result::Result<u64, Error> {
            Ok(hz)
        }
        fn set_rate(&mut self, clk: Clk, hz: u64) -> core::result::Result<u64, Error> {
            self.0.set_rate(clk, hz)
        }
    }

    fn opp(khz: u32) -> Opp {
        Opp { freq_khz: khz, capacity: 1, power_mw: 1 }
    }

    const ROWS: [(u64, u32); 4] =
        [(375_000_000, 800_000), (500_000_000, 850_000), (750_000_000, 900_000), (1_500_000_000, 1_100_000)];

    #[test]
    fn the_rail_and_the_clock_move_in_order_and_each_write_is_recorded_first() {
        let cpu_blob = vf2(0);
        let cpu_fdt = Fdt::parse(&cpu_blob).unwrap();
        let log = Log::new();
        let mut st = Storage::new();
        let (mut soc, mut bus, mut fx) = soc_over(&mut st, &cpu_fdt, &log, JH);
        bus.regs.insert(SYS, 1 << 24);
        bus.regs.insert(SYS + 4, 1); // 1.5 GHz
        let mut chip = chip(&log, 1_100_000);
        let mut rail_fx = Sink::new(&log);
        let t = table(1_200_000, &ROWS);
        log.clear();
        WAITED_US.with(|w| w.set(0));

        let hw = SocK1Hw {
            clocks: ExactDiv(Direct { tree: &mut soc.clocks, bus: &mut bus, fx: &mut fx }),
            i2c: &mut chip,
            fx: &mut rail_fx,
            wires: wires(1_200_000),
            delay: wait,
        };
        let mut a = K1Opp::new(hw);
        assert!(a.bind(0, t));

        // Down to 750 MHz: the divider first, then the rail.
        assert_eq!(a.set_opp(0, &opp(750_000)), Ok(()));
        let k = |e: &Ev| match e {
            Ev::E(x) => format!("fx:{}:{:?}:{}", x.kind, x.op, x.value),
            Ev::W(a, v) if a & I2C_TAG != 0 => format!("i2c:{:#x}:{}", a & 0xff, v),
            Ev::W(a, v) => format!("w:{a:#x}:{v}"),
            Ev::R(_) => String::new(),
        };
        let seq = |log: &Log| log.all().iter().map(k).filter(|s| !s.is_empty()).collect::<Vec<_>>();
        let down = seq(&log);
        let writes: Vec<&String> = down.iter().filter(|s| s.starts_with("w:") || s.starts_with("i2c:")).collect();
        // Selector 0x48: (900000 - 500000) / 5000 = 80.
        assert_eq!(writes, [&format!("w:{:#x}:2", SYS + 4), &"i2c:0x48:80".to_string()], "{down:?}");
        // Each write is preceded by its record.
        for (i, s) in down.iter().enumerate() {
            if s.starts_with("w:") || s.starts_with("i2c:") {
                assert!(down[i - 1].starts_with("fx:"), "{down:?}");
            }
        }
        assert_eq!(WAITED_US.with(Cell::get), 0, "no wait for a fall");

        // Back up to 1.5 GHz: the rail first (200 mV at 5000 uV/us: 40 us), then the divider.
        log.clear();
        assert_eq!(a.set_opp(0, &opp(1_500_000)), Ok(()));
        let up = seq(&log);
        let writes: Vec<&String> = up.iter().filter(|s| s.starts_with("w:") || s.starts_with("i2c:")).collect();
        // (1100000 - 500000) / 5000 = 120.
        assert_eq!(writes, [&"i2c:0x48:120".to_string(), &format!("w:{:#x}:1", SYS + 4)], "{up:?}");
        assert_eq!(WAITED_US.with(Cell::get), 40);
        drop(a);
        assert_eq!(uv_of(&chip), 1_100_000);
    }

    #[test]
    fn a_voltage_over_the_rails_own_constraints_is_refused_before_the_clock_moves() {
        let cpu_blob = vf2(0);
        let cpu_fdt = Fdt::parse(&cpu_blob).unwrap();
        let log = Log::new();
        let mut st = Storage::new();
        let (mut soc, mut bus, mut fx) = soc_over(&mut st, &cpu_fdt, &log, JH);
        bus.regs.insert(SYS, 1 << 24);
        bus.regs.insert(SYS + 4, 4); // 375 MHz
        let mut chip = chip(&log, 800_000);
        let mut rail_fx = Sink::new(&log);
        // A table built against a ceiling the rail does not have (a wrong
        // `regulator-max-microvolt` handed in): the rail's own constraints are
        // the second line, and the clock never moves up on a rail that stayed low.
        let t = table(1_300_000, &[(375_000_000, 800_000), (1_500_000_000, 1_250_000)]);
        log.clear();
        let hw = SocK1Hw {
            clocks: ExactDiv(Direct { tree: &mut soc.clocks, bus: &mut bus, fx: &mut fx }),
            i2c: &mut chip,
            fx: &mut rail_fx,
            wires: wires(1_200_000),
            delay: wait,
        };
        let mut a = K1Opp::new(hw);
        assert!(a.bind(0, t));
        assert_eq!(a.set_opp(0, &opp(1_500_000)), Err(ActuateError::Refused));
        assert!(log.writes().is_empty(), "{:?}", log.writes());
        // An unwired cluster is not there.
        assert_eq!(a.set_opp(1, &opp(375_000)), Err(ActuateError::Unsupported));
    }

    #[test]
    fn a_sink_that_refuses_the_rail_leaves_the_clock_where_it_was() {
        let cpu_blob = vf2(0);
        let cpu_fdt = Fdt::parse(&cpu_blob).unwrap();
        let log = Log::new();
        let mut st = Storage::new();
        let (mut soc, mut bus, mut fx) = soc_over(&mut st, &cpu_fdt, &log, JH);
        let mut rail_fx = Sink::new(&log).refusing(|e| e.kind == KIND_REGULATOR);
        bus.regs.insert(SYS, 1 << 24);
        bus.regs.insert(SYS + 4, 4);
        let mut chip = chip(&log, 800_000);
        let t = table(1_200_000, &[(375_000_000, 800_000), (1_500_000_000, 1_100_000)]);
        log.clear();
        let hw = SocK1Hw {
            clocks: ExactDiv(Direct { tree: &mut soc.clocks, bus: &mut bus, fx: &mut fx }),
            i2c: &mut chip,
            fx: &mut rail_fx,
            wires: wires(1_200_000),
            delay: wait,
        };
        let mut a = K1Opp::new(hw);
        assert!(a.bind(0, t));
        assert_eq!(a.set_opp(0, &opp(1_500_000)), Err(ActuateError::Refused));
        assert!(log.writes().is_empty(), "{:?}", log.writes());
    }
}

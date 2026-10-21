// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The JH7110 system clock controller, reset banks and PMU against
//! hand-written register traces. The clock layout (ids = register offset / 4,
//! field widths, divider limits, the AXI/AHB/APB chain) is the one TRM 2.8.1
//! Tables 2-50..2-206 and Figure 2-4 give; the reset banks and the PMU
//! sequence are the ones of TRM 2.8.1..2.8.3 and 3.6.
use crate::support::*;
use azos_soc::clk::{Clk, ClockTree};
use azos_soc::consumer::Sel;
use azos_soc::effect::{Class, Effect, Op, KIND_CLOCK};
use azos_soc::fdt::Fdt;
use azos_soc::fixed::FixedClock;
use azos_soc::jh7110::Jh7110Clk;
use azos_soc::Error;

const SYS: u8 = 3; // provider index: three fixed clocks come first

fn reg(id: u32) -> u64 {
    SYSCRG_BASE + 4 * id as u64
}

fn eff(op: Op, class: Class, id: u32, value: u64) -> Ev {
    Ev::E(Effect { kind: KIND_CLOCK, op, class, provider: SYS, id, value })
}

macro_rules! rig {
    ($blob:ident, $fdt:ident, $log:ident, $bus:ident, $fx:ident, $tree:ident) => {
        let $blob = board();
        let $fdt = Fdt::parse(&$blob).unwrap();
        let $log = Log::new();
        let mut $bus = TraceBus::new(&$log);
        let mut $fx = Sink::new(&$log);
        let mut osc = FixedClock::from_dt(&$fdt, $fdt.by_phandle(OSC).unwrap()).unwrap();
        let mut pll0 = FixedClock::from_dt(&$fdt, $fdt.by_phandle(PLL0).unwrap()).unwrap();
        let mut pll2 = FixedClock::from_dt(&$fdt, $fdt.by_phandle(PLL2).unwrap()).unwrap();
        let mut sys = Jh7110Clk::from_dt(&$fdt, $fdt.by_phandle(SYSCRG).unwrap()).unwrap();
        let mut $tree = ClockTree::new();
        $tree.add($fdt.by_phandle(OSC).unwrap(), &mut osc).unwrap();
        $tree.add($fdt.by_phandle(PLL0).unwrap(), &mut pll0).unwrap();
        $tree.add($fdt.by_phandle(PLL2).unwrap(), &mut pll2).unwrap();
        $tree.add($fdt.by_phandle(SYSCRG).unwrap(), &mut sys).unwrap();
        $tree.link(&$fdt);
    };
}

#[test]
fn the_uart_clocks_resolve_through_the_tree() {
    rig!(blob, fdt, log, bus, fx, tree);
    let _ = (&mut bus, &mut fx, &log);
    let u = uart(&fdt);
    assert_eq!(tree.get(&fdt, u, Sel::Name("baudclk")).unwrap(), Clk { prov: SYS, id: 146 });
    assert_eq!(tree.get(&fdt, u, Sel::Name("apb_pclk")).unwrap(), Clk { prov: SYS, id: 145 });
    // The controller only comes from its own compatible.
    assert!(Jh7110Clk::from_dt(&fdt, fdt.by_phandle(PMU).unwrap()).is_none());
}

#[test]
fn enabling_the_uart_apb_clock_writes_the_gates_root_first() {
    rig!(blob, fdt, log, bus, fx, tree);
    // Gate bits are read-modify-written: the other bits survive.
    bus.regs.insert(reg(12), 0x0000_0003);
    bus.regs.insert(reg(11), 2);
    let apb = tree.get(&fdt, uart(&fdt), Sel::Name("apb_pclk")).unwrap();
    tree.enable(&mut bus, &mut fx, apb).unwrap();
    // 145 <- apb0 (12) <- apb_bus_func (11, divider) <- ahb1 (10) <- bus_root
    // (5, mux: its select field is read once) <- osc. Only 10, 12 and 145
    // have gates.
    assert_eq!(
        log.all(),
        [
            Ev::R(reg(5)),
            eff(Op::Enable, Class::Reversible, 10, 1),
            Ev::R(reg(10)),
            Ev::W(reg(10), 0x8000_0000),
            eff(Op::Enable, Class::Reversible, 12, 1),
            Ev::R(reg(12)),
            Ev::W(reg(12), 0x8000_0003),
            eff(Op::Enable, Class::Reversible, 145, 1),
            Ev::R(reg(145)),
            Ev::W(reg(145), 0x8000_0000),
        ]
    );
    // Every clock in the chain is held once, down to the oscillator.
    for id in [145, 12, 11, 10, 5] {
        assert_eq!(tree.refs(Clk { prov: SYS, id }), 1, "clock {id}");
    }
    assert_eq!(tree.refs(Clk { prov: 0, id: 0 }), 1);
    assert!(tree.is_enabled(&mut bus, apb).unwrap());
}

#[test]
fn the_core_clock_shares_the_oscillator_and_closes_alone() {
    rig!(blob, fdt, log, bus, fx, tree);
    let u = uart(&fdt);
    let apb = tree.get(&fdt, u, Sel::Name("apb_pclk")).unwrap();
    let baud = tree.get(&fdt, u, Sel::Name("baudclk")).unwrap();
    tree.enable(&mut bus, &mut fx, apb).unwrap();
    log.clear();
    tree.enable(&mut bus, &mut fx, baud).unwrap();
    // 146's parent is the oscillator, already held: one gate, one more holder.
    assert_eq!(
        log.all(),
        [eff(Op::Enable, Class::Reversible, 146, 1), Ev::R(reg(146)), Ev::W(reg(146), 0x8000_0000)]
    );
    assert_eq!(tree.refs(Clk { prov: 0, id: 0 }), 2);
    log.clear();
    tree.disable(&mut bus, &mut fx, baud).unwrap();
    assert_eq!(
        log.all(),
        [eff(Op::Disable, Class::Safe, 146, 0), Ev::R(reg(146)), Ev::W(reg(146), 0)]
    );
    assert_eq!(tree.refs(Clk { prov: 0, id: 0 }), 1);
}

#[test]
fn clocks_without_a_gate_write_nothing() {
    rig!(blob, fdt, log, bus, fx, tree);
    let core = Clk { prov: SYS, id: 1 }; // cpu_core: divider under the cpu_root mux
    tree.enable(&mut bus, &mut fx, core).unwrap();
    assert!(log.writes().is_empty());
    assert!(log.effects().is_empty());
    assert_eq!(tree.refs(core), 1);
}

/// Seed the dividers of the AXI/AHB chain the APB clocks hang under:
/// axi_cfg0 (7) and stg_axiahb (8). The registers read 0 (a stopped clock)
/// until something writes them.
fn seed_chain(bus: &mut TraceBus, axi_cfg0: u32, stg_axiahb: u32) {
    bus.regs.insert(reg(7), axi_cfg0);
    bus.regs.insert(reg(8), stg_axiahb);
}

#[test]
fn rates_come_from_the_mux_and_the_dividers() {
    rig!(blob, fdt, log, bus, fx, tree);
    let _ = (&mut fx, &log);
    let apb = Clk { prov: SYS, id: 145 };
    seed_chain(&mut bus, 1, 1);
    bus.regs.insert(reg(11), 2);
    assert_eq!(tree.rate(&mut bus, apb).unwrap(), 12_000_000);
    // A divider of 0 is a stopped clock.
    bus.regs.insert(reg(11), 0);
    assert_eq!(tree.rate(&mut bus, apb).unwrap(), 0);
    // The board's chain (Figure 2-4): bus_root select 1 is pll2_out
    // (1_188 MHz), axi_cfg0 /3, stg_axiahb /2, apb_bus_func /4.
    bus.regs.insert(reg(5), 1 << 24);
    seed_chain(&mut bus, 3, 2);
    bus.regs.insert(reg(11), 4);
    assert_eq!(tree.rate(&mut bus, apb).unwrap(), 49_500_000);
    // A stopped divider anywhere up the chain stops everything below it.
    seed_chain(&mut bus, 3, 0);
    assert_eq!(tree.rate(&mut bus, apb).unwrap(), 0);
    // cpu_root select 1 is pll0_out (1 GHz), cpu_core divides by 2.
    bus.regs.insert(reg(0), 1 << 24);
    bus.regs.insert(reg(1), 2);
    assert_eq!(tree.rate(&mut bus, Clk { prov: SYS, id: 1 }).unwrap(), 500_000_000);
    // Select 0 is the oscillator.
    bus.regs.insert(reg(0), 0);
    assert_eq!(tree.rate(&mut bus, Clk { prov: SYS, id: 1 }).unwrap(), 12_000_000);
    // A select value with no parent is the hardware in a state the table
    // does not know.
    bus.regs.insert(reg(0), 5 << 24);
    assert_eq!(tree.rate(&mut bus, Clk { prov: SYS, id: 1 }), Err(Error::Hardware));
    // clk_mux_sel is the six bits [29:24] (T2-50): bit 29 alone is select 32.
    bus.regs.insert(reg(0), 1 << 29);
    assert_eq!(tree.rate(&mut bus, Clk { prov: SYS, id: 1 }), Err(Error::Hardware));
}

#[test]
fn set_rate_writes_the_closest_divider_and_keeps_the_other_bits() {
    rig!(blob, fdt, log, bus, fx, tree);
    let bus_func = Clk { prov: SYS, id: 11 }; // apb_bus_func, divider up to 8 (T2-61)
    seed_chain(&mut bus, 1, 1);
    bus.regs.insert(reg(11), 0x4000_0002); // a reserved bit set, divider 2
    assert_eq!(tree.set_rate(&mut bus, &mut fx, bus_func, 3_000_000).unwrap(), 3_000_000);
    assert_eq!(
        log.all(),
        [
            Ev::R(reg(5)),
            Ev::R(reg(7)),
            Ev::R(reg(8)),
            eff(Op::SetRate, Class::Reversible, 11, 3_000_000),
            Ev::R(reg(11)),
            Ev::W(reg(11), 0x4000_0008),
        ]
    );
    // Below what the divider can reach: its largest value, the rate that gives.
    assert_eq!(tree.set_rate(&mut bus, &mut fx, bus_func, 1_000_000).unwrap(), 3_000_000);
    assert_eq!(bus.regs[&reg(11)], 0x4000_0008);
    // Above the parent: divide by one.
    assert_eq!(tree.set_rate(&mut bus, &mut fx, bus_func, 100_000_000).unwrap(), 24_000_000);
    assert_eq!(bus.regs[&reg(11)], 0x4000_0001);
    // Rounded to the closest divider, not down: 24 MHz / 7 MHz = 3.43 -> 3.
    assert_eq!(tree.set_rate(&mut bus, &mut fx, bus_func, 7_000_000).unwrap(), 8_000_000);
    assert_eq!(tree.set_rate(&mut bus, &mut fx, bus_func, 0), Err(Error::BadSpec));
    // A gate cannot change its rate.
    assert_eq!(tree.set_rate(&mut bus, &mut fx, Clk { prov: SYS, id: 12 }, 1_000_000), Err(Error::Unsupported));
    // The divider limits are the TRM's: cpu_bus (2) takes at most 2 (T2-52),
    // stg_axiahb (8) at most 2 (T2-58), axi_cfg0 (7) at most 3 (T2-57).
    bus.regs.insert(reg(1), 1);
    for (id, max) in [(2u32, 2u32), (8, 2), (7, 3)] {
        let c = Clk { prov: SYS, id: id as u16 };
        tree.set_rate(&mut bus, &mut fx, c, 1).unwrap();
        assert_eq!(bus.regs[&reg(id)] & 0x00ff_ffff, max, "clock {id}");
    }
}

#[test]
fn a_clock_the_table_does_not_have_is_a_bad_spec_and_writes_nothing() {
    rig!(blob, fdt, log, bus, fx, tree);
    // Ids 3 and 4 are inside the table's range but not in it; 141..=144 are
    // not the UARTs (UART0 APB is 0x244 / 4 = 145, T2-195).
    assert_eq!(tree.enable(&mut bus, &mut fx, Clk { prov: SYS, id: 3 }), Err(Error::BadSpec));
    assert_eq!(tree.enable(&mut bus, &mut fx, Clk { prov: SYS, id: 141 }), Err(Error::BadSpec));
    assert_eq!(tree.enable(&mut bus, &mut fx, Clk { prov: SYS, id: 4000 }), Err(Error::BadSpec));
    assert!(log.writes().is_empty());
    assert!(log.effects().is_empty());
}

#[test]
fn a_refused_gate_leaves_the_register_alone() {
    rig!(blob, fdt, log, bus, _fx, tree);
    let mut fx = Sink::new(&log).refusing(|e| e.op == Op::Enable && e.id == 145);
    let apb = Clk { prov: SYS, id: 145 };
    assert_eq!(tree.enable(&mut bus, &mut fx, apb), Err(Error::Refused(77)));
    // 10 and 12 were opened and are closed again; 145 never was written.
    assert_eq!(
        log.writes(),
        [(reg(10), 0x8000_0000), (reg(12), 0x8000_0000), (reg(12), 0), (reg(10), 0)]
    );
    assert_eq!(tree.refs(apb), 0);
    assert_eq!(tree.refs(Clk { prov: 0, id: 0 }), 0);
}

// ---- reset banks (TRM 2.8.1 T2-240..T2-247, 2.8.2 T2-277/T2-278, 2.8.3 T2-293/T2-294) ----

mod resets {
    use crate::support::*;
    use azos_soc::jh7110::Jh7110Reset;
    use azos_soc::reset::ResetOps;
    use azos_soc::Error;

    const B: u64 = 0x1000_0000;

    fn rig() -> (std::rc::Rc<Log>, TraceBus) {
        let log = Log::new();
        let bus = TraceBus::new(&log);
        (log, bus)
    }

    #[test]
    fn the_assert_and_status_banks_are_where_the_tables_put_them() {
        // SYSCRG: assert 0x2f8 + 4 * bank, status 0x308 + 4 * bank.
        let (log, mut bus) = rig();
        let mut sys = Jh7110Reset::sys(B);
        for (line, bank) in [(0u32, 0u64), (33, 1), (64, 2), (96, 3)] {
            log.clear();
            sys.assert(&mut bus, line).unwrap();
            assert_eq!(log.writes().len(), 1);
            assert_eq!(log.writes()[0].0, B + 0x2f8 + 4 * bank, "assert, line {line}");
            // The status read of the same line: the bank the assert is in.
            // A released line reads 1, so the bit set means not held.
            bus.regs.insert(B + 0x308 + 4 * bank, 1 << (line % 32));
            log.clear();
            assert!(!sys.is_asserted(&mut bus, line).unwrap(), "status, line {line}");
            assert_eq!(log.reads(), [B + 0x308 + 4 * bank]);
        }
        // STGCRG: assert 0x74, status 0x78.
        let (log, mut bus) = rig();
        let mut stg = Jh7110Reset::stg(B);
        stg.assert(&mut bus, 22).unwrap();
        assert_eq!(log.writes(), [(B + 0x74, 1 << 22)]);
        assert!(stg.is_asserted(&mut bus, 22).unwrap());
        bus.regs.insert(B + 0x78, 1 << 22);
        assert!(!stg.is_asserted(&mut bus, 22).unwrap());
        // AONCRG: assert 0x38, status 0x3c.
        let (log, mut bus) = rig();
        let mut aon = Jh7110Reset::aon(B);
        aon.assert(&mut bus, 7).unwrap();
        assert_eq!(log.writes(), [(B + 0x38, 1 << 7)]);
        assert!(aon.is_asserted(&mut bus, 7).unwrap());
        bus.regs.insert(B + 0x3c, 1 << 7);
        assert!(!aon.is_asserted(&mut bus, 7).unwrap());
    }

    #[test]
    fn only_the_lines_the_tables_name_exist() {
        let (log, mut bus) = rig();
        let mut sys = Jh7110Reset::sys(B);
        // One past the highest line: bank 3 has bits 0..=29.
        assert_eq!(sys.count(), 126);
        // Holes inside banks: bank 0 bits 24, 25, 28, 30; bank 1 bit 11;
        // bank 3 bits 30 and 31.
        for id in [24, 25, 28, 30, 43, 126, 127, 128] {
            assert_eq!(sys.assert(&mut bus, id), Err(Error::BadSpec), "line {id}");
            assert_eq!(sys.deassert(&mut bus, id), Err(Error::BadSpec), "line {id}");
            assert_eq!(sys.is_asserted(&mut bus, id), Err(Error::BadSpec), "line {id}");
        }
        let mut aon = Jh7110Reset::aon(B);
        assert_eq!(aon.count(), 8);
        assert_eq!(aon.assert(&mut bus, 8), Err(Error::BadSpec));
        let mut stg = Jh7110Reset::stg(B);
        assert_eq!(stg.count(), 23);
        assert_eq!(stg.assert(&mut bus, 23), Err(Error::BadSpec));
        assert!(log.all().is_empty());
    }

    #[test]
    fn a_status_bit_of_one_means_released_on_every_line() {
        let (log, mut bus) = rig();
        let mut sys = Jh7110Reset::sys(B);
        // Status 1 is released, so a release is confirmed at the first read.
        for line in [0u32, 5, 33, 96] {
            let bank = (line / 32) as u64;
            log.clear();
            bus.regs.insert(B + 0x2f8 + 4 * bank, 1 << (line % 32));
            bus.regs.insert(B + 0x308 + 4 * bank, 1 << (line % 32));
            sys.deassert(&mut bus, line).unwrap();
            assert_eq!(log.writes(), [(B + 0x2f8 + 4 * bank, 0)], "line {line}");
            // Status 0 is "still held": the wait runs out.
            bus.regs.insert(B + 0x308 + 4 * bank, 0);
            assert_eq!(sys.deassert(&mut bus, line), Err(Error::Timeout), "line {line}");
        }
    }
}

// ---- PMU (TRM 3.6) ----

mod pmu {
    use crate::support::*;
    use azos_soc::jh7110::Jh7110Pmu;
    use azos_soc::pd::PowerDomainOps;
    use azos_soc::Error;

    const B: u64 = 0x1703_0000;

    #[test]
    fn the_sequence_starts_with_ff_and_the_domains_are_the_current_mode_bits() {
        let log = Log::new();
        let mut bus = TraceBus::new(&log).with(B + 0x8c, 1);
        let mut pmu = Jh7110Pmu::new(B);
        // Table 3-26: bit n of the current power mode is domain n (SYSTOP..VENC).
        bus.regs.insert(B + 0x80, 0b000_0011);
        assert!(pmu.is_on(&mut bus, 0).unwrap() && pmu.is_on(&mut bus, 1).unwrap());
        assert!(!pmu.is_on(&mut bus, 6).unwrap());
        assert_eq!(pmu.is_on(&mut bus, 7), Err(Error::BadSpec));
        // Turn VENC (6) on: 0x0c <- mask, then 0xff, 0x05, 0x50 into 0x44 (3.6.4).
        log.clear();
        pmu.power_on(&mut bus, 6).unwrap();
        let w = log.writes();
        assert_eq!(&w[..4], &[(B + 0x0c, 1 << 6), (B + 0x44, 0xff), (B + 0x44, 0x05), (B + 0x44, 0x50)]);
        // And off: 0x10 <- mask, then 0xff, 0x0a, 0xa0.
        bus.regs.insert(B + 0x80, 1 << 6);
        log.clear();
        pmu.power_off(&mut bus, 6).unwrap();
        let w = log.writes();
        assert_eq!(&w[..4], &[(B + 0x10, 1 << 6), (B + 0x44, 0xff), (B + 0x44, 0x0a), (B + 0x44, 0xa0)]);
    }

    #[test]
    fn the_interrupt_status_bits_are_the_ones_of_table_3_29() {
        // [2:3] software failure, [4:5] hardware failure, [8:6] P-channel
        // failure: every one is a failure, not a completion.
        for bit in 2..=8 {
            let log = Log::new();
            let mut bus = TraceBus::new(&log).with(B + 0x8c, 1 << bit);
            let mut pmu = Jh7110Pmu::new(B);
            assert_eq!(pmu.power_on(&mut bus, 2), Err(Error::Hardware), "bit {bit}");
        }
        // [1] is a hardware encouragement request: neither done nor failed.
        let log = Log::new();
        let mut bus = TraceBus::new(&log).with(B + 0x8c, 1 << 1);
        let mut pmu = Jh7110Pmu::new(B);
        assert_eq!(pmu.power_on(&mut bus, 2), Err(Error::Timeout));
        // [0] is the sequence-done event.
        let mut bus = TraceBus::new(&log).with(B + 0x8c, 1);
        assert_eq!(pmu.power_on(&mut bus, 2), Ok(()));
    }
}

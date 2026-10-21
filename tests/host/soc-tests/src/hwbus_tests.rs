// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The hardware bus hands a bound driver its device; the device's tree node
//! is the key the SoC frameworks look its resources up with.
use crate::support::*;
use azos_hwbus::Device;
use azos_soc::clk::ClockTree;
use azos_soc::consumer::Sel;
use azos_soc::fdt::Fdt;
use azos_soc::fixed::FixedClock;
use azos_soc::jh7110::Jh7110Clk;
use azos_soc::{Error, NodeId};

#[test]
fn a_device_carries_the_tree_node_its_resources_are_looked_up_from() {
    let blob = board();
    let fdt = Fdt::parse(&blob).unwrap();
    let node = uart(&fdt);
    let (base, size) = fdt.reg(node).unwrap();
    let dev = Device::dt("serial@10000000", b"snps,dw-apb-uart\0", base, size, 0).with_dt_node(node.0);

    let mut osc = FixedClock::from_dt(&fdt, fdt.by_phandle(OSC).unwrap()).unwrap();
    let mut pll0 = FixedClock::from_dt(&fdt, fdt.by_phandle(PLL0).unwrap()).unwrap();
    let mut pll2 = FixedClock::from_dt(&fdt, fdt.by_phandle(PLL2).unwrap()).unwrap();
    let mut sys = Jh7110Clk::from_dt(&fdt, fdt.by_phandle(SYSCRG).unwrap()).unwrap();
    let mut tree = ClockTree::new();
    tree.add(fdt.by_phandle(OSC).unwrap(), &mut osc).unwrap();
    tree.add(fdt.by_phandle(PLL0).unwrap(), &mut pll0).unwrap();
    tree.add(fdt.by_phandle(PLL2).unwrap(), &mut pll2).unwrap();
    tree.add(fdt.by_phandle(SYSCRG).unwrap(), &mut sys).unwrap();
    tree.link(&fdt);

    let from_dev = NodeId(dev.dt_node.expect("the bus recorded the node"));
    assert_eq!(from_dev, node);
    let clk = tree.get(&fdt, from_dev, Sel::Name("baudclk")).unwrap();
    assert_eq!((clk.prov, clk.id), (3, 146));
}

#[test]
fn a_device_that_did_not_come_from_the_tree_has_no_node() {
    let d = Device::dt("uart@10000000", b"snps,dw-apb-uart\0", 0x1000_0000, 0x1_0000, 0);
    assert_eq!(d.dt_node, None);
    assert_eq!(Device::virtio_mmio(0x1000_1000, 0x1000, 1, 2).dt_node, None);
    // Nothing to look up from: the caller's error, not a silent default.
    let blob = board();
    let fdt = Fdt::parse(&blob).unwrap();
    let tree = ClockTree::new();
    assert_eq!(tree.get(&fdt, NodeId(0), Sel::Index(0)).unwrap_err(), Error::NotFound);
}

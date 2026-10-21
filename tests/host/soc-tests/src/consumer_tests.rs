// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
use crate::support::*;
use azos_soc::consumer::{self, Sel};
use azos_soc::fdt::Fdt;
use azos_soc::Error;

#[test]
fn entries_are_split_by_each_providers_cells() {
    let mut b = Builder::new();
    b.begin("osc").cells("#clock-cells", &[0]).ph(1).end();
    b.begin("ctl").cells("#clock-cells", &[1]).ph(2).end();
    b.begin("big").cells("#clock-cells", &[2]).ph(3).end();
    // osc (0 cells), ctl 12, a placeholder, big 7 8, ctl 99.
    b.begin("dev")
        .cells("clocks", &[1, 2, 12, 0, 3, 7, 8, 2, 99])
        .strs("clock-names", &["a", "b", "", "d", "e"])
        .end();
    let blob = b.finish();
    let fdt = Fdt::parse(&blob).unwrap();
    let dev = by_path(&fdt, "/dev").unwrap();
    let get = |i| consumer::entry(&fdt, dev, "clocks", "#clock-cells", i);
    let e0 = get(0).unwrap();
    assert_eq!(e0.provider, fdt.by_phandle(1).unwrap());
    assert_eq!(e0.id(), Ok(0));
    assert_eq!(get(1).unwrap().id(), Ok(12));
    assert_eq!(get(2).unwrap_err(), Error::NotFound); // the <0> placeholder keeps its index
    let e3 = get(3).unwrap();
    assert_eq!(e3.spec.len(), 8);
    assert_eq!(e3.id(), Err(Error::BadSpec)); // a two-cell specifier has no single id
    assert_eq!(get(4).unwrap().id(), Ok(99));
    assert_eq!(get(5).unwrap_err(), Error::NotFound);
}

#[test]
fn names_select_entries() {
    let blob = board();
    let fdt = Fdt::parse(&blob).unwrap();
    let u = uart(&fdt);
    let by = |n| consumer::lookup(&fdt, u, "clocks", "clock-names", "#clock-cells", Sel::Name(n));
    assert_eq!(by("baudclk").unwrap().id(), Ok(146));
    assert_eq!(by("apb_pclk").unwrap().id(), Ok(145));
    assert_eq!(by("nope").unwrap_err(), Error::NotFound);
    let r = consumer::lookup(&fdt, u, "resets", "reset-names", "#reset-cells", Sel::Name("core")).unwrap();
    assert_eq!(r.id(), Ok(75));
    assert_eq!(consumer::lookup(&fdt, u, "clocks", "clock-names", "#clock-cells", Sel::Index(1)).unwrap().id(), Ok(145));
}

#[test]
fn a_provider_without_its_cells_property_is_a_bad_spec() {
    let mut b = Builder::new();
    b.begin("ctl").ph(2).end();
    b.begin("dev").cells("clocks", &[2, 1]).end();
    let blob = b.finish();
    let fdt = Fdt::parse(&blob).unwrap();
    let dev = by_path(&fdt, "/dev").unwrap();
    assert_eq!(consumer::entry(&fdt, dev, "clocks", "#clock-cells", 0).unwrap_err(), Error::BadSpec);
    // A phandle that is not in the tree.
    let mut b = Builder::new();
    b.begin("dev").cells("clocks", &[42]).end();
    let blob = b.finish();
    let fdt = Fdt::parse(&blob).unwrap();
    let dev = by_path(&fdt, "/dev").unwrap();
    assert_eq!(consumer::entry(&fdt, dev, "clocks", "#clock-cells", 0).unwrap_err(), Error::NotFound);
    // A specifier cut short.
    let mut b = Builder::new();
    b.begin("ctl").cells("#clock-cells", &[2]).ph(2).end();
    b.begin("dev").cells("clocks", &[2, 1]).end();
    let blob = b.finish();
    let fdt = Fdt::parse(&blob).unwrap();
    let dev = by_path(&fdt, "/dev").unwrap();
    assert_eq!(consumer::entry(&fdt, dev, "clocks", "#clock-cells", 0).unwrap_err(), Error::BadSpec);
}

#[test]
fn single_phandles_and_lists() {
    let blob = board();
    let fdt = Fdt::parse(&blob).unwrap();
    let u = uart(&fdt);
    assert_eq!(consumer::phandle(&fdt, u, "vdd-supply").unwrap(), fdt.by_phandle(VDD).unwrap());
    assert_eq!(consumer::phandle(&fdt, u, "vio-supply").unwrap_err(), Error::NotFound);
    let l: Vec<_> = consumer::phandles(&fdt, u, "pinctrl-0").collect();
    assert_eq!(l, [Ok(fdt.by_phandle(UART0_PINS).unwrap())]);
    assert_eq!(consumer::phandles(&fdt, u, "pinctrl-1").count(), 0);
}

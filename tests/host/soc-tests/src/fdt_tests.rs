// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
use crate::support::*;
use azos_soc::fdt::{strings, Fdt};

#[test]
fn nodes_are_found_by_phandle_and_by_path() {
    let blob = board();
    let fdt = Fdt::parse(&blob).unwrap();
    let sys = fdt.by_phandle(SYSCRG).unwrap();
    assert_eq!(fdt.name(sys), Some("clock-controller@13020000"));
    assert_eq!(by_path(&fdt, "/soc/clock-controller@13020000"), Some(sys));
    // A component without a unit address matches the first node of that name.
    assert_eq!(by_path(&fdt, "/soc/clock-controller"), Some(sys));
    assert_eq!(fdt.by_phandle(0), None);
    assert_eq!(fdt.by_phandle(9999), None);
    assert_eq!(by_path(&fdt, "/soc/nothing"), None);
    assert_eq!(fdt.name(azos_soc::NodeId(0)), Some(""));
}

#[test]
fn properties_and_compatible() {
    let blob = board();
    let fdt = Fdt::parse(&blob).unwrap();
    let osc = fdt.by_phandle(OSC).unwrap();
    assert_eq!(fdt.u32_prop(osc, "clock-frequency"), Some(24_000_000));
    assert!(fdt.is_compatible(osc, "fixed-clock"));
    assert!(!fdt.is_compatible(osc, "fixed-factor-clock"));
    assert!(fdt.has_prop(fdt.by_phandle(VDD).unwrap(), "regulator-always-on"));
    assert_eq!(strings(fdt.prop(fdt.by_phandle(VDD).unwrap(), "regulator-name").unwrap()).next(), Some("vdd"));
    assert!(fdt.is_available(osc));
    let mut b = Builder::new();
    b.begin("a").str("status", "disabled").end();
    b.begin("b").str("status", "okay").end();
    b.begin("c").str("status", "fail").end();
    let blob2 = b.finish();
    let f2 = Fdt::parse(&blob2).unwrap();
    assert!(!f2.is_available(by_path(&f2, "/a").unwrap()));
    assert!(f2.is_available(by_path(&f2, "/b").unwrap()));
    assert!(!f2.is_available(by_path(&f2, "/c").unwrap()));
}

#[test]
fn reg_is_read_with_the_parents_cells() {
    let blob = board();
    let fdt = Fdt::parse(&blob).unwrap();
    assert_eq!(fdt.reg(fdt.by_phandle(SYSCRG).unwrap()), Some((SYSCRG_BASE, 0x10000)));
    assert_eq!(fdt.reg(fdt.by_phandle(PMU).unwrap()), Some((PMU_BASE, 0x10000)));
    // No reg.
    assert_eq!(fdt.reg(fdt.by_phandle(OSC).unwrap()), None);
}

#[test]
fn reg_refuses_a_bus_that_translates() {
    let mut b = Builder::new();
    b.cells("#address-cells", &[1]).cells("#size-cells", &[1]);
    b.begin("bus").cells("#address-cells", &[1]).cells("#size-cells", &[1]).cells("ranges", &[0, 0x4000_0000, 0x1000]);
    b.begin("dev@10").cells("reg", &[0x10, 4]).end();
    b.end();
    b.begin("flat").cells("#address-cells", &[1]).cells("#size-cells", &[1]).flag("ranges");
    b.begin("dev@20").cells("reg", &[0x20, 4]).end();
    b.end();
    let blob = b.finish();
    let fdt = Fdt::parse(&blob).unwrap();
    // The bus's ranges would turn 0x10 into 0x40000010; this view does not
    // translate, so it must not answer 0x10.
    assert_eq!(fdt.reg(by_path(&fdt, "/bus/dev@10").unwrap()), None);
    // An empty ranges is the identity.
    assert_eq!(fdt.reg(by_path(&fdt, "/flat/dev@20").unwrap()), Some((0x20, 4)));
}

#[test]
fn ancestors_and_children() {
    let blob = board();
    let fdt = Fdt::parse(&blob).unwrap();
    let pins = fdt.by_phandle(UART0_PINS).unwrap();
    let anc = fdt.ancestors(pins).unwrap();
    assert_eq!(anc.as_slice().len(), 3); // root, soc, pinctrl
    assert_eq!(anc.parent(), fdt.by_phandle(PINS));
    assert_eq!(fdt.ancestors(azos_soc::NodeId(0)).unwrap().parent(), None);
    let names: Vec<_> = fdt.children(pins).map(|c| fdt.name(c).unwrap()).collect();
    assert_eq!(names, ["tx-pins", "rx-pins"]);
    // Children skip a node's whole subtree.
    let pc = fdt.by_phandle(PINS).unwrap();
    let names: Vec<_> = fdt.children(pc).map(|c| fdt.name(c).unwrap()).collect();
    assert_eq!(names, ["uart0-0", "flat-0"]);
}

#[test]
fn name_lists_keep_empty_entries() {
    assert_eq!(strings(b"a\0\0c\0").collect::<Vec<_>>(), ["a", "", "c"]);
    assert_eq!(strings(b"").count(), 0);
    assert_eq!(strings(b"\0").collect::<Vec<_>>(), [""]);
}

#[test]
fn a_damaged_blob_answers_none_and_never_panics() {
    let blob = board();
    assert!(Fdt::parse(&blob[..30]).is_none());
    let mut bad = blob.clone();
    bad[0] ^= 0xff;
    assert!(Fdt::parse(&bad).is_none());
    // Every truncation that still parses: no lookup may panic.
    for cut in 0..blob.len() {
        let mut t = blob.clone();
        // Keep the header's totalsize honest for the cut.
        t.truncate(cut);
        if let Some(fdt) = Fdt::parse(&t) {
            let _ = fdt.by_phandle(SYSCRG);
            let _ = by_path(&fdt, "/soc/serial@10000000");
            for n in fdt.children(azos_soc::NodeId(0)) {
                let _ = fdt.props(n).count();
                let _ = fdt.reg(n);
                let _ = fdt.ancestors(n);
            }
        }
    }
    // Corrupt single bytes of the structure block.
    for i in 56..blob.len().min(56 + 600) {
        let mut t = blob.clone();
        t[i] = t[i].wrapping_add(0x55);
        if let Some(fdt) = Fdt::parse(&t) {
            let _ = fdt.by_phandle(SYSCRG);
            let _ = by_path(&fdt, "/soc/serial@10000000");
            for n in fdt.children(azos_soc::NodeId(0)) {
                let _ = fdt.props(n).count();
                let _ = fdt.reg(n);
                let _ = fdt.children(n).count();
            }
        }
    }
}

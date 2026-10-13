// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host tests of `azos_hwbus`: patterns, the match tables, the bind policy and
//! the bus lifecycle (add, bind, unbind, rebind, reconcile).
//!
//! Canary discipline: the policy rows below FAIL when the crate is built with
//! `--features policy-canary` (topology-only then admits like auto); the
//! duplicate-id rows build the conflict `build.rs` refuses and assert the
//! check finds it, so the check is shown to bite.

#![cfg(test)]

use azos_hwbus::pattern::first_overlap;
use azos_hwbus::*;

// ── Fixtures ────────────────────────────────────────────────────────────

const NATIVE_FIX: &[NativeEntry] = &[
    NativeEntry { pattern: Pattern::Virtio(2), driver: "virtio-blk", boot: false },
    NativeEntry { pattern: Pattern::Virtio(1), driver: "virtio-net", boot: false },
    NativeEntry { pattern: Pattern::pci(0x1af4, 0x1041), driver: "virtio-net-pci", boot: false },
    NativeEntry { pattern: Pattern::pci_class(0x010802, 0xffffff), driver: "nvme", boot: false },
    NativeEntry { pattern: Pattern::Dt("ns16550a"), driver: "uart", boot: true },
];

const LINUX_FIX: &[LinuxEntry] = &[
    LinuxEntry { pattern: Pattern::pci(0x8086, 0x1234), class: "net", module: "e1000x" },
    LinuxEntry { pattern: Pattern::pci_class(0x0c0330, 0xffffff), class: "usb", module: "xhci-pci" },
    LinuxEntry { pattern: Pattern::Dt("vendor,sensor-a"), class: "iio", module: "sensor-a" },
];

fn pci(vendor: u16, device: u16, class: u32, slot: u8) -> Device {
    Device::pci(PciId { bus: 0, device: slot, function: 0, vendor, device_id: device, class })
}

fn virtio(id: u32, base: u64) -> Device {
    Device::virtio_mmio(base, 0x1000, 0, id)
}

fn dt(compat: &[u8], name: &str) -> Device {
    Device::dt(name, compat, 0x1000_0000, 0x1000, 10)
}

#[derive(Default)]
struct Recorder {
    lines: Vec<String>,
}

impl Sink for Recorder {
    fn event(&mut self, ev: &Event<'_>) {
        self.lines.push(match ev {
            Event::Added { dev, .. } => format!("added {}", dev.name.as_str()),
            Event::Bound { dev, choice, .. } => match choice {
                Choice::Native(n) => format!("bound {} native {}", dev.name.as_str(), n),
                Choice::Linux { class, .. } => format!("bound {} linux {}", dev.name.as_str(), class),
            },
            Event::ProbeFailed { dev, driver, err, .. } => {
                format!("probe-failed {} {} {:?}", dev.name.as_str(), driver, err)
            }
            Event::NotAdmitted { dev, natural, by_row, .. } => format!(
                "not-admitted {} natural={} row={}",
                dev.name.as_str(),
                match natural {
                    Some(Choice::Native(n)) => n.to_string(),
                    Some(Choice::Linux { class, .. }) => format!("linux:{class}"),
                    None => "none".into(),
                },
                by_row
            ),
            Event::Unmatched { dev, .. } => format!("unmatched {}", dev.name.as_str()),
            Event::Unbound { dev, was, .. } => format!("unbound {} {:?}", dev.name.as_str(), was),
            Event::UnbindRefused { dev, driver, .. } => format!("unbind-refused {} {}", dev.name.as_str(), driver),
        });
    }
}

/// Scripted drivers: probe succeeds unless the driver is listed in `fail`,
/// `busy` drivers serve one device, unknown names are refused.
#[derive(Default)]
struct Fake {
    known: Vec<&'static str>,
    fail: Vec<&'static str>,
    busy_after_one: Vec<&'static str>,
    /// Drivers that refuse to let go of a device.
    stuck: Vec<&'static str>,
    probed: Vec<(String, u32)>,
    removed: Vec<(String, u32)>,
}

impl Fake {
    fn with(known: &[&'static str]) -> Self {
        Fake { known: known.to_vec(), ..Default::default() }
    }
}

impl Drivers for Fake {
    fn probe(&mut self, driver: &str, h: Handle, _dev: &Device) -> Result<(), ProbeError> {
        if !self.known.contains(&driver) {
            return Err(ProbeError::NoSuchDriver);
        }
        if self.fail.contains(&driver) {
            return Err(ProbeError::Failed);
        }
        if self.busy_after_one.contains(&driver) && self.probed.iter().any(|(d, _)| d == driver) {
            return Err(ProbeError::Busy);
        }
        self.probed.push((driver.to_string(), h.0));
        Ok(())
    }
    fn remove(&mut self, driver: &str, h: Handle, _dev: &Device) -> Result<(), ProbeError> {
        self.removed.push((driver.to_string(), h.0));
        if self.stuck.contains(&driver) { Err(ProbeError::Busy) } else { Ok(()) }
    }
}

fn rules<'a>(rows: &'a [Row<'a>], policy: Policy) -> Rules<'a> {
    Rules { native: NATIVE_FIX, linux: LINUX_FIX, rows, policy }
}

const ALL: &[&str] = &["virtio-blk", "virtio-net", "virtio-net-pci", "nvme", "uart", "other-net"];

// ── Patterns ────────────────────────────────────────────────────────────

#[test]
fn selectors_parse() {
    assert_eq!(Pattern::parse("pci:1af4:1041"), Some(Pattern::pci(0x1af4, 0x1041)));
    assert_eq!(Pattern::parse("pci:1af4:*"), Some(Pattern::pci(0x1af4, ANY)));
    assert_eq!(Pattern::parse("pciclass:010802:ffffff"), Some(Pattern::pci_class(0x010802, 0xffffff)));
    assert_eq!(Pattern::parse("dt:sifive,plic-1.0.0"), Some(Pattern::Dt("sifive,plic-1.0.0")));
    assert_eq!(Pattern::parse("virtio:18"), Some(Pattern::Virtio(18)));
    for bad in ["", "pci", "pci:1af4", "pci:zzzz:1", "pci:10000:1", "pciclass:1000000:1", "dt:", "dt:a b",
                "virtio:", "virtio:x", "virtio:99999999999", "usb:1:2", "pci:1af4:1041:7"] {
        assert_eq!(Pattern::parse(bad), None, "{bad:?} must not parse");
    }
}

#[test]
fn overlap_is_per_field_and_per_kind() {
    let p = Pattern::pci;
    assert!(p(0x8086, 0x1234).overlaps(&p(0x8086, 0x1234)));
    assert!(!p(0x8086, 0x1234).overlaps(&p(0x8086, 0x1235)));
    assert!(p(0x8086, ANY).overlaps(&p(0x8086, 0x1235)), "a wildcard device overlaps any device of the vendor");
    assert!(!p(0x8086, ANY).overlaps(&p(0x1af4, 0x1041)));
    // Class patterns overlap when no bit both of them test differs.
    assert!(Pattern::pci_class(0x010802, 0xffffff).overlaps(&Pattern::pci_class(0x010800, 0xffff00)));
    assert!(!Pattern::pci_class(0x010802, 0xffffff).overlaps(&Pattern::pci_class(0x0c0330, 0xffffff)));
    assert!(Pattern::Dt("a,b").overlaps(&Pattern::Dt("a,b")));
    // An id and a class are different claims, however a device could satisfy both.
    assert!(!p(0x1af4, 0x1041).overlaps(&Pattern::pci_class(0x0c0330, 0xffffff)));
    assert!(!Pattern::Dt("a,b").overlaps(&Pattern::Dt("a,c")));
    assert!(!Pattern::Dt("a,b").overlaps(&Pattern::Virtio(1)));
    assert!(!Pattern::Virtio(1).overlaps(&Pattern::pci(0x1af4, 0x1041)));
}

#[test]
fn a_device_matches_only_patterns_of_its_own_kind() {
    let nic = pci(0x1af4, 0x1041, 0x020000, 3);
    assert!(nic.matches(&Pattern::pci(0x1af4, 0x1041)));
    assert!(nic.matches(&Pattern::pci(0x1af4, ANY)));
    assert!(!nic.matches(&Pattern::pci(0x1af4, 0x1042)));
    assert!(!nic.matches(&Pattern::Virtio(1)), "virtio-mmio ids do not name a PCI function");
    let nvme = pci(0x8086, 0x5845, 0x010802, 4);
    assert!(nvme.matches(&Pattern::pci_class(0x010802, 0xffffff)));
    assert!(!nic.matches(&Pattern::pci_class(0x010802, 0xffffff)));
    let uart = dt(b"ns16550a\0", "uart@10000000");
    assert!(uart.matches(&Pattern::Dt("ns16550a")));
    assert!(!uart.matches(&Pattern::Dt("ns16550")), "a prefix is not a match");
    let v = virtio(2, 0x1000_2000);
    assert!(v.matches(&Pattern::Virtio(2)) && !v.matches(&Pattern::Virtio(1)));
    assert!(!v.matches(&Pattern::Dt("virtio,mmio")));
}

#[test]
fn device_compatible_keeps_order_and_drops_what_does_not_fit() {
    let d = dt(b"vendor,exact\0vendor,family\0generic\0", "n@0");
    assert_eq!(d.compatible().collect::<Vec<_>>(), ["vendor,exact", "vendor,family", "generic"]);
    // A list longer than COMPAT_LEN keeps the strings that fit whole.
    let mut long = Vec::new();
    for i in 0..30 {
        long.extend_from_slice(format!("vendor,chip-number-{i}\0").as_bytes());
    }
    let d = dt(&long, "n@0");
    let kept: Vec<_> = d.compatible().collect();
    assert!(!kept.is_empty() && kept.len() < 30);
    assert_eq!(kept[0], "vendor,chip-number-0");
    assert!(kept.iter().map(|s| s.len() + 1).sum::<usize>() <= COMPAT_LEN);
}

#[test]
fn names_are_cut_on_a_character_boundary() {
    let long = "é".repeat(NAME_LEN);
    let n = Name::new(&long);
    assert!(n.as_str().len() <= NAME_LEN && n.as_str().chars().all(|c| c == 'é'));
    assert_eq!(pci(1, 2, 0, 0x1f).name.as_str(), "00:1f.0");
    assert_eq!(virtio(1, 0x1000_1000).name.as_str(), "virtio@10001000");
}

// ── Tables ──────────────────────────────────────────────────────────────

#[test]
fn the_generated_tables_have_no_id_in_both() {
    assert_eq!(first_conflict(NATIVE, LINUX), None, "build.rs refuses this build; so does this row");
    for e in NATIVE {
        assert!(!e.driver.is_empty());
    }
    for e in LINUX {
        assert!(!e.class.is_empty() && !e.module.is_empty());
    }
}

#[test]
fn the_conflict_check_finds_an_id_in_both_tables() {
    // Canary: the fixture the build check must refuse.
    let native = [NativeEntry { pattern: Pattern::pci(0x1af4, 0x1041), driver: "virtio-net-pci", boot: false }];
    let linux = [
        LinuxEntry { pattern: Pattern::pci(0x8086, 0x1234), class: "net", module: "a" },
        LinuxEntry { pattern: Pattern::pci(0x1af4, ANY), class: "net", module: "b" },
    ];
    assert_eq!(first_conflict(&native, &linux), Some((0, 1)));
    // Two class claims over the same class conflict too.
    let nvme_native = [NativeEntry { pattern: Pattern::pci_class(0x010802, 0xffffff), driver: "nvme", boot: false }];
    let nvme_linux = [LinuxEntry { pattern: Pattern::pci_class(0x010800, 0xffff00), class: "block", module: "nvme" }];
    assert_eq!(first_conflict(&nvme_native, &nvme_linux), Some((0, 0)));
    // And the same check over parsed text, as build.rs runs it.
    let a = ["dt:vendor,x", "virtio:3"];
    let b = ["virtio:4", "virtio:3"];
    let hit = first_overlap(&a, &b, |s| Pattern::parse(s).unwrap(), |s| Pattern::parse(s).unwrap());
    assert_eq!(hit, Some((1, 1)));
    assert_eq!(first_conflict(NATIVE_FIX, LINUX_FIX), None);
}

// ── Decision ────────────────────────────────────────────────────────────

#[test]
fn native_beats_linux_and_linux_covers_the_rest() {
    let native = [NativeEntry { pattern: Pattern::pci_class(0x0c0330, 0xffff00), driver: "xhci-native", boot: false }];
    let d = pci(0x1b36, 0x000d, 0x0c0330, 5);
    assert_eq!(natural(&d, &native, LINUX_FIX), Some(Choice::Native("xhci-native")));
    assert_eq!(
        natural(&d, &[], LINUX_FIX),
        Some(Choice::Linux { class: "usb", module: "xhci-pci" })
    );
    assert_eq!(natural(&pci(0x10ec, 0x8168, 0x020000, 6), NATIVE_FIX, LINUX_FIX), None);
}

#[test]
fn auto_binds_what_the_tables_match() {
    let d = virtio(2, 0x1000_2000);
    assert_eq!(
        decide(&d, NATIVE_FIX, LINUX_FIX, &[], Policy::Auto),
        Verdict::Bind(Choice::Native("virtio-blk"))
    );
    assert_eq!(decide(&virtio(99, 0x1000_3000), NATIVE_FIX, LINUX_FIX, &[], Policy::Auto), Verdict::Unmatched);
}

#[test]
fn topology_only_detects_everything_and_binds_nothing_unlisted() {
    // Canary: with `--features policy-canary` the policy admits, and this fails.
    let d = virtio(2, 0x1000_2000);
    assert_eq!(
        decide(&d, NATIVE_FIX, LINUX_FIX, &[], Policy::TopologyOnly),
        Verdict::NotAdmitted { natural: Some(Choice::Native("virtio-blk")), by_row: false }
    );
    // A device nothing names is just unmatched, in either policy.
    assert_eq!(
        decide(&virtio(99, 0x1000_3000), NATIVE_FIX, LINUX_FIX, &[], Policy::TopologyOnly),
        Verdict::Unmatched
    );
}

#[test]
fn what_the_kernel_booted_on_is_bound_whatever_the_policy_or_a_row_says() {
    let uart = dt(b"ns16550a\0", "uart@10000000");
    let refuse = [Row { select: Pattern::Dt("ns16550a"), admit: false, driver: None }];
    for rows in [&[][..], &refuse[..]] {
        for policy in [Policy::Auto, Policy::TopologyOnly] {
            assert_eq!(
                decide(&uart, NATIVE_FIX, LINUX_FIX, rows, policy),
                Verdict::Bind(Choice::Native("uart")),
                "{policy:?}, {} rows", rows.len()
            );
        }
    }
    // And through the bus: the UART is bound, hence not mappable by ring 3.
    let mut bus = Bus::new();
    let mut rec = Recorder::default();
    let h = bus.add(uart, &mut rec).unwrap();
    bus.bind_all(&rules(&refuse, Policy::TopologyOnly), &mut Fake::with(ALL), &mut rec);
    assert_eq!(bus.get(h).unwrap().state, State::Bound);
    assert_eq!(bus.user_window(h), None);
}

#[test]
fn a_row_admits_in_topology_only_mode() {
    let rows = [Row { select: Pattern::Virtio(2), admit: true, driver: None }];
    let blk = virtio(2, 0x1000_2000);
    let net = virtio(1, 0x1000_3000);
    assert_eq!(
        decide(&blk, NATIVE_FIX, LINUX_FIX, &rows, Policy::TopologyOnly),
        Verdict::Bind(Choice::Native("virtio-blk"))
    );
    assert_eq!(
        decide(&net, NATIVE_FIX, LINUX_FIX, &rows, Policy::TopologyOnly),
        Verdict::NotAdmitted { natural: Some(Choice::Native("virtio-net")), by_row: false },
        "a row admits what it selects and nothing else"
    );
}

#[test]
fn a_row_can_refuse_or_redirect_in_auto_mode() {
    let rows = [
        Row { select: Pattern::pci(0x1af4, 0x1041), admit: false, driver: None },
        Row { select: Pattern::Virtio(1), admit: true, driver: Some("other-net") },
    ];
    assert_eq!(
        decide(&pci(0x1af4, 0x1041, 0x020000, 3), NATIVE_FIX, LINUX_FIX, &rows, Policy::Auto),
        Verdict::NotAdmitted { natural: Some(Choice::Native("virtio-net-pci")), by_row: true }
    );
    assert_eq!(
        decide(&virtio(1, 0x1000_3000), NATIVE_FIX, LINUX_FIX, &rows, Policy::Auto),
        Verdict::Bind(Choice::Native("other-net"))
    );
    // A row that admits a device no table names, with no driver, has nothing to bind.
    let rows = [Row { select: Pattern::Virtio(99), admit: true, driver: None }];
    assert_eq!(decide(&virtio(99, 0x1000_3000), NATIVE_FIX, LINUX_FIX, &rows, Policy::Auto), Verdict::Unmatched);
}

#[test]
fn the_first_matching_row_wins() {
    let rows = [
        Row { select: Pattern::Virtio(1), admit: false, driver: None },
        Row { select: Pattern::Virtio(1), admit: true, driver: None },
    ];
    assert!(matches!(
        decide(&virtio(1, 0x1000_3000), NATIVE_FIX, LINUX_FIX, &rows, Policy::Auto),
        Verdict::NotAdmitted { by_row: true, .. }
    ));
}

// ── The bus ─────────────────────────────────────────────────────────────

fn populated() -> (Bus, Recorder, Vec<Handle>) {
    let mut bus = Bus::new();
    let mut rec = Recorder::default();
    let hs = vec![
        bus.add(dt(b"ns16550a\0", "uart@10000000"), &mut rec).unwrap(),
        bus.add(virtio(2, 0x1000_2000), &mut rec).unwrap(),
        bus.add(virtio(1, 0x1000_3000), &mut rec).unwrap(),
        bus.add(pci(0x8086, 0x1234, 0x020000, 4), &mut rec).unwrap(),
        bus.add(pci(0x1b36, 0x000d, 0x0c0330, 5), &mut rec).unwrap(),
        bus.add(dt(b"vendor,rtc\0", "rtc@101000"), &mut rec).unwrap(),
    ];
    (bus, rec, hs)
}

#[test]
fn bind_all_in_auto_mode_binds_native_then_linux_and_reports_the_rest() {
    let (mut bus, mut rec, hs) = populated();
    let mut drv = Fake::with(ALL);
    bus.bind_all(&rules(&[], Policy::Auto), &mut drv, &mut rec);
    assert_eq!(bus.get(hs[0]).unwrap().state, State::Bound);
    assert_eq!(bus.get(hs[1]).unwrap().binding, Binding::Native(Name::new("virtio-blk")));
    assert!(matches!(bus.get(hs[3]).unwrap().binding, Binding::Linux { class } if class.as_str() == "net"));
    assert!(matches!(bus.get(hs[4]).unwrap().binding, Binding::Linux { class } if class.as_str() == "usb"));
    assert_eq!(bus.get(hs[5]).unwrap().state, State::Unmatched);
    // Only the native drivers were probed, once each.
    assert_eq!(drv.probed.len(), 3);
    assert!(bus.linux_class_wanted("usb") && bus.linux_class_wanted("net"));
    assert!(!bus.linux_class_wanted("iio"), "no id of the iio class matched a device");
    assert!(rec.lines.iter().any(|l| l == "unmatched rtc@101000"));
}

#[test]
fn bind_all_in_topology_only_mode_binds_only_the_rows_and_says_the_rest() {
    let (mut bus, mut rec, hs) = populated();
    let mut drv = Fake::with(ALL);
    let rows = [Row { select: Pattern::Virtio(2), admit: true, driver: None }];
    bus.bind_all(&rules(&rows, Policy::TopologyOnly), &mut drv, &mut rec);
    assert_eq!(bus.get(hs[1]).unwrap().state, State::Bound);
    assert_eq!(bus.get(hs[0]).unwrap().state, State::Bound, "the UART is the kernel's, a boot entry");
    for i in [2, 3, 4] {
        assert_eq!(bus.get(hs[i]).unwrap().state, State::NotAdmitted, "device {i}");
    }
    assert_eq!(bus.get(hs[5]).unwrap().state, State::Unmatched);
    assert_eq!(drv.probed.len(), 2, "the UART and the admitted disk; unadmitted drivers start nothing");
    assert!(!bus.linux_class_wanted("usb"), "a Linux id that matched but was not admitted launches no server");
    assert!(rec.lines.contains(&"not-admitted 00:05.0 natural=linux:usb row=false".to_string()));
}

#[test]
fn an_unknown_or_failing_driver_is_a_probe_failure_not_a_bind() {
    let (mut bus, mut rec, hs) = populated();
    let mut drv = Fake::with(&["virtio-blk"]);
    drv.fail.push("virtio-blk");
    bus.bind_all(&rules(&[], Policy::Auto), &mut drv, &mut rec);
    assert_eq!(bus.get(hs[1]).unwrap().state, State::ProbeFailed);
    assert_eq!(bus.get(hs[2]).unwrap().state, State::ProbeFailed, "virtio-net is not linked into this fake");
    assert_eq!(bus.get(hs[1]).unwrap().binding, Binding::None);
    assert!(rec.lines.contains(&"probe-failed virtio@10002000 virtio-blk Failed".to_string()));
    assert!(rec.lines.contains(&"probe-failed virtio@10003000 virtio-net NoSuchDriver".to_string()));
}

#[test]
fn a_single_device_driver_bound_twice_leaves_the_second_device_unbound() {
    let mut bus = Bus::new();
    let mut rec = Recorder::default();
    let a = bus.add(virtio(2, 0x1000_2000), &mut rec).unwrap();
    let b = bus.add(virtio(2, 0x1000_4000), &mut rec).unwrap();
    let mut drv = Fake::with(ALL);
    drv.busy_after_one.push("virtio-blk");
    bus.bind_all(&rules(&[], Policy::Auto), &mut drv, &mut rec);
    assert_eq!(bus.get(a).unwrap().state, State::Bound);
    assert_eq!(bus.get(b).unwrap().state, State::ProbeFailed);
}

#[test]
fn unbind_releases_the_driver_and_keeps_the_device() {
    let (mut bus, mut rec, hs) = populated();
    let mut drv = Fake::with(ALL);
    bus.bind_all(&rules(&[], Policy::Auto), &mut drv, &mut rec);
    assert_eq!(bus.unbind(hs[1], &mut drv, &mut rec), Ok(()));
    assert_eq!(drv.removed, [("virtio-blk".to_string(), hs[1].0)]);
    assert_eq!(bus.get(hs[1]).unwrap().state, State::Unbound);
    assert_eq!(bus.unbind(hs[1], &mut drv, &mut rec), Err(UnbindError::NotBound), "a second unbind has nothing to release");
    assert_eq!(bus.unbind(hs[5], &mut drv, &mut rec), Err(UnbindError::NotBound), "an unmatched device was never bound");
}

#[test]
fn a_driver_that_will_not_let_go_keeps_its_device() {
    let (mut bus, mut rec, hs) = populated();
    let mut drv = Fake::with(ALL);
    drv.stuck.push("virtio-blk");
    bus.bind_all(&rules(&[], Policy::Auto), &mut drv, &mut rec);
    assert_eq!(bus.unbind(hs[1], &mut drv, &mut rec), Err(UnbindError::Refused));
    assert_eq!(bus.get(hs[1]).unwrap().state, State::Bound);
    assert_eq!(bus.get(hs[1]).unwrap().binding, Binding::Native(Name::new("virtio-blk")));
    assert!(rec.lines.contains(&"unbind-refused virtio@10002000 virtio-blk".to_string()));
    assert_eq!(bus.user_window(hs[1]), None, "still the kernel's");
    // A rebind through a stuck driver does not happen either, and a topology
    // that no longer admits the disk leaves it bound.
    assert!(!bus.rebind(hs[1], "other-net", &mut drv, &mut rec));
    assert_eq!(bus.get(hs[1]).unwrap().binding, Binding::Native(Name::new("virtio-blk")));
    let rows = [Row { select: Pattern::Virtio(2), admit: false, driver: None }];
    bus.reconcile(&rules(&rows, Policy::Auto), &mut drv, &mut rec);
    assert_eq!(bus.get(hs[1]).unwrap().state, State::Bound);
}

#[test]
fn bind_where_binds_in_stages() {
    let (mut bus, mut rec, hs) = populated();
    let mut drv = Fake::with(ALL);
    let r = rules(&[], Policy::Auto);
    // First stage: only the disk.
    bus.bind_where(&r, &mut drv, &mut rec, &|_, v| matches!(v, Verdict::Bind(Choice::Native("virtio-blk"))));
    assert_eq!(bus.get(hs[1]).unwrap().state, State::Bound);
    assert_eq!(bus.get(hs[0]).unwrap().state, State::Detected, "the rest wait for their stage");
    assert_eq!(bus.get(hs[5]).unwrap().state, State::Detected, "an unmatched device is settled by the last stage only");
    assert_eq!(drv.probed.len(), 1);
    // The last stage takes everything still detected.
    bus.bind_all(&r, &mut drv, &mut rec);
    assert!(bus.iter().all(|(_, s)| s.state != State::Detected));
    assert_eq!(drv.probed.len(), 3, "the disk is not probed twice");
}

#[test]
fn rebind_swaps_the_driver() {
    let (mut bus, mut rec, hs) = populated();
    let mut drv = Fake::with(ALL);
    bus.bind_all(&rules(&[], Policy::Auto), &mut drv, &mut rec);
    assert!(bus.rebind(hs[2], "other-net", &mut drv, &mut rec));
    assert_eq!(bus.get(hs[2]).unwrap().binding, Binding::Native(Name::new("other-net")));
    assert_eq!(drv.removed.last().unwrap().0, "virtio-net");
    // A driver that is not linked leaves the device unbound, not half-bound.
    assert!(!bus.rebind(hs[2], "nonexistent", &mut drv, &mut rec));
    assert_eq!(bus.get(hs[2]).unwrap().state, State::ProbeFailed);
    assert_eq!(bus.get(hs[2]).unwrap().binding, Binding::None);
}

#[test]
fn reconcile_applies_a_later_topology_to_devices_the_first_one_bound() {
    // The built-in topology (no rows, auto) binds; the signed one arrives and
    // refuses the NIC, redirects the disk and leaves the UART alone.
    let (mut bus, mut rec, hs) = populated();
    let mut drv = Fake::with(ALL);
    bus.bind_all(&rules(&[], Policy::Auto), &mut drv, &mut rec);
    let probed_before = drv.probed.len();
    let rows = [
        Row { select: Pattern::Virtio(1), admit: false, driver: None },
        Row { select: Pattern::Virtio(2), admit: true, driver: Some("other-net") },
    ];
    bus.reconcile(&rules(&rows, Policy::Auto), &mut drv, &mut rec);
    assert_eq!(bus.get(hs[0]).unwrap().state, State::Bound, "the UART's verdict did not change");
    assert!(!drv.removed.iter().any(|(_, h)| *h == hs[0].0), "and its driver was not disturbed");
    assert_eq!(bus.get(hs[2]).unwrap().state, State::NotAdmitted);
    assert!(drv.removed.contains(&("virtio-net".to_string(), hs[2].0)));
    assert_eq!(bus.get(hs[1]).unwrap().binding, Binding::Native(Name::new("other-net")));
    assert_eq!(drv.probed.len(), probed_before + 1, "exactly one new probe");
    // Reconciling again under the same rules changes nothing.
    let n = rec.lines.len();
    bus.reconcile(&rules(&rows, Policy::Auto), &mut drv, &mut rec);
    assert_eq!(rec.lines.len(), n);
}

#[test]
fn reconcile_leaves_a_device_waiting_for_its_stage_alone() {
    let (mut bus, mut rec, hs) = populated();
    let mut drv = Fake::with(ALL);
    // Everything but the disk is decided; the disk waits for its stage.
    bus.bind_where(&rules(&[], Policy::Auto), &mut drv, &mut rec, &|_, v| {
        !matches!(v, Verdict::Bind(Choice::Native("virtio-blk")))
    });
    assert_eq!(bus.get(hs[1]).unwrap().state, State::Detected);
    bus.reconcile(&rules(&[], Policy::Auto), &mut drv, &mut rec);
    assert_eq!(bus.get(hs[1]).unwrap().state, State::Detected, "reconcile does not run a later stage early");
    assert!(!drv.probed.iter().any(|(d, _)| d == "virtio-blk"));
}

#[test]
fn reconcile_binds_a_device_a_later_topology_admits() {
    let (mut bus, mut rec, hs) = populated();
    let mut drv = Fake::with(ALL);
    bus.bind_all(&rules(&[], Policy::TopologyOnly), &mut drv, &mut rec);
    assert_eq!(bus.get(hs[1]).unwrap().state, State::NotAdmitted);
    let rows = [Row { select: Pattern::Virtio(2), admit: true, driver: None }];
    bus.reconcile(&rules(&rows, Policy::TopologyOnly), &mut drv, &mut rec);
    assert_eq!(bus.get(hs[1]).unwrap().state, State::Bound);
}

#[test]
fn the_bus_refuses_a_device_when_full_and_counts_it() {
    let mut bus = Bus::new();
    let mut rec = Recorder::default();
    for i in 0..MAX_DEVICES {
        bus.add(virtio(4, 0x1000_0000 + i as u64 * 0x1000), &mut rec).unwrap();
    }
    assert_eq!(bus.add(virtio(4, 0x2000_0000), &mut rec), Err(AddError::Full));
    assert_eq!(bus.refused(), 1);
    assert_eq!(bus.len(), MAX_DEVICES);
}

#[test]
fn find_returns_the_nth_match_in_slot_order() {
    let (bus, _rec, hs) = populated();
    assert_eq!(bus.find(&Pattern::Dt("ns16550a"), 0), Some(hs[0]));
    assert_eq!(bus.find(&Pattern::Dt("ns16550a"), 1), None);
    assert_eq!(bus.find(&Pattern::pci(ANY, ANY), 1), Some(hs[4]));
}

#[test]
fn ring_3_may_map_a_device_no_kernel_driver_owns() {
    let (mut bus, mut rec, hs) = populated();
    let mut drv = Fake::with(ALL);
    bus.bind_all(&rules(&[], Policy::Auto), &mut drv, &mut rec);
    // The UART and the virtio disk are the kernel's.
    assert_eq!(bus.user_window(hs[0]), None);
    assert_eq!(bus.user_window(hs[1]), None);
    // The RTC nobody drives is mappable, over exactly its window.
    assert_eq!(bus.user_window(hs[5]), Some((0x1000_0000, 0x1000)));
    // After an unbind the device is no longer the kernel's.
    bus.unbind(hs[1], &mut drv, &mut rec).unwrap();
    assert_eq!(bus.user_window(hs[1]), Some((0x1000_2000, 0x1000)));
    // A PCI function with no assigned BAR has no window to map; with one, it has.
    assert_eq!(bus.user_window(hs[3]), None);
    let with_bar = pci(0x8086, 0x1234, 0x020000, 9).with_window(0x4000_0000, 0x2000);
    let h = bus.add(with_bar, &mut rec).unwrap();
    assert_eq!(bus.user_window(h), None, "not decided yet: a kernel driver may still take it");
    bus.bind(h, &rules(&[], Policy::Auto), &mut drv, &mut rec);
    assert_eq!(bus.user_window(h), Some((0x4000_0000, 0x2000)));
    // A Linux-class server's device is ring 3's by construction.
    assert!(matches!(bus.get(hs[3]).unwrap().binding, Binding::Linux { .. }));
}

#[test]
fn a_device_waiting_for_its_stage_or_whose_probe_failed_is_not_mappable() {
    let (mut bus, mut rec, hs) = populated();
    // Nothing is bound yet: every device is still `Detected`, windows and all.
    for h in &hs {
        assert_eq!(bus.get(*h).unwrap().state, State::Detected);
        assert_eq!(bus.user_window(*h), None, "{:?}", bus.get(*h).unwrap().dev.name);
    }
    // A probe that failed may have left queues and DMA addresses programmed.
    let mut drv = Fake::with(ALL);
    drv.fail.push("virtio-blk");
    bus.bind_all(&rules(&[], Policy::Auto), &mut drv, &mut rec);
    assert_eq!(bus.get(hs[1]).unwrap().state, State::ProbeFailed);
    assert_eq!(bus.user_window(hs[1]), None);
    assert_eq!(bus.claim_user_window(hs[1]), None);
    // Once decided with no kernel driver in it, the window is ring 3's.
    assert_eq!(bus.get(hs[5]).unwrap().state, State::Unmatched);
    assert_eq!(bus.user_window(hs[5]), Some((0x1000_0000, 0x1000)));
}

#[test]
fn a_device_a_task_mapped_is_never_given_to_a_kernel_driver() {
    let mut bus = Bus::new();
    let mut rec = Recorder::default();
    let h = bus.add(virtio(2, 0x1000_2000), &mut rec).unwrap();
    // Not admitted under topology-only: ring 3 may map it.
    let mut drv = Fake::with(ALL);
    bus.bind_all(&rules(&[], Policy::TopologyOnly), &mut drv, &mut rec);
    assert_eq!(bus.get(h).unwrap().state, State::NotAdmitted);
    assert_eq!(bus.claim_user_window(h), Some((0x1000_2000, 0x1000)));
    // A later topology admits it for the native disk driver: the mapping
    // cannot be taken back, so the driver is not asked.
    let rows = [Row { select: Pattern::Virtio(2), admit: true, driver: None }];
    bus.reconcile(&rules(&rows, Policy::TopologyOnly), &mut drv, &mut rec);
    assert_eq!(bus.get(h).unwrap().state, State::ProbeFailed);
    assert!(drv.probed.is_empty(), "the driver never saw the device");
    assert!(rec.lines.contains(&"probe-failed virtio@10002000 virtio-blk Busy".to_string()));
    // A booking given back (the mapping failed) leaves the device free to bind.
    let mut bus = Bus::new();
    let h = bus.add(virtio(2, 0x1000_2000), &mut rec).unwrap();
    bus.bind_all(&rules(&[], Policy::TopologyOnly), &mut drv, &mut rec);
    bus.claim_user_window(h).unwrap();
    bus.unclaim_user_window(h);
    bus.reconcile(&rules(&rows, Policy::TopologyOnly), &mut drv, &mut rec);
    assert_eq!(bus.get(h).unwrap().state, State::Bound);
}

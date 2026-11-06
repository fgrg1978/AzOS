// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Driver records: the generated ids, unbind and rebind through a record, the
//! post-unbind check, and the order a system suspend takes devices down in.
//!
//! The environment is a fake with books: which device holds which interrupt
//! line, live DMA and its window. A line is held by one device at a time, so a
//! rebind whose earlier unbind left the line bound is refused, as the kernel's
//! line binding refuses it.

use super::{rules, virtio, Recorder, NATIVE_FIX};
use azos_hwbus::pattern::first_overlap;
use azos_hwbus::*;
use std::collections::BTreeMap;

struct Fake;

impl Host for Fake {
    type Env<'a> = FakeEnv;
}

#[derive(Default)]
struct FakeEnv {
    /// Interrupt line to the handle that holds it.
    irq: BTreeMap<u32, u32>,
    dma: Vec<u32>,
    window: Vec<u32>,
    /// Devices whose suspend fails.
    refuse_suspend: Vec<u32>,
    /// Lines enabled on an interrupt-controller context (a hart), as
    /// `(line, hart)`; each device's line is booked with the hart it was
    /// enabled on.
    enabled: Vec<(u32, u32)>,
    booked_hart: BTreeMap<u32, u32>,
    /// The hart the op runs on.
    hart: u32,
    log: Vec<String>,
}

impl Env for FakeEnv {
    fn held(&mut self, h: Handle, dev: &Device) -> Held {
        Held {
            irq: self.irq.iter().find(|(_, o)| **o == h.0).map(|(l, _)| *l).or_else(|| {
                let line = dev.irq;
                self.enabled.iter().any(|&(l, _)| l == line).then_some(line)
            }),
            dma: self.dma.contains(&h.0),
            window: self.window.contains(&h.0),
        }
    }
}

/// A line another device holds is refused; one this device still holds (a
/// re-probe after a leaked unbind) is kept.
fn probe(env: &mut FakeEnv, h: Handle, dev: &Device) -> Result<(), ProbeError> {
    if env.irq.get(&dev.irq).is_some_and(|&o| o != h.0) {
        return Err(ProbeError::Busy);
    }
    env.irq.insert(dev.irq, h.0);
    env.dma.retain(|&x| x != h.0);
    env.window.retain(|&x| x != h.0);
    env.dma.push(h.0);
    env.window.push(h.0);
    env.log.push(format!("probe {}", h.0));
    Ok(())
}

/// Another driver for the NIC: what a later topology may choose.
fn probe_b(env: &mut FakeEnv, h: Handle, _dev: &Device) -> Result<(), ProbeError> {
    env.log.push(format!("probe-b {}", h.0));
    Ok(())
}

/// DMA stopped, window forgotten, then the line.
fn unbind(env: &mut FakeEnv, h: Handle, dev: &Device) -> Result<(), ProbeError> {
    env.dma.retain(|&x| x != h.0);
    env.window.retain(|&x| x != h.0);
    if !cfg!(feature = "leak-canary") {
        env.irq.remove(&dev.irq);
    }
    env.log.push(format!("unbind {}", h.0));
    Ok(())
}

/// Forgets the interrupt line.
fn leaky_unbind(env: &mut FakeEnv, h: Handle, _dev: &Device) -> Result<(), ProbeError> {
    env.dma.retain(|&x| x != h.0);
    env.window.retain(|&x| x != h.0);
    Ok(())
}

fn suspend(env: &mut FakeEnv, h: Handle, _dev: &Device) -> Result<(), ProbeError> {
    if env.refuse_suspend.contains(&h.0) {
        return Err(ProbeError::Busy);
    }
    env.log.push(format!("suspend {}", h.0));
    Ok(())
}

fn resume(env: &mut FakeEnv, h: Handle, _dev: &Device) -> Result<(), ProbeError> {
    env.log.push(format!("resume {}", h.0));
    Ok(())
}

fn record_only(_env: &mut FakeEnv, _h: Handle, _dev: &Device) -> Result<(), ProbeError> {
    Ok(())
}

/// Enables its line on the hart it runs on and books that hart.
fn probe_on_hart(env: &mut FakeEnv, h: Handle, dev: &Device) -> Result<(), ProbeError> {
    probe(env, h, dev)?;
    env.enabled.push((dev.irq, env.hart));
    env.booked_hart.insert(h.0, env.hart);
    Ok(())
}

/// Masks the line on the context it was enabled on.
fn unbind_booked_hart(env: &mut FakeEnv, h: Handle, dev: &Device) -> Result<(), ProbeError> {
    let hart = env.booked_hart[&h.0];
    env.enabled.retain(|&e| e != (dev.irq, hart));
    unbind(env, h, dev)
}

/// Masks the line on the hart the unbind runs on.
fn unbind_this_hart(env: &mut FakeEnv, h: Handle, dev: &Device) -> Result<(), ProbeError> {
    let hart = env.hart;
    env.enabled.retain(|&e| e != (dev.irq, hart));
    unbind(env, h, dev)
}

static CLEAN: Ops<Fake> = Ops {
    probe,
    unbind: Unbind::<Fake>::Op(unbind),
    power: Power::<Fake>::Op { suspend, resume },
};
static LEAKY: Ops<Fake> = Ops { unbind: Unbind::<Fake>::Op(leaky_unbind), ..CLEAN };
static NO_PM: Ops<Fake> = Ops { power: Power::Unsupported, ..CLEAN };
static NET_B_OPS: Ops<Fake> = Ops { probe: probe_b, ..CLEAN };
static NET_B: DriverIds = DriverIds { name: "other-net", ids: &[Pattern::pci(0x8086, 0x1234)], boot: false };
static ON_HART: Ops<Fake> = Ops { probe: probe_on_hart, unbind: Unbind::<Fake>::Op(unbind_booked_hart), ..CLEAN };
static THIS_HART: Ops<Fake> = Ops { probe: probe_on_hart, unbind: Unbind::<Fake>::Op(unbind_this_hart), ..CLEAN };
static PINNED: Ops<Fake> = Ops { probe: record_only, unbind: Unbind::Pinned, power: Power::Stateless };

static BLK: DriverIds = DriverIds { name: "virtio-blk", ids: &[Pattern::Virtio(2)], boot: false };
static NET: DriverIds = DriverIds { name: "virtio-net", ids: &[Pattern::Virtio(1)], boot: false };
static NET_PCI: DriverIds =
    DriverIds { name: "virtio-net-pci", ids: &[Pattern::pci(0x1af4, 0x1041)], boot: false };
static UART: DriverIds = DriverIds { name: "uart", ids: &[Pattern::Dt("ns16550a")], boot: true };

fn table(net: &'static Ops<Fake>) -> [Record<Fake>; 4] {
    [
        Record { ids: &BLK, ops: &CLEAN },
        Record { ids: &NET, ops: net },
        Record { ids: &NET_PCI, ops: &CLEAN },
        Record { ids: &UART, ops: &PINNED },
    ]
}

fn dev_at(id: u32, base: u64, irq: u32) -> Device {
    let mut d = virtio(id, base);
    d.irq = irq;
    d
}

fn net_pci(irq: u32) -> Device {
    let mut d = Device::pci(PciId { bus: 0, device: 3, function: 0, vendor: 0x1af4, device_id: 0x1041, class: 0x020000 });
    d.irq = irq;
    d
}

/// A bus with a disk (line 5), a NIC (6), a PCI NIC (7) and the console (10),
/// bound in that order through `recs`.
fn bound(recs: &[Record<Fake>], env: &mut FakeEnv) -> (Bus, Vec<Handle>) {
    let mut bus = Bus::new();
    let mut sink = Recorder::default();
    let hs = vec![
        bus.add(dev_at(2, 0x1000_1000, 5), &mut sink).unwrap(),
        bus.add(dev_at(1, 0x1000_2000, 6), &mut sink).unwrap(),
        bus.add(net_pci(7), &mut sink).unwrap(),
        bus.add(Device::dt("uart0", b"ns16550a\0", 0x1000_0000, 0x100, 10), &mut sink).unwrap(),
    ];
    bus.bind_all(&rules(&[], Policy::Auto), &mut Records { records: recs, env }, &mut sink);
    for &h in &hs {
        assert_eq!(bus.get(h).unwrap().state, State::Bound);
    }
    (bus, hs)
}

fn name_of(bus: &Bus, h: Handle) -> String {
    match bus.get(h).unwrap().binding {
        Binding::Native(n) => n.as_str().to_string(),
        b => panic!("{b:?}"),
    }
}

// ── The generated records ───────────────────────────────────────────────

/// One record's ids per driver name, every native id in its driver's record,
/// and no id of one driver overlapping another driver's.
#[test]
fn the_generated_records_are_one_per_driver_and_every_id_has_one_owner() {
    assert!(!DRIVERS.is_empty());
    for (i, d) in DRIVERS.iter().enumerate() {
        assert!(DRIVERS[..i].iter().all(|e| e.name != d.name), "{} has two records", d.name);
        assert!(!d.ids.is_empty(), "{} has a record without ids", d.name);
        for e in DRIVERS[i + 1..].iter() {
            assert!(
                first_overlap(d.ids, e.ids, |p| *p, |p| *p).is_none(),
                "an id of {} overlaps one of {}",
                d.name,
                e.name
            );
        }
    }
    for n in NATIVE {
        let d = DRIVERS.iter().find(|d| d.name == n.driver).unwrap_or_else(|| panic!("{} has no record", n.driver));
        assert!(d.ids.iter().any(|p| p == &n.pattern), "{}: {:?} is not in its record", n.driver, n.pattern);
        assert_eq!(d.boot, n.boot, "{}", n.driver);
    }
    let ids: usize = DRIVERS.iter().map(|d| d.ids.len()).sum();
    assert_eq!(ids, NATIVE.len(), "an id is in no record or in two");
}

/// `native_drivers!` lists every record, in order, by index and identifier:
/// what a host's record table is built from.
#[test]
fn the_record_list_macro_names_every_generated_record() {
    macro_rules! listed {
        ($($i:literal $id:ident)*) => {
            [$(($i, stringify!($id))),*]
        };
    }
    let listed = native_drivers!(listed);
    assert_eq!(listed.len(), DRIVERS.len());
    for (k, (i, id)) in listed.iter().enumerate() {
        assert_eq!(*i, k);
        assert_eq!(*id, DRIVERS[k].name.to_ascii_uppercase().replace('-', "_"));
    }
}

// ── Unbind and rebind ───────────────────────────────────────────────────

/// Each bound driver lets go once (its line, DMA and window all given back)
/// and binds again, holding its line anew. Fails under `leak-canary`.
#[test]
fn unbind_and_rebind_each_bound_driver_once_and_the_device_is_driven_after() {
    let mut env = FakeEnv::default();
    let recs = table(&CLEAN);
    let (mut bus, hs) = bound(&recs, &mut env);
    let mut sink = Recorder::default();
    for &h in &hs[..3] {
        let (driver, line) = (name_of(&bus, h), bus.get(h).unwrap().dev.irq);
        let mut d = Records { records: &recs, env: &mut env };
        assert_eq!(bus.unbind(h, &mut d, &mut sink), Ok(()), "{driver}: {:?}", sink.lines);
        assert_eq!(d.env.held(h, &bus.get(h).unwrap().dev), Held::NONE);
        assert!(bus.rebind(h, &driver, &mut d, &mut sink), "{driver} did not bind again: {:?}", sink.lines);
        assert_eq!(env.irq.get(&line), Some(&h.0));
    }
    let probes = env.log.iter().filter(|l| l.starts_with("probe")).count();
    assert_eq!(probes, 6, "{:?}", env.log);
}

/// The canary's own row, permanent: an unbind that forgets the interrupt line
/// is not taken on the driver's word. The device stays bound, the bus says
/// what it holds, and the rebind is refused. Fails under `unbind-canary`.
#[test]
fn a_record_whose_unbind_leaves_the_irq_bound_keeps_its_device_and_the_rebind_fails() {
    let mut env = FakeEnv::default();
    let recs = table(&LEAKY);
    let (mut bus, hs) = bound(&recs, &mut env);
    let mut sink = Recorder::default();
    let mut d = Records { records: &recs, env: &mut env };
    let held = Held { irq: Some(6), dma: false, window: false };
    assert_eq!(bus.unbind(hs[1], &mut d, &mut sink), Err(UnbindError::Leaked(held)));
    assert_eq!(bus.get(hs[1]).unwrap().state, State::Bound);
    assert!(sink.lines.iter().any(|l| l.starts_with("unbind-leaked virtio@10002000")), "{:?}", sink.lines);
    assert!(!bus.rebind(hs[1], "virtio-net", &mut d, &mut sink));
}

/// A rebind to another driver after a leaked unbind never probes the new
/// driver over hardware the old one still drives: the old driver is asked to
/// bind again and keeps the device, its binding intact. Red with the rebind
/// continuing on `Leaked`, or with no bound-device guard in the bind plan.
#[test]
fn a_leaked_unbind_probes_the_old_driver_again_and_never_the_new_one() {
    let mut env = FakeEnv::default();
    let recs = [
        Record { ids: &BLK, ops: &CLEAN },
        Record { ids: &NET, ops: &LEAKY },
        Record { ids: &NET_PCI, ops: &CLEAN },
        Record { ids: &UART, ops: &PINNED },
        Record { ids: &NET_B, ops: &NET_B_OPS },
    ];
    let (mut bus, hs) = bound(&recs, &mut env);
    env.log.clear();
    let mut sink = Recorder::default();
    let mut d = Records { records: &recs, env: &mut env };
    assert!(!bus.rebind(hs[1], "other-net", &mut d, &mut sink));
    assert_eq!(bus.get(hs[1]).unwrap().binding, Binding::Native(Name::new("virtio-net")));
    assert_eq!(bus.get(hs[1]).unwrap().state, State::Bound);
    let n = hs[1].0;
    assert_eq!(env.log, [format!("probe {n}")], "{:?}", sink.lines);
}

/// A bind decision is not made again for a device that is bound: no probe,
/// no change of owner.
#[test]
fn a_bound_device_is_not_decided_again() {
    let mut env = FakeEnv::default();
    let recs = table(&CLEAN);
    let (mut bus, hs) = bound(&recs, &mut env);
    env.log.clear();
    let mut sink = Recorder::default();
    let rows = [Row { select: Pattern::Virtio(1), admit: false, driver: None }];
    bus.bind(hs[1], &rules(&rows, Policy::Auto), &mut Records { records: &recs, env: &mut env }, &mut sink);
    assert_eq!(bus.get(hs[1]).unwrap().state, State::Bound);
    assert!(env.log.is_empty() && sink.lines.is_empty(), "{:?} {:?}", env.log, sink.lines);
}

/// Hardware the kernel drives outside the bus is never released.
#[test]
fn a_pinned_record_keeps_its_device() {
    let mut env = FakeEnv::default();
    let recs = table(&CLEAN);
    let (mut bus, hs) = bound(&recs, &mut env);
    let mut sink = Recorder::default();
    let mut d = Records { records: &recs, env: &mut env };
    assert_eq!(bus.unbind(hs[3], &mut d, &mut sink), Err(UnbindError::Refused));
    assert_eq!(bus.get(hs[3]).unwrap().state, State::Bound);
    assert_eq!(sink.lines, ["unbind-refused uart0 uart"]);
}

/// A name the table has no record for is no driver.
#[test]
fn a_driver_without_a_record_is_not_probed() {
    let mut env = FakeEnv::default();
    let recs = [Record { ids: &BLK, ops: &CLEAN }];
    let mut bus = Bus::new();
    let mut sink = Recorder::default();
    let h = bus.add(dev_at(1, 0x1000_2000, 6), &mut sink).unwrap();
    bus.bind_all(&rules(&[], Policy::Auto), &mut Records { records: &recs, env: &mut env }, &mut sink);
    assert_eq!(bus.get(h).unwrap().state, State::ProbeFailed);
    assert!(sink.lines.iter().any(|l| l.ends_with("virtio-net NoSuchDriver")), "{:?}", sink.lines);
}

// ── System suspend ──────────────────────────────────────────────────────

/// Bound in an order that is not slot order: the PCI NIC first, then the disk,
/// then the NIC (and the console, bound before them all at boot).
fn staged(recs: &[Record<Fake>], env: &mut FakeEnv) -> (Bus, Vec<Handle>) {
    let mut bus = Bus::new();
    let mut sink = Recorder::default();
    let hs = vec![
        bus.add(dev_at(2, 0x1000_1000, 5), &mut sink).unwrap(),
        bus.add(dev_at(1, 0x1000_2000, 6), &mut sink).unwrap(),
        bus.add(net_pci(7), &mut sink).unwrap(),
        bus.add(Device::dt("uart0", b"ns16550a\0", 0x1000_0000, 0x100, 10), &mut sink).unwrap(),
    ];
    for stage in [&["uart"][..], &["virtio-net-pci"], &["virtio-blk"], &["virtio-net"]] {
        bus.bind_where(&rules(&[], Policy::Auto), &mut Records { records: recs, env: &mut *env }, &mut sink, &|_, v| {
            matches!(v, Verdict::Bind(Choice::Native(n)) if stage.contains(n))
        });
    }
    (bus, hs)
}

/// Down newest bind first, up oldest first; the console has nothing to save.
#[test]
fn a_suspend_takes_devices_down_newest_bind_first_and_brings_them_back_oldest_first() {
    let mut env = FakeEnv::default();
    let recs = table(&CLEAN);
    let (mut bus, hs) = staged(&recs, &mut env);
    env.log.clear();
    let mut sink = Recorder::default();
    let mut d = Records { records: &recs, env: &mut env };
    assert_eq!(bus.quiesce(&mut d, &mut sink), Ok(()));
    assert!(hs.iter().all(|&h| bus.suspended(h)));
    assert_eq!(bus.unquiesce(&mut d, &mut sink), 0);
    assert!(hs.iter().all(|&h| !bus.suspended(h)));
    let (blk, net, pci) = (hs[0].0, hs[1].0, hs[2].0);
    let want: Vec<String> = [
        format!("suspend {net}"),
        format!("suspend {blk}"),
        format!("suspend {pci}"),
        format!("resume {pci}"),
        format!("resume {blk}"),
        format!("resume {net}"),
    ]
    .into();
    assert_eq!(env.log, want);
    assert!(sink.lines.is_empty(), "{:?}", sink.lines);
}

/// All or nothing: the disk refuses, the NIC already down comes back, the PCI
/// NIC is never asked, and the suspend is refused with one blocker.
#[test]
fn a_device_that_will_not_go_down_brings_the_others_back_and_refuses_the_suspend() {
    let mut env = FakeEnv::default();
    let recs = table(&CLEAN);
    let (mut bus, hs) = staged(&recs, &mut env);
    env.log.clear();
    env.refuse_suspend.push(hs[0].0);
    let mut sink = Recorder::default();
    let mut d = Records { records: &recs, env: &mut env };
    assert_eq!(bus.quiesce(&mut d, &mut sink), Err(1));
    assert!(hs.iter().all(|&h| !bus.suspended(h)));
    let net = hs[1].0;
    assert_eq!(env.log, [format!("suspend {net}"), format!("resume {net}")]);
    assert_eq!(sink.lines, ["suspend-refused virtio@10001000 virtio-blk Busy"]);
}

/// A bound driver with no power ops blocks the suspend.
#[test]
fn a_driver_without_power_ops_refuses_the_suspend() {
    let mut env = FakeEnv::default();
    let recs = table(&NO_PM);
    let (mut bus, _) = staged(&recs, &mut env);
    let mut sink = Recorder::default();
    assert_eq!(bus.quiesce(&mut Records { records: &recs, env: &mut env }, &mut sink), Err(1));
    assert_eq!(sink.lines, ["suspend-refused virtio@10002000 virtio-net Unsupported"]);
}

/// The fixtures bind through the records the test table names, not the
/// generated one: the fixture table is the one `rules` reads.
#[test]
fn the_fixture_drivers_are_the_fixture_table_s() {
    for r in table(&CLEAN).iter() {
        assert!(NATIVE_FIX.iter().any(|n| n.driver == r.name()), "{}", r.name());
    }
}

/// A line enabled on one hart's context and given back from another: masked
/// on the context it was enabled on, the unbind is clean; masked only on the
/// hart the unbind runs on, the line is still live on the first and the bus
/// keeps the device (the riscv PLIC / IMSIC case).
#[test]
fn a_line_is_given_back_on_the_context_it_was_enabled_on() {
    for (ops, clean) in [(&ON_HART, true), (&THIS_HART, false)] {
        let mut env = FakeEnv { hart: 1, ..FakeEnv::default() };
        let recs = table(ops);
        let (mut bus, hs) = bound(&recs, &mut env);
        env.hart = 0;
        let mut sink = Recorder::default();
        let r = bus.unbind(hs[1], &mut Records { records: &recs, env: &mut env }, &mut sink);
        assert_eq!(r.is_ok(), clean, "{r:?} {:?}", sink.lines);
        assert_eq!(env.enabled.iter().any(|&(l, _)| l == 6), !clean);
    }
}

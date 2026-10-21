// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The class driver over the xHCI mock: a device is plugged in, the driver
//! authorizes it, reads its descriptor (or asks for the boot protocol), opens
//! the interrupt endpoint, and the reports a test injects come out as events.

use azos_decision::{Filter, ProvenanceRecord};
use azos_input_wire::event::*;
use azos_usb::class::{Registry, UsbClass, UsbClassDirect};
use azos_usb::listing::Lister;
use azos_usb::usbcore::pipe::PipeRings;
use azos_usb::MAX_PIPES;
use azos_usb_hid::driver::MAX_BINDS;
use azos_usb_hid::{HidClass, Policy, Sink, State};
use azos_usb_tests::devices::*;
use azos_usb_tests::harness::Rig;

use crate::fixtures::*;

const ADMIT: Policy = Policy { admit_hid: true, max_tier: 5, refuse_composite: true };

#[derive(Default)]
struct TestSink {
    events: Vec<(u8, u16, u16, u32)>,
    gone: Vec<u8>,
}

impl Sink for TestSink {
    fn event(&mut self, dev: u8, ty: u16, code: u16, value: u32) {
        self.events.push((dev, ty, code, value));
    }
    fn gone(&mut self, dev: u8) {
        self.gone.push(dev);
    }
}

struct Bench {
    rig: Rig,
    hid: UsbClassDirect<HidClass<'static>>,
    sink: TestSink,
    now: u64,
}

impl Bench {
    fn new(policy: Policy) -> Bench {
        let rig = Rig::new();
        let hid = UsbClassDirect(HidClass::new(rig.rings, policy));
        Bench { rig, hid, sink: TestSink::default(), now: 1000 }
    }

    /// One millisecond: the core's service, the driver's poll.
    fn tick(&mut self) {
        let mut reg = Registry::new();
        reg.register(0, Lister::rule(), &mut self.rig.lister).unwrap();
        reg.register(1, HidClass::rule(), &mut self.hid).unwrap();
        self.rig.usb.service(&mut reg);
        drop(reg);
        self.hid.0.poll(&mut self.rig.usb, self.now, &mut self.sink);
        use azos_usb::hw::Clock;
        self.rig.hw.clock().delay_us(1_000);
        self.now += 1;
    }

    fn run(&mut self, ms: u64) {
        for _ in 0..ms {
            self.tick();
        }
    }

    /// Long enough for debounce, reset, a few hub levels and the driver's control transfers.
    fn settle(&mut self) {
        self.run(2_400);
    }

    fn events(&self) -> Vec<(u8, u16, u16, u32)> {
        self.sink.events.clone()
    }
}

/// A full speed device with the given interfaces.
fn device(vid: u16, pid: u16, ifaces: &[Iface]) -> DevRef {
    let dd = device_desc(0x0110, 0, 0, 0, 8, vid, pid, 0, 0);
    MockDev::new(1, dd, config_desc(1, ifaces)).into_ref()
}

/// A boot keyboard with a report descriptor.
fn keyboard_with_descriptor(vid: u16, pid: u16) -> DevRef {
    let d = device(vid, pid, &[iface(0, 3, 1, 1, vec![ep(0x81, 3, 8, 10)])]);
    d.borrow_mut().report_descs.push((0, BOOT_KEYBOARD.to_vec()));
    d
}

fn requests(d: &DevRef) -> Vec<[u8; 8]> {
    d.borrow().requests.iter().map(|(s, _)| *s).collect()
}

fn asked_for_report_descriptor(r: &[[u8; 8]]) -> bool {
    r.iter().any(|s| s[0] == 0x81 && s[1] == 6 && s[3] == 0x22)
}

fn set_protocol(r: &[[u8; 8]]) -> Option<[u8; 8]> {
    r.iter().copied().find(|s| s[0] == 0x21 && s[1] == 0x0b)
}

fn set_idle(r: &[[u8; 8]]) -> bool {
    r.iter().any(|s| s[0] == 0x21 && s[1] == 0x0a)
}

/// The `usb-authorize` records of the device `vid_pid`.
fn records(vid_pid: u32) -> Vec<ProvenanceRecord> {
    let mut ids = vec![0u64; 1024];
    let f = Filter { rule: Some(azos_decision::Rule::UsbAuthorize as u8), verdict: None, subject: None, after: 0 };
    let n = azos_decision::query(&f, &mut ids);
    ids[..n].iter().filter_map(|&i| azos_decision::lookup(i)).filter(|r| r.n[0] == vid_pid as u64).collect()
}

#[test]
fn a_keyboard_with_a_descriptor_runs_in_report_protocol() {
    let mut b = Bench::new(ADMIT);
    let kb = keyboard_with_descriptor(0x1111, 0x0001);
    b.rig.hw.attach_root(1, kb.clone());
    b.settle();
    assert_eq!(b.hid.0.state(0), State::Running);
    assert_eq!(b.hid.0.running(), 1);
    let r = requests(&kb);
    assert!(asked_for_report_descriptor(&r));
    assert!(set_idle(&r));
    // The device's own descriptor is used: the boot protocol is not asked for.
    assert!(set_protocol(&r).is_none());

    b.rig.hw.inject_in(&kb, 1, &[0x02, 0, 4, 0, 0, 0, 0, 0]);
    b.run(30);
    assert_eq!(b.events(), vec![(0, EV_KEY, KEY_LEFTSHIFT, 1), (0, EV_KEY, KEY_A, 1)]);
    b.rig.hw.inject_in(&kb, 1, &[0; 8]);
    b.run(30);
    assert_eq!(b.events().len(), 4);
    assert_eq!(b.events()[3], (0, EV_KEY, KEY_A, 0));
}

#[test]
fn a_keyboard_that_will_not_give_its_descriptor_is_asked_for_the_boot_protocol() {
    let mut b = Bench::new(ADMIT);
    // The mock's plain keyboard stalls GET_DESCRIPTOR(Report).
    let kb = keyboard();
    b.rig.hw.attach_root(1, kb.clone());
    b.settle();
    assert_eq!(b.hid.0.state(0), State::Running);
    let r = requests(&kb);
    assert!(asked_for_report_descriptor(&r));
    let p = set_protocol(&r).expect("SET_PROTOCOL");
    // wValue 0 is the boot protocol; wIndex the interface.
    assert_eq!((p[2], p[3], p[4], p[5]), (0, 0, 0, 0));
    assert!(set_idle(&r));

    b.rig.hw.inject_in(&kb, 1, &[0, 0, 0x28, 0, 0, 0, 0, 0]);
    b.run(30);
    assert_eq!(b.events(), vec![(0, EV_KEY, KEY_ENTER, 1)]);
}

#[test]
fn a_boot_mouse_without_a_descriptor_moves_and_clicks() {
    let mut b = Bench::new(ADMIT);
    let m = device(0x1111, 0x0002, &[iface(0, 3, 1, 2, vec![ep(0x81, 3, 4, 10)])]);
    b.rig.hw.attach_root(1, m.clone());
    b.settle();
    assert_eq!(b.hid.0.state(0), State::Running);
    assert!(set_protocol(&requests(&m)).is_some());
    b.rig.hw.inject_in(&m, 1, &[0x01, 5, 0xfd]);
    b.run(30);
    assert_eq!(b.events(), vec![(0, EV_REL, REL_X, 5), (0, EV_REL, REL_Y, (-3i32) as u32), (0, EV_KEY, BTN_LEFT, 1)]);
}

#[test]
fn an_interface_that_is_not_a_boot_device_needs_its_descriptor() {
    let mut b = Bench::new(ADMIT);
    // Class 3, subclass 0: no boot protocol to fall back to.
    let d = device(0x1111, 0x0003, &[iface(0, 3, 0, 0, vec![ep(0x81, 3, 8, 10)])]);
    b.rig.hw.attach_root(1, d.clone());
    b.settle();
    assert_eq!(b.hid.0.state(0), State::Failed);
    assert_eq!(b.hid.0.running(), 0);
    assert!(set_protocol(&requests(&d)).is_none());
    // It gave back its control pipe: a device that fails holds nothing.
    assert!(no_pipe_in_use(&b));
}

fn no_pipe_in_use(b: &Bench) -> bool {
    (0..azos_usb::MAX_PIPES).all(|i| !b.rig.usb.pipe_in_use(i as u8))
}

#[test]
fn an_interface_that_keeps_failing_is_given_up_and_gives_everything_back() {
    let mut b = Bench::new(ADMIT);
    let kb = keyboard_with_descriptor(0x1111, 0x0008);
    b.rig.hw.attach_root(1, kb.clone());
    b.settle();
    b.rig.hw.inject_in(&kb, 1, &[0, 0, 4, 0, 0, 0, 0, 0]);
    b.run(30);
    assert!(!no_pipe_in_use(&b), "the interrupt pipe is open while it runs");
    // Every transfer fails (USB transaction error) until the driver stops asking.
    let slot = b.rig.slot_of(&kb) as usize;
    for _ in 0..64 {
        b.rig.hw.inject_error(slot, 3, 4);
    }
    // The mock polls an endpoint when it is kicked; the real one does every interval.
    for _ in 0..2_000 {
        b.rig.hw.kick_dev(&kb);
        b.tick();
    }
    assert_eq!(b.hid.0.state(0), State::Failed);
    // The key that was down is released and the sink told, before anything is freed.
    assert_eq!(b.events().last(), Some(&(0, EV_KEY, KEY_A, 0)));
    assert_eq!(b.sink.gone, vec![0]);
    assert!(no_pipe_in_use(&b), "a failed interface holds no pipe");
}

#[test]
fn a_receiver_with_a_keyboard_a_mouse_and_a_vendor_interface_binds_the_first_two() {
    let mut b = Bench::new(ADMIT);
    let r = device(
        0x046d,
        0xc52b,
        &[
            iface(0, 3, 1, 1, vec![ep(0x81, 3, 8, 8)]),
            iface(1, 3, 1, 2, vec![ep(0x82, 3, 8, 2)]),
            iface(2, 3, 0, 0, vec![ep(0x83, 3, 32, 2)]),
        ],
    );
    r.borrow_mut().report_descs = vec![(0, BOOT_KEYBOARD.to_vec()), (1, LOGITECH_MOUSE.to_vec()), (2, LOGITECH_HIDPP.to_vec())];
    b.rig.hw.attach_root(1, r.clone());
    b.settle();
    let states: Vec<State> = (0..3).map(|i| b.hid.0.state(i)).collect();
    assert_eq!(states, vec![State::Running, State::Running, State::Ignored]);
    assert_eq!(b.hid.0.running(), 2);

    // The mouse interface speaks report ID 2.
    b.rig.hw.inject_in(&r, 2, &[2, 0x01, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00]);
    b.rig.hw.inject_in(&r, 1, &[0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00]);
    b.run(30);
    let mut ev = b.events();
    ev.sort();
    assert_eq!(ev, vec![(0, EV_KEY, KEY_A, 1), (1, EV_KEY, BTN_LEFT, 1), (1, EV_REL, REL_X, 3)]);
}

#[test]
fn unplugging_releases_the_keys_and_frees_the_interface() {
    let mut b = Bench::new(ADMIT);
    let kb = keyboard_with_descriptor(0x1111, 0x0004);
    b.rig.hw.attach_root(1, kb.clone());
    b.settle();
    b.rig.hw.inject_in(&kb, 1, &[0x02, 0, 4, 0, 0, 0, 0, 0]);
    b.run(30);
    assert_eq!(b.events().len(), 2);

    b.rig.hw.detach_root(1);
    b.run(200);
    // Shift and `a` were down: both are released, then the sink is told.
    assert_eq!(b.events()[2..].to_vec(), vec![(0, EV_KEY, KEY_LEFTSHIFT, 0), (0, EV_KEY, KEY_A, 0)]);
    assert_eq!(b.sink.gone, vec![0]);
    assert_eq!(b.hid.0.state(0), State::Free);

    // The pipes' rings and the table slot are reusable.
    let kb2 = keyboard_with_descriptor(0x1111, 0x0005);
    b.rig.hw.attach_root(1, kb2.clone());
    b.settle();
    assert_eq!(b.hid.0.state(0), State::Running);
    b.rig.hw.inject_in(&kb2, 1, &[0, 0, 5, 0, 0, 0, 0, 0]);
    b.run(30);
    assert_eq!(b.events().last(), Some(&(0, EV_KEY, 48, 1)));
}

#[test]
fn a_key_held_repeats_after_the_delay_and_stops_when_released() {
    let mut b = Bench::new(ADMIT);
    let kb = keyboard_with_descriptor(0x1111, 0x0006);
    b.rig.hw.attach_root(1, kb.clone());
    b.settle();
    b.rig.hw.inject_in(&kb, 1, &[0, 0, 4, 0, 0, 0, 0, 0]);
    let delay = azos_limits::USB_HID_REPEAT_DELAY_MS;
    let period = azos_limits::USB_HID_REPEAT_PERIOD_MS;
    b.run(delay - 60);
    assert_eq!(b.events(), vec![(0, EV_KEY, KEY_A, 1)]);
    b.run(120);
    let repeats = |b: &Bench| b.events().iter().filter(|e| e.1 == EV_KEY && e.3 == 2).count();
    assert!(repeats(&b) >= 1, "no repeat after the delay");
    b.run(period * 10);
    let held = repeats(&b);
    assert!(held >= 5 && held <= 14, "{held} repeats");
    assert!(b.events().iter().filter(|e| e.3 == 2).all(|e| e.2 == KEY_A));
    // Release: it stops.
    b.rig.hw.inject_in(&kb, 1, &[0; 8]);
    b.run(30);
    let stopped = repeats(&b);
    b.run(period * 6);
    assert_eq!(repeats(&b), stopped);
}

#[test]
fn a_transfer_error_does_not_stop_the_keyboard() {
    let mut b = Bench::new(ADMIT);
    let kb = keyboard_with_descriptor(0x1111, 0x0007);
    b.rig.hw.attach_root(1, kb.clone());
    b.settle();
    let slot = b.rig.slot_of(&kb);
    // The next interrupt transfer fails with a USB transaction error (code 4).
    b.rig.hw.inject_error(slot as usize, 3, 4);
    b.rig.hw.inject_in(&kb, 1, &[0, 0, 4, 0, 0, 0, 0, 0]);
    b.run(100);
    b.rig.hw.inject_in(&kb, 1, &[0, 0, 5, 0, 0, 0, 0, 0]);
    b.run(100);
    assert_eq!(b.hid.0.state(0), State::Running);
    assert!(b.events().iter().any(|e| e.2 == 48 && e.3 == 1), "{:?}", b.events());
}

#[test]
fn a_mass_storage_stick_is_not_this_drivers() {
    let mut b = Bench::new(ADMIT);
    let s = stick();
    b.rig.hw.attach_root(1, s);
    b.settle();
    assert_eq!(b.hid.0.state(0), State::Free);
    assert!(b.events().is_empty());
}

#[test]
fn the_table_is_full_when_every_slot_is_claimed() {
    let rings: &'static [PipeRings; MAX_PIPES] = Box::leak(Box::new(std::array::from_fn(|_| PipeRings::new())));
    let mut c = HidClass::new(rings, ADMIT);
    let claim = |i: u32| azos_usb::Claim::new(i as u8 + 1, 0, 1).0;
    for i in 0..MAX_BINDS as u32 {
        assert_eq!(c.attach(claim(i), 1, 3 << 16, 0).code, azos_devif::outcome::OK);
    }
    assert_eq!(c.attach(claim(99), 1, 3 << 16, 0).code, azos_devif::outcome::NO_RESOURCE);
    // A device-scope claim is not an interface's.
    let dev = azos_usb::Claim::new(1, azos_usb::class::WHOLE_DEVICE, 1).0;
    assert_eq!(c.attach(dev, 1, 3 << 16, 0).code, azos_devif::outcome::UNSUPPORTED);
    // A claim that was never made is let go quietly; a real one frees its slot at the next poll.
    assert_eq!(c.detach(claim(98)).code, azos_devif::outcome::OK);
    assert_eq!(c.detach(claim(0)).code, azos_devif::outcome::OK);
    assert_eq!(c.state(0), State::Gone);
}

// ---- Authorization ----

#[test]
fn a_build_that_admits_no_hid_refuses_a_keyboard_before_it_talks_to_it() {
    let mut b = Bench::new(Policy { admit_hid: false, ..ADMIT });
    let kb = keyboard_with_descriptor(0x2222, 0x0001);
    b.rig.hw.attach_root(2, kb.clone());
    b.settle();
    assert_eq!(b.hid.0.state(0), State::Refused);
    // Not a single HID request reached the device.
    let r = requests(&kb);
    assert!(!asked_for_report_descriptor(&r) && !set_idle(&r) && set_protocol(&r).is_none());
    b.rig.hw.inject_in(&kb, 1, &[0, 0, 4, 0, 0, 0, 0, 0]);
    b.run(50);
    assert!(b.events().is_empty());
    let rec = records(0x2222_0001);
    assert_eq!(rec.len(), 1);
    assert_eq!((rec[0].verdict, rec[0].subject, rec[0].n[2]), (1, 2, 1));
}

#[test]
fn a_device_behind_too_many_hubs_is_refused() {
    for (max_tier, running) in [(0u8, false), (1, true)] {
        let mut b = Bench::new(Policy { max_tier, ..ADMIT });
        let h = hub_device(false, 4, 3, false);
        let kb = keyboard_with_descriptor(0x3333, 0x0100 + max_tier as u16);
        b.rig.hw.attach_root(1, h.clone());
        b.settle();
        b.rig.hw.hub_attach(&h, 1, kb.clone());
        b.settle();
        assert_eq!(b.hid.0.state(0), if running { State::Running } else { State::Refused }, "max tier {max_tier}");
        let rec = records(0x3333_0100 + max_tier as u32);
        assert_eq!(rec.len(), 1);
        assert_eq!(rec[0].n[2], if running { 0 } else { 2 });
    }
}

#[test]
fn a_keyboard_that_is_also_storage_is_refused() {
    let composite = || {
        let d = device(
            0x4444,
            0x0001,
            &[iface(0, 3, 1, 1, vec![ep(0x81, 3, 8, 10)]), iface(1, 8, 6, 0x50, vec![ep(0x82, 2, 64, 0), ep(0x03, 2, 64, 0)])],
        );
        d.borrow_mut().report_descs.push((0, BOOT_KEYBOARD.to_vec()));
        d
    };
    let mut b = Bench::new(ADMIT);
    b.rig.hw.attach_root(1, composite());
    b.settle();
    assert_eq!(b.hid.0.state(0), State::Refused);
    assert_eq!(records(0x4444_0001)[0].n[2], 3);

    // The same device with the rule off binds.
    let mut b = Bench::new(Policy { refuse_composite: false, ..ADMIT });
    b.rig.hw.attach_root(1, composite());
    b.settle();
    assert_eq!(b.hid.0.state(0), State::Running);
}

#[test]
fn a_keyboard_with_a_vendor_interface_is_not_a_composite_in_the_rule() {
    let mut b = Bench::new(ADMIT);
    let d = device(
        0x4545,
        0x0001,
        &[iface(0, 3, 1, 1, vec![ep(0x81, 3, 8, 10)]), iface(1, 0xff, 1, 1, vec![ep(0x82, 3, 16, 4)])],
    );
    d.borrow_mut().report_descs.push((0, BOOT_KEYBOARD.to_vec()));
    b.rig.hw.attach_root(1, d);
    b.settle();
    assert_eq!(b.hid.0.state(0), State::Running);
}

#[test]
fn every_authorization_is_recorded() {
    let mut b = Bench::new(ADMIT);
    let kb = keyboard_with_descriptor(0x5555, 0x0001);
    b.rig.hw.attach_root(3, kb);
    b.settle();
    let rec = records(0x5555_0001);
    assert_eq!(rec.len(), 1, "one record per interface");
    let r = &rec[0];
    // Admit, the root port, the vendor and product, the interface's class triple, reason 0.
    assert_eq!((r.verdict, r.subject), (0, 3));
    assert_eq!(r.n, [0x5555_0001, 3 << 16 | 1 << 8 | 1, 0]);
}

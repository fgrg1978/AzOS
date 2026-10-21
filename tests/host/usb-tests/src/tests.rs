// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The suites. See the table in `lib.rs` for the canary each one guards.

use azos_rings::Push;
use azos_usb::class::{Match, UsbClassCall, UsbClassClient, UsbClassIdl, UsbDeviceCall, UsbDeviceClient, UsbDeviceIdl};
use azos_usb::usbcore::desc::Setup;
use azos_usb::usbcore::pipe::{Completion, Dir, Status, Transfer};
use azos_usb::usbcore::OpenError;
use azos_idl::{MsgDesc, Transport};
use std::cell::RefCell;
use azos_usb::xhci::trb::Trb;
use azos_usb::xhci::Xhci;
use azos_usb::{Claim, EventKind};

use crate::devices::*;
use crate::harness::Rig;
use crate::mock::{Config, Hw};

fn cfg() -> Config {
    Config::default()
}

fn ids(rig: &Rig, dev: &DevRef) -> (u16, u16) {
    let s = rig.slot_of(dev);
    let d = rig.usb.device(s).expect("enumerated");
    (d.desc.vendor, d.desc.product)
}

// ---- The hardware bus ----

#[test]
fn the_hardware_bus_binds_xhci_functions_and_device_tree_nodes_to_the_driver() {
    use azos_hwbus::{natural, Choice, Device, PciId, LINUX, NATIVE};
    // Any PCI function of class 0C:03:30, whoever made it.
    for (vendor, device) in [(0x1b36, 0x000d), (0x8086, 0x1e31), (0x1033, 0x0194)] {
        let d = Device::pci(PciId { bus: 0, device: 3, function: 0, vendor, device_id: device, class: 0x0c0330 });
        assert!(matches!(natural(&d, NATIVE, LINUX), Some(Choice::Native("xhci"))), "{vendor:x}:{device:x}");
    }
    // USB 2 controllers (EHCI, class 0C0320) and USB 1 ones are not this driver's.
    for class in [0x0c0320, 0x0c0300, 0x0c0310] {
        let d = Device::pci(PciId { bus: 0, device: 4, function: 0, vendor: 0x8086, device_id: 1, class });
        assert!(!matches!(natural(&d, NATIVE, LINUX), Some(Choice::Native("xhci"))), "class {class:x}");
    }
    for compat in [&b"generic-xhci\0"[..], b"snps,dwc3\0"] {
        let d = Device::dt("usb", compat, 0x1000_0000, 0x10000, 5);
        assert!(matches!(natural(&d, NATIVE, LINUX), Some(Choice::Native("xhci"))), "{compat:?}");
    }
}

#[test]
fn a_dwc3_is_a_host_only_when_the_device_tree_says_so() {
    use azos_usb::dwc3::{is_host_only, set_host_mode, GCTL, GCTL_PRTCAPDIR_HOST};
    // `dr_mode = "host"` only. A gadget port (`peripheral`), a dual-role one
    // (`otg`) and a node without the property (the binding's default is otg)
    // are not the xHCI driver's.
    assert!(is_host_only(Some(b"host\0")));
    for v in [&b"peripheral\0"[..], b"otg\0", b"", b"hostile\0"] {
        assert!(!is_host_only(Some(v)), "{v:?}");
    }
    assert!(!is_host_only(None));
    // PRTCAPDIR becomes host and the rest of GCTL is left alone.
    struct One(core::cell::Cell<u32>);
    impl azos_usb::hw::Regs for One {
        fn read32(&self, off: usize) -> u32 {
            assert_eq!(off, GCTL);
            self.0.get()
        }
        fn write32(&self, off: usize, val: u32) {
            assert_eq!(off, GCTL);
            self.0.set(val)
        }
    }
    let r = One(core::cell::Cell::new(0x0000_3000 | 0x0400_0001)); // PRTCAPDIR = 3 (otg) plus other bits
    set_host_mode(&r);
    assert_eq!(r.0.get(), GCTL_PRTCAPDIR_HOST | 0x0400_0001);
}

// ---- The controller ----

#[test]
fn controller_starts_and_runs_a_command() {
    let rig = Rig::new();
    assert_eq!(rig.hw.fault(), None);
    // The bring-up proves the rings with one no-op command.
    assert_eq!(rig.hw.commands(), vec![23]);
}

#[test]
fn command_ring_wraps_over_the_link_trb() {
    let hw = Hw::new(cfg());
    let mut x = Xhci::new(hw.regs(), hw.mem(), hw.clock(), u64::MAX, false).unwrap();
    // A one-page ring holds 255 TRBs and a Link: 700 commands wrap it twice.
    for i in 0..700 {
        x.command(Trb::noop_cmd()).unwrap_or_else(|e| panic!("command {i}: {e:?}"));
    }
    assert_eq!(hw.commands().len(), 701);
    assert_eq!(hw.fault(), None);
}

#[test]
fn event_handler_busy_is_cleared_after_each_drain() {
    let hw = Hw::new(cfg());
    let mut x = Xhci::new(hw.regs(), hw.mem(), hw.clock(), u64::MAX, true).unwrap();
    let before = hw.interrupts();
    for _ in 0..5 {
        x.command(Trb::noop_cmd()).unwrap();
    }
    // A controller raises an interrupt for an event only while Event Handler
    // Busy is clear; the driver clears it when it writes the dequeue pointer.
    assert_eq!(hw.interrupts() - before, 5, "one interrupt per drained event");
}

#[test]
fn a_controller_the_firmware_owns_is_taken_over() {
    let rig = Rig::with(Config { bios_owned: true, ..cfg() });
    let (legsup, legctl) = rig.hw.legacy_support();
    assert_ne!(legsup & 1 << 24, 0, "OS-owned semaphore not set");
    assert_eq!(legsup & 1 << 16, 0, "the firmware still owns the controller");
    assert_eq!(legctl & (1 | 1 << 4 | 1 << 13), 0, "SMIs still enabled");
}

#[test]
fn controller_without_ac64_gets_low_memory() {
    let mut rig = Rig::with(Config { ac64: false, ..cfg() });
    rig.hw.attach_root(1, stick());
    rig.settle();
    assert_eq!(rig.hw.fault(), None, "the controller addressed memory above 4 GiB");
    assert_eq!(rig.usb.devices().count(), 1);
}

#[test]
fn controller_with_64_byte_contexts_enumerates() {
    let mut rig = Rig::with(Config { csz64: true, ..cfg() });
    let kb = keyboard();
    rig.hw.attach_root(1, kb.clone());
    rig.settle();
    assert_eq!(rig.usb.devices().count(), 1);
    assert_eq!(ids(&rig, &kb), (0x046d, 0xc31c));
    // An endpoint configured at the right stride is a real endpoint.
    let s = rig.slot_of(&kb) as usize;
    assert_eq!(rig.hw.ep_info(s, 1).0, 4);
}

#[test]
fn scratchpad_count_is_the_split_field() {
    // 37 = 1 << 5 | 5: the high field is 1, the low field 5.
    let rig = Rig::try_with(Config { scratch: 37, ..cfg() });
    assert!(rig.is_ok(), "controller refused: {:?}", rig.err());
    assert_eq!(rig.unwrap().hw.fault(), None, "a scratchpad entry the controller asked for is missing");
}

// ---- Enumeration ----

#[test]
fn enumerates_a_device_behind_a_root_port() {
    let mut rig = Rig::new();
    let st = stick();
    rig.hw.attach_root(2, st.clone());
    rig.settle();
    let slot = rig.slot_of(&st);
    let d = rig.usb.device(slot).unwrap();
    assert_eq!((d.desc.vendor, d.desc.product), (0x0781, 0x5567));
    assert_eq!(d.root_port, 2);
    assert_eq!(d.speed, azos_usb::xhci::Speed::High);
    assert_eq!(d.config.num_interfaces, 2);
    assert_eq!(d.config.interfaces()[0].class, 8);
    assert_eq!(d.config.interfaces()[0].num_endpoints, 2);
    assert_eq!(d.manufacturer.as_str(), "SanDisk");
    assert_eq!(d.product.as_str(), "Cruzer Blade");
    assert!(d.bos.unwrap().lpm);
    // The device was configured.
    assert_eq!(st.borrow().configuration, 1);
    // The slot context the controller got: root port 2, high speed, no route.
    let sc = rig.hw.slot_ctx(slot as usize);
    assert_eq!(sc[0] & 0xf_ffff, 0);
    assert_eq!((sc[0] >> 20) & 0xf, 3);
    assert_eq!((sc[1] >> 16) & 0xff, 2);
    assert_eq!(rig.hw.fault(), None);
    let ev = rig.drain_events();
    assert_eq!(ev.len(), 1);
    assert_eq!(ev[0].kind, EventKind::Attached);
    assert_eq!((ev[0].slot, ev[0].root_port, ev[0].vid_pid), (slot, 2, 0x0781_5567));
}

#[test]
fn full_speed_device_gets_its_real_ep0_size() {
    let mut rig = Rig::new();
    let kb = keyboard();
    kb.borrow_mut().dev_desc[7] = 64;
    rig.hw.attach_root(1, kb.clone());
    rig.settle();
    let s = rig.slot_of(&kb) as usize;
    // The controller was told 8, the device said 64, Evaluate Context fixed it.
    assert!(rig.hw.commands().contains(&13), "no Evaluate Context");
    assert_eq!(rig.hw.ep_info(s, 1).1, 64);
}

#[test]
fn superspeed_device_uses_the_exponent_form_of_ep0_size() {
    let mut rig = Rig::new();
    let d = ss_drive();
    rig.hw.attach_root(3, d.clone());
    rig.settle();
    let s = rig.slot_of(&d);
    let dev = rig.usb.device(s).unwrap();
    assert_eq!(dev.desc.ep0_mps(), 512);
    assert!(dev.bos.unwrap().superspeed);
    assert_eq!(rig.hw.ep_info(s as usize, 1).1, 512);
    assert!(dev.config.interfaces()[0].endpoints()[0].has_companion);
}

#[test]
fn a_device_that_fails_enumeration_frees_its_slot() {
    let mut rig = Rig::new();
    let bad = stick();
    bad.borrow_mut().fail_everything = true;
    rig.hw.attach_root(1, bad);
    rig.settle();
    assert_eq!(rig.usb.devices().count(), 0);
    assert_eq!(rig.hw.enabled_slots(), 0, "the slot of a failed device stays enabled");
    assert_eq!(rig.usb.stats().failed, 1);
    // The next device is not held back.
    let kb = keyboard();
    rig.hw.attach_root(2, kb.clone());
    rig.settle();
    assert_eq!(ids(&rig, &kb), (0x046d, 0xc31c));
}

#[test]
fn a_device_that_stalls_bos_still_enumerates() {
    let mut rig = Rig::new();
    let st = stick();
    st.borrow_mut().bos = None; // GET_DESCRIPTOR(BOS) stalls
    rig.hw.attach_root(1, st.clone());
    rig.settle();
    let s = rig.slot_of(&st);
    assert!(rig.usb.device(s).unwrap().bos.is_none());
    // The stall halted endpoint 0; the core reset it and went on.
    let cmds = rig.hw.commands();
    assert!(cmds.contains(&14) && cmds.contains(&16), "endpoint not recovered: {cmds:?}");
    assert_eq!(rig.usb.device(s).unwrap().product.as_str(), "Cruzer Blade");
}

#[test]
fn unplug_removes_the_device() {
    let mut rig = Rig::new();
    let st = stick();
    rig.hw.attach_root(1, st.clone());
    rig.settle();
    let slot = rig.slot_of(&st);
    rig.drain_events();
    rig.hw.detach_root(1);
    rig.settle();
    assert_eq!(rig.usb.devices().count(), 0, "the device stays in the table");
    assert!(!rig.hw.slot_enabled(slot as usize));
    let ev = rig.drain_events();
    assert_eq!(ev.len(), 1);
    assert_eq!((ev[0].kind, ev[0].slot), (EventKind::Detached, slot));
    assert_eq!(rig.lister.0.present(), 0);
    assert_eq!(rig.usb.stats().detached, 1);
}

#[test]
fn replug_is_a_new_generation_and_old_claims_are_dead() {
    let mut rig = Rig::new();
    rig.add_driver(Match::interface_class(8), true);
    rig.hw.attach_root(1, stick());
    rig.settle();
    let slot = rig.usb.devices().next().unwrap().slot;
    let old = rig.claim(slot, 0);
    rig.hw.detach_root(1);
    rig.settle();
    rig.hw.attach_root(1, stick());
    rig.settle();
    let d = rig.usb.devices().next().unwrap();
    assert_eq!(d.slot, slot, "the controller reuses the slot");
    assert_ne!(d.generation, old.generation());
    assert_eq!(rig.usb.open_pipe(old, 0x81), Err(OpenError::NoDevice));
}

#[test]
fn port_changes_that_are_not_a_connection_start_no_enumeration() {
    let mut rig = Rig::new();
    let st = stick();
    rig.hw.attach_root(1, st.clone());
    rig.settle();
    let cmds = rig.hw.commands().len();
    // Link state change (PLC), over-current change (OCC), reset change (PRC)
    // events: acknowledged, and nothing else happens.
    for bits in [1 << 22, 1 << 20, 1 << 21] {
        rig.hw.poke_port(1, bits);
        rig.settle();
    }
    assert_eq!(rig.hw.commands().len(), cmds, "the controller was asked for something");
    assert_eq!(rig.usb.devices().count(), 1);
    assert_eq!(rig.usb.stats().enumerated, 1);
    assert_eq!(ids(&rig, &st), (0x0781, 0x5567));
}

#[test]
fn the_controller_running_out_of_slots_fails_the_device_not_the_driver() {
    let mut rig = Rig::with(Config { max_slots: 2, ..cfg() });
    let (a, b, c) = (keyboard(), stick(), keyboard());
    rig.hw.attach_root(1, a.clone());
    rig.hw.attach_root(2, b.clone());
    rig.hw.attach_root(3, c.clone());
    rig.settle();
    assert_eq!(rig.usb.devices().count(), 2);
    assert_eq!(rig.usb.stats().failed, 1);
    assert!(rig.hw.slot_of(&c).is_none());
    // The slot a removal frees takes the next device.
    rig.hw.detach_root(1);
    rig.settle();
    rig.hw.detach_root(3);
    rig.hw.attach_root(3, keyboard());
    rig.settle();
    assert_eq!(rig.usb.devices().count(), 2);
}

#[test]
fn hot_plug_events_wait_for_a_reader_and_keep_their_order() {
    let mut rig = Rig::new();
    // 12 plugs and unplugs make 24 events: more than the queue holds.
    for _ in 0..12 {
        rig.hw.attach_root(1, keyboard());
        rig.settle();
        rig.hw.detach_root(1);
        rig.settle();
    }
    let mut got = Vec::new();
    // Reading makes room; the held events follow on the next services.
    for _ in 0..8 {
        got.extend(rig.drain_events());
        rig.run(2);
    }
    let kinds: Vec<_> = got.iter().map(|e| e.kind).collect();
    // Whatever was delivered alternates attach, detach, in order.
    assert!(kinds.windows(2).all(|w| w[0] != w[1]), "out of order: {kinds:?}");
    assert_eq!(kinds[0], EventKind::Attached);
    assert_eq!(got.len() as u32 + rig.usb.stats().events_lost, 24);
}

// ---- Hubs ----

#[test]
fn full_speed_device_behind_a_high_speed_hub_uses_its_translator() {
    let mut rig = Rig::new();
    let h = hub_device(false, 4, 3, false);
    rig.hw.attach_root(1, h.clone());
    rig.settle();
    let hub_slot = rig.slot_of(&h);
    {
        let sc = rig.hw.slot_ctx(hub_slot as usize);
        assert_ne!(sc[0] & (1 << 26), 0, "the slot context does not say hub");
        assert_eq!(sc[1] >> 24, 4, "port count");
        assert_eq!(sc[0] & (1 << 25), 0, "MTT on a single-TT hub");
    }
    let kb = keyboard();
    rig.hw.hub_attach(&h, 3, kb.clone());
    rig.settle();
    let kb_slot = rig.slot_of(&kb);
    let sc = rig.hw.slot_ctx(kb_slot as usize);
    assert_eq!(sc[0] & 0xf_ffff, 3, "route string");
    assert_eq!(sc[2] & 0xff, hub_slot as u32, "TT hub slot");
    assert_eq!((sc[2] >> 8) & 0xff, 3, "TT port");
    assert_eq!((sc[1] >> 16) & 0xff, 1, "root port");
    assert_eq!(ids(&rig, &kb), (0x046d, 0xc31c));
    // The hub's ports were powered.
    let powered = h.borrow().hub.as_ref().unwrap().ports.iter().filter(|p| p.powered).count();
    assert_eq!(powered, 4);
}

#[test]
fn device_already_plugged_into_a_hub_is_found_at_power_on() {
    let mut rig = Rig::new();
    let h = hub_device(false, 4, 3, false);
    let st = stick();
    // Plugged in before the hub is even enumerated.
    {
        let mut hb = h.borrow_mut();
        let hm = hb.hub.as_mut().unwrap();
        hm.children[1] = Some(st.clone());
        hm.ports[1].connected = true;
        hm.ports[1].high = true;
        hm.ports[1].change = 1;
    }
    rig.hw.attach_root(1, h);
    rig.settle();
    assert_eq!(ids(&rig, &st), (0x0781, 0x5567));
}

#[test]
fn multi_tt_hub_says_so_in_the_slot_context() {
    let mut rig = Rig::new();
    let h = hub_device(false, 2, 3, true);
    rig.hw.attach_root(1, h.clone());
    rig.settle();
    let sc = rig.hw.slot_ctx(rig.slot_of(&h) as usize);
    assert_ne!(sc[0] & (1 << 25), 0, "MTT");
}

#[test]
fn route_string_names_the_hub_ports() {
    let mut rig = Rig::new();
    let a = hub_device(false, 4, 3, false);
    let b = hub_device(false, 4, 3, false);
    let st = stick();
    rig.hw.attach_root(1, a.clone());
    rig.settle();
    rig.hw.hub_attach(&a, 2, b.clone());
    rig.settle();
    rig.hw.hub_attach(&b, 4, st.clone());
    rig.settle();
    let sb = rig.hw.slot_ctx(rig.slot_of(&b) as usize);
    let ss = rig.hw.slot_ctx(rig.slot_of(&st) as usize);
    assert_eq!(sb[0] & 0xf_ffff, 0x2, "hub B is on port 2 of hub A");
    assert_eq!(ss[0] & 0xf_ffff, 0x42, "the stick is on port 4 of hub B, which is on port 2 of hub A");
    assert_eq!(ids(&rig, &st), (0x0781, 0x5567));
    assert_eq!(rig.usb.device(rig.slot_of(&st)).unwrap().tier, 2);
}

#[test]
fn superspeed_hub_is_told_its_depth() {
    let mut rig = Rig::new();
    let a = hub_device(true, 4, 4, false);
    let b = hub_device(true, 4, 4, false);
    let d = ss_drive();
    rig.hw.attach_root(1, a.clone());
    rig.settle();
    rig.hw.hub_attach(&a, 1, b.clone());
    rig.settle();
    rig.hw.hub_attach(&b, 3, d.clone());
    rig.settle();
    assert_eq!(a.borrow().hub.as_ref().unwrap().depth, Some(0));
    assert_eq!(b.borrow().hub.as_ref().unwrap().depth, Some(1));
    assert_eq!(rig.hw.slot_ctx(rig.slot_of(&d) as usize)[0] & 0xf_ffff, 0x31);
    assert_eq!(ids(&rig, &d), (0x1058, 0x2621));
}

#[test]
fn unplugging_a_hub_removes_what_hangs_below_it() {
    let mut rig = Rig::new();
    let a = hub_device(false, 4, 3, false);
    let b = hub_device(false, 4, 3, false);
    rig.hw.attach_root(1, a.clone());
    rig.settle();
    rig.hw.hub_attach(&a, 1, b.clone());
    rig.settle();
    rig.hw.hub_attach(&b, 2, keyboard());
    rig.hw.hub_attach(&b, 3, stick());
    rig.settle();
    assert_eq!(rig.usb.devices().count(), 4);
    rig.drain_events();
    rig.hw.detach_root(1);
    rig.settle();
    assert_eq!(rig.usb.devices().count(), 0);
    assert_eq!(rig.hw.enabled_slots(), 0);
    let ev = rig.drain_events();
    assert_eq!(ev.iter().filter(|e| e.kind == EventKind::Detached).count(), 4);
    // Children go before their parents.
    assert_eq!(ev.last().unwrap().vid_pid >> 16, 0x05e3);
}

#[test]
fn unplugging_one_device_from_a_hub_leaves_the_rest() {
    let mut rig = Rig::new();
    let h = hub_device(false, 4, 3, false);
    let (kb, st) = (keyboard(), stick());
    rig.hw.attach_root(1, h.clone());
    rig.settle();
    rig.hw.hub_attach(&h, 1, kb.clone());
    rig.hw.hub_attach(&h, 2, st.clone());
    rig.settle();
    assert_eq!(rig.usb.devices().count(), 3);
    rig.hw.hub_detach(&h, 1);
    rig.settle();
    assert_eq!(rig.usb.devices().count(), 2);
    assert!(rig.hw.slot_of(&kb).is_none());
    assert_eq!(ids(&rig, &st), (0x0781, 0x5567));
    // And the port takes a new device.
    let kb2 = keyboard();
    rig.hw.hub_attach(&h, 1, kb2.clone());
    rig.settle();
    assert_eq!(ids(&rig, &kb2), (0x046d, 0xc31c));
}

#[test]
fn a_hub_nested_too_deep_is_refused() {
    let mut rig = Rig::new();
    let mut parent = hub_device(false, 2, 3, false);
    rig.hw.attach_root(1, parent.clone());
    rig.settle();
    // Five hubs below the root are the most the route string addresses; the
    // sixth is refused and the device it carried never appears.
    for _ in 0..5 {
        let next = hub_device(false, 2, 3, false);
        rig.hw.hub_attach(&parent, 1, next.clone());
        rig.settle();
        parent = next;
    }
    let before = rig.usb.stats().failed;
    let st = stick();
    rig.hw.hub_attach(&parent, 1, st.clone());
    rig.settle();
    assert!(rig.hw.slot_of(&st).is_none());
    assert!(rig.usb.stats().failed > before);
}

// ---- Pipes ----

fn xfer(tag: u32, dir: Dir, buf: u64, len: u32) -> Transfer {
    Transfer { tag, dir, setup: [0; 8], buf, len }
}

fn ctl(tag: u32, setup: Setup, buf: u64, len: u32) -> Transfer {
    Transfer { tag, dir: Dir::In, setup: setup.to_bytes(), buf, len }
}

/// A rig with a stick attached and a driver on each of its interfaces.
fn with_stick() -> (Rig, DevRef, u8, [usize; 2]) {
    let mut rig = Rig::new();
    let d0 = rig.add_driver(Match::interface_class(8), true);
    let d1 = rig.add_driver(Match::interface_class(0xff), true);
    let st = stick();
    rig.hw.attach_root(1, st.clone());
    rig.settle();
    let slot = rig.slot_of(&st);
    (rig, st, slot, [d0, d1])
}

#[test]
fn drivers_are_offered_the_interfaces_they_match() {
    let (rig, _, slot, [d0, d1]) = with_stick();
    let a = &rig.driver(d0).attached;
    assert_eq!(a.len(), 1);
    assert_eq!(Claim(a[0].0), rig.claim(slot, 0));
    assert_eq!(a[0].1, 0x0781_5567);
    assert_eq!(a[0].2, 8 << 16 | 6 << 8 | 0x50);
    assert_eq!(a[0].3, 3 << 8 | 1, "high speed on root port 1");
    let b = &rig.driver(d1).attached;
    assert_eq!(Claim(b[0].0), rig.claim(slot, 1));
}

#[test]
fn a_driver_that_declines_is_skipped() {
    let mut rig = Rig::new();
    let no = rig.add_driver(Match::interface_class(8), false);
    let yes = rig.add_driver(Match::interface_class(8), true);
    rig.hw.attach_root(1, stick());
    rig.settle();
    assert!(rig.driver(no).attached.is_empty());
    assert_eq!(rig.driver(yes).attached.len(), 1);
    // The claim is the second driver's: it can open the interface's pipes.
    let claim = Claim(rig.driver(yes).attached[0].0);
    assert!(rig.usb.open_pipe(claim, 0x81).is_ok());
}

#[test]
fn a_watcher_and_a_driver_both_attach_and_both_hear_of_the_unplug() {
    let mut rig = Rig::new();
    let w = rig.add_driver(Match::every_device(), true);
    let d = rig.add_driver(Match::interface_class(8), true);
    rig.hw.attach_root(1, stick());
    rig.settle();
    assert_eq!(rig.lister.0.present(), 1);
    assert_eq!(rig.driver(w).attached.len(), 1);
    assert!(Claim(rig.driver(w).attached[0].0).is_device_scope());
    assert_eq!(rig.driver(d).attached.len(), 1);
    rig.hw.detach_root(1);
    rig.settle();
    assert_eq!(rig.driver(w).detached.len(), 1);
    assert_eq!(rig.driver(d).detached.len(), 1);
    assert_eq!(rig.lister.0.present(), 0);
}

#[test]
fn interrupt_in_pipe_round_trip() {
    let mut rig = Rig::new();
    let d = rig.add_driver(Match::interface_class(3), true);
    let kb = keyboard();
    rig.hw.attach_root(1, kb.clone());
    rig.settle();
    let slot = rig.slot_of(&kb);
    let claim = Claim(rig.driver(d).attached[0].0);
    let id = rig.usb.open_pipe(claim, 0x81).unwrap();
    // The controller holds a full speed interrupt IN endpoint: DCI 3, 8-byte
    // packets, 10 ms (2^6 x 125 us).
    assert_eq!(rig.hw.ep_info(slot as usize, 3), (7, 8, 6, 1));
    let mut end = rig.pipe_end(id);
    let buf = rig.buffer(4096);
    assert!(matches!(end.sq.push(xfer(7, Dir::In, buf.bus(), 8)), Push::Pushed));
    rig.service();
    assert!(end.cq.pop().is_none(), "completed with no data");
    rig.hw.inject_in(&kb, 1, &[0, 0, 4, 0, 0, 0, 0, 0]);
    rig.service();
    assert_eq!(end.cq.pop(), Some(Completion { tag: 7, status: Status::Ok, actual: 8 }));
    let mut got = [0u8; 8];
    buf.read_bytes(0, &mut got);
    assert_eq!(got, [0, 0, 4, 0, 0, 0, 0, 0]);
}

#[test]
fn bulk_out_and_in_with_a_short_packet() {
    let (mut rig, st, slot, _) = with_stick();
    let claim = rig.claim(slot, 0);
    let pin = rig.usb.open_pipe(claim, 0x81).unwrap();
    let pout = rig.usb.open_pipe(claim, 0x02).unwrap();
    assert_eq!(rig.hw.ep_info(slot as usize, 3).0, 6, "bulk IN");
    assert_eq!(rig.hw.ep_info(slot as usize, 4).0, 2, "bulk OUT");
    let (mut ein, mut eout) = (rig.pipe_end(pin), rig.pipe_end(pout));
    let buf = rig.buffer(8192);
    let payload: Vec<u8> = (0..100u8).collect();
    buf.write_bytes(0, &payload);
    assert!(matches!(eout.sq.push(xfer(1, Dir::Out, buf.bus(), 100)), Push::Pushed));
    rig.service();
    assert_eq!(eout.cq.pop(), Some(Completion { tag: 1, status: Status::Ok, actual: 100 }));
    assert_eq!(st.borrow().out_log, vec![(2, payload.clone())]);
    // The device answers with 100 bytes to a request for 512: a short packet.
    assert!(matches!(ein.sq.push(xfer(2, Dir::In, buf.bus_at(4096), 512)), Push::Pushed));
    rig.service();
    rig.hw.inject_in(&st, 1, &payload);
    rig.service();
    assert_eq!(ein.cq.pop(), Some(Completion { tag: 2, status: Status::Ok, actual: 100 }));
    let mut got = vec![0u8; 100];
    buf.read_bytes(4096, &mut got);
    assert_eq!(got, payload);
}

#[test]
fn transfer_across_a_64k_boundary_is_split() {
    let (mut rig, st, slot, _) = with_stick();
    let claim = rig.claim(slot, 0);
    let pout = rig.usb.open_pipe(claim, 0x02).unwrap();
    let mut eout = rig.pipe_end(pout);
    let region = rig.buffer(256 * 1024);
    // A buffer that starts 2 KiB below a 64 KiB boundary and runs 4 KiB past it.
    let boundary = (region.bus() + 0xffff) & !0xffff;
    let start = boundary - 0x800;
    let off = (start - region.bus()) as usize;
    let payload: Vec<u8> = (0..6144u32).map(|i| (i % 251) as u8).collect();
    region.write_bytes(off, &payload);
    assert!(matches!(eout.sq.push(xfer(9, Dir::Out, start, 6144)), Push::Pushed));
    rig.service();
    assert_eq!(eout.cq.pop(), Some(Completion { tag: 9, status: Status::Ok, actual: 6144 }), "events: {:?}", rig.hw.xfer_events());
    assert_eq!(st.borrow().out_log[0].1, payload);
}

#[test]
fn stall_on_a_bulk_pipe_is_reported_and_the_pipe_recovers() {
    let (mut rig, st, slot, _) = with_stick();
    let claim = rig.claim(slot, 0);
    let pout = rig.usb.open_pipe(claim, 0x02).unwrap();
    let mut eout = rig.pipe_end(pout);
    let buf = rig.buffer(4096);
    rig.hw.inject_error(slot as usize, 4, 6);
    assert!(matches!(eout.sq.push(xfer(1, Dir::Out, buf.bus(), 64)), Push::Pushed));
    rig.service();
    let c = eout.cq.pop().expect("completion");
    assert_eq!((c.tag, c.status), (1, Status::Stall));
    // The endpoint was reset and its dequeue pointer moved: it takes more.
    let cmds = rig.hw.commands();
    assert!(cmds.ends_with(&[14, 16]), "no Reset Endpoint + Set TR Dequeue: {cmds:?}");
    assert_eq!(rig.hw.ep_info(slot as usize, 4).3, 1, "endpoint not running again");
    assert!(matches!(eout.sq.push(xfer(2, Dir::Out, buf.bus(), 64)), Push::Pushed));
    rig.service();
    assert_eq!(eout.cq.pop(), Some(Completion { tag: 2, status: Status::Ok, actual: 64 }));
    assert_eq!(st.borrow().out_log.len(), 1, "the failed transfer reached the device");
}

#[test]
fn a_device_that_sends_too_much_is_a_babble() {
    let mut rig = Rig::new();
    let d = rig.add_driver(Match::interface_class(3), true);
    let kb = keyboard();
    rig.hw.attach_root(1, kb.clone());
    rig.settle();
    let claim = Claim(rig.driver(d).attached[0].0);
    let id = rig.usb.open_pipe(claim, 0x81).unwrap();
    let mut end = rig.pipe_end(id);
    let buf = rig.buffer(4096);
    assert!(matches!(end.sq.push(xfer(1, Dir::In, buf.bus(), 8)), Push::Pushed));
    rig.service();
    rig.hw.inject_in(&kb, 1, &[0xaa; 16]);
    rig.service();
    assert_eq!(end.cq.pop().map(|c| c.status), Some(Status::Babble));
    // The pipe is usable again after the controller's reset of the endpoint.
    assert!(matches!(end.sq.push(xfer(2, Dir::In, buf.bus(), 8)), Push::Pushed));
    rig.service();
    rig.hw.inject_in(&kb, 1, &[1; 8]);
    rig.service();
    assert_eq!(end.cq.pop().map(|c| (c.tag, c.status, c.actual)), Some((2, Status::Ok, 8)));
}

#[test]
fn transaction_error_is_reported_as_such() {
    let (mut rig, _, slot, _) = with_stick();
    let claim = rig.claim(slot, 0);
    let pin = rig.usb.open_pipe(claim, 0x81).unwrap();
    let mut ein = rig.pipe_end(pin);
    let buf = rig.buffer(4096);
    rig.hw.inject_error(slot as usize, 3, 4);
    assert!(matches!(ein.sq.push(xfer(5, Dir::In, buf.bus(), 512)), Push::Pushed));
    rig.service();
    assert_eq!(ein.cq.pop().map(|c| c.status), Some(Status::Transaction));
}

#[test]
fn control_requests_are_confined_to_the_claimed_interface() {
    let (mut rig, _, slot, _) = with_stick();
    let claim = rig.claim(slot, 0);
    let id = rig.usb.open_pipe(claim, 0).unwrap();
    let mut end = rig.pipe_end(id);
    let buf = rig.buffer(4096);
    let class_in = |index: u16| Setup { request_type: 0xa1, request: 0xfe, value: 0, index, length: 1 };
    let cases: [(Setup, Status); 5] = [
        (class_in(0), Status::Ok),
        // The other interface's.
        (class_in(1), Status::Denied),
        // A device-wide standard request.
        (Setup::set_configuration(0), Status::Denied),
        // A hub-style class request to the device.
        (Setup::hub_class(true, 0, 0, 1, 4, 3), Status::Denied),
        (Setup::get_descriptor(1, 0, 0, 18), Status::Ok),
    ];
    for (i, (setup, want)) in cases.iter().enumerate() {
        assert!(matches!(end.sq.push(ctl(i as u32, *setup, buf.bus(), 64)), Push::Pushed));
        rig.service();
        let c = end.cq.pop().unwrap_or_else(|| panic!("case {i}: no completion"));
        assert_eq!(c.status, *want, "case {i}");
    }
    let mut b = [0u8; 1];
    // The first request's answer (the mock echoes the request number).
    assert!(matches!(end.sq.push(ctl(9, class_in(0), buf.bus(), 64)), Push::Pushed));
    rig.service();
    assert_eq!(end.cq.pop().map(|c| c.actual), Some(1));
    buf.read_bytes(0, &mut b);
    assert_eq!(b[0], 0xfe);
}

#[test]
fn opening_endpoints_outside_the_claim_is_denied() {
    let (mut rig, _, slot, _) = with_stick();
    let claim0 = rig.claim(slot, 0);
    // Endpoint 3 belongs to interface 1.
    assert_eq!(rig.usb.open_pipe(claim0, 0x83), Err(OpenError::Denied));
    // An endpoint the device does not have.
    assert_eq!(rig.usb.open_pipe(claim0, 0x85), Err(OpenError::Denied));
    // A device-scope claim holds no interface.
    let w = Claim::new(slot, azos_usb::class::WHOLE_DEVICE, claim0.generation());
    assert_eq!(rig.usb.open_pipe(w, 0x81), Err(OpenError::Denied));
    // An interface nobody took.
    let mut rig2 = Rig::new();
    rig2.hw.attach_root(1, stick());
    rig2.settle();
    let s2 = rig2.usb.devices().next().unwrap().slot;
    assert_eq!(rig2.usb.open_pipe(rig2.claim(s2, 0), 0x81), Err(OpenError::Denied));
    // The same endpoint twice.
    let _ = rig.usb.open_pipe(claim0, 0x81).unwrap();
    assert_eq!(rig.usb.open_pipe(claim0, 0x81), Err(OpenError::Busy));
}

#[test]
fn a_buffer_the_controller_cannot_reach_is_refused() {
    let mut rig = Rig::with(Config { ac64: false, ..cfg() });
    let d = rig.add_driver(Match::interface_class(3), true);
    rig.hw.attach_root(1, keyboard());
    rig.settle();
    let claim = Claim(rig.driver(d).attached[0].0);
    let id = rig.usb.open_pipe(claim, 0x81).unwrap();
    let mut end = rig.pipe_end(id);
    assert!(matches!(end.sq.push(xfer(1, Dir::In, 0x1_0000_0000, 8)), Push::Pushed));
    rig.service();
    assert_eq!(end.cq.pop().map(|c| c.status), Some(Status::Bounce));
    assert_eq!(rig.hw.fault(), None);
}

#[test]
fn unplug_completes_outstanding_transfers_as_disconnected() {
    let mut rig = Rig::new();
    let d = rig.add_driver(Match::interface_class(3), true);
    rig.hw.attach_root(1, keyboard());
    rig.settle();
    let claim = Claim(rig.driver(d).attached[0].0);
    let id = rig.usb.open_pipe(claim, 0x81).unwrap();
    let mut end = rig.pipe_end(id);
    let buf = rig.buffer(4096);
    assert!(matches!(end.sq.push(xfer(3, Dir::In, buf.bus(), 8)), Push::Pushed));
    rig.service();
    rig.hw.detach_root(1);
    rig.settle();
    assert_eq!(end.cq.pop(), Some(Completion { tag: 3, status: Status::Disconnected, actual: 0 }));
    assert_eq!(rig.driver(d).detached, vec![claim.0]);
    assert!(!rig.usb.pipe_in_use(id), "the pipe outlives its device");
}

#[test]
fn closing_a_pipe_drops_its_endpoint_and_it_can_be_reopened() {
    let (mut rig, _, slot, _) = with_stick();
    let claim = rig.claim(slot, 0);
    let id = rig.usb.open_pipe(claim, 0x81).unwrap();
    assert_eq!(rig.hw.ep_info(slot as usize, 3).3, 1);
    // Another claim cannot close it.
    assert!(rig.usb.close_pipe(rig.claim(slot, 1), id).is_err());
    rig.usb.close_pipe(claim, id).unwrap();
    assert_eq!(rig.hw.ep_info(slot as usize, 3).3, 0, "endpoint still configured");
    assert_eq!(rig.usb.open_pipe(claim, 0x81), Ok(id));
}

#[test]
fn outstanding_transfers_never_exceed_the_ring_depth() {
    let mut rig = Rig::new();
    let d = rig.add_driver(Match::interface_class(3), true);
    let kb = keyboard();
    rig.hw.attach_root(1, kb.clone());
    rig.settle();
    let claim = Claim(rig.driver(d).attached[0].0);
    let id = rig.usb.open_pipe(claim, 0x81).unwrap();
    let mut end = rig.pipe_end(id);
    let buf = rig.buffer(4096);
    let depth = azos_usb::PIPE_DEPTH;
    // Fill the submission ring, then keep feeding data: every transfer
    // completes exactly once and none is lost.
    let mut next = 0u32;
    let mut done = Vec::new();
    for _ in 0..4 * depth {
        while let Push::Pushed = end.sq.push(xfer(next, Dir::In, buf.bus(), 8)) {
            next += 1;
        }
        rig.service();
        rig.hw.inject_in(&kb, 1, &[1; 8]);
        rig.service();
        while let Some(c) = end.cq.pop() {
            assert_eq!(c.status, Status::Ok);
            done.push(c.tag);
        }
    }
    assert!(done.len() >= 4 * depth - depth, "only {} completions", done.len());
    assert!(done.windows(2).all(|w| w[1] == w[0] + 1), "out of order: {done:?}");
    assert_eq!(rig.usb.stats().completions_lost, 0);
}

// ---- The class-driver interface over the wire, and the listing ----

struct Loop<F: Fn(&MsgDesc, &mut MsgDesc) -> azos_idl::Result>(F);

impl<F: Fn(&MsgDesc, &mut MsgDesc) -> azos_idl::Result> Transport for Loop<F> {
    fn call(&self, msg: &mut MsgDesc) -> azos_idl::Result {
        let req = *msg;
        let mut reply = MsgDesc::default();
        (self.0)(&req, &mut reply)?;
        *msg = reply;
        Ok(())
    }
}

#[test]
fn the_class_interface_carries_attach_and_detach_over_messages() {
    let lister = RefCell::new(azos_usb::listing::Lister::new());
    let mut client = UsbClassClient::new(Loop(|req, reply| UsbClassIdl::dispatch(&mut *lister.borrow_mut(), req, reply)));
    let claim = Claim::new(3, azos_usb::class::WHOLE_DEVICE, 1);
    let out = client.attach(claim.0, 0x1234_5678, 9 << 16, 3 << 8 | 1).unwrap();
    assert_eq!(out.code, 0);
    let l = lister.borrow();
    let r = l.rows()[2];
    assert!(r.present);
    assert_eq!((r.vendor, r.product, r.class, r.speed, r.root_port), (0x1234, 0x5678, 9, 3, 1));
}

#[test]
fn the_device_interface_serves_one_claim_over_messages() {
    let (mut rig, _, slot, _) = with_stick();
    let claim = rig.claim(slot, 0);
    let session = RefCell::new(rig.usb.session(claim));
    let mut c = UsbDeviceClient::new(Loop(|req, reply| UsbDeviceIdl::dispatch(&mut *session.borrow_mut(), req, reply)));
    // vendor and product, the interface's class triple, its endpoint count.
    assert_eq!(c.info(0).unwrap().value, 0x0781_5567);
    assert_eq!(c.info(1).unwrap().value, 8 << 16 | 6 << 8 | 0x50);
    assert_eq!(c.info(4).unwrap().value, 2);
    // Endpoint 0 of the interface is 0x81, bulk, 512 bytes.
    let e = c.endpoint(0).unwrap().value;
    assert_eq!((e & 0xff, (e >> 8) & 0xff, (e >> 16) & 0xffff), (0x81, 2, 512));
    assert_eq!(c.endpoint(5).unwrap().code, azos_devif::outcome::BAD_ARGUMENT);
    // Pipes: the other interface's endpoint is refused, ours opens and closes.
    assert_eq!(c.pipe_open(0x83).unwrap().code, azos_devif::outcome::DENIED);
    let p = c.pipe_open(0x81).unwrap();
    assert_eq!(p.code, azos_devif::outcome::OK);
    assert_eq!(c.pipe_close(p.value).unwrap().code, azos_devif::outcome::OK);
    assert_eq!(c.pipe_close(p.value).unwrap().code, azos_devif::outcome::NO_RESOURCE);
}

#[test]
fn lsusb_listing_is_published_through_the_inspection_tree() {
    use azos_inspect::{Class, NodeId, Reader, Region, Value, Writer};
    use std::sync::atomic::AtomicU64;

    let mut rig = Rig::new();
    let h = hub_device(false, 4, 3, false);
    let (kb, st) = (keyboard(), stick());
    rig.hw.attach_root(2, h.clone());
    rig.settle();
    rig.hw.hub_attach(&h, 1, kb.clone());
    rig.hw.hub_attach(&h, 2, st.clone());
    rig.settle();

    let words: Vec<AtomicU64> = (0..(64 * 1024) / 8).map(|_| AtomicU64::new(0)).collect();
    let region = unsafe { Region::from_raw(words.as_ptr() as *const u8, words.len() * 8) }.unwrap();
    let w = Writer::init(region, Class::Public).unwrap();
    let mut tree = None;
    w.rebuild(|b| {
        tree = Some(azos_usb::listing::build(b, NodeId::ROOT)?);
        Ok(())
    })
    .unwrap();
    let tree = tree.unwrap();
    assert_eq!(azos_usb::listing::refresh(&w, &tree, &rig.lister.0), 0);

    let r = Reader::open(region, Class::Public).unwrap();
    let get = |path: &str| match r.read(r.lookup(path).unwrap().unwrap()).unwrap() {
        Value::U64(v) => v,
        _ => panic!("{path} is not a u64"),
    };
    assert_eq!(get("usb/devices"), 3);
    let (hs, ks, ss) = (rig.slot_of(&h) as usize - 1, rig.slot_of(&kb) as usize - 1, rig.slot_of(&st) as usize - 1);
    assert_eq!(get(&format!("usb/dev{hs}/class")), 9);
    assert_eq!(get(&format!("usb/dev{ks}/vendor")), 0x046d);
    assert_eq!(get(&format!("usb/dev{ks}/product")), 0xc31c);
    assert_eq!(get(&format!("usb/dev{ks}/speed")), 1);
    assert_eq!(get(&format!("usb/dev{ss}/vendor")), 0x0781);
    assert_eq!(get(&format!("usb/dev{ss}/speed")), 3);
    assert_eq!(get(&format!("usb/dev{ss}/root_port")), 2);
    // An empty slot reads as absent.
    let free = (0..azos_usb::MAX_DEVICES).find(|i| ![hs, ks, ss].contains(i)).unwrap();
    assert_eq!(get(&format!("usb/dev{free}/present")), 0);

    // An unplug rewrites values in the same tree.
    rig.hw.hub_detach(&h, 1);
    rig.settle();
    assert_eq!(azos_usb::listing::refresh(&w, &tree, &rig.lister.0), 0);
    assert_eq!(get("usb/devices"), 2);
    assert_eq!(get(&format!("usb/dev{ks}/present")), 0);
}

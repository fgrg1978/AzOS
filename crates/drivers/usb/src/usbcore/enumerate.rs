// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Device bring-up and removal: port reset, Enable Slot, Address Device, the
//! descriptors, SET_CONFIGURATION, the offer to the class drivers; and the
//! reverse.

use super::desc::{self, Setup, DT_BOS, DT_CONFIG, DT_DEVICE, DT_STRING};
use super::{Device, Text, Usb, UsbError, MAX_TIERS};
use crate::class::{Claim, Registry, Scope, WHOLE_DEVICE};
use crate::event::EventKind;
use crate::hw::{Clock, Memory, Regs};
use crate::xhci::context::SlotParams;
use crate::xhci::regs::{self as hwregs, Speed};
use azos_devif::outcome::OK;

/// A connection must hold this long before the port is reset (USB 2.0,
/// 7.1.7.3: TATTDB).
const DEBOUNCE_US: u32 = 100_000;
/// A port reset gets this long to complete.
const RESET_TIMEOUT_US: u64 = 500_000;
/// Recovery after a reset before the device is addressed (TRSTRCY).
const RESET_RECOVERY_US: u32 = 10_000;
/// A USB 3 port gets this long after a reset to train its link.
const LINK_TIMEOUT_US: u64 = 200_000;
/// A device gets this long to settle after Address Device before its first
/// control request (USB 2.0 TSETADDR is 50 ms at most; 10 ms is what hosts use).
const SET_ADDRESS_RECOVERY_US: u32 = 10_000;
/// Configuration descriptor bytes read at most.
const CONFIG_MAX: usize = 1024;

impl<'q, R: Regs, M: Memory, C: Clock> Usb<'q, R, M, C> {
    /// A root port changed: remove what left, enumerate what arrived.
    pub(crate) fn root_port_event(&mut self, reg: &mut Registry<'_>, port: u8) {
        let st = self.hc.port_status(port);
        let ch = st.changes();
        if ch != 0 {
            self.hc.port_ack(port, ch);
        }
        let child = self.root_dev[port as usize - 1];
        let connect_change = ch & hwregs::PORTSC_CSC != 0;
        if child != 0 && (!st.connected() || connect_change) {
            self.remove_device(reg, child);
        }
        if connect_change {
            self.mark_connect(port, true);
        }
        if !st.connected() {
            self.mark_connect(port, false);
            return;
        }
        // Only a connection nobody has tried yet is enumerated: the change
        // events of the reset itself, or of a link state, are not one.
        if self.root_dev[port as usize - 1] != 0 || !self.mark_connect(port, false) {
            return;
        }
        // Debounce: the connection must hold before the port is reset.
        self.hc.clock().delay_us(DEBOUNCE_US);
        let st2 = self.hc.port_status(port);
        if st2.changes() != 0 {
            self.hc.port_ack(port, st2.changes());
        }
        if !st2.connected() {
            return;
        }
        let speed = match self.reset_root_port(port) {
            Ok(s) => s,
            Err(_) => {
                self.stats.failed += 1;
                return;
            }
        };
        match self.enumerate(reg, None, port, speed) {
            Ok(slot) => self.root_dev[port as usize - 1] = slot,
            Err(_) => self.stats.failed += 1,
        }
    }

    fn reset_root_port(&mut self, port: u8) -> Result<Speed, UsbError> {
        self.hc.port_reset(port);
        let deadline = self.hc.clock().now_us() + RESET_TIMEOUT_US;
        loop {
            let st = self.hc.port_status(port);
            if st.0 & (hwregs::PORTSC_PRC | hwregs::PORTSC_WRC) != 0 {
                break;
            }
            if self.hc.clock().now_us() >= deadline {
                return Err(UsbError::Port);
            }
            self.hc.clock().delay_us(1_000);
        }
        // The reset's own change bits are acknowledged here; the events they
        // raised find nothing left to do.
        let st = self.hc.port_status(port);
        self.hc.port_ack(port, st.changes());
        if !st.connected() {
            return Err(UsbError::Port);
        }
        // A USB 3 port enables when its link trains; a USB 2 port with the reset.
        let deadline = self.hc.clock().now_us() + LINK_TIMEOUT_US;
        let mut st = self.hc.port_status(port);
        while !st.enabled() {
            if self.hc.clock().now_us() >= deadline {
                return Err(UsbError::Port);
            }
            self.hc.clock().delay_us(1_000);
            st = self.hc.port_status(port);
        }
        self.hc.clock().delay_us(RESET_RECOVERY_US);
        st.speed().ok_or(UsbError::Port)
    }

    /// Bring a device up to the point where it is configured and offered to
    /// the class drivers. `parent` is the hub slot and port the device is on,
    /// `None` for a root port. Returns the slot.
    pub(crate) fn enumerate(
        &mut self,
        reg: &mut Registry<'_>,
        parent: Option<(u8, u8)>,
        root_port: u8,
        speed: Speed,
    ) -> Result<u8, UsbError> {
        let mut route = 0u32;
        let mut tier = 0u8;
        let (mut tt_slot, mut tt_port) = (0u8, 0u8);
        if let Some((hub, port)) = parent {
            let h = self.device(hub).ok_or(UsbError::NoDevice)?;
            tier = h.tier + 1;
            if tier as usize > MAX_TIERS {
                return Err(UsbError::TooDeep);
            }
            #[cfg(not(feature = "canary-route"))]
            {
                route = h.route | (port.min(15) as u32) << (4 * h.tier as u32);
            }
            // A low or full speed device behind a high speed hub is served by
            // that hub's transaction translator; behind a full speed hub it
            // inherits the translator the hub itself uses.
            if speed <= Speed::Full {
                if h.speed == Speed::High {
                    (tt_slot, tt_port) = (h.slot, port);
                } else {
                    (tt_slot, tt_port) = (h.tt_slot, h.tt_port);
                }
            }
        }
        let slot = self.hc.enable_slot()?;
        let params = SlotParams {
            route,
            speed_psiv: speed.psiv(),
            root_port,
            tt_slot,
            tt_port,
            ..SlotParams::default()
        };
        if let Err(e) = self.hc.address_device(slot, params, speed.default_ep0_mps()) {
            let _ = self.hc.disable_slot(slot);
            return Err(e.into());
        }
        // The device answers at its new address after SET_ADDRESS recovery.
        self.hc.clock().delay_us(SET_ADDRESS_RECOVERY_US);
        let gen = self.next_generation(slot);
        let base = Device {
            slot,
            generation: gen,
            speed,
            root_port,
            parent: parent.map_or(0, |p| p.0),
            port: parent.map_or(root_port, |p| p.1),
            tier,
            route,
            tt_slot,
            tt_port,
            desc: desc::DeviceDesc::default(),
            config: desc::ConfigDesc::default(),
            bos: None,
            product: Text::EMPTY,
            manufacturer: Text::EMPTY,
            hub: None,
            owner: [0; desc::MAX_IFACES],
            watchers: [0; 4],
        };
        match self.read_device(slot, base) {
            Ok(dev) => {
                self.devices[slot as usize - 1] = Some(dev);
                if dev.desc.class == desc::CLASS_HUB {
                    if let Err(e) = self.hub_bring_up(slot) {
                        self.devices[slot as usize - 1] = None;
                        let _ = self.hc.disable_slot(slot);
                        return Err(e);
                    }
                }
                self.stats.enumerated += 1;
                let d = self.devices[slot as usize - 1].expect("just stored");
                self.emit(EventKind::Attached, &d);
                self.bind_classes(reg, slot);
                Ok(slot)
            }
            Err(e) => {
                let _ = self.hc.disable_slot(slot);
                Err(e)
            }
        }
    }

    /// The descriptors and the configuration of an addressed device.
    fn read_device(&mut self, slot: u8, mut d: Device) -> Result<Device, UsbError> {
        let mut buf = [0u8; 256];
        // The first 8 bytes give endpoint 0's real max packet size, which a
        // full speed device may have answered differently from the guess.
        let n = self.control(slot, Setup::get_descriptor(DT_DEVICE, 0, 0, 8), &[], &mut buf)?;
        if n < 8 || buf[1] != DT_DEVICE {
            return Err(desc::DescError::Truncated.into());
        }
        let mps0 = if u16::from_le_bytes([buf[2], buf[3]]) >= 0x0300 {
            if buf[7] > 15 { 512 } else { 1u16 << buf[7] }
        } else {
            buf[7] as u16
        };
        if mps0 != 0 && mps0 != d.speed.default_ep0_mps() && d.speed <= Speed::Full {
            self.hc.set_ep0_mps(slot, mps0)?;
        }
        let n = self.control(slot, Setup::get_descriptor(DT_DEVICE, 0, 0, 18), &[], &mut buf)?;
        d.desc = desc::parse_device(&buf[..n])?;

        // BOS: a USB 2.01 or later device has one (and may stall the request
        // anyway).
        if d.desc.bcd_usb >= 0x0201 {
            if let Ok(n) = self.control(slot, Setup::get_descriptor(DT_BOS, 0, 0, 5), &[], &mut buf) {
                if let Ok(total) = desc::bos_total_len(&buf[..n]) {
                    let want = (total as usize).min(buf.len());
                    if let Ok(n) = self.control(slot, Setup::get_descriptor(DT_BOS, 0, 0, want as u16), &[], &mut buf) {
                        d.bos = desc::parse_bos(&buf[..n]).ok();
                    }
                }
            }
        }

        // The first configuration, whole.
        if d.desc.num_configs == 0 {
            return Err(UsbError::NoConfig);
        }
        let n = self.control(slot, Setup::get_descriptor(DT_CONFIG, 0, 0, 9), &[], &mut buf)?;
        let total = (desc::config_total_len(&buf[..n])? as usize).min(CONFIG_MAX);
        let mut cfg = [0u8; CONFIG_MAX];
        let n = self.control(slot, Setup::get_descriptor(DT_CONFIG, 0, 0, total as u16), &[], &mut cfg)?;
        match desc::parse_config_lenient(&cfg[..n]) {
            (Some(c), _) if c.num_interfaces > 0 => d.config = c,
            _ => return Err(UsbError::NoConfig),
        }

        // Strings, when there are any: English (0x0409), as many bytes as fit.
        d.manufacturer = self.string(slot, d.desc.i_manufacturer);
        d.product = self.string(slot, d.desc.i_product);

        self.control(slot, Setup::set_configuration(d.config.value), &[], &mut [])?;
        Ok(d)
    }

    fn string(&mut self, slot: u8, index: u8) -> Text {
        if index == 0 {
            return Text::EMPTY;
        }
        let mut buf = [0u8; 64];
        match self.control(slot, Setup::get_descriptor(DT_STRING, index, 0x0409, 64), &[], &mut buf) {
            Ok(n) => {
                let mut out = [0u8; 24];
                let k = desc::string_ascii(&buf[..n], &mut out);
                Text::from_ascii(&out[..k])
            }
            Err(_) => Text::EMPTY,
        }
    }

    /// Offer a new device to the watchers and the interface drivers.
    fn bind_classes(&mut self, reg: &mut Registry<'_>, slot: u8) {
        let Some(d) = self.device(slot).copied() else { return };
        let speed_port = d.speed.psiv() << 8 | d.root_port as u32;
        let mut watchers = [0u8; 4];
        let mut nw = 0;
        for e in reg.iter_mut() {
            if nw == watchers.len() {
                break;
            }
            if e.rule.matches(Scope::Device, d.vid_pid(), d.desc.class, d.desc.subclass, d.desc.protocol) {
                let claim = Claim::new(slot, WHOLE_DEVICE, d.generation);
                if matches!(e.driver.attach(claim.0, d.vid_pid(), d.triple(), speed_port), Ok(o) if o.code == OK) {
                    watchers[nw] = e.id + 1;
                    nw += 1;
                }
            }
        }
        let mut owner = [0u8; desc::MAX_IFACES];
        if !d.is_hub() {
            for (ix, i) in d.config.interfaces().iter().enumerate() {
                let triple = (i.class as u32) << 16 | (i.subclass as u32) << 8 | i.protocol as u32;
                for e in reg.iter_mut() {
                    if e.rule.matches(Scope::Interface, d.vid_pid(), i.class, i.subclass, i.protocol) {
                        let claim = Claim::new(slot, i.number, d.generation);
                        if matches!(e.driver.attach(claim.0, d.vid_pid(), triple, speed_port), Ok(o) if o.code == OK) {
                            owner[ix] = e.id + 1;
                            break;
                        }
                    }
                }
            }
        }
        if let Some(dev) = self.devices[slot as usize - 1].as_mut() {
            dev.watchers = watchers;
            dev.owner = owner;
        }
    }

    /// A device is gone: everything below it first, then it. Its pipes
    /// complete their outstanding transfers as disconnected, the class
    /// drivers are told, and the slot is released.
    pub(crate) fn remove_device(&mut self, reg: &mut Registry<'_>, slot: u8) {
        let ix = slot as usize - 1;
        #[cfg(not(feature = "canary-unplug"))]
        let Some(d) = self.devices[ix].take() else { return };
        #[cfg(feature = "canary-unplug")]
        let Some(d) = self.devices[ix] else { return };
        if let Some(h) = d.hub {
            for c in h.children {
                if c != 0 {
                    self.remove_device(reg, c);
                }
            }
        }
        self.kill_pipes(slot);
        let _ = self.hc.disable_slot(slot);
        self.drain();
        for w in d.watchers.iter().filter(|w| **w != 0) {
            if let Some(e) = reg.by_id(w - 1) {
                let _ = e.driver.detach(Claim::new(slot, WHOLE_DEVICE, d.generation).0);
            }
        }
        for (i, o) in d.owner.iter().enumerate().filter(|(_, o)| **o != 0) {
            if let (Some(e), Some(iface)) = (reg.by_id(o - 1), d.config.interfaces().get(i)) {
                let _ = e.driver.detach(Claim::new(slot, iface.number, d.generation).0);
            }
        }
        self.reap_pipes(slot);
        if d.parent == 0 {
            if self.root_dev[d.root_port as usize - 1] == slot {
                self.root_dev[d.root_port as usize - 1] = 0;
            }
        } else if let Some(Some(p)) = self.devices.get_mut(d.parent as usize - 1) {
            if let Some(h) = p.hub.as_mut() {
                if let Some(c) = h.children.get_mut(d.port as usize - 1) {
                    if *c == slot {
                        *c = 0;
                    }
                }
            }
        }
        self.stats.detached += 1;
        self.emit(EventKind::Detached, &d);
    }
}

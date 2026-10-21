// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The hub class (USB 3.2, chapter 10), inside the core: USB 2 and USB 3 hubs,
//! port power, the status-change endpoint, port reset, enumeration of what
//! hangs below, the transaction translator fields of the slot context.
//!
//! A hub is configured like any device, then: its descriptor is read, a
//! SuperSpeed hub is told its depth, the slot context learns that the device
//! is a hub (port count, think time, multiple translators), its status-change
//! endpoint is opened and a transfer kept armed on it, and its ports are
//! powered. The endpoint's bitmap says which ports changed; the core reads
//! each one's status, acknowledges its change bits and acts: remove the
//! device that left, reset the port and enumerate the one that arrived.
//!
//! Hubs are driven only by the core. Class requests addressed to a hub or to
//! one of its ports are not something a class driver's claim can send.

use super::desc::{
    self, Setup, DT_HUB, DT_SS_HUB, REQ_CLEAR_FEATURE, REQ_GET_DESCRIPTOR, REQ_GET_STATUS, REQ_SET_FEATURE,
    REQ_SET_HUB_DEPTH, RT_RECIP_DEVICE, RT_RECIP_OTHER, RT_TYPE_CLASS, XFER_INTERRUPT,
};
use super::{Hub, Usb, UsbError, MAX_HUB_PORTS};
use crate::class::Registry;
use crate::hw::{Clock, Memory, Regs};
use crate::xhci::context::{self, SlotParams};
use crate::xhci::regs::Speed;
use crate::xhci::{Done, EpSpec, Owner, TdKind, TdSpec, Xhci};
use crate::MAX_DEVICES;

// Port features (USB 3.2 table 10-7 and USB 2.0 table 11-17).
const PORT_RESET: u16 = 4;
const PORT_POWER: u16 = 8;
const C_PORT_CONNECTION: u16 = 16;
const C_PORT_RESET: u16 = 20;
const C_PORT_LINK_STATE: u16 = 25;
const C_PORT_CONFIG_ERROR: u16 = 26;
const C_BH_PORT_RESET: u16 = 29;

// wPortStatus / wPortChange bits both hub flavours share.
const ST_CONNECTION: u16 = 1 << 0;
const ST_ENABLE: u16 = 1 << 1;
const CH_CONNECTION: u16 = 1 << 0;
const CH_RESET: u16 = 1 << 4;
// USB 2 hub port status: speed.
const ST2_LOW_SPEED: u16 = 1 << 9;
const ST2_HIGH_SPEED: u16 = 1 << 10;

const DEBOUNCE_US: u32 = 100_000;
const RESET_TIMEOUT_US: u64 = 800_000;
const RESET_RECOVERY_US: u32 = 10_000;

impl<'q, R: Regs, M: Memory, C: Clock> Usb<'q, R, M, C> {
    /// Configure a freshly addressed and configured hub. See the module
    /// documentation.
    pub(crate) fn hub_bring_up(&mut self, slot: u8) -> Result<(), UsbError> {
        let d = *self.device(slot).ok_or(UsbError::NoDevice)?;
        let ss = d.speed.is_super();
        let mut buf = [0u8; 32];
        let (dt, len) = if ss { (DT_SS_HUB, 12) } else { (DT_HUB, 16) };
        let n = self.control(
            slot,
            Setup::hub_class(true, REQ_GET_DESCRIPTOR, (dt as u16) << 8, 0, len, RT_RECIP_DEVICE),
            &[],
            &mut buf,
        )?;
        let hd = desc::parse_hub(&buf[..n])?;
        let ports = hd.ports.min(MAX_HUB_PORTS as u8);
        if ss {
            // The hub forwards by the route string's nibble at its depth.
            self.control(
                slot,
                Setup { request_type: RT_TYPE_CLASS, request: REQ_SET_HUB_DEPTH, value: d.tier as u16, index: 0, length: 0 },
                &[],
                &mut [],
            )?;
        }
        // The slot context learns it is a hub: ports, think time, and whether
        // it has a translator per port (bDeviceProtocol 2).
        self.hc.update_slot(
            slot,
            SlotParams {
                route: d.route,
                speed_psiv: d.speed.psiv(),
                hub: true,
                mtt: d.desc.protocol == 2,
                entries: 0,
                root_port: d.root_port,
                num_ports: ports,
                tt_slot: d.tt_slot,
                tt_port: d.tt_port,
                ttt: hd.tt_think_time(),
            },
        )?;

        // The status-change endpoint of the hub interface.
        let iface = d.config.interfaces().first().ok_or(UsbError::NoConfig)?;
        let ep = iface
            .endpoints()
            .iter()
            .find(|e| e.is_in() && e.transfer_type() == XFER_INTERRUPT)
            .copied()
            .ok_or(UsbError::NoConfig)?;
        let pid = self.alloc_pipe_slot().ok_or(UsbError::NoConfig)?;
        let dci = context::dci(ep.address);
        self.hc.configure_endpoints(
            slot,
            &[EpSpec {
                dci,
                ep_type: context::EP_TYPE_INT_IN,
                mps: ep.mps,
                burst: ep.burst,
                mult: 0,
                interval: context::interval_field(d.speed, ep.interval),
                max_esit: ep.mps as u32,
                ep: Xhci::<R, M, C>::ep_for_pipe(pid),
            }],
        )?;
        self.set_hub_pipe(pid, slot, dci);
        let hub = Hub { ports, desc: hd, pipe: pid, children: [0; MAX_HUB_PORTS], changed: 0, armed: false };
        if let Some(dev) = self.devices[slot as usize - 1].as_mut() {
            dev.hub = Some(hub);
        }

        // Power the ports, wait for the power to be good, and have every port
        // looked at once: a device already plugged in raised its change before
        // we listened.
        for p in 1..=ports {
            self.hub_set_feature(slot, p, PORT_POWER)?;
        }
        self.hc.clock().delay_us(1_000 * (hd.power_good_ms as u32).max(20));
        self.hub_arm(slot)?;
        if let Some(h) = self.devices[slot as usize - 1].as_mut().and_then(|d| d.hub.as_mut()) {
            h.changed = ((1u32 << ports) - 1) << 1;
        }
        Ok(())
    }

    /// Queue the next transfer on a hub's status-change endpoint.
    fn hub_arm(&mut self, slot: u8) -> Result<(), UsbError> {
        let Some(h) = self.device(slot).and_then(|d| d.hub) else { return Err(UsbError::NoDevice) };
        let mps = self.device(slot).map_or(1, |d| {
            d.config.interfaces().first().and_then(|i| i.endpoints().first()).map_or(1, |e| e.mps)
        });
        let len = ((h.ports as usize + 1).div_ceil(8) as u32).min(mps as u32).max(1);
        let buf = self.hub_buf().bus_at(16 * (slot as usize - 1));
        self.hc.queue_td(
            Xhci::<R, M, C>::ep_for_pipe(h.pipe),
            TdSpec { owner: Owner::Hub(slot), tag: 0, kind: TdKind::Data { buf, len, dir_in: true } },
        )?;
        if let Some(h) = self.devices[slot as usize - 1].as_mut().and_then(|d| d.hub.as_mut()) {
            h.armed = true;
        }
        Ok(())
    }

    /// A status-change transfer finished.
    pub(crate) fn hub_status_done(&mut self, slot: u8, done: Done) {
        let Some(h) = self.device(slot).and_then(|d| d.hub) else { return };
        let mut bits = 0u32;
        if done.ok() {
            let hb = self.hub_buf().sub(16 * (slot as usize - 1), 16);
            self.hc.mem().from_device(hb.cpu(), 4);
            let mut b = [0u8; 4];
            hb.read_bytes(0, &mut b);
            let n = (done.actual as usize).min(4);
            for (i, byte) in b[..n].iter().enumerate() {
                bits |= (*byte as u32) << (8 * i);
            }
            // Only the hub's own ports.
            bits &= (1u32 << (h.ports + 1)) - 1;
        }
        if let Some(h) = self.devices[slot as usize - 1].as_mut().and_then(|d| d.hub.as_mut()) {
            h.changed |= bits;
            h.armed = false;
        }
    }

    /// Look at every hub that has changes (or lost its armed transfer).
    pub(crate) fn hub_ports(&mut self, reg: &mut Registry<'_>) {
        for slot in 1..=MAX_DEVICES as u8 {
            let Some(h) = self.device(slot).and_then(|d| d.hub) else { continue };
            if !h.armed && !self.hc.ep_halted(Xhci::<R, M, C>::ep_for_pipe(h.pipe)) {
                let _ = self.hub_arm(slot);
            }
            loop {
                let Some(h) = self.device(slot).and_then(|d| d.hub) else { break };
                if h.changed == 0 {
                    break;
                }
                let b = h.changed.trailing_zeros();
                if let Some(h) = self.devices[slot as usize - 1].as_mut().and_then(|d| d.hub.as_mut()) {
                    h.changed &= !(1 << b);
                }
                // Bit 0 is the hub itself (local power, over-current): the
                // core has nothing to do about either.
                if b != 0 {
                    self.hub_port_event(reg, slot, b as u8);
                }
            }
        }
    }

    fn hub_port_status(&mut self, hub: u8, port: u8) -> Result<(u16, u16), UsbError> {
        let mut b = [0u8; 4];
        let n = self.control(
            hub,
            Setup::hub_class(true, REQ_GET_STATUS, 0, port as u16, 4, RT_RECIP_OTHER),
            &[],
            &mut b,
        )?;
        if n < 4 {
            return Err(desc::DescError::Truncated.into());
        }
        Ok((u16::from_le_bytes([b[0], b[1]]), u16::from_le_bytes([b[2], b[3]])))
    }

    fn hub_set_feature(&mut self, hub: u8, port: u8, feature: u16) -> Result<(), UsbError> {
        self.control(hub, Setup::hub_class(false, REQ_SET_FEATURE, feature, port as u16, 0, RT_RECIP_OTHER), &[], &mut [])
            .map(|_| ())
    }

    fn hub_clear_feature(&mut self, hub: u8, port: u8, feature: u16) -> Result<(), UsbError> {
        self.control(hub, Setup::hub_class(false, REQ_CLEAR_FEATURE, feature, port as u16, 0, RT_RECIP_OTHER), &[], &mut [])
            .map(|_| ())
    }

    /// Acknowledge the change bits of a port status, by the feature each
    /// clears.
    fn hub_ack_changes(&mut self, hub: u8, port: u8, ss: bool, change: u16) {
        // (change bit, feature): USB 2 and USB 3 hubs share bits 0 to 4 and
        // differ above.
        let table: &[(u16, u16)] = if ss {
            &[(0, C_PORT_CONNECTION), (3, 19), (4, C_PORT_RESET), (5, C_BH_PORT_RESET), (6, C_PORT_LINK_STATE), (7, C_PORT_CONFIG_ERROR)]
        } else {
            &[(0, C_PORT_CONNECTION), (1, 17), (2, 18), (3, 19), (4, C_PORT_RESET)]
        };
        for &(bit, feature) in table {
            if change & (1 << bit) != 0 {
                let _ = self.hub_clear_feature(hub, port, feature);
            }
        }
    }

    /// One port of a hub changed.
    fn hub_port_event(&mut self, reg: &mut Registry<'_>, hub: u8, port: u8) {
        let Some(hd) = self.device(hub).copied() else { return };
        let ss = hd.speed.is_super();
        let Ok((status, change)) = self.hub_port_status(hub, port) else {
            self.stats.failed += 1;
            return;
        };
        self.hub_ack_changes(hub, port, ss, change);
        let child = hd.hub.map_or(0, |h| h.children.get(port as usize - 1).copied().unwrap_or(0));
        let connected = status & ST_CONNECTION != 0;
        if change & CH_CONNECTION == 0 && (connected || child == 0) {
            return;
        }
        if child != 0 {
            self.remove_device(reg, child);
        }
        if !connected {
            return;
        }
        // Debounce, reset, enumerate.
        self.hc.clock().delay_us(DEBOUNCE_US);
        let Ok((status, _)) = self.hub_port_status(hub, port) else { return };
        if status & ST_CONNECTION == 0 {
            return;
        }
        let speed = match self.hub_reset_port(hub, port, ss) {
            Ok(s) => s,
            Err(_) => {
                self.stats.failed += 1;
                return;
            }
        };
        match self.enumerate(reg, Some((hub, port)), hd.root_port, speed) {
            Ok(slot) => {
                if let Some(h) = self.devices[hub as usize - 1].as_mut().and_then(|d| d.hub.as_mut()) {
                    h.children[port as usize - 1] = slot;
                }
            }
            Err(_) => self.stats.failed += 1,
        }
    }

    /// Reset a hub port and read the speed the device came up at.
    fn hub_reset_port(&mut self, hub: u8, port: u8, ss: bool) -> Result<Speed, UsbError> {
        self.hub_set_feature(hub, port, PORT_RESET)?;
        let deadline = self.hc.clock().now_us() + RESET_TIMEOUT_US;
        let status = loop {
            self.hc.clock().delay_us(10_000);
            let (status, change) = self.hub_port_status(hub, port)?;
            if change & CH_RESET != 0 {
                let _ = self.hub_clear_feature(hub, port, C_PORT_RESET);
                break status;
            }
            if self.hc.clock().now_us() >= deadline {
                return Err(UsbError::Port);
            }
        };
        if status & (ST_CONNECTION | ST_ENABLE) != (ST_CONNECTION | ST_ENABLE) {
            return Err(UsbError::Port);
        }
        self.hc.clock().delay_us(RESET_RECOVERY_US);
        Ok(if ss {
            Speed::Super
        } else if status & ST2_HIGH_SPEED != 0 {
            Speed::High
        } else if status & ST2_LOW_SPEED != 0 {
            Speed::Low
        } else {
            Speed::Full
        })
    }
}

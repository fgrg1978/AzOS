// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Fake devices for the xHCI mock: descriptor builders and the device model
//! (what a device answers on endpoint 0, what a hub reports on its ports).

use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;

pub type DevRef = Rc<RefCell<MockDev>>;

/// A device descriptor.
#[allow(clippy::too_many_arguments)]
pub fn device_desc(bcd: u16, class: u8, sub: u8, proto: u8, mps0: u8, vid: u16, pid: u16, imfr: u8, iprod: u8) -> Vec<u8> {
    let mut d = vec![18, 1];
    d.extend(bcd.to_le_bytes());
    d.extend([class, sub, proto, mps0]);
    d.extend(vid.to_le_bytes());
    d.extend(pid.to_le_bytes());
    d.extend(0x0100u16.to_le_bytes());
    d.extend([imfr, iprod, 0, 1]);
    d
}

/// One endpoint: address, attributes, max packet, interval, and an optional
/// SuperSpeed companion (max burst, bytes per interval).
pub struct Ep {
    pub addr: u8,
    pub attrs: u8,
    pub mps: u16,
    pub interval: u8,
    pub companion: Option<(u8, u16)>,
}

pub fn ep(addr: u8, attrs: u8, mps: u16, interval: u8) -> Ep {
    Ep { addr, attrs, mps, interval, companion: None }
}

/// One interface with its endpoints.
pub struct Iface {
    pub number: u8,
    pub class: u8,
    pub sub: u8,
    pub proto: u8,
    pub eps: Vec<Ep>,
    /// An alternate setting 1 (an interface descriptor only).
    pub alt: bool,
}

pub fn iface(number: u8, class: u8, sub: u8, proto: u8, eps: Vec<Ep>) -> Iface {
    Iface { number, class, sub, proto, eps, alt: false }
}

pub fn config_desc(value: u8, ifaces: &[Iface]) -> Vec<u8> {
    let mut body = Vec::new();
    for i in ifaces {
        body.extend([9, 4, i.number, 0, i.eps.len() as u8, i.class, i.sub, i.proto, 0]);
        for e in &i.eps {
            body.extend([7, 5, e.addr, e.attrs]);
            body.extend(e.mps.to_le_bytes());
            body.push(e.interval);
            if let Some((burst, bpi)) = e.companion {
                body.extend([6, 48, burst, 0]);
                body.extend(bpi.to_le_bytes());
            }
        }
        if i.alt {
            body.extend([9, 4, i.number, 1, 0, i.class, i.sub, i.proto, 0]);
        }
    }
    let total = 9 + body.len();
    let mut c = vec![9, 2];
    c.extend((total as u16).to_le_bytes());
    c.extend([ifaces.len() as u8, value, 0, 0x80, 50]);
    c.extend(body);
    c
}

/// A BOS with a USB 2.0 extension (LPM) and a SuperSpeed capability.
pub fn bos_desc(superspeed: bool) -> Vec<u8> {
    let mut caps = vec![7, 16, 2, 0b10, 0, 0, 0];
    if superspeed {
        caps.extend([10, 16, 3, 0, 0x0e, 0x00, 1, 10, 0x20, 0x00]);
    }
    let total = 5 + caps.len();
    let mut b = vec![5, 15];
    b.extend((total as u16).to_le_bytes());
    b.push(if superspeed { 2 } else { 1 });
    b.extend(caps);
    b
}

pub fn string_desc(s: &str) -> Vec<u8> {
    let mut d = vec![2 + 2 * s.len() as u8, 3];
    for c in s.encode_utf16() {
        d.extend(c.to_le_bytes());
    }
    d
}

// ---- The device model ----

#[derive(Clone, Copy, Default)]
pub struct PortModel {
    pub connected: bool,
    pub enabled: bool,
    pub powered: bool,
    /// USB 2 hub: low speed / high speed device bits (9 / 10).
    pub low: bool,
    pub high: bool,
    /// wPortChange bits.
    pub change: u16,
}

pub struct HubModel {
    pub ss: bool,
    pub ports: Vec<PortModel>,
    pub children: Vec<Option<DevRef>>,
    pub depth: Option<u16>,
    /// A multi-TT hub (bDeviceProtocol 2).
    pub power_good_2ms: u8,
}

pub struct MockDev {
    pub speed_psiv: u32,
    pub dev_desc: Vec<u8>,
    pub config: Vec<u8>,
    pub bos: Option<Vec<u8>>,
    /// String descriptors by index (1-based).
    pub strings: Vec<Vec<u8>>,
    pub hub: Option<HubModel>,
    pub configuration: u8,
    /// Every control request seen, with its OUT data.
    pub requests: Vec<([u8; 8], Vec<u8>)>,
    /// Packets an IN endpoint will return, by endpoint number.
    pub in_queue: Vec<VecDeque<Vec<u8>>>,
    /// Bytes received on OUT endpoints: (endpoint number, data).
    pub out_log: Vec<(u8, Vec<u8>)>,
    /// Stall the control request with this bRequest.
    pub stall_requests: Vec<u8>,
    /// HID report descriptors by interface number.
    pub report_descs: Vec<(u8, Vec<u8>)>,
    pub fail_everything: bool,
    /// Requests answered with fixed bytes, looked up before the generic arms:
    /// (bmRequestType, bRequest, answer). A class request the model has no
    /// arm for (GET_NTB_PARAMETERS) or a standard one it has none for
    /// (SET_INTERFACE) is given here by the test that needs it.
    pub canned: Vec<(u8, u8, Vec<u8>)>,
    /// Vendor requests (bmRequestType type 2), answered by the test's model
    /// of the chip (a USB Ethernet function's register file).
    #[allow(clippy::type_complexity)]
    pub vendor: Option<Box<dyn FnMut([u8; 8], &[u8]) -> Result<Vec<u8>, ()>>>,
}

impl MockDev {
    pub fn new(speed_psiv: u32, dev_desc: Vec<u8>, config: Vec<u8>) -> MockDev {
        MockDev {
            speed_psiv,
            dev_desc,
            config,
            bos: None,
            strings: Vec::new(),
            hub: None,
            configuration: 0,
            requests: Vec::new(),
            in_queue: (0..16).map(|_| VecDeque::new()).collect(),
            out_log: Vec::new(),
            stall_requests: Vec::new(),
            report_descs: Vec::new(),
            fail_everything: false,
            canned: Vec::new(),
            vendor: None,
        }
    }

    pub fn into_ref(self) -> DevRef {
        Rc::new(RefCell::new(self))
    }

    pub fn hub_status_bitmap(&self) -> Option<Vec<u8>> {
        let h = self.hub.as_ref()?;
        let mut bits = 0u32;
        for (i, p) in h.ports.iter().enumerate() {
            if p.change != 0 {
                bits |= 1 << (i + 1);
            }
        }
        if bits == 0 {
            return None;
        }
        let n = (h.ports.len() + 1).div_ceil(8);
        Some(bits.to_le_bytes()[..n].to_vec())
    }

    /// Answer a control request: `Ok(data)` (IN) or `Err(())` for a stall.
    pub fn control(&mut self, setup: [u8; 8], out: &[u8]) -> Result<Vec<u8>, ()> {
        self.requests.push((setup, out.to_vec()));
        if self.fail_everything || self.stall_requests.contains(&setup[1]) {
            return Err(());
        }
        let (rt, req) = (setup[0], setup[1]);
        let value = u16::from_le_bytes([setup[2], setup[3]]);
        let index = u16::from_le_bytes([setup[4], setup[5]]);
        if let Some((_, _, answer)) = self.canned.iter().find(|(t, r, _)| *t == rt && *r == req) {
            return Ok(answer.clone());
        }
        if rt & 0x60 == 0x40 {
            if let Some(v) = self.vendor.as_mut() {
                return v(setup, out);
            }
        }
        match (rt, req) {
            (0x80, 6) => match (value >> 8) as u8 {
                1 => Ok(self.dev_desc.clone()),
                2 => Ok(self.config.clone()),
                15 => self.bos.clone().ok_or(()),
                3 => {
                    let i = (value & 0xff) as usize;
                    if i == 0 {
                        Ok(vec![4, 3, 0x09, 0x04])
                    } else {
                        self.strings.get(i - 1).cloned().ok_or(())
                    }
                }
                _ => Err(()),
            },
            // A HID interface's report descriptor.
            (0x81, 6) if value >> 8 == 0x22 => {
                self.report_descs.iter().find(|(i, _)| *i as u16 == index).map(|(_, d)| d.clone()).ok_or(())
            }
            (0x00, 9) => {
                self.configuration = value as u8;
                Ok(vec![])
            }
            // Hub class requests.
            (0xa0, 6) => {
                let h = self.hub.as_ref().ok_or(())?;
                let n = h.ports.len() as u8;
                Ok(if h.ss {
                    vec![12, 0x2a, n, 0x09, 0x00, h.power_good_2ms, 0, 0, 0, 0, 0, 0]
                } else {
                    vec![9, 0x29, n, 0x09, 0x00, h.power_good_2ms, 0, 0, 0xff]
                })
            }
            (0x20, 12) => {
                self.hub.as_mut().ok_or(())?.depth = Some(value);
                Ok(vec![])
            }
            (0xa3, 0) => {
                let h = self.hub.as_ref().ok_or(())?;
                let p = h.ports.get((index as usize).wrapping_sub(1)).ok_or(())?;
                let mut st = 0u16;
                if p.connected {
                    st |= 1;
                }
                if p.enabled {
                    st |= 2;
                }
                if p.powered {
                    st |= if h.ss { 1 << 9 } else { 1 << 8 };
                }
                if !h.ss {
                    if p.low {
                        st |= 1 << 9;
                    }
                    if p.high {
                        st |= 1 << 10;
                    }
                }
                let mut d = st.to_le_bytes().to_vec();
                d.extend(p.change.to_le_bytes());
                Ok(d)
            }
            (0x23, 3) => {
                let h = self.hub.as_mut().ok_or(())?;
                let p = h.ports.get_mut((index as usize).wrapping_sub(1)).ok_or(())?;
                match value {
                    8 => p.powered = true,
                    4 => {
                        // Reset completes at once: enabled, reset change.
                        if p.connected {
                            p.enabled = true;
                            p.change |= 1 << 4;
                        }
                    }
                    _ => {}
                }
                Ok(vec![])
            }
            (0x23, 1) => {
                let h = self.hub.as_mut().ok_or(())?;
                let ss = h.ss;
                let p = h.ports.get_mut((index as usize).wrapping_sub(1)).ok_or(())?;
                let bit = match (value, ss) {
                    (16, _) => 0,
                    (17, false) => 1,
                    (18, false) => 2,
                    (19, _) => 3,
                    (20, _) => 4,
                    (29, true) => 5,
                    (25, true) => 6,
                    (26, true) => 7,
                    _ => return Err(()),
                };
                p.change &= !(1 << bit);
                Ok(vec![])
            }
            // A class request to an interface: echo a recognisable byte.
            (0xa1, _) | (0x21, _) => Ok(vec![req]),
            (0x02, 1) => Ok(vec![]),
            (0x80, 0) | (0x81, 0) | (0x82, 0) => Ok(vec![0, 0]),
            _ => Err(()),
        }
    }

    /// The next data an IN endpoint (number `ep`) has, if any.
    pub fn poll_in(&mut self, ep: u8, is_hub_status: bool) -> Option<Vec<u8>> {
        if is_hub_status {
            return self.hub_status_bitmap();
        }
        self.in_queue.get_mut(ep as usize)?.pop_front()
    }
}

/// A hub model with `n` ports.
pub fn hub(ss: bool, n: usize) -> HubModel {
    HubModel {
        ss,
        ports: vec![PortModel::default(); n],
        children: (0..n).map(|_| None).collect(),
        depth: None,
        power_good_2ms: 10,
    }
}

/// A USB 2 hub device (high speed): class 9, one interface, one interrupt IN
/// endpoint 1.
pub fn hub_device(ss: bool, ports: usize, speed_psiv: u32, multi_tt: bool) -> DevRef {
    let proto = if multi_tt { 2 } else { 1 };
    let bcd = if ss { 0x0300 } else { 0x0200 };
    let mps0 = if ss { 9 } else { 64 };
    let dd = device_desc(bcd, 9, 0, if ss { 3 } else { proto }, mps0, 0x05e3, 0x0608, 0, 0);
    let mut dd = dd;
    if multi_tt {
        dd[6] = 2;
    }
    let cfg = config_desc(1, &[iface(0, 9, 0, 0, vec![ep(0x81, 3, 2, if ss { 8 } else { 12 })])]);
    let mut d = MockDev::new(speed_psiv, dd, cfg);
    d.hub = Some(hub(ss, ports));
    d.into_ref()
}

/// A full speed keyboard: HID boot interface with an interrupt IN endpoint 1.
pub fn keyboard() -> DevRef {
    let dd = device_desc(0x0110, 0, 0, 0, 8, 0x046d, 0xc31c, 1, 2);
    let cfg = config_desc(1, &[iface(0, 3, 1, 1, vec![ep(0x81, 3, 8, 10)])]);
    let mut d = MockDev::new(1, dd, cfg);
    d.strings = vec![string_desc("Logitech"), string_desc("USB Keyboard")];
    d.into_ref()
}

/// A high speed mass-storage stick: bulk-only interface with bulk IN 1 and
/// bulk OUT 2, and a vendor interface with an interrupt IN endpoint 3.
pub fn stick() -> DevRef {
    let dd = device_desc(0x0210, 0, 0, 0, 64, 0x0781, 0x5567, 1, 2);
    let cfg = config_desc(
        1,
        &[
            iface(0, 8, 6, 0x50, vec![ep(0x81, 2, 512, 0), ep(0x02, 2, 512, 0)]),
            iface(1, 0xff, 1, 1, vec![ep(0x83, 3, 16, 4)]),
        ],
    );
    let mut d = MockDev::new(3, dd, cfg);
    d.bos = Some(bos_desc(false));
    d.strings = vec![string_desc("SanDisk"), string_desc("Cruzer Blade")];
    d.into_ref()
}

/// A SuperSpeed drive: bulk endpoints with companions.
pub fn ss_drive() -> DevRef {
    let dd = device_desc(0x0300, 0, 0, 0, 9, 0x1058, 0x2621, 1, 2);
    let mut e1 = ep(0x81, 2, 1024, 0);
    e1.companion = Some((15, 0));
    let mut e2 = ep(0x02, 2, 1024, 0);
    e2.companion = Some((15, 0));
    let cfg = config_desc(1, &[iface(0, 8, 6, 0x50, vec![e1, e2])]);
    let mut d = MockDev::new(4, dd, cfg);
    d.bos = Some(bos_desc(true));
    d.strings = vec![string_desc("WD"), string_desc("My Passport")];
    d.into_ref()
}

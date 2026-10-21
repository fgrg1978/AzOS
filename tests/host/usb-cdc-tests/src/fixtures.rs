// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Descriptor sets of CDC devices, built byte by byte the way a gadget does.

use azos_usb_tests::devices::{device_desc, string_desc, DevRef, MockDev};

/// A class-specific interface descriptor.
pub fn cs(ty: u8, payload: &[u8]) -> Vec<u8> {
    let mut v = vec![3 + payload.len() as u8, 0x24, ty];
    v.extend(payload);
    v
}

pub fn iface(num: u8, alt: u8, neps: u8, class: u8, sub: u8) -> Vec<u8> {
    vec![9, 4, num, alt, neps, class, sub, 0, 0]
}

pub fn ep(addr: u8, attrs: u8, mps: u16, interval: u8) -> Vec<u8> {
    let mut v = vec![7, 5, addr, attrs];
    v.extend(mps.to_le_bytes());
    v.push(interval);
    v
}

pub fn config(ifaces: u8, body: Vec<u8>) -> Vec<u8> {
    let total = 9 + body.len();
    let mut c = vec![9, 2];
    c.extend((total as u16).to_le_bytes());
    c.extend([ifaces, 1, 0, 0x80, 50]);
    c.extend(body);
    c
}

/// An Ethernet function: ECM (`sub` 6) or NCM (`sub` 0x0d).
#[derive(Clone)]
pub struct NetFn {
    pub sub: u8,
    pub comm: u8,
    pub data: u8,
    /// The data interface the union descriptor names.
    pub union_data: u8,
    pub union: bool,
    /// iMACAddress.
    pub mac_idx: u8,
    pub segment: u16,
    /// The NCM descriptor's bmNetworkCapabilities (`None`: no NCM descriptor).
    pub ncm: Option<u8>,
    /// The bulk endpoints are in setting 0 of the data interface (an old
    /// device) rather than in setting 1.
    pub eps_in_alt0: bool,
    /// Endpoint number of the bulk pair: IN is `0x80 | base`, OUT `base + 1`,
    /// the notification endpoint `0x80 | (base + 2)`.
    pub base: u8,
    pub mps: u16,
}

impl NetFn {
    pub fn ecm() -> NetFn {
        NetFn {
            sub: 6,
            comm: 0,
            data: 1,
            union_data: 1,
            union: true,
            mac_idx: 3,
            segment: 1514,
            ncm: None,
            eps_in_alt0: false,
            base: 1,
            mps: 512,
        }
    }

    pub fn ncm() -> NetFn {
        NetFn { sub: 0x0d, ncm: Some(1), ..NetFn::ecm() }
    }

    pub fn ep_in(&self) -> u8 {
        0x80 | self.base
    }

    pub fn ep_out(&self) -> u8 {
        self.base + 1
    }

    /// The interface descriptors and what follows them.
    pub fn bytes(&self) -> Vec<u8> {
        let mut b = iface(self.comm, 0, 1, 2, self.sub);
        b.extend(cs(0, &[0x10, 0x01]));
        if self.union {
            b.extend(cs(6, &[self.comm, self.union_data]));
        }
        let mut eth = vec![self.mac_idx, 0, 0, 0, 0];
        eth.extend(self.segment.to_le_bytes());
        eth.extend([0, 0, 0]);
        b.extend(cs(0x0f, &eth));
        if let Some(caps) = self.ncm {
            b.extend(cs(0x1a, &[0x00, 0x01, caps]));
        }
        b.extend(ep(0x80 | (self.base + 2), 3, 16, 8));
        let bulk = |b: &mut Vec<u8>| {
            b.extend(ep(self.ep_in(), 2, self.mps, 0));
            b.extend(ep(self.ep_out(), 2, self.mps, 0));
        };
        if self.eps_in_alt0 {
            b.extend(iface(self.data, 0, 2, 0x0a, 0));
            bulk(&mut b);
        } else {
            b.extend(iface(self.data, 0, 0, 0x0a, 0));
            b.extend(iface(self.data, 1, 2, 0x0a, 0));
            bulk(&mut b);
        }
        b
    }
}

/// A serial function.
#[derive(Clone)]
pub struct AcmFn {
    pub comm: u8,
    pub data: u8,
    /// bmCapabilities of the ACM descriptor (`None`: no ACM descriptor).
    pub caps: Option<u8>,
    pub base: u8,
}

impl AcmFn {
    pub fn new() -> AcmFn {
        AcmFn { comm: 0, data: 1, caps: Some(0x02), base: 1 }
    }

    pub fn ep_in(&self) -> u8 {
        0x80 | self.base
    }

    pub fn ep_out(&self) -> u8 {
        self.base + 1
    }

    pub fn bytes(&self) -> Vec<u8> {
        let mut b = iface(self.comm, 0, 1, 2, 2);
        b.extend(cs(0, &[0x10, 0x01]));
        b.extend(cs(1, &[0, self.data]));
        if let Some(c) = self.caps {
            b.extend(cs(2, &[c]));
        }
        b.extend(cs(6, &[self.comm, self.data]));
        b.extend(ep(0x80 | (self.base + 2), 3, 16, 8));
        b.extend(iface(self.data, 0, 2, 0x0a, 0));
        b.extend(ep(self.ep_in(), 2, 512, 0));
        b.extend(ep(self.ep_out(), 2, 512, 0));
        b
    }
}

/// GET_NTB_PARAMETERS' answer.
pub fn ntb_params(formats: u16, in_max: u32, out_max: u32, divisor: u16, remainder: u16, align: u16, datagrams: u16) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend(28u16.to_le_bytes());
    p.extend(formats.to_le_bytes());
    p.extend(in_max.to_le_bytes());
    p.extend(4u16.to_le_bytes()); // wNdpInDivisor
    p.extend(0u16.to_le_bytes());
    p.extend(4u16.to_le_bytes());
    p.extend(0u16.to_le_bytes());
    p.extend(out_max.to_le_bytes());
    p.extend(divisor.to_le_bytes());
    p.extend(remainder.to_le_bytes());
    p.extend(align.to_le_bytes());
    p.extend(datagrams.to_le_bytes());
    assert_eq!(p.len(), 28);
    p
}

/// A high speed device made of `body` (its interface descriptors).
pub fn device(ifaces: u8, body: Vec<u8>, mac: &str) -> DevRef {
    let dd = device_desc(0x0200, 0, 0, 0, 64, 0x0525, 0xa4a2, 1, 2);
    let mut d = MockDev::new(3, dd, config(ifaces, body));
    d.strings = vec![string_desc("Gadget"), string_desc("CDC"), string_desc(mac)];
    // SET_INTERFACE: the model has no arm for it.
    d.canned.push((0x01, 11, vec![]));
    d.into_ref()
}

pub const MAC: &str = "02a1b2c3d4e5";
pub const MAC_BYTES: [u8; 6] = [0x02, 0xa1, 0xb2, 0xc3, 0xd4, 0xe5];

pub fn ecm_device() -> DevRef {
    device(2, NetFn::ecm().bytes(), MAC)
}

/// An NCM device that sends blocks up to `in_max`, takes up to `out_max`.
pub fn ncm_device(in_max: u32, out_max: u32) -> DevRef {
    let d = device(2, NetFn::ncm().bytes(), MAC);
    d.borrow_mut().canned.push((0xa1, 0x80, ntb_params(1, in_max, out_max, 4, 0, 4, 0)));
    d
}

pub fn acm_device() -> DevRef {
    device(2, AcmFn::new().bytes(), "")
}

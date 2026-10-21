// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! USB descriptors (USB 3.2 specification, chapter 9): the setup packet, and
//! the parsers of the device, configuration (with its interface, endpoint and
//! SuperSpeed endpoint companion descriptors), BOS, hub and string
//! descriptors. Pure bytes in, plain values out; no allocation, and a
//! descriptor that lies about its own length is an error, not a panic.

pub const DT_DEVICE: u8 = 1;
pub const DT_CONFIG: u8 = 2;
pub const DT_STRING: u8 = 3;
pub const DT_INTERFACE: u8 = 4;
pub const DT_ENDPOINT: u8 = 5;
pub const DT_BOS: u8 = 15;
pub const DT_DEVICE_CAPABILITY: u8 = 16;
pub const DT_SS_ENDPOINT_COMPANION: u8 = 48;
pub const DT_HUB: u8 = 0x29;
pub const DT_SS_HUB: u8 = 0x2a;

pub const CAP_USB2_EXT: u8 = 2;
pub const CAP_SUPERSPEED: u8 = 3;
pub const CAP_SUPERSPEED_PLUS: u8 = 10;

pub const CLASS_HUB: u8 = 9;

/// Interfaces and endpoints kept per configuration. A configuration with more
/// is truncated (the excess is counted in [`ConfigDesc::dropped`]).
pub const MAX_IFACES: usize = 8;
pub const MAX_EPS: usize = 8;
/// Endpoints of alternate settings kept per configuration (see
/// [`ConfigDesc::alt_endpoints`]).
pub const MAX_ALT_EPS: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DescError {
    /// Shorter than the descriptor's fixed size, or a length field that runs
    /// past the buffer or is under 2.
    Truncated,
    /// Not the type that was asked for.
    WrongType,
}

// ---- Setup packet ----

pub const REQ_GET_STATUS: u8 = 0;
pub const REQ_CLEAR_FEATURE: u8 = 1;
pub const REQ_SET_FEATURE: u8 = 3;
pub const REQ_SET_ADDRESS: u8 = 5;
pub const REQ_GET_DESCRIPTOR: u8 = 6;
pub const REQ_SET_CONFIGURATION: u8 = 9;
pub const REQ_SET_INTERFACE: u8 = 11;
pub const REQ_SET_HUB_DEPTH: u8 = 12;

pub const RT_DIR_IN: u8 = 0x80;
pub const RT_TYPE_STANDARD: u8 = 0 << 5;
pub const RT_TYPE_CLASS: u8 = 1 << 5;
pub const RT_TYPE_MASK: u8 = 3 << 5;
pub const RT_RECIP_DEVICE: u8 = 0;
pub const RT_RECIP_INTERFACE: u8 = 1;
pub const RT_RECIP_ENDPOINT: u8 = 2;
pub const RT_RECIP_OTHER: u8 = 3;
pub const RT_RECIP_MASK: u8 = 0x1f;

/// A setup packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Setup {
    pub request_type: u8,
    pub request: u8,
    pub value: u16,
    pub index: u16,
    pub length: u16,
}

impl Setup {
    pub fn to_bytes(&self) -> [u8; 8] {
        let mut b = [0u8; 8];
        b[0] = self.request_type;
        b[1] = self.request;
        b[2..4].copy_from_slice(&self.value.to_le_bytes());
        b[4..6].copy_from_slice(&self.index.to_le_bytes());
        b[6..8].copy_from_slice(&self.length.to_le_bytes());
        b
    }
    pub fn from_bytes(b: [u8; 8]) -> Setup {
        Setup {
            request_type: b[0],
            request: b[1],
            value: u16::from_le_bytes([b[2], b[3]]),
            index: u16::from_le_bytes([b[4], b[5]]),
            length: u16::from_le_bytes([b[6], b[7]]),
        }
    }
    pub fn is_in(&self) -> bool {
        self.request_type & RT_DIR_IN != 0
    }
    pub fn recipient(&self) -> u8 {
        self.request_type & RT_RECIP_MASK
    }
    pub fn kind(&self) -> u8 {
        self.request_type & RT_TYPE_MASK
    }

    pub fn get_descriptor(ty: u8, index: u8, lang: u16, length: u16) -> Setup {
        Setup {
            request_type: RT_DIR_IN | RT_TYPE_STANDARD | RT_RECIP_DEVICE,
            request: REQ_GET_DESCRIPTOR,
            value: (ty as u16) << 8 | index as u16,
            index: lang,
            length,
        }
    }
    pub fn set_configuration(value: u8) -> Setup {
        Setup {
            request_type: RT_TYPE_STANDARD | RT_RECIP_DEVICE,
            request: REQ_SET_CONFIGURATION,
            value: value as u16,
            index: 0,
            length: 0,
        }
    }
    /// A hub class request addressed to the hub itself (`recip` device) or a
    /// port of it (`recip` other, `index` the port number).
    pub fn hub_class(dir_in: bool, request: u8, value: u16, index: u16, length: u16, recip: u8) -> Setup {
        Setup {
            request_type: if dir_in { RT_DIR_IN } else { 0 } | RT_TYPE_CLASS | recip,
            request,
            value,
            index,
            length,
        }
    }
    pub fn clear_halt(ep: u8) -> Setup {
        Setup {
            request_type: RT_TYPE_STANDARD | RT_RECIP_ENDPOINT,
            request: REQ_CLEAR_FEATURE,
            value: 0, // ENDPOINT_HALT
            index: ep as u16,
            length: 0,
        }
    }
}

// ---- Device ----

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DeviceDesc {
    pub bcd_usb: u16,
    pub class: u8,
    pub subclass: u8,
    pub protocol: u8,
    /// bMaxPacketSize0 as the descriptor holds it: bytes for USB 2, the
    /// exponent for USB 3 (2^n).
    pub max_packet0: u8,
    pub vendor: u16,
    pub product: u16,
    pub bcd_device: u16,
    pub i_manufacturer: u8,
    pub i_product: u8,
    pub i_serial: u8,
    pub num_configs: u8,
}

impl DeviceDesc {
    /// Endpoint 0's max packet size in bytes (the SuperSpeed exponent form
    /// decoded).
    pub fn ep0_mps(&self) -> u16 {
        if self.bcd_usb >= 0x0300 {
            if self.max_packet0 > 15 { 512 } else { 1 << self.max_packet0 }
        } else {
            self.max_packet0 as u16
        }
    }
}

pub fn parse_device(b: &[u8]) -> Result<DeviceDesc, DescError> {
    if b.len() < 18 || b[0] < 18 {
        return Err(DescError::Truncated);
    }
    if b[1] != DT_DEVICE {
        return Err(DescError::WrongType);
    }
    Ok(DeviceDesc {
        bcd_usb: u16::from_le_bytes([b[2], b[3]]),
        class: b[4],
        subclass: b[5],
        protocol: b[6],
        max_packet0: b[7],
        vendor: u16::from_le_bytes([b[8], b[9]]),
        product: u16::from_le_bytes([b[10], b[11]]),
        bcd_device: u16::from_le_bytes([b[12], b[13]]),
        i_manufacturer: b[14],
        i_product: b[15],
        i_serial: b[16],
        num_configs: b[17],
    })
}

// ---- Configuration ----

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct EndpointDesc {
    /// bEndpointAddress: number in bits 3:0, direction in bit 7.
    pub address: u8,
    /// bmAttributes: transfer type in bits 1:0.
    pub attrs: u8,
    /// wMaxPacketSize bits 10:0 (payload), the additional-transactions field
    /// (bits 12:11) in `mult`.
    pub mps: u16,
    pub mult: u8,
    pub interval: u8,
    /// SuperSpeed endpoint companion: bMaxBurst, bmAttributes (bulk: max
    /// streams; isoch: mult), wBytesPerInterval.
    pub burst: u8,
    pub ss_attrs: u8,
    pub bytes_per_interval: u16,
    pub has_companion: bool,
}

pub const XFER_CONTROL: u8 = 0;
pub const XFER_ISOCH: u8 = 1;
pub const XFER_BULK: u8 = 2;
pub const XFER_INTERRUPT: u8 = 3;

impl EndpointDesc {
    pub fn number(&self) -> u8 {
        self.address & 0x0f
    }
    pub fn is_in(&self) -> bool {
        self.address & 0x80 != 0
    }
    pub fn transfer_type(&self) -> u8 {
        self.attrs & 3
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct InterfaceDesc {
    pub number: u8,
    pub class: u8,
    pub subclass: u8,
    pub protocol: u8,
    pub i_interface: u8,
    pub endpoints: [EndpointDesc; MAX_EPS],
    pub num_endpoints: u8,
    /// Alternate settings other than 0 seen for this interface number. The
    /// core configures alternate setting 0 and a class driver that wants
    /// another asks for it with SET_INTERFACE; only the endpoints of one
    /// setting are kept, see [`InterfaceDesc::alt_setting`].
    pub alternates: u8,
    /// The setting `endpoints` belong to: 0, or, for an interface whose
    /// setting 0 has no endpoints (a CDC data interface, an audio streaming
    /// one), the first alternate setting that has some. A driver selects it
    /// with SET_INTERFACE before it uses a pipe of the interface.
    pub alt_setting: u8,
}

impl InterfaceDesc {
    pub fn endpoints(&self) -> &[EndpointDesc] {
        &self.endpoints[..self.num_endpoints as usize]
    }
}

/// An endpoint of an alternate setting (setting 1 and up) of an interface.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AltEndpoint {
    pub iface: u8,
    pub alt: u8,
    pub ep: EndpointDesc,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ConfigDesc {
    pub value: u8,
    pub attrs: u8,
    /// bMaxPower in the descriptor's units (2 mA, or 8 mA for SuperSpeed).
    pub max_power: u8,
    pub total_len: u16,
    pub interfaces: [InterfaceDesc; MAX_IFACES],
    pub num_interfaces: u8,
    /// Every endpoint of every alternate setting (1 and up) of the interfaces
    /// listed above, in descriptor order. An interface keeps the endpoints of
    /// one setting in [`InterfaceDesc::endpoints`]; a class driver that picks
    /// a setting by the bandwidth it needs (a camera's isochronous streaming
    /// interface has a setting per bandwidth) opens a pipe on an endpoint of
    /// this table by naming the setting (`Usb::open_pipe_alt`).
    pub alt_endpoints: [AltEndpoint; MAX_ALT_EPS],
    pub num_alt_endpoints: u8,
    /// Interfaces or endpoints that did not fit the tables.
    pub dropped: u8,
}

impl ConfigDesc {
    pub fn interfaces(&self) -> &[InterfaceDesc] {
        &self.interfaces[..self.num_interfaces as usize]
    }

    pub fn alt_endpoints(&self) -> &[AltEndpoint] {
        &self.alt_endpoints[..self.num_alt_endpoints as usize]
    }

    /// Endpoint `address` of setting `alt` of interface `iface`: setting 0 is
    /// the interface's own endpoint table, any other the alternate table.
    pub fn endpoint(&self, iface: u8, alt: u8, address: u8) -> Option<EndpointDesc> {
        if alt == 0 {
            let i = self.interfaces().iter().find(|i| i.number == iface)?;
            return i.endpoints().iter().find(|e| e.address == address).copied();
        }
        self.alt_endpoints().iter().find(|a| a.iface == iface && a.alt == alt && a.ep.address == address).map(|a| a.ep)
    }
}

/// wTotalLength of a configuration descriptor from its first bytes (the
/// 9-byte header read first, to size the full read).
pub fn config_total_len(header: &[u8]) -> Result<u16, DescError> {
    if header.len() < 9 || header[0] < 9 {
        return Err(DescError::Truncated);
    }
    if header[1] != DT_CONFIG {
        return Err(DescError::WrongType);
    }
    Ok(u16::from_le_bytes([header[2], header[3]]))
}

/// The fields of an endpoint descriptor `d` (at least 7 bytes).
fn endpoint_from(d: &[u8]) -> EndpointDesc {
    let w = u16::from_le_bytes([d[4], d[5]]);
    EndpointDesc {
        address: d[2],
        attrs: d[3],
        mps: w & 0x7ff,
        mult: ((w >> 11) & 3) as u8,
        interval: d[6],
        ..EndpointDesc::default()
    }
}

/// Walk the descriptors of `b` (a configuration descriptor and everything
/// after it, up to wTotalLength). A descriptor with a length under 2 or past
/// the end ends the walk with [`DescError::Truncated`] (what was read before
/// it is still returned by [`parse_config_lenient`]).
pub fn parse_config(b: &[u8]) -> Result<ConfigDesc, DescError> {
    let (c, err) = parse_config_lenient(b);
    match err {
        Some(e) => Err(e),
        None => c.ok_or(DescError::Truncated),
    }
}

/// As [`parse_config`], but keeps what was read before a damaged descriptor.
pub fn parse_config_lenient(b: &[u8]) -> (Option<ConfigDesc>, Option<DescError>) {
    if b.len() < 9 || b[0] < 9 {
        return (None, Some(DescError::Truncated));
    }
    if b[1] != DT_CONFIG {
        return (None, Some(DescError::WrongType));
    }
    let total = (u16::from_le_bytes([b[2], b[3]]) as usize).min(b.len());
    let mut c = ConfigDesc {
        value: b[5],
        attrs: b[7],
        max_power: b[8],
        total_len: u16::from_le_bytes([b[2], b[3]]),
        ..ConfigDesc::default()
    };
    let mut off = b[0] as usize;
    // Index of the interface descriptor the endpoints that follow belong to;
    // None while they belong to an alternate setting or to a dropped one.
    let mut cur: Option<usize> = None;
    // The alternate setting of the interface descriptor `cur` stands for.
    let mut cur_alt = 0u8;
    let mut last_ep: Option<(usize, usize)> = None;
    // The setting (interface number, setting) whose endpoints are being
    // listed in the alternate table, and the entry of the last one.
    let mut alt_cur: Option<(u8, u8)> = None;
    let mut last_alt_ep: Option<usize> = None;
    while off < total {
        let len = b[off] as usize;
        if len < 2 || off + len > total {
            return (Some(c), Some(DescError::Truncated));
        }
        let d = &b[off..off + len];
        match d[1] {
            DT_INTERFACE if len >= 9 => {
                last_ep = None;
                last_alt_ep = None;
                let (num, alt) = (d[2], d[3]);
                alt_cur = if alt != 0 && c.interfaces().iter().any(|i| i.number == num) { Some((num, alt)) } else { None };
                if alt != 0 {
                    // An alternate setting of an interface already listed. One
                    // that has no endpoint in setting 0 takes the endpoints of
                    // the first alternate setting that has some.
                    cur = None;
                    if let Some(i) = c.interfaces().iter().position(|i| i.number == num) {
                        c.interfaces[i].alternates = c.interfaces[i].alternates.saturating_add(1);
                        if c.interfaces[i].num_endpoints == 0 {
                            cur = Some(i);
                            cur_alt = alt;
                        }
                    }
                } else if (c.num_interfaces as usize) < MAX_IFACES {
                    let i = c.num_interfaces as usize;
                    c.interfaces[i] = InterfaceDesc {
                        number: num,
                        class: d[5],
                        subclass: d[6],
                        protocol: d[7],
                        i_interface: d[8],
                        ..InterfaceDesc::default()
                    };
                    c.num_interfaces += 1;
                    cur = Some(i);
                    cur_alt = 0;
                } else {
                    c.dropped = c.dropped.saturating_add(1);
                    cur = None;
                }
            }
            DT_ENDPOINT if len >= 7 => {
                if let Some((iface, alt)) = alt_cur {
                    let n = c.num_alt_endpoints as usize;
                    if n < MAX_ALT_EPS {
                        c.alt_endpoints[n] = AltEndpoint { iface, alt, ep: endpoint_from(d) };
                        c.num_alt_endpoints += 1;
                        last_alt_ep = Some(n);
                    } else {
                        c.dropped = c.dropped.saturating_add(1);
                        last_alt_ep = None;
                    }
                }
                if let Some(i) = cur {
                    let n = c.interfaces[i].num_endpoints as usize;
                    if n < MAX_EPS {
                        if n == 0 {
                            c.interfaces[i].alt_setting = cur_alt;
                        }
                        c.interfaces[i].endpoints[n] = endpoint_from(d);
                        c.interfaces[i].num_endpoints += 1;
                        last_ep = Some((i, n));
                    } else {
                        c.dropped = c.dropped.saturating_add(1);
                        last_ep = None;
                    }
                }
            }
            DT_SS_ENDPOINT_COMPANION if len >= 6 => {
                if let Some(n) = last_alt_ep {
                    let e = &mut c.alt_endpoints[n].ep;
                    e.burst = d[2];
                    e.ss_attrs = d[3];
                    e.bytes_per_interval = u16::from_le_bytes([d[4], d[5]]);
                    e.has_companion = true;
                }
                if let Some((i, n)) = last_ep {
                    let e = &mut c.interfaces[i].endpoints[n];
                    e.burst = d[2];
                    e.ss_attrs = d[3];
                    e.bytes_per_interval = u16::from_le_bytes([d[4], d[5]]);
                    e.has_companion = true;
                }
            }
            _ => {}
        }
        off += len;
    }
    (Some(c), None)
}

// ---- BOS ----

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Bos {
    /// The USB 2.0 extension capability is present and advertises LPM.
    pub lpm: bool,
    /// SuperSpeed capability present: wSpeedsSupported, bU1DevExitLat and
    /// wU2DevExitLat.
    pub superspeed: bool,
    pub speeds_supported: u16,
    pub u1_exit_lat: u8,
    pub u2_exit_lat: u16,
    pub superspeed_plus: bool,
}

pub fn bos_total_len(header: &[u8]) -> Result<u16, DescError> {
    if header.len() < 5 || header[0] < 5 {
        return Err(DescError::Truncated);
    }
    if header[1] != DT_BOS {
        return Err(DescError::WrongType);
    }
    Ok(u16::from_le_bytes([header[2], header[3]]))
}

pub fn parse_bos(b: &[u8]) -> Result<Bos, DescError> {
    bos_total_len(b)?;
    let total = (u16::from_le_bytes([b[2], b[3]]) as usize).min(b.len());
    let mut out = Bos::default();
    let mut off = b[0] as usize;
    while off < total {
        let len = b[off] as usize;
        if len < 3 || off + len > total {
            return Err(DescError::Truncated);
        }
        let d = &b[off..off + len];
        if d[1] == DT_DEVICE_CAPABILITY {
            match d[2] {
                CAP_USB2_EXT if len >= 7 => {
                    let attrs = u32::from_le_bytes([d[3], d[4], d[5], d[6]]);
                    out.lpm = attrs & (1 << 1) != 0;
                }
                CAP_SUPERSPEED if len >= 10 => {
                    out.superspeed = true;
                    out.speeds_supported = u16::from_le_bytes([d[4], d[5]]);
                    out.u1_exit_lat = d[7];
                    out.u2_exit_lat = u16::from_le_bytes([d[8], d[9]]);
                }
                CAP_SUPERSPEED_PLUS => out.superspeed_plus = true,
                _ => {}
            }
        }
        off += len;
    }
    Ok(out)
}

// ---- Hub ----

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HubDesc {
    pub ports: u8,
    /// wHubCharacteristics.
    pub characteristics: u16,
    /// Milliseconds from power-on of a port to its power being good
    /// (bPwrOn2PwrGood is in 2 ms units).
    pub power_good_ms: u16,
    pub superspeed: bool,
}

impl HubDesc {
    /// The hub gives each port its own power switch (characteristics bits 1:0
    /// are 0 or 1); a ganged hub powers every port by one switch.
    pub fn per_port_power(&self) -> bool {
        self.characteristics & 3 == 1
    }
    /// TT think time in full-speed bit times (8, 16, 24, 32), bits 6:5.
    pub fn tt_think_time(&self) -> u8 {
        ((self.characteristics >> 5) & 3) as u8
    }
}

pub fn parse_hub(b: &[u8]) -> Result<HubDesc, DescError> {
    if b.len() < 7 || b[0] < 7 {
        return Err(DescError::Truncated);
    }
    let superspeed = match b[1] {
        DT_HUB => false,
        DT_SS_HUB => true,
        _ => return Err(DescError::WrongType),
    };
    Ok(HubDesc {
        ports: b[2],
        characteristics: u16::from_le_bytes([b[3], b[4]]),
        power_good_ms: (b[5] as u16) * 2,
        superspeed,
    })
}

// ---- Strings ----

/// A string descriptor's text as ASCII into `out` (UTF-16 code units outside
/// 0x20..0x7e become `?`); the number of bytes written.
pub fn string_ascii(b: &[u8], out: &mut [u8]) -> usize {
    if b.len() < 2 || b[1] != DT_STRING {
        return 0;
    }
    let len = (b[0] as usize).min(b.len());
    let mut n = 0;
    let mut i = 2;
    while i + 1 < len && n < out.len() {
        let u = u16::from_le_bytes([b[i], b[i + 1]]);
        out[n] = if (0x20..0x7f).contains(&u) { u as u8 } else { b'?' };
        n += 1;
        i += 2;
    }
    n
}

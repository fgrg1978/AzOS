// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! HCI: the commands the host sends and the events it understands.
//!
//! Only what the host uses: the controller's initialisation, advertising,
//! scanning, one connection at a time being created, link encryption with a
//! long term key, and the events that answer them. An event the host does not
//! use decodes to [`Event::Other`]; a short or malformed one is an [`Error`].

use crate::{le16, put16, Error, PeerAddr};

/// `OGF << 10 | OCF`.
pub const fn opcode(ogf: u16, ocf: u16) -> u16 {
    ogf << 10 | ocf
}

pub const OP_DISCONNECT: u16 = opcode(0x01, 0x0006);
pub const OP_SET_EVENT_MASK: u16 = opcode(0x03, 0x0001);
pub const OP_RESET: u16 = opcode(0x03, 0x0003);
pub const OP_READ_BD_ADDR: u16 = opcode(0x04, 0x0009);
pub const OP_LE_SET_EVENT_MASK: u16 = opcode(0x08, 0x0001);
pub const OP_LE_READ_BUFFER_SIZE: u16 = opcode(0x08, 0x0002);
pub const OP_LE_SET_RANDOM_ADDRESS: u16 = opcode(0x08, 0x0005);
pub const OP_LE_SET_ADV_PARAMS: u16 = opcode(0x08, 0x0006);
pub const OP_LE_SET_ADV_DATA: u16 = opcode(0x08, 0x0008);
pub const OP_LE_SET_SCAN_RSP_DATA: u16 = opcode(0x08, 0x0009);
pub const OP_LE_SET_ADV_ENABLE: u16 = opcode(0x08, 0x000A);
pub const OP_LE_SET_SCAN_PARAMS: u16 = opcode(0x08, 0x000B);
pub const OP_LE_SET_SCAN_ENABLE: u16 = opcode(0x08, 0x000C);
pub const OP_LE_CREATE_CONNECTION: u16 = opcode(0x08, 0x000D);
pub const OP_LE_CREATE_CONNECTION_CANCEL: u16 = opcode(0x08, 0x000E);
pub const OP_LE_CONNECTION_UPDATE: u16 = opcode(0x08, 0x0013);
pub const OP_LE_START_ENCRYPTION: u16 = opcode(0x08, 0x0019);
pub const OP_LE_LTK_REPLY: u16 = opcode(0x08, 0x001A);
pub const OP_LE_LTK_NEGATIVE_REPLY: u16 = opcode(0x08, 0x001B);

/// Status codes the host names.
pub mod status {
    pub const SUCCESS: u8 = 0x00;
    pub const UNKNOWN_COMMAND: u8 = 0x01;
    pub const AUTH_FAILURE: u8 = 0x05;
    pub const CONNECTION_TIMEOUT: u8 = 0x08;
    pub const REMOTE_USER_TERMINATED: u8 = 0x13;
    pub const LOCAL_HOST_TERMINATED: u8 = 0x16;
    pub const PAIRING_NOT_ALLOWED: u8 = 0x18;
    /// Not a controller code: the host's own answer to a command that never
    /// completed.
    pub const HOST_TIMEOUT: u8 = 0xFF;
}

/// Event codes.
pub const EVT_DISCONNECTION_COMPLETE: u8 = 0x05;
pub const EVT_ENCRYPTION_CHANGE: u8 = 0x08;
pub const EVT_COMMAND_COMPLETE: u8 = 0x0E;
pub const EVT_COMMAND_STATUS: u8 = 0x0F;
pub const EVT_HARDWARE_ERROR: u8 = 0x10;
pub const EVT_NUM_COMPLETED_PACKETS: u8 = 0x13;
pub const EVT_LE_META: u8 = 0x3E;

/// LE meta subevents.
pub const LE_CONNECTION_COMPLETE: u8 = 0x01;
pub const LE_ADVERTISING_REPORT: u8 = 0x02;
pub const LE_CONNECTION_UPDATE_COMPLETE: u8 = 0x03;
pub const LE_LTK_REQUEST: u8 = 0x05;

/// Most parameter bytes of a command the host builds.
pub const CMD_PARAM_MAX: usize = 32;

/// Advertising PDU types (`LE Set Advertising Parameters`).
pub const ADV_IND: u8 = 0x00;
pub const ADV_SCAN_IND: u8 = 0x02;
pub const ADV_NONCONN_IND: u8 = 0x03;

/// The event mask the host sets: disconnection, encryption change, command
/// complete and status, hardware error, number of completed packets (the
/// bits of "Set Event Mask" the controller needs to send what flow control and
/// the link need) and the LE meta event.
pub const EVENT_MASK: u64 = 1 << 4 | 1 << 7 | 1 << 13 | 1 << 14 | 1 << 15 | 1 << 18 | 1 << 61;
/// The LE event mask: connection complete, advertising report, connection
/// update complete, long term key request.
pub const LE_EVENT_MASK: u64 = 1 << 0 | 1 << 1 | 1 << 2 | 1 << 4;

/// Advertising parameters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AdvParams {
    /// Units of 0.625 ms, 0x0020..=0x4000.
    pub interval_min: u16,
    pub interval_max: u16,
    /// `ADV_IND` (connectable), `ADV_SCAN_IND` or `ADV_NONCONN_IND`.
    pub kind: u8,
    /// `0` public, `1` random.
    pub own_addr_type: u8,
    /// Channels 37, 38 and 39 as bits 0..=2.
    pub channel_map: u8,
}

/// Scan parameters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScanParams {
    pub active: bool,
    /// Units of 0.625 ms.
    pub interval: u16,
    pub window: u16,
    pub own_addr_type: u8,
}

/// Parameters of a connection being created or updated.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConnParams {
    /// Units of 1.25 ms, 6..=3200.
    pub interval_min: u16,
    pub interval_max: u16,
    /// Connection events the peripheral may skip.
    pub latency: u16,
    /// Units of 10 ms, 10..=3200.
    pub timeout: u16,
}

impl ConnParams {
    /// The ranges the specification allows, and a timeout that outlasts the
    /// slave latency (`timeout > (1 + latency) * interval_max * 2`, in ms).
    pub fn valid(&self) -> bool {
        let t_ms = self.timeout as u32 * 10;
        let span_ms = (1 + self.latency as u32) * self.interval_max as u32 * 5 / 2;
        (6..=3200).contains(&self.interval_min)
            && (self.interval_min..=3200).contains(&self.interval_max)
            && self.latency <= 499
            && (10..=3200).contains(&self.timeout)
            && t_ms > span_ms
    }
}

/// A command the host sends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cmd {
    Reset,
    SetEventMask(u64),
    ReadBdAddr,
    LeSetEventMask(u64),
    LeReadBufferSize,
    LeSetRandomAddress([u8; 6]),
    LeSetAdvParams(AdvParams),
    LeSetAdvData { len: u8, data: [u8; 31] },
    LeSetScanRspData { len: u8, data: [u8; 31] },
    LeSetAdvEnable(bool),
    LeSetScanParams(ScanParams),
    LeSetScanEnable { enable: bool, filter_duplicates: bool },
    LeCreateConnection { peer: PeerAddr, own_addr_type: u8, params: ConnParams },
    LeCreateConnectionCancel,
    LeConnectionUpdate { handle: u16, params: ConnParams },
    Disconnect { handle: u16, reason: u8 },
    LeStartEncryption { handle: u16, rand: [u8; 8], ediv: u16, ltk: [u8; 16] },
    LeLtkReply { handle: u16, ltk: [u8; 16] },
    LeLtkNegativeReply { handle: u16 },
}

impl Cmd {
    /// The opcode and the parameter block into `out`.
    pub fn encode(&self, out: &mut [u8; CMD_PARAM_MAX]) -> (u16, usize) {
        *out = [0; CMD_PARAM_MAX];
        match *self {
            Cmd::Reset => (OP_RESET, 0),
            Cmd::SetEventMask(m) => {
                out[..8].copy_from_slice(&m.to_le_bytes());
                (OP_SET_EVENT_MASK, 8)
            }
            Cmd::ReadBdAddr => (OP_READ_BD_ADDR, 0),
            Cmd::LeSetEventMask(m) => {
                out[..8].copy_from_slice(&m.to_le_bytes());
                (OP_LE_SET_EVENT_MASK, 8)
            }
            Cmd::LeReadBufferSize => (OP_LE_READ_BUFFER_SIZE, 0),
            Cmd::LeSetRandomAddress(a) => {
                out[..6].copy_from_slice(&a);
                (OP_LE_SET_RANDOM_ADDRESS, 6)
            }
            Cmd::LeSetAdvParams(p) => {
                put16(out, 0, p.interval_min);
                put16(out, 2, p.interval_max);
                out[4] = p.kind;
                out[5] = p.own_addr_type;
                // Peer address type and address: unused for undirected advertising.
                out[13] = p.channel_map;
                out[14] = 0; // allow scan and connect requests from any device
                (OP_LE_SET_ADV_PARAMS, 15)
            }
            Cmd::LeSetAdvData { len, data } => {
                out[0] = len;
                out[1..32].copy_from_slice(&data);
                (OP_LE_SET_ADV_DATA, 32)
            }
            Cmd::LeSetScanRspData { len, data } => {
                out[0] = len;
                out[1..32].copy_from_slice(&data);
                (OP_LE_SET_SCAN_RSP_DATA, 32)
            }
            Cmd::LeSetAdvEnable(on) => {
                out[0] = on as u8;
                (OP_LE_SET_ADV_ENABLE, 1)
            }
            Cmd::LeSetScanParams(p) => {
                out[0] = p.active as u8;
                put16(out, 1, p.interval);
                put16(out, 3, p.window);
                out[5] = p.own_addr_type;
                out[6] = 0; // accept all advertisers
                (OP_LE_SET_SCAN_PARAMS, 7)
            }
            Cmd::LeSetScanEnable { enable, filter_duplicates } => {
                out[0] = enable as u8;
                out[1] = filter_duplicates as u8;
                (OP_LE_SET_SCAN_ENABLE, 2)
            }
            Cmd::LeCreateConnection { peer, own_addr_type, params } => {
                put16(out, 0, 0x0060); // scan interval, 60 ms
                put16(out, 2, 0x0030); // scan window, 30 ms
                out[4] = 0; // the peer below, not a filter list
                out[5] = peer.kind;
                out[6..12].copy_from_slice(&peer.addr);
                out[12] = own_addr_type;
                put16(out, 13, params.interval_min);
                put16(out, 15, params.interval_max);
                put16(out, 17, params.latency);
                put16(out, 19, params.timeout);
                // Connection event length bounds: no constraint.
                (OP_LE_CREATE_CONNECTION, 25)
            }
            Cmd::LeCreateConnectionCancel => (OP_LE_CREATE_CONNECTION_CANCEL, 0),
            Cmd::LeConnectionUpdate { handle, params } => {
                put16(out, 0, handle);
                put16(out, 2, params.interval_min);
                put16(out, 4, params.interval_max);
                put16(out, 6, params.latency);
                put16(out, 8, params.timeout);
                (OP_LE_CONNECTION_UPDATE, 14)
            }
            Cmd::Disconnect { handle, reason } => {
                put16(out, 0, handle);
                out[2] = reason;
                (OP_DISCONNECT, 3)
            }
            Cmd::LeStartEncryption { handle, rand, ediv, ltk } => {
                put16(out, 0, handle);
                out[2..10].copy_from_slice(&rand);
                put16(out, 10, ediv);
                out[12..28].copy_from_slice(&ltk);
                (OP_LE_START_ENCRYPTION, 28)
            }
            Cmd::LeLtkReply { handle, ltk } => {
                put16(out, 0, handle);
                out[2..18].copy_from_slice(&ltk);
                (OP_LE_LTK_REPLY, 18)
            }
            Cmd::LeLtkNegativeReply { handle } => {
                put16(out, 0, handle);
                (OP_LE_LTK_NEGATIVE_REPLY, 2)
            }
        }
    }
}

/// `LE Connection Complete`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConnComplete {
    pub status: u8,
    pub handle: u16,
    /// `0` central (initiator), `1` peripheral.
    pub role: u8,
    pub peer: PeerAddr,
    pub interval: u16,
    pub latency: u16,
    pub timeout: u16,
}

/// One advertising report.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AdvReport<'a> {
    /// `ADV_IND`, `ADV_DIRECT_IND`, `ADV_SCAN_IND`, `ADV_NONCONN_IND`, `SCAN_RSP`.
    pub kind: u8,
    pub peer: PeerAddr,
    pub data: &'a [u8],
    /// dBm, `127` when the controller does not know.
    pub rssi: i8,
}

/// The reports of one `LE Advertising Report`, in the spec's layout (arrays of
/// each field, so a report's data starts after the lengths of the ones before).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AdvReports<'a> {
    raw: &'a [u8],
    n: usize,
}

impl<'a> AdvReports<'a> {
    fn parse(p: &'a [u8]) -> Result<AdvReports<'a>, Error> {
        let n = *p.first().ok_or(Error::Short)? as usize;
        if n == 0 || p.len() < 1 + 9 * n {
            return Err(Error::Short);
        }
        let total: usize = (0..n).map(|i| p[1 + 8 * n + i] as usize).sum();
        if p.len() < 1 + 9 * n + total {
            return Err(Error::Short);
        }
        Ok(AdvReports { raw: p, n })
    }

    pub fn len(&self) -> usize {
        self.n
    }

    pub fn is_empty(&self) -> bool {
        self.n == 0
    }

    pub fn get(&self, i: usize) -> Option<AdvReport<'a>> {
        if i >= self.n {
            return None;
        }
        let (p, n) = (self.raw, self.n);
        let off: usize = (0..i).map(|j| p[1 + 8 * n + j] as usize).sum();
        let len = p[1 + 8 * n + i] as usize;
        let data_at = 1 + 9 * n + off;
        let mut addr = [0u8; 6];
        addr.copy_from_slice(&p[1 + 2 * n + 6 * i..1 + 2 * n + 6 * i + 6]);
        let total: usize = (0..n).map(|j| p[1 + 8 * n + j] as usize).sum();
        Some(AdvReport {
            kind: p[1 + i],
            peer: PeerAddr { kind: p[1 + n + i], addr },
            data: &p[data_at..data_at + len],
            rssi: p[1 + 9 * n + total + i] as i8,
        })
    }
}

/// `Number Of Completed Packets`: pairs of handle and count.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Completed<'a> {
    raw: &'a [u8],
    n: usize,
}

impl<'a> Completed<'a> {
    pub fn len(&self) -> usize {
        self.n
    }

    pub fn is_empty(&self) -> bool {
        self.n == 0
    }

    pub fn get(&self, i: usize) -> Option<(u16, u16)> {
        if i >= self.n {
            return None;
        }
        Some((le16(self.raw, 1 + 2 * i) & 0x0FFF, le16(self.raw, 1 + 2 * self.n + 2 * i)))
    }
}

/// A decoded event.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event<'a> {
    CommandComplete { ncmd: u8, opcode: u16, ret: &'a [u8] },
    CommandStatus { status: u8, ncmd: u8, opcode: u16 },
    DisconnectionComplete { status: u8, handle: u16, reason: u8 },
    EncryptionChange { status: u8, handle: u16, enabled: u8 },
    HardwareError(u8),
    NumCompletedPackets(Completed<'a>),
    LeConnectionComplete(ConnComplete),
    LeAdvertisingReport(AdvReports<'a>),
    LeConnectionUpdateComplete { status: u8, handle: u16, interval: u16, latency: u16, timeout: u16 },
    LeLtkRequest { handle: u16, rand: [u8; 8], ediv: u16 },
    /// An event the host does not use.
    Other(u8),
}

impl<'a> Event<'a> {
    /// Decode an event packet body (`code, length, parameters`).
    pub fn parse(body: &'a [u8]) -> Result<Event<'a>, Error> {
        if body.len() < 2 {
            return Err(Error::Short);
        }
        let code = body[0];
        let p = &body[2..];
        if p.len() != body[1] as usize {
            return Err(Error::Invalid);
        }
        let need = |n: usize| if p.len() >= n { Ok(()) } else { Err(Error::Short) };
        Ok(match code {
            EVT_COMMAND_COMPLETE => {
                need(3)?;
                Event::CommandComplete { ncmd: p[0], opcode: le16(p, 1), ret: &p[3..] }
            }
            EVT_COMMAND_STATUS => {
                need(4)?;
                Event::CommandStatus { status: p[0], ncmd: p[1], opcode: le16(p, 2) }
            }
            EVT_DISCONNECTION_COMPLETE => {
                need(4)?;
                Event::DisconnectionComplete { status: p[0], handle: le16(p, 1) & 0x0FFF, reason: p[3] }
            }
            EVT_ENCRYPTION_CHANGE => {
                need(4)?;
                Event::EncryptionChange { status: p[0], handle: le16(p, 1) & 0x0FFF, enabled: p[3] }
            }
            EVT_HARDWARE_ERROR => {
                need(1)?;
                Event::HardwareError(p[0])
            }
            EVT_NUM_COMPLETED_PACKETS => {
                need(1)?;
                let n = p[0] as usize;
                need(1 + 4 * n)?;
                Event::NumCompletedPackets(Completed { raw: p, n })
            }
            EVT_LE_META => {
                need(1)?;
                let sub = p[0];
                let q = &p[1..];
                let needq = |n: usize| if q.len() >= n { Ok(()) } else { Err(Error::Short) };
                match sub {
                    LE_CONNECTION_COMPLETE => {
                        needq(18)?;
                        let mut addr = [0u8; 6];
                        addr.copy_from_slice(&q[5..11]);
                        Event::LeConnectionComplete(ConnComplete {
                            status: q[0],
                            handle: le16(q, 1) & 0x0FFF,
                            role: q[3],
                            peer: PeerAddr { kind: q[4], addr },
                            interval: le16(q, 11),
                            latency: le16(q, 13),
                            timeout: le16(q, 15),
                        })
                    }
                    LE_ADVERTISING_REPORT => Event::LeAdvertisingReport(AdvReports::parse(q)?),
                    LE_CONNECTION_UPDATE_COMPLETE => {
                        needq(9)?;
                        Event::LeConnectionUpdateComplete {
                            status: q[0],
                            handle: le16(q, 1) & 0x0FFF,
                            interval: le16(q, 3),
                            latency: le16(q, 5),
                            timeout: le16(q, 7),
                        }
                    }
                    LE_LTK_REQUEST => {
                        needq(12)?;
                        let mut rand = [0u8; 8];
                        rand.copy_from_slice(&q[2..10]);
                        Event::LeLtkRequest { handle: le16(q, 0) & 0x0FFF, rand, ediv: le16(q, 10) }
                    }
                    _ => Event::Other(code),
                }
            }
            _ => Event::Other(code),
        })
    }
}

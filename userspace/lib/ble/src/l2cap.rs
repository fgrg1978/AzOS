// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! L2CAP over LE: the ACL header, reassembly of a basic frame from its
//! fragments, fragmentation of one for the controller's buffers, and the LE
//! signalling channel (Core Vol 3 Part A).
//!
//! LE uses three fixed channels: ATT (4), signalling (5) and SMP (6). The
//! credit-based channels are refused (no PSM is registered; the host answers a
//! connection request with "PSM not supported"), which is all the signalling
//! the host needs to run the two other channels and the connection parameters.

use crate::{le16, put16, Error, L2CAP_MTU};

pub use crate::att::CID_ATT;
/// Fixed channel of the LE signalling commands.
pub const CID_SIGNALLING: u16 = 0x0005;
/// Fixed channel of SMP.
pub const CID_SMP: u16 = 0x0006;

/// Packet-boundary flag: first fragment of a frame.
pub const PB_FIRST: u8 = 0b00;
/// Packet-boundary flag: continuation.
pub const PB_CONTINUATION: u8 = 0b01;

/// The ACL header of a packet body (`handle+flags, length`, then the data).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AclHeader {
    pub handle: u16,
    /// Packet-boundary flags: `0b00` and `0b10` start a frame, `0b01` continues.
    pub pb: u8,
}

/// Split an ACL packet body into its header and its data.
pub fn parse_acl(body: &[u8]) -> Result<(AclHeader, &[u8]), Error> {
    if body.len() < 4 {
        return Err(Error::Short);
    }
    let hf = le16(body, 0);
    let len = le16(body, 2) as usize;
    if body.len() != 4 + len {
        return Err(Error::Invalid);
    }
    Ok((AclHeader { handle: hf & 0x0FFF, pb: (hf >> 12) as u8 & 3 }, &body[4..]))
}

/// What reassembly produced.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reassembled {
    /// More fragments are due.
    Pending,
    /// A whole frame: its channel and its length (bytes at [`Reassembler::frame`]).
    Frame { cid: u16, len: usize },
    /// The fragment broke the rules (a continuation with no frame begun, a new
    /// frame inside one, more data than the header announced, a frame past
    /// [`L2CAP_MTU`]); the frame in progress is dropped.
    Dropped,
}

/// Reassembly of the frames of one connection.
pub struct Reassembler {
    buf: [u8; L2CAP_MTU],
    cid: u16,
    expect: usize,
    have: usize,
    active: bool,
    pub dropped: u32,
}

impl Default for Reassembler {
    fn default() -> Self {
        Self::new()
    }
}

impl Reassembler {
    pub const fn new() -> Reassembler {
        Reassembler { buf: [0; L2CAP_MTU], cid: 0, expect: 0, have: 0, active: false, dropped: 0 }
    }

    /// Forget a frame in progress (a new connection).
    pub fn clear(&mut self) {
        self.active = false;
    }

    /// The payload of the frame [`push`](Self::push) completed.
    pub fn frame(&self, len: usize) -> &[u8] {
        &self.buf[..len]
    }

    /// Take the data of one ACL packet of this connection.
    pub fn push(&mut self, pb: u8, data: &[u8]) -> Reassembled {
        match pb {
            PB_CONTINUATION => {
                if !self.active || self.have + data.len() > self.expect {
                    return self.drop_frame();
                }
                self.buf[self.have..self.have + data.len()].copy_from_slice(data);
                self.have += data.len();
            }
            PB_FIRST | 0b10 => {
                if self.active || data.len() < 4 {
                    // A frame began inside one, or the header itself is cut:
                    // the header is never split by a sane controller.
                    return self.drop_frame();
                }
                let len = le16(data, 0) as usize;
                if len > L2CAP_MTU || data.len() - 4 > len {
                    return self.drop_frame();
                }
                self.cid = le16(data, 2);
                self.expect = len;
                self.buf[..data.len() - 4].copy_from_slice(&data[4..]);
                self.have = data.len() - 4;
                self.active = true;
            }
            _ => return self.drop_frame(),
        }
        if self.have == self.expect {
            self.active = false;
            Reassembled::Frame { cid: self.cid, len: self.have }
        } else {
            Reassembled::Pending
        }
    }

    fn drop_frame(&mut self) -> Reassembled {
        self.active = false;
        self.dropped += 1;
        Reassembled::Dropped
    }
}

/// Header of a basic frame into `out`, then the payload: the whole frame, or
/// `None` when it does not fit.
pub fn frame(cid: u16, payload: &[u8], out: &mut [u8]) -> Option<usize> {
    let n = 4 + payload.len();
    if payload.len() > L2CAP_MTU || out.len() < n {
        return None;
    }
    put16(out, 0, payload.len() as u16);
    put16(out, 2, cid);
    out[4..n].copy_from_slice(payload);
    Some(n)
}

/// Signalling codes.
pub mod sig {
    pub const COMMAND_REJECT: u8 = 0x01;
    pub const DISCONNECTION_REQ: u8 = 0x06;
    pub const CONNECTION_PARAMETER_UPDATE_REQ: u8 = 0x12;
    pub const CONNECTION_PARAMETER_UPDATE_RSP: u8 = 0x13;
    pub const LE_CREDIT_CONNECTION_REQ: u8 = 0x14;
    pub const LE_CREDIT_CONNECTION_RSP: u8 = 0x15;
    /// LE flow control credit: a grant for a channel, never answered.
    pub const FLOW_CONTROL_CREDIT: u8 = 0x16;
    /// Command Reject reasons.
    pub const REASON_NOT_UNDERSTOOD: u16 = 0x0000;
    pub const REASON_INVALID_CID: u16 = 0x0002;
    /// LE credit connection result: PSM not supported.
    pub const RESULT_PSM_NOT_SUPPORTED: u16 = 0x0002;
    /// Connection parameter update result.
    pub const UPDATE_ACCEPTED: u16 = 0x0000;
    pub const UPDATE_REJECTED: u16 = 0x0001;
}

/// A signalling command the host understands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Signal {
    CommandReject { id: u8, reason: u16 },
    /// A channel disconnection request for a channel the host does not have.
    DisconnectionReq { id: u8, dcid: u16, scid: u16 },
    ConnectionParameterUpdateReq { id: u8, interval_min: u16, interval_max: u16, latency: u16, timeout: u16 },
    ConnectionParameterUpdateRsp { id: u8, result: u16 },
    LeCreditConnectionReq { id: u8, psm: u16, scid: u16 },
    LeCreditConnectionRsp { id: u8, result: u16 },
    /// A command code the host does not decode (the identifier answers it).
    Other { code: u8, id: u8 },
}

impl Signal {
    /// Decode one command (an LE signalling frame holds exactly one).
    pub fn parse(b: &[u8]) -> Result<Signal, Error> {
        if b.len() < 4 {
            return Err(Error::Short);
        }
        let (code, id, len) = (b[0], b[1], le16(b, 2) as usize);
        if b.len() != 4 + len {
            return Err(Error::Invalid);
        }
        let p = &b[4..];
        let need = |n: usize| if p.len() >= n { Ok(()) } else { Err(Error::Short) };
        Ok(match code {
            sig::COMMAND_REJECT => {
                need(2)?;
                Signal::CommandReject { id, reason: le16(p, 0) }
            }
            sig::DISCONNECTION_REQ => {
                need(4)?;
                Signal::DisconnectionReq { id, dcid: le16(p, 0), scid: le16(p, 2) }
            }
            sig::CONNECTION_PARAMETER_UPDATE_REQ => {
                need(8)?;
                Signal::ConnectionParameterUpdateReq {
                    id,
                    interval_min: le16(p, 0),
                    interval_max: le16(p, 2),
                    latency: le16(p, 4),
                    timeout: le16(p, 6),
                }
            }
            sig::CONNECTION_PARAMETER_UPDATE_RSP => {
                need(2)?;
                Signal::ConnectionParameterUpdateRsp { id, result: le16(p, 0) }
            }
            sig::LE_CREDIT_CONNECTION_REQ => {
                need(10)?;
                Signal::LeCreditConnectionReq { id, psm: le16(p, 0), scid: le16(p, 2) }
            }
            _ => Signal::Other { code, id },
        })
    }

    /// Encode into `out`; the bytes written.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, Error> {
        let mut body = [0u8; 10];
        let (code, id, n) = match *self {
            Signal::CommandReject { id, reason } => {
                put16(&mut body, 0, reason);
                (sig::COMMAND_REJECT, id, 2)
            }
            Signal::ConnectionParameterUpdateReq { id, interval_min, interval_max, latency, timeout } => {
                put16(&mut body, 0, interval_min);
                put16(&mut body, 2, interval_max);
                put16(&mut body, 4, latency);
                put16(&mut body, 6, timeout);
                (sig::CONNECTION_PARAMETER_UPDATE_REQ, id, 8)
            }
            Signal::ConnectionParameterUpdateRsp { id, result } => {
                put16(&mut body, 0, result);
                (sig::CONNECTION_PARAMETER_UPDATE_RSP, id, 2)
            }
            // dcid 0, mtu/mps 0, credits 0 and the result: a refusal.
            Signal::LeCreditConnectionRsp { id, result } => {
                put16(&mut body, 8, result);
                (sig::LE_CREDIT_CONNECTION_RSP, id, 10)
            }
            // The requests below are what a peer sends us; this host only answers them.
            Signal::DisconnectionReq { .. } | Signal::LeCreditConnectionReq { .. } | Signal::Other { .. } => {
                return Err(Error::Invalid)
            }
        };
        if out.len() < 4 + n {
            return Err(Error::NoRoom);
        }
        out[0] = code;
        out[1] = id;
        put16(out, 2, n as u16);
        out[4..4 + n].copy_from_slice(&body[..n]);
        Ok(4 + n)
    }
}

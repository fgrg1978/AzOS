// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Device and input contexts (xHCI 1.2, section 6.2).
//!
//! A controller reports HCCPARAMS1.CSZ: its context entries are 32 or 64
//! bytes. Everything here takes the entry size; a driver that assumed 32
//! would put the endpoint contexts at the wrong offsets on a 64-byte
//! controller and the controller would read garbage as an endpoint.
//!
//! Layouts, with `S` the entry size:
//!
//! - device context: slot context at `0`, endpoint context of device context
//!   index (DCI) `n` at `S * n` (DCI 1 is endpoint 0, then OUT before IN: DCI
//!   `2*ep + dir_in`);
//! - input context: the input control context at `0`, the slot context at
//!   `S`, DCI `n` at `S * (n + 1)`.

use super::regs::Speed;
use crate::hw::DmaBuf;

pub const EP_TYPE_ISOCH_OUT: u8 = 1;
pub const EP_TYPE_BULK_OUT: u8 = 2;
pub const EP_TYPE_INT_OUT: u8 = 3;
pub const EP_TYPE_CONTROL: u8 = 4;
pub const EP_TYPE_ISOCH_IN: u8 = 5;
pub const EP_TYPE_BULK_IN: u8 = 6;
pub const EP_TYPE_INT_IN: u8 = 7;

/// Endpoint context states.
pub const EP_DISABLED: u8 = 0;
pub const EP_RUNNING: u8 = 1;
pub const EP_HALTED: u8 = 2;
pub const EP_STOPPED: u8 = 3;
pub const EP_ERROR: u8 = 4;

/// Slot states.
pub const SLOT_DISABLED_OR_ENABLED: u8 = 0;
pub const SLOT_DEFAULT: u8 = 1;
pub const SLOT_ADDRESSED: u8 = 2;
pub const SLOT_CONFIGURED: u8 = 3;

/// The device context index of endpoint address `ep` (bit 7 = IN): 1 for
/// endpoint 0 (control, both directions), `2*n + dir_in` otherwise.
pub fn dci(ep: u8) -> u8 {
    let n = ep & 0x0f;
    if n == 0 {
        1
    } else {
        2 * n + (ep >> 7)
    }
}

/// Where the slot context and endpoint contexts live in an input context.
#[derive(Clone, Copy, Debug)]
pub struct Layout {
    /// Bytes per context entry: 32 or 64.
    pub size: usize,
}

impl Layout {
    pub fn input_control(&self) -> usize {
        0
    }
    pub fn input_slot(&self) -> usize {
        self.size
    }
    pub fn input_ep(&self, dci: u8) -> usize {
        self.size * (dci as usize + 1)
    }
    pub fn dev_slot(&self) -> usize {
        0
    }
    pub fn dev_ep(&self, dci: u8) -> usize {
        self.size * dci as usize
    }
    /// Bytes of a whole device context (slot + 31 endpoints).
    pub fn device_bytes(&self) -> usize {
        self.size * 32
    }
    /// Bytes of a whole input context.
    pub fn input_bytes(&self) -> usize {
        self.size * 33
    }
}

/// The fields of a slot context the driver sets.
#[derive(Clone, Copy, Debug, Default)]
pub struct SlotParams {
    pub route: u32,
    pub speed_psiv: u32,
    pub hub: bool,
    pub mtt: bool,
    /// Index of the last valid endpoint context (the "context entries").
    pub entries: u8,
    pub root_port: u8,
    pub num_ports: u8,
    /// The high-speed hub whose transaction translator serves a low/full
    /// speed device: its slot id and the port number on it. 0, 0 for none.
    pub tt_slot: u8,
    pub tt_port: u8,
    pub ttt: u8,
}

/// The fields of an endpoint context the driver sets.
#[derive(Clone, Copy, Debug, Default)]
pub struct EpParams {
    pub ep_type: u8,
    pub mps: u16,
    pub burst: u8,
    pub mult: u8,
    pub interval: u8,
    pub max_esit: u32,
    pub avg_trb_len: u16,
    pub deq: u64,
    pub dcs: bool,
}

/// Write the input control context: endpoints to drop (`drop`) and to add
/// (`add`), bit `n` for DCI `n`; bit 0 of `add` is the slot context.
pub fn write_input_control(buf: &DmaBuf, l: &Layout, drop: u32, add: u32) {
    let o = l.input_control();
    for i in (0..l.size).step_by(4) {
        buf.w32(o + i, 0);
    }
    buf.w32(o, drop);
    buf.w32(o + 4, add);
}

pub fn write_slot(buf: &DmaBuf, off: usize, l: &Layout, p: &SlotParams) {
    for i in (0..l.size).step_by(4) {
        buf.w32(off + i, 0);
    }
    buf.w32(
        off,
        (p.route & 0xf_ffff)
            | (p.speed_psiv & 0xf) << 20
            | (p.mtt as u32) << 25
            | (p.hub as u32) << 26
            | (p.entries as u32 & 0x1f) << 27,
    );
    buf.w32(off + 4, (p.root_port as u32) << 16 | (p.num_ports as u32) << 24);
    buf.w32(off + 8, p.tt_slot as u32 | (p.tt_port as u32) << 8 | (p.ttt as u32 & 3) << 16);
}

pub fn write_ep(buf: &DmaBuf, off: usize, l: &Layout, p: &EpParams) {
    for i in (0..l.size).step_by(4) {
        buf.w32(off + i, 0);
    }
    buf.w32(off, (p.mult as u32 & 3) << 8 | (p.interval as u32) << 16 | ((p.max_esit >> 16) & 0xff) << 24);
    // CErr 3: three bus errors before the endpoint halts.
    buf.w32(off + 4, 3 << 1 | (p.ep_type as u32 & 7) << 3 | (p.burst as u32) << 8 | (p.mps as u32) << 16);
    buf.w64(off + 8, (p.deq & !0xf) | p.dcs as u64);
    buf.w32(off + 16, p.avg_trb_len as u32 | (p.max_esit & 0xffff) << 16);
}

/// Change only the max packet size of an endpoint context (Evaluate Context
/// after the device descriptor revealed endpoint 0's real size).
pub fn set_ep_mps(buf: &DmaBuf, off: usize, mps: u16) {
    let d1 = buf.r32(off + 4);
    buf.w32(off + 4, (d1 & 0xffff) | (mps as u32) << 16);
}

/// The endpoint state of the endpoint context at `off` of a device context.
pub fn ep_state(buf: &DmaBuf, off: usize) -> u8 {
    (buf.r32(off) & 7) as u8
}

/// Slot state and USB device address of a device context's slot context.
pub fn slot_state(buf: &DmaBuf, off: usize) -> (u8, u8) {
    let d3 = buf.r32(off + 12);
    ((d3 >> 27) as u8, d3 as u8)
}

/// The endpoint context's interval field for a bInterval, by speed
/// (xHCI 1.2 section 6.2.3.6): high and super speed interrupt endpoints use
/// bInterval - 1 as an exponent of 125 us; low and full speed ones give
/// milliseconds, which the field expresses as the nearest power-of-two number
/// of 125 us frames (so 3 to 10).
pub fn interval_field(speed: Speed, b_interval: u8) -> u8 {
    let b = b_interval.max(1);
    match speed {
        Speed::High | Speed::Super | Speed::SuperPlus => (b - 1).min(15),
        Speed::Low | Speed::Full => {
            let frames = b as u32 * 8;
            // floor(log2(frames)), clamped to the field's 3..=10.
            let log2 = 31 - frames.leading_zeros();
            log2.clamp(3, 10) as u8
        }
    }
}

/// The interval field for an isochronous endpoint (xHCI 1.2 section 6.2.3.6):
/// bInterval is the exponent of the period for every speed (`2^(b-1)` frames
/// of 1 ms at full speed, of 125 us above it), and the field counts 125 us
/// units, so a full speed endpoint's exponent is raised by 3.
pub fn interval_field_isoch(speed: Speed, b_interval: u8) -> u8 {
    let e = b_interval.clamp(1, 16) - 1;
    match speed {
        Speed::Low | Speed::Full => (e + 3).min(18),
        _ => e,
    }
}

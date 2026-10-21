// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The `Can` interface: one CAN 2.0B controller.
//!
//! The endpoint's badge is the controller (`endpoint = "can.0"`). `READ`
//! receives and observes, `WRITE` transmits, `EXEC` controls the bus
//! (filters, bitrate, leaving bus-off): a task that may listen to the bus is
//! not thereby a node that can speak on it, nor one that can retune it.
//!
//! A frame is the four words of [`Frame`]. The calls are the control-rate
//! path (a command frame, a heartbeat); a task that follows a busy bus
//! reads it from a ring the controller's stream owns.
//!
//! # Failure contract
//!
//! `send` puts a frame on a bus other nodes act on: a lost reply must not
//! make the client transmit it twice, so it is `once_only`; a controller that
//! is off the bus answers `FAULT` and the client carries on without the bus
//! (`degrade`). Receiving consumes a frame, so `recv` is `at_most_once`.

use crate::outcome::Out;
use azos_idl::{azos_interface, Reader, Wire, Writer};

/// The interface id (ASCII "CAN ").
pub const CAN_ID: u32 = 0x4341_4E20;

/// Controllers the interface can name.
pub const CONTROLLERS: u32 = 4;
/// Most data bytes of a frame.
pub const MAX_DLC: u32 = 8;
/// Largest standard (11-bit) identifier.
pub const STD_ID_MAX: u32 = 0x7FF;
/// Largest extended (29-bit) identifier.
pub const EXT_ID_MAX: u32 = 0x1FFF_FFFF;
/// Slowest bitrate accepted, bits per second.
pub const BITRATE_MIN: u32 = 10_000;
/// Fastest bitrate accepted (classic CAN), bits per second.
pub const BITRATE_MAX: u32 = 1_000_000;

/// `Frame::flags`: a 29-bit identifier.
pub const FLAG_EXTENDED: u32 = 1;
/// `Frame::flags`: a remote transmission request.
pub const FLAG_RTR: u32 = 2;

/// [`Can::state`]: the controller has not been started.
pub const STATE_UNINIT: u32 = 0;
/// [`Can::state`]: on the bus.
pub const STATE_ACTIVE: u32 = 1;
/// [`Can::state`]: off the bus after too many transmit errors; only
/// [`Can::recover`] brings it back.
pub const STATE_BUS_OFF: u32 = 2;

/// One frame: identifier, flags, data length and up to eight data bytes
/// packed little-endian into one word.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Frame {
    pub id: u32,
    /// `FLAG_*`.
    pub flags: u32,
    /// Data bytes that are meaningful, 0..=[`MAX_DLC`].
    pub dlc: u32,
    /// The data, byte `i` in bits `8 * i..8 * i + 8`; the rest zero.
    pub data: u64,
}

impl Frame {
    /// A data frame of `data` (at most eight bytes of it).
    pub fn new(id: u32, flags: u32, data: &[u8]) -> Frame {
        let n = data.len().min(MAX_DLC as usize);
        let mut word = 0u64;
        for (i, b) in data[..n].iter().enumerate() {
            word |= (*b as u64) << (i * 8);
        }
        Frame { id, flags, dlc: n as u32, data: word }
    }

    /// Copy the data bytes into `out`; returns how many were copied.
    pub fn copy_to(&self, out: &mut [u8]) -> usize {
        let n = (self.dlc.min(MAX_DLC) as usize).min(out.len());
        for (i, o) in out[..n].iter_mut().enumerate() {
            *o = (self.data >> (i * 8)) as u8;
        }
        n
    }

    /// Is the frame one the controller can transmit: a length of at most
    /// eight, an identifier of the width its flag says, data only where the
    /// length says (a remote request carries none)?
    pub fn is_valid(&self) -> bool {
        let id_max = if self.flags & FLAG_EXTENDED != 0 { EXT_ID_MAX } else { STD_ID_MAX };
        let used = if self.dlc >= 8 { u64::MAX } else { (1u64 << (self.dlc * 8)) - 1 };
        self.dlc <= MAX_DLC
            && self.id <= id_max
            && self.flags & !(FLAG_EXTENDED | FLAG_RTR) == 0
            && self.data & !used == 0
            && (self.flags & FLAG_RTR == 0 || self.data == 0)
    }
}

impl Wire for Frame {
    const WORDS: usize = 4;
    const CAPS: usize = 0;
    fn put(&self, w: &mut Writer<'_>) {
        self.id.put(w);
        self.flags.put(w);
        self.dlc.put(w);
        self.data.put(w);
    }
    fn get(r: &mut Reader<'_>) -> Self {
        Frame { id: u32::get(r), flags: u32::get(r), dlc: u32::get(r), data: u64::get(r) }
    }
}

#[azos_interface(id = 0x4341_4E20, level = 1)]
pub trait Can {
    /// Transmit `frame` (not [`Frame::is_valid`]: `BAD_ARGUMENT`). `NOT_READY`
    /// before the controller is started, `FAULT` when it is off the bus
    /// ([`STATE_BUS_OFF`]). Needs `WRITE`.
    #[once_only]
    #[on_failure(degrade)]
    #[deadline_ns = 2_000_000]
    #[budget_us = 100]
    fn send(&mut self, frame: Frame) -> Out<()>;
    /// The oldest received frame that passes the filters. `NOT_READY` when
    /// there is none. Needs `READ`.
    #[at_most_once]
    fn recv(&mut self) -> Out<Frame>;
    /// Accept the frames whose identifier matches `id` under `mask` (an
    /// identifier `x` passes when `x & mask == id & mask`). With no filter
    /// every frame passes. `BUSY` when the controller has no filter left.
    /// Needs `EXEC`.
    #[at_most_once]
    fn add_filter(&mut self, id: u32, mask: u32) -> Out<()>;
    /// Remove every filter: every frame passes again. Needs `EXEC`.
    #[idempotent]
    fn clear_filters(&mut self) -> Out<()>;
    /// Set the bitrate ([`BITRATE_MIN`]..=[`BITRATE_MAX`], else
    /// `BAD_ARGUMENT`). Needs `EXEC`.
    #[idempotent]
    fn set_bitrate(&mut self, bps: u32) -> Out<()>;
    /// `STATE_*`. Needs `READ`.
    #[idempotent]
    fn state(&self) -> Out<u32>;
    /// Rejoin the bus after bus-off; served and a no-op on a controller that
    /// is on the bus. `NOT_READY` before the controller is started. Needs
    /// `EXEC`.
    #[idempotent]
    fn recover(&mut self) -> Out<()>;
}

// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! PS/2 mouse packets to evdev events.
//!
//! Pure (core only), host-tested. The standard mouse (no wheel) streams
//! three-byte packets once data reporting is on:
//!
//! * byte 0: bit 0 left, bit 1 right, bit 2 middle, bit 3 always 1 (the
//!   sync bit), bit 4 X sign, bit 5 Y sign, bit 6 X overflow, bit 7 Y overflow;
//! * byte 1: X movement (low 8 bits, sign in byte 0), byte 2: Y movement,
//!   positive UP (evdev's `REL_Y` is positive down, so it is negated).
//!
//! A first byte without the sync bit cannot start a packet, so it is dropped
//! and the stream resynchronises on the next byte that has it. An overflow
//! bit means the axis moved further than 9 bits can say; that axis is
//! dropped rather than reported wrong, the buttons are still reported.
//!
//! Output events are exactly what virtio-input mice produce: `EV_REL`
//! `REL_X`/`REL_Y` for a non-zero movement and `EV_KEY` `BTN_*` for each
//! button that changed. There is no `EV_SYN`: nothing downstream reads it.

use super::keymap::{EV_KEY, EV_REL};

pub const REL_X: u16 = 0x00;
pub const REL_Y: u16 = 0x01;
pub const BTN_LEFT: u16 = 0x110;
pub const BTN_RIGHT: u16 = 0x111;
pub const BTN_MIDDLE: u16 = 0x112;

const SYNC: u8 = 0x08;

/// Decoder state of one mouse.
#[derive(Clone, Copy, Debug, Default)]
pub struct Decoder {
    pkt: [u8; 3],
    have: usize,
    /// Buttons of the previous packet (bit 0 left, 1 right, 2 middle).
    buttons: u8,
    /// Bytes dropped while looking for a sync bit.
    pub resyncs: u32,
}

impl Decoder {
    pub const fn new() -> Self {
        Decoder { pkt: [0; 3], have: 0, buttons: 0, resyncs: 0 }
    }

    /// One byte from the mouse. When it completes a packet, `emit(type, code,
    /// value)` is called once per resulting event.
    pub fn feed(&mut self, b: u8, mut emit: impl FnMut(u16, u16, u32)) {
        if self.have == 0 && b & SYNC == 0 {
            self.resyncs += 1;
            return;
        }
        self.pkt[self.have] = b;
        self.have += 1;
        if self.have < 3 {
            return;
        }
        self.have = 0;
        let [flags, x, y] = self.pkt;
        if flags & 0x40 == 0 {
            let dx = x as i32 - if flags & 0x10 != 0 { 256 } else { 0 };
            if dx != 0 {
                emit(EV_REL, REL_X, dx as u32);
            }
        }
        if flags & 0x80 == 0 {
            let dy = -(y as i32 - if flags & 0x20 != 0 { 256 } else { 0 });
            if dy != 0 {
                emit(EV_REL, REL_Y, dy as u32);
            }
        }
        let now = flags & 0x07;
        let changed = now ^ self.buttons;
        self.buttons = now;
        for (bit, code) in [(0x01, BTN_LEFT), (0x02, BTN_RIGHT), (0x04, BTN_MIDDLE)] {
            if changed & bit != 0 {
                emit(EV_KEY, code, (now & bit != 0) as u32);
            }
        }
    }
}

// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! PS/2 mouse packets to evdev events.
//!
//! Pure (core only), host-tested. The standard mouse streams three-byte
//! packets once data reporting is on (an IntelliMouse, which the bring-up
//! asks for with the sample-rate knock, adds a fourth byte, the wheel):
//!
//! * byte 0: bit 0 left, bit 1 right, bit 2 middle, bit 3 always 1 (the
//!   sync bit), bit 4 X sign, bit 5 Y sign, bit 6 X overflow, bit 7 Y overflow;
//! * byte 1: X movement (low 8 bits, sign in byte 0), byte 2: Y movement,
//!   positive UP (evdev's `REL_Y` is positive down, so it is negated).
//!
//! * byte 3 (wheel mice only): the wheel movement, a signed 4-bit count in the
//!   low bits, positive towards the user; evdev's `REL_WHEEL` is positive away
//!   from the user, so it is negated.
//!
//! A first byte without the sync bit cannot start a packet, so it is dropped
//! and the stream resynchronises on the next byte that has it. An overflow
//! bit means the axis moved further than 9 bits can say; that axis is
//! dropped rather than reported wrong, the buttons are still reported.
//!
//! Output events are exactly what virtio-input mice produce: `EV_REL`
//! `REL_X`/`REL_Y` for a non-zero movement and `EV_KEY` `BTN_*` for each
//! button that changed. There is no `EV_SYN`: nothing downstream reads it.

pub use super::keymap::{BTN_LEFT, BTN_MIDDLE, BTN_RIGHT, REL_WHEEL, REL_X, REL_Y};
use super::keymap::{EV_KEY, EV_REL};

const SYNC: u8 = 0x08;

/// Decoder state of one mouse.
#[derive(Clone, Copy, Debug, Default)]
pub struct Decoder {
    pkt: [u8; 4],
    have: usize,
    /// Packets are four bytes (an IntelliMouse).
    wheel: bool,
    /// Buttons of the previous packet (bit 0 left, 1 right, 2 middle).
    buttons: u8,
    /// Bytes dropped while looking for a sync bit.
    pub resyncs: u32,
}

impl Decoder {
    pub const fn new() -> Self {
        Decoder { pkt: [0; 4], have: 0, wheel: false, buttons: 0, resyncs: 0 }
    }

    /// The mouse streams four-byte packets (the bring-up found a wheel).
    pub fn set_wheel(&mut self, on: bool) {
        self.wheel = on;
        self.have = 0;
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
        if self.have < if self.wheel { 4 } else { 3 } {
            return;
        }
        self.have = 0;
        let [flags, x, y, z] = self.pkt;
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
        if self.wheel {
            // Low 4 bits, sign-extended.
            let dz = ((z << 4) as i8 >> 4) as i32;
            if dz != 0 {
                emit(EV_REL, REL_WHEEL, (-dz) as u32);
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

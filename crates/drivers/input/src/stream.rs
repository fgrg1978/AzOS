// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The bytes of the two PS/2 ports to console bytes and input events.
//!
//! Pure (core only), host-tested: this is [`super::ps2`]'s interrupt arm
//! without the I/O. A keyboard byte goes through the set-2 decoder and the
//! shared keymap ([`super::keymap::route`]); a mouse byte goes through the
//! packet decoder.

use super::keymap::{route, Keymap, Route, EV_KEY};
use super::mouse;
use super::scancode;

/// What one byte came to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Out {
    /// A console byte for the UART's RX ring.
    Byte(u8),
    /// An event for the shared event ring: `(type, code, value)`. A mouse
    /// axis or button, or a key that makes no byte.
    Event(u16, u16, u32),
    /// A key event the console took (it made the byte before it, or nothing):
    /// `(code, value)`. Not for the first ring; the input server's stream gets
    /// it.
    Taken(u16, u32),
}

/// Decoder state of the keyboard and the mouse.
#[derive(Clone, Copy, Debug)]
pub struct Stream {
    kbd: scancode::Decoder,
    km: Keymap,
    mouse: mouse::Decoder,
}

impl Stream {
    pub const fn new() -> Self {
        Stream { kbd: scancode::Decoder::new(), km: Keymap::new(), mouse: mouse::Decoder::new() }
    }

    /// The mouse streams four-byte packets (it has a wheel).
    pub fn set_wheel(&mut self, on: bool) {
        self.mouse.set_wheel(on);
    }

    /// One byte `b` read from the keyboard port (`aux` false) or the mouse
    /// port (`aux` true); `out` is called once per result.
    pub fn feed(&mut self, aux: bool, b: u8, mut out: impl FnMut(Out)) {
        if aux {
            self.mouse.feed(b, |ty, code, value| out(Out::Event(ty, code, value)));
            return;
        }
        let Some((code, value)) = self.kbd.feed(b) else { return };
        match route(&mut self.km, EV_KEY, code, value) {
            Route::Byte(c) => {
                out(Out::Taken(code, value));
                out(Out::Byte(c));
            }
            Route::Consumed => out(Out::Taken(code, value)),
            Route::Publish => out(Out::Event(EV_KEY, code, value)),
        }
    }
}

impl Default for Stream {
    fn default() -> Self { Self::new() }
}

// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! PS/2 keyboard scancode set 2 to evdev key events.
//!
//! Pure (core only), host-tested. The controller is configured with
//! translation off (`i8042`), so the keyboard's own set 2 arrives byte for
//! byte:
//!
//! * a key's make code is one byte (`0x1C` for A), or `0xE0` and one byte for
//!   the extended keys (right Ctrl, arrows, keypad Enter, ...);
//! * its break code is the make code behind `0xF0` (`0xF0 0x1C`,
//!   `0xE0 0xF0 0x14`);
//! * held, the keyboard repeats the make code with no break between, which
//!   becomes value 2 so [`super::keymap::Keymap`] treats it as a repeat (a
//!   repeated Caps Lock does not toggle twice);
//! * Print Screen wraps its make in fake shifts (`E0 12 E0 7C`, and
//!   `E0 F0 7C E0 F0 12` for the break): `E0 12` has no entry in the extended
//!   table, so the fake shift gives no key;
//! * Pause is the eight bytes `E1 14 77 E1 F0 14 F0 77` with no break: it is
//!   swallowed whole, no event;
//! * replies of the keyboard itself (`0xFA` ack, `0xFE` resend, `0xAA`
//!   self-test passed, `0x00`/`0xFF` error) are no key.
//!
//! The output is `(code, value)` with the Linux evdev `KEY_*` codes the
//! keymap and every other input driver speak: value 1 press, 0 release, 2
//! repeat.

/// Extended-key prefix.
const PREFIX_EXT: u8 = 0xE0;
/// Break prefix.
const PREFIX_BREAK: u8 = 0xF0;
/// Pause's prefix; 7 more bytes follow.
const PREFIX_PAUSE: u8 = 0xE1;
const PAUSE_REST: u8 = 7;
/// F7's make code, the only one above 0x7F.
const F7_MAKE: u8 = 0x83;

pub const KEY_PRINT: u16 = 99;

/// Set-2 make code to evdev code (0 = none), no prefix.
const MAIN: [u16; 0x84] = {
    let pairs: &[(usize, u16)] = &[
        (0x01, 67), (0x03, 63), (0x04, 61), (0x05, 59), (0x06, 60), (0x07, 88),
        (0x09, 68), (0x0A, 66), (0x0B, 64), (0x0C, 62), (0x0D, 15), (0x0E, 41),
        (0x11, 56), (0x12, 42), (0x14, 29), (0x15, 16), (0x16, 2), (0x1A, 44),
        (0x1B, 31), (0x1C, 30), (0x1D, 17), (0x1E, 3), (0x21, 46), (0x22, 45),
        (0x23, 32), (0x24, 18), (0x25, 5), (0x26, 4), (0x29, 57), (0x2A, 47),
        (0x2B, 33), (0x2C, 20), (0x2D, 19), (0x2E, 6), (0x31, 49), (0x32, 48),
        (0x33, 35), (0x34, 34), (0x35, 21), (0x36, 7), (0x3A, 50), (0x3B, 36),
        (0x3C, 22), (0x3D, 8), (0x3E, 9), (0x41, 51), (0x42, 37), (0x43, 23),
        (0x44, 24), (0x45, 11), (0x46, 10), (0x49, 52), (0x4A, 53), (0x4B, 38),
        (0x4C, 39), (0x4D, 25), (0x4E, 12), (0x52, 40), (0x54, 26), (0x55, 13),
        (0x58, 58), (0x59, 54), (0x5A, 28), (0x5B, 27), (0x5D, 43), (0x61, 86),
        (0x66, 14), (0x69, 79), (0x6B, 75), (0x6C, 71), (0x70, 82), (0x71, 83),
        (0x72, 80), (0x73, 76), (0x74, 77), (0x75, 72), (0x76, 1), (0x77, 69),
        (0x78, 87), (0x79, 78), (0x7A, 81), (0x7B, 74), (0x7C, 55), (0x7D, 73),
        (0x7E, 70), (0x83, 65),
    ];
    let mut t = [0u16; 0x84];
    let mut i = 0;
    while i < pairs.len() {
        t[pairs[i].0] = pairs[i].1;
        i += 1;
    }
    t
};

/// Set-2 make code behind `0xE0` to evdev code (0 = none).
const EXT: [u16; 0x7E] = {
    let pairs: &[(usize, u16)] = &[
        (0x11, 100), (0x14, 97), (0x1F, 125), (0x27, 126), (0x2F, 127), (0x4A, 98),
        (0x5A, 96), (0x69, 107), (0x6B, 105), (0x6C, 102), (0x70, 110), (0x71, 111),
        (0x72, 108), (0x74, 106), (0x75, 103), (0x7A, 109), (0x7D, 104),
        (0x7C, KEY_PRINT),
    ];
    let mut t = [0u16; 0x7E];
    let mut i = 0;
    while i < pairs.len() {
        t[pairs[i].0] = pairs[i].1;
        i += 1;
    }
    t
};

fn lookup(ext: bool, code: u8) -> u16 {
    let c = code as usize;
    let table: &[u16] = if ext { &EXT } else { &MAIN };
    table.get(c).copied().unwrap_or(0)
}

/// Decoder state of one keyboard.
#[derive(Clone, Copy, Debug)]
pub struct Decoder {
    ext: bool,
    brk: bool,
    /// Bytes of a Pause sequence still to swallow.
    skip: u8,
    /// Keys held, by (extended, make code): the difference between a press
    /// and an autorepeat. Bit 127 stands for F7 (0x83); 0x7F is no make code.
    down: [u128; 2],
}

impl Decoder {
    pub const fn new() -> Self {
        Decoder { ext: false, brk: false, skip: 0, down: [0; 2] }
    }

    /// One byte from the keyboard: the key event it completes, if any. A
    /// byte that is no key (a reply, noise) clears a pending prefix, so a
    /// lost byte costs one key, not the stream.
    pub fn feed(&mut self, b: u8) -> Option<(u16, u32)> {
        if self.skip != 0 {
            self.skip -= 1;
            return None;
        }
        match b {
            PREFIX_EXT => { self.ext = true; return None; }
            PREFIX_BREAK => { self.brk = true; return None; }
            PREFIX_PAUSE => {
                self.skip = PAUSE_REST;
                self.ext = false;
                self.brk = false;
                return None;
            }
            _ => {}
        }
        let (ext, brk) = (self.ext, self.brk);
        self.ext = false;
        self.brk = false;
        let code = lookup(ext, b);
        if code == 0 {
            return None;
        }
        let bit = 1u128 << if b == F7_MAKE { 127 } else { b as u32 };
        let slot = &mut self.down[ext as usize];
        let was = *slot & bit != 0;
        if brk {
            *slot &= !bit;
            Some((code, 0))
        } else {
            *slot |= bit;
            Some((code, if was { 2 } else { 1 }))
        }
    }
}

impl Default for Decoder {
    fn default() -> Self { Self::new() }
}

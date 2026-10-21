// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Input events to console bytes: the US keymap, and where each event goes.
//!
//! Pure (core only), so `tests/host/drivers-tests` pulls it in with `#[path]`.
//! Shared by every keyboard driver: virtio-input reports Linux evdev events
//! as they are, and the PS/2 driver (`scancode`) translates set-2 scancodes to
//! the same codes.
//!
//! The events are Linux evdev events: `type` (`EV_KEY`, `EV_REL`, ...),
//! `code` (a key or axis), `value` (1 press, 0 release, 2 autorepeat for a
//! key). The console wants bytes. [`Keymap`] holds the modifier state and
//! turns a key event into at most one byte; [`route`] decides what becomes of
//! every other event.

pub use azos_input_wire::event::*;

/// What the console reads for Enter (the UART delivers `\r` for it).
pub const BYTE_ENTER: u8 = b'\r';
/// What the console reads for Backspace (the shell's editor takes 0x08 and 0x7f).
pub const BYTE_BACKSPACE: u8 = 0x7f;

/// Unshifted byte of key `code` (0 = none), codes 0..=57.
const BASE: [u8; 58] = [
    0, 0x1b, b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9', b'0', b'-', b'=', BYTE_BACKSPACE, b'\t',
    b'q', b'w', b'e', b'r', b't', b'y', b'u', b'i', b'o', b'p', b'[', b']', BYTE_ENTER, 0,
    b'a', b's', b'd', b'f', b'g', b'h', b'j', b'k', b'l', b';', b'\'', b'`', 0, b'\\',
    b'z', b'x', b'c', b'v', b'b', b'n', b'm', b',', b'.', b'/', 0, b'*', 0, b' ',
];

/// Shifted byte of key `code` (0 = none), codes 0..=57.
const SHIFTED: [u8; 58] = [
    0, 0x1b, b'!', b'@', b'#', b'$', b'%', b'^', b'&', b'*', b'(', b')', b'_', b'+', BYTE_BACKSPACE, b'\t',
    b'Q', b'W', b'E', b'R', b'T', b'Y', b'U', b'I', b'O', b'P', b'{', b'}', BYTE_ENTER, 0,
    b'A', b'S', b'D', b'F', b'G', b'H', b'J', b'K', b'L', b':', b'"', b'~', 0, b'|',
    b'Z', b'X', b'C', b'V', b'B', b'N', b'M', b'<', b'>', b'?', 0, b'*', 0, b' ',
];

/// Is `code` a modifier (consumed by [`Keymap`], never a byte)?
pub const fn is_modifier(code: u16) -> bool {
    matches!(code, KEY_LEFTSHIFT | KEY_RIGHTSHIFT | KEY_LEFTCTRL | KEY_RIGHTCTRL | KEY_CAPSLOCK)
}

/// The byte `code` produces with no modifier but possibly shift, 0 if none.
const fn table(code: u16, shift: bool) -> u8 {
    if code == KEY_KPENTER {
        return BYTE_ENTER;
    }
    if (code as usize) >= BASE.len() {
        return 0;
    }
    if shift { SHIFTED[code as usize] } else { BASE[code as usize] }
}

/// Does key `code` produce a byte (the console consumes it)?
pub const fn has_byte(code: u16) -> bool {
    table(code, false) != 0
}

/// Modifier state of one keyboard.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Keymap {
    lshift: bool,
    rshift: bool,
    lctrl: bool,
    rctrl: bool,
    caps: bool,
}

impl Keymap {
    pub const fn new() -> Self {
        Keymap { lshift: false, rshift: false, lctrl: false, rctrl: false, caps: false }
    }

    pub const fn shift(&self) -> bool { self.lshift || self.rshift }
    pub const fn ctrl(&self) -> bool { self.lctrl || self.rctrl }

    /// One key event (`value`: 0 release, 1 press, 2 repeat). Modifiers
    /// update the state and give nothing; a release gives nothing; a press
    /// or repeat of a mapped key gives its byte. Ctrl + letter is the
    /// control byte (`^C` = 0x03, which the console's interrupt handling
    /// reads); Caps Lock flips the case of letters only.
    pub fn key(&mut self, code: u16, value: u32) -> Option<u8> {
        let down = value != 0;
        match code {
            KEY_LEFTSHIFT => { self.lshift = down; return None; }
            KEY_RIGHTSHIFT => { self.rshift = down; return None; }
            KEY_LEFTCTRL => { self.lctrl = down; return None; }
            KEY_RIGHTCTRL => { self.rctrl = down; return None; }
            // Caps Lock toggles on the press only (a repeat must not).
            KEY_CAPSLOCK => { if value == 1 { self.caps = !self.caps; } return None; }
            _ => {}
        }
        if !down {
            return None;
        }
        let lower = table(code, false);
        let letter = lower.is_ascii_lowercase();
        let shifted = self.shift() ^ (self.caps && letter);
        let b = table(code, shifted);
        if b == 0 {
            return None;
        }
        if self.ctrl() && letter {
            return Some(lower & 0x1f);
        }
        Some(b)
    }
}

/// What becomes of one event.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Route {
    /// A console byte.
    Byte(u8),
    /// Taken here and not kept: a sync marker, the release of a key that
    /// gave a byte.
    Consumed,
    /// Not the console's: a mouse button or axis, the wheel, a tablet
    /// position, a modifier key, a key with no byte. Goes to the event ring
    /// the terminal server drains.
    Publish,
}

/// Decide what becomes of the event `(ty, code, value)`.
pub fn route(km: &mut Keymap, ty: u16, code: u16, value: u32) -> Route {
    match ty {
        EV_SYN => Route::Consumed,
        EV_KEY if code < BTN_MOUSE => {
            if is_modifier(code) {
                // The console's own state follows it, and the ring carries it
                // too: the terminal server tracks the modifiers itself, so a
                // key with no byte (an arrow) arrives without modifier bits.
                km.key(code, value);
                return Route::Publish;
            }
            if has_byte(code) {
                match km.key(code, value) {
                    Some(b) => Route::Byte(b),
                    None => Route::Consumed,
                }
            } else {
                Route::Publish
            }
        }
        _ => Route::Publish,
    }
}

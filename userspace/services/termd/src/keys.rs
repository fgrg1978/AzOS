// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Keys with no byte to standard VT/xterm escape sequences.
//!
//! The kernel turns a key that makes a character into a console byte; the
//! rest (arrows, Home/End, Page Up/Down, Insert/Delete, F1-F12) arrive on the
//! input event ring as evdev key events, together with the modifier keys
//! themselves. [`Mods`] follows the modifiers; [`encode`] gives the bytes the
//! line editor and a raw-mode client read: the CSI/SS3 forms of xterm,
//! `ESC [ 1 ; m A` for a modified arrow (`m` = 1 + shift 1 + alt 2 + ctrl 4 +
//! meta 8), `ESC [ n ; m ~` for the tilde keys.
//!
//! Pure: `tests/host/term-tests` pulls this file in with `#[path]`.

use azos_input_wire::event::*;

/// The modifiers held, by physical key.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Mods {
    held: u16,
}

const BITS: [(u16, u16); 8] = [
    (KEY_LEFTSHIFT, 1 << 0),
    (KEY_RIGHTSHIFT, 1 << 1),
    (KEY_LEFTALT, 1 << 2),
    (KEY_RIGHTALT, 1 << 3),
    (KEY_LEFTCTRL, 1 << 4),
    (KEY_RIGHTCTRL, 1 << 5),
    (KEY_LEFTMETA, 1 << 6),
    (KEY_RIGHTMETA, 1 << 7),
];

impl Mods {
    pub const fn new() -> Self {
        Self { held: 0 }
    }

    /// A key event; `true` when the key was a modifier.
    pub fn key(&mut self, code: u16, value: u32) -> bool {
        for (c, bit) in BITS {
            if c == code {
                if value != 0 {
                    self.held |= bit;
                } else {
                    self.held &= !bit;
                }
                return true;
            }
        }
        false
    }

    pub const fn shift(&self) -> bool {
        self.held & 0b11 != 0
    }

    pub const fn alt(&self) -> bool {
        self.held & 0b1100 != 0
    }

    pub const fn ctrl(&self) -> bool {
        self.held & 0b11_0000 != 0
    }

    pub const fn meta(&self) -> bool {
        self.held & 0b1100_0000 != 0
    }

    /// xterm's modifier parameter: 1 for none, else 1 + the bits.
    pub const fn param(&self) -> u8 {
        1 + self.shift() as u8 + 2 * self.alt() as u8 + 4 * self.ctrl() as u8 + 8 * self.meta() as u8
    }
}

/// The longest sequence: `ESC [ 2 4 ; 1 6 ~`.
pub const SEQ_MAX: usize = 8;

/// One escape sequence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Seq {
    buf: [u8; SEQ_MAX],
    len: u8,
}

impl Seq {
    pub fn bytes(&self) -> &[u8] {
        &self.buf[..self.len as usize]
    }

    fn new() -> Self {
        Seq { buf: [0; SEQ_MAX], len: 0 }
    }

    fn put(&mut self, b: u8) {
        self.buf[self.len as usize] = b;
        self.len += 1;
    }

    fn num(&mut self, n: u8) {
        if n >= 10 {
            self.put(b'0' + n / 10);
        }
        self.put(b'0' + n % 10);
    }
}

/// How a key is written.
enum Form {
    /// `ESC [ <final>`, or `ESC [ 1 ; m <final>` with modifiers.
    Csi(u8),
    /// `ESC O <final>`, or `ESC [ 1 ; m <final>` with modifiers (F1-F4).
    Ss3(u8),
    /// `ESC [ <n> ~`, or `ESC [ <n> ; m ~` with modifiers.
    Tilde(u8),
}

fn form(code: u16) -> Option<Form> {
    Some(match code {
        KEY_UP => Form::Csi(b'A'),
        KEY_DOWN => Form::Csi(b'B'),
        KEY_RIGHT => Form::Csi(b'C'),
        KEY_LEFT => Form::Csi(b'D'),
        KEY_HOME => Form::Csi(b'H'),
        KEY_END => Form::Csi(b'F'),
        KEY_INSERT => Form::Tilde(2),
        KEY_DELETE => Form::Tilde(3),
        KEY_PAGEUP => Form::Tilde(5),
        KEY_PAGEDOWN => Form::Tilde(6),
        c if (KEY_F1..=KEY_F1 + 3).contains(&c) => Form::Ss3(b'P' + (c - KEY_F1) as u8),
        c if (KEY_F1 + 4..=KEY_F10).contains(&c) => Form::Tilde([15, 17, 18, 19, 20, 21][(c - KEY_F1 - 4) as usize]),
        KEY_F11 => Form::Tilde(23),
        KEY_F12 => Form::Tilde(24),
        _ => return None,
    })
}

/// The sequence for the key `code` with `mods` held, `None` for a key that
/// has none.
pub fn encode(code: u16, mods: &Mods) -> Option<Seq> {
    let f = form(code)?;
    let m = mods.param();
    let mut s = Seq::new();
    s.put(0x1b);
    match f {
        Form::Csi(fin) | Form::Ss3(fin) if m == 1 => {
            s.put(if matches!(f, Form::Ss3(_)) { b'O' } else { b'[' });
            s.put(fin);
        }
        Form::Csi(fin) | Form::Ss3(fin) => {
            s.put(b'[');
            s.put(b'1');
            s.put(b';');
            s.num(m);
            s.put(fin);
        }
        Form::Tilde(n) => {
            s.put(b'[');
            s.num(n);
            if m != 1 {
                s.put(b';');
                s.num(m);
            }
            s.put(b'~');
        }
    }
    Some(s)
}

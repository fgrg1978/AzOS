// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The input event word and the evdev codes it carries.
//!
//! Producers are the PS/2 driver and virtio-input (all three ISAs); both
//! publish Linux evdev events, packed by [`pack`], into the one event ring the
//! terminal server drains. The consumer decodes with [`unpack`].
//!
//! The first ring publishes every event the console has no byte for: mouse buttons,
//! relative and absolute axes, the wheel, **the modifier keys themselves**
//! (the consumer tracks its own modifier state, so an arrow key's word needs
//! no modifier bits) and keys with no byte (arrows, F-keys, Home, ...). With
//! the input server (Kconfig `INPUTD`) it does so only while the console holds
//! the focus ([`FOCUS_OFFSET`]); the modifiers and the Secure Attention chord
//! ([`attention`]) it always gets, so the console can see the chord.

pub const EV_SYN: u16 = 0x00;
pub const EV_KEY: u16 = 0x01;
pub const EV_REL: u16 = 0x02;
pub const EV_ABS: u16 = 0x03;

pub const KEY_ESC: u16 = 1;
pub const KEY_BACKSPACE: u16 = 14;
pub const KEY_TAB: u16 = 15;
pub const KEY_ENTER: u16 = 28;
pub const KEY_LEFTCTRL: u16 = 29;
pub const KEY_A: u16 = 30;
pub const KEY_LEFTSHIFT: u16 = 42;
pub const KEY_RIGHTSHIFT: u16 = 54;
pub const KEY_LEFTALT: u16 = 56;
pub const KEY_SPACE: u16 = 57;
pub const KEY_CAPSLOCK: u16 = 58;
pub const KEY_F1: u16 = 59;
pub const KEY_F10: u16 = 68;
pub const KEY_F11: u16 = 87;
pub const KEY_F12: u16 = 88;
pub const KEY_KPENTER: u16 = 96;
pub const KEY_RIGHTCTRL: u16 = 97;
pub const KEY_RIGHTALT: u16 = 100;
pub const KEY_HOME: u16 = 102;
pub const KEY_UP: u16 = 103;
pub const KEY_PAGEUP: u16 = 104;
pub const KEY_LEFT: u16 = 105;
pub const KEY_RIGHT: u16 = 106;
pub const KEY_END: u16 = 107;
pub const KEY_DOWN: u16 = 108;
pub const KEY_PAGEDOWN: u16 = 109;
pub const KEY_INSERT: u16 = 110;
pub const KEY_DELETE: u16 = 111;
pub const KEY_LEFTMETA: u16 = 125;
pub const KEY_RIGHTMETA: u16 = 126;

/// First mouse button (`BTN_MOUSE`); keyboards stay below it.
pub const BTN_MOUSE: u16 = 0x110;
pub const BTN_LEFT: u16 = 0x110;
pub const BTN_RIGHT: u16 = 0x111;
pub const BTN_MIDDLE: u16 = 0x112;

pub const REL_X: u16 = 0x00;
pub const REL_Y: u16 = 0x01;
pub const REL_HWHEEL: u16 = 0x06;
pub const REL_WHEEL: u16 = 0x08;

pub const ABS_X: u16 = 0x00;
pub const ABS_Y: u16 = 0x01;
/// Full scale of an absolute axis (the virtio tablet's range is `0..=0x7FFF`).
pub const ABS_MAX: u32 = 0x7FFF;

/// Slots of the event ring (a power of two); the ring is one page.
pub const RING_CAP: u32 = 256;

/// Byte offset, in the event ring's region, of the word that counts the events
/// the producer had to drop because the ring was full: it follows the ring
/// (`azos_rings::region::SpscRing::bytes(RING_CAP)`, 64-byte aligned; the
/// producer side checks the equality at compile time). The producer adds to it
/// under its lock; the consumer only reads it. A consumer that sees it move
/// knows the state it built from the events (modifiers held, buttons down) may
/// have missed a release.
pub const DROPS_OFFSET: usize = 256 + RING_CAP as usize * 8;

/// Bytes of the event ring's region: the ring and the drop counter's line.
pub const REGION_BYTES: usize = DROPS_OFFSET + 64;

/// Slots of the stream ring (a power of two). The region holds a second ring
/// after the first: the **stream**, which carries every event of every input
/// device, keys that made console bytes included, for the input server
/// (`userspace/services/inputd`, Kconfig `INPUTD`) to deliver to the holder of
/// the focus. The terminal server drains the first ring and never the second,
/// and the input server the second and never the first, so neither is
/// disturbed by the other. Producers write the stream only with `INPUTD` on;
/// then the focus word ([`FOCUS_OFFSET`]) decides what the first ring and the
/// console get at all.
pub const STREAM_CAP: u32 = 128;

/// Byte offset of the stream ring in the region (64-byte aligned: it follows
/// the first ring's counter line).
pub const STREAM_OFFSET: usize = REGION_BYTES;

/// Byte offset of the word counting the events the stream dropped because it
/// was full: it follows the stream ring (`STREAM_OFFSET +
/// azos_rings::region::SpscRing::bytes(STREAM_CAP)`; the producer side checks
/// the equality at compile time). The input server resynchronizes the key and
/// button state it holds when this moves.
pub const STREAM_DROPS_OFFSET: usize = STREAM_OFFSET + 256 + STREAM_CAP as usize * 8;

/// Byte offset of the **focus word**: who the keyboard and the pointer belong
/// to, on a line of its own after the stream's counter. 0: the console (the
/// terminal server); otherwise the generation of the task that holds the focus
/// (`azos_devif::input`). The input server writes it when the focus moves; the
/// producers read it for every event and route by it
/// (`azos_drv_input::keymap::route`), and a producer that sees the Secure
/// Attention chord sets it back to 0 itself, so the chord reaches the console
/// whatever the input server does. 0 is also its value before the input server
/// runs and after it exits.
pub const FOCUS_OFFSET: usize = STREAM_DROPS_OFFSET + 64;

/// Bytes of the whole region: both rings, both counters' lines and the focus
/// word's. Less than one page.
pub const REGION_TOTAL: usize = FOCUS_OFFSET + 64;

/// Set in the type half of a **stream** word whose event the console was given
/// (the focus word was 0 when the producer routed it): the input server tracks
/// it (held keys, the chord) and delivers it to no holder, so no event reaches
/// two parties. Bit 15 of the type: evdev types stop at 0x1f. The first ring
/// never carries it.
pub const STREAM_CONSOLE: u64 = 1 << 15;

/// The Secure Attention Key: Ctrl+Alt+Delete (either Ctrl, either Alt). `true`
/// for the Delete event `code` with both modifiers held: the chord's key, whose
/// press takes the focus. The producers, the input server and the terminal
/// server all ask this.
pub const fn attention(code: u16, ctrl: bool, alt: bool) -> bool {
    code == KEY_DELETE && ctrl && alt
}

/// One event packed into a ring word: `type | code << 16 | value << 32`.
/// `value` is a key state (0 release, 1 press, 2 repeat), a signed relative
/// movement (two's complement), or an absolute position.
pub const fn pack(ty: u16, code: u16, value: u32) -> u64 {
    (ty as u64) | ((code as u64) << 16) | ((value as u64) << 32)
}

/// Inverse of [`pack`].
pub const fn unpack(w: u64) -> (u16, u16, u32) {
    (w as u16, (w >> 16) as u16, (w >> 32) as u32)
}

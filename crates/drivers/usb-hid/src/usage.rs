// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! HID usages to evdev codes.
//!
//! The numbers on the left are the HID Usage Tables 1.4 (keyboard/keypad page
//! 0x07, button page 0x09, generic desktop page 0x01, consumer page 0x0C); the
//! numbers on the right are the evdev codes `azos_input_wire::event` and every
//! other input producer (PS/2, virtio-input) already speak, so a USB keyboard
//! and a PS/2 one are the same keyboard to the console.

use azos_input_wire::event::{
    BTN_LEFT, KEY_LEFTALT, KEY_LEFTCTRL, KEY_LEFTMETA, KEY_LEFTSHIFT, KEY_RIGHTALT, KEY_RIGHTCTRL, KEY_RIGHTMETA,
    KEY_RIGHTSHIFT,
};

pub const PAGE_GENERIC_DESKTOP: u16 = 0x01;
pub const PAGE_KEYBOARD: u16 = 0x07;
pub const PAGE_BUTTON: u16 = 0x09;
pub const PAGE_CONSUMER: u16 = 0x0c;

/// Generic desktop usages of the application collections a driver here serves.
pub const GD_POINTER: u16 = 0x01;
pub const GD_MOUSE: u16 = 0x02;
pub const GD_KEYBOARD: u16 = 0x06;
pub const GD_KEYPAD: u16 = 0x07;
/// Generic desktop axes.
pub const GD_X: u16 = 0x30;
pub const GD_Y: u16 = 0x31;
pub const GD_WHEEL: u16 = 0x38;
/// Consumer page: AC Pan, the horizontal wheel.
pub const CONSUMER_AC_PAN: u16 = 0x238;

/// First keyboard usage that is a modifier (Left Control).
pub const MODIFIER_FIRST: u16 = 0xe0;
/// Last modifier usage (Right GUI).
pub const MODIFIER_LAST: u16 = 0xe7;

/// The evdev code of the modifier keys, in the order of usages 0xe0..=0xe7.
pub const MODIFIER_CODES: [u16; 8] = [
    KEY_LEFTCTRL,
    KEY_LEFTSHIFT,
    KEY_LEFTALT,
    KEY_LEFTMETA,
    KEY_RIGHTCTRL,
    KEY_RIGHTSHIFT,
    KEY_RIGHTALT,
    KEY_RIGHTMETA,
];

/// Keyboard usages 0x00..=0x73 (0x00..=0x03 are "no event" and the error
/// codes). 0 is "no key".
const KEYBOARD: [u8; 0x74] = [
    // 0x00..=0x03: reserved, ErrorRollOver, POSTFail, ErrorUndefined.
    0, 0, 0, 0,
    // 0x04..=0x1d: a..z.
    30, 48, 46, 32, 18, 33, 34, 35, 23, 36, 37, 38, 50, 49, 24, 25, 16, 19, 31, 20, 22, 47, 17, 45, 21, 44,
    // 0x1e..=0x27: 1..9, 0.
    2, 3, 4, 5, 6, 7, 8, 9, 10, 11,
    // 0x28..=0x38: Enter, Escape, Backspace, Tab, Space, - = [ ] \ non-US # ; ' ` , . /.
    28, 1, 14, 15, 57, 12, 13, 26, 27, 43, 43, 39, 40, 41, 51, 52, 53,
    // 0x39: Caps Lock; 0x3a..=0x45: F1..F12.
    58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 87, 88,
    // 0x46..=0x52: Print Screen, Scroll Lock, Pause, Insert, Home, Page Up, Delete, End, Page Down,
    // Right, Left, Down, Up.
    99, 70, 119, 110, 102, 104, 111, 107, 109, 106, 105, 108, 103,
    // 0x53..=0x63: Num Lock, keypad / * - + Enter 1..9 0 .
    69, 98, 55, 74, 78, 96, 79, 80, 81, 75, 76, 77, 71, 72, 73, 82, 83,
    // 0x64..=0x67: non-US \, Application, Power, keypad =.
    86, 127, 116, 117,
    // 0x68..=0x73: F13..F24.
    183, 184, 185, 186, 187, 188, 189, 190, 191, 192, 193, 194,
];

/// The evdev code of keyboard-page usage `usage`, 0 for none.
pub const fn key_code(usage: u16) -> u16 {
    if usage >= MODIFIER_FIRST && usage <= MODIFIER_LAST {
        return MODIFIER_CODES[(usage - MODIFIER_FIRST) as usize];
    }
    if (usage as usize) < KEYBOARD.len() {
        KEYBOARD[usage as usize] as u16
    } else {
        0
    }
}

/// The evdev code of button `usage` (1-based) of a pointer: `BTN_LEFT`,
/// `BTN_RIGHT`, `BTN_MIDDLE`, `BTN_SIDE`, ... up to 16 buttons; 0 for none.
pub const fn button_code(usage: u16) -> u16 {
    if usage >= 1 && usage <= 16 { BTN_LEFT + usage - 1 } else { 0 }
}

/// Is `code` one of the eight modifier keys?
pub const fn is_modifier_code(code: u16) -> bool {
    let mut i = 0;
    while i < MODIFIER_CODES.len() {
        if MODIFIER_CODES[i] == code {
            return true;
        }
        i += 1;
    }
    false
}

/// The error codes a key array may carry instead of a key (ErrorRollOver,
/// POSTFail, ErrorUndefined): the report says nothing about which keys are down.
pub const fn is_array_error(usage: u16) -> bool {
    usage >= 1 && usage <= 3
}

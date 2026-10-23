// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Reports to events, the usage table, autorepeat, and what the console's
//! keymap makes of the events.

use azos_input_wire::event::*;
use azos_usb_hid::decode::{Decoder, Repeat};
use azos_usb_hid::report::Layout;
use azos_usb_hid::usage;

use crate::fixtures::*;
use crate::keymap::{route, Keymap, Route};

type Ev = (u16, u16, u32);

fn run(d: &mut Decoder, l: &Layout, report: &[u8]) -> Vec<Ev> {
    let mut v = Vec::new();
    d.report(l, report, |ty, code, value| v.push((ty, code, value)));
    v
}

fn key(code: u16, v: u32) -> Ev {
    (EV_KEY, code, v)
}

fn kbd() -> (Decoder, Layout) {
    (Decoder::new(), Layout::parse(BOOT_KEYBOARD).unwrap())
}

#[test]
fn the_usage_table_matches_the_hid_usage_tables() {
    // Letters, digits, the main block, the function keys, navigation and the keypad.
    assert_eq!(usage::key_code(0x04), KEY_A);
    assert_eq!(usage::key_code(0x1d), 44); // z
    assert_eq!(usage::key_code(0x1e), 2); // 1
    assert_eq!(usage::key_code(0x27), 11); // 0
    assert_eq!(usage::key_code(0x28), KEY_ENTER);
    assert_eq!(usage::key_code(0x29), KEY_ESC);
    assert_eq!(usage::key_code(0x2a), KEY_BACKSPACE);
    assert_eq!(usage::key_code(0x2b), KEY_TAB);
    assert_eq!(usage::key_code(0x2c), KEY_SPACE);
    assert_eq!(usage::key_code(0x39), KEY_CAPSLOCK);
    assert_eq!(usage::key_code(0x3a), KEY_F1);
    assert_eq!(usage::key_code(0x43), KEY_F10);
    assert_eq!(usage::key_code(0x44), KEY_F11);
    assert_eq!(usage::key_code(0x45), KEY_F12);
    assert_eq!(usage::key_code(0x49), KEY_INSERT);
    assert_eq!(usage::key_code(0x4a), KEY_HOME);
    assert_eq!(usage::key_code(0x4b), KEY_PAGEUP);
    assert_eq!(usage::key_code(0x4c), KEY_DELETE);
    assert_eq!(usage::key_code(0x4d), KEY_END);
    assert_eq!(usage::key_code(0x4e), KEY_PAGEDOWN);
    assert_eq!(usage::key_code(0x4f), KEY_RIGHT);
    assert_eq!(usage::key_code(0x50), KEY_LEFT);
    assert_eq!(usage::key_code(0x51), KEY_DOWN);
    assert_eq!(usage::key_code(0x52), KEY_UP);
    assert_eq!(usage::key_code(0x58), KEY_KPENTER);
    assert_eq!(usage::key_code(0x59), 79); // keypad 1
    assert_eq!(usage::key_code(0x62), 82); // keypad 0
    assert_eq!(usage::key_code(0x73), 194); // F24
    // The modifiers, in usage order.
    let m: Vec<u16> = (0xe0..=0xe7).map(usage::key_code).collect();
    assert_eq!(m, vec![KEY_LEFTCTRL, KEY_LEFTSHIFT, KEY_LEFTALT, KEY_LEFTMETA, KEY_RIGHTCTRL, KEY_RIGHTSHIFT, KEY_RIGHTALT, KEY_RIGHTMETA]);
    // Reserved, the error codes and what is past the table.
    for u in [0, 1, 2, 3, 0x74, 0xa5, 0xe8, 0xffff] {
        assert_eq!(usage::key_code(u), 0, "{u:#x}");
    }
    assert_eq!(usage::button_code(1), BTN_LEFT);
    assert_eq!(usage::button_code(3), BTN_MIDDLE);
    assert_eq!(usage::button_code(0), 0);
    assert_eq!(usage::button_code(17), 0);
}

#[test]
fn every_keyboard_usage_maps_to_a_distinct_key() {
    let mut seen = std::collections::HashMap::new();
    for u in (0u16..0x74).chain(0xe0..=0xe7) {
        let c = usage::key_code(u);
        if c != 0 {
            // Usages 0x31 (backslash) and 0x32 (non-US #) are the one pair that shares a key.
            if let Some(prev) = seen.insert(c, u) {
                assert!(prev == 0x31 && u == 0x32, "usages {prev:#x} and {u:#x} both give {c}");
            }
        }
    }
}

#[test]
fn a_key_goes_down_stays_down_and_goes_up() {
    let (mut d, l) = kbd();
    assert_eq!(run(&mut d, &l, &[0, 0, 4, 0, 0, 0, 0, 0]), vec![key(KEY_A, 1)]);
    // A second key: only the new one is an event.
    assert_eq!(run(&mut d, &l, &[0, 0, 4, 5, 0, 0, 0, 0]), vec![key(48, 1)]);
    // The first goes up, the second stays.
    assert_eq!(run(&mut d, &l, &[0, 0, 0, 5, 0, 0, 0, 0]), vec![key(KEY_A, 0)]);
    // The same report again: nothing.
    assert_eq!(run(&mut d, &l, &[0, 0, 0, 5, 0, 0, 0, 0]), vec![]);
    assert_eq!(run(&mut d, &l, &[0; 8]), vec![key(48, 0)]);
}

#[test]
fn modifiers_come_before_the_keys_of_their_report() {
    let (mut d, l) = kbd();
    // Left shift and `a` in one report: the shift first, or the console reads `a`.
    assert_eq!(run(&mut d, &l, &[0x02, 0, 4, 0, 0, 0, 0, 0]), vec![key(KEY_LEFTSHIFT, 1), key(KEY_A, 1)]);
    // Shift goes up while `b` comes down: the release first, or `b` reads shifted.
    assert_eq!(run(&mut d, &l, &[0x00, 0, 4, 5, 0, 0, 0, 0]), vec![key(KEY_LEFTSHIFT, 0), key(48, 1)]);
    // Right control (bit 4) and right alt (bit 6).
    let mut d = Decoder::new();
    assert_eq!(run(&mut d, &l, &[0x50, 0, 0, 0, 0, 0, 0, 0]), vec![key(KEY_RIGHTCTRL, 1), key(KEY_RIGHTALT, 1)]);
}

#[test]
fn the_console_reads_what_was_typed() {
    let (mut d, l) = kbd();
    let mut km = Keymap::new();
    let mut routes = Vec::new();
    for r in [
        [0x00u8, 0, 4, 0, 0, 0, 0, 0],    // a
        [0x00, 0, 0, 0, 0, 0, 0, 0],      // up
        [0x02, 0, 4, 0, 0, 0, 0, 0],      // shift + a
        [0x00, 0, 0, 0, 0, 0, 0, 0],
        [0x01, 0, 6, 0, 0, 0, 0, 0],      // ctrl + c
        [0x00, 0, 0x28, 0, 0, 0, 0, 0],   // enter
        [0x00, 0, 0x52, 0, 0, 0, 0, 0],   // up arrow
    ] {
        for (ty, code, value) in run(&mut d, &l, &r) {
            routes.push(route(&mut km, ty, code, value, true));
        }
    }
    assert_eq!(
        routes,
        vec![
            Route::Byte(b'a'),
            Route::Consumed, // a up
            Route::Publish,  // shift down: the terminal server tracks modifiers
            Route::Byte(b'A'),
            Route::Publish,  // shift up (the modifier is emitted before the key's release)
            Route::Consumed, // A up
            Route::Publish,  // ctrl down
            Route::Byte(3),  // ^C
            Route::Publish,  // ctrl up
            Route::Consumed, // c up
            Route::Byte(b'\r'),
            Route::Consumed, // enter up
            Route::Publish,  // up arrow has no byte
        ]
    );
}

#[test]
fn a_rollover_report_changes_nothing() {
    let (mut d, l) = kbd();
    assert_eq!(run(&mut d, &l, &[0, 0, 4, 0, 0, 0, 0, 0]), vec![key(KEY_A, 1)]);
    // Seven keys at once: a keyboard that cannot say sends ErrorRollOver in every slot.
    assert_eq!(run(&mut d, &l, &[0, 0, 1, 1, 1, 1, 1, 1]), vec![]);
    assert_eq!(d.dropped, 1);
    // `a` is still down: its release is the next report that lacks it.
    assert_eq!(run(&mut d, &l, &[0; 8]), vec![key(KEY_A, 0)]);
}

#[test]
fn a_short_or_empty_report_is_not_a_crash() {
    let (mut d, l) = kbd();
    assert_eq!(run(&mut d, &l, &[]), vec![]);
    // Four bytes: the modifiers and the first two key slots are there.
    assert_eq!(run(&mut d, &l, &[0, 0, 4, 5]), vec![key(KEY_A, 1), key(48, 1)]);
    assert_eq!(d.dropped, 1);
}

#[test]
fn a_nkro_bitmap_reports_every_key_it_holds() {
    let l = Layout::parse(NKRO_KEYBOARD).unwrap();
    let mut d = Decoder::new();
    let mut r = [0u8; 15];
    // Usage 4 (a) is bit 0 of the bitmap, usage 0x1d (z) bit 25, F24 (0x73) bit 111.
    r[1] |= 1;
    r[1 + 25 / 8] |= 1 << (25 % 8);
    r[1 + 111 / 8] |= 1 << (111 % 8);
    assert_eq!(run(&mut d, &l, &r), vec![key(KEY_A, 1), key(44, 1), key(194, 1)]);
    assert_eq!(run(&mut d, &l, &[0; 15]), vec![key(KEY_A, 0), key(44, 0), key(194, 0)]);
}

#[test]
fn the_boot_mouse_moves_clicks_and_y_is_not_inverted() {
    let l = Layout::parse(BOOT_MOUSE).unwrap();
    let mut d = Decoder::new();
    // Left button, X +5, Y +3 (HID Y is positive downward, as evdev's).
    assert_eq!(run(&mut d, &l, &[0x01, 5, 3]), vec![(EV_REL, REL_X, 5), (EV_REL, REL_Y, 3), key(BTN_LEFT, 1)]);
    // Released, moved left and up.
    assert_eq!(
        run(&mut d, &l, &[0x00, 0xfb, 0xfd]),
        vec![(EV_REL, REL_X, (-5i32) as u32), (EV_REL, REL_Y, (-3i32) as u32), key(BTN_LEFT, 0)]
    );
    // No motion, no event.
    assert_eq!(run(&mut d, &l, &[0, 0, 0]), vec![]);
}

#[test]
fn relative_axes_are_signed() {
    let l = Layout::parse(BOOT_MOUSE).unwrap();
    let mut d = Decoder::new();
    let ev = run(&mut d, &l, &[0, 0xff, 0x80]);
    assert_eq!(ev, vec![(EV_REL, REL_X, (-1i32) as u32), (EV_REL, REL_Y, (-128i32) as u32)]);
}

#[test]
fn a_report_with_an_id_is_read_after_the_id() {
    let l = Layout::parse(LOGITECH_MOUSE).unwrap();
    let mut d = Decoder::new();
    // ID 2; buttons 1 and 16; X = -1 (0xfff), Y = 1 in 12 bits each; wheel -2; pan 3.
    let r = [2u8, 0x01, 0x80, 0xff, 0x1f, 0x00, 0xfe, 0x03];
    assert_eq!(
        run(&mut d, &l, &r),
        vec![
            (EV_REL, REL_X, (-1i32) as u32),
            (EV_REL, REL_Y, 1),
            (EV_REL, REL_WHEEL, (-2i32) as u32),
            (EV_REL, REL_HWHEEL, 3),
            key(BTN_LEFT, 1),
            key(BTN_LEFT + 15, 1),
        ]
    );
    // A report of an ID the descriptor does not have is dropped, counted.
    assert_eq!(run(&mut d, &l, &[0x10, 1, 2, 3, 4, 5, 6]), vec![]);
    assert_eq!(d.dropped, 1);
}

#[test]
fn an_apple_keyboard_report_with_id_1_decodes_and_the_consumer_report_is_dropped() {
    let l = Layout::parse(APPLE_KEYBOARD).unwrap();
    let mut d = Decoder::new();
    assert_eq!(run(&mut d, &l, &[1, 0x08, 0, 0x2c, 0, 0, 0, 0, 0]), vec![key(KEY_LEFTMETA, 1), key(KEY_SPACE, 1)]);
    // The consumer report (ID 2): its controls were not kept, so there is
    // nothing to decode and the bits that were down are not touched.
    assert_eq!(run(&mut d, &l, &[2, 0x02]), vec![]);
    assert_eq!(run(&mut d, &l, &[1, 0, 0, 0, 0, 0, 0, 0, 0]), vec![key(KEY_LEFTMETA, 0), key(KEY_SPACE, 0)]);
}

#[test]
fn a_tablet_position_is_scaled_and_sent_when_it_changes() {
    let l = Layout::parse(QEMU_TABLET).unwrap();
    let mut d = Decoder::new();
    // Buttons 0, X = 0x7fff, Y = 0x3fff, wheel 0.
    let ev = run(&mut d, &l, &[0, 0xff, 0x7f, 0xff, 0x3f, 0]);
    assert_eq!(ev, vec![(EV_ABS, ABS_X, ABS_MAX), (EV_ABS, ABS_Y, 0x3fff * ABS_MAX / 0x7fff)]);
    // The same position: nothing. A click at it: the button only.
    assert_eq!(run(&mut d, &l, &[1, 0xff, 0x7f, 0xff, 0x3f, 0]), vec![key(BTN_LEFT, 1)]);
    // Only Y moved; the wheel turned.
    let ev = run(&mut d, &l, &[1, 0xff, 0x7f, 0x00, 0x00, 0xff]);
    assert_eq!(ev, vec![(EV_ABS, ABS_Y, 0), (EV_REL, REL_WHEEL, (-1i32) as u32)]);
}

#[test]
fn a_gamepad_report_gives_nothing() {
    let l = Layout::parse(GAMEPAD).unwrap();
    let mut d = Decoder::new();
    assert_eq!(run(&mut d, &l, &[10, 20, 0xff]), vec![]);
}

#[test]
fn releasing_everything_leaves_no_key_down() {
    let (mut d, l) = kbd();
    run(&mut d, &l, &[0x03, 0, 4, 5, 0, 0, 0, 0]);
    let mut v = Vec::new();
    d.release_all(|ty, code, value| v.push((ty, code, value)));
    assert_eq!(v, vec![key(KEY_LEFTCTRL, 0), key(KEY_LEFTSHIFT, 0), key(KEY_A, 0), key(48, 0)]);
    let mut again = Vec::new();
    d.release_all(|ty, code, value| again.push((ty, code, value)));
    assert!(again.is_empty());
}

#[test]
fn autorepeat_repeats_the_last_key_after_a_delay_at_a_period() {
    let mut r = Repeat::new();
    r.observe(EV_KEY, KEY_A, 1, 1000, 500);
    assert_eq!(r.due(1499, 33), None);
    assert_eq!(r.due(1500, 33), Some(KEY_A));
    assert_eq!(r.due(1520, 33), None);
    assert_eq!(r.due(1533, 33), Some(KEY_A));
    // A late service repeats once, not for every period it missed.
    assert_eq!(r.due(2000, 33), Some(KEY_A));
    assert_eq!(r.due(2001, 33), None);
    // A second key takes over; releasing the first (still held) does not stop it.
    r.observe(EV_KEY, 48, 1, 2100, 500);
    r.observe(EV_KEY, KEY_A, 0, 2200, 500);
    assert_eq!(r.due(2600, 33), Some(48));
    // Its release stops it.
    r.observe(EV_KEY, 48, 0, 2610, 500);
    assert_eq!(r.due(3000, 33), None);
}

#[test]
fn modifiers_buttons_and_axes_do_not_repeat() {
    let mut r = Repeat::new();
    r.observe(EV_KEY, KEY_LEFTSHIFT, 1, 0, 500);
    r.observe(EV_KEY, BTN_LEFT, 1, 0, 500);
    r.observe(EV_REL, REL_X, 1, 0, 500);
    assert_eq!(r.due(10_000, 33), None);
    assert!(Repeat::repeats(KEY_UP) && Repeat::repeats(KEY_A));
    assert!(!Repeat::repeats(KEY_RIGHTALT) && !Repeat::repeats(BTN_MIDDLE) && !Repeat::repeats(0));
}

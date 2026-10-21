// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The report descriptor parser on recorded descriptors.

use azos_input_wire::event::{ABS_X, ABS_Y, REL_HWHEEL, REL_WHEEL, REL_X, REL_Y};
use azos_usb_hid::report::{Kind, Layout, ParseError, MAX_CONTROLS};

use crate::fixtures::*;

fn kinds(l: &Layout) -> Vec<(Kind, u16, u8, u16)> {
    l.controls().iter().map(|c| (c.kind, c.off, c.size, c.count)).collect()
}

#[test]
fn the_boot_keyboard_is_a_modifier_run_and_an_array_of_six() {
    let l = Layout::parse(BOOT_KEYBOARD).unwrap();
    assert!(!l.has_ids && l.keys && !l.pointer);
    assert_eq!(l.n_ids, 1);
    // 8 modifier bits, a reserved byte, six key bytes; the LED output is no input.
    assert_eq!(l.bits[0], 64);
    assert_eq!(l.max_report_bytes(), 8);
    assert_eq!(kinds(&l), vec![(Kind::Bits, 0, 1, 8), (Kind::Array, 16, 8, 6)]);
    let run = l.controls()[0];
    assert_eq!((run.page, run.base), (7, 0xe0));
    let arr = l.controls()[1];
    assert_eq!((arr.base, arr.lmin, arr.lmax), (0, 0, 0x65));
}

#[test]
fn the_boot_mouse_is_three_buttons_and_two_signed_axes() {
    let l = Layout::parse(BOOT_MOUSE).unwrap();
    assert!(l.pointer && !l.keys && !l.has_ids);
    assert_eq!(l.bits[0], 24);
    assert_eq!(kinds(&l), vec![(Kind::Bits, 0, 1, 3), (Kind::Rel, 8, 8, 1), (Kind::Rel, 16, 8, 1)]);
    let c = l.controls();
    assert_eq!((c[0].page, c[0].base), (9, 1));
    assert_eq!((c[1].code, c[1].lmin, c[1].lmax), (REL_X, -127, 127));
    assert_eq!(c[2].code, REL_Y);
}

#[test]
fn the_drivers_boot_layouts_are_those_descriptors() {
    for (proto, d) in [(1u8, BOOT_KEYBOARD), (2, BOOT_MOUSE)] {
        let l = azos_usb_hid::boot::layout(proto).unwrap();
        assert_eq!(kinds(&l), kinds(&Layout::parse(d).unwrap()));
    }
    assert!(azos_usb_hid::boot::layout(0).is_none());
    assert!(azos_usb_hid::boot::layout(3).is_none());
}

#[test]
fn the_logitech_receiver_mouse_has_report_id_2_and_twelve_bit_axes() {
    let l = Layout::parse(LOGITECH_MOUSE).unwrap();
    assert!(l.has_ids && l.pointer);
    assert_eq!(&l.ids[..l.n_ids as usize], &[2]);
    // 16 buttons, X and Y of 12 bits, wheel and pan of 8: 7 payload bytes, 8 with the ID.
    assert_eq!(l.bits[0], 56);
    assert_eq!(l.max_report_bytes(), 8);
    let c = l.controls();
    assert_eq!(c.len(), 5);
    assert_eq!((c[0].kind, c[0].count, c[0].page, c[0].base), (Kind::Bits, 16, 9, 1));
    assert_eq!((c[1].code, c[1].off, c[1].size, c[1].lmin, c[1].lmax), (REL_X, 16, 12, -2047, 2047));
    assert_eq!((c[2].code, c[2].off, c[2].size), (REL_Y, 28, 12));
    assert_eq!((c[3].code, c[3].off, c[3].size, c[3].lmin), (REL_WHEEL, 40, 8, -127));
    // AC Pan is on the consumer page, inside the mouse collection.
    assert_eq!((c[4].code, c[4].off), (REL_HWHEEL, 48));
}

#[test]
fn vendor_collections_advance_nothing_and_give_nothing() {
    let l = Layout::parse(LOGITECH_HIDPP).unwrap();
    assert!(l.has_ids);
    assert!(!l.is_useful());
    // Three report IDs seen, 6, 19 and 14 bytes.
    assert_eq!(&l.ids[..l.n_ids as usize], &[0x10, 0x11, 0x20]);
    assert_eq!(&l.bits[..3], &[48, 152, 112]);
}

#[test]
fn an_apple_style_keyboard_keeps_its_keyboard_and_ignores_the_rest() {
    let l = Layout::parse(APPLE_KEYBOARD).unwrap();
    assert!(l.has_ids && l.keys && !l.pointer);
    // IDs 1 (keyboard) and 2 (consumer) have input; 0x11 has a Feature item only.
    assert_eq!(&l.ids[..l.n_ids as usize], &[1, 2]);
    assert_eq!(&l.bits[..2], &[64, 8]);
    // The consumer collection is nobody's: the keyboard's two controls are all.
    assert_eq!(kinds(&l), vec![(Kind::Bits, 0, 1, 8), (Kind::Array, 16, 8, 6)]);
    let arr = l.controls()[1];
    assert_eq!((arr.lmin, arr.lmax), (0, 255));
    assert_eq!(l.controls()[0].id, 0);
}

#[test]
fn the_qemu_tablet_has_absolute_axes_and_a_relative_wheel() {
    let l = Layout::parse(QEMU_TABLET).unwrap();
    let c = l.controls();
    assert_eq!(c.len(), 4);
    assert_eq!((c[0].kind, c[0].count), (Kind::Bits, 3));
    assert_eq!((c[1].kind, c[1].code, c[1].off, c[1].size, c[1].lmax), (Kind::Abs, ABS_X, 8, 16, 32767));
    assert_eq!((c[2].kind, c[2].code, c[2].off), (Kind::Abs, ABS_Y, 24));
    assert_eq!((c[3].kind, c[3].code, c[3].off), (Kind::Rel, REL_WHEEL, 40));
}

#[test]
fn a_nkro_bitmap_is_one_control_over_112_usages() {
    let l = Layout::parse(NKRO_KEYBOARD).unwrap();
    assert_eq!(kinds(&l), vec![(Kind::Bits, 0, 1, 8), (Kind::Bits, 8, 1, 112)]);
    assert_eq!(l.controls()[1].base, 4);
}

#[test]
fn a_gamepad_is_not_a_pointer() {
    let l = Layout::parse(GAMEPAD).unwrap();
    assert!(!l.is_useful() && !l.pointer && !l.keys);
    // Its bits are counted all the same.
    assert_eq!(l.bits[0], 24);
}

#[test]
fn explicit_usages_are_judged_one_by_one() {
    // Keyboard app; a variable item with Usage lists (A, B, F1) of 1 bit each.
    let d = [
        0x05, 0x01, 0x09, 0x06, 0xa1, 0x01, 0x05, 0x07, 0x09, 0x04, 0x09, 0x05, 0x09, 0x3a, 0x15, 0x00, 0x25, 0x01, 0x75,
        0x01, 0x95, 0x03, 0x81, 0x02, 0xc0,
    ];
    let l = Layout::parse(&d).unwrap();
    assert_eq!(kinds(&l), vec![(Kind::Bits, 0, 1, 1), (Kind::Bits, 1, 1, 1), (Kind::Bits, 2, 1, 1)]);
    let bases: Vec<u16> = l.controls().iter().map(|c| c.base).collect();
    assert_eq!(bases, vec![4, 5, 0x3a]);
}

#[test]
fn push_and_pop_restore_the_globals() {
    // Report size 8 / count 1 pushed, changed to 1 / 8 for the buttons, popped for an axis.
    let d = [
        0x05, 0x01, 0x09, 0x02, 0xa1, 0x01, 0x75, 0x08, 0x95, 0x01, 0xa4, 0x05, 0x09, 0x19, 0x01, 0x29, 0x08, 0x15, 0x00,
        0x25, 0x01, 0x75, 0x01, 0x95, 0x08, 0x81, 0x02, 0xb4, 0x05, 0x01, 0x09, 0x30, 0x15, 0x81, 0x25, 0x7f, 0x81, 0x06,
        0xc0,
    ];
    let l = Layout::parse(&d).unwrap();
    assert_eq!(kinds(&l), vec![(Kind::Bits, 0, 1, 8), (Kind::Rel, 8, 8, 1)]);
}

#[test]
fn a_long_item_is_skipped_and_a_four_byte_usage_carries_its_page() {
    // A long item (0xfe, 2 data bytes, tag 0x10) before a keyboard whose
    // application usage is the extended 0x00010006.
    let d = [
        0xfe, 0x02, 0x10, 0xaa, 0xbb, 0x0b, 0x06, 0x00, 0x01, 0x00, 0xa1, 0x01, 0x05, 0x07, 0x19, 0xe0, 0x29, 0xe7, 0x15,
        0x00, 0x25, 0x01, 0x75, 0x01, 0x95, 0x08, 0x81, 0x02, 0xc0,
    ];
    let l = Layout::parse(&d).unwrap();
    assert!(l.keys);
    assert_eq!(kinds(&l), vec![(Kind::Bits, 0, 1, 8)]);
}

#[test]
fn a_malformed_descriptor_is_refused_not_guessed() {
    // An item whose data runs past the end.
    assert_eq!(Layout::parse(&BOOT_KEYBOARD[..BOOT_KEYBOARD.len() - 4]).err(), Some(ParseError::Truncated));
    assert_eq!(Layout::parse(&[0x05]).err(), Some(ParseError::Truncated));
    // End Collection with nothing open.
    assert_eq!(Layout::parse(&[0xc0]).err(), Some(ParseError::Unbalanced));
    // Pop with nothing pushed.
    assert_eq!(Layout::parse(&[0xb4]).err(), Some(ParseError::Unbalanced));
    // The empty descriptor parses to nothing useful.
    assert!(!Layout::parse(&[]).unwrap().is_useful());
}

#[test]
fn more_controls_than_the_table_holds_is_an_error() {
    // Keyboard app; each main item names 16 explicit usages: 3 items = 48 controls.
    let mut d = vec![0x05, 0x01, 0x09, 0x06, 0xa1, 0x01, 0x05, 0x07, 0x15, 0x00, 0x25, 0x01, 0x75, 0x01, 0x95, 0x10];
    for _ in 0..3 {
        for u in 4..20u8 {
            d.extend([0x09, u]);
        }
        d.extend([0x81, 0x02]);
    }
    d.push(0xc0);
    assert!(MAX_CONTROLS < 48);
    assert_eq!(Layout::parse(&d).err(), Some(ParseError::TooManyControls));
}

#[test]
fn more_report_ids_than_the_table_holds_is_an_error() {
    let mut d = vec![0x05, 0x01, 0x09, 0x02, 0xa1, 0x01, 0x05, 0x09, 0x19, 0x01, 0x29, 0x01, 0x75, 0x01, 0x95, 0x01];
    for id in 1..=9u8 {
        d.extend([0x85, id, 0x81, 0x02]);
    }
    d.push(0xc0);
    assert_eq!(Layout::parse(&d).err(), Some(ParseError::TooManyIds));
}

#[test]
fn a_logical_maximum_is_signed_only_when_the_minimum_is() {
    // Logical 0..255 in one byte (`26 ff 00` is 2 bytes; `25 ff` is -1 as 1 byte but 255 here).
    let d = [
        0x05, 0x01, 0x09, 0x06, 0xa1, 0x01, 0x05, 0x07, 0x19, 0x00, 0x29, 0xff, 0x15, 0x00, 0x25, 0xff, 0x75, 0x08, 0x95,
        0x06, 0x81, 0x00, 0xc0,
    ];
    let l = Layout::parse(&d).unwrap();
    assert_eq!(l.controls()[0].lmax, 255);
    // And -127..127 is signed.
    let m = Layout::parse(BOOT_MOUSE).unwrap();
    assert_eq!(m.controls()[1].lmin, -127);
}

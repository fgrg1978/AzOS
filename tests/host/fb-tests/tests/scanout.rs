// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host test for `azos_fb::scanout`: the registered framebuffer as the
//! `Display` interface's scanout. The connector it reports, the mode list the
//! current mode and an EDID make, the copy of a band onto the framebuffer, the
//! flip hook, the panic flag and the console handover, all through the
//! `azos_devif::Scanout` trait the kernel's server calls.
//!
//! One test: the framebuffer registry is process-wide.

use azos_devif::display::{
    Rect, Scanout, CONN_CONNECTED, CONN_EDID, FORMAT_XBGR8888, FORMAT_XRGB8888, MODE_CURRENT, MODE_PREFERRED, SURFACES,
};
use azos_fb::pixel::PixelFormat;
use azos_fb::scanout::{publish_edid, SCANOUT};
use azos_fb::FbInfo;
use std::sync::atomic::AtomicU8;
use std::sync::Mutex;

mod common;
use common::{hex, FHD_1_3, SXGA_1_3, TV_1_3_CTA};

static FLIPS: Mutex<Vec<azos_fb::Rect>> = Mutex::new(Vec::new());

fn hook(r: azos_fb::Rect) {
    FLIPS.lock().unwrap().push(r);
}

fn flips() -> Vec<(u32, u32, u32, u32)> {
    std::mem::take(&mut *FLIPS.lock().unwrap()).iter().map(|r| (r.x, r.y, r.w, r.h)).collect()
}

fn modes(s: &dyn Scanout) -> Vec<(u32, u32, u32, u32)> {
    let n = s.connector().unwrap().modes;
    (0..n).map(|i| s.mode(i).unwrap()).map(|m| (m.width, m.height, m.refresh_mhz, m.flags)).collect()
}

/// **Canary.** List the current mode again among the display's (do not skip the
/// equal entry): 640x480 appears twice in the 640x480 list below.
#[test]
fn the_framebuffer_is_a_scanout_with_modes_a_copy_and_a_handover() {
    let s: &dyn Scanout = &SCANOUT;

    // ── no framebuffer yet ──
    assert_eq!(s.connector(), None);
    assert_eq!(s.mode(0), None);
    assert!(!s.retire_console() && !s.resume_console());
    assert!(!publish_edid(&[0u8; 300]), "not an EDID");
    let blank: [AtomicU8; 16] = Default::default();
    assert!(!s.copy_rect(&blank, 16, 0, Rect::new(0, 0, 1, 1)), "no screen to copy onto");

    // ── a 640x480 XRGB8888 framebuffer with a padded stride ──
    let (w, h, stride) = (640u32, 480u32, 640 * 4 + 64);
    let mem: &'static mut [u8] = Box::leak(vec![0u8; (stride * h) as usize].into_boxed_slice());
    let base = mem.as_mut_ptr();
    let fi = FbInfo { phys: 0x9000_0000, width: w, height: h, stride, format: PixelFormat::XRGB8888 };
    assert!(azos_fb::register(fi, base as usize));
    assert!(azos_fb::set_flip(hook));

    let c = s.connector().unwrap();
    assert_eq!((c.width, c.height, c.stride, c.format), (w, h, stride, FORMAT_XRGB8888));
    assert_eq!((c.refresh_mhz, c.flags, c.width_mm, c.height_mm, c.modes), (60_000, CONN_CONNECTED, 0, 0, 1));
    assert_eq!(c.surfaces, SURFACES as u32);
    assert_eq!(modes(s), vec![(640, 480, 60_000, MODE_CURRENT)], "one mode without an EDID");
    assert_eq!(s.mode(1), None);

    // ── with an EDID ──
    let mut broken = hex(FHD_1_3);
    broken[40] ^= 1;
    assert!(!publish_edid(&broken), "a bad checksum changes nothing");
    assert_eq!(s.connector().unwrap().flags, CONN_CONNECTED);
    assert!(publish_edid(&hex(FHD_1_3)));
    let c = s.connector().unwrap();
    assert_eq!((c.flags, c.width_mm, c.height_mm, c.refresh_mhz, c.modes), (CONN_CONNECTED | CONN_EDID, 509, 286, 60_000, 10));
    // The display lists 640x480 at 60 Hz (an established timing): that is the
    // current mode, listed once, first; the other nine follow in the
    // display's order, the preferred 1920x1080 first of them.
    assert_eq!(
        modes(s),
        vec![
            (640, 480, 60_000, MODE_CURRENT),
            (1920, 1080, 60_000, MODE_PREFERRED),
            (1280, 1024, 60_000, 0),
            (1280, 960, 60_000, 0),
            (1440, 900, 60_000, 0),
            (1600, 900, 60_000, 0),
            (1680, 1050, 60_000, 0),
            (1280, 800, 60_000, 0),
            (800, 600, 60_000, 0),
            (1024, 768, 60_000, 0),
        ]
    );
    assert_eq!(s.mode(10), None);

    // Another display, whose list has 640x480 at 72 Hz before 640x480 at 60:
    // the current mode's refresh is the entry nearest 60 Hz, and the other
    // is a mode of its own.
    assert!(publish_edid(&hex(SXGA_1_3)));
    let m = modes(s);
    assert_eq!(m[0], (640, 480, 60_000, MODE_CURRENT));
    assert_eq!(m[1], (1280, 1024, 60_020, MODE_PREFERRED));
    assert!(m.contains(&(640, 480, 72_000, 0)));
    assert_eq!(m.iter().filter(|x| (x.0, x.1, x.2) == (640, 480, 60_000)).count(), 1);
    // A television with no 640x480 at all: the current mode is the default rate.
    assert!(publish_edid(&hex(TV_1_3_CTA)));
    let m = modes(s);
    assert_eq!(m[0], (640, 480, 60_000, MODE_CURRENT), "no 640x480 in its list: the default rate");
    assert_eq!(m[1], (1920, 1080, 60_000, MODE_PREFERRED));
    assert_eq!(s.connector().unwrap().modes as usize, m.len());
    assert!(publish_edid(&hex(FHD_1_3)), "back to the first");

    // ── the pixel format code ──
    // (A scanout in another layout reports it, or 0 when the interface has no name for it.)
    assert_ne!(FORMAT_XRGB8888, FORMAT_XBGR8888);

    // ── copy and flip ──
    // An image of rows 100..200 only (a band): 100 rows of the same stride.
    let src_stride = stride as usize;
    let mut img = vec![0u8; 100 * src_stride];
    for row in 0..100usize {
        for x in 0..w as usize {
            let v = ((100 + row) * 1000 + x + 1) as u32;
            img[row * src_stride + x * 4..][..4].copy_from_slice(&v.to_le_bytes());
        }
    }
    // The image as the scanout sees a client's surface: bytes that may change.
    let img: Vec<AtomicU8> = img.into_iter().map(AtomicU8::new).collect();
    let copy = |top: u32, r: Rect| s.copy_rect(&img, stride, top, r);
    assert!(copy(100, Rect::new(5, 150, 10, 20)));
    let px = |x: u32, y: u32| u32::from_le_bytes(unsafe { std::slice::from_raw_parts(base.add((y * stride + x * 4) as usize), 4) }.try_into().unwrap());
    assert_eq!(px(5, 150), 150 * 1000 + 6);
    assert_eq!(px(14, 169), 169 * 1000 + 15);
    assert_eq!(px(4, 150), 0);
    assert_eq!(px(15, 150), 0);
    assert_eq!(px(5, 149), 0);
    assert_eq!(px(5, 170), 0);
    assert!(!copy(100, Rect::new(0, 99, 4, 2)), "starts above the band");
    assert!(!copy(100, Rect::new(0, 199, 4, 2)), "reaches below it");
    // Past the right edge the rectangle is cut to the screen (the server never
    // sends one: `Present::check` refuses it first).
    assert!(copy(100, Rect::new(630, 100, 20, 1)));
    assert_eq!(px(639, 100), 100 * 1000 + 640);
    assert_eq!(px(630, 100), 100 * 1000 + 631);
    assert_eq!(px(629, 100), 0);
    assert!(flips().is_empty(), "a copy flips nothing; the server says when");
    s.flip(Rect::new(5, 150, 10, 20));
    s.flip(Rect::new(0, 0, 640, 480));
    assert_eq!(flips(), vec![(5, 150, 10, 20), (0, 0, 640, 480)]);

    // ── the panic flag and the console ──
    assert!(!s.panic_active());
    assert!(s.retire_console());
    assert!(!s.retire_console(), "once");
    assert!(azos_fb::console_retired());
    assert!(s.resume_console());
    assert!(!s.resume_console(), "once");
    azos_fb::panic::puts("x");
    assert!(s.panic_active());
}

// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host tests for `azos_fb::blit::copy_rect`, the pixel move of a `present`:
//! a rectangle of a client's image lands at the same place on the scanout,
//! clipped, with both strides honoured, and nothing outside it is touched.

use azos_fb::blit::copy_rect;
use azos_fb::pixel::{PixelFormat, Surface};
use azos_fb::Rect;

const W: usize = 10;
const H: usize = 6;

struct Screen {
    mem: Vec<u8>,
    s: Surface,
}

/// A screen with a padded stride of its own, filled with `fill`.
fn screen(fmt: PixelFormat, pad: usize, fill: u8) -> Screen {
    let stride = W * fmt.bytes() + pad;
    let mut mem = vec![fill; stride * H];
    let s = Surface { base: mem.as_mut_ptr(), width: W, height: H, stride, fmt };
    Screen { mem, s }
}

/// An image of the same size with a different stride; pixel (x, y) holds the
/// bytes `[x as u8 + 1, y as u8 + 1, ..]` so every pixel is distinguishable.
fn image(fmt: PixelFormat, stride: usize) -> Vec<u8> {
    let bpp = fmt.bytes();
    let mut v = vec![0xEE; stride * H];
    for y in 0..H {
        for x in 0..W {
            for c in 0..bpp {
                v[y * stride + x * bpp + c] = if c == 0 { x as u8 + 1 } else if c == 1 { y as u8 + 1 } else { 0x40 + c as u8 };
            }
        }
    }
    v
}

fn r(x: u32, y: u32, w: u32, h: u32) -> Rect {
    Rect { x, y, w, h }
}

/// For every pixel size: the rectangle is copied, pixel for pixel, and every
/// pixel outside it keeps what it had, including the padding of each row.
///
/// **Canary:** index the source by the screen's stride instead of the
/// image's: the pixels inside the rectangle come out shifted.
#[test]
fn the_rectangle_lands_where_it_was_and_nothing_else_changes() {
    for fmt in [PixelFormat::XRGB8888, PixelFormat::RGB888, PixelFormat::RGB565] {
        let bpp = fmt.bytes();
        let sc = screen(fmt, 12, 0x11);
        let src = image(fmt, W * bpp + 20);
        let got = copy_rect(&sc.s, &src, W * bpp + 20, 0, r(2, 1, 5, 3));
        assert_eq!(got, Some(r(2, 1, 5, 3)));
        for y in 0..H {
            for x in 0..W {
                let inside = (2..7).contains(&x) && (1..4).contains(&y);
                for c in 0..bpp {
                    let have = sc.mem[y * sc.s.stride + x * bpp + c];
                    let want = if inside { src[y * (W * bpp + 20) + x * bpp + c] } else { 0x11 };
                    assert_eq!(have, want, "fmt {}bpp pixel ({x},{y}) byte {c}", fmt.bpp);
                }
            }
            for p in W * bpp..sc.s.stride {
                assert_eq!(sc.mem[y * sc.s.stride + p], 0x11, "row padding of row {y}");
            }
        }
    }
}

/// A rectangle past the screen is cut to it and the cut rectangle is what
/// comes back (what the display is told to flip); one wholly outside, or
/// empty, copies nothing.
#[test]
fn the_rectangle_is_cut_to_the_screen() {
    let fmt = PixelFormat::XRGB8888;
    let sc = screen(fmt, 0, 0);
    let src = image(fmt, W * 4);
    assert_eq!(copy_rect(&sc.s, &src, W * 4, 0, r(8, 4, 100, 100)), Some(r(8, 4, 2, 2)));
    assert_eq!(sc.mem[4 * W * 4 + 8 * 4], 9, "pixel (8,4)");
    assert_eq!(sc.mem[5 * W * 4 + 9 * 4], 10, "pixel (9,5), the last");
    let after = sc.mem.clone();
    for rect in [r(W as u32, 0, 3, 3), r(0, H as u32, 3, 3), r(0, 0, 0, 3), r(0, 0, 3, 0), r(u32::MAX, u32::MAX, 5, 5)] {
        assert_eq!(copy_rect(&sc.s, &src, W * 4, 0, rect), None, "{rect:?}");
    }
    assert_eq!(sc.mem, after);
}

/// An image that is too short for the rectangle's last byte, or whose stride
/// is shorter than a row of the screen, copies nothing at all (not the rows
/// that would have fit).
///
/// **Canary:** drop the length check: the short image reads past its end (a
/// debug build or Miri says so) or the first rows are copied before the
/// refusal.
#[test]
fn a_short_image_is_refused_whole() {
    let fmt = PixelFormat::XRGB8888;
    let sc = screen(fmt, 0, 0x22);
    let src = image(fmt, W * 4);
    let before = sc.mem.clone();
    // One byte short of the last pixel of row 5.
    assert_eq!(copy_rect(&sc.s, &src[..src.len() - 1], W * 4, 0, r(0, 0, W as u32, H as u32)), None);
    assert_eq!(sc.mem, before);
    // The same rectangle ends in row 4: the same short image holds it.
    assert!(copy_rect(&sc.s, &src[..src.len() - 1], W * 4, 0, r(0, 0, W as u32, 5)).is_some());
    let sc = screen(fmt, 0, 0x22);
    assert_eq!(copy_rect(&sc.s, &src, W * 4 - 1, 0, r(0, 0, 2, 2)), None, "stride shorter than a row");
    assert_eq!(copy_rect(&sc.s, &[], 0, 0, r(0, 0, 2, 2)), None);
    assert!(sc.mem.iter().all(|&b| b == 0x22));
    // A source stride so large that the offset arithmetic would overflow a 32-bit usize.
    assert_eq!(copy_rect(&sc.s, &src, usize::MAX / 2, 0, r(0, 1, 2, 2)), None);
}

/// A band: an image of rows 2..5 only. A rectangle inside those rows is
/// copied from the band's own first row; one that starts above the band, or
/// reaches below what the band holds, is refused whole.
///
/// **Canary:** index the band from row 0 instead of `src_top`: the pixels
/// come from rows 2 rows too far down and the length check refuses the
/// rectangle at the band's end.
#[test]
fn a_band_is_read_from_its_own_first_row() {
    let fmt = PixelFormat::XRGB8888;
    let sc = screen(fmt, 0, 0x33);
    let full = image(fmt, W * 4);
    let band = &full[2 * W * 4..5 * W * 4]; // screen rows 2, 3, 4
    assert_eq!(copy_rect(&sc.s, band, W * 4, 2, r(1, 3, 4, 2)), Some(r(1, 3, 4, 2)));
    for y in 0..H {
        for x in 0..W {
            let have = &sc.mem[y * sc.s.stride + x * 4..][..4];
            let inside = (1..5).contains(&x) && (3..5).contains(&y);
            if inside {
                assert_eq!(have, &full[y * W * 4 + x * 4..][..4], "pixel ({x},{y}) comes from its own row of the band");
            } else {
                assert_eq!(have, &[0x33; 4], "({x},{y}) untouched");
            }
        }
    }
    let before = sc.mem.clone();
    assert_eq!(copy_rect(&sc.s, band, W * 4, 2, r(0, 1, 2, 2)), None, "starts above the band");
    assert_eq!(copy_rect(&sc.s, band, W * 4, 2, r(0, 4, 2, 2)), None, "reaches below the band");
    assert_eq!(sc.mem, before);
}

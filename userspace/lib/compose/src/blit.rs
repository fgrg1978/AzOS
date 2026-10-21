// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Fill, blit and scale over [`Sink`] rows.
//!
//! The scale is the rational `num / den` of device pixels per source pixel
//! (an output at integer HiDPI factor `num` showing a buffer of factor `den`),
//! sampled by nearest neighbour: destination pixel `d`, counted from the
//! layer's origin, shows source pixel `floor(d * den / num)`. That is exact
//! integer arithmetic with no rounding to choose, a pixel row is walked with
//! two adders instead of a division per pixel, and the source pixels a damage
//! rectangle changes are the destination pixels [`dst_range`] names.

use crate::image::{Sink, Source};
use crate::pixel::{mix, Px, Rgb565, Xrgb, Format};
use azos_devif::display::Rect;

/// The destination pixels (counted from the layer's origin) that show source
/// pixels `a..b`: `ceil(a * num / den) .. ceil(b * num / den)`.
pub fn dst_range(a: u32, b: u32, num: u32, den: u32) -> (u32, u32) {
    let up = |v: u32| (v as u64 * num as u64).div_ceil(den as u64) as u32;
    (up(a), up(b))
}

/// Paint `rect` of `sink` with `rgb`. Rows the sink cannot give are added to
/// `missing`.
pub fn fill<K: Sink + ?Sized>(sink: &mut K, rect: Rect, rgb: u32, missing: &mut u32) {
    if rect.is_empty() {
        return;
    }
    let fmt = sink.format();
    let (x0, x1) = (rect.x as usize, rect.x as usize + rect.w as usize);
    for y in rect.y as u32..rect.y as u32 + rect.h as u32 {
        let Some(row) = sink.row_mut(y) else {
            *missing += 1;
            continue;
        };
        let bpp = fmt.bytes();
        let Some(span) = row.get_mut(x0 * bpp..x1 * bpp) else {
            *missing += 1;
            continue;
        };
        let (first, rest) = span.split_at_mut(bpp);
        fmt.store(first, rgb);
        for px in rest.chunks_exact_mut(bpp) {
            px.copy_from_slice(first);
        }
    }
}

/// `src` shown at `num / den` with its top left at device pixel
/// (`origin_x`, `origin_y`), cut to `clip` (the part of `clip` the image does
/// not reach is left alone). Rows either side cannot give are added to
/// `missing`.
///
/// `clip` lies inside the image's span on the screen and `src` is as large as the
/// layer says: the caller checked both.
pub(crate) fn blit_scaled<K: Sink + ?Sized>(
    sink: &mut K,
    clip: Rect,
    origin: (i64, i64),
    src: &dyn Source,
    (num, den): (u32, u32),
    missing: &mut u32,
) {
    let (num, den) = (num as i64, den as i64);
    let (sf, df) = (src.format(), sink.format());
    let (x0, x1) = (clip.x as i64, clip.x as i64 + clip.w as i64);
    // Where the first column of the clip lands in the source, and the remainder
    // the adders carry.
    let rel0 = if cfg!(feature = "canary-scale-origin") { 0 } else { x0 - origin.0 };
    let sx0 = (rel0 * den / num) as usize;
    let acc0 = (rel0 * den % num) as u32;
    let sx_last = ((x1 - 1 - origin.0) * den / num) as usize;
    for y in clip.y as i64..clip.y as i64 + clip.h as i64 {
        let sy = ((y - origin.1) * den / num) as u32;
        let (Some(s), Some(d)) = (src.row(sy), sink.row_mut(y as u32)) else {
            *missing += 1;
            continue;
        };
        if s.len() < (sx_last + 1) * sf.bytes() || d.len() < x1 as usize * df.bytes() {
            *missing += 1;
            continue;
        }
        let cols = (x0 as usize, x1 as usize);
        let step = (num as u32, den as u32);
        match (df, sf) {
            (Format::Xrgb8888, Format::Xrgb8888) if num == den => {
                let n = (cols.1 - cols.0) * 4;
                d[cols.0 * 4..cols.0 * 4 + n].copy_from_slice(&s[sx0 * 4..sx0 * 4 + n]);
            }
            (Format::Rgb565, Format::Rgb565) if num == den => {
                let n = (cols.1 - cols.0) * 2;
                d[cols.0 * 2..cols.0 * 2 + n].copy_from_slice(&s[sx0 * 2..sx0 * 2 + n]);
            }
            (Format::Xrgb8888, Format::Xrgb8888) => row::<Xrgb, Xrgb>(d, s, cols, sx0, acc0, step),
            (Format::Xrgb8888, Format::Rgb565) => row::<Xrgb, Rgb565>(d, s, cols, sx0, acc0, step),
            (Format::Rgb565, Format::Xrgb8888) => row::<Rgb565, Xrgb>(d, s, cols, sx0, acc0, step),
            (Format::Rgb565, Format::Rgb565) => row::<Rgb565, Rgb565>(d, s, cols, sx0, acc0, step),
        }
    }
}

/// One row: destination pixels `cols` from source pixel `sx`, `acc` the part
/// of a destination step already taken.
#[inline(always)]
fn row<D: Px, S: Px>(dst: &mut [u8], src: &[u8], cols: (usize, usize), mut sx: usize, mut acc: u32, (num, den): (u32, u32)) {
    for x in cols.0..cols.1 {
        D::store(&mut dst[x * D::BYTES..], S::load(&src[sx * S::BYTES..]));
        acc += den;
        while acc >= num {
            acc -= num;
            sx += 1;
        }
    }
}

/// A straight-alpha ARGB image (`0xAARRGGBB`, `w` x `h`, row after row) laid
/// over `sink` with its top left at (`x`, `y`) on the screen, cut to `clip`.
pub(crate) fn blend_argb<K: Sink + ?Sized>(
    sink: &mut K,
    clip: Rect,
    (x, y): (i64, i64),
    (w, px): (usize, &[u32]),
    missing: &mut u32,
) {
    let fmt = sink.format();
    let bpp = fmt.bytes();
    let rows = (px.len() / w) as i64;
    let y0 = (clip.y as i64).max(y);
    let y1 = (clip.y as i64 + clip.h as i64).min(y + rows);
    let x0 = (clip.x as i64).max(x);
    let x1 = (clip.x as i64 + clip.w as i64).min(x + w as i64);
    if x0 >= x1 {
        return;
    }
    for dy in y0..y1 {
        let Some(row) = sink.row_mut(dy as u32) else {
            *missing += 1;
            continue;
        };
        let Some(span) = row.get_mut(x0 as usize * bpp..x1 as usize * bpp) else {
            *missing += 1;
            continue;
        };
        let src = &px[(dy - y) as usize * w + (x0 - x) as usize..][..(x1 - x0) as usize];
        for (d, &p) in span.chunks_exact_mut(bpp).zip(src) {
            let a = p >> 24;
            match a {
                0 => {}
                255 => fmt.store(d, p),
                _ => {
                    let under = fmt.load(d);
                    fmt.store(d, mix(p, under, a));
                }
            }
        }
    }
}

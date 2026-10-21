// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host tests of the compositor's pixel engine (`userspace/lib/compose`).
//!
//! The proof has three layers. Golden images (`golden/*.txt`, one character per
//! pixel through [`PALETTE`]) pin what a scene looks like, so a wrong pixel is
//! seen where it is. A reference model that shares no code with the engine (a
//! per-pixel walk over the scene, `floor(d * den / num)` for the source pixel)
//! must agree with it on random scenes. And the invariant a damage-driven
//! compositor lives by: a frame that repaints only the damage leaves the
//! screen exactly as a full repaint would, and changes nothing outside the
//! damage it hands back.
//!
//! Canaries (cargo features of this crate, each planting one bug in the engine):
//! `canary-damage-drop` must fail `damage_always_covers_everything_added` and
//! `more_changes_than_a_present_holds_are_merged_not_lost`,
//! `canary-z-inverted` must fail `layers_stack_in_z_order`, `canary-scale-origin`
//! must fail `a_layer_cut_by_the_screen_edge_shows_the_right_pixels`.

#![cfg(test)]

use azos_compose::blit::{dst_range, fill};
use azos_compose::geom::{area, bounds, contains, intersect};
use azos_compose::pixel::mix;
use azos_compose::{Compositor, Damage, Error, Format, Image, ImageMut, Layer, Output, Sink, Source, Sources};
use azos_devif::display::{ConnectorInfo, Present, Rect, DAMAGE_MAX};
use std::collections::BTreeMap;

// ── fixtures ────────────────────────────────────────────────────────────────

/// Every colour is exact in RGB565 too (the channels are 0x00, 0x84 or 0xFF),
/// so one palette names the pixels of either format.
const PALETTE: [(char, u32); 11] = [
    ('.', 0x000000),
    ('n', 0x000084),
    ('R', 0xFF0000),
    ('G', 0x00FF00),
    ('B', 0x0000FF),
    ('W', 0xFFFFFF),
    ('Y', 0xFFFF00),
    ('C', 0x00FFFF),
    ('M', 0xFF00FF),
    ('g', 0x848284),
    // Half red over blue (the cursor test); not a 565 colour.
    ('p', 0x80007F),
];
const NAVY: u32 = 0x000084;

fn colour(c: char) -> u32 {
    PALETTE.iter().find(|p| p.0 == c).unwrap_or_else(|| panic!("no colour {c:?}")).1
}

/// A buffer the tests own: a client's image, or the screen.
#[derive(Clone)]
struct Buf {
    data: Vec<u8>,
    w: u32,
    h: u32,
    fmt: Format,
}

impl Buf {
    fn new(w: u32, h: u32, fmt: Format) -> Buf {
        Buf { data: vec![0xA5; (w * h) as usize * fmt.bytes()], w, h, fmt }
    }

    fn art(fmt: Format, rows: &[&str]) -> Buf {
        let (w, h) = (rows[0].len() as u32, rows.len() as u32);
        let mut b = Buf::new(w, h, fmt);
        for (y, row) in rows.iter().enumerate() {
            assert_eq!(row.len() as u32, w, "ragged art");
            for (x, c) in row.chars().enumerate() {
                b.put(x as u32, y as u32, colour(c));
            }
        }
        b
    }

    fn at(&self, x: u32, y: u32) -> usize {
        (y * self.w + x) as usize * self.fmt.bytes()
    }

    fn put(&mut self, x: u32, y: u32, rgb: u32) {
        let at = self.at(x, y);
        self.fmt.store(&mut self.data[at..], rgb);
    }

    fn get(&self, x: u32, y: u32) -> u32 {
        self.fmt.load(&self.data[self.at(x, y)..])
    }

    fn sink(&mut self) -> ImageMut<'_> {
        let stride = self.w as usize * self.fmt.bytes();
        ImageMut::new(&mut self.data, self.w, self.h, stride, self.fmt).unwrap()
    }

    /// One character per pixel; a colour the palette lacks is `?`.
    fn dump(&self) -> String {
        let mut s = String::new();
        for y in 0..self.h {
            for x in 0..self.w {
                let rgb = self.get(x, y);
                s.push(PALETTE.iter().find(|p| p.1 == rgb).map_or('?', |p| p.0));
            }
            s.push('\n');
        }
        s
    }
}

impl Source for Buf {
    fn width(&self) -> u32 {
        self.w
    }
    fn height(&self) -> u32 {
        self.h
    }
    fn format(&self) -> Format {
        self.fmt
    }
    fn row(&self, y: u32) -> Option<&[u8]> {
        let at = self.at(0, y);
        self.data.get(at..at + self.w as usize * self.fmt.bytes())
    }
}

#[derive(Default)]
struct Set(BTreeMap<u32, Buf>);

impl Sources for Set {
    fn source(&self, id: u32) -> Option<&dyn Source> {
        self.0.get(&id).map(|b| b as &dyn Source)
    }
}

fn golden(name: &str, got: &Buf) {
    let path = format!("{}/golden/{name}.txt", env!("CARGO_MANIFEST_DIR"));
    let text = got.dump();
    if std::env::var_os("COMPOSE_BLESS").is_some() {
        std::fs::write(&path, &text).unwrap();
    }
    let want = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e} (COMPOSE_BLESS=1 writes it)"));
    assert!(want == text, "golden {name} differs\n--- want\n{want}--- got\n{text}");
}

fn layer(id: u32, x: i32, y: i32, buf: &Buf, scale: u32) -> Layer {
    Layer { id, x, y, buf_w: buf.w, buf_h: buf.h, buffer_scale: scale, visible: true }
}

fn output(w: u32, h: u32, scale: u32) -> Output {
    Output::new(w, h, scale).unwrap()
}

/// A scene of `layers` over a navy background on a `w` x `h` screen at `scale`,
/// drawn once.
fn scene(w: u32, h: u32, scale: u32, fmt: Format, layers: &[(Layer, Buf)]) -> (Compositor<8>, Set, Buf) {
    let mut comp = Compositor::<8>::new(output(w, h, scale), NAVY);
    let mut set = Set::default();
    for (l, b) in layers {
        comp.add(*l).unwrap();
        set.0.insert(l.id, b.clone());
    }
    let mut fb = Buf::new(w, h, fmt);
    let f = comp.frame(&set, &mut fb.sink());
    assert_eq!(f.missing, 0);
    (comp, set, fb)
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: u64) -> u64 {
        (self.next() >> 11) % n
    }
    fn range(&mut self, lo: i32, hi: i32) -> i32 {
        lo + self.below((hi - lo) as u64) as i32
    }
}

const X: Format = Format::Xrgb8888;
const P: Format = Format::Rgb565;

// ── pixels ──────────────────────────────────────────────────────────────────

#[test]
fn rgb565_round_trips_every_pixel() {
    for v in 0..=u16::MAX {
        let mut px = v.to_le_bytes();
        let rgb = P.load(&px);
        P.store(&mut px, rgb);
        assert_eq!(u16::from_le_bytes(px), v, "{v:#06x} -> {rgb:#08x}");
    }
}

#[test]
fn rgb565_keeps_black_and_white() {
    let mut px = [0u8; 2];
    P.store(&mut px, 0xFFFFFF);
    assert_eq!(px, [0xFF, 0xFF]);
    assert_eq!(P.load(&px), 0xFFFFFF);
    P.store(&mut px, 0);
    assert_eq!(P.load(&px), 0);
    // Red is the top five bits of the word, blue the low five.
    P.store(&mut px, 0xFF0000);
    assert_eq!(u16::from_le_bytes(px), 0xF800);
    P.store(&mut px, 0x0000FF);
    assert_eq!(u16::from_le_bytes(px), 0x001F);
}

#[test]
fn xrgb_is_blue_first_and_ignores_the_unused_byte() {
    let mut px = [0u8; 4];
    X.store(&mut px, 0x11_2233_44);
    assert_eq!(px, [0x44, 0x33, 0x22, 0x00]);
    assert_eq!(X.load(&[0x44, 0x33, 0x22, 0xFF]), 0x223344);
}

#[test]
fn display_formats_the_engine_does_not_compose_are_refused() {
    use azos_devif::display::*;
    assert_eq!(Format::from_display(FORMAT_XRGB8888), Some(X));
    assert_eq!(Format::from_display(FORMAT_RGB565), Some(P));
    assert_eq!(Format::from_display(FORMAT_XBGR8888), None);
    assert_eq!(Format::from_display(FORMAT_RGB888), None);
    assert_eq!(Format::from_display(0), None);
}

#[test]
fn mix_is_the_rounded_division_by_255() {
    for a in 0..=255u32 {
        for s in 0..=255u32 {
            for d in 0..=255u32 {
                let want = (2 * (s * a + d * (255 - a)) + 255) / 510;
                let got = mix(s * 0x010101, d * 0x010101, a);
                assert_eq!(got, want * 0x010101, "s={s} d={d} a={a}");
            }
        }
    }
}

// ── images ──────────────────────────────────────────────────────────────────

#[test]
fn an_image_needs_its_pixels() {
    let data = [0u8; 4 * 3 * 2 + 8];
    assert!(Image::new(&data, 3, 2, 16, X).is_some());
    assert!(Image::new(&data[..16 + 12 - 1], 3, 2, 16, X).is_none(), "one byte short of the last pixel");
    assert!(Image::new(&data[..16 + 12], 3, 2, 16, X).is_some(), "the last row needs no padding");
    assert!(Image::new(&data, 3, 2, 8, X).is_none(), "a row shorter than its pixels");
    assert!(Image::new(&data, 0, 2, 16, X).is_none());
    assert!(Image::new(&data, 3, 0, 16, X).is_none());
    assert!(Image::new(&data, 3, 2, 16, P).is_some());
    assert!(Image::new(&data, usize::MAX as u32, 2, 16, X).is_none() || usize::BITS == 64);
}

#[test]
fn an_image_hands_out_exact_rows() {
    let mut data = vec![0u8; 16 * 2];
    for (i, b) in data.iter_mut().enumerate() {
        *b = i as u8;
    }
    let img = Image::new(&data, 3, 2, 16, X).unwrap();
    assert_eq!(img.row(1).unwrap(), &data[16..28]);
    assert!(img.row(2).is_none());
    let mut out = data.clone();
    let mut sink = ImageMut::new(&mut out, 3, 2, 16, X).unwrap();
    assert_eq!(sink.row_mut(0).unwrap().len(), 12);
    assert!(sink.row_mut(2).is_none());
}

// ── damage ──────────────────────────────────────────────────────────────────

fn painted(d: &Damage, side: u16) -> Vec<bool> {
    let mut m = vec![false; side as usize * side as usize];
    for r in d.rects() {
        for y in r.y..r.y + r.h {
            for x in r.x..r.x + r.w {
                m[y as usize * side as usize + x as usize] = true;
            }
        }
    }
    m
}

#[test]
fn a_covered_rectangle_adds_nothing_and_a_covering_one_replaces() {
    let mut d = Damage::new();
    assert!(d.is_empty());
    d.add(Rect::new(0, 0, 0, 5));
    assert!(d.is_empty(), "an empty rectangle is no damage");
    d.add(Rect::new(10, 10, 20, 20));
    d.add(Rect::new(12, 12, 4, 4));
    assert_eq!(d.rects(), &[Rect::new(10, 10, 20, 20)]);
    d.add(Rect::new(100, 100, 5, 5));
    d.add(Rect::new(0, 0, 200, 200));
    assert_eq!(d.rects(), &[Rect::new(0, 0, 200, 200)], "both held rectangles were inside it");
    d.clear();
    assert!(d.rects().is_empty());
}

#[test]
fn the_overflowing_rectangle_merges_where_it_wastes_least() {
    let mut d = Damage::new();
    // Six unit squares on a diagonal, far apart.
    for i in 0..DAMAGE_MAX as u16 {
        d.add(Rect::new(i * 20, i * 20, 1, 1));
    }
    assert_eq!(d.rects().len(), DAMAGE_MAX);
    // A seventh next to the third: the merge is those two, nothing else grows.
    d.add(Rect::new(41, 40, 1, 1));
    assert_eq!(d.rects().len(), DAMAGE_MAX);
    assert!(d.rects().contains(&Rect::new(40, 40, 2, 1)));
    for i in [0u16, 1, 3, 4, 5] {
        assert!(d.rects().contains(&Rect::new(i * 20, i * 20, 1, 1)), "square {i} untouched");
    }
}

#[test]
fn two_held_rectangles_merge_when_that_wastes_less_than_growing_one_for_the_new() {
    let mut d = Damage::new();
    // Two neighbours and four loners; the new one is far from everything, so the
    // cheapest room is the neighbours' pair.
    d.add(Rect::new(0, 0, 4, 4));
    d.add(Rect::new(4, 0, 4, 4));
    for i in 1..5u16 {
        d.add(Rect::new(i * 50, 100 + i * 40, 2, 2));
    }
    assert_eq!(d.rects().len(), DAMAGE_MAX);
    d.add(Rect::new(300, 10, 2, 2));
    assert_eq!(d.rects().len(), DAMAGE_MAX);
    assert!(d.rects().contains(&Rect::new(0, 0, 8, 4)));
    assert!(d.rects().contains(&Rect::new(300, 10, 2, 2)));
}

#[test]
fn damage_always_covers_everything_added() {
    const SIDE: u16 = 96;
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    for _ in 0..400 {
        let mut d = Damage::new();
        let mut want = vec![false; SIDE as usize * SIDE as usize];
        for _ in 0..rng.range(1, 24) {
            let (x, y) = (rng.range(0, SIDE as i32 - 1) as u16, rng.range(0, SIDE as i32 - 1) as u16);
            let w = rng.range(1, (SIDE - x) as i32 + 1).min(rng.range(1, 30)) as u16;
            let h = rng.range(1, (SIDE - y) as i32 + 1).min(rng.range(1, 30)) as u16;
            let r = Rect::new(x, y, w, h);
            d.add(r);
            for yy in y..y + h {
                for xx in x..x + w {
                    want[yy as usize * SIDE as usize + xx as usize] = true;
                }
            }
            assert!(d.rects().len() <= DAMAGE_MAX);
            let got = painted(&d, SIDE);
            for (i, (&w, &g)) in want.iter().zip(&got).enumerate() {
                assert!(!w || g, "pixel ({}, {}) was added and is not in the damage", i % SIDE as usize, i / SIDE as usize);
            }
            assert!(d.rects().iter().all(|r| !r.is_empty() && r.inside(SIDE as u32, SIDE as u32)));
        }
    }
}

#[test]
fn geometry_helpers_agree_with_a_pixel_walk() {
    let mut rng = Rng(7);
    let rect = |rng: &mut Rng| Rect::new(rng.range(0, 20) as u16, rng.range(0, 20) as u16, rng.range(0, 12) as u16, rng.range(0, 12) as u16);
    let has = |r: Rect, x: u16, y: u16| x >= r.x && x < r.x + r.w && y >= r.y && y < r.y + r.h;
    for _ in 0..2000 {
        let (a, b) = (rect(&mut rng), rect(&mut rng));
        let mut both = 0u64;
        let mut inner_in_outer = true;
        for y in 0..40u16 {
            for x in 0..40u16 {
                if has(a, x, y) && has(b, x, y) {
                    both += 1;
                }
                if has(b, x, y) && !has(a, x, y) {
                    inner_in_outer = false;
                }
            }
        }
        assert_eq!(intersect(a, b).map_or(0, area), both, "{a:?} {b:?}");
        assert_eq!(contains(a, b), inner_in_outer, "{a:?} {b:?}");
        let u = bounds(a, b);
        for y in 0..40u16 {
            for x in 0..40u16 {
                assert!(!(has(a, x, y) || has(b, x, y)) || has(u, x, y));
            }
        }
    }
}

#[test]
fn a_damage_range_names_the_destination_pixels_that_show_the_source_ones() {
    for num in 1..=4u32 {
        for den in 1..=4u32 {
            for a in 0..10u32 {
                for b in a + 1..=10 {
                    let (d0, d1) = dst_range(a, b, num, den);
                    let want: Vec<u32> = (0..60).filter(|d| (a..b).contains(&(d * den / num))).collect();
                    assert_eq!(want, (d0..d1).collect::<Vec<_>>(), "src {a}..{b} at {num}/{den}");
                }
            }
        }
    }
}

// ── composition: goldens ────────────────────────────────────────────────────

fn two_windows() -> [(Layer, Buf); 2] {
    let red = Buf::art(X, &["RRRRRRRW", "RYYYYYYR", "RYGGGGYR", "RYYYYYYR", "WRRRRRRR"]);
    let blue = Buf::art(X, &["BBBBBBBB", "BCCCCCCB", "BCMMMMCB", "BCCCCCCB", "BBBBBBBB"]);
    [(layer(1, 1, 1, &red, 1), red), (layer(2, 6, 3, &blue, 1), blue)]
}

#[test]
fn layers_stack_in_z_order() {
    let (mut comp, set, mut fb) = scene(16, 9, 1, X, &two_windows());
    golden("z_order", &fb);
    // The later layer is on top where they overlap, the background shows where
    // neither is.
    assert_eq!(fb.get(7, 3), colour('B'));
    assert_eq!(fb.get(0, 0), NAVY);
    comp.raise(1).unwrap();
    assert_eq!(comp.layers().iter().map(|l| l.id).collect::<Vec<_>>(), [2, 1]);
    let f = comp.frame(&set, &mut fb.sink());
    golden("z_order_raised", &fb);
    assert_eq!(f.damage.rects(), &[Rect::new(1, 1, 8, 5)], "raising damages the layer's own rectangle");
    comp.lower(1).unwrap();
    comp.frame(&set, &mut fb.sink());
    golden("z_order", &fb);
}

#[test]
fn a_layer_cut_by_the_screen_edge_shows_the_right_pixels() {
    let art = Buf::art(X, &["RGBWRGBW", "GBWRGBWR", "BWRGBWRG", "WRGBWRGB", "RGBWRGBW"]);
    let both = [(layer(1, -3, -2, &art, 1), art.clone()), (layer(2, 12, 5, &art, 1), art)];
    let (_, _, fb) = scene(16, 9, 1, X, &both);
    golden("cut_by_edges", &fb);
    // Pixel (0,0) of the screen is pixel (3,2) of the layer, "BWRGBWRG"[3].
    assert_eq!(fb.get(0, 0), colour('G'));
    assert_eq!(fb.get(15, 8), colour('B'));
    assert_eq!(fb.get(12, 5), colour('R'));
}

#[test]
fn a_layer_outside_the_screen_or_hidden_draws_nothing() {
    let art = Buf::art(X, &["RRRR", "RRRR"]);
    let mut l3 = layer(3, 4, 4, &art, 1);
    l3.visible = false;
    let ls = [(layer(1, 40, 2, &art, 1), art.clone()), (layer(2, -9, 2, &art, 1), art.clone()), (l3, art)];
    let (mut comp, set, mut fb) = scene(16, 9, 1, X, &ls);
    assert!((0..9).all(|y| (0..16).all(|x| fb.get(x, y) == NAVY)));
    assert!(comp.pending().is_empty());
    comp.set_visible(3, true).unwrap();
    comp.frame(&set, &mut fb.sink());
    assert_eq!(fb.get(4, 4), colour('R'));
    comp.set_visible(3, false).unwrap();
    let f = comp.frame(&set, &mut fb.sink());
    assert_eq!(fb.get(4, 4), NAVY);
    assert_eq!(f.damage.rects(), &[Rect::new(4, 4, 4, 2)]);
}

#[test]
fn a_one_x_buffer_on_a_two_x_output_is_doubled() {
    let art = Buf::art(X, &["RGBW", "WBGR", "RRGG"]);
    let (comp, _, fb) = scene(16, 12, 2, X, &[(layer(1, 1, 1, &art, 1), art)]);
    golden("hidpi_1x_on_2x", &fb);
    assert_eq!(comp.layers()[0].buf_w, 4);
}

#[test]
fn a_two_x_buffer_on_a_two_x_output_is_copied() {
    // The same picture as above at twice the resolution: the screen is identical.
    let art = Buf::art(X, &["RRGGBBWW", "RRGGBBWW", "WWBBGGRR", "WWBBGGRR", "RRRRGGGG", "RRRRGGGG"]);
    let (_, _, fb) = scene(16, 12, 2, X, &[(layer(1, 1, 1, &art, 2), art)]);
    golden("hidpi_1x_on_2x", &fb);
}

#[test]
fn a_two_x_buffer_on_a_one_x_output_takes_every_other_pixel() {
    // The odd columns and rows (the Y) are never shown.
    let art = Buf::art(X, &["RYGGBBWW", "YYGGBBWW", "WWBBGGRR", "WWBBGGRR", "RRRRGGGG", "RRRRGGGG"]);
    let (_, _, fb) = scene(16, 9, 1, X, &[(layer(1, 2, 1, &art, 2), art)]);
    golden("hidpi_2x_on_1x", &fb);
}

#[test]
fn rgb565_converts_both_ways() {
    let art_x = Buf::art(X, &["RGBW", "gYCM"]);
    let art_p = Buf::art(P, &["WBGR", "MCYg"]);
    let ls = [(layer(1, 1, 1, &art_x, 1), art_x), (layer(2, 6, 2, &art_p, 1), art_p)];
    let (_, _, p_screen) = scene(12, 5, 1, P, &ls);
    golden("rgb565_screen", &p_screen);
    let (_, _, x_screen) = scene(12, 5, 1, X, &ls);
    golden("rgb565_screen", &x_screen);
}

#[test]
fn a_covering_layer_hides_what_is_below_without_reading_it() {
    // The bottom layer has no buffer at all: it is below a layer that covers the
    // screen, so it is neither drawn nor counted.
    let top = Buf::art(X, &["RGBWRGBW"; 4]);
    let mut comp = Compositor::<4>::new(output(8, 4, 1), NAVY);
    let mut set = Set::default();
    comp.add(Layer { id: 1, x: 0, y: 0, buf_w: 8, buf_h: 4, buffer_scale: 1, visible: true }).unwrap();
    comp.add(layer(2, 0, 0, &top, 1)).unwrap();
    set.0.insert(2, top.clone());
    let mut fb = Buf::new(8, 4, X);
    let f = comp.frame(&set, &mut fb.sink());
    assert_eq!(f.missing, 0);
    assert_eq!(fb.dump(), top.dump());
}

#[test]
fn a_layer_without_a_buffer_is_skipped_and_counted_and_hides_nothing() {
    let under = Buf::art(X, &["RRRRRRRR"; 4]);
    let small = Buf::art(X, &["GG"; 2]);
    let mut comp = Compositor::<4>::new(output(8, 4, 1), NAVY);
    let mut set = Set::default();
    comp.add(layer(1, 0, 0, &under, 1)).unwrap();
    set.0.insert(1, under);
    // Layer 2 covers the screen but its client's buffer is gone; layer 3's buffer
    // is smaller than the layer says.
    comp.add(Layer { id: 2, x: 0, y: 0, buf_w: 8, buf_h: 4, buffer_scale: 1, visible: true }).unwrap();
    comp.add(Layer { id: 3, x: 1, y: 1, buf_w: 4, buf_h: 4, buffer_scale: 1, visible: true }).unwrap();
    set.0.insert(3, small);
    let mut fb = Buf::new(8, 4, X);
    let f = comp.frame(&set, &mut fb.sink());
    assert_eq!(f.missing, 2);
    assert!((0..4).all(|y| (0..8).all(|x| fb.get(x, y) == colour('R'))), "layer 1 shows");
}

// ── cursor ──────────────────────────────────────────────────────────────────

const CURSOR: [u32; 9] = [
    0xFFFF_0000, 0xFFFF_0000, 0x0000_0000, // opaque red, opaque red, clear
    0xFFFF_0000, 0x80FF_0000, 0x0000_0000, // opaque red, half red, clear
    0x0000_0000, 0x0000_0000, 0xFFFF_FFFF, // clear, clear, opaque white
];

#[test]
fn the_cursor_is_drawn_last_at_its_hot_spot() {
    let blue = Buf::art(X, &["BBBBBBBB"; 6]);
    let (mut comp, set, mut fb) = scene(8, 6, 1, X, &[(layer(1, 0, 0, &blue, 1), blue)]);
    comp.set_cursor_image(3, 3, 1, 1, &CURSOR).unwrap();
    comp.show_cursor(false);
    comp.move_cursor(4, 3);
    let f = comp.frame(&set, &mut fb.sink());
    assert!(f.damage.is_empty(), "a hidden cursor damages nothing");
    comp.show_cursor(true);
    let f = comp.frame(&set, &mut fb.sink());
    assert_eq!(f.damage.rects(), &[Rect::new(3, 2, 3, 3)]);
    golden("cursor", &fb);
    // Half red over blue: red 128, blue 127.
    assert_eq!(fb.get(4, 3), 0x80007F);
    // The hot spot (1,1) of the image is the pointer: pixel (1,1) is the half red.
    comp.move_cursor(1, 1);
    comp.frame(&set, &mut fb.sink());
    assert_eq!(fb.get(1, 1), 0x80007F);
    assert_eq!(fb.get(0, 0), colour('R'), "the image reaches (-1,-1) of the hot spot: cut by the edge");
    assert_eq!(fb.get(4, 3), colour('B'), "the old position is repainted");
}

#[test]
fn moving_the_cursor_damages_where_it_was_and_where_it_is() {
    let (mut comp, set, mut fb) = scene(32, 16, 1, X, &[]);
    comp.set_cursor_image(3, 3, 0, 0, &CURSOR).unwrap();
    comp.show_cursor(true);
    comp.move_cursor(2, 2);
    comp.frame(&set, &mut fb.sink());
    comp.move_cursor(20, 8);
    assert_eq!(comp.pending().rects(), &[Rect::new(2, 2, 3, 3), Rect::new(20, 8, 3, 3)]);
    comp.frame(&set, &mut fb.sink());
    assert_eq!(fb.get(2, 2), NAVY);
    assert_eq!(fb.get(20, 8), colour('R'));
}

#[test]
fn a_cursor_image_is_checked() {
    let mut comp = Compositor::<2>::new(output(8, 8, 1), NAVY);
    assert_eq!(comp.set_cursor_image(3, 3, 3, 0, &CURSOR), Err(Error::Geometry), "hot spot outside");
    assert_eq!(comp.set_cursor_image(3, 3, 0, 0, &CURSOR[..8]), Err(Error::Geometry), "short");
    assert_eq!(comp.set_cursor_image(0, 3, 0, 0, &[]), Err(Error::Geometry));
    assert_eq!(comp.set_cursor_image(65, 1, 0, 0, &[0; 65]), Err(Error::Geometry));
    assert_eq!(comp.set_cursor_image(64, 64, 63, 63, &[0; 4096]), Ok(()));
}

// ── scene changes ───────────────────────────────────────────────────────────

#[test]
fn scene_changes_damage_what_they_change_in_device_pixels() {
    let art = Buf::art(X, &["RGBW", "WBGR", "RRGG"]);
    let (mut comp, set, mut fb) = scene(16, 12, 2, X, &[]);
    comp.add(layer(1, 1, 1, &art, 1)).unwrap();
    let mut set = set;
    set.0.insert(1, art.clone());
    assert_eq!(comp.pending().rects(), &[Rect::new(2, 2, 8, 6)]);
    comp.frame(&set, &mut fb.sink());
    assert!(comp.pending().is_empty());
    // Source pixels (1..3, 1..2) at 2x: columns 2..6, rows 2..4 of the layer.
    comp.damage_layer(1, Some(Rect::new(1, 1, 2, 1))).unwrap();
    assert_eq!(comp.pending().rects(), &[Rect::new(4, 4, 4, 2)]);
    comp.frame(&set, &mut fb.sink());
    comp.damage_layer(1, Some(Rect::new(50, 50, 4, 4))).unwrap();
    assert!(comp.pending().is_empty(), "outside the buffer");
    comp.place(1, 3, 2).unwrap();
    assert_eq!(comp.pending().rects().len(), 2, "where it was and where it is");
    comp.frame(&set, &mut fb.sink());
    comp.remove(1).unwrap();
    assert_eq!(comp.pending().rects(), &[Rect::new(6, 4, 8, 6)]);
    comp.frame(&set, &mut fb.sink());
    assert_eq!(fb.get(7, 5), NAVY);
    comp.damage_all();
    assert_eq!(comp.pending().rects(), &[Rect::new(0, 0, 16, 12)]);
}

#[test]
fn a_new_buffer_size_repaints_both_footprints() {
    let a = Buf::art(X, &["RR", "RR"]);
    let b = Buf::art(X, &["GGGGGG", "GGGGGG", "GGGGGG", "GGGGGG"]);
    let (mut comp, mut set, mut fb) = scene(16, 8, 1, X, &[(layer(1, 1, 1, &a, 1), a)]);
    set.0.insert(1, b);
    comp.set_buffer(1, 6, 4, 2).unwrap();
    assert_eq!(comp.pending().rects(), &[Rect::new(1, 1, 3, 2)], "the new footprint (3x2) holds the old one (2x2)");
    comp.frame(&set, &mut fb.sink());
    assert_eq!(fb.get(3, 2), colour('G'));
}

#[test]
fn changes_that_cannot_be_made_say_why() {
    let art = Buf::art(X, &["RRRR"; 4]);
    let mut comp = Compositor::<2>::new(output(8, 8, 1), NAVY);
    assert_eq!(comp.add(Layer { buf_w: 0, ..layer(1, 0, 0, &art, 1) }), Err(Error::Geometry));
    assert_eq!(comp.add(Layer { buf_w: 3, ..layer(1, 0, 0, &art, 2) }), Err(Error::Geometry), "not a multiple of the factor");
    assert_eq!(comp.add(Layer { buffer_scale: 0, ..layer(1, 0, 0, &art, 1) }), Err(Error::Geometry));
    assert_eq!(comp.add(Layer { buffer_scale: 5, buf_w: 5, buf_h: 5, ..layer(1, 0, 0, &art, 1) }), Err(Error::Geometry));
    assert_eq!(comp.add(Layer { buf_w: 70_000, ..layer(1, 0, 0, &art, 1) }), Err(Error::Geometry));
    assert_eq!(comp.add(layer(1, 0, 0, &art, 1)), Ok(()));
    assert_eq!(comp.add(layer(1, 1, 1, &art, 1)), Err(Error::Exists));
    assert_eq!(comp.add(layer(2, 1, 1, &art, 1)), Ok(()));
    assert_eq!(comp.add(layer(3, 1, 1, &art, 1)), Err(Error::Full));
    assert_eq!(comp.remove(9), Err(Error::NoLayer));
    assert_eq!(comp.raise(9), Err(Error::NoLayer));
    assert_eq!(comp.place(9, 0, 0), Err(Error::NoLayer));
    assert_eq!(comp.set_buffer(1, 5, 4, 2), Err(Error::Geometry));
    assert!(Output::new(0, 5, 1).is_none() && Output::new(5, 5, 0).is_none() && Output::new(5, 5, 5).is_none());
    assert!(Output::new(65_536, 5, 1).is_none() && Output::new(65_535, 65_535, 4).is_some());
}

// ── a banded sink ───────────────────────────────────────────────────────────

/// A display surface as the Display interface has it: bands of whole rows,
/// each its own allocation; a band can be missing.
struct Banded {
    bands: Vec<Option<Vec<u8>>>,
    rows: u32,
    row_bytes: usize,
}

impl Sink for Banded {
    fn format(&self) -> Format {
        X
    }
    fn row_mut(&mut self, y: u32) -> Option<&mut [u8]> {
        let band = self.bands.get_mut((y / self.rows) as usize)?.as_mut()?;
        let at = (y % self.rows) as usize * self.row_bytes;
        band.get_mut(at..at + self.row_bytes)
    }
}

#[test]
fn a_banded_surface_composes_like_a_flat_one_and_a_missing_band_is_counted() {
    let layers = two_windows();
    let (mut flat_comp, set, flat) = scene(16, 9, 1, X, &layers);
    let mut banded = Banded { bands: vec![Some(vec![0; 16 * 4 * 4]), Some(vec![0; 16 * 4 * 4]), Some(vec![0; 16 * 4 * 4])], rows: 4, row_bytes: 64 };
    let mut comp = Compositor::<8>::new(output(16, 9, 1), NAVY);
    for (l, _) in &layers {
        comp.add(*l).unwrap();
    }
    assert_eq!(comp.frame(&set, &mut banded).missing, 0);
    for y in 0..9u32 {
        assert_eq!(banded.row_mut(y).unwrap(), flat.row(y).unwrap(), "row {y}");
    }
    // The middle band is not attached: its rows are counted, the others drawn.
    banded.bands[1] = None;
    flat_comp.damage_all();
    comp.damage_all();
    let f = comp.frame(&set, &mut banded);
    assert!(f.missing >= 4, "four rows, once per thing drawn on them: {}", f.missing);
    assert_eq!(banded.row_mut(0).unwrap(), flat.row(0).unwrap());
}

#[test]
fn fill_paints_only_its_rectangle() {
    let mut fb = Buf::new(8, 4, P);
    let mut missing = 0;
    fill(&mut fb.sink(), Rect::new(0, 0, 8, 4), colour('n'), &mut missing);
    fill(&mut fb.sink(), Rect::new(2, 1, 3, 2), colour('Y'), &mut missing);
    fill(&mut fb.sink(), Rect::new(7, 3, 0, 0), colour('R'), &mut missing);
    assert_eq!(missing, 0);
    golden("fill_565", &fb);
}

// ── the model ───────────────────────────────────────────────────────────────

/// The scene drawn pixel by pixel from the layers in `order`, sharing nothing
/// with the engine's row loops: the source pixel of destination pixel `d` is
/// `floor(d * den / num)`, a pixel is quantised to the screen's format where it
/// is stored, and the cursor blends with what was stored.
fn model(w: u32, h: u32, scale: u32, fmt: Format, order: &[Layer], bufs: &BTreeMap<u32, Buf>, cur: Option<(i32, i32, i32, i32, usize, &[u32])>) -> Buf {
    let mut out = Buf::new(w, h, fmt);
    for y in 0..h as i64 {
        for x in 0..w as i64 {
            let mut c = NAVY;
            for l in order.iter().filter(|l| l.visible) {
                let (ox, oy) = (l.x as i64 * scale as i64, l.y as i64 * scale as i64);
                let (lw, lh) = ((l.buf_w / l.buffer_scale) as i64 * scale as i64, (l.buf_h / l.buffer_scale) as i64 * scale as i64);
                let (dx, dy) = (x - ox, y - oy);
                if (0..lw).contains(&dx) && (0..lh).contains(&dy) {
                    let b = &bufs[&l.id];
                    c = b.get((dx * l.buffer_scale as i64 / scale as i64) as u32, (dy * l.buffer_scale as i64 / scale as i64) as u32);
                }
            }
            out.put(x as u32, y as u32, c);
            if let Some((cx, cy, hx, hy, cw, px)) = cur {
                let (ix, iy) = (x - (cx - hx) as i64, y - (cy - hy) as i64);
                if ix >= 0 && iy >= 0 && (ix as usize) < cw && (iy as usize) < px.len() / cw {
                    let p = px[iy as usize * cw + ix as usize];
                    let a = p >> 24;
                    if a != 0 {
                        let under = out.get(x as u32, y as u32);
                        let v = if a == 255 { p & 0xFFFFFF } else { mix(p, under, a) };
                        out.put(x as u32, y as u32, v);
                    }
                }
            }
        }
    }
    out
}

fn random_buf(rng: &mut Rng, w: u32, h: u32) -> Buf {
    let fmt = if rng.below(2) == 0 { X } else { P };
    let mut b = Buf::new(w, h, fmt);
    for byte in b.data.iter_mut() {
        *byte = rng.next() as u8;
    }
    b
}

struct World {
    comp: Compositor<6>,
    set: Set,
    order: Vec<Layer>,
    fb: Buf,
    scale: u32,
    cursor: Option<(i32, i32, i32, i32, usize, Vec<u32>)>,
    shown: bool,
    next_id: u32,
}

impl World {
    fn new(rng: &mut Rng) -> World {
        let (w, h, scale) = (rng.range(6, 40) as u32, rng.range(6, 30) as u32, rng.range(1, 4) as u32);
        let fmt = if rng.below(2) == 0 { X } else { P };
        World {
            comp: Compositor::new(output(w, h, scale), NAVY),
            set: Set::default(),
            order: vec![],
            fb: Buf::new(w, h, fmt),
            scale,
            cursor: None,
            shown: false,
            next_id: 1,
        }
    }

    fn new_layer(&mut self, rng: &mut Rng) -> (Layer, Buf) {
        let bs = rng.range(1, 4) as u32;
        let (w, h) = (rng.range(1, 9) as u32 * bs, rng.range(1, 7) as u32 * bs);
        let b = random_buf(rng, w, h);
        let l = Layer { id: self.next_id, x: rng.range(-8, 30), y: rng.range(-6, 22), buf_w: w, buf_h: h, buffer_scale: bs, visible: true };
        self.next_id += 1;
        (l, b)
    }

    fn step(&mut self, rng: &mut Rng) {
        let n = self.order.len();
        let pick = |rng: &mut Rng| rng.below(n as u64) as usize;
        match rng.below(14) {
            0 | 1 if n < 6 => {
                let (l, b) = self.new_layer(rng);
                self.comp.add(l).unwrap();
                self.set.0.insert(l.id, b);
                self.order.push(l);
            }
            2 if n > 0 => {
                let i = pick(rng);
                let l = self.order.remove(i);
                self.comp.remove(l.id).unwrap();
                self.set.0.remove(&l.id);
            }
            3 if n > 0 => {
                let i = pick(rng);
                let l = self.order.remove(i);
                self.order.push(l);
                self.comp.raise(l.id).unwrap();
            }
            4 if n > 0 => {
                let i = pick(rng);
                let l = self.order.remove(i);
                self.order.insert(0, l);
                self.comp.lower(l.id).unwrap();
            }
            5 | 6 if n > 0 => {
                let i = pick(rng);
                self.order[i].x = rng.range(-8, 30);
                self.order[i].y = rng.range(-6, 22);
                self.comp.place(self.order[i].id, self.order[i].x, self.order[i].y).unwrap();
            }
            7 if n > 0 => {
                let i = pick(rng);
                let bs = rng.range(1, 4) as u32;
                let (w, h) = (rng.range(1, 9) as u32 * bs, rng.range(1, 7) as u32 * bs);
                self.order[i].buf_w = w;
                self.order[i].buf_h = h;
                self.order[i].buffer_scale = bs;
                self.set.0.insert(self.order[i].id, random_buf(rng, w, h));
                self.comp.set_buffer(self.order[i].id, w, h, bs).unwrap();
            }
            8 if n > 0 => {
                let i = pick(rng);
                self.order[i].visible = !self.order[i].visible;
                self.comp.set_visible(self.order[i].id, self.order[i].visible).unwrap();
            }
            9 | 10 if n > 0 => {
                // The client draws in part of its buffer and says where.
                let i = pick(rng);
                let l = self.order[i];
                let (rx, ry) = (rng.range(0, l.buf_w as i32), rng.range(0, l.buf_h as i32));
                let (rw, rh) = (rng.range(1, (l.buf_w as i32 - rx) + 1), rng.range(1, (l.buf_h as i32 - ry) + 1));
                let b = self.set.0.get_mut(&l.id).unwrap();
                for y in ry..ry + rh {
                    for x in rx..rx + rw {
                        let v = rng.next() as u32 & 0xFFFFFF;
                        b.put(x as u32, y as u32, v);
                    }
                }
                self.comp.damage_layer(l.id, Some(Rect::new(rx as u16, ry as u16, rw as u16, rh as u16))).unwrap();
            }
            11 => {
                let (x, y) = (rng.range(-3, 45), rng.range(-3, 35));
                if let Some(c) = self.cursor.as_mut() {
                    c.0 = x;
                    c.1 = y;
                }
                self.comp.move_cursor(x, y);
            }
            12 => {
                self.shown = !self.shown;
                self.comp.show_cursor(self.shown);
            }
            13 => {
                let (w, h) = (rng.range(1, 6) as usize, rng.range(1, 6) as usize);
                let px: Vec<u32> = (0..w * h)
                    .map(|_| match rng.below(3) {
                        0 => 0,
                        1 => 0xFF00_0000 | rng.next() as u32 & 0xFFFFFF,
                        _ => (rng.next() as u32 & 0xFF) << 24 | rng.next() as u32 & 0xFFFFFF,
                    })
                    .collect();
                let (hx, hy) = (rng.range(0, w as i32), rng.range(0, h as i32));
                self.comp.set_cursor_image(w, h, hx, hy, &px).unwrap();
                let (x, y) = self.cursor.as_ref().map_or((0, 0), |c| (c.0, c.1));
                self.cursor = Some((x, y, hx, hy, w, px));
                // The engine's position is its own; line the model up with it.
                self.comp.move_cursor(x, y);
            }
            _ => {}
        }
    }

    fn expect(&self) -> Buf {
        let cur = if self.shown { self.cursor.as_ref().map(|c| (c.0, c.1, c.2, c.3, c.4, &c.5[..])) } else { None };
        model(self.fb.w, self.fb.h, self.scale, self.fb.fmt, &self.order, &self.set.0, cur)
    }
}

#[test]
fn incremental_frames_equal_a_full_repaint() {
    let mut rng = Rng(0xC0FF_EE00_1234_5678);
    for world in 0..120 {
        let mut w = World::new(&mut rng);
        let info = ConnectorInfo { width: w.fb.w, height: w.fb.h, ..Default::default() };
        for frame in 0..14 {
            let before = w.fb.data.clone();
            for _ in 0..rng.range(1, 9) {
                w.step(&mut rng);
            }
            let f = w.comp.frame(&w.set, &mut w.fb.sink());
            assert_eq!(f.missing, 0);
            let want = w.expect();
            assert!(w.fb.dump_raw() == want.dump_raw(), "world {world} frame {frame}: the screen differs from a full repaint\n--- want\n{}--- got\n{}", want.dump(), w.fb.dump());
            // What the frame did not report, it did not touch.
            let bpp = w.fb.fmt.bytes();
            for y in 0..w.fb.h {
                for x in 0..w.fb.w {
                    let in_damage = f.damage.rects().iter().any(|r| x >= r.x as u32 && x < r.x as u32 + r.w as u32 && y >= r.y as u32 && y < r.y as u32 + r.h as u32);
                    let at = w.fb.at(x, y);
                    assert!(in_damage || before[at..at + bpp] == w.fb.data[at..at + bpp], "world {world} frame {frame}: ({x},{y}) changed outside the damage");
                }
            }
            // And it is a present the Display interface accepts.
            if let Some(p) = Present::new(1, f.damage.rects()) {
                assert_eq!(p.check(&info), Ok(()), "{:?}", f.damage.rects());
            } else {
                assert!(f.damage.is_empty());
            }
        }
    }
}

#[test]
fn more_changes_than_a_present_holds_are_merged_not_lost() {
    let mut rng = Rng(99);
    let art = random_buf(&mut rng, 64, 16);
    let (mut comp, mut set, mut fb) = scene(64, 16, 1, art.fmt, &[(layer(1, 0, 0, &art, 1), art)]);
    // Twelve single-pixel changes far from each other: twice what a present holds.
    for i in 0..12u32 {
        let (x, y) = (i * 5 + 1, (i * 7) % 16);
        set.0.get_mut(&1).unwrap().put(x, y, 0x123456);
        comp.damage_layer(1, Some(Rect::new(x as u16, y as u16, 1, 1))).unwrap();
    }
    let f = comp.frame(&set, &mut fb.sink());
    assert_eq!(f.damage.rects().len(), DAMAGE_MAX);
    assert!(fb.dump_raw() == set.0[&1].dump_raw(), "a change was lost in the merge");
}

impl Buf {
    fn dump_raw(&self) -> Vec<u32> {
        (0..self.h).flat_map(|y| (0..self.w).map(move |x| (x, y))).map(|(x, y)| self.get(x, y)).collect()
    }
}

#[test]
fn the_model_itself_scales_by_floor() {
    // The model is what the engine is held to: pin its reading of "3 device
    // pixels for 2 source pixels" with a hand-counted row.
    let art = Buf::art(X, &["RGBW", "WBGR"]);
    let l = layer(1, 0, 0, &art, 2);
    let mut bufs = BTreeMap::new();
    bufs.insert(1, art);
    // Output scale 3, buffer scale 2: logical width 2, device 6; destination
    // pixel d shows source floor(2d/3): 0 0 1 2 2 3.
    let m = model(6, 3, 3, X, &[l], &bufs, None);
    let row: String = (0..6).map(|x| PALETTE.iter().find(|p| p.1 == m.get(x, 0)).unwrap().0).collect();
    assert_eq!(row, "RRGBBW");
}

#[test]
fn the_engine_scales_a_fractional_ratio_the_way_the_model_does() {
    let art = Buf::art(X, &["RGBW", "WBGR"]);
    let (_, _, fb) = scene(6, 6, 3, X, &[(layer(1, 0, 0, &art, 2), art.clone())]);
    let first_row: String = (0..6).map(|x| PALETTE.iter().find(|p| p.1 == fb.get(x, 0)).unwrap().0).collect();
    assert_eq!(first_row, "RRGBBW");
    // Two source rows over 3 device rows: floor(2d/3) = 0 0 1.
    assert_eq!(fb.get(0, 1), colour('R'));
    assert_eq!(fb.get(0, 2), colour('W'));
}

// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host tests for `crates/drivers/fb`: the font, pixel packing, the text grid's
//! scroll and dirty-rect math, and the panic screen, all over a `Vec<u8>`
//! standing in for the framebuffer. Each assertion has a canary: break the
//! thing it checks (see the comment on each test) and it goes red.

// The virtio-gpu wire format is pure (`core` only): the driver's request
// encoders, the answer and EDID parsers and the damage rectangle run here over
// fixed bytes.
#[cfg(test)]
#[allow(dead_code)]
#[path = "../../../../crates/drivers/virtio/src/virtio/gpu_proto.rs"]
mod gpu_proto;

#[cfg(test)]
mod tests {
    use azos_fb::font::{self, CELL_H, CELL_W};
    use azos_fb::grid::{Dirty, Grid};
    use azos_fb::pixel::{PixelFormat, Surface};

    /// A Vec-backed XRGB8888 surface.
    struct Screen {
        mem: Vec<u8>,
        s: Surface,
    }

    fn screen(w: usize, h: usize, fmt: PixelFormat) -> Screen {
        let stride = w * fmt.bytes() + 8; // a padded stride, as real hardware has
        let mut mem = vec![0u8; stride * h];
        let s = Surface { base: mem.as_mut_ptr(), width: w, height: h, stride, fmt };
        Screen { mem, s }
    }

    impl Screen {
        fn px(&self, x: usize, y: usize) -> u32 {
            let b = self.s.fmt.bytes();
            let o = y * self.s.stride + x * b;
            let mut w = [0u8; 4];
            w[..b].copy_from_slice(&self.mem[o..o + b]);
            u32::from_le_bytes(w)
        }
    }

    const FG: u32 = 0x00FF_FFFF;
    const BG: u32 = 0x0000_0000;

    // ---- font ----

    /// The cell as 16 strings of '#'/'.', for readable assertions.
    fn art(c: u8) -> Vec<String> {
        font::glyph(c)
            .iter()
            .map(|&r| (0..8).map(|i| if r & (0x80 >> i) != 0 { '#' } else { '.' }).collect())
            .collect()
    }

    /// Canary: shift the expansion one column (`0x80 >> x`) and `|` moves off
    /// column 3; drop the vertical doubling and rows 1/2 differ.
    #[test]
    fn the_bar_is_one_column_the_full_height() {
        let a = art(b'|');
        assert_eq!(a[0], "........", "blank top row");
        assert_eq!(a[15], "........", "blank bottom row");
        for r in 1..15 {
            assert_eq!(a[r], "...#....", "row {r}");
        }
    }

    #[test]
    fn space_is_empty_and_every_printable_glyph_but_space_has_ink() {
        assert!(font::glyph(b' ').iter().all(|&r| r == 0));
        for c in b'!'..=b'~' {
            assert!(font::glyph(c).iter().any(|&r| r != 0), "{:?} has no pixels", c as char);
        }
    }

    /// Canary: build the table from the wrong row bit order (`>> (6 - gr)`)
    /// and the crossbar of `A` leaves row 7.
    #[test]
    fn a_has_apex_legs_and_a_crossbar() {
        let a = art(b'A');
        assert_eq!(a[1], "..###...", "apex row");
        assert_eq!(a[2], a[1], "rows are doubled");
        let rows_full: Vec<usize> = (0..16).filter(|&r| a[r].matches('#').count() == 5).collect();
        assert_eq!(rows_full, vec![9, 10], "crossbar: glyph row 4 doubled");
        assert_eq!(a[14], ".#...#..", "legs reach the last glyph row");
        assert_eq!(a[15], "........");
    }

    #[test]
    fn glyphs_stay_inside_columns_one_to_five() {
        for c in b' '..=b'~' {
            for r in font::glyph(c) {
                assert_eq!(r & 0x81, 0, "{:?}: left margin and right margin must be blank", c as char);
                assert_eq!(r & 0x03, 0);
            }
        }
    }

    /// Canary: return `FONT[0]` for unknown bytes and this test reads a blank.
    #[test]
    fn unprintable_bytes_draw_a_question_mark() {
        assert_eq!(font::glyph(0x07), font::glyph(b'?'));
        assert_eq!(font::glyph(0xC3), font::glyph(b'?'));
        assert_ne!(font::glyph(b'?'), font::glyph(b'!'));
    }

    // ---- pixel format ----

    /// Canary: swap r_shift and b_shift in XRGB8888 and the red pixel reads 0x0000FF.
    #[test]
    fn pack_puts_each_channel_where_the_format_says() {
        assert_eq!(PixelFormat::XRGB8888.pack(0xFF, 0, 0), 0x00FF_0000);
        assert_eq!(PixelFormat::XBGR8888.pack(0xFF, 0, 0), 0x0000_00FF);
        assert_eq!(PixelFormat::RGB565.pack(0xFF, 0, 0), 0xF800);
        assert_eq!(PixelFormat::RGB565.pack(0, 0xFF, 0), 0x07E0);
        assert_eq!(PixelFormat::RGB565.pack(0, 0, 0xFF), 0x001F);
        assert_eq!(PixelFormat::RGB888.pack(1, 2, 3), 0x0001_0203);
    }

    #[test]
    fn device_tree_format_strings_and_validity() {
        assert_eq!(PixelFormat::from_dt(b"x8r8g8b8\0"), Some(PixelFormat::XRGB8888));
        assert_eq!(PixelFormat::from_dt(b"r5g6b5"), Some(PixelFormat::RGB565));
        assert_eq!(PixelFormat::from_dt(b"a2r10g10b10"), None);
        assert!(PixelFormat::XRGB8888.valid());
        assert!(!PixelFormat::new(32, 28, 8, 0, 8, 0, 8).valid(), "red overflows the word");
        assert!(!PixelFormat::new(8, 0, 3, 3, 3, 6, 2).valid(), "8 bpp is not drawn");
    }

    // ---- surface ----

    /// Canary: forget `* bpp` in `put_row` and the 565 glyph lands on the wrong bytes.
    #[test]
    fn a_glyph_blits_foreground_and_background_in_every_format() {
        for fmt in [PixelFormat::XRGB8888, PixelFormat::RGB565, PixelFormat::RGB888] {
            let mut sc = screen(24, 32, fmt);
            let (fg, bg) = (fmt.pack(0xFF, 0xFF, 0xFF), fmt.pack(0, 0, 0x80));
            sc.s.draw_glyph(8, 16, b'|', fg, bg);
            assert_eq!(sc.px(8 + 3, 16 + 5), fg, "{fmt:?}: ink");
            assert_eq!(sc.px(8 + 2, 16 + 5), bg, "{fmt:?}: paper");
            assert_eq!(sc.px(8 + 3, 16), bg, "{fmt:?}: blank top row");
            assert_eq!(sc.px(7, 16 + 5), 0, "{fmt:?}: outside the cell is untouched");
            sc.mem[0] = 0; // keep the borrow checker honest about `mem`
        }
    }

    /// Canary: use `width` instead of `stride` for the row offset and the second row
    /// of the glyph lands inside the first row's padding.
    #[test]
    fn rows_advance_by_the_stride_not_the_width() {
        let sc = screen(8, 16, PixelFormat::XRGB8888);
        sc.s.draw_glyph(0, 0, b'|', FG, BG);
        let o = 5 * sc.s.stride + 3 * 4;
        assert_eq!(&sc.mem[o..o + 4], &[0xFF, 0xFF, 0xFF, 0x00]);
        let pad = 8 * 4; // the padding bytes after row 0 stay zero
        assert!(sc.mem[pad..pad + 8].iter().all(|&b| b == 0));
    }

    #[test]
    fn drawing_clips_at_the_edges_and_never_writes_outside() {
        let sc = screen(12, 20, PixelFormat::XRGB8888);
        let before = sc.mem.len();
        sc.s.draw_glyph(8, 8, b'#', FG, 0x00FF_0000); // 4 px of the cell fit, 12 rows fit
        sc.s.draw_glyph(100, 100, b'#', FG, BG); // wholly outside
        assert_eq!(sc.mem.len(), before);
        assert_eq!(sc.px(11, 8), 0x00FF_0000 | if font::glyph(b'#')[0] & 0x10 != 0 { FG } else { 0 });
        // Nothing reached the row padding (bytes past the width) or the row below.
        let stride = sc.s.stride;
        for y in 0..20 {
            assert!(sc.mem[y * stride + 12 * 4..(y + 1) * stride].iter().all(|&b| b == 0), "row {y} padding");
        }
        sc.s.fill_rect(10, 18, 50, 50, 0x1234);
        assert_eq!(sc.px(11, 19), 0x1234);
        assert_eq!(sc.px(9, 19), 0x00FF_0000, "left of the fill: the glyph's own paper");
    }

    // ---- grid: scroll and dirty-rect math ----

    type G = Grid<10, 4>;

    fn grid() -> G {
        let mut g = G::new();
        assert!(g.resize(80, 64)); // 10 x 4 cells
        g
    }

    fn row(g: &G, r: usize) -> String {
        (0..g.cols).map(|c| g.at(c, r) as char).collect()
    }

    /// Canary: compare `cx + 1 < cols` in `put_char` and the 10th column wraps early.
    #[test]
    fn text_wraps_at_the_right_edge() {
        let mut g = grid();
        g.put_bytes(b"0123456789AB");
        assert_eq!(row(&g, 0), "0123456789");
        assert_eq!(row(&g, 1), "AB        ");
        assert_eq!((g.cx, g.cy), (2, 1));
    }

    /// Canary: drop `self.top = ...` in `newline` and the screen never scrolls;
    /// drop the `fill` and the bottom row keeps the old text.
    #[test]
    fn the_fifth_line_scrolls_the_screen_up_one_row() {
        let mut g = grid();
        g.put_bytes(b"one\ntwo\nthree\nfour");
        assert_eq!(g.scrolls, 0);
        assert_eq!((g.cy, g.top), (3, 0));
        g.put_bytes(b"\nfive");
        assert_eq!(g.scrolls, 1);
        assert_eq!(row(&g, 0), "two       ");
        assert_eq!(row(&g, 1), "three     ");
        assert_eq!(row(&g, 2), "four      ");
        assert_eq!(row(&g, 3), "five      ");
        assert!(g.dirty.all, "a scroll moves every row");
        // The ring wraps a full turn without losing the order.
        for i in 0..9 {
            g.put_bytes(format!("\nl{i}").as_bytes());
        }
        assert_eq!(row(&g, 3), "l8        ");
        assert_eq!(row(&g, 0), "l5        ");
        assert_eq!(g.top, (1 + 9) % 4);
    }

    /// Canary: widen `mark` to always cover the whole row range and the rectangle test fails.
    #[test]
    fn the_dirty_rect_is_the_bounding_box_of_what_changed() {
        let mut g = grid();
        g.dirty = Dirty::CLEAN;
        g.put_bytes(b"\n\n  x");
        assert!(!g.dirty.all && !g.dirty.empty);
        // The two spaces before `x` are cells written too.
        assert_eq!((g.dirty.c0, g.dirty.c1, g.dirty.r0, g.dirty.r1), (0, 2, 2, 2));
        g.put_bytes(b"yz\rQ");
        assert_eq!((g.dirty.c0, g.dirty.c1, g.dirty.r0, g.dirty.r1), (0, 4, 2, 2));
        // Two writes after a flush: the box grows from the first one's cell.
        g.dirty = Dirty::CLEAN;
        g.put_bytes(b"cd");
        assert_eq!((g.dirty.c0, g.dirty.c1), (g.cx - 2, g.cx - 1));
        assert!(g.dirty.c0 > 0);
    }

    /// Canary: flush the whole grid always and the cell count is 40, not 3.
    #[test]
    fn flush_draws_only_the_dirty_cells_then_goes_clean() {
        let mut g = grid();
        let sc = screen(80, 64, PixelFormat::XRGB8888);
        g.flush(&sc.s, FG, BG); // the resize left it all dirty
        g.put_bytes(b"ab");
        g.put_bytes(b"c");
        assert_eq!(g.flush(&sc.s, FG, BG), 3);
        assert_eq!(g.dirty, Dirty::CLEAN);
        assert_eq!(g.flush(&sc.s, FG, BG), 0, "nothing changed");
        // 'c' is in cell 2: ink in its first glyph row.
        let (x, y) = (2 * CELL_W, 0);
        let c_row = font::glyph(b'c')[4];
        let want = |i: usize| if c_row & (0x80 >> i) != 0 { FG } else { BG };
        for i in 0..CELL_W {
            assert_eq!(sc.px(x + i, y + 4), want(i));
        }
        g.put_bytes(b"\n\n\n\n"); // scroll: full redraw
        assert_eq!(g.flush(&sc.s, FG, BG), 40);
        assert_eq!(sc.px(x + 3, y + 4), BG, "'c' scrolled off the top");
    }

    #[test]
    fn control_bytes_and_escape_sequences() {
        let mut g = grid();
        g.put_bytes(b"ab\x08c\r\n");
        assert_eq!(row(&g, 0), "ac        ");
        // A colour sequence is skipped; a tab pads to the next multiple of 8;
        // BEL is not printable.
        g.put_bytes(b"\x1b[31mred\x1b[0mx\ty\x07");
        assert_eq!(row(&g, 1), "redx    y?");
    }

    #[test]
    fn a_grid_that_fits_nothing_ignores_input() {
        let mut g = G::new();
        assert!(!g.resize(4, 4));
        g.put_bytes(b"x\n");
        assert_eq!(g.scrolls, 0);
    }

    #[test]
    fn the_grid_is_clamped_to_its_capacity() {
        let mut g = G::new();
        assert!(g.resize(8 * 200, 16 * 200));
        assert_eq!((g.cols, g.rows), (10, 4));
    }

    #[test]
    fn dirty_pixels_is_what_flush_redraws() {
        // Canary: a rectangle other than the flush's (an off-by-one cell, the
        // row/column swapped, "all" ignored) leaves part of a redraw unshown.
        let mut g = grid();
        assert_eq!(g.dirty_pixels(), Some(azos_fb::Rect { x: 0, y: 0, w: (g.cols * CELL_W) as u32, h: (g.rows * CELL_H) as u32 }),
            "a fresh grid is all dirty");
        let sc = screen(g.cols * CELL_W, g.rows * CELL_H, PixelFormat::XRGB8888);
        g.flush(&sc.s, FG, BG);
        assert_eq!(g.dirty_pixels(), None, "clean");
        g.put_bytes(b"\n\nabc");
        assert_eq!(g.dirty_pixels(), Some(azos_fb::Rect { x: 0, y: 2 * CELL_H as u32, w: 3 * CELL_W as u32, h: CELL_H as u32 }));
        g.put_bytes(b"\nz");
        assert_eq!(g.dirty_pixels(), Some(azos_fb::Rect { x: 0, y: 2 * CELL_H as u32, w: 3 * CELL_W as u32, h: 2 * CELL_H as u32 }));
        let n = g.flush(&sc.s, FG, BG);
        assert_eq!(n, 6, "the rectangle's cells are the ones drawn");
        let mut empty = Grid::<20, 4>::new();
        assert_eq!(empty.dirty_pixels(), None, "a grid that fits nothing has no rectangle");
        empty.resize(10, 10);
        assert_eq!(empty.dirty_pixels(), None);
    }

    #[test]
    fn a_rect_is_cut_to_the_screen() {
        use azos_fb::Rect;
        let r = |x, y, w, h| Rect { x, y, w, h };
        assert_eq!(r(0, 0, 10, 10).clip(8, 6), Some(r(0, 0, 8, 6)));
        assert_eq!(r(7, 5, 10, 10).clip(8, 6), Some(r(7, 5, 1, 1)));
        assert_eq!(r(8, 0, 1, 1).clip(8, 6), None, "starts at the right edge");
        assert_eq!(r(0, 6, 1, 1).clip(8, 6), None, "starts at the bottom edge");
        assert_eq!(r(0, 0, 0, 1).clip(8, 6), None);
        assert_eq!(r(0, 0, 1, 0).clip(8, 6), None);
        assert_eq!(r(u32::MAX, 0, 5, 5).clip(8, 6), None);
    }

    // ---- registry, console, panic screen ----

    /// One test: the registry is process-wide and registers once.
    #[test]
    fn registry_console_and_panic_screen() {
        use azos_fb::{console, info, panic, register, surface, FbInfo};
        assert!(surface().is_none());
        assert!(console::init().is_none(), "no framebuffer yet");
        console::mirror(b"ignored", true);
        let fmt = PixelFormat::XRGB8888;
        let mut sc = screen(160, 70, fmt); // 4 text rows and a 6-pixel strip
        let fi = FbInfo { phys: 0xdead_0000, width: 160, height: 70, stride: sc.s.stride as u32, format: fmt };
        assert!(!register(FbInfo { stride: 100, ..fi }, sc.mem.as_mut_ptr() as usize), "row shorter than the pixels");
        assert!(!register(fi, 0));
        assert!(register(fi, sc.mem.as_mut_ptr() as usize));
        assert!(!register(fi, sc.mem.as_mut_ptr() as usize), "once");
        assert_eq!(info().unwrap().0, fi);

        // The flip hook: refused twice, a no-op without one.
        use azos_fb::{flip, flip_all, set_flip, Rect};
        static SEEN: std::sync::Mutex<Vec<Rect>> = std::sync::Mutex::new(Vec::new());
        fn hook(r: Rect) {
            SEEN.lock().unwrap().push(r);
        }
        let seen = || SEEN.lock().unwrap().clone();
        let r = |x, y, w, h| Rect { x, y, w, h };
        flip(r(0, 0, 4, 4));
        assert!(seen().is_empty());
        assert!(set_flip(hook));
        assert!(!set_flip(hook), "once");
        flip(r(10, 5, 1000, 1000)); // cut to the 160x70 screen
        flip(r(160, 0, 8, 8)); // outside
        flip(r(0, 70, 8, 8));
        flip(r(3, 3, 0, 8)); // empty
        flip_all();
        assert_eq!(seen(), vec![r(10, 5, 150, 65), r(0, 0, 160, 70)]);
        SEEN.lock().unwrap().clear();

        // Initialising the console shows the cleared screen.
        assert_eq!(console::init(), Some((20, 4)));
        assert_eq!(seen(), vec![r(0, 0, 160, 70)]);
        SEEN.lock().unwrap().clear();
        console::mirror(b"hi\n", true);
        assert_eq!(seen(), vec![r(0, 0, 2 * CELL_W as u32, CELL_H as u32)], "the cells the line changed");
        SEEN.lock().unwrap().clear();
        let (fg, bg) = azos_fb::colours(&fmt);
        let cell = |sc: &Screen, c: usize, r: usize, ch: u8, fg: u32, bg: u32| {
            (0..CELL_H).all(|y| {
                (0..CELL_W).all(|x| {
                    let ink = font::glyph(ch)[y] & (0x80 >> x) != 0;
                    sc.px(c * CELL_W + x, r * CELL_H + y) == if ink { fg } else { bg }
                })
            })
        };
        assert!(cell(&sc, 0, 0, b'h', fg, bg) && cell(&sc, 1, 0, b'i', fg, bg), "the mirror drew the line");

        // `draw` false (an interrupt printing): recorded, not drawn; the next drawing caller shows both.
        console::mirror(b"x", false);
        assert!(cell(&sc, 0, 1, b' ', fg, bg), "not drawn yet");
        assert!(seen().is_empty(), "nothing drawn, nothing to show");
        console::mirror(b"y", true);
        assert!(cell(&sc, 0, 1, b'x', fg, bg) && cell(&sc, 1, 1, b'y', fg, bg), "drawn with the next flush");
        assert_eq!(seen(), vec![r(0, CELL_H as u32, 2 * CELL_W as u32, CELL_H as u32)]);
        SEEN.lock().unwrap().clear();
        console::mirror(b"\n", true);
        assert!(seen().is_empty(), "a newline that changed no cell shows nothing");

        // The panic screen: claims the screen red, draws white, ignores the console after.
        let red = fmt.pack(0x70, 0, 0);
        let white = fmt.pack(0xFF, 0xFF, 0xFF);
        panic::puts("[PANIC] boom\n  at x.rs:1");
        assert_eq!(seen(), vec![r(0, 0, 160, 70), r(0, 0, 160, 2 * CELL_H as u32)], "the red screen, then the two rows");
        SEEN.lock().unwrap().clear();
        assert!(azos_fb::panic_active());
        assert!(cell(&sc, 1, 0, b'P', white, red), "banner on a red screen");
        assert!(cell(&sc, 2, 1, b'a', white, red), "second line, indented");
        let before = sc.mem.clone();
        console::mirror(b"after the panic\n", true);
        assert_eq!(sc.mem, before, "the console mirror must stay off a panic screen");
        assert!(seen().is_empty(), "and show nothing");
        panic::puts("\n\n\nBELOW"); // text row 4: only a 6-pixel strip of it is on the surface
        assert_eq!(seen(), vec![r(0, CELL_H as u32, 160, 3 * CELL_H as u32)], "up to the last row on the screen");
        SEEN.lock().unwrap().clear();
        panic::puts("\n\n\nfar below");
        assert_eq!(sc.mem, before, "text past the bottom edge is dropped, not written out of bounds");
        assert!(seen().is_empty(), "and not shown");
    }
}

// ---- virtio-gpu wire format ----

#[cfg(test)]
mod gpu_wire {
    use super::gpu_proto::*;

    fn le32(b: &[u8], off: usize) -> u32 {
        u32::from_le_bytes(b[off..off + 4].try_into().unwrap())
    }
    fn le64(b: &[u8], off: usize) -> u64 {
        u64::from_le_bytes(b[off..off + 8].try_into().unwrap())
    }
    const R: Rect = Rect { x: 3, y: 5, w: 7, h: 11 };

    #[test]
    fn requests_have_the_spec_layout() {
        // Canary: a swapped field, a wrong type number or a wrong length is a
        // request QEMU answers with ERR_INVALID_PARAMETER (or reads garbage).
        let b = get_display_info();
        assert_eq!((b.len(), le32(&b, 0)), (24, 0x100));
        assert!(b[4..].iter().all(|&x| x == 0), "no flags, fence, context");

        let b = get_edid(2);
        assert_eq!((b.len(), le32(&b, 0), le32(&b, 24)), (32, 0x10a, 2));

        let b = resource_create_2d(1, FORMAT_B8G8R8X8, 1280, 800);
        assert_eq!((b.len(), le32(&b, 0)), (40, 0x101));
        assert_eq!((le32(&b, 24), le32(&b, 28), le32(&b, 32), le32(&b, 36)), (1, 2, 1280, 800));

        let b = resource_attach_backing_1(1, 0x8000_0000_1000, 4096000);
        assert_eq!((b.len(), le32(&b, 0)), (48, 0x106));
        assert_eq!((le32(&b, 24), le32(&b, 28)), (1, 1), "resource, one entry");
        assert_eq!((le64(&b, 32), le32(&b, 40), le32(&b, 44)), (0x8000_0000_1000, 4096000, 0));

        let b = set_scanout(0, 1, R);
        assert_eq!((b.len(), le32(&b, 0)), (48, 0x103));
        assert_eq!([le32(&b, 24), le32(&b, 28), le32(&b, 32), le32(&b, 36)], [3, 5, 7, 11], "rect x y w h");
        assert_eq!((le32(&b, 40), le32(&b, 44)), (0, 1), "scanout, then resource");

        let b = transfer_to_host_2d(1, R, 0x1234);
        assert_eq!((b.len(), le32(&b, 0)), (56, 0x105));
        assert_eq!([le32(&b, 24), le32(&b, 28), le32(&b, 32), le32(&b, 36)], [3, 5, 7, 11]);
        assert_eq!((le64(&b, 40), le32(&b, 48), le32(&b, 52)), (0x1234, 1, 0), "offset, resource, pad");

        let b = resource_flush(1, R);
        assert_eq!((b.len(), le32(&b, 0)), (48, 0x104));
        assert_eq!([le32(&b, 24), le32(&b, 28), le32(&b, 32), le32(&b, 36)], [3, 5, 7, 11]);
        assert_eq!((le32(&b, 40), le32(&b, 44)), (1, 0), "resource, pad");
    }

    /// A GET_DISPLAY_INFO answer whose scanout 0 is `w` x `h`.
    fn display_info(ty: u32, w: u32, h: u32, enabled: u32) -> Vec<u8> {
        let mut b = vec![0u8; RESP_LEN_DISPLAY_INFO];
        b[0..4].copy_from_slice(&ty.to_le_bytes());
        b[32..36].copy_from_slice(&w.to_le_bytes());
        b[36..40].copy_from_slice(&h.to_le_bytes());
        b[40..44].copy_from_slice(&enabled.to_le_bytes());
        b
    }

    #[test]
    fn display_info_gives_scanout_zero() {
        let m = parse_display_info(&display_info(RESP_OK_DISPLAY_INFO, 1280, 800, 1));
        assert_eq!(m, Some(Mode { width: 1280, height: 800, hz: 60 }));
        assert_eq!(parse_display_info(&display_info(RESP_OK_DISPLAY_INFO, 1280, 800, 0)), None, "disabled");
        assert_eq!(parse_display_info(&display_info(RESP_OK_DISPLAY_INFO, 0, 800, 1)), None, "empty");
        assert_eq!(parse_display_info(&display_info(0x1200, 1280, 800, 1)), None, "an error answer");
        assert_eq!(parse_display_info(&display_info(RESP_OK_DISPLAY_INFO, 1, 1, 1)[..40]), None, "short");
        assert_eq!(resp_type(&[0; 3]), None);
    }

    /// A base EDID block whose first descriptor is the timing given.
    fn edid(hactive: u32, hblank: u32, vactive: u32, vblank: u32, clock_10khz: u16) -> Vec<u8> {
        let mut e = vec![0u8; 128];
        e[..8].copy_from_slice(&[0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0]);
        let d = &mut e[54..72];
        d[0..2].copy_from_slice(&clock_10khz.to_le_bytes());
        d[2] = hactive as u8;
        d[3] = hblank as u8;
        d[4] = ((hactive >> 4) & 0xf0) as u8 | ((hblank >> 8) & 0x0f) as u8;
        d[5] = vactive as u8;
        d[6] = vblank as u8;
        d[7] = ((vactive >> 4) & 0xf0) as u8 | ((vblank >> 8) & 0x0f) as u8;
        let sum = e[..127].iter().fold(0u8, |a, &b| a.wrapping_add(b));
        e[127] = 0u8.wrapping_sub(sum);
        e
    }

    fn edid_answer(e: &[u8]) -> Vec<u8> {
        let mut b = vec![0u8; RESP_LEN_EDID];
        b[0..4].copy_from_slice(&RESP_OK_EDID.to_le_bytes());
        b[24..28].copy_from_slice(&(e.len() as u32).to_le_bytes());
        b[32..32 + e.len()].copy_from_slice(e);
        b
    }

    #[test]
    fn edid_preferred_timing_gives_mode_and_refresh() {
        // 1920x1080 at 148.5 MHz over 2200x1125: 60 Hz. 12-bit sizes cross the
        // high-nibble packing (1920 = 0x780).
        let m = parse_edid_block(&edid(1920, 280, 1080, 45, 14850));
        assert_eq!(m, Some(Mode { width: 1920, height: 1080, hz: 60 }));
        // A QEMU-style 1280x800: 75 Hz.
        let clock = (75u64 * 1440 * 846 / 10_000) as u16;
        assert_eq!(parse_edid_block(&edid(1280, 160, 800, 46, clock)), Some(Mode { width: 1280, height: 800, hz: 75 }));
        // Through the answer: size word, then the block.
        let e = edid(1920, 280, 1080, 45, 14850);
        assert_eq!(parse_edid(&edid_answer(&e)), Some(Mode { width: 1920, height: 1080, hz: 60 }));
        // A refresh outside 24..=240 Hz is not believed.
        assert_eq!(parse_edid_block(&edid(1920, 280, 1080, 45, 100)).map(|m| m.hz), Some(60));
    }

    #[test]
    fn a_bad_edid_is_not_a_mode() {
        let good = edid(1920, 280, 1080, 45, 14850);
        let mut bad = good.clone();
        bad[127] ^= 1;
        assert_eq!(parse_edid_block(&bad), None, "checksum");
        let mut bad = good.clone();
        bad[0] = 1;
        assert_eq!(parse_edid_block(&bad), None, "header");
        let mut bad = good.clone();
        bad[54] = 0;
        bad[55] = 0; // pixel clock 0: a display descriptor, not a timing
        let sum = bad[..127].iter().fold(0u8, |a, &b| a.wrapping_add(b));
        bad[127] = 0u8.wrapping_sub(sum);
        assert_eq!(parse_edid_block(&bad), None, "not a timing descriptor");
        assert_eq!(parse_edid_block(&good[..100]), None, "short block");
        let mut a = edid_answer(&good);
        a[0..4].copy_from_slice(&0x1200u32.to_le_bytes());
        assert_eq!(parse_edid(&a), None, "an error answer");
        let mut a = edid_answer(&good);
        a[24..28].copy_from_slice(&64u32.to_le_bytes());
        assert_eq!(parse_edid(&a), None, "size shorter than a block");
        // The blob handed on to the connector is exactly the EDID bytes the
        // answer carries (what `publish_edid` parses), and only for an EDID answer.
        let ok = edid_answer(&good);
        assert_eq!(edid_blob(&ok), Some(&good[..]), "the bytes of the answer");
        let mut err = ok.clone();
        err[0..4].copy_from_slice(&0x1200u32.to_le_bytes());
        assert_eq!(edid_blob(&err), None, "an error answer carries none");
    }

    #[test]
    fn mode_choice_prefers_the_edid_then_the_scanout_then_the_default() {
        let edid_m = Mode { width: 1920, height: 1080, hz: 60 };
        let info_m = Mode { width: 1280, height: 800, hz: 60 };
        assert_eq!(choose_mode(Some(edid_m), Some(info_m)), edid_m);
        assert_eq!(choose_mode(None, Some(info_m)), info_m);
        assert_eq!(choose_mode(None, None), DEFAULT_MODE);
        let huge = Mode { width: 8192, height: 8192, hz: 60 };
        assert_eq!(choose_mode(Some(huge), Some(info_m)), info_m, "a mode too big to allocate is skipped");
        assert!(!mode_ok(Mode { width: 0, height: 600, hz: 60 }));
        assert!(!mode_ok(Mode { width: 8193, height: 1, hz: 60 }));
        assert!(mode_ok(Mode { width: 1920, height: 1080, hz: 60 }));
        assert!(mode_ok(Mode { width: 2048, height: 2048, hz: 60 }), "exactly 16 MiB");
        assert!(!mode_ok(Mode { width: 2049, height: 2048, hz: 60 }));
    }

    #[test]
    fn damage_is_the_bounding_box_and_taken_once() {
        // Canary: a lost update (the CAS replaced by load/store) or a union that
        // keeps only the last rectangle leaves part of the screen stale.
        let d = Damage::new();
        assert!(!d.pending() && d.take().is_none());
        d.add(Rect { x: 10, y: 20, w: 5, h: 5 });
        d.add(Rect { x: 40, y: 8, w: 2, h: 4 });
        d.add(Rect { x: 0, y: 0, w: 0, h: 9 }); // empty: ignored
        assert!(d.pending());
        assert_eq!(d.take(), Some(Rect { x: 10, y: 8, w: 32, h: 17 }));
        assert!(!d.pending() && d.take().is_none(), "taken once");
        d.add(Rect { x: 0, y: 0, w: 1, h: 1 });
        assert_eq!(d.take(), Some(Rect { x: 0, y: 0, w: 1, h: 1 }), "a rectangle at the origin is not 'empty'");
        d.add(Rect { x: u32::MAX, y: 1, w: 5, h: 5 });
        assert!(!d.pending(), "out of the 16-bit space");
        d.add(Rect { x: 65530, y: 0, w: 100, h: 1 });
        assert_eq!(d.take(), Some(Rect { x: 65530, y: 0, w: 5, h: 1 }), "clipped, not wrapped");
    }

    #[test]
    fn damage_from_many_threads_loses_nothing() {
        use std::sync::Arc;
        let d = Arc::new(Damage::new());
        let hs: Vec<_> = (0..4u32)
            .map(|t| {
                let d = d.clone();
                std::thread::spawn(move || {
                    for i in 0..2000u32 {
                        d.add(Rect { x: t * 100 + i % 100, y: t * 50, w: 1, h: 1 + i % 3 });
                    }
                })
            })
            .collect();
        for h in hs {
            h.join().unwrap();
        }
        let r = d.take().unwrap();
        assert_eq!((r.x, r.y), (0, 0));
        assert_eq!((r.x + r.w, r.y + r.h), (400, 153), "the union of every thread's rectangles");
    }
}

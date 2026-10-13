// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host tests for `crates/drivers/fb`: the font, pixel packing, the text grid's
//! scroll and dirty-rect math, and the panic screen, all over a `Vec<u8>`
//! standing in for the framebuffer. Each assertion has a canary: break the
//! thing it checks (see the comment on each test) and it goes red.

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

        assert_eq!(console::init(), Some((20, 4)));
        console::mirror(b"hi\n", true);
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
        console::mirror(b"y", true);
        assert!(cell(&sc, 0, 1, b'x', fg, bg) && cell(&sc, 1, 1, b'y', fg, bg), "drawn with the next flush");
        console::mirror(b"\n", true);

        // The panic screen: claims the screen red, draws white, ignores the console after.
        let red = fmt.pack(0x70, 0, 0);
        let white = fmt.pack(0xFF, 0xFF, 0xFF);
        panic::puts("[PANIC] boom\n  at x.rs:1");
        assert!(azos_fb::panic_active());
        assert!(cell(&sc, 1, 0, b'P', white, red), "banner on a red screen");
        assert!(cell(&sc, 2, 1, b'a', white, red), "second line, indented");
        let before = sc.mem.clone();
        console::mirror(b"after the panic\n", true);
        assert_eq!(sc.mem, before, "the console mirror must stay off a panic screen");
        panic::puts("\n\n\nBELOW"); // text row 4: only a 6-pixel strip of it is on the surface
        panic::puts("\n\n\nfar below");
        assert_eq!(sc.mem, before, "text past the bottom edge is dropped, not written out of bounds");
    }
}

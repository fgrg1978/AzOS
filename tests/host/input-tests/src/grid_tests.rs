// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The framebuffer text grid as the publisher of the screen region and the
//! renderer of its overlay: what the terminal server reads and what it asks
//! to have drawn, over a `Vec`-backed surface.

use azos_fb::font::{CELL_H, CELL_W};
use azos_fb::grid::Grid;
use azos_fb::pixel::{PixelFormat, Surface};
use azos_input_wire::screen::*;

const COLS: usize = 8;
const ROWS: usize = 4;
const SB: u32 = 3;
const L: Layout = Layout { cols_max: COLS as u32, rows_max: ROWS as u32, sb_cap: SB };
const FG: u32 = 0x00FF_FFFF;
const BG: u32 = 0x0000_0000;

struct Rig {
    grid: Grid<COLS, ROWS>,
    mem: Vec<u8>,
    surf: Surface,
    v: Viewer,
    _scr: Vec<u32>,
}

impl Rig {
    fn new() -> Rig {
        let fmt = PixelFormat::XRGB8888;
        let (w, h) = (COLS * CELL_W, ROWS * CELL_H);
        let stride = w * fmt.bytes();
        let mut mem = vec![0u8; stride * h];
        let surf = Surface { base: mem.as_mut_ptr(), width: w, height: h, stride, fmt };
        let mut scr = vec![0u32; L.bytes().div_ceil(4)];
        let base = scr.as_mut_ptr() as *mut u8;
        let mut grid = Grid::<COLS, ROWS>::new();
        assert!(grid.resize(w, h));
        // SAFETY: the Vec lives as long as the rig.
        let (p, v) = unsafe { (Publisher::format(base, L.bytes(), L).expect("formats"), Viewer::open(base, L.bytes()).expect("opens")) };
        grid.attach_screen(p);
        grid.flush(&surf, FG, BG);
        Rig { grid, mem, surf, v, _scr: scr }
    }

    fn write(&mut self, b: &[u8]) -> usize {
        self.grid.put_bytes(b);
        self.grid.flush(&self.surf, FG, BG)
    }

    /// The pixels of cell (`c`, `r`).
    fn cell(&self, c: usize, r: usize) -> Vec<u32> {
        let mut out = Vec::new();
        for y in 0..CELL_H {
            for x in 0..CELL_W {
                let o = ((r * CELL_H + y) * self.surf.stride) + (c * CELL_W + x) * 4;
                out.push(u32::from_le_bytes([self.mem[o], self.mem[o + 1], self.mem[o + 2], self.mem[o + 3]]));
            }
        }
        out
    }

    fn row_text(&self, vrow: i32) -> String {
        let mut b = [0u8; COLS];
        self.v.row(vrow, &mut b).expect("a row");
        String::from_utf8_lossy(&b).into_owned()
    }
}

/// What a cell showing `ch` looks like, plain or inverse.
fn glyph(ch: u8, inverse: bool) -> Vec<u32> {
    let fmt = PixelFormat::XRGB8888;
    let mut mem = vec![0u8; CELL_W * CELL_H * 4];
    let s = Surface { base: mem.as_mut_ptr(), width: CELL_W, height: CELL_H, stride: CELL_W * 4, fmt };
    let (f, b) = if inverse { (BG, FG) } else { (FG, BG) };
    s.draw_glyph(0, 0, ch, f, b);
    mem.chunks(4).map(|p| u32::from_le_bytes([p[0], p[1], p[2], p[3]])).collect()
}

#[test]
fn flushed_rows_reach_the_region_with_their_wrap_flags() {
    let mut g = Rig::new();
    g.write(b"ABCDEFGHIJ\nxy");
    assert_eq!(g.row_text(0), "ABCDEFGH");
    assert_eq!(g.v.row(0, &mut [0; COLS]), Some((COLS, true)), "the row the text ran off the end of");
    assert_eq!(g.row_text(1).trim_end(), "IJ");
    assert_eq!(g.v.row(1, &mut [0; COLS]), Some((COLS, false)), "a newline ends the line for good");
    assert_eq!(g.row_text(2).trim_end(), "xy");
    assert_eq!(g.v.dims(), (COLS as u32, ROWS as u32));
}

#[test]
fn a_flush_that_changes_the_text_changes_the_sequence_and_one_that_does_not_keeps_it() {
    let mut g = Rig::new();
    let s0 = g.v.seq();
    g.write(b"hi");
    let s1 = g.v.seq();
    assert_ne!(s0, s1);
    g.write(&[0]);
    assert_eq!(g.v.seq(), s1, "the redraw byte changes no text");
    assert_eq!(g.grid.cx, 2, "and it moves no cursor");
    assert_eq!(g.row_text(0).trim_end(), "hi", "nor writes a question mark");
}

#[test]
fn lines_that_scroll_off_are_kept_up_to_the_bound() {
    let mut g = Rig::new();
    // Ten lines on a four-row screen: six scroll off, three are kept.
    g.write(b"l0\nl1\nl2\nl3\nl4\nl5\nl6\nl7\nl8\nl9");
    assert_eq!(g.v.sb_count(), SB);
    assert_eq!(g.row_text(-1).trim_end(), "l5", "the newest line that scrolled off");
    assert_eq!(g.row_text(-3).trim_end(), "l3");
    assert!(g.v.row(-4, &mut [0; COLS]).is_none(), "the older ones fell off the end");
    assert_eq!(g.row_text(0).trim_end(), "l6", "the screen shows the last four lines");
    assert_eq!(g.row_text(3).trim_end(), "l9");
}

#[test]
fn mouse_reporting_modes_are_noted_from_the_console_output() {
    let mut g = Rig::new();
    g.write(b"\x1b[?1000;1006h");
    assert_eq!(g.v.mouse_mode(), MOUSE_PRESS | MOUSE_SGR);
    g.write(b"\x1b[?1002h\x1b[2J\x1b[1;1H");
    assert_eq!(g.v.mouse_mode(), MOUSE_PRESS | MOUSE_SGR | MOUSE_DRAG, "other sequences leave it alone");
    g.write(b"\x1b[?1000l");
    assert_eq!(g.v.mouse_mode(), MOUSE_SGR | MOUSE_DRAG);
    g.write(b"\x1b[1000h");
    assert_eq!(g.v.mouse_mode(), MOUSE_SGR | MOUSE_DRAG, "not private: not a mouse mode");
    g.write(b"\x1b[?25l");
    assert_eq!(g.v.mouse_mode(), MOUSE_SGR | MOUSE_DRAG, "the cursor mode is not one either");
    // A sequence split across writes still counts.
    g.write(b"\x1b[?10");
    g.write(b"03h");
    assert_eq!(g.v.mouse_mode(), MOUSE_SGR | MOUSE_DRAG | MOUSE_MOTION);
    // The server forgets the mode (the job that set it is gone).
    g.v.clear_mouse_mode();
    g.write(&[0]);
    assert_eq!(g.v.mouse_mode(), 0);
    assert_eq!(g.grid.mouse_mode(), 0);
}

#[test]
fn the_pointer_and_the_selection_are_drawn_in_inverse_video_over_the_text() {
    let mut g = Rig::new();
    g.write(b"hello wo");
    assert_eq!(g.cell(1, 0), glyph(b'e', false));
    g.v.set_overlay(&Overlay { ptr: Some((1, 0)), sel: Some((3, 5)), view_off: 0 });
    let drawn = g.write(&[0]);
    assert_eq!(g.cell(1, 0), glyph(b'e', true), "the pointer cell is inverse");
    assert_eq!(g.cell(0, 0), glyph(b'h', false));
    for (c, ch) in [(3, b'l'), (4, b'o'), (5, b' ')] {
        assert_eq!(g.cell(c, 0), glyph(ch, true), "selected cell {c}");
    }
    assert_eq!(g.cell(6, 0), glyph(b'w', false));
    assert_eq!(drawn, COLS, "only the row the overlay touches is redrawn");
    // The text itself was not written over: the region and the grid are as before.
    assert_eq!(g.row_text(0), "hello wo");
    // Pointer on a selected cell: the two cancel, so it stays findable as a hole.
    g.v.set_overlay(&Overlay { ptr: Some((4, 0)), sel: Some((3, 5)), view_off: 0 });
    g.write(&[0]);
    assert_eq!(g.cell(4, 0), glyph(b'o', false));
    assert_eq!(g.cell(1, 0), glyph(b'e', false), "the old pointer cell is restored");
    // Gone.
    g.v.set_overlay(&Overlay::default());
    g.write(&[0]);
    for c in 0..COLS {
        assert_ne!(g.cell(c, 0), glyph(b'?', true));
    }
    assert_eq!(g.cell(4, 0), glyph(b'o', false));
    assert_eq!(g.cell(3, 0), glyph(b'l', false));
}

#[test]
fn moving_a_selection_end_redraws_only_the_rows_it_changed() {
    let mut g = Rig::new();
    g.write(b"aaaaaaaa\nbbbbbbbb\ncccccccc\ndddddddd");
    g.v.set_overlay(&Overlay { ptr: None, sel: Some((2, 10)), view_off: 0 });
    g.write(&[0]);
    // The end moves within row 1; the start stays in row 0.
    g.v.set_overlay(&Overlay { ptr: None, sel: Some((2, 12)), view_off: 0 });
    let drawn = g.write(&[0]);
    assert_eq!(drawn, COLS, "one row");
    assert_eq!(g.cell(4, 1), glyph(b'b', true));
}

#[test]
fn a_view_scrolled_back_shows_the_scrollback_and_returns() {
    let mut g = Rig::new();
    g.write(b"l0\nl1\nl2\nl3\nl4\nl5");
    // Two lines scrolled off: l0, l1. The screen shows l2..l5.
    assert_eq!(g.v.sb_count(), 2);
    assert_eq!(g.cell(1, 0), glyph(b'2', false));
    g.v.set_overlay(&Overlay { ptr: None, sel: None, view_off: 2 });
    g.write(&[0]);
    assert_eq!(g.cell(1, 0), glyph(b'0', false), "row 0 is now the older scrolled-off line");
    assert_eq!(g.cell(1, 1), glyph(b'1', false));
    assert_eq!(g.cell(1, 2), glyph(b'2', false), "and the live screen follows below");
    g.v.set_overlay(&Overlay::default());
    g.write(&[0]);
    assert_eq!(g.cell(1, 0), glyph(b'2', false));
    // More scrollback than exists is cut to what exists.
    g.v.set_overlay(&Overlay { ptr: None, sel: None, view_off: 99 });
    g.write(&[0]);
    assert_eq!(g.cell(1, 0), glyph(b'0', false));
}

#[test]
fn a_grid_without_a_screen_draws_as_it_did() {
    let fmt = PixelFormat::XRGB8888;
    let mut mem = vec![0u8; COLS * CELL_W * 4 * ROWS * CELL_H];
    let surf = Surface { base: mem.as_mut_ptr(), width: COLS * CELL_W, height: ROWS * CELL_H, stride: COLS * CELL_W * 4, fmt };
    let mut grid = Grid::<COLS, ROWS>::new();
    assert!(grid.resize(COLS * CELL_W, ROWS * CELL_H));
    grid.flush(&surf, FG, BG);
    grid.put_bytes(b"ab\x1b[?1000h");
    assert_eq!(grid.flush(&surf, FG, BG), 2);
    assert_eq!(grid.mouse_mode(), MOUSE_PRESS, "noted even with nowhere to publish it");
}

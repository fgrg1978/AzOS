// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host test for the handover of the screen: a display server retires the
//! text console, the console keeps its text but stops drawing, and when the
//! server lets go the whole grid is drawn again.
//!
//! One test: the framebuffer registry and the console are process-wide.

use azos_fb::font::{self, CELL_H, CELL_W};
use azos_fb::pixel::PixelFormat;
use azos_fb::{console, console_retired, register, resume_console, retire_console, FbInfo};

#[test]
fn retire_keeps_the_text_and_resume_draws_all_of_it() {
    // No framebuffer yet: nothing to retire, nothing to resume.
    assert!(!retire_console() && !console_retired());
    assert!(!resume_console());

    let fmt = PixelFormat::XRGB8888;
    let (w, h) = (160usize, 64usize); // 20 x 4 text cells
    let stride = w * 4;
    let mut mem = vec![0u8; stride * h];
    assert!(register(FbInfo { phys: 0x8000_0000, width: w as u32, height: h as u32, stride: stride as u32, format: fmt }, mem.as_mut_ptr() as usize));
    assert_eq!(console::init(), Some((20, 4)));
    console::mirror(b"ab\n", true);

    let (fg, bg) = azos_fb::colours(&fmt);
    let px = |mem: &[u8], x: usize, y: usize| u32::from_le_bytes(mem[y * stride + x * 4..y * stride + x * 4 + 4].try_into().unwrap());
    let cell_is = |mem: &[u8], c: usize, r: usize, ch: u8| {
        (0..CELL_H).all(|y| {
            (0..CELL_W).all(|x| {
                let ink = font::glyph(ch)[y] & (0x80 >> x) != 0;
                px(mem, c * CELL_W + x, r * CELL_H + y) == if ink { fg } else { bg }
            })
        })
    };
    assert!(cell_is(&mem, 0, 0, b'a') && cell_is(&mem, 1, 0, b'b'));

    // The display server claims the screen.
    assert!(retire_console());
    assert!(!retire_console(), "once");
    assert!(console_retired());

    // It draws its own picture; the console's text goes to the grid only.
    let server = 0x00AB_CDEFu32.to_le_bytes();
    for p in mem.chunks_exact_mut(4) {
        p.copy_from_slice(&server);
    }
    let picture = mem.clone();
    console::mirror(b"cd\n", true);
    console::mirror(b"ef", false);
    assert_eq!(mem, picture, "a retired console draws nothing, interrupt context or not");

    // The server lets go. The next line prints the whole grid, including what
    // was written while the server held the screen and the server's picture is gone.
    assert!(resume_console());
    assert!(!resume_console(), "once");
    assert!(!console_retired());
    console::mirror(b"g\n", true);
    assert!(cell_is(&mem, 0, 0, b'a') && cell_is(&mem, 1, 0, b'b'), "text from before");
    assert!(cell_is(&mem, 0, 1, b'c') && cell_is(&mem, 1, 1, b'd'), "text written while retired");
    assert!(cell_is(&mem, 0, 2, b'e') && cell_is(&mem, 1, 2, b'f') && cell_is(&mem, 2, 2, b'g'));
    assert!(cell_is(&mem, 19, 3, b' '), "the server's picture is overdrawn to the last cell");
    assert!(mem.chunks_exact(4).all(|p| p != server), "no pixel of the server's picture survives");
}

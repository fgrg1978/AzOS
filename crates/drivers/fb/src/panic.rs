// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The panic screen (Kconfig `FB_PANIC_SCREEN`): the `[PANIC]` report drawn
//! straight onto the write-combining mapping. No lock, no allocation, no
//! text grid: it reads the registered framebuffer through atomics and keeps
//! its own cursor, so it works from a panic taken inside the console mirror
//! or with the heap gone. The first call claims the screen (the console
//! mirror stops) and paints it dark red; text stops at the bottom edge.

use crate::font::{CELL_H, CELL_W};
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

static CLAIMED: AtomicBool = AtomicBool::new(false);
static COL: AtomicUsize = AtomicUsize::new(0);
static ROW: AtomicUsize = AtomicUsize::new(0);

/// Append `s` to the panic screen. `\n` starts a line; a line past the right
/// edge wraps; past the bottom, text is dropped.
pub fn puts(s: &str) {
    let Some(surf) = crate::surface() else { return };
    let fmt = surf.fmt;
    let bg = fmt.pack(0x70, 0x00, 0x00);
    let fg = fmt.pack(0xFF, 0xFF, 0xFF);
    if !CLAIMED.swap(true, Ordering::AcqRel) {
        crate::set_panic_active();
        surf.fill_rect(0, 0, surf.width, surf.height, bg);
        COL.store(0, Ordering::Relaxed);
        ROW.store(0, Ordering::Relaxed);
    }
    let cols = surf.width / CELL_W;
    let rows = surf.height / CELL_H;
    let (mut col, mut row) = (COL.load(Ordering::Relaxed), ROW.load(Ordering::Relaxed));
    for b in s.bytes() {
        match b {
            b'\n' => {
                col = 0;
                row += 1;
            }
            b'\r' => {}
            _ => {
                if col >= cols {
                    col = 0;
                    row += 1;
                }
                if row < rows {
                    surf.draw_glyph(col * CELL_W, row * CELL_H, b, fg, bg);
                }
                col += 1;
            }
        }
    }
    COL.store(col, Ordering::Relaxed);
    ROW.store(row, Ordering::Relaxed);
}

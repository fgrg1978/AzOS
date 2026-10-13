// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The kernel framebuffer console (Kconfig `FB_CONSOLE`): a text grid that
//! mirrors every byte the UART console writes. [`mirror`] runs inside
//! whatever context printed (an interrupt handler included), so it only
//! try-locks: a line that finds the grid busy is dropped from the screen
//! (counted by [`dropped`]) and never waits.

use crate::grid::Grid;
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

const COLS: usize = azos_limits::FB_CONSOLE_COLS_MAX;
const ROWS: usize = azos_limits::FB_CONSOLE_ROWS_MAX;

struct State(UnsafeCell<Grid<COLS, ROWS>>);
// SAFETY: every access holds `LOCK`.
unsafe impl Sync for State {}

static GRID: State = State(UnsafeCell::new(Grid::new()));
static LOCK: AtomicBool = AtomicBool::new(false);
static ACTIVE: AtomicBool = AtomicBool::new(false);
static DROPPED: AtomicU32 = AtomicU32::new(0);

fn try_lock() -> bool {
    LOCK.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed).is_ok()
}

/// Size the grid for the registered framebuffer, clear the screen and start
/// mirroring. `Some((cols, rows))`, or `None` without a framebuffer.
pub fn init() -> Option<(usize, usize)> {
    let surf = crate::surface()?;
    while !try_lock() {
        core::hint::spin_loop();
    }
    // SAFETY: LOCK held.
    let grid = unsafe { &mut *GRID.0.get() };
    let ok = grid.resize(surf.width, surf.height);
    let (fg, bg) = crate::colours(&surf.fmt);
    surf.fill_rect(0, 0, surf.width, surf.height, bg);
    grid.flush(&surf, fg, bg);
    let out = (grid.cols, grid.rows);
    LOCK.store(false, Ordering::Release);
    if ok {
        ACTIVE.store(true, Ordering::Release);
        Some(out)
    } else {
        None
    }
}

/// Mirror console bytes onto the screen. Cheap no-op until [`init`]. With
/// `draw` false (an interrupt handler or a spinlock holder is printing) the
/// text goes into the grid only; the next caller that may draw flushes it.
pub fn mirror(bytes: &[u8], draw: bool) {
    if !ACTIVE.load(Ordering::Acquire) || crate::panic_active() {
        return;
    }
    if !try_lock() {
        DROPPED.fetch_add(1, Ordering::Relaxed);
        return;
    }
    if let Some(surf) = crate::surface() {
        // SAFETY: LOCK held.
        let grid = unsafe { &mut *GRID.0.get() };
        grid.put_bytes(bytes);
        if draw {
            let (fg, bg) = crate::colours(&surf.fmt);
            grid.flush(&surf, fg, bg);
        }
    }
    LOCK.store(false, Ordering::Release);
}

/// Writes the screen dropped because the grid was busy.
pub fn dropped() -> u32 {
    DROPPED.load(Ordering::Relaxed)
}

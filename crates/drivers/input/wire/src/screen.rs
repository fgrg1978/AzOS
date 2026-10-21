// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The console screen region: what a terminal server needs from the
//! framebuffer console to select text and scroll it back, and what it hands
//! the renderer in return, all through shared memory (no call per cell).
//!
//! ```text
//! 0      header: 256 bytes of u32 words (indices in [`word`])
//! 256    cells:   rows_max x cols_max bytes, screen order (row 0 = top)
//! ..     flags:   rows_max + sb_cap bytes, bit 0 = the row continues on the
//!                 next one (it was left by auto-wrap, not by a newline);
//!                 rows 0..rows_max are the screen, then the scrollback slots
//! ..     scrollback: sb_cap x cols_max bytes, a ring of the lines that
//!                 scrolled off, `sb_head` the next slot to write
//! ```
//!
//! **Two owners.** The kernel ([`Publisher`]) writes cells, flags, scrollback,
//! the dimensions, the sequence word and the mouse mode; the server
//! ([`Viewer`]) writes only the overlay words and the mode-clear word. The
//! region is mapped read-write into the server, so the kernel keeps its own
//! copy of every number it indexes with (layout, scrollback head and count)
//! and treats the overlay words as untrusted input ([`Publisher::overlay`]
//! clamps them). The overlay is a seqlock: the server makes the sequence odd,
//! writes the words, makes it even; the kernel takes an overlay only from an
//! even, unchanged sequence.

use core::sync::atomic::{AtomicU32, Ordering};

/// "SCRN".
pub const MAGIC: u32 = 0x4E52_4353;
pub const VERSION: u32 = 1;
/// Bytes of the header.
pub const HEADER: usize = 256;

/// Header word indices.
pub mod word {
    pub const MAGIC: usize = 0;
    pub const VERSION: usize = 1;
    pub const COLS_MAX: usize = 2;
    pub const ROWS_MAX: usize = 3;
    pub const SB_CAP: usize = 4;
    /// Columns and rows in use.
    pub const COLS: usize = 5;
    pub const ROWS: usize = 6;
    /// Bumped by the kernel after the cells or the scrollback changed.
    pub const SEQ: usize = 7;
    pub const SB_COUNT: usize = 8;
    pub const SB_HEAD: usize = 9;
    /// `MOUSE_*` bits: what the programs asked the terminal to report.
    pub const MOUSE_MODE: usize = 10;
    // Server to kernel.
    pub const PTR_VIS: usize = 16;
    pub const PTR_COL: usize = 17;
    pub const PTR_ROW: usize = 18;
    pub const SEL_ON: usize = 19;
    pub const SEL_A: usize = 20;
    pub const SEL_B: usize = 21;
    pub const VIEW_OFF: usize = 22;
    /// Any change clears [`MOUSE_MODE`] (the foreground job is gone).
    pub const MODE_CLEAR: usize = 23;
    /// The overlay seqlock.
    pub const OVL_SEQ: usize = 24;
}

/// `ESC [ ? 1000 h`: report button presses and releases.
pub const MOUSE_PRESS: u32 = 1;
/// `ESC [ ? 1002 h`: also report motion while a button is held.
pub const MOUSE_DRAG: u32 = 2;
/// `ESC [ ? 1003 h`: report all motion.
pub const MOUSE_MOTION: u32 = 4;
/// `ESC [ ? 1006 h`: SGR encoding.
pub const MOUSE_SGR: u32 = 8;
/// Any reporting mode on (SGR alone reports nothing).
pub const MOUSE_ANY: u32 = MOUSE_PRESS | MOUSE_DRAG | MOUSE_MOTION;

/// The geometry of a region, fixed when the kernel formats it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Layout {
    pub cols_max: u32,
    pub rows_max: u32,
    pub sb_cap: u32,
}

impl Layout {
    const fn cells_len(&self) -> usize {
        self.cols_max as usize * self.rows_max as usize
    }
    const fn flags_off(&self) -> usize {
        HEADER + self.cells_len()
    }
    const fn sb_off(&self) -> usize {
        self.flags_off() + self.rows_max as usize + self.sb_cap as usize
    }
    /// Bytes of a region of this geometry.
    pub const fn bytes(&self) -> usize {
        self.sb_off() + self.sb_cap as usize * self.cols_max as usize
    }
    fn sane(&self) -> bool {
        self.cols_max >= 1 && self.rows_max >= 1 && self.cols_max <= 4096 && self.rows_max <= 4096 && self.sb_cap <= 1 << 20
    }
}

/// The overlay the server asks the renderer to draw.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Overlay {
    /// The pointer cell (column, row) of the view, inverse video.
    pub ptr: Option<(u32, u32)>,
    /// The selection, as view cell indices (`row * cols + col`), `a <= b`,
    /// both ends inclusive, inverse video.
    pub sel: Option<(u32, u32)>,
    /// Lines the view is scrolled back into the scrollback (0 = live).
    pub view_off: u32,
}

/// A memory region of the geometry, as raw words.
#[derive(Clone, Copy)]
struct Region {
    base: *mut u8,
}

// SAFETY: the region is shared memory accessed only through atomics and
// volatile bytes.
unsafe impl Send for Region {}
unsafe impl Sync for Region {}

impl Region {
    fn word(&self, i: usize) -> &AtomicU32 {
        debug_assert!(i * 4 < HEADER);
        // SAFETY: `from_raw` checked the base alignment and that the header
        // fits; `i` is a `word::*` index.
        unsafe { &*(self.base.add(i * 4) as *const AtomicU32) }
    }

    fn put(&self, off: usize, bytes: &[u8]) {
        for (i, &b) in bytes.iter().enumerate() {
            // SAFETY: callers keep `off + bytes.len()` inside the layout.
            unsafe { core::ptr::write_volatile(self.base.add(off + i), b) };
        }
    }

    fn get(&self, off: usize, out: &mut [u8]) {
        for (i, o) in out.iter_mut().enumerate() {
            // SAFETY: as `put`.
            *o = unsafe { core::ptr::read_volatile(self.base.add(off + i)) };
        }
    }

    fn byte(&self, off: usize) -> u8 {
        let mut b = [0u8];
        self.get(off, &mut b);
        b[0]
    }
}

fn region_ok(base: *mut u8, len: usize, l: &Layout) -> bool {
    !base.is_null() && base as usize % 4 == 0 && l.sane() && len >= l.bytes()
}

/// The kernel's side: writes the screen, reads the overlay.
pub struct Publisher {
    r: Region,
    l: Layout,
    cols: u32,
    rows: u32,
    sb_head: u32,
    sb_count: u32,
}

impl Publisher {
    /// Format the `len` bytes at `base` as a screen region of geometry `l`.
    ///
    /// # Safety
    /// `base..base+len` must be writable memory the caller owns for as long
    /// as the publisher lives; other readers and writers use this module.
    pub unsafe fn format(base: *mut u8, len: usize, l: Layout) -> Option<Publisher> {
        if !region_ok(base, len, &l) {
            return None;
        }
        let r = Region { base };
        for i in 0..HEADER / 4 {
            r.word(i).store(0, Ordering::Relaxed);
        }
        r.word(word::VERSION).store(VERSION, Ordering::Relaxed);
        r.word(word::COLS_MAX).store(l.cols_max, Ordering::Relaxed);
        r.word(word::ROWS_MAX).store(l.rows_max, Ordering::Relaxed);
        r.word(word::SB_CAP).store(l.sb_cap, Ordering::Relaxed);
        r.word(word::MAGIC).store(MAGIC, Ordering::Release);
        Some(Publisher { r, l, cols: 0, rows: 0, sb_head: 0, sb_count: 0 })
    }

    /// Columns and rows in use (the renderer sized the grid).
    pub fn set_dims(&mut self, cols: u32, rows: u32) {
        self.cols = cols.min(self.l.cols_max);
        self.rows = rows.min(self.l.rows_max);
        self.sb_head = 0;
        self.sb_count = 0;
        self.r.word(word::COLS).store(self.cols, Ordering::Relaxed);
        self.r.word(word::ROWS).store(self.rows, Ordering::Relaxed);
        self.r.word(word::SB_HEAD).store(0, Ordering::Relaxed);
        self.r.word(word::SB_COUNT).store(0, Ordering::Relaxed);
        self.bump_seq();
    }

    /// Screen row `row` as it is now.
    pub fn put_row(&mut self, row: u32, cells: &[u8], wrapped: bool) {
        if row >= self.rows {
            return;
        }
        let n = cells.len().min(self.cols as usize);
        self.r.put(HEADER + row as usize * self.l.cols_max as usize, &cells[..n]);
        self.r.put(self.l.flags_off() + row as usize, &[wrapped as u8]);
    }

    /// A line scrolled off the top of the screen.
    pub fn push_scrollback(&mut self, cells: &[u8], wrapped: bool) {
        if self.l.sb_cap == 0 {
            return;
        }
        let n = cells.len().min(self.cols as usize);
        let slot = self.sb_head as usize;
        self.r.put(self.l.sb_off() + slot * self.l.cols_max as usize, &cells[..n]);
        self.r.put(self.l.flags_off() + self.l.rows_max as usize + slot, &[wrapped as u8]);
        self.sb_head = (self.sb_head + 1) % self.l.sb_cap;
        self.sb_count = (self.sb_count + 1).min(self.l.sb_cap);
        self.r.word(word::SB_HEAD).store(self.sb_head, Ordering::Relaxed);
        self.r.word(word::SB_COUNT).store(self.sb_count, Ordering::Relaxed);
    }

    /// Lines in the scrollback now.
    pub fn sb_count(&self) -> u32 {
        self.sb_count
    }

    /// Scrollback line `back` (0 = the newest) into `out`; its wrapped flag.
    pub fn sb_row(&self, back: u32, out: &mut [u8]) -> Option<bool> {
        if back >= self.sb_count {
            return None;
        }
        let slot = (self.sb_head + self.l.sb_cap - 1 - back) % self.l.sb_cap;
        let n = out.len().min(self.cols as usize);
        self.r.get(self.l.sb_off() + slot as usize * self.l.cols_max as usize, &mut out[..n]);
        Some(self.r.byte(self.l.flags_off() + self.l.rows_max as usize + slot as usize) & 1 != 0)
    }

    /// The cells and the scrollback changed: publish a new sequence.
    pub fn bump_seq(&self) {
        self.r.word(word::SEQ).fetch_add(1, Ordering::Release);
    }

    pub fn set_mouse_mode(&self, mode: u32) {
        self.r.word(word::MOUSE_MODE).store(mode, Ordering::Release);
    }

    pub fn mouse_mode(&self) -> u32 {
        self.r.word(word::MOUSE_MODE).load(Ordering::Acquire)
    }

    /// The server's request to forget the mouse mode (a counter it bumps).
    pub fn mode_clear_seq(&self) -> u32 {
        self.r.word(word::MODE_CLEAR).load(Ordering::Acquire)
    }

    /// The overlay the server last published, clamped to this screen. `None`
    /// while the server is mid-write (the caller keeps what it drew).
    pub fn overlay(&self) -> Option<Overlay> {
        let s1 = self.r.word(word::OVL_SEQ).load(Ordering::Acquire);
        if s1 & 1 != 0 {
            return None;
        }
        let w = |i| self.r.word(i).load(Ordering::Relaxed);
        let (vis, col, row) = (w(word::PTR_VIS), w(word::PTR_COL), w(word::PTR_ROW));
        let (son, sa, sb) = (w(word::SEL_ON), w(word::SEL_A), w(word::SEL_B));
        let off = w(word::VIEW_OFF);
        core::sync::atomic::fence(Ordering::Acquire);
        if self.r.word(word::OVL_SEQ).load(Ordering::Relaxed) != s1 {
            return None;
        }
        let cells = self.cols * self.rows;
        Some(Overlay {
            ptr: (vis != 0 && col < self.cols && row < self.rows).then_some((col, row)),
            sel: (son != 0 && cells != 0).then(|| {
                let (a, b) = (sa.min(sb), sa.max(sb));
                (a.min(cells - 1), b.min(cells - 1))
            }),
            view_off: off.min(self.sb_count),
        })
    }
}

/// The server's side: reads the screen, writes the overlay.
pub struct Viewer {
    r: Region,
    l: Layout,
}

impl Viewer {
    /// Open the region at `base` (`len` bytes) a kernel formatted. `None` for
    /// memory that is not one (wrong magic, version or geometry).
    ///
    /// # Safety
    /// `base..base+len` must be readable and writable mapped memory for as
    /// long as the viewer lives.
    pub unsafe fn open(base: *mut u8, len: usize) -> Option<Viewer> {
        if base.is_null() || base as usize % 4 != 0 || len < HEADER {
            return None;
        }
        let r = Region { base };
        if r.word(word::MAGIC).load(Ordering::Acquire) != MAGIC || r.word(word::VERSION).load(Ordering::Relaxed) != VERSION {
            return None;
        }
        let l = Layout {
            cols_max: r.word(word::COLS_MAX).load(Ordering::Relaxed),
            rows_max: r.word(word::ROWS_MAX).load(Ordering::Relaxed),
            sb_cap: r.word(word::SB_CAP).load(Ordering::Relaxed),
        };
        region_ok(base, len, &l).then_some(Viewer { r, l })
    }

    fn w(&self, i: usize) -> u32 {
        self.r.word(i).load(Ordering::Acquire)
    }

    /// Columns and rows in use.
    pub fn dims(&self) -> (u32, u32) {
        (self.w(word::COLS).min(self.l.cols_max), self.w(word::ROWS).min(self.l.rows_max))
    }

    /// The content sequence: changes when the cells or the scrollback do.
    pub fn seq(&self) -> u32 {
        self.w(word::SEQ)
    }

    /// Lines in the scrollback.
    pub fn sb_count(&self) -> u32 {
        self.w(word::SB_COUNT).min(self.l.sb_cap)
    }

    pub fn mouse_mode(&self) -> u32 {
        self.w(word::MOUSE_MODE)
    }

    /// Line `vrow` into `out`: `0..rows` is the live screen, `-1` the newest
    /// scrollback line, `-2` the one before. The number of cells read and
    /// whether the line continues on the next one.
    pub fn row(&self, vrow: i32, out: &mut [u8]) -> Option<(usize, bool)> {
        let (cols, rows) = self.dims();
        let n = out.len().min(cols as usize);
        if vrow >= 0 {
            if vrow as u32 >= rows {
                return None;
            }
            self.r.get(HEADER + vrow as usize * self.l.cols_max as usize, &mut out[..n]);
            return Some((n, self.r.byte(self.l.flags_off() + vrow as usize) & 1 != 0));
        }
        let back = vrow.unsigned_abs() - 1;
        let (count, head) = (self.sb_count(), self.w(word::SB_HEAD));
        if back >= count || self.l.sb_cap == 0 || head >= self.l.sb_cap {
            return None;
        }
        let slot = (head + self.l.sb_cap - 1 - back) % self.l.sb_cap;
        self.r.get(self.l.sb_off() + slot as usize * self.l.cols_max as usize, &mut out[..n]);
        Some((n, self.r.byte(self.l.flags_off() + self.l.rows_max as usize + slot as usize) & 1 != 0))
    }

    /// Ask the renderer to draw `o`. The renderer picks it up at its next
    /// flush.
    pub fn set_overlay(&self, o: &Overlay) {
        let s = self.r.word(word::OVL_SEQ);
        // Odd first, and the fence keeps the data stores after it (a seqlock
        // writer): a reader that sees an even, unchanged sequence on both
        // sides saw no store in between.
        s.fetch_add(1, Ordering::Relaxed);
        core::sync::atomic::fence(Ordering::Release);
        let put = |i, v: u32| self.r.word(i).store(v, Ordering::Relaxed);
        let (pc, pr) = o.ptr.unwrap_or((0, 0));
        put(word::PTR_VIS, o.ptr.is_some() as u32);
        put(word::PTR_COL, pc);
        put(word::PTR_ROW, pr);
        let (sa, sb) = o.sel.unwrap_or((0, 0));
        put(word::SEL_ON, o.sel.is_some() as u32);
        put(word::SEL_A, sa);
        put(word::SEL_B, sb);
        put(word::VIEW_OFF, o.view_off);
        s.fetch_add(1, Ordering::Release);
    }

    /// Forget the mouse mode the programs set (the job that set it is gone).
    pub fn clear_mouse_mode(&self) {
        self.r.word(word::MODE_CLEAR).fetch_add(1, Ordering::Release);
    }
}

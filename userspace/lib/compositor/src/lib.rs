// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The `Compositor` object: how a client puts a window on the screen.
//!
//! `COMPSRV.ELF` (`userspace/services/compositor`) serves it on [`ENDPOINT`].
//! It is the sole holder of the kernel's `Display` interface; a client never
//! touches the screen. A window is **a memory object the client made**:
//!
//! ```text
//! page 0       control: the damage ring (WindowRing) the client posts to
//! CONTROL_BYTES.. pixels, XRGB8888, `width` pixels per row, rows packed
//! ```
//!
//! # Calls are authority, data goes through the ring
//!
//! * [`Compositor::attach`] lends the object (a `Lent`, a copy of the client's
//!   capability: the client keeps drawing in its own mapping) with the
//!   window's [`Shape`]. The reply is the window's id and **a call right bound to
//!   that window** (`Lent<WindowRight>`): the compositor derived it from its own
//!   endpoint with a badge only it names ([`window_badge`]), so a call through
//!   it can only concern this window.
//! * [`Compositor::detach`] takes the window down. It is accepted only through
//!   that right: the plain call right every client holds (it attaches) cannot
//!   take another client's window away, and a right revoked by a detach is dead.
//! * Drawing posts no call. The client writes pixels into the object and
//!   pushes the rectangle it changed into the [`WindowRing`]; the compositor
//!   reads the ring on its frame timer, composes the damage and presents it. A
//!   full ring means "everything changed" ([`WindowRing::overflowed`]).
//!   Tearing is tolerated: a present may copy while the client is drawing.
//! * [`Compositor::status`] is the server's counters.
//!
//! The frame a client sees is the compositor's: it does not learn when its
//! damage was shown (no vsync is promised by the scanouts the kernel drives).
//!
//! # What this does not do
//!
//! A window is one memory object of at most [`MAX_PAGES`] pages (the object
//! model's ceiling, `azos_devif::display`'s doc), control page included, so a
//! window is a small thing (about 250x250 pixels); a client needing more takes
//! several windows. Input is the input server's (`azos_devif::input`): a
//! client asks it for the focus as before, and the compositor routes nothing.

#![no_std]

use azos_devif::display::Rect;
use azos_devif::outcome::Out;
use azos_idl::{azos_interface, Lent, Reader, Wire, Writer};
use azos_rings::region::{RingStep, SpscRing, RING_SLOTS as RING_HEADER_BYTES};

/// The interface id (ASCII "CMPS").
pub const COMPOSITOR_ID: u32 = 0x434D_5053;
/// The endpoint a topology row declares for this object.
pub const ENDPOINT: &str = "endpoint.compositor";

/// Windows the compositor shows at once.
pub const WINDOWS: usize = 8;
/// Pages of a window's memory object at most (`MAX_MEMOBJ_PAGES`).
pub const MAX_PAGES: u64 = 64;
/// Bytes of the control area at the start of a window's object. The pixels
/// begin right after it.
pub const CONTROL_BYTES: usize = 4096;
/// Bytes per pixel: XRGB8888, little endian (blue in the first byte).
pub const PIXEL_BYTES: usize = 4;
/// Slots of the damage ring (a power of two); with its header it fits the
/// control area.
pub const DAMAGE_SLOTS: u32 = 64;
/// Longest side of a window in pixels (what a damage rectangle can name).
pub const SIDE_MAX: u32 = 4096;

/// The badge bit that marks a window's right, as a warrant's does for the input
/// server: a badge a topology row can carry is small, so a call that arrives
/// with this bit set came through a right the compositor derived itself. The
/// low bits are the window id.
pub const WINDOW_BADGE: u32 = 1 << 31;

/// The badge of the call right bound to window `id`.
pub const fn window_badge(id: u32) -> u32 {
    WINDOW_BADGE | (id & !WINDOW_BADGE)
}

/// The window a badge names; `None` for a badge that is no window's (a row's own,
/// or the unbadged endpoint).
pub const fn window_of(badge: u32) -> Option<u32> {
    if badge & WINDOW_BADGE != 0 {
        Some(badge & !WINDOW_BADGE)
    } else {
        None
    }
}

/// What a `Lent<WindowBuffer>` names: the client's memory object, read-write,
/// mappable, [`CONTROL_BYTES`] of control and then the pixels. Lent (a copy of
/// the client's capability, mode DUP), not moved: a holder whose capability
/// moves away loses its mapping with it (`azos_ipc::memobj`), and the client
/// goes on drawing in the object. The copy needs `READ`, `WRITE` and `MAP`: the
/// compositor maps it writable, because it consumes the damage ring.
pub struct WindowBuffer;

/// What a `Lent<WindowRight>` names: a call right on the compositor's endpoint
/// bound to one window, lapsing when the window goes.
pub struct WindowRight;

/// Where a window sits and how big it is.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Shape {
    /// Top left on the screen, pixels (may be negative or past the screen: a
    /// window half out).
    pub x: i32,
    pub y: i32,
    /// Size in pixels, each `1..=`[`SIDE_MAX`].
    pub width: u32,
    pub height: u32,
}

impl Shape {
    /// Bytes of the pixel area.
    pub const fn pixel_bytes(&self) -> u64 {
        self.width as u64 * self.height as u64 * PIXEL_BYTES as u64
    }

    /// Pages a memory object needs for this window on a `page_bytes` granule
    /// (control area included).
    pub const fn pages(&self, page_bytes: usize) -> u64 {
        (CONTROL_BYTES as u64 + self.pixel_bytes()).div_ceil(page_bytes as u64)
    }

    /// Is it a window the compositor accepts when the object has `pages` pages
    /// of `page_bytes`? `BAD_ARGUMENT` for an empty or too large side, or a
    /// window that does not fit in [`MAX_PAGES`]; `BAD_ARGUMENT` also for an
    /// object too small for it.
    pub fn check(&self, pages: u64, page_bytes: usize) -> Result<(), u32> {
        let ok = |side: u32| side != 0 && side <= SIDE_MAX;
        if !ok(self.width) || !ok(self.height) || page_bytes == 0 {
            return Err(azos_devif::outcome::BAD_ARGUMENT);
        }
        let need = self.pages(page_bytes);
        if need > MAX_PAGES || pages < need || pages > MAX_PAGES {
            return Err(azos_devif::outcome::BAD_ARGUMENT);
        }
        Ok(())
    }
}

impl Wire for Shape {
    const WORDS: usize = 2;
    const CAPS: usize = 0;
    fn put(&self, w: &mut Writer<'_>) {
        w.word(self.x as u32 as u64 | (self.y as u32 as u64) << 32);
        w.word(self.width as u64 | (self.height as u64) << 32);
    }
    fn get(r: &mut Reader<'_>) -> Self {
        let a = r.word();
        let b = r.word();
        Shape { x: a as u32 as i32, y: (a >> 32) as u32 as i32, width: b as u32, height: (b >> 32) as u32 }
    }
}

/// [`Compositor::attach`]'s answer: the window's id and the right to take it
/// down, both or neither.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Attached {
    pub window: u32,
    pub right: Lent<WindowRight>,
}

impl Default for Attached {
    fn default() -> Self {
        Attached { window: 0, right: Lent::none() }
    }
}

impl Wire for Attached {
    const WORDS: usize = 1 + <Lent<WindowRight> as Wire>::WORDS;
    const CAPS: usize = <Lent<WindowRight> as Wire>::CAPS;
    fn put(&self, w: &mut Writer<'_>) {
        self.window.put(w);
        self.right.put(w);
    }
    fn get(r: &mut Reader<'_>) -> Self {
        Attached { window: u32::get(r), right: <Lent<WindowRight> as Wire>::get(r) }
    }
}

/// [`Compositor::status`]'s answer.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Status {
    /// Windows shown now.
    pub windows: u32,
    /// Secure Attention Key chords the compositor has seen (the trusted page's
    /// count).
    pub chords: u32,
    /// Frames presented to the screen, and the damage rectangles they carried.
    pub presents: u64,
    pub rects: u64,
}

impl Wire for Status {
    const WORDS: usize = 3;
    const CAPS: usize = 0;
    fn put(&self, w: &mut Writer<'_>) {
        w.word(self.windows as u64 | (self.chords as u64) << 32);
        w.word(self.presents);
        w.word(self.rects);
    }
    fn get(r: &mut Reader<'_>) -> Self {
        let a = r.word();
        Status { windows: a as u32, chords: (a >> 32) as u32, presents: r.word(), rects: r.word() }
    }
}

#[azos_interface(id = 0x434D_5053, level = 1)]
pub trait Compositor {
    /// Show the window whose memory object is `buffer` (a copy of the client's
    /// capability; the client keeps its own and its mapping) with `shape`. Answers the
    /// window's id and the call right bound to it. `BAD_ARGUMENT` for a shape the
    /// object cannot hold ([`Shape::check`]) or a handle that is no such object;
    /// `BUSY` when [`WINDOWS`] are shown, the compositor has no memory object
    /// left or no capability slot for the right; `NOT_READY` while the
    /// compositor has no display (nothing is shown, so nothing is attached).
    #[at_most_once]
    #[on_failure(restart)]
    fn attach(&mut self, buffer: Lent<WindowBuffer>, shape: Shape) -> Out<Attached>;
    /// Take the window down: it leaves the screen, its right is revoked and the
    /// object is let go. Only the right `attach` lent is accepted (`DENIED` for
    /// the plain call right or a right of a window that is gone).
    #[at_most_once]
    #[on_failure(restart)]
    fn detach(&mut self) -> Out<()>;
    /// The compositor's counters.
    #[idempotent]
    #[on_failure(degrade)]
    fn status(&self) -> Out<Status>;
}

// ── The damage ring ─────────────────────────────────────────────────────

/// The damage ring of a window whose object is mapped at `base`: the client
/// pushes the rectangles it changed (window pixels, one word each), the
/// compositor pops them. A full ring loses the rectangle and sets the overflow
/// word, which the compositor reads as "the whole window changed".
#[derive(Clone, Copy)]
pub struct WindowRing {
    pub base: usize,
}

/// Offset of the overflow word in the control page (after the ring's slots).
const OVERFLOW_OFF: usize = RING_HEADER_BYTES + DAMAGE_SLOTS as usize * 8;
const _: () = assert!(OVERFLOW_OFF + 4 <= CONTROL_BYTES);

impl WindowRing {
    fn ring(&self) -> SpscRing {
        SpscRing { base: self.base, cap: DAMAGE_SLOTS }
    }

    fn overflow_word(&self) -> &'static core::sync::atomic::AtomicU32 {
        // SAFETY: `base` is the start of a mapping at least `CONTROL_BYTES` long
        // and page aligned (the caller's contract), and the word is inside the
        // control page, aligned for its type; any bit pattern is a valid atomic.
        unsafe { &*((self.base + OVERFLOW_OFF) as *const core::sync::atomic::AtomicU32) }
    }

    /// Client: make an empty ring (the object is zero when created, so this is
    /// only needed to be explicit).
    pub fn init(&self) {
        self.ring().init();
        self.overflow_word().store(0, core::sync::atomic::Ordering::Relaxed);
    }

    /// Client: say `rect` of the window changed. `false` when the ring was full
    /// (the overflow word says so; the compositor repaints the whole window).
    pub fn post(&self, rect: Rect) -> bool {
        let word = rect_word(rect);
        match self.ring().try_push(word) {
            RingStep::Blocked => {
                let w = self.overflow_word();
                w.store(w.load(core::sync::atomic::Ordering::Relaxed).wrapping_add(1), core::sync::atomic::Ordering::Release);
                false
            }
            // The compositor polls; it never announces a sleep.
            _ => true,
        }
    }

    /// Compositor: the oldest rectangle posted, if any.
    pub fn take(&self) -> Option<Rect> {
        match self.ring().try_pop() {
            (RingStep::Blocked, _) => None,
            (_, w) => Some(rect_of(w)),
        }
    }

    /// Compositor: how many rectangles were lost for want of room, since the
    /// window began; wraps. A change since the last look means repaint it all.
    pub fn overflowed(&self) -> u32 {
        self.overflow_word().load(core::sync::atomic::Ordering::Acquire)
    }
}

/// A rectangle as the ring's one word (`Rect`'s wire form).
const fn rect_word(r: Rect) -> u64 {
    r.x as u64 | (r.y as u64) << 16 | (r.w as u64) << 32 | (r.h as u64) << 48
}

const fn rect_of(v: u64) -> Rect {
    Rect { x: v as u16, y: (v >> 16) as u16, w: (v >> 32) as u16, h: (v >> 48) as u16 }
}

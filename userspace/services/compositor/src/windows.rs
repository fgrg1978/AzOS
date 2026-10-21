// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The compositor's windows: the `Compositor` object over a [`Host`].
//!
//! Pure given a [`Host`] (mapping a client's memory object, deriving and revoking
//! the call right bound to a window, the console): `tests/host/compositor-tests`
//! pulls this file in with `#[path]` and drives it through the generated client
//! stub over a loopback, so the wire form a client sends and receives is the one
//! under test.
//!
//! **A window is its memory object.** `attach` maps the object, checks the shape
//! fits it ([`Shape::check`]), puts a layer on top of the scene (`azos_compose`)
//! and derives the call right bound to the window. The pixels are never copied:
//! [`Service::frame`] reads each window's rows from its mapping while it composes.
//! Drawing posts no call: the client pushes the rectangle it changed into the ring
//! in the object's first page, and [`Service::drain`] turns them into scene damage.
//! A ring that overflowed (the client drew faster than the frame timer looks)
//! means the whole window changed.
//!
//! **Authority.** The plain call right every client holds attaches. A window is
//! taken down only through its own right (`window_of(caller)`): another client's
//! detach, or a right the detach revoked, is `DENIED`.
//!
//! **Z order.** A new window goes on top, but the trusted overlays
//! ([`BANNER_LAYER`], [`PANEL_LAYER`]) stay above every window, so a client that
//! attaches while the banner is up cannot cover it.

use azos_compose::{Compositor as Scene, Format, Frame, Image, Layer, Output, Sink, Source, Sources};
use azos_compositor::{
    window_badge, window_of, Attached, Compositor, Shape, Status, WindowBuffer, WindowRing, CONTROL_BYTES, DAMAGE_SLOTS,
    PIXEL_BYTES, WINDOWS,
};
use azos_devif::outcome::{self, Out};
use azos_idl::Lent;

/// Layers of the scene: the windows and the two trusted overlays.
pub const LAYERS: usize = WINDOWS + 2;
/// The scene layer of the trusted-path banner.
pub const BANNER_LAYER: u32 = 0x7FFF_FF01;
/// The scene layer of the "why was this refused" panel.
pub const PANEL_LAYER: u32 = 0x7FFF_FF02;
/// Window ids count up to this, then wrap past 1: below the overlays' ids.
const WINDOW_ID_LIMIT: u32 = 0x4000_0000;
/// The colour behind every window, `0x00RRGGBB`.
pub const BACKGROUND: u32 = 0x0010_1820;

/// The rights of the call right bound to a window: the call right, nothing
/// more (not `DUP`: the holder cannot hand its window's right on).
pub const WINDOW_RIGHTS: azos_abi::cap::CapPerms = azos_abi::cap::CapPerms::WRITE;

/// A client's memory object, mapped here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Mapped {
    /// The capability the object arrived as.
    pub cap: u32,
    /// Where it is mapped.
    pub base: usize,
    /// Its size in pages.
    pub pages: u64,
}

/// What the compositor needs from its surroundings.
pub trait Host {
    /// Bytes of a page (the granule memory objects are counted in).
    fn page_bytes(&self) -> usize;
    /// Map the object `cap` read-write and say how big it is; `None` when it is
    /// not a memory object or cannot be mapped (the handle is given up).
    fn map_window(&mut self, cap: u32) -> Option<Mapped>;
    /// Unmap the object and give its handle up.
    fn unmap_window(&mut self, m: &Mapped);
    /// Give a handle up that was never mapped.
    fn close(&mut self, cap: u32);
    /// The first `bytes` bytes of the mapped object (control area included).
    fn pixels(&self, m: &Mapped, bytes: usize) -> &[u8];
    /// Derive the call right bound to the window whose badge is `badge` from the
    /// server's own endpoint: the handle, or `None` when no capability can be
    /// made.
    fn derive_right(&mut self, badge: u32) -> Option<u32>;
    /// Revoke what was lent through `right` and give the handle up.
    fn revoke(&mut self, right: u32);
    /// A line for the console.
    fn log(&mut self, line: &[u8]);
}

#[derive(Clone, Copy)]
struct Window {
    id: u32,
    shape: Shape,
    m: Mapped,
    right: u32,
    /// The ring's overflow count at the last look.
    overflow_seen: u32,
}

/// Counters the status call answers.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counters {
    pub presents: u64,
    pub rects: u64,
    pub chords: u32,
}

/// Rectangles one window may post that one [`Service::drain`] takes: the ring
/// holds [`DAMAGE_SLOTS`], and a client refilling it as fast as it is emptied
/// must not hold the lock for ever.
const DRAIN_MAX: u32 = DAMAGE_SLOTS * 2;

/// The Compositor object served over a [`Host`].
pub struct Service<H: Host> {
    pub host: H,
    /// The badge of the call being served; the loop sets it from the request
    /// (0 when the request carried none).
    pub caller: u32,
    /// The scene; `None` while the compositor has no display.
    scene: Option<Scene<LAYERS>>,
    slots: [Option<Window>; WINDOWS],
    next: u32,
    pub counters: Counters,
}

impl<H: Host> Service<H> {
    pub const fn new(host: H) -> Self {
        Self { host, caller: 0, scene: None, slots: [None; WINDOWS], next: 0, counters: Counters { presents: 0, rects: 0, chords: 0 } }
    }

    /// The screen is claimed and its surface made: compose for a `width` x
    /// `height` output. `false` for a size the scene cannot have. Windows
    /// attached before (none today: attach waits for this) stay.
    pub fn set_output(&mut self, width: u32, height: u32) -> bool {
        let Some(out) = Output::new(width, height, 1) else { return false };
        match &mut self.scene {
            Some(s) => s.set_output(out),
            None => self.scene = Some(Scene::new(out, BACKGROUND)),
        }
        true
    }

    /// The size of the output in pixels; `None` without a display.
    pub fn output(&self) -> Option<(u32, u32)> {
        self.scene.as_ref().map(|s| (s.output().width(), s.output().height()))
    }

    /// Windows shown now.
    pub fn windows(&self) -> u32 {
        self.slots.iter().flatten().count() as u32
    }

    /// Put a trusted overlay (`id` is [`BANNER_LAYER`] or [`PANEL_LAYER`]) on top
    /// of everything, `w` x `h` pixels at (`x`, `y`). Showing it again moves it.
    pub fn show_overlay(&mut self, id: u32, x: i32, y: i32, w: u32, h: u32) {
        let Some(s) = &mut self.scene else { return };
        let _ = s.remove(id);
        let _ = s.add(Layer { id, x, y, buf_w: w, buf_h: h, buffer_scale: 1, visible: true });
        // The banner stays above the panel, whichever was shown last.
        let _ = s.raise(BANNER_LAYER);
    }

    /// Take an overlay off the screen.
    pub fn hide_overlay(&mut self, id: u32) {
        if let Some(s) = &mut self.scene {
            let _ = s.remove(id);
        }
    }

    /// Turn what the clients posted into scene damage.
    pub fn drain(&mut self) {
        let Some(scene) = &mut self.scene else { return };
        for w in self.slots.iter_mut().flatten() {
            let ring = WindowRing { base: w.m.base };
            for _ in 0..DRAIN_MAX {
                let Some(r) = ring.take() else { break };
                // A rectangle past the window is the client's bug: the scene
                // cuts it to the buffer (nothing outside it is damaged).
                let _ = scene.damage_layer(w.id, Some(r));
            }
            let o = ring.overflowed();
            if o != w.overflow_seen {
                w.overflow_seen = o;
                let _ = scene.damage_layer(w.id, None);
            }
        }
    }

    /// Repaint the damage into `sink`. `extra` holds the pixels of the overlays.
    /// `None` without a display.
    pub fn frame<K: Sink + ?Sized>(&mut self, extra: &dyn Sources, sink: &mut K) -> Option<Frame> {
        let Service { host, scene, slots, .. } = self;
        let scene = scene.as_mut()?;
        let mut images: [Option<(u32, Image<'_>)>; WINDOWS] = [None; WINDOWS];
        for (i, w) in slots.iter().flatten().enumerate() {
            let bytes = CONTROL_BYTES + w.shape.pixel_bytes() as usize;
            let all = host.pixels(&w.m, bytes);
            if let Some(px) = all.get(CONTROL_BYTES..) {
                let stride = w.shape.width as usize * PIXEL_BYTES;
                images[i] = Image::new(px, w.shape.width, w.shape.height, stride, Format::Xrgb8888).map(|img| (w.id, img));
            }
        }
        Some(scene.frame(&Layers { windows: &images, extra }, sink))
    }

    /// Does the scene have damage waiting?
    pub fn has_damage(&self) -> bool {
        self.scene.as_ref().is_some_and(|s| !s.pending().is_empty())
    }

    fn free_slot(&self) -> Option<usize> {
        self.slots.iter().position(|s| s.is_none())
    }

    /// The next window id: unused, non-zero, below [`WINDOW_ID_LIMIT`].
    fn new_id(&mut self) -> u32 {
        loop {
            self.next = if self.next + 1 >= WINDOW_ID_LIMIT { 1 } else { self.next + 1 };
            if !self.slots.iter().flatten().any(|w| w.id == self.next) {
                return self.next;
            }
        }
    }

    /// "[compsrv] window 3 attached 120x80" / "[compsrv] window 3 detached".
    fn line(&mut self, what: &[u8], id: u32, size: Option<(u32, u32)>) {
        let mut line = [0u8; 96];
        let mut n = put(&mut line, 0, b"[compsrv] window ");
        let mut d = [0u8; 10];
        n = put(&mut line, n, dec(id, &mut d));
        n = put(&mut line, n, b" ");
        n = put(&mut line, n, what);
        if let Some((w, h)) = size {
            n = put(&mut line, n, b" ");
            n = put(&mut line, n, dec(w, &mut d));
            n = put(&mut line, n, b"x");
            n = put(&mut line, n, dec(h, &mut d));
        }
        n = put(&mut line, n, b"\n");
        self.host.log(&line[..n]);
    }
}

/// The scene's sources: the windows' mappings, then the overlays'.
struct Layers<'a> {
    windows: &'a [Option<(u32, Image<'a>)>; WINDOWS],
    extra: &'a dyn Sources,
}

impl Sources for Layers<'_> {
    fn source(&self, id: u32) -> Option<&dyn Source> {
        self.windows
            .iter()
            .flatten()
            .find(|(i, _)| *i == id)
            .map(|(_, img)| img as &dyn Source)
            .or_else(|| self.extra.source(id))
    }
}

impl<H: Host> Compositor for Service<H> {
    fn attach(&mut self, buffer: Lent<WindowBuffer>, shape: Shape) -> Out<Attached> {
        let Some(buffer) = buffer.get() else { return Out::err(outcome::BAD_ARGUMENT) };
        let cap = buffer.raw();
        if self.scene.is_none() {
            self.host.close(cap);
            return Out::err(outcome::NOT_READY);
        }
        let Some(slot) = self.free_slot() else {
            self.host.close(cap);
            return Out::err(outcome::BUSY);
        };
        let Some(m) = self.host.map_window(cap) else { return Out::err(outcome::BAD_ARGUMENT) };
        if let Err(code) = shape.check(m.pages, self.host.page_bytes()) {
            self.host.unmap_window(&m);
            return Out::err(code);
        }
        let id = self.new_id();
        let layer = Layer { id, x: shape.x, y: shape.y, buf_w: shape.width, buf_h: shape.height, buffer_scale: 1, visible: true };
        let added = self.scene.as_mut().is_some_and(|s| s.add(layer).is_ok());
        if !added {
            self.host.unmap_window(&m);
            return Out::err(outcome::BUSY);
        }
        let Some(right) = self.host.derive_right(window_badge(id)) else {
            if let Some(s) = &mut self.scene {
                let _ = s.remove(id);
            }
            self.host.unmap_window(&m);
            return Out::err(outcome::BUSY);
        };
        if let Some(s) = &mut self.scene {
            // The overlays stay above the new window.
            let _ = s.raise(PANEL_LAYER);
            let _ = s.raise(BANNER_LAYER);
        }
        let ring = WindowRing { base: m.base };
        self.slots[slot] = Some(Window { id, shape, m, right, overflow_seen: ring.overflowed() });
        self.line(b"attached", id, Some((shape.width, shape.height)));
        Out::ok(Attached { window: id, right: Lent::dup(right, WINDOW_RIGHTS.bits() as u16) })
    }

    fn detach(&mut self) -> Out<()> {
        let Some(id) = window_of(self.caller) else { return Out::err(outcome::DENIED) };
        let Some(slot) = self.slots.iter().position(|s| s.is_some_and(|w| w.id == id)) else {
            return Out::err(outcome::DENIED);
        };
        let Some(w) = self.slots[slot].take() else { return Out::err(outcome::DENIED) };
        if let Some(s) = &mut self.scene {
            let _ = s.remove(w.id);
        }
        // Everything lent through the right is gone, the object is let go.
        self.host.revoke(w.right);
        self.host.unmap_window(&w.m);
        self.line(b"detached", id, None);
        Out::ok(())
    }

    fn status(&self) -> Out<Status> {
        Out::ok(Status {
            windows: self.windows(),
            chords: self.counters.chords,
            presents: self.counters.presents,
            rects: self.counters.rects,
        })
    }
}

pub fn put(line: &mut [u8], at: usize, s: &[u8]) -> usize {
    let n = s.len().min(line.len().saturating_sub(at));
    line[at..at + n].copy_from_slice(&s[..n]);
    at + n
}

pub fn dec(mut v: u32, out: &mut [u8; 10]) -> &[u8] {
    let mut i = out.len();
    loop {
        i -= 1;
        out[i] = b'0' + (v % 10) as u8;
        v /= 10;
        if v == 0 {
            return &out[i..];
        }
    }
}

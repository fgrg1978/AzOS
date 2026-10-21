// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The scene: layers in z-order, the cursor plane, the damage they cause, and
//! the frame that repaints it.
//!
//! # Coordinates
//!
//! * A **layer** sits at (`x`, `y`) in LOGICAL pixels, which may be negative or
//!   past the screen (a window dragged half out). Its buffer is `buf_w` x
//!   `buf_h` pixels at `buffer_scale` buffer pixels per logical pixel, so its
//!   logical size is `buf_w / buffer_scale` x `buf_h / buffer_scale`.
//! * The **output** is `width` x `height` DEVICE pixels, the mode the scanout
//!   runs, at `scale` device pixels per logical pixel (HiDPI). A layer's origin
//!   and size in device pixels are the logical ones times `scale`, and its buffer
//!   is shown at `scale / buffer_scale` (see [`crate::blit`]): a 1x buffer on a
//!   2x output is doubled, a 2x buffer on a 2x output is copied, a 2x buffer on
//!   a 1x output is halved by taking every other pixel.
//! * Damage is always in device pixels, cut to the output, so it is what
//!   `Present::new(..).check(..)` accepts.
//! * The **cursor** is in device pixels: its image is authored for the scale
//!   in use, and a pointer is a position on the screen, not in a window.
//!
//! # Frame
//!
//! Every change to the scene records the pixels it changes. [`Compositor::frame`]
//! repaints exactly those: for each damage rectangle it draws the background (or,
//! when a layer that covers the rectangle exists, starts from the topmost
//! such layer), then every layer above it in z-order, then the cursor, so
//! the pixels of a frame depend on the scene alone and not on the order of the
//! rectangles. It hands the damage back for `Display::present`.

use crate::blit::{blend_argb, blit_scaled, dst_range, fill};
use crate::damage::Damage;
use crate::geom::{intersect, Span};
use crate::image::{Sink, Source};
use azos_devif::display::Rect;

/// Largest HiDPI factor, for the output and for a buffer.
pub const SCALE_MAX: u32 = 4;
/// Largest cursor image side, pixels.
pub const CURSOR_MAX: usize = 64;

/// What a scene change can refuse.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// No room for another layer.
    Full,
    /// A layer of that id exists.
    Exists,
    /// No layer of that id.
    NoLayer,
    /// A size, factor or hot spot out of range.
    Geometry,
}

/// The mode the scene is composed for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Output {
    width: u32,
    height: u32,
    scale: u32,
}

impl Output {
    /// `width` x `height` device pixels (each 1..=65535, what a `Rect` holds) at
    /// `scale` (1..=[`SCALE_MAX`]).
    pub const fn new(width: u32, height: u32, scale: u32) -> Option<Output> {
        if width == 0 || height == 0 || width > u16::MAX as u32 || height > u16::MAX as u32 || scale == 0 || scale > SCALE_MAX {
            return None;
        }
        Some(Output { width, height, scale })
    }
    pub const fn width(&self) -> u32 {
        self.width
    }
    pub const fn height(&self) -> u32 {
        self.height
    }
    pub const fn scale(&self) -> u32 {
        self.scale
    }
    const fn full(&self) -> Rect {
        Rect::full(self.width, self.height)
    }
}

/// One window's place in the scene. `id` is the server's own name for the layer
/// (the client it serves), not a Display surface id.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Layer {
    pub id: u32,
    /// Top left, logical pixels.
    pub x: i32,
    pub y: i32,
    /// The buffer's size in buffer pixels (each 1..=65535), a multiple of
    /// `buffer_scale`.
    pub buf_w: u32,
    pub buf_h: u32,
    /// Buffer pixels per logical pixel, 1..=[`SCALE_MAX`].
    pub buffer_scale: u32,
    pub visible: bool,
}

impl Layer {
    fn valid(&self) -> bool {
        let ok = |side: u32| side != 0 && side <= u16::MAX as u32 && side % self.buffer_scale == 0;
        self.buffer_scale != 0 && self.buffer_scale <= SCALE_MAX && ok(self.buf_w) && ok(self.buf_h)
    }

    /// Where it lands on the screen, device pixels.
    fn span(&self, scale: u32) -> Span {
        let s = scale as i64;
        let (x0, y0) = (self.x as i64 * s, self.y as i64 * s);
        Span {
            x0,
            y0,
            x1: x0 + (self.buf_w / self.buffer_scale) as i64 * s,
            y1: y0 + (self.buf_h / self.buffer_scale) as i64 * s,
        }
    }
}

/// The buffers behind the layers, by layer id.
pub trait Sources {
    fn source(&self, id: u32) -> Option<&dyn Source>;
}

/// What [`Compositor::frame`] did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Frame {
    /// What was repainted, to present.
    pub damage: Damage,
    /// Layers not drawn (no buffer for the id, or one smaller than the layer
    /// says) and rows the sink or a source could not give. Zero in a server that
    /// has attached everything it composes.
    pub missing: u32,
}

#[derive(Clone, Copy)]
struct Cursor {
    w: usize,
    h: usize,
    hot_x: i32,
    hot_y: i32,
    x: i32,
    y: i32,
    visible: bool,
    px: [u32; CURSOR_MAX * CURSOR_MAX],
}

impl Cursor {
    /// Its box on the screen, device pixels; empty when hidden or without an image.
    fn span(&self) -> Option<Span> {
        if !self.visible || self.w == 0 {
            return None;
        }
        let x0 = self.x as i64 - self.hot_x as i64;
        let y0 = self.y as i64 - self.hot_y as i64;
        Some(Span { x0, y0, x1: x0 + self.w as i64, y1: y0 + self.h as i64 })
    }
}

/// At most `N` layers, bottom to top, over one output.
pub struct Compositor<const N: usize> {
    out: Output,
    background: u32,
    layers: [Layer; N],
    len: usize,
    cursor: Cursor,
    damage: Damage,
}

impl<const N: usize> Compositor<N> {
    /// An empty scene of `background` (`0x00RRGGBB`) over `out`, all of it
    /// damaged.
    pub fn new(out: Output, background: u32) -> Compositor<N> {
        let mut damage = Damage::new();
        damage.add(out.full());
        Compositor {
            out,
            background,
            layers: [Layer::default(); N],
            len: 0,
            cursor: Cursor { w: 0, h: 0, hot_x: 0, hot_y: 0, x: 0, y: 0, visible: false, px: [0; CURSOR_MAX * CURSOR_MAX] },
            damage,
        }
    }

    pub fn output(&self) -> Output {
        self.out
    }

    /// The layers, bottom to top.
    pub fn layers(&self) -> &[Layer] {
        &self.layers[..self.len]
    }

    /// The damage waiting for the next frame.
    pub fn pending(&self) -> &Damage {
        &self.damage
    }

    /// Run on another mode (the connector's, after a claim): everything is
    /// repainted.
    pub fn set_output(&mut self, out: Output) {
        self.out = out;
        self.damage_all();
    }

    /// Repaint everything at the next frame (the screen was taken and given
    /// back, so its contents are not ours).
    pub fn damage_all(&mut self) {
        self.damage.clear();
        self.damage.add(self.out.full());
    }

    fn index(&self, id: u32) -> Result<usize, Error> {
        self.layers().iter().position(|l| l.id == id).ok_or(Error::NoLayer)
    }

    /// The on-screen part of layer `i`, if it shows anything.
    fn shown(&self, l: &Layer) -> Option<Rect> {
        if l.visible { l.span(self.out.scale).clip(self.out.width, self.out.height) } else { None }
    }

    fn damage_span(&mut self, s: Span) {
        if let Some(r) = s.clip(self.out.width, self.out.height) {
            self.damage.add(r);
        }
    }

    fn damage_layer_whole(&mut self, l: Layer) {
        if l.visible {
            self.damage_span(l.span(self.out.scale));
        }
    }

    /// Put a new layer on top of the others.
    pub fn add(&mut self, layer: Layer) -> Result<(), Error> {
        if !layer.valid() {
            return Err(Error::Geometry);
        }
        if self.index(layer.id).is_ok() {
            return Err(Error::Exists);
        }
        if self.len == N {
            return Err(Error::Full);
        }
        self.layers[self.len] = layer;
        self.len += 1;
        self.damage_layer_whole(layer);
        Ok(())
    }

    pub fn remove(&mut self, id: u32) -> Result<(), Error> {
        let i = self.index(id)?;
        let l = self.layers[i];
        self.layers.copy_within(i + 1..self.len, i);
        self.len -= 1;
        self.damage_layer_whole(l);
        Ok(())
    }

    /// Move the layer above all others.
    pub fn raise(&mut self, id: u32) -> Result<(), Error> {
        let i = self.index(id)?;
        if i + 1 == self.len {
            return Ok(());
        }
        let l = self.layers[i];
        self.layers.copy_within(i + 1..self.len, i);
        self.layers[self.len - 1] = l;
        self.damage_layer_whole(l);
        Ok(())
    }

    /// Move the layer below all others.
    pub fn lower(&mut self, id: u32) -> Result<(), Error> {
        let i = self.index(id)?;
        if i == 0 {
            return Ok(());
        }
        let l = self.layers[i];
        self.layers.copy_within(0..i, 1);
        self.layers[0] = l;
        self.damage_layer_whole(l);
        Ok(())
    }

    /// Move the layer's top left to (`x`, `y`), logical pixels.
    pub fn place(&mut self, id: u32, x: i32, y: i32) -> Result<(), Error> {
        let i = self.index(id)?;
        let old = self.layers[i];
        self.layers[i].x = x;
        self.layers[i].y = y;
        self.damage_layer_whole(old);
        self.damage_layer_whole(self.layers[i]);
        Ok(())
    }

    /// The client attached a buffer of another size or factor.
    pub fn set_buffer(&mut self, id: u32, buf_w: u32, buf_h: u32, buffer_scale: u32) -> Result<(), Error> {
        let i = self.index(id)?;
        let old = self.layers[i];
        let new = Layer { buf_w, buf_h, buffer_scale, ..old };
        if !new.valid() {
            return Err(Error::Geometry);
        }
        self.layers[i] = new;
        self.damage_layer_whole(old);
        self.damage_layer_whole(new);
        Ok(())
    }

    pub fn set_visible(&mut self, id: u32, visible: bool) -> Result<(), Error> {
        let i = self.index(id)?;
        if self.layers[i].visible != visible {
            self.layers[i].visible = visible;
            // Shown or hidden, it is the same rectangle that changes.
            self.damage_span(self.layers[i].span(self.out.scale));
        }
        Ok(())
    }

    /// The client drew in `rect` of its buffer (buffer pixels; `None` is all of
    /// it).
    pub fn damage_layer(&mut self, id: u32, rect: Option<Rect>) -> Result<(), Error> {
        let i = self.index(id)?;
        let l = self.layers[i];
        let whole = Rect::full(l.buf_w, l.buf_h);
        let Some(r) = intersect(rect.unwrap_or(whole), whole) else { return Ok(()) };
        let (num, den) = (self.out.scale, l.buffer_scale);
        let (dx0, dx1) = dst_range(r.x as u32, r.x as u32 + r.w as u32, num, den);
        let (dy0, dy1) = dst_range(r.y as u32, r.y as u32 + r.h as u32, num, den);
        if l.visible {
            let o = l.span(num);
            self.damage_span(Span { x0: o.x0 + dx0 as i64, y0: o.y0 + dy0 as i64, x1: o.x0 + dx1 as i64, y1: o.y0 + dy1 as i64 });
        }
        Ok(())
    }

    /// The cursor's image: `w` x `h` straight-alpha `0xAARRGGBB` pixels, the
    /// pixel (`hot_x`, `hot_y`) of which is the pointer's position.
    pub fn set_cursor_image(&mut self, w: usize, h: usize, hot_x: i32, hot_y: i32, px: &[u32]) -> Result<(), Error> {
        let fits = w != 0 && h != 0 && w <= CURSOR_MAX && h <= CURSOR_MAX && px.len() == w * h;
        if !fits || hot_x < 0 || hot_y < 0 || hot_x as usize >= w || hot_y as usize >= h {
            return Err(Error::Geometry);
        }
        self.damage_cursor();
        self.cursor.w = w;
        self.cursor.h = h;
        self.cursor.hot_x = hot_x;
        self.cursor.hot_y = hot_y;
        self.cursor.px[..px.len()].copy_from_slice(px);
        self.damage_cursor();
        Ok(())
    }

    /// The pointer is at (`x`, `y`), device pixels.
    pub fn move_cursor(&mut self, x: i32, y: i32) {
        self.damage_cursor();
        self.cursor.x = x;
        self.cursor.y = y;
        self.damage_cursor();
    }

    pub fn show_cursor(&mut self, visible: bool) {
        if self.cursor.visible != visible {
            self.damage_cursor();
            self.cursor.visible = visible;
            self.damage_cursor();
        }
    }

    fn damage_cursor(&mut self) {
        if let Some(s) = self.cursor.span() {
            self.damage_span(s);
        }
    }

    /// Repaint the damage into `sink` and hand it back for the present.
    pub fn frame<S: Sources + ?Sized, K: Sink + ?Sized>(&mut self, sources: &S, sink: &mut K) -> Frame {
        let damage = core::mem::take(&mut self.damage);
        let mut missing = 0;
        for &r in damage.rects() {
            self.paint(sources, sink, r, &mut missing);
        }
        Frame { damage, missing }
    }

    /// The buffer of `l` if it can be drawn.
    fn buffer<'a, S: Sources + ?Sized>(sources: &'a S, l: &Layer) -> Option<&'a dyn Source> {
        let src = sources.source(l.id)?;
        (src.width() >= l.buf_w && src.height() >= l.buf_h).then_some(src)
    }

    fn paint<S: Sources + ?Sized, K: Sink + ?Sized>(&self, sources: &S, sink: &mut K, clip: Rect, missing: &mut u32) {
        let scale = self.out.scale;
        // Layers are opaque: nothing below the topmost one that covers the
        // clip shows through.
        let covering = self.layers().iter().rposition(|l| {
            l.visible && l.span(scale).covers(clip) && Self::buffer(sources, l).is_some()
        });
        let first = match covering {
            Some(i) => i,
            None => {
                fill(sink, clip, self.background, missing);
                0
            }
        };
        let above = self.len - first;
        for k in 0..above {
            let i = if cfg!(feature = "canary-z-inverted") { self.len - 1 - k } else { first + k };
            let l = &self.layers[i];
            let Some(shown) = self.shown(l).and_then(|s| intersect(s, clip)) else { continue };
            let Some(src) = Self::buffer(sources, l) else {
                *missing += 1;
                continue;
            };
            let o = l.span(scale);
            blit_scaled(sink, shown, (o.x0, o.y0), src, (scale, l.buffer_scale), missing);
        }
        if let Some(s) = self.cursor.span() {
            if let Some(shown) = s.clip(self.out.width, self.out.height).and_then(|s| intersect(s, clip)) {
                let c = &self.cursor;
                blend_argb(sink, shown, (s.x0, s.y0), (c.w, &c.px[..c.w * c.h]), missing);
            }
        }
    }
}

// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The compositor's pixel engine.
//!
//! **Who links it.** The compositor server (`userspace/services/compositor`, a
//! ring-3 image): it claims a connector through the
//! Display interface (`azos_devif::display`), makes surfaces of bands to
//! compose into, and per frame calls [`Compositor::frame`] with a [`Sink`]
//! over the surface's bands and [`Sources`] over its clients' buffers, then
//! gives the returned [`Damage`] to `Display::present`. Nothing in this crate is
//! for any other caller.
//!
//! **What it is.**
//!
//! * [`Compositor`]: a z-ordered list of [`Layer`]s (a client's buffer, its
//!   place, its HiDPI factor), the [`Damage`] every change to the scene
//!   causes, and a software cursor plane drawn last.
//! * [`Damage`]: the union of what changed, held as at most
//!   `display::DAMAGE_MAX` rectangles so it is a `Present` as it stands.
//! * [`blit`]: fill and nearest-neighbour blit and scale from and into
//!   XRGB8888 and RGB565 (the formats of the Display interface it handles; the
//!   other two are refused by [`Format::from_display`]).
//! * [`Source`], [`Sink`]: pixels as rows, so a display surface made of bands
//!   and a plain slice ([`Image`], [`ImageMut`]) are the same thing to it.
//!
//! **What it is not.** No syscall, no allocation, no clock: pure over the
//! bytes it is given, which is why the golden images of the host tests are
//! its whole proof. Input routing (which layer a pointer is over), window
//! management policy and the cursor's shape set belong to the server.

#![no_std]
#![forbid(unsafe_code)]

pub mod blit;
mod compositor;
pub mod damage;
pub mod geom;
pub mod image;
pub mod pixel;

pub use compositor::{Compositor, Error, Frame, Layer, Output, Sources, CURSOR_MAX, SCALE_MAX};
pub use damage::Damage;
pub use image::{Image, ImageMut, Sink, Source};
pub use pixel::Format;

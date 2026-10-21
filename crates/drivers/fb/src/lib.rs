// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
#![no_std]
//! The generic framebuffer: ONE object (geometry, stride, pixel format) fed
//! by whichever source the platform has (QEMU `ramfb`, the Limine
//! framebuffer, a device-tree `simple-framebuffer`), mapped write-combining by
//! the kernel (`azos_mm::vmm::map_framebuffer`), then registered here.
//!
//! On top of it, behind features:
//!
//! - `console` ([`console`]): an 8x16 text console that mirrors the UART
//!   console, with scrolling and a dirty-rect flush (Kconfig `FB_CONSOLE`).
//!   A scroll redraws the screen from the text grid (write-only: reading a
//!   write-combining mapping back is slow), so a full screen scrolled one
//!   line per `kprintln!` costs one screen of glyph blits per line.
//! - `panic-screen` ([`panic`]): the panic report drawn straight onto the
//!   mapping, no lock and no allocation (Kconfig `FB_PANIC_SCREEN`).
//!
//! - [`edid`]: the parser of a display's EDID (its modes, preferred mode, size
//!   and name); [`blit`]: the rectangle copy of a `present`, a client's image
//!   onto the scanout; [`scanout`]: the framebuffer as the kernel-hosted
//!   `Display` interface's scanout (`azos_devif::Scanout`).
//!
//! # Handover
//!
//! A display server that owns the screen retires the text console
//! ([`retire_console`]): the console keeps taking the kernel's output into its
//! grid but draws nothing, and [`resume_console`] gives the screen back with
//! the whole grid owed to it. The panic screen is not retired: a panic always
//! owns the screen.
//!
//! # Flip
//!
//! A scanout the CPU draws into directly (ramfb, Limine, `simple-framebuffer`)
//! shows a pixel the moment it is written. A source that scans out a copy
//! (virtio-gpu: the host owns the displayed image) registers a flip hook
//! ([`set_flip`]); everything that draws ([`console`], [`panic`], and any later
//! compositor) then reports what it changed with [`flip`], and the hook commits
//! that rectangle to the display. The hook is `fn(Rect)`, callable from any
//! context, the panic screen included. It may wait for the display in task
//! context (bounded: a display that stops answering is given up on), but not
//! while [`panic_active`]: then a rectangle it cannot commit yet stays pending
//! with the source and goes out with the next flip. Only a display that is
//! dead, or that refuses the request, drops one.

pub mod blit;
pub mod edid;
pub mod font;
pub mod grid;
pub mod pixel;
pub mod scanout;

#[cfg(feature = "console")]
pub mod console;
#[cfg(feature = "panic-screen")]
pub mod panic;

use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicU64, AtomicUsize, Ordering};
use pixel::{PixelFormat, Surface};

/// A rectangle of the framebuffer, in pixels.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rect {
    pub x: u32,
    pub y: u32,
    pub w: u32,
    pub h: u32,
}

impl Rect {
    /// `self` cut to a `width` x `height` screen; `None` if nothing is left.
    pub fn clip(self, width: u32, height: u32) -> Option<Rect> {
        if self.x >= width || self.y >= height || self.w == 0 || self.h == 0 {
            return None;
        }
        Some(Rect { x: self.x, y: self.y, w: self.w.min(width - self.x), h: self.h.min(height - self.y) })
    }
}

/// The hook a source with its own copy of the screen provides: commit the
/// rectangle to the display ([`set_flip`]).
pub type FlipFn = fn(Rect);

/// What a source reports about its framebuffer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FbInfo {
    /// Physical base address.
    pub phys: u64,
    pub width: u32,
    pub height: u32,
    /// Bytes per row.
    pub stride: u32,
    pub format: PixelFormat,
}

impl FbInfo {
    /// Bytes from `phys` to the end of the last row.
    pub fn size(&self) -> usize {
        self.stride as usize * self.height as usize
    }

    /// Geometry a console can use: a valid format, a row that holds the
    /// pixels, and a non-empty screen.
    pub fn usable(&self) -> bool {
        self.format.valid()
            && self.width > 0
            && self.height > 0
            && (self.stride as usize) >= self.width as usize * self.format.bytes()
    }
}

// The registered framebuffer, readable without a lock from any context
// (the panic screen included). `BASE` is stored last, with Release; a reader
// that sees it non-zero sees every other field.
static BASE: AtomicUsize = AtomicUsize::new(0);
static PHYS: AtomicU64 = AtomicU64::new(0);
static GEOM: AtomicU64 = AtomicU64::new(0); // width << 32 | height
static STRIDE: AtomicU64 = AtomicU64::new(0);
static FMT: AtomicU64 = AtomicU64::new(0);
static PANICKED: AtomicBool = AtomicBool::new(false);
static RETIRED: AtomicBool = AtomicBool::new(false);
static REDRAW: AtomicBool = AtomicBool::new(false);
static FLIP: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());

fn fmt_pack(f: PixelFormat) -> u64 {
    u64::from_le_bytes([f.bpp, f.r_shift, f.r_size, f.g_shift, f.g_size, f.b_shift, f.b_size, 0])
}

fn fmt_unpack(v: u64) -> PixelFormat {
    let b = v.to_le_bytes();
    PixelFormat::new(b[0], b[1], b[2], b[3], b[4], b[5], b[6])
}

/// Publish the framebuffer, mapped at `va`. Once: a second call is refused.
/// Returns `false` for geometry [`FbInfo::usable`] rejects or a repeat.
pub fn register(info: FbInfo, va: usize) -> bool {
    if !info.usable() || va == 0 || BASE.load(Ordering::Acquire) != 0 {
        return false;
    }
    PHYS.store(info.phys, Ordering::Relaxed);
    GEOM.store((info.width as u64) << 32 | info.height as u64, Ordering::Relaxed);
    STRIDE.store(info.stride as u64, Ordering::Relaxed);
    FMT.store(fmt_pack(info.format), Ordering::Relaxed);
    BASE.store(va, Ordering::Release);
    true
}

/// Register the hook that commits a changed rectangle to the display, for a
/// source that scans out a copy of the framebuffer. Once, after [`register`]:
/// a second call or no registered framebuffer is refused.
pub fn set_flip(f: FlipFn) -> bool {
    if BASE.load(Ordering::Acquire) == 0 {
        return false;
    }
    FLIP.compare_exchange(core::ptr::null_mut(), f as *mut (), Ordering::AcqRel, Ordering::Relaxed).is_ok()
}

/// `r` was drawn: commit it to the display. A no-op on a scanout the CPU
/// draws into directly, and for a rectangle outside the screen. Lock-free
/// here; the hook decides what it may do in the caller's context.
pub fn flip(r: Rect) {
    let p = FLIP.load(Ordering::Acquire);
    if p.is_null() {
        return;
    }
    let g = GEOM.load(Ordering::Relaxed);
    if let Some(r) = r.clip((g >> 32) as u32, g as u32) {
        // SAFETY: only `set_flip` stores here, always a `FlipFn`.
        let f: FlipFn = unsafe { core::mem::transmute(p) };
        f(r);
    }
}

/// The whole screen was drawn.
pub fn flip_all() {
    let g = GEOM.load(Ordering::Relaxed);
    flip(Rect { x: 0, y: 0, w: (g >> 32) as u32, h: g as u32 });
}

/// The registered framebuffer's description and its virtual base.
pub fn info() -> Option<(FbInfo, usize)> {
    let va = BASE.load(Ordering::Acquire);
    if va == 0 {
        return None;
    }
    let g = GEOM.load(Ordering::Relaxed);
    Some((
        FbInfo {
            phys: PHYS.load(Ordering::Relaxed),
            width: (g >> 32) as u32,
            height: g as u32,
            stride: STRIDE.load(Ordering::Relaxed) as u32,
            format: fmt_unpack(FMT.load(Ordering::Relaxed)),
        },
        va,
    ))
}

/// The drawing surface over the registered framebuffer. Lock-free.
pub fn surface() -> Option<Surface> {
    let (i, va) = info()?;
    Some(Surface {
        base: va as *mut u8,
        width: i.width as usize,
        height: i.height as usize,
        stride: i.stride as usize,
        fmt: i.format,
    })
}

/// A display server owns the screen: the text console stops drawing (its
/// grid keeps taking the kernel's output, so the history is there when the
/// screen is handed back). `false` when it was retired already or there is no
/// framebuffer to retire it from.
pub fn retire_console() -> bool {
    BASE.load(Ordering::Acquire) != 0 && !RETIRED.swap(true, Ordering::AcqRel)
}

/// The display server let go of the screen: the text console draws again,
/// the whole grid, from the next line it prints. `false` when it was not
/// retired.
pub fn resume_console() -> bool {
    if !RETIRED.swap(false, Ordering::AcqRel) {
        return false;
    }
    REDRAW.store(true, Ordering::Release);
    true
}

/// Is the text console retired ([`retire_console`])?
pub fn console_retired() -> bool {
    RETIRED.load(Ordering::Acquire)
}

/// Does the console owe the screen a full redraw ([`resume_console`])? Taken
/// once, by whoever redraws.
#[cfg_attr(not(feature = "console"), allow(dead_code))]
pub(crate) fn take_redraw() -> bool {
    REDRAW.swap(false, Ordering::AcqRel)
}

/// A panic owns the screen: the console mirror stops drawing.
pub fn panic_active() -> bool {
    PANICKED.load(Ordering::Relaxed)
}

#[cfg(feature = "panic-screen")]
pub(crate) fn set_panic_active() {
    PANICKED.store(true, Ordering::Relaxed);
}

/// Text colours: light grey on black.
pub fn colours(f: &PixelFormat) -> (u32, u32) {
    (f.pack(0xD8, 0xD8, 0xD8), f.pack(0, 0, 0))
}

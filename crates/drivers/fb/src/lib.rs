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

pub mod font;
pub mod grid;
pub mod pixel;

#[cfg(feature = "console")]
pub mod console;
#[cfg(feature = "panic-screen")]
pub mod panic;

use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use pixel::{PixelFormat, Surface};

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

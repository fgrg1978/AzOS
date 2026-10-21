// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Framebuffer bring-up (Kconfig `FB_GENERIC`): find the machine's
//! framebuffer, map it write-combining, register it as THE framebuffer
//! (`azos_fb`), and start the console that mirrors the UART (`FB_CONSOLE`).
//!
//! Sources, first match wins: a virtio-gpu the hardware bus bound (its pixels
//! are guest RAM the driver allocated; the display is told what changed through
//! the flip hook), QEMU `ramfb` (the `ramfb` feature configures the device), the
//! framebuffer the Limine loader set up (x86_64), a device-tree
//! `simple-framebuffer` node (riscv64, aarch64).

use azos_arch_api::MemType;
use azos_drv_sys::{kerr, kprintln, kwarn};
use azos_fb::{pixel::PixelFormat, FbInfo};

/// A source whose pixels are guest RAM the kernel already maps, with a copy on
/// the display: where the CPU reaches them, and how the display is told.
struct Ram {
    va: usize,
    flip: azos_fb::FlipFn,
    hz: u32,
}

/// Where the framebuffer came from, and what it is.
struct Found {
    source: &'static str,
    info: FbInfo,
    ram: Option<Ram>,
}

/// A scanout the CPU draws into directly: the device shows what is written.
fn direct(source: &'static str, info: FbInfo) -> Option<Found> {
    Some(Found { source, info, ram: None })
}

/// The virtio-gpu flip hook: `azos_fb`'s rectangle to the driver's.
fn flip_virtio_gpu(r: azos_fb::Rect) {
    // A panic never waits for the display: the driver leaves a rectangle it
    // cannot commit yet pending.
    azos_drv_virtio::virtio::gpu::flip(r.x, r.y, r.w, r.h, !azos_fb::panic_active());
}

/// How the pixels are reached, for the boot line.
struct Reach(Option<MemType>, u32);

impl core::fmt::Display for Reach {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self.0 {
            None => write!(f, "RAM, direct map, flipped to the display at {} Hz", self.1),
            Some(m) => {
                write!(f, "mapped {:?}", m)?;
                if m != MemType::WC {
                    f.write_str(" (this hart has no write-combining encoding: plain PTE)")?;
                }
                Ok(())
            }
        }
    }
}

fn discover(dtb_ptr: usize) -> Option<Found> {
    let _ = dtb_ptr;
    if let Some(g) = azos_drv_virtio::virtio::gpu::framebuffer() {
        return Some(Found {
            source: "virtio-gpu",
            info: FbInfo { phys: g.phys, width: g.width, height: g.height, stride: g.stride, format: PixelFormat::XRGB8888 },
            ram: Some(Ram { va: g.va, flip: flip_virtio_gpu, hz: g.hz }),
        });
    }
    #[cfg(feature = "ramfb")]
    if let Some(info) = azos_display::qemu_display_init() {
        return direct("ramfb", info);
    }
    #[cfg(feature = "x86-limine")]
    if let Some(f) = crate::entry::x86_64::ext::limine::framebuffer() {
        return direct(
            "limine",
            FbInfo {
                phys: f.phys,
                width: f.width as u32,
                height: f.height as u32,
                stride: f.pitch as u32,
                format: PixelFormat::new(
                    f.bpp as u8, f.red_shift, f.red_size, f.green_shift, f.green_size, f.blue_shift, f.blue_size,
                ),
            },
        );
    }
    #[cfg(not(target_arch = "x86_64"))]
    if dtb_ptr != 0 {
        // SAFETY: the boot's own DTB pointer, as `read_cmdline` uses it.
        let node = unsafe {
            azos_dtb::dtb_simple_framebuffer(azos_mm::addr::phys_to_virt(dtb_ptr) as *const u8)
        };
        if let Some(n) = node {
            let Some(format) = PixelFormat::from_dt(&n.format) else {
                kwarn!("[FB] simple-framebuffer format {:?} is not drawn", core::str::from_utf8(&n.format).unwrap_or("?"));
                return None;
            };
            return direct("dt", FbInfo { phys: n.base, width: n.width, height: n.height, stride: n.stride, format });
        }
    }
    None
}

pub(crate) fn init(dtb_ptr: usize) {
    let Some(Found { source, info, ram }) = discover(dtb_ptr) else {
        kprintln!("[FB] no framebuffer");
        return;
    };
    if !info.usable() {
        kwarn!("[FB] {}: {}x{} stride {} {}bpp is not a usable framebuffer", source, info.width, info.height, info.stride, info.format.bpp);
        return;
    }
    let (va, reach) = match &ram {
        // Guest RAM is already in the kernel's direct map: a second, write-
        // combining mapping of it would alias those frames with another
        // attribute (undefined on aarch64).
        Some(r) => (r.va, Reach(None, r.hz)),
        None => {
            // Write-combining: the pixels are only written, and merged writes
            // are what a framebuffer wants. The leaf reports what the hart
            // could encode.
            match azos_mm::vmm::map_framebuffer(info.phys as usize, info.size(), MemType::WC) {
                Ok((va, mem)) => (va, Reach(Some(mem), 0)),
                Err(e) => {
                    kerr!("[FB] {}: mapping {:#x}+{:#x} failed: {:?}", source, info.phys, info.size(), e);
                    return;
                }
            }
        }
    };
    if !azos_fb::register(info, va) {
        kerr!("[FB] {}: framebuffer refused", source);
        return;
    }
    // The kernel-hosted `Display` interface draws on this framebuffer
    // (`azos_syscall::display`).
    if !azos_syscall::display::set_scanout(&azos_fb::scanout::SCANOUT) {
        kerr!("[FB] {}: scanout already registered", source);
    }
    // The display's EDID, where the source has one, gives the connector its
    // physical size and the modes the display offers.
    if ram.is_some() {
        if let Some((blob, len)) = azos_drv_virtio::virtio::gpu::edid() {
            if !azos_fb::scanout::publish_edid(&blob[..len]) {
                kwarn!("[FB] {}: the display's EDID is not one to trust", source);
            }
        }
    }
    // Before the console draws its first frame: every draw reports its rectangle.
    if let Some(r) = ram {
        if !azos_fb::set_flip(r.flip) {
            kerr!("[FB] {}: flip hook refused", source);
        }
    }
    kprintln!(
        "[FB] {} {}x{} stride {} {}bpp (r{}<<{} g{}<<{} b{}<<{}) at {:#x}, {}",
        source, info.width, info.height, info.stride, info.format.bpp,
        info.format.r_size, info.format.r_shift, info.format.g_size, info.format.g_shift,
        info.format.b_size, info.format.b_shift, info.phys, reach,
    );
    #[cfg(feature = "fb-console")]
    match azos_fb::console::init() {
        Some((cols, rows)) => {
            azos_drv_sys::uart::set_console_mirror(azos_fb::console::mirror);
            kprintln!("[FB] console {}x{} cells, mirroring the UART", cols, rows);
        }
        None => kwarn!("[FB] console: the screen holds no 8x16 cell"),
    }
    #[cfg(feature = "fb-panic-screen")]
    kprintln!("[FB] panic screen armed");
}

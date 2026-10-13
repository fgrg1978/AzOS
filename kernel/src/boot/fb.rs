// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Framebuffer bring-up (Kconfig `FB_GENERIC`): find the machine's
//! framebuffer, map it write-combining, register it as THE framebuffer
//! (`azos_fb`), and start the console that mirrors the UART (`FB_CONSOLE`).
//!
//! Sources, first match wins: QEMU `ramfb` (the `ramfb` feature configures
//! the device), the framebuffer the Limine loader set up (x86_64), a
//! device-tree `simple-framebuffer` node (riscv64, aarch64).

use azos_arch_api::MemType;
use azos_drv_sys::{kerr, kprintln, kwarn};
use azos_fb::{pixel::PixelFormat, FbInfo};

/// Where the framebuffer came from, and what it is.
fn discover(dtb_ptr: usize) -> Option<(&'static str, FbInfo)> {
    let _ = dtb_ptr;
    #[cfg(feature = "ramfb")]
    if let Some(info) = azos_display::qemu_display_init() {
        return Some(("ramfb", info));
    }
    #[cfg(feature = "x86-limine")]
    if let Some(f) = crate::entry::x86_64::limine::framebuffer() {
        return Some((
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
        ));
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
            return Some(("dt", FbInfo { phys: n.base, width: n.width, height: n.height, stride: n.stride, format }));
        }
    }
    None
}

pub(crate) fn init(dtb_ptr: usize) {
    let Some((source, info)) = discover(dtb_ptr) else {
        kprintln!("[FB] no framebuffer");
        return;
    };
    if !info.usable() {
        kwarn!("[FB] {}: {}x{} stride {} {}bpp is not a usable framebuffer", source, info.width, info.height, info.stride, info.format.bpp);
        return;
    }
    // Write-combining: the pixels are only written, and merged writes are what
    // a framebuffer wants. The leaf reports what the hart could encode.
    let mapped = azos_mm::vmm::map_framebuffer(info.phys as usize, info.size(), MemType::WC);
    let (va, mem) = match mapped {
        Ok(m) => m,
        Err(e) => {
            kerr!("[FB] {}: mapping {:#x}+{:#x} failed: {:?}", source, info.phys, info.size(), e);
            return;
        }
    };
    if !azos_fb::register(info, va) {
        kerr!("[FB] {}: framebuffer refused", source);
        return;
    }
    kprintln!(
        "[FB] {} {}x{} stride {} {}bpp (r{}<<{} g{}<<{} b{}<<{}) at {:#x}, mapped {:?}{}",
        source, info.width, info.height, info.stride, info.format.bpp,
        info.format.r_size, info.format.r_shift, info.format.g_size, info.format.g_shift,
        info.format.b_size, info.format.b_shift, info.phys, mem,
        if mem == MemType::WC { "" } else { " (this hart has no write-combining encoding: plain PTE)" },
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

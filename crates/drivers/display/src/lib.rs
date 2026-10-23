// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
#![no_std]
//! DC8200 + Innosilicon HDMI TX framebuffer driver — VF2 only.
//!
//! Feature-gated behind `hdmi` (opt-in, not part of the `vf2` feature
//! bundle — see `kernel/Cargo.toml`), which also enables this crate's own
//! `vf2` feature (see `Cargo.toml`) gating everything below — without it,
//! this crate compiles to an empty no-op, since plain `cargo build
//! --features <anything>` builds every workspace member regardless of
//! that feature, and this crate's real body needs VF2-only MMIO
//! constants that don't exist for other boards.
//!
//! Fixed 640x480@60 VESA mode, no EDID negotiation, single plane,
//! solid-color milestone — deliberate simplifications agreed before
//! writing any of this, given the real scope of a full display stack.
//!
//! # Status: never validated against real hardware
//!
//! QEMU has no model for either DC8200 or the HDMI TX — there is no
//! boot-test path for this driver the way every other fix this session
//! had. `hdmi::phy_init()` in particular writes placeholder PHY
//! calibration values that are NOT confirmed correct (see that
//! function's doc comment) — expect no signal on a real monitor until
//! that specific gap is closed with real hardware/TRM data.
//!
//! # Licensing note
//!
//! Register offsets/addresses here are hardware facts, confirmed against
//! Linux mainline driver source used as primary-source reference (same
//! footing as a datasheet) — not copied from that GPL-licensed code. This
//! module's structure, abstractions, and Rust code are written from
//! scratch for this (Apache-2.0 OR GPL-2.0-only) project.

#[cfg(feature = "vf2")]
mod dc8200;
#[cfg(feature = "vf2")]
mod hdmi;

#[cfg(feature = "vf2")]
mod imp {
    use azos_drv_base::platform::hw::{DC8200_MAIN_BASE, HDMI_TX_BASE};

    /// Kconfig-driven framebuffer dimensions (`config/arch/Kconfig.platform`,
    /// `HDMI_WIDTH`/`HDMI_HEIGHT`). Wiring these through is what makes
    /// this "configurable at compile time" — but changing them alone
    /// does NOT give you a different display mode: the CRTC/HDMI timing
    /// constants in `dc8200.rs`/`hdmi.rs` encode one specific real VESA
    /// mode (640x480@60), not a formula derived from width/height. The
    /// assert below makes that constraint a compile error instead of a
    /// silent mismatch, until this driver grows more than one supported
    /// mode.
    const FB_WIDTH: usize = azos_limits::HDMI_WIDTH;
    const FB_HEIGHT: usize = azos_limits::HDMI_HEIGHT;
    const _: () = assert!(
        FB_WIDTH == 640 && FB_HEIGHT == 480,
        "HDMI_WIDTH/HDMI_HEIGHT changed in Kconfig, but dc8200.rs/hdmi.rs \
         still hardcode the 640x480@60 VESA mode's timing constants — \
         update dc8200::MODE_640X480_60 and hdmi::set_timing() to a real, \
         valid mode matching the new resolution before changing this \
         Kconfig value."
    );

    /// Bytes per pixel — matches `dc8200::FB_CONFIG_FMT_UNCONFIRMED`'s
    /// assumption of a 32-bit format (XRGB8888-shaped, exact hardware
    /// enum value still unconfirmed — see that constant's doc comment).
    /// If the real format turns out to be 16-bit (e.g. RGB565), this and
    /// the pixel fill below need to change together.
    const BYTES_PER_PIXEL: usize = 4;
    const STRIDE: usize = FB_WIDTH * BYTES_PER_PIXEL;
    const FB_SIZE_BYTES: usize = FB_WIDTH * FB_HEIGHT * BYTES_PER_PIXEL;

    /// The framebuffer itself — DMA target for DC8200's plane 0. Static
    /// `.bss` allocation, same pattern as `IMG_BUF`/`ELF_BUF` elsewhere
    /// in this kernel (large buffer, no heap dependency, zero-initialized
    /// for free rather than costing image size).
    static mut FRAMEBUFFER: [u8; FB_SIZE_BYTES] = [0u8; FB_SIZE_BYTES];

    /// Fill the framebuffer with a fixed solid color (opaque mid-blue) —
    /// the actual "milestone 1" deliverable: prove pixels reach the
    /// screen at all, before attempting text/font rendering.
    fn fill_solid_color(fb: &mut [u8]) {
        // XRGB8888-shaped bytes, little-endian word: 0x00_40_80_FF (X, R, G, B).
        // Meaningless if the real pixel format turns out to be different —
        // see BYTES_PER_PIXEL's doc comment.
        let pixel: [u8; 4] = [0xFF, 0x80, 0x40, 0x00];
        for chunk in fb.chunks_exact_mut(4) {
            chunk.copy_from_slice(&pixel);
        }
    }

    /// Initialize the display pipeline: fill the framebuffer, bring up
    /// DC8200's timing/plane, bring up the HDMI TX. Call once, after
    /// FAT32/UART are already up (matches where other optional-hardware
    /// init calls sit in `kernel_main`) — never call twice, this driver
    /// keeps no re-entrancy state.
    pub fn display_init() {
        azos_drv_sys::kprintln!(
            "[DISPLAY] init: {}x{}, {} bytes framebuffer, format UNCONFIRMED (see docs)",
            FB_WIDTH, FB_HEIGHT, FB_SIZE_BYTES
        );

        let fb = unsafe { &mut *core::ptr::addr_of_mut!(FRAMEBUFFER) };
        fill_solid_color(fb);
        let fb_addr = fb.as_ptr() as usize;

        crate::dc8200::init(DC8200_MAIN_BASE, fb_addr, STRIDE as u32);
        crate::hdmi::init(HDMI_TX_BASE);

        azos_drv_sys::kprintln!(
            "[DISPLAY] init complete — PHY calibration is unconfirmed, real \
             hardware may still show no signal (see hdmi::phy_init doc comment)"
        );
    }
}

#[cfg(feature = "vf2")]
pub use imp::display_init;

/// No-op on any board other than VF2 — see the module doc comment.
#[cfg(not(feature = "vf2"))]
pub fn display_init() {}

// ---- QEMU ramfb path: a framebuffer source for `azos_fb` — see ramfb.rs ----
// Entirely separate from the vf2/`display_init()` path above: different
// feature (`qemu`, not `vf2`), different device. It allocates the pixel
// buffer and configures the device; the caller maps it write-combining and
// registers it with `azos_fb` (kernel/src/boot/fb.rs).

#[cfg(feature = "qemu")]
mod ramfb;

#[cfg(feature = "qemu")]
mod qemu_imp {
    use azos_fb::{pixel::PixelFormat, FbInfo};

    const FB_WIDTH: usize = 640;
    const FB_HEIGHT: usize = 480;
    const BYTES_PER_PIXEL: usize = 4;
    const STRIDE: usize = FB_WIDTH * BYTES_PER_PIXEL;
    const FB_SIZE_BYTES: usize = FB_WIDTH * FB_HEIGHT * BYTES_PER_PIXEL;
    const _: () = assert!(FB_SIZE_BYTES % 4096 == 0, "whole pages: the kernel remaps them as write-combining");

    /// The pixel buffer: page-aligned `.bss`, so every page is the buffer's
    /// alone when the kernel rewrites its mapping.
    #[repr(C, align(4096))]
    struct Buffer([u8; FB_SIZE_BYTES]);
    static mut FRAMEBUFFER: Buffer = Buffer([0u8; FB_SIZE_BYTES]);

    /// Hand the buffer to QEMU's `ramfb` device via `fw_cfg`. `None` without
    /// `-device ramfb` on the QEMU command line (`ramfb::init` says why).
    /// The device scans out guest physical memory, so it is handed the
    /// buffer's physical address: a `.bss` symbol's own address is not that
    /// once KASLR slid the image (`azos_mm::addr::virt_to_phys`).
    pub fn qemu_display_init() -> Option<FbInfo> {
        let va = core::ptr::addr_of_mut!(FRAMEBUFFER) as usize;
        // Gate canary `ramfb-va-canary`: the virtual address again.
        let pa = if cfg!(feature = "ramfb-va-canary") { va } else { azos_mm::addr::virt_to_phys(va) };
        if !crate::ramfb::init(pa, FB_WIDTH as u32, FB_HEIGHT as u32, STRIDE as u32) {
            return None;
        }
        Some(FbInfo {
            phys: pa as u64,
            width: FB_WIDTH as u32,
            height: FB_HEIGHT as u32,
            stride: STRIDE as u32,
            format: PixelFormat::XRGB8888,
        })
    }
}

#[cfg(feature = "qemu")]
pub use qemu_imp::qemu_display_init;

// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Verisilicon DC8200 display controller — minimal single-plane, fixed-mode
//! driver. VF2-only, feature-gated behind `hdmi` (see crate root).
//!
//! Register offsets and addresses below are hardware facts (MMIO
//! addresses, register layout, bit positions) confirmed against Linux
//! mainline device tree source and the Verisilicon DRM driver's own
//! register headers as primary-source reference — not copied from that
//! driver's code, which is GPL-licensed and structured very differently
//! (regmap abstraction, DRM CRTC/plane framework). This module is a
//! ground-up Rust implementation of just the sequence this crate needs:
//! program one fixed timing, point one plane at a framebuffer, enable.
//!
//! Never validated against real hardware — QEMU has no model for this
//! peripheral at all, so there is no QEMU boot-test path the way every
//! other driver fixed this session had. First real exercise happens in
//! the VF2 hardware bring-up plan's display phase.

/// DC8200 top-level/config block (chip ID, top IRQ ack/enable) — unused by
/// this minimal driver; kept for future chip-identity probing.
#[allow(dead_code)]
const TOP_BASE: usize = azos_drv_base::platform::hw::DC8200_TOP_BASE;

// ---- Main block register offsets (relative to DC8200_MAIN_BASE) ----
// Confirmed against the Verisilicon DC driver's own register headers
// (vs_crtc_regs.h, vs_primary_plane_regs.h) as hardware-fact reference.

/// Framebuffer physical base address, plane `n` (n=0 here — single plane).
const FB_ADDRESS: usize = 0x1400;
/// Framebuffer stride (bytes per row), plane `n`.
const FB_STRIDE: usize = 0x1408;
/// Horizontal size: bits [14:0] = visible pixels, bits [30:16] = htotal.
const DISP_HSIZE: usize = 0x1430;
/// Horizontal sync: bits [14:0] = start, [29:15] = end, bit 30 = enable.
const DISP_HSYNC: usize = 0x1438;
/// Vertical size: bits [14:0] = visible lines, bits [30:16] = vtotal.
const DISP_VSIZE: usize = 0x1440;
/// Vertical sync: bits [14:0] = start, [29:15] = end, bit 30 = enable.
const DISP_VSYNC: usize = 0x1448;
/// Framebuffer format/rotation/tiling config, plane `n`.
const FB_CONFIG: usize = 0x1518;
/// Framebuffer width/height (plane size, distinct from display timing).
const FB_SIZE: usize = 0x1810;
/// Extended plane config: bit 12 = commit, bit 13 = plane enable.
const FB_CONFIG_EX: usize = 0x1CC0;

const DISP_HSYNC_EN: u32 = 1 << 30;
const DISP_VSYNC_EN: u32 = 1 << 30;
const FB_CONFIG_EX_COMMIT: u32 = 1 << 12;
const FB_CONFIG_EX_FB_EN: u32 = 1 << 13;

/// Pixel format field (`FB_CONFIG` bits [31:26]) — UNCONFIRMED.
///
/// Every primary source checked (Linux mainline DC8200 driver files,
/// including the header that should hold this lookup table) either
/// doesn't define this enum inline or defines it in a file this session
/// couldn't locate. `0` is a deliberately conservative placeholder — NOT
/// a verified "this means XRGB8888" value. Do not treat this as correct;
/// it needs either the JH7110 TRM or register-probing on real hardware
/// (compare against what a known-working image looks like) to pin down.
/// Until fixed, the solid-color milestone may show wrong colors or a
/// corrupted image even if every other register in this module is right.
const FB_CONFIG_FMT_UNCONFIRMED: u32 = 0;

#[inline(always)]
fn reg_read(base: usize, off: usize) -> u32 {
    unsafe { core::ptr::read_volatile((base + off) as *const u32) }
}

#[inline(always)]
fn reg_write(base: usize, off: usize, val: u32) {
    unsafe { core::ptr::write_volatile((base + off) as *mut u32, val) }
}

/// One fixed display mode — VESA 640x480@60Hz, the most universally
/// supported fallback timing (no EDID negotiation, see the crate root
/// doc comment for why). Sourced from the public VESA timing standard,
/// not from any Linux driver — these numbers are the same on every
/// implementation of this exact standard mode, StarFive or otherwise.
struct Mode {
    hdisplay: u32,
    htotal: u32,
    hsync_start: u32,
    hsync_end: u32,
    vdisplay: u32,
    vtotal: u32,
    vsync_start: u32,
    vsync_end: u32,
}

const MODE_640X480_60: Mode = Mode {
    hdisplay: 640,
    htotal: 800,
    hsync_start: 656,
    hsync_end: 752,
    vdisplay: 480,
    vtotal: 525,
    vsync_start: 490,
    vsync_end: 492,
};

/// Program the fixed timing mode into the DC8200's single display output
/// (`n = 0`).
fn set_timing(main_base: usize, mode: &Mode) {
    reg_write(main_base, DISP_HSIZE,
        (mode.hdisplay & 0x7FFF) | ((mode.htotal & 0x7FFF) << 16));
    reg_write(main_base, DISP_VSIZE,
        (mode.vdisplay & 0x7FFF) | ((mode.vtotal & 0x7FFF) << 16));
    reg_write(main_base, DISP_HSYNC,
        (mode.hsync_start & 0x7FFF)
            | ((mode.hsync_end & 0x7FFF) << 15)
            | DISP_HSYNC_EN);
    reg_write(main_base, DISP_VSYNC,
        (mode.vsync_start & 0x7FFF)
            | ((mode.vsync_end & 0x7FFF) << 15)
            | DISP_VSYNC_EN);
}

/// Point plane 0 at `fb_addr` (physical address of a framebuffer already
/// filled with pixel data — see `crate::fill_solid_color`), with `stride`
/// bytes per row, and enable it.
fn set_plane(main_base: usize, fb_addr: usize, width: u32, height: u32, stride: u32) {
    reg_write(main_base, FB_ADDRESS, fb_addr as u32);
    reg_write(main_base, FB_STRIDE, stride);
    reg_write(main_base, FB_SIZE, (width & 0x7FFF) | ((height & 0x7FFF) << 16));
    reg_write(main_base, FB_CONFIG, FB_CONFIG_FMT_UNCONFIRMED << 26);
    reg_write(main_base, FB_CONFIG_EX, FB_CONFIG_EX_FB_EN | FB_CONFIG_EX_COMMIT);
}

/// Initialize DC8200 for the fixed 640x480@60 mode with plane 0 pointed at
/// `fb_addr`. Does not touch clock/reset (`DC8200_NOC_BASE`) — assumes
/// U-Boot/OpenSBI already left the display pipeline's clocks enabled at
/// boot, the same assumption every other driver in this kernel makes
/// about not owning JH7110's clock tree.
pub fn init(main_base: usize, fb_addr: usize, stride: u32) {
    azos_drv_sys::kprintln!("[DC8200] init: 640x480@60, fb={:#x} stride={}", fb_addr, stride);
    set_timing(main_base, &MODE_640X480_60);
    set_plane(main_base, fb_addr, MODE_640X480_60.hdisplay, MODE_640X480_60.vdisplay, stride);
    let _ = reg_read(main_base, DISP_HSIZE); // readback, not yet used for verification
}

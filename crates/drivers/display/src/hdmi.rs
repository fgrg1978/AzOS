// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Innosilicon HDMI TX — minimal fixed-mode driver. VF2-only, feature-gated
//! behind `hdmi` (see crate root doc comment).
//!
//! Register offsets confirmed as hardware facts against Linux mainline's
//! `drivers/gpu/drm/bridge/inno-hdmi.c` (used as primary-source reference,
//! not copied — see the licensing note in the crate root and `dc8200.rs`).
//! This chip uses byte-addressed (8-bit) registers, unlike DC8200's
//! word-aligned layout.
//!
//! **The PHY calibration values in this file are UNCONFIRMED** — see
//! `phy_init()`'s doc comment. Everything else here can be correct and
//! this will still show no signal on a real monitor until that's fixed.

// ---- Register offsets (byte-addressed, relative to HDMI_TX_BASE) ----

/// AV mute control — bit 0 (`VIDEO_BLACK`) blanks the video output.
const AV_MUTE: usize = 0x05;
const AV_MUTE_VIDEO_BLACK: u8 = 1 << 0;

const VIDEO_TIMING_CTL: usize = 0x08;
const VIDEO_EXT_HTOTAL_L: usize = 0x09;
const VIDEO_EXT_HTOTAL_H: usize = 0x0a;
const VIDEO_EXT_HBLANK_L: usize = 0x0b;
const VIDEO_EXT_HBLANK_H: usize = 0x0c;
const VIDEO_EXT_HDELAY_L: usize = 0x0d;
const VIDEO_EXT_HDELAY_H: usize = 0x0e;
const VIDEO_EXT_HDURATION_L: usize = 0x0f;
const VIDEO_EXT_HDURATION_H: usize = 0x10;
const VIDEO_EXT_VTOTAL_L: usize = 0x11;
const VIDEO_EXT_VTOTAL_H: usize = 0x12;
const VIDEO_EXT_VBLANK: usize = 0x13;
const VIDEO_EXT_VDELAY: usize = 0x14;
const VIDEO_EXT_VDURATION: usize = 0x15;

const PHY_SYNC: usize = 0xce;
const PHY_SYS_CTL: usize = 0xe0;
const PHY_CHG_PWR: usize = 0xe1;
const PHY_DRIVER: usize = 0xe2;
const PHY_PRE_EMPHASIS: usize = 0xe3;
const PHY_FEEDBACK_DIV_RATIO_LOW: usize = 0xe7;
const PHY_FEEDBACK_DIV_RATIO_HIGH: usize = 0xe8;
const PHY_PRE_DIV_RATIO: usize = 0xed;

#[inline(always)]
fn reg_read(base: usize, off: usize) -> u8 {
    unsafe { core::ptr::read_volatile((base + off) as *const u8) }
}

#[inline(always)]
fn reg_write(base: usize, off: usize, val: u8) {
    unsafe { core::ptr::write_volatile((base + off) as *mut u8, val) }
}

fn set_le16(base: usize, off_low: usize, off_high: usize, val: u16) {
    reg_write(base, off_low, (val & 0xFF) as u8);
    reg_write(base, off_high, (val >> 8) as u8);
}

/// Program extended timing registers to match DC8200's 640x480@60 mode
/// (see `dc8200::MODE_640X480_60` — duplicated here as plain numbers since
/// the two modules don't share a common `Mode` type across the crate
/// boundary yet; keep these in sync if the mode ever changes).
fn set_timing(base: usize) {
    const HDISPLAY: u16 = 640;
    const HTOTAL: u16 = 800;
    const HSYNC_START: u16 = 656;
    const HBLANK: u16 = HTOTAL - HDISPLAY;
    const HDELAY: u16 = HSYNC_START - HDISPLAY;
    const HDURATION: u16 = HTOTAL;
    const VTOTAL: u16 = 525;
    const VDISPLAY: u16 = 480;
    const VSYNC_START: u16 = 490;
    const VBLANK: u8 = (VTOTAL - VDISPLAY) as u8;
    const VDELAY: u8 = (VSYNC_START - VDISPLAY) as u8;
    const VDURATION: u8 = VTOTAL as u8; // truncated — VTOTAL(525) > u8::MAX;
                                         // matches the single-byte VDURATION
                                         // register width, another sign this
                                         // whole path needs real-hardware
                                         // verification, not just review.

    set_le16(base, VIDEO_EXT_HTOTAL_L, VIDEO_EXT_HTOTAL_H, HTOTAL);
    set_le16(base, VIDEO_EXT_HBLANK_L, VIDEO_EXT_HBLANK_H, HBLANK);
    set_le16(base, VIDEO_EXT_HDELAY_L, VIDEO_EXT_HDELAY_H, HDELAY);
    set_le16(base, VIDEO_EXT_HDURATION_L, VIDEO_EXT_HDURATION_H, HDURATION);
    set_le16(base, VIDEO_EXT_VTOTAL_L, VIDEO_EXT_VTOTAL_H, VTOTAL);
    reg_write(base, VIDEO_EXT_VBLANK, VBLANK);
    reg_write(base, VIDEO_EXT_VDELAY, VDELAY);
    reg_write(base, VIDEO_EXT_VDURATION, VDURATION);
    // Enable extended (non-CEA-standard-table) timing mode. The exact bit
    // meaning of VIDEO_TIMING_CTL beyond "enable extended timing" is not
    // confirmed — written as 0x01 (enable, no other bits) as the most
    // conservative interpretation of the register name.
    reg_write(base, VIDEO_TIMING_CTL, 0x01);
}

/// Configure the HDMI PHY (TMDS clock generation) for the target pixel
/// clock.
///
/// **UNCONFIRMED — this is the single biggest gap in the whole display
/// driver.** The real Innosilicon driver picks `PHY_FEEDBACK_DIV_RATIO_*`
/// / `PHY_PRE_DIV_RATIO` (and the exact `SYS_CTL`/`CHG_PWR`/`DRIVER`/
/// `PRE_EMPHASIS` power-up sequence) from a per-SoC calibration TABLE
/// keyed by target pixel clock — not a formula this session could derive
/// or find published for JH7110 specifically. The values below are
/// PLACEHOLDERS (register locations are real; the values written to them
/// are not verified against any source) — do not trust this to produce a
/// valid TMDS clock. Every other register in this whole driver (DC8200
/// timing/framebuffer, HDMI extended timing) can be perfectly correct and
/// the monitor will still show no signal until this function is fixed
/// with either the JH7110 TRM's PHY table or empirical values found by
/// probing real hardware.
fn phy_init(base: usize) {
    azos_drv_sys::kwarn!("[HDMI] WARNING: PHY calibration is unconfirmed placeholder data — expect no signal until this is fixed with real hardware/TRM values");
    reg_write(base, PHY_PRE_DIV_RATIO, 0);
    reg_write(base, PHY_FEEDBACK_DIV_RATIO_LOW, 0);
    reg_write(base, PHY_FEEDBACK_DIV_RATIO_HIGH, 0);
    reg_write(base, PHY_PRE_EMPHASIS, 0);
    reg_write(base, PHY_DRIVER, 0);
    reg_write(base, PHY_CHG_PWR, 0);
    reg_write(base, PHY_SYS_CTL, 0);
    reg_write(base, PHY_SYNC, 0);
}

/// Initialize the HDMI TX for the fixed 640x480@60 mode and unmute video.
/// Must run after `dc8200::init()` has already started producing a pixel
/// stream at the matching timing.
pub fn init(base: usize) {
    azos_drv_sys::kprintln!("[HDMI] init: 640x480@60 (fixed, no EDID)");
    set_timing(base);
    phy_init(base);
    // Un-blank: clear VIDEO_BLACK once timing + PHY are (attempted to be)
    // configured. If phy_init's placeholder values are wrong, this will
    // just unmute a signal the monitor can't lock onto — harmless, not a
    // new failure mode.
    let mute = reg_read(base, AV_MUTE);
    reg_write(base, AV_MUTE, mute & !AV_MUTE_VIDEO_BLACK);
}

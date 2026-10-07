// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
#![no_std]
//! Virtual camera driver — Phase 14.
//!
//! Provides a simulated 8×4 grayscale sensor with three pre-defined patterns
//! that map directly into the Phase-12/14 MLP input space.
//!
//! | Pattern        | dist_front | dist_right | MLP class    |
//! |----------------|------------|------------|--------------|
//! | CLEAR (0)      |   0.800    |   0.302    | go_forward   |
//! | RIGHT_WALL (1) |   0.600    |   0.102    | turn_right   |
//! | OBSTACLE (2)   |   0.102    |   0.502    | stop         |
//!
//! Feature extraction computes the arithmetic mean of two 8-pixel regions:
//! - **dist_front**: rows 1-2, cols 2-5 (center region, 8 pixels)
//! - **dist_right**: cols 6-7, all rows   (right  region, 8 pixels)
//!
//! With `--features rvv` each mean is computed via `dot_f32_rvv` (RVV 1.0
//! SIMD dot product with uniform weights [0.125; 8]); otherwise falls back
//! to `dot_f32_scalar`.

// ── Sensor geometry ───────────────────────────────────────────────────────────

/// Frame width in pixels.
pub const CAM_W: usize = 8;
/// Frame height in pixels.
pub const CAM_H: usize = 4;
/// Total pixels per frame (CAM_W × CAM_H).
pub const CAM_PIXELS: usize = CAM_W * CAM_H;

// ── Pattern IDs ───────────────────────────────────────────────────────────────

/// Clear path ahead → predicts go_forward.
pub const PATTERN_CLEAR: u8 = 0;
/// Right-side wall, path clear ahead → predicts turn_right.
pub const PATTERN_RIGHT_WALL: u8 = 1;
/// Obstacle directly ahead → predicts stop.
pub const PATTERN_OBSTACLE: u8 = 2;
/// Number of synthetic patterns.
pub const PATTERN_COUNT: u8 = 3;

// ── Pixel data for each pattern ───────────────────────────────────────────────
//
// Frame layout (8 wide × 4 tall, row-major):
//
//   col:   0    1    2    3    4    5    6    7
//  row 0 [  .    .    .    .    .    .    R    R ]
//  row 1 [  .    .    F    F    F    F    R    R ]
//  row 2 [  .    .    F    F    F    F    R    R ]
//  row 3 [  .    .    .    .    .    .    R    R ]
//
//  F = dist_front region (center, 8 px)
//  R = dist_right region (right,  8 px)
//  . = background (128, neutral gray)
//
// Pixel index = row * 8 + col:
//   Center pixels: 10,11,12,13,18,19,20,21
//   Right  pixels:  6, 7,14,15,22,23,30,31
//
// Pattern → center px → dist_front     right px → dist_right
//   CLEAR      204     →  204/255≈0.800    77    →  77/255≈0.302  → go_forward
//   RIGHT_WALL 153     →  153/255≈0.600    26    →  26/255≈0.102  → turn_right
//   OBSTACLE    26     →   26/255≈0.102   128    → 128/255≈0.502  → stop

static PIXELS_CLEAR: [u8; CAM_PIXELS] = [
    128, 128, 128, 128, 128, 128,  77,  77,   // row 0
    128, 128, 204, 204, 204, 204,  77,  77,   // row 1 — center F = 204
    128, 128, 204, 204, 204, 204,  77,  77,   // row 2 — center F = 204
    128, 128, 128, 128, 128, 128,  77,  77,   // row 3
];

static PIXELS_RIGHT_WALL: [u8; CAM_PIXELS] = [
    128, 128, 128, 128, 128, 128,  26,  26,   // row 0
    128, 128, 153, 153, 153, 153,  26,  26,   // row 1 — center F = 153
    128, 128, 153, 153, 153, 153,  26,  26,   // row 2 — center F = 153
    128, 128, 128, 128, 128, 128,  26,  26,   // row 3
];

static PIXELS_OBSTACLE: [u8; CAM_PIXELS] = [
    128, 128, 128, 128, 128, 128, 128, 128,   // row 0
    128, 128,  26,  26,  26,  26, 128, 128,   // row 1 — center F = 26
    128, 128,  26,  26,  26,  26, 128, 128,   // row 2 — center F = 26
    128, 128, 128, 128, 128, 128, 128, 128,   // row 3
];

// ── Public types ──────────────────────────────────────────────────────────────

/// A single 8×4 grayscale frame (row-major, u8 per pixel).
#[derive(Clone, Copy)]
pub struct Frame {
    pub pixels: [u8; CAM_PIXELS],
}

/// Scalar features extracted from a [`Frame`].
#[derive(Clone, Copy)]
pub struct CamFeatures {
    /// Mean of center region (rows 1-2, cols 2-5), normalised 0..1.
    pub dist_front: f32,
    /// Mean of right region (all rows, cols 6-7), normalised 0..1.
    pub dist_right: f32,
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Capture a frame from the virtual sensor.
///
/// Returns a [`Frame`] populated with the pre-defined pixel pattern for
/// `pattern`.  Values outside `0..PATTERN_COUNT` default to `PATTERN_CLEAR`.
pub fn cam_capture(pattern: u8) -> Frame {
    let src = match pattern {
        PATTERN_RIGHT_WALL => &PIXELS_RIGHT_WALL,
        PATTERN_OBSTACLE   => &PIXELS_OBSTACLE,
        _                  => &PIXELS_CLEAR,
    };
    let mut f = Frame { pixels: [0u8; CAM_PIXELS] };
    f.pixels.copy_from_slice(src);
    f
}

/// Extract features from a frame using dot product with uniform weights.
///
/// Pixels are first normalised from u8 (0..255) to f32 (0.0..1.0), then
/// the mean of each 8-pixel region is computed as a dot product with
/// UNIFORM_8 = [0.125; 8].  With `--features rvv`, uses `dot_f32_rvv`.
pub fn cam_extract_features(frame: &Frame) -> CamFeatures {
    // Uniform weights: 1/8 for each pixel → result = arithmetic mean.
    const UNIFORM_8: [f32; 8] = [0.125; 8];

    // Center region: rows 1-2, cols 2-5
    // Pixel indices: row1=[10,11,12,13], row2=[18,19,20,21]
    let center: [f32; 8] = [
        frame.pixels[10] as f32 / 255.0,
        frame.pixels[11] as f32 / 255.0,
        frame.pixels[12] as f32 / 255.0,
        frame.pixels[13] as f32 / 255.0,
        frame.pixels[18] as f32 / 255.0,
        frame.pixels[19] as f32 / 255.0,
        frame.pixels[20] as f32 / 255.0,
        frame.pixels[21] as f32 / 255.0,
    ];

    // Right region: cols 6-7, all rows
    // Pixel indices: row0=[6,7], row1=[14,15], row2=[22,23], row3=[30,31]
    let right: [f32; 8] = [
        frame.pixels[6]  as f32 / 255.0,
        frame.pixels[7]  as f32 / 255.0,
        frame.pixels[14] as f32 / 255.0,
        frame.pixels[15] as f32 / 255.0,
        frame.pixels[22] as f32 / 255.0,
        frame.pixels[23] as f32 / 255.0,
        frame.pixels[30] as f32 / 255.0,
        frame.pixels[31] as f32 / 255.0,
    ];

    let dist_front = dot(&center, &UNIFORM_8);
    let dist_right = dot(&right,  &UNIFORM_8);

    CamFeatures { dist_front, dist_right }
}

/// Print camera driver info (used by the shell `cam info` command).
pub fn cam_info() {
    azos_drv_sys::kprintln!("[CAM] ========================================");
    azos_drv_sys::kprintln!("[CAM]  Phase 14: Virtual Camera Driver");
    azos_drv_sys::kprintln!("[CAM]  Resolution: {}x{} pixels (grayscale u8)", CAM_W, CAM_H);
    azos_drv_sys::kprintln!("[CAM]  Patterns: CLEAR(0), RIGHT_WALL(1), OBSTACLE(2)");
    azos_drv_sys::kprintln!("[CAM]  dist_front region: rows 1-2, cols 2-5  (8 px)");
    azos_drv_sys::kprintln!("[CAM]  dist_right region: cols 6-7, all rows  (8 px)");
    #[cfg(feature = "rvv")]
    azos_drv_sys::kprintln!("[CAM]  Feature extractor: RVV 1.0 dot_f32_rvv");
    #[cfg(not(feature = "rvv"))]
    azos_drv_sys::kprintln!("[CAM]  Feature extractor: scalar dot_f32_scalar");
    azos_drv_sys::kprintln!("[CAM] ========================================");
}

// ── Internal helpers ──────────────────────────────────────────────────────────

#[inline(always)]
fn dot(a: &[f32], b: &[f32]) -> f32 {
    azos_arch::Vector::dot_f32(&azos_arch::ARCH, a, b)
}

// ── CSI / MIPI camera skeleton ───────────────────────────────────────────────
//
// Phase H: real camera support via CSI-2 (MIPI) interface.
// VisionFive 2 has an ISP + CSI-2 receiver at 0x19800000 (StarFive ISP).
// This is a skeleton — capture returns synthetic data until real HW bringup.

/// CSI-2 camera state.
pub struct CsiCamera {
    /// Base address of CSI-2 receiver.
    pub base:   usize,
    /// True if hardware was successfully probed.
    pub ready:  bool,
    /// Frame width configured.
    pub width:  u16,
    /// Frame height configured.
    pub height: u16,
}

/// CSI-2 register offsets (StarFive ISP / MIPI-CSI2 RX).
#[allow(dead_code)]
pub mod csi_regs {
    pub const CSI2_CTRL:      usize = 0x000;
    pub const CSI2_STATUS:    usize = 0x004;
    pub const CSI2_DPHY_CFG:  usize = 0x008;
    pub const CSI2_DATA_ID:   usize = 0x00C;
    pub const CSI2_ERR_STATUS:usize = 0x010;
    pub const CSI2_LINE_CNT:  usize = 0x014;
    pub const CSI2_FRAME_CNT: usize = 0x018;
}

/// VisionFive 2 CSI-2 receiver base (JH7110 ISP subsystem).
pub const VF2_CSI_BASE: usize = 0x1980_0000;

impl CsiCamera {
    /// Create an uninitialized CSI camera handle.
    pub const fn new() -> Self {
        CsiCamera { base: 0, ready: false, width: 0, height: 0 }
    }

    /// Probe and initialize the CSI-2 receiver.
    ///
    /// Returns `true` if hardware was detected. Currently always returns
    /// `false` (skeleton) — real init requires D-PHY lane config + ISP setup.
    pub fn init(&mut self, base: usize, w: u16, h: u16) -> bool {
        self.base   = base;
        self.width  = w;
        self.height = h;
        // TODO: D-PHY power-on, lane configuration, ISP pipeline setup.
        // For now, mark as not ready.
        azos_drv_sys::kprintln!("[CSI] Camera @ {:#x} {}x{} — skeleton (not ready)",
            base, w, h);
        self.ready = false;
        false
    }

    /// Capture a frame from the CSI camera.
    ///
    /// Returns `None` until real hardware is initialized.
    /// When ready, this would DMA a frame into the provided buffer.
    pub fn capture(&self, _buf: &mut [u8]) -> Option<usize> {
        if !self.ready { return None; }
        // TODO: Trigger ISP capture, wait for frame-done IRQ, copy from DMA buffer.
        None
    }

    /// Print CSI camera status.
    pub fn info(&self) {
        azos_drv_sys::kprintln!("[CSI] Camera skeleton:");
        azos_drv_sys::kprintln!("[CSI]   Base: {:#x}", self.base);
        azos_drv_sys::kprintln!("[CSI]   Resolution: {}x{}", self.width, self.height);
        azos_drv_sys::kprintln!("[CSI]   Status: {}",
            if self.ready { "ready" } else { "not initialized (skeleton)" });
    }
}

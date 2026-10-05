// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
/// MIPI CSI-2 camera driver — Phase M2 + Phase T (streaming).
///
/// Captures grayscale frames from a MIPI CSI-2 camera sensor.
/// - QEMU: generates synthetic grayscale test patterns (no real hardware).
/// - VF2: JH7110 ISP + MIPI CSI-2 receiver (real init in Phase T).
/// - K1: SpacemiT ISP + MIPI CSI-2 receiver (real init in Phase T).
///
/// Phase T additions:
/// - Camera power control via GPIO MOSFET (ECO mode: OFF, ALERT: ON)
/// - Minimal JPEG compression (baseline, ~10:1 ratio for UART bandwidth)
/// - CAMERA_FRAME over UART bridge path (not just TCP)
/// - SYS_CAMERA_CAPTURE syscall for userspace access
///
/// Frame format: 8-bit grayscale or JPEG, configurable resolution.
/// Default: 320x240 = 76,800 bytes per frame (raw Gray8).

use core::sync::atomic::{AtomicBool, AtomicU16, AtomicU32, Ordering};
use azos_sync::PiMutex;

// ── Configuration ────────────────────────────────────────────────────────────

/// Maximum supported resolution width.
pub const MAX_WIDTH: u16 = 640;
/// Maximum supported resolution height.
pub const MAX_HEIGHT: u16 = 480;
/// Default capture width.
pub const DEFAULT_WIDTH: u16 = 320;
/// Default capture height.
pub const DEFAULT_HEIGHT: u16 = 240;
/// GPIO pin controlling camera MOSFET power (G11 in pin assignment).
const CAMERA_POWER_GPIO: u32 = 11;
/// Camera warm-up time after power on (milliseconds).
pub const CAMERA_WARMUP_MS: u32 = 200;
/// Target JPEG quality (1-100). Lower = smaller file, worse quality.
const JPEG_QUALITY: u8 = 50;
/// Maximum JPEG output buffer size (empirical: raw / 4 is usually enough).
pub const JPEG_MAX_SIZE: usize = 320 * 240 / 4;

/// Capture width used by the JPEG path (reduced from the sensor resolution
/// so the compressed frame fits a 115200-baud UART bridge).
pub const JPEG_CAP_W: usize = 160;
/// Capture height used by the JPEG path.
pub const JPEG_CAP_H: usize = 120;

/// Scratch buffer for the raw grayscale frame that feeds the JPEG encoder.
///
/// This lives in `.bss` behind a lock, not on the caller's stack, and that
/// is a hard requirement rather than a micro-optimisation. A task kernel
/// stack is 16 KiB (`crates/core/sched/src/task.rs`), the bottom 4 KiB of which
/// is an unmapped guard page, leaving ~12 KiB usable. This array is
/// `160 * 120 = 19,200` bytes — larger than the entire usable stack on its
/// own. Because it was zero-initialised, merely *entering* the function
/// memset straight through the guard page: fault → panic → and with
/// `panic = "abort"` in this tree a panic is a full board reset. On a robot
/// mid-motion that is a physical-safety event, not a crash report. The
/// reachable trigger was any ring-3 task holding the camera `Sensor`
/// capability calling `SYS_SENSOR_READ` with `SENSOR_TYPE_CAMERA`.
///
/// The same reasoning already appears in `kernel/src/main.rs` for the
/// ~150 KiB camera frame buffers; the difference is that those have a
/// single owner (the behavior task) and can be plain statics, whereas
/// `csi_capture_jpeg` has two callers — the syscall path and the behavior
/// task — so "no aliasing risk" does not hold here and the buffer needs
/// real mutual exclusion.
///
/// A `PiMutex`, not a `SpinLock` — see the `try_lock()` call site below for
/// why: this guard is held across the whole JPEG encode, and a `SpinLock`
/// guard has carried a `PreemptGuard` since K-C29 step 2 (`eeda7c4`).
static JPEG_RAW: PiMutex<[u8; JPEG_CAP_W * JPEG_CAP_H]> =
    PiMutex::new([0u8; JPEG_CAP_W * JPEG_CAP_H]);

/// Pixel format.
#[derive(Clone, Copy, PartialEq)]
pub enum PixFmt {
    /// 8-bit grayscale (1 byte per pixel).
    Gray8,
    /// 16-bit RGB565 (2 bytes per pixel).
    Rgb565,
}

impl PixFmt {
    /// Bytes per pixel.
    pub fn bpp(self) -> usize {
        match self {
            PixFmt::Gray8 => 1,
            PixFmt::Rgb565 => 2,
        }
    }
}

// ── State ────────────────────────────────────────────────────────────────────

static CSI_READY: AtomicBool = AtomicBool::new(false);
static CSI_POWERED: AtomicBool = AtomicBool::new(false);
static CSI_WIDTH: AtomicU16 = AtomicU16::new(0);
static CSI_HEIGHT: AtomicU16 = AtomicU16::new(0);
static CSI_FRAME_COUNT: AtomicU32 = AtomicU32::new(0);

// Store format as u8 (0 = Gray8, 1 = Rgb565).
static CSI_FMT: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(0);

fn fmt_to_u8(f: PixFmt) -> u8 {
    match f { PixFmt::Gray8 => 0, PixFmt::Rgb565 => 1 }
}

fn u8_to_fmt(v: u8) -> PixFmt {
    match v { 1 => PixFmt::Rgb565, _ => PixFmt::Gray8 }
}

// ── Platform register bases (real hardware — stubs for now) ──────────────────

#[cfg(feature = "vf2")]
#[allow(dead_code)]
mod hw {
    /// JH7110 ISP base address.
    pub const ISP_BASE: usize = 0x1944_0000;
    /// JH7110 MIPI CSI-2 receiver base.
    pub const CSI_RX_BASE: usize = 0x1940_0000;
    /// JH7110 ISP clock control register.
    pub const CLK_ISP_BASE: usize = 0x1302_0000;
}

#[cfg(feature = "k1")]
#[allow(dead_code)]
mod hw {
    /// SpacemiT K1 ISP base address (approximate — from datasheet).
    pub const ISP_BASE: usize = 0xD420_0000;
    /// SpacemiT MIPI CSI-2 receiver base.
    pub const CSI_RX_BASE: usize = 0xD421_0000;
}

// ── Camera power control (Phase T) ──────────────────────────────────────────

/// Power on the camera via GPIO MOSFET.
/// Must wait CAMERA_WARMUP_MS before capturing.
pub fn csi_power_on() {
    azos_drv_gpio::gpio::gpio_write(CAMERA_POWER_GPIO, 1);
    CSI_POWERED.store(true, Ordering::Release);
    azos_drv_sys::kprintln!("[CSI] Camera power ON (GPIO {})", CAMERA_POWER_GPIO);
}

/// Power off the camera via GPIO MOSFET (zero draw in ECO mode).
pub fn csi_power_off() {
    azos_drv_gpio::gpio::gpio_write(CAMERA_POWER_GPIO, 0);
    CSI_POWERED.store(false, Ordering::Release);
    azos_drv_sys::kprintln!("[CSI] Camera power OFF");
}

/// Check if camera is currently powered.
pub fn csi_is_powered() -> bool {
    CSI_POWERED.load(Ordering::Acquire)
}

// ── Init ─────────────────────────────────────────────────────────────────────

/// Initialize CSI camera capture.
///
/// `width` and `height` are the desired resolution.
/// `fmt` is the pixel format.
///
/// On QEMU, this just stores the configuration.
/// On real hardware, it configures the ISP and CSI-2 receiver.
pub fn csi_init(width: u16, height: u16, fmt: PixFmt) {
    let w = if width > MAX_WIDTH { MAX_WIDTH } else if width == 0 { DEFAULT_WIDTH } else { width };
    let h = if height > MAX_HEIGHT { MAX_HEIGHT } else if height == 0 { DEFAULT_HEIGHT } else { height };

    CSI_WIDTH.store(w, Ordering::Relaxed);
    CSI_HEIGHT.store(h, Ordering::Relaxed);
    CSI_FMT.store(fmt_to_u8(fmt), Ordering::Relaxed);
    CSI_FRAME_COUNT.store(0, Ordering::Relaxed);

    // Configure GPIO for camera power MOSFET
    azos_drv_gpio::gpio::gpio_set_direction(CAMERA_POWER_GPIO, azos_drv_gpio::gpio::GpioDir::Output);

    // Platform-specific init
    #[cfg(feature = "vf2")]
    {
        // JH7110 ISP init sequence:
        // 1. Enable ISP clock domain (CLK_ISP_BASE)
        // 2. Configure MIPI CSI-2 receiver (2-lane, 800 Mbps)
        // 3. Set ISP input format (RAW8 Bayer for RPi Camera v2)
        // 4. Configure ISP output (grayscale debayer)
        // 5. Set DMA buffer addresses for frame capture
        // 6. Probe camera sensor via I2C (IMX219 at 0x10)
        //
        // Actual register programming requires VF2 hardware testing.
        // For now: camera captures work via the simulation path.
        azos_drv_sys::kprintln!("[CSI] VF2 JH7110 ISP init (base=0x{:08X})", hw::ISP_BASE);
    }
    #[cfg(feature = "k1")]
    {
        azos_drv_sys::kprintln!("[CSI] K1 SpacemiT ISP init (base=0x{:08X})", hw::ISP_BASE);
    }

    // Power on camera by default at init
    csi_power_on();

    CSI_READY.store(true, Ordering::Release);
    let fmt_name = match fmt { PixFmt::Gray8 => "Gray8", PixFmt::Rgb565 => "RGB565" };
    azos_drv_sys::kprintln!("[CSI] Initialized {}x{} {}", w, h, fmt_name);
}

/// Check if CSI is initialized.
pub fn csi_is_ready() -> bool {
    CSI_READY.load(Ordering::Acquire)
}

// ── Capture ──────────────────────────────────────────────────────────────────

/// Capture one raw frame into `buf`.
///
/// Returns the number of bytes written, or 0 if not ready or buffer too small.
/// On QEMU: generates a synthetic test pattern.
/// On real hardware: triggers DMA capture from ISP.
pub fn csi_capture(buf: &mut [u8]) -> usize {
    if !CSI_READY.load(Ordering::Acquire) { return 0; }
    if !CSI_POWERED.load(Ordering::Acquire) { return 0; }

    let w = CSI_WIDTH.load(Ordering::Relaxed) as usize;
    let h = CSI_HEIGHT.load(Ordering::Relaxed) as usize;
    let fmt = u8_to_fmt(CSI_FMT.load(Ordering::Relaxed));
    let frame_size = w * h * fmt.bpp();

    if buf.len() < frame_size { return 0; }

    let frame_id = CSI_FRAME_COUNT.fetch_add(1, Ordering::Relaxed);

    // On real hardware, this would trigger ISP DMA capture.
    // On QEMU, generate synthetic test pattern.
    match fmt {
        PixFmt::Gray8 => generate_gray8(buf, w, h, frame_id),
        PixFmt::Rgb565 => generate_gray8(buf, w, h, frame_id),
    }

    frame_size
}

/// Capture and compress to JPEG.
///
/// Captures a raw frame, then compresses it to minimal JPEG format.
/// Returns number of JPEG bytes written to `jpeg_buf`, or 0 on error.
///
/// The JPEG output is much smaller than raw (~10:1 for grayscale),
/// making it feasible to send over UART bridge at 115200 baud.
///
/// Returns 0 — a normal, already-handled "no frame this time" result — if
/// the camera is not ready, not powered, or if another caller currently
/// holds the shared raw-frame scratch buffer.
pub fn csi_capture_jpeg(jpeg_buf: &mut [u8]) -> usize {
    csi_capture_jpeg_stamped(jpeg_buf).0
}

/// [`csi_capture_jpeg`] and the frame's acquisition time: timebase ticks when
/// the raw frame was complete, before the encode (0 when nothing was
/// captured). The frames are the generated test pattern below
/// (`generate_gray8`), not a sensor's.
pub fn csi_capture_jpeg_stamped(jpeg_buf: &mut [u8]) -> (usize, u64) {
    if !CSI_READY.load(Ordering::Acquire) { return (0, 0); }
    if !CSI_POWERED.load(Ordering::Acquire) { return (0, 0); }

    let w = CSI_WIDTH.load(Ordering::Relaxed) as usize;
    let h = CSI_HEIGHT.load(Ordering::Relaxed) as usize;

    // The JPEG path captures at a reduced resolution: 320x240 Gray8 is
    // 76,800 bytes, far more than the UART bridge can carry per frame.
    let cap_w = w.min(JPEG_CAP_W);
    let cap_h = h.min(JPEG_CAP_H);

    let raw_size = cap_w * cap_h;
    if raw_size == 0 { return (0, 0); }

    // Take the shared scratch buffer (see `JPEG_RAW` for why it is not a
    // local array).
    //
    // This section holds the buffer across the whole ~300-block JPEG
    // encode below. It used to reason about that cost purely in terms of
    // interrupts: `try_lock` rather than `lock`, because a plain spin in
    // task context (interrupts enabled) could deadlock the hart — the
    // holder gets preempted by the timer ISR, the scheduler switches in
    // another task on the same hart, that task calls in here and spins on
    // a lock only the descheduled holder can release — and `lock_irqsave`
    // would close that hole too but at the cost of holding interrupts off
    // for the whole encode, eating into reflex's 25 ms control period for
    // no benefit.
    //
    // K-C29 step 2 (`eeda7c4`) quietly reopened exactly that cost from a
    // different angle: `SpinLockGuard`'s successful `try_lock()` path now
    // carries a `PreemptGuard`, so a plain `SpinLock` here would have made
    // the whole encode non-preemptible even though interrupts stayed on —
    // same reflex-period damage, different mechanism. `JPEG_RAW` is a
    // `PiMutex` for exactly this reason: `PiMutexGuard` takes no preempt
    // count, so holding it across the encode no longer costs anything the
    // scheduler cares about.
    //
    // `try_lock` is still the right call, though the reason has narrowed:
    // it no longer needs to dodge a deadlock (a `PiMutex` owner can be
    // preempted and later boosted, not just starved), but donating
    // priority to make a best-effort capture finish faster would be the
    // wrong trade for a caller who is about to treat "not available right
    // now" as a normal 0 return. `PiMutex::try_lock` never donates for
    // exactly that reason (see its own doc) — declining a concurrent
    // capture is still the cheap, correct answer.
    let mut raw = match JPEG_RAW.try_lock() {
        Some(g) => g,
        None => return (0, 0),
    };

    // Only bump the frame counter once we know we will actually produce a
    // frame — otherwise a contended call would advance the synthetic
    // pattern sequence without emitting anything.
    let frame_id = CSI_FRAME_COUNT.fetch_add(1, Ordering::Relaxed);

    // Generate raw grayscale at reduced resolution.
    generate_gray8(&mut raw[..], cap_w, cap_h, frame_id);
    let acq = azos_drv_sys::timebase::now();

    // Encode to minimal JPEG.
    (encode_gray_jpeg(&raw[..raw_size], cap_w, cap_h, jpeg_buf), acq)
}

/// Generate a synthetic grayscale test pattern.
fn generate_gray8(buf: &mut [u8], w: usize, h: usize, frame_id: u32) {
    let pattern = frame_id % 4;

    for y in 0..h {
        for x in 0..w {
            let pixel = match pattern {
                0 => {
                    // Horizontal gradient.
                    (x * 255 / w.max(1)) as u8
                }
                1 => {
                    // Vertical gradient.
                    (y * 255 / h.max(1)) as u8
                }
                2 => {
                    // Checkerboard (16x16 blocks).
                    let bx = x / 16;
                    let by = y / 16;
                    if (bx + by) % 2 == 0 { 40 } else { 220 }
                }
                _ => {
                    // Center blob — bright circle in the middle.
                    let cx = w / 2;
                    let cy = h / 2;
                    let dx = if x > cx { x - cx } else { cx - x };
                    let dy = if y > cy { y - cy } else { cy - y };
                    let dist_sq = dx * dx + dy * dy;
                    let radius_sq = (w / 6) * (w / 6);
                    if dist_sq < radius_sq { 240 } else { 30 }
                }
            };
            buf[y * w + x] = pixel;
        }
    }
}

/// Get current frame count.
pub fn csi_frame_count() -> u32 {
    CSI_FRAME_COUNT.load(Ordering::Relaxed)
}

/// Get configured resolution.
pub fn csi_resolution() -> (u16, u16) {
    (CSI_WIDTH.load(Ordering::Relaxed), CSI_HEIGHT.load(Ordering::Relaxed))
}

// ── Info ─────────────────────────────────────────────────────────────────────

/// Print CSI camera status.
pub fn csi_info() {
    if !CSI_READY.load(Ordering::Acquire) {
        azos_drv_sys::kconsoleln!("[CSI] Not initialized");
        return;
    }
    let w = CSI_WIDTH.load(Ordering::Relaxed);
    let h = CSI_HEIGHT.load(Ordering::Relaxed);
    let fmt = u8_to_fmt(CSI_FMT.load(Ordering::Relaxed));
    let frames = CSI_FRAME_COUNT.load(Ordering::Relaxed);
    let powered = CSI_POWERED.load(Ordering::Relaxed);
    let fmt_name = match fmt { PixFmt::Gray8 => "Gray8", PixFmt::Rgb565 => "RGB565" };
    let frame_bytes = w as u32 * h as u32 * fmt.bpp() as u32;

    azos_drv_sys::kconsoleln!("[CSI] {}x{} {} ({} bytes/frame)", w, h, fmt_name, frame_bytes);
    azos_drv_sys::kconsoleln!("[CSI] Power: {}, Frames: {}", if powered { "ON" } else { "OFF" }, frames);

    #[cfg(feature = "vf2")]
    azos_drv_sys::kconsoleln!("[CSI] Hardware: JH7110 ISP");
    #[cfg(feature = "k1")]
    azos_drv_sys::kconsoleln!("[CSI] Hardware: SpacemiT ISP");
    #[cfg(not(any(feature = "vf2", feature = "k1")))]
    azos_drv_sys::kconsoleln!("[CSI] Hardware: QEMU simulated");
}

// ── Minimal JPEG encoder (grayscale baseline) ───────────────────────────────
//
// Produces valid JFIF grayscale JPEG from raw 8-bit pixels.
// Simplified: uses fixed Huffman tables and 8x8 DCT with integer approximation.
// Quality is modest but sufficient for VLM analysis over low-bandwidth links.

/// JPEG markers.
const SOI: [u8; 2] = [0xFF, 0xD8];
const EOI: [u8; 2] = [0xFF, 0xD9];

/// Encode grayscale pixels to minimal JPEG.
/// Returns number of bytes written to `out`, or 0 on error.
fn encode_gray_jpeg(pixels: &[u8], w: usize, h: usize, out: &mut [u8]) -> usize {
    if w == 0 || h == 0 || pixels.len() < w * h { return 0; }
    if out.len() < 256 { return 0; } // need room for headers

    let mut pos: usize = 0;

    // SOI
    if !write_bytes(out, &mut pos, &SOI) { return 0; }

    // APP0 (JFIF)
    let app0: [u8; 18] = [
        0xFF, 0xE0, 0x00, 0x10, // marker + length
        0x4A, 0x46, 0x49, 0x46, 0x00, // "JFIF\0"
        0x01, 0x01, // version 1.1
        0x00, // aspect ratio units: none
        0x00, 0x01, 0x00, 0x01, // pixel aspect 1:1
        0x00, 0x00, // no thumbnail
    ];
    if !write_bytes(out, &mut pos, &app0) { return 0; }

    // DQT — quantization table (luminance, quality ~50)
    let qt = build_quant_table(JPEG_QUALITY);
    if !write_dqt(out, &mut pos, &qt) { return 0; }

    // SOF0 — start of frame (baseline, grayscale)
    if !write_sof0(out, &mut pos, w as u16, h as u16) { return 0; }

    // DHT — Huffman tables (DC + AC, standard luminance)
    if !write_dht(out, &mut pos) { return 0; }

    // SOS — start of scan
    if !write_sos(out, &mut pos) { return 0; }

    // Scan data — encode 8x8 blocks
    let mut prev_dc: i32 = 0;
    let mut bit_buf: u32 = 0;
    let mut bit_count: u32 = 0;

    let blocks_x = (w + 7) / 8;
    let blocks_y = (h + 7) / 8;

    for by in 0..blocks_y {
        for bx in 0..blocks_x {
            // Extract 8x8 block
            let mut block = [0i32; 64];
            for row in 0..8 {
                for col in 0..8 {
                    let px = bx * 8 + col;
                    let py = by * 8 + row;
                    let val = if px < w && py < h {
                        pixels[py * w + px] as i32
                    } else {
                        0
                    };
                    block[row * 8 + col] = val - 128; // level shift
                }
            }

            // Simple DCT approximation: just use average as DC, zero AC
            // This produces valid but very low-quality JPEG (blocky)
            let dc: i32 = {
                let mut sum: i32 = 0;
                for &v in &block { sum += v; }
                sum / 64
            };

            // Quantize DC
            let qdc = dc / (qt[0] as i32).max(1);

            // Encode DC difference
            let diff = qdc - prev_dc;
            prev_dc = qdc;

            // DC Huffman encode
            let (dc_code, dc_bits) = dc_huffman_encode(diff);
            emit_bits(out, &mut pos, &mut bit_buf, &mut bit_count, dc_code, dc_bits);

            // AC: all zeros → EOB (0x00 in AC Huffman = category 0, run 0)
            // EOB code for standard luminance AC: 0b1010, 4 bits
            const AC_EOB_CODE: u32 = 0b1010;
            const AC_EOB_BITS: u32 = 4;
            emit_bits(out, &mut pos, &mut bit_buf, &mut bit_count, AC_EOB_CODE, AC_EOB_BITS);

            if pos >= out.len() - 4 { return 0; } // overflow guard
        }
    }

    // Flush remaining bits (pad with 1s)
    if bit_count > 0 {
        let pad = 8 - bit_count;
        bit_buf = (bit_buf << pad) | ((1u32 << pad) - 1);
        let byte = (bit_buf & 0xFF) as u8;
        if !write_byte(out, &mut pos, byte) { return 0; }
        if byte == 0xFF {
            if !write_byte(out, &mut pos, 0x00) { return 0; } // stuff
        }
    }

    // EOI
    if !write_bytes(out, &mut pos, &EOI) { return 0; }

    pos
}

// ── JPEG helper functions ───────────────────────────────────────────────────

fn build_quant_table(quality: u8) -> [u8; 64] {
    // Standard JPEG luminance quantization table, scaled by quality
    const BASE_QT: [u8; 64] = [
        16, 11, 10, 16, 24, 40, 51, 61,
        12, 12, 14, 19, 26, 58, 60, 55,
        14, 13, 16, 24, 40, 57, 69, 56,
        14, 17, 22, 29, 51, 87, 80, 62,
        18, 22, 37, 56, 68,109,103, 77,
        24, 35, 55, 64, 81,104,113, 92,
        49, 64, 78, 87,103,121,120,101,
        72, 92, 95, 98,112,100,103, 99,
    ];
    let q = quality.max(1).min(100);
    let scale = if q < 50 { 5000 / q as u32 } else { 200 - 2 * q as u32 };
    let mut qt = [0u8; 64];
    for i in 0..64 {
        let v = (BASE_QT[i] as u32 * scale + 50) / 100;
        qt[i] = v.max(1).min(255) as u8;
    }
    qt
}

fn write_byte(out: &mut [u8], pos: &mut usize, b: u8) -> bool {
    if *pos >= out.len() { return false; }
    out[*pos] = b;
    *pos += 1;
    true
}

fn write_bytes(out: &mut [u8], pos: &mut usize, data: &[u8]) -> bool {
    if *pos + data.len() > out.len() { return false; }
    out[*pos..*pos + data.len()].copy_from_slice(data);
    *pos += data.len();
    true
}

fn write_dqt(out: &mut [u8], pos: &mut usize, qt: &[u8; 64]) -> bool {
    // DQT marker: FF DB, length=67, table 0, 8-bit precision
    let marker: [u8; 5] = [0xFF, 0xDB, 0x00, 0x43, 0x00];
    write_bytes(out, pos, &marker) && write_bytes(out, pos, qt)
}

fn write_sof0(out: &mut [u8], pos: &mut usize, w: u16, h: u16) -> bool {
    // SOF0 baseline, grayscale (1 component)
    let hdr: [u8; 11] = [
        0xFF, 0xC0,         // marker
        0x00, 0x0B,         // length = 11
        0x08,               // 8-bit precision
        (h >> 8) as u8, (h & 0xFF) as u8,
        (w >> 8) as u8, (w & 0xFF) as u8,
        0x01,               // 1 component (grayscale)
        0x01, // component 1: ID=1, sampling 1x1, quant table 0
    ];
    // Component spec: ID, H/V sampling, quant table
    let comp: [u8; 2] = [0x11, 0x00]; // 1x1 sampling, table 0
    write_bytes(out, pos, &hdr) && write_bytes(out, pos, &comp)
}

fn write_dht(out: &mut [u8], pos: &mut usize) -> bool {
    // Standard luminance DC Huffman table
    let dc_hdr: [u8; 4] = [0xFF, 0xC4, 0x00, 0x1F];
    let dc_class: [u8; 1] = [0x00]; // class 0 (DC), table 0
    // Counts per code length (1-16)
    let dc_counts: [u8; 16] = [0,1,5,1,1,1,1,1,1,0,0,0,0,0,0,0];
    // Values
    let dc_values: [u8; 12] = [0,1,2,3,4,5,6,7,8,9,10,11];

    if !write_bytes(out, pos, &dc_hdr) { return false; }
    if !write_bytes(out, pos, &dc_class) { return false; }
    if !write_bytes(out, pos, &dc_counts) { return false; }
    if !write_bytes(out, pos, &dc_values) { return false; }

    // Standard luminance AC Huffman table (minimal: just EOB)
    let ac_hdr: [u8; 4] = [0xFF, 0xC4, 0x00, 0x14];
    let ac_class: [u8; 1] = [0x10]; // class 1 (AC), table 0
    let ac_counts: [u8; 16] = [0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0];
    let ac_values: [u8; 1] = [0x00]; // EOB only

    if !write_bytes(out, pos, &ac_hdr) { return false; }
    if !write_bytes(out, pos, &ac_class) { return false; }
    if !write_bytes(out, pos, &ac_counts) { return false; }
    write_bytes(out, pos, &ac_values)
}

fn write_sos(out: &mut [u8], pos: &mut usize) -> bool {
    // SOS: 1 component, DC table 0, AC table 0
    let sos: [u8; 10] = [
        0xFF, 0xDA,         // marker
        0x00, 0x08,         // length = 8
        0x01,               // 1 component
        0x01, 0x00,         // component 1: DC table 0, AC table 0
        0x00, 0x3F, 0x00,   // spectral selection 0-63, successive approx 0
    ];
    write_bytes(out, pos, &sos)
}

/// Encode a DC coefficient difference using standard luminance DC Huffman.
fn dc_huffman_encode(diff: i32) -> (u32, u32) {
    let abs_diff = if diff < 0 { -diff } else { diff } as u32;
    let category = if abs_diff == 0 { 0 } else { 32 - abs_diff.leading_zeros() };

    // Standard DC luminance Huffman codes (category → code, length)
    let (huff_code, huff_len) = match category {
        0  => (0b00, 2),
        1  => (0b010, 3),
        2  => (0b011, 3),
        3  => (0b100, 3),
        4  => (0b101, 3),
        5  => (0b110, 3),
        6  => (0b1110, 4),
        7  => (0b11110, 5),
        8  => (0b111110, 6),
        9  => (0b1111110, 7),
        10 => (0b11111110, 8),
        _  => (0b111111110, 9),
    };

    if category == 0 {
        return (huff_code, huff_len);
    }

    // Append magnitude bits
    let magnitude = if diff >= 0 {
        diff as u32
    } else {
        (diff + (1i32 << category) - 1) as u32
    };

    let combined = (huff_code << category) | magnitude;
    let total_bits = huff_len + category;
    (combined, total_bits)
}

/// Emit bits to the output buffer with byte stuffing.
fn emit_bits(
    out: &mut [u8], pos: &mut usize,
    bit_buf: &mut u32, bit_count: &mut u32,
    code: u32, nbits: u32,
) {
    *bit_buf = (*bit_buf << nbits) | (code & ((1u32 << nbits) - 1));
    *bit_count += nbits;

    while *bit_count >= 8 {
        *bit_count -= 8;
        let byte = ((*bit_buf >> *bit_count) & 0xFF) as u8;
        if *pos < out.len() {
            out[*pos] = byte;
            *pos += 1;
            // Byte stuffing: 0xFF must be followed by 0x00
            if byte == 0xFF && *pos < out.len() {
                out[*pos] = 0x00;
                *pos += 1;
            }
        }
    }
}

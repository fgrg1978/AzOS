// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! virtio-gpu wire format (virtio 1.x 5.7), 2D only: the requests the driver
//! sends, the answers it reads, the EDID's preferred mode and the damage
//! rectangle the display is told about.
//!
//! Pure (`core` only), so `tests/host/fb-tests` runs it against fixed bytes.
//! Every request is built as a fixed-size array (all fields little endian,
//! whatever the CPU): the driver copies it into a request slot, so no encoder
//! has a length to get wrong and none can panic.

use core::sync::atomic::{AtomicU64, Ordering};

/// PCI: vendor 0x1af4, device 0x1040 + the virtio device id (16).
pub const PCI_DEVICE: u16 = 0x1050;

/// Feature word 0, bit 1: the device answers `GET_EDID`.
pub const F_EDID: u32 = 1 << 1;

/// `struct virtio_gpu_ctrl_hdr`: type, flags, fence id, context, ring index, pad.
pub const HDR_LEN: usize = 24;

// Requests.
pub const CMD_GET_DISPLAY_INFO: u32 = 0x0100;
pub const CMD_RESOURCE_CREATE_2D: u32 = 0x0101;
pub const CMD_SET_SCANOUT: u32 = 0x0103;
pub const CMD_RESOURCE_FLUSH: u32 = 0x0104;
pub const CMD_TRANSFER_TO_HOST_2D: u32 = 0x0105;
pub const CMD_RESOURCE_ATTACH_BACKING: u32 = 0x0106;
pub const CMD_GET_EDID: u32 = 0x010a;

// Answers.
pub const RESP_OK_NODATA: u32 = 0x1100;
pub const RESP_OK_DISPLAY_INFO: u32 = 0x1101;
pub const RESP_OK_EDID: u32 = 0x1104;

/// `VIRTIO_GPU_FORMAT_B8G8R8X8_UNORM`: little-endian bytes B, G, R, X, which is
/// the CPU word `0x00RRGGBB`, `azos_fb`'s `PixelFormat::XRGB8888`.
pub const FORMAT_B8G8R8X8: u32 = 2;
/// Bytes per pixel of that format.
pub const BYTES_PER_PIXEL: u32 = 4;

/// Request sizes.
pub const LEN_GET_DISPLAY_INFO: usize = HDR_LEN;
pub const LEN_GET_EDID: usize = HDR_LEN + 8;
pub const LEN_CREATE_2D: usize = HDR_LEN + 16;
pub const LEN_ATTACH_BACKING_1: usize = HDR_LEN + 8 + 16;
pub const LEN_SET_SCANOUT: usize = HDR_LEN + 16 + 8;
pub const LEN_TRANSFER: usize = HDR_LEN + 16 + 8 + 8;
pub const LEN_FLUSH: usize = HDR_LEN + 16 + 8;

/// Answer sizes: the header alone, the 16 scanout descriptors, the EDID block.
pub const RESP_LEN_NODATA: usize = HDR_LEN;
pub const RESP_LEN_DISPLAY_INFO: usize = HDR_LEN + 16 * 24;
pub const RESP_LEN_EDID: usize = HDR_LEN + 8 + 1024;

/// A rectangle in pixels.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rect {
    pub x: u32,
    pub y: u32,
    pub w: u32,
    pub h: u32,
}

fn put32(b: &mut [u8], off: usize, v: u32) {
    b[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

fn put64(b: &mut [u8], off: usize, v: u64) {
    b[off..off + 8].copy_from_slice(&v.to_le_bytes());
}

fn get32(b: &[u8], off: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(off..off + 4)?.try_into().ok()?))
}

fn put_rect(b: &mut [u8], off: usize, r: Rect) {
    put32(b, off, r.x);
    put32(b, off + 4, r.y);
    put32(b, off + 8, r.w);
    put32(b, off + 12, r.h);
}

/// A request of type `ty`, header only (no fence, context 0).
fn hdr<const N: usize>(ty: u32) -> [u8; N] {
    let mut b = [0u8; N];
    put32(&mut b, 0, ty);
    b
}

pub fn get_display_info() -> [u8; LEN_GET_DISPLAY_INFO] {
    hdr(CMD_GET_DISPLAY_INFO)
}

pub fn get_edid(scanout: u32) -> [u8; LEN_GET_EDID] {
    let mut b = hdr::<LEN_GET_EDID>(CMD_GET_EDID);
    put32(&mut b, HDR_LEN, scanout);
    b
}

pub fn resource_create_2d(resource: u32, format: u32, width: u32, height: u32) -> [u8; LEN_CREATE_2D] {
    let mut b = hdr::<LEN_CREATE_2D>(CMD_RESOURCE_CREATE_2D);
    put32(&mut b, HDR_LEN, resource);
    put32(&mut b, HDR_LEN + 4, format);
    put32(&mut b, HDR_LEN + 8, width);
    put32(&mut b, HDR_LEN + 12, height);
    b
}

/// Attach `len` bytes at bus address `addr` as the resource's backing store:
/// one `virtio_gpu_mem_entry` (the framebuffer is one physically contiguous
/// block).
pub fn resource_attach_backing_1(resource: u32, addr: u64, len: u32) -> [u8; LEN_ATTACH_BACKING_1] {
    let mut b = hdr::<LEN_ATTACH_BACKING_1>(CMD_RESOURCE_ATTACH_BACKING);
    put32(&mut b, HDR_LEN, resource);
    put32(&mut b, HDR_LEN + 4, 1);
    put64(&mut b, HDR_LEN + 8, addr);
    put32(&mut b, HDR_LEN + 16, len);
    b
}

pub fn set_scanout(scanout: u32, resource: u32, r: Rect) -> [u8; LEN_SET_SCANOUT] {
    let mut b = hdr::<LEN_SET_SCANOUT>(CMD_SET_SCANOUT);
    put_rect(&mut b, HDR_LEN, r);
    put32(&mut b, HDR_LEN + 16, scanout);
    put32(&mut b, HDR_LEN + 20, resource);
    b
}

/// Copy `r` of the guest backing store to the host's resource. `offset` is the
/// byte offset into the backing store of the rectangle's first pixel (the host
/// then steps by the resource's own stride, `width * 4`).
pub fn transfer_to_host_2d(resource: u32, r: Rect, offset: u64) -> [u8; LEN_TRANSFER] {
    let mut b = hdr::<LEN_TRANSFER>(CMD_TRANSFER_TO_HOST_2D);
    put_rect(&mut b, HDR_LEN, r);
    put64(&mut b, HDR_LEN + 16, offset);
    put32(&mut b, HDR_LEN + 24, resource);
    b
}

pub fn resource_flush(resource: u32, r: Rect) -> [u8; LEN_FLUSH] {
    let mut b = hdr::<LEN_FLUSH>(CMD_RESOURCE_FLUSH);
    put_rect(&mut b, HDR_LEN, r);
    put32(&mut b, HDR_LEN + 16, resource);
    b
}

/// The `type` field of an answer; `None` for one shorter than a header.
pub fn resp_type(resp: &[u8]) -> Option<u32> {
    get32(resp, 0)
}

/// What a scanout or an EDID says about the display.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Mode {
    pub width: u32,
    pub height: u32,
    /// Refresh rate in Hz.
    pub hz: u32,
}

/// Refresh rate when the display does not say (an EDID-less scanout).
pub const DEFAULT_HZ: u32 = 60;
/// What the display gets when the device reports none (Linux's default too).
pub const DEFAULT_MODE: Mode = Mode { width: 1024, height: 768, hz: DEFAULT_HZ };
/// The largest framebuffer the driver allocates, in bytes.
pub const MAX_FB_BYTES: u64 = 16 << 20;
/// The largest side of a mode, in pixels (damage coordinates are 16 bits).
pub const MAX_SIDE: u32 = 8192;

/// `true` for a mode the driver can allocate: both sides in `1..=MAX_SIDE` and
/// the framebuffer within [`MAX_FB_BYTES`].
pub fn mode_ok(m: Mode) -> bool {
    m.width >= 1
        && m.height >= 1
        && m.width <= MAX_SIDE
        && m.height <= MAX_SIDE
        && m.width as u64 * m.height as u64 * BYTES_PER_PIXEL as u64 <= MAX_FB_BYTES
}

/// Scanout 0 of a `GET_DISPLAY_INFO` answer: its size when the host reports it
/// enabled with a non-empty rectangle. The refresh rate is [`DEFAULT_HZ`]: only
/// the EDID carries one.
pub fn parse_display_info(resp: &[u8]) -> Option<Mode> {
    if resp_type(resp)? != RESP_OK_DISPLAY_INFO {
        return None;
    }
    // pmodes[0]: rect (x, y, w, h), enabled, flags.
    let (w, h, enabled) = (get32(resp, HDR_LEN + 8)?, get32(resp, HDR_LEN + 12)?, get32(resp, HDR_LEN + 16)?);
    if enabled == 0 || w == 0 || h == 0 {
        return None;
    }
    Some(Mode { width: w, height: h, hz: DEFAULT_HZ })
}

/// The preferred mode of a base EDID block (the first detailed timing
/// descriptor, EDID 1.4 3.10.2). `None` when the block is not an EDID (header
/// or checksum wrong), when the first descriptor is not a timing, or when it
/// describes no pixels. The refresh rate is pixel clock over the blanking-
/// inclusive frame, kept only within 24..=240 Hz, else [`DEFAULT_HZ`].
pub fn parse_edid_block(edid: &[u8]) -> Option<Mode> {
    const HEADER: [u8; 8] = [0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0];
    let block = edid.get(..128)?;
    if block[..8] != HEADER || block.iter().fold(0u8, |a, &b| a.wrapping_add(b)) != 0 {
        return None;
    }
    let d = &block[54..72];
    let clock_10khz = u16::from_le_bytes([d[0], d[1]]) as u64;
    if clock_10khz == 0 {
        return None; // a display descriptor (name, range limits), not a timing
    }
    let hactive = d[2] as u32 | (d[4] as u32 & 0xf0) << 4;
    let hblank = d[3] as u32 | (d[4] as u32 & 0x0f) << 8;
    let vactive = d[5] as u32 | (d[7] as u32 & 0xf0) << 4;
    let vblank = d[6] as u32 | (d[7] as u32 & 0x0f) << 8;
    if hactive == 0 || vactive == 0 {
        return None;
    }
    let frame = (hactive + hblank) as u64 * (vactive + vblank) as u64;
    let hz = (clock_10khz * 10_000 + frame / 2) / frame;
    let hz = if (24..=240).contains(&hz) { hz as u32 } else { DEFAULT_HZ };
    Some(Mode { width: hactive, height: vactive, hz })
}

/// The preferred mode of a `GET_EDID` answer: `size` bytes of EDID follow the
/// header and the size word.
pub fn parse_edid(resp: &[u8]) -> Option<Mode> {
    parse_edid_block(edid_blob(resp)?)
}

/// The EDID bytes of a `GET_EDID` answer (at most 1024 of them), `None` when
/// the answer is not an EDID response.
pub fn edid_blob(resp: &[u8]) -> Option<&[u8]> {
    if resp_type(resp)? != RESP_OK_EDID {
        return None;
    }
    let size = get32(resp, HDR_LEN)? as usize;
    resp.get(HDR_LEN + 8..)?.get(..size.min(1024))
}

/// The mode to use: the EDID's preferred one, else the scanout's size, else the
/// default; the first of them the driver can allocate.
pub fn choose_mode(edid: Option<Mode>, info: Option<Mode>) -> Mode {
    [edid, info].into_iter().flatten().find(|&m| mode_ok(m)).unwrap_or(DEFAULT_MODE)
}

/// The rectangle of the framebuffer changed since the display was last told,
/// kept in one word so any context (an interrupt handler, the panic screen) can
/// add to it and the context that commits can take it, with no lock.
///
/// `x0 | y0 << 16 | x1 << 32 | y1 << 48`, the end coordinates exclusive; zero
/// is empty (a non-empty rectangle has `x1 > 0`).
pub struct Damage(AtomicU64);

fn pack(x0: u32, y0: u32, x1: u32, y1: u32) -> u64 {
    x0 as u64 | (y0 as u64) << 16 | (x1 as u64) << 32 | (y1 as u64) << 48
}

fn unpack(v: u64) -> (u32, u32, u32, u32) {
    (v as u16 as u32, (v >> 16) as u16 as u32, (v >> 32) as u16 as u32, (v >> 48) as u16 as u32)
}

impl Damage {
    pub const fn new() -> Self {
        Damage(AtomicU64::new(0))
    }

    /// Add `r` (clipped to the 16-bit coordinate space) to the pending rectangle.
    pub fn add(&self, r: Rect) {
        let x1 = r.x.saturating_add(r.w).min(0xffff);
        let y1 = r.y.saturating_add(r.h).min(0xffff);
        if r.x >= x1 || r.y >= y1 {
            return;
        }
        let mut cur = self.0.load(Ordering::Relaxed);
        loop {
            let new = if cur == 0 {
                pack(r.x, r.y, x1, y1)
            } else {
                let (cx0, cy0, cx1, cy1) = unpack(cur);
                pack(cx0.min(r.x), cy0.min(r.y), cx1.max(x1), cy1.max(y1))
            };
            match self.0.compare_exchange_weak(cur, new, Ordering::AcqRel, Ordering::Relaxed) {
                Ok(_) => return,
                Err(seen) => cur = seen,
            }
        }
    }

    /// Take the pending rectangle, leaving none.
    pub fn take(&self) -> Option<Rect> {
        let v = self.0.swap(0, Ordering::AcqRel);
        if v == 0 {
            return None;
        }
        let (x0, y0, x1, y1) = unpack(v);
        Some(Rect { x: x0, y: y0, w: x1 - x0, h: y1 - y0 })
    }

    /// Is anything pending?
    pub fn pending(&self) -> bool {
        self.0.load(Ordering::Acquire) != 0
    }
}

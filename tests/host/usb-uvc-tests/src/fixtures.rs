// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! A UVC camera, built byte by byte the way a webcam's firmware does: its
//! descriptors, and the PROBE answer of its streaming control.

use azos_usb_tests::devices::{device_desc, string_desc, DevRef, MockDev};

/// A class-specific interface descriptor of the video class.
pub fn cs(subtype: u8, payload: &[u8]) -> Vec<u8> {
    let mut v = vec![3 + payload.len() as u8, 0x24, subtype];
    v.extend(payload);
    v
}

pub fn iface(num: u8, alt: u8, neps: u8, sub: u8) -> Vec<u8> {
    vec![9, 4, num, alt, neps, 14, sub, 0, 0]
}

pub fn ep(addr: u8, attrs: u8, mps_word: u16, interval: u8) -> Vec<u8> {
    let mut v = vec![7, 5, addr, attrs];
    v.extend(mps_word.to_le_bytes());
    v.push(interval);
    v
}

/// SuperSpeed endpoint companion: max burst, bmAttributes, bytes per interval.
pub fn companion(burst: u8, attrs: u8, bpi: u16) -> Vec<u8> {
    let mut v = vec![6, 48, burst, attrs];
    v.extend(bpi.to_le_bytes());
    v
}

pub const YUY2_GUID: [u8; 16] = [0x59, 0x55, 0x59, 0x32, 0x00, 0x00, 0x10, 0x00, 0x80, 0x00, 0x00, 0xaa, 0x00, 0x38, 0x9b, 0x71];

pub const NV12_GUID: [u8; 16] = [0x4e, 0x56, 0x31, 0x32, 0x00, 0x00, 0x10, 0x00, 0x80, 0x00, 0x00, 0xaa, 0x00, 0x38, 0x9b, 0x71];

/// One frame descriptor of a format.
#[derive(Clone)]
pub struct Frame {
    pub width: u16,
    pub height: u16,
    /// dwMaxVideoFrameBufferSize.
    pub max_size: u32,
    /// dwDefaultFrameInterval, 100 ns units.
    pub default_interval: u32,
    /// The discrete intervals (`bFrameIntervalType` = their count), or, with
    /// `step` set, the (min, max) of a continuous range.
    pub intervals: Vec<u32>,
    pub step: Option<u32>,
}

impl Frame {
    /// A frame with discrete intervals, default the first.
    pub fn new(width: u16, height: u16, max_size: u32, intervals: &[u32]) -> Frame {
        Frame { width, height, max_size, default_interval: intervals[0], intervals: intervals.to_vec(), step: None }
    }

    fn bytes(&self, subtype: u8, index: u8) -> Vec<u8> {
        let mut p = vec![index, 0];
        p.extend(self.width.to_le_bytes());
        p.extend(self.height.to_le_bytes());
        p.extend((self.width as u32 * self.height as u32 * 16 * 15).to_le_bytes()); // dwMinBitRate
        p.extend((self.width as u32 * self.height as u32 * 16 * 30).to_le_bytes()); // dwMaxBitRate
        p.extend(self.max_size.to_le_bytes());
        p.extend(self.default_interval.to_le_bytes());
        match self.step {
            None => {
                p.push(self.intervals.len() as u8);
                for i in &self.intervals {
                    p.extend(i.to_le_bytes());
                }
            }
            Some(step) => {
                p.push(0);
                p.extend(self.intervals[0].to_le_bytes());
                p.extend(self.intervals[1].to_le_bytes());
                p.extend(step.to_le_bytes());
            }
        }
        cs(subtype, &p)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    Mjpeg,
    Yuy2,
    /// Uncompressed, but not YUY2: 12 bits per pixel.
    Nv12,
    /// A frame-based format (H.264): its own format and frame subtypes.
    H264,
}

#[derive(Clone)]
pub struct Format {
    pub kind: Kind,
    pub frames: Vec<Frame>,
}

/// One alternate setting of the streaming interface: an isochronous IN
/// endpoint with a max packet word (size in bits 10:0, extra transactions in
/// 12:11), its interval, and a SuperSpeed companion.
#[derive(Clone)]
pub struct Alt {
    pub mps_word: u16,
    pub interval: u8,
    pub companion: Option<(u8, u8, u16)>,
}

#[derive(Clone)]
pub enum Streaming {
    /// Setting 0 empty, settings 1.. with one isochronous endpoint each.
    Isoch(Vec<Alt>),
    /// One bulk IN endpoint in setting 0 (max packet size).
    Bulk(u16),
}

#[derive(Clone)]
pub struct Cam {
    pub bcd_uvc: u16,
    pub formats: Vec<Format>,
    pub streaming: Streaming,
    pub endpoint: u8,
    pub vc: u8,
    pub vs: u8,
    /// Add an Interface Association descriptor in front of the two interfaces.
    pub iad: bool,
}

impl Cam {
    /// A UVC 1.1 camera with MJPEG (160x120 and 320x240) and YUY2 (160x120)
    /// at 5, 10 and 15 fps, streaming isochronously with three settings of
    /// 192, 512 and 1024 bytes per service interval.
    pub fn new() -> Cam {
        let fps = |n: u32| 10_000_000 / n;
        let ivs = [fps(15), fps(10), fps(5)];
        Cam {
            bcd_uvc: 0x0110,
            formats: vec![
                Format {
                    kind: Kind::Mjpeg,
                    frames: vec![Frame::new(320, 240, 320 * 240 * 2, &ivs), Frame::new(160, 120, 160 * 120 * 2, &ivs)],
                },
                Format { kind: Kind::Yuy2, frames: vec![Frame::new(160, 120, 160 * 120 * 2, &ivs)] },
            ],
            streaming: Streaming::Isoch(vec![
                Alt { mps_word: 192, interval: 1, companion: None },
                Alt { mps_word: 512, interval: 1, companion: None },
                Alt { mps_word: 1024, interval: 1, companion: None },
            ]),
            endpoint: 0x81,
            vc: 0,
            vs: 1,
            iad: true,
        }
    }

    pub fn bulk() -> Cam {
        Cam { streaming: Streaming::Bulk(512), endpoint: 0x82, ..Cam::new() }
    }

    /// The format descriptors of the streaming interface, and the input
    /// header that opens them.
    fn vs_class_bytes(&self) -> Vec<u8> {
        let mut body = Vec::new();
        for (fi, f) in self.formats.iter().enumerate() {
            let idx = fi as u8 + 1;
            let n = f.frames.len() as u8;
            match f.kind {
                Kind::Mjpeg => body.extend(cs(6, &[idx, n, 1, 1, 0, 0, 0, 0])),
                Kind::Yuy2 | Kind::Nv12 => {
                    let mut p = vec![idx, n];
                    p.extend(if f.kind == Kind::Yuy2 { YUY2_GUID } else { NV12_GUID });
                    p.extend([if f.kind == Kind::Yuy2 { 16 } else { 12 }, 1, 0, 0, 0, 0]);
                    body.extend(cs(4, &p));
                }
                Kind::H264 => {
                    let mut p = vec![idx, n];
                    p.extend([b'H', b'2', b'6', b'4', 0, 0, 0x10, 0, 0x80, 0, 0, 0xaa, 0, 0x38, 0x9b, 0x71]);
                    p.extend([0, 1, 0, 0, 0, 0, 0, 0]);
                    body.extend(cs(0x10, &p));
                }
            }
            let sub = match f.kind {
                Kind::Mjpeg => 7,
                Kind::H264 => 0x11,
                _ => 5,
            };
            for (i, fr) in f.frames.iter().enumerate() {
                body.extend(fr.bytes(sub, i as u8 + 1));
            }
            // A colour matching descriptor after the frames, as cameras have.
            body.extend(cs(0x0d, &[1, 1, 1]));
        }
        let p = self.formats.len();
        let total = 13 + p + body.len();
        let mut hdr = vec![p as u8];
        hdr.extend((total as u16).to_le_bytes());
        hdr.extend([self.endpoint, 0, 2, 0, 0, 0, 1]);
        hdr.extend(std::iter::repeat_n(0u8, p));
        let mut out = cs(1, &hdr);
        out.extend(body);
        out
    }

    pub fn config(&self) -> Vec<u8> {
        let mut b = Vec::new();
        if self.iad {
            b.extend([8, 11, self.vc, 2, 14, 3, 0, 0]);
        }
        // Video control: the header names the streaming interface.
        b.extend(iface(self.vc, 0, 0, 1));
        let mut h = Vec::new();
        h.extend(self.bcd_uvc.to_le_bytes());
        h.extend(13u16.to_le_bytes());
        h.extend(48_000_000u32.to_le_bytes());
        h.extend([1, self.vs]);
        b.extend(cs(1, &h));
        // Video streaming.
        match &self.streaming {
            Streaming::Bulk(mps) => {
                b.extend(iface(self.vs, 0, 1, 2));
                b.extend(self.vs_class_bytes());
                b.extend(ep(self.endpoint, 2, *mps, 0));
            }
            Streaming::Isoch(alts) => {
                b.extend(iface(self.vs, 0, 0, 2));
                b.extend(self.vs_class_bytes());
                for (i, a) in alts.iter().enumerate() {
                    b.extend(iface(self.vs, i as u8 + 1, 1, 2));
                    b.extend(ep(self.endpoint, 5, a.mps_word, a.interval));
                    if let Some((burst, attrs, bpi)) = a.companion {
                        b.extend(companion(burst, attrs, bpi));
                    }
                }
            }
        }
        let total = 9 + b.len();
        let mut c = vec![9, 2];
        c.extend((total as u16).to_le_bytes());
        c.extend([2, 1, 0, 0x80, 50]);
        c.extend(b);
        c
    }

    /// The device at speed `psiv` (1 full, 3 high, 4 super), with the
    /// requests the model has no arm for answered.
    pub fn device(&self, psiv: u32) -> DevRef {
        let ss = psiv >= 4;
        let dd = device_desc(if ss { 0x0300 } else { 0x0200 }, 0xef, 2, 1, if ss { 9 } else { 64 }, 0x046d, 0x0825, 1, 2);
        let mut d = MockDev::new(psiv, dd, self.config());
        if ss {
            d.bos = Some(azos_usb_tests::devices::bos_desc(true));
        }
        d.strings = vec![string_desc("Cam Maker"), string_desc("USB Camera")];
        // SET_INTERFACE: the model has no arm for it.
        d.canned.push((0x01, 11, vec![]));
        d.into_ref()
    }
}

impl Default for Cam {
    fn default() -> Self {
        Cam::new()
    }
}

/// A PROBE/COMMIT control block of `len` bytes (26, 34 or 48).
#[allow(clippy::too_many_arguments)]
pub fn probe_block(len: usize, hint: u16, format: u8, frame: u8, interval: u32, max_frame: u32, max_payload: u32) -> Vec<u8> {
    let mut b = vec![0u8; len];
    b[0..2].copy_from_slice(&hint.to_le_bytes());
    b[2] = format;
    b[3] = frame;
    b[4..8].copy_from_slice(&interval.to_le_bytes());
    b[18..22].copy_from_slice(&max_frame.to_le_bytes());
    b[22..26].copy_from_slice(&max_payload.to_le_bytes());
    if len >= 34 {
        b[26..30].copy_from_slice(&48_000_000u32.to_le_bytes());
        b[30] = 3; // bmFramingInfo
        b[32] = 1; // bMinVersion
        b[33] = 1; // bMaxVersion
    }
    b
}

/// One UVC payload: header (length 2, 6 with a PTS, 12 with PTS and SCR) and
/// data. `fid` toggles per frame, `eof` ends it, `err` flags a bad payload.
pub fn payload(fid: bool, eof: bool, err: bool, pts: Option<u32>, data: &[u8]) -> Vec<u8> {
    let mut info = 0x80u8; // end of header
    info |= fid as u8;
    info |= (eof as u8) << 1;
    if pts.is_some() {
        info |= 1 << 2;
    }
    info |= (err as u8) << 6;
    let mut v = vec![2, info];
    if let Some(p) = pts {
        v.extend(p.to_le_bytes());
        v[0] = 6;
    }
    v.extend(data);
    v
}

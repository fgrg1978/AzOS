// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The USB video class driver: a UVC 1.0 / 1.1 / 1.5 camera as a producer of
//! frames into a camera frame ring (`azos_cam_ring`), for the perception
//! camera of a Pi or a PC.
//!
//! It is a class driver like the mass-storage one ([`super::msc`]): it serves
//! [`UsbClass`], claims the **video streaming** interface (class 14,
//! subclass 2) and moves data only through the pipes the core opened for that
//! claim. The video control interface (brightness, exposure, zoom, ...) is
//! left to the listing: a camera streams without it.
//!
//! # What it does
//!
//! 1. **Describes.** It reads the configuration descriptor through the
//!    control pipe and walks the class-specific descriptors the core's parser
//!    skips ([`survey`]): the video control header (`bcdUVC`, which sizes the
//!    PROBE block), the streaming input header (the data endpoint), the
//!    MJPEG and uncompressed (YUY2) formats and their frames, and the
//!    endpoint of every alternate setting of the streaming interface. It
//!    picks one (format, frame, interval): Motion-JPEG over YUY2, then the
//!    frame whose area is closest to [`Want`], then the interval closest to
//!    its frame rate. A Motion-JPEG frame size larger than the one wanted is
//!    offered only if the camera's own bound on a frame fits what the
//!    consumer carries ([`Want::max_jpeg`]), and a raw one only if it fits
//!    the slot; a camera with nothing that fits fails `NoFormat`.
//! 2. **Negotiates.** `SET_CUR(VS_PROBE_CONTROL)` with that choice,
//!    `GET_CUR(VS_PROBE_CONTROL)` for what the camera makes of it (the
//!    format and frame must be the ones asked for, `dwMaxPayloadTransferSize`
//!    is the bandwidth the stream needs). The block is 26 bytes for a 1.0
//!    camera and 34 for 1.1 and later, as the host stack of Linux sends it.
//! 3. **Streams while somebody reads.** The camera is idle until
//!    [`FrameSink::wanted`] is true (the ring has a consumer): then
//!    `SET_CUR(VS_COMMIT_CONTROL)`, the pipe of the streaming endpoint, and
//!    for an isochronous camera `SET_INTERFACE` to the smallest alternate
//!    setting whose bytes per service interval carry the negotiated payload.
//!    When nobody has read for [`IDLE_STOP_US`] the pipe is closed and the
//!    interface goes back to setting 0, which frees the bus bandwidth.
//! 4. **Assembles.** Every completed transfer is one payload: a header
//!    (`bHeaderLength`, `bmHeaderInfo`: FID, EOF, PTS, SCR, STI, ERR) and
//!    data. A frame is the payloads between two toggles of FID (or up to
//!    EOF), appended to a slot claimed from the sink, and committed when it
//!    ends if it is a whole one. The first frame after the stream starts is
//!    dropped (the camera may have been mid-frame), and so is every frame
//!    with a payload the camera flagged, a payload the bus lost, or more data
//!    than the slot holds. A camera that never sets EOF ends frames at the
//!    FID toggle; one that does set it loses a frame whose EOF payload never
//!    came.
//!
//! # Placement of the transfers
//!
//! An isochronous transfer is one service interval (the setting's bytes per
//! interval), a bulk one up to `dwMaxPayloadTransferSize`; [`PIPE_DEPTH`]
//! of them are outstanding and each is resubmitted as it completes, so the
//! camera never finds the ring empty for longer than the `usb` task takes to
//! come round. The buffers are one region under the controller's DMA mask,
//! placed so that none crosses a 64 KiB boundary (a TRB may not).
//!
//! # Limits, said plainly
//!
//! One camera at a time (a second is declined `BUSY`), one stream, no still
//! images (payloads with the STI bit are ignored), no frame-based formats
//! (H.264, VP8), no UVC 1.5 stream layouts, no bandwidth renegotiation (a
//! camera whose lowest frame rate needs more than its largest setting offers
//! is failed, not slowed down), and the time of a frame is the arrival of its
//! last payload, not the camera's presentation time. A camera that fails
//! stays failed until it is unplugged. A high-speed isochronous camera needs
//! a transfer per 125 us interval outstanding for as long as the `usb` task
//! sleeps: with the default `USB_PIPE_DEPTH` of 8 and `USB_POLL_MS` of 10 most
//! of its intervals are lost (counted in [`Stats::lost`]); full-speed and
//! bulk cameras are not affected, and the numbers to set for a high-speed
//! board are a test-week measurement.

use azos_cam_ring::{FrameInfo, FrameSink};
use azos_devif::outcome::{BAD_ARGUMENT, BUSY, OK, UNSUPPORTED};
use azos_devif::Out;
use azos_rings::Push;

use crate::class::{Claim, Match, Scope, UsbClass, UsbDevice};
use crate::hw::{Clock, DmaBuf, Memory, PAGE};
use crate::usbcore::desc::{
    Setup, DT_CONFIG, DT_ENDPOINT, DT_INTERFACE, DT_SS_ENDPOINT_COMPANION, REQ_SET_INTERFACE, RT_DIR_IN,
    RT_RECIP_INTERFACE, RT_TYPE_CLASS, XFER_BULK, XFER_ISOCH,
};
use crate::usbcore::pipe::{Completion, Dir, PipeEnd, PipeRings, Status, Transfer};
use crate::PIPE_DEPTH;

/// Interface class of the video class.
pub const CLASS_VIDEO: u8 = 0x0e;
/// Subclass of the video control interface.
pub const SC_CONTROL: u8 = 1;
/// Subclass of the video streaming interface.
pub const SC_STREAMING: u8 = 2;

const CS_INTERFACE: u8 = 0x24;
const VC_HEADER: u8 = 1;
const VS_INPUT_HEADER: u8 = 1;
const VS_FORMAT_UNCOMPRESSED: u8 = 4;
const VS_FRAME_UNCOMPRESSED: u8 = 5;
const VS_FORMAT_MJPEG: u8 = 6;
const VS_FRAME_MJPEG: u8 = 7;
/// Format descriptors of frame-based and stream-based formats (H.264, VP8,
/// MPEG-2 TS ...): their frames are not frames of this driver.
const VS_FORMAT_OTHER: [u8; 4] = [0x0a, 0x0b, 0x10, 0x12];

/// GUID of the YUY2 format (packed 4:2:2, `Y0 U Y1 V`).
const YUY2_GUID: [u8; 16] = [0x59, 0x55, 0x59, 0x32, 0x00, 0x00, 0x10, 0x00, 0x80, 0x00, 0x00, 0xaa, 0x00, 0x38, 0x9b, 0x71];

// Class requests of the video streaming interface (UVC 1.5, tables A-8, A-19).
const SET_CUR: u8 = 0x01;
const GET_CUR: u8 = 0x81;
const VS_PROBE_CONTROL: u16 = 1;
const VS_COMMIT_CONTROL: u16 = 2;

// `bmHeaderInfo` bits of a payload header.
const HDR_FID: u8 = 1 << 0;
const HDR_EOF: u8 = 1 << 1;
const HDR_STI: u8 = 1 << 5;
const HDR_ERR: u8 = 1 << 6;

/// Longest payload header (2 + PTS 4 + SCR 6).
const HEADER_MAX: usize = 12;
/// The largest probe/commit block (UVC 1.5).
const BLOCK_MAX: usize = 48;

/// Bytes of configuration descriptor read (a camera with many frame sizes
/// has a few KB; the rest is cut and the walk stops at the cut).
const CFG_MAX: usize = 4096;
const OUT_OFF: usize = 0;
const IN_OFF: usize = 64;
const CFG_OFF: usize = PAGE;
const CTL_BYTES: usize = PAGE + CFG_MAX;

/// A control step that outlives this is a camera that does not answer.
const CTL_TIMEOUT_US: u64 = 2_000_000;
/// A stream that completes nothing for this long is restarted.
const STALL_US: u64 = 3_000_000;
/// Restarts in a row, with no frame between, before the camera is failed.
const MAX_RESTARTS: u32 = 4;
/// How long nobody reading the ring is tolerated before the stream stops.
pub const IDLE_STOP_US: u64 = 500_000;

/// Transfers kept outstanding on the streaming pipe.
const BUFS: usize = PIPE_DEPTH;
/// Most bytes of one bulk transfer.
const BULK_XFER_MAX: u32 = 60 * 1024;
/// Streaming endpoints of alternate settings kept by [`survey`].
pub const MAX_ALTS: usize = 16;

// ---- What the camera offers ----

/// How the bytes of a frame are coded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pixels {
    Mjpeg,
    Yuyv,
}

/// What the stream should be like.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Want {
    pub width: u16,
    pub height: u16,
    /// Frames per second.
    pub fps: u16,
    /// Bytes a frame may be at most (the sink's slot): a raw format is
    /// offered only when a frame of it fits.
    pub max_frame: usize,
    /// Bytes a Motion-JPEG frame may be at most to be of use: what the
    /// consumer can carry on (the brain link's camera packet), which is less
    /// than a slot. A larger frame is dropped as `oversize`, and a frame size
    /// that cannot be shown to fit is not offered ([`frame_candidate`]).
    pub max_jpeg: usize,
}

/// The format, frame and interval picked from the camera's descriptors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Choice {
    pub pixels: Pixels,
    pub format_index: u8,
    pub frame_index: u8,
    pub width: u16,
    pub height: u16,
    /// Frame interval, 100 ns units.
    pub interval: u32,
}

impl Choice {
    /// Frames per second, rounded.
    pub fn fps(&self) -> u32 {
        if self.interval == 0 { 0 } else { (10_000_000 + self.interval / 2) / self.interval }
    }
}

/// The streaming endpoint of one alternate setting of the streaming
/// interface.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AltInfo {
    pub alt: u8,
    /// 0: this setting has no endpoint (setting 0 of an isochronous camera).
    pub address: u8,
    pub attrs: u8,
    /// `wMaxPacketSize`: the size in bits 10:0, the additional transactions
    /// of a high-bandwidth endpoint in 12:11.
    pub mps_word: u16,
    /// SuperSpeed companion: max burst, bmAttributes, bytes per interval.
    pub companion: Option<(u8, u8, u16)>,
}

impl AltInfo {
    /// Bytes the endpoint carries per service interval.
    pub fn bytes_per_interval(&self) -> u32 {
        match self.companion {
            Some((_, _, bpi)) if bpi != 0 => bpi as u32,
            _ => (self.mps_word & 0x7ff) as u32 * (1 + ((self.mps_word >> 11) & 3) as u32),
        }
    }

    fn transfer_type(&self) -> u8 {
        self.attrs & 3
    }
}

/// What [`survey`] found in a configuration descriptor.
#[derive(Clone, Copy, Debug)]
pub struct Survey {
    /// `bcdUVC` of the video control header (0: none seen).
    pub bcd_uvc: u16,
    /// The streaming input header's `bEndpointAddress`.
    pub endpoint: u8,
    /// The streaming interface's descriptors were seen.
    pub streaming: bool,
    /// The best (format, frame, interval) for the [`Want`].
    pub best: Option<Choice>,
    pub alts: [AltInfo; MAX_ALTS],
    pub n_alts: usize,
}

impl Survey {
    const fn new() -> Survey {
        Survey {
            bcd_uvc: 0,
            endpoint: 0,
            streaming: false,
            best: None,
            alts: [AltInfo { alt: 0, address: 0, attrs: 0, mps_word: 0, companion: None }; MAX_ALTS],
            n_alts: 0,
        }
    }

    /// The settings of the streaming interface, in descriptor order.
    pub fn alts(&self) -> &[AltInfo] {
        &self.alts[..self.n_alts]
    }
}

/// How the stream reaches the host.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// A bulk endpoint of setting 0.
    Bulk { endpoint: u8, mps: u16 },
    /// An isochronous endpoint of setting `alt`, `bytes` per service interval.
    Isoch { alt: u8, endpoint: u8, bytes: u32 },
}

/// The way to carry `payload` bytes per payload transfer: the bulk endpoint
/// of setting 0 if there is one, else the isochronous setting with the
/// fewest bytes per interval that is enough. `None`: the camera offers no
/// endpoint, or none big enough.
pub fn pick_mode(s: &Survey, payload: u32) -> Option<Mode> {
    if let Some(a) = s.alts().iter().find(|a| a.alt == 0 && a.address != 0 && a.transfer_type() == XFER_BULK) {
        return Some(Mode::Bulk { endpoint: a.address, mps: a.mps_word & 0x7ff });
    }
    let mut isoch = s.alts().iter().filter(|a| a.alt != 0 && a.address & 0x80 != 0 && a.transfer_type() == XFER_ISOCH);
    // Canary: the first setting is taken whatever it carries.
    let pick = if cfg!(feature = "canary-uvc-alt") {
        isoch.next()
    } else {
        isoch.filter(|a| a.bytes_per_interval() >= payload).min_by_key(|a| a.bytes_per_interval())
    };
    pick.map(|a| Mode::Isoch { alt: a.alt, endpoint: a.address, bytes: a.bytes_per_interval() })
}

fn le16(d: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([d[at], d[at + 1]])
}

fn le32(d: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([d[at], d[at + 1], d[at + 2], d[at + 3]])
}

/// The interval of frame descriptor `d` closest to `target` (100 ns units),
/// or the default interval when the descriptor does not say.
fn pick_interval(d: &[u8], target: u32) -> u32 {
    let default = le32(d, 21);
    let kind = d[25] as usize;
    if kind == 0 {
        // Continuous: a range with a step.
        if d.len() < 38 {
            return default;
        }
        let (min, max, step) = (le32(d, 26), le32(d, 30), le32(d, 34));
        if min > max {
            return default;
        }
        let t = target.clamp(min, max);
        return if step == 0 { t } else { (min + (t - min + step / 2) / step * step).min(max) };
    }
    if d.len() < 26 + 4 * kind {
        return default;
    }
    (0..kind).map(|k| le32(d, 26 + 4 * k)).filter(|iv| *iv != 0).min_by_key(|iv| iv.abs_diff(target)).unwrap_or(default)
}

/// The order frames are preferred in, lower first: Motion-JPEG over raw
/// pixels, then the area closest to the one wanted, then not larger.
fn rank(c: &Choice, want: &Want) -> (u8, u32, u8) {
    let area = c.width as u32 * c.height as u32;
    let wanted = want.width as u32 * want.height as u32;
    (matches!(c.pixels, Pixels::Yuyv) as u8, area.abs_diff(wanted), (area > wanted) as u8)
}

/// Walk the descriptors of a configuration (`total` bytes, read through
/// `read(offset, out)`) for the streaming interface `vs_iface` and its
/// camera. A descriptor that runs past the end, or has a length under 2,
/// ends the walk with what was seen.
pub fn survey(total: usize, read: &mut dyn FnMut(usize, &mut [u8]), vs_iface: u8, want: &Want) -> Survey {
    let mut s = Survey::new();
    let (mut iface, mut alt, mut class, mut sub) = (0xffu8, 0u8, 0u8, 0u8);
    // The format whose frames are being listed, and the alternate-setting
    // entry and endpoint last stored (a companion belongs to it).
    let mut fmt: Option<(Pixels, u8)> = None;
    let mut cur_alt: Option<usize> = None;
    let mut last_ep: Option<usize> = None;
    let mut buf = [0u8; 255];
    let mut off = 0;
    while off + 2 <= total {
        let mut h = [0u8; 2];
        read(off, &mut h);
        let len = h[0] as usize;
        if len < 2 || off + len > total {
            break;
        }
        read(off, &mut buf[..len]);
        let d = &buf[..len];
        off += len;
        match d[1] {
            DT_INTERFACE if len >= 9 => {
                (iface, alt, class, sub) = (d[2], d[3], d[5], d[6]);
                last_ep = None;
                cur_alt = None;
                if iface == vs_iface && class == CLASS_VIDEO && sub == SC_STREAMING {
                    s.streaming = true;
                    if s.n_alts < MAX_ALTS {
                        s.alts[s.n_alts] = AltInfo { alt, ..AltInfo::default() };
                        cur_alt = Some(s.n_alts);
                        s.n_alts += 1;
                    }
                }
            }
            DT_ENDPOINT if len >= 7 => {
                last_ep = None;
                if let Some(i) = cur_alt {
                    let a = &mut s.alts[i];
                    if a.address == 0 && (s.endpoint == 0 || d[2] == s.endpoint) {
                        (a.address, a.attrs, a.mps_word) = (d[2], d[3], le16(d, 4));
                        last_ep = Some(i);
                    }
                }
            }
            DT_SS_ENDPOINT_COMPANION if len >= 6 => {
                if let Some(i) = last_ep {
                    s.alts[i].companion = Some((d[2], d[3], le16(d, 4)));
                }
            }
            CS_INTERFACE if len >= 3 => {
                let subtype = d[2];
                if class == CLASS_VIDEO && sub == SC_CONTROL && subtype == VC_HEADER && len >= 5 {
                    s.bcd_uvc = le16(d, 3);
                } else if iface == vs_iface && class == CLASS_VIDEO && sub == SC_STREAMING && alt == 0 {
                    match subtype {
                        VS_INPUT_HEADER if len >= 7 => s.endpoint = d[6],
                        VS_FORMAT_MJPEG if len >= 5 => fmt = Some((Pixels::Mjpeg, d[3])),
                        // 16 bits per pixel and the YUY2 GUID: anything else
                        // uncompressed (NV12, Y8, ...) is another format.
                        VS_FORMAT_UNCOMPRESSED if len >= 22 => {
                            fmt = (d[5..21] == YUY2_GUID && d[21] == 16).then_some((Pixels::Yuyv, d[3]));
                        }
                        VS_FRAME_MJPEG | VS_FRAME_UNCOMPRESSED if len >= 26 => {
                            let kind = if subtype == VS_FRAME_MJPEG { Pixels::Mjpeg } else { Pixels::Yuyv };
                            if let Some((pixels, format_index)) = fmt.filter(|f| f.0 == kind) {
                                frame_candidate(&mut s, d, pixels, format_index, want);
                            }
                        }
                        t if VS_FORMAT_OTHER.contains(&t) => fmt = None,
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }
    s
}

/// Consider frame descriptor `d` (at least 26 bytes) of the format being
/// listed.
fn frame_candidate(s: &mut Survey, d: &[u8], pixels: Pixels, format_index: u8, want: &Want) {
    let (width, height) = (le16(d, 5), le16(d, 7));
    if width == 0 || height == 0 {
        return;
    }
    let area = width as usize * height as usize;
    match pixels {
        // A raw frame is offered only if one fits the sink's slot.
        Pixels::Yuyv if 2 * area > want.max_frame => return,
        // A JPEG's size is not known until it is made. The frame fits if the
        // camera's own bound (`dwMaxVideoFrameBufferSize`, offset 17) says so;
        // otherwise only a frame no larger than the one wanted is trusted to
        // (the size the consumer is sized for). A larger one would stream
        // 10 to 60 KB colour JPEGs the link cannot carry.
        Pixels::Mjpeg => {
            let bound = le32(d, 17) as usize;
            let proven = bound != 0 && bound <= want.max_jpeg;
            if !proven && area > want.width as usize * want.height as usize {
                return;
            }
        }
        _ => {}
    }
    let target = if want.fps == 0 { le32(d, 21) } else { 10_000_000 / want.fps as u32 };
    let interval = pick_interval(d, target);
    if interval == 0 {
        return;
    }
    let c = Choice { pixels, format_index, frame_index: d[3], width, height, interval };
    if s.best.is_none_or(|b| rank(&c, want) < rank(&b, want)) {
        s.best = Some(c);
    }
}

// ---- PROBE and COMMIT ----

/// Bytes of the probe/commit block sent and read: 26 for a UVC 1.0 camera,
/// 34 from 1.1 on (what Linux's host stack sends, and 1.5 cameras take).
pub fn block_len(bcd_uvc: u16) -> usize {
    // Canary: every camera is sent the 1.0 block.
    if cfg!(feature = "canary-uvc-probe-len") || bcd_uvc < 0x0110 { 26 } else { 34 }
}

/// The block that asks for `c`: the hint says only `dwFrameInterval` is
/// fixed by the host (the camera adjusts the rest), the indexes and the
/// interval are the choice's, the other fields are zero.
pub fn request_block(c: &Choice) -> [u8; BLOCK_MAX] {
    let mut b = [0u8; BLOCK_MAX];
    b[0] = 1; // bmHint: dwFrameInterval
    b[2] = c.format_index;
    b[3] = c.frame_index;
    b[4..8].copy_from_slice(&c.interval.to_le_bytes());
    b
}

/// What the camera made of a request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Negotiated {
    pub format_index: u8,
    pub frame_index: u8,
    pub interval: u32,
    /// `dwMaxPayloadTransferSize`: the bytes one payload transfer carries at
    /// most, the bandwidth the stream needs.
    pub max_payload: u32,
}

/// Decode a probe/commit block (at least the 26 bytes every version has).
pub fn parse_block(b: &[u8]) -> Option<Negotiated> {
    if b.len() < 26 {
        return None;
    }
    Some(Negotiated {
        format_index: b[2],
        frame_index: b[3],
        interval: le32(b, 4),
        max_payload: le32(b, 22),
    })
}

// ---- The payload ----

/// A payload header (UVC 1.5, section 2.4.3.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    /// `bHeaderLength`: where the data starts.
    pub len: usize,
    /// Toggles at the start of each frame.
    pub fid: bool,
    /// The last payload of the frame.
    pub eof: bool,
    /// The camera flags the payload as bad.
    pub err: bool,
    /// A payload of a still image, not of the stream.
    pub still: bool,
}

/// Decode the header at the start of `p` (a whole payload, or its first
/// `HEADER_MAX` bytes). `None`: shorter than it says, or under 2 bytes.
pub fn parse_header(p: &[u8]) -> Option<Header> {
    if p.len() < 2 {
        return None;
    }
    let len = p[0] as usize;
    if len < 2 || len > p.len() {
        return None;
    }
    let info = p[1];
    Some(Header {
        len,
        fid: info & HDR_FID != 0,
        eof: info & HDR_EOF != 0,
        // Canary: the camera's error flag is not looked at.
        err: info & HDR_ERR != 0 && !cfg!(feature = "canary-uvc-err"),
        still: info & HDR_STI != 0,
    })
}

// ---- The driver ----

/// Why a camera is failed. It stays failed until it is unplugged.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fail {
    /// No streaming endpoint (the header names none, or no setting has it).
    NoEndpoint,
    /// No format the driver knows (MJPEG, YUY2) in the descriptors.
    NoFormat,
    /// The core refused a pipe.
    Pipe,
    /// No DMA memory for the buffers.
    NoMemory,
    /// The camera answered PROBE with another format or frame, a stall, or
    /// no payload size.
    Negotiation,
    /// No alternate setting carries the payload the camera asks for.
    Bandwidth,
    /// A control step outlived its deadline.
    Timeout,
    /// A control transfer or the stream failed in a way a restart does not
    /// repair.
    Transport,
    /// The stream restarted `MAX_RESTARTS` times in a row and no frame came.
    NoFrames,
    /// The device was unplugged.
    Gone,
}

/// Where the driver is in the life of one camera.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    /// No camera.
    Idle,
    /// Claimed; the `usb` task gives [`Uvc::service`] a session next.
    Claimed,
    /// Reading descriptors and probing.
    Negotiating,
    /// Negotiated; the stream starts when the sink is wanted.
    Ready,
    /// Committing, opening the pipe, selecting the setting.
    Starting,
    Streaming,
    /// Closing the pipe and returning to setting 0.
    Stopping,
    Failed(Fail),
}

/// Counters, for a status line and the tests.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    /// Frames committed to the sink.
    pub frames: u32,
    /// Frames dropped: flagged, short, lost a payload, oversize, or the
    /// partial one the stream started in.
    pub dropped: u32,
    /// Frames the sink refused a slot for.
    pub refused: u32,
    /// Frames with more data than a slot holds, or a JPEG with more than
    /// [`Want::max_jpeg`].
    pub oversize: u32,
    /// Payloads whose header did not parse.
    pub bad_headers: u32,
    /// Intervals the bus lost (completions with an error code).
    pub lost: u32,
    /// Payloads taken (empty intervals excluded).
    pub payloads: u32,
    /// Times the stream was restarted after a stall or a halt.
    pub restarts: u32,
    /// Cameras declined because one is driven already.
    pub declined: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Step {
    Config,
    ProbeSet,
    ProbeGet,
    CommitSet,
    SetAlt,
    ClearHalt,
    AltZero,
}

impl Step {
    const fn code(self) -> u32 {
        self as u32 + 1
    }
}

/// Where the assembly of frames is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    /// The stream just started: what arrives is the end of a frame whose
    /// start was missed, up to the first toggle of FID or EOF.
    Syncing,
    /// Between frames: the next payload starts one.
    Between,
    /// Inside a frame.
    InFrame,
}

/// The frame being assembled: a slot of the sink, or none when the sink
/// refused it.
struct Frame<'q> {
    slot: Option<&'q mut [u8]>,
    len: usize,
    /// A payload of it was flagged or lost, or it overflowed the slot.
    bad: bool,
}

/// The camera driver. `S` is the ring the frames go to.
pub struct Uvc<'q, M: Memory, C: Clock, S: FrameSink> {
    mem: M,
    clock: C,
    mask: u64,
    rings: &'q [PipeRings],
    sink: &'q S,
    want: Want,
    /// The clock the ring's stamps are in.
    stamp: fn() -> u64,
    state: State,
    claim: Option<Claim>,
    vs_iface: u8,
    /// The core told us the device is gone; clean up on the next turn.
    gone: bool,
    ctl: Option<PipeEnd<'q>>,
    stream: Option<PipeEnd<'q>>,
    ctlbuf: Option<DmaBuf>,
    bufs: Option<DmaBuf>,
    /// Offsets of the [`BUFS`] transfer buffers in `bufs`, and their length.
    offs: [u32; BUFS],
    xfer_len: u32,
    /// The control step in flight and its deadline.
    step: Option<(Step, u64)>,
    survey: Survey,
    choice: Option<Choice>,
    block_len: usize,
    /// The probe answer, committed at each start.
    neg_block: [u8; BLOCK_MAX],
    mode: Option<Mode>,
    /// Transfers in flight, by buffer.
    inflight: [bool; BUFS],
    /// The bulk endpoint stalled: the buffers wait for the halt to be cleared.
    halted: bool,
    /// The stream pipe is open.
    pipe_open: bool,
    /// SET_INTERFACE selected an alternate setting.
    alt_set: bool,
    // -- assembly
    frame: Frame<'q>,
    phase: Phase,
    /// A payload was lost between two frames: the next one is spoilt.
    hole: bool,
    /// FID of the last payload, once there is one since the stream started.
    last_fid: bool,
    fid_known: bool,
    /// The camera was seen to set EOF; a toggle without it is a lost tail.
    eof_seen: bool,
    // -- timing
    idle_since_us: Option<u64>,
    last_progress_us: u64,
    restarts_in_a_row: u32,
    stats: Stats,
}

impl<'q, M: Memory, C: Clock, S: FrameSink> Uvc<'q, M, C, S> {
    /// A driver with no camera. `mask` is the controller's DMA mask, `rings`
    /// the pipe rings the core indexes by pipe number, `sink` the ring the
    /// frames go to, `stamp` the clock a frame's acquisition stamp is read
    /// from.
    pub fn new(mem: M, clock: C, mask: u64, rings: &'q [PipeRings], sink: &'q S, want: Want, stamp: fn() -> u64) -> Self {
        Uvc {
            mem,
            clock,
            mask,
            rings,
            sink,
            want,
            stamp,
            state: State::Idle,
            claim: None,
            vs_iface: 0,
            gone: false,
            ctl: None,
            stream: None,
            ctlbuf: None,
            bufs: None,
            offs: [0; BUFS],
            xfer_len: 0,
            step: None,
            survey: Survey::new(),
            choice: None,
            block_len: 0,
            neg_block: [0; BLOCK_MAX],
            mode: None,
            inflight: [false; BUFS],
            halted: false,
            pipe_open: false,
            alt_set: false,
            frame: Frame { slot: None, len: 0, bad: false },
            phase: Phase::Syncing,
            hole: false,
            last_fid: false,
            fid_known: false,
            eof_seen: false,
            idle_since_us: None,
            last_progress_us: 0,
            restarts_in_a_row: 0,
            stats: Stats::default(),
        }
    }

    /// The rule to register it under: video streaming interfaces.
    pub const fn rule() -> Match {
        Match { scope: Scope::Interface, vid_pid: None, class: Some(CLASS_VIDEO), subclass: Some(SC_STREAMING), protocol: None }
    }

    pub fn state(&self) -> State {
        self.state
    }

    pub fn stats(&self) -> Stats {
        self.stats
    }

    /// The format, frame and interval the camera agreed to, once it has.
    pub fn stream_choice(&self) -> Option<Choice> {
        self.choice
    }

    /// How the stream reaches the host, once negotiated.
    pub fn mode(&self) -> Option<Mode> {
        self.mode
    }

    /// The claim to open a session for, while there is a camera: the `usb`
    /// task passes its session to [`Uvc::service`] every turn.
    pub fn claim(&self) -> Option<Claim> {
        if self.gone { None } else { self.claim }
    }

    // ---- The machine ----

    /// Advance: take the completions the core posted, start the next step,
    /// start or stop the stream as the sink asks, clean up after an unplug.
    /// `dev` is the session of [`Uvc::claim`] (`None` when there is none);
    /// steps that open or close pipes wait for it.
    pub fn service(&mut self, mut dev: Option<&mut dyn UsbDevice>) {
        if self.gone {
            self.cleanup();
            return;
        }
        let now = self.clock.now_us();
        if self.state == State::Claimed {
            if let Some(d) = reborrow(&mut dev) {
                self.begin(d);
            }
        }
        self.reap_ctl();
        self.reap_stream(now);
        match self.state {
            State::Negotiating | State::Starting | State::Stopping => {
                if self.step.is_some_and(|(_, deadline)| now > deadline) {
                    self.fail(Fail::Timeout);
                }
            }
            State::Ready => {
                if self.sink.wanted() {
                    self.start(now);
                }
            }
            State::Streaming => {
                if self.sink.wanted() {
                    self.idle_since_us = None;
                    if now.saturating_sub(self.last_progress_us) > STALL_US {
                        self.restart(now);
                    }
                } else {
                    let since = *self.idle_since_us.get_or_insert(now);
                    if now.saturating_sub(since) >= IDLE_STOP_US {
                        self.state = State::Stopping;
                    }
                }
            }
            _ => {}
        }
        // The steps that open and close the stream's pipe need the session. A
        // failed camera gives its pipe (and its bandwidth) back too.
        if matches!(self.state, State::Failed(_)) && self.pipe_open {
            self.close_stream(reborrow(&mut dev));
        }
        if self.state == State::Starting {
            self.starting(reborrow(&mut dev));
        }
        if self.state == State::Stopping {
            self.stopping(reborrow(&mut dev));
        }
    }

    // ---- Opening, describing, negotiating ----

    fn begin(&mut self, dev: &mut dyn UsbDevice) {
        let Some(claim) = self.claim else { return };
        let Some(buf) = self.mem.alloc_region(CTL_BYTES, PAGE, self.mask) else { return self.fail(Fail::NoMemory) };
        self.ctlbuf = Some(buf);
        match open_one(dev, self.rings, 0) {
            Some(e) => self.ctl = Some(e),
            None => return self.fail(Fail::Pipe),
        }
        self.vs_iface = claim.iface();
        self.state = State::Negotiating;
        self.ctl_submit(Step::Config, Setup::get_descriptor(DT_CONFIG, 0, 0, CFG_MAX as u16), 0);
    }

    /// Put one control transfer on the control pipe. An OUT stage's `out_len`
    /// bytes are at [`OUT_OFF`] of the control buffer, an IN stage's land at
    /// [`IN_OFF`] (the configuration at [`CFG_OFF`]).
    fn ctl_submit(&mut self, step: Step, setup: Setup, out_len: usize) {
        let (Some(buf), Some(ctl)) = (self.ctlbuf.as_ref(), self.ctl.as_mut()) else { return };
        let (dir, off) = if setup.is_in() {
            (Dir::In, if step == Step::Config { CFG_OFF } else { IN_OFF })
        } else {
            self.mem.to_device(buf.cpu().wrapping_add(OUT_OFF), out_len);
            (Dir::Out, OUT_OFF)
        };
        let t = Transfer { tag: step.code(), dir, setup: setup.to_bytes(), buf: buf.bus_at(off), len: setup.length as u32 };
        self.step = Some((step, self.clock.now_us() + CTL_TIMEOUT_US));
        if !matches!(ctl.sq.push(t), Push::Pushed) {
            self.fail(Fail::Transport);
        }
    }

    /// A class request to the streaming interface for control `selector`.
    fn class_request(&self, set: bool, selector: u16, len: usize) -> Setup {
        Setup {
            request_type: if set { 0 } else { RT_DIR_IN } | RT_TYPE_CLASS | RT_RECIP_INTERFACE,
            request: if set { SET_CUR } else { GET_CUR },
            value: selector << 8,
            index: self.vs_iface as u16,
            length: len as u16,
        }
    }

    fn set_interface(&self, alt: u8) -> Setup {
        Setup {
            request_type: RT_RECIP_INTERFACE,
            request: REQ_SET_INTERFACE,
            value: alt as u16,
            index: self.vs_iface as u16,
            length: 0,
        }
    }

    /// The completion of the control step in flight, if it is in.
    fn reap_ctl(&mut self) {
        let Some((step, _)) = self.step else { return };
        let Some(c) = self.ctl.as_mut().and_then(|e| e.cq.pop()) else { return };
        self.step = None;
        if c.tag != step.code() {
            return self.fail(Fail::Transport);
        }
        match step {
            Step::Config => self.on_config(c),
            Step::ProbeSet => {
                if c.status != Status::Ok {
                    return self.fail(Fail::Negotiation);
                }
                let setup = self.class_request(false, VS_PROBE_CONTROL, self.block_len);
                self.ctl_submit(Step::ProbeGet, setup, 0);
            }
            Step::ProbeGet => self.on_probe(c),
            // The pipe is opened by `starting`, which has the session.
            Step::CommitSet => {
                if c.status != Status::Ok {
                    self.fail(Fail::Negotiation);
                }
            }
            Step::SetAlt => {
                if c.status != Status::Ok {
                    return self.fail(Fail::Transport);
                }
                self.alt_set = true;
                self.begin_streaming();
            }
            Step::ClearHalt => {
                if c.status != Status::Ok {
                    return self.fail(Fail::Transport);
                }
                self.halted = false;
                for i in 0..BUFS {
                    if !self.inflight[i] {
                        self.submit_buf(i);
                    }
                }
            }
            // The device may not answer a request on an interface it has
            // already lost; either way the stream is down.
            Step::AltZero => {
                self.alt_set = false;
                self.stopped();
            }
        }
    }

    fn on_config(&mut self, c: Completion) {
        let Some(buf) = self.ctlbuf else { return };
        if c.status != Status::Ok || c.actual < 9 {
            return self.fail(Fail::Transport);
        }
        let total = (c.actual as usize).min(CFG_MAX);
        self.mem.from_device(buf.cpu().wrapping_add(CFG_OFF), total);
        let s = survey(total, &mut |off, out| buf.read_bytes(CFG_OFF + off, out), self.vs_iface, &self.want);
        let Some(best) = s.best else { return self.fail(Fail::NoFormat) };
        if !s.streaming || s.alts().iter().all(|a| a.address == 0) {
            return self.fail(Fail::NoEndpoint);
        }
        self.survey = s;
        self.choice = Some(best);
        self.block_len = block_len(s.bcd_uvc);
        let req = request_block(&best);
        buf.write_bytes(OUT_OFF, &req[..self.block_len]);
        let setup = self.class_request(true, VS_PROBE_CONTROL, self.block_len);
        self.ctl_submit(Step::ProbeSet, setup, self.block_len);
    }

    fn on_probe(&mut self, c: Completion) {
        let (Some(buf), Some(mut choice)) = (self.ctlbuf, self.choice) else { return };
        if c.status != Status::Ok {
            return self.fail(Fail::Negotiation);
        }
        let n = (c.actual as usize).min(BLOCK_MAX);
        self.mem.from_device(buf.cpu().wrapping_add(IN_OFF), n);
        let mut block = [0u8; BLOCK_MAX];
        buf.read_bytes(IN_OFF, &mut block[..n]);
        let Some(neg) = parse_block(&block[..n]) else { return self.fail(Fail::Negotiation) };
        if neg.format_index != choice.format_index || neg.frame_index != choice.frame_index || neg.max_payload == 0 {
            return self.fail(Fail::Negotiation);
        }
        // The camera's interval is the one it will stream at.
        if neg.interval != 0 {
            choice.interval = neg.interval;
        }
        self.choice = Some(choice);
        let Some(mode) = pick_mode(&self.survey, neg.max_payload) else {
            let any = self.survey.alts().iter().any(|a| a.address != 0);
            return self.fail(if any { Fail::Bandwidth } else { Fail::NoEndpoint });
        };
        let len = match mode {
            Mode::Isoch { bytes, .. } => bytes,
            Mode::Bulk { mps, .. } => neg.max_payload.next_multiple_of(mps.max(1) as u32).clamp(mps as u32, BULK_XFER_MAX),
        };
        if let Err(f) = self.alloc_stream(len) {
            return self.fail(f);
        }
        self.mode = Some(mode);
        self.neg_block = block;
        self.state = State::Ready;
    }

    /// The transfer buffers: [`BUFS`] of `len` bytes in one region, each
    /// placed so that it does not cross a 64 KiB boundary of bus addresses.
    fn alloc_stream(&mut self, len: u32) -> Result<(), Fail> {
        let stride = (len as usize).next_multiple_of(128);
        // Each buffer takes its stride and, when it is moved to the next
        // boundary, less than its length more.
        let size = (BUFS * (stride + len as usize)).next_multiple_of(PAGE);
        let region = self.mem.alloc_region(size, PAGE, self.mask).ok_or(Fail::NoMemory)?;
        let mut off = 0usize;
        for o in self.offs.iter_mut() {
            let at = ((region.bus() + off as u64) & 0xffff) as usize;
            if at + len as usize > 0x1_0000 {
                off += 0x1_0000 - at;
            }
            *o = off as u32;
            off += stride;
        }
        debug_assert!(off <= region.len());
        self.mem.to_device(region.cpu(), region.len());
        self.bufs = Some(region);
        self.xfer_len = len;
        Ok(())
    }

    // ---- Starting and stopping the stream ----

    /// The sink is wanted: commit what was negotiated.
    fn start(&mut self, now: u64) {
        let Some(buf) = self.ctlbuf else { return };
        self.state = State::Starting;
        self.pipe_open = false;
        self.alt_set = false;
        self.halted = false;
        self.last_progress_us = now;
        buf.write_bytes(OUT_OFF, &self.neg_block[..self.block_len]);
        let setup = self.class_request(true, VS_COMMIT_CONTROL, self.block_len);
        self.ctl_submit(Step::CommitSet, setup, self.block_len);
    }

    /// After the commit: open the streaming pipe, select the setting.
    fn starting(&mut self, dev: Option<&mut dyn UsbDevice>) {
        if self.step.is_some() || self.pipe_open {
            return;
        }
        let (Some(dev), Some(mode)) = (dev, self.mode) else { return };
        let (ep, alt) = match mode {
            Mode::Bulk { endpoint, .. } => (endpoint, 0),
            Mode::Isoch { endpoint, alt, .. } => (endpoint, alt),
        };
        // The pipe is opened on the setting's endpoint: its parameters are
        // that setting's (`pipe_open` takes the setting in bits 15:8).
        match open_one(dev, self.rings, ep as u32 | (alt as u32) << 8) {
            Some(e) => self.stream = Some(e),
            None => return self.fail(Fail::Pipe),
        }
        self.pipe_open = true;
        match mode {
            Mode::Bulk { .. } => self.begin_streaming(),
            Mode::Isoch { alt, .. } => {
                let setup = self.set_interface(alt);
                self.ctl_submit(Step::SetAlt, setup, 0);
            }
        }
    }

    /// Everything is set: put the transfers out.
    fn begin_streaming(&mut self) {
        self.reset_assembly();
        self.inflight = [false; BUFS];
        self.state = State::Streaming;
        self.last_progress_us = self.clock.now_us();
        self.idle_since_us = None;
        for i in 0..BUFS {
            self.submit_buf(i);
        }
    }

    /// Close the pipe, go back to setting 0, and be `Ready` again.
    fn stopping(&mut self, mut dev: Option<&mut dyn UsbDevice>) {
        self.abort_frame();
        if self.pipe_open {
            self.close_stream(reborrow(&mut dev));
            if self.pipe_open {
                return;
            }
        }
        if self.step.is_some() {
            return;
        }
        if self.alt_set && dev.is_some() {
            let setup = self.set_interface(0);
            self.ctl_submit(Step::AltZero, setup, 0);
        } else {
            self.alt_set = false;
            self.stopped();
        }
    }

    /// Close the streaming pipe, if there is a session to do it with. The
    /// setting stays selected: the camera is not told, only the controller.
    fn close_stream(&mut self, dev: Option<&mut dyn UsbDevice>) {
        let Some(dev) = dev else { return };
        if let Some(mut e) = self.stream.take() {
            let id = e.id;
            let _ = dev.pipe_close(id as u32);
            // What the core completed on its way out is of no use now.
            while e.cq.pop().is_some() {}
        }
        self.pipe_open = false;
        self.inflight = [false; BUFS];
        self.halted = false;
    }

    fn stopped(&mut self) {
        if self.state == State::Stopping {
            self.state = State::Ready;
        }
    }

    /// A stall in the stream: stop and start again, a few times.
    fn restart(&mut self, now: u64) {
        self.stats.restarts += 1;
        self.restarts_in_a_row += 1;
        self.last_progress_us = now;
        if self.restarts_in_a_row > MAX_RESTARTS {
            return self.fail(Fail::NoFrames);
        }
        self.state = State::Stopping;
    }

    // ---- The stream ----

    fn submit_buf(&mut self, i: usize) {
        if self.halted || self.state != State::Streaming {
            return;
        }
        let (Some(buf), Some(s)) = (self.bufs.as_ref(), self.stream.as_mut()) else { return };
        let t = Transfer { tag: i as u32, dir: Dir::In, setup: [0; 8], buf: buf.bus_at(self.offs[i] as usize), len: self.xfer_len };
        if matches!(s.sq.push(t), Push::Pushed) {
            self.inflight[i] = true;
        } else {
            self.fail(Fail::Transport);
        }
    }

    /// Take the completions of the stream: each is one payload (or one
    /// lost interval), and its buffer goes out again.
    fn reap_stream(&mut self, now: u64) {
        loop {
            let Some(c) = self.stream.as_mut().and_then(|e| e.cq.pop()) else { break };
            let i = c.tag as usize;
            if i >= BUFS {
                continue;
            }
            self.inflight[i] = false;
            if self.state != State::Streaming {
                continue;
            }
            self.last_progress_us = now;
            match c.status {
                Status::Ok => {
                    if c.actual > 0 {
                        self.payload(i, c.actual as usize);
                    }
                    self.submit_buf(i);
                }
                Status::Stall => self.halted = true,
                // A bus error loses that interval; a camera that was reset
                // under us completes its stopped transfers this way.
                Status::Transaction | Status::Babble | Status::Other(_) => {
                    self.stats.lost += 1;
                    self.lose_data();
                    self.submit_buf(i);
                }
                Status::Disconnected => {}
                Status::Bounce | Status::Denied | Status::Invalid => return self.fail(Fail::Pipe),
            }
        }
        // A halted bulk endpoint is cleared on the device side too, then the
        // buffers go out again.
        if self.halted && self.state == State::Streaming && self.step.is_none() {
            if let Some(Mode::Bulk { endpoint, .. }) = self.mode {
                self.ctl_submit(Step::ClearHalt, Setup::clear_halt(endpoint), 0);
            }
        }
    }

    /// One payload, `actual` bytes in buffer `i`.
    fn payload(&mut self, i: usize, actual: usize) {
        let Some(buf) = self.bufs else { return };
        let at = self.offs[i] as usize;
        self.mem.from_device(buf.cpu().wrapping_add(at), actual);
        let mut head = [0u8; HEADER_MAX];
        let n = actual.min(HEADER_MAX);
        buf.read_bytes(at, &mut head[..n]);
        let Some(h) = parse_header(&head[..n]) else {
            self.stats.bad_headers += 1;
            self.lose_data();
            return;
        };
        if h.still {
            return;
        }
        self.stats.payloads += 1;
        self.assemble(&h, &buf, at + h.len, actual - h.len);
    }

    // ---- Frames ----

    /// Data of the stream was lost (a payload the bus dropped, a header that
    /// does not parse): the frame being assembled is spoilt, or, between two
    /// frames, the next one is (its first payload may be the one that is
    /// gone).
    fn lose_data(&mut self) {
        if self.phase == Phase::InFrame {
            self.frame.bad = true;
        } else {
            self.hole = true;
        }
    }

    fn reset_assembly(&mut self) {
        self.hole = false;
        self.abort_frame();
        self.phase = if cfg!(feature = "canary-uvc-sync") { Phase::Between } else { Phase::Syncing };
        self.fid_known = false;
        self.eof_seen = false;
    }

    /// Give the slot back, publishing nothing.
    fn abort_frame(&mut self) {
        if self.frame.slot.take().is_some() {
            self.sink.abort();
        }
        self.frame = Frame { slot: None, len: 0, bad: false };
    }

    /// Fold payload `h` with `len` data bytes at `data` of `buf` into the
    /// frame being assembled.
    fn assemble(&mut self, h: &Header, buf: &DmaBuf, data: usize, len: usize) {
        // The first payload tells nothing: a stream that starts in the middle
        // of a frame has the FID of that frame.
        let toggled = self.fid_known && h.fid != self.last_fid && !cfg!(feature = "canary-uvc-fid");
        let eof_before = self.eof_seen;
        self.fid_known = true;
        self.last_fid = h.fid;
        self.eof_seen |= h.eof;
        match self.phase {
            Phase::Syncing => {
                if toggled {
                    // The start of a frame; what came before was the end of
                    // one, which is dropped.
                    self.stats.dropped += 1;
                    self.begin_frame();
                } else {
                    if h.eof {
                        self.stats.dropped += 1;
                        self.phase = Phase::Between;
                    }
                    return;
                }
            }
            Phase::Between => self.begin_frame(),
            Phase::InFrame => {
                if toggled {
                    // The previous frame had no EOF: a camera that never
                    // sets one ends its frames here; one that does has lost
                    // the tail of this one.
                    self.end_frame(!eof_before);
                    self.begin_frame();
                }
            }
        }
        if h.err {
            self.frame.bad = true;
        }
        self.append(buf, data, len);
        if h.eof {
            self.end_frame(true);
            self.phase = Phase::Between;
        }
    }

    fn begin_frame(&mut self) {
        self.phase = Phase::InFrame;
        let sink = self.sink;
        let bad = core::mem::take(&mut self.hole);
        self.frame = match sink.claim() {
            Some(slot) => Frame { slot: Some(slot), len: 0, bad },
            None => {
                self.stats.refused += 1;
                Frame { slot: None, len: 0, bad }
            }
        };
    }

    fn append(&mut self, buf: &DmaBuf, data: usize, len: usize) {
        let f = &mut self.frame;
        let Some(slot) = f.slot.as_deref_mut() else { return };
        if f.bad || len == 0 {
            return;
        }
        // A JPEG the consumer cannot carry is as good as one the slot cannot.
        let cap = match self.choice {
            Some(Choice { pixels: Pixels::Mjpeg, .. }) => slot.len().min(self.want.max_jpeg),
            _ => slot.len(),
        };
        if f.len + len > cap {
            f.bad = true;
            self.stats.oversize += 1;
            return;
        }
        buf.read_bytes(data, &mut slot[f.len..f.len + len]);
        f.len += len;
    }

    /// The frame ends: committed if `complete` and whole, dropped otherwise.
    fn end_frame(&mut self, complete: bool) {
        let Some(slot) = self.frame.slot.take() else { return };
        let len = self.frame.len;
        let ok = complete && !self.frame.bad && self.whole(&slot[..len]);
        self.frame = Frame { slot: None, len: 0, bad: false };
        match (ok, self.choice) {
            (true, Some(c)) => {
                let info = match c.pixels {
                    Pixels::Mjpeg => FrameInfo::JPEG,
                    Pixels::Yuyv => FrameInfo::yuyv(c.width, c.height),
                };
                self.sink.commit(len, (self.stamp)(), info);
                self.stats.frames += 1;
                self.restarts_in_a_row = 0;
            }
            _ => {
                self.sink.abort();
                self.stats.dropped += 1;
            }
        }
    }

    /// Is `frame` a frame of the negotiated format: a JPEG starts with SOI,
    /// raw pixels are all of them.
    fn whole(&self, frame: &[u8]) -> bool {
        match self.choice {
            Some(Choice { pixels: Pixels::Mjpeg, .. }) => frame.len() >= 4 && frame[..2] == [0xff, 0xd8],
            Some(Choice { pixels: Pixels::Yuyv, width, height, .. }) => frame.len() == 2 * width as usize * height as usize,
            None => false,
        }
    }

    // ---- Failure and unplug ----

    fn fail(&mut self, f: Fail) {
        self.abort_frame();
        self.step = None;
        self.state = State::Failed(f);
    }

    /// The device is gone and the core has released the pipes: drain what is
    /// left, let go of the ring ends and the memory, forget the camera.
    fn cleanup(&mut self) {
        self.abort_frame();
        for mut e in [self.ctl.take(), self.stream.take()].into_iter().flatten() {
            while e.cq.pop().is_some() {}
        }
        for b in [self.ctlbuf.take(), self.bufs.take()].into_iter().flatten() {
            self.mem.free_region(b);
        }
        self.step = None;
        self.choice = None;
        self.mode = None;
        self.survey = Survey::new();
        self.inflight = [false; BUFS];
        self.halted = false;
        self.pipe_open = false;
        self.alt_set = false;
        self.idle_since_us = None;
        self.restarts_in_a_row = 0;
        self.claim = None;
        self.gone = false;
        self.state = State::Idle;
    }
}

/// `dev` lent for one call.
fn reborrow<'a>(dev: &'a mut Option<&mut dyn UsbDevice>) -> Option<&'a mut dyn UsbDevice> {
    match dev {
        Some(d) => Some(&mut **d),
        None => None,
    }
}

/// Open the pipe of endpoint `ep` (0: control; bits 15:8 the setting) and
/// take the driver's ends of its rings.
fn open_one<'q>(dev: &mut dyn UsbDevice, rings: &'q [PipeRings], ep: u32) -> Option<PipeEnd<'q>> {
    let p = dev.pipe_open(ep);
    if p.code != OK {
        return None;
    }
    let id = p.value as u8;
    match rings.get(id as usize).and_then(|r| PipeEnd::take(r, id)) {
        Some(e) => Some(e),
        None => {
            let _ = dev.pipe_close(id as u32);
            None
        }
    }
}

impl<M: Memory, C: Clock, S: FrameSink> UsbClass for Uvc<'_, M, C, S> {
    fn attach(&mut self, claim: u32, _vid_pid: u32, triple: u32, _speed_port: u32) -> Out<u32> {
        // Protocol 0 is UVC 1.0 and 1.1, 1 is UVC 1.5.
        if (triple >> 16) as u8 != CLASS_VIDEO || (triple >> 8) as u8 != SC_STREAMING || (triple as u8) > 1 {
            return Out::new(UNSUPPORTED, 0);
        }
        if self.state != State::Idle || self.gone {
            self.stats.declined += 1;
            return Out::new(BUSY, 0);
        }
        let c = Claim(claim);
        if c.is_device_scope() {
            return Out::new(BAD_ARGUMENT, 0);
        }
        self.claim = Some(c);
        self.state = State::Claimed;
        Out::new(OK, 0)
    }

    fn detach(&mut self, claim: u32) -> Out<u32> {
        if self.claim == Some(Claim(claim)) {
            // The core killed the pipes: what was queued completes as
            // disconnected, and the ring ends are let go of by `service`.
            self.gone = true;
            self.state = State::Failed(Fail::Gone);
        }
        Out::new(OK, 0)
    }
}

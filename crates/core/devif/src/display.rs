// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The `Display` interface: a connector, the modes it offers, and a way for a
//! display server to put pixels on it.
//!
//! The kernel hosts it (`endpoint = "display.<n>"`, badge `n + 1`: connector
//! `n`, below [`CONNECTORS`]). Today one connector is backed, connector 0, by
//! whatever scanout the platform has (the generic framebuffer of
//! `azos_fb`: QEMU ramfb, the Limine framebuffer, a device-tree
//! `simple-framebuffer`, virtio-gpu); the other connectors answer
//! `NO_RESOURCE`. A board with a display controller of its own serves the
//! same trait from its driver's endpoint and the client does not know which.
//! The kernel's server reaches the screen through [`Scanout`], which the
//! framebuffer crate implements (`azos_fb::scanout`).
//!
//! `READ` observes the connector ([`Display::connector`], [`Display::mode`]);
//! `WRITE` draws ([`Display::surface`], [`Display::present`], ...); `EXEC`
//! takes and gives back the screen ([`Display::claim`], [`Display::release`]).
//! A display server holds all three. Presenting is not an actuation, so the
//! `WRITE` of this endpoint is checked by the capability's right alone: a
//! contained system keeps presenting the surfaces it has, because the operator's
//! screen is where it says so. Containment still applies to the capabilities an
//! op takes: attaching a band (a `WRITE` memory object) or a vsync port (a
//! `WRITE` port) is refused while the system is contained, so a display server
//! sets its surfaces up before it needs them.
//!
//! # The model
//!
//! * **Mode.** The scanout runs ONE mode, the one the platform set at boot;
//!   [`Mode`] index 0 is that mode (flag [`MODE_CURRENT`]). The rest of the
//!   list is what the display's EDID offers (`azos_fb::edid`), preferred one
//!   flagged [`MODE_PREFERRED`]. There is no op that changes the mode: the
//!   scanouts the kernel drives cannot, and an op nothing implements is not
//!   added. A driver that can adds `set_mode` with its first user.
//! * **Surface.** A client image of the whole screen, in the scanout's pixel
//!   format and the current mode's size, so a rectangle of it sits at the same
//!   coordinates on the screen: there is no conversion and no scaling in the
//!   kernel. [`Display::surface`] creates it (row stride, format); the pixels
//!   are attached to it in **bands**, one memory object each ([`Display::band`]):
//!   a memory object holds at most 64 pages (`MAX_MEMOBJ_PAGES`: 256 KiB on a
//!   4 KiB granule, one bit per page of its copy-on-write state), so no
//!   screen fits one. A band is a read-write, physically contiguous
//!   (`MemKind::Contig`) object the server made; it holds `floor(bytes /
//!   stride)` whole rows and covers the next rows of the surface, the last
//!   band only what is left ([`band_take`]). The surface can be presented once
//!   its bands cover every row. At most [`SURFACES`] surfaces of at most
//!   [`BANDS_MAX`] bands are attached at a time.
//!
//!   **What a surface costs.** One slot of the system-wide MemObj table (Kconfig
//!   `MAX_MEMOBJS`, 16 by default, 256 at most, and a task may own half of
//!   them) per band: a 1920x1080 XRGB8888 surface is 8,294,400 bytes, 32
//!   bands of 64 pages on a 4 KiB granule (8 on a 16 KiB one), so a
//!   double-buffered full-HD server needs `MAX_MEMOBJS` of at least 128 on
//!   x86_64 and riscv64. That is the object model's limit, not this
//!   interface's; a band kind with more pages (or the `Phys` kind the
//!   memory-object module reserves for the scanout) lifts it, and this
//!   interface is the same with fewer, larger bands.
//! * **Present.** [`Display::present`] copies up to [`DAMAGE_MAX`] damage
//!   rectangles of a complete surface onto the scanout and tells the display what
//!   changed (the flip hook of a source that scans out a copy). The reply is
//!   the frame number. The copy happens in the call, on the caller's own
//!   stack; it is bounded by the rectangles, which a call carries in its
//!   message and never by address.
//! * **Vsync.** [`Display::vsync`] attaches a port and a key. The kernel posts
//!   one event on it for each frame put on the screen: `source_type`
//!   `PORT_EVENT_TIMER`, `key` the one given, `source_id` the frame number
//!   (low 32 bits) the matching `present` answered. This is the pacing a
//!   display server draws by: draw the next frame when the last one is
//!   shown. It is posted when `present` has finished handing the frame to the
//!   scanout (for a source that copies, when the flip hook has returned), not
//!   at a hardware vertical blank: no scanout the kernel drives reports
//!   one yet. A driver that has a vblank interrupt posts the same event from it.
//!
//! # Handover
//!
//! The kernel's text console draws on the same screen. [`Display::claim`]
//! retires it: its grid keeps taking the kernel's output, nothing is drawn
//! until [`Display::release`] (or the death of the claim's holder) hands the
//! screen back and the console redraws. One task holds the claim; it is the
//! one that may attach surfaces, present and attach the vsync port, and a
//! second claimant gets `BUSY`. The panic screen is not part of this: a panic
//! owns the screen whatever a server is doing.
//!
//! # Failure contract
//!
//! The kernel serves the whole interface on the caller's stack, so a call
//! returns or the caller is dead; there is no server to lose a reply.
//! `connector` and `mode` answer `NOT_READY` when the platform has no
//! scanout. `surface` and `band` are `at_most_once`: a surface made twice is
//! two surfaces. `present` is idempotent (the same rectangles show the same
//! pixels, and the event counts a frame again). The time bounds below are for
//! a full-HD frame and are not measured.

use crate::outcome::{self, Out};
use azos_idl::{azos_interface, Cap, Reader, Wire, Writer};
use core::sync::atomic::AtomicU8;

/// The interface id (ASCII "DISP").
pub const DISPLAY_ID: u32 = 0x4449_5350;

/// Connectors the interface can name.
pub const CONNECTORS: u32 = 4;
/// Surfaces a display server may have at once.
pub const SURFACES: usize = 4;
/// Bands one surface can have: a task owns at most 128 memory objects (half of
/// the table's 256), so no surface needs more.
pub const BANDS_MAX: usize = 128;
/// Damage rectangles one [`Display::present`] carries.
pub const DAMAGE_MAX: usize = 6;

/// The badge of `display.<n>`.
pub const fn connector_badge(n: u32) -> u32 {
    n + 1
}

/// What a `Cap<SurfaceBand>` names: a read-write, physically contiguous memory
/// object of the caller's that holds whole rows of a surface's pixels.
pub struct SurfaceBand;
/// What a `Cap<VsyncPort>` names: a port (`WRITE`) that gets a frame event.
pub struct VsyncPort;

/// [`ConnectorInfo::format`], [`Display::surface`]: 32 bits, `0x00RRGGBB` in a
/// little-endian word (blue in the first byte).
pub const FORMAT_XRGB8888: u32 = 1;
/// 32 bits, `0x00BBGGRR` (red in the first byte).
pub const FORMAT_XBGR8888: u32 = 2;
/// 24 bits, blue in the first byte.
pub const FORMAT_RGB888: u32 = 3;
/// 16 bits, `RRRRRGGGGGGBBBBB`.
pub const FORMAT_RGB565: u32 = 4;

/// Bytes per pixel of a format; `None` for a value that is not one.
pub const fn format_bytes(format: u32) -> Option<u32> {
    match format {
        FORMAT_XRGB8888 | FORMAT_XBGR8888 => Some(4),
        FORMAT_RGB888 => Some(3),
        FORMAT_RGB565 => Some(2),
        _ => None,
    }
}

/// [`ConnectorInfo::flags`]: a display is behind the connector (a scanout is
/// registered).
pub const CONN_CONNECTED: u32 = 1 << 0;
/// [`ConnectorInfo::flags`]: the mode list comes from the display's EDID; else
/// it is the one mode the scanout runs.
pub const CONN_EDID: u32 = 1 << 1;
/// [`ConnectorInfo::flags`]: some task holds the claim.
pub const CONN_CLAIMED: u32 = 1 << 2;
/// [`ConnectorInfo::flags`]: the caller holds the claim.
pub const CONN_YOURS: u32 = 1 << 3;

/// [`Mode::flags`]: the mode the scanout runs now.
pub const MODE_CURRENT: u32 = 1 << 0;
/// [`Mode::flags`]: the display's preferred mode.
pub const MODE_PREFERRED: u32 = 1 << 1;

/// Refresh rate reported for a scanout whose source did not say (millihertz).
pub const DEFAULT_REFRESH_MHZ: u32 = 60_000;

/// A rectangle of the screen in pixels. One word on the wire, so a damage
/// list fits a message; 16 bits per field, which is why a mode is at most
/// 65535 pixels on a side.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Rect {
    pub x: u16,
    pub y: u16,
    pub w: u16,
    pub h: u16,
}

impl Rect {
    pub const fn new(x: u16, y: u16, w: u16, h: u16) -> Rect {
        Rect { x, y, w, h }
    }

    /// The whole of a `width` x `height` screen (cut to what 16 bits hold).
    pub const fn full(width: u32, height: u32) -> Rect {
        Rect {
            x: 0,
            y: 0,
            w: if width > u16::MAX as u32 { u16::MAX } else { width as u16 },
            h: if height > u16::MAX as u32 { u16::MAX } else { height as u16 },
        }
    }

    /// Does it cover no pixel?
    pub const fn is_empty(&self) -> bool {
        self.w == 0 || self.h == 0
    }

    /// Is it non-empty and inside a `width` x `height` screen?
    pub const fn inside(&self, width: u32, height: u32) -> bool {
        !self.is_empty() && self.x as u32 + self.w as u32 <= width && self.y as u32 + self.h as u32 <= height
    }
}

impl Wire for Rect {
    const WORDS: usize = 1;
    const CAPS: usize = 0;
    fn put(&self, w: &mut Writer<'_>) {
        w.word(self.x as u64 | (self.y as u64) << 16 | (self.w as u64) << 32 | (self.h as u64) << 48);
    }
    fn get(r: &mut Reader<'_>) -> Self {
        let v = r.word();
        Rect { x: v as u16, y: (v >> 16) as u16, w: (v >> 32) as u16, h: (v >> 48) as u16 }
    }
}

/// What a connector is: the mode the scanout runs now and what is known of the
/// display.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ConnectorInfo {
    /// The current mode, pixels.
    pub width: u32,
    pub height: u32,
    /// Bytes per row of the scanout.
    pub stride: u32,
    /// `FORMAT_*` of the scanout; a surface must be in it.
    pub format: u32,
    /// Refresh rate of the current mode, millihertz.
    pub refresh_mhz: u32,
    /// `CONN_*`.
    pub flags: u32,
    /// Physical size of the picture in millimetres, 0 when unknown.
    pub width_mm: u32,
    pub height_mm: u32,
    /// Modes [`Display::mode`] lists.
    pub modes: u32,
    /// Surfaces [`Display::surface`] attaches at most.
    pub surfaces: u32,
}

impl Wire for ConnectorInfo {
    const WORDS: usize = 5;
    const CAPS: usize = 0;
    fn put(&self, w: &mut Writer<'_>) {
        for (a, b) in [
            (self.width, self.height),
            (self.stride, self.format),
            (self.refresh_mhz, self.flags),
            (self.width_mm, self.height_mm),
            (self.modes, self.surfaces),
        ] {
            w.word(a as u64 | (b as u64) << 32);
        }
    }
    fn get(r: &mut Reader<'_>) -> Self {
        let mut pair = || {
            let v = r.word();
            (v as u32, (v >> 32) as u32)
        };
        let (width, height) = pair();
        let (stride, format) = pair();
        let (refresh_mhz, flags) = pair();
        let (width_mm, height_mm) = pair();
        let (modes, surfaces) = pair();
        ConnectorInfo { width, height, stride, format, refresh_mhz, flags, width_mm, height_mm, modes, surfaces }
    }
}

impl ConnectorInfo {
    /// Is a surface with row stride `stride` and pixel format `format` one this
    /// connector's scanout can be fed from? `BAD_ARGUMENT` for: a format that
    /// is not the scanout's, a row shorter than the screen's pixels, or a
    /// stride past 1 MiB (no scanout has one). `NOT_READY` for a connector
    /// with no display behind it.
    pub fn check_surface(&self, stride: u32, format: u32) -> Result<(), u32> {
        if self.flags & CONN_CONNECTED == 0 || self.width == 0 || self.height == 0 {
            return Err(outcome::NOT_READY);
        }
        let Some(bpp) = format_bytes(format) else { return Err(outcome::BAD_ARGUMENT) };
        if format != self.format || (stride as u64) < self.width as u64 * bpp as u64 || stride > 1 << 20 {
            return Err(outcome::BAD_ARGUMENT);
        }
        Ok(())
    }
}

/// Whole rows of stride `stride` a band of `bytes` bytes holds.
pub const fn band_rows(stride: u32, bytes: u64) -> u64 {
    if stride == 0 { 0 } else { bytes / stride as u64 }
}

/// The rows a band of `bytes` bytes adds to a surface of `height` rows that
/// `covered` rows already have: all it holds, or what is left. `BUSY` for a
/// surface already complete, `BAD_ARGUMENT` for a band that holds no whole row.
pub fn band_take(height: u32, covered: u32, stride: u32, bytes: u64) -> Result<u32, u32> {
    if covered >= height {
        return Err(outcome::BUSY);
    }
    match band_rows(stride, bytes) {
        0 => Err(outcome::BAD_ARGUMENT),
        rows => Ok(rows.min((height - covered) as u64) as u32),
    }
}

/// One mode of a connector.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Mode {
    pub width: u32,
    pub height: u32,
    /// Refresh rate in millihertz.
    pub refresh_mhz: u32,
    /// `MODE_*`.
    pub flags: u32,
}

impl Wire for Mode {
    const WORDS: usize = 2;
    const CAPS: usize = 0;
    fn put(&self, w: &mut Writer<'_>) {
        w.word(self.width as u64 | (self.height as u64) << 32);
        w.word(self.refresh_mhz as u64 | (self.flags as u64) << 32);
    }
    fn get(r: &mut Reader<'_>) -> Self {
        let a = r.word();
        let b = r.word();
        Mode { width: a as u32, height: (a >> 32) as u32, refresh_mhz: b as u32, flags: (b >> 32) as u32 }
    }
}

/// A `present`: which surface, and what changed in it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Present {
    /// The surface id [`Display::surface`] answered.
    pub surface: u32,
    /// Rectangles of `rects` in use, `1..=`[`DAMAGE_MAX`].
    pub count: u32,
    pub rects: [Rect; DAMAGE_MAX],
}

impl Present {
    /// A present of `rects` (at most [`DAMAGE_MAX`]; `None` for more or for
    /// none) from `surface`.
    pub fn new(surface: u32, rects: &[Rect]) -> Option<Present> {
        if rects.is_empty() || rects.len() > DAMAGE_MAX {
            return None;
        }
        let mut p = Present { surface, count: rects.len() as u32, rects: [Rect::default(); DAMAGE_MAX] };
        p.rects[..rects.len()].copy_from_slice(rects);
        Some(p)
    }

    /// The rectangles in use.
    pub fn damage(&self) -> &[Rect] {
        &self.rects[..(self.count as usize).min(DAMAGE_MAX)]
    }

    /// Is the damage well formed for `info`'s screen? `BAD_ARGUMENT` for a count
    /// that is zero or past [`DAMAGE_MAX`] and for any rectangle that is empty
    /// or reaches outside the screen: a damage rectangle the client got wrong
    /// is its bug to see, not something to cut silently.
    pub fn check(&self, info: &ConnectorInfo) -> Result<(), u32> {
        if self.count == 0 || self.count as usize > DAMAGE_MAX {
            return Err(outcome::BAD_ARGUMENT);
        }
        if self.damage().iter().all(|r| r.inside(info.width, info.height)) {
            Ok(())
        } else {
            Err(outcome::BAD_ARGUMENT)
        }
    }
}

impl Wire for Present {
    const WORDS: usize = 1 + DAMAGE_MAX;
    const CAPS: usize = 0;
    fn put(&self, w: &mut Writer<'_>) {
        w.word(self.surface as u64 | (self.count as u64) << 32);
        for r in &self.rects {
            r.put(w);
        }
    }
    fn get(r: &mut Reader<'_>) -> Self {
        let head = r.word();
        let mut rects = [Rect::default(); DAMAGE_MAX];
        for slot in rects.iter_mut() {
            *slot = Rect::get(r);
        }
        Present { surface: head as u32, count: (head >> 32) as u32, rects }
    }
}

/// Who holds the claim on a connector: the handover's state, kept apart from
/// the kernel so that its rules are tested on the host.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Claim {
    holder: Option<u32>,
}

impl Claim {
    pub const fn new() -> Claim {
        Claim { holder: None }
    }

    /// The holder's task id, if any.
    pub const fn holder(&self) -> Option<u32> {
        self.holder
    }

    /// Take the claim for `tid`. `Ok(true)` when it was free, `Ok(false)` when
    /// `tid` held it already, `BUSY` when another task does.
    pub fn claim(&mut self, tid: u32) -> Result<bool, u32> {
        match self.holder {
            None => {
                self.holder = Some(tid);
                Ok(true)
            }
            Some(h) if h == tid => Ok(false),
            Some(_) => Err(outcome::BUSY),
        }
    }

    /// Give it back. `Ok(true)` when `tid` held it, `Ok(false)` when nobody
    /// did (nothing to give), `BUSY` when another task does.
    pub fn release(&mut self, tid: u32) -> Result<bool, u32> {
        match self.holder {
            None => Ok(false),
            Some(h) if h == tid => {
                self.holder = None;
                Ok(true)
            }
            Some(_) => Err(outcome::BUSY),
        }
    }

    /// May `tid` use the connector's drawing ops? `NOT_READY` when nobody holds
    /// the claim (claim first), `BUSY` when another task does.
    pub fn require(&self, tid: u32) -> Result<(), u32> {
        match self.holder {
            None => Err(outcome::NOT_READY),
            Some(h) if h == tid => Ok(()),
            Some(_) => Err(outcome::BUSY),
        }
    }
}

/// The screen behind connector 0 as the kernel's display server sees it. The
/// framebuffer driver (`azos_fb::scanout`) implements it; the kernel registers
/// it with the server (`azos_syscall::display::set_scanout`) when a scanout
/// exists. The seam is a trait so that the syscall crate, which is part of the
/// certified partition, does not depend on the framebuffer crate, which is
/// scaffolding (`tools/lint/tcb_check.sh`); a board whose display controller is a
/// driver of its own implements it the same way.
pub trait Scanout: Sync {
    /// The connector as the scanout runs it: geometry, stride, pixel format,
    /// refresh, the display's size and the number of modes, with
    /// [`CONN_CONNECTED`] (and [`CONN_EDID`] when the modes come from an EDID)
    /// in `flags`. `None` when no display is behind the connector. The claim
    /// flags are the server's.
    fn connector(&self) -> Option<ConnectorInfo>;
    /// Mode `index` of the connector ([`Display::mode`] answers it).
    fn mode(&self, index: u32) -> Option<Mode>;
    /// Copy `rect` of the image `src` (rows `stride` bytes apart, its first
    /// row screen row `top`) onto the scanout. `false` when the copy was
    /// refused: nothing was copied.
    ///
    /// `src` is memory another party may write while it is read (a display
    /// client's surface), so it is atomics, not `&[u8]`: the slice keeps it
    /// mapped for the call, and its bytes may change meanwhile.
    fn copy_rect(&self, src: &[AtomicU8], stride: u32, top: u32, rect: Rect) -> bool;
    /// `rect` was drawn: tell the display (the flip hook of a source that
    /// scans out a copy; nothing for a scanout the CPU draws into directly).
    fn flip(&self, rect: Rect);
    /// Does a panic own the screen? Nothing may draw over it then.
    fn panic_active(&self) -> bool;
    /// Stop drawing the kernel's text console. `false` when it was stopped
    /// already.
    fn retire_console(&self) -> bool;
    /// Let the text console draw again, the whole grid. `false` when it was
    /// not stopped.
    fn resume_console(&self) -> bool;
}

#[azos_interface(id = 0x4449_5350, level = 1)]
pub trait Display {
    /// The connector: the current mode, the scanout's stride and pixel format,
    /// the display's physical size, and how many modes and surfaces there are.
    /// `NOT_READY` when the platform has no scanout. Needs `READ`.
    #[idempotent]
    #[on_failure(degrade)]
    fn connector(&self) -> Out<ConnectorInfo>;
    /// Mode `index` of the connector (0 is the current one; `BAD_ARGUMENT`
    /// from [`ConnectorInfo::modes`] on). Needs `READ`.
    #[idempotent]
    #[on_failure(degrade)]
    fn mode(&self, index: u32) -> Out<Mode>;
    /// Take the screen: retire the kernel's text console and become the task
    /// that may attach surfaces and present. `BUSY` when another task holds
    /// it, `NOT_READY` without a scanout; claiming again is `OK`. Needs `EXEC`.
    #[idempotent]
    #[on_failure(degrade)]
    fn claim(&mut self) -> Out<()>;
    /// Give the screen back: surfaces and the vsync port are let go, the text
    /// console redraws. `OK` when nobody holds the claim, `BUSY` when another
    /// task does. Needs `EXEC`.
    #[idempotent]
    #[on_failure(degrade)]
    fn release(&mut self) -> Out<()>;
    /// Create a surface with row stride `stride` (bytes) and pixel format
    /// `format` (`FORMAT_*`, the scanout's): an image of the current mode's
    /// size with no pixels yet ([`Display::band`] adds them). Answers the
    /// surface id (1..=[`SURFACES`]). `BAD_ARGUMENT` for a stride or format
    /// [`ConnectorInfo::check_surface`] refuses; `BUSY` when [`SURFACES`]
    /// exist; `NOT_READY` without the claim. Needs `WRITE`.
    #[at_most_once]
    #[on_failure(degrade)]
    fn surface(&mut self, stride: u32, format: u32) -> Out<u32>;
    /// Attach the memory object `mem` as the next band of surface `id`: the
    /// rows after the ones it has. The object is a read-write, physically
    /// contiguous memory object the caller holds with `READ | WRITE`, holding at
    /// least one row ([`band_take`]); the kernel pins it and keeps its own reference until
    /// [`Display::destroy_surface`] or the release. Answers the rows the
    /// surface has now. `BAD_ARGUMENT` for a handle that is not such an
    /// object; `BUSY` when the surface is complete, has [`BANDS_MAX`] bands, or
    /// the object is a band already; `NO_RESOURCE` for an id that does not
    /// exist; `NOT_READY` without the claim. Needs `WRITE`.
    #[at_most_once]
    #[on_failure(degrade)]
    fn band(&mut self, id: u32, mem: Cap<SurfaceBand>) -> Out<u32>;
    /// Let go of surface `id` and the kernel's reference on every band.
    /// `NO_RESOURCE` for an id that does not exist. Needs `WRITE`.
    #[at_most_once]
    #[on_failure(degrade)]
    fn destroy_surface(&mut self, id: u32) -> Out<()>;
    /// Copy the damage rectangles of a complete surface onto the screen and
    /// tell the display what changed. Answers the frame number (counts from 1 at each
    /// claim). `BAD_ARGUMENT` for a damage list [`Present::check`] refuses;
    /// `NO_RESOURCE` for a surface that does not exist; `NOT_READY` for one
    /// whose bands do not cover every row yet; `BUSY` while a panic owns the
    /// screen; `FAULT` when the copy of a band the damage touches is refused
    /// (a kernel accounting error: a surface the checks passed is always
    /// copyable). Needs `WRITE`.
    #[idempotent]
    #[on_failure(degrade)]
    #[deadline_ns = 20_000_000]
    #[budget_us = 10_000]
    fn present(&mut self, request: Present) -> Out<u64>;
    /// Attach the port `events` (a port held with `WRITE`) that gets a frame
    /// event carrying `key` for each frame put on the screen. Replaces a port
    /// attached before. `BAD_ARGUMENT` for a handle that is not such a port.
    /// Needs `WRITE`.
    #[idempotent]
    #[on_failure(degrade)]
    fn vsync(&mut self, events: Cap<VsyncPort>, key: u64) -> Out<()>;
}

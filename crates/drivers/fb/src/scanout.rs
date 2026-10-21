// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The registered framebuffer as the `Display` interface's scanout
//! (`azos_devif::Scanout`): what the kernel's display server reads the
//! connector from and draws onto.
//!
//! The kernel registers [`SCANOUT`] with the server when a framebuffer
//! exists. The connector is the framebuffer's geometry and format; its mode
//! list is that one mode first, then what the display's EDID offers
//! ([`publish_edid`], parsed by [`crate::edid`]), less the entry that is the
//! current mode. The framebuffer runs the one mode the platform set at boot:
//! there is no way to change it, so the other modes are information.

use crate::edid::{self, Edid};
use crate::pixel::PixelFormat;
use azos_devif::display::{
    self, ConnectorInfo, Mode, Scanout, CONN_CONNECTED, CONN_EDID, DEFAULT_REFRESH_MHZ, FORMAT_RGB565, FORMAT_RGB888,
    FORMAT_XBGR8888, FORMAT_XRGB8888, MODE_CURRENT, MODE_PREFERRED,
};
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, Ordering};

/// The registered framebuffer as a scanout.
pub struct FbScanout;

/// The one scanout of this build.
pub static SCANOUT: FbScanout = FbScanout;

struct Slot {
    lock: AtomicBool,
    edid: UnsafeCell<Option<Edid>>,
}

// SAFETY: every access holds `lock`.
unsafe impl Sync for Slot {}

static EDID: Slot = Slot { lock: AtomicBool::new(false), edid: UnsafeCell::new(None) };

/// The EDID published, copied out.
fn published() -> Option<Edid> {
    while EDID.lock.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed).is_err() {
        core::hint::spin_loop();
    }
    // SAFETY: the lock is held.
    let e = unsafe { *EDID.edid.get() };
    EDID.lock.store(false, Ordering::Release);
    e
}

/// Hand over the EDID of the display behind the framebuffer. The producer is
/// the virtio-gpu driver's `GET_EDID` answer (`kernel/src/boot/fb.rs`); another
/// source (a loader's EDID, a DDC read) calls this when it exists. `false` when the blob is
/// not one [`edid::parse`] trusts; the connector keeps its previous modes
/// then.
pub fn publish_edid(blob: &[u8]) -> bool {
    let Ok(e) = edid::parse(blob) else { return false };
    while EDID.lock.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed).is_err() {
        core::hint::spin_loop();
    }
    // SAFETY: the lock is held.
    unsafe { *EDID.edid.get() = Some(e) };
    EDID.lock.store(false, Ordering::Release);
    true
}

/// `FORMAT_*` of a pixel format, 0 for one the interface does not name (no
/// surface can then match, and a client sees why).
fn format_code(f: &PixelFormat) -> u32 {
    if *f == PixelFormat::XRGB8888 {
        FORMAT_XRGB8888
    } else if *f == PixelFormat::XBGR8888 {
        FORMAT_XBGR8888
    } else if *f == PixelFormat::RGB888 {
        FORMAT_RGB888
    } else if *f == PixelFormat::RGB565 {
        FORMAT_RGB565
    } else {
        0
    }
}

/// The refresh rate the current `width` x `height` mode has. The framebuffer
/// does not know it (a boot framebuffer is programmed once, at 60 Hz in every
/// source the kernel has): the EDID entry of that size nearest to 60 Hz, else
/// [`DEFAULT_REFRESH_MHZ`].
fn refresh_of(width: u32, height: u32, edid: Option<&Edid>) -> u32 {
    edid.and_then(|e| {
        e.modes()
            .iter()
            .filter(|m| m.width as u32 == width && m.height as u32 == height)
            .min_by_key(|m| m.refresh_mhz.abs_diff(DEFAULT_REFRESH_MHZ))
    })
    .map_or(DEFAULT_REFRESH_MHZ, |m| m.refresh_mhz)
}

/// Mode `index` of a connector whose scanout runs `cur` (width, height,
/// millihertz): the current mode first, then the EDID's modes in its order,
/// less the one that is the current mode. `None` past the end.
fn mode_at(cur: (u32, u32, u32), edid: Option<&Edid>, index: u32) -> Option<Mode> {
    let preferred = edid.and_then(|e| e.preferred());
    // The current mode is the preferred one exactly when the two are equal.
    let is_pref = |w: u32, h: u32, mhz: u32| {
        preferred.is_some_and(|p| (p.width as u32, p.height as u32, p.refresh_mhz) == (w, h, mhz))
    };
    if index == 0 {
        let flags = MODE_CURRENT | if is_pref(cur.0, cur.1, cur.2) { MODE_PREFERRED } else { 0 };
        return Some(Mode { width: cur.0, height: cur.1, refresh_mhz: cur.2, flags });
    }
    edid?
        .modes()
        .iter()
        .filter(|m| (m.width as u32, m.height as u32, m.refresh_mhz) != cur)
        .nth(index as usize - 1)
        .map(|m| {
            let (w, h) = (m.width as u32, m.height as u32);
            let flags = if is_pref(w, h, m.refresh_mhz) { MODE_PREFERRED } else { 0 };
            Mode { width: w, height: h, refresh_mhz: m.refresh_mhz, flags }
        })
}

/// Modes [`mode_at`] lists.
fn mode_count(cur: (u32, u32, u32), edid: Option<&Edid>) -> u32 {
    1 + edid.map_or(0, |e| e.modes().iter().filter(|m| (m.width as u32, m.height as u32, m.refresh_mhz) != cur).count() as u32)
}

/// The scanout's current mode: width, height and refresh.
fn current(edid: Option<&Edid>) -> Option<(crate::FbInfo, (u32, u32, u32))> {
    let (fb, _) = crate::info()?;
    let cur = (fb.width, fb.height, refresh_of(fb.width, fb.height, edid));
    Some((fb, cur))
}

impl Scanout for FbScanout {
    fn connector(&self) -> Option<ConnectorInfo> {
        let e = published();
        let (fb, cur) = current(e.as_ref())?;
        let (width_mm, height_mm) = e.map_or((0, 0), |e| (e.width_mm, e.height_mm));
        Some(ConnectorInfo {
            width: fb.width,
            height: fb.height,
            stride: fb.stride,
            format: format_code(&fb.format),
            refresh_mhz: cur.2,
            flags: CONN_CONNECTED | if e.is_some() { CONN_EDID } else { 0 },
            width_mm,
            height_mm,
            modes: mode_count(cur, e.as_ref()),
            surfaces: display::SURFACES as u32,
        })
    }

    fn mode(&self, index: u32) -> Option<Mode> {
        let e = published();
        let (_, cur) = current(e.as_ref())?;
        mode_at(cur, e.as_ref(), index)
    }

    unsafe fn copy_rect(&self, src: *const u8, src_len: usize, stride: u32, top: u32, rect: display::Rect) -> bool {
        let Some(dst) = crate::surface() else { return false };
        let r = crate::Rect { x: rect.x as u32, y: rect.y as u32, w: rect.w as u32, h: rect.h as u32 };
        // SAFETY: the caller's promise about `src`.
        unsafe { crate::blit::copy_rect_raw(&dst, src, src_len, stride as usize, top as usize, r) }.is_some()
    }

    fn flip(&self, rect: display::Rect) {
        crate::flip(crate::Rect { x: rect.x as u32, y: rect.y as u32, w: rect.w as u32, h: rect.h as u32 });
    }

    fn panic_active(&self) -> bool {
        crate::panic_active()
    }

    fn retire_console(&self) -> bool {
        crate::retire_console()
    }

    fn resume_console(&self) -> bool {
        crate::resume_console()
    }
}

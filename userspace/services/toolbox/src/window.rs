// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `window`: put a window on the screen through the compositor (Kconfig
//! `COMPOSITOR`), a client of the `Compositor` object (`azos_compositor`) that
//! `COMPSRV.ELF` serves.
//!
//! ```text
//! window show [-n FRAMES] [-s WxH] [-p X,Y]
//! window status
//! ```
//!
//! `show` makes the window's memory object (a control page and the pixels),
//! attaches it, draws FRAMES frames (default 3) of colour bars that move one
//! step each frame, posts the rectangle it changed in the damage ring in the
//! object's first page after each (no call per frame: the compositor looks at
//! the ring on its frame timer), holds the last frame long enough to be
//! presented, and takes the window down through the call right the attach
//! lent. It prints what it did and the compositor's count of frames presented.
//! `status` prints the compositor's counters.
//!
//! The tool's authority is its row's call right on `endpoint.compositor` and
//! nothing else. The row also holds the input server's call right, and both
//! are unbadged `WRITE` grants on a task-hosted endpoint, so the tool finds the
//! compositor's by asking each: the one that answers `status` is it.

use super::{fail, put, put_num};
use azos_compositor::{CompositorCall, CompositorClient, Shape, WindowBuffer, WindowRing, CONTROL_BYTES};
use azos_devif::display::Rect;
use azos_libsys as sys;
use azos_abi::cap::CapPerms;
use azos_devif::Lent;
use azos_libsys::dev::Ep;

/// Milliseconds between two frames: long enough for the compositor's frame
/// timer (`COMPOSITOR_FRAME_MS`, 16 by default) to have looked at the ring.
const FRAME_MS: u64 = 60;
/// Milliseconds the last frame is held before the window is taken down.
const HOLD_MS: u64 = 400;
const DEFAULT_SIZE: (u32, u32) = (96, 64);
const DEFAULT_AT: (i32, i32) = (20, 20);
const USAGE: &[u8] = b"usage: window show [-n FRAMES] [-s WxH] [-p X,Y] | status";

type Client = CompositorClient<Ep>;

/// The compositor's endpoint: the call right of the row that answers the
/// Compositor object's `status`.
fn connect() -> Option<Client> {
    (0..256u32).find_map(|i| {
        let h = sys::cap_lookup(sys::ty::ENDPOINT.raw(), i);
        if h <= 0 {
            return None;
        }
        let info = sys::cap_info(h as u32).ok()?;
        if info.rights & CapPerms::WRITE.bits() == 0 {
            return None;
        }
        let c = CompositorClient::new(Ep(h as u32));
        matches!(c.status(), Ok(o) if o.is_ok()).then_some(c)
    })
}

fn text(fd: u64, parts: &[&[u8]]) {
    for p in parts {
        let _ = put(fd, p);
    }
}

fn refused(op: &[u8], code: u32) -> i32 {
    text(2, &[b"window: ", op, b" refused (outcome "]);
    put_num(2, code as u64);
    text(2, &[b")\n"]);
    1
}

/// `n,m` as two numbers split at `sep`.
fn pair(a: &[u8], sep: u8) -> Option<(u64, u64)> {
    let at = a.iter().position(|&c| c == sep)?;
    Some((super::parse_u64(&a[..at])?, super::parse_u64(&a[at + 1..])?))
}

/// Frame `f` of the bars: vertical stripes of four colours that step one stripe
/// per frame, so every frame differs from the last.
fn draw(base: usize, shape: &Shape, f: u32) {
    const COLOURS: [u32; 4] = [0x00E0_3030, 0x0030_C050, 0x0030_60E0, 0x00E0_C030];
    let px = (base + CONTROL_BYTES) as *mut u32;
    for y in 0..shape.height as usize {
        for x in 0..shape.width as usize {
            let c = COLOURS[((x / 12) + f as usize) % COLOURS.len()];
            // SAFETY: the object holds `shape.pages` pages from `base`: the
            // control page and then `width * height` pixels, which this loop
            // stays inside; the compositor reads the same memory (a torn frame is
            // tolerated).
            unsafe { px.add(y * shape.width as usize + x).write_volatile(c) };
        }
    }
}

fn show(c: &mut Client) -> i32 {
    let (mut frames, mut size, mut at) = (3u64, DEFAULT_SIZE, DEFAULT_AT);
    let mut i = 2;
    while i < sys::argc() {
        let flag = sys::arg(i).unwrap_or(b"");
        i += 1;
        let val = sys::arg(i).unwrap_or(b"");
        match flag {
            b"-n" => match super::parse_u64(val) {
                Some(n) if n > 0 && n < 1000 => frames = n,
                _ => {
                    fail(b"window", USAGE);
                    return 2;
                }
            },
            b"-s" => match pair(val, b'x') {
                Some((w, h)) if w > 0 && h > 0 && w <= 4096 && h <= 4096 => size = (w as u32, h as u32),
                _ => {
                    fail(b"window", USAGE);
                    return 2;
                }
            },
            b"-p" => match pair(val, b',') {
                Some((x, y)) if x < 65536 && y < 65536 => at = (x as i32, y as i32),
                _ => {
                    fail(b"window", USAGE);
                    return 2;
                }
            },
            _ => {
                fail(b"window", USAGE);
                return 2;
            }
        }
        i += 1;
    }
    let shape = Shape { x: at.0, y: at.1, width: size.0, height: size.1 };
    let pages = shape.pages(sys::PAGE_SIZE);
    if shape.check(pages, sys::PAGE_SIZE).is_err() {
        fail(b"window", b"that window does not fit one memory object (about 250x250 pixels at most)");
        return 2;
    }
    let cap = sys::shm_create_typed(pages, sys::SHM_RW);
    if cap <= 0 {
        fail(b"window", b"no memory object for the window");
        return 1;
    }
    let va = sys::shm_map_typed(cap as u32);
    if va <= 0 {
        fail(b"window", b"the window's memory object cannot be mapped");
        return 1;
    }
    let base = va as usize;
    let ring = WindowRing { base };
    ring.init();
    draw(base, &shape, 0);
    // Lent, not moved: this task keeps its capability, so its mapping stays.
    let rights = CapPerms::READ.union(CapPerms::WRITE).union(CapPerms::MAP).bits() as u16;
    let attached = match c.attach(Lent::<WindowBuffer>::dup(cap as u32, rights), shape) {
        Err(_) => {
            fail(b"window", b"the compositor did not answer");
            return 1;
        }
        Ok(o) if !o.is_ok() => return refused(b"attach", o.code),
        Ok(o) => o.value,
    };
    let Some(right) = attached.right.get() else {
        fail(b"window", b"the compositor lent no right to take the window down");
        return 1;
    };
    text(1, &[b"window: attached "]);
    put_num(1, attached.window as u64);
    text(1, &[b" ("]);
    put_num(1, shape.width as u64);
    text(1, &[b"x"]);
    put_num(1, shape.height as u64);
    text(1, &[b")\n"]);
    let whole = Rect::full(shape.width, shape.height);
    let mut posted = 0u64;
    for f in 0..frames {
        if f > 0 {
            draw(base, &shape, f as u32);
        }
        // Every frame moves the bars across the whole window: the ring carries
        // what changed.
        if ring.post(whole) {
            posted += 1;
        }
        text(1, &[b"window: frame "]);
        put_num(1, f + 1);
        text(1, &[b" drawn\n"]);
        if let sys::SleepResult::Refused(_) = sys::sleep_until_ns(sys::vdso_now_ns() + FRAME_MS * 1_000_000) {
            break;
        }
    }
    let _ = sys::sleep_until_ns(sys::vdso_now_ns() + HOLD_MS * 1_000_000);
    let status = c.status().ok().filter(|o| o.is_ok()).map(|o| o.value);
    // Through the window's own right: the plain one cannot take it down.
    let mut w = CompositorClient::new(Ep(right.raw()));
    let detached = matches!(w.detach(), Ok(o) if o.is_ok());
    text(1, &[b"window: ", if detached { b"detached" } else { b"not detached" }, b", "]);
    put_num(1, posted);
    text(1, &[b" damage posts\n"]);
    if let Some(s) = status {
        text(1, &[b"window: compositor presented "]);
        put_num(1, s.presents);
        text(1, &[b" frames\n"]);
    }
    if detached { 0 } else { 1 }
}

fn status(c: &mut Client) -> i32 {
    let s = match c.status() {
        Err(_) => {
            fail(b"window", b"the compositor did not answer");
            return 1;
        }
        Ok(o) if !o.is_ok() => return refused(b"status", o.code),
        Ok(o) => o.value,
    };
    text(1, &[b"windows "]);
    put_num(1, s.windows as u64);
    text(1, &[b" chords "]);
    put_num(1, s.chords as u64);
    text(1, &[b" presents "]);
    put_num(1, s.presents);
    text(1, &[b" rects "]);
    put_num(1, s.rects);
    text(1, &[b"\n"]);
    0
}

/// `window <show|status> ...`: an exit code.
pub fn run() -> i32 {
    let sub = sys::arg(1).unwrap_or(b"");
    if !matches!(sub, b"show" | b"status") {
        fail(b"window", USAGE);
        return 2;
    }
    let Some(mut c) = connect() else {
        fail(b"window", b"no compositor answered: this row holds no call right on it (Kconfig COMPOSITOR)");
        return 1;
    };
    match sub {
        b"show" => show(&mut c),
        _ => status(&mut c),
    }
}

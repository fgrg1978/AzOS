// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `COMPSRV.ELF`: the AzOS compositor.
//!
//! A ring-3 program whose topology row is its whole authority (`COMPOSITOR_CAPS`
//! in `crates/core/topology/src/builder.rs`):
//!
//! * `READ` + `WRITE` with `transfer` on `endpoint.compositor`: it serves the
//!   `Compositor` object (`userspace/lib/compositor`) there, and derives from the
//!   same grant the call right bound to each window it shows;
//! * `display.0` with all three classes: the sole holder of the kernel's `Display`
//!   interface. It claims the screen (the kernel's text console stops drawing),
//!   keeps one full-screen surface made of bands, and presents the damage its
//!   clients post;
//! * the call right on `endpoint.input` with `EXEC` beside it, which the kernel
//!   badges as the trusted surface's: after the Secure Attention Key the input
//!   server grants the focus to this caller alone, which it takes (and gives
//!   back) once the banner has been up for `COMPOSITOR_BANNER_MS`;
//! * where the decision server runs, the call right on `endpoint.decisions`, for
//!   the "why was this refused" panel.
//!
//! **Three threads.** The main thread serves: the endpoint's `READ` grant is
//! stamped with the TID of the task the program started as, and the kernel hands
//! a call only to the thread that has that TID. The *painter* does every call on
//! the Display (the claim belongs to the task that made it), and each
//! `COMPOSITOR_FRAME_MS` looks at the clients' damage rings and at the trusted
//! page, composes and presents. The *why* thread fetches the newest refusals
//! from the decision server: a call on a server that does not answer waits for
//! ever, so it is not made by a thread that has the banner or the focus to see
//! to. The three meet in one spin lock around the server's state; the why thread
//! calls the decision server without it.
//!
//! **Without a display** (no scanout, a format it cannot compose, a refused
//! claim) the server still runs the trusted path: it acknowledges the chord
//! without a banner and hands the focus on, so the focus stays obtainable;
//! `attach` answers `NOT_READY`.
//!
//! The decisions are `windows.rs` (the Compositor object), `trust.rs` (when the
//! banner goes up and the focus is handed on), `bands.rs` (the surface's cut) and
//! `panel.rs` (the two trusted panels), which the host suite
//! (`tests/host/compositor-tests`) drives.

#![no_std]
#![no_main]

mod bands;
#[allow(dead_code)]
#[path = "../../../../crates/drivers/fb/src/font.rs"]
mod font;
mod panel;
mod trust;
mod windows;

use azos_abi::syscall_nr::{SHM_CREATE_KIND_SHIFT, SHM_KIND_CONTIG};
use azos_compose::{Format, Image, Source, Sources};
use azos_compositor::{CompositorIdl, PIXEL_BYTES};
use azos_decisions::{DecisionsClient, Filter};
use azos_devif::display::{connector_badge, Present, SurfaceBand};
use azos_devif::input::{TrustedPage, TRUSTED_BADGE};
use azos_devif::{DisplayCall, DisplayClient, InputCall, InputClient};
use azos_idl::MsgDesc;
use azos_libsys as sys;
use azos_libsys::dev::{Cap, Ep};
use bands::{plan, Bands, BANDS_MAX};
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use panel::{Why, BANNER_BYTES, BANNER_H, PANEL_W, WHY_BYTES, WHY_DECISIONS, WHY_H};
use trust::Trust;
use windows::{Host, Mapped, Service, BANNER_LAYER, PANEL_LAYER};

/// The rights of the capability window rights are derived from: the call right
/// that can be lent (`DUP` and `TRANSFER`, which a row gets from `transfer =
/// true`).
const SOURCE_RIGHTS: u8 = azos_abi::cap::CapPerms::WRITE.union(azos_abi::cap::CapPerms::DELEGATE).bits();

/// Milliseconds between two looks at the damage and the trusted page.
const FRAME_MS: u64 = azos_limits::COMPOSITOR_FRAME_MS as u64;
/// Where the banner sits: centred at the top; the panel below it.
const BANNER_Y: i32 = 8;
const PANEL_Y: i32 = BANNER_Y + BANNER_H as i32 + 8;
/// Presents logged: the first ones, then every this many.
const LOG_FIRST: u64 = 16;
const LOG_EVERY: u64 = 64;

/// The server's surroundings.
struct Sys {
    /// The call right on this server's own endpoint, from which window rights are
    /// derived.
    source: u32,
}

impl Host for Sys {
    fn page_bytes(&self) -> usize {
        sys::PAGE_SIZE
    }

    fn map_window(&mut self, cap: u32) -> Option<Mapped> {
        let mut info = [0u8; sys::SHM_INFO_BYTES];
        if sys::shm_acquire_typed(cap, &mut info) < 0 {
            let _ = sys::close_typed(cap);
            return None;
        }
        let pages = u32::from_le_bytes([info[0], info[1], info[2], info[3]]) as u64;
        let va = sys::shm_map_typed(cap);
        if va <= 0 {
            let _ = sys::close_typed(cap);
            return None;
        }
        Some(Mapped { cap, base: va as usize, pages })
    }

    fn unmap_window(&mut self, m: &Mapped) {
        let _ = sys::shm_release_typed(m.cap);
    }

    fn close(&mut self, cap: u32) {
        let _ = sys::close_typed(cap);
    }

    fn pixels(&self, m: &Mapped, bytes: usize) -> &[u8] {
        let len = bytes.min(m.pages as usize * sys::PAGE_SIZE);
        // SAFETY: `map_window` mapped `m.pages` pages at `m.base` and the mapping
        // lives until `unmap_window`, which the caller does not call while a
        // frame borrows this slice (both are under the server's lock). The client
        // may write the pixels while they are read: a torn frame is tolerated
        // (the module doc of `azos_compositor`), and a byte read is never UB for
        // memory the kernel mapped.
        unsafe { core::slice::from_raw_parts(m.base as *const u8, len) }
    }

    fn derive_right(&mut self, badge: u32) -> Option<u32> {
        let h = sys::endpoint_derive(self.source, SOURCE_RIGHTS, badge, 0, &[]);
        (h > 0).then_some(h as u32)
    }

    fn revoke(&mut self, right: u32) {
        // Everything derived from it is gone (the client's copy); the replacement
        // handle is not wanted either.
        let r = sys::cap_revoke(right);
        let _ = sys::close_typed(if r > 0 { r as u32 } else { right });
    }

    fn log(&mut self, line: &[u8]) {
        let _ = sys::console_write(sys::STDOUT, line);
    }
}

fn log(line: &[u8]) {
    let _ = sys::console_write(sys::STDOUT, line);
}

/// The two panels' pixels.
struct Panels {
    banner: [u8; BANNER_BYTES],
    why: [u8; WHY_BYTES],
}

/// The panels as the scene's overlay sources.
struct Overlays<'a> {
    banner: Option<Image<'a>>,
    why: Option<Image<'a>>,
}

impl Sources for Overlays<'_> {
    fn source(&self, id: u32) -> Option<&dyn Source> {
        match id {
            BANNER_LAYER => self.banner.as_ref().map(|i| i as &dyn Source),
            PANEL_LAYER => self.why.as_ref().map(|i| i as &dyn Source),
            _ => None,
        }
    }
}

/// The display, once claimed.
struct Display {
    client: DisplayClient<Ep>,
    surface: u32,
    bands: Bands,
}

/// Everything the three threads share, under [`LOCK`]. The panels' pixels are
/// not in it: it has non-zero fields, and a static with any would put them in the
/// image file.
struct State {
    svc: Service<Sys>,
    trust: Trust,
    /// The panel is drawn and up (the banner is).
    why_up: bool,
    display: Option<Display>,
    /// The trusted surface's call right on `endpoint.input` (0: none).
    input: u32,
    /// Where the trusted-path page is mapped (0: none).
    page: usize,
}

impl State {
    const fn new() -> State {
        State {
            svc: Service::new(Sys { source: 0 }),
            trust: Trust::new(0, azos_limits::COMPOSITOR_BANNER_MS as u32),
            why_up: false,
            display: None,
            input: 0,
            page: 0,
        }
    }
}

struct Shared<T>(UnsafeCell<T>);

// SAFETY: every access is under `LOCK` (see `with`).
unsafe impl<T> Sync for Shared<T> {}

static STATE: Shared<State> = Shared(UnsafeCell::new(State::new()));
/// All zero, so it is in `.bss`.
static PANELS: Shared<Panels> = Shared(UnsafeCell::new(Panels { banner: [0; BANNER_BYTES], why: [0; WHY_BYTES] }));
static LOCK: AtomicBool = AtomicBool::new(false);

/// Run `f` on the state and the panels' pixels with the lock held.
fn with<R>(f: impl FnOnce(&mut State, &mut Panels) -> R) -> R {
    while LOCK.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed).is_err() {
        sys::yield_now();
    }
    // SAFETY: the lock is held; nothing else takes a reference to either.
    let r = f(unsafe { &mut *STATE.0.get() }, unsafe { &mut *PANELS.0.get() });
    LOCK.store(false, Ordering::Release);
    r
}

/// The refusal panel is wanted (a chord was seen), and the last one the why
/// thread answered: the thread fetches whenever the two differ.
static WHY_WANT: AtomicU32 = AtomicU32::new(0);
static WHY_DONE: AtomicU32 = AtomicU32::new(0);
/// The decision server's call right (0: none), set before the threads start.
static DECISIONS: AtomicU32 = AtomicU32::new(0);

// ── Finding the row's capabilities ──────────────────────────────────────

/// The endpoint capabilities of the row, told apart by what they carry.
struct Found {
    /// `READ` + the lendable call right, unbadged: the grant of `endpoint.compositor`.
    source: u32,
    /// The call right with the trusted badge.
    input: u32,
    /// The plain call right on the decision server.
    decisions: u32,
}

fn find_caps() -> Found {
    use azos_abi::cap::CapPerms;
    let serve = CapPerms::READ.union(CapPerms::WRITE).union(CapPerms::DELEGATE).bits();
    let mut f = Found { source: 0, input: 0, decisions: 0 };
    for i in 0..azos_limits::IPC_ENDPOINTS as u32 {
        let h = sys::cap_lookup(sys::ty::ENDPOINT.raw(), i);
        if h <= 0 {
            continue;
        }
        let Ok(info) = sys::cap_info(h as u32) else { continue };
        if info.badge == TRUSTED_BADGE {
            f.input = h as u32;
        } else if info.badge == 0 && info.rights & serve == serve {
            f.source = h as u32;
        } else if info.badge == 0 && info.rights == CapPerms::WRITE.bits() {
            f.decisions = h as u32;
        }
    }
    f
}

// ── The display ─────────────────────────────────────────────────────────

/// A fresh physically contiguous memory object of `pages` pages, mapped here:
/// its capability and address.
fn make_band(pages: u64) -> Option<(u32, usize)> {
    let cap = sys::shm_create_typed(pages, sys::SHM_RW | SHM_KIND_CONTIG << SHM_CREATE_KIND_SHIFT);
    if cap <= 0 {
        return None;
    }
    let va = sys::shm_map_typed(cap as u32);
    if va <= 0 {
        let _ = sys::shm_release_typed(cap as u32);
        return None;
    }
    Some((cap as u32, va as usize))
}

/// Claim the screen and make its surface. `Err` is the line that says why not.
fn bring_up_display() -> Result<(Display, u32, u32), &'static [u8]> {
    let Some(ep) = sys::dev::lookup(sys::dev::key::DISPLAY, connector_badge(0)) else {
        return Err(b"[compsrv] no display: this row holds no grant of display.0\n");
    };
    let mut client = DisplayClient::new(Ep(ep));
    let Ok(info) = sys::dev::value(client.connector()) else {
        return Err(b"[compsrv] no display: the platform has no scanout\n");
    };
    let Some(format) = Format::from_display(info.format) else {
        return Err(b"[compsrv] no display: the scanout's pixel format is not composed\n");
    };
    let stride = info.width * format.bytes() as u32;
    let Some(plan) = plan(info.height, stride, sys::PAGE_SIZE, azos_compositor::MAX_PAGES) else {
        return Err(b"[compsrv] no display: the screen does not fit the bands this server keeps\n");
    };
    // The bands are charged to this row's frame ceiling, which holds this much
    // surface (in 4 KiB topology pages, whatever the base page).
    if plan.pages * plan.count as u64 * sys::PAGE_SIZE as u64 > azos_limits::COMPOSITOR_SURFACE_PAGES as u64 * 4096 {
        return Err(b"[compsrv] no display: the screen's bands exceed this row's budget (Kconfig COMPOSITOR_SURFACE_PAGES)\n");
    }
    if sys::dev::value(client.claim()).is_err() {
        return Err(b"[compsrv] no display: another task holds the screen\n");
    }
    // From here a failure gives the screen back.
    let give_back = |client: &mut DisplayClient<Ep>, why: &'static [u8]| {
        let _ = client.release();
        Err(why)
    };
    let Ok(surface) = sys::dev::value(client.surface(stride, info.format)) else {
        return give_back(&mut client, b"[compsrv] no display: the surface was refused\n");
    };
    let mut bases = [0usize; BANDS_MAX];
    for base in bases.iter_mut().take(plan.count as usize) {
        let Some((cap, va)) = make_band(plan.pages) else {
            return give_back(&mut client, b"[compsrv] no display: a band's memory object was refused (Kconfig MAX_MEMOBJS, or no contiguous run free)\n");
        };
        // The band is moved to the kernel; the mapping stays.
        if sys::dev::value(client.band(surface, Cap::<SurfaceBand>::from_raw(cap))).is_err() {
            return give_back(&mut client, b"[compsrv] no display: a band was refused\n");
        }
        *base = va;
    }
    let bands = Bands::new(bases, plan, stride, info.height, format);
    Ok((Display { client, surface, bands }, info.width, info.height))
}

// ── The trusted path ────────────────────────────────────────────────────

/// Take the focus as the trusted surface (which opens the input server's gate)
/// and give it straight back, so the plain callers may ask for it. `true` when it
/// was done.
fn hand_on(input: u32) -> bool {
    let mut client = InputClient::new(Ep(input));
    let lease = match client.take_focus() {
        Ok(o) if o.is_ok() => o.value,
        _ => return false,
    };
    if let Some(w) = lease.warrant.get() {
        // Through the warrant: the plain call right is no holder's.
        let _ = InputClient::new(Ep(w.raw())).release();
        let _ = sys::close_typed(w.raw());
    }
    if let Some(r) = lease.ring.get() {
        let _ = sys::close_typed(r.raw());
    }
    true
}

/// Is the input server's gate closed: attention pending, only this caller may
/// take the focus?
fn gate_closed(input: u32) -> bool {
    matches!(InputClient::new(Ep(input)).status(), Ok(o) if o.is_ok() && o.value.pending != 0)
}

/// One look at the trusted page: a new chord puts the banner up; a banner that
/// has been up long enough hands the focus on and comes down.
fn trusted_path(st: &mut State, panels: &mut Panels, now: u64) {
    if st.page != 0 {
        let count = TrustedPage::count(st.page);
        if st.trust.observe(count, now) {
            st.svc.counters.chords = count;
            panel::render_banner(&mut panels.banner, count, azos_limits::COMPOSITOR_BANNER_MS as u32);
            let x = banner_x(&st.svc);
            st.svc.show_overlay(BANNER_LAYER, x, BANNER_Y, PANEL_W as u32, BANNER_H as u32);
            WHY_WANT.fetch_add(1, Ordering::Release);
            log(b"[compsrv] trusted path: banner up, focus held back\n");
        }
    }
    if st.trust.due(now) && st.input != 0 {
        if hand_on(st.input) {
            st.trust.handed_on();
            st.svc.hide_overlay(BANNER_LAYER);
            st.svc.hide_overlay(PANEL_LAYER);
            st.why_up = false;
            log(b"[compsrv] trusted path handed on: the focus may be taken again\n");
        }
        // A refused hand-on (the input server is busy) is tried again at the
        // next look; the gate stays closed until it works.
    }
}

/// The banner's x: centred on the screen, or at the left edge when the screen
/// is narrower.
fn banner_x(svc: &Service<Sys>) -> i32 {
    let w = svc.output().map_or(0, |o| o.0 as i32);
    ((w - PANEL_W as i32) / 2).max(0)
}

// ── The painter ─────────────────────────────────────────────────────────

/// The stack of the painter thread: the scene is built on it (the cursor plane is
/// 16 KiB) before it is moved into the state.
const PAINTER_STACK_BYTES: usize = 64 * 1024;
/// The stack of the why thread.
const WHY_STACK_BYTES: usize = 8 * 1024;

#[repr(C, align(16))]
struct Stack<const N: usize>(UnsafeCell<[u8; N]>);

// SAFETY: each is one thread's alone.
unsafe impl<const N: usize> Sync for Stack<N> {}

static PAINTER_STACK: Stack<PAINTER_STACK_BYTES> = Stack(UnsafeCell::new([0; PAINTER_STACK_BYTES]));
static WHY_STACK: Stack<WHY_STACK_BYTES> = Stack(UnsafeCell::new([0; WHY_STACK_BYTES]));

/// Compose what the clients posted and present the damage.
fn paint(st: &mut State, panels: &Panels) {
    let State { svc, display, .. } = st;
    let Some(d) = display else { return };
    svc.drain();
    if !svc.has_damage() {
        return;
    }
    let ov = Overlays {
        banner: Image::new(&panels.banner, PANEL_W as u32, BANNER_H as u32, PANEL_W * PIXEL_BYTES, Format::Xrgb8888),
        why: Image::new(&panels.why, PANEL_W as u32, WHY_H as u32, PANEL_W * PIXEL_BYTES, Format::Xrgb8888),
    };
    let Some(frame) = svc.frame(&ov, &mut d.bands) else { return };
    let Some(p) = Present::new(d.surface, frame.damage.rects()) else { return };
    let n = frame.damage.rects().len() as u64;
    if matches!(sys::dev::value(d.client.present(p)), Ok(_)) {
        svc.counters.presents += 1;
        svc.counters.rects += n;
        let k = svc.counters.presents;
        if k <= LOG_FIRST || k % LOG_EVERY == 0 {
            let mut line = [0u8; 80];
            let mut w = windows::put(&mut line, 0, b"[compsrv] present ");
            let mut dg = [0u8; 10];
            w = windows::put(&mut line, w, windows::dec(k as u32, &mut dg));
            w = windows::put(&mut line, w, b": damage ");
            w = windows::put(&mut line, w, windows::dec(n as u32, &mut dg));
            w = windows::put(&mut line, w, b" rects, windows ");
            w = windows::put(&mut line, w, windows::dec(svc.windows(), &mut dg));
            w = windows::put(&mut line, w, b", missing ");
            w = windows::put(&mut line, w, windows::dec(frame.missing, &mut dg));
            w = windows::put(&mut line, w, b"\n");
            log(&line[..w]);
        }
    }
}

extern "C" fn painter(_: u64, _: u64, _: u64) -> ! {
    // The trusted page: where the chords are counted.
    let input = with(|st, _| st.input);
    let page = if input != 0 { map_trusted_page(input) } else { 0 };
    with(|st, _| {
        st.page = page;
        if page != 0 {
            st.trust = Trust::new(TrustedPage::count(page), azos_limits::COMPOSITOR_BANNER_MS as u32);
            st.svc.counters.chords = st.trust.chords();
        }
    });
    // A chord before this server existed (it was restarted, or the keys were
    // pressed while it started) left the input server's gate closed, and nothing
    // here saw the count move: open it now, or no application could ever take the
    // focus. Not done when nothing is pending, which takes no grant at all.
    if input != 0 && gate_closed(input) && hand_on(input) {
        log(b"[compsrv] trusted path: the gate was closed before this server started, handed on\n");
    }
    match bring_up_display() {
        Ok((d, w, h)) => {
            with(|st, _| {
                if st.svc.set_output(w, h) {
                    st.display = Some(d);
                }
            });
            let mut line = [0u8; 80];
            let mut n = windows::put(&mut line, 0, b"[compsrv] display claimed: ");
            let mut dg = [0u8; 10];
            n = windows::put(&mut line, n, windows::dec(w, &mut dg));
            n = windows::put(&mut line, n, b"x");
            n = windows::put(&mut line, n, windows::dec(h, &mut dg));
            n = windows::put(&mut line, n, b"\n");
            log(&line[..n]);
        }
        Err(why) => log(why),
    }
    loop {
        sys::sleep(FRAME_MS);
        with(|st, panels| {
            let now = sys::vdso_now_ns();
            trusted_path(st, panels, now);
            paint(st, panels);
        });
    }
}

/// Ask the input server for the trusted-path page and map it read-only.
fn map_trusted_page(input: u32) -> usize {
    let mut client = InputClient::new(Ep(input));
    let page = match client.trusted() {
        Ok(o) if o.is_ok() => o.value.page.get(),
        _ => None,
    };
    let Some(page) = page else {
        log(b"[compsrv] no trusted-path page: the input server did not lend it\n");
        return 0;
    };
    let va = sys::shm_map_typed(page.raw());
    if va <= 0 {
        log(b"[compsrv] the trusted-path page cannot be mapped\n");
        return 0;
    }
    va as usize
}

// ── The refusal panel ───────────────────────────────────────────────────

/// Fill `why` with the newest refusals the decision server holds.
fn fetch_refusals(ep: u32, why: &mut Why) {
    use azos_decisions::{fetch, list};
    let client = DecisionsClient::new(Ep(ep));
    // The ids run in the order the decisions were made and the query lists the
    // oldest first, so look only at the last stretch: from `total - WINDOW` on.
    const WINDOW: u64 = 256;
    let mut ids = [0u64; 24];
    let mut count = 0;
    let Ok((_, total)) = list(&client, &Filter::ANY, &mut ids[..1]) else {
        why.note("the decision server did not answer");
        return;
    };
    let after = total.saturating_sub(WINDOW);
    // Refusals and denials, oldest first within each verdict.
    let (mut refused, mut denied) = ([0u64; 12], [0u64; 12]);
    let rn = list(&client, &Filter { verdict: Some(1), after, ..Filter::ANY }, &mut refused).map_or(0, |r| r.0);
    let dn = list(&client, &Filter { verdict: Some(3), after, ..Filter::ANY }, &mut denied).map_or(0, |r| r.0);
    for &id in refused[..rn].iter().chain(denied[..dn].iter()) {
        if count < ids.len() {
            ids[count] = id;
            count += 1;
        }
    }
    let ids = &mut ids[..count];
    ids.sort_unstable();
    if ids.is_empty() {
        why.note("no refusal recorded in the last stretch");
        return;
    }
    // The newest first.
    for &id in ids.iter().rev().take(WHY_DECISIONS) {
        if let Ok(Some(rec)) = fetch(&client, id) {
            if !why.decision(&rec) {
                break;
            }
        }
    }
}

extern "C" fn why_thread(_: u64, _: u64, _: u64) -> ! {
    loop {
        sys::sleep(25);
        let want = WHY_WANT.load(Ordering::Acquire);
        if want == WHY_DONE.load(Ordering::Relaxed) {
            continue;
        }
        let mut why = Why::new();
        match DECISIONS.load(Ordering::Relaxed) {
            0 => why.note("the decision server is not in this build"),
            ep => fetch_refusals(ep, &mut why),
        }
        with(|st, panels| {
            // The banner may have come down while the server answered: the panel
            // is then not wanted.
            if st.trust.active() {
                panel::render_why(&mut panels.why, &why);
                let x = banner_x(&st.svc);
                st.svc.show_overlay(PANEL_LAYER, x, PANEL_Y, PANEL_W as u32, WHY_H as u32);
                st.why_up = true;
            }
        });
        WHY_DONE.store(want, Ordering::Release);
    }
}

// ── The server ──────────────────────────────────────────────────────────

/// Accept a call on `endpoint.compositor`, dispatch it, reply, for ever: the main
/// thread's loop (the thread the endpoint is stamped with).
fn serve() -> ! {
    loop {
        let mut req = MsgDesc::default();
        let call = sys::ipc_accept_v2(&mut req);
        if call < 0 {
            // Nothing arrived (a spurious wake): wait a little rather than spin.
            sys::sleep(10);
            continue;
        }
        let mut rep = MsgDesc::default();
        with(|st, _| {
            // The badge of the capability the call came through: a window's
            // right, or 0 for the plain call right.
            st.svc.caller = if req.flags & azos_abi::ipc_msg::MSG_BADGED != 0 { req.badge as u32 } else { 0 };
            let _ = CompositorIdl::dispatch(&mut st.svc, &req, &mut rep);
        });
        let _ = sys::ipc_reply_v2(call as u64, &rep);
    }
}

#[sys::main(panic_exit = 70)]
fn main() -> ! {
    let found = find_caps();
    if found.source == 0 {
        log(b"[compsrv] the row grants no call right to lend on endpoint.compositor\n");
        sys::exit(1);
    }
    if found.input == 0 {
        // Without it the chord's gate could not be opened: refuse to run rather
        // than leave the focus unobtainable after the first chord.
        log(b"[compsrv] the row grants no trusted call right on endpoint.input\n");
        sys::exit(1);
    }
    DECISIONS.store(found.decisions, Ordering::Relaxed);
    with(|st, _| {
        st.svc.host.source = found.source;
        st.input = found.input;
    });
    let painter_top = PAINTER_STACK.0.get() as usize + PAINTER_STACK_BYTES;
    if sys::thread_create(painter, painter_top, 0, core::ptr::null_mut()) < 0 {
        log(b"[compsrv] no thread for the painter\n");
        sys::exit(1);
    }
    let why_top = WHY_STACK.0.get() as usize + WHY_STACK_BYTES;
    if sys::thread_create(why_thread, why_top, 0, core::ptr::null_mut()) < 0 {
        log(b"[compsrv] no thread for the refusal panel\n");
        sys::exit(1);
    }
    log(b"[compsrv] AzOS compositor (Compositor on endpoint.compositor)\n");
    serve()
}

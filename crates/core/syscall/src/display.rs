// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The `Display` interface the kernel hosts (`endpoint = "display.<n>"`): the
//! generic framebuffer's connector, its modes, and the path from a display
//! server's image to the screen. The interface, its rules and its wire forms
//! are `azos_devif::display`; this is the server behind connector 0.
//!
//! * **Scanout.** The screen is an `azos_devif::Scanout` the kernel registers
//!   ([`set_scanout`]): the generic framebuffer (`azos_fb::scanout`: ramfb,
//!   Limine, `simple-framebuffer`, virtio-gpu), or a display controller's own
//!   driver. The syscall crate knows only the trait: the framebuffer crate is
//!   scaffolding, and a core crate does not depend on that (`tools/tcb_check.sh`).
//!   It runs one mode; its mode list is that mode first, then what the display's
//!   EDID offers (`azos_fb::scanout::publish_edid`).
//! * **Claim.** [`claim`](azos_devif::Display::claim) retires the kernel's text
//!   console (`Scanout::retire_console`); the claim's holder is the task (thread)
//!   that called it. Release, and the holder's exit ([`release_all`], called
//!   from the kernel's task-exit hook), give the screen back and the console
//!   redraws.
//! * **Surfaces.** A surface is made of bands, `Contig`, read-write MemObjs the
//!   holder made, each holding whole rows (`azos_devif::display`, "Surfaces",
//!   for why they are bands and what they cost). The kernel takes its own
//!   pinned reference on each (as `vm.rs` does for guest RAM), remembers the
//!   direct-map address of its first frame, and copies from it on every present.
//!   One band is one contiguous run, so one address; that is why the kind is
//!   `Contig` and not any MemObj.
//! * **Present.** The damage rectangles are copied (`Scanout::copy_rect`) from the
//!   bands they touch to the scanout in the caller's own call, with no lock held
//!   across a copy, then each rectangle is reported to the display
//!   (`Scanout::flip`). Only the claim's holder can reach a surface or change
//!   the state, so no copy races a destroy.
//! * **Vsync.** After the copy, one `PORT_EVENT_TIMER` event on the attached port
//!   (module doc of `azos_devif::display`, "Vsync").
//!
//! # Trust in the surface
//!
//! The image is shared with its writer by design (the server draws the next
//! frame while this one is copied); a copy that overlaps a write shows a mix of
//! two frames, which damage tracking in the server is there to avoid, and costs
//! the kernel nothing: it reads bytes and writes them to a screen. What the
//! kernel does rely on is that the frames stay where they were. Each band is a
//! `Contig` object (one physical run, so one direct-map address) that the
//! kernel holds a pinned reference on, so it is not freed, resized or revoked
//! while the surface exists; and a `Contig` object is never shared
//! copy-on-write (`memobj_clone` shares frames only for `Anon` objects and
//! copies any other kind), so nothing moves its frames from under the copy.
//! What the kernel reads is the holder's own pixels.

use azos_abi::cap::{CapHandle, CapPerms};
use azos_abi::invoke::CLASS_CTL;
use azos_devif::display::{self, band_take, ConnectorInfo, Mode, Present, Rect, Scanout, BANDS_MAX, CONN_CLAIMED, CONN_YOURS, SURFACES};
use azos_devif::{outcome, Cap as WireCap, Out};
use azos_ipc::cap::{targets, Cap, CapError, CapTarget};
use azos_ipc::memobj::{
    memobj_acquire_ref, memobj_describe_ref, memobj_kernel_page_phys_ref, memobj_pin_ref, memobj_release_ref, MemKind,
    MemPerms, ATTR_NO_KERNEL_MAP, ATTR_SWAPPABLE, MEMOBJ_KERNEL_OWNER,
};
use azos_ipc::port::{port_live_epoch, port_queue_event_bound, PortEvent, PORT_EVENT_TIMER};
use azos_sync::SpinLock;

use crate::invoke::class_op;
use crate::khost::Caller;

/// One band of a surface: an object that holds `rows` whole rows, the first
/// of them screen row `top`.
#[derive(Clone, Copy)]
struct Band {
    /// The MemObj, by packed reference; the kernel holds a pinned reference.
    obj: u32,
    /// Physical address of its first frame, as the contiguous run starts.
    phys: usize,
    top: u32,
    rows: u32,
}

impl Band {
    const NONE: Band = Band { obj: 0, phys: 0, top: 0, rows: 0 };
}

/// A surface the holder made: its geometry and the bands that cover its first
/// `covered` rows, in order.
struct Surf {
    /// The slot is in use. (A slot is reset in place: the band table is 4 KiB,
    /// too much to build on a kernel stack and move.)
    live: bool,
    stride: u32,
    covered: u32,
    n: usize,
    bands: [Band; BANDS_MAX],
}

impl Surf {
    const FREE: Surf = Surf { live: false, stride: 0, covered: 0, n: 0, bands: [Band::NONE; BANDS_MAX] };

    /// Make the slot a surface of row stride `stride` with no bands.
    fn start(&mut self, stride: u32) {
        self.live = true;
        self.stride = stride;
        self.covered = 0;
        self.n = 0;
    }

    /// The band that holds screen row `row`.
    fn band_of(&self, row: u32) -> Option<Band> {
        let bands = &self.bands[..self.n];
        let i = bands.partition_point(|b| b.top + b.rows <= row);
        bands.get(i).copied().filter(|b| b.top <= row)
    }
}

/// The port that gets the frame events, by packed reference and the epoch of
/// its slot.
#[derive(Clone, Copy)]
struct Link {
    port: u32,
    epoch: u32,
    key: u64,
}

struct State {
    claim: display::Claim,
    surfaces: [Surf; SURFACES],
    vsync: Option<Link>,
    /// Frames presented since the claim.
    frames: u64,
}

static STATE: SpinLock<State> =
    SpinLock::new(State { claim: display::Claim::new(), surfaces: [Surf::FREE; SURFACES], vsync: None, frames: 0 });

/// The screen behind connector 0; none until the kernel registers one.
static SCANOUT: SpinLock<Option<&'static dyn Scanout>> = SpinLock::new(None);

/// Register the scanout behind connector 0. Once: `false` for a second.
pub fn set_scanout(s: &'static dyn Scanout) -> bool {
    let mut slot = SCANOUT.lock();
    if slot.is_some() {
        return false;
    }
    *slot = Some(s);
    true
}

fn scanout() -> Option<&'static dyn Scanout> {
    *SCANOUT.lock()
}

/// The connector behind a badge: connector 0 is the only one backed; the
/// others the topology can spell, and an unbadged endpoint, name nothing.
fn connector_of(badge: u32) -> Result<(), u32> {
    if badge == display::connector_badge(0) { Ok(()) } else { Err(outcome::NO_RESOURCE) }
}

/// The connector as the caller `tid` sees it: the scanout's, with the claim's
/// flags. `None` without a display.
fn describe(tid: u32, st: &State) -> Option<ConnectorInfo> {
    let mut info = scanout()?.connector()?;
    if let Some(h) = st.claim.holder() {
        info.flags |= CONN_CLAIMED;
        if h == tid {
            info.flags |= CONN_YOURS;
        }
    }
    Some(info)
}

// ── capabilities and memory ─────────────────────────────────────────────

/// The caller's capability `raw` as a `T` with `need`, resolved in place (the
/// entry stays in the caller's table): the object it names. A refusal for a
/// right the handle lacks is recorded as a typed denial; anything that is not
/// such a handle is `BAD_ARGUMENT`. Attaching an object steers its life (the
/// kernel pins it), so the use is the `CTL` class.
pub(crate) fn resolve<T: CapTarget>(who: &Caller, raw: u32, need: CapPerms) -> Result<u32, u32> {
    let cap: Cap<T> = Cap::from_raw(CapHandle::from_raw(raw));
    match azos_ipc::cap_store::with_table(who.tid, |t| t.get_op(cap, need, class_op(T::TYPE, CLASS_CTL))) {
        Some(Ok(r)) => Ok(r),
        Some(Err(e)) => {
            crate::handlers::note_typed_denial_for(who.tid, T::TYPE, e);
            Err(match e {
                CapError::MissingPerms | CapError::Contained => outcome::DENIED,
                _ => outcome::BAD_ARGUMENT,
            })
        }
        None => Err(outcome::BAD_ARGUMENT),
    }
}

/// Take the kernel's pinned reference on the memory object `obj`: from then on
/// it cannot be resized, revoked or freed while the kernel holds the frames.
pub(crate) fn pin(obj: u32) -> Result<(), u32> {
    memobj_acquire_ref(MEMOBJ_KERNEL_OWNER, obj).map_err(|_| outcome::FAULT)?;
    if memobj_pin_ref(MEMOBJ_KERNEL_OWNER, obj) != Ok(true) {
        let _ = memobj_release_ref(MEMOBJ_KERNEL_OWNER, obj);
        return Err(outcome::FAULT);
    }
    Ok(())
}

pub(crate) fn unpin(obj: u32) {
    let _ = memobj_release_ref(MEMOBJ_KERNEL_OWNER, obj);
}

/// Give back the kernel's reference on every band of `s`.
fn unpin_all(s: &Surf) {
    for b in &s.bands[..s.n] {
        unpin(b.obj);
    }
}

/// The object a band may be: read-write, `Contig` (one physical run), not
/// reclaimable, and visible to the kernel's direct map. Its pages, and the
/// physical address of the first.
fn surface_object(obj: u32) -> Result<(usize, usize), u32> {
    let d = memobj_describe_ref(obj).map_err(|_| outcome::BAD_ARGUMENT)?;
    if d.perms != MemPerms::ReadWrite
        || d.kind != MemKind::Contig
        || d.attrs & (ATTR_SWAPPABLE | ATTR_NO_KERNEL_MAP) != 0
        || d.page_count == 0
    {
        return Err(outcome::BAD_ARGUMENT);
    }
    let phys = memobj_kernel_page_phys_ref(obj, 0).ok().flatten().ok_or(outcome::BAD_ARGUMENT)?;
    Ok((d.page_count, phys))
}

// ── the handover ────────────────────────────────────────────────────────

/// Give the screen back: let go of every surface and the port, free the claim,
/// and let the text console draw again. `st` is the state with the claim held.
fn teardown(st: &mut State, tid: u32) {
    for s in st.surfaces.iter_mut().filter(|s| s.live) {
        unpin_all(s);
        s.live = false;
    }
    st.vsync = None;
    st.frames = 0;
    let _ = st.claim.release(tid);
    let resumed = scanout().is_some_and(|s| s.resume_console());
    if resumed {
        // The line is also what makes the console draw: its first output after
        // the handover redraws the whole grid.
        azos_drv_sys::kprintln!("[DISPLAY] connector 0 released by tid {}: text console resumed", tid);
    }
}

/// The task `tid` is gone: if it held the claim, the screen goes back to the
/// text console and its surfaces are let go. Called from the kernel's task-exit
/// hook, first among the exit work. The kernel's pinned references on the
/// surfaces are its own and do not depend on the task's capabilities, so the
/// order against their release does not matter.
pub fn release_all(tid: u32) {
    let mut st = STATE.lock();
    if st.claim.holder() == Some(tid) {
        teardown(&mut st, tid);
    }
}

/// The `Display` interface served for one caller.
pub struct Server(pub Caller);

impl Server {
    /// The gate of a drawing op: the capability carries `WRITE`. Containment is
    /// not asked of the endpoint: putting pixels on a screen is no actuation, and
    /// a contained system is when the operator most needs the screen. It is still
    /// asked of the capabilities an op takes (`resolve`: a band, a port), so
    /// `band` and `vsync` are refused while contained (the interface's module
    /// doc).
    fn draw_gate<T: Default>(&self) -> Result<(), Out<T>> {
        if self.0.holds(CapPerms::WRITE) {
            return Ok(());
        }
        self.0.deny(CapPerms::WRITE);
        Err(Out::err(outcome::DENIED))
    }
}

impl azos_devif::Display for Server {
    fn connector(&self) -> Out<ConnectorInfo> {
        if let Err(o) = self.0.gate::<ConnectorInfo>(CapPerms::READ) {
            return o;
        }
        if let Err(c) = connector_of(self.0.badge) {
            return Out::err(c);
        }
        match describe(self.0.tid, &STATE.lock()) {
            Some(info) => Out::ok(info),
            None => Out::err(outcome::NOT_READY),
        }
    }

    fn mode(&self, index: u32) -> Out<Mode> {
        if let Err(o) = self.0.gate::<Mode>(CapPerms::READ) {
            return o;
        }
        if let Err(c) = connector_of(self.0.badge) {
            return Out::err(c);
        }
        let Some(sc) = scanout().filter(|s| s.connector().is_some()) else { return Out::err(outcome::NOT_READY) };
        match sc.mode(index) {
            Some(m) => Out::ok(m),
            None => Out::err(outcome::BAD_ARGUMENT),
        }
    }

    fn claim(&mut self) -> Out<()> {
        if let Err(o) = self.0.gate::<()>(CapPerms::EXEC) {
            return o;
        }
        if let Err(c) = connector_of(self.0.badge) {
            return Out::err(c);
        }
        let mut st = STATE.lock();
        let Some(sc) = scanout().filter(|s| s.connector().is_some()) else { return Out::err(outcome::NOT_READY) };
        match st.claim.claim(self.0.tid) {
            Ok(true) => {
                st.frames = 0;
                sc.retire_console();
                azos_drv_sys::kprintln!("[DISPLAY] connector 0 claimed by tid {}: text console retired", self.0.tid);
                Out::ok(())
            }
            Ok(false) => Out::ok(()),
            Err(c) => Out::err(c),
        }
    }

    fn release(&mut self) -> Out<()> {
        if let Err(o) = self.0.gate::<()>(CapPerms::EXEC) {
            return o;
        }
        if let Err(c) = connector_of(self.0.badge) {
            return Out::err(c);
        }
        let mut st = STATE.lock();
        match st.claim.require(self.0.tid) {
            Ok(()) => {
                teardown(&mut st, self.0.tid);
                Out::ok(())
            }
            // Nobody holds it: nothing to give back.
            Err(outcome::NOT_READY) => Out::ok(()),
            Err(c) => Out::err(c),
        }
    }

    fn surface(&mut self, stride: u32, format: u32) -> Out<u32> {
        if let Err(o) = self.draw_gate::<u32>() {
            return o;
        }
        if let Err(c) = connector_of(self.0.badge) {
            return Out::err(c);
        }
        let mut st = STATE.lock();
        let Some(info) = describe(self.0.tid, &st) else { return Out::err(outcome::NOT_READY) };
        if let Err(c) = st.claim.require(self.0.tid).and_then(|()| info.check_surface(stride, format)) {
            return Out::err(c);
        }
        match st.surfaces.iter().position(|s| !s.live) {
            Some(slot) => {
                st.surfaces[slot].start(stride);
                Out::ok(slot as u32 + 1)
            }
            None => Out::err(outcome::BUSY),
        }
    }

    fn band(&mut self, id: u32, mem: WireCap<display::SurfaceBand>) -> Out<u32> {
        if let Err(o) = self.draw_gate::<u32>() {
            return o;
        }
        if let Err(c) = connector_of(self.0.badge) {
            return Out::err(c);
        }
        let who = self.0;
        let Some(info) = describe(who.tid, &STATE.lock()) else { return Out::err(outcome::NOT_READY) };
        // The capability and the object first, with no lock held; the lock is
        // then held for the claim, the rows and the pin.
        let obj = match resolve::<targets::Shm>(&who, mem.raw(), CapPerms::RW) {
            Ok(o) => o,
            Err(c) => return Out::err(c),
        };
        let (pages, phys) = match surface_object(obj) {
            Ok(v) => v,
            Err(c) => return Out::err(c),
        };
        let mut st = STATE.lock();
        if let Err(c) = st.claim.require(who.tid) {
            return Out::err(c);
        }
        if st.surfaces.iter().filter(|s| s.live).any(|s| s.bands[..s.n].iter().any(|b| b.obj == obj)) {
            return Out::err(outcome::BUSY);
        }
        let Some(surf) = (id as usize).checked_sub(1).and_then(|i| st.surfaces.get_mut(i)).filter(|s| s.live) else {
            return Out::err(outcome::NO_RESOURCE);
        };
        if surf.n >= BANDS_MAX {
            return Out::err(outcome::BUSY);
        }
        let rows = match band_take(info.height, surf.covered, surf.stride, (pages * azos_arch::PAGE_SIZE) as u64) {
            Ok(r) => r,
            Err(c) => return Out::err(c),
        };
        if let Err(c) = pin(obj) {
            return Out::err(c);
        }
        surf.bands[surf.n] = Band { obj, phys, top: surf.covered, rows };
        surf.n += 1;
        surf.covered += rows;
        Out::ok(surf.covered)
    }

    fn destroy_surface(&mut self, id: u32) -> Out<()> {
        if let Err(o) = self.draw_gate::<()>() {
            return o;
        }
        if let Err(c) = connector_of(self.0.badge) {
            return Out::err(c);
        }
        let mut st = STATE.lock();
        if let Err(c) = st.claim.require(self.0.tid) {
            return Out::err(c);
        }
        match (id as usize).checked_sub(1).and_then(|i| st.surfaces.get_mut(i)).filter(|s| s.live) {
            Some(s) => {
                unpin_all(s);
                s.live = false;
                Out::ok(())
            }
            None => Out::err(outcome::NO_RESOURCE),
        }
    }

    fn present(&mut self, request: Present) -> Out<u64> {
        if let Err(o) = self.draw_gate::<u64>() {
            return o;
        }
        if let Err(c) = connector_of(self.0.badge) {
            return Out::err(c);
        }
        let tid = self.0.tid;
        let id = request.surface as usize;
        let Some(sc) = scanout() else { return Out::err(outcome::NOT_READY) };
        let stride = {
            let st = STATE.lock();
            let Some(info) = describe(tid, &st) else { return Out::err(outcome::NOT_READY) };
            if let Err(c) = st.claim.require(tid) {
                return Out::err(c);
            }
            if let Err(c) = request.check(&info) {
                return Out::err(c);
            }
            let Some(surf) = id.checked_sub(1).and_then(|i| st.surfaces.get(i)).filter(|s| s.live) else {
                return Out::err(outcome::NO_RESOURCE);
            };
            if surf.covered < info.height {
                return Out::err(outcome::NOT_READY);
            }
            surf.stride
        };
        // A panic owns the screen and nothing may draw over it.
        if sc.panic_active() {
            return Out::err(outcome::BUSY);
        }
        for r in request.damage() {
            let end = r.y as u32 + r.h as u32;
            let mut row = r.y as u32;
            while row < end {
                // The band that holds this row. The holder is the only task that
                // changes the surfaces, so it is still there when the lock is
                // gone.
                let band = {
                    let st = STATE.lock();
                    st.surfaces.get(id - 1).filter(|s| s.live).and_then(|s| s.band_of(row))
                };
                let Some(band) = band else { return Out::err(outcome::FAULT) };
                let take = end.min(band.top + band.rows) - row;
                let src = azos_mm::addr::phys_to_virt(band.phys) as *const core::sync::atomic::AtomicU8;
                let len = band.rows as usize * stride as usize;
                // The rows fit 16 bits: they lie inside the screen the rectangle
                // was checked against, and a rectangle names its rows in 16 bits.
                let (Ok(y), Ok(h)) = (u16::try_from(row), u16::try_from(take)) else { return Out::err(outcome::FAULT) };
                // SAFETY: the object is pinned by the kernel and is one contiguous
                // run (module doc, "Trust in the surface"); the direct map covers
                // it, and `rows * stride` bytes of it are rows by `band_take`. The
                // client writes it meanwhile, so the bytes are atomics.
                let src = unsafe { core::slice::from_raw_parts(src, len) };
                let copied = sc.copy_rect(src, stride, band.top, Rect { x: r.x, y, w: r.w, h });
                if !copied {
                    // `check_surface`, `band_take` and `Present::check` made this
                    // impossible; the scanout refusing is the kernel's own bug.
                    return Out::err(outcome::FAULT);
                }
                row += take;
            }
            // The display is told once per rectangle, not once per band.
            sc.flip(*r);
        }
        let (seq, link) = {
            let mut st = STATE.lock();
            st.frames += 1;
            (st.frames, st.vsync)
        };
        if let Some(l) = link {
            let ev = PortEvent { key: l.key, source_type: PORT_EVENT_TIMER, source_id: seq as u32, code: 0, cpu: 0 };
            if !port_queue_event_bound(l.port, l.epoch, ev) {
                // The server's port is gone: stop posting to it.
                let mut st = STATE.lock();
                if st.vsync.is_some_and(|c| c.port == l.port && c.epoch == l.epoch) {
                    st.vsync = None;
                }
            }
        }
        Out::ok(seq)
    }

    fn vsync(&mut self, events: WireCap<display::VsyncPort>, key: u64) -> Out<()> {
        if let Err(o) = self.draw_gate::<()>() {
            return o;
        }
        if let Err(c) = connector_of(self.0.badge) {
            return Out::err(c);
        }
        let who = self.0;
        let port = match resolve::<targets::Port>(&who, events.raw(), CapPerms::WRITE) {
            Ok(p) => p,
            Err(c) => return Out::err(c),
        };
        let Ok(epoch) = port_live_epoch(port) else { return Out::err(outcome::BAD_ARGUMENT) };
        let mut st = STATE.lock();
        if let Err(c) = st.claim.require(who.tid) {
            return Out::err(c);
        }
        st.vsync = Some(Link { port, epoch, key });
        Out::ok(())
    }
}

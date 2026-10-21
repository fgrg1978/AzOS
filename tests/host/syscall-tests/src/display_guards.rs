// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// Host tests for the kernel-hosted `Display` interface --
// `crates/core/syscall/src/display.rs::Server`, and `khost::serve` in front of
// it: the authority each op demands, the claim and the console handover, the
// bands of a surface, the copy of a present into a framebuffer that is a
// `Vec`, the frame event on a port, the exit of the holder, and the mode list
// an EDID gives. The rules those lean on are `tests/host/devif-tests/tests/
// display.rs`, the EDID parser's `tests/host/fb-tests/tests/edid.rs`.
//
// Included inside `mod handlers { .. }` like `net_guards.rs`.

use super::harness::serial;
use azos_abi::cap::CapPerms;
use azos_devif::display::{
    self, ConnectorInfo, Present, Rect, CONN_CLAIMED, CONN_CONNECTED, CONN_EDID, CONN_YOURS, FORMAT_RGB565,
    FORMAT_XRGB8888, MODE_CURRENT, MODE_PREFERRED,
};
use azos_devif::{key, outcome, Cap as WireCap, Display, DisplayIdl, Out};
use azos_fb::pixel::PixelFormat;
use azos_fb::FbInfo;
use azos_idl::{header, MsgDesc, Writer, MSG_VERSION};
use azos_ipc::cap::targets::{Port, Shm};
use azos_ipc::memobj::{memobj_clone_cap, memobj_create_cap, MemPerms, MemSpec};
use crate::display::{release_all, set_scanout, Server};
use azos_fb::scanout::{publish_edid, SCANOUT};
use crate::khost::Caller;
use std::sync::atomic::{AtomicU32, Ordering::SeqCst};
use std::sync::Mutex;

/// Cap-store pool slots for this file (`SLOT`, and `SLOT2` for a second task);
/// no other file in this crate binds 63 or 29.
const SLOT: usize = 63;
const SLOT2: usize = 29;

static NEXT_TID: AtomicU32 = AtomicU32::new(0x7e63_0001);
/// `(kind code, reason code)` of every typed capability denial recorded.
static DENIALS: Mutex<Vec<(u8, u32)>> = Mutex::new(Vec::new());

fn typed_recorder(kind_code: u8, reason_code: u32) {
    DENIALS.lock().unwrap_or_else(|e| e.into_inner()).push((kind_code, reason_code));
}

fn denials() -> Vec<(u8, u32)> {
    DENIALS.lock().unwrap_or_else(|e| e.into_inner()).clone()
}

const ENDPOINT_CODE: u8 = azos_abi::cap::ty::ENDPOINT.denial_code();
const MISSING_PERMS: u32 = 3;

/// A task with an empty table. Dropping it ends its claim (as the kernel's exit
/// hook does), releases its memory objects and the containment flag.
struct Scene {
    tid: u32,
}

impl Drop for Scene {
    fn drop(&mut self) {
        release_all(self.tid);
        azos_ipc::cap::degraded_set(false);
        azos_ipc::memobj::memobj_release_all(self.tid);
        ipc_task_pool::shim_kill(self.tid);
    }
}

fn scene_in(slot: usize) -> Scene {
    DENIALS.lock().unwrap_or_else(|e| e.into_inner()).clear();
    let tid = NEXT_TID.fetch_add(1, SeqCst);
    ipc_task_pool::shim_bind(tid, slot);
    azos_ipc::cap_store::reset(tid);
    azos_sched::set_current_user_pt(0xBAD0_0000);
    azos_sched::set_current_task_tid(tid);
    set_cap_deny_typed_recorder(typed_recorder);
    Scene { tid }
}

fn scene() -> Scene {
    scene_in(SLOT)
}

fn server(s: &Scene, rights: CapPerms) -> Server {
    Server(Caller { tid: s.tid, badge: display::connector_badge(0), rights })
}

/// All three classes: what a display server holds.
fn full(s: &Scene) -> Server {
    server(s, CapPerms::ALL)
}

/// A read-write contiguous region of `pages` pages, with its handle.
fn region(s: &Scene, pages: usize) -> WireCap<display::SurfaceBand> {
    let cap = memobj_create_cap(s.tid, pages, &MemSpec::contig(MemPerms::ReadWrite, false)).expect("a region");
    WireCap::from_raw(cap.raw().0)
}

/// `f` with a region of `pages` pages, which is given back after: the table
/// of memory objects is 16 entries for the whole suite and 8 for a task.
fn with_region<R>(s: &Scene, pages: usize, spec: MemSpec, f: impl FnOnce(WireCap<display::SurfaceBand>) -> R) -> R {
    let cap = memobj_create_cap(s.tid, pages, &spec).expect("a region");
    let out = f(WireCap::from_raw(cap.raw().0));
    azos_ipc::cap_store::read_table(s.tid, |t| azos_ipc::memobj::memobj_release_cap(s.tid, t, cap)).expect("a table").expect("released");
    out
}

fn raw_port(s: &Scene) -> (WireCap<display::VsyncPort>, azos_ipc::cap::Cap<Port>) {
    let p = azos_ipc::port::port_create_cap(s.tid).expect("a port");
    (WireCap::from_raw(p.raw().0), p)
}

const FHD_EDID: &str = concat!(
    "00ffffffffffff0007543412010101010c1f010380331d782aee91a3544c9926",
    "0f5054210800818081409500a9c0b300810001010101023a801871382d40582c",
    "4500fd1e1100001e000000fc00415a2046484432330a20202020000000fd0030",
    "4b1e5311000a202020202020000000ff00534e303030310a2020202020200007",
);

/// Every op demands its own class and refuses before it looks at anything
/// else, recording the refusal once; the class alone gets past the gate. A
/// contained system keeps `READ` and `EXEC` and, for the drawing ops, `WRITE`
/// too: putting pixels on a screen is no actuation.
///
/// **Canary.** Make the drawing gate `allows` (containment-aware) instead of
/// `holds`: `present` and `surface` answer `DENIED` in the contained rows.
#[test]
fn every_op_demands_its_class_and_a_contained_system_still_draws() {
    let _g = serial();
    let s = scene();
    let region = region(&s, 1);
    let (port, _) = raw_port(&s);
    let one = Present::new(1, &[Rect::new(0, 0, 1, 1)]).unwrap();
    type Call<'a> = &'a dyn Fn(&mut Server) -> u32;
    let rows: [(&str, CapPerms, Call); 9] = [
        ("connector", CapPerms::READ, &|d| d.connector().code),
        ("mode", CapPerms::READ, &|d| d.mode(0).code),
        ("claim", CapPerms::EXEC, &|d| d.claim().code),
        ("release", CapPerms::EXEC, &|d| d.release().code),
        ("surface", CapPerms::WRITE, &|d| d.surface(5120, FORMAT_XRGB8888).code),
        ("band", CapPerms::WRITE, &|d| d.band(1, region).code),
        ("destroy_surface", CapPerms::WRITE, &|d| d.destroy_surface(1).code),
        ("present", CapPerms::WRITE, &|d| d.present(one).code),
        ("vsync", CapPerms::WRITE, &|d| d.vsync(port, 7).code),
    ];
    for (name, need, call) in rows {
        let out = call(&mut server(&s, need));
        assert_ne!(out, outcome::DENIED, "{name} with {need:?} alone");
        assert!(denials().is_empty(), "{name} served is not a refusal");
        for other in [CapPerms::READ, CapPerms::WRITE, CapPerms::EXEC, CapPerms::NONE] {
            if other == need {
                continue;
            }
            DENIALS.lock().unwrap().clear();
            assert_eq!(call(&mut server(&s, other)), outcome::DENIED, "{name} with only {other:?}");
            assert_eq!(denials(), vec![(ENDPOINT_CODE, MISSING_PERMS)], "{name}: the refusal is recorded once");
        }
        DENIALS.lock().unwrap().clear();
    }
    // Contained: reading, controlling and presenting stay (the two ops that take
    // a WRITE capability are refused by its containment: `a_display_server_...`).
    azos_ipc::cap::degraded_set(true);
    for (name, need, call) in rows {
        if name != "band" && name != "vsync" {
            assert_ne!(call(&mut server(&s, need)), outcome::DENIED, "{name} while contained");
        }
    }
    assert!(denials().is_empty(), "nothing was refused");
}

/// Connector 0 is the only one backed: the unbadged endpoint and the ones the
/// topology can spell but nothing serves name no resource, op by op.
#[test]
fn only_connector_zero_is_served() {
    let _g = serial();
    let s = scene();
    let region = region(&s, 1);
    let (port, _) = raw_port(&s);
    let one = Present::new(1, &[Rect::new(0, 0, 1, 1)]).unwrap();
    for badge in [0, 2, 3, 4, 5, u32::MAX] {
        let mut d = Server(Caller { tid: s.tid, badge, rights: CapPerms::ALL });
        let codes = [
            d.connector().code,
            d.mode(0).code,
            d.claim().code,
            d.release().code,
            d.surface(5120, FORMAT_XRGB8888).code,
            d.band(1, region).code,
            d.destroy_surface(1).code,
            d.present(one).code,
            d.vsync(port, 1).code,
        ];
        assert_eq!(codes, [outcome::NO_RESOURCE; 9], "badge {badge}");
    }
}

/// Through `khost::serve`: the interface is the only one besides the queue and
/// VM ones whose requests may carry capability entries; a `connector` request
/// answers its five words; a `present` header with the surface unknown answers
/// the server's refusal in the outcome word.
#[test]
fn the_wire_form_round_trips_through_khost() {
    let _g = serial();
    let s = scene();
    assert!(crate::khost::takes_caps(key::DISPLAY));
    assert!(!crate::khost::takes_caps(key::NET) && !crate::khost::takes_caps(key::BLOCK));

    let who = Caller { tid: s.tid, badge: display::connector_badge(0), rights: CapPerms::RW };
    let mut req = MsgDesc { version: MSG_VERSION, ..MsgDesc::default() };
    {
        let mut w = Writer::new(&mut req);
        w.word(header(DisplayIdl::ID, DisplayIdl::LEVEL, DisplayIdl::OP_CONNECTOR));
        w.finish();
    }
    let mut rep = MsgDesc::default();
    crate::khost::serve(key::DISPLAY, &who, &req, &mut rep);
    assert_eq!(rep.words[0], azos_idl::STATUS_OK);
    let code = rep.words[1] as u32;
    assert!(code == outcome::OK || code == outcome::NOT_READY, "served, or no scanout in this process yet: {code}");
    assert_eq!(rep.n_words, if code == outcome::OK { 7 } else { 7 }, "status, outcome and five words either way");

    // A present of surface 9 with one rectangle: the whole eight-word request.
    let p = Present::new(9, &[Rect::new(0, 0, 4, 4)]).unwrap();
    let mut req = MsgDesc { version: MSG_VERSION, ..MsgDesc::default() };
    {
        use azos_devif::Wire;
        let mut w = Writer::new(&mut req);
        w.word(header(DisplayIdl::ID, DisplayIdl::LEVEL, DisplayIdl::OP_PRESENT));
        p.put(&mut w);
        w.finish();
    }
    assert_eq!(req.n_words, 8);
    let mut rep = MsgDesc::default();
    crate::khost::serve(key::DISPLAY, &who, &req, &mut rep);
    assert_eq!(rep.words[0], azos_idl::STATUS_OK);
    assert_ne!(rep.words[1] as u32, outcome::OK, "nothing to present from");
}

// ── the whole path, over a framebuffer that is a Vec ────────────────────

const W: u32 = 640;
const H: u32 = 480;
/// A padded row, as hardware has.
const STRIDE: u32 = W * 4 + 64;
/// Pages of one band on the host's 4 KiB granule: 64 pages, 99 rows of 2,624 bytes.
const BAND_PAGES: usize = 64;
const BAND_ROWS: u32 = (BAND_PAGES * 4096 / STRIDE as usize) as u32;

static FB_MEM: AtomicU32 = AtomicU32::new(0);
static FB_BASE: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
static FLIPS: Mutex<Vec<azos_fb::Rect>> = Mutex::new(Vec::new());

fn flip_hook(r: azos_fb::Rect) {
    FLIPS.lock().unwrap().push(r);
}

fn flips() -> Vec<azos_fb::Rect> {
    std::mem::take(&mut *FLIPS.lock().unwrap())
}

/// The framebuffer's pixel at (x, y), as the host sees the scanout.
fn screen_px(x: u32, y: u32) -> u32 {
    let base = FB_BASE.load(SeqCst) as *const u8;
    // SAFETY: inside the leaked `STRIDE * H` byte buffer registered below.
    unsafe { (base.add((y * STRIDE + x * 4) as usize) as *const u32).read_unaligned() }
}

fn px_pattern(x: u32, y: u32) -> u32 {
    y * 1000 + x + 1
}

/// Write the pattern into the rows `[top, top + rows)` of the band region `cap`
/// (its row 0 is the band's first).
fn paint(s: &Scene, cap: WireCap<display::SurfaceBand>, top: u32, rows: u32) {
    let r = azos_ipc::cap_store::get(s.tid, azos_ipc::cap::Cap::<Shm>::from_raw(azos_abi::cap::CapHandle::from_raw(cap.raw())), CapPerms::READ)
        .expect("the region");
    let phys = azos_ipc::memobj::memobj_page_phys_ref(r, 0).unwrap().unwrap();
    let base = azos_mm::addr::phys_to_virt(phys) as *mut u8;
    for row in 0..rows {
        for x in 0..W {
            // SAFETY: inside the region: `rows * STRIDE` bytes of a `BAND_PAGES` page run.
            unsafe { (base.add((row * STRIDE + x * 4) as usize) as *mut u32).write_unaligned(px_pattern(x, top + row)) };
        }
    }
}

fn event(s: &Scene, p: azos_ipc::cap::Cap<Port>) -> Option<azos_ipc::port::PortEvent> {
    azos_ipc::cap_store::read_table(s.tid, |t| azos_ipc::port::port_poll_cap(t, p)).and_then(|r| r.ok())
}

fn first_use_of_the_scanout() {
    // Nothing is registered yet: the connector, its modes and the claim say so.
    let s = scene();
    let mut d = full(&s);
    assert_eq!(d.connector().code, outcome::NOT_READY);
    assert_eq!(d.mode(0).code, outcome::NOT_READY);
    assert_eq!(d.claim().code, outcome::NOT_READY, "no console to retire, nothing to hold");
    assert!(!azos_fb::console_retired());
    assert!(!publish_edid(&[0u8; 200]), "not an EDID");

    let mem: &'static mut [u8] = Box::leak(vec![0u8; (STRIDE * H) as usize].into_boxed_slice());
    FB_BASE.store(mem.as_ptr() as usize, SeqCst);
    FB_MEM.store(mem.len() as u32, SeqCst);
    let info = FbInfo { phys: 0x9000_0000, width: W, height: H, stride: STRIDE, format: PixelFormat::XRGB8888 };
    assert!(azos_fb::register(info, mem.as_mut_ptr() as usize));
    assert!(azos_fb::set_flip(flip_hook));
    assert!(set_scanout(&SCANOUT), "the kernel registers it once the framebuffer is");
    assert!(!set_scanout(&SCANOUT), "once");
}

/// One test: the framebuffer registry is process-wide and registers once.
///
/// The connector as the scanout runs it, the EDID's modes behind it, the
/// claim and its refusals, a surface of five bands, a present that crosses a
/// band seam, the copy and the one flip per rectangle, the frame events, a
/// band cloned, the destroy, the release and the holder's exit.
///
/// **Canary.** Read a band from its object's row 0 instead of from the
/// surface row it starts at (`src_top`): every pixel below the first seam comes
/// from the wrong row and the full-screen comparison fails.
#[test]
fn a_display_server_from_claim_to_exit() {
    let _g = serial();
    first_use_of_the_scanout();

    let a = scene();
    let b = scene_in(SLOT2);
    let (mut da, mut db) = (full(&a), full(&b));

    // ── the connector without an EDID ──
    let c = da.connector().value;
    assert_eq!(
        c,
        ConnectorInfo {
            width: W,
            height: H,
            stride: STRIDE,
            format: FORMAT_XRGB8888,
            refresh_mhz: 60_000,
            flags: CONN_CONNECTED,
            width_mm: 0,
            height_mm: 0,
            modes: 1,
            surfaces: display::SURFACES as u32
        }
    );
    let m0 = da.mode(0).value;
    assert_eq!((m0.width, m0.height, m0.refresh_mhz, m0.flags), (W, H, 60_000, MODE_CURRENT));
    assert_eq!(da.mode(1).code, outcome::BAD_ARGUMENT, "one mode without an EDID");

    // ── with one: the current mode first, the display's others after it ──
    let edid = {
        let h = FHD_EDID;
        (0..h.len()).step_by(2).map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap()).collect::<Vec<u8>>()
    };
    let mut broken = edid.clone();
    broken[40] ^= 1;
    assert!(!publish_edid(&broken), "a bad checksum is not taken");
    assert_eq!(da.connector().value.flags & CONN_EDID, 0, "and changes nothing");
    assert!(publish_edid(&edid));
    let c = da.connector().value;
    assert_eq!((c.flags, c.width_mm, c.height_mm, c.refresh_mhz), (CONN_CONNECTED | CONN_EDID, 509, 286, 60_000));
    // The display lists 640x480 at 60 Hz (an established timing): that is the
    // current mode, listed once; the other nine follow in the display's order,
    // 1920x1080 first, flagged preferred.
    assert_eq!(c.modes, 10);
    let list: Vec<_> = (0..c.modes).map(|i| da.mode(i).value).collect();
    assert_eq!((list[0].width, list[0].height, list[0].flags), (640, 480, MODE_CURRENT));
    assert_eq!((list[1].width, list[1].height, list[1].refresh_mhz, list[1].flags), (1920, 1080, 60_000, MODE_PREFERRED));
    assert_eq!((list[9].width, list[9].height), (1024, 768));
    assert_eq!(list.iter().filter(|m| (m.width, m.height) == (640, 480)).count(), 1);
    assert_eq!(list.iter().filter(|m| m.flags & MODE_PREFERRED != 0).count(), 1);
    assert_eq!(da.mode(10).code, outcome::BAD_ARGUMENT);

    // ── the claim ──
    assert_eq!(da.present(Present::new(1, &[Rect::new(0, 0, 4, 4)]).unwrap()).code, outcome::NOT_READY, "claim first");
    assert_eq!(da.claim(), Out::ok(()));
    assert_eq!(da.claim(), Out::ok(()), "again");
    assert!(azos_fb::console_retired(), "the claim retired the text console");
    assert_eq!(da.connector().value.flags & (CONN_CLAIMED | CONN_YOURS), CONN_CLAIMED | CONN_YOURS);
    assert_eq!(db.connector().value.flags & (CONN_CLAIMED | CONN_YOURS), CONN_CLAIMED, "claimed, not by b");
    assert_eq!(db.claim().code, outcome::BUSY);
    assert_eq!(db.release().code, outcome::BUSY);
    assert_eq!(db.surface(STRIDE, FORMAT_XRGB8888).code, outcome::BUSY, "only the holder draws");
    assert_eq!(db.present(Present::new(1, &[Rect::new(0, 0, 4, 4)]).unwrap()).code, outcome::BUSY);
    assert_eq!(db.vsync(raw_port(&b).0, 1).code, outcome::BUSY);

    // ── a surface and its bands ──
    assert_eq!(da.surface(STRIDE, FORMAT_RGB565).code, outcome::BAD_ARGUMENT, "not the scanout's format");
    assert_eq!(da.surface(W * 4 - 1, FORMAT_XRGB8888).code, outcome::BAD_ARGUMENT, "a row shorter than the screen's");
    assert_eq!(da.surface(STRIDE, FORMAT_XRGB8888), Out::ok(1));
    assert_eq!(da.present(Present::new(1, &[Rect::new(0, 0, 4, 4)]).unwrap()).code, outcome::NOT_READY, "no pixels yet");
    let contig = || MemSpec::contig(MemPerms::ReadWrite, false);
    assert_eq!(with_region(&a, 1, contig(), |r| da.band(2, r)).code, outcome::NO_RESOURCE);
    assert_eq!(da.band(1, WireCap::from_raw(0x7777)).code, outcome::BAD_ARGUMENT, "not a capability");
    let anon = MemSpec::anon(MemPerms::ReadWrite);
    assert_eq!(with_region(&a, 1, anon, |r| da.band(1, r)).code, outcome::BAD_ARGUMENT, "anonymous frames are not one run");
    let ro = MemSpec::contig(MemPerms::ReadOnly, false);
    assert_eq!(with_region(&a, 1, ro, |r| da.band(1, r)).code, outcome::DENIED, "the server writes the pixels: read-write");

    // Five bands of 99 rows cover 480: the last takes the 84 that are left.
    let bands: Vec<_> = (0..5).map(|_| region(&a, BAND_PAGES)).collect();
    for (k, &band) in bands.iter().enumerate() {
        let top = k as u32 * BAND_ROWS;
        let want = (top + BAND_ROWS).min(H);
        assert_eq!(da.present(Present::new(1, &[Rect::new(0, 0, 4, 4)]).unwrap()).code, outcome::NOT_READY, "{k} bands");
        assert_eq!(da.band(1, band), Out::ok(want), "band {k}");
        paint(&a, band, top, want - top);
    }
    assert_eq!(with_region(&a, 1, contig(), |r| da.band(1, r)).code, outcome::BUSY, "the surface is complete");
    // A region already a band is refused (checked before the rows are, so a second surface sees it too).
    assert_eq!(da.surface(STRIDE, FORMAT_XRGB8888), Out::ok(2));
    assert_eq!(da.band(2, bands[0]).code, outcome::BUSY, "one object is one band of one surface");
    assert_eq!(da.destroy_surface(2), Out::ok(()));

    // ── present ──
    let vsync_region_not_a_port = da.vsync(WireCap::from_raw(bands[0].raw()), 1);
    assert_eq!(vsync_region_not_a_port.code, outcome::BAD_ARGUMENT, "a memory object is not a port");
    let (port, port_cap) = raw_port(&a);
    assert_eq!(da.vsync(port, 0xFEED_0001), Out::ok(()));
    let _ = flips();

    // A rectangle that crosses the seam between the bands of rows 0..99 and 99..198.
    let r1 = Rect::new(10, 90, 20, 20);
    assert_eq!(da.present(Present::new(1, &[r1]).unwrap()), Out::ok(1), "frame 1");
    assert_eq!(flips(), vec![azos_fb::Rect { x: 10, y: 90, w: 20, h: 20 }], "one flip for the rectangle, not one per band");
    for y in 0..H {
        for x in 0..W {
            let inside = (10..30).contains(&x) && (90..110).contains(&y);
            assert_eq!(screen_px(x, y), if inside { px_pattern(x, y) } else { 0 }, "pixel ({x},{y})");
        }
    }
    let ev = event(&a, port_cap).expect("the frame event");
    assert_eq!((ev.key, ev.source_type, ev.source_id, ev.code), (0xFEED_0001, azos_abi::syscall_nr::PORT_EVENT_TIMER, 1, 0));
    assert!(event(&a, port_cap).is_none(), "one event per frame");

    // The whole screen, and six rectangles in one call: each one flipped.
    assert_eq!(da.present(Present::new(1, &[Rect::full(W, H)]).unwrap()), Out::ok(2));
    assert_eq!(flips(), vec![azos_fb::Rect { x: 0, y: 0, w: W, h: H }]);
    for y in (0..H).step_by(7) {
        for x in 0..W {
            assert_eq!(screen_px(x, y), px_pattern(x, y), "pixel ({x},{y})");
        }
    }
    assert_eq!(screen_px(W - 1, H - 1), px_pattern(W - 1, H - 1), "the last pixel, the last band");
    assert_eq!(event(&a, port_cap).map(|e| e.source_id), Some(2), "frame 2");
    let six: Vec<_> = (0..6).map(|i| Rect::new(i * 3, i * 70, 3, 5)).collect();
    assert_eq!(da.present(Present::new(1, &six).unwrap()), Out::ok(3));
    assert_eq!(flips().len(), 6);
    let _ = event(&a, port_cap);

    // Refusals leave the screen and the frame count alone.
    let before = screen_px(5, 5);
    for bad in [
        Present::new(1, &[Rect::new(W as u16 - 1, 0, 2, 1)]).unwrap(),
        Present::new(1, &[Rect::new(0, H as u16, 1, 1)]).unwrap(),
        Present::new(1, &[Rect::new(0, 0, 0, 1)]).unwrap(),
        Present { surface: 1, count: 0, rects: [Rect::default(); display::DAMAGE_MAX] },
    ] {
        assert_eq!(da.present(bad).code, outcome::BAD_ARGUMENT);
    }
    assert_eq!(da.present(Present::new(0, &[Rect::new(0, 0, 1, 1)]).unwrap()).code, outcome::NO_RESOURCE, "surface 0");
    assert_eq!(da.present(Present::new(3, &[Rect::new(0, 0, 1, 1)]).unwrap()).code, outcome::NO_RESOURCE);
    assert_eq!(da.present(Present::new(5, &[Rect::new(0, 0, 1, 1)]).unwrap()).code, outcome::NO_RESOURCE);
    assert!(flips().is_empty() && event(&a, port_cap).is_none());
    assert_eq!(screen_px(5, 5), before);
    assert_eq!(da.present(Present::new(1, &[Rect::new(0, 0, 1, 1)]).unwrap()), Out::ok(4), "the count went on from 3");
    let _ = (flips(), event(&a, port_cap));

    // ── contained ──
    // The endpoint keeps presenting; the two ops that take a WRITE capability are
    // refused by that capability's containment.
    azos_ipc::cap::degraded_set(true);
    assert_eq!(da.present(Present::new(1, &[Rect::new(0, 0, 4, 4)]).unwrap()), Out::ok(5));
    assert_eq!(da.surface(STRIDE, FORMAT_XRGB8888), Out::ok(2));
    assert_eq!(da.destroy_surface(2), Out::ok(()));
    assert_eq!(with_region(&a, 1, contig(), |r| da.band(1, r)).code, outcome::DENIED);
    assert_eq!(da.vsync(port, 1).code, outcome::DENIED);
    azos_ipc::cap::degraded_set(false);
    assert_eq!(da.vsync(port, 0xFEED_0001), Out::ok(()), "and works again");
    let _ = (flips(), event(&a, port_cap));

    // ── a clone of a band is a copy ──
    // `memobj_clone` shares frames only for Anon objects; a Contig band is
    // copied, so cloning it (and writing the clone) leaves what the kernel
    // reads untouched and the present going.
    let cap3 = azos_ipc::cap::Cap::<Shm>::from_raw(azos_abi::cap::CapHandle::from_raw(bands[3].raw()));
    let clone = memobj_clone_cap(a.tid, cap3, MemPerms::ReadWrite, 0).expect("a clone");
    let r3 = azos_ipc::cap_store::get(a.tid, clone, CapPerms::READ).unwrap();
    let phys = azos_ipc::memobj::memobj_page_phys_ref(r3, 0).unwrap().unwrap();
    // SAFETY: the clone's first page, ours alone.
    unsafe { (azos_mm::addr::phys_to_virt(phys) as *mut u32).write(0xDEAD_BEEF) };
    assert_eq!(azos_ipc::memobj::memobj_describe_ref(r3).unwrap().cow_shared, 0, "copied, not shared");
    assert_eq!(da.present(Present::new(1, &[Rect::new(0, 297, 4, 1)]).unwrap()), Out::ok(6));
    assert_eq!(screen_px(0, 297), px_pattern(0, 297), "the band's pixels, not the clone's");
    let _ = flips();

    // ── destroy ──
    assert_eq!(da.destroy_surface(0).code, outcome::NO_RESOURCE);
    assert_eq!(da.destroy_surface(1), Out::ok(()));
    assert_eq!(da.destroy_surface(1).code, outcome::NO_RESOURCE, "once");
    assert_eq!(da.present(Present::new(1, &[Rect::new(0, 0, 1, 1)]).unwrap()).code, outcome::NO_RESOURCE);
    // Its bands are free again.
    assert_eq!(da.surface(STRIDE, FORMAT_XRGB8888), Out::ok(1));
    assert_eq!(da.band(1, bands[0]), Out::ok(BAND_ROWS));
    let mut ids = Vec::new();
    for _ in 0..display::SURFACES {
        ids.push(da.surface(STRIDE, FORMAT_XRGB8888).code);
    }
    assert_eq!(ids, vec![outcome::OK, outcome::OK, outcome::OK, outcome::BUSY], "{} surfaces in all", display::SURFACES);

    // ── release ──
    assert_eq!(db.release().code, outcome::BUSY);
    assert_eq!(da.release(), Out::ok(()));
    assert!(!azos_fb::console_retired(), "the text console is back");
    assert_eq!(da.release(), Out::ok(()), "nothing to give back");
    assert_eq!(da.connector().value.flags & (CONN_CLAIMED | CONN_YOURS), 0);
    assert_eq!(da.present(Present::new(1, &[Rect::new(0, 0, 1, 1)]).unwrap()).code, outcome::NOT_READY, "surfaces went with the claim");
    // b can take it now, and a holder that exits gives it back without asking.
    assert_eq!(db.claim(), Out::ok(()));
    assert!(azos_fb::console_retired());
    assert_eq!(da.claim().code, outcome::BUSY);
    release_all(a.tid);
    assert!(azos_fb::console_retired(), "a never held it: its exit changes nothing");
    release_all(b.tid);
    assert!(!azos_fb::console_retired(), "b's exit gave the screen back");
    assert_eq!(db.present(Present::new(1, &[Rect::new(0, 0, 1, 1)]).unwrap()).code, outcome::NOT_READY);
    assert_eq!(da.claim(), Out::ok(()));
    assert_eq!(da.surface(STRIDE, FORMAT_XRGB8888), Out::ok(1));
    assert_eq!(da.band(1, bands[1]), Out::ok(BAND_ROWS));
    release_all(a.tid);
    assert_eq!(db.claim(), Out::ok(()), "and the bands went with a: b starts clean");
    assert_eq!(db.surface(STRIDE, FORMAT_XRGB8888), Out::ok(1), "slot 1 is free again");
    assert_eq!(db.present(Present::new(1, &[Rect::new(0, 0, 1, 1)]).unwrap()).code, outcome::NOT_READY, "with no bands");
}

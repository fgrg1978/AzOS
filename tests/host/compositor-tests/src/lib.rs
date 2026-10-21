// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host-side tests for the compositor: the protocol (`userspace/lib/compositor`)
//! and the server's decisions (`userspace/services/compositor/src`, pulled in
//! with `#[path]` so the code under test is the code `COMPSRV.ELF` is built
//! from).
//!
//! The Compositor object is driven through the generated client stub over a
//! loopback, so the wire form a client sends and receives is the one under
//! test: the call right of a reply (`Lent<WindowRight>`) is read off the
//! descriptor. The pixels are real memory: a client window is page-aligned
//! storage the fake host maps, the damage ring in its first page is the real
//! `WindowRing`, and the frames are composed by the real `azos_compose` into a
//! plain image. What the kernel does (a revoked right fails the holder's next
//! call, a `Display::present` copies the bands) is tested where the kernel
//! tables are.

#[allow(dead_code)]
#[path = "../../../../crates/drivers/fb/src/font.rs"]
pub mod font;
#[path = "../../../../userspace/services/compositor/src/bands.rs"]
pub mod bands;
#[path = "../../../../userspace/services/compositor/src/panel.rs"]
pub mod panel;
#[path = "../../../../userspace/services/compositor/src/trust.rs"]
pub mod trust;
#[path = "../../../../userspace/services/compositor/src/windows.rs"]
pub mod windows;

#[cfg(test)]
mod protocol {
    use azos_compositor::*;
    use azos_devif::display::Rect;
    use azos_devif::outcome;
    use azos_idl::{OnFailure, Reader, Wire, Writer};

    /// A page-aligned, zeroed run of `pages` pages (what a mapping is).
    #[repr(C, align(4096))]
    #[derive(Clone)]
    pub struct Page(pub [u8; 4096]);

    pub fn region(pages: usize) -> Vec<Page> {
        vec![Page([0; 4096]); pages]
    }

    /// **A window's badge names the window and nothing else is a window's.** The
    /// top bit marks a right the compositor derived; a row's own badge (small),
    /// the plain call right (none) and the trusted badge of the input server are
    /// no window's.
    ///
    /// **Canary.** Drop the `WINDOW_BADGE` bit from `window_badge`: the first
    /// assertion goes red.
    #[test]
    fn a_window_badge_names_the_window() {
        assert_eq!(window_of(window_badge(7)), Some(7));
        assert_eq!(window_of(window_badge(0x4000_0000)), Some(0x4000_0000));
        assert_eq!(window_of(0), None);
        assert_eq!(window_of(3), None);
        assert_eq!(window_of(azos_devif::input::TRUSTED_BADGE), None);
    }

    /// **A shape crosses as two words, a negative position included.**
    #[test]
    fn a_shape_round_trips_on_the_wire() {
        for s in [
            Shape { x: 10, y: 20, width: 120, height: 80 },
            Shape { x: -5, y: -7, width: 1, height: 4096 },
            Shape { x: i32::MIN, y: i32::MAX, width: 4096, height: 1 },
        ] {
            let mut msg = azos_idl::MsgDesc::default();
            s.put(&mut Writer::new(&mut msg));
            msg.n_words = <Shape as Wire>::WORDS as u8;
            assert_eq!(Shape::get(&mut Reader::new(&msg)), s);
        }
        assert_eq!(<Shape as Wire>::WORDS, 2);
    }

    /// **A window must fit its object.** 4 KiB pages: the control page plus the
    /// pixels (`width * height * 4`) in at most 64 pages, an object no smaller
    /// than that, no empty or huge side.
    ///
    /// **Canaries.** Forget the control page in `pages`: the 252-row window is
    /// accepted and the boundary assertion goes red. Drop the `pages <` test:
    /// the too-small object is accepted.
    #[test]
    fn a_shape_must_fit_its_object() {
        let page = 4096;
        let s = |w, h| Shape { x: 0, y: 0, width: w, height: h };
        // 64 pages = 1 control + 63 of pixels = 258,048 bytes = 64,512 pixels.
        assert_eq!(s(256, 252).pages(page), 64);
        assert_eq!(s(256, 253).pages(page), 65);
        assert_eq!(s(256, 252).check(64, page), Ok(()));
        assert_eq!(s(256, 253).check(64, page), Err(outcome::BAD_ARGUMENT), "one row too many");
        assert_eq!(s(256, 252).check(63, page), Err(outcome::BAD_ARGUMENT), "an object one page short");
        assert_eq!(s(256, 252).check(65, page), Err(outcome::BAD_ARGUMENT), "no object has more than 64 pages");
        assert_eq!(s(0, 10).check(64, page), Err(outcome::BAD_ARGUMENT));
        assert_eq!(s(10, 0).check(64, page), Err(outcome::BAD_ARGUMENT));
        assert_eq!(s(SIDE_MAX + 1, 1).check(64, page), Err(outcome::BAD_ARGUMENT));
        assert_eq!(s(1, 1).check(2, page), Ok(()));
        // A 16 KiB granule: the control area is a quarter of a page.
        assert_eq!(s(64, 64).pages(16384), 2);
    }

    /// **The damage ring carries what the client posts, in order, and a full
    /// ring says "everything changed".** The ring is the real one, in a real
    /// page; a client that posts more than it holds sets the overflow word, which
    /// the compositor reads as a change of the count.
    ///
    /// **Canary.** Do not count the overflow in `post`: the last assertion goes
    /// red.
    #[test]
    fn the_damage_ring_carries_rectangles_and_counts_overflow() {
        let mem = region(1);
        let ring = WindowRing { base: mem.as_ptr() as usize };
        ring.init();
        assert_eq!(ring.take(), None);
        let r = |i: u16| Rect::new(i, i + 1, 10, 20);
        for i in 0..3 {
            assert!(ring.post(r(i)));
        }
        assert_eq!(ring.take(), Some(r(0)));
        assert_eq!(ring.take(), Some(r(1)));
        assert_eq!(ring.take(), Some(r(2)));
        assert_eq!(ring.take(), None);
        assert_eq!(ring.overflowed(), 0);
        for i in 0..DAMAGE_SLOTS as u16 {
            assert!(ring.post(r(i)));
        }
        assert!(!ring.post(r(99)), "a full ring loses the rectangle");
        assert_eq!(ring.overflowed(), 1);
        assert_eq!(ring.take(), Some(r(0)), "what was posted before is kept");
    }

    /// **A failing server restarts; reading its counters does not.** The failure
    /// contract the component manager acts on is the strongest of the ops'.
    #[test]
    fn the_interface_declares_its_failure_contract() {
        let strongest = CompositorIdl::OPS.iter().filter_map(|o| o.on_failure).max_by_key(|f| match f {
            OnFailure::Degrade => 1,
            OnFailure::Restart => 2,
            OnFailure::SafeState => 3,
            OnFailure::Escalate => 4,
        });
        assert_eq!(strongest, Some(OnFailure::Restart));
        assert_eq!(CompositorIdl::OPS.len(), 3);
    }
}

#[cfg(test)]
mod server {
    use crate::protocol::{region, Page};
    use crate::windows::*;
    use azos_abi::cap::CapPerms;
    use azos_compose::{Format, ImageMut, Sink, Source, Sources};
    use azos_compositor::*;
    use azos_devif::display::Rect;
    use azos_devif::outcome;
    use azos_idl::{IdlError, Lent, MsgDesc, Transport, CAP_MODE_DUP};
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::rc::Rc;

    const PAGE: usize = 4096;

    #[derive(Default)]
    struct World {
        /// The client's objects by the handle they arrive as.
        objects: HashMap<u32, Vec<Page>>,
        mapped: Vec<u32>,
        unmapped: Vec<u32>,
        closed: Vec<u32>,
        /// (handle, badge) of every right derived; the handles revoked.
        rights: Vec<(u32, u32)>,
        revoked: Vec<u32>,
        no_right: bool,
        console: Vec<u8>,
    }

    #[derive(Clone, Default)]
    struct Fake(Rc<RefCell<World>>);

    const RIGHT0: u32 = 700;

    impl Host for Fake {
        fn page_bytes(&self) -> usize {
            PAGE
        }
        fn map_window(&mut self, cap: u32) -> Option<Mapped> {
            let mut w = self.0.borrow_mut();
            let Some(o) = w.objects.get(&cap) else {
                w.closed.push(cap);
                return None;
            };
            let m = Mapped { cap, base: o.as_ptr() as usize, pages: o.len() as u64 };
            w.mapped.push(cap);
            Some(m)
        }
        fn unmap_window(&mut self, m: &Mapped) {
            self.0.borrow_mut().unmapped.push(m.cap);
        }
        fn close(&mut self, cap: u32) {
            self.0.borrow_mut().closed.push(cap);
        }
        fn pixels(&self, m: &Mapped, bytes: usize) -> &[u8] {
            // SAFETY: the object lives in the world until the test ends and the
            // mapping is its storage; the client writes while it is read, as in
            // the server.
            unsafe { std::slice::from_raw_parts(m.base as *const u8, bytes.min(m.pages as usize * PAGE)) }
        }
        fn derive_right(&mut self, badge: u32) -> Option<u32> {
            let mut w = self.0.borrow_mut();
            if w.no_right {
                return None;
            }
            let h = RIGHT0 + w.rights.len() as u32;
            w.rights.push((h, badge));
            Some(h)
        }
        fn revoke(&mut self, right: u32) {
            self.0.borrow_mut().revoked.push(right);
        }
        fn log(&mut self, line: &[u8]) {
            self.0.borrow_mut().console.extend_from_slice(line);
        }
    }

    impl Fake {
        /// A client makes an object of `pages` pages; the handle it arrives as.
        fn object(&self, handle: u32, pages: usize) -> usize {
            let mem = region(pages);
            let base = mem.as_ptr() as usize;
            self.0.borrow_mut().objects.insert(handle, mem);
            base
        }
        fn console(&self) -> String {
            String::from_utf8(self.0.borrow().console.clone()).unwrap()
        }
    }

    struct Loop {
        svc: RefCell<Service<Fake>>,
        /// The badge of the capability the next call goes through.
        badge: RefCell<u32>,
        /// The last request, as the client sent it.
        req: RefCell<MsgDesc>,
        last: RefCell<MsgDesc>,
    }

    impl Transport for &Loop {
        fn call(&self, msg: &mut MsgDesc) -> Result<(), IdlError> {
            let mut svc = self.svc.borrow_mut();
            svc.caller = *self.badge.borrow();
            *self.req.borrow_mut() = *msg;
            let mut rep = MsgDesc::default();
            CompositorIdl::dispatch(&mut *svc, msg, &mut rep)?;
            *self.last.borrow_mut() = rep;
            *msg = rep;
            Ok(())
        }
    }

    fn lp(w: &Fake, output: Option<(u32, u32)>) -> Loop {
        let mut svc = Service::new(w.clone());
        if let Some((ow, oh)) = output {
            assert!(svc.set_output(ow, oh));
        }
        Loop { svc: RefCell::new(svc), badge: RefCell::new(0), req: RefCell::new(MsgDesc::default()), last: RefCell::new(MsgDesc::default()) }
    }

    fn shape(x: i32, y: i32, width: u32, height: u32) -> Shape {
        Shape { x, y, width, height }
    }

    /// Attach a window of `s` whose object arrived as `handle`; (the answer, the
    /// client's pointer to its object).
    fn attach(l: &Loop, w: &Fake, handle: u32, s: Shape) -> (azos_devif::Out<Attached>, usize) {
        let pages = s.pages(PAGE) as usize;
        let base = w.object(handle, pages);
        let r = CompositorClient::new(l).attach(Lent::dup(handle, BUFFER), s).unwrap();
        (r, base)
    }

    /// Fill the window's pixels at `base` with `rgb`.
    fn paint(base: usize, s: Shape, rgb: u32) {
        let px = (base + CONTROL_BYTES) as *mut u32;
        for i in 0..(s.width * s.height) as usize {
            // SAFETY: the object holds `pages(s)` pages: control, then the pixels.
            unsafe { px.add(i).write(rgb) };
        }
    }

    /// Nothing for the overlays to show.
    struct NoOverlays;
    impl Sources for NoOverlays {
        fn source(&self, _: u32) -> Option<&dyn Source> {
            None
        }
    }

    /// One solid-colour image: the banner stand-in.
    struct Solid {
        w: u32,
        h: u32,
        px: Vec<u8>,
    }
    impl Solid {
        fn new(w: u32, h: u32, rgb: u32) -> Solid {
            let mut px = vec![0u8; (w * h * 4) as usize];
            for p in px.chunks_mut(4) {
                p.copy_from_slice(&[rgb as u8, (rgb >> 8) as u8, (rgb >> 16) as u8, 0]);
            }
            Solid { w, h, px }
        }
    }
    impl Source for Solid {
        fn width(&self) -> u32 {
            self.w
        }
        fn height(&self) -> u32 {
            self.h
        }
        fn format(&self) -> Format {
            Format::Xrgb8888
        }
        fn row(&self, y: u32) -> Option<&[u8]> {
            self.px.get((y * self.w * 4) as usize..((y + 1) * self.w * 4) as usize)
        }
    }
    struct Overlay(Solid);
    impl Sources for Overlay {
        fn source(&self, id: u32) -> Option<&dyn Source> {
            (id == BANNER_LAYER).then_some(&self.0 as &dyn Source)
        }
    }

    /// The screen: a plain image.
    struct Screen {
        w: u32,
        h: u32,
        px: Vec<u8>,
    }
    impl Screen {
        fn new(w: u32, h: u32) -> Screen {
            Screen { w, h, px: vec![0; (w * h * 4) as usize] }
        }
        fn at(&self, x: u32, y: u32) -> u32 {
            let i = ((y * self.w + x) * 4) as usize;
            u32::from_le_bytes([self.px[i], self.px[i + 1], self.px[i + 2], 0])
        }
        fn sink(&mut self) -> ImageMut<'_> {
            ImageMut::new(&mut self.px, self.w, self.h, (self.w * 4) as usize, Format::Xrgb8888).unwrap()
        }
    }

    const RED: u32 = 0x00FF_0000;
    const GREEN: u32 = 0x0000_FF00;
    const BLUE: u32 = 0x0000_00FF;
    /// The rights a client lends its window's object with (the toolbox's).
    const BUFFER: u16 = CapPerms::READ.union(CapPerms::WRITE).union(CapPerms::MAP).bits() as u16;

    /// **An attach lends a call right bound to the window, with exactly its
    /// rights.** The reply has one DUP entry: the call right and nothing else
    /// (not `DUP`: the holder cannot hand its window's right on), derived with the
    /// window's badge; the window's object was mapped. The object came as a copy
    /// (mode DUP), not moved: a holder whose capability moves loses its mapping,
    /// and the client goes on drawing in it.
    ///
    /// **Canaries.** Lend the right with `WINDOW_RIGHTS | DUP`: the rights assertion
    /// goes red. Derive it with a badge that carries no window: `window_of` goes red.
    /// Make `attach` take a `Cap<WindowBuffer>` (moved): the request's mode goes red.
    #[test]
    fn an_attach_lends_the_window_its_own_call_right() {
        let w = Fake::default();
        let l = lp(&w, Some((64, 48)));
        let s = shape(10, 20, 32, 16);
        let (r, _) = attach(&l, &w, 40, s);
        assert!(r.is_ok());
        let id = r.value.window;
        assert_ne!(id, 0);
        assert!(r.value.right.get().is_some());
        let req = *l.req.borrow();
        assert_eq!(req.n_caps, 1);
        assert_eq!((req.caps[0].handle, req.caps[0].mode, req.caps[0].rights), (40, CAP_MODE_DUP, BUFFER));
        let rep = *l.last.borrow();
        assert_eq!(rep.n_caps, 1);
        let right = rep.caps[0];
        assert_eq!((right.handle, right.mode), (RIGHT0, CAP_MODE_DUP));
        assert_eq!(right.rights, CapPerms::WRITE.bits() as u16, "the call right and nothing else");
        assert_eq!(WINDOW_RIGHTS, CapPerms::WRITE);
        assert_eq!(w.0.borrow().rights, [(RIGHT0, window_badge(id))]);
        assert_eq!(window_of(window_badge(id)), Some(id));
        assert_eq!(w.0.borrow().mapped, [40]);
        assert_eq!(l.svc.borrow().windows(), 1);
        assert!(w.console().contains(&format!("window {id} attached 32x16")), "{}", w.console());
        let st = CompositorClient::new(&l).status().unwrap().value;
        assert_eq!(st.windows, 1);
    }

    /// **Every refusal gives back what the attach took.** No display, a shape the
    /// object cannot hold, a handle that is no object, a full table, a right that
    /// cannot be derived: each leaves no window, no mapping and no handle behind
    /// (a refused handle was moved to the compositor, which must close it).
    ///
    /// **Canaries.** Skip the `unmap_window` after a failed `shape.check`: the
    /// leak assertion goes red. Skip the `remove` of the layer when the right
    /// cannot be derived: three failures fill the scene's spare layers and the
    /// windows of the last block are refused.
    #[test]
    fn every_refused_attach_gives_back_what_it_took() {
        let w = Fake::default();
        // No display yet.
        let l = lp(&w, None);
        let (r, _) = attach(&l, &w, 40, shape(0, 0, 8, 8));
        assert_eq!(r.code, outcome::NOT_READY);
        assert_eq!(w.0.borrow().closed, [40], "the moved handle is closed, never mapped");
        assert!(w.0.borrow().mapped.is_empty());

        let w = Fake::default();
        let l = lp(&w, Some((64, 48)));
        // A shape the object does not hold: the object has 2 pages, the shape needs more.
        let base = w.object(41, 2);
        let r = CompositorClient::new(&l).attach(Lent::dup(41, BUFFER), shape(0, 0, 64, 64)).unwrap();
        assert_eq!(r.code, outcome::BAD_ARGUMENT);
        let _ = base;
        assert_eq!(w.0.borrow().mapped, [41]);
        assert_eq!(w.0.borrow().unmapped, [41], "mapped, found wanting, unmapped");
        // A handle that is no object.
        let r = CompositorClient::new(&l).attach(Lent::dup(99, BUFFER), shape(0, 0, 8, 8)).unwrap();
        assert_eq!(r.code, outcome::BAD_ARGUMENT);
        assert!(w.0.borrow().closed.contains(&99));
        // A right that cannot be made.
        w.0.borrow_mut().no_right = true;
        for h in 42..45 {
            let (r, _) = attach(&l, &w, h, shape(0, 0, 8, 8));
            assert_eq!(r.code, outcome::BUSY);
        }
        assert_eq!(w.0.borrow().unmapped, [41, 42, 43, 44]);
        assert_eq!(l.svc.borrow().windows(), 0);
        w.0.borrow_mut().no_right = false;
        // The scene has all its layers still: WINDOWS windows fit, one more is BUSY.
        for i in 0..WINDOWS as u32 {
            let (r, _) = attach(&l, &w, 100 + i, shape(i as i32, 0, 4, 4));
            assert!(r.is_ok(), "window {i}");
        }
        let (r, _) = attach(&l, &w, 200, shape(0, 0, 4, 4));
        assert_eq!(r.code, outcome::BUSY, "a ninth window");
        assert!(w.0.borrow().closed.contains(&200), "its handle is closed");
        assert_eq!(l.svc.borrow().windows(), WINDOWS as u32);
    }

    /// **A window is taken down only through its own right.** The plain call right
    /// (badge 0), a row's badge and another window's right are `DENIED` and leave
    /// the window up; its own right takes it down: the layer goes, the right is
    /// revoked, the object is let go; the same right again is `DENIED` (the window
    /// is gone).
    ///
    /// **Canaries.** Take `detach` through any badged caller: the other window's
    /// right takes this one down and the first block goes red. Skip `revoke`: the
    /// revoked list is empty and the second block goes red.
    #[test]
    fn a_window_is_taken_down_only_through_its_own_right() {
        let w = Fake::default();
        let l = lp(&w, Some((64, 48)));
        let (a, _) = attach(&l, &w, 40, shape(0, 0, 8, 8));
        let (b, _) = attach(&l, &w, 41, shape(8, 0, 8, 8));
        let (ida, idb) = (a.value.window, b.value.window);
        let mut c = CompositorClient::new(&l);
        for badge in [0, 3, window_badge(idb ^ 0x100), window_badge(idb)] {
            if badge == window_badge(idb) {
                continue;
            }
            *l.badge.borrow_mut() = badge;
            assert_eq!(c.detach().unwrap().code, outcome::DENIED, "badge {badge:#x}");
        }
        assert_eq!(l.svc.borrow().windows(), 2);
        // `b`'s right does not take `a` down: it takes `b` down.
        *l.badge.borrow_mut() = window_badge(idb);
        assert!(c.detach().unwrap().is_ok());
        assert_eq!(l.svc.borrow().windows(), 1);
        assert_eq!(w.0.borrow().revoked, [RIGHT0 + 1], "b's right, not a's");
        assert_eq!(w.0.borrow().unmapped, [41]);
        assert!(w.console().contains(&format!("window {idb} detached")));
        // The same right again: the window is gone.
        assert_eq!(c.detach().unwrap().code, outcome::DENIED);
        *l.badge.borrow_mut() = window_badge(ida);
        assert!(c.detach().unwrap().is_ok());
        assert_eq!(l.svc.borrow().windows(), 0);
        assert_eq!(w.0.borrow().revoked, [RIGHT0 + 1, RIGHT0]);
    }

    /// **The first frame paints the whole screen; a client's damage repaints only
    /// that.** The window's pixels are composed in place at its position over the
    /// background; after the client changes a corner and posts that rectangle, the
    /// next frame's damage is that rectangle in screen coordinates and nothing
    /// else changes on the screen.
    ///
    /// **Canaries.** Ignore the ring in `drain`: the second frame's damage is
    /// empty and the rectangle assertion goes red. Damage in screen pixels instead
    /// of window pixels (skip the layer origin): the rectangle is at (1,1).
    #[test]
    fn a_clients_damage_repaints_only_that_rectangle() {
        let w = Fake::default();
        let l = lp(&w, Some((16, 12)));
        let s = shape(2, 3, 4, 4);
        let (r, base) = attach(&l, &w, 40, s);
        assert!(r.is_ok());
        paint(base, s, RED);
        let mut screen = Screen::new(16, 12);
        let f = l.svc.borrow_mut().frame(&NoOverlays, &mut screen.sink()).unwrap();
        assert_eq!(f.missing, 0);
        assert_eq!(screen.at(0, 0), BACKGROUND);
        assert_eq!(screen.at(2, 3), RED);
        assert_eq!(screen.at(5, 6), RED);
        assert_eq!(screen.at(6, 3), BACKGROUND);
        assert_eq!(screen.at(2, 7), BACKGROUND);
        // Nothing posted, nothing damaged.
        l.svc.borrow_mut().drain();
        assert!(!l.svc.borrow().has_damage());
        // The client changes its bottom right 2x2 and says so.
        let px = (base + CONTROL_BYTES) as *mut u32;
        for (x, y) in [(2, 2), (3, 2), (2, 3), (3, 3)] {
            unsafe { px.add(y * 4 + x).write(GREEN) };
        }
        let ring = WindowRing { base };
        assert!(ring.post(Rect::new(2, 2, 2, 2)));
        l.svc.borrow_mut().drain();
        assert!(l.svc.borrow().has_damage());
        let f = l.svc.borrow_mut().frame(&NoOverlays, &mut screen.sink()).unwrap();
        assert_eq!(f.damage.rects(), [Rect::new(4, 5, 2, 2)], "window pixels (2,2) are screen pixels (4,5)");
        assert_eq!(screen.at(4, 5), GREEN);
        assert_eq!(screen.at(5, 6), GREEN);
        assert_eq!(screen.at(3, 4), RED, "the rest of the window is untouched");
    }

    /// **A ring that overflowed repaints the whole window.** The client posted
    /// more than the ring holds; the lost rectangles are unknown, so the whole
    /// window is damaged (once: the next look finds the count unchanged).
    ///
    /// **Canary.** Skip the overflow check in `drain`: the rectangle is the part
    /// the ring still held and the assertion goes red.
    #[test]
    fn an_overflowed_ring_repaints_the_whole_window() {
        let w = Fake::default();
        let l = lp(&w, Some((16, 12)));
        let s = shape(2, 3, 4, 4);
        let (_, base) = attach(&l, &w, 40, s);
        let mut screen = Screen::new(16, 12);
        let _ = l.svc.borrow_mut().frame(&NoOverlays, &mut screen.sink()).unwrap();
        let ring = WindowRing { base };
        for _ in 0..DAMAGE_SLOTS {
            assert!(ring.post(Rect::new(0, 0, 1, 1)));
        }
        assert!(!ring.post(Rect::new(3, 3, 1, 1)));
        l.svc.borrow_mut().drain();
        let f = l.svc.borrow_mut().frame(&NoOverlays, &mut screen.sink()).unwrap();
        assert_eq!(f.damage.rects(), [Rect::new(2, 3, 4, 4)], "the whole window");
        l.svc.borrow_mut().drain();
        assert!(!l.svc.borrow().has_damage(), "once");
    }

    /// **The trusted overlays stay above every window, whichever came last.** The
    /// banner is shown, then a window that covers it attaches: the banner's pixels
    /// are still the ones on the screen where they overlap.
    ///
    /// **Canary.** Remove the two `raise` calls of `attach`: the window covers the
    /// banner and the pixel assertion goes red.
    #[test]
    fn the_banner_stays_above_a_window_that_attaches_after_it() {
        let w = Fake::default();
        let l = lp(&w, Some((16, 12)));
        l.svc.borrow_mut().show_overlay(BANNER_LAYER, 0, 0, 8, 4);
        let s = shape(0, 0, 16, 12);
        let (r, base) = attach(&l, &w, 40, s);
        assert!(r.is_ok());
        paint(base, s, RED);
        let mut screen = Screen::new(16, 12);
        let ov = Overlay(Solid::new(8, 4, BLUE));
        let f = l.svc.borrow_mut().frame(&ov, &mut screen.sink()).unwrap();
        assert_eq!(f.missing, 0);
        assert_eq!(screen.at(0, 0), BLUE, "the banner, over a window drawn later");
        assert_eq!(screen.at(7, 3), BLUE);
        assert_eq!(screen.at(8, 0), RED, "the window outside it");
        // Taken down, it leaves the window.
        l.svc.borrow_mut().hide_overlay(BANNER_LAYER);
        let _ = l.svc.borrow_mut().frame(&ov, &mut screen.sink()).unwrap();
        assert_eq!(screen.at(0, 0), RED);
    }

    /// **A window half off the screen is clipped, and a rectangle past its buffer
    /// is the client's bug, not damage.** The compositor draws the part inside the
    /// output and ignores a rectangle that names nothing of the buffer.
    #[test]
    fn a_window_partly_off_the_screen_is_clipped_and_a_wild_rectangle_is_ignored() {
        let w = Fake::default();
        let l = lp(&w, Some((16, 12)));
        let s = shape(-2, -1, 4, 4);
        let (_, base) = attach(&l, &w, 40, s);
        paint(base, s, GREEN);
        let mut screen = Screen::new(16, 12);
        let f = l.svc.borrow_mut().frame(&NoOverlays, &mut screen.sink()).unwrap();
        assert_eq!(f.missing, 0);
        assert_eq!(screen.at(0, 0), GREEN);
        assert_eq!(screen.at(1, 2), GREEN);
        assert_eq!(screen.at(2, 0), BACKGROUND);
        assert_eq!(screen.at(0, 3), BACKGROUND);
        let ring = WindowRing { base };
        assert!(ring.post(Rect::new(100, 100, 5, 5)));
        l.svc.borrow_mut().drain();
        assert!(!l.svc.borrow().has_damage());
    }

    /// **Without a display nothing is composed.**
    #[test]
    fn without_a_display_there_is_no_frame() {
        let w = Fake::default();
        let l = lp(&w, None);
        let mut screen = Screen::new(4, 4);
        assert!(l.svc.borrow_mut().frame(&NoOverlays, &mut screen.sink()).is_none());
        assert_eq!(l.svc.borrow().output(), None);
    }

    /// The `Sink` of a screen is a plain image here; keep the trait in use so a
    /// change of its shape breaks this file, not just the server.
    #[test]
    fn the_screen_stand_in_is_a_sink_of_the_composed_format() {
        let mut screen = Screen::new(4, 4);
        let sink = screen.sink();
        assert_eq!(Sink::format(&sink), Format::Xrgb8888);
    }
}

#[cfg(test)]
mod trusted_path {
    use crate::trust::Trust;

    const MS: u64 = 1_000_000;

    /// **A chord puts the banner up at once and opens the gate `banner_ms` later,
    /// once.** No chord, no banner; the count the compositor started with is not a
    /// chord; the hand-on is due at exactly the deadline; after it the path is
    /// idle until the next chord.
    ///
    /// **Canaries.** Treat the starting count as a chord: the first assertion goes
    /// red. Make `due` early by one millisecond: the boundary assertion goes red.
    #[test]
    fn a_chord_raises_the_banner_and_the_gate_opens_after_the_interval() {
        let mut t = Trust::new(5, 1500);
        assert!(!t.observe(5, 0), "the count at start is history");
        assert!(!t.active() && !t.due(10_000 * MS));
        assert!(t.observe(6, 100 * MS));
        assert!(t.active());
        assert_eq!(t.chords(), 6);
        assert!(!t.observe(6, 200 * MS), "the same count is not another chord");
        assert!(!t.due(1599 * MS));
        assert!(t.due(1600 * MS));
        assert!(t.due(5000 * MS), "still due until it is done");
        t.handed_on();
        assert!(!t.active() && !t.due(5000 * MS));
        assert!(!t.observe(6, 6000 * MS));
    }

    /// **A second chord inside the interval extends it**, and a count that wrapped
    /// is a chord like any other (the page's count wraps).
    #[test]
    fn a_second_chord_extends_the_interval() {
        let mut t = Trust::new(u32::MAX, 1000);
        assert!(t.observe(0, 0), "wrapped");
        assert!(t.observe(1, 700 * MS));
        assert!(!t.due(1000 * MS), "the first deadline passed, the second has not");
        assert!(!t.due(1699 * MS));
        assert!(t.due(1700 * MS));
    }
}

#[cfg(test)]
mod surface {
    use crate::bands::*;
    use azos_compose::{Format, Sink};

    /// **The cut of a screen into bands.** 640x480 XRGB8888 on 4 KiB pages and
    /// 64-page objects: 102 rows a band (262,144 / 2,560), five bands, each as
    /// many pages as its rows need. 1280x800: 51 rows, 16 bands. A screen that
    /// needs more than the bands kept, or a row longer than an object, is not
    /// cut.
    ///
    /// **Canary.** Round the rows up instead of down: the first band would
    /// hold more than its object, and the exact-rows assertion goes red.
    #[test]
    fn a_screen_is_cut_into_bands_of_whole_rows() {
        let p = plan(480, 640 * 4, 4096, 64).unwrap();
        assert_eq!((p.rows, p.count, p.pages), (102, 5, 64));
        let p = plan(800, 1280 * 4, 4096, 64).unwrap();
        assert_eq!((p.rows, p.count), (51, 16));
        assert_eq!(p.pages, 64);
        // A small screen is one band of exactly its pages.
        let p = plan(10, 64 * 4, 4096, 64).unwrap();
        assert_eq!((p.rows, p.count, p.pages), (10, 1, 1));
        assert_eq!(plan(1080, 1920 * 4, 4096, 64).map(|p| p.count), Some(32), "full HD fills the bands kept");
        assert_eq!(plan(1440, 2560 * 4, 4096, 64), None, "more bands than are kept");
        assert_eq!(plan(10, 300_000, 4096, 64), None, "a row longer than an object");
        assert_eq!(plan(0, 100, 4096, 64), None);
        // The rows a band holds are what the kernel will take from it.
        let p = plan(480, 640 * 4, 4096, 64).unwrap();
        assert!(p.pages * 4096 / (640 * 4) >= p.rows as u64);
        assert!(p.pages * 4096 / (640 * 4) <= p.rows as u64, "no band holds a row more than the plan says");
    }

    /// **A row of the sink is the right row of the right band.** Each band is a
    /// separate allocation; the row `y` lands in band `y / rows` at row `y % rows`,
    /// the last row of one band and the first of the next are not confused, and a
    /// row past the screen is `None`.
    ///
    /// **Canary.** Index the band by `(y + 1) / rows`: the boundary assertions go
    /// red.
    #[test]
    fn the_sink_writes_each_row_to_its_band() {
        let p = Plan { pages: 1, rows: 4, count: 3 };
        let stride = 16u32;
        let mem: Vec<Vec<u8>> = (0..3).map(|_| vec![0u8; 4096]).collect();
        let mut bases = [0usize; BANDS_MAX];
        for (i, m) in mem.iter().enumerate() {
            bases[i] = m.as_ptr() as usize;
        }
        let mut sink = Bands::new(bases, p, stride, 10, Format::Xrgb8888);
        for y in 0..10u32 {
            sink.row_mut(y).unwrap().fill(y as u8 + 1);
        }
        assert!(sink.row_mut(10).is_none());
        for y in 0..10usize {
            let (band, row) = (y / 4, y % 4);
            let got = &mem[band][row * 16..row * 16 + 16];
            assert!(got.iter().all(|&b| b == y as u8 + 1), "row {y}: {got:?}");
        }
        assert_eq!(mem[2][2 * 16], 0, "rows 10 and 11 of the last band were never written");
        assert_eq!(sink.row_mut(3).unwrap().len(), 16);
        // A band that is not attached has no rows: the frame counts them missing.
        let mut bases2 = bases;
        bases2[1] = 0;
        let mut sink = Bands::new(bases2, p, stride, 10, Format::Xrgb8888);
        assert!(sink.row_mut(3).is_some());
        assert!(sink.row_mut(4).is_none());
    }
}

#[cfg(test)]
mod panels {
    use crate::panel::*;
    use azos_decisions::ProvenanceRecord;

    fn pixel(px: &[u8], x: usize, y: usize) -> [u8; 4] {
        let at = (y * PANEL_W + x) * 4;
        [px[at], px[at + 1], px[at + 2], px[at + 3]]
    }

    /// **The banner is drawn: an amber frame, the text in it, and the chord
    /// count in the words.** Two banners for different counts differ; the frame
    /// is amber at every corner, the inside is the banner's blue where no text is.
    ///
    /// **Canary.** Skip the `frame` call: the corner assertion goes red. Draw the
    /// count as a constant: the two banners are equal and the last assertion goes
    /// red.
    #[test]
    fn the_banner_has_a_frame_text_and_the_count() {
        let mut a = vec![0u8; BANNER_BYTES];
        render_banner(&mut a, 1, 1500);
        let amber = [0x3C, 0xC8, 0xFF, 0];
        assert_eq!(pixel(&a, 0, 0), amber);
        assert_eq!(pixel(&a, PANEL_W - 1, BANNER_H - 1), amber);
        assert_eq!(pixel(&a, PANEL_W - 1, 0), amber);
        // Inside the frame, away from the text: the blue.
        assert_eq!(pixel(&a, PANEL_W - 4, BANNER_H - 4), [0x5C, 0x2C, 0x10, 0]);
        // The text is there: some pixel inside the first row is the title colour.
        assert!((8..PANEL_W - 8).any(|x| (8..24).any(|y| pixel(&a, x, y) == amber)));
        let mut b = vec![0u8; BANNER_BYTES];
        render_banner(&mut b, 2, 1500);
        assert_ne!(a, b);
    }

    /// **A decision is two rows: who decided what about whom, and what the rule
    /// rejected.** Rule 0 (deadline admission) refusing subject 7 as decision 42;
    /// the rows are cut at the panel's width; the panel holds
    /// [`WHY_DECISIONS`] decisions and says it is full for the next.
    ///
    /// **Canaries.** Let a row grow past `WHY_COLS`: the length assertion goes red.
    /// Accept a fourth decision: the `false` goes red.
    #[test]
    fn a_decision_is_two_rows_and_the_panel_holds_three() {
        let rec = ProvenanceRecord { rule: 0, verdict: 1, subject: 7, seq: 42, ..ProvenanceRecord::default() };
        let mut why = Why::new();
        assert!(why.decision(&rec));
        let rows = why.rows();
        assert_eq!(rows.len(), 2);
        assert_eq!(core::str::from_utf8(rows[0].as_bytes()).unwrap(), "#42 deadline-admission refuse cpus=7");
        let second = core::str::from_utf8(rows[1].as_bytes()).unwrap();
        assert!(second.starts_with("  not: run the rows"), "{second}");
        assert!(second.len() <= WHY_COLS, "cut to the panel's width: {}", second.len());
        for _ in 1..WHY_DECISIONS {
            assert!(why.decision(&rec));
        }
        assert!(!why.decision(&rec), "the panel is full");
        assert_eq!(why.rows().len(), WHY_DECISIONS * 2);
        // A rule the table does not have is a row, not a panic.
        let mut why = Why::new();
        assert!(why.decision(&ProvenanceRecord { rule: 250, verdict: 9, seq: 1, ..ProvenanceRecord::default() }));
        assert!(core::str::from_utf8(why.rows()[0].as_bytes()).unwrap().contains("unknown-rule"));
    }

    /// **The refusal panel draws its rows; an empty panel draws only the title.**
    #[test]
    fn the_refusal_panel_draws_its_rows() {
        let mut empty = vec![0u8; WHY_BYTES];
        render_why(&mut empty, &Why::new());
        let mut one = Why::new();
        one.note("no refusal recorded in the last stretch");
        let mut full = vec![0u8; WHY_BYTES];
        render_why(&mut full, &one);
        assert_ne!(empty, full);
        // The first row (y 8..24) is the title in both; the second (24..40) only in one.
        let row = |px: &[u8], y0: usize| (y0..y0 + 16).any(|y| (8..PANEL_W - 8).any(|x| pixel_at(px, x, y) != [0x18, 0x18, 0x18, 0]));
        assert!(row(&empty, 8) && row(&full, 8));
        assert!(!row(&empty, 24));
        assert!(row(&full, 24));
    }

    fn pixel_at(px: &[u8], x: usize, y: usize) -> [u8; 4] {
        let at = (y * PANEL_W + x) * 4;
        [px[at], px[at + 1], px[at + 2], px[at + 3]]
    }
}

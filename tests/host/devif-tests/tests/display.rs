// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The `Display` interface: its registry row and topology spelling, its op
//! table, the wire form of its types, the rules the kernel's server applies
//! before it touches a pixel (surface and damage checks, the claim) and the
//! generated client and dispatcher over a mock. The server behind the row is
//! `crates/core/syscall/src/display.rs`, driven by
//! `tests/host/syscall-tests/src/display_guards.rs`.

use azos_devif::display::{
    self, band_rows, band_take, Claim, ConnectorInfo, Mode, Present, Rect, SurfaceBand, VsyncPort, CONNECTORS,
    CONN_CONNECTED, DAMAGE_MAX, FORMAT_RGB565, FORMAT_RGB888, FORMAT_XBGR8888, FORMAT_XRGB8888,
};
use azos_devif::{
    by_key, by_name, key, outcome, parse_target, Display, DisplayCall, DisplayClient, DisplayIdl, Out, DISPLAY_ID,
};
use azos_idl::{
    Cap, MsgDesc, Reader, Result as IdlResult, Transport, Wire, Writer, OP_AT_MOST_ONCE, OP_IDEMPOTENT,
};
use std::cell::RefCell;

struct Loop<'a> {
    serve: &'a dyn Fn(&MsgDesc, &mut MsgDesc),
}

impl Transport for &Loop<'_> {
    fn call(&self, msg: &mut MsgDesc) -> IdlResult {
        let req = *msg;
        (self.serve)(&req, msg);
        Ok(())
    }
}

/// A 1920x1080 XRGB8888 scanout with a padded stride.
fn full_hd() -> ConnectorInfo {
    ConnectorInfo {
        width: 1920,
        height: 1080,
        stride: 1920 * 4 + 64,
        format: FORMAT_XRGB8888,
        refresh_mhz: 60_000,
        flags: CONN_CONNECTED,
        width_mm: 509,
        height_mm: 286,
        modes: 3,
        surfaces: display::SURFACES as u32,
    }
}

fn words<T: Wire>(v: &T) -> MsgDesc {
    let mut m = MsgDesc::default();
    let mut w = Writer::new(&mut m);
    v.put(&mut w);
    w.finish();
    m
}

fn back<T: Wire>(m: &MsgDesc) -> T {
    T::get(&mut Reader::new(m))
}

/// The row: key 23 after `net`, the id "DISP", a connector index as the
/// resource, badge `n + 1`.
///
/// **Canary.** Move the key, spell the bare name, or lift the bound: red.
#[test]
fn the_display_row_is_registered_after_net_and_names_a_connector() {
    assert_eq!(key::DISPLAY, 23);
    assert_eq!(DISPLAY_ID.to_be_bytes(), *b"DISP");
    let i = by_name("display").expect("no row display");
    assert_eq!((i.key, i.id), (key::DISPLAY, DISPLAY_ID));
    assert_eq!(by_key(key::DISPLAY).map(|x| x.name), Some("display"));
    for n in 0..CONNECTORS {
        assert_eq!(parse_target(&format!("display.{n}")).map(|(i, b)| (i.name, b)), Some(("display", n + 1)));
    }
    assert_eq!(display::connector_badge(0), 1, "badge 0 is the unbadged endpoint: no connector");
    for bad in ["display", "display.4", "display.-1", "display.0.1", "display.x", "display2", "display."] {
        assert!(parse_target(bad).is_none(), "{bad}");
    }
}

/// The op table in the order the trait declares them, with the delivery class
/// each declares: reads, claim, release, present and the vsync attach can be
/// repeated; creating a surface, adding a band and destroying a surface cannot.
/// Present declares the bounds for a frame.
///
/// **Canary.** Swap two methods: the numbers a client was built against move.
#[test]
fn the_op_table_and_what_each_op_may_repeat() {
    let names: Vec<_> = DisplayIdl::OPS.iter().map(|o| o.name).collect();
    assert_eq!(
        names,
        ["connector", "mode", "claim", "release", "surface", "band", "destroy_surface", "present", "vsync"]
    );
    let flags: Vec<_> = DisplayIdl::OPS.iter().map(|o| o.flags).collect();
    assert_eq!(
        flags,
        [
            OP_IDEMPOTENT,
            OP_IDEMPOTENT,
            OP_IDEMPOTENT,
            OP_IDEMPOTENT,
            OP_AT_MOST_ONCE,
            OP_AT_MOST_ONCE,
            OP_AT_MOST_ONCE,
            OP_IDEMPOTENT,
            OP_IDEMPOTENT
        ]
    );
    let present = &DisplayIdl::OPS[7];
    assert_eq!((present.deadline_ns, present.budget_us), (20_000_000, 10_000));
    // A present fills the message exactly: the header, the surface and count
    // word and six rectangles.
    assert_eq!(DisplayIdl::REQ_WORDS_PRESENT, 8);
    assert_eq!(DisplayIdl::REP_WORDS_PRESENT, 1 + 1 + 1, "status, outcome and the frame number");
    assert_eq!(DisplayIdl::REP_WORDS_CONNECTOR, 1 + 1 + 5);
    assert_eq!((DisplayIdl::OPS[5].req_caps, DisplayIdl::OPS[8].req_caps), (1, 1), "the band, the port");
    assert_eq!(DisplayIdl::OPS[0].req_caps + DisplayIdl::OPS[4].req_caps + DisplayIdl::OPS[7].req_caps, 0);
}

/// A rectangle is one word and every field keeps its place, whatever the
/// others hold.
#[test]
fn a_rectangle_is_one_word_with_four_independent_fields() {
    for r in [Rect::new(1, 2, 3, 4), Rect::new(u16::MAX, 0, 0, u16::MAX), Rect::new(0, u16::MAX, u16::MAX, 0), Rect::default()] {
        let m = words(&r);
        assert_eq!(m.n_words, 1);
        assert_eq!(back::<Rect>(&m), r);
    }
    assert_eq!(words(&Rect::new(1, 2, 3, 4)).words[0], 1 | 2 << 16 | 3 << 32 | 4 << 48);
}

/// Distinct values in every field of the multi-field types: none is read
/// from, or written to, another's place.
///
/// **Canary.** Swap `width_mm` and `height_mm` in `get`: the connector's
/// fields differ.
#[test]
fn the_connector_the_mode_and_a_present_round_trip_field_by_field() {
    let c = ConnectorInfo {
        width: 1920,
        height: 1080,
        stride: 7744,
        format: 3,
        refresh_mhz: 59_940,
        flags: 0xF,
        width_mm: 509,
        height_mm: 286,
        modes: 7,
        surfaces: 4,
    };
    let m = words(&c);
    assert_eq!(m.n_words, 5);
    assert_eq!(back::<ConnectorInfo>(&m), c);

    let md = Mode { width: 3840, height: 2160, refresh_mhz: 30_000, flags: 3 };
    let m = words(&md);
    assert_eq!(m.n_words, 2);
    assert_eq!(back::<Mode>(&m), md);

    let rects = [Rect::new(0, 0, 10, 10), Rect::new(10, 20, 30, 40), Rect::new(1, 1, 1, 1)];
    let p = Present::new(3, &rects).unwrap();
    let m = words(&p);
    assert_eq!(m.n_words, 7);
    assert_eq!(m.words[0], 3 | 3 << 32);
    let got: Present = back(&m);
    assert_eq!(got, p);
    assert_eq!(got.damage(), &rects);
}

/// A damage list is 1 to [`DAMAGE_MAX`] rectangles; `damage()` never reads
/// past the array even when `count` lies.
#[test]
fn a_present_holds_one_to_six_rectangles() {
    let r = Rect::new(0, 0, 1, 1);
    assert!(Present::new(1, &[]).is_none());
    assert!(Present::new(1, &[r; DAMAGE_MAX]).is_some());
    assert!(Present::new(1, &[r; DAMAGE_MAX + 1]).is_none());
    let lying = Present { surface: 1, count: u32::MAX, rects: [r; DAMAGE_MAX] };
    assert_eq!(lying.damage().len(), DAMAGE_MAX);
    assert_eq!(lying.check(&full_hd()), Err(outcome::BAD_ARGUMENT));
    assert_eq!(Present { surface: 1, count: 0, rects: [r; DAMAGE_MAX] }.check(&full_hd()), Err(outcome::BAD_ARGUMENT));
}

/// The damage check: every rectangle non-empty and inside the screen, exactly
/// at the edge allowed, one pixel past refused, 16-bit sums that would wrap
/// refused; one bad rectangle refuses the list.
///
/// **Canary.** Compute `x + w` in 16 bits: `(65535, 0, 2, 1)` wraps to 1 and
/// passes.
#[test]
fn damage_must_lie_inside_the_screen() {
    let c = full_hd();
    let ok = |r: Rect| Present::new(1, &[r]).unwrap().check(&c);
    assert_eq!(ok(Rect::full(1920, 1080)), Ok(()));
    assert_eq!(ok(Rect::new(1919, 1079, 1, 1)), Ok(()));
    assert_eq!(ok(Rect::new(1919, 1079, 2, 1)), Err(outcome::BAD_ARGUMENT));
    assert_eq!(ok(Rect::new(1919, 1079, 1, 2)), Err(outcome::BAD_ARGUMENT));
    assert_eq!(ok(Rect::new(1920, 0, 1, 1)), Err(outcome::BAD_ARGUMENT));
    assert_eq!(ok(Rect::new(0, 0, 0, 5)), Err(outcome::BAD_ARGUMENT), "empty");
    assert_eq!(ok(Rect::new(0, 0, 5, 0)), Err(outcome::BAD_ARGUMENT), "empty");
    assert_eq!(ok(Rect::new(u16::MAX, 0, 2, 1)), Err(outcome::BAD_ARGUMENT));
    assert_eq!(ok(Rect::new(0, u16::MAX, 1, u16::MAX)), Err(outcome::BAD_ARGUMENT));
    let mixed = Present::new(1, &[Rect::new(0, 0, 8, 8), Rect::new(1900, 0, 100, 8)]).unwrap();
    assert_eq!(mixed.check(&c), Err(outcome::BAD_ARGUMENT));
    // A screen wider than 16 bits can name: its full rectangle is cut, and
    // the rectangle that would reach past 65535 does not exist.
    assert_eq!(Rect::full(70_000, 5), Rect::new(0, 0, u16::MAX, 5));
}

/// What a surface may be: the scanout's format, rows at least a screen row
/// long, a sane stride; a connector with no display, or a mode with no
/// pixels, has nothing to feed.
///
/// **Canary.** Accept any format: a 565 surface is taken for a 32-bit scanout
/// and `present` copies two bytes where four belong.
#[test]
fn a_surface_must_match_the_scanout() {
    let c = full_hd();
    let row = 1920 * 4;
    assert_eq!(c.check_surface(row, FORMAT_XRGB8888), Ok(()));
    assert_eq!(c.check_surface(row - 1, FORMAT_XRGB8888), Err(outcome::BAD_ARGUMENT), "row too short");
    assert_eq!(c.check_surface(8192, FORMAT_XRGB8888), Ok(()), "a padded row");
    for other in [FORMAT_XBGR8888, FORMAT_RGB888, FORMAT_RGB565, 0, 5, u32::MAX] {
        assert_eq!(c.check_surface(row, other), Err(outcome::BAD_ARGUMENT), "format {other}");
    }
    assert_eq!(c.check_surface(1 << 20, FORMAT_XRGB8888), Ok(()), "1 MiB is the most");
    assert_eq!(c.check_surface((1 << 20) + 4, FORMAT_XRGB8888), Err(outcome::BAD_ARGUMENT));
    assert_eq!(ConnectorInfo::default().check_surface(row, FORMAT_XRGB8888), Err(outcome::NOT_READY));
    let no_height = ConnectorInfo { height: 0, ..c };
    assert_eq!(no_height.check_surface(row, FORMAT_XRGB8888), Err(outcome::NOT_READY));
    let rgb = ConnectorInfo { format: FORMAT_RGB888, ..c };
    assert_eq!(rgb.check_surface(1920 * 3, FORMAT_RGB888), Ok(()));
    assert_eq!(rgb.check_surface(1920 * 3 - 1, FORMAT_RGB888), Err(outcome::BAD_ARGUMENT));
}

/// Bands: an object holds whole rows only (the rest of its last page is
/// unused), the last band takes what is left, a band that holds no row or
/// arrives after the surface is complete is refused. The numbers are the
/// 1920x1080 XRGB8888 surface on a 4 KiB granule, 64 pages (262,144 bytes) a
/// band: 34 rows of 7,680 bytes, so 32 bands, the last of 22 rows.
///
/// **Canary.** Round the rows up instead of down: a band of 34.13 rows
/// "holds" 35 and the 35th row reads past it.
#[test]
fn bands_add_whole_rows_until_the_surface_is_complete() {
    let (stride, band) = (1920 * 4, 64 * 4096u64);
    assert_eq!(band_rows(stride, band), 34);
    assert_eq!(band_rows(stride, stride as u64 - 1), 0);
    assert_eq!(band_rows(0, band), 0, "no stride, no rows");
    let (mut covered, mut bands) = (0u32, 0);
    while covered < 1080 {
        covered += band_take(1080, covered, stride, band).unwrap();
        bands += 1;
    }
    assert_eq!((covered, bands), (1080, 32));
    assert_eq!(band_take(1080, 1058, stride, band), Ok(22), "the last band takes what is left");
    assert_eq!(band_take(1080, 1080, stride, band), Err(outcome::BUSY), "complete");
    assert_eq!(band_take(1080, 0, stride, stride as u64 - 1), Err(outcome::BAD_ARGUMENT), "not one row");
    assert_eq!(band_take(1080, 1079, stride, u64::MAX), Ok(1), "an enormous band still takes one row");
    // A 16 KiB granule: 64 pages are 1 MiB, 136 rows, 8 bands.
    let big = 64 * 16384u64;
    let mut covered = 0;
    let mut bands = 0;
    while covered < 1080 {
        covered += band_take(1080, covered, stride, big).unwrap();
        bands += 1;
    }
    assert_eq!(bands, 8);
}

/// The claim: one holder at a time; the holder's repeat is not news; the
/// drawing ops need the claim and say why they were refused.
///
/// **Canary.** Let `claim` overwrite a holder: the second claimant `Ok`s and
/// the first stops being the holder.
#[test]
fn the_claim_has_one_holder() {
    let mut c = Claim::new();
    assert_eq!(c.holder(), None);
    assert_eq!(c.require(7), Err(outcome::NOT_READY), "claim first");
    assert_eq!(c.release(7), Ok(false), "nothing to give back");
    assert_eq!(c.claim(7), Ok(true));
    assert_eq!(c.claim(7), Ok(false), "again: the same holder");
    assert_eq!(c.claim(8), Err(outcome::BUSY));
    assert_eq!(c.require(7), Ok(()));
    assert_eq!(c.require(8), Err(outcome::BUSY));
    assert_eq!(c.release(8), Err(outcome::BUSY), "only the holder gives it back");
    assert_eq!(c.holder(), Some(7));
    assert_eq!(c.release(7), Ok(true));
    assert_eq!(c.release(7), Ok(false));
    assert_eq!(c.claim(8), Ok(true));
}

/// A server for the client tests: 1920x1080, two modes, and a claim by tid 1.
struct Mock {
    claim: Claim,
    me: u32,
    /// `(stride, format, bands)` per surface.
    surfaces: Vec<(u32, u32, Vec<u32>)>,
    frames: u64,
    vsync: Option<(u32, u64)>,
}

impl Display for Mock {
    fn connector(&self) -> Out<ConnectorInfo> {
        Out::ok(full_hd())
    }
    fn mode(&self, index: u32) -> Out<Mode> {
        match index {
            0 => Out::ok(Mode { width: 1920, height: 1080, refresh_mhz: 60_000, flags: display::MODE_CURRENT | display::MODE_PREFERRED }),
            1 => Out::ok(Mode { width: 1280, height: 720, refresh_mhz: 60_000, flags: 0 }),
            _ => Out::err(outcome::BAD_ARGUMENT),
        }
    }
    fn claim(&mut self) -> Out<()> {
        match self.claim.claim(self.me) {
            Ok(_) => Out::ok(()),
            Err(c) => Out::err(c),
        }
    }
    fn release(&mut self) -> Out<()> {
        match self.claim.release(self.me) {
            Ok(_) => Out::ok(()),
            Err(c) => Out::err(c),
        }
    }
    fn surface(&mut self, stride: u32, format: u32) -> Out<u32> {
        if let Err(c) = self.claim.require(self.me).and_then(|()| full_hd().check_surface(stride, format)) {
            return Out::err(c);
        }
        self.surfaces.push((stride, format, vec![]));
        Out::ok(self.surfaces.len() as u32)
    }
    fn band(&mut self, id: u32, mem: Cap<SurfaceBand>) -> Out<u32> {
        if let Err(c) = self.claim.require(self.me) {
            return Out::err(c);
        }
        let Some((stride, _, bands)) = (id as usize).checked_sub(1).and_then(|i| self.surfaces.get_mut(i)) else {
            return Out::err(outcome::NO_RESOURCE);
        };
        let covered = bands.len() as u32 * 34;
        match band_take(1080, covered.min(1080), *stride, 64 * 4096) {
            Ok(rows) => {
                bands.push(mem.raw());
                Out::ok(covered + rows)
            }
            Err(c) => Out::err(c),
        }
    }
    fn destroy_surface(&mut self, id: u32) -> Out<()> {
        match id as usize {
            1..=4 if (id as usize) <= self.surfaces.len() => Out::ok(()),
            _ => Out::err(outcome::NO_RESOURCE),
        }
    }
    fn present(&mut self, request: Present) -> Out<u64> {
        if let Err(c) = self.claim.require(self.me).and_then(|()| request.check(&full_hd())) {
            return Out::err(c);
        }
        self.frames += 1;
        Out::ok(self.frames)
    }
    fn vsync(&mut self, events: Cap<VsyncPort>, key: u64) -> Out<()> {
        self.vsync = Some((events.raw(), key));
        Out::ok(())
    }
}

/// Through the generated client and dispatcher: a full present (all six
/// rectangles) arrives intact, the two capability ops carry one entry each,
/// the answers keep their values, and refusals come back as the server
/// gave them.
#[test]
fn the_client_and_the_dispatcher_carry_every_op() {
    let mock = RefCell::new(Mock { claim: Claim::new(), me: 1, surfaces: vec![], frames: 0, vsync: None });
    let serve = |req: &MsgDesc, rep: &mut MsgDesc| {
        let _ = DisplayIdl::dispatch(&mut *mock.borrow_mut(), req, rep);
    };
    let lp = Loop { serve: &serve };
    let mut c = DisplayClient::new(&lp);

    assert_eq!(c.connector().unwrap(), Out::ok(full_hd()));
    assert_eq!(c.mode(0).unwrap().value.flags, display::MODE_CURRENT | display::MODE_PREFERRED);
    assert_eq!(c.mode(1).unwrap().value.width, 1280);
    assert_eq!(c.mode(2).unwrap(), Out::err(outcome::BAD_ARGUMENT));

    let one = Present::new(1, &[Rect::new(0, 0, 4, 4)]).unwrap();
    assert_eq!(c.present(one).unwrap().code, outcome::NOT_READY, "before the claim");
    assert_eq!(c.surface(7680, FORMAT_XRGB8888).unwrap().code, outcome::NOT_READY);
    assert_eq!(c.claim().unwrap(), Out::ok(()));
    assert_eq!(c.claim().unwrap(), Out::ok(()), "repeatable");

    assert_eq!(c.surface(7680, FORMAT_XRGB8888).unwrap(), Out::ok(1));
    assert_eq!(c.band(1, Cap::from_raw(9)).unwrap(), Out::ok(34), "the first band's rows");
    assert_eq!(c.band(1, Cap::from_raw(10)).unwrap(), Out::ok(68));
    assert_eq!(c.band(2, Cap::from_raw(11)).unwrap().code, outcome::NO_RESOURCE);
    assert_eq!(
        mock.borrow().surfaces,
        vec![(7680, FORMAT_XRGB8888, vec![9, 10])],
        "both scalars, the id and each capability arrived"
    );
    assert_eq!(c.surface(7680, FORMAT_RGB565).unwrap().code, outcome::BAD_ARGUMENT);
    assert_eq!(c.destroy_surface(1).unwrap(), Out::ok(()));
    assert_eq!(c.destroy_surface(2).unwrap().code, outcome::NO_RESOURCE);

    let six = Present::new(1, &[Rect::new(0, 0, 1, 1), Rect::new(1, 1, 1, 1), Rect::new(2, 2, 1, 1), Rect::new(3, 3, 1, 1), Rect::new(4, 4, 1, 1), Rect::new(1919, 1079, 1, 1)]).unwrap();
    assert_eq!(c.present(six).unwrap(), Out::ok(1));
    assert_eq!(c.present(one).unwrap(), Out::ok(2));
    let off = Present::new(1, &[Rect::new(1919, 0, 2, 1)]).unwrap();
    assert_eq!(c.present(off).unwrap().code, outcome::BAD_ARGUMENT);

    assert_eq!(c.vsync(Cap::from_raw(5), 0xBEEF_0000_0001).unwrap(), Out::ok(()));
    assert_eq!(mock.borrow().vsync, Some((5, 0xBEEF_0000_0001)));
    assert_eq!(c.release().unwrap(), Out::ok(()));
    assert_eq!(c.present(one).unwrap().code, outcome::NOT_READY, "after the release");
}

/// A request header for another interface's id, and an op number that is not
/// the interface's, are refused by the dispatcher and never reach the server.
#[test]
fn a_foreign_header_never_reaches_the_server() {
    let mut mock = Mock { claim: Claim::new(), me: 1, surfaces: vec![], frames: 0, vsync: None };
    for header in [azos_idl::header(DISPLAY_ID, 1, 0), azos_idl::header(DISPLAY_ID, 1, 9), azos_idl::header(0x4E45_5420, 1, 1)] {
        let mut req = MsgDesc { version: azos_idl::MSG_VERSION, ..MsgDesc::default() };
        let mut w = Writer::new(&mut req);
        w.word(header);
        w.finish();
        let mut rep = MsgDesc::default();
        assert!(DisplayIdl::dispatch(&mut mock, &req, &mut rep).is_err(), "{header:#x}");
        assert_ne!(rep.words[0], azos_idl::STATUS_OK);
    }
    assert_eq!(mock.claim.holder(), None);
}

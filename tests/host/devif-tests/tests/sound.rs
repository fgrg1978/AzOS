// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The `Sound` interface: its op table, its wire form, the geometry a stream's
//! parameters amount to, the period slots of the two queues, the held-period
//! bitmap, the order of the capture reasons, and the equality of the bounds
//! with the topology's and Kconfig's.

use azos_devif::outcome;
use azos_devif::sound::{
    self, arena_rights, capture_reason, format_bit, sample_bytes, Arena, DoneQueue, Geometry, Info, Opened, Params, Period, Posted,
    ReadyQueue, Status, ARENA_BYTES_MAX, CHANNELS_MAX, DIR_CAPTURE, DIR_PLAYBACK, ENDPOINT, ENDPOINT_NAME, FMT_F32,
    FMT_S16, FMT_S24, FMT_S32, FORMATS_ALL, MIC_ADMITTED, MIC_HELD, MIC_NO_GRANT, MIC_NO_INDICATOR, MIC_NO_REQUEST, NO_PERIOD,
    PERIODS_MAX, PERIODS_MIN, PERIOD_CANCELLED, PERIOD_END, PERIOD_FRAMES_MAX, PERIOD_FRAMES_MIN, PERIOD_XRUN,
    QUEUE_RIGHTS, RATE_HZ_MAX, RATE_HZ_MIN, SLOT_WORDS, STATE_OPEN, STATE_RUNNING,
};
use azos_devif::{Out, Sound, SoundCall, SoundClient, SoundIdl, SOUND_ID};
use azos_abi::cap::CapPerms;
use azos_idl::{header, IdlError, Lent, MsgDesc, Result as IdlResult, Transport, CAP_MODE_DUP};
use std::cell::{Cell, RefCell};

/// A device that records what it was asked and enforces the interface's own
/// checks, as the audio server does.
#[derive(Default)]
struct Dev {
    open: Option<(Params, Geometry, u32, u32, u32)>,
    state: u32,
    log: Vec<&'static str>,
}

impl Sound for Dev {
    fn info(&self) -> Out<Info> {
        Out::ok(Info {
            dirs: DIR_PLAYBACK | DIR_CAPTURE,
            formats: format_bit(FMT_S16) | format_bit(FMT_F32),
            rate_hz: 48_000,
            channels: 2,
            period_frames_min: 64,
            period_frames_max: 4_096,
        })
    }
    fn open(&mut self, params: Params, ready: Lent<ReadyQueue>, done: Lent<DoneQueue>, arena: Lent<Arena>, _on_behalf: u64) -> Out<Opened> {
        self.log.push("open");
        if self.open.is_some() {
            return Out::err(outcome::BUSY);
        }
        let geo = match params.check() {
            Ok(g) => g,
            Err(c) => return Out::err(c),
        };
        let (Some(ready), Some(done), Some(arena)) = (ready.get(), done.get(), arena.get()) else {
            return Out::err(outcome::BAD_ARGUMENT);
        };
        self.open = Some((params, geo, ready.raw(), done.raw(), arena.raw()));
        self.state = STATE_OPEN;
        Out::ok(Opened { period_bytes: geo.period_bytes, latency_frames: 96 })
    }
    fn start(&mut self) -> Out<()> {
        self.log.push("start");
        if self.open.is_none() {
            return Out::err(outcome::NOT_READY);
        }
        self.state = STATE_RUNNING;
        Out::ok(())
    }
    fn stop(&mut self) -> Out<()> {
        self.log.push("stop");
        if self.open.is_some() {
            self.state = STATE_OPEN;
        }
        Out::ok(())
    }
    fn drain(&mut self) -> Out<()> {
        self.log.push("drain");
        if self.open.is_none() {
            return Out::err(outcome::NOT_READY);
        }
        Out::ok(())
    }
    fn close(&mut self) -> Out<()> {
        self.log.push("close");
        self.open = None;
        self.state = 0;
        Out::ok(())
    }
    fn status(&self) -> Out<Status> {
        Out::ok(Status { state: self.state, xruns: 3, frames: 1 << 40 })
    }
}

struct Loop<'a> {
    server: &'a RefCell<Dev>,
    sent: Cell<u32>,
    last: RefCell<MsgDesc>,
}

impl Transport for &Loop<'_> {
    fn call(&self, msg: &mut MsgDesc) -> IdlResult {
        self.sent.set(self.sent.get() + 1);
        let req = *msg;
        *self.last.borrow_mut() = req;
        let _ = SoundIdl::dispatch(&mut *self.server.borrow_mut(), &req, msg);
        Ok(())
    }
}

fn lp(server: &RefCell<Dev>) -> Loop<'_> {
    Loop { server, sent: Cell::new(0), last: RefCell::new(MsgDesc::default()) }
}

fn stereo() -> Params {
    Params { dir: DIR_PLAYBACK, format: FMT_S16, rate_hz: 48_000, channels: 2, period_frames: 480, periods: 4 }
}

/// The table is the trait in order; only `open` is once-only (a capture open
/// is an effect), with its failure contract; every other op may be asked
/// again; and each shape fits the message: `open` is the header and six
/// parameter words with three capabilities, `info` an eight-word reply.
///
/// **Canary.** Make `open` `#[idempotent]`, drop its `#[on_failure]`, or add a
/// fourth capability to it: red (or a compile error, which is the lint).
#[test]
fn the_op_table_is_the_trait_and_only_open_is_once_only() {
    let names: Vec<&str> = SoundIdl::OPS.iter().map(|o| o.name).collect();
    assert_eq!(names, ["info", "open", "start", "stop", "drain", "close", "status"]);
    assert_eq!(SoundIdl::ID, SOUND_ID);
    for (i, o) in SoundIdl::OPS.iter().enumerate() {
        assert_eq!(o.op as usize, i + 1);
        if o.name == "open" {
            assert!(o.once_only() && !o.retry_safe(), "an open is never asked twice");
            assert_eq!(o.on_failure, Some(azos_idl::OnFailure::Degrade));
            assert!(o.deadline_ns > 0 && o.budget_us > 0);
        } else {
            assert!(o.idempotent() && o.retry_safe(), "{} may not be asked again", o.name);
        }
    }
    let open = SoundIdl::OPS[1];
    assert_eq!((open.req_words, open.req_caps, open.rep_words, open.rep_caps), (8, 3, 4, 0));
    assert_eq!(SoundIdl::OPS[0].rep_words, 8, "info is the widest reply the message holds");
    assert!(SoundIdl::OPS[3].deadline_ns > 0, "a stop declares how fast it must be");
}

/// `open` is the header, the six parameters two to a word, the three objects
/// as presence words and capability entries in order (ready, done, arena) and
/// `on_behalf`; the reply is the geometry the server computed. The entries are
/// lent (`DUP`, with [`QUEUE_RIGHTS`] and [`arena_rights`]), never moved: a
/// memory object that moves takes the client's mapping with it, and the client
/// goes on writing all three. A second open is `BUSY` and changes nothing; a
/// bad parameter, or an object not lent, is refused before anything is attached.
///
/// **Canary.** Swap `ready` and `done` in the stub: the order row is red.
/// Let a second `open` replace the first: the `BUSY` row is red. Make the
/// argument types `Cap` again (MOVE): the mode row is red.
#[test]
fn open_lends_three_objects_and_answers_the_geometry() {
    let dev = RefCell::new(Dev::default());
    let l = lp(&dev);
    let mut c = SoundClient::new(&l);
    let (q, d, a) = (
        Lent::<ReadyQueue>::dup(10, QUEUE_RIGHTS),
        Lent::<DoneQueue>::dup(11, QUEUE_RIGHTS),
        Lent::<Arena>::dup(12, arena_rights(DIR_PLAYBACK)),
    );
    let got = c.open(stereo(), q, d, a, 0).unwrap();
    assert_eq!(got, Out::ok(Opened { period_bytes: 480 * 4, latency_frames: 96 }));
    let r = *l.last.borrow();
    assert_eq!((r.n_words, r.n_caps), (8, 3));
    assert_eq!(r.words[0], header(SOUND_ID, 1, SoundIdl::OP_OPEN));
    let pair = |lo: u32, hi: u32| u64::from(lo) | u64::from(hi) << 32;
    assert_eq!(&r.words[1..8], &[pair(DIR_PLAYBACK, FMT_S16), pair(48_000, 2), pair(480, 4), 1, 1, 1, 0]);
    assert_eq!((r.caps[0].handle, r.caps[1].handle, r.caps[2].handle), (10, 11, 12), "ready, done, arena");
    assert!(r.caps[..3].iter().all(|e| e.mode == CAP_MODE_DUP), "lent, not moved");
    let rw_map = CapPerms::RW.union(CapPerms::MAP).bits() as u16;
    let r_map = CapPerms::READ.union(CapPerms::MAP).bits() as u16;
    assert_eq!((r.caps[0].rights, r.caps[1].rights, r.caps[2].rights), (rw_map, rw_map, r_map), "both ends write a queue; playback reads the arena");
    assert_eq!(arena_rights(DIR_CAPTURE), rw_map, "capture writes the arena");
    assert_eq!(dev.borrow().open.as_ref().map(|o| (o.2, o.3, o.4)), Some((10, 11, 12)));

    let again = c.open(stereo(), Lent::dup(20, QUEUE_RIGHTS), Lent::dup(21, QUEUE_RIGHTS), Lent::dup(22, r_map), 0).unwrap();
    assert_eq!(again.code, outcome::BUSY);
    assert_eq!(dev.borrow().open.as_ref().map(|o| o.2), Some(10), "the refused open did not replace the stream");

    assert_eq!(c.close(), Ok(Out::ok(())));
    let bad = Params { periods: 1, ..stereo() };
    assert_eq!(c.open(bad, q, d, a, 0).unwrap().code, outcome::BAD_ARGUMENT);
    assert!(dev.borrow().open.is_none(), "nothing attached for a refused geometry");
    // A request names all three: fewer entries than the op declares is not a
    // request the dispatcher hands the server.
    assert_eq!(c.open(stereo(), q, Lent::none(), a, 0), Err(IdlError::Malformed), "a queue not lent");
    assert_eq!(l.last.borrow().n_caps, 2, "no entry for what is not lent");
    assert!(dev.borrow().open.is_none(), "nothing attached for a missing object");
}

/// The transport ops carry no argument; `start` needs a stream; `stop`, `drain`
/// and `close` are served; `status` and `info` carry their whole answer.
///
/// **Canary.** Add an argument to `start`: the word count is red.
#[test]
fn the_transport_ops_are_bare_and_the_answers_carry_whole() {
    let dev = RefCell::new(Dev::default());
    let l = lp(&dev);
    let mut c = SoundClient::new(&l);
    assert_eq!(c.start().unwrap().code, outcome::NOT_READY, "no stream, nothing to start");
    assert_eq!(c.drain().unwrap().code, outcome::NOT_READY);
    assert_eq!(c.stop(), Ok(Out::ok(())));
    c.open(stereo(), Lent::dup(1, QUEUE_RIGHTS), Lent::dup(2, QUEUE_RIGHTS), Lent::dup(3, arena_rights(DIR_PLAYBACK)), 0).unwrap();
    for (call, op) in [(0, SoundIdl::OP_START), (1, SoundIdl::OP_STOP), (2, SoundIdl::OP_DRAIN)] {
        let out = match call {
            0 => c.start(),
            1 => c.stop(),
            _ => c.drain(),
        };
        assert_eq!(out, Ok(Out::ok(())));
        let r = *l.last.borrow();
        assert_eq!((r.n_words, r.n_caps), (1, 0));
        assert_eq!(r.words[0], header(SOUND_ID, 1, op));
    }
    assert_eq!(c.status(), Ok(Out::ok(Status { state: STATE_OPEN, xruns: 3, frames: 1 << 40 })), "stop left it open");
    assert_eq!(c.info().unwrap().value.rate_hz, 48_000);
    assert_eq!(c.info().unwrap().value.period_frames_max, 4_096);
    assert_eq!(dev.borrow().log, ["start", "drain", "stop", "open", "start", "stop", "drain"]);
}

fn bad(f: impl Fn(&mut Params)) -> Result<Geometry, u32> {
    let mut p = stereo();
    f(&mut p);
    p.check()
}

/// A queue of `queue_slots` slots never refuses a push of the server: with
/// every period of the arena already returned on `done` and none consumed, the
/// drain end marker (one slot that is not a period) still finds room. This is
/// the power-of-two case (`periods` 8 among them, a Kconfig default) that sized
/// `done` at exactly `periods` slots.
///
/// **Canary.** Size the queues at `periods.next_power_of_two()`: the rows with
/// a power-of-two `periods` are red (the marker lands on a full queue and the
/// drain never completes).
#[test]
fn the_done_queue_has_room_for_every_period_and_the_end_marker() {
    for periods in PERIODS_MIN..=PERIODS_MAX {
        let g = bad(|p| p.periods = periods).unwrap();
        assert!(g.queue_slots.is_power_of_two(), "periods {periods}");
        // Every period back, unconsumed, then the end marker.
        assert!(g.queue_slots >= periods + 1, "periods {periods}: {} slots", g.queue_slots);
        let mut done = 0u32;
        for _ in 0..periods {
            assert!(done < g.queue_slots, "a returned period found `done` full");
            done += 1;
        }
        assert!(done < g.queue_slots, "periods {periods}: the end marker found `done` full");
    }
    assert_eq!(bad(|p| p.periods = 8).unwrap().queue_slots, 16);
    assert_eq!(bad(|p| p.periods = 64).unwrap().queue_slots, 128);
}

/// The geometry of a stream is what its parameters multiply to, and every
/// parameter has a floor and a ceiling: exactly one direction, a defined
/// format, a rate, channel count, period length and period count in range, and
/// an arena that fits the ceiling.
///
/// **Canary.** Accept `dir = 3` (both), or drop the arena ceiling: the matching
/// rows are red. Widen `frame_bytes` to a product that wraps: the extreme row
/// is red.
#[test]
fn the_parameters_amount_to_a_geometry_or_are_refused() {
    let g = stereo().check().unwrap();
    assert_eq!(
        g,
        Geometry { frame_bytes: 4, period_frames: 480, period_bytes: 1_920, periods: 4, arena_bytes: 7_680, queue_slots: 8 }
    );
    assert_eq!(bad(|p| p.periods = 5).unwrap().queue_slots, 8, "rounded up to a power of two");
    assert_eq!(bad(|p| p.periods = 8).unwrap().queue_slots, 16, "the end marker is one more than the periods");
    assert_eq!(bad(|p| p.format = FMT_S24).unwrap().frame_bytes, 8);
    assert_eq!(bad(|p| p.format = FMT_F32).unwrap().frame_bytes, 8);
    assert_eq!(bad(|p| p.dir = DIR_CAPTURE).unwrap().arena_bytes, 7_680);

    let refused = Err(outcome::BAD_ARGUMENT);
    assert_eq!(bad(|p| p.dir = 0), refused);
    assert_eq!(bad(|p| p.dir = DIR_PLAYBACK | DIR_CAPTURE), refused, "one stream, one direction");
    assert_eq!(bad(|p| p.dir = 4), refused);
    assert_eq!(bad(|p| p.format = 0), refused);
    assert_eq!(bad(|p| p.format = 5), refused);
    assert_eq!(bad(|p| p.rate_hz = RATE_HZ_MIN - 1), refused);
    assert_eq!(bad(|p| p.rate_hz = RATE_HZ_MAX + 1), refused);
    assert_eq!(bad(|p| p.channels = 0), refused);
    assert_eq!(bad(|p| p.channels = CHANNELS_MAX + 1), refused);
    assert_eq!(bad(|p| p.period_frames = PERIOD_FRAMES_MIN - 1), refused);
    assert_eq!(bad(|p| p.period_frames = PERIOD_FRAMES_MAX + 1), refused);
    assert_eq!(bad(|p| p.periods = PERIODS_MIN - 1), refused);
    assert_eq!(bad(|p| p.periods = PERIODS_MAX + 1), refused);
    assert_eq!(bad(|p| p.periods = u32::MAX), refused);
    assert!(bad(|p| p.rate_hz = RATE_HZ_MIN).is_ok() && bad(|p| p.rate_hz = RATE_HZ_MAX).is_ok());
    assert!(bad(|p| p.periods = PERIODS_MIN).is_ok() && bad(|p| p.periods = PERIODS_MAX).is_ok());
    // The ceiling: 32 channels of 4-byte samples, 16_384 frames, 64 periods
    // is 128 MiB; 8 periods of it is exactly the 16 MiB ceiling.
    let big = |periods| Params { channels: 32, format: FMT_S32, period_frames: PERIOD_FRAMES_MAX, periods, ..stereo() };
    assert_eq!(big(8).check().map(|g| g.arena_bytes), Ok(ARENA_BYTES_MAX));
    assert_eq!(big(9).check(), refused, "one period over the ceiling");
    assert_eq!(big(PERIODS_MAX).check(), refused);
}

/// Every format has its size and `FORMATS_ALL` is exactly the defined set.
///
/// **Canary.** Add a format to `sample_bytes` without its bit in
/// `FORMATS_ALL`: red.
#[test]
fn the_formats_have_sizes_and_a_set() {
    let defined: Vec<u32> = (0..32).filter(|&f| sample_bytes(f).is_some()).collect();
    assert_eq!(defined, [FMT_S16, FMT_S24, FMT_S32, FMT_F32]);
    assert_eq!(defined.iter().fold(0, |m, &f| m | format_bit(f)), FORMATS_ALL);
    assert_eq!([FMT_S16, FMT_S24, FMT_S32, FMT_F32].map(|f| sample_bytes(f).unwrap()), [2, 4, 4, 4]);
}

/// A period index addresses the arena only inside it, and the offset of the
/// last period ends at the arena's end; an index past it is `None`, not a wrap.
///
/// **Canary.** Compare with `<=`: the one-past row is red.
#[test]
fn a_period_index_names_a_period_of_the_arena_and_no_byte_outside_it() {
    let g = stereo().check().unwrap();
    assert_eq!(g.period_offset(0), Some(0));
    assert_eq!(g.period_offset(3), Some(3 * 1_920));
    assert_eq!(g.period_offset(3).unwrap() + u64::from(g.period_bytes), g.arena_bytes);
    assert_eq!(g.period_offset(4), None);
    assert_eq!(g.period_offset(NO_PERIOD), None);
}

fn period() -> Period {
    Period { index: 2, frames: 480, flags: 0, time_ns: 0 }
}

/// A slot is four words and comes back as it went; a field too wide for its
/// type or a flag this interface does not define is refused, not guessed at.
///
/// **Canary.** Drop the flag mask in `from_slot`, or the `try_from` on the
/// index: the matching row is red.
#[test]
fn slots_round_trip_and_refuse_what_they_do_not_understand() {
    assert_eq!(SLOT_WORDS * 8, 32);
    for p in [
        period(),
        Period { index: 1, frames: 480, flags: PERIOD_XRUN, time_ns: 123_456_789_012 },
        Period { index: 0, frames: 0, flags: PERIOD_CANCELLED | PERIOD_XRUN, time_ns: 0 },
        Period { index: NO_PERIOD, frames: 0, flags: PERIOD_END, time_ns: u64::MAX },
    ] {
        assert_eq!(Period::from_slot(&p.to_slot()), Some(p));
    }
    let mut s = period().to_slot();
    s[0] = 1 << 32;
    assert_eq!(Period::from_slot(&s), None, "index wider than u32");
    let mut s = period().to_slot();
    s[1] = 1 << 32;
    assert_eq!(Period::from_slot(&s), None, "frames wider than u32");
    let mut s = period().to_slot();
    s[2] = 8;
    assert_eq!(Period::from_slot(&s), None, "a flag nobody defined");
    s[2] = 1 << 32;
    assert_eq!(Period::from_slot(&s), None, "flags wider than u32");
}

/// What the client posts is checked before the arena is touched: the index is
/// a period of the geometry, the frames are 1..=period for playback and
/// exactly the period for capture, and the server's own fields are zero.
///
/// **Canary.** Skip the `period_offset` test: the index rows are red. Accept
/// `frames = 0` for playback, or a short capture post: those rows are red.
#[test]
fn a_posted_period_is_checked_against_the_geometry() {
    let g = stereo().check().unwrap();
    assert_eq!(period().check(&g, DIR_PLAYBACK), Ok(()));
    assert_eq!(Period { frames: 1, ..period() }.check(&g, DIR_PLAYBACK), Ok(()), "a short last period plays");
    let refused = Err(outcome::BAD_ARGUMENT);
    assert_eq!(Period { index: 4, ..period() }.check(&g, DIR_PLAYBACK), refused, "one past the arena");
    assert_eq!(Period { index: NO_PERIOD, ..period() }.check(&g, DIR_PLAYBACK), refused, "the marker is not a post");
    assert_eq!(Period { frames: 0, ..period() }.check(&g, DIR_PLAYBACK), refused);
    assert_eq!(Period { frames: 481, ..period() }.check(&g, DIR_PLAYBACK), refused, "more than the period holds");
    assert_eq!(period().check(&g, DIR_CAPTURE), Ok(()));
    assert_eq!(Period { frames: 100, ..period() }.check(&g, DIR_CAPTURE), refused, "capture room is the whole period");
    assert_eq!(Period { flags: PERIOD_XRUN, ..period() }.check(&g, DIR_PLAYBACK), refused, "flags are the server's");
    assert_eq!(Period { time_ns: 1, ..period() }.check(&g, DIR_PLAYBACK), refused, "so is the time");
}

/// A period is held once and given back once; a second post of one the server
/// holds, a return of one it does not, and an index past the bitmap change
/// nothing.
///
/// **Canary.** Let `post` set a bit already set: the double-post row is red;
/// shift by `index` without the bound: the 64 row panics.
#[test]
fn a_period_is_held_once_and_given_back_once() {
    let mut p = Posted::default();
    assert!(p.post(0) && p.post(3) && p.post(PERIODS_MAX - 1));
    assert_eq!(p.held(), 3);
    assert!(!p.post(3), "already held");
    assert!(!p.post(PERIODS_MAX), "no such period");
    assert!(!p.post(NO_PERIOD));
    assert_eq!(p.held(), 3);
    assert!(p.give_back(3) && !p.give_back(3), "back once");
    assert!(!p.give_back(PERIODS_MAX) && !p.give_back(1));
    assert_eq!(p.held(), 2);
    assert!(p.post(3), "a returned period can be posted again");
}

/// The capture reason is decided in a fixed order, so a task without the
/// microphone effect never learns whether the device is held, and a capture
/// never opens while the person cannot be told it is live.
///
/// **Canary.** Test `held_by_other` before `mic_effect`: the first row is red.
#[test]
fn the_capture_reasons_are_decided_in_order() {
    assert_eq!(capture_reason(true, true, false), MIC_ADMITTED);
    assert_eq!(capture_reason(false, true, false), MIC_NO_GRANT);
    assert_eq!(capture_reason(false, false, true), MIC_NO_GRANT, "no grant is told before anything else");
    assert_eq!(capture_reason(true, false, true), MIC_NO_INDICATOR, "no indicator is told before a held device");
    assert_eq!(capture_reason(true, true, true), MIC_HELD);
    // The numbers are the `audio-capture` decision rule's `reason` field.
    assert_eq!([MIC_ADMITTED, MIC_NO_GRANT, MIC_NO_INDICATOR, MIC_HELD, MIC_NO_REQUEST], [0, 1, 2, 3, 4]);
}

/// Whose effect a capture open is decided on: the caller's own when it names no
/// call, the maker of the call it names when it serves that call, and nobody's
/// when it names a call it does not serve. The messenger's identity never
/// stands in for the requester's.
///
/// **Canary.** Return `Some(caller)` whatever `on_behalf` says: the second row
/// is red (the server decides on its own class again).
#[test]
fn a_capture_is_decided_for_the_requester_not_the_messenger() {
    const SERVER: u32 = 7;
    const CLIENT: u32 = 9;
    let served = |call: u64| (call == 0x55).then_some(CLIENT);
    assert_eq!(sound::capture_subject(SERVER, 0, served), Some(SERVER), "a task asks for itself");
    assert_eq!(sound::capture_subject(SERVER, 0x55, served), Some(CLIENT), "the server asks for its client");
    assert_eq!(sound::capture_subject(SERVER, 0x56, served), None, "a call the server does not serve names nobody");
    assert_eq!(sound::capture_subject(SERVER, 0, |_| panic!("no call named, nothing to resolve")), Some(SERVER));
}

/// The wire structs have the words they declare.
#[test]
fn the_answers_have_the_words_they_declare() {
    use azos_idl::{Reader, Wire, Writer};
    fn trip<T: Wire + PartialEq + core::fmt::Debug>(v: T) {
        let mut m = MsgDesc::default();
        let mut w = Writer::new(&mut m);
        v.put(&mut w);
        w.finish();
        assert_eq!(m.n_words as usize, T::WORDS);
        let mut r = Reader::new(&m);
        assert_eq!(T::get(&mut r), v);
    }
    trip(stereo());
    trip(Opened { period_bytes: 1_920, latency_frames: 7 });
    trip(Status { state: STATE_RUNNING, xruns: u32::MAX, frames: u64::MAX });
    trip(Info { dirs: 3, formats: FORMATS_ALL, rate_hz: 96_000, channels: 8, period_frames_min: 16, period_frames_max: 16_384 });
}

/// The endpoint spelling and the pool name are one name.
///
/// **Canary.** Change `ENDPOINT_NAME`: red.
#[test]
fn the_pool_name_is_the_topology_name_without_its_prefix() {
    assert_eq!(ENDPOINT.strip_prefix("endpoint."), Some(ENDPOINT_NAME));
    assert!(ENDPOINT_NAME.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-'));
    assert!(ENDPOINT_NAME.len() <= 24, "ENDPOINT_NAME_MAX");
    let _ = sound::SOUND_ID;
}

/// The kernel hosts the interface for the device it drives, from the endpoint
/// `sound.<n>` with badge `n + 1`; the audio server's `endpoint.audio` is another
/// name.
///
/// **Canary.** Lift `DEVICES` to 2 or spell the bare name: red.
#[test]
fn the_kernel_hosted_endpoint_names_a_device_and_the_badge_is_one_more() {
    assert_eq!(azos_devif::key::SOUND, 26);
    let i = azos_devif::by_name("sound").expect("no row sound");
    assert_eq!((i.key, i.id), (azos_devif::key::SOUND, SOUND_ID));
    assert_eq!(azos_devif::by_key(azos_devif::key::SOUND).map(|x| x.name), Some("sound"));
    for n in 0..sound::DEVICES {
        assert_eq!(azos_devif::parse_target(&format!("sound.{n}")).map(|(i, b)| (i.name, b)), Some(("sound", n + 1)));
    }
    assert_eq!(sound::device_badge(0), 1, "badge 0 is the unbadged endpoint: no device");
    for bad in ["sound", "sound.1", "sound.-1", "sound.0.1", "sound.x", "sound2", "sound.", "audio.0"] {
        assert!(azos_devif::parse_target(bad).is_none(), "{bad}");
    }
}

fn read(rel: &str) -> String {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..").join(rel);
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
}

/// The rate and channel bounds are the topology's (the `[audio.NAME]` row the
/// device comes from is refused outside them), and the `mic` effect is a word
/// an `[envelope.NAME]` row can spell.
///
/// **Canary.** Change `RATE_HZ_MAX` here or `AUDIO_RATE_HZ` there: red. Delete
/// `Mic = "mic"` from the topology: red.
#[test]
fn the_bounds_are_the_topologys_and_the_mic_effect_is_a_row_word() {
    let t = read("crates/core/topology/src/types.rs");
    let want = format!("pub const AUDIO_RATE_HZ: (u32, u32) = ({}, {});", fmt_us(RATE_HZ_MIN), fmt_us(RATE_HZ_MAX));
    assert!(t.contains(&want), "topology rate bounds drifted from `{want}`");
    assert!(t.contains(&format!("pub const AUDIO_CHANNELS_MAX: u8 = {CHANNELS_MAX};")), "channel bound drifted");
    assert!(t.contains("Mic = \"mic\","), "EffectKind::Mic is the `mic` effect of Sound::open");
}

/// `8_000`, as the topology spells it.
fn fmt_us(n: u32) -> String {
    let s = n.to_string();
    let mut out = String::new();
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i) % 3 == 0 {
            out.push('_');
        }
        out.push(c);
    }
    out
}

/// The audio server's policy options stop at the interface's bounds: a range
/// that reached past them would promise what `Params::check` refuses.
///
/// **Canary.** Raise `AUDIO_MAX_PERIODS` to `range 2 128`: red.
#[test]
fn the_kconfig_ranges_stop_at_the_interface_bounds() {
    let k = read("config/subsys/Kconfig.audio");
    let range = |sym: &str| -> (u64, u64) {
        let block = k.split(&format!("config {sym}\n")).nth(1).unwrap_or_else(|| panic!("{sym} missing"));
        let line = block.lines().find(|l| l.trim_start().starts_with("range ")).unwrap_or_else(|| panic!("{sym} has no range"));
        let mut it = line.split_whitespace().skip(1).map(|n| n.parse::<u64>().unwrap());
        (it.next().unwrap(), it.next().unwrap())
    };
    assert_eq!(range("AUDIO_MAX_PERIODS"), (u64::from(PERIODS_MIN), u64::from(PERIODS_MAX)));
    assert_eq!(range("AUDIO_ARENA_KB_MAX").1 * 1024, ARENA_BYTES_MAX);
    assert!(range("AUDIO_MAX_STREAMS").0 >= 1);
}

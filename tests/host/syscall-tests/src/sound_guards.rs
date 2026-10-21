// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// Host tests for the kernel-hosted `Sound` interface --
// `crates/core/syscall/src/sound_host.rs`, with `khost::serve` in front of it,
// over the model of the virtio-sound device in `shims/drivers` (`snd::fake`):
// the authority each op demands, what `open` checks before it touches the
// device, a playback stream from the client's `ready` queue to the device and
// back to `done`, a stop that returns everything, both drains, the microphone
// rules, the pin on the arena and the exit of the holder. The rules those lean
// on are `tests/host/devif-tests/tests/sound.rs`; the driver's own behaviour is
// `tests/host/drivers-tests` (`virtio::snd`).
//
// Included inside `mod handlers { .. }` like `display_guards.rs`.

use super::harness::serial;
use azos_abi::cap::CapPerms;
use azos_devif::sound::{
    self as snd, Params, Period, DIR_CAPTURE, DIR_PLAYBACK, FMT_S16, FMT_S32, NO_PERIOD, PERIOD_CANCELLED, PERIOD_END,
};
use azos_devif::{key, outcome, Cap as WireCap, Out, Sound, SoundIdl};
use azos_drv_virtio::virtio::snd::fake;
use azos_idl::{header, MsgDesc, Writer, MSG_VERSION};
use azos_ipc::memobj::{memobj_create_cap, memobj_describe_ref, memobj_page_phys_ref, memobj_release_cap, MemPerms, MemSpec};
use azos_rings::region::{RingStep, SpscSlots};
use crate::khost::Caller;
use crate::sound_host::{self as host, Server};
use std::sync::atomic::{AtomicU32, Ordering::SeqCst};
use std::sync::Mutex;

/// Cap-store pool slots for this file (a second task uses `SLOT2`); no other
/// file in this crate binds 31 or 32.
const SLOT: usize = 31;
const SLOT2: usize = 32;

static NEXT_TID: AtomicU32 = AtomicU32::new(0x7e64_0001);
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

/// Slots a one-page queue holds (the largest power of two after the header).
const SLOTS: u32 = 64;

/// A task with the three objects `open` takes, each made by it: two one-page
/// queue regions and a one-page arena (the geometry below fills 2 KiB).
struct Client {
    tid: u32,
    ready: (u32, u32),
    done: (u32, u32),
    arena: (u32, u32),
}

impl Drop for Client {
    fn drop(&mut self) {
        // The holder's exit: its stream is ended by the pump, as in the kernel.
        host::release_all(self.tid);
        host::pump(0, 1_000);
        host::clear_withheld_mic();
        azos_ipc::fastcall::shim_answer_all();
        azos_ipc::cap::degraded_set(false);
        azos_ipc::memobj::memobj_release_all(self.tid);
        ipc_task_pool::shim_kill(self.tid);
    }
}

fn region(tid: u32, spec: &MemSpec) -> (u32, u32) {
    let cap = memobj_create_cap(tid, 1, spec).expect("a region");
    let r = azos_ipc::cap_store::get(tid, cap, CapPerms::READ).expect("the capability resolves");
    (cap.raw().0, r)
}

fn client_in(slot: usize) -> Client {
    DENIALS.lock().unwrap_or_else(|e| e.into_inner()).clear();
    let tid = NEXT_TID.fetch_add(1, SeqCst);
    ipc_task_pool::shim_bind(tid, slot);
    azos_ipc::cap_store::reset(tid);
    azos_sched::set_current_user_pt(0xBAD0_0000);
    azos_sched::set_current_task_tid(tid);
    set_cap_deny_typed_recorder(typed_recorder);
    let rw = MemSpec::contig(MemPerms::ReadWrite, false);
    Client { tid, ready: region(tid, &rw), done: region(tid, &rw), arena: region(tid, &rw) }
}

/// A client on a device that is up and takes both directions.
fn client() -> Client {
    fake().reset();
    client_in(SLOT)
}

fn server(c: &Client, rights: CapPerms) -> Server {
    Server(Caller { tid: c.tid, badge: snd::device_badge(0), rights })
}

fn params(dir: u32) -> Params {
    Params { dir, format: FMT_S16, rate_hz: 48_000, channels: 2, period_frames: 64, periods: 8 }
}

/// Frames of a period of `params()`, and its bytes (S16 stereo).
const PERIOD_FRAMES: u32 = 64;
const PERIOD_BYTES: u32 = 256;

type Handles = (WireCap<snd::ReadyQueue>, WireCap<snd::DoneQueue>, WireCap<snd::Arena>);

impl Client {
    fn handles(&self) -> Handles {
        (WireCap::from_raw(self.ready.0), WireCap::from_raw(self.done.0), WireCap::from_raw(self.arena.0))
    }

    fn open(&self, p: Params) -> Out<snd::Opened> {
        self.open_for(p, 0)
    }

    /// `open` naming the call `on_behalf` this task is serving.
    fn open_for(&self, p: Params, on_behalf: u64) -> Out<snd::Opened> {
        let (r, d, a) = self.handles();
        server(self, CapPerms::ALL).open(p, r, d, a, on_behalf)
    }

    fn sv(&self) -> Server {
        server(self, CapPerms::ALL)
    }

    /// Post `p` on `ready` as the client does.
    fn post(&self, p: Period) {
        self.post_raw(p.to_slot());
    }

    fn post_raw(&self, w: [u64; 4]) {
        assert!(!matches!(ring(self.ready.1).try_push(&w), RingStep::Blocked), "ready has room");
    }

    /// Everything the server returned on `done`, oldest first.
    fn returned(&self) -> Vec<Period> {
        let mut out = Vec::new();
        loop {
            let mut w = [0u64; 4];
            if matches!(ring(self.done.1).try_pop(&mut w), RingStep::Blocked) {
                return out;
            }
            out.push(Period::from_slot(&w).expect("the server wrote a valid slot"));
        }
    }

    fn arena_phys(&self) -> u64 {
        memobj_page_phys_ref(self.arena.1, 0).unwrap().unwrap() as u64
    }
}

fn ring(r: u32) -> SpscSlots<4> {
    let phys = memobj_page_phys_ref(r, 0).expect("live").expect("a page");
    SpscSlots { base: azos_mm::addr::phys_to_virt(phys), cap: SLOTS }
}

fn pump() {
    host::pump(0, 1_000);
}

fn code<T>(o: Out<T>) -> u32 {
    o.code
}

fn play(index: u32, frames: u32) -> Period {
    Period { index, frames, flags: 0, time_ns: 0 }
}

fn calls() -> Vec<String> {
    fake().calls.clone()
}

// ── authority ────────────────────────────────────────────────────────────

/// Every op demands its own class and refuses before it looks at anything
/// else, recording the refusal once. A contained system keeps `READ` and
/// refuses the ops that make sound (`open`, `start`) but still honours the ones
/// that end it (`stop`, `drain`, `close`).
///
/// **Canary.** Make `end_gate` containment-aware (`gate(WRITE)`): `stop`,
/// `drain` and `close` answer `DENIED` in the contained rows.
#[test]
fn every_op_demands_its_class_and_a_contained_system_still_stops() {
    let _g = serial();
    let c = client();
    let (r, d, a) = c.handles();
    type Call<'a> = &'a dyn Fn(&mut Server) -> u32;
    let rows: [(&str, CapPerms, Call); 7] = [
        ("info", CapPerms::READ, &|s| code(s.info())),
        ("open", CapPerms::WRITE, &|s| code(s.open(params(DIR_PLAYBACK), r, d, a, 0))),
        ("start", CapPerms::WRITE, &|s| code(s.start())),
        ("stop", CapPerms::WRITE, &|s| code(s.stop())),
        ("drain", CapPerms::WRITE, &|s| code(s.drain())),
        ("close", CapPerms::WRITE, &|s| code(s.close())),
        ("status", CapPerms::READ, &|s| code(s.status())),
    ];
    for (name, need, call) in rows {
        // `open` opens: close it again so the next row sees a closed device.
        let out = call(&mut server(&c, need));
        assert_ne!(out, outcome::DENIED, "{name} with {need:?} alone");
        assert!(denials().is_empty(), "{name} served is not a refusal");
        let _ = c.sv().close();
        for other in [CapPerms::READ, CapPerms::WRITE, CapPerms::EXEC, CapPerms::NONE] {
            if other == need {
                continue;
            }
            DENIALS.lock().unwrap().clear();
            assert_eq!(call(&mut server(&c, other)), outcome::DENIED, "{name} with only {other:?}");
            assert_eq!(denials(), vec![(ENDPOINT_CODE, MISSING_PERMS)], "{name}: the refusal is recorded once");
        }
        DENIALS.lock().unwrap().clear();
    }
    assert_eq!(calls().iter().filter(|c| c.starts_with("open")).count(), 1, "only the permitted open reached the device");

    azos_ipc::cap::degraded_set(true);
    for (name, need, call) in rows {
        let denied = call(&mut server(&c, need)) == outcome::DENIED;
        assert_eq!(denied, name == "open" || name == "start", "{name} while contained");
    }
    azos_ipc::cap::degraded_set(false);
    assert_eq!(c.open(params(DIR_PLAYBACK)).code, outcome::OK);
    azos_ipc::cap::degraded_set(true);
    assert_eq!(c.sv().stop().code, outcome::OK, "a contained system can be stopped");
    assert_eq!(c.sv().close().code, outcome::OK);
}

/// Device 0 is the only one: the unbadged endpoint and the ones the topology
/// can spell but nothing serves name no resource, op by op. With no device up,
/// the ones that need it are `NOT_READY`.
#[test]
fn only_device_zero_is_served_and_only_when_it_is_up() {
    let _g = serial();
    let c = client();
    let (r, d, a) = c.handles();
    for badge in [0, 2, 3, u32::MAX] {
        let mut s = Server(Caller { tid: c.tid, badge, rights: CapPerms::ALL });
        let codes = [
            code(s.info()),
            code(s.open(params(DIR_PLAYBACK), r, d, a, 0)),
            code(s.start()),
            code(s.stop()),
            code(s.drain()),
            code(s.close()),
            code(s.status()),
        ];
        assert_eq!(codes, [outcome::NO_RESOURCE; 7], "badge {badge}");
    }
    assert!(!calls().iter().any(|c| c.starts_with("open")), "nothing reached the device");
    fake().caps = None;
    assert_eq!(c.sv().info().code, outcome::NOT_READY);
    assert_eq!(c.open(params(DIR_PLAYBACK)).code, outcome::NOT_READY);
}

#[test]
fn info_is_what_the_device_runs_at() {
    let _g = serial();
    let c = client();
    let i = c.sv().info().value;
    assert_eq!((i.dirs, i.rate_hz, i.channels), (DIR_PLAYBACK | DIR_CAPTURE, 48_000, 2));
    assert_eq!(i.formats, snd::format_bit(FMT_S16) | snd::format_bit(snd::FMT_F32));
    assert_eq!((i.period_frames_min, i.period_frames_max), (snd::PERIOD_FRAMES_MIN, snd::PERIOD_FRAMES_MAX));
    fake().caps = Some(azos_drv_virtio::virtio::snd::Caps { dirs: DIR_PLAYBACK, formats: snd::format_bit(FMT_S16), rate_hz: 44_100, channels: 1 });
    let i = c.sv().info().value;
    assert_eq!((i.dirs, i.rate_hz, i.channels), (DIR_PLAYBACK, 44_100, 1));
}

// ── open ─────────────────────────────────────────────────────────────────

/// `open` refuses what is wrong before the device is asked, and takes nothing
/// from the client (the pin is not taken).
///
/// **Canary.** Drop the `rate_hz != caps.rate_hz` test: the 44.1 kHz row
/// reaches the device.
#[test]
fn open_refuses_before_it_touches_the_device() {
    let _g = serial();
    let c = client();
    let mut bad: Vec<(&str, u32, Params)> = Vec::new();
    bad.push(("no direction", outcome::BAD_ARGUMENT, Params { dir: 0, ..params(DIR_PLAYBACK) }));
    bad.push(("both directions", outcome::BAD_ARGUMENT, Params { dir: 3, ..params(DIR_PLAYBACK) }));
    bad.push(("more periods than the server allows", outcome::BAD_ARGUMENT, Params { periods: azos_limits::AUDIO_MAX_PERIODS as u32 + 1, ..params(DIR_PLAYBACK) }));
    bad.push(("an undefined format", outcome::BAD_ARGUMENT, Params { format: 99, ..params(DIR_PLAYBACK) }));
    bad.push(("a format the device lacks", outcome::UNSUPPORTED, Params { format: FMT_S32, ..params(DIR_PLAYBACK) }));
    bad.push(("another rate", outcome::UNSUPPORTED, Params { rate_hz: 44_100, ..params(DIR_PLAYBACK) }));
    bad.push(("another channel count", outcome::UNSUPPORTED, Params { channels: 1, ..params(DIR_PLAYBACK) }));
    for (what, want, p) in bad {
        assert_eq!(c.open(p).code, want, "{what}");
    }
    assert!(!calls().iter().any(|c| c.starts_with("open")), "the device was not asked");
    assert_eq!(memobj_describe_ref(c.arena.1).map(|d| d.page_count), Ok(1));
    // The objects.
    let p = params(DIR_PLAYBACK);
    let (r, d, a) = c.handles();
    let attenuated = |reg: (u32, u32), perms| azos_ipc::cap::objref::grant_packed::<azos_ipc::cap::targets::Shm>(c.tid, perms, reg.1).expect("a handle").raw().0;
    let no_read = WireCap::from_raw(attenuated(c.ready, CapPerms::WRITE));
    let no_write = WireCap::from_raw(attenuated(c.done, CapPerms::READ));
    let arena_w = WireCap::from_raw(attenuated(c.arena, CapPerms::WRITE));
    let mut s = c.sv();
    assert_eq!(s.open(p, no_read, d, a, 0).code, outcome::DENIED, "the server reads `ready`");
    assert_eq!(s.open(p, r, no_write, a, 0).code, outcome::DENIED, "the server writes `done`");
    assert_eq!(s.open(p, r, d, arena_w, 0).code, outcome::DENIED, "a playback arena is read");
    assert_eq!(s.open(p, r, r_as_done(r), a, 0).code, outcome::BAD_ARGUMENT, "one region is not both queues");
    assert_eq!(s.open(p, r, d, r_as_arena(r), 0).code, outcome::BAD_ARGUMENT, "a queue is not the arena");
    assert_eq!(s.open(p, WireCap::from_raw(0xdead), d, a, 0).code, outcome::BAD_ARGUMENT, "not a handle");
    // An arena that is not one physical run, or is too small for the geometry.
    let anon = region(c.tid, &MemSpec::anon(MemPerms::ReadWrite));
    assert_eq!(s.open(p, r, d, WireCap::from_raw(anon.0), 0).code, outcome::BAD_ARGUMENT, "not Contig");
    let big = Params { period_frames: 512, ..p };
    assert_eq!(s.open(big, r, d, a, 0).code, outcome::BAD_ARGUMENT, "16 KiB in a page");
    assert!(!calls().iter().any(|c| c.starts_with("open")), "still not asked");
    assert!(!fake().s[0].open);
}

fn r_as_done(r: WireCap<snd::ReadyQueue>) -> WireCap<snd::DoneQueue> {
    WireCap::from_raw(r.raw())
}

fn r_as_arena(r: WireCap<snd::ReadyQueue>) -> WireCap<snd::Arena> {
    WireCap::from_raw(r.raw())
}

/// A task holds one stream; a direction holds one. The arena is pinned for the
/// stream's life and let go with it.
///
/// **Canary.** Skip the `pin`: the region is gone once the client lets go of
/// its handle, and the second assertion on `memobj_describe_ref` fails.
#[test]
fn a_task_holds_one_stream_and_the_arena_stays_pinned() {
    let _g = serial();
    let c = client();
    let o = c.open(params(DIR_PLAYBACK));
    assert_eq!((o.code, o.value), (outcome::OK, snd::Opened { period_bytes: PERIOD_BYTES, latency_frames: 0 }));
    assert_eq!(calls(), vec!["open play".to_string()]);
    assert_eq!(fake().s[0].arena_phys, c.arena_phys(), "the device is given the arena's frames");
    assert_eq!(c.open(params(DIR_PLAYBACK)).code, outcome::BUSY, "a second stream on the capability");
    assert_eq!(c.open(params(DIR_CAPTURE)).code, outcome::BUSY, "a task holds one stream, whichever way");
    // The client lets go of the arena's handle: the kernel's pin keeps the frames.
    azos_ipc::cap_store::read_table(c.tid, |t| memobj_release_cap(c.tid, t, azos_ipc::cap::Cap::<azos_ipc::cap::targets::Shm>::from_raw(azos_abi::cap::CapHandle(c.arena.0))))
        .expect("a table")
        .expect("released");
    assert!(memobj_describe_ref(c.arena.1).is_ok(), "the pinned arena is still there");
    // Another task finds the direction taken.
    let other = client_in(SLOT2);
    assert_eq!(other.open(params(DIR_PLAYBACK)).code, outcome::BUSY);
    drop(other);
    azos_sched::set_current_task_tid(c.tid);
    assert_eq!(c.sv().close().code, outcome::OK);
    assert_eq!(calls().last().map(String::as_str), Some("close play"));
    assert!(memobj_describe_ref(c.arena.1).is_err(), "closed: the pin is given back and the frames freed");
    assert_eq!(c.sv().close().code, outcome::OK, "close is served when nothing is open");
}

#[test]
fn a_refusal_by_the_device_leaves_nothing_behind() {
    let _g = serial();
    let c = client();
    fake().fail_open = Some(azos_drv_virtio::virtio::snd::Error::Unsupported);
    assert_eq!(c.open(params(DIR_PLAYBACK)).code, outcome::UNSUPPORTED);
    fake().fail_open = Some(azos_drv_virtio::virtio::snd::Error::Fault);
    assert_eq!(c.open(params(DIR_PLAYBACK)).code, outcome::FAULT);
    assert_eq!(c.sv().status().value.state, snd::STATE_CLOSED);
    assert!(memobj_describe_ref(c.arena.1).is_ok());
    fake().fail_open = None;
    assert_eq!(c.open(params(DIR_PLAYBACK)).code, outcome::OK, "the direction was never taken");
    // The pin was undone by the failed opens: once the client lets go of its
    // handle, one close frees the region.
    azos_ipc::cap_store::read_table(c.tid, |t| memobj_release_cap(c.tid, t, azos_ipc::cap::Cap::<azos_ipc::cap::targets::Shm>::from_raw(azos_abi::cap::CapHandle(c.arena.0))))
        .expect("a table")
        .expect("released");
    assert!(memobj_describe_ref(c.arena.1).is_ok(), "the open stream's pin holds it");
    assert_eq!(c.sv().close().code, outcome::OK);
    assert!(memobj_describe_ref(c.arena.1).is_err());
}

// ── the periods ──────────────────────────────────────────────────────────

/// A period the client posts reaches the device with its index and frames; one
/// the client wrote wrong reaches nothing; a completed period comes back on
/// `done`; the device taking two at a time leaves the rest in `ready`.
///
/// **Canary.** Skip `Period::check` in `feed`: the out-of-range index, the
/// zero-frame period and the one with a flag are submitted.
#[test]
fn periods_flow_from_ready_to_the_device_and_back_to_done() {
    let _g = serial();
    let c = client();
    fake().room = 2;
    c.open(params(DIR_PLAYBACK));
    assert_eq!(c.sv().start().code, outcome::OK);
    assert_eq!(c.sv().status().value.state, snd::STATE_RUNNING);
    c.post(play(0, PERIOD_FRAMES));
    c.post(play(1, 30));
    // Hostile slots: past the arena, no frames, a flag, a field that does not fit.
    c.post(play(8, 10));
    c.post(play(2, 0));
    c.post(Period { index: 2, frames: 10, flags: 1, time_ns: 0 });
    c.post_raw([u64::MAX, 1, 0, 0]);
    c.post_raw([2, 10, 1 << 40, 0]);
    c.post(play(2, 20));
    c.post(play(3, 20));
    pump();
    assert_eq!(fake().s[0].submitted, vec![(0, PERIOD_FRAMES), (1, 30)], "the device takes two");
    // The hostile slots were consumed and ignored as the pump looked for room? No: it
    // stopped at the device's limit, so what is left is still queued, in order.
    fake().complete(DIR_PLAYBACK, 2, None);
    pump();
    assert_eq!(c.returned(), vec![play(0, PERIOD_FRAMES), play(1, 30)]);
    assert_eq!(fake().s[0].submitted, vec![(0, PERIOD_FRAMES), (1, 30), (2, 20), (3, 20)], "the rest, the wrong ones dropped");
    fake().complete(DIR_PLAYBACK, 2, None);
    pump();
    assert_eq!(c.returned(), vec![play(2, 20), play(3, 20)]);
}

/// A period that is in flight cannot be posted again.
#[test]
fn a_period_posted_twice_is_ignored_the_second_time() {
    let _g = serial();
    let c = client();
    c.open(params(DIR_PLAYBACK));
    c.post(play(4, 10));
    c.post(play(4, 10));
    pump();
    assert_eq!(fake().s[0].submitted, vec![(4, 10)]);
    fake().complete(DIR_PLAYBACK, 1, None);
    pump();
    assert_eq!(c.returned(), vec![play(4, 10)], "returned once");
}

/// A stop gives back everything the server holds: what the device had, then
/// what was still in `ready`, all cancelled.
///
/// **Canary.** Leave out `cancel_ready`: the two periods behind the device's
/// limit never come back.
#[test]
fn a_stop_returns_every_period_posted_cancelled() {
    let _g = serial();
    let c = client();
    fake().room = 2;
    c.open(params(DIR_PLAYBACK));
    c.sv().start();
    for i in 0..4 {
        c.post(play(i, 10));
    }
    pump();
    assert_eq!(fake().s[0].in_flight.len(), 2);
    assert_eq!(c.sv().stop().code, outcome::OK);
    let cancelled = |i| Period { index: i, frames: 0, flags: PERIOD_CANCELLED, time_ns: 0 };
    assert_eq!(c.returned(), vec![cancelled(0), cancelled(1), cancelled(2), cancelled(3)]);
    assert_eq!(c.sv().status().value.state, snd::STATE_OPEN);
    // Served when not running, and posts keep working.
    assert_eq!(c.sv().stop().code, outcome::OK);
    c.post(play(5, 10));
    pump();
    assert_eq!(fake().s[0].submitted.last(), Some(&(5, 10)));
}

/// A playback drain plays everything posted, however long it takes the device,
/// and only then stops it and returns the end marker.
///
/// **Canary.** Finish the drain when the device is idle without asking whether
/// `ready` is empty: the third period is returned unplayed.
#[test]
fn a_playback_drain_plays_everything_posted_then_ends() {
    let _g = serial();
    let c = client();
    fake().room = 2;
    c.open(params(DIR_PLAYBACK));
    c.sv().start();
    for i in 0..3 {
        c.post(play(i, 10));
    }
    assert_eq!(c.sv().drain().code, outcome::OK);
    assert_eq!(c.sv().status().value.state, snd::STATE_DRAINING);
    assert_eq!(fake().s[0].submitted.len(), 2, "the drain moves the posted periods to the device first");
    pump();
    assert!(c.returned().is_empty());
    fake().complete(DIR_PLAYBACK, 2, None);
    pump();
    assert_eq!(c.returned(), vec![play(0, 10), play(1, 10)]);
    assert_eq!(c.sv().status().value.state, snd::STATE_DRAINING, "the third is still playing");
    assert!(!calls().iter().any(|c| c == "finish_drain play"));
    fake().complete(DIR_PLAYBACK, 1, None);
    pump();
    let end = Period { index: NO_PERIOD, frames: 0, flags: PERIOD_END, time_ns: 0 };
    assert_eq!(c.returned(), vec![play(2, 10), end]);
    assert!(calls().iter().any(|c| c == "finish_drain play"));
    assert_eq!(c.sv().status().value.state, snd::STATE_OPEN);
    // A drain with nothing posted is over at the next pass.
    assert_eq!(c.sv().drain().code, outcome::OK);
    pump();
    assert_eq!(c.returned(), vec![end]);
}

/// A capture drain is over at once: the buffer being filled comes back short,
/// the rest cancelled, then the end marker.
#[test]
fn a_capture_drain_returns_the_short_period_then_the_end() {
    let _g = serial();
    let c = client();
    c.open(params(DIR_CAPTURE));
    c.sv().start();
    for i in 0..3 {
        c.post(play(i, PERIOD_FRAMES));
    }
    pump();
    fake().partial_frames = 25;
    assert_eq!(c.sv().drain().code, outcome::OK);
    let cancelled = |i| Period { index: i, frames: 0, flags: PERIOD_CANCELLED, time_ns: 0 };
    let end = Period { index: NO_PERIOD, frames: 0, flags: PERIOD_END, time_ns: 0 };
    assert_eq!(c.returned(), vec![play(0, 25), cancelled(1), cancelled(2), end]);
    assert_eq!(c.sv().status().value.state, snd::STATE_OPEN);
    // A capture post is the whole room.
    c.post(play(0, PERIOD_FRAMES - 1));
    pump();
    assert_eq!(fake().s[1].submitted.len(), 3, "the short post was dropped");
}

// ── the microphone ───────────────────────────────────────────────────────

fn capture_records() -> Vec<azos_decision::Record> {
    let mut v = Vec::new();
    azos_decision::for_each(|r| {
        if r.rule == azos_decision::Rule::AudioCapture as u8 {
            v.push(*r);
        }
    });
    v
}

/// Every capture attempt writes a decision record, admitted or refused; a
/// second capture while one is open is refused (reason 3); the first stream's
/// end frees the device.
///
/// **Canary.** Drop the `record` call: the counts do not move.
#[test]
fn a_capture_stream_is_recorded_and_held_by_one_task() {
    let _g = serial();
    let a = client();
    let before = capture_records().len();
    assert_eq!(a.open(params(DIR_CAPTURE)).code, outcome::OK);
    let recs = capture_records();
    assert_eq!(recs.len(), before + 1);
    let r = recs.last().unwrap();
    assert_eq!((r.verdict, r.subject, r.n), (azos_decision::Verdict::Admit as u8, a.tid, [0, 48_000, snd::MIC_ADMITTED as u64]));
    let b = client_in(SLOT2);
    assert_eq!(b.open(params(DIR_CAPTURE)).code, outcome::REFUSED, "another task listens");
    let r = *capture_records().last().unwrap();
    assert_eq!((r.verdict, r.subject, r.n[2]), (azos_decision::Verdict::Refuse as u8, b.tid, snd::MIC_HELD as u64));
    assert_eq!(capture_records().len(), before + 2);
    drop(b);
    azos_sched::set_current_task_tid(a.tid);
    assert_eq!(a.sv().close().code, outcome::OK);
    let b = client_in(SLOT2);
    assert_eq!(b.open(params(DIR_CAPTURE)).code, outcome::OK, "the device is free again");
}

/// The effect rule: a `mic` row at `contained` for the class withholds it.
///
/// **Canary.** Ignore the row's level: the contained row admits.
#[test]
fn the_mic_effect_is_withheld_by_a_contained_envelope_of_the_class() {
    use azos_topology::{EffectKind, EnvelopeSpec, Envelope, MaybeStr};
    let row = |name: &'static str, kind, class: &'static str, level| EnvelopeSpec {
        name: MaybeStr::from_bytes(name.as_bytes()),
        kind,
        class: MaybeStr::from_bytes(class.as_bytes()),
        level,
    };
    let rows = [
        row("a", EffectKind::Mic, "sandboxed", Envelope::Contained),
        row("b", EffectKind::Egress, "trusted", Envelope::Contained),
        row("c", EffectKind::Mic, "limited", Envelope::Cautious),
    ];
    let class = |c: &'static str| MaybeStr::from_bytes(c.as_bytes());
    assert!(!host::mic_admitted(&rows, &class("sandboxed")), "contained for its class");
    assert!(host::mic_admitted(&rows, &class("trusted")), "another kind's row says nothing of the microphone");
    assert!(host::mic_admitted(&rows, &class("limited")), "only `contained` withholds it");
    assert!(host::mic_admitted(&rows, &class("anything else")), "a class with no row has the effect");
    assert!(host::mic_admitted(&[], &class("sandboxed")));
}

/// A server in front of the device (the audio server) opens a capture stream for
/// a client by naming the call it is serving: the client's class decides the
/// effect and the client is the subject of the record, whatever the server's
/// class is. Two clients, one with the effect and one without, through one
/// server whose own class has it.
///
/// **Canary.** Decide on the caller (`mic_effect(who.tid)`) instead of the
/// requester: the client without the effect is admitted.
#[test]
fn a_server_opens_capture_for_its_client_and_the_clients_effect_decides() {
    let _g = serial();
    let srv = client();
    let (with, without) = (0x7e65_0001u32, 0x7e65_0002u32);
    azos_ipc::fastcall::shim_serve(0x11, srv.tid, with);
    azos_ipc::fastcall::shim_serve(0x22, srv.tid, without);
    host::withhold_mic(without);
    let before = capture_records().len();

    assert_eq!(srv.open_for(params(DIR_CAPTURE), 0x22).code, outcome::REFUSED, "the client without the effect");
    let recs = capture_records();
    assert_eq!(recs.len(), before + 1, "the refusal leaves a record");
    let r = *recs.last().unwrap();
    assert_eq!(
        (r.verdict, r.subject, r.n[2]),
        (azos_decision::Verdict::Refuse as u8, without, snd::MIC_NO_GRANT as u64),
        "it names the client, not the server"
    );
    assert!(!calls().iter().any(|c| c.starts_with("open")), "the device was never asked");

    assert_eq!(srv.open_for(params(DIR_CAPTURE), 0x11).code, outcome::OK, "the client with the effect");
    let r = *capture_records().last().unwrap();
    assert_eq!((r.verdict, r.subject, r.n[2]), (azos_decision::Verdict::Admit as u8, with, snd::MIC_ADMITTED as u64));
    assert_ne!(r.subject, srv.tid, "the server is never the subject");
    // The stream is the server's thread's to run and end; the client is who it is for.
    assert_eq!(srv.sv().status().code, outcome::OK);
    assert_eq!(srv.sv().close().code, outcome::OK);
}

/// The warrant a server names must be one it holds: a call another task is
/// serving, a call already answered and a made-up handle name nobody, and the
/// attempt is recorded against the caller.
///
/// **Canary.** Fall back to the caller when the call does not resolve
/// (`None => capture_reason(mic_effect(who.tid), ..)`): every row admits.
#[test]
fn a_call_the_caller_is_not_serving_names_no_requester() {
    let _g = serial();
    let srv = client();
    azos_ipc::fastcall::shim_serve(0x33, srv.tid + 1000, 0x7e65_0003);
    let before = capture_records().len();
    for (what, call) in [("another server's call", 0x33u64), ("a made-up handle", 0xdead_beef)] {
        assert_eq!(srv.open_for(params(DIR_CAPTURE), call).code, outcome::REFUSED, "{what}");
        let r = *capture_records().last().unwrap();
        assert_eq!(
            (r.verdict, r.subject, r.n[2]),
            (azos_decision::Verdict::Refuse as u8, srv.tid, snd::MIC_NO_REQUEST as u64),
            "{what}: recorded against the caller"
        );
    }
    assert_eq!(capture_records().len(), before + 2);
    // Answered: nothing is left to lend.
    azos_ipc::fastcall::shim_serve(0x44, srv.tid, 0x7e65_0004);
    azos_ipc::fastcall::shim_answer_all();
    assert_eq!(srv.open_for(params(DIR_CAPTURE), 0x44).code, outcome::REFUSED, "an answered call");
    // And the device was not touched by any of them.
    assert!(!calls().iter().any(|c| c.starts_with("open")));
}

/// A playback stream is nobody's authority to lend: naming a call is a bad
/// argument, and a capture open naming none asks for the caller itself.
///
/// **Canary.** Drop the `d == PLAY` check: the playback open succeeds.
#[test]
fn playback_names_no_call() {
    let _g = serial();
    let c = client();
    azos_ipc::fastcall::shim_serve(0x55, c.tid, 0x7e65_0005);
    assert_eq!(c.open_for(params(DIR_PLAYBACK), 0x55).code, outcome::BAD_ARGUMENT);
    assert_eq!(c.open_for(params(DIR_PLAYBACK), 0).code, outcome::OK);
}

// ── exit ─────────────────────────────────────────────────────────────────

/// A task's exit ends its stream: the pump, not the exit hook, talks to the
/// device. Until the pump runs the direction is still taken.
#[test]
fn the_exit_of_the_holder_ends_its_stream() {
    let _g = serial();
    let c = client();
    c.open(params(DIR_PLAYBACK));
    c.sv().start();
    c.post(play(0, 10));
    pump();
    host::release_all(c.tid);
    assert!(!calls().iter().any(|c| c == "close play"), "the exit hook did not wait for the device");
    pump();
    assert_eq!(calls().last().map(String::as_str), Some("close play"));
    assert!(!fake().s[0].open);
    assert!(memobj_describe_ref(c.arena.1).is_err() || azos_ipc::memobj::memobj_release_all(c.tid) == (), "the pin went with the stream");
    let other = client_in(SLOT2);
    assert_eq!(other.open(params(DIR_PLAYBACK)).code, outcome::OK, "the direction is free");
    // A task that holds no stream leaves the others alone.
    host::release_all(0xdead);
    pump();
    assert!(fake().s[0].open);
}

/// A queue whose region is gone ends the stream.
#[test]
fn a_stream_whose_queue_is_gone_is_closed() {
    let _g = serial();
    let c = client();
    c.open(params(DIR_PLAYBACK));
    c.post(play(0, 10));
    azos_ipc::cap_store::read_table(c.tid, |t| memobj_release_cap(c.tid, t, azos_ipc::cap::Cap::<azos_ipc::cap::targets::Shm>::from_raw(azos_abi::cap::CapHandle(c.ready.0))))
        .expect("a table")
        .expect("released");
    pump();
    assert!(!fake().s[0].open, "the pump found `ready` gone and closed the stream");
    assert_eq!(c.sv().status().value.state, snd::STATE_CLOSED);
}

// ── the wire ─────────────────────────────────────────────────────────────

/// Through `khost::serve`: `Sound` is one of the interfaces whose requests may
/// carry capability entries (`open` takes three); an `info` request answers its
/// six words; a request with the wrong badge answers the server's refusal in
/// the outcome word.
#[test]
fn the_wire_form_round_trips_through_khost() {
    let _g = serial();
    let c = client();
    assert!(crate::khost::takes_caps(key::SOUND));
    let who = Caller { tid: c.tid, badge: snd::device_badge(0), rights: CapPerms::RW };
    let ask = |who: &Caller| {
        let mut req = MsgDesc { version: MSG_VERSION, ..MsgDesc::default() };
        {
            let mut w = Writer::new(&mut req);
            w.word(header(SoundIdl::ID, SoundIdl::LEVEL, SoundIdl::OP_INFO));
            w.finish();
        }
        let mut rep = MsgDesc::default();
        crate::khost::serve(key::SOUND, who, &req, &mut rep);
        rep
    };
    let rep = ask(&who);
    assert_eq!(rep.words[0], azos_idl::STATUS_OK);
    assert_eq!(rep.words[1] as u32, outcome::OK);
    assert_eq!(&rep.words[2..8], &[(DIR_PLAYBACK | DIR_CAPTURE) as u64, (snd::format_bit(FMT_S16) | snd::format_bit(snd::FMT_F32)) as u64, 48_000, 2, snd::PERIOD_FRAMES_MIN as u64, snd::PERIOD_FRAMES_MAX as u64]);
    let rep = ask(&Caller { badge: 9, ..who });
    assert_eq!((rep.words[0], rep.words[1] as u32), (azos_idl::STATUS_OK, outcome::NO_RESOURCE));
}

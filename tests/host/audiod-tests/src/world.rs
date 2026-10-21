// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The world the audio server runs in on the host: memory on the heap, a
//! clock the test moves, a fake `sound.0` that plays the periods it is given
//! and returns them, and a fake microphone gate that decides as the kernel's
//! does: on the task that made the call the server names, never on the server.

use crate::server::{DevMem, Env, Limits, Mapped, Server};
use azos_devif::outcome;
use azos_devif::sound::{
    self as snd, Info, Opened, Params, Period, Status, DIR_CAPTURE, DIR_PLAYBACK, FMT_S16, NO_PERIOD, PERIOD_END, SLOT_WORDS,
};
use azos_idl::Cap;
use azos_rings::region::{RingStep, SpscSlots};
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

#[repr(C, align(64))]
#[derive(Clone, Copy)]
struct Chunk([u8; 64]);

/// A zeroed, 64-byte aligned region that does not move.
pub struct Mem {
    v: Vec<Chunk>,
    bytes: usize,
}

impl Mem {
    pub fn new(bytes: usize) -> Mem {
        Mem { v: vec![Chunk([0; 64]); bytes.div_ceil(64)], bytes }
    }
    pub fn va(&self) -> usize {
        self.v.as_ptr() as usize
    }
    pub fn bytes(&self) -> usize {
        self.bytes
    }
}

/// The device the fake `sound.0` models: 48 kHz, stereo, signed 16-bit.
pub fn device_info() -> Info {
    Info {
        dirs: DIR_PLAYBACK | DIR_CAPTURE,
        formats: snd::format_bit(FMT_S16) | snd::format_bit(snd::FMT_F32),
        rate_hz: 48_000,
        channels: 2,
        period_frames_min: 64,
        period_frames_max: 4096,
    }
}

/// The task id of the audio server in the fake kernel: the one caller the
/// kernel hears from.
pub const SERVER_TID: u32 = 1;

/// The task id of the client that holds badge `badge`: one task per badge.
pub const fn client_tid(badge: u32) -> u32 {
    1000 + badge
}

#[derive(Default)]
pub struct World {
    pub now: u64,
    mems: HashMap<u32, Mem>,
    /// Capabilities whose object is read-only.
    pub read_only: Vec<u32>,
    /// Capabilities the server let go of, in order.
    pub released: Vec<u32>,
    pub woken: usize,
    pub logs: Vec<String>,
    // The device.
    pub info_calls: u32,
    pub device_fails_open: bool,
    pub dev_open: Option<DevState>,
    pub dev_opens: u32,
    pub dev_closes: u32,
    /// Everything the device played, as interleaved samples.
    pub played: Vec<i16>,
    /// Periods the device played, with the flags it returned.
    pub dev_periods: u32,
    // The microphone gate. `served` is the calls the server has accepted and
    // not answered, by warrant, with the task that made each (what the kernel
    // knows and ring 3 does not); `withheld` the tasks whose class has no `mic`
    // effect. The server's own task, `SERVER_TID`, is never withheld: its class
    // holds the effect, as it did when the server was the authority, so a
    // client refused here is refused on its own account. `gate` is the decision
    // record of every attempt that reached it: `(subject, admitted, reason)`.
    pub served: HashMap<u64, u32>,
    pub withheld: Vec<u32>,
    pub gate: Vec<(u32, bool, u32)>,
    pub lease_calls: Vec<&'static str>,
    pub lease_open_calls: u32,
    pub lease_status: Status,
    pub lease_active: bool,
}

pub struct DevState {
    pub ready: SpscSlots<{ SLOT_WORDS }>,
    pub done: SpscSlots<{ SLOT_WORDS }>,
    pub arena: usize,
    pub geo: snd::Geometry,
    pub started: bool,
    pub draining: bool,
    mem: [Mem; 3],
}

impl World {
    pub fn add(&mut self, cap: u32, bytes: usize) -> usize {
        let m = Mem::new(bytes);
        let va = m.va();
        self.mems.insert(cap, m);
        va
    }

    /// The device plays every period posted to it, in order, returning each
    /// on `done`; after a drain it returns the end marker.
    pub fn device_cycle(&mut self) {
        let Some(d) = self.dev_open.as_mut() else { return };
        if !d.started && !d.draining {
            return;
        }
        loop {
            let mut w = [0u64; SLOT_WORDS];
            if d.ready.try_pop(&mut w) == RingStep::Blocked {
                break;
            }
            let p = Period::from_slot(&w).expect("the server posted a valid slot");
            assert!(p.index < d.geo.periods, "an index inside the arena");
            assert_eq!(p.frames, d.geo.period_frames, "whole periods");
            // SAFETY: the arena is a live heap region of `arena_bytes`.
            let bytes = unsafe {
                std::slice::from_raw_parts((d.arena + p.index as usize * d.geo.period_bytes as usize) as *const u8, d.geo.period_bytes as usize)
            };
            self.played.extend(bytes.chunks_exact(2).map(|c| i16::from_le_bytes([c[0], c[1]])));
            self.dev_periods += 1;
            let _ = d.done.try_push(&Period { index: p.index, frames: p.frames, flags: 0, time_ns: self.now }.to_slot());
        }
        if d.draining {
            let end = Period { index: NO_PERIOD, frames: 0, flags: PERIOD_END, time_ns: 0 };
            let _ = d.done.try_push(&end.to_slot());
            d.draining = false;
        }
    }

    /// Samples the device played since the last call.
    pub fn take_played(&mut self) -> Vec<i16> {
        std::mem::take(&mut self.played)
    }
}

#[derive(Clone)]
pub struct Fake(pub Rc<RefCell<World>>);

impl Env for Fake {
    fn now_ns(&mut self) -> u64 {
        self.0.borrow().now
    }
    fn map(&mut self, cap: u32) -> Option<Mapped> {
        let w = self.0.borrow();
        let m = w.mems.get(&cap)?;
        Some(Mapped { va: m.va(), bytes: m.bytes(), rw: !w.read_only.contains(&cap) })
    }
    fn release(&mut self, cap: u32) {
        self.0.borrow_mut().released.push(cap);
    }
    fn wake(&mut self, _addr: usize) {
        self.0.borrow_mut().woken += 1;
    }
    fn log(&mut self, line: &[u8]) {
        self.0.borrow_mut().logs.push(String::from_utf8_lossy(line).into_owned());
    }
    fn dev_info(&mut self) -> Result<Info, u32> {
        self.0.borrow_mut().info_calls += 1;
        Ok(device_info())
    }
    fn dev_open(&mut self, params: Params) -> Result<DevMem, u32> {
        let mut w = self.0.borrow_mut();
        if w.device_fails_open {
            return Err(outcome::BUSY);
        }
        assert_eq!((params.dir, params.format, params.rate_hz, params.channels), (DIR_PLAYBACK, FMT_S16, 48_000, 2));
        let geo = params.check().expect("the server asks the device for a valid stream");
        let slots = crate::server::slots_for(4096).unwrap();
        let (r, d, a) = (Mem::new(4096), Mem::new(4096), Mem::new(geo.arena_bytes as usize));
        let (ready, done) = (SpscSlots { base: r.va(), cap: slots }, SpscSlots { base: d.va(), cap: slots });
        ready.init();
        done.init();
        let arena = a.va();
        w.dev_opens += 1;
        w.dev_open = Some(DevState { ready, done, arena, geo, started: false, draining: false, mem: [r, d, a] });
        Ok(DevMem { ready, done, arena, geo })
    }
    fn dev_start(&mut self) -> Result<(), u32> {
        self.0.borrow_mut().dev_open.as_mut().expect("opened first").started = true;
        Ok(())
    }
    fn dev_drain(&mut self) -> Result<(), u32> {
        let mut w = self.0.borrow_mut();
        let d = w.dev_open.as_mut().expect("opened first");
        d.draining = true;
        Ok(())
    }
    fn dev_close(&mut self) {
        let mut w = self.0.borrow_mut();
        let d = w.dev_open.take().expect("closed once, after it opened");
        let _ = &d.mem;
        w.dev_closes += 1;
    }
    fn lease_open(&mut self, params: Params, _ready: u32, _done: u32, _arena: u32, on_behalf: u64) -> Result<Opened, u32> {
        let mut w = self.0.borrow_mut();
        w.lease_open_calls += 1;
        // The kernel's gate, with its own rules (`azos_devif::sound`): whose
        // effect, then why not, then the record; a refusal is `REFUSED`.
        let subject = snd::capture_subject(SERVER_TID, on_behalf, |call| w.served.get(&call).copied());
        let reason = match subject {
            Some(t) => snd::capture_reason(!w.withheld.contains(&t), true, w.lease_active),
            None => snd::MIC_NO_REQUEST,
        };
        let admitted = reason == snd::MIC_ADMITTED;
        w.gate.push((subject.unwrap_or(SERVER_TID), admitted, reason));
        if !admitted {
            return Err(outcome::REFUSED);
        }
        let geo = params.check()?;
        w.lease_active = true;
        w.lease_calls.push("open");
        Ok(Opened { period_bytes: geo.period_bytes, latency_frames: 0 })
    }
    fn lease_start(&mut self) -> Result<(), u32> {
        self.0.borrow_mut().lease_calls.push("start");
        Ok(())
    }
    fn lease_stop(&mut self) -> Result<(), u32> {
        self.0.borrow_mut().lease_calls.push("stop");
        Ok(())
    }
    fn lease_drain(&mut self) -> Result<(), u32> {
        self.0.borrow_mut().lease_calls.push("drain");
        Ok(())
    }
    fn lease_close(&mut self) -> Result<(), u32> {
        let mut w = self.0.borrow_mut();
        w.lease_calls.push("close");
        w.lease_active = false;
        Ok(())
    }
    fn lease_status(&mut self) -> Result<Status, u32> {
        Ok(self.0.borrow().lease_status)
    }
}

pub fn limits() -> Limits {
    Limits { max_streams: 4, max_periods: 16, arena_bytes_max: 256 * 1024, capture: true }
}

pub fn server() -> (Server<Fake>, Rc<RefCell<World>>) {
    server_with(limits())
}

pub fn server_with(l: Limits) -> (Server<Fake>, Rc<RefCell<World>>) {
    let w = Rc::new(RefCell::new(World::default()));
    (Server::new(Fake(w.clone()), l), w)
}

/// The stream a client asks for: the device's rate and channels, 256-frame
/// periods, four of them.
pub fn params() -> Params {
    Params { dir: DIR_PLAYBACK, format: FMT_S16, rate_hz: 48_000, channels: 2, period_frames: 256, periods: 4 }
}

/// A client's side of one stream: the objects it made and moved.
pub struct Client {
    pub caps: [u32; 3],
    pub ready: SpscSlots<{ SLOT_WORDS }>,
    pub done: SpscSlots<{ SLOT_WORDS }>,
    pub arena: usize,
    pub geo: snd::Geometry,
    pub badge: u32,
}

impl Client {
    pub fn new(w: &Rc<RefCell<World>>, badge: u32, caps: [u32; 3], p: &Params) -> Client {
        let geo = p.check().unwrap();
        let mut wm = w.borrow_mut();
        let (rv, dv) = (wm.add(caps[0], 4096), wm.add(caps[1], 4096));
        let av = wm.add(caps[2], geo.arena_bytes as usize);
        let slots = crate::server::slots_for(4096).unwrap();
        let c = Client {
            caps,
            ready: SpscSlots { base: rv, cap: slots },
            done: SpscSlots { base: dv, cap: slots },
            arena: av,
            geo,
            badge,
        };
        c.ready.init();
        c.done.init();
        c
    }

    /// Fill period `index` with `frames` frames of `value` on every channel
    /// and post it.
    pub fn post(&self, index: u32, frames: u32, value: i16) -> bool {
        let ch = self.geo.frame_bytes as usize / 2;
        // SAFETY: the arena is a live heap region of `arena_bytes`; `index` is
        // below `periods` for every honest caller.
        let out = unsafe {
            std::slice::from_raw_parts_mut((self.arena + index as usize * self.geo.period_bytes as usize) as *mut u8, self.geo.period_bytes as usize)
        };
        for s in out.chunks_exact_mut(2).take(frames as usize * ch) {
            s.copy_from_slice(&value.to_le_bytes());
        }
        self.post_raw(Period { index, frames, flags: 0, time_ns: 0 }.to_slot())
    }

    pub fn post_raw(&self, slot: [u64; SLOT_WORDS]) -> bool {
        !matches!(self.ready.try_push(&slot), RingStep::Blocked)
    }

    /// Everything the server returned.
    pub fn returned(&self) -> Vec<Period> {
        let mut v = Vec::new();
        loop {
            let mut w = [0u64; SLOT_WORDS];
            if self.done.try_pop(&mut w) == RingStep::Blocked {
                return v;
            }
            v.push(Period::from_slot(&w).expect("the server wrote a valid slot"));
        }
    }

    pub fn open(&self, srv: &mut Server<Fake>, p: Params) -> azos_devif::Out<Opened> {
        self.open_naming(srv, p, 0)
    }

    /// `open` with the client's own `on_behalf` word, which an honest client
    /// leaves 0. While the call is served the kernel knows its maker.
    pub fn open_naming(&self, srv: &mut Server<Fake>, p: Params, on_behalf: u64) -> azos_devif::Out<Opened> {
        use azos_devif::Sound;
        srv.caller = self.badge;
        srv.call = self.call();
        srv.env.0.borrow_mut().served.insert(srv.call, client_tid(self.badge));
        srv.prepare();
        let r = srv.open(p, Cap::from_raw(self.caps[0]), Cap::from_raw(self.caps[1]), Cap::from_raw(self.caps[2]), on_behalf);
        srv.env.0.borrow_mut().served.remove(&srv.call);
        srv.caller = 0;
        srv.call = 0;
        r
    }

    /// The warrant of this client's call to the server.
    pub fn call(&self) -> u64 {
        Self::call_of(self.badge)
    }

    /// The warrant of the call of the client that holds badge `badge`.
    pub const fn call_of(badge: u32) -> u64 {
        0xCA11_0000 + badge as u64
    }
}

/// Make a call as `badge`.
pub fn call<R>(srv: &mut Server<Fake>, badge: u32, f: impl FnOnce(&mut Server<Fake>) -> R) -> R {
    srv.caller = badge;
    srv.prepare();
    let r = f(srv);
    srv.caller = 0;
    r
}

/// Run the pump `n` times, the device playing between passes, `ms`
/// milliseconds apart.
pub fn pump(srv: &mut Server<Fake>, w: &Rc<RefCell<World>>, n: usize, ms: u64) {
    for _ in 0..n {
        w.borrow_mut().now += ms * 1_000_000;
        srv.tick();
        w.borrow_mut().device_cycle();
    }
}

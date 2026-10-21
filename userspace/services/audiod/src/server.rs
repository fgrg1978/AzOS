// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The audio server's decisions: the `Sound` interface (`azos_devif::sound`)
//! served on `endpoint.audio`, in front of the kernel's `sound.0`.
//!
//! No system call is made here. Everything the server needs of the world is
//! the [`Env`] trait (`main.rs` implements it over the kernel; the host test
//! `tests/host/audiod-tests` implements it over a heap and a fake device), and
//! this file is pulled into that test with `#[path]`, so the code under test
//! is the code `AUDIOD.ELF` is built from.
//!
//! # Playback: mixed into one device stream
//!
//! A client opens a stream on the server's endpoint exactly as it would on the
//! kernel's (`Sound::open` with a `ready` queue, a `done` queue and an arena it
//! made); the three objects are **moved** to the server, which maps them. The
//! client's periods never cross a call: the server pops them from `ready`,
//! mixes them ([`mixer`]) into the periods of the **one** playback stream it
//! holds on the device, and returns each, played, on `done`.
//!
//! * **Rate, channels and format are the device's.** A stream names the
//!   device's rate and channel count and signed 16-bit samples, or `open`
//!   answers `UNSUPPORTED`. Nothing is converted: a server that resampled
//!   would hide the cost of the conversion from the client that causes it.
//! * **The mix saturates** and each live stream is mixed at the gain
//!   [`mixer::headroom_gain`] gives for the number of live streams.
//! * **An underrun of one stream is its own**: it contributes silence for the
//!   rest of the pass, its next returned period carries `PERIOD_XRUN`, and the
//!   device and the other streams are untouched.
//! * **A client's period is not a device period.** The server consumes each
//!   client period frame by frame across the device's periods, whatever length
//!   the client chose.
//!
//! The device stream is opened when a stream first runs and drained and closed
//! when none does ([`Server::tick`]): a stream that starts while the device
//! drains waits for the drain to end, then the device is opened again.
//!
//! # Who a stream belongs to
//!
//! A call on this endpoint carries the **badge** of the capability it went
//! through, and the badge is the only identity the server has (the kernel does
//! not tell a ring-3 server which task called). One badge is one stream: a
//! client derives a badged copy of its endpoint capability (`cap_derive`) and
//! makes every call through it. A call with badge 0 is unidentified and is
//! refused (`DENIED`). The badge is chosen by the holder, so two cooperating
//! clients are told apart and two hostile ones are not (a client that learns
//! another's badge can stop its stream): the audio endpoint is for the
//! principals a row trusts to share a speaker.
//!
//! A stream whose client died is found by what it does not do: a running
//! stream that gives the mixer nothing for [`STALL_NS`] is closed, and a
//! stream that is not running and has not been called for [`IDLE_NS`] is.
//!
//! # Capture is lent, never mixed
//!
//! A capture stream is an irreversible effect on the person in the room, so
//! the server has no policy of its own to get wrong: the client's three
//! objects are handed to the kernel's `sound.0` **as they are** (the kernel
//! resolves the client's queues and arena in place; nothing is copied through
//! this task), and the kernel's gate answers. The gate is the `mic` effect of
//! this server's scheduler class, plus Kconfig `AUDIO_CAPTURE` and the
//! microphone indicator, and it writes the `audio-capture` decision record
//! for **every attempt**, admitted or refused: ring 3 has no way to write one.
//! `REFUSED` is passed to the client unchanged, and nothing about the server
//! changes: the three objects are released, no lease is taken. At most one
//! capture stream exists (the kernel's rule: one stream per direction).
//!
//! The kernel binds a stream to the **thread** that opened it, and gives the
//! `mic` effect only to a thread seeded from a topology row, which the pump
//! thread is not: so every capture call is made by the main thread (the one
//! that serves the endpoint), and the playback mix by the pump thread. The two
//! therefore coexist.
//!
//! Known limits, both of the same cause (ring 3 has no way to ask who called
//! or to write a decision):
//!
//! * the `mic` effect that is checked is the **server's**, not the client's
//!   class's; a deployment that must tell clients apart on the microphone
//!   gives only those clients the endpoint;
//! * a lease whose client stopped posting room (the device's xruns grow by
//!   [`LEASE_STALL_XRUNS`] between two looks, [`LEASE_POLL_NS`] apart) is
//!   closed, but only when a call next reaches the server: the main thread
//!   sleeps in `accept`, and the kernel ends a stream when its thread exits,
//!   not when the client does.

use crate::mixer::{self, ACC_MAX};
use azos_devif::outcome;
use azos_devif::sound::{
    self as snd, Info, Opened, Params, Period, Posted, Status, DIR_CAPTURE, DIR_PLAYBACK, FMT_S16, NO_PERIOD,
    PERIOD_CANCELLED, PERIOD_END, PERIOD_XRUN, SLOT_WORDS, STATE_DRAINING, STATE_OPEN, STATE_RUNNING,
};
use azos_devif::{Cap as WireCap, Out};
use azos_rings::region::{RingStep, SpscSlots, RING_SLOTS};

/// Streams the table can hold, whatever Kconfig `AUDIO_MAX_STREAMS` allows.
pub const STREAMS_MAX: usize = 32;
/// Frames of one device period the server asks for (21 ms at 48 kHz).
pub const DEV_PERIOD_FRAMES: u32 = 1024;
/// Periods in the device stream's arena.
pub const DEV_PERIODS: u32 = 4;
/// Device periods mixed ahead of the one playing: the delay a stream that
/// starts late sees.
pub const DEV_AHEAD: u32 = 2;
/// A running stream that gave the mixer nothing for this long is closed (ns).
pub const STALL_NS: u64 = 3_000_000_000;
/// A stream that is not running and was not called for this long is closed (ns).
pub const IDLE_NS: u64 = 60_000_000_000;
/// A device drain that has not ended after this long is cut short (ns).
pub const DRAIN_NS: u64 = 1_000_000_000;
/// After a failed open of the device, the next try is this long after (ns).
pub const RETRY_NS: u64 = 1_000_000_000;
/// The capture lease is looked at this often (ns).
pub const LEASE_POLL_NS: u64 = 500_000_000;
/// A capture lease whose device xruns grew by this many between two looks has
/// a client that is not posting room: it is closed.
pub const LEASE_STALL_XRUNS: u32 = 256;

/// What a mapped memory object is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Mapped {
    pub va: usize,
    pub bytes: usize,
}

/// The device's playback stream as the server made it: the two queues and the
/// arena, mapped here, and the geometry the device agreed to.
#[derive(Clone, Copy)]
pub struct DevMem {
    pub ready: SpscSlots<SLOT_WORDS>,
    pub done: SpscSlots<SLOT_WORDS>,
    pub arena: usize,
    pub geo: snd::Geometry,
}

/// What the server asks of the world.
pub trait Env {
    /// The monotonic clock, ns.
    fn now_ns(&mut self) -> u64;
    /// Map the memory object behind a capability this task holds (read-write).
    fn map(&mut self, cap: u32) -> Option<Mapped>;
    /// Unmap the object behind `cap` and let go of the capability. Called for
    /// a capability that was never mapped too (a refused `open`'s objects).
    fn release(&mut self, cap: u32);
    /// Wake the sleeper on the ring index word at `addr`.
    fn wake(&mut self, addr: usize);
    /// One line for the console.
    fn log(&mut self, line: &[u8]);
    /// What the device behind `sound.0` can do.
    fn dev_info(&mut self) -> Result<Info, u32>;
    /// Make the three objects and open the device's playback stream with
    /// `params`; the stream is `OPEN`.
    fn dev_open(&mut self, params: Params) -> Result<DevMem, u32>;
    /// Start the device's playback stream.
    fn dev_start(&mut self) -> Result<(), u32>;
    /// Drain it: the posted periods play, then the end marker comes.
    fn dev_drain(&mut self) -> Result<(), u32>;
    /// Close it and give its three objects back.
    fn dev_close(&mut self);
    /// Hand the client's three objects to the device as a capture stream.
    /// They are resolved in this task's table; `Ok` leaves them there.
    fn lease_open(&mut self, params: Params, ready: u32, done: u32, arena: u32) -> Result<Opened, u32>;
    fn lease_start(&mut self) -> Result<(), u32>;
    fn lease_stop(&mut self) -> Result<(), u32>;
    fn lease_drain(&mut self) -> Result<(), u32>;
    fn lease_close(&mut self) -> Result<(), u32>;
    fn lease_status(&mut self) -> Result<Status, u32>;
}

/// The bounds a build lets the server accept (Kconfig `AUDIO_*`).
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub max_streams: usize,
    pub max_periods: u32,
    pub arena_bytes_max: u64,
    pub capture: bool,
}

/// The slots of a ring in a region of `bytes` bytes: the most a power of two
/// the region holds after the 256-byte header. The same rule as the kernel's
/// and the client's, so the three agree on where the ring wraps. `None` below
/// two slots.
pub fn slots_for(bytes: usize) -> Option<u32> {
    let room = bytes.checked_sub(RING_SLOTS)? / (SLOT_WORDS * 8);
    if room < 2 {
        return None;
    }
    Some(1u32 << (usize::BITS - 1 - room.leading_zeros()).min(31))
}

/// The period being consumed.
#[derive(Clone, Copy)]
struct Cur {
    index: u32,
    frames: u32,
    pos: u32,
}

/// A client's playback stream.
struct Stream {
    badge: u32,
    geo: snd::Geometry,
    caps: [u32; 3],
    ready: SpscSlots<SLOT_WORDS>,
    done: SpscSlots<SLOT_WORDS>,
    arena: usize,
    state: u32,
    cur: Option<Cur>,
    gain: u32,
    /// The next period returned carries `PERIOD_XRUN`.
    xrun_owed: bool,
    xruns: u32,
    /// Frames mixed since `open`.
    frames: u64,
    /// The end marker `done` had no room for.
    end_owed: bool,
    /// Last time a call touched the stream, or it last gave the mixer data.
    active_ns: u64,
}

impl Stream {
    fn running(&self) -> bool {
        self.state == STATE_RUNNING || self.state == STATE_DRAINING
    }

    /// Return a period to the client.
    fn give<E: Env>(&mut self, env: &mut E, p: Period) {
        match self.done.try_push(&p.to_slot()) {
            // The client is not reading `done`: the period is lost to it.
            RingStep::Blocked => {}
            RingStep::DoneWake { addr } => env.wake(addr),
            RingStep::Done => {}
        }
    }

    /// The end marker, once; owed again when `done` is full.
    fn give_end<E: Env>(&mut self, env: &mut E) {
        let end = Period { index: NO_PERIOD, frames: 0, flags: PERIOD_END, time_ns: 0 };
        match self.done.try_push(&end.to_slot()) {
            RingStep::Blocked => self.end_owed = true,
            RingStep::DoneWake { addr } => {
                self.end_owed = false;
                env.wake(addr);
            }
            RingStep::Done => self.end_owed = false,
        }
    }

    /// The oldest valid period the client posted. A slot it wrote wrong is
    /// consumed and ignored: it names nothing the server holds. The server
    /// holds one period of a stream at a time (`cur`), so a period posted
    /// twice is played twice, once the first has been returned: the client
    /// lied about what it owned, to its own stream only.
    fn next_posted<E: Env>(&mut self, env: &mut E) -> Option<Cur> {
        for _ in 0..self.geo.queue_slots {
            let mut w = [0u64; SLOT_WORDS];
            match self.ready.try_pop(&mut w) {
                RingStep::Blocked => return None,
                RingStep::DoneWake { addr } => env.wake(addr),
                RingStep::Done => {}
            }
            let Some(p) = Period::from_slot(&w) else { continue };
            if p.check(&self.geo, DIR_PLAYBACK).is_err() {
                continue;
            }
            return Some(Cur { index: p.index, frames: p.frames, pos: 0 });
        }
        None
    }

    /// Mix up to `frames` frames of this stream into `acc` (`channels`
    /// samples a frame). The frames it had; the rest of the pass is silence
    /// from this stream.
    fn pull<E: Env>(&mut self, env: &mut E, acc: &mut [i32], frames: u32, channels: usize) -> u32 {
        let fb = self.geo.frame_bytes as usize;
        let mut at = 0u32;
        while at < frames {
            if self.cur.is_none() {
                self.cur = self.next_posted(env);
            }
            let Some(c) = self.cur else { break };
            let take = (frames - at).min(c.frames - c.pos);
            let off = c.index as usize * self.geo.period_bytes as usize + c.pos as usize * fb;
            // SAFETY: `c.index` is below `periods` (`Period::check`), `c.pos +
            // take` is within the period's `frames`, which are within
            // `period_frames`, and `open` mapped an arena of at least
            // `arena_bytes`. The memory is the client's, shared with it: a
            // sample it changes while this reads is a torn sample, not a
            // fault.
            let src = unsafe { core::slice::from_raw_parts((self.arena + off) as *const u8, take as usize * fb) };
            let lo = at as usize * channels;
            mixer::accumulate(&mut acc[lo..lo + take as usize * channels], src, self.gain);
            at += take;
            let pos = c.pos + take;
            if pos == c.frames {
                self.cur = None;
                let flags = if core::mem::take(&mut self.xrun_owed) { PERIOD_XRUN } else { 0 };
                self.give(env, Period { index: c.index, frames: c.frames, flags, time_ns: 0 });
            } else {
                self.cur = Some(Cur { pos, ..c });
            }
        }
        self.frames += u64::from(at);
        at
    }

    /// Everything the server holds of this stream goes back to the client as
    /// cancelled: the period being played (with the frames that were) and
    /// every posted one.
    fn cancel<E: Env>(&mut self, env: &mut E) {
        if let Some(c) = self.cur.take() {
            self.give(env, Period { index: c.index, frames: c.pos, flags: PERIOD_CANCELLED, time_ns: 0 });
        }
        while let Some(c) = self.next_posted(env) {
            self.give(env, Period { index: c.index, frames: 0, flags: PERIOD_CANCELLED, time_ns: 0 });
        }
    }
}

/// The capture stream lent to a client.
struct Lease {
    badge: u32,
    caps: [u32; 3],
    xruns_seen: u32,
    polled_ns: u64,
}

/// Where the device's playback stream is.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Running,
    /// Drained; the end marker is awaited until the instant.
    Draining(u64),
}

struct Dev {
    mem: DevMem,
    phase: Phase,
    /// Device periods the device holds now.
    held: Posted,
    xruns: u32,
}

/// The audio server.
pub struct Server<E: Env> {
    pub env: E,
    limits: Limits,
    /// The badge of the call being served (0: unidentified). Set by the loop
    /// before each dispatch.
    pub caller: u32,
    streams: [Option<Stream>; STREAMS_MAX],
    lease: Option<Lease>,
    lease_cache: Option<Status>,
    dev: Option<Dev>,
    info: Option<Info>,
    retry_at: u64,
    acc: [i32; ACC_MAX],
}

fn out_err<T: Default>(code: u32) -> Out<T> {
    Out::err(code)
}

impl<E: Env> Server<E> {
    pub fn new(env: E, limits: Limits) -> Server<E> {
        Server {
            env,
            limits,
            caller: 0,
            streams: [const { None }; STREAMS_MAX],
            lease: None,
            lease_cache: None,
            dev: None,
            info: None,
            retry_at: 0,
            acc: [0; ACC_MAX],
        }
    }

    /// Streams open (playback), and the capture lease counted as one.
    #[cfg(test)]
    pub fn open_streams(&self) -> usize {
        self.streams.iter().flatten().count() + self.lease.is_some() as usize
    }

    /// Streams that are mixing now.
    pub fn live_streams(&self) -> usize {
        self.streams.iter().flatten().filter(|s| s.running()).count()
    }

    /// Is the device's playback stream open?
    #[cfg(test)]
    pub fn device_open(&self) -> bool {
        self.dev.is_some()
    }

    /// Does the server need to be looked at soon: the device stream is open,
    /// or a stream is running or waits for the device?
    pub fn busy(&self) -> bool {
        self.dev.is_some() || self.live_streams() > 0 || self.lease.is_some()
    }

    fn device_info(&mut self) -> Result<Info, u32> {
        if let Some(i) = self.info {
            return Ok(i);
        }
        let i = self.env.dev_info()?;
        self.info = Some(i);
        Ok(i)
    }

    fn slot_of(&self, badge: u32) -> Option<usize> {
        self.streams.iter().position(|s| s.as_ref().is_some_and(|s| s.badge == badge))
    }

    fn lease_of_caller(&self) -> bool {
        self.lease.as_ref().is_some_and(|l| l.badge == self.caller)
    }

    fn release_all(&mut self, caps: [u32; 3]) {
        for c in caps {
            self.env.release(c);
        }
    }

    /// The parameters of the device's playback stream: its rate and channels,
    /// signed 16-bit, a period as long as the mix pass holds.
    fn dev_params(info: &Info) -> Option<Params> {
        if info.channels == 0 || info.channels as usize > ACC_MAX {
            return None;
        }
        let max = (ACC_MAX as u32 / info.channels).min(DEV_PERIOD_FRAMES);
        let period_frames = max.min(info.period_frames_max);
        if period_frames < info.period_frames_min.max(snd::PERIOD_FRAMES_MIN) {
            return None;
        }
        let p = Params {
            dir: DIR_PLAYBACK,
            format: FMT_S16,
            rate_hz: info.rate_hz,
            channels: info.channels,
            period_frames,
            periods: DEV_PERIODS,
        };
        p.check().ok().map(|_| p)
    }

    // ── the pump ─────────────────────────────────────────────────────────

    /// One pass: close what a dead client left, then move the device stream
    /// (open it when a stream runs, mix and post periods while one does, drain
    /// and close it when none does). Call it every few milliseconds while
    /// [`busy`](Self::busy), and when a call has changed a stream.
    pub fn tick(&mut self) {
        let now = self.env.now_ns();
        self.reap_stale(now);
        let Server { env, streams, .. } = self;
        for s in streams.iter_mut().flatten().filter(|s| s.end_owed) {
            s.give_end(env);
        }
        let live = self.live_streams();
        match self.dev.as_ref().map(|d| d.phase) {
            None => {
                if live > 0 && now >= self.retry_at {
                    self.open_device(now);
                }
            }
            Some(Phase::Running) => {
                self.reap_device();
                if live == 0 {
                    self.drain_device(now);
                } else {
                    self.fill_device(live);
                }
            }
            Some(Phase::Draining(by)) => {
                let ended = self.reap_device();
                if ended || now >= by {
                    self.close_device();
                    // A stream that started while the device drained is
                    // served at once.
                    if live > 0 {
                        self.open_device(now);
                    }
                }
            }
        }
    }

    fn open_device(&mut self, now: u64) {
        let fail = |this: &mut Self, why: &[u8]| {
            this.retry_at = now.saturating_add(RETRY_NS);
            this.env.log(why);
        };
        let Ok(info) = self.device_info() else { return fail(self, b"[audiod] no sound device\n") };
        let Some(params) = Self::dev_params(&info) else { return fail(self, b"[audiod] the device runs a stream this server cannot mix\n") };
        let mem = match self.env.dev_open(params) {
            Ok(m) => m,
            Err(_) => return fail(self, b"[audiod] the device refused the playback stream\n"),
        };
        self.dev = Some(Dev { mem, phase: Phase::Running, held: Posted::new(), xruns: 0 });
        let live = self.live_streams();
        for _ in 0..DEV_AHEAD {
            self.fill_device(live);
        }
        if self.env.dev_start().is_err() {
            self.close_device();
            fail(self, b"[audiod] the device would not start\n");
        }
    }

    fn close_device(&mut self) {
        if self.dev.take().is_some() {
            self.env.dev_close();
        }
    }

    fn drain_device(&mut self, now: u64) {
        if self.env.dev_drain().is_ok() {
            if let Some(d) = self.dev.as_mut() {
                d.phase = Phase::Draining(now.saturating_add(DRAIN_NS));
            }
        } else {
            self.close_device();
        }
    }

    /// Take the periods the device returned. `true` once the end marker of a
    /// drain has come.
    fn reap_device(&mut self) -> bool {
        let Some(d) = self.dev.as_mut() else { return false };
        let mut ended = false;
        for _ in 0..DEV_PERIODS + 2 {
            let mut w = [0u64; SLOT_WORDS];
            match d.mem.done.try_pop(&mut w) {
                RingStep::Blocked => break,
                RingStep::DoneWake { addr } => self.env.wake(addr),
                RingStep::Done => {}
            }
            let Some(p) = Period::from_slot(&w) else { continue };
            if p.flags & PERIOD_END != 0 {
                ended = true;
                continue;
            }
            d.xruns += u32::from(p.flags & PERIOD_XRUN != 0);
            d.held.give_back(p.index);
        }
        ended
    }

    /// Mix periods and post them while the device has fewer than
    /// [`DEV_AHEAD`] and an arena period is free.
    fn fill_device(&mut self, live: usize) {
        while let Some(d) = self.dev.as_ref() {
            if d.held.held() >= DEV_AHEAD {
                return;
            }
            let Some(idx) = (0..d.mem.geo.periods).find(|&i| {
                let mut h = d.held;
                h.post(i)
            }) else {
                return;
            };
            let geo = d.mem.geo;
            let ch = (geo.frame_bytes / 2) as usize;
            let n = geo.period_frames as usize * ch;
            self.acc[..n].fill(0);
            let gain = mixer::headroom_gain(live);
            let now = self.env.now_ns();
            let Server { env, streams, acc, .. } = self;
            for s in streams.iter_mut().flatten() {
                if !s.running() {
                    continue;
                }
                s.gain = gain;
                let got = s.pull(env, &mut acc[..n], geo.period_frames, ch);
                if got > 0 {
                    s.active_ns = now;
                }
                if got < geo.period_frames {
                    if s.state == STATE_DRAINING && s.cur.is_none() {
                        // Everything posted has been mixed: the drain is over.
                        s.state = STATE_OPEN;
                        s.give_end(env);
                    } else {
                        s.xruns += 1;
                        s.xrun_owed = true;
                    }
                }
            }
            let d = self.dev.as_mut().expect("checked above");
            // SAFETY: `idx` is below `periods`; the device arena is mapped for
            // `arena_bytes`, and this period is not held by the device (`held`
            // says so), so nothing reads it now.
            let out = unsafe {
                core::slice::from_raw_parts_mut((d.mem.arena + idx as usize * geo.period_bytes as usize) as *mut u8, geo.period_bytes as usize)
            };
            mixer::finish(&self.acc[..n], out);
            let slot = Period { index: idx, frames: geo.period_frames, flags: 0, time_ns: 0 }.to_slot();
            match d.mem.ready.try_push(&slot) {
                RingStep::Blocked => return,
                RingStep::DoneWake { addr } => self.env.wake(addr),
                RingStep::Done => {}
            }
            d.held.post(idx);
        }
    }

    /// Close the streams whose clients stopped: a running one that gave
    /// nothing for [`STALL_NS`], any other that nothing called for
    /// [`IDLE_NS`].
    fn reap_stale(&mut self, now: u64) {
        for i in 0..STREAMS_MAX {
            let stale = self.streams[i].as_ref().is_some_and(|s| {
                let limit = if s.running() { STALL_NS } else { IDLE_NS };
                now.saturating_sub(s.active_ns) > limit
            });
            if stale {
                self.env.log(b"[audiod] closed a stream whose client stopped\n");
                self.drop_stream(i);
            }
        }
    }

    fn drop_stream(&mut self, slot: usize) {
        if let Some(s) = self.streams[slot].take() {
            self.release_all(s.caps);
        }
    }

    fn poll_lease(&mut self, now: u64) {
        let Some(l) = self.lease.as_mut() else { return };
        if now.saturating_sub(l.polled_ns) < LEASE_POLL_NS {
            return;
        }
        l.polled_ns = now;
        let seen = l.xruns_seen;
        let stalled = match self.env.lease_status() {
            Ok(st) => {
                if let Some(l) = self.lease.as_mut() {
                    l.xruns_seen = st.xruns;
                }
                st.state == STATE_RUNNING && st.xruns.wrapping_sub(seen) >= LEASE_STALL_XRUNS
            }
            Err(_) => true,
        };
        if stalled {
            self.env.log(b"[audiod] closed the capture stream: its client stopped posting room\n");
            self.end_lease();
        }
    }

    fn end_lease(&mut self) {
        if let Some(l) = self.lease.take() {
            let _ = self.env.lease_close();
            self.release_all(l.caps);
        }
    }
}

impl<E: Env> snd::Sound for Server<E> {
    fn info(&self) -> Out<Info> {
        // The device's answer is cached (`prepare` asks before the dispatch).
        match self.info {
            Some(i) => Out::ok(Info {
                dirs: i.dirs & (DIR_PLAYBACK | if self.limits.capture { DIR_CAPTURE } else { 0 }),
                formats: i.formats & snd::format_bit(FMT_S16),
                ..i
            }),
            None => out_err(outcome::NOT_READY),
        }
    }

    fn open(
        &mut self,
        params: Params,
        ready: WireCap<snd::ReadyQueue>,
        done: WireCap<snd::DoneQueue>,
        arena: WireCap<snd::Arena>,
    ) -> Out<Opened> {
        let caps = [ready.raw(), done.raw(), arena.raw()];
        let r = self.open_inner(params, caps);
        // A refused open leaves the three objects with this task, which has no
        // use for them.
        if r.code != outcome::OK {
            self.release_all(caps);
        }
        r
    }

    fn start(&mut self) -> Out<()> {
        if self.caller == 0 {
            return out_err(outcome::DENIED);
        }
        if self.lease_of_caller() {
            return into_out(self.env.lease_start());
        }
        let Some(i) = self.slot_of(self.caller) else { return out_err(outcome::NOT_READY) };
        let now = self.env.now_ns();
        let s = self.streams[i].as_mut().expect("slot_of found it");
        s.active_ns = now;
        match s.state {
            STATE_OPEN => s.state = STATE_RUNNING,
            STATE_DRAINING => return out_err(outcome::BUSY),
            _ => {}
        }
        Out::ok(())
    }

    fn stop(&mut self) -> Out<()> {
        if self.caller == 0 {
            return out_err(outcome::DENIED);
        }
        if self.lease_of_caller() {
            return into_out(self.env.lease_stop());
        }
        let Some(i) = self.slot_of(self.caller) else { return Out::ok(()) };
        let now = self.env.now_ns();
        let Server { env, streams, .. } = self;
        let s = streams[i].as_mut().expect("slot_of found it");
        s.active_ns = now;
        let was_draining = s.state == STATE_DRAINING;
        s.state = STATE_OPEN;
        s.cancel(env);
        if was_draining {
            s.give_end(env);
        }
        Out::ok(())
    }

    fn drain(&mut self) -> Out<()> {
        if self.caller == 0 {
            return out_err(outcome::DENIED);
        }
        if self.lease_of_caller() {
            return into_out(self.env.lease_drain());
        }
        let Some(i) = self.slot_of(self.caller) else { return out_err(outcome::NOT_READY) };
        let now = self.env.now_ns();
        let s = self.streams[i].as_mut().expect("slot_of found it");
        s.active_ns = now;
        s.state = STATE_DRAINING;
        Out::ok(())
    }

    fn close(&mut self) -> Out<()> {
        if self.caller == 0 {
            return out_err(outcome::DENIED);
        }
        if self.lease_of_caller() {
            self.end_lease();
            return Out::ok(());
        }
        if let Some(i) = self.slot_of(self.caller) {
            self.drop_stream(i);
        }
        Out::ok(())
    }

    fn status(&self) -> Out<Status> {
        if self.caller == 0 {
            return out_err(outcome::DENIED);
        }
        if self.lease_of_caller() {
            // The kernel's count, read by `prepare` just before this call.
            return match self.lease_cache {
                Some(st) => Out::ok(st),
                None => out_err(outcome::NOT_READY),
            };
        }
        match self.slot_of(self.caller).and_then(|i| self.streams[i].as_ref()) {
            Some(s) => Out::ok(Status { state: s.state, xruns: s.xruns, frames: s.frames }),
            None => Out::ok(Status::default()),
        }
    }
}

fn into_out(r: Result<(), u32>) -> Out<()> {
    match r {
        Ok(()) => Out::ok(()),
        Err(c) => out_err(c),
    }
}

impl<E: Env> Server<E> {
    /// Before a call is served, with `caller` set: close a capture stream
    /// whose client stopped posting room, and read what `info` and `status`
    /// answer from because they cannot call out (what the device can do, and
    /// the kernel's count of a lent capture stream when the caller holds it).
    /// It runs on the main thread, the one the capture stream is made on.
    pub fn prepare(&mut self) {
        let now = self.env.now_ns();
        self.poll_lease(now);
        let _ = self.device_info();
        self.lease_cache = if self.lease_of_caller() { self.env.lease_status().ok() } else { None };
    }

    fn open_inner(&mut self, params: Params, caps: [u32; 3]) -> Out<Opened> {
        if self.caller == 0 {
            return out_err(outcome::DENIED);
        }
        let geo = match params.check() {
            Ok(g) => g,
            Err(c) => return out_err(c),
        };
        if params.periods > self.limits.max_periods || geo.arena_bytes > self.limits.arena_bytes_max {
            return out_err(outcome::BAD_ARGUMENT);
        }
        let info = match self.device_info() {
            Ok(i) => i,
            Err(c) => return out_err(c),
        };
        if params.dir == DIR_CAPTURE {
            return self.open_capture(params, caps, &info);
        }
        if info.dirs & DIR_PLAYBACK == 0
            || info.formats & snd::format_bit(params.format) == 0
            || params.format != FMT_S16
            || params.rate_hz != info.rate_hz
            || params.channels != info.channels
            || params.period_frames < info.period_frames_min
            || params.period_frames > info.period_frames_max
            || Self::dev_params(&info).is_none()
        {
            return out_err(outcome::UNSUPPORTED);
        }
        if self.slot_of(self.caller).is_some() {
            return out_err(outcome::BUSY);
        }
        let Some(slot) = self.streams.iter().take(self.limits.max_streams.min(STREAMS_MAX)).position(Option::is_none) else {
            return out_err(outcome::BUSY);
        };
        let (Some(r), Some(d), Some(a)) = (self.env.map(caps[0]), self.env.map(caps[1]), self.env.map(caps[2])) else {
            return out_err(outcome::BAD_ARGUMENT);
        };
        let (Some(rs), Some(ds)) = (slots_for(r.bytes), slots_for(d.bytes)) else { return out_err(outcome::BAD_ARGUMENT) };
        // Each queue holds at least the periods and the end marker, the three
        // objects are three, and the arena holds every period.
        if rs < geo.queue_slots
            || ds < geo.queue_slots
            || r.va == d.va
            || r.va == a.va
            || d.va == a.va
            || (a.bytes as u64) < geo.arena_bytes
        {
            return out_err(outcome::BAD_ARGUMENT);
        }
        let now = self.env.now_ns();
        self.streams[slot] = Some(Stream {
            badge: self.caller,
            geo,
            caps,
            ready: SpscSlots { base: r.va, cap: rs },
            done: SpscSlots { base: d.va, cap: ds },
            arena: a.va,
            state: STATE_OPEN,
            cur: None,
            gain: mixer::GAIN_UNITY,
            xrun_owed: false,
            xruns: 0,
            frames: 0,
            end_owed: false,
            active_ns: now,
        });
        Out::ok(Opened { period_bytes: geo.period_bytes, latency_frames: DEV_AHEAD * DEV_PERIOD_FRAMES })
    }

    /// Capture: the kernel's gate decides, on the client's own objects.
    fn open_capture(&mut self, params: Params, caps: [u32; 3], info: &Info) -> Out<Opened> {
        if !self.limits.capture || info.dirs & DIR_CAPTURE == 0 {
            return out_err(outcome::UNSUPPORTED);
        }
        // Asked even when a lease is held: the kernel orders its answers so a
        // task without the effect is refused before it learns the device is
        // busy, and it records every attempt.
        match self.env.lease_open(params, caps[0], caps[1], caps[2]) {
            Ok(o) => {
                let now = self.env.now_ns();
                self.lease = Some(Lease { badge: self.caller, caps, xruns_seen: 0, polled_ns: now });
                Out::ok(o)
            }
            Err(c) => out_err(c),
        }
    }
}

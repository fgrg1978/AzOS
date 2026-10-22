// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The `Sound` interface the kernel hosts (`endpoint = "sound.<n>"`): the
//! virtio-sound device (`azos_drv_virtio::virtio::snd`) as streams of
//! memory-object periods. The interface, its stream life and its wire forms
//! are `azos_devif::sound`; this is the server behind device 0.
//!
//! # One stream per task and direction
//!
//! The device has one playback stream and one capture stream, so a direction
//! holds at most one stream, and the caller of every op other than `info` is
//! known only by its task, not by the capability it called through: **a task
//! holds one stream here** (`BUSY` for a second `open`), found by the task id
//! the stream was opened by. A client that plays and records is two tasks, or
//! the audio server in front of both (the module doc of `azos_devif::sound`).
//!
//! # What `open` takes
//!
//! * The two queues, resolved in place exactly as `Uart::attach` resolves its
//!   (`devices.rs`, "Queues"): the capability stays in the caller's table, the
//!   kernel keeps the region's packed reference and asks the region table
//!   again on every push and pop, so a region freed under the stream ends the
//!   stream and writes nowhere.
//! * The arena, **pinned**: a `Contig`, read-write, kernel-mapped memory object
//!   of at least the geometry's size, on which the kernel takes a reference of
//!   its own (as `display.rs` does for a surface band). The device then DMAs
//!   from or into the frames themselves, so the frames must not move, be
//!   resized, revoked or freed while a descriptor names them; the pin is held
//!   until `close` has made the device let go (`SET_PARAMS`..`RELEASE`), and
//!   the arena is never shared copy-on-write (`Contig` is not).
//!
//! # The pump
//!
//! The kernel does not move periods in the caller's call: `dev-pump`
//! (`devices.rs`) calls [`pump`], which per stream reaps the device's
//! completions into `done`, takes periods from `ready` while the device has
//! room, and ends a playback drain. The device's interrupt wakes the pump
//! ([`azos_drv_virtio::virtio::snd::irq`], then `devices::wake_pump`); the
//! `ready` queue has no doorbell on the kernel side, so a running or open
//! stream is also looked at every `DEVIF_PUMP_POLL_US`. A task's exit ends its
//! stream the same way ([`release_all`] marks it, the pump closes it: closing
//! talks to the device, which the exit hook may not wait for).
//!
//! # Capture
//!
//! A capture stream is an irreversible effect on the person in the room
//! (`azos_devif::sound`, "Capture needs the microphone effect, the requester's").
//! `open` with `DIR_CAPTURE` decides [`azos_devif::sound::capture_reason`] for the
//! **requester** and writes an `audio-capture` decision record naming it for
//! every attempt, admitted or refused; a refusal answers `REFUSED`.
//!
//! * **The requester** is the caller, or, when `on_behalf` names the call the
//!   caller is serving (`azos_ipc::fastcall::warrant_peer`: the warrant the
//!   kernel gave it at accept, unanswered, held by it), the task that made that
//!   call. The audio server serves many clients through one thread, so what it
//!   lends the device is each client's own request; its class is not consulted.
//!   A warrant the caller does not hold is refused with the reason
//!   `MIC_NO_REQUEST`, recorded against the caller.
//! * **The `mic` effect** is withheld from a task whose scheduler class has an
//!   `[envelope.NAME]` row with `kind = "mic"` and ceiling `contained`; a class
//!   with no such row has it. The class is the one of the topology row the task
//!   was seeded from (`natfork::row_of`); with a topology installed, a task with
//!   no row has no class, so no grant.
//! * **The indicator** that tells the person a microphone is live is a line on
//!   the kernel console (`[AUDIO] microphone LIVE`, naming the requester) written
//!   before the device is asked and again when the stream ends. The console is
//!   the only channel every build has; a screen or LED indicator replaces
//!   [`indicator_on`] and [`indicator_off`] when one exists.
//! * **Held by another task**: one capture stream at a time. The stream belongs
//!   to the thread that opened it (the server's, which also ends it); the
//!   requester is who it is for.
//!
//! Kconfig `AUDIO_CAPTURE` n compiles the path out: a capture `open` answers
//! `UNSUPPORTED` and nothing is recorded (there is nothing to decide).

use azos_abi::cap::CapPerms;
use azos_decision::{Rule, Verdict};
use azos_devif::sound::{
    self as snd, capture_reason, Info, Opened, Params, Period, Status, DIR_CAPTURE, DIR_PLAYBACK, MIC_ADMITTED, MIC_NO_REQUEST,
    NO_PERIOD, PERIOD_CANCELLED, PERIOD_END, SLOT_WORDS,
};
use azos_devif::{outcome, Lent, Out};
use azos_drv_virtio::virtio::snd as dev;
use azos_ipc::cap::targets;
use azos_ipc::memobj::{
    memobj_describe_ref, memobj_kernel_page_phys_ref, MemKind, MemPerms, ATTR_NO_KERNEL_MAP, ATTR_SWAPPABLE,
};
use azos_sync::kmutex::Mutex;
use core::sync::atomic::{AtomicU32, Ordering};

use crate::devices::{kick_pump, wake_pump, QueueEnd};
use crate::display::{pin, resolve, unpin};
use crate::khost::Caller;

const PLAY: usize = 0;
const REC: usize = 1;

const fn dir_of(d: usize) -> u32 {
    if d == PLAY { DIR_PLAYBACK } else { DIR_CAPTURE }
}

/// Periods moved from `ready` to the device in one pass, so a flood cannot
/// keep the pump from the other stream.
const FEED_MAX: usize = snd::PERIODS_MAX as usize;

/// A stream a task opened.
struct Hosted {
    /// The task the stream is for: the task that opened it, or, for a capture
    /// stream a server opened on a client's call, the client (the indicator
    /// names it). The task that opened it is `OWNER[d]`.
    subject: u32,
    geo: snd::Geometry,
    ready: QueueEnd,
    done: QueueEnd,
    /// The arena, by packed reference; the kernel holds a pinned reference.
    arena: u32,
    /// A playback drain is under way: the end marker comes when everything
    /// posted has played.
    draining: bool,
    /// An end marker `done` had no room for; retried every pass.
    end_owed: bool,
    /// Completed periods `done` had no room for (the client is not reading it).
    lost: u32,
}

struct Host {
    s: [Option<Hosted>; 2],
}

/// The streams. A sleeping lock: ops and the pump talk to the device while
/// holding it (a control request waits for the device's answer).
static HOST: Mutex<Host> = Mutex::new(Host { s: [None, None] });

/// The task that owns each direction's stream (0: none): readable without
/// [`HOST`], by `status` and by the exit hook.
static OWNER: [AtomicU32; 2] = [AtomicU32::new(0), AtomicU32::new(0)];

/// Directions whose owner exited: bit `d`. The pump closes them.
static ORPHAN: AtomicU32 = AtomicU32::new(0);

fn code_of(e: dev::Error) -> u32 {
    match e {
        dev::Error::NoDevice | dev::Error::NotReady => outcome::NOT_READY,
        dev::Error::Busy => outcome::BUSY,
        dev::Error::Unsupported => outcome::UNSUPPORTED,
        dev::Error::BadArgument => outcome::BAD_ARGUMENT,
        dev::Error::Fault => outcome::FAULT,
    }
}

// ── the microphone ───────────────────────────────────────────────────────

/// The envelope rule: a class has the `mic` effect unless an `[envelope.NAME]`
/// row of kind `mic` for the class caps it at `contained`.
pub fn mic_admitted(envelopes: &[azos_topology::EnvelopeSpec<'_>], class: &azos_topology::MaybeStr<'_>) -> bool {
    !envelopes
        .iter()
        .any(|e| e.kind == azos_topology::EffectKind::Mic && e.class == *class && e.level == azos_topology::Envelope::Contained)
}

/// Tasks whose `mic` effect the host suites withhold (0: free slot): they
/// install no topology (it is installed once per process), so the class lookup
/// has nothing to ask.
#[cfg(test)]
static MIC_WITHHELD: [AtomicU32; 8] = [const { AtomicU32::new(0) }; 8];

/// Withhold the `mic` effect from `tid` (host suites only).
#[cfg(test)]
pub fn withhold_mic(tid: u32) {
    for s in &MIC_WITHHELD {
        if s.compare_exchange(0, tid, Ordering::AcqRel, Ordering::Acquire).is_ok() {
            return;
        }
    }
}

/// Give every task the `mic` effect again (host suites only).
#[cfg(test)]
pub fn clear_withheld_mic() {
    for s in &MIC_WITHHELD {
        s.store(0, Ordering::Release);
    }
}

/// Is the `mic` effect admitted for task `tid`'s scheduler class? No topology
/// installed: there are no classes to cap. With one, a task seeded from no row
/// has no class and so no grant.
fn mic_effect(tid: u32) -> bool {
    #[cfg(test)]
    if MIC_WITHHELD.iter().any(|s| s.load(Ordering::Acquire) == tid) {
        return false;
    }
    let Some(topo) = azos_topology::get() else { return true };
    let Some(task) = crate::natfork::row_of(tid).and_then(|row| topo.tasks().get(row)) else { return false };
    mic_admitted(topo.envelopes(), &task.class_name)
}

/// The task that made the call `call` names, when `server` is serving it (it
/// accepted it and has not answered it): the requester a server opens a capture
/// stream for. `None` for any other warrant, including one a task made up.
fn call_requester(server: u32, call: u64) -> Option<u32> {
    azos_ipc::fastcall::warrant_peer(call, server).map(|(caller, _)| caller)
}

/// Tell the person a microphone is live. The console is the indicator every
/// build has.
fn indicator_on(tid: u32) {
    azos_drv_sys::kwarn!("[AUDIO] microphone LIVE: capture stream opened by tid {}", tid);
}

fn indicator_off(tid: u32) {
    azos_drv_sys::kwarn!("[AUDIO] microphone off: capture stream of tid {} ended", tid);
}

/// Whether the indicator can be shown: always, the console being the channel.
const fn indicator_available() -> bool {
    true
}

// ── the ring ends ────────────────────────────────────────────────────────

impl Hosted {
    /// Return a period to the client. `false` when `done` can no longer be
    /// touched (its region is gone: the stream ends).
    fn give(&mut self, p: Period) -> bool {
        match self.done.push::<SLOT_WORDS>(&p.to_slot()) {
            Ok(true) => true,
            Ok(false) => {
                // The client is not reading `done`; the period is lost to it.
                self.lost = self.lost.wrapping_add(1);
                true
            }
            Err(()) => false,
        }
    }

    /// The end marker, once; kept owed when `done` is full.
    fn give_end(&mut self) -> bool {
        let end = Period { index: NO_PERIOD, frames: 0, flags: PERIOD_END, time_ns: 0 };
        match self.done.push::<SLOT_WORDS>(&end.to_slot()) {
            Ok(fit) => {
                self.end_owed = !fit;
                true
            }
            Err(()) => false,
        }
    }

    /// Move the device's completed periods to `done`.
    fn deliver(&mut self, dir: u32) -> bool {
        while let Some(p) = dev::take_done(dir) {
            if !self.give(p) {
                return false;
            }
        }
        true
    }

    /// Take periods from `ready` while the device has room for them. `None`
    /// when a queue's region is gone; otherwise whether `ready` was found
    /// empty (a drain may end) or left with periods for the next pass.
    fn feed(&mut self, dir: u32) -> Option<bool> {
        for _ in 0..FEED_MAX {
            if !dev::room(dir) {
                return Some(false);
            }
            let w = match self.ready.pop::<SLOT_WORDS>() {
                Ok(Some(w)) => w,
                Ok(None) => return Some(true),
                Err(()) => return None,
            };
            // A slot the client wrote wrong is consumed and ignored: it names
            // nothing the server holds.
            let Some(p) = Period::from_slot(&w) else { continue };
            if p.check(&self.geo, dir).is_err() {
                continue;
            }
            match dev::submit(dir, p.index, p.frames) {
                dev::Submit::Queued | dev::Submit::Dup | dev::Submit::Bad | dev::Submit::NotOpen => {}
                dev::Submit::Full => {
                    // `room` said yes a moment ago; whatever changed, the
                    // client gets the period back to post again.
                    if !self.give(Period { index: p.index, frames: 0, flags: PERIOD_CANCELLED, time_ns: 0 }) {
                        return None;
                    }
                }
            }
        }
        Some(false)
    }

    /// Return every period still in `ready` as cancelled: they are posted,
    /// so the server holds them (`stop` and a capture drain give back all).
    fn cancel_ready(&mut self, dir: u32) -> bool {
        for _ in 0..self.geo.queue_slots {
            let w = match self.ready.pop::<SLOT_WORDS>() {
                Ok(Some(w)) => w,
                Ok(None) => return true,
                Err(()) => return false,
            };
            let Some(p) = Period::from_slot(&w) else { continue };
            if p.check(&self.geo, dir).is_err() {
                continue;
            }
            if !self.give(Period { index: p.index, frames: 0, flags: PERIOD_CANCELLED, time_ns: 0 }) {
                return false;
            }
        }
        true
    }
}

// ── close ────────────────────────────────────────────────────────────────

/// End direction `d`'s stream: the device lets go (`STOP`, `RELEASE`), the
/// kernel's pin on the arena is given back. The host lock is held.
fn close_locked(h: &mut Host, d: usize) {
    let Some(s) = h.s[d].take() else { return };
    let _ = dev::close(dir_of(d));
    unpin(s.arena);
    OWNER[d].store(0, Ordering::Release);
    if d == REC {
        indicator_off(s.subject);
    }
}

// ── the pump ─────────────────────────────────────────────────────────────

/// One pass over the streams (the `dev-pump` task calls it): close what a
/// dead task left, then per stream reap, deliver, feed and end a drain.
/// Answers when to look again (`None`: no stream, the pump may park).
pub fn pump(now_ns: u64, poll_ns: u64) -> Option<u64> {
    if OWNER.iter().all(|o| o.load(Ordering::Acquire) == 0) && ORPHAN.load(Ordering::Acquire) == 0 {
        return None;
    }
    let mut h = HOST.lock();
    let orphans = ORPHAN.swap(0, Ordering::AcqRel);
    for d in 0..2 {
        if orphans >> d & 1 != 0 {
            close_locked(&mut h, d);
        }
    }
    let mut live = false;
    for d in 0..2 {
        let Some(s) = h.s[d].as_mut() else { continue };
        let dir = dir_of(d);
        dev::reap(dir);
        let mut ok = s.deliver(dir);
        if ok && s.end_owed {
            ok = s.give_end();
        }
        let mut empty = false;
        if ok && !s.end_owed {
            match s.feed(dir) {
                Some(e) => empty = e,
                None => ok = false,
            }
        }
        if ok && s.draining && empty && dev::drained(dir) {
            // Everything posted has played: stop the device, return what is
            // left and the end marker.
            ok = dev::finish_drain(dir).is_ok() && s.deliver(dir) && s.give_end();
            s.draining = false;
        }
        if ok {
            live = true;
        } else {
            // A queue's region is gone: the stream cannot go on.
            close_locked(&mut h, d);
        }
    }
    live.then(|| now_ns.saturating_add(poll_ns))
}

/// The task `tid` exited: mark its streams for the pump to close. Called from
/// the kernel's task-exit hook (through `devices::release_all`), which may not
/// wait for the device.
pub fn release_all(tid: u32) {
    let mut any = false;
    for d in 0..2 {
        if OWNER[d].load(Ordering::Acquire) == tid {
            ORPHAN.fetch_or(1 << d, Ordering::AcqRel);
            any = true;
        }
    }
    if any {
        let _ = wake_pump();
    }
}

// ── the interface ────────────────────────────────────────────────────────

/// The `Sound` interface served for one caller: device 0 (`sound.0`, badge 1).
/// `READ` observes (`info`, `status`); `WRITE` runs a stream. `open` and `start`
/// make sound (or listen) and are refused while the system is contained; `stop`,
/// `drain` and `close` are honoured whatever containment says.
pub struct Server(pub Caller);

impl Server {
    fn device(&self) -> Result<(), u32> {
        if self.0.badge == snd::device_badge(0) { Ok(()) } else { Err(outcome::NO_RESOURCE) }
    }

    /// The gate of an op that ends or finishes: the capability carries
    /// `WRITE`; containment does not matter.
    fn end_gate<T: Default>(&self) -> Result<(), Out<T>> {
        if self.0.holds(CapPerms::WRITE) {
            return Ok(());
        }
        self.0.deny(CapPerms::WRITE);
        Err(Out::err(outcome::DENIED))
    }

    /// The direction this task holds a stream in.
    fn dir(&self) -> Option<usize> {
        (0..2).find(|&d| OWNER[d].load(Ordering::Acquire) == self.0.tid)
    }
}

impl snd::Sound for Server {
    fn info(&self) -> Out<Info> {
        if let Err(o) = self.0.gate::<Info>(CapPerms::READ) {
            return o;
        }
        if let Err(c) = self.device() {
            return Out::err(c);
        }
        let Some(c) = dev::caps() else { return Out::err(outcome::NOT_READY) };
        let dirs = if azos_limits::AUDIO_CAPTURE { c.dirs } else { c.dirs & !DIR_CAPTURE };
        if dirs == 0 {
            return Out::err(outcome::NOT_READY);
        }
        Out::ok(Info {
            dirs,
            formats: c.formats,
            rate_hz: c.rate_hz,
            channels: c.channels,
            period_frames_min: snd::PERIOD_FRAMES_MIN,
            period_frames_max: snd::PERIOD_FRAMES_MAX,
        })
    }

    fn open(
        &mut self,
        params: Params,
        ready: Lent<snd::ReadyQueue>,
        done: Lent<snd::DoneQueue>,
        arena: Lent<snd::Arena>,
        on_behalf: u64,
    ) -> Out<Opened> {
        if let Err(o) = self.0.gate::<Opened>(CapPerms::WRITE) {
            return o;
        }
        if let Err(c) = self.device() {
            return Out::err(c);
        }
        let who = self.0;
        let geo = match params.check() {
            Ok(g) => g,
            Err(c) => return Out::err(c),
        };
        // The three objects are lent: the entries name the caller's own
        // capabilities, which stay in its table (`khost::takes_caps`).
        let (Some(ready), Some(done), Some(arena)) = (ready.get(), done.get(), arena.get()) else {
            return Out::err(outcome::BAD_ARGUMENT);
        };
        if params.periods > azos_limits::AUDIO_MAX_PERIODS as u32
            || geo.arena_bytes > azos_limits::AUDIO_ARENA_KB_MAX as u64 * 1024
        {
            return Out::err(outcome::BAD_ARGUMENT);
        }
        let d = if params.dir == DIR_PLAYBACK { PLAY } else { REC };
        // Whom the stream is for. Playback is nobody's authority to lend: it
        // names no call.
        let mut subject = who.tid;
        if d == PLAY && on_behalf != 0 {
            return Out::err(outcome::BAD_ARGUMENT);
        }
        if d == REC {
            if !azos_limits::AUDIO_CAPTURE {
                return Out::err(outcome::UNSUPPORTED);
            }
            // The requester's effect, never the messenger's: a task without it
            // learns nothing of the device.
            let reason = match snd::capture_subject(who.tid, on_behalf, |call| call_requester(who.tid, call)) {
                Some(requester) => {
                    subject = requester;
                    let held = OWNER[REC].load(Ordering::Acquire) != 0;
                    capture_reason(mic_effect(requester), indicator_available(), held)
                }
                None => MIC_NO_REQUEST,
            };
            let verdict = if reason == MIC_ADMITTED { Verdict::Admit } else { Verdict::Refuse };
            // Device 0 is the one the kernel drives. The record names the
            // requester, or the caller when there is none.
            azos_decision::record(Rule::AudioCapture, verdict, subject, [0, params.rate_hz as u64, reason as u64]);
            if reason != MIC_ADMITTED {
                return Out::err(outcome::REFUSED);
            }
        }
        let Some(caps) = dev::caps() else { return Out::err(outcome::NOT_READY) };
        if caps.dirs & params.dir == 0
            || caps.formats & snd::format_bit(params.format) == 0
            || params.rate_hz != caps.rate_hz
            || params.channels != caps.channels
        {
            return Out::err(outcome::UNSUPPORTED);
        }
        // The capabilities and the objects first, with the host lock free.
        let ready_end = match QueueEnd::resolve::<SLOT_WORDS>(&who, ready.raw(), CapPerms::READ) {
            Ok(e) => e,
            Err(c) => return Out::err(c),
        };
        let done_end = match QueueEnd::resolve::<SLOT_WORDS>(&who, done.raw(), CapPerms::WRITE) {
            Ok(e) => e,
            Err(c) => return Out::err(c),
        };
        // Each queue holds at least the periods and the end marker, and they
        // are two regions: one ring cannot be both directions.
        if ready_end.region == done_end.region || ready_end.slots < geo.queue_slots || done_end.slots < geo.queue_slots {
            return Out::err(outcome::BAD_ARGUMENT);
        }
        let need = if d == REC { CapPerms::WRITE } else { CapPerms::READ };
        let obj = match resolve::<targets::Shm>(&who, arena.raw(), need) {
            Ok(o) => o,
            Err(c) => return Out::err(c),
        };
        if obj == ready_end.region || obj == done_end.region {
            return Out::err(outcome::BAD_ARGUMENT);
        }
        let phys = match arena_object(obj, geo.arena_bytes) {
            Ok(p) => p,
            Err(c) => return Out::err(c),
        };
        let mut h = HOST.lock();
        let open = h.s.iter().flatten().count();
        if h.s[d].is_some() || self.dir().is_some() || open >= azos_limits::AUDIO_MAX_STREAMS as usize {
            return Out::err(outcome::BUSY);
        }
        if let Err(c) = pin(obj) {
            return Out::err(c);
        }
        if d == REC {
            indicator_on(subject);
        }
        if let Err(e) = dev::open(params.dir, &params, &geo, phys as u64) {
            unpin(obj);
            if d == REC {
                indicator_off(subject);
            }
            return Out::err(code_of(e));
        }
        h.s[d] = Some(Hosted { subject, geo, ready: ready_end, done: done_end, arena: obj, draining: false, end_owed: false, lost: 0 });
        OWNER[d].store(who.tid, Ordering::Release);
        drop(h);
        if !kick_pump() {
            // No task to move the periods: the stream would never run.
            close_locked(&mut HOST.lock(), d);
            return Out::err(outcome::NO_RESOURCE);
        }
        Out::ok(Opened { period_bytes: geo.period_bytes, latency_frames: 0 })
    }

    fn start(&mut self) -> Out<()> {
        if let Err(o) = self.0.gate::<()>(CapPerms::WRITE) {
            return o;
        }
        if let Err(c) = self.device() {
            return Out::err(c);
        }
        let Some(d) = self.dir() else { return Out::err(outcome::NOT_READY) };
        let _h = HOST.lock();
        match dev::start(dir_of(d)) {
            Ok(()) => Out::ok(()),
            Err(e) => Out::err(code_of(e)),
        }
    }

    fn stop(&mut self) -> Out<()> {
        if let Err(o) = self.end_gate::<()>() {
            return o;
        }
        if let Err(c) = self.device() {
            return Out::err(c);
        }
        let Some(d) = self.dir() else { return Out::ok(()) };
        let mut h = HOST.lock();
        let r = dev::stop(dir_of(d));
        if let Some(s) = h.s[d].as_mut() {
            let was_draining = core::mem::take(&mut s.draining);
            let alive = s.deliver(dir_of(d)) && s.cancel_ready(dir_of(d)) && (!was_draining || s.give_end());
            if !alive {
                close_locked(&mut h, d);
            }
        }
        match r {
            Ok(()) => Out::ok(()),
            Err(e) => Out::err(code_of(e)),
        }
    }

    fn drain(&mut self) -> Out<()> {
        if let Err(o) = self.end_gate::<()>() {
            return o;
        }
        if let Err(c) = self.device() {
            return Out::err(c);
        }
        let Some(d) = self.dir() else { return Out::err(outcome::NOT_READY) };
        let dir = dir_of(d);
        let mut h = HOST.lock();
        let Some(s) = h.s[d].as_mut() else { return Out::err(outcome::NOT_READY) };
        // Periods already posted are the server's: playback plays them, so they
        // go to the device before the drain begins.
        if d == PLAY && s.feed(dir).is_none() {
            close_locked(&mut h, d);
            return Out::err(outcome::FAULT);
        }
        match dev::drain(dir) {
            Ok(false) => {
                s.draining = true;
                Out::ok(())
            }
            Ok(true) => {
                // Capture: the buffer being filled came back short, the rest
                // cancelled; the stream is open again at once.
                let alive = s.deliver(dir) && s.cancel_ready(dir) && s.give_end();
                if !alive {
                    close_locked(&mut h, d);
                    return Out::err(outcome::FAULT);
                }
                Out::ok(())
            }
            Err(e) => Out::err(code_of(e)),
        }
    }

    fn close(&mut self) -> Out<()> {
        if let Err(o) = self.end_gate::<()>() {
            return o;
        }
        if let Err(c) = self.device() {
            return Out::err(c);
        }
        if let Some(d) = self.dir() {
            close_locked(&mut HOST.lock(), d);
        }
        Out::ok(())
    }

    fn status(&self) -> Out<Status> {
        if let Err(o) = self.0.gate::<Status>(CapPerms::READ) {
            return o;
        }
        if let Err(c) = self.device() {
            return Out::err(c);
        }
        match self.dir() {
            Some(d) => Out::ok(dev::status(dir_of(d))),
            None => Out::ok(Status::default()),
        }
    }
}

/// What the arena may be: read-write, `Contig` (one physical run, so one bus
/// address for the device), not reclaimable, visible to the kernel's direct
/// map and at least `bytes` long. The physical address of its first frame.
fn arena_object(obj: u32, bytes: u64) -> Result<usize, u32> {
    let d = memobj_describe_ref(obj).map_err(|_| outcome::BAD_ARGUMENT)?;
    if d.perms != MemPerms::ReadWrite
        || d.kind != MemKind::Contig
        || d.attrs & (ATTR_SWAPPABLE | ATTR_NO_KERNEL_MAP) != 0
        || (d.page_count as u64) * (azos_arch::PAGE_SIZE as u64) < bytes
    {
        return Err(outcome::BAD_ARGUMENT);
    }
    memobj_kernel_page_phys_ref(obj, 0).ok().flatten().ok_or(outcome::BAD_ARGUMENT)
}

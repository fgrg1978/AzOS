// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `beep [MS]`: play a short tone, through the audio server when the row holds
//! its endpoint (`endpoint.audio`, Kconfig AUDIOD), else straight on the
//! kernel's sound device (`sound.0`).
//!
//! The server and the kernel serve the same `Sound` interface, so the flow is
//! one: only the endpoint differs, and with it who gets the objects. Through
//! the server a task tells its stream from another's by the badge of the
//! capability it calls through, so it derives a copy of its endpoint capability
//! badged with its process id (two `beep`s at once are two streams the server
//! mixes); `open` then moves the three objects to the server, which maps them,
//! and this task goes on with the mappings it made.
//!
//! The flow `beep.rs` has the arithmetic of. A playback stream is three
//! memory objects this task makes and the server (or the kernel) is handed with `Sound::open`:
//! the `ready` queue (this task posts periods), the `done` queue (the kernel
//! returns them) and the arena, a `Contig` object the device reads its
//! samples from. Three of the system's memory-object slots while the tool
//! runs, and no more: nothing is made per period. The samples never cross a
//! call; the only calls are `info`, `open`, `start`, `drain`, `status` and
//! `close`, and the sleep on `done`'s doorbell, which is bounded.
//!
//! A tone of `n` periods is posted `PERIODS` at a time; each one that comes back
//! on `done` is filled with the next piece and posted again; after the last is
//! posted the stream is drained and the tool waits for the end marker. The tone
//! has played when the periods that came back, not cancelled, are all `n`.

use crate::beep::{self, Plan, Tone};
use crate::{fail, put};
use azos_abi::cap::CapPerms;
use azos_abi::syscall_nr::{SHM_CREATE_KIND_SHIFT, SHM_KIND_ANON, SHM_KIND_CONTIG};
use azos_devif::sound::{
    self as snd, Params, Period, DIR_PLAYBACK, FMT_S16, NO_PERIOD, PERIOD_CANCELLED, PERIOD_END, PERIOD_XRUN, SLOT_WORDS,
};
use azos_libsys as sys;
use azos_libsys::{RingSleep, RingStep, SpscSlots};
use sys::dev::{Cap, Ep, SoundCall, SoundClient};

/// Longest the tool waits for the stream to give a period back, ns: the device
/// plays a period in 21 ms, so a wait this long is a device that stopped.
const STALL_NS: u64 = 2_000_000_000;
/// One sleep on the `done` doorbell, ns; a wake normally ends it first.
const SLEEP_NS: u64 = 50_000_000;

/// A queue or the arena: the capability and where this task maps it.
struct Region {
    cap: u32,
    va: usize,
}

/// A memory object of `pages` pages, read-write, mapped here. `kind` is the
/// creation word's kind field (`SHM_KIND_ANON` or `SHM_KIND_CONTIG`).
fn make(pages: usize, kind: u64) -> Option<Region> {
    let word = sys::SHM_RW | kind << SHM_CREATE_KIND_SHIFT;
    let cap = sys::shm_create_typed(pages as u64, word);
    if cap <= 0 {
        return None;
    }
    let va = sys::shm_map_typed(cap as u32);
    if va <= 0 {
        let _ = sys::shm_release_typed(cap as u32);
        return None;
    }
    Some(Region { cap: cap as u32, va: va as usize })
}

/// Everything the stream needs, so one place gives it back.
struct Stream {
    snd: SoundClient<Ep>,
    ready: SpscSlots<SLOT_WORDS>,
    done: SpscSlots<SLOT_WORDS>,
    arena: usize,
    period_bytes: usize,
    channels: u32,
}

impl Stream {
    /// Fill period `index` with the next `frames` frames of the tone and post it.
    /// `false` when the ring cannot take it (it was sized for all of them).
    fn post(&self, tone: &mut Tone, index: u32, frames: u32) -> bool {
        // SAFETY: `arena` is the base of a mapping of `periods * period_bytes`
        // bytes this task owns, `index` is below `periods` (it came from the
        // post of that period or from the first `periods` indices), and the
        // period is ours: it was never posted, or the kernel returned it.
        let out = unsafe { core::slice::from_raw_parts_mut((self.arena + index as usize * self.period_bytes) as *mut u8, self.period_bytes) };
        tone.fill(out, frames, self.channels);
        let slot = Period { index, frames, flags: 0, time_ns: 0 }.to_slot();
        !matches!(self.ready.try_push(&slot), RingStep::Blocked)
    }

    /// The oldest period the kernel returned, or `None`: sleep on `done`'s
    /// doorbell for at most [`SLEEP_NS`] first.
    fn next(&self) -> Option<Period> {
        let mut w = [0u64; SLOT_WORDS];
        match self.done.try_pop(&mut w) {
            RingStep::Blocked => {
                if let RingSleep::Wait { addr, expected } = self.done.consumer_sleep() {
                    let _ = sys::futex_wait_addr(addr, expected, SLEEP_NS);
                    self.done.consumer_woke();
                }
                None
            }
            step => {
                if let RingStep::DoneWake { addr } = step {
                    let _ = sys::futex_wake_addr(addr, 1);
                }
                Period::from_slot(&w)
            }
        }
    }
}

/// The audio server's endpoint, if this row holds it: the first endpoint of the
/// pool (the pool index is the resource of a plain lookup), the only one the
/// row grants.
fn audio_endpoint() -> Option<u32> {
    (0..16u32).find_map(|i| {
        let h = sys::cap_lookup(sys::ty::ENDPOINT.raw(), i);
        (h > 0).then_some(h as u32)
    })
}

/// Where `beep` plays: a call-only copy of the audio server's endpoint badged
/// with this process's id, else the kernel's `sound.0`.
///
/// The client and the handle it calls through, which `run` closes after play.
fn connect() -> Result<(SoundClient<Ep>, u32), &'static [u8]> {
    if let Some(ep) = audio_endpoint() {
        let badge = sys::getpid().max(1) as u32;
        let h = sys::cap_derive(ep, u16::from(CapPerms::WRITE.bits()), badge, 0);
        if h <= 0 {
            return Err(b"cannot derive this task's stream capability on the audio server");
        }
        return Ok((SoundClient::new(Ep(h as u32)), h as u32));
    }
    let Some(ep) = sys::dev::lookup(sys::dev::key::SOUND, snd::device_badge(0)) else {
        return Err(b"no sound endpoint: this image's row does not grant it");
    };
    Ok((SoundClient::new(Ep(ep)), ep))
}

/// `beep [MS]`.
pub fn run() -> i32 {
    let ms = match beep::parse_ms(if sys::argc() > 1 { sys::arg(1) } else { None }) {
        Some(ms) if sys::argc() <= 2 => ms,
        _ => {
            fail(b"beep", b"usage: beep [MS]  (1 to 5000 milliseconds)");
            return 2;
        }
    };
    let (client, handle) = match connect() {
        Ok(c) => c,
        Err(why) => {
            fail(b"beep", why);
            return 1;
        }
    };
    let code = play(client, ms);
    // The tool is done with its call right whatever became of the tone: it
    // lets go of the handle (`SYS_CAP_CLOSE` deletes an endpoint slot) instead
    // of leaving it to the task's exit, the badged copy it derived on the audio
    // server's endpoint and the `sound.0` handle alike.
    let _ = sys::close_typed(handle);
    code
}

/// The tone of `ms` milliseconds through `client`; the exit code.
fn play(client: SoundClient<Ep>, ms: u32) -> i32 {
    let info = match sys::dev::value(client.info()) {
        Ok(i) => i,
        Err(code) => {
            fail(b"beep", beep::why(code).as_bytes());
            return 1;
        }
    };
    if info.dirs & DIR_PLAYBACK == 0 || info.formats & snd::format_bit(FMT_S16) == 0 {
        fail(b"beep", b"the device cannot play signed 16-bit audio");
        return 1;
    }
    let params = Params {
        dir: DIR_PLAYBACK,
        format: FMT_S16,
        rate_hz: info.rate_hz,
        channels: info.channels,
        period_frames: beep::PERIOD_FRAMES.clamp(info.period_frames_min, info.period_frames_max),
        periods: beep::PERIODS,
    };
    let Ok(geo) = params.check() else {
        fail(b"beep", b"the device runs at a rate or channel count this tool cannot ask for");
        return 1;
    };
    let plan = Plan::new(info.rate_hz, geo.period_frames, ms);

    // The three objects. A queue is one page; the kernel sizes its end from
    // the region, and so does `queue_slots`.
    let arena_pages = (geo.arena_bytes as usize).div_ceil(sys::PAGE_SIZE);
    let (Some(ready), Some(done), Some(arena)) =
        (make(1, SHM_KIND_ANON), make(1, SHM_KIND_ANON), make(arena_pages, SHM_KIND_CONTIG))
    else {
        fail(b"beep", b"cannot make the stream's memory (this task's frame budget, or no contiguous run)");
        return 1;
    };
    let Some(slots) = beep::queue_slots(sys::PAGE_SIZE, SLOT_WORDS) else {
        fail(b"beep", b"a page is too small for a queue");
        return 1;
    };
    let mut s = Stream {
        snd: client,
        ready: SpscSlots { base: ready.va, cap: slots },
        done: SpscSlots { base: done.va, cap: slots },
        arena: arena.va,
        period_bytes: geo.period_bytes as usize,
        channels: geo.frame_bytes / 2,
    };
    s.ready.init();
    s.done.init();

    let opened = sys::dev::value(s.snd.open(params, Cap::from_raw(ready.cap), Cap::from_raw(done.cap), Cap::from_raw(arena.cap)));
    match opened {
        Ok(o) if o.period_bytes == geo.period_bytes => {}
        Ok(_) => {
            fail(b"beep", b"the kernel computed another period size");
            let _ = s.snd.close();
            return 1;
        }
        Err(code) => {
            fail(b"beep", beep::why(code).as_bytes());
            return 1;
        }
    }

    let wanted = plan.periods();
    let mut tone = Tone::new(&plan, beep::FREQ_HZ);
    let mut posted = 0u32;
    let mut ok = true;
    // Prime the stream, then start it.
    while posted < wanted.min(geo.periods) {
        ok &= s.post(&mut tone, posted, plan.frames_of(posted));
        posted += 1;
    }
    let mut code = 0;
    if !ok || sys::dev::value(s.snd.start()).is_err() {
        fail(b"beep", b"the stream did not start");
        code = 1;
    }
    let (mut played, mut frames, mut xruns) = (0u32, 0u64, 0u32);
    let mut draining = false;
    let mut last = sys::vdso_now_ns();
    while code == 0 {
        if !draining && posted == wanted {
            if sys::dev::value(s.snd.drain()).is_err() {
                fail(b"beep", b"the stream did not drain");
                code = 1;
                break;
            }
            draining = true;
        }
        let Some(p) = s.next() else {
            if sys::vdso_now_ns().saturating_sub(last) > STALL_NS {
                fail(b"beep", b"the device stopped giving periods back");
                code = 1;
            }
            continue;
        };
        last = sys::vdso_now_ns();
        if p.flags & PERIOD_END != 0 && p.index == NO_PERIOD {
            break;
        }
        xruns += u32::from(p.flags & PERIOD_XRUN != 0);
        if p.flags & PERIOD_CANCELLED == 0 {
            played += 1;
            frames += u64::from(p.frames);
        }
        if posted < wanted {
            // The period is ours again: the next piece of the tone goes in it.
            if !s.post(&mut tone, p.index, plan.frames_of(posted)) {
                fail(b"beep", b"the ready queue is full");
                code = 1;
            }
            posted += 1;
        }
    }
    let status = sys::dev::value(s.snd.status()).unwrap_or_default();
    let _ = s.snd.close();
    if code == 0 && played != wanted {
        fail(b"beep", b"the tone was cut short");
        code = 1;
    }
    if code == 0 {
        let mut l = crate::Line { b: [0; 256], n: 0 };
        let _ = beep::write_report(&mut l, played, wanted, frames, info.rate_hz, geo.frame_bytes / 2, status.xruns.max(xruns));
        let _ = put(1, &l.b[..l.n]);
    }
    code
}

// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The `Sound` interface: one PCM stream on one audio device.
//!
//! The audio server (AUDIOD, a ring-3 task) serves it from [`ENDPOINT`]; the
//! device behind it is a codec or a virtio-snd stream, and the client does not
//! know which. The endpoint's badge is the device (an `[audio.NAME]` row of
//! the topology, position + 1). The kernel serves the same interface for the
//! device it drives itself, from the endpoint `sound.<n>` (`n` below
//! [`DEVICES`], badge `n + 1`): that is what the audio server, or a task that
//! plays one tone, calls on the hardware. A task holds one stream there. **One endpoint capability is one stream**: a
//! client that plays and records holds two capabilities, and the server keeps
//! at most one open stream per capability. `READ` observes ([`Sound::info`],
//! [`Sound::status`]); `WRITE` runs a stream (every other op).
//!
//! **The samples travel in a queue of memory-object periods, never in calls.**
//! The client makes an **arena** (a memory object of [`Geometry::arena_bytes`]:
//! `periods` consecutive periods of `period_frames` frames) and two queues of
//! [`Period`] slots, `ready` and `done`, and **lends** the three with
//! [`Sound::open`] (each a `Lent`: a copy of its capability with the rights
//! [`QUEUE_RIGHTS`] and [`arena_rights`] name), keeping its own capabilities
//! and its mappings: it goes on writing the arena and both queues. A move
//! would not do: a memory object that moves takes the sender's mapping with
//! it. The client's Domain stays charged for the frames. The protocol is the
//! same in both directions:
//!
//! * The client **posts** a period on `ready`. Playback: the period holds
//!   `frames` frames to play. Capture: it is empty room for up to
//!   `period_frames` frames.
//! * The server takes it, plays or fills it, and **returns** it on `done`:
//!   playback, `frames` played; capture, `frames` captured. From then on the
//!   client owns the period again. Between post and return the period is the
//!   server's and the client does not touch it.
//!
//! The only calls are the ones that change what the stream may do (`open`,
//! `start`, `stop`, `drain`, `close`) and the sleep on a queue's doorbell
//! (`azos_rings::region`, `SpscSlots<SLOT_WORDS>` over each queue's memory).
//! A period is addressed by its **index** into the arena, never by a byte
//! offset the client chose: `index * period_bytes` is inside the arena for
//! every index below `periods`, which is the one check a hostile slot needs
//! ([`Period::check`]). Samples are interleaved frames, little-endian, the
//! first channel first.
//!
//! # A stream's life
//!
//! `open` leaves it `OPEN` (queues attached, nothing moving; the client may
//! already post periods, which is how playback is primed). `start` makes it
//! `RUNNING`. `stop` makes it `OPEN` again at once, and every period still
//! held by the server comes back flagged [`PERIOD_CANCELLED`]. `drain`
//! makes it `DRAINING`: playback plays every period already posted; capture
//! completes the period being filled (short: fewer than `period_frames`) and
//! cancels the rest; either way the server then returns an end marker (a
//! slot with index [`NO_PERIOD`] and [`PERIOD_END`]) and the stream is `OPEN`.
//! `close` stops, lets go of the three objects and leaves the capability free
//! to `open` again. A server whose client dies closes the stream.
//!
//! A period the hardware needed and the client had not posted is an **xrun**:
//! playback goes silent, capture loses frames. It is counted
//! ([`Status::xruns`]) and the next period returned is flagged
//! [`PERIOD_XRUN`], so the client sees where the gap is.
//!
//! # Capture needs the microphone effect, the requester's
//!
//! A capture stream is an irreversible effect on the person in the room, so
//! it is never granted by the capability alone. [`Sound::open`] with
//! [`DIR_CAPTURE`] needs the **`mic` effect** (`azos_topology::EffectKind::Mic`)
//! to be admitted for the **requester's** scheduler class: an `[envelope.NAME]`
//! row with `kind = "mic"` whose ceiling is `contained` withholds it (a class
//! with no such row has the full effect), exactly as the effect gate treats any
//! other kind. Every attempt, admitted or refused, writes a decision record
//! (`azos_decision::Rule::AudioCapture`: device, rate, reason) whose subject is
//! the requester. [`capture_reason`] is the order the reasons are decided in,
//! so the server and its tests agree on which one a refusal reports. A refused
//! capture answers `REFUSED`.
//!
//! **The requester is whoever asked, not whoever the kernel hears from.** A
//! task that calls the device itself asks for itself (`on_behalf` is 0). A
//! server in front of the device (the audio server) is only the messenger of
//! its clients: it names the call it is serving in `on_behalf`, the warrant
//! the kernel gave it when it accepted that call. The kernel resolves the
//! warrant to the task that made the call and decides the effect on **that**
//! task's class, records **that** task as the subject, and names it in the
//! microphone indicator; the server's own class is never consulted. The
//! warrant is the client's authority lent for the length of its call: it
//! exists only while the call is unanswered, only its holder can name it, and
//! it ends with the reply, so it cannot be kept, replayed or passed to another
//! client's capture. A warrant that is not one the caller is serving is
//! refused ([`MIC_NO_REQUEST`]) and recorded against the caller. Every client
//! passes 0: a server never forwards its client's value, it refuses one
//! (`BAD_ARGUMENT`), because a client has no call of its own to name.
//!
//! # Outcomes
//!
//! `DENIED`: the capability lacks `WRITE`. `NO_RESOURCE`: the badge names no
//! device. `NOT_READY`: the device has no hardware behind it yet (or `start`
//! on a capability with no open stream). `BAD_ARGUMENT`: a parameter outside
//! the bounds of this module, an arena or a queue too small for the geometry,
//! or a handle that is not the object of the right rights. `UNSUPPORTED`: a
//! valid request the device cannot do (a direction, format, rate or channel
//! count outside [`Info`]). `BUSY`: a stream is already open on this
//! capability, another task holds the device exclusively, or `start` while
//! `DRAINING`. `REFUSED`: capture without the microphone effect of the requester. `FAULT`: the
//! device failed the op.
//!
//! # Failure contract
//!
//! `open` is `once_only`: for a capture stream a lost reply must not make the
//! client open twice, and the client carries on without sound (`degrade`).
//! Every other op is idempotent, so a reply lost to a restart of the server is
//! asked again.

use crate::outcome::{Out, BAD_ARGUMENT};
use azos_abi::cap::CapPerms;
use azos_idl::{azos_interface, Lent, Reader, Wire, Writer};

/// The interface id (ASCII "SOUN").
pub const SOUND_ID: u32 = 0x534F_554E;

/// Devices the kernel hosts a `Sound` endpoint for (`sound.0` ..): the one
/// virtio-snd stream pair it drives. The badge of `sound.<n>` is `n + 1`.
pub const DEVICES: u32 = 1;

/// The badge of the kernel-hosted endpoint `sound.<n>`.
pub const fn device_badge(n: u32) -> u32 {
    n + 1
}

/// The endpoint a topology row declares for the audio server.
pub const ENDPOINT: &str = "endpoint.audio";

/// The name that endpoint has in the kernel's pool.
pub const ENDPOINT_NAME: &str = "audio";

/// What a `Lent<ReadyQueue>` names: a queue of [`Period`] slots, the client its
/// producer. The server needs `READ` on it, and maps it.
pub struct ReadyQueue;
/// What a `Lent<DoneQueue>` names: a queue of [`Period`] slots, the server its
/// producer. The server needs `WRITE` on it, and maps it.
pub struct DoneQueue;
/// What a `Lent<Arena>` names: the memory object the periods live in. The
/// server needs `READ` on it for a playback stream and `WRITE` for a capture
/// stream.
pub struct Arena;

/// The rights a client lends each queue with: `READ|WRITE|MAP`. Both ends of
/// a ring write its memory (the producer its head, the consumer its tail), so
/// a server that maps a queue maps it read-write; one lent without `WRITE`
/// is refused (`BAD_ARGUMENT`) rather than faulted on.
pub const QUEUE_RIGHTS: u16 = CapPerms::RW.union(CapPerms::MAP).bits() as u16;

/// The rights a client lends the arena with for a stream of direction `dir`:
/// `READ|MAP` for playback (the server only reads the samples), and
/// `READ|WRITE|MAP` for capture (the server writes them).
pub const fn arena_rights(dir: u32) -> u16 {
    let rights = if dir == DIR_CAPTURE { CapPerms::RW } else { CapPerms::READ };
    rights.union(CapPerms::MAP).bits() as u16
}

/// [`Params::dir`] and [`Info::dirs`]: audio goes out.
pub const DIR_PLAYBACK: u32 = 1;
/// [`Params::dir`] and [`Info::dirs`]: audio comes in. Needs the microphone
/// effect.
pub const DIR_CAPTURE: u32 = 2;

/// [`Params::format`]: signed 16-bit, 2 bytes a sample.
pub const FMT_S16: u32 = 1;
/// [`Params::format`]: signed 24-bit in the low bytes of a 32-bit word,
/// 4 bytes a sample.
pub const FMT_S24: u32 = 2;
/// [`Params::format`]: signed 32-bit, 4 bytes a sample.
pub const FMT_S32: u32 = 3;
/// [`Params::format`]: IEEE-754 single, 4 bytes a sample.
pub const FMT_F32: u32 = 4;
/// The bit of format `f` in [`Info::formats`].
pub const fn format_bit(format: u32) -> u32 {
    1 << format
}
/// Every format of this interface, as [`Info::formats`] spells a set.
pub const FORMATS_ALL: u32 =
    format_bit(FMT_S16) | format_bit(FMT_S24) | format_bit(FMT_S32) | format_bit(FMT_F32);

/// Bytes of one sample of `format`; `None` for a format this interface does
/// not define.
pub const fn sample_bytes(format: u32) -> Option<u32> {
    match format {
        FMT_S16 => Some(2),
        FMT_S24 | FMT_S32 | FMT_F32 => Some(4),
        _ => None,
    }
}

/// Lowest sample rate a stream may name, Hz. Equal to the lower bound of
/// `azos_topology::AUDIO_RATE_HZ`, which bounds the `[audio.NAME]` row the
/// device comes from.
pub const RATE_HZ_MIN: u32 = 8_000;
/// Highest sample rate a stream may name, Hz (`azos_topology::AUDIO_RATE_HZ`).
pub const RATE_HZ_MAX: u32 = 384_000;
/// Most channels of a stream (`azos_topology::AUDIO_CHANNELS_MAX`).
pub const CHANNELS_MAX: u32 = 32;
/// Fewest frames of a period.
pub const PERIOD_FRAMES_MIN: u32 = 16;
/// Most frames of a period.
pub const PERIOD_FRAMES_MAX: u32 = 16_384;
/// Fewest periods of a stream: one being played or filled and one being
/// posted.
pub const PERIODS_MIN: u32 = 2;
/// Most periods of a stream. The bound of [`Posted`], one bit a period.
pub const PERIODS_MAX: u32 = 64;
/// Most bytes of an arena. The audio server's own ceiling
/// (Kconfig `AUDIO_ARENA_KB_MAX`) is at most this.
pub const ARENA_BYTES_MAX: u64 = 16 << 20;

const _: () = assert!(PERIODS_MAX <= u64::BITS, "Posted holds one bit a period");

/// Words of one slot of either queue: half a cache line.
pub const SLOT_WORDS: usize = 4;
/// `Period::index` of the end marker the server returns when a drain ends.
pub const NO_PERIOD: u32 = u32::MAX;

/// `Period::flags`, on a returned period: an xrun happened before it (playback
/// went silent for want of a period, capture lost frames).
pub const PERIOD_XRUN: u32 = 1;
/// `Period::flags`, on a returned period: it was not played or filled to the
/// end because the stream was stopped, or drained in capture. `frames` is how
/// much was (0 when none).
pub const PERIOD_CANCELLED: u32 = 2;
/// `Period::flags`, on the end marker only: the drain is over, the stream is
/// `OPEN` again and every period is the client's.
pub const PERIOD_END: u32 = 4;
const PERIOD_FLAGS_ALL: u32 = PERIOD_XRUN | PERIOD_CANCELLED | PERIOD_END;

/// [`Status::state`]: no stream is open on the capability.
pub const STATE_CLOSED: u32 = 0;
/// [`Status::state`]: open, nothing moving.
pub const STATE_OPEN: u32 = 1;
/// [`Status::state`]: running.
pub const STATE_RUNNING: u32 = 2;
/// [`Status::state`]: draining.
pub const STATE_DRAINING: u32 = 3;

/// What a device can do, from its topology row and its hardware: the answer
/// of [`Sound::info`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Info {
    /// `DIR_*` bits the device has.
    pub dirs: u32,
    /// The formats it takes, as [`format_bit`] bits.
    pub formats: u32,
    /// The one sample rate it runs at (the `[audio.NAME]` row's), Hz.
    pub rate_hz: u32,
    /// The one channel count it runs with.
    pub channels: u32,
    /// The shortest period it takes, frames.
    pub period_frames_min: u32,
    /// The longest period it takes, frames.
    pub period_frames_max: u32,
}

impl Wire for Info {
    const WORDS: usize = 6;
    const CAPS: usize = 0;
    fn put(&self, w: &mut Writer<'_>) {
        self.dirs.put(w);
        self.formats.put(w);
        self.rate_hz.put(w);
        self.channels.put(w);
        self.period_frames_min.put(w);
        self.period_frames_max.put(w);
    }
    fn get(r: &mut Reader<'_>) -> Self {
        let dirs = u32::get(r);
        let formats = u32::get(r);
        let rate_hz = u32::get(r);
        let channels = u32::get(r);
        let period_frames_min = u32::get(r);
        Info { dirs, formats, rate_hz, channels, period_frames_min, period_frames_max: u32::get(r) }
    }
}

/// The stream a client asks for: the argument of [`Sound::open`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Params {
    /// Exactly one of [`DIR_PLAYBACK`], [`DIR_CAPTURE`].
    pub dir: u32,
    /// `FMT_*`.
    pub format: u32,
    /// Sample rate, Hz.
    pub rate_hz: u32,
    /// Channels per frame.
    pub channels: u32,
    /// Frames in one period.
    pub period_frames: u32,
    /// Periods in the arena.
    pub periods: u32,
}

/// Two `u32` fields in one word, the first in the low half.
fn pair(lo: u32, hi: u32) -> u64 {
    u64::from(lo) | u64::from(hi) << 32
}

/// [`pair`] taken apart.
fn unpair(w: u64) -> (u32, u32) {
    (w as u32, (w >> 32) as u32)
}

/// Three words, two fields in each: with the three lent objects' presence
/// words and `on_behalf`, `open` fills the message's inline words exactly.
impl Wire for Params {
    const WORDS: usize = 3;
    const CAPS: usize = 0;
    fn put(&self, w: &mut Writer<'_>) {
        w.word(pair(self.dir, self.format));
        w.word(pair(self.rate_hz, self.channels));
        w.word(pair(self.period_frames, self.periods));
    }
    fn get(r: &mut Reader<'_>) -> Self {
        let (dir, format) = unpair(r.word());
        let (rate_hz, channels) = unpair(r.word());
        let (period_frames, periods) = unpair(r.word());
        Params { dir, format, rate_hz, channels, period_frames, periods }
    }
}

/// What [`Params`] amount to in bytes and slots.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Geometry {
    /// Bytes of one frame: `channels * sample_bytes(format)`.
    pub frame_bytes: u32,
    /// Frames in one period.
    pub period_frames: u32,
    /// Bytes of one period.
    pub period_bytes: u32,
    /// Periods in the arena.
    pub periods: u32,
    /// Bytes of the arena: `periods * period_bytes`.
    pub arena_bytes: u64,
    /// Slots of each queue: the periods plus the one slot of the drain end
    /// marker (it is not a period), rounded up to the power of two a
    /// `SpscSlots` ring needs. The client never has more periods posted than
    /// `periods`, so at most `periods` slots are ever occupied by periods and
    /// the end marker still finds a free slot on `done` with every period
    /// already returned unconsumed: neither queue can be full when it pushes.
    pub queue_slots: u32,
}

impl Params {
    /// The geometry of the stream, or `BAD_ARGUMENT` when a parameter is
    /// outside the bounds of this module: not exactly one direction, an
    /// undefined format, a rate, channel count, period length or period count
    /// outside its range, or an arena over [`ARENA_BYTES_MAX`]. Whether the
    /// *device* can do it is [`Info`]'s question (`UNSUPPORTED`), not this
    /// one's: the server checks the bounds first, so nothing it computes from
    /// a hostile parameter wraps.
    pub fn check(&self) -> Result<Geometry, u32> {
        let one_dir = self.dir == DIR_PLAYBACK || self.dir == DIR_CAPTURE;
        let Some(sample) = sample_bytes(self.format) else { return Err(BAD_ARGUMENT) };
        let in_range = |v: u32, lo: u32, hi: u32| (lo..=hi).contains(&v);
        if !one_dir
            || !in_range(self.rate_hz, RATE_HZ_MIN, RATE_HZ_MAX)
            || !in_range(self.channels, 1, CHANNELS_MAX)
            || !in_range(self.period_frames, PERIOD_FRAMES_MIN, PERIOD_FRAMES_MAX)
            || !in_range(self.periods, PERIODS_MIN, PERIODS_MAX)
        {
            return Err(BAD_ARGUMENT);
        }
        // At most 32 * 4 * 16_384: fits u32.
        let frame_bytes = self.channels * sample;
        let period_bytes = frame_bytes * self.period_frames;
        let arena_bytes = u64::from(period_bytes) * u64::from(self.periods);
        if arena_bytes > ARENA_BYTES_MAX {
            return Err(BAD_ARGUMENT);
        }
        Ok(Geometry {
            frame_bytes,
            period_frames: self.period_frames,
            period_bytes,
            periods: self.periods,
            arena_bytes,
            queue_slots: (self.periods + 1).next_power_of_two(),
        })
    }
}

impl Geometry {
    /// Where period `index` starts in the arena; `None` for an index the
    /// arena has no period for.
    pub fn period_offset(&self, index: u32) -> Option<u64> {
        (index < self.periods).then(|| u64::from(index) * u64::from(self.period_bytes))
    }
}

/// One slot of either queue: a period of the arena and what became of it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Period {
    /// Which period of the arena (below `periods`), or [`NO_PERIOD`] on the
    /// end marker.
    pub index: u32,
    /// Posted: playback, frames to play (1..=`period_frames`); capture, the
    /// room, which is `period_frames`. Returned: frames played or captured.
    pub frames: u32,
    /// Posted: zero. Returned: `PERIOD_*`.
    pub flags: u32,
    /// Posted: zero. Returned: nanoseconds on the monotonic clock at which the
    /// first frame was played (playback) or captured (capture); 0 when the
    /// device cannot say.
    pub time_ns: u64,
}

impl Period {
    /// The queue slot: the fields in order.
    pub fn to_slot(&self) -> [u64; SLOT_WORDS] {
        [self.index as u64, self.frames as u64, self.flags as u64, self.time_ns]
    }

    /// The period in a slot. `None` when a field does not fit its type or a
    /// flag is not one this interface defines: a slot the other end wrote
    /// wrong is refused, not guessed at.
    pub fn from_slot(s: &[u64; SLOT_WORDS]) -> Option<Period> {
        let flags = u32::try_from(s[2]).ok()?;
        if flags & !PERIOD_FLAGS_ALL != 0 {
            return None;
        }
        Some(Period { index: u32::try_from(s[0]).ok()?, frames: u32::try_from(s[1]).ok()?, flags, time_ns: s[3] })
    }

    /// Whether a period the client posted is one the server may touch:
    /// the index names a period of `geo`, the frames are 1..=`period_frames`
    /// (a capture post is the full `period_frames`), and flags and time are
    /// zero. `Err` is the outcome code (`BAD_ARGUMENT`); the server checks
    /// before it reads or writes the arena, so a hostile slot reaches no byte
    /// outside it. That the period is not already posted is [`Posted`]'s.
    pub fn check(&self, geo: &Geometry, dir: u32) -> Result<(), u32> {
        let frames_ok = match dir {
            DIR_CAPTURE => self.frames == geo.period_frames,
            _ => (1..=geo.period_frames).contains(&self.frames),
        };
        if geo.period_offset(self.index).is_none() || !frames_ok || self.flags != 0 || self.time_ns != 0 {
            return Err(BAD_ARGUMENT);
        }
        Ok(())
    }
}

/// The periods the server holds now, one bit each. A period is posted once
/// and returned once; a second post of one still held is the client lying
/// about what it owns, and the server drops the slot.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Posted(u64);

impl Posted {
    /// No period held.
    pub const fn new() -> Posted {
        Posted(0)
    }

    /// Take period `index` (below [`PERIODS_MAX`]). `false` when it is
    /// already held, or `index` is no period: nothing changes.
    pub fn post(&mut self, index: u32) -> bool {
        if index >= PERIODS_MAX || self.0 & (1 << index) != 0 {
            return false;
        }
        self.0 |= 1 << index;
        true
    }

    /// Give period `index` back. `false` when it was not held.
    pub fn give_back(&mut self, index: u32) -> bool {
        if index >= PERIODS_MAX || self.0 & (1 << index) == 0 {
            return false;
        }
        self.0 &= !(1 << index);
        true
    }

    /// Periods held.
    pub fn held(&self) -> u32 {
        self.0.count_ones()
    }
}

/// [`capture_reason`]: admitted.
pub const MIC_ADMITTED: u32 = 0;
/// [`capture_reason`]: the requester's class has no microphone effect (its
/// `mic` envelope ceiling is `contained`).
pub const MIC_NO_GRANT: u32 = 1;
/// [`capture_reason`]: the indicator that tells the person a microphone is
/// live is not available.
pub const MIC_NO_INDICATOR: u32 = 2;
/// [`capture_reason`]: another task holds the device exclusively.
pub const MIC_HELD: u32 = 3;
/// A refusal that comes before [`capture_reason`] has a subject to ask about:
/// the call `on_behalf` names is not one the caller is serving, so there is no
/// requester (see [`capture_subject`]).
pub const MIC_NO_REQUEST: u32 = 4;

/// Whose `mic` effect decides a capture open, and whom the record and the
/// indicator name. `caller` is the task that called the device; `on_behalf` is
/// the open's argument of that name, and `served` maps it to the task that made
/// the call it names, when the caller is the one serving that call. `None` is a
/// request with no requester ([`MIC_NO_REQUEST`]).
pub fn capture_subject(caller: u32, on_behalf: u64, served: impl FnOnce(u64) -> Option<u32>) -> Option<u32> {
    if on_behalf == 0 {
        Some(caller)
    } else {
        served(on_behalf)
    }
}

/// Why a capture stream is admitted or refused: the `reason` word of the
/// `audio-capture` decision record. The order is the contract: no grant is
/// reported before a missing indicator, a missing indicator before a held
/// device, so a task without the effect learns nothing about the device. A
/// capture never opens while the person cannot be told it is live.
pub const fn capture_reason(mic_effect: bool, indicator: bool, held_by_other: bool) -> u32 {
    if !mic_effect {
        MIC_NO_GRANT
    } else if !indicator {
        MIC_NO_INDICATOR
    } else if held_by_other {
        MIC_HELD
    } else {
        MIC_ADMITTED
    }
}

/// What [`Sound::open`] settled.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Opened {
    /// Bytes of one period, as the server computed them from [`Params`]: a
    /// client that disagrees has the wrong format.
    pub period_bytes: u32,
    /// Frames between a frame leaving the arena and reaching the converter
    /// (playback), or between the converter and the arena (capture), at the
    /// moment of the open; 0 when the device cannot say.
    pub latency_frames: u32,
}

impl Wire for Opened {
    const WORDS: usize = 2;
    const CAPS: usize = 0;
    fn put(&self, w: &mut Writer<'_>) {
        self.period_bytes.put(w);
        self.latency_frames.put(w);
    }
    fn get(r: &mut Reader<'_>) -> Self {
        let period_bytes = u32::get(r);
        Opened { period_bytes, latency_frames: u32::get(r) }
    }
}

/// What a stream counted.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Status {
    /// `STATE_*`.
    pub state: u32,
    /// Xruns since `open`.
    pub xruns: u32,
    /// Frames played or captured since `open`.
    pub frames: u64,
}

impl Wire for Status {
    const WORDS: usize = 3;
    const CAPS: usize = 0;
    fn put(&self, w: &mut Writer<'_>) {
        self.state.put(w);
        self.xruns.put(w);
        self.frames.put(w);
    }
    fn get(r: &mut Reader<'_>) -> Self {
        let state = u32::get(r);
        let xruns = u32::get(r);
        Status { state, xruns, frames: u64::get(r) }
    }
}

#[azos_interface(id = 0x534F_554E, level = 1)]
pub trait Sound {
    /// What the device behind the capability can do. Needs `READ`.
    #[idempotent]
    fn info(&self) -> Out<Info>;
    /// Open the stream `params` on the three objects the client lends: the
    /// `ready` queue (the server consumes), the `done` queue (the server
    /// produces) and the `arena`, each at least the size `Params::check`
    /// computes and lent with the rights named at the types (`BAD_ARGUMENT`
    /// otherwise, and for one not lent at all). The stream is `OPEN`, not
    /// running. `BUSY` while a stream is
    /// open on the capability. Capture needs the microphone effect of the
    /// requester's class (`REFUSED` without it). `on_behalf` is 0 for every
    /// client; a server that opens the stream for a client passes the warrant
    /// of the call it is serving (the module doc, "Capture needs the
    /// microphone effect, the requester's"), and a playback open names none
    /// (`BAD_ARGUMENT`). Needs `WRITE`.
    #[once_only]
    #[on_failure(degrade)]
    #[deadline_ns = 20_000_000]
    #[budget_us = 500]
    fn open(
        &mut self,
        params: Params,
        ready: Lent<ReadyQueue>,
        done: Lent<DoneQueue>,
        arena: Lent<Arena>,
        on_behalf: u64,
    ) -> Out<Opened>;
    /// Start moving periods: `OPEN` becomes `RUNNING`. Served when already
    /// running; `NOT_READY` with no stream open; `BUSY` while draining. Needs
    /// `WRITE`.
    #[idempotent]
    fn start(&mut self) -> Out<()>;
    /// Stop at once: the stream is `OPEN`, and every period the server still
    /// holds comes back [`PERIOD_CANCELLED`]. Served when not running. Needs
    /// `WRITE`.
    #[idempotent]
    #[deadline_ns = 2_000_000]
    #[budget_us = 100]
    fn stop(&mut self) -> Out<()>;
    /// Finish what is posted and stop: the stream is `DRAINING` until the end
    /// marker ([`PERIOD_END`]) arrives on `done`, then `OPEN`. Answers when
    /// the drain has begun, not when it ends. Served when already draining;
    /// `NOT_READY` with no stream open. Needs `WRITE`.
    #[idempotent]
    fn drain(&mut self) -> Out<()>;
    /// Stop, let go of the three objects and leave the capability free to
    /// `open` again. Served when no stream is open. Needs `WRITE`.
    #[idempotent]
    fn close(&mut self) -> Out<()>;
    /// What the stream counted. Needs `READ`.
    #[idempotent]
    fn status(&self) -> Out<Status>;
}

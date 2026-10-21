// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! VirtIO sound (device id 25, virtio 1.2 section 5.14): PCM playback and
//! capture, over the memory-object periods of the `Sound` interface
//! (`azos_devif::sound`).
//!
//! # What the device is
//!
//! One control queue (jack, PCM and channel-map information, and the PCM
//! state machine `SET_PARAMS -> PREPARE -> START -> STOP -> RELEASE`), an event
//! queue (not used: leaving a queue unready is legal), a tx queue (playback
//! periods) and an rx queue (capture periods). The driver reads the jack, PCM
//! and channel-map items once at bring-up ([`Device::start`]): which streams
//! the device has, in which direction, with which formats, rates and channel
//! counts, whether a jack is plugged in.
//!
//! # A period is one descriptor chain, zero-copy
//!
//! The arena the `Sound` client made is physically contiguous (`Contig` memory
//! object) and the kernel host pins it, so the bus address of period `i` is
//! `arena_bus + i * period_bytes`. A period posted to the device is three
//! descriptors: the `virtio_snd_pcm_xfer` header (the stream id, read by the
//! device, one buffer per direction shared by every chain), the period's
//! bytes (read by the device for playback, written for capture) and the
//! `virtio_snd_pcm_status` the device fills (one per in-flight chain). The
//! chains in flight are bounded by the descriptors ([`SLOTS`]); a period the
//! queue has no room for stays in the client's `ready` queue until a
//! completion frees one ([`Device::room`]).
//!
//! # Interrupts
//!
//! A completion raises the device's interrupt: [`irq`] (virtio-mmio line) or
//! [`msi_irq`] (virtio-pci MSI-X vector) acknowledges it, wakes the task
//! waiting for a control answer and tells the kernel whether to wake the
//! `dev-pump` task. **The handler takes no lock and reaps nothing.** The pump
//! (task context) reaps the used rings ([`Device::reap`]) and moves the
//! completed periods to the client's `done` queue, which is a memory-object
//! operation an interrupt may not do.
//!
//! # Waiting
//!
//! A control request (one in flight, serialised by a sleeping lock) is waited
//! for with `DeviceWait`'s pattern: list the task, re-check the used ring, and
//! only then block (`set_hooks` supplies the kernel's block and wake), bounded
//! by [`WAIT_MS`]. A device that answers nothing within it is dead: every
//! period in flight comes back cancelled and nothing is sent to it again.
//! Before the scheduler runs (bring-up) the wait spins.
//!
//! # Stop and drain
//!
//! `STOP` leaves queued buffers in the device. To give every period back
//! "at once" with [`PERIOD_CANCELLED`] the driver follows it with `RELEASE`
//! (the device completes all pending I/O of the stream before it answers) and
//! `PREPARE` (back to the state `open` leaves). A capture drain does the same
//! but keeps what the buffer being filled holds (a short period). A playback
//! drain sends nothing until the posted periods have all completed.
//!
//! # Transports
//!
//! virtio-mmio ([`init_at`], bound by the hardware bus for `virtio:25`) and
//! virtio-pci ([`init_pci`], `1af4:1059`) differ only in how the device is
//! negotiated, its queues are registered and its doorbell is rung; everything
//! after is shared. Behind QEMU's virtio-mmio the transport must not be legacy
//! (`-global virtio-mmio.force-legacy=false`): the sound device has no legacy
//! interface.

// The vf2 and k1 boards carry no virtio-sound device: `init_at` refuses every
// window.
#![cfg_attr(any(feature = "vf2", feature = "k1"), allow(unused_imports, dead_code))]

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};

use azos_devif::sound::{
    self as iface, Geometry, Params, Period, Posted, Status as StreamStatus, DIR_CAPTURE, DIR_PLAYBACK,
    PERIOD_CANCELLED, PERIOD_XRUN, PERIODS_MAX,
};
use azos_dma::Direction;
use azos_drv_api::block::DeviceWait;
use azos_drv_sys::{kprintln, timebase};
use azos_sync::kmutex::Mutex;
use azos_sync::SpinLock;

use super::snd_proto as p;
use super::{
    init_with, mmio_read, mmio_write, probe, virtq_alloc_desc, virtq_device_wants_kick, virtq_free_desc,
    virtq_has_used, virtq_init_sized, virtq_notify_mmio, virtq_poll_with_len, virtq_publish, Dma, VirtioDev, Virtq,
    VIRTIO_DEV_SND, VIRTIO_MMIO_INTERRUPT_ACK, VIRTIO_MMIO_INTERRUPT_STATUS, VIRTIO_MMIO_STATUS,
    VIRTIO_STATUS_DRIVER_OK, VIRTQ_CAPACITY, VIRTQ_DESC_F_NEXT, VIRTQ_DESC_F_WRITE,
};

/// How long the device may take to answer a control request before it is
/// given up on. Generous on purpose: the limit is read off the guest's clock,
/// which a virtual-time (`-icount`) run advances faster than the host serves
/// the queue.
pub const WAIT_MS: u64 = 1000;

/// Entries of the control, tx and rx queues (QEMU offers 64).
pub const QUEUE_SIZE: usize = if VIRTQ_CAPACITY < 64 { VIRTQ_CAPACITY } else { 64 };
/// Periods in flight in one direction: a chain is three descriptors.
pub const SLOTS: usize = QUEUE_SIZE / 3;
const _: () = assert!(SLOTS >= 2 && SLOTS <= 32, "the busy mask is a u32 and a stream needs two periods");
const _: () = assert!(QUEUE_SIZE.is_power_of_two());

const PLAY: usize = 0;
const REC: usize = 1;
const DIRS: usize = 2;

/// The queue index (device numbering) of direction `d`'s I/O queue.
const fn io_queue(d: usize) -> u32 {
    if d == PLAY { p::VQ_TX } else { p::VQ_RX }
}

fn dir_index(dir: u32) -> Option<usize> {
    match dir {
        DIR_PLAYBACK => Some(PLAY),
        DIR_CAPTURE => Some(REC),
        _ => None,
    }
}

/// Streams, jacks and channel maps asked about at bring-up: a device with
/// more is read up to these.
const STREAMS_READ: u32 = 8;
const JACKS_READ: u32 = 8;
const CHMAPS_READ: u32 = 16;

// ── Errors ───────────────────────────────────────────────────────────────

/// Why a run-time call did not do what it was asked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// No device is up, or it died.
    NoDevice,
    /// The direction has a stream open already.
    Busy,
    /// The device cannot do it: a direction it lacks, a format, rate or
    /// channel count outside what it reports (or it answered `NOT_SUPP`).
    Unsupported,
    /// The parameters are wrong (or the device answered `BAD_MSG`).
    BadArgument,
    /// The call does not apply in the stream's state.
    NotReady,
    /// The device failed the request or did not answer.
    Fault,
}

/// Why a bring-up did not produce a device.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InitError {
    /// A device is already up.
    Busy,
    /// Not a virtio-sound device, or the wrong kind of window.
    NotSound,
    /// A legacy (version 1) virtio-mmio window.
    Legacy,
    /// `FEATURES_OK` refused.
    Features,
    /// A DMA mapping was refused or the domain would not start.
    Dma,
    /// No memory for a ring.
    NoMemory,
    /// A queue could not be set up.
    Queue,
    /// The device answered a bring-up query wrongly or not at all.
    Query(&'static str),
    #[cfg(all(feature = "pci", target_os = "none"))]
    Pci(&'static str),
}

// ── DMA buffers ──────────────────────────────────────────────────────────

/// A buffer alone in its cache lines: behind a non-coherent device the CPU
/// maintains the caches of each separately.
#[repr(C, align(128))]
struct Line<const N: usize>([u8; N]);

impl<const N: usize> Line<N> {
    const fn new() -> Self {
        Line([0; N])
    }
}

/// The sample formats the `Sound` interface defines, as the device's bit
/// numbers.
fn wire_format(format: u32) -> Option<u8> {
    match format {
        iface::FMT_S16 => Some(p::FMT_S16),
        iface::FMT_S24 => Some(p::FMT_S24),
        iface::FMT_S32 => Some(p::FMT_S32),
        iface::FMT_F32 => Some(p::FMT_FLOAT),
        _ => None,
    }
}

/// Which `Sound` formats a device with the format map `formats` takes
/// (`azos_devif::sound::format_bit` bits).
fn sound_formats(info: &p::PcmInfo) -> u32 {
    [iface::FMT_S16, iface::FMT_S24, iface::FMT_S32, iface::FMT_F32]
        .iter()
        .filter(|&&f| wire_format(f).is_some_and(|w| info.has_format(w)))
        .fold(0, |m, &f| m | iface::format_bit(f))
}

// ── Transport ────────────────────────────────────────────────────────────

/// How the doorbell is rung.
#[derive(Clone, Copy)]
enum Transport {
    Mmio(VirtioDev),
    /// virtio-pci: the address of each queue's notify register.
    #[cfg(all(feature = "pci", target_os = "none"))]
    Pci { notify: [usize; 4] },
    /// The host tests' device: the doorbell is nothing, the test steps the
    /// simulated device.
    #[cfg(test)]
    Null,
}

impl Transport {
    fn kick(&self, queue: u32) {
        match *self {
            #[cfg(test)]
            Transport::Null => {
                let _ = queue;
            }
            Transport::Mmio(d) => {
                // SAFETY: `d` is the initialised device's mapped window.
                unsafe { virtq_notify_mmio(&d, queue) }
            }
            #[cfg(all(feature = "pci", target_os = "none"))]
            Transport::Pci { notify } => {
                // SAFETY: the notify register of a mapped BAR.
                unsafe { core::ptr::write_volatile(notify[queue as usize] as *mut u16, queue as u16) }
            }
        }
    }
}

// ── What the device has ──────────────────────────────────────────────────

/// One direction of the device: the first stream it reports in that
/// direction.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct DirCaps {
    present: bool,
    stream_id: u32,
    info: p::PcmInfo,
    /// Channels of the first channel map for the direction (0: none).
    chmap_channels: u8,
}

/// What the device can do, in the terms of the `Sound` interface
/// ([`azos_devif::sound::Info`]).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Caps {
    /// `DIR_*` bits.
    pub dirs: u32,
    /// `format_bit` bits: the formats every present direction takes.
    pub formats: u32,
    /// The one rate the device is run at.
    pub rate_hz: u32,
    /// The one channel count it is run with.
    pub channels: u32,
}

/// The rate and channel count the device is run at: the preferred rate every
/// present direction has (else the first direction's), and the channel count
/// of the first channel map, else stereo where the device has it.
fn run_point(caps: &[DirCaps; DIRS]) -> Option<(u32, u32)> {
    let present: [Option<&DirCaps>; DIRS] = [caps[PLAY].present.then_some(&caps[PLAY]), caps[REC].present.then_some(&caps[REC])];
    let first = present.iter().flatten().next()?;
    let common = present.iter().flatten().fold(u64::MAX, |m, c| m & c.info.rates);
    let rate = p::preferred_rate(common).or_else(|| p::preferred_rate(first.info.rates))?;
    let ch_ok = |n: u32| present.iter().flatten().all(|c| c.info.has_channels(n));
    let channels = match present.iter().flatten().map(|c| c.chmap_channels as u32).find(|&n| n != 0) {
        Some(n) if ch_ok(n) => n,
        _ if ch_ok(2) => 2,
        _ => first.info.channels_min.max(1) as u32,
    };
    Some((rate, channels))
}

// ── Stream state (data queues) ───────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    /// No stream.
    Free,
    /// `open` is talking to the device.
    Opening,
    /// The device is in `PREPARE`: periods may be queued.
    Open,
    /// The device is in `START`.
    Running,
}

/// How periods that complete are accounted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Flush {
    None,
    /// Stop: every period completes `PERIOD_CANCELLED`.
    Cancel,
    /// Capture drain: a period holding data completes short, an empty one
    /// `PERIOD_CANCELLED`.
    Partial,
}

/// What the driver remembers of a chain in flight.
#[derive(Clone, Copy)]
struct Slot {
    period: u32,
    /// Frames queued (playback).
    frames: u32,
    /// The head descriptor of the chain.
    head: u16,
    /// The queue ran dry before this period was posted: flag it.
    xrun: bool,
}

const SLOT_NONE: Slot = Slot { period: 0, frames: 0, head: 0, xrun: false };
const PERIOD_NONE: Period = Period { index: 0, frames: 0, flags: 0, time_ns: 0 };
const GEO_NONE: Geometry = Geometry { frame_bytes: 0, period_frames: 0, period_bytes: 0, periods: 0, arena_bytes: 0, queue_slots: 0 };

/// One direction's stream.
struct Stream {
    phase: Phase,
    flush: Flush,
    draining: bool,
    geo: Geometry,
    /// The arena as the device sees it, and the CPU's address of the same
    /// bytes (cache maintenance behind a non-coherent device).
    arena_bus: u64,
    arena_va: usize,
    posted: Posted,
    /// Bit `i`: slot `i` has a chain the device has not completed.
    busy: u32,
    slots: [Slot; SLOTS],
    /// Which slot the chain headed by descriptor `d` is.
    head_slot: [u8; VIRTQ_CAPACITY],
    /// The queue ran dry while running: the next period posted follows a gap.
    dry: bool,
    xruns: u32,
    frames: u64,
    /// Completions the device got wrong (an id nobody posted).
    bad: u32,
    /// Periods completed and not yet taken by the host, oldest first.
    done: [Period; PERIODS_MAX as usize],
    done_at: usize,
    done_n: usize,
}

impl Stream {
    const fn new() -> Self {
        Stream {
            phase: Phase::Free,
            flush: Flush::None,
            draining: false,
            geo: GEO_NONE,
            arena_bus: 0,
            arena_va: 0,
            posted: Posted::new(),
            busy: 0,
            slots: [SLOT_NONE; SLOTS],
            head_slot: [0; VIRTQ_CAPACITY],
            dry: false,
            xruns: 0,
            frames: 0,
            bad: 0,
            done: [PERIOD_NONE; PERIODS_MAX as usize],
            done_at: 0,
            done_n: 0,
        }
    }

    /// Forget the stream (the arena's mapping is the caller's to undo).
    fn clear(&mut self) {
        *self = Stream::new();
    }

    fn push_done(&mut self, p: Period) {
        // At most `PERIODS_MAX` periods are ever outstanding, so this has room;
        // a full ring means the host never took them: the oldest is lost.
        if self.done_n == self.done.len() {
            self.done_at = (self.done_at + 1) % self.done.len();
            self.done_n -= 1;
            self.bad = self.bad.wrapping_add(1);
        }
        let at = (self.done_at + self.done_n) % self.done.len();
        self.done[at] = p;
        self.done_n += 1;
    }

    fn pop_done(&mut self) -> Option<Period> {
        if self.done_n == 0 {
            return None;
        }
        let p = self.done[self.done_at];
        self.done_at = (self.done_at + 1) % self.done.len();
        self.done_n -= 1;
        Some(p)
    }
}

/// What [`Device::submit`] did with a period.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Submit {
    /// Queued for the device.
    Queued,
    /// The queue has no room: leave the period where it is and look again
    /// after a completion.
    Full,
    /// The period is held already (or its slot is): the client lied about
    /// what it owns; drop the slot.
    Dup,
    /// Not a period this stream has, or the wrong number of frames.
    Bad,
    /// No stream is open in that state (or the device is gone).
    NotOpen,
}

/// The data side: the tx and rx queues, the buffers the device reads and
/// writes with them, and the two streams.
struct Data {
    t: Option<Transport>,
    dma: Dma,
    vq: [Virtq; DIRS],
    /// `virtio_snd_pcm_xfer` (the stream id) of each direction: device-read,
    /// shared by every chain of the direction.
    xfer: [Line<{ p::LEN_XFER }>; DIRS],
    /// `virtio_snd_pcm_status` of each chain in flight.
    status: [[Line<{ p::LEN_PCM_STATUS }>; SLOTS]; DIRS],
    xfer_bus: [u64; DIRS],
    status_bus: [u64; DIRS],
    caps: [DirCaps; DIRS],
    s: [Stream; DIRS],
    dead: bool,
}

// SAFETY: the raw pointers inside (the queues, the doorbell) are used only
// under `Device::data`'s lock.
unsafe impl Send for Data {}

impl Data {
    const fn new() -> Self {
        Data {
            t: None,
            dma: Dma::fallback(),
            vq: [Virtq::zeroed(), Virtq::zeroed()],
            xfer: [const { Line::new() }; DIRS],
            status: [const { [const { Line::new() }; SLOTS] }; DIRS],
            xfer_bus: [0; DIRS],
            status_bus: [0; DIRS],
            caps: [DirCaps { present: false, stream_id: 0, info: p::PcmInfo { formats: 0, rates: 0, direction: 0, channels_min: 0, channels_max: 0 }, chmap_channels: 0 }; DIRS],
            s: [Stream::new(), Stream::new()],
            dead: false,
        }
    }

    fn kick(&self, d: usize) {
        if let Some(t) = &self.t {
            t.kick(io_queue(d));
        }
    }

    /// The status buffer of slot `slot` of direction `d`: the pointer the CPU
    /// reads and the bus address the device writes.
    fn status_ptr(&self, d: usize, slot: usize) -> *const u8 {
        self.status[d][slot].0.as_ptr()
    }

    fn status_bus_of(&self, d: usize, slot: usize) -> u64 {
        self.status_bus[d] + (slot * core::mem::size_of::<Line<{ p::LEN_PCM_STATUS }>>()) as u64
    }

    /// May [`submit`](Self::submit) take another period now?
    fn room(&self, d: usize) -> bool {
        let s = &self.s[d];
        !self.dead
            && matches!(s.phase, Phase::Open | Phase::Running)
            && s.flush == Flush::None
            && s.busy.count_ones() < SLOTS as u32
            && self.vq[d].free_count >= 3
    }

    /// Queue period `index` of direction `d` as a chain: the transfer header,
    /// the period's bytes at `frames` frames (playback: `1..=period_frames`;
    /// capture: the whole period) and the status the device fills. The
    /// doorbell is rung unless the device said it needs none.
    fn submit(&mut self, d: usize, index: u32, frames: u32) -> Submit {
        if self.dead || !matches!(self.s[d].phase, Phase::Open | Phase::Running) || self.s[d].flush != Flush::None {
            return Submit::NotOpen;
        }
        let geo = self.s[d].geo;
        let Some(off) = geo.period_offset(index) else { return Submit::Bad };
        let frames_ok = if d == REC { frames == geo.period_frames } else { (1..=geo.period_frames).contains(&frames) };
        if !frames_ok {
            return Submit::Bad;
        }
        if !self.s[d].posted.post(index) {
            return Submit::Dup;
        }
        let slot = (!self.s[d].busy).trailing_zeros() as usize;
        if slot >= SLOTS || self.vq[d].free_count < 3 {
            self.s[d].posted.give_back(index);
            return Submit::Full;
        }
        let len = if d == REC { geo.period_bytes } else { frames * geo.frame_bytes };
        let data_bus = self.s[d].arena_bus + off;
        let (xfer_bus, status_bus) = (self.xfer_bus[d], self.status_bus_of(d, slot));
        let flags_data = VIRTQ_DESC_F_NEXT | if d == REC { VIRTQ_DESC_F_WRITE } else { 0 };
        // The status is the device's to write; the capture bytes too: drop the
        // CPU's cached copies first, the period's for playback is written back.
        self.status[d][slot].0 = [0; p::LEN_PCM_STATUS];
        let (sp, ap) = (self.status_ptr(d, slot), (self.s[d].arena_va + off as usize) as *const u8);
        // SAFETY: the status buffer is this driver's mapped storage; the
        // period lies inside the arena the host pinned and the driver mapped
        // (`index < periods`, `frames <= period_frames`, checked above).
        unsafe {
            self.dma.sync_for_device(sp, p::LEN_PCM_STATUS, Direction::FromDevice);
            self.dma.sync_for_device(ap, len as usize, if d == REC { Direction::FromDevice } else { Direction::ToDevice });
        }
        let vq = &mut self.vq[d];
        // SAFETY: the queue was initialised by the bring-up and is used only
        // under the lock; the three descriptors are ours until the device
        // returns the chain.
        let head = unsafe {
            let Some(d0) = virtq_alloc_desc(vq) else {
                self.s[d].posted.give_back(index);
                return Submit::Full;
            };
            let Some(d1) = virtq_alloc_desc(vq) else {
                virtq_free_desc(vq, d0);
                self.s[d].posted.give_back(index);
                return Submit::Full;
            };
            let Some(d2) = virtq_alloc_desc(vq) else {
                virtq_free_desc(vq, d0);
                virtq_free_desc(vq, d1);
                self.s[d].posted.give_back(index);
                return Submit::Full;
            };
            let a = vq.desc.add(d0);
            (*a).addr = xfer_bus;
            (*a).len = p::LEN_XFER as u32;
            (*a).flags = VIRTQ_DESC_F_NEXT;
            (*a).next = d1 as u16;
            let b = vq.desc.add(d1);
            (*b).addr = data_bus;
            (*b).len = len;
            (*b).flags = flags_data;
            (*b).next = d2 as u16;
            let c = vq.desc.add(d2);
            (*c).addr = status_bus;
            (*c).len = p::LEN_PCM_STATUS as u32;
            (*c).flags = VIRTQ_DESC_F_WRITE;
            (*c).next = 0;
            virtq_publish(vq, d0);
            d0
        };
        let s = &mut self.s[d];
        s.slots[slot] = Slot { period: index, frames, head: head as u16, xrun: s.dry };
        s.dry = false;
        s.head_slot[head] = slot as u8;
        s.busy |= 1 << slot;
        // SAFETY: as above.
        if unsafe { virtq_device_wants_kick(&self.vq[d]) } {
            self.kick(d);
        }
        Submit::Queued
    }

    /// Take every completion the device has written to direction `d`'s queue:
    /// free the chains, account the periods, queue them for the host. The
    /// number reaped.
    fn reap(&mut self, d: usize) -> usize {
        let mut n = 0;
        // SAFETY: as in `submit`.
        while unsafe { virtq_has_used(&self.vq[d]) } {
            n += 1;
            // `None` for an entry whose id is outside the table: consumed and
            // counted by the poll (`bad_completions`), and the ones behind it
            // still to be read.
            if let Some((head, used)) = unsafe { virtq_poll_with_len(&mut self.vq[d]) } {
                self.complete(d, head, used);
            }
        }
        let s = &mut self.s[d];
        if n != 0 && s.phase == Phase::Running && s.flush == Flush::None && !s.draining && s.posted.held() == 0 {
            // Everything the device was given is played or filled and nothing
            // is behind it: it runs dry (playback goes silent, capture loses
            // frames) until the next period arrives.
            s.dry = true;
        }
        n
    }

    /// One completion: descriptor chain `head`, `used` bytes written by the
    /// device. A head nobody posted is a device fault, counted and ignored.
    fn complete(&mut self, d: usize, head: usize, used: usize) {
        let slot = self.s[d].head_slot[head] as usize;
        let num = self.vq[d].num as usize;
        let live = slot < SLOTS
            && self.s[d].busy >> slot & 1 != 0
            && self.s[d].slots[slot].head as usize == head
            && self.vq[d].desc_used[head];
        if !live {
            self.s[d].bad = self.s[d].bad.wrapping_add(1);
            return;
        }
        // SAFETY: `head < num` (the poll checked) and the chain is ours: its
        // `next` fields were written by `submit`.
        unsafe {
            let vq = &mut self.vq[d];
            let d1 = ((*vq.desc.add(head)).next as usize).min(num - 1);
            let d2 = ((*vq.desc.add(d1)).next as usize).min(num - 1);
            virtq_free_desc(vq, head);
            virtq_free_desc(vq, d1);
            virtq_free_desc(vq, d2);
        }
        // SAFETY: the status buffer is this driver's mapped storage.
        let st = unsafe {
            self.dma.sync_for_cpu(self.status_ptr(d, slot), p::LEN_PCM_STATUS, Direction::FromDevice);
            core::ptr::read_volatile(&self.status[d][slot].0)
        };
        let status = p::pcm_status(&st);
        let s = &mut self.s[d];
        let sl = s.slots[slot];
        let geo = s.geo;
        let ok = status.is_some_and(|x| x.status == p::S_OK);
        let mut frames = if d == REC {
            // The device wrote the bytes, then the status.
            let bytes = used.saturating_sub(p::LEN_PCM_STATUS).min(geo.period_bytes as usize);
            (bytes as u32 / geo.frame_bytes.max(1)).min(geo.period_frames)
        } else if ok {
            sl.frames
        } else {
            0
        };
        let mut flags = 0;
        if !ok && s.flush == Flush::None {
            // The device refused or lost the period (its xrun report).
            flags |= PERIOD_XRUN;
            s.xruns = s.xruns.wrapping_add(1);
            if d == PLAY {
                frames = 0;
            }
        }
        if sl.xrun {
            flags |= PERIOD_XRUN;
            s.xruns = s.xruns.wrapping_add(1);
        }
        match s.flush {
            Flush::None => {}
            Flush::Cancel => {
                flags |= PERIOD_CANCELLED;
                if d == PLAY {
                    frames = 0;
                }
            }
            Flush::Partial => {
                if frames == 0 {
                    flags |= PERIOD_CANCELLED;
                }
            }
        }
        if d == REC && frames != 0 {
            // SAFETY: the period lies inside the pinned, mapped arena.
            unsafe {
                let off = geo.period_offset(sl.period).unwrap_or(0) as usize;
                self.dma.sync_for_cpu((s.arena_va + off) as *const u8, frames as usize * geo.frame_bytes as usize, Direction::FromDevice);
            }
        }
        s.frames += frames as u64;
        s.posted.give_back(sl.period);
        s.busy &= !(1 << slot);
        s.push_done(Period { index: sl.period, frames, flags, time_ns: 0 });
    }

    /// The device will not give these chains back (it is dead, or a flush was
    /// not honoured): every period it still holds comes back cancelled, and
    /// the stream's queue is forgotten, never reused.
    fn abandon(&mut self, d: usize) {
        let s = &mut self.s[d];
        for slot in 0..SLOTS {
            if s.busy >> slot & 1 != 0 {
                let sl = s.slots[slot];
                s.posted.give_back(sl.period);
                s.push_done(Period { index: sl.period, frames: 0, flags: PERIOD_CANCELLED, time_ns: 0 });
            }
        }
        s.busy = 0;
        self.dead = true;
    }
}

// ── The control queue ────────────────────────────────────────────────────

azos_common::ro_hook! {
    /// The kernel's hook: block the caller until woken or the deadline
    /// (timebase ticks); `false` when it cannot block.
    static BLOCK_FN: fn(u64) -> bool;
}
azos_common::ro_hook! {
    /// The kernel's hook: wake task `tid` (interrupt context).
    static WAKE_FN: fn(u32);
}

/// Supply the kernel's block and wake (once). Until then a control request is
/// waited for by polling.
pub fn set_hooks(block_until: fn(u64) -> bool, wake: fn(u32)) {
    BLOCK_FN.set(block_until);
    WAKE_FN.set(wake);
}

/// The task asleep in a control request (the lock lets one at a time in).
static WAITER: DeviceWait = DeviceWait::new();
/// Interrupts are wired: a control wait can sleep to its deadline.
static IRQ_ARMED: AtomicBool = AtomicBool::new(false);
/// Streams open (the interrupt handler asks the kernel to wake the pump only
/// then).
static OPEN_STREAMS: AtomicU32 = AtomicU32::new(0);
static IRQS: AtomicU32 = AtomicU32::new(0);

struct Ctl {
    t: Option<Transport>,
    dma: Dma,
    vq: Virtq,
    req: Line<{ p::REQ_MAX }>,
    resp: Line<{ p::INFO_RESP_MAX }>,
    req_bus: u64,
    resp_bus: u64,
    dead: bool,
}

// SAFETY: the raw pointers inside are used only under `Device::ctl`'s lock.
unsafe impl Send for Ctl {}

fn ticks(ms: u64) -> u64 {
    timebase::TIMER_FREQ * ms / 1000
}

impl Ctl {
    const fn new() -> Self {
        Ctl {
            t: None,
            dma: Dma::fallback(),
            vq: Virtq::zeroed(),
            req: Line::new(),
            resp: Line::new(),
            req_bus: 0,
            resp_bus: 0,
            dead: false,
        }
    }

    /// Wait for the device's used entry; `Some` of the head, `None` after
    /// [`WAIT_MS`].
    fn wait(&mut self) -> Option<usize> {
        azos_sync::lockdep::might_wait_device("virtio-snd control");
        let deadline = timebase::now().saturating_add(ticks(WAIT_MS));
        loop {
            // SAFETY: the queue is initialised and ours under the lock.
            if let Some((head, _)) = unsafe { virtq_poll_with_len(&mut self.vq) } {
                return Some(head);
            }
            let now = timebase::now();
            if now >= deadline {
                return None;
            }
            let tid = azos_sync::waitqueue::caller_tid();
            let Some(block) = BLOCK_FN.get().filter(|_| tid != 0 && tid != u32::MAX) else {
                core::hint::spin_loop();
                continue;
            };
            // A line that is not wired cannot wake us: look again soon.
            let slice = if IRQ_ARMED.load(Ordering::Acquire) { ticks(50) } else { ticks(1) };
            let until = deadline.min(now.saturating_add(slice));
            let vq = &self.vq;
            // Re-check after listing: a completion before the listing raised
            // its interrupt when nobody could be woken.
            // SAFETY: as above, read only.
            WAITER.park(tid, || unsafe { virtq_has_used(vq) }, || block(until));
        }
    }

    /// One request and its `resp_len`-byte answer, waited for: the answer's
    /// status code. `Err(Fault)` for a device that did not answer (it is then
    /// dead) or answered short.
    fn request(&mut self, req: &[u8], resp_len: usize) -> Result<u32, Error> {
        if self.dead || self.t.is_none() {
            return Err(Error::NoDevice);
        }
        debug_assert!(req.len() <= p::REQ_MAX && resp_len <= p::INFO_RESP_MAX && resp_len >= p::RESP_HDR_LEN);
        self.req.0[..req.len()].copy_from_slice(req);
        self.resp.0[..resp_len].fill(0);
        // SAFETY: both ranges are inside the driver's mapped buffers.
        unsafe {
            self.dma.sync_for_device(self.req.0.as_ptr(), req.len(), Direction::ToDevice);
            self.dma.sync_for_device(self.resp.0.as_ptr(), resp_len, Direction::FromDevice);
        }
        // SAFETY: the queue is initialised and ours under the lock.
        unsafe {
            let (Some(d0), Some(d1)) = (virtq_alloc_desc(&mut self.vq), virtq_alloc_desc(&mut self.vq)) else {
                return Err(Error::Fault);
            };
            let a = self.vq.desc.add(d0);
            (*a).addr = self.req_bus;
            (*a).len = req.len() as u32;
            (*a).flags = VIRTQ_DESC_F_NEXT;
            (*a).next = d1 as u16;
            let b = self.vq.desc.add(d1);
            (*b).addr = self.resp_bus;
            (*b).len = resp_len as u32;
            (*b).flags = VIRTQ_DESC_F_WRITE;
            (*b).next = 0;
            virtq_publish(&mut self.vq, d0);
        }
        if let Some(t) = &self.t {
            t.kick(p::VQ_CONTROL);
        }
        let Some(head) = self.wait() else {
            self.dead = true;
            kprintln!("[VIRTIO-SND] no answer in {} ms: device stopped", WAIT_MS);
            return Err(Error::Fault);
        };
        // SAFETY: `head` is the chain published above; its second descriptor
        // is its `next`.
        unsafe {
            let tail = (*self.vq.desc.add(head)).next as usize;
            virtq_free_desc(&mut self.vq, head);
            virtq_free_desc(&mut self.vq, tail);
            self.dma.sync_for_cpu(self.resp.0.as_ptr(), resp_len, Direction::FromDevice);
        }
        p::resp_status(&self.resp.0).ok_or(Error::Fault)
    }

    /// A request whose answer is a bare status, which must be `S_OK`.
    fn command(&mut self, req: &[u8]) -> Result<(), Error> {
        match self.request(req, p::RESP_HDR_LEN)? {
            p::S_OK => Ok(()),
            p::S_NOT_SUPP => Err(Error::Unsupported),
            p::S_BAD_MSG => Err(Error::BadArgument),
            _ => Err(Error::Fault),
        }
    }

    /// An info query (`R_*_INFO`) for item `id`: the item's bytes, in
    /// `self.resp` from byte 4.
    fn info(&mut self, code: u32, id: u32, item_len: usize) -> Result<(), InitError> {
        let q = p::query_info(code, id, 1, item_len as u32);
        match self.request(&q, p::RESP_HDR_LEN + item_len) {
            Ok(p::S_OK) => Ok(()),
            _ => Err(InitError::Query(match code {
                p::R_JACK_INFO => "jack info",
                p::R_PCM_INFO => "pcm info",
                _ => "chmap info",
            })),
        }
    }
}

/// What bring-up read from the device.
struct Found {
    caps: [DirCaps; DIRS],
    jacks: u32,
    jacks_connected: u32,
    chmaps: u32,
    streams: u32,
}

impl Ctl {
    /// Read the jack, PCM and channel-map items the config space counts.
    fn survey(&mut self, cfg: p::Config) -> Result<Found, InitError> {
        let mut caps = [DirCaps::default(); DIRS];
        for id in 0..cfg.streams.min(STREAMS_READ) {
            self.info(p::R_PCM_INFO, id, p::PCM_INFO_LEN)?;
            let Some(info) = p::PcmInfo::parse(&self.resp.0[p::RESP_HDR_LEN..]) else {
                return Err(InitError::Query("pcm info"));
            };
            let d = match info.direction {
                p::D_OUTPUT => PLAY,
                p::D_INPUT => REC,
                _ => continue,
            };
            if !caps[d].present {
                caps[d] = DirCaps { present: true, stream_id: id, info, chmap_channels: 0 };
            }
        }
        let mut jacks_connected = 0;
        for id in 0..cfg.jacks.min(JACKS_READ) {
            self.info(p::R_JACK_INFO, id, p::JACK_INFO_LEN)?;
            if p::JackInfo::parse(&self.resp.0[p::RESP_HDR_LEN..]).is_some_and(|j| j.connected) {
                jacks_connected += 1;
            }
        }
        for id in 0..cfg.chmaps.min(CHMAPS_READ) {
            self.info(p::R_CHMAP_INFO, id, p::CHMAP_INFO_LEN)?;
            let Some(m) = p::ChmapInfo::parse(&self.resp.0[p::RESP_HDR_LEN..]) else { continue };
            let d = if m.direction == p::D_INPUT { REC } else { PLAY };
            if caps[d].present && caps[d].chmap_channels == 0 {
                caps[d].chmap_channels = m.channels;
            }
        }
        Ok(Found { caps, jacks: cfg.jacks, jacks_connected, chmaps: cfg.chmaps, streams: cfg.streams })
    }
}

// ── The device ───────────────────────────────────────────────────────────

/// The virtio-sound device: its control queue (a sleeping lock, held across a
/// request's wait) and its data side (a spin lock, never held across a wait).
/// Lock order: `ctl` before `data`.
pub struct Device {
    ctl: Mutex<Ctl>,
    data: SpinLock<Data>,
}

/// The one device the kernel drives.
static DEVICE: Device = Device::new();

impl Device {
    pub const fn new() -> Self {
        Device { ctl: Mutex::new(Ctl::new()), data: SpinLock::new(Data::new()) }
    }

    /// Read the device's items and publish them: the second half of every
    /// bring-up, with the queues registered and `DRIVER_OK` set.
    fn start(&self, cfg: p::Config) -> Result<Found, InitError> {
        let found = self.ctl.lock().survey(cfg)?;
        self.data.lock().caps = found.caps;
        Ok(found)
    }

    /// What the device can do; `None` without a device, or one with neither
    /// direction.
    pub fn caps(&self) -> Option<Caps> {
        let d = self.data.lock();
        if d.dead || d.t.is_none() {
            return None;
        }
        let (rate_hz, channels) = run_point(&d.caps)?;
        let mut dirs = 0;
        let mut formats = u32::MAX;
        for (i, dir) in [(PLAY, DIR_PLAYBACK), (REC, DIR_CAPTURE)] {
            if d.caps[i].present {
                dirs |= dir;
                formats &= sound_formats(&d.caps[i].info);
            }
        }
        Some(Caps { dirs, formats, rate_hz, channels })
    }

    /// Whether the stream of direction `dir` is open (any phase but free).
    pub fn is_open(&self, dir: u32) -> bool {
        dir_index(dir).is_some_and(|d| self.data.lock().s[d].phase != Phase::Free)
    }

    /// Open the stream `p` (already checked against the interface's bounds,
    /// geometry `geo`) on the arena at physical address `arena_phys`
    /// (`geo.arena_bytes` of it, physically contiguous, pinned by the caller
    /// until [`close`](Self::close)): `SET_PARAMS` then `PREPARE`.
    pub fn open(&self, dir: u32, p: &Params, geo: &Geometry, arena_phys: u64) -> Result<(), Error> {
        let d = dir_index(dir).ok_or(Error::BadArgument)?;
        let mut c = self.ctl.lock();
        let req = {
            let mut data = self.data.lock();
            if data.dead || data.t.is_none() {
                return Err(Error::NoDevice);
            }
            let caps = data.caps[d];
            if !caps.present {
                return Err(Error::Unsupported);
            }
            if data.s[d].phase != Phase::Free {
                return Err(Error::Busy);
            }
            let format = wire_format(p.format).filter(|&f| caps.info.has_format(f)).ok_or(Error::Unsupported)?;
            let rate = p::rate_bit(p.rate_hz).filter(|&r| caps.info.has_rate(r)).ok_or(Error::Unsupported)?;
            if !caps.info.has_channels(p.channels) {
                return Err(Error::Unsupported);
            }
            let (Ok(period_bytes), Ok(buffer_bytes)) = (u32::try_from(geo.period_bytes), u32::try_from(geo.arena_bytes)) else {
                return Err(Error::BadArgument);
            };
            let bus = data
                .dma
                .map_phys(arena_phys, geo.arena_bytes as usize, Direction::Bidirectional)
                .map_err(|_| Error::Fault)?;
            let dma = data.dma;
            data.xfer[d].0 = p::xfer(caps.stream_id);
            // SAFETY: the transfer header is this driver's mapped storage.
            unsafe { dma.sync_for_device(data.xfer[d].0.as_ptr(), p::LEN_XFER, Direction::ToDevice) };
            let s = &mut data.s[d];
            s.clear();
            s.phase = Phase::Opening;
            s.geo = *geo;
            s.arena_bus = bus;
            s.arena_va = azos_mm::addr::phys_to_virt(arena_phys as usize);
            p::set_params(&p::SetParams {
                stream_id: caps.stream_id,
                buffer_bytes,
                period_bytes,
                channels: p.channels as u8,
                format,
                rate,
            })
        };
        let stream_id = self.data.lock().caps[d].stream_id;
        let r = c.command(&req).and_then(|_| c.command(&p::pcm_hdr(p::R_PCM_PREPARE, stream_id)));
        let mut data = self.data.lock();
        match r {
            Ok(()) => {
                data.s[d].phase = Phase::Open;
                OPEN_STREAMS.fetch_add(1, Ordering::AcqRel);
                Ok(())
            }
            Err(e) => {
                let (bus, len) = (data.s[d].arena_bus, data.s[d].geo.arena_bytes as usize);
                data.dma.unmap(bus, len);
                data.s[d].clear();
                Err(e)
            }
        }
    }

    /// `OPEN` becomes `RUNNING`: `START`. Served when already running.
    pub fn start_stream(&self, dir: u32) -> Result<(), Error> {
        let d = dir_index(dir).ok_or(Error::BadArgument)?;
        let mut c = self.ctl.lock();
        let stream_id = {
            let data = self.data.lock();
            if data.dead {
                return Err(Error::NoDevice);
            }
            match data.s[d].phase {
                Phase::Open | Phase::Running if data.s[d].draining => return Err(Error::Busy),
                Phase::Running => return Ok(()),
                Phase::Open => data.caps[d].stream_id,
                _ => return Err(Error::NotReady),
            }
        };
        c.command(&p::pcm_hdr(p::R_PCM_START, stream_id))?;
        let mut data = self.data.lock();
        if data.s[d].phase == Phase::Open {
            data.s[d].phase = Phase::Running;
        }
        Ok(())
    }

    /// Give every period the device holds back at once, cancelled
    /// (`Flush::Cancel`), or keeping what a capture buffer holds
    /// (`Flush::Partial`); the stream ends `OPEN` (`prepared`) or released.
    /// `Ok` also for a stream that is not open (nothing to give back).
    fn flush(&self, c: &mut Ctl, d: usize, mode: Flush, prepared: bool) -> Result<(), Error> {
        let (running, stream_id) = {
            let mut data = self.data.lock();
            if !matches!(data.s[d].phase, Phase::Open | Phase::Running) {
                return Ok(());
            }
            data.s[d].flush = mode;
            (data.s[d].phase == Phase::Running, data.caps[d].stream_id)
        };
        let mut r = Ok(());
        if running {
            r = c.command(&p::pcm_hdr(p::R_PCM_STOP, stream_id));
        }
        if r.is_ok() {
            // The device completes every pending I/O message of the stream
            // before it answers RELEASE.
            r = c.command(&p::pcm_hdr(p::R_PCM_RELEASE, stream_id));
        }
        if r.is_ok() && prepared {
            r = c.command(&p::pcm_hdr(p::R_PCM_PREPARE, stream_id));
        }
        let mut data = self.data.lock();
        data.reap(d);
        if r.is_err() || data.s[d].busy != 0 {
            // A dead device, or one that kept buffers through RELEASE: its
            // periods cannot be got back from it, the host gets them anyway.
            data.abandon(d);
            data.s[d].flush = Flush::None;
            data.s[d].phase = Phase::Open;
            return Err(r.err().unwrap_or(Error::Fault));
        }
        let s = &mut data.s[d];
        s.flush = Flush::None;
        s.draining = false;
        s.dry = false;
        // `PREPARE`d, or released and about to be forgotten by `close`.
        s.phase = Phase::Open;
        Ok(())
    }

    /// Stop at once: the stream is `OPEN` and every period the device held is
    /// in the done list, cancelled. Served when not running.
    pub fn stop(&self, dir: u32) -> Result<(), Error> {
        let d = dir_index(dir).ok_or(Error::BadArgument)?;
        let mut c = self.ctl.lock();
        self.flush(&mut c, d, Flush::Cancel, true)
    }

    /// Begin a drain. Capture: the buffer being filled completes short, the
    /// rest cancelled, and the stream is `OPEN` again at once (the caller then
    /// returns the end marker). Playback: nothing is sent; the stream is
    /// `DRAINING` until [`drained`](Self::drained). `Ok(true)` when the drain
    /// is over already.
    pub fn drain(&self, dir: u32) -> Result<bool, Error> {
        let d = dir_index(dir).ok_or(Error::BadArgument)?;
        let mut c = self.ctl.lock();
        {
            let mut data = self.data.lock();
            if !matches!(data.s[d].phase, Phase::Open | Phase::Running) {
                return Err(Error::NotReady);
            }
            if d == PLAY {
                data.s[d].draining = true;
                return Ok(false);
            }
        }
        self.flush(&mut c, d, Flush::Partial, true).map(|()| true)
    }

    /// A playback drain whose posted periods have all completed (the caller
    /// has also emptied its `ready` queue): [`finish_drain`](Self::finish_drain)
    /// may run.
    pub fn drained(&self, dir: u32) -> bool {
        dir_index(dir).is_some_and(|d| {
            let data = self.data.lock();
            data.s[d].draining && data.s[d].busy == 0
        })
    }

    /// End a playback drain: the device is stopped (`STOP`, `RELEASE`,
    /// `PREPARE`: nothing is in flight) and the stream is `OPEN`.
    pub fn finish_drain(&self, dir: u32) -> Result<(), Error> {
        let d = dir_index(dir).ok_or(Error::BadArgument)?;
        let mut c = self.ctl.lock();
        self.flush(&mut c, d, Flush::Cancel, true)
    }

    /// Stop, release the stream on the device and forget it; undo the arena's
    /// DMA mapping. Served when no stream is open. The periods the device held
    /// are in the done list (cancelled) for a last look.
    pub fn close(&self, dir: u32) -> Result<(), Error> {
        let d = dir_index(dir).ok_or(Error::BadArgument)?;
        let mut c = self.ctl.lock();
        let was_open = matches!(self.data.lock().s[d].phase, Phase::Open | Phase::Running);
        let r = self.flush(&mut c, d, Flush::Cancel, false);
        let mut data = self.data.lock();
        if was_open {
            OPEN_STREAMS.fetch_sub(1, Ordering::AcqRel);
        }
        let (bus, len) = (data.s[d].arena_bus, data.s[d].geo.arena_bytes as usize);
        if was_open || data.s[d].phase == Phase::Opening {
            data.dma.unmap(bus, len);
        }
        data.s[d].clear();
        r
    }

    /// May [`submit`](Self::submit) take a period?
    pub fn room(&self, dir: u32) -> bool {
        dir_index(dir).is_some_and(|d| self.data.lock().room(d))
    }

    pub fn submit(&self, dir: u32, index: u32, frames: u32) -> Submit {
        match dir_index(dir) {
            Some(d) => self.data.lock().submit(d, index, frames),
            None => Submit::Bad,
        }
    }

    /// Reap the used ring of `dir`'s queue; the number of completions.
    pub fn reap(&self, dir: u32) -> usize {
        dir_index(dir).map_or(0, |d| self.data.lock().reap(d))
    }

    /// The next completed period, oldest first.
    pub fn take_done(&self, dir: u32) -> Option<Period> {
        self.data.lock().s[dir_index(dir)?].pop_done()
    }

    /// Whether the stream is draining, and how many periods the device holds.
    pub fn held(&self, dir: u32) -> u32 {
        dir_index(dir).map_or(0, |d| self.data.lock().s[d].posted.held())
    }

    /// `STATE_*` and the counters, as `Sound::status` answers.
    pub fn status(&self, dir: u32) -> StreamStatus {
        let Some(d) = dir_index(dir) else { return StreamStatus::default() };
        let data = self.data.lock();
        let s = &data.s[d];
        let state = match s.phase {
            Phase::Free | Phase::Opening => iface::STATE_CLOSED,
            Phase::Open if s.draining => iface::STATE_DRAINING,
            Phase::Open => iface::STATE_OPEN,
            Phase::Running if s.draining => iface::STATE_DRAINING,
            Phase::Running => iface::STATE_RUNNING,
        };
        StreamStatus { state, xruns: s.xruns, frames: s.frames }
    }

    /// Completions the device got wrong since boot, and whether it died.
    pub fn faults(&self) -> (u32, bool) {
        let data = self.data.lock();
        (data.s.iter().fold(0u32, |a, s| a.wrapping_add(s.bad)) + data.vq.iter().map(|q| q.bad_completions as u32).sum::<u32>(), data.dead)
    }
}

// ── Public entry points on the one device ────────────────────────────────

/// See [`Device::caps`].
pub fn caps() -> Option<Caps> {
    DEVICE.caps()
}
/// See [`Device::is_open`].
pub fn is_open(dir: u32) -> bool {
    DEVICE.is_open(dir)
}
/// See [`Device::open`].
pub fn open(dir: u32, p: &Params, geo: &Geometry, arena_phys: u64) -> Result<(), Error> {
    DEVICE.open(dir, p, geo, arena_phys)
}
/// See [`Device::start_stream`].
pub fn start(dir: u32) -> Result<(), Error> {
    DEVICE.start_stream(dir)
}
/// See [`Device::stop`].
pub fn stop(dir: u32) -> Result<(), Error> {
    DEVICE.stop(dir)
}
/// See [`Device::drain`].
pub fn drain(dir: u32) -> Result<bool, Error> {
    DEVICE.drain(dir)
}
/// See [`Device::drained`].
pub fn drained(dir: u32) -> bool {
    DEVICE.drained(dir)
}
/// See [`Device::finish_drain`].
pub fn finish_drain(dir: u32) -> Result<(), Error> {
    DEVICE.finish_drain(dir)
}
/// See [`Device::close`].
pub fn close(dir: u32) -> Result<(), Error> {
    DEVICE.close(dir)
}
/// See [`Device::room`].
pub fn room(dir: u32) -> bool {
    DEVICE.room(dir)
}
/// See [`Device::submit`].
pub fn submit(dir: u32, index: u32, frames: u32) -> Submit {
    DEVICE.submit(dir, index, frames)
}
/// See [`Device::reap`].
pub fn reap(dir: u32) -> usize {
    DEVICE.reap(dir)
}
/// See [`Device::take_done`].
pub fn take_done(dir: u32) -> Option<Period> {
    DEVICE.take_done(dir)
}
/// See [`Device::held`].
pub fn held(dir: u32) -> u32 {
    DEVICE.held(dir)
}
/// See [`Device::status`].
pub fn status(dir: u32) -> StreamStatus {
    DEVICE.status(dir)
}
/// See [`Device::faults`].
pub fn faults() -> (u32, bool) {
    DEVICE.faults()
}

// ── Interrupts ───────────────────────────────────────────────────────────

/// The virtio-mmio window of the device, once up (its interrupt line is the
/// kernel's to find: `kernel/src/boot/snd_irq.rs`).
static MMIO_BASE: AtomicUsize = AtomicUsize::new(0);
/// The line wired to it (`u32::MAX`: none).
static IRQ_LINE: AtomicU32 = AtomicU32::new(u32::MAX);
/// virtio-pci: the vector's token (`MsiRoute::isr_token`) and whether it is
/// armed.
static MSI_TOKEN: AtomicU32 = AtomicU32::new(0);
static MSI_ARMED: AtomicBool = AtomicBool::new(false);

/// `(slot, base)` of the virtio-mmio transport the device is on, once up.
pub fn mmio_window() -> Option<usize> {
    match MMIO_BASE.load(Ordering::Acquire) {
        0 => None,
        b => Some(b),
    }
}

/// Take completions by interrupt on `line` from now on. Call BEFORE the
/// interrupt controller enables `line` (its handler must already recognise
/// it: [`irq`]); the device's pending interrupt is acknowledged here.
pub fn set_irq_line(line: u32) -> bool {
    let base = MMIO_BASE.load(Ordering::Acquire);
    if base == 0 {
        return false;
    }
    // SAFETY: `base` is the device's mapped virtio-mmio window; the two
    // registers are the interrupt status and acknowledge.
    unsafe {
        let b = base as *mut u32;
        let status = mmio_read(b, VIRTIO_MMIO_INTERRUPT_STATUS);
        mmio_write(b, VIRTIO_MMIO_INTERRUPT_ACK, status);
    }
    IRQ_LINE.store(line, Ordering::Release);
    IRQ_ARMED.store(true, Ordering::Release);
    true
}

/// What every interrupt does, whatever the transport: count, wake the task
/// waiting for a control answer, and say whether the pump has work (a stream
/// is open).
fn on_interrupt() -> bool {
    IRQS.fetch_add(1, Ordering::Relaxed);
    if let Some(wake) = WAKE_FN.get() {
        let tid = WAITER.sleeper();
        if tid != 0 {
            wake(tid);
        }
    }
    OPEN_STREAMS.load(Ordering::Acquire) != 0
}

/// The interrupt handler's arm for `line` (interrupt context, any CPU):
/// `None` when the line is not this device's; otherwise the device is
/// acknowledged and the answer is whether the kernel should wake the pump.
/// Takes no lock.
pub fn irq(line: u32) -> Option<bool> {
    if line != IRQ_LINE.load(Ordering::Acquire) {
        return None;
    }
    let base = MMIO_BASE.load(Ordering::Acquire) as *mut u32;
    // SAFETY: as in `set_irq_line`.
    unsafe {
        let status = mmio_read(base, VIRTIO_MMIO_INTERRUPT_STATUS);
        mmio_write(base, VIRTIO_MMIO_INTERRUPT_ACK, status);
    }
    Some(on_interrupt())
}

/// The virtio-pci arm: `token` is what the interrupt controller reported
/// (`MsiRoute::isr_token`). `None` when it is not this device's vector.
pub fn msi_irq(token: u32) -> Option<bool> {
    if !MSI_ARMED.load(Ordering::Acquire) || MSI_TOKEN.load(Ordering::Relaxed) != token {
        return None;
    }
    Some(on_interrupt())
}

/// Interrupts taken since boot.
pub fn irq_count() -> u32 {
    IRQS.load(Ordering::Relaxed)
}

// ── Bring-up ─────────────────────────────────────────────────────────────

/// Map the driver's DMA buffers through `dma` (once; they live as long as the
/// kernel).
fn map_buffers(c: &mut Ctl, d: &mut Data, dma: Dma) -> Result<(), InitError> {
    c.dma = dma;
    d.dma = dma;
    let map = |ptr: *const u8, len: usize| dma.map(ptr, len, Direction::Bidirectional).map_err(|_| InitError::Dma);
    c.req_bus = map(c.req.0.as_ptr(), core::mem::size_of_val(&c.req))?;
    c.resp_bus = map(c.resp.0.as_ptr(), core::mem::size_of_val(&c.resp))?;
    for i in 0..DIRS {
        d.xfer_bus[i] = map(d.xfer[i].0.as_ptr(), core::mem::size_of_val(&d.xfer[i]))?;
        d.status_bus[i] = map(d.status[i][0].0.as_ptr(), core::mem::size_of_val(&d.status[i]))?;
    }
    Ok(())
}

fn report(transport: impl core::fmt::Display, f: &Found, caps: Option<Caps>) {
    let (rate, ch) = caps.map_or((0, 0), |c| (c.rate_hz, c.channels));
    kprintln!(
        "[VIRTIO-SND] {}: {} streams ({}{}), {} jacks ({} connected), {} chmaps, {} Hz x {} ch",
        transport,
        f.streams,
        if f.caps[PLAY].present { "playback" } else { "no playback" },
        if f.caps[REC].present { ", capture" } else { "" },
        f.jacks,
        f.jacks_connected,
        f.chmaps,
        rate,
        ch
    );
}

/// Bring up the virtio-sound device whose virtio-mmio transport is at `base`.
/// Called by the hardware bus when it binds `virtio-snd` to a device
/// (`kernel/src/boot/hwbus.rs`), in task context, before any line is
/// enabled: the line is the kernel's to wire ([`set_irq_line`]). `Err` for a
/// window that is not a sound device, a second device, or a device that fails
/// its bring-up.
#[cfg(any(feature = "vf2", feature = "k1"))]
pub fn init_at(_base: usize) -> Result<(), InitError> {
    Err(InitError::NotSound)
}

#[cfg(not(any(feature = "vf2", feature = "k1")))]
pub fn init_at(base: usize) -> Result<(), InitError> {
    let r = init_mmio(&DEVICE, base);
    if let Err(e) = r {
        kprintln!("[VIRTIO-SND] virtio-mmio {:#x} not used: {:?}", base, e);
    }
    r
}

#[cfg(not(any(feature = "vf2", feature = "k1")))]
fn init_mmio(dev: &Device, base: usize) -> Result<(), InitError> {
    {
        let c = dev.ctl.lock();
        if c.t.is_some() {
            return Err(InitError::Busy);
        }
    }
    let mut vdev = VirtioDev::zeroed();
    // SAFETY: `base` is a populated virtio-mmio window the bus enumerated.
    if unsafe { probe(base, &mut vdev) }.is_err() || vdev.device_id != VIRTIO_DEV_SND {
        return Err(InitError::NotSound);
    }
    // The sound device has no legacy interface.
    if vdev.version == 1 {
        return Err(InitError::Legacy);
    }
    // SAFETY: the status handshake of the window just probed; no optional
    // feature (the control elements are not used).
    unsafe { init_with(&mut vdev, 0) }.map_err(|_| InitError::Features)?;
    let cfg = {
        let mut c = dev.ctl.lock();
        let mut d = dev.data.lock();
        let dma = Dma::mmio(base);
        map_buffers(&mut c, &mut d, dma)?;
        // SAFETY: queues 0, 2 and 3 of that device; `dma` maps their rings.
        unsafe {
            if virtq_init_sized(&mut vdev, p::VQ_CONTROL, &mut c.vq, QUEUE_SIZE, &dma).is_err()
                || virtq_init_sized(&mut vdev, p::VQ_TX, &mut d.vq[PLAY], QUEUE_SIZE, &dma).is_err()
                || virtq_init_sized(&mut vdev, p::VQ_RX, &mut d.vq[REC], QUEUE_SIZE, &dma).is_err()
            {
                return Err(InitError::Queue);
            }
        }
        dma.enable().map_err(|_| InitError::Dma)?;
        c.t = Some(Transport::Mmio(vdev));
        d.t = c.t;
        // SAFETY: DRIVER_OK after the queues are registered, as the handshake
        // ends; the config space is read after it (3 x u32).
        unsafe {
            let s = mmio_read(vdev.base, VIRTIO_MMIO_STATUS);
            mmio_write(vdev.base, VIRTIO_MMIO_STATUS, s | VIRTIO_STATUS_DRIVER_OK);
            let mut raw = [0u8; p::CONFIG_LEN];
            for i in 0..3 {
                raw[i * 4..i * 4 + 4].copy_from_slice(&super::read_config32(&vdev, i as u32 * 4).to_le_bytes());
            }
            p::Config::parse(&raw).ok_or(InitError::Query("config"))?
        }
    };
    let found = dev.start(cfg)?;
    MMIO_BASE.store(base, Ordering::Release);
    report(format_args!("virtio-mmio {:#x}", base), &found, dev.caps());
    Ok(())
}

/// Bring up the virtio-sound PCI function `info` (`1af4:1059`, modern
/// transport): its BARs are assigned from `window` and mapped, the control,
/// tx and rx queues are registered on one MSI-X vector when `route` can
/// target it (else the queues are polled by the pump).
#[cfg(all(feature = "pci", target_os = "none"))]
pub fn init_pci<C, R>(
    cfg: &mut C,
    info: &azos_pci::FunctionInfo,
    window: &mut azos_pci::BarWindow,
    route: &mut R,
) -> Result<(), InitError>
where
    C: azos_pci::ConfigSpace,
    R: super::pci::msix_selftest::MsiRoute,
{
    let r = init_pci_on(&DEVICE, cfg, info, window, route);
    if let Err(e) = r {
        kprintln!("[VIRTIO-SND] virtio-pci {} not used: {:?}", info.bdf, e);
    }
    r
}

#[cfg(all(feature = "pci", target_os = "none"))]
fn init_pci_on<C, R>(
    dev: &Device,
    cfg: &mut C,
    info: &azos_pci::FunctionInfo,
    window: &mut azos_pci::BarWindow,
    route: &mut R,
) -> Result<(), InitError>
where
    C: azos_pci::ConfigSpace,
    R: super::pci::msix_selftest::MsiRoute,
{
    use super::pci::msix_selftest::{map_bars, KernelBar};
    use super::pci::{
        common_cfg_bar, find_virtio_caps, VirtioPciDevice, VIRTIO_F_ACCESS_PLATFORM_HI_BIT, VIRTIO_PCI_NO_VECTOR,
    };
    use azos_pci::BarMem;

    if dev.ctl.lock().t.is_some() {
        return Err(InitError::Busy);
    }
    if info.vendor != 0x1af4 || info.device != p::PCI_DEVICE {
        return Err(InitError::NotSound);
    }
    let bar_base = map_bars(cfg, info, window).map_err(|_| InitError::Pci("bars"))?;
    let dma = Dma::pci(info.bdf.requester_id());
    let cfg_words = {
        let mut c = dev.ctl.lock();
        let mut d = dev.data.lock();
        map_buffers(&mut c, &mut d, dma)?;

        // One vector for every queue, when the function has MSI-X and the
        // route can target it.
        let msix = info.msix.filter(|m| m.table_size >= 1);
        let irq = msix.is_some() && route.prepare(1);
        if let (true, Some(m)) = (irq, msix) {
            let table_base = bar_base.get(m.table_bar as usize).copied().unwrap_or(0);
            if table_base == 0 {
                return Err(InitError::Pci("msi-x table bar unmapped"));
            }
            let mut table = KernelBar::new(table_base);
            let (addr, data) = route.target(0);
            // The message is a DMA write to the doorbell: a translating domain
            // must let it through.
            dma.allow_msi(addr).map_err(|_| InitError::Dma)?;
            azos_pci::program_msix_entry(&mut table, m.table_offset, 0, addr, data, false);
            let _ = BarMem::read32(&table, m.table_offset as usize);
            azos_pci::msix_set_enable(cfg, info.bdf, &m, true);
        }

        let (caps, n) = find_virtio_caps(cfg, info.bdf);
        let bar = common_cfg_bar(&caps, n).ok_or(InitError::Pci("no virtio capabilities"))?;
        let dev_base = bar_base.get(bar as usize).copied().filter(|&b| b != 0).ok_or(InitError::Pci("bar unmapped"))?;
        let mut pdev = VirtioPciDevice::new(KernelBar::new(dev_base), &caps, n, bar)
            .ok_or(InitError::Pci("capabilities in different BARs"))?;
        pdev.begin(0, VIRTIO_F_ACCESS_PLATFORM_HI_BIT).map_err(|_| InitError::Features)?;
        pdev.set_msix_config_vector(VIRTIO_PCI_NO_VECTOR);

        let vector = if irq { 0 } else { VIRTIO_PCI_NO_VECTOR };
        let mut notify = [0usize; 4];
        let [play, rec] = &mut d.vq;
        const _: () = assert!(PLAY == 0 && REC == 1);
        for (q, vq) in [(p::VQ_CONTROL, &mut c.vq), (p::VQ_TX, play), (p::VQ_RX, rec)] {
            // SAFETY: a fresh queue structure; the rings are mapped through `dma`.
            let (dd, aa, uu) = unsafe { super::virtq_alloc_rings(vq, QUEUE_SIZE as u16, &dma) }.map_err(|_| InitError::NoMemory)?;
            let agreed = pdev.setup_queue(q as u16, QUEUE_SIZE as u16, dd, aa, uu, vector);
            if agreed < 2 {
                pdev.reset();
                return Err(InitError::Queue);
            }
            if agreed < QUEUE_SIZE as u16 {
                // SAFETY: the rings above, re-threaded for the smaller size.
                unsafe { super::virtq_resize(vq, agreed) };
            }
            if irq && pdev.queue_msix_vector(q as u16) != 0 {
                pdev.reset();
                return Err(InitError::Pci("vector refused"));
            }
            let off = pdev.queue_notify_off_of(q as u16);
            notify[q as usize] = dev_base + pdev.queue_notify_offset(off);
        }
        // Three words at the start of the device config: jacks, streams, chmaps.
        let bar_mem = KernelBar::new(dev_base);
        let mut raw = [0u8; p::CONFIG_LEN];
        for i in 0..3 {
            raw[i * 4..i * 4 + 4].copy_from_slice(&BarMem::read32(&bar_mem, pdev.device_cfg + i * 4).to_le_bytes());
        }
        dma.enable().map_err(|_| InitError::Dma)?;
        let t = Transport::Pci { notify };
        c.t = Some(t);
        d.t = Some(t);
        pdev.set_driver_ok();
        if irq {
            MSI_TOKEN.store(route.isr_token(0), Ordering::Relaxed);
            MSI_ARMED.store(true, Ordering::Release);
            IRQ_ARMED.store(true, Ordering::Release);
        }
        p::Config::parse(&raw).ok_or(InitError::Query("config"))?
    };
    let found = dev.start(cfg_words)?;
    report(
        format_args!("virtio-pci {} ({})", info.bdf, if MSI_ARMED.load(Ordering::Acquire) { "irq" } else { "poll" }),
        &found,
        dev.caps(),
    );
    Ok(())
}

// The driver against a device simulated in host memory (the suite that pulls
// this module in, `tests/host/drivers-tests`, builds it with `cfg(test)`):
// request encoding, the period ring, a stop mid-stream, a drain, a dead or
// lying device. What needs the real device -- the doorbell, the interrupt, the
// bring-up of either transport -- is covered by the QEMU rows.
#[cfg(test)]
mod tests {
    use super::*;
    use super::super::{VirtqAvail, VirtqDesc, VirtqUsed, VirtqUsedElem};
    use std::sync::atomic::AtomicBool as StdBool;
    use std::sync::{Arc, Mutex as StdMutex};

    /// The statics (`OPEN_STREAMS`, the MSI token) are shared by every test of
    /// the module.
    static SERIAL: StdMutex<()> = StdMutex::new(());

    const PERIOD_FRAMES: u32 = 64;
    const PERIODS: u32 = 32;
    const FRAME: u32 = 4; // S16 stereo
    const PERIOD_BYTES: u32 = PERIOD_FRAMES * FRAME;

    /// A queue in leaked host memory.
    fn queue(num: u16) -> Virtq {
        let desc = Box::leak(Box::new(core::array::from_fn::<VirtqDesc, VIRTQ_CAPACITY, _>(|_| VirtqDesc {
            addr: 0,
            len: 0,
            flags: 0,
            next: 0,
        })));
        let avail = Box::leak(Box::new(VirtqAvail { flags: 0, idx: 0, ring: [0; VIRTQ_CAPACITY] }));
        let used = Box::leak(Box::new(VirtqUsed {
            flags: 0,
            idx: 0,
            ring: core::array::from_fn::<VirtqUsedElem, VIRTQ_CAPACITY, _>(|_| VirtqUsedElem { id: 0, len: 0 }),
        }));
        for i in 0..num as usize {
            desc[i].next = (i as u16) + 1;
        }
        let mut vq = Virtq::zeroed();
        vq.desc = desc.as_mut_ptr();
        vq.avail = avail;
        vq.used = used;
        vq.num = num;
        vq.free_head = 0;
        vq.free_count = num;
        vq
    }

    /// The device's view of one queue.
    #[derive(Clone, Copy)]
    struct Q {
        desc: *mut VirtqDesc,
        avail: *const VirtqAvail,
        used: *mut VirtqUsed,
        num: u16,
    }
    // SAFETY: the rings are leaked host memory the tests hand to one thread at a time.
    unsafe impl Send for Q {}

    impl Q {
        fn of(vq: &Virtq) -> Q {
            Q { desc: vq.desc, avail: vq.avail, used: vq.used, num: vq.num }
        }
        fn avail_idx(&self) -> u16 {
            // SAFETY: leaked rings.
            unsafe { core::ptr::read_volatile(core::ptr::addr_of!((*self.avail).idx)) }
        }
        fn head_at(&self, n: u16) -> usize {
            // SAFETY: leaked rings.
            unsafe { core::ptr::addr_of!((*self.avail).ring[(n % self.num) as usize]).read_unaligned() as usize }
        }
        /// The descriptors of the chain at `head`: (addr, len, flags).
        fn chain(&self, head: usize) -> Vec<(u64, u32, u16)> {
            let mut out = Vec::new();
            let mut at = head;
            loop {
                // SAFETY: leaked rings; the chain is the driver's.
                let (addr, len, flags, next) = unsafe {
                    let d = self.desc.add(at);
                    (
                        core::ptr::addr_of!((*d).addr).read_unaligned(),
                        core::ptr::addr_of!((*d).len).read_unaligned(),
                        core::ptr::addr_of!((*d).flags).read_unaligned(),
                        core::ptr::addr_of!((*d).next).read_unaligned(),
                    )
                };
                out.push((addr, len, flags));
                if flags & VIRTQ_DESC_F_NEXT == 0 || out.len() > 4 {
                    return out;
                }
                at = next as usize;
            }
        }
        fn push_used(&self, id: u32, len: u32) {
            // SAFETY: leaked rings.
            unsafe {
                let u = core::ptr::addr_of_mut!((*self.used).idx);
                let at = core::ptr::read_volatile(u);
                core::ptr::addr_of_mut!((*self.used).ring[(at % self.num) as usize]).write_unaligned(VirtqUsedElem { id, len });
                core::sync::atomic::fence(Ordering::Release);
                core::ptr::write_volatile(u, at.wrapping_add(1));
            }
        }
    }

    /// What the simulated device answers a request with.
    struct Sim {
        ctl: Q,
        data: [Q; DIRS],
        /// How far into each avail ring (control, tx, rx) the device has looked.
        seen: [u16; 3],
        /// Every control request, in order.
        log: Vec<Vec<u8>>,
        /// Status to answer a request code with (default `S_OK`).
        fail: Vec<(u32, u32)>,
        /// The device answers nothing from now on.
        mute: bool,
        /// Bytes of the first pending capture buffer the RELEASE finds filled.
        flush_fill: u32,
        /// Data-queue chains completed so far, per direction.
        completed: [u16; DIRS],
    }

    impl Sim {
        fn pcm_info(dir: u8) -> Vec<u8> {
            let mut b = vec![0u8; p::PCM_INFO_LEN];
            let formats = (1u64 << p::FMT_S16) | (1 << p::FMT_S32) | (1 << p::FMT_FLOAT);
            let rates = (1u64 << p::RATE_44100) | (1 << p::RATE_48000);
            b[8..16].copy_from_slice(&formats.to_le_bytes());
            b[16..24].copy_from_slice(&rates.to_le_bytes());
            b[24] = dir;
            b[25] = 1;
            b[26] = 2;
            b
        }

        /// Answer every control request not seen yet.
        fn step_ctl(&mut self) {
            if self.mute {
                return;
            }
            let idx = self.ctl.avail_idx();
            while self.seen[0] != idx {
                let head = self.ctl.head_at(self.seen[0]);
                self.seen[0] = self.seen[0].wrapping_add(1);
                let chain = self.ctl.chain(head);
                assert_eq!(chain.len(), 2, "a control request is a request and an answer");
                assert_eq!(chain[0].2, VIRTQ_DESC_F_NEXT, "request: device-readable, chained");
                assert_eq!(chain[1].2, VIRTQ_DESC_F_WRITE, "answer: device-writable");
                // SAFETY: the driver's static buffers, mapped identity on the host.
                let req = unsafe { core::slice::from_raw_parts(chain[0].0 as *const u8, chain[0].1 as usize) }.to_vec();
                let code = u32::from_le_bytes(req[..4].try_into().unwrap());
                let status = self.fail.iter().find(|f| f.0 == code).map_or(p::S_OK, |f| f.1);
                let mut resp = status.to_le_bytes().to_vec();
                match code {
                    p::R_PCM_INFO => resp.extend(Sim::pcm_info(if req[4] == 0 { p::D_OUTPUT } else { p::D_INPUT })),
                    p::R_JACK_INFO => {
                        let mut j = vec![0u8; p::JACK_INFO_LEN];
                        j[16] = 1;
                        resp.extend(j);
                    }
                    p::R_CHMAP_INFO => {
                        let mut m = vec![0u8; p::CHMAP_INFO_LEN];
                        m[4] = if req[4] == 0 { p::D_OUTPUT } else { p::D_INPUT };
                        m[5] = 2;
                        resp.extend(m);
                    }
                    p::R_PCM_RELEASE => {
                        // Every pending I/O message of the stream completes
                        // before the answer.
                        let d = if u32::from_le_bytes(req[4..8].try_into().unwrap()) == 0 { PLAY } else { REC };
                        self.flush(d);
                    }
                    _ => {}
                }
                self.log.push(req);
                let n = resp.len().min(chain[1].1 as usize);
                // SAFETY: as above.
                unsafe { core::ptr::copy_nonoverlapping(resp.as_ptr(), chain[1].0 as *mut u8, n) };
                self.ctl.push_used(head as u32, n as u32);
            }
        }

        /// Complete every pending chain of direction `d`.
        fn flush(&mut self, d: usize) {
            let mut first = true;
            while self.complete(d, p::S_OK, if std::mem::take(&mut first) { Some(self.flush_fill) } else { Some(0) }) {}
        }

        /// Complete the oldest pending chain of direction `d` with `status`;
        /// `fill` bytes of a capture buffer written (`None`: the whole buffer).
        /// `false` when there is none.
        fn complete(&mut self, d: usize, status: u32, fill: Option<u32>) -> bool {
            let q = self.data[d];
            let n = self.completed[d];
            if n == q.avail_idx() {
                return false;
            }
            let head = q.head_at(n);
            self.completed[d] = n.wrapping_add(1);
            let chain = q.chain(head);
            assert_eq!(chain.len(), 3, "a period is the header, the bytes and the status");
            let write_data = d == REC;
            assert_eq!(chain[0].2, VIRTQ_DESC_F_NEXT);
            assert_eq!(chain[1].2, VIRTQ_DESC_F_NEXT | if write_data { VIRTQ_DESC_F_WRITE } else { 0 });
            assert_eq!(chain[2].2, VIRTQ_DESC_F_WRITE);
            let mut used = p::LEN_PCM_STATUS as u32;
            if write_data {
                let n = fill.unwrap_or(chain[1].1).min(chain[1].1);
                // The pattern lets a test see where the bytes landed.
                // SAFETY: the test's arena.
                unsafe { core::ptr::write_bytes(chain[1].0 as *mut u8, 0xA5, n as usize) };
                used += n;
            }
            let mut st = [0u8; 8];
            st[..4].copy_from_slice(&status.to_le_bytes());
            // SAFETY: the driver's status buffer.
            unsafe { core::ptr::copy_nonoverlapping(st.as_ptr(), chain[2].0 as *mut u8, 8) };
            q.push_used(head as u32, used);
            true
        }

        fn pending(&self, d: usize) -> u16 {
            self.data[d].avail_idx().wrapping_sub(self.completed[d])
        }

        fn requests(&self) -> Vec<u32> {
            self.log.iter().map(|r| u32::from_le_bytes(r[..4].try_into().unwrap())).collect()
        }
    }

    struct Rig {
        dev: &'static Device,
        sim: Arc<StdMutex<Sim>>,
        stop: Arc<StdBool>,
        thread: Option<std::thread::JoinHandle<()>>,
        _g: std::sync::MutexGuard<'static, ()>,
        arena: &'static mut [u8],
    }

    impl Drop for Rig {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Relaxed);
            if let Some(t) = self.thread.take() {
                t.join().unwrap();
            }
            OPEN_STREAMS.store(0, Ordering::Relaxed);
            MSI_ARMED.store(false, Ordering::Relaxed);
        }
    }

    /// A device that is up and surveyed (one playback stream, one capture
    /// stream, one connected jack, two channel maps) with a thread answering
    /// the control queue.
    fn rig() -> Rig {
        let g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        OPEN_STREAMS.store(0, Ordering::Relaxed);
        let dev: &'static Device = Box::leak(Box::new(Device::new()));
        let sim = {
            let mut c = dev.ctl.lock();
            let mut d = dev.data.lock();
            c.vq = queue(QUEUE_SIZE as u16);
            d.vq = [queue(QUEUE_SIZE as u16), queue(QUEUE_SIZE as u16)];
            map_buffers(&mut c, &mut d, Dma::fallback()).unwrap();
            c.t = Some(Transport::Null);
            d.t = Some(Transport::Null);
            Arc::new(StdMutex::new(Sim {
                ctl: Q::of(&c.vq),
                data: [Q::of(&d.vq[PLAY]), Q::of(&d.vq[REC])],
                seen: [0; 3],
                log: Vec::new(),
                fail: Vec::new(),
                mute: false,
                flush_fill: 0,
                completed: [0; DIRS],
            }))
        };
        let stop = Arc::new(StdBool::new(false));
        let thread = {
            let (sim, stop) = (sim.clone(), stop.clone());
            std::thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    sim.lock().unwrap().step_ctl();
                    std::thread::sleep(std::time::Duration::from_micros(200));
                }
            })
        };
        let found = dev.start(p::Config { jacks: 1, streams: 2, chmaps: 2 }).expect("survey");
        assert_eq!((found.jacks, found.jacks_connected, found.chmaps), (1, 1, 2));
        let arena = Box::leak(vec![0u8; (PERIOD_BYTES * PERIODS) as usize].into_boxed_slice());
        Rig { dev, sim, stop, thread: Some(thread), _g: g, arena }
    }

    fn params(dir: u32) -> Params {
        Params { dir, format: iface::FMT_S16, rate_hz: 48_000, channels: 2, period_frames: PERIOD_FRAMES, periods: PERIODS }
    }

    impl Rig {
        fn geo(&self) -> Geometry {
            params(DIR_PLAYBACK).check().unwrap()
        }
        fn open(&self, dir: u32) -> Result<(), Error> {
            self.dev.open(dir, &params(dir), &self.geo(), self.arena.as_ptr() as u64)
        }
        fn sim(&self) -> std::sync::MutexGuard<'_, Sim> {
            self.sim.lock().unwrap()
        }
        fn requests(&self) -> Vec<u32> {
            self.sim().requests()
        }
        fn data_q(&self, d: usize) -> Q {
            self.sim().data[d]
        }
        /// The chain of the `n`th period posted in direction `d`.
        fn chain(&self, d: usize, n: u16) -> Vec<(u64, u32, u16)> {
            let q = self.data_q(d);
            q.chain(q.head_at(n))
        }
        fn complete_all(&self, d: usize) {
            let mut s = self.sim();
            while s.complete(d, p::S_OK, None) {}
        }
        fn drain_done(&self, dir: u32) -> Vec<Period> {
            std::iter::from_fn(|| self.dev.take_done(dir)).collect()
        }
    }

    fn le32(b: &[u8], off: usize) -> u32 {
        u32::from_le_bytes(b[off..off + 4].try_into().unwrap())
    }

    // ── bring-up ─────────────────────────────────────────────────────────

    /// The survey asks for every stream, jack and channel map the config
    /// counts, in that order, and keeps the first stream of each direction.
    ///
    /// **Canary.** Skip the chmap loop in `survey`: the request list and the
    /// run point (stereo from the map, else the channel minimum) change.
    #[test]
    fn the_survey_reads_streams_jacks_and_chmaps_and_picks_a_run_point() {
        let r = rig();
        let want = vec![p::R_PCM_INFO, p::R_PCM_INFO, p::R_JACK_INFO, p::R_CHMAP_INFO, p::R_CHMAP_INFO];
        assert_eq!(r.requests(), want);
        let log = r.sim().log.clone();
        assert_eq!((le32(&log[0], 4), le32(&log[0], 8), le32(&log[0], 12)), (0, 1, p::PCM_INFO_LEN as u32), "stream 0, one item, its size");
        assert_eq!(le32(&log[1], 4), 1);
        let caps = r.dev.caps().unwrap();
        assert_eq!(caps.dirs, DIR_PLAYBACK | DIR_CAPTURE);
        assert_eq!((caps.rate_hz, caps.channels), (48_000, 2));
        assert_eq!(caps.formats, iface::format_bit(iface::FMT_S16) | iface::format_bit(iface::FMT_S32) | iface::format_bit(iface::FMT_F32));
        assert_eq!(r.dev.data.lock().caps[REC].stream_id, 1);
    }

    #[test]
    fn a_device_without_a_rate_in_common_has_no_run_point_and_one_direction_is_enough() {
        let mut caps = [DirCaps::default(); DIRS];
        assert_eq!(run_point(&caps), None, "no direction");
        let mut info = p::PcmInfo { formats: 1 << p::FMT_S16, rates: 1 << p::RATE_44100, direction: p::D_OUTPUT, channels_min: 1, channels_max: 1 };
        caps[PLAY] = DirCaps { present: true, stream_id: 0, info, chmap_channels: 0 };
        assert_eq!(run_point(&caps), Some((44_100, 1)), "mono only: the channel minimum, not stereo");
        info.rates = 1 << p::RATE_48000;
        info.direction = p::D_INPUT;
        info.channels_max = 2;
        caps[REC] = DirCaps { present: true, stream_id: 1, info, chmap_channels: 0 };
        // No rate in common: the first direction's preferred one.
        assert_eq!(run_point(&caps), Some((44_100, 1)));
    }

    // ── open ─────────────────────────────────────────────────────────────

    /// SET_PARAMS then PREPARE, the buffer being every period of the arena.
    ///
    /// **Canary.** Send `period_bytes` as the buffer size: the 4th field fails.
    #[test]
    fn open_sends_set_params_then_prepare() {
        let r = rig();
        let n0 = r.sim().log.len();
        r.open(DIR_PLAYBACK).unwrap();
        let log = r.sim().log[n0..].to_vec();
        assert_eq!(log.len(), 2);
        assert_eq!(le32(&log[0], 0), p::R_PCM_SET_PARAMS);
        assert_eq!(le32(&log[0], 4), 0, "the playback stream");
        assert_eq!(le32(&log[0], 8), PERIOD_BYTES * PERIODS, "buffer_bytes: the whole arena");
        assert_eq!(le32(&log[0], 12), PERIOD_BYTES, "period_bytes");
        assert_eq!(&log[0][20..23], &[2, p::FMT_S16, p::RATE_48000], "channels, format, rate");
        assert_eq!((le32(&log[1], 0), le32(&log[1], 4)), (p::R_PCM_PREPARE, 0));
        assert_eq!(r.dev.status(DIR_PLAYBACK).state, iface::STATE_OPEN);
        assert_eq!(OPEN_STREAMS.load(Ordering::Relaxed), 1);
        // Capture is the device's second stream.
        r.open(DIR_CAPTURE).unwrap();
        assert_eq!(le32(&r.sim().log[n0 + 2], 4), 1);
    }

    /// What the device does not have is refused before it is asked, and
    /// leaves the direction free.
    ///
    /// **Canary.** Drop the `has_rate` filter: 11025 Hz reaches the device.
    #[test]
    fn what_the_device_lacks_is_unsupported_without_a_request() {
        let r = rig();
        let n0 = r.sim().log.len();
        let mut p = params(DIR_PLAYBACK);
        p.format = iface::FMT_S24;
        assert_eq!(r.dev.open(DIR_PLAYBACK, &p, &r.geo(), r.arena.as_ptr() as u64), Err(Error::Unsupported));
        let mut p = params(DIR_PLAYBACK);
        p.rate_hz = 11_025;
        assert_eq!(r.dev.open(DIR_PLAYBACK, &p, &r.geo(), r.arena.as_ptr() as u64), Err(Error::Unsupported));
        let mut p = params(DIR_PLAYBACK);
        p.rate_hz = 12_345;
        assert_eq!(r.dev.open(DIR_PLAYBACK, &p, &r.geo(), r.arena.as_ptr() as u64), Err(Error::Unsupported), "a rate with no bit");
        let mut p = params(DIR_PLAYBACK);
        p.channels = 3;
        assert_eq!(r.dev.open(DIR_PLAYBACK, &p, &r.geo(), r.arena.as_ptr() as u64), Err(Error::Unsupported));
        assert_eq!(r.dev.open(0, &params(DIR_PLAYBACK), &r.geo(), 0), Err(Error::BadArgument), "no such direction");
        assert_eq!(r.sim().log.len(), n0, "nothing was sent");
        assert!(!r.dev.is_open(DIR_PLAYBACK));
        assert_eq!(OPEN_STREAMS.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn a_refusal_from_the_device_frees_the_direction_for_another_try() {
        let r = rig();
        r.sim().fail.push((p::R_PCM_SET_PARAMS, p::S_NOT_SUPP));
        assert_eq!(r.open(DIR_PLAYBACK), Err(Error::Unsupported));
        assert!(!r.dev.is_open(DIR_PLAYBACK));
        r.sim().fail.clear();
        r.sim().fail.push((p::R_PCM_PREPARE, p::S_BAD_MSG));
        assert_eq!(r.open(DIR_PLAYBACK), Err(Error::BadArgument));
        r.sim().fail.clear();
        r.open(DIR_PLAYBACK).expect("a direction the device refused once opens when it agrees");
        assert_eq!(r.open(DIR_PLAYBACK), Err(Error::Busy), "a second stream on the direction");
        assert_eq!(OPEN_STREAMS.load(Ordering::Relaxed), 1, "the refused opens counted nothing");
    }

    // ── the period ring ──────────────────────────────────────────────────

    /// A playback period is the header, the period's bytes at the arena's
    /// bus address plus `index * period_bytes`, and the status the device
    /// fills; a short period sends only its frames.
    ///
    /// **Canary.** Use `period_bytes` as the length of a short period, or
    /// forget the `index *` in the address: the second descriptor fails.
    #[test]
    fn a_playback_period_is_three_descriptors_zero_copy() {
        let r = rig();
        r.open(DIR_PLAYBACK).unwrap();
        assert_eq!(r.dev.submit(DIR_PLAYBACK, 5, 40), Submit::Queued);
        let c = r.chain(PLAY, 0);
        let (xfer_bus, status_lo) = {
            let d = r.dev.data.lock();
            (d.xfer_bus[PLAY], d.status_bus[PLAY])
        };
        assert_eq!(c[0], (xfer_bus, 4, VIRTQ_DESC_F_NEXT));
        assert_eq!(c[1], (r.arena.as_ptr() as u64 + 5 * PERIOD_BYTES as u64, 40 * FRAME, VIRTQ_DESC_F_NEXT));
        assert_eq!((c[2].1, c[2].2), (8, VIRTQ_DESC_F_WRITE));
        assert!(c[2].0 >= status_lo && c[2].0 < status_lo + (SLOTS * 128) as u64, "a status slot");
        // SAFETY: the driver's header buffer, identity-mapped.
        assert_eq!(unsafe { core::slice::from_raw_parts(xfer_bus as *const u8, 4) }, &[0, 0, 0, 0], "stream 0");
        assert_eq!(r.dev.held(DIR_PLAYBACK), 1);
    }

    #[test]
    fn a_capture_period_is_written_by_the_device_whole() {
        let r = rig();
        r.open(DIR_CAPTURE).unwrap();
        assert_eq!(r.dev.submit(DIR_CAPTURE, 3, PERIOD_FRAMES), Submit::Queued);
        let c = r.chain(REC, 0);
        assert_eq!(c[1], (r.arena.as_ptr() as u64 + 3 * PERIOD_BYTES as u64, PERIOD_BYTES, VIRTQ_DESC_F_NEXT | VIRTQ_DESC_F_WRITE));
        let xfer_bus = r.dev.data.lock().xfer_bus[REC];
        // SAFETY: the driver's header buffer, identity-mapped.
        assert_eq!(unsafe { core::slice::from_raw_parts(xfer_bus as *const u8, 4) }, &[1, 0, 0, 0], "stream 1");
        // A capture post is the full room.
        assert_eq!(r.dev.submit(DIR_CAPTURE, 4, PERIOD_FRAMES - 1), Submit::Bad);
    }

    /// A completion hands the period back with the frames played, and what
    /// the driver held is free again.
    ///
    /// **Canary.** Report `period_frames` instead of the posted frames: the
    /// 40-frame period reads 64.
    #[test]
    fn a_completion_returns_the_period_with_its_frames() {
        let r = rig();
        r.open(DIR_PLAYBACK).unwrap();
        r.dev.submit(DIR_PLAYBACK, 7, 40);
        assert_eq!(r.dev.reap(DIR_PLAYBACK), 0, "the device has not answered");
        assert_eq!(r.dev.take_done(DIR_PLAYBACK), None);
        r.complete_all(PLAY);
        assert_eq!(r.dev.reap(DIR_PLAYBACK), 1);
        assert_eq!(r.dev.take_done(DIR_PLAYBACK), Some(Period { index: 7, frames: 40, flags: 0, time_ns: 0 }));
        assert_eq!(r.dev.held(DIR_PLAYBACK), 0);
        assert_eq!(r.dev.data.lock().vq[PLAY].free_count, QUEUE_SIZE as u16, "the chain's descriptors came back");
        assert_eq!(r.dev.status(DIR_PLAYBACK).frames, 40);
        // The same index can be posted again.
        assert_eq!(r.dev.submit(DIR_PLAYBACK, 7, 64), Submit::Queued);
    }

    #[test]
    fn a_capture_completion_counts_the_frames_the_device_wrote() {
        let r = rig();
        r.open(DIR_CAPTURE).unwrap();
        r.dev.submit(DIR_CAPTURE, 2, PERIOD_FRAMES);
        r.sim().complete(REC, p::S_OK, Some(10 * FRAME));
        r.dev.reap(DIR_CAPTURE);
        assert_eq!(r.dev.take_done(DIR_CAPTURE), Some(Period { index: 2, frames: 10, flags: 0, time_ns: 0 }));
        // The bytes landed in period 2 of the arena.
        let off = 2 * PERIOD_BYTES as usize;
        assert!(r.arena[off..off + 40].iter().all(|&b| b == 0xA5) && r.arena[off + 40] == 0);
    }

    #[test]
    fn a_hostile_post_is_refused_and_takes_nothing() {
        let r = rig();
        assert_eq!(r.dev.submit(DIR_PLAYBACK, 0, 10), Submit::NotOpen, "no stream yet");
        r.open(DIR_PLAYBACK).unwrap();
        assert_eq!(r.dev.submit(DIR_PLAYBACK, PERIODS, 10), Submit::Bad, "past the arena");
        assert_eq!(r.dev.submit(DIR_PLAYBACK, u32::MAX, 10), Submit::Bad);
        assert_eq!(r.dev.submit(DIR_PLAYBACK, 0, 0), Submit::Bad, "no frames");
        assert_eq!(r.dev.submit(DIR_PLAYBACK, 0, PERIOD_FRAMES + 1), Submit::Bad, "more than a period");
        assert_eq!(r.dev.held(DIR_PLAYBACK), 0);
        assert_eq!(r.dev.submit(DIR_PLAYBACK, 1, 10), Submit::Queued);
        assert_eq!(r.dev.submit(DIR_PLAYBACK, 1, 10), Submit::Dup, "the client posts what it does not own");
        assert_eq!(r.dev.held(DIR_PLAYBACK), 1);
        assert_eq!(r.sim().pending(PLAY), 1, "only one chain reached the device");
    }

    /// More periods than the queue has chains wait; periods come back in the
    /// order the device completed them.
    ///
    /// **Canary.** Let `room` ignore the descriptor count: the 22nd post
    /// panics in the allocator instead of answering `Full`.
    #[test]
    fn a_full_queue_says_so_and_frees_in_completion_order() {
        let r = rig();
        r.open(DIR_PLAYBACK).unwrap();
        for i in 0..SLOTS as u32 {
            assert!(r.dev.room(DIR_PLAYBACK), "room for period {i}");
            assert_eq!(r.dev.submit(DIR_PLAYBACK, i, 10), Submit::Queued);
        }
        assert!(!r.dev.room(DIR_PLAYBACK));
        assert_eq!(r.dev.submit(DIR_PLAYBACK, SLOTS as u32, 10), Submit::Full);
        assert_eq!(r.dev.held(DIR_PLAYBACK), SLOTS as u32, "the refused period is not held");
        r.sim().complete(PLAY, p::S_OK, None);
        r.sim().complete(PLAY, p::S_OK, None);
        assert_eq!(r.dev.reap(DIR_PLAYBACK), 2);
        assert!(r.dev.room(DIR_PLAYBACK));
        assert_eq!(r.dev.submit(DIR_PLAYBACK, SLOTS as u32, 10), Submit::Queued, "the refused period goes in now");
        r.complete_all(PLAY);
        r.dev.reap(DIR_PLAYBACK);
        let order: Vec<u32> = r.drain_done(DIR_PLAYBACK).iter().map(|p| p.index).collect();
        let mut want: Vec<u32> = (0..SLOTS as u32).collect();
        want.push(SLOTS as u32);
        assert_eq!(order, want);
        assert_eq!(r.dev.held(DIR_PLAYBACK), 0);
    }

    // ── stop, drain, close ───────────────────────────────────────────────

    /// A stop mid-stream gives every period back cancelled and leaves the
    /// stream open and startable: STOP, RELEASE, PREPARE.
    ///
    /// **Canary.** Leave out RELEASE: the device keeps the buffers, the
    /// periods only come back through the dead-device path and `faults()`
    /// reports a dead device.
    #[test]
    fn a_stop_mid_stream_cancels_every_period_in_flight() {
        let r = rig();
        r.open(DIR_PLAYBACK).unwrap();
        r.dev.start_stream(DIR_PLAYBACK).unwrap();
        for i in 0..3 {
            r.dev.submit(DIR_PLAYBACK, i, 30);
        }
        let n0 = r.sim().log.len();
        r.dev.stop(DIR_PLAYBACK).unwrap();
        assert_eq!(r.sim().requests()[n0 - 1..], [p::R_PCM_START, p::R_PCM_STOP, p::R_PCM_RELEASE, p::R_PCM_PREPARE]);
        let done = r.drain_done(DIR_PLAYBACK);
        assert_eq!(
            done,
            (0..3).map(|i| Period { index: i, frames: 0, flags: PERIOD_CANCELLED, time_ns: 0 }).collect::<Vec<_>>()
        );
        assert_eq!(r.dev.held(DIR_PLAYBACK), 0);
        assert_eq!(r.dev.status(DIR_PLAYBACK).state, iface::STATE_OPEN);
        assert_eq!(r.dev.status(DIR_PLAYBACK).frames, 0, "cancelled frames are not played frames");
        assert!(!r.dev.faults().1);
        assert_eq!(r.dev.data.lock().vq[PLAY].free_count, QUEUE_SIZE as u16);
        // Open again: periods are accepted and START works.
        assert_eq!(r.dev.submit(DIR_PLAYBACK, 0, 30), Submit::Queued);
        r.dev.start_stream(DIR_PLAYBACK).unwrap();
        assert_eq!(*r.sim().requests().last().unwrap(), p::R_PCM_START);
        assert_eq!(r.dev.status(DIR_PLAYBACK).state, iface::STATE_RUNNING);
        // A stop while not running sends no STOP.
        let n = r.sim().log.len();
        r.dev.stop(DIR_PLAYBACK).unwrap();
        r.dev.stop(DIR_PLAYBACK).unwrap();
        assert_eq!(r.sim().requests()[n..], [p::R_PCM_STOP, p::R_PCM_RELEASE, p::R_PCM_PREPARE, p::R_PCM_RELEASE, p::R_PCM_PREPARE]);
    }

    #[test]
    fn a_stop_with_no_stream_is_served_and_sends_nothing() {
        let r = rig();
        let n = r.sim().log.len();
        assert_eq!(r.dev.stop(DIR_PLAYBACK), Ok(()));
        assert_eq!(r.sim().log.len(), n);
        assert_eq!(r.dev.start_stream(DIR_PLAYBACK), Err(Error::NotReady));
        assert_eq!(r.dev.drain(DIR_PLAYBACK), Err(Error::NotReady));
    }

    /// A playback drain waits for the periods already posted to finish and
    /// only then stops the device.
    ///
    /// **Canary.** Make `drain` call `flush` straight away: the posted
    /// periods come back cancelled and `drained()` never has to wait.
    #[test]
    fn a_playback_drain_plays_what_is_posted_then_stops() {
        let r = rig();
        r.open(DIR_PLAYBACK).unwrap();
        r.dev.start_stream(DIR_PLAYBACK).unwrap();
        r.dev.submit(DIR_PLAYBACK, 0, 64);
        r.dev.submit(DIR_PLAYBACK, 1, 20);
        let n = r.sim().log.len();
        assert_eq!(r.dev.drain(DIR_PLAYBACK), Ok(false));
        assert_eq!(r.sim().log.len(), n, "nothing is sent while periods play");
        assert_eq!(r.dev.status(DIR_PLAYBACK).state, iface::STATE_DRAINING);
        assert!(!r.dev.drained(DIR_PLAYBACK));
        assert_eq!(r.dev.start_stream(DIR_PLAYBACK), Err(Error::Busy), "no start while draining");
        r.complete_all(PLAY);
        r.dev.reap(DIR_PLAYBACK);
        assert!(r.dev.drained(DIR_PLAYBACK));
        let done = r.drain_done(DIR_PLAYBACK);
        assert_eq!(done.iter().map(|p| (p.frames, p.flags)).collect::<Vec<_>>(), [(64, 0), (20, 0)], "played, not cancelled");
        r.dev.finish_drain(DIR_PLAYBACK).unwrap();
        assert_eq!(r.sim().requests()[n..], [p::R_PCM_STOP, p::R_PCM_RELEASE, p::R_PCM_PREPARE]);
        assert_eq!(r.dev.status(DIR_PLAYBACK).state, iface::STATE_OPEN);
        assert!(!r.dev.drained(DIR_PLAYBACK));
        // A drain with nothing posted is over at once.
        assert_eq!(r.dev.drain(DIR_PLAYBACK), Ok(false));
        assert!(r.dev.drained(DIR_PLAYBACK));
    }

    /// A capture drain keeps what the buffer being filled holds and cancels
    /// the rest.
    ///
    /// **Canary.** Use `Flush::Cancel` in `drain`: the short period is
    /// flagged cancelled and its frames are lost.
    #[test]
    fn a_capture_drain_returns_the_partial_period_and_cancels_the_rest() {
        let r = rig();
        r.open(DIR_CAPTURE).unwrap();
        r.dev.start_stream(DIR_CAPTURE).unwrap();
        for i in 0..3 {
            r.dev.submit(DIR_CAPTURE, i, PERIOD_FRAMES);
        }
        r.sim().flush_fill = 25 * FRAME;
        assert_eq!(r.dev.drain(DIR_CAPTURE), Ok(true), "a capture drain ends at once");
        let done = r.drain_done(DIR_CAPTURE);
        let got: Vec<(u32, u32, u32)> = done.iter().map(|p| (p.index, p.frames, p.flags)).collect();
        assert_eq!(got, [(0, 25, 0), (1, 0, PERIOD_CANCELLED), (2, 0, PERIOD_CANCELLED)]);
        assert_eq!(r.dev.status(DIR_CAPTURE).state, iface::STATE_OPEN);
        assert_eq!(r.dev.status(DIR_CAPTURE).frames, 25);
    }

    #[test]
    fn a_close_releases_the_stream_and_frees_the_direction() {
        let r = rig();
        r.open(DIR_PLAYBACK).unwrap();
        r.dev.start_stream(DIR_PLAYBACK).unwrap();
        r.dev.submit(DIR_PLAYBACK, 4, 30);
        let n = r.sim().log.len();
        r.dev.close(DIR_PLAYBACK).unwrap();
        assert_eq!(r.sim().requests()[n..], [p::R_PCM_STOP, p::R_PCM_RELEASE], "released, not prepared again");
        assert!(!r.dev.is_open(DIR_PLAYBACK));
        assert_eq!(OPEN_STREAMS.load(Ordering::Relaxed), 0);
        assert_eq!(r.dev.status(DIR_PLAYBACK).state, iface::STATE_CLOSED);
        r.dev.close(DIR_PLAYBACK).expect("served when no stream is open");
        r.open(DIR_PLAYBACK).expect("and the direction opens again");
        assert_eq!(OPEN_STREAMS.load(Ordering::Relaxed), 1);
    }

    // ── xruns and a lying device ─────────────────────────────────────────

    /// Playback that ran out of periods while running flags the next one.
    ///
    /// **Canary.** Never set `dry`: the second period is not flagged.
    #[test]
    fn a_gap_in_a_running_stream_is_an_xrun_on_the_next_period() {
        let r = rig();
        r.open(DIR_PLAYBACK).unwrap();
        r.dev.start_stream(DIR_PLAYBACK).unwrap();
        r.dev.submit(DIR_PLAYBACK, 0, 64);
        r.complete_all(PLAY);
        r.dev.reap(DIR_PLAYBACK);
        r.dev.submit(DIR_PLAYBACK, 1, 64);
        r.dev.submit(DIR_PLAYBACK, 2, 64);
        r.complete_all(PLAY);
        r.dev.reap(DIR_PLAYBACK);
        let flags: Vec<u32> = r.drain_done(DIR_PLAYBACK).iter().map(|p| p.flags).collect();
        assert_eq!(flags, [0, PERIOD_XRUN, 0], "the gap precedes period 1 only");
        assert_eq!(r.dev.status(DIR_PLAYBACK).xruns, 1);
    }

    #[test]
    fn an_idle_open_stream_is_not_an_xrun() {
        let r = rig();
        r.open(DIR_PLAYBACK).unwrap();
        r.dev.submit(DIR_PLAYBACK, 0, 64);
        r.complete_all(PLAY);
        r.dev.reap(DIR_PLAYBACK);
        r.dev.submit(DIR_PLAYBACK, 1, 64);
        r.complete_all(PLAY);
        r.dev.reap(DIR_PLAYBACK);
        assert!(r.drain_done(DIR_PLAYBACK).iter().all(|p| p.flags == 0), "not started: no gap");
        assert_eq!(r.dev.status(DIR_PLAYBACK).xruns, 0);
    }

    #[test]
    fn a_period_the_device_reports_as_an_io_error_is_an_xrun_with_no_frames() {
        let r = rig();
        r.open(DIR_PLAYBACK).unwrap();
        r.dev.start_stream(DIR_PLAYBACK).unwrap();
        r.dev.submit(DIR_PLAYBACK, 3, 64);
        r.sim().complete(PLAY, p::S_IO_ERR, None);
        r.dev.reap(DIR_PLAYBACK);
        assert_eq!(r.dev.take_done(DIR_PLAYBACK), Some(Period { index: 3, frames: 0, flags: PERIOD_XRUN, time_ns: 0 }));
        assert_eq!(r.dev.status(DIR_PLAYBACK).xruns, 1);
    }

    /// An id nobody posted, or one completed twice, is counted and ignored.
    ///
    /// **Canary.** Never take the `!live` branch in `complete`: the repeated
    /// completion frees descriptors twice and returns period 0 twice.
    #[test]
    fn a_device_that_completes_what_was_not_posted_is_counted_not_obeyed() {
        let r = rig();
        r.open(DIR_PLAYBACK).unwrap();
        r.dev.submit(DIR_PLAYBACK, 0, 64);
        let q = r.data_q(PLAY);
        let head = q.head_at(0) as u32;
        r.complete_all(PLAY);
        q.push_used(head, 8); // the same chain again
        q.push_used(9, 8); // a descriptor nobody used
        q.push_used(u32::MAX, 8); // past the table
        assert_eq!(r.dev.reap(DIR_PLAYBACK), 4);
        assert_eq!(r.drain_done(DIR_PLAYBACK).len(), 1, "period 0 came back once");
        let (bad, dead) = r.dev.faults();
        assert!(bad >= 3 && !dead, "{bad}");
        assert_eq!(r.dev.data.lock().vq[PLAY].free_count, QUEUE_SIZE as u16, "no descriptor freed twice");
        assert_eq!(r.dev.submit(DIR_PLAYBACK, 0, 64), Submit::Queued);
    }

    /// A device that stops answering is given up on within WAIT_MS, and the
    /// periods it held come back.
    #[test]
    fn a_dead_device_is_given_up_on_and_gives_its_periods_back() {
        let r = rig();
        r.open(DIR_PLAYBACK).unwrap();
        r.dev.start_stream(DIR_PLAYBACK).unwrap();
        r.dev.submit(DIR_PLAYBACK, 0, 64);
        r.dev.submit(DIR_PLAYBACK, 1, 64);
        r.sim().mute = true;
        let t0 = std::time::Instant::now();
        assert_eq!(r.dev.stop(DIR_PLAYBACK), Err(Error::Fault));
        assert!(t0.elapsed() >= std::time::Duration::from_millis(WAIT_MS * 9 / 10), "it waited");
        assert!(t0.elapsed() < std::time::Duration::from_millis(WAIT_MS * 5), "and no longer");
        let done = r.drain_done(DIR_PLAYBACK);
        assert_eq!(done.iter().map(|p| (p.index, p.flags)).collect::<Vec<_>>(), [(0, PERIOD_CANCELLED), (1, PERIOD_CANCELLED)]);
        assert!(r.dev.faults().1);
        assert!(!r.dev.room(DIR_PLAYBACK) && r.dev.caps().is_none());
        let t0 = std::time::Instant::now();
        assert_eq!(r.dev.start_stream(DIR_PLAYBACK), Err(Error::NoDevice));
        assert_eq!(r.open(DIR_CAPTURE), Err(Error::NoDevice));
        assert!(t0.elapsed() < std::time::Duration::from_millis(100), "a dead device is not waited for again");
    }

    // ── interrupts ───────────────────────────────────────────────────────

    /// The handler answers whether the pump has work and takes no lock.
    ///
    /// **Canary.** Take `DEVICE.data` in `on_interrupt`: this test holds it
    /// and deadlocks.
    #[test]
    fn the_msi_arm_is_lock_free_and_wakes_the_pump_only_with_a_stream_open() {
        let r = rig();
        assert_eq!(msi_irq(7), None, "not armed");
        MSI_TOKEN.store(7, Ordering::Relaxed);
        MSI_ARMED.store(true, Ordering::Release);
        assert_eq!(msi_irq(8), None, "another device's vector");
        let held = r.dev.data.lock();
        let held2 = r.dev.ctl.lock();
        assert_eq!(msi_irq(7), Some(false), "no stream open: nothing for the pump");
        OPEN_STREAMS.store(1, Ordering::Relaxed);
        assert_eq!(msi_irq(7), Some(true));
        drop((held, held2));
        assert!(irq_count() >= 2);
        assert_eq!(irq(3), None, "no virtio-mmio line is wired");
    }

    #[test]
    fn a_sleeping_control_wait_is_woken_by_the_interrupt() {
        static WOKEN: AtomicU32 = AtomicU32::new(0);
        fn wake(tid: u32) {
            WOKEN.store(tid, Ordering::SeqCst);
        }
        let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        WAKE_FN.set(wake);
        let tid = 41;
        let slept = WAITER.park(tid, || false, || {
            // The interrupt arrives while the task is listed, before it blocks.
            MSI_TOKEN.store(5, Ordering::Relaxed);
            MSI_ARMED.store(true, Ordering::Release);
            assert!(msi_irq(5).is_some());
            true
        });
        MSI_ARMED.store(false, Ordering::Release);
        assert!(slept);
        assert_eq!(WOKEN.load(Ordering::SeqCst), 41, "the listed task was woken");
        assert_eq!(WAITER.sleeper(), 0, "and delisted when it woke");
    }

    #[test]
    fn the_format_map_follows_the_device() {
        let info = p::PcmInfo { formats: 1 << p::FMT_S16 | 1 << p::FMT_S24, rates: 0, direction: 0, channels_min: 1, channels_max: 2 };
        assert_eq!(sound_formats(&info), iface::format_bit(iface::FMT_S16) | iface::format_bit(iface::FMT_S24));
        assert_eq!(wire_format(iface::FMT_F32), Some(p::FMT_FLOAT));
        assert_eq!(wire_format(0), None);
        assert_eq!(wire_format(99), None);
    }
}

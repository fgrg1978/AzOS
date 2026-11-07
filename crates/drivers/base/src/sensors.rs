// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The sensor class: every sensor is an instance with channels, served by the
//! `Sensor` interface and published as a stream.
//!
//! A [`Sensor`] describes its record as [`Channel`]s (what each is, in what
//! unit, over what range, how often it is sampled) and has one source:
//!
//! * [`Source::Stream`]: a producer (a task, a driver's interrupt step) takes
//!   the one [`Producer`] and publishes a [`Sample`] per acquisition into the
//!   sensor's log. A read answers the newest sample, stamped with when it
//!   was acquired; readers that want every sample hold a [`Cursor`], which
//!   counts the samples it was told it lost.
//! * [`Source::Chip`]: the device is read when asked ([`SensorChip`]), with
//!   its own statement of whether the read may sleep.
//! * [`Source::Unsupported`]: a record that does not fit a sample (a LiDAR
//!   scan, a camera frame); the descriptor says what the sensor is.
//!
//! Instances are numbered by registration ([`crate::instances`]). The board's
//! own are registered first, in the order the topology's `sensor.<n>`
//! endpoints name them ([`board`]), then the temperature sensors a thermal
//! zone reads. The class's limit is Kconfig `SENSOR_INSTANCES`, the depth of
//! every stream `SENSOR_STREAM_DEPTH`.
//!
//! The single writer of a stream is a property of the type: [`Sensor::producer`]
//! returns it once. The store masks preemption, so a reader on the same hart
//! never spins on a store its preempted writer cannot finish.

use crate::instances::{Instances, Lease, RegisterError};
pub use azos_devif::sensor::Sample;
use azos_rings::{Log, Next, Reader, Writer};
use azos_sync::critical_section;

#[path = "sensors/board.rs"]
pub mod board;

/// Samples every stream keeps.
pub const STREAM_DEPTH: usize = azos_limits::SENSOR_STREAM_DEPTH as usize;

/// The log a stream sensor publishes into. All zero, so a `static` of it is
/// `.bss`; it is a static of its own, not a field of the [`Sensor`] (whose
/// pointers are not zero and would take the log into `.data`).
pub type Stream = Log<Sample, STREAM_DEPTH>;

/// An empty stream.
pub const fn stream() -> Stream {
    Log::new(Sample::EMPTY)
}

/// Instances the class keeps.
pub const INSTANCES: usize = azos_limits::SENSOR_INSTANCES as usize;

/// What a channel measures.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Quantity {
    Acceleration,
    AngularRate,
    Distance,
    Angle,
    Count,
    Voltage,
    Current,
    Charge,
    Ratio,
    Temperature,
    Coordinate,
    Flags,
    /// A record that is not a sample: a frame or a scan.
    Image,
}

/// The unit a channel's integer is in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unit {
    MilliG,
    MilliDegPerSec,
    Millimeter,
    CentiDegree,
    Ticks,
    MilliVolt,
    MilliAmp,
    MilliAmpHour,
    Percent,
    DegreeE7,
    MilliDegC,
    CentiDegC,
    Bits,
    None,
}

/// One value of a sensor's record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Channel {
    pub quantity: Quantity,
    pub unit: Unit,
    /// Bytes of the record the value takes: 1, 2, 4 or 8.
    pub width: u8,
    pub signed: bool,
    /// The values the part can measure; a reading outside is not one.
    pub min: i64,
    pub max: i64,
    /// Samples per second the sensor is acquired at; 0 = when asked.
    pub rate_hz: u32,
}

impl Channel {
    /// Is `v` a value this channel can hold?
    pub const fn admits(&self, v: i64) -> bool {
        self.min <= v && v <= self.max
    }
}

/// Channel `idx` of `sample`'s record, laid out as `chans` say, or `None` when
/// the record does not reach it.
pub fn value(chans: &[Channel], sample: &Sample, idx: usize) -> Option<i64> {
    let ch = chans.get(idx)?;
    let off: usize = chans[..idx].iter().map(|c| c.width as usize).sum();
    let end = off + ch.width as usize;
    if end > sample.len as usize {
        return None;
    }
    let mut all = [0u8; azos_devif::sensor::SAMPLE_BYTES];
    sample.copy_to(&mut all);
    let mut raw = [0u8; 8];
    raw[..ch.width as usize].copy_from_slice(&all[off..end]);
    let v = u64::from_le_bytes(raw);
    Some(if ch.signed {
        let shift = 64 - 8 * ch.width as u32;
        ((v << shift) as i64) >> shift
    } else {
        v as i64
    })
}

/// A sample whose record holds `vals`, one per channel in order, each as many
/// little-endian bytes as its channel is wide (the inverse of [`value`]).
pub fn pack(chans: &[Channel], vals: &[i64], flags: u32, acq_ns: u64) -> Sample {
    let mut rec = [0u8; azos_devif::sensor::SAMPLE_BYTES];
    let mut off = 0;
    for (c, v) in chans.iter().zip(vals) {
        let w = c.width as usize;
        if off + w > rec.len() {
            break;
        }
        rec[off..off + w].copy_from_slice(&v.to_le_bytes()[..w]);
        off += w;
    }
    Sample::new(&rec[..off], flags, acq_ns)
}

/// Why a read gave no sample.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReadError {
    /// Nothing yet: no producer has published, or the device has no reading.
    NotReady,
    /// The record does not fit a sample.
    Unsupported,
    /// The device or its transport failed, or delivered a value its channel
    /// cannot hold.
    Io,
}

/// A device read when asked.
pub trait SensorChip: Sync {
    /// Read the device now.
    fn read(&self) -> Result<Sample, ReadError>;
    /// May [`read`](Self::read) sleep (a transfer on a bus that waits for its
    /// completion)? `false` only for a read that is bounded register access
    /// or a copy: an io_ring pass serves its sensor (`OP_CALL`), and a sensor
    /// that may sleep is the typed call's.
    fn may_sleep(&self) -> bool;
}

/// Where a sensor's samples come from.
#[derive(Clone, Copy)]
pub enum Source {
    Stream(&'static Stream),
    Chip(&'static dyn SensorChip),
    Unsupported,
}

/// One sensor instance.
pub struct Sensor {
    channels: &'static [Channel],
    source: Source,
}

impl Sensor {
    pub const fn new(channels: &'static [Channel], source: Source) -> Self {
        Sensor { channels, source }
    }

    pub const fn channels(&self) -> &'static [Channel] {
        self.channels
    }

    /// A sample of this sensor holding `vals`, one per channel.
    pub fn pack(&self, vals: &[i64], flags: u32, acq_ns: u64) -> Sample {
        pack(self.channels, vals, flags, acq_ns)
    }

    pub fn source(&self) -> Source {
        self.source
    }

    /// May a read of this sensor sleep?
    pub fn may_sleep(&self) -> bool {
        match self.source {
            Source::Chip(c) => c.may_sleep(),
            Source::Stream(_) | Source::Unsupported => false,
        }
    }

    /// The stream, for a sensor that has one.
    fn stream(&self) -> Option<&'static Stream> {
        match self.source {
            Source::Stream(s) => Some(s),
            Source::Chip(_) | Source::Unsupported => None,
        }
    }

    /// The sensor's one writer; `None` when it is already out, or when the
    /// sensor has no stream.
    pub fn producer(&self) -> Option<Producer<'static>> {
        self.stream()?.writer().map(|w| Producer { w, published: 0 })
    }

    /// Samples published so far.
    pub fn published(&self) -> u64 {
        self.stream().map_or(0, |s| s.head())
    }

    /// The newest sample, or `None` before the first (and for a sensor with
    /// no stream). Bounded: it retries only while the producer is inside a
    /// store of a few words.
    pub fn latest(&self) -> Option<Sample> {
        let (seq, s) = self.stream()?.latest();
        (seq != 0).then_some(s)
    }

    /// A reader that sees the samples published from now on; `None` for a
    /// sensor with no stream.
    pub fn cursor(&self) -> Option<Cursor<'static>> {
        Some(Cursor { r: self.stream()?.reader(), delivered: 0, overrun: 0 })
    }

    /// One reading: the newest published sample, or the device's read.
    pub fn read(&self) -> Result<Sample, ReadError> {
        match self.source {
            Source::Stream(_) => self.latest().ok_or(ReadError::NotReady),
            Source::Chip(c) => c.read(),
            Source::Unsupported => Err(ReadError::Unsupported),
        }
    }
}

/// The only handle that publishes into a sensor's stream. Not `Clone`.
pub struct Producer<'a> {
    w: Writer<'a, Sample, STREAM_DEPTH>,
    published: u64,
}

impl Producer<'_> {
    /// Publish one acquisition. Never waits. Returns the sample's number.
    #[cfg(not(feature = "sensor-drop-canary"))]
    pub fn publish(&mut self, s: Sample) -> u64 {
        self.published += 1;
        let _preempt = critical_section();
        self.w.publish(s)
    }

    /// Canary: every 10th sample is dropped before it reaches the stream.
    #[cfg(feature = "sensor-drop-canary")]
    pub fn publish(&mut self, s: Sample) -> u64 {
        self.published += 1;
        if self.published % 10 == 0 {
            return self.w.head();
        }
        let _preempt = critical_section();
        self.w.publish(s)
    }

    /// Acquisitions handed to [`publish`](Self::publish) so far.
    pub fn acquired(&self) -> u64 {
        self.published
    }
}

/// A private position in a sensor's stream.
pub struct Cursor<'a> {
    r: Reader<'a, Sample, STREAM_DEPTH>,
    delivered: u64,
    overrun: u64,
}

impl Cursor<'_> {
    /// The next sample this reader has not seen. A reader that fell behind
    /// the stream's depth jumps to the oldest retained sample and adds what
    /// it missed to [`overrun`](Self::overrun).
    pub fn next(&mut self) -> Option<Sample> {
        loop {
            match self.r.next() {
                Next::Item(s) => {
                    self.delivered += 1;
                    return Some(s);
                }
                Next::Empty => return None,
                Next::Overrun(n) => self.overrun += n,
            }
        }
    }

    /// Samples handed out.
    pub fn delivered(&self) -> u64 {
        self.delivered
    }

    /// Samples the stream overwrote before this reader saw them.
    pub fn overrun(&self) -> u64 {
        self.overrun
    }
}

static SENSORS: Instances<Sensor, INSTANCES> = Instances::empty();

/// Sensor `n`, if one is registered: held for the read while the lease lives.
pub fn get(n: u32) -> Option<Lease<'static, Sensor>> {
    SENSORS.get(n)
}

/// Register the board's own sensors consecutively, or none; the instance number
/// of the first.
pub fn register_boards(sensors: &[&'static Sensor]) -> Result<u32, RegisterError> {
    SENSORS.register_boards(sensors)
}

const _: () = assert!(INSTANCES >= board::COUNT, "Kconfig SENSOR_INSTANCES is below the board's own sensors");

/// The temperature sensor `n` reads, in milli-degrees Celsius: the sensor's
/// read, decoded by its first channel, which must measure a temperature in that
/// unit and admit the value (a reading outside what the part can measure is a
/// transport fault, not a temperature: `Io`). A sensor that is not registered
/// is not ready.
pub fn temperature_mdeg(n: u32) -> Result<i32, ReadError> {
    let s = get(n).ok_or(ReadError::NotReady)?;
    let ch = *s.channels().first().ok_or(ReadError::Unsupported)?;
    if ch.quantity != Quantity::Temperature || ch.unit != Unit::MilliDegC {
        return Err(ReadError::Unsupported);
    }
    let sample = s.read()?;
    let v = value(s.channels(), &sample, 0).ok_or(ReadError::NotReady)?;
    if !ch.admits(v) {
        return Err(ReadError::Io);
    }
    i32::try_from(v).map_err(|_| ReadError::Io)
}

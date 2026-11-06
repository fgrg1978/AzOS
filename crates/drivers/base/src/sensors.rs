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
//! Instances are numbered by registration. The board's own are registered
//! first, in the order the topology's `sensor.<n>` endpoints name them
//! ([`board`]); a bound device's sensor takes the next number and keeps it
//! for the boot ([`crate::instances`]). The class's limit is Kconfig
//! `SENSOR_INSTANCES`, the depth of every stream `SENSOR_STREAM_DEPTH`.
//!
//! The single writer of a stream is a property of the type: [`Sensor::producer`]
//! returns it once. The store masks preemption, so a reader on the same hart
//! never spins on a store its preempted writer cannot finish.

use crate::instances::{DeviceId, Instances, Lease, RegisterError, UnregisterError};
pub use azos_devif::sensor::Sample;
use azos_rings::{Log, Next, Reader, Writer};
use azos_sync::critical_section;

#[path = "sensors/board.rs"]
pub mod board;

/// Samples every stream keeps.
pub const STREAM_DEPTH: usize = azos_limits::SENSOR_STREAM_DEPTH as usize;

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
    /// The device or its transport failed.
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
    Stream,
    Chip(&'static dyn SensorChip),
    Unsupported,
}

/// One sensor instance.
pub struct Sensor {
    channels: &'static [Channel],
    source: Source,
    log: Log<Sample, STREAM_DEPTH>,
}

impl Sensor {
    pub const fn new(channels: &'static [Channel], source: Source) -> Self {
        Sensor { channels, source, log: Log::new(Sample::EMPTY) }
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
            Source::Stream | Source::Unsupported => false,
        }
    }

    /// The sensor's one writer; `None` when it is already out.
    pub fn producer(&self) -> Option<Producer<'_>> {
        self.log.writer().map(|w| Producer { w, published: 0 })
    }

    /// Samples published so far.
    pub fn published(&self) -> u64 {
        self.log.head()
    }

    /// The newest sample, or `None` before the first. Bounded: it retries
    /// only while the producer is inside a store of a few words.
    pub fn latest(&self) -> Option<Sample> {
        let (seq, s) = self.log.latest();
        (seq != 0).then_some(s)
    }

    /// A reader that sees the samples published from now on.
    pub fn cursor(&self) -> Cursor<'_> {
        Cursor { r: self.log.reader(), delivered: 0, overrun: 0 }
    }

    /// One reading: the newest published sample, or the device's read.
    pub fn read(&self) -> Result<Sample, ReadError> {
        match self.source {
            Source::Stream => self.latest().ok_or(ReadError::NotReady),
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

/// Register one of the board's own sensors; its instance number.
pub fn register_board(s: &'static Sensor) -> Result<u32, RegisterError> {
    SENSORS.register_board(s)
}

/// Register bound device `dev`'s sensor; its instance number.
pub fn register(dev: DeviceId, s: &'static Sensor) -> Result<u32, RegisterError> {
    SENSORS.register(dev, s)
}

/// Withdraw device `dev`'s sensor once no read is inside it.
pub fn unregister(dev: DeviceId, patience: &mut dyn FnMut() -> bool) -> Result<u32, UnregisterError> {
    SENSORS.unregister(dev, patience)
}

/// How many sensors are registered.
pub fn count() -> usize {
    SENSORS.count()
}

/// The first instance whose channel 0 measures `q` in `unit`, searching from
/// `from`.
pub fn find(q: Quantity, unit: Unit, from: u32) -> Option<u32> {
    (from..INSTANCES as u32).find(|&n| {
        get(n).is_some_and(|s| s.channels().first().is_some_and(|c| c.quantity == q && c.unit == unit))
    })
}

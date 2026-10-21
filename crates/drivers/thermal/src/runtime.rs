// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The thermal tick: read the zones that are due, decide, move the clocks,
//! settle the degrade level.
//!
//! One call per wake-up of the kernel's thermal task ([`Runtime::tick`]); it
//! does nothing for a zone that is not due, so the caller may call it as
//! often as it likes ([`Runtime::poll_interval_ms`] says when it is worth it).
//!
//! Per domain the clock is touched only when the framework has a reason:
//!
//! * the governor named an OPP (`want`): the answer is the governor's, capped
//!   by the heat and held up by the floors ([`azos_energy::thermal::Thermal::limit`]);
//! * no governor runs (`want` is `None`, today's `Fixed`) and the heat caps
//!   the domain: the domain's current OPP is the request, so heat can still
//!   pull a clock down. The OPP it was at is remembered, and put back once
//!   the cap is gone;
//! * otherwise the clock is left alone (invariant I4: no model, no
//!   thermal zone, no change).
//!
//! The OPP "put back" is the one [`azos_energy::opp::Dvfs`] knows: wiring must
//! [`Dvfs::assume`](azos_energy::opp::Dvfs::assume) the firmware's boot OPP
//! (the Pi: `arm_clock_rate()` mapped to the nearest OPP) before the first
//! tick. With the OPP unknown there is nothing to restore, and a clock the
//! heat pulled down stays there until a governor asks for another one;
//! putting it back at the fastest OPP instead would raise a clock firmware
//! had chosen lower, against invariant I4.
//!
//! A clock that cannot be moved while the heat wants it lower
//! ([`azos_energy::opp::ActuateError`]) counts like a floor holding it up:
//! the level rises instead of the machine running hot unannounced.
//!
//! A zone whose sensor is lost (`SENSOR_FAIL_LIMIT` failed reads) caps its
//! domains at the deepest state of its cooling maps, so a machine that cannot
//! see its temperature does not keep the clock where the governor left it.
//!
//! # The consumer of the outcome
//!
//! [`Runtime::tick`] returns [`Settled`]: `level` is the degrade level the
//! power service applies, and `shutdown` (latched on a critical trip) is the
//! request for an orderly shutdown. Both belong to the caller of the tick,
//! the kernel's `thermal` task (`kernel/src/boot/thermal.rs`), which is the
//! only place that can reach the shutdown path; this crate decides and
//! records, it does not power the machine off.

use azos_dtb::DtThermal;
use azos_energy::model::{EnergyModel, PerfDomain, MAX_DOMAINS};
use azos_energy::opp::{Dvfs, OppActuator};
use azos_energy::thermal::{Event, Settled, Thermal};

use crate::dt::{self, Built};
use crate::sensor::SensorBank;

/// The shortest sleep between two ticks, milliseconds. A tree that declares a
/// polling delay of a few milliseconds (or none, which reads as 0 in some
/// bindings) does not get a task that wakes every millisecond: the clocks the
/// framework moves settle slower than that.
pub const MIN_TICK_MS: u32 = 10;

/// The sensor index of a board that has one temperature sensor (every board
/// this crate has an object for): a zone names the sensor by phandle and cell,
/// and the cell of a one-sensor controller is 0 or absent. A zone with no
/// phandle, or a cell past the first sensor, has nothing to read.
pub fn single_sensor(phandle: u32, cell: u32) -> Option<u8> {
    (phandle != 0 && cell == 0).then_some(0)
}

/// The OPP of `d` whose frequency is nearest `khz`; a tie goes to the lower
/// one (a clock restored after the heat is never put above where it ran).
/// `None` for a domain with no OPP.
pub fn nearest_opp(d: &PerfDomain, khz: u32) -> Option<usize> {
    d.opps()
        .iter()
        .enumerate()
        .min_by_key(|(_, o)| (o.freq_khz.abs_diff(khz), o.freq_khz))
        .map(|(i, _)| i)
}

/// Which way a [`azos_energy::thermal::Record`] moved the machine: what the
/// kernel's decision record says about it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stance {
    /// The framework acted on the heat: a trip fired and the clock is capped.
    Acted,
    /// The machine could not, or declined to, do what the heat asked by the
    /// clock alone: a floor holds a clock up, the level rose, a sensor was
    /// lost, the shutdown was requested.
    Declined,
    /// The situation relaxed: a trip cleared, a domain is cooled, the level
    /// fell, a sensor is back.
    Relaxed,
}

/// The stance of `ev`. `level_rose`: for [`Event::Level`], whether the new
/// level is above the previous one (a fall is a relaxation).
pub fn stance(ev: Event, level_rose: bool) -> Stance {
    match ev {
        Event::TripUp => Stance::Acted,
        Event::Uncooled | Event::Shutdown | Event::SensorLost => Stance::Declined,
        Event::Level if level_rose => Stance::Declined,
        Event::TripDown | Event::Cooled | Event::Level | Event::SensorBack => Stance::Relaxed,
    }
}

/// The name of `ev` for the console and `/proc/thermal`.
pub const fn event_name(ev: Event) -> &'static str {
    match ev {
        Event::TripUp => "trip-up",
        Event::TripDown => "trip-down",
        Event::Uncooled => "uncooled",
        Event::Cooled => "cooled",
        Event::Level => "level",
        Event::Shutdown => "shutdown",
        Event::SensorLost => "sensor-lost",
        Event::SensorBack => "sensor-back",
    }
}

/// What [`Runtime::from_dt`] could not use of the device tree.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Report {
    /// Zones kept.
    pub zones: u8,
    /// Zones dropped (no sensor the board knows, no trip, too many).
    pub zones_dropped: u8,
    /// Trips dropped (unknown type).
    pub trips_dropped: u8,
    /// Cooling-device entries dropped (unknown CPU, CPU in no domain, ...).
    pub coolers_dropped: u8,
    /// The reader or a zone ran out of room.
    pub truncated: bool,
}

/// What the caller knows each tick.
#[derive(Clone, Copy, Debug)]
pub struct Inputs {
    /// Per domain, the OPP the governor chose (`None`: no governor request).
    pub want: [Option<usize>; MAX_DOMAINS],
    /// Per domain, the real-time density admitted on its most loaded hart,
    /// parts per million (the SCHED-RT ledger's `density`).
    pub admitted_ppm: [u32; MAX_DOMAINS],
}

impl Inputs {
    /// No governor request and no reservation anywhere.
    pub const IDLE: Self = Self { want: [None; MAX_DOMAINS], admitted_ppm: [0; MAX_DOMAINS] };
}

/// Not set: the OPP before thermal pressure.
const NONE: u8 = u8::MAX;

/// The runtime state: the zones, the clocks' bookkeeping and what to put back.
pub struct Runtime {
    /// The zones and the record ring.
    pub thermal: Thermal,
    /// Which OPP each domain runs at.
    pub dvfs: Dvfs,
    /// Per domain, the OPP the heat found it at, to be restored.
    restore: [u8; MAX_DOMAINS],
    /// Per domain, the heat holds the clock down and no governor runs.
    pressed: [bool; MAX_DOMAINS],
    last: Settled,
    /// Evaluations made ([`Runtime::tick`] calls), wrapping.
    pub ticks: u32,
}

impl Runtime {
    /// A runtime over `thermal`.
    pub const fn new(thermal: Thermal) -> Self {
        Self {
            thermal,
            dvfs: Dvfs::new(),
            restore: [NONE; MAX_DOMAINS],
            pressed: [false; MAX_DOMAINS],
            last: Settled { level: 0, shutdown: false },
            ticks: 0,
        }
    }

    /// The runtime of a board whose device tree is `dt`: the zones
    /// ([`dt::build`], the sensor named through [`single_sensor`]) over
    /// `model`, and each domain's boot OPP taken from `boot_khz(domain)` (the
    /// clock the firmware left, read back by the board: the Pi's
    /// `arm_clock_rate()`, the SoC clock framework's rate), so a clock the
    /// heat pulled down has an OPP to be put back at. A domain whose clock
    /// cannot be read stays unknown and is not restored (see the module
    /// documentation).
    pub fn from_dt(dt: &DtThermal, model: &EnergyModel, boot_khz: impl Fn(usize) -> Option<u32>) -> (Self, Report) {
        let Built { thermal, zones_dropped, trips_dropped, coolers_dropped, truncated } =
            dt::build(dt, model, single_sensor);
        let report = Report { zones: thermal.zones().len() as u8, zones_dropped, trips_dropped, coolers_dropped, truncated };
        let mut rt = Self::new(thermal);
        rt.assume_boot(model, boot_khz);
        (rt, report)
    }

    /// Record the OPP each domain of `model` boots at, from `boot_khz`.
    pub fn assume_boot(&mut self, model: &EnergyModel, boot_khz: impl Fn(usize) -> Option<u32>) {
        for (dom, d) in model.domains().iter().enumerate() {
            if let Some(i) = boot_khz(dom).and_then(|khz| nearest_opp(d, khz)) {
                self.dvfs.assume(dom, i);
            }
        }
    }

    /// How long until the zones need reading again, from the polling delays
    /// the tree declared (passive delay while a trip is active, the idle one
    /// otherwise), never under [`MIN_TICK_MS`]. `None`: no zone, nothing to
    /// poll, so no task.
    pub fn poll_interval_ms(&self) -> Option<u32> {
        (0..self.thermal.zones().len())
            .map(|z| self.thermal.zones()[z].interval_ms(self.thermal.active(z) != 0))
            .min()
            .map(|ms| ms.max(MIN_TICK_MS))
    }

    /// The situation as of the last tick.
    pub fn last(&self) -> Settled {
        self.last
    }

    /// One evaluation at `now_ms`. `hw` is the board object: it reads the
    /// sensors and moves the clocks.
    pub fn tick<H: SensorBank + OppActuator>(
        &mut self,
        hw: &mut H,
        model: &EnergyModel,
        now_ms: u64,
        inp: &Inputs,
    ) -> Settled {
        self.ticks = self.ticks.wrapping_add(1);
        for z in 0..self.thermal.zones().len() {
            if !self.thermal.due(z, now_ms) {
                continue;
            }
            let sensor = self.thermal.zones()[z].sensor;
            match hw.read_mdeg(sensor) {
                Ok(t) => {
                    self.thermal.update(z, t, now_ms);
                }
                Err(_) => self.thermal.sensor_failed(z, now_ms),
            }
        }
        for (dom, d) in model.domains().iter().enumerate() {
            let pressure = self.thermal.cap_state(dom) > 0;
            let cur = self.dvfs.current(dom);
            let want = match (inp.want[dom], pressure) {
                (Some(w), _) => {
                    // A governor owns the clock: nothing of ours to put back.
                    self.pressed[dom] = false;
                    self.restore[dom] = NONE;
                    Some(w)
                }
                (None, true) => {
                    // Where the clock was when the heat first took hold.
                    if !self.pressed[dom] {
                        self.pressed[dom] = true;
                        self.restore[dom] = cur.map_or(NONE, |c| c as u8);
                    }
                    Some(cur.unwrap_or(d.opps().len().saturating_sub(1)))
                }
                (None, false) => {
                    self.pressed[dom] = false;
                    match core::mem::replace(&mut self.restore[dom], NONE) {
                        NONE => None,
                        r => Some(r as usize),
                    }
                }
            };
            let Some(want) = want else { continue };
            let lim = self.thermal.limit(d, dom, want, inp.admitted_ppm[dom]);
            if self.dvfs.set(hw, model, dom, lim.opp).is_err() && pressure && cur.is_none_or(|c| lim.opp < c) {
                self.thermal.unactuated(dom);
            }
        }
        self.last = self.thermal.settle(now_ms);
        self.last
    }
}

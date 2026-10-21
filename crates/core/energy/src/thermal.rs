// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Thermal zones, trips and cooling by OPP capping (the policy half of the
//! thermal framework; `azos_thermal` holds the sensors and the runtime).
//!
//! The data model is the device tree's `thermal-zones` binding: a **zone** is
//! read through one sensor and has **trips** (a temperature, a hysteresis and
//! a kind) and **cooling maps** (while this trip is active, cap this
//! performance domain by N OPP steps, N between `min` and `max`).
//!
//! # Cooling by capping
//!
//! A cooling state is "steps below the fastest OPP": state 0 runs the whole
//! table, state `n` at most OPP `top - n`. The governor is the Linux
//! `step_wise` one, without the trend (the sensor is read at a fixed
//! interval, so the sign of the last difference is noise):
//!
//! * temperature at or above an active-capable trip: the map's state rises by
//!   one per evaluation, clamped to its `max` (and to at least its `min`);
//! * inside the hysteresis band below the trip: the state holds;
//! * below the band: the trip is inactive and the state falls by one per
//!   evaluation, so a cooled-down domain gets its clock back gradually and a
//!   reading that jitters around the trip does not toggle it.
//!
//! A domain's cap is the largest state over every map that names it, in
//! every zone.
//!
//! # The floors are not negotiable
//!
//! [`Thermal::limit`] returns `max(min(want, cap), floor)` where the floor is
//! the larger of the **deadline floor** of the admitted real-time
//! reservations (invariant I1) and the **safety floor** of the WCET reference
//! frequency (invariant I6): heat never lowers a clock below what an admitted
//! guarantee needs. When the cap would have gone lower, the domain is
//! *floor-bound*: cooling by clock alone cannot get the zone down, and the
//! framework says so instead of silently running hot.
//!
//! # Degrade, shutdown, record
//!
//! What the clock cannot do, the system declines to do. [`Thermal::settle`]
//! turns the situation into a level of the degrade vocabulary
//! (`DEGRADE_LEVEL_*` of `domains/robot/degrade-policy`, the signed
//! topology's `Envelope`) that the power service applies:
//!
//! | Situation | Level |
//! |---|---|
//! | some domain floor-bound while capped | 1, cautious |
//! | a `hot` trip active, or a sensor lost | 2, slow |
//! | a `critical` trip reached | 3, contained, and [`Settled::shutdown`] latched |
//!
//! A lost sensor does more than raise the level: its zone's cooling maps cap
//! their domains at their deepest state until a read succeeds again
//! ([`Thermal::cap_state`]), so the clock does not stay wherever the governor
//! last put it. A zone with no cooling map has nothing to cap and is left at
//! the level alone.
//!
//! Every trip crossing, floor-bound transition, level change and sensor loss
//! leaves a [`Record`] in a ring ([`Thermal::record`]): entering a degrade
//! level is a recorded decision, never a silent one. The level and a critical
//! trip's [`Settled::shutdown`] are returned to the caller of the tick
//! (`azos_thermal::runtime::Runtime::tick`), which hands the level to the
//! power service and performs the orderly shutdown; the clock stays at the
//! floor meanwhile.

use crate::governor::{deadline_floor_opp, safety_floor_opp};
use crate::model::{EnergyModel, PerfDomain, MAX_DOMAINS};

/// Zones one [`Thermal`] holds: as many as the device-tree reader records.
pub const MAX_ZONES: usize = 8;
const _: () = assert!(MAX_ZONES == azos_dtb::DT_THERMAL_ZONES);
/// Trips per zone.
pub const MAX_TRIPS: usize = 6;
/// Cooling maps per zone.
pub const MAX_MAPS: usize = 6;
/// Bytes of a zone name.
pub const ZONE_NAME_LEN: usize = 16;
/// Records kept (the most recent).
pub const LOG_LEN: usize = 16;
/// Consecutive failed reads after which a sensor counts as lost.
pub const SENSOR_FAIL_LIMIT: u8 = 3;
/// Poll interval of a zone that declares none, milliseconds.
pub const DEFAULT_POLL_MS: u32 = 1_000;

/// `Envelope::Cautious` / `DEGRADE_LEVEL_CAUTIOUS`.
pub const LEVEL_CAUTIOUS: u8 = 1;
/// `Envelope::Slow` / `DEGRADE_LEVEL_SLOW`.
pub const LEVEL_SLOW: u8 = 2;
/// `Envelope::Contained` / `DEGRADE_LEVEL_CONTAINED`.
pub const LEVEL_CONTAINED: u8 = 3;

/// What reaching a trip means (the `type` property of a trip node).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum TripKind {
    /// Cool by capping the clock (cooling maps apply).
    Passive = 0,
    /// A fan or similar: recorded, no clock action of its own.
    Active = 1,
    /// Capping was not enough: the system slows down ([`LEVEL_SLOW`]).
    Hot = 2,
    /// The silicon is in danger: an orderly shutdown is requested.
    Critical = 3,
}

/// One trip point.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Trip {
    /// Temperature at which the trip fires, milli-degrees Celsius.
    pub temp_mdeg: i32,
    /// The trip stays active until the temperature is below
    /// `temp_mdeg - hyst_mdeg`.
    pub hyst_mdeg: u32,
    /// What it means.
    pub kind: TripKind,
}

impl Trip {
    const EMPTY: Self = Self { temp_mdeg: 0, hyst_mdeg: 0, kind: TripKind::Passive };
}

/// While trip `trip` is active, cap performance domain `domain` by a state
/// between `min_state` and `max_state` (steps below its fastest OPP).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CoolingMap {
    /// Index into the zone's trips.
    pub trip: u8,
    /// Index into the energy model's domains.
    pub domain: u8,
    /// Lowest state while the trip is active.
    pub min_state: u8,
    /// Highest state the map may reach.
    pub max_state: u8,
}

impl CoolingMap {
    const EMPTY: Self = Self { trip: 0, domain: 0, min_state: 0, max_state: 0 };
}

/// Why a zone or a map was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ThermalFault {
    /// More than [`MAX_ZONES`].
    TooManyZones,
    /// More than [`MAX_TRIPS`] in a zone.
    TooManyTrips,
    /// More than [`MAX_MAPS`] in a zone.
    TooManyMaps,
    /// A zone with no trip at all (it could never act).
    NoTrips,
    /// A map names a trip the zone does not have, or a critical one (a
    /// critical trip shuts down; it does not cool).
    BadMapTrip,
    /// A map names a domain the model does not have.
    BadMapDomain,
    /// `min_state > max_state`, or `max_state` past the domain's OPP table.
    BadMapStates,
}

/// One thermal zone.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Zone {
    name: [u8; ZONE_NAME_LEN],
    name_len: u8,
    /// The sensor that reads it (an index the runtime resolves).
    pub sensor: u8,
    /// Interval between reads while a passive or hot trip is active, ms
    /// (0 = [`Zone::poll_ms`]).
    pub poll_passive_ms: u32,
    /// Interval between reads otherwise, ms (0 = [`DEFAULT_POLL_MS`]).
    pub poll_ms: u32,
    trips: [Trip; MAX_TRIPS],
    n_trips: u8,
    maps: [CoolingMap; MAX_MAPS],
    n_maps: u8,
}

impl Zone {
    const EMPTY: Self = Self {
        name: [0; ZONE_NAME_LEN],
        name_len: 0,
        sensor: 0,
        poll_passive_ms: 0,
        poll_ms: 0,
        trips: [Trip::EMPTY; MAX_TRIPS],
        n_trips: 0,
        maps: [CoolingMap::EMPTY; MAX_MAPS],
        n_maps: 0,
    };

    /// A zone named `name` (truncated) read by `sensor`, with no trip yet.
    pub fn new(name: &[u8], sensor: u8) -> Self {
        let mut z = Self { sensor, ..Self::EMPTY };
        let n = name.len().min(ZONE_NAME_LEN);
        z.name[..n].copy_from_slice(&name[..n]);
        z.name_len = n as u8;
        z
    }

    /// The name's bytes.
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len as usize]
    }
    /// The trips, in declaration order.
    pub fn trips(&self) -> &[Trip] {
        &self.trips[..self.n_trips as usize]
    }
    /// The cooling maps, in declaration order.
    pub fn maps(&self) -> &[CoolingMap] {
        &self.maps[..self.n_maps as usize]
    }

    /// Append a trip; returns its index.
    pub fn push_trip(&mut self, t: Trip) -> Result<u8, ThermalFault> {
        if self.n_trips as usize >= MAX_TRIPS {
            return Err(ThermalFault::TooManyTrips);
        }
        self.trips[self.n_trips as usize] = t;
        self.n_trips += 1;
        Ok(self.n_trips - 1)
    }

    /// Append a cooling map, checked against the zone's trips and `model`.
    pub fn push_map(&mut self, m: CoolingMap, model: &EnergyModel) -> Result<(), ThermalFault> {
        if self.n_maps as usize >= MAX_MAPS {
            return Err(ThermalFault::TooManyMaps);
        }
        match self.trips().get(m.trip as usize) {
            Some(t) if t.kind != TripKind::Critical => {}
            _ => return Err(ThermalFault::BadMapTrip),
        }
        let Some(d) = model.domains().get(m.domain as usize) else {
            return Err(ThermalFault::BadMapDomain);
        };
        if m.min_state > m.max_state || m.max_state as usize >= d.opps().len() {
            return Err(ThermalFault::BadMapStates);
        }
        self.maps[self.n_maps as usize] = m;
        self.n_maps += 1;
        Ok(())
    }

    /// Milliseconds between reads given whether cooling is under way.
    pub fn interval_ms(&self, cooling: bool) -> u32 {
        let idle = if self.poll_ms == 0 { DEFAULT_POLL_MS } else { self.poll_ms };
        if cooling && self.poll_passive_ms != 0 {
            self.poll_passive_ms
        } else {
            idle
        }
    }
}

/// What a [`Record`] says happened.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Event {
    /// Trip `arg` became active.
    TripUp = 1,
    /// Trip `arg` became inactive.
    TripDown = 2,
    /// Domain `arg` could not be capped as far as the heat asked: a floor
    /// held it up, or the clock could not be moved.
    Uncooled = 3,
    /// Domain `arg` is no longer held up.
    Cooled = 4,
    /// The degrade level became `arg`.
    Level = 5,
    /// A critical trip fired: an orderly shutdown is requested.
    Shutdown = 6,
    /// The zone's sensor failed [`SENSOR_FAIL_LIMIT`] reads in a row.
    SensorLost = 7,
    /// The zone's sensor answered again.
    SensorBack = 8,
}

/// One entry of the event ring.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Record {
    /// When, milliseconds on the caller's clock.
    pub now_ms: u64,
    /// Which zone.
    pub zone: u8,
    /// What.
    pub event: Event,
    /// Trip, domain or level, per [`Event`].
    pub arg: u8,
    /// The reading that caused it (0 for a sensor event).
    pub temp_mdeg: i32,
}

const NO_RECORD: Record = Record { now_ms: 0, zone: 0, event: Event::TripUp, arg: 0, temp_mdeg: 0 };

/// Trips that changed state in one [`Thermal::update`], one bit per trip.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZoneUpdate {
    /// Became active.
    pub up: u8,
    /// Became inactive.
    pub down: u8,
}

/// The situation after an evaluation ([`Thermal::settle`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Settled {
    /// The degrade level the power service should hold (0 = none).
    pub level: u8,
    /// A critical trip fired; latched until the machine restarts.
    pub shutdown: bool,
}

/// What [`Thermal::limit`] answers for one domain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limited {
    /// The OPP to run at.
    pub opp: usize,
    /// The highest OPP the heat allows (the fastest when nothing is capped).
    pub cap: usize,
    /// The floor: the larger of the deadline and safety floors.
    pub floor: usize,
    /// The heat asked for less than the floor allows.
    pub bound: bool,
}

#[derive(Clone, Copy)]
struct ZoneState {
    /// Bit `i`: trip `i` is active.
    active: u8,
    /// Current cooling state of each map.
    steps: [u8; MAX_MAPS],
    /// Consecutive failed reads.
    fails: u8,
    /// When the zone was last read (or failed to be), if ever.
    polled_ms: Option<u64>,
}

impl ZoneState {
    const EMPTY: Self = Self { active: 0, steps: [0; MAX_MAPS], fails: 0, polled_ms: None };
}

/// The thermal state of the machine: zones, their live state and the ring.
pub struct Thermal {
    zones: [Zone; MAX_ZONES],
    n_zones: u8,
    st: [ZoneState; MAX_ZONES],
    /// Domains found floor-bound in the evaluation under way.
    bound: u8,
    /// Domains found floor-bound in the previous one.
    bound_seen: u8,
    level: u8,
    shutdown: bool,
    log: [Record; LOG_LEN],
    logged: u32,
}

impl Thermal {
    /// No zone.
    pub const fn new() -> Self {
        Self {
            zones: [Zone::EMPTY; MAX_ZONES],
            n_zones: 0,
            st: [ZoneState::EMPTY; MAX_ZONES],
            bound: 0,
            bound_seen: 0,
            level: 0,
            shutdown: false,
            log: [NO_RECORD; LOG_LEN],
            logged: 0,
        }
    }

    /// Add a zone; returns its index. A zone needs at least one trip.
    pub fn push_zone(&mut self, z: Zone) -> Result<usize, ThermalFault> {
        if self.n_zones as usize >= MAX_ZONES {
            return Err(ThermalFault::TooManyZones);
        }
        if z.trips().is_empty() {
            return Err(ThermalFault::NoTrips);
        }
        self.zones[self.n_zones as usize] = z;
        self.n_zones += 1;
        Ok(self.n_zones as usize - 1)
    }

    /// The zones.
    pub fn zones(&self) -> &[Zone] {
        &self.zones[..self.n_zones as usize]
    }

    fn push_record(&mut self, r: Record) {
        self.log[self.logged as usize % LOG_LEN] = r;
        self.logged = self.logged.wrapping_add(1);
    }

    /// Records written so far (the ring keeps the last [`LOG_LEN`]).
    pub fn logged(&self) -> u32 {
        self.logged
    }

    /// The `i`-th most recent record (0 = newest).
    pub fn record(&self, i: usize) -> Option<Record> {
        if i >= (self.logged as usize).min(LOG_LEN) {
            return None;
        }
        Some(self.log[(self.logged as usize - 1 - i) % LOG_LEN])
    }

    /// Is zone `z` due for a read at `now_ms`?
    pub fn due(&self, z: usize, now_ms: u64) -> bool {
        let (Some(zone), Some(st)) = (self.zones().get(z), self.st.get(z)) else {
            return false;
        };
        match st.polled_ms {
            None => true,
            Some(last) => now_ms.saturating_sub(last) >= zone.interval_ms(self.cooling(z)) as u64,
        }
    }

    /// Is any non-critical trip of zone `z` active?
    fn cooling(&self, z: usize) -> bool {
        let zone = &self.zones[z];
        zone.trips().iter().enumerate().any(|(i, t)| {
            t.kind != TripKind::Critical && self.st[z].active & (1 << i) != 0
        })
    }

    /// Zone `z` was read: `temp_mdeg`. Moves the trips and the cooling states
    /// of its maps one evaluation forward.
    pub fn update(&mut self, z: usize, temp_mdeg: i32, now_ms: u64) -> ZoneUpdate {
        let none = ZoneUpdate { up: 0, down: 0 };
        if z >= self.n_zones as usize {
            return none;
        }
        let zone = self.zones[z];
        if self.st[z].fails >= SENSOR_FAIL_LIMIT {
            self.push_record(Record { now_ms, zone: z as u8, event: Event::SensorBack, arg: 0, temp_mdeg: 0 });
        }
        self.st[z].fails = 0;
        self.st[z].polled_ms = Some(now_ms);

        let mut upd = none;
        let mut at_or_above = 0u8;
        for (i, t) in zone.trips().iter().enumerate() {
            let bit = 1u8 << i;
            let was = self.st[z].active & bit != 0;
            let hot = temp_mdeg >= t.temp_mdeg;
            // Active from the trip's temperature until the reading is below
            // `temp - hyst`.
            let now = hot || (was && (temp_mdeg as i64) >= t.temp_mdeg as i64 - t.hyst_mdeg as i64);
            if hot {
                at_or_above |= bit;
            }
            if now && !was {
                self.st[z].active |= bit;
                upd.up |= bit;
                self.push_record(Record { now_ms, zone: z as u8, event: Event::TripUp, arg: i as u8, temp_mdeg });
            } else if !now && was {
                self.st[z].active &= !bit;
                upd.down |= bit;
                self.push_record(Record { now_ms, zone: z as u8, event: Event::TripDown, arg: i as u8, temp_mdeg });
            }
        }
        let active = self.st[z].active;
        for (k, m) in zone.maps().iter().enumerate() {
            let bit = 1u8 << m.trip;
            let s = &mut self.st[z].steps[k];
            if at_or_above & bit != 0 {
                *s = (*s + 1).clamp(m.min_state, m.max_state);
            } else if active & bit == 0 {
                *s = s.saturating_sub(1);
            }
        }
        upd
    }

    /// Zone `z` could not be read at `now_ms`. After [`SENSOR_FAIL_LIMIT`]
    /// failures in a row the zone counts as blind: its cooling maps hold
    /// their domains at their deepest state ([`Thermal::cap_state`]) and
    /// [`Thermal::settle`] holds the slow level, both until a read succeeds (a
    /// machine that cannot see its temperature does not run flat out).
    pub fn sensor_failed(&mut self, z: usize, now_ms: u64) {
        if z >= self.n_zones as usize {
            return;
        }
        self.st[z].polled_ms = Some(now_ms);
        let f = &mut self.st[z].fails;
        *f = f.saturating_add(1);
        if *f == SENSOR_FAIL_LIMIT {
            self.push_record(Record { now_ms, zone: z as u8, event: Event::SensorLost, arg: 0, temp_mdeg: 0 });
        }
    }

    /// The cooling state of `domain`: the largest over every map naming it.
    /// A map of a zone whose sensor is lost counts at its `max_state`: with
    /// the temperature unknown the domain is held at the deepest cap the
    /// zone's maps allow (the floors of [`Thermal::limit`] still win).
    pub fn cap_state(&self, domain: usize) -> u8 {
        let mut s = 0;
        for z in 0..self.n_zones as usize {
            let blind = self.st[z].fails >= SENSOR_FAIL_LIMIT;
            for (k, m) in self.zones[z].maps().iter().enumerate() {
                if m.domain as usize == domain {
                    s = s.max(if blind { m.max_state } else { self.st[z].steps[k] });
                }
            }
        }
        s
    }

    /// The OPP `domain` (number `dom` in the model) may run at, given what
    /// the governor `want`s (the current OPP when no governor runs) and the
    /// real-time density `admitted_ppm` admitted on its most loaded hart.
    /// See the module documentation for the floors.
    pub fn limit(&mut self, d: &PerfDomain, dom: usize, want: usize, admitted_ppm: u32) -> Limited {
        let top = d.opps().len().saturating_sub(1);
        let cap = top.saturating_sub(self.cap_state(dom) as usize);
        let floor = deadline_floor_opp(d, admitted_ppm).max(safety_floor_opp(d));
        let capped = want.min(cap);
        let opp = if cfg!(feature = "thermal-floor-canary") { capped } else { capped.max(floor) };
        let bound = floor > cap;
        if bound && dom < MAX_DOMAINS {
            self.bound |= 1 << dom;
        }
        Limited { opp, cap, floor, bound }
    }

    /// The clock of `domain` could not be moved although the heat asked for a
    /// lower cap (no actuator, or it refused): the same situation to the
    /// level as a floor holding the domain up.
    pub fn unactuated(&mut self, domain: usize) {
        if domain < MAX_DOMAINS {
            self.bound |= 1 << domain;
        }
    }

    /// Close an evaluation (every zone updated, every domain limited): work
    /// out the degrade level, latch a shutdown, and record what changed.
    pub fn settle(&mut self, now_ms: u64) -> Settled {
        let mut hot = false;
        let mut crit = None;
        for z in 0..self.n_zones as usize {
            if self.st[z].fails >= SENSOR_FAIL_LIMIT {
                hot = true;
            }
            for (i, t) in self.zones[z].trips().iter().enumerate() {
                if self.st[z].active & (1 << i) == 0 {
                    continue;
                }
                match t.kind {
                    TripKind::Hot => hot = true,
                    TripKind::Critical => crit = crit.or(Some(z as u8)),
                    TripKind::Passive | TripKind::Active => {}
                }
            }
        }
        if let (Some(z), false) = (crit, self.shutdown) {
            self.shutdown = true;
            self.push_record(Record { now_ms, zone: z, event: Event::Shutdown, arg: 0, temp_mdeg: 0 });
        }
        let level = if self.shutdown {
            LEVEL_CONTAINED
        } else if hot {
            LEVEL_SLOW
        } else if self.bound != 0 {
            LEVEL_CAUTIOUS
        } else {
            0
        };
        for dom in 0..MAX_DOMAINS as u8 {
            let (was, is) = (self.bound_seen & (1 << dom) != 0, self.bound & (1 << dom) != 0);
            if is != was {
                let event = if is { Event::Uncooled } else { Event::Cooled };
                self.push_record(Record { now_ms, zone: 0, event, arg: dom, temp_mdeg: 0 });
            }
        }
        self.bound_seen = self.bound;
        self.bound = 0;
        if level != self.level {
            self.level = level;
            self.push_record(Record { now_ms, zone: 0, event: Event::Level, arg: level, temp_mdeg: 0 });
        }
        Settled { level, shutdown: self.shutdown }
    }

    /// Active trips of zone `z`, one bit per trip.
    pub fn active(&self, z: usize) -> u8 {
        self.st.get(z).map_or(0, |s| s.active)
    }

    /// The degrade level as of the last [`Thermal::settle`].
    pub fn level(&self) -> u8 {
        self.level
    }
}

impl Default for Thermal {
    fn default() -> Self {
        Self::new()
    }
}

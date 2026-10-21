// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! SpacemiT K1 (X60 cores): the board object of the thermal framework. The
//! five-channel `TSEN` temperature block as a [`SensorBank`], and the
//! [`OppActuator`] that moves a cluster's clock and its supply together.
//!
//! The K1 is the first board here whose rail the kernel can move: the Pi
//! asks firmware, the JH7110 runs below the voltage firmware left. A K1
//! cluster has a CPU PLL/divider (the APMU `CPU_C0` / `CPU_C1` clock
//! controls) and a PMIC buck behind an I2C bus, so a frequency is only half
//! of an operating point; the other half is the voltage the cores need at it.
//!
//! # The table
//!
//! [`K1Table::from_dt`] reads the voltage of each OPP from the device tree's
//! `operating-points-v2` (`opp-microvolt`, kept by `azos_dtb::DtOpp`). The
//! table is keyed by kHz, the same number as `azos_energy::model::Opp`'s, so
//! the energy model stays voltage-free and a request for a frequency that is
//! not in the table is [`ActuateError::Refused`] (a voltage nobody wrote down
//! is not guessed).
//!
//! * **The ceiling.** An OPP whose target voltage is above its own
//!   `opp-microvolt` maximum, or above the rail's `regulator-max-microvolt`
//!   (the second argument of [`K1Table::from_dt`], from the regulator
//!   framework's constraints), is dropped from the table, counted in
//!   [`K1Table::dropped`], and refused when asked for. It is never clamped:
//!   running the frequency at a lower voltage than the DT says it needs is
//!   the failure, and a higher one is the Linux 7.3 K1 maximum-voltage bug.
//! * **Monotonic.** The voltage of a faster OPP is not below the voltage of a
//!   slower one. The ordering below relies on it (a table that is not is
//!   [`TableError::NotMonotonic`]).
//! * **Slowest first.** The DT does not order its OPPs; the table does.
//!
//! # The order
//!
//! The clock and the rail are read back before every move, never assumed, so
//! a step the rail refused last time, or the frequency firmware booted at,
//! cannot leave the ordering wrong. The frequency that counts is the one the
//! clock will *make* ([`K1Hw::round_khz`]): a DT row says 819000000 and the
//! PLL divider makes 819200000, so the voltage a move needs is the voltage of
//! the slowest row at or above the frequency that results ([`K1Table::need_uv`]),
//! never the row's own when the clock lands above it.
//!
//! * **Going up**: the rail is raised first (never lowered: if it already
//!   sits above what is needed it stays), the actuator waits the rail's ramp
//!   (`regulator-ramp-delay`, microvolts per microsecond), then the clock is
//!   raised. A clock that will not move puts the rail back where it was, so
//!   the cluster is left as it was found.
//! * **Going down** (or the same frequency): the clock first, then the rail
//!   to what is now needed.
//! * Nothing above the ceiling is ever written, and a refused request writes
//!   nothing.
//!
//! # What `Ok` and `Err` say about the machine
//!
//! The thermal runtime's bookkeeping (`azos_energy::opp::Dvfs`) believes the
//! domain is at the OPP of the last `Ok` and at the previous one after an
//! `Err`, and the heat caps and restores by that belief. So the answer is
//! about the *clock*, which is what the heat and the governor asked about:
//!
//! * `Err`: the clock did not move. A rail that was raised for it is put back
//!   (and, if that put-back fails too, the rail stays higher than the clock
//!   needs: safe, counted in [`K1Opp::lagged`] and left in [`K1Opp::take_lag`]).
//! * `Ok`: the clock is at the OPP asked, as far as the clock reports it. The
//!   rail may be a step behind: a rail that would not follow the clock *down*
//!   (or would not be raised after the clock fell) is not a refusal of the
//!   throttle, which is done, and answering `Err` would make the runtime
//!   believe the domain still runs at the old OPP (and raise the degrade level
//!   for a cap that took effect, and never restore a clock it thinks it never
//!   lowered). The supply above what the clock needs wastes power and breaks
//!   nothing; it is reported through [`K1Opp::take_lag`], and the next move
//!   reads the state again and retries the rail. The one exception is the
//!   same-frequency case where the rail is *below* what the clock needs and
//!   cannot be raised: nothing moved, and that is an `Err`.
//!
//! # A rail two clusters share
//!
//! The Milk-V Jupiter tree puts all eight CPUs on one buck
//! (`cpu-supply = <&buck1_0v9>`), so lowering cluster 0 must not take the
//! rail from cluster 1. [`K1Hw::rail_of`] says which domains share a rail, and
//! the voltage a move asks for is the largest of what this cluster needs at
//! its new clock and what every other cluster on the rail needs at the clock
//! it runs now (the slowest row at or above its read-back). A cluster that is
//! not bound, or whose clock is above its fastest row (nothing says what it
//! needs), holds the rail where it is: the rail is not lowered below what it
//! is running at while such a cluster shares it. A cluster on the rail that
//! cannot be read stops the move before anything is written.
//!
//! # Hardware
//!
//! [`K1Hw`] is the seam: the clocks and rails of up to two clusters
//! ([`MAX_K1_DOMAINS`], domain `n` = cluster `Cn`). [`crate::k1_soc::SocK1Hw`]
//! is it over the SoC clock framework (the K1 clock provider of `azos_soc`,
//! one operation at a time) and the P1 PMIC buck behind the I2C master, driven
//! with no lock held because a voltage step is several I2C transfers;
//! [`crate::k1_soc::k1_plan`] builds the tables and wires from the device
//! tree. The host suite pins the logic against fakes and against those
//! providers over register models; `Documentation/energy.md` lists what the
//! board must confirm.
//!
//! # The sensor
//!
//! [`K1Tsensor`] is the K1's `TSEN` block (`spacemit,k1-tsensor`) as a
//! [`SensorBank`]: five channels, polled (the interrupt path of the Linux
//! driver is not used: the thermal tick polls). The kernel starts it at probe
//! (`kernel/src/boot/hwbus.rs`, `k1-tsensor`) through [`K1Tsensor::start`],
//! which refuses to bind a window that does not hold what it wrote. Its zones
//! name a channel by the cell of `thermal-sensors` ([`sensor_of`]).
//!
//! # Users
//!
//! The kernel's thermal task (`kernel/src/boot/thermal.rs`, `Board::K1`)
//! builds [`K1`] for each tick and the runtime from [`runtime_from_dt`].
//! Host-tested (`tests/host/thermal-tests`, `k1_opp` and `k1_tsensor`
//! modules, and `tests/host/soc-tests`, the `k1` wire tests over the Jupiter
//! fixture).

use azos_dtb::{DtOppTable, DtThermal, DT_ENERGY_OPPS};
use azos_energy::model::{EnergyModel, Opp};
use azos_energy::opp::{ActuateError, OppActuator};

use crate::dt::{self, Built};
use crate::runtime::{Report, Runtime};
use crate::sensor::{SensorBank, SensorError};

/// Clusters the actuator drives (the K1 has two, `C0` and `C1`).
pub const MAX_K1_DOMAINS: usize = 2;
/// OPPs per table (what `azos_dtb` records).
pub const MAX_K1_OPPS: usize = DT_ENERGY_OPPS;

/// One operating point: a frequency and the voltage it runs at.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct K1Row {
    /// Core clock, kHz.
    pub freq_khz: u32,
    /// Supply, microvolts.
    pub uv: u32,
}

/// Why a table could not be made.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TableError {
    /// No OPP survived (none in the DT, or all of them over the ceiling).
    Empty,
    /// An OPP has no usable `opp-microvolt`: a K1 table with a hole in its
    /// voltages cannot be run, so the whole table is refused.
    NoVoltage,
    /// An OPP's `opp-hz` is zero or does not fit kHz in a `u32`.
    BadFrequency,
    /// Two OPPs have the same kHz.
    Duplicate,
    /// A faster OPP asks for less voltage than a slower one.
    NotMonotonic,
    /// The rail has no `regulator-max-microvolt`: no ceiling, no voltage.
    NoCeiling,
    /// The ramp rate is zero: the wait after a raise could not be computed.
    ZeroRamp,
}

/// One cluster's OPPs, slowest first, and the limits they were checked
/// against.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct K1Table {
    rows: [K1Row; MAX_K1_OPPS],
    n: u8,
    dropped: u8,
    ceiling_uv: u32,
    ramp_uv_per_us: u32,
}

impl K1Table {
    /// The table of `t`. `rail_max_uv` is the rail's `regulator-max-microvolt`
    /// and `ramp_uv_per_us` its `regulator-ramp-delay` (microvolts per
    /// microsecond).
    pub fn from_dt(t: &DtOppTable, rail_max_uv: u32, ramp_uv_per_us: u32) -> Result<Self, TableError> {
        if rail_max_uv == 0 {
            return Err(TableError::NoCeiling);
        }
        if ramp_uv_per_us == 0 {
            return Err(TableError::ZeroRamp);
        }
        let mut out = Self {
            rows: [K1Row { freq_khz: 0, uv: 0 }; MAX_K1_OPPS],
            n: 0,
            dropped: 0,
            ceiling_uv: rail_max_uv,
            ramp_uv_per_us,
        };
        for o in &t.opps[..t.n_opps as usize] {
            let khz = u32::try_from(o.hz / 1000).ok().filter(|&k| k != 0).ok_or(TableError::BadFrequency)?;
            if o.uv == 0 {
                return Err(TableError::NoVoltage);
            }
            // The ceiling of this OPP: its own maximum (a one-cell
            // `opp-microvolt` makes it the target) and the rail's.
            if o.uv > o.uv_max || o.uv > rail_max_uv {
                out.dropped = out.dropped.saturating_add(1);
                continue;
            }
            // Insert keeping the table slowest first.
            let mut i = out.n as usize;
            out.rows[i] = K1Row { freq_khz: khz, uv: o.uv };
            while i > 0 && out.rows[i - 1].freq_khz > out.rows[i].freq_khz {
                out.rows.swap(i - 1, i);
                i -= 1;
            }
            out.n += 1;
        }
        if out.n == 0 {
            return Err(TableError::Empty);
        }
        for w in out.rows().windows(2) {
            if w[0].freq_khz == w[1].freq_khz {
                return Err(TableError::Duplicate);
            }
            if w[0].uv > w[1].uv {
                return Err(TableError::NotMonotonic);
            }
        }
        Ok(out)
    }

    /// The rows, slowest first.
    pub fn rows(&self) -> &[K1Row] {
        &self.rows[..self.n as usize]
    }

    /// OPPs left out because their voltage is over a ceiling.
    pub fn dropped(&self) -> u8 {
        self.dropped
    }

    /// The highest voltage the actuator will ever ask the rail for.
    pub fn ceiling_uv(&self) -> u32 {
        self.ceiling_uv
    }

    /// The row for exactly `khz`.
    pub fn row(&self, khz: u32) -> Option<K1Row> {
        self.rows().iter().copied().find(|r| r.freq_khz == khz)
    }

    /// The voltage a cluster needs to run at `khz`: that of the slowest row at
    /// or above it. `None` when `khz` is above the fastest row, which no
    /// voltage in the table is known to carry.
    pub fn need_uv(&self, khz: u32) -> Option<u32> {
        self.rows().iter().find(|r| r.freq_khz >= khz).map(|r| r.uv)
    }

    /// Microseconds the rail needs to rise by `delta_uv`, rounded up.
    fn ramp_us(&self, delta_uv: u32) -> u32 {
        delta_uv.div_ceil(self.ramp_uv_per_us)
    }
}

/// The clocks and rails of the clusters, supplied by the board.
pub trait K1Hw {
    /// The cluster's clock now, kHz.
    fn cpu_khz(&mut self, domain: usize) -> Result<u32, ActuateError>;
    /// Run the cluster at `khz`.
    fn set_cpu_khz(&mut self, domain: usize, khz: u32) -> Result<(), ActuateError>;
    /// The cluster's supply now, microvolts.
    fn voltage_uv(&mut self, domain: usize) -> Result<u32, ActuateError>;
    /// Set the cluster's supply to exactly `uv` microvolts.
    fn set_voltage_uv(&mut self, domain: usize, uv: u32) -> Result<(), ActuateError>;
    /// The frequency the cluster's clock will read back after
    /// `set_cpu_khz(domain, khz)`: the clock makes the closest rate it can,
    /// which is not always the asked one. Writes nothing.
    fn round_khz(&mut self, domain: usize, khz: u32) -> Result<u32, ActuateError>;
    /// The rail the cluster is supplied from, as a number only compared for
    /// equality: clusters that return the same one share a buck. `None`:
    /// the board does not say, and the cluster is taken to have its own.
    fn rail_of(&self, domain: usize) -> Option<u8>;
    /// Busy-wait at least `us` microseconds.
    fn delay_us(&mut self, us: u32);
}

/// A move that left a rail short of the clock's plan: the supply did not reach
/// `want_uv`. Not a refusal; see the module documentation, "What `Ok` and `Err`
/// say about the machine".
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RailLag {
    /// The cluster.
    pub domain: u8,
    /// The cluster's clock after the move, kHz: the one the throttle asked
    /// for when the move answered `Ok`, the one it was found at when it did
    /// not (a clock that would not move after the rail was raised for it).
    pub khz: u32,
    /// The supply as it was read before the write that failed, microvolts.
    /// A write that failed on its read-back may have taken effect: this is
    /// the last value known to be on the rail, not a measurement.
    pub last_uv: u32,
    /// The voltage the move wanted on the rail.
    pub want_uv: u32,
    /// What the rail answered.
    pub err: ActuateError,
}

/// The K1 actuator: a table per cluster over one [`K1Hw`].
pub struct K1Opp<H> {
    /// The clocks and rails.
    pub hw: H,
    tables: [Option<K1Table>; MAX_K1_DOMAINS],
    lag: Option<RailLag>,
    lagged: u32,
}

impl<H: K1Hw> K1Opp<H> {
    /// No cluster is bound: every request is `Unsupported` until
    /// [`K1Opp::bind`].
    pub const fn new(hw: H) -> Self {
        Self { hw, tables: [None; MAX_K1_DOMAINS], lag: None, lagged: 0 }
    }

    /// Give `domain` its table. `false` for a domain the K1 does not have.
    pub fn bind(&mut self, domain: usize, table: K1Table) -> bool {
        match self.tables.get_mut(domain) {
            Some(slot) => {
                *slot = Some(table);
                true
            }
            None => false,
        }
    }

    /// The last move that left a rail short, if it was not taken yet
    /// ([`RailLag`]).
    pub fn take_lag(&mut self) -> Option<RailLag> {
        self.lag.take()
    }

    /// Moves that left a rail short since this actuator was made, wrapping.
    pub fn lagged(&self) -> u32 {
        self.lagged
    }

    fn note_lag(&mut self, domain: usize, khz: u32, last_uv: u32, want_uv: u32, err: ActuateError) {
        self.lagged = self.lagged.wrapping_add(1);
        self.lag = Some(RailLag { domain: domain as u8, khz, last_uv, want_uv, err });
    }

    /// The voltage the *other* clusters on `domain`'s rail need at the clock
    /// they run now (0 if it has none). A cluster that has no table, or whose
    /// clock no row carries, needs "what the rail is at": `cur_uv`.
    fn shared_need(&mut self, domain: usize, cur_uv: u32) -> Result<u32, ActuateError> {
        let Some(rail) = self.hw.rail_of(domain) else { return Ok(0) };
        let mut need = 0;
        for other in 0..MAX_K1_DOMAINS {
            if other == domain || self.hw.rail_of(other) != Some(rail) {
                continue;
            }
            let known = match self.tables[other] {
                Some(t) => t.need_uv(self.hw.cpu_khz(other)?),
                None => None,
            };
            need = need.max(known.unwrap_or(cur_uv));
        }
        Ok(need)
    }
}

impl<H: K1Hw> OppActuator for K1Opp<H> {
    fn set_opp(&mut self, domain: usize, opp: &Opp) -> Result<(), ActuateError> {
        let t = self.tables.get(domain).copied().flatten().ok_or(ActuateError::Unsupported)?;
        let row = t.row(opp.freq_khz).ok_or(ActuateError::Refused)?;
        // Dropped at construction already; checked again so no path to the
        // rail depends on how the table was built.
        if row.uv > t.ceiling_uv {
            return Err(ActuateError::Refused);
        }
        // The clock that will result, and the voltage it needs: the slowest
        // row at or above it. A clock that would land above the fastest row
        // has no voltage anyone wrote down.
        let target_khz = self.hw.round_khz(domain, row.freq_khz)?;
        let own_uv = t.need_uv(target_khz).ok_or(ActuateError::Refused)?;
        let cur_khz = self.hw.cpu_khz(domain)?;
        let cur_uv = self.hw.voltage_uv(domain)?;
        // What the rail must carry: this cluster's need and the others on it.
        let want_uv = own_uv.max(self.shared_need(domain, cur_uv)?);
        if want_uv > t.ceiling_uv {
            return Err(ActuateError::Refused);
        }

        if target_khz > cur_khz {
            // Up: the rail first, and only ever up.
            let raised = want_uv > cur_uv;
            if raised {
                self.hw.set_voltage_uv(domain, want_uv)?;
                self.hw.delay_us(t.ramp_us(want_uv - cur_uv));
            }
            if let Err(e) = self.hw.set_cpu_khz(domain, row.freq_khz) {
                // Leave the cluster as it was found: put the rail back to the
                // voltage the cluster was already running at (not checked
                // against the table: that is firmware's). If the put-back
                // fails too the higher voltage stays, which is below the
                // ceiling and so safe; the clock did not move, so this is an
                // `Err` with the rail left short of the plan.
                if raised {
                    if let Err(back) = self.hw.set_voltage_uv(domain, cur_uv) {
                        self.note_lag(domain, cur_khz, want_uv, cur_uv, back);
                    }
                }
                return Err(e);
            }
            Ok(())
        } else {
            // Down, or the same frequency: the clock first, then the rail.
            let moved = target_khz < cur_khz;
            if moved {
                self.hw.set_cpu_khz(domain, row.freq_khz)?;
            }
            if want_uv != cur_uv {
                match self.hw.set_voltage_uv(domain, want_uv) {
                    Ok(()) => {
                        if want_uv > cur_uv {
                            self.hw.delay_us(t.ramp_us(want_uv - cur_uv));
                        }
                    }
                    // The clock is where it was asked and the supply is short
                    // of the plan, or the plan was to lower it and it did not
                    // come down: the throttle is done either way.
                    Err(e) if moved || want_uv < cur_uv => self.note_lag(domain, target_khz, cur_uv, want_uv, e),
                    // The clock did not move and the supply is below what it
                    // needs and cannot be raised: not an operating point.
                    Err(e) => return Err(e),
                }
            }
            Ok(())
        }
    }
}

// ---- the temperature sensor ----

/// Register offsets and fields of the `TSEN` block. All from Linux v7.3
/// `drivers/thermal/spacemit/k1_tsensor.c` (`K1_TSENSOR_*`).
mod reg {
    /// `K1_TSENSOR_PCTRL_REG`.
    pub const PCTRL: usize = 0x00;
    pub const PCTRL_ENABLE: u32 = 1 << 0;
    pub const PCTRL_TEMP_MODE: u32 = 1 << 3;
    pub const PCTRL_RAW_SEL: u32 = 1 << 7;
    /// `CTUNE`, bits 11:8.
    pub const PCTRL_CTUNE: u32 = 0xf << 8;
    /// `SW_CTRL`, bits 21:18.
    pub const PCTRL_SW_CTRL: u32 = 0xf << 18;
    pub const PCTRL_HW_AUTO_MODE: u32 = 1 << 23;
    /// `K1_TSENSOR_EN_REG`: one bit per sensor.
    pub const EN: usize = 0x08;
    /// `K1_TSENSOR_TIME_REG`, `K1_TSENSOR_TIME_MASK` is bits 23:0; the init
    /// sets the three fields below to all ones (`GENMASK`s).
    pub const TIME: usize = 0x0c;
    pub const TIME_MASK: u32 = 0x00ff_ffff;
    pub const TIME_FIELDS: u32 = (0x3 << 20) | (0xf << 4) | 0xf;
    /// `K1_TSENSOR_INT_EN_REG`: written all ones, which masks every
    /// interrupt (the tick polls).
    pub const INT_EN: usize = 0x14;
    /// `K1_TSENSOR_DATA_REG(x)`: `0x20 + (x / 2) * 4`; even sensors in the low
    /// half-word, odd in the high.
    pub const DATA_BASE: usize = 0x20;
}

/// Sensors of the block (`MAX_SENSOR_NUMBER`): 0 soc, 1 package, 2 gpu,
/// 3 cluster 0, 4 cluster 1 (the binding's `#thermal-sensor-cells`).
pub const K1_SENSORS: u8 = 5;
/// `TEMPERATURE_OFFSET`: the reading is degrees Celsius plus 278.
const TEMPERATURE_OFFSET: i32 = 278;

/// Register access to the `TSEN` window, supplied by the board.
pub trait K1TsensorBus {
    /// Read the register at byte offset `off`.
    fn read32(&mut self, off: usize) -> u32;
    /// Write the register at byte offset `off`.
    fn write32(&mut self, off: usize, v: u32);
}

/// Why [`K1Tsensor::start`] left the block alone or found it not running.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StartError {
    /// `PCTRL` read as all ones: nothing answers behind the window. No
    /// register was written.
    NoWindow,
    /// The block answers but did not keep what was written (held in reset, or
    /// its clock off): the registers were written and the block is not
    /// converting.
    NotHeld,
}

/// The K1 temperature sensor block.
pub struct K1Tsensor<B> {
    bus: B,
}

impl<B: K1TsensorBus> K1Tsensor<B> {
    /// Wrap the bus. The sensors are not converting yet: call
    /// [`K1Tsensor::start`].
    pub const fn new(bus: B) -> Self {
        Self { bus }
    }

    /// `k1_tsensor_init`: mask the interrupts, set the sampling time and
    /// filter, put every sensor in hardware auto mode and power the block up,
    /// enable each sensor.
    ///
    /// Clock and reset of the block are the platform's (`CLK_TSEN`,
    /// `CLK_TSEN_BUS`, `RESET_TSEN` of the APBC controller, which has no
    /// provider here), so the window is checked rather than assumed:
    ///
    /// * before anything is written, `PCTRL` is read; an all-ones word is what
    ///   a window with nothing behind it returns, and the block is refused
    ///   ([`StartError::NoWindow`]) with no register touched;
    /// * after the last write, `PCTRL` and `EN` are read back; a block held in
    ///   reset (it reads zeros whatever is written) does not keep the bits,
    ///   and is refused ([`StartError::NotHeld`]).
    ///
    /// The read-back sees a window that answers and does not hold the write.
    /// It cannot see a window that does not answer at all: an unclocked APB
    /// peripheral may stall the bus instead of returning, and no code at this
    /// level can tell. The APBC clock and reset are the platform's to give
    /// before the probe.
    pub fn start(&mut self) -> Result<(), StartError> {
        let p = self.bus.read32(reg::PCTRL);
        if p == 0xffff_ffff {
            return Err(StartError::NoWindow);
        }
        self.bus.write32(reg::INT_EN, 0xffff_ffff);
        let t = self.bus.read32(reg::TIME);
        self.bus.write32(reg::TIME, (t & !reg::TIME_MASK) | reg::TIME_FIELDS);
        let p = (p & !(reg::PCTRL_SW_CTRL | reg::PCTRL_CTUNE))
            | reg::PCTRL_RAW_SEL
            | reg::PCTRL_TEMP_MODE
            | reg::PCTRL_HW_AUTO_MODE
            | reg::PCTRL_ENABLE;
        self.bus.write32(reg::PCTRL, p);
        let all = (1 << K1_SENSORS) - 1;
        let en = self.bus.read32(reg::EN);
        self.bus.write32(reg::EN, en | all);
        let held = reg::PCTRL_ENABLE | reg::PCTRL_HW_AUTO_MODE;
        if self.bus.read32(reg::PCTRL) & held != held || self.bus.read32(reg::EN) & all != all {
            return Err(StartError::NotHeld);
        }
        Ok(())
    }
}

impl<B: K1TsensorBus> SensorBank for K1Tsensor<B> {
    /// Sensor `sensor`, milli-degrees Celsius. `Invalid` for a block that is
    /// not running (control or enable bit clear), for a conversion that has
    /// not landed (0), and for an all-ones half-word (what a window with nothing
    /// behind it reads as).
    fn read_mdeg(&mut self, sensor: u8) -> Result<i32, SensorError> {
        if sensor >= K1_SENSORS {
            return Err(SensorError::Absent);
        }
        if self.bus.read32(reg::PCTRL) & reg::PCTRL_ENABLE == 0 || self.bus.read32(reg::EN) & (1 << sensor) == 0 {
            return Err(SensorError::Invalid);
        }
        let w = self.bus.read32(reg::DATA_BASE + (sensor as usize / 2) * 4);
        let raw = if sensor % 2 == 1 { w >> 16 } else { w & 0xffff };
        if raw == 0 || raw == 0xffff {
            return Err(SensorError::Invalid);
        }
        Ok((raw as i32 - TEMPERATURE_OFFSET) * 1000)
    }
}

/// The K1 board object: the temperature sensor and the DVFS actuator.
pub struct K1<B, H> {
    /// The temperature sensor block.
    pub sensor: K1Tsensor<B>,
    /// The clusters' clocks and rails.
    pub opp: K1Opp<H>,
}

impl<B, H> K1<B, H> {
    /// The board object over its two halves.
    pub const fn new(sensor: K1Tsensor<B>, opp: K1Opp<H>) -> Self {
        Self { sensor, opp }
    }
}

impl<B: K1TsensorBus, H: K1Hw> SensorBank for K1<B, H> {
    fn read_mdeg(&mut self, sensor: u8) -> Result<i32, SensorError> {
        self.sensor.read_mdeg(sensor)
    }
}

impl<B: K1TsensorBus, H: K1Hw> OppActuator for K1<B, H> {
    fn set_opp(&mut self, domain: usize, opp: &Opp) -> Result<(), ActuateError> {
        self.opp.set_opp(domain, opp)
    }
}

/// The sensor channel a zone's `thermal-sensors = <&tsensor N>` names: the
/// K1's binding makes the cell the channel (`#thermal-sensor-cells = <1>`),
/// so a zone on channel 3 reads channel 3. `Runtime::from_dt`'s
/// `single_sensor` is the one-sensor boards' rule (cell 0 only) and would drop
/// the other four zones of the Jupiter tree. The phandle is not compared: a K1
/// tree has one sensor controller.
pub fn sensor_of(_phandle: u32, cell: u32) -> Option<u8> {
    u8::try_from(cell).ok().filter(|&c| c < K1_SENSORS)
}

/// The runtime of a K1 whose device tree is `dt`: [`Runtime::from_dt`] with
/// the K1's sensor rule ([`sensor_of`]), and each domain's boot OPP taken from
/// `boot_khz(domain)` (the cluster clock read back).
pub fn runtime_from_dt(
    dt: &DtThermal,
    model: &EnergyModel,
    boot_khz: impl Fn(usize) -> Option<u32>,
) -> (Runtime, Report) {
    let Built { thermal, zones_dropped, trips_dropped, coolers_dropped, truncated } = dt::build(dt, model, sensor_of);
    let report = Report { zones: thermal.zones().len() as u8, zones_dropped, trips_dropped, coolers_dropped, truncated };
    let mut rt = Runtime::new(thermal);
    rt.assume_boot(model, boot_khz);
    (rt, report)
}

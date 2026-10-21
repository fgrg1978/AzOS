// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The battery model: the state of charge, from the samples of the INA219
//! power monitor (`sensor.9`, the `SENSOR_TYPE_POWER` record). Pure: no
//! syscall here, the host suite (`tests/host/power-tests`) feeds it scripted
//! samples.
//!
//! The monitor's own `capacity_pct` assumes the pack was full when the driver
//! started, so it is right only on the first boot after a charge. The model
//! here keeps two estimates and lets each correct the other:
//!
//! * **Coulomb counting** follows the charge that left the pack since the last
//!   anchor: the growth of the monitor's `mah_used` against the pack's nominal
//!   capacity. Smooth, drifts.
//! * **Open-circuit voltage** reads the charge off the pack's voltage curve.
//!   Honest only at rest (the pack's own resistance drops the voltage under
//!   load), so the sample's voltage is first corrected by `current x R_int`,
//!   and the anchor moves the estimate only after [`REST_SAMPLES`] samples
//!   under [`REST_MA`] in a row.
//!
//! The first sample anchors the estimate on the voltage alone (load-corrected):
//! a pack that was half full at boot is not reported full.
//!
//! The monitor reports the current as a magnitude, so a charger is not seen:
//! the estimate only falls between rests, and a rested voltage is what raises
//! it again.
//!
//! The pack is the one the driver is sized for (`azos_ina219::chip`): 2S3P,
//! 3600 mAh. The curve is a generic Li-ion cell's, and `R_INT_MOHM` an estimate
//! for that pack, not a measurement (the same standing as the degrade speed
//! caps): both are the model's inputs to replace when the pack is measured.

/// Cells in series of the pack (2S3P).
pub const CELLS: u32 = 2;
/// Nominal capacity, mAh (`azos_ina219::chip::BATTERY_NOMINAL_MAH`).
pub const NOMINAL_MAH: u32 = 3_600;
/// Pack resistance, milliohms. An estimate, not a measurement.
pub const R_INT_MOHM: u32 = 100;
/// A sample under this current is at rest, mA.
pub const REST_MA: u32 = 50;
/// Consecutive rest samples before the voltage moves the estimate.
pub const REST_SAMPLES: u32 = 5;
/// A rested voltage pulls the estimate by 1/`REST_PULL` of the distance per
/// sample.
pub const REST_PULL: i32 = 8;
/// The monitor's `SENSOR_TYPE_POWER` record, bytes.
pub const RECORD_BYTES: usize = 12;

/// Open-circuit voltage of one cell, millivolts, against charge, tenths of a
/// percent: a generic Li-ion curve, 3.00 V empty to 4.20 V full.
const OCV: [(u32, i32); 11] = [
    (3_000, 0),
    (3_300, 50),
    (3_500, 100),
    (3_600, 200),
    (3_700, 400),
    (3_800, 550),
    (3_900, 700),
    (4_000, 820),
    (4_100, 920),
    (4_150, 970),
    (4_200, 1_000),
];

/// One sample of the monitor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sample {
    /// Pack voltage, millivolts.
    pub voltage_mv: u32,
    /// Current magnitude, milliamps.
    pub current_ma: u32,
    /// Charge drawn since the monitor started, mAh (grows).
    pub mah_used: u32,
}

impl Sample {
    /// Read the `SENSOR_TYPE_POWER` record: `voltage_mv u16`, `current_ma
    /// u16`, `mah_used u32` (little-endian). `None` for a short record.
    pub fn parse(rec: &[u8]) -> Option<Sample> {
        if rec.len() < 8 {
            return None;
        }
        Some(Sample {
            voltage_mv: u16::from_le_bytes([rec[0], rec[1]]) as u32,
            current_ma: u16::from_le_bytes([rec[2], rec[3]]) as u32,
            mah_used: u32::from_le_bytes([rec[4], rec[5], rec[6], rec[7]]),
        })
    }
}

/// The charge, tenths of a percent, a cell voltage means at rest.
pub const fn ocv_tenths(cell_mv: u32) -> i32 {
    if cell_mv <= OCV[0].0 {
        return 0;
    }
    let mut i = 1;
    while i < OCV.len() {
        let (v1, c1) = OCV[i];
        if cell_mv <= v1 {
            let (v0, c0) = OCV[i - 1];
            return c0 + ((cell_mv - v0) as i32 * (c1 - c0)) / (v1 - v0) as i32;
        }
        i += 1;
    }
    1_000
}

/// The charge, tenths of a percent, a pack sample means at rest: the voltage
/// corrected for the drop across the pack's resistance, per cell.
pub const fn pack_tenths(voltage_mv: u32, current_ma: u32) -> i32 {
    let drop_mv = current_ma * R_INT_MOHM / 1_000;
    ocv_tenths((voltage_mv + drop_mv) / CELLS)
}

/// The state of charge estimator.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Estimator {
    /// Tenths of a percent; `None` before the first sample.
    soc: Option<i32>,
    /// `mah_used` of the last sample.
    last_mah: u32,
    /// Consecutive rest samples.
    rest: u32,
}

impl Estimator {
    /// No sample yet.
    pub const fn new() -> Self {
        Estimator { soc: None, last_mah: 0, rest: 0 }
    }

    /// Take one sample; the charge now, percent (0..=100).
    pub fn update(&mut self, s: Sample) -> u8 {
        let anchor = pack_tenths(s.voltage_mv, s.current_ma);
        let mut soc = match self.soc {
            // The first sample, or a monitor that started over (its count went
            // back): the voltage alone.
            None => anchor,
            Some(_) if s.mah_used < self.last_mah => {
                self.rest = 0;
                anchor
            }
            Some(soc) => {
                let drawn = (s.mah_used - self.last_mah) as i64 * 1_000 / NOMINAL_MAH as i64;
                (soc as i64 - drawn).max(0) as i32
            }
        };
        self.last_mah = s.mah_used;
        if s.current_ma < REST_MA {
            self.rest = self.rest.saturating_add(1);
            if self.rest >= REST_SAMPLES {
                soc += (anchor - soc) / REST_PULL;
            }
        } else {
            self.rest = 0;
        }
        let soc = soc.clamp(0, 1_000);
        self.soc = Some(soc);
        pct(soc)
    }
}

fn pct(tenths: i32) -> u8 {
    ((tenths + 5) / 10).clamp(0, 100) as u8
}

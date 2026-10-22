// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The AHRS's barometric altitude term: the altitude relative to a reference
//! pressure. Pure, a child of `lib.rs`, so the host suite
//! (tests/host/flight-math-tests) pulls it by path.
//!
//! A failed read is never a pressure. The estimate stays where the last real
//! reading put it (`CH_BARO`'s age says how old that is), and the reference is
//! a real reading, never a standard atmosphere: a substituted 101 325 Pa made
//! the altitude jump to "sea level" on every barometer fault.

/// Relative barometric altitude.
#[derive(Clone, Copy)]
pub struct BaroAltitude {
    /// Pressure at the reference altitude (Pa); `None` until a real reading.
    ref_pa: Option<u32>,
    /// The last estimate, in centimetres above the reference.
    alt_cm: i32,
}

impl BaroAltitude {
    pub const fn new() -> Self {
        BaroAltitude { ref_pa: None, alt_cm: 0 }
    }

    /// Take `pa` as the reference (the boot's first reading).
    pub fn set_reference(&mut self, pa: u32) {
        self.ref_pa = Some(pa);
    }

    /// Fold in one reading (`None`: the read failed) and return the altitude
    /// in centimetres above the reference. With no reference yet, the first
    /// real reading becomes it.
    pub fn update(&mut self, pa: Option<u32>) -> i32 {
        if let Some(pa) = pa {
            let reference = *self.ref_pa.get_or_insert(pa);
            // Linear approximation near sea level: 8.3 cm per Pa.
            self.alt_cm = (reference as i32 - pa as i32) * 83 / 10;
        }
        self.alt_cm
    }
}

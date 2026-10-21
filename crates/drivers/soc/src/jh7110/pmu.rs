// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The JH7110 power-management unit: seven switchable domains, one bit each in
//! the switch registers. A switch is: write the domain mask to the turn-on
//! (or turn-off) register, write the three-word software "encourage" sequence
//! (`0xff`, then the two unlock words), then wait for the sequencer to report
//! done (or a failure) in the interrupt status register.
//!
//! Confirmed against the TRM (3.6, base `0x1703_0000` from Table 2-4):
//!
//! * `0x0c` software turn-on power mode and `0x10` software turn-off power
//!   mode, bit n = domain n (Table 3-13, Table 3-14);
//! * `0x44` software encourage, `[7:0]` (Table 3-19), written `0xff`, `0x05`,
//!   `0x50` to turn on and `0xff`, `0x0a`, `0xa0` to turn off (3.6.4,
//!   "Programming model");
//! * `0x80` current power mode, the same bit per domain (Table 3-26);
//! * `0x8c` interrupt status: `[0]` sequence done, `[1]` hardware request,
//!   `[3:2]` software failure, `[5:4]` hardware failure, `[8:6]` P-channel
//!   failure (Table 3-29);
//! * the domains in bit order: SYSTOP, CPU, GPUA, VDEC, VOUT, ISP, VENC.
//!
//! [verify] The acknowledge write to `0x8c` after a sequence: Table 3-29 lists
//! the register as read-only and documents no clear mechanism, so the write
//! (and whether a stale "done" bit survives into the next switch) is untested
//! on hardware.

use crate::pd::PowerDomainOps;
use crate::{Bus, Error, Result};

pub const PMU_COMPATIBLE: &str = "starfive,jh7110-pmu";

const SW_TURN_ON_POWER: u64 = 0x0c;
const SW_TURN_OFF_POWER: u64 = 0x10;
const SW_ENCOURAGE: u64 = 0x44;
const CURR_POWER_MODE: u64 = 0x80;
const INT_STATUS: u64 = 0x8c;

/// First word of both software sequences.
const ENCOURAGE_START: u32 = 0xff;
const ENCOURAGE_ON: [u32; 2] = [0x05, 0x50];
const ENCOURAGE_OFF: [u32; 2] = [0x0a, 0xa0];

const INT_SEQ_DONE: u32 = 1 << 0;
/// Software, hardware and power-switch failure bits.
const INT_FAIL: u32 = 0x1fc;

/// Domains: SYSTOP, CPU, GPUA, VDEC, VOUT, ISP, VENC (ids 0..=6, Table 3-13).
pub const DOMAINS: u32 = 7;
/// Status polls before a switch reports `Timeout`.
pub const POLL_BUDGET: u32 = 1000;

pub struct Jh7110Pmu {
    base: u64,
}

impl Jh7110Pmu {
    pub const fn new(base: u64) -> Self {
        Jh7110Pmu { base }
    }

    pub fn from_dt(fdt: &crate::Fdt<'_>, node: crate::NodeId) -> Option<Self> {
        if !fdt.is_available(node) || !fdt.is_compatible(node, PMU_COMPATIBLE) {
            return None;
        }
        fdt.reg(node).map(|(base, _)| Jh7110Pmu::new(base))
    }

    fn switch(&mut self, bus: &mut dyn Bus, id: u32, on: bool) -> Result<()> {
        if id >= DOMAINS {
            return Err(Error::BadSpec);
        }
        let mask = 1u32 << id;
        if (bus.read32(self.base + CURR_POWER_MODE) & mask != 0) == on {
            return Ok(());
        }
        bus.write32(self.base + if on { SW_TURN_ON_POWER } else { SW_TURN_OFF_POWER }, mask);
        let [lo, hi] = if on { ENCOURAGE_ON } else { ENCOURAGE_OFF };
        bus.write32(self.base + SW_ENCOURAGE, ENCOURAGE_START);
        bus.write32(self.base + SW_ENCOURAGE, lo);
        bus.write32(self.base + SW_ENCOURAGE, hi);
        for _ in 0..POLL_BUDGET {
            let st = bus.read32(self.base + INT_STATUS);
            if st & (INT_SEQ_DONE | INT_FAIL) != 0 {
                // Acknowledge what was read.
                bus.write32(self.base + INT_STATUS, st);
                return if st & INT_FAIL != 0 { Err(Error::Hardware) } else { Ok(()) };
            }
        }
        Err(Error::Timeout)
    }
}

impl PowerDomainOps for Jh7110Pmu {
    fn count(&self) -> u32 {
        DOMAINS
    }
    fn power_on(&mut self, bus: &mut dyn Bus, id: u32) -> Result<()> {
        self.switch(bus, id, true)
    }
    fn power_off(&mut self, bus: &mut dyn Bus, id: u32) -> Result<()> {
        self.switch(bus, id, false)
    }
    fn is_on(&mut self, bus: &mut dyn Bus, id: u32) -> Result<bool> {
        if id >= DOMAINS {
            return Err(Error::BadSpec);
        }
        Ok(bus.read32(self.base + CURR_POWER_MODE) & (1 << id) != 0)
    }
}

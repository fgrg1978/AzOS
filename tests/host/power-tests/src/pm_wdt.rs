// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The BCM2835 PM block (crates/drivers/power/src/bcm2835_pm.rs, pulled in by
//! path, so the code under test is the code the kernel links) against a fake
//! block that behaves as the datasheet and QEMU's `bcm2835_powermgt` say: a
//! write without the password is dropped, `WDOG` counts down at 65 536 Hz,
//! and with `RSTC.WRCFG` = full reset the SoC resets when it reaches 0, into
//! the boot partition `RSTS` names.

#[allow(dead_code)]
#[path = "../../../../crates/drivers/power/src/bcm2835_pm.rs"]
mod bcm2835_pm;

use bcm2835_pm::*;
use std::cell::Cell;

#[derive(Default)]
struct Block {
    rstc: Cell<u32>,
    rsts: Cell<u32>,
    wdog: Cell<u32>,
    /// Writes the block dropped (no password).
    dropped: Cell<u32>,
    /// Resets fired, and the partition the firmware saw at the last one.
    resets: Cell<u32>,
    partition: Cell<Option<u8>>,
}

impl Block {
    /// What the firmware decodes from `RSTS` after a reset: the even bits.
    fn decode_partition(rsts: u32) -> u8 {
        let mut p = 0u8;
        for i in 0..6 {
            p |= ((rsts >> (2 * i) & 1) as u8) << i;
        }
        p
    }

    /// Let `ticks` watchdog ticks pass.
    fn advance(&self, ticks: u32) {
        if self.rstc.get() & 0x30 != RSTC_WRCFG_FULL_RESET {
            return;
        }
        let left = self.wdog.get();
        if ticks >= left {
            self.wdog.set(0);
            self.resets.set(self.resets.get() + 1);
            self.partition.set(Some(Self::decode_partition(self.rsts.get())));
            // The reset clears WRCFG.
            self.rstc.set(self.rstc.get() & RSTC_WRCFG_CLR);
        } else {
            self.wdog.set(left - ticks);
        }
    }

    fn halted(&self) -> bool {
        self.partition.get() == Some(PARTITION_HALT)
    }
}

impl PmRegs for Block {
    fn read32(&self, off: usize) -> u32 {
        match off {
            RSTC => self.rstc.get(),
            RSTS => self.rsts.get(),
            WDOG => self.wdog.get(),
            _ => panic!("read of {off:#x}"),
        }
    }
    fn write32(&self, off: usize, val: u32) {
        if val & 0xff00_0000 != PASSWORD {
            self.dropped.set(self.dropped.get() + 1);
            return;
        }
        let v = val & 0x00ff_ffff;
        match off {
            RSTC => self.rstc.set(v),
            RSTS => self.rsts.set(v),
            WDOG => self.wdog.set(v & WDOG_TIME_MASK),
            _ => panic!("write of {off:#x}"),
        }
    }
}

#[test]
fn the_partition_is_spread_over_the_even_bits() {
    assert_eq!(partition_bits(0), 0);
    assert_eq!(partition_bits(1), 1);
    assert_eq!(partition_bits(2), 4);
    assert_eq!(partition_bits(PARTITION_HALT), 0x555);
    assert_eq!(Block::decode_partition(partition_bits(42)), 42);
}

#[test]
fn a_timeout_becomes_ticks_within_what_the_counter_holds() {
    assert_eq!(ticks_for_ms(1000), TICKS_PER_S);
    assert_eq!(ticks_for_ms(0), 1);
    assert_eq!(ticks_for_ms(60_000), WDOG_TIME_MASK);
    assert_eq!(MAX_TIMEOUT_MS, 15_999);
    assert!(ticks_for_ms(MAX_TIMEOUT_MS) <= WDOG_TIME_MASK);
}

#[test]
fn a_reboot_resets_into_partition_zero_soon() {
    let b = Block::default();
    // A bit outside the partition field (bit 9) stays as it was.
    b.rsts.set(0x200 | partition_bits(PARTITION_HALT));
    restart(&b, 0);
    assert_eq!(b.dropped.get(), 0, "every write carries the password");
    b.advance(RESET_TICKS - 1);
    assert_eq!(b.resets.get(), 0);
    b.advance(1);
    assert_eq!(b.resets.get(), 1);
    assert_eq!(b.partition.get(), Some(0));
    assert_eq!(b.rsts.get() & 0x200, 0x200);
}

#[test]
fn a_power_off_resets_into_the_halt_partition() {
    let b = Block::default();
    restart(&b, PARTITION_HALT);
    assert_eq!(b.dropped.get(), 0);
    b.advance(RESET_TICKS);
    assert_eq!(b.resets.get(), 1);
    assert!(b.halted(), "the firmware must see partition 63, saw {:?}", b.partition.get());
}

#[test]
fn a_kicked_watchdog_never_fires_and_a_forgotten_one_does() {
    let b = Block::default();
    let t = ticks_for_ms(1000);
    arm(&b, t);
    assert!(armed(&b));
    for _ in 0..20 {
        b.advance(t / 2);
        arm(&b, t);
    }
    assert_eq!(b.resets.get(), 0);
    b.advance(t);
    assert_eq!(b.resets.get(), 1);
    assert_eq!(b.partition.get(), Some(0));
}

#[test]
fn a_disarmed_watchdog_never_fires() {
    let b = Block::default();
    arm(&b, ticks_for_ms(100));
    disarm(&b);
    assert!(!armed(&b));
    b.advance(WDOG_TIME_MASK);
    assert_eq!(b.resets.get(), 0);
    assert_eq!(b.dropped.get(), 0);
}

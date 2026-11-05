// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The device models of this suite keep 32-bit register files behind inherent
//! `$read(&self, off) -> u32` and `$write(&self, off, u32)`; this makes them
//! the kit's `Mmio`. Any other width panics: a driver that reads a 32-bit
//! register as a byte is wrong, and the model says so.

macro_rules! registers32 {
    ($m:ty, $read:ident, $write:ident) => {
        impl azos_drvkit::Mmio for $m {
            fn load(&self, off: usize, w: azos_drvkit::Width) -> u64 {
                assert_eq!(w, azos_drvkit::Width::W32, "the model's registers are 32-bit");
                self.$read(off) as u64
            }
            fn store(&self, off: usize, w: azos_drvkit::Width, v: u64) {
                assert_eq!(w, azos_drvkit::Width::W32, "the model's registers are 32-bit");
                self.$write(off, v as u32)
            }
        }
    };
}

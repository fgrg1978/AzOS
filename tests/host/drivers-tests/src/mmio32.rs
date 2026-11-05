// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The device models of this suite keep register files behind inherent
//! methods of their own; these make them the kit's `Mmio`. A width the model
//! has no method for panics: a driver that reads a 32-bit register as a byte
//! is wrong, and the model says so.

/// A model whose registers are all 32 bits wide: `$read(off) -> u32` and
/// `$write(off, u32)`, at address 0 or at the `$base()` the model names.
macro_rules! registers32 {
    ($m:ty, $read:ident, $write:ident) => {
        registers32!($m, $read, $write, |_: &$m| 0usize);
    };
    ($m:ty, $read:ident, $write:ident, $base:ident) => {
        registers32!($m, $read, $write, |m: &$m| m.$base());
    };
    ($m:ty, $read:ident, $write:ident, $base:expr) => {
        impl azos_drvkit::Mmio for $m {
            fn load(&self, off: usize, w: azos_drvkit::Width) -> u64 {
                assert_eq!(w, azos_drvkit::Width::W32, "the model's registers are 32-bit");
                self.$read(off) as u64
            }
            fn store(&self, off: usize, w: azos_drvkit::Width, v: u64) {
                assert_eq!(w, azos_drvkit::Width::W32, "the model's registers are 32-bit");
                self.$write(off, v as u32)
            }
            fn base(&self) -> usize {
                ($base)(self)
            }
        }
    };
}

/// A model with 8, 16 and 32-bit registers: `$r8`, `$r16`, `$r32` and
/// `$w8`, `$w16`, `$w32`, at the `$base()` the model names.
macro_rules! registers {
    ($m:ty, $r8:ident, $r16:ident, $r32:ident, $w8:ident, $w16:ident, $w32:ident, $base:ident) => {
        impl azos_drvkit::Mmio for $m {
            fn load(&self, off: usize, w: azos_drvkit::Width) -> u64 {
                match w {
                    azos_drvkit::Width::W8 => self.$r8(off) as u64,
                    azos_drvkit::Width::W16 => self.$r16(off) as u64,
                    azos_drvkit::Width::W32 => self.$r32(off) as u64,
                    azos_drvkit::Width::W64 => panic!("the model has no 64-bit registers"),
                }
            }
            fn store(&self, off: usize, w: azos_drvkit::Width, v: u64) {
                match w {
                    azos_drvkit::Width::W8 => self.$w8(off, v as u8),
                    azos_drvkit::Width::W16 => self.$w16(off, v as u16),
                    azos_drvkit::Width::W32 => self.$w32(off, v as u32),
                    azos_drvkit::Width::W64 => panic!("the model has no 64-bit registers"),
                }
            }
            fn base(&self) -> usize {
                self.$base()
            }
        }
    };
}

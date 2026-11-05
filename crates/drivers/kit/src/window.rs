// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! [`Window`]: the register block at a mapped address.

use crate::{Mmio, Width};
use azos_arch_api::mmio;

/// The registers at `base`, read and written through `azos_arch_api::mmio`
/// (VA = the address the block is mapped at: the kernel's identity map, or the
/// ring-3 mapping a `DOMAIN_MMIO_MAP` returned).
#[derive(Clone, Copy)]
pub struct Window {
    base: usize,
}

impl Window {
    /// # Safety
    /// `base` is the start of a mapped device register block, and every offset
    /// the driver reads or writes through the window lies inside it, aligned to
    /// the width of the access, for as long as the window is used.
    #[inline(always)]
    pub const unsafe fn new(base: usize) -> Self {
        Window { base }
    }

}

impl Mmio for Window {
    #[inline(always)]
    fn load(&self, off: usize, w: Width) -> u64 {
        let a = self.base + off;
        // SAFETY: `new`'s contract: the offset is inside the mapped block.
        unsafe {
            match w {
                Width::W8 => mmio::read8(a) as u64,
                Width::W16 => mmio::read16(a) as u64,
                Width::W32 => mmio::read32(a) as u64,
                Width::W64 => mmio::read64(a),
            }
        }
    }

    #[inline(always)]
    fn base(&self) -> usize {
        self.base
    }

    #[inline(always)]
    fn store(&self, off: usize, w: Width, v: u64) {
        let a = self.base + off;
        // SAFETY: as `load`.
        unsafe {
            match w {
                Width::W8 => mmio::write8(a, v as u8),
                Width::W16 => mmio::write16(a, v as u16),
                Width::W32 => mmio::write32(a, v as u32),
                Width::W64 => mmio::write64(a, v),
            }
        }
    }
}

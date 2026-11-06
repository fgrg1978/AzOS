// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! An interrupt line as a source: a ring-3 driver's.

use super::{ok, Port};
use azos_libsys as sys;

impl Port {
    /// Report the interrupts of the line `line` (routed to `cpu`): the CPU
    /// the kernel routed it to.
    pub fn bind_irq(&self, line: u32, key: u64, cpu: u64) -> Result<u32, isize> {
        let r = sys::irq_bind(line, self.cap, key, cpu);
        ok(r).map(|()| r as u32)
    }
}

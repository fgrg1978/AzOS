// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! A doorbell source: the consumer side of a shared ring.

use super::{ok, Port};
use azos_libsys as sys;

impl Port {
    /// Report the wakes of the word at `offset` of the region `region`.
    pub fn bind_doorbell(&self, region: u32, offset: u32, key: u64) -> Result<(), isize> {
        ok(sys::port_bind_doorbell(self.cap, region, offset, key))
    }
}

// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The resource-partition tag follows the task (riscv64 Ssqosid `srmcfg`;
//! aarch64 MPAM and x86_64 RDT answer "no tagging" until they implement
//! `Cpu::qos_max_partition`/`Cpu::set_qos_tag`).
//!
//! Every memory request a hart issues carries a small id that a cache or
//! bandwidth controller apportions by. A task's id is its Domain's
//! `partition_id` (`domain::partition_of`): the `partition_id` of its topology
//! task row, inherited by a child Domain. On a context switch the incoming
//! task's id is made the hart's ([`HartTags::retag`], called from
//! `asid::prepare_switch`, the one place all three switch sites pass
//! through), and only when it differs from what this hart already holds: a
//! kernel with no partitioned row writes the tag once per hart (the first
//! switch-in, since the CSR's reset value is the hardware's, not ours).
//!
//! The kernel's own work for a task (a syscall, a fault) runs under that
//! task's tag, as on Linux: it is the task's cache footprint. A kernel task
//! and the idle task are in Domain 0's partition, the default.
//!
//! This file is pure (no arch dependency, host-tested): the seam is the
//! `write` closure, the arch calls live in `asid.rs` and `scheduler/budget.rs`.

use core::sync::atomic::{AtomicU32, Ordering};

/// Kconfig `NR_CPUS`: one slot per CPU id.
pub const HARTS: usize = azos_limits::NR_CPUS;

/// What a slot holds before its hart has written once.
const UNKNOWN: u32 = u32::MAX;

/// The tag each hart holds, as this kernel last wrote it. A slot is touched
/// only by its own hart, with interrupts masked (the switch path), so
/// `Relaxed` is the whole protocol.
pub struct HartTags([AtomicU32; HARTS]);

impl HartTags {
    pub const fn new() -> Self {
        Self([const { AtomicU32::new(UNKNOWN) }; HARTS])
    }

    /// Make `want` the tag of CPU `cpu`: `write(want)` unless the hart already
    /// holds it. `true` when `write` ran and succeeded. A `write` that answers
    /// `false` (the hardware cannot tag `want`) leaves the slot as it was, so
    /// the next switch asks again instead of believing a write that did not
    /// happen. A CPU id past the table (never, with `NR_CPUS` right) writes
    /// every time.
    #[inline(always)]
    pub fn retag(&self, cpu: usize, want: u16, write: impl FnOnce(u16) -> bool) -> bool {
        let Some(slot) = self.0.get(cpu) else { return write(want) };
        if slot.load(Ordering::Relaxed) == want as u32 {
            return false;
        }
        let done = write(want);
        if done {
            slot.store(want as u32, Ordering::Relaxed);
        }
        done
    }

    /// The tag CPU `cpu` holds as last written; `None` before its first write.
    pub fn held(&self, cpu: usize) -> Option<u16> {
        self.0.get(cpu).map(|s| s.load(Ordering::Relaxed)).filter(|&v| v != UNKNOWN).map(|v| v as u16)
    }
}

/// The tags of every hart (`asid::prepare_switch`).
pub static TAGS: HartTags = HartTags::new();

/// The partition a Domain actually runs in when its row asks for `want` on a
/// machine whose hart tags up to `max` (`Cpu::qos_max_partition`): `want`
/// itself when it fits, or when the machine does not tag at all (`max == 0`:
/// nothing to alias, and the declared id stays visible to introspection);
/// the default partition `0` when `want` is above `max`, because a masked
/// write would put it in another partition's share.
pub const fn fit(want: u16, max: u16) -> u16 {
    if max != 0 && want > max { 0 } else { want }
}

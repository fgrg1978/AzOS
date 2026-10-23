// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Ring-3 port I/O: the seam between the ports a thread has open (one
//! [`PortGrant`] per task slot, kept by `azos_sched::ioport`) and the ISA
//! mechanism that enforces them ([`IoPorts`]).
//!
//! | ISA     | port space                         | mechanism                         |
//! |---------|------------------------------------|-----------------------------------|
//! | x86_64  | 0..[`PORTS`] (Kconfig)             | the TSS I/O permission bitmap     |
//! | riscv64 | none: devices are memory-mapped    | the defaults: nothing to load     |
//! | aarch64 | none: devices are memory-mapped    | the defaults: nothing to load     |
//!
//! The space is Kconfig `X86_IOPORT_BITMAP_PORTS`, which the build refuses
//! to set off x86_64, so [`PORTS`] is 0 on the other ISAs and every caller
//! of the seam (the minter, the op, the switch) answers "no port space"
//! there through the same code, not through a `cfg`.

use core::sync::atomic::{AtomicU32, AtomicU64, AtomicU8, Ordering};

/// Ports ring 3 can be given: 0..this-1. 0 where the ISA has no port space.
pub const PORTS: u32 = azos_limits::X86_IOPORT_BITMAP_PORTS as u32;

/// Ranges one thread can hold open (Kconfig `X86_IOPORT_RANGES`).
pub const RANGES: usize = azos_limits::X86_IOPORT_RANGES as usize;

/// The source of [`PortGrant`] keys: never 0, never reused.
static NEXT_KEY: AtomicU64 = AtomicU64::new(1);

/// One thread's open ports: up to [`RANGES`] inclusive `(first, last)`
/// ranges, and the key that names this exact set.
///
/// Only the thread itself changes its set (the op, on its own CPU, with
/// interrupts off) and the slot's creation clears it; a switch to the thread
/// reads it. Each change takes a fresh key, so an ISA that caches "the
/// bitmap of key K is loaded on this CPU" can never mistake an older set, or
/// another thread's, for this one. Key 0 is the empty set.
pub struct PortGrant {
    key: AtomicU64,
    n: AtomicU8,
    /// `first | last << 16`, the first `n` in use.
    ranges: [AtomicU32; RANGES],
}

/// Why [`PortGrant::add`] refused.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum GrantFull {
    /// The thread already holds [`RANGES`] ranges.
    Full,
}

impl PortGrant {
    /// No port open.
    pub const fn new() -> Self {
        PortGrant { key: AtomicU64::new(0), n: AtomicU8::new(0), ranges: [const { AtomicU32::new(0) }; RANGES] }
    }

    /// The key of the set: 0 when no port is open.
    #[inline(always)]
    pub fn key(&self) -> u64 {
        self.key.load(Ordering::Acquire)
    }

    /// The open ranges, `(first, last)` inclusive, into `out`; their count.
    pub fn ranges(&self, out: &mut [(u16, u16); RANGES]) -> usize {
        let n = (self.n.load(Ordering::Relaxed) as usize).min(RANGES);
        for (o, r) in out.iter_mut().zip(&self.ranges[..n]) {
            let w = r.load(Ordering::Relaxed);
            *o = (w as u16, (w >> 16) as u16);
        }
        n
    }

    /// Open `first..=last` too. `Ok(false)` when an open range already holds
    /// it (nothing changes, the key stays), `Ok(true)` when it was added
    /// under a new key.
    pub fn add(&self, first: u16, last: u16) -> Result<bool, GrantFull> {
        let n = (self.n.load(Ordering::Relaxed) as usize).min(RANGES);
        let covered = self.ranges[..n].iter().any(|r| {
            let w = r.load(Ordering::Relaxed);
            w as u16 <= first && last <= (w >> 16) as u16
        });
        if covered {
            return Ok(false);
        }
        if n == RANGES {
            return Err(GrantFull::Full);
        }
        self.ranges[n].store(first as u32 | (last as u32) << 16, Ordering::Relaxed);
        self.n.store(n as u8 + 1, Ordering::Relaxed);
        self.key.store(NEXT_KEY.fetch_add(1, Ordering::Relaxed), Ordering::Release);
        Ok(true)
    }

    /// Close every port.
    pub fn clear(&self) {
        self.key.store(0, Ordering::Release);
        self.n.store(0, Ordering::Relaxed);
    }
}

impl Default for PortGrant {
    fn default() -> Self {
        Self::new()
    }
}

/// The ISA side of ring-3 port I/O. The defaults are the ISAs with no port
/// space: there is nothing to load, so riscv64 and aarch64 implement nothing.
pub trait IoPorts: Send + Sync {
    /// This CPU is about to run (or goes on running) a thread whose open
    /// ports are `grant`: from its next instruction in ring 3, exactly those
    /// ports run and every other faults. Called by the scheduler on every
    /// switch (`set_current_task`) and by the op that opens a range, with
    /// interrupts off, on the CPU `cpu` names (the caller's own).
    #[inline(always)]
    fn io_ports_load(&self, cpu: usize, grant: &PortGrant) {
        let _ = (cpu, grant);
    }
}

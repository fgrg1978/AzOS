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
//!
//! **The kernel's own ports.** A kernel driver that binds legacy ports
//! (COM1, the CMOS clock, the PCI configuration pair, the 8042, the PIT's
//! channel 0, the 8259s, the ACPI PM timer) says so where it binds them
//! ([`reserve`]), and the topology minter (`azos_ipc::ioport_cap`) refuses a
//! grant that holds one of them ([`reserved`]), whatever the signed row asks.
//! The set is one bit per port of the space, filled at boot before the first
//! ring-3 row is seeded, so it holds exactly what the kernel's drivers bound
//! on this machine: no list of ports to keep in step with them.
//!
//! **Revocation.** A capability over a range that leaves its table (revoked,
//! moved away) closes the range in every thread of that table that opened it
//! through it ([`PortGrant::remove_within`]): the set takes a new key, so the
//! next switch to the thread loads the smaller set, and `azos_sched::ioport`
//! makes every other CPU switch-load its running thread again by IPI.

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicU8, Ordering};

/// Ports ring 3 can be given: 0..this-1. 0 where the ISA has no port space.
pub const PORTS: u32 = azos_limits::X86_IOPORT_BITMAP_PORTS as u32;

/// Ranges one thread can hold open (Kconfig `X86_IOPORT_RANGES`).
pub const RANGES: usize = azos_limits::X86_IOPORT_RANGES as usize;

/// The source of [`PortGrant`] keys: never 0, never reused.
static NEXT_KEY: AtomicU64 = AtomicU64::new(1);

/// One thread's open ports: up to [`RANGES`] inclusive `(first, last)`
/// ranges, the capability table they were opened through, and the key that
/// names this exact set.
///
/// Three writers change a set: the thread itself (the op, on its own CPU),
/// a revocation on any CPU ([`remove_within`](Self::remove_within)) and the
/// slot's creation ([`clear`](Self::clear)). They take the set's own lock,
/// with interrupts off; a switch to the thread reads it without one. Each
/// change takes a fresh key, stored last, so an ISA that caches "the bitmap
/// of key K is loaded on this CPU" can never mistake an older set, or
/// another thread's, for this one: a switch that read an old key while a
/// writer ran loaded a part of the old set, and the next one sees the new
/// key. Key 0 is the empty set.
pub struct PortGrant {
    key: AtomicU64,
    n: AtomicU8,
    /// The writers' lock (see the type's doc).
    busy: AtomicBool,
    /// The capability table the ranges were opened through ([`NO_TABLE`]: none).
    table: AtomicU32,
    /// `first | last << 16`, the first `n` in use.
    ranges: [AtomicU32; RANGES],
}

/// [`PortGrant`]'s table when no range is open.
pub const NO_TABLE: u32 = u32::MAX;

/// Why [`PortGrant::add`] refused.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum GrantFull {
    /// The thread already holds [`RANGES`] ranges.
    Full,
}

impl PortGrant {
    /// No port open.
    pub const fn new() -> Self {
        PortGrant {
            key: AtomicU64::new(0),
            n: AtomicU8::new(0),
            busy: AtomicBool::new(false),
            table: AtomicU32::new(NO_TABLE),
            ranges: [const { AtomicU32::new(0) }; RANGES],
        }
    }

    /// Run `f` as the set's one writer.
    fn write<R>(&self, f: impl FnOnce() -> R) -> R {
        while self.busy.compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed).is_err() {
            core::hint::spin_loop();
        }
        let r = f();
        self.busy.store(false, Ordering::Release);
        r
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

    /// Open `first..=last` too, through a capability of table `table` (the
    /// thread's own: every range of a set has the same). `Ok(false)` when an
    /// open range already holds it (nothing changes, the key stays),
    /// `Ok(true)` when it was added under a new key.
    pub fn add(&self, first: u16, last: u16, table: u32) -> Result<bool, GrantFull> {
        self.write(|| {
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
            self.table.store(table, Ordering::Relaxed);
            self.ranges[n].store(first as u32 | (last as u32) << 16, Ordering::Relaxed);
            self.n.store(n as u8 + 1, Ordering::Relaxed);
            self.key.store(NEXT_KEY.fetch_add(1, Ordering::Relaxed), Ordering::Release);
            Ok(true)
        })
    }

    /// A capability of table `table` over `first..=last` went: close every
    /// open range inside it, when the set was opened through that table.
    /// `true` when one closed: the set has a new key (0 when it is empty).
    ///
    /// Only the ranges inside go. A range the thread opened through another,
    /// wider capability stays; one it opened through this capability and
    /// also holds by another of the same range closes with it, and the thread
    /// opens it again through the other.
    ///
    /// The ranges kept are moved down in place: a switch reading the set
    /// meanwhile sees a part of the old one, never a port outside it.
    pub fn remove_within(&self, table: u32, first: u16, last: u16) -> bool {
        self.write(|| {
            if self.table.load(Ordering::Relaxed) != table {
                return false;
            }
            let n = (self.n.load(Ordering::Relaxed) as usize).min(RANGES);
            let mut kept = 0;
            for i in 0..n {
                let w = self.ranges[i].load(Ordering::Relaxed);
                if first <= w as u16 && (w >> 16) as u16 <= last {
                    continue;
                }
                self.ranges[kept].store(w, Ordering::Relaxed);
                kept += 1;
            }
            if kept == n {
                return false;
            }
            self.n.store(kept as u8, Ordering::Relaxed);
            let key = if kept == 0 { 0 } else { NEXT_KEY.fetch_add(1, Ordering::Relaxed) };
            self.key.store(key, Ordering::Release);
            true
        })
    }

    /// Close every port.
    pub fn clear(&self) {
        self.write(|| {
            self.key.store(0, Ordering::Release);
            self.n.store(0, Ordering::Relaxed);
            self.table.store(NO_TABLE, Ordering::Relaxed);
        })
    }
}

impl Default for PortGrant {
    fn default() -> Self {
        Self::new()
    }
}

/// A set of ports, one bit each, below `32 * W`: a port past that is never
/// in it.
pub struct PortSet<const W: usize> {
    bits: [AtomicU32; W],
}

impl<const W: usize> PortSet<W> {
    /// No port.
    pub const fn new() -> Self {
        PortSet { bits: [const { AtomicU32::new(0) }; W] }
    }

    /// Add `first..=last`; the ports past the set's reach are left out (no
    /// grant can name them).
    pub fn insert(&self, first: u16, last: u16) {
        for port in first as usize..=last as usize {
            let Some(w) = self.bits.get(port / 32) else { break };
            w.fetch_or(1 << (port % 32), Ordering::Release);
        }
    }

    /// The first port of `first..=last` in the set.
    pub fn first_in(&self, first: u16, last: u16) -> Option<u16> {
        (first..=last).find(|&p| {
            let p = p as usize;
            self.bits.get(p / 32).is_some_and(|w| w.load(Ordering::Acquire) & 1 << (p % 32) != 0)
        })
    }
}

impl<const W: usize> Default for PortSet<W> {
    fn default() -> Self {
        Self::new()
    }
}

/// The ports the kernel drives itself: one bit per port of the space,
/// none where there is no space.
static KERNEL_PORTS: PortSet<{ (PORTS as usize).div_ceil(32) }> = PortSet::new();

/// The kernel drives `first..=last` itself: no grant may open a port of it
/// (`azos_ipc::ioport_cap`). Called by each kernel driver where it binds the
/// ports, at boot, before the first ring-3 row is seeded; never undone (a
/// kernel driver does not give its ports to ring 3).
pub fn reserve(first: u16, last: u16) {
    KERNEL_PORTS.insert(first, last)
}

/// The first port of `first..=last` the kernel [`reserve`]d.
pub fn reserved(first: u16, last: u16) -> Option<u16> {
    KERNEL_PORTS.first_in(first, last)
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

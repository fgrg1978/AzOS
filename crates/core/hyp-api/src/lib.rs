// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The ABI between the kernel and the resident monitor (VIRT_SPLIT), the same
//! on every ISA: call ids, status codes, the invariants `probe` reports and
//! the violation record. Arguments are physical addresses or plain values;
//! nothing here dereferences anything.
#![no_std]

/// Bumped on any change of a call's arguments or of [`Violation`].
pub const ABI_VERSION: u64 = 1;

/// SMCCC fast call, 64-bit convention, owner "vendor hypervisor service"
/// (OEN 6): the range PSCI and firmware services never use, so one trap
/// handler tells a monitor call from a firmware call by the id alone.
pub const CALL_BASE: u64 = 0xC600_0000;
pub const CALL_MASK: u64 = 0xFFFF_0000;

/// `probe() -> (OK, ABI_VERSION, invariants, pes_up)`.
pub const CALL_PROBE: u64 = CALL_BASE;
/// `violation_read(cursor) -> (status, next, kind | pe << 32, syndrome, addr, aux)`.
pub const CALL_VIOLATION_READ: u64 = CALL_BASE + 1;

pub const fn is_monitor_call(id: u64) -> bool {
    id & CALL_MASK == CALL_BASE
}

/// Status in the first return register; negative values as `i64`.
pub const OK: i64 = 0;
pub const NOT_SUPPORTED: i64 = -1;
pub const DENIED: i64 = -2;
pub const INVALID: i64 = -3;
/// `violation_read` at the head of the ring: no record yet.
pub const EMPTY: i64 = -4;

/// Invariants in force, as `probe` reports them. A bit is set only by the
/// code that enforces it, never by configuration.
pub const INV_EL2_MMU: u64 = 1 << 0;
/// Host stage-2 on, the monitor's own memory a hole in it.
pub const INV_HOST_S2: u64 = 1 << 1;
/// SMC trapped; PSCI and firmware calls filtered, PE entries substituted.
pub const INV_PSCI: u64 = 1 << 2;

pub const INVARIANT_NAMES: [(u64, &str); 3] = [
    (INV_EL2_MMU, "el2-mmu"),
    (INV_HOST_S2, "host-s2"),
    (INV_PSCI, "psci"),
];

/// What a violation record describes.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum Kind {
    /// A stage-2 fault: `addr` is the faulting IPA, `aux` the PC.
    Stage2Fault = 1,
    /// A firmware call off the allow list: `addr` is the function id.
    CallRefused = 2,
    /// A PE entry (CPU_ON, suspend) other than the registered one: `addr` is
    /// the requested entry, `aux` the target.
    EntryRefused = 3,
    /// A trap the monitor has no handler for: `addr` is the PC.
    UnexpectedTrap = 4,
}

impl Kind {
    pub const fn from_u32(v: u32) -> Option<Kind> {
        Some(match v {
            1 => Kind::Stage2Fault,
            2 => Kind::CallRefused,
            3 => Kind::EntryRefused,
            4 => Kind::UnexpectedTrap,
            _ => return None,
        })
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Violation {
    pub kind: u32,
    pub pe: u32,
    pub syndrome: u64,
    pub addr: u64,
    pub aux: u64,
}

impl Violation {
    pub const ZERO: Violation = Violation { kind: 0, pe: 0, syndrome: 0, addr: 0, aux: 0 };

    pub const fn word1(&self) -> u64 {
        self.kind as u64 | (self.pe as u64) << 32
    }

    pub const fn from_words(w1: u64, syndrome: u64, addr: u64, aux: u64) -> Violation {
        Violation { kind: w1 as u32, pe: (w1 >> 32) as u32, syndrome, addr, aux }
    }
}

/// The violation ring: `N` records, a sequence number per push. A reader
/// keeps its cursor (the next sequence it wants); a cursor the ring has
/// overwritten reads the oldest record still held, so loss shows as a jump.
pub struct Ring<const N: usize> {
    recs: [Violation; N],
    head: u64,
}

impl<const N: usize> Ring<N> {
    pub const fn new() -> Self {
        Ring { recs: [Violation::ZERO; N], head: 0 }
    }

    pub fn push(&mut self, v: Violation) {
        self.recs[(self.head % N as u64) as usize] = v;
        self.head += 1;
    }

    pub const fn head(&self) -> u64 {
        self.head
    }

    /// The record at `cursor` (or the oldest held) and the cursor after it.
    pub fn read(&self, cursor: u64) -> Option<(u64, Violation)> {
        if cursor >= self.head {
            return None;
        }
        let oldest = self.head.saturating_sub(N as u64);
        let seq = if cursor < oldest { oldest } else { cursor };
        Some((seq + 1, self.recs[(seq % N as u64) as usize]))
    }
}

impl<const N: usize> Default for Ring<N> {
    fn default() -> Self {
        Self::new()
    }
}

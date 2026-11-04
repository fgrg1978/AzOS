// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The ABI between the kernel and the resident monitor (VIRT_SPLIT), the same
//! on every ISA: call ids, status codes, the invariants `probe` reports and
//! the violation record. Arguments are physical addresses or plain values;
//! nothing here dereferences anything.
#![no_std]
#![forbid(unsafe_code)]

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
/// `lock_kernel_image(desc_pa)`: one-shot, with one PE up. Text read-only and
/// executable at EL1 only, rodata read-only, every other RAM page executable
/// at EL0 only, the secondary entry fixed (I1, I2). Needs FEAT_XNX.
pub const CALL_LOCK_KERNEL_IMAGE: u64 = CALL_BASE + 2;
/// `lock_ro_data()`: one-shot, after the image lock: the `ro_after_init`
/// range the lock named becomes read-only.
pub const CALL_LOCK_RO_DATA: u64 = CALL_BASE + 3;

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
/// I1: kernel text and rodata are read-only at stage 2.
pub const INV_IMAGE_RO: u64 = 1 << 3;
/// I2: only kernel text executes at EL1.
pub const INV_EL1_EXEC_TEXT_ONLY: u64 = 1 << 4;
/// `ro_after_init` is read-only at stage 2.
pub const INV_RO_DATA: u64 = 1 << 5;

pub const INVARIANT_NAMES: [(u64, &str); 6] = [
    (INV_EL2_MMU, "el2-mmu"),
    (INV_HOST_S2, "host-s2"),
    (INV_PSCI, "psci"),
    (INV_IMAGE_RO, "image-ro"),
    (INV_EL1_EXEC_TEXT_ONLY, "el1-exec-text-only"),
    (INV_RO_DATA, "ro-data"),
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

/// RAM ranges a lock descriptor carries.
pub const LOCK_RAM_MAX: usize = 8;

/// What `lock_kernel_image` locks, by physical address, page-aligned. The
/// kernel builds it before the lock, while it is still trusted.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct LockDesc {
    pub text: [u64; 2],
    pub rodata: [u64; 2],
    pub ro_after_init: [u64; 2],
    /// `[base, end)` pairs; everything outside them is a device window.
    pub ram: [[u64; 2]; LOCK_RAM_MAX],
    pub nram: u64,
    /// The one EL1 entry a secondary or a resumed PE may enter at.
    pub secondary_entry: u64,
}

/// Why a lock descriptor is refused; `None`: it is well formed against a
/// monitor at `[hole, hole_end)`. Pure, so the host suite checks it.
pub fn lock_desc_error(d: &LockDesc, hole: u64, hole_end: u64) -> Option<&'static str> {
    const P: u64 = 4096;
    let ranges = [d.text, d.rodata, d.ro_after_init];
    if d.nram == 0 || d.nram as usize > LOCK_RAM_MAX { return Some("ram count"); }
    for r in ranges.iter() {
        if r[0] >= r[1] || r[0] % P != 0 || r[1] % P != 0 { return Some("range not page-aligned or empty"); }
        if r[0] < hole_end && hole < r[1] { return Some("range overlaps the monitor"); }
        let inside = d.ram[..d.nram as usize].iter().any(|m| m[0] <= r[0] && r[1] <= m[1]);
        if !inside { return Some("range outside RAM"); }
    }
    for (i, a) in ranges.iter().enumerate() {
        for b in ranges[i + 1..].iter() {
            if a[0] < b[1] && b[0] < a[1] { return Some("ranges overlap"); }
        }
    }
    for m in d.ram[..d.nram as usize].iter() {
        if m[0] >= m[1] || m[0] % P != 0 || m[1] % P != 0 { return Some("ram range not page-aligned or empty"); }
    }
    if d.secondary_entry < d.text[0] || d.secondary_entry >= d.text[1] { return Some("secondary entry outside text"); }
    None
}

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
/// `text_patch(pa, word)`: after the lock, write `word` at `pa` when `pa` is
/// a site the lock listed and `word` is one of its two forms.
pub const CALL_TEXT_PATCH: u64 = CALL_BASE + 4;
/// `guard_pages(pa, n)`: donate `n` pages at `pa` to the monitor. The host
/// stage-2 stops mapping them, for good: no EL1 or EL0 access reaches them
/// and the monitor never gives them back (I4).
pub const CALL_GUARD_PAGES: u64 = CALL_BASE + 5;
/// `pin() -> (status, mode, pes_pinned)`: after the lock, on the calling PE
/// only: its writes to `SCTLR_EL1`, `TCR_EL1` and `TTBR1_EL1` are refused from
/// now on (I3). Each PE calls it once it has made its own last write to them,
/// and again after a power-down. `mode` is [`PIN_FGT`] or [`PIN_TVM`].
pub const CALL_PIN: u64 = CALL_BASE + 6;

/// The pin is armed by `HFGWTR_EL2` (FEAT_FGT): `TTBR0_EL1` is not trapped.
pub const PIN_FGT: u64 = 1;
/// The pin is armed by `HCR_EL2.TVM`: every virtual-memory register write
/// traps, and the ones that are not refused are carried out by the monitor.
pub const PIN_TVM: u64 = 2;

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
/// I4: at least one page is guarded: unmapped at stage 2 for every EL1 and EL0 access.
pub const INV_GUARDED: u64 = 1 << 6;
/// I3: a PE that called `pin` cannot write `SCTLR_EL1`, `TCR_EL1` or `TTBR1_EL1`.
pub const INV_PINNED: u64 = 1 << 7;

pub const INVARIANT_NAMES: [(u64, &str); 8] = [
    (INV_EL2_MMU, "el2-mmu"),
    (INV_HOST_S2, "host-s2"),
    (INV_PSCI, "psci"),
    (INV_IMAGE_RO, "image-ro"),
    (INV_EL1_EXEC_TEXT_ONLY, "el1-exec-text-only"),
    (INV_RO_DATA, "ro-data"),
    (INV_GUARDED, "guarded"),
    (INV_PINNED, "pinned"),
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
    /// A write to a pinned register: `addr` is the register's encoding as
    /// `sys_reg(op0, op1, crn, crm, op2)` packs it, `aux` the value refused.
    SysregRefused = 5,
}

impl Kind {
    pub const fn from_u32(v: u32) -> Option<Kind> {
        Some(match v {
            1 => Kind::Stage2Fault,
            2 => Kind::CallRefused,
            3 => Kind::EntryRefused,
            4 => Kind::UnexpectedTrap,
            5 => Kind::SysregRefused,
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
/// Text sites a lock descriptor may list for `text_patch`.
pub const TEXT_SITES_MAX: usize = 1024;

/// One instruction the kernel may rewrite after the lock, and its two forms.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct TextSite {
    pub pa: u64,
    pub off: u32,
    pub on: u32,
}

impl TextSite {
    pub const ZERO: TextSite = TextSite { pa: 0, off: 0, on: 0 };
}

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
    /// The `TextSite` array (`nsites` entries) `text_patch` may write.
    pub sites: u64,
    pub nsites: u64,
}

/// Ranges guarded before the lock that the locked map must keep unmapped.
pub const GUARD_RANGES_MAX: usize = 16;
/// Pages one `guard_pages` call may donate.
pub const GUARD_PAGES_MAX: u64 = 512;

/// Why a lock descriptor is refused; `None`: it is well formed against a
/// monitor at `[hole, hole_end)` and the `guarded` ranges. Pure, so the host
/// suite checks it.
pub fn lock_desc_error(d: &LockDesc, hole: u64, hole_end: u64, guarded: &[[u64; 2]]) -> Option<&'static str> {
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
    for g in guarded {
        if !d.ram[..d.nram as usize].iter().any(|m| m[0] <= g[0] && g[1] <= m[1]) { return Some("guarded range outside RAM"); }
        if ranges.iter().any(|r| g[0] < r[1] && r[0] < g[1]) { return Some("guarded range overlaps the image"); }
    }
    if d.secondary_entry < d.text[0] || d.secondary_entry >= d.text[1] { return Some("secondary entry outside text"); }
    if d.nsites as usize > TEXT_SITES_MAX { return Some("too many text sites"); }
    None
}

/// Why a text site is refused against a locked text range; `None`: it is a
/// 4-aligned word inside text.
pub fn text_site_error(s: &TextSite, text: [u64; 2]) -> Option<&'static str> {
    if s.pa % 4 != 0 { return Some("site not 4-aligned"); }
    if s.pa < text[0] || s.pa + 4 > text[1] { return Some("site outside text"); }
    None
}

/// The pages donated so far, as `[lo, hi)` ranges. The monitor keeps one and
/// the locked map is built around it.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Guarded {
    ranges: [[u64; 2]; GUARD_RANGES_MAX],
    n: usize,
}

impl Guarded {
    pub const fn new() -> Self {
        Guarded { ranges: [[0; 2]; GUARD_RANGES_MAX], n: 0 }
    }

    pub fn as_slice(&self) -> &[[u64; 2]] {
        &self.ranges[..self.n]
    }

    /// Does `[lo, hi)` touch a guarded page?
    pub fn overlaps(&self, lo: u64, hi: u64) -> bool {
        self.as_slice().iter().any(|g| lo < g[1] && g[0] < hi)
    }

    /// Record `[lo, hi)`; false when the table is full.
    pub fn add(&mut self, lo: u64, hi: u64) -> bool {
        if self.n == GUARD_RANGES_MAX {
            return false;
        }
        self.ranges[self.n] = [lo, hi];
        self.n += 1;
        true
    }

    /// Take back the last range added (the call that added it failed).
    pub fn pop(&mut self) {
        self.n = self.n.saturating_sub(1);
    }
}

impl Default for Guarded {
    fn default() -> Self {
        Self::new()
    }
}

/// Why `guard_pages(pa, n)` is refused; `None`: `n` whole pages at `pa` lie in
/// RAM, clear of the locked `image` ranges, the monitor `[hole, hole_end)` and
/// everything guarded. `ram` and `image` are empty before the lock, when the
/// kernel has not named them yet. Pure, so the host suite checks it.
pub fn guard_error(
    pa: u64,
    n: u64,
    ram: &[[u64; 2]],
    image: &[[u64; 2]],
    hole: u64,
    hole_end: u64,
    guarded: &Guarded,
) -> Option<&'static str> {
    const P: u64 = 4096;
    if n == 0 || n > GUARD_PAGES_MAX { return Some("page count"); }
    if pa % P != 0 { return Some("not page-aligned"); }
    let Some(end) = pa.checked_add(n * P) else { return Some("wraps") };
    if pa < hole_end && hole < end { return Some("overlaps the monitor"); }
    if image.iter().any(|r| pa < r[1] && r[0] < end) { return Some("overlaps the image"); }
    if guarded.overlaps(pa, end) { return Some("already guarded"); }
    if !ram.is_empty() && !ram.iter().any(|m| m[0] <= pa && end <= m[1]) { return Some("outside RAM"); }
    None
}

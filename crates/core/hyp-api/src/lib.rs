// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The ABI between the kernel and the resident monitor (VIRT_SPLIT), the same
//! on every ISA: call ids, status codes, the invariants `probe` reports and
//! the violation record. Arguments are physical addresses or plain values;
//! nothing here dereferences anything.
#![no_std]
#![forbid(unsafe_code)]

use core::sync::atomic::{AtomicU64, Ordering};

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

/// `key_root_set(slot, pa) -> status`: root `slot` is the 32 bytes at `pa`,
/// inside a page the caller already donated with `guard_pages`. One-shot per
/// slot. The monitor reads the root from there when it derives, and nobody
/// else can.
pub const CALL_KEY_ROOT_SET: u64 = CALL_BASE + 7;
/// `key_derive(slot, req_pa) -> (status, out[0..4])`: `HKDF-SHA256(salt, ikm =
/// the root of slot, info)` for the [`DeriveReq`] at `req_pa`, 32 bytes back in
/// four little-endian words. The request lies in memory the kernel still owns.
pub const CALL_KEY_DERIVE: u64 = CALL_BASE + 8;

/// `smmu_init(base, size | max_sid << 32) -> (status, oas)`: before the lock,
/// once. The monitor brings up the SMMUv3 at `base` with a stream table for
/// streams `0..=max_sid`, its own queues, every stream aborting; from the lock
/// the register window is unmapped from the host, so the kernel never touches
/// the unit again (I1 for DMA).
pub const CALL_SMMU_INIT: u64 = CALL_BASE + 9;
/// `smmu_attach(sid | mode << 32, cd_pa)`: put stream `sid` in `mode`. Stage 2
/// is always the host's (shared with the CPUs), so no stream reaches memory the
/// host stage-2 does not map. `cd_pa` is the kernel's stage-1 Context
/// Descriptor for [`SMMU_NESTED`], 0 otherwise.
pub const CALL_SMMU_ATTACH: u64 = CALL_BASE + 10;
/// `smmu_flush(sid)`: drop what the unit cached about the kernel's stage 1.
pub const CALL_SMMU_FLUSH: u64 = CALL_BASE + 11;
/// `smmu_event() -> (status, dword0, dword2)`: the oldest fault record (type
/// and stream id in dword 0, the input address in dword 2), or [`EMPTY`].
pub const CALL_SMMU_EVENT: u64 = CALL_BASE + 12;

/// `its_init(its_base, rd_base, rd_stride | ncpu << 32)`: before the lock, once.
/// The monitor brings up the GICv3 ITS at `its_base` and enables LPIs on the
/// redistributor at `rd_base`, with its own command queue, device and
/// collection tables, ITTs and LPI tables. From the lock the ITS control frame
/// is unmapped from the host and the first 64 KiB of each of the `ncpu`
/// redistributors (`rd_stride` apart) is read-only: a write there is carried
/// out by the monitor unless it aims `GICR_PROPBASER` or `GICR_PENDBASER`.
pub const CALL_ITS_INIT: u64 = CALL_BASE + 13;
/// `its_map_device(dev) -> (status, slot)`: MAPD of device id `dev` onto a
/// fresh ITT of the monitor's.
pub const CALL_ITS_MAP_DEVICE: u64 = CALL_BASE + 14;
/// `its_map_vector(slot | event << 32, lpi)`: enable `lpi` in the LPI
/// configuration table, MAPTI the event of the slot's device to it, INV.
pub const CALL_ITS_MAP_VECTOR: u64 = CALL_BASE + 15;

/// `pt_lock_pool(pool_pa, pages | page_shift << 32, root_pa)`: one-shot, after
/// the image lock. The `pages` page-table pages (`1 << page_shift` bytes each,
/// at most [`PT_POOL_PAGES_MAX`]) at `pool_pa` become read-only for the host
/// (I3), and `root_pa`, one of them, is the root of the kernel half. The tables
/// already built are walked from the root and every word checked as `pt_set`
/// checks it; one that fails refuses the lock.
pub const CALL_PT_LOCK_POOL: u64 = CALL_BASE + 16;
/// `pt_set(entry_pa, expected, new, level) -> (status, observed)`: after the
/// pool lock, replace the word at `entry_pa` (an entry of a pool table, `level`
/// 0 being the last) by `new` when it still holds `expected`. [`RACED`] with the
/// word found when it does not; [`DENIED`] when the word breaks a rule.
pub const CALL_PT_SET: u64 = CALL_BASE + 17;

/// Pool pages the monitor keeps a level for (a bound, not a detected count).
pub const PT_POOL_PAGES_MAX: u64 = 1024;

/// Devices the monitor's ITS holds ITTs for, and events each (a bound, not a
/// detected count; the kernel driver's own).
pub const ITS_DEVICES_MAX: u64 = 4;
pub const ITS_EVENTS_MAX: u64 = 8;

/// Every access of the stream is refused.
pub const SMMU_BLOCK: u64 = 0;
/// Stage 1 bypassed: the stream's addresses are host physical addresses, under
/// the host stage-2.
pub const SMMU_S2_ONLY: u64 = 1;
/// The kernel's stage 1 (a Context Descriptor) under the host stage-2.
pub const SMMU_NESTED: u64 = 2;
/// Streams the monitor's stream table holds (a bound, not a detected count).
pub const SMMU_STREAMS_MAX: u64 = 256;
/// Register window the unit needs (two 64 KiB pages) and the most the monitor
/// maps; the unit lies below 1 GiB, where the monitor's own map is Device.
pub const SMMU_WINDOW_MIN: u64 = 0x2_0000;
pub const SMMU_WINDOW_MAX: u64 = 0x10_0000;
pub const SMMU_DEVICE_TOP: u64 = 1 << 30;

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
/// `pt_set`: the word was not the one expected; the one found comes back.
pub const RACED: i64 = -5;

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
/// At least one keystore root is held in guarded memory and derives there.
pub const INV_KEY_ROOTS: u64 = 1 << 8;
/// The SMMU is the monitor's: its registers are unmapped from the host and every
/// stream it serves goes through the host stage-2. Masters not behind it stay
/// unconfined.
pub const INV_SMMU: u64 = 1 << 9;
/// The ITS is the monitor's: its control frame is unmapped from the host and the
/// redistributors' LPI table pointers cannot be written by it.
pub const INV_ITS: u64 = 1 << 10;

/// I3: the kernel half's tables are the monitor's pool, read-only for the host,
/// and every word written there passed `pt_set`'s checks.
pub const INV_KERNEL_TABLES: u64 = 1 << 11;

pub const INVARIANT_NAMES: [(u64, &str); 12] = [
    (INV_EL2_MMU, "el2-mmu"),
    (INV_HOST_S2, "host-s2"),
    (INV_PSCI, "psci"),
    (INV_IMAGE_RO, "image-ro"),
    (INV_EL1_EXEC_TEXT_ONLY, "el1-exec-text-only"),
    (INV_RO_DATA, "ro-data"),
    (INV_GUARDED, "guarded"),
    (INV_PINNED, "pinned"),
    (INV_KEY_ROOTS, "key-roots"),
    (INV_SMMU, "smmu"),
    (INV_ITS, "its"),
    (INV_KERNEL_TABLES, "kernel-tables"),
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
    /// A fault record of the SMMU: `addr` is the input address, `aux` the
    /// stream id in the high word and the event type in the low.
    DmaFault = 6,
    /// A write the host made to a protected device register, refused: `addr`
    /// is the register's address, `aux` the value.
    MmioRefused = 7,
}

impl Kind {
    pub const fn from_u32(v: u32) -> Option<Kind> {
        Some(match v {
            1 => Kind::Stage2Fault,
            2 => Kind::CallRefused,
            3 => Kind::EntryRefused,
            4 => Kind::UnexpectedTrap,
            5 => Kind::SysregRefused,
            6 => Kind::DmaFault,
            7 => Kind::MmioRefused,
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
    /// The kernel VA each of `text`, `rodata` and `ro_after_init` starts at,
    /// which the pool lock walks to prove the image lives where it is locked.
    pub va: [u64; 3],
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
/// RAM, clear of the locked `image` ranges, the monitor `[hole, hole_end)`,
/// the kernel-half table pool `pool` (empty, 0..0, until it is locked) and
/// everything guarded. `ram` and `image` are empty before the lock, when the
/// kernel has not named them yet. Pure, so the host suite checks it.
pub fn guard_error(
    pa: u64,
    n: u64,
    ram: &[[u64; 2]],
    image: &[[u64; 2]],
    hole: u64,
    hole_end: u64,
    pool: [u64; 2],
    guarded: &Guarded,
) -> Option<&'static str> {
    const P: u64 = 4096;
    if n == 0 || n > GUARD_PAGES_MAX { return Some("page count"); }
    if pa % P != 0 { return Some("not page-aligned"); }
    let Some(end) = pa.checked_add(n * P) else { return Some("wraps") };
    if pa < hole_end && hole < end { return Some("overlaps the monitor"); }
    if image.iter().any(|r| pa < r[1] && r[0] < end) { return Some("overlaps the image"); }
    if !cfg!(feature = "canary-guard-pool") && pa < pool[1] && pool[0] < end { return Some("overlaps the kernel tables"); }
    if guarded.overlaps(pa, end) { return Some("already guarded"); }
    if !ram.is_empty() && !ram.iter().any(|m| m[0] <= pa && end <= m[1]) { return Some("outside RAM"); }
    None
}

/// What a confidential split image needs in force once the boot has locked
/// everything: the image, the read-only data, the kernel tables and the pin.
pub const INV_BOOT_LOCKED: u64 = INV_IMAGE_RO | INV_EL1_EXEC_TEXT_ONLY | INV_RO_DATA | INV_KERNEL_TABLES | INV_PINNED;

/// The bits of [`INV_BOOT_LOCKED`] a `probe` mask does not report.
pub fn missing_invariants(reported: u64) -> u64 {
    if cfg!(feature = "canary-missing-inv") { return 0; }
    INV_BOOT_LOCKED & !reported
}

/// A one-shot call's latch, taken only once `validate` has passed: a call
/// refused for what it carried (`Some(error)`) leaves the latch free for a
/// corrected retry, and a second call after the latch is `DENIED`. `validate`
/// runs under the caller's lock and must not change what a retry would see.
pub fn latch_after(flag: &AtomicU64, validate: impl FnOnce() -> Option<i64>) -> Option<i64> {
    if cfg!(feature = "canary-latch-first") {
        if flag.swap(1, Ordering::AcqRel) != 0 { return Some(DENIED); }
        return validate();
    }
    if flag.load(Ordering::Acquire) != 0 { return Some(DENIED); }
    if let Some(e) = validate() { return Some(e); }
    if flag.swap(1, Ordering::AcqRel) != 0 { return Some(DENIED); }
    None
}

/// Keystore roots the monitor can hold (`azos_crypto::keystore::ROOTS`; the
/// kernel asserts they agree) and the length of one root and of one output.
pub const KEY_ROOTS: usize = 3;
pub const KEY_LEN: usize = 32;
/// Longest salt and info a derive request may carry. The keystore's are 26 and
/// 54 bytes at most.
pub const DERIVE_SALT_MAX: usize = 64;
pub const DERIVE_INFO_MAX: usize = 96;

/// What `key_derive` is asked, in the kernel's memory at an 8-aligned address.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(C, align(8))]
pub struct DeriveReq {
    pub salt_len: u32,
    pub info_len: u32,
    pub salt: [u8; DERIVE_SALT_MAX],
    pub info: [u8; DERIVE_INFO_MAX],
}

impl DeriveReq {
    pub const ZERO: DeriveReq = DeriveReq { salt_len: 0, info_len: 0, salt: [0; DERIVE_SALT_MAX], info: [0; DERIVE_INFO_MAX] };

    /// A request for `salt` and `info`; `None` when either is too long.
    pub fn new(salt: &[u8], info: &[u8]) -> Option<DeriveReq> {
        if salt.len() > DERIVE_SALT_MAX || info.len() > DERIVE_INFO_MAX {
            return None;
        }
        let mut r = DeriveReq::ZERO;
        r.salt_len = salt.len() as u32;
        r.info_len = info.len() as u32;
        r.salt[..salt.len()].copy_from_slice(salt);
        r.info[..info.len()].copy_from_slice(info);
        Some(r)
    }

    pub fn salt(&self) -> &[u8] {
        &self.salt[..self.salt_len as usize]
    }

    pub fn info(&self) -> &[u8] {
        &self.info[..self.info_len as usize]
    }
}

/// Why a request the monitor read is refused; the lengths are the kernel's.
pub fn derive_req_error(r: &DeriveReq) -> Option<&'static str> {
    if r.salt_len as usize > DERIVE_SALT_MAX { return Some("salt too long"); }
    if r.info_len as usize > DERIVE_INFO_MAX { return Some("info too long"); }
    None
}

/// Why the memory a request is read from is refused: it must be 8-aligned, not
/// wrap, lie in RAM (`ram` is empty before the lock) and touch neither the
/// monitor nor a guarded page (the monitor would read the kernel's secrets
/// back to it as key material, or a device frame the lock took from the host).
pub fn derive_req_addr_error(pa: u64, ram: &[[u64; 2]], hole: u64, hole_end: u64, guarded: &Guarded) -> Option<&'static str> {
    if pa % 8 != 0 { return Some("request not 8-aligned"); }
    let Some(end) = pa.checked_add(core::mem::size_of::<DeriveReq>() as u64) else { return Some("wraps") };
    if pa < hole_end && hole < end { return Some("request over the monitor"); }
    if guarded.overlaps(pa, end) { return Some("request over a guarded page"); }
    if !cfg!(feature = "canary-derive-no-ram") && !ram.is_empty() && !ram.iter().any(|m| m[0] <= pa && end <= m[1]) {
        return Some("request outside RAM");
    }
    None
}

/// Why `key_root_set(slot, pa)` is refused: a slot there is, and 32 bytes
/// wholly inside one guarded range.
pub fn key_root_error(slot: u64, pa: u64, guarded: &Guarded) -> Option<&'static str> {
    if slot >= KEY_ROOTS as u64 { return Some("no such root"); }
    let Some(end) = pa.checked_add(KEY_LEN as u64) else { return Some("wraps") };
    if !guarded.as_slice().iter().any(|g| g[0] <= pa && end <= g[1]) { return Some("root not in guarded memory"); }
    None
}

/// An output as the four register words `key_derive` returns, and back.
pub fn out_to_words(out: &[u8; KEY_LEN]) -> [u64; 4] {
    core::array::from_fn(|i| u64::from_le_bytes(out[i * 8..i * 8 + 8].try_into().unwrap()))
}

pub fn words_to_out(w: [u64; 4]) -> [u8; KEY_LEN] {
    let mut out = [0u8; KEY_LEN];
    for (i, x) in w.iter().enumerate() {
        out[i * 8..i * 8 + 8].copy_from_slice(&x.to_le_bytes());
    }
    out
}

/// Why `smmu_init(base, size, max_sid)` is refused: a window of whole pages,
/// big enough for the unit and no bigger than the monitor maps, inside the
/// Device gigabyte of the monitor's map, clear of the monitor itself; and
/// streams the stream table holds.
pub fn smmu_init_error(base: u64, size: u64, max_sid: u64, hole: u64, hole_end: u64) -> Option<&'static str> {
    if base % 4096 != 0 || size % 4096 != 0 { return Some("window not page-aligned"); }
    if !(SMMU_WINDOW_MIN..=SMMU_WINDOW_MAX).contains(&size) { return Some("window size"); }
    let Some(end) = base.checked_add(size) else { return Some("wraps") };
    if end > SMMU_DEVICE_TOP { return Some("window not in the monitor's Device map"); }
    if base < hole_end && hole < end { return Some("window over the monitor"); }
    if max_sid >= SMMU_STREAMS_MAX { return Some("too many streams"); }
    None
}

/// Why `smmu_attach(sid | mode << 32, cd_pa)` is refused: a stream the table
/// holds, a mode there is, and for a nested stream a 64-byte-aligned
/// Context Descriptor in ordinary memory (not the monitor's, not guarded, in RAM
/// once the kernel has named it); for the others no descriptor.
pub fn smmu_attach_error(
    nstreams: u64,
    sid: u64,
    mode: u64,
    cd_pa: u64,
    ram: &[[u64; 2]],
    hole: u64,
    hole_end: u64,
    guarded: &Guarded,
) -> Option<&'static str> {
    if sid >= nstreams { return Some("no such stream"); }
    match mode {
        SMMU_BLOCK | SMMU_S2_ONLY => return if cd_pa != 0 { Some("descriptor for a stream with no stage 1") } else { None },
        SMMU_NESTED => {}
        _ => return Some("no such mode"),
    }
    if cd_pa % 64 != 0 { return Some("descriptor not 64-aligned"); }
    let Some(end) = cd_pa.checked_add(64) else { return Some("wraps") };
    if cd_pa < hole_end && hole < end { return Some("descriptor over the monitor"); }
    if guarded.overlaps(cd_pa, end) { return Some("descriptor over a guarded page"); }
    if !ram.is_empty() && !ram.iter().any(|m| m[0] <= cd_pa && end <= m[1]) { return Some("descriptor outside RAM"); }
    None
}

/// Why `its_init(its_base, rd_base, rd_stride | ncpu << 32)` is refused: 64 KiB
/// frames on 64 KiB boundaries, redistributors a whole number of frames apart
/// (an RD frame and its SGI frame at least), a handful of them, all below
/// the monitor's Device gigabyte and clear of the monitor.
pub fn its_init_error(its_base: u64, rd_base: u64, rd_stride: u64, ncpu: u64, hole: u64, hole_end: u64) -> Option<&'static str> {
    const FRAME: u64 = 0x1_0000;
    if its_base % FRAME != 0 || rd_base % FRAME != 0 { return Some("frame not 64 KiB-aligned"); }
    if rd_stride < 2 * FRAME || rd_stride % FRAME != 0 { return Some("redistributor stride"); }
    if ncpu == 0 || ncpu > 64 { return Some("redistributor count"); }
    let Some(rd_end) = ncpu.checked_mul(rd_stride).and_then(|n| rd_base.checked_add(n)) else { return Some("wraps") };
    let Some(its_end) = its_base.checked_add(2 * FRAME) else { return Some("wraps") };
    if rd_end > SMMU_DEVICE_TOP || its_end > SMMU_DEVICE_TOP { return Some("not in the monitor's Device map"); }
    for (lo, hi) in [(its_base, its_end), (rd_base, rd_end)] {
        if lo < hole_end && hole < hi { return Some("window over the monitor"); }
    }
    if its_base < rd_end && rd_base < its_end { return Some("the ITS and the redistributors overlap"); }
    None
}

/// Why `its_map_vector(slot | event << 32, lpi)` is refused: a device the
/// monitor mapped, an event its ITT holds, and an LPI the configuration table
/// covers (`lpi_lo..lpi_hi`).
pub fn its_vector_error(ndev: u64, slot: u64, event: u64, lpi: u64, lpi_lo: u64, lpi_hi: u64) -> Option<&'static str> {
    if slot >= ndev { return Some("no such device slot"); }
    if event >= ITS_EVENTS_MAX { return Some("event past the ITT"); }
    if lpi < lpi_lo || lpi >= lpi_hi { return Some("LPI outside the configuration table"); }
    None
}

/// The store a stage-2 data abort describes, from `ESR_EL2`: the width in bytes
/// and the source register (31 is the zero register). `None` unless the
/// syndrome is valid (ISV), a write, and a permission fault: the only aborts
/// the monitor emulates.
pub const fn mmio_store(esr: u64) -> Option<(u8, u8)> {
    const ISV: u64 = 1 << 24;
    const WNR: u64 = 1 << 6;
    if esr & ISV == 0 || esr & WNR == 0 || esr & 0x3c != 0x0c { return None; }
    Some((1 << ((esr >> 22) & 3), ((esr >> 16) & 0x1f) as u8))
}

/// A write of `value` the host aims at `offset` of redistributor `rd`'s first
/// frame. `GICR_PROPBASER` and `GICR_PENDBASER` (0x70..0x7f) are never the
/// host's to write. Only redistributor 0 has the tables the monitor
/// programmed, so on any other the host may not turn LPIs on (`GICR_CTLR`
/// bit 0) or use the DirectLPI registers (`SETLPIR` and `CLRLPIR` at 0x40..0x4f, `INVLPIR` and
/// `INVALLR` at 0xa0..0xbf): the redistributor would read or write a pending
/// table the monitor never checked.
pub const fn rd_write_refused(rd: u64, offset: u64, value: u64) -> bool {
    let off = offset & 0xffff;
    if matches!(off, 0x70..=0x7f) { return true; }
    if cfg!(feature = "canary-rd-lpi-open") || rd == 0 { return false; }
    (off == 0 && value & 1 != 0) || matches!(off, 0x40..=0x4f | 0xa0..=0xbf)
}

/// Why `pt_lock_pool(pool_pa, pages | page_shift << 32, root_pa)` is refused;
/// `None`: `pages` whole pages of a granule the walk supports lie in RAM, clear
/// of the locked `image` ranges, the monitor and everything guarded, and the
/// root is the first byte of one of them. Pure, so the host suite checks it.
pub fn pt_pool_error(
    pool_pa: u64,
    pages: u64,
    page_shift: u64,
    root_pa: u64,
    ram: &[[u64; 2]],
    image: &[[u64; 2]],
    hole: u64,
    hole_end: u64,
    guarded: &Guarded,
) -> Option<&'static str> {
    if !matches!(page_shift, 12 | 14 | 16) { return Some("granule"); }
    if pages == 0 || pages > PT_POOL_PAGES_MAX { return Some("page count"); }
    let page = 1u64 << page_shift;
    if pool_pa % page != 0 { return Some("not page-aligned"); }
    let Some(end) = pool_pa.checked_add(pages * page) else { return Some("wraps") };
    if pool_pa < hole_end && hole < end { return Some("overlaps the monitor"); }
    if image.iter().any(|r| pool_pa < r[1] && r[0] < end) { return Some("overlaps the image"); }
    if guarded.overlaps(pool_pa, end) { return Some("overlaps a guarded page"); }
    if !ram.iter().any(|m| m[0] <= pool_pa && end <= m[1]) { return Some("outside RAM"); }
    if root_pa < pool_pa || root_pa >= end || root_pa % page != 0 { return Some("root outside the pool"); }
    None
}

/// Why `pt_set(entry_pa, ..)` is refused for the entry alone; `None`: an
/// 8-aligned word inside the pool's `pages` pages, at a level the walk has.
pub fn pt_entry_error(entry_pa: u64, level: u64, pool_pa: u64, pages: u64, page_shift: u64, levels: u64) -> Option<&'static str> {
    if level >= levels { return Some("level"); }
    if entry_pa % 8 != 0 { return Some("entry not 8-aligned"); }
    if entry_pa < pool_pa || entry_pa >= pool_pa + (pages << page_shift) { return Some("entry outside the pool"); }
    None
}

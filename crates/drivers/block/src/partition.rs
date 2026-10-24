// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Partition table parser (MBR and GPT) and the table the kernel publishes
//! from it.
//!
//! A capability names ONE partition: the `block` endpoint's badge `n + 1` is
//! partition `n` of the table parsed here at boot, and its holder names
//! sectors relative to that partition ([`resolve`] adds the start); the block
//! entry refuses, and records, any run past its end. No capability names the
//! whole medium.
//!
//! # What is parsed, and what is refused
//!
//! The medium is attacker-writable (a removable SD card), so every field
//! is checked before it is used, all arithmetic is checked, and a table that
//! is present but wrong publishes NOTHING rather than the parts that looked
//! right: a capability to "partition 1" must not change meaning because a
//! neighbour was malformed.
//!
//! * No `0x55AA` at LBA 0, or LBA 0 is a FAT boot sector (the "superfloppy"
//!   layout `mkfs.fat` writes on a bare device, which is what every QEMU
//!   image in the tree is) → [`Scheme::None`], zero partitions.
//! * A classic MBR: four entries, status `0x00`/`0x80`, non-empty entries
//!   inside the medium, starting past LBA 0, not overlapping. A status byte
//!   outside those two means the sector is boot code, not a table →
//!   [`Scheme::None`]. Extended partitions (`0x05`/`0x0F`/`0x85`) are kept as
//!   the container they are and not walked.
//! * A protective MBR (`0xEE`) → GPT at LBA 1: signature, header size, header
//!   CRC32, `my_lba == 1`, usable range inside the medium, entry size 128..=
//!   512 and a multiple of 8, at most [`GPT_MAX_ENTRIES`] entries, entry
//!   array CRC32, every used entry inside the usable range, no overlaps.
//! * More than [`MAX_PARTS`] used entries → refused, not truncated.
//!
//! # The swap partition
//!
//! An MBR entry of type `0x82` or a GPT entry of the Linux swap type GUID is
//! the swap area (Kconfig `MM_SWAP_BACKEND`); a GPT entry carries it as
//! `mbr_type == 0x82` too, so one test names both ([`Partition::is_swap`]).
//! The kernel [`claim_swap`]s the first one at boot, and from then on the
//! partition is the kernel's: [`partition`] (and so [`contains`], [`resolve`],
//! the capability minter and the filesystem scan) no longer names it, while
//! [`extent`] still does, for the accounting of what lies where on the medium.
//! Its index stays reserved, so the other partitions keep their numbers.
//!
//! # The AzOS records partition
//!
//! On a GPT medium the kernel's own records (the brain-link key, the entropy
//! seed, the device record, the topology counter floor: `kernel/src/
//! reserved_tail.rs`) live in a small partition of type
//! [`GPT_RECORDS_GUID`], 653ED7AA-51CA-43D8-9AF7-54775962C612 (generated once,
//! at random, for AzOS; `tools/image/azos_records.py` carries the same bytes). A
//! GPT laid out to its end keeps its backup table where an MBR medium keeps
//! the reserved tail, so the tail cannot be used there (audit K2-M1). The
//! partition is the kernel's from the moment the table is published:
//! [`partition`] never names it, so no capability is minted for it and no
//! filesystem scan mounts it; [`extent`] and [`records`] still do. A table
//! naming two of them is refused whole ([`PartError::TwoRecords`]): which one
//! holds the key must not depend on entry order.
//!
//! The records are written only after [`verify_backup`] finds the backup
//! header and array equal to the primary ones. That check is the records'
//! alone: a GPT whose backup is stale (a resized disk) still publishes its
//! partitions, as before.
//!
//! This file has no dependency on the rest of the crate (it names only
//! `core`), so the host test crates pull it with `#[path]`.

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

pub const SECTOR: usize = 512;

/// Most partitions the kernel publishes (and so the most a topology can name).
pub const MAX_PARTS: usize = 16;

/// Most GPT entries read. The UEFI minimum array is 128 entries of 128 B.
pub const GPT_MAX_ENTRIES: u32 = 128;

/// The MBR type byte of a Linux swap partition.
pub const MBR_SWAP: u8 = 0x82;

/// The GPT type GUID of a Linux swap partition,
/// 0657FD6D-A4AB-43C4-84E5-0933C86F1BC8, as it lies in an entry (the first
/// three fields little-endian).
pub const GPT_SWAP_GUID: [u8; 16] =
    [0x6D, 0xFD, 0x57, 0x06, 0xAB, 0xA4, 0xC4, 0x43, 0x84, 0xE5, 0x09, 0x33, 0xC8, 0x6F, 0x1B, 0xC8];

/// The GPT type GUID of the AzOS records partition,
/// 653ED7AA-51CA-43D8-9AF7-54775962C612, as it lies in an entry (the first
/// three fields little-endian).
pub const GPT_RECORDS_GUID: [u8; 16] =
    [0xAA, 0xD7, 0x3E, 0x65, 0xCA, 0x51, 0xD8, 0x43, 0x9A, 0xF7, 0x54, 0x77, 0x59, 0x62, 0xC6, 0x12];

/// The `mbr_type` a GPT entry of type [`GPT_RECORDS_GUID`] carries. `0xEE` is
/// the protective-MBR type: an MBR holding such an entry is parsed as GPT, so
/// no MBR-scheme partition can carry it.
pub const MBR_RECORDS: u8 = 0xEE;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Scheme {
    /// No partition table: a bare filesystem or an empty medium.
    None,
    Mbr,
    Gpt,
}

/// One partition: `sectors` 512-byte sectors starting at LBA `start`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Partition {
    pub start: u64,
    pub sectors: u64,
    /// The MBR type byte; for a GPT entry 0, [`MBR_SWAP`] when its type
    /// GUID is the swap one, or [`MBR_RECORDS`] for the records one.
    pub mbr_type: u8,
}

impl Partition {
    /// Is this a swap partition (either scheme)?
    pub const fn is_swap(&self) -> bool {
        self.mbr_type == MBR_SWAP
    }
    /// Is this the AzOS records partition (GPT only)?
    pub const fn is_records(&self) -> bool {
        self.mbr_type == MBR_RECORDS
    }
}

const NO_PART: Partition = Partition { start: 0, sectors: 0, mbr_type: 0 };

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Table {
    pub scheme: Scheme,
    pub parts: [Partition; MAX_PARTS],
    pub count: usize,
}

impl Table {
    const fn empty(scheme: Scheme) -> Self {
        Table { scheme, parts: [NO_PART; MAX_PARTS], count: 0 }
    }
    pub fn get(&self, i: usize) -> Option<Partition> {
        if i < self.count { Some(self.parts[i]) } else { None }
    }
    /// The index of the first swap partition.
    pub fn swap_index(&self) -> Option<usize> {
        self.parts[..self.count].iter().position(Partition::is_swap)
    }
    /// The index of the records partition.
    pub fn records_index(&self) -> Option<usize> {
        self.parts[..self.count].iter().position(Partition::is_records)
    }
    fn push(&mut self, p: Partition) -> Result<(), PartError> {
        if self.count >= MAX_PARTS {
            return Err(PartError::TooMany);
        }
        self.parts[self.count] = p;
        self.count += 1;
        Ok(())
    }
}

/// Why a present table was refused.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PartError {
    /// The device read failed.
    Io,
    /// An entry reaches past the medium, starts at LBA 0, or is empty.
    OutOfRange,
    /// Two entries share a sector.
    Overlap,
    /// More than `MAX_PARTS` used entries.
    TooMany,
    /// A protective MBR whose GPT header is missing or malformed.
    BadGptHeader,
    /// The GPT header CRC32 does not match.
    BadHeaderCrc,
    /// The GPT entry array CRC32 does not match.
    BadEntriesCrc,
    /// Two entries of the records type ([`GPT_RECORDS_GUID`]).
    TwoRecords,
    /// The backup GPT header is not on the last sector, or it or its entry
    /// array does not match the primary ones ([`verify_backup`]).
    BadBackup,
}

fn le16(b: &[u8], o: usize) -> u16 { u16::from_le_bytes([b[o], b[o + 1]]) }
fn le32(b: &[u8], o: usize) -> u32 { u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]]) }
fn le64(b: &[u8], o: usize) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[o..o + 8]);
    u64::from_le_bytes(a)
}

/// CRC-32 (IEEE 802.3, reflected, as UEFI uses), bitwise: it runs once at
/// boot over at most 32 KiB, so a 1 KiB table is not worth its bytes.
pub fn crc32_update(mut crc: u32, data: &[u8]) -> u32 {
    crc = !crc;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 { (crc >> 1) ^ 0xEDB8_8320 } else { crc >> 1 };
        }
    }
    !crc
}

/// Is LBA 0 a FAT (12/16/32) boot sector rather than a partition table?
///
/// The same tests a FAT driver makes before trusting a BPB: a jump
/// instruction, 512..4096 bytes per sector as a power of two, a non-zero
/// power-of-two cluster size, and the "FAT" file-system type string at the
/// FAT12/16 (54) or FAT32 (82) offset. A real MBR's boot code does not carry
/// all four.
fn is_fat_boot_sector(s: &[u8; SECTOR]) -> bool {
    let jump = s[0] == 0xE9 || (s[0] == 0xEB && s[2] == 0x90);
    let bps = le16(s, 11);
    let spc = s[13];
    let bps_ok = (512..=4096).contains(&bps) && bps.is_power_of_two();
    let spc_ok = spc != 0 && spc.is_power_of_two();
    let fat_str = &s[54..57] == b"FAT" || &s[82..85] == b"FAT";
    jump && bps_ok && spc_ok && fat_str
}

/// Check `p` against the medium and the partitions already accepted.
fn accept(t: &mut Table, p: Partition, lo: u64, hi_excl: u64) -> Result<(), PartError> {
    let end = p.start.checked_add(p.sectors).ok_or(PartError::OutOfRange)?;
    if p.sectors == 0 || p.start < lo || end > hi_excl {
        return Err(PartError::OutOfRange);
    }
    for q in &t.parts[..t.count] {
        // Both ends already proven not to overflow.
        if p.start < q.start + q.sectors && q.start < end {
            return Err(PartError::Overlap);
        }
    }
    t.push(p)
}

/// Parse the table of a medium of `capacity` sectors, reading sectors
/// through `read`.
pub fn parse<F>(capacity: u64, read: &mut F) -> Result<Table, PartError>
where
    F: FnMut(u64, &mut [u8; SECTOR]) -> Result<(), ()>,
{
    let mut s0 = [0u8; SECTOR];
    read(0, &mut s0).map_err(|()| PartError::Io)?;
    if s0[510] != 0x55 || s0[511] != 0xAA || is_fat_boot_sector(&s0) {
        return Ok(Table::empty(Scheme::None));
    }
    // Four 16-byte entries at 446.
    for i in 0..4 {
        let st = s0[446 + 16 * i];
        if st != 0x00 && st != 0x80 {
            return Ok(Table::empty(Scheme::None));
        }
    }
    if (0..4).any(|i| s0[446 + 16 * i + 4] == 0xEE) {
        return parse_gpt(capacity, read);
    }
    let mut t = Table::empty(Scheme::Mbr);
    for i in 0..4 {
        let e = &s0[446 + 16 * i..446 + 16 * (i + 1)];
        let ty = e[4];
        let start = le32(e, 8) as u64;
        let sectors = le32(e, 12) as u64;
        if ty == 0 && start == 0 && sectors == 0 {
            continue;
        }
        if ty == 0 {
            // A type-0 entry with a range is not "unused"; it is malformed.
            return Err(PartError::OutOfRange);
        }
        accept(&mut t, Partition { start, sectors, mbr_type: ty }, 1, capacity)?;
    }
    Ok(t)
}

/// The fields of a GPT header that the parser and [`verify_backup`] use.
#[derive(Clone, Copy, PartialEq, Eq)]
struct GptHeader {
    my_lba: u64,
    alternate_lba: u64,
    first_usable: u64,
    last_usable: u64,
    disk_guid: [u8; 16],
    entries_lba: u64,
    n_entries: u32,
    esize: u32,
    entries_crc: u32,
}

/// Read the GPT header at `lba` and check it: signature, size, CRC32, its own
/// LBA, the usable range and the entry array inside the medium, and the
/// array's CRC32 over exactly `n_entries * esize` bytes.
fn read_gpt_header<F>(lba: u64, capacity: u64, read: &mut F) -> Result<GptHeader, PartError>
where
    F: FnMut(u64, &mut [u8; SECTOR]) -> Result<(), ()>,
{
    let mut h = [0u8; SECTOR];
    read(lba, &mut h).map_err(|()| PartError::Io)?;
    if &h[0..8] != b"EFI PART" {
        return Err(PartError::BadGptHeader);
    }
    let hsize = le32(&h, 12) as usize;
    if !(92..=SECTOR).contains(&hsize) {
        return Err(PartError::BadGptHeader);
    }
    let stored = le32(&h, 16);
    let mut hc = h;
    hc[16..20].copy_from_slice(&[0; 4]);
    if crc32_update(0, &hc[..hsize]) != stored {
        return Err(PartError::BadHeaderCrc);
    }
    let mut disk_guid = [0u8; 16];
    disk_guid.copy_from_slice(&h[56..72]);
    let g = GptHeader {
        my_lba: le64(&h, 24),
        alternate_lba: le64(&h, 32),
        first_usable: le64(&h, 40),
        last_usable: le64(&h, 48),
        disk_guid,
        entries_lba: le64(&h, 72),
        n_entries: le32(&h, 80),
        esize: le32(&h, 84),
        entries_crc: le32(&h, 88),
    };
    if g.my_lba != lba
        || g.first_usable < 2
        || g.first_usable > g.last_usable
        || g.last_usable >= capacity
        || g.entries_lba < 2
        || g.n_entries > GPT_MAX_ENTRIES
        || !(128..=512).contains(&g.esize)
        || g.esize % 8 != 0
    {
        return Err(PartError::BadGptHeader);
    }
    let bytes = (g.n_entries as u64) * (g.esize as u64); // <= 128 * 512
    let n_sectors = bytes.div_ceil(SECTOR as u64);
    let array_end = g.entries_lba.checked_add(n_sectors).ok_or(PartError::BadGptHeader)?;
    if array_end > capacity {
        return Err(PartError::BadGptHeader);
    }
    let mut crc = 0u32;
    let mut left = bytes as usize;
    let mut buf = [0u8; SECTOR];
    for k in 0..n_sectors {
        read(g.entries_lba + k, &mut buf).map_err(|()| PartError::Io)?;
        let take = left.min(SECTOR);
        crc = crc32_update(crc, &buf[..take]);
        left -= take;
    }
    if crc != g.entries_crc {
        return Err(PartError::BadEntriesCrc);
    }
    Ok(g)
}

fn parse_gpt<F>(capacity: u64, read: &mut F) -> Result<Table, PartError>
where
    F: FnMut(u64, &mut [u8; SECTOR]) -> Result<(), ()>,
{
    let GptHeader { first_usable, last_usable, entries_lba, n_entries, esize, .. } =
        read_gpt_header(1, capacity, read)?;
    let mut buf = [0u8; SECTOR];
    // The entries, their CRC checked by `read_gpt_header`. An entry may
    // straddle sectors (esize is a multiple of 8, not of 512), so it is
    // assembled byte by byte.
    let mut t = Table::empty(Scheme::Gpt);
    let mut ent = [0u8; 512];
    let mut have_sector = u64::MAX;
    for i in 0..n_entries as u64 {
        let off = i * esize as u64;
        for j in 0..48u64 {
            // Only the first 48 bytes are read: type GUID, unique GUID,
            // first and last LBA.
            let byte = off + j;
            let sec = entries_lba + byte / SECTOR as u64;
            if sec != have_sector {
                read(sec, &mut buf).map_err(|()| PartError::Io)?;
                have_sector = sec;
            }
            ent[j as usize] = buf[(byte % SECTOR as u64) as usize];
        }
        if ent[0..16].iter().all(|&b| b == 0) {
            continue;
        }
        let first = le64(&ent, 32);
        let last = le64(&ent, 40);
        if last < first {
            return Err(PartError::OutOfRange);
        }
        let sectors = (last - first).checked_add(1).ok_or(PartError::OutOfRange)?;
        let hi = last_usable.checked_add(1).ok_or(PartError::OutOfRange)?;
        let mbr_type = if ent[0..16] == GPT_SWAP_GUID {
            MBR_SWAP
        } else if ent[0..16] == GPT_RECORDS_GUID {
            if t.records_index().is_some() {
                return Err(PartError::TwoRecords);
            }
            MBR_RECORDS
        } else {
            0
        };
        accept(&mut t, Partition { start: first, sectors, mbr_type }, first_usable, hi)?;
    }
    Ok(t)
}

/// Check the backup GPT of a medium of `capacity` sectors against its
/// primary one: the primary header's `AlternateLBA` is the last sector (where
/// UEFI puts the backup), the header there passes every check the primary
/// passes (its own LBA, CRC32, its entry array's CRC32) and points back at
/// LBA 1, its array lies past the usable range, and it describes the same
/// disk, usable range and array (size and CRC32) as the primary. Any
/// difference is [`PartError::BadBackup`] (a failing check of the backup
/// itself keeps its own error): one of the two copies was changed, and
/// nothing says which one is right.
pub fn verify_backup<F>(capacity: u64, read: &mut F) -> Result<(), PartError>
where
    F: FnMut(u64, &mut [u8; SECTOR]) -> Result<(), ()>,
{
    let p = read_gpt_header(1, capacity, read)?;
    let last = capacity.checked_sub(1).ok_or(PartError::BadBackup)?;
    if p.alternate_lba != last {
        return Err(PartError::BadBackup);
    }
    let b = read_gpt_header(last, capacity, read)?;
    let same = b.alternate_lba == 1
        && b.entries_lba > b.last_usable
        && (b.first_usable, b.last_usable, b.disk_guid) == (p.first_usable, p.last_usable, p.disk_guid)
        && (b.n_entries, b.esize, b.entries_crc) == (p.n_entries, p.esize, p.entries_crc);
    if same { Ok(()) } else { Err(PartError::BadBackup) }
}

// ── The published table ──────────────────────────────────────────────────────
//
// Written once, at boot, before any task can hold a disk capability; read by
// the capability minter (`crates/core/ipc/src/disk_cap.rs`) and by the disk
// syscalls' range check. Atomics rather than a lock so this file stays
// dependency-free; the count is stored last with `Release`, so a reader that
// sees `n` partitions sees their bounds.

static STARTS: [AtomicU64; MAX_PARTS] = [const { AtomicU64::new(0) }; MAX_PARTS];
static LENS: [AtomicU64; MAX_PARTS] = [const { AtomicU64::new(0) }; MAX_PARTS];
static COUNT: AtomicU32 = AtomicU32::new(0);
/// Index of the swap partition plus one; 0 for none.
static SWAP_AT: AtomicU32 = AtomicU32::new(0);
/// Index of the records partition plus one; 0 for none.
static RECORDS_AT: AtomicU32 = AtomicU32::new(0);
/// Set by [`claim_swap`]: the swap partition is the kernel's.
static SWAP_CLAIMED: AtomicBool = AtomicBool::new(false);
static PUBLISHED: AtomicBool = AtomicBool::new(false);

/// Publish `t`. Only the first call takes effect: a capability minted for
/// "partition n" must not change meaning under its holder. Returns whether
/// this call published.
pub fn publish(t: &Table) -> bool {
    if PUBLISHED.swap(true, Ordering::AcqRel) {
        return false;
    }
    for (i, p) in t.parts[..t.count].iter().enumerate() {
        STARTS[i].store(p.start, Ordering::Relaxed);
        LENS[i].store(p.sectors, Ordering::Relaxed);
    }
    SWAP_AT.store(t.swap_index().map_or(0, |i| i as u32 + 1), Ordering::Relaxed);
    RECORDS_AT.store(t.records_index().map_or(0, |i| i as u32 + 1), Ordering::Relaxed);
    COUNT.store(t.count as u32, Ordering::Release);
    true
}

/// Take the swap partition for the kernel, as `(start, sectors)`: `None` when
/// the table has none, or it was taken already. Call it at boot, before any
/// task can hold a disk capability; afterwards [`partition`] answers `None`
/// for its index, so no capability can be minted for it and no disk syscall
/// reaches it.
pub fn claim_swap() -> Option<(u64, u64)> {
    let n = COUNT.load(Ordering::Acquire);
    let at = SWAP_AT.load(Ordering::Relaxed);
    if at == 0 || at > n || SWAP_CLAIMED.swap(true, Ordering::AcqRel) {
        return None;
    }
    let i = at as usize - 1;
    Some((STARTS[i].load(Ordering::Relaxed), LENS[i].load(Ordering::Relaxed)))
}

/// Partition `index` of the published table, as `(start, sectors)`. `None`
/// for the swap partition once the kernel has claimed it, and always for the
/// records partition: this is the view of everything that hands the medium
/// to someone (capabilities, the disk syscalls, the filesystem scan).
pub fn partition(index: u32) -> Option<(u64, u64)> {
    if SWAP_CLAIMED.load(Ordering::Acquire) && index + 1 == SWAP_AT.load(Ordering::Relaxed) {
        return None;
    }
    if RECORDS_AT.load(Ordering::Acquire).checked_sub(1) == Some(index) {
        return None;
    }
    extent(index)
}

/// The published records partition, as `(index, start, sectors)`; `None`
/// when the table has none (or is not published yet). Its contents are the
/// kernel's alone: [`partition`] never names it.
pub fn records() -> Option<(u32, u64, u64)> {
    let at = RECORDS_AT.load(Ordering::Acquire);
    let (start, sectors) = extent(at.checked_sub(1)?)?;
    Some((at - 1, start, sectors))
}

/// Partition `index` as `(start, sectors)` *whoever owns it*, the claimed swap
/// partition included. For the kernel's own accounting of what lies where on
/// the medium (the reserved tail past the last partition), which must not
/// treat the swap partition as free space.
pub fn extent(index: u32) -> Option<(u64, u64)> {
    let n = COUNT.load(Ordering::Acquire);
    if index >= n {
        return None;
    }
    let i = index as usize;
    Some((STARTS[i].load(Ordering::Relaxed), LENS[i].load(Ordering::Relaxed)))
}

/// How many partitions were published (0 before `publish`).
pub fn count() -> u32 {
    COUNT.load(Ordering::Acquire)
}

/// Is `[lba, lba + max(count, 1))` inside partition `index`?
///
/// A zero count is treated as one sector, so a request cannot name a sector
/// outside the partition just because it asked for nothing there; the
/// syscall rejects the zero count on its own afterwards.
pub fn contains(index: u32, lba: u64, count: u64) -> bool {
    let (start, len) = match partition(index) {
        Some(p) => p,
        None => return false,
    };
    let end = match lba.checked_add(count.max(1)) {
        Some(e) => e,
        None => return false,
    };
    // `start + len` cannot overflow: `parse` checked it before publishing.
    lba >= start && end <= start + len
}

/// The absolute LBA of sector `rel` of partition `index`, if the run
/// `[rel, rel + max(count, 1))` lies inside that partition.
///
/// **A partition capability names sectors RELATIVE to its partition** (owner
/// decision, round 23): the kernel adds the start, so a holder cannot even
/// spell an LBA outside it. `rel` 0 is the partition's first sector and
/// `len - 1` its last; a run reaching `len` or past it, or one whose end
/// overflows, is `None`. A zero count is treated as one sector, as in
/// [`contains`].
pub fn resolve(index: u32, rel: u64, count: u64) -> Option<u64> {
    let (start, len) = partition(index)?;
    let end = rel.checked_add(count.max(1))?;
    if end > len {
        return None;
    }
    // `start + len` fits (checked by `parse`), and `rel < end <= len`.
    Some(start + rel)
}

/// Host tests only: forget the published table.
#[cfg(not(target_os = "none"))]
pub fn reset_for_tests() {
    COUNT.store(0, Ordering::Release);
    SWAP_AT.store(0, Ordering::Relaxed);
    RECORDS_AT.store(0, Ordering::Relaxed);
    SWAP_CLAIMED.store(false, Ordering::Release);
    PUBLISHED.store(false, Ordering::Release);
}

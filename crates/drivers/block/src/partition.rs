// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Partition table parser (MBR and GPT) and the table the kernel publishes
//! from it (RFC-0048 prerequisite P3).
//!
//! A `Cap<Disk>` used to mean the whole medium: `sys_disk_read`/`write` asked
//! for resource 0 and nothing else existed. Since P3 a capability can name
//! ONE partition instead — resource `n + 1` is partition `n` of the table
//! parsed here at boot — and its holder names sectors relative to that
//! partition ([`resolve`] adds the start); the disk syscalls refuse, and
//! record, any run past its end. Resource 0 keeps its old, absolute meaning.
//!
//! # What is parsed, and what is refused
//!
//! The medium is attacker-writable (SD card, USB MSC gadget), so every field
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
//! This file has no dependency on the rest of the crate (it names only
//! `core`), so the host test crates pull it with `#[path]`.

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

pub const SECTOR: usize = 512;

/// Most partitions the kernel publishes (and so the most a topology can name).
pub const MAX_PARTS: usize = 16;

/// Most GPT entries read. The UEFI minimum array is 128 entries of 128 B.
pub const GPT_MAX_ENTRIES: u32 = 128;

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
    /// The MBR type byte, or 0 for a GPT entry.
    pub mbr_type: u8,
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

fn parse_gpt<F>(capacity: u64, read: &mut F) -> Result<Table, PartError>
where
    F: FnMut(u64, &mut [u8; SECTOR]) -> Result<(), ()>,
{
    let mut h = [0u8; SECTOR];
    read(1, &mut h).map_err(|()| PartError::Io)?;
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
    let my_lba = le64(&h, 24);
    let first_usable = le64(&h, 40);
    let last_usable = le64(&h, 48);
    let entries_lba = le64(&h, 72);
    let n_entries = le32(&h, 80);
    let esize = le32(&h, 84);
    let entries_crc = le32(&h, 88);
    if my_lba != 1
        || first_usable < 2
        || first_usable > last_usable
        || last_usable >= capacity
        || entries_lba < 2
        || n_entries > GPT_MAX_ENTRIES
        || !(128..=512).contains(&esize)
        || esize % 8 != 0
    {
        return Err(PartError::BadGptHeader);
    }
    let bytes = (n_entries as u64) * (esize as u64); // <= 128 * 512
    let n_sectors = bytes.div_ceil(SECTOR as u64);
    let array_end = entries_lba.checked_add(n_sectors).ok_or(PartError::BadGptHeader)?;
    if array_end > capacity {
        return Err(PartError::BadGptHeader);
    }
    // First pass: the CRC over exactly `bytes` bytes.
    let mut crc = 0u32;
    let mut left = bytes as usize;
    let mut buf = [0u8; SECTOR];
    for k in 0..n_sectors {
        read(entries_lba + k, &mut buf).map_err(|()| PartError::Io)?;
        let take = left.min(SECTOR);
        crc = crc32_update(crc, &buf[..take]);
        left -= take;
    }
    if crc != entries_crc {
        return Err(PartError::BadEntriesCrc);
    }
    // Second pass: the entries. An entry may straddle sectors (esize is a
    // multiple of 8, not of 512), so it is assembled byte by byte.
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
        accept(&mut t, Partition { start: first, sectors, mbr_type: 0 }, first_usable, hi)?;
    }
    Ok(t)
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
    COUNT.store(t.count as u32, Ordering::Release);
    true
}

/// Partition `index` of the published table, as `(start, sectors)`.
pub fn partition(index: u32) -> Option<(u64, u64)> {
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
    PUBLISHED.store(false, Ordering::Release);
}

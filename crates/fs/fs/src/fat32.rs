// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
/// FAT32 filesystem — port of kernel/fs/fat32.c
///
/// Mounts a FAT32 volume on VirtIO block device and provides read AND write
/// file access — the file-level API below (`fat32_open`/`fat32_write`/
/// `fat32_seek`/`fat32_close`) and the root-level write helpers
/// (`fat32_write_file`, journal, cluster allocation) are the write half.
/// "read-only (read/write could be added in the future)" described an
/// earlier state of this file; roughly 1,400 lines of write path have been
/// added since.

use azos_sync::SpinLock;

// The boot disk (`/fat`) and its knobs: the `fat32_dev` module next to this
// file (the crate root's; a host suite that pulls this file gives its own).
// Every other volume is a [`Vol`] over a [`VolDev`] of its own (`usbvol`).
use super::fat32_dev::{self as dev, blkdev};

/// Why a discard did not happen: the block layer's answer, for every volume.
pub use blkdev::DiscardError;

/// The device of a volume, as this file reads and writes it: 512-byte
/// sectors, the surface of `azos_drv_block::blkdev` the volume uses, and the
/// medium's partition table.
pub trait VolDev: Sync {
    fn capacity_sectors(&self) -> u64;
    /// A read the cache owner issues (no read observer).
    fn read_quiet(&self, sector: u64, count: u32, buf: &mut [u8]) -> Result<(), ()>;
    /// A write the cache owner issues (no write observer).
    fn write_quiet(&self, sector: u64, count: u32, buf: &[u8]) -> Result<(), ()>;
    /// `preflush`: every completed write is durable first; `fua`: this one
    /// is durable when it returns (asked only where [`VolDev::fua_commit`]).
    fn write_run(&self, sector: u64, count: u32, buf: &[u8], preflush: bool, fua: bool) -> Result<(), ()>;
    fn flush(&self) -> Result<(), azos_drv_api::block::FlushError>;
    /// Does a FUA write commit natively?
    fn fua_commit(&self) -> bool;
    /// Is discard compiled in for this device at all?
    fn discard_supported(&self) -> bool;
    fn discard(&self, runs: &[(u64, u32)]) -> Result<(), DiscardError>;
    /// Install the observers of the medium's other readers and writers (the
    /// boot disk's ring-3 block path); a device nobody else reads does nothing.
    fn set_write_observer(&self, f: fn(u64, u32));
    fn set_read_observer(&self, f: fn(u64, u32), held: fn(u64, u32) -> bool);
    /// The medium's partitions, as `(start, sectors)`.
    fn partition_count(&self) -> u32;
    fn partition(&self, index: u32) -> Option<(u64, u64)>;
}

/// What differs between two volumes beyond their device.
#[derive(Clone, Copy)]
pub struct Knobs {
    /// The cache runs write-back (Kconfig `FS_WRITEBACK` for the boot disk);
    /// otherwise write-through.
    pub writeback: bool,
    /// The `fs-wb` task serves the volume's flush tickets.
    pub ticketed: bool,
    /// [`crate::vfs::FileSystem::fs_type`] of the volume.
    pub fs_type: u32,
    /// [`crate::vfs::ContentStamp::fs`] of the volume's files.
    pub stamp: u32,
}

/// The boot disk: `azos_drv_block::blkdev` and its published partition table.
struct BootDev;

impl VolDev for BootDev {
    fn capacity_sectors(&self) -> u64 { blkdev::capacity_sectors() }
    fn read_quiet(&self, sector: u64, count: u32, buf: &mut [u8]) -> Result<(), ()> {
        blkdev::read_quiet(sector, count, buf)
    }
    fn write_quiet(&self, sector: u64, count: u32, buf: &[u8]) -> Result<(), ()> {
        blkdev::write_quiet(sector, count, buf)
    }
    fn write_run(&self, sector: u64, count: u32, buf: &[u8], preflush: bool, fua: bool) -> Result<(), ()> {
        blkdev::write_run(sector, count, buf, preflush, fua)
    }
    fn flush(&self) -> Result<(), azos_drv_api::block::FlushError> { blkdev::flush() }
    fn fua_commit(&self) -> bool { blkdev::fua_commit() }
    fn discard_supported(&self) -> bool { blkdev::DISCARD }
    fn discard(&self, runs: &[(u64, u32)]) -> Result<(), DiscardError> {
        blkdev::discard(runs)
    }
    fn set_write_observer(&self, f: fn(u64, u32)) { blkdev::set_write_observer(f) }
    fn set_read_observer(&self, f: fn(u64, u32), held: fn(u64, u32) -> bool) { blkdev::set_read_observer(f, held) }
    fn partition_count(&self) -> u32 { dev::partition::count() }
    fn partition(&self, index: u32) -> Option<(u64, u64)> { dev::partition::partition(index) }
}

/// The boot volume, `/fat`.
pub static BOOT: Vol = Vol::new(
    &BootDev,
    Knobs { writeback: dev::WRITEBACK, ticketed: dev::TICKETED, fs_type: dev::FS_TYPE, stamp: dev::STAMP_FS },
    &FAT32_FS,
    VolCache::Boot(&BOOT_CACHE),
);

// ── FAT32 on-disk structures ──────────────────────────────────────────────────

/// BIOS Parameter Block (BPB) as found at sector 0.
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct Fat32Bpb {
    pub jmp_boot:        [u8; 3],
    pub oem_name:        [u8; 8],
    pub bytes_per_sec:   u16,
    pub sec_per_clus:    u8,
    pub rsvd_sec_cnt:    u16,
    pub num_fats:        u8,
    pub root_ent_cnt:    u16,   // 0 for v.fat32
    pub tot_sec16:       u16,   // 0 for v.fat32
    pub media:           u8,
    pub fat_sz16:        u16,   // 0 for v.fat32
    pub sec_per_trk:     u16,
    pub num_heads:       u16,
    pub hidd_sec:        u32,
    pub tot_sec32:       u32,
    // FAT32-specific
    pub fat_sz32:        u32,
    pub ext_flags:       u16,
    pub fs_ver:          u16,
    pub root_clus:       u32,
    pub fs_info:         u16,
    pub bk_boot_sec:     u16,
    pub reserved:        [u8; 12],
    pub drv_num:         u8,
    pub reserved1:       u8,
    pub boot_sig:        u8,
    pub vol_id:          u32,
    pub vol_lab:         [u8; 11],
    pub fil_sys_type:    [u8; 8],
}

/// FAT32 short-name directory entry (32 bytes).
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct Fat32Dirent {
    pub name:       [u8; 8],
    pub ext:        [u8; 3],
    pub attr:       u8,
    pub nt_res:     u8,
    pub crt_time_tenth: u8,
    pub crt_time:   u16,
    pub crt_date:   u16,
    pub lst_acc_date: u16,
    pub fst_clus_hi: u16,
    pub wrt_time:   u16,
    pub wrt_date:   u16,
    pub fst_clus_lo: u16,
    pub file_size:  u32,
}

#[allow(dead_code)] const ATTR_READ_ONLY: u8 = 0x01;
#[allow(dead_code)] const ATTR_HIDDEN:    u8 = 0x02;
#[allow(dead_code)] const ATTR_SYSTEM:    u8 = 0x04;
const ATTR_VOLUME_ID: u8 = 0x08;
const ATTR_DIRECTORY: u8 = 0x10;
#[allow(dead_code)] const ATTR_ARCHIVE:   u8 = 0x20;
const ATTR_LFN:       u8 = 0x0F;  // Long filename entry marker

const FAT32_EOC: u32 = 0x0FFF_FFF8;  // End-of-chain marker
/// Value written to the FAT to terminate a cluster chain (canonical EOC).
const FAT32_END_OF_CHAIN: u32 = 0x0FFF_FFFF;
/// First valid data cluster number (0 and 1 are reserved per the FAT spec).
const FAT32_FIRST_DATA_CLUSTER: u32 = 2;

const SECTOR_SIZE: usize = 512;

/// FAT32 entries are 4 bytes, so a 512-byte sector holds 128 of them.
const FAT32_ENTRIES_PER_SECTOR: u32 = (SECTOR_SIZE / 4) as u32;

/// Size of one on-disk directory entry.
const FAT32_DIR_ENTRY_SIZE: usize = 32;
/// Number of directory entries that fit in a 512-byte sector.
const FAT32_DIRENTS_PER_SECTOR: usize = SECTOR_SIZE / FAT32_DIR_ENTRY_SIZE;

/// First byte of a directory entry slot that is unused and terminates the dir.
const DIRENT_MARK_END: u8 = 0x00;
/// First byte of a directory entry slot that was deleted (reusable).
const DIRENT_MARK_DELETED: u8 = 0xE5;

/// Size of one on-disk directory entry, and how many fit in a sector.
///
/// **These were eight copied literals** — `for e in 0..DIRENTS_PER_SECTOR { let off = e * DIRENT_SIZE; }`
/// written out four times, with no constant anywhere and `SECTOR_SIZE` sitting
/// twenty lines above. Every one of those loops indexes a `[u8; SECTOR_SIZE]`
/// at `off + DIRENT_OFF_*`, so the day the two numbers stop agreeing — a
/// 4 KiB-sector device, a different entry layout — the index goes past the
/// buffer, and `panic = "abort"` turns that into a board reset.
///
/// Derived, not restated, so the relationship is the compiler's to check
/// rather than the next reader's to notice. The assert below is what makes
/// `DIRENTS_PER_SECTOR` a fact instead of an assumption.
const DIRENT_SIZE: usize = 32;
const DIRENTS_PER_SECTOR: usize = SECTOR_SIZE / DIRENT_SIZE;
const _: () = assert!(
    SECTOR_SIZE % DIRENT_SIZE == 0,
    "a sector must hold a whole number of directory entries: the scan loops \
     step by DIRENT_SIZE and stop at DIRENTS_PER_SECTOR, so a remainder would \
     leave a partial entry unread and, worse, make the last full entry's \
     fields index past the sector buffer"
);

/// Offsets within a directory entry ([`DIRENT_SIZE`] bytes).
const DIRENT_OFF_NAME: usize = 0;
const DIRENT_OFF_EXT: usize = 8;
const DIRENT_OFF_ATTR: usize = 11;
const DIRENT_OFF_FST_CLUS_HI: usize = 20;
const DIRENT_OFF_FST_CLUS_LO: usize = 26;
const DIRENT_OFF_FILE_SIZE: usize = 28;

/// ATTR byte value for a regular file (archive bit set).
const DIRENT_ATTR_ARCHIVE_FILE: u8 = 0x20;
/// ATTR byte value for a subdirectory.
const DIRENT_ATTR_SUBDIR: u8 = ATTR_DIRECTORY;

/// Maximum concurrently open FAT32 file handles.
pub const FAT32_MAX_OPEN_FILES: usize = 16;
/// Maximum directory depth supported by the path walker.
const FAT32_MAX_PATH_DEPTH: usize = 8;

// ── Write-Ahead Journal (AS — Power-Loss Safety) ────────────────────────────

/// Journal sector location. Sector 8: inside the reserved region every
/// FAT32 volume has (`rsvd_sec_cnt`, 32 by mkfs.fat's default), clear of
/// the boot sector (0), FSInfo (1 by default), and the backup boot sector
/// pair (6/7). U09-9 (2026-09-25) found the journal at sector 1 — it was
/// overwriting FSInfo on every journaled write; the first fix rejected
/// mkfs.fat's default layout instead, which refused every gate image.
/// `validate_bpb` still refuses a volume whose FSInfo/backup-boot sectors
/// alias this one, or whose reserved region is too small to hold it.
pub const JOURNAL_SECTOR: u32 = 8;

/// Journal entry states.
const JOURNAL_EMPTY: u8 = 0x00;
const JOURNAL_PENDING: u8 = 0x01;
const JOURNAL_COMMITTED: u8 = 0x02;

/// Journal operation types.
///
/// **1 and 2 are RESERVED, not free.** Neither is ever written: counted
/// 2026-09-21, the writers are `fat32_write_file` (`WRITE_DIR`) and
/// `fat32_unlink_root` (`UNLINK`). `ALLOC` also had a recovery arm that
/// obeyed it — an op the kernel never emits, acted on at mount, from a sector
/// an adversary writes; see `fat32_journal_recover`. The arm is gone and the
/// numbers stay declared, because a journal on a volume written by an older
/// build may still carry them and reassigning 1 or 2 would make that entry
/// mean something else. Same rule as the retired syscall numbers: append,
/// never reuse.
#[allow(dead_code)]
const JOURNAL_OP_ALLOC: u8 = 1;
#[allow(dead_code)]
const JOURNAL_OP_FREE: u8 = 2;
const JOURNAL_OP_WRITE_DIR: u8 = 3;
const JOURNAL_OP_UNLINK: u8 = 4;
/// Compound "unlink old file + install new file" — a single journal record
/// covering `fat32_write_file`'s overwrite path end to end.
///
/// **Written by:** `fat32_write_file`, and only when `name83` already names
/// an existing file (the overwrite case). Written once, before the old
/// file's chain is freed or its dirent touched at all.
///
/// **Obeyed by:** `fat32_journal_recover` at mount. Unlike `WRITE_DIR` and
/// `UNLINK` above — whose PENDING state is always discarded because nothing
/// has been touched yet when they are written — a PENDING `OVERWRITE` entry
/// IS acted on, because by the time it exists on disk the new chain is
/// already fully allocated and written (see `fat32_write_file`), so there is
/// real work an interrupted crash may have left unfinished. See that
/// function and the recovery arm below for why both replay steps are
/// idempotent.
const JOURNAL_OP_OVERWRITE: u8 = 5;
/// Wave 15: `fat32_rename` over an existing file, ONE record. `dir_sector`/
/// `dir_offset`: the destination's dirent; `cluster`/`size`: the source's
/// chain and size, which the destination takes; `fat_value`: the
/// destination's old chain, freed. In `_reserved`: the source dirent's
/// sector (`[0..4]`), offset (`[4..6]`) and 8.3 name (`[6..17]`), which is
/// deleted. Replayed whole at mount once PENDING is durable, so a cut leaves
/// the rename undone or done, never both names on one chain.
const JOURNAL_OP_RENAME: u8 = 6;

/// Journal magic bytes — "JRNL".
const JOURNAL_MAGIC: [u8; 4] = [b'J', b'R', b'N', b'L'];

/// Size of the reserved portion after JournalEntry fixed fields.
const JOURNAL_RESERVED_SIZE: usize = 486;

/// Journal entry format — fits in one 512-byte sector.
/// Written BEFORE the actual FAT/directory update, so on power loss
/// we can replay or discard the pending operation.
#[repr(C)]
#[derive(Clone, Copy)]
struct JournalEntry {
    magic: [u8; 4],                         // "JRNL"
    state: u8,                              // EMPTY, PENDING, COMMITTED
    op_type: u8,                            // ALLOC, FREE, WRITE_DIR, UNLINK, OVERWRITE
    _pad: [u8; 2],
    cluster: u32,                           // target cluster (OVERWRITE: new first cluster)
    fat_value: u32,                         // new FAT entry value (OVERWRITE: old chain to free)
    dir_sector: u32,                        // directory sector being modified
    dir_offset: u16,                        // offset within directory sector
    size: u32,                              // OVERWRITE only: new file size
    _reserved: [u8; JOURNAL_RESERVED_SIZE], // padding to 512 bytes
}

impl JournalEntry {
    const fn empty() -> Self {
        JournalEntry {
            magic: JOURNAL_MAGIC,
            state: JOURNAL_EMPTY,
            op_type: 0,
            _pad: [0; 2],
            cluster: 0,
            fat_value: 0,
            dir_sector: 0,
            dir_offset: 0,
            size: 0,
            _reserved: [0; JOURNAL_RESERVED_SIZE],
        }
    }

    /// Serialize journal entry into a 512-byte sector buffer.
    fn to_sector(&self, buf: &mut [u8; SECTOR_SIZE]) {
        buf.fill(0);
        buf[0..4].copy_from_slice(&self.magic);
        buf[4] = self.state;
        buf[5] = self.op_type;
        // _pad at [6..8]
        buf[8..12].copy_from_slice(&self.cluster.to_le_bytes());
        buf[12..16].copy_from_slice(&self.fat_value.to_le_bytes());
        buf[16..20].copy_from_slice(&self.dir_sector.to_le_bytes());
        buf[20..22].copy_from_slice(&self.dir_offset.to_le_bytes());
        buf[22..26].copy_from_slice(&self.size.to_le_bytes());
        buf[26..].copy_from_slice(&self._reserved);
    }

    /// Deserialize journal entry from a 512-byte sector buffer.
    fn from_sector(buf: &[u8; SECTOR_SIZE]) -> Self {
        let mut entry = JournalEntry::empty();
        entry.magic.copy_from_slice(&buf[0..4]);
        entry.state = buf[4];
        entry.op_type = buf[5];
        entry.cluster = u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]);
        entry.fat_value = u32::from_le_bytes([buf[12], buf[13], buf[14], buf[15]]);
        entry.dir_sector = u32::from_le_bytes([buf[16], buf[17], buf[18], buf[19]]);
        entry.dir_offset = u16::from_le_bytes([buf[20], buf[21]]);
        entry.size = u32::from_le_bytes([buf[22], buf[23], buf[24], buf[25]]);
        entry._reserved.copy_from_slice(&buf[26..]);
        entry
    }
}

/// Write a journal entry to the journal sector.
fn fat32_journal_write(v: &'static Vol, entry: &JournalEntry) -> Result<(), ()> {
    let mut buf = [0u8; SECTOR_SIZE];
    entry.to_sector(&mut buf);
    write_sector(v, JOURNAL_SECTOR, &buf)
}

/// Read the journal entry from the journal sector.
fn fat32_journal_read(v: &'static Vol) -> Result<JournalEntry, ()> {
    let mut buf = [0u8; SECTOR_SIZE];
    read_sector(v, JOURNAL_SECTOR, &mut buf)?;
    Ok(JournalEntry::from_sector(&buf))
}

/// Clear the journal (set state to EMPTY).
fn fat32_journal_clear(v: &'static Vol) -> Result<(), ()> {
    let entry = JournalEntry::empty();
    fat32_journal_write(v, &entry)
}

/// Check and replay journal on mount.
/// If journal has PENDING entry -> roll back (free allocated clusters).
/// If journal has COMMITTED entry -> complete (clear journal).
/// The first cluster the dirent at `(sector, off)` names, or `None` when
/// the location is outside the data region or unreadable (U09-10: journal
/// fields come off an attacker-writable volume).
fn dirent_first_cluster_at(v: &'static Vol, sector: u32, off: u16) -> Option<(u32, [u8; SECTOR_SIZE])> {
    let (data_start, data_clusters, spc) = {
        let fv = v.fat32.lock();
        (fv.data_start, fv.data_clusters, fv.secs_per_clus.max(1))
    };
    let data_end = data_start.saturating_add(data_clusters.saturating_mul(spc));
    let off = off as usize;
    if sector < data_start || sector >= data_end || off + DIRENT_SIZE > SECTOR_SIZE || off % DIRENT_SIZE != 0 {
        return None;
    }
    let mut buf = [0u8; SECTOR_SIZE];
    read_sector(v, sector, &mut buf).ok()?;
    let hi = u16::from_le_bytes([buf[off + DIRENT_OFF_FST_CLUS_HI], buf[off + DIRENT_OFF_FST_CLUS_HI + 1]]);
    let lo = u16::from_le_bytes([buf[off + DIRENT_OFF_FST_CLUS_LO], buf[off + DIRENT_OFF_FST_CLUS_LO + 1]]);
    Some((((hi as u32) << 16) | lo as u32, buf))
}

/// Apply a `JOURNAL_OP_RENAME` record: the destination dirent takes the
/// source's cluster and size, the source dirent is deleted, the
/// destination's old chain is freed. Every step writes a recorded target
/// state, so a replay over a partly applied rename reproduces the same
/// bytes; the record is discarded when the dirents it names do not hold
/// what it says (either before or after the rename).
fn journal_replay_rename(v: &'static Vol, entry: &JournalEntry) {
    let src_sector = u32::from_le_bytes([entry._reserved[0], entry._reserved[1], entry._reserved[2], entry._reserved[3]]);
    let src_off = u16::from_le_bytes([entry._reserved[4], entry._reserved[5]]);
    let mut src_name = [0u8; 11];
    src_name.copy_from_slice(&entry._reserved[6..17]);
    let dst_ok = matches!(dirent_first_cluster_at(v, entry.dir_sector, entry.dir_offset),
        Some((c, _)) if c == entry.fat_value || c == entry.cluster);
    let src = dirent_first_cluster_at(v, src_sector, src_off);
    let src_ok = match &src {
        Some((c, buf)) => {
            let o = src_off as usize;
            // Before the delete: the source's name and chain; after it: a
            // deleted slot.
            (buf[o..o + 11] == src_name && *c == entry.cluster) || buf[o] == DIRENT_MARK_DELETED
        }
        None => false,
    };
    if !dst_ok || !src_ok {
        azos_drv_sys::kwarn!("[FAT32] Journal recovery: RENAME entry does not match its dirents — discarded");
        return;
    }
    azos_drv_sys::kprintln!("[FAT32] Journal recovery: completing rename (clus={}, old_clus={})",
        entry.cluster, entry.fat_value);
    let _ = rename_apply(v, entry.dir_sector, entry.dir_offset, src_sector, src_off, &src_name,
        entry.cluster, entry.size, entry.fat_value, true);
}

/// The three writes of a rename over an existing file (see
/// `JOURNAL_OP_RENAME`), in an order whose every prefix leaves one name on
/// the chain: destination first, then the source deleted, then the old
/// chain freed (`free_old`: recovery; a live rename under `defer_frees`
/// holds it until its record is cleared instead).
#[allow(clippy::too_many_arguments)]
fn rename_apply(v: &'static Vol, dst_sector: u32, dst_off: u16, src_sector: u32, src_off: u16, src_name: &[u8; 11],
                cluster: u32, size: u32, old_chain: u32, free_old: bool) -> Result<(), ()> {
    fat32_update_dirent_clus_size(v, dst_sector, dst_off, cluster, size)?;
    let mut buf = [0u8; SECTOR_SIZE];
    read_sector(v, src_sector, &mut buf)?;
    let o = src_off as usize;
    if buf[o..o + 11] == *src_name {
        buf[o] = DIRENT_MARK_DELETED;
        write_sector(v, src_sector, &buf)?;
    }
    if free_old && old_chain >= FAT32_FIRST_DATA_CLUSTER && old_chain != cluster {
        fat32_free_chain_on(v, old_chain);
    }
    Ok(())
}

fn fat32_journal_recover(v: &'static Vol) -> Result<(), ()> {
    let entry = fat32_journal_read(v)?;

    // Not a valid journal entry — nothing to recover.
    if entry.magic != JOURNAL_MAGIC {
        return Ok(());
    }

    match entry.state {
        JOURNAL_PENDING if entry.op_type == JOURNAL_OP_OVERWRITE => {
            // **Complete the interrupted overwrite — the fix for the
            // write-path audit's open finding (2026-09-23).**
            //
            // By construction (see `fat32_write_file`), this entry only
            // ever reaches disk AFTER the new chain (`entry.cluster`,
            // `entry.size`) is fully allocated and written, and BEFORE the
            // old file (`entry.fat_value`'s chain, the dirent at
            // `entry.dir_sector`/`entry.dir_offset`) is touched at all. So
            // whatever crashed mid-operation, exactly two steps can still
            // be outstanding, and both are DETERMINISTIC writes of a target
            // state recorded right here — not a toggle — so replaying
            // either one when it already happened reproduces the same
            // bytes instead of corrupting anything:
            //   1. Point the dirent at the new cluster/size. Idempotent:
            //      same fields, same bytes, every time.
            //   2. Free the old chain. Idempotent: `fat32_free_chain` on an
            //      already-free chain stops at the first non-live cluster
            //      it finds, i.e. immediately.
            // Order matters only for a SECOND crash between these two: the
            // dirent is fixed first so that crash still leaves a complete,
            // readable file, with only a leaked cluster chain to reclaim
            // (never a live one — see step 2's proof above).
            //
            // **U09-10.** `dir_sector` and `fat_value` both come off LBA 1,
            // inside the volume an adversary rewrites over USB mass
            // storage — nothing above bounds `dir_sector` to the data
            // region, or confirms the dirent actually THERE points at
            // `fat_value` before it gets freed. Both checks below close
            // that: `dir_sector` must land in the data region (the only
            // place a real dirent can live), and the dirent it names must
            // currently show EITHER `fat_value` (crash before step 1) OR
            // `cluster` (crash between steps 1 and 2 — see the "order
            // matters" note above for why that is a legitimate, idempotent
            // second pass) — anything else means this entry does not
            // describe the dirent it points at, and is discarded rather
            // than replayed.
            let (data_start, data_clusters, spc) = {
                let fv = v.fat32.lock();
                (fv.data_start, fv.data_clusters, fv.secs_per_clus.max(1))
            };
            let data_end = data_start.saturating_add(data_clusters.saturating_mul(spc));
            let dirent_matches = entry.dir_sector >= data_start
                && entry.dir_sector < data_end
                && (entry.dir_offset as usize) + DIRENT_SIZE <= SECTOR_SIZE
                && {
                    let mut sec_buf = [0u8; SECTOR_SIZE];
                    read_sector(v, entry.dir_sector, &mut sec_buf).is_ok() && {
                        let off = entry.dir_offset as usize;
                        let hi = u16::from_le_bytes(
                            [sec_buf[off + DIRENT_OFF_FST_CLUS_HI], sec_buf[off + DIRENT_OFF_FST_CLUS_HI + 1]],
                        );
                        let lo = u16::from_le_bytes(
                            [sec_buf[off + DIRENT_OFF_FST_CLUS_LO], sec_buf[off + DIRENT_OFF_FST_CLUS_LO + 1]],
                        );
                        let first_cluster = ((hi as u32) << 16) | lo as u32;
                        first_cluster == entry.fat_value || first_cluster == entry.cluster
                    }
                };

            if !dirent_matches {
                azos_drv_sys::kwarn!(
                    "[FAT32] Journal recovery: OVERWRITE entry does not match the dirent \
                     it names — discarded, not replayed"
                );
                return fat32_journal_clear(v);
            }

            azos_drv_sys::kprintln!(
                "[FAT32] Journal recovery: completing overwrite (new_clus={}, old_clus={})",
                entry.cluster, entry.fat_value
            );
            let _ = fat32_update_dirent_clus_size(v, 
                entry.dir_sector, entry.dir_offset, entry.cluster, entry.size,
            );
            if entry.fat_value >= FAT32_FIRST_DATA_CLUSTER {
                fat32_free_chain_on(v, entry.fat_value);
            }
            fat32_journal_clear(v)
        }
        JOURNAL_PENDING if entry.op_type == JOURNAL_OP_RENAME => {
            journal_replay_rename(v, &entry);
            fat32_journal_clear(v)
        }
        JOURNAL_PENDING => {
            // **A PENDING entry (any other op) is discarded, never acted on.**
            //
            // This arm used to free `entry.cluster` when `op_type` was
            // `JOURNAL_OP_ALLOC`. `entry` comes off LBA 1, inside the volume
            // an adversary rewrites over USB mass storage, and the write
            // reached every FAT copy — automatically, at mount, before
            // userspace exists. A bounds check on the cluster kept it inside
            // the FAT, which stops a stray write but not the actual harm:
            // marking a cluster of a LIVE file free, deterministically, on
            // every boot, so the next allocation crosses two chains.
            //
            // **And no production path ever writes `JOURNAL_OP_ALLOC`.**
            // Counted 2026-09-21: the constant and this arm. The writers are
            // `fat32_write_file` and `fat32_unlink_root`, which use
            // `WRITE_DIR` and `UNLINK`. An op type the kernel never emits had
            // exactly one possible author, and it was not the kernel.
            //
            // Discarding is also the right answer for the ops that ARE
            // written: PENDING means the FAT and the directory had not been
            // touched yet, so there is nothing to undo. The worst case is one
            // leaked cluster — against freeing a live one, that is not a
            // trade, it is a strict improvement.
            azos_drv_sys::kprintln!(
                "[FAT32] Journal recovery: discarded pending op={}",
                entry.op_type
            );
            fat32_journal_clear(v)
        }
        JOURNAL_COMMITTED => {
            // Operation completed but journal wasn't cleared — just clear it.
            azos_drv_sys::kprintln!("[FAT32] Journal recovery: cleared committed entry");
            fat32_journal_clear(v)
        }
        _ => {
            // EMPTY or unknown — nothing to do.
            Ok(())
        }
    }
}

// ── Mounted volume state ──────────────────────────────────────────────────────

struct Fat32Vol {
    mounted:       bool,
    fat_start:     u32,   // First sector of FAT
    data_start:    u32,   // First sector of data region
    root_cluster:  u32,   // Cluster number of root directory
    secs_per_clus: u32,   // Sectors per cluster
    bytes_per_clus: u32,  // Bytes per cluster
    fat_sz32:      u32,   // Sectors per FAT table (Phase 8)
    num_fats:      u8,    // Number of FAT copies, typically 2 (Phase 8)
    /// Data clusters the volume actually has, from `tot_sec32`. The
    /// anti-cycle bound — see [`chain_walk_limit`].
    data_clusters: u32,
}

impl Fat32Vol {
    const fn new() -> Self {
        Fat32Vol {
            mounted:        false,
            fat_start:      0,
            data_start:     0,
            root_cluster:   2,
            secs_per_clus:  1,
            bytes_per_clus: 512,
            fat_sz32:       0,
            num_fats:       2,
            data_clusters:  0,
        }
    }

    /// Convert cluster number to first sector in that cluster.
    /// `None` when the cluster does not map into a representable sector range.
    #[allow(dead_code)]
    fn cluster_to_sector(&self, cluster: u32) -> Option<u32> {
        cluster_first_sector(self.data_start, cluster, self.secs_per_clus)
    }
}

/// One FAT32 volume: its device, its knobs and every piece of state that
/// was a static of this file. [`BOOT`] is the boot disk (`/fat`); a second
/// volume (`usbvol`, a USB stick) is another `Vol` over another device, run
/// by the same code: every function that touches a volume takes it as its
/// first argument.
pub struct Vol {
    /// The device the volume sits on.
    dev: &'static dyn VolDev,
    /// The knobs that differ per volume.
    knobs: Knobs,
    /// The volume as a VFS backend (its page cache and unmount name it).
    fs: &'static Fat32Fs,
    /// The sector cache: its own static per volume, of the volume's size
    /// ([`VolCache`]).
    sector_cache: VolCache,
    fat32: SpinLock<Fat32Vol>,
    /// FAT-sector claims: how concurrent FAT mutators stay correct with NO
    /// mutex held across device I/O (owner rule F1, wave 15 FM).
    ///
    /// **What needs excluding.** A FAT entry update (`fat32_write_fat_entry`)
    /// reads its FAT sector, patches 4 bytes and writes the sector to every FAT
    /// copy. Two updates of different entries in the SAME sector, interleaved,
    /// lose one (the second write carries the first's old bytes); two allocators
    /// that both see entry N free both claim it (U09-2: one file's data aliasing
    /// another's). Both are per-sector read-modify-write races.
    ///
    /// **The protocol.** An updater claims the FAT sector's slot (`sector %
    /// FAT32_SECTOR_CLAIM_SLOTS`) in [`FAT_SECTOR_BUSY`] with one `fetch_or`, does
    /// its read-modify-write I/O, and publishes by clearing the bit, bumping
    /// [`FAT_SECTOR_GEN`] and waking [`FAT_SECTOR_WQ`]. A second updater of the
    /// same slot sleeps on that wait queue and retries after the publish; while
    /// it sleeps it lends its priority to the holder ([`ClaimPi`], FX12), so
    /// load between the two priorities cannot starve the holder (`log-flush`
    /// at 12 waiting on `fs-wb` at 20 under prio 13..19 load). No RT task
    /// takes a claim (RT tasks never do block I/O), so the donor is never RT
    /// and F1's concern, an RT waiter inheriting disk latency, does not arise. The allocator
    /// scans without any claim, then claims the candidate's sector and re-reads
    /// it: every write to that sector happens under the claim, so the re-read
    /// is current and the free entry it finds is really free. Nobody holds two
    /// claims, so there is no lock order and no deadlock. `chain_nth_or_extend`
    /// needs no wider hold: once the fresh cluster reads end-of-chain no scan
    /// can hand it out, so "allocate, then link" is safe as two claims.
    ///
    /// **History.** U09-2 introduced `FAT_MUTATE`, held for the whole scan-then-
    /// mark and the free walk; wave 15 (VF) made it a `Mutex` (as a `SpinLock`
    /// its device I/O ran preempt-off: 7.24 ms at `fat32_free_chain` on riscv64
    /// under `-icount`). As a `Mutex` it was held across the virtio-blk wait,
    /// so a priority-1 waiter donated its priority to a task waiting on the
    /// device and inherited disk latency (MUTEX survey, F1). The claim replaces
    /// it; durability and write order are unchanged (every write is still the
    /// same write-through `write_sector`, in the same order).
    ///
    /// The reset-path panic handler refuses to write while any claim is out
    /// ([`fat32_locks_available`]). Claims are taken only outside `SpinLock`s.
    ///
    /// Canaries put the old `FAT_MUTATE` back around the whole allocation, the
    /// extend branch's alloc-and-link and the whole free walk
    /// ([`FAT_MUTATE_CANARY`]): `fat-mutate-spin-canary` as a `SpinLock`
    /// (preempt-off across the I/O: the `lat: ... FAT spinlock canary` rows),
    /// `fat-mutate-pi-canary` as a `Mutex` (the VF shape: `[LAT] fat pi_io=`
    /// goes non-zero). `fat-sector-claim-canary` claims nothing
    /// (fs-tests' concurrent-mutator tests lose an update / double-allocate).
    fat_sector_busy: core::sync::atomic::AtomicU64,
    /// Bumped on every claim release; a waiter sleeps only while it is unchanged.
    fat_sector_gen: core::sync::atomic::AtomicU32,
    /// The task holding each slot's claim (`caller_tid`), 0 when free: a task
    /// that panics holding a claim must not be contained, because nobody would
    /// ever release it ([`fat32_claims_held_by`], the panic policy's check 4).
    fat_sector_owner: [core::sync::atomic::AtomicU32; 64],
    /// Updaters waiting for a claimed slot.
    fat_sector_wq: azos_sync::waitqueue::WaitQueue,
    /// One [`ClaimPi`] per FAT-sector claim slot.
    fat_sector_pi: [ClaimPi; 64],
    /// The task holding the write-back claim (`caller_tid`), 0 when free.
    wb_busy: core::sync::atomic::AtomicBool,
    wb_owner: core::sync::atomic::AtomicU32,
    wb_gen: core::sync::atomic::AtomicU32,
    wb_wq: azos_sync::waitqueue::WaitQueue,
    /// The write-back claim's donation state ([`ClaimPi`]).
    wb_pi: ClaimPi,
    /// The mode the next configure of the cache takes: `WB` until
    /// [`fat32_set_writeback`] changes it.
    wb_on: core::sync::atomic::AtomicBool,
    /// Sticky: a write-back no caller was waiting for (the task, a reader's)
    /// failed. The next `fat32_sync_checked` / `fat32_fsync` reports `Io` and
    /// clears it (Linux's errseq, reduced to one volume-wide bit).
    wb_error: core::sync::atomic::AtomicBool,
    /// `WB_CLOCK()` (milliseconds) when the cache went from clean to dirty;
    /// 0 while clean. The age the `fs-wb` task compares.
    wb_dirty_since: core::sync::atomic::AtomicU64,
    /// Last ticket asked for.
    flush_asked: core::sync::atomic::AtomicU64,
    /// Every ticket `<=` this is done.
    flush_done: core::sync::atomic::AtomicU64,
    /// Tickets `[FLUSH_FAIL_LO, FLUSH_FAIL_HI]` were covered by a failed flush
    /// (the union of every failure: an error is never lost, a ticket a later
    /// failure's range spans may read -EIO although its own flush succeeded).
    flush_fail_lo: core::sync::atomic::AtomicU64,
    flush_fail_hi: core::sync::atomic::AtomicU64,
    /// First sector of the mounted volume on the medium.
    vol_base: core::sync::atomic::AtomicU64,
    /// Bumped by every write of the volume — FAT32's own (`write_sector`), any
    /// other writer's (`fat32_on_medium_write`) — and by mount and unmount. A
    /// read-only stream remembers it with the start cluster it found at open
    /// (`Fat32Fs::read_handle`); while it is unchanged, nothing can have moved,
    /// freed or resized that chain, so the stream reads it without looking the
    /// name up again. Never 0, so a handle of 0 never matches.
    write_gen: core::sync::atomic::AtomicU32,
    /// The same events as [`WRITE_GEN`], counted in 64 bits so a value never
    /// comes back (wave 14, SPAWNCACHE): the verified-image cache stamps what it
    /// verified with it ([`Fat32Fs::content_stamp`]) and must never take a stamp
    /// from before a write for one after it. Bumped AFTER `WRITE_GEN`, and every
    /// bump comes after the write it reports has reached the device and the
    /// block cache: a reader that loads the epoch, reads, and loads the same
    /// epoch again read nothing a later bump reports.
    write_epoch: core::sync::atomic::AtomicU64,
    /// Sectors of the mounted volume (`tot_sec32`), `u64::MAX` while a mount is
    /// still reading its BPB. Bounds which medium writes touch the cache.
    vol_sectors: core::sync::atomic::AtomicU64,
    /// This mount wrote the dirty flag, so the unmount owes the clear.
    volume_marked_dirty: core::sync::atomic::AtomicBool,
    mount_report: SpinLock<MountReport>,
    /// `fat32_read_range`'s geometry, published by `fat32_mount`: sectors per
    /// cluster and data start (A), FAT start and the chain-walk bound (B). A
    /// stream reads it without taking `FAT32`; 0 before the first mount.
    stream_geom_a: core::sync::atomic::AtomicU64,
    stream_geom_b: core::sync::atomic::AtomicU64,
    /// A leaf lock, held for one probe (a hash and an 11-byte compare).
    dcache: SpinLock<[Dentry; DCACHE_SLOTS]>,
    /// [`fat32_alloc_cluster`] without the canaries' old lock, for the canary
    /// build of `chain_nth_or_extend`, which holds that lock itself.
    /// The FAT sector (relative to the FAT start) the last allocation found a
    /// free entry in; the next scan starts there. Reset at mount.
    alloc_hint: core::sync::atomic::AtomicU32,
    held: SpinLock<[HeldChain; HELD_SLOTS]>,
    /// Sum of the held chains' `clusters`: what statfs counts as free on top of
    /// the FAT's zero entries.
    held_clusters: core::sync::atomic::AtomicU32,
    /// The device has refused a discard (no such command, or no request layer
    /// under it): none is sent until the next mount.
    discard_off: core::sync::atomic::AtomicBool,
    open_files: SpinLock<[OpenFileEntry; FAT32_MAX_OPEN_FILES]>,
    /// Bumped by every FAT entry write and every mount.
    free_gen: core::sync::atomic::AtomicU32,
    /// `(generation << 32) | free clusters`; valid while the generation matches.
    free_cache: core::sync::atomic::AtomicU64,
}

impl Vol {
    /// A volume over `dev`, served as `fs`, caching its sectors in `cache`.
    pub const fn new(dev: &'static dyn VolDev, knobs: Knobs, fs: &'static Fat32Fs, cache: VolCache) -> Vol {
        Vol {
            dev,
            knobs,
            fs,
            sector_cache: cache,
            fat32: SpinLock::new(Fat32Vol::new()),
            fat_sector_busy: core::sync::atomic::AtomicU64::new(0),
            fat_sector_gen: core::sync::atomic::AtomicU32::new(0),
            fat_sector_owner: [const { core::sync::atomic::AtomicU32::new(0) }; 64],
            fat_sector_wq: azos_sync::waitqueue::WaitQueue::new(),
            fat_sector_pi: [const { ClaimPi::new() }; 64],
            wb_busy: core::sync::atomic::AtomicBool::new(false),
            wb_owner: core::sync::atomic::AtomicU32::new(0),
            wb_gen: core::sync::atomic::AtomicU32::new(0),
            wb_wq: azos_sync::waitqueue::WaitQueue::new(),
            wb_pi: ClaimPi::new(),
            wb_on: core::sync::atomic::AtomicBool::new(knobs.writeback),
            wb_error: core::sync::atomic::AtomicBool::new(false),
            wb_dirty_since: core::sync::atomic::AtomicU64::new(0),
            flush_asked: core::sync::atomic::AtomicU64::new(0),
            flush_done: core::sync::atomic::AtomicU64::new(0),
            flush_fail_lo: core::sync::atomic::AtomicU64::new(u64::MAX),
            flush_fail_hi: core::sync::atomic::AtomicU64::new(0),
            vol_base: core::sync::atomic::AtomicU64::new(0),
            write_gen: core::sync::atomic::AtomicU32::new(1),
            write_epoch: core::sync::atomic::AtomicU64::new(1),
            vol_sectors: core::sync::atomic::AtomicU64::new(u64::MAX),
            volume_marked_dirty: core::sync::atomic::AtomicBool::new(false),
            mount_report: SpinLock::new(MountReport::new()),
            stream_geom_a: core::sync::atomic::AtomicU64::new(0),
            stream_geom_b: core::sync::atomic::AtomicU64::new(0),
            dcache: SpinLock::new([NO_DENTRY; DCACHE_SLOTS]),
            alloc_hint: core::sync::atomic::AtomicU32::new(0),
            held: SpinLock::new([HeldChain { first: 0, clusters: 0, epoch: 0 }; HELD_SLOTS]),
            held_clusters: core::sync::atomic::AtomicU32::new(0),
            discard_off: core::sync::atomic::AtomicBool::new(false),
            open_files: SpinLock::new([EMPTY_OPEN_FILE; FAT32_MAX_OPEN_FILES]),
            free_gen: core::sync::atomic::AtomicU32::new(1),
            free_cache: core::sync::atomic::AtomicU64::new(0),
        }
    }
}

/// Kconfig `FAT32_SECTOR_CLAIM_SLOTS` (1..=64): bits of `Vol::fat_sector_busy` used.
const FAT_SECTOR_SLOTS: u32 = {
    let n = azos_limits::FAT32_SECTOR_CLAIM_SLOTS;
    assert!(n >= 1 && n <= 64, "FAT32_SECTOR_CLAIM_SLOTS must be 1..=64");
    n as u32
};
#[cfg(feature = "fat-mutate-spin-canary")]
static FAT_MUTATE_CANARY: SpinLock<()> = SpinLock::new(());
#[cfg(feature = "fat-mutate-pi-canary")]
static FAT_MUTATE_CANARY: azos_sync::kmutex::Mutex<()> = azos_sync::kmutex::Mutex::new(());

/// Priority donation from a claim waiter to the claim's owner (FX12), the
/// counted protocol `Mutex` uses, through the scheduler's
/// `donate_priority` / `return_donation` pair (its `donation_for` rule and
/// ring-3 floor; one counter, `donation_count`, shared with every donor).
///
/// * **Take:** the busy bit and the owner change together under `st`, so a
///   waiter that sees the claim taken sees who took it (the `Mutex`
///   `try_acquire` livelock: busy with no owner, nobody to donate to);
///   `epoch` counts acquisitions and `donations` starts at 0.
/// * **Wait:** before each sleep a waiter donates once per acquisition
///   (`epoch`) it observes, under `st`; a donation the scheduler made is
///   counted in `donations`.
/// * **Release:** under `st` the owner is cleared, the claim freed and the
///   count taken; the owner wakes its waiters and only then returns the
///   donations (`return_donation` once each), so it never runs unboosted
///   between the release and the wake.
/// * **Owner exit:** a task cannot exit holding a claim: the claim is RAII,
///   and a task that panics holding one is not contained
///   ([`fat32_claims_held_by`], the panic policy's check 4: reset). A slot
///   reused by a new task starts with `donation_count` 0 (`task_create`),
///   and `return_donation` to a TID that is gone is a no-op.
///
/// Lock order: claim `st` -> the owner's donation lock -> `CPU_LOCKS`, the
/// chain `Mutex::pi_state` takes. `st` is held for a few stores and the
/// boost, never across a sleep or device I/O; claims are task context only,
/// so it needs no interrupt masking. Without hooks (host tests, before
/// boot) a waiter only sleeps. The counted donation does the boost in both
/// `WAIT_GRAPH` modes: the graph's stage 1 does not boost a Fair donor
/// (`classes::pi_prio`: no weight inheritance), and claim waiters are never
/// RT, so an edge alone would lend `log-flush` (12, Fair) nothing. With
/// Kconfig `WAIT_GRAPH` y the waiter also takes an `EdgeKind::Claim` edge
/// (`st` being the object's lock) for the graph's bookkeeping: its
/// `blocked_on`, the cycle check, the owner-exit detach. The counted
/// donation can go once the graph inherits Fair priorities (stage 2).
///
/// Runtime canary `canary=claim-no-donate` ([`fat32_canary_claim_no_donate`]):
/// no waiter donates (ktest `fat_claim_waiter_donates_to_owner` goes red).
struct ClaimPi {
    st: SpinLock<()>,
    epoch: core::sync::atomic::AtomicU32,
    donations: core::sync::atomic::AtomicU32,
    /// The claim's wait-graph node (`EdgeKind::Claim`); `()` with `WAIT_GRAPH` n.
    node: azos_sync::waitgraph::DonorNode,
}

/// The scheduler side of [`ClaimPi`], registered by the kernel at boot
/// ([`fat32_claim_pi_hooks`]). This crate does not depend on the scheduler.
pub struct ClaimPiHooks {
    /// `scheduler::donate_priority(donor, owner)`: `true` = one
    /// `give_back(owner)` is owed.
    pub donate: fn(donor: u32, owner: u32) -> bool,
    /// `scheduler::return_donation(owner)`.
    pub give_back: fn(owner: u32),
    /// The wait-graph id (the scheduler slot) of a TID; read with `WAIT_GRAPH` y only.
    pub graph_id: fn(tid: u32) -> Option<azos_sync::waitgraph::TaskId>,
}

azos_common::ro_hook! {
    static CLAIM_PI_HOOKS: &'static ClaimPiHooks;
}

/// Install the claim donation hooks (kernel boot, once, before any task
/// takes a claim).
pub fn fat32_claim_pi_hooks(h: &'static ClaimPiHooks) {
    CLAIM_PI_HOOKS.set(h);
}

fn claim_pi_hooks() -> Option<&'static ClaimPiHooks> {
    CLAIM_PI_HOOKS.get()
}

static CANARY_CLAIM_NO_DONATE: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Arm `canary=claim-no-donate` (boot, once): claim waiters lend nothing.
pub fn fat32_canary_claim_no_donate() {
    CANARY_CLAIM_NO_DONATE.store(true, core::sync::atomic::Ordering::Relaxed);
}

/// What a waiter carries between its sleeps: the acquisition it donated to
/// (counted path) and its graph id while it sits in the wait graph (y).
#[derive(Clone, Copy, Default)]
struct ClaimWait {
    donated: Option<u32>,
    graph: Option<azos_sync::waitgraph::TaskId>,
}

impl ClaimPi {
    #[allow(clippy::declare_interior_mutable_const)]
    const fn new() -> Self {
        ClaimPi {
            st: SpinLock::new(()),
            epoch: core::sync::atomic::AtomicU32::new(0),
            donations: core::sync::atomic::AtomicU32::new(0),
            node: <azos_sync::waitgraph::NodeSel<{ azos_sync::waitgraph::ENABLED }>
                as azos_sync::waitgraph::SelectNode>::CLAIM,
        }
    }

    /// The claim's graph node, `None` with `WAIT_GRAPH` n.
    #[inline(always)]
    fn pi(&self) -> Option<&azos_sync::waitgraph::PiWaiters> {
        ClaimNode::pi(&self.node)
    }

    /// Take the claim if `take()` succeeds, recording `me` as its owner in
    /// the same section. A waiter in the graph leaves its edge here.
    fn try_take(&self, take: impl FnOnce() -> bool, owner: &core::sync::atomic::AtomicU32, me: u32, w: &mut ClaimWait) -> bool {
        use core::sync::atomic::Ordering::SeqCst;
        let _g = self.st.lock();
        if !take() {
            return false;
        }
        owner.store(me, SeqCst);
        self.epoch.fetch_add(1, SeqCst);
        self.donations.store(0, SeqCst);
        if let Some(n) = self.pi() {
            if let Some(id) = w.graph.take() {
                azos_sync::waitgraph::unblock(id, n, azos_sync::waitgraph::UnblockReason::Acquired);
            }
            n.set_owner(claim_pi_hooks().and_then(|h| (h.graph_id)(me)));
        }
        true
    }

    /// Before a sleep: lend `me`'s priority to the current owner, once per
    /// acquisition. With `WAIT_GRAPH` y the waiter also enters the graph
    /// behind the owner, once (the graph follows a change of owner itself).
    fn donate(&self, owner: &core::sync::atomic::AtomicU32, me: u32, w: &mut ClaimWait) {
        use core::sync::atomic::Ordering::SeqCst;
        if CANARY_CLAIM_NO_DONATE.load(core::sync::atomic::Ordering::Relaxed) {
            return;
        }
        if me == u32::MAX {
            return; // no scheduler yet: nobody to lend a priority
        }
        let Some(h) = claim_pi_hooks() else { return };
        if let (Some(n), None, Some(id)) = (self.pi(), w.graph, (h.graph_id)(me)) {
            let pending = {
                let _g = self.st.lock();
                let o = owner.load(SeqCst);
                if o == 0 || o == u32::MAX || o == me || n.owner().is_none() {
                    None
                } else {
                    azos_sync::waitgraph::block_prepare(id, n).ok()
                }
            };
            if let Some(p) = pending {
                if azos_sync::waitgraph::block_commit(p).is_ok() {
                    w.graph = Some(id);
                }
            }
        }
        let _g = self.st.lock();
        let o = owner.load(SeqCst);
        let e = self.epoch.load(SeqCst);
        if o == 0 || o == u32::MAX || o == me || w.donated == Some(e) {
            return;
        }
        if (h.donate)(me, o) {
            self.donations.fetch_add(1, SeqCst);
        }
        w.donated = Some(e);
    }

    /// Release: clear the owner and run `free` (the busy bit) under `st`;
    /// returns what [`ClaimPi::give_back`] owes, which the caller runs after
    /// waking the waiters.
    fn release(&self, owner: &core::sync::atomic::AtomicU32, free: impl FnOnce()) -> (u32, u32) {
        use core::sync::atomic::Ordering::SeqCst;
        let _g = self.st.lock();
        let o = owner.swap(0, SeqCst);
        if let Some(n) = self.pi() {
            if let Some(id) = n.owner() {
                let _ = azos_sync::waitgraph::release(id, n);
                n.set_owner(None);
            }
        }
        free();
        (o, self.donations.swap(0, SeqCst))
    }

    /// Return the donations [`ClaimPi::release`] took (`return_donation` once each).
    fn give_back(owed: (u32, u32)) {
        let (o, n) = owed;
        if o == 0 || o == u32::MAX || n == 0 {
            return;
        }
        if let Some(h) = claim_pi_hooks() {
            for _ in 0..n {
                (h.give_back)(o);
            }
        }
    }
}

/// [`ClaimPi::node`] as the graph sees it: `PiWaiters` (y) or nothing (n).
trait ClaimNode {
    fn pi(&self) -> Option<&azos_sync::waitgraph::PiWaiters>;
}

impl ClaimNode for azos_sync::waitgraph::PiWaiters {
    #[inline(always)]
    fn pi(&self) -> Option<&azos_sync::waitgraph::PiWaiters> {
        Some(self)
    }
}

impl ClaimNode for () {
    #[inline(always)]
    fn pi(&self) -> Option<&azos_sync::waitgraph::PiWaiters> {
        None
    }
}

/// A claim on one FAT sector's slot; released (published) on drop.
struct FatSectorClaim {
    v: &'static Vol,
    bit: u64,
    slot: usize,
    /// `fat-mutate-spin-canary`: see [`CanaryHold`].
    #[cfg(feature = "fat-mutate-spin-canary")]
    _hold: CanaryHold,
}

/// `fat-mutate-spin-canary` only: a claim (FAT sector, write-back) is held
/// with preemption off. The canary holds a `SpinLock` across paths that may
/// wait for a claim (an allocation's sector claims, a write that needs a
/// write-back first); a waiter with preemption off cannot sleep (K-C29
/// refuses the block and it retries), so a holder switched out on the
/// waiter's CPU would never run again to release it: on the lat rows' one
/// CPU, the `fs-wb` task preempted mid write-back hung the FAT writer and
/// the row printed no `[LAT]`. With preemption off for the claim, its
/// holder runs to the release. Production builds hold no `SpinLock` across
/// a claim wait (F1) and are unaffected.
#[cfg(feature = "fat-mutate-spin-canary")]
type CanaryHold = azos_sync::preempt::PreemptGuard;

#[cfg(feature = "fat-mutate-spin-canary")]
fn canary_hold() -> CanaryHold {
    azos_sync::preempt::critical_section()
}

/// Claim the slot of FAT sector `fat_sector_off` (relative to the FAT
/// start, so the same for every copy), sleeping while another updater holds it.
fn fat_sector_claim(v: &'static Vol, fat_sector_off: u32) -> FatSectorClaim {
    use core::sync::atomic::Ordering::SeqCst;
    let slot = (fat_sector_off % FAT_SECTOR_SLOTS) as usize;
    let bit = if cfg!(feature = "fat-sector-claim-canary") { 0 } else { 1u64 << slot };
    let me = azos_sync::waitqueue::caller_tid();
    let pi = &v.fat_sector_pi[slot];
    let mut w = ClaimWait::default();
    loop {
        // Read the generation BEFORE trying: a release between the failed
        // try and the sleep then changes it, and `wait_if` (which re-checks
        // under the queue's lock) does not sleep through that publish.
        let gen = v.fat_sector_gen.load(SeqCst);
        #[cfg(feature = "fat-mutate-spin-canary")]
        let hold = canary_hold();
        if pi.try_take(|| v.fat_sector_busy.fetch_or(bit, SeqCst) & bit == 0, &v.fat_sector_owner[slot], me, &mut w) {
            return FatSectorClaim {
                v,
                bit,
                slot,
                #[cfg(feature = "fat-mutate-spin-canary")]
                _hold: hold,
            };
        }
        #[cfg(feature = "fat-mutate-spin-canary")]
        drop(hold);
        pi.donate(&v.fat_sector_owner[slot], me, &mut w);
        v.fat_sector_wq.wait_if_for(azos_sync::waitstat::Site::FatSector, || v.fat_sector_gen.load(SeqCst) == gen);
    }
}

impl Drop for FatSectorClaim {
    fn drop(&mut self) {
        use core::sync::atomic::Ordering::SeqCst;
        let v = self.v;
        let bit = self.bit;
        let owed = v.fat_sector_pi[self.slot].release(&v.fat_sector_owner[self.slot], || {
            v.fat_sector_busy.fetch_and(!bit, SeqCst);
        });
        v.fat_sector_gen.fetch_add(1, SeqCst);
        v.fat_sector_wq.wake_all();
        ClaimPi::give_back(owed);
    }
}

/// [`fat32_claims_held_by_on`] on the boot volume ([`BOOT`]).
#[inline]
pub fn fat32_claims_held_by(tid: u32) -> u32 {
    fat32_claims_held_by_on(&BOOT, tid)
}

/// FAT-sector claims task `tid` holds (0 or 1: claims never nest). The panic
/// path adds it to the task's held `Mutex` count: a claim abandoned by a
/// contained task would block every later update of its FAT sectors.
pub fn fat32_claims_held_by_on(v: &'static Vol, tid: u32) -> u32 {
    use core::sync::atomic::Ordering::SeqCst;
    if tid == 0 { return 0; }
    v.fat_sector_owner.iter().filter(|o| o.load(SeqCst) == tid).count() as u32
        + (v.wb_owner.load(SeqCst) == tid) as u32
}

/// `fat-pi-io-probe` (the `lat-fat` smoke): FAT32 device I/O issued while
/// the issuing task held a `Mutex` — the F1 violation. Counted at the FAT32
/// layer, before `blkdev` takes its own `BLK_LOCK`. [`FAT_PI_IO`] counts every
/// task; [`FAT_PI_IO_WATCHED`] only the task [`fat32_pi_io_watch`] names (the
/// smoke's FAT writer, which holds no `Mutex` of its own: whatever it counts
/// was taken inside FAT32).
#[cfg(feature = "fat-pi-io-probe")]
static FAT_PI_IO: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
#[cfg(feature = "fat-pi-io-probe")]
static FAT_PI_IO_WATCHED: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
#[cfg(feature = "fat-pi-io-probe")]
static FAT_PI_IO_WATCH: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
/// The same probe for FAT32 device I/O issued with preemption off on the
/// issuing hart (a `SpinLock` or any other critical section held, or
/// interrupts masked): the device round trip then runs inside the
/// preempt-off window. A count, not a duration: how long that window lasts
/// in virtual time follows when the host completes the request (also under
/// `-icount`), how many requests it spans does not.
#[cfg(feature = "fat-pi-io-probe")]
static FAT_NOPREEMPT_IO: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
#[cfg(feature = "fat-pi-io-probe")]
static FAT_NOPREEMPT_IO_WATCHED: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

#[inline(always)]
fn pi_io_probe() {
    #[cfg(feature = "fat-pi-io-probe")]
    {
        use core::sync::atomic::Ordering::Relaxed;
        let tid = azos_sync::waitqueue::caller_tid();
        if azos_sync::held::held_by(tid) != 0 {
            FAT_PI_IO.fetch_add(1, Relaxed);
            if tid != 0 && tid == FAT_PI_IO_WATCH.load(Relaxed) {
                FAT_PI_IO_WATCHED.fetch_add(1, Relaxed);
            }
            pi_io_site_record(tid);
        }
        if azos_sync::preempt::disabled() || !azos_sync::preempt::irqs_enabled() {
            FAT_NOPREEMPT_IO.fetch_add(1, Relaxed);
            if tid != 0 && tid == FAT_PI_IO_WATCH.load(Relaxed) {
                FAT_NOPREEMPT_IO_WATCHED.fetch_add(1, Relaxed);
            }
        }
    }
}

/// Distinct (task, held `Mutex`es) seen by [`pi_io_probe`]: which lock
/// each F1 violation held. Packed (tid, outermost lock, innermost lock);
/// first come first kept, then only counted.
#[cfg(feature = "fat-pi-io-probe")]
const PI_IO_SITES: usize = azos_limits::FAT_PI_IO_SITES;
#[cfg(feature = "fat-pi-io-probe")]
static PI_IO_SITE: azos_sync::SpinLock<[(u32, usize, usize, u32); PI_IO_SITES]> =
    azos_sync::SpinLock::new([(0, 0, 0, 0); PI_IO_SITES]);

#[cfg(feature = "fat-pi-io-probe")]
fn pi_io_site_record(tid: u32) {
    let mut held = [0usize; 4];
    let n = azos_sync::held::held_addrs(tid, &mut held);
    let (outer, inner) = if n == 0 { (0, 0) } else { (held[0], held[n - 1]) };
    let mut t = PI_IO_SITE.lock();
    for e in t.iter_mut() {
        if e.3 != 0 && e.0 == tid && e.1 == outer && e.2 == inner { e.3 += 1; return; }
    }
    if let Some(e) = t.iter_mut().find(|e| e.3 == 0) { *e = (tid, outer, inner, 1); }
}

/// Every recorded F1 site: `f(tid, outermost lock, innermost lock, count)`.
#[cfg(feature = "fat-pi-io-probe")]
pub fn fat32_pi_io_sites(mut f: impl FnMut(u32, usize, usize, u32)) {
    let t = *PI_IO_SITE.lock();
    for e in t.iter().filter(|e| e.3 != 0) { f(e.0, e.1, e.2, e.3); }
}

/// Name the task whose PI-held FAT I/O [`fat32_pi_io_counts`] reports first.
#[cfg(feature = "fat-pi-io-probe")]
pub fn fat32_pi_io_watch(tid: u32) {
    FAT_PI_IO_WATCH.store(tid, core::sync::atomic::Ordering::Relaxed);
}

/// FAT32 device I/Os issued with a `Mutex` held: (by the watched task, by
/// any task). 0 for the watched FAT writer = F1 holds inside FAT32.
#[cfg(feature = "fat-pi-io-probe")]
pub fn fat32_pi_io_counts() -> (u32, u32) {
    use core::sync::atomic::Ordering::Relaxed;
    (FAT_PI_IO_WATCHED.load(Relaxed), FAT_PI_IO.load(Relaxed))
}

/// FAT32 device I/Os issued with preemption off: (by the watched task, by any
/// task). 0 for the watched FAT writer = no FAT update holds a spinning lock
/// across a device round trip.
#[cfg(feature = "fat-pi-io-probe")]
pub fn fat32_preempt_off_io_counts() -> (u32, u32) {
    use core::sync::atomic::Ordering::Relaxed;
    (FAT_NOPREEMPT_IO_WATCHED.load(Relaxed), FAT_NOPREEMPT_IO.load(Relaxed))
}

/// First data sector of `cluster`, or `None` if the whole cluster does not fit
/// in the u32 sector space.
///
/// Cluster values come from on-disk FAT entries / directory entries and are
/// only bounded by `FAT32_EOC` (~268M) before use, so `(cluster - 2) * spc`
/// (spc up to 128) overflows u32 easily on a crafted image. This used to
/// saturate, which merely moved the abort one line down: every caller then did
/// `read_sector(first_sector + s)` with a plain `+`, and with
/// `overflow-checks = true` and `panic = "abort"` that addition is a board
/// reset — a physical-safety event on a robot. Saturating also silently
/// aliased distinct clusters onto the same sector.
///
/// Returning `Option` fixes the class instead of one site. **The success case
/// guarantees `first_sector + spc` fits in u32**, so every caller may use a
/// plain `+` for `first_sector + s` with `s < spc` and be provably
/// overflow-free; `saturating_add` at those sites would be worse, silently
/// reading the *wrong* sector if the invariant ever broke.
///
/// Clusters below `FAT32_FIRST_DATA_CLUSTER` (0 and 1 are reserved, and 0 is
/// also the "empty file" marker) are rejected here rather than wrapping.
#[inline]
fn cluster_first_sector(data_start: u32, cluster: u32, spc: u32) -> Option<u32> {
    let first = cluster
        .checked_sub(FAT32_FIRST_DATA_CLUSTER)?
        .checked_mul(spc)?
        .checked_add(data_start)?;
    // Reject unless the *entire* cluster is addressable, so the caller's
    // `first_sector + s` loop (and `first_sector + sector_index`) cannot
    // overflow for any s < spc.
    first.checked_add(spc)?;
    Some(first)
}

/// Maximum number of clusters a single chain may visit before we declare the
/// volume corrupt.
///
/// FAT cluster chains are attacker-controlled: the volume is on a removable
/// card, so an adversary with physical access and a card reader can set
/// `FAT[2] = 2` and every naive `while cluster < EOC { cluster = next(cluster) }`
/// walker spins forever. Because the FAT sector is held in `SECTOR_CACHE`, that
/// spin does no I/O and never yields — it is a hard hang of whichever hart
/// serviced a ring-3 `open()`, not a slow path.
///
/// A chain cannot legitimately be longer than the number of entries the FAT
/// itself can hold (`fat_sz32` sectors × 128 entries per sector), so exceeding
/// that bound proves a cycle or a corrupt table. Saturating keeps a hostile
/// `fat_sz32` from wrapping the bound to something tiny.
#[inline]

fn chain_walk_limit(fat_sz32: u32, data_clusters: u32) -> u32 {
    // **Bounded by what the volume HAS, not by what its FAT could address.**
    // `fat_sz32 * 128` is how many entries the FAT has room for, and the
    // attacker writes `fat_sz32`; the number of clusters that exist comes
    // from `tot_sec32` at mount. Take the smaller — a chain cannot
    // legitimately visit a cluster the data region does not contain.
    //
    // `+ FAT32_FIRST_DATA_CLUSTER` because cluster numbering starts at 2, so
    // a volume with N data clusters has valid numbers 2..N+2.
    //
    // **This bound alone does not make a hang unreachable.** The comment here
    // used to say the `num_fats == 0` rejection did, because a `fat_sz32`
    // large enough to inflate the bound also pushes `data_start` large and
    // `cluster_first_sector` then fails. That holds only for `data_start` past
    // u32: with `num_fats = 1`, `fat_sz32 = 0xFFFFFF` and `tot_sec32 =
    // 0xFFFF_FFFF` on a 128 KiB medium, `data_start` fits, every data read
    // fails at the device, and a walker that skipped the unreadable sector and
    // followed a self-linked root (`FAT[2] = 2`, served from the cache) spun
    // ~2^31 steps (fuzz finding, wave 15; the input is
    // `regressions/fat32_image/root-self-link-volume-past-medium`). Three
    // guards close it, each on its own:
    //   * the mount refuses a `tot_sec32` larger than the medium (or its
    //     partition), so this bound counts clusters that exist on the device;
    //   * a sector read error ends every walk (no walker skips a sector and
    //     follows the chain on);
    //   * every walk runs under a [`ChainWalk`], whose cycle check stops a
    //     cyclic chain within about twice its length, whatever the bound.
    let by_fat = fat_sz32.saturating_mul(FAT32_ENTRIES_PER_SECTOR);
    let by_data = data_clusters.saturating_add(FAT32_FIRST_DATA_CLUSTER);
    by_fat.min(by_data)
}

/// One chain walk's guard: the [`chain_walk_limit`] step bound plus Brent's
/// cycle detection (wave 15, GR4).
///
/// A FAT chain never visits a cluster twice, so a repeat proves a cycle.
/// Brent's method finds one with one saved cluster and one compare per step:
/// the saved cluster moves to the current one at each power-of-two step, and
/// a cycle of length L entered after M steps is caught within about
/// `2 * (M + L)` steps — a `FAT[n] = n` self-link on the second visit —
/// instead of after `limit` steps, which on a large volume is millions of
/// cache-served lookups with no yield. No sizes or thresholds of its own:
/// the bound is the volume's, the detection is exact.
#[derive(Clone, Copy)]
struct ChainWalk {
    /// Visits left before the walk is declared corrupt.
    left: u32,
    /// Brent's saved cluster (`u32::MAX`, never a valid cluster, until the
    /// first visit).
    saved: u32,
    /// Steps between moves of `saved`, doubling.
    power: u32,
    /// Steps since `saved` last moved.
    lam: u32,
}

impl ChainWalk {
    #[inline]
    fn new(limit: u32) -> Self {
        ChainWalk { left: limit, saved: u32::MAX, power: 1, lam: 1 }
    }

    /// The walk for the mounted volume's geometry.
    #[inline]
    fn for_volume(fat_sz32: u32, data_clusters: u32) -> Self {
        Self::new(chain_walk_limit(fat_sz32, data_clusters))
    }

    /// Admit `cluster` as the walk's next visit. `false`: the bound is spent
    /// or `cluster` repeats an earlier visit (a cycle); the walk must stop.
    #[inline]
    fn visit(&mut self, cluster: u32) -> bool {
        if self.left == 0 { return false; }
        if cluster == self.saved && !cfg!(feature = "fat-walk-cycle-canary") { return false; }
        self.left -= 1;
        if self.power == self.lam {
            self.saved = cluster;
            self.power = self.power.saturating_mul(2);
            self.lam = 0;
        }
        self.lam += 1;
        true
    }
}

// ── Sector cache: the shared block cache, Kconfig FS_BLOCK_CACHE_KB ──────────
//
// FAT32 access patterns are heavily skewed: a single file read of N
// clusters causes the kernel to re-read the same FAT sector and the
// same directory sector dozens of times. Without this cache, every
// `vfs_read(1 byte)` paid a full VirtIO round-trip (~5 ms). With 8
// cache entries we hold the boot sector, the active FAT sector, the
// root-dir sector, and 5 hot data sectors — covers the common case of
// reading a small file under 4 KiB without ever hitting the device
// after the first miss.
//
// This is an instance of `crate::bcache::BlockCache`, the
// cache every filesystem in this crate shares, configured exactly as the
// private cache it replaced: 512 B blocks (one sector per block, block number
// = LBA), 8 lines, least-recently-used eviction, **write-through** — every
// write reaches the device before `write_sector` returns, a present line is
// updated, a write miss installs nothing, and no line is ever dirty. The
// journal barriers below therefore see every write already issued; the
// cache's write-back pass in `device_flush` is a no-op on this instance and is
// there so the ordering rule holds by construction if the mode ever changes.
// The cache lock is still released across the device read on a miss (the
// split `lookup`/`install` path), as it always was.
//
// Wave 14 (FATCACHE): the size is Kconfig `FS_BLOCK_CACHE_KB` (0 keeps the
// 8 x 512 B cache above), set-associative past 8 lines, and it now holds file
// DATA too: `fat32_read_chain`'s run reads fill it and are served from it, so
// a repeated open/read of a small file or a repeated spawn of the same image
// does not touch the device. Coherence with every writer of the medium that
// is not this file: `fat32_on_medium_write`, below. Still write-through: the
// device sees exactly the writes, in exactly the order, it saw before.
//
// The lock is a leaf: nothing is taken while it is held, and it is held for
// one line's copy (512 B) plus one set's probe (8 tags) at most. Whole-cache
// drops are a generation bump.

const SECTOR_CACHE_BYTES: usize = if azos_limits::FS_BLOCK_CACHE_KB == 0 {
    8 * SECTOR_SIZE
} else {
    azos_limits::FS_BLOCK_CACHE_KB * 1024
};
const SECTOR_CACHE_LINES: usize = SECTOR_CACHE_BYTES / SECTOR_SIZE;

/// The boot volume's sector cache (Kconfig `FS_BLOCK_CACHE_KB`).
pub type SectorCache = crate::bcache::BlockCache<SECTOR_CACHE_BYTES, SECTOR_CACHE_LINES>;

/// Kconfig `USB_VOLUME_CACHE_KB`: a removable volume's cache (0 keeps eight
/// lines, as for the boot volume).
const REMOVABLE_CACHE_BYTES: usize = if azos_limits::USB_VOLUME_CACHE_KB == 0 {
    8 * SECTOR_SIZE
} else {
    azos_limits::USB_VOLUME_CACHE_KB * 1024
};

/// A removable volume's sector cache (Kconfig `USB_VOLUME_CACHE_KB`): the
/// same cache code over storage of its own size.
pub type RemovableCache = crate::bcache::BlockCache<REMOVABLE_CACHE_BYTES, { REMOVABLE_CACHE_BYTES / SECTOR_SIZE }>;

pub use vol_cache::VolCache;

/// A volume's sector cache, whichever of the two sizes it has: the lock and
/// the operations, which run the one copy of `bcache`'s code over the
/// storage (`CacheMut`, `CacheRef`).
mod vol_cache {
    use super::{RemovableCache, SectorCache};
    use crate::bcache::{BlockIo, CacheMut, CacheRef, CacheStats, ConfigError, Dirty, IoError, Mode, Run};
    use azos_sync::{SpinLock, SpinLockGuard};

    /// Where a volume's sector cache is.
    #[derive(Clone, Copy)]
    pub enum VolCache {
        /// `FS_BLOCK_CACHE_KB` of storage (the boot disk).
        Boot(&'static SpinLock<SectorCache>),
        /// `USB_VOLUME_CACHE_KB` of storage (a removable volume).
        Removable(&'static SpinLock<RemovableCache>),
    }

    /// A volume's sector cache, locked.
    pub enum CacheGuard<'a> {
        Boot(SpinLockGuard<'a, SectorCache>),
        Removable(SpinLockGuard<'a, RemovableCache>),
    }

    impl VolCache {
        #[inline]
        pub fn lock(&self) -> CacheGuard<'static> {
            match *self {
                VolCache::Boot(l) => CacheGuard::Boot(l.lock()),
                VolCache::Removable(l) => CacheGuard::Removable(l.lock()),
            }
        }
        #[inline]
        pub fn try_lock(&self) -> Option<CacheGuard<'static>> {
            match *self {
                VolCache::Boot(l) => l.try_lock().map(CacheGuard::Boot),
                VolCache::Removable(l) => l.try_lock().map(CacheGuard::Removable),
            }
        }
    }

    impl CacheGuard<'_> {
        #[inline]
        pub fn view(&mut self) -> CacheMut<'_> {
            match self {
                CacheGuard::Boot(g) => g.view(),
                CacheGuard::Removable(g) => g.view(),
            }
        }
        #[inline]
        pub fn get(&self) -> CacheRef<'_> {
            match self {
                CacheGuard::Boot(g) => g.get(),
                CacheGuard::Removable(g) => g.get(),
            }
        }

    #[inline]
    pub fn block_size(&self) -> usize { self.get().block_size() }
    #[inline]
    pub fn line_count(&self) -> usize { self.get().line_count() }
    #[inline]
    pub fn ways(&self) -> usize { self.get().ways() }
    #[inline]
    pub fn mode(&self) -> Mode { self.get().mode() }
    #[inline]
    pub fn stats(&self) -> CacheStats { self.get().stats() }
    #[inline]
    pub fn epoch(&self) -> u64 { self.get().epoch() }
    #[inline]
    pub fn top_epoch(&self) -> u64 { self.get().top_epoch() }
    #[inline]
    pub fn dirty_count(&self) -> usize { self.get().dirty_count() }
    #[cfg(test)]
    #[inline]
    pub fn dirty_scan(&self) -> usize { self.get().dirty_scan() }
    #[inline]
    pub fn oldest_dirty_epoch(&self) -> Option<u64> { self.get().oldest_dirty_epoch() }
    #[inline]
    pub fn dirty_epochs(&self) -> usize { self.get().dirty_epochs() }
    #[inline]
    pub fn lba_of(&self, block: u64) -> Option<u64> { self.get().lba_of(block) }
    #[inline]
    pub fn peek(&self, block: u64, dst: &mut [u8]) -> bool { self.get().peek(block, dst) }
    #[inline]
    pub fn any_dirty_in(&self, first: u64, count: u64) -> bool { self.get().any_dirty_in(first, count) }
    #[inline]
    pub fn lookup_miss_token(&self) -> u64 { self.get().lookup_miss_token() }
    #[inline]
    pub fn configure(&mut self, block: usize, mode: Mode, base_lba: u64) -> Result<(), ConfigError> { self.view().configure(block, mode, base_lba) }
    #[inline]
    pub fn reset_stats(&mut self) { self.view().reset_stats() }
    #[inline]
    pub fn lookup(&mut self, block: u64, dst: &mut [u8]) -> bool { self.view().lookup(block, dst) }
    #[inline]
    pub fn lookup_bytes(&mut self, block: u64, offset: usize, dst: &mut [u8]) -> bool { self.view().lookup_bytes(block, offset, dst) }
    #[inline]
    pub fn install(&mut self, block: u64, src: &[u8], token: u64) -> bool { self.view().install(block, src, token) }
    #[inline]
    pub fn update_if_present(&mut self, block: u64, src: &[u8]) { self.view().update_if_present(block, src) }
    #[inline]
    pub fn invalidate(&mut self, block: u64) -> bool { self.view().invalidate(block) }
    #[inline]
    pub fn invalidate_range(&mut self, first: u64, count: u64) -> usize { self.view().invalidate_range(first, count) }
    #[inline]
    pub fn invalidate_all(&mut self) -> usize { self.view().invalidate_all() }
    #[cfg(test)]
    #[inline]
    pub fn force_generation(&mut self, g: u32) { self.view().force_generation(g) }
    #[inline]
    pub fn read<D: BlockIo>(&mut self, dev: &mut D, block: u64, dst: &mut [u8]) -> Result<(), IoError<D::FlushErr>> { self.view().read(dev, block, dst) }
    #[inline]
    pub fn write<D: BlockIo>(&mut self, dev: &mut D, block: u64, src: &[u8]) -> Result<(), IoError<D::FlushErr>> { self.view().write(dev, block, src) }
    #[inline]
    pub fn write_dirty(&mut self, block: u64, src: &[u8]) -> Dirty { self.view().write_dirty(block, src) }
    #[inline]
    pub fn write_dirty_ahead(&mut self, block: u64, src: &[u8]) -> Dirty { self.view().write_dirty_ahead(block, src) }
    #[inline]
    pub fn checkout_run(&mut self, upto: u64, max_blocks: usize, buf: &mut [u8]) -> Option<Run> { self.view().checkout_run(upto, max_blocks, buf) }
    #[inline]
    pub fn checkout_begin(&mut self, upto: u64, max_blocks: usize, buf_len: usize) -> Option<Run> { self.view().checkout_begin(upto, max_blocks, buf_len) }
    #[inline]
    pub fn checkout_next(&mut self, run: &mut Run, buf: &mut [u8]) -> bool { self.view().checkout_next(run, buf) }
    #[inline]
    pub fn checkin(&mut self, run: &Run, ok: bool) { self.view().checkin(run, ok) }
    #[inline]
    pub fn note_ordering_flush(&mut self) { self.view().note_ordering_flush() }
    #[inline]
    pub fn barrier(&mut self) -> u64 { self.view().barrier() }
    #[inline]
    pub fn write_back_all<D: BlockIo>(&mut self, dev: &mut D) -> Result<(), IoError<D::FlushErr>> { self.view().write_back_all(dev) }
    #[inline]
    pub fn sync<D: BlockIo>(&mut self, dev: &mut D) -> Result<(), IoError<D::FlushErr>> { self.view().sync(dev) }
    #[inline]
    pub fn note_flushed(&mut self) { self.view().note_flushed() }
    }
}

/// All-zero until the first mount configures it (`fat32_cache_reset`), so
/// the storage is `.bss`, not image bytes.
static BOOT_CACHE: SpinLock<SectorCache> = SpinLock::new(SectorCache::unconfigured());

/// A volume's device, as the shared cache sees it.
struct BlkDev(&'static Vol);

impl crate::bcache::BlockIo for BlkDev {
    type FlushErr = FsError;
    fn read(&mut self, lba: u64, count: u32, buf: &mut [u8]) -> Result<(), ()> {
        let v = self.0;
        v.dev.read_quiet(dev_lba(v, lba), count, buf)
    }
    fn write(&mut self, lba: u64, count: u32, buf: &[u8]) -> Result<(), ()> {
        let v = self.0;
        // Quiet: this runs with `SECTOR_CACHE` held (`device_flush`'s
        // write-back pass), and the observer takes it.
        v.dev.write_quiet(dev_lba(v, lba), count, buf)
    }
    fn flush(&mut self) -> Result<(), FsError> {
        device_flush_raw(self.0)
    }
    fn write_ordered(&mut self, lba: u64, count: u32, buf: &[u8], preflush: bool)
        -> Result<(), crate::bcache::IoError<FsError>>
    {
        let v = self.0;
        // Quiet, like `write`; the epoch flush rides in the request.
        v.dev.write_run(dev_lba(v, lba), count, buf, preflush, false).map_err(|()| crate::bcache::IoError::Io)
    }
}

// ── Write-back (wave 15, WRITEBACK) ─────────────────────────────────────────
//
// Kconfig `FS_WRITEBACK`: the cache above runs in `Mode::WriteBack`. A
// `write_sector` dirties a line (`BlockCache::write_dirty`) and returns; the
// device sees the dirty lines later, oldest epoch first, as coalesced
// multi-sector runs (`wb_write_back`), from one of:
//
// * `device_flush` — every journal barrier, `fat32_fsync`, `fat32_sync*`,
//   and `fat32_write_file`'s final flush: everything dirty goes out, then a
//   device flush. Every durability point of the write-through design is a
//   `device_flush`, so each still returns only once its writes are durable.
// * the `fs-wb` task (`fat32_writeback_tick`): by age
//   (`FS_WRITEBACK_MAX_AGE_MS`) and dirty-line watermark.
// * a writer whose block's line holds an older epoch, or whose set has no
//   clean line (`Dirty::NeedWriteback`): it writes back through that epoch
//   itself, then retries.
// * a reader of the medium that is not this file (`blkdev::read`'s
//   observer, `fat32_before_medium_read`): dirty lines in its range go out
//   first, so it never reads a stale sector.
//
// Ordering. `device_flush` closes the cache's epoch, so the epochs are the
// intervals between this file's flushes. Within one, the device may persist
// any subset of the writes even with write-through (a volatile write cache
// confirms a write it may still lose); across them, `checkout_run` puts a
// flush between the last write of one epoch and the first of the next. A
// cut therefore leaves a state the write-through design could leave too:
// crash consistency is unchanged, and the journal's recovery covers it
// (`tests/host/fs-tests` `writeback`: every cut of every epoch).
//
// No lock across the device (owner rule F1): runs are copied out under
// `SECTOR_CACHE` into `WB_STAGE` and written with it released. One flusher
// at a time (`WB_OWNER`, a claim like the FAT-sector ones: a sleeping wait,
// never a spinlock across I/O): a second one could put an epoch-`e` block on
// the wire while an older one was still in flight, which no flush orders.
// Lock order: FAT-sector claim -> write-back claim -> `SECTOR_CACHE`.

/// Kconfig `FS_WRITEBACK` (the boot volume; a removable one is write-through).
const WB: bool = dev::WRITEBACK;

/// Sectors in one coalesced write-back request (Kconfig `FS_WRITEBACK_RUN_KB`).
const WB_RUN_SECTORS: usize = if WB {
    let n = azos_limits::FS_WRITEBACK_RUN_KB * 1024 / SECTOR_SIZE;
    if n == 0 { 1 } else { n }
} else {
    1
};

/// The staging buffer a run is copied into; only the write-back claim's
/// holder touches it.
struct WbStage(core::cell::UnsafeCell<[u8; WB_RUN_SECTORS * SECTOR_SIZE]>);
// SAFETY: accessed only by the holder of the write-back claim (`WbClaim`).
unsafe impl Sync for WbStage {}
static WB_STAGE: WbStage = WbStage(core::cell::UnsafeCell::new([0u8; WB_RUN_SECTORS * SECTOR_SIZE]));

azos_common::ro_hook! {
    /// Milliseconds, registered by the kernel (`fat32_writeback_hooks`); unset
    /// until then (host tests: age is driven through `fat32_writeback_tick`).
    static WB_CLOCK: fn() -> u64;
}
azos_common::ro_hook! {
    /// Wakes the `fs-wb` task (watermark crossed); unset = none.
    static WB_WAKE: fn();
}

/// Register the kernel's clock (milliseconds) and the `fs-wb` task's waker.
pub fn fat32_writeback_hooks(clock_ms: fn() -> u64, wake: fn()) {
    WB_CLOCK.set(clock_ms);
    WB_WAKE.set(wake);
}

fn wb_now_ms() -> u64 {
    match WB_CLOCK.get() {
        Some(f) => f().max(1),
        None => 1,
    }
}

fn wb_wake() {
    if let Some(f) = WB_WAKE.get() {
        f();
    }
}

/// The write-back claim; released on drop.
struct WbClaim {
    v: &'static Vol,
    /// `fat-mutate-spin-canary`: see [`CanaryHold`].
    #[cfg(feature = "fat-mutate-spin-canary")]
    _hold: CanaryHold,
}

/// Take the write-back claim, sleeping while another flusher holds it.
/// Never called with a `SpinLock` held; never nested.
fn wb_claim(v: &'static Vol) -> WbClaim {
    use core::sync::atomic::Ordering::SeqCst;
    let me = azos_sync::waitqueue::caller_tid();
    let mut w = ClaimWait::default();
    loop {
        let gen = v.wb_gen.load(SeqCst);
        #[cfg(feature = "fat-mutate-spin-canary")]
        let hold = canary_hold();
        if v.wb_pi.try_take(|| !v.wb_busy.swap(true, SeqCst), &v.wb_owner, me, &mut w) {
            return WbClaim {
                v,
                #[cfg(feature = "fat-mutate-spin-canary")]
                _hold: hold,
            };
        }
        #[cfg(feature = "fat-mutate-spin-canary")]
        drop(hold);
        v.wb_pi.donate(&v.wb_owner, me, &mut w);
        v.wb_wq.wait_if_for(azos_sync::waitstat::Site::FatWriteback, || v.wb_gen.load(SeqCst) == gen);
    }
}

impl Drop for WbClaim {
    fn drop(&mut self) {
        use core::sync::atomic::Ordering::SeqCst;
        let v = self.v;
        let owed = v.wb_pi.release(&v.wb_owner, || v.wb_busy.store(false, SeqCst));
        v.wb_gen.fetch_add(1, SeqCst);
        v.wb_wq.wake_all();
        ClaimPi::give_back(owed);
    }
}

/// [`fat32_wb_pass_here_on`] on the boot volume ([`BOOT`]).
#[inline]
pub fn fat32_wb_pass_here() -> bool {
    fat32_wb_pass_here_on(&BOOT)
}

/// Is the calling task inside a write-back pass (does it hold the write-back
/// claim)? Every pass writes the dirty lines oldest epoch first, so a record
/// waiting in the cache goes out with it: the block request layer's real-time
/// class (Kconfig `BLK_IOSCHED_RT_DEADLINE`) asks this, with the flight
/// recorder's pending record, of the `fs-wb` task and of any task that runs a
/// pass (an fsync, a sync) while the record waits.
pub fn fat32_wb_pass_here_on(v: &'static Vol) -> bool {
    use core::sync::atomic::Ordering::SeqCst;
    v.knobs.writeback && v.wb_busy.load(SeqCst) && v.wb_owner.load(SeqCst) == azos_sync::waitqueue::caller_tid()
}

/// ktest `fat_claim_waiter_donates_to_owner` (FX12): run `f` holding the
/// write-back claim, taken as any flusher takes it (waiting, and lending
/// its priority to the holder, when another task holds it).
#[cfg(feature = "ktest")]
pub fn fat32_ktest_with_wb_claim(f: impl FnOnce()) {
    let c = wb_claim();
    f();
    drop(c);
}

/// Write back every dirty line of an epoch `<= upto`, oldest epoch first, as
/// coalesced runs, `SECTOR_CACHE` released across each device request. A
/// run of a later epoch than one already written since the last flush is
/// preceded by a device flush (the epoch rule; `Unsupported` passes, as in
/// `fat32_fsync`'s ordering flush: such a device gives no ordering to keep).
/// On a failed write the run stays dirty, nothing later is written, and the
/// error is returned.
fn wb_write_back(v: &'static Vol, _claim: &WbClaim, upto: u64, commit: bool) -> Result<bool, FsError> {
    let mut committed = false;
    loop {
        // SAFETY: the claim makes this task the stage's only user.
        let stage = unsafe { &mut *WB_STAGE.0.get() };
        // `SECTOR_CACHE` is a spinlock (preemption off): it is taken for the
        // pick (one tag scan) and then for each block's copy, never across
        // the whole run (up to FS_WRITEBACK_RUN_KB). A block written in
        // between is copied as it is now and stays dirty at the checkin.
        let run = v.sector_cache.lock().checkout_begin(upto, WB_RUN_SECTORS, stage.len());
        let run = run.map(|mut run| {
            while v.sector_cache.lock().checkout_next(&mut run, stage) {}
            run
        });
        // The first block's line went (written or moved) before its copy:
        // nothing was taken, pick again.
        if run.is_some_and(|r| r.blocks == 0) {
            continue;
        }
        let Some(run) = run else {
            if v.sector_cache.lock().dirty_count() == 0 {
                v.wb_dirty_since.store(0, core::sync::atomic::Ordering::Relaxed);
            }
            return Ok(committed);
        };
        pi_io_probe();
        let bytes = run.sectors as usize * SECTOR_SIZE;
        // The commit run (Kconfig `BLK_FUA`, a device whose FUA is native):
        // the run that leaves no dirty line behind carries PREFLUSH | FUA, so
        // every write that completed before it started is durable first and
        // the run is stable when it completes: the explicit flush an fsync
        // ends with has nothing left to do. The dirty counter still counts this
        // run's own lines (they are cleaned at the checkin below), so equal
        // means no other line is dirty, of any epoch.
        let last = commit
            && v.dev.fua_commit()
            && v.sector_cache.lock().dirty_count() == run.blocks as usize;
        // One request: the flush the epoch rule asks for (`flush_first`) goes
        // out ahead of the data with no round trip to this task between them
        // (`Unsupported`, a device with nothing to flush, passes as before).
        let r = v.dev.write_run(
            dev_lba(v, run.lba), run.sectors, &stage[..bytes], run.flush_first || last, last);
        if r.is_ok() && run.flush_first {
            v.sector_cache.lock().note_ordering_flush();
        }
        v.sector_cache.lock().checkin(&run, r.is_ok());
        if r.is_err() {
            return Err(FsError::Io);
        }
        // A later run (a line dirtied meanwhile in an epoch the pass covers)
        // is written after this one, and ends the commit instead.
        committed = last;
    }
}

/// [`fat32_writeback_tick_on`] on the boot volume ([`BOOT`]).
#[inline]
pub fn fat32_writeback_tick(now_ms: u64) -> bool {
    fat32_writeback_tick_on(&BOOT, now_ms)
}

/// The `fs-wb` task's pass at `now_ms`: write everything back and flush when
/// the oldest unsynced write is `FS_WRITEBACK_MAX_AGE_MS` old or the dirty
/// share reached `FS_WRITEBACK_WATERMARK_PCT`. Returns whether it wrote. A
/// failure is kept for the next fsync/sync (`WB_ERROR`).
pub fn fat32_writeback_tick_on(v: &'static Vol, now_ms: u64) -> bool {
    use core::sync::atomic::Ordering::Relaxed;
    // The page cache's pass first (storage L11): files whose oldest dirty
    // page is old, or the oldest ones over the dirty share, go to `write_at`
    // and so into the block cache below.
    // A file it could not write back is kept for the next fsync or sync
    // (`vfs::page_cache_flush_fs`), not for the block cache's error flag.
    let paged = crate::vfs::page_cache_writeback_due(now_ms);
    if !v.knobs.writeback { return paged; }
    let (dirty, lines) = {
        let c = v.sector_cache.lock();
        (c.dirty_count(), c.line_count())
    };
    if dirty == 0 { return paged; }
    let since = v.wb_dirty_since.load(Relaxed);
    // Pages this pass wrote were old enough to be written: their lines do
    // not wait another age to reach the device.
    let aged = paged || (since != 0
        && now_ms.saturating_sub(since) >= azos_limits::FS_WRITEBACK_MAX_AGE_MS as u64);
    if !aged && !wb_over_watermark(dirty, lines) { return paged; }
    if device_flush(v).is_err() {
        v.wb_error.store(true, Relaxed);
    }
    true
}

// ── Flush tickets (io_ring `OP_FSYNC`, K1) ────────────────────────────────
//
// An asynchronous fsync: the asker takes a ticket and wakes the `fs-wb` task;
// the task runs `fat32_sync_checked` (journal settle, write back every epoch,
// device flush) and marks every ticket asked before the sync began done. A
// write made before a ticket was taken is in that ticket's flush: the task
// reads the asked count BEFORE it syncs. Never waits in the asker: an RT
// submitter only enqueues. With no `fs-wb` task (FS_WRITEBACK=n, or before it
// runs) the asker syncs inline, as write-through writes wait anyway.

/// One flush on behalf of every ticket in `(done, upto]`.
fn flush_for_tickets(v: &'static Vol, upto: u64) {
    use core::sync::atomic::Ordering::SeqCst;
    let from = v.flush_done.load(SeqCst) + 1;
    // No volume mounted: nothing of FAT32's to flush (a RAM descriptor's
    // fsync is 0, as the synchronous call answers), not a failure.
    if matches!(fat32_sync_checked_on(v), Err(e) if e != FsError::NotMounted) {
        v.flush_fail_lo.fetch_min(from, SeqCst);
        v.flush_fail_hi.fetch_max(upto, SeqCst);
    }
    v.flush_done.fetch_max(upto, SeqCst);
}

/// [`fat32_flush_request_on`] on the boot volume ([`BOOT`]).
#[inline]
pub fn fat32_flush_request() -> u64 {
    fat32_flush_request_on(&BOOT)
}

/// Ask for a flush of every write made so far; answers the ticket to wait
/// for with [`fat32_flush_done`]. Wakes the `fs-wb` task and returns; with no
/// task to wake, flushes inline (write-through mode).
pub fn fat32_flush_request_on(v: &'static Vol) -> u64 {
    use core::sync::atomic::Ordering::SeqCst;
    let t = v.flush_asked.fetch_add(1, SeqCst) + 1;
    if v.knobs.writeback && WB_WAKE.is_set() {
        wb_wake();
    } else {
        flush_for_tickets(v, t);
    }
    t
}

/// [`fat32_flush_done_on`] on the boot volume ([`BOOT`]).
#[inline]
pub fn fat32_flush_done(t: u64) -> Option<Result<(), FsError>> {
    fat32_flush_done_on(&BOOT, t)
}

/// `None` while ticket `t`'s flush runs; `Some(Ok)` once durable,
/// `Some(Err(Io))` when a flush covering it failed.
pub fn fat32_flush_done_on(v: &'static Vol, t: u64) -> Option<Result<(), FsError>> {
    use core::sync::atomic::Ordering::SeqCst;
    if v.flush_done.load(SeqCst) < t { return None; }
    if v.flush_fail_lo.load(SeqCst) <= t && t <= v.flush_fail_hi.load(SeqCst) {
        Some(Err(FsError::Io))
    } else {
        Some(Ok(()))
    }
}

/// [`fat32_flush_service_on`] on the boot volume ([`BOOT`]).
#[inline]
pub fn fat32_flush_service() -> bool {
    fat32_flush_service_on(&BOOT)
}

/// The `fs-wb` task's half: run one flush for every ticket asked so far.
/// Returns whether it ran one (the caller then posts the completions).
pub fn fat32_flush_service_on(v: &'static Vol) -> bool {
    use core::sync::atomic::Ordering::SeqCst;
    let upto = v.flush_asked.load(SeqCst);
    if upto <= v.flush_done.load(SeqCst) { return false; }
    flush_for_tickets(v, upto);
    true
}

/// [`fat32_writeback_now_on`] on the boot volume ([`BOOT`]).
#[inline]
pub fn fat32_writeback_now() -> Result<(), FsError> {
    fat32_writeback_now_on(&BOOT)
}

/// Write every queued write back and flush the device now (what `sync`
/// does without settling the journal). A no-op flush under write-through.
pub fn fat32_writeback_now_on(v: &'static Vol) -> Result<(), FsError> {
    device_flush(v)
}

/// The `fs-wb` task's wait between passes: a quarter of the age bound.
pub fn fat32_writeback_period_ms() -> u64 {
    (azos_limits::FS_WRITEBACK_MAX_AGE_MS as u64 / 4).max(1)
}

/// [`fat32_writeback_dirty_on`] on the boot volume ([`BOOT`]).
#[inline]
pub fn fat32_writeback_dirty() -> (usize, usize) {
    fat32_writeback_dirty_on(&BOOT)
}

/// Dirty lines and lines in the FAT32 cache (diagnostics, the `fs-wb` rows).
pub fn fat32_writeback_dirty_on(v: &'static Vol) -> (usize, usize) {
    let c = v.sector_cache.lock();
    (c.dirty_count(), c.line_count())
}

fn wb_over_watermark(dirty: usize, lines: usize) -> bool {
    dirty * 100 >= lines * azos_limits::FS_WRITEBACK_WATERMARK_PCT as usize
}

/// [`fat32_before_medium_read_on`] on the boot volume ([`BOOT`]).
#[inline]
pub fn fat32_before_medium_read(lba: u64, count: u32) {
    fat32_before_medium_read_on(&BOOT, lba, count)
}

/// `blkdev::read`'s observer: a reader that is not this file is about to
/// read MEDIUM sectors `[lba, lba + count)`. Dirty lines in that range go to
/// the device first (all of them, oldest epoch first: a partial write-back
/// could not keep the epoch rule). Called with no FAT32 lock held.
pub fn fat32_before_medium_read_on(v: &'static Vol, lba: u64, count: u32) {
    use core::sync::atomic::Ordering::Relaxed;
    if !v.knobs.writeback || cfg!(feature = "wb-read-observer-canary") { return; }
    if !fat32_medium_read_would_wait_on(v, lba, count) { return; }
    let claim = wb_claim(v);
    if wb_write_back(v, &claim, u64::MAX, false).is_err() {
        v.wb_error.store(true, Relaxed);
    }
}

/// [`fat32_medium_read_would_wait_on`] on the boot volume ([`BOOT`]).
#[inline]
pub fn fat32_medium_read_would_wait(lba: u64, count: u32) -> bool {
    fat32_medium_read_would_wait_on(&BOOT, lba, count)
}

/// Does the cache hold a dirty sector in medium range `[lba, lba + count)`?
/// Then [`fat32_before_medium_read`] writes it back, waiting for the device. The
/// cache's leaf lock only; waits for nothing.
pub fn fat32_medium_read_would_wait_on(v: &'static Vol, lba: u64, count: u32) -> bool {
    use core::sync::atomic::Ordering::Relaxed;
    if !v.knobs.writeback { return false; }
    let base = v.vol_base.load(Relaxed);
    let end = base.saturating_add(v.vol_sectors.load(Relaxed));
    let first = lba.max(base);
    let last = lba.saturating_add(count as u64).min(end);
    count != 0 && first < last && v.sector_cache.lock().any_dirty_in(first - base, last - first)
}

/// [`fat32_set_writeback_on`] on the boot volume ([`BOOT`]).
#[inline]
pub fn fat32_set_writeback(on: bool) -> Result<(), FsError> {
    fat32_set_writeback_on(&BOOT, on)
}

/// Switch the FAT32 cache between write-back and write-through at run time
/// (host tests; a kernel canary). Writes every dirty line back first.
pub fn fat32_set_writeback_on(v: &'static Vol, on: bool) -> Result<(), FsError> {
    if on && !v.knobs.writeback { return Err(FsError::Unsupported); }
    v.wb_on.store(on, core::sync::atomic::Ordering::Relaxed);
    let claim = wb_claim(v);
    wb_write_back(v, &claim, u64::MAX, false)?;
    let mut c = v.sector_cache.lock();
    if c.line_count() == 0 { return Ok(()); }
    let mode = if on { crate::bcache::Mode::WriteBack } else { crate::bcache::Mode::WriteThrough };
    c.configure(SECTOR_SIZE, mode, 0).map_err(|_| FsError::Io)
}

// ── Where the volume starts on the medium ────────────────────────────────────
//
// Every sector number in this file is VOLUME-relative: sector 0 is the boot
// sector, the cache is keyed by it, and the journal, FAT and data offsets are
// all counted from it. `dev_lba` is the one place the volume's first sector on
// the medium is added, right before the block device is called.
//
// On a bare `mkfs.fat` medium (every QEMU image but the partitioned one) the
// base is 0 and nothing changes. On a partitioned medium `fat32_mount` picks
// the first partition of the table the kernel PUBLISHED at boot
// (`azos_drv_block::partition`) whose first sector is a valid FAT32 boot
// sector no larger than the partition — never the BPB's own `hidd_sec`, which
// is a field on the attacker-writable medium. A volume found there cannot
// address a sector past its partition through its own geometry: `tot_sec32`
// bounds every cluster walk, and the mount refuses a `tot_sec32` larger than
// the partition.

fn write_gen_bump(v: &'static Vol) {
    use core::sync::atomic::Ordering::AcqRel;
    if cfg!(feature = "write-gen-canary") { return; }
    if v.write_gen.fetch_add(1, AcqRel) == u32::MAX {
        // Wrapped to 0: step past it (a stale handle would need 2^32 writes
        // in between to alias, and still only to the same name's lookup).
        v.write_gen.fetch_add(1, AcqRel);
    }
    if cfg!(feature = "write-epoch-canary") { return; }
    v.write_epoch.fetch_add(1, AcqRel);
}

/// [`fat32_write_epoch_on`] on the boot volume ([`BOOT`]).
#[inline]
pub fn fat32_write_epoch() -> u64 {
    fat32_write_epoch_on(&BOOT)
}

/// The volume's write epoch (see `Vol::write_epoch`).
pub fn fat32_write_epoch_on(v: &'static Vol) -> u64 {
    v.write_epoch.load(core::sync::atomic::Ordering::Acquire)
}

/// The medium sector of volume sector `sector`.
#[inline]
fn dev_lba(v: &'static Vol, sector: u64) -> u64 {
    v.vol_base.load(core::sync::atomic::Ordering::Relaxed) + sector
}

/// [`fat32_volume_base_on`] on the boot volume ([`BOOT`]).
#[inline]
pub fn fat32_volume_base() -> u64 {
    fat32_volume_base_on(&BOOT)
}

/// The first sector of the volume on the medium, as the last mount chose it
/// (0 for a bare FAT32 medium).
pub fn fat32_volume_base_on(v: &'static Vol) -> u64 {
    v.vol_base.load(core::sync::atomic::Ordering::Relaxed)
}

/// Where a FAT32 volume starts on the medium, and how many sectors it may
/// span (`0`: unbounded, the bare-medium case).
///
/// The first published partition whose first sector passes
/// [`validate_bpb`] and whose `tot_sec32` fits inside it, else the whole
/// medium from sector 0. A partition that fails either check is skipped, not
/// fatal: a GPT disk may carry other filesystems before the FAT one.
fn select_volume(v: &'static Vol) -> (u64, u64) {
    for i in 0..v.dev.partition_count() {
        let (start, len) = match v.dev.partition(i) {
            Some(p) => p,
            None => continue,
        };
        let mut s0 = [0u8; SECTOR_SIZE];
        if v.dev.read_quiet(start, 1, &mut s0).is_err() {
            continue;
        }
        let bpb = unsafe { &*(s0.as_ptr() as *const Fat32Bpb) };
        if validate_bpb(bpb, &s0).is_ok() && (bpb.tot_sec32 as u64) <= len {
            return (start, len);
        }
    }
    (0, 0)
}

/// [`fat32_locks_available_on`] on the boot volume ([`BOOT`]).
#[inline]
pub fn fat32_locks_available() -> bool {
    fat32_locks_available_on(&BOOT)
}

/// Non-blocking check for whether the FAT32 locks (`FAT32` volume state,
/// `SECTOR_CACHE`) are free and no FAT-sector claim (`Vol::fat_sector_busy`)
/// is out. A claimed sector's next updater sleeps on a wait queue, which the
/// panic handler must not reach.
///
/// Intended for callers that must never block (e.g. the panic handler),
/// mirroring `vfs::vfs_fs_lock_available()`. Any FAT32-backed VFS
/// operation (open/read/write/close on a `/fat/...` path) can end up
/// acquiring both of these in addition to the VFS-level `FS` lock, so a
/// caller that only checked `FS` can still spin here. Like its VFS
/// counterpart, this is a racy point-in-time check, not a hold — the
/// locks can be taken by another hart right after this returns `true`.
pub fn fat32_locks_available_on(v: &'static Vol) -> bool {
    v.fat32.try_lock().is_some() && v.sector_cache.try_lock().is_some()
        && v.fat_sector_busy.load(core::sync::atomic::Ordering::SeqCst) == 0
        && !v.wb_busy.load(core::sync::atomic::Ordering::SeqCst)
}

/// [`fat32_cache_invalidate_on`] on the boot volume ([`BOOT`]).
#[inline]
pub fn fat32_cache_invalidate(sector: u32) {
    fat32_cache_invalidate_on(&BOOT, sector)
}

/// Invalidate every cache line touching `sector` — call after an
/// out-of-band write (raw block layer, OTA writes that bypass FS).
#[allow(dead_code)]
pub fn fat32_cache_invalidate_on(v: &'static Vol, sector: u32) {
    v.sector_cache.lock().invalidate(sector as u64);
}

/// More medium sectors than this in one write drop the whole cache (O(1))
/// instead of probing each sector: the lock is never held for more than a
/// set's worth of probes, however long the write.
const EXTERNAL_WRITE_RANGE_MAX: u64 = crate::bcache::MAX_WAYS as u64;

/// [`fat32_on_medium_write_on`] on the boot volume ([`BOOT`]).
#[inline]
pub fn fat32_on_medium_write(lba: u64, count: u32) {
    fat32_on_medium_write_on(&BOOT, lba, count)
}

/// The block layer's write observer (`azos_drv_block::write_observer`):
/// MEDIUM sectors `[lba, lba + count)` were written by someone other than
/// this file — a reserved-tail record, ring-3 block entries through a partition's `block` endpoint. Drops the cached copy
/// of every volume sector in the range; a range outside the volume (the
/// partition table, another partition, the reserved tail) drops nothing.
///
/// Called after the device answered, with no lock held, from any task. Takes
/// only `SECTOR_CACHE`, a leaf; the volume bounds are atomics, so it never
/// waits on `FAT32`. A reader whose device read raced this write cannot
/// install what it read: the invalidation bumps the cache's write sequence,
/// and `install` refuses a token taken before it.
pub fn fat32_on_medium_write_on(v: &'static Vol, lba: u64, count: u32) {
    if cfg!(feature = "fatcache-observer-canary") {
        return;
    }
    use core::sync::atomic::Ordering::Relaxed;
    let base = v.vol_base.load(Relaxed);
    let end = base.saturating_add(v.vol_sectors.load(Relaxed));
    let first = lba.max(base);
    let last = lba.saturating_add(count as u64).min(end);
    if count == 0 || first >= last {
        return;
    }
    let n = last - first;
    {
        let mut c = v.sector_cache.lock();
        if n > EXTERNAL_WRITE_RANGE_MAX && c.dirty_count() == 0 {
            c.invalidate_all();
        } else {
            // Write-back with dirty lines: `invalidate_range` drops exactly
            // the range (one O(lines) scan past a set's worth), never the
            // pending writes of other sectors.
            c.invalidate_range(first - base, n);
        }
    }
    // The FAT may have changed under the held chains: forget them (they
    // leak) rather than free clusters another writer may now use.
    held_reset(v);
    write_gen_bump(v);
}

/// Configure the cache for a mount and drop every line: 512 B lines (one
/// per volume sector), write-through, and the observer installed.
fn fat32_cache_reset(v: &'static Vol) {
    write_gen_bump(v);
    {
        let mut c = v.sector_cache.lock();
        if c.line_count() == 0 {
            // First mount: O(lines) once. Cannot fail: 512 is a valid block
            // size for any SECTOR_CACHE_BYTES (a multiple of 512), and a
            // write-through cache is never dirty.
            let on = v.knobs.writeback && v.wb_on.load(core::sync::atomic::Ordering::Relaxed);
            let mode = if on { crate::bcache::Mode::WriteBack } else { crate::bcache::Mode::WriteThrough };
            let _ = c.configure(SECTOR_SIZE, mode, 0);
        } else {
            // Every later mount: a generation bump, O(1).
            c.invalidate_all();
        }
    }
    // Again once the lines are gone (wave 14, SPAWNCACHE): a reader between
    // the first bump and the drop read the previous medium's lines under the
    // new value.
    write_gen_bump(v);
    v.dev.set_write_observer(fat32_on_medium_write);
    if v.knobs.writeback {
        v.dev.set_read_observer(fat32_before_medium_read, fat32_medium_read_would_wait);
    }
}

/// [`fat32_cache_invalidate_all_on`] on the boot volume ([`BOOT`]).
#[inline]
pub fn fat32_cache_invalidate_all() {
    fat32_cache_invalidate_all_on(&BOOT)
}

/// Drop every cache line, regardless of which sector it holds.
///
/// U09-6: the cache had no notion of the medium changing — `fat32_mount`
/// and `fat32_unmount` never called `fat32_cache_invalidate` (which is
/// per-sector anyway, and mount time does not know in advance which
/// sectors are stale) at all, so a remount after a media swap read the
/// PREVIOUS card's cached BPB/root/FAT sectors straight through the
/// "read". Only `SECTOR_CACHE_LINES` (8) lines exist, so dropping all of
/// them is O(8), not a real cost against a mount that is about to do disk
/// I/O anyway. (Wave 14: a generation bump, O(1) at any size.)
///
/// Public for the host tests, which drop every line the way a mount does.
/// Every other writer of the medium invalidates its own sectors through the
/// block layer's write observer, so this is not the coherence mechanism.
pub fn fat32_cache_invalidate_all_on(v: &'static Vol) {
    v.sector_cache.lock().invalidate_all();
    write_gen_bump(v);
}

/// Read a sector, preferring the cache. On miss, fetch via the block
/// device and install in the LRU-evicted line.
fn read_sector(v: &'static Vol, sector: u32, buf: &mut [u8; SECTOR_SIZE]) -> Result<(), ()> {
    let token = {
        let mut c = v.sector_cache.lock();
        if c.lookup(sector as u64, buf) {
            return Ok(());
        }
        c.lookup_miss_token()
    };
    // Miss — fetch from the device with the cache lock released.
    crate::census::count(crate::census::DEV_READS);
    pi_io_probe();
    v.dev.read_quiet(dev_lba(v, sector as u64), 1, buf)?;
    v.sector_cache.lock().install(sector as u64, buf, token);
    Ok(())
}

/// [`read_sector`] that installs the line only when `retain`. File data read
/// for the page cache's fills is held there; a second copy in this cache is
/// the double caching the page cache replaces. A resident line still answers
/// (a dirty one is newer than the medium).
fn read_sector_with(v: &'static Vol, sector: u32, buf: &mut [u8; SECTOR_SIZE], retain: bool) -> Result<(), ()> {
    if retain {
        return read_sector(v, sector, buf);
    }
    if v.sector_cache.lock().lookup(sector as u64, buf) {
        return Ok(());
    }
    crate::census::count(crate::census::DEV_READS);
    pi_io_probe();
    v.dev.read_quiet(dev_lba(v, sector as u64), 1, buf)
}

/// [`fat32_cache_stats_on`] on the boot volume ([`BOOT`]).
#[inline]
pub fn fat32_cache_stats() -> (u32, u32) {
    fat32_cache_stats_on(&BOOT)
}

/// Lines of volume `v`'s sector cache as configured (diagnostics: its
/// Kconfig size, `FS_BLOCK_CACHE_KB` or `USB_VOLUME_CACHE_KB`, in blocks).
pub fn fat32_cache_lines_on(v: &'static Vol) -> usize {
    v.sector_cache.lock().line_count()
}

/// Statistics for diagnostics (`fs cache` shell command, etc.).
#[allow(dead_code)]
pub fn fat32_cache_stats_on(v: &'static Vol) -> (u32, u32) {
    let st = v.sector_cache.lock().stats();
    (st.hits, st.misses)
}

/// [`fat32_cache_counters_on`] on the boot volume ([`BOOT`]).
#[inline]
pub fn fat32_cache_counters() -> crate::bcache::CacheStats {
    fat32_cache_counters_on(&BOOT)
}

/// The shared cache's full counters for the FAT32 instance (hits, misses,
/// write-backs, ordering flushes). The last two stay 0 while the instance is
/// write-through.
#[allow(dead_code)]
pub fn fat32_cache_counters_on(v: &'static Vol) -> crate::bcache::CacheStats {
    v.sector_cache.lock().stats()
}

/// [`fat32_cache_epoch_on`] on the boot volume ([`BOOT`]).
#[inline]
pub fn fat32_cache_epoch() -> u64 {
    fat32_cache_epoch_on(&BOOT)
}

/// The FAT32 cache's current epoch (diagnostics, host tests: a barrier
/// moves it by one).
#[allow(dead_code)]
pub fn fat32_cache_epoch_on(v: &'static Vol) -> u64 {
    v.sector_cache.lock().epoch()
}

/// [`fat32_dirty_epochs_on`] on the boot volume ([`BOOT`]).
#[inline]
pub fn fat32_dirty_epochs() -> usize {
    fat32_dirty_epochs_on(&BOOT)
}

/// Distinct epochs among the FAT32 cache's dirty lines (diagnostics, host
/// tests).
#[allow(dead_code)]
pub fn fat32_dirty_epochs_on(v: &'static Vol) -> usize {
    v.sector_cache.lock().dirty_epochs()
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Offset of the boot-sector signature within sector 0. NOT part of
/// `Fat32Bpb` — that struct ends at byte 90 — so it is read directly off
/// the raw sector rather than through a field.
const BOOT_SIG_OFFSET: usize = 510;
const BOOT_SIG: [u8; 2] = [0x55, 0xAA];

/// Validate every BPB field U09's 14-row attacker-controlled-field table
/// lists, one row at a time — the class fix, not one more special case.
/// Ten of the table's fourteen rows are NOT BPB fields at all (FAT entry
/// values, chain length, dirent fields, LFN entries, journal fields) and
/// are checked at the point they are used, which this function's own doc
/// on each BPB row states explicitly rather than silently skipping them.
///
/// Called with the lock NOT held — every check here reads `bpb`/`sector0`
/// only, never `FAT32`'s state.
fn validate_bpb(bpb: &Fat32Bpb, sector0: &[u8; SECTOR_SIZE]) -> Result<(), ()> {
    // `bytes_per_sec`: this whole file reads into `[u8; 512]` buffers: a
    // different value means either a corrupt BPB or a physical sector size
    // this parser cannot serve correctly either way.
    if bpb.bytes_per_sec != 512 { return Err(()); }

    // **FAT12/16 rejection — U09-9's headline finding.** `root_ent_cnt`,
    // `tot_sec16`, `fat_sz16` are the FAT12/16 BPB's own fields; on a
    // genuine FAT32 volume `mkfs.fat` always zeroes them, because
    // `fat_sz32`/`ext_flags`/`fs_ver`/`root_clus`/`fs_info`/`bk_boot_sec`
    // occupy the SAME BYTES a FAT12/16 BPB does not have. A FAT16 card
    // whose `tot_sec32` happens to be nonzero (its `hidd_sec`+`tot_sec32`
    // region, or simply left as whatever the card's own data holds) passed
    // every check that existed before this one and mounted as FAT32. The
    // FAT spec's own "is this FAT32" test is exactly these three fields
    // being zero — there is no FAT32 volume for which they are legitimately
    // nonzero, so this is a rejection with no false-positive case.
    if bpb.root_ent_cnt != 0 { return Err(()); }
    if bpb.tot_sec16     != 0 { return Err(()); }
    if bpb.fat_sz16      != 0 { return Err(()); }

    if bpb.fat_sz32 == 0        { return Err(()); }
    // **`num_fats == 0` is not a volume, it is a lever.** It makes
    // `data_start == fat_start` — small, and passing every other check — while
    // leaving `fat_sz32` free to inflate the cluster-walk bound. FAT32 always
    // has at least one FAT.
    if bpb.num_fats == 0        { return Err(()); }
    // A volume that claims no sectors has no data clusters, and every walk
    // bound below would be zero.
    if bpb.tot_sec32 == 0       { return Err(()); }

    // `fs_ver`: the FAT32 revision. This parser was written against, and
    // only understands, revision 0.0 (every field offset above assumes
    // it). A nonzero revision may use a layout this parser was never
    // checked against — refuse rather than guess.
    if bpb.fs_ver != 0 { return Err(()); }

    // `ext_flags` bit 7: "FAT mirroring disabled, only the copy named by
    // bits 0-3 is active". `fat32_write_fat_entry` writes ALL `num_fats`
    // copies on the assumption every copy mirrors every other; a volume
    // with mirroring disabled would have this parser overwrite a FAT copy
    // the volume's own driver treats as stale, corrupting the active one's
    // intended divergence.
    if bpb.ext_flags & 0x0080 != 0 { return Err(()); }

    let spc = bpb.sec_per_clus as u32;
    // Reject bogus geometry: spc must be a power of two in 1..=128 (FAT spec),
    // and the data-region start must not overflow u32 (crafted BPB → abort).
    if spc == 0 || spc > 128 || (spc & (spc - 1)) != 0 { return Err(()); }

    // The boot-sector signature. Every field above can coincidentally line
    // up on non-FAT32 media (all-zero, for instance, passes `fs_ver`,
    // `ext_flags`, `root_ent_cnt` et al. for free); this is the one
    // whole-sector check the FAT spec itself defines for "is this a boot
    // sector at all", so it catches what the field-by-field checks, taken
    // individually, cannot.
    if sector0[BOOT_SIG_OFFSET] != BOOT_SIG[0] || sector0[BOOT_SIG_OFFSET + 1] != BOOT_SIG[1] {
        return Err(());
    }

    // `rsvd_sec_cnt`: no lower bound before this — `data_start`'s overflow
    // was checked, but a `rsvd_sec_cnt` of 0 or 1 was accepted, putting the
    // FAT (or the data region) on the SAME sector as this driver's own
    // journal at `JOURNAL_SECTOR`. Requiring strictly more reserved
    // sectors than `JOURNAL_SECTOR` keeps the journal inside the reserved
    // region and off both the FAT and the data.
    if (bpb.rsvd_sec_cnt as u32) <= JOURNAL_SECTOR { return Err(()); }

    // `fs_info` / `bk_boot_sec`: U09-9's other half. `mkfs.fat -F 32`'s
    // default places FSInfo at sector 1 — EXACTLY `JOURNAL_SECTOR` — so
    // every journal write overwrites FSInfo, and a host tool repairing
    // FSInfo erases a pending journal record. This parser never reads or
    // writes FSInfo or the backup boot sector, so there is no "read the
    // real location" fix available; the fix is refusing to mount a volume
    // that would put either of them where the journal already lives.
    // `0xFFFF` means "unused" (FAT spec) and is not a collision.
    if bpb.fs_info != 0xFFFF && bpb.fs_info as u32 == JOURNAL_SECTOR { return Err(()); }
    if bpb.bk_boot_sec != 0 && bpb.bk_boot_sec as u32 == JOURNAL_SECTOR { return Err(()); }

    // `root_clus`: no check here, and not by omission. Every walker that
    // ever reads a cluster number (`fat32_next_cluster`'s `chain_walk_limit`
    // bound, `cluster_first_sector`'s overflow check) already rejects
    // `< 2`, `>= EOC`, and a `data_start` overflow — the exact bound a
    // bogus `root_clus` would need, so a mount-time duplicate would only
    // check the same thing twice.
    Ok(())
}

/// [`fat32_mount_on`] on the boot volume ([`BOOT`]).
#[inline]
pub fn fat32_mount() -> Result<(), ()> {
    fat32_mount_on(&BOOT)
}

/// Mount a FAT32 filesystem on the first VirtIO block device.
/// Returns Ok(()) on success.
///
/// After journal recovery an unclean volume (see the volume-state notes
/// above `MountReport`) is checked and its leaked space given back
/// ([`fat32_mount_report`] says what was found), and the volume is marked
/// dirty until [`fat32_unmount`] clears it.
pub fn fat32_mount_on(v: &'static Vol) -> Result<(), ()> {
    // U09-3: already mounted — nothing to do. `fat32_mount_volume_on()` is a
    // thin wrapper over this function, and its callers — the logger's
    // `open()` on every log rotation, `secure_boot.rs`'s
    // `read_sig_file`/`read_image_file` — used to call through to a full
    // re-read of sector 0, a full re-derivation of the volume geometry, and
    // a full `fat32_journal_recover()` on EVERY call. The recovery half is
    // the dangerous one: it can replay a PENDING `OVERWRITE` entry that a
    // writer on another hart is still in the middle of committing, freeing
    // a chain that writer is about to link (U09-3's specific failure) —
    // and `fat32_journal_recover`'s own doc says it runs "at mount, before
    // userspace exists", which was true for the FIRST mount and false for
    // every mount after. This early-out makes it true again,
    // unconditionally. `fat32_unmount_on()` clears `mounted`, so a real
    // remount (media change, an explicit unmount/mount cycle) still runs
    // the full path below.
    if v.fat32.lock().mounted {
        return Ok(());
    }

    // U09-6: this IS a real mount attempt past the early-out above — drop
    // every cached sector before reading anything. Without this, a remount
    // after `fat32_unmount_on()` (media swap, or the crash-recovery path that
    // unmounts and remounts the same medium) would read the PREVIOUS
    // medium's cached BPB/root/FAT sectors through `read_sector`'s cache
    // hit, never touching the device this mount is supposed to be reading.
    fat32_cache_reset(v);

    // Where the volume is: a published partition holding a FAT32 boot
    // sector, or the bare medium. Chosen before the first `read_sector`, and
    // the cache was just emptied, so no line holds a sector of the old base.
    let (base, part_len) = select_volume(v);
    v.vol_sectors.store(u64::MAX, core::sync::atomic::Ordering::Relaxed);
    v.vol_base.store(base, core::sync::atomic::Ordering::Relaxed);
    // A new volume (or the same one after an unmount): no cached free count
    // carries over.
    free_count_invalidate(v);
    v.alloc_hint.store(0, core::sync::atomic::Ordering::Relaxed);
    held_reset(v);

    let mut sector0 = [0u8; SECTOR_SIZE];
    read_sector(v, 0, &mut sector0)?;

    // Parse BPB (at offset 0 in sector 0)
    let bpb = unsafe { &*(sector0.as_ptr() as *const Fat32Bpb) };
    validate_bpb(bpb, &sector0)?;
    // Re-checked on the bytes actually mounted: the volume may not claim more
    // sectors than its partition holds, and on a bare medium no more than the
    // device holds (wave 15, GR4). `tot_sec32` is what bounds every chain walk
    // (`chain_walk_limit`) and every allocation; a BPB claiming 2^32 sectors
    // on a 128 KiB medium made that bound ~2^31 steps, and a self-linked root
    // then spun a walker that long (fuzz input `regressions/fat32_image/
    // root-self-link-volume-past-medium`). A capacity of 0 means the device
    // has not said (virtio-blk before its probe, an MMC card whose CSD was
    // not parsed): no bound from it, as before.
    let medium = if part_len != 0 {
        part_len
    } else {
        v.dev.capacity_sectors().saturating_sub(base)
    };
    if medium != 0 && bpb.tot_sec32 as u64 > medium && !cfg!(feature = "fat-medium-bound-canary") {
        return Err(());
    }
    v.vol_sectors.store(bpb.tot_sec32 as u64, core::sync::atomic::Ordering::Relaxed);

    let spc = bpb.sec_per_clus as u32;
    let fat_start  = bpb.rsvd_sec_cnt as u32;
    let data_start = match (bpb.num_fats as u32)
        .checked_mul(bpb.fat_sz32)
        .and_then(|f| fat_start.checked_add(f))
    {
        Some(v) => v,
        None => return Err(()),
    };
    let root_clus  = bpb.root_clus;
    // The root directory must be a cluster of this volume's data region.
    // `validate_bpb` never looked at it: `root_clus = 0xFFFF_FFFF` mounted,
    // every directory walk then started past EOC, and the first create
    // allocated a cluster for a "directory extension" it could not link —
    // one cluster lost per create (wave 11, `tests/fuzz/fs-fuzz`).
    let data_clusters = bpb.tot_sec32.saturating_sub(data_start) / spc;
    if root_clus < FAT32_FIRST_DATA_CLUSTER
        || root_clus - FAT32_FIRST_DATA_CLUSTER >= data_clusters
    {
        return Err(());
    }

    let mut fv = v.fat32.lock();
    fv.fat_start      = fat_start;
    fv.data_start     = data_start;
    fv.root_cluster   = root_clus;
    fv.secs_per_clus  = spc;
    fv.bytes_per_clus = spc * 512;
    fv.fat_sz32       = bpb.fat_sz32;
    fv.num_fats       = bpb.num_fats;
    fv.mounted        = true;
    // **The anti-cycle bound, published before anything can walk a chain.**
    // The old one was `fat_sz32 * 128` — a figure the attacker writes. A BPB
    // with `num_fats = 0` keeps `data_start` small and passing every other
    // check while inflating `fat_sz32` to saturate that product at
    // `u32::MAX`; a self-cycling FAT entry then spins a walker ~4e9 times
    // with every read served from the sector cache, so no I/O slows it down.
    // A hart wedged for minutes is a watchdog reset, i.e. a physical-safety
    // event. Found by audit 2026-09-21.
    //
    // `saturating_sub` because a BPB may claim fewer total sectors than its
    // own reserved+FAT region needs — that volume simply has no data.
    fv.data_clusters  = bpb.tot_sec32.saturating_sub(data_start) / spc;
    // The read-only streams' copy of the geometry (wave 14), published with
    // the fields above while `fv` is held. Each pair travels in one word, so a
    // reader never sees `spc` from one mount and `data_start` from another.
    {
        use core::sync::atomic::Ordering::Release;
        let limit = chain_walk_limit(fv.fat_sz32, fv.data_clusters);
        v.stream_geom_a.store(((spc as u64) << 32) | data_start as u64, Release);
        v.stream_geom_b.store(((fat_start as u64) << 32) | limit as u64, Release);
    }

    azos_drv_sys::kprintln!(
        "[FAT32] Mounted: FAT@{}, data@{}, root_clus={}, spc={}, base LBA {}",
        fat_start, data_start, root_clus, spc, base
    );

    // Recover from any incomplete operations before power loss.
    drop(fv);
    // Write-back orders its epochs with device flushes; a device that cannot
    // flush gives no order, so this mount stays write-through (whose journal
    // barriers then refuse, fail closed, as before).
    if v.knobs.writeback && v.wb_on.load(core::sync::atomic::Ordering::Relaxed) {
        let wt = matches!(device_flush_raw(v), Err(FsError::Unsupported));
        let mut c = v.sector_cache.lock();
        let want = if wt { crate::bcache::Mode::WriteThrough } else { crate::bcache::Mode::WriteBack };
        if c.mode() != want && c.dirty_count() == 0 {
            let _ = c.configure(SECTOR_SIZE, want, 0);
        }
    }
    // A journal record found here means the last run was cut inside an
    // operation, whatever the volume's flag says (a volume last written by a
    // build that did not keep the flag).
    let journal_busy = !fat32_journal_idle_on(v);
    fat32_journal_recover(v)?;
    // Write-back: what recovery repaired is on the medium before the volume
    // is used (a second cut must not find the same journal record again).
    if v.knobs.writeback && v.sector_cache.lock().dirty_count() != 0 {
        match device_flush(v) {
            Ok(()) | Err(FsError::Unsupported) => {}
            Err(_) => return Err(()),
        }
    }

    // Power-loss safety: an unclean volume is checked (after recovery, so the
    // scan does not judge chains recovery has just linked or freed), then
    // marked dirty for this mount, durably, before the first write of the
    // mount. Best effort throughout: a medium that cannot be repaired or
    // flagged (read-only, a failing sector) still mounts, as it always did.
    let mut rep = MountReport::new();
    rep.unclean = !volume_is_clean(v);
    if rep.unclean || journal_busy {
        check_volume(v, &mut rep);
        if v.knobs.writeback && v.sector_cache.lock().dirty_count() != 0 {
            let _ = device_flush(v);
        }
    }
    rep.marked_dirty = mark_volume_dirty(v);
    v.volume_marked_dirty.store(rep.marked_dirty, core::sync::atomic::Ordering::Relaxed);
    *v.mount_report.lock() = rep;

    Ok(())
}

// ── Volume state (dirty bit) and the mount-time check ────────────────────────
//
// **Power-loss safety, the part the journal does not cover.** The journal
// makes each structural operation all-or-nothing, and the write order (data,
// then FAT, then directory entry; see `write_file_journaled`, `fat32_release`,
// `dir_insert`) means a cut leaves a valid volume. What a cut can still leave
// is SPACE: clusters allocated by a write whose directory entry never landed
// (a PENDING `WRITE_DIR` is discarded, not rolled back), a chain whose free
// reached only some FAT copies, a file's chain held for a free that never ran.
// None of that is corruption, but it is unbounded over many cuts and nothing
// would ever give it back.
//
// The volume carries the standard "was this shut down cleanly" state so the
// mount knows whether to look:
//   * FAT[1] bit 27 (`ClnShutBitMask`): set = clean.
//   * boot sector byte 0x41 (`BS_Reserved1`, the FAT32 NT flags) bit 0: set =
//     dirty. Linux's vfat and `fsck.fat` use this one; Windows uses both.
// A volume is clean only when BOTH say so. A mount sets it dirty (before the
// first write of the mount: the flag is flushed ahead of everything else) and
// an unmount clears it after the last flush, so after any cut the flag says
// "dirty" and the next mount runs the check below.

/// `FAT[1]` bit 27: the volume was shut down cleanly.
const FAT_STATE_CLEAN: u32 = 0x0800_0000;
/// Boot sector byte `BS_Reserved1` of a FAT32 volume (offset 0x41), bit 0: dirty.
const BS_STATE_OFF: usize = 0x41;
const BS_STATE_DIRTY: u8 = 0x01;
/// The value of `FAT[1]` is entry 1 of FAT sector 0.
const FAT_STATE_ENTRY_OFF: usize = 4;

/// Largest reachability bitmap the mount check will allocate, in bytes (one
/// bit per cluster: 1 MiB covers 8 Mi clusters, 256 GiB at 32 KiB clusters).
/// A volume past it, or a heap that cannot give it, is checked for FAT copy
/// agreement only and nothing is reclaimed.
const CHECK_BITMAP_MAX_BYTES: usize = 1 << 20;
/// Most subdirectories the check holds waiting to be scanned.
const CHECK_DIR_STACK_MAX: usize = 4096;
/// FAT sectors the check reads per device request when the heap allows it.
const CHECK_RUN_SECTORS: u32 = 16;

/// What the last mount found and did (see [`fat32_mount_report`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MountReport {
    /// The volume was not marked clean (a cut, a crash, or a mount that was
    /// never unmounted).
    pub unclean: bool,
    /// The check ran: the volume was unclean, or the journal held a record.
    pub checked: bool,
    /// The reachability scan walked every directory and chain without a read
    /// error or a limit; lost clusters are reclaimed only then.
    pub complete: bool,
    /// FAT sectors whose copy differed from copy 0 (copy 0 is what every walk
    /// reads, and it wins).
    pub fat_mismatch: u32,
    /// Allocated clusters no directory entry reaches.
    pub lost_clusters: u32,
    /// Of those, the clusters given back (0 unless `complete`).
    pub reclaimed: u32,
    /// Chains that reached a cluster another chain had already claimed.
    pub cross_linked: u32,
    /// Chains that left the data region or ran through a free cluster.
    pub broken_chains: u32,
    /// This mount set the volume's dirty flag (it will clear it on unmount).
    pub marked_dirty: bool,
}

impl MountReport {
    const fn new() -> Self {
        MountReport {
            unclean: false, checked: false, complete: false, fat_mismatch: 0,
            lost_clusters: 0, reclaimed: 0, cross_linked: 0, broken_chains: 0,
            marked_dirty: false,
        }
    }
}

/// [`fat32_mount_report_on`] on the boot volume ([`BOOT`]).
#[inline]
pub fn fat32_mount_report() -> MountReport {
    fat32_mount_report_on(&BOOT)
}

/// The report of the most recent mount of this volume.
pub fn fat32_mount_report_on(v: &'static Vol) -> MountReport {
    *v.mount_report.lock()
}

/// Whether the medium says "shut down cleanly": the FAT[1] bit set and the
/// boot sector bit clear. An unreadable sector reads as not clean.
fn volume_is_clean(v: &'static Vol) -> bool {
    let fat_start = v.fat32.lock().fat_start;
    let mut boot = [0u8; SECTOR_SIZE];
    let mut fat0 = [0u8; SECTOR_SIZE];
    if read_sector(v, 0, &mut boot).is_err() || read_sector(v, fat_start, &mut fat0).is_err() {
        return false;
    }
    let e = u32::from_le_bytes(fat0[FAT_STATE_ENTRY_OFF..FAT_STATE_ENTRY_OFF + 4].try_into().unwrap());
    e & FAT_STATE_CLEAN != 0 && boot[BS_STATE_OFF] & BS_STATE_DIRTY == 0
}

/// Write the clean/dirty state: `FAT[1]` bit 27 in every FAT copy (a
/// read-modify-write of FAT sector 0 under its claim, every other bit kept)
/// and the boot sector's bit 0. A sector is written only when it changes.
/// Straight to the device ([`write_sector_direct`]): a medium that refuses
/// the write leaves nothing queued to fail later, and the caller must have
/// flushed the cache first (`volume_state_write_ready`).
fn volume_set_clean(v: &'static Vol, clean: bool) -> Result<(), ()> {
    let (fat_start, fat_sz32, num_fats) = {
        let fv = v.fat32.lock();
        (fv.fat_start, fv.fat_sz32, fv.num_fats.max(1) as u32)
    };
    {
        let _claim = fat_sector_claim(v, 0);
        let mut buf = [0u8; SECTOR_SIZE];
        read_sector(v, fat_start, &mut buf)?;
        let o = FAT_STATE_ENTRY_OFF;
        let cur = u32::from_le_bytes(buf[o..o + 4].try_into().unwrap());
        let new = if clean { cur | FAT_STATE_CLEAN } else { cur & !FAT_STATE_CLEAN };
        if new != cur {
            buf[o..o + 4].copy_from_slice(&new.to_le_bytes());
            for i in 0..num_fats {
                let sec = i.checked_mul(fat_sz32).and_then(|off| fat_start.checked_add(off)).ok_or(())?;
                write_sector_direct(v, sec, &buf)?;
            }
        }
    }
    let mut boot = [0u8; SECTOR_SIZE];
    read_sector(v, 0, &mut boot)?;
    let cur = boot[BS_STATE_OFF];
    let new = if clean { cur & !BS_STATE_DIRTY } else { cur | BS_STATE_DIRTY };
    if new != cur {
        boot[BS_STATE_OFF] = new;
        write_sector_direct(v, 0, &boot)?;
    }
    Ok(())
}

/// Nothing dirty in the cache: the precondition of a direct state write. A
/// dirty line is flushed first (a failed flush says no).
fn volume_state_write_ready(v: &'static Vol) -> bool {
    if v.sector_cache.lock().dirty_count() == 0 { return true; }
    matches!(device_flush(v), Ok(())) && v.sector_cache.lock().dirty_count() == 0
}

/// Mark the volume dirty for this mount, durably, before anything else is
/// written: a cut after the first write of the mount must find the flag set.
/// Not fatal: a medium that refuses the write (write-protected) still mounts,
/// and `false` tells the unmount there is nothing to clear.
fn mark_volume_dirty(v: &'static Vol) -> bool {
    if cfg!(feature = "fat-dirty-bit-canary") { return false; }
    if !volume_state_write_ready(v) || volume_set_clean(v, false).is_err() { return false; }
    if cfg!(feature = "fat-dirty-unordered-canary") { return true; }
    // The flag reaches the medium before any later write does: a flush. A
    // device that cannot flush (`Unsupported`) orders nothing, as for
    // `dir_insert`'s barrier; one whose flush fails refuses every later
    // barrier too, so the mount goes on and the first structural write says so.
    let _ = device_flush_raw(v);
    true
}

/// A one-bit-per-cluster set over the data region, for the reachability scan.
struct Marks {
    bits: alloc::vec::Vec<u64>,
    /// Data clusters: valid cluster numbers are `2 .. 2 + clusters`.
    clusters: u32,
}

impl Marks {
    fn new(clusters: u32) -> Option<Marks> {
        let words = (clusters as usize).div_ceil(64);
        if words * 8 > CHECK_BITMAP_MAX_BYTES { return None; }
        let mut bits = alloc::vec::Vec::new();
        bits.try_reserve_exact(words).ok()?;
        bits.resize(words, 0u64);
        Some(Marks { bits, clusters })
    }

    fn valid(&self, c: u32) -> bool {
        c >= FAT32_FIRST_DATA_CLUSTER && c - FAT32_FIRST_DATA_CLUSTER < self.clusters
    }

    /// Set `c`'s bit; whether it was already set. `c` must be `valid`.
    fn test_and_set(&mut self, c: u32) -> bool {
        let i = (c - FAT32_FIRST_DATA_CLUSTER) as usize;
        let (w, m) = (i / 64, 1u64 << (i % 64));
        let was = self.bits[w] & m != 0;
        self.bits[w] |= m;
        was
    }

    fn get(&self, c: u32) -> bool {
        let i = (c - FAT32_FIRST_DATA_CLUSTER) as usize;
        self.bits[i / 64] & (1u64 << (i % 64)) != 0
    }
}

/// Claim the chain starting at `first` in `marks`. `Ok(true)`: its first
/// cluster was free to claim (the chain is new; a chain that later left the
/// data region, ran through a free cluster or met another chain is counted
/// in `rep` and ends there); `Ok(false)`: nothing was claimed. `Err`: the FAT
/// could not be read.
fn check_mark_chain(v: &'static Vol, first: u32, marks: &mut Marks, rep: &mut MountReport) -> Result<bool, ()> {
    let (fat_sz32, data_clusters) = {
        let fv = v.fat32.lock();
        (fv.fat_sz32, fv.data_clusters)
    };
    let mut walk = ChainWalk::for_volume(fat_sz32, data_clusters);
    let mut c = first;
    let mut fresh = false;
    loop {
        if !marks.valid(c) || !walk.visit(c) {
            rep.broken_chains += 1;
            return Ok(fresh);
        }
        if marks.test_and_set(c) {
            rep.cross_linked += 1;
            return Ok(fresh);
        }
        fresh = true;
        let next = fat32_next_cluster(v, c)?;
        if next == 0 {
            // The chain runs through a FREE cluster: it ends there.
            rep.broken_chains += 1;
            return Ok(true);
        }
        if next >= FAT32_EOC { return Ok(true); }
        c = next;
    }
}

/// Claim every chain the entries of directory `dir` name, queueing the
/// subdirectories on `stack`. `Err`: a read failed, a limit was reached, or
/// the directory itself is damaged (its chain leaves the data region or runs
/// through a free cluster, or a second entry names it); what hangs off it is
/// then unknown and the scan is incomplete.
fn check_scan_dir(
    v: &'static Vol, dir: u32,
    marks: &mut Marks,
    stack: &mut alloc::vec::Vec<u32>,
    rep: &mut MountReport,
) -> Result<(), ()> {
    let (spc, data_start, fat_sz32, data_clusters) = {
        let fv = v.fat32.lock();
        (fv.secs_per_clus, fv.data_start, fv.fat_sz32, fv.data_clusters)
    };
    let mut walk = ChainWalk::for_volume(fat_sz32, data_clusters);
    let mut cluster = dir;
    loop {
        if !marks.valid(cluster) || !walk.visit(cluster) { return Err(()); }
        let first = cluster_first_sector(data_start, cluster, spc).ok_or(())?;
        for s in 0..spc {
            let mut buf = [0u8; SECTOR_SIZE];
            read_sector(v, first + s, &mut buf)?;
            for e in 0..DIRENTS_PER_SECTOR {
                let off = e * DIRENT_SIZE;
                let lead = buf[off];
                if lead == DIRENT_MARK_END { return Ok(()); }
                if lead == DIRENT_MARK_DELETED { continue; }
                let attr = buf[off + DIRENT_OFF_ATTR];
                if attr == ATTR_LFN || attr & ATTR_VOLUME_ID != 0 { continue; }
                let is_dir = attr & ATTR_DIRECTORY != 0;
                // "." and "..": names, not children.
                if is_dir && lead == b'.' { continue; }
                let hi = u16::from_le_bytes([buf[off + DIRENT_OFF_FST_CLUS_HI], buf[off + DIRENT_OFF_FST_CLUS_HI + 1]]);
                let lo = u16::from_le_bytes([buf[off + DIRENT_OFF_FST_CLUS_LO], buf[off + DIRENT_OFF_FST_CLUS_LO + 1]]);
                let c = ((hi as u32) << 16) | lo as u32;
                // An empty file names no cluster.
                if c == 0 { continue; }
                // Canary: a file's chain is not claimed (live data looks lost).
                let fresh = if cfg!(feature = "fat-check-no-mark-canary") && !is_dir {
                    false
                } else {
                    check_mark_chain(v, c, marks, rep)?
                };
                if is_dir {
                    if !fresh || stack.len() >= CHECK_DIR_STACK_MAX { return Err(()); }
                    stack.try_reserve(1).map_err(|_| ())?;
                    stack.push(c);
                }
            }
        }
        let next = fat32_next_cluster(v, cluster)?;
        if next >= FAT32_EOC { return Ok(()); }
        // 0 (a free cluster) fails `valid` at the top.
        cluster = next;
    }
}

/// The scratch for the two FAT passes: `CHECK_RUN_SECTORS` sectors twice from
/// the heap when it gives them, else one sector twice from `small`.
fn check_scratch<'a>(
    heap: &'a mut alloc::vec::Vec<u8>,
    small: &'a mut [u8; 2 * SECTOR_SIZE],
) -> (&'a mut [u8], u32) {
    let big = 2 * CHECK_RUN_SECTORS as usize * SECTOR_SIZE;
    if heap.try_reserve_exact(big).is_ok() {
        heap.resize(big, 0);
        (&mut heap[..], CHECK_RUN_SECTORS)
    } else {
        (&mut small[..], 1)
    }
}

/// FAT copies against copy 0, sector by sector: a differing copy is
/// overwritten with copy 0 (every walk and every allocation reads copy 0, so
/// that is the volume as the driver sees it; a cut between the copies' writes
/// leaves exactly this). Counts into `rep.fat_mismatch`.
fn check_fat_copies(v: &'static Vol, rep: &mut MountReport) -> Result<(), ()> {
    let (fat_start, fat_sz32, num_fats) = {
        let fv = v.fat32.lock();
        (fv.fat_start, fv.fat_sz32, fv.num_fats as u32)
    };
    if num_fats < 2 { return Ok(()); }
    let mut heap = alloc::vec::Vec::new();
    let mut small = [0u8; 2 * SECTOR_SIZE];
    let (scratch, run) = check_scratch(&mut heap, &mut small);
    let (a, b) = scratch.split_at_mut(run as usize * SECTOR_SIZE);
    let mut s = 0u32;
    while s < fat_sz32 {
        let n = run.min(fat_sz32 - s);
        let len = n as usize * SECTOR_SIZE;
        read_run_cached(v, fat_start + s, n, &mut a[..len], true)?;
        for k in 1..num_fats {
            let base = k.checked_mul(fat_sz32).and_then(|o| fat_start.checked_add(o)).ok_or(())? + s;
            read_run_cached(v, base, n, &mut b[..len], true)?;
            for i in 0..n as usize {
                let (x, y) = (&a[i * SECTOR_SIZE..][..SECTOR_SIZE], &b[i * SECTOR_SIZE..][..SECTOR_SIZE]);
                if x == y { continue; }
                rep.fat_mismatch += 1;
                if cfg!(feature = "fat-no-repair-canary") { continue; }
                write_sector(v, base + i as u32, x.try_into().unwrap())?;
            }
        }
        s += n;
    }
    Ok(())
}

/// Give back every allocated cluster `marks` does not hold: one FAT pass,
/// each changed sector rewritten in every copy.
fn check_reclaim_lost(v: &'static Vol, marks: &Marks, reclaim: bool, rep: &mut MountReport) -> Result<(), ()> {
    let (fat_start, fat_sz32, num_fats) = {
        let fv = v.fat32.lock();
        (fv.fat_start, fv.fat_sz32, fv.num_fats.max(1) as u32)
    };
    let mut heap = alloc::vec::Vec::new();
    let mut small = [0u8; 2 * SECTOR_SIZE];
    let (scratch, run) = check_scratch(&mut heap, &mut small);
    let a = &mut scratch[..run as usize * SECTOR_SIZE];
    // FAT sectors that hold entries 0 .. clusters + 2.
    let sectors = (marks.clusters + FAT32_FIRST_DATA_CLUSTER).div_ceil(FAT32_ENTRIES_PER_SECTOR).min(fat_sz32);
    let mut s = 0u32;
    while s < sectors {
        let n = run.min(sectors - s);
        read_run_cached(v, fat_start + s, n, &mut a[..n as usize * SECTOR_SIZE], true)?;
        for i in 0..n {
            let sec = &mut a[i as usize * SECTOR_SIZE..][..SECTOR_SIZE];
            let mut changed = 0u32;
            for e in 0..FAT32_ENTRIES_PER_SECTOR {
                let cluster = (s + i) * FAT32_ENTRIES_PER_SECTOR + e;
                if !marks.valid(cluster) { continue; }
                let o = e as usize * 4;
                let raw = u32::from_le_bytes(sec[o..o + 4].try_into().unwrap());
                let v = raw & 0x0FFF_FFFF;
                // Free, or the bad-cluster mark: not ours to give back.
                if v == 0 || v == 0x0FFF_FFF7 || marks.get(cluster) { continue; }
                rep.lost_clusters += 1;
                if reclaim {
                    sec[o..o + 4].copy_from_slice(&(raw & 0xF000_0000).to_le_bytes());
                    changed += 1;
                }
            }
            if changed != 0 {
                let buf: &[u8; SECTOR_SIZE] = (&*sec).try_into().unwrap();
                for k in 0..num_fats {
                    let at = k.checked_mul(fat_sz32).and_then(|o| fat_start.checked_add(o)).ok_or(())? + s + i;
                    write_sector(v, at, buf)?;
                }
                rep.reclaimed += changed;
            }
        }
        s += n;
    }
    if rep.reclaimed != 0 {
        free_count_invalidate(v);
        v.alloc_hint.store(0, core::sync::atomic::Ordering::Relaxed);
    }
    Ok(())
}

/// The mount-time check of an unclean volume, after journal recovery: FAT
/// copy agreement, then the lost clusters (allocated, reached by no entry).
fn check_volume(v: &'static Vol, rep: &mut MountReport) {
    rep.checked = true;
    if check_fat_copies(v, rep).is_err() {
        azos_drv_sys::kprintln!("[FAT32] check: FAT copy comparison or repair failed (read error, or a medium that refuses writes)");
    }
    let clusters = v.fat32.lock().data_clusters;
    let Some(mut marks) = Marks::new(clusters) else {
        azos_drv_sys::kprintln!("[FAT32] check: volume too large or heap short, lost clusters not scanned");
        return;
    };
    let mut stack = alloc::vec::Vec::new();
    let root = v.fat32.lock().root_cluster;
    let scanned = (|| -> Result<(), ()> {
        if !check_mark_chain(v, root, &mut marks, rep)? { return Err(()); }
        stack.try_reserve(1).map_err(|_| ())?;
        stack.push(root);
        while let Some(dir) = stack.pop() {
            check_scan_dir(v, dir, &mut marks, &mut stack, rep)?;
        }
        Ok(())
    })();
    rep.complete = scanned.is_ok();
    if !rep.complete {
        azos_drv_sys::kprintln!("[FAT32] check: directory scan incomplete, nothing reclaimed");
    }
    let reclaim = rep.complete && !cfg!(feature = "fat-no-repair-canary");
    if check_reclaim_lost(v, &marks, reclaim, rep).is_err() {
        azos_drv_sys::kprintln!("[FAT32] check: FAT pass failed");
    }
}

/// Read the FAT entry for `cluster` to find the next cluster in the chain.
/// Returns Ok(next_cluster), where >= FAT32_EOC means end of chain.
fn fat32_next_cluster(v: &'static Vol, cluster: u32) -> Result<u32, ()> {
    let (fat_start, fat_sz32, data_clusters) = {
        let fv = v.fat32.lock();
        (fv.fat_start, fv.fat_sz32, fv.data_clusters)
    };

    // The FAT only has `fat_sz32 * 128` entries. Without this bound a cluster
    // number harvested from a crafted directory entry (up to 0x0FFFFFFF) walks
    // straight past the end of the table and the parser starts interpreting
    // *file data* — or anything else on the disk — as FAT entries, which is
    // both an information leak and a way to steer subsequent chain walks
    // anywhere on the medium.
    if cluster >= chain_walk_limit(fat_sz32, data_clusters) { return Err(()); }

    // Each FAT32 entry is 4 bytes; 512-byte sector holds 128 entries.
    // `cluster < fat_sz32 * 128` implies `cluster / 128 < fat_sz32`, and mount
    // already proved `fat_start + num_fats * fat_sz32` fits in u32, so this
    // add cannot overflow; checked anyway so the proof is not load-bearing.
    let fat_sector = fat_start
        .checked_add(cluster / FAT32_ENTRIES_PER_SECTOR)
        .ok_or(())?;
    let fat_offset = (cluster % FAT32_ENTRIES_PER_SECTOR) as usize;

    // FATCACHE: a cached FAT sector answers with its 4 bytes alone. A run
    // read walks the chain one cluster at a time (512 B clusters on the
    // shipped 32 MiB volumes), and copying the whole sector out per step
    // cost more than the data copy it was walking for.
    let mut entry_bytes = [0u8; 4];
    if !v.sector_cache.lock().lookup_bytes(fat_sector as u64, fat_offset * 4, &mut entry_bytes) {
        let mut buf = [0u8; SECTOR_SIZE];
        read_sector(v, fat_sector, &mut buf)?;
        entry_bytes.copy_from_slice(&buf[fat_offset * 4..fat_offset * 4 + 4]);
    }
    let entry = u32::from_le_bytes(entry_bytes);
    Ok(entry & 0x0FFF_FFFF)
}

/// Sectors [`fat32_read_chain`] asks the device for in one call, at most
/// (the driver splits it into its own DMA-sized requests).
const READ_RUN_MAX_SECTORS: u32 = 64;

/// Read volume sectors `[first, first + run)` into `dst` (exactly `run`
/// sectors long): the cached prefix from the cache, the rest in one device
/// request, which then fills the cache (not when `retain` is false: the page
/// cache's fills hold the data themselves, [`read_sector_with`]). Each cache
/// step takes the lock for one sector's copy only.
fn read_run_cached(v: &'static Vol, first: u32, run: u32, dst: &mut [u8], retain: bool) -> Result<(), ()> {
    let mut hit = 0u32;
    if !cfg!(feature = "fatcache-run-bypass-canary") {
        while hit < run {
            let o = hit as usize * SECTOR_SIZE;
            let line = &mut dst[o..o + SECTOR_SIZE];
            if !v.sector_cache.lock().lookup((first + hit) as u64, line) {
                break;
            }
            hit += 1;
        }
    }
    if hit == run {
        return Ok(());
    }
    let token = if cfg!(feature = "fatcache-token-canary") {
        0
    } else {
        v.sector_cache.lock().lookup_miss_token()
    };
    let o = hit as usize * SECTOR_SIZE;
    crate::census::count(crate::census::DEV_READS);
    v.dev.read_quiet(dev_lba(v, (first + hit) as u64), run - hit, &mut dst[o..])?;
    for k in hit..run {
        let o = k as usize * SECTOR_SIZE;
        let mut c = v.sector_cache.lock();
        // Write-back: a line present now is newer than the device's copy
        // (dirty, or written after the read) — it answers, not the device.
        if v.knobs.writeback && c.mode() == crate::bcache::Mode::WriteBack && !cfg!(feature = "wb-run-overlay-canary")
            && c.peek((first + k) as u64, &mut dst[o..o + SECTOR_SIZE])
        {
            continue;
        }
        // The canary installs whatever the device returned, however stale:
        // the token is re-read after the fact instead of before the read.
        let t = if cfg!(feature = "fatcache-token-canary") { c.lookup_miss_token() } else { token };
        if retain {
            c.install((first + k) as u64, &dst[o..o + SECTOR_SIZE], t);
        }
    }
    Ok(())
}

/// [`fat32_read_range_on`] on the boot volume ([`BOOT`]).
#[inline]
pub fn fat32_read_range(first: u32, size: u32, offset: u32, dst: &mut [u8], retain: bool) -> usize {
    fat32_read_range_on(&BOOT, first, size, offset, dst, retain)
}

/// Read up to `dst.len()` bytes at byte `offset` of the file whose chain
/// starts at `first` and whose size is `size`; bytes copied (0 at or past
/// EOF, or when the chain is shorter than the size claims).
///
/// The read-only stream's reader (wave 14). One walk to the cluster holding
/// `offset`, then forward only. A sector the request covers whole goes
/// through [`read_run_cached`] straight into `dst` — contiguous clusters
/// joined into one run, as `fat32_read_chain` does — so a cold read is one
/// device request per run and a warm one is one cache copy per sector; a
/// partial sector is copied out of its cached line in place
/// (`lookup_bytes`), with no 512-byte staging copy.
///
/// `retain: false` (the page cache's fills) leaves the data sectors it reads
/// out of the block cache: a resident line still answers, a miss is read from
/// the device and not installed ([`read_sector_with`]).
pub fn fat32_read_range_on(v: &'static Vol, first: u32, size: u32, offset: u32, dst: &mut [u8], retain: bool) -> usize {
    if offset >= size || dst.is_empty() { return 0; }
    let len = dst.len().min((size - offset) as usize);
    let (a, b) = {
        use core::sync::atomic::Ordering::Acquire;
        (v.stream_geom_a.load(Acquire), v.stream_geom_b.load(Acquire))
    };
    let (spc, data_start) = ((a >> 32) as u32, a as u32);
    let (fat_start, limit) = ((b >> 32) as u32, b as u32);
    if spc == 0 { return 0; }
    let bpc = spc as usize * SECTOR_SIZE;
    let mut fat = FatWindow::new(fat_start, limit);
    let mut steps = offset / bpc as u32;
    if first < FAT32_FIRST_DATA_CLUSTER || steps >= limit { return 0; }
    let mut cl = first;
    for _ in 0..steps {
        match fat.next(v, cl) {
            Ok(n) if n >= FAT32_FIRST_DATA_CLUSTER && n < FAT32_EOC => cl = n,
            _ => return 0,
        }
    }
    // Byte position of `cl`'s first byte, relative to `offset`'s cluster.
    let mut pos = offset as usize % bpc;
    let end = pos + len;
    let mut cl_base = 0usize;
    let mut done = 0usize;
    // The successor of `cl`, when a run already read it.
    let mut next_known: Option<u32> = None;
    while pos < end {
        if pos - cl_base >= bpc {
            if steps >= limit { break; }
            let n = match next_known.take() {
                Some(n) => n,
                None => match fat.next(v, cl) { Ok(n) => n, Err(()) => break },
            };
            if n < FAT32_FIRST_DATA_CLUSTER || n >= FAT32_EOC { break; }
            steps += 1;
            cl = n;
            cl_base += bpc;
        }
        let fs = match cluster_first_sector(data_start, cl, spc) { Some(v) => v, None => break };
        let in_cl = pos - cl_base;
        let s = (in_cl / SECTOR_SIZE) as u32;
        let o = in_cl % SECTOR_SIZE;
        let left = end - pos;
        if o == 0 && left >= SECTOR_SIZE {
            // Whole sectors: the rest of this cluster, then whole contiguous
            // clusters while the request lasts.
            let whole = (left / SECTOR_SIZE) as u32;
            let mut run = whole.min(spc - s);
            let mut tail = cl;
            let mut advanced = 0usize;
            if s + run == spc {
                while run < whole && run < READ_RUN_MAX_SECTORS && steps + 1 < limit {
                    let n = match fat.next(v, tail) { Ok(n) => n, Err(()) => break };
                    let contiguous = n >= FAT32_FIRST_DATA_CLUSTER && n < FAT32_EOC
                        && matches!(
                            (cluster_first_sector(data_start, n, spc), fs.checked_add(s + run)),
                            (Some(a), Some(b)) if a == b
                        );
                    if !contiguous {
                        next_known = Some(n);
                        break;
                    }
                    let take = spc.min(whole - run).min(READ_RUN_MAX_SECTORS - run);
                    run += take;
                    tail = n;
                    steps += 1;
                    advanced += 1;
                    if take < spc { break; }
                }
            }
            let bytes = run as usize * SECTOR_SIZE;
            if read_run_cached(v, fs + s, run, &mut dst[done..done + bytes], retain).is_err() { break; }
            done += bytes;
            pos += bytes;
            if advanced > 0 {
                cl = tail;
                cl_base += advanced * bpc;
            }
        } else {
            let chunk = left.min(SECTOR_SIZE - o);
            let out = &mut dst[done..done + chunk];
            if !v.sector_cache.lock().lookup_bytes((fs + s) as u64, o, out) {
                let mut sec = [0u8; SECTOR_SIZE];
                if read_sector_with(v, fs + s, &mut sec, retain).is_err() { break; }
                out.copy_from_slice(&sec[o..o + chunk]);
            }
            done += chunk;
            pos += chunk;
        }
    }
    done
}

/// One FAT sector held for the length of one [`fat32_read_range`]: a chain
/// walk asks for consecutive entries, 128 to a sector, so one copy out of
/// the cache serves them all instead of one locked lookup per cluster. Local
/// to the call, so it is no staler than reading the entries one by one.
/// The buffer is only filled (and only zeroed) when a walk first needs it,
/// so a read inside one cluster pays nothing for it.
struct FatWindow {
    fat_start: u32,
    limit: u32,
    sector: u32,
    buf: Option<[u8; SECTOR_SIZE]>,
}

impl FatWindow {
    fn new(fat_start: u32, limit: u32) -> Self {
        FatWindow { fat_start, limit, sector: 0, buf: None }
    }

    /// `fat32_next_cluster`, with the same bound.
    fn next(&mut self, v: &'static Vol, cluster: u32) -> Result<u32, ()> {
        if cluster >= self.limit { return Err(()); }
        let sector = self.fat_start.checked_add(cluster / FAT32_ENTRIES_PER_SECTOR).ok_or(())?;
        if self.buf.is_none() || self.sector != sector {
            let buf = self.buf.insert([0u8; SECTOR_SIZE]);
            if !v.sector_cache.lock().lookup(sector as u64, buf) {
                if read_sector(v, sector, buf).is_err() {
                    self.buf = None;
                    return Err(());
                }
            }
            self.sector = sector;
        }
        let b = self.buf.as_ref().ok_or(())?;
        let o = (cluster % FAT32_ENTRIES_PER_SECTOR) as usize * 4;
        let e = u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]]);
        Ok(e & 0x0FFF_FFFF)
    }
}

/// [`fat32_read_chain_on`] on the boot volume ([`BOOT`]).
#[inline]
pub fn fat32_read_chain(start_cluster: u32, out_buf: &mut [u8]) -> usize {
    fat32_read_chain_on(&BOOT, start_cluster, out_buf)
}

/// Read all data from a cluster chain into `out_buf`.
/// Returns bytes written.
pub fn fat32_read_chain_on(v: &'static Vol, start_cluster: u32, out_buf: &mut [u8]) -> usize {
    let (spc, data_start, fat_sz32, data_clusters) = {
        let fv = v.fat32.lock();
        (fv.secs_per_clus, fv.data_start, fv.fat_sz32, fv.data_clusters)
    };
    // Cycle guard — see `ChainWalk`. A self-referential FAT entry would
    // otherwise spin here forever whenever `out_buf` is larger than one cluster.
    let mut walk = ChainWalk::for_volume(fat_sz32, data_clusters);

    let mut cluster = start_cluster;
    let mut written = 0;

    while written < out_buf.len() {
        if cluster < FAT32_FIRST_DATA_CLUSTER || cluster >= FAT32_EOC { break; }
        if !walk.visit(cluster) { break; }

        // `None` means the cluster does not map to an addressable sector range
        // (crafted cluster number); stop rather than fabricate a sector.
        let first_sector = match cluster_first_sector(data_start, cluster, spc) {
            Some(v) => v,
            None => break,
        };

        // Wave 14: a run of whole clusters goes to the device in ONE read,
        // straight into `out_buf`. Sector by sector, a file cost one device
        // request per 512 bytes (the 8-line cache holds none of a file being
        // streamed, and evicted the FAT sector the chain walk needs), and a
        // request is a polled round trip: 40 of them for a 20 KiB image
        // every time it is spawned. The cache is write-through, never
        // dirty, so the device holds what a cached line would. A cluster the
        // buffer cannot take whole, and a chain that is not contiguous, go
        // through the per-sector path below as before.
        //
        // FATCACHE: the run is served from the sector cache as far as it
        // hits, sector by sector straight into `out_buf`; the rest of the
        // run is ONE device read into `out_buf`, whose sectors are then
        // installed. One token, taken before that read, covers every install:
        // a write of any sector (ours or an external one) while it was in
        // flight makes all of them refuse.
        let whole = ((out_buf.len() - written) / SECTOR_SIZE) as u32;
        if spc > 0 && whole >= spc && !cfg!(feature = "read-chain-sector-canary") {
            let mut run = spc;
            let mut next = fat32_next_cluster(v, cluster).ok();
            while let Some(n) = next {
                if n != cluster.wrapping_add(run / spc)
                    || n < FAT32_FIRST_DATA_CLUSTER || n >= FAT32_EOC
                    || run + spc > whole || run + spc > READ_RUN_MAX_SECTORS
                    || cluster_first_sector(data_start, n, spc) != first_sector.checked_add(run)
                    // Last: a visit is only taken by a cluster the run keeps.
                    || !walk.visit(n)
                {
                    break;
                }
                run += spc;
                next = fat32_next_cluster(v, n).ok();
            }
            let bytes = run as usize * SECTOR_SIZE;
            if read_run_cached(v, first_sector, run, &mut out_buf[written..written + bytes], true).is_err() {
                break;
            }
            written += bytes;
            match next {
                Some(n) => { cluster = n; continue; }
                None => break,
            }
        }

        for s in 0..spc {
            let remaining = out_buf.len() - written;
            if remaining == 0 { break; }
            let mut sec_buf = [0u8; SECTOR_SIZE];
            // `s < spc` and `cluster_first_sector` proved `first_sector + spc`
            // fits in u32, so this addition cannot overflow. A read error ends
            // the read, not just this cluster: following the chain past a
            // sector it could not read copied nothing and walked on, up to the
            // whole step bound (wave 15, GR4).
            if read_sector(v, first_sector + s, &mut sec_buf).is_err() {
                if cfg!(feature = "fat-walk-read-error-canary") { break; }
                return written;
            }
            let to_copy = remaining.min(SECTOR_SIZE);
            out_buf[written..written + to_copy].copy_from_slice(&sec_buf[..to_copy]);
            written += to_copy;
        }

        cluster = match fat32_next_cluster(v, cluster) {
            Ok(n) => n,
            Err(_) => break,
        };
    }

    written
}

/// [`fat32_lookup_root_on`] on the boot volume ([`BOOT`]).
#[inline]
pub fn fat32_lookup_root(name83: &[u8; 11]) -> Result<(u32, u32), ()> {
    fat32_lookup_root_on(&BOOT, name83)
}

/// Find a file in the root directory by short name (8.3 format, uppercased).
/// Returns (start_cluster, file_size) or Err if not found.
pub fn fat32_lookup_root_on(v: &'static Vol, name83: &[u8; 11]) -> Result<(u32, u32), ()> {
    fat32_lookup_root_entry_on(v, name83).map(|e| (e.cluster, e.size))
}

/// A name on the volume, resolved: the directory it is in and its 8.3 name
/// there, with the VFS key (the canonical path, [`key_of_path`]) that is also
/// the page cache's name for the file. Every change to a file goes through
/// one of these, so the root directory is a case of a directory, not a
/// separate code path.
#[derive(Clone, Copy)]
struct FName {
    /// First cluster of the directory.
    dir: u32,
    /// The name inside it.
    name: [u8; 11],
    key: crate::vfs::InodeKey,
}

impl FName {
    /// A file of the root directory.
    fn root(v: &'static Vol, name83: &[u8; 11]) -> FName {
        let mut path = [0u8; 13];
        let n = name83_to_path(name83, &mut path);
        let mut key = crate::vfs::ZEROED_KEY;
        // Without the leading slash, as every key is.
        key.bytes[..n - 1].copy_from_slice(&path[1..n]);
        FName { dir: v.fat32.lock().root_cluster, name: *name83, key }
    }

    /// The file a VFS key names: its directories walked from the root.
    /// `NotFound` when one of them is missing, `WrongType` when one is a file.
    fn of_key(v: &'static Vol, key: &crate::vfs::InodeKey) -> Result<FName, FsError> {
        let n = key.bytes.iter().position(|&b| b == 0).unwrap_or(crate::vfs::INODE_KEY_LEN);
        let (dir, last) = resolve_parent(v, &key.bytes[..n])?;
        let name = component_to_83(last).ok_or(FsError::InvalidArg)?;
        Ok(FName { dir, name, key: *key })
    }

    /// Both name the same directory entry.
    fn same(&self, other: &FName) -> bool {
        self.dir == other.dir && self.name == other.name
    }
}

/// The VFS key of the file `path` names: its components as 8.3 names in
/// upper case, `NAME.EXT` (no dot without an extension), joined by `/`, no
/// leading slash, NUL-padded: `PKG/SYS_B/KERN.BIN`. The key is the path and
/// not a cluster number, so it stays right across a rename of a directory or
/// a directory removed and made again, and it is the page cache's name for
/// the file. `None` for a path with no component, a component that is not an
/// 8.3 name, more than `FAT32_MAX_PATH_DEPTH` of them, or one that does not
/// fit the key (63 bytes).
fn key_of_path(path: &[u8]) -> Option<crate::vfs::InodeKey> {
    let mut comps: [&[u8]; FAT32_MAX_PATH_DEPTH] = [&[]; FAT32_MAX_PATH_DEPTH];
    let n = split_path(path, &mut comps).ok()?;
    if n == 0 { return None; }
    let mut key = crate::vfs::ZEROED_KEY;
    let mut at = 0;
    for (i, c) in comps[..n].iter().enumerate() {
        let name83 = component_to_83(c)?;
        let mut text = [0u8; 13];
        let len = name83_to_path(&name83, &mut text);
        // `name83_to_path` leads with the separator: the key's first
        // component has none.
        let part = if i == 0 { &text[1..len] } else { &text[..len] };
        if at + part.len() >= crate::vfs::INODE_KEY_LEN { return None; }
        key.bytes[at..at + part.len()].copy_from_slice(part);
        at += part.len();
    }
    Some(key)
}

/// A root-directory entry's fields, as [`fat32_lookup_root_entry`] finds
/// them: what `FileSystem::stat` reports.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RootEntry {
    pub cluster:  u32,
    pub size:     u32,
    pub attr:     u8,
    pub wrt_date: u16,
    pub wrt_time: u16,
    pub crt_date: u16,
    pub crt_time: u16,
    pub acc_date: u16,
}

/// [`fat32_lookup_root_entry_on`] on the boot volume ([`BOOT`]).
#[inline]
pub fn fat32_lookup_root_entry(name83: &[u8; 11]) -> Result<RootEntry, ()> {
    fat32_lookup_root_entry_on(&BOOT, name83)
}

/// [`fat32_lookup_root`], keeping the whole entry: attributes and the DOS
/// dates and times. The same single scan.
pub fn fat32_lookup_root_entry_on(v: &'static Vol, name83: &[u8; 11]) -> Result<RootEntry, ()> {
    let root = v.fat32.lock().root_cluster;
    lookup_entry(v, root, name83)
}

/// [`fat32_lookup_root_entry`] in any directory (`dir`: its first cluster).
fn lookup_entry(v: &'static Vol, dir: u32, name83: &[u8; 11]) -> Result<RootEntry, ()> {
    // Wave 14: the generation BEFORE the scan stamps what the scan finds, so
    // a write that lands while it runs leaves the entry already stale.
    let gen = v.write_gen.load(core::sync::atomic::Ordering::Acquire);
    // Canary: the cache is blind to the directory, as it was when only the
    // root had files (a file of the same name below it is answered for).
    let cdir = if cfg!(feature = "dir-blind-dcache-canary") { 0 } else { dir };
    if let Some(e) = dcache_get(v, cdir, name83, gen) { return Ok(e); }
    let e = lookup_entry_scan(v, dir, name83)?;
    dcache_put(v, cdir, name83, gen, e);
    Ok(e)
}

// ── Directory entry cache (wave 14) ──────────────────────────────────────────
//
// `open("/fat/NAME")` scans the root directory: on the shipped 32 MiB volume,
// with long-name entries beside every short one, VSBENCH.ELF is the 34th slot,
// three sectors and two FAT steps in — about 6.6k instructions, all of them
// cache hits. This table answers a repeat by name in one probe. An entry is
// good only while `WRITE_GEN` is what it was BEFORE the scan that found it:
// any write of the volume (ours or another writer's), mount and unmount move
// it, so nothing here outlives a change of the directory — the same rule the
// read-only streams follow. Positive answers only.

const DCACHE_SLOTS: usize = 16;

#[derive(Clone, Copy)]
struct Dentry { gen: u32, dir: u32, name: [u8; 11], e: RootEntry }

const NO_DENTRY: Dentry = Dentry {
    gen: 0,
    dir: 0,
    name: [0u8; 11],
    e: RootEntry { cluster: 0, size: 0, attr: 0, wrt_date: 0, wrt_time: 0, crt_date: 0, crt_time: 0, acc_date: 0 },
};

#[inline]
fn dcache_slot(dir: u32, name: &[u8; 11]) -> usize {
    let mut h = dir;
    for &b in name { h = h.wrapping_mul(31).wrapping_add(b as u32); }
    (h as usize) % DCACHE_SLOTS
}

fn dcache_get(v: &'static Vol, dir: u32, name: &[u8; 11], gen: u32) -> Option<RootEntry> {
    let d = v.dcache.lock()[dcache_slot(dir, name)];
    let fresh = d.gen == gen || cfg!(feature = "dcache-stale-canary");
    (d.gen != 0 && fresh && d.dir == dir && d.name == *name).then_some(d.e)
}

fn dcache_put(v: &'static Vol, dir: u32, name: &[u8; 11], gen: u32, e: RootEntry) {
    v.dcache.lock()[dcache_slot(dir, name)] = Dentry { gen, dir, name: *name, e };
}

fn lookup_entry_scan(v: &'static Vol, dir: u32, name83: &[u8; 11]) -> Result<RootEntry, ()> {
    if !v.fat32.lock().mounted { return Err(()); }

    let (spc, data_start, fat_sz32, data_clusters) = {
        let fv = v.fat32.lock();
        (fv.secs_per_clus, fv.data_start, fv.fat_sz32, fv.data_clusters)
    };
    // Cycle guard — see `ChainWalk`. Reachable from ring 3 via open().
    let mut walk = ChainWalk::for_volume(fat_sz32, data_clusters);

    let mut cluster = dir;
    while cluster >= FAT32_FIRST_DATA_CLUSTER && cluster < FAT32_EOC {
        if !walk.visit(cluster) { return Err(()); }

        // `None` = crafted cluster number that does not map into the sector
        // space; treat as "not found" rather than fabricating a sector.
        let first_sector = match cluster_first_sector(data_start, cluster, spc) {
            Some(v) => v,
            None => return Err(()),
        };

        for s in 0..spc {
            let mut sec_buf = [0u8; SECTOR_SIZE];
            // U09-12 (same class as `fat32_creat_root_dirent`): a swallowed
            // read error left `sec_buf` all-zero, and `entry.name[0] == 0`
            // reads exactly like a legitimate end-of-directory marker —
            // "not found" for the wrong reason, indistinguishable from the
            // right one at the call site. Propagate instead.
            // s < spc, and cluster_first_sector proved first_sector + spc fits.
            read_sector(v, first_sector + s, &mut sec_buf)?;

            // 16 directory entries per 512-byte sector
            for e in 0..DIRENTS_PER_SECTOR {
                let off = e * DIRENT_SIZE;
                let entry = unsafe {
                    &*(sec_buf[off..off + 32].as_ptr() as *const Fat32Dirent)
                };
                if entry.name[0] == 0x00 { return Err(()); }  // End of directory
                if entry.name[0] == 0xE5 { continue; }        // Deleted
                if entry.attr == ATTR_LFN { continue; }        // LFN entry
                if entry.attr & ATTR_VOLUME_ID != 0 { continue; }

                let mut ent_name = [0u8; 11];
                ent_name[..8].copy_from_slice(&entry.name);
                ent_name[8..11].copy_from_slice(&entry.ext);
                if &ent_name == name83 {
                    let cluster_hi = entry.fst_clus_hi as u32;
                    let cluster_lo = entry.fst_clus_lo as u32;
                    let file_cluster = (cluster_hi << 16) | cluster_lo;
                    return Ok(RootEntry {
                        cluster: file_cluster, size: entry.file_size, attr: entry.attr,
                        wrt_date: entry.wrt_date, wrt_time: entry.wrt_time,
                        crt_date: entry.crt_date, crt_time: entry.crt_time,
                        acc_date: entry.lst_acc_date,
                    });
                }
            }
        }

        cluster = fat32_next_cluster(v, cluster).unwrap_or(FAT32_EOC);
    }
    Err(())
}

/// [`fat32_mounted_on`] on the boot volume ([`BOOT`]).
#[inline]
pub fn fat32_mounted() -> bool {
    fat32_mounted_on(&BOOT)
}

/// Returns true if FAT32 is mounted.
pub fn fat32_mounted_on(v: &'static Vol) -> bool {
    v.fat32.lock().mounted
}

// ── Write support (Phase 8) ───────────────────────────────────────────────────

/// Write a single 512-byte sector via VirtIO block.
///
/// Updates the in-memory sector cache so a subsequent read sees the
/// fresh contents (write-through). Without invalidation a later
/// read_sector() would return stale cached data even after a write.
fn write_sector(v: &'static Vol, sector: u32, buf: &[u8; SECTOR_SIZE]) -> Result<(), ()> {
    write_sector_in(v, sector, buf, false)
}

/// [`write_sector`] into the epoch after the current one, with no barrier
/// (`BlockCache::write_dirty_ahead`); write-back only — a write-through
/// cache answers `Uncached` and the sector goes to the device now, which
/// the caller must have ordered itself. For a directory entry that names
/// data and a chain written in the current epoch (wave 15, FW).
fn write_sector_ahead(v: &'static Vol, sector: u32, buf: &[u8; SECTOR_SIZE]) -> Result<(), ()> {
    write_sector_in(v, sector, buf, true)
}

fn write_sector_in(v: &'static Vol, sector: u32, buf: &[u8; SECTOR_SIZE], ahead: bool) -> Result<(), ()> {
    if v.knobs.writeback {
        loop {
            let r = if ahead {
                v.sector_cache.lock().write_dirty_ahead(sector as u64, buf)
            } else {
                v.sector_cache.lock().write_dirty(sector as u64, buf)
            };
            match r {
                crate::bcache::Dirty::Done { first } => {
                    if first {
                        v.wb_dirty_since.store(wb_now_ms(), core::sync::atomic::Ordering::Relaxed);
                    }
                    write_gen_bump(v);
                    let (dirty, lines) = fat32_writeback_dirty_on(v);
                    if wb_over_watermark(dirty, lines) { wb_wake(); }
                    return Ok(());
                }
                crate::bcache::Dirty::NeedWriteback(epoch) => {
                    let claim = wb_claim(v);
                    if wb_write_back(v, &claim, epoch, false).is_err() {
                        write_gen_bump(v);
                        return Err(());
                    }
                }
                crate::bcache::Dirty::Uncached => break,
            }
        }
    }
    write_sector_device(v, sector, buf)
}

/// [`write_sector`] straight to the device, never through the dirty cache.
/// The cache line, if present, is updated. For a write that must be on the
/// medium (or fail) now, with nothing queued behind it to retry or reorder:
/// the volume's clean/dirty flag. The caller has no dirty lines pending, or
/// this write would carry their sector's newer bytes ahead of their epoch.
fn write_sector_direct(v: &'static Vol, sector: u32, buf: &[u8; SECTOR_SIZE]) -> Result<(), ()> {
    write_sector_device(v, sector, buf)
}

fn write_sector_device(v: &'static Vol, sector: u32, buf: &[u8; SECTOR_SIZE]) -> Result<(), ()> {
    // Quiet: this path keeps the cache coherent itself, just below; the
    // block layer's observer is for writers that do not.
    // Gate canary only: the bump BEFORE the bytes land (the class of order
    // the comment below rules out).
    if cfg!(feature = "write-gen-early-canary") { write_gen_bump(v); }
    pi_io_probe();
    let r = v.dev.write_quiet(dev_lba(v, sector as u64), 1, buf);
    if r.is_err() {
        // What the device holds now is unknown; the old line must not answer.
        v.sector_cache.lock().invalidate(sector as u64);
    } else if !cfg!(feature = "fatcache-writethrough-canary") {
        // Update the line if present (write-through). Cheaper than a straight
        // invalidate because the next reader pays no miss cost. Never installs.
        v.sector_cache.lock().update_if_present(sector as u64, buf);
    }
    // Whatever the device answered, a directory entry or a FAT link may have
    // moved: every read-only stream looks its name up again. After the cache
    // line is current (wave 14, SPAWNCACHE): bumped before it, a reader could
    // load the new generation, read the old line, and stamp old bytes with a
    // generation no later write moves.
    if !cfg!(feature = "write-gen-early-canary") {
        write_gen_bump(v);
    }
    if r.is_err() { return Err(()); }
    Ok(())
}

/// Write a FAT32 entry for `cluster` to all FAT table copies.
///
/// The upper 4 bits of the existing entry are preserved (as per FAT32 spec).
/// Claims the entry's FAT sector for the read-modify-write
/// ([`fat_sector_claim`]); never call it while holding a claim.
fn fat32_write_fat_entry(v: &'static Vol, cluster: u32, value: u32) -> Result<(), ()> {
    let _claim = fat_sector_claim(v, cluster / FAT32_ENTRIES_PER_SECTOR);
    fat32_write_fat_entry_claimed(v, cluster, value)
}

/// The body of [`fat32_write_fat_entry`], for a caller that already holds the
/// claim on `cluster`'s FAT sector (the allocator, which re-read that sector
/// under it). Without the claim this is the lost-update race the claim closes.
fn fat32_write_fat_entry_claimed(v: &'static Vol, cluster: u32, value: u32) -> Result<(), ()> {
    let (fat_start, fat_sz32, num_fats, data_clusters) = {
        let fv = v.fat32.lock();
        (fv.fat_start, fv.fat_sz32, fv.num_fats, fv.data_clusters)
    };

    // Bound the cluster against the actual FAT size *here*, not only in the
    // callers. This function does a read-modify-write at
    // `fat_start + cluster/128` in EVERY FAT copy, so an unbounded `cluster`
    // is an arbitrary 4-byte disk write. The journal at LBA 1 lives inside the
    // attacker-writable volume and feeds a cluster number straight into this
    // function during `fat32_journal_recover()`, i.e. automatically on the next
    // mount, before anything else touches the disk. Clusters 0 and 1 hold the
    // media descriptor / dirty flags and are never legitimate targets.
    if fat_sz32 == 0 { return Err(()); }
    if cluster < FAT32_FIRST_DATA_CLUSTER || cluster >= chain_walk_limit(fat_sz32, data_clusters) {
        return Err(());
    }

    let fat_sector_off = cluster / FAT32_ENTRIES_PER_SECTOR;
    let fat_byte_off   = (cluster % FAT32_ENTRIES_PER_SECTOR) as usize * 4;

    // Read sector from FAT copy 0 for modification.
    let mut buf = [0u8; SECTOR_SIZE];
    read_sector(v, fat_start.checked_add(fat_sector_off).ok_or(())?, &mut buf)?;

    // Preserve upper nibble of the existing entry (FAT32 spec requirement).
    let cur = u32::from_le_bytes([
        buf[fat_byte_off], buf[fat_byte_off + 1],
        buf[fat_byte_off + 2], buf[fat_byte_off + 3],
    ]);
    let new_val = (cur & 0xF000_0000) | (value & 0x0FFF_FFFF);
    let bytes = new_val.to_le_bytes();
    buf[fat_byte_off..fat_byte_off + 4].copy_from_slice(&bytes);

    // Any cached free count is stale from here on, whether or not every copy
    // below is written: bump before the first write, not after.
    free_count_invalidate(v);

    // Write updated sector to all FAT copies.
    // `num_fats` and `fat_sz32` are both straight out of the BPB; compute each
    // copy's sector with checked arithmetic so a bogus geometry errors out
    // instead of aborting the kernel on overflow.
    let copies = num_fats.max(1) as u32;
    for i in 0..copies {
        let sec = i
            .checked_mul(fat_sz32)
            .and_then(|off| fat_start.checked_add(off))
            .and_then(|base| base.checked_add(fat_sector_off))
            .ok_or(())?;
        write_sector(v, sec, &buf)?;
    }
    // And again after: a statfs scan on another hart that started after the
    // bump above but read this FAT sector before the write landed must not
    // find its generation unchanged and publish the stale count.
    free_count_invalidate(v);
    Ok(())
}

/// [`fat32_alloc_cluster_on`] on the boot volume ([`BOOT`]).
#[inline]
pub fn fat32_alloc_cluster() -> Result<u32, ()> {
    fat32_alloc_cluster_on(&BOOT)
}

/// Scan the FAT for a free cluster (entry == 0), mark it as end-of-chain,
/// and return its cluster number.
///
/// No lock spans the scan (F1: nothing is held across the device reads it
/// may miss into). A candidate is confirmed under its FAT sector's claim
/// ([`fat_sector_claim`]): the sector is re-read there — every write to it
/// happens under that claim, so the copy read is current — and the first
/// entry still free is marked. If another updater took them all in between,
/// the scan moves on.
pub fn fat32_alloc_cluster_on(v: &'static Vol) -> Result<u32, ()> {
    #[cfg(any(feature = "fat-mutate-spin-canary", feature = "fat-mutate-pi-canary"))]
    let _canary = FAT_MUTATE_CANARY.lock();
    fat32_alloc_cluster_inner(v)
}

fn fat32_alloc_cluster_inner(v: &'static Vol) -> Result<u32, ()> {
    match alloc_scan(v) {
        Ok(c) => Ok(c),
        // Full, but chains are held for the next flush (`defer_free`):
        // flush now, which frees every held chain, and scan once more.
        // Not in the FAT_MUTATE canary builds, whose caller may hold the
        // lock the flush's frees would take.
        Err(()) if fat32_held_clusters_on(v) > 0
            && !cfg!(any(feature = "fat-mutate-spin-canary", feature = "fat-mutate-pi-canary"))
            && device_flush(v).is_ok() => alloc_scan(v),
        Err(()) => Err(()),
    }
}

/// One scan of the FAT for a free entry (see [`fat32_alloc_cluster`]).
fn alloc_scan(v: &'static Vol) -> Result<u32, ()> {
    // **Closed by the write-path audit, 2026-09-23 — this does NOT hand back
    // an out-of-range cluster, and here is why rather than an assertion.**
    // This scans `0..fat_sz32` sectors of FAT entries in ascending cluster
    // order, and `fat32_write_fat_entry_claimed` below (called with `?`)
    // refuses to mark any cluster `>= chain_walk_limit(fat_sz32,
    // data_clusters)`. Every in-range cluster number sorts below every
    // out-of-range one, so the scan always exhausts the legitimate range
    // before it can reach an illegitimate free entry — "no free cluster in
    // range" and "the first free entry found is out of range" are the same
    // event on this volume, and both correctly return `Err(())`. Verified with
    // a discriminating host test (`alloc_cluster_never_hands_out_a_cluster_past_the_data_region`
    // in fs-tests).
    let (fat_start, fat_sz32, root_cluster, data_clusters) = {
        let fv = v.fat32.lock();
        (fv.fat_start, fv.fat_sz32, fv.root_cluster, fv.data_clusters)
    };
    if fat_sz32 == 0 { return Err(()); }
    // Entries past the data region read free in the FAT's last sector; a
    // scan that starts mid-FAT reaches them before it wraps to the free
    // clusters below, so they are skipped here, not refused.
    let last_valid = data_clusters.saturating_add(FAT32_FIRST_DATA_CLUSTER);

    // Wave 15: start where the last allocation found room (FSInfo's
    // `nxt_free`, kept in RAM), wrapping once: a scan from FAT sector 0
    // walked every full sector before it on each allocation, and under the
    // write-back cache those reads evicted the clean lines a busy writer
    // needs. Same search order otherwise, so the same "disk full" verdict.
    let hint = if cfg!(feature = "alloc-hint-canary") {
        0
    } else {
        v.alloc_hint.load(core::sync::atomic::Ordering::Relaxed).min(fat_sz32 - 1)
    };
    for k in 0..fat_sz32 {
        let sec_idx = (hint + k) % fat_sz32;
        let mut buf = [0u8; SECTOR_SIZE];
        // Checked, not saturating: saturating would silently rescan the last
        // addressable sector and hand out a cluster number that does not
        // correspond to the entry we actually read.
        let sec = match fat_start.checked_add(sec_idx) { Some(v) => v, None => return Err(()) };
        if read_sector(v, sec, &mut buf).is_err() { return Err(()); }
        match first_free_in_fat_sector(&buf, sec_idx, root_cluster)? {
            Some(c) if c < last_valid => {}
            _ => continue,
        }
        // A candidate. Confirm it on a current copy of the sector, under its
        // claim, and mark it there.
        let _claim = fat_sector_claim(v, sec_idx);
        if read_sector(v, sec, &mut buf).is_err() { return Err(()); }
        let cluster = match first_free_in_fat_sector(&buf, sec_idx, root_cluster)? {
            Some(c) if c < last_valid => c,
            _ => continue, // another updater took them: scan on
        };
        // Mark as end-of-chain (allocated). A failure part-way leaves the
        // copies disagreeing — typically copy 0 marked and a mirror not — and
        // copy 0 is the one every scan reads, so the cluster would read
        // allocated and be referenced by nothing: one cluster leaked per
        // failed allocation. Put the entry back to free (best effort: if this
        // fails too, the device is failing and there is nothing better to do)
        // before reporting the failure.
        if fat32_write_fat_entry_claimed(v, cluster, 0x0FFF_FFFF).is_err() {
            let _ = fat32_write_fat_entry_claimed(v, cluster, 0);
            return Err(());
        }
        v.alloc_hint.store(sec_idx, core::sync::atomic::Ordering::Relaxed);
        return Ok(cluster);
    }
    Err(()) // Disk full
}

/// The first free entry in FAT sector `sec_idx` (contents `buf`), skipping
/// the reserved clusters 0/1 and the root directory's first cluster.
/// `Err` only on cluster-number overflow.
fn first_free_in_fat_sector(
    buf: &[u8; SECTOR_SIZE],
    sec_idx: u32,
    root_cluster: u32,
) -> Result<Option<u32>, ()> {
    for i in 0..FAT32_ENTRIES_PER_SECTOR {
        let cluster = sec_idx
            .checked_mul(FAT32_ENTRIES_PER_SECTOR)
            .and_then(|c| c.checked_add(i))
            .ok_or(())?;
        if cluster < FAT32_FIRST_DATA_CLUSTER { continue; }
        // The root directory's first cluster is in use whatever its FAT
        // entry says. A volume that marks it free (fs-fuzz, wave 12) used to
        // have it handed out: as a file's data over the root's entries, or as
        // the root's own extension, linking it to itself.
        if cluster == root_cluster { continue; }
        let off = (i * 4) as usize;
        let entry = u32::from_le_bytes([
            buf[off], buf[off + 1], buf[off + 2], buf[off + 3],
        ]) & 0x0FFF_FFFF;
        if entry == 0 { return Ok(Some(cluster)); }
    }
    Ok(None)
}

/// Bytes of zeros a swap file grows by per write.
const SWAP_ZERO_CHUNK: usize = 4096;

/// Cut a file to `new_size` bytes (`0 < new_size < e.size`), in place: the
/// chain keeps the clusters that cover `new_size` and the rest is freed. The
/// order is the one `truncate` to zero keeps for a whole chain: the new end of
/// the chain, then the entry's size, then the tail given back only once both
/// are durable (held until then, or freed after a barrier), so a cut leaves a
/// leaked tail (the mount check reclaims it), never a live entry over free
/// clusters. This is the swap file's shrink; an ordinary truncate to a length
/// that is not zero still rewrites the file (`Fat32Fs::truncate`).
fn fat32_trim_file(v: &'static Vol, f: &FName, e: RootEntry, new_size: u32) -> Result<(), crate::vfs::FsErr> {
    use crate::vfs::FsErr;
    let bpc = v.fat32.lock().bytes_per_clus.max(1);
    let keep = new_size.div_ceil(bpc).max(1);
    let last = chain_nth(v, e.cluster, keep - 1).map_err(fs_err)?;
    let tail = fat32_next_cluster(v, last).map_err(|()| FsErr::Io)?;
    let has_tail = tail >= FAT32_FIRST_DATA_CLUSTER && tail < FAT32_EOC;
    if has_tail {
        fat32_write_fat_entry(v, last, FAT32_END_OF_CHAIN).map_err(|()| FsErr::Io)?;
    }
    let (sector, off) = find_dirent_location(v, f.dir, &f.name).map_err(|()| FsErr::Io)?;
    dirent_clus_size_in(v, sector, off, e.cluster, new_size, false).map_err(|()| FsErr::Io)?;
    if has_tail {
        let gone = e.size.div_ceil(bpc).saturating_sub(keep).max(1);
        if defer_frees(v) {
            defer_free(v, tail, gone.saturating_mul(bpc)).map_err(fs_err)?;
        } else {
            order_barrier(v).or_else(|e| if e == FsError::Unsupported { Ok(()) } else { Err(e) }).map_err(fs_err)?;
            fat32_free_chain_on(v, tail);
        }
    }
    Ok(())
}

/// [`fat32_free_chain_on`] on the boot volume ([`BOOT`]).
#[inline]
pub fn fat32_free_chain(start: u32) {
    fat32_free_chain_on(&BOOT, start)
}

/// Free all clusters in a chain starting at `start`.
pub fn fat32_free_chain_on(v: &'static Vol, start: u32) {
    #[cfg(any(feature = "fat-mutate-spin-canary", feature = "fat-mutate-pi-canary"))]
    let _canary = FAT_MUTATE_CANARY.lock();
    free_chain_unlocked(v, start);
}

/// [`fat32_free_chain`] without the canaries' old lock: the release of held
/// chains runs inside an allocation that a canary build may call with that
/// lock held.
fn free_chain_unlocked(v: &'static Vol, start: u32) {
    // No hold across the walk: each entry write claims its own FAT sector
    // (`fat32_write_fat_entry`). `next` is read before its cluster is freed,
    // so a cluster an allocator takes the instant it is freed is never
    // followed.
    let (fat_sz32, data_clusters) = { let fv = v.fat32.lock(); (fv.fat_sz32, fv.data_clusters) };
    // Cycle guard — see `ChainWalk`. This loop looks self-terminating on
    // a cycle (freeing FAT[2] makes the next lookup return 0), but that relies
    // on the write succeeding: the `let _ =` swallows a device error, and
    // `fat32_write_fat_entry` now legitimately rejects out-of-range clusters,
    // so on either path the loop would revisit the same cluster forever.
    let mut walk = ChainWalk::for_volume(fat_sz32, data_clusters);

    let mut cluster = start;
    while cluster >= FAT32_FIRST_DATA_CLUSTER && cluster < FAT32_EOC {
        if !walk.visit(cluster) { break; }
        let next = fat32_next_cluster(v, cluster).unwrap_or(FAT32_EOC);
        let _ = fat32_write_fat_entry(v, cluster, 0); // Mark as free
        cluster = next;
    }
}

// ── Deferred frees (wave 15, `FS_DEFERRED_FREE`) ─────────────────────────────
//
// The chain an O_TRUNC to zero, an overwrite or a rename over a file takes
// away from its name is HELD: it stays allocated in the FAT, so the
// allocator cannot hand it out (it scans for zero entries), until the epoch
// holding the write that stopped naming it is durable. The flush that makes
// it durable (`device_flush`) then frees it, into the next epoch, with no
// flush of its own; the next flush carries it. Before it, a cut finds the
// chain still allocated and unnamed (a leak, never a live entry over free
// clusters, never the old file's clusters holding new bytes); after it, the
// unlinking entry is on the medium, so freeing and reusing the clusters can
// no longer reach a name. A journaled replacement holds its chain until its
// record is cleared: replaying a record whose clear did not land frees the
// old chain again, which must not have been reused.
//
// RAM only: a mount, an unmount or a writer of the medium that is not this
// file drops the list, and the chains leak (never freed wrongly).

/// One held chain: its first cluster (0 = slot empty), its clusters (from
/// the size that named it, for statfs) and the cache epoch whose flush
/// releases it.
#[derive(Copy, Clone)]
struct HeldChain { first: u32, clusters: u32, epoch: u64 }

const HELD_SLOTS: usize = azos_limits::FS_DEFERRED_FREE_SLOTS;

/// Whether a chain taken away now is held (write-back with
/// `FS_DEFERRED_FREE`). Write-through flushes at every barrier, so it keeps
/// the undeferred order.
fn defer_frees(v: &'static Vol) -> bool {
    azos_limits::FS_DEFERRED_FREE && wb_active(v)
}

/// [`fat32_held_clusters_on`] on the boot volume ([`BOOT`]).
#[inline]
pub fn fat32_held_clusters() -> u32 {
    fat32_held_clusters_on(&BOOT)
}

/// Clusters held for a later free (statfs counts them free).
pub fn fat32_held_clusters_on(v: &'static Vol) -> u32 {
    v.held_clusters.load(core::sync::atomic::Ordering::Relaxed)
}

/// Hold `first`'s chain (named by `size` bytes) until the epoch current now
/// is durable. Call it AFTER the write that stops naming the chain, so that
/// write is in this epoch or an earlier one. When every slot is taken, the
/// undeferred order: close the epoch, then free into the next one (the
/// write-back puts a flush between them). `Err` only from that barrier; the
/// chain then leaks.
fn defer_free(v: &'static Vol, first: u32, size: u32) -> Result<(), FsError> {
    if first < FAT32_FIRST_DATA_CLUSTER { return Ok(()); }
    if cfg!(feature = "deferred-free-canary") {
        // Canary: the chain is freed at once, in the unlinking write's own
        // epoch, and the allocator may reuse it there.
        fat32_free_chain_on(v, first);
        return Ok(());
    }
    let bpc = v.fat32.lock().bytes_per_clus.max(1);
    let clusters = size.div_ceil(bpc).max(1);
    // The top epoch: the unlinking write may be an entry written ahead
    // (`write_sector_ahead`), and the chain is held until it is durable.
    let epoch = v.sector_cache.lock().top_epoch();
    {
        let mut h = v.held.lock();
        if let Some(s) = h.iter_mut().find(|s| s.first == 0) {
            *s = HeldChain { first, clusters, epoch };
            v.held_clusters.fetch_add(clusters, core::sync::atomic::Ordering::Relaxed);
            return Ok(());
        }
    }
    // Every slot is taken. Write-back (wave 15, FW): close the epochs
    // (`barrier` returns the highest one closed) and free into the next
    // one this chain AND every held one: each unlinking write is in a
    // closed epoch, so the write-back puts a flush before the frees, as
    // write-through's "free one epoch later". One barrier then serves
    // `FS_DEFERRED_FREE_SLOTS` more holds, not one.
    if wb_active(v) && !cfg!(feature = "fw-free-one-held-canary") {
        // Through `barrier_closing`, like every other barrier, so the
        // `wb-barrier-flushes-canary` build flushes here too (FW2).
        let top = barrier_closing(v)?;
        fat32_free_chain_on(v, first);
        release_held(v, top);
        return Ok(());
    }
    match order_barrier(v) {
        // The flush made the unlinking write durable: the chain can be
        // discarded before it is freed.
        Ok(()) => {
            free_chain_discarding(v, first);
            return Ok(());
        }
        // A device that cannot flush gives no durability to discard behind.
        Err(FsError::Unsupported) => {}
        Err(e) => return Err(e),
    }
    fat32_free_chain_on(v, first);
    Ok(())
}

/// Free every held chain whose epoch is `<= upto`, which the caller has
/// just made durable. Called with no FAT32 lock and no write-back claim
/// held: the frees write FAT sectors through the cache, and the discards
/// (Kconfig `BLK_DISCARD`) wait for the device. Returns how many.
///
/// A released chain is discarded while it is still allocated, before its FAT
/// entries are freed: its unlinking write is durable (that is what released
/// it), so no name reaches it, and the allocator cannot hand it out until the
/// free, so no new data can be erased by the discard. `batched` gathers the
/// runs of every chain released here and discards them together before the
/// first free; `online` discards each chain's runs and frees it.
fn release_held(v: &'static Vol, upto: u64) -> usize {
    let mut n = 0;
    let discarding = discard_enabled(v);
    let batched = discarding && azos_limits::BLK_DISCARD_BATCHED;
    let mut waiting = [0u32; HELD_SLOTS];
    let mut held = 0;
    let mut batch = DiscardBatch::new();
    loop {
        let first = {
            let mut h = v.held.lock();
            match h.iter_mut().find(|s| s.first != 0 && s.epoch <= upto) {
                Some(s) => {
                    v.held_clusters.fetch_sub(s.clusters, core::sync::atomic::Ordering::Relaxed);
                    let f = s.first;
                    *s = HeldChain { first: 0, clusters: 0, epoch: 0 };
                    f
                }
                None => break,
            }
        };
        n += 1;
        if discarding {
            chain_runs(v, first, &mut batch);
            if batched {
                waiting[held] = first;
                held += 1;
                continue;
            }
            batch.issue(v);
        }
        free_chain_unlocked(v, first);
    }
    if held != 0 {
        batch.issue(v);
        for &first in &waiting[..held] {
            free_chain_unlocked(v, first);
        }
    }
    n
}

// ── Discard of released chains (Kconfig `BLK_DISCARD`) ───────────────────────

/// Is a released chain discarded at all (the option is on and the device has
/// not refused)?
fn discard_enabled(v: &'static Vol) -> bool {
    v.dev.discard_supported() && !v.discard_off.load(core::sync::atomic::Ordering::Relaxed)
}

/// Sector runs of freed clusters, gathered up to Kconfig `FS_DISCARD_RUNS`
/// and discarded together. Adjacent runs merge; a full batch is issued and a
/// new one started, so the gathering never fails.
struct DiscardBatch {
    runs: [(u64, u32); azos_limits::FS_DISCARD_RUNS as usize],
    n: usize,
}

impl DiscardBatch {
    const fn new() -> Self {
        DiscardBatch { runs: [(0, 0); azos_limits::FS_DISCARD_RUNS as usize], n: 0 }
    }

    /// Add `sectors` sectors from sector `first` of the volume.
    fn add(&mut self, v: &'static Vol, first: u64, sectors: u32) {
        let lba = dev_lba(v, first);
        for r in &mut self.runs[..self.n] {
            if r.0 + r.1 as u64 == lba {
                r.1 = r.1.saturating_add(sectors);
                return;
            }
            if lba + sectors as u64 == r.0 {
                *r = (lba, r.1.saturating_add(sectors));
                return;
            }
        }
        if self.n == self.runs.len() {
            self.issue(v);
        }
        self.runs[self.n] = (lba, sectors);
        self.n += 1;
    }

    /// Discard what has been gathered, wait for it, and start over. The
    /// device's answer is a hint's: a refusal switches discard off for this
    /// mount, a failure is dropped (the clusters are freed either way).
    fn issue(&mut self, v: &'static Vol) {
        if self.n == 0 {
            return;
        }
        match v.dev.discard(&self.runs[..self.n]) {
            Ok(()) | Err(DiscardError::Io) => {}
            Err(DiscardError::Unsupported) => {
                v.discard_off.store(true, core::sync::atomic::Ordering::Relaxed);
            }
        }
        self.n = 0;
    }
}

/// Add the clusters of the chain starting at `start`, as runs of contiguous
/// clusters, to `batch`. The chain is still allocated: the walk is the one
/// `free_chain_unlocked` makes, with the same cycle guard.
fn chain_runs(v: &'static Vol, start: u32, batch: &mut DiscardBatch) {
    let (fat_sz32, data_clusters, spc, data_start) = {
        let fv = v.fat32.lock();
        (fv.fat_sz32, fv.data_clusters, fv.secs_per_clus, fv.data_start)
    };
    let mut walk = ChainWalk::for_volume(fat_sz32, data_clusters);
    // The run being built: its first cluster and its length in clusters.
    let (mut first, mut len) = (0u32, 0u32);
    let mut cluster = start;
    let mut put = |first: u32, len: u32| {
        if len != 0 {
            if let Some(sec) = cluster_first_sector(data_start, first, spc) {
                batch.add(v, sec as u64, len.saturating_mul(spc));
            }
        }
    };
    while cluster >= FAT32_FIRST_DATA_CLUSTER && cluster < FAT32_EOC {
        if !walk.visit(cluster) { break; }
        if len != 0 && cluster == first + len {
            len += 1;
        } else {
            put(first, len);
            (first, len) = (cluster, 1);
        }
        cluster = fat32_next_cluster(v, cluster).unwrap_or(FAT32_EOC);
    }
    put(first, len);
}

/// Discard the chain at `start` and free it. For a chain whose unlinking
/// write is durable only.
fn free_chain_discarding(v: &'static Vol, start: u32) {
    if discard_enabled(v) {
        let mut batch = DiscardBatch::new();
        chain_runs(v, start, &mut batch);
        batch.issue(v);
    }
    fat32_free_chain_on(v, start);
}

/// Forget every held chain (they leak): a new volume, or the medium changed
/// under this file.
fn held_reset(v: &'static Vol) {
    let mut h = v.held.lock();
    for s in h.iter_mut() { *s = HeldChain { first: 0, clusters: 0, epoch: 0 }; }
    v.held_clusters.store(0, core::sync::atomic::Ordering::Relaxed);
    // A new mount asks the device again.
    v.discard_off.store(false, core::sync::atomic::Ordering::Relaxed);
}

/// Write `data` into the sectors of `cluster`, zero-padding the last sector.
fn fat32_write_cluster(v: &'static Vol, cluster: u32, data: &[u8]) -> Result<(), ()> {
    let (spc, data_start) = {
        let fv = v.fat32.lock();
        (fv.secs_per_clus, fv.data_start)
    };
    let first_sector = cluster_first_sector(data_start, cluster, spc).ok_or(())?;
    let mut written = 0usize;
    for s in 0..spc {
        let mut sec_buf = [0u8; SECTOR_SIZE];
        let remaining = data.len().saturating_sub(written);
        let to_copy   = remaining.min(SECTOR_SIZE);
        if to_copy > 0 {
            sec_buf[..to_copy].copy_from_slice(&data[written..written + to_copy]);
        }
        // s < spc, and cluster_first_sector proved first_sector + spc fits.
        write_sector(v, first_sector + s, &sec_buf)?;
        written += to_copy;
        if written >= data.len() { break; }
    }
    Ok(())
}

/// After a legitimate insert consumes a directory-end marker (`0x00`) at
/// `(cur_sector, entry_idx)`, make sure the very next slot a walker will
/// look at is also terminated.
///
/// `dir_find_in`, `fat32_lookup_root`, `fat32_ls_root` and `Fat32DirIter`
/// all stop scanning at the first `DIRENT_MARK_END` byte they see —
/// everything physically stored after it is, per the FAT spec, unused and
/// never read. The instant an insert overwrites that marker with a real
/// entry, whatever sits next on disk (later in this sector, the next sector
/// of this cluster, or the first sector of the next cluster already linked
/// in the chain) becomes reachable. On a freshly zeroed directory that byte
/// is `0x00` too, so nothing changes — but on a volume that is
/// attacker-controlled, or merely carries a longer on-disk chain than its
/// logical content (a directory once bigger, shrunk without trimming its
/// chain), it need not be. This makes the new terminator explicit instead
/// of trusting what happens to already be there.
///
/// Only marks slots that already exist in the chain — it must never
/// allocate a cluster, or inserting into a full directory would silently
/// grow it.
fn propagate_end_marker(
    v: &'static Vol, cluster: u32,
    sector_in_cluster: u32,
    cur_sector: u32,
    entry_idx: usize,
    entries_per_sector: usize,
    spc: u32,
    data_start: u32,
    cur_buf: &mut [u8; SECTOR_SIZE],
) -> Result<(), ()> {
    if entry_idx + 1 < entries_per_sector {
        // Same sector — the caller writes `cur_buf` back.
        cur_buf[(entry_idx + 1) * DIRENT_SIZE + DIRENT_OFF_NAME] = DIRENT_MARK_END;
        return Ok(());
    }
    // The next slot lives in a different sector. Staying within the same
    // cluster (`cur_sector + 1`) cannot overflow: the caller's own
    // `cluster_first_sector` already proved `first_sector + spc` fits.
    // Otherwise follow the chain to the next cluster, if any — never
    // allocate one; a chain that simply ends here is already correctly
    // terminated for every walker, which stops when the chain does.
    let next_sector = if sector_in_cluster + 1 < spc {
        Some(cur_sector + 1)
    } else {
        match fat32_next_cluster(v, cluster) {
            Ok(next_cluster)
                if next_cluster >= FAT32_FIRST_DATA_CLUSTER && next_cluster < FAT32_EOC =>
            {
                cluster_first_sector(data_start, next_cluster, spc)
            }
            _ => None,
        }
    };
    if let Some(sec) = next_sector {
        let mut buf = [0u8; SECTOR_SIZE];
        read_sector(v, sec, &mut buf)?;
        buf[DIRENT_OFF_NAME] = DIRENT_MARK_END;
        write_sector(v, sec, &buf)?;
    }
    Ok(())
}

/// [`fat32_unlink_root_on`] on the boot volume ([`BOOT`]).
#[inline]
pub fn fat32_unlink_root(name83: &[u8; 11]) -> Result<(), ()> {
    fat32_unlink_root_on(&BOOT, name83)
}

/// Mark a root-directory entry as deleted (first byte = 0xE5). ([`unlink_at`]
/// does it for a file in any directory.)
///
/// Uses journal for power-loss safety:
///   1. Write journal (PENDING, op=UNLINK)
///   2. Barrier (device flush)
///   3. Mark directory entry deleted
///   4. Barrier (device flush)
///   5. Write journal (COMMITTED)
///   6. Clear journal
///
/// Frees nothing: a caller that owns the chain frees it AFTER this returns
/// (see [`fat32_unlink_path`]), so the dirent is gone from the medium
/// before its clusters can be handed out again.
pub fn fat32_unlink_root_on(v: &'static Vol, name83: &[u8; 11]) -> Result<(), ()> {
    unlink_at(v, &FName::root(v, name83))
}

/// [`fat32_unlink_root`] for a file in any directory.
fn unlink_at(v: &'static Vol, f: &FName) -> Result<(), ()> {
    // Before, so the dirent goes with no dirty page waiting to create it
    // again; after, for a page a writer dirtied in between.
    cache_forget(v, &f.key);
    let r = unlink_inner(v, f.dir, &f.name);
    cache_forget(v, &f.key);
    r
}

fn unlink_inner(v: &'static Vol, dir: u32, name83: &[u8; 11]) -> Result<(), ()> {
    let (spc, data_start, fat_sz32, data_clusters) = {
        let fv = v.fat32.lock();
        (fv.secs_per_clus, fv.data_start, fv.fat_sz32, fv.data_clusters)
    };
    // Cycle guard — see `ChainWalk`.
    let mut walk = ChainWalk::for_volume(fat_sz32, data_clusters);

    let mut cluster = dir;
    while cluster >= FAT32_FIRST_DATA_CLUSTER && cluster < FAT32_EOC {
        if !walk.visit(cluster) { return Err(()); }
        let first_sector = match cluster_first_sector(data_start, cluster, spc) {
            Some(v) => v,
            None => return Err(()),
        };
        for s in 0..spc {
            let mut sec_buf = [0u8; SECTOR_SIZE];
            // s < spc, and cluster_first_sector proved first_sector + spc fits.
            // A read error ends the walk (wave 15, GR4): the name may be in
            // the sector it could not read, and skipping it walked on.
            if read_sector(v, first_sector + s, &mut sec_buf).is_err() {
                if cfg!(feature = "fat-walk-read-error-canary") { continue; }
                return Err(());
            }
            for e in 0..DIRENTS_PER_SECTOR {
                let off = e * DIRENT_SIZE;
                if sec_buf[off] == 0x00 { return Err(()); }  // End of directory
                if sec_buf[off] == 0xE5 { continue; }         // Already deleted
                let attr = sec_buf[off + 11];
                if attr == ATTR_LFN { continue; }
                if attr & ATTR_VOLUME_ID != 0 { continue; }
                let mut ent_name = [0u8; 11];
                ent_name[..8].copy_from_slice(&sec_buf[off..off + 8]);
                ent_name[8..11].copy_from_slice(&sec_buf[off + 8..off + 11]);
                if &ent_name == name83 {
                    // Step 1: Journal PENDING before modifying directory.
                    let sector_num = first_sector + s;
                    let journal = JournalEntry {
                        magic: JOURNAL_MAGIC,
                        state: JOURNAL_PENDING,
                        op_type: JOURNAL_OP_UNLINK,
                        _pad: [0; 2],
                        cluster: 0,
                        fat_value: 0,
                        dir_sector: sector_num,
                        dir_offset: off as u16,
                        size: 0,
                        _reserved: [0; JOURNAL_RESERVED_SIZE],
                    };
                    fat32_journal_write(v, &journal)?;
                    journal_barrier(v)?;

                    // Step 2: Mark deleted.
                    sec_buf[off] = 0xE5;
                    write_sector(v, sector_num, &sec_buf)?;
                    journal_barrier(v)?;

                    // Step 3: Journal COMMITTED.
                    let committed = JournalEntry {
                        magic: JOURNAL_MAGIC,
                        state: JOURNAL_COMMITTED,
                        op_type: JOURNAL_OP_UNLINK,
                        _pad: [0; 2],
                        cluster: 0,
                        fat_value: 0,
                        dir_sector: sector_num,
                        dir_offset: off as u16,
                        size: 0,
                        _reserved: [0; JOURNAL_RESERVED_SIZE],
                    };
                    fat32_journal_write(v, &committed)?;

                    // Step 4: Clear journal.
                    return fat32_journal_clear(v);
                }
            }
        }
        cluster = fat32_next_cluster(v, cluster).unwrap_or(FAT32_EOC);
    }
    Err(())
}

/// [`fat32_rename_on`] on the boot volume ([`BOOT`]).
#[inline]
pub fn fat32_rename(old_name83: &[u8; 11], new_name83: &[u8; 11]) -> Result<(), crate::vfs::FsErr> {
    fat32_rename_on(&BOOT, old_name83, new_name83)
}

/// Rename a root-directory file, replacing `new_name83` if it already
/// exists ([`rename_at`] does it for names in any directories) — what an OTA promotion needs (copy the staged image in under a
/// temp name, verify it, then atomically become the live image's name)
/// instead of writing the live name directly and having a failed
/// verification take the live image down with it.
///
/// **Atomic, as far as FAT allows (wave 15).** Over an existing file it is
/// one journal record (`JOURNAL_OP_RENAME`): a cut leaves either the old
/// destination with the source still present, or the new destination with
/// the source gone — never both names on one chain, never neither, and the
/// destination's bytes are the old file's or the new one's, whole. To a new
/// name it is an in-place rewrite of the source dirent's 8.3 name (one
/// sector write). What it does NOT promise: durability (an fsync/sync makes
/// it so). Together with an in-place write this is the atomic-replace recipe:
/// write a temp file, fsync it, rename it over the live name
/// (`vfs::vfs_replace_file`).
///
/// **Across directories** a file takes the same one-record path: a name that
/// is free is first made an empty entry in the target directory (a cut there
/// leaves the source whole and an empty file under the new name), and the
/// record then moves the chain onto it and deletes the source, so a cut never
/// leaves both names on the chain nor neither. A directory is not moved
/// across directories (`Unsupported`: its `..` would have to follow).
pub fn fat32_rename_on(
    v: &'static Vol, old_name83: &[u8; 11],
    new_name83: &[u8; 11],
) -> Result<(), crate::vfs::FsErr> {
    rename_at(v, &FName::root(v, old_name83), &FName::root(v, new_name83))
}

/// [`fat32_rename`] for names in any directories.
fn rename_at(v: &'static Vol, from: &FName, to: &FName) -> Result<(), crate::vfs::FsErr> {
    // A directory takes its files' keys with it (they are paths): everything
    // cached reaches the volume first and none of it is kept.
    let is_dir = fat32_lookup_dir_entry(v, from).is_some_and(|e| e.attr & ATTR_DIRECTORY != 0);
    if is_dir {
        crate::vfs::page_cache_flush_fs(v.fs)?;
    }
    // The source's cached bytes reach the file before it moves; what is cached
    // under either name is not the file's afterwards.
    crate::vfs::page_cache_flush_file(v.fs, &from.key)?;
    cache_forget(v, &to.key);
    let r = rename_inner(v, from, to);
    cache_forget(v, &from.key);
    if is_dir {
        crate::vfs::page_cache_drop(v.fs, None, 0);
    }
    r
}

/// The entry `f` names, if it exists.
fn fat32_lookup_dir_entry(v: &'static Vol, f: &FName) -> Option<RootEntry> {
    lookup_entry(v, f.dir, &f.name).ok()
}

fn rename_inner(v: &'static Vol, from: &FName, to: &FName) -> Result<(), crate::vfs::FsErr> {
    use crate::vfs::FsErr;
    // Every `Err(())` below is a block-device or journal failure, which is
    // what `Io` means; the answers that say WHY the call was refused are
    // decided up front, before anything is written.
    macro_rules! io { ($e:expr) => { $e.map_err(|_| FsErr::Io)? }; }

    if from.same(to) { return Ok(()); }
    let (old_name83, new_name83) = (&from.name, &to.name);
    let src = lookup_entry(v, from.dir, old_name83).map_err(|()| FsErr::NotFound)?;
    let (src_cluster, src_size) = (src.cluster, src.size);
    let src_is_dir = src.attr & ATTR_DIRECTORY != 0;
    let mut dest = lookup_entry(v, to.dir, new_name83).ok();
    if let Some(d) = &dest {
        let dest_is_dir = d.attr & ATTR_DIRECTORY != 0;
        // A directory is never a replacement target: the overwrite arm frees
        // the destination's chain, which for a directory is its contents. A
        // file onto a directory is `IsDir` (POSIX `EISDIR`), a directory onto
        // anything is `Exists` (this volume does not merge or replace
        // directories).
        if dest_is_dir && !src_is_dir { return Err(FsErr::IsDir); }
        if src_is_dir { return Err(FsErr::Exists); }
    }
    let across = from.dir != to.dir;
    if src_is_dir && across { return Err(FsErr::Unsupported); }
    let (src_sector, src_offset) = io!(find_dirent_location(v, from.dir, old_name83));
    if dest.is_none() && across {
        // The name is free in the other directory: an empty entry takes it
        // (the source's attributes), and the record below is then a rename
        // over an existing file whose chain is nothing to free.
        if cfg!(feature = "rename-across-unjournaled-canary") {
            // Canary: the chain is named in the target, then the source is
            // deleted, as two unrelated writes: a cut between them leaves
            // both names on one chain.
            io!(dir_insert(v, to.dir, new_name83, src_cluster, src_size, src.attr));
            io!(unlink_inner(v, from.dir, old_name83));
            return Ok(());
        }
        io!(dir_insert(v, to.dir, new_name83, 0, 0, src.attr));
        dest = Some(RootEntry { cluster: 0, size: 0, ..src });
    }

    match dest {
        Some(d) => {
            // Over an existing file: ONE journal record (`JOURNAL_OP_RENAME`)
            // covers the destination's new chain, the source's deletion and
            // the old chain's free. The first barrier puts the source chain
            // (written by an earlier call that need not have flushed it)
            // ahead of the record; once the record is durable, recovery
            // completes the rename.
            let dest_old_cluster = d.cluster;
            let defer = defer_frees(v);
            let (dest_sector, dest_offset) = io!(find_dirent_location(v, to.dir, new_name83));
            io!(journal_barrier(v));
            let mut reserved = [0u8; JOURNAL_RESERVED_SIZE];
            reserved[0..4].copy_from_slice(&src_sector.to_le_bytes());
            reserved[4..6].copy_from_slice(&src_offset.to_le_bytes());
            reserved[6..17].copy_from_slice(old_name83);
            let journal = JournalEntry {
                magic: JOURNAL_MAGIC,
                state: JOURNAL_PENDING,
                op_type: if cfg!(feature = "rename-two-records-canary") { JOURNAL_OP_OVERWRITE } else { JOURNAL_OP_RENAME },
                _pad: [0; 2],
                cluster: src_cluster,
                fat_value: dest_old_cluster,
                dir_sector: dest_sector,
                dir_offset: dest_offset,
                size: src_size,
                _reserved: reserved,
            };
            io!(fat32_journal_write(v, &journal));
            io!(journal_barrier(v));
            io!(rename_apply(v, dest_sector, dest_offset, src_sector, src_offset, old_name83,
                src_cluster, src_size, dest_old_cluster, !defer));
            io!(journal_barrier(v));
            let committed = JournalEntry { state: JOURNAL_COMMITTED, ..journal };
            io!(fat32_journal_write(v, &committed));
            io!(fat32_journal_clear(v));
            // Held until the clear is durable (`defer_free`): recovery of a
            // record whose clear did not land frees this chain again.
            if defer && dest_old_cluster >= FAT32_FIRST_DATA_CLUSTER && dest_old_cluster != src_cluster {
                let _ = defer_free(v, dest_old_cluster, d.size);
            }
        }
        None => {
            // To a new name: the source's own dirent is renamed in place —
            // eleven bytes of one sector, one device write, so a cut leaves
            // the old name or the new one, never both and never neither. The
            // slot, attributes, chain and size are untouched.
            let mut sec_buf = [0u8; SECTOR_SIZE];
            io!(read_sector(v, src_sector, &mut sec_buf));
            let o = src_offset as usize;
            if sec_buf[o..o + 11] != *old_name83 { return Err(FsErr::Io); }
            sec_buf[o..o + 11].copy_from_slice(new_name83);
            io!(write_sector(v, src_sector, &sec_buf));
        }
    }
    Ok(())
}

/// Scan directory `dir` for `name83`'s dirent location, read-only.
///
/// Split out of `fat32_unlink_root`'s scan so `fat32_write_file`'s overwrite
/// path can learn WHERE the old dirent lives before it commits to touching
/// anything — the journal entry it writes needs that location as ground
/// truth, recorded before the free/overwrite it is meant to make crash-safe.
fn find_dirent_location(v: &'static Vol, dir: u32, name83: &[u8; 11]) -> Result<(u32, u16), ()> {
    let (spc, data_start, fat_sz32, data_clusters) = {
        let fv = v.fat32.lock();
        (fv.secs_per_clus, fv.data_start, fv.fat_sz32, fv.data_clusters)
    };
    // Cycle guard — see `ChainWalk`.
    let mut walk = ChainWalk::for_volume(fat_sz32, data_clusters);

    let mut cluster = dir;
    while cluster >= FAT32_FIRST_DATA_CLUSTER && cluster < FAT32_EOC {
        if !walk.visit(cluster) { return Err(()); }
        let first_sector = match cluster_first_sector(data_start, cluster, spc) {
            Some(v) => v,
            None => return Err(()),
        };
        for s in 0..spc {
            let mut sec_buf = [0u8; SECTOR_SIZE];
            // A read error ends the walk (wave 15, GR4), as in
            // `fat32_unlink_root`.
            if read_sector(v, first_sector + s, &mut sec_buf).is_err() {
                if cfg!(feature = "fat-walk-read-error-canary") { continue; }
                return Err(());
            }
            for e in 0..DIRENTS_PER_SECTOR {
                let off = e * DIRENT_SIZE;
                if sec_buf[off] == 0x00 { return Err(()); }  // End of directory
                if sec_buf[off] == 0xE5 { continue; }         // Deleted
                let attr = sec_buf[off + DIRENT_OFF_ATTR];
                if attr == ATTR_LFN { continue; }
                if attr & ATTR_VOLUME_ID != 0 { continue; }
                let mut ent_name = [0u8; 11];
                ent_name[..8].copy_from_slice(&sec_buf[off..off + 8]);
                ent_name[8..11].copy_from_slice(&sec_buf[off + 8..off + 11]);
                if &ent_name == name83 {
                    return Ok((first_sector + s, off as u16));
                }
            }
        }
        cluster = fat32_next_cluster(v, cluster).unwrap_or(FAT32_EOC);
    }
    Err(())
}

/// Overwrite only the cluster-pointer and size fields of an EXISTING
/// directory entry at `(dir_sector, dir_offset)`; name/ext/attr are left
/// untouched.
///
/// A deterministic "set to this value" write, not a toggle: calling it twice
/// with the same arguments produces the same on-disk bytes both times. That
/// is what lets `fat32_journal_recover` replay it unconditionally for a
/// PENDING `OVERWRITE` entry — whether or not the original attempt already
/// got this far, replaying converges to the same state instead of doing
/// further damage.
fn fat32_update_dirent_clus_size(
    v: &'static Vol, dir_sector: u32, dir_offset: u16, cluster: u32, size: u32,
) -> Result<(), ()> {
    dirent_clus_size_in(v, dir_sector, dir_offset, cluster, size, false)
}

/// [`fat32_update_dirent_clus_size`], the sector written ahead
/// (`write_sector_ahead`) when `ahead`.
fn dirent_clus_size_in(
    v: &'static Vol, dir_sector: u32, dir_offset: u16, cluster: u32, size: u32, ahead: bool,
) -> Result<(), ()> {
    let off = dir_offset as usize;
    if off + DIRENT_SIZE > SECTOR_SIZE { return Err(()); }
    let mut sec_buf = [0u8; SECTOR_SIZE];
    read_sector(v, dir_sector, &mut sec_buf)?;
    let hi = ((cluster >> 16) & 0xFFFF) as u16;
    let lo = (cluster & 0xFFFF) as u16;
    sec_buf[off + DIRENT_OFF_FST_CLUS_HI]     = (hi & 0xFF) as u8;
    sec_buf[off + DIRENT_OFF_FST_CLUS_HI + 1] = (hi >> 8) as u8;
    sec_buf[off + DIRENT_OFF_FST_CLUS_LO]     = (lo & 0xFF) as u8;
    sec_buf[off + DIRENT_OFF_FST_CLUS_LO + 1] = (lo >> 8) as u8;
    sec_buf[off + DIRENT_OFF_FILE_SIZE]     = (size & 0xFF) as u8;
    sec_buf[off + DIRENT_OFF_FILE_SIZE + 1] = ((size >> 8) & 0xFF) as u8;
    sec_buf[off + DIRENT_OFF_FILE_SIZE + 2] = ((size >> 16) & 0xFF) as u8;
    sec_buf[off + DIRENT_OFF_FILE_SIZE + 3] = ((size >> 24) & 0xFF) as u8;
    if ahead { write_sector_ahead(v, dir_sector, &sec_buf) } else { write_sector(v, dir_sector, &sec_buf) }
}

/// Allocate a fresh cluster chain and write `data` into it, extending one
/// cluster at a time. Never called with empty `data` — callers special-case
/// that as cluster 0 (no chain), matching a FAT32 zero-length file.
fn fat32_alloc_and_write_chain(v: &'static Vol, data: &[u8], bytes_per_clus: usize) -> Result<u32, ()> {
    let fc = fat32_alloc_cluster_on(v)?;
    if fat32_write_chain_from(v, fc, data, bytes_per_clus).is_err() {
        fat32_free_chain_on(v, fc);
        return Err(());
    }
    Ok(fc)
}

/// Write `data` into a chain that starts at the already-allocated `fc`,
/// allocating and linking the rest. On `Err` the chain from `fc` is
/// well-formed (every allocated cluster is linked into it or was freed here)
/// and the caller owns freeing it.
///
/// Found by `tests/fuzz/fs-fuzz` (wave 11): this loop used to `?` out of the
/// middle of a chain — disk full is the everyday case — and no caller freed
/// what it had taken, so every failed write shrank the volume for good.
fn fat32_write_chain_from(v: &'static Vol, fc: u32, data: &[u8], bytes_per_clus: usize) -> Result<(), ()> {
    let mut cur = fc;
    let mut off = 0usize;
    loop {
        let end = (off + bytes_per_clus).min(data.len());
        fat32_write_cluster(v, cur, &data[off..end])?;
        off = end;
        if off >= data.len() { break; }
        let next = fat32_alloc_cluster_on(v)?;
        if fat32_write_fat_entry(v, cur, next).is_err() {
            fat32_free_chain_on(v, next);
            return Err(());
        }
        cur = next;
    }
    Ok(())
}

/// [`fat32_write_file_on`] on the boot volume ([`BOOT`]).
#[inline]
pub fn fat32_write_file(name83: &[u8; 11], data: &[u8]) -> Result<(), ()> {
    fat32_write_file_on(&BOOT, name83, data)
}

/// Create or overwrite a file in the FAT32 root directory ([`write_file_at`]
/// does it for a file in any directory).
///
/// **Create** (no existing dirent for `name83`) uses the original six-step
/// protocol, unchanged:
///   1. Write journal entry (state=PENDING)
///   2. Write data clusters
///   3. Write FAT table
///   4. Write directory entry
///   5. Write journal entry (state=COMMITTED)
///   6. Clear journal (state=EMPTY)
///
/// **Overwrite** (a dirent for `name83` already exists) used to free the old
/// chain and unlink the old dirent BEFORE any journal record of the
/// overwrite existed — closed 2026-09-23 (write-path audit finding). The
/// new order makes the whole operation one journal transaction:
///   1. Build the ENTIRE new chain first — old file untouched, so if this
///      crashes, nothing has changed and the journal (whatever it held
///      before) still describes the truth. Any clusters allocated here are,
///      at worst, a leak — the same class already accepted by the create
///      path's own step 1..3 window.
///   2. Write ONE journal entry, `state=PENDING, op=OVERWRITE`, recording the
///      new chain (`cluster`, `size`) AND the old chain/dirent location
///      (`fat_value`, `dir_sector`, `dir_offset`) — the one moment both
///      halves are simultaneously known and neither has been touched.
///   3. Point the old dirent at the new chain/size (in place — same slot,
///      same name, only the cluster and size fields change).
///   4. Free the old chain.
///   5. Journal COMMITTED, then clear.
/// A crash after step 2 leaves a PENDING `OVERWRITE` entry that
/// `fat32_journal_recover` completes — see that function's recovery arm for
/// why replaying steps 3 and 4 is safe no matter how far the crashed attempt
/// got. This is exactly the "journal the unlink and the create as one
/// operation" fix the prior audit named as the remaining work.
pub fn fat32_write_file_on(v: &'static Vol, name83: &[u8; 11], data: &[u8]) -> Result<(), ()> {
    write_file_at(v, &FName::root(v, name83), data)
}

/// [`fat32_write_file`] for a file in any directory.
fn write_file_at(v: &'static Vol, f: &FName, data: &[u8]) -> Result<(), ()> {
    write_file_journaled(v, f, data)?;
    // The whole-file write is complete on the device's side; make it durable
    // before telling the caller it is written (`vfs_close` reports this
    // result, and `CRASH.LOG`/`BOOTMETA` are written this way).
    //
    // This is the last of the operation's flushes: `write_file_journaled`
    // separates its journal steps with `journal_barrier`s (create: 2,
    // overwrite: 3), so with a volatile cache a power cut at any point
    // leaves a state mount-time recovery replays or discards. This one
    // also makes the journal clear durable before the caller can reuse
    // the clusters the overwrite freed.
    //
    // `Unsupported` is NOT an error here: this function's `Err` means "not
    // written", and the data was written. The device's inability to confirm
    // durability is reported by `fat32_fsync` / `fat32_sync_checked`, which
    // are the calls that claim it. (Only an empty-file create reaches this
    // point on such a device: every other path crossed a `journal_barrier`,
    // which refuses `Unsupported`.)
    match device_flush(v) {
        Ok(()) | Err(FsError::Unsupported) => Ok(()),
        Err(_) => Err(()),
    }
}

/// [`fat32_write_file_queued_on`] on the boot volume ([`BOOT`]).
#[inline]
pub fn fat32_write_file_queued(name83: &[u8; 11], data: &[u8]) -> Result<(), ()> {
    fat32_write_file_queued_on(&BOOT, name83, data)
}

/// [`fat32_write_file`] without its final flush, under write-back: the
/// journaled create/overwrite is queued in the cache, its steps ordered by
/// epochs, and returns without waiting on the device. A cut before the
/// write-back leaves the old file or the new one, as for the durable call;
/// what is not promised is WHICH until an fsync/sync (or the `fs-wb` task's
/// age bound) has run. The VFS proxy's close and fsync use it (fsync then
/// flushes: `FileSystem::fsync`). Write-through: exactly `fat32_write_file`.
pub fn fat32_write_file_queued_on(v: &'static Vol, name83: &[u8; 11], data: &[u8]) -> Result<(), ()> {
    write_file_queued_at(v, &FName::root(v, name83), data)
}

/// [`fat32_write_file_queued`] for a file in any directory.
fn write_file_queued_at(v: &'static Vol, f: &FName, data: &[u8]) -> Result<(), ()> {
    if !wb_active(v) || cfg!(feature = "wb-close-flushes-canary") {
        return write_file_at(v, f, data);
    }
    write_file_journaled(v, f, data)
}

/// The journaled create/overwrite protocol behind [`fat32_write_file`].
fn write_file_journaled(v: &'static Vol, f: &FName, data: &[u8]) -> Result<(), ()> {
    if !v.fat32.lock().mounted { return Err(()); }
    // The cached pages are the old file's; again after, for a page a writer
    // dirtied while the new file was being made.
    cache_forget(v, &f.key);
    let r = write_file_journaled_inner(v, f, data);
    cache_forget(v, &f.key);
    r
}

fn write_file_journaled_inner(v: &'static Vol, f: &FName, data: &[u8]) -> Result<(), ()> {

    // Read-only: is this an overwrite, and if so, where does the old dirent
    // live? Nothing is modified here — the old file is still fully intact
    // after this block, whichever branch `fat32_write_file` takes below.
    let overwrite = match lookup_entry(v, f.dir, &f.name).map(|e| (e.cluster, e.size)) {
        Ok((old_cluster, old_size)) => match find_dirent_location(v, f.dir, &f.name) {
            Ok((dir_sector, dir_offset)) => Some((old_cluster, old_size, dir_sector, dir_offset)),
            // Lookup found it but the location scan didn't (e.g. a
            // concurrent-looking, mid-directory-walk mismatch) — fail
            // closed rather than silently falling back to a second dirent
            // for the same name.
            Err(_) => return Err(()),
        },
        Err(_) => None,
    };

    let bytes_per_clus = v.fat32.lock().bytes_per_clus as usize;
    if bytes_per_clus == 0 { return Err(()); }

    if let Some((old_cluster, old_size, dir_sector, dir_offset)) = overwrite {
        // ── Overwrite path ──────────────────────────────────────────────
        let new_cluster = if data.is_empty() {
            0u32
        } else {
            fat32_alloc_and_write_chain(v, data, bytes_per_clus)?
        };

        // Barrier 0: the new chain (data + FAT) on the medium BEFORE the
        // record that recovery will replay onto it. A PENDING `OVERWRITE` is
        // acted on at mount — it points the dirent at `new_cluster` — so a
        // record that reached the medium ahead of the chain would install
        // a chain the medium does not hold.
        //
        // Nothing names the new chain until that record is written, so a
        // failure here gives it back (wave 11, `tests/fuzz/fs-fuzz`). Not after
        // it: recovery may install `new_cluster` into the dirent.
        if journal_barrier(v).is_err() {
            if new_cluster >= FAT32_FIRST_DATA_CLUSTER { fat32_free_chain_on(v, new_cluster); }
            return Err(());
        }

        let journal = JournalEntry {
            magic: JOURNAL_MAGIC,
            state: JOURNAL_PENDING,
            op_type: JOURNAL_OP_OVERWRITE,
            _pad: [0; 2],
            cluster: new_cluster,
            fat_value: old_cluster,
            dir_sector,
            dir_offset,
            size: data.len() as u32,
            _reserved: [0; JOURNAL_RESERVED_SIZE],
        };
        fat32_journal_write(v, &journal)?;
        // Barrier 1: the record before the first write it covers. Without
        // it the old chain's free could reach the medium while neither the
        // record nor the new dirent did: a live dirent over free clusters.
        journal_barrier(v)?;

        let defer = defer_frees(v);
        fat32_update_dirent_clus_size(v, dir_sector, dir_offset, new_cluster, data.len() as u32)?;
        if !defer && old_cluster >= FAT32_FIRST_DATA_CLUSTER {
            fat32_free_chain_on(v, old_cluster);
        }
        // Barrier 2: the mutation before the commit. A COMMITTED (or
        // cleared) record that overtook it would stop recovery from
        // finishing a half-applied overwrite.
        journal_barrier(v)?;

        let committed = JournalEntry { state: JOURNAL_COMMITTED, ..journal };
        fat32_journal_write(v, &committed)?;
        fat32_journal_clear(v)?;
        // Held until the clear is durable (`defer_free`): recovery of a
        // PENDING record frees the old chain again, so it must not have
        // been reused before the clear landed.
        if defer { let _ = defer_free(v, old_cluster, old_size); }
        return Ok(());
    }

    // ── Create path (no existing file) — unchanged ordering ─────────────
    let first_cluster = if data.is_empty() {
        0u32  // Empty file: no cluster
    } else {
        let fc = fat32_alloc_cluster_on(v)?;

        // Step 1: Write journal (PENDING) before any FAT/dir modifications.
        let journal = JournalEntry {
            magic: JOURNAL_MAGIC,
            state: JOURNAL_PENDING,
            op_type: JOURNAL_OP_WRITE_DIR,
            _pad: [0; 2],
            cluster: fc,
            fat_value: FAT32_EOC,
            dir_sector: 0,
            dir_offset: 0,
            size: 0,
            _reserved: [0; JOURNAL_RESERVED_SIZE],
        };
        // Until the dirent exists nothing names `fc`'s chain, and mount
        // discards a PENDING `WRITE_DIR` without touching the FAT, so every
        // failure from here to the dirent frees the chain itself. It used to
        // `?` out and keep it: disk full leaked the whole partial chain on
        // every attempt (wave 11, `tests/fuzz/fs-fuzz`).
        let written = fat32_journal_write(v, &journal).is_ok()
            // Barrier 1: the record before the writes it describes. A PENDING
            // `WRITE_DIR` is discarded at mount, so this one is not what keeps
            // the volume consistent (barrier 2 is); it keeps the owner's
            // journal-first protocol exact.
            && journal_barrier(v).is_ok()
            // Steps 2-3: data clusters, FAT chain.
            && fat32_write_chain_from(v, fc, data, bytes_per_clus).is_ok()
            // Barrier 2: data + FAT chain on the medium before the dirent that
            // makes them a file. Without it the dirent can land first and name
            // clusters whose data or FAT links the medium never received —
            // and a PENDING `WRITE_DIR` is discarded, not rolled back.
            && journal_barrier(v).is_ok();
        if !written {
            fat32_free_chain_on(v, fc);
            let _ = fat32_journal_clear(v);
            return Err(());
        }
        fc
    };

    // Step 4: Write the directory entry.
    match dir_insert(v, f.dir, &f.name, first_cluster, data.len() as u32, DIRENT_ATTR_ARCHIVE_FILE) {
        Ok(_) => {}
        // No cluster for a directory extension: nothing in the directory was
        // written, so the chain built above is referenced by nothing. Hand
        // it back and clear the record instead of leaking a cluster per
        // failed attempt on a volume that is, by definition, already out of
        // space. A crash between the free and the clear leaves a PENDING
        // `WRITE_DIR`, which mount discards.
        Err(FsError::NoSpace) => {
            if first_cluster >= FAT32_FIRST_DATA_CLUSTER {
                fat32_free_chain_on(v, first_cluster);
            }
            let _ = fat32_journal_clear(v);
            return Err(());
        }
        // Any other failure may have reached the directory — but usually
        // did not (a root chain the walk refuses fails before any write).
        // Keep the chain only if a dirent naming it did land: a dangling
        // dirent over freed clusters is worse than a leak, and a leak per
        // attempt is what this used to be (wave 11, `tests/fuzz/fs-fuzz`).
        Err(_) => {
            let named = matches!(lookup_entry(v, f.dir, &f.name), Ok(e) if e.cluster == first_cluster);
            if first_cluster >= FAT32_FIRST_DATA_CLUSTER && !named {
                fat32_free_chain_on(v, first_cluster);
                let _ = fat32_journal_clear(v);
            }
            return Err(());
        }
    }

    // Step 5: Mark journal as COMMITTED.
    let committed = JournalEntry {
        magic: JOURNAL_MAGIC,
        state: JOURNAL_COMMITTED,
        op_type: JOURNAL_OP_WRITE_DIR,
        _pad: [0; 2],
        cluster: first_cluster,
        fat_value: FAT32_EOC,
        dir_sector: 0,
        dir_offset: 0,
        size: 0,
        _reserved: [0; JOURNAL_RESERVED_SIZE],
    };
    fat32_journal_write(v, &committed)?;

    // Step 6: Clear journal.
    fat32_journal_clear(v)
}

/// Convert a raw filename (no slashes) to FAT32 8.3 format.
fn path_to_83_local(name: &[u8]) -> Option<[u8; 11]> {
    if name.is_empty() { return None; }
    let (base, ext) = match name.iter().position(|&b| b == b'.') {
        Some(i) => (&name[..i], &name[i + 1..]),
        None    => (name, &[][..]),
    };
    if base.is_empty() || base.len() > 8 || ext.len() > 3 { return None; }
    let mut result = [b' '; 11];
    for (i, &b) in base.iter().enumerate() { result[i]     = b.to_ascii_uppercase(); }
    for (i, &b) in ext.iter().enumerate()  { result[8 + i] = b.to_ascii_uppercase(); }
    Some(result)
}

/// [`fat32_unlink_path_on`] on the boot volume ([`BOOT`]).
#[inline]
pub fn fat32_unlink_path(name: &[u8]) -> Result<(), ()> {
    fat32_unlink_path_on(&BOOT, name)
}

/// Unlink a root-directory file by raw filename (e.g. `b"TEST.TXT"`).
/// Marks the directory entry deleted, then frees its cluster chain.
///
/// That order, with `fat32_unlink_root`'s barrier after the dirent write:
/// the chain used to be freed FIRST, so a power cut could leave the dirent
/// on the medium over clusters the FAT already called free — the next
/// allocation would cross-link them. Now the worst a cut leaves is a
/// deleted dirent and a leaked chain.
pub fn fat32_unlink_path_on(v: &'static Vol, name: &[u8]) -> Result<(), ()> {
    let name83 = path_to_83_local(name).ok_or(())?;
    let cluster = fat32_lookup_root_on(v, &name83).map(|(c, _)| c).unwrap_or(0);
    fat32_unlink_root_on(v, &name83)?;
    if cluster >= 2 { fat32_free_chain_on(v, cluster); }
    Ok(())
}

/// A whole-file change made behind the page cache's back (the direct
/// `fat32_*` API: a journaled replace, an unlink, a rename): the pages cached
/// under the name are not the file's bytes any more, dirty ones included,
/// and are forgotten. The VFS's own paths settle first (`vfs.rs`); these
/// callers never wrote through the cache.
///
/// Every public way to change a file's bytes or name, and what settles the
/// cache (rows: `coherence_*` in `tests/host/fs-tests/src/l11b.rs`):
/// * `fat32_write_file`, `fat32_write_file_queued`, `Fat32Fs::write_all`,
///   `Fat32Fs::create`, `Fat32Fs::truncate` to a non-zero length: all reach
///   `write_file_journaled`, which forgets before and after.
/// * `fat32_unlink_root`, `fat32_unlink_path`, `Fat32Fs::unlink`,
///   `Fat32Fs::rmdir`: forget before and after the dirent goes (the chain is
///   freed after, with no entry naming it).
/// * `fat32_rename`: flushes the source, forgets the target and both names.
/// * `fat32_open` (a root file) and `fat32_read`/`fat32_write` on its handle:
///   `TRUNCATE` forgets; a read or write flushes before it touches the bytes,
///   and a write forgets after (`OpenFileEntry::cache_name`). `Fat32Fs::read_at`/`write_at` are the
///   cache's backing and use the raw variants.
/// * `Fat32Fs::truncate` to zero (the in-place entry reset) and `fat32_mkdir`:
///   no forget of their own. A truncate is reached through `vfs_truncate` and
///   `vfs_open(O_TRUNC)`, which flush or drop around it; `fat32_mkdir` of a
///   name a cached file holds fails (`Exists`), and a directory is never
///   cached.
fn cache_forget(v: &'static Vol, key: &crate::vfs::InodeKey) {
    crate::vfs::page_cache_drop(v.fs, Some(key), 0);
}

// ── Sync (AS — Power-Loss Safety) ────────────────────────────────────────────

/// Ask the block device to make every completed write durable
/// (`blkdev::flush`, a `VIRTIO_BLK_T_FLUSH` on QEMU).
///
/// Every `write_sector` completes when the device has ACCEPTED the sector.
/// On a device with a volatile write cache that is not durability: a power
/// cut can lose any write not followed by a successful flush. This is the
/// one place this crate issues that flush; every durability claim below
/// goes through it.
///
/// `FsError::Unsupported` when the device cannot flush (see
/// `blkdev::FlushError::Unsupported`), `FsError::Io` when a flush failed.
///
/// It first asks the shared block cache to write back its
/// dirty lines, oldest epoch first, and then closes the cache's epoch after
/// the flush: a journal barrier is an epoch boundary of the cache too. The
/// FAT32 instance is write-through, so the write-back pass finds nothing and
/// issues no I/O — the device sees exactly the write/flush sequence it saw
/// before the cache was shared (`tests/host/fs-tests` `durability`/`power_cut`
/// assert that sequence).
fn device_flush(v: &'static Vol) -> Result<(), FsError> {
    if v.knobs.writeback && v.sector_cache.lock().mode() == crate::bcache::Mode::WriteBack {
        // Write-back: under the claim, close the epoch FIRST (a write made
        // after this point is not this flush's to make durable, and cannot
        // keep it running), write back through it, then flush the device.
        let claim = wb_claim(v);
        // `barrier` returns the highest epoch it closed: the one a
        // directory entry was written ahead into (`write_sector_ahead`)
        // when there is one, so this flush makes it durable too.
        let upto = v.sector_cache.lock().barrier();
        // The pass may end with a run that is itself the flush (PREFLUSH |
        // FUA: `wb_write_back`'s `commit`). Only then is the explicit flush
        // skipped: a pass that wrote nothing, or whose last run was not the
        // last dirty line, still ends with the device flush. The fsync always
        // makes its own writes durable; none is implied by the writes before it.
        let committed = if cfg!(feature = "wb-flush-no-writeback-canary") {
            false
        } else {
            wb_write_back(v, &claim, upto, true)?
        };
        let r = if committed { Ok(()) } else { device_flush_raw(v) };
        if r.is_ok() {
            v.sector_cache.lock().note_flushed();
        }
        drop(claim);
        // Every epoch `<= upto` is durable now: free the chains their
        // unlinking writes released (`defer_free`), into the epoch just
        // opened. Outside the claim: a free may have to write back.
        if r.is_ok() && !cfg!(feature = "wb-flush-no-writeback-canary") {
            release_held(v, upto);
        }
        return r;
    }
    {
        let mut c = v.sector_cache.lock();
        match c.write_back_all(&mut BlkDev(v)) {
            Ok(()) => {}
            Err(crate::bcache::IoError::Flush(e)) => return Err(e),
            Err(_) => return Err(FsError::Io),
        }
    }
    let r = device_flush_raw(v);
    if r.is_ok() {
        let mut c = v.sector_cache.lock();
        c.note_flushed();
        c.barrier();
    }
    r
}

/// The device flush alone, with the driver's answer mapped to `FsError`.
fn device_flush_raw(v: &'static Vol) -> Result<(), FsError> {
    match v.dev.flush() {
        Ok(()) => Ok(()),
        Err(azos_drv_api::block::FlushError::Unsupported) => Err(FsError::Unsupported),
        Err(azos_drv_api::block::FlushError::Io) => Err(FsError::Io),
    }
}

/// Ordering barrier between the steps of a journaled operation: every write
/// issued before it reaches the medium before any write issued after it.
///
/// Anything but a confirmed flush fails the operation closed — nothing
/// after the barrier is written, and whatever reached the medium before it
/// is a state mount-time recovery already handles. That includes
/// `Unsupported` (owner decision, wave 7): a device that cannot flush gives
/// no ordering, so the journal's guarantees do not hold on it and a
/// structural write is refused rather than made without them.
///
/// `fat32_fsync`'s ordering flush keeps its own rule (`Unsupported` passes,
/// the call then answers `Err(Unsupported)`): it mutates one dirent in
/// place, its caller is told the result is not durable either way, and
/// nothing is replayed from it at mount.
fn journal_barrier(v: &'static Vol) -> Result<(), ()> {
    order_barrier(v).map_err(|_| ())
}

/// Whether the FAT32 cache is in write-back mode now.
fn wb_active(v: &'static Vol) -> bool {
    v.knobs.writeback && v.sector_cache.lock().mode() == crate::bcache::Mode::WriteBack
}

/// Every write issued before this reaches the medium before any issued
/// after it. Write-through: a device flush (`device_flush`). Write-back: the
/// cache's epoch closes — no I/O; the write-back puts the flush between the
/// two epochs when it writes them (`checkout_run`'s `flush_first`), and a
/// cut leaves the same states as with the flush here. A write-back mount
/// requires a device that flushes (`fat32_mount` probes it), so the
/// fail-closed rule for `Unsupported` above holds by construction.
fn order_barrier(v: &'static Vol) -> Result<(), FsError> {
    barrier_closing(v).map(|_| ())
}

/// [`order_barrier`], returning the highest epoch it closed: every write
/// issued before it is in that epoch or an earlier one. Write-back: the
/// cache's barrier (no I/O). Write-through, and the
/// `wb-barrier-flushes-canary` build: a device flush, which closes the same
/// epochs and makes them durable. Every barrier FAT32 puts between its own
/// writes goes through here, so the canary reaches each of them.
fn barrier_closing(v: &'static Vol) -> Result<u64, FsError> {
    if wb_active(v) && !cfg!(feature = "wb-barrier-flushes-canary") {
        return Ok(v.sector_cache.lock().barrier());
    }
    let top = v.sector_cache.lock().top_epoch();
    device_flush(v).map(|()| top)
}

/// [`fat32_journal_idle_on`] on the boot volume ([`BOOT`]).
#[inline]
pub fn fat32_journal_idle() -> bool {
    fat32_journal_idle_on(&BOOT)
}

/// `true` when the journal sector holds no PENDING or COMMITTED record —
/// what mount-time recovery must leave behind. Read-only; for the
/// power-cut gate row, which asserts it after every cut.
pub fn fat32_journal_idle_on(v: &'static Vol) -> bool {
    match fat32_journal_read(v) {
        Ok(e) => e.magic != JOURNAL_MAGIC || (e.state != JOURNAL_PENDING && e.state != JOURNAL_COMMITTED),
        Err(()) => false,
    }
}

/// [`fat32_check_root_chain_on`] on the boot volume ([`BOOT`]).
#[inline]
pub fn fat32_check_root_chain(name83: &[u8; 11]) -> Result<Option<(u32, u32)>, &'static str> {
    fat32_check_root_chain_on(&BOOT, name83)
}

/// Structural check of `name83`'s root-directory chain, read-only.
///
/// `Ok(None)`: no such dirent. `Ok(Some((first_cluster, size)))`: every
/// cluster the chain visits is an in-range data cluster the FAT does not
/// call free, the chain ends in EOC, and it covers `size`: exactly, or with
/// a sound tail past it. `Err(reason)` otherwise. For the power-cut gate
/// row: a dirent over a chain the FAT freed reads back correctly until the
/// clusters are reused, so a content check alone cannot see it.
///
/// The tail (FW2): an in-place write extends the chain before the entry
/// naming the new size reaches the medium (the entry follows its chain), so
/// a cut between a write-back that wrote the entry and the next one that
/// writes the extension leaves the old size over a longer chain. Reads stop
/// at the size; the file's next write past its size reuses the tail
/// (`chain_nth_or_extend` follows the chain before it allocates), and a
/// truncate or unlink frees it with the chain (`free_chain_unlocked` runs to
/// EOC). Until then it is leaked space, as after any cut before a free;
/// Linux's FAT driver reads such a file the same way and fsck.fat trims it.
/// A tail through a FREE cluster is not sound: `chain_nth_or_extend` orders
/// a new cluster's end-of-chain mark before the link to it.
pub fn fat32_check_root_chain_on(v: &'static Vol, name83: &[u8; 11]) -> Result<Option<(u32, u32)>, &'static str> {
    let (first, size) = match fat32_lookup_root_on(v, name83) {
        Ok(v) => v,
        Err(()) => return Ok(None),
    };
    let (bpc, data_clusters) = {
        let fv = v.fat32.lock();
        (fv.bytes_per_clus, fv.data_clusters)
    };
    if bpc == 0 { return Err("volume not mounted"); }
    let want = (size as u64).div_ceil(bpc as u64);
    if want == 0 {
        return if first == 0 { Ok(Some((0, 0))) } else { Err("empty file names a cluster") };
    }
    let last_valid = data_clusters.saturating_add(FAT32_FIRST_DATA_CLUSTER);
    let limit = data_clusters as u64;
    let mut cluster = first;
    let mut seen = 0u64;
    loop {
        if cluster < FAT32_FIRST_DATA_CLUSTER || cluster >= last_valid {
            return Err("link to a cluster outside the data region");
        }
        seen += 1;
        // Past the size: a tail is sound if it ends in EOC (see above). A
        // walk longer than the data region is a cycle.
        if seen > limit { return Err("chain does not end (a cycle)"); }
        if seen > want && cfg!(feature = "fat-check-exact-chain-canary") {
            return Err("chain longer than its size");
        }
        let next = fat32_next_cluster(v, cluster).map_err(|()| "FAT unreadable")?;
        if next == 0 { return Err("a live chain runs through a FREE cluster"); }
        if next >= FAT32_EOC { break; }
        cluster = next;
    }
    if seen < want { return Err("chain shorter than its size"); }
    Ok(Some((first, size)))
}

/// Clear a committed journal entry so the NEXT mount does not replay it.
fn journal_settle(v: &'static Vol) -> Result<(), ()> {
    let entry = fat32_journal_read(v)?;
    if entry.magic == JOURNAL_MAGIC && entry.state == JOURNAL_COMMITTED {
        fat32_journal_clear(v)?;
    }
    Ok(())
}

/// [`fat32_sync_checked_on`] on the boot volume ([`BOOT`]).
#[inline]
pub fn fat32_sync_checked() -> Result<(), FsError> {
    fat32_sync_checked_on(&BOOT)
}

/// Settle the journal, then flush the device, so every write this volume has
/// completed so far is durable when this returns `Ok`.
///
/// Returns the device's answer: `Unsupported` if it cannot flush, `Io` if the
/// flush failed. `NotMounted` / `Io` from the journal step as before.
pub fn fat32_sync_checked_on(v: &'static Vol) -> Result<(), FsError> {
    if !v.fat32.lock().mounted { return Err(FsError::NotMounted); }
    // The page cache's dirty pages reach the block cache first (storage L11):
    // `write_at` puts their data and chain in the current epoch and the
    // entry ahead of it, then the flush below makes it all durable. A write-back
    // that failed is this call's verdict, after the rest was synced.
    let paged = crate::vfs::page_cache_flush_fs(v.fs).map_err(|_| FsError::Io);
    journal_settle(v).map_err(|()| FsError::Io)?;
    device_flush(v)?;
    wb_take_error(v)?;
    paged
}

/// `Err(Io)` once after a write-back no caller waited for failed.
fn wb_take_error(v: &'static Vol) -> Result<(), FsError> {
    if v.wb_error.swap(false, core::sync::atomic::Ordering::Relaxed) { Err(FsError::Io) } else { Ok(()) }
}

/// [`fat32_sync_on`] on the boot volume ([`BOOT`]).
#[inline]
pub fn fat32_sync() -> Result<(), ()> {
    fat32_sync_on(&BOOT)
}

/// [`fat32_sync_checked`] with the error folded to `()`, for the callers and
/// the `FileSystem::sync` signature that take `Result<(), ()>`. `Err` now
/// includes "the device could not confirm the flush".
pub fn fat32_sync_on(v: &'static Vol) -> Result<(), ()> {
    fat32_sync_checked_on(v).map_err(|_| ())
}

// ── Directory listing ─────────────────────────────────────────────────────────

/// Convert a FAT32 8.3 raw name to a printable string.
/// Strips trailing spaces and inserts a '.' before the extension.
/// Returns (buffer, length).
fn format_83_name(raw: &[u8; 11]) -> ([u8; 13], usize) {
    let base_end = raw[..8].iter().rposition(|&b| b != b' ').map(|i| i + 1).unwrap_or(0);
    let ext_end  = raw[8..11].iter().rposition(|&b| b != b' ').map(|i| i + 1).unwrap_or(0);
    let mut buf = [0u8; 13];
    let mut len = 0usize;
    buf[..base_end].copy_from_slice(&raw[..base_end]);
    len += base_end;
    if ext_end > 0 {
        buf[len] = b'.';
        len += 1;
        buf[len..len + ext_end].copy_from_slice(&raw[8..8 + ext_end]);
        len += ext_end;
    }
    (buf, len)
}

/// [`fat32_ls_root_on`] on the boot volume ([`BOOT`]).
#[inline]
pub fn fat32_ls_root(cb: impl FnMut(&[u8], u32, bool)) {
    fat32_ls_root_on(&BOOT, cb)
}

/// Enumerate all entries in the FAT32 root directory.
///
/// Calls `cb(name, file_size, is_dir)` for each valid, non-deleted entry.
/// Deleted entries, LFN entries, and volume-ID entries are skipped.
pub fn fat32_ls_root_on(v: &'static Vol, mut cb: impl FnMut(&[u8], u32, bool)) {
    if !v.fat32.lock().mounted { return; }
    let root_cluster = v.fat32.lock().root_cluster;

    let (spc, data_start, fat_sz32, data_clusters) = {
        let fv = v.fat32.lock();
        (fv.secs_per_clus, fv.data_start, fv.fat_sz32, fv.data_clusters)
    };
    // Cycle guard — see `ChainWalk`.
    let mut walk = ChainWalk::for_volume(fat_sz32, data_clusters);

    let mut cluster = root_cluster;
    while cluster >= FAT32_FIRST_DATA_CLUSTER && cluster < FAT32_EOC {
        if !walk.visit(cluster) { return; }
        let first_sector = match cluster_first_sector(data_start, cluster, spc) {
            Some(v) => v,
            None => return,
        };

        'outer: for s in 0..spc {
            let mut sec_buf = [0u8; SECTOR_SIZE];
            // s < spc, and cluster_first_sector proved first_sector + spc fits.
            // A read error ends the listing (wave 15, GR4): it used to leave
            // only this cluster and follow the chain on.
            if read_sector(v, first_sector + s, &mut sec_buf).is_err() {
                if cfg!(feature = "fat-walk-read-error-canary") { break 'outer; }
                return;
            }

            for e in 0..DIRENTS_PER_SECTOR {
                let off = e * DIRENT_SIZE;
                let entry = unsafe {
                    &*(sec_buf[off..off + 32].as_ptr() as *const Fat32Dirent)
                };
                if entry.name[0] == 0x00 { return; }   // End of directory
                if entry.name[0] == 0xE5 { continue; }  // Deleted
                if entry.attr == ATTR_LFN { continue; }  // LFN entry
                if entry.attr & ATTR_VOLUME_ID != 0 { continue; }

                let is_dir = entry.attr & ATTR_DIRECTORY != 0;
                let mut name83 = [0u8; 11];
                name83[..8].copy_from_slice(&entry.name);
                name83[8..].copy_from_slice(&entry.ext);
                let (name_buf, name_len) = format_83_name(&name83);
                cb(&name_buf[..name_len], entry.file_size, is_dir);
            }
        }

        cluster = fat32_next_cluster(v, cluster).unwrap_or(FAT32_EOC);
    }
}

// ── AS — File-level API (open / read / write / seek / close / sync) ──────────
//
// The APIs above expose raw cluster-chain primitives; the behavior crate (E06
// logging) needs a real file handle with positional I/O, append, seek, and
// fsync.  Everything below is `#![no_std]` and heap-free: open files live in
// a fixed-size table guarded by a SpinLock.
//
// Subdirectory support: mkdir, directory-entry updates in any directory
// cluster chain (not just root), and path walking from "/" through arbitrary
// nested subdirectories.  Long-filename (VFAT LFN) is NOT implemented — only
// 8.3 short names.

/// Error type returned by the file-level API.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum FsError {
    /// Filesystem not mounted.
    NotMounted,
    /// Path not found.
    NotFound,
    /// Path exists but is a directory when a file was expected (or vice versa).
    WrongType,
    /// File is not open.
    BadHandle,
    /// Open handle table exhausted.
    TooManyOpen,
    /// Invalid path / component / flags.
    InvalidArg,
    /// Underlying block device I/O failed.
    Io,
    /// Disk full (no free clusters).
    NoSpace,
    /// Directory entry could not be created (no free slot and no extend).
    DirFull,
    /// Operation not supported (e.g. removing a non-empty directory).
    Unsupported,
    /// The name is already taken (`fat32_mkdir` onto an existing entry).
    Exists,
}

/// Open-mode flags for `fat32_open`.
pub mod open_flags {
    /// Open for reading.
    pub const READ: u32 = 0x0001;
    /// Open for writing.
    pub const WRITE: u32 = 0x0002;
    /// Create file if it does not exist.
    pub const CREATE: u32 = 0x0004;
    /// Truncate to zero length on open.
    pub const TRUNCATE: u32 = 0x0008;
    /// Seek to end of file before each write.
    pub const APPEND: u32 = 0x0010;
}

/// Seek origin for `fat32_seek`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SeekFrom {
    Start(u32),
    Current(i32),
    End(i32),
}

/// Zero-sized volume marker.  Present so future multi-volume support is a
/// backwards-compatible change; today there is a single static `FAT32` volume.
#[derive(Copy, Clone)]
pub struct Volume {
    _private: (),
}

/// Opaque handle to an open FAT32 file.  Always returned by value and passed
/// by value; identifies a slot in the static open-file table.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Fat32File {
    slot: u16,
    /// Generation counter — guards against stale handles after close+reopen.
    generation: u16,
}

/// Entry yielded by a directory iterator.
#[derive(Copy, Clone, Debug)]
pub struct DirEntryInfo {
    /// Printable 8.3 name ("FOO.TXT" or "SUBDIR") — trailing spaces stripped.
    pub name: [u8; 13],
    pub name_len: u8,
    pub size: u32,
    pub is_dir: bool,
    /// Starting cluster of the file/directory content (0 for empty files).
    pub first_cluster: u32,
}

/// Directory iterator.  Walks the cluster chain of a directory and yields one
/// `DirEntryInfo` at a time via `next()`.  Skips deleted / LFN / volume-ID
/// entries.  Stops at the first `DIRENT_MARK_END` sentinel.
pub struct Fat32DirIter {
    /// The volume the directory is on.
    v: &'static Vol,
    cluster: u32,
    sector_in_cluster: u32,
    entry_in_sector: usize,
    done: bool,
    /// This walk's guard ([`ChainWalk`]: the `chain_walk_limit` bound and the
    /// cycle check), taken on every advance.
    ///
    /// This has to live in the struct, not as a local in `next()`: the loop is
    /// re-entered on each call, so a local would reset every time and a
    /// directory cycle whose sectors contain only deleted (0xE5) entries —
    /// which never produce a `return` — would still spin forever inside a
    /// single `next()`. A cycle through live entries would yield them forever
    /// to a caller that reads to the end.
    walk: ChainWalk,
}

/// Internal per-open-file state.
#[derive(Copy, Clone)]
struct OpenFileEntry {
    in_use: bool,
    generation: u16,
    /// Absolute sector number of the dirent.
    dir_sector: u32,
    /// Byte offset within `dir_sector` of the dirent.
    dir_offset: u16,
    /// First cluster of the file's data chain (0 = empty file).
    first_cluster: u32,
    /// Current file size in bytes (as known to the handle).
    size: u32,
    /// Current file position.
    pos: u32,
    /// Open flags.
    flags: u32,
    /// Dirty flag: file data / size was modified and the dirent needs updating
    /// on sync/close.
    dirty: bool,
    /// The page cache's name for the file, when the handle was opened through
    /// the public API (see `cache_forget`).
    cache_name: Option<crate::vfs::InodeKey>,
}

const EMPTY_OPEN_FILE: OpenFileEntry = OpenFileEntry {
    in_use: false,
    generation: 0,
    dir_sector: 0,
    dir_offset: 0,
    first_cluster: 0,
    size: 0,
    pos: 0,
    flags: 0,
    dirty: false,
    cache_name: None,
};

// ── Volume mount/unmount API ─────────────────────────────────────────────────

/// [`fat32_mount_volume_on`] on the boot volume ([`BOOT`]).
#[inline]
pub fn fat32_mount_volume() -> Result<Volume, FsError> {
    fat32_mount_volume_on(&BOOT)
}

/// Mount the FAT32 filesystem and return a `Volume` handle.  Wraps
/// [`fat32_mount`] for a more modern API surface.
pub fn fat32_mount_volume_on(v: &'static Vol) -> Result<Volume, FsError> {
    fat32_mount_on(v).map(|()| Volume { _private: () }).map_err(|()| FsError::NotMounted)
}

/// [`fat32_unmount_on`] on the boot volume ([`BOOT`]).
#[inline]
pub fn fat32_unmount(_vol: Volume) -> Result<(), FsError> {
    fat32_unmount_on(&BOOT, _vol)
}

/// Unmount the FAT32 filesystem.  Flushes the journal and closes all open
/// files (dropping their dirty writes after a final sync), then marks the
/// volume clean as the last write, if everything above reached the medium.
/// Anything short of a clean unmount (a cut, a crash, a halt that never gets
/// here) leaves the volume dirty and the next mount checks it.  Safe to call
/// even if no volume is mounted.
pub fn fat32_unmount_on(v: &'static Vol, _vol: Volume) -> Result<(), FsError> {
    let was_mounted = v.fat32.lock().mounted;
    // Sync + close every currently-open file so no write is lost.
    let slots_to_close: [(bool, u16); FAT32_MAX_OPEN_FILES] = {
        let t = v.open_files.lock();
        let mut out = [(false, 0u16); FAT32_MAX_OPEN_FILES];
        for i in 0..FAT32_MAX_OPEN_FILES {
            out[i] = (t[i].in_use, t[i].generation);
        }
        out
    };
    for i in 0..FAT32_MAX_OPEN_FILES {
        if slots_to_close[i].0 {
            let h = Fat32File { slot: i as u16, generation: slots_to_close[i].1 };
            let _ = fat32_close_on(v, h);
        }
    }
    // Canary: the clean flag goes out ahead of the flush that makes the
    // mount's writes durable, so a cut can keep it over a volume that leaks.
    // (A direct write, as the flag's always is, so it is not queued behind
    // the rest: it reaches the medium first.)
    if cfg!(feature = "fat-clean-early-canary") && v.volume_marked_dirty.load(core::sync::atomic::Ordering::Relaxed) {
        let _ = volume_set_clean(v, true);
    }
    // The sync writes the page cache's dirty pages back first (they are writes
    // the volume has not seen, and the clean flag below promises there are
    // none) and fails if they could not be.
    let mut settled = fat32_sync_on(v).is_ok();
    // That flush freed the held chains into a new epoch (`defer_free`):
    // write it too, or the invalidation below drops the frees.
    if v.sector_cache.lock().dirty_count() > 0 {
        settled &= device_flush(v).is_ok();
    }
    // Clean only if everything above is on the medium and nothing is still
    // held for a free that has not run: the flag promises no lost space.
    settled &= was_mounted && fat32_held_clusters_on(v) == 0 && fat32_journal_idle_on(v);
    held_reset(v);
    if settled && volume_state_write_ready(v)
        && v.volume_marked_dirty.swap(false, core::sync::atomic::Ordering::Relaxed)
    {
        // Last write of the mount, flushed: a cut before it lands leaves the
        // volume dirty, which only costs the next mount a check.
        if volume_set_clean(v, true).is_ok() {
            let _ = device_flush_raw(v);
        }
    }
    // Mark volume unmounted.
    v.fat32.lock().mounted = false;
    // U09-6: drop every cached sector on unmount too, not just on the next
    // mount. Between this unmount and a future mount, the medium may be
    // physically swapped (an SD card) with the cache never told;
    // invalidating here as well as in `fat32_mount` means neither the
    // outgoing nor the incoming volume's sectors can be read through a
    // stale line, regardless of which of the two calls a caller happens to
    // make first.
    fat32_cache_invalidate_all_on(v);
    // The medium may be another one at the next mount: so are the pages.
    crate::vfs::page_cache_drop(v.fs, None, 0);
    Ok(())
}

// ── Path helpers ─────────────────────────────────────────────────────────────

/// Convert one raw path component (no slashes) to FAT32 8.3 uppercase form.
fn component_to_83(name: &[u8]) -> Option<[u8; 11]> {
    if name.is_empty() || name == b"." || name == b".." { return None; }
    let (base, ext) = match name.iter().position(|&b| b == b'.') {
        Some(i) => (&name[..i], &name[i + 1..]),
        None => (name, &[][..]),
    };
    if base.is_empty() || base.len() > 8 || ext.len() > 3 { return None; }
    let mut result = [b' '; 11];
    for (i, &b) in base.iter().enumerate() { result[i] = b.to_ascii_uppercase(); }
    for (i, &b) in ext.iter().enumerate() { result[8 + i] = b.to_ascii_uppercase(); }
    Some(result)
}

/// Split an absolute path (e.g. `b"/dir/sub/file.txt"`) into components.
/// Leading slashes are stripped; empty components are skipped.
/// Writes components into `out` and returns the number of components written.
fn split_path<'a>(
    path: &'a [u8],
    out: &mut [&'a [u8]; FAT32_MAX_PATH_DEPTH],
) -> Result<usize, FsError> {
    let mut rest = path;
    while rest.first() == Some(&b'/') { rest = &rest[1..]; }
    let mut count = 0usize;
    while !rest.is_empty() {
        let end = rest.iter().position(|&c| c == b'/').unwrap_or(rest.len());
        let comp = &rest[..end];
        if !comp.is_empty() {
            if count >= FAT32_MAX_PATH_DEPTH { return Err(FsError::InvalidArg); }
            out[count] = comp;
            count += 1;
        }
        rest = if end < rest.len() { &rest[end + 1..] } else { &[] };
    }
    Ok(count)
}

// ── Directory walking ────────────────────────────────────────────────────────

/// Result of searching a directory for an entry.
struct DirentLocation {
    /// Sector holding the dirent.
    sector: u32,
    /// Byte offset within `sector` of the dirent.
    offset: u16,
    first_cluster: u32,
    size: u32,
    attr: u8,
}

/// Search a directory (given by its starting cluster) for an entry matching
/// `name83`.
fn dir_find_in(v: &'static Vol, dir_cluster: u32, name83: &[u8; 11]) -> Result<DirentLocation, FsError> {
    let (spc, data_start, fat_sz32, data_clusters) = {
        let fv = v.fat32.lock();
        (fv.secs_per_clus, fv.data_start, fv.fat_sz32, fv.data_clusters)
    };
    // Cycle guard — see `ChainWalk`. This is the walker a ring-3
    // `open()` reaches first, so a `FAT[n] = n` cycle here hangs the hart that
    // serviced the syscall with no I/O and no yield.
    let mut walk = ChainWalk::for_volume(fat_sz32, data_clusters);

    let mut cluster = dir_cluster;
    while cluster >= FAT32_FIRST_DATA_CLUSTER && cluster < FAT32_EOC {
        if !walk.visit(cluster) { return Err(FsError::Io); }
        let first_sector = cluster_first_sector(data_start, cluster, spc)
            .ok_or(FsError::Io)?;
        for s in 0..spc {
            // s < spc, and cluster_first_sector proved first_sector + spc fits.
            let sec_num = first_sector + s;
            let mut buf = [0u8; SECTOR_SIZE];
            read_sector(v, sec_num, &mut buf).map_err(|()| FsError::Io)?;
            for e in 0..FAT32_DIRENTS_PER_SECTOR {
                let off = e * FAT32_DIR_ENTRY_SIZE;
                if buf[off + DIRENT_OFF_NAME] == DIRENT_MARK_END {
                    return Err(FsError::NotFound);
                }
                if buf[off + DIRENT_OFF_NAME] == DIRENT_MARK_DELETED { continue; }
                let attr = buf[off + DIRENT_OFF_ATTR];
                if attr == ATTR_LFN { continue; }
                if attr & ATTR_VOLUME_ID != 0 { continue; }
                let mut ent_name = [0u8; 11];
                ent_name[..8].copy_from_slice(&buf[off + DIRENT_OFF_NAME..off + DIRENT_OFF_NAME + 8]);
                ent_name[8..11].copy_from_slice(&buf[off + DIRENT_OFF_EXT..off + DIRENT_OFF_EXT + 3]);
                if &ent_name == name83 {
                    let hi = u16::from_le_bytes([
                        buf[off + DIRENT_OFF_FST_CLUS_HI],
                        buf[off + DIRENT_OFF_FST_CLUS_HI + 1],
                    ]) as u32;
                    let lo = u16::from_le_bytes([
                        buf[off + DIRENT_OFF_FST_CLUS_LO],
                        buf[off + DIRENT_OFF_FST_CLUS_LO + 1],
                    ]) as u32;
                    let size = u32::from_le_bytes([
                        buf[off + DIRENT_OFF_FILE_SIZE],
                        buf[off + DIRENT_OFF_FILE_SIZE + 1],
                        buf[off + DIRENT_OFF_FILE_SIZE + 2],
                        buf[off + DIRENT_OFF_FILE_SIZE + 3],
                    ]);
                    return Ok(DirentLocation {
                        sector: sec_num,
                        offset: off as u16,
                        first_cluster: (hi << 16) | lo,
                        size,
                        attr,
                    });
                }
            }
        }
        cluster = fat32_next_cluster(v, cluster).map_err(|()| FsError::Io)?;
    }
    Err(FsError::NotFound)
}

/// Resolve the directory that contains the final component of `path`.
///
/// Returns `(parent_dir_cluster, last_component)` — the caller can then call
/// `dir_find_in(parent_dir_cluster, ...)` or insert a new entry.
fn resolve_parent<'a>(v: &'static Vol, path: &'a [u8]) -> Result<(u32, &'a [u8]), FsError> {
    if !fat32_mounted_on(v) { return Err(FsError::NotMounted); }
    let mut comps: [&[u8]; FAT32_MAX_PATH_DEPTH] = [&[]; FAT32_MAX_PATH_DEPTH];
    let n = split_path(path, &mut comps)?;
    if n == 0 { return Err(FsError::InvalidArg); }

    let root_cluster = v.fat32.lock().root_cluster;
    let mut dir_cluster = root_cluster;
    // Walk all but the last component.
    for i in 0..(n - 1) {
        let name83 = component_to_83(comps[i]).ok_or(FsError::InvalidArg)?;
        let loc = dir_find_in(v, dir_cluster, &name83)?;
        if loc.attr & ATTR_DIRECTORY == 0 { return Err(FsError::WrongType); }
        if loc.first_cluster < FAT32_FIRST_DATA_CLUSTER { return Err(FsError::NotFound); }
        dir_cluster = loc.first_cluster;
    }
    Ok((dir_cluster, comps[n - 1]))
}

// ── Directory entry insert / update ──────────────────────────────────────────

/// Write a raw 32-byte dirent into the first free slot of `dir_cluster`.
/// If no slot exists and the chain is full, extends the directory by
/// allocating a new cluster.
///
/// Returns the sector and offset where the entry landed.
fn dir_insert(
    v: &'static Vol, dir_cluster: u32,
    name83: &[u8; 11],
    first_cluster: u32,
    size: u32,
    attr: u8,
) -> Result<(u32, u16), FsError> {
    let (spc, data_start, fat_sz32, data_clusters) = {
        let fv = v.fat32.lock();
        (fv.secs_per_clus, fv.data_start, fv.fat_sz32, fv.data_clusters)
    };
    // Cycle guard — see `ChainWalk`. Here the cap MUST return an error
    // rather than fall out of the loop: the code below the loop extends the
    // directory by allocating a fresh cluster and splicing it in with
    // `fat32_write_fat_entry(last_cluster, new_clus)`. Exiting the loop on a
    // cycle would graft a real allocation onto an attacker-controlled ring.
    let mut walk = ChainWalk::for_volume(fat_sz32, data_clusters);

    // Walk the chain looking for a free (end or deleted) slot.
    let mut cluster = dir_cluster;
    let mut last_cluster = cluster;
    while cluster >= FAT32_FIRST_DATA_CLUSTER && cluster < FAT32_EOC {
        if !walk.visit(cluster) { return Err(FsError::Io); }
        let first_sector = cluster_first_sector(data_start, cluster, spc)
            .ok_or(FsError::Io)?;
        for s in 0..spc {
            // s < spc, and cluster_first_sector proved first_sector + spc fits.
            let sec_num = first_sector + s;
            let mut buf = [0u8; SECTOR_SIZE];
            read_sector(v, sec_num, &mut buf).map_err(|()| FsError::Io)?;
            for e in 0..FAT32_DIRENTS_PER_SECTOR {
                let off = e * FAT32_DIR_ENTRY_SIZE;
                let first_byte = buf[off + DIRENT_OFF_NAME];
                if first_byte == DIRENT_MARK_END || first_byte == DIRENT_MARK_DELETED {
                    write_dirent_into_buf(&mut buf, off, name83, first_cluster, size, attr);
                    if first_byte == DIRENT_MARK_END {
                        // We just consumed the end-of-directory marker —
                        // terminate at whatever slot comes next, whether
                        // that is later in this sector, the next sector of
                        // this cluster, or the first sector of the next
                        // cluster already linked in the chain. See
                        // `propagate_end_marker`; the old same-sector-only
                        // check left every cross-boundary case (the only
                        // case at all when `spc == 1`) unterminated.
                        propagate_end_marker(v, 
                            cluster, s, sec_num, e, FAT32_DIRENTS_PER_SECTOR,
                            spc, data_start, &mut buf,
                        ).map_err(|()| FsError::Io)?;
                    }
                    write_sector(v, sec_num, &buf).map_err(|()| FsError::Io)?;
                    return Ok((sec_num, off as u16));
                }
            }
        }
        last_cluster = cluster;
        cluster = fat32_next_cluster(v, cluster).map_err(|()| FsError::Io)?;
    }

    // Extend the directory by one cluster: allocate it (the allocator marks
    // it end-of-chain), fill it — the dirent in slot 0, every other slot
    // zero, so slot 1 terminates the directory — and only THEN link it after
    // `last_cluster`. The link is the commit point: it used to come first,
    // so a crash (or a failed write) before the zeroing grafted a cluster of
    // stale data onto the directory, whose bytes every later walk would read
    // as entries. Now a failure before the link leaves the directory exactly
    // as it was and, at worst, one allocated cluster nothing references.
    let new_clus = fat32_alloc_cluster_on(v).map_err(|()| FsError::NoSpace)?;
    let filled = cluster_first_sector(data_start, new_clus, spc).ok_or(()).and_then(|first_sector| {
        let mut buf = [0u8; SECTOR_SIZE];
        write_dirent_into_buf(&mut buf, 0, name83, first_cluster, size, attr);
        write_sector(v, first_sector, &buf)?;
        let zero = [0u8; SECTOR_SIZE];
        for s in 1..spc {
            // s < spc, and cluster_first_sector proved first_sector + spc fits.
            write_sector(v, first_sector + s, &zero)?;
        }
        Ok(first_sector)
    });
    // Barrier: the filled cluster on the medium before the link. With a
    // volatile device cache the two would otherwise be one unordered epoch,
    // and a cut that kept the link but not the fill is the stale graft the
    // order above exists to prevent. `Unsupported` is not a failure here
    // (a device that cannot flush orders nothing, as before); an I/O error
    // is. Once per directory extension, never on the common insert.
    let first_sector = match filled {
        Ok(sec) if matches!(order_barrier(v), Ok(()) | Err(FsError::Unsupported)) => sec,
        _ => {
            fat32_free_chain_on(v, new_clus);
            return Err(FsError::Io);
        }
    };
    // The link. If it fails part-way, copy 0 (the copy every walk reads) may
    // or may not name `new_clus` — the mirror write can fail after copy 0's
    // landed — so `new_clus` is handed back only once the link is undone:
    // `last_cluster` is end-of-chain again in every copy, and nothing
    // references the extension. If the undo fails too, `new_clus` stays
    // allocated: a cluster copy 0 may still reference must not be freed
    // (a later allocation would hand it out while this directory uses it).
    if fat32_write_fat_entry(v, last_cluster, new_clus).is_err() {
        if fat32_write_fat_entry(v, last_cluster, FAT32_END_OF_CHAIN).is_ok() {
            fat32_free_chain_on(v, new_clus);
        }
        return Err(FsError::Io);
    }
    Ok((first_sector, 0))
}

/// Fill a 32-byte dirent inside `buf` at `off`.
fn write_dirent_into_buf(
    buf: &mut [u8; SECTOR_SIZE],
    off: usize,
    name83: &[u8; 11],
    first_cluster: u32,
    size: u32,
    attr: u8,
) {
    for b in &mut buf[off..off + FAT32_DIR_ENTRY_SIZE] { *b = 0; }
    buf[off + DIRENT_OFF_NAME..off + DIRENT_OFF_NAME + 8]
        .copy_from_slice(&name83[..8]);
    buf[off + DIRENT_OFF_EXT..off + DIRENT_OFF_EXT + 3]
        .copy_from_slice(&name83[8..11]);
    buf[off + DIRENT_OFF_ATTR] = attr;
    let hi = ((first_cluster >> 16) & 0xFFFF) as u16;
    let lo = (first_cluster & 0xFFFF) as u16;
    buf[off + DIRENT_OFF_FST_CLUS_HI..off + DIRENT_OFF_FST_CLUS_HI + 2]
        .copy_from_slice(&hi.to_le_bytes());
    buf[off + DIRENT_OFF_FST_CLUS_LO..off + DIRENT_OFF_FST_CLUS_LO + 2]
        .copy_from_slice(&lo.to_le_bytes());
    buf[off + DIRENT_OFF_FILE_SIZE..off + DIRENT_OFF_FILE_SIZE + 4]
        .copy_from_slice(&size.to_le_bytes());
}

/// Update the size + first-cluster fields of an existing dirent (in-place).
/// Used after writes extend/truncate a file.
fn dir_update_meta(
    v: &'static Vol, dir_sector: u32,
    dir_offset: u16,
    first_cluster: u32,
    size: u32,
) -> Result<(), FsError> {
    dir_update_meta_in(v, dir_sector, dir_offset, first_cluster, size, false)
}

/// [`dir_update_meta`] with the sector written ahead (`write_sector_ahead`)
/// when `ahead`.
fn dir_update_meta_in(
    v: &'static Vol, dir_sector: u32,
    dir_offset: u16,
    first_cluster: u32,
    size: u32,
    ahead: bool,
) -> Result<(), FsError> {
    let mut buf = [0u8; SECTOR_SIZE];
    read_sector(v, dir_sector, &mut buf).map_err(|()| FsError::Io)?;
    let off = dir_offset as usize;
    let hi = ((first_cluster >> 16) & 0xFFFF) as u16;
    let lo = (first_cluster & 0xFFFF) as u16;
    buf[off + DIRENT_OFF_FST_CLUS_HI..off + DIRENT_OFF_FST_CLUS_HI + 2]
        .copy_from_slice(&hi.to_le_bytes());
    buf[off + DIRENT_OFF_FST_CLUS_LO..off + DIRENT_OFF_FST_CLUS_LO + 2]
        .copy_from_slice(&lo.to_le_bytes());
    buf[off + DIRENT_OFF_FILE_SIZE..off + DIRENT_OFF_FILE_SIZE + 4]
        .copy_from_slice(&size.to_le_bytes());
    if ahead { write_sector_ahead(v, dir_sector, &buf) } else { write_sector(v, dir_sector, &buf) }
        .map_err(|()| FsError::Io)?;
    Ok(())
}

// ── Cluster chain walking helper ─────────────────────────────────────────────

/// Walk the cluster chain starting at `first_cluster` and return the cluster
/// number at the `n`-th position (0-indexed).  If the chain ends before that
/// position, returns `Err(FsError::NotFound)`.
fn chain_nth(v: &'static Vol, first_cluster: u32, n: u32) -> Result<u32, FsError> {
    if first_cluster < FAT32_FIRST_DATA_CLUSTER { return Err(FsError::NotFound); }
    // A chain longer than the FAT has entries is a cycle. `n` is already
    // bounded by the u32 file position, so this is not a hang, but a crafted
    // cycle would otherwise make one `fat32_read` grind through millions of
    // FAT lookups and then hand back data from a cluster the file never owned.
    let (fat_sz32, data_clusters) = { let fv = v.fat32.lock(); (fv.fat_sz32, fv.data_clusters) };
    if n >= chain_walk_limit(fat_sz32, data_clusters) { return Err(FsError::Io); }
    // A cycle is caught at its first repeat, not after `n` lookups.
    let mut walk = ChainWalk::for_volume(fat_sz32, data_clusters);
    walk.visit(first_cluster);
    let mut cur = first_cluster;
    for _ in 0..n {
        let next = fat32_next_cluster(v, cur).map_err(|()| FsError::Io)?;
        if next < FAT32_FIRST_DATA_CLUSTER || next >= FAT32_EOC {
            return Err(FsError::NotFound);
        }
        if !walk.visit(next) { return Err(FsError::Io); }
        cur = next;
    }
    Ok(cur)
}

/// The cluster after `cluster`, which [`chain_nth`] found at position
/// `n - 1`: position `n` of the same chain, with `chain_nth`'s bound and its
/// answers (`NotFound` where the chain ends, `Io` past the volume's bound or
/// on a failed FAT read). One step from a cluster a full walk already proved
/// is on the chain cannot loop.
fn chain_step(v: &'static Vol, cluster: u32, n: u32) -> Result<u32, FsError> {
    let (fat_sz32, data_clusters) = { let fv = v.fat32.lock(); (fv.fat_sz32, fv.data_clusters) };
    if n >= chain_walk_limit(fat_sz32, data_clusters) { return Err(FsError::Io); }
    let next = fat32_next_cluster(v, cluster).map_err(|()| FsError::Io)?;
    if next < FAT32_FIRST_DATA_CLUSTER || next >= FAT32_EOC {
        return Err(FsError::NotFound);
    }
    Ok(next)
}

/// Walk the cluster chain starting at `first_cluster` to the `n`-th position,
/// allocating new clusters as needed.  The final cluster is marked as
/// end-of-chain.  Returns the cluster number at position `n`.
fn chain_nth_or_extend(v: &'static Vol, first_cluster: u32, n: u32) -> Result<u32, FsError> {
    if first_cluster < FAT32_FIRST_DATA_CLUSTER { return Err(FsError::InvalidArg); }
    // Same bound as `chain_nth`: no legitimate chain can be longer than the
    // number of entries the FAT holds, and refusing early stops a crafted
    // cycle from turning one write into millions of FAT lookups.
    let (fat_sz32, data_clusters) = { let fv = v.fat32.lock(); (fv.fat_sz32, fv.data_clusters) };
    if n >= chain_walk_limit(fat_sz32, data_clusters) { return Err(FsError::Io); }
    // A cycle is caught at its first repeat, as in `chain_nth`; never
    // extended (the link below would graft onto the ring).
    let mut walk = ChainWalk::for_volume(fat_sz32, data_clusters);
    walk.visit(first_cluster);
    let mut cur = first_cluster;
    for _ in 0..n {
        let next = fat32_next_cluster(v, cur).map_err(|()| FsError::Io)?;
        if next >= FAT32_FIRST_DATA_CLUSTER && next < FAT32_EOC && !walk.visit(next) {
            return Err(FsError::Io);
        }
        if next < FAT32_FIRST_DATA_CLUSTER || next >= FAT32_EOC {
            // U09-2: once `fresh` reads end-of-chain no allocator can take
            // it, so allocation and the link below need no common hold —
            // each entry write claims its own FAT sector (F1: nothing is held
            // across the device I/O).
            #[cfg(any(feature = "fat-mutate-spin-canary", feature = "fat-mutate-pi-canary"))]
            let _canary = FAT_MUTATE_CANARY.lock(); // the old hold: alloc + both links
            let fresh = fat32_alloc_cluster_inner(v).map_err(|()| FsError::NoSpace)?;
            // FW2: `fresh`'s end-of-chain mark reaches the medium before the
            // link to it. In one FAT sector the two are one sector write;
            // across a sector boundary they are two lines of one epoch, and
            // a cut could leave the link without the mark: a chain through
            // a FREE cluster, which the allocator hands out again while
            // this file's next extension (or its free) still follows the
            // link into it. A barrier between them, once per FAT sector the
            // chain crosses (every 128 clusters when it is contiguous; up to
            // every cluster on a fragmented FAT): write-back closes an epoch
            // (no I/O), write-through flushes. A cut then leaves at worst a sound
            // tail past the size (`fat32_check_root_chain`).
            if fresh / FAT32_ENTRIES_PER_SECTOR != cur / FAT32_ENTRIES_PER_SECTOR
                && !cfg!(feature = "fw-tail-link-unordered-canary")
            {
                if let Err(e) = order_barrier(v) {
                    if e != FsError::Unsupported {
                        let _ = fat32_write_fat_entry(v, fresh, 0);
                        return Err(e);
                    }
                }
            }
            // A failed link would leak `fresh` (allocated, in no chain):
            // undo it as `dir_insert` does, and give `fresh` back only when
            // `cur` is end-of-chain again in every copy.
            if fat32_write_fat_entry(v, cur, fresh).is_err() {
                if fat32_write_fat_entry(v, cur, FAT32_END_OF_CHAIN).is_ok() {
                    let _ = fat32_write_fat_entry(v, fresh, 0);
                }
                return Err(FsError::Io);
            }
            // `fresh` is already end-of-chain in every copy: the allocator
            // marked it so under its sector's claim (wave 15, FW: this
            // rewrote it, a FAT read-modify-write per copy per cluster).
            if cfg!(feature = "fw-chain-walk-canary") {
                fat32_write_fat_entry(v, fresh, FAT32_END_OF_CHAIN).map_err(|()| FsError::Io)?;
            }
            cur = fresh;
        } else {
            cur = next;
        }
    }
    Ok(cur)
}

/// Zero-fill file bytes in `[start, end)`.
///
/// Used when a write creates a "hole" — a `seek` past the current size
/// followed by a `write` — so the hole reads back as zero instead of
/// whatever is physically sitting on the clusters that cover it.
/// `fat32_alloc_cluster` never zeroes a cluster's data, `fat32_free_chain`
/// never wipes it, and `chain_nth_or_extend` only links clusters into the
/// chain — none of them touch content. Without this, reading a hole returns
/// whatever a *previous* file left on that disk space, which on a shared
/// volume is a live information leak: create file A, delete it, create file
/// B reusing A's freed cluster, seek past it and write once more, and the
/// gap in B reads back as A's bytes. `first_cluster` must already be
/// allocated (the caller ensures that before a hole can exist).
fn zero_fill_range(
    v: &'static Vol, first_cluster: u32,
    start: u32,
    end: u32,
    bytes_per_clus: u32,
    spc: u32,
    data_start: u32,
) -> Result<(), FsError> {
    let mut pos = start;
    while pos < end {
        let cluster_index = pos / bytes_per_clus;
        let offset_in_cluster = (pos % bytes_per_clus) as usize;
        let cluster = chain_nth_or_extend(v, first_cluster, cluster_index)?;
        let first_sector = cluster_first_sector(data_start, cluster, spc)
            .ok_or(FsError::Io)?;

        // offset_in_cluster < bytes_per_clus == spc * 512, so sector_index <
        // spc, and cluster_first_sector proved first_sector + spc fits.
        let sector_index = (offset_in_cluster / SECTOR_SIZE) as u32;
        let offset_in_sector = offset_in_cluster % SECTOR_SIZE;
        let sec_num = first_sector + sector_index;

        let remaining_in_sector = SECTOR_SIZE - offset_in_sector;
        let to_zero = ((end - pos) as usize).min(remaining_in_sector);

        let mut sec_buf = [0u8; SECTOR_SIZE];
        if offset_in_sector != 0 || to_zero < SECTOR_SIZE {
            // Partial sector: read first so bytes outside [offset_in_sector,
            // offset_in_sector + to_zero) — legitimate data below `start`,
            // or a tail this call was not asked to zero — are preserved
            // rather than clobbered with zeros.
            read_sector(v, sec_num, &mut sec_buf).map_err(|()| FsError::Io)?;
        }
        for b in &mut sec_buf[offset_in_sector..offset_in_sector + to_zero] { *b = 0; }
        write_sector(v, sec_num, &sec_buf).map_err(|()| FsError::Io)?;

        pos += to_zero as u32;
    }
    Ok(())
}

// ── File handle pool helpers ─────────────────────────────────────────────────

fn alloc_handle(v: &'static Vol, entry: OpenFileEntry) -> Result<Fat32File, FsError> {
    let mut t = v.open_files.lock();
    for i in 0..FAT32_MAX_OPEN_FILES {
        if !t[i].in_use {
            let gen = t[i].generation.wrapping_add(1);
            let mut e = entry;
            e.in_use = true;
            e.generation = gen;
            t[i] = e;
            return Ok(Fat32File { slot: i as u16, generation: gen });
        }
    }
    Err(FsError::TooManyOpen)
}

fn with_handle<R>(
    v: &'static Vol, file: Fat32File,
    f: impl FnOnce(&mut OpenFileEntry) -> Result<R, FsError>,
) -> Result<R, FsError> {
    let mut t = v.open_files.lock();
    let slot = file.slot as usize;
    if slot >= FAT32_MAX_OPEN_FILES { return Err(FsError::BadHandle); }
    if !t[slot].in_use || t[slot].generation != file.generation {
        return Err(FsError::BadHandle);
    }
    f(&mut t[slot])
}

fn snapshot_handle(v: &'static Vol, file: Fat32File) -> Result<OpenFileEntry, FsError> {
    with_handle(v, file, |e| Ok(*e))
}

// ── Public open/close/read/write/seek/sync ───────────────────────────────────

/// [`fat32_open_on`] on the boot volume ([`BOOT`]).
#[inline]
pub fn fat32_open(vol: Volume, path: &[u8], flags: u32) -> Result<Fat32File, FsError> {
    fat32_open_on(&BOOT, vol, path, flags)
}

/// Open a file by absolute path (e.g. `b"/log/boot.log"`).  Supports nested
/// directories up to `FAT32_MAX_PATH_DEPTH` deep.
///
/// The file is also the page cache's (storage L11), under its key
/// (`key_of_path`): `TRUNCATE` forgets its pages, and the handle's reads and
/// writes settle them (see `fat32_read` and `fat32_write`).
pub fn fat32_open_on(v: &'static Vol, vol: Volume, path: &[u8], flags: u32) -> Result<Fat32File, FsError> {
    let name = key_of_path(path);
    if let Some(n) = &name {
        if flags & open_flags::TRUNCATE != 0 {
            cache_forget(v, n);
        }
    }
    open_entry(v, vol, path, flags, name)
}

/// The file's dirty pages go to the volume, for a direct reader or writer.
fn settle_cache(v: &'static Vol, key: &crate::vfs::InodeKey) -> Result<(), FsError> {
    crate::vfs::page_cache_flush_file(v.fs, key).map_err(|_| FsError::Io)
}

/// [`fat32_open`] with the page cache not consulted: what `Fat32Fs::read_at`
/// and `write_at` (the cache's own fill and write-back) open with, and the
/// body of the public call. `cache_name` is what the handle's later reads and
/// writes settle (`None`: nothing).
fn open_entry(v: &'static Vol, _vol: Volume, path: &[u8], flags: u32, cache_name: Option<crate::vfs::InodeKey>) -> Result<Fat32File, FsError> {
    if !fat32_mounted_on(v) { return Err(FsError::NotMounted); }
    if flags & (open_flags::READ | open_flags::WRITE) == 0 {
        return Err(FsError::InvalidArg);
    }

    let (parent_cluster, last) = resolve_parent(v, path)?;
    let name83 = component_to_83(last).ok_or(FsError::InvalidArg)?;
    open_at(v, parent_cluster, &name83, flags, cache_name)
}

/// [`open_entry`] for a file whose directory is already resolved (`flags`
/// checked, volume mounted).
fn open_at(v: &'static Vol, parent_cluster: u32, name83: &[u8; 11], flags: u32, cache_name: Option<crate::vfs::InodeKey>) -> Result<Fat32File, FsError> {

    let (dir_sector, dir_offset, first_cluster, size) =
        match dir_find_in(v, parent_cluster, name83) {
            Ok(loc) => {
                if loc.attr & ATTR_DIRECTORY != 0 { return Err(FsError::WrongType); }
                (loc.sector, loc.offset, loc.first_cluster, loc.size)
            }
            Err(FsError::NotFound) => {
                if flags & open_flags::CREATE == 0 { return Err(FsError::NotFound); }
                // Create empty dirent (no cluster allocated yet).
                let (sec, off) = dir_insert(v, 
                    parent_cluster,
                    name83,
                    0,
                    0,
                    DIRENT_ATTR_ARCHIVE_FILE,
                )?;
                (sec, off, 0u32, 0u32)
            }
            Err(e) => return Err(e),
        };

    let mut entry = OpenFileEntry {
        in_use: false,
        generation: 0,
        dir_sector,
        dir_offset,
        first_cluster,
        size,
        pos: 0,
        flags,
        dirty: false,
        cache_name,
    };

    // Handle TRUNCATE.
    //
    // U09-13: this used to free the chain FIRST and update the dirent
    // SECOND, with no journal covering the gap — the same "unlink old +
    // install new" shape `fat32_write_file`'s overwrite path already
    // journals as `OVERWRITE`, just with the new side empty (cluster=0,
    // size=0). A crash between the free and the dirent update left a
    // dirent pointing at a chain the next allocation could hand to another
    // file — a cross-link, not merely a leak. Journaled the same way, in
    // the same order `fat32_write_file`'s overwrite path and
    // `fat32_journal_recover`'s replay arm already agree on: write PENDING,
    // update the dirent, free the old chain, write COMMITTED, clear.
    if flags & open_flags::TRUNCATE != 0 && entry.size > 0 {
        let old_cluster = entry.first_cluster;

        let journal = JournalEntry {
            magic: JOURNAL_MAGIC,
            state: JOURNAL_PENDING,
            op_type: JOURNAL_OP_OVERWRITE,
            _pad: [0; 2],
            cluster: 0,
            fat_value: old_cluster,
            dir_sector,
            dir_offset,
            size: 0,
            _reserved: [0; JOURNAL_RESERVED_SIZE],
        };
        fat32_journal_write(v, &journal).map_err(|()| FsError::Io)?;
        // Barriers as in `write_file_journaled`'s overwrite arm (no chain
        // to order ahead of the record: the new side is empty).
        journal_barrier(v).map_err(|()| FsError::Io)?;

        let defer = defer_frees(v);
        dir_update_meta(v, dir_sector, dir_offset, 0, 0)?;
        if !defer && old_cluster >= FAT32_FIRST_DATA_CLUSTER {
            fat32_free_chain_on(v, old_cluster);
        }
        journal_barrier(v).map_err(|()| FsError::Io)?;

        let committed = JournalEntry { state: JOURNAL_COMMITTED, ..journal };
        fat32_journal_write(v, &committed).map_err(|()| FsError::Io)?;
        fat32_journal_clear(v).map_err(|()| FsError::Io)?;
        // Held until the clear is durable, as in `write_file_journaled`.
        if defer { let _ = defer_free(v, old_cluster, entry.size); }

        entry.first_cluster = 0;
        entry.size = 0;
        entry.dirty = true;
    }

    // APPEND positions at end-of-file on open.
    if flags & open_flags::APPEND != 0 {
        entry.pos = entry.size;
    }

    alloc_handle(v, entry)
}

/// [`fat32_read_on`] on the boot volume ([`BOOT`]).
#[inline]
pub fn fat32_read(file: Fat32File, buf: &mut [u8]) -> Result<usize, FsError> {
    fat32_read_on(&BOOT, file, buf)
}

/// Read up to `buf.len()` bytes starting at the file's current position.
/// Returns the number of bytes actually read (0 at EOF).
pub fn fat32_read_on(v: &'static Vol, file: Fat32File, buf: &mut [u8]) -> Result<usize, FsError> {
    if let Some(n) = snapshot_handle(v, file)?.cache_name {
        settle_cache(v, &n)?;
    }
    // File data the page cache can hold is not also held by the block cache.
    // This handle API is not the page cache's (OTA and driver images, config),
    // so with a cache installed these reads are one-shot and retain nothing.
    fat32_read_with(v, file, buf, !crate::vfs::page_cache_installed())
}

/// [`fat32_read`]; `retain: false` leaves the data sectors it reads out of the
/// block cache ([`read_sector_with`]).
fn fat32_read_with(v: &'static Vol, file: Fat32File, buf: &mut [u8], retain: bool) -> Result<usize, FsError> {
    let mut e = snapshot_handle(v, file)?;
    if e.flags & open_flags::READ == 0 { return Err(FsError::InvalidArg); }
    if e.pos >= e.size || buf.is_empty() { return Ok(0); }

    // One lock for the whole geometry: `sector_index < spc` below is only
    // provable if `bytes_per_clus == spc * 512` was read atomically. Three
    // separate locks let a concurrent (re)mount interleave and break that.
    let (bytes_per_clus, spc, data_start) = {
        let fv = v.fat32.lock();
        (fv.bytes_per_clus, fv.secs_per_clus, fv.data_start)
    };
    if bytes_per_clus == 0 { return Err(FsError::NotMounted); }

    let max = (e.size - e.pos) as usize;
    let mut remaining = buf.len().min(max);
    let mut written = 0usize;
    // The chain position this call reached: the next sector is in the same
    // cluster or the next one, one FAT lookup away, not a walk from the first
    // cluster (`chain_nth` for every sector made a sequential read of an
    // N-cluster file cost N*N/2 lookups).
    let mut at: Option<(u32, u32)> = None;

    while remaining > 0 {
        let cluster_index = e.pos / bytes_per_clus;
        let offset_in_cluster = (e.pos % bytes_per_clus) as usize;
        let cluster = match at {
            Some((i, c)) if i == cluster_index => c,
            Some((i, c)) if i + 1 == cluster_index => chain_step(v, c, cluster_index)?,
            _ => chain_nth(v, e.first_cluster, cluster_index)?,
        };
        at = Some((cluster_index, cluster));
        let first_sector = cluster_first_sector(data_start, cluster, spc)
            .ok_or(FsError::Io)?;

        // offset_in_cluster < bytes_per_clus == spc * 512, so
        // sector_index < spc, and cluster_first_sector proved
        // first_sector + spc fits in u32 — this add cannot overflow.
        let sector_index = (offset_in_cluster / SECTOR_SIZE) as u32;
        let offset_in_sector = offset_in_cluster % SECTOR_SIZE;
        let sec_num = first_sector + sector_index;

        let mut sec_buf = [0u8; SECTOR_SIZE];
        read_sector_with(v, sec_num, &mut sec_buf, retain).map_err(|()| FsError::Io)?;

        let avail_in_sector = SECTOR_SIZE - offset_in_sector;
        let chunk = remaining.min(avail_in_sector);
        buf[written..written + chunk]
            .copy_from_slice(&sec_buf[offset_in_sector..offset_in_sector + chunk]);

        written += chunk;
        remaining -= chunk;
        e.pos += chunk as u32;
    }

    // Persist updated position back into the slot.
    with_handle(v, file, |slot| {
        slot.pos = e.pos;
        Ok(())
    })?;
    Ok(written)
}

/// [`fat32_write_on`] on the boot volume ([`BOOT`]).
#[inline]
pub fn fat32_write(file: Fat32File, buf: &[u8]) -> Result<usize, FsError> {
    fat32_write_on(&BOOT, file, buf)
}

/// Write `buf` at the file's current position, extending the file and the
/// underlying cluster chain as needed.  Returns bytes written.
///
/// A failure part-way through a multi-sector write is a short write, as
/// POSIX `write(2)`: the bytes that reached the device are counted, the
/// handle's position and size advance by them, and the call returns
/// `Ok(n)` with `n < buf.len()` (the next call meets the error again and
/// returns it). Only a write that placed no byte returns `Err`; if that call
/// had started the chain of an empty file, the chain is freed again rather
/// than left allocated and named by nothing.
///
/// On a handle the page cache's dirty pages of the
/// file are written back first (this write is a read-modify-write of sectors
/// they may cover) and the cached pages are forgotten after: they are older
/// than the bytes written.
pub fn fat32_write_on(v: &'static Vol, file: Fat32File, buf: &[u8]) -> Result<usize, FsError> {
    let Some(n) = snapshot_handle(v, file)?.cache_name else { return fat32_write_raw(v, file, buf) };
    settle_cache(v, &n)?;
    let r = fat32_write_raw(v, file, buf);
    cache_forget(v, &n);
    r
}

/// [`fat32_write`] with the page cache not consulted (`Fat32Fs::write_at`: the
/// cache's write-back).
fn fat32_write_raw(v: &'static Vol, file: Fat32File, buf: &[u8]) -> Result<usize, FsError> {
    if buf.is_empty() { return Ok(0); }

    let mut e = snapshot_handle(v, file)?;
    if e.flags & open_flags::WRITE == 0 { return Err(FsError::InvalidArg); }

    // APPEND: jump to current size before every write.
    if e.flags & open_flags::APPEND != 0 { e.pos = e.size; }

    // Guard the position arithmetic below up front: `e.pos` grows by `chunk`
    // every loop iteration, and while reaching u32::MAX would take millions
    // of cluster allocations first (practically unreachable on any real
    // volume), an unchecked `+=` is still an `overflow-checks = true` abort
    // — a board reset — waiting to happen rather than a clean error.
    if e.pos.checked_add(buf.len() as u32).is_none() {
        return Err(FsError::NoSpace);
    }

    // One lock for the whole geometry — see the matching comment in
    // `fat32_read`; `sector_index < spc` depends on a consistent snapshot.
    let (bytes_per_clus, spc, data_start) = {
        let fv = v.fat32.lock();
        (fv.bytes_per_clus, fv.secs_per_clus, fv.data_start)
    };
    if bytes_per_clus == 0 { return Err(FsError::NotMounted); }

    // Ensure we have at least one cluster allocated (for empty files).
    let before = e;
    let mut fresh_first = None;
    if e.first_cluster < FAT32_FIRST_DATA_CLUSTER {
        let fresh = fat32_alloc_cluster_on(v).map_err(|()| FsError::NoSpace)?;
        // fat32_alloc_cluster already marks it EOC (0x0FFF_FFFF).
        e.first_cluster = fresh;
        e.dirty = true;
        fresh_first = Some(fresh);
    }

    // A seek past the current size followed by this write creates a hole:
    // zero-fill it now rather than let the loop below leave whatever is
    // physically on the newly linked clusters exposed as file data. See
    // `zero_fill_range`.
    let mut written = 0usize;
    let outcome = if e.pos > e.size {
        zero_fill_range(v, e.first_cluster, e.size, e.pos, bytes_per_clus, spc, data_start)
    } else {
        Ok(())
    }
    .and_then(|()| write_loop(v, &mut e, buf, &mut written, bytes_per_clus, spc, data_start));

    // Nothing landed and the chain was started by this call: hand the chain
    // back and leave the handle as it was. Kept, it would be allocated and
    // named by nothing until a later write or close happened to record it.
    if outcome.is_err() && written == 0 {
        if let Some(fresh) = fresh_first {
            fat32_free_chain_on(v, fresh);
            e = before;
        }
    }
    // Persist updated size/position/dirty/first_cluster back into the slot —
    // also after a failure, so what reached the device is counted.
    with_handle(v, file, |slot| {
        slot.pos = e.pos;
        slot.size = e.size;
        slot.first_cluster = e.first_cluster;
        slot.dirty = e.dirty;
        Ok(())
    })?;
    match outcome {
        Ok(()) => Ok(written),
        Err(_) if written > 0 => Ok(written),
        Err(err) => Err(err),
    }
}

/// The sector loop of [`fat32_write`]: `written` and `e` advance only past a
/// sector the device accepted, so on an `Err` they describe exactly what
/// landed.
fn write_loop(
    v: &'static Vol, e: &mut OpenFileEntry,
    buf: &[u8],
    written: &mut usize,
    bytes_per_clus: u32,
    spc: u32,
    data_start: u32,
) -> Result<(), FsError> {
    // Wave 15 (FW): the last (index, cluster) reached. The next sector is in
    // that cluster or the one after it, one FAT step away, so a write of n
    // clusters reads O(n) FAT entries, not the O(n^2) of a walk from the
    // first cluster per sector.
    let mut cursor: Option<(u32, u32)> = None;
    while *written < buf.len() {
        let written_now = *written;
        let cluster_index = e.pos / bytes_per_clus;
        let offset_in_cluster = (e.pos % bytes_per_clus) as usize;
        let cluster = match cursor {
            Some((i, c)) if i == cluster_index && !cfg!(feature = "fw-chain-walk-canary") => c,
            Some((i, c)) if i + 1 == cluster_index && !cfg!(feature = "fw-chain-walk-canary") =>
                chain_nth_or_extend(v, c, 1)?,
            _ => chain_nth_or_extend(v, e.first_cluster, cluster_index)?,
        };
        cursor = Some((cluster_index, cluster));
        let first_sector = cluster_first_sector(data_start, cluster, spc)
            .ok_or(FsError::Io)?;

        // sector_index < spc (offset_in_cluster < spc * 512) and
        // cluster_first_sector proved first_sector + spc fits in u32.
        let sector_index = (offset_in_cluster / SECTOR_SIZE) as u32;
        let offset_in_sector = offset_in_cluster % SECTOR_SIZE;
        let sec_num = first_sector + sector_index;

        // Read-modify-write the sector (partial writes require the untouched
        // head/tail to be preserved).
        let mut sec_buf = [0u8; SECTOR_SIZE];
        let sector_is_within_size = e.pos < e.size
            && (offset_in_sector != 0
                || (buf.len() - written_now) < SECTOR_SIZE);
        if sector_is_within_size {
            read_sector(v, sec_num, &mut sec_buf).map_err(|()| FsError::Io)?;
        } else if offset_in_sector != 0 {
            // Past current size but starting mid-sector — read to preserve
            // whatever junk is there (treated as zeros after size extension).
            read_sector(v, sec_num, &mut sec_buf).map_err(|()| FsError::Io)?;
            // Zero the tail beyond current size so stale bytes don't leak.
            for b in &mut sec_buf[offset_in_sector..] { *b = 0; }
        }

        let avail_in_sector = SECTOR_SIZE - offset_in_sector;
        let chunk = (buf.len() - written_now).min(avail_in_sector);
        sec_buf[offset_in_sector..offset_in_sector + chunk]
            .copy_from_slice(&buf[written_now..written_now + chunk]);
        write_sector(v, sec_num, &sec_buf).map_err(|()| FsError::Io)?;

        *written += chunk;
        e.pos += chunk as u32;
        if e.pos > e.size { e.size = e.pos; }
        e.dirty = true;
    }
    Ok(())
}

/// [`fat32_seek_on`] on the boot volume ([`BOOT`]).
#[inline]
pub fn fat32_seek(file: Fat32File, whence: SeekFrom) -> Result<u32, FsError> {
    fat32_seek_on(&BOOT, file, whence)
}

/// Seek within an open file.  Seeking past EOF is allowed but will NOT
/// allocate clusters until a write happens.
pub fn fat32_seek_on(v: &'static Vol, file: Fat32File, whence: SeekFrom) -> Result<u32, FsError> {
    with_handle(v, file, |e| {
        let new = match whence {
            SeekFrom::Start(p) => p,
            SeekFrom::Current(d) => {
                if d >= 0 { e.pos.saturating_add(d as u32) }
                else { e.pos.saturating_sub((-d) as u32) }
            }
            SeekFrom::End(d) => {
                if d >= 0 { e.size.saturating_add(d as u32) }
                else { e.size.saturating_sub((-d) as u32) }
            }
        };
        e.pos = new;
        Ok(new)
    })
}

/// [`fat32_fsync_on`] on the boot volume ([`BOOT`]).
#[inline]
pub fn fat32_fsync(file: Fat32File) -> Result<(), FsError> {
    fat32_fsync_on(&BOOT, file)
}

/// Make everything written through `file` durable: its data sectors, its
/// FAT chain, and the directory entry (size + first cluster) that makes
/// them part of the file.
///
/// Two device flushes, in this order:
///
/// 1. **Before the directory entry is written.** [`fat32_write`] has already
///    written the data sectors and linked the chain, but with a volatile
///    device cache those writes may still be pending. If the entry's new
///    size reached the medium first, a power cut would leave a file whose
///    tail is whatever the newly linked cluster held before: freed data of
///    some older file, which for the flight recorder can be an old, valid
///    record. This flush is an ordering barrier; `Unsupported` does not stop
///    the entry update (there is nothing to order against), `Io` does.
/// 2. **After the directory entry is written.** This is the durability point
///    a caller of `fsync` means. Its result is this function's result.
///
/// The handle stays dirty unless the device confirmed the second flush, so
/// `dirty` means "not known to be durable": `Err(Unsupported)` (the entry was
/// written, the device cannot confirm it) and `Err(Io)` both leave it set,
/// and the next `fsync` or `close` writes the entry and asks again. An `Ok`
/// from this function therefore always follows a confirmed flush.
pub fn fat32_fsync_on(v: &'static Vol, file: Fat32File) -> Result<(), FsError> {
    let snapshot = snapshot_handle(v, file)?;
    if !snapshot.dirty { return Ok(()); }
    match order_barrier(v) {
        Ok(()) | Err(FsError::Unsupported) => {}
        Err(e) => return Err(e),
    }
    dir_update_meta(v, 
        snapshot.dir_sector,
        snapshot.dir_offset,
        snapshot.first_cluster,
        snapshot.size,
    )?;
    let _ = journal_settle(v);
    device_flush(v)?;
    wb_take_error(v)?;
    with_handle(v, file, |e| { e.dirty = false; Ok(()) })
}

/// [`fat32_close_on`] on the boot volume ([`BOOT`]).
#[inline]
pub fn fat32_close(file: Fat32File) -> Result<(), FsError> {
    fat32_close_on(&BOOT, file)
}

/// Close an open file handle.  Implicitly fsyncs if the file is dirty.
///
/// The handle is released whatever happens (a descriptor is gone after
/// `close`, as in POSIX), but the implicit `fsync`'s verdict is the result:
/// until wave 11 this returned `Ok` even when the entry write or the flush
/// had failed, so a caller that checked `close` could not learn that the
/// data it had written was not durable (fsyncgate).
pub fn fat32_close_on(v: &'static Vol, file: Fat32File) -> Result<(), FsError> {
    let synced = fat32_fsync_on(v, file);
    with_handle(v, file, |e| {
        e.in_use = false;
        e.dirty = false;
        e.pos = 0;
        e.size = 0;
        e.first_cluster = 0;
        Ok(())
    })?;
    synced
}

/// Release a handle WITHOUT making it durable (wave 15): a dirty handle's
/// directory entry (size, first cluster) goes in a later epoch than the
/// data and the chain it names — a cut never leaves an entry over bytes the
/// device does not have — and nothing is flushed. The VFS's in-place writes
/// use it; `fat32_close` (= fsync) stays the durable close of this API.
///
/// Write-back (wave 15, FW): the entry is written AHEAD, into the epoch
/// after the current one, with no barrier. Consecutive writes of one file
/// then share one epoch for their data and chain, the entry is one cache
/// line rewritten in place, and it reaches the device once, after them,
/// at the write-back or the fsync that closes both epochs. Every reader
/// looks the entry up through the cache, so it sees the new size at once.
/// Write-through: an ordering barrier (a device flush), then the entry.
pub fn fat32_release(v: &'static Vol, file: Fat32File) -> Result<(), FsError> {
    let snapshot = snapshot_handle(v, file)?;
    let r = if snapshot.dirty && wb_active(v) && !cfg!(feature = "fw-entry-per-write-canary") {
        dir_update_meta_in(v, snapshot.dir_sector, snapshot.dir_offset,
            snapshot.first_cluster, snapshot.size, true)
    } else if snapshot.dirty {
        match order_barrier(v) {
            Ok(()) | Err(FsError::Unsupported) => dir_update_meta(v, 
                snapshot.dir_sector, snapshot.dir_offset, snapshot.first_cluster, snapshot.size),
            Err(e) => Err(e),
        }
    } else {
        Ok(())
    };
    with_handle(v, file, |e| {
        e.in_use = false;
        e.dirty = false;
        e.pos = 0;
        e.size = 0;
        e.first_cluster = 0;
        Ok(())
    })?;
    r
}

/// [`fat32_file_stat_on`] on the boot volume ([`BOOT`]).
#[inline]
pub fn fat32_file_stat(file: Fat32File) -> Result<(u32, u32), FsError> {
    fat32_file_stat_on(&BOOT, file)
}

/// Return `(position, size)` for an open file.  Useful for tests.
pub fn fat32_file_stat_on(v: &'static Vol, file: Fat32File) -> Result<(u32, u32), FsError> {
    with_handle(v, file, |e| Ok((e.pos, e.size)))
}

// ── Directories: opendir / readdir / mkdir ───────────────────────────────────

/// [`fat32_opendir_on`] on the boot volume ([`BOOT`]).
#[inline]
pub fn fat32_opendir(_vol: Volume, path: &[u8]) -> Result<Fat32DirIter, FsError> {
    fat32_opendir_on(&BOOT, _vol, path)
}

/// Open a directory by absolute path (`b"/"` for root).  Returns an iterator
/// that yields each non-deleted, non-LFN, non-volume-ID entry.
pub fn fat32_opendir_on(v: &'static Vol, _vol: Volume, path: &[u8]) -> Result<Fat32DirIter, FsError> {
    if !fat32_mounted_on(v) { return Err(FsError::NotMounted); }
    let mut comps: [&[u8]; FAT32_MAX_PATH_DEPTH] = [&[]; FAT32_MAX_PATH_DEPTH];
    let n = split_path(path, &mut comps)?;
    let root_cluster = v.fat32.lock().root_cluster;
    let mut dir_cluster = root_cluster;
    for i in 0..n {
        let name83 = component_to_83(comps[i]).ok_or(FsError::InvalidArg)?;
        let loc = dir_find_in(v, dir_cluster, &name83)?;
        if loc.attr & ATTR_DIRECTORY == 0 { return Err(FsError::WrongType); }
        if loc.first_cluster < FAT32_FIRST_DATA_CLUSTER { return Err(FsError::NotFound); }
        dir_cluster = loc.first_cluster;
    }
    let mut walk = { let fv = v.fat32.lock(); ChainWalk::for_volume(fv.fat_sz32, fv.data_clusters) };
    // The first cluster is the walk's first visit, so a self-link is seen
    // at the first advance.
    walk.visit(dir_cluster);
    Ok(Fat32DirIter {
        v,
        cluster: dir_cluster,
        sector_in_cluster: 0,
        entry_in_sector: 0,
        done: false,
        walk,
    })
}

impl Fat32DirIter {
    /// Return the next valid directory entry, or `None` at end.
    pub fn next(&mut self) -> Option<DirEntryInfo> {
        let v = self.v;
        if self.done { return None; }
        let (spc, data_start) = {
            let fv = v.fat32.lock();
            (fv.secs_per_clus, fv.data_start)
        };
        loop {
            if self.cluster < FAT32_FIRST_DATA_CLUSTER || self.cluster >= FAT32_EOC {
                self.done = true;
                return None;
            }
            // `None` = crafted cluster that does not map into the sector space.
            let first_sector = match cluster_first_sector(data_start, self.cluster, spc) {
                Some(v) => v,
                None => { self.done = true; return None; }
            };
            while self.sector_in_cluster < spc {
                // sector_in_cluster < spc, and cluster_first_sector proved
                // first_sector + spc fits in u32.
                let sec_num = first_sector + self.sector_in_cluster;
                let mut buf = [0u8; SECTOR_SIZE];
                if read_sector(v, sec_num, &mut buf).is_err() {
                    self.done = true;
                    return None;
                }
                while self.entry_in_sector < FAT32_DIRENTS_PER_SECTOR {
                    let off = self.entry_in_sector * FAT32_DIR_ENTRY_SIZE;
                    let first_byte = buf[off + DIRENT_OFF_NAME];
                    self.entry_in_sector += 1;
                    if first_byte == DIRENT_MARK_END {
                        self.done = true;
                        return None;
                    }
                    if first_byte == DIRENT_MARK_DELETED { continue; }
                    let attr = buf[off + DIRENT_OFF_ATTR];
                    if attr == ATTR_LFN { continue; }
                    if attr & ATTR_VOLUME_ID != 0 { continue; }
                    let mut name83 = [0u8; 11];
                    name83[..8].copy_from_slice(&buf[off + DIRENT_OFF_NAME..off + DIRENT_OFF_NAME + 8]);
                    name83[8..11].copy_from_slice(&buf[off + DIRENT_OFF_EXT..off + DIRENT_OFF_EXT + 3]);
                    let (name_buf, name_len) = format_83_name(&name83);
                    let hi = u16::from_le_bytes([
                        buf[off + DIRENT_OFF_FST_CLUS_HI],
                        buf[off + DIRENT_OFF_FST_CLUS_HI + 1],
                    ]) as u32;
                    let lo = u16::from_le_bytes([
                        buf[off + DIRENT_OFF_FST_CLUS_LO],
                        buf[off + DIRENT_OFF_FST_CLUS_LO + 1],
                    ]) as u32;
                    let size = u32::from_le_bytes([
                        buf[off + DIRENT_OFF_FILE_SIZE],
                        buf[off + DIRENT_OFF_FILE_SIZE + 1],
                        buf[off + DIRENT_OFF_FILE_SIZE + 2],
                        buf[off + DIRENT_OFF_FILE_SIZE + 3],
                    ]);
                    return Some(DirEntryInfo {
                        name: name_buf,
                        name_len: name_len as u8,
                        size,
                        is_dir: attr & ATTR_DIRECTORY != 0,
                        first_cluster: (hi << 16) | lo,
                    });
                }
                self.entry_in_sector = 0;
                self.sector_in_cluster += 1;
            }
            self.sector_in_cluster = 0;
            self.cluster = match fat32_next_cluster(v, self.cluster) {
                Ok(n) => n,
                Err(()) => { self.done = true; return None; }
            };
            // Cycle guard — see `walk`. Taken at the advance, so re-entering
            // `next()` on the same cluster does not consume budget.
            if !self.walk.visit(self.cluster) {
                self.done = true;
                return None;
            }
        }
    }
}

/// [`fat32_mkdir_on`] on the boot volume ([`BOOT`]).
#[inline]
pub fn fat32_mkdir(_vol: Volume, path: &[u8]) -> Result<(), FsError> {
    fat32_mkdir_on(&BOOT, _vol, path)
}

/// Create a new subdirectory at `path`.  The parent directory must exist.
/// Writes `.` (self) and `..` (parent) entries into the new directory.
pub fn fat32_mkdir_on(v: &'static Vol, _vol: Volume, path: &[u8]) -> Result<(), FsError> {
    if !fat32_mounted_on(v) { return Err(FsError::NotMounted); }
    let (parent_cluster, last) = resolve_parent(v, path)?;
    let name83 = component_to_83(last).ok_or(FsError::InvalidArg)?;

    // Fail if an entry already exists.
    if dir_find_in(v, parent_cluster, &name83).is_ok() { return Err(FsError::Exists); }

    // Allocate a cluster for the new directory and zero every sector.
    let new_clus = fat32_alloc_cluster_on(v).map_err(|()| FsError::NoSpace)?;
    let (spc, data_start) = {
        let fv = v.fat32.lock();
        (fv.secs_per_clus, fv.data_start)
    };
    let first_sector = match cluster_first_sector(data_start, new_clus, spc) {
        Some(v) => v,
        None => { fat32_free_chain_on(v, new_clus); return Err(FsError::Io); }
    };
    let mut buf = [0u8; SECTOR_SIZE];
    // '.' entry -> new_clus itself.
    let mut dot_name = [b' '; 11];
    dot_name[0] = b'.';
    write_dirent_into_buf(&mut buf, 0, &dot_name, new_clus, 0, DIRENT_ATTR_SUBDIR);
    // '..' entry -> parent cluster (root stored as 0 per FAT32 convention).
    let root_cluster = v.fat32.lock().root_cluster;
    let dotdot_target = if parent_cluster == root_cluster { 0 } else { parent_cluster };
    let mut dotdot_name = [b' '; 11];
    dotdot_name[0] = b'.';
    dotdot_name[1] = b'.';
    write_dirent_into_buf(
        &mut buf,
        FAT32_DIR_ENTRY_SIZE,
        &dotdot_name,
        dotdot_target,
        0,
        DIRENT_ATTR_SUBDIR,
    );
    // The rest of the sector is already zero (DIRENT_MARK_END).
    // A failed write frees the cluster it allocated, as a failed insert does
    // below: nothing names it yet, so it would otherwise leak for good.
    if write_sector(v, first_sector, &buf).is_err() {
        fat32_free_chain_on(v, new_clus);
        return Err(FsError::Io);
    }
    // Zero remaining sectors in the cluster so iteration terminates.
    let zero = [0u8; SECTOR_SIZE];
    for s in 1..spc {
        // s < spc, and cluster_first_sector proved first_sector + spc fits.
        if write_sector(v, first_sector + s, &zero).is_err() {
            fat32_free_chain_on(v, new_clus);
            return Err(FsError::Io);
        }
    }

    // Barrier: the new directory's cluster (its "." and ".." entries, the
    // rest zero) and its FAT mark on the medium before the parent's entry
    // that names it. Without it they are one unordered epoch, and a cut that
    // keeps the entry but not the cluster lists a directory whose first
    // sector is whatever the cluster held before (garbage entries). The same
    // order `dir_insert` keeps for a directory extension. `Unsupported` is a
    // device that orders nothing, as there.
    if !cfg!(feature = "mkdir-unordered-canary")
        && !matches!(order_barrier(v), Ok(()) | Err(FsError::Unsupported))
    {
        fat32_free_chain_on(v, new_clus);
        return Err(FsError::Io);
    }
    // Insert dirent for the new dir into the parent.
    match dir_insert(v, parent_cluster, &name83, new_clus, 0, DIRENT_ATTR_SUBDIR) {
        Ok(_) => Ok(()),
        Err(e) => {
            // Roll back: free the allocated cluster.
            fat32_free_chain_on(v, new_clus);
            Err(e)
        }
    }
}

// Provide a const constructor to let callers build a Volume handle without
// going through `fat32_mount_volume` — useful in tests that mount via the
// legacy `fat32_mount_on()` API.
impl Volume {
    pub const fn assume_mounted() -> Self { Volume { _private: () } }
}

// ── The VFS backend ───────────────────────────────────────────────────────────
//
// `crates/fs/fs` declared no traits at all: three filesystems, no interface
// between them, and the generic inode carrying an 8.3 name because this one
// filesystem needed it. This block is FAT32's side of `vfs::FileSystem` — the
// eight operations the VFS actually performs, and nothing else. The free
// `fat32_*` functions above are untouched and remain the direct API; the
// measured `fs.*` bench lane and every in-kernel caller still use them.

/// FAT32 as a value the VFS can be handed.
///
/// A handle to one volume's state ([`Vol`]), not a copy of it: one static
/// per volume ([`FAT32_FS`] for [`BOOT`], `usbvol::USB_FS` for the stick),
/// which the VFS tells apart by address (`mount_index`, the page cache).
pub struct Fat32Fs { vol: &'static Vol }

/// The boot volume as a backend (`vfs_mount_fs`): what its own page-cache and
/// unmount paths name it by ([`Vol`]'s `fs`), and what `vfs::FAT32_FS`
/// re-exports for `/fat`.
pub static FAT32_FS: Fat32Fs = Fat32Fs { vol: &BOOT };

impl Fat32Fs {
    /// The backend of volume `v` (its own static: the VFS tells backends
    /// apart by address).
    pub const fn of(v: &'static Vol) -> Fat32Fs {
        Fat32Fs { vol: v }
    }
}

/// The longest 8.3 name as text (`NAME.EXT`) is twelve bytes; the generic key
/// must hold at least one. Checked here, where the requirement is, rather than
/// asserted in `vfs.rs`, where the number would be a FAT32 constant wearing a
/// generic name. (A deeper path needs more; `key_of_path` refuses what does
/// not fit.)
const _: () = assert!(12 < crate::vfs::INODE_KEY_LEN);

/// The file a key names, as the `FileSystem` methods that cannot report why
/// (`Option`, `()`) see it.
#[inline]
fn named(v: &'static Vol, key: &crate::vfs::InodeKey) -> Option<FName> {
    FName::of_key(v, key).ok()
}

impl crate::vfs::FileSystem for Fat32Fs {
    #[inline]
    fn fs_type(&self) -> u32 { self.vol.knobs.fs_type }

    #[inline]
    fn mount(&self) -> Result<(), ()> { fat32_mount_on(self.vol) }

    #[inline]
    fn sync(&self) -> Result<(), ()> { fat32_sync_on(self.vol) }

    /// A file's fsync is the volume's (`fat32_sync_checked`), so a volume
    /// flush ticket is every descriptor's. Only where the `fs-wb` task serves
    /// this volume's tickets (`dev::TICKETED`); elsewhere `None`, and the
    /// caller syncs inline.
    #[inline]
    fn flush_request(&self) -> Option<u64> {
        let v = self.vol;
        if v.knobs.ticketed { Some(fat32_flush_request_on(v)) } else { None }
    }

    #[inline]
    fn flush_done(&self, t: u64) -> Option<Result<(), crate::vfs::FsErr>> {
        fat32_flush_done(t).map(|r| r.map_err(fs_err))
    }

    /// 8.3 conversion of every component, and the directories: the key is the
    /// canonical path (`key_of_path`). A leading, trailing or doubled slash
    /// names nothing.
    #[inline]
    fn key_for(&self, name: &[u8]) -> Option<crate::vfs::InodeKey> {
        if name.first() == Some(&b'/') || name.last() == Some(&b'/') || name.windows(2).any(|w| w == b"//") {
            return None;
        }
        key_of_path(name)
    }

    /// One directory scan, whose result carries the start cluster forward as
    /// the opaque cookie so `read_all` does not scan again.
    #[inline]
    ///
    /// It also reports what the entry holds: directory or
    /// file, read-only (`0444` instead of `0644`), and the DOS write, create
    /// and access stamps as Unix seconds (local time, as FAT stores it; 0
    /// for a stamp of 0).
    fn stat(&self, key: &crate::vfs::InodeKey) -> Option<crate::vfs::FileStat> {
        let v = self.vol;
        let f = named(v, key)?;
        let e = lookup_entry(v, f.dir, &f.name).ok()?;
        let is_dir = e.attr & ATTR_DIRECTORY != 0;
        let mut st = if is_dir {
            crate::vfs::FileStat::dir(e.size as u64)
        } else {
            crate::vfs::FileStat::file(e.size as u64, e.cluster)
        };
        st.cookie = e.cluster;
        if e.attr & ATTR_READ_ONLY != 0 { st.mode &= !0o222; }
        st.mtime = dos_to_unix(e.wrt_date, e.wrt_time);
        st.ctime = st.mtime;
        st.atime = dos_to_unix(e.acc_date, 0);
        Some(st)
    }

    #[inline]
    fn read_all(
        &self,
        _key: &crate::vfs::InodeKey,
        st: &crate::vfs::FileStat,
        dst: &mut [u8],
    ) -> usize {
        let v = self.vol;
        // The cookie is the start cluster `stat` already found. The key is not
        // needed, and using it would cost a second scan of the same directory.
        fat32_read_chain_on(v, st.cookie, dst)
    }

    #[inline]
    fn write_all(&self, key: &crate::vfs::InodeKey, src: &[u8]) -> Result<(), ()> {
        let v = self.vol;
        let f = named(v, key).ok_or(())?;
        // Queued under write-back (wave 15): a close is not a durability
        // point; `fsync` (below, `fat32_sync_checked`) is.
        write_file_queued_at(v, &f, src)
    }

    /// Deletes the directory entry and then frees the cluster chain, which
    /// is what `fat32_unlink_path` does (see its doc for why in that order)
    /// — the same operation, entered with a key instead of a raw filename.
    #[inline]
    fn unlink(&self, key: &crate::vfs::InodeKey) -> Result<(), ()> {
        let v = self.vol;
        let f = named(v, key).ok_or(())?;
        let cluster = lookup_entry(v, f.dir, &f.name).map(|e| e.cluster).unwrap_or(0);
        unlink_at(v, &f)?;
        if cluster >= 2 { fat32_free_chain_on(v, cluster); }
        Ok(())
    }

    /// Read-only opens stream through the read handle (wave 14): no
    /// whole-file load for `open` + `read`.
    #[inline]
    fn stream_reads(&self) -> bool { true }

    /// Writable opens stream too (wave 15, owner decision): reads and writes
    /// go to the file in place through the block cache, as on Linux — no
    /// whole-file proxy load on open and no journaled whole-file rewrite on
    /// close. A write is not atomic; an atomic replace is a temp file,
    /// fsync, then `rename` over the live name (`fat32_rename`):
    /// `vfs::vfs_replace_file`.
    #[inline]
    fn streaming(&self) -> bool { !cfg!(feature = "fat-proxy-writes-canary") }

    /// Read-only opens keep the read-handle path above.
    #[inline]
    fn ro_handles(&self) -> bool { true }

    /// File data goes through the page cache when the kernel installs one
    /// (`vfs::vfs_page_cache_hooks`); `read_at`/`write_at` are its backing.
    #[inline]
    fn page_cached(&self) -> bool { true }

    /// The start cluster `stat` found, with the volume's write generation
    /// then (see `WRITE_GEN`).
    #[inline]
    fn read_handle(&self, cookie: u32) -> u64 {
        let v = self.vol;
        ((v.write_gen.load(core::sync::atomic::Ordering::Acquire) as u64) << 32) | cookie as u64
    }

    /// The handle's start cluster is the one `stat` reports now: the name was
    /// not replaced or renamed over since the open.
    #[inline]
    fn handle_names(&self, handle: u64, cookie: u32) -> bool {
        handle as u32 == cookie
    }

    /// The file's identity under the volume's write epoch (wave 14,
    /// SPAWNCACHE): its start cluster and size, valid while no write of the
    /// volume (ours, an observed external one, a mount or an unmount) has
    /// happened since. `None` for a directory, an empty file, or a lookup a
    /// write overlapped.
    fn content_stamp(&self, key: &crate::vfs::InodeKey) -> Option<crate::vfs::ContentStamp> {
        let v = self.vol;
        let f = named(v, key)?;
        let epoch = fat32_write_epoch_on(v);
        let e = lookup_entry(v, f.dir, &f.name).ok()?;
        if e.attr & ATTR_DIRECTORY != 0 || e.cluster < 2 || e.size == 0 {
            return None;
        }
        if fat32_write_epoch_on(v) != epoch {
            return None;
        }
        Some(crate::vfs::ContentStamp {
            fs: v.knobs.stamp, epoch, id: e.cluster as u64, size: e.size as u64,
        })
    }

    /// One root-entry lookup, none of `stat`'s date conversions.
    #[inline]
    fn stat_brief(&self, key: &crate::vfs::InodeKey) -> Option<(u64, bool, u32)> {
        let v = self.vol;
        let f = named(v, key)?;
        let e = lookup_entry(v, f.dir, &f.name).ok()?;
        Some((e.size as u64, e.attr & ATTR_DIRECTORY != 0, e.cluster))
    }

    /// While no write touched the volume since the open, the chain and size
    /// the open found still hold: read them directly. Otherwise look the
    /// name up again and read what the directory says now (a rewrite may
    /// have moved or freed the old chain — reading it would hand out
    /// another file's clusters).
    fn read_at_handle(
        &self,
        key: &crate::vfs::InodeKey,
        handle: u64,
        size: u64,
        offset: u64,
        dst: &mut [u8],
    ) -> usize {
        let v = self.vol;
        let offset = match u32::try_from(offset) { Ok(o) => o, Err(_) => return 0 };
        let gen = v.write_gen.load(core::sync::atomic::Ordering::Acquire);
        if (handle >> 32) as u32 == gen && size <= u32::MAX as u64 {
            return fat32_read_range_on(v, handle as u32, size as u32, offset, dst, true);
        }
        let Some(f) = named(v, key) else { return 0 };
        match lookup_entry(v, f.dir, &f.name) {
            Ok(e) if e.attr & ATTR_DIRECTORY == 0 => fat32_read_range_on(v, e.cluster, e.size, offset, dst, true),
            _ => 0,
        }
    }

    /// The page cache's fill (or a read with none): the name is looked up
    /// (the directory cache answers a repeat) and the bytes are read by
    /// [`fat32_read_range`], one walk of the chain to the cluster holding
    /// `offset` through a FAT window and then forward only. The file's data is
    /// held in the cache's pages, not again in the block cache.
    ///
    /// This used to open a handle, seek and `fat32_read_with`, which looked
    /// the whole chain up again from the first cluster for EVERY SECTOR it
    /// copied (`chain_nth`, a lock and a cache probe per step): a sequential
    /// read of an N-cluster file cost N*N/2 FAT lookups, and starting a
    /// 850 KB service image from a volume of 512 B clusters kept the spawn
    /// busy for seconds (the component manager started the console program
    /// behind it).
    #[inline]
    fn read_at(&self, key: &crate::vfs::InodeKey, offset: u64, dst: &mut [u8]) -> usize {
        let v = self.vol;
        // FAT32 files end below 4 GiB; an offset past that is past EOF.
        let offset = match u32::try_from(offset) { Ok(o) => o, Err(_) => return 0 };
        let Some(f) = named(v, key) else { return 0 };
        match lookup_entry(v, f.dir, &f.name) {
            Ok(e) if e.attr & ATTR_DIRECTORY == 0 => {
                fat32_read_range_on(v, e.cluster, e.size, offset, dst, !crate::vfs::page_cache_installed())
            }
            _ => 0,
        }
    }

    /// Streams through the same file-level API: `fat32_write` does a
    /// sector-granular read-modify-write at the seeked position (extending
    /// the cluster chain as needed via `chain_nth_or_extend`), never a
    /// whole-file rewrite. `CREATE` is set so a first `write_at` on a file
    /// that exists only as an `InodeKey` (no dirent yet) still lands.
    #[inline]
    fn write_at(&self, key: &crate::vfs::InodeKey, offset: u64, src: &[u8]) -> Result<usize, ()> {
        let v = self.vol;
        let offset = u32::try_from(offset).map_err(|_| ())?;
        let f = named(v, key).ok_or(())?;
        let t0 = crate::census::now();
        let file = open_at(v, 
            f.dir,
            &f.name,
            open_flags::WRITE | open_flags::CREATE,
            None,
        ).map_err(|_| ())?;
        let t1 = crate::census::now();
        crate::census::add(crate::census::W_LOOKUP, t0, t1);
        let result = match fat32_seek_on(v, file, SeekFrom::Start(offset)) {
            Ok(_)  => fat32_write_raw(v, file, src).map_err(|_| ()),
            Err(_) => Err(()),
        };
        let t2 = crate::census::now();
        crate::census::add(crate::census::W_DATA, t1, t2);
        // The directory entry follows the data and the FAT chain in a later
        // epoch (`fat32_release`); no flush — `fsync` is the durability
        // point (`FileSystem::fsync`, `fat32_sync_checked`).
        let released = fat32_release(v, file);
        crate::census::add(crate::census::W_ENTRY, t2, crate::census::now());
        match (result, released) {
            (Ok(n), Ok(())) => Ok(n),
            _ => Err(()),
        }
    }

    // ── Streaming backend ──────────────────────────────────────
    //
    // FAT32 stays a PROXY backend for every open that may write
    // (`streaming` keeps its default `false`): that open/close behaviour, and
    // every gate row built on it, is unchanged. Since wave 14 a READ-ONLY
    // open streams instead (`stream_reads`, above). What it gains is the part of the new surface it can honour
    // with code it already has; the rest answers `Unsupported`.

    /// An empty file through the journaled whole-file write, only when no
    /// entry exists (that write would otherwise truncate).
    fn create(&self, key: &crate::vfs::InodeKey) -> Result<(), crate::vfs::FsErr> {
        let v = self.vol;
        let f = FName::of_key(v, key).map_err(fs_err)?;
        if lookup_entry(v, f.dir, &f.name).is_ok() { return Ok(()); }
        // Queued under write-back, like `write_all`: durable at fsync/sync.
        write_file_queued_at(v, &f, &[]).map_err(|()| crate::vfs::FsErr::Io)
    }

    /// Every length through the journaled whole-file write, the path every
    /// FAT32 proxy close already takes: the first `min(len, size)` bytes are
    /// read, the rest zero-filled, and the result replaces the file in one
    /// journaled step, so a cut leaves the old file or the new one. The
    /// current length is a no-op. A directory is `Invalid`; a length a FAT32
    /// file cannot have (4 GiB or more) is `NoSpace`, and so is a buffer the
    /// heap cannot give — refused, never a panic. (No in-place chain trim:
    /// that is a second journaled path to keep correct, and a FAT32 file is
    /// already held whole in memory by the proxy that opens it.)
    fn truncate(&self, key: &crate::vfs::InodeKey, len: u64) -> Result<(), crate::vfs::FsErr> {
        let v = self.vol;
        let t0 = crate::census::now();
        let r = (|| -> Result<(), crate::vfs::FsErr> {
            use crate::vfs::FsErr;
            let f = FName::of_key(v, key).map_err(fs_err)?;
            let e = lookup_entry(v, f.dir, &f.name).map_err(|()| FsErr::NotFound)?;
            if e.attr & ATTR_DIRECTORY != 0 { return Err(FsErr::Invalid); }
            if len == e.size as u64 { return Ok(()); }
            if len == 0 && !cfg!(feature = "fat-proxy-writes-canary") {
                // Wave 15, the `O_TRUNC` of an in-place write: the entry first
                // (no chain, size 0), then the old chain freed, never in the
                // same epoch. Write-back holds it (`defer_free`) until the
                // flush that makes this entry durable, so the new data and
                // chain share the entry's epoch and an fsync is two flushes;
                // write-through frees one epoch later. A cut leaves the old
                // file or an empty one; at worst the old chain leaks, it is
                // never named by a live entry while free. No journal record,
                // no whole-file rewrite.
                //
                // Wave 15 (FW): with the old chain held, the cleared entry is
                // written AHEAD (`write_sector_ahead`), like the entry an
                // in-place write leaves: nothing in the current epoch depends
                // on it (the held chain cannot be reallocated), so a truncate
                // and the writes after it share the current epoch for their
                // data and one later epoch for the entry. The held chain is
                // stamped with that later epoch (`defer_free`). A chain freed
                // at once (write-through, `FS_DEFERRED_FREE` off) keeps the
                // entry in the current epoch, ordered before the free.
                let (sector, off) = find_dirent_location(v, f.dir, &f.name).map_err(|()| FsErr::Io)?;
                let ahead = defer_frees(v) && !cfg!(feature = "fw-entry-per-write-canary");
                dirent_clus_size_in(v, sector, off, 0, 0, ahead).map_err(|()| FsErr::Io)?;
                if e.cluster >= FAT32_FIRST_DATA_CLUSTER {
                    if defer_frees(v) {
                        defer_free(v, e.cluster, e.size).map_err(fs_err)?;
                    } else {
                        order_barrier(v).or_else(|e| if e == FsError::Unsupported { Ok(()) } else { Err(e) })
                            .map_err(fs_err)?;
                        fat32_free_chain_on(v, e.cluster);
                    }
                }
                return Ok(());
            }
            let len = u32::try_from(len).map_err(|_| FsErr::NoSpace)? as usize;
            let mut buf = alloc::vec::Vec::new();
            buf.try_reserve_exact(len).map_err(|_| FsErr::NoSpace)?;
            buf.resize(len, 0u8);
            let keep = len.min(e.size as usize);
            if keep > 0 && fat32_read_chain_on(v, e.cluster, &mut buf[..keep]) != keep {
                return Err(FsErr::Io);
            }
            write_file_queued_at(v, &f, &buf).map_err(|()| FsErr::Io)
        })();
        crate::census::add(crate::census::TRUNC, t0, crate::census::now());
        r
    }

    /// An empty subdirectory: its dirent is removed first
    /// (journaled, as `unlink`'s is) and its chain freed after, so a cut
    /// leaves at worst a leaked chain, never a listed directory over free
    /// clusters. `NotEmpty` when it holds anything besides `.` and `..`,
    /// `NotDir` for a file.
    fn rmdir(&self, name: &[u8]) -> Result<(), crate::vfs::FsErr> {
        let v = self.vol;
        use crate::vfs::FsErr;
        let key = self.key_for(name).ok_or(FsErr::Invalid)?;
        let f = FName::of_key(v, &key).map_err(fs_err)?;
        let e = lookup_entry(v, f.dir, &f.name).map_err(|()| FsErr::NotFound)?;
        if e.attr & ATTR_DIRECTORY == 0 { return Err(FsErr::NotDir); }
        if !fat32_dir_is_empty(v, e.cluster).map_err(|()| FsErr::Io)? { return Err(FsErr::NotEmpty); }
        unlink_at(v, &f).map_err(|()| FsErr::Io)?;
        if e.cluster >= FAT32_FIRST_DATA_CLUSTER { fat32_free_chain_on(v, e.cluster); }
        Ok(())
    }

    /// Volume-wide: the journal is settled and the device flushed
    /// (`fat32_sync_checked`); FAT32 keeps no per-file dirty state here.
    fn fsync(&self, _key: &crate::vfs::InodeKey) -> Result<(), crate::vfs::FsErr> {
        let v = self.vol;
        fat32_sync_checked_on(v).map_err(fs_err)
    }

    /// Swap file (`MM_SWAP_BACKEND_FILE`): a grow appends zeroed clusters
    /// through the ordinary write path (the chain is extended a cluster at a
    /// time, the entry follows), a shrink to zero is the journaled truncate,
    /// any other shrink [`fat32_trim_file`]. Durable on return. A FAT32 file
    /// ends below 4 GiB: more is `NoSpace`.
    fn swap_resize(&self, key: &crate::vfs::InodeKey, len: u64) -> Result<(), crate::vfs::FsErr> {
        let v = self.vol;
        use crate::vfs::FsErr;
        let f = FName::of_key(v, key).map_err(fs_err)?;
        let e = lookup_entry(v, f.dir, &f.name).map_err(|()| FsErr::NotFound)?;
        if e.attr & ATTR_DIRECTORY != 0 { return Err(FsErr::Invalid); }
        let want = u32::try_from(len).map_err(|_| FsErr::NoSpace)?;
        if want > e.size {
            // Zeros from the end of the file: the blocks the chain gains hold
            // no other file's bytes, and nothing is a hole.
            let zeros = [0u8; SWAP_ZERO_CHUNK];
            let mut at = e.size;
            while at < want {
                let n = ((want - at) as usize).min(zeros.len());
                match self.write_at(key, at as u64, &zeros[..n]) {
                    Ok(w) if w == n => at += n as u32,
                    Ok(_) => return Err(FsErr::NoSpace),
                    Err(()) => return Err(FsErr::Io),
                }
            }
        } else if want == 0 && e.size != 0 {
            self.truncate(key, 0)?;
        } else if want < e.size {
            fat32_trim_file(v, &f, e, want)?;
        }
        fat32_sync_checked_on(v).map_err(fs_err)
    }

    /// Swap file: the clusters of the chain, in order, as runs of sectors
    /// (`dev_lba` adds the volume's first sector on the medium); clusters
    /// that follow each other on the medium are one run. The last run stops
    /// at `len`. A chain shorter than `len` is `Invalid`.
    fn swap_runs(
        &self,
        key: &crate::vfs::InodeKey,
        len: u64,
        out: &mut [crate::vfs::SectorRun],
    ) -> Result<usize, crate::vfs::FsErr> {
        let v = self.vol;
        use crate::vfs::{FsErr, SectorRun};
        let f = FName::of_key(v, key).map_err(fs_err)?;
        let e = lookup_entry(v, f.dir, &f.name).map_err(|()| FsErr::NotFound)?;
        if e.attr & ATTR_DIRECTORY != 0 || len > e.size as u64 { return Err(FsErr::Invalid); }
        let mut left = len.div_ceil(SECTOR_SIZE as u64);
        if left == 0 { return Ok(0); }
        let (spc, data_start, fat_sz32, data_clusters) = {
            let fv = v.fat32.lock();
            (fv.secs_per_clus, fv.data_start, fv.fat_sz32, fv.data_clusters)
        };
        let mut walk = ChainWalk::for_volume(fat_sz32, data_clusters);
        let (mut cl, mut n) = (e.cluster, 0usize);
        while left > 0 {
            if cl < FAT32_FIRST_DATA_CLUSTER || cl >= FAT32_EOC || !walk.visit(cl) { return Err(FsErr::Invalid); }
            let first = cluster_first_sector(data_start, cl, spc).ok_or(FsErr::Invalid)?;
            let take = left.min(spc as u64) as u32;
            let lba = dev_lba(v, first as u64);
            match n.checked_sub(1).map(|i| out[i]) {
                Some(r) if r.lba + r.sectors as u64 == lba => out[n - 1].sectors += take,
                _ => {
                    if n == out.len() { return Err(FsErr::NoSpace); }
                    out[n] = SectorRun { lba, sectors: take };
                    n += 1;
                }
            }
            left -= take as u64;
            if left > 0 { cl = fat32_next_cluster(v, cl).map_err(|()| FsErr::Io)?; }
        }
        Ok(n)
    }

    fn mkdir(&self, name: &[u8]) -> Result<(), crate::vfs::FsErr> {
        let v = self.vol;
        fat32_mkdir_on(v, Volume { _private: () }, name).map_err(fs_err)
    }

    /// Within a directory or from one to another (a file; see
    /// `fat32_rename`).
    fn rename(&self, from: &[u8], to: &[u8]) -> Result<(), crate::vfs::FsErr> {
        let v = self.vol;
        let a = self.key_for(from).ok_or(crate::vfs::FsErr::Invalid)?;
        let b = self.key_for(to).ok_or(crate::vfs::FsErr::Invalid)?;
        rename_at(v, &FName::of_key(v, &a).map_err(fs_err)?, &FName::of_key(v, &b).map_err(fs_err)?)
    }

    fn statfs(&self) -> Result<crate::vfs::StatFs, crate::vfs::FsErr> {
        let v = self.vol;
        let (bpc, clusters) = {
            let fv = v.fat32.lock();
            if !fv.mounted { return Err(crate::vfs::FsErr::NotFound); }
            (fv.bytes_per_clus, fv.data_clusters)
        };
        // Held chains (`defer_free`) count as free: the allocator flushes
        // and frees them rather than report the volume full.
        let free = (fat32_free_clusters(v).map_err(|()| crate::vfs::FsErr::Io)? as u64
            + fat32_held_clusters_on(v) as u64).min(clusters as u64);
        Ok(crate::vfs::StatFs {
            fs_type: crate::vfs::FS_TYPE_FAT32, block_size: bpc,
            blocks: clusters as u64, blocks_free: free,
            files: 0, files_free: 0, name_max: 12,
        })
    }

    /// Any directory `fat32_opendir` reaches (subdirectories included). The
    /// cookie is the number of entries already returned: the iterator is
    /// re-walked from the start, O(n) per call, which is what a FAT
    /// directory costs without a position to resume at.
    fn readdir(
        &self,
        dir: &[u8],
        cookie: u64,
        out: &mut crate::vfs::DirEnt,
    ) -> Result<Option<u64>, crate::vfs::FsErr> {
        let v = self.vol;
        let mut it = fat32_opendir_on(v, Volume { _private: () }, dir).map_err(fs_err)?;
        let mut i = 0u64;
        while let Some(e) = it.next() {
            if i == cookie {
                out.set(&e.name[..e.name_len as usize], e.is_dir, e.size as u64);
                return Ok(Some(cookie + 1));
            }
            i += 1;
        }
        Ok(None)
    }
}

fn fs_err(e: FsError) -> crate::vfs::FsErr {
    use crate::vfs::FsErr as E;
    match e {
        FsError::NotMounted | FsError::NotFound => E::NotFound,
        FsError::WrongType => E::NotDir,
        FsError::BadHandle | FsError::InvalidArg => E::Invalid,
        FsError::TooManyOpen => E::Busy,
        FsError::Io => E::Io,
        FsError::NoSpace | FsError::DirFull => E::NoSpace,
        FsError::Unsupported => E::Unsupported,
        FsError::Exists => E::Exists,
    }
}

/// A DOS date and time (FAT's local-time stamp) as seconds since the Unix
/// epoch, ignoring the time zone FAT does not record. A zero date is "no
/// stamp" and answers 0; out-of-range fields are clamped, never trusted as
/// indices (the volume is attacker-writable).
pub(crate) fn dos_to_unix(date: u16, time: u16) -> u64 {
    if date == 0 { return 0; }
    let year = 1980 + (date >> 9) as u64;
    let month = ((date >> 5) & 0xF).clamp(1, 12) as u64;
    let day = (date & 0x1F).max(1) as u64;
    let hour = ((time >> 11) as u64).min(23);
    let min = (((time >> 5) & 0x3F) as u64).min(59);
    let sec = (((time & 0x1F) as u64) * 2).min(59);
    // Days from 1970-01-01 to `year`-01-01, closed form (wave 14: the loop
    // over years it replaces was ~1.7k instructions of every `stat`, twice).
    let leaps = |n: u64| n / 4 - n / 100 + n / 400;
    let mut days = 365 * (year - 1970) + leaps(year - 1) - leaps(1969);
    const CUM: [u64; 12] = [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334];
    days += CUM[(month - 1) as usize];
    let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    if leap && month > 2 { days += 1; }
    days += day - 1;
    ((days * 24 + hour) * 60 + min) * 60 + sec
}

/// Does the directory whose chain starts at `cluster` hold nothing but `.`,
/// `..`, deleted entries and long-name fragments? Walks the whole chain up to
/// its end marker, under the same cycle bound as every other walker.
fn fat32_dir_is_empty(v: &'static Vol, cluster: u32) -> Result<bool, ()> {
    let (spc, data_start, fat_sz32, data_clusters) = {
        let fv = v.fat32.lock();
        (fv.secs_per_clus, fv.data_start, fv.fat_sz32, fv.data_clusters)
    };
    let mut walk = ChainWalk::for_volume(fat_sz32, data_clusters);
    let mut c = cluster;
    while c >= FAT32_FIRST_DATA_CLUSTER && c < FAT32_EOC {
        if !walk.visit(c) { return Err(()); }
        let first = cluster_first_sector(data_start, c, spc).ok_or(())?;
        for s in 0..spc {
            let mut buf = [0u8; SECTOR_SIZE];
            read_sector(v, first + s, &mut buf)?;
            for e in 0..DIRENTS_PER_SECTOR {
                let off = e * DIRENT_SIZE;
                match buf[off] {
                    0x00 => return Ok(true),
                    0xE5 => continue,
                    _ => {}
                }
                let attr = buf[off + 11];
                if attr == ATTR_LFN || attr & ATTR_VOLUME_ID != 0 { continue; }
                let n = &buf[off..off + 11];
                if n == b".          " || n == b"..         " { continue; }
                return Ok(false);
            }
        }
        c = fat32_next_cluster(v, c).unwrap_or(FAT32_EOC);
    }
    Ok(true)
}

// ── `statfs`'s free count, cached ─────────────────────────────────────────────
//
// Counting free clusters reads the whole first FAT; on a 32 MiB volume that is
// 512 sectors per `statfs`. The count is cached and invalidated by generation:
// every FAT write (`fat32_write_fat_entry`, the only function in this file
// that writes a FAT sector — journal replay goes through it too) bumps
// `FREE_GEN` before its first sector write and again after its last, every
// mount bumps it, and a cached count is used only while its recorded
// generation is still current. A scan overlapping any part of a FAT write
// sees the generation move and stores nothing, so a stale count is never
// published.

/// Full FAT scans `statfs` has made (host tests read it; nothing else does).
pub static FREE_SCANS: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

fn free_count_invalidate(v: &'static Vol) {
    v.free_gen.fetch_add(1, core::sync::atomic::Ordering::AcqRel);
}

/// Free clusters in the first FAT: the cached count if no FAT entry changed
/// since it was taken, else a fresh scan.
fn fat32_free_clusters(v: &'static Vol) -> Result<u32, ()> {
    use core::sync::atomic::Ordering;
    let gen = v.free_gen.load(Ordering::Acquire);
    let c = v.free_cache.load(Ordering::Acquire);
    if (c >> 32) as u32 == gen {
        return Ok(c as u32);
    }
    let free = fat32_free_clusters_scan(v)?;
    FREE_SCANS.fetch_add(1, Ordering::Relaxed);
    if v.free_gen.load(Ordering::Acquire) == gen {
        v.free_cache.store(((gen as u64) << 32) | free as u64, Ordering::Release);
    }
    Ok(free)
}

/// Free clusters in the first FAT, counted from the device (not through the
/// sector cache, so a `statfs` does not evict the hot sectors). FAT writes
/// are write-through, so the device is current.
fn fat32_free_clusters_scan(v: &'static Vol) -> Result<u32, ()> {
    let (fat_start, fat_sz32, clusters) = {
        let fv = v.fat32.lock();
        if !fv.mounted { return Err(()); }
        (fv.fat_start, fv.fat_sz32, fv.data_clusters)
    };
    let last = clusters.checked_add(FAT32_FIRST_DATA_CLUSTER).ok_or(())?;
    let mut free = 0u32;
    let mut buf = [0u8; SECTOR_SIZE];
    for s in 0..fat_sz32 {
        let first = s.checked_mul((SECTOR_SIZE / 4) as u32).ok_or(())?;
        if first >= last { break; }
        let lba = fat_start.checked_add(s).ok_or(())?;
        // The cache first: under write-back it may hold a FAT sector the
        // device does not have yet. Not installed on a miss (a scan of the
        // whole FAT would evict everything hot).
        if !v.sector_cache.lock().peek(lba as u64, &mut buf) {
            v.dev.read_quiet(dev_lba(v, lba as u64), 1, &mut buf)?;
        }
        for k in 0..SECTOR_SIZE / 4 {
            let c = first + k as u32;
            if c < FAT32_FIRST_DATA_CLUSTER { continue; }
            if c >= last { break; }
            let v = u32::from_le_bytes([buf[4 * k], buf[4 * k + 1], buf[4 * k + 2], buf[4 * k + 3]]);
            if v & 0x0FFF_FFFF == 0 { free += 1; }
        }
    }
    Ok(free)
}

/// Rebuild a `fat32_open`-compatible path (e.g. `b"/FOO.TXT"`) from the
/// padded 8.3 `name83` an `InodeKey` carries — the inverse of
/// `path_to_83_local`/`component_to_83`. Trailing spaces in the 8-byte base
/// and 3-byte extension are trimmed, and a `.` is inserted only when the
/// extension is non-empty, so a file called `README` with no extension
/// round-trips to `/README`, not `/README.` or `/README   `.
///
/// `out` must be at least 13 bytes (`/` + 8 + `.` + 3 + NUL never needed
/// since this returns a length, not a C string). Returns the length used.
fn name83_to_path(name83: &[u8; 11], out: &mut [u8; 13]) -> usize {
    let base_len = name83[..8].iter().rposition(|&b| b != b' ').map(|i| i + 1).unwrap_or(0);
    let ext_len  = name83[8..].iter().rposition(|&b| b != b' ').map(|i| i + 1).unwrap_or(0);
    out[0] = b'/';
    out[1..1 + base_len].copy_from_slice(&name83[..base_len]);
    let mut n = 1 + base_len;
    if ext_len > 0 {
        out[n] = b'.';
        n += 1;
        out[n..n + ext_len].copy_from_slice(&name83[8..8 + ext_len]);
        n += ext_len;
    }
    n
}

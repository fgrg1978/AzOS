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
    pub root_ent_cnt:    u16,   // 0 for FAT32
    pub tot_sec16:       u16,   // 0 for FAT32
    pub media:           u8,
    pub fat_sz16:        u16,   // 0 for FAT32
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
fn fat32_journal_write(entry: &JournalEntry) -> Result<(), ()> {
    let mut buf = [0u8; SECTOR_SIZE];
    entry.to_sector(&mut buf);
    write_sector(JOURNAL_SECTOR, &buf)
}

/// Read the journal entry from the journal sector.
fn fat32_journal_read() -> Result<JournalEntry, ()> {
    let mut buf = [0u8; SECTOR_SIZE];
    read_sector(JOURNAL_SECTOR, &mut buf)?;
    Ok(JournalEntry::from_sector(&buf))
}

/// Clear the journal (set state to EMPTY).
fn fat32_journal_clear() -> Result<(), ()> {
    let entry = JournalEntry::empty();
    fat32_journal_write(&entry)
}

/// Check and replay journal on mount.
/// If journal has PENDING entry -> roll back (free allocated clusters).
/// If journal has COMMITTED entry -> complete (clear journal).
/// The first cluster the dirent at `(sector, off)` names, or `None` when
/// the location is outside the data region or unreadable (U09-10: journal
/// fields come off an attacker-writable volume).
fn dirent_first_cluster_at(sector: u32, off: u16) -> Option<(u32, [u8; SECTOR_SIZE])> {
    let (data_start, data_clusters, spc) = {
        let v = FAT32.lock();
        (v.data_start, v.data_clusters, v.secs_per_clus.max(1))
    };
    let data_end = data_start.saturating_add(data_clusters.saturating_mul(spc));
    let off = off as usize;
    if sector < data_start || sector >= data_end || off + DIRENT_SIZE > SECTOR_SIZE || off % DIRENT_SIZE != 0 {
        return None;
    }
    let mut buf = [0u8; SECTOR_SIZE];
    read_sector(sector, &mut buf).ok()?;
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
fn journal_replay_rename(entry: &JournalEntry) {
    let src_sector = u32::from_le_bytes([entry._reserved[0], entry._reserved[1], entry._reserved[2], entry._reserved[3]]);
    let src_off = u16::from_le_bytes([entry._reserved[4], entry._reserved[5]]);
    let mut src_name = [0u8; 11];
    src_name.copy_from_slice(&entry._reserved[6..17]);
    let dst_ok = matches!(dirent_first_cluster_at(entry.dir_sector, entry.dir_offset),
        Some((c, _)) if c == entry.fat_value || c == entry.cluster);
    let src = dirent_first_cluster_at(src_sector, src_off);
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
    let _ = rename_apply(entry.dir_sector, entry.dir_offset, src_sector, src_off, &src_name,
        entry.cluster, entry.size, entry.fat_value, true);
}

/// The three writes of a rename over an existing file (see
/// `JOURNAL_OP_RENAME`), in an order whose every prefix leaves one name on
/// the chain: destination first, then the source deleted, then the old
/// chain freed (`free_old`: recovery; a live rename under `defer_frees`
/// holds it until its record is cleared instead).
#[allow(clippy::too_many_arguments)]
fn rename_apply(dst_sector: u32, dst_off: u16, src_sector: u32, src_off: u16, src_name: &[u8; 11],
                cluster: u32, size: u32, old_chain: u32, free_old: bool) -> Result<(), ()> {
    fat32_update_dirent_clus_size(dst_sector, dst_off, cluster, size)?;
    let mut buf = [0u8; SECTOR_SIZE];
    read_sector(src_sector, &mut buf)?;
    let o = src_off as usize;
    if buf[o..o + 11] == *src_name {
        buf[o] = DIRENT_MARK_DELETED;
        write_sector(src_sector, &buf)?;
    }
    if free_old && old_chain >= FAT32_FIRST_DATA_CLUSTER && old_chain != cluster {
        fat32_free_chain(old_chain);
    }
    Ok(())
}

fn fat32_journal_recover() -> Result<(), ()> {
    let entry = fat32_journal_read()?;

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
                let v = FAT32.lock();
                (v.data_start, v.data_clusters, v.secs_per_clus.max(1))
            };
            let data_end = data_start.saturating_add(data_clusters.saturating_mul(spc));
            let dirent_matches = entry.dir_sector >= data_start
                && entry.dir_sector < data_end
                && (entry.dir_offset as usize) + DIRENT_SIZE <= SECTOR_SIZE
                && {
                    let mut sec_buf = [0u8; SECTOR_SIZE];
                    read_sector(entry.dir_sector, &mut sec_buf).is_ok() && {
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
                return fat32_journal_clear();
            }

            azos_drv_sys::kprintln!(
                "[FAT32] Journal recovery: completing overwrite (new_clus={}, old_clus={})",
                entry.cluster, entry.fat_value
            );
            let _ = fat32_update_dirent_clus_size(
                entry.dir_sector, entry.dir_offset, entry.cluster, entry.size,
            );
            if entry.fat_value >= FAT32_FIRST_DATA_CLUSTER {
                fat32_free_chain(entry.fat_value);
            }
            fat32_journal_clear()
        }
        JOURNAL_PENDING if entry.op_type == JOURNAL_OP_RENAME => {
            journal_replay_rename(&entry);
            fat32_journal_clear()
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
            fat32_journal_clear()
        }
        JOURNAL_COMMITTED => {
            // Operation completed but journal wasn't cleared — just clear it.
            azos_drv_sys::kprintln!("[FAT32] Journal recovery: cleared committed entry");
            fat32_journal_clear()
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

static FAT32: SpinLock<Fat32Vol> = SpinLock::new(Fat32Vol::new());

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
/// same slot sleeps on that wait queue — no priority inheritance, so an RT
/// waiter never boosts a task that is waiting on the disk, and the holder
/// keeps its own priority — and retries after the publish. The allocator
/// scans without any claim, then claims the candidate's sector and re-reads
/// it: every write to that sector happens under the claim, so the re-read
/// is current and the free entry it finds is really free. Nobody holds two
/// claims, so there is no lock order and no deadlock. `chain_nth_or_extend`
/// needs no wider hold: once the fresh cluster reads end-of-chain no scan
/// can hand it out, so "allocate, then link" is safe as two claims.
///
/// **History.** U09-2 introduced `FAT_MUTATE`, held for the whole scan-then-
/// mark and the free walk; wave 15 (VF) made it a `PiMutex` (as a `SpinLock`
/// its device I/O ran preempt-off: 7.24 ms at `fat32_free_chain` on riscv64
/// under `-icount`). As a `PiMutex` it was held across the virtio-blk wait,
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
/// `fat-mutate-pi-canary` as a `PiMutex` (the VF shape: `[LAT] fat pi_io=`
/// goes non-zero). `fat-sector-claim-canary` claims nothing
/// (fs-tests' concurrent-mutator tests lose an update / double-allocate).
static FAT_SECTOR_BUSY: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
/// Bumped on every claim release; a waiter sleeps only while it is unchanged.
static FAT_SECTOR_GEN: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
/// The task holding each slot's claim (`caller_tid`), 0 when free: a task
/// that panics holding a claim must not be contained, because nobody would
/// ever release it ([`fat32_claims_held_by`], the panic policy's check 4).
static FAT_SECTOR_OWNER: [core::sync::atomic::AtomicU32; 64] =
    [const { core::sync::atomic::AtomicU32::new(0) }; 64];
/// Updaters waiting for a claimed slot.
static FAT_SECTOR_WQ: azos_sync::waitqueue::WaitQueue = azos_sync::waitqueue::WaitQueue::new();
/// Kconfig `FAT32_SECTOR_CLAIM_SLOTS` (1..=64): bits of [`FAT_SECTOR_BUSY`] used.
const FAT_SECTOR_SLOTS: u32 = {
    let n = azos_limits::FAT32_SECTOR_CLAIM_SLOTS;
    assert!(n >= 1 && n <= 64, "FAT32_SECTOR_CLAIM_SLOTS must be 1..=64");
    n as u32
};
#[cfg(feature = "fat-mutate-spin-canary")]
static FAT_MUTATE_CANARY: SpinLock<()> = SpinLock::new(());
#[cfg(feature = "fat-mutate-pi-canary")]
static FAT_MUTATE_CANARY: azos_sync::pi_mutex::PiMutex<()> = azos_sync::pi_mutex::PiMutex::new(());

/// A claim on one FAT sector's slot; released (published) on drop.
struct FatSectorClaim {
    bit: u64,
    slot: usize,
}

/// Claim the slot of FAT sector `fat_sector_off` (relative to the FAT
/// start, so the same for every copy), sleeping while another updater holds it.
fn fat_sector_claim(fat_sector_off: u32) -> FatSectorClaim {
    use core::sync::atomic::Ordering::SeqCst;
    let slot = (fat_sector_off % FAT_SECTOR_SLOTS) as usize;
    let bit = if cfg!(feature = "fat-sector-claim-canary") { 0 } else { 1u64 << slot };
    loop {
        // Read the generation BEFORE trying: a release between the failed
        // try and the sleep then changes it, and `wait_if` (which re-checks
        // under the queue's lock) does not sleep through that publish.
        let gen = FAT_SECTOR_GEN.load(SeqCst);
        if FAT_SECTOR_BUSY.fetch_or(bit, SeqCst) & bit == 0 {
            FAT_SECTOR_OWNER[slot].store(azos_sync::waitqueue::caller_tid(), SeqCst);
            return FatSectorClaim {
                bit,
                slot,
            };
        }
        FAT_SECTOR_WQ.wait_if(|| FAT_SECTOR_GEN.load(SeqCst) == gen);
    }
}

impl Drop for FatSectorClaim {
    fn drop(&mut self) {
        use core::sync::atomic::Ordering::SeqCst;
        FAT_SECTOR_OWNER[self.slot].store(0, SeqCst);
        FAT_SECTOR_BUSY.fetch_and(!self.bit, SeqCst);
        FAT_SECTOR_GEN.fetch_add(1, SeqCst);
        FAT_SECTOR_WQ.wake_all();
    }
}

/// FAT-sector claims task `tid` holds (0 or 1: claims never nest). The panic
/// path adds it to the task's held `PiMutex` count: a claim abandoned by a
/// contained task would block every later update of its FAT sectors.
pub fn fat32_claims_held_by(tid: u32) -> u32 {
    use core::sync::atomic::Ordering::SeqCst;
    if tid == 0 { return 0; }
    FAT_SECTOR_OWNER.iter().filter(|o| o.load(SeqCst) == tid).count() as u32
        + (WB_OWNER.load(SeqCst) == tid) as u32
}

/// `fat-pi-io-probe` (the `lat-fat` smoke): FAT32 device I/O issued while
/// the issuing task held a `PiMutex` — the F1 violation. Counted at the FAT32
/// layer, before `blkdev` takes its own `BLK_LOCK`. [`FAT_PI_IO`] counts every
/// task; [`FAT_PI_IO_WATCHED`] only the task [`fat32_pi_io_watch`] names (the
/// smoke's FAT writer, which holds no `PiMutex` of its own: whatever it counts
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
        if azos_sync::pi_mutex::held_by(tid) != 0 {
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

/// Distinct (task, held `PiMutex`es) seen by [`pi_io_probe`]: which lock
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
    let n = azos_sync::pi_mutex::held_addrs(tid, &mut held);
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

/// FAT32 device I/Os issued with a `PiMutex` held: (by the watched task, by
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
/// FAT cluster chains are attacker-controlled: the volume is exported over USB
/// mass storage by `msc_gadget`, so an adversary with physical access can set
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
    // **Which half actually closes the reset, stated because the canary says
    // so.** Reverting this `min` to `by_fat` alone leaves all 16 host tests
    // green, and that is not a missing test — it is the shape of the fix.
    // With `num_fats >= 1` enforced at the mount, a `fat_sz32` large enough
    // to inflate `by_fat` also forces `data_start` large, and
    // `cluster_first_sector` then returns `None` and every walker breaks. So
    // the **`num_fats == 0` rejection is what makes the hang unreachable**;
    // this bound is defence in depth for the geometries that check leaves
    // legal. Both were added together on 2026-09-21; only the first has a
    // discriminating test, and this comment is why.
    let by_fat = fat_sz32.saturating_mul(FAT32_ENTRIES_PER_SECTOR);
    let by_data = data_clusters.saturating_add(FAT32_FIRST_DATA_CLUSTER);
    by_fat.min(by_data)
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
// Since RFC-0048 P1 this is an instance of `crate::bcache::BlockCache`, the
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

type SectorCache = crate::bcache::BlockCache<SECTOR_CACHE_BYTES, SECTOR_CACHE_LINES>;

/// All-zero until the first mount configures it (`fat32_cache_reset`), so
/// the storage is `.bss`, not image bytes.
static SECTOR_CACHE: SpinLock<SectorCache> = SpinLock::new(SectorCache::unconfigured());

/// The block device, as the shared cache sees it.
struct BlkDev;

impl crate::bcache::BlockIo for BlkDev {
    type FlushErr = FsError;
    fn read(&mut self, lba: u64, count: u32, buf: &mut [u8]) -> Result<(), ()> {
        azos_drv_block::blkdev::read_quiet(dev_lba(lba), count, buf)
    }
    fn write(&mut self, lba: u64, count: u32, buf: &[u8]) -> Result<(), ()> {
        // Quiet: this runs with `SECTOR_CACHE` held (`device_flush`'s
        // write-back pass), and the observer takes it.
        azos_drv_block::blkdev::write_quiet(dev_lba(lba), count, buf)
    }
    fn flush(&mut self) -> Result<(), FsError> {
        device_flush_raw()
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

/// Kconfig `FS_WRITEBACK`.
const WB: bool = azos_limits::FS_WRITEBACK;

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

/// The task holding the write-back claim (`caller_tid`), 0 when free.
static WB_BUSY: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
static WB_OWNER: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
static WB_GEN: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
static WB_WQ: azos_sync::waitqueue::WaitQueue = azos_sync::waitqueue::WaitQueue::new();

/// The mode the next configure of the cache takes: `WB` until
/// [`fat32_set_writeback`] changes it.
static WB_ON: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(WB);

/// Sticky: a write-back no caller was waiting for (the task, a reader's)
/// failed. The next `fat32_sync_checked` / `fat32_fsync` reports `Io` and
/// clears it (Linux's errseq, reduced to one volume-wide bit).
static WB_ERROR: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// `WB_CLOCK()` (milliseconds) when the cache went from clean to dirty;
/// 0 while clean. The age the `fs-wb` task compares.
static WB_DIRTY_SINCE: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// `fn() -> u64` milliseconds, registered by the kernel (`fat32_writeback_hooks`);
/// 0 until then (host tests: age is driven through `fat32_writeback_tick`).
static WB_CLOCK: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
/// `fn()` that wakes the `fs-wb` task (watermark crossed); 0 = none.
static WB_WAKE: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

/// Register the kernel's clock (milliseconds) and the `fs-wb` task's waker.
pub fn fat32_writeback_hooks(clock_ms: fn() -> u64, wake: fn()) {
    use core::sync::atomic::Ordering::Release;
    WB_CLOCK.store(clock_ms as usize, Release);
    WB_WAKE.store(wake as usize, Release);
}

fn wb_now_ms() -> u64 {
    let f = WB_CLOCK.load(core::sync::atomic::Ordering::Acquire);
    if f == 0 { return 1; }
    // SAFETY: only `fat32_writeback_hooks` stores here, and it stores a `fn() -> u64`.
    let f: fn() -> u64 = unsafe { core::mem::transmute::<usize, fn() -> u64>(f) };
    f().max(1)
}

fn wb_wake() {
    let f = WB_WAKE.load(core::sync::atomic::Ordering::Acquire);
    if f != 0 {
        // SAFETY: only `fat32_writeback_hooks` stores here, and it stores a `fn()`.
        let f: fn() = unsafe { core::mem::transmute::<usize, fn()>(f) };
        f();
    }
}

/// The write-back claim; released on drop.
struct WbClaim;

/// Take the write-back claim, sleeping while another flusher holds it.
/// Never called with a `SpinLock` held; never nested.
fn wb_claim() -> WbClaim {
    use core::sync::atomic::Ordering::SeqCst;
    loop {
        let gen = WB_GEN.load(SeqCst);
        if !WB_BUSY.swap(true, SeqCst) {
            WB_OWNER.store(azos_sync::waitqueue::caller_tid(), SeqCst);
            return WbClaim;
        }
        WB_WQ.wait_if(|| WB_GEN.load(SeqCst) == gen);
    }
}

impl Drop for WbClaim {
    fn drop(&mut self) {
        use core::sync::atomic::Ordering::SeqCst;
        WB_OWNER.store(0, SeqCst);
        WB_BUSY.store(false, SeqCst);
        WB_GEN.fetch_add(1, SeqCst);
        WB_WQ.wake_all();
    }
}

/// Write back every dirty line of an epoch `<= upto`, oldest epoch first, as
/// coalesced runs, `SECTOR_CACHE` released across each device request. A
/// run of a later epoch than one already written since the last flush is
/// preceded by a device flush (the epoch rule; `Unsupported` passes, as in
/// `fat32_fsync`'s ordering flush: such a device gives no ordering to keep).
/// On a failed write the run stays dirty, nothing later is written, and the
/// error is returned.
fn wb_write_back(_claim: &WbClaim, upto: u64) -> Result<(), FsError> {
    loop {
        // SAFETY: the claim makes this task the stage's only user.
        let stage = unsafe { &mut *WB_STAGE.0.get() };
        let run = SECTOR_CACHE.lock().checkout_run(upto, WB_RUN_SECTORS, stage);
        let Some(run) = run else {
            if SECTOR_CACHE.lock().dirty_count() == 0 {
                WB_DIRTY_SINCE.store(0, core::sync::atomic::Ordering::Relaxed);
            }
            return Ok(());
        };
        if run.flush_first {
            match device_flush_raw() {
                Ok(()) | Err(FsError::Unsupported) => {}
                Err(e) => return Err(e),
            }
            SECTOR_CACHE.lock().note_ordering_flush();
        }
        pi_io_probe();
        let bytes = run.sectors as usize * SECTOR_SIZE;
        let r = azos_drv_block::blkdev::write_quiet(dev_lba(run.lba), run.sectors, &stage[..bytes]);
        SECTOR_CACHE.lock().checkin(&run, r.is_ok());
        if r.is_err() {
            return Err(FsError::Io);
        }
    }
}

/// The `fs-wb` task's pass at `now_ms`: write everything back and flush when
/// the oldest unsynced write is `FS_WRITEBACK_MAX_AGE_MS` old or the dirty
/// share reached `FS_WRITEBACK_WATERMARK_PCT`. Returns whether it wrote. A
/// failure is kept for the next fsync/sync (`WB_ERROR`).
pub fn fat32_writeback_tick(now_ms: u64) -> bool {
    use core::sync::atomic::Ordering::Relaxed;
    if !WB { return false; }
    let (dirty, lines) = {
        let c = SECTOR_CACHE.lock();
        (c.dirty_count(), c.line_count())
    };
    if dirty == 0 { return false; }
    let since = WB_DIRTY_SINCE.load(Relaxed);
    let aged = since != 0
        && now_ms.saturating_sub(since) >= azos_limits::FS_WRITEBACK_MAX_AGE_MS as u64;
    if !aged && !wb_over_watermark(dirty, lines) { return false; }
    if device_flush().is_err() {
        WB_ERROR.store(true, Relaxed);
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

/// Last ticket asked for.
static FLUSH_ASKED: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
/// Every ticket `<=` this is done.
static FLUSH_DONE: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
/// Tickets `[FLUSH_FAIL_LO, FLUSH_FAIL_HI]` were covered by a failed flush
/// (the union of every failure: an error is never lost, a ticket a later
/// failure's range spans may read -EIO although its own flush succeeded).
static FLUSH_FAIL_LO: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(u64::MAX);
static FLUSH_FAIL_HI: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// One flush on behalf of every ticket in `(done, upto]`.
fn flush_for_tickets(upto: u64) {
    use core::sync::atomic::Ordering::SeqCst;
    let from = FLUSH_DONE.load(SeqCst) + 1;
    // No volume mounted: nothing of FAT32's to flush (a RAM descriptor's
    // fsync is 0, as the synchronous call answers), not a failure.
    if matches!(fat32_sync_checked(), Err(e) if e != FsError::NotMounted) {
        FLUSH_FAIL_LO.fetch_min(from, SeqCst);
        FLUSH_FAIL_HI.fetch_max(upto, SeqCst);
    }
    FLUSH_DONE.fetch_max(upto, SeqCst);
}

/// Ask for a flush of every write made so far; answers the ticket to wait
/// for with [`fat32_flush_done`]. Wakes the `fs-wb` task and returns; with no
/// task to wake, flushes inline (write-through mode).
pub fn fat32_flush_request() -> u64 {
    use core::sync::atomic::Ordering::SeqCst;
    let t = FLUSH_ASKED.fetch_add(1, SeqCst) + 1;
    if WB && WB_WAKE.load(SeqCst) != 0 {
        wb_wake();
    } else {
        flush_for_tickets(t);
    }
    t
}

/// `None` while ticket `t`'s flush runs; `Some(Ok)` once durable,
/// `Some(Err(Io))` when a flush covering it failed.
pub fn fat32_flush_done(t: u64) -> Option<Result<(), FsError>> {
    use core::sync::atomic::Ordering::SeqCst;
    if FLUSH_DONE.load(SeqCst) < t { return None; }
    if FLUSH_FAIL_LO.load(SeqCst) <= t && t <= FLUSH_FAIL_HI.load(SeqCst) {
        Some(Err(FsError::Io))
    } else {
        Some(Ok(()))
    }
}

/// The `fs-wb` task's half: run one flush for every ticket asked so far.
/// Returns whether it ran one (the caller then posts the completions).
pub fn fat32_flush_service() -> bool {
    use core::sync::atomic::Ordering::SeqCst;
    let upto = FLUSH_ASKED.load(SeqCst);
    if upto <= FLUSH_DONE.load(SeqCst) { return false; }
    flush_for_tickets(upto);
    true
}

/// Write every queued write back and flush the device now (what `sync`
/// does without settling the journal). A no-op flush under write-through.
pub fn fat32_writeback_now() -> Result<(), FsError> {
    device_flush()
}

/// The `fs-wb` task's wait between passes: a quarter of the age bound.
pub fn fat32_writeback_period_ms() -> u64 {
    (azos_limits::FS_WRITEBACK_MAX_AGE_MS as u64 / 4).max(1)
}

/// Dirty lines and lines in the FAT32 cache (diagnostics, the `fs-wb` rows).
pub fn fat32_writeback_dirty() -> (usize, usize) {
    let c = SECTOR_CACHE.lock();
    (c.dirty_count(), c.line_count())
}

fn wb_over_watermark(dirty: usize, lines: usize) -> bool {
    dirty * 100 >= lines * azos_limits::FS_WRITEBACK_WATERMARK_PCT as usize
}

/// `blkdev::read`'s observer: a reader that is not this file is about to
/// read MEDIUM sectors `[lba, lba + count)`. Dirty lines in that range go to
/// the device first (all of them, oldest epoch first: a partial write-back
/// could not keep the epoch rule). Called with no FAT32 lock held.
pub fn fat32_before_medium_read(lba: u64, count: u32) {
    use core::sync::atomic::Ordering::Relaxed;
    if !WB || cfg!(feature = "wb-read-observer-canary") { return; }
    let base = VOL_BASE.load(Relaxed);
    let end = base.saturating_add(VOL_SECTORS.load(Relaxed));
    let first = lba.max(base);
    let last = lba.saturating_add(count as u64).min(end);
    if count == 0 || first >= last { return; }
    if !SECTOR_CACHE.lock().any_dirty_in(first - base, last - first) { return; }
    let claim = wb_claim();
    if wb_write_back(&claim, u64::MAX).is_err() {
        WB_ERROR.store(true, Relaxed);
    }
}

/// Switch the FAT32 cache between write-back and write-through at run time
/// (host tests; a kernel canary). Writes every dirty line back first.
pub fn fat32_set_writeback(on: bool) -> Result<(), FsError> {
    if on && !WB { return Err(FsError::Unsupported); }
    WB_ON.store(on, core::sync::atomic::Ordering::Relaxed);
    let claim = wb_claim();
    wb_write_back(&claim, u64::MAX)?;
    let mut c = SECTOR_CACHE.lock();
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

/// First sector of the mounted volume on the medium.
static VOL_BASE: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Bumped by every write of the volume — FAT32's own (`write_sector`), any
/// other writer's (`fat32_on_medium_write`) — and by mount and unmount. A
/// read-only stream remembers it with the start cluster it found at open
/// (`Fat32Fs::read_handle`); while it is unchanged, nothing can have moved,
/// freed or resized that chain, so the stream reads it without looking the
/// name up again. Never 0, so a handle of 0 never matches.
static WRITE_GEN: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(1);

/// The same events as [`WRITE_GEN`], counted in 64 bits so a value never
/// comes back (wave 14, SPAWNCACHE): the verified-image cache stamps what it
/// verified with it ([`Fat32Fs::content_stamp`]) and must never take a stamp
/// from before a write for one after it. Bumped AFTER `WRITE_GEN`, and every
/// bump comes after the write it reports has reached the device and the
/// block cache: a reader that loads the epoch, reads, and loads the same
/// epoch again read nothing a later bump reports.
static WRITE_EPOCH: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(1);

fn write_gen_bump() {
    use core::sync::atomic::Ordering::AcqRel;
    if cfg!(feature = "write-gen-canary") { return; }
    if WRITE_GEN.fetch_add(1, AcqRel) == u32::MAX {
        // Wrapped to 0: step past it (a stale handle would need 2^32 writes
        // in between to alias, and still only to the same name's lookup).
        WRITE_GEN.fetch_add(1, AcqRel);
    }
    if cfg!(feature = "write-epoch-canary") { return; }
    WRITE_EPOCH.fetch_add(1, AcqRel);
}

/// The volume's write epoch (see [`WRITE_EPOCH`]).
pub fn fat32_write_epoch() -> u64 {
    WRITE_EPOCH.load(core::sync::atomic::Ordering::Acquire)
}

/// Sectors of the mounted volume (`tot_sec32`), `u64::MAX` while a mount is
/// still reading its BPB. Bounds which medium writes touch the cache.
static VOL_SECTORS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(u64::MAX);

/// The medium sector of volume sector `sector`.
#[inline]
fn dev_lba(sector: u64) -> u64 {
    VOL_BASE.load(core::sync::atomic::Ordering::Relaxed) + sector
}

/// The first sector of the volume on the medium, as the last mount chose it
/// (0 for a bare FAT32 medium).
pub fn fat32_volume_base() -> u64 {
    VOL_BASE.load(core::sync::atomic::Ordering::Relaxed)
}

/// Where a FAT32 volume starts on the medium, and how many sectors it may
/// span (`0`: unbounded, the bare-medium case).
///
/// The first published partition whose first sector passes
/// [`validate_bpb`] and whose `tot_sec32` fits inside it, else the whole
/// medium from sector 0. A partition that fails either check is skipped, not
/// fatal: a GPT disk may carry other filesystems before the FAT one.
fn select_volume() -> (u64, u64) {
    use azos_drv_block::partition;
    for i in 0..partition::count() {
        let (start, len) = match partition::partition(i) {
            Some(p) => p,
            None => continue,
        };
        let mut s0 = [0u8; SECTOR_SIZE];
        if azos_drv_block::blkdev::read_quiet(start, 1, &mut s0).is_err() {
            continue;
        }
        let bpb = unsafe { &*(s0.as_ptr() as *const Fat32Bpb) };
        if validate_bpb(bpb, &s0).is_ok() && (bpb.tot_sec32 as u64) <= len {
            return (start, len);
        }
    }
    (0, 0)
}

/// Non-blocking check for whether the FAT32 locks (`FAT32` volume state,
/// `SECTOR_CACHE`) are free and no FAT-sector claim ([`FAT_SECTOR_BUSY`])
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
pub fn fat32_locks_available() -> bool {
    FAT32.try_lock().is_some() && SECTOR_CACHE.try_lock().is_some()
        && FAT_SECTOR_BUSY.load(core::sync::atomic::Ordering::SeqCst) == 0
        && !WB_BUSY.load(core::sync::atomic::Ordering::SeqCst)
}

/// Invalidate every cache line touching `sector` — call after an
/// out-of-band write (raw block layer, OTA writes that bypass FS).
#[allow(dead_code)]
pub fn fat32_cache_invalidate(sector: u32) {
    SECTOR_CACHE.lock().invalidate(sector as u64);
}

/// More medium sectors than this in one write drop the whole cache (O(1))
/// instead of probing each sector: the lock is never held for more than a
/// set's worth of probes, however long the write.
const EXTERNAL_WRITE_RANGE_MAX: u64 = crate::bcache::MAX_WAYS as u64;

/// The block layer's write observer (`azos_drv_block::write_observer`):
/// MEDIUM sectors `[lba, lba + count)` were written by someone other than
/// this file — the USB mass-storage gadget, a reserved-tail record, ring-3
/// `SYS_DISK_WRITE` through a partition `Cap<Disk>`. Drops the cached copy
/// of every volume sector in the range; a range outside the volume (the
/// partition table, another partition, the reserved tail) drops nothing.
///
/// Called after the device answered, with no lock held, from any task. Takes
/// only `SECTOR_CACHE`, a leaf; the volume bounds are atomics, so it never
/// waits on `FAT32`. A reader whose device read raced this write cannot
/// install what it read: the invalidation bumps the cache's write sequence,
/// and `install` refuses a token taken before it.
pub fn fat32_on_medium_write(lba: u64, count: u32) {
    if cfg!(feature = "fatcache-observer-canary") {
        return;
    }
    use core::sync::atomic::Ordering::Relaxed;
    let base = VOL_BASE.load(Relaxed);
    let end = base.saturating_add(VOL_SECTORS.load(Relaxed));
    let first = lba.max(base);
    let last = lba.saturating_add(count as u64).min(end);
    if count == 0 || first >= last {
        return;
    }
    let n = last - first;
    {
        let mut c = SECTOR_CACHE.lock();
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
    held_reset();
    write_gen_bump();
}

/// Configure the cache for a mount and drop every line: 512 B lines (one
/// per volume sector), write-through, and the observer installed.
fn fat32_cache_reset() {
    write_gen_bump();
    {
        let mut c = SECTOR_CACHE.lock();
        if c.line_count() == 0 {
            // First mount: O(lines) once. Cannot fail: 512 is a valid block
            // size for any SECTOR_CACHE_BYTES (a multiple of 512), and a
            // write-through cache is never dirty.
            let on = WB && WB_ON.load(core::sync::atomic::Ordering::Relaxed);
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
    write_gen_bump();
    azos_drv_block::blkdev::set_write_observer(fat32_on_medium_write);
    if WB {
        azos_drv_block::blkdev::set_read_observer(fat32_before_medium_read);
    }
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
/// Public for the USB mass-storage handback: when the gadget gives the volume
/// back after a host owned it, the caller drops every line. Every gadget
/// WRITE_10 already invalidates its own sector through the block layer's
/// write observer, so this is belt and braces, not the coherence mechanism.
pub fn fat32_cache_invalidate_all() {
    SECTOR_CACHE.lock().invalidate_all();
    write_gen_bump();
}

/// Read a sector, preferring the cache. On miss, fetch via the block
/// device and install in the LRU-evicted line.
fn read_sector(sector: u32, buf: &mut [u8; SECTOR_SIZE]) -> Result<(), ()> {
    let token = {
        let mut c = SECTOR_CACHE.lock();
        if c.lookup(sector as u64, buf) {
            return Ok(());
        }
        c.lookup_miss_token()
    };
    // Miss — fetch from the device with the cache lock released.
    crate::census::count(crate::census::DEV_READS);
    pi_io_probe();
    azos_drv_block::blkdev::read_quiet(dev_lba(sector as u64), 1, buf)?;
    SECTOR_CACHE.lock().install(sector as u64, buf, token);
    Ok(())
}

/// Statistics for diagnostics (`fs cache` shell command, etc.).
#[allow(dead_code)]
pub fn fat32_cache_stats() -> (u32, u32) {
    let st = SECTOR_CACHE.lock().stats();
    (st.hits, st.misses)
}

/// The shared cache's full counters for the FAT32 instance (hits, misses,
/// write-backs, ordering flushes). The last two stay 0 while the instance is
/// write-through.
#[allow(dead_code)]
pub fn fat32_cache_counters() -> crate::bcache::CacheStats {
    SECTOR_CACHE.lock().stats()
}

/// The FAT32 cache's current epoch (diagnostics, host tests: a barrier
/// moves it by one).
#[allow(dead_code)]
pub fn fat32_cache_epoch() -> u64 {
    SECTOR_CACHE.lock().epoch()
}

/// Distinct epochs among the FAT32 cache's dirty lines (diagnostics, host
/// tests).
#[allow(dead_code)]
pub fn fat32_dirty_epochs() -> usize {
    SECTOR_CACHE.lock().dirty_epochs()
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

/// Mount a FAT32 filesystem on the first VirtIO block device.
/// Returns Ok(()) on success.
pub fn fat32_mount() -> Result<(), ()> {
    // U09-3: already mounted — nothing to do. `fat32_mount_volume()` is a
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
    // unconditionally. `fat32_unmount()` clears `mounted`, so a real
    // remount (media change, an explicit unmount/mount cycle) still runs
    // the full path below.
    if FAT32.lock().mounted {
        return Ok(());
    }

    // U09-6: this IS a real mount attempt past the early-out above — drop
    // every cached sector before reading anything. Without this, a remount
    // after `fat32_unmount()` (media swap, or the crash-recovery path that
    // unmounts and remounts the same medium) would read the PREVIOUS
    // medium's cached BPB/root/FAT sectors through `read_sector`'s cache
    // hit, never touching the device this mount is supposed to be reading.
    fat32_cache_reset();

    // Where the volume is: a published partition holding a FAT32 boot
    // sector, or the bare medium. Chosen before the first `read_sector`, and
    // the cache was just emptied, so no line holds a sector of the old base.
    let (base, part_len) = select_volume();
    VOL_SECTORS.store(u64::MAX, core::sync::atomic::Ordering::Relaxed);
    VOL_BASE.store(base, core::sync::atomic::Ordering::Relaxed);
    // A new volume (or the same one after an unmount): no cached free count
    // carries over.
    free_count_invalidate();
    ALLOC_HINT.store(0, core::sync::atomic::Ordering::Relaxed);
    held_reset();

    let mut sector0 = [0u8; SECTOR_SIZE];
    read_sector(0, &mut sector0)?;

    // Parse BPB (at offset 0 in sector 0)
    let bpb = unsafe { &*(sector0.as_ptr() as *const Fat32Bpb) };
    validate_bpb(bpb, &sector0)?;
    // Re-checked on the bytes actually mounted: the volume may not claim more
    // sectors than its partition holds.
    if part_len != 0 && bpb.tot_sec32 as u64 > part_len { return Err(()); }
    VOL_SECTORS.store(bpb.tot_sec32 as u64, core::sync::atomic::Ordering::Relaxed);

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

    let mut v = FAT32.lock();
    v.fat_start      = fat_start;
    v.data_start     = data_start;
    v.root_cluster   = root_clus;
    v.secs_per_clus  = spc;
    v.bytes_per_clus = spc * 512;
    v.fat_sz32       = bpb.fat_sz32;
    v.num_fats       = bpb.num_fats;
    v.mounted        = true;
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
    v.data_clusters  = bpb.tot_sec32.saturating_sub(data_start) / spc;
    // The read-only streams' copy of the geometry (wave 14), published with
    // the fields above while `v` is held. Each pair travels in one word, so a
    // reader never sees `spc` from one mount and `data_start` from another.
    {
        use core::sync::atomic::Ordering::Release;
        let limit = chain_walk_limit(v.fat_sz32, v.data_clusters);
        STREAM_GEOM_A.store(((spc as u64) << 32) | data_start as u64, Release);
        STREAM_GEOM_B.store(((fat_start as u64) << 32) | limit as u64, Release);
    }

    azos_drv_sys::kprintln!(
        "[FAT32] Mounted: FAT@{}, data@{}, root_clus={}, spc={}, base LBA {}",
        fat_start, data_start, root_clus, spc, base
    );

    // Recover from any incomplete operations before power loss.
    drop(v);
    // Write-back orders its epochs with device flushes; a device that cannot
    // flush gives no order, so this mount stays write-through (whose journal
    // barriers then refuse, fail closed, as before).
    if WB && WB_ON.load(core::sync::atomic::Ordering::Relaxed) {
        let wt = matches!(device_flush_raw(), Err(FsError::Unsupported));
        let mut c = SECTOR_CACHE.lock();
        let want = if wt { crate::bcache::Mode::WriteThrough } else { crate::bcache::Mode::WriteBack };
        if c.mode() != want && c.dirty_count() == 0 {
            let _ = c.configure(SECTOR_SIZE, want, 0);
        }
    }
    fat32_journal_recover()?;
    // Write-back: what recovery repaired is on the medium before the volume
    // is used (a second cut must not find the same journal record again).
    if WB && SECTOR_CACHE.lock().dirty_count() != 0 {
        match device_flush() {
            Ok(()) | Err(FsError::Unsupported) => {}
            Err(_) => return Err(()),
        }
    }

    Ok(())
}

/// Read the FAT entry for `cluster` to find the next cluster in the chain.
/// Returns Ok(next_cluster), where >= FAT32_EOC means end of chain.
fn fat32_next_cluster(cluster: u32) -> Result<u32, ()> {
    let (fat_start, fat_sz32, data_clusters) = {
        let v = FAT32.lock();
        (v.fat_start, v.fat_sz32, v.data_clusters)
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
    if !SECTOR_CACHE.lock().lookup_bytes(fat_sector as u64, fat_offset * 4, &mut entry_bytes) {
        let mut buf = [0u8; SECTOR_SIZE];
        read_sector(fat_sector, &mut buf)?;
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
/// request, which then fills the cache. Each cache step takes the lock for
/// one sector's copy only.
fn read_run_cached(first: u32, run: u32, dst: &mut [u8]) -> Result<(), ()> {
    let mut hit = 0u32;
    if !cfg!(feature = "fatcache-run-bypass-canary") {
        while hit < run {
            let o = hit as usize * SECTOR_SIZE;
            let line = &mut dst[o..o + SECTOR_SIZE];
            if !SECTOR_CACHE.lock().lookup((first + hit) as u64, line) {
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
        SECTOR_CACHE.lock().lookup_miss_token()
    };
    let o = hit as usize * SECTOR_SIZE;
    crate::census::count(crate::census::DEV_READS);
    azos_drv_block::blkdev::read_quiet(dev_lba((first + hit) as u64), run - hit, &mut dst[o..])?;
    for k in hit..run {
        let o = k as usize * SECTOR_SIZE;
        let mut c = SECTOR_CACHE.lock();
        // Write-back: a line present now is newer than the device's copy
        // (dirty, or written after the read) — it answers, not the device.
        if WB && c.mode() == crate::bcache::Mode::WriteBack && !cfg!(feature = "wb-run-overlay-canary")
            && c.peek((first + k) as u64, &mut dst[o..o + SECTOR_SIZE])
        {
            continue;
        }
        // The canary installs whatever the device returned, however stale:
        // the token is re-read after the fact instead of before the read.
        let t = if cfg!(feature = "fatcache-token-canary") { c.lookup_miss_token() } else { token };
        c.install((first + k) as u64, &dst[o..o + SECTOR_SIZE], t);
    }
    Ok(())
}

/// `fat32_read_range`'s geometry, published by `fat32_mount`: sectors per
/// cluster and data start (A), FAT start and the chain-walk bound (B). A
/// stream reads it without taking `FAT32`; 0 before the first mount.
static STREAM_GEOM_A: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static STREAM_GEOM_B: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

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
pub fn fat32_read_range(first: u32, size: u32, offset: u32, dst: &mut [u8]) -> usize {
    if offset >= size || dst.is_empty() { return 0; }
    let len = dst.len().min((size - offset) as usize);
    let (a, b) = {
        use core::sync::atomic::Ordering::Acquire;
        (STREAM_GEOM_A.load(Acquire), STREAM_GEOM_B.load(Acquire))
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
        match fat.next(cl) {
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
                None => match fat.next(cl) { Ok(n) => n, Err(()) => break },
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
                    let n = match fat.next(tail) { Ok(n) => n, Err(()) => break };
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
            if read_run_cached(fs + s, run, &mut dst[done..done + bytes]).is_err() { break; }
            done += bytes;
            pos += bytes;
            if advanced > 0 {
                cl = tail;
                cl_base += advanced * bpc;
            }
        } else {
            let chunk = left.min(SECTOR_SIZE - o);
            let out = &mut dst[done..done + chunk];
            if !SECTOR_CACHE.lock().lookup_bytes((fs + s) as u64, o, out) {
                let mut sec = [0u8; SECTOR_SIZE];
                if read_sector(fs + s, &mut sec).is_err() { break; }
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
    fn next(&mut self, cluster: u32) -> Result<u32, ()> {
        if cluster >= self.limit { return Err(()); }
        let sector = self.fat_start.checked_add(cluster / FAT32_ENTRIES_PER_SECTOR).ok_or(())?;
        if self.buf.is_none() || self.sector != sector {
            let buf = self.buf.insert([0u8; SECTOR_SIZE]);
            if !SECTOR_CACHE.lock().lookup(sector as u64, buf) {
                if read_sector(sector, buf).is_err() {
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

/// Read all data from a cluster chain into `out_buf`.
/// Returns bytes written.
pub fn fat32_read_chain(start_cluster: u32, out_buf: &mut [u8]) -> usize {
    let (spc, data_start, fat_sz32, data_clusters) = {
        let v = FAT32.lock();
        (v.secs_per_clus, v.data_start, v.fat_sz32, v.data_clusters)
    };
    // Cycle guard — see `chain_walk_limit`. A self-referential FAT entry would
    // otherwise spin here forever whenever `out_buf` is larger than one cluster.
    let limit = chain_walk_limit(fat_sz32, data_clusters);
    let mut steps = 0u32;

    let mut cluster = start_cluster;
    let mut written = 0;

    while written < out_buf.len() {
        if cluster < FAT32_FIRST_DATA_CLUSTER || cluster >= FAT32_EOC { break; }
        if steps >= limit { break; }
        steps += 1;

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
            let mut next = fat32_next_cluster(cluster).ok();
            while let Some(n) = next {
                if n != cluster.wrapping_add(run / spc)
                    || n < FAT32_FIRST_DATA_CLUSTER || n >= FAT32_EOC
                    || run + spc > whole || run + spc > READ_RUN_MAX_SECTORS
                    || steps >= limit
                    || cluster_first_sector(data_start, n, spc) != first_sector.checked_add(run)
                {
                    break;
                }
                steps += 1;
                run += spc;
                next = fat32_next_cluster(n).ok();
            }
            let bytes = run as usize * SECTOR_SIZE;
            if read_run_cached(first_sector, run, &mut out_buf[written..written + bytes]).is_err() {
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
            // fits in u32, so this addition cannot overflow.
            if read_sector(first_sector + s, &mut sec_buf).is_err() { break; }
            let to_copy = remaining.min(SECTOR_SIZE);
            out_buf[written..written + to_copy].copy_from_slice(&sec_buf[..to_copy]);
            written += to_copy;
        }

        cluster = match fat32_next_cluster(cluster) {
            Ok(n) => n,
            Err(_) => break,
        };
    }

    written
}

/// Find a file in the root directory by short name (8.3 format, uppercased).
/// Returns (start_cluster, file_size) or Err if not found.
pub fn fat32_lookup_root(name83: &[u8; 11]) -> Result<(u32, u32), ()> {
    fat32_lookup_root_entry(name83).map(|e| (e.cluster, e.size))
}

/// A root-directory entry's fields, as [`fat32_lookup_root_entry`] finds
/// them: what `FileSystem::stat` reports (RFC-0048 P2).
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

/// [`fat32_lookup_root`], keeping the whole entry: attributes and the DOS
/// dates and times. The same single scan.
pub fn fat32_lookup_root_entry(name83: &[u8; 11]) -> Result<RootEntry, ()> {
    // Wave 14: the generation BEFORE the scan stamps what the scan finds, so
    // a write that lands while it runs leaves the entry already stale.
    let gen = WRITE_GEN.load(core::sync::atomic::Ordering::Acquire);
    if let Some(e) = dcache_get(name83, gen) { return Ok(e); }
    let e = fat32_lookup_root_entry_scan(name83)?;
    dcache_put(name83, gen, e);
    Ok(e)
}

// ── Root-directory entry cache (wave 14) ─────────────────────────────────────
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
struct Dentry { gen: u32, name: [u8; 11], e: RootEntry }

const NO_DENTRY: Dentry = Dentry {
    gen: 0,
    name: [0u8; 11],
    e: RootEntry { cluster: 0, size: 0, attr: 0, wrt_date: 0, wrt_time: 0, crt_date: 0, crt_time: 0, acc_date: 0 },
};

/// A leaf lock, held for one probe (a hash and an 11-byte compare).
static DCACHE: SpinLock<[Dentry; DCACHE_SLOTS]> = SpinLock::new([NO_DENTRY; DCACHE_SLOTS]);

#[inline]
fn dcache_slot(name: &[u8; 11]) -> usize {
    let mut h = 0u32;
    for &b in name { h = h.wrapping_mul(31).wrapping_add(b as u32); }
    (h as usize) % DCACHE_SLOTS
}

fn dcache_get(name: &[u8; 11], gen: u32) -> Option<RootEntry> {
    let d = DCACHE.lock()[dcache_slot(name)];
    let fresh = d.gen == gen || cfg!(feature = "dcache-stale-canary");
    (d.gen != 0 && fresh && d.name == *name).then_some(d.e)
}

fn dcache_put(name: &[u8; 11], gen: u32, e: RootEntry) {
    DCACHE.lock()[dcache_slot(name)] = Dentry { gen, name: *name, e };
}

fn fat32_lookup_root_entry_scan(name83: &[u8; 11]) -> Result<RootEntry, ()> {
    if !FAT32.lock().mounted { return Err(()); }
    let root_cluster = FAT32.lock().root_cluster;

    let (spc, data_start, fat_sz32, data_clusters) = {
        let v = FAT32.lock();
        (v.secs_per_clus, v.data_start, v.fat_sz32, v.data_clusters)
    };
    // Cycle guard — see `chain_walk_limit`. Reachable from ring 3 via open().
    let limit = chain_walk_limit(fat_sz32, data_clusters);
    let mut steps = 0u32;

    let mut cluster = root_cluster;
    while cluster >= FAT32_FIRST_DATA_CLUSTER && cluster < FAT32_EOC {
        if steps >= limit { return Err(()); }
        steps += 1;

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
            read_sector(first_sector + s, &mut sec_buf)?;

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

        cluster = fat32_next_cluster(cluster).unwrap_or(FAT32_EOC);
    }
    Err(())
}

/// Returns true if FAT32 is mounted.
pub fn fat32_mounted() -> bool {
    FAT32.lock().mounted
}

// ── Write support (Phase 8) ───────────────────────────────────────────────────

/// Write a single 512-byte sector via VirtIO block.
///
/// Updates the in-memory sector cache so a subsequent read sees the
/// fresh contents (write-through). Without invalidation a later
/// read_sector() would return stale cached data even after a write.
fn write_sector(sector: u32, buf: &[u8; SECTOR_SIZE]) -> Result<(), ()> {
    write_sector_in(sector, buf, false)
}

/// [`write_sector`] into the epoch after the current one, with no barrier
/// (`BlockCache::write_dirty_ahead`); write-back only — a write-through
/// cache answers `Uncached` and the sector goes to the device now, which
/// the caller must have ordered itself. For a directory entry that names
/// data and a chain written in the current epoch (wave 15, FW).
fn write_sector_ahead(sector: u32, buf: &[u8; SECTOR_SIZE]) -> Result<(), ()> {
    write_sector_in(sector, buf, true)
}

fn write_sector_in(sector: u32, buf: &[u8; SECTOR_SIZE], ahead: bool) -> Result<(), ()> {
    if WB {
        loop {
            let r = if ahead {
                SECTOR_CACHE.lock().write_dirty_ahead(sector as u64, buf)
            } else {
                SECTOR_CACHE.lock().write_dirty(sector as u64, buf)
            };
            match r {
                crate::bcache::Dirty::Done { first } => {
                    if first {
                        WB_DIRTY_SINCE.store(wb_now_ms(), core::sync::atomic::Ordering::Relaxed);
                    }
                    write_gen_bump();
                    let (dirty, lines) = fat32_writeback_dirty();
                    if wb_over_watermark(dirty, lines) { wb_wake(); }
                    return Ok(());
                }
                crate::bcache::Dirty::NeedWriteback(epoch) => {
                    let claim = wb_claim();
                    if wb_write_back(&claim, epoch).is_err() {
                        write_gen_bump();
                        return Err(());
                    }
                }
                crate::bcache::Dirty::Uncached => break,
            }
        }
    }
    // Quiet: this path keeps the cache coherent itself, just below; the
    // block layer's observer is for writers that do not.
    // Gate canary only: the bump BEFORE the bytes land (the class of order
    // the comment below rules out).
    if cfg!(feature = "write-gen-early-canary") { write_gen_bump(); }
    pi_io_probe();
    let r = azos_drv_block::blkdev::write_quiet(dev_lba(sector as u64), 1, buf);
    if r.is_err() {
        // What the device holds now is unknown; the old line must not answer.
        SECTOR_CACHE.lock().invalidate(sector as u64);
    } else if !cfg!(feature = "fatcache-writethrough-canary") {
        // Update the line if present (write-through). Cheaper than a straight
        // invalidate because the next reader pays no miss cost. Never installs.
        SECTOR_CACHE.lock().update_if_present(sector as u64, buf);
    }
    // Whatever the device answered, a directory entry or a FAT link may have
    // moved: every read-only stream looks its name up again. After the cache
    // line is current (wave 14, SPAWNCACHE): bumped before it, a reader could
    // load the new generation, read the old line, and stamp old bytes with a
    // generation no later write moves.
    if !cfg!(feature = "write-gen-early-canary") {
        write_gen_bump();
    }
    if r.is_err() { return Err(()); }
    Ok(())
}

/// Write a FAT32 entry for `cluster` to all FAT table copies.
///
/// The upper 4 bits of the existing entry are preserved (as per FAT32 spec).
/// Claims the entry's FAT sector for the read-modify-write
/// ([`fat_sector_claim`]); never call it while holding a claim.
fn fat32_write_fat_entry(cluster: u32, value: u32) -> Result<(), ()> {
    let _claim = fat_sector_claim(cluster / FAT32_ENTRIES_PER_SECTOR);
    fat32_write_fat_entry_claimed(cluster, value)
}

/// The body of [`fat32_write_fat_entry`], for a caller that already holds the
/// claim on `cluster`'s FAT sector (the allocator, which re-read that sector
/// under it). Without the claim this is the lost-update race the claim closes.
fn fat32_write_fat_entry_claimed(cluster: u32, value: u32) -> Result<(), ()> {
    let (fat_start, fat_sz32, num_fats, data_clusters) = {
        let v = FAT32.lock();
        (v.fat_start, v.fat_sz32, v.num_fats, v.data_clusters)
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
    read_sector(fat_start.checked_add(fat_sector_off).ok_or(())?, &mut buf)?;

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
    free_count_invalidate();

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
        write_sector(sec, &buf)?;
    }
    // And again after: a statfs scan on another hart that started after the
    // bump above but read this FAT sector before the write landed must not
    // find its generation unchanged and publish the stale count.
    free_count_invalidate();
    Ok(())
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
pub fn fat32_alloc_cluster() -> Result<u32, ()> {
    #[cfg(any(feature = "fat-mutate-spin-canary", feature = "fat-mutate-pi-canary"))]
    let _canary = FAT_MUTATE_CANARY.lock();
    fat32_alloc_cluster_inner()
}

/// [`fat32_alloc_cluster`] without the canaries' old lock, for the canary
/// build of `chain_nth_or_extend`, which holds that lock itself.
/// The FAT sector (relative to the FAT start) the last allocation found a
/// free entry in; the next scan starts there. Reset at mount.
static ALLOC_HINT: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

fn fat32_alloc_cluster_inner() -> Result<u32, ()> {
    match alloc_scan() {
        Ok(c) => Ok(c),
        // Full, but chains are held for the next flush (`defer_free`):
        // flush now, which frees every held chain, and scan once more.
        // Not in the FAT_MUTATE canary builds, whose caller may hold the
        // lock the flush's frees would take.
        Err(()) if fat32_held_clusters() > 0
            && !cfg!(any(feature = "fat-mutate-spin-canary", feature = "fat-mutate-pi-canary"))
            && device_flush().is_ok() => alloc_scan(),
        Err(()) => Err(()),
    }
}

/// One scan of the FAT for a free entry (see [`fat32_alloc_cluster`]).
fn alloc_scan() -> Result<u32, ()> {
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
        let v = FAT32.lock();
        (v.fat_start, v.fat_sz32, v.root_cluster, v.data_clusters)
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
        ALLOC_HINT.load(core::sync::atomic::Ordering::Relaxed).min(fat_sz32 - 1)
    };
    for k in 0..fat_sz32 {
        let sec_idx = (hint + k) % fat_sz32;
        let mut buf = [0u8; SECTOR_SIZE];
        // Checked, not saturating: saturating would silently rescan the last
        // addressable sector and hand out a cluster number that does not
        // correspond to the entry we actually read.
        let sec = match fat_start.checked_add(sec_idx) { Some(v) => v, None => return Err(()) };
        if read_sector(sec, &mut buf).is_err() { return Err(()); }
        match first_free_in_fat_sector(&buf, sec_idx, root_cluster)? {
            Some(c) if c < last_valid => {}
            _ => continue,
        }
        // A candidate. Confirm it on a current copy of the sector, under its
        // claim, and mark it there.
        let _claim = fat_sector_claim(sec_idx);
        if read_sector(sec, &mut buf).is_err() { return Err(()); }
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
        if fat32_write_fat_entry_claimed(cluster, 0x0FFF_FFFF).is_err() {
            let _ = fat32_write_fat_entry_claimed(cluster, 0);
            return Err(());
        }
        ALLOC_HINT.store(sec_idx, core::sync::atomic::Ordering::Relaxed);
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

/// Free all clusters in a chain starting at `start`.
pub fn fat32_free_chain(start: u32) {
    #[cfg(any(feature = "fat-mutate-spin-canary", feature = "fat-mutate-pi-canary"))]
    let _canary = FAT_MUTATE_CANARY.lock();
    free_chain_unlocked(start);
}

/// [`fat32_free_chain`] without the canaries' old lock: the release of held
/// chains runs inside an allocation that a canary build may call with that
/// lock held.
fn free_chain_unlocked(start: u32) {
    // No hold across the walk: each entry write claims its own FAT sector
    // (`fat32_write_fat_entry`). `next` is read before its cluster is freed,
    // so a cluster an allocator takes the instant it is freed is never
    // followed.
    let (fat_sz32, data_clusters) = { let v = FAT32.lock(); (v.fat_sz32, v.data_clusters) };
    // Cycle guard — see `chain_walk_limit`. This loop looks self-terminating on
    // a cycle (freeing FAT[2] makes the next lookup return 0), but that relies
    // on the write succeeding: the `let _ =` swallows a device error, and
    // `fat32_write_fat_entry` now legitimately rejects out-of-range clusters,
    // so on either path the loop would revisit the same cluster forever.
    let limit = chain_walk_limit(fat_sz32, data_clusters);
    let mut steps = 0u32;

    let mut cluster = start;
    while cluster >= FAT32_FIRST_DATA_CLUSTER && cluster < FAT32_EOC {
        if steps >= limit { break; }
        steps += 1;
        let next = fat32_next_cluster(cluster).unwrap_or(FAT32_EOC);
        let _ = fat32_write_fat_entry(cluster, 0); // Mark as free
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
static HELD: SpinLock<[HeldChain; HELD_SLOTS]> =
    SpinLock::new([HeldChain { first: 0, clusters: 0, epoch: 0 }; HELD_SLOTS]);
/// Sum of the held chains' `clusters`: what statfs counts as free on top of
/// the FAT's zero entries.
static HELD_CLUSTERS: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// Whether a chain taken away now is held (write-back with
/// `FS_DEFERRED_FREE`). Write-through flushes at every barrier, so it keeps
/// the undeferred order.
fn defer_frees() -> bool {
    azos_limits::FS_DEFERRED_FREE && wb_active()
}

/// Clusters held for a later free (statfs counts them free).
pub fn fat32_held_clusters() -> u32 {
    HELD_CLUSTERS.load(core::sync::atomic::Ordering::Relaxed)
}

/// Hold `first`'s chain (named by `size` bytes) until the epoch current now
/// is durable. Call it AFTER the write that stops naming the chain, so that
/// write is in this epoch or an earlier one. When every slot is taken, the
/// undeferred order: close the epoch, then free into the next one (the
/// write-back puts a flush between them). `Err` only from that barrier; the
/// chain then leaks.
fn defer_free(first: u32, size: u32) -> Result<(), FsError> {
    if first < FAT32_FIRST_DATA_CLUSTER { return Ok(()); }
    if cfg!(feature = "deferred-free-canary") {
        // Canary: the chain is freed at once, in the unlinking write's own
        // epoch, and the allocator may reuse it there.
        fat32_free_chain(first);
        return Ok(());
    }
    let bpc = FAT32.lock().bytes_per_clus.max(1);
    let clusters = size.div_ceil(bpc).max(1);
    // The top epoch: the unlinking write may be an entry written ahead
    // (`write_sector_ahead`), and the chain is held until it is durable.
    let epoch = SECTOR_CACHE.lock().top_epoch();
    {
        let mut h = HELD.lock();
        if let Some(s) = h.iter_mut().find(|s| s.first == 0) {
            *s = HeldChain { first, clusters, epoch };
            HELD_CLUSTERS.fetch_add(clusters, core::sync::atomic::Ordering::Relaxed);
            return Ok(());
        }
    }
    // Every slot is taken. Write-back (wave 15, FW): close the epochs
    // (`barrier` returns the highest one closed) and free into the next
    // one this chain AND every held one: each unlinking write is in a
    // closed epoch, so the write-back puts a flush before the frees, as
    // write-through's "free one epoch later". One barrier then serves
    // `FS_DEFERRED_FREE_SLOTS` more holds, not one.
    if wb_active() && !cfg!(feature = "fw-free-one-held-canary") {
        // Through `barrier_closing`, like every other barrier, so the
        // `wb-barrier-flushes-canary` build flushes here too (FW2).
        let top = barrier_closing()?;
        fat32_free_chain(first);
        release_held(top);
        return Ok(());
    }
    match order_barrier() {
        Ok(()) | Err(FsError::Unsupported) => {}
        Err(e) => return Err(e),
    }
    fat32_free_chain(first);
    Ok(())
}

/// Free every held chain whose epoch is `<= upto`, which the caller has
/// just made durable. Called with no FAT32 lock and no write-back claim
/// held: the frees write FAT sectors through the cache. Returns how many.
fn release_held(upto: u64) -> usize {
    let mut n = 0;
    loop {
        let first = {
            let mut h = HELD.lock();
            match h.iter_mut().find(|s| s.first != 0 && s.epoch <= upto) {
                Some(s) => {
                    HELD_CLUSTERS.fetch_sub(s.clusters, core::sync::atomic::Ordering::Relaxed);
                    let f = s.first;
                    *s = HeldChain { first: 0, clusters: 0, epoch: 0 };
                    f
                }
                None => return n,
            }
        };
        free_chain_unlocked(first);
        n += 1;
    }
}

/// Forget every held chain (they leak): a new volume, or the medium changed
/// under this file.
fn held_reset() {
    let mut h = HELD.lock();
    for s in h.iter_mut() { *s = HeldChain { first: 0, clusters: 0, epoch: 0 }; }
    HELD_CLUSTERS.store(0, core::sync::atomic::Ordering::Relaxed);
}

/// Write `data` into the sectors of `cluster`, zero-padding the last sector.
fn fat32_write_cluster(cluster: u32, data: &[u8]) -> Result<(), ()> {
    let (spc, data_start) = {
        let v = FAT32.lock();
        (v.secs_per_clus, v.data_start)
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
        write_sector(first_sector + s, &sec_buf)?;
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
    cluster: u32,
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
        match fat32_next_cluster(cluster) {
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
        read_sector(sec, &mut buf)?;
        buf[DIRENT_OFF_NAME] = DIRENT_MARK_END;
        write_sector(sec, &buf)?;
    }
    Ok(())
}

/// Write a new 32-byte directory entry into the first free slot (0x00 or 0xE5)
/// of the root directory, extending the root's cluster chain by one cluster
/// when every slot of it is in use.
///
/// **This used to be its own slot finder, and it did not extend.** It walked
/// the chain and answered "no free directory slot" at its end, while
/// `dir_insert` — behind open-with-CREATE, `mkdir` and `rename` — grew the
/// directory. So a root whose chain happened to be exactly full could still
/// take a new subdirectory but not a new FILE through the whole-file write
/// every FAT32 proxy close uses: gate 192's `secure boot falls to R` row,
/// where `/fat/BOOTMETA.B` was the entry that no longer fit and the recovery
/// steer halted instead of resetting. One insert path now serves both.
///
/// `Err(FsError::NoSpace)` means the extension could not allocate a cluster,
/// and nothing in the directory was written — the caller may hand back what
/// it allocated for the file. Any other error may have written.
fn fat32_creat_root_dirent(name83: &[u8; 11], cluster: u32, size: u32) -> Result<(), FsError> {
    let root_cluster = FAT32.lock().root_cluster;
    dir_insert(root_cluster, name83, cluster, size, DIRENT_ATTR_ARCHIVE_FILE).map(|_| ())
}

/// Mark a root-directory entry as deleted (first byte = 0xE5).
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
pub fn fat32_unlink_root(name83: &[u8; 11]) -> Result<(), ()> {
    let (root_cluster, spc, data_start, fat_sz32, data_clusters) = {
        let v = FAT32.lock();
        (v.root_cluster, v.secs_per_clus, v.data_start, v.fat_sz32, v.data_clusters)
    };
    // Cycle guard — see `chain_walk_limit`.
    let limit = chain_walk_limit(fat_sz32, data_clusters);
    let mut steps = 0u32;

    let mut cluster = root_cluster;
    while cluster >= FAT32_FIRST_DATA_CLUSTER && cluster < FAT32_EOC {
        if steps >= limit { return Err(()); }
        steps += 1;
        let first_sector = match cluster_first_sector(data_start, cluster, spc) {
            Some(v) => v,
            None => return Err(()),
        };
        for s in 0..spc {
            let mut sec_buf = [0u8; SECTOR_SIZE];
            // s < spc, and cluster_first_sector proved first_sector + spc fits.
            if read_sector(first_sector + s, &mut sec_buf).is_err() { continue; }
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
                    fat32_journal_write(&journal)?;
                    journal_barrier()?;

                    // Step 2: Mark deleted.
                    sec_buf[off] = 0xE5;
                    write_sector(sector_num, &sec_buf)?;
                    journal_barrier()?;

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
                    fat32_journal_write(&committed)?;

                    // Step 4: Clear journal.
                    return fat32_journal_clear();
                }
            }
        }
        cluster = fat32_next_cluster(cluster).unwrap_or(FAT32_EOC);
    }
    Err(())
}

/// Rename a root-directory file, replacing `new_name83` if it already
/// exists — what an OTA promotion needs (copy the staged image in under a
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
/// it so), and crossing directories (root-directory names only). Together
/// with an in-place write this is the atomic-replace recipe: write a temp
/// file, fsync it, rename it over the live name.
pub fn fat32_rename(
    old_name83: &[u8; 11],
    new_name83: &[u8; 11],
) -> Result<(), crate::vfs::FsErr> {
    use crate::vfs::FsErr;
    // Every `Err(())` below is a block-device or journal failure, which is
    // what `Io` means; the answers that say WHY the call was refused are
    // decided up front, before anything is written.
    macro_rules! io { ($e:expr) => { $e.map_err(|_| FsErr::Io)? }; }

    if old_name83 == new_name83 { return Ok(()); }
    let src = fat32_lookup_root_entry(old_name83).map_err(|()| FsErr::NotFound)?;
    let (src_cluster, src_size) = (src.cluster, src.size);
    let src_is_dir = src.attr & ATTR_DIRECTORY != 0;
    let dest = fat32_lookup_root_entry(new_name83).ok();
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
    let (src_sector, src_offset) = io!(fat32_find_dirent_location(old_name83));

    match dest {
        Some(d) => {
            // Over an existing file: ONE journal record (`JOURNAL_OP_RENAME`)
            // covers the destination's new chain, the source's deletion and
            // the old chain's free. The first barrier puts the source chain
            // (written by an earlier call that need not have flushed it)
            // ahead of the record; once the record is durable, recovery
            // completes the rename.
            let dest_old_cluster = d.cluster;
            let defer = defer_frees();
            let (dest_sector, dest_offset) = io!(fat32_find_dirent_location(new_name83));
            io!(journal_barrier());
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
            io!(fat32_journal_write(&journal));
            io!(journal_barrier());
            io!(rename_apply(dest_sector, dest_offset, src_sector, src_offset, old_name83,
                src_cluster, src_size, dest_old_cluster, !defer));
            io!(journal_barrier());
            let committed = JournalEntry { state: JOURNAL_COMMITTED, ..journal };
            io!(fat32_journal_write(&committed));
            io!(fat32_journal_clear());
            // Held until the clear is durable (`defer_free`): recovery of a
            // record whose clear did not land frees this chain again.
            if defer && dest_old_cluster != src_cluster {
                let _ = defer_free(dest_old_cluster, d.size);
            }
        }
        None => {
            // To a new name: the source's own dirent is renamed in place —
            // eleven bytes of one sector, one device write, so a cut leaves
            // the old name or the new one, never both and never neither. The
            // slot, attributes, chain and size are untouched.
            let mut sec_buf = [0u8; SECTOR_SIZE];
            io!(read_sector(src_sector, &mut sec_buf));
            let o = src_offset as usize;
            if sec_buf[o..o + 11] != *old_name83 { return Err(FsErr::Io); }
            sec_buf[o..o + 11].copy_from_slice(new_name83);
            io!(write_sector(src_sector, &sec_buf));
        }
    }
    Ok(())
}

/// Scan the root directory for `name83`'s dirent location, read-only.
///
/// Split out of `fat32_unlink_root`'s scan so `fat32_write_file`'s overwrite
/// path can learn WHERE the old dirent lives before it commits to touching
/// anything — the journal entry it writes needs that location as ground
/// truth, recorded before the free/overwrite it is meant to make crash-safe.
fn fat32_find_dirent_location(name83: &[u8; 11]) -> Result<(u32, u16), ()> {
    let (root_cluster, spc, data_start, fat_sz32, data_clusters) = {
        let v = FAT32.lock();
        (v.root_cluster, v.secs_per_clus, v.data_start, v.fat_sz32, v.data_clusters)
    };
    // Cycle guard — see `chain_walk_limit`.
    let limit = chain_walk_limit(fat_sz32, data_clusters);
    let mut steps = 0u32;

    let mut cluster = root_cluster;
    while cluster >= FAT32_FIRST_DATA_CLUSTER && cluster < FAT32_EOC {
        if steps >= limit { return Err(()); }
        steps += 1;
        let first_sector = match cluster_first_sector(data_start, cluster, spc) {
            Some(v) => v,
            None => return Err(()),
        };
        for s in 0..spc {
            let mut sec_buf = [0u8; SECTOR_SIZE];
            if read_sector(first_sector + s, &mut sec_buf).is_err() { continue; }
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
        cluster = fat32_next_cluster(cluster).unwrap_or(FAT32_EOC);
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
    dir_sector: u32, dir_offset: u16, cluster: u32, size: u32,
) -> Result<(), ()> {
    dirent_clus_size_in(dir_sector, dir_offset, cluster, size, false)
}

/// [`fat32_update_dirent_clus_size`], the sector written ahead
/// (`write_sector_ahead`) when `ahead`.
fn dirent_clus_size_in(
    dir_sector: u32, dir_offset: u16, cluster: u32, size: u32, ahead: bool,
) -> Result<(), ()> {
    let off = dir_offset as usize;
    if off + DIRENT_SIZE > SECTOR_SIZE { return Err(()); }
    let mut sec_buf = [0u8; SECTOR_SIZE];
    read_sector(dir_sector, &mut sec_buf)?;
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
    if ahead { write_sector_ahead(dir_sector, &sec_buf) } else { write_sector(dir_sector, &sec_buf) }
}

/// Allocate a fresh cluster chain and write `data` into it, extending one
/// cluster at a time. Never called with empty `data` — callers special-case
/// that as cluster 0 (no chain), matching a FAT32 zero-length file.
fn fat32_alloc_and_write_chain(data: &[u8], bytes_per_clus: usize) -> Result<u32, ()> {
    let fc = fat32_alloc_cluster()?;
    if fat32_write_chain_from(fc, data, bytes_per_clus).is_err() {
        fat32_free_chain(fc);
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
fn fat32_write_chain_from(fc: u32, data: &[u8], bytes_per_clus: usize) -> Result<(), ()> {
    let mut cur = fc;
    let mut off = 0usize;
    loop {
        let end = (off + bytes_per_clus).min(data.len());
        fat32_write_cluster(cur, &data[off..end])?;
        off = end;
        if off >= data.len() { break; }
        let next = fat32_alloc_cluster()?;
        if fat32_write_fat_entry(cur, next).is_err() {
            fat32_free_chain(next);
            return Err(());
        }
        cur = next;
    }
    Ok(())
}

/// Create or overwrite a file in the FAT32 root directory.
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
pub fn fat32_write_file(name83: &[u8; 11], data: &[u8]) -> Result<(), ()> {
    write_file_journaled(name83, data)?;
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
    match device_flush() {
        Ok(()) | Err(FsError::Unsupported) => Ok(()),
        Err(_) => Err(()),
    }
}

/// [`fat32_write_file`] without its final flush, under write-back: the
/// journaled create/overwrite is queued in the cache, its steps ordered by
/// epochs, and returns without waiting on the device. A cut before the
/// write-back leaves the old file or the new one, as for the durable call;
/// what is not promised is WHICH until an fsync/sync (or the `fs-wb` task's
/// age bound) has run. The VFS proxy's close and fsync use it (fsync then
/// flushes: `FileSystem::fsync`). Write-through: exactly `fat32_write_file`.
pub fn fat32_write_file_queued(name83: &[u8; 11], data: &[u8]) -> Result<(), ()> {
    if !wb_active() || cfg!(feature = "wb-close-flushes-canary") {
        return fat32_write_file(name83, data);
    }
    write_file_journaled(name83, data)
}

/// The journaled create/overwrite protocol behind [`fat32_write_file`].
fn write_file_journaled(name83: &[u8; 11], data: &[u8]) -> Result<(), ()> {
    if !FAT32.lock().mounted { return Err(()); }

    // Read-only: is this an overwrite, and if so, where does the old dirent
    // live? Nothing is modified here — the old file is still fully intact
    // after this block, whichever branch `fat32_write_file` takes below.
    let overwrite = match fat32_lookup_root(name83) {
        Ok((old_cluster, old_size)) => match fat32_find_dirent_location(name83) {
            Ok((dir_sector, dir_offset)) => Some((old_cluster, old_size, dir_sector, dir_offset)),
            // Lookup found it but the location scan didn't (e.g. a
            // concurrent-looking, mid-directory-walk mismatch) — fail
            // closed rather than silently falling back to a second dirent
            // for the same name.
            Err(_) => return Err(()),
        },
        Err(_) => None,
    };

    let bytes_per_clus = FAT32.lock().bytes_per_clus as usize;
    if bytes_per_clus == 0 { return Err(()); }

    if let Some((old_cluster, old_size, dir_sector, dir_offset)) = overwrite {
        // ── Overwrite path ──────────────────────────────────────────────
        let new_cluster = if data.is_empty() {
            0u32
        } else {
            fat32_alloc_and_write_chain(data, bytes_per_clus)?
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
        if journal_barrier().is_err() {
            if new_cluster >= FAT32_FIRST_DATA_CLUSTER { fat32_free_chain(new_cluster); }
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
        fat32_journal_write(&journal)?;
        // Barrier 1: the record before the first write it covers. Without
        // it the old chain's free could reach the medium while neither the
        // record nor the new dirent did: a live dirent over free clusters.
        journal_barrier()?;

        let defer = defer_frees();
        fat32_update_dirent_clus_size(dir_sector, dir_offset, new_cluster, data.len() as u32)?;
        if !defer && old_cluster >= FAT32_FIRST_DATA_CLUSTER {
            fat32_free_chain(old_cluster);
        }
        // Barrier 2: the mutation before the commit. A COMMITTED (or
        // cleared) record that overtook it would stop recovery from
        // finishing a half-applied overwrite.
        journal_barrier()?;

        let committed = JournalEntry { state: JOURNAL_COMMITTED, ..journal };
        fat32_journal_write(&committed)?;
        fat32_journal_clear()?;
        // Held until the clear is durable (`defer_free`): recovery of a
        // PENDING record frees the old chain again, so it must not have
        // been reused before the clear landed.
        if defer { let _ = defer_free(old_cluster, old_size); }
        return Ok(());
    }

    // ── Create path (no existing file) — unchanged ordering ─────────────
    let first_cluster = if data.is_empty() {
        0u32  // Empty file: no cluster
    } else {
        let fc = fat32_alloc_cluster()?;

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
        let written = fat32_journal_write(&journal).is_ok()
            // Barrier 1: the record before the writes it describes. A PENDING
            // `WRITE_DIR` is discarded at mount, so this one is not what keeps
            // the volume consistent (barrier 2 is); it keeps the owner's
            // journal-first protocol exact.
            && journal_barrier().is_ok()
            // Steps 2-3: data clusters, FAT chain.
            && fat32_write_chain_from(fc, data, bytes_per_clus).is_ok()
            // Barrier 2: data + FAT chain on the medium before the dirent that
            // makes them a file. Without it the dirent can land first and name
            // clusters whose data or FAT links the medium never received —
            // and a PENDING `WRITE_DIR` is discarded, not rolled back.
            && journal_barrier().is_ok();
        if !written {
            fat32_free_chain(fc);
            let _ = fat32_journal_clear();
            return Err(());
        }
        fc
    };

    // Step 4: Write the directory entry.
    match fat32_creat_root_dirent(name83, first_cluster, data.len() as u32) {
        Ok(()) => {}
        // No cluster for a directory extension: nothing in the directory was
        // written, so the chain built above is referenced by nothing. Hand
        // it back and clear the record instead of leaking a cluster per
        // failed attempt on a volume that is, by definition, already out of
        // space. A crash between the free and the clear leaves a PENDING
        // `WRITE_DIR`, which mount discards.
        Err(FsError::NoSpace) => {
            if first_cluster >= FAT32_FIRST_DATA_CLUSTER {
                fat32_free_chain(first_cluster);
            }
            let _ = fat32_journal_clear();
            return Err(());
        }
        // Any other failure may have reached the directory — but usually
        // did not (a root chain the walk refuses fails before any write).
        // Keep the chain only if a dirent naming it did land: a dangling
        // dirent over freed clusters is worse than a leak, and a leak per
        // attempt is what this used to be (wave 11, `tests/fuzz/fs-fuzz`).
        Err(_) => {
            let named = matches!(fat32_lookup_root(name83), Ok((c, _)) if c == first_cluster);
            if first_cluster >= FAT32_FIRST_DATA_CLUSTER && !named {
                fat32_free_chain(first_cluster);
                let _ = fat32_journal_clear();
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
    fat32_journal_write(&committed)?;

    // Step 6: Clear journal.
    fat32_journal_clear()
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

/// Unlink a root-directory file by raw filename (e.g. `b"TEST.TXT"`).
/// Marks the directory entry deleted, then frees its cluster chain.
///
/// That order, with `fat32_unlink_root`'s barrier after the dirent write:
/// the chain used to be freed FIRST, so a power cut could leave the dirent
/// on the medium over clusters the FAT already called free — the next
/// allocation would cross-link them. Now the worst a cut leaves is a
/// deleted dirent and a leaked chain.
pub fn fat32_unlink_path(name: &[u8]) -> Result<(), ()> {
    let name83 = path_to_83_local(name).ok_or(())?;
    let cluster = fat32_lookup_root(&name83).map(|(c, _)| c).unwrap_or(0);
    fat32_unlink_root(&name83)?;
    if cluster >= 2 { fat32_free_chain(cluster); }
    Ok(())
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
/// Since RFC-0048 P1 it first asks the shared block cache to write back its
/// dirty lines, oldest epoch first, and then closes the cache's epoch after
/// the flush: a journal barrier is an epoch boundary of the cache too. The
/// FAT32 instance is write-through, so the write-back pass finds nothing and
/// issues no I/O — the device sees exactly the write/flush sequence it saw
/// before the cache was shared (`tests/host/fs-tests` `durability`/`power_cut`
/// assert that sequence).
fn device_flush() -> Result<(), FsError> {
    if WB && SECTOR_CACHE.lock().mode() == crate::bcache::Mode::WriteBack {
        // Write-back: under the claim, close the epoch FIRST (a write made
        // after this point is not this flush's to make durable, and cannot
        // keep it running), write back through it, then flush the device.
        let claim = wb_claim();
        // `barrier` returns the highest epoch it closed: the one a
        // directory entry was written ahead into (`write_sector_ahead`)
        // when there is one, so this flush makes it durable too.
        let upto = SECTOR_CACHE.lock().barrier();
        if !cfg!(feature = "wb-flush-no-writeback-canary") {
            wb_write_back(&claim, upto)?;
        }
        let r = device_flush_raw();
        if r.is_ok() {
            SECTOR_CACHE.lock().note_flushed();
        }
        drop(claim);
        // Every epoch `<= upto` is durable now: free the chains their
        // unlinking writes released (`defer_free`), into the epoch just
        // opened. Outside the claim: a free may have to write back.
        if r.is_ok() && !cfg!(feature = "wb-flush-no-writeback-canary") {
            release_held(upto);
        }
        return r;
    }
    {
        let mut c = SECTOR_CACHE.lock();
        match c.write_back_all(&mut BlkDev) {
            Ok(()) => {}
            Err(crate::bcache::IoError::Flush(e)) => return Err(e),
            Err(_) => return Err(FsError::Io),
        }
    }
    let r = device_flush_raw();
    if r.is_ok() {
        let mut c = SECTOR_CACHE.lock();
        c.note_flushed();
        c.barrier();
    }
    r
}

/// The device flush alone, with the driver's answer mapped to `FsError`.
fn device_flush_raw() -> Result<(), FsError> {
    match azos_drv_block::blkdev::flush() {
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
fn journal_barrier() -> Result<(), ()> {
    order_barrier().map_err(|_| ())
}

/// Whether the FAT32 cache is in write-back mode now.
fn wb_active() -> bool {
    WB && SECTOR_CACHE.lock().mode() == crate::bcache::Mode::WriteBack
}

/// Every write issued before this reaches the medium before any issued
/// after it. Write-through: a device flush (`device_flush`). Write-back: the
/// cache's epoch closes — no I/O; the write-back puts the flush between the
/// two epochs when it writes them (`checkout_run`'s `flush_first`), and a
/// cut leaves the same states as with the flush here. A write-back mount
/// requires a device that flushes (`fat32_mount` probes it), so the
/// fail-closed rule for `Unsupported` above holds by construction.
fn order_barrier() -> Result<(), FsError> {
    barrier_closing().map(|_| ())
}

/// [`order_barrier`], returning the highest epoch it closed: every write
/// issued before it is in that epoch or an earlier one. Write-back: the
/// cache's barrier (no I/O). Write-through, and the
/// `wb-barrier-flushes-canary` build: a device flush, which closes the same
/// epochs and makes them durable. Every barrier FAT32 puts between its own
/// writes goes through here, so the canary reaches each of them.
fn barrier_closing() -> Result<u64, FsError> {
    if wb_active() && !cfg!(feature = "wb-barrier-flushes-canary") {
        return Ok(SECTOR_CACHE.lock().barrier());
    }
    let top = SECTOR_CACHE.lock().top_epoch();
    device_flush().map(|()| top)
}

/// `true` when the journal sector holds no PENDING or COMMITTED record —
/// what mount-time recovery must leave behind. Read-only; for the
/// power-cut gate row, which asserts it after every cut.
pub fn fat32_journal_idle() -> bool {
    match fat32_journal_read() {
        Ok(e) => e.magic != JOURNAL_MAGIC || (e.state != JOURNAL_PENDING && e.state != JOURNAL_COMMITTED),
        Err(()) => false,
    }
}

/// Structural check of `name83`'s root-directory chain, read-only.
///
/// `Ok(None)`: no such dirent. `Ok(Some((first_cluster, size)))`: every
/// cluster the chain visits is an in-range data cluster the FAT does not
/// call free, the chain ends in EOC, and its length is exactly what `size`
/// needs. `Err(reason)` otherwise. For the power-cut gate row: a dirent
/// over a chain the FAT freed reads back correctly until the clusters are
/// reused, so a content check alone cannot see it.
pub fn fat32_check_root_chain(name83: &[u8; 11]) -> Result<Option<(u32, u32)>, &'static str> {
    let (first, size) = match fat32_lookup_root(name83) {
        Ok(v) => v,
        Err(()) => return Ok(None),
    };
    let (bpc, data_clusters) = {
        let v = FAT32.lock();
        (v.bytes_per_clus, v.data_clusters)
    };
    if bpc == 0 { return Err("volume not mounted"); }
    let want = (size as u64).div_ceil(bpc as u64);
    if want == 0 {
        return if first == 0 { Ok(Some((0, 0))) } else { Err("empty file names a cluster") };
    }
    let last_valid = data_clusters.saturating_add(FAT32_FIRST_DATA_CLUSTER);
    let mut cluster = first;
    let mut seen = 0u64;
    loop {
        if cluster < FAT32_FIRST_DATA_CLUSTER || cluster >= last_valid {
            return Err("link to a cluster outside the data region");
        }
        seen += 1;
        if seen > want { return Err("chain longer than its size"); }
        let next = fat32_next_cluster(cluster).map_err(|()| "FAT unreadable")?;
        if next == 0 { return Err("a live chain runs through a FREE cluster"); }
        if next >= FAT32_EOC { break; }
        cluster = next;
    }
    if seen != want { return Err("chain shorter than its size"); }
    Ok(Some((first, size)))
}

/// Clear a committed journal entry so the NEXT mount does not replay it.
fn journal_settle() -> Result<(), ()> {
    let entry = fat32_journal_read()?;
    if entry.magic == JOURNAL_MAGIC && entry.state == JOURNAL_COMMITTED {
        fat32_journal_clear()?;
    }
    Ok(())
}

/// Settle the journal, then flush the device, so every write this volume has
/// completed so far is durable when this returns `Ok`.
///
/// Returns the device's answer: `Unsupported` if it cannot flush, `Io` if the
/// flush failed. `NotMounted` / `Io` from the journal step as before.
pub fn fat32_sync_checked() -> Result<(), FsError> {
    if !FAT32.lock().mounted { return Err(FsError::NotMounted); }
    journal_settle().map_err(|()| FsError::Io)?;
    device_flush()?;
    wb_take_error()
}

/// `Err(Io)` once after a write-back no caller waited for failed.
fn wb_take_error() -> Result<(), FsError> {
    if WB_ERROR.swap(false, core::sync::atomic::Ordering::Relaxed) { Err(FsError::Io) } else { Ok(()) }
}

/// [`fat32_sync_checked`] with the error folded to `()`, for the callers and
/// the `FileSystem::sync` signature that take `Result<(), ()>`. `Err` now
/// includes "the device could not confirm the flush".
pub fn fat32_sync() -> Result<(), ()> {
    fat32_sync_checked().map_err(|_| ())
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

/// Enumerate all entries in the FAT32 root directory.
///
/// Calls `cb(name, file_size, is_dir)` for each valid, non-deleted entry.
/// Deleted entries, LFN entries, and volume-ID entries are skipped.
pub fn fat32_ls_root(mut cb: impl FnMut(&[u8], u32, bool)) {
    if !FAT32.lock().mounted { return; }
    let root_cluster = FAT32.lock().root_cluster;

    let (spc, data_start, fat_sz32, data_clusters) = {
        let v = FAT32.lock();
        (v.secs_per_clus, v.data_start, v.fat_sz32, v.data_clusters)
    };
    // Cycle guard — see `chain_walk_limit`.
    let limit = chain_walk_limit(fat_sz32, data_clusters);
    let mut steps = 0u32;

    let mut cluster = root_cluster;
    while cluster >= FAT32_FIRST_DATA_CLUSTER && cluster < FAT32_EOC {
        if steps >= limit { return; }
        steps += 1;
        let first_sector = match cluster_first_sector(data_start, cluster, spc) {
            Some(v) => v,
            None => return,
        };

        'outer: for s in 0..spc {
            let mut sec_buf = [0u8; SECTOR_SIZE];
            // s < spc, and cluster_first_sector proved first_sector + spc fits.
            if read_sector(first_sector + s, &mut sec_buf).is_err() { break 'outer; }

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

        cluster = fat32_next_cluster(cluster).unwrap_or(FAT32_EOC);
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
    cluster: u32,
    sector_in_cluster: u32,
    entry_in_sector: usize,
    done: bool,
    /// Clusters visited so far by this iterator, checked against
    /// `chain_walk_limit` on every advance.
    ///
    /// This has to live in the struct, not as a local in `next()`: the loop is
    /// re-entered on each call, so a local would reset every time and a
    /// directory cycle whose sectors contain only deleted (0xE5) entries —
    /// which never produce a `return` — would still spin forever inside a
    /// single `next()`.
    clusters_walked: u32,
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
};

static OPEN_FILES: SpinLock<[OpenFileEntry; FAT32_MAX_OPEN_FILES]> =
    SpinLock::new([EMPTY_OPEN_FILE; FAT32_MAX_OPEN_FILES]);

// ── Volume mount/unmount API ─────────────────────────────────────────────────

/// Mount the FAT32 filesystem and return a `Volume` handle.  Wraps
/// [`fat32_mount`] for a more modern API surface.
pub fn fat32_mount_volume() -> Result<Volume, FsError> {
    fat32_mount().map(|()| Volume { _private: () }).map_err(|()| FsError::NotMounted)
}

/// Unmount the FAT32 filesystem.  Flushes the journal and closes all open
/// files (dropping their dirty writes after a final sync).  Safe to call even
/// if no volume is mounted.
pub fn fat32_unmount(_vol: Volume) -> Result<(), FsError> {
    // Sync + close every currently-open file so no write is lost.
    let slots_to_close: [(bool, u16); FAT32_MAX_OPEN_FILES] = {
        let t = OPEN_FILES.lock();
        let mut out = [(false, 0u16); FAT32_MAX_OPEN_FILES];
        for i in 0..FAT32_MAX_OPEN_FILES {
            out[i] = (t[i].in_use, t[i].generation);
        }
        out
    };
    for i in 0..FAT32_MAX_OPEN_FILES {
        if slots_to_close[i].0 {
            let h = Fat32File { slot: i as u16, generation: slots_to_close[i].1 };
            let _ = fat32_close(h);
        }
    }
    let _ = fat32_sync();
    // That flush freed the held chains into a new epoch (`defer_free`):
    // write it too, or the invalidation below drops the frees.
    if SECTOR_CACHE.lock().dirty_count() > 0 {
        let _ = device_flush();
    }
    held_reset();
    // Mark volume unmounted.
    FAT32.lock().mounted = false;
    // U09-6: drop every cached sector on unmount too, not just on the next
    // mount. Between this unmount and a future mount, the medium may be
    // physically swapped (MSC gadget, SD card) with the cache never told;
    // invalidating here as well as in `fat32_mount` means neither the
    // outgoing nor the incoming volume's sectors can be read through a
    // stale line, regardless of which of the two calls a caller happens to
    // make first.
    fat32_cache_invalidate_all();
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
fn dir_find_in(dir_cluster: u32, name83: &[u8; 11]) -> Result<DirentLocation, FsError> {
    let (spc, data_start, fat_sz32, data_clusters) = {
        let v = FAT32.lock();
        (v.secs_per_clus, v.data_start, v.fat_sz32, v.data_clusters)
    };
    // Cycle guard — see `chain_walk_limit`. This is the walker a ring-3
    // `open()` reaches first, so a `FAT[n] = n` cycle here hangs the hart that
    // serviced the syscall with no I/O and no yield.
    let limit = chain_walk_limit(fat_sz32, data_clusters);
    let mut steps = 0u32;

    let mut cluster = dir_cluster;
    while cluster >= FAT32_FIRST_DATA_CLUSTER && cluster < FAT32_EOC {
        if steps >= limit { return Err(FsError::Io); }
        steps += 1;
        let first_sector = cluster_first_sector(data_start, cluster, spc)
            .ok_or(FsError::Io)?;
        for s in 0..spc {
            // s < spc, and cluster_first_sector proved first_sector + spc fits.
            let sec_num = first_sector + s;
            let mut buf = [0u8; SECTOR_SIZE];
            read_sector(sec_num, &mut buf).map_err(|()| FsError::Io)?;
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
        cluster = fat32_next_cluster(cluster).map_err(|()| FsError::Io)?;
    }
    Err(FsError::NotFound)
}

/// Resolve the directory that contains the final component of `path`.
///
/// Returns `(parent_dir_cluster, last_component)` — the caller can then call
/// `dir_find_in(parent_dir_cluster, ...)` or insert a new entry.
fn resolve_parent<'a>(path: &'a [u8]) -> Result<(u32, &'a [u8]), FsError> {
    if !fat32_mounted() { return Err(FsError::NotMounted); }
    let mut comps: [&[u8]; FAT32_MAX_PATH_DEPTH] = [&[]; FAT32_MAX_PATH_DEPTH];
    let n = split_path(path, &mut comps)?;
    if n == 0 { return Err(FsError::InvalidArg); }

    let root_cluster = FAT32.lock().root_cluster;
    let mut dir_cluster = root_cluster;
    // Walk all but the last component.
    for i in 0..(n - 1) {
        let name83 = component_to_83(comps[i]).ok_or(FsError::InvalidArg)?;
        let loc = dir_find_in(dir_cluster, &name83)?;
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
    dir_cluster: u32,
    name83: &[u8; 11],
    first_cluster: u32,
    size: u32,
    attr: u8,
) -> Result<(u32, u16), FsError> {
    let (spc, data_start, fat_sz32, data_clusters) = {
        let v = FAT32.lock();
        (v.secs_per_clus, v.data_start, v.fat_sz32, v.data_clusters)
    };
    // Cycle guard — see `chain_walk_limit`. Here the cap MUST return an error
    // rather than fall out of the loop: the code below the loop extends the
    // directory by allocating a fresh cluster and splicing it in with
    // `fat32_write_fat_entry(last_cluster, new_clus)`. Exiting the loop on a
    // cycle would graft a real allocation onto an attacker-controlled ring.
    let limit = chain_walk_limit(fat_sz32, data_clusters);
    let mut steps = 0u32;

    // Walk the chain looking for a free (end or deleted) slot.
    let mut cluster = dir_cluster;
    let mut last_cluster = cluster;
    while cluster >= FAT32_FIRST_DATA_CLUSTER && cluster < FAT32_EOC {
        if steps >= limit { return Err(FsError::Io); }
        steps += 1;
        let first_sector = cluster_first_sector(data_start, cluster, spc)
            .ok_or(FsError::Io)?;
        for s in 0..spc {
            // s < spc, and cluster_first_sector proved first_sector + spc fits.
            let sec_num = first_sector + s;
            let mut buf = [0u8; SECTOR_SIZE];
            read_sector(sec_num, &mut buf).map_err(|()| FsError::Io)?;
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
                        propagate_end_marker(
                            cluster, s, sec_num, e, FAT32_DIRENTS_PER_SECTOR,
                            spc, data_start, &mut buf,
                        ).map_err(|()| FsError::Io)?;
                    }
                    write_sector(sec_num, &buf).map_err(|()| FsError::Io)?;
                    return Ok((sec_num, off as u16));
                }
            }
        }
        last_cluster = cluster;
        cluster = fat32_next_cluster(cluster).map_err(|()| FsError::Io)?;
    }

    // Extend the directory by one cluster: allocate it (the allocator marks
    // it end-of-chain), fill it — the dirent in slot 0, every other slot
    // zero, so slot 1 terminates the directory — and only THEN link it after
    // `last_cluster`. The link is the commit point: it used to come first,
    // so a crash (or a failed write) before the zeroing grafted a cluster of
    // stale data onto the directory, whose bytes every later walk would read
    // as entries. Now a failure before the link leaves the directory exactly
    // as it was and, at worst, one allocated cluster nothing references.
    let new_clus = fat32_alloc_cluster().map_err(|()| FsError::NoSpace)?;
    let filled = cluster_first_sector(data_start, new_clus, spc).ok_or(()).and_then(|first_sector| {
        let mut buf = [0u8; SECTOR_SIZE];
        write_dirent_into_buf(&mut buf, 0, name83, first_cluster, size, attr);
        write_sector(first_sector, &buf)?;
        let zero = [0u8; SECTOR_SIZE];
        for s in 1..spc {
            // s < spc, and cluster_first_sector proved first_sector + spc fits.
            write_sector(first_sector + s, &zero)?;
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
        Ok(sec) if matches!(order_barrier(), Ok(()) | Err(FsError::Unsupported)) => sec,
        _ => {
            fat32_free_chain(new_clus);
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
    if fat32_write_fat_entry(last_cluster, new_clus).is_err() {
        if fat32_write_fat_entry(last_cluster, FAT32_END_OF_CHAIN).is_ok() {
            fat32_free_chain(new_clus);
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
    dir_sector: u32,
    dir_offset: u16,
    first_cluster: u32,
    size: u32,
) -> Result<(), FsError> {
    dir_update_meta_in(dir_sector, dir_offset, first_cluster, size, false)
}

/// [`dir_update_meta`] with the sector written ahead (`write_sector_ahead`)
/// when `ahead`.
fn dir_update_meta_in(
    dir_sector: u32,
    dir_offset: u16,
    first_cluster: u32,
    size: u32,
    ahead: bool,
) -> Result<(), FsError> {
    let mut buf = [0u8; SECTOR_SIZE];
    read_sector(dir_sector, &mut buf).map_err(|()| FsError::Io)?;
    let off = dir_offset as usize;
    let hi = ((first_cluster >> 16) & 0xFFFF) as u16;
    let lo = (first_cluster & 0xFFFF) as u16;
    buf[off + DIRENT_OFF_FST_CLUS_HI..off + DIRENT_OFF_FST_CLUS_HI + 2]
        .copy_from_slice(&hi.to_le_bytes());
    buf[off + DIRENT_OFF_FST_CLUS_LO..off + DIRENT_OFF_FST_CLUS_LO + 2]
        .copy_from_slice(&lo.to_le_bytes());
    buf[off + DIRENT_OFF_FILE_SIZE..off + DIRENT_OFF_FILE_SIZE + 4]
        .copy_from_slice(&size.to_le_bytes());
    if ahead { write_sector_ahead(dir_sector, &buf) } else { write_sector(dir_sector, &buf) }
        .map_err(|()| FsError::Io)?;
    Ok(())
}

// ── Cluster chain walking helper ─────────────────────────────────────────────

/// Walk the cluster chain starting at `first_cluster` and return the cluster
/// number at the `n`-th position (0-indexed).  If the chain ends before that
/// position, returns `Err(FsError::NotFound)`.
fn chain_nth(first_cluster: u32, n: u32) -> Result<u32, FsError> {
    if first_cluster < FAT32_FIRST_DATA_CLUSTER { return Err(FsError::NotFound); }
    // A chain longer than the FAT has entries is a cycle. `n` is already
    // bounded by the u32 file position, so this is not a hang, but a crafted
    // cycle would otherwise make one `fat32_read` grind through millions of
    // FAT lookups and then hand back data from a cluster the file never owned.
    let (fat_sz32, data_clusters) = { let v = FAT32.lock(); (v.fat_sz32, v.data_clusters) };
    if n >= chain_walk_limit(fat_sz32, data_clusters) { return Err(FsError::Io); }
    let mut cur = first_cluster;
    for _ in 0..n {
        let next = fat32_next_cluster(cur).map_err(|()| FsError::Io)?;
        if next < FAT32_FIRST_DATA_CLUSTER || next >= FAT32_EOC {
            return Err(FsError::NotFound);
        }
        cur = next;
    }
    Ok(cur)
}

/// Walk the cluster chain starting at `first_cluster` to the `n`-th position,
/// allocating new clusters as needed.  The final cluster is marked as
/// end-of-chain.  Returns the cluster number at position `n`.
fn chain_nth_or_extend(first_cluster: u32, n: u32) -> Result<u32, FsError> {
    if first_cluster < FAT32_FIRST_DATA_CLUSTER { return Err(FsError::InvalidArg); }
    // Same bound as `chain_nth`: no legitimate chain can be longer than the
    // number of entries the FAT holds, and refusing early stops a crafted
    // cycle from turning one write into millions of FAT lookups.
    let (fat_sz32, data_clusters) = { let v = FAT32.lock(); (v.fat_sz32, v.data_clusters) };
    if n >= chain_walk_limit(fat_sz32, data_clusters) { return Err(FsError::Io); }
    let mut cur = first_cluster;
    for _ in 0..n {
        let next = fat32_next_cluster(cur).map_err(|()| FsError::Io)?;
        if next < FAT32_FIRST_DATA_CLUSTER || next >= FAT32_EOC {
            // U09-2: once `fresh` reads end-of-chain no allocator can take
            // it, so allocation and the link below need no common hold —
            // each entry write claims its own FAT sector (F1: nothing is held
            // across the device I/O).
            #[cfg(any(feature = "fat-mutate-spin-canary", feature = "fat-mutate-pi-canary"))]
            let _canary = FAT_MUTATE_CANARY.lock(); // the old hold: alloc + both links
            let fresh = fat32_alloc_cluster_inner().map_err(|()| FsError::NoSpace)?;
            // A failed link would leak `fresh` (allocated, in no chain):
            // undo it as `dir_insert` does, and give `fresh` back only when
            // `cur` is end-of-chain again in every copy.
            if fat32_write_fat_entry(cur, fresh).is_err() {
                if fat32_write_fat_entry(cur, FAT32_END_OF_CHAIN).is_ok() {
                    let _ = fat32_write_fat_entry(fresh, 0);
                }
                return Err(FsError::Io);
            }
            // `fresh` is already end-of-chain in every copy: the allocator
            // marked it so under its sector's claim (wave 15, FW: this
            // rewrote it, a FAT read-modify-write per copy per cluster).
            if cfg!(feature = "fw-chain-walk-canary") {
                fat32_write_fat_entry(fresh, FAT32_END_OF_CHAIN).map_err(|()| FsError::Io)?;
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
    first_cluster: u32,
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
        let cluster = chain_nth_or_extend(first_cluster, cluster_index)?;
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
            read_sector(sec_num, &mut sec_buf).map_err(|()| FsError::Io)?;
        }
        for b in &mut sec_buf[offset_in_sector..offset_in_sector + to_zero] { *b = 0; }
        write_sector(sec_num, &sec_buf).map_err(|()| FsError::Io)?;

        pos += to_zero as u32;
    }
    Ok(())
}

// ── File handle pool helpers ─────────────────────────────────────────────────

fn alloc_handle(entry: OpenFileEntry) -> Result<Fat32File, FsError> {
    let mut t = OPEN_FILES.lock();
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
    file: Fat32File,
    f: impl FnOnce(&mut OpenFileEntry) -> Result<R, FsError>,
) -> Result<R, FsError> {
    let mut t = OPEN_FILES.lock();
    let slot = file.slot as usize;
    if slot >= FAT32_MAX_OPEN_FILES { return Err(FsError::BadHandle); }
    if !t[slot].in_use || t[slot].generation != file.generation {
        return Err(FsError::BadHandle);
    }
    f(&mut t[slot])
}

fn snapshot_handle(file: Fat32File) -> Result<OpenFileEntry, FsError> {
    with_handle(file, |e| Ok(*e))
}

// ── Public open/close/read/write/seek/sync ───────────────────────────────────

/// Open a file by absolute path (e.g. `b"/log/boot.log"`).  Supports nested
/// directories up to `FAT32_MAX_PATH_DEPTH` deep.
pub fn fat32_open(_vol: Volume, path: &[u8], flags: u32) -> Result<Fat32File, FsError> {
    if !fat32_mounted() { return Err(FsError::NotMounted); }
    if flags & (open_flags::READ | open_flags::WRITE) == 0 {
        return Err(FsError::InvalidArg);
    }

    let (parent_cluster, last) = resolve_parent(path)?;
    let name83 = component_to_83(last).ok_or(FsError::InvalidArg)?;

    let (dir_sector, dir_offset, first_cluster, size) =
        match dir_find_in(parent_cluster, &name83) {
            Ok(loc) => {
                if loc.attr & ATTR_DIRECTORY != 0 { return Err(FsError::WrongType); }
                (loc.sector, loc.offset, loc.first_cluster, loc.size)
            }
            Err(FsError::NotFound) => {
                if flags & open_flags::CREATE == 0 { return Err(FsError::NotFound); }
                // Create empty dirent (no cluster allocated yet).
                let (sec, off) = dir_insert(
                    parent_cluster,
                    &name83,
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
        fat32_journal_write(&journal).map_err(|()| FsError::Io)?;
        // Barriers as in `write_file_journaled`'s overwrite arm (no chain
        // to order ahead of the record: the new side is empty).
        journal_barrier().map_err(|()| FsError::Io)?;

        let defer = defer_frees();
        dir_update_meta(dir_sector, dir_offset, 0, 0)?;
        if !defer && old_cluster >= FAT32_FIRST_DATA_CLUSTER {
            fat32_free_chain(old_cluster);
        }
        journal_barrier().map_err(|()| FsError::Io)?;

        let committed = JournalEntry { state: JOURNAL_COMMITTED, ..journal };
        fat32_journal_write(&committed).map_err(|()| FsError::Io)?;
        fat32_journal_clear().map_err(|()| FsError::Io)?;
        // Held until the clear is durable, as in `write_file_journaled`.
        if defer { let _ = defer_free(old_cluster, entry.size); }

        entry.first_cluster = 0;
        entry.size = 0;
        entry.dirty = true;
    }

    // APPEND positions at end-of-file on open.
    if flags & open_flags::APPEND != 0 {
        entry.pos = entry.size;
    }

    alloc_handle(entry)
}

/// Read up to `buf.len()` bytes starting at the file's current position.
/// Returns the number of bytes actually read (0 at EOF).
pub fn fat32_read(file: Fat32File, buf: &mut [u8]) -> Result<usize, FsError> {
    let mut e = snapshot_handle(file)?;
    if e.flags & open_flags::READ == 0 { return Err(FsError::InvalidArg); }
    if e.pos >= e.size || buf.is_empty() { return Ok(0); }

    // One lock for the whole geometry: `sector_index < spc` below is only
    // provable if `bytes_per_clus == spc * 512` was read atomically. Three
    // separate locks let a concurrent (re)mount interleave and break that.
    let (bytes_per_clus, spc, data_start) = {
        let v = FAT32.lock();
        (v.bytes_per_clus, v.secs_per_clus, v.data_start)
    };
    if bytes_per_clus == 0 { return Err(FsError::NotMounted); }

    let max = (e.size - e.pos) as usize;
    let mut remaining = buf.len().min(max);
    let mut written = 0usize;

    while remaining > 0 {
        let cluster_index = e.pos / bytes_per_clus;
        let offset_in_cluster = (e.pos % bytes_per_clus) as usize;
        let cluster = chain_nth(e.first_cluster, cluster_index)?;
        let first_sector = cluster_first_sector(data_start, cluster, spc)
            .ok_or(FsError::Io)?;

        // offset_in_cluster < bytes_per_clus == spc * 512, so
        // sector_index < spc, and cluster_first_sector proved
        // first_sector + spc fits in u32 — this add cannot overflow.
        let sector_index = (offset_in_cluster / SECTOR_SIZE) as u32;
        let offset_in_sector = offset_in_cluster % SECTOR_SIZE;
        let sec_num = first_sector + sector_index;

        let mut sec_buf = [0u8; SECTOR_SIZE];
        read_sector(sec_num, &mut sec_buf).map_err(|()| FsError::Io)?;

        let avail_in_sector = SECTOR_SIZE - offset_in_sector;
        let chunk = remaining.min(avail_in_sector);
        buf[written..written + chunk]
            .copy_from_slice(&sec_buf[offset_in_sector..offset_in_sector + chunk]);

        written += chunk;
        remaining -= chunk;
        e.pos += chunk as u32;
    }

    // Persist updated position back into the slot.
    with_handle(file, |slot| {
        slot.pos = e.pos;
        Ok(())
    })?;
    Ok(written)
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
pub fn fat32_write(file: Fat32File, buf: &[u8]) -> Result<usize, FsError> {
    if buf.is_empty() { return Ok(0); }

    let mut e = snapshot_handle(file)?;
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
        let v = FAT32.lock();
        (v.bytes_per_clus, v.secs_per_clus, v.data_start)
    };
    if bytes_per_clus == 0 { return Err(FsError::NotMounted); }

    // Ensure we have at least one cluster allocated (for empty files).
    let before = e;
    let mut fresh_first = None;
    if e.first_cluster < FAT32_FIRST_DATA_CLUSTER {
        let fresh = fat32_alloc_cluster().map_err(|()| FsError::NoSpace)?;
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
        zero_fill_range(e.first_cluster, e.size, e.pos, bytes_per_clus, spc, data_start)
    } else {
        Ok(())
    }
    .and_then(|()| write_loop(&mut e, buf, &mut written, bytes_per_clus, spc, data_start));

    // Nothing landed and the chain was started by this call: hand the chain
    // back and leave the handle as it was. Kept, it would be allocated and
    // named by nothing until a later write or close happened to record it.
    if outcome.is_err() && written == 0 {
        if let Some(fresh) = fresh_first {
            fat32_free_chain(fresh);
            e = before;
        }
    }
    // Persist updated size/position/dirty/first_cluster back into the slot —
    // also after a failure, so what reached the device is counted.
    with_handle(file, |slot| {
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
    e: &mut OpenFileEntry,
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
                chain_nth_or_extend(c, 1)?,
            _ => chain_nth_or_extend(e.first_cluster, cluster_index)?,
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
            read_sector(sec_num, &mut sec_buf).map_err(|()| FsError::Io)?;
        } else if offset_in_sector != 0 {
            // Past current size but starting mid-sector — read to preserve
            // whatever junk is there (treated as zeros after size extension).
            read_sector(sec_num, &mut sec_buf).map_err(|()| FsError::Io)?;
            // Zero the tail beyond current size so stale bytes don't leak.
            for b in &mut sec_buf[offset_in_sector..] { *b = 0; }
        }

        let avail_in_sector = SECTOR_SIZE - offset_in_sector;
        let chunk = (buf.len() - written_now).min(avail_in_sector);
        sec_buf[offset_in_sector..offset_in_sector + chunk]
            .copy_from_slice(&buf[written_now..written_now + chunk]);
        write_sector(sec_num, &sec_buf).map_err(|()| FsError::Io)?;

        *written += chunk;
        e.pos += chunk as u32;
        if e.pos > e.size { e.size = e.pos; }
        e.dirty = true;
    }
    Ok(())
}

/// Seek within an open file.  Seeking past EOF is allowed but will NOT
/// allocate clusters until a write happens.
pub fn fat32_seek(file: Fat32File, whence: SeekFrom) -> Result<u32, FsError> {
    with_handle(file, |e| {
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
pub fn fat32_fsync(file: Fat32File) -> Result<(), FsError> {
    let snapshot = snapshot_handle(file)?;
    if !snapshot.dirty { return Ok(()); }
    match order_barrier() {
        Ok(()) | Err(FsError::Unsupported) => {}
        Err(e) => return Err(e),
    }
    dir_update_meta(
        snapshot.dir_sector,
        snapshot.dir_offset,
        snapshot.first_cluster,
        snapshot.size,
    )?;
    let _ = journal_settle();
    device_flush()?;
    wb_take_error()?;
    with_handle(file, |e| { e.dirty = false; Ok(()) })
}

/// Close an open file handle.  Implicitly fsyncs if the file is dirty.
///
/// The handle is released whatever happens (a descriptor is gone after
/// `close`, as in POSIX), but the implicit `fsync`'s verdict is the result:
/// until wave 11 this returned `Ok` even when the entry write or the flush
/// had failed, so a caller that checked `close` could not learn that the
/// data it had written was not durable (fsyncgate).
pub fn fat32_close(file: Fat32File) -> Result<(), FsError> {
    let synced = fat32_fsync(file);
    with_handle(file, |e| {
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
pub fn fat32_release(file: Fat32File) -> Result<(), FsError> {
    let snapshot = snapshot_handle(file)?;
    let r = if snapshot.dirty && wb_active() && !cfg!(feature = "fw-entry-per-write-canary") {
        dir_update_meta_in(snapshot.dir_sector, snapshot.dir_offset,
            snapshot.first_cluster, snapshot.size, true)
    } else if snapshot.dirty {
        match order_barrier() {
            Ok(()) | Err(FsError::Unsupported) => dir_update_meta(
                snapshot.dir_sector, snapshot.dir_offset, snapshot.first_cluster, snapshot.size),
            Err(e) => Err(e),
        }
    } else {
        Ok(())
    };
    with_handle(file, |e| {
        e.in_use = false;
        e.dirty = false;
        e.pos = 0;
        e.size = 0;
        e.first_cluster = 0;
        Ok(())
    })?;
    r
}

/// Return `(position, size)` for an open file.  Useful for tests.
pub fn fat32_file_stat(file: Fat32File) -> Result<(u32, u32), FsError> {
    with_handle(file, |e| Ok((e.pos, e.size)))
}

// ── Directories: opendir / readdir / mkdir ───────────────────────────────────

/// Open a directory by absolute path (`b"/"` for root).  Returns an iterator
/// that yields each non-deleted, non-LFN, non-volume-ID entry.
pub fn fat32_opendir(_vol: Volume, path: &[u8]) -> Result<Fat32DirIter, FsError> {
    if !fat32_mounted() { return Err(FsError::NotMounted); }
    let mut comps: [&[u8]; FAT32_MAX_PATH_DEPTH] = [&[]; FAT32_MAX_PATH_DEPTH];
    let n = split_path(path, &mut comps)?;
    let root_cluster = FAT32.lock().root_cluster;
    let mut dir_cluster = root_cluster;
    for i in 0..n {
        let name83 = component_to_83(comps[i]).ok_or(FsError::InvalidArg)?;
        let loc = dir_find_in(dir_cluster, &name83)?;
        if loc.attr & ATTR_DIRECTORY == 0 { return Err(FsError::WrongType); }
        if loc.first_cluster < FAT32_FIRST_DATA_CLUSTER { return Err(FsError::NotFound); }
        dir_cluster = loc.first_cluster;
    }
    Ok(Fat32DirIter {
        cluster: dir_cluster,
        sector_in_cluster: 0,
        entry_in_sector: 0,
        done: false,
        clusters_walked: 0,
    })
}

impl Fat32DirIter {
    /// Return the next valid directory entry, or `None` at end.
    pub fn next(&mut self) -> Option<DirEntryInfo> {
        if self.done { return None; }
        let (spc, data_start, fat_sz32, data_clusters) = {
            let v = FAT32.lock();
            (v.secs_per_clus, v.data_start, v.fat_sz32, v.data_clusters)
        };
        let limit = chain_walk_limit(fat_sz32, data_clusters);
        loop {
            if self.cluster < FAT32_FIRST_DATA_CLUSTER || self.cluster >= FAT32_EOC {
                self.done = true;
                return None;
            }
            // Cycle guard — see `chain_walk_limit` and `clusters_walked`.
            // Counted at the advance below, so re-entering `next()` on the
            // same cluster does not consume budget.
            if self.clusters_walked >= limit {
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
                if read_sector(sec_num, &mut buf).is_err() {
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
            self.clusters_walked = self.clusters_walked.saturating_add(1);
            self.cluster = match fat32_next_cluster(self.cluster) {
                Ok(n) => n,
                Err(()) => { self.done = true; return None; }
            };
        }
    }
}

/// Create a new subdirectory at `path`.  The parent directory must exist.
/// Writes `.` (self) and `..` (parent) entries into the new directory.
pub fn fat32_mkdir(_vol: Volume, path: &[u8]) -> Result<(), FsError> {
    if !fat32_mounted() { return Err(FsError::NotMounted); }
    let (parent_cluster, last) = resolve_parent(path)?;
    let name83 = component_to_83(last).ok_or(FsError::InvalidArg)?;

    // Fail if an entry already exists.
    if dir_find_in(parent_cluster, &name83).is_ok() { return Err(FsError::Exists); }

    // Allocate a cluster for the new directory and zero every sector.
    let new_clus = fat32_alloc_cluster().map_err(|()| FsError::NoSpace)?;
    let (spc, data_start) = {
        let v = FAT32.lock();
        (v.secs_per_clus, v.data_start)
    };
    let first_sector = match cluster_first_sector(data_start, new_clus, spc) {
        Some(v) => v,
        None => { fat32_free_chain(new_clus); return Err(FsError::Io); }
    };
    let mut buf = [0u8; SECTOR_SIZE];
    // '.' entry -> new_clus itself.
    let mut dot_name = [b' '; 11];
    dot_name[0] = b'.';
    write_dirent_into_buf(&mut buf, 0, &dot_name, new_clus, 0, DIRENT_ATTR_SUBDIR);
    // '..' entry -> parent cluster (root stored as 0 per FAT32 convention).
    let root_cluster = FAT32.lock().root_cluster;
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
    if write_sector(first_sector, &buf).is_err() {
        fat32_free_chain(new_clus);
        return Err(FsError::Io);
    }
    // Zero remaining sectors in the cluster so iteration terminates.
    let zero = [0u8; SECTOR_SIZE];
    for s in 1..spc {
        // s < spc, and cluster_first_sector proved first_sector + spc fits.
        if write_sector(first_sector + s, &zero).is_err() {
            fat32_free_chain(new_clus);
            return Err(FsError::Io);
        }
    }

    // Insert dirent for the new dir into the parent.
    match dir_insert(parent_cluster, &name83, new_clus, 0, DIRENT_ATTR_SUBDIR) {
        Ok(_) => Ok(()),
        Err(e) => {
            // Roll back: free the allocated cluster.
            fat32_free_chain(new_clus);
            Err(e)
        }
    }
}

// Provide a const constructor to let callers build a Volume handle without
// going through `fat32_mount_volume` — useful in tests that mount via the
// legacy `fat32_mount()` API.
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
/// Zero-sized on purpose: the volume state is the module's `FAT32` static and
/// its lock, so this is a handle to it, not a second copy. A future
/// multi-volume FAT32 would carry a volume index here and nothing in
/// `vfs.rs` would change.
pub struct Fat32Fs;

/// The 8.3 name is eleven bytes; the generic key must hold it. Checked here,
/// where the requirement is, rather than asserted in `vfs.rs`, where the
/// number would be a FAT32 constant wearing a generic name.
const _: () = assert!(11 <= crate::vfs::INODE_KEY_LEN);

impl crate::vfs::FileSystem for Fat32Fs {
    #[inline]
    fn fs_type(&self) -> u32 { crate::vfs::FS_TYPE_FAT32 }

    #[inline]
    fn mount(&self) -> Result<(), ()> { fat32_mount() }

    #[inline]
    fn sync(&self) -> Result<(), ()> { fat32_sync() }

    /// 8.3 conversion plus the root-directory-only restriction.
    ///
    /// Both used to sit in `vfs.rs`: a byte-for-byte copy of
    /// `path_to_83_local` below, and an open-coded
    /// `sub.is_empty() || sub.contains(&b'/')`. Neither is a property of a
    /// filesystem in general; both are properties of this one.
    #[inline]
    fn key_for(&self, name: &[u8]) -> Option<crate::vfs::InodeKey> {
        // Root-directory files only (no subdirectories yet).
        if name.is_empty() || name.contains(&b'/') { return None; }
        let name83 = path_to_83_local(name)?;
        let mut bytes = [0u8; crate::vfs::INODE_KEY_LEN];
        bytes[..11].copy_from_slice(&name83);
        Some(crate::vfs::InodeKey { bytes })
    }

    /// One directory scan, whose result carries the start cluster forward as
    /// the opaque cookie so `read_all` does not scan again.
    #[inline]
    ///
    /// Since RFC-0048 P2 it also reports what the entry holds: directory or
    /// file, read-only (`0444` instead of `0644`), and the DOS write, create
    /// and access stamps as Unix seconds (local time, as FAT stores it; 0
    /// for a stamp of 0).
    fn stat(&self, key: &crate::vfs::InodeKey) -> Option<crate::vfs::FileStat> {
        let name83: [u8; 11] = key.bytes[..11].try_into().ok()?;
        let e = fat32_lookup_root_entry(&name83).ok()?;
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
        // The cookie is the start cluster `stat` already found. The key is not
        // needed, and using it would cost a second scan of the same directory.
        fat32_read_chain(st.cookie, dst)
    }

    #[inline]
    fn write_all(&self, key: &crate::vfs::InodeKey, src: &[u8]) -> Result<(), ()> {
        let name83: [u8; 11] = key.bytes[..11].try_into().map_err(|_| ())?;
        // Queued under write-back (wave 15): a close is not a durability
        // point; `fsync` (below, `fat32_sync_checked`) is.
        fat32_write_file_queued(&name83, src)
    }

    /// Deletes the directory entry and then frees the cluster chain, which
    /// is what `fat32_unlink_path` does (see its doc for why in that order)
    /// — the same operation, entered with a key instead of a raw filename.
    #[inline]
    fn unlink(&self, key: &crate::vfs::InodeKey) -> Result<(), ()> {
        let name83: [u8; 11] = key.bytes[..11].try_into().map_err(|_| ())?;
        let cluster = fat32_lookup_root(&name83).map(|(c, _)| c).unwrap_or(0);
        fat32_unlink_root(&name83)?;
        if cluster >= 2 { fat32_free_chain(cluster); }
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
    /// fsync, then `rename` over the live name (`fat32_rename`).
    #[inline]
    fn streaming(&self) -> bool { !cfg!(feature = "fat-proxy-writes-canary") }

    /// Read-only opens keep the read-handle path above.
    #[inline]
    fn ro_handles(&self) -> bool { true }

    /// The start cluster `stat` found, with the volume's write generation
    /// then (see `WRITE_GEN`).
    #[inline]
    fn read_handle(&self, cookie: u32) -> u64 {
        ((WRITE_GEN.load(core::sync::atomic::Ordering::Acquire) as u64) << 32) | cookie as u64
    }

    /// The file's identity under the volume's write epoch (wave 14,
    /// SPAWNCACHE): its start cluster and size, valid while no write of the
    /// volume (ours, an observed external one, a mount or an unmount) has
    /// happened since. `None` for a directory, an empty file, or a lookup a
    /// write overlapped.
    fn content_stamp(&self, key: &crate::vfs::InodeKey) -> Option<crate::vfs::ContentStamp> {
        let name83: [u8; 11] = key.bytes[..11].try_into().ok()?;
        let epoch = fat32_write_epoch();
        let e = fat32_lookup_root_entry(&name83).ok()?;
        if e.attr & ATTR_DIRECTORY != 0 || e.cluster < 2 || e.size == 0 {
            return None;
        }
        if fat32_write_epoch() != epoch {
            return None;
        }
        Some(crate::vfs::ContentStamp {
            fs: crate::vfs::STAMP_FS_FAT32, epoch, id: e.cluster as u64, size: e.size as u64,
        })
    }

    /// One root-entry lookup, none of `stat`'s date conversions.
    #[inline]
    fn stat_brief(&self, key: &crate::vfs::InodeKey) -> Option<(u64, bool, u32)> {
        let name83: [u8; 11] = key.bytes[..11].try_into().ok()?;
        let e = fat32_lookup_root_entry(&name83).ok()?;
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
        let offset = match u32::try_from(offset) { Ok(o) => o, Err(_) => return 0 };
        let gen = WRITE_GEN.load(core::sync::atomic::Ordering::Acquire);
        if (handle >> 32) as u32 == gen && size <= u32::MAX as u64 {
            return fat32_read_range(handle as u32, size as u32, offset, dst);
        }
        let name83: [u8; 11] = match key.bytes[..11].try_into() { Ok(v) => v, Err(_) => return 0 };
        match fat32_lookup_root_entry(&name83) {
            Ok(e) if e.attr & ATTR_DIRECTORY == 0 => fat32_read_range(e.cluster, e.size, offset, dst),
            _ => 0,
        }
    }

    /// Streams through the file-level API (`fat32_open`/`fat32_seek`/
    /// `fat32_read`/`fat32_close`) instead of `read_all`'s whole-chain walk
    /// from cluster 0: `fat32_seek` positions past the leading clusters
    /// without reading them, and `fat32_read` copies only `dst.len()` bytes
    /// from there — no buffer sized to the whole file is ever allocated.
    #[inline]
    fn read_at(&self, key: &crate::vfs::InodeKey, offset: u64, dst: &mut [u8]) -> usize {
        // FAT32 files end below 4 GiB; an offset past that is past EOF.
        let offset = match u32::try_from(offset) { Ok(o) => o, Err(_) => return 0 };
        let name83: [u8; 11] = match key.bytes[..11].try_into() {
            Ok(v)  => v,
            Err(_) => return 0,
        };
        let mut path_buf = [0u8; 13];
        let n = name83_to_path(&name83, &mut path_buf);
        let file = match fat32_open(Volume { _private: () }, &path_buf[..n], open_flags::READ) {
            Ok(f)  => f,
            Err(_) => return 0,
        };
        let n_read = if fat32_seek(file, SeekFrom::Start(offset)).is_ok() {
            fat32_read(file, dst).unwrap_or(0)
        } else {
            0
        };
        let _ = fat32_close(file);
        n_read
    }

    /// Streams through the same file-level API: `fat32_write` does a
    /// sector-granular read-modify-write at the seeked position (extending
    /// the cluster chain as needed via `chain_nth_or_extend`), never a
    /// whole-file rewrite. `CREATE` is set so a first `write_at` on a file
    /// that exists only as an `InodeKey` (no dirent yet) still lands.
    #[inline]
    fn write_at(&self, key: &crate::vfs::InodeKey, offset: u64, src: &[u8]) -> Result<usize, ()> {
        let offset = u32::try_from(offset).map_err(|_| ())?;
        let name83: [u8; 11] = key.bytes[..11].try_into().map_err(|_| ())?;
        let mut path_buf = [0u8; 13];
        let n = name83_to_path(&name83, &mut path_buf);
        let t0 = crate::census::now();
        let file = fat32_open(
            Volume { _private: () },
            &path_buf[..n],
            open_flags::WRITE | open_flags::CREATE,
        ).map_err(|_| ())?;
        let t1 = crate::census::now();
        crate::census::add(crate::census::W_LOOKUP, t0, t1);
        let result = match fat32_seek(file, SeekFrom::Start(offset)) {
            Ok(_)  => fat32_write(file, src).map_err(|_| ()),
            Err(_) => Err(()),
        };
        let t2 = crate::census::now();
        crate::census::add(crate::census::W_DATA, t1, t2);
        // The directory entry follows the data and the FAT chain in a later
        // epoch (`fat32_release`); no flush — `fsync` is the durability
        // point (`FileSystem::fsync`, `fat32_sync_checked`).
        let released = fat32_release(file);
        crate::census::add(crate::census::W_ENTRY, t2, crate::census::now());
        match (result, released) {
            (Ok(n), Ok(())) => Ok(n),
            _ => Err(()),
        }
    }

    // ── RFC-0048 P2 ──────────────────────────────────────────────────────
    //
    // FAT32 stays a PROXY backend for every open that may write
    // (`streaming` keeps its default `false`): that open/close behaviour, and
    // every gate row built on it, is unchanged. Since wave 14 a READ-ONLY
    // open streams instead (`stream_reads`, above). What it gains is the part of the new surface it can honour
    // with code it already has; the rest answers `Unsupported`.

    /// An empty file through the journaled whole-file write, only when no
    /// entry exists (that write would otherwise truncate).
    fn create(&self, key: &crate::vfs::InodeKey) -> Result<(), crate::vfs::FsErr> {
        let name83: [u8; 11] = key.bytes[..11].try_into().map_err(|_| crate::vfs::FsErr::Invalid)?;
        if fat32_lookup_root(&name83).is_ok() { return Ok(()); }
        // Queued under write-back, like `write_all`: durable at fsync/sync.
        fat32_write_file_queued(&name83, &[]).map_err(|()| crate::vfs::FsErr::Io)
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
        let t0 = crate::census::now();
        let r = (|| -> Result<(), crate::vfs::FsErr> {
            use crate::vfs::FsErr;
            let name83: [u8; 11] = key.bytes[..11].try_into().map_err(|_| FsErr::Invalid)?;
            let e = fat32_lookup_root_entry(&name83).map_err(|()| FsErr::NotFound)?;
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
                let (sector, off) = fat32_find_dirent_location(&name83).map_err(|()| FsErr::Io)?;
                let ahead = defer_frees() && !cfg!(feature = "fw-entry-per-write-canary");
                dirent_clus_size_in(sector, off, 0, 0, ahead).map_err(|()| FsErr::Io)?;
                if e.cluster >= FAT32_FIRST_DATA_CLUSTER {
                    if defer_frees() {
                        defer_free(e.cluster, e.size).map_err(fs_err)?;
                    } else {
                        order_barrier().or_else(|e| if e == FsError::Unsupported { Ok(()) } else { Err(e) })
                            .map_err(fs_err)?;
                        fat32_free_chain(e.cluster);
                    }
                }
                return Ok(());
            }
            let len = u32::try_from(len).map_err(|_| FsErr::NoSpace)? as usize;
            let mut buf = alloc::vec::Vec::new();
            buf.try_reserve_exact(len).map_err(|_| FsErr::NoSpace)?;
            buf.resize(len, 0u8);
            let keep = len.min(e.size as usize);
            if keep > 0 && fat32_read_chain(e.cluster, &mut buf[..keep]) != keep {
                return Err(FsErr::Io);
            }
            fat32_write_file_queued(&name83, &buf).map_err(|()| FsErr::Io)
        })();
        crate::census::add(crate::census::TRUNC, t0, crate::census::now());
        r
    }

    /// An empty root-directory subdirectory: its dirent is removed first
    /// (journaled, as `unlink`'s is) and its chain freed after, so a cut
    /// leaves at worst a leaked chain, never a listed directory over free
    /// clusters. `NotEmpty` when it holds anything besides `.` and `..`,
    /// `NotDir` for a file. Root-directory names only, as `key_for`.
    fn rmdir(&self, name: &[u8]) -> Result<(), crate::vfs::FsErr> {
        use crate::vfs::FsErr;
        let key = self.key_for(name).ok_or(FsErr::Invalid)?;
        let name83: [u8; 11] = key.bytes[..11].try_into().map_err(|_| FsErr::Invalid)?;
        let e = fat32_lookup_root_entry(&name83).map_err(|()| FsErr::NotFound)?;
        if e.attr & ATTR_DIRECTORY == 0 { return Err(FsErr::NotDir); }
        if !fat32_dir_is_empty(e.cluster).map_err(|()| FsErr::Io)? { return Err(FsErr::NotEmpty); }
        fat32_unlink_root(&name83).map_err(|()| FsErr::Io)?;
        if e.cluster >= FAT32_FIRST_DATA_CLUSTER { fat32_free_chain(e.cluster); }
        Ok(())
    }

    /// Volume-wide: the journal is settled and the device flushed
    /// (`fat32_sync_checked`); FAT32 keeps no per-file dirty state here.
    fn fsync(&self, _key: &crate::vfs::InodeKey) -> Result<(), crate::vfs::FsErr> {
        fat32_sync_checked().map_err(fs_err)
    }

    fn mkdir(&self, name: &[u8]) -> Result<(), crate::vfs::FsErr> {
        fat32_mkdir(Volume { _private: () }, name).map_err(fs_err)
    }

    /// Root-directory 8.3 names only, as `fat32_rename` is.
    fn rename(&self, from: &[u8], to: &[u8]) -> Result<(), crate::vfs::FsErr> {
        let a = self.key_for(from).ok_or(crate::vfs::FsErr::Invalid)?;
        let b = self.key_for(to).ok_or(crate::vfs::FsErr::Invalid)?;
        let a: [u8; 11] = a.bytes[..11].try_into().map_err(|_| crate::vfs::FsErr::Invalid)?;
        let b: [u8; 11] = b.bytes[..11].try_into().map_err(|_| crate::vfs::FsErr::Invalid)?;
        fat32_rename(&a, &b)
    }

    fn statfs(&self) -> Result<crate::vfs::StatFs, crate::vfs::FsErr> {
        let (bpc, clusters) = {
            let v = FAT32.lock();
            if !v.mounted { return Err(crate::vfs::FsErr::NotFound); }
            (v.bytes_per_clus, v.data_clusters)
        };
        // Held chains (`defer_free`) count as free: the allocator flushes
        // and frees them rather than report the volume full.
        let free = (fat32_free_clusters().map_err(|()| crate::vfs::FsErr::Io)? as u64
            + fat32_held_clusters() as u64).min(clusters as u64);
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
        let mut it = fat32_opendir(Volume { _private: () }, dir).map_err(fs_err)?;
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
fn fat32_dir_is_empty(cluster: u32) -> Result<bool, ()> {
    let (spc, data_start, fat_sz32, data_clusters) = {
        let v = FAT32.lock();
        (v.secs_per_clus, v.data_start, v.fat_sz32, v.data_clusters)
    };
    let limit = chain_walk_limit(fat_sz32, data_clusters);
    let mut steps = 0u32;
    let mut c = cluster;
    while c >= FAT32_FIRST_DATA_CLUSTER && c < FAT32_EOC {
        if steps >= limit { return Err(()); }
        steps += 1;
        let first = cluster_first_sector(data_start, c, spc).ok_or(())?;
        for s in 0..spc {
            let mut buf = [0u8; SECTOR_SIZE];
            read_sector(first + s, &mut buf)?;
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
        c = fat32_next_cluster(c).unwrap_or(FAT32_EOC);
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

/// Bumped by every FAT entry write and every mount.
static FREE_GEN: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(1);
/// `(generation << 32) | free clusters`; valid while the generation matches.
static FREE_CACHE: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
/// Full FAT scans `statfs` has made (host tests read it; nothing else does).
pub static FREE_SCANS: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

fn free_count_invalidate() {
    FREE_GEN.fetch_add(1, core::sync::atomic::Ordering::AcqRel);
}

/// Free clusters in the first FAT: the cached count if no FAT entry changed
/// since it was taken, else a fresh scan.
fn fat32_free_clusters() -> Result<u32, ()> {
    use core::sync::atomic::Ordering;
    let gen = FREE_GEN.load(Ordering::Acquire);
    let c = FREE_CACHE.load(Ordering::Acquire);
    if (c >> 32) as u32 == gen {
        return Ok(c as u32);
    }
    let free = fat32_free_clusters_scan()?;
    FREE_SCANS.fetch_add(1, Ordering::Relaxed);
    if FREE_GEN.load(Ordering::Acquire) == gen {
        FREE_CACHE.store(((gen as u64) << 32) | free as u64, Ordering::Release);
    }
    Ok(free)
}

/// Free clusters in the first FAT, counted from the device (not through the
/// sector cache, so a `statfs` does not evict the hot sectors). FAT writes
/// are write-through, so the device is current.
fn fat32_free_clusters_scan() -> Result<u32, ()> {
    let (fat_start, fat_sz32, clusters) = {
        let v = FAT32.lock();
        if !v.mounted { return Err(()); }
        (v.fat_start, v.fat_sz32, v.data_clusters)
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
        if !SECTOR_CACHE.lock().peek(lba as u64, &mut buf) {
            azos_drv_block::blkdev::read_quiet(dev_lba(lba as u64), 1, &mut buf)?;
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

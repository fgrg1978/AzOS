// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Two probes live here.
//!
//! * [`probe_volume`]: what a partition holds (an azvol volume, a FAT32 volume,
//!   or neither), which the native-volume mount asks before it believes a
//!   topology row (`azvol/mount.rs`, `kernel/src/boot/azvol.rs`).
//! * [`inode_leak_probe`], the U09-1 QEMU/board proof: `MAX_FILES + 1`
//!   create+unlink cycles through the ramfs fallback path — the same path
//!   `sys_open(O_CREAT)` on any name outside `/fat`, followed by `sys_unlink`,
//!   drives from ring 3 (`handlers.rs:1088,1450` -> `vfs::vfs_open`'s create
//!   branch / `path_parent` + `dir_remove_entry`). The host test in
//!   `tests/host/fs-tests/src/lib.rs` (`inode_leak` module) proves the same
//!   property against a hand-built `FS` pool; this prints one line so the gate
//!   can also observe it on a live boot, not just on the host.
//!
//! The inode probe is opt-in via `feature = "fs-inode-probe"`
//! (`crates/fs/Cargo.toml`). Its one caller is a one-line hook in
//! `kernel/src/main.rs`'s boot path, delivered as a diff — `main.rs` is not
//! this front's file to edit directly.

#[cfg(feature = "fs-inode-probe")]
use crate::vfs;

// ─── Volume probe (L15) ───────────────────────────────────────────────────────
//
// What does a partition hold? The topology's `[volume.NAME]` row says a
// partition is an azvol volume; the row is the owner's statement, the bytes
// are the medium's, and a mount that believed the row without looking would
// hand a FAT32 volume, a blank partition or a stranger's data to the azvol
// engine. The probe reads the two places a superblock can be (blocks 0 and
// 64) and one FAT boot sector, and says which it is. It never writes and never
// formats: a blank partition is `Unknown` and the mount refuses it.

use super::azvol::layout::{Superblock, SB_SLOTS};
use super::azvol::{Error, BLOCK_SIZE};

/// What a partition's first blocks say it holds ([`probe_volume`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VolumeKind {
    /// An azvol superblock that checks out (magic, checksum, version, geometry
    /// derived from the block count): the volume's size in blocks and the
    /// newest valid copy's commit generation.
    Azvol { blocks: u64, generation: u64 },
    /// The azvol magic is there but no copy is usable: damaged, or a feature
    /// this build does not have. The error is the newest copy's.
    AzvolRefused(Error),
    /// A FAT32 boot sector (what the boot, latch and CRASH.LOG volume holds).
    Fat32,
    /// Neither: blank, or something else.
    Unknown,
}

/// A FAT32 BIOS parameter block, as far as telling it from other data needs:
/// the 0x55AA signature, a sector size and cluster size that are powers of
/// two in range, no fixed root directory and a 32-bit FAT size (the fields
/// FAT12/16 and exFAT use differently).
fn looks_like_fat32(s: &[u8]) -> bool {
    if s.len() < 512 || s[510] != 0x55 || s[511] != 0xAA {
        return false;
    }
    let bps = u16::from_le_bytes([s[11], s[12]]);
    let spc = s[13];
    let root_entries = u16::from_le_bytes([s[17], s[18]]);
    let fat16 = u16::from_le_bytes([s[22], s[23]]);
    let fat32 = u32::from_le_bytes([s[36], s[37], s[38], s[39]]);
    matches!(bps, 512 | 1024 | 2048 | 4096)
        && spc.is_power_of_two()
        && spc <= 128
        && root_entries == 0
        && fat16 == 0
        && fat32 != 0
}

/// Classify the medium behind `read`, which reads one azvol block (4096 bytes)
/// by number and answers whether it could. The newest of the two superblock
/// copies that decode wins, as the mount picks them.
pub fn probe_volume(read: &mut dyn FnMut(u64, &mut [u8]) -> bool) -> VolumeKind {
    let mut buf = alloc::vec![0u8; BLOCK_SIZE];
    let mut best: Option<Superblock> = None;
    let mut refused: Option<Error> = None;
    let mut fat = false;
    for (i, slot) in SB_SLOTS.iter().enumerate() {
        if !read(*slot, &mut buf) {
            continue;
        }
        if i == 0 {
            fat = looks_like_fat32(&buf);
        }
        match Superblock::decode(&buf) {
            Ok(sb) => {
                if best.is_none_or(|b| sb.generation >= b.generation) {
                    best = Some(sb);
                }
            }
            Err(Error::BadMagic) => {}
            Err(e) => refused = Some(e),
        }
    }
    match (best, refused) {
        (Some(sb), _) => VolumeKind::Azvol { blocks: sb.geo.block_count, generation: sb.generation },
        (None, Some(e)) => VolumeKind::AzvolRefused(e),
        (None, None) if fat => VolumeKind::Fat32,
        (None, None) => VolumeKind::Unknown,
    }
}

/// Run `MAX_FILES + 1` create/unlink cycles against the ramfs fallback.
///
/// Before the U09-1 fix, `inode_alloc` pre-counted the directory entry's
/// link (`link_count = 1` at alloc, `+1` again at `dir_add_entry`), so
/// `dir_remove_entry`'s single decrement on unlink never reached 0 and the
/// inode was never freed: the `(MAX_FILES + 1)`th cycle's `vfs_open` fails
/// with the pool exhausted. After the fix every cycle frees its inode and
/// all `MAX_FILES + 1` cycles complete. Either outcome is printed — this
/// probe never panics on failure, so a regression shows up as a grep-able
/// line instead of a silent hang.
#[cfg(not(feature = "fs-inode-probe"))]
pub fn inode_leak_probe() {}

#[cfg(feature = "fs-inode-probe")]
pub fn inode_leak_probe() {
    let mut t = vfs::ScratchFds::new();
    let mut completed = 0usize;
    let total = vfs::MAX_FILES + 1;

    for i in 0..total {
        let path = alloc::format!("/probe{i}");

        let fd = vfs::vfs_open(&mut t, path.as_bytes(), vfs::O_WRONLY | vfs::O_CREAT);
        if fd < 0 {
            azos_drv_sys::kprintln!(
                "[FS] inode probe: OPEN FAILED at cycle {} of {} — inode leak reproduced",
                i, total,
            );
            return;
        }
        vfs::vfs_close(&mut t, fd);

        // Mirrors `kernel/src/boot/seams.rs`'s `unlink()`: `path_parent` +
        // `dir_remove_entry`. `vfs.rs` has no `vfs_unlink` of its own.
        let (parent_idx, name) = vfs::path_parent(path.as_bytes());
        if parent_idx == vfs::NO_IDX || name.is_empty()
            || vfs::dir_remove_entry(parent_idx, name).is_err()
        {
            azos_drv_sys::kprintln!(
                "[FS] inode probe: UNLINK FAILED at cycle {} of {}",
                i, total,
            );
            return;
        }
        completed += 1;
    }

    azos_drv_sys::kprintln!(
        "[FS] inode probe: {} cycles, open still succeeds", completed,
    );
}

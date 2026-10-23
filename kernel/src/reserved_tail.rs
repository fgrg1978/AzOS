// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The reserved tail of the boot medium: the last [`TAIL_SECTORS`] sectors,
//! past the end of the filesystem, holding the board's secrets and records
//! one sector each (the brain-link key, the entropy seed, the device record,
//! the topology counter floor).
//!
//! U06-9/#30: the link key and the entropy seed used to be FAT32 files, and
//! anything on the FAT volume is reachable by whatever can write a file there.
//! The tail sits past the end of the filesystem, so no file write can reach
//! it; a card reader can.
//!
//! **The tail is touched only when it is ours.** An image built without the
//! headroom, or a card whose partition runs to the last sector, has
//! filesystem data where the tail would be: anyone who can write a file
//! there would choose the "key", and a rewrite of the seed would corrupt the
//! volume. [`read`] and [`write`] therefore refuse unless
//! `azos_crypto::entropy::seed_tail_check` finds no partition, no GPT backup and no FAT32
//! volume reaching the tail ([`verdict`]). A missing key or seed is safe; a
//! sector of filesystem data taken for one is not.
//!
//! Each sector carries its own magic, version and integrity tag, decoded by
//! its owner; this module only does the raw sector I/O.

use azos_crypto::entropy::{seed_tail_check, SeedTail};
use core::sync::atomic::{AtomicBool, Ordering};

/// Sectors reserved at the tail of the medium: 8 (4 KiB), one per record
/// with room to spare.
pub const TAIL_SECTORS: u32 = 8;

/// Sector assignment (offsets into the tail). One name per consumer so a
/// second one added later cannot silently collide with an existing sector by
/// picking the same literal; Kconfig `TOPOLOGY_FLOOR_SECTOR` names the
/// topology floor's.
///
/// The brain-link key, which is also the board's device seed (DICE, the
/// keystore, the volume keys): `azos_crypto::secure_channel`'s link-key
/// record, written from the host by `tools/link_key_provision.py`, never by
/// the kernel.
pub const LINK_KEY: u32 = 0;
/// U09-8 — the persisted entropy seed (owner decision 2026-09-26, V1.2):
/// refuse to derive session keys on an unseeded pool, but persist a seed
/// across boots so a board with no TRNG can be seeded from its second boot on.
/// Format: `azos_crypto::entropy::{seed_file_encode, seed_file_decode}`, one
/// sector, `SEED_FILE_BYTES` (73) meaningful:
///   offset 0    4   magic "SEED"
///   offset 4    1   version (1)
///   offset 5   64   seed bytes
///   offset 69   4   integrity tag (first 4 bytes of SHA-256(magic‖version‖seed))
/// A missing sector, bad magic/version, or tag mismatch is treated as "no
/// seed" (mix nothing) — never as zero bytes, which would credit a known,
/// attacker-guessable value as if it were entropy. At every boot
/// (`install_entropy_seed` in `kernel/src/boot/entropy.rs`) the seed is mixed into the pool —
/// credited only when no other source has seeded it — and a FRESH record drawn
/// from the pool replaces it before anything else can draw, so a recorded old
/// seed does not stay valid and a seed is never used twice. It is replaced
/// again at an orderly power-off or reboot, best-effort: a robot's power can
/// also just go away. A first seed for a board with no entropy device is
/// written from the host with `tools/seed_provision.py`.
pub const ENTROPY_SEED: u32 = 1;
/// Wave 11 — the device record: this device's id, which
/// a `CONFIG.SIG` v2 must name, and the lowest `CONFIG.SIG` counter still
/// accepted. Format: `azos_topology::device_record::DeviceRecord` (37
/// bytes meaningful). Written from the host by `tools/device_provision.py`
/// (floor 0) and by the kernel when it accepts a higher counter
/// (`boot::config_auth`). A USB host cannot address it; a card reader can
/// (only a hardware counter closes that).
pub const DEVICE: u32 = 2;

/// The medium's tail was found [`SeedTail::Clear`] once: nothing repartitions
/// the medium while the kernel runs, so the answer stands for the boot. Any
/// other verdict is not kept: it is asked again, in case the first ask came
/// before the block device or its partition table was up.
static CLEAR: AtomicBool = AtomicBool::new(false);

/// Whether the tail of this boot's medium is ours: `Clear` when no partition,
/// no GPT backup table and no FAT32 volume reaches it.
pub fn verdict() -> SeedTail {
    if CLEAR.load(Ordering::Acquire) {
        return SeedTail::Clear;
    }
    let cap = azos_drv_block::blkdev::capacity_sectors();
    if cap == 0 {
        return SeedTail::TooSmall;
    }
    let mut s0 = [0u8; 512];
    if azos_drv_block::blkdev::read(0, 1, &mut s0).is_err() {
        return SeedTail::UnknownLayout;
    }
    // The primary GPT header; read on every medium (one sector), looked at
    // only when sector 0 is a protective MBR. Unreadable: empty.
    let mut s1 = [0u8; 512];
    let s1: &[u8] = if azos_drv_block::blkdev::read(1, 1, &mut s1).is_ok() { &s1 } else { &[] };
    let mut parts = [(0u64, 0u64); 16];
    let mut np = 0usize;
    for i in 0..azos_drv_block::partition::count().min(parts.len() as u32) {
        if let Some(p) = azos_drv_block::partition::extent(i) {
            parts[np] = p;
            np += 1;
        }
    }
    let v = seed_tail_check(cap, u64::from(TAIL_SECTORS), &parts[..np], &s0, s1);
    if v == SeedTail::Clear {
        CLEAR.store(true, Ordering::Release);
    }
    v
}

/// The LBA of tail sector `offset`, when the tail is ours and `len` bytes fit
/// one sector.
fn lba(offset: u32, len: usize) -> Result<u64, ()> {
    if len > 512 || offset >= TAIL_SECTORS || verdict() != SeedTail::Clear {
        return Err(());
    }
    let cap = azos_drv_block::blkdev::capacity_sectors();
    Ok(cap - u64::from(TAIL_SECTORS) + u64::from(offset))
}

/// Read `out` (≤ 512 bytes, the start of one sector) from tail sector
/// `offset`. `Err` when the tail is not ours ([`verdict`]), `offset` is past
/// it, or the read fails.
pub fn read(offset: u32, out: &mut [u8]) -> Result<(), ()> {
    let lba = lba(offset, out.len())?;
    let mut sector = [0u8; 512];
    azos_drv_block::blkdev::read(lba, 1, &mut sector)?;
    out.copy_from_slice(&sector[..out.len()]);
    azos_crypto::ct::secure_zero(&mut sector);
    Ok(())
}

/// Write `data` (≤ 512 bytes) to tail sector `offset`, under the same refusals
/// as [`read`]. The rest of the sector is zero-filled, not left as whatever
/// the medium held, so a shorter write cannot leave a stale trailing fragment
/// of a longer previous value on disk.
pub fn write(offset: u32, data: &[u8]) -> Result<(), ()> {
    let lba = lba(offset, data.len())?;
    let mut sector = [0u8; 512];
    sector[..data.len()].copy_from_slice(data);
    azos_drv_block::blkdev::write(lba, 1, &sector)
}

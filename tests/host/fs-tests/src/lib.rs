// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host-side tests for `crates/fs/fs/src/fat32.rs` and `crates/fs/fs/src/vfs.rs`,
//! driven against hand-built volume images.
//!
//! Both files are the REAL ones, pulled with `#[path]`. `vfs.rs` joined them
//! on 2026-09-24 — see the `vfs` seam note below for what had been blocking
//! it — and with it the open/write/close path over a mounted backend, which
//! had no test of any kind and was losing the contents of every file reopened
//! with `O_CREAT|O_APPEND`.
//!
//! **WHY.** 2142 lines parsing structures that come from a disk, with no test
//! of any kind. A FAT32 volume is attacker-controlled input the moment the
//! robot accepts an SD card or an OTA image, and this kernel is
//! `panic = "abort"` with `overflow-checks = true`: one bad field is a board
//! reset, not an error. That is the same class already found in `ip.rs`, where
//! a crafted `total_length < ihl` produced a reversed range.
//!
//! The module is pulled in with `#[path]` against a `fs_test_drivers` shim
//! that provides an in-memory disk, so the **real** parser runs — not a
//! reimplementation of it. A test that hand-copies the logic it claims to
//! watch is the exact failure `tests/host/regression-tests/src/sched_tests.rs`
//! documents at length.

// The pulled `crates/fs/fs` sources name the driver class crates directly
// (`azos_drv_block::blkdev`, `azos_drv_sys::kprintln!`,
// `azos_drv_base::platform`); all three are the one host shim.
extern crate fs_test_drivers as azos_drv_block;
extern crate fs_test_drivers as azos_drv_sys;
extern crate fs_test_drivers as azos_drv_base;

// `dead_code` only, and only on the pulled module: this suite exercises the
// mount and read paths, so the write/journal/iterator halves of `fat32.rs` are
// legitimately unreferenced here. Silencing it narrowly keeps the project's
// "warnings are failures" rule intact for everything else — including this
// file's own code.
#[allow(dead_code)]
#[path = "../../../../crates/fs/fs/src/fat32.rs"]
mod fat32;

// The shared block cache (RFC-0048 P1). `fat32.rs` keeps its sector cache in
// one, so the seam needs it; `bcache_tests` below drives it directly against
// a recording device. `dead_code`: the write-back half is exercised only from
// the test module, not from the pulled FAT32 code.
#[allow(dead_code)]
#[path = "../../../../crates/fs/fs/src/bcache.rs"]
mod bcache;

// `vfs.rs` and `fat32.rs` call the `file-census` hooks (no-ops without the
// feature, which this suite never enables).
#[allow(dead_code)]
#[path = "../../../../crates/fs/fs/src/census.rs"]
mod census;

// The MBR/GPT parser the kernel scopes `Cap<Disk>` by (RFC-0048 P3). It
// lives in the driver crates (`crates/drivers/*`) (both the minter in `crates/core/ipc` and the check in
// `crates/core/syscall` reach it there) and names only `core`, so it is pulled
// here unmodified. `partition_tests` below feeds it hand-built and
// host-tool-built tables, valid and malformed.
//
// Pulled through the drivers shim, not with a second `#[path]` here: the
// FAT32 driver mounts from the table the kernel PUBLISHED, and a second copy
// of the file would be a second, separate table.
#[cfg(test)]
use azos_drv_block::partition;

// ── The `vfs` seam ───────────────────────────────────────────────
//
// `fat32.rs` ends with `impl crate::vfs::FileSystem for Fat32Fs` — its side of
// the one interface the three filesystems in `crates/fs/fs` share. This used to
// be a hand-written MIRROR of that trait, because the real `vfs.rs` could not
// be pulled: it opened with `use alloc::alloc::{...}`, and this suite inherits
// `[unstable] build-std = ["core", "alloc"]` from the repository's
// `.cargo/config.toml` (cargo config arrays are MERGED, so this crate's own
// `build-std = []` cannot switch it off), which puts a second `alloc` next to
// the one `std` carries:
//
//     error[E0152]: duplicate lang item in crate `alloc`: `owned_box`
//
// Renaming a host shim crate to `alloc` so the extern prelude satisfies the
// import fails one error later, for the same reason:
//
//     error[E0464]: multiple candidates for `rmeta` dependency `alloc`
//
// The fix was not in `vfs.rs` and not in a shim: this crate was the ONLY
// host-test crate in the tree without a `rust-toolchain.toml`. Every other one
// pins stable, which does not accept `-Z` and therefore skips build-std
// entirely. With that pin in place `extern crate alloc` is simply the
// sysroot's `alloc` — the one `std` already links — and the REAL `vfs.rs`
// compiles unmodified. The mirror is gone, and with it the whole class of
// "the mirror and the trait drifted apart".
extern crate alloc;

// `dead_code` for the same reason as `fat32`: this suite drives the open /
// write / close path, so the descriptor-table half of `vfs.rs` (dup, dup2,
// owner quotas) is legitimately unreferenced here.
#[allow(dead_code)]
#[path = "../../../../crates/fs/fs/src/vfs.rs"]
mod vfs;

// The rotation policy for `/fat/CRASH.LOG` (`kernel/src/panic.rs`'s crash
// black box). `dead_code` for the same reason as `fat32`/`vfs` above: every
// item here IS exercised, but only from the `#[cfg(test)]` module below, so
// the plain (non-test) build of this lib target sees no caller at all.
#[allow(dead_code)]
#[path = "../../../../crates/fs/fs/src/crash_log.rs"]
mod crash_log;

// The panic record kept in reserved RAM across a warm reboot
// (`kernel/src/pstore.rs` owns the region; this file is the format).
#[allow(dead_code)]
#[path = "../../../../crates/fs/fs/src/pstore.rs"]
mod pstore;

// tmpfs.rs, same pattern as fat32/vfs/crash_log above. Its only dependency
// beyond `alloc`/`core` is `azos_sync::SpinLock`, already satisfied by
// the same `cap_test_sync` shim `vfs.rs` uses — no new shim needed. Pulled
// so `TmpFs::read_at`/`write_at` (U09 §5 Q3) run against the REAL
// `tmpfs_read_at`/`tmpfs_write_at`, not a hand-copy of them.
#[allow(dead_code)]
#[path = "../../../../crates/fs/fs/src/tmpfs.rs"]
mod tmpfs;

// procfs, pulled the same way (wave 10) for its `FileSystem::key_for` rule:
// with the generic key widened to 64 bytes, procfs bounds its own keys, and
// `full_path` must not be driven past its buffer. Its generators read two
// platform constants and three page counters, which the drivers shim and the
// `shims/mm` stand-in provide.
#[allow(dead_code)]
#[path = "../../../../crates/fs/fs/src/procfs.rs"]
mod procfs;

// The on-disk names of the signed topology pair (`crates/core/topology/src/
// paths.rs`), pulled the same way so `topology_paths_on_a_real_volume` below
// opens the CONSTANTS a loader will use, not literals copied from them. The
// file is self-contained for exactly this reason; `#[cfg(test)]` because
// nothing outside that module reads it.
#[cfg(test)]
#[path = "../../../../crates/core/topology/src/paths.rs"]
mod topology_paths;

// The ML service's data files (`crates/core/abi/src/ml_srv.rs`, constants only),
// for the same row: the paths `userspace/services/mlsrv` opens, not copies of them.
#[cfg(test)]
#[path = "../../../../crates/core/abi/src/ml_srv.rs"]
#[allow(dead_code)]
mod ml_srv_paths;

#[cfg(test)]
mod image {
    pub const SECTOR: usize = 512;

    /// Offsets into the BPB, read off `Fat32Bpb` rather than counted by hand.
    /// Getting these wrong is how a conformance test ends up asserting its own
    /// arithmetic; four DNS/TCP checks in this repo failed that way first.
    pub const OFF_BYTES_PER_SEC: usize = 11;  // after jmp[3] + oem[8]
    pub const OFF_SEC_PER_CLUS:  usize = 13;
    pub const OFF_RSVD_SEC_CNT:  usize = 14;
    pub const OFF_NUM_FATS:      usize = 16;
    /// `BPB_TotSec32`. The builder left this ZERO until 2026-09-21, which no
    /// test noticed because nothing read it — the cluster-walk bound came
    /// from `fat_sz32` instead, which is exactly the attacker-controlled
    /// figure the audit found. `mkfs.fat` always writes it.
    pub const OFF_TOT_SEC32:     usize = 32;
    pub const OFF_FAT_SZ32:      usize = 36;
    pub const OFF_ROOT_CLUS:     usize = 44;
    // U09-9's row: the fields `validate_bpb` added checks for. `build()`
    // leaves them zeroed (a legal FAT32 volume), so a rejection test writes
    // one nonzero and a fresh `build()` call proves the check does not
    // reject everything.
    pub const OFF_ROOT_ENT_CNT:  usize = 17;
    pub const OFF_TOT_SEC16:     usize = 19;
    pub const OFF_FAT_SZ16:      usize = 22;
    pub const OFF_EXT_FLAGS:     usize = 40;
    pub const OFF_FS_VER:        usize = 42;
    pub const OFF_FS_INFO:       usize = 48;
    pub const OFF_BK_BOOT_SEC:   usize = 50;
    pub const OFF_BOOT_SIG:      usize = 510;

    pub struct Geom {
        pub spc: u8,
        pub rsvd: u16,
        pub num_fats: u8,
        pub fat_sz32: u32,
        pub root_clus: u32,
        pub total_sectors: usize,
    }

    impl Default for Geom {
        fn default() -> Self {
            // Deliberately small but legal: 1 sector per cluster keeps cluster
            // arithmetic checkable by hand, and 2 FATs is what mkfs writes.
            Geom { spc: 1, rsvd: 32, num_fats: 2, fat_sz32: 8,
                   root_clus: 2, total_sectors: 256 }
        }
    }

    /// Write a FAT entry (little-endian u32) into the first FAT.
    ///
    /// `fat_start` is `rsvd`, so entry `n` lives at
    /// `rsvd * SECTOR + n * 4`. Written out rather than computed inline
    /// because a wrong FAT offset produces a test that reads zeros and passes
    /// for the wrong reason.
    pub fn set_fat(img: &mut [u8], g: &Geom, cluster: u32, value: u32) {
        let off = (g.rsvd as usize) * SECTOR + (cluster as usize) * 4;
        img[off..off + 4].copy_from_slice(&value.to_le_bytes());
    }

    /// First sector of `cluster` in the data region, mirroring the driver's
    /// own `cluster_first_sector`: `data_start + (cluster - 2) * spc`.
    pub fn cluster_sector(g: &Geom, cluster: u32) -> usize {
        let data_start = g.rsvd as usize + (g.num_fats as usize) * (g.fat_sz32 as usize);
        data_start + ((cluster as usize) - 2) * (g.spc as usize)
    }

    /// Fill a cluster's first sector with a repeated byte.
    pub fn fill_cluster(img: &mut [u8], g: &Geom, cluster: u32, byte: u8) {
        let off = cluster_sector(g, cluster) * SECTOR;
        for b in img[off..off + SECTOR].iter_mut() { *b = byte; }
    }

    pub fn build(g: &Geom) -> Vec<u8> {
        let mut img = vec![0u8; g.total_sectors * SECTOR];
        img[0..3].copy_from_slice(&[0xEB, 0x58, 0x90]);
        img[3..11].copy_from_slice(b"MSWIN4.1");
        img[OFF_BYTES_PER_SEC..OFF_BYTES_PER_SEC + 2]
            .copy_from_slice(&512u16.to_le_bytes());
        img[OFF_SEC_PER_CLUS] = g.spc;
        img[OFF_RSVD_SEC_CNT..OFF_RSVD_SEC_CNT + 2]
            .copy_from_slice(&g.rsvd.to_le_bytes());
        img[OFF_NUM_FATS] = g.num_fats;
        // `total_sectors` already describes the image; it was simply never
        // written into the BPB, so the kernel could not derive a trustworthy
        // cluster count from it.
        img[OFF_TOT_SEC32..OFF_TOT_SEC32 + 4]
            .copy_from_slice(&(g.total_sectors as u32).to_le_bytes());
        img[OFF_FAT_SZ32..OFF_FAT_SZ32 + 4]
            .copy_from_slice(&g.fat_sz32.to_le_bytes());
        img[OFF_ROOT_CLUS..OFF_ROOT_CLUS + 4]
            .copy_from_slice(&g.root_clus.to_le_bytes());
        img[510] = 0x55; img[511] = 0xAA;
        img
    }
}

/// **One lock for the whole crate, not one per module.**
///
/// The shim disk, the mounted volume and the sector cache are all statics —
/// `fat32.rs` is a kernel singleton by design. A first version gave each test
/// module its own `SERIAL`, which serialises nothing between them: the two
/// modules then interleaved and a read-path test's image was still installed
/// when a mount test asserted a rejection. It passed anyway on the first runs,
/// which is exactly how this hides.
#[cfg(test)]
static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
fn serial() -> std::sync::MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(|e| e.into_inner())
}

/// `vfs::init()`, exactly once per test binary, shared across every test
/// module that needs the ramfs root ("/", "/dev", the three std device
/// files) to exist.
///
/// It has to be ONE `Once` for the whole crate, not one per module: `FS` is
/// a static, so `vfs::init()` runs against the same pool no matter which
/// module calls it first, and it `.expect()`s on adding `/dev` — a second
/// call panics. `vfs_open_close`'s own `vfs_once()` used to call
/// `vfs::init()` directly with a module-local `Once`; that was safe only
/// because it was the sole caller. `inode_leak` below needs the same root
/// without the FAT32 mount `vfs_once()` also sets up, so the `Once` moved
/// here instead of being duplicated.
#[cfg(test)]
fn vfs_root_once() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(vfs::init);
}

/// Simulate ejecting whatever medium is mounted and inserting a new one:
/// unmount first (if mounted), install `img` into the shim disk, then drop
/// every cached sector.
///
/// **Why the unmount matters now, and did not before.** `fat32_mount()`
/// early-outs when `mounted` is already true (U09-3 — the fix for
/// `fat32_mount_volume()` re-mounting and replaying the journal on every
/// log open). Every test in this crate shares ONE process-wide `FAT32`
/// static, so without an explicit unmount between images, every test after
/// the first "swap" silently kept the PREVIOUS volume's geometry — a
/// rejection test's bad BPB was never even parsed, and it passed by
/// accident (`Ok(())` from the early-out, not from validation). This is not
/// a test-only convenience: production has no automatic "the card changed"
/// detection either (U09-6), so a real remount needs exactly this sequence
/// — unmount, THEN mount the new medium — and modelling a swap as anything
/// less here would test a discipline nothing enforces.
#[cfg(test)]
fn swap_medium(img: Vec<u8>) {
    let _ = fat32::fat32_unmount(fat32::Volume::assume_mounted());
    fs_test_drivers::disk_load(img);
    // The BPB and the journal live in the first sectors; dropping more than
    // is strictly needed costs nothing and removes a source of doubt.
    for s in 0..64 { fat32::fat32_cache_invalidate(s); }
}

/// Run the rest of a test with the FAT32 cache in write-through mode, the
/// pre-wave-15 behaviour (the shim builds with Kconfig `FS_WRITEBACK` on).
/// For tests whose property is write-through's: a device write per FAT32
/// write, in program order, failing where it is issued. Restored on drop.
#[must_use]
pub struct WriteThrough;
pub fn write_through() -> WriteThrough {
    fat32::fat32_set_writeback(false).expect("switch to write-through");
    WriteThrough
}
impl Drop for WriteThrough {
    fn drop(&mut self) {
        let _ = fat32::fat32_set_writeback(true);
    }
}

#[cfg(test)]
mod mount_tests {
    use super::{fat32, image::*};
    use fs_test_drivers::disk_stats;

    /// Install an image AND drop the sector cache.
    ///
    /// **Without the invalidation these tests are worthless, and they said so
    /// loudly.** `read_sector` keeps an LRU sector cache; the first test mounts
    /// a good volume and caches sector 0, and every later `disk_load` then has
    /// its BPB ignored in favour of the cached one. Four rejection tests
    /// "failed" with `left: Ok(())` — the mount succeeding on a corrupt image
    /// — because they were never given the corrupt image at all. Each of them
    /// passed in isolation, which is precisely how this kind of contamination
    /// hides.
    ///
    /// Worth writing down beyond the test fix: the cache has no notion of the
    /// medium changing. `fat32_cache_invalidate` is per-sector and nothing
    /// calls it on mount, so swapping a card without unmounting would read the
    /// old volume's sectors. Not a defect for a robot with a soldered-in card,
    /// and not something to discover on the bench.
    use super::serial;

    fn load(img: Vec<u8>) {
        super::swap_medium(img);
    }

    #[test]
    fn mounts_a_well_formed_volume_and_reads_sector_zero() {
        let _g = serial();
        let g = Geom::default();
        load(build(&g));
        assert_eq!(fat32::fat32_mount(), Ok(()), "a legal BPB must mount");
        assert!(fat32::fat32_mounted());
        // The mount must actually have gone to the device: a mount that
        // succeeds without reading sector 0 is not parsing anything.
        let (reads, _) = disk_stats();
        assert!(reads >= 1, "mount read no sectors");
    }

    /// FAT32 fixes the logical sector at 512. `read_sector` copies into a
    /// `[u8; 512]`, so a BPB claiming 1024 would have the rest of the code
    /// deriving offsets that do not match the buffer it reads into.
    #[test]
    fn rejects_a_sector_size_other_than_512() {
        let _g = serial();
        let g = Geom::default();
        let mut img = build(&g);
        img[OFF_BYTES_PER_SEC..OFF_BYTES_PER_SEC + 2]
            .copy_from_slice(&1024u16.to_le_bytes());
        load(img);
        assert_eq!(fat32::fat32_mount(), Err(()));
    }

    /// `sec_per_clus` must be a power of two in 1..=128 (the FAT spec's own
    /// constraint). It is the multiplier in every cluster→sector conversion,
    /// so a crafted 0 divides the volume by nothing and a crafted 255 walks
    /// the arithmetic straight out of the data region.
    #[test]
    fn rejects_bogus_sectors_per_cluster() {
        let _g = serial();
        for bad in [0u8, 3, 5, 100, 255] {
            let g = Geom::default();
            let mut img = build(&g);
            img[OFF_SEC_PER_CLUS] = bad;
            load(img);
            assert_eq!(fat32::fat32_mount(), Err(()),
                       "sec_per_clus={} must be refused", bad);
        }
        // ...and every legal power of two still mounts, so the check above is
        // not passing by rejecting everything.
        for good in [1u8, 2, 4, 8, 16, 32, 64, 128] {
            let mut g = Geom::default();
            g.spc = good;
            load(build(&g));
            assert_eq!(fat32::fat32_mount(), Ok(()),
                       "sec_per_clus={} is legal and must mount", good);
        }
    }

    /// A zero FAT size means there is no allocation table to walk. Accepting
    /// it leaves `fat32_next_cluster` reading whatever sits where the FAT
    /// should be.
    #[test]
    fn rejects_a_zero_fat_size() {
        let _g = serial();
        let g = Geom::default();
        let mut img = build(&g);
        img[OFF_FAT_SZ32..OFF_FAT_SZ32 + 4].copy_from_slice(&0u32.to_le_bytes());
        load(img);
        assert_eq!(fat32::fat32_mount(), Err(()));
    }

    /// **The overflow the mount code guards with `checked_mul`.**
    /// `data_start = rsvd + num_fats * fat_sz32`, all u32. A crafted
    /// `num_fats = 255` with `fat_sz32 = 0xFFFF_FFFF` overflows, and under
    /// `overflow-checks = true` an unchecked multiply here is not a wrong
    /// number — it is a panic, and `panic = "abort"` makes that a board reset
    /// triggered by inserting a card.
    #[test]
    fn rejects_a_bpb_whose_geometry_overflows_u32() {
        let _g = serial();
        let g = Geom::default();
        let mut img = build(&g);
        img[OFF_NUM_FATS] = 255;
        img[OFF_FAT_SZ32..OFF_FAT_SZ32 + 4]
            .copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        load(img);
        assert_eq!(fat32::fat32_mount(), Err(()));
    }

    /// **`num_fats = 0` is not a volume, it is a lever on the cycle bound.**
    ///
    /// Audit finding 2026-09-21. Every other BPB check passes: with zero FAT
    /// copies `data_start == rsvd`, small and valid, while `fat_sz32` stays
    /// free to inflate `chain_walk_limit` (`fat_sz32 * 128`) toward
    /// `u32::MAX`. A self-cycling FAT entry then spins a chain walker about
    /// 4e9 times with every read served from the sector cache — no I/O to
    /// slow it, no yield — which is a hart wedged for minutes and a watchdog
    /// reset. On a robot that is a physical-safety event, reachable by
    /// writing a card.
    #[test]
    fn rejects_a_bpb_claiming_zero_fat_copies() {
        let _g = serial();
        let g = Geom::default();
        let mut img = build(&g);
        img[OFF_NUM_FATS] = 0;
        load(img);
        assert_eq!(fat32::fat32_mount(), Err(()));
    }

    /// A volume that claims no sectors has no data clusters, so every walk
    /// bound derived from it would be zero. Rejected at the mount rather than
    /// left to produce a bound that refuses every legitimate chain.
    #[test]
    fn rejects_a_bpb_claiming_zero_total_sectors() {
        let _g = serial();
        let g = Geom::default();
        let mut img = build(&g);
        img[OFF_TOT_SEC32..OFF_TOT_SEC32 + 4].copy_from_slice(&0u32.to_le_bytes());
        load(img);
        assert_eq!(fat32::fat32_mount(), Err(()));
    }

    /// **U09-9 — FAT12/16 rejection.** A genuine FAT32 volume always zeroes
    /// `root_ent_cnt`/`tot_sec16`/`fat_sz16` (the FAT spec's own "is this
    /// FAT32" test); a FAT12/16 BPB does not. Each is checked, and set
    /// separately, so one wrong offset cannot hide behind another.
    #[test]
    fn rejects_a_fat12_16_shaped_bpb() {
        let _g = serial();
        for off in [OFF_ROOT_ENT_CNT, OFF_TOT_SEC16, OFF_FAT_SZ16] {
            let g = Geom::default();
            let mut img = build(&g);
            img[off..off + 2].copy_from_slice(&1u16.to_le_bytes());
            load(img);
            assert_eq!(fat32::fat32_mount(), Err(()),
                       "a nonzero byte at offset {off} must be refused");
        }
    }

    /// **U09-9 — `fs_ver` and `ext_flags`.** This parser understands FAT32
    /// revision 0.0 only, and assumes every FAT copy mirrors every other
    /// (`ext_flags` bit 7 clear). Both fields are zero on a `build()`
    /// volume, so both checks are exercised as a positive-then-negative
    /// pair, same shape as `rejects_bogus_sectors_per_cluster`.
    #[test]
    fn rejects_an_unsupported_fs_version_or_disabled_mirroring() {
        let _g = serial();
        let g = Geom::default();
        let mut img = build(&g);
        img[OFF_FS_VER..OFF_FS_VER + 2].copy_from_slice(&1u16.to_le_bytes());
        load(img);
        assert_eq!(fat32::fat32_mount(), Err(()), "fs_ver=1 must be refused");

        let mut img = build(&g);
        img[OFF_EXT_FLAGS..OFF_EXT_FLAGS + 2].copy_from_slice(&0x0080u16.to_le_bytes());
        load(img);
        assert_eq!(fat32::fat32_mount(), Err(()), "ext_flags bit 7 (mirroring disabled) must be refused");
    }

    /// **U09-9 — the boot-sector signature.** Every field-level check above
    /// can coincidentally pass on non-FAT32 media (an all-zero sector
    /// passes `fs_ver`/`ext_flags`/`root_ent_cnt` for free); `0x55AA` at
    /// bytes 510-511 is the one whole-sector check the FAT spec itself
    /// defines.
    #[test]
    fn rejects_a_missing_boot_signature() {
        let _g = serial();
        let g = Geom::default();
        let mut img = build(&g);
        img[OFF_BOOT_SIG] = 0x00;
        load(img);
        assert_eq!(fat32::fat32_mount(), Err(()));
    }

    /// **U09-9 — `rsvd_sec_cnt` too small to hold the journal, and
    /// `fs_info`/`bk_boot_sec` colliding with it.** `mkfs.fat -F 32`'s
    /// default (`fs_info = 1`) WAS `JOURNAL_SECTOR` until the journal moved
    /// to sector 8; this pins the collision U09-9 named, at the new sector. `0xFFFF` in `fs_info` means "unused" and must
    /// still mount.
    #[test]
    fn rejects_a_reserved_region_that_collides_with_the_journal() {
        let _g = serial();
        // rsvd_sec_cnt == JOURNAL_SECTOR (8): no room for the journal at all.
        let mut g = Geom::default();
        g.rsvd = fat32::JOURNAL_SECTOR as u16;
        load(build(&g));
        assert_eq!(fat32::fat32_mount(), Err(()), "rsvd_sec_cnt=JOURNAL_SECTOR leaves no room for the journal");

        // fs_info aliases JOURNAL_SECTOR (mkfs.fat's default, 1, no longer does).
        let g = Geom::default();
        let mut img = build(&g);
        img[OFF_FS_INFO..OFF_FS_INFO + 2].copy_from_slice(&(fat32::JOURNAL_SECTOR as u16).to_le_bytes());
        load(img);
        assert_eq!(fat32::fat32_mount(), Err(()), "fs_info=JOURNAL_SECTOR collides with the journal");

        // bk_boot_sec aliases JOURNAL_SECTOR.
        let g = Geom::default();
        let mut img = build(&g);
        img[OFF_BK_BOOT_SEC..OFF_BK_BOOT_SEC + 2].copy_from_slice(&(fat32::JOURNAL_SECTOR as u16).to_le_bytes());
        load(img);
        assert_eq!(fat32::fat32_mount(), Err(()), "bk_boot_sec=JOURNAL_SECTOR collides with the journal");

        // fs_info == 0xFFFF means "unused" and must NOT be refused.
        let g = Geom::default();
        let mut img = build(&g);
        img[OFF_FS_INFO..OFF_FS_INFO + 2].copy_from_slice(&0xFFFFu16.to_le_bytes());
        load(img);
        assert_eq!(fat32::fat32_mount(), Ok(()), "fs_info=0xFFFF (unused) must still mount");
    }

    /// **U09-3 — mounting an already-mounted volume must not re-run journal
    /// recovery.** A device-read-count assertion does not discriminate this:
    /// `read_sector`'s own cache already suppresses a repeat read of sector
    /// 0, early-out or not. And a PENDING entry with any `op_type` OTHER
    /// than `OVERWRITE` is just discarded by recovery regardless of how many
    /// times it runs (the `ALLOC`-frees-a-live-cluster bug this suite's
    /// `a_hostile_pending_journal_entry_does_not_free_a_live_cluster` pins
    /// was already fixed by discarding, not by this front) — so the ONLY
    /// `op_type` recovery ACTS on, `OVERWRITE`, is the one that has to be
    /// used here to discriminate anything.
    ///
    /// Modelled: plant a PENDING `OVERWRITE` journal entry via `disk_poke`
    /// (bypassing this driver — standing in for a writer on ANOTHER hart
    /// having just written it) whose `fat_value` (the "old chain to free")
    /// names a cluster that is actually a DIFFERENT, live, unrelated file's
    /// chain — the exact shape of "freeing a chain a writer is about to
    /// link" the audit warns about, made concrete as "freeing a chain that
    /// is currently in use". If a redundant `fat32_mount()` replays it, that
    /// cluster gets freed; if the early-out fires, it does not.
    #[test]
    fn a_second_mount_while_already_mounted_does_not_replay_a_concurrent_overwrite() {
        let _g = serial();
        let g = Geom::default();
        let mut img = build(&g);
        const LIVE: u32 = 3;
        const EOC: u32 = 0x0FFF_FFFF;
        set_fat(&mut img, &g, LIVE, EOC);
        load(img);
        assert_eq!(fat32::fat32_mount(), Ok(()), "the first mount must succeed on a clean volume");

        // "JRNL", state=PENDING(1), op_type=OVERWRITE(5), cluster=4 (the
        // "new" chain — unused by this test), fat_value=LIVE (the chain
        // recovery would free), dir_sector=root's own sector (harmless to
        // overwrite an unused slot in), dir_offset=64 (third dirent slot,
        // unused by this fixture), size=999 (unchecked by this test).
        // `JournalEntry` is `#[repr(C)]`, not packed: offsets below follow
        // from `u32`/`u16` alignment after the 6-byte magic+state+op_type+pad
        // header, and are cross-checked by the RED run (wrong offsets would
        // make op_type parse as something other than OVERWRITE, and the
        // "replay" branch below would never execute even without the fix).
        let mut j = [0u8; SECTOR];
        j[0..4].copy_from_slice(b"JRNL");
        j[4] = 0x01;
        j[5] = 5;
        j[8..12].copy_from_slice(&4u32.to_le_bytes());
        j[12..16].copy_from_slice(&LIVE.to_le_bytes());
        j[16..20].copy_from_slice(&(cluster_sector(&g, 2) as u32).to_le_bytes());
        j[20..22].copy_from_slice(&64u16.to_le_bytes());
        j[24..28].copy_from_slice(&999u32.to_le_bytes());
        fs_test_drivers::disk_poke(fat32::JOURNAL_SECTOR as u64, &j);
        // Drop the cache line for `JOURNAL_SECTOR` ONLY — see the
        // note on the sibling test above for why this specific line, and
        // why sector 0's is deliberately left alone.
        fat32::fat32_cache_invalidate(fat32::JOURNAL_SECTOR);

        assert_eq!(fat32::fat32_mount(), Ok(()), "a second mount while mounted must still report success");

        let fat_sector = fs_test_drivers::disk_peek(g.rsvd as u64)
            .expect("the FAT sector is readable");
        let off = (LIVE as usize) * 4;
        let entry = u32::from_le_bytes([
            fat_sector[off], fat_sector[off + 1], fat_sector[off + 2], fat_sector[off + 3],
        ]) & 0x0FFF_FFFF;
        assert_eq!(entry, EOC,
                   "a redundant mount must not replay the planted OVERWRITE entry — the live, \
                    unrelated file's FAT entry must still read EOC, not freed");
    }

    /// **U09-6 — mount must not read sector 0 through the OLD cache after a
    /// medium swap.** Deliberately does NOT go through `swap_medium`/`load`
    /// (which manually invalidate as a test-harness safety net) — this
    /// calls `disk_load` directly with nothing invalidated by hand, so the
    /// ONLY thing that can drop the stale cache line is `fat32_mount`'s own
    /// `fat32_cache_invalidate_all`. If that call is missing, `read_sector`
    /// hits the line still holding the FIRST volume's sector 0 and never
    /// reaches the device a second time.
    #[test]
    fn mount_reads_a_swapped_medium_not_the_old_cache() {
        let _g = serial();
        let _ = fat32::fat32_unmount(fat32::Volume::assume_mounted());
        fs_test_drivers::disk_load(build(&Geom::default()));
        for s in 0..64 { fat32::fat32_cache_invalidate(s); }
        assert_eq!(fat32::fat32_mount(), Ok(()), "the first volume must mount");
        let _ = fat32::fat32_unmount(fat32::Volume::assume_mounted());

        // Swap the medium with NOTHING invalidated by hand. `disk_load`
        // installs a brand new shim `Disk` with its OWN read counter reset
        // to 0, so any nonzero count below can only come from a read
        // issued AFTER this swap — a cache hit on the line still holding
        // the first volume's sector 0 would leave it at 0 forever.
        fs_test_drivers::disk_load(build(&Geom::default()));
        assert_eq!(fat32::fat32_mount(), Ok(()), "the second volume must mount");
        let (reads_after_swap, _) = disk_stats();
        assert!(reads_after_swap > 0,
                "mount after a medium swap must read the device (sector 0 at least) — a hit \
                 on the stale cache line would leave the read count at 0");
    }

    /// **U09-10 — an OVERWRITE journal entry whose dirent does not match it
    /// must be discarded, not replayed.** `fat_value`/`cluster` name clusters
    /// and `dir_sector`/`dir_offset` name a dirent — all four come off LBA 1.
    /// This plants an entry naming a LIVE, unrelated file's cluster as the
    /// "old chain to free", but points `dir_sector`/`dir_offset` at an EMPTY
    /// dirent slot instead of that file's real one, so the dirent recovery
    /// reads shows neither `fat_value` nor `cluster` — the mismatch the fix
    /// checks for. Before the fix, recovery frees `fat_value` unconditionally.
    #[test]
    fn an_overwrite_entry_whose_dirent_does_not_match_is_discarded() {
        let _g = serial();
        let g = Geom::default();
        let mut img = build(&g);
        const LIVE: u32 = 3;
        const EOC: u32 = 0x0FFF_FFFF;
        set_fat(&mut img, &g, LIVE, EOC);
        super::vfs_backend::put_dirent(&mut img, &g, 0, b"LIVE    TXT", LIVE, 1);

        // "JRNL", state=PENDING(1), op_type=OVERWRITE(5), cluster=4 (unused),
        // fat_value=LIVE, dir_offset=64 (an EMPTY slot — NOT slot 0, where
        // LIVE's real dirent lives).
        let j = SECTOR;
        img[j..j + 4].copy_from_slice(b"JRNL");
        img[j + 4] = 0x01;
        img[j + 5] = 5;
        img[j + 8..j + 12].copy_from_slice(&4u32.to_le_bytes());
        img[j + 12..j + 16].copy_from_slice(&LIVE.to_le_bytes());
        img[j + 16..j + 20].copy_from_slice(&(cluster_sector(&g, 2) as u32).to_le_bytes());
        img[j + 20..j + 22].copy_from_slice(&64u16.to_le_bytes());
        img[j + 24..j + 28].copy_from_slice(&999u32.to_le_bytes());
        load(img);

        assert!(fat32::fat32_mount().is_ok(), "the volume itself is well formed");

        let fat_sector = fs_test_drivers::disk_peek(g.rsvd as u64)
            .expect("the FAT sector is readable");
        let entry = u32::from_le_bytes([
            fat_sector[12], fat_sector[13], fat_sector[14], fat_sector[15],
        ]) & 0x0FFF_FFFF;
        assert_eq!(entry, EOC,
                   "a mismatched OVERWRITE entry must not free the cluster it names — LIVE's \
                    FAT entry must still read EOC");
    }

    /// **A hostile journal must not move a single FAT byte.**
    ///
    /// Audit finding 2026-09-21. `fat32_journal_recover` runs automatically
    /// inside the mount and used to honour a PENDING entry with
    /// `op_type == JOURNAL_OP_ALLOC` by writing 0 over that cluster's FAT
    /// entry — in every FAT copy, before userspace exists. LBA 1 is inside
    /// the volume an adversary rewrites, so the cluster was theirs to choose:
    /// naming a cluster of a live file freed it, deterministically, on every
    /// boot, and the next allocation crossed two chains.
    ///
    /// No production path ever writes `ALLOC` (the writers use `WRITE_DIR`
    /// and `UNLINK`), so the only possible author of such an entry was the
    /// attacker. This plants exactly that entry and asserts the FAT is
    /// untouched.
    #[test]
    fn a_hostile_pending_journal_entry_does_not_free_a_live_cluster() {
        let _g = serial();
        let g = Geom::default();
        let mut img = build(&g);
        // Cluster 3 belongs to a live single-cluster file: its FAT entry is
        // end-of-chain. That is what the attacker wants zeroed.
        const LIVE: u32 = 3;
        const EOC: u32 = 0x0FFF_FFFF;
        set_fat(&mut img, &g, LIVE, EOC);
        // LBA 1: "JRNL", state = PENDING(1), op_type = ALLOC(1), cluster = 3.
        let j = SECTOR;
        img[j..j + 4].copy_from_slice(b"JRNL");
        img[j + 4] = 0x01;
        img[j + 5] = 1;
        img[j + 8..j + 12].copy_from_slice(&LIVE.to_le_bytes());
        load(img);

        assert!(fat32::fat32_mount().is_ok(), "the volume itself is well formed");

        // The FAT sector as the DEVICE holds it after the mount.
        let fat_sector = fs_test_drivers::disk_peek(g.rsvd as u64)
            .expect("the FAT sector is readable");
        let entry = u32::from_le_bytes([
            fat_sector[LIVE as usize * 4],
            fat_sector[LIVE as usize * 4 + 1],
            fat_sector[LIVE as usize * 4 + 2],
            fat_sector[LIVE as usize * 4 + 3],
        ]);
        assert_eq!(
            entry, EOC,
            "the mount freed a live cluster on the say-so of an attacker-written journal",
        );
    }

    /// A device that cannot be read must fail the mount, not mount an empty
    /// volume. `disk_fail_after(0)` fails the very first read.
    #[test]
    fn a_failing_device_fails_the_mount() {
        let _g = serial();
        load(build(&Geom::default()));
        fs_test_drivers::disk_fail_after(0);
        assert_eq!(fat32::fat32_mount(), Err(()));
    }
}

#[cfg(test)]
mod read_path {
    use super::{fat32, image::*};

    use super::serial;

    /// Mount an image via `swap_medium` (unmount + load + drop the sector
    /// cache) — see its doc: without the unmount, `fat32_mount`'s U09-3
    /// early-out would keep the PREVIOUS image's geometry across tests.
    fn mount(img: Vec<u8>) {
        super::swap_medium(img);
        assert_eq!(fat32::fat32_mount(), Ok(()), "the fixture must mount");
    }

    /// A two-cluster chain reads back both clusters in order. Without this the
    /// rejection tests below would all pass on a reader that returns nothing.
    #[test]
    fn a_valid_chain_reads_its_clusters_in_order() {
        let _g = serial();
        let g = Geom::default();
        let mut img = build(&g);
        // 3 -> 4 -> EOC, with distinguishable contents.
        set_fat(&mut img, &g, 3, 4);
        set_fat(&mut img, &g, 4, 0x0FFF_FFFF);
        fill_cluster(&mut img, &g, 3, 0xAA);
        fill_cluster(&mut img, &g, 4, 0xBB);
        mount(img);

        let mut out = [0u8; 1024];
        let n = fat32::fat32_read_chain(3, &mut out);
        assert_eq!(n, 1024, "two 512-byte clusters");
        assert!(out[..512].iter().all(|&b| b == 0xAA), "first cluster");
        assert!(out[512..].iter().all(|&b| b == 0xBB), "second, in order");
    }

    /// **A contiguous run of clusters is one device read (wave 14).** Sector
    /// by sector, a file cost one request per 512 bytes (the 8-line cache
    /// holds none of a file being streamed), and that is what every spawn
    /// paid for its image. The run 3..=6 is read at once; the jump to 9 starts
    /// a second run; the half-sector tail goes through the cache as before.
    /// The bytes must come back the same, in chain order.
    ///
    /// **Canary.** Feature `read-chain-sector-canary`: one request per
    /// sector, and the request bound fails.
    #[test]
    fn a_contiguous_run_is_read_in_one_device_request() {
        let _g = serial();
        let g = Geom::default();
        let mut img = build(&g);
        // 3 -> 4 -> 5 -> 6 -> 9 -> 10 -> EOC
        for (c, n) in [(3, 4), (4, 5), (5, 6), (6, 9), (9, 10), (10, 0x0FFF_FFFF)] {
            set_fat(&mut img, &g, c, n);
        }
        for (k, c) in [3u32, 4, 5, 6, 9, 10].into_iter().enumerate() {
            fill_cluster(&mut img, &g, c, 0x10 + k as u8);
        }
        mount(img);

        let mut out = [0u8; 5 * 512 + 256];
        let before = fs_test_drivers::disk_stats().0;
        let n = fat32::fat32_read_chain(3, &mut out);
        let reads = fs_test_drivers::disk_stats().0 - before;
        assert_eq!(n, out.len());
        for k in 0..5 {
            assert!(out[k * 512..(k + 1) * 512].iter().all(|&b| b == 0x10 + k as u8),
                    "cluster {k} in chain order");
        }
        assert!(out[5 * 512..].iter().all(|&b| b == 0x15), "the tail, from the cluster after 9");
        // Two runs, the tail's sector and the FAT sector: per sector it was
        // six data reads plus the FAT.
        assert!(reads <= 4, "{reads} device reads for two runs and a tail");
    }

    /// **A self-referential FAT entry must terminate the walk.**
    ///
    /// `FAT[3] = 3` is the cycle `chain_walk_limit` exists to stop, and the
    /// driver's own comment says why it is not merely slow: the FAT sector sits
    /// in the sector cache, so the spin does **no I/O and never yields** — it
    /// is a hard hang of whichever hart serviced a ring-3 `open()`. The volume
    /// is exported over USB mass storage, so anyone with physical access can
    /// write that entry.
    ///
    /// **Measured, not assumed:** removing the guard does *not* hang this test.
    /// `fat32_read_chain` also stops at `out_buf.len()`, so the caller's buffer
    /// bounds the walk on its own — the guard is the second line, and the one
    /// that matters for `fat32_lookup_root`, which walks a directory chain with
    /// no output buffer to run out of. A first version of this comment claimed
    /// the hang; disabling the guard produced a clean pass instead.
    #[test]
    fn a_self_referential_cluster_does_not_loop_forever() {
        let _g = serial();
        let g = Geom::default();
        let mut img = build(&g);
        set_fat(&mut img, &g, 3, 3);          // 3 -> 3
        fill_cluster(&mut img, &g, 3, 0xCC);
        mount(img);

        let mut out = [0u8; 4096];
        let n = fat32::fat32_read_chain(3, &mut out);
        assert!(n <= out.len(), "the walk must terminate within the buffer");
    }

    /// A two-cluster cycle — 3 -> 4 -> 3 — which a naive "did the cluster
    /// number repeat?" check misses because no single step repeats.
    #[test]
    fn a_multi_cluster_cycle_does_not_loop_forever() {
        let _g = serial();
        let g = Geom::default();
        let mut img = build(&g);
        set_fat(&mut img, &g, 3, 4);
        set_fat(&mut img, &g, 4, 3);          // back to the start
        mount(img);

        let mut out = [0u8; 4096];
        let n = fat32::fat32_read_chain(3, &mut out);
        assert!(n <= out.len());
    }

    /// **A cluster past the end of the FAT must not extend the walk.** A
    /// crafted directory entry can carry up to 0x0FFFFFFF; without
    /// `chain_walk_limit` the parser reads past the table and starts
    /// interpreting *file data* as FAT entries — an information leak, and a way
    /// to steer later walks anywhere on the medium.
    ///
    /// **The geometry here is doing real work.** A first version used the
    /// default `Geom` and asserted `n == 0` for clusters like 100_000. It
    /// passed — and would have passed on a kernel with no bounds at all,
    /// because those clusters map to sectors outside the 256-sector image and
    /// the *shim disk* refused the read. Verified by deleting the bound: the
    /// test stayed green.
    ///
    /// So `fat_sz32 = 1` shrinks the FAT to 128 entries while the image still
    /// holds ~220 clusters. Cluster 150 is therefore addressable on the medium
    /// but outside the table: the first cluster's data is read, and the walk
    /// must then stop because `fat32_next_cluster` refuses to look it up.
    #[test]
    fn a_cluster_beyond_the_fat_cannot_extend_the_walk() {
        let _g = serial();
        let mut g = Geom::default();
        g.fat_sz32 = 1;                  // 128 FAT entries, one sector
        let mut img = build(&g);
        // **Plant what the attack plants.** Past a one-sector FAT lies the
        // second FAT copy and then file data — all attacker-controlled on a
        // volume exported over USB. Leaving it zero makes an unbounded walk
        // stop by accident (entry 0 < first data cluster), and the test then
        // passes with the guard deleted. Verified: it did. So the out-of-table
        // slot for cluster 150 gets a plausible cluster number, and only the
        // bound can stop the walk.
        //
        // Entry 150 would live at FAT sector `rsvd + 150/128` = rsvd+1, byte
        // offset `(150 % 128) * 4` = 88.
        let planted = (g.rsvd as usize + 1) * SECTOR + 88;
        img[planted..planted + 4].copy_from_slice(&4u32.to_le_bytes());
        set_fat(&mut img, &g, 4, 0x0FFF_FFFF);
        fill_cluster(&mut img, &g, 4, 0xEE);
        mount(img);
        let mut out = [0u8; 4096];
        let n = fat32::fat32_read_chain(150, &mut out);
        assert!(n <= (g.spc as usize) * SECTOR,
                "cluster 150 is outside a 128-entry FAT; the walk must stop \
                 after its own data, got {n} bytes");
    }

    /// Values at or past the end-of-chain marker are terminators, not data.
    #[test]
    fn an_end_of_chain_value_reads_nothing() {
        let _g = serial();
        mount(build(&Geom::default()));
        let mut out = [0u8; 512];
        for eoc in [0x0FFF_FFF8u32, 0x0FFF_FFFF] {
            assert_eq!(fat32::fat32_read_chain(eoc, &mut out), 0,
                       "{eoc:#x} is an end-of-chain marker");
        }
    }

    /// Clusters 0 and 1 are reserved and are not data. Accepting them would
    /// have `cluster - 2` underflow, which `checked_sub` turns into a refusal
    /// rather than a wrap to the top of the address space.
    #[test]
    fn the_reserved_clusters_are_not_readable() {
        let _g = serial();
        mount(build(&Geom::default()));
        let mut out = [0u8; 512];
        assert_eq!(fat32::fat32_read_chain(0, &mut out), 0);
        assert_eq!(fat32::fat32_read_chain(1, &mut out), 0);
    }

    /// The read must stop at the caller's buffer, not at the chain's end: a
    /// chain longer than the buffer is normal for a large file read in pieces.
    #[test]
    fn the_read_stops_at_the_output_buffer() {
        let _g = serial();
        let g = Geom::default();
        let mut img = build(&g);
        set_fat(&mut img, &g, 3, 4);
        set_fat(&mut img, &g, 4, 5);
        set_fat(&mut img, &g, 5, 0x0FFF_FFFF);
        fill_cluster(&mut img, &g, 3, 0x11);
        mount(img);

        let mut small = [0u8; 100];
        let n = fat32::fat32_read_chain(3, &mut small);
        assert_eq!(n, 100, "must fill exactly the buffer");
        assert!(small.iter().all(|&b| b == 0x11));
    }

    /// Looking up a name in an empty root must fail cleanly rather than
    /// walking off the directory cluster.
    #[test]
    fn a_lookup_in_an_empty_root_fails_cleanly() {
        let _g = serial();
        let g = Geom::default();
        let mut img = build(&g);
        set_fat(&mut img, &g, 2, 0x0FFF_FFFF);   // root cluster, end of chain
        mount(img);
        assert!(fat32::fat32_lookup_root(b"NOSUCH  TXT").is_err());
    }
}

#[cfg(test)]
mod write_path {
    //! Host tests for the write-path audit (2026-09-23): `fat32_alloc_cluster`
    //! and its callers, directory-entry allocation, and the sparse-hole gap
    //! in `fat32_write`. See `fat32.rs` for the fixes these pin.

    use super::{fat32, image::*};
    use super::serial;

    fn mount(img: Vec<u8>) {
        super::swap_medium(img);
        assert_eq!(fat32::fat32_mount(), Ok(()), "the fixture must mount");
    }

    /// **Finding A, verified CLOSED — not a bug, and now a fact instead of a
    /// comment.** `fat32_alloc_cluster` scans clusters in ascending order,
    /// and `fat32_write_fat_entry` (called with `?`) refuses to mark any
    /// cluster `>= chain_walk_limit(fat_sz32, data_clusters)`. Every
    /// in-range cluster number (2..limit) sorts below every out-of-range
    /// one, so the scan always exhausts the legitimate range before it can
    /// reach an illegitimate free entry: "no free cluster in range" and
    /// "the first free entry found is out of range" are the same event on
    /// this volume, and both correctly return `Err(())`.
    ///
    /// This test fills every in-range cluster (2..210) and leaves only the
    /// out-of-range tail (210..1024, `fat_sz32=8` gives 1024 FAT entries)
    /// free, then asserts the allocator refuses rather than handing one
    /// back.
    #[test]
    fn alloc_cluster_never_hands_out_a_cluster_past_the_data_region() {
        let _g = serial();
        let g = Geom::default(); // fat_sz32=8 -> 1024 entries; data_clusters=208
        let mut img = build(&g);
        for c in 2u32..210 { set_fat(&mut img, &g, c, 0x0FFF_FFFF); }
        mount(img);
        assert_eq!(
            fat32::fat32_alloc_cluster(),
            Err(()),
            "every in-range cluster (2..210) is used; the only free entries \
             left are past the data region and must not be handed out",
        );
    }

    /// **Finding B.** `dir_insert` — behind `fat32_open(CREATE)` and
    /// `fat32_mkdir` — used to terminate the directory only when the slot it
    /// just consumed had another slot after it in the SAME sector. With
    /// `spc=1` (one sector per cluster, as built here) every full cluster's
    /// last slot crosses into the NEXT cluster of the chain, so that case
    /// never applied and the terminator was never propagated at all. A
    /// directory chain longer than its logical content — root here: cluster
    /// 2 full of real entries, linked on disk to cluster 5 — then leaks
    /// whatever is physically on that next cluster into every later
    /// listing.
    #[test]
    fn dir_insert_terminates_across_a_cluster_boundary() {
        let _g = serial();
        let g = Geom::default();
        let mut img = build(&g);
        // Root directory chain: cluster 2 (full) -> cluster 5 (EOC).
        set_fat(&mut img, &g, 2, 5);
        set_fat(&mut img, &g, 5, 0x0FFF_FFFF);
        // Fill 15 of cluster 2's 16 slots with non-terminating, non-deleted
        // bytes, so dir_insert must reach the last slot before finding a
        // free one — slot 15 stays at the image's default zero (END),
        // which is exactly the slot the insert will consume.
        {
            let sec = cluster_sector(&g, 2) * SECTOR;
            for slot in 0..15usize {
                img[sec + slot * 32] = b'A'; // any non-0x00, non-0xE5 byte
            }
        }
        // Cluster 5 — already linked, never logically part of the
        // directory's content — carries a phantom entry that must stay
        // invisible.
        {
            let sec = cluster_sector(&g, 5) * SECTOR;
            img[sec..sec + 8].copy_from_slice(b"GHOST   ");
            img[sec + 8..sec + 11].copy_from_slice(b"GHO");
            img[sec + 11] = 0x20; // ATTR_ARCHIVE — a plausible file, not junk
        }
        mount(img);

        let vol = fat32::Volume::assume_mounted();
        fat32::fat32_open(
            vol, b"/NEWFILE.TXT",
            fat32::open_flags::CREATE | fat32::open_flags::WRITE,
        ).expect("root has a free (END) slot in cluster 2");

        let mut names: Vec<Vec<u8>> = Vec::new();
        let mut it = fat32::fat32_opendir(vol, b"/").expect("root must open");
        while let Some(ent) = it.next() {
            names.push(ent.name[..ent.name_len as usize].to_vec());
        }
        assert!(
            !names.iter().any(|n| n.starts_with(b"GHOST")),
            "cluster 5's phantom entry must not surface in a listing: {:?}",
            names.iter().map(|n| String::from_utf8_lossy(n).into_owned())
                 .collect::<Vec<_>>(),
        );
    }

    /// **Finding B, the worse sibling.** `fat32_creat_root_dirent` — behind
    /// `fat32_write_file` — propagated nothing at all, not even within the
    /// same sector: a single free (END) slot anywhere before the logical
    /// end of the directory left every later slot's leftover bytes exposed,
    /// no cluster boundary required.
    #[test]
    fn write_file_terminates_within_the_same_sector() {
        let _g = serial();
        let g = Geom::default();
        let mut img = build(&g);
        set_fat(&mut img, &g, 2, 0x0FFF_FFFF); // root: single cluster
        let sec = cluster_sector(&g, 2) * SECTOR;
        // Slots 0..4 used, slot 5 is END (default zero), slot 6 carries a
        // phantom entry that a same-sector propagation must blank out.
        for slot in 0..5usize { img[sec + slot * 32] = b'A'; }
        img[sec + 6 * 32..sec + 6 * 32 + 8].copy_from_slice(b"GHOST   ");
        img[sec + 6 * 32 + 8..sec + 6 * 32 + 11].copy_from_slice(b"GHO");
        img[sec + 6 * 32 + 11] = 0x20;
        mount(img);

        let mut name83 = [b' '; 11];
        name83[0..3].copy_from_slice(b"NEW");
        name83[8..11].copy_from_slice(b"TXT");
        assert_eq!(fat32::fat32_write_file(&name83, b"hi"), Ok(()));

        let mut names: Vec<Vec<u8>> = Vec::new();
        fat32::fat32_ls_root(|name, _size, _is_dir| names.push(name.to_vec()));
        assert!(
            !names.iter().any(|n| n.starts_with(b"GHOST")),
            "the phantom entry past the new file must not surface: {:?}",
            names.iter().map(|n| String::from_utf8_lossy(n).into_owned())
                 .collect::<Vec<_>>(),
        );
    }

    /// **Finding C — the big one, and the only one reachable on a wholly
    /// legitimate volume through nothing but the public API.** No
    /// adversarial image is needed: an ordinary file, an unlink, a second
    /// ordinary file, and a `seek` past its own end-of-file reproduce it.
    ///
    /// File A occupies two clusters of a recognizable pattern. Unlinking it
    /// frees both, in ascending order. File B's first (whole, aligned)
    /// write happens to zero its own first cluster as a side effect of the
    /// existing "nothing to preserve" fast path — that case was never
    /// buggy. What was buggy is the SECOND: seeking to file offset 600 and
    /// writing one byte lands `chain_nth_or_extend` on A's *second*
    /// cluster — still carrying A's pattern — at a **mid-sector** offset
    /// (88). The old code read that sector, zeroed only the tail from
    /// offset 88 onward, and left the head — file bytes [512, 600), the
    /// actual hole — as A's leftover 0x5A, not zero.
    #[test]
    fn a_seek_past_eof_hole_reads_as_zero_not_the_previous_tenants_data() {
        let _g = serial();
        let g = Geom::default();
        let mut img = build(&g);
        // The root cluster's own FAT entry defaults to 0 (free) in a bare
        // image; without terminating it, `fat32_alloc_cluster` can hand
        // cluster 2 back out as if it were unused, aliasing file A's data
        // cluster onto the root directory itself.
        set_fat(&mut img, &g, 2, 0x0FFF_FFFF);
        mount(img);
        let vol = fat32::Volume::assume_mounted();

        // File A: two clusters (spc=1 => 512 bytes each), a recognizable
        // non-zero pattern throughout.
        let fa = fat32::fat32_open(
            vol, b"/A.BIN",
            fat32::open_flags::CREATE | fat32::open_flags::WRITE,
        ).unwrap();
        let pattern = [0x5A_u8; 1024];
        assert_eq!(fat32::fat32_write(fa, &pattern), Ok(1024));
        fat32::fat32_close(fa).unwrap();
        fat32::fat32_unlink_path(b"A.BIN").unwrap(); // frees both clusters

        // File B: a single whole-sector write claims A's first cluster (and
        // is zeroed as a side effect of the existing fast path — not the
        // case under test). Seeking to 600 and writing one more byte reaches
        // into A's second cluster at offset 88 — mid-sector, not aligned —
        // which is exactly the shape that used to leak.
        let fb = fat32::fat32_open(
            vol, b"/B.BIN",
            fat32::open_flags::CREATE | fat32::open_flags::WRITE | fat32::open_flags::READ,
        ).unwrap();
        assert_eq!(fat32::fat32_write(fb, &[0x11u8; 512]), Ok(512));
        fat32::fat32_seek(fb, fat32::SeekFrom::Start(600)).unwrap();
        assert_eq!(fat32::fat32_write(fb, &[0x22]), Ok(1));

        // Read exactly the hole inside A's reused second cluster: file
        // offsets [512, 600) must be zero, not A's 0x5A pattern still
        // sitting on the disk it used to own.
        fat32::fat32_seek(fb, fat32::SeekFrom::Start(512)).unwrap();
        let mut hole = [0xFFu8; 88];
        assert_eq!(fat32::fat32_read(fb, &mut hole), Ok(88));
        assert!(
            hole.iter().all(|&b| b == 0),
            "the hole must read back as zero; got {:02x?} — A's leftover \
             0x5A cluster content leaking through B",
            hole,
        );
    }

    /// **The write-path audit's open finding (2026-09-23), closed.**
    ///
    /// `fat32_write_file`'s overwrite path used to free the old chain and
    /// unlink the old dirent BEFORE writing any journal record of the
    /// overwrite. A crash in that window left NOTHING on disk to say an
    /// overwrite had even been attempted — not a corrupted file, an
    /// *invisible* one: `fat32_journal_recover` would see an EMPTY journal
    /// (the old unlink's own PENDING/COMMITTED cycle had already cleared
    /// it) and do nothing, so the file was simply gone.
    ///
    /// This drives the real, public `fat32_write_file` end to end and
    /// injects a device-write failure at an exact, counted point: right
    /// after the new chain is fully allocated and written and the
    /// compound-overwrite journal entry becomes durable (4 writes: 2 FAT
    /// copies to mark the new cluster allocated, 1 data-cluster write, 1
    /// journal-sector write) — but before the old dirent is touched or the
    /// old chain is freed. That is the crash the fix's ordering targets:
    /// the journal record must exist before anything about the old file is
    /// disturbed.
    ///
    /// After the simulated crash, remounting must run recovery and produce
    /// a fully consistent NEW file — not lose it, not double-free the old
    /// chain, not leave a dangling FAT reference.
    #[test]
    fn overwrite_crash_after_journal_pending_recovers_the_new_file_instead_of_losing_it() {
        let _g = serial();
        let g = Geom::default(); // spc=1, num_fats=2, fat_sz32=8, rsvd=32
        let mut img = build(&g);
        set_fat(&mut img, &g, 2, 0x0FFF_FFFF); // root: single cluster, EOC
        mount(img);

        let mut name83 = [b' '; 11];
        name83[0..3].copy_from_slice(b"OVR");
        name83[8..11].copy_from_slice(b"TXT");

        // Original file.
        assert_eq!(fat32::fat32_write_file(&name83, b"OLD-DATA"), Ok(()));
        let (old_cluster, old_size) = fat32::fat32_lookup_root(&name83)
            .expect("the original file must exist before the overwrite");
        assert_eq!(old_size, 8);

        // Crash 4 writes into the overwrite -- see the doc comment above for
        // exactly which 4. The 5th write (the dirent update) never reaches
        // the device. `disk_write_fail_after` counts writes from `disk_load`,
        // not from this call, so the threshold must be offset by whatever
        // the original create above already spent.
        let (_, writes_before_overwrite) = fs_test_drivers::disk_stats();
        fs_test_drivers::disk_write_fail_after(writes_before_overwrite + 4);
        let new_data = b"NEW-CONTENT-LONGER";
        let result = fat32::fat32_write_file(&name83, new_data);
        assert!(result.is_err(), "the injected write failure must surface, not be swallowed");
        fs_test_drivers::disk_write_fail_clear();

        // "Reboot": a real reboot starts a fresh process with `mounted ==
        // false`, so `fat32_mount()`'s U09-3 early-out does not apply on
        // the very first mount after a crash. Modelled here the same way:
        // unmount (the medium itself is untouched — a crash does not
        // reformat the card) before the remount that runs
        // `fat32_journal_recover()`.
        let _ = fat32::fat32_unmount(fat32::Volume::assume_mounted());
        for s in 0..64 { fat32::fat32_cache_invalidate(s); }
        assert_eq!(fat32::fat32_mount(), Ok(()), "remount after the simulated crash");

        // **The file must still exist and be readable as the NEW content.**
        // Before the fix, this lookup fails (`Err(())`) -- the file is
        // simply gone, with no journal record to explain why. That is the
        // exact bug the audit named.
        let (final_cluster, final_size) = fat32::fat32_lookup_root(&name83)
            .expect(
                "the file must survive the crash -- losing it silently with \
                 no journal record is the audited bug this test pins",
            );
        assert_eq!(final_size, new_data.len() as u32, "recovery must finish installing the NEW size");
        assert_ne!(
            final_cluster, old_cluster,
            "the new chain was allocated (and the old one still marked used) \
             BEFORE the old chain was freed, so it can never collide with it",
        );

        let mut out = [0u8; 64];
        let n = fat32::fat32_read_chain(final_cluster, &mut out);
        assert_eq!(
            &out[..new_data.len().min(n)], new_data,
            "recovery must leave the NEW content readable, not a half-written \
             or stale cluster",
        );

        // The OLD chain must have been freed by recovery, not leaked forever
        // and not double-freed into corruption. Read the FAT entry directly
        // off the device, the way `a_hostile_pending_journal_entry_does_not_free_a_live_cluster`
        // already does.
        let fat_sector = (g.rsvd as u64) + (old_cluster as u64) / 128;
        let byte_off = ((old_cluster as usize) % 128) * 4;
        let sector = fs_test_drivers::disk_peek(fat_sector).expect("FAT sector must be readable");
        let old_entry = u32::from_le_bytes([
            sector[byte_off], sector[byte_off + 1], sector[byte_off + 2], sector[byte_off + 3],
        ]) & 0x0FFF_FFFF;
        assert_eq!(old_entry, 0, "the old chain must be freed by recovery, not leaked");

        // The journal itself must end up clean (EMPTY), not stuck PENDING --
        // otherwise the next mount would try to replay it again.
        let journal_sector = fs_test_drivers::disk_peek(fat32::JOURNAL_SECTOR as u64).expect("journal sector must be readable");
        assert_eq!(&journal_sector[0..4], b"JRNL", "journal magic must still be intact");
        assert_eq!(journal_sector[4], 0x00, "journal state must be EMPTY (cleared) after recovery");
    }

    /// **U09-13 — a crash between freeing the old chain and installing the
    /// truncated dirent must not leak (or cross-link) that chain.**
    /// `fat32_open(O_TRUNC)` used to free the chain first and update the
    /// dirent second, with no journal spanning the gap. Fixed to journal it
    /// the same way `fat32_write_file`'s overwrite path already does: PENDING
    /// -> dirent update -> free -> COMMITTED -> clear. This crashes AFTER
    /// the dirent update lands (durable: the file already reads as empty)
    /// but BEFORE the old chain's FAT entry is cleared, then proves recovery
    /// finishes the free on remount.
    #[test]
    fn truncate_crash_before_the_old_chain_is_freed_still_frees_it_on_recovery() {
        let _g = serial();
        let _wt = crate::write_through();
        let g = Geom::default(); // spc=1, num_fats=2, fat_sz32=8, rsvd=32
        let mut img = build(&g);
        set_fat(&mut img, &g, 2, 0x0FFF_FFFF); // root: single cluster, EOC
        mount(img);

        let mut name83 = [b' '; 11];
        name83[0..3].copy_from_slice(b"TRN");
        name83[8..11].copy_from_slice(b"TXT");
        assert_eq!(fat32::fat32_write_file(&name83, b"OLD-DATA"), Ok(()));
        let (old_cluster, old_size) = fat32::fat32_lookup_root(&name83)
            .expect("the file must exist before truncation");
        assert_eq!(old_size, 8);

        // Crash 2 writes into the truncate: journal PENDING (1) + the dirent
        // update (1) both land; `fat32_free_chain`'s first FAT-copy write
        // (the 3rd) never reaches the device.
        let (_, writes_before_trunc) = fs_test_drivers::disk_stats();
        fs_test_drivers::disk_write_fail_after(writes_before_trunc + 2);
        let vol = fat32::Volume::assume_mounted();
        let mut path = [0u8; 12];
        path[0] = b'/';
        path[1..4].copy_from_slice(b"TRN");
        path[4] = b'.';
        path[5..8].copy_from_slice(b"TXT");
        let open_result = fat32::fat32_open(
            vol, &path[..8], fat32::open_flags::WRITE | fat32::open_flags::TRUNCATE,
        );
        assert!(open_result.is_err(), "the injected write failure must surface, not be swallowed");
        fs_test_drivers::disk_write_fail_clear();

        // "Reboot": same reasoning as the overwrite-crash test above.
        let _ = fat32::fat32_unmount(fat32::Volume::assume_mounted());
        for s in 0..64 { fat32::fat32_cache_invalidate(s); }
        assert_eq!(fat32::fat32_mount(), Ok(()), "remount after the simulated crash");

        // The dirent already reads as empty (that write landed before the
        // crash) — recovery's job is only to finish freeing the old chain.
        let (cluster_after, size_after) = fat32::fat32_lookup_root(&name83)
            .expect("the dirent itself must survive — only its chain was mid-free");
        assert_eq!((cluster_after, size_after), (0, 0),
                   "the dirent must read as truncated (empty), which is what was durable \
                    before the crash");

        let fat_sector = (g.rsvd as u64) + (old_cluster as u64) / 128;
        let byte_off = ((old_cluster as usize) % 128) * 4;
        let sector = fs_test_drivers::disk_peek(fat_sector).expect("FAT sector must be readable");
        let old_entry = u32::from_le_bytes([
            sector[byte_off], sector[byte_off + 1], sector[byte_off + 2], sector[byte_off + 3],
        ]) & 0x0FFF_FFFF;
        assert_eq!(old_entry, 0,
                   "recovery must finish freeing the old chain — before the fix, a crash here \
                    left it marked used forever (a leak) with no journal record to reclaim it");
    }

    /// **`fat32_rename` — the OTA front's copy-verify-rename ask.** Renaming
    /// a staged file onto an EXISTING destination (the promotion shape:
    /// `STAGED.BIN` -> `KERNEL.BIN`, replacing the live image) must install
    /// the staged content at the destination's dirent, free the
    /// destination's OLD chain, and remove the source dirent — leaving
    /// exactly one file behind, under the destination name, with the
    /// staged content.
    #[test]
    fn rename_onto_an_existing_destination_replaces_it_and_removes_the_source() {
        let _g = serial();
        let _wt = crate::write_through();
        let g = Geom::default();
        mount(build(&g));

        let mut staged = [b' '; 11];
        staged[0..6].copy_from_slice(b"STAGED");
        staged[8..11].copy_from_slice(b"BIN");
        let mut kernel = [b' '; 11];
        kernel[0..6].copy_from_slice(b"KERNEL");
        kernel[8..11].copy_from_slice(b"BIN");

        assert_eq!(fat32::fat32_write_file(&kernel, b"OLD-KERNEL-IMAGE"), Ok(()));
        let (old_kernel_cluster, _) = fat32::fat32_lookup_root(&kernel).unwrap();
        assert_eq!(fat32::fat32_write_file(&staged, b"NEW-KERNEL"), Ok(()));
        let (staged_cluster, _) = fat32::fat32_lookup_root(&staged).unwrap();

        assert_eq!(fat32::fat32_rename(&staged, &kernel), Ok(()));

        let (final_cluster, final_size) = fat32::fat32_lookup_root(&kernel)
            .expect("the destination name must exist after rename");
        assert_eq!(final_cluster, staged_cluster, "the destination must now own the staged chain");
        assert_eq!(final_size, 10, "the destination's size must be the staged file's");
        let mut out = [0u8; 16];
        let n = fat32::fat32_read_chain(final_cluster, &mut out);
        assert_eq!(&out[..n.min(10)], b"NEW-KERNEL");

        assert_eq!(fat32::fat32_lookup_root(&staged), Err(()),
                   "the source name must no longer exist after rename");

        let fat_sector = (g.rsvd as u64) + (old_kernel_cluster as u64) / 128;
        let byte_off = ((old_kernel_cluster as usize) % 128) * 4;
        let sector = fs_test_drivers::disk_peek(fat_sector).unwrap();
        let old_entry = u32::from_le_bytes([
            sector[byte_off], sector[byte_off + 1], sector[byte_off + 2], sector[byte_off + 3],
        ]) & 0x0FFF_FFFF;
        assert_eq!(old_entry, 0, "the OLD destination chain must be freed, not leaked");
    }
}

/// **The FAT32 side of `vfs::FileSystem`.**
///
/// These are the operations the VFS used to open-code against `fat32_*` with
/// an 8.3 name it built itself. The naming rules moved into `key_for` and the
/// `stat`/`read_all` pair now carries the start cluster forward as an opaque
/// cookie, which is what keeps an open at ONE directory scan. Nothing asserted
/// either property before, in this suite or anywhere else.
#[cfg(test)]
mod vfs_backend {
    use super::{fat32, image::*, serial, vfs::FileSystem};

    fn mount(img: Vec<u8>) {
        super::swap_medium(img);
        assert_eq!(fat32::fat32_mount(), Ok(()), "the fixture must mount");
    }

    /// Write a root-directory entry by hand: 8.3 name, archive attr, start
    /// cluster split across the two halves FAT32 keeps it in, and a size.
    pub(super) fn put_dirent(img: &mut [u8], g: &Geom, slot: usize, name83: &[u8; 11],
                             cluster: u32, size: u32) {
        let off = cluster_sector(g, 2) * SECTOR + slot * 32;
        img[off..off + 11].copy_from_slice(name83);
        img[off + 11] = 0x20; // ATTR_ARCHIVE
        img[off + 20..off + 22].copy_from_slice(&((cluster >> 16) as u16).to_le_bytes());
        img[off + 26..off + 28].copy_from_slice(&((cluster & 0xFFFF) as u16).to_le_bytes());
        img[off + 28..off + 32].copy_from_slice(&size.to_le_bytes());
    }

    /// The 8.3 conversion that used to live in `vfs.rs` as a byte-for-byte
    /// copy of `fat32.rs`'s own: uppercased, space-padded, split at the dot.
    #[test]
    fn key_for_produces_the_space_padded_uppercase_8_3_name() {
        let k = fat32::Fat32Fs.key_for(b"config.ini").expect("a legal 8.3 name");
        assert_eq!(&k.bytes[..11], b"CONFIG  INI");
        assert!(k.bytes[11..].iter().all(|&b| b == 0), "FAT32 uses 11 bytes of the key");

        let k = fat32::Fat32Fs.key_for(b"hello").expect("no extension is legal");
        assert_eq!(&k.bytes[..11], b"HELLO      ");
    }

    /// **The root-directory-only restriction is the backend's, not the VFS's.**
    ///
    /// It used to be `sub.is_empty() || sub.contains(&b'/')` open-coded in
    /// `try_fat32_open` *and* again in `try_fat32_create`. A backend that
    /// supported subdirectories could not have said so.
    #[test]
    fn key_for_refuses_what_this_backend_cannot_name() {
        assert!(fat32::Fat32Fs.key_for(b"").is_none(), "empty");
        assert!(fat32::Fat32Fs.key_for(b"sub/file.txt").is_none(), "subdirectory");
        assert!(fat32::Fat32Fs.key_for(b"TOOLONGNAME.TXT").is_none(), "base > 8");
        assert!(fat32::Fat32Fs.key_for(b"NAME.TOOLONG").is_none(), "ext > 3");
    }

    /// `stat` then `read_all` returns the file's bytes, and `stat` reports the
    /// size from the directory entry rather than the cluster count.
    #[test]
    fn stat_then_read_all_returns_the_files_bytes() {
        let _g = serial();
        let g = Geom::default();
        let mut img = build(&g);
        set_fat(&mut img, &g, 2, 0x0FFF_FFFF);        // root: one cluster
        set_fat(&mut img, &g, 3, 0x0FFF_FFFF);        // data: one cluster
        fill_cluster(&mut img, &g, 3, 0xCD);
        put_dirent(&mut img, &g, 0, b"DATA    BIN", 3, 300);
        mount(img);

        let key = fat32::Fat32Fs.key_for(b"data.bin").expect("legal name");
        let st  = fat32::Fat32Fs.stat(&key).expect("the entry exists");
        assert_eq!(st.size, 300, "size comes from the directory entry");
        assert!(!st.is_dir);

        let mut out = [0u8; 512];
        let n = fat32::Fat32Fs.read_all(&key, &st, &mut out);
        assert_eq!(n, 512, "one whole cluster is read");
        assert!(out.iter().all(|&b| b == 0xCD));
    }

    /// **The cookie is the start cluster, and that is what stops the open
    /// costing two directory scans.**
    ///
    /// Asserted against a second file placed at a different cluster, so a
    /// `read_all` that ignored the cookie and re-looked-up by name would still
    /// pass — but one that carried the wrong cookie would not.
    #[test]
    fn read_all_follows_the_cookie_stat_produced() {
        let _g = serial();
        let g = Geom::default();
        let mut img = build(&g);
        set_fat(&mut img, &g, 2, 0x0FFF_FFFF);
        set_fat(&mut img, &g, 3, 0x0FFF_FFFF);
        set_fat(&mut img, &g, 4, 0x0FFF_FFFF);
        fill_cluster(&mut img, &g, 3, 0x11);
        fill_cluster(&mut img, &g, 4, 0x22);
        put_dirent(&mut img, &g, 0, b"ONE     BIN", 3, 512);
        put_dirent(&mut img, &g, 1, b"TWO     BIN", 4, 512);
        mount(img);

        let k2 = fat32::Fat32Fs.key_for(b"two.bin").expect("legal name");
        let s2 = fat32::Fat32Fs.stat(&k2).expect("the entry exists");
        assert_eq!(s2.cookie, 4, "the cookie is TWO.BIN's start cluster");

        let mut out = [0u8; 512];
        fat32::Fat32Fs.read_all(&k2, &s2, &mut out);
        assert!(out.iter().all(|&b| b == 0x22), "TWO.BIN's cluster, not ONE.BIN's");
    }

    /// A name the directory does not hold has no `stat`, which is how the VFS
    /// decides an open fails.
    #[test]
    fn stat_of_a_missing_file_is_none() {
        let _g = serial();
        let g = Geom::default();
        let mut img = build(&g);
        set_fat(&mut img, &g, 2, 0x0FFF_FFFF);
        mount(img);

        let key = fat32::Fat32Fs.key_for(b"absent.bin").expect("legal name");
        assert!(fat32::Fat32Fs.stat(&key).is_none());
    }

    /// The tag the VFS mount table stores for this backend.
    #[test]
    fn fs_type_is_the_fat32_tag() {
        assert_eq!(fat32::Fat32Fs.fs_type(), super::vfs::FS_TYPE_FAT32);
    }
}

/// **The VFS open/write/close path over a mounted backend.**
///
/// The three `vfs_backend` tests above check the FAT32 side of the seam in
/// isolation: `key_for`, `stat`, `read_all`. Nothing checked what `vfs_open`
/// and `vfs_close` DO with those calls, and that is where a file's contents
/// were being thrown away — `path_lookup` returns `NO_IDX` for every
/// backend-mounted path, so `O_CREAT` always took the create branch and built
/// an EMPTY proxy inode, and `vfs_close` then wrote that proxy over the whole
/// file. An `O_CREAT|O_APPEND` reopen therefore discarded everything already
/// in the file. `/fat/CRASH.LOG` is opened exactly that way by the panic
/// handler, so the log held one panic: the most recent.
#[cfg(test)]
mod vfs_open_close {
    use super::{crash_log, fat32, image::*, serial, vfs};
    use vfs::FileSystem as _;
    use fs_test_drivers::{disk_write_fail_after, disk_write_fail_clear};

    /// Where the FAT32 volume is mounted, matching `kernel/src/boot/seams.rs`.
    const MOUNT: &[u8] = b"/fat";

    /// `vfs::init()` and the mount happen ONCE per test binary.
    ///
    /// Both are one-shot by construction: `init()` `.expect()`s on adding
    /// `/dev` to the root and would panic the second time, and `vfs_mount`
    /// appends to a table of `MAX_MOUNTS = 4`. The ramfs inode pool is a
    /// static, like everything else in this suite, so `serial()` still
    /// orders the tests.
    pub(super) fn vfs_once() {
        super::vfs_root_once();
        static ONCE: std::sync::Once = std::sync::Once::new();
        ONCE.call_once(|| {
            vfs::vfs_mount(MOUNT, vfs::FS_TYPE_FAT32)
                .expect("the mount table has room for one volume");
        });
    }

    /// A blank, writable volume with the root cluster terminated.
    ///
    /// Without `set_fat(.., 2, EOC)` the root's own FAT entry reads as free
    /// and `fat32_alloc_cluster` hands cluster 2 back out, aliasing a file's
    /// data onto the root directory — the fixture bug `write_path` documents.
    pub(super) fn fresh_volume() {
        let g = Geom::default();
        let mut img = build(&g);
        set_fat(&mut img, &g, 2, 0x0FFF_FFFF);
        super::swap_medium(img);
        assert_eq!(fat32::fat32_mount(), Ok(()), "the fixture must mount");
        vfs_once();
    }

    /// What the FILE holds, read through the backend rather than back through
    /// the VFS.
    ///
    /// Deliberately an independent oracle: reading through a second
    /// `vfs_open` would exercise the same proxy machinery under test, so a
    /// bug that lost the file's bytes could hide behind a proxy that still
    /// had them. This asks the directory entry for the size and walks the
    /// cluster chain.
    pub(super) fn on_disk(name: &[u8]) -> Vec<u8> {
        use vfs::FileSystem;
        let key = fat32::Fat32Fs.key_for(name).expect("a legal 8.3 name");
        let st  = fat32::Fat32Fs.stat(&key).expect("the file exists on the volume");
        let mut buf = vec![0u8; (st.size as usize) + 1024];
        let n = fat32::Fat32Fs.read_all(&key, &st, &mut buf);
        buf.truncate(n.min(st.size as usize));
        buf
    }

    /// Open, write one record, close. The flags are the panic handler's.
    fn append_record(t: &mut vfs::ScratchFds, path: &[u8], rec: &[u8]) -> i32 {
        let fd = vfs::vfs_open(t, path, vfs::O_WRONLY | vfs::O_CREAT | vfs::O_APPEND);
        assert!(fd >= 0, "the append open must succeed");
        assert_eq!(
            vfs::vfs_write(t, fd, rec.as_ptr(), rec.len()),
            rec.len() as i32,
            "the whole record must be written",
        );
        vfs::vfs_close(t, fd)
    }

    /// **The bug that matters: a second `O_CREAT|O_APPEND` open must not
    /// erase the first panic.**
    ///
    /// `kernel/src/panic.rs` opens `/fat/CRASH.LOG` with exactly these flags
    /// on every panic. The file it appends to is the one a field failure is
    /// reconstructed from, and the record that explains a cascade is the
    /// FIRST one, not the last.
    #[test]
    fn an_append_open_of_an_existing_file_keeps_what_is_already_there() {
        let _g = serial();
        fresh_volume();
        let mut t = vfs::ScratchFds::new();

        assert_eq!(append_record(&mut t, b"/fat/CRASH.LOG", b"PANIC A\n"), 0);
        assert_eq!(on_disk(b"crash.log"), b"PANIC A\n", "the first record lands");

        assert_eq!(append_record(&mut t, b"/fat/CRASH.LOG", b"PANIC B\n"), 0);
        assert_eq!(
            on_disk(b"crash.log"), b"PANIC A\nPANIC B\n",
            "the second open must APPEND; if it truncates, the panic log only \
             ever holds the most recent panic",
        );
    }

    /// The same property stated as a length, so a readback that happened to
    /// return the right bytes for the wrong reason (a short read, a stale
    /// cached sector) still fails.
    #[test]
    fn the_directory_entry_grows_by_the_appended_length() {
        let _g = serial();
        fresh_volume();
        let mut t = vfs::ScratchFds::new();
        use vfs::FileSystem;

        append_record(&mut t, b"/fat/GROW.LOG", b"0123456789");
        let key = fat32::Fat32Fs.key_for(b"grow.log").unwrap();
        assert_eq!(fat32::Fat32Fs.stat(&key).unwrap().size, 10);

        append_record(&mut t, b"/fat/GROW.LOG", b"abcde");
        assert_eq!(
            fat32::Fat32Fs.stat(&key).unwrap().size, 15,
            "the size on disk must be first + second, not just the second",
        );
    }

    /// `O_CREAT|O_APPEND` on a file that does not exist still CREATES it.
    /// The fix must not turn the append open into an open-only.
    #[test]
    fn an_append_open_still_creates_a_file_that_is_not_there() {
        let _g = serial();
        fresh_volume();
        let mut t = vfs::ScratchFds::new();

        assert_eq!(append_record(&mut t, b"/fat/NEW.LOG", b"first ever\n"), 0);
        assert_eq!(on_disk(b"new.log"), b"first ever\n");
    }

    /// **A truncating open must keep truncating.**
    ///
    /// `O_WRONLY|O_CREAT|O_TRUNC` is what every other caller in the tree uses
    /// (the shell's redirect, `cp`, OTA's image writer, DFU recovery). If the
    /// append fix leaked into this path, a rewritten file would keep the tail
    /// of the longer file it replaced.
    #[test]
    fn a_truncating_open_still_truncates() {
        let _g = serial();
        fresh_volume();
        let mut t = vfs::ScratchFds::new();

        append_record(&mut t, b"/fat/CFG.INI", b"a-long-previous-content\n");
        assert_eq!(on_disk(b"cfg.ini").len(), 24);

        let fd = vfs::vfs_open(
            &mut t, b"/fat/CFG.INI",
            vfs::O_WRONLY | vfs::O_CREAT | vfs::O_TRUNC,
        );
        assert!(fd >= 0);
        assert_eq!(vfs::vfs_write(&mut t, fd, b"short\n".as_ptr(), 6), 6);
        assert_eq!(vfs::vfs_close(&mut t, fd), 0);

        assert_eq!(
            on_disk(b"cfg.ini"), b"short\n",
            "O_TRUNC must replace the file, not append to it",
        );
    }

    /// Bare `O_CREAT` — no `O_APPEND`, no `O_TRUNC` — on a backend path also
    /// truncates today, because the create branch is all there is. Nothing in
    /// the tree opens a file this way, so the two readings of "a truncating
    /// open" are indistinguishable in production; this pins the behaviour
    /// that was there before the fix so a later change has to be deliberate.
    #[test]
    fn a_bare_create_open_writes_in_place() {
        let _g = serial();
        fresh_volume();
        let mut t = vfs::ScratchFds::new();

        append_record(&mut t, b"/fat/BARE.TXT", b"original\n");

        let fd = vfs::vfs_open(&mut t, b"/fat/BARE.TXT", vfs::O_WRONLY | vfs::O_CREAT);
        assert!(fd >= 0);
        assert_eq!(vfs::vfs_write(&mut t, fd, b"new\n".as_ptr(), 4), 4);
        assert_eq!(vfs::vfs_close(&mut t, fd), 0);

        // Wave 15: FAT32 writes in place (POSIX): a bare O_CREAT keeps the
        // file and the write overwrites its first four bytes.
        assert_eq!(on_disk(b"bare.txt"), b"new\ninal\n");
    }

    /// **Round 48: descriptors made by `dup`/`dup2` share one open file
    /// description**, so one offset, as in Linux: a write through either one
    /// lands after the other's. The file reads `ab`, not `b`.
    ///
    /// **Canary.** `--features fd-private-offset-canary` (a private copy of
    /// the offset per descriptor, the old `dup`): the file reads `b`.
    #[test]
    fn dup_and_dup2_share_the_offset() {
        let _g = serial();
        fresh_volume();
        let mut t = vfs::ScratchFds::new();
        let fd = vfs::vfs_open(&mut t, b"/fat/DUP.TXT", vfs::O_WRONLY | vfs::O_CREAT | vfs::O_TRUNC);
        assert!(fd >= 0);
        let d = vfs::fd_dup(&mut t, fd);
        let d2 = vfs::fd_dup2(&mut t, fd, 6);
        assert!(d >= 0 && d != fd && d2 == 6);
        assert_eq!(vfs::vfs_write(&mut t, fd, b"a".as_ptr(), 1), 1);
        assert_eq!(vfs::vfs_write(&mut t, d, b"b".as_ptr(), 1), 1);
        assert_eq!(vfs::vfs_write(&mut t, d2, b"c".as_ptr(), 1), 1);
        assert_eq!(t.off(fd), 3, "one offset for the three descriptors");
        // A seek through one is seen by the others.
        assert_eq!(vfs::vfs_lseek(&mut t, d, 1, vfs::SEEK_SET), 1);
        assert_eq!(t.off(d2), 1);
        assert_eq!(vfs::vfs_lseek(&mut t, d2, 0, vfs::SEEK_END), 3);
        for x in [fd, d, d2] {
            assert_eq!(vfs::vfs_close(&mut t, x), 0);
        }
        assert_eq!(on_disk(b"dup.txt"), b"abc");
    }

    /// Wave 15 (PI), owner rule F1: the descriptor operations the kernel's
    /// shared table runs without its lock. An open in a private table moves
    /// into the shared one (`fd_adopt`); a lent copy writes and its offset is
    /// published (`fd_lend`/`fd_settle`), but not into a slot closed in
    /// between; a close that leaves another descriptor on the inode does not
    /// flush, and the last one hands back the flush (`fd_detach`), which
    /// writes the bytes.
    #[test]
    fn descriptor_io_without_the_table_lock() {
        let _g = serial();
        fresh_volume();
        let mut private = vfs::ScratchFds::new();
        let sfd = vfs::vfs_open(&mut private, b"/fat/LEND.TXT", vfs::O_WRONLY | vfs::O_CREAT | vfs::O_TRUNC);
        assert!(sfd >= 0);
        let mut t = vfs::ScratchFds::new();
        let fd = vfs::fd_adopt(&mut t, &mut private, sfd);
        assert!(fd >= 3, "adopted into a free slot");
        assert!(!private.fds[sfd as usize].in_use, "moved, not copied");
        assert_eq!(private.desc_refs(sfd), 0);

        let (mut lone, desc) = vfs::fd_lend(&t, fd).expect("an open descriptor lends");
        assert_eq!(vfs::vfs_write(&mut lone, 0, b"hello".as_ptr(), 5), 5);
        assert_eq!(t.off(fd), 0, "nothing published before the settle");
        vfs::fd_settle(&mut t, fd, desc, &lone);
        vfs::fd_free(&mut lone, 0);
        assert_eq!(t.off(fd), 5);

        // A settle into a descriptor closed in between publishes nothing.
        let d = vfs::fd_dup(&mut t, fd);
        assert!(d >= 0);
        let (mut lone, desc) = vfs::fd_lend(&t, d).unwrap();
        assert_eq!(vfs::vfs_write(&mut lone, 0, b"!".as_ptr(), 1), 1);
        assert!(vfs::fd_detach(&mut t, d).is_none(), "fd still names the inode: no flush");
        vfs::fd_settle(&mut t, d, desc, &lone);
        vfs::fd_free(&mut lone, 0);
        assert_eq!(t.off(fd), 5, "the closed slot's offset went nowhere");
        {
            // Wave 15: FAT32 writes in place, so both writes are in the file
            // already, whichever descriptor closes last.
            use vfs::FileSystem;
            let key = fat32::Fat32Fs.key_for(b"lend.txt").unwrap();
            assert_eq!(fat32::Fat32Fs.stat(&key).map(|st| st.size), Some(6));
        }

        let mut last = vfs::fd_detach(&mut t, fd).expect("the last descriptor hands back the flush");
        assert!(!t.fds[fd as usize].in_use);
        assert_eq!(vfs::vfs_close(&mut last, 0), 0);
        assert_eq!(on_disk(b"lend.txt"), b"hello!");
    }

    /// Wave 15 (PI): two threads sharing ONE open file description (a dup)
    /// read a device-backed streaming file with the table's lock released
    /// (`fd_stream_transfer`); the description's position lock (Linux
    /// `f_pos_lock`) makes every record come out exactly once — no offset
    /// read twice, none skipped.
    ///
    /// **Canary.** `--features fd-pos-lock-canary` (no position lock): both
    /// threads lend the same offset and a record repeats.
    #[test]
    fn shared_description_never_repeats_an_offset() {
        let _g = serial();
        fresh_volume();
        const RECS: u16 = 2048;
        let data: Vec<u8> = (0..RECS).flat_map(|i| i.to_le_bytes()).collect();
        {
            let mut w = vfs::ScratchFds::new();
            let fd = vfs::vfs_open(&mut w, b"/fat/POS.BIN", vfs::O_WRONLY | vfs::O_CREAT | vfs::O_TRUNC);
            assert!(fd >= 0);
            assert_eq!(vfs::vfs_write(&mut w, fd, data.as_ptr(), data.len()), data.len() as i32);
            assert_eq!(vfs::vfs_close(&mut w, fd), 0);
        }
        let table = std::sync::Mutex::new(vfs::ScratchFds::new());
        let fd = vfs::vfs_open(&mut table.lock().unwrap(), b"/fat/POS.BIN", vfs::O_RDONLY);
        assert!(fd >= 0);
        assert!(vfs::fd_streams(&table.lock().unwrap(), fd), "a read-only FAT32 open streams");
        let d = vfs::fd_dup(&mut table.lock().unwrap(), fd);
        assert!(d >= 0);
        let with = |f: &mut dyn FnMut(&mut vfs::ScratchFds)| f(&mut table.lock().unwrap());
        let wref = &with;
        let mut all: Vec<u16> = std::thread::scope(|s| {
            let hs: Vec<_> = [fd, d].into_iter().map(|x| s.spawn(move || {
                let mut got = Vec::new();
                loop {
                    let mut b = [0u8; 2];
                    let n = vfs::fd_stream_transfer(wref, || (), x, false, b.as_mut_ptr(), 2);
                    if n <= 0 { break; }
                    assert_eq!(n, 2);
                    got.push(u16::from_le_bytes(b));
                }
                got
            })).collect();
            hs.into_iter().flat_map(|h| h.join().unwrap()).collect()
        });
        let n = all.len();
        all.sort_unstable();
        all.dedup();
        assert_eq!(all.len(), n, "a record was read twice: two transfers at one offset");
        assert_eq!(all, (0..RECS).collect::<Vec<_>>(), "every record exactly once");
        let mut t = table.lock().unwrap();
        assert_eq!(vfs::vfs_close(&mut t, d), 0);
        assert_eq!(vfs::vfs_close(&mut t, fd), 0);
    }

    /// The description is counted: each descriptor holds one reference,
    /// a close drops one, the description outlives every close but the last,
    /// and the last one frees it for reuse (a new open starts at offset 0).
    /// Opening, duplicating and closing in a loop leaks no description.
    #[test]
    fn an_open_file_description_is_reference_counted() {
        let _g = serial();
        fresh_volume();
        let mut t = vfs::ScratchFds::new();
        let fd = vfs::vfs_open(&mut t, b"/fat/REF.TXT", vfs::O_WRONLY | vfs::O_CREAT | vfs::O_TRUNC);
        assert_eq!(t.desc_refs(fd), 1);
        let d = vfs::fd_dup(&mut t, fd);
        assert_eq!((t.desc_refs(fd), t.desc_refs(d)), (2, 2));
        assert_eq!(vfs::vfs_write(&mut t, fd, b"xy".as_ptr(), 2), 2);
        assert_eq!(vfs::vfs_close(&mut t, fd), 0);
        assert_eq!(t.desc_refs(fd), 0, "the closed descriptor names nothing");
        assert_eq!(t.desc_refs(d), 1, "the other keeps the description");
        assert_eq!(t.off(d), 2, "and its offset");
        assert_eq!(vfs::vfs_write(&mut t, d, b"z".as_ptr(), 1), 1);
        assert_eq!(vfs::vfs_close(&mut t, d), 0);
        assert!(t.descs.iter().all(|x| x.refs == 0), "the last close frees it");
        assert_eq!(on_disk(b"ref.txt"), b"xyz");
        for _ in 0..64 {
            let a = vfs::vfs_open(&mut t, b"/fat/REF.TXT", vfs::O_RDONLY);
            let b = vfs::fd_dup(&mut t, a);
            assert!(a >= 0 && b >= 0, "a description leaked");
            assert_eq!(t.off(a), 0, "a reused description starts at offset 0");
            assert_eq!(vfs::vfs_close(&mut t, b), 0);
            assert_eq!(vfs::vfs_close(&mut t, a), 0);
        }
        assert!(t.descs.iter().all(|x| x.refs == 0));
    }

    /// **A flush that fails must be visible to the caller.**
    ///
    /// `vfs_close` is where a backend-backed inode is written out, and it
    /// dropped `write_all`'s `Result` with `let _ =`. A filesystem write that
    /// never reached the device was indistinguishable from one that did:
    /// `close()` returned 0 either way, so a ring-3 program that wrote a file
    /// and closed it cleanly had no way to learn its data was gone.
    ///
    /// `disk_write_fail_after(0)` fails the write at the device, which is the
    /// same shape as a dead SD card.
    #[test]
    fn a_write_whose_device_write_fails_reports_it() {
        let _g = serial();
        let _wt = crate::write_through();
        fresh_volume();
        let mut t = vfs::ScratchFds::new();

        let fd = vfs::vfs_open(
            &mut t, b"/fat/LOST.BIN",
            vfs::O_WRONLY | vfs::O_CREAT | vfs::O_TRUNC,
        );
        assert!(fd >= 0);
        // Wave 15: in place, write-through — the write itself meets the
        // device, so ITS answer reports the failure (a close is no longer a
        // flush; under write-back fsync reports it, `writeback` tests).
        disk_write_fail_after(0);
        let w = vfs::vfs_write(&mut t, fd, b"payload".as_ptr(), 7);
        disk_write_fail_clear();
        let _ = vfs::vfs_close(&mut t, fd);

        assert_eq!(w, -1, "a write that could not reach the device must not report success");
    }

    /// A failed flush still releases the descriptor. Reporting the error by
    /// leaking a slot out of a table of `SCRATCH_FDS` would trade data loss
    /// for a denial of service.
    #[test]
    fn a_failed_flush_still_frees_the_descriptor() {
        let _g = serial();
        fresh_volume();
        let mut t = vfs::ScratchFds::new();

        let fd = vfs::vfs_open(
            &mut t, b"/fat/LOST2.BIN",
            vfs::O_WRONLY | vfs::O_CREAT | vfs::O_TRUNC,
        );
        assert!(fd >= 0);
        assert_eq!(vfs::vfs_write(&mut t, fd, b"payload".as_ptr(), 7), 7);

        disk_write_fail_after(0);
        let _ = vfs::vfs_close(&mut t, fd);
        disk_write_fail_clear();

        assert!(vfs::fd_get(&t, fd).is_none(), "the slot must be free again");
        let again = vfs::vfs_open(&mut t, b"/fat/OK.BIN", vfs::O_WRONLY | vfs::O_CREAT);
        assert!(again >= 0, "a later open must still find a descriptor");
        assert_eq!(vfs::vfs_close(&mut t, again), 0);
    }

    /// **An append open that CANNOT load the existing file must refuse, not
    /// replace it.**
    ///
    /// `try_backend_open` answers `NO_IDX` for three different reasons: the
    /// file is absent, it is bigger than `MAX_FAT32_PROXY_BYTES`, or the heap
    /// could not hold it. Only the first may fall through to the create path.
    /// The first cut of this fix fell through on all three — so a crash log
    /// that had grown past the 8 MiB proxy cap was still replaced by an empty
    /// proxy and written back over, which is the very loss the fix exists to
    /// stop, on the path where the history is most valuable.
    ///
    /// A directory entry claiming `MAX_FAT32_PROXY_BYTES + 1` reproduces it
    /// without an 8 MiB fixture: the size the VFS believes comes from that
    /// entry, and the cap is checked against it before any allocation.
    #[test]
    fn an_append_open_of_a_large_file_opens_it_in_place_untouched() {
        let _g = serial();
        use vfs::FileSystem;

        let g = Geom::default();
        let mut img = build(&g);
        set_fat(&mut img, &g, 2, 0x0FFF_FFFF);
        set_fat(&mut img, &g, 3, 0x0FFF_FFFF);
        let huge = vfs::MAX_FAT32_PROXY_BYTES as u32 + 1;
        super::vfs_backend::put_dirent(&mut img, &g, 0, b"CRASH   LOG", 3, huge);
        super::swap_medium(img);
        assert_eq!(fat32::fat32_mount(), Ok(()), "the fixture must mount");
        vfs_once();

        let mut t = vfs::ScratchFds::new();
        let fd = vfs::vfs_open(
            &mut t, b"/fat/CRASH.LOG",
            vfs::O_WRONLY | vfs::O_CREAT | vfs::O_APPEND,
        );
        // Wave 15: no proxy load any more — the file opens in place,
        // whatever its size, and the open itself leaves it untouched.
        assert!(fd >= 0, "an append open of an existing file opens it in place");
        assert_eq!(vfs::vfs_close(&mut t, fd), 0);

        let key = fat32::Fat32Fs.key_for(b"crash.log").unwrap();
        assert_eq!(
            fat32::Fat32Fs.stat(&key).unwrap().size, huge as u64,
            "the directory entry must be untouched by the refused open",
        );
    }

    /// A close with nothing to flush is still success.
    #[test]
    fn a_close_with_a_clean_inode_returns_zero() {
        let _g = serial();
        fresh_volume();
        let mut t = vfs::ScratchFds::new();

        append_record(&mut t, b"/fat/READ.ME", b"contents\n");
        let fd = vfs::vfs_open(&mut t, b"/fat/READ.ME", vfs::O_RDONLY);
        assert!(fd >= 0);
        assert_eq!(vfs::vfs_close(&mut t, fd), 0);
    }

    // ── `/fat/CRASH.LOG` rotation (`crates/fs/fs/src/crash_log.rs`) ───────────
    //
    // The DECISION (`plan_rotation`) is pure — bare integers, no fixture —
    // and covered first, on its own. The MECHANISM (`record_entry_with_cap`)
    // is covered against the real `vfs`/`fat32` this suite already pulls,
    // reusing `fresh_volume`/`on_disk`/`serial` above: the same independent
    // oracle (reading back through the FAT32 backend, not through another
    // `vfs_open`) that `vfs_open_close`'s own tests use, so a bug that lost
    // bytes cannot hide behind the same proxy machinery under test.
    //
    // `record_entry_with_cap` takes the cap as an argument specifically so
    // these tests can use a cap of a few hundred bytes rather than the real
    // `CRASH_LOG_CAP` (64 KiB) — `record_entry` (no `_with_cap`) is the
    // fixed-cap call `kernel/src/panic.rs` actually uses.

    /// Pure decision, no fixture: comfortably under the cap.
    #[test]
    fn plan_below_cap_appends() {
        assert_eq!(crash_log::plan_rotation(50, 10, 100), crash_log::RotationPlan::Append);
    }

    /// Pure decision, companion to the boundary test below: landing EXACTLY
    /// on the cap still fits. Without this, a `>=` vs `>` slip in
    /// `plan_rotation` would rotate one entry too early and nothing here
    /// would catch it.
    #[test]
    fn plan_entry_fits_exactly_at_cap_appends() {
        assert_eq!(crash_log::plan_rotation(90, 10, 100), crash_log::RotationPlan::Append);
    }

    /// Pure decision: the log has ALREADY reached the cap, so even a
    /// minimal entry cannot fit — the boundary between "still room" and "no
    /// room" tested at the point itself, not comfortably past it.
    #[test]
    fn plan_already_at_cap_boundary_rotates() {
        assert_eq!(crash_log::plan_rotation(100, 1, 100), crash_log::RotationPlan::Rotate);
    }

    /// Pure decision: there IS room left, just not enough for this entry —
    /// distinct from the boundary case above (`current < cap`, not `==`).
    #[test]
    fn plan_entry_longer_than_remaining_space_rotates() {
        assert_eq!(crash_log::plan_rotation(95, 10, 100), crash_log::RotationPlan::Rotate);
    }

    /// Below the cap, `record_entry_with_cap` must not rotate at all: no
    /// `/fat/CRASH.OLD` appears, and `/fat/CRASH.LOG` holds both entries in
    /// order. The regression guard for everything below it — if this ever
    /// rotates on every call, so would the panic handler on every panic.
    #[test]
    fn record_below_cap_appends_without_rotating() {
        let _g = serial();
        fresh_volume();
        let mut t = vfs::ScratchFds::new();

        let a = crash_log::record_entry_with_cap(&mut t, b"PANIC A\n", 100);
        assert_eq!(a, crash_log::RecordOutcome {
            write: crash_log::WriteResult::Written, rotated: false, old_copy_ok: true,
        });
        let b = crash_log::record_entry_with_cap(&mut t, b"PANIC B\n", 100);
        assert_eq!(b, crash_log::RecordOutcome {
            write: crash_log::WriteResult::Written, rotated: false, old_copy_ok: true,
        });

        assert_eq!(on_disk(b"crash.log"), b"PANIC A\nPANIC B\n");
        assert!(
            fat32::Fat32Fs.key_for(b"crash.old").and_then(|k| fat32::Fat32Fs.stat(&k)).is_none(),
            "no rotation happened, so /fat/CRASH.OLD must not exist",
        );
    }

    /// Past the cap, `record_entry_with_cap` rotates for real: the OLD
    /// content lands whole in `/fat/CRASH.OLD`, and `/fat/CRASH.LOG` ends up
    /// holding ONLY the new entry (not old+new — a rotation that forgot to
    /// truncate would still "work" by this test's earlier assertions alone).
    #[test]
    fn record_past_cap_rotates_old_content_into_crash_old() {
        let _g = serial();
        fresh_volume();
        let mut t = vfs::ScratchFds::new();

        // Pre-seed CRASH.LOG directly through the backend — an independent
        // setup path from `record_entry_with_cap` under test, so a bug in
        // ONE cannot make the other look correct by symmetry.
        let old_content = b"OLD ENTRY ONE\nOLD ENTRY TWO\n";
        assert_eq!(
            fat32::Fat32Fs.write_all(
                &fat32::Fat32Fs.key_for(b"crash.log").unwrap(), old_content,
            ),
            Ok(()),
        );

        let new_entry = b"NEW PANIC AFTER ROTATION\n";
        // cap = old_content.len() + 1: the smallest cap that FORCES rotation
        // for any non-empty new entry, without hand-computing an unrelated
        // number.
        let cap = old_content.len() + 1;
        let outcome = crash_log::record_entry_with_cap(&mut t, new_entry, cap);

        assert_eq!(outcome, crash_log::RecordOutcome {
            write: crash_log::WriteResult::Written, rotated: true, old_copy_ok: true,
        });
        assert_eq!(
            on_disk(b"crash.log"), new_entry,
            "CRASH.LOG must hold ONLY the new entry after rotation, not old+new",
        );
        assert_eq!(
            on_disk(b"crash.old"), old_content,
            "CRASH.OLD must hold exactly what CRASH.LOG held before rotation",
        );
    }

    /// **The ordering property the whole policy exists for.** The root
    /// directory is filled AND the volume left with a single free cluster, so
    /// creating `/fat/CRASH.OLD` (a NEW name) cannot succeed — its dirent
    /// needs a directory extension the volume has no cluster for — while
    /// `/fat/CRASH.LOG` — an EXISTING entry, rewritten in place rather than
    /// newly named — needs no free directory slot at all. That is a real
    /// failure mode (a full volume), not a disk-write-failure injection that
    /// would also have failed the write this test needs to succeed.
    ///
    /// A full root ALONE stopped being a failure on 2026-09-28 (gate 192):
    /// the whole-file write now extends the root's chain like `dir_insert`
    /// does, which this row used to rely on NOT happening. The one free
    /// cluster is also what the copy's failed create must hand back: the
    /// new entry's own write takes it.
    #[test]
    fn record_rotation_copy_failure_still_writes_the_new_entry() {
        let _g = serial();
        fresh_volume();
        let mut t = vfs::ScratchFds::new();

        let old_content = b"OLD CONTENT THAT MUST NOT BLOCK THE NEW ENTRY\n";
        assert_eq!(
            fat32::Fat32Fs.write_all(
                &fat32::Fat32Fs.key_for(b"crash.log").unwrap(), old_content,
            ),
            Ok(()),
        );

        // Fill the rest of the (16-entry, 1-cluster) root directory so no
        // slot remains for a brand new name like CRASH.OLD. CRASH.LOG
        // already used one of the 16 above.
        for i in 0..15u8 {
            let name83 = junk_name83(i);
            assert_eq!(
                fat32::fat32_write_file(&name83, b""), Ok(()),
                "fixture setup: junk file {} must be creatable", i,
            );
        }
        assert!(
            fat32::Fat32Fs.key_for(b"crash.old").and_then(|k| fat32::Fat32Fs.stat(&k)).is_none(),
            "fixture check: CRASH.OLD must not exist before the call under test",
        );
        // One free cluster left: enough for either file's data, not for the
        // copy's data AND a root extension.
        let mut taken = Vec::new();
        while let Ok(c) = fat32::fat32_alloc_cluster() { taken.push(c); }
        fat32::fat32_free_chain(taken.pop().expect("fixture: the volume had free clusters"));

        let new_entry = b"THE PANIC THAT JUST HAPPENED\n";
        let cap = old_content.len() + 1;
        let outcome = crash_log::record_entry_with_cap(&mut t, new_entry, cap);

        assert_eq!(
            outcome.write, crash_log::WriteResult::Written,
            "the new entry must be written even though the CRASH.OLD copy failed",
        );
        assert!(outcome.rotated, "a cap this small must still choose to rotate");
        assert!(
            !outcome.old_copy_ok,
            "the volume has no room for CRASH.OLD's entry, so the copy must \
             be reported as failed, not silently skipped",
        );
        assert_eq!(
            on_disk(b"crash.log"), new_entry,
            "losing CRASH.OLD must not cost the entry that explains the panic",
        );
    }

    /// 8.3 name `"JNK{i:02}   TXT"`-shaped, for filling directory slots with
    /// files whose content does not matter.
    fn junk_name83(i: u8) -> [u8; 11] {
        let mut name = [b' '; 11];
        name[0] = b'J';
        name[1] = b'N';
        name[2] = b'K';
        name[3] = b'0' + (i / 10);
        name[4] = b'0' + (i % 10);
        name[8] = b'T';
        name[9] = b'X';
        name[10] = b'T';
        name
    }

    // ── U09 §5 Q3 — `FileSystem::read_at`/`write_at` on the REAL Fat32Fs ──
    //
    // The property that matters is not "the bytes round-trip" (`read_all`/
    // `write_all` already prove that) — it is that `read_at`/`write_at` do
    // NOT go through the whole-file proxy at all. These tests exercise
    // `fat32::Fat32Fs` directly, the same value `vfs.rs` would hold behind
    // `dyn FileSystem`, through the trait so a signature mismatch would be
    // a compile error here, not just in `vfs.rs`.

    /// A `write_at` at offset 0 on a file that does not exist yet creates
    /// it (mirrors `fat32_open`'s `CREATE` flag), and `read_at` reads back
    /// exactly what was written — the ordinary case, stated as a baseline
    /// before the offset/hole cases below.
    #[test]
    fn fat32fs_write_at_creates_then_read_at_returns_it() {
        let _g = serial();
        fresh_volume();
        use vfs::FileSystem;

        let key = fat32::Fat32Fs.key_for(b"stream.txt").unwrap();
        assert_eq!(fat32::Fat32Fs.write_at(&key, 0, b"hello world"), Ok(11));

        let mut buf = [0u8; 32];
        let n = fat32::Fat32Fs.read_at(&key, 0, &mut buf);
        assert_eq!(&buf[..n], b"hello world");
    }

    /// `read_at` at a non-zero offset returns the bytes FROM THAT OFFSET,
    /// not the first `dst.len()` bytes of the file. A `read_all`-shaped bug
    /// (ignoring the offset and always reading from 0) would pass the
    /// previous test and fail this one.
    #[test]
    fn fat32fs_read_at_offset_skips_the_leading_bytes() {
        let _g = serial();
        fresh_volume();
        use vfs::FileSystem;

        let key = fat32::Fat32Fs.key_for(b"seek.txt").unwrap();
        assert_eq!(fat32::Fat32Fs.write_at(&key, 0, b"0123456789"), Ok(10));

        let mut buf = [0u8; 4];
        let n = fat32::Fat32Fs.read_at(&key, 6, &mut buf);
        assert_eq!(&buf[..n], b"6789", "must start at byte 6, not byte 0");
    }

    /// `write_at` past the current end of file must not require (or
    /// silently skip) the file-level API's own hole-zeroing — the same
    /// property `write_path::a_seek_past_eof_hole_reads_as_zero_...` proves
    /// for `fat32_write` directly, checked again here at the trait seam so
    /// a future `read_at`/`write_at` reimplementation cannot regress it by
    /// bypassing `fat32_seek`/`fat32_write`.
    #[test]
    fn fat32fs_write_at_past_eof_leaves_a_zero_hole() {
        let _g = serial();
        fresh_volume();
        use vfs::FileSystem;

        let key = fat32::Fat32Fs.key_for(b"hole.txt").unwrap();
        assert_eq!(fat32::Fat32Fs.write_at(&key, 0, b"AB"), Ok(2));
        assert_eq!(fat32::Fat32Fs.write_at(&key, 10, b"Z"), Ok(1));

        let mut buf = [0u8; 11];
        let n = fat32::Fat32Fs.read_at(&key, 0, &mut buf);
        assert_eq!(n, 11, "size must now be offset(10) + len(1)");
        assert_eq!(&buf[..2], b"AB");
        assert_eq!(&buf[2..10], &[0u8; 8], "the hole must read as zero");
        assert_eq!(&buf[10..11], b"Z");
    }

    /// `read_at` past the end of file returns 0, not a short read of
    /// garbage — the proof that a caller can use it as an EOF test the way
    /// it already uses `fat32_read`'s `Ok(0)`.
    #[test]
    fn fat32fs_read_at_past_eof_returns_zero() {
        let _g = serial();
        fresh_volume();
        use vfs::FileSystem;

        let key = fat32::Fat32Fs.key_for(b"short.txt").unwrap();
        assert_eq!(fat32::Fat32Fs.write_at(&key, 0, b"hi"), Ok(2));

        let mut buf = [0u8; 8];
        assert_eq!(fat32::Fat32Fs.read_at(&key, 100, &mut buf), 0);
    }

    /// `write_at` streams: it must not cost a whole-file-sized allocation
    /// the way `try_backend_open`/`write_all` do. Not directly measurable
    /// from a host test (no heap instrumentation here), so this instead
    /// pins the OBSERVABLE consequence — a multi-record append built out of
    /// several small `write_at` calls lands the same bytes a single
    /// `write_all` of the concatenation would — which is what a caller
    /// migrating off `write_all` needs to be true.
    #[test]
    fn fat32fs_write_at_sequential_appends_match_one_whole_file_write() {
        let _g = serial();
        fresh_volume();
        use vfs::FileSystem;

        let key = fat32::Fat32Fs.key_for(b"append.txt").unwrap();
        let mut off = 0u64;
        for chunk in [&b"AAAA"[..], &b"BB"[..], &b"CCCCCC"[..]] {
            let n = fat32::Fat32Fs.write_at(&key, off, chunk).unwrap();
            off += n as u64;
        }

        let mut buf = [0u8; 16];
        let n = fat32::Fat32Fs.read_at(&key, 0, &mut buf);
        assert_eq!(&buf[..n], b"AAAABBCCCCCC");
    }
}

/// U09 §5 Q3 — `FileSystem::read_at`/`write_at` for `TmpFs`.
///
/// tmpfs is already RAM-resident, so "streaming" buys it nothing in cost —
/// what these tests pin is that the SAME trait signature FAT32 streams
/// through behaves correctly for tmpfs too: offset reads/writes, holes
/// zero-filled the same way, and growth without corrupting what was there.
/// Runs against the real `tmpfs_read_at`/`tmpfs_write_at`, pulled via
/// `#[path]` like `fat32`/`vfs` above.
#[cfg(test)]
mod tmpfs_streaming {
    use super::{serial, tmpfs, vfs};
    use vfs::FileSystem as _;

    fn key(name: &[u8]) -> vfs::InodeKey {
        tmpfs::TmpFs.key_for(name).expect("name fits INODE_KEY_LEN")
    }

    #[test]
    fn write_at_then_read_at_round_trips() {
        let _g = serial();
        let k = key(b"a");
        assert_eq!(tmpfs::TmpFs.write_at(&k, 0, b"hello"), Ok(5));
        let mut buf = [0u8; 8];
        let n = tmpfs::TmpFs.read_at(&k, 0, &mut buf);
        assert_eq!(&buf[..n], b"hello");
        let _ = tmpfs::tmpfs_unlink(b"a");
    }

    #[test]
    fn read_at_offset_skips_leading_bytes() {
        let _g = serial();
        let k = key(b"b");
        tmpfs::TmpFs.write_at(&k, 0, b"0123456789").unwrap();
        let mut buf = [0u8; 4];
        let n = tmpfs::TmpFs.read_at(&k, 6, &mut buf);
        assert_eq!(&buf[..n], b"6789");
        let _ = tmpfs::tmpfs_unlink(b"b");
    }

    #[test]
    fn write_at_past_eof_leaves_a_zero_hole() {
        let _g = serial();
        let k = key(b"c");
        tmpfs::TmpFs.write_at(&k, 0, b"AB").unwrap();
        tmpfs::TmpFs.write_at(&k, 10, b"Z").unwrap();
        let mut buf = [0u8; 11];
        let n = tmpfs::TmpFs.read_at(&k, 0, &mut buf);
        assert_eq!(n, 11);
        assert_eq!(&buf[..2], b"AB");
        assert_eq!(&buf[2..10], &[0u8; 8], "the hole must read as zero");
        assert_eq!(&buf[10..11], b"Z");
        let _ = tmpfs::tmpfs_unlink(b"c");
    }

    #[test]
    fn write_at_inside_existing_bounds_overwrites_without_disturbing_the_rest() {
        let _g = serial();
        let k = key(b"d");
        tmpfs::TmpFs.write_at(&k, 0, b"AAAAAAAAAA").unwrap();
        tmpfs::TmpFs.write_at(&k, 3, b"XX").unwrap();
        let mut buf = [0u8; 10];
        let n = tmpfs::TmpFs.read_at(&k, 0, &mut buf);
        assert_eq!(&buf[..n], b"AAAXXAAAAA");
        let _ = tmpfs::tmpfs_unlink(b"d");
    }

    #[test]
    fn read_at_past_eof_returns_zero() {
        let _g = serial();
        let k = key(b"e");
        tmpfs::TmpFs.write_at(&k, 0, b"hi").unwrap();
        let mut buf = [0u8; 8];
        assert_eq!(tmpfs::TmpFs.read_at(&k, 100, &mut buf), 0);
        let _ = tmpfs::tmpfs_unlink(b"e");
    }
}

/// U09-1 — every ramfs `create + unlink` cycle leaked one inode slot.
///
/// `inode_alloc` used to set `link_count = 1` on allocation, pre-counting the
/// directory entry a caller was about to add. `dir_add_entry` then added its
/// own `+1` (`link_count == 2`), so `dir_remove_entry`'s single `-1` on unlink
/// could only ever bring it back to 1 — never 0 — and `fd_free`'s
/// `rc == 0 && lc == 0` auto-free test never fired. `MAX_FILES = 128` is
/// machine-wide (`vfs::MAX_FILES`), and ring 3 reaches this ramfs fallback
/// through `sys_open(O_CREAT)` on any path outside `/fat` (`vfs_open`'s
/// create branch, `vfs.rs`) plus `sys_unlink` (`path_parent` +
/// `dir_remove_entry`, the same composition `kernel/src/boot/seams.rs`'s `unlink()`
/// uses) — so `MAX_FILES + 1` cycles of it either exhaust the pool (the bug)
/// or all succeed (fixed).
#[cfg(test)]
mod inode_leak {
    use super::vfs;

    /// `kernel/src/boot/seams.rs`'s `unlink()` is exactly `path_parent` +
    /// `dir_remove_entry`; `vfs.rs` has no `vfs_unlink` of its own, so the
    /// test composes the same two exported primitives rather than adding a
    /// third copy of the logic.
    fn unlink(path: &[u8]) -> i64 {
        let (parent_idx, name) = vfs::path_parent(path);
        if parent_idx == vfs::NO_IDX || name.is_empty() { return -1; }
        match vfs::dir_remove_entry(parent_idx, name) {
            Ok(())  => 0,
            Err(()) => -1,
        }
    }

    #[test]
    fn create_unlink_cycles_beyond_max_files_still_open() {
        let _g = super::serial();
        super::vfs_root_once();

        let mut t = vfs::ScratchFds::new();
        for i in 0..(vfs::MAX_FILES + 1) {
            let path = format!("/probe{i}").into_bytes();
            let fd = vfs::vfs_open(&mut t, &path, vfs::O_WRONLY | vfs::O_CREAT);
            assert!(
                fd >= 0,
                "cycle {i}: create must succeed — a leaked inode from an \
                 earlier cycle exhausted the {}-slot pool",
                vfs::MAX_FILES,
            );
            assert_eq!(vfs::vfs_close(&mut t, fd), 0, "cycle {i}: close must succeed");
            assert_eq!(unlink(&path), 0, "cycle {i}: unlink must succeed");
        }
    }

    /// Same defect, the other ordering: unlink while an fd from BEFORE the
    /// unlink is still open, close it after. `dir_remove_entry` alone cannot
    /// free the inode here (`rc == 1`, something still has it open) — the
    /// free has to come from the LATER `fd_free`, exercising the half of the
    /// fix that stayed in `fd_free`'s existing `rc == 0 && lc == 0` check
    /// rather than the new one added to `dir_remove_entry`.
    #[test]
    fn unlink_before_close_still_frees_on_close() {
        let _g = super::serial();
        super::vfs_root_once();

        let mut t = vfs::ScratchFds::new();
        for i in 0..(vfs::MAX_FILES + 1) {
            let path = format!("/probeb{i}").into_bytes();
            let fd = vfs::vfs_open(&mut t, &path, vfs::O_WRONLY | vfs::O_CREAT);
            assert!(
                fd >= 0,
                "cycle {i}: create must succeed — a leaked inode from an \
                 earlier cycle exhausted the {}-slot pool",
                vfs::MAX_FILES,
            );
            assert_eq!(unlink(&path), 0, "cycle {i}: unlink-before-close must succeed");
            assert_eq!(vfs::vfs_close(&mut t, fd), 0, "cycle {i}: close-after-unlink must succeed");
        }
    }
}

/// **The signed topology files must be reachable by the names a loader opens.**
///
/// `crates/fs/fs/src/fat32.rs` matches short 8.3 names only. `crates/core/topology`
/// used to document its sidecars as `CAPS.TOML.SIG` / `SCHED.TOML.SIG`, and the
/// data files as `CAPS.TOML` / `SCHED.TOML`: all four fail 8.3 (a four-letter
/// extension, and two dots), and `mcopy` stores them under generated short
/// names (`CAPS~1.TOM`, `CAPSTO~1.SIG`, ...) that nothing would ever look up.
/// Nothing loads them today — the kernel installs `default_minimal()` — so the
/// failure would have surfaced as a silent "file not found" on the day a real
/// loader was wired.
///
/// The volume is built by the SAME tools and the same `mkfs.fat` command line
/// as the Makefile's disk recipes, not by `image::build`: the property is about
/// what real tools write, and a hand-built directory entry would only encode
/// this file's belief about them. A missing tool FAILS the test rather than
/// skipping it — a skipped row reads as green.
#[cfg(test)]
mod topology_paths_on_a_real_volume {
    use super::{fat32, serial, topology_paths as tp, vfs};
    use std::path::{Path, PathBuf};
    use std::process::Command;

    /// Homebrew's `sbin` holds `mkfs.fat` on macOS and is not on every PATH.
    fn tool(name: &str) -> PathBuf {
        for dir in ["/opt/homebrew/sbin", "/opt/homebrew/bin", "/usr/local/sbin",
                    "/usr/local/bin", "/usr/sbin", "/sbin", "/usr/bin"] {
            let p = Path::new(dir).join(name);
            if p.is_file() { return p; }
        }
        panic!("`{name}` not found: this test needs real mtools/dosfstools \
                (the same ones the Makefile's disk recipes use), and does not \
                skip without them");
    }

    fn run(cmd: &mut Command) {
        let out = cmd.output().unwrap_or_else(|e| panic!("{cmd:?}: {e}"));
        assert!(out.status.success(), "{cmd:?} failed: {}",
                String::from_utf8_lossy(&out.stderr));
    }

    /// A FAT32 volume made by `mkfs.fat` with `files` written by `mcopy`
    /// under exactly the given names (the name mcopy is TOLD, i.e. what an
    /// operator or a Makefile recipe would type).
    fn mtools_volume(files: &[(&str, &[u8])]) -> Vec<u8> {
        let dir = std::env::temp_dir().join(format!(
            "azos-fs-tests-topo-{}-{:?}", std::process::id(), std::thread::current().id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let img = dir.join("vol.img");
        // Makefile: `mkfs.fat -F 32 -n "ROBTOS" $@ 32768`; `-C` creates the
        // file the recipe gets from its preceding `dd`.
        run(Command::new(tool("mkfs.fat"))
            .args(["-C", "-F", "32", "-n", "ROBTOS"]).arg(&img).arg("32768"));
        for (i, (name, bytes)) in files.iter().enumerate() {
            let src = dir.join(format!("src{i}"));
            std::fs::write(&src, bytes).unwrap();
            run(Command::new(tool("mcopy")).arg("-i").arg(&img).arg(&src)
                .arg(format!("::{name}")));
        }
        let v = std::fs::read(&img).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        v
    }

    fn mount(img: Vec<u8>) {
        super::swap_medium(img);
        assert_eq!(fat32::fat32_mount(), Ok(()),
                   "a volume made by mkfs.fat -F 32 must mount");
        super::vfs_open_close::vfs_once();
    }

    /// `vfs_open` + `vfs_read` + `vfs_close`, O_RDONLY — the sequence
    /// `kernel/src/boot/config_auth.rs` uses for `/fat/CONFIG.INI` and `/fat/CONFIG.SIG`.
    /// `None` when the open fails.
    fn load(path: &[u8]) -> Option<Vec<u8>> {
        let mut t = vfs::ScratchFds::new();
        let fd = vfs::vfs_open(&mut t, path, vfs::O_RDONLY);
        if fd < 0 { return None; }
        let mut buf = vec![0u8; 4096];
        let n = vfs::vfs_read(&mut t, fd, buf.as_mut_ptr(), buf.len());
        vfs::vfs_close(&mut t, fd);
        assert!(n >= 0, "read of an opened file failed: {}", String::from_utf8_lossy(path));
        buf.truncate(n as usize);
        Some(buf)
    }

    /// The name mcopy must be told for a VFS path: the part after `/fat/`.
    fn on_volume(path: &'static [u8]) -> &'static str {
        core::str::from_utf8(path.strip_prefix(b"/fat/").expect("a /fat/ path")).unwrap()
    }

    fn short_names() -> Vec<String> {
        let mut v = Vec::new();
        fat32::fat32_ls_root(|n, _, _| v.push(String::from_utf8_lossy(n).into_owned()));
        v
    }

    /// Every constant opens and reads back the bytes mcopy wrote — distinct
    /// payloads, so a lookup that resolved to the wrong entry cannot pass.
    #[test]
    fn every_topology_path_opens_on_a_volume_mtools_wrote() {
        let _g = serial();
        let caps: &[u8]      = b"[[task]]\nname = \"autorun\"\n";
        let caps_sig: &[u8]  = &[0xC5; 64];
        let sched: &[u8]     = b"[[class]]\nname = \"best_effort\"\n";
        let sched_sig: &[u8] = &[0x5E; 64];
        mount(mtools_volume(&[
            (on_volume(tp::CAPS_TOML_PATH), caps),
            (on_volume(tp::CAPS_SIG_PATH), caps_sig),
            (on_volume(tp::SCHED_TOML_PATH), sched),
            (on_volume(tp::SCHED_SIG_PATH), sched_sig),
        ]));
        for (path, want) in [(tp::CAPS_TOML_PATH, caps), (tp::CAPS_SIG_PATH, caps_sig),
                             (tp::SCHED_TOML_PATH, sched), (tp::SCHED_SIG_PATH, sched_sig)] {
            let got = load(path).unwrap_or_else(|| panic!(
                "{} is not reachable on a volume mtools wrote it to; the root \
                 holds {:?}", String::from_utf8_lossy(path), short_names()));
            assert_eq!(got, want, "{} read back other bytes", String::from_utf8_lossy(path));
        }
    }

    /// **Control: the old names really are unreachable, and not because the
    /// files are missing.** The files ARE on the volume — the root listing
    /// shows the short names mtools generated for them — yet the names a
    /// human wrote do not open. Without the listing, a failed open could not
    /// tell "unreachable name" from "absent file", and this control would
    /// pass on an empty volume.
    #[test]
    fn the_two_dot_and_four_letter_names_are_on_disk_but_unreachable() {
        let _g = serial();
        let old = ["CAPS.TOML", "CAPS.TOML.SIG", "SCHED.TOML", "SCHED.TOML.SIG"];
        let files: Vec<(&str, &[u8])> = old.iter().map(|n| (*n, &b"x"[..])).collect();
        mount(mtools_volume(&files));

        let listed = short_names();
        assert_eq!(listed.len(), old.len(), "all four files are on the volume: {listed:?}");
        for n in &old {
            assert!(!listed.iter().any(|l| l == n),
                    "{n} was stored under its own name — the premise of this row changed \
                     (mtools no longer mangles it, or the driver learned LFN): {listed:?}");
            let path = format!("/fat/{n}");
            assert!(load(path.as_bytes()).is_none(),
                    "{path} opened; the FAT32 driver resolved a non-8.3 name");
        }
    }

    /// The ML service's two files open by the constants it passes to the open
    /// syscall (minus the NUL), on a volume the Makefile's tools wrote.
    ///
    /// Control, on a second volume: the weights file under its pre-wave-10
    /// name, `MLP.RMLP`, is on it (mtools lists it under a generated short
    /// name) and does NOT open — the service printed "not found" on every
    /// boot and ran on its compiled-in weights.
    #[test]
    fn ml_service_paths_open_and_the_old_weights_name_does_not() {
        let _g = serial();
        let weights: &[u8] = &[0x57; 292];
        let policy: &[u8] = b"GGUF-policy-bytes";
        let strip = |p: &'static [u8]| p.strip_suffix(b"\0").expect("a NUL-terminated path");
        let wp = strip(super::ml_srv_paths::WEIGHTS_PATH);
        let pp = strip(super::ml_srv_paths::POLICY_PATH);
        mount(mtools_volume(&[(on_volume(wp), weights), (on_volume(pp), policy)]));
        for (path, want) in [(wp, weights), (pp, policy)] {
            let got = load(path).unwrap_or_else(|| panic!(
                "{} is not reachable on a volume mtools wrote it to; the root \
                 holds {:?}", String::from_utf8_lossy(path), short_names()));
            assert_eq!(got, want, "{} read back other bytes", String::from_utf8_lossy(path));
        }

        mount(mtools_volume(&[("MLP.RMLP", weights)]));
        let listed = short_names();
        assert_eq!(listed.len(), 1, "the file is on the volume: {listed:?}");
        assert!(!listed.iter().any(|l| l == "MLP.RMLP"),
                "MLP.RMLP was stored under its own name: {listed:?}");
        assert!(load(b"/fat/MLP.RMLP").is_none(), "/fat/MLP.RMLP opened");
    }
}

/// Durability under a volatile device write cache.
///
/// The shim's `disk_writeback()` makes a write durable only once a
/// successful `blkdev::flush` follows it, and `disk_durable_image()` is what
/// a power cut leaves. Each test "reboots" onto that image and reads back
/// through a fresh mount, so what is asserted is the medium, not the
/// in-memory state of the volume that wrote it.
#[cfg(test)]
mod durability {
    use super::{fat32, image::*, serial, swap_medium};
    use fs_test_drivers::{
        disk_durable_image, disk_events, disk_flush_mode, disk_writeback,
        DiskEvent, FlushMode,
    };

    const PATH: &[u8] = b"/REC.LOG";
    const RECORD: &[u8] = b"SAFETY_ESTOP action=2 detail=0 .";

    fn fresh() {
        let g = Geom::default();
        let mut img = build(&g);
        set_fat(&mut img, &g, 2, 0x0FFF_FFFF);
        swap_medium(img);
        assert_eq!(fat32::fat32_mount(), Ok(()), "the fixture must mount");
    }

    fn create() -> fat32::Fat32File {
        fat32::fat32_open(
            fat32::Volume::assume_mounted(), PATH,
            fat32::open_flags::CREATE | fat32::open_flags::WRITE,
        ).expect("the root has room for one file")
    }

    /// Cut the power, boot onto what was durable, and read `path` back.
    /// `None` when the file does not exist on that medium.
    fn after_power_cut(path: &[u8]) -> Option<Vec<u8>> {
        swap_medium(disk_durable_image());
        assert_eq!(fat32::fat32_mount(), Ok(()), "the durable image must mount");
        let f = fat32::fat32_open(
            fat32::Volume::assume_mounted(), path, fat32::open_flags::READ,
        ).ok()?;
        let (_, size) = fat32::fat32_file_stat(f).expect("an open handle has a size");
        let mut buf = vec![0u8; size as usize];
        let n = if size == 0 { 0 } else { fat32::fat32_read(f, &mut buf).expect("read") };
        let _ = fat32::fat32_close(f);
        buf.truncate(n);
        Some(buf)
    }

    /// The control: without an fsync the cut loses the file, so the model
    /// really does drop unflushed writes and the tests below can fail.
    #[test]
    fn an_append_without_fsync_does_not_survive_a_power_cut() {
        let _g = serial();
        fresh();
        disk_writeback();
        let f = create();
        assert_eq!(fat32::fat32_write(f, RECORD), Ok(RECORD.len()));
        assert_eq!(after_power_cut(PATH), None);
    }

    #[test]
    fn an_fsynced_append_survives_a_power_cut() {
        let _g = serial();
        fresh();
        disk_writeback();
        let f = create();
        assert_eq!(fat32::fat32_write(f, RECORD), Ok(RECORD.len()));
        assert_eq!(fat32::fat32_fsync(f), Ok(()));
        assert_eq!(after_power_cut(PATH).as_deref(), Some(RECORD));
    }

    /// The order inside `fsync`: a flush BEFORE the directory entry (so the
    /// entry never exposes data the medium does not hold yet) and one after
    /// it (the durability point). A power-cut test cannot see the first one
    /// under this model, which never reorders writes, so the sequence is
    /// asserted directly.
    #[test]
    fn fsync_flushes_before_the_directory_entry_and_after_it() {
        let _g = serial();
        let _wt = crate::write_through();
        fresh();
        let f = create();
        assert_eq!(fat32::fat32_write(f, RECORD), Ok(RECORD.len()));
        let _ = disk_events();
        assert_eq!(fat32::fat32_fsync(f), Ok(()));
        let root = cluster_sector(&Geom::default(), 2) as u64;
        assert_eq!(
            disk_events(),
            vec![DiskEvent::Flush, DiskEvent::Write(root), DiskEvent::Flush],
        );
    }

    /// A device that cannot flush: the entry is still written (on a
    /// write-through medium that is all there is), `fsync` says so, and the
    /// handle stays dirty so the next `fsync` does not answer `Ok`.
    #[test]
    fn fsync_on_a_device_that_cannot_flush_writes_the_entry_and_says_so() {
        let _g = serial();
        fresh();
        disk_flush_mode(FlushMode::Unsupported);
        let f = create();
        assert_eq!(fat32::fat32_write(f, RECORD), Ok(RECORD.len()));
        assert_eq!(fat32::fat32_fsync(f), Err(fat32::FsError::Unsupported));
        assert_eq!(fat32::fat32_fsync(f), Err(fat32::FsError::Unsupported));
        assert_eq!(after_power_cut(PATH).as_deref(), Some(RECORD));
    }

    #[test]
    fn a_failed_flush_keeps_the_handle_dirty_and_a_retry_flushes() {
        let _g = serial();
        fresh();
        disk_writeback();
        disk_flush_mode(FlushMode::Io);
        let f = create();
        assert_eq!(fat32::fat32_write(f, RECORD), Ok(RECORD.len()));
        assert_eq!(fat32::fat32_fsync(f), Err(fat32::FsError::Io));
        disk_flush_mode(FlushMode::Ok);
        assert_eq!(fat32::fat32_fsync(f), Ok(()));
        assert_eq!(after_power_cut(PATH).as_deref(), Some(RECORD));
    }

    #[test]
    fn sync_returns_the_device_answer() {
        let _g = serial();
        fresh();
        disk_flush_mode(FlushMode::Unsupported);
        assert_eq!(fat32::fat32_sync_checked(), Err(fat32::FsError::Unsupported));
        disk_flush_mode(FlushMode::Io);
        assert_eq!(fat32::fat32_sync_checked(), Err(fat32::FsError::Io));
        assert_eq!(fat32::fat32_sync(), Err(()));
        disk_flush_mode(FlushMode::Ok);
        let _ = disk_events();
        assert_eq!(fat32::fat32_sync_checked(), Ok(()));
        assert_eq!(disk_events().last(), Some(&DiskEvent::Flush));
    }

    /// `fat32_write_file` is what `vfs_close` (CRASH.LOG, BOOTMETA) reports.
    #[test]
    fn a_whole_file_write_is_durable_when_it_returns() {
        let _g = serial();
        fresh();
        disk_writeback();
        let mut name83 = [b' '; 11];
        name83[0..3].copy_from_slice(b"REC");
        name83[8..11].copy_from_slice(b"LOG");
        assert_eq!(fat32::fat32_write_file(&name83, RECORD), Ok(()));
        assert_eq!(after_power_cut(PATH).as_deref(), Some(RECORD));
    }
}

/// Power cuts INSIDE the journaled operations, against a device cache that
/// may persist its pending writes in any order.
///
/// `durability` above cuts only at "everything up to the last flush", which
/// never reorders, so it cannot see a missing ordering barrier (the wave-5
/// report said as much). Here each operation's write/flush log (the shim's
/// `disk_take_log`) is replayed onto the pre-operation image as EVERY state
/// a cut may leave: all writes before flush `k`, plus every subset of the
/// writes between flush `k` and flush `k + 1`. Each state is mounted — which
/// runs the real `fat32_journal_recover` — and must then hold one of the
/// operation's legal outcomes, with a structurally sound chain behind every
/// dirent and no journal record left behind.
///
/// Files span several one-sector clusters, so a read follows FAT links and
/// a chain the FAT calls free cannot pass by reading its first cluster.
#[cfg(test)]
mod power_cut {
    use super::{fat32, image::*, serial, swap_medium};
    use fs_test_drivers::{disk_durable_image, disk_events, disk_take_log, DiskEvent, LogEntry};

    const OLD: usize = 1400; // 3 clusters
    const NEW: usize = 900;  // 2 clusters
    const EOC_MIN: u32 = 0x0FFF_FFF8;

    fn pattern(len: usize, seed: u8) -> Vec<u8> {
        (0..len).map(|i| seed.wrapping_add((i % 251) as u8)).collect()
    }

    fn name(base: &[u8], ext: &[u8]) -> [u8; 11] {
        let mut n = [b' '; 11];
        n[..base.len()].copy_from_slice(base);
        n[8..8 + ext.len()].copy_from_slice(ext);
        n
    }

    fn remount(img: Vec<u8>) {
        swap_medium(img);
        for s in 0..Geom::default().total_sectors as u32 { fat32::fat32_cache_invalidate(s); }
        assert_eq!(fat32::fat32_mount(), Ok(()), "a power-cut image must mount");
    }

    fn fresh_image() -> Vec<u8> {
        let g = Geom::default();
        let mut img = build(&g);
        set_fat(&mut img, &g, 2, 0x0FFF_FFFF);
        img
    }

    fn fat(img: &[u8], c: u32) -> u32 {
        let off = Geom::default().rsvd as usize * SECTOR + c as usize * 4;
        u32::from_le_bytes(img[off..off + 4].try_into().unwrap())
    }

    /// `(first_cluster, size)` of `n83` in the root directory, read off the
    /// medium itself, not through the driver under test.
    /// Follows the root's FAT chain, so an entry in a cluster a directory
    /// extension added is found too.
    fn dirent(img: &[u8], n83: &[u8; 11]) -> Option<(u32, u32)> {
        let mut c = 2u32;
        for _ in 0..200 {
            if !(2..200).contains(&c) { return None; }
            let root = cluster_sector(&Geom::default(), c) * SECTOR;
            for e in 0..16 {
                let d = &img[root + e * 32..root + e * 32 + 32];
                if d[0] == 0 { return None; }
                if d[0] == 0xE5 || &d[..11] != n83 { continue; }
                let hi = u16::from_le_bytes([d[20], d[21]]) as u32;
                let lo = u16::from_le_bytes([d[26], d[27]]) as u32;
                return Some(((hi << 16) | lo, u32::from_le_bytes(d[28..32].try_into().unwrap())));
            }
            c = fat(img, c);
        }
        None
    }

    /// The clusters `n83`'s dirent names, or why the chain is unsound:
    /// a link to a free (0) or out-of-range cluster, or a length that does
    /// not match the size.
    fn chain(img: &[u8], n83: &[u8; 11]) -> Result<Vec<u32>, String> {
        let Some((first, size)) = dirent(img, n83) else { return Ok(Vec::new()) };
        let want = (size as usize).div_ceil(SECTOR);
        let mut out = Vec::new();
        let mut c = first;
        while want > 0 && out.len() <= want {
            if !(2..200).contains(&c) { return Err(format!("link to cluster {c:#x}")); }
            out.push(c);
            let v = fat(img, c);
            if v == 0 { return Err(format!("cluster {c} of a live chain is FREE in the FAT")); }
            if v >= EOC_MIN { break; }
            c = v;
        }
        if out.len() != want { return Err(format!("chain of {} clusters for size {size}", out.len())); }
        Ok(out)
    }

    fn read_back(path: &[u8]) -> Option<Vec<u8>> {
        let f = fat32::fat32_open(fat32::Volume::assume_mounted(), path, fat32::open_flags::READ).ok()?;
        let (_, size) = fat32::fat32_file_stat(f).expect("stat");
        let mut buf = vec![0u8; size as usize];
        let n = if size == 0 { 0 } else { fat32::fat32_read(f, &mut buf).unwrap_or(usize::MAX) };
        let _ = fat32::fat32_close(f);
        if n == usize::MAX { return Some(b"<read error>".to_vec()); }
        buf.truncate(n);
        Some(buf)
    }

    /// Every state a cut may leave: `(epoch, subset mask, image)`.
    fn crash_states(pristine: &[u8], log: &[LogEntry]) -> Vec<(usize, u32, Vec<u8>)> {
        let mut epochs: Vec<Vec<(u64, Vec<u8>)>> = vec![Vec::new()];
        for e in log {
            match e {
                LogEntry::Write(s, d) => epochs.last_mut().unwrap().push((*s, d.clone())),
                LogEntry::Flush => epochs.push(Vec::new()),
            }
        }
        let mut out = Vec::new();
        let mut base = pristine.to_vec();
        for (k, ep) in epochs.iter().enumerate() {
            assert!(ep.len() <= 16, "epoch {k} has {} writes; subsets would not be enumerable", ep.len());
            for mask in 0u32..(1u32 << ep.len()) {
                let mut img = base.clone();
                for (i, (s, d)) in ep.iter().enumerate() {
                    if mask & (1 << i) != 0 {
                        let off = *s as usize * SECTOR;
                        img[off..off + SECTOR].copy_from_slice(d);
                    }
                }
                out.push((k, mask, img));
            }
            for (s, d) in ep {
                let off = *s as usize * SECTOR;
                base[off..off + SECTOR].copy_from_slice(d);
            }
        }
        out
    }

    /// Run `op` on `pristine`, then check every cut state with `judge`,
    /// which sees the mounted, recovered volume and returns `Err` for an
    /// illegal outcome. Returns the number of flushes `op` issued.
    fn cut_everywhere(
        pristine: Vec<u8>,
        op: impl FnOnce(),
        judge: impl Fn(&[u8]) -> Result<(), String>,
    ) -> usize {
        remount(pristine.clone());
        let _ = disk_take_log();
        let _ = disk_events();
        op();
        // Write-back: what the operation queued goes out now, epoch by epoch
        // with a flush between (a no-op write-through, where it already did).
        // Until clean: a flush frees the chains held for it (`defer_free`)
        // into a new epoch, which the next pass writes, so those cuts are
        // checked too.
        for _ in 0..4 {
            if fat32::fat32_writeback_dirty().0 == 0 { break; }
            assert_eq!(fat32::fat32_writeback_now(), Ok(()));
        }
        assert_eq!(fat32::fat32_writeback_dirty().0, 0, "write-back did not settle");
        let log = disk_take_log();
        let flushes = log.iter().filter(|e| **e == LogEntry::Flush).count();
        let states = crash_states(&pristine, &log);
        let writes = log.len() - flushes;
        println!("power_cut: {writes} writes, {flushes} flushes, {} cut states", states.len());
        assert!(states.len() > flushes + 1, "no subset beyond the prefix cuts was checked");
        for (k, mask, img) in states {
            remount(img);
            let after = disk_durable_image();
            let j = &after[fat32::JOURNAL_SECTOR as usize * SECTOR..][..SECTOR];
            if j[0..4] == *b"JRNL" && j[4] != 0 {
                panic!("cut in epoch {k} subset {mask:#b}: journal state {} left after mount", j[4]);
            }
            if let Err(why) = judge(&after) {
                panic!("cut in epoch {k} subset {mask:#b} of {flushes} flushes: {why}");
            }
        }
        flushes
    }

    fn one_of(n83: &[u8; 11], path: &[u8], img: &[u8], legal: &[Option<&[u8]>]) -> Result<(), String> {
        chain(img, n83)?;
        let got = read_back(path);
        if legal.iter().any(|l| l.map(|v| v.to_vec()) == got) { return Ok(()); }
        Err(format!("{} holds {:?} bytes, not a legal outcome",
            String::from_utf8_lossy(path), got.map(|v| v.len())))
    }

    fn with_file(n83: &[u8; 11], data: &[u8]) -> Vec<u8> {
        remount(fresh_image());
        assert_eq!(fat32::fat32_write_file(n83, data), Ok(()));
        disk_durable_image()
    }

    /// The root's entry names, walked off the medium along the root's FAT
    /// chain (not through the driver): every live short-name slot up to the
    /// terminator. `Err` for a chain that leaves the data region.
    fn root_names(img: &[u8]) -> Result<Vec<[u8; 11]>, String> {
        let g = Geom::default();
        let mut out = Vec::new();
        let mut c = g.root_clus;
        for _ in 0..200 {
            if !(2..200).contains(&c) { return Err(format!("root chain links to {c:#x}")); }
            let base = cluster_sector(&g, c) * SECTOR;
            for e in 0..16 {
                let d = &img[base + e * 32..base + e * 32 + 32];
                if d[0] == 0 { return Ok(out); }
                if d[0] == 0xE5 || d[11] == 0x0F { continue; }
                out.push(d[..11].try_into().unwrap());
            }
            let v = fat(img, c);
            if v >= EOC_MIN { return Ok(out); }
            c = v;
        }
        Err("root chain does not end".into())
    }

    /// **Gate 192's create, cut everywhere.** Root full (16 live entries in
    /// its one cluster), every free data cluster holding stale non-zero
    /// bytes, and a new root file written: the root must be extended, and
    /// no cut may leave the directory listing anything but the 16 old names
    /// or those plus the WHOLE new file. The extension cluster used to be
    /// linked into the root before it was zeroed: a cut between the two
    /// listed the stale bytes as sixteen phantom entries.
    #[test]
    fn a_create_that_extends_a_full_root_cut_anywhere_lists_no_phantoms() {
        let _g = serial();
        let g = Geom::default();
        let mut img = fresh_image();
        let root = cluster_sector(&g, 2) * SECTOR;
        let mut old_names = Vec::new();
        for e in 0..16usize {
            let n = name(&[b'O', b'L', b'D', b'0' + (e / 10) as u8, b'0' + (e % 10) as u8], b"TXT");
            img[root + e * 32..root + e * 32 + 11].copy_from_slice(&n);
            img[root + e * 32 + 11] = 0x20;
            old_names.push(n);
        }
        for c in 3u32..200 { fill_cluster(&mut img, &g, c, b'Q'); }
        let n = name(b"BOOTMETA", b"B");
        let data = pattern(300, 0x21);
        let f = cut_everywhere(img,
            || assert_eq!(fat32::fat32_write_file(&n, &data), Ok(())),
            |img| {
                let names = root_names(img)?;
                if names[..] == old_names[..] { return Ok(()); }
                let mut with_new = old_names.clone();
                with_new.push(n);
                if names != with_new {
                    return Err(format!("root lists {} entries: {:?}", names.len(),
                        names.iter().map(|x| String::from_utf8_lossy(x).into_owned()).collect::<Vec<_>>()));
                }
                if chain(img, &n)?.is_empty() { return Err("listed, but no sound chain".into()); }
                one_of(&n, b"/BOOTMETA.B", img, &[Some(&data[..])])
            });
        assert_eq!(f, 4, "create: journal barrier, data barrier, extension barrier, final flush");
    }

    #[test]
    fn a_create_cut_anywhere_leaves_nothing_or_the_whole_file() {
        let _g = serial();
        let n = name(b"REC", b"DAT");
        let old = pattern(OLD, 0x11);
        let f = cut_everywhere(fresh_image(),
            || assert_eq!(fat32::fat32_write_file(&n, &old), Ok(())),
            |img| one_of(&n, b"/REC.DAT", img, &[None, Some(&old[..])]));
        assert_eq!(f, 3, "create: journal barrier, data barrier, final flush");
    }

    #[test]
    fn an_overwrite_cut_anywhere_leaves_the_old_or_the_new_file() {
        let _g = serial();
        let n = name(b"REC", b"DAT");
        let old = pattern(OLD, 0x11);
        let new = pattern(NEW, 0x77);
        let f = cut_everywhere(with_file(&n, &old),
            || assert_eq!(fat32::fat32_write_file(&n, &new), Ok(())),
            |img| one_of(&n, b"/REC.DAT", img, &[Some(&old[..]), Some(&new[..])]));
        // + the write-back of the old chain's free, held until the final
        // flush made the cleared record durable (`defer_free`).
        assert_eq!(f, 5, "overwrite: chain, record and mutation barriers + final flush + the free");
    }

    #[test]
    fn an_unlink_cut_anywhere_leaves_the_file_or_nothing() {
        let _g = serial();
        let n = name(b"REC", b"DAT");
        let old = pattern(OLD, 0x11);
        let f = cut_everywhere(with_file(&n, &old),
            || assert_eq!(fat32::fat32_unlink_path(b"REC.DAT"), Ok(())),
            |img| one_of(&n, b"/REC.DAT", img, &[Some(&old[..]), None]));
        // Write-back: the journal clear left queued goes out in a third
        // epoch, after the mutation's flush, with the write-back's own flush.
        assert_eq!(f, 3, "unlink: record barrier + mutation barrier + the clear's write-back");
    }

    #[test]
    fn a_truncating_open_cut_anywhere_leaves_the_old_or_an_empty_file() {
        let _g = serial();
        let n = name(b"REC", b"DAT");
        let old = pattern(OLD, 0x11);
        let f = cut_everywhere(with_file(&n, &old),
            || {
                let h = fat32::fat32_open(fat32::Volume::assume_mounted(), b"/REC.DAT",
                    fat32::open_flags::WRITE | fat32::open_flags::TRUNCATE).expect("open");
                assert_eq!(fat32::fat32_close(h), Ok(()));
            },
            |img| one_of(&n, b"/REC.DAT", img, &[Some(&old[..]), Some(&b""[..])]));
        assert_eq!(f, 5, "truncate: 2 barriers, close's fsync (2 flushes), the held chain's free");
    }

    #[test]
    fn a_rename_over_a_file_cut_anywhere_never_loses_the_source() {
        let _g = serial();
        let a = name(b"LIVE", b"BIN");
        let b = name(b"STAGE", b"BIN");
        let old = pattern(OLD, 0x11);
        let new = pattern(NEW, 0x77);
        let _ = with_file(&a, &old);
        assert_eq!(fat32::fat32_write_file(&b, &new), Ok(()));
        let pristine = disk_durable_image();
        let f = cut_everywhere(pristine,
            || assert_eq!(fat32::fat32_rename(&b, &a), Ok(())),
            |img| {
                let live = read_back(b"/LIVE.BIN");
                let stage = read_back(b"/STAGE.BIN");
                one_of(&a, b"/LIVE.BIN", img, &[Some(&old[..]), Some(&new[..])])?;
                one_of(&b, b"/STAGE.BIN", img, &[Some(&new[..]), None])?;
                if live.as_deref() == Some(&old[..]) && stage.is_none() {
                    return Err("both names lost the new image".into());
                }
                // Wave 15: one RENAME record — never both names on the new
                // image's chain (two names on one chain cross-link it the
                // moment either is freed).
                if live.as_deref() == Some(&new[..]) && stage.is_some() {
                    return Err("both names on one chain".into());
                }
                Ok(())
            });
        println!("rename over a file: {f} flushes");
    }

    /// **Wave 15: an in-place rewrite through the VFS (O_TRUNC, write,
    /// fsync), cut anywhere**: the old file, an empty one, or the whole new
    /// one — never a size over bytes the device does not hold, never a live
    /// chain through a free cluster. (No atomic replace: that is a temp file
    /// and a rename, `a_rename_over_a_file_cut_anywhere_never_loses_the_source`.)
    #[test]
    fn an_in_place_rewrite_cut_anywhere_leaves_old_empty_or_new() {
        let _g = serial();
        let n = name(b"REC", b"DAT");
        let old = pattern(OLD, 0x11);
        let new = pattern(NEW, 0x77);
        let f = cut_everywhere(with_file(&n, &old),
            || {
                super::vfs_open_close::vfs_once();
                let mut t = super::vfs::ScratchFds::new();
                let fd = super::vfs::vfs_open(&mut t, b"/fat/REC.DAT",
                    super::vfs::O_WRONLY | super::vfs::O_TRUNC);
                assert!(fd >= 0);
                assert_eq!(super::vfs::vfs_write(&mut t, fd, new.as_ptr(), new.len()), new.len() as i32);
                assert_eq!(super::vfs::vfs_fsync(&mut t, fd), Ok(()));
                assert_eq!(super::vfs::vfs_close(&mut t, fd), 0);
            },
            |img| one_of(&n, b"/REC.DAT", img, &[Some(&old[..]), Some(&b""[..]), Some(&new[..])]));
        println!("in-place rewrite: {f} flushes");
    }

    /// Open `/fat/REC.DAT` with `O_TRUNC`, write `data`, fsync, close.
    /// Returns the device flushes before the fsync and those of the fsync.
    fn rewrite_in_place(data: &[u8]) -> (usize, usize) {
        let _ = disk_take_log();
        rewrite_in_place_counting(data, &|| disk_take_log().iter().filter(|e| **e == LogEntry::Flush).count())
    }

    /// [`rewrite_in_place`] with the flush counter given (`cut_everywhere`
    /// needs the log left alone).
    fn rewrite_in_place_counting(data: &[u8], flushes: &dyn Fn() -> usize) -> (usize, usize) {
        super::vfs_open_close::vfs_once();
        let mut t = super::vfs::ScratchFds::new();
        let fd = super::vfs::vfs_open(&mut t, b"/fat/REC.DAT", super::vfs::O_WRONLY | super::vfs::O_TRUNC);
        assert!(fd >= 0);
        assert_eq!(super::vfs::vfs_write(&mut t, fd, data.as_ptr(), data.len()), data.len() as i32);
        let before = flushes();
        assert_eq!(super::vfs::vfs_fsync(&mut t, fd), Ok(()));
        let fsync = flushes();
        assert_eq!(super::vfs::vfs_close(&mut t, fd), 0);
        assert_eq!(flushes(), 0, "close does no I/O");
        (before, fsync)
    }

    /// **Wave 15 (FD): the fsync of an in-place rewrite is two device
    /// flushes** (it was three): the truncated chain is held, not freed one
    /// epoch after the entry, so the entry, the new chain and the data
    /// share one epoch and the new entry is the second. The held chain is
    /// freed by the fsync's flush into the next epoch, which the NEXT
    /// rewrite's fsync carries: two again, no flush of its own.
    #[test]
    fn an_in_place_rewrite_fsync_issues_two_flushes() {
        let _g = serial();
        let n = name(b"REC", b"DAT");
        let old = pattern(OLD, 0x11);
        let new = pattern(NEW, 0x77);
        let newer = pattern(OLD, 0x33);
        remount(with_file(&n, &old));
        let free0 = super::vfs::vfs_statfs(b"/fat").expect("statfs").blocks_free;
        assert_eq!(rewrite_in_place(&new), (0, 2), "first rewrite: (before fsync, fsync) flushes");
        assert_eq!(fat32::fat32_held_clusters(), 0, "the fsync's flush freed the held chain");
        assert_eq!(rewrite_in_place(&newer), (0, 2), "second rewrite carries the first one's free");
        assert_eq!(read_back(b"/REC.DAT").as_deref(), Some(&newer[..]));
        assert_eq!(fat32::fat32_writeback_now(), Ok(()));
        let free1 = super::vfs::vfs_statfs(b"/fat").expect("statfs").blocks_free;
        assert_eq!(free1, free0, "every chain the rewrites took away is free again");
    }

    /// Open `/fat/REC.DAT` with `O_TRUNC` and write `data` in `n` `write`
    /// calls, then fsync and close. Returns the cache epochs the writes
    /// opened, the distinct epochs among the dirty lines before the fsync,
    /// and the device flushes of the fsync (0 unless `count`:
    /// `cut_everywhere` needs the log left alone).
    fn n_writes_then_fsync(data: &[u8], n: usize, count: bool) -> (u64, usize, usize) {
        super::vfs_open_close::vfs_once();
        let mut t = super::vfs::ScratchFds::new();
        let fd = super::vfs::vfs_open(&mut t, b"/fat/REC.DAT", super::vfs::O_WRONLY | super::vfs::O_TRUNC);
        assert!(fd >= 0);
        let e0 = fat32::fat32_cache_epoch();
        let step = data.len().div_ceil(n);
        for c in data.chunks(step) {
            assert_eq!(super::vfs::vfs_write(&mut t, fd, c.as_ptr(), c.len()), c.len() as i32);
        }
        let opened = fat32::fat32_cache_epoch() - e0;
        let dirty = fat32::fat32_dirty_epochs();
        if count { let _ = disk_take_log(); }
        assert_eq!(super::vfs::vfs_fsync(&mut t, fd), Ok(()));
        let fsync = if count { disk_take_log().iter().filter(|e| **e == LogEntry::Flush).count() } else { 0 };
        assert_eq!(super::vfs::vfs_close(&mut t, fd), 0);
        (opened, dirty, fsync)
    }

    /// **Wave 15 (FW): consecutive writes to one open file share one
    /// epoch.** Eight `write` calls open no epoch; the dirty lines before
    /// the fsync are two epochs (the data, the chain and the truncating
    /// entry; then the entry naming the new size, written once), and the
    /// fsync is two device flushes, as for one write. Before FW every write
    /// closed an epoch for its own entry update: 8, 9 and 9.
    #[test]
    fn eight_writes_share_one_epoch_and_one_entry_update() {
        let _g = serial();
        let n = name(b"REC", b"DAT");
        let old = pattern(OLD, 0x11);
        let new = pattern(800, 0x77);
        remount(with_file(&n, &old));
        let (opened, dirty, fsync) = n_writes_then_fsync(&new, 8, true);
        println!("8 writes: {opened} epochs opened, {dirty} dirty epochs, {fsync} fsync flushes");
        assert_eq!((opened, dirty, fsync), (0, 2, 2), "(epochs opened, dirty epochs, fsync flushes)");
        assert_eq!(read_back(b"/REC.DAT").as_deref(), Some(&new[..]));
    }

    /// **Eight writes, cut anywhere: the old file or a prefix of the new
    /// one the entry names whole** — never an entry over clusters the
    /// device does not have (`one_of` checks the chain against the size).
    #[test]
    fn eight_writes_cut_anywhere_leave_old_empty_or_new() {
        let _g = serial();
        let n = name(b"REC", b"DAT");
        let old = pattern(OLD, 0x11);
        let new = pattern(800, 0x77);
        let f = cut_everywhere(with_file(&n, &old),
            || { let _ = n_writes_then_fsync(&new, 8, false); },
            |img| {
                // A write is not atomic: any prefix the entry names whole is
                // legal (since FW only the empty file or the whole one occur).
                let prefixes: Vec<Vec<u8>> = (0..=8).map(|k| new[..k * 100].to_vec()).collect();
                let mut legal: Vec<Option<&[u8]>> = vec![Some(&old[..])];
                legal.extend(prefixes.iter().map(|p| Some(&p[..])));
                one_of(&n, b"/REC.DAT", img, &legal)
            });
        println!("eight writes: {f} flushes");
    }

    /// **Eight appends to a new file without fsync, cut anywhere** (the
    /// write-back writes them): nothing, or a prefix the entry names whole
    /// — never an entry over clusters the device does not have.
    #[test]
    fn eight_appends_to_a_new_file_cut_anywhere_leave_nothing_empty_or_all() {
        let _g = serial();
        let n = name(b"NEW", b"DAT");
        let new = pattern(800, 0x5A);
        let mut pristine = fresh_image();
        {
            remount(pristine.clone());
            pristine = disk_durable_image();
        }
        let f = cut_everywhere(pristine,
            || {
                super::vfs_open_close::vfs_once();
                let mut t = super::vfs::ScratchFds::new();
                let fd = super::vfs::vfs_open(&mut t, b"/fat/NEW.DAT",
                    super::vfs::O_WRONLY | super::vfs::O_CREAT);
                assert!(fd >= 0);
                for c in new.chunks(100) {
                    assert_eq!(super::vfs::vfs_write(&mut t, fd, c.as_ptr(), c.len()), c.len() as i32);
                }
                assert_eq!(super::vfs::vfs_close(&mut t, fd), 0);
            },
            |img| {
                let prefixes: Vec<Vec<u8>> = (0..=8).map(|k| new[..k * 100].to_vec()).collect();
                let mut legal: Vec<Option<&[u8]>> = vec![None];
                legal.extend(prefixes.iter().map(|p| Some(&p[..])));
                one_of(&n, b"/NEW.DAT", img, &legal)
            });
        println!("eight appends: {f} flushes");
    }

    /// The vsbench `file-write 4K` lane on the host: `iters` times create
    /// or truncate, write 4 KiB, close, no fsync; then the write-back.
    /// Returns (epochs opened, device writes, device flushes) of the whole
    /// run, the write-back included.
    fn lane_file_write(iters: usize) -> (u64, usize, usize) {
        super::vfs_open_close::vfs_once();
        let data = [0xA5u8; 4096];
        let _ = disk_take_log();
        let e0 = fat32::fat32_cache_epoch();
        for _ in 0..iters {
            let mut t = super::vfs::ScratchFds::new();
            let fd = super::vfs::vfs_open(&mut t, b"/fat/VSBW.DAT",
                super::vfs::O_WRONLY | super::vfs::O_CREAT | super::vfs::O_TRUNC);
            assert!(fd >= 0);
            assert_eq!(super::vfs::vfs_write(&mut t, fd, data.as_ptr(), data.len()), 4096);
            assert_eq!(super::vfs::vfs_close(&mut t, fd), 0);
        }
        let opened = fat32::fat32_cache_epoch() - e0;
        for _ in 0..4 {
            if fat32::fat32_writeback_dirty().0 == 0 { break; }
            assert_eq!(fat32::fat32_writeback_now(), Ok(()));
        }
        let log = disk_take_log();
        let flushes = log.iter().filter(|e| **e == LogEntry::Flush).count();
        (opened, log.len() - flushes, flushes)
    }

    /// **The lane's I/O shape** (`--nocapture` prints it): 40 iterations on
    /// the 256-sector test volume (512-byte clusters: 8 per iteration).
    /// Before FW: 71 epochs opened, 444 device writes, 73 flushes (a
    /// barrier per write for its entry, and one per truncate once the
    /// `FS_DEFERRED_FREE_SLOTS` holds were taken). Now the truncate's entry
    /// and the write's go ahead, and a full hold table is emptied by one
    /// barrier: two epochs per `FS_DEFERRED_FREE_SLOTS + 1` iterations.
    #[test]
    fn the_file_write_lane_io_shape() {
        let _g = serial();
        remount(fresh_image());
        let (opened, writes, flushes) = lane_file_write(40);
        println!("file-write lane x40: {opened} epochs opened, {writes} device writes, {flushes} flushes");
        let bound = 2 * 40u64.div_ceil(azos_limits::FS_DEFERRED_FREE_SLOTS as u64 + 1);
        assert!(opened <= bound, "{opened} epochs opened for 40 rewrites, bound {bound}");
        assert!(flushes as u64 <= bound + 3, "{flushes} flushes for 40 rewrites");
    }

    /// **A full hold table closes epochs, no device I/O** (FW2): two more
    /// truncate + write + close of one file than `FS_DEFERRED_FREE_SLOTS`,
    /// no fsync. The first past the table takes the full-table path (one
    /// barrier, then every held chain freed into the next epoch), and none
    /// of it reaches the device before the write-back.
    ///
    /// **Canary.** `wb-barrier-flushes-canary`: every barrier FAT32 puts
    /// between its own writes flushes, the full-table one included.
    #[test]
    fn a_full_hold_table_frees_without_device_io() {
        let _g = serial();
        let n = name(b"REC", b"DAT");
        remount(with_file(&n, &pattern(OLD, 0x11)));
        super::vfs_open_close::vfs_once();
        let v = pattern(400, 0x42); // one 512-byte cluster per version
        let _ = disk_events();
        for _ in 0..azos_limits::FS_DEFERRED_FREE_SLOTS + 2 {
            let mut t = super::vfs::ScratchFds::new();
            let fd = super::vfs::vfs_open(&mut t, b"/fat/REC.DAT",
                super::vfs::O_WRONLY | super::vfs::O_TRUNC);
            assert!(fd >= 0);
            assert_eq!(super::vfs::vfs_write(&mut t, fd, v.as_ptr(), v.len()), v.len() as i32);
            assert_eq!(super::vfs::vfs_close(&mut t, fd), 0);
        }
        let ev = disk_events();
        // The full-table path ran: it emptied the table, and only the last
        // truncate's one-cluster chain is held now.
        assert_eq!(fat32::fat32_held_clusters(), 1, "the full-table path did not run");
        assert!(ev.is_empty(), "past the hold table the truncates touched the device: {ev:?}");
        assert_eq!(fat32::fat32_sync(), Ok(()));
        assert_eq!(read_back(b"/REC.DAT").as_deref(), Some(&v[..]));
    }

    /// **A write of n clusters reads the chain once** (wave 15, FW): one
    /// 8 KiB `write` to a new file (16 clusters of 512 B) looks up O(n)
    /// sectors in the cache: 80. Walking the chain from its first cluster
    /// for every sector (16 * 15 / 2 = 120 FAT reads), and rewriting each
    /// new cluster's end-of-chain mark, made it 200. Canary:
    /// `fw-chain-walk-canary`.
    #[test]
    fn a_write_of_n_clusters_reads_the_chain_once() {
        let _g = serial();
        remount(fresh_image());
        super::vfs_open_close::vfs_once();
        let data = pattern(16 * 512, 0x21);
        let mut t = super::vfs::ScratchFds::new();
        let fd = super::vfs::vfs_open(&mut t, b"/fat/BIG.DAT", super::vfs::O_WRONLY | super::vfs::O_CREAT);
        assert!(fd >= 0);
        let c0 = fat32::fat32_cache_counters();
        assert_eq!(super::vfs::vfs_write(&mut t, fd, data.as_ptr(), data.len()), data.len() as i32);
        let c1 = fat32::fat32_cache_counters();
        assert_eq!(super::vfs::vfs_close(&mut t, fd), 0);
        let lookups = (c1.hits + c1.misses) - (c0.hits + c0.misses);
        println!("16-cluster write: {lookups} cache lookups");
        assert!(lookups <= 100, "{lookups} cache lookups for a 16-cluster write");
        assert_eq!(read_back(b"/BIG.DAT").as_deref(), Some(&data[..]));
    }

    /// **The lane's loop, cut anywhere**: twelve truncate + write + close
    /// of one file, no fsync, past the hold table (8 slots), then the
    /// write-back. A cut leaves the old file, an empty one, or one of the
    /// versions written, whole — never an entry over a chain that was
    /// freed or not written.
    #[test]
    fn a_truncate_rewrite_loop_cut_anywhere_leaves_a_whole_version() {
        let _g = serial();
        let n = name(b"REC", b"DAT");
        let old = pattern(OLD, 0x11);
        let versions: Vec<Vec<u8>> = (0..12u8).map(|i| pattern(400, 0x40 + i)).collect();
        let f = cut_everywhere(with_file(&n, &old),
            || {
                super::vfs_open_close::vfs_once();
                for v in &versions {
                    let mut t = super::vfs::ScratchFds::new();
                    let fd = super::vfs::vfs_open(&mut t, b"/fat/REC.DAT",
                        super::vfs::O_WRONLY | super::vfs::O_TRUNC);
                    assert!(fd >= 0);
                    assert_eq!(super::vfs::vfs_write(&mut t, fd, v.as_ptr(), v.len()), v.len() as i32);
                    assert_eq!(super::vfs::vfs_close(&mut t, fd), 0);
                }
            },
            |img| {
                let mut legal: Vec<Option<&[u8]>> = vec![Some(&old[..]), Some(&b""[..])];
                legal.extend(versions.iter().map(|v| Some(&v[..])));
                one_of(&n, b"/REC.DAT", img, &legal)
            });
        println!("truncate-rewrite loop: {f} flushes");
    }

    /// **A held chain is not reused, and statfs counts it free.** After the
    /// truncate statfs reports the old chain's clusters as free; the write
    /// that follows (before any flush) allocates around them; the fsync's
    /// flush frees them, and the write-back after it puts the frees on the
    /// medium.
    #[test]
    fn a_held_chain_is_not_reused_and_statfs_counts_it_free() {
        let _g = serial();
        let n = name(b"REC", b"DAT");
        let old = pattern(OLD, 0x11);
        let new = pattern(NEW, 0x77);
        let img = with_file(&n, &old);
        let old_chain = chain(&img, &n).expect("sound");
        remount(img);
        super::vfs_open_close::vfs_once();
        let free0 = super::vfs::vfs_statfs(b"/fat").expect("statfs").blocks_free;
        let mut t = super::vfs::ScratchFds::new();
        let fd = super::vfs::vfs_open(&mut t, b"/fat/REC.DAT", super::vfs::O_WRONLY | super::vfs::O_TRUNC);
        assert!(fd >= 0);
        assert_eq!(fat32::fat32_held_clusters() as usize, old_chain.len());
        assert_eq!(super::vfs::vfs_statfs(b"/fat").expect("statfs").blocks_free,
            free0 + old_chain.len() as u64, "held clusters count as free");
        assert_eq!(super::vfs::vfs_write(&mut t, fd, new.as_ptr(), new.len()), new.len() as i32);
        assert_eq!(super::vfs::vfs_fsync(&mut t, fd), Ok(()));
        assert_eq!(super::vfs::vfs_close(&mut t, fd), 0);
        assert_eq!(fat32::fat32_held_clusters(), 0, "the fsync's flush freed it");
        let after = disk_durable_image();
        let new_chain = chain(&after, &n).expect("sound");
        assert!(new_chain.iter().all(|c| !old_chain.contains(c)),
            "the write reused a held cluster: old {old_chain:?}, new {new_chain:?}");
        assert!(old_chain.iter().all(|&c| fat(&after, c) != 0), "premise: frees not written yet");
        assert_eq!(fat32::fat32_writeback_now(), Ok(()));
        let after = disk_durable_image();
        assert!(old_chain.iter().all(|&c| fat(&after, c) == 0), "the held chain's free reached the medium");
    }

    /// The `REC.DAT` image with every free data cluster taken (leaked
    /// single-cluster chains): the only room is the file's own chain.
    fn full_volume_with_file(n83: &[u8; 11], data: &[u8]) -> Vec<u8> {
        let g = Geom::default();
        let mut img = with_file(n83, data);
        let data_start = g.rsvd as usize + g.num_fats as usize * g.fat_sz32 as usize;
        let clusters = (g.total_sectors - data_start) / g.spc as usize;
        for c in 2..(2 + clusters) as u32 {
            if fat(&img, c) == 0 { set_fat(&mut img, &g, c, 0x0FFF_FFFF); }
        }
        img
    }

    /// **Disk full while a chain is held: the allocation flushes once,
    /// frees it and goes on** (never ENOSPC for space statfs reported), and
    /// every cut is the old file, an empty one or the new one, whole.
    #[test]
    fn an_in_place_rewrite_of_a_full_volume_flushes_once_more_instead_of_enospc() {
        let _g = serial();
        let n = name(b"REC", b"DAT");
        let old = pattern(OLD, 0x11);
        let new = pattern(NEW, 0x77);
        let img = full_volume_with_file(&n, &old);
        remount(img.clone());
        super::vfs_open_close::vfs_once();
        assert_eq!(super::vfs::vfs_statfs(b"/fat").expect("statfs").blocks_free, 0, "premise: full");
        assert_eq!(rewrite_in_place(&new), (1, 2), "one forced flush, then the fsync's two");
        assert_eq!(read_back(b"/REC.DAT").as_deref(), Some(&new[..]));
        let f = cut_everywhere(img,
            || { let _ = rewrite_in_place_counting(&new, &|| 0); },
            |img| one_of(&n, b"/REC.DAT", img, &[Some(&old[..]), Some(&b""[..]), Some(&new[..])]));
        println!("full-volume in-place rewrite: {f} flushes");
    }

    #[test]
    fn a_rename_to_a_new_name_cut_anywhere_keeps_at_least_one_name() {
        let _g = serial();
        let a = name(b"LIVE", b"BIN");
        let b = name(b"STAGE", b"BIN");
        let new = pattern(NEW, 0x77);
        let f = cut_everywhere(with_file(&b, &new),
            || assert_eq!(fat32::fat32_rename(&b, &a), Ok(())),
            |img| {
                one_of(&a, b"/LIVE.BIN", img, &[Some(&new[..]), None])?;
                one_of(&b, b"/STAGE.BIN", img, &[Some(&new[..]), None])?;
                let (l, s) = (read_back(b"/LIVE.BIN"), read_back(b"/STAGE.BIN"));
                if l.is_none() && s.is_none() {
                    return Err("neither name survived".into());
                }
                // Wave 15: an in-place rename of the dirent — exactly one.
                if l.is_some() && s.is_some() {
                    return Err("both names on one chain".into());
                }
                Ok(())
            });
        assert_eq!(f, 1, "rename to a new name: one dirent sector, then the write-back's flush");
    }

    /// The gate row's probe (`fat32_check_root_chain`) must itself see a
    /// dirent over a freed cluster, which reads back fine until reuse.
    #[test]
    fn the_chain_probe_sees_a_live_chain_through_a_free_cluster() {
        let _g = serial();
        let n = name(b"REC", b"DAT");
        let old = pattern(OLD, 0x11);
        let img = with_file(&n, &old);
        remount(img.clone());
        let (first, size) = fat32::fat32_check_root_chain(&n).expect("sound").expect("present");
        assert_eq!(size as usize, OLD);
        assert!(fat32::fat32_journal_idle());
        // Free the LAST cluster (its FAT entry EOC -> 0): every byte of the
        // file still reads back through the chain, which never follows that
        // entry, so only the structural probe can see it.
        let last = fat(&img, fat(&img, first));
        let mut bad = img.clone();
        let off = Geom::default().rsvd as usize * SECTOR + last as usize * 4;
        bad[off..off + 4].copy_from_slice(&0u32.to_le_bytes());
        remount(bad);
        let mut buf = vec![0u8; OLD];
        assert_eq!(fat32::fat32_read_chain(first, &mut buf), OLD);
        assert_eq!(buf, old, "premise: the content check alone passes");
        assert_eq!(fat32::fat32_check_root_chain(&n), Err("a live chain runs through a FREE cluster"));
        assert_eq!(fat32::fat32_check_root_chain(&name(b"NONE", b"")), Ok(None));
    }

    /// A device that cannot flush (`Unsupported`) gives no ordering, so a
    /// journaled operation refuses at its first barrier (owner decision,
    /// wave 7): nothing it would have ordered is written.
    #[test]
    fn a_barrier_over_a_device_that_cannot_flush_refuses() {
        let _g = serial();
        let _wt = crate::write_through();
        let n = name(b"REC", b"DAT");
        let old = pattern(OLD, 0x11);
        let before = with_file(&n, &old);
        remount(before.clone());
        fs_test_drivers::disk_flush_mode(fs_test_drivers::FlushMode::Unsupported);
        let _ = disk_events();
        let journal = DiskEvent::Write(fat32::JOURNAL_SECTOR as u64);

        // Overwrite: refused before its PENDING record.
        assert_eq!(fat32::fat32_write_file(&n, &pattern(NEW, 0x77)), Err(()));
        assert!(!disk_events().contains(&journal), "overwrite wrote its record past the barrier");
        // Create: the PENDING record is written, nothing after it.
        let m = name(b"NEW", b"DAT");
        assert_eq!(fat32::fat32_write_file(&m, &pattern(NEW, 0x77)), Err(()));
        let ev = disk_events();
        // Write-back writes the barrier's epoch in block order, so the
        // record need not be last; what must hold is that nothing of the
        // next step (a directory or data sector) went out: only the record
        // and the FAT sectors the allocation before it dirtied.
        let g = Geom::default();
        let fat_end = (g.rsvd as u64) + g.num_fats as u64 * g.fat_sz32 as u64;
        assert!(ev.contains(&journal), "create never wrote its record: {ev:?}");
        assert!(ev.iter().all(|e| *e == journal
            || matches!(e, DiskEvent::Write(s) if (g.rsvd as u64..fat_end).contains(s))),
            "create wrote past its first barrier: {ev:?}");
        // Unlink: the dirent survives.
        assert_eq!(fat32::fat32_unlink_path(b"REC.DAT"), Err(()));

        fs_test_drivers::disk_flush_mode(fs_test_drivers::FlushMode::Ok);
        remount(disk_durable_image());
        assert_eq!(read_back(b"/REC.DAT").as_deref(), Some(&old[..]));
        assert_eq!(read_back(b"/NEW.DAT"), None);
        assert_eq!(dirent(&disk_durable_image(), &n), dirent(&before, &n));
    }

    /// A barrier that cannot confirm fails the operation closed: nothing
    /// after it reaches the device.
    #[test]
    fn a_failed_barrier_stops_the_overwrite_before_the_old_file_is_touched() {
        let _g = serial();
        let n = name(b"REC", b"DAT");
        let old = pattern(OLD, 0x11);
        remount(with_file(&n, &old));
        let before = disk_durable_image();
        let _ = disk_events();
        fs_test_drivers::disk_flush_mode(fs_test_drivers::FlushMode::Io);
        assert_eq!(fat32::fat32_write_file(&n, &pattern(NEW, 0x77)), Err(()));
        let ev = disk_events();
        assert!(!ev.contains(&DiskEvent::Write(fat32::JOURNAL_SECTOR as u64)),
            "the journal record was written past a failed barrier: {ev:?}");
        fs_test_drivers::disk_flush_mode(fs_test_drivers::FlushMode::Ok);
        remount(disk_durable_image());
        assert_eq!(dirent(&disk_durable_image(), &n), dirent(&before, &n));
        assert_eq!(read_back(b"/REC.DAT").as_deref(), Some(&old[..]));
    }
}

// ── The shared block cache (RFC-0048 P1) ─────────────────────────────────────
//
// `bcache.rs` driven directly against a recording device: every read, write
// and flush the cache issues is logged in order, so LRU choice, dirty
// tracking and the epoch ordering rule are asserted on the device's view,
// not on the cache's own bookkeeping.
#[cfg(test)]
mod bcache_tests {
    use super::bcache::{BlockCache, BlockIo, CacheStats, ConfigError, IoError, Mode};

    #[derive(Clone, Debug, PartialEq, Eq)]
    enum Ev { R(u64, u32), W(u64, u32, u8), F }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct FlushFailed;

    struct Dev {
        data: Vec<u8>,
        log: Vec<Ev>,
        fail_writes: bool,
        fail_flush: bool,
    }

    impl Dev {
        fn new(sectors: usize) -> Self {
            let data = (0..sectors * 512).map(|i| (i / 512) as u8).collect();
            Dev { data, log: Vec::new(), fail_writes: false, fail_flush: false }
        }
        fn take(&mut self) -> Vec<Ev> { core::mem::take(&mut self.log) }
    }

    impl BlockIo for Dev {
        type FlushErr = FlushFailed;
        fn read(&mut self, lba: u64, count: u32, buf: &mut [u8]) -> Result<(), ()> {
            let off = lba as usize * 512;
            let len = count as usize * 512;
            if buf.len() != len || off + len > self.data.len() { return Err(()); }
            buf.copy_from_slice(&self.data[off..off + len]);
            self.log.push(Ev::R(lba, count));
            Ok(())
        }
        fn write(&mut self, lba: u64, count: u32, buf: &[u8]) -> Result<(), ()> {
            if self.fail_writes { return Err(()); }
            let off = lba as usize * 512;
            let len = count as usize * 512;
            if buf.len() != len || off + len > self.data.len() { return Err(()); }
            self.data[off..off + len].copy_from_slice(buf);
            self.log.push(Ev::W(lba, count, buf[0]));
            Ok(())
        }
        fn flush(&mut self) -> Result<(), FlushFailed> {
            if self.fail_flush { return Err(FlushFailed); }
            self.log.push(Ev::F);
            Ok(())
        }
    }

    fn blk(size: usize, fill: u8) -> Vec<u8> { vec![fill; size] }

    /// **LRU, counted.** Four 512 B lines; after 0..3 are read and 0 is
    /// touched again, reading 4 must evict 1 (the least recently used), not
    /// 0. Hits and misses are counted on the way.
    ///
    /// **Canary.** Pick the MOST recently used clean line in `pick_victim`
    /// (`t.last_use > b`): block 0 is evicted and its re-read goes to the
    /// device, so the event assertion fails.
    #[test]
    fn lru_evicts_the_least_recently_used_line_and_counts() {
        let mut dev = Dev::new(64);
        let mut c: BlockCache<2048, 4> = BlockCache::new(512, Mode::WriteThrough);
        let mut b = blk(512, 0);
        for n in 0..4 { c.read(&mut dev, n, &mut b).unwrap(); }
        c.read(&mut dev, 0, &mut b).unwrap();
        assert_eq!(b[0], 0);
        dev.take();
        c.read(&mut dev, 4, &mut b).unwrap();
        c.read(&mut dev, 0, &mut b).unwrap();
        c.read(&mut dev, 1, &mut b).unwrap();
        assert_eq!(dev.take(), vec![Ev::R(4, 1), Ev::R(1, 1)], "block 0 was evicted instead of 1");
        assert_eq!(c.stats(), CacheStats { hits: 2, misses: 6, writebacks: 0, ordering_flushes: 0 });
    }

    /// **1 KiB and 4 KiB blocks address the right sectors**, from a base LBA
    /// (a partition start), and a block size that does not tile the storage
    /// is refused.
    ///
    /// **Canary.** Drop `base_lba` from `lba_of`: the 4 KiB read lands at
    /// LBA 16, not 116.
    #[test]
    fn one_and_four_kib_blocks_map_to_the_right_lbas() {
        let mut dev = Dev::new(256);
        let mut c: BlockCache<8192, 8> = BlockCache::new(1024, Mode::WriteBack);
        assert_eq!(c.line_count(), 8);
        let mut b = blk(1024, 0);
        c.read(&mut dev, 3, &mut b).unwrap();
        assert_eq!((b[0], b[512]), (6, 7), "1 KiB block 3 is sectors 6 and 7");
        c.configure(4096, Mode::WriteBack, 100).unwrap();
        assert_eq!(c.line_count(), 2);
        let mut b4 = blk(4096, 0);
        c.read(&mut dev, 2, &mut b4).unwrap();
        assert_eq!(dev.take(), vec![Ev::R(6, 2), Ev::R(116, 8)]);
        assert_eq!(b4[0], 116);
        assert_eq!(c.configure(3000, Mode::WriteBack, 0), Err(ConfigError::BadBlockSize));
        assert_eq!(c.configure(512, Mode::WriteBack, 0), Err(ConfigError::BadBlockSize),
                   "16 lines of 512 B do not fit 8 tags");
        assert_eq!(c.configure(8192, Mode::WriteBack, 0), Err(ConfigError::BadBlockSize));
        assert_eq!(c.read(&mut dev, 0, &mut blk(1024, 0)), Err(IoError::Range),
                   "a buffer of the wrong block size");
        assert_eq!(c.read(&mut dev, u64::MAX, &mut b4), Err(IoError::Range), "LBA overflow");
    }

    /// **Write-through (FAT32's mode)**: the device sees the write before the
    /// call returns, no line is ever dirty, a present line is updated and a
    /// write miss installs nothing.
    #[test]
    fn write_through_writes_at_once_and_never_dirties() {
        let mut dev = Dev::new(64);
        let mut c: BlockCache<2048, 4> = BlockCache::new(512, Mode::WriteThrough);
        let mut b = blk(512, 0);
        c.read(&mut dev, 1, &mut b).unwrap();
        dev.take();
        c.write(&mut dev, 1, &blk(512, 0xA1)).unwrap();
        c.write(&mut dev, 9, &blk(512, 0xA9)).unwrap();
        assert_eq!(dev.take(), vec![Ev::W(1, 1, 0xA1), Ev::W(9, 1, 0xA9)]);
        assert_eq!(c.dirty_count(), 0);
        c.read(&mut dev, 1, &mut b).unwrap();
        assert_eq!(b[0], 0xA1, "the present line was not updated");
        c.read(&mut dev, 9, &mut b).unwrap();
        assert_eq!(dev.take(), vec![Ev::R(9, 1)], "a write miss installed a line");
        c.sync(&mut dev).unwrap();
        assert_eq!(dev.take(), vec![Ev::F], "write-through sync is the flush alone");
    }

    /// **Write-back defers, and `sync` writes then flushes.**
    #[test]
    fn write_back_defers_until_sync_and_the_flush_comes_last() {
        let mut dev = Dev::new(64);
        let mut c: BlockCache<2048, 4> = BlockCache::new(512, Mode::WriteBack);
        c.write(&mut dev, 7, &blk(512, 0x77)).unwrap();
        c.write(&mut dev, 3, &blk(512, 0x33)).unwrap();
        assert!(dev.take().is_empty(), "write-back touched the device before sync");
        assert_eq!(c.dirty_count(), 2);
        let mut b = blk(512, 0);
        c.read(&mut dev, 7, &mut b).unwrap();
        assert_eq!(b[0], 0x77, "a dirty line must be readable before it is written");
        c.sync(&mut dev).unwrap();
        assert_eq!(dev.take(), vec![Ev::W(3, 1, 0x33), Ev::W(7, 1, 0x77), Ev::F]);
        assert_eq!(c.dirty_count(), 0);
        assert_eq!(c.stats().writebacks, 2);
    }

    /// **A barrier orders epochs, with a flush between them.** Blocks 5 and
    /// 6 are written before the barrier, block 1 after: block 1 must reach
    /// the device after a flush that follows 5 and 6, although it sorts
    /// first by number.
    ///
    /// **Canary.** Delete the ordering flush in `write_line` (the
    /// `if lo < t.epoch` arm): the sequence reads W5, W6, W1, F.
    #[test]
    fn a_barrier_orders_epochs_with_a_flush_between_them() {
        let mut dev = Dev::new(64);
        let mut c: BlockCache<2048, 4> = BlockCache::new(512, Mode::WriteBack);
        c.write(&mut dev, 5, &blk(512, 5)).unwrap();
        c.write(&mut dev, 6, &blk(512, 6)).unwrap();
        c.barrier();
        c.write(&mut dev, 1, &blk(512, 1)).unwrap();
        c.sync(&mut dev).unwrap();
        assert_eq!(dev.take(), vec![Ev::W(5, 1, 5), Ev::W(6, 1, 6), Ev::F, Ev::W(1, 1, 1), Ev::F]);
        assert_eq!(c.stats().ordering_flushes, 1);
    }

    /// **Eviction keeps the order too.** Two lines. Block 0 is dirtied in
    /// epoch 0, blocks 1 and 2 in epoch 1: writing 2 evicts 0 (oldest epoch,
    /// no flush needed), writing 3 then evicts 1, which may only follow a
    /// flush of block 0.
    ///
    /// **Canary.** Same deletion as above: the sequence reads W0, W1.
    #[test]
    fn evicting_a_later_epoch_is_preceded_by_a_flush() {
        let mut dev = Dev::new(64);
        let mut c: BlockCache<1024, 2> = BlockCache::new(512, Mode::WriteBack);
        c.write(&mut dev, 0, &blk(512, 0xA0)).unwrap();
        c.barrier();
        c.write(&mut dev, 1, &blk(512, 0xA1)).unwrap();
        c.write(&mut dev, 2, &blk(512, 0xA2)).unwrap();
        assert_eq!(dev.take(), vec![Ev::W(0, 1, 0xA0)]);
        c.write(&mut dev, 3, &blk(512, 0xA3)).unwrap();
        assert_eq!(dev.take(), vec![Ev::F, Ev::W(1, 1, 0xA1)]);
    }

    /// **Re-dirtying a block of an older, unwritten epoch writes its old
    /// contents first**, so the older epoch is complete on the device before
    /// the block moves forward.
    #[test]
    fn re_dirtying_an_older_epoch_writes_the_old_contents_first() {
        let mut dev = Dev::new(64);
        let mut c: BlockCache<2048, 4> = BlockCache::new(512, Mode::WriteBack);
        c.write(&mut dev, 4, &blk(512, 0x0A)).unwrap();
        c.barrier();
        c.write(&mut dev, 4, &blk(512, 0x0B)).unwrap();
        c.sync(&mut dev).unwrap();
        assert_eq!(dev.take(), vec![Ev::W(4, 1, 0x0A), Ev::F, Ev::W(4, 1, 0x0B), Ev::F]);
    }

    /// **A failed write-back keeps the line dirty and stops**: no flush and
    /// nothing of a later epoch follows it.
    #[test]
    fn a_failed_write_back_keeps_the_line_dirty_and_stops() {
        let mut dev = Dev::new(64);
        let mut c: BlockCache<2048, 4> = BlockCache::new(512, Mode::WriteBack);
        c.write(&mut dev, 2, &blk(512, 2)).unwrap();
        c.barrier();
        c.write(&mut dev, 3, &blk(512, 3)).unwrap();
        dev.fail_writes = true;
        assert_eq!(c.sync(&mut dev), Err(IoError::Io));
        assert!(dev.take().is_empty());
        assert_eq!(c.dirty_count(), 2);
        dev.fail_writes = false;
        dev.fail_flush = true;
        assert_eq!(c.sync(&mut dev), Err(IoError::Flush(FlushFailed)),
                   "the device's own reason must come back");
        assert_eq!(dev.take(), vec![Ev::W(2, 1, 2)], "epoch 1 was written past a failed ordering flush");
        dev.fail_flush = false;
        c.sync(&mut dev).unwrap();
        assert_eq!(dev.take(), vec![Ev::F, Ev::W(3, 1, 3), Ev::F]);
    }

    /// **Dirty data is never dropped silently.** `configure` refuses while a
    /// line is dirty; `invalidate`/`invalidate_all` say how much they drop.
    #[test]
    fn dirty_lines_are_not_dropped_silently() {
        let mut dev = Dev::new(64);
        let mut c: BlockCache<2048, 4> = BlockCache::new(512, Mode::WriteBack);
        c.write(&mut dev, 1, &blk(512, 1)).unwrap();
        c.write(&mut dev, 2, &blk(512, 2)).unwrap();
        assert_eq!(c.configure(1024, Mode::WriteBack, 0), Err(ConfigError::Dirty));
        assert!(c.invalidate(1));
        assert_eq!(c.invalidate_all(), 1);
        assert_eq!(c.configure(1024, Mode::WriteBack, 0), Ok(()));
    }

    /// **The split path does not cache a read that a write overtook.** A
    /// reader that missed, released the lock and read the device must not
    /// install its (stale) data if the block was written meanwhile.
    ///
    /// **Canary.** Remove `token != self.wseq` from `install`: the stale
    /// bytes are installed and the final lookup hits with them.
    #[test]
    fn install_with_a_stale_token_caches_nothing() {
        let mut c: BlockCache<2048, 4> = BlockCache::new(512, Mode::WriteThrough);
        let mut b = blk(512, 0);
        assert!(!c.lookup(8, &mut b));
        let token = c.lookup_miss_token();
        c.update_if_present(8, &blk(512, 0xEE));
        assert!(!c.install(8, &blk(512, 0x08), token), "stale data was installed");
        assert!(!c.lookup(8, &mut b));
        let token = c.lookup_miss_token();
        assert!(c.install(8, &blk(512, 0x08), token));
        assert!(c.lookup(8, &mut b));
        assert_eq!(b[0], 0x08);
        assert_eq!(c.stats().misses, 2);
    }
}

// ── Partition tables (RFC-0048 P3) ───────────────────────────────────────────
//
// Three fixtures made by tools other than this parser, so its reading is
// checked against an implementation it did not write:
//   * `mkfs_fat32_lba0.bin` — LBA 0 of `mkfs.fat -C -F 32 -n ROBTOS x 32768`,
//     the Makefile's recipe for every QEMU disk: a superfloppy, no table.
//   * `hdiutil_mbr_lba0.bin` — LBA 0 of `hdiutil create -size 8m -layout
//     MBRSPUD -fs MS-DOS`: one FAT32 (0x0B) partition, LBA 1 + 16383.
//   * `hdiutil_gpt_head.bin` — LBAs 0..33 of the same with `-layout GPTSPUD`:
//     protective MBR, GPT header, 128 x 128 B entries, one partition
//     2048..=14335. The medium is 16384 sectors.
// Everything malformed is derived from these by flipping named fields, with
// the CRCs recomputed when the test is about a field and not about a CRC.
#[cfg(test)]
mod partition_tests {
    use super::partition::{self, crc32_update, parse, PartError, Partition, Scheme, SECTOR};

    const MKFS_LBA0: &[u8] = include_bytes!("../fixtures/mkfs_fat32_lba0.bin");
    const MBR_LBA0: &[u8] = include_bytes!("../fixtures/hdiutil_mbr_lba0.bin");
    const GPT_HEAD: &[u8] = include_bytes!("../fixtures/hdiutil_gpt_head.bin");
    const HDIUTIL_CAP: u64 = 16384;

    /// A medium of `cap` sectors holding `head` at LBA 0, and a read count.
    struct Medium { img: Vec<u8>, reads: u32 }

    impl Medium {
        fn new(head: &[u8], cap: u64) -> Self {
            let mut img = vec![0u8; cap as usize * SECTOR];
            img[..head.len()].copy_from_slice(head);
            Medium { img, reads: 0 }
        }
        fn parse(&mut self, cap: u64) -> Result<partition::Table, PartError> {
            let img = &self.img;
            let reads = &mut self.reads;
            parse(cap, &mut |lba, buf: &mut [u8; SECTOR]| {
                *reads += 1;
                let o = lba as usize * SECTOR;
                if o + SECTOR > img.len() { return Err(()); }
                buf.copy_from_slice(&img[o..o + SECTOR]);
                Ok(())
            })
        }
    }

    fn le32_put(b: &mut [u8], o: usize, v: u32) { b[o..o + 4].copy_from_slice(&v.to_le_bytes()); }
    fn le64_put(b: &mut [u8], o: usize, v: u64) { b[o..o + 8].copy_from_slice(&v.to_le_bytes()); }

    /// Recompute the GPT entry-array CRC and then the header CRC.
    fn fix_gpt_crcs(img: &mut [u8]) {
        let h = 512;
        let n = u32::from_le_bytes(img[h + 80..h + 84].try_into().unwrap()) as usize;
        let es = u32::from_le_bytes(img[h + 84..h + 88].try_into().unwrap()) as usize;
        let lba = u64::from_le_bytes(img[h + 72..h + 80].try_into().unwrap()) as usize;
        // The helper must survive the fields the tests corrupt: an array
        // that lies outside the image keeps its old CRC.
        let arr = lba.checked_mul(512).and_then(|o| Some((o, o.checked_add(n.checked_mul(es)?)?)));
        if let Some((o, e)) = arr.filter(|&(_, e)| e <= img.len()) {
            let crc = crc32_update(0, &img[o..e]);
            le32_put(img, h + 88, crc);
        }
        le32_put(img, h + 16, 0);
        let hs = (u32::from_le_bytes(img[h + 12..h + 16].try_into().unwrap()) as usize).min(512);
        let hc = crc32_update(0, &img[h..h + hs]);
        le32_put(img, h + 16, hc);
    }

    fn mbr_entry(img: &mut [u8], i: usize, status: u8, ty: u8, start: u32, len: u32) {
        let o = 446 + 16 * i;
        img[o] = status;
        img[o + 4] = ty;
        le32_put(img, o + 8, start);
        le32_put(img, o + 12, len);
    }

    #[test]
    fn crc32_is_the_ieee_one() {
        assert_eq!(crc32_update(0, b"123456789"), 0xCBF4_3926);
        assert_eq!(crc32_update(crc32_update(0, b"1234"), b"56789"), 0xCBF4_3926,
                   "incremental and one-shot must agree");
    }

    /// **The gate image is not a table.** LBA 0 of every QEMU disk is a FAT32
    /// boot sector with `0x55AA`; it must parse as "no partitions", so no
    /// existing image gains a mintable partition. A FAT boot sector whose
    /// entry area holds bytes that WOULD be a valid entry is still a boot
    /// sector.
    ///
    /// **Canary.** Drop `is_fat_boot_sector` from `parse`'s first test: the
    /// crafted sector publishes one MBR partition.
    #[test]
    fn a_mkfs_fat_superfloppy_has_no_partitions() {
        let mut m = Medium::new(MKFS_LBA0, 65536);
        let t = m.parse(65536).unwrap();
        assert_eq!((t.scheme, t.count), (Scheme::None, 0));
        let mut crafted = MKFS_LBA0.to_vec();
        mbr_entry(&mut crafted, 0, 0x80, 0x0C, 2048, 4096);
        let t = Medium::new(&crafted, 65536).parse(65536).unwrap();
        assert_eq!((t.scheme, t.count), (Scheme::None, 0), "a FAT boot sector was read as a table");
        let mut blank = vec![0u8; 512];
        blank[510] = 0x55;
        blank[511] = 0xAA;
        blank[446] = 0x17; // boot code in the entry area, not a status byte
        let t = Medium::new(&blank, 64).parse(64).unwrap();
        assert_eq!(t.scheme, Scheme::None);
        let t = Medium::new(&[0u8; 512], 64).parse(64).unwrap();
        assert_eq!(t.scheme, Scheme::None, "no signature, no table");
    }

    #[test]
    fn an_hdiutil_mbr_reads_as_one_fat32_partition() {
        let t = Medium::new(MBR_LBA0, HDIUTIL_CAP).parse(HDIUTIL_CAP).unwrap();
        assert_eq!(t.scheme, Scheme::Mbr);
        assert_eq!(t.count, 1);
        assert_eq!(t.parts[0], Partition { start: 1, sectors: 16383, mbr_type: 0x0B });
    }

    /// **An hdiutil GPT reads as its one partition**, both CRCs checked.
    #[test]
    fn an_hdiutil_gpt_reads_as_one_partition() {
        let mut m = Medium::new(GPT_HEAD, HDIUTIL_CAP);
        let t = m.parse(HDIUTIL_CAP).unwrap();
        assert_eq!(t.scheme, Scheme::Gpt);
        assert_eq!(t.count, 1);
        assert_eq!(t.parts[0], Partition { start: 2048, sectors: 12288, mbr_type: 0 });
        assert!(m.reads <= 2 + 32 + 32, "reads are bounded by the entry array: {}", m.reads);
    }

    /// **Every malformed MBR is refused whole** — nothing is published from a
    /// table that is wrong somewhere.
    ///
    /// **Canary.** Remove the overlap loop in `accept`: the overlapping
    /// table parses with two partitions.
    #[test]
    fn malformed_mbrs_are_refused() {
        let cap = 10_000u64;
        let base = || { let mut b = vec![0u8; 512]; b[510] = 0x55; b[511] = 0xAA; b };
        let cases: &[(&str, &[(u8, u8, u32, u32)], PartError)] = &[
            ("past the end",   &[(0, 0x83, 9_000, 1_001)], PartError::OutOfRange),
            ("at LBA 0",       &[(0, 0x83, 0, 100)], PartError::OutOfRange),
            ("empty range",    &[(0, 0x83, 100, 0)], PartError::OutOfRange),
            ("type 0, a range",&[(0, 0x00, 100, 10)], PartError::OutOfRange),
            ("u32 wrap",       &[(0, 0x83, u32::MAX, u32::MAX)], PartError::OutOfRange),
            ("overlap",        &[(0, 0x83, 100, 100), (0x80, 0x83, 150, 10)], PartError::Overlap),
            ("same start",     &[(0, 0x83, 100, 1), (0, 0x0C, 100, 1)], PartError::Overlap),
        ];
        for (what, ents, want) in cases {
            let mut b = base();
            for (i, &(st, ty, s, l)) in ents.iter().enumerate() { mbr_entry(&mut b, i, st, ty, s, l); }
            assert_eq!(Medium::new(&b, cap).parse(cap).map(|t| t.count), Err(*want), "{what}");
        }
        // Adjacent is not overlapping; an extended container is kept as is.
        let mut b = base();
        mbr_entry(&mut b, 0, 0x80, 0x0C, 1, 99);
        mbr_entry(&mut b, 1, 0x00, 0x05, 100, 900);
        let t = Medium::new(&b, cap).parse(cap).unwrap();
        assert_eq!(t.count, 2);
        assert_eq!(t.get(1), Some(Partition { start: 100, sectors: 900, mbr_type: 0x05 }));
        assert_eq!(t.get(2), None);
    }

    /// **GPT fields are checked before they are used**, each case changing one
    /// field of the hdiutil table (CRCs recomputed unless the CRC is the
    /// case).
    ///
    /// **Canary.** Delete the `n_entries > GPT_MAX_ENTRIES` test: the
    /// `entries 129` case is read instead of refused (and 129 x 128 B still
    /// fits the medium, so nothing else catches it).
    ///
    /// **Canary.** `let sectors = (last - first) + 1;` in `parse_gpt`: the
    /// `0..=u64::MAX` case panics on overflow (this crate builds with
    /// `overflow-checks`, as the kernel does).
    #[test]
    fn malformed_gpts_are_refused() {
        type Edit = fn(&mut Vec<u8>);
        let cases: &[(&str, Edit, bool, PartError)] = &[
            ("bad signature",  |i| i[512] = b'X', true, PartError::BadGptHeader),
            ("header crc",     |i| i[512 + 16] ^= 1, false, PartError::BadHeaderCrc),
            ("entries crc",    |i| i[1024 + 200] ^= 1, false, PartError::BadEntriesCrc),
            ("header size 91", |i| le32_put(i, 512 + 12, 91), true, PartError::BadGptHeader),
            ("header size 513",|i| le32_put(i, 512 + 12, 513), true, PartError::BadGptHeader),
            ("my_lba 2",       |i| le64_put(i, 512 + 24, 2), true, PartError::BadGptHeader),
            ("last usable past end", |i| le64_put(i, 512 + 48, HDIUTIL_CAP), true, PartError::BadGptHeader),
            ("first > last usable",  |i| le64_put(i, 512 + 40, 0x4000), true, PartError::BadGptHeader),
            ("entries at LBA 1",     |i| le64_put(i, 512 + 72, 1), true, PartError::BadGptHeader),
            ("entries past end",     |i| le64_put(i, 512 + 72, u64::MAX - 3), true, PartError::BadGptHeader),
            ("entries 129",          |i| le32_put(i, 512 + 80, 129), true, PartError::BadGptHeader),
            ("entry size 64",        |i| le32_put(i, 512 + 84, 64), true, PartError::BadGptHeader),
            ("entry size 130",       |i| le32_put(i, 512 + 84, 130), true, PartError::BadGptHeader),
            ("last < first",   |i| le64_put(i, 1024 + 40, 0x7FF), true, PartError::OutOfRange),
            ("below usable",   |i| le64_put(i, 1024 + 32, 1), true, PartError::OutOfRange),
            ("past usable",    |i| le64_put(i, 1024 + 40, 0x3FDF), true, PartError::OutOfRange),
            ("last u64::MAX",  |i| le64_put(i, 1024 + 40, u64::MAX), true, PartError::OutOfRange),
            ("0..=u64::MAX",   |i| { le64_put(i, 1024 + 32, 0); le64_put(i, 1024 + 40, u64::MAX); }, true, PartError::OutOfRange),
            ("overlap",        |i| { let e: Vec<u8> = i[1024..1152].to_vec(); i[1152..1280].copy_from_slice(&e); }, true, PartError::Overlap),
        ];
        for (what, edit, fix, want) in cases {
            let mut img = vec![0u8; HDIUTIL_CAP as usize * SECTOR];
            img[..GPT_HEAD.len()].copy_from_slice(GPT_HEAD);
            edit(&mut img);
            if *fix { fix_gpt_crcs(&mut img); }
            let mut m = Medium { img, reads: 0 };
            assert_eq!(m.parse(HDIUTIL_CAP).map(|t| t.count), Err(*want), "{what}");
        }
    }

    /// **Seventeen used entries are refused, not truncated to sixteen.**
    #[test]
    fn more_partitions_than_the_table_holds_are_refused() {
        let mut img = vec![0u8; HDIUTIL_CAP as usize * SECTOR];
        img[..GPT_HEAD.len()].copy_from_slice(GPT_HEAD);
        let e: Vec<u8> = img[1024..1152].to_vec();
        for k in 0..17u64 {
            let o = 1024 + 128 * k as usize;
            img[o..o + 128].copy_from_slice(&e);
            le64_put(&mut img, o + 32, 2048 + k * 10);
            le64_put(&mut img, o + 40, 2048 + k * 10 + 9);
        }
        fix_gpt_crcs(&mut img);
        assert_eq!(Medium { img: img.clone(), reads: 0 }.parse(HDIUTIL_CAP).map(|t| t.count),
                   Err(PartError::TooMany));
        // Sixteen fit.
        let o = 1024 + 128 * 16;
        img[o..o + 128].fill(0);
        fix_gpt_crcs(&mut img);
        assert_eq!(Medium { img, reads: 0 }.parse(HDIUTIL_CAP).map(|t| t.count), Ok(16));
    }

    /// **Fuzz-ish: no input panics.** Random single-byte and random-field
    /// corruptions of all three fixtures, with and without CRC repair, under
    /// `overflow-checks`; every result must be a table whose partitions lie
    /// inside the medium, or an error. Deterministic (xorshift), 20 000
    /// cases.
    #[test]
    fn corrupted_tables_never_panic_and_never_publish_outside_the_medium() {
        let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut rnd = move || { x ^= x << 13; x ^= x >> 7; x ^= x << 17; x };
        let fixtures: [&[u8]; 3] = [MKFS_LBA0, MBR_LBA0, GPT_HEAD];
        for n in 0..20_000u32 {
            let f = fixtures[(n % 3) as usize];
            let cap = [64u64, 2048, HDIUTIL_CAP][(rnd() % 3) as usize];
            let mut img = vec![0u8; HDIUTIL_CAP as usize * SECTOR];
            img[..f.len()].copy_from_slice(f);
            for _ in 0..(1 + rnd() % 4) {
                let region = rnd() % 3;
                let off = match region { 0 => 446 + (rnd() % 66) as usize, 1 => 512 + (rnd() % 96) as usize, _ => 1024 + (rnd() % 256) as usize };
                img[off] = rnd() as u8;
            }
            if f.len() > 512 && rnd() % 2 == 0 { fix_gpt_crcs(&mut img); }
            let mut m = Medium { img, reads: 0 };
            if let Ok(t) = m.parse(cap) {
                assert!(t.count <= partition::MAX_PARTS);
                for p in &t.parts[..t.count] {
                    assert!(p.sectors > 0 && p.start > 0 && p.start + p.sectors <= cap,
                            "case {n}: {p:?} outside a {cap}-sector medium");
                }
            }
            assert!(m.reads <= 2 + 2 * 128, "case {n}: {} reads", m.reads);
        }
    }

    /// **The published table**: first publish wins, `contains` is exact at
    /// both edges, a zero count is one sector, overflow is outside.
    ///
    /// **Canary.** Make `contains` test `end <= start + len + 1`: the
    /// one-past-the-end write is admitted.
    #[test]
    fn the_published_table_bounds_exactly() {
        let _g = super::serial();
        partition::reset_for_tests();
        let t = Medium::new(GPT_HEAD, HDIUTIL_CAP).parse(HDIUTIL_CAP).unwrap();
        assert!(partition::publish(&t));
        let other = Medium::new(MBR_LBA0, HDIUTIL_CAP).parse(HDIUTIL_CAP).unwrap();
        assert!(!partition::publish(&other), "a second publish changed the table");
        assert_eq!(partition::partition(0), Some((2048, 12288)));
        assert_eq!(partition::partition(1), None);
        assert!(partition::contains(0, 2048, 1));
        assert!(partition::contains(0, 14335, 1));
        assert!(partition::contains(0, 2048, 12288));
        assert!(!partition::contains(0, 14335, 2), "one sector past the end");
        assert!(!partition::contains(0, 2047, 1), "one sector before the start");
        assert!(!partition::contains(0, 14336, 0), "a zero count is still a sector");
        assert!(!partition::contains(0, u64::MAX, 2));
        assert!(!partition::contains(1, 2048, 1), "no partition 1");
        partition::reset_for_tests();
        assert_eq!(partition::partition(0), None);
    }
}

// ── The P2 trait and VFS surface (RFC-0048) ──────────────────────────────────
//
// tmpfs mounted at `/tmp` is the streaming backend; FAT32 at `/fat` stays a
// proxy. Both mounts and `vfs::init` happen once per binary (`FS` is one
// static); `serial()` orders the tests.
#[cfg(test)]
mod vfs_p2 {
    use super::{fat32, serial, tmpfs, vfs};
    use vfs::{DirEnt, FileSystem as _, FsErr, O_APPEND, O_CREAT, O_RDONLY, O_RDWR, O_TRUNC,
              O_WRONLY, SEEK_CUR, SEEK_END, SEEK_SET};

    fn tmp_once() {
        super::vfs_open_close::vfs_once();
        static ONCE: std::sync::Once = std::sync::Once::new();
        ONCE.call_once(|| {
            vfs::vfs_mount_fs(b"/tmp", &tmpfs::TMPFS_FS).expect("room for /tmp");
        });
    }

    fn clear_tmpfs() {
        let mut names = Vec::new();
        tmpfs::tmpfs_ls(|n, _| names.push(n.to_vec()));
        for n in names { tmpfs::tmpfs_unlink(&n).unwrap(); }
    }

    fn read_fd(t: &mut vfs::ScratchFds, fd: i32, n: usize) -> Vec<u8> {
        let mut b = vec![0u8; n];
        let r = vfs::vfs_read(t, fd, b.as_mut_ptr(), n);
        assert!(r >= 0, "read failed");
        b.truncate(r as usize);
        b
    }

    /// **A streaming open loads nothing and a streaming close rewrites
    /// nothing.** Bytes changed in the backend after the open are what the
    /// descriptor reads; bytes written through the descriptor are in the
    /// backend before the close.
    ///
    /// **Canary.** Make `TmpFs::streaming` answer `false`: the open takes the
    /// proxy path, the read returns the snapshot `"old!"`, and the direct
    /// read before close finds `"old!"` too.
    #[test]
    fn a_streaming_open_reads_and_writes_the_backend_in_place() {
        let _g = serial();
        tmp_once();
        clear_tmpfs();
        tmpfs::tmpfs_write(b"live", b"old!").unwrap();
        let mut t = vfs::ScratchFds::new();
        let fd = vfs::vfs_open(&mut t, b"/tmp/live", O_RDWR);
        assert!(fd >= 0);
        tmpfs::tmpfs_write_at(b"live", 0, b"new!").unwrap();
        assert_eq!(read_fd(&mut t, fd, 16), b"new!", "the open took a snapshot");
        assert_eq!(vfs::vfs_write(&mut t, fd, b"++".as_ptr(), 2), 2);
        let mut direct = [0u8; 8];
        let n = tmpfs::tmpfs_read(b"live", &mut direct).unwrap();
        assert_eq!(&direct[..n], b"new!++", "the write waited for the close");
        assert_eq!(vfs::vfs_close(&mut t, fd), 0);
        assert_eq!(tmpfs::tmpfs_size(b"live"), Some(6));
    }

    /// **`O_CREAT`, `O_TRUNC` and `O_APPEND` are the backend's**: create
    /// makes an empty file, truncate empties an existing one, append lands at
    /// the size the backend reports at write time (another writer grew it).
    #[test]
    fn open_flags_on_a_streaming_backend() {
        let _g = serial();
        tmp_once();
        clear_tmpfs();
        let mut t = vfs::ScratchFds::new();
        assert_eq!(vfs::vfs_open(&mut t, b"/tmp/nofile", O_RDONLY), -1, "opened a missing file");
        let fd = vfs::vfs_open(&mut t, b"/tmp/made", O_WRONLY | O_CREAT);
        assert!(fd >= 0);
        assert_eq!(tmpfs::tmpfs_size(b"made"), Some(0), "O_CREAT made nothing");
        vfs::vfs_close(&mut t, fd);

        tmpfs::tmpfs_write(b"trunc", b"0123456789").unwrap();
        let fd = vfs::vfs_open(&mut t, b"/tmp/trunc", O_WRONLY | O_TRUNC);
        assert_eq!(tmpfs::tmpfs_size(b"trunc"), Some(0), "O_TRUNC left the bytes");
        vfs::vfs_close(&mut t, fd);

        tmpfs::tmpfs_write(b"log", b"a").unwrap();
        let fd = vfs::vfs_open(&mut t, b"/tmp/log", O_WRONLY | O_APPEND);
        tmpfs::tmpfs_write_at(b"log", 1, b"b").unwrap();
        assert_eq!(vfs::vfs_write(&mut t, fd, b"c".as_ptr(), 1), 1);
        vfs::vfs_close(&mut t, fd);
        let mut b = [0u8; 4];
        let n = tmpfs::tmpfs_read(b"log", &mut b).unwrap();
        assert_eq!(&b[..n], b"abc", "the append overwrote another writer's byte");
    }

    /// **Offsets are 64-bit.** A streaming file can be seeked past 4 GiB (the
    /// backend then refuses the write: tmpfs holds 2 MiB); negative and
    /// overflowing seeks are refused; a ramfs file still cannot be seeked
    /// past its end.
    ///
    /// **Canary.** Truncate the offset to `u32` in `vfs_lseek`
    /// (`new_offset as u32 as u64`): the 5 GiB seek answers 1 GiB.
    #[test]
    fn offsets_are_64_bit() {
        let _g = serial();
        tmp_once();
        clear_tmpfs();
        tmpfs::tmpfs_write(b"big", b"xyz").unwrap();
        let mut t = vfs::ScratchFds::new();
        let fd = vfs::vfs_open(&mut t, b"/tmp/big", O_RDWR);
        let five_gib = 5i64 << 30;
        assert_eq!(vfs::vfs_lseek(&mut t, fd, five_gib, SEEK_SET), five_gib);
        assert_eq!(vfs::vfs_lseek(&mut t, fd, 1, SEEK_CUR), five_gib + 1);
        assert_eq!(vfs::vfs_write(&mut t, fd, b"!".as_ptr(), 1), -1, "tmpfs cannot hold it");
        assert_eq!(vfs::vfs_lseek(&mut t, fd, -1, SEEK_SET), -1);
        assert_eq!(vfs::vfs_lseek(&mut t, fd, i64::MAX, SEEK_CUR), -1, "overflow");
        assert_eq!(vfs::vfs_lseek(&mut t, fd, -1, SEEK_END), 2);
        assert_eq!(read_fd(&mut t, fd, 8), b"z");
        vfs::vfs_close(&mut t, fd);

        let fd = vfs::vfs_open(&mut t, b"/ramfile", O_RDWR | O_CREAT);
        assert!(fd >= 0);
        assert_eq!(vfs::vfs_write(&mut t, fd, b"12".as_ptr(), 2), 2);
        assert_eq!(vfs::vfs_lseek(&mut t, fd, 3, SEEK_SET), -1, "a ramfs seek past the end");
        vfs::vfs_close(&mut t, fd);
    }

    /// **stat reports type, size and mode** for the ramfs, a streaming
    /// backend, a proxy backend and a mount root.
    #[test]
    fn stat_reports_type_size_and_mode() {
        let _g = serial();
        tmp_once();
        clear_tmpfs();
        let d = vfs::vfs_stat(b"/dev").expect("/dev");
        assert!(d.is_dir);
        assert_eq!(d.mode & 0o170000, vfs::S_IFDIR);
        let c = vfs::vfs_stat(b"/dev/stdout").expect("/dev/stdout");
        assert_eq!(c.mode & 0o170000, vfs::S_IFCHR);
        tmpfs::tmpfs_write(b"sz", &[7u8; 300]).unwrap();
        let st = vfs::vfs_stat(b"/tmp/sz").expect("/tmp/sz");
        assert_eq!((st.size, st.is_dir, st.mode, st.nlink), (300, false, vfs::S_IFREG | 0o644, 1));
        assert!(vfs::vfs_stat(b"/tmp").expect("mount root").is_dir);
        assert!(vfs::vfs_stat(b"/tmp/none").is_none());
        assert!(vfs::vfs_stat(b"/nowhere").is_none());
    }

    /// **DOS stamps become Unix seconds**, leap years included; a zero date
    /// is "no stamp"; out-of-range fields are clamped, never used as indices.
    ///
    /// **Canary.** Drop the `leap && month > 2` day: 2000-02-29 and
    /// 2026-09-28 are unaffected, 2024-03-01 reads one day early.
    #[test]
    fn dos_stamps_become_unix_seconds() {
        // 2026-09-28 12:34:56 and 2000-02-29 23:59:58, from Python's calendar.timegm.
        assert_eq!(fat32::dos_to_unix(23868, 25692), 1_790_598_896);
        assert_eq!(fat32::dos_to_unix(10333, 49021), 951_868_798);
        // 2024-03-01 00:00:00: the leap day before it must count.
        assert_eq!(fat32::dos_to_unix(22625, 0), 1_709_251_200);
        assert_eq!(fat32::dos_to_unix((0 << 9) | (1 << 5) | 1, 0), 315_532_800);
        assert_eq!(fat32::dos_to_unix(0, 0xFFFF), 0);
        let _ = fat32::dos_to_unix(0xFFFF, 0xFFFF); // month 15, day 31, hour 31: no panic
        let _ = fat32::dos_to_unix(0x01E0, 0); // month 15 -> clamped
    }

    /// **readdir with a cookie** walks each kind of directory once, in
    /// order, and ends with `None`.
    ///
    /// **Canary.** Return `Some(cookie)` instead of `Some(cookie + 1)` from
    /// the ramfs arm of `vfs_readdir`: the walk never ends (bounded here) and
    /// repeats `stdin`.
    #[test]
    fn readdir_walks_with_a_cookie() {
        let _g = serial();
        tmp_once();
        clear_tmpfs();
        fn walk(path: &[u8]) -> Vec<(String, bool, u64)> {
            let mut out = Vec::new();
            let mut cookie = 0u64;
            let mut e = DirEnt::new();
            for _ in 0..100 {
                match vfs::vfs_readdir(path, cookie, &mut e).expect("readdir") {
                    Some(next) => {
                        out.push((String::from_utf8_lossy(e.name()).into_owned(), e.is_dir, e.size));
                        cookie = next;
                    }
                    None => return out,
                }
            }
            panic!("readdir of {:?} did not end", String::from_utf8_lossy(path));
        }
        let dev: Vec<_> = walk(b"/dev").into_iter().map(|e| e.0).collect();
        assert_eq!(dev, ["stdin", "stdout", "stderr"]);
        tmpfs::tmpfs_write(b"a", b"1").unwrap();
        tmpfs::tmpfs_write(b"bb", b"22").unwrap();
        let tmp = walk(b"/tmp");
        assert_eq!(tmp, vec![("a".into(), false, 1), ("bb".into(), false, 2)]);
        let mut e = DirEnt::new();
        assert_eq!(vfs::vfs_readdir(b"/dev/stdin", 0, &mut e), Err(FsErr::NotDir));
        assert_eq!(vfs::vfs_readdir(b"/tmp/sub", 0, &mut e), Err(FsErr::NotFound));
    }

    /// **The FAT32 half**: mkdir, readdir (root and the new directory),
    /// rename, truncate to 0, statfs, fsync, and `Unsupported` where FAT32
    /// has no code (rmdir, a non-zero truncate).
    #[test]
    fn fat32_through_the_new_surface() {
        let _g = serial();
        super::vfs_open_close::fresh_volume();
        tmp_once();
        let mut t = vfs::ScratchFds::new();
        let fd = vfs::vfs_open(&mut t, b"/fat/ONE.TXT", O_WRONLY | O_CREAT | O_TRUNC);
        assert_eq!(vfs::vfs_write(&mut t, fd, b"hello".as_ptr(), 5), 5);
        assert_eq!(vfs::vfs_fsync(&mut t, fd), Ok(()), "fsync must write the dirty proxy");
        let key = fat32::Fat32Fs.key_for(b"ONE.TXT").unwrap();
        assert_eq!(fat32::Fat32Fs.stat(&key).unwrap().size, 5, "fsync did not reach the volume");
        vfs::vfs_close(&mut t, fd);

        assert_eq!(vfs::vfs_mkdir(b"/fat/SUB"), Ok(()));
        let mut names = Vec::new();
        let mut e = DirEnt::new();
        let mut c = 0;
        while let Some(n) = vfs::vfs_readdir(b"/fat", c, &mut e).unwrap() {
            names.push((String::from_utf8_lossy(e.name()).into_owned(), e.is_dir));
            c = n;
        }
        assert!(names.contains(&("ONE.TXT".into(), false)), "{names:?}");
        assert!(names.contains(&("SUB".into(), true)), "{names:?}");
        assert!(vfs::vfs_readdir(b"/fat/SUB", 0, &mut e).is_ok(), "a subdirectory lists");

        assert_eq!(vfs::vfs_rename(b"/fat/ONE.TXT", b"/fat/TWO.TXT"), Ok(()));
        assert!(vfs::vfs_stat(b"/fat/ONE.TXT").is_none());
        assert_eq!(vfs::vfs_stat(b"/fat/TWO.TXT").unwrap().size, 5);
        // Wave 9 (FS2): a non-zero truncate and rmdir are implemented now;
        // this line asserted `Unsupported` for both.
        assert_eq!(vfs::vfs_truncate(b"/fat/TWO.TXT", 3), Ok(()));
        assert_eq!(vfs::vfs_stat(b"/fat/TWO.TXT").unwrap().size, 3);
        assert_eq!(vfs::vfs_truncate(b"/fat/TWO.TXT", 3), Ok(()));
        assert_eq!(vfs::vfs_truncate(b"/fat/TWO.TXT", 0), Ok(()));
        assert_eq!(vfs::vfs_stat(b"/fat/TWO.TXT").unwrap().size, 0);
        assert_eq!(vfs::vfs_rmdir(b"/fat/SUB"), Ok(()));
        assert!(vfs::vfs_stat(b"/fat/SUB").is_none(), "rmdir left the directory listed");
        assert_eq!(vfs::vfs_rename(b"/fat/TWO.TXT", b"/tmp/two"), Err(FsErr::Invalid),
                   "a rename across mounts");

        let sf = vfs::vfs_statfs(b"/fat").unwrap();
        assert_eq!(sf.fs_type, vfs::FS_TYPE_FAT32);
        assert!(sf.blocks > 0 && sf.blocks_free > 0 && sf.blocks_free < sf.blocks, "{sf:?}");
        let fd = vfs::vfs_open(&mut t, b"/fat/BIG.DAT", O_WRONLY | O_CREAT | O_TRUNC);
        let blob = vec![0x5Au8; 4 * sf.block_size as usize];
        assert_eq!(vfs::vfs_write(&mut t, fd, blob.as_ptr(), blob.len()), blob.len() as i32);
        vfs::vfs_close(&mut t, fd);
        let after = vfs::vfs_statfs(b"/fat").unwrap();
        assert_eq!(after.blocks_free, sf.blocks_free - 4, "four clusters were allocated");
    }

    /// **tmpfs rename, truncate and statfs**, through the VFS.
    #[test]
    fn tmpfs_rename_truncate_statfs() {
        let _g = serial();
        tmp_once();
        clear_tmpfs();
        tmpfs::tmpfs_write(b"src", b"payload").unwrap();
        tmpfs::tmpfs_write(b"dst", b"old").unwrap();
        assert_eq!(vfs::vfs_rename(b"/tmp/src", b"/tmp/dst"), Ok(()));
        assert_eq!(tmpfs::tmpfs_size(b"src"), None);
        assert_eq!(tmpfs::tmpfs_size(b"dst"), Some(7), "rename did not replace");
        assert_eq!(vfs::vfs_truncate(b"/tmp/dst", 3), Ok(()));
        assert_eq!(vfs::vfs_truncate(b"/tmp/dst", 6), Ok(()));
        let mut b = [0xFFu8; 8];
        let n = tmpfs::tmpfs_read(b"dst", &mut b).unwrap();
        assert_eq!(&b[..n], b"pay\0\0\0", "grow must zero-fill");
        let sf = vfs::vfs_statfs(b"/tmp").unwrap();
        assert_eq!((sf.blocks - sf.blocks_free, sf.files - sf.files_free), (6, 1));
        assert_eq!(vfs::vfs_rename(b"/tmp/none", b"/tmp/x"), Err(FsErr::NotFound));
        assert_eq!(vfs::vfs_mkdir(b"/tmp/d"), Err(FsErr::Unsupported), "tmpfs is flat");
    }

    /// **A mount path is not truncated into another, and not mounted twice.**
    #[test]
    fn mount_paths_are_refused_not_truncated() {
        let _g = serial();
        tmp_once();
        assert!(vfs::vfs_mount_fs(b"/tmp", &tmpfs::TMPFS_FS).is_err(), "mounted /tmp twice");
        let long = [b'a'; 70];
        let mut p = vec![b'/'];
        p.extend_from_slice(&long);
        assert!(vfs::vfs_mount_fs(&p, &tmpfs::TMPFS_FS).is_err(), "a 71-byte mount path");
    }
}

// ── Creating a root file when the root directory's chain is full (gate 192) ──
//
// Gate 192's `secure boot falls to R` row halted with "recovery steer did not
// persist": the root directory of `build/disk-recovery.img` had every slot of
// its cluster chain in use, and `/fat/BOOTMETA.B` is a NEW root file. The
// whole-file write (`fat32_write_file`, behind every FAT32 proxy close) placed
// its dirent with a slot finder that stopped at the end of the chain instead of
// extending it — while `dir_insert` (open-with-CREATE, mkdir, rename) did
// extend. These rows pin the extension on the whole-file path, through the
// same `vfs_open(O_WRONLY|O_CREAT|O_TRUNC)` + write + close the OTA writer uses.
#[cfg(test)]
mod full_root_create {
    use super::{fat32, image::*, serial, vfs};
    use vfs::FileSystem as _;

    const EOC: u32 = 0x0FFF_FFFF;

    /// A volume whose root directory is cluster 2 alone (spc=1: 16 slots),
    /// with EVERY slot holding a live short entry, mounted at `/fat`.
    fn full_root_volume() -> Geom {
        let g = Geom::default();
        let mut img = build(&g);
        set_fat(&mut img, &g, 2, EOC);
        let sec = cluster_sector(&g, 2) * SECTOR;
        for slot in 0..16usize {
            let off = sec + slot * 32;
            img[off..off + 11].copy_from_slice(&junk(slot as u8));
            img[off + 11] = 0x20; // ARCHIVE; cluster 0, size 0: empty files
        }
        super::swap_medium(img);
        assert_eq!(fat32::fat32_mount(), Ok(()), "the fixture must mount");
        super::vfs_open_close::vfs_once();
        g
    }

    fn junk(i: u8) -> [u8; 11] {
        let mut n = *b"FULL00  TXT";
        n[4] = b'0' + i / 10;
        n[5] = b'0' + i % 10;
        n
    }

    fn fat_entry(g: &Geom, cluster: u32) -> u32 {
        let byte = cluster as usize * 4;
        let sec = fs_test_drivers::disk_peek(g.rsvd as u64 + (byte / SECTOR) as u64)
            .expect("FAT sector in the image");
        let o = byte % SECTOR;
        u32::from_le_bytes([sec[o], sec[o + 1], sec[o + 2], sec[o + 3]]) & 0x0FFF_FFFF
    }

    /// The whole medium as the device holds it, remounted from scratch: the
    /// assertions after this read what a NEXT boot reads, not the cache.
    fn remount_from_device(g: &Geom) {
        let mut img = Vec::with_capacity(g.total_sectors * SECTOR);
        for s in 0..g.total_sectors as u64 {
            img.extend_from_slice(&fs_test_drivers::disk_peek(s).expect("sector"));
        }
        super::swap_medium(img);
        assert_eq!(fat32::fat32_mount(), Ok(()), "the written volume must remount");
    }

    fn free_clusters() -> u64 {
        fat32::Fat32Fs.statfs().ok().expect("statfs on a mounted volume").blocks_free
    }

    /// The root chain grew by exactly one cluster, which holds the new entry
    /// in slot 0 and a terminator in slot 1; the old 16 entries are intact.
    fn assert_root_extended(g: &Geom, name83: &[u8; 11]) {
        let next = fat_entry(g, 2);
        assert!(
            (3..EOC).contains(&next),
            "the root chain must now continue past cluster 2 (FAT[2] = {:#x})", next,
        );
        assert_eq!(fat_entry(g, next), EOC, "the extension must end the chain");
        let sec = fs_test_drivers::disk_peek(cluster_sector(g, next) as u64).unwrap();
        assert_eq!(&sec[0..11], name83, "the new entry sits in the extension's slot 0");
        assert_eq!(sec[32], 0x00, "the slot after it must terminate the directory");
        for i in 0..16u8 {
            assert!(fat32::fat32_lookup_root(&junk(i)).is_ok(), "old entry {} lost", i);
        }
    }

    /// **The mechanism, at the function the proxy close calls.**
    #[test]
    fn write_file_extends_a_full_root_directory() {
        let _g = serial();
        let g = full_root_volume();
        let name = *b"BOOTMETAB  ";
        let data = b"seq=2\nactive_slot=r\n";
        assert_eq!(
            fat32::fat32_write_file(&name, data), Ok(()),
            "a new root file must be creatable when the root chain is full: \
             the directory is extended, as dir_insert already does",
        );
        assert_root_extended(&g, &name);
        remount_from_device(&g);
        let (clus, size) = fat32::fat32_lookup_root(&name).expect("found after a remount");
        assert_eq!(size as usize, data.len());
        let mut buf = [0u8; 512];
        let n = fat32::fat32_read_chain(clus, &mut buf);
        assert_eq!(&buf[..n.min(data.len())], &data[..], "the contents after a remount");
        assert!(fat32::fat32_journal_idle(), "the create committed and cleared its record");
    }

    /// **The OTA writer's exact shape**: `vfs_open(O_WRONLY|O_CREAT|O_TRUNC)`
    /// + `vfs_write` + `vfs_close` of a new `/fat/BOOTMETA.B`. Before the
    /// fix the close answered -1 and `fs_write_meta_record` dropped it.
    #[test]
    fn vfs_create_of_a_new_root_file_lands_on_a_full_root() {
        let _g = serial();
        let _wt = crate::write_through();
        let g = full_root_volume();
        let mut t = vfs::ScratchFds::new();
        let rec = b"seq=2\nactive_slot=r\ncrc=00000000\n";
        let fd = vfs::vfs_open(&mut t, b"/fat/BOOTMETA.B", vfs::O_WRONLY | vfs::O_CREAT | vfs::O_TRUNC);
        assert!(fd >= 0, "the proxy open does not touch the directory");
        assert_eq!(vfs::vfs_write(&mut t, fd, rec.as_ptr(), rec.len()), rec.len() as i32);
        assert_eq!(vfs::vfs_close(&mut t, fd), 0, "the close's whole-file write must land");
        assert_root_extended(&g, b"BOOTMETAB  ");
        remount_from_device(&g);
        let mut buf = [0u8; 64];
        let fd = vfs::vfs_open(&mut t, b"/fat/BOOTMETA.B", vfs::O_RDONLY);
        assert!(fd >= 0, "BOOTMETA.B must open after a remount");
        let n = vfs::vfs_read(&mut t, fd, buf.as_mut_ptr(), buf.len());
        vfs::vfs_close(&mut t, fd);
        assert_eq!(&buf[..n as usize], &rec[..]);
    }

    /// An EMPTY new file (no data chain: `Fat32Fs::create`, `truncate` to 0
    /// of a missing name) takes the same dirent path.
    #[test]
    fn empty_create_extends_a_full_root_directory() {
        let _g = serial();
        let _wt = crate::write_through();
        let g = full_root_volume();
        let key = fat32::Fat32Fs.key_for(b"empty.bin").unwrap();
        assert_eq!(fat32::Fat32Fs.create(&key), Ok(()));
        assert_root_extended(&g, b"EMPTY   BIN");
        assert_eq!(fat32::fat32_lookup_root(b"EMPTY   BIN"), Ok((0, 0)));
    }

    /// **A create that cannot extend costs nothing.** Root full AND no free
    /// cluster left after the file's data: the dirent cannot be placed, the
    /// write fails — and the data cluster it allocated is handed back and
    /// the journal record cleared, instead of leaking a cluster per failed
    /// attempt (which would make the NEXT write fail for lack of space).
    #[test]
    fn a_create_that_cannot_extend_the_root_leaks_nothing() {
        let _g = serial();
        let _geom = full_root_volume();
        // Leave exactly one free cluster: enough for the data, none for the
        // directory extension.
        let mut taken = Vec::new();
        while let Ok(c) = fat32::fat32_alloc_cluster() { taken.push(c); }
        fat32::fat32_free_chain(taken.pop().expect("the volume had free clusters"));
        assert_eq!(free_clusters(), 1, "fixture: one free cluster");

        assert_eq!(fat32::fat32_write_file(b"BOOTMETAB  ", b"x"), Err(()));
        assert!(fat32::fat32_lookup_root(b"BOOTMETAB  ").is_err());
        assert_eq!(free_clusters(), 1, "the failed create must return its data cluster");
        assert!(fat32::fat32_journal_idle(), "and must not leave a PENDING record");
        // The one cluster is still usable: an overwrite of an existing name.
        assert_eq!(fat32::fat32_write_file(&junk(0), b"still writable"), Ok(()));
    }

    // ── Wave 12: one transient I/O error must not leak a cluster ───────────
    //
    // `disk_write_fail_nth(n)` fails exactly one write and lets the rest
    // through, so the code that runs after the failure (the rollback, the
    // undo) reaches the device. Each test pins the ordinal it fails from the
    // events of the same operation, so a change in the write sequence fails
    // the precondition instead of silently failing a different write.

    use fs_test_drivers::{disk_events, disk_write_fail_nth, DiskEvent};

    /// A volume with the root at cluster 2 (end of chain) and every other
    /// cluster free, mounted at `/fat`.
    fn plain_volume() -> Geom {
        let g = Geom::default();
        let mut img = build(&g);
        set_fat(&mut img, &g, 2, EOC);
        super::swap_medium(img);
        assert_eq!(fat32::fat32_mount(), Ok(()), "the fixture must mount");
        super::vfs_open_close::vfs_once();
        g
    }

    fn fat_entry_copy(g: &Geom, copy: u32, cluster: u32) -> u32 {
        let byte = cluster as usize * 4;
        let lba = g.rsvd as u64 + (copy * g.fat_sz32) as u64 + (byte / SECTOR) as u64;
        let sec = fs_test_drivers::disk_peek(lba).expect("FAT sector in the image");
        let o = byte % SECTOR;
        u32::from_le_bytes([sec[o], sec[o + 1], sec[o + 2], sec[o + 3]]) & 0x0FFF_FFFF
    }

    /// The sectors `op` wrote, in order (one entry per one-sector write).
    fn writes_of(op: impl FnOnce()) -> Vec<u64> {
        let _ = disk_events();
        op();
        disk_events().into_iter().filter_map(|e| match e {
            DiskEvent::Write(s) => Some(s),
            DiskEvent::Flush => None,
        }).collect()
    }

    /// **The allocator's mirror write fails.** Copy 0 is marked end-of-chain,
    /// copy 1 is not, the allocation reports failure — and the cluster used
    /// to stay marked in copy 0, the copy every scan reads: allocated, in no
    /// chain, one cluster per failed allocation. Now the entry is put back.
    ///
    /// **Canary.** Drop the rollback in `fat32_alloc_cluster_locked`: copy 0
    /// reads end-of-chain at the cluster and the free count is one short.
    #[test]
    fn a_failed_fat_mirror_write_in_the_allocator_leaks_no_cluster() {
        let _g = serial();
        let _wt = crate::write_through();
        let g = plain_volume();
        let free = free_clusters();
        let mirror = g.rsvd as u64 + g.fat_sz32 as u64;
        let w = writes_of(|| {
            disk_write_fail_nth(1);
            assert_eq!(fat32::fat32_alloc_cluster(), Err(()), "the failed mark must be reported");
        });
        // Precondition: write 0 (copy 0's mark) landed, write 1 (the mirror)
        // is the one that failed, and what followed is the rollback.
        assert_eq!(w, [g.rsvd as u64, g.rsvd as u64, mirror],
                   "the write sequence changed; re-pin the failing ordinal");
        assert_eq!(fat_entry_copy(&g, 0, 3), 0, "copy 0 must read cluster 3 free again");
        assert_eq!(fat_entry_copy(&g, 1, 3), 0);
        assert_eq!(free_clusters(), free, "no cluster may leak");
        assert_eq!(fat32::fat32_alloc_cluster(), Ok(3), "and the next allocation gets it");
    }

    /// Where `dir_insert`'s final link lands in a create that extends a full
    /// root: the ordinal (from the drain point) of the write of copy 0's FAT
    /// sector holding entry 2 that comes after the new cluster's fill.
    fn link_ordinal(g: &Geom) -> usize {
        let name = *b"LINKORD BIN";
        let w = writes_of(|| assert_eq!(fat32::fat32_write_file(&name, b"x"), Ok(())));
        let new = fat_entry(g, 2);
        assert!((3..EOC).contains(&new), "the dry run must extend the root");
        let fill = w.iter().position(|&s| s == cluster_sector(g, new) as u64).expect("fill write");
        fill + w[fill..].iter().position(|&s| s == g.rsvd as u64).expect("link write")
    }

    /// **`dir_insert`'s final link fails** — on copy 0, or on the mirror
    /// after copy 0 landed. The extension cluster was allocated and filled;
    /// it used to stay allocated and unreferenced (copy 0 failure), or be
    /// referenced by copy 0 alone (mirror failure). Now the link is undone
    /// (entry 2 end-of-chain in both copies) and the cluster given back.
    ///
    /// **Canary.** Restore `fat32_write_fat_entry(last_cluster, new_clus)?`
    /// without the undo: the free count is one short (both cases), and in
    /// the mirror case copy 0 still names the extension.
    #[test]
    fn a_failed_final_link_in_dir_insert_leaks_no_cluster() {
        let _g = serial();
        let _wt = crate::write_through();
        let g = full_root_volume();
        let at = link_ordinal(&g);
        for (case, nth) in [("copy 0", at), ("mirror", at + 1)] {
            let g = full_root_volume();
            let free = free_clusters();
            let w = writes_of(|| {
                disk_write_fail_nth(nth as u32);
                assert_eq!(fat32::fat32_write_file(b"BOOTMETAB  ", b"x"), Err(()), "{case}");
            });
            // Precondition: the writes before the failure match the dry run's
            // shape — the one before the link wrote the extension's fill.
            assert!(w.len() > at, "{case}: the create stopped before the link");
            assert_eq!(fat_entry_copy(&g, 0, 2), EOC, "{case}: copy 0 must end the root at 2");
            assert_eq!(fat_entry_copy(&g, 1, 2), EOC, "{case}: and so must the mirror");
            assert_eq!(free_clusters(), free, "{case}: no cluster may leak");
            assert!(fat32::fat32_lookup_root(b"BOOTMETAB  ").is_err(), "{case}");
            for i in 0..16u8 {
                assert!(fat32::fat32_lookup_root(&junk(i)).is_ok(), "{case}: old entry {i} lost");
            }
        }
    }

    fn open_new(path: &[u8]) -> fat32::Fat32File {
        fat32::fat32_open(
            fat32::Volume::assume_mounted(), path,
            fat32::open_flags::CREATE | fat32::open_flags::WRITE,
        ).expect("room for one file")
    }

    /// The ordinals of the data-region writes `fat32_write(buf)` makes on a
    /// fresh file, from a dry run on its own fixture.
    fn data_write_ordinals(buf: &[u8]) -> Vec<usize> {
        let g = plain_volume();
        let f = open_new(b"/DRY.BIN");
        let w = writes_of(|| assert_eq!(fat32::fat32_write(f, buf), Ok(buf.len())));
        let _ = fat32::fat32_close(f);
        let data0 = cluster_sector(&g, 2) as u64;
        w.iter().enumerate().filter(|(_, &s)| s >= data0).map(|(i, _)| i).collect()
    }

    /// **A multi-sector write that fails part-way is a short write.** Three
    /// sectors (three clusters at one sector per cluster); the second data
    /// sector's write fails. The call answers `Ok(512)`, the handle's size
    /// and position advance by 512, and those bytes become the file — they
    /// used to be lost behind `Err(Io)` with the handle unmoved, though they
    /// were on the device and their clusters linked.
    ///
    /// **Canary.** Return the loop's error unconditionally from `fat32_write`
    /// (the old `?`): `Err(Io)`, red.
    #[test]
    fn a_multi_sector_write_that_fails_part_way_returns_the_bytes_written() {
        let _g = serial();
        let _wt = crate::write_through();
        let buf: Vec<u8> = (0..3 * SECTOR).map(|i| (i % 251) as u8).collect();
        let data = data_write_ordinals(&buf);
        assert_eq!(data.len(), 3, "precondition: three data sectors");
        let _geom = plain_volume();
        let f = open_new(b"/SHORT.BIN");
        disk_write_fail_nth(data[1] as u32);
        assert_eq!(fat32::fat32_write(f, &buf), Ok(SECTOR), "the bytes that landed");
        assert_eq!(fat32::fat32_file_stat(f), Ok((SECTOR as u32, SECTOR as u32)),
                   "size and position advance by what landed");
        // The rest goes through on the next call, from where the first stopped.
        assert_eq!(fat32::fat32_write(f, &buf[SECTOR..]), Ok(2 * SECTOR));
        assert_eq!(fat32::fat32_close(f), Ok(()));
        let (clus, size) = fat32::fat32_lookup_root(b"SHORT   BIN").expect("the file");
        assert_eq!(size as usize, buf.len());
        let mut back = vec![0u8; buf.len()];
        assert_eq!(fat32::fat32_read_chain(clus, &mut back), buf.len());
        assert_eq!(back, buf, "the file reads back whole");
    }

    /// **A write that places no byte on an empty file frees the cluster it
    /// started the chain with**, and the handle stays empty: the cluster used
    /// to be recorded nowhere until a later write or close happened to name
    /// it. Also the class: the chain extension's link (`chain_nth_or_extend`)
    /// failing on copy 0 gives back the cluster it allocated.
    ///
    /// **Canaries.** Drop the `free_chain(fresh)` in `fat32_write`: the free
    /// count is one short after the first failure. Drop the undo in
    /// `chain_nth_or_extend`: one short after the second.
    #[test]
    fn a_write_that_places_nothing_keeps_no_cluster() {
        let _g = serial();
        let _wt = crate::write_through();
        let buf = [0x5Au8; SECTOR];
        let data = data_write_ordinals(&buf);
        assert_eq!(data.len(), 1, "precondition: one data sector");
        let _geom = plain_volume();
        let free = free_clusters();
        let f = open_new(b"/EMPTY.BIN");
        disk_write_fail_nth(data[0] as u32);
        assert_eq!(fat32::fat32_write(f, &buf), Err(fat32::FsError::Io));
        assert_eq!(fat32::fat32_file_stat(f), Ok((0, 0)));
        assert_eq!(free_clusters(), free, "the fresh first cluster must be given back");

        // One sector lands; the second sector's chain extension fails at its
        // link (copy 0): the writes are the allocation's two, then the link.
        assert_eq!(fat32::fat32_write(f, &buf), Ok(SECTOR));
        let free = free_clusters();
        let w = writes_of(|| {
            disk_write_fail_nth(2);
            assert_eq!(fat32::fat32_write(f, &buf), Err(fat32::FsError::Io));
        });
        assert!(w.len() >= 2, "precondition: the allocation's two writes landed");
        assert_eq!(free_clusters(), free, "the extension's cluster must be given back");
        assert_eq!(fat32::fat32_file_stat(f), Ok((SECTOR as u32, SECTOR as u32)));
        assert_eq!(fat32::fat32_close(f), Ok(()));
    }
}

// ── Concurrent FAT mutators with no lock across I/O (wave 15, FM) ────────────
//
// Owner rule F1: no mutex is held across a device wait, so two FAT updaters
// can be inside their device I/O at once. What keeps them correct is the
// FAT-sector claim (`fat_sector_claim` in fat32.rs). Each test parks thread A
// inside its FAT write (the shim's before-write hook, before the bytes land)
// and runs thread B's update on the SAME FAT sector meanwhile. With the claim,
// B waits for A's publish; A's park is bounded, so a correct build finishes in
// well under a second and a broken one fails instead of hanging.
//
// Canary: `--features fat-sector-claim-canary` (the claim excludes nothing):
// both tests fail.
#[cfg(test)]
mod concurrent_fat_mutators {
    use super::{fat32, image::*, serial};
    use std::sync::atomic::{AtomicBool, Ordering::SeqCst};
    use std::time::{Duration, Instant};

    const EOC: u32 = 0x0FFF_FFFF;

    static ARMED: AtomicBool = AtomicBool::new(false);
    static PARKED: AtomicBool = AtomicBool::new(false);
    static B_DONE: AtomicBool = AtomicBool::new(false);
    /// `fat32_claims_held_by` for A's task while A was parked (the host's
    /// `caller_tid` is `u32::MAX` on every thread).
    static A_CLAIMS: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    /// `fat32_locks_available` while A was parked inside its claim.
    static A_LOCKS_FREE: AtomicBool = AtomicBool::new(true);
    std::thread_local!(static IS_A: core::cell::Cell<bool> = const { core::cell::Cell::new(false) });

    /// Thread A's first device write parks until B is done (broken build:
    /// B ran its whole update in A's window) or 300 ms passed (correct build:
    /// B is waiting on A's claim and cannot finish until A publishes).
    fn park_a() {
        if !IS_A.with(|a| a.get()) || !ARMED.swap(false, SeqCst) { return; }
        A_CLAIMS.store(fat32::fat32_claims_held_by(u32::MAX), SeqCst);
        A_LOCKS_FREE.store(fat32::fat32_locks_available(), SeqCst);
        PARKED.store(true, SeqCst);
        let t0 = Instant::now();
        while !B_DONE.load(SeqCst) && t0.elapsed() < Duration::from_millis(300) {
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    fn plain_volume() -> Geom {
        let g = Geom::default();
        let mut img = build(&g);
        set_fat(&mut img, &g, 2, EOC);
        super::swap_medium(img);
        assert_eq!(fat32::fat32_mount(), Ok(()), "the fixture must mount");
        g
    }

    fn fat_entry_copy(g: &Geom, copy: u32, cluster: u32) -> u32 {
        let byte = cluster as usize * 4;
        let lba = g.rsvd as u64 + (copy * g.fat_sz32) as u64 + (byte / SECTOR) as u64;
        let sec = fs_test_drivers::disk_peek(lba).expect("FAT sector in the image");
        let o = byte % SECTOR;
        u32::from_le_bytes([sec[o], sec[o + 1], sec[o + 2], sec[o + 3]]) & 0x0FFF_FFFF
    }

    /// Run `a` on thread A (parked inside its first FAT write) and, once A is
    /// parked, `b` on thread B. Returns both results.
    fn race<RA: Send + 'static, RB: Send + 'static>(
        a: fn() -> RA,
        b: fn() -> RB,
    ) -> (RA, RB) {
        PARKED.store(false, SeqCst);
        B_DONE.store(false, SeqCst);
        ARMED.store(true, SeqCst);
        fs_test_drivers::disk_before_write(Some(park_a));
        let ta = std::thread::spawn(move || { IS_A.with(|x| x.set(true)); a() });
        let t0 = Instant::now();
        while !PARKED.load(SeqCst) {
            assert!(t0.elapsed() < Duration::from_secs(5), "precondition: A never reached its FAT write");
            std::thread::sleep(Duration::from_millis(1));
        }
        let tb = std::thread::spawn(move || { let r = b(); B_DONE.store(true, SeqCst); r });
        let rb = tb.join().expect("thread B");
        let ra = ta.join().expect("thread A");
        fs_test_drivers::disk_before_write(None);
        ARMED.store(false, SeqCst);
        (ra, rb)
    }

    /// **Two allocators, one FAT sector.** A scanned, found cluster 3 free and
    /// is writing its mark; B scans the same sector meanwhile. Unclaimed, B
    /// sees 3 free too and both files would own cluster 3 (U09-2).
    #[test]
    fn two_allocators_in_one_fat_sector_get_distinct_clusters() {
        let _g = serial();
        let _wt = crate::write_through();
        let g = plain_volume();
        let (a, b) = race(fat32::fat32_alloc_cluster, fat32::fat32_alloc_cluster);
        let (a, b) = (a.expect("A allocates"), b.expect("B allocates"));
        assert_ne!(a, b, "two allocations handed out the same cluster");
        assert_eq!(A_CLAIMS.load(SeqCst), 1,
                   "inside its FAT write A must read as holding one claim (the panic policy's check)");
        assert!(!A_LOCKS_FREE.load(SeqCst),
                "with a claim out, the panic path must not see the FAT32 locks as free");
        for copy in 0..2 {
            assert_eq!(fat_entry_copy(&g, copy, a), EOC, "A's cluster {a} must read allocated (copy {copy})");
            assert_eq!(fat_entry_copy(&g, copy, b), EOC, "B's cluster {b} must read allocated (copy {copy})");
        }
    }

    /// **An allocator and a freer, one FAT sector.** Cluster 5 is allocated;
    /// A is mid-way through marking cluster 3 (it read the sector, its write
    /// is in flight) when B frees cluster 5. Unclaimed, A's sector write
    /// carries the old "5 = allocated" bytes over B's free: cluster 5 leaks.
    #[test]
    fn a_free_during_an_allocation_in_the_same_fat_sector_is_not_lost() {
        let _g = serial();
        let _wt = crate::write_through();
        let g = Geom::default();
        let mut img = build(&g);
        set_fat(&mut img, &g, 2, EOC);
        set_fat(&mut img, &g, 4, EOC);
        set_fat(&mut img, &g, 5, EOC);
        super::swap_medium(img);
        assert_eq!(fat32::fat32_mount(), Ok(()), "the fixture must mount");
        let (a, ()) = race(fat32::fat32_alloc_cluster, || fat32::fat32_free_chain(5));
        assert_eq!(a, Ok(3), "A allocates the first free cluster");
        for copy in 0..2 {
            assert_eq!(fat_entry_copy(&g, copy, 3), EOC, "A's mark must land (copy {copy})");
            assert_eq!(fat_entry_copy(&g, copy, 5), 0, "B's free must survive A's write (copy {copy})");
            assert_eq!(fat_entry_copy(&g, copy, 4), EOC, "an untouched entry stays (copy {copy})");
        }
    }
}

// ── FAT32 inside a partition (wave 9, FS2) ───────────────────────────────────
//
// A medium with an MBR at LBA 0 and the FAT32 volume at LBA 2048: the driver
// mounts at the start of the first PUBLISHED partition whose first sector is a
// valid FAT32 boot sector no larger than the partition, and every sector it
// touches is volume-relative plus that start.
#[cfg(test)]
mod partitioned_volume {
    use super::{fat32, image::*, partition, serial};

    pub(super) const BASE: u64 = 2048;

    /// MBR + 2047 blank sectors + the default fixture volume + an 8-sector
    /// tail, with partition 0 = the volume, `part_len` sectors long.
    pub(super) fn medium(part_len: u32) -> (Vec<u8>, usize) {
        let g = Geom::default();
        let mut vol = build(&g);
        set_fat(&mut vol, &g, 2, 0x0FFF_FFFF);
        let vol_sectors = vol.len() / SECTOR;
        let mut m = vec![0u8; BASE as usize * SECTOR];
        let o = 446;
        m[o + 4] = 0x0C;
        m[o + 8..o + 12].copy_from_slice(&(BASE as u32).to_le_bytes());
        m[o + 12..o + 16].copy_from_slice(&part_len.to_le_bytes());
        m[510] = 0x55;
        m[511] = 0xAA;
        m.extend_from_slice(&vol);
        m.extend_from_slice(&[0u8; 8 * SECTOR]);
        (m, vol_sectors)
    }

    pub(super) fn publish(m: &[u8]) {
        partition::reset_for_tests();
        let cap = (m.len() / SECTOR) as u64;
        let mut rd = |lba: u64, buf: &mut [u8; SECTOR]| -> Result<(), ()> {
            let o = lba as usize * SECTOR;
            buf.copy_from_slice(m.get(o..o + SECTOR).ok_or(())?);
            Ok(())
        };
        let t = partition::parse(cap, &mut rd).expect("the MBR parses");
        assert_eq!(t.count, 1);
        assert!(partition::publish(&t));
    }

    /// **The volume is found at its partition and written there.** The mount
    /// reports base 2048; a file written through the driver lands past LBA
    /// 2048, LBA 0 (the MBR) is byte-for-byte unchanged, and the file reads
    /// back.
    ///
    /// **Canary.** Make `select_volume` return `(0, 0)`: the mount reads the
    /// MBR as a boot sector and refuses (`Err(())`). **Canary.** Drop the
    /// base in `dev_lba`: same refusal.
    #[test]
    fn a_fat32_volume_in_a_partition_mounts_at_its_start() {
        let _g = serial();
        let (mut m, vol_sectors) = medium(0);
        // `part_len` exactly the volume: `tot_sec32 <= len` holds at equality.
        let o = 446 + 12;
        m[o..o + 4].copy_from_slice(&(vol_sectors as u32).to_le_bytes());
        let mbr = m[..SECTOR].to_vec();
        publish(&m);
        super::swap_medium(m);
        assert_eq!(fat32::fat32_mount(), Ok(()), "the partitioned volume did not mount");
        assert_eq!(fat32::fat32_volume_base(), BASE);

        let name = *b"PARTED  TXT";
        let body = b"written through a partition-relative volume";
        assert_eq!(fat32::fat32_write_file(&name, body), Ok(()));
        let (cl, size) = fat32::fat32_lookup_root(&name).expect("the new file is listed");
        assert_eq!(size as usize, body.len());
        let mut back = vec![0u8; 512];
        let n = fat32::fat32_read_chain(cl, &mut back);
        assert!(n >= body.len() && &back[..body.len()] == body, "read back {:?}", &back[..16]);

        assert_eq!(fs_test_drivers::disk_peek(0).unwrap(), mbr, "LBA 0 (the MBR) was written");
        let mut hit = None;
        for lba in 0..(BASE + vol_sectors as u64) {
            let sec = fs_test_drivers::disk_peek(lba).unwrap();
            if sec.windows(body.len()).any(|w| w == body) { hit = Some(lba); break; }
        }
        let hit = hit.expect("the file's bytes are nowhere on the medium");
        assert!(hit >= BASE, "the file's data landed at LBA {hit}, below the partition");
        let _ = fat32::fat32_unmount(fat32::Volume::assume_mounted());
        partition::reset_for_tests();
    }

    /// **A partition smaller than the volume it holds is not mounted from.**
    /// Its first sector is a valid boot sector, but `tot_sec32` (256) exceeds
    /// the partition (255): the volume could address sectors past it. The
    /// driver skips it, falls back to LBA 0, finds the MBR there, and refuses.
    ///
    /// **Canary.** Delete BOTH the `tot_sec32 <= len` condition in
    /// `select_volume` and the re-check after the BPB is read in
    /// `fat32_mount`: the mount succeeds at base 2048. Either one alone keeps
    /// this green — the second re-reads the bytes actually mounted.
    #[test]
    fn a_volume_larger_than_its_partition_is_refused() {
        let _g = serial();
        let (mut m, vol_sectors) = medium(0);
        let o = 446 + 12;
        m[o..o + 4].copy_from_slice(&(vol_sectors as u32 - 1).to_le_bytes());
        publish(&m);
        super::swap_medium(m);
        assert_eq!(fat32::fat32_mount(), Err(()), "mounted a volume larger than its partition");
        partition::reset_for_tests();
    }
}

// ── FAT32 rmdir, non-zero truncate, statfs's cached free count (wave 9, FS2) ─
#[cfg(test)]
mod fat32_round23 {
    use super::{fat32, serial, vfs};
    use std::sync::atomic::Ordering;
    use vfs::{FileSystem, FsErr};

    fn fresh() {
        super::vfs_open_close::fresh_volume();
    }

    fn free() -> u64 {
        fat32::Fat32Fs.statfs().expect("statfs on a mounted volume").blocks_free
    }

    fn read(name: &[u8]) -> Vec<u8> {
        let key = fat32::Fat32Fs.key_for(name).unwrap();
        let st = fat32::Fat32Fs.stat(&key).expect("the file exists");
        let mut b = vec![0u8; st.size as usize + 1024];
        let n = fat32::Fat32Fs.read_all(&key, &st, &mut b);
        b.truncate(n.min(st.size as usize));
        b
    }

    /// **rmdir removes an empty directory and gives its cluster back**, and
    /// refuses a directory that holds a file (`NotEmpty`), a file
    /// (`NotDir`) and a missing name (`NotFound`).
    ///
    /// **Canary.** Make `fat32_dir_is_empty` return `Ok(true)` at once: the
    /// non-empty directory is removed (`Ok(())` instead of `NotEmpty`).
    #[test]
    fn rmdir_removes_only_an_empty_directory() {
        let _g = serial();
        fresh();
        let before = free();
        assert_eq!(fat32::Fat32Fs.mkdir(b"EMPTY"), Ok(()));
        assert_eq!(free(), before - 1, "mkdir took one cluster");
        assert_eq!(fat32::Fat32Fs.rmdir(b"EMPTY"), Ok(()));
        assert_eq!(free(), before, "rmdir did not give the cluster back");
        assert_eq!(fat32::fat32_lookup_root(b"EMPTY      "), Err(()), "still listed");

        assert_eq!(fat32::Fat32Fs.mkdir(b"FULL"), Ok(()));
        let f = fat32::fat32_open(fat32::Volume::assume_mounted(), b"/FULL/IN.TXT",
                                  fat32::open_flags::WRITE | fat32::open_flags::CREATE)
            .expect("create a file inside the directory");
        assert_eq!(fat32::fat32_write(f, b"x"), Ok(1));
        let _ = fat32::fat32_close(f);
        assert_eq!(fat32::Fat32Fs.rmdir(b"FULL"), Err(FsErr::NotEmpty));
        assert!(fat32::fat32_lookup_root(b"FULL       ").is_ok(), "a refused rmdir removed it");

        assert_eq!(fat32::fat32_write_file(b"PLAIN   TXT", b"data"), Ok(()));
        assert_eq!(fat32::Fat32Fs.rmdir(b"PLAIN.TXT"), Err(FsErr::NotDir));
        assert_eq!(fat32::Fat32Fs.rmdir(b"NOSUCH"), Err(FsErr::NotFound));
    }

    /// **truncate to any length**: shorter keeps the prefix, longer
    /// zero-fills, and a directory is refused. Each goes through the
    /// journaled whole-file write, so the old cluster chain is released.
    ///
    /// **Canary.** Put back `if len != 0 { return Err(Unsupported) }`: the
    /// first truncate answers `Unsupported`.
    #[test]
    fn truncate_keeps_the_prefix_and_zero_fills() {
        let _g = serial();
        fresh();
        let key = fat32::Fat32Fs.key_for(b"T.TXT").unwrap();
        assert_eq!(fat32::fat32_write_file(b"T       TXT", b"abcdef"), Ok(()));
        let before = free();
        assert_eq!(fat32::Fat32Fs.truncate(&key, 3), Ok(()));
        assert_eq!(read(b"T.TXT"), b"abc");
        assert_eq!(fat32::Fat32Fs.truncate(&key, 700), Ok(()));
        let long = read(b"T.TXT");
        assert_eq!(long.len(), 700);
        assert_eq!(&long[..3], b"abc");
        assert!(long[3..].iter().all(|&b| b == 0), "the extension is not zero-filled");
        assert_eq!(free(), before - 1, "700 bytes on 512-byte clusters is one more cluster");
        assert_eq!(fat32::Fat32Fs.truncate(&key, 0), Ok(()));
        assert_eq!(read(b"T.TXT"), b"");
        assert_eq!(fat32::Fat32Fs.mkdir(b"ADIR"), Ok(()));
        let dkey = fat32::Fat32Fs.key_for(b"ADIR").unwrap();
        assert_eq!(fat32::Fat32Fs.truncate(&dkey, 1), Err(FsErr::Invalid));
        assert_eq!(fat32::Fat32Fs.truncate(&key, 1 << 32), Err(FsErr::NoSpace));
    }

    /// **statfs scans the FAT once, and never answers stale.** A second
    /// statfs with no FAT change makes no scan; a file write changes the
    /// FAT and the next statfs scans again and sees the clusters it took.
    ///
    /// **Canary.** Delete the `free_count_invalidate()` in
    /// `fat32_write_fat_entry`: after the write the free count is the old one.
    #[test]
    fn statfs_caches_the_free_count_and_a_fat_write_invalidates_it() {
        let _g = serial();
        fresh();
        let a = free();
        let scans = fat32::FREE_SCANS.load(Ordering::SeqCst);
        assert_eq!(free(), a);
        assert_eq!(fat32::FREE_SCANS.load(Ordering::SeqCst), scans, "the second statfs scanned");
        assert_eq!(fat32::fat32_write_file(b"TWO     BIN", &[7u8; 1000]), Ok(()));
        assert_eq!(free(), a - 2, "the count did not see the two clusters the write took");
        assert_eq!(fat32::FREE_SCANS.load(Ordering::SeqCst), scans + 1);
    }
}

/// Wave 10: `INODE_KEY_LEN` 11 -> 64 (owner decision). The generic key now
/// holds every tmpfs name, FAT32 still uses its first 11 bytes, and procfs
/// bounds its own keys by what `procfs_register` accepts.
#[cfg(test)]
mod inode_key_64 {
    use super::{fat32, procfs, serial, tmpfs, vfs};
    use vfs::FileSystem as _;

    /// **A tmpfs name longer than 11 bytes is reachable through the key.**
    /// Until wave 10 `TmpFs::key_for` answered `None` for any name past 11
    /// bytes. A 40-byte name round-trips through `write_at`/`read_at`, and
    /// two names that share their first 11 bytes stay two files.
    ///
    /// **Canary.** `INODE_KEY_LEN = 11`: `key_for` answers `None` and the
    /// first `expect` fails.
    #[test]
    fn a_long_tmpfs_name_round_trips_and_does_not_alias_its_prefix() {
        let _g = serial();
        let a: &[u8] = b"a-forty-byte-tmpfs-name-0000000000000001";
        let b: &[u8] = b"a-forty-byte-tmpfs-name-0000000000000002";
        assert_eq!(a.len(), 40);
        let ka = tmpfs::TmpFs.key_for(a).expect("a 40-byte tmpfs name must fit the key");
        let kb = tmpfs::TmpFs.key_for(b).expect("a 40-byte tmpfs name must fit the key");
        assert!(ka != kb, "two names sharing a prefix made one key");
        assert_eq!(tmpfs::TmpFs.write_at(&ka, 0, b"AAAA"), Ok(4));
        assert_eq!(tmpfs::TmpFs.write_at(&kb, 0, b"BB"), Ok(2));
        let mut out = [0u8; 8];
        assert_eq!(tmpfs::TmpFs.read_at(&ka, 0, &mut out), 4);
        assert_eq!(&out[..4], b"AAAA");
        assert_eq!(tmpfs::TmpFs.read_at(&kb, 0, &mut out), 2);
        assert_eq!(&out[..2], b"BB");
        let _ = tmpfs::TmpFs.unlink(&ka);
        let _ = tmpfs::TmpFs.unlink(&kb);
        // A name over the key is still refused, not truncated into another.
        assert!(tmpfs::TmpFs.key_for(&[b'x'; vfs::INODE_KEY_LEN + 1]).is_none());
    }

    /// **FAT32's 8.3 key is unchanged**: 11 bytes, the rest of the key zero,
    /// and a name that is not a legal 8.3 name is still refused.
    #[test]
    fn the_fat_8_3_key_uses_eleven_bytes_and_zero_fills_the_rest() {
        let k = fat32::Fat32Fs.key_for(b"crash.log").expect("legal 8.3 name");
        assert_eq!(&k.bytes[..11], b"CRASH   LOG");
        assert!(k.bytes[11..].iter().all(|&b| b == 0));
        assert!(fat32::Fat32Fs.key_for(b"a-long-name-that-is-not-8.3.txt").is_none());
    }

    fn gen_x(buf: &mut [u8]) -> usize {
        let s = b"x\n";
        buf[..s.len()].copy_from_slice(s);
        s.len()
    }

    /// **procfs bounds its own keys.** The longest name `procfs_register`
    /// accepts (47 bytes) gets a key and its file is readable through it; a
    /// 48-byte name gets none, since nothing can be registered under it.
    ///
    /// **Canary.** Replace the bound in `ProcFs::key_for` with
    /// `name.len() > INODE_KEY_LEN` (the pre-wave-10 shape): the 48-byte
    /// name gets a key and the `is_none` assertion fails.
    #[test]
    fn procfs_keys_stop_at_what_can_be_registered() {
        let _g = serial();
        let name47 = [b'p'; procfs::PROCFS_PATH_LEN - 1];
        assert!(procfs::procfs_register(procfs::ProcNs::Proc, &name47, gen_x));
        let k = procfs::PROCFS_FS.key_for(&name47).expect("a registrable name has a key");
        let st = procfs::PROCFS_FS.stat(&k).expect("the registered file is found");
        assert_eq!(st.size, 2);
        assert!(procfs::PROCFS_FS.key_for(&[b'p'; procfs::PROCFS_PATH_LEN]).is_none(),
                "a name procfs_register refuses got a key");
    }

    /// Wave 12 (owner round 48): `/proc/<tid>` names a task only in strict
    /// decimal, so one task has one path (`007` is not `7`, `+7` and `7a`
    /// are nothing), and 0 or a value past `u32` is never a TID.
    #[test]
    fn a_proc_tid_name_is_strict_decimal() {
        assert_eq!(procfs::parse_tid_name(b"7"), Some(7));
        assert_eq!(procfs::parse_tid_name(b"4294967295"), Some(u32::MAX));
        for bad in [&b""[..], b"0", b"007", b"+7", b"-7", b"7a", b" 7", b"4294967296", b"99999999999", b"tasks"] {
            assert_eq!(procfs::parse_tid_name(bad), None, "{:?}", core::str::from_utf8(bad));
        }
    }

    /// The task-file hook the kernel registers: 7 is visible, 9 exists but is
    /// hidden from this reader. Both a hidden and an absent TID give 0 bytes,
    /// the same answer.
    fn gen_tid(tid: u32, buf: &mut [u8]) -> usize {
        if tid == 7 { buf[..3].copy_from_slice(b"t7\n"); 3 } else { 0 }
    }

    /// Wave 12 (owner round 48, Linux `hidepid=2`): `/proc/<tid>` goes to the
    /// TID provider; a TID the provider will not show has no file at all —
    /// `stat` finds nothing, exactly as for a TID that does not exist, so a
    /// hidden task is not even visible by path. A registered name wins over
    /// the provider, and `/sys/<digits>` never reaches it.
    ///
    /// **Canary.** Make `procfs_read` call the provider for `/sys` too: red
    /// on "`/sys/7` reached the task provider".
    #[test]
    fn a_hidden_tid_has_no_proc_path() {
        let _g = serial();
        procfs::procfs_register_tid(gen_tid);
        let k7 = procfs::PROCFS_FS.key_for(b"7").expect("a TID name has a key");
        let st = procfs::PROCFS_FS.stat(&k7).expect("/proc/7 is visible");
        assert_eq!(st.size, 3);
        let mut out = [0u8; 8];
        assert_eq!(procfs::PROCFS_FS.read_all(&k7, &st, &mut out), 3);
        assert_eq!(&out[..3], b"t7\n");
        let k9 = procfs::PROCFS_FS.key_for(b"9").expect("a TID name has a key");
        assert!(procfs::PROCFS_FS.stat(&k9).is_none(), "a hidden TID has a file");
        let k5 = procfs::PROCFS_FS.key_for(b"5").expect("a TID name has a key");
        assert!(procfs::PROCFS_FS.stat(&k5).is_none(), "an absent TID has a file");
        let k007 = procfs::PROCFS_FS.key_for(b"007").expect("a name has a key");
        assert!(procfs::PROCFS_FS.stat(&k007).is_none(), "007 aliases 7");
        assert_eq!(procfs::procfs_read(b"/sys/7", &mut out), 0, "/sys/7 reached the task provider");
        assert!(procfs::procfs_register(procfs::ProcNs::Proc, b"77", gen_x));
        assert_eq!(procfs::procfs_read(b"/proc/77", &mut out), 2, "a registered name lost to the provider");
    }

    /// **A key longer than `full_path`'s buffer names nothing** rather than
    /// being written past it or cut into a shorter, registered name.
    ///
    /// **Canary.** Delete the `prefix.len() + name.len() > out.len()` guard
    /// in `full_path`: `stat` panics on the slice past the 64-byte buffer.
    #[test]
    fn a_hand_built_key_past_the_path_buffer_names_nothing() {
        let _g = serial();
        let k = vfs::InodeKey { bytes: [b'q'; vfs::INODE_KEY_LEN] };
        assert!(procfs::PROCFS_FS.stat(&k).is_none());
        let mut out = [0u8; 8];
        assert_eq!(procfs::PROCFS_FS.read_at(&k, 0, &mut out), 0);
    }

    static FLIP: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

    /// Long on even calls, short on odd ones: what `/proc/tasks` does when a
    /// task exits between the VFS's `stat` and its `read_all`.
    fn gen_shrinks(buf: &mut [u8]) -> usize {
        let s: &[u8] = if FLIP.fetch_add(1, std::sync::atomic::Ordering::SeqCst) % 2 == 0 {
            b"0123456789\n"
        } else {
            b"012\n"
        };
        buf[..s.len()].copy_from_slice(s);
        s.len()
    }

    /// **Wave 12: `/proc` through the VFS.** The open path generates a
    /// synthetic file twice (`stat` sizes the proxy, `read_all` fills it);
    /// when the second generation is shorter, the file reads as that
    /// generation, not padded with NULs to the first one's length.
    ///
    /// **Canary.** Drop the procfs `inode_resize` after `read_all` in
    /// `vfs.rs`: the read returns 11 bytes, seven of them NUL.
    #[test]
    fn a_procfs_file_that_shrinks_between_stat_and_read_reads_without_padding() {
        let _g = serial();
        super::vfs_open_close::vfs_once();
        static ONCE: std::sync::Once = std::sync::Once::new();
        ONCE.call_once(|| {
            vfs::vfs_mount_fs(b"/proc", &procfs::PROCFS_FS).expect("room for /proc");
        });
        assert!(procfs::procfs_register(procfs::ProcNs::Proc, b"shrinks", gen_shrinks));
        FLIP.store(0, std::sync::atomic::Ordering::SeqCst);
        let mut t = vfs::ScratchFds::new();
        let fd = vfs::vfs_open(&mut t, b"/proc/shrinks", vfs::O_RDONLY);
        assert!(fd >= 0, "/proc/shrinks does not open through the VFS");
        let mut b = [0u8; 32];
        let n = vfs::vfs_read(&mut t, fd, b.as_mut_ptr(), b.len());
        vfs::vfs_close(&mut t, fd);
        assert_eq!(&b[..n as usize], b"012\n");
    }
}

/// **Wave 11 (HERM): real errnos from `fat32_rename`, `mkdir`/`unlink` that
/// reach FAT32 through the VFS, and `fsync`/`close` that do not hide a failed
/// write (fsyncgate).**
#[cfg(test)]
mod herm_wave11 {
    use super::{fat32, image::*, serial, swap_medium, vfs, vfs_open_close::fresh_volume};
    use fat32::FsError;
    use fs_test_drivers::{
        disk_durable_image, disk_events, disk_stats, disk_write_fail_after,
        disk_write_fail_clear, disk_writeback, DiskEvent,
    };
    use vfs::FsErr;

    fn n83(base: &[u8], ext: &[u8]) -> [u8; 11] {
        let mut n = [b' '; 11];
        n[..base.len()].copy_from_slice(base);
        n[8..8 + ext.len()].copy_from_slice(ext);
        n
    }

    fn put(name: &[u8; 11], body: &[u8]) {
        assert_eq!(fat32::fat32_write_file(name, body), Ok(()));
    }

    /// Fail every device write from now on.
    fn fail_writes_now() {
        disk_write_fail_after(disk_stats().1);
    }

    // ── fat32_rename: the real answer ──────────────────────────────────────

    #[test]
    fn rename_of_a_missing_source_is_not_found() {
        let _g = serial();
        fresh_volume();
        assert_eq!(
            fat32::fat32_rename(&n83(b"NOPE", b"TXT"), &n83(b"NEW", b"TXT")),
            Err(FsErr::NotFound));
        // Through the VFS entry point the syscall layer uses.
        assert_eq!(vfs::vfs_rename(b"/fat/NOPE.TXT", b"/fat/NEW.TXT"), Err(FsErr::NotFound));
    }

    #[test]
    fn rename_of_a_file_onto_a_directory_is_is_dir_and_the_directory_survives() {
        let _g = serial();
        fresh_volume();
        let sub = n83(b"SUB", b"");
        let f = n83(b"F", b"TXT");
        assert_eq!(fat32::fat32_mkdir(fat32::Volume::assume_mounted(), b"/SUB"), Ok(()));
        put(&f, b"payload");
        let before = fat32::fat32_lookup_root_entry(&sub).unwrap();
        assert_eq!(fat32::fat32_rename(&f, &sub), Err(FsErr::IsDir));
        let after = fat32::fat32_lookup_root_entry(&sub).unwrap();
        assert_eq!((before.cluster, before.attr), (after.cluster, after.attr),
                   "the refused rename must not have touched the directory");
        assert!(fat32::fat32_lookup_root(&f).is_ok(), "nor the source");
    }

    #[test]
    fn rename_of_a_directory_onto_an_existing_name_is_exists() {
        let _g = serial();
        fresh_volume();
        let sub = n83(b"SUB", b"");
        let f = n83(b"F", b"TXT");
        assert_eq!(fat32::fat32_mkdir(fat32::Volume::assume_mounted(), b"/SUB"), Ok(()));
        put(&f, b"payload");
        assert_eq!(fat32::fat32_rename(&sub, &f), Err(FsErr::Exists));
        assert!(fat32::fat32_lookup_root(&sub).is_ok());
        assert_eq!(fat32::fat32_lookup_root(&f).map(|(_, s)| s), Ok(7));
    }

    /// The success control for the two above: a directory renamed to a free
    /// name is still a directory (the insert used to hard-code the file
    /// attribute, turning it into a file whose "data" was its entries).
    #[test]
    fn a_directory_renamed_to_a_free_name_stays_a_directory() {
        let _g = serial();
        fresh_volume();
        let sub = n83(b"SUB", b"");
        let moved = n83(b"MOVED", b"");
        assert_eq!(fat32::fat32_mkdir(fat32::Volume::assume_mounted(), b"/SUB"), Ok(()));
        assert_eq!(fat32::fat32_rename(&sub, &moved), Ok(()));
        assert!(fat32::fat32_lookup_root(&sub).is_err());
        let e = fat32::fat32_lookup_root_entry(&moved).unwrap();
        assert_ne!(e.attr & 0x10, 0, "the renamed entry must still be a directory");
    }

    /// A rename that needs a new directory entry and cannot get one is
    /// `NoSpace`, not `Io`: the root is full (16 entries in its one cluster)
    /// and every cluster is taken, so the directory cannot grow.
    #[test]
    fn rename_with_no_room_for_a_new_entry_reuses_the_slot() {
        let _g = serial();
        let g = Geom::default();
        let mut img = build(&g);
        set_fat(&mut img, &g, 2, 0x0FFF_FFFF);
        // Cluster 3 stays free for the source file; 4..=209 are all taken.
        for c in 4..210u32 { set_fat(&mut img, &g, c, 0x0FFF_FFFF); }
        // Fifteen zero-length files fill 15 of the root's 16 slots.
        let root = cluster_sector(&g, 2) * SECTOR;
        for i in 0..15usize {
            let off = root + i * 32;
            let name = format!("FILL{:02}  TXT", i);
            img[off..off + 11].copy_from_slice(name.as_bytes());
            img[off + 11] = 0x20;
        }
        swap_medium(img);
        assert_eq!(fat32::fat32_mount(), Ok(()));
        let src = n83(b"SRC", b"BIN");
        put(&src, b"x");
        // Wave 15: a rename to a new name reuses the source's own slot, so a
        // full directory no longer refuses it.
        let _ = FsErr::NoSpace;
        assert_eq!(fat32::fat32_rename(&src, &n83(b"DST", b"BIN")), Ok(()));
        assert!(fat32::fat32_lookup_root(&src).is_err(), "the old name is gone");
        assert!(fat32::fat32_lookup_root(&n83(b"DST", b"BIN")).is_ok(), "the new name holds it");
    }

    /// A device that fails the write is `Io`, and the source is still there.
    #[test]
    fn rename_on_a_failing_device_is_io_and_keeps_the_source() {
        let _g = serial();
        let _wt = crate::write_through();
        fresh_volume();
        let src = n83(b"SRC", b"BIN");
        put(&src, b"keep me");
        fail_writes_now();
        let r = fat32::fat32_rename(&src, &n83(b"DST", b"BIN"));
        disk_write_fail_clear();
        assert_eq!(r, Err(FsErr::Io));
        assert_eq!(fat32::fat32_lookup_root(&src).map(|(_, s)| s), Ok(7));
    }

    // ── mkdir / unlink under a mount ──────────────────────────────────────

    #[test]
    fn mkdir_and_unlink_reach_fat32_under_the_mount() {
        let _g = serial();
        fresh_volume();
        assert!(vfs::vfs_on_mount(b"/fat/X"));
        assert!(!vfs::vfs_on_mount(b"/tmp/x"));

        // mkdir: created, listed as a directory, then EEXIST, then ENOENT for
        // a missing parent.
        assert_eq!(vfs::vfs_mkdir(b"/fat/SUB"), Ok(()));
        assert!(vfs::vfs_stat(b"/fat/SUB").unwrap().is_dir);
        assert_eq!(vfs::vfs_mkdir(b"/fat/SUB"), Err(FsErr::Exists));
        assert_eq!(vfs::vfs_mkdir(b"/fat"), Err(FsErr::Exists), "the mount point itself");
        assert_eq!(vfs::vfs_mkdir(b"/fat/NOPE/DEEP"), Err(FsErr::NotFound));

        // unlink: a file goes, its clusters come back, a second unlink is
        // ENOENT, a directory is EISDIR and survives.
        let free_before = vfs::FileSystem::statfs(&fat32::Fat32Fs).unwrap().blocks_free;
        let mut t = vfs::ScratchFds::new();
        let fd = vfs::vfs_open(&mut t, b"/fat/F.TXT", vfs::O_WRONLY | vfs::O_CREAT);
        assert!(fd >= 0);
        assert_eq!(vfs::vfs_write(&mut t, fd, b"hello".as_ptr(), 5), 5);
        assert_eq!(vfs::vfs_close(&mut t, fd), 0);
        assert!(vfs::vfs_stat(b"/fat/F.TXT").is_some());
        assert!(vfs::FileSystem::statfs(&fat32::Fat32Fs).unwrap().blocks_free < free_before);
        assert_eq!(vfs::vfs_unlink(b"/fat/F.TXT"), Ok(()));
        assert!(vfs::vfs_stat(b"/fat/F.TXT").is_none());
        assert_eq!(vfs::FileSystem::statfs(&fat32::Fat32Fs).unwrap().blocks_free, free_before,
                   "unlink must give the file's clusters back");
        assert_eq!(vfs::vfs_unlink(b"/fat/F.TXT"), Err(FsErr::NotFound));
        assert_eq!(vfs::vfs_unlink(b"/fat/SUB"), Err(FsErr::IsDir));
        assert!(vfs::vfs_stat(b"/fat/SUB").unwrap().is_dir, "EISDIR must not have removed it");
        assert_eq!(vfs::vfs_rmdir(b"/fat/SUB"), Ok(()));
        // Off every mount: nothing for the backend path to do.
        assert_eq!(vfs::vfs_unlink(b"/nomount/X"), Err(FsErr::NotFound));
    }

    // ── fsyncgate ─────────────────────────────────────────────────────────

    const REC: &[u8] = b"flight record, must not be lost silently";

    fn open_new(path: &[u8]) -> fat32::Fat32File {
        fat32::fat32_open(
            fat32::Volume::assume_mounted(), path,
            fat32::open_flags::CREATE | fat32::open_flags::WRITE,
        ).expect("room for one file")
    }

    /// The directory entry's size as the MEDIUM holds it.
    fn size_on_medium(name: &[u8; 11]) -> Option<u32> {
        fat32::fat32_lookup_root(name).ok().map(|(_, s)| s)
    }

    /// A write the device refused is reported by the write, leaves the handle
    /// exactly as it was, and a later `fsync` does not claim the bytes that
    /// never landed.
    #[test]
    fn a_refused_write_is_reported_and_fsync_does_not_claim_the_lost_bytes() {
        let _g = serial();
        let _wt = crate::write_through();
        fresh_volume();
        let f = open_new(b"/REC.LOG");
        assert_eq!(fat32::fat32_write(f, b"first"), Ok(5));
        assert_eq!(fat32::fat32_fsync(f), Ok(()));
        assert_eq!(size_on_medium(&n83(b"REC", b"LOG")), Some(5));
        fail_writes_now();
        assert_eq!(fat32::fat32_write(f, REC), Err(FsError::Io), "the write must say so");
        assert_eq!(fat32::fat32_file_stat(f), Ok((5, 5)), "the handle must not advance");
        disk_write_fail_clear();
        assert_eq!(fat32::fat32_fsync(f), Ok(()));
        assert_eq!(size_on_medium(&n83(b"REC", b"LOG")), Some(5),
                   "fsync must not publish a size that includes the refused write");
        let _ = fat32::fat32_close(f);
    }

    /// The fsyncgate shape: the data is written, the entry write fails.
    /// `fsync` says Io, a second `fsync` on the same failing device says Io
    /// again (NOT Ok: the first error does not "clear" the dirty state), and
    /// `close` reports it too. Once the device works, the same handle's
    /// `fsync` succeeds and the bytes are durable.
    #[test]
    fn a_failed_fsync_is_not_forgotten_by_the_next_fsync_or_by_close() {
        let _g = serial();
        fresh_volume();
        disk_writeback();
        let f = open_new(b"/REC.LOG");
        assert_eq!(fat32::fat32_write(f, REC), Ok(REC.len()));
        fail_writes_now();
        assert_eq!(fat32::fat32_fsync(f), Err(FsError::Io));
        assert_eq!(fat32::fat32_fsync(f), Err(FsError::Io),
                   "a retry on a still-failing device must not report success");
        disk_write_fail_clear();
        assert_eq!(fat32::fat32_fsync(f), Ok(()), "the handle kept its data, so the retry lands it");
        swap_medium(disk_durable_image());
        assert_eq!(fat32::fat32_mount(), Ok(()));
        assert_eq!(size_on_medium(&n83(b"REC", b"LOG")), Some(REC.len() as u32),
                   "after the successful retry the entry is durable");
    }

    /// `close` is the other place the error used to vanish: it fsynced with
    /// `let _ =` and returned `Ok`.
    #[test]
    fn close_reports_a_failed_implicit_fsync() {
        let _g = serial();
        fresh_volume();
        let f = open_new(b"/REC.LOG");
        assert_eq!(fat32::fat32_write(f, REC), Ok(REC.len()));
        fail_writes_now();
        assert_eq!(fat32::fat32_close(f), Err(FsError::Io),
                   "close must carry the failed fsync's verdict");
        disk_write_fail_clear();
        // The handle is gone either way (POSIX close), so it cannot be reused.
        assert_eq!(fat32::fat32_fsync(f), Err(FsError::BadHandle));
    }

    /// A clean close still returns Ok: the control that keeps the test above
    /// from passing on a `close` that always fails.
    #[test]
    fn close_of_a_clean_handle_is_ok() {
        let _g = serial();
        fresh_volume();
        let f = open_new(b"/REC.LOG");
        assert_eq!(fat32::fat32_write(f, REC), Ok(REC.len()));
        assert_eq!(fat32::fat32_close(f), Ok(()));
        assert_eq!(size_on_medium(&n83(b"REC", b"LOG")), Some(REC.len() as u32));
    }

    /// The same shape one layer up, through descriptors: a proxy file's
    /// dirty buffer is written by `vfs_fsync`; a failure leaves it dirty, a
    /// retry on the still-failing device fails again, and once the device
    /// works the retry writes the buffer — nothing was thrown away.
    #[test]
    fn vfs_fsync_keeps_a_failed_buffer_dirty_until_it_lands() {
        let _g = serial();
        fresh_volume();
        let mut t = vfs::ScratchFds::new();
        let fd = vfs::vfs_open(&mut t, b"/fat/REC.LOG", vfs::O_WRONLY | vfs::O_CREAT);
        assert!(fd >= 0);
        assert_eq!(vfs::vfs_write(&mut t, fd, REC.as_ptr(), REC.len()), REC.len() as i32);
        fail_writes_now();
        assert_eq!(vfs::vfs_fsync(&mut t, fd), Err(FsErr::Io));
        assert_eq!(vfs::vfs_fsync(&mut t, fd), Err(FsErr::Io), "the second fsync must not be Ok");
        disk_write_fail_clear();
        assert_eq!(vfs::vfs_fsync(&mut t, fd), Ok(()));
        let key = vfs::FileSystem::key_for(&fat32::Fat32Fs, b"REC.LOG").unwrap();
        let st = vfs::FileSystem::stat(&fat32::Fat32Fs, &key).unwrap();
        assert_eq!(st.size as usize, REC.len(), "the buffer reached the volume");
        assert_eq!(vfs::vfs_close(&mut t, fd), 0);
    }

    /// And `vfs_close` on a failing device returns -1 (it was already so;
    /// kept here so the three layers are asserted together).
    #[test]
    fn vfs_write_reports_a_failed_device_write() {
        let _g = serial();
        let _wt = crate::write_through();
        fresh_volume();
        let mut t = vfs::ScratchFds::new();
        let fd = vfs::vfs_open(&mut t, b"/fat/REC.LOG", vfs::O_WRONLY | vfs::O_CREAT);
        assert!(fd >= 0);
        // Wave 15: the device failure surfaces where the bytes meet it —
        // the write, under write-through (see `a_close_whose_flush_fails_reports_it`).
        fail_writes_now();
        assert_eq!(vfs::vfs_write(&mut t, fd, REC.as_ptr(), REC.len()), -1);
        disk_write_fail_clear();
        let _ = vfs::vfs_close(&mut t, fd);
    }

    // ── Journal wear: how often the journal sector is written ─────────────

    const JOURNAL_LBA: u64 = fat32::JOURNAL_SECTOR as u64;

    fn journal_writes_of(op: impl FnOnce()) -> usize {
        let _ = disk_events();
        op();
        disk_events().iter().filter(|e| **e == DiskEvent::Write(JOURNAL_LBA)).count()
    }

    /// Measured, and pinned so a change that adds journal writes to an
    /// operation is a visible diff. Every journaled operation writes the
    /// journal sector three times (PENDING, COMMITTED, clear). A create, an
    /// overwrite, an unlink and a rename onto a free name are one record
    /// each; a rename onto an existing name is an OVERWRITE record plus an
    /// UNLINK record (6). `mkdir`, an append and an `fsync` do not journal.
    #[test]
    fn journal_sector_writes_per_operation() {
        let _g = serial();
        let _wt = crate::write_through();
        fresh_volume();
        let a = n83(b"A", b"BIN");
        let b = n83(b"B", b"BIN");
        let create = journal_writes_of(|| put(&a, b"one"));
        let overwrite = journal_writes_of(|| put(&a, b"two-two"));
        let rename_new = journal_writes_of(|| {
            assert_eq!(fat32::fat32_rename(&a, &b), Ok(()));
        });
        put(&a, b"third");
        let rename_over = journal_writes_of(|| {
            assert_eq!(fat32::fat32_rename(&a, &b), Ok(()));
        });
        let unlink = journal_writes_of(|| {
            assert_eq!(fat32::fat32_unlink_root(&b), Ok(()));
        });
        let mkdir = journal_writes_of(|| {
            assert_eq!(fat32::fat32_mkdir(fat32::Volume::assume_mounted(), b"/D"), Ok(()));
        });
        let f = open_new(b"/REC.LOG");
        let append_fsync = journal_writes_of(|| {
            assert_eq!(fat32::fat32_write(f, REC), Ok(REC.len()));
            assert_eq!(fat32::fat32_fsync(f), Ok(()));
        });
        let _ = fat32::fat32_close(f);
        println!("JOURNAL-WRITES create={create} overwrite={overwrite} rename_new={rename_new} \
                  rename_over={rename_over} unlink={unlink} mkdir={mkdir} append_fsync={append_fsync}");
        assert_eq!(
            (create, overwrite, rename_new, rename_over, unlink, mkdir, append_fsync),
            // Wave 15: a rename to a new name rewrites the dirent in place (no
            // record); over a file it is ONE record (pending, committed, clear).
            (3, 3, 0, 3, 3, 0, 0));
    }
}

/// Entry point for `tests/fuzz/fs-fuzz` (cargo-fuzz). Compiled only under the
/// `--cfg fuzzing` cargo-fuzz passes to every crate it builds, so `cargo
/// test` never sees it; it lives here to reuse this crate's shim disk and the
/// real `fat32.rs` it already pulls in, instead of a second copy of both.
#[cfg(fuzzing)]
pub mod fuzz_entry {
    use super::fat32;
    use super::vfs::FileSystem as _;

    const SECTOR: usize = 512;
    /// Smallest image handed to the driver: `image::build`'s default geometry
    /// (256 sectors). The input overlays its start, where every structure the
    /// driver parses lives; a longer input is the whole image (capped).
    const MIN_SECTORS: usize = 256;
    const MAX_BYTES: usize = 1 << 20;

    /// A name no seed uses, so the leak check below starts from "absent".
    const NEW: [u8; 11] = *b"FUZZNEW BIN";
    const MOVED: [u8; 11] = *b"FUZZMOV BIN";

    /// Harness-side precondition for the read-back check: every cluster of
    /// the root directory's chain is allocated in the first FAT. A FAT that
    /// calls a root-directory cluster free (fuzzer input, or a torn write
    /// from another implementation) lets the next allocation hand that
    /// cluster to file data, and the new dirent then lands inside the file it
    /// describes. The driver trusts the FAT there, as Linux's `vfat` does;
    /// that is an inconsistent volume, not a driver defect, so the check
    /// below only runs on volumes where it cannot happen.
    fn root_chain_allocated() -> bool { root_chain_len().is_some() }

    /// Harness-side precondition for the leak check: the volume the BPB
    /// describes (`BPB_TotSec32` from its base) fits on the medium. A bare
    /// medium gives the driver no size to check against, so a larger claim
    /// mounts and every write past the end fails with an I/O error — and an
    /// allocation whose FAT-mirror write fails keeps its first-FAT mark (a
    /// leak, but one that needs an I/O error; reported, not chased here).
    fn volume_fits(medium_sectors: u64) -> bool {
        let base = fat32::fat32_volume_base();
        let Some(s0) = fs_test_drivers::disk_peek(base) else { return false };
        let tot = u32::from_le_bytes([s0[32], s0[33], s0[34], s0[35]]) as u64;
        base + tot <= medium_sectors
    }

    /// Clusters in the root directory's chain, walking the first FAT on the
    /// medium; `None` if the chain meets a free entry, leaves the cluster
    /// range, or does not end within 4096 steps.
    fn root_chain_len() -> Option<u32> {
        root_chain().map(|c| c.len() as u32)
    }

    /// The root directory's clusters, in chain order; `None` as for
    /// [`root_chain_len`].
    fn root_chain() -> Option<Vec<u32>> {
        let base = fat32::fat32_volume_base();
        let s0 = fs_test_drivers::disk_peek(base)?;
        let mut c = u32::from_le_bytes([s0[44], s0[45], s0[46], s0[47]]) & 0x0FFF_FFFF;
        let mut chain = Vec::new();
        for _ in 1..=4096 {
            if c < 2 { return None; }
            chain.push(c);
            let v = fat_entry(c)?;
            if v == 0 { return None; }
            if v >= 0x0FFF_FFF8 { return Some(chain); }
            c = v;
        }
        None
    }

    /// The first FAT's bytes as the medium holds them (`BPB_FATSz32`
    /// sectors, cut where the medium ends).
    fn first_fat() -> Vec<u8> {
        let base = fat32::fat32_volume_base();
        let Some(s0) = fs_test_drivers::disk_peek(base) else { return Vec::new() };
        let rsvd = u16::from_le_bytes([s0[14], s0[15]]) as u64;
        let fsz = u32::from_le_bytes([s0[36], s0[37], s0[38], s0[39]]) as u64;
        let mut out = Vec::new();
        for i in 0..fsz.min(64) {
            match fs_test_drivers::disk_peek(base + rsvd + i) {
                Some(sec) => out.extend_from_slice(&sec[..]),
                None => break,
            }
        }
        out
    }

    /// Cluster `c`'s entry in the first FAT on the medium.
    fn fat_entry(c: u32) -> Option<u32> {
        let base = fat32::fat32_volume_base();
        let s0 = fs_test_drivers::disk_peek(base)?;
        let rsvd = u16::from_le_bytes([s0[14], s0[15]]) as u64;
        let byte = c as u64 * 4;
        let sec = fs_test_drivers::disk_peek(base + rsvd + byte / SECTOR as u64)?;
        let o = (byte % SECTOR as u64) as usize;
        Some(u32::from_le_bytes([sec[o], sec[o + 1], sec[o + 2], sec[o + 3]]) & 0x0FFF_FFFF)
    }

    /// How many clusters the root directory took out of the free count
    /// between `before` (cluster -> its first-FAT entry, read before the
    /// create) and now: the clusters of its chain now that were FREE (entry
    /// 0) then. A cluster the root already owned is not one, and neither is
    /// one whose entry was some other non-free value — the fuzzer's volume
    /// `regressions/fat32_image/root-fat-entry-reserved` gives the root's
    /// first cluster the reserved value 1: not counted free, ended the walk,
    /// and the extension relinked it; only the new cluster left the count.
    fn root_took(before: &dyn Fn(u32) -> Option<u32>) -> u64 {
        match root_chain() {
            Some(chain) => chain.iter().filter(|&&c| before(c) == Some(0)).count() as u64,
            None => 0,
        }
    }

    /// `FS_FUZZ_TRACE=1`: print each write-path step (triage of a finding).
    fn trace(msg: core::fmt::Arguments) {
        if std::env::var_os("FS_FUZZ_TRACE").is_some() { eprintln!("[fs-fuzz] {msg}"); }
    }

    fn free_clusters() -> Option<u64> {
        fat32::Fat32Fs.statfs().ok().map(|s| s.blocks_free)
    }

    /// Mount `data` as a FAT32 medium and drive the read and write paths over
    /// it. Panics (the fuzzer's crash signal) on any property violation; a
    /// refusal (`Err`) is always fine.
    pub fn fat32_image(data: &[u8]) {
        let data = &data[..data.len().min(MAX_BYTES)];
        let len = (data.len().max(MIN_SECTORS * SECTOR) + SECTOR - 1) / SECTOR * SECTOR;
        let mut img = vec![0u8; len];
        img[..data.len()].copy_from_slice(data);

        // `swap_medium`, for an image of any size.
        let _ = fat32::fat32_unmount(fat32::Volume::assume_mounted());
        fs_test_drivers::disk_load(img);
        for s in 0..(len / SECTOR) as u32 { fat32::fat32_cache_invalidate(s); }

        let Ok(vol) = fat32::fat32_mount_volume() else { return };

        // ── Read path ────────────────────────────────────────────────────
        let mut names: Vec<[u8; 11]> = Vec::new();
        fat32::fat32_ls_root(|name, _size, _dir| {
            if names.len() < 16 && name.len() <= 11 {
                let mut n = [b' '; 11];
                n[..name.len()].copy_from_slice(name);
                names.push(n);
            }
        });
        let mut buf = vec![0u8; 64 * 1024];
        for n in &names {
            if let Ok((first, _size)) = fat32::fat32_lookup_root(n) {
                let got = fat32::fat32_read_chain(first, &mut buf);
                assert!(got <= buf.len());
            }
            let _ = fat32::fat32_lookup_root_entry(n);
            let _ = fat32::fat32_check_root_chain(n);
        }
        if let Ok(mut it) = fat32::fat32_opendir(vol, b"/") {
            let mut k = 0;
            while let Some(e) = it.next() {
                assert!((e.name_len as usize) <= e.name.len());
                // Open whatever the listing names, as a path, and read it.
                let mut path = vec![b'/'];
                path.extend_from_slice(&e.name[..e.name_len as usize]);
                if e.is_dir {
                    if let Ok(mut sub) = fat32::fat32_opendir(vol, &path) {
                        let mut j = 0;
                        while sub.next().is_some() && j < 64 { j += 1; }
                    }
                } else if let Ok(f) = fat32::fat32_open(vol, &path, fat32::open_flags::READ) {
                    let mut chunk = [0u8; 4096];
                    let mut total = 0usize;
                    while let Ok(n) = fat32::fat32_read(f, &mut chunk) {
                        if n == 0 || total > 256 * 1024 { break; }
                        total += n;
                    }
                    let _ = fat32::fat32_file_stat(f);
                    let _ = fat32::fat32_close(f);
                }
                k += 1;
                if k >= 64 { break; }
            }
        }

        // ── Write path: no cluster may leak, what was written reads back ──
        if fat32::fat32_lookup_root(&NEW).is_err() && fat32::fat32_lookup_root(&MOVED).is_err() {
            if let Some(free0) = free_clusters() {
                let root_ok = root_chain_allocated();
                let fits = volume_fits((len / SECTOR) as u64);
                // The first FAT before the create, for `root_took`.
                let fat0 = first_fat();
                let payload: Vec<u8> =
                    data.iter().take(3000).enumerate().map(|(i, b)| b ^ i as u8).collect();
                let _ = fs_test_drivers::disk_take_log();
                let wrote = fat32::fat32_write_file(&NEW, &payload).is_ok();
                if std::env::var_os("FS_FUZZ_TRACE").is_some() {
                    for e in fs_test_drivers::disk_take_log() {
                        if let fs_test_drivers::LogEntry::Write(sec, b) = e {
                            trace(format_args!("  wrote sector {sec}: {:02x?}", &b[..16]));
                        }
                    }
                }
                trace(format_args!("free0={free0} root_ok={root_ok} write={wrote} free={:?} chain={:?}",
                    free_clusters(), fat32::fat32_check_root_chain(&NEW)));
                if wrote && root_ok {
                    // What `fat32_write_file` reported written is a sound chain
                    // holding exactly those bytes.
                    match fat32::fat32_check_root_chain(&NEW) {
                        Ok(Some((first, size))) => {
                            assert_eq!(size as usize, payload.len(), "written size");
                            if !payload.is_empty() {
                                let got = fat32::fat32_read_chain(first, &mut buf);
                                assert!(got >= payload.len(), "short read-back");
                                assert!(buf[..payload.len()] == payload[..], "read-back differs");
                            }
                        }
                        other => panic!("written file fails the chain check: {other:?}"),
                    }
                }
                // `fat32_unlink_path` is the unlink callers use; it frees the
                // chain (`fat32_unlink_root` only retires the dirent).
                if wrote && fat32::fat32_rename(&NEW, &MOVED).is_ok() {
                    trace(format_args!("rename ok free={:?} chain={:?}", free_clusters(),
                        fat32::fat32_check_root_chain(&MOVED)));
                    let r = fat32::fat32_unlink_path(b"FUZZMOV.BIN");
                    trace(format_args!("unlink {r:?} free={:?}", free_clusters()));
                } else {
                    let r = fat32::fat32_unlink_path(b"FUZZNEW.BIN");
                    trace(format_args!("unlink {r:?} free={:?}", free_clusters()));
                }
                if fat32::fat32_lookup_root(&NEW).is_err() && fat32::fat32_lookup_root(&MOVED).is_err() {
                    // A full root directory grows by a cluster for the new
                    // dirent and keeps it after the unlink (directories do
                    // not shrink): that cluster is in use, not leaked. A
                    // root whose first cluster the FAT marked free has no
                    // chain until an extension links one, and then that
                    // cluster left the free count too. Counted as what was
                    // FREE before: a root cluster whose entry held another
                    // value (1, reserved) was never in the count.
                    let grew = root_took(&|c| {
                        let o = c as usize * 4;
                        fat0.get(o..o + 4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]) & 0x0FFF_FFFF)
                    });
                    if let (Some(free1), true) = (free_clusters(), fits) {
                        assert_eq!(free1 + grew, free0, "create+unlink changed the free-cluster count");
                    }
                }
            }
        }
        let _ = fat32::fat32_mkdir(vol, b"/FZDIR");
        let _ = fat32::fat32_sync();
        let _ = fat32::fat32_unmount(vol);
    }
}

/// Regressions found by `tests/fuzz/fs-fuzz` (wave 11). Each failed with the
/// free-cluster count lower after the call than before it: a create or
/// overwrite that FAILED had already allocated (part of) its new chain, and
/// nothing gave it back. Mount-time recovery does not either — it discards a
/// PENDING `WRITE_DIR` record without touching the FAT — so every failed
/// write shrank the volume for good. Disk full is the everyday trigger.
#[cfg(test)]
mod fuzz_regressions {
    use super::vfs::FileSystem as _;
    use super::{fat32, image::*, serial};

    const EOC: u32 = 0x0FFF_FFFF;

    fn free() -> u64 {
        fat32::Fat32Fs.statfs().expect("statfs on a mounted volume").blocks_free
    }

    fn mounted_default() -> Geom {
        let g = Geom::default();
        let mut img = build(&g);
        set_fat(&mut img, &g, 0, 0x0FFF_FFF8);
        set_fat(&mut img, &g, 1, 0xFFFF_FFFF);
        set_fat(&mut img, &g, 2, EOC); // root directory
        super::swap_medium(img);
        assert_eq!(fat32::fat32_mount(), Ok(()), "the fixture must mount");
        g
    }

    /// **The root's first cluster is never allocated**, even on a volume
    /// whose FAT marks it free (fs-fuzz, wave 12: the input in
    /// `regressions/fat32_image/root-cluster-free-self-link`). It used to be
    /// the first free entry the allocator found, and a directory extension
    /// then linked the root to itself: a one-cluster cycle every later walk
    /// of the root refuses. **Canary:** drop the `root_cluster` skip in
    /// `fat32_alloc_cluster_locked`: the first allocation returns 2.
    #[test]
    fn the_root_cluster_is_never_allocated_even_when_marked_free() {
        let _g = serial();
        let g = Geom::default();
        let mut img = build(&g);
        set_fat(&mut img, &g, 0, 0x0FFF_FFF8);
        set_fat(&mut img, &g, 1, 0xFFFF_FFFF);
        // FAT[root] left 0: the root is marked free.
        super::swap_medium(img);
        assert_eq!(fat32::fat32_mount(), Ok(()), "the fixture must mount");
        let root = g.root_clus;
        for _ in 0..4 {
            let c = fat32::fat32_alloc_cluster().expect("free clusters");
            assert_ne!(c, root, "the root's cluster was handed out");
        }
    }

    /// A create larger than the free space fails — and must hand back every
    /// cluster it took on the way. **Canary:** without the fix this reports
    /// `left: 0, right: 207` (the chain filled the volume and stayed).
    #[test]
    fn a_create_that_runs_out_of_space_leaks_no_cluster() {
        let _g = serial();
        mounted_default();
        let before = free();
        let big = vec![0xA5u8; (before as usize + 4) * SECTOR];
        assert_eq!(fat32::fat32_write_file(b"BIG     BIN", &big), Err(()));
        assert_eq!(free(), before, "a failed create kept clusters");
        assert!(fat32::fat32_lookup_root(b"BIG     BIN").is_err(), "no dirent for a failed create");
        assert!(fat32::fat32_journal_idle(), "the failed create left its journal record");
    }

    /// The overwrite half: replacing a one-cluster file with one too large
    /// for the volume fails, the old file stays, and nothing leaks.
    #[test]
    fn an_overwrite_that_runs_out_of_space_leaks_no_cluster() {
        let _g = serial();
        mounted_default();
        assert_eq!(fat32::fat32_write_file(b"OLD     BIN", b"old contents"), Ok(()));
        let before = free();
        let big = vec![0x5Au8; (before as usize + 4) * SECTOR];
        assert_eq!(fat32::fat32_write_file(b"OLD     BIN", &big), Err(()));
        assert_eq!(free(), before, "a failed overwrite kept clusters");
        let (first, size) = fat32::fat32_lookup_root(b"OLD     BIN").expect("old file survives");
        assert_eq!(size, 12);
        let mut buf = vec![0u8; SECTOR];
        assert!(fat32::fat32_read_chain(first, &mut buf) >= 12);
        assert_eq!(&buf[..12], b"old contents");
    }

    /// The fuzzer's input (`tests/fuzz/fs-fuzz/regressions/fat32_image/
    /// create-dirent-fails`): a root directory the new dirent cannot be
    /// inserted into, so `dir_insert` fails AFTER the data chain was written.
    /// **Canary:** without the fix, `left: 57, right: 63`.
    #[test]
    fn a_create_whose_dirent_insert_fails_leaks_no_cluster() {
        let _g = serial();
        let img = include_bytes!("../../../fuzz/fs-fuzz/regressions/fat32_image/create-dirent-fails");
        let mut v = img.to_vec();
        v.resize(256 * SECTOR, 0);
        super::swap_medium(v);
        assert_eq!(fat32::fat32_mount(), Ok(()), "the fuzzer's volume mounts");
        let before = free();
        let payload = vec![0x3Cu8; 3000];
        assert_eq!(fat32::fat32_write_file(b"FUZZNEW BIN", &payload), Err(()));
        assert_eq!(free(), before, "a failed create kept clusters");
    }

    /// The fuzzer's volume (`regressions/fat32_image/root-fat-entry-reserved`,
    /// wave 11 gate tag 4b457f6f: "create+unlink changed the free-cluster
    /// count", 200 vs 201): the root directory's first FAT entry holds the
    /// reserved value 1. That is not a free entry, so it is not in the free
    /// count, and it ends the root's chain; the rename's dirent extends the
    /// root by ONE fresh cluster, relinking the first. Create, rename and
    /// unlink therefore cost exactly that one cluster. The crash was the
    /// harness counting the root's first cluster as freed-then-taken (its
    /// arm for a FAT that marks the root free); `root_took` now counts what
    /// was free before.
    /// **Canary:** skip `fat32_free_chain` in `fat32_unlink_path`: `left`
    /// is six clusters short.
    #[test]
    fn a_root_whose_fat_entry_is_reserved_grows_by_one_cluster_and_leaks_none() {
        let _g = serial();
        let img = include_bytes!("../../../fuzz/fs-fuzz/regressions/fat32_image/root-fat-entry-reserved");
        let mut v = img.to_vec();
        v.resize(256 * SECTOR, 0);
        super::swap_medium(v);
        assert_eq!(fat32::fat32_mount(), Ok(()), "the fuzzer's volume mounts");
        let before = free();
        let payload = vec![0x5Au8; 3000];
        assert_eq!(fat32::fat32_write_file(b"FUZZNEW BIN", &payload), Ok(()));
        assert!(fat32::fat32_rename(b"FUZZNEW BIN", b"FUZZMOV BIN").is_ok());
        assert_eq!(fat32::fat32_unlink_path(b"FUZZMOV.BIN"), Ok(()));
        assert!(fat32::fat32_lookup_root(b"FUZZMOV BIN").is_err());
        // Wave 15: the rename rewrites the dirent in place, so the root no
        // longer grows for it: the three operations cost nothing.
        assert_eq!(free(), before, "create+rename+unlink must leave the free count as it was");
    }

    /// `BPB_RootClus` outside the data region is refused at mount. The
    /// fuzzer's volume (`regressions/fat32_image/root-cluster-past-eoc`)
    /// carried `0xFFFF_FFFF` and mounted; each create then lost a cluster.
    /// The default geometry has 208 data clusters: 2..=209 are valid.
    /// **Canary:** drop the check and the first assertion fails with
    /// `root_clus=4294967295 mounted`.
    #[test]
    fn a_root_cluster_outside_the_data_region_is_refused() {
        let _g = serial();
        for (root, ok) in [(0xFFFF_FFFFu32, false), (0x0FFF_FFFF, false), (0, false), (1, false),
                           (210, false), (209, true), (2, true)] {
            let g = Geom { root_clus: root, ..Geom::default() };
            let mut img = build(&g);
            if ok { set_fat(&mut img, &g, root, EOC); }
            super::swap_medium(img);
            assert_eq!(fat32::fat32_mount().is_ok(), ok, "root_clus={root} mounted={}", !ok);
        }
    }
}

// ── pstore: the RAM panic record (`crates/fs/fs/src/pstore.rs`) ─────────────
//
// The format is pure, so most tests are plain slices. The last two take the
// recovery line through the real `crash_log::record_entry` onto a volume, the
// same call `kernel/src/pstore.rs::recover` makes at boot.
#[cfg(test)]
mod pstore_record {
    use super::{crash_log, pstore, serial, vfs};
    use super::vfs_open_close::{fresh_volume, on_disk};
    use pstore::{Record, Reject};

    const ENTRY: &[u8] = b"[t=42] hart=0 task=init at kernel/src/x.rs:7 boom\n";

    fn written(len: usize, payload: &[u8]) -> Vec<u8> {
        let mut r = vec![0u8; len];
        assert_eq!(pstore::encode(&mut r, payload), payload.len().min(pstore::capacity(len)));
        r
    }

    /// The CRC is IEEE CRC-32: the standard check value.
    #[test]
    fn crc32_matches_the_ieee_check_value() {
        assert_eq!(pstore::crc32(0, b"123456789"), 0xCBF4_3926);
        assert_eq!(pstore::crc32(pstore::crc32(0, b"1234"), b"56789"), 0xCBF4_3926,
            "feeding the result back continues the same CRC");
    }

    #[test]
    fn a_written_record_reads_back_whole() {
        let r = written(4096, ENTRY);
        assert_eq!(&r[..8], &pstore::PSTORE_MAGIC);
        assert_eq!(pstore::decode(&r), Record::Valid(ENTRY));
    }

    /// Zeroed RAM (QEMU's first boot) and RAM without the magic (a board's
    /// power-on contents) are both "no record", never a rejection.
    #[test]
    fn ram_without_the_magic_is_empty() {
        assert_eq!(pstore::decode(&[0u8; 4096]), Record::Empty);
        let noise: Vec<u8> = (0..4096u32).map(|i| (i.wrapping_mul(2654435761) >> 13) as u8).collect();
        assert_eq!(pstore::decode(&noise), Record::Empty);
        assert_eq!(pstore::decode(&[0u8; 8]), Record::Empty, "shorter than a header");
        let mut out = [0u8; 64];
        assert_eq!(pstore::recovery_line(&Record::Empty, &mut out), 0);
    }

    /// The canary the gate row repeats in QEMU: one payload bit flipped
    /// after the CRC was taken.
    #[test]
    fn a_flipped_payload_bit_is_rejected_with_both_crcs() {
        let mut r = written(4096, ENTRY);
        r[pstore::PSTORE_HEADER_LEN + 5] ^= 0x01;
        match pstore::decode(&r) {
            Record::Rejected(Reject::Checksum { stored, computed }) => assert_ne!(stored, computed),
            other => panic!("want a checksum rejection, got {other:?}"),
        }
    }

    /// The CRC covers the length and the version too, not only the payload:
    /// a shorter length still inside the region must not pass as a valid,
    /// shorter record.
    #[test]
    fn a_damaged_header_is_rejected() {
        let mut r = written(4096, ENTRY);
        r[12] = r[12].wrapping_sub(1);
        assert!(matches!(pstore::decode(&r), Record::Rejected(Reject::Checksum { .. })),
            "length shortened in place: {:?}", pstore::decode(&r));

        let mut r = written(4096, ENTRY);
        r[12..16].copy_from_slice(&5000u32.to_le_bytes());
        assert_eq!(pstore::decode(&r), Record::Rejected(Reject::Length { len: 5000, cap: 4096 - 24 }));

        let mut r = written(4096, ENTRY);
        r[8..12].copy_from_slice(&2u32.to_le_bytes());
        assert_eq!(pstore::decode(&r), Record::Rejected(Reject::Version(2)));
    }

    #[test]
    fn a_payload_longer_than_the_region_is_truncated_not_overrun() {
        let long = vec![b'x'; 100];
        let r = written(64, &long);
        assert_eq!(pstore::decode(&r), Record::Valid(&long[..64 - pstore::PSTORE_HEADER_LEN]));
        let mut tiny = [0u8; 16];
        assert_eq!(pstore::encode(&mut tiny, ENTRY), 0, "no room for a header: nothing written");
        assert_eq!(tiny, [0u8; 16]);
    }

    /// A new record replaces an old one completely, and `clear` leaves
    /// nothing a later decode would accept.
    #[test]
    fn rewrite_and_clear() {
        let mut r = written(4096, b"an older, longer entry that came first\n");
        pstore::encode(&mut r, ENTRY);
        assert_eq!(pstore::decode(&r), Record::Valid(ENTRY));
        pstore::clear(&mut r);
        assert_eq!(pstore::decode(&r), Record::Empty);
        assert_eq!(&r[..pstore::PSTORE_HEADER_LEN], &[0u8; 24]);
    }

    #[test]
    fn recovery_lines() {
        let mut out = [0u8; 640];
        let n = pstore::recovery_line(&Record::Valid(ENTRY), &mut out);
        assert_eq!(&out[..n], [b"[pstore] ".as_slice(), ENTRY].concat().as_slice());

        let n = pstore::recovery_line(&Record::Valid(b"no newline"), &mut out);
        assert_eq!(&out[..n], b"[pstore] no newline\n");

        let rej = Record::Rejected(Reject::Checksum { stored: 0xDEAD_BEEF, computed: 0x0000_00A1 });
        let n = pstore::recovery_line(&rej, &mut out);
        assert_eq!(&out[..n],
            b"[pstore] corrupt record discarded: checksum stored 0xdeadbeef computed 0x000000a1\n");

        let mut small = [0u8; 12];
        let n = pstore::recovery_line(&Record::Valid(ENTRY), &mut small);
        assert_eq!(n, 12);
        assert_eq!(small[11], b'\n', "a truncated line still ends the CRASH.LOG entry");
    }

    /// End to end on a real volume: the record a panic left goes into
    /// `/fat/CRASH.LOG` with its prefix, exactly once.
    #[test]
    fn a_recovered_record_lands_in_crash_log() {
        let _g = serial();
        fresh_volume();
        let mut t = vfs::ScratchFds::new();
        let r = written(4096, ENTRY);
        let mut line = [0u8; 640];
        let n = pstore::recovery_line(&pstore::decode(&r), &mut line);
        let out = crash_log::record_entry(&mut t, &line[..n]);
        assert_eq!(out.write, crash_log::WriteResult::Written);
        assert_eq!(on_disk(b"crash.log"), [b"[pstore] ".as_slice(), ENTRY].concat());
    }

    #[test]
    fn a_rejected_record_leaves_a_note_not_its_text() {
        let _g = serial();
        fresh_volume();
        let mut t = vfs::ScratchFds::new();
        let mut r = written(4096, ENTRY);
        r[pstore::PSTORE_HEADER_LEN] ^= 0x01;
        let mut line = [0u8; 640];
        let n = pstore::recovery_line(&pstore::decode(&r), &mut line);
        assert_eq!(crash_log::record_entry(&mut t, &line[..n]).write, crash_log::WriteResult::Written);
        let log = on_disk(b"crash.log");
        assert!(log.starts_with(b"[pstore] corrupt record discarded: checksum stored 0x"),
            "{}", String::from_utf8_lossy(&log));
        assert!(!log.windows(4).any(|w| w == b"boom"), "the damaged text must not be copied");
    }
}

// Wave 14 (FATCACHE): the FAT32 sector cache at a real size (Kconfig
// `FS_BLOCK_CACHE_KB`; the limits shim says 64 KiB, embedded's default) —
// file data served from RAM on a repeat, and one test per coherence path:
// FAT32's own writes, writes through the block layer (USB mass-storage
// gadget, reserved-tail records), a writer that reports itself
// (`SYS_DISK_WRITE`), a long external write, writes outside the volume, and
// a write racing a fill. Each names the canary feature that turns it red.
#[cfg(test)]
mod fatcache {
    use super::{fat32, image::*, serial, vfs};
    use super::vfs_open_close::fresh_volume;
    use fs_test_drivers::{blkdev, disk_peek, disk_poke, disk_stats, disk_write_during_read_of};

    const NAME: [u8; 11] = *b"VSB     ELF";
    const PATH: &[u8] = b"/fat/VSB.ELF";
    /// 41 sectors: the size of the 20.5 KB image `spawn+wait` and
    /// `file-ord` read.
    const LEN: usize = 41 * 512;

    fn body(seed: u8) -> Vec<u8> {
        (0..LEN).map(|i| (i as u32).wrapping_mul(7).wrapping_add(seed as u32) as u8).collect()
    }

    /// `file-ord`'s shape: open read-only, read `n` bytes, close.
    fn open_read_close(n: usize) -> Vec<u8> {
        let mut t = vfs::ScratchFds::new();
        let fd = vfs::vfs_open(&mut t, PATH, vfs::O_RDONLY);
        assert!(fd >= 0, "the open must succeed");
        let mut buf = vec![0u8; n];
        let got = vfs::vfs_read(&mut t, fd, buf.as_mut_ptr(), n);
        assert_eq!(vfs::vfs_close(&mut t, fd), 0);
        assert!(got >= 0, "the read must succeed");
        buf.truncate(got as usize);
        buf
    }

    /// Fresh volume, the image written through the driver, read once so the
    /// cache holds it. Returns the volume sector of its first data cluster.
    fn warm(seed: u8) -> usize {
        fresh_volume();
        assert_eq!(fat32::fat32_write_file(&NAME, &body(seed)), Ok(()));
        assert_eq!(open_read_close(LEN), body(seed), "the image reads back");
        let (cl, size) = fat32::fat32_lookup_root(&NAME).expect("the image is listed");
        assert_eq!(size as usize, LEN);
        cluster_sector(&Geom::default(), cl)
    }

    fn reads() -> u32 { disk_stats().0 }

    /// **A repeated open/read/close is served from RAM.** After one warm
    /// read, ten `file-ord` iterations and ten whole-image reads (the spawn
    /// read's shape, `read_all`) issue no device read at all: the directory
    /// sector, the FAT sector and all 41 data sectors hit.
    ///
    /// **Canary.** `fatcache-run-bypass-canary` (run reads go to the device
    /// as before wave 14): every iteration reads the device again.
    #[test]
    fn a_repeated_open_read_close_is_served_from_ram() {
        let _g = serial();
        warm(1);
        let before = reads();
        for _ in 0..10 {
            assert_eq!(open_read_close(64), body(1)[..64]);
        }
        for _ in 0..10 {
            assert_eq!(super::vfs_open_close::on_disk(b"vsb.elf"), body(1));
        }
        assert_eq!(reads() - before, 0, "a warm image must not touch the device");
        let (h, m) = fat32::fat32_cache_stats();
        assert!(h > m, "{h} hits, {m} misses");
    }

    /// **FAT32's own writes update the cached lines (write-through).** The
    /// image is rewritten with other contents and another length; the
    /// directory and FAT sectors the cache holds are written in place, so the
    /// next open must see the new entry and the new chain.
    ///
    /// **Canary.** `fatcache-writethrough-canary` (`write_sector` skips
    /// `update_if_present`): the cached directory sector still names the old
    /// size and chain, and the old bytes come back.
    #[test]
    fn fat32_own_writes_update_the_cached_lines() {
        let _g = serial();
        warm(2);
        let new: Vec<u8> = body(3)[..3000].to_vec();
        assert_eq!(fat32::fat32_write_file(&NAME, &new), Ok(()));
        assert_eq!(open_read_close(LEN), new, "the rewrite must be what is read");
    }

    /// **A write through the block layer drops the cached sector** — the USB
    /// mass-storage gadget's WRITE_10 and the reserved-tail records both go
    /// through `blkdev::write`, which reports to the observer. A host
    /// rewriting the image's first data sector, and then its directory entry
    /// (size 100), must be seen by the next open.
    ///
    /// **Canary.** `fatcache-observer-canary`: the cached sectors answer and
    /// the old bytes / old size come back.
    #[test]
    fn a_block_layer_write_drops_the_cached_sector() {
        let _g = serial();
        let s = warm(4) as u64;
        let host = [0x5Au8; 512];
        blkdev::write(s, 1, &host).expect("the gadget's write");
        assert_eq!(open_read_close(512), host.to_vec(), "the data sector the host wrote");

        // The directory entry: the root directory is cluster 2.
        let root = cluster_sector(&Geom::default(), 2) as u64;
        let mut dir = disk_peek(root).expect("the root directory sector");
        let at = dir.chunks(32).position(|e| e[..11] == NAME).expect("the entry") * 32;
        dir[at + 28..at + 32].copy_from_slice(&100u32.to_le_bytes());
        blkdev::write(root, 1, &dir).expect("the gadget's write");
        assert_eq!(fat32::fat32_lookup_root(&NAME).map(|e| e.1), Ok(100), "the size the host wrote");
        assert_eq!(open_read_close(LEN).len(), 100);
    }

    /// **A writer that reports itself is coherent too** — ring-3
    /// `SYS_DISK_WRITE` writes `virtio::blk` directly and then calls
    /// `blkdev::note_external_write`. Modelled as a write that bypasses the
    /// driver (`disk_poke`) followed by that report.
    ///
    /// **Canary.** `fatcache-observer-canary`.
    #[test]
    fn a_reported_raw_write_drops_the_cached_sector() {
        let _g = serial();
        let s = warm(5) as u64;
        let raw = [0xC3u8; 512];
        disk_poke(s + 1, &raw);
        blkdev::note_external_write(s + 1, 1);
        assert_eq!(open_read_close(1024)[512..], raw[..], "the sector written past the driver");
    }

    /// **A long external write drops the whole cache**, in O(1): more than a
    /// set's worth of sectors (16 here) is a generation bump, not 16 probes.
    /// The written sectors read back new, and a sector the write did not
    /// touch is read from the device again (it was dropped too).
    ///
    /// **Canary.** `fatcache-observer-canary`.
    #[test]
    fn a_long_external_write_drops_the_whole_cache() {
        let _g = serial();
        let s = warm(6) as u64;
        let long = vec![0x77u8; 16 * 512];
        blkdev::write(s, 16, &long).expect("a 16-sector write");
        let before = reads();
        let got = open_read_close(LEN);
        assert_eq!(got[..16 * 512], long[..], "the 16 sectors written");
        assert_eq!(got[16 * 512..], body(6)[16 * 512..], "the rest of the image");
        assert!(reads() > before, "the cache was not dropped");
    }

    /// **A write outside the volume keeps the cache; one inside maps through
    /// the partition base.** The volume sits at LBA 2048. Writes to the MBR,
    /// to medium LBA = the image's VOLUME-relative sector (in the gap before
    /// the partition) and to the tail past the volume drop nothing: the next
    /// read issues no device read. A write at base + that sector is the
    /// image's sector and must be seen.
    ///
    /// **Canary.** Drop `- base` in `fat32_on_medium_write`: the gap write
    /// drops the image's sector (a device read) and the in-volume write
    /// drops the wrong one (stale bytes). `fatcache-observer-canary` also
    /// fails the last assertion.
    #[test]
    fn writes_outside_the_volume_keep_the_cache() {
        let _g = serial();
        use super::partitioned_volume::{medium, publish, BASE};
        let (mut m, vol_sectors) = medium(0);
        let o = 446 + 12;
        m[o..o + 4].copy_from_slice(&(vol_sectors as u32).to_le_bytes());
        publish(&m);
        let mbr = m[..512].to_vec();
        super::swap_medium(m);
        assert_eq!(fat32::fat32_mount(), Ok(()));
        super::vfs_open_close::vfs_once();
        assert_eq!(fat32::fat32_volume_base(), BASE);
        assert_eq!(fat32::fat32_write_file(&NAME, &body(7)), Ok(()));
        assert_eq!(open_read_close(LEN), body(7));
        let (cl, _) = fat32::fat32_lookup_root(&NAME).unwrap();
        let s = cluster_sector(&Geom::default(), cl) as u64;

        let before = reads();
        blkdev::write(0, 1, &mbr).expect("the MBR");
        blkdev::write(s, 1, &[0xEEu8; 512]).expect("the gap");
        let tail = BASE + vol_sectors as u64;
        blkdev::write(tail, 8, &[0u8; 8 * 512]).expect("the tail");
        assert_eq!(open_read_close(LEN), body(7), "writes outside the volume change nothing");
        assert_eq!(reads() - before, 0, "and drop nothing");

        blkdev::write(BASE + s, 1, &[0x99u8; 512]).expect("in the volume");
        assert_eq!(open_read_close(512), vec![0x99u8; 512], "the image's own sector");

        super::partition::reset_for_tests();
        super::swap_medium(super::image::build(&Geom::default()));
    }

    /// **A write racing a fill is not installed.** The first read of the
    /// image misses; while its device read is in flight (after the device
    /// returned the old bytes, before they are installed) another writer
    /// rewrites the first data sector through the block layer. The read in
    /// flight may return the old bytes — it raced — but the cache must not
    /// keep them: the next read sees the new ones.
    ///
    /// **Canary.** `fatcache-token-canary` (the install token taken after
    /// the device read instead of before): the old bytes are installed and
    /// answer the second read.
    #[test]
    fn a_write_racing_a_fill_is_not_installed() {
        let _g = serial();
        let _wt = crate::write_through();
        fresh_volume();
        assert_eq!(fat32::fat32_write_file(&NAME, &body(8)), Ok(()));
        let (cl, _) = fat32::fat32_lookup_root(&NAME).unwrap();
        let s = cluster_sector(&Geom::default(), cl) as u64;
        let new = [0x3Cu8; 512];
        disk_write_during_read_of(s, s, &new);
        let mut out = vec![0u8; LEN];
        assert_eq!(fat32::fat32_read_chain(cl, &mut out), LEN);
        assert_eq!(out[..512], body(8)[..512], "the racing read saw the old bytes (the race happened)");
        assert_eq!(fat32::fat32_read_chain(cl, &mut out), LEN);
        assert_eq!(out[..512], new[..], "the second read must not be served the stale fill");
        assert_eq!(out[512..], body(8)[512..]);
    }

    /// **Every writer of the medium is accounted for** (a source inventory,
    /// so a new writer cannot be added without deciding how the cache learns
    /// of it):
    /// * `blkdev::write` is coherent by construction (it notifies) — any
    ///   number of callers;
    /// * `blkdev::write_quiet` (no notification) only in `fat32.rs`, whose
    ///   write path updates the cache itself;
    /// * `virtio::blk::write(` only in `blkdev.rs` (the backend) and in
    ///   `handlers.rs`'s `sys_disk_write`, which must then call
    ///   `note_external_write`;
    /// * `mmc_write(` only in `blkdev.rs` (the backend) and the QEMU-only MMC
    ///   flush smoke, which writes a second, `sdhci-pci` card, never the
    ///   medium FAT32 mounts.
    ///
    /// **Canary.** Delete the `note_external_write` call in
    /// `sys_disk_write`, or call `write_quiet` from `msc_gadget.rs`: red.
    #[test]
    fn every_medium_writer_is_accounted_for() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
        let mut files = Vec::new();
        for d in ["crates", "kernel", "domains", "userspace"] {
            walk(&root.join(d), &mut files);
        }
        let mut quiet = Vec::new();
        let mut virtio = Vec::new();
        let mut mmc = Vec::new();
        for f in &files {
            let src = std::fs::read_to_string(f).unwrap_or_default();
            let rel = f.strip_prefix(&root).unwrap().to_string_lossy().replace('\\', "/");
            for line in src.lines() {
                let l = line.trim_start();
                if l.starts_with("//") || l.contains("fn ") { continue; }
                if l.contains("blkdev::write_quiet(") { quiet.push(rel.clone()); }
                if l.contains("virtio::blk::write(") { virtio.push(rel.clone()); }
                if l.contains("mmc_write(") { mmc.push(rel.clone()); }
            }
        }
        quiet.dedup();
        virtio.dedup();
        mmc.dedup();
        assert_eq!(quiet, ["crates/fs/fs/src/fat32.rs"], "write_quiet outside FAT32's write path");
        assert_eq!(virtio, ["crates/core/syscall/src/handlers.rs", "crates/drivers/block/src/blkdev.rs"],
                   "a new direct virtio-blk writer");
        assert_eq!(mmc, ["crates/drivers/block/src/blkdev.rs", "kernel/src/smokes/storage.rs"],
                   "a new direct MMC writer");
        let h = std::fs::read_to_string(root.join("crates/core/syscall/src/handlers.rs")).unwrap();
        let body = &h[h.find("pub fn sys_disk_write(").expect("sys_disk_write")..];
        let body = &body[..body.find("\n}\n").expect("its end")];
        let w = body.find("virtio::blk::write(").expect("its device write");
        let n = body.find("blkdev::note_external_write(sector, count as u32)")
            .expect("sys_disk_write must report its write to the block cache");
        assert!(n > w, "the report must follow the write");
    }

    fn walk(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        let Ok(rd) = std::fs::read_dir(dir) else { return };
        let mut v: Vec<_> = rd.filter_map(|e| e.ok()).map(|e| e.path()).collect();
        v.sort();
        for p in v {
            if p.is_dir() {
                if p.file_name().map_or(false, |n| n == "target") { continue; }
                walk(&p, out);
            } else if p.extension().map_or(false, |e| e == "rs") {
                out.push(p);
            }
        }
    }
}

// Wave 14 (FATCACHE): `bcache.rs`'s sets and generations, against a
// recording device.
#[cfg(test)]
mod bcache_sets {
    use super::bcache::{BlockCache, BlockIo, IoError, Mode, MAX_WAYS};

    struct Dev { data: Vec<u8>, reads: Vec<u64> }

    impl Dev {
        fn new(sectors: usize) -> Self {
            Dev { data: (0..sectors * 512).map(|i| (i / 512) as u8).collect(), reads: Vec::new() }
        }
    }

    impl BlockIo for Dev {
        type FlushErr = ();
        fn read(&mut self, lba: u64, count: u32, buf: &mut [u8]) -> Result<(), ()> {
            let o = lba as usize * 512;
            buf.copy_from_slice(&self.data[o..o + count as usize * 512]);
            self.reads.push(lba);
            Ok(())
        }
        fn write(&mut self, lba: u64, count: u32, buf: &[u8]) -> Result<(), ()> {
            let o = lba as usize * 512;
            self.data[o..o + count as usize * 512].copy_from_slice(buf);
            Ok(())
        }
        fn flush(&mut self) -> Result<(), ()> { Ok(()) }
    }

    type Big = BlockCache<{ 64 * 512 }, 64>;

    fn rd(c: &mut Big, d: &mut Dev, b: u64) -> u8 {
        let mut buf = [0u8; 512];
        c.read(d, b, &mut buf).unwrap();
        buf[0]
    }

    /// **Past 8 lines a write-through cache is 8-way set-associative, LRU per
    /// set.** 64 lines = 8 sets. Blocks 0..64 fill every set; block 64 maps
    /// to set 0 and evicts that set's least recently used line (block 0), not
    /// block 1 (set 1, untouched). A write-back cache of the same size stays
    /// one fully associative set.
    ///
    /// **Canary.** `set_mask` 0 (one 64-way set): block 0 is still the LRU,
    /// but `ways()` is 64 and the assertion on it fails; with LRU taken
    /// across sets instead of within one, block 1 would be evicted instead.
    #[test]
    fn a_large_write_through_cache_is_eight_way_set_associative() {
        let mut d = Dev::new(256);
        let mut c = Big::new(512, Mode::WriteThrough);
        assert_eq!((c.line_count(), c.ways()), (64, MAX_WAYS));
        for b in 0..64 { assert_eq!(rd(&mut c, &mut d, b), b as u8); }
        assert_eq!(d.reads.len(), 64);
        for b in 1..64 { rd(&mut c, &mut d, b); }     // every line but 0 used again
        assert_eq!(d.reads.len(), 64, "all 64 resident");
        rd(&mut c, &mut d, 64);
        rd(&mut c, &mut d, 1);
        rd(&mut c, &mut d, 8);
        assert_eq!(d.reads.len(), 65, "64 evicted block 0 of its set, nothing else");
        rd(&mut c, &mut d, 0);
        assert_eq!(d.reads.len(), 66, "block 0 was the victim");

        // Wave 15: write-back is set-associative too (evicting a dirty line
        // writes every older epoch first, so the choice need not be global).
        let wb = Big::new(512, Mode::WriteBack);
        assert_eq!((wb.line_count(), wb.ways()), (64, MAX_WAYS));
        // 12 lines: one set of 8, the remainder unused.
        let odd: BlockCache<{ 12 * 512 }, 12> = BlockCache::new(512, Mode::WriteThrough);
        assert_eq!((odd.line_count(), odd.ways()), (8, 8));
    }

    /// **`invalidate_all` is a generation bump, and the wrap cannot revive a
    /// line.** After a drop every block misses; a line stamped long ago
    /// stays dead when the generation wraps past it.
    ///
    /// **Canary.** On wrap, set the generation to 1 without wiping the
    /// stamps (`if self.gen == 0 { self.gen = 1 }`): block 5, stamped 1,
    /// answers again.
    #[test]
    fn invalidate_all_is_o1_and_survives_the_wrap() {
        let mut d = Dev::new(64);
        let mut c = Big::new(512, Mode::WriteThrough);
        rd(&mut c, &mut d, 5);
        c.invalidate_all();
        let n = d.reads.len();
        rd(&mut c, &mut d, 5);
        assert_eq!(d.reads.len(), n + 1, "dropped");

        let mut c = Big::new(512, Mode::WriteThrough);   // generation 1
        rd(&mut c, &mut d, 5);                            // stamped 1
        c.force_generation(u32::MAX);
        c.invalidate_all();                               // wraps
        let n = d.reads.len();
        rd(&mut c, &mut d, 5);
        assert_eq!(d.reads.len(), n + 1, "a pre-wrap stamp revived");
    }

    /// **`invalidate_range` drops exactly its blocks up to a set's worth, and
    /// everything beyond.** 8 blocks: only those miss afterwards. 9 blocks:
    /// the whole cache.
    #[test]
    fn invalidate_range_is_exact_up_to_a_set_and_total_beyond() {
        let mut d = Dev::new(128);
        let mut c = Big::new(512, Mode::WriteThrough);
        for b in 0..32 { rd(&mut c, &mut d, b); }
        c.invalidate_range(4, 8);
        let n = d.reads.len();
        for b in 0..32 { rd(&mut c, &mut d, b); }
        assert_eq!(d.reads[n..], (4..12).collect::<Vec<u64>>()[..]);
        c.invalidate_range(100, 9);
        let n = d.reads.len();
        for b in 0..32 { rd(&mut c, &mut d, b); }
        assert_eq!(d.reads.len() - n, 32, "more than a set: everything dropped");
    }

    /// **`lookup_bytes` copies a slice of a cached line, and nothing else.**
    /// The FAT walk reads 4 bytes of a cached FAT sector this way. A miss,
    /// and a range that runs past the line, copy nothing.
    #[test]
    fn lookup_bytes_copies_a_slice_of_a_cached_line() {
        let mut d = Dev::new(64);
        d.data[9 * 512 + 100..9 * 512 + 104].copy_from_slice(&[1, 2, 3, 4]);
        let mut c = Big::new(512, Mode::WriteThrough);
        let mut w = [0u8; 4];
        assert!(!c.lookup_bytes(9, 100, &mut w), "not cached yet");
        rd(&mut c, &mut d, 9);
        assert!(c.lookup_bytes(9, 100, &mut w));
        assert_eq!(w, [1, 2, 3, 4]);
        assert!(!c.lookup_bytes(9, 509, &mut w), "past the line");
        assert!(!c.lookup_bytes(10, 100, &mut w), "another block");
        assert_eq!(d.reads, [9]);
    }

    /// **An unconfigured cache keeps nothing and refuses whole-block calls;
    /// `configure` makes it a cache.** The FAT32 static starts this way so
    /// its storage is `.bss`.
    #[test]
    fn an_unconfigured_cache_keeps_nothing_until_configured() {
        let mut d = Dev::new(64);
        let mut c = Big::unconfigured();
        let mut buf = [0u8; 512];
        assert!(!c.lookup(3, &mut buf));
        assert!(!c.install(3, &buf, c.lookup_miss_token()));
        assert!(!c.lookup(3, &mut buf));
        assert_eq!(c.read(&mut d, 3, &mut buf), Err(IoError::Range));
        c.invalidate(3);
        c.invalidate_all();
        c.configure(512, Mode::WriteThrough, 0).unwrap();
        assert_eq!(rd(&mut c, &mut d, 3), 3);
        assert_eq!(rd(&mut c, &mut d, 3), 3);
        assert_eq!(d.reads, [3], "configured: the second read hits");
    }
}

// Wave 14 (FATCACHE, second step): read-only opens of a FAT32 file stream
// (`vfs.rs` `try_backend_ro_stream_open`, `fat32.rs` `fat32_read_range`)
// instead of loading the whole file into a heap proxy.
#[cfg(test)]
mod ro_stream {
    use super::{fat32, image::*, serial, vfs};

    /// A volume with `spc` sectors per cluster and one file, `FRAG.BIN`, whose
    /// chain is `chain` (clusters in order, deliberately fragmented) and whose
    /// byte `i` is `pat(i)`. Mounted, and `/fat` registered.
    fn volume(spc: u8, chain: &[u32], size: usize) {
        let g = Geom { spc, total_sectors: 32 + 16 + 64 * spc as usize, ..Geom::default() };
        let mut img = build(&g);
        set_fat(&mut img, &g, 2, 0x0FFF_FFFF);
        for w in chain.windows(2) { set_fat(&mut img, &g, w[0], w[1]); }
        set_fat(&mut img, &g, *chain.last().unwrap(), 0x0FFF_FFFF);
        let bpc = spc as usize * SECTOR;
        for (k, &c) in chain.iter().enumerate() {
            let o = cluster_sector(&g, c) * SECTOR;
            for j in 0..bpc { img[o + j] = pat(k * bpc + j); }
        }
        let root = cluster_sector(&g, 2) * SECTOR;
        let e = &mut img[root..root + 32];
        e[..11].copy_from_slice(b"FRAG    BIN");
        e[11] = 0x20;
        e[20..22].copy_from_slice(&((chain[0] >> 16) as u16).to_le_bytes());
        e[26..28].copy_from_slice(&(chain[0] as u16).to_le_bytes());
        e[28..32].copy_from_slice(&(size as u32).to_le_bytes());
        super::swap_medium(img);
        assert_eq!(fat32::fat32_mount(), Ok(()));
        super::vfs_open_close::vfs_once();
    }

    fn pat(i: usize) -> u8 { (i as u32).wrapping_mul(31).wrapping_add(i as u32 >> 9) as u8 }

    const PATH: &[u8] = b"/fat/FRAG.BIN";

    fn cache_ops() -> u32 { let (h, m) = fat32::fat32_cache_stats(); h + m }

    /// **Any offset, any chunk size, across fragments, reads the file's
    /// bytes and stops at its size.** One sector per cluster and four, a
    /// chain with three fragments, a size that ends mid-sector; reads of 1 to
    /// 4096 bytes from offsets that straddle sector and cluster edges.
    ///
    /// **Canary.** Off-by-one the cluster base after a run
    /// (`cl_base += advanced * bpc` → `(advanced + 1) * bpc`): the bytes
    /// after the first fragment come from the wrong cluster.
    #[test]
    fn reads_at_any_offset_match_the_file() {
        let _g = serial();
        for (spc, chain) in [(1u8, vec![3u32, 4, 5, 9, 10, 20, 21, 22, 23, 30]),
                             (4u8, vec![3u32, 4, 7, 8, 9, 15])] {
            let size = chain.len() * spc as usize * 512 - 300;
            volume(spc, &chain, size);
            let want: Vec<u8> = (0..size).map(pat).collect();
            let mut t = vfs::ScratchFds::new();
            for chunk in [1usize, 7, 511, 512, 513, 777, 1536, 4096] {
                for start in [0usize, 1, 511, 512, 1000, 2047, 2048, 3333] {
                    let fd = vfs::vfs_open(&mut t, PATH, vfs::O_RDONLY);
                    assert!(fd >= 0);
                    assert_eq!(vfs::vfs_lseek(&mut t, fd, start as i64, vfs::SEEK_SET), start as i64);
                    let mut got = Vec::new();
                    let mut buf = vec![0u8; chunk];
                    loop {
                        let n = vfs::vfs_read(&mut t, fd, buf.as_mut_ptr(), chunk);
                        assert!(n >= 0);
                        if n == 0 { break; }
                        got.extend_from_slice(&buf[..n as usize]);
                    }
                    assert_eq!(vfs::vfs_close(&mut t, fd), 0);
                    assert!(got == want[start.min(size)..], "spc {spc} chunk {chunk} from {start}");
                }
            }
        }
    }

    /// **A read-only open + 64-byte read touches the directory and one
    /// sector, not the file.** A 40-sector file: open, read 64 B, close costs
    /// a handful of cache operations; the whole-file proxy cost two per
    /// sector (the data and the FAT step).
    ///
    /// **Canary.** `ro-stream-off-canary` (read-only opens take the proxy).
    #[test]
    fn a_read_only_open_does_not_load_the_file() {
        let _g = serial();
        let chain: Vec<u32> = (3..43).collect();
        volume(1, &chain, 40 * 512);
        let mut t = vfs::ScratchFds::new();
        let before = cache_ops();
        let fd = vfs::vfs_open(&mut t, PATH, vfs::O_RDONLY);
        let mut buf = [0u8; 64];
        assert_eq!(vfs::vfs_read(&mut t, fd, buf.as_mut_ptr(), 64), 64);
        assert_eq!(vfs::vfs_close(&mut t, fd), 0);
        assert_eq!(buf[..], (0..64).map(pat).collect::<Vec<u8>>()[..]);
        let ops = cache_ops() - before;
        assert!(ops <= 6, "{ops} cache operations for open + 64 B + close");
    }

    /// **A stream follows a rewrite.** Open, read; the file is then
    /// rewritten through the driver (a new, shorter chain; the old one is
    /// freed but still holds the old bytes) and, separately, its directory
    /// entry is rewritten through the block layer (as the USB gadget would).
    /// The same descriptor must read what the directory says now — never the
    /// freed chain, never past the new size.
    ///
    /// **Canary.** `write-gen-canary` (writes do not move the generation):
    /// the descriptor keeps reading the old chain at the old size.
    #[test]
    fn a_stream_follows_a_rewrite_of_its_file() {
        let _g = serial();
        let chain: Vec<u32> = (3..13).collect();
        volume(1, &chain, 10 * 512);
        let mut t = vfs::ScratchFds::new();
        let fd = vfs::vfs_open(&mut t, PATH, vfs::O_RDONLY);
        let mut buf = vec![0u8; 8192];
        assert_eq!(vfs::vfs_read(&mut t, fd, buf.as_mut_ptr(), 64), 64);

        let new = vec![0xA5u8; 100];
        assert_eq!(fat32::fat32_write_file(b"FRAG    BIN", &new), Ok(()));
        assert_eq!(vfs::vfs_lseek(&mut t, fd, 0, vfs::SEEK_SET), 0);
        let n = vfs::vfs_read(&mut t, fd, buf.as_mut_ptr(), 8192);
        assert_eq!(&buf[..n.max(0) as usize], &new[..], "the rewrite, at its size");

        // The gadget points the entry back at cluster 3 with 700 bytes.
        let g = Geom::default();
        let root = cluster_sector(&g, 2) as u64;
        let mut dir = fs_test_drivers::disk_peek(root).unwrap();
        let at = dir.chunks(32).position(|e| &e[..11] == b"FRAG    BIN").unwrap() * 32;
        dir[at + 20..at + 22].copy_from_slice(&0u16.to_le_bytes());
        dir[at + 26..at + 28].copy_from_slice(&3u16.to_le_bytes());
        dir[at + 28..at + 32].copy_from_slice(&700u32.to_le_bytes());
        // Cluster 3 still holds the original bytes (only FAT links changed).
        fs_test_drivers::blkdev::write(root, 1, &dir).unwrap();
        assert_eq!(vfs::vfs_lseek(&mut t, fd, 0, vfs::SEEK_SET), 0);
        let n = vfs::vfs_read(&mut t, fd, buf.as_mut_ptr(), 8192);
        assert!(n > 0 && n <= 700, "{n} bytes after the gadget's rewrite");
        assert_eq!(buf[..64], (0..64).map(pat).collect::<Vec<u8>>()[..]);
        assert_eq!(vfs::vfs_close(&mut t, fd), 0);
    }

    /// **A read-only stream refuses writes; a writable open is still the
    /// proxy.** `vfs_write` on the stream answers -1 and the file is
    /// unchanged; an `O_RDWR` open writes through the proxy as before.
    #[test]
    fn a_read_only_stream_refuses_writes() {
        let _g = serial();
        volume(1, &[3, 4], 1024);
        let mut t = vfs::ScratchFds::new();
        let fd = vfs::vfs_open(&mut t, PATH, vfs::O_RDONLY);
        assert_eq!(vfs::vfs_write(&mut t, fd, b"xx".as_ptr(), 2), -1);
        assert_eq!(vfs::vfs_close(&mut t, fd), 0);
        assert_eq!(super::vfs_open_close::on_disk(b"frag.bin")[..2], [pat(0), pat(1)]);
        let fd = vfs::vfs_open(&mut t, PATH, vfs::O_RDWR);
        assert_eq!(vfs::vfs_write(&mut t, fd, b"xx".as_ptr(), 2), 2);
        assert_eq!(vfs::vfs_close(&mut t, fd), 0);
        assert_eq!(super::vfs_open_close::on_disk(b"frag.bin")[..2], *b"xx");
    }

    /// **`dos_to_unix`'s closed form agrees with counting the years**, for
    /// every DOS year (1980-2107), month and a day/time per month.
    #[test]
    fn dos_to_unix_matches_a_year_by_year_count() {
        for yy in 0u16..128 {
            for m in 1u16..=12 {
                let date = (yy << 9) | (m << 5) | 28;
                let time = (13 << 11) | (37 << 5) | 21;
                let year = 1980 + yy as u64;
                let mut days = 0u64;
                for y in 1970..year {
                    days += if (y % 4 == 0 && y % 100 != 0) || y % 400 == 0 { 366 } else { 365 };
                }
                const CUM: [u64; 12] = [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334];
                days += CUM[(m - 1) as usize];
                if ((year % 4 == 0 && year % 100 != 0) || year % 400 == 0) && m > 2 { days += 1; }
                days += 27;
                let want = ((days * 24 + 13) * 60 + 37) * 60 + 42;
                assert_eq!(fat32::dos_to_unix(date, time), want, "{year}-{m}");
            }
        }
    }

    /// **The spawn read (`read_whole`'s loop) of a warm image touches no
    /// device and copies once.** Ten whole reads of a 41-sector file: zero
    /// device reads after the first.
    #[test]
    fn a_warm_whole_read_touches_no_device() {
        let _g = serial();
        let chain: Vec<u32> = (3..44).collect();
        volume(1, &chain, 41 * 512 - 77);
        let want: Vec<u8> = (0..41 * 512 - 77).map(pat).collect();
        let mut t = vfs::ScratchFds::new();
        let mut buf = vec![0u8; 32 * 1024];
        let mut whole = |t: &mut vfs::ScratchFds| {
            let fd = vfs::vfs_open(t, PATH, vfs::O_RDONLY);
            let mut total = 0usize;
            loop {
                let n = vfs::vfs_read(t, fd, buf[total..].as_mut_ptr(), buf.len() - total);
                if n <= 0 { break; }
                total += n as usize;
            }
            assert_eq!(vfs::vfs_close(t, fd), 0);
            assert!(buf[..total] == want[..]);
        };
        whole(&mut t);
        let before = fs_test_drivers::disk_stats().0;
        for _ in 0..10 { whole(&mut t); }
        assert_eq!(fs_test_drivers::disk_stats().0 - before, 0);
    }
}

/// Wave 14 (SPAWNCACHE): the content stamp the verified-image cache keys by.
/// Equal stamps must mean equal bytes: every way the volume's bytes change
/// moves it, and the epoch it carries is never one a reader could have read
/// while the bytes it reports were still landing.
#[cfg(test)]
mod content_stamp {
    use super::{fat32, image::*, serial, vfs};
    use std::sync::Mutex;

    const PATH: &[u8] = b"/fat/FRAG.BIN";

    /// `FRAG.BIN`, 3 clusters of 512 B from cluster 3, mounted at `/fat`.
    fn volume() -> Geom {
        let g = Geom { spc: 1, total_sectors: 32 + 16 + 64, ..Geom::default() };
        let mut img = build(&g);
        set_fat(&mut img, &g, 2, 0x0FFF_FFFF);
        set_fat(&mut img, &g, 3, 4);
        set_fat(&mut img, &g, 4, 5);
        set_fat(&mut img, &g, 5, 0x0FFF_FFFF);
        for c in 3..6u32 {
            let o = cluster_sector(&g, c) * SECTOR;
            for j in 0..SECTOR { img[o + j] = (c as usize * 7 + j) as u8; }
        }
        let root = cluster_sector(&g, 2) * SECTOR;
        let e = &mut img[root..root + 32];
        e[..11].copy_from_slice(b"FRAG    BIN");
        e[11] = 0x20;
        e[26..28].copy_from_slice(&3u16.to_le_bytes());
        e[28..32].copy_from_slice(&1400u32.to_le_bytes());
        super::swap_medium(img);
        assert_eq!(fat32::fat32_mount(), Ok(()));
        super::vfs_open_close::vfs_once();
        g
    }

    fn stamp() -> vfs::ContentStamp {
        vfs::vfs_content_stamp(PATH).expect("a FAT32 file has a stamp")
    }

    /// **A stamp holds while nothing writes, and names the file.** Two
    /// lookups agree; the stamp carries the start cluster and the size; a
    /// ramfs path and a missing name have none.
    ///
    /// **Canary.** `content-stamp-off-canary`: no stamp at all (red here;
    /// in the kernel nothing would then be cached).
    #[test]
    fn a_stamp_holds_while_nothing_writes() {
        let _g = serial();
        volume();
        let a = stamp();
        assert_eq!(a, stamp());
        assert_eq!((a.fs, a.id, a.size), (vfs::STAMP_FS_FAT32, 3, 1400));
        assert_eq!(vfs::vfs_content_stamp(b"/fat/NOPE.BIN"), None);
        assert_eq!(vfs::vfs_content_stamp(b"/tmp-not-mounted/X"), None);
    }

    /// **Every way the volume changes moves the stamp, including a rewrite
    /// that keeps the cluster and the size.** FAT32's own write of another
    /// file; the USB gadget's write of the file's own data sector through
    /// the block layer (same chain, same size, new bytes); a
    /// `SYS_DISK_WRITE`-style external note; a cache drop; a remount.
    ///
    /// **Canary.** `write-epoch-canary` (the epoch never moves): every
    /// stamp below equals the one before it.
    #[test]
    fn every_write_path_moves_the_stamp() {
        let _g = serial();
        let g = volume();
        let s0 = stamp();
        assert_eq!(fat32::fat32_write_file(b"OTHER   BIN", &[1, 2, 3]), Ok(()));
        let s1 = stamp();
        assert_ne!(s1, s0, "FAT32's own write of another file");

        let data = cluster_sector(&g, 3) as u64;
        let mut sec = fs_test_drivers::disk_peek(data).unwrap();
        sec[0] ^= 0xFF;
        fs_test_drivers::blkdev::write(data, 1, &sec).unwrap();
        let s2 = stamp();
        assert_eq!((s2.id, s2.size), (s1.id, s1.size), "same chain, same size");
        assert_ne!(s2, s1, "the gadget rewrote the file's bytes in place");

        fs_test_drivers::blkdev::note_external_write(data, 1);
        let s3 = stamp();
        assert_ne!(s3, s2, "an external write the block layer was told of");

        fat32::fat32_cache_invalidate_all();
        let s4 = stamp();
        assert_ne!(s4, s3, "a whole-cache drop (the gadget's handback)");

        let v = fat32::fat32_mount_volume().expect("mounted");
        assert_eq!(fat32::fat32_unmount(v), Ok(()));
        assert_eq!(vfs::vfs_content_stamp(PATH), None, "no stamp while unmounted");
        assert_eq!(fat32::fat32_mount(), Ok(()));
        let s5 = stamp();
        assert_ne!(s5, s4, "an unmount and a mount");
    }

    static SEEN: Mutex<Vec<u64>> = Mutex::new(Vec::new());
    fn record_epoch() { SEEN.lock().unwrap().push(fat32::fat32_write_epoch()); }

    /// **No epoch a reader can load while a write's bytes are landing is
    /// the epoch after that write.** The block shim records the epoch at the
    /// start of every device write, before the bytes land; once FAT32's
    /// write returns, the epoch must have moved past the last one recorded.
    /// A reader that stamped what it read with the recorded value would
    /// otherwise keep old bytes under the current epoch for good.
    ///
    /// **Canary.** `write-gen-early-canary` (FAT32 bumps before the device
    /// write): the last recorded epoch is the final one.
    #[test]
    fn every_epoch_bump_follows_the_bytes_it_reports() {
        let _g = serial();
        let _wt = crate::write_through();
        volume();
        SEEN.lock().unwrap().clear();
        fs_test_drivers::disk_before_write(Some(record_epoch));
        let r = fat32::fat32_write_file(b"FRAG    BIN", &[9u8; 300]);
        fs_test_drivers::disk_before_write(None);
        assert_eq!(r, Ok(()));
        let seen = SEEN.lock().unwrap().clone();
        assert!(!seen.is_empty(), "the rewrite wrote sectors");
        let last = *seen.last().unwrap();
        assert!(fat32::fat32_write_epoch() > last,
            "epoch {} after the write, {} while its last sector was landing",
            fat32::fat32_write_epoch(), last);
    }
}

/// Wave 15 (WRITEBACK): the FAT32 cache in `Mode::WriteBack` (Kconfig
/// `FS_WRITEBACK`). The cache's split write-back API first, against a
/// recording device; then FAT32 on the shim disk: coalescing, coherence
/// with other readers and writers of the medium, and power cuts at random
/// points with the dirty lines dropped.
#[cfg(test)]
mod writeback {
    use super::{bcache::{BlockCache, Dirty, Mode}, fat32, image::*, serial};
    use fs_test_drivers::{blkdev, disk_events, disk_peek, disk_take_log, disk_writeback, disk_durable_image,
                          DiskEvent, LogEntry};

    type C = BlockCache<{ 16 * 512 }, 16>;

    fn blk(fill: u8) -> [u8; 512] { [fill; 512] }

    fn dirty(c: &mut C, b: u64, fill: u8) {
        assert!(matches!(c.write_dirty(b, &blk(fill)), Dirty::Done { .. }), "block {b} must dirty");
    }

    /// **Contiguous dirty blocks of one epoch leave as ONE run**, lowest
    /// first; a gap ends it.
    ///
    /// **Canary.** `wb-no-coalesce-canary`: every run is one block.
    #[test]
    fn an_ahead_line_leaves_after_the_current_epoch_and_a_barrier_closes_both() {
        // Wave 15 (FW): block 5 written ahead, then block 9 in the current
        // epoch AFTER it: the write-back takes 9 first, and 5 after a flush.
        let mut c = C::new(512, Mode::WriteBack);
        let e = c.epoch();
        assert!(matches!(c.write_dirty_ahead(5, &blk(1)), Dirty::Done { .. }));
        dirty(&mut c, 9, 2);
        assert!(matches!(c.write_dirty_ahead(5, &blk(3)), Dirty::Done { .. }), "rewritten in place");
        assert_eq!((c.epoch(), c.top_epoch(), c.dirty_epochs(), c.dirty_count()), (e, e + 1, 2, 2));
        let mut buf = vec![0u8; 8 * 512];
        let r = c.checkout_run(u64::MAX, 8, &mut buf).expect("a run");
        assert_eq!((r.block, r.epoch, r.flush_first), (9, e, false));
        c.checkin(&r, true);
        let r = c.checkout_run(u64::MAX, 8, &mut buf).expect("the ahead run");
        assert_eq!((r.block, r.epoch, r.flush_first, buf[0]), (5, e + 1, true, 3));
        c.checkin(&r, true);
        // A plain write to a line held ahead joins its epoch, never demotes it.
        assert!(matches!(c.write_dirty_ahead(6, &blk(4)), Dirty::Done { .. }));
        dirty(&mut c, 6, 5);
        assert_eq!(c.epoch(), e + 1, "the plain write joined the ahead epoch");
        assert_eq!(c.dirty_epochs(), 1);
        // The barrier closes the ahead epoch too and says so.
        assert!(matches!(c.write_dirty_ahead(7, &blk(6)), Dirty::Done { .. }));
        assert_eq!(c.barrier(), e + 2);
        assert_eq!(c.epoch(), e + 3);
    }

    #[test]
    fn consecutive_dirty_blocks_of_one_epoch_are_one_run() {
        let mut c = C::new(512, Mode::WriteBack);
        for b in [12u64, 10, 11, 13, 20] { dirty(&mut c, b, b as u8); }
        let mut buf = vec![0u8; 8 * 512];
        let r = c.checkout_run(u64::MAX, 8, &mut buf).expect("a run");
        assert_eq!((r.block, r.blocks, r.sectors, r.flush_first), (10, 4, 4, false));
        assert_eq!(buf[512 * 3], 13, "the run's bytes, in block order");
        c.checkin(&r, true);
        let r = c.checkout_run(u64::MAX, 8, &mut buf).expect("the second run");
        assert_eq!((r.block, r.blocks), (20, 1));
        c.checkin(&r, true);
        assert_eq!(c.dirty_count(), 0);
        assert_eq!(c.dirty_count(), c.dirty_scan());
    }

    /// **A later epoch's run is preceded by a flush** once an older epoch
    /// went out, and never coalesces with it.
    ///
    /// **Canary.** `wb-no-ordering-flush-canary`: `flush_first` stays false.
    #[test]
    fn a_later_epoch_waits_for_a_flush() {
        let mut c = C::new(512, Mode::WriteBack);
        dirty(&mut c, 5, 1);
        c.barrier();
        dirty(&mut c, 6, 2);
        dirty(&mut c, 3, 3);
        let mut buf = vec![0u8; 8 * 512];
        let r = c.checkout_run(u64::MAX, 8, &mut buf).unwrap();
        assert_eq!((r.block, r.blocks, r.epoch, r.flush_first), (5, 1, 0, false), "oldest epoch first, 6 not merged");
        assert!(c.checkout_run(0, 8, &mut buf).is_some(), "still dirty until checkin");
        c.checkin(&r, true);
        assert!(c.checkout_run(0, 8, &mut buf).is_none(), "`upto` stops at the epoch");
        let r = c.checkout_run(u64::MAX, 8, &mut buf).unwrap();
        assert_eq!((r.block, r.blocks, r.epoch, r.flush_first), (3, 1, 1, true));
        c.note_ordering_flush();
        c.checkin(&r, true);
        let r = c.checkout_run(u64::MAX, 8, &mut buf).unwrap();
        assert_eq!((r.block, r.flush_first), (6, false), "same epoch after the flush: no second flush");
    }

    /// **An older epoch's unwritten line is never overwritten in place**:
    /// re-dirtying it keeps the old contents as a shadow (no I/O) that goes
    /// out first, in its own epoch; with no free line in the set,
    /// `write_dirty` asks for a write-back instead. A full set of dirty
    /// lines asks too (it never evicts a dirty one).
    ///
    /// **Canaries.** `wb-epoch-merge-canary`: the newer bytes replace the
    /// older epoch's, which then never reach the device.
    /// `wb-no-shadow-canary`: the re-dirty asks for a write-back.
    #[test]
    fn re_dirtying_an_older_epoch_keeps_a_shadow() {
        let mut c = C::new(512, Mode::WriteBack);
        dirty(&mut c, 7, 1);
        c.barrier();
        dirty(&mut c, 7, 2);
        assert_eq!(c.dirty_count(), 2, "the epoch-0 shadow and the epoch-1 line");
        let mut probe = [0u8; 512];
        assert!(c.peek(7, &mut probe) && probe[0] == 2, "reads see the newest bytes");
        let mut buf = vec![0u8; 512];
        let r = c.checkout_run(u64::MAX, 1, &mut buf).unwrap();
        assert_eq!((r.epoch, buf[0]), (0, 1), "the epoch-0 bytes go out first");
        c.checkin(&r, true);
        let r = c.checkout_run(u64::MAX, 1, &mut buf).unwrap();
        assert_eq!((r.epoch, buf[0], r.flush_first), (1, 2, true));
        c.checkin(&r, true);
        assert_eq!(c.dirty_count(), 0);
        assert_eq!(c.dirty_count(), c.dirty_scan());
        // One set of 8 ways (16 lines, 2 sets) full of dirty lines: a new
        // block of that set must wait for a write-back, but a re-dirty of an
        // older epoch parks its shadow in the other set.
        let mut d = C::new(512, Mode::WriteBack);
        for k in 0..8u64 { dirty(&mut d, k * 2, 9); }
        assert_eq!(d.write_dirty(16, &blk(9)), Dirty::NeedWriteback(0));
        d.barrier();
        dirty(&mut d, 0, 8);
        assert_eq!(d.dirty_count(), 9);
        assert!(d.peek(0, &mut probe) && probe[0] == 8);
        let r = d.checkout_run(u64::MAX, 1, &mut buf).unwrap();
        assert_eq!((r.block, r.epoch, buf[0]), (0, 0, 9), "the parked epoch-0 bytes go out first");
        d.checkin(&r, true);
        assert_eq!(d.dirty_count(), d.dirty_scan());
        // Every line dirty: no room anywhere.
        let mut e = C::new(512, Mode::WriteBack);
        for k in 0..16u64 { dirty(&mut e, k, 1); }
        e.barrier();
        assert_eq!(e.write_dirty(3, &blk(2)), Dirty::NeedWriteback(0), "no line for a shadow");
        assert_eq!(e.dirty_count(), e.dirty_scan());
    }

    /// **A line dirtied while its run is on the wire stays dirty.**
    #[test]
    fn a_write_racing_its_run_is_not_lost() {
        let mut c = C::new(512, Mode::WriteBack);
        dirty(&mut c, 4, 1);
        let mut buf = vec![0u8; 512];
        let r = c.checkout_run(u64::MAX, 1, &mut buf).unwrap();
        dirty(&mut c, 4, 2);
        c.checkin(&r, true);
        assert_eq!(c.dirty_count(), 1, "the newer bytes still need writing");
        let r = c.checkout_run(u64::MAX, 1, &mut buf).unwrap();
        assert_eq!(buf[0], 2);
        c.checkin(&r, false);
        assert_eq!(c.dirty_count(), 1, "a failed write keeps the line dirty");
    }

    const N1: [u8; 11] = *b"WB1     DAT";

    fn fresh() {
        super::vfs_open_close::fresh_volume();
        let _ = disk_events();
    }

    fn pattern(len: usize, seed: u8) -> Vec<u8> {
        (0..len).map(|i| seed.wrapping_add((i % 251) as u8)).collect()
    }

    /// **A streaming write waits on nothing; fsync writes it as coalesced
    /// requests, then flushes.** 12 data sectors of consecutive clusters
    /// go out in at most two requests instead of twelve.
    #[test]
    fn a_streaming_write_is_queued_then_coalesced_at_fsync() {
        let _g = serial();
        fresh();
        let f = fat32::fat32_open(fat32::Volume::assume_mounted(), b"/WB1.DAT",
            fat32::open_flags::WRITE | fat32::open_flags::CREATE).expect("open");
        let data = pattern(12 * 512, 3);
        assert_eq!(fat32::fat32_write(f, &data), Ok(data.len()));
        let ev = disk_events();
        assert!(ev.is_empty(), "a queued write touched the device: {ev:?}");
        assert_eq!(fat32::fat32_fsync(f), Ok(()));
        let ev = disk_events();
        let g = Geom::default();
        let data_start = (g.rsvd as u64) + g.num_fats as u64 * g.fat_sz32 as u64;
        let data_writes = ev.iter().filter(|e| matches!(e, DiskEvent::Write(s) if *s >= data_start)).count();
        assert!(data_writes <= 3, "12 data sectors in {data_writes} requests: {ev:?}");
        assert_eq!(ev.last(), Some(&DiskEvent::Flush), "fsync ends in a flush: {ev:?}");
        let (cl, size) = fat32::fat32_lookup_root(&N1).expect("listed");
        assert_eq!(size as usize, data.len());
        let first = cluster_sector(&g, cl) as u64;
        assert_eq!(disk_peek(first).unwrap(), data[..512], "the bytes are on the device");
        let _ = fat32::fat32_close(f);
    }

    /// **A reader of the medium that is not FAT32 never reads a sector a
    /// returned write left dirty**: `blkdev::read`'s observer writes it back
    /// first.
    ///
    /// **Canary.** `wb-read-observer-canary`: the raw read sees the old bytes.
    #[test]
    fn a_raw_reader_sees_queued_writes() {
        let _g = serial();
        fresh();
        let f = fat32::fat32_open(fat32::Volume::assume_mounted(), b"/WB1.DAT",
            fat32::open_flags::WRITE | fat32::open_flags::CREATE).expect("open");
        let data = pattern(512, 0x40);
        assert_eq!(fat32::fat32_write(f, &data), Ok(512));
        let (dirty, _) = fat32::fat32_writeback_dirty();
        assert!(dirty > 0, "the write is queued");
        // The data sector is the file's first cluster (first free: 3).
        let s = cluster_sector(&Geom::default(), 3) as u64;
        let mut raw = [0u8; 512];
        blkdev::read(s, 1, &mut raw).unwrap();
        assert_eq!(raw[..], data[..], "the raw reader must see the queued bytes");
        let _ = fat32::fat32_close(f);
    }

    /// **A long external write drops only its own range**: the pending
    /// writes of other sectors survive it and still reach the device.
    ///
    /// **Canary.** `wb-observer-drop-canary`: the whole cache is dropped,
    /// dirty lines with it, and the file's bytes never reach the device.
    #[test]
    fn a_long_external_write_keeps_other_pending_writes() {
        let _g = serial();
        fresh();
        let f = fat32::fat32_open(fat32::Volume::assume_mounted(), b"/WB1.DAT",
            fat32::open_flags::WRITE | fat32::open_flags::CREATE).expect("open");
        let data = pattern(512, 0x51);
        assert_eq!(fat32::fat32_write(f, &data), Ok(512));
        // 16 sectors near the end of the volume, far from the file.
        let far = Geom::default().total_sectors as u64 - 16;
        blkdev::write(far, 16, &[0xEEu8; 16 * 512]).unwrap();
        assert_eq!(fat32::fat32_fsync(f), Ok(()));
        let s = cluster_sector(&Geom::default(), 3) as u64;
        assert_eq!(disk_peek(s).unwrap(), data[..], "the queued write was dropped");
        let _ = fat32::fat32_close(f);
    }

    /// **A run read overlays the cache's newer lines** on what the device
    /// returned: sector 1 of a 3-sector run is dirty, sector 0 is not
    /// cached, so the run goes to the device and must not return sector 1's
    /// old bytes.
    ///
    /// **Canary.** `wb-run-overlay-canary`.
    #[test]
    fn a_run_read_returns_the_queued_bytes_not_the_devices() {
        let _g = serial();
        fresh();
        let old = pattern(3 * 512, 1);
        assert_eq!(fat32::fat32_write_file(&N1, &old), Ok(()));
        let (cl, _) = fat32::fat32_lookup_root(&N1).unwrap();
        let s0 = cluster_sector(&Geom::default(), cl) as u32;
        let f = fat32::fat32_open(fat32::Volume::assume_mounted(), b"/WB1.DAT", fat32::open_flags::WRITE).unwrap();
        assert!(fat32::fat32_seek(f, fat32::SeekFrom::Start(512)).is_ok());
        let new = pattern(512, 0x90);
        assert_eq!(fat32::fat32_write(f, &new), Ok(512));
        fat32::fat32_cache_invalidate(s0); // clean: just forgotten
        let mut out = vec![0u8; 3 * 512];
        assert_eq!(fat32::fat32_read_chain(cl, &mut out), 3 * 512);
        assert_eq!(out[512..1024], new[..], "the run returned the device's stale sector");
        assert_eq!(out[..512], old[..512]);
        let _ = fat32::fat32_close(f);
    }

    /// **A VFS close of a FAT32 file queues; `sync` lands it.** The proxy's
    /// close (`write_all`, the journaled whole-file write) touches no device;
    /// the following `sync` writes it epoch by epoch with flushes between,
    /// and the file is on the medium.
    ///
    /// **Canary.** `wb-close-flushes-canary`: the close waits on the device.
    #[test]
    fn a_vfs_close_queues_and_sync_lands_it() {
        let _g = serial();
        fresh();
        let data = pattern(3000, 0x33);
        let mut t = super::vfs::ScratchFds::new();
        let fd = super::vfs::vfs_open(&mut t, b"/fat/WB1.DAT", super::vfs::O_WRONLY | super::vfs::O_CREAT);
        assert!(fd >= 0, "open");
        assert_eq!(super::vfs::vfs_write(&mut t, fd, data.as_ptr(), data.len()), data.len() as i32);
        let _ = disk_events();
        assert_eq!(super::vfs::vfs_close(&mut t, fd), 0);
        let ev = disk_events();
        assert!(ev.is_empty(), "the close waited on the device: {ev:?}");
        assert_eq!(fat32::fat32_sync(), Ok(()));
        let ev = disk_events();
        let flushes = ev.iter().filter(|e| **e == DiskEvent::Flush).count();
        assert!(flushes >= 2, "epochs separated by flushes: {ev:?}");
        let (cl, size) = fat32::fat32_lookup_root(&N1).expect("listed");
        assert_eq!(size as usize, data.len());
        let first = cluster_sector(&Geom::default(), cl) as u64;
        assert_eq!(disk_peek(first).unwrap(), data[..512]);
    }

    /// **A journal barrier is an epoch, not a device flush**: the queued
    /// whole-file write issues no I/O at all.
    ///
    /// **Canary.** `wb-barrier-flushes-canary`: every barrier flushes.
    #[test]
    fn journal_barriers_queue_as_epochs() {
        let _g = serial();
        fresh();
        assert_eq!(fat32::fat32_write_file_queued(&N1, &pattern(700, 9)), Ok(()));
        assert_eq!(fat32::fat32_write_file_queued(&N1, &pattern(900, 10)), Ok(()));
        let ev = disk_events();
        assert!(ev.is_empty(), "a queued create and overwrite touched the device: {ev:?}");
        assert_eq!(fat32::fat32_writeback_now(), Ok(()));
        let (cl, size) = fat32::fat32_lookup_root(&N1).unwrap();
        let mut out = vec![0u8; size as usize];
        assert_eq!(fat32::fat32_read_chain(cl, &mut out), 900);
        assert!(out == pattern(900, 10));
    }

    /// **A device that cannot flush mounts write-through**: write-back's
    /// order is made of flushes, so without them every write goes to the
    /// device at once, as before wave 15, and the journal fails closed.
    #[test]
    fn a_device_that_cannot_flush_mounts_write_through() {
        let _g = serial();
        let g = Geom::default();
        let mut img = build(&g);
        set_fat(&mut img, &g, 2, 0x0FFF_FFFF);
        super::swap_medium(img);
        fs_test_drivers::disk_flush_mode(fs_test_drivers::FlushMode::Unsupported);
        assert_eq!(fat32::fat32_mount(), Ok(()));
        let f = fat32::fat32_open(fat32::Volume::assume_mounted(), b"/WB1.DAT",
            fat32::open_flags::WRITE | fat32::open_flags::CREATE).expect("open");
        let _ = disk_events();
        assert_eq!(fat32::fat32_write(f, &pattern(512, 1)), Ok(512));
        let ev = disk_events();
        fs_test_drivers::disk_flush_mode(fs_test_drivers::FlushMode::Ok);
        let _ = fat32::fat32_close(f);
        assert!(!ev.is_empty(), "the write must reach the device at once");
        // Back to write-back for the next test's mount.
        let _ = fat32::fat32_unmount(fat32::Volume::assume_mounted());
        let _ = fat32::fat32_set_writeback(true);
    }

    /// **K1 flush tickets** (io_ring `OP_FSYNC`): with no `fs-wb` task to
    /// wake the asker flushes inline; a ticket is done once its flush ran,
    /// `Err(Io)` when that flush failed, and a later ticket's clean flush is
    /// `Ok`. With no volume mounted there is nothing to flush: `Ok`, as the
    /// synchronous fsync of a RAM descriptor answers.
    ///
    /// **Canary.** Drop the `NotMounted` arm in `flush_for_tickets`: the
    /// unmounted ticket reads `Err(Io)`.
    #[test]
    fn a_flush_ticket_is_done_after_its_flush_and_carries_its_failure() {
        let _g = serial();
        let _ = fat32::fat32_unmount(fat32::Volume::assume_mounted());
        let t = fat32::fat32_flush_request();
        assert_eq!(fat32::fat32_flush_done(t), Some(Ok(())), "unmounted: nothing to flush");
        fresh();
        let f = fat32::fat32_open(fat32::Volume::assume_mounted(), b"/K1.DAT",
            fat32::open_flags::WRITE | fat32::open_flags::CREATE).expect("open");
        assert_eq!(fat32::fat32_write(f, &pattern(512, 3)), Ok(512));
        fs_test_drivers::disk_write_fail_after(0);
        let bad = fat32::fat32_flush_request();
        fs_test_drivers::disk_write_fail_clear();
        assert_eq!(fat32::fat32_flush_done(bad), Some(Err(fat32::FsError::Io)), "the failed flush is reported");
        assert_eq!(fat32::fat32_write(f, &pattern(512, 4)), Ok(512));
        let good = fat32::fat32_flush_request();
        assert_eq!(fat32::fat32_flush_done(good), Some(Ok(())), "a later clean flush is not the old failure");
        assert_eq!(fat32::fat32_flush_done(good + 1), None, "a ticket not asked for is not done");
        let _ = fat32::fat32_close(f);
    }

    /// **A device failure of a queued in-place write is reported by fsync**
    /// (and the close claims nothing): the fsyncgate property, moved to the
    /// call that claims durability.
    #[test]
    fn a_failed_write_back_is_reported_by_fsync() {
        let _g = serial();
        fresh();
        let mut t = super::vfs::ScratchFds::new();
        let fd = super::vfs::vfs_open(&mut t, b"/fat/WB1.DAT", super::vfs::O_WRONLY | super::vfs::O_CREAT);
        assert!(fd >= 0);
        assert_eq!(super::vfs::vfs_write(&mut t, fd, b"payload".as_ptr(), 7), 7, "queued");
        fs_test_drivers::disk_write_fail_after(0);
        let r = super::vfs::vfs_fsync(&mut t, fd);
        fs_test_drivers::disk_write_fail_clear();
        assert!(r.is_err(), "fsync must report the lost write");
        let _ = super::vfs::vfs_close(&mut t, fd);
    }

    /// **An allocation starts where the last one found room** (FSInfo's
    /// `nxt_free`, in RAM): with the first 2000 clusters taken (16 full FAT
    /// sectors), 50 allocations look at a handful of FAT sectors each time,
    /// not all 16 again — under write-back those reads evicted the clean
    /// lines a busy writer needs.
    ///
    /// **Canary.** `alloc-hint-canary`: every allocation scans from sector 0.
    #[test]
    fn an_allocation_starts_at_the_last_free_entry() {
        let _g = serial();
        let g = Geom { fat_sz32: 32, total_sectors: 32 + 2 * 32 + 3000, ..Geom::default() };
        let mut img = build(&g);
        for c in 2..2000u32 { set_fat(&mut img, &g, c, 0x0FFF_FFFF); }
        super::swap_medium(img);
        assert_eq!(fat32::fat32_mount(), Ok(()));
        let _ = fat32::fat32_alloc_cluster().expect("first");
        let before = fat32::fat32_cache_counters();
        for _ in 0..50 { fat32::fat32_alloc_cluster().expect("room"); }
        let after = fat32::fat32_cache_counters();
        let looks = (after.hits + after.misses) - (before.hits + before.misses);
        assert!(looks < 50 * 4, "{looks} FAT-sector lookups for 50 allocations");
    }

    /// xorshift64*, so a failing seed replays.
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 >> 12; self.0 ^= self.0 << 25; self.0 ^= self.0 >> 27;
            self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
        }
        fn below(&mut self, n: u64) -> u64 { self.next() % n.max(1) }
    }

    fn n83(i: usize) -> [u8; 11] {
        let mut n = *b"F00     DAT";
        n[1] = b'0' + (i / 10) as u8;
        n[2] = b'0' + (i % 10) as u8;
        n
    }

    /// **Power cut at a random point, dirty lines dropped: the volume stays
    /// consistent.** A random mix of journaled creates and streaming writes
    /// (some aged out by the `fs-wb` tick, some fsynced, some left dirty)
    /// runs on a volatile-cache disk; the cut keeps everything flushed
    /// before a random point of the device log plus a random subset of the
    /// writes since the last flush, and loses the cache. After the remount:
    /// the journal is idle, every listed file's chain is sound, and every
    /// file whose durable step completed before the cut reads back exactly.
    ///
    /// **Canary.** `wb-flush-no-writeback-canary` (a barrier/fsync flushes
    /// without writing the queue back): fsynced bytes are missing, or a
    /// later epoch lands without an earlier one.
    #[test]
    fn a_power_cut_at_a_random_point_leaves_a_consistent_volume() {
        let _g = serial();
        let mut rng = Rng(0x5EED_2026_0A09);
        let mut cuts = 0;
        for round in 0..24 {
            fresh();
            let pristine = fs_test_drivers::disk_image();
            disk_writeback();
            let _ = disk_take_log();
            // (name, bytes, log length when it became durable)
            let mut done: Vec<([u8; 11], Vec<u8>, usize)> = Vec::new();
            let mut logged = 0usize;
            let mut log: Vec<LogEntry> = Vec::new();
            let take = |log: &mut Vec<LogEntry>, logged: &mut usize| {
                log.extend(disk_take_log());
                *logged = log.len();
            };
            for i in 0..6 {
                let name = n83(round % 4 * 6 + i);
                let len = 1 + rng.below(1500) as usize;
                let data = pattern(len, rng.next() as u8);
                let kind = rng.below(3);
                if kind == 0 {
                    assert_eq!(fat32::fat32_write_file(&name, &data), Ok(()));
                    take(&mut log, &mut logged);
                    done.push((name, data, logged));
                } else if kind == 1 {
                    // The VFS close's shape: queued; durable only after a sync.
                    assert_eq!(fat32::fat32_write_file_queued(&name, &data), Ok(()));
                    if rng.below(2) == 0 {
                        assert_eq!(fat32::fat32_sync(), Ok(()));
                        take(&mut log, &mut logged);
                        done.push((name, data, logged));
                    }
                } else {
                    let mut path = b"/F00.DAT".to_vec();
                    path[2] = name[1]; path[3] = name[2];
                    let f = fat32::fat32_open(fat32::Volume::assume_mounted(), &path,
                        fat32::open_flags::WRITE | fat32::open_flags::CREATE).expect("open");
                    let half = len / 2;
                    assert_eq!(fat32::fat32_write(f, &data[..half]), Ok(half));
                    if rng.below(2) == 0 { fat32::fat32_writeback_tick(u64::MAX / 2); }
                    assert_eq!(fat32::fat32_write(f, &data[half..]), Ok(len - half));
                    if rng.below(3) == 0 {
                        // Left open and dirty: the cut may take it.
                        continue;
                    }
                    assert_eq!(fat32::fat32_fsync(f), Ok(()));
                    take(&mut log, &mut logged);
                    done.push((name, data, logged));
                    let _ = fat32::fat32_close(f);
                }
            }
            take(&mut log, &mut logged);
            // The cut: a random point of the log; a random subset of the
            // writes since the last flush before it survives.
            let p = rng.below(log.len() as u64 + 1) as usize;
            let last_flush = log[..p].iter().rposition(|e| *e == LogEntry::Flush).map_or(0, |k| k + 1);
            let mut img = pristine.clone();
            for (k, e) in log[..p].iter().enumerate() {
                if let LogEntry::Write(s, d) = e {
                    if k < last_flush || rng.below(2) == 0 {
                        let off = *s as usize * SECTOR;
                        img[off..off + SECTOR].copy_from_slice(d);
                    }
                }
            }
            let _ = disk_durable_image();
            super::swap_medium(img);
            assert_eq!(fat32::fat32_mount(), Ok(()), "round {round}: a cut image must mount");
            assert!(fat32::fat32_journal_idle(), "round {round}: journal busy after mount");
            for i in 0..24 {
                let name = n83(i);
                if let Err(why) = fat32::fat32_check_root_chain(&name) {
                    panic!("round {round} cut {p}/{}: {}: {why}", log.len(), String::from_utf8_lossy(&name));
                }
            }
            for (name, data, at) in &done {
                if *at > last_flush { continue; }
                let (cl, size) = fat32::fat32_lookup_root(name)
                    .unwrap_or_else(|_| panic!("round {round}: a durable file is gone"));
                assert_eq!(size as usize, data.len(), "round {round}: durable size");
                let mut out = vec![0u8; data.len()];
                assert_eq!(fat32::fat32_read_chain(cl, &mut out), data.len());
                assert!(out == *data, "round {round}: a durable file's bytes differ");
            }
            cuts += 1;
        }
        assert_eq!(cuts, 24);
    }
}




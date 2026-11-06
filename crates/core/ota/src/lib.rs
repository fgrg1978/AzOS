// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
#![no_std]
// SC01 — safety coding standard lints.
#![warn(
    clippy::pedantic,
    clippy::missing_safety_doc,
    clippy::undocumented_unsafe_blocks,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
)]
#![allow(
    clippy::module_name_repetitions, // re-exporting from `pure` is intentional
    clippy::missing_errors_doc,      // most fns return bool/Option, not Result
    clippy::missing_panics_doc,      // panics audited via SC-5
    clippy::cast_possible_truncation, // u32/usize casts audited at call sites
    clippy::cast_sign_loss,           // FS APIs return isize for n bytes
    clippy::similar_names,            // crc_a/crc_b etc. are intentional
    clippy::indexing_slicing,         // FS read/write paths check len() above
    clippy::manual_let_else,          // explicit `if x < 0 { return ... }` is clearer here
    clippy::match_same_arms,          // intentional duplication for readability
    clippy::large_stack_arrays,       // OTA_RECV_BUF_SIZE buffer is by design (no_std, no heap in safety path)
)]
//! OTA firmware update — A/B slot management, image format, CRC-32.
//!
//! ## On-wire format (TCP transfer)
//!
//! The OTA header (24 bytes) is sent over TCP before the payload.
//! It is **never** stored on disk — only the raw kernel binary is written.
//!
//! ```text
//! Offset  Size  Field
//! 0x00    4     Magic: "ROTA" (0x524F5441)
//! 0x04    4     Header version (1)
//! 0x08    4     Image size (payload only, excl. header)
//! 0x0C    4     CRC-32 of payload (IEEE 802.3)
//! 0x10    4     Firmware version (major.minor.patch packed u32)
//! 0x14    1     Platform ID (0=qemu, 1=vf2, 2=k1)
//! 0x15    1     Flags (bit0=compressed)
//! 0x16    2     Reserved (zero)
//! 0x18    --    Payload (raw kernel binary)
//! ```
//!
//! ## Disk layout
//!
//! ```text
//! /fat/KERN_A.BIN  — raw kernel binary (no header), directly bootable by U-Boot
//! /fat/KERN_B.BIN  — raw kernel binary (no header), directly bootable by U-Boot
//! /fat/BOOTMETA    — INI text with slot info + per-slot CRC/size/version
//! ```
//!
//! ## Boot metadata (`/fat/BOOTMETA`)
//!
//! ```text
//! active_slot=a
//! boot_count=0
//! last_good=a
//! fw_version_a=0
//! fw_version_b=0
//! fw_version_r=0
//! image_size_a=0
//! image_size_b=0
//! image_size_r=0
//! image_crc_a=0
//! image_crc_b=0
//! image_crc_r=0
//! min_fw_version=0
//! sec_epoch_a=0
//! sec_epoch_b=0
//! min_sec_epoch=0
//! ```
//!
//! `sec_epoch_a`/`sec_epoch_b` are the epochs of the signed whole-system sets
//! ([`update`]) the slots hold, and `min_sec_epoch` is the anti-rollback floor
//! of the whole system, advanced only when a boot is confirmed. With Kconfig
//! `OTA_FLOOR_TPM_NV` the floor also lives in a TPM NV index ([`floor`]): the
//! floor in force is the higher of the two, so a rolled-back BOOTMETA does not
//! lower it.
//!
//! `active_slot`/`last_good` are one-letter codes: `a`/`b`/`r` (OT04 —
//! `r` selects the recovery slot). The `_r` fields exist so the recovery
//! slot can be CRC-verified like A/B, but nothing writes them today: R is
//! flashed at the factory and never touched by OTA, so on every BOOTMETA
//! in the field `image_size_r` reads back as 0 and `ota_verify_slot(SLOT_R)`
//! is unconditionally `false` until some future flashing tool populates it.
//! Old (pre-OT04) BOOTMETA files simply lack these keys — the INI parser
//! treats missing keys as 0, which is the same "R not verifiable" state.
//!
//! ## Whole-system update
//!
//! A kernel does not run alone: the userspace images, the topology and the
//! configuration are part of what a slot boots. [`update`] makes the slot the
//! unit of installation: one signed manifest covers all of them, the set is
//! staged into the inactive slot, [`ota_update_switch`] flips ONE BOOTMETA
//! record, and the existing boot confirmation and rollback then confirm or
//! return all of it together. The installer service (`userspace/services/pkgd`)
//! stages; the switch is here, in the kernel, where the boot record and the
//! floors are, and is asked for through the `Ota` interface's `switch` (the
//! `ota switch` tool). The boot of a slot with a signed set ([`ota_install_boot_set`],
//! first thing after the volume mounts) makes the set's files the ones the
//! root of the volume names, so every later read of an image, the topology or
//! the configuration is the set's.
//!
//! All pure (deterministic, side-effect-free) logic lives in [`pure`] —
//! keep it that way so the host test crate can `#[path]`-include it.

use core::sync::atomic::{AtomicU32, Ordering};

pub mod floor;
pub mod pure;
#[cfg(feature = "boot-slots")]
pub mod recovery;
pub mod secure_boot;
#[cfg(feature = "boot-slots")]
mod slots;
#[cfg(feature = "boot-slots")]
pub use slots::*;
pub mod update;

// Re-export all pure constants, types, and functions for backwards compat.
pub use pure::{
    BootMeta, BootMetaRecord, BootValidateOutcome, Crc32State, OtaHeader,
    StagedSet, SwitchRefusal, ota_install_refused_pure, ota_kernel_install_pure, ota_switch_pure, ota_update_allowed_pure,
    OTA_FLAG_COMPRESSED, OTA_HEADER_SIZE, OTA_HEADER_VERSION, OTA_MAGIC,
    OTA_PLATFORM_K1, OTA_PLATFORM_QEMU, OTA_PLATFORM_VF2,
    SLOT_A, SLOT_B, SLOT_R,
    OTA_DEFAULT_MAX_BOOT_ATTEMPTS,
    crc32, ota_boot_exhausted, ota_boot_validate_pure, ota_check_rollback_pure,
    ota_void_boot_pure,
    ota_encode_header, ota_inactive_slot_pure,
    ota_mark_boot_good_pure, ota_next_seq, ota_parse_header, ota_slot_char,
    ota_pick_boot_meta_record, ota_pick_meta_write_slot, ota_validate_header,
    parse_boot_meta, parse_boot_meta_record, serialize_boot_meta,
    serialize_boot_meta_record,
};

/// Maximum firmware payload size the OTA receiver will accept, straight from
/// Kconfig (`OTA_MAX_IMAGE_SIZE_MB`, range 1-64, default 8 MiB).
///
/// This used to be a hardcoded `2 * 1024 * 1024` inside [`pure`] that ignored
/// the Kconfig symbol entirely — the symbol was declared, emitted as
/// `OTA_MAX_IMAGE_SIZE_BYTES`, and referenced by nobody. `config/subsys/Kconfig.ota`'s own
/// help text documented the intent to migrate it and it never happened.
///
/// It lives here rather than in [`pure`] because that module must stay
/// dependency-free for the host test crate; [`pure::ota_validate_header`]
/// takes the ceiling as a parameter instead.
///
/// NOTE: secure-boot verification used to have a separate, smaller ceiling
/// (`SECURE_BOOT_MAX_IMAGE_SIZE`, a 2 MiB `.bss` buffer for holding a whole
/// image contiguously). Closed 2026-09-26 (U09-14): the signed manifest
/// binds `sha256(image)` rather than the image itself, so verification now
/// streams the hash and this is the only size ceiling in the OTA path.
pub const OTA_MAX_IMAGE_SIZE: usize = azos_limits::OTA_MAX_IMAGE_SIZE_BYTES;

#[cfg(feature = "boot-slots")]
pub use secure_boot::{secure_boot_steer_to_recovery, RecoverySteer};

pub use secure_boot::{
    BootTrust, BootTrustReason, SecureBootInfo,
    secure_boot_verify_slot, secure_boot_verify_slot_detailed,
    secure_boot_verify_staged_detailed, secure_boot_verify_image_detailed,
    secure_boot_require_signature, secure_boot_enforced_at_compile_time,
    secure_boot_set_require_signature, secure_boot_info,
    secure_boot_sig_path, secure_boot_tmp_path,
    secure_boot_verify_other_slots, SECURE_BOOT_PUBKEY,
    SECURE_BOOT_PUBKEY_LEN,
    SECURE_BOOT_SIG_PATH_A, SECURE_BOOT_SIG_PATH_B, SECURE_BOOT_SIG_PATH_R,
    SECURE_BOOT_TMP_PATH_A, SECURE_BOOT_TMP_PATH_B,
};

// ── Network defaults ───────────────────────────────────────────────────────

/// Default TCP port for OTA receive.
pub const OTA_DEFAULT_PORT: u16 = 8080;

/// Size of the streaming receive buffer (bytes per chunk).
pub const OTA_RECV_BUF_SIZE: usize = 4096;

// ── Boot loop detection ────────────────────────────────────────────────────

/// Seconds of successful uptime before marking boot as good.
pub const OTA_BOOT_GOOD_DELAY_S: u32 = 30;

/// One-shot latch for the "fell back to the unauthenticated legacy BOOTMETA"
/// warning in [`ota_read_boot_meta`]. 0 = not yet warned, 1 = warned.
/// See the comment at the use site for why the print must not repeat.
static LEGACY_META_WARNED: AtomicU32 = AtomicU32::new(0);

// ── File paths on FAT32 ────────────────────────────────────────────────────

pub const OTA_SLOT_A_PATH: &[u8] = b"/fat/KERN_A.BIN";
pub const OTA_SLOT_B_PATH: &[u8] = b"/fat/KERN_B.BIN";
/// OT04 — immutable recovery slot. Read-only; OTA never writes here.
/// Boot fallback: if both A and B fail to load, U-Boot tries this path.
pub const OTA_SLOT_R_PATH: &[u8] = b"/fat/KERN_R.BIN";

// OT02.A — atomic-write staging files for OTA payload.
// Receiver writes to `*.TMP` first, validates CRC, then promotes to `.BIN`.
pub const OTA_SLOT_A_TMP_PATH: &[u8] = b"/fat/KERN_A.TMP";
pub const OTA_SLOT_B_TMP_PATH: &[u8] = b"/fat/KERN_B.TMP";

// OT02.B — dual BOOTMETA records (power-loss safe).
// Two physical files; reader picks the higher-seq valid CRC; writer
// always targets the older/invalid one so a torn write loses at most
// one generation.
pub const OTA_META_PATH_A: &[u8] = b"/fat/BOOTMETA.A";
pub const OTA_META_PATH_B: &[u8] = b"/fat/BOOTMETA.B";

// Legacy single-file path — read-only fallback for one-time migration
// from the pre-OT02.B format. New writes never touch this path.
pub const OTA_META_PATH:   &[u8] = b"/fat/BOOTMETA";

/// Maximum size of one BOOTMETA record on disk.
///
/// Our serialized records are ~260 bytes (OT04 added the `_r` fields);
/// 512 keeps generous headroom and matches the FAT32 sector size.
pub const OTA_META_RECORD_MAX_BYTES: usize = 512;

// ── Boot metadata read/write — OT02.B dual-file power-loss-safe ────────────

/// Read a single BOOTMETA record from disk, validating its embedded CRC.
///
/// Returns `None` if the file is missing, empty, or fails CRC validation
/// (torn-write detection).
fn fs_read_meta_record(path: &[u8]) -> Option<BootMetaRecord> {
    let mut fd_table = azos_fs::ScratchFds::new();
    let fd = azos_fs::vfs_open(&mut fd_table, path, azos_fs::O_RDONLY);
    if fd < 0 {
        return None;
    }
    let mut buf = [0u8; OTA_META_RECORD_MAX_BYTES];
    let n = azos_fs::vfs_read(&mut fd_table, fd, buf.as_mut_ptr(), buf.len());
    azos_fs::vfs_close(&mut fd_table, fd);
    if n <= 0 {
        return None;
    }
    parse_boot_meta_record(&buf[..n as usize])
}

///
/// Returns a tuple `(rec_a, rec_b)` with `None` for any file that
/// is missing or has a CRC mismatch.
#[must_use]
pub fn ota_read_boot_meta_records() -> (Option<BootMetaRecord>, Option<BootMetaRecord>) {
    (fs_read_meta_record(OTA_META_PATH_A),
     fs_read_meta_record(OTA_META_PATH_B))
}

/// Read effective boot metadata.
///
/// Selection order:
/// 1. The valid record with the higher `seq` from `BOOTMETA.A`/`BOOTMETA.B`.
/// 2. (Migration) the legacy `/fat/BOOTMETA` parsed as raw `BootMeta`
///    (no seq, no CRC) — only consulted on first boot after upgrade.
/// 3. `BootMeta::default()` if nothing is available.
#[must_use]
pub fn ota_read_boot_meta() -> BootMeta {
    let mut meta = read_boot_meta_stored();
    // The epoch floor is the higher of the volume's and the hardware
    // backend's (`floor`): a record that was rolled back on the volume does
    // not lower it. Every consumer (the update's admission, the livepatch
    // check) reads it through here.
    meta.min_sec_epoch = floor::lift(meta.min_sec_epoch);
    meta
}

// REQ-014
/// The epoch floor a package or a livepatch is judged against, `None` when
/// this build keeps none it may trust: BOOTMETA's floor rises only at a
/// confirmed boot (`BOOT_SLOTS`), so without the slots it is trusted only
/// where a hardware backend holds it too (`floor::trusted`). Never a zero
/// standing in for "no floor".
#[must_use]
pub fn ota_floor() -> Option<u32> {
    floor::trusted(read_boot_meta_stored().min_sec_epoch, cfg!(feature = "boot-slots"))
}

/// BOOTMETA as the volume holds it, floor included: what
/// [`ota_read_boot_meta`] starts from.
fn read_boot_meta_stored() -> BootMeta {
    let (rec_a, rec_b) = ota_read_boot_meta_records();
    if let Some(picked) = ota_pick_boot_meta_record(rec_a, rec_b) {
        return picked.meta;
    }

    // Legacy migration path: try the old single-file format.
    //
    // SECURITY — this record is UNAUTHENTICATED. Unlike `BOOTMETA.A`/`.B`,
    // the legacy file carries no `crc=` line, so `parse_boot_meta` accepts
    // whatever bytes are on disk: there is no torn-write detection and, more
    // to the point, no way to tell an old file left by an upgrade from one an
    // attacker planted. The FAT volume is on a removable card anyone with a
    // card reader can rewrite, and reaching this branch only requires deleting or
    // corrupting both dual-file records — so "the legacy file is what we
    // read" is a state that can be *caused*, not merely inherited.
    //
    // What that buys an attacker is bounded but real: they choose
    // `active_slot`, `last_good`, and in particular `min_fw_version`, which
    // they will set to 0 to flatten the OT03 anti-rollback floor.
    // Deliberately NOT hardened into a rejection: refusing here falls through
    // to `BootMeta::default()`, whose `min_fw_version` is *also* 0, so
    // rejecting buys no security at all and costs the one-time migration this
    // branch exists for. `parse_slot_char` already clamps any unrecognised
    // slot code to `SLOT_A`, so there is no out-of-range slot to guard
    // against either.
    //
    // What actually contains this is secure boot: the anti-rollback floor is
    // advisory, and an image that reaches the slot still has to carry a
    // signature `secure_boot_verify_slot_detailed()` accepts. The warning
    // below exists so that a fleet operator sees the downgrade in the boot
    // log rather than discovering it forensically.
    let mut fd_table = azos_fs::ScratchFds::new();
    let fd = azos_fs::vfs_open(&mut fd_table, OTA_META_PATH,
                                    azos_fs::O_RDONLY);
    if fd >= 0 {
        let mut buf = [0u8; OTA_META_RECORD_MAX_BYTES];
        let n = azos_fs::vfs_read(&mut fd_table, fd, buf.as_mut_ptr(), buf.len());
        azos_fs::vfs_close(&mut fd_table, fd);
        if n > 0 {
            let meta = parse_boot_meta(&buf[..n as usize]);
            // Warn once per boot, not once per call. `ota_read_boot_meta()` is
            // on hot-ish paths (`ota_slot_info` → `secure_boot_verify_*`, the
            // shell's `ota status`), and the QEMU disk image built by the
            // Makefile ships exactly this layout — a plain `::BOOTMETA` with
            // no `.A`/`.B` — so an unlatched print here would repeat on every
            // call and drown the console the smoke tests read.
            if LEGACY_META_WARNED
                .compare_exchange(0, 1, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                azos_drv_sys::kwarn!(
                "[OTA] WARNING: both BOOTMETA.A/.B are missing or failed CRC — \
                 falling back to the UNAUTHENTICATED legacy /fat/BOOTMETA \
                 (active_slot={}, min_fw_version={}). Anti-rollback floor from \
                 this file is NOT trustworthy; secure boot is the only gate \
                 left. Expected once after upgrade — otherwise investigate.",
                    ota_slot_char(meta.active_slot),
                    meta.min_fw_version);
            }
            return meta;
        }
    }

    BootMeta::default()
}

// ── Current platform detection ─────────────────────────────────────────────

/// Return the platform ID for the currently running kernel.
#[must_use] 
pub fn ota_current_platform() -> u8 {
    #[cfg(feature = "vf2")]
    { return OTA_PLATFORM_VF2; }
    #[cfg(feature = "k1")]
    { return OTA_PLATFORM_K1; }
    #[cfg(not(any(feature = "vf2", feature = "k1")))]
    { OTA_PLATFORM_QEMU }
}

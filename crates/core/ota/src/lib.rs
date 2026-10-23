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

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

pub mod floor;
pub mod pure;
pub mod recovery;
pub mod secure_boot;
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

pub use secure_boot::{
    BootTrust, BootTrustReason, SecureBootInfo,
    secure_boot_verify_slot, secure_boot_verify_slot_detailed,
    secure_boot_verify_staged_detailed, secure_boot_verify_image_detailed,
    secure_boot_require_signature, secure_boot_enforced_at_compile_time,
    secure_boot_set_require_signature, secure_boot_info,
    secure_boot_sig_path, secure_boot_tmp_path,
    secure_boot_steer_to_recovery, RecoverySteer,
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

// ── Runtime atomics (populated from BOOTMETA at boot) ──────────────────────

/// Active boot slot (0 = A, 1 = B).
pub static CFG_OTA_ACTIVE_SLOT: AtomicU32 = AtomicU32::new(0);

/// Current boot count (incremented each boot, reset on success).
pub static CFG_OTA_BOOT_COUNT: AtomicU32 = AtomicU32::new(0);

/// Maximum boot attempts before automatic rollback.
pub static CFG_OTA_MAX_BOOT_ATTEMPTS: AtomicU32 =
    AtomicU32::new(OTA_DEFAULT_MAX_BOOT_ATTEMPTS);

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

// ── Slot management (FS-aware wrappers) ────────────────────────────────────

/// Return the inactive slot (the slot we write new firmware to).
pub fn ota_inactive_slot() -> u8 {
    pure::ota_inactive_slot_pure(CFG_OTA_ACTIVE_SLOT.load(Ordering::Acquire) as u8)
}

/// Return the FAT32 path for the given slot.
#[must_use]
pub fn ota_slot_path(slot: u8) -> &'static [u8] {
    match slot {
        SLOT_A => OTA_SLOT_A_PATH,
        SLOT_B => OTA_SLOT_B_PATH,
        SLOT_R => OTA_SLOT_R_PATH,
        _      => OTA_SLOT_A_PATH, // defensive default
    }
}

/// Return the active slot index.
pub fn ota_active_slot() -> u8 {
    CFG_OTA_ACTIVE_SLOT.load(Ordering::Acquire) as u8
}

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

/// Replace the file at `path` with `bytes` (open with `O_CREAT|O_TRUNC`,
/// write, close) and flush the volume.
///
/// Returns the step that failed, for the console. Every BOOTMETA writer used
/// to ignore all three return values, so a record the volume refused — gate
/// 192: a new `/fat/BOOTMETA.B` on a root directory whose chain was full —
/// left no trace but its absence. For the FAT32 proxy the directory entry
/// and the data are written by the CLOSE, so that is the step a refused
/// create reports. The result is diagnostic only: every caller's decision
/// still rests on reading the record back (`secure_boot_steer_to_recovery`),
/// because a successful close is not proof that the record parses.
fn fs_replace_file(path: &[u8], bytes: &[u8]) -> Result<(), &'static str> {
    let mut fd_table = azos_fs::ScratchFds::new();
    let fd = azos_fs::vfs_open(&mut fd_table, path,
        azos_fs::O_WRONLY | azos_fs::O_CREAT | azos_fs::O_TRUNC);
    if fd < 0 {
        return Err("open");
    }
    let written = azos_fs::vfs_write(&mut fd_table, fd, bytes.as_ptr(), bytes.len());
    let closed = azos_fs::vfs_close(&mut fd_table, fd);
    // Flush the FAT32 dirty cache so the record is durable on disk
    // before we return. A torn write here is exactly the case
    // OT02.B is designed to survive — but we still want each record
    // to be as durable as possible, and a record the volume did not
    // flush is reported like one it did not take.
    let synced = azos_fs::fat32_sync().is_ok();
    pure::ota_replace_verdict_pure(written as isize, bytes.len(), closed, synced)
}

/// Say that a BOOTMETA file was not written, and at which step.
fn report_meta_write(path: &[u8], result: Result<(), &'static str>) {
    if let Err(step) = result {
        azos_drv_sys::kerr!(
            "[OTA] {} not written: {} failed",
            core::str::from_utf8(path).unwrap_or("BOOTMETA"),
            step
        );
    }
}

/// Write a BOOTMETA record to disk and request a flush.
fn fs_write_meta_record(path: &[u8], record: &BootMetaRecord) {
    let mut buf = [0u8; OTA_META_RECORD_MAX_BYTES];
    let n = serialize_boot_meta_record(record, &mut buf);
    report_meta_write(path, fs_replace_file(path, &buf[..n.min(buf.len())]));
}

/// Write the plain, single-file `/fat/BOOTMETA` that U-Boot's `boot.cmd`
/// reads via `env import -t`. This is the kernel's dual-file `.A`/`.B`
/// scheme's *view* projected into the legacy format U-Boot understands —
/// U-Boot has no knowledge of the CRC/seq dual-file protocol. A torn
/// write here is accepted: `.A`/`.B` remain the kernel's own source of
/// truth and recover independently; this file only has to be *eventually*
/// consistent for U-Boot's next boot decision.
fn fs_write_plain_boot_meta(meta: &BootMeta) {
    let mut buf = [0u8; OTA_META_RECORD_MAX_BYTES];
    let n = serialize_boot_meta(meta, &mut buf);
    report_meta_write(OTA_META_PATH, fs_replace_file(OTA_META_PATH, &buf[..n.min(buf.len())]));
}

/// Read both dual-file records and the legacy single-file fallback.
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

/// Write boot metadata using the dual-file scheme.
///
/// Picks the older (or invalid) of `BOOTMETA.A`/`BOOTMETA.B` as the
/// target, increments the sequence number, and writes the new record.
/// A torn write here is recoverable on next boot — the previous record
/// in the *other* file remains valid.
pub fn ota_write_boot_meta(meta: &BootMeta) {
    let (rec_a, rec_b) = ota_read_boot_meta_records();
    let current_best = ota_pick_boot_meta_record(rec_a, rec_b);
    let next_seq = ota_next_seq(current_best);
    let target_slot = ota_pick_meta_write_slot(rec_a, rec_b);
    let target_path = if target_slot == SLOT_A {
        OTA_META_PATH_A
    } else {
        OTA_META_PATH_B
    };
    let record = BootMetaRecord { meta: *meta, seq: next_seq };
    fs_write_meta_record(target_path, &record);
    // Keep U-Boot's view (boot.cmd's `env import -t` of the plain file)
    // in sync with what the kernel just decided.
    fs_write_plain_boot_meta(meta);
}

/// Apply boot metadata to runtime atomics.
pub fn ota_apply_meta(meta: &BootMeta) {
    CFG_OTA_ACTIVE_SLOT.store(u32::from(meta.active_slot), Ordering::Release);
    CFG_OTA_BOOT_COUNT.store(meta.boot_count, Ordering::Release);
}

/// What THIS boot recorded as its unconfirmed mark: `slot << 32 | count`,
/// written by [`ota_boot_validate`] once the record read back, and taken
/// (swapped to 0) by whichever of [`ota_mark_boot_good`] and
/// [`ota_void_unconfirmed_boot`] runs first. 0 = nothing left to confirm or
/// void (a count of 0 is never recorded: a validated boot counts at least 1).
static UNCONFIRMED: AtomicU64 = AtomicU64::new(0);

/// Serializes the two read-modify-write passes over BOOTMETA that can race
/// at run time: sys-wdt's boot-good mark and an orderly shutdown's void.
static META_RMW: AtomicBool = AtomicBool::new(false);

struct MetaRmw;
impl MetaRmw {
    fn take() -> Self {
        while META_RMW
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
        MetaRmw
    }
}
impl Drop for MetaRmw {
    fn drop(&mut self) {
        META_RMW.store(false, Ordering::Release);
    }
}

/// What [`ota_void_unconfirmed_boot`] did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VoidOutcome {
    /// This boot's +1 was taken back: `boot_count` went `from` -> `from - 1`.
    Voided { from: u32 },
    /// Nothing to void: the boot was already confirmed (or voided), or it
    /// never recorded a mark (no volume).
    NothingRecorded,
    /// The record no longer says what this boot wrote (an OTA install
    /// switched the slot and reset the count): left alone.
    RecordMoved,
}

/// An ORDERLY reboot or power-off is about to happen: take back this boot's
/// own unconfirmed mark, so the shutdown does not count as a crash (owner
/// decision 2026-09-28). Called by `sys_reboot`/`sys_shutdown` (through the
/// kernel's hook, `crates/core/syscall`) and by the shell's `reboot`/`shutdown`,
/// never by the panic path: a crash or a reset still counts.
///
/// Voids rather than confirms: confirming would move `last_good` and the
/// anti-rollback floor for an image that has not run its
/// `OTA_BOOT_GOOD_DELAY_S`, and would let a reboot out of safe mode bless the
/// image that put the device there. Compare-and-decrement against what this
/// boot wrote ([`ota_void_boot_pure`]), under the lock the boot-good mark
/// takes, so an OTA install's fresh record is never overwritten.
pub fn ota_void_unconfirmed_boot() -> VoidOutcome {
    let _g = MetaRmw::take();
    let packed = UNCONFIRMED.swap(0, Ordering::AcqRel);
    if packed == 0 {
        return VoidOutcome::NothingRecorded;
    }
    let (slot, count) = ((packed >> 32) as u8, packed as u32);
    let mut meta = ota_read_boot_meta();
    if !ota_void_boot_pure(&mut meta, slot, count) {
        azos_drv_sys::kprintln!(
            "[OTA] orderly shutdown: BOOTMETA no longer holds this boot's mark (slot={} count={}): left alone",
            ota_slot_char(meta.active_slot), meta.boot_count);
        return VoidOutcome::RecordMoved;
    }
    ota_write_boot_meta(&meta);
    ota_apply_meta(&meta);
    azos_drv_sys::kprintln!(
        "[OTA] orderly shutdown before the boot was confirmed: its mark voided (boot_count {} -> {})",
        count, meta.boot_count);
    VoidOutcome::Voided { from: count }
}

/// Mark the current boot as successful (reset `boot_count`, set `last_good`).
///
/// This is also the one point where a boot stops counting as a crash:
/// `boot_count` IS the watchdog's crash counter (see [`ota_boot_validate`]),
/// so its in-memory copy is cleared here, after the record is written.
pub fn ota_mark_boot_good() {
    let _g = MetaRmw::take();
    UNCONFIRMED.store(0, Ordering::Release);
    let mut meta = ota_read_boot_meta();
    ota_mark_boot_good_pure(&mut meta);
    // The hardware floor first: a crash between the two leaves it ahead of the
    // volume's, which only holds the floor higher. It gets the confirmed
    // slot's epoch, never `meta.min_sec_epoch`: that is the volume's number,
    // and a forged one must not reach a floor that cannot come down.
    floor::commit(pure::ota_confirmed_epoch(&meta));
    ota_write_boot_meta(&meta);
    CFG_OTA_BOOT_COUNT.store(0, Ordering::Release);
    azos_drv_sys::wdt::crash_counter_reset();
    azos_drv_sys::kprintln!("[OTA] Boot marked good (slot={})",
        ota_slot_char(meta.active_slot));
}

// ── Slot CRC verification (FS) ─────────────────────────────────────────────

/// Verify CRC-32 of a raw firmware file against the expected CRC from BOOTMETA.
///
/// The .BIN file is a raw kernel binary (no header). The expected CRC and
/// size come from BOOTMETA, which was set during the OTA receive.
///
/// Returns `true` if the file exists, size matches, and CRC matches.
#[must_use] 
pub fn ota_verify_slot(slot: u8) -> bool {
    let meta = ota_read_boot_meta();
    let expected_crc = meta.slot_crc(slot);
    let expected_size = meta.slot_size(slot);

    if expected_size == 0 {
        return false; // no firmware recorded for this slot
    }

    let path = ota_slot_path(slot);
    let mut fd_table = azos_fs::ScratchFds::new();
    let fd = azos_fs::vfs_open(&mut fd_table, path, azos_fs::O_RDONLY);
    if fd < 0 { return false; }

    // Stream file and compute CRC-32
    let mut crc_state = Crc32State::new();
    let mut total_read = 0u32;
    let mut chunk = [0u8; OTA_RECV_BUF_SIZE];

    loop {
        let got = azos_fs::vfs_read(&mut fd_table, fd,
                                         chunk.as_mut_ptr(), chunk.len());
        if got <= 0 { break; }
        crc_state.update(&chunk[..got as usize]);
        total_read += got as u32;
    }
    azos_fs::vfs_close(&mut fd_table, fd);

    if total_read != expected_size {
        return false;
    }

    crc_state.finalize() == expected_crc
}

/// Get the slot info (version, size, crc) from BOOTMETA for display.
#[must_use] 
pub fn ota_slot_info(slot: u8) -> (u32, u32, u32) {
    let meta = ota_read_boot_meta();
    (meta.slot_version(slot), meta.slot_size(slot), meta.slot_crc(slot))
}

// ── Boot-time validation (called from kernel_main) ─────────────────────────

/// What [`ota_boot_validate`] found and did.
#[derive(Clone, Copy, Debug)]
pub struct BootValidation {
    /// The boot metadata as written back (possibly rolled back).
    pub meta: BootMeta,
    /// `boot_count` as read, before this boot's increment: the consecutive
    /// boots that were never marked good ([`ota_mark_boot_good`]). This is
    /// the watchdog's crash counter; the kernel loads it into
    /// `wdt::CRASH_COUNTER` and hands it to the recovery decision.
    pub prior_unconfirmed: u32,
    /// Neither `BOOTMETA.A` nor `BOOTMETA.B` held a valid record before this
    /// boot wrote one (a fresh volume, or one with only the legacy file).
    pub fresh: bool,
    /// A re-read after the write returned this boot's `boot_count`: the
    /// unconfirmed mark is on the volume, not only in memory.
    pub recorded: bool,
    /// What the FSM did. `Exhausted` and `RollbackRefused` are the boots
    /// whose attempts are spent ([`ota_boot_exhausted`]): safe mode.
    pub outcome: BootValidateOutcome,
    /// `max_attempts` the FSM ran with.
    pub max_attempts: u32,
}

/// Boot-time OTA validation: increment `boot_count`, rollback if stuck.
///
/// Call after FAT32 is mounted and config is loaded, before starting tasks.
///
/// `boot_count` is the one unconfirmed-boot counter on the device: this call
/// counts the boot, [`ota_mark_boot_good`] (from `sys-wdt`, after
/// `OTA_BOOT_GOOD_DELAY_S` of uptime) clears it. A boot that panics, hangs or
/// loses power in between leaves it raised for the next boot, which reads it
/// as its crash count ([`BootValidation::prior_unconfirmed`]). It used to have
/// a twin, `/fat/BOOTCNT.BIN`, cleared at the end of late init instead.
pub fn ota_boot_validate() -> BootValidation {
    let (rec_a, rec_b) = ota_read_boot_meta_records();
    let fresh = rec_a.is_none() && rec_b.is_none();
    let mut meta = ota_read_boot_meta();
    let prior_unconfirmed = meta.boot_count;
    let max_attempts = CFG_OTA_MAX_BOOT_ATTEMPTS.load(Ordering::Relaxed);

    // Pure FSM does the increment + possible rollback.
    let outcome = ota_boot_validate_pure(&mut meta, max_attempts);

    if outcome == BootValidateOutcome::RolledBack {
        azos_drv_sys::kwarn!(
            "[OTA] Boot loop detected (max={}) — rolling back to slot {}",
            max_attempts,
            ota_slot_char(meta.last_good));
    } else if outcome == BootValidateOutcome::Exhausted {
        azos_drv_sys::kerr!(
            "[OTA] Boot loop detected (max={}) with nothing to roll back to: slot {} IS \
             last_good. Count kept at {}; boot attempts exhausted.",
            max_attempts,
            ota_slot_char(meta.active_slot),
            meta.boot_count);
    } else if outcome == BootValidateOutcome::RollbackRefused {
        // The one case where a boot loop is NOT answered by a rollback: the
        // fallback slot is recorded in `bad_slots` as having failed secure
        // boot. Loud, because the device is now in a state that needs an OTA
        // or a reflash — and silent-and-rolling-back is precisely the attack.
        azos_drv_sys::kerr!(
            "[OTA] Boot loop detected (max={}) — REFUSING to roll back: slot {} \
             failed secure-boot verification (bad_slots={:#04x}). Staying on \
             slot {}; install a signed image or reflash.",
            max_attempts,
            ota_slot_char(meta.last_good),
            meta.bad_slots,
            ota_slot_char(meta.active_slot));
    }

    // Persist updated metadata
    ota_write_boot_meta(&meta);
    ota_apply_meta(&meta);
    let recorded = ota_read_boot_meta().boot_count == meta.boot_count;
    if recorded && meta.boot_count != 0 {
        UNCONFIRMED.store(
            (u64::from(meta.active_slot) << 32) | u64::from(meta.boot_count),
            Ordering::Release);
    }

    // `bad_slots` is on this line, and not only on the boot gate's own
    // "recorded" line, because the gate prints that one ONLY when the mask
    // changes. Without this field, a verdict written by one boot would be
    // invisible on every boot after it — and "did it persist" is the whole
    // point of writing it down.
    azos_drv_sys::kprintln!("[OTA] Boot: slot={} count={}/{} last_good={} bad_slots={:#04x}",
        ota_slot_char(meta.active_slot),
        meta.boot_count, max_attempts,
        ota_slot_char(meta.last_good),
        meta.bad_slots);

    BootValidation { meta, prior_unconfirmed, fresh, recorded, outcome, max_attempts }
}

// ── Whole-system update: the switch (called by whoever holds the authority) ──

/// `KERN_<slot>.SIG` in the VFS's spelling (the secure-boot gate reads the same
/// files by their root-relative names, `secure_boot_sig_path`).
fn ota_sig_path(slot: u8) -> &'static [u8] {
    match slot {
        SLOT_B => b"/fat/KERN_B.SIG",
        _      => b"/fat/KERN_A.SIG",
    }
}

/// The FAT32 volume as the stager's and the switch's [`update::Store`].
struct FatStore {
    fds: azos_fs::ScratchFds,
    /// Descriptors opened for writing: their close is followed by a flush.
    writing: u32,
}

impl FatStore {
    fn new() -> Self {
        FatStore { fds: azos_fs::ScratchFds::new(), writing: 0 }
    }

    fn missing(path: &[u8]) -> update::IoErr {
        if azos_fs::vfs_stat(path).is_none() { update::IoErr::Missing } else { update::IoErr::Io }
    }
}

// The step numbers of an update's two gated steps are the envelope's own.
const _: () = {
    assert!(update::Apply::Stage as u8 == azos_common::envelope::OtaOp::Stage as u8);
    assert!(update::Apply::Switch as u8 == azos_common::envelope::OtaOp::Switch as u8);
};

impl update::Store for FatStore {
    /// The effect gate's `ota` row for the calling Domain (a kernel task with
    /// no row, like the recovery console's, is not held).
    fn may_apply(&mut self, step: update::Apply, slot: u8) -> bool {
        use azos_common::envelope::{asked, Ask, OtaOp};
        let op = match step {
            update::Apply::Stage => OtaOp::Stage,
            update::Apply::Switch => OtaOp::Switch,
        };
        asked(Ask::Ota { op, slot })
    }

    fn open_read(&mut self, path: &[u8]) -> Result<u32, update::IoErr> {
        let fd = azos_fs::vfs_open(&mut self.fds, path, azos_fs::O_RDONLY);
        if fd < 0 { Err(Self::missing(path)) } else { Ok(fd as u32) }
    }

    fn read(&mut self, h: u32, buf: &mut [u8]) -> Result<usize, update::IoErr> {
        let n = azos_fs::vfs_read(&mut self.fds, h as i32, buf.as_mut_ptr(), buf.len());
        if n < 0 { Err(update::IoErr::Io) } else { Ok(n as usize) }
    }

    fn open_write(&mut self, path: &[u8]) -> Result<u32, update::IoErr> {
        let fd = azos_fs::vfs_open(&mut self.fds, path,
            azos_fs::O_WRONLY | azos_fs::O_CREAT | azos_fs::O_TRUNC);
        if fd < 0 {
            return Err(update::IoErr::Io);
        }
        self.writing |= 1 << fd;
        Ok(fd as u32)
    }

    fn write(&mut self, h: u32, data: &[u8]) -> Result<(), update::IoErr> {
        let n = azos_fs::vfs_write(&mut self.fds, h as i32, data.as_ptr(), data.len());
        if n < 0 || n as usize != data.len() { Err(update::IoErr::Io) } else { Ok(()) }
    }

    fn close(&mut self, h: u32) -> Result<(), update::IoErr> {
        let was_writing = self.writing & (1 << h) != 0;
        self.writing &= !(1 << h);
        let closed = azos_fs::vfs_close(&mut self.fds, h as i32);
        // The FAT32 proxy writes the entry and the data at the close; flush the
        // dirty cache so the file is on the medium before the record that
        // depends on it, as `fs_replace_file` does for BOOTMETA.
        let synced = !was_writing || azos_fs::fat32_sync().is_ok();
        if closed == 0 && synced { Ok(()) } else { Err(update::IoErr::Io) }
    }

    fn remove(&mut self, path: &[u8]) -> Result<(), update::IoErr> {
        azos_fs::vfs_unlink(path).map_err(|e| match e {
            azos_fs::FsErr::NotFound => update::IoErr::Missing,
            _ => update::IoErr::Io,
        })
    }

    fn ensure_dir(&mut self, path: &[u8]) -> Result<(), update::IoErr> {
        match azos_fs::vfs_stat(path) {
            Some(st) if st.is_dir => Ok(()),
            Some(_) => Err(update::IoErr::Io),
            None => azos_fs::vfs_mkdir(path).map_err(|_| update::IoErr::Io),
        }
    }

    fn entry(&mut self, dir: &[u8], index: usize, name: &mut [u8; update::NAME_BUF]) -> Option<usize> {
        let mut cookie = 0u64;
        let mut seen = 0usize;
        let mut ent = azos_fs::DirEnt::new();
        // The cookie is the backend's; walk it, skipping the dot entries a
        // backend may list, until the `index`-th real one.
        loop {
            cookie = azos_fs::vfs_readdir(dir, cookie, &mut ent).ok()??;
            let n = ent.name();
            if n == b"." || n == b".." {
                continue;
            }
            if seen == index {
                let len = n.len().min(update::NAME_BUF);
                name[..len].copy_from_slice(&n[..len]);
                return Some(len);
            }
            seen += 1;
        }
    }
}

/// Why [`ota_update_switch`] did not switch. In every case BOOTMETA still
/// names the slot it named before.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UpdateError {
    /// No update key is installed (`SECURE_BOOT_PUBKEY` is all zeros): a
    /// whole-system update is never installed on trust.
    NoKey,
    /// The staged set is not valid or not admissible, or the kernel could not be
    /// promoted.
    Switch(update::SwitchError),
    /// The record was written and did not read back as written.
    Record,
    /// Another switch is running.
    Busy,
    /// This boot has not been confirmed yet ([`ota_mark_boot_good`] has not run):
    /// the system that is running has not proven itself, so it is not replaced,
    /// and the confirmation that is still to come would otherwise land on the
    /// slot just switched to.
    BootUnconfirmed,
}

/// The manifest buffers (~3.6 KiB): in `.bss`, not on the stack of whoever
/// asks. Owned by [`ota_update_switch`] while it runs: it does long volume
/// I/O, so it excludes by refusing a second caller (`try_acquire`), not by
/// spinning or queueing, and holds no lock across the I/O (a claim, rule F1).
static UPDATE_WORK: azos_sync::claim::Claim<update::Work> = azos_sync::claim::Claim::new(update::Work::new());

/// The switch of a whole-system update: the one step that makes the set staged
/// in the inactive slot (by the installer, or by anyone: it is verified here
/// again, against the key and the floors only this side holds) the one that
/// boots.
///
/// 1. The staged set is verified whole ([`update::verify_set`]) and admitted
///    against the boot record, including the epoch floor.
/// 2. The kernel and its signature are promoted into the slot's boot paths and
///    hashed where the boot will load them from.
/// 3. One BOOTMETA record names the slot active with a fresh boot count
///    ([`ota_switch_pure`]). Until it is written the old slot is the active one
///    and nothing about it has changed.
///
/// The new system then boots on trial: [`ota_mark_boot_good`] confirms it
/// (moving `last_good` and both floors), and `ota_boot_validate` rolls the whole
/// slot back if it never is.
///
/// Whoever calls this holds the authority to change the boot record; the
/// installer service in ring 3 does not, and only stages.
pub fn ota_update_switch() -> Result<update::Verified, UpdateError> {
    if SECURE_BOOT_PUBKEY.iter().all(|&b| b == 0) {
        return Err(UpdateError::NoKey);
    }
    let mut work = UPDATE_WORK.try_acquire().ok_or(UpdateError::Busy)?;
    if UNCONFIRMED.load(Ordering::Acquire) != 0 {
        return Err(UpdateError::BootUnconfirmed);
    }

    // The slow part, on a snapshot of the record and WITHOUT the BOOTMETA lock:
    // hashing and copying a kernel on FAT takes long, and `MetaRmw` is a spin
    // lock that sys-wdt's confirmation takes at a higher priority.
    let snapshot = ota_read_boot_meta();
    let slot = pure::ota_inactive_slot_pure(snapshot.active_slot);
    let dev = update::Device {
        platform: Some(ota_current_platform()),
        meta: snapshot,
        max_kernel_size: OTA_MAX_IMAGE_SIZE.min(u32::MAX as usize) as u32,
    };
    let boot = update::BootPaths { kernel: ota_slot_path(slot), kernel_sig: ota_sig_path(slot) };

    let mut store = FatStore::new();
    let mut buf = [0u8; OTA_RECV_BUF_SIZE];
    let v = update::switch(&mut store, &dev, &SECURE_BOOT_PUBKEY, &boot, &mut work, &mut buf)
        .map_err(UpdateError::Switch)?;

    // The record: read again under the lock, and decided again. If the record
    // moved while the kernel was being copied (a rollback, an install), the
    // pure switch sees the new state and refuses what no longer fits.
    let _g = MetaRmw::take();
    let mut meta = ota_read_boot_meta();
    ota_switch_pure(&mut meta, v.slot, &v.set())
        .map_err(|r| UpdateError::Switch(update::SwitchError::Refused(update::refusal_of(r))))?;
    ota_write_boot_meta(&meta);
    ota_apply_meta(&meta);
    let back = ota_read_boot_meta();
    if back.active_slot != meta.active_slot || back.sec_epoch_a != meta.sec_epoch_a
        || back.sec_epoch_b != meta.sec_epoch_b
    {
        return Err(UpdateError::Record);
    }
    azos_drv_sys::kprintln!(
        "[OTA] System update: slot {} (epoch {}, fw {}) switched to; reboot to apply, it confirms after the boot is good",
        ota_slot_char(v.slot), v.sec_epoch, v.fw_version);
    Ok(v)
}

/// Withdraw the signed set of `slot` (its marker), for an install that puts a
/// kernel into the slot without one: the files left there are the previous
/// system's, and nothing may treat them as a set. The record side is
/// [`ota_kernel_install_pure`], which zeroes the slot's epoch.
pub fn ota_unstage_slot(slot: u8) -> Result<(), update::IoErr> {
    update::unstage(&mut FatStore::new(), slot)
}

/// What [`ota_install_boot_set`] decided for this boot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BootSetOutcome {
    /// The running slot holds no signed set (a kernel-only install, or one that
    /// never had a set): the files of the volume's root are the system's.
    RootFiles,
    /// The running slot's set is in force: `files` names of it now resolve to
    /// the set's directory.
    Set { slot: u8, sec_epoch: u32, files: usize },
    /// BOOTMETA says the slot holds a set of that epoch and the directory does
    /// not hold it, or holds one that does not verify. The root files stay,
    /// which are not this kernel's: the boot must not be confirmed.
    Refused { slot: u8, why: update::Refusal },
}

/// Resolve the running slot's files: the first thing the boot does once the
/// volume is mounted, before the configuration, the topology or any image is
/// read.
///
/// The running slot is the one BOOTMETA names active as it stands at boot (the
/// boot's own validation moves it only for the next boot), read here without
/// counting the boot. A slot with a signed set ([`update::boot_set`]) gets its
/// names installed in the VFS as the root overlay; any other leaves the
/// volume's root as the system.
pub fn ota_install_boot_set() -> BootSetOutcome {
    let meta = ota_read_boot_meta();
    let Some(mut work) = UPDATE_WORK.try_acquire() else {
        // Nothing else runs before the boot has installed the set.
        return BootSetOutcome::Refused { slot: meta.active_slot, why: update::Refusal::Io(update::Io::Read) };
    };
    let mut store = FatStore::new();
    match update::boot_set(&mut store, &meta, &SECURE_BOOT_PUBKEY, &mut work) {
        Ok(None) => BootSetOutcome::RootFiles,
        Ok(Some(set)) => {
            let files = set.names().count();
            if azos_fs::vfs_set_root_overlay(set.dir, set.names()) {
                BootSetOutcome::Set { slot: meta.active_slot, sec_epoch: set.sec_epoch, files }
            } else {
                BootSetOutcome::Refused { slot: meta.active_slot, why: update::Refusal::Format }
            }
        }
        Err(why) => BootSetOutcome::Refused { slot: meta.active_slot, why },
    }
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

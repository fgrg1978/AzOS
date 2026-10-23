// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Pure OTA logic — no FS, no drivers, no `azos_*` deps beyond `azos_crypto`.
//!
//! Everything in this module is deterministic, side-effect-free, and host-
//! testable. The kernel re-exports these from `lib.rs` and layers the
//! FAT32 + UART side effects on top.
//!
//! Keep this file free of drivers and file systems so the host test crate
//! (`tests/host/ota-tests/`) and the installer service can `#[path]`-include
//! it directly, beside `update.rs`: the delta section at the end reads and
//! hashes through `crate::update`'s `Source` and `Store` and `azos_crypto`'s
//! SHA-256, which every includer already links for `update.rs`.

// SC-1..SC-10 — the safety coding standard rules.
//
// All indexing in this module is preceded by a length check or operates
// on stack-allocated fixed-size buffers passed in by the caller. The
// parser/serializer pair is covered by 27 host-side tests (OT01) including
// fuzz-style garbage and oversize inputs. Indexing-slicing warnings here
// are not actionable bugs; refactoring to `.get()`/`.copy_from_slice()`
// would not improve safety, only obscure intent. We accept the lint.
#![allow(clippy::indexing_slicing)]

use azos_crypto::sha256::Sha256;

use crate::update::{
    set_dir, IoErr, Manifest, Refusal, Source, Store, MANIFEST_MAX, MARKER, MAX_PARTS, MSG_MAX, NAME_LEN,
    PATH_MAX,
};

// ── On-wire OTA header constants ───────────────────────────────────────────

/// Magic bytes identifying an OTA transfer: "ROTA".
pub const OTA_MAGIC: [u8; 4] = *b"ROTA";

/// Current header format version.
pub const OTA_HEADER_VERSION: u32 = 1;

/// Size of the OTA on-wire header in bytes.
pub const OTA_HEADER_SIZE: usize = 24;

// NOTE: the acceptance limit itself deliberately does NOT live here.
//
// It comes from Kconfig (`OTA_MAX_IMAGE_SIZE_MB`) via `azos_limits`, and
// this module must stay dependency-free so `tests/host/ota-tests/` can
// `#[path]`-include it (see the module header). So the limit is defined in
// `lib.rs` as `OTA_MAX_IMAGE_SIZE` and passed into `ota_validate_header`
// as a parameter instead of being read from a global here.

// ── Platform IDs ───────────────────────────────────────────────────────────

pub const OTA_PLATFORM_QEMU:    u8 = 0;
pub const OTA_PLATFORM_VF2:     u8 = 1;
pub const OTA_PLATFORM_K1:      u8 = 2;

// ── Flags ──────────────────────────────────────────────────────────────────

pub const OTA_FLAG_COMPRESSED: u8 = 0x01;

// ── Slot identifiers ───────────────────────────────────────────────────────

pub const SLOT_A: u8 = 0;
pub const SLOT_B: u8 = 1;
/// OT04 — immutable recovery slot. Never overwritten by OTA. U-Boot falls
/// back to it when both A and B fail to load. Kernel-side helpers can
/// query it (verify, signature check) but `ota_inactive_slot_pure()`
/// never returns SLOT_R — OTA writes always target A or B.
///
/// `BootMeta::active_slot`/`last_good` CAN hold `SLOT_R` (serialized as
/// `"r"`), and two independent paths steer the *next* boot at it:
///
/// * The **CRC** chain in `kernel/src/boot/ota.rs`, when neither the active slot
///   nor `last_good` passes its CRC. That one is still dormant: it needs
///   `image_size_r`/`image_crc_r` populated in BOOTMETA and nothing writes
///   them (R is factory-flashed), so `ota_verify_slot(SLOT_R)` answers
///   `false` every time.
/// * The **secure-boot** fall (owner decision 99,
///   `secure_boot_steer_to_recovery`), which is NOT dormant: it verifies R by
///   Ed25519 signature rather than by BOOTMETA CRC, precisely so it does not
///   depend on the `_r` fields nobody populates — and so an attacker cannot
///   deny recovery by writing a bogus `image_size_r`.
///
/// So a running kernel can genuinely have `active_slot == SLOT_R`. Label it
/// with `ota_slot_char` below; do not spell it as an A/B ternary.
pub const SLOT_R: u8 = 2;

/// One-character slot label for console lines: `'A'`, `'B'`, `'R'`, `'?'`.
///
/// Owner decision 99 made `SLOT_R` reachable as the **active** slot — secure
/// boot steers the next boot at recovery when the running slot fails
/// verification — and every log site in the tree spelled the label as
/// `if slot == SLOT_A { 'A' } else { 'B' }`, so a board genuinely running R
/// would have announced itself as B on every line. A log that names the wrong
/// slot is worse than no log: it sends whoever reads it to the wrong file.
///
/// An unrecognised code prints `'?'` rather than falling back to a real slot,
/// for the same reason.
///
/// Sites that label an OTA *write target* are deliberately left alone: that
/// value comes from `ota_inactive_slot_pure`, which never returns `SLOT_R`.
#[must_use]
pub fn ota_slot_char(slot: u8) -> char {
    match slot {
        SLOT_A => 'A',
        SLOT_B => 'B',
        SLOT_R => 'R',
        _      => '?',
    }
}

// ── Header struct + parse/encode/validate ──────────────────────────────────

/// Parsed OTA header (24 bytes, on-wire only — NOT stored on disk).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OtaHeader {
    pub header_version: u32,
    pub image_size:     u32,
    pub image_crc32:    u32,
    pub fw_version:     u32,
    pub platform_id:    u8,
    pub flags:          u8,
}

/// Parse an OTA header from a 24-byte buffer.
///
/// Returns `None` if the magic or header version is wrong.
#[must_use]
pub fn ota_parse_header(buf: &[u8]) -> Option<OtaHeader> {
    if buf.len() < OTA_HEADER_SIZE { return None; }
    if buf[0..4] != OTA_MAGIC { return None; }

    let header_version = get_u32(buf, 4);
    if header_version != OTA_HEADER_VERSION { return None; }

    Some(OtaHeader {
        header_version,
        image_size:  get_u32(buf, 8),
        image_crc32: get_u32(buf, 12),
        fw_version:  get_u32(buf, 16),
        platform_id: buf[20],
        flags:       buf[21],
    })
}

/// Validate an OTA header against the running platform.
///
/// `max_image_size` is the acceptance ceiling; callers in the kernel pass
/// `crate::OTA_MAX_IMAGE_SIZE` (from Kconfig `OTA_MAX_IMAGE_SIZE_MB`). It is a
/// parameter rather than a module constant so this file stays dependency-free
/// for the host test crate — see the module header.
#[must_use]
pub fn ota_validate_header(h: &OtaHeader, platform: u8, max_image_size: usize) -> bool {
    if h.platform_id != platform { return false; }
    // Reject zero-size: previously accepted, then the kernel wrote a
    // 0-byte .TMP, computed CRC over nothing (=0) and either silently
    // succeeded with no firmware or left a stale .TMP for next attempt.
    if h.image_size == 0 { return false; }
    if h.image_size as usize > max_image_size { return false; }
    if h.flags & OTA_FLAG_COMPRESSED != 0 { return false; } // not yet supported
    true
}

/// Encode an OTA header into a 24-byte buffer.
pub fn ota_encode_header(h: &OtaHeader, out: &mut [u8]) {
    if out.len() < OTA_HEADER_SIZE { return; }
    out[0..4].copy_from_slice(&OTA_MAGIC);
    put_u32(out, 4,  h.header_version);
    put_u32(out, 8,  h.image_size);
    put_u32(out, 12, h.image_crc32);
    put_u32(out, 16, h.fw_version);
    out[20] = h.platform_id;
    out[21] = h.flags;
    out[22] = 0; // reserved
    out[23] = 0;
}

// ── Boot metadata struct + serialize/parse ─────────────────────────────────

/// Parsed boot metadata from `/fat/BOOTMETA`.
///
/// Contains slot selection + per-slot CRC/size/version for verification.
/// The .BIN files on disk are raw kernel binaries (no OTA header).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BootMeta {
    pub active_slot:  u8,    // 0=A, 1=B, 2=R
    pub boot_count:   u32,
    pub last_good:    u8,    // 0=A, 1=B, 2=R
    pub fw_version_a: u32,
    pub fw_version_b: u32,
    /// OT04 — firmware version recorded for the recovery slot. Nothing at
    /// runtime writes this today (R is factory-flashed, never OTA-written —
    /// see `SLOT_R` doc above); it stays 0 unless some future factory/
    /// flashing tool populates it. A 0 value keeps `slot_size`-gated
    /// verification (`ota_verify_slot`) from ever treating R as a
    /// candidate — see `image_size_r`.
    pub fw_version_r: u32,
    pub image_size_a: u32,   // payload size in bytes
    pub image_size_b: u32,
    /// OT04 — payload size recorded for the recovery slot. `ota_verify_slot`
    /// short-circuits to `false` whenever this is 0, which is exactly the
    /// state of every BOOTMETA on disk today (nothing populates it) — R is
    /// schema-representable but not yet a practical boot candidate.
    pub image_size_r: u32,
    pub image_crc_a:  u32,   // CRC-32 of raw binary
    pub image_crc_b:  u32,
    /// OT04 — CRC-32 of `/fat/KERN_R.BIN`, recorded for the recovery slot.
    pub image_crc_r:  u32,
    /// OT03 anti-rollback floor — incoming firmware whose `fw_version` is
    /// strictly less than this value MUST be rejected. Bumped to
    /// `slot_auth_version(active)` (NOT `slot_version`) whenever a boot is
    /// marked good — see that field's doc for why. Old firmware (signed
    /// with the same key) cannot replace newer firmware.
    pub min_fw_version: u32,
    /// Ed25519-AUTHENTICATED firmware version for slot A/B — the value
    /// bound into the signed manifest (`crates/core/crypto/src/ed25519.rs`) of
    /// the image that currently occupies the slot, or 0 if the slot was
    /// last installed without a verified signature.
    ///
    /// **Why this exists separately from `fw_version_a`/`fw_version_b`**
    /// (U09-4 / U11-4 / security finding #10): those fields used to be set
    /// straight from the OTA wire header's `fw_version` — sender-chosen,
    /// UNSIGNED — and `ota_mark_boot_good_pure` bumped `min_fw_version`
    /// from them. A peer sending `fw_version = 0xFFFFFFFF` on an install
    /// that was never cryptographically verified (dev/unenforced builds)
    /// therefore PINNED the anti-rollback floor at `u32::MAX` on the next
    /// good-boot, permanently rejecting every legitimate future update.
    ///
    /// The floor must only ever advance from a version this device
    /// actually verified a signature for. `fw_version_a`/`fw_version_b`
    /// stay as sender-reported values for `ota status` display (which was
    /// always their only real job); this pair is the one
    /// `ota_mark_boot_good_pure` reads.
    pub authenticated_fw_version_a: u32,
    pub authenticated_fw_version_b: u32,
    /// Whole-system update: the `sec_epoch` of the signed manifest
    /// (`crate::update`) whose system set occupies slot A / B, or 0 when the
    /// slot holds a kernel that was installed on its own (the ROTA path) and
    /// so carries no authenticated epoch. Written only by
    /// [`ota_switch_pure`], from a manifest whose signature verified.
    pub sec_epoch_a: u32,
    pub sec_epoch_b: u32,
    /// The anti-rollback floor of the whole system, in epochs: a manifest
    /// whose `sec_epoch` is below it is refused. Advances to the active
    /// slot's [`BootMeta::slot_sec_epoch`] when a boot is confirmed
    /// ([`ota_mark_boot_good_pure`]), never at the switch: a set that has not
    /// booted well must not pin the floor, or one bad update that was rolled
    /// back would also forbid the good one that follows it.
    pub min_sec_epoch: u32,
    /// Owner decision, 2026-09-19 — slots that failed **secure-boot
    /// verification** and must therefore never be *selected*. One bit per
    /// slot, `1 << SLOT_x`.
    ///
    /// Set by the boot gate on an enforced build after it verifies every slot
    /// present on the volume, not only the active one. Cleared for a slot when
    /// an OTA install promotes a freshly verified image into it.
    ///
    /// **What this closes.** `ota_boot_validate_pure` rolls back to
    /// `last_good` after `max_attempts` failed boots, and rollback used to be
    /// unconditional: an attacker who writes a payload into the inactive slot
    /// and then induces a boot loop gets the payload selected, because the
    /// rollback never asked whether the slot it was falling back to is signed.
    ///
    /// **What this does NOT close.** F1, the confused deputy — U-Boot picks
    /// the slot from a file the kernel does not authenticate, so an attacker
    /// whose payload is already *executing* never runs this code at all. That
    /// is closable only in the loader; see
    /// `project-security-audit-unit2c-secureboot-vfs`. This field hardens the
    /// OTA/rollback path and nothing beyond it.
    ///
    /// Advisory like the rest of BOOTMETA: the file is attacker-writable, so
    /// clearing a bit is trivial for anyone who can write the volume. It
    /// defends the *accident* and the remote-OTA attacker, not the one with
    /// the USB port — for whom the signature check itself is the defence.
    pub bad_slots: u8,
}

impl BootMeta {
    #[must_use]
    pub const fn default() -> Self {
        BootMeta {
            active_slot:  SLOT_A,
            boot_count:   0,
            last_good:    SLOT_A,
            fw_version_a: 0,
            fw_version_b: 0,
            fw_version_r: 0,
            image_size_a: 0,
            image_size_b: 0,
            image_size_r: 0,
            image_crc_a:  0,
            image_crc_b:  0,
            image_crc_r:  0,
            min_fw_version: 0,
            authenticated_fw_version_a: 0,
            authenticated_fw_version_b: 0,
            sec_epoch_a: 0,
            sec_epoch_b: 0,
            min_sec_epoch: 0,
            bad_slots:    0,
        }
    }

    /// Bit position of `slot` in [`BootMeta::bad_slots`].
    ///
    /// An unrecognised slot code maps to no bit at all (`0`), so a corrupt
    /// BOOTMETA cannot brand a real slot by accident — and, symmetrically,
    /// `mark_slot_bad` on garbage is a no-op rather than a wild shift.
    #[must_use]
    const fn slot_bad_bit(slot: u8) -> u8 {
        match slot {
            SLOT_A => 1 << SLOT_A,
            SLOT_B => 1 << SLOT_B,
            SLOT_R => 1 << SLOT_R,
            _      => 0,
        }
    }

    /// Has `slot` been recorded as failing secure-boot verification?
    #[must_use]
    pub const fn slot_is_bad(&self, slot: u8) -> bool {
        let bit = Self::slot_bad_bit(slot);
        bit != 0 && (self.bad_slots & bit) != 0
    }

    /// Record `slot` as unfit for selection.
    pub const fn mark_slot_bad(&mut self, slot: u8) {
        self.bad_slots |= Self::slot_bad_bit(slot);
    }

    /// Clear `slot`'s verdict — an OTA install has put a freshly verified
    /// image there, so the old one's failure no longer describes it.
    pub const fn clear_slot_bad(&mut self, slot: u8) {
        self.bad_slots &= !Self::slot_bad_bit(slot);
    }

    /// Get the stored CRC for a given slot.
    #[must_use]
    pub fn slot_crc(&self, slot: u8) -> u32 {
        match slot {
            SLOT_A => self.image_crc_a,
            SLOT_R => self.image_crc_r,
            _      => self.image_crc_b,
        }
    }

    /// Get the stored size for a given slot.
    #[must_use]
    pub fn slot_size(&self, slot: u8) -> u32 {
        match slot {
            SLOT_A => self.image_size_a,
            SLOT_R => self.image_size_r,
            _      => self.image_size_b,
        }
    }

    /// Get the stored firmware version for a given slot. DISPLAY ONLY —
    /// sender-reported, unauthenticated. See [`BootMeta::slot_auth_version`]
    /// for the value any security decision must use instead.
    #[must_use]
    pub fn slot_version(&self, slot: u8) -> u32 {
        match slot {
            SLOT_A => self.fw_version_a,
            SLOT_R => self.fw_version_r,
            _      => self.fw_version_b,
        }
    }

    /// Get the Ed25519-AUTHENTICATED firmware version for a given slot (0
    /// if the slot's current occupant was never signature-verified). This
    /// is what [`ota_mark_boot_good_pure`] advances `min_fw_version` from —
    /// see [`BootMeta::authenticated_fw_version_a`] for why. `SLOT_R` has no
    /// authenticated-version field (the recovery slot is factory-flashed
    /// and OTA never writes it, same reasoning as `image_size_r`); reads as
    /// 0, same as an unverified A/B slot.
    #[must_use]
    pub fn slot_auth_version(&self, slot: u8) -> u32 {
        match slot {
            SLOT_A => self.authenticated_fw_version_a,
            SLOT_B => self.authenticated_fw_version_b,
            _      => 0,
        }
    }
}

impl BootMeta {
    /// The epoch of the system set in `slot` (0 for R, and for a slot whose
    /// occupant was never installed from a signed manifest).
    #[must_use]
    pub fn slot_sec_epoch(&self, slot: u8) -> u32 {
        match slot {
            SLOT_A => self.sec_epoch_a,
            SLOT_B => self.sec_epoch_b,
            _      => 0,
        }
    }
}

/// Is a staged kernel image refused for its signature before it replaces
/// anything? A signature that is present and does not verify (`failed`)
/// always is. An image with no usable signature (not `verified`, not
/// `failed`) is when the build requires one (`sig_required`: the
/// `secure-boot-enforced` feature, or Kconfig `OTA_SIG_MANDATORY`).
#[must_use]
pub const fn ota_install_refused_pure(verified: bool, failed: bool, sig_required: bool) -> bool {
    !verified && (failed || sig_required)
}

/// Compute which slot we'd write a new image to (the inactive one).
#[must_use]
pub fn ota_inactive_slot_pure(active: u8) -> u8 {
    if active == SLOT_A { SLOT_B } else { SLOT_A }
}

// ── Boot validation FSM (pure) ─────────────────────────────────────────────
//
// The whole sequence, with the default `max_attempts` of 3 (owner decision
// 2026-09-28). `boot_count` is the running slot's consecutive boots that were
// never confirmed (`ota_mark_boot_good`, after 30 s of uptime); each boot
// writes its own +1 before anything can crash.
//
//   new image in B, last_good = A:
//     boots 1-3 on B     count 1, 2, 3                        Normal
//     boot 4             count 4 > 3 -> active = A, count = 1  RolledBack
//                        (A gets a fresh budget; NOT safe mode)
//     boots 5-6 on A     count 2, 3                            Normal
//     boot 7             count 4 > 3, last_good == active      Exhausted
//                        -> SAFE MODE (count kept, not reset)
//   one image only (last_good == active from the start):
//     boots 1-3          count 1, 2, 3                         Normal
//     boot 4             count 4                               Exhausted -> SAFE MODE
//   last_good failed secure boot (`bad_slots`): boot 4       RollbackRefused -> SAFE MODE
//
// Safe mode (`kernel/src/boot/ota.rs`, `boot_count_loaded`) holds every actuator,
// starts no ring-3 program, keeps the console and OTA alive and does NOT
// confirm the boot, so the count keeps climbing on every later boot and the
// device stays in safe mode until an OTA install writes a new active slot with
// `boot_count = 0`. An orderly reboot or power-off (`sys_reboot`,
// `sys_shutdown`, the shell's `reboot`/`shutdown`) voids its own boot's +1
// ([`ota_void_boot_pure`]) instead of counting as a crash, in safe mode too.
//
// Before 2026-09-28 the "rollback" of boot 4 with last_good == active reset
// the count to 1 onto the same slot, forever: the device crash-looped with
// the recovery decision armed one boot in four and nothing acting on it.

/// Maximum consecutive unconfirmed boots of one slot before the rollback or,
/// with nothing to roll back to, safe mode. Also the recovery decision's
/// boot-loop threshold (`recovery::RECOVERY_BOOT_LOOP_THRESHOLD`), so the two
/// cannot disagree on which boot is the exhausted one.
pub const OTA_DEFAULT_MAX_BOOT_ATTEMPTS: u32 = 3;

/// Outcome of a boot-validation tick.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BootValidateOutcome {
    /// Normal boot — `boot_count` has been incremented.
    Normal,
    /// Boot loop detected — slot rolled back to `last_good`, whose count
    /// restarts at 1 (this boot).
    RolledBack,
    /// Boot loop detected with nothing to roll back to: `last_good` IS the
    /// active slot. `boot_count` is NOT reset (it stays `> max_attempts` and
    /// keeps climbing); the kernel enters safe mode.
    Exhausted,
    /// Boot loop detected, and `last_good` is recorded in
    /// [`BootMeta::bad_slots`] as having failed secure-boot verification. The
    /// active slot is left ALONE: falling back into an unsigned image is the
    /// attack the rollback would otherwise complete. `boot_count` is still
    /// incremented, so the condition stays visible instead of being reset.
    RollbackRefused,
}

/// Boot-validation pure FSM.
///
/// Mutates `meta` in place: increments `boot_count`, and if the count
/// exceeds `max_attempts`, rolls the active slot back to `last_good`
/// and resets the count to 1 (this very boot attempt) — unless there is no
/// other slot to go to ([`BootValidateOutcome::Exhausted`]) or it failed
/// secure boot ([`BootValidateOutcome::RollbackRefused`]); both keep the
/// count. [`ota_boot_exhausted`] is true after exactly those two.
pub fn ota_boot_validate_pure(meta: &mut BootMeta, max_attempts: u32) -> BootValidateOutcome {
    // `saturating_add`, not `+`. `boot_count` is parsed from BOOTMETA by
    // `parse_u32_simple`, which saturates at `u32::MAX` rather than rejecting
    // an oversized field — so `boot_count=4294967295` is a value that survives
    // a round trip through the parser and lands here intact.
    //
    // That file lives on the FAT volume, on a removable card: writing it is a
    // thing an attacker with a card reader can do, and `ota_boot_validate()`
    // runs unconditionally on every boot.
    // With `overflow-checks = true` and `panic = "abort"`, a plain `+= 1`
    // there is not a wrong number — it is a panic, and a panic on this
    // codebase is a full board reset. One 12-byte edit would put the robot in
    // an unrecoverable reset loop that no rollback path ever gets to run.
    //
    // Saturating instead keeps the value at `u32::MAX`, which is `>
    // max_attempts` and therefore takes the rollback branch below — the
    // correct response to "this slot has failed to boot an absurd number of
    // times" and the one that actually restores the device.
    meta.boot_count = meta.boot_count.saturating_add(1);
    if meta.boot_count > max_attempts {
        // Owner decision, 2026-09-19: a rollback must not SELECT a slot that
        // failed secure-boot verification.
        //
        // This branch used to be unconditional, and that is the concrete hole:
        // an attacker who can write the inactive slot (remote OTA, or a
        // half-finished install) and then induce `max_attempts` failed boots
        // got their image selected, because the rollback never asked whether
        // the slot it was falling back to is signed. The verification verdict
        // already exists — the boot gate computes it for every present slot —
        // it simply was not consulted here.
        //
        // Refusing is strictly better than rolling back into it: the image
        // currently in RAM is at least running, and on an enforced build it is
        // running *because it verified*. `boot_count` is still bumped, so the
        // condition stays visible in BOOTMETA and on the console rather than
        // being silently reset.
        if meta.slot_is_bad(meta.last_good) {
            return BootValidateOutcome::RollbackRefused;
        }
        // Owner decision 2026-09-28: rolling back onto the slot that is
        // already running is not a rollback. Resetting the count here made a
        // single-image device (or one already rolled back) crash-loop forever.
        if meta.last_good == meta.active_slot {
            return BootValidateOutcome::Exhausted;
        }
        meta.active_slot = meta.last_good;
        meta.boot_count = 1;
        BootValidateOutcome::RolledBack
    } else {
        BootValidateOutcome::Normal
    }
}

/// The step a file replacement (open, write, close, flush) failed at, from
/// what the last three answered: `written` the bytes the write took (negative:
/// refused) of the `len` asked, `closed` the close's code (the FAT32 proxy
/// writes the entry and the data there), `synced` whether the volume's flush
/// succeeded. The earliest step that failed is the one named: a flush cannot
/// make durable what the write or the close did not take.
pub fn ota_replace_verdict_pure(written: isize, len: usize, closed: i32, synced: bool) -> Result<(), &'static str> {
    if written < 0 || written as usize != len {
        return Err("write");
    }
    if closed != 0 {
        return Err("close (the write to the volume)");
    }
    if !synced {
        return Err("sync (the flush to the medium)");
    }
    Ok(())
}

/// Are the running slot's boot attempts exhausted after validation, i.e.
/// did [`ota_boot_validate_pure`] answer `Exhausted` or `RollbackRefused`?
/// A rollback resets the count to 1, so it never is.
#[must_use]
pub fn ota_boot_exhausted(meta: &BootMeta, max_attempts: u32) -> bool {
    meta.boot_count > max_attempts
}

/// Void one boot's own unconfirmed mark — pure form. For an ORDERLY reboot or
/// power-off before the boot was confirmed (owner decision 2026-09-28): a
/// deliberate shutdown is not a crash, so it must not count toward the
/// rollback or safe mode. It does not CONFIRM the boot either — that would
/// move `last_good` and the anti-rollback floor for an image that has not
/// run its 30 s.
///
/// Compare-and-decrement: `this_slot`/`this_count` are what THIS boot wrote.
/// Only when the record still says exactly that is `boot_count` taken back to
/// `this_count - 1`. Anything else means the record moved since (an OTA
/// install switched the slot and wrote `boot_count = 0`, or the boot was
/// marked good) and is left alone; returns whether it wrote.
pub fn ota_void_boot_pure(meta: &mut BootMeta, this_slot: u8, this_count: u32) -> bool {
    if this_count == 0 || meta.active_slot != this_slot || meta.boot_count != this_count {
        return false;
    }
    meta.boot_count = this_count - 1;
    true
}

// REQ-014
/// Mark the current boot as good — pure form.
///
/// Resets `boot_count` to zero and copies `active_slot` into `last_good`.
/// OT03: also bumps `min_fw_version` to the version of the now-confirmed
/// active slot — incoming firmware older than this can no longer overwrite
/// us (anti-rollback floor advances monotonically).
pub fn ota_mark_boot_good_pure(meta: &mut BootMeta) {
    meta.boot_count = 0;
    meta.last_good = meta.active_slot;
    // `slot_auth_version`, NOT `slot_version` — see `authenticated_fw_version_a`
    // doc comment (U09-4/U11-4/security finding #10). Reads 0 for a slot that
    // was never signature-verified, so an unauthenticated install can never
    // advance the floor, no matter what version it claimed on the wire.
    let active_ver = meta.slot_auth_version(meta.active_slot);
    if active_ver > meta.min_fw_version {
        meta.min_fw_version = active_ver;
    }
    // The same for the system epoch: only the epoch of a set that booted and
    // was confirmed moves the floor.
    let active_epoch = ota_confirmed_epoch(meta);
    if active_epoch > meta.min_sec_epoch {
        meta.min_sec_epoch = active_epoch;
    }
}

// REQ-014
/// The epoch of the set that is being confirmed: the one value
/// `ota_mark_boot_good` hands to the hardware floor (`crate::floor::commit`).
/// It is the active slot's own epoch, recorded when that set was installed
/// from a signed manifest, and never BOOTMETA's `min_sec_epoch`: that field is
/// whatever the FAT volume holds (CRC only, no secret), and the hardware floor
/// only ever goes up, so a forged value there would lock updates out for good.
#[must_use]
pub fn ota_confirmed_epoch(meta: &BootMeta) -> u32 {
    meta.slot_sec_epoch(meta.active_slot)
}

// REQ-006
/// OT03 anti-rollback gate (pure form).
///
/// Returns `true` if an incoming firmware with `incoming_version` is allowed
/// to be installed given the current `min_fw_version` floor. The floor is
/// advanced by `ota_mark_boot_good_pure`. A version equal to the floor is
/// allowed (re-installing the same version is a valid recovery operation);
/// only strictly older versions are rejected.
#[must_use]
pub fn ota_check_rollback_pure(incoming_version: u32, min_fw_version: u32) -> bool {
    incoming_version >= min_fw_version
}

// ── Whole-system update: the switch (pure) ─────────────────────────────────

/// What a verified, fully staged system set says about itself: the numbers
/// [`ota_switch_pure`] records. Every field comes from the signed manifest or
/// from bytes hashed against it (`crate::update::Verified`), never from the
/// sender.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StagedSet {
    /// The kernel's firmware version, bound into the signed manifest.
    pub fw_version: u32,
    /// The manifest's `sec_epoch`.
    pub sec_epoch: u32,
    /// Length of the kernel image in bytes.
    pub kernel_size: u32,
    /// CRC-32 of the kernel image (what `ota_verify_slot` checks at boot).
    pub kernel_crc: u32,
}

/// Why the switch was refused. Each is a refusal to touch BOOTMETA: the
/// record is unchanged.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SwitchRefusal {
    /// The set was staged into a slot that is not the inactive one: it would
    /// replace the system that is running.
    NotInactive,
    /// The active slot is not the last confirmed one: an earlier switch is
    /// still on trial, and the inactive slot is the system a rollback returns
    /// to. Staging over it, or switching to it, would destroy the way back.
    TrialPending,
    /// `sec_epoch` is below the floor.
    BelowEpochFloor { epoch: u32, floor: u32 },
    /// The kernel's version is below `min_fw_version`.
    BelowFwFloor { fw_version: u32, floor: u32 },
}

/// Is a system update allowed to target the inactive slot now? The checks that
/// need only BOOTMETA and the manifest's numbers, shared by the stager
/// (`crate::update::admit`, early refusal) and the switch (authoritative).
pub fn ota_update_allowed_pure(
    meta: &BootMeta,
    fw_version: u32,
    sec_epoch: u32,
) -> Result<u8, SwitchRefusal> {
    if meta.active_slot != meta.last_good {
        return Err(SwitchRefusal::TrialPending);
    }
    if !cfg!(feature = "update-canary-epoch") && !ota_check_rollback_pure(sec_epoch, meta.min_sec_epoch) {
        return Err(SwitchRefusal::BelowEpochFloor { epoch: sec_epoch, floor: meta.min_sec_epoch });
    }
    if !ota_check_rollback_pure(fw_version, meta.min_fw_version) {
        return Err(SwitchRefusal::BelowFwFloor { fw_version, floor: meta.min_fw_version });
    }
    Ok(ota_inactive_slot_pure(meta.active_slot))
}

/// The one step that makes a staged system set the one to boot: a single
/// BOOTMETA record. `target` must be the inactive slot; the record then names
/// it active with a fresh boot count, and carries the slot's kernel numbers
/// and its epoch. Nothing else moves: the userspace images, topology and
/// config of the set are in the slot's own directory, so they switch with it,
/// and a rollback to `last_good` returns all of them.
///
/// `min_fw_version`, `min_sec_epoch` and `last_good` are NOT touched: they move
/// only when the boot is confirmed ([`ota_mark_boot_good_pure`]).
pub fn ota_switch_pure(meta: &mut BootMeta, target: u8, set: &StagedSet) -> Result<(), SwitchRefusal> {
    let inactive = ota_update_allowed_pure(meta, set.fw_version, set.sec_epoch)?;
    if target != inactive {
        return Err(SwitchRefusal::NotInactive);
    }
    meta.active_slot = target;
    meta.boot_count = 0;
    // The verdict about the slot's previous occupant no longer describes it.
    meta.clear_slot_bad(target);
    if target == SLOT_A {
        meta.fw_version_a = set.fw_version;
        meta.authenticated_fw_version_a = set.fw_version;
        meta.sec_epoch_a = set.sec_epoch;
        meta.image_size_a = set.kernel_size;
        meta.image_crc_a = set.kernel_crc;
    } else {
        meta.fw_version_b = set.fw_version;
        meta.authenticated_fw_version_b = set.fw_version;
        meta.sec_epoch_b = set.sec_epoch;
        meta.image_size_b = set.kernel_size;
        meta.image_crc_b = set.kernel_crc;
    }
    Ok(())
}

/// The record a kernel-only install (the OTA receiver: one image, no set) leaves
/// behind in `target`'s slot, and the slot becomes the active one with a fresh
/// boot count. `authenticated` is the version a signature verified (`None` for
/// an install that did not verify: the slot's authenticated version stays what
/// it last verified to, so such an install can never move the floor).
///
/// The slot's `sec_epoch` is ZEROED. The epoch says "this slot holds a signed
/// whole-system set of that epoch"; the install has just put a different kernel
/// beside whatever set the slot had, and the set no longer belongs to it. The
/// boot resolves a slot's userspace images, topology and configuration through
/// its set only when its epoch is non-zero, and the confirmation raises
/// `min_sec_epoch` from the active slot's epoch, so a stale epoch would both
/// load the old set under the new kernel and advance the floor to a number no
/// confirmed system ever had.
pub fn ota_kernel_install_pure(
    meta: &mut BootMeta,
    target: u8,
    fw_version: u32,
    authenticated: Option<u32>,
    image_size: u32,
    image_crc: u32,
) {
    meta.active_slot = target;
    meta.boot_count = 0;
    // The verdict about the slot's previous occupant no longer describes it.
    meta.clear_slot_bad(target);
    // The canary keeps the old epoch, as the install did before the epoch was
    // reset: `kernel_install_resets_the_epoch` must turn red with it.
    let epoch = if cfg!(feature = "update-canary-stale-epoch") { None } else { Some(0) };
    if target == SLOT_A {
        meta.fw_version_a = fw_version;
        if let Some(v) = authenticated {
            meta.authenticated_fw_version_a = v;
        }
        if let Some(e) = epoch {
            meta.sec_epoch_a = e;
        }
        meta.image_size_a = image_size;
        meta.image_crc_a = image_crc;
    } else {
        meta.fw_version_b = fw_version;
        if let Some(v) = authenticated {
            meta.authenticated_fw_version_b = v;
        }
        if let Some(e) = epoch {
            meta.sec_epoch_b = e;
        }
        meta.image_size_b = image_size;
        meta.image_crc_b = image_crc;
    }
}

// ── BOOTMETA persistence record (OT02.B — power-loss-safe) ────────────────

/// On-disk BOOTMETA record carrying a sequence number + content CRC.
///
/// Two physical files (`/fat/BOOTMETA.A` + `/fat/BOOTMETA.B`) hold these.
/// Each `ota_write_boot_meta` writes the new record to the older file with
/// `seq` incremented; `ota_read_boot_meta` picks the file with the higher
/// `seq` whose CRC validates. A power-loss during the write of one file
/// leaves the other intact, so we never lose more than one generation.
///
/// The CRC is computed over the serialized text of *all* fields that
/// precede the `crc=` line. Recomputing on read must match the value
/// stored there, otherwise the record is rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BootMetaRecord {
    pub meta: BootMeta,
    pub seq:  u32,
}

impl BootMetaRecord {
    /// Empty record (used as sentinel when neither persistent file is valid).
    #[must_use]
    pub const fn default() -> Self {
        BootMetaRecord { meta: BootMeta::default(), seq: 0 }
    }
}

/// Pick the better of two parsed records (or one valid + one missing).
///
/// Higher `seq` wins; ties favour `a`. `None` means "this file was
/// missing or its CRC didn't match".
#[must_use]
pub fn ota_pick_boot_meta_record(
    a: Option<BootMetaRecord>,
    b: Option<BootMetaRecord>,
) -> Option<BootMetaRecord> {
    match (a, b) {
        (Some(ra), Some(rb)) => {
            if rb.seq > ra.seq { Some(rb) } else { Some(ra) }
        }
        (Some(r), None) | (None, Some(r)) => Some(r),
        (None, None) => None,
    }
}

/// Choose which slot the next write should go to.
///
/// Writes to the *older* (or invalid) of the two so a power-loss during
/// the write keeps the newer record intact for read on next boot.
/// Returns `SLOT_A` if A should be overwritten, else `SLOT_B`.
#[must_use]
pub fn ota_pick_meta_write_slot(
    a: Option<BootMetaRecord>,
    b: Option<BootMetaRecord>,
) -> u8 {
    match (a, b) {
        // If one is missing, write there first.
        (None, _) => SLOT_A,
        (_, None) => SLOT_B,
        // Both valid — write to the lower-seq one.
        (Some(ra), Some(rb)) => if ra.seq <= rb.seq { SLOT_A } else { SLOT_B },
    }
}

/// Compute the next sequence number from the current best record.
///
/// `None` (no valid record yet) → 1. Otherwise current.seq + 1, saturating
/// at `u32::MAX` (2^32 OTAs is far beyond device lifetime).
#[must_use]
pub fn ota_next_seq(current: Option<BootMetaRecord>) -> u32 {
    current.map_or(1, |r| r.seq.saturating_add(1))
}

/// Parse a BOOTMETA record (with embedded CRC) from INI-style text.
///
/// Returns `None` if the embedded CRC line is missing or doesn't match
/// the recomputed CRC over the prefix (everything above `crc=`).
#[must_use]
pub fn parse_boot_meta_record(data: &[u8]) -> Option<BootMetaRecord> {
    // Locate the `crc=` line. The CRC covers everything strictly before
    // the start of `crc=` (and the optional newline immediately above it
    // is included in the prefix — exactly what serialize writes).
    let crc_start = find_crc_line_start(data)?;
    let prefix = &data[..crc_start];

    // Extract crc value
    let val_start = crc_start + b"crc=".len();
    let mut val_end = val_start;
    while val_end < data.len() && data[val_end] != b'\n' && data[val_end] != b'\r' {
        val_end += 1;
    }
    let crc_field = &data[val_start..val_end];
    let stored_crc = parse_u32_hex_or_dec(crc_field);

    let actual_crc = crc32(prefix);
    if actual_crc != stored_crc {
        return None;
    }

    // Now parse the prefix as a normal BootMeta + extract seq=
    let meta = parse_boot_meta(prefix);
    let seq = parse_seq_line(prefix);

    Some(BootMetaRecord { meta, seq })
}

/// Serialize a BOOTMETA record (with embedded CRC line). Returns bytes written.
///
/// Layout:
/// ```text
/// seq=<N>
/// active_slot=...
/// boot_count=...
/// ...
/// crc=0x<8 hex>
/// ```
/// The `crc=` field covers every byte from the start of the buffer up to
/// (but not including) `crc=` itself. On read, recomputing this CRC and
/// comparing against the stored value detects torn writes.
pub fn serialize_boot_meta_record(rec: &BootMetaRecord, buf: &mut [u8]) -> usize {
    let mut pos = 0;
    pos += write_kv_u32(buf, pos, b"seq=", rec.seq);
    pos += serialize_boot_meta(&rec.meta, &mut buf[pos..]);

    // CRC32 covers `seq=N\n` + body — everything written so far.
    let prefix_crc = crc32(&buf[..pos]);

    pos += write_kv_u32_hex(buf, pos, b"crc=", prefix_crc);
    pos
}

// ── Helpers private to BOOTMETA record ─────────────────────────────────────

/// Find the start offset of a line beginning with `crc=` in the buffer.
fn find_crc_line_start(data: &[u8]) -> Option<usize> {
    // Linear scan looking for either start-of-buffer or '\n' followed by "crc=".
    let needle = b"crc=";
    let mut i = 0;
    while i < data.len() {
        // At buffer start OR right after a newline, check for "crc=".
        let at_line_start = i == 0 || data[i - 1] == b'\n';
        if at_line_start && i + needle.len() <= data.len() && &data[i..i + needle.len()] == needle {
            return Some(i);
        }
        i += 1;
    }
    None
}

/// Pull the integer following `seq=` from the prefix. 0 if absent.
fn parse_seq_line(data: &[u8]) -> u32 {
    let needle = b"seq=";
    let mut i = 0;
    while i < data.len() {
        let at_line_start = i == 0 || data[i - 1] == b'\n';
        if at_line_start && i + needle.len() <= data.len() && &data[i..i + needle.len()] == needle {
            let start = i + needle.len();
            let mut end = start;
            while end < data.len() && data[end] != b'\n' && data[end] != b'\r' {
                end += 1;
            }
            return parse_u32_simple(&data[start..end]);
        }
        i += 1;
    }
    0
}

/// Parse a u32 from text that may be hex (`0x1234`) or decimal.
fn parse_u32_hex_or_dec(s: &[u8]) -> u32 {
    let mut s = s;
    while !s.is_empty() && (s[0] == b' ' || s[0] == b'\t') { s = &s[1..]; }
    if s.len() >= 2 && s[0] == b'0' && (s[1] == b'x' || s[1] == b'X') {
        let mut v = 0u32;
        let hex = &s[2..];
        for &b in hex {
            let d = match b {
                b'0'..=b'9' => u32::from(b - b'0'),
                b'a'..=b'f' => u32::from(b - b'a' + 10),
                b'A'..=b'F' => u32::from(b - b'A' + 10),
                _ => break,
            };
            v = v.wrapping_mul(16).wrapping_add(d);
        }
        v
    } else {
        parse_u32_simple(s)
    }
}

fn write_kv_u32_hex(buf: &mut [u8], pos: usize, key: &[u8], val: u32) -> usize {
    // 2 ("0x") + 8 hex digits + nul/newline
    let mut hex_buf = [0u8; 10];
    hex_buf[0] = b'0';
    hex_buf[1] = b'x';
    for i in 0..8 {
        let nibble = ((val >> ((7 - i) * 4)) & 0xF) as u8;
        hex_buf[2 + i] = if nibble < 10 { b'0' + nibble } else { b'a' + nibble - 10 };
    }
    write_kv(buf, pos, key, &hex_buf)
}

// ── CRC-32 (IEEE 802.3) ────────────────────────────────────────────────────

/// Compute CRC-32 of a byte slice (bit-at-a-time, no table).
#[must_use]
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xEDB8_8320;
            } else {
                crc >>= 1;
            }
        }
    }
    !crc
}

/// Incremental CRC-32 state for streaming computation.
pub struct Crc32State {
    crc: u32,
}

impl Default for Crc32State {
    fn default() -> Self { Self::new() }
}

impl Crc32State {
    /// Create a new CRC-32 accumulator.
    #[must_use]
    pub const fn new() -> Self {
        Crc32State { crc: 0xFFFF_FFFF }
    }

    /// Feed a chunk of data into the CRC.
    pub fn update(&mut self, data: &[u8]) {
        for &byte in data {
            self.crc ^= u32::from(byte);
            for _ in 0..8 {
                if self.crc & 1 != 0 {
                    self.crc = (self.crc >> 1) ^ 0xEDB8_8320;
                } else {
                    self.crc >>= 1;
                }
            }
        }
    }

    /// Finalize and return the CRC-32 value.
    #[must_use]
    pub fn finalize(&self) -> u32 {
        !self.crc
    }
}

// ── BOOTMETA INI text serialization ────────────────────────────────────────

/// Parse boot metadata from INI-style text.
#[must_use]
pub fn parse_boot_meta(data: &[u8]) -> BootMeta {
    let mut meta = BootMeta::default();

    let mut i = 0;
    while i < data.len() {
        while i < data.len() && (data[i] == b'\n' || data[i] == b'\r'
                                  || data[i] == b' ' || data[i] == b'\t') {
            i += 1;
        }
        if i >= data.len() { break; }
        if data[i] == b'#' {
            while i < data.len() && data[i] != b'\n' { i += 1; }
            continue;
        }

        let key_start = i;
        while i < data.len() && data[i] != b'=' && data[i] != b'\n' { i += 1; }
        if i >= data.len() || data[i] != b'=' { continue; }
        let key = &data[key_start..i];
        i += 1;

        let val_start = i;
        while i < data.len() && data[i] != b'\n' && data[i] != b'\r' { i += 1; }
        let val = &data[val_start..i];

        if key == b"active_slot" {
            meta.active_slot = parse_slot_char(val);
        } else if key == b"boot_count" {
            meta.boot_count = parse_u32_simple(val);
        } else if key == b"last_good" {
            meta.last_good = parse_slot_char(val);
        } else if key == b"fw_version_a" {
            meta.fw_version_a = parse_u32_simple(val);
        } else if key == b"fw_version_b" {
            meta.fw_version_b = parse_u32_simple(val);
        } else if key == b"fw_version_r" {
            meta.fw_version_r = parse_u32_simple(val);
        } else if key == b"image_size_a" {
            meta.image_size_a = parse_u32_simple(val);
        } else if key == b"image_size_b" {
            meta.image_size_b = parse_u32_simple(val);
        } else if key == b"image_size_r" {
            meta.image_size_r = parse_u32_simple(val);
        } else if key == b"image_crc_a" {
            meta.image_crc_a = parse_u32_simple(val);
        } else if key == b"image_crc_b" {
            meta.image_crc_b = parse_u32_simple(val);
        } else if key == b"image_crc_r" {
            meta.image_crc_r = parse_u32_simple(val);
        } else if key == b"min_fw_version" {
            meta.min_fw_version = parse_u32_simple(val);
        } else if key == b"auth_fw_version_a" {
            meta.authenticated_fw_version_a = parse_u32_simple(val);
        } else if key == b"auth_fw_version_b" {
            meta.authenticated_fw_version_b = parse_u32_simple(val);
        } else if key == b"sec_epoch_a" {
            meta.sec_epoch_a = parse_u32_simple(val);
        } else if key == b"sec_epoch_b" {
            meta.sec_epoch_b = parse_u32_simple(val);
        } else if key == b"min_sec_epoch" {
            meta.min_sec_epoch = parse_u32_simple(val);
        } else if key == b"bad_slots" {
            // `parse_u32_simple` saturates at u32::MAX rather than rejecting,
            // so truncate to the low byte instead of `as u8` on a saturated
            // value — and mask to the three defined slots, so a hand-edited
            // `bad_slots=255` cannot set bits that no `slot_bad_bit` ever
            // produces and that nothing would ever clear.
            const ALL_SLOT_BITS: u32 = (1 << SLOT_A) | (1 << SLOT_B) | (1 << SLOT_R);
            meta.bad_slots = (parse_u32_simple(val) & ALL_SLOT_BITS) as u8;
        }
    }

    meta
}

/// Serialize boot metadata to INI text. Returns bytes written.
pub fn serialize_boot_meta(meta: &BootMeta, buf: &mut [u8]) -> usize {
    let mut pos = 0;

    pos += write_kv(buf, pos, b"active_slot=", slot_char(meta.active_slot));
    pos += write_kv_u32(buf, pos, b"boot_count=", meta.boot_count);
    pos += write_kv(buf, pos, b"last_good=", slot_char(meta.last_good));
    pos += write_kv_u32(buf, pos, b"fw_version_a=", meta.fw_version_a);
    pos += write_kv_u32(buf, pos, b"fw_version_b=", meta.fw_version_b);
    pos += write_kv_u32(buf, pos, b"fw_version_r=", meta.fw_version_r);
    pos += write_kv_u32(buf, pos, b"image_size_a=", meta.image_size_a);
    pos += write_kv_u32(buf, pos, b"image_size_b=", meta.image_size_b);
    pos += write_kv_u32(buf, pos, b"image_size_r=", meta.image_size_r);
    pos += write_kv_u32(buf, pos, b"image_crc_a=", meta.image_crc_a);
    pos += write_kv_u32(buf, pos, b"image_crc_b=", meta.image_crc_b);
    pos += write_kv_u32(buf, pos, b"image_crc_r=", meta.image_crc_r);
    pos += write_kv_u32(buf, pos, b"min_fw_version=", meta.min_fw_version);
    pos += write_kv_u32(buf, pos, b"auth_fw_version_a=", meta.authenticated_fw_version_a);
    pos += write_kv_u32(buf, pos, b"auth_fw_version_b=", meta.authenticated_fw_version_b);
    pos += write_kv_u32(buf, pos, b"sec_epoch_a=", meta.sec_epoch_a);
    pos += write_kv_u32(buf, pos, b"sec_epoch_b=", meta.sec_epoch_b);
    pos += write_kv_u32(buf, pos, b"min_sec_epoch=", meta.min_sec_epoch);
    pos += write_kv_u32(buf, pos, b"bad_slots=", u32::from(meta.bad_slots));

    pos
}

// ── Internal helpers ───────────────────────────────────────────────────────

/// Encode a `SLOT_*` constant as its one-letter BOOTMETA text form.
/// Anything that is not `SLOT_A`/`SLOT_R` is written as `"b"` — this
/// matches the pre-OT04 fallback (only A/B existed) for any value that
/// isn't one of the three defined slots.
fn slot_char(slot: u8) -> &'static [u8] {
    match slot {
        SLOT_A => b"a",
        SLOT_R => b"r",
        _      => b"b",
    }
}

/// Parse a one-letter slot code (`"a"`/`"b"`/`"r"`, case-insensitive) into
/// a `SLOT_*` constant. Anything else (including the field being absent,
/// which is how every pre-OT04 BOOTMETA reads today) defaults to `SLOT_A`,
/// exactly as before this field gained a third possible value.
fn parse_slot_char(val: &[u8]) -> u8 {
    if val == b"b" || val == b"B" {
        SLOT_B
    } else if val == b"r" || val == b"R" {
        SLOT_R
    } else {
        SLOT_A
    }
}

#[inline]
pub(crate) fn get_u32(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}

#[inline]
pub(crate) fn put_u32(buf: &mut [u8], off: usize, v: u32) {
    let b = v.to_le_bytes();
    buf[off]     = b[0];
    buf[off + 1] = b[1];
    buf[off + 2] = b[2];
    buf[off + 3] = b[3];
}

fn write_kv(buf: &mut [u8], pos: usize, key: &[u8], val: &[u8]) -> usize {
    let needed = key.len() + val.len() + 1;
    if pos + needed > buf.len() { return 0; }
    buf[pos..pos + key.len()].copy_from_slice(key);
    let p = pos + key.len();
    buf[p..p + val.len()].copy_from_slice(val);
    buf[p + val.len()] = b'\n';
    needed
}

fn write_kv_u32(buf: &mut [u8], pos: usize, key: &[u8], val: u32) -> usize {
    let mut num_buf = [0u8; 10];
    let num_len = fmt_u32_to_buf(val, &mut num_buf);
    write_kv(buf, pos, key, &num_buf[..num_len])
}

fn fmt_u32_to_buf(mut val: u32, buf: &mut [u8; 10]) -> usize {
    if val == 0 {
        buf[0] = b'0';
        return 1;
    }
    let mut i = 10;
    while val > 0 {
        i -= 1;
        // val % 10 always fits in u8 (0..=9).
        #[allow(clippy::cast_possible_truncation)]
        let digit = (val % 10) as u8;
        buf[i] = b'0' + digit;
        val /= 10;
    }
    let len = 10 - i;
    buf.copy_within(i..10, 0);
    len
}

fn parse_u32_simple(s: &[u8]) -> u32 {
    let mut v = 0u32;
    for &b in s {
        if !b.is_ascii_digit() { break; }
        v = v.saturating_mul(10).saturating_add(u32::from(b - b'0'));
    }
    v
}

// ── Delta updates: the whole-system bundle as a patch of the running one ────
//
// A whole-system update arrives as a bundle: the signed manifest, then the
// parts' bytes in table order (`crate::update`). Most of a new bundle is the
// running one: the same userspace images, the same topology, a kernel that moved
// in a few places. The running slot's set directory holds exactly the bytes of
// the bundle it was staged from (the marker IS the manifest and the part files
// are the parts, in the order the manifest lists them), so the new bundle can be
// sent as a patch against it.
//
// The patch is applied by READING, not by writing: [`DeltaSource`] is the new
// bundle seen through a [`Source`], and the stager copies it into the inactive
// slot exactly as it copies a bundle that came whole. So nothing about the
// atomic update changes: the signed manifest is still verified before any byte
// is written, every part is still hashed against it as it is copied and again as
// it is read back, the marker is still written last, and the switch is still one
// BOOTMETA record. The patch cannot make an update that the signature does not
// cover, and a patch applied to the wrong base, or damaged, makes a bundle the
// stager refuses. What the patch adds is the early refusal, below, and the
// fact that only what changed has to cross the wire.
//
// Wire form (little endian):
//
//    0   4  magic "AZDL"           op, at 80..:
//    4   2  format = 1               COPY    01  src_off u32  len u32
//    6   2  flags = 0                INSERT  02  len u32  bytes
//    8   4  base length
//   12  32  SHA-256 of the base    The ops run to the end of the delta. They
//   44   4  result length          produce the result in order; COPY takes
//   48  32  SHA-256 of the result  `len` bytes of the base at `src_off`,
//   80  ..  ops                    INSERT takes its own bytes. No op is empty.
//
// [`DeltaSource::open`] refuses before the stager has written a byte: a base
// that is not the one the patch was made against (`base length`, `SHA-256 of the
// base`), a patch whose ops do not run exactly to the result's length or reach
// outside the base, and a result whose SHA-256 is not the one the head says. The
// last check reads the whole patch and the base once, writing nothing, so a
// corrupted patch is found while the inactive slot is still untouched. The head
// is not signed (the result's authority is the manifest the stager verifies),
// so these checks are about not wearing the flash, and about saying WHY.

/// "AZDL": AzOS delta.
pub const DELTA_MAGIC: [u8; 4] = *b"AZDL";
/// The delta format this build reads.
pub const DELTA_FORMAT: u16 = 1;
/// Bytes of the delta head.
pub const DELTA_HEAD_LEN: usize = 80;
/// Bytes of a COPY op: tag, source offset, length.
pub const DELTA_COPY_LEN: usize = 9;
/// Bytes of an INSERT op before its data: tag, length.
pub const DELTA_INSERT_LEN: usize = 5;
/// The COPY op tag.
pub const DELTA_OP_COPY: u8 = 1;
/// The INSERT op tag.
pub const DELTA_OP_INSERT: u8 = 2;

/// Why a delta was refused. The first check that failed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DeltaError {
    /// Shorter than its own head.
    Truncated,
    /// Not a delta, or one of a format this build does not read.
    Format,
    /// The result is larger than the device accepts, or empty.
    TooLarge,
    /// The base is not as long as the delta was made against.
    BaseLength,
    /// The base is not the bytes the delta was made against.
    BaseHash,
    /// An op is malformed or reaches outside the base, or the ops do not end
    /// exactly at the result's length and the delta's end.
    Op,
    /// The ops produce something other than the result the head names.
    ResultHash,
    /// Reading the base or the delta failed.
    Io,
}

impl DeltaError {
    /// The refusal as a number for a status word or a decision record: 1 for
    /// the first, in the order of the variants.
    pub const fn code(self) -> u64 {
        match self {
            DeltaError::Truncated => 1,
            DeltaError::Format => 2,
            DeltaError::TooLarge => 3,
            DeltaError::BaseLength => 4,
            DeltaError::BaseHash => 5,
            DeltaError::Op => 6,
            DeltaError::ResultHash => 7,
            DeltaError::Io => 8,
        }
    }
}

fn delta_u32(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

/// Read exactly `buf.len()` bytes at `off`.
fn read_exact<R: Source>(src: &mut R, off: u64, buf: &mut [u8]) -> Result<(), DeltaError> {
    let mut done = 0;
    while done < buf.len() {
        match src.read(off + done as u64, &mut buf[done..]) {
            Ok(0) | Err(_) => return Err(DeltaError::Io),
            Ok(n) => done += n,
        }
    }
    Ok(())
}

/// Where the reader is in the result and in the op it is inside.
#[derive(Clone, Copy)]
struct DeltaCursor {
    /// Result offset of the next byte.
    pos: u64,
    /// Offset in the delta of the next op's tag.
    dpos: u64,
    /// The current op reads from the delta (INSERT) rather than the base.
    insert: bool,
    /// Offset the current op's next byte is read from (base or delta).
    src: u64,
    /// Bytes the current op still yields.
    left: u32,
}

impl DeltaCursor {
    const START: DeltaCursor = DeltaCursor { pos: 0, dpos: DELTA_HEAD_LEN as u64, insert: false, src: 0, left: 0 };
}

/// The new bundle: `base` with `delta` applied, read through [`Source`].
///
/// Reads are streamed, nothing of the result is held. A read at an offset below
/// the last one starts over from the head, so the stager (which reads the
/// bundle once, in order) never pays for it.
pub struct DeltaSource<B: Source, D: Source> {
    base: B,
    delta: D,
    base_len: u64,
    result_len: u32,
    cur: DeltaCursor,
}

impl<B: Source, D: Source> DeltaSource<B, D> {
    /// Check `delta` against `base` and return the result as a [`Source`].
    ///
    /// `max_len` is the largest result the device accepts; `buf` is the scratch
    /// the two checks that read everything use (any size; larger is faster).
    /// Nothing is written anywhere.
    pub fn open(mut base: B, mut delta: D, max_len: u32, buf: &mut [u8]) -> Result<Self, DeltaError> {
        if buf.is_empty() {
            return Err(DeltaError::Io);
        }
        if delta.len() < DELTA_HEAD_LEN as u64 {
            return Err(DeltaError::Truncated);
        }
        let mut head = [0u8; DELTA_HEAD_LEN];
        read_exact(&mut delta, 0, &mut head)?;
        if head[..4] != DELTA_MAGIC || u16::from_le_bytes([head[4], head[5]]) != DELTA_FORMAT || head[6..8] != [0, 0] {
            return Err(DeltaError::Format);
        }
        let base_len = delta_u32(&head, 8);
        let result_len = delta_u32(&head, 44);
        if result_len == 0 || result_len > max_len {
            return Err(DeltaError::TooLarge);
        }
        if base.len() != u64::from(base_len) {
            return Err(DeltaError::BaseLength);
        }

        // The base is the one the delta was made against.
        let mut sha = Sha256::new();
        let mut off = 0u64;
        while off < u64::from(base_len) {
            let want = buf.len().min((u64::from(base_len) - off) as usize);
            read_exact(&mut base, off, &mut buf[..want])?;
            sha.update(&buf[..want]);
            off += want as u64;
        }
        if !cfg!(feature = "update-canary-hash") && sha.finalize()[..] != head[12..44] {
            return Err(DeltaError::BaseHash);
        }

        // The ops make exactly the result the head names.
        let mut s = DeltaSource { base, delta, base_len: u64::from(base_len), result_len, cur: DeltaCursor::START };
        let mut sha = Sha256::new();
        let mut off = 0u64;
        while off < u64::from(result_len) {
            let n = s.read_at(off, buf)?;
            if n == 0 {
                return Err(DeltaError::Op);
            }
            sha.update(&buf[..n]);
            off += n as u64;
        }
        if s.cur.dpos != s.delta.len() || s.cur.left != 0 {
            return Err(DeltaError::Op);
        }
        if !cfg!(feature = "update-canary-hash") && sha.finalize()[..] != head[48..80] {
            return Err(DeltaError::ResultHash);
        }
        s.cur = DeltaCursor::START;
        Ok(s)
    }

    /// Load the next op into the cursor.
    fn fetch(&mut self) -> Result<(), DeltaError> {
        if self.cur.dpos >= self.delta.len() {
            return Err(DeltaError::Op);
        }
        let mut tag = [0u8; 1];
        read_exact(&mut self.delta, self.cur.dpos, &mut tag)?;
        let (insert, src, len, used) = match tag[0] {
            DELTA_OP_COPY => {
                let mut b = [0u8; DELTA_COPY_LEN - 1];
                read_exact(&mut self.delta, self.cur.dpos + 1, &mut b)?;
                let (src, len) = (u64::from(delta_u32(&b, 0)), delta_u32(&b, 4));
                if src + u64::from(len) > self.base_len {
                    return Err(DeltaError::Op);
                }
                (false, src, len, DELTA_COPY_LEN as u64)
            }
            DELTA_OP_INSERT => {
                let mut b = [0u8; DELTA_INSERT_LEN - 1];
                read_exact(&mut self.delta, self.cur.dpos + 1, &mut b)?;
                let len = delta_u32(&b, 0);
                let at = self.cur.dpos + DELTA_INSERT_LEN as u64;
                if at + u64::from(len) > self.delta.len() {
                    return Err(DeltaError::Op);
                }
                (true, at, len, DELTA_INSERT_LEN as u64 + u64::from(len))
            }
            _ => return Err(DeltaError::Op),
        };
        if len == 0 || self.cur.pos + u64::from(len) > u64::from(self.result_len) {
            return Err(DeltaError::Op);
        }
        self.cur.insert = insert;
        self.cur.src = src;
        self.cur.left = len;
        self.cur.dpos += used;
        Ok(())
    }

    fn read_at(&mut self, off: u64, buf: &mut [u8]) -> Result<usize, DeltaError> {
        if off >= u64::from(self.result_len) {
            return Ok(0);
        }
        if off < self.cur.pos {
            self.cur = DeltaCursor::START;
        }
        // Skip to `off` without reading what is skipped.
        while self.cur.pos < off {
            if self.cur.left == 0 {
                self.fetch()?;
            }
            let take = u64::from(self.cur.left).min(off - self.cur.pos) as u32;
            self.cur.src += u64::from(take);
            self.cur.left -= take;
            self.cur.pos += u64::from(take);
        }
        let mut n = 0;
        while n < buf.len() && self.cur.pos < u64::from(self.result_len) {
            if self.cur.left == 0 {
                self.fetch()?;
            }
            let take = (self.cur.left as usize).min(buf.len() - n);
            if self.cur.insert {
                read_exact(&mut self.delta, self.cur.src, &mut buf[n..n + take])?;
            } else {
                read_exact(&mut self.base, self.cur.src, &mut buf[n..n + take])?;
            }
            self.cur.src += take as u64;
            self.cur.left -= take as u32;
            self.cur.pos += take as u64;
            n += take;
        }
        Ok(n)
    }
}

impl<B: Source, D: Source> Source for DeltaSource<B, D> {
    fn len(&self) -> u64 {
        u64::from(self.result_len)
    }

    fn read(&mut self, off: u64, buf: &mut [u8]) -> Result<usize, IoErr> {
        if off > u64::from(self.result_len) {
            return Err(IoErr::Io);
        }
        // A patch that changed under us fails here, as a short or malformed
        // read; one that changed but still decodes is caught by the stager's
        // hash of every part against the signed manifest.
        self.read_at(off, buf).map_err(|_| IoErr::Io)
    }
}

/// The bundle the running slot was staged from, read back from its set
/// directory: the marker (the manifest) and then the part files, in the order
/// the manifest lists them. This is the base of a [`DeltaSource`].
///
/// `Store` reads are sequential, so the stream stays open between reads; a read
/// ahead skips forward by reading and a read behind (or in another file)
/// reopens. The generator of the delta keeps its copies in ascending order where
/// it can for that reason.
///
/// The base is only read. Its manifest is verified under the trusted key when it
/// is opened, so a set directory somebody else wrote is not a base. A base that
/// is not the one a delta was made against is no danger either: the delta
/// refuses it ([`DeltaError::BaseHash`]), and a delta that produced a wrong
/// bundle would still fail the stager's checks against the signed manifest.
pub struct SetBase<S: Store> {
    store: S,
    dir: &'static [u8],
    /// The marker's name, then the parts', NUL padded.
    names: [[u8; NAME_LEN]; MAX_PARTS + 1],
    sizes: [u32; MAX_PARTS + 1],
    files: usize,
    total: u64,
    /// The open stream: handle, index of its file, bytes consumed from it.
    open: Option<(u32, usize, u64)>,
}

impl<S: Store> SetBase<S> {
    /// The set directory of `slot` as a base. `mb` and `msg` are the manifest
    /// buffers (`Work` keeps its own private to the module, so the caller lends
    /// these). Fails with the refusal the manifest earns, or `NotStaged` if the
    /// slot holds no set: a slot a kernel-only install wrote has none, and the
    /// update to it must come whole.
    pub fn open(
        mut store: S,
        slot: u8,
        key: &[u8; azos_crypto::sig::KEY_LEN],
        mb: &mut [u8; MANIFEST_MAX],
        msg: &mut [u8; MSG_MAX],
    ) -> Result<Self, Refusal> {
        let dir = set_dir(slot).ok_or(Refusal::NotInactive)?;
        let mut path = [0u8; PATH_MAX];
        let h = store.open_read(join(&mut path, dir, MARKER)).map_err(|_| Refusal::NotStaged)?;
        let mut n = 0;
        let read = loop {
            if n == mb.len() {
                break Err(Refusal::Format);
            }
            match store.read(h, &mut mb[n..]) {
                Ok(0) => break Ok(()),
                Ok(k) => n += k,
                Err(_) => break Err(Refusal::NotStaged),
            }
        };
        let _ = store.close(h);
        read?;
        if Manifest::wire_len(&mb[..n]).ok_or(Refusal::Format)? != n {
            return Err(Refusal::Truncated);
        }
        let m = Manifest::parse(&mb[..n], key, msg)?;

        let mut b = SetBase {
            store,
            dir,
            names: [[0; NAME_LEN]; MAX_PARTS + 1],
            sizes: [0; MAX_PARTS + 1],
            files: 1,
            total: n as u64,
            open: None,
        };
        b.names[0][..MARKER.len()].copy_from_slice(MARKER);
        b.sizes[0] = n as u32;
        for p in m.parts() {
            b.names[b.files] = p.name;
            b.sizes[b.files] = p.size;
            b.total += u64::from(p.size);
            b.files += 1;
        }
        Ok(b)
    }

    fn close(&mut self) {
        if let Some((h, _, _)) = self.open.take() {
            let _ = self.store.close(h);
        }
    }

    /// Bytes from `off` out of the one file `off` is in.
    fn read_one(&mut self, off: u64, buf: &mut [u8]) -> Result<usize, IoErr> {
        let mut start = 0u64;
        let mut i = 0;
        while i < self.files && off >= start + u64::from(self.sizes[i]) {
            start += u64::from(self.sizes[i]);
            i += 1;
        }
        if i == self.files {
            return Ok(0);
        }
        let at = off - start;

        if self.open.is_some_and(|(_, f, pos)| f != i || pos > at) {
            self.close();
        }
        if self.open.is_none() {
            let mut path = [0u8; PATH_MAX];
            let n = self.names[i].iter().position(|&c| c == 0).unwrap_or(NAME_LEN);
            let h = self.store.open_read(join(&mut path, self.dir, &self.names[i][..n]))?;
            self.open = Some((h, i, 0));
        }
        let Some((h, _, mut pos)) = self.open else { return Err(IoErr::Io) };
        let mut skip = [0u8; 64];
        let r = (|| {
            while pos < at {
                let want = skip.len().min((at - pos) as usize);
                match self.store.read(h, &mut skip[..want])? {
                    0 => return Err(IoErr::Io),
                    k => pos += k as u64,
                }
            }
            let want = buf.len().min((u64::from(self.sizes[i]) - at) as usize);
            let k = self.store.read(h, &mut buf[..want])?;
            pos += k as u64;
            // A file shorter than the manifest says is not the base.
            if k == 0 { Err(IoErr::Io) } else { Ok(k) }
        })();
        match r {
            Ok(k) => {
                self.open = Some((h, i, pos));
                Ok(k)
            }
            Err(e) => {
                self.close();
                Err(e)
            }
        }
    }
}

impl<S: Store> Drop for SetBase<S> {
    fn drop(&mut self) {
        self.close();
    }
}

impl<S: Store> Source for SetBase<S> {
    fn len(&self) -> u64 {
        self.total
    }

    fn read(&mut self, off: u64, buf: &mut [u8]) -> Result<usize, IoErr> {
        if off > self.total {
            return Err(IoErr::Io);
        }
        let mut n = 0;
        while n < buf.len() {
            match self.read_one(off + n as u64, &mut buf[n..])? {
                0 => break,
                k => n += k,
            }
        }
        Ok(n)
    }
}

fn join<'a>(out: &'a mut [u8; PATH_MAX], dir: &[u8], name: &[u8]) -> &'a [u8] {
    out[..dir.len()].copy_from_slice(dir);
    out[dir.len()] = b'/';
    out[dir.len() + 1..dir.len() + 1 + name.len()].copy_from_slice(name);
    &out[..dir.len() + 1 + name.len()]
}

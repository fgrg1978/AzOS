// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Pure OTA logic — no FS, no drivers, no `azos_*` deps.
//!
//! Everything in this module is deterministic, side-effect-free, and host-
//! testable. The kernel re-exports these from `lib.rs` and layers the
//! FAT32 + UART side effects on top.
//!
//! Keep this file dependency-free so the host test crate
//! (`tests/host/ota-tests/`) can `#[path]`-include it directly.

// SC-1..SC-10 — the safety coding standard rules.
//
// All indexing in this module is preceded by a length check or operates
// on stack-allocated fixed-size buffers passed in by the caller. The
// parser/serializer pair is covered by 27 host-side tests (OT01) including
// fuzz-style garbage and oversize inputs. Indexing-slicing warnings here
// are not actionable bugs; refactoring to `.get()`/`.copy_from_slice()`
// would not improve safety, only obscure intent. We accept the lint.
#![allow(clippy::indexing_slicing)]

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
    // That file lives on the FAT volume, which `msc_gadget.rs` exports over
    // USB mass storage: writing it is a thing an attacker with the USB port
    // can do, and `ota_boot_validate()` runs unconditionally on every boot.
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
}

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

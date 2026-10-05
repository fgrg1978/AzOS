// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! F18 — Secure boot: Ed25519 signature verification for OTA slots.
//!
//! # Design
//!
//! - The OTA header layout is unchanged — we keep CRC-32 there so old
//!   images still boot, and store Ed25519 signatures as a separate
//!   sidecar file per slot (`/KERN_A.SIG` and `/KERN_B.SIG`, at the FAT32
//!   volume root — same convention `tools/boot.cmd` uses for `KERN_A.BIN`).
//! - The signature file uses the `RSIG` format already provided by
//!   `azos_crypto::ed25519` (`FirmwareSignature`): magic + version
//!   + pubkey + signature + length.
//! - The kernel compares the `pubkey` field against the embedded
//!   trusted `SECURE_BOOT_PUBKEY`. Mismatch → rejected, regardless of
//!   whether the signature itself is mathematically valid.
//! - Missing signature file ⇒ `BootTrust::Unverified` (warning). When
//!   `secure_boot_require_signature()` is true, Unverified becomes
//!   fatal (rollback to `last_good`).
//!
//! # Production vs development
//!
//! - Dev key is embedded at `SECURE_BOOT_PUBKEY` in this file (ALL ZEROS
//!   by default). A production build replaces it via linker override or
//!   an eFuse/OTP read at boot (not implemented here).
//! - Sign images with `tools/sign_ota.py` using the matching private key
//!   (see `tools/gen_dev_key.py`).

use core::sync::atomic::{AtomicU32, Ordering};
use azos_crypto::ct::ct_eq;
use azos_crypto::sha256::Sha256;
use azos_crypto::ed25519::{
    sig_parse_header, sig_verify_manifest,
    ED25519_PUBLIC_KEY_SIZE, ED25519_SIGNATURE_SIZE, SIG_HEADER_SIZE,
};

// ───────────────────────────────────────────────────────────────────────────
// Named constants — no magic numbers.
// ───────────────────────────────────────────────────────────────────────────

/// Length of the Ed25519 public key (bytes).
pub const SECURE_BOOT_PUBKEY_LEN: usize = ED25519_PUBLIC_KEY_SIZE;
/// Length of the Ed25519 signature (bytes).
pub const SECURE_BOOT_SIG_LEN: usize = ED25519_SIGNATURE_SIZE;

/// Historical note (U09-14, closed): this crate used to hold a whole image
/// in a 2 MiB `.bss` buffer (`SECURE_BOOT_MAX_IMAGE_SIZE`) to verify it,
/// because pure Ed25519 signs the raw message and needs it contiguous. That
/// ceiling was smaller than and disconnected from `OTA_MAX_IMAGE_SIZE`
/// (Kconfig), so an image between the two sizes was accepted by the OTA
/// receiver and then unverifiable — `BootTrustReason::ImageTooLargeToVerify`.
///
/// The manifest scheme (see `crates/core/crypto/src/ed25519.rs` module docs)
/// signs `{fw_version, payload_size, sha256(image)}` — 40 fixed bytes —
/// instead of the image itself, so verification now streams the image
/// through [`Sha256`] in [`SECURE_BOOT_READ_CHUNK_SIZE`] chunks
/// (`hash_image_file` below) and never needs it resident. There is exactly
/// one size ceiling left: `OTA_MAX_IMAGE_SIZE`.

/// Slot signature file paths (alongside `KERN_A.BIN` / `KERN_B.BIN`).
///
/// Root-relative, no `/fat` prefix: unlike `crate::OTA_SLOT_A_PATH` (used
/// via the VFS layer, where `/fat` is a *mount point* stripped before
/// lookup), these paths go straight to `fat32_open()` (see
/// `read_sig_file`/`hash_image_file` below), which resolves them directly
/// against the mounted volume — a leading `/fat/` there would be looked
/// up as a literal subdirectory named "fat", which doesn't exist. Real
/// hardware confirms the root-relative convention is correct: `boot.cmd`
/// (`tools/boot.cmd`) loads `BOOTMETA`/`KERN_A.BIN` via `fatload mmc 0:1`
/// with no subdirectory either. Found and fixed 2026-08 by actually
/// booting a signed image in QEMU (D2) instead of trusting this by
/// inspection — with the old `/fat/...` paths, `secure-boot-enforced`
/// could never find the `.SIG` file on a disk laid out the way U-Boot
/// actually expects, and would halt at the fail-closed `loop { wfi() }`
/// on every real boot once that feature was ever turned on.
pub const SECURE_BOOT_SIG_PATH_A: &[u8] = b"/KERN_A.SIG";
pub const SECURE_BOOT_SIG_PATH_B: &[u8] = b"/KERN_B.SIG";
/// OT04 — recovery slot signature (read-only, signed at flash time).
pub const SECURE_BOOT_SIG_PATH_R: &[u8] = b"/KERN_R.SIG";

/// Slot kernel-image paths for direct `fat32_open()` access (see
/// `hash_image_file` below) — root-relative for the same reason as
/// `SECURE_BOOT_SIG_PATH_*` above. Deliberately separate from
/// `crate::OTA_SLOT_A_PATH`/`ota_slot_path()`, which stay `/fat`-prefixed
/// because their callers (`ota_verify_slot` and friends) go through the
/// VFS layer, where that prefix is the mount point, not a literal path
/// component.
pub const SECURE_BOOT_BIN_PATH_A: &[u8] = b"/KERN_A.BIN";
pub const SECURE_BOOT_BIN_PATH_B: &[u8] = b"/KERN_B.BIN";
pub const SECURE_BOOT_BIN_PATH_R: &[u8] = b"/KERN_R.BIN";

/// Root-relative staging paths, for verifying an OTA image *before* it is
/// promoted over the live slot binary.
///
/// Same root-relative convention as `SECURE_BOOT_BIN_PATH_*` above (these go
/// straight to `fat32_open()`), and deliberately separate from
/// `crate::OTA_SLOT_A_TMP_PATH` / `OTA_SLOT_B_TMP_PATH`, which keep the
/// `/fat` mount-point prefix because the OTA receiver reaches them through
/// the VFS layer.
///
/// These exist because verifying *after* promotion is not good enough: the
/// promotion is what destroys the rollback target. `cmd_ota_recv` writes into
/// the inactive slot, which is normally `last_good` — the exact image
/// `ota_boot_validate_pure()` and `ota rollback` fall back to. If a rejected
/// update had already overwritten it, an attacker who can merely *reach* the
/// OTA port would destroy the fallback without ever flipping `active_slot`,
/// turning the next failure of the active slot into an unrecoverable brick on
/// an enforced build. Verifying the `.TMP` leaves `KERN_{A,B}.BIN`
/// byte-identical when the image is refused.
pub const SECURE_BOOT_TMP_PATH_A: &[u8] = b"/KERN_A.TMP";
pub const SECURE_BOOT_TMP_PATH_B: &[u8] = b"/KERN_B.TMP";

/// Return the kernel-image path for a given slot index, for direct
/// `fat32_open()` access — see `SECURE_BOOT_BIN_PATH_*` doc comment.
#[must_use]
fn secure_boot_bin_path(slot: u8) -> &'static [u8] {
    match slot {
        crate::SLOT_A => SECURE_BOOT_BIN_PATH_A,
        crate::SLOT_B => SECURE_BOOT_BIN_PATH_B,
        crate::SLOT_R => SECURE_BOOT_BIN_PATH_R,
        _             => SECURE_BOOT_BIN_PATH_A,
    }
}

/// Return the *staging* (`.TMP`) path for a given slot index, for direct
/// `fat32_open()` access — see `SECURE_BOOT_TMP_PATH_*` doc comment.
///
/// `SLOT_R` has no staging file (the recovery slot is flashed at the factory
/// and OTA never writes it), so it falls through to slot A's path exactly the
/// way `secure_boot_bin_path` handles an out-of-range slot: defensively, not
/// meaningfully. Callers only ever pass `ota_inactive_slot()`, which is A or B.
#[must_use]
pub fn secure_boot_tmp_path(slot: u8) -> &'static [u8] {
    match slot {
        crate::SLOT_B => SECURE_BOOT_TMP_PATH_B,
        _             => SECURE_BOOT_TMP_PATH_A,
    }
}

/// Max size of a signature file on disk (header + slack).
pub const SECURE_BOOT_SIG_FILE_MAX: usize = SIG_HEADER_SIZE + 16;

/// Chunk size used when streaming a slot's kernel image off FAT32 into the
/// SHA-256 hasher (see `hash_image_file`). The manifest scheme signs
/// `sha256(image)`, not the image itself (`crates/core/crypto/src/ed25519.rs`
/// module docs), so this bounds a stack-local chunk buffer only — there is
/// no whole-image buffer to size any more (U09-14). 4 KiB matches the chunk
/// size already used by the OTA receive path (`OTA_CHUNK` in
/// `crates/core/shell/src/lib.rs`).
pub const SECURE_BOOT_READ_CHUNK_SIZE: usize = 4096;

// ───────────────────────────────────────────────────────────────────────────
// Trusted public key.
//
// OT05 — the array contents come from `build.rs`, which reads
// `tools/keys/prod_pub.bin` at compile time (or `$PROD_PUBKEY_PATH`). When
// no prod key file is present, the array is all zeros and the kernel treats
// every signature as Unverified (dev default). To rotate to a real key:
//
//   1. python3 tools/gen_prod_key.py        # writes prod_priv.bin + prod_pub.bin
//   2. cargo clean -p azos_ota          # force build.rs to re-run
//   3. cargo build --release --features qemu
//
// The kernel binary now embeds the real pubkey; signed firmware images
// produced by `tools/sign_ota.py --priv tools/keys/prod_priv.bin` will
// verify, all others will fail with BootTrust::Failed.
// ───────────────────────────────────────────────────────────────────────────

include!(concat!(env!("OUT_DIR"), "/secure_boot_pubkey.rs"));

/// Trusted public key. Override at link time or via OTP in production.
#[no_mangle]
#[link_section = ".secure_boot_pubkey"]
pub static SECURE_BOOT_PUBKEY: [u8; SECURE_BOOT_PUBKEY_LEN] =
    SECURE_BOOT_PUBKEY_BYTES;

// ───────────────────────────────────────────────────────────────────────────
// Enforcement policy.
// ───────────────────────────────────────────────────────────────────────────

/// 0 = dev (warn on missing/bad sig, still boot); 1 = production (refuse to
/// run an unsigned image). Defaulted to 0 in dev builds; release builds with
/// `--features secure-boot-enforced` default this to 1 so a production binary
/// can't ship with sig-enforcement off if someone forgets to flip the runtime
/// flag. Either mode can still be flipped at runtime via the setter below.
#[cfg(not(feature = "secure-boot-enforced"))]
pub static CFG_SECURE_BOOT_REQUIRE_SIG: AtomicU32 = AtomicU32::new(0);
#[cfg(feature = "secure-boot-enforced")]
pub static CFG_SECURE_BOOT_REQUIRE_SIG: AtomicU32 = AtomicU32::new(1);

#[inline]
pub fn secure_boot_require_signature() -> bool {
    CFG_SECURE_BOOT_REQUIRE_SIG.load(Ordering::Relaxed) != 0
}

#[inline]
pub fn secure_boot_set_require_signature(require: bool) {
    CFG_SECURE_BOOT_REQUIRE_SIG.store(u32::from(require), Ordering::Relaxed);
}

/// Is the `secure-boot-enforced` feature compiled into this build?
///
/// This is deliberately NOT `secure_boot_require_signature()`. The two answer
/// different questions and only one of them is safe for a gate that must
/// agree with the boot path:
///
/// * `secure_boot_require_signature()` reads `CFG_SECURE_BOOT_REQUIRE_SIG`,
///   an atomic any caller can flip at runtime via
///   `secure_boot_set_require_signature()`. Advisory / soft callers only.
/// * this function is a pure `cfg!` — it cannot be relaxed at runtime, which
///   is exactly the property `kernel/src/boot/ota.rs`'s boot gate relies on
///   ("Policy is fixed at COMPILE TIME ... never by a runtime flag").
///
/// Any code that decides whether to *install* firmware must use this one, so
/// that it agrees with the gate that later decides whether to *boot* it. If
/// the installer consulted the relaxable runtime flag while the boot gate
/// consulted the feature, an enforced build could be talked into staging an
/// image it will then refuse to boot — which on a device whose only recovery
/// is physical access is a brick, not a refusal.
///
/// Exposed from this crate (rather than each caller writing its own
/// `#[cfg(feature = ...)]`) because the feature lives on `azos_ota`;
/// downstream crates such as `azos_shell` do not declare it, and cargo
/// feature unification means this answers for the whole build.
#[must_use]
pub const fn secure_boot_enforced_at_compile_time() -> bool {
    cfg!(feature = "secure-boot-enforced")
}

// ───────────────────────────────────────────────────────────────────────────
// Boot trust level.
// ───────────────────────────────────────────────────────────────────────────

/// Trust level returned by `secure_boot_verify_slot()`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BootTrust {
    /// Signature present, matches embedded pubkey, passes verification.
    Verified,
    /// No .SIG file found (dev mode). Boot allowed with warning.
    Unverified,
    /// .SIG present but pubkey mismatch or signature verification failed.
    Failed,
}

impl BootTrust {
    #[must_use] 
    pub fn is_bootable(self) -> bool {
        match self {
            BootTrust::Verified   => true,
            BootTrust::Unverified => !secure_boot_require_signature(),
            BootTrust::Failed     => false,
        }
    }

    #[must_use] 
    pub fn as_str(self) -> &'static str {
        match self {
            BootTrust::Verified   => "verified",
            BootTrust::Unverified => "unverified",
            BootTrust::Failed     => "failed",
        }
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Detailed failure reason (diagnostics only).
// ───────────────────────────────────────────────────────────────────────────

/// Fine-grained reason behind a `BootTrust::Unverified` / `BootTrust::Failed`
/// result. This exists purely for console diagnostics at boot (which slot,
/// why) — the pass/fail *decision* is entirely owned by `BootTrust` (and by
/// the caller's own policy for what to do with an `Unverified`/`Failed`
/// result); nothing reads `BootTrustReason` to decide whether to boot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BootTrustReason {
    /// Matches `BootTrust::Verified` — nothing to report.
    Verified,
    /// `SECURE_BOOT_PUBKEY` is all zeros (dev build, no signing key installed).
    NoTrustedKey,
    /// No `.SIG` file found (or unreadable) for this slot.
    SignatureAbsent,
    /// `.SIG` file present but its header is malformed (bad magic/version).
    SignatureMalformed,
    /// `.SIG` file's embedded pubkey doesn't match the trusted `SECURE_BOOT_PUBKEY`.
    PubkeyMismatch,
    /// The slot's kernel image could not be read from disk.
    ImageUnreadable,
    /// The actual streamed length of the image on disk does not match the
    /// `payload_size` bound into the signed manifest. Checked BEFORE the
    /// signature so a truncated/extended file is reported precisely rather
    /// than folded into `SignatureInvalid`.
    PayloadSizeMismatch,
    /// Ed25519 signature verification failed against the image contents.
    SignatureInvalid,
}

impl BootTrustReason {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            BootTrustReason::Verified            => "verified",
            BootTrustReason::NoTrustedKey         => "no trusted signing key embedded (dev build)",
            BootTrustReason::SignatureAbsent      => "signature file absent",
            BootTrustReason::SignatureMalformed   => "signature file malformed",
            BootTrustReason::PubkeyMismatch       => "signature key does not match trusted key",
            BootTrustReason::ImageUnreadable      => "kernel image unreadable from disk",
            BootTrustReason::PayloadSizeMismatch  =>
                "image size on disk does not match the signed manifest's payload_size",
            BootTrustReason::SignatureInvalid     => "signature invalid for image contents",
        }
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Verification.
// ───────────────────────────────────────────────────────────────────────────

/// Return the signature-file path for a given slot index.
#[must_use]
pub fn secure_boot_sig_path(slot: u8) -> &'static [u8] {
    match slot {
        crate::SLOT_A => SECURE_BOOT_SIG_PATH_A,
        crate::SLOT_B => SECURE_BOOT_SIG_PATH_B,
        crate::SLOT_R => SECURE_BOOT_SIG_PATH_R,
        _             => SECURE_BOOT_SIG_PATH_A,
    }
}

/// Read the whole signature-file contents into `out`. Returns length or 0.
///
/// The `.SIG` file on disk is a single `FirmwareSignature` structure
/// followed by arbitrary padding to the next cluster boundary.
fn read_sig_file(path: &[u8], out: &mut [u8]) -> usize {
    use azos_fs::{
        fat32_mount_volume, fat32_open, fat32_read, fat32_close, open_flags,
    };

    let vol = match fat32_mount_volume() {
        Ok(v)  => v,
        Err(_) => return 0,
    };
    let file = match fat32_open(vol, path, open_flags::READ) {
        Ok(f)  => f,
        Err(_) => return 0,
    };
    let n = fat32_read(file, out).unwrap_or(0);
    let _ = fat32_close(file);
    n
}

/// Stream the kernel image at `path` through SHA-256, in
/// `SECURE_BOOT_READ_CHUNK_SIZE` chunks on a small STACK buffer.
///
/// Takes a path rather than a slot index because the same reader has to serve
/// two callers: the boot gate, which verifies the live `KERN_{A,B}.BIN`, and
/// the OTA receiver, which verifies the staged `KERN_{A,B}.TMP` before
/// promoting it (see `SECURE_BOOT_TMP_PATH_*`).
///
/// Returns `(digest, total_len)`, or `None` if the file could not be opened
/// or nothing could be read from it. Unlike the pre-manifest scheme
/// (U09-14), this never needs the whole image resident: the manifest
/// signs `sha256(image)`, not the image itself, so a fixed 4 KiB chunk
/// buffer (stack-local — small enough not to need `.bss`, unlike the old
/// 2 MiB `IMG_BUF`) is all streaming a hash ever needs, at any image size
/// up to `OTA_MAX_IMAGE_SIZE`.
fn hash_image_file(path: &[u8]) -> Option<(azos_crypto::sha256::Digest, u32)> {
    use azos_fs::{
        fat32_mount_volume, fat32_open, fat32_read, fat32_close, open_flags,
    };

    let vol = fat32_mount_volume().ok()?;
    let file = fat32_open(vol, path, open_flags::READ).ok()?;

    let mut hasher = Sha256::new();
    let mut chunk = [0u8; SECURE_BOOT_READ_CHUNK_SIZE];
    let mut total: u32 = 0;
    loop {
        let n = fat32_read(file, &mut chunk).unwrap_or(0);
        if n == 0 {
            break;
        }
        hasher.update(&chunk[..n]);
        total = total.saturating_add(n as u32);
    }
    let _ = fat32_close(file);

    if total == 0 {
        return None;
    }
    Some((hasher.finalize(), total))
}

/// Verify the Ed25519 signature of a slot's kernel image.
///
/// # Behaviour
/// 1. If `SECURE_BOOT_PUBKEY` is all zeros, return `Unverified`
///    (dev build — no signing key installed).
/// 2. Attempt to read `/fat/KERN_{A,B}.SIG` into a local buffer.
/// 3. Parse the header; fail if magic/version wrong.
/// 4. Compare the embedded key in the header against the trusted
///    `SECURE_BOOT_PUBKEY`. Mismatch → `Failed`.
/// 5. Stream the kernel image through SHA-256, verify the Ed25519
///    signature against the signed manifest.
#[must_use]
pub fn secure_boot_verify_slot(slot: u8) -> BootTrust {
    secure_boot_verify_slot_detailed(slot).0
}

/// As [`secure_boot_verify_slot`], but also returns the specific
/// [`BootTrustReason`] behind a non-`Verified` result, for boot-time
/// diagnostics. A thin wrapper over
/// [`secure_boot_verify_image_detailed_ex`] so there is exactly one place
/// the checks are performed.
#[must_use]
pub fn secure_boot_verify_slot_detailed(slot: u8) -> (BootTrust, BootTrustReason) {
    let (t, r, _fw) = secure_boot_verify_image_detailed_ex(
        secure_boot_bin_path(slot),
        secure_boot_sig_path(slot),
    );
    (t, r)
}

/// Verify a *staged* OTA image (`KERN_{A,B}.TMP`) against the signature
/// sidecar its promoted form would be checked against at boot.
///
/// The OTA receiver calls this BEFORE `ota_promote_tmp_to_bin`, so that a
/// refused image never touches the live slot binary — see
/// `SECURE_BOOT_TMP_PATH_*` for why overwriting the inactive slot with an
/// unverified image is itself the attack, independent of `active_slot`.
///
/// Returns the [`BootTrust`]/[`BootTrustReason`] pair AND, when
/// `BootTrust::Verified`, the `fw_version` bound into the signed manifest
/// (0 otherwise). Callers MUST use this returned version — never the
/// unsigned `fw_version` from the OTA wire header — to decide the
/// anti-rollback floor (U09-4 / U11-4 / security finding #10): the wire
/// header is sender-chosen and unauthenticated; this value is not.
#[must_use]
pub fn secure_boot_verify_staged_detailed(slot: u8) -> (BootTrust, BootTrustReason, u32) {
    secure_boot_verify_image_detailed_ex(
        secure_boot_tmp_path(slot),
        secure_boot_sig_path(slot),
    )
}

/// Verify the Ed25519 signature at `sig_path` over the image at `bin_path`,
/// dropping the authenticated `fw_version` — for callers that only need the
/// pass/fail verdict (the boot gate; slots other than the one being
/// installed).
#[must_use]
pub fn secure_boot_verify_image_detailed(
    bin_path: &[u8],
    sig_path: &[u8],
) -> (BootTrust, BootTrustReason) {
    let (t, r, _fw) = secure_boot_verify_image_detailed_ex(bin_path, sig_path);
    (t, r)
}

/// Core verifier. Both root-relative paths use the `fat32_open()` convention
/// — see `SECURE_BOOT_SIG_PATH_*`. Returns the authenticated `fw_version`
/// from the signed manifest (0 when the result is not `Verified`).
///
/// There is no longer an `image_size` parameter (removed with
/// `SECURE_BOOT_MAX_IMAGE_SIZE`/`ImageTooLargeToVerify`, U09-14): the actual
/// on-disk length is measured while streaming the hash, and checked against
/// the signed `payload_size` field itself (`PayloadSizeMismatch`) — so the
/// caller no longer needs to separately supply or trust a size from BOOTMETA.
#[must_use]
fn secure_boot_verify_image_detailed_ex(
    bin_path: &[u8],
    sig_path: &[u8],
) -> (BootTrust, BootTrustReason, u32) {
    // Dev early-out: all-zero pubkey means no trusted key yet.
    if SECURE_BOOT_PUBKEY.iter().all(|b| *b == 0) {
        return (BootTrust::Unverified, BootTrustReason::NoTrustedKey, 0);
    }

    let mut sig_buf = [0u8; SECURE_BOOT_SIG_FILE_MAX];
    let n = read_sig_file(sig_path, &mut sig_buf);
    if n == 0 {
        return (BootTrust::Unverified, BootTrustReason::SignatureAbsent, 0);
    }

    let sig = match sig_parse_header(&sig_buf[..n]) {
        Some(s) => s,
        None    => return (BootTrust::Failed, BootTrustReason::SignatureMalformed, 0),
    };

    // Trust check: signature's embedded pubkey must match the trusted one.
    // Constant-time comparison (`azos_crypto::ct::ct_eq`) — `!=` on byte
    // arrays short-circuits on the first mismatching byte and leaks the
    // trusted key bit-by-bit through observable timing/power side channels
    // (one boot per byte recovered).
    if !ct_eq(&sig.public_key, &SECURE_BOOT_PUBKEY) {
        return (BootTrust::Failed, BootTrustReason::PubkeyMismatch, 0);
    }

    // Stream the image through SHA-256 in bounded chunks (see
    // `hash_image_file` — no `.bss` megabyte buffer needed any more).
    let Some((digest, actual_len)) = hash_image_file(bin_path) else {
        return (BootTrust::Failed, BootTrustReason::ImageUnreadable, 0);
    };

    // The signed manifest binds `payload_size`; the bytes actually on disk
    // must match it exactly, checked BEFORE the signature so a truncated or
    // padded file is reported precisely instead of folded into "signature
    // invalid" (which would send whoever debugs it looking for a key
    // problem that doesn't exist).
    if sig.payload_size != actual_len {
        return (BootTrust::Failed, BootTrustReason::PayloadSizeMismatch, 0);
    }

    if sig_verify_manifest(&SECURE_BOOT_PUBKEY, &sig.signature,
                            sig.fw_version, sig.payload_size, &digest) {
        (BootTrust::Verified, BootTrustReason::Verified, sig.fw_version)
    } else {
        (BootTrust::Failed, BootTrustReason::SignatureInvalid, 0)
    }
}

/// Verify every slot the board is **not** running, so a slot that fails can be
/// recorded and never selected. Owner decision, 2026-09-19.
///
/// Returns one entry per slot, indexed by `SLOT_A`/`SLOT_B`/`SLOT_R`:
/// * `None` for the active slot — the caller already has that verdict and
///   re-reading a 2 MiB image to recompute it would double the boot cost for
///   an answer it is holding.
/// * `None` for every slot when `SECURE_BOOT_PUBKEY` is all zeros: with no
///   trusted key nothing is judgeable, and branding slots on a dev build would
///   write verdicts a signed build never agreed with.
///
/// # What this is for, and what it is NOT for
///
/// `ota_boot_validate_pure` rolls back to `last_good` after a boot loop, and
/// that rollback used to be unconditional. Recording the verdict here is what
/// lets it refuse. So this closes the **rollback/OTA** path: an attacker who
/// writes the inactive slot and induces a boot loop no longer gets their image
/// selected.
///
/// It does **not** close F1, the confused deputy. U-Boot chooses the slot from
/// a file this kernel does not authenticate; an attacker whose payload is
/// already executing never reaches this function. F1 closes in the loader or
/// not at all.
///
/// # Cost, stated plainly
///
/// Up to two extra image reads and two extra Ed25519 verifications on every
/// boot — the reason the caller runs this only on an enforced build, and only
/// after the active slot has already been accepted (if the board is about to
/// halt, the extra work buys nothing).
///
/// Same single-hart, pre-SMP context as the rest of the boot gate. No shared
/// mutable buffer to reason about any more (U09-14): `hash_image_file`
/// streams through a stack-local chunk buffer.
#[must_use]
pub fn secure_boot_verify_other_slots(
    active_slot: u8,
) -> [Option<(BootTrust, BootTrustReason)>; 3] {
    let mut out = [None, None, None];
    if SECURE_BOOT_PUBKEY.iter().all(|b| *b == 0) {
        return out;
    }
    for (i, entry) in out.iter_mut().enumerate() {
        let slot = i as u8;
        if slot == active_slot {
            continue;
        }
        *entry = Some(secure_boot_verify_image_detailed(
            secure_boot_bin_path(slot),
            secure_boot_sig_path(slot),
        ));
    }
    out
}

// ───────────────────────────────────────────────────────────────────────────
// OT04 / owner decision 99 — fall to the recovery slot instead of bricking.
// ───────────────────────────────────────────────────────────────────────────

/// What [`secure_boot_steer_to_recovery`] was able to do about a slot that
/// failed secure-boot verification on an enforced build.
///
/// Only `Steered` authorises the caller to reset. Every other variant means
/// the caller must fall through to its fail-closed halt: resetting without a
/// persisted, verified recovery target replaces a diagnosable brick with a
/// reset loop, which is strictly worse — nothing reaches the console long
/// enough to read, and the flash takes a write per cycle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecoverySteer {
    /// `/fat/BOOTMETA*` now names slot R, and the readback confirms it.
    /// The caller must reset; U-Boot's `boot.cmd` takes its `active_slot = r`
    /// branch and loads `KERN_R.BIN`.
    Steered,
    /// This boot IS the recovery slot. There is nothing further to fall to,
    /// and steering R at itself would be a reset loop by construction.
    AlreadyRecovery,
    /// Slot R does not carry a signature this build trusts. Falling to it
    /// would brick one boot later, with the failure reported against the
    /// wrong slot.
    RecoveryUnverified(BootTrustReason),
    /// The steer was written and did not read back. The write path reports
    /// a failed step on the console (`[OTA] ... not written: ... failed`)
    /// but returns `()`, so the readback is what tells "persisted" from
    /// "dropped" — and resetting on a dropped steer boots the identical
    /// state again, forever.
    SteerDidNotPersist,
}

/// Point the NEXT boot at the immutable recovery slot, after `active_slot`
/// failed secure-boot verification.
///
/// This does NOT reset — the caller owns that, because the caller is the only
/// one that knows whether it is allowed to keep running (it is not, on an
/// enforced build) and because the reset must happen after the console has
/// drained the explanation.
///
/// # Why R is verified by signature rather than by BOOTMETA's CRC path
///
/// Not via `ota_verify_slot(SLOT_R)` (the CRC path used by the OT04 block
/// earlier in boot): a CRC says the file is intact, not that it is ours. On
/// an enforced build the question is authenticity. This function's
/// `image_size`-free verification (U09-14) also means an attacker-written
/// `image_size_r` in BOOTMETA — previously usable to force
/// `ImageTooLargeToVerify` and deny recovery — has no verification-side
/// effect left to have.
///
/// # Context
///
/// Single-hart, pre-SMP, pre-`task_create` — same call context as the boot
/// gate itself. No shared buffer to reason about (U09-14): this adds a
/// second sequential streaming-hash pass, nothing concurrent.
#[must_use]
pub fn secure_boot_steer_to_recovery(active_slot: u8) -> RecoverySteer {
    if active_slot == crate::SLOT_R {
        return RecoverySteer::AlreadyRecovery;
    }

    let (trust, reason) = secure_boot_verify_image_detailed(
        SECURE_BOOT_BIN_PATH_R,
        SECURE_BOOT_SIG_PATH_R,
    );
    if trust != BootTrust::Verified {
        return RecoverySteer::RecoveryUnverified(reason);
    }

    let mut meta = crate::ota_read_boot_meta();
    meta.active_slot = crate::SLOT_R;
    crate::ota_write_boot_meta(&meta);

    // Readback. `ota_write_boot_meta` writes the dual records AND the legacy
    // single file U-Boot actually reads, but every one of those writes is
    // best-effort: a read-only volume, a full one, or an FS that is not up
    // yet all produce a silent no-op. Re-reading is cheap here (single-hart,
    // nothing else touches the volume) and converts a reset loop into a halt
    // the console explains.
    if crate::ota_read_boot_meta().active_slot != crate::SLOT_R {
        return RecoverySteer::SteerDidNotPersist;
    }

    crate::ota_apply_meta(&meta);
    RecoverySteer::Steered
}

/// Best-effort verification that adds the trust string to a text buffer.
/// Intended for kprintln: "secure boot: verified/unverified/failed".
#[must_use] 
pub fn secure_boot_status_str(slot: u8) -> &'static str {
    secure_boot_verify_slot(slot).as_str()
}

// Constant-time byte-array comparison for the pubkey check above, used to
// avoid timing-side-channel leakage of the trusted key. This used to be a
// fifth hand-rolled copy of the accumulate-then-`black_box` loop — see
// `azos_crypto::ct`'s module docs for the audit that found five, only
// two `black_box`-hardened (this one was). Deduped to the one shared copy;
// `use` at the top of this file.

// ───────────────────────────────────────────────────────────────────────────
// Re-exports from crypto crate for callers' convenience.
// ───────────────────────────────────────────────────────────────────────────

pub use azos_crypto::ed25519::{
    verify_boot_image as secure_boot_verify_raw,
    firmware_hash as secure_boot_hash,
    FirmwareSignature,
};

pub const SECURE_BOOT_HEADER_SIZE: usize = SIG_HEADER_SIZE;

// ───────────────────────────────────────────────────────────────────────────
// Diagnostic helper used by the boot path / shell.
// ───────────────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug)]
pub struct SecureBootInfo {
    pub trust:   BootTrust,
    pub require: bool,
    pub pubkey:  [u8; SECURE_BOOT_PUBKEY_LEN],
}

#[must_use] 
pub fn secure_boot_info(slot: u8) -> SecureBootInfo {
    SecureBootInfo {
        trust:   secure_boot_verify_slot(slot),
        require: secure_boot_require_signature(),
        pubkey:  SECURE_BOOT_PUBKEY,
    }
}

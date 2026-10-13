// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! On-disk names of the signed topology pair and their `.SIG` sidecars.
//!
//! **Every name here must be a valid FAT 8.3 short name**: one dot, a base of
//! at most 8 characters, an extension of at most 3. `crates/fs/fs/src/fat32.rs`
//! matches directory entries by their short name only — it skips VFAT
//! long-filename entries and never parses them — so a file whose name is not
//! already 8.3 is unreachable by the name a human wrote. Standard tools do not
//! refuse such a name; they silently store a generated short name next to a
//! long-name entry the kernel ignores. Observed with `mkfs.fat` + `mcopy`
//! (GNU mtools 4.0.49):
//!
//! ```text
//!     written as       stored short name   reachable by the kernel as
//!     CAPS.TOML        CAPS~1.TOM          (nothing a caller would guess)
//!     CAPS.TOML.SIG    CAPSTO~1.SIG
//!     SCHED.TOML       SCHED~1.TOM
//!     SCHED.TOML.SIG   SCHEDT~1.SIG
//! ```
//!
//! The `~1` suffix depends on what else is in the directory, so it cannot be
//! hard-coded either. Hence the names below: the TOML extension truncated to
//! three characters, and each sidecar sharing its signed file's BASE name under
//! the `SIG` extension. That is the shape every other signed pair in the tree
//! already has (`KERN_A.BIN`/`KERN_A.SIG` for the OTA slots,
//! `CONFIG.INI`/`CONFIG.SIG` for W2-B5). "CAPS.TOML" and "SCHED.TOML" remain
//! the names of the two FORMATS (RFC-0005) in prose; these constants are the
//! file names a loader opens.
//!
//! **Why the `/fat` prefix.** These paths are for `azos_fs::vfs_open`,
//! where `/fat` is the mount point the VFS strips before the FAT32 lookup —
//! the way `kernel/src/boot/config_auth.rs` already opens `/fat/CONFIG.INI` and
//! `/fat/CONFIG.SIG`. A caller going straight to `fat32_open` must use the
//! root-relative form instead (see `crates/core/ota/src/secure_boot.rs`'s
//! `SECURE_BOOT_SIG_PATH_A` doc for the boot failure mixing the two caused).
//!
//! Self-contained on purpose (no `crate::` paths): `tests/host/fs-tests` pulls
//! this file with `#[path]` and opens every constant through the REAL VFS and
//! FAT32 driver on a volume built by `mkfs.fat` + `mcopy`, so a name that
//! drifts out of 8.3 fails a host test instead of a future boot.

/// Signed capability topology (RFC-0005 `CAPS.TOML` format).
pub const CAPS_TOML_PATH: &[u8] = b"/fat/CAPS.TOM";
/// Bare 64-byte Ed25519 signature over the bytes of [`CAPS_TOML_PATH`].
pub const CAPS_SIG_PATH: &[u8] = b"/fat/CAPS.SIG";
/// Signed scheduler topology (RFC-0005 `SCHED.TOML` format).
pub const SCHED_TOML_PATH: &[u8] = b"/fat/SCHED.TOM";
/// Bare 64-byte Ed25519 signature over the bytes of [`SCHED_TOML_PATH`].
/// Retired by the loader in wave 15: SCHED.TOML is authenticated by the
/// `sched_sha256` its signed CAPS.TOML carries (`crate::signed`). The name is
/// kept so tools and tests can say which file they no longer need.
pub const SCHED_SIG_PATH: &[u8] = b"/fat/SCHED.SIG";

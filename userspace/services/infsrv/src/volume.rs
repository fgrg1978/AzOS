// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The fixed paths the service opens on the FAT32 volume. Constants only, so
//! `tests/host/fs-tests` includes this file and opens the very paths the
//! service passes to the open syscall.
//!
//! The model bundles are found by their extension (`bundles.rs`), not by a
//! path. The two data files here are the start-up self-test's.

/// The GGUF policy the start-up self-test classifies with, NUL-terminated for
/// the open syscall.
///
/// An 8.3 name: the FAT32 driver matches short names only (a longer extension
/// is stored by `mcopy` under a generated short name no lookup reaches).
pub const POLICY_PATH: &[u8] = b"/fat/POLICY.GGF\0";

/// Ed25519 signature over [`POLICY_PATH`]'s bytes: a bare 64-byte sidecar, the
/// `CAPS.SIG`/`CONFIG.SIG` format, signed with the same key
/// (`azos_topology::TRUSTED_PUBKEY`). An 8.3 name sharing the base name:
/// `POLICY.GGF.SIG` has two dots and the FAT32 driver could never open it.
pub const POLICY_SIG_PATH: &[u8] = b"/fat/POLICY.SIG\0";

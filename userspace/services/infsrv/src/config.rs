// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The Kconfig numbers of the service (`config/Kconfig.limits`, "Inference
//! service"), as the sizes they are used as.

/// `INFSRV_MODELS`: bundles held at once.
pub const MODELS: usize = azos_limits::INFSRV_MODELS;
/// `INFSRV_BLOB_KIB`: bytes of the blob arena.
pub const BLOB_BYTES: usize = azos_limits::INFSRV_BLOB_KIB * 1024;
/// `INFSRV_WORK_KIB`: working memory a run may use, bytes.
pub const WORK_BYTES: u32 = (azos_limits::INFSRV_WORK_KIB * 1024) as u32;
/// `INFSRV_CONTEXTS`: client contexts accounted.
pub const CONTEXTS: usize = azos_limits::INFSRV_CONTEXTS;
/// `INFSRV_ENERGY_QUOTA_UJ`: energy a context may use per window, 0 = no quota.
pub const ENERGY_QUOTA_UJ: u64 = azos_limits::INFSRV_ENERGY_QUOTA_UJ as u64;
/// `INFSRV_ENERGY_WINDOW_MS`, in nanoseconds.
pub const ENERGY_WINDOW_NS: u64 = azos_limits::INFSRV_ENERGY_WINDOW_MS * 1_000_000;
/// Receipts kept: the depth the kernel keeps its own durable journal at
/// (`DECISION_JOURNAL_ENTRIES`).
pub const JOURNAL_ENTRIES: usize = azos_limits::DECISION_JOURNAL_ENTRIES;

const _: () = assert!(MODELS >= 1 && CONTEXTS >= 1);

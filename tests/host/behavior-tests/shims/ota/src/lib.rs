// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host stand-in for `azos_ota`.
//!
//! **WHY a shim for a crate that builds on the host.** `azos_ota` pulls in
//! `azos_arch` and `azos_driver_server`, which pull the real
//! `azos_sync` — RV64 `sstatus` in inline asm — and that transitive chain
//! cannot compile here whatever this crate does about its own dependencies.
//!
//! `auth_envelope` reads exactly one thing from it: a **compile-time
//! constant** saying whether secure boot is enforced. A stand-in returning the
//! same value is equivalent, not an approximation — there is no behaviour to
//! diverge from. The suite exercises the unenforced arm, which is the one that
//! accepts frames and therefore the one worth testing.

/// Mirrors the unenforced build, matching the default `.config`.
pub const fn secure_boot_enforced_at_compile_time() -> bool { false }

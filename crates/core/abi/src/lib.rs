// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! AZOS frozen ABI.
//!
//! This crate is the **single source of truth** for everything that crosses
//! the user/kernel boundary:
//!
//! - syscall numbers
//! - error codes (Errno-style)
//! - `#[repr(C)]` data structures shared user↔kernel
//! - capability handle wire format
//!
//! Within a major release series, breaking changes here are forbidden. ABI
//! evolution rules are defined in RFC-0008 and RFC-0016.
//!
//! # Stability declaration
//!
//! As of AZOS v1.0 (the Phase 1 release):
//!
//! - Every `pub` item in this crate is **frozen** for the entirety of the
//!   `v1.x` series. Removing, renaming, or changing the wire format of any
//!   public item is a `v2.0` change and requires an RFC.
//! - Sizes of `#[repr(C)]` types are asserted at compile time in
//!   `crates/core/abi/src/types.rs`; the host-side `abi-tests` crate
//!   double-checks them.
//! - Syscall numbers will not be re-assigned. New syscalls take the next
//!   unused number; the `SYS_NR_RESERVED_UPPER` constant grows with each
//!   minor release.
//! - The `CapHandle` bitfield layout (4-bit kind, 4-bit perms, 8-bit
//!   generation, 16-bit slot) is part of the wire format and frozen.
//!
//! See `crates/core/abi/CHANGELOG.md` for the per-release diff.
//!
//! ## Stability tiers
//!
//! - **`stable`** items (everything currently in this crate): frozen.
//! - **`experimental`** items (gated by `cfg(feature = "experimental")`):
//!   subject to change; not part of the stability promise.
//!
//! ## Design notes
//!
//! - Pure types only — no kernel internals, no `unsafe`, no allocator.
//! - `no_std` everywhere.
//! - Constants are `u64` to match the syscall-arg width on RV64 / aarch64 /
//!   x86_64.
//! - All `repr(C)` structures must round-trip across the FFI boundary
//!   without alignment surprises; we assert sizes in `static_assertions`.

#![no_std]
#![deny(missing_docs)]
#![forbid(unsafe_code)]

pub mod cap;
pub mod drv_kind;
pub mod error;
pub mod exit_status;
pub mod io_ring;
pub mod ml_srv;
pub mod power;
/// Wave 15: the cross-level admission rule boot and run-time admission share.
pub mod rt_levels;
/// Wave 12: the flight, behavior, config and OTA typed calls (615..=618).
pub mod families;
pub mod sensor_sample;
pub mod syscall_nr;
pub mod time;
/// Wave 15: the kernel tracer's control call (632), classes and event ids.
pub mod trace;
pub mod types;
pub mod ushell;
pub mod vdso;

/// AZOS ABI version. Bumps on **major** breaking change only.
///
/// Within a series, all releases must match this constant. Mismatched ABI
/// versions cause user-space `libsys` to refuse to load.
pub const ABI_VERSION: u32 = 1;

/// Re-exports for the most-used items.
pub mod prelude {
    pub use crate::cap::{CapHandle, CapKind, CapPerms, CAP_NULL};
    pub use crate::error::Errno;
    pub use crate::ABI_VERSION;
}

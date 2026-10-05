// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Scheduler runtime registry — typed selector for the active
//! dispatch backend. RFC-0002 stub.
//!
//! # The state today (Phase 1)
//!
//! There are two dispatch paths in production:
//!
//! - **Legacy**: the original priority-queue scheduler in
//!   `crate::scheduler`. This is the default and what every CPU
//!   uses unless told otherwise.
//! - **APS**: the W4 Adaptive Partitioning combinator in
//!   `crate::aps_state` + per-class policies in
//!   `crate::policies::*`.
//!
//! Today the choice is encoded as a single boolean (`SCHED_USE_APS`
//! in `crate::scheduler`). This module wraps that boolean in a
//! typed enum so consumers can express the choice as data — the
//! same shape `crates/drivers/base/src/runtime/registry.rs` uses for
//! drivers.
//!
//! # The future (Phase 2+)
//!
//! The remaining variants of [`SchedulerHandle`] are reserved enum
//! slots. When per-CPU dispatch learns to route to a single policy
//! (FIFO-only, EDF-only, etc.) the registry's [`set_active`] call
//! starts accepting them. Until then they return
//! [`RegistryError::Unsupported`].
//!
//! # Why the typed API matters
//!
//! - **Cert.** The auditor sees one place where dispatch backend is
//!   selected, not a bag of `if some_bool { ... } else { ... }`.
//! - **Hot-swap**: future RFC can add `Registry::quiesce_and_swap`
//!   without touching consumers.
//! - **Userspace introspection**: `procfs` can read this enum value
//!   directly via a syscall, instead of decoding multiple bools.

use core::sync::atomic::{AtomicU8, Ordering};

// ──────────────────────────────────────────────────────────────────────────
// Public types
// ──────────────────────────────────────────────────────────────────────────

/// Which dispatch backend the scheduler is using *right now*.
///
/// Wire-stable: serialised verbatim into `procfs` and the eventual
/// `sys_sched_active` syscall. Changing existing discriminants is an
/// ABI break.
#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SchedulerHandle {
    /// Legacy priority-queue scheduler (`crate::scheduler`). Default.
    Legacy = 0,
    /// Adaptive Partitioning combinator (`crate::aps_state`). W4.
    Aps = 1,
    /// **Reserved** — FIFO standalone. Backed by
    /// `crate::policies::fifo` but not yet a top-level dispatch
    /// option in Phase 1.
    Fifo = 2,
    /// **Reserved** — EDF + CBS standalone.
    EdfCbs = 3,
    /// **Reserved** — Round-Robin standalone.
    Rr = 4,
    /// **Reserved** — CFS standalone.
    Cfs = 5,
    /// **Reserved** — Sporadic-server standalone.
    Sporadic = 6,
}

impl SchedulerHandle {
    /// Recover a handle from its wire byte. Returns `None` for
    /// unknown values rather than panicking — `procfs` and other
    /// readers may see future variants on a downgrade.
    pub const fn from_raw(raw: u8) -> Option<Self> {
        match raw {
            0 => Some(Self::Legacy),
            1 => Some(Self::Aps),
            2 => Some(Self::Fifo),
            3 => Some(Self::EdfCbs),
            4 => Some(Self::Rr),
            5 => Some(Self::Cfs),
            6 => Some(Self::Sporadic),
            _ => None,
        }
    }

    /// Wire byte representation.
    pub const fn as_raw(self) -> u8 {
        self as u8
    }

    /// Whether Phase 1 has a real dispatch path for this handle. The
    /// reserved variants return `false`; calling
    /// [`set_active`] with one of them yields
    /// [`RegistryError::Unsupported`].
    pub const fn is_supported_now(self) -> bool {
        matches!(self, Self::Legacy | Self::Aps)
    }
}

/// Errors returned by [`set_active`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RegistryError {
    /// The requested handle is reserved for a future phase and has
    /// no live dispatch path yet.
    Unsupported,
}

// ──────────────────────────────────────────────────────────────────────────
// Internal state
// ──────────────────────────────────────────────────────────────────────────

/// Current active handle, stored as `u8` so it can live in an
/// `AtomicU8`. Use [`active`] / [`set_active`] — do not poke this
/// directly.
static ACTIVE: AtomicU8 = AtomicU8::new(SchedulerHandle::Legacy.as_raw());

// ──────────────────────────────────────────────────────────────────────────
// Public API
// ──────────────────────────────────────────────────────────────────────────

/// Returns the currently-active scheduler handle.
///
/// Cheap: a single relaxed atomic load. Safe to call from any
/// context including ISR.
pub fn active() -> SchedulerHandle {
    let raw = ACTIVE.load(Ordering::Acquire);
    // ACTIVE is only ever written from set_active() with a valid
    // SchedulerHandle, so from_raw should always succeed. Fall back
    // to Legacy if something corrupts the value, to keep dispatch
    // alive rather than panic in a hot path.
    SchedulerHandle::from_raw(raw).unwrap_or(SchedulerHandle::Legacy)
}

/// Activate `handle`. Returns the previous active handle on
/// success, or [`RegistryError::Unsupported`] if Phase 1 cannot yet
/// dispatch to it.
///
/// **Note**: this is the typed entry point; the legacy
/// `crate::scheduler::use_aps_dispatch(bool)` is preserved for
/// backward compatibility and is implemented in terms of this call.
pub fn set_active(handle: SchedulerHandle) -> Result<SchedulerHandle, RegistryError> {
    if !handle.is_supported_now() {
        return Err(RegistryError::Unsupported);
    }
    let prev_raw = ACTIVE.swap(handle.as_raw(), Ordering::AcqRel);
    Ok(SchedulerHandle::from_raw(prev_raw).unwrap_or(SchedulerHandle::Legacy))
}

/// Convenience: `true` iff the active handle is [`SchedulerHandle::Aps`].
///
/// Equivalent to (and the new home of)
/// `crate::scheduler::aps_dispatch_enabled`; the latter delegates
/// here. Kept as a separate function so the hot path stays a single
/// atomic load + cmp.
#[inline]
pub fn is_aps_active() -> bool {
    ACTIVE.load(Ordering::Acquire) == SchedulerHandle::Aps.as_raw()
}

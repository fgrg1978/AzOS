// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The `MemCtl` interface: how the owner of a memory object says it may be
//! dropped.
//!
//! A memory object created volatile (`SHM_ATTR_VOLATILE`) is memory the owner
//! can rebuild: decoded weights, a rendered-surface cache. While the owner needs the contents it leaves the object alone.
//! When it does not, it calls [`MemCtl::set_volatile`]: from then on memory
//! reclaim may take the object's frames whole, under pressure, **without
//! writing them anywhere** (the cheapest frames the reclaim pass has; the
//! first stage of `azos_mm::zpool::reclaim_pass`). Before it uses the object
//! again it calls [`MemCtl::set_nonvolatile`], and is told whether the
//! contents are still there.
//!
//! The kernel hosts it on the `memctl` endpoint (`endpoint = "memctl"` in a
//! row's imports). The memory object travels as a capability in the request,
//! stays in the caller's table, and is resolved there; the endpoint's `WRITE`
//! right is the right to change what reclaim may take.
//!
//! Purged is final: the object has no frames any more, `SYS_MO_MAP` and a
//! clone of it answer `-EPURGED`, and both ops answer `true` ("purged") from
//! then on. The owner lets go of the object (`SYS_MO_UNMAP`) and makes a new
//! one. A task that touches a mapping of a volatile object may find the page
//! gone: the owner stops using the object before it calls `set_volatile`.
//!
//! # Availability and users
//!
//! Reclaim runs only on an image built with `MM_RECLAIM_COMPRESS`. Without it
//! (`MM_RECLAIM_OFF`, the default of the robot, industrial, automotive and
//! firmware profiles) nothing ever purges a volatile object: the ops succeed
//! and `set_nonvolatile` always answers `false`. A caller that handles `true`
//! is correct on both. The user in the tree is `infsrv`, whose blob arena is
//! a volatile object (`azos_syscall::memctl` says how).
//!
//! # Outcomes
//!
//! `DENIED`: the endpoint capability lacks `WRITE`, or the caller is not the
//! object's owner (the one who made it, or received its owning reference by a
//! MOVE): a holder that only shares the object must not make it droppable
//! under the others. `BAD_ARGUMENT`: the handle is not a memory object the
//! caller holds with `READ`, or the object was created without
//! `SHM_ATTR_VOLATILE`.

use crate::outcome::Out;
use azos_idl::{azos_interface, Cap};

/// The interface id (ASCII "MCTL").
pub const MEMCTL_ID: u32 = 0x4D43_544C;

/// What a `Cap<VolatileMem>` names: a memory object the caller owns, created
/// with `SHM_ATTR_VOLATILE`.
pub struct VolatileMem;

#[azos_interface(id = 0x4D43_544C, level = 1)]
pub trait MemCtl {
    /// The owner does not need the contents of `mem` now: reclaim may drop its
    /// frames. Answers whether the object was already purged (`true`: the
    /// contents are gone and the call changed nothing). Asking again says the
    /// same. Needs `WRITE`.
    #[idempotent]
    fn set_volatile(&mut self, mem: Cap<VolatileMem>) -> Out<bool>;
    /// The owner needs the contents of `mem` again: reclaim leaves it alone.
    /// Answers whether the object was purged while it was volatile (`true`:
    /// the contents are gone, and so is the object's use). Asking again says
    /// the same. Needs `WRITE`.
    #[idempotent]
    fn set_nonvolatile(&mut self, mem: Cap<VolatileMem>) -> Out<bool>;
}

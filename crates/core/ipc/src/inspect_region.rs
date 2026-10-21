// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! How a task obtains the kernel's introspection regions (Kconfig INSPECT).
//!
//! The kernel (`kernel/src/boot/inspect.rs`) creates two kernel-owned,
//! read-only MemObjs and publishes their packed references here
//! ([`publish`]). A task gets a `Cap<Shm>` to one by its topology row: it
//! declares `MemObj inspect.public` or `MemObj inspect.admin`, the kernel seeds the capability
//! ([`seed_mint`], installed as the row minter), and the task finds it with
//! `SYS_CAP_LOOKUP(Shm, SHM_INSPECT_PUBLIC | SHM_INSPECT_ADMIN)`
//! ([`lookup_resource`]) and maps it read-only. After the map a read is a
//! load: no system call, no copy.
//!
//! # Authority
//!
//! * `READ` and `MAP` and nothing else (the row says `perm = "rm"`): a `WRITE`,
//!   `DUP` or `TRANSFER` request is refused, so the holder cannot write the
//!   tree and cannot hand the region on. `MAP` is there because the holder
//!   maps it; `READ` alone would map nothing.
//! * `inspect.admin` names other tasks, so it needs the **admin warrant**:
//!   the full task view (`Cap<Task>` `READ` on `"tasks"`) must already be in
//!   the task's table when the grant is made. A row lists the task view before
//!   the admin region. The warrant is checked when the capability is granted;
//!   a mapping made then outlives it.
//! * A **view** region (`inspect.names`, `inspect.rpc`, `inspect.mcp`,
//!   `inspect.components`, `inspect.logins`, `inspect.clock`: [`ViewKind`])
//!   carries what one service needs of the signed topology's wiring. Only the
//!   rows that declare it are granted it; the kernel builds it for exactly
//!   those rows (`kernel/src/boot/inspect_views.rs`).
//!
//! Gate canary: `inspect-view-canary` grants every published view along with
//! the public region, to a row that declares none of them.

use crate::cap::{ty, CapHandle, CapPerms};
use core::sync::atomic::{AtomicU32, Ordering};

/// No region published.
const NONE: u32 = u32::MAX;
static PUBLIC: AtomicU32 = AtomicU32::new(NONE);
static ADMIN: AtomicU32 = AtomicU32::new(NONE);
static VIEWS: [AtomicU32; ViewKind::ALL.len()] = [const { AtomicU32::new(NONE) }; ViewKind::ALL.len()];

/// The view regions: what one service reads of the topology's wiring.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ViewKind {
    Names = 0,
    Rpc = 1,
    Mcp = 2,
    Components = 3,
    Logins = 4,
    Clock = 5,
}

impl ViewKind {
    pub const ALL: [ViewKind; 6] =
        [ViewKind::Names, ViewKind::Rpc, ViewKind::Mcp, ViewKind::Components, ViewKind::Logins, ViewKind::Clock];

    /// The target a row names it by.
    pub const fn target(self) -> &'static str {
        match self {
            ViewKind::Names => "inspect.names",
            ViewKind::Rpc => "inspect.rpc",
            ViewKind::Mcp => "inspect.mcp",
            ViewKind::Components => "inspect.components",
            ViewKind::Logins => "inspect.logins",
            ViewKind::Clock => "inspect.clock",
        }
    }

    /// The `SYS_CAP_INFO(Shm, ..)` key a task finds it by.
    pub const fn key(self) -> u32 {
        use azos_abi::cap::*;
        match self {
            ViewKind::Names => SHM_INSPECT_NAMES,
            ViewKind::Rpc => SHM_INSPECT_RPC,
            ViewKind::Mcp => SHM_INSPECT_MCP,
            ViewKind::Components => SHM_INSPECT_COMPONENTS,
            ViewKind::Logins => SHM_INSPECT_LOGINS,
            ViewKind::Clock => SHM_INSPECT_CLOCK,
        }
    }

    fn of_target(t: &str) -> Option<ViewKind> {
        ViewKind::ALL.into_iter().find(|v| v.target() == t)
    }

    fn of_key(k: u32) -> Option<ViewKind> {
        ViewKind::ALL.into_iter().find(|v| v.key() == k)
    }
}

/// Publish the view region `v`'s packed `Cap<Shm>` reference. Boot, once per
/// view, before any task is seeded.
pub fn publish_view(v: ViewKind, region: u32) {
    VIEWS[v as usize].store(region, Ordering::Release);
}

/// What a row asks for and the capability carries: read the tree through a
/// mapping of the region.
pub const VIEW: CapPerms = CapPerms::READ.union(CapPerms::MAP);

/// The target of the public region's row.
pub const TARGET_PUBLIC: &str = "inspect.public";
/// The target of the admin region's row.
pub const TARGET_ADMIN: &str = "inspect.admin";

/// Publish the regions' packed `Cap<Shm>` references: the public one, and the
/// admin one when the configuration has it. Boot, once, before any task is
/// seeded.
pub fn publish(public: u32, admin: Option<u32>) {
    PUBLIC.store(public, Ordering::Release);
    ADMIN.store(admin.unwrap_or(NONE), Ordering::Release);
}

fn published(a: &AtomicU32) -> Option<u32> {
    let r = a.load(Ordering::Acquire);
    (r != NONE).then_some(r)
}

/// The topology minter for `inspect.public`, `inspect.admin` and the views.
/// `None` for any other target, a region that is not published, any rights
/// but exactly `READ|MAP`, the admin region without the task view, or a full
/// table.
pub fn seed_mint(tid: u32, target: &str, perms: CapPerms) -> Option<CapHandle> {
    if perms != VIEW {
        return None;
    }
    let region = match target {
        TARGET_PUBLIC => {
            // Gate canary: every view goes with the public region.
            if cfg!(feature = "inspect-view-canary") {
                for v in &VIEWS {
                    if let Some(r) = published(v) {
                        let _ = crate::cap::objref::grant_packed::<crate::cap::targets::Shm>(tid, perms, r);
                    }
                }
            }
            published(&PUBLIC)?
        }
        TARGET_ADMIN => {
            let region = published(&ADMIN)?;
            let warrant = crate::cap_store::with_table(tid, |t| t.holds_kind_resource_with(ty::TASK, 0, CapPerms::READ))
                .unwrap_or(false);
            if !warrant {
                return None;
            }
            region
        }
        t => published(&VIEWS[ViewKind::of_target(t)? as usize])?,
    };
    crate::cap::objref::grant_packed::<crate::cap::targets::Shm>(tid, perms, region).map(|c| c.raw())
}

/// `SYS_CAP_INFO`'s `Shm` resource, translated: an introspection key
/// (`azos_abi::cap::SHM_INSPECT_*`) becomes the published region's index,
/// which is what a `Shm` lookup compares. Any other value, and a key whose
/// region is not published, is returned as given (it then matches nothing: a
/// key is above every pool index).
pub fn lookup_resource(resource: u32) -> u32 {
    use azos_abi::cap::{SHM_INSPECT_ADMIN, SHM_INSPECT_PUBLIC};
    let slot = match resource {
        SHM_INSPECT_PUBLIC => &PUBLIC,
        SHM_INSPECT_ADMIN => &ADMIN,
        k => match ViewKind::of_key(k) {
            Some(v) => &VIEWS[v as usize],
            None => return resource,
        },
    };
    match published(slot) {
        Some(r) => crate::cap::objref::resource_index(ty::SHM, r),
        None => resource,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use azos_abi::cap::{SHM_INSPECT_ADMIN, SHM_INSPECT_PUBLIC};
    use std::sync::{Mutex, MutexGuard};

    /// The published refs are process-wide statics: one test at a time.
    static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());

    fn serial() -> MutexGuard<'static, ()> {
        ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// A task with a table of its own (the host scheduler shim binds the slot).
    fn bound(tid: u32) -> u32 {
        azos_sched::shim_bind(tid, tid as usize);
        tid
    }

    #[test]
    fn an_unpublished_region_is_neither_minted_nor_translated() {
        let _g = serial();
        publish(NONE, None);
        assert!(seed_mint(bound(24), TARGET_PUBLIC, VIEW).is_none());
        assert!(seed_mint(24, TARGET_ADMIN, VIEW).is_none());
        assert_eq!(lookup_resource(SHM_INSPECT_PUBLIC), SHM_INSPECT_PUBLIC);
        assert_eq!(lookup_resource(SHM_INSPECT_ADMIN), SHM_INSPECT_ADMIN);
        assert_eq!(lookup_resource(3), 3);
    }

    #[test]
    fn only_read_is_granted_and_only_for_a_known_target() {
        let _g = serial();
        publish(0, Some(1));
        let tid = bound(25);
        for perms in [CapPerms::RW, CapPerms::WRITE, CapPerms::READ, CapPerms::MAP, VIEW.union(CapPerms::DUP), VIEW.union(CapPerms::TRANSFER)] {
            assert!(seed_mint(tid, TARGET_PUBLIC, perms).is_none(), "{perms:?}");
        }
        assert!(seed_mint(tid, "inspect.root", CapPerms::READ).is_none());
        assert!(seed_mint(tid, "inspect.", CapPerms::READ).is_none());
        assert!(seed_mint(tid, TARGET_PUBLIC, VIEW).is_some());
        publish(NONE, None);
    }

    #[test]
    fn the_admin_region_needs_the_task_view() {
        let _g = serial();
        publish(0, Some(1));
        let tid = bound(26);
        assert!(seed_mint(tid, TARGET_ADMIN, VIEW).is_none(), "no warrant, no admin region");
        // The public region is not the warrant either.
        assert!(seed_mint(tid, TARGET_PUBLIC, VIEW).is_some());
        assert!(seed_mint(tid, TARGET_ADMIN, VIEW).is_none());
        crate::cap_store::grant::<crate::cap::targets::Task>(tid, CapPerms::READ, 0).expect("the task view");
        assert!(seed_mint(tid, TARGET_ADMIN, VIEW).is_some(), "the warrant opens it");
        publish(NONE, None);
    }

    #[test]
    fn a_view_is_granted_by_its_own_target_only() {
        let _g = serial();
        publish(0, Some(1));
        publish_view(ViewKind::Names, 2);
        let tid = bound(27);
        assert!(seed_mint(tid, "inspect.rpc", VIEW).is_none(), "an unpublished view is not granted");
        assert!(seed_mint(tid, "inspect.names", CapPerms::READ).is_none(), "READ|MAP only");
        assert!(seed_mint(tid, "inspect.names", VIEW).is_some());
        assert_eq!(lookup_resource(azos_abi::cap::SHM_INSPECT_NAMES), crate::cap::objref::resource_index(ty::SHM, 2));
        assert_eq!(lookup_resource(azos_abi::cap::SHM_INSPECT_RPC), azos_abi::cap::SHM_INSPECT_RPC);
        publish_view(ViewKind::Names, NONE);
        publish(NONE, None);
    }

    #[test]
    fn a_key_translates_to_the_region_index() {
        let _g = serial();
        publish(0, Some(1));
        assert_eq!(lookup_resource(SHM_INSPECT_PUBLIC), crate::cap::objref::resource_index(ty::SHM, 0));
        assert_eq!(lookup_resource(SHM_INSPECT_ADMIN), crate::cap::objref::resource_index(ty::SHM, 1));
        publish(NONE, None);
    }
}

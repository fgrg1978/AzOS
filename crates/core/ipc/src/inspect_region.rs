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
//!   the full task view (`Cap<Task>` `READ` on `"tasks"`, the same right that
//!   lifts the `/proc/tasks` filter) must already be in the task's table when
//!   the grant is made. A row lists the task view before the admin region.
//!   The warrant is checked when the capability is granted; a mapping made
//!   then outlives it.

use crate::cap::{ty, CapHandle, CapPerms};
use core::sync::atomic::{AtomicU32, Ordering};

/// No region published.
const NONE: u32 = u32::MAX;
static PUBLIC: AtomicU32 = AtomicU32::new(NONE);
static ADMIN: AtomicU32 = AtomicU32::new(NONE);

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

/// The topology minter for `inspect.public` and `inspect.admin`. `None` for
/// any other target, a region that is not published, any rights but exactly
/// `READ|MAP`, the admin region without the task view, or a full table.
pub fn seed_mint(tid: u32, target: &str, perms: CapPerms) -> Option<CapHandle> {
    if perms != VIEW {
        return None;
    }
    let region = match target {
        TARGET_PUBLIC => published(&PUBLIC)?,
        TARGET_ADMIN => {
            let region = published(&ADMIN)?;
            let warrant = crate::cap_store::with_table(tid, |t| t.holds_kind_resource_with(ty::TASK, 0, CapPerms::READ))
                .unwrap_or(false);
            if !warrant {
                return None;
            }
            region
        }
        _ => return None,
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
        _ => return resource,
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
    fn a_key_translates_to_the_region_index() {
        let _g = serial();
        publish(0, Some(1));
        assert_eq!(lookup_resource(SHM_INSPECT_PUBLIC), crate::cap::objref::resource_index(ty::SHM, 0));
        assert_eq!(lookup_resource(SHM_INSPECT_ADMIN), crate::cap::objref::resource_index(ty::SHM, 1));
        publish(NONE, None);
    }
}

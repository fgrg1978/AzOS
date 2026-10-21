// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Kernel-owned regions a topology row grants a task: `input.events` (the
//! ring the input drivers publish into, whose consumer moves the tail) and
//! `console.screen` (the framebuffer console's screen region, whose reader
//! writes the overlay words), both for reading AND writing; and `klog.ring`
//! (the structured kernel log, whose readers keep their own cursors) for
//! reading only.
//!
//! Like the introspection regions ([`crate::inspect_region`]): the kernel
//! creates a contiguous memory object at boot and publishes its packed
//! reference here ([`publish`]); a row names it (`MemObj input.events`), the
//! kernel seeds the capability ([`seed_mint`], called from `cap_seed`), and the
//! task finds the `Cap<Shm>` with `SYS_CAP_INFO(Shm, SHM_INPUT_EVENTS |
//! SHM_CONSOLE_SCREEN | SHM_KLOG_RING)` ([`lookup_resource`]). After the map
//! the task's accesses are loads and stores.
//!
//! # Authority
//!
//! Each region has the one set of rights its row must ask for ([`Region::perms`]).
//! The input ring and the screen are exactly `READ|WRITE|MAP` ([`RW`]): a
//! holder reads the region, writes the words its layout leaves to the reader,
//! and maps it. The kernel log is exactly `READ|MAP` ([`VIEW`]): the kernel is
//! the only writer. In both cases `DUP` and `TRANSFER` are refused, so the
//! holder cannot hand the region on. The kernel's writers keep their own copy
//! of every number they index with (see `azos_input_wire::screen`), so what a
//! holder writes into a region can make the screen wrong but not the kernel's
//! memory accesses.

use crate::cap::{ty, CapHandle, CapPerms};
use core::sync::atomic::{AtomicU32, Ordering};

/// No region published.
const NONE: u32 = u32::MAX;
static INPUT_EVENTS: AtomicU32 = AtomicU32::new(NONE);
static CONSOLE_SCREEN: AtomicU32 = AtomicU32::new(NONE);
static KLOG_RING: AtomicU32 = AtomicU32::new(NONE);

/// What a row asks for and the capability carries.
pub const RW: CapPerms = CapPerms::READ.union(CapPerms::WRITE).union(CapPerms::MAP);

/// What a row for a read-only region asks for and the capability carries.
pub const VIEW: CapPerms = CapPerms::READ.union(CapPerms::MAP);

/// The target of the input event ring's row.
pub const TARGET_INPUT_EVENTS: &str = "input.events";
/// The target of the console screen region's row.
pub const TARGET_CONSOLE_SCREEN: &str = "console.screen";
/// The target of the structured kernel log's row.
pub const TARGET_KLOG_RING: &str = "klog.ring";

/// Which region.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Region {
    InputEvents,
    ConsoleScreen,
    KlogRing,
}

impl Region {
    fn slot(self) -> &'static AtomicU32 {
        match self {
            Region::InputEvents => &INPUT_EVENTS,
            Region::ConsoleScreen => &CONSOLE_SCREEN,
            Region::KlogRing => &KLOG_RING,
        }
    }

    /// The rights a row for this region asks for, and the capability carries.
    pub const fn perms(self) -> CapPerms {
        match self {
            Region::InputEvents | Region::ConsoleScreen => RW,
            Region::KlogRing => VIEW,
        }
    }

    fn of_target(target: &str) -> Option<Region> {
        match target {
            TARGET_INPUT_EVENTS => Some(Region::InputEvents),
            TARGET_CONSOLE_SCREEN => Some(Region::ConsoleScreen),
            TARGET_KLOG_RING => Some(Region::KlogRing),
            _ => None,
        }
    }
}

/// Publish the packed `Cap<Shm>` reference of `region`. Boot, before any task
/// is seeded.
pub fn publish(region: Region, packed: u32) {
    region.slot().store(packed, Ordering::Release);
}

fn published(region: Region) -> Option<u32> {
    let r = region.slot().load(Ordering::Acquire);
    (r != NONE).then_some(r)
}

/// Is `target` one of these regions' names?
pub fn is_target(target: &str) -> bool {
    Region::of_target(target).is_some()
}

/// The topology minter. `None` for another target, a region that is not
/// published, any rights but exactly the region's own ([`Region::perms`]), or
/// a full table.
pub fn seed_mint(tid: u32, target: &str, perms: CapPerms) -> Option<CapHandle> {
    let which = Region::of_target(target)?;
    if perms != which.perms() {
        return None;
    }
    let region = published(which)?;
    crate::cap::objref::grant_packed::<crate::cap::targets::Shm>(tid, perms, region).map(|c| c.raw())
}

/// The minter the kernel installs for every kernel-owned region target
/// (`cap_seed::set_shm_inspect_minter`): the regions of this module, else the
/// introspection regions.
pub fn seed_mint_any(tid: u32, target: &str, perms: CapPerms) -> Option<CapHandle> {
    if is_target(target) {
        seed_mint(tid, target, perms)
    } else {
        crate::inspect_region::seed_mint(tid, target, perms)
    }
}

/// `SYS_CAP_INFO`'s `Shm` resource, translated: a key (`azos_abi::cap::SHM_*`)
/// becomes the published region's index, which is what a `Shm` lookup
/// compares. Any other value, and a key whose region is not published, is
/// returned as given (it then matches nothing: a key is above every pool
/// index).
pub fn lookup_resource(resource: u32) -> u32 {
    use azos_abi::cap::{SHM_CONSOLE_SCREEN, SHM_INPUT_EVENTS, SHM_KLOG_RING};
    let region = match resource {
        SHM_INPUT_EVENTS => Region::InputEvents,
        SHM_CONSOLE_SCREEN => Region::ConsoleScreen,
        SHM_KLOG_RING => Region::KlogRing,
        _ => return resource,
    };
    match published(region) {
        Some(r) => crate::cap::objref::resource_index(ty::SHM, r),
        None => resource,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use azos_abi::cap::{SHM_CONSOLE_SCREEN, SHM_INPUT_EVENTS, SHM_KLOG_RING};
    use std::sync::{Mutex, MutexGuard};

    /// The published refs are process-wide statics: one test at a time.
    static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());

    fn serial() -> MutexGuard<'static, ()> {
        ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn bound(tid: u32) -> u32 {
        azos_sched::shim_bind(tid, tid as usize);
        tid
    }

    fn clear() {
        publish(Region::InputEvents, NONE);
        publish(Region::ConsoleScreen, NONE);
        publish(Region::KlogRing, NONE);
    }

    #[test]
    fn an_unpublished_region_is_neither_minted_nor_translated() {
        let _g = serial();
        clear();
        assert!(seed_mint(bound(40), TARGET_INPUT_EVENTS, RW).is_none());
        assert!(seed_mint(40, TARGET_CONSOLE_SCREEN, RW).is_none());
        assert_eq!(lookup_resource(SHM_INPUT_EVENTS), SHM_INPUT_EVENTS);
        assert_eq!(lookup_resource(SHM_CONSOLE_SCREEN), SHM_CONSOLE_SCREEN);
        assert!(seed_mint(40, TARGET_KLOG_RING, VIEW).is_none());
        assert_eq!(lookup_resource(SHM_KLOG_RING), SHM_KLOG_RING);
    }

    /// The log is granted `READ|MAP` and nothing else: a row that asks to
    /// write it (or for the other regions' rights) is refused, and the other
    /// regions refuse the log's rights.
    #[test]
    fn the_kernel_log_is_read_only() {
        let _g = serial();
        publish(Region::InputEvents, 0);
        publish(Region::KlogRing, 2);
        let tid = bound(42);
        for perms in [RW, CapPerms::RW, VIEW.union(CapPerms::WRITE), VIEW.union(CapPerms::DUP), VIEW.union(CapPerms::TRANSFER), CapPerms::READ] {
            assert!(seed_mint(tid, TARGET_KLOG_RING, perms).is_none(), "{perms:?}");
        }
        assert!(seed_mint(tid, TARGET_INPUT_EVENTS, VIEW).is_none(), "the input ring is not a view");
        assert!(seed_mint(tid, TARGET_KLOG_RING, VIEW).is_some());
        assert_eq!(lookup_resource(SHM_KLOG_RING), crate::cap::objref::resource_index(ty::SHM, 2));
        clear();
    }

    #[test]
    fn only_read_write_map_is_granted_and_only_for_a_known_target() {
        let _g = serial();
        publish(Region::InputEvents, 0);
        publish(Region::ConsoleScreen, 1);
        let tid = bound(41);
        for perms in [
            CapPerms::READ.union(CapPerms::MAP),
            CapPerms::RW,
            RW.union(CapPerms::DUP),
            RW.union(CapPerms::TRANSFER),
            CapPerms::WRITE,
        ] {
            assert!(seed_mint(tid, TARGET_INPUT_EVENTS, perms).is_none(), "{perms:?}");
        }
        assert!(seed_mint(tid, "input.", RW).is_none());
        assert!(seed_mint(tid, "inspect.public", RW).is_none());
        assert!(seed_mint(tid, TARGET_INPUT_EVENTS, RW).is_some());
        assert!(seed_mint(tid, TARGET_CONSOLE_SCREEN, RW).is_some());
        clear();
    }

    #[test]
    fn a_key_translates_to_the_region_index() {
        let _g = serial();
        publish(Region::InputEvents, 0);
        publish(Region::ConsoleScreen, 1);
        assert_eq!(lookup_resource(SHM_INPUT_EVENTS), crate::cap::objref::resource_index(ty::SHM, 0));
        assert_eq!(lookup_resource(SHM_CONSOLE_SCREEN), crate::cap::objref::resource_index(ty::SHM, 1));
        assert_eq!(lookup_resource(3), 3, "any other value stays");
        clear();
    }
}

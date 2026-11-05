// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `Cap<Launch>`: the right to start one image with
//! `SYS_SPAWN_EX`.
//!
//! Seeded from the topology word `"launch"` whose target is an image name as
//! the seccomp table spells it (`"TOOLBOX.ELF"`). The name is interned here
//! and the capability's resource is its index, so the spawn check compares a
//! small integer: the caller must hold `EXEC` on the resource of the image
//! the FILE'S DIGEST resolves to (`ImageProfile::image`), not of the path it
//! typed. A renamed or copied binary therefore needs the grant of what it
//! is, not of what it is called.
//!
//! A topology word whose target is `pkg.<hex>` grants the images of one signed
//! package instead (`azos_abi::cap::launch_name::Target::Package`): the
//! capability's resource is the package's index in its own table, behind
//! [`PACKAGE_RESOURCE`], so a package never takes one of the image names'
//! slots. The spawn check asks for the image's resource and, when the image
//! belongs to an applied package, for that package's.

use crate::cap::{targets, Cap, CapPerms};
use azos_abi::cap::launch_name::{parse, Target};
use azos_sync::SpinLock;

/// Distinct image names the topology can grant launch rights on: the tools the
/// shell starts and the rows the component manager starts
/// (`tests/host/topology-tests` fails when a built-in topology names more).
pub const MAX_LAUNCH_NAMES: usize = 32;
pub use azos_abi::cap::launch_name::{is_valid as name_is_valid, MAX as LAUNCH_NAME_MAX};

/// Distinct packages the topology can grant launch rights on.
pub const MAX_LAUNCH_PACKAGES: usize = 8;

/// Set in the resource of a package grant; an image name's resource is its
/// index below [`MAX_LAUNCH_NAMES`] and never has it.
pub const PACKAGE_RESOURCE: u32 = 1 << 31;

struct Packages {
    ids: [[u8; 32]; MAX_LAUNCH_PACKAGES],
    count: usize,
}

static PACKAGES: SpinLock<Packages> = SpinLock::new(Packages { ids: [[0; 32]; MAX_LAUNCH_PACKAGES], count: 0 });

struct Names {
    names: [[u8; LAUNCH_NAME_MAX]; MAX_LAUNCH_NAMES],
    lens: [u8; MAX_LAUNCH_NAMES],
    count: usize,
}

static NAMES: SpinLock<Names> = SpinLock::new(Names {
    names: [[0; LAUNCH_NAME_MAX]; MAX_LAUNCH_NAMES],
    lens: [0; MAX_LAUNCH_NAMES],
    count: 0,
});

/// The resource for image `name`, interning it; `None` for a name
/// [`name_is_valid`] refuses or a full table.
pub fn launch_resource(name: &[u8]) -> Option<u32> {
    if !name_is_valid(name) {
        return None;
    }
    let mut t = NAMES.lock();
    for i in 0..t.count {
        if &t.names[i][..t.lens[i] as usize] == name {
            return Some(i as u32);
        }
    }
    if t.count >= MAX_LAUNCH_NAMES {
        return None;
    }
    let i = t.count;
    t.names[i][..name.len()].copy_from_slice(name);
    t.lens[i] = name.len() as u8;
    t.count += 1;
    Some(i as u32)
}

/// The resource image `name` was interned under, without interning it. An
/// image no row grants launch rights on has none, and no capability can name
/// it.
pub fn launch_resource_of(name: &[u8]) -> Option<u32> {
    let t = NAMES.lock();
    (0..t.count).find(|&i| &t.names[i][..t.lens[i] as usize] == name).map(|i| i as u32)
}

/// The resource for package `id`, interning it; `None` on a full table.
pub fn package_resource(id: &[u8; 32]) -> Option<u32> {
    let mut t = PACKAGES.lock();
    if let Some(i) = t.ids[..t.count].iter().position(|p| p == id) {
        return Some(PACKAGE_RESOURCE | i as u32);
    }
    if t.count >= MAX_LAUNCH_PACKAGES {
        return None;
    }
    let i = t.count;
    t.ids[i] = *id;
    t.count += 1;
    Some(PACKAGE_RESOURCE | i as u32)
}

/// The resource package `id` was interned under, without interning it. A
/// package no row grants launch rights on has none.
pub fn package_resource_of(id: &[u8; 32]) -> Option<u32> {
    let t = PACKAGES.lock();
    t.ids[..t.count].iter().position(|p| p == id).map(|i| PACKAGE_RESOURCE | i as u32)
}

/// Mint a `Cap<Launch>` on `target` (an image name, or `pkg.` and a package
/// id, `launch_name::parse`) into `tid`. Only `EXEC` means anything; a grant
/// of anything else is refused rather than trimmed.
pub fn launch_grant_cap(tid: u32, target: &str, perms: CapPerms) -> Option<Cap<targets::Launch>> {
    if perms != CapPerms::EXEC {
        return None;
    }
    let resource = match parse(target.as_bytes())? {
        Target::Image(name) => launch_resource(name)?,
        Target::Package(id) => package_resource(&id)?,
    };
    crate::cap_store::grant::<targets::Launch>(tid, perms, resource)
}

/// Empty the table (host tests only).
#[doc(hidden)]
pub fn reset_for_tests() {
    let mut t = NAMES.lock();
    t.count = 0;
    t.lens = [0; MAX_LAUNCH_NAMES];
    PACKAGES.lock().count = 0;
}

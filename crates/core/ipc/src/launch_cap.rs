// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `Cap<Launch>` (RFC-0055, wave 11): the right to start one image with
//! `SYS_SPAWN_EX`.
//!
//! Seeded from the topology word `"launch"` whose target is an image name as
//! the seccomp table spells it (`"TOOLBOX.ELF"`). The name is interned here
//! and the capability's resource is its index, so the spawn check compares a
//! small integer: the caller must hold `EXEC` on the resource of the image
//! the FILE'S DIGEST resolves to (`ImageProfile::image`), not of the path it
//! typed. A renamed or copied binary therefore needs the grant of what it
//! is, not of what it is called.

use crate::cap::{targets, Cap, CapPerms};
use azos_sync::SpinLock;

/// Distinct image names the topology can grant launch rights on.
pub const MAX_LAUNCH_NAMES: usize = 16;
/// Longest image name: an 8.3 name.
pub const LAUNCH_NAME_MAX: usize = 12;

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

/// Is `name` an image name a launch grant may target: 1..=12 bytes of
/// upper-case letters, digits, `_`, `-`, ending in `.ELF`?
pub fn name_is_valid(name: &[u8]) -> bool {
    if name.len() <= 4 || name.len() > LAUNCH_NAME_MAX || !name.ends_with(b".ELF") {
        return false;
    }
    let base = &name[..name.len() - 4];
    base.len() <= 8
        && base.iter().all(|&b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
}

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

/// Mint a `Cap<Launch>` on image `target` into `tid`. Only `EXEC` means
/// anything; a grant of anything else is refused rather than trimmed.
pub fn launch_grant_cap(tid: u32, target: &str, perms: CapPerms) -> Option<Cap<targets::Launch>> {
    if perms != CapPerms::EXEC {
        return None;
    }
    let resource = launch_resource(target.as_bytes())?;
    crate::cap_store::grant::<targets::Launch>(tid, perms, resource)
}

/// Empty the table (host tests only).
#[doc(hidden)]
pub fn reset_for_tests() {
    let mut t = NAMES.lock();
    t.count = 0;
    t.lens = [0; MAX_LAUNCH_NAMES];
}

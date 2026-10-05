// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `Cap<File>` naming a directory tree: the authority for the calls that
//! change the tree (wave 10, owner decision).
//!
//! `SYS_MKDIR`, `SYS_UNLINK`, `SYS_RMDIR`, `SYS_RENAME` and `SYS_TRUNCATE`
//! needed no capability: a seccomp profile row was the only gate. A ring-3
//! caller now needs a `Cap<File>` with `WRITE` whose tree covers the path:
//!
//! * create, remove, rename — the DIRECTORY the entry is in: the path must lie
//!   strictly under the tree's root (the root itself is not an entry of the
//!   tree, so a grant on `/fat` cannot remove `/fat`);
//! * truncate — the FILE: the path may be the root itself or lie under it.
//!
//! **Why `Cap<File>` and not a new kind.** A `Cap<File>` minted by
//! `SYS_FILE_OPEN_TYPED` names a descriptor (resource = the descriptor
//! number, always below `MAX_FDS_PER_PROC`). A tree grant is the same kind
//! with a resource at or above [`TREE_RESOURCE_BASE`], an index into the
//! table below. The two ranges cannot meet (checked at compile time), and
//! every place that turns a `Cap<File>` into a descriptor refuses a tree
//! resource as the wrong kind of object (`handlers.rs::file_fd_for`,
//! `sys_close_typed`, `ioring_ops.rs::file_io`).
//!
//! **Why a path, and why this table.** A filesystem mounted from a block
//! device has no inode the VFS keeps (FAT32 directories are not in the
//! inode table), so a descriptor-based directory handle cannot name one.
//! The tree is named by its absolute path, interned once here at seed time:
//! the capability carries the index, not the bytes.
//!
//! **The only minter is the topology** (`cap_seed`, kind `"file"`, target the
//! absolute path of the tree's root). Targets are refused, not normalised
//! into something else: relative, containing a `.` or `..` component, longer
//! than [`TREE_PATH_MAX`] bytes, or asking for anything but read and/or
//! write (a tree grant carries no `DUP`, so it cannot be handed on).

use crate::cap::{targets, Cap, CapPerms};
use azos_sync::SpinLock;

/// First resource value that names a tree rather than a descriptor.
pub const TREE_RESOURCE_BASE: u32 = 0x4000_0000;

/// Distinct trees the topology can name, across all tasks.
pub const MAX_TREES: usize = 16;

/// Longest tree root, in bytes (after normalisation).
pub const TREE_PATH_MAX: usize = 64;

// A descriptor number can never be read as a tree.
const _: () = assert!((azos_limits::MAX_FDS_PER_PROC as u64) < TREE_RESOURCE_BASE as u64);

struct Trees {
    paths: [[u8; TREE_PATH_MAX]; MAX_TREES],
    lens:  [u8; MAX_TREES],
    count: usize,
}

static TREES: SpinLock<Trees> = SpinLock::new(Trees {
    paths: [[0; TREE_PATH_MAX]; MAX_TREES],
    lens:  [0; MAX_TREES],
    count: 0,
});

/// Does `resource` name a tree rather than a descriptor?
#[inline]
pub const fn is_tree_resource(resource: u32) -> bool {
    resource >= TREE_RESOURCE_BASE
}

/// Split an absolute path into its components, `//` collapsed, `None` when
/// it is relative or has a `.`/`..` component (neither is resolved here:
/// the filesystem, not this check, would give them meaning — FAT32
/// directories carry `..` entries). A trailing `/` is allowed.
fn components(path: &[u8]) -> Option<impl Iterator<Item = &[u8]> + Clone> {
    if path.first() != Some(&b'/') { return None; }
    let it = path.split(|&b| b == b'/').filter(|c| !c.is_empty());
    if it.clone().any(|c| c == b"." || c == b"..") { return None; }
    Some(it)
}

/// Is `path` a path the tree calls accept from ring 3: absolute, with no
/// `.`/`..` component?
pub fn path_is_plain(path: &[u8]) -> bool {
    components(path).is_some()
}

/// Does the tree rooted at `root` cover `path`? `strict`: `path` must lie
/// under the root (an entry of the tree); otherwise the root itself counts
/// too. Component-wise, so `/fatx` is not under `/fat`. A path that is not
/// plain is covered by nothing.
pub fn tree_covers_path(root: &[u8], path: &[u8], strict: bool) -> bool {
    let (Some(mut r), Some(mut p)) = (components(root), components(path)) else {
        return false;
    };
    loop {
        match (r.next(), p.next()) {
            (None, None) => return !strict,
            (None, Some(_)) => return true,
            (Some(_), None) => return false,
            (Some(a), Some(b)) if a == b => {}
            _ => return false,
        }
    }
}

/// Normalise a topology target into `out`: `//` collapsed, no trailing `/`
/// (`/` alone for the root). `None` for a target this module refuses.
fn normalise(target: &[u8], out: &mut [u8; TREE_PATH_MAX]) -> Option<usize> {
    let comps = components(target)?;
    let mut n = 0usize;
    for c in comps {
        let end = n.checked_add(1)?.checked_add(c.len())?;
        if end > TREE_PATH_MAX { return None; }
        out[n] = b'/';
        out[n + 1..end].copy_from_slice(c);
        n = end;
    }
    if n == 0 {
        out[0] = b'/';
        n = 1;
    }
    Some(n)
}

/// Intern `target` and return its resource, or `None` when the target is
/// refused or the table is full. The same tree named twice (by two tasks,
/// or spelt `/fat/` and `/fat`) is one entry.
pub fn tree_resource(target: &[u8]) -> Option<u32> {
    let mut norm = [0u8; TREE_PATH_MAX];
    let n = normalise(target, &mut norm)?;
    let mut t = TREES.lock();
    for i in 0..t.count {
        if t.lens[i] as usize == n && t.paths[i][..n] == norm[..n] {
            return Some(TREE_RESOURCE_BASE + i as u32);
        }
    }
    if t.count >= MAX_TREES { return None; }
    let i = t.count;
    t.paths[i] = norm;
    t.lens[i] = n as u8;
    t.count += 1;
    Some(TREE_RESOURCE_BASE + i as u32)
}

/// The set of interned trees that cover `path`, as a bit per tree index
/// (bit `i` = resource `TREE_RESOURCE_BASE + i`). Taken under the table's
/// lock and returned by value, so a caller then asks its capability table
/// without holding this one.
pub fn trees_covering(path: &[u8], strict: bool) -> u32 {
    let t = TREES.lock();
    let mut mask = 0u32;
    for i in 0..t.count {
        let n = t.lens[i] as usize;
        if tree_covers_path(&t.paths[i][..n], path, strict) {
            mask |= 1 << i;
        }
    }
    mask
}

/// Is `resource` a tree whose bit is set in `mask` (from [`trees_covering`])?
#[inline]
pub const fn tree_in(resource: u32, mask: u32) -> bool {
    if !is_tree_resource(resource) { return false; }
    let i = resource - TREE_RESOURCE_BASE;
    i < MAX_TREES as u32 && mask & (1 << i) != 0
}

/// Mint a tree `Cap<File>` for `target` into `tid`.
///
/// Refused for a target [`tree_resource`] refuses, a full table, or `perms`
/// other than read and/or write.
pub fn file_tree_grant_cap(tid: u32, target: &str, perms: CapPerms) -> Option<Cap<targets::File>> {
    let bits = perms.bits();
    if bits == 0 || bits & !CapPerms::RW.bits() != 0 {
        return None;
    }
    let resource = tree_resource(target.as_bytes())?;
    crate::cap_store::grant::<targets::File>(tid, perms, resource)
}

/// Empty the table (host tests only).
#[doc(hidden)]
pub fn reset_for_tests() {
    let mut t = TREES.lock();
    t.count = 0;
    t.lens = [0; MAX_TREES];
}

// MAX_TREES bits fit the mask.
const _: () = assert!(MAX_TREES <= 32);

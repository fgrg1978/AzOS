// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! U09-1 QEMU/board proof: `MAX_FILES + 1` create+unlink cycles through the
//! ramfs fallback path — the same path `sys_open(O_CREAT)` on any name
//! outside `/fat`, followed by `sys_unlink`, drives from ring 3
//! (`handlers.rs:1088,1450` -> `vfs::vfs_open`'s create branch / `path_parent`
//! + `dir_remove_entry`). The host test in `tests/host/fs-tests/src/lib.rs`
//! (`inode_leak` module) proves the same property against a hand-built
//! `FS` pool; this prints one line so the gate can also observe it on a
//! live boot, not just on the host.
//!
//! Opt-in via `feature = "fs-inode-probe"` (`crates/fs/fs/Cargo.toml`). The one
//! caller is a one-line hook in `kernel/src/main.rs`'s boot path, delivered
//! as a diff — `main.rs` is not this front's file to edit directly.

#[cfg(feature = "fs-inode-probe")]
use crate::vfs;

/// Run `MAX_FILES + 1` create/unlink cycles against the ramfs fallback.
///
/// Before the U09-1 fix, `inode_alloc` pre-counted the directory entry's
/// link (`link_count = 1` at alloc, `+1` again at `dir_add_entry`), so
/// `dir_remove_entry`'s single decrement on unlink never reached 0 and the
/// inode was never freed: the `(MAX_FILES + 1)`th cycle's `vfs_open` fails
/// with the pool exhausted. After the fix every cycle frees its inode and
/// all `MAX_FILES + 1` cycles complete. Either outcome is printed — this
/// probe never panics on failure, so a regression shows up as a grep-able
/// line instead of a silent hang.
#[cfg(not(feature = "fs-inode-probe"))]
pub fn inode_leak_probe() {}

#[cfg(feature = "fs-inode-probe")]
pub fn inode_leak_probe() {
    let mut t = vfs::ScratchFds::new();
    let mut completed = 0usize;
    let total = vfs::MAX_FILES + 1;

    for i in 0..total {
        let path = alloc::format!("/probe{i}");

        let fd = vfs::vfs_open(&mut t, path.as_bytes(), vfs::O_WRONLY | vfs::O_CREAT);
        if fd < 0 {
            azos_drv_sys::kprintln!(
                "[FS] inode probe: OPEN FAILED at cycle {} of {} — inode leak reproduced",
                i, total,
            );
            return;
        }
        vfs::vfs_close(&mut t, fd);

        // Mirrors `kernel/src/boot/seams.rs`'s `unlink()`: `path_parent` +
        // `dir_remove_entry`. `vfs.rs` has no `vfs_unlink` of its own.
        let (parent_idx, name) = vfs::path_parent(path.as_bytes());
        if parent_idx == vfs::NO_IDX || name.is_empty()
            || vfs::dir_remove_entry(parent_idx, name).is_err()
        {
            azos_drv_sys::kprintln!(
                "[FS] inode probe: UNLINK FAILED at cycle {} of {}",
                i, total,
            );
            return;
        }
        completed += 1;
    }

    azos_drv_sys::kprintln!(
        "[FS] inode probe: {} cycles, open still succeeds", completed,
    );
}

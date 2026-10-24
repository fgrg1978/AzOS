// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The memory family: `SYS_MO_CREATE`, `SYS_MO_MAP` and `SYS_MO_UNMAP`.
//!
//! A memory object is anonymous memory the caller owns (handle 0, a plain
//! mapping with no object behind it) or a `Cap<Shm>` region it holds a handle
//! for. `mo_create` makes the region (and its copy-on-write clones: a bit of
//! the creation word); `mo_map` maps either; `mo_unmap` unmaps either and, for a
//! region, gives the caller's references back. The bodies are the handlers
//! that were calls of their own (`sys_mmap`, `sys_munmap`,
//! `sys_shm_map_typed`, `sys_shm_release_typed`); this file only chooses.

use azos_abi::cap::{ty, CapHandle, CapType};
use azos_abi::error::Errno;

/// What a handle in the first argument names: nothing (0, anonymous memory), a
/// region, or something that is not memory.
enum Target {
    Anonymous,
    Region,
    Other,
}

fn target(handle: u64) -> Target {
    if handle == 0 {
        return Target::Anonymous;
    }
    let Ok(raw) = u32::try_from(handle) else { return Target::Other };
    match CapType::from_raw(CapHandle::from_raw(raw).kind()) {
        Some(t) if t == ty::SHM => Target::Region,
        _ => Target::Other,
    }
}

/// `SYS_MO_MAP`: `a0` a region handle, or 0 for anonymous memory.
///
/// * Anonymous (`a0` 0): `a1` the address hint, `a2` the length, `a3` the
///   protection (`PROT_READ|PROT_WRITE`; executable is refused), `a4` the flags
///   (`MAP_POPULATE`, `MAP_LOCKED`, `MAP_FIXED_NOREPLACE`: Linux's values).
///   Returns the address. Placed by `handlers::mmap_place`: at the break for a
///   native task (the hint unread; its `MAP_FIXED_NOREPLACE` is `lxsrv`'s
///   module window, `crate::module_window`), in its mmap area for a Linux
///   task.
/// * A region: `a1` 0 to map it (or the protect form: see
///   `sys_shm_map_typed`). Returns the address.
///
/// A handle that is not memory is `-ECAPKIND`.
pub fn sys_mo_map(a0: u64, a1: u64, a2: u64, a3: u64, a4: u64) -> i64 {
    match target(a0) {
        Target::Anonymous => crate::handlers::sys_mmap(a1, a2, a3, a4, u64::MAX, 0),
        Target::Region => crate::ipc_handlers::sys_shm_map_typed(a0, a1),
        Target::Other => Errno::ECAPKIND.to_syscall_ret(),
    }
}

/// `SYS_MO_UNMAP`: `a0` a region handle (the caller's mapping of it goes, and its
/// references), or 0 with `a1` the address and `a2` the length of anonymous
/// memory to unmap.
pub fn sys_mo_unmap(a0: u64, a1: u64, a2: u64) -> i64 {
    match target(a0) {
        Target::Anonymous => crate::handlers::sys_munmap(a1, a2),
        Target::Region => crate::ipc_handlers::sys_shm_release_typed(a0),
        Target::Other => Errno::ECAPKIND.to_syscall_ret(),
    }
}

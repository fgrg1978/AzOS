// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Memory: anonymous mappings, over the memory family (`SYS_MO_MAP`,
//! `SYS_MO_UNMAP`). There is no program break.
//!
//! The native memory family maps memory objects. The only object this layer
//! creates is anonymous memory, so `mmap` is the anonymous form: a file is
//! not memory (read it), and the kernel places the mapping where it likes
//! (`MAP_FIXED` and an address hint are refused / ignored). That is what the
//! allocator (dlmalloc over `mmap`) and the TLS and stack mappings of relibc
//! itself need.

use super::{check, nosys};
use crate::{
    error::{Errno, Result},
    header::{
        errno::{EACCES, EINVAL, ENOMEM},
        sys_mman::{MAP_ANONYMOUS, MAP_FIXED, PROT_EXEC},
    },
    platform::types::{c_int, c_void, off_t},
};

pub(crate) unsafe fn mmap(
    addr: *mut c_void,
    len: usize,
    prot: c_int,
    flags: c_int,
    fildes: c_int,
    _off: off_t,
) -> Result<*mut c_void> {
    if flags & MAP_ANONYMOUS == 0 || fildes != -1 {
        // A mapping of a file: the node ops read and write it, they do not map it.
        return nosys();
    }
    if flags & MAP_FIXED != 0 || len == 0 {
        return Err(Errno(EINVAL));
    }
    if prot & PROT_EXEC != 0 {
        // Code is mapped by the loader from a signed image, never by the program.
        return Err(Errno(EACCES));
    }
    let r = azos_libsys::mmap(addr as u64, len as u64, prot as u64, flags as u64, azos_libsys::MAP_ANON_FD, 0);
    // "-1": the mapping could not be made.
    if r == -1 {
        return Err(Errno(ENOMEM));
    }
    Ok(check(r)? as *mut c_void)
}

pub(crate) unsafe fn munmap(addr: *mut c_void, len: usize) -> Result<()> {
    check(azos_libsys::munmap(addr as u64, len as u64)).map(|_| ())
}

pub(crate) unsafe fn mprotect(_addr: *mut c_void, _len: usize, _prot: c_int) -> Result<()> {
    // A mapping keeps the rights it was made with.
    nosys()
}

/// There is no program break: the allocator and everything else that wants
/// memory maps it (`mmap`), so `brk` and `sbrk` are not answered.
pub(crate) fn brk(_addr: *mut c_void) -> Result<*mut c_void> {
    nosys()
}

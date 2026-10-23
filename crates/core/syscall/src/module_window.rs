// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The module window of a Linux driver server: `SYS_MO_MAP` with
//! [`MMAP_MAP_FIXED_NOREPLACE`] places anonymous memory at an exact address
//! inside it, and `DOMAIN_MODULE_MAP_X` refuses module text outside it.
//!
//! Kconfig `LX_MODULE_WINDOW_BASE` and `LX_MODULE_WINDOW_SIZE` say where it
//! is; `crates/core/sched/src/process.rs` checks at build time that it is
//! page-aligned, clear of the break and of the vDSO, and within an aarch64
//! direct branch of the lowest user address, which keeps every relocation of
//! a module placed in it within reach on all three ISAs.
//!
//! The placement is honoured only for a task that holds a live module token
//! (it called `DOMAIN_MODULE_VERIFY` and has not mapped that module yet), so
//! only a Linux driver server, in the middle of loading a module, uses it.
//! Every other native mapping keeps the bump at the break. It replaces
//! nothing: a page already mapped in the range answers `EEXIST`, a page the
//! kernel maps for itself (riscv64 shares the low gigabyte with the kernel's
//! device windows) `EINVAL`. The pages are committed at once and never
//! executable; only `DOMAIN_MODULE_MAP_X` flips text to read-execute.

use azos_abi::error::Errno;

pub use azos_abi::syscall_nr::MMAP_MAP_FIXED_NOREPLACE;

/// `[base, end)` of the window.
pub const fn window() -> (usize, usize) {
    (azos_limits::LX_MODULE_WINDOW_BASE, azos_limits::LX_MODULE_WINDOW_BASE + azos_limits::LX_MODULE_WINDOW_SIZE)
}

/// Does `[start, end)` lie inside the window?
pub fn contains(start: usize, end: usize) -> bool {
    let (lo, hi) = window();
    start < end && start >= lo && end <= hi
}

/// May the calling task place memory in the window? Only with the module
/// loader, and only while it holds a live module token.
pub fn caller_may_place() -> bool {
    #[cfg(feature = "lx-loader")]
    {
        crate::module_ops::caller_holds_token()
    }
    #[cfg(not(feature = "lx-loader"))]
    {
        false
    }
}

/// `SYS_MO_MAP` with [`MMAP_MAP_FIXED_NOREPLACE`] in `user_pt`: `addr`, or
/// `-EPERM` (`allowed` is false: the caller holds no module token),
/// `-EINVAL` (not page-aligned, outside the window, `PROT_NONE`, or a page
/// the kernel maps), `-EEXIST` (a page of the range is mapped), `-ENOMEM`
/// (the frame budget or the frames ran out; nothing stays mapped). The caller
/// holds the address-space lock and has refused `PROT_EXEC`.
pub fn map_fixed(user_pt: usize, addr: u64, len: usize, prot: u64, allowed: bool) -> i64 {
    if !allowed {
        return Errno::EPERM.to_syscall_ret();
    }
    let page = azos_arch::PAGE_SIZE;
    let start = addr as usize;
    if start % page != 0 || prot & (crate::handlers::MMAP_PROT_READ | crate::handlers::MMAP_PROT_WRITE) == 0 {
        return Errno::EINVAL.to_syscall_ret();
    }
    let pages = len.div_ceil(page);
    let Some(end) = pages.checked_mul(page).and_then(|s| start.checked_add(s)) else {
        return Errno::EINVAL.to_syscall_ret();
    };
    if !contains(start, end) {
        return Errno::EINVAL.to_syscall_ret();
    }
    let mut va = start;
    while va < end {
        if azos_mm::vmm::va_is_kernel_mapped(va) {
            return Errno::EINVAL.to_syscall_ret();
        }
        if azos_mm::vmm::translate_user(user_pt, va, false).is_some() {
            return Errno::EEXIST.to_syscall_ret();
        }
        va += page;
    }
    if !azos_sched::mm_charge(pages as u32) {
        return Errno::ENOMEM.to_syscall_ret();
    }
    let writable = prot & crate::handlers::MMAP_PROT_WRITE != 0;
    let perms = azos_arch_api::PagePerms {
        accessed: true, dirty: writable, write: writable,
        ..azos_arch_api::PagePerms::USER_RW
    };
    let mut va = start;
    while va < end {
        let mapped = match azos_mm::pmm::alloc_page() {
            Ok(frame) => {
                let ok = azos_mm::vmm::map(user_pt, va, frame.as_usize(), perms).is_ok();
                if !ok {
                    let _ = azos_mm::pmm::free_page(frame);
                }
                ok
            }
            Err(_) => false,
        };
        if !mapped {
            crate::handlers::mmap_unwind(user_pt, start, va);
            azos_sched::mm_discharge(pages as u32);
            return Errno::ENOMEM.to_syscall_ret();
        }
        va += page;
    }
    start as i64
}

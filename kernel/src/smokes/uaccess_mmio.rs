// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! ktest `uaccess_refuses_a_user_device_window` (front uaccess-mmio-buffer).
//!
//! A user device window (`DOMAIN_MMIO_MAP`: a `PagePerms::USER_MMIO_RW`
//! leaf) passed as a buffer must be `EFAULT`, never a kernel access through
//! `addr::phys_to_virt` of a frame the kernel's map of RAM does not hold.
//! The probe maps such a leaf over the first page past the RAM the kernel
//! maps (`vmm::ram_end`), so no device register is touched whatever the code
//! does. Before the fix the copy walked the leaf, then took a fatal kernel
//! page fault on aarch64 and x86_64 (linear and direct map hold RAM only)
//! and on riscv64 (identity, nothing mapped there).
//!
//! Host twin: `syscall-tests`' `uaccess_mmio` (canary `uaccess-mmio-canary`).

use azos_arch_api::{PagePerms, PAGE_SIZE};
use azos_mm::{uaccess, vmm};

/// A user VA below every ISA's user ceiling, above the null guard.
const PROBE_VA: usize = 0x1_0000;

azos_ktest::ktest! {
    fn uaccess_refuses_a_user_device_window() {
        let root = vmm::create_pagetable().map_err(|_| "no frame for the probe root")?;
        let pa = (vmm::ram_end() + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
        if vmm::map(root, PROBE_VA, pa, PagePerms::USER_MMIO_RW).is_err() {
            vmm::destroy_user_pagetable(root);
            return Err("the probe window did not map");
        }
        let mut b = [0u8; 64];
        let small_in = uaccess::copy_in(root, b.as_mut_ptr(), PROBE_VA, 8);
        let run_in = uaccess::copy_in(root, b.as_mut_ptr(), PROBE_VA, 64);
        let out = uaccess::copy_out(root, PROBE_VA, b.as_ptr(), 64);
        let s = uaccess::cstr_in(root, &mut b, PROBE_VA);
        // A device frame the PMM never owned: unmapped, not freed, as
        // `process::mmio_map_user`'s rollback does.
        vmm::unmap(root, PROBE_VA);
        vmm::destroy_user_pagetable(root);
        if small_in || run_in || out || s.is_some() {
            return Err("a user device window was copied through the kernel's map");
        }
        Ok(())
    }
}

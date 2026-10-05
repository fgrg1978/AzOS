// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
/// Newtype wrappers for physical and virtual addresses.
///
/// These prevent accidentally mixing physical and virtual addresses.

use azos_arch::mmu::{PAGE_SIZE, PAGE_SHIFT};

// ─────────────────────────────────────────────────────────────────────────
// phys_to_virt / virt_to_phys — aarch64 TTBR1 migration scaffold.
//
// **What this is.** A single, explicit conversion point for "I have a
// physical address a kernel-owned page table, PMM frame, or COW page lives
// at, and I need a pointer I can dereference." Every one of those sites
// used to write `pa as *mut T` directly, which was only correct while
// PA == VA for kernel memory.
//
// **The flip has happened (2026-09-24).** On an aarch64 KERNEL build
// `KERNEL_PHYS_TO_VIRT_OFFSET` is `KERNEL_VA_OFFSET`, not `0`:
// `kernel/linker-aarch64.ld` links the kernel in the upper half with a
// VMA/LMA split, `boot.S` jumps the PC there, and `TTBR0_EL1` keeps only
// device windows. So on that build `phys_to_virt(pa) != pa`, and a site
// that still writes `pa as *mut T` dereferences an address the kernel no
// longer maps — a fault, not silent corruption, which is the one mercy
// here. It stays `0` everywhere else (riscv64, and every host test
// build), where the identity still holds.
//
// The scaffold did its job: landing the call sites ahead of the flip meant
// the migration moved ONE line instead of forty-seven ad hoc casts. Twelve
// sites were nevertheless found dereferencing physical addresses directly
// during that migration — the ELF loader, user copies, io_ring pages, the
// virtio queues and their `desc.addr` reads among them. If you are adding a
// site that touches a PA, it goes through here.
//
// **What must NOT go through this.** Anything handed to a device that
// reads physical memory itself — a virtio ring/descriptor base, a DMA
// buffer physical address, PSCI's `entry_pa`, the value written into
// `TTBR0_EL1`/`TTBR1_EL1`/`satp` — is a PA by definition and must stay a
// PA. Wrapping one of those in `phys_to_virt` would be a bug the day the
// offset stops being zero. [`virt_to_phys`] is the explicit inverse for
// exactly that case: a symbol's own address (a VA once the kernel links
// high) that must be handed to hardware as a PA.
// aarch64 KERNEL builds only: the kernel links and executes in the upper
// half (TTBR1), so a symbol's own address sits this far above the physical
// byte the loader placed it at. `target_os = "none"` is load-bearing — a
// bare `target_arch = "aarch64"` also matches this Mac, and setting the
// offset for host test builds broke `mm-tests`/`syscall-tests` on 2026-09-23.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub const KERNEL_PHYS_TO_VIRT_OFFSET: usize = azos_arch::mmu::KERNEL_VA_OFFSET as usize;
#[cfg(not(all(target_arch = "aarch64", target_os = "none")))]
pub const KERNEL_PHYS_TO_VIRT_OFFSET: usize = 0;

/// Convert a physical address of kernel-owned memory (a page-table frame,
/// a PMM page, a COW page) into the address the kernel should dereference
/// it through. Identity on riscv64 and on host builds; a real translation
/// on an aarch64 kernel build — see the module doc above.
#[inline(always)]
pub const fn phys_to_virt(pa: usize) -> usize {
    pa + KERNEL_PHYS_TO_VIRT_OFFSET
}

/// Inverse of [`phys_to_virt`]: given the kernel's own view of an address
/// (typically `some_symbol as *const _ as usize`), produce the physical
/// address a device (PSCI, virtio, DMA) must be handed instead. Identity
/// today on both ISAs — see the module doc above.
#[inline(always)]
pub const fn virt_to_phys(va: usize) -> usize {
    va - KERNEL_PHYS_TO_VIRT_OFFSET
}

/// A physical address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(transparent)]
pub struct PhysAddr(pub usize);

/// A virtual address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(transparent)]
pub struct VirtAddr(pub usize);

impl PhysAddr {
    #[inline]
    pub const fn new(addr: usize) -> Self {
        Self(addr)
    }

    #[inline]
    pub const fn as_usize(self) -> usize {
        self.0
    }

    /// Convert to a raw pointer, through [`phys_to_virt`] — identity today
    /// (see this module's doc), the kernel's high-half address once the
    /// aarch64 TTBR1 migration links the kernel there.
    #[inline]
    pub fn as_ptr<T>(self) -> *const T {
        phys_to_virt(self.0) as *const T
    }

    /// Convert to a mutable raw pointer, through [`phys_to_virt`] — see
    /// [`PhysAddr::as_ptr`].
    #[inline]
    pub fn as_mut_ptr<T>(self) -> *mut T {
        phys_to_virt(self.0) as *mut T
    }

    #[inline]
    pub const fn page_number(self) -> usize {
        self.0 >> PAGE_SHIFT
    }

    #[inline]
    pub const fn page_offset(self) -> usize {
        self.0 & (PAGE_SIZE - 1)
    }

    #[inline]
    pub const fn is_page_aligned(self) -> bool {
        self.0 & (PAGE_SIZE - 1) == 0
    }

    #[inline]
    pub const fn page_align_up(self) -> Self {
        Self((self.0 + PAGE_SIZE - 1) & !(PAGE_SIZE - 1))
    }

    #[inline]
    pub const fn page_align_down(self) -> Self {
        Self(self.0 & !(PAGE_SIZE - 1))
    }

    #[inline]
    pub const fn offset(self, bytes: usize) -> Self {
        Self(self.0 + bytes)
    }
}

impl VirtAddr {
    #[inline]
    pub const fn new(addr: usize) -> Self {
        Self(addr)
    }

    #[inline]
    pub const fn as_usize(self) -> usize {
        self.0
    }

    #[inline]
    pub const fn is_page_aligned(self) -> bool {
        self.0 & (PAGE_SIZE - 1) == 0
    }

    #[inline]
    pub const fn page_align_up(self) -> Self {
        Self((self.0 + PAGE_SIZE - 1) & !(PAGE_SIZE - 1))
    }
}

impl core::fmt::LowerHex for PhysAddr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::LowerHex::fmt(&self.0, f)
    }
}

impl core::fmt::LowerHex for VirtAddr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::LowerHex::fmt(&self.0, f)
    }
}

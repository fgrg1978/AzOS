// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Device registers: the one way the tree reads and writes MMIO, in the kernel
//! and in a ring-3 driver. `tools/lint/mmio_accessors.py` keeps it the only way.
//!
//! On aarch64 every access is one `ldr`/`str` of the register's width with a
//! bare base register, in `asm!` because `read_volatile`/`write_volatile` leave
//! the addressing mode to the compiler. A trapped writeback or pair access to a
//! device reaches the hypervisor with ISV=0, no syndrome saying which register
//! and how wide, so it cannot be emulated: HVF aborts the VM on it.
//!
//! No `nomem` or `readonly`: the access has device effects and must stay ordered
//! with the memory around it as written. The other ISAs have no such form to
//! avoid; a volatile access is what they need.

macro_rules! accessors {
    ($($t:ty, $read:ident, $write:ident, $ldr:literal, $str:literal;)*) => {$(
        /// One read of the register at `addr`.
        ///
        /// # Safety
        /// `addr` is a mapped register of this width, aligned to it, and
        /// reading it is what the caller means, side effects included.
        #[inline(always)]
        pub unsafe fn $read(addr: usize) -> $t {
            #[cfg(target_arch = "aarch64")]
            {
                let v: $t;
                // SAFETY: the caller's contract; a bare base has no writeback.
                unsafe {
                    core::arch::asm!($ldr, a = in(reg) addr, v = out(reg) v,
                        options(nostack, preserves_flags));
                }
                v
            }
            #[cfg(not(target_arch = "aarch64"))]
            // SAFETY: the caller's contract.
            unsafe {
                core::ptr::read_volatile(addr as *const $t)
            }
        }

        /// One write of the register at `addr`.
        ///
        /// # Safety
        /// `addr` is a mapped register of this width, aligned to it, and
        /// writing `v` to it is what the caller means.
        #[inline(always)]
        pub unsafe fn $write(addr: usize, v: $t) {
            #[cfg(target_arch = "aarch64")]
            // SAFETY: the caller's contract; a bare base has no writeback.
            unsafe {
                core::arch::asm!($str, a = in(reg) addr, v = in(reg) v,
                    options(nostack, preserves_flags));
            }
            #[cfg(not(target_arch = "aarch64"))]
            // SAFETY: the caller's contract.
            unsafe {
                core::ptr::write_volatile(addr as *mut $t, v)
            }
        }
    )*};
}

accessors! {
    u8,  read8,  write8,  "ldrb {v:w}, [{a}]", "strb {v:w}, [{a}]";
    u16, read16, write16, "ldrh {v:w}, [{a}]", "strh {v:w}, [{a}]";
    u32, read32, write32, "ldr {v:w}, [{a}]",  "str {v:w}, [{a}]";
    u64, read64, write64, "ldr {v:x}, [{a}]",  "str {v:x}, [{a}]";
}

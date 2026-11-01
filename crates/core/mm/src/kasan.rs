// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Kernel address sanitizer (Kconfig `KASAN`, development builds):
//! the compiler calls `__asan_load<N>` / `__asan_store<N>` before every
//! access of the kernel's own code, and a shadow byte per 8 bytes of RAM says
//! how much of the granule may be touched.
//!
//! Shadow of an address `a` inside the RAM map: `shadow_va + (a - ram_va) / 8`.
//! `0` is a granule fully accessible, `1..=7` the first bytes of it only, the
//! values with the top bit set are poison ([`REDZONE`], [`FREED`]). The map is
//! the linear map of RAM; every other address (the image, MMIO, user space)
//! is not checked. Every hook returns at once until [`init`] has zeroed the
//! shadow, so the code that runs before it is simply not checked.
//!
//! Poisoned by the heap guard (`kheap_guard.rs`): its red zones while a block
//! is live, the whole block while it sits in quarantine. Stacks, globals and
//! frames are not poisoned.
//!
//! The hook path calls nothing: `core` is built with the sanitizer too, and
//! LLVM does not inline an instrumented function into one with the sanitizer
//! off, so an atomic's `load` or `Ord::min` in a hook is an instrumented call
//! back into the hook, without end. The state is `static mut`, read with
//! plain derefs, and the arithmetic is written out.

#![allow(static_mut_refs)]

/// Shadow value of a heap red zone.
pub const REDZONE: u8 = 0xfa;
/// Shadow value of a freed heap block.
pub const FREED: u8 = 0xfd;

static mut READY: bool = false;
static mut RAM_VA: usize = 0;
static mut RAM_LEN: usize = 0;
static mut SHADOW_VA: usize = 0;
/// Set while a report is being written: the report's own accesses are not
/// checked.
static mut REPORTING: bool = false;
/// Open [`expect`] scopes.
static mut EXPECTING: usize = 0;
static mut COUNT: usize = 0;
static mut LAST_ADDR: usize = 0;
static mut LAST_SIZE: usize = 0;
static mut LAST_WRITE: bool = false;
static mut LAST_SHADOW: u8 = 0;

/// Bytes of shadow for `ram_len` bytes of RAM.
pub const fn shadow_bytes(ram_len: usize) -> usize {
    ram_len / 8
}

/// Start checking: `[ram_va, ram_va + ram_len)` is the linear map of RAM and
/// `shadow_va` the kernel address of [`shadow_bytes`] bytes nobody else uses.
///
/// # Safety
/// The shadow range is mapped, writable and exclusively the sanitizer's.
#[sanitize(address = "off")]
pub unsafe fn init(ram_va: usize, ram_len: usize, shadow_va: usize) {
    unsafe {
        let n = shadow_bytes(ram_len);
        let mut i = 0;
        while i < n {
            *((shadow_va + i) as *mut u8) = 0;
            i += 1;
        }
        RAM_VA = ram_va;
        RAM_LEN = ram_len;
        SHADOW_VA = shadow_va;
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        READY = true;
    }
}

/// Reserve the shadow (an eighth of the RAM the PMM manages, out of the free
/// frames after the heap's) and start checking; the bytes reserved, or `None`
/// when no free run is big enough (the kernel then runs unchecked).
pub fn boot() -> Option<usize> {
    let (pa, len) = crate::pmm::managed_range();
    let n = shadow_bytes(len);
    let at = crate::pmm::first_free_run(n)?;
    crate::pmm::reserve_range(at, n);
    unsafe { init(crate::addr::phys_to_virt(pa), len, crate::addr::phys_to_virt(at)) };
    Some(n)
}

/// Mark `[addr, addr + len)` with `val`; both ends 8-aligned.
#[sanitize(address = "off")]
pub fn poison(addr: usize, len: usize, val: u8) {
    unsafe {
        if !READY || addr < RAM_VA || addr - RAM_VA >= RAM_LEN {
            return;
        }
        let mut s = SHADOW_VA + ((addr - RAM_VA) >> 3);
        let end = s + (len >> 3);
        while s < end {
            *(s as *mut u8) = val;
            s += 1;
        }
    }
}

/// Make `[addr, addr + size)` accessible: `addr` 8-aligned, a partial last
/// granule keeps its trailing bytes inaccessible.
#[sanitize(address = "off")]
pub fn unpoison(addr: usize, size: usize) {
    unsafe {
        if !READY || addr < RAM_VA || addr - RAM_VA >= RAM_LEN {
            return;
        }
        let mut s = SHADOW_VA + ((addr - RAM_VA) >> 3);
        let end = s + (size >> 3);
        while s < end {
            *(s as *mut u8) = 0;
            s += 1;
        }
        if size & 7 != 0 {
            *(s as *mut u8) = (size & 7) as u8;
        }
    }
}

#[cold]
#[inline(never)]
#[sanitize(address = "off")]
fn report(addr: usize, size: usize, write: bool, shadow: u8) {
    unsafe {
        REPORTING = true;
        if core::ptr::read_volatile(core::ptr::addr_of!(EXPECTING)) != 0 {
            use core::ptr::{addr_of_mut, write_volatile as wr};
            wr(addr_of_mut!(COUNT), COUNT + 1);
            wr(addr_of_mut!(LAST_ADDR), addr);
            wr(addr_of_mut!(LAST_SIZE), size);
            wr(addr_of_mut!(LAST_WRITE), write);
            wr(addr_of_mut!(LAST_SHADOW), shadow);
            REPORTING = false;
            return;
        }
    }
    let what = match shadow {
        FREED => "use after free",
        REDZONE => "heap buffer overflow or underflow (red zone)",
        _ => "out of bounds",
    };
    panic!("KASAN: {} in a {} of size {} at {:#x} (shadow {:#04x})",
        what, if write { "write" } else { "read" }, size, addr, shadow);
}

/// The hook: refuse an access of `size` bytes at `addr` that touches a granule
/// whose shadow does not allow it.
#[sanitize(address = "off")]
fn check(addr: usize, size: usize, write: bool) {
    unsafe {
        if !READY || REPORTING || addr < RAM_VA || size > RAM_LEN {
            return;
        }
        let ram = RAM_VA;
        let len = RAM_LEN;
        if addr - ram >= len {
            return;
        }
        let end = addr + size;
        let mut g = addr & !7;
        while g < end {
            let off = g - ram;
            if off >= len {
                return;
            }
            let v = *((SHADOW_VA + (off >> 3)) as *const u8);
            if v != 0 {
                let hi = if end < g + 8 { end - g } else { 8 };
                // 1..=7: only the first `v` bytes of the granule may be touched.
                if (v as i8) < 0 || hi > v as usize {
                    report(addr, size, write, v);
                    return;
                }
            }
            g += 8;
        }
    }
}

/// What a scope of [`expect`] saw.
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct Finding {
    /// Findings in the scope.
    pub count: usize,
    /// The last one: the accessed address, the access size, whether it was a
    /// write, and the shadow byte that refused it.
    pub addr: usize,
    pub size: usize,
    pub write: bool,
    pub shadow: u8,
}

/// Run `f`, counting the sanitizer's findings instead of panicking on them.
/// The state is touched volatile: the instrumentation calls the hooks after the
/// optimizer has run, so the optimizer sees no reader of it and would drop the
/// scope's writes.
pub fn expect<R>(f: impl FnOnce() -> R) -> (R, Finding) {
    use core::ptr::{addr_of, addr_of_mut, read_volatile as rd, write_volatile as wr};
    unsafe {
        let before = rd(addr_of!(COUNT));
        wr(addr_of_mut!(EXPECTING), rd(addr_of!(EXPECTING)) + 1);
        let r = f();
        wr(addr_of_mut!(EXPECTING), rd(addr_of!(EXPECTING)) - 1);
        let fnd = Finding {
            count: rd(addr_of!(COUNT)) - before,
            addr: rd(addr_of!(LAST_ADDR)),
            size: rd(addr_of!(LAST_SIZE)),
            write: rd(addr_of!(LAST_WRITE)),
            shadow: rd(addr_of!(LAST_SHADOW)),
        };
        (r, fnd)
    }
}

macro_rules! hooks {
    ($($load:ident $store:ident $loadn:ident $storen:ident $n:expr;)*) => {$(
        #[no_mangle]
        #[sanitize(address = "off")]
        pub extern "C" fn $load(addr: usize) { check(addr, $n, false) }
        #[no_mangle]
        #[sanitize(address = "off")]
        pub extern "C" fn $store(addr: usize) { check(addr, $n, true) }
        #[no_mangle]
        #[sanitize(address = "off")]
        pub extern "C" fn $loadn(addr: usize) { check(addr, $n, false) }
        #[no_mangle]
        #[sanitize(address = "off")]
        pub extern "C" fn $storen(addr: usize) { check(addr, $n, true) }
    )*};
}

hooks! {
    __asan_load1 __asan_store1 __asan_load1_noabort __asan_store1_noabort 1;
    __asan_load2 __asan_store2 __asan_load2_noabort __asan_store2_noabort 2;
    __asan_load4 __asan_store4 __asan_load4_noabort __asan_store4_noabort 4;
    __asan_load8 __asan_store8 __asan_load8_noabort __asan_store8_noabort 8;
    __asan_load16 __asan_store16 __asan_load16_noabort __asan_store16_noabort 16;
}

#[no_mangle]
#[sanitize(address = "off")]
pub extern "C" fn __asan_loadN(addr: usize, size: usize) {
    check(addr, size, false)
}
#[no_mangle]
#[sanitize(address = "off")]
pub extern "C" fn __asan_storeN(addr: usize, size: usize) {
    check(addr, size, true)
}
#[no_mangle]
#[sanitize(address = "off")]
pub extern "C" fn __asan_loadN_noabort(addr: usize, size: usize) {
    check(addr, size, false)
}
#[no_mangle]
#[sanitize(address = "off")]
pub extern "C" fn __asan_storeN_noabort(addr: usize, size: usize) {
    check(addr, size, true)
}
/// The compiler calls this before a function that does not return.
#[no_mangle]
#[sanitize(address = "off")]
pub extern "C" fn __asan_handle_no_return() {}

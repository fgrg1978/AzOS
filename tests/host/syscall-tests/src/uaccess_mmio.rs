// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// Host tests for a user device window used as a buffer (front
// uaccess-mmio-buffer). A task that holds a `Device` capability maps its
// registers with `DOMAIN_MMIO_MAP` (`process::mmio_map_user`, a
// `PagePerms::USER_MMIO_*` leaf) and can pass that VA to `read`, `write` or
// any call taking a buffer. The walk used to accept the leaf: USER and R/W
// are set. The copy then went through `addr::phys_to_virt` of a device frame,
// and the kernel's map of RAM does not hold that frame. On aarch64 and x86_64
// the access is a fatal kernel page fault. On riscv64 it lands on whatever
// VA == PA maps in the task's table. Here the "device frame" is a host page
// outside the PMM arena, so the old code reads and writes it instead of
// faulting, and the tests see that.
//
// Canary `uaccess-mmio-canary` (`vmm::kernel_reaches` answers `true`): both
// tests fail.

use super::harness::serial;
use azos_arch::mmu::PAGE_SIZE;
use azos_arch_api::PagePerms;

/// A page-aligned host page the PMM does not manage: stands for a device
/// frame. Only these tests touch it, under `serial()`.
#[repr(C, align(4096))]
struct DevPage(core::cell::UnsafeCell<[u8; PAGE_SIZE]>);
unsafe impl Sync for DevPage {}
static DEV: DevPage = DevPage(core::cell::UnsafeCell::new([0; PAGE_SIZE]));

const VA: usize = 0x60_0000;

fn fresh_root() -> usize {
    let pt = azos_mm::pmm::alloc_page().expect("arena").as_usize();
    unsafe { core::ptr::write_bytes(pt as *mut u8, 0, PAGE_SIZE) };
    azos_mm::pager::forget(pt);
    pt
}

/// Svpbmt on for the guard's life (a riscv64 leaf then carries the device
/// type, as aarch64 and x86_64 leaves always do), off again after.
struct Pbmt;
impl Pbmt {
    fn on() -> Self {
        azos_arch::mmu::svpbmt_select(true, true);
        Pbmt
    }
}
impl Drop for Pbmt {
    fn drop(&mut self) {
        azos_arch::mmu::svpbmt_select(false, false);
    }
}

/// Every access path refuses `VA` of `pt`, and the frame behind it is left
/// as `fill` (nothing read through, nothing written).
fn refused_everywhere(pt: usize, frame: *mut u8, fill: u8) {
    let src = [0x5Au8; 64];
    assert!(!azos_mm::uaccess::copy_out(pt, VA, src.as_ptr(), 8), "small copy out");
    assert!(!azos_mm::uaccess::copy_out(pt, VA, src.as_ptr(), 64), "run copy out");
    let mut dst = [0u8; 64];
    assert!(!azos_mm::uaccess::copy_in(pt, dst.as_mut_ptr(), VA, 8), "small copy in");
    assert!(!azos_mm::uaccess::copy_in(pt, dst.as_mut_ptr(), VA, 64), "run copy in");
    assert_eq!(azos_mm::uaccess::copy_in_resident(pt, dst.as_mut_ptr(), VA, 64), 0, "resident read");
    assert_eq!(azos_mm::uaccess::cstr_in(pt, &mut dst, VA), None, "string");
    assert_eq!(azos_mm::uaccess::cas_u32(pt, VA, 0, 1, true), Err(None), "cas");
    assert_eq!(azos_mm::uaccess::cas_u32(pt, VA, 0, 1, false), Err(None), "cas, no fault-in");
    assert!(azos_mm::vmm::translate_user(pt, VA, true).is_none(), "translate for a write");
    assert!(!azos_mm::vmm::user_write_would_be_permitted(pt, VA), "write query");
    for k in 0..64 {
        assert_eq!(unsafe { *frame.add(k) }, fill, "byte {k} of the device frame changed");
    }
}

/// riscv64 without Svpbmt: the leaf has no memory type, the frame is outside
/// RAM. This is the case of every device window on aarch64 and on riscv64.
#[test]
fn a_device_window_outside_ram_is_refused() {
    let _g = serial();
    let frame = DEV.0.get() as *mut u8;
    assert!(azos_mm::pmm::frame_index(frame as usize).is_none(), "the stand-in must lie outside the PMM arena");
    unsafe { core::ptr::write_bytes(frame, 0, PAGE_SIZE) };
    let pt = fresh_root();
    azos_mm::vmm::map(pt, VA, frame as usize, PagePerms::USER_MMIO_RW).expect("map");
    refused_everywhere(pt, frame, 0);
    // Control: the same VA over a RAM frame is accepted.
    let pt2 = fresh_root();
    let ram = azos_mm::pmm::alloc_page().expect("arena").as_usize();
    azos_mm::vmm::map(pt2, VA, ram, PagePerms::USER_RW).expect("map");
    let v = 7u64;
    assert!(azos_mm::uaccess::copy_out(pt2, VA, &v as *const u64 as *const u8, 8));
}

/// A device-typed leaf over a frame inside the PMM's span (x86_64: a device
/// in the 32-bit hole when RAM continues above 4 GiB): the type refuses it.
#[test]
fn a_device_typed_leaf_inside_the_pmm_span_is_refused() {
    let _g = serial();
    let _p = Pbmt::on();
    let frame = azos_mm::pmm::alloc_page().expect("arena").as_usize() as *mut u8;
    unsafe { core::ptr::write_bytes(frame, 0xA5, PAGE_SIZE) };
    let pt = fresh_root();
    azos_mm::vmm::map(pt, VA, frame as usize, PagePerms::USER_MMIO_RW).expect("map");
    refused_everywhere(pt, frame, 0xA5);
}

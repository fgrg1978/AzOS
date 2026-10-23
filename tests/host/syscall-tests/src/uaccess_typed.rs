// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// Host tests for the typed user pointers (`crates/core/sched/src/uptr.rs`,
// the real file, pulled by the sched shim) over the real copy loops, and for
// the driver request's byte image that replaced copying the struct whole.
//
// Canaries (run by hand, recorded in the front's report): `read_into`
// without its length check reads past the slice
// (`a_slice_never_reaches_past_its_length` fails); `to_bytes` copying the
// struct whole hands the padding out (`the_request_image_has_no_stale_padding`
// fails).

use super::harness::serial;
use azos_arch::mmu::PAGE_SIZE;
use azos_arch_api::PagePerms;
use azos_sched::{Efault, UserCStr, UserPtr, UserSlice};

const VA: usize = 0x60_0000;

/// The current task's address space: one page at [`VA`]; its frame.
fn space() -> usize {
    let pt = azos_mm::pmm::alloc_page().expect("arena").as_usize();
    unsafe { core::ptr::write_bytes(pt as *mut u8, 0, PAGE_SIZE) };
    azos_mm::pager::forget(pt);
    let fr = azos_mm::pmm::alloc_page().expect("arena").as_usize();
    unsafe { core::ptr::write_bytes(fr as *mut u8, 0, PAGE_SIZE) };
    azos_mm::vmm::map(pt, VA, fr, PagePerms::USER_RW).expect("map");
    azos_sched::set_current_user_pt(pt);
    azos_sched::set_current_task_tid(1);
    fr
}

#[test]
fn a_value_goes_out_and_comes_back() {
    let _g = serial();
    let fr = space();
    let p = UserPtr::<u64>::new(VA as u64 + 8);
    assert_eq!(p.write(&0x1122_3344_5566_7788), Ok(()));
    assert_eq!(unsafe { *((fr + 8) as *const u64) }, 0x1122_3344_5566_7788);
    assert_eq!(p.read(), Ok(0x1122_3344_5566_7788));
    let d = azos_abi::ipc_msg::MsgDesc { version: 3, n_words: 2, badge: 9, ..Default::default() };
    let q = UserPtr::<azos_abi::ipc_msg::MsgDesc>::new(VA as u64 + 64);
    assert_eq!(q.write(&d), Ok(()));
    assert_eq!(q.read(), Ok(d));
    // The end of the page: the read would cross into nothing.
    assert_eq!(UserPtr::<u64>::new((VA + PAGE_SIZE - 4) as u64).read(), Err(Efault));
    assert_eq!(UserPtr::<u32>::new(0).read(), Err(Efault), "null is no user address");
    azos_sched::set_current_user_pt(0);
}

#[test]
fn a_slice_never_reaches_past_its_length() {
    let _g = serial();
    let fr = space();
    for i in 0..32u8 {
        unsafe { *((fr + i as usize) as *mut u8) = i };
    }
    let s = UserSlice::<u8>::new(VA as u64, 8);
    let mut eight = [0u8; 8];
    assert_eq!(s.read_into(&mut eight), Ok(()));
    assert_eq!(eight, [0, 1, 2, 3, 4, 5, 6, 7]);
    // A buffer longer than the slice is a fault, not a read of 16 bytes.
    let mut sixteen = [0xFFu8; 16];
    assert_eq!(s.read_into(&mut sixteen), Err(Efault));
    assert_eq!(sixteen, [0xFF; 16], "nothing was read");
    assert_eq!(s.write_from(&[9u8; 9]), Err(Efault));
    assert_eq!(unsafe { *((fr + 8) as *const u8) }, 8, "nothing was written");
    let mut raw = [core::mem::MaybeUninit::<u8>::uninit(); 4];
    assert_eq!(UserSlice::<u8>::new(VA as u64 + 4, 4).read_uninit(&mut raw).map(|b| b.to_vec()), Ok(vec![4, 5, 6, 7]));
    // Words: the count is in elements.
    let w = UserSlice::<u64>::new(VA as u64 + 64, 2);
    assert_eq!(w.write_from(&[1, 2]), Ok(()));
    let mut back = [0u64; 2];
    assert_eq!(w.read_into(&mut back), Ok(()));
    assert_eq!(back, [1, 2]);
    azos_sched::set_current_user_pt(0);
}

#[test]
fn a_string_is_copied_with_its_length() {
    let _g = serial();
    let fr = space();
    unsafe { core::ptr::copy_nonoverlapping(b"/tmp/x\0".as_ptr(), (fr + 100) as *mut u8, 7) };
    let mut buf = [0u8; 16];
    assert_eq!(UserCStr::new(VA as u64 + 100).read_into(&mut buf), Ok(6));
    assert_eq!(&buf[..7], b"/tmp/x\0");
    let mut small = [0u8; 6];
    assert_eq!(UserCStr::new(VA as u64 + 100).read_into(&mut small), Err(Efault), "no room for the NUL");
    azos_sched::set_current_user_pt(0);
}

#[test]
fn the_request_image_has_no_stale_padding() {
    use azos_driver_server::{DriverRequest, DRIVER_REQUEST_BYTES};
    // A request whose bytes, padding included, start as 0xAB everywhere.
    let mut req = core::mem::MaybeUninit::<DriverRequest>::uninit();
    unsafe { core::ptr::write_bytes(req.as_mut_ptr() as *mut u8, 0xAB, DRIVER_REQUEST_BYTES) };
    let mut req = unsafe { req.assume_init() };
    req.token = 1;
    req.client_tid = 2;
    req.op = 3;
    req.in_len = 4;
    req.out_cap = 5;
    req.input = [6; azos_driver_server::DRIVER_REQUEST_PAYLOAD_BYTES];
    let b = req.to_bytes();
    // The fields at their `repr(C)` offsets, as the userspace mirrors read them.
    let raw = unsafe { core::slice::from_raw_parts(&req as *const DriverRequest as *const u8, DRIVER_REQUEST_BYTES) };
    let fields = 20 + azos_driver_server::DRIVER_REQUEST_PAYLOAD_BYTES;
    assert_eq!(&b[..fields], &raw[..fields]);
    assert!(b[fields..].iter().all(|&x| x == 0), "the tail padding goes out as zero, not as the stack held it");
}

// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// The file protocol has one op table (`azos_devif::fs`): the `Node` and `Dir`
// interfaces name the kernel's own op numbers, and the kernel's `SYS_INVOKE`
// dispatch of a file handle is their fast form. Driven through the real
// entry (`invoke::sys_invoke`) with a file handle the caller does not hold:
// an op the kernel serves answers the capability refusal (`-ECAPSTALE`), an
// op it does not have answers `-EINVAL` from the dispatch, before any body.

use super::harness::serial;
use crate::dispatch::SyscallOut;
use crate::invoke::sys_invoke;
use azos_abi::cap::{ty, CapHandle, CapKind};
use azos_abi::error::Errno;
use azos_abi::invoke::{op, op_class, op_kind, CLASSES, CLASS_NET, INVOKE_REGS, NODE_MMAP};
use azos_arch_api::PagePerms;
use azos_devif::fs::{DirIdl, NodeIdl};
use azos_sched::filter::SyscallFilter;
use std::collections::BTreeSet;

const SCRATCH: usize = 0x0077_0000;

/// Every op of kind `Node` the kernel dispatches on a file handle, found by
/// asking it each number: a stale `ty::FILE` handle (generation 7 of a slot
/// nothing holds), and words no argument check refuses, so a served op
/// reaches its capability check.
fn kernel_file_ops() -> BTreeSet<u16> {
    let tid = 0x7c40_0001;
    ipc_task_pool::shim_bind(tid, 62);
    azos_ipc::cap_store::reset(tid);
    let pt = azos_mm::pmm::alloc_page().expect("arena exhausted").as_usize();
    azos_sched::set_current_user_pt(pt);
    azos_sched::set_current_task_tid(tid);
    let page = azos_mm::pmm::alloc_page().expect("arena exhausted").as_usize();
    azos_mm::vmm::map(pt, SCRATCH, page, PagePerms::USER_RW).expect("map");
    azos_sched::scheduler::set_current_syscall_filter(SyscallFilter::disabled());
    let stale = CapHandle::pack(ty::FILE, 5, 7).as_raw() as u64;
    let w = SCRATCH as u64;
    let mut served = BTreeSet::new();
    for class in 0..CLASSES {
        for n in 0..=u8::MAX {
            let o = op(CapKind::Node, class, n);
            // Two sets of words: a flag word of 0 (what `unlinkat` and
            // `seek` accept), and one that is a mapped address (what an op
            // with a second buffer refuses as null otherwise).
            let rcs = [[w, 0, w, azos_abi::syscall_nr::READDIR_NAME_BYTES as u64], [w, w, w, azos_abi::syscall_nr::READDIR_NAME_BYTES as u64]].map(|[a, b, c, d]| {
                let mut out = SyscallOut::new();
                sys_invoke(stale, INVOKE_REGS | o as u64, a, b, c, d, &mut out)
            });
            if rcs.contains(&Errno::ECAPSTALE.to_syscall_ret()) {
                served.insert(o);
            } else {
                assert!(rcs.iter().all(|&rc| rc == Errno::EINVAL.to_syscall_ret()), "op {o:#x} answered {rcs:?}");
            }
        }
    }
    azos_sched::set_current_user_pt(0);
    served
}

/// **The kernel's file ops and the protocol's are one table.** Every op the
/// two interfaces declare is a `Node` op the kernel serves, and every `Node`
/// op the kernel serves on a file handle is one of theirs, but for the socket
/// class and the mapping of a file.
///
/// **Canary.** Delete the `NODE_TRUNCATEAT` arm of `node_op` in
/// `crates/core/syscall/src/invoke.rs`: the protocol declares an op the
/// kernel no longer serves. (Or drop `truncateat` from `azos_devif::fs::Dir`:
/// the kernel serves an op the protocol does not declare.)
#[test]
fn the_kernel_serves_exactly_the_file_protocols_ops() {
    let _g = serial();
    let idl: BTreeSet<u16> = NodeIdl::OPS.iter().chain(DirIdl::OPS.iter()).map(|r| r.op).collect();
    assert_eq!(idl.len(), NodeIdl::OPS.len() + DirIdl::OPS.len(), "Node and Dir share an op number");
    for o in &idl {
        assert_eq!(op_kind(*o), CapKind::Node as u8, "op {o:#x} is not a Node op");
    }
    let kernel: BTreeSet<u16> =
        kernel_file_ops().into_iter().filter(|&o| op_class(o) != CLASS_NET && o != NODE_MMAP).collect();
    assert!(!idl.contains(&NODE_MMAP));
    assert_eq!(kernel, idl, "the kernel's file ops and the file protocol's differ");
}

/// A directory of two entries: a short name, and one longer than the record.
struct Listing;

const LONG: [u8; azos_abi::syscall_nr::READDIR_NAME_BYTES] = [b'L'; azos_abi::syscall_nr::READDIR_NAME_BYTES];

impl crate::file_ops::FileOps for Listing {
    fn open_at(&self, _: &[u8], _: &[u8], _: u32) -> i64 { unreachable!() }
    fn close(&self, _: i32) -> i64 { unreachable!() }
    fn read(&self, _: i32, _: &mut [u8]) -> i64 { unreachable!() }
    fn write(&self, _: i32, _: &[u8]) -> i64 { unreachable!() }
    fn lseek(&self, _: i32, _: i64, _: i32) -> i64 { unreachable!() }
    fn dup(&self, _: i32) -> i64 { unreachable!() }
    fn mkdir(&self, _: &[u8], _: &[u8]) -> i64 { unreachable!() }
    fn unlink(&self, _: &[u8], _: &[u8]) -> i64 { unreachable!() }
    // Lexical names: the root is nothing to this listing.
    fn readdir_beneath(&self, _: &[u8], path: &[u8], index: u32) -> Result<Option<([u8; azos_abi::syscall_nr::READDIR_NAME_BYTES], u32, bool)>, i64> {
        Ok(self.readdir(path, index))
    }
    fn readdir(&self, path: &[u8], index: u32) -> Option<([u8; azos_abi::syscall_nr::READDIR_NAME_BYTES], u32, bool)> {
        assert_eq!(path, b"/tmp/d");
        let mut short = [0u8; azos_abi::syscall_nr::READDIR_NAME_BYTES];
        short[..5].copy_from_slice(b"HELLO");
        match index {
            0 => Some((short, 7777, true)),
            1 => Some((LONG, 9, false)),
            _ => None,
        }
    }
    fn release_all(&self, _: u32) -> usize { unreachable!() }
    fn read_whole(&self, _: &[u8], _: &mut [u8]) -> usize { unreachable!() }
}

static LISTING: Listing = Listing;

struct Uninstall;
impl Drop for Uninstall {
    fn drop(&mut self) {
        crate::file_ops::__file_ops_clear_for_tests();
        azos_sched::set_current_user_pt(0);
    }
}

/// **`NODE_READDIR` answers through the register form**: 1 and the size, the
/// directory flag and the name-cut flag in `a1..a3`, the name zero-padded in
/// the caller's buffer; a name longer than the record is cut to 63 bytes and
/// says so; past the last entry, 0.
///
/// **Canary.** Swap the size and the directory flag in `node_op`'s reply
/// (`[is_dir, size, cut]`): the first entry's `a1` reads 1. **Canary.** Report
/// `cut` as `false` in `sys_readdirat`: the long name's `a3` reads 0.
#[test]
fn readdir_answers_its_entry_in_the_reply_registers() {
    use azos_abi::invoke::NODE_READDIR;
    let _g = serial();
    let _u = Uninstall;
    let tid = 0x7c40_0002;
    ipc_task_pool::shim_bind(tid, 62);
    azos_ipc::cap_store::reset(tid);
    azos_ipc::file_cap::reset_for_tests();
    let pt = azos_mm::pmm::alloc_page().expect("arena exhausted").as_usize();
    azos_sched::set_current_user_pt(pt);
    azos_sched::set_current_task_tid(tid);
    let page = azos_mm::pmm::alloc_page().expect("arena exhausted").as_usize();
    azos_mm::vmm::map(pt, SCRATCH, page, PagePerms::USER_RW).expect("map");
    azos_sched::scheduler::set_current_syscall_filter(SyscallFilter::disabled());
    crate::file_ops::set_file_ops(&LISTING);
    let d = azos_ipc::file_cap::file_tree_grant_cap(tid, "/tmp", azos_abi::cap::CapPerms::READ)
        .expect("tree grant")
        .raw()
        .as_raw() as u64;
    let host = page as *mut u8;
    unsafe {
        core::ptr::write_bytes(host, 0xEE, 4096);
        core::ptr::copy_nonoverlapping(b"d\0".as_ptr(), host, 2);
    }
    let (name, buf) = (SCRATCH as u64, (SCRATCH + 0x100) as u64);
    let call = |index: u64| {
        let mut out = SyscallOut::new();
        let rc = sys_invoke(d, INVOKE_REGS | NODE_READDIR as u64, name, index, buf, azos_abi::syscall_nr::READDIR_NAME_BYTES as u64, &mut out);
        (rc, out.regs)
    };
    let record = || unsafe { core::slice::from_raw_parts(host.add(0x100), azos_abi::syscall_nr::READDIR_NAME_BYTES).to_vec() };

    let (rc, regs) = call(0);
    assert_eq!((rc, &regs[..3]), (1, &[7777, 1, 0][..]), "size, directory, not cut");
    let r = record();
    assert_eq!(&r[..5], b"HELLO");
    assert!(r[5..].iter().all(|&b| b == 0), "the record is zero-padded");

    let (rc, regs) = call(1);
    assert_eq!((rc, &regs[..3]), (1, &[9, 0, 1][..]), "a name longer than the record says it was cut");
    let r = record();
    assert!(r[..azos_abi::syscall_nr::READDIR_NAME_BYTES - 1].iter().all(|&b| b == b'L') && r[azos_abi::syscall_nr::READDIR_NAME_BYTES - 1] == 0, "cut to one byte short and a NUL");

    assert_eq!(call(2).0, 0, "past the last entry");
}

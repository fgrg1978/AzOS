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
            let rcs = [[w, 0, w, 64], [w, w, w, 64]].map(|[a, b, c, d]| {
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

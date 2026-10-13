// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// Host tests for `SYS_INVOKE` (`crates/core/syscall/src/invoke.rs`): what the
// entry refuses before any op body runs, and the console's right split.
//
// **What is real here.** The entry itself, its decode and its dispatch, the
// real `SyscallFilter::op_verdict` on the current task's filter, the real
// `seccomp_deny_op_kill`, and the task's real capability table
// (`shims/ipc` pulls `cap_store` in whole). **What is not.** The sched shim's
// exit (a panic that records the code), and the terminal server's `ushell`
// ops, which answer `ushell::REACHED` so a test tells "the op was reached"
// from a refusal.
//
// Each test names the mutation of `invoke.rs` that turns it red (a canary,
// run by hand when the test was written: the mutated entry fails the test
// that names it and no other of this file).

use super::harness::serial;
use crate::dispatch::SyscallOut;
use crate::invoke::sys_invoke;
use azos_abi::cap::{CapHandle, CapKind, CapPerms, CapType};
use azos_ipc::cap::targets;
use azos_abi::error::Errno;
use azos_abi::invoke::{
    op, DOMAIN_SELF, DOMAIN_SUBREAPER, INVOKE_REGS, LOG_CONSOLE_WAIT, LOG_CONSOLE_WRITE, CLASS_ADMIN, CLASS_READ,
};
use azos_abi::ipc_msg::{MsgDesc, MSG_VERSION};
use azos_abi::syscall_nr::SUBREAPER_GET;
use azos_arch_api::PagePerms;
use azos_sched::filter::SyscallFilter;
use std::sync::atomic::{AtomicU32, Ordering};

const SLOT: usize = 61;
static NEXT_TID: AtomicU32 = AtomicU32::new(0x7c20_0001);
/// A page mapped user-RW.
const SCRATCH: usize = 0x0075_0000;
/// A page nothing maps.
const UNMAPPED: usize = 0x0076_0000;

/// The calling domain's self handle, as the call receives it.
const SELF: u64 = DOMAIN_SELF.as_raw() as u64;
/// `DOMAIN_SUBREAPER` in the register form, reading the mark: a deterministic
/// op with no side effect, the positive control of every refusal below.
const SUBREAPER_REGS: u64 = INVOKE_REGS | DOMAIN_SUBREAPER as u64;

/// A ring-3 task: its own capability table, a user page table with [`SCRATCH`]
/// mapped (the page as the host reaches it is returned), no filter.
fn ring3() -> (u32, *mut u8) {
    let tid = NEXT_TID.fetch_add(1, Ordering::SeqCst);
    ipc_task_pool::shim_bind(tid, SLOT);
    azos_ipc::cap_store::reset(tid);
    let pt = azos_mm::pmm::alloc_page().expect("arena exhausted").as_usize();
    azos_sched::set_current_user_pt(pt);
    azos_sched::set_current_task_tid(tid);
    let page = azos_mm::pmm::alloc_page().expect("arena exhausted").as_usize();
    azos_mm::vmm::map(pt, SCRATCH, page, PagePerms::USER_RW).expect("map");
    azos_sched::scheduler::set_current_syscall_filter(SyscallFilter::disabled());
    (tid, page as *mut u8)
}

fn invoke(handle: u64, opw: u64, a2: u64, a3: u64, a4: u64, a5: u64) -> i64 {
    let mut out = SyscallOut::new();
    sys_invoke(handle, opw, a2, a3, a4, a5, &mut out)
}

/// Write `d` at the start of the scratch page.
fn put_desc(page: *mut u8, d: &MsgDesc) {
    // SAFETY: the page is the host's own arena frame, a page long; a
    // `MsgDesc` is plain data and fits in it.
    unsafe { core::ptr::copy_nonoverlapping(d as *const MsgDesc as *const u8, page, core::mem::size_of::<MsgDesc>()) };
}

fn desc(n_words: u8, n_caps: u8) -> MsgDesc {
    let mut d = MsgDesc { version: MSG_VERSION, n_words, n_caps, ..MsgDesc::default() };
    d.words[0] = SUBREAPER_GET;
    d
}

/// An enforcing filter that lists the op classes `classes` of the domain kind.
fn enforcing(classes: &[u8], audit: bool) -> SyscallFilter {
    let mut f = SyscallFilter::disabled();
    f.enabled = true;
    f.audit = audit;
    for &c in classes {
        f.allow_op(op(CapKind::Domain, c, 1));
    }
    f
}

/// Run `f`, a call the profile kills: the exit code the task was ended with,
/// or `None` if the call returned.
fn killed(f: impl FnOnce() -> i64) -> Option<i32> {
    let _ = azos_sched::shim_take_exit_codes();
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)) {
        Ok(_) => None,
        Err(e) => {
            let msg = e.downcast_ref::<String>().cloned().unwrap_or_default();
            assert!(msg.contains(azos_sched::TASK_EXIT_MARKER), "panicked elsewhere than at the exit: {msg}");
            azos_sched::shim_take_exit_codes().first().copied()
        }
    }
}

/// **A flag the call does not know, or a handle wider than 32 bits, is
/// `-EINVAL`** before anything is resolved. The same call without the stray
/// bit is the control: it reads the subreaper mark.
///
/// **Canary.** Drop the `opw & !(INVOKE_OP_MASK | INVOKE_FLAGS_KNOWN) != 0`
/// clause (and, for the second half, the `handle > u32::MAX` one) from
/// `sys_invoke`'s first check: the stray bit is ignored and the call answers 0.
#[test]
fn an_unknown_flag_or_a_wide_handle_is_einval() {
    let _g = serial();
    ring3();
    let einval = Errno::EINVAL.to_syscall_ret();
    assert_eq!(invoke(SELF, SUBREAPER_REGS, SUBREAPER_GET, 0, 0, 0), 0, "the control call");
    assert_eq!(invoke(SELF, SUBREAPER_REGS | (1 << 17), SUBREAPER_GET, 0, 0, 0), einval, "bit 17 of the op word");
    assert_eq!(invoke(SELF, SUBREAPER_REGS | (1 << 40), SUBREAPER_GET, 0, 0, 0), einval, "bit 40 of the op word");
    assert_eq!(invoke(SELF | (1 << 32), SUBREAPER_REGS, SUBREAPER_GET, 0, 0, 0), einval, "a handle past 32 bits");
}

/// **An op the handle's type has none of is `-EINVAL`**, not a guess at the
/// nearest one.
///
/// **Canary.** Make the `_` arm of `domain_self_op` return 0: the call
/// answers 0.
#[test]
fn an_op_the_handle_type_does_not_have_is_einval() {
    let _g = serial();
    ring3();
    let unknown = op(CapKind::Domain, CLASS_READ, 250) as u64;
    assert_eq!(invoke(SELF, INVOKE_REGS | unknown, 0, 0, 0, 0), Errno::EINVAL.to_syscall_ret());
}

/// **The descriptor form takes its words from the descriptor alone**: `a3`,
/// `a4` and `a5` must be zero, or the call is `-EINVAL`. A descriptor in
/// `a2` with the three clear is the control.
///
/// **Canary.** Delete the `a3 != 0 || a4 != 0 || a5 != 0` check from the
/// descriptor branch: each stray word is ignored and the call answers 0.
#[test]
fn the_descriptor_form_takes_no_words_in_a3_to_a5() {
    let _g = serial();
    let (_, page) = ring3();
    put_desc(page, &desc(1, 0));
    let einval = Errno::EINVAL.to_syscall_ret();
    let a2 = SCRATCH as u64;
    assert_eq!(invoke(SELF, DOMAIN_SUBREAPER as u64, a2, 0, 0, 0), 0, "the control call");
    assert_eq!(invoke(SELF, DOMAIN_SUBREAPER as u64, a2, 1, 0, 0), einval, "a3");
    assert_eq!(invoke(SELF, DOMAIN_SUBREAPER as u64, a2, 0, 1, 0), einval, "a4");
    assert_eq!(invoke(SELF, DOMAIN_SUBREAPER as u64, a2, 0, 0, 1), einval, "a5");
}

/// **A descriptor must be readable, well formed and carry no capability**: an
/// unmapped one is `-EFAULT`, an unknown version or a count past the ABI's is
/// `-EINVAL`, and so is `n_caps != 0` (an op takes words only; a transfer is
/// an IPC call). The descriptor with words alone is the control.
///
/// **Canary.** Drop `|| desc.n_caps != 0` from the descriptor check: the
/// descriptor with one capability entry is served and answers 0.
#[test]
fn a_descriptor_must_be_readable_well_formed_and_carry_no_capability() {
    let _g = serial();
    let (_, page) = ring3();
    let einval = Errno::EINVAL.to_syscall_ret();
    let a2 = SCRATCH as u64;
    put_desc(page, &desc(1, 0));
    assert_eq!(invoke(SELF, DOMAIN_SUBREAPER as u64, a2, 0, 0, 0), 0, "the control call");
    put_desc(page, &desc(1, 1));
    assert_eq!(invoke(SELF, DOMAIN_SUBREAPER as u64, a2, 0, 0, 0), einval, "n_caps = 1");
    let mut d = desc(1, 0);
    d.version = MSG_VERSION + 1;
    put_desc(page, &d);
    assert_eq!(invoke(SELF, DOMAIN_SUBREAPER as u64, a2, 0, 0, 0), einval, "an unknown version");
    put_desc(page, &desc(255, 0));
    assert_eq!(invoke(SELF, DOMAIN_SUBREAPER as u64, a2, 0, 0, 0), einval, "more words than the ABI has");
    assert_eq!(
        invoke(SELF, DOMAIN_SUBREAPER as u64, UNMAPPED as u64, 0, 0, 0),
        Errno::EFAULT.to_syscall_ret(),
        "an unmapped descriptor",
    );
}

/// **An op of another kind than the handle's is refused before the profile is
/// asked.** The task's profile lists no op class at all; a console op on the
/// domain's self handle is `-EINVAL` (the op does not belong to that kind) and
/// the task lives. Without the check the profile would be asked about the
/// op's class on the HANDLE's kind and kill the task for a mistake that is not
/// a breach.
///
/// **Canary.** Delete the `op_kind(c.op) != kind` check in `dispatch`: the
/// profile is consulted and the task is killed (the test sees the exit).
#[test]
fn an_op_of_another_kind_is_einval_and_does_not_reach_the_profile() {
    let _g = serial();
    ring3();
    azos_sched::scheduler::set_current_syscall_filter(enforcing(&[], false));
    let rc = killed(|| invoke(SELF, INVOKE_REGS | LOG_CONSOLE_WRITE as u64, SCRATCH as u64, 1, 0, 0));
    assert_eq!(rc, None, "the task was killed for an op of another kind");
    assert_eq!(
        invoke(SELF, INVOKE_REGS | LOG_CONSOLE_WRITE as u64, SCRATCH as u64, 1, 0, 0),
        Errno::EINVAL.to_syscall_ret(),
    );
}

/// **A domain op takes the self handle and no other.** A handle that names a
/// domain by a slot (a forged or stale one: the generation of a stored
/// handle is never 0, the self handle's is) is `-ECAPKIND`, not an action on
/// the caller's domain.
///
/// **Canary.** Delete the `!is_domain_self(c.handle)` refusal from
/// `domain_self_op`: the forged handle reads the subreaper mark and answers 0.
#[test]
fn a_domain_op_on_a_handle_that_is_not_self_is_ecapkind() {
    let _g = serial();
    ring3();
    let forged = CapHandle::pack(CapType::new(CapKind::Domain, 1), CapPerms::ALL, 1, 3).as_raw() as u64;
    assert_ne!(forged, SELF);
    assert_eq!(invoke(SELF, SUBREAPER_REGS, SUBREAPER_GET, 0, 0, 0), 0, "the control call");
    assert_eq!(invoke(forged, SUBREAPER_REGS, SUBREAPER_GET, 0, 0, 0), Errno::ECAPKIND.to_syscall_ret());
}

/// **An op class the image's profile does not list kills the task** (exit
/// 159, the same as an unlisted syscall number), a listed one runs, and in
/// audit mode the unlisted one runs and is recorded instead.
///
/// **Canary.** Make the `Deny` arm of `dispatch`'s verdict match fall through
/// as `Allow`: the unlisted op runs and the first half sees no exit.
#[test]
fn a_denied_op_class_kills_the_task_and_a_listed_one_runs() {
    let _g = serial();
    ring3();
    // Unlisted: the subreaper op is class ADMIN of the domain.
    azos_sched::scheduler::set_current_syscall_filter(enforcing(&[CLASS_READ], false));
    let rc = killed(|| invoke(SELF, SUBREAPER_REGS, SUBREAPER_GET, 0, 0, 0));
    assert_eq!(rc, Some(crate::handlers::SECCOMP_KILL_EXIT_CODE), "an op class outside the profile");
    // Listed.
    azos_sched::scheduler::set_current_syscall_filter(enforcing(&[CLASS_ADMIN], false));
    assert_eq!(killed(|| invoke(SELF, SUBREAPER_REGS, SUBREAPER_GET, 0, 0, 0)), None);
    assert_eq!(invoke(SELF, SUBREAPER_REGS, SUBREAPER_GET, 0, 0, 0), 0, "a listed class runs");
    // Audit mode: nothing listed, the call goes through.
    azos_sched::scheduler::set_current_syscall_filter(enforcing(&[], true));
    assert_eq!(killed(|| invoke(SELF, SUBREAPER_REGS, SUBREAPER_GET, 0, 0, 0)), None);
    assert_eq!(invoke(SELF, SUBREAPER_REGS, SUBREAPER_GET, 0, 0, 0), 0, "audit mode lets it through");
}

/// A console handle with `perms`, as the task's table holds it.
fn console_cap(tid: u32, perms: CapPerms) -> u64 {
    azos_ipc::cap_store::grant::<targets::Console>(tid, perms, 0)
        .expect("cap table full")
        .raw()
        .as_raw() as u64
}

/// **The console's right split.** `WRITE` writes whatever the system's state:
/// a contained (degraded) task still reports on the console, so the write is
/// uncontained. `WAIT` needs `READ` on the handle, and a handle with `WRITE`
/// alone is `-ECAPPERMS` before the wait is reached; a forged handle is
/// `-ECAPSTALE`.
///
/// **Canaries.** `contained_ok` false for `LOG_CONSOLE_WRITE` in `console_op`:
/// the write under containment answers `E_CONTAINED`. `CapPerms::READ` replaced
/// by `CapPerms::WRITE` for `LOG_CONSOLE_WAIT`: the write-only handle reaches
/// the wait.
#[test]
fn the_console_write_is_uncontained_and_its_wait_needs_read() {
    let _g = serial();
    let (tid, page) = ring3();
    // SAFETY: the host's own frame, one page long.
    unsafe { core::ptr::copy_nonoverlapping(b"ok".as_ptr(), page, 2) };
    let wr = console_cap(tid, CapPerms::WRITE);
    let rw = console_cap(tid, CapPerms::READ.union(CapPerms::WRITE));
    let write = INVOKE_REGS | LOG_CONSOLE_WRITE as u64;
    let wait = INVOKE_REGS | LOG_CONSOLE_WAIT as u64;
    syscall_test_drivers::shim_fwd::arm(syscall_test_drivers::shim_fwd::Fwd::default());

    assert_eq!(invoke(wr, write, SCRATCH as u64, 2, 0, 0), 2, "a write with the right");
    azos_ipc::cap::degraded_set(true);
    let contained = invoke(wr, write, SCRATCH as u64, 2, 0, 0);
    azos_ipc::cap::degraded_set(false);
    assert_eq!(contained, 2, "a contained task's console write was refused");

    assert_eq!(invoke(wr, wait, 0, 0, 0, 0), Errno::ECAPPERMS.to_syscall_ret(), "WAIT on a write-only handle");
    assert_eq!(invoke(rw, wait, 0, 0, 0, 0), crate::ushell::REACHED, "WAIT with READ reaches the wait");
    let forged = CapHandle::pack(azos_abi::cap::ty::CONSOLE, CapPerms::ALL, 1, 200).as_raw() as u64;
    assert_eq!(invoke(forged, write, SCRATCH as u64, 2, 0, 0), Errno::ECAPSTALE.to_syscall_ret(), "a console handle nothing stored");

    let log = syscall_test_drivers::shim_fwd::disarm().map(|f| f.log).unwrap_or_default();
    assert_eq!(log.len(), 2, "the two accepted writes reached the console: {log:?}");
}

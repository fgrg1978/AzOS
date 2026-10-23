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

// ── ENDPOINT_DERIVE: the caveated derive of an endpoint (B3) ────────────────

/// An endpoint the task serves, and a handle on it with `perms`.
fn endpoint_with(tid: u32, perms: CapPerms) -> u64 {
    use azos_ipc::cap::{targets::Endpoint, Cap};
    let made = crate::ipc_handlers::sys_endpoint_create_typed();
    assert!(made > 0, "an endpoint: {made}");
    let r = azos_ipc::cap_store::get(tid, Cap::<Endpoint>::from_raw(CapHandle::from_raw(made as u32)), CapPerms::NONE)
        .expect("a live capability");
    azos_ipc::cap_store::grant::<Endpoint>(tid, perms, r).expect("cap table full").raw().as_raw() as u64
}

/// The words of an `ENDPOINT_DERIVE`: the copy's rights, badge and deadline,
/// then its caveats as `(kind, argument)`.
fn derive_desc(rights: u8, badge: u32, expiry_ns: u64, caveats: &[(u8, u64)]) -> MsgDesc {
    let mut d = MsgDesc { version: MSG_VERSION, n_words: 7, ..MsgDesc::default() };
    d.words[0] = rights as u64 | (caveats.len() as u64) << 8 | (badge as u64) << 32;
    d.words[1] = expiry_ns;
    for (i, &(k, a)) in caveats.iter().enumerate() {
        d.words[2] |= (k as u64) << (8 * i);
        d.words[3 + i] = a;
    }
    d
}

/// `ENDPOINT_DERIVE` on `h` with `d`, in the descriptor form.
fn derive_with(h: u64, page: *mut u8, d: &MsgDesc) -> i64 {
    put_desc(page, d);
    invoke(h, azos_abi::invoke::ENDPOINT_DERIVE as u64, SCRATCH as u64, 0, 0, 0)
}

/// **A derive through the entry mints a child of the source, with the
/// source's caveats first and the request's after, the badge and the rights
/// asked for.** The copy is in the caller's table as an endpoint, revoking the
/// source revokes it, and it is the handle the call returns.
///
/// **Canary.** Replace `mint_badged_caveated` by `mint_badged_until` in
/// `endpoint_derive` (the caveats are dropped): the caveat list below is
/// empty, red.
#[test]
fn an_endpoint_derive_mints_a_caveated_child_of_the_source() {
    use azos_ipc::cap::{caveat, Caveat};
    let _g = serial();
    let (tid, page) = ring3();
    let src = endpoint_with(tid, CapPerms::RW_DELEGATE);
    let asked = [(caveat::OP_MASK, 0b0110), (caveat::RECEIPT, caveat::receipt::arg(0x0103, 0, 500))];
    let rc = derive_with(src, page, &derive_desc(CapPerms::WRITE.bits(), 0xB3, 0, &asked));
    assert!(rc > 0, "a handle: {rc}");
    let h = rc as u64;
    assert_eq!(CapHandle::from_raw(h as u32).kind(), azos_abi::cap::ty::ENDPOINT.raw(), "an endpoint");
    assert_ne!(h, src);
    if azos_ipc::cap::SLOT_EXT {
        let w = azos_ipc::cap_store::with_table(tid, |t| t.warrant_of(CapHandle::from_raw(h as u32))).flatten().unwrap();
        assert_eq!(
            w.caveats.as_slice(),
            &[Caveat::new(caveat::OP_MASK, 0b0110), Caveat::new(caveat::RECEIPT, asked[1].1)],
            "the request's caveats on the copy"
        );
        assert_eq!(w.depth, 1, "a child of the source");
    }
    // A caveat-less derive is the plain one: no caveats on the copy.
    let plain = derive_with(src, page, &derive_desc(CapPerms::WRITE.bits(), 0xB4, 0, &[]));
    assert!(plain > 0, "{plain}");
    if azos_ipc::cap::SLOT_EXT {
        let w = azos_ipc::cap_store::with_table(tid, |t| t.warrant_of(CapHandle::from_raw(plain as u32))).flatten().unwrap();
        assert!(w.caveats.as_slice().is_empty());
    }
    // Revoking the source revokes the copy.
    azos_ipc::cap_store::revoke_derived(tid, CapHandle::from_raw(src as u32)).expect("revoke");
    let after = derive_with(h, page, &derive_desc(CapPerms::WRITE.bits(), 0xB5, 0, &[]));
    assert_eq!(after, Errno::ECAPSTALE.to_syscall_ret(), "the copy went with its source");
}

/// **The words are checked whole before anything is minted.** A caveat count
/// past four, a stray bit of the first word, a kind byte or an argument past
/// the count, rights the capability model has no bit for: `-EINVAL`. A caveat
/// kind the kernel does not know is `-ECAPPERMS`; a source without `DUP`
/// `-ECAPPERMS`; a handle nothing stored `-ECAPSTALE`. The positive control
/// is the plain derive, which answers a handle.
///
/// **Canary.** Delete the `n > ENDPOINT_DERIVE_CAVEATS_MAX` test of
/// `EndpointDerive::decode`: the count of five reads the words past the
/// seventh and the first assertion goes red; drop the `d.rights` check in
/// `endpoint_derive`: the rights assertion answers a handle.
#[test]
fn an_endpoint_derive_refuses_what_it_cannot_decode_or_mint() {
    use azos_ipc::cap::caveat;
    let _g = serial();
    let (tid, page) = ring3();
    let einval = Errno::EINVAL.to_syscall_ret();
    let src = endpoint_with(tid, CapPerms::RW_DELEGATE);
    let w = CapPerms::WRITE.bits();
    assert!(derive_with(src, page, &derive_desc(w, 1, 0, &[])) > 0, "the control");

    let mut d = derive_desc(w, 1, 0, &[]);
    d.words[0] |= 5 << 8;
    assert_eq!(derive_with(src, page, &d), einval, "five caveats");
    let mut d = derive_desc(w, 1, 0, &[]);
    d.words[0] |= 1 << 16;
    assert_eq!(derive_with(src, page, &d), einval, "a stray bit of the first word");
    let mut d = derive_desc(w, 1, 0, &[(caveat::QUOTA, 3)]);
    d.words[2] |= 7 << 8;
    assert_eq!(derive_with(src, page, &d), einval, "a kind byte past the count");
    let mut d = derive_desc(w, 1, 0, &[(caveat::QUOTA, 3)]);
    d.words[4] = 1;
    assert_eq!(derive_with(src, page, &d), einval, "an argument past the count");
    assert_eq!(derive_with(src, page, &derive_desc(0x40, 1, 0, &[])), einval, "rights past the sixth bit");
    assert_eq!(
        derive_with(src, page, &derive_desc(w, 0, 0, &[])),
        Errno::ECAPPERMS.to_syscall_ret(),
        "badge 0 is the unbadged source's own"
    );
    assert_eq!(
        derive_with(src, page, &derive_desc(w, 1, 0, &[(99, 0)])),
        Errno::ECAPPERMS.to_syscall_ret(),
        "a caveat kind the kernel does not know"
    );
    let no_dup = endpoint_with(tid, CapPerms::RW);
    assert_eq!(derive_with(no_dup, page, &derive_desc(w, 1, 0, &[])), Errno::ECAPPERMS.to_syscall_ret(), "no DUP");
    let forged = CapHandle::pack(azos_abi::cap::ty::ENDPOINT, CapPerms::ALL, 1, 200).as_raw() as u64;
    assert_eq!(derive_with(forged, page, &derive_desc(w, 1, 0, &[])), Errno::ECAPSTALE.to_syscall_ret(), "nothing stored");
}

/// **A declassification warrant is issued only to a user principal.** The
/// caveat is the one that grants, so the entry stamps it by the issuer's own
/// rule: an agent, a service and a task with no principal are `-ECAPPERMS`
/// (nothing minted); a user's request is checked whole first (no bit, a bit
/// that is no kind, two warrants in one call: `-EINVAL`) and its copy carries
/// the warrant after the request's other caveats.
///
/// **Canary.** Drop the principal test in `endpoint::mint_badged_issued`: the
/// agent row answers a handle, red. Let the entry pass `DECLASSIFY` through
/// the caveat list (`caveats.with`): `narrow_warrant` refuses it for every
/// issuer and the user row is red.
#[test]
fn a_declassify_warrant_is_issued_only_to_a_user_principal() {
    use azos_abi::ipc_msg::{LABEL_AGENT, LABEL_USER};
    use azos_ipc::cap::{caveat, Caveat};
    use azos_ipc::endpoint::label;
    let _g = serial();
    let (tid, page) = ring3();
    if !label::ENABLED || !azos_ipc::cap::SLOT_EXT {
        return;
    }
    let src = endpoint_with(tid, CapPerms::RW_DELEGATE);
    let w = CapPerms::WRITE.bits();
    let derive = |caveats: &[(u8, u64)]| derive_with(src, page, &derive_desc(w, 1, 0, caveats));
    let denied = Errno::ECAPPERMS.to_syscall_ret();
    let einval = Errno::EINVAL.to_syscall_ret();
    let warrant_of = |h: i64| {
        azos_ipc::cap_store::with_table(tid, |t| t.warrant_of(CapHandle::from_raw(h as u32))).flatten().unwrap()
    };

    assert_eq!(derive(&[(caveat::DECLASSIFY, LABEL_AGENT as u64)]), denied, "no principal");
    for kind in [1u8, 3] {
        assert!(label::set_principal(tid, kind));
        assert_eq!(derive(&[(caveat::DECLASSIFY, LABEL_AGENT as u64)]), denied, "principal kind {kind}");
    }
    assert!(label::set_principal(tid, 2));
    assert_eq!(derive(&[(caveat::DECLASSIFY, 0)]), einval, "a warrant that names nothing is spent");
    assert_eq!(derive(&[(caveat::DECLASSIFY, 1 << 5)]), einval, "a bit that is no kind");
    assert_eq!(
        derive(&[(caveat::DECLASSIFY, LABEL_AGENT as u64), (caveat::DECLASSIFY, LABEL_USER as u64)]),
        einval,
        "two warrants in one copy"
    );
    let rc = derive(&[(caveat::OP_MASK, 0b0110), (caveat::DECLASSIFY, LABEL_AGENT as u64)]);
    assert!(rc > 0, "a user principal issues: {rc}");
    assert_eq!(
        warrant_of(rc).caveats.as_slice(),
        &[Caveat::new(caveat::OP_MASK, 0b0110), Caveat::new(caveat::DECLASSIFY, LABEL_AGENT as u64)],
        "the request's caveats, then the warrant"
    );
    label::__reset_for_tests();
}

/// **A copy born expired is refused before it is minted**, with
/// `-EDEADLINE` and a `DeadlineExpired` record, the rule of `SYS_CAP_DERIVE`;
/// a deadline still ahead mints.
///
/// **Canary.** Delete the `d.expiry_ns <= now` refusal in `endpoint_derive`:
/// the dead deadline mints a copy and the first assertion goes red.
#[test]
fn an_endpoint_derive_refuses_a_deadline_already_past() {
    let _g = serial();
    let (tid, page) = ring3();
    let src = endpoint_with(tid, CapPerms::RW_DELEGATE);
    let ms = |n: u64| n * 1_000_000;
    let ticks = |ns: u64| ns / 1_000 * (azos_drv_irqchip::clint::TIMER_FREQ / 1_000_000);
    azos_drv_irqchip::clint::set_time(ticks(ms(10)));
    let before = azos_decision::total();
    let w = CapPerms::WRITE.bits();
    assert_eq!(derive_with(src, page, &derive_desc(w, 1, ms(5), &[])), Errno::EDEADLINE.to_syscall_ret());
    assert_eq!(derive_with(src, page, &derive_desc(w, 1, ms(10), &[])), Errno::EDEADLINE.to_syscall_ret(), "at the instant");
    let refused = (before + 1..=azos_decision::total())
        .filter_map(azos_decision::get)
        .filter(|r| r.rule == azos_decision::Rule::DeadlineExpired as u8 && r.subject == tid)
        .count();
    assert_eq!(refused, 2, "one record a refusal");
    assert!(derive_with(src, page, &derive_desc(w, 1, ms(20), &[])) > 0, "a deadline ahead mints");
    azos_drv_irqchip::clint::set_time(0);
}

/// **The op belongs to the endpoint kind and the image's profile lists its
/// class.** An endpoint op on a handle of another kind is `-EINVAL` and the
/// task lives; a profile with no endpoint class kills the task at the call; one
/// listing `ENDPOINT_DERIVE` runs it; an op number of the kind the endpoint arm
/// does not know is `-EINVAL`.
///
/// **Canary.** Delete the `ty::ENDPOINT` arm of `dispatch`: the listed call
/// answers `-ECAPKIND`; make `endpoint_op` answer 0 for any op: the unknown op
/// answers 0.
#[test]
fn an_endpoint_derive_is_an_endpoint_op_and_a_profile_class() {
    use azos_abi::invoke::{op, ENDPOINT_DERIVE, CLASS_CTL};
    let _g = serial();
    let (tid, page) = ring3();
    let src = endpoint_with(tid, CapPerms::RW_DELEGATE);
    let w = CapPerms::WRITE.bits();
    let d = derive_desc(w, 1, 0, &[]);
    put_desc(page, &d);
    let call = |h: u64, o: u16| invoke(h, o as u64, SCRATCH as u64, 0, 0, 0);

    assert_eq!(call(SELF, ENDPOINT_DERIVE), Errno::EINVAL.to_syscall_ret(), "an endpoint op on the domain");
    let con = console_cap(tid, CapPerms::WRITE);
    assert_eq!(call(con, ENDPOINT_DERIVE), Errno::EINVAL.to_syscall_ret(), "an endpoint op on the console");
    assert_eq!(call(src, op(CapKind::Endpoint, CLASS_CTL, 2)), Errno::EINVAL.to_syscall_ret(), "an op the endpoint does not have");

    let mut profile = SyscallFilter::disabled();
    profile.enabled = true;
    azos_sched::scheduler::set_current_syscall_filter(profile.clone());
    assert_eq!(killed(|| call(src, ENDPOINT_DERIVE)), Some(crate::handlers::SECCOMP_KILL_EXIT_CODE), "unlisted");
    profile.allow_op(ENDPOINT_DERIVE);
    azos_sched::scheduler::set_current_syscall_filter(profile);
    put_desc(page, &d);
    assert!(call(src, ENDPOINT_DERIVE) > 0, "listed");
}

/// **Ring-3 port I/O answers by the ISA's port space, before the handle.**
/// This suite's build has none (its .config is not x86_64's, Kconfig
/// `X86_IOPORT_BITMAP_PORTS` 0, as on riscv64 and aarch64): the open op on
/// a port-range handle the task does not hold is `-ENODEV`, not the
/// handle's refusal, and an op the type does not have is still `-EINVAL`.
///
/// **Canary.** Move the `PORTS == 0` test of `ioport_op` after the
/// capability check: the call answers `-ECAPSTALE`.
#[test]
fn the_port_op_answers_enodev_without_a_port_space() {
    use azos_abi::invoke::{CLASS_DRIVER, DEVICE_IOPORT_ENABLE};
    let _g = serial();
    ring3();
    assert_eq!(azos_arch_api::ioport::PORTS, 0, "this suite's build has no port space");
    let forged = CapHandle::pack(azos_abi::cap::ty::IOPORT, CapPerms::RW, 3, 7).as_raw() as u64;
    assert_eq!(invoke(forged, INVOKE_REGS | DEVICE_IOPORT_ENABLE as u64, 0, 0, 0, 0),
               Errno::ENODEV.to_syscall_ret());
    let unknown = op(CapKind::Device, CLASS_DRIVER, 250) as u64;
    assert_eq!(invoke(forged, INVOKE_REGS | unknown, 0, 0, 0, 0), Errno::EINVAL.to_syscall_ret());
}

/// **A port-range capability takes its ports with it.** `SYS_CAP_CLOSE` on
/// one revokes it (a second close is stale), and the capability store's
/// event for it, as for any revocation, closes its range in the holder's
/// table (`azos_sched::ioport::revoke`, the shim records the ask): the
/// table's index and the range's bounds.
///
/// **Canary.** Drop the `ty::IOPORT` arm of `sys_close_typed`: the close is
/// `-ECAPKIND` and nothing closes.
#[test]
fn closing_a_port_capability_closes_its_ports() {
    let _g = serial();
    let (tid, _) = ring3();
    let table = azos_ipc::cap_store::table_slot(tid).expect("a live table") as u32;
    let range = azos_abi::cap::ioport_range(0x80, 1).unwrap();
    let cap = azos_ipc::cap_store::grant::<targets::IoPorts>(tid, CapPerms::RW, range).expect("a free slot");
    azos_ipc::cap_store::set_cap_event_hook(crate::ioport::ioport_cap_event);
    azos_sched::ioport::REVOKED.lock().unwrap().clear();
    let r = crate::handlers::sys_close_typed(cap.raw().as_raw() as u64);
    let second = crate::handlers::sys_close_typed(cap.raw().as_raw() as u64);
    azos_ipc::cap_store::set_cap_event_hook(|_| {});
    assert_eq!(r, 0, "the holder closes its port range");
    assert_eq!(*azos_sched::ioport::REVOKED.lock().unwrap(), vec![(table, 0x80, 0x80)]);
    assert_eq!(second, Errno::ECAPSTALE.to_syscall_ret(), "the capability went with the close");
}

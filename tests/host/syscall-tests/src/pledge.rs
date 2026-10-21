// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// `DOMAIN_PLEDGE` through `SYS_INVOKE` (`crates/core/syscall/src/invoke.rs`):
// the one setter of a Domain's pledge mask. The entry, the op's dispatch and
// the profile check are the real ones; the Domain table is the real
// `crates/core/sched/src/domain.rs` (the sched shim pulls it); a test makes its
// own Domains and puts a task in one with `shim_bind_domain`. What the
// prologue does with the mask is `tests/host/trap-tests/src/pledge.rs`.
//
// **Canary.** Drop `domain_pledge`'s `Widen` arm (answer 0 for it): the
// widening line fails. Make the arm for the op in `domain_self_op` answer
// `-EINVAL`: every line of `a_task_narrows_its_domain_and_never_widens` fails.

use super::harness::serial;
use crate::invoke::sys_invoke;
use crate::dispatch::SyscallOut;
use azos_abi::cap::CapKind;
use azos_abi::error::Errno;
use azos_abi::invoke::*;
use azos_abi::syscall_nr::{CASE_AUTHORITY, CASE_BLOCK_WAKE};
use azos_sched::domain::{self, Key};
use azos_sched::filter::SyscallFilter;
use std::sync::atomic::{AtomicU32, Ordering};

const SLOT_A: usize = 49;
const SLOT_B: usize = 50;
static NEXT_TID: AtomicU32 = AtomicU32::new(0x7a40_0001);

const SELF: u64 = DOMAIN_SELF.as_raw() as u64;
const PLEDGE_REGS: u64 = INVOKE_REGS | DOMAIN_PLEDGE as u64;

fn pledge_call(mask: u64) -> i64 {
    let mut out = SyscallOut::new();
    sys_invoke(SELF, PLEDGE_REGS, mask, 0, 0, 0, &mut out)
}

/// Make a fresh task the calling one, in the Domain `dom` (`None`: in none).
fn task_in(slot: usize, dom: Option<Key>) -> u32 {
    let tid = NEXT_TID.fetch_add(1, Ordering::SeqCst);
    ipc_task_pool::shim_bind(tid, slot);
    azos_ipc::cap_store::reset(tid);
    azos_sched::set_current_task_tid(tid);
    azos_sched::scheduler::set_current_syscall_filter(SyscallFilter::disabled());
    match dom {
        Some(k) => azos_sched::shim_bind_domain(tid, k),
        None => azos_sched::shim_unbind_domains(),
    }
    tid
}

fn done(tids: &[u32], doms: &[Key]) {
    azos_sched::set_current_task_tid(0);
    azos_sched::scheduler::set_current_syscall_filter(SyscallFilter::disabled());
    azos_sched::shim_unbind_domains();
    for &t in tids {
        azos_ipc::cap_store::reset(t);
    }
    for &k in doms.iter().rev() {
        domain::leave(k);
    }
}

const STEADY: u32 = pledge_case(CASE_BLOCK_WAKE) | pledge_class(CLASS_NET) | pledge_class(CLASS_WRITE);

/// **The op narrows the caller's Domain and returns the mask now in force; a
/// request that holds a bit the mask has lost is `-EACCES` and changes nothing;
/// a bit that names nothing, or a word wider than 32 bits, is `-EINVAL`.**
#[test]
fn a_task_narrows_its_domain_and_never_widens() {
    let _g = serial();
    let d = domain::create().unwrap();
    let t = task_in(SLOT_A, Some(d));
    assert_eq!(pledge_call(u64::from(STEADY)), i64::from(STEADY | PLEDGE_ALWAYS), "the mask now in force, exit kept");
    assert_eq!(pledge_call(u64::from(STEADY | pledge_case(CASE_AUTHORITY))), Errno::EACCES.to_syscall_ret(), "wider: refused");
    assert_eq!(pledge_call(u64::from(STEADY)), i64::from(STEADY | PLEDGE_ALWAYS), "and nothing changed");
    assert_eq!(pledge_call(u64::from(pledge_case(CASE_BLOCK_WAKE))), i64::from(pledge_case(CASE_BLOCK_WAKE) | PLEDGE_ALWAYS), "narrower: taken");
    assert_eq!(pledge_call(u64::from(STEADY)), Errno::EACCES.to_syscall_ret(), "and the class it dropped is gone for good");
    assert_eq!(pledge_call(1 << 30), Errno::EINVAL.to_syscall_ret(), "a bit that names nothing");
    assert_eq!(pledge_call(1 << 32), Errno::EINVAL.to_syscall_ret(), "a word past 32 bits");
    done(&[t], &[d]);
}

/// **The mask is the Domain's, not the thread's:** another task of the Domain is
/// bound by what the first narrowed, and cannot widen it; a Domain made beneath
/// it afterwards starts narrowed; a task of another Domain is untouched.
#[test]
fn the_mask_binds_every_thread_and_the_children_of_the_domain() {
    let _g = serial();
    let d = domain::create().unwrap();
    let other = domain::create().unwrap();
    let t1 = task_in(SLOT_A, Some(d));
    assert_eq!(pledge_call(u64::from(STEADY)), i64::from(STEADY | PLEDGE_ALWAYS));
    // A second thread of the Domain.
    let t2 = task_in(SLOT_B, Some(d));
    assert_eq!(pledge_call(u64::from(PLEDGE_ALL)), Errno::EACCES.to_syscall_ret(), "the thread finds the Domain narrowed");
    // A Domain created beneath it now.
    let child = domain::create_child(d).unwrap();
    let t3 = task_in(SLOT_A, Some(child));
    assert_eq!(pledge_call(u64::from(STEADY | pledge_case(CASE_AUTHORITY))), Errno::EACCES.to_syscall_ret(), "the child begins narrowed");
    assert_eq!(pledge_call(u64::from(pledge_class(CLASS_NET))), i64::from(pledge_class(CLASS_NET) | PLEDGE_ALWAYS));
    // An unrelated Domain is whole.
    let t4 = task_in(SLOT_B, Some(other));
    assert_eq!(pledge_call(u64::from(PLEDGE_ALL)), i64::from(PLEDGE_ALL));
    done(&[t1, t2, t3, t4], &[d, other, child]);
}

/// **A caller in no Domain has nothing to narrow:** `-EINVAL`.
#[test]
fn a_task_in_no_domain_has_nothing_to_narrow() {
    let _g = serial();
    let t = task_in(SLOT_A, None);
    assert_eq!(pledge_call(u64::from(STEADY)), Errno::EINVAL.to_syscall_ret());
    done(&[t], &[]);
}

/// **The op is of the `Domain` kind, class admin**, so an image profile that
/// does not list it kills the task that asks (the profile of `PTPD.ELF` and
/// `ZENOHD.ELF` list it: `tests/host/seccomp-tests`).
#[test]
fn an_image_that_does_not_list_the_class_is_killed() {
    let _g = serial();
    assert_eq!((op_kind(DOMAIN_PLEDGE), op_class(DOMAIN_PLEDGE)), (CapKind::Domain as u8, CLASS_ADMIN));
    let d = domain::create().unwrap();
    let t = task_in(SLOT_A, Some(d));
    let mut f = SyscallFilter::disabled();
    f.enabled = true;
    f.allow_op(op(CapKind::Domain, CLASS_READ, 1));
    azos_sched::scheduler::set_current_syscall_filter(f);
    let _ = azos_sched::shim_take_exit_codes();
    let r = std::panic::catch_unwind(|| pledge_call(u64::from(STEADY)));
    assert!(r.is_err(), "the op's class is not listed: the task is ended, not answered");
    assert!(!azos_sched::shim_take_exit_codes().is_empty());
    // Listed: it runs.
    let mut f = SyscallFilter::disabled();
    f.enabled = true;
    f.allow_op(DOMAIN_PLEDGE);
    azos_sched::scheduler::set_current_syscall_filter(f);
    assert_eq!(pledge_call(u64::from(STEADY)), i64::from(STEADY | PLEDGE_ALWAYS));
    done(&[t], &[d]);
}

// ── The ring: one trap, many entries ───────────────────────────────────────
//
// `SYS_RING_ENTER` is a call of case block/wake, which a program that narrowed
// keeps, and the ring runs net, file, block and device entries in the kernel.
// The prologue judged the one trap only: the ring asks the mask itself, for
// each entry, by the call the entry stands for (`IoRingOps::pledge_allowed`).

mod ring {
    use super::*;
    use crate::ioring_ops::KERNEL_IORING_OPS;
    use azos_ipc::io_ring::{
        self as io, CqEntry, IoRing, SqEntry, CQE_F_REFUSED, IO_ERR_PLEDGE, IO_ERR_SECCOMP, OP_BLOCK_WRITE, OP_FILE_READ,
        OP_FILE_WRITE, OP_FSYNC, OP_MOTOR_SPEED, OP_NET_RECV, OP_NET_SEND, OP_NOTIFY_WAIT, OP_TIMER, RING_CQ_SIZE, RING_SQ_SIZE,
    };

    fn sqe(opcode: u16) -> SqEntry {
        SqEntry { opcode, flags: 0, param0: 0, param1: 0, param2: 8, addr: 0, reg: 0, user_data: 0x91ed }
    }

    /// A ring of `owner` (a kernel-style one: no user page table), and its page.
    fn ring_of(owner: u32) -> (u32, *mut IoRing) {
        azos_sched::set_current_user_pt(0);
        io::io_ring_register_ops(&KERNEL_IORING_OPS);
        let (id, phys) = io::io_ring_create(owner as usize).expect("ring");
        (id, phys as *mut IoRing)
    }

    /// Queue `e`, submit, and consume its completion.
    unsafe fn submit(id: u32, ring: *mut IoRing, e: SqEntry) -> CqEntry {
        let tail = (*ring).sq_tail.load(Ordering::Acquire);
        (*ring).sq_entries[tail as usize % RING_SQ_SIZE] = e;
        (*ring).sq_tail.store(tail.wrapping_add(1), Ordering::Release);
        let cq = (*ring).cq_tail.load(Ordering::Acquire);
        let _ = io::io_ring_submit(id);
        // Under IORING_ASYNC a file entry is the worker's: its turn follows.
        if azos_limits::IORING_ASYNC {
            io::io_ring_worker_pass();
        }
        let c = (*ring).cq_entries[cq as usize % RING_CQ_SIZE];
        (*ring).cq_head.store((*ring).cq_tail.load(Ordering::Acquire), Ordering::Release);
        c
    }

    fn refused(c: CqEntry) -> bool {
        c.result == IO_ERR_PLEDGE && c.flags == CQE_F_REFUSED
    }

    /// The `pledge` records of the task `subject`, oldest first.
    fn receipts(subject: u32) -> Vec<azos_decision::Record> {
        let mut v = Vec::new();
        azos_decision::for_each(|r| {
            if r.rule == azos_decision::Rule::Pledge as u8 && r.subject == subject {
                v.push(*r);
            }
        });
        v
    }

    const SLOT_C: usize = 51;

    /// **A Domain that gave up the net, write or read class, or the block/wake
    /// case, cannot do the same work as ring entries.** Each entry is judged
    /// by the bit of the call it stands for, refused with `-EACCES` and the
    /// refused flag, and leaves a `pledge` receipt (subject the owner task, the
    /// mask in force, the ring door, the call): the first of a bit a `Refuse`,
    /// the rest `Deny`. An entry of a bit the Domain
    /// kept is not refused by the mask, and nothing was refused before the
    /// Domain narrowed.
    ///
    /// **Canary.** Make `pledge_allowed` in `ioring_ops.rs` answer `true`: every
    /// refusal line fails (the entries run to their capability check instead).
    #[test]
    fn a_ring_entry_is_judged_by_its_domains_mask() {
        let _g = serial();
        let d = domain::create().unwrap();
        let t = task_in(SLOT_A, Some(d));
        let (id, ring) = ring_of(t);
        let all = |op| unsafe { submit(id, ring, sqe(op)) };

        // Whole: nothing is the mask's to refuse.
        for op in [OP_NET_SEND, OP_FILE_WRITE, OP_FILE_READ] {
            assert!(!refused(all(op)), "opcode {op} refused before anything was narrowed");
        }
        assert!(receipts(t).is_empty());

        // A steady state that reads files and sleeps/waits, and does no more.
        let keep = pledge_class(CLASS_READ) | pledge_case(CASE_BLOCK_WAKE);
        assert_eq!(pledge_call(u64::from(keep)), i64::from(keep | PLEDGE_ALWAYS));
        assert!(refused(all(OP_NET_SEND)), "net send");
        assert!(refused(all(OP_NET_RECV)), "net recv");
        assert!(refused(all(OP_FILE_WRITE)), "file write");
        assert!(refused(all(OP_FSYNC)), "fsync is a write");
        assert!(!refused(all(OP_FILE_READ)), "the read class was kept");
        assert!(!refused(all(OP_TIMER)), "a timer is a sleep");
        assert!(!refused(all(OP_NOTIFY_WAIT)), "a wait is a futex wait: the block/wake case was kept");

        // Giving up block/wake takes the device entries and the waits with it.
        let keep = pledge_class(CLASS_READ);
        assert_eq!(pledge_call(u64::from(keep)), i64::from(keep | PLEDGE_ALWAYS));
        assert!(refused(all(OP_MOTOR_SPEED)), "a device entry is an IPC call");
        assert!(refused(all(OP_BLOCK_WRITE)), "block entry");
        assert!(refused(all(OP_TIMER)), "timer");
        assert!(refused(all(OP_NOTIFY_WAIT)), "wait");
        assert!(!refused(all(OP_FILE_READ)), "the read class was kept");

        // The receipts, oldest first: net send, net recv, file write, fsync under
        // the first mask; the device entry, block write, timer and wait under the
        // second. One bit's first refusal is a `Refuse` (the net, write and
        // block/wake bits: three), the repeats `Deny`.
        let rs = receipts(t);
        let verdicts: Vec<u8> = rs.iter().map(|r| r.verdict).collect();
        let (refuse, deny) = (azos_decision::Verdict::Refuse as u8, azos_decision::Verdict::Deny as u8);
        assert_eq!(verdicts, [refuse, deny, refuse, deny, refuse, deny, deny, deny], "one Refuse per bit, the rest Deny");
        assert_eq!(rs[0].n[2], azos_abi::syscall_nr::SYS_INVOKE, "an op of a handle is a SYS_INVOKE");
        for (i, r) in rs.iter().enumerate() {
            let mask = if i < 4 { pledge_class(CLASS_READ) | pledge_case(CASE_BLOCK_WAKE) } else { pledge_class(CLASS_READ) };
            assert_eq!(r.n[0], u64::from(mask | PLEDGE_ALWAYS), "record {i}: the mask in force");
            assert_eq!(r.n[1], domain::Door::Ring.refused(), "record {i}: a ring entry, not a trapped call");
        }

        io::io_ring_release_all(t);
        done(&[t], &[d]);
    }

    /// **The Domain judged is the ring OWNER's, not the task that runs the
    /// entry.** The SQ poller is a kernel task in no Domain: its pass of a
    /// narrowed owner's ring is refused all the same; and a task of another,
    /// whole Domain running the pass does not lend its mask.
    ///
    /// **Canary.** Look the Domain up from the current task in `pledge_allowed`:
    /// the entry runs under the whole Domain's mask.
    #[test]
    fn the_owners_mask_binds_an_entry_another_task_runs() {
        let _g = serial();
        let d = domain::create().unwrap();
        let whole = domain::create().unwrap();
        let owner = task_in(SLOT_A, Some(d));
        let (id, ring) = ring_of(owner);
        let keep = pledge_class(CLASS_READ);
        assert_eq!(pledge_call(u64::from(keep)), i64::from(keep | PLEDGE_ALWAYS));
        // The owner's profile as the poller reads it (`task_syscall_verdict`).
        azos_sched::scheduler::shim_set_task_filter(owner, Some(SyscallFilter::disabled()));
        // Another task, of a whole Domain, runs the pass.
        let runner = task_in(SLOT_C, Some(whole));
        let c = unsafe { submit(id, ring, sqe(OP_NET_SEND)) };
        assert!(refused(c), "the pass of another task ran an entry the owner's Domain gave up: {:?}", (c.result, c.flags));
        assert_eq!(receipts(runner).len(), 0, "the runner's Domain was judged");
        assert_eq!(receipts(owner).len(), 1, "the receipt names the ring's owner, not the task that ran the pass");
        azos_sched::scheduler::shim_set_task_filter(owner, None);
        io::io_ring_release_all(owner);
        done(&[owner, runner], &[d, whole]);
    }

    /// **Seccomp answers first and keeps its own errno:** an owner whose profile
    /// refuses the call gets `-EPERM`, not the mask's `-EACCES`; the mask is
    /// asked only of what the profile let through.
    #[test]
    fn seccomp_is_asked_before_the_mask() {
        let _g = serial();
        let d = domain::create().unwrap();
        let t = task_in(SLOT_A, Some(d));
        let (id, ring) = ring_of(t);
        assert_eq!(pledge_call(u64::from(pledge_class(CLASS_READ))), i64::from(pledge_class(CLASS_READ) | PLEDGE_ALWAYS));
        let mut f = SyscallFilter::disabled();
        f.enabled = true;
        f.allow(azos_abi::syscall_nr::SYS_RING_ENTER as u16);
        azos_sched::scheduler::set_current_syscall_filter(f);
        let c = unsafe { submit(id, ring, sqe(OP_NET_SEND)) };
        assert_eq!((c.result, c.flags), (IO_ERR_SECCOMP, CQE_F_REFUSED));
        assert!(receipts(t).is_empty(), "the mask judged an entry seccomp had already refused");
        io::io_ring_release_all(t);
        done(&[t], &[d]);
    }
}

/// **`PTPD.ELF` and `ZENOHD.ELF` list `DOMAIN_PLEDGE`**, the one op they narrow
/// themselves with once their setup is done; an image profile that lacks it
/// ends the task that asks (`an_image_that_does_not_list_the_class_is_killed`),
/// so the row is what lets the two programs live.
///
/// **Canary.** Delete `DOMAIN_PLEDGE` from either row in `seccomp.rs`: this goes
/// red (and the program is killed at its pledge on the target).
#[test]
fn ptpd_and_zenohd_list_the_pledge_op() {
    for image in ["PTPD.ELF", "ZENOHD.ELF"] {
        let row = azos_sched::seccomp::IMAGE_PROFILES.iter().find(|p| p.image == image).expect("the image has a profile row");
        assert!(row.ops.contains(&DOMAIN_PLEDGE), "{image} cannot pledge");
    }
}

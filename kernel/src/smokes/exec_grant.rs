// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The launch check of an exec, in a running kernel.
//!
//! * `exec_with_a_launch_grant_is_admitted_with_a_record`: a task holding a
//!   launch grant on an image is admitted, and the admission is one
//!   `exec-grant` record naming the basis and the site.
//! * `exec_without_a_launch_grant_is_refused_with_a_record`: a task holding
//!   none is refused for an image no grant names and for one the table knows,
//!   each with one `exec-grant` refusal. Canary `canary=exec-grant-skip`: the
//!   check finds a grant on every image, the refusal is an admission, `not ok`.

use azos_abi::cap::CapPerms;
use azos_decision::{Rule, Verdict};
use azos_sync::SpinLock;
use azos_syscall::exec_grant::{decide, Basis, Site};
use core::sync::atomic::{AtomicBool, Ordering};

const PRIO: u32 = 5;
const GRANTED: &str = "KTXGRANT.ELF";
const KNOWN: &str = "KTXKNOWN.ELF";
const UNKNOWN: &str = "KTXNONE.ELF";
const DIGEST: [u8; 32] = [0xE7; 32];

type Verdict_ = Result<(), &'static str>;

static DONE: [AtomicBool; 2] = [const { AtomicBool::new(false) }; 2];
static REASON: SpinLock<[Option<Verdict_>; 2]> = SpinLock::new([None, None]);

fn recorded(tid: u32, since: u64, verdict: Verdict, basis: Basis, site: Site) -> bool {
    let mut found = false;
    azos_decision::for_each(|r| {
        found |= r.seq > since
            && r.rule == Rule::ExecGrant as u8
            && r.verdict == verdict as u8
            && r.subject == tid
            && r.n[1] == basis as u64
            && r.n[2] == site as u64
            && r.n[0] == u64::from_be_bytes([DIGEST[0]; 8]);
    });
    found || !azos_decision::ON
}

fn admitted(tid: u32) -> Verdict_ {
    azos_ipc::launch_cap::launch_grant_cap(tid, GRANTED, CapPerms::EXEC).ok_or("the launch grant was not minted")?;
    let since = azos_decision::total();
    if decide(tid, Site::SpawnEx, GRANTED, &DIGEST) != Ok(Basis::Image) {
        return Err("a task holding the grant was refused");
    }
    if !recorded(tid, since, Verdict::Admit, Basis::Image, Site::SpawnEx) {
        return Err("the admission left no exec-grant record");
    }
    Ok(())
}

fn refused(tid: u32) -> Verdict_ {
    azos_ipc::launch_cap::launch_resource(KNOWN.as_bytes()).ok_or("the launch table refused a name")?;
    for image in [KNOWN, UNKNOWN] {
        let since = azos_decision::total();
        if decide(tid, Site::Execve, image, &DIGEST).is_ok() {
            return Err("a task holding no grant was admitted");
        }
        if !recorded(tid, since, Verdict::Refuse, Basis::NoGrant, Site::Execve) {
            return Err("the refusal left no exec-grant record");
        }
    }
    Ok(())
}

fn body(k: usize) {
    let tid = azos_sched::current_task_tid();
    let r = if k == 0 { admitted(tid) } else { refused(tid) };
    azos_ipc::cap_store::with_table(tid, |t| t.delete_where(|_, _| true));
    REASON.lock()[k] = Some(r);
    DONE[k].store(true, Ordering::Release);
}

fn run(name: &'static str, k: usize) -> Verdict_ {
    azos_sched::task_create_affinity(name, body, k, PRIO, -1);
    crate::ktest::wait("the task never reported", || DONE[k].load(Ordering::Acquire))?;
    REASON.lock()[k].take().unwrap_or(Err("no verdict"))
}

azos_ktest::ktest_late! {
    fn exec_with_a_launch_grant_is_admitted_with_a_record() {
        run("exec-grant-yes", 0)
    }
}

azos_ktest::ktest_late! {
    fn exec_without_a_launch_grant_is_refused_with_a_record() {
        run("exec-grant-no", 1)
    }
}

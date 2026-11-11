// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// What a Linux task may not widen through `clone` and `execve`: `process.rs`
// and `linux.rs` are not compiled here, so the wiring is read from their
// source (the behaviour of the count is `tests/host/sched-policy-tests`
// `row_gate_tests`, the end-to-end rows are the gate's `linux: fork past the
// row's instances` and `linux: execve row scheduling canary`).
//
// * `the_fork_claims_its_row_before_the_child_exists_and_gives_it_back`:
//   a fork child counts against its row's `instances`.
// * `an_exec_into_another_row_takes_that_rows_scheduling`: the new image runs
//   with the target row's class and priority, and a row with a reservation is
//   refused before anything is built.
//
// **Canaries (by hand).** Delete the `row_claim_for_fork` call, the child's
// `set_task_mem_row`, or either release: the first row is red. Delete the
// `apply_exec_row` call or the `exec_may_enter` check: the second is red. The
// compiled canaries are `fork-row-instance-canary` and
// `exec-row-sched-canary` (their gate rows).

/// `path`'s source with comments dropped and whitespace removed.
fn code(src: &str) -> String {
    src.lines().map(|l| l.split("//").next().unwrap()).collect::<Vec<_>>().join("\n").split_whitespace().collect()
}

/// The text of `f`'s body: from its signature to the next top-level `}`.
fn body(src: &str, f: &str) -> String {
    let at = src.find(f).unwrap_or_else(|| panic!("{f} moved"));
    let end = src[at..].find("\n}\n").map_or(src.len(), |e| at + e);
    src[at..end].to_string()
}

#[test]
fn the_fork_claims_its_row_before_the_child_exists_and_gives_it_back() {
    let raw = include_str!("../../../../crates/core/sched/src/process.rs");
    let fork = code(&body(raw, "fn fork_hooked_inner("));
    let claim = fork.find("row_claim_for_fork(parent_row)").expect("the fork claims its row");
    let create = fork.find("try_task_create_init(").expect("the child is created");
    assert!(claim < create, "the claim comes before the child exists");
    let refused = &fork[claim..create];
    assert!(refused.contains("note_fork_refusal(ForkRefusalSite::Instances)"), "a refusal is recorded");
    assert!(refused.contains("aspace::destroy(child_space)"), "a refusal gives the space back");
    let after = &fork[create..];
    let pool = after.find("ForkRefusalSite::PoolExhausted").expect("pool exit");
    assert!(after[..pool].contains("row_release(parent_row)"), "a full pool gives the count back");
    let miss = after.find("ForkRefusalSite::TidLookupMiss").expect("tid exit");
    assert!(after[pool..miss].contains("row_release(parent_row)"), "a lost slot gives the count back");
    assert!(after[miss..].contains("set_task_mem_row(child_idx,parent_row)"), "the child's exit gives it back");
    // The exit that returns the count is the one that returns a spawn's.
    let life = code(include_str!("../../../../crates/core/sched/src/scheduler/lifecycle.rs"));
    assert!(life.contains("lett=task_mut(idx);letrow=t.mem.row;t.mem.row=0;row_release(row);"), "the exit releases the task's row once");
}

#[test]
fn an_exec_into_another_row_takes_that_rows_scheduling() {
    let linux = include_str!("../../../../crates/core/syscall/src/linux.rs");
    let exec = code(&body(linux, "fn exec_image("));
    let may = exec.find("exec_may_enter(profile.image)").expect("a row with a reservation is refused");
    let build = exec.find("with_elf(").expect("the image is built");
    assert!(may < build, "refused before anything is built");
    let enter = code(&body(linux, "fn enter_row("));
    assert!(enter.contains("apply_exec_row(me,profile.image)"), "the row's scheduling is applied with its caps and filter");
    let topo = code(&body(include_str!("../../../../crates/core/syscall/src/topo_sched.rs"), "pub fn apply_exec_row("));
    for want in ["rt::withdraw(", "set_current_sched_params(", "set_timer_slack_row(slack)", "set_call_budget(budget)"] {
        assert!(topo.contains(want), "apply_exec_row misses {want}");
    }
}

// Small closes of the 11-11 audit's lows, read from the source for the same
// reason: `sched_getaffinity` asks `may_signal` for a task that is not the
// caller (L-6); `close` releases only on the slot's own transition (L-4); a
// personality entry whose TID is no longer a Linux task's is reusable (L-5).
// **Canary (by hand).** Delete the check named: red.
#[test]
fn the_personality_closes_its_probes_and_races() {
    let linux = include_str!("../../../../crates/core/syscall/src/linux.rs");
    let aff = code(&body(linux, "nr::SCHED_GETAFFINITY =>"));
    assert!(aff.contains("tid!=me_thread&&!may_signal("), "a TID the caller may not signal is ESRCH");
    let close = code(&body(linux, "fn sys_close("));
    assert!(close.contains("p.fds[fdasusize].kind==Kind::Closed{returnNone;}"), "a closed slot is not closed twice");
    assert!(close.contains("Some(None)=>returnneg(le::EBADF)"), "the loser of the race gets EBADF");
    let init = code(&body(linux, "pub fn proc_init("));
    assert!(init.contains("!azos_sched::scheduler::tid_is_linux(p.tid)"), "an entry of a recycled TID is reusable");
}

/// A call the personality answers `-ENOSYS`, and a translated call a seccomp
/// profile refuses, are counted per number (`NOT_ANSWERED`, `SECCOMP_REFUSED`):
/// the evidence the next Linux call is added on. The count itself is
/// `tests/host/linux-abi-tests` `unanswered_tally`; this reads that the two
/// places feed it. **Canary (by hand).** Delete either `record`: red.
#[test]
fn the_unanswered_and_refused_calls_are_counted() {
    let linux = include_str!("../../../../crates/core/syscall/src/linux.rs");
    let un = code(&body(linux, "fn unanswered("));
    assert!(un.contains("NOT_ANSWERED.record(num)") && un.contains("neg(le::ENOSYS)"));
    let reach = code(&body(linux, "fn reach("));
    assert!(reach.contains("SECCOMP_REFUSED.record(num);crate::handlers::seccomp_deny_kill(num)"), "a refusal is counted before the task is ended");
}

/// One claim for every fork: the native `sys_fork` (reached through
/// `SYS_FOREIGN_FORK`) and the personality's `clone` both fork through
/// `sys_fork_impl_hooked`, which is where the row's instance is claimed
/// (`the_fork_claims_its_row_before_the_child_exists_and_gives_it_back`), and
/// neither creates a child task of its own. **Canary (by hand).** Make either
/// caller create the child itself: red.
#[test]
fn native_and_linux_forks_share_the_one_claim() {
    let handlers = code(&body(include_str!("../../../../crates/core/syscall/src/handlers.rs"), "pub fn sys_fork("));
    let linux = code(&body(include_str!("../../../../crates/core/syscall/src/linux.rs"), "fn sys_clone("));
    for (who, src) in [("sys_fork", &handlers), ("sys_clone", &linux)] {
        assert!(src.contains("sys_fork_impl_hooked("), "{who} forks through the shared path");
        assert!(!src.contains("try_task_create"), "{who} creates no child of its own");
    }
}

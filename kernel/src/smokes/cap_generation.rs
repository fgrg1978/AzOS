// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! A capability slot's generation running out, in a running kernel.
//!
//! * `cap_slot_restarts_past_its_last_generation`: a domain with one free slot
//!   opens and closes well past the point a slot used to be lost, and a stale
//!   handle is refused across that point and across the restart. Canary
//!   `canary=cap-gen-retire`: nothing restarts, the open at the end of the
//!   cycle is refused, `not ok`.
//! * `cap_table_full_refuses_with_a_record`: a grant into a full table is
//!   refused and leaves a `cap-table-full` record. Canary
//!   `canary=cap-full-silent`: the refusal is silent, `not ok`.

use azos_abi::cap::{CapHandle, CapPerms};
use azos_decision::{Rule, Verdict};
use azos_ipc::cap::targets::Port;
use azos_ipc::cap::{Cap, CapError};
use azos_ipc::cap_store;
use azos_sync::SpinLock;
use core::sync::atomic::{AtomicBool, Ordering};

const PRIO: u32 = 5;
const CYCLE: u32 = CapHandle::MAX_GENERATION as u32;
const OLD_LIMIT: u32 = 2047;
const FILLER: u32 = 0xC000;

type Verdict_ = Result<(), &'static str>;

static DONE: [AtomicBool; 2] = [const { AtomicBool::new(false) }; 2];
static REASON: SpinLock<[Option<Verdict_>; 2]> = SpinLock::new([None, None]);

fn finish(k: usize, tid: u32, r: Verdict_) {
    // A filler names no object: nothing to release but the slot.
    cap_store::with_table(tid, |t| t.delete_where(|_, _| true));
    REASON.lock()[k] = Some(r);
    DONE[k].store(true, Ordering::Release);
}

fn fill_to(tid: u32, left: usize) -> Verdict_ {
    let free = cap_store::with_table(tid, |t| t.free_slots()).ok_or("the task has no table")?;
    for i in 0..free.checked_sub(left).ok_or("the table is too full to start")? {
        cap_store::grant::<Port>(tid, CapPerms::RW, FILLER + i as u32).ok_or("a free slot refused a grant")?;
    }
    Ok(())
}

fn open(tid: u32, res: u32) -> Result<Cap<Port>, &'static str> {
    cap_store::grant(tid, CapPerms::RW, res).ok_or("a domain with a free slot was refused an open")
}

fn close(tid: u32, c: Cap<Port>) -> Verdict_ {
    if cap_store::with_table(tid, |t| t.delete_raw(c.raw())) == Some(true) {
        Ok(())
    } else {
        Err("a live handle would not close")
    }
}

fn stale(tid: u32, c: Cap<Port>) -> Verdict_ {
    match cap_store::get(tid, c, CapPerms::READ) {
        Err(CapError::Stale) => Ok(()),
        _ => Err("a stale handle was not refused"),
    }
}

fn churn(tid: u32) -> Verdict_ {
    fill_to(tid, 1)?;
    let first = open(tid, 1)?;
    close(tid, first)?;
    let (mut at_old_limit, mut at_top) = (None, None);
    let mut gen = first.raw().generation() as u32;
    while gen < CYCLE {
        let c = open(tid, gen)?;
        gen = c.raw().generation() as u32;
        if cap_store::get(tid, c, CapPerms::READ) != Ok(gen - 1) {
            return Err("an open past the old limit does not resolve");
        }
        stale(tid, first)?;
        if let Some(old) = at_old_limit {
            stale(tid, old)?;
        }
        if gen == OLD_LIMIT {
            at_old_limit = Some(c);
        }
        if gen == CYCLE {
            at_top = Some(c);
        }
        close(tid, c)?;
    }
    let (at_old_limit, at_top) = (at_old_limit.ok_or("no old limit")?, at_top.ok_or("no top")?);
    let c = open(tid, 7)?;
    if c.raw().generation() != 1 || c.raw().slot() != first.raw().slot() {
        return Err("the slot did not restart at generation 1");
    }
    stale(tid, at_top)?;
    stale(tid, at_old_limit)?;
    close(tid, c)?;
    // Past the old limit again in the new cycle, and still one slot.
    for i in 0..2 * OLD_LIMIT {
        let c = open(tid, i)?;
        stale(tid, at_top)?;
        close(tid, c)?;
    }
    Ok(())
}

fn full(tid: u32) -> Verdict_ {
    fill_to(tid, 0)?;
    let since = azos_decision::total();
    if cap_store::grant::<Port>(tid, CapPerms::RW, 1).is_some() {
        return Err("a full table granted");
    }
    if !azos_decision::ON {
        return Ok(());
    }
    let live = cap_store::with_table(tid, |t| t.occupied()).unwrap_or(0) as u64;
    let mut found = false;
    azos_decision::for_each(|r| {
        found |= r.seq > since
            && r.rule == Rule::CapTableFull as u8
            && r.verdict == Verdict::Refuse as u8
            && r.n[0] == live
            && r.n[1] == 0;
    });
    if found { Ok(()) } else { Err("the refusal left no cap-table-full record") }
}

fn body(k: usize) {
    let tid = azos_sched::current_task_tid();
    let r = if k == 0 { churn(tid) } else { full(tid) };
    finish(k, tid, r);
}

fn run(name: &'static str, k: usize) -> Verdict_ {
    azos_sched::task_create_affinity(name, body, k, PRIO, -1);
    crate::ktest::wait("the task never reported", || DONE[k].load(Ordering::Acquire))?;
    REASON.lock()[k].take().unwrap_or(Err("no verdict"))
}

azos_ktest::ktest_late! {
    fn cap_slot_restarts_past_its_last_generation() {
        run("cap-gen-churn", 0)
    }
}

azos_ktest::ktest_late! {
    fn cap_table_full_refuses_with_a_record() {
        run("cap-gen-full", 1)
    }
}

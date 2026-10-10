// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The periodic fast-IPC census task (`ipc-census`).

use crate::*;

/// Period of the census print.
#[cfg(feature = "ipc-census")]
const IPC_CENSUS_INTERVAL: u64 = 20_000_000; // 2 s at the 10 MHz CLINT

/// Fast-IPC slot census — prints `(pending, accepted, replied)` every few
/// seconds. Diagnostic only, compiled out unless `--features ipc-trace`.
///
/// **WHY a periodic census and not the per-exchange trace.** When a fast-IPC
/// exchange wedges, the client sits on `FastIpcClient(slot)` and the server on
/// `FastIpcServer(tid)`, and the log cannot tell whether the slot is `Pending`
/// (the server lost the wake) or `Accepted` (it took the call and never
/// answered). Those are different bugs. The per-exchange `ipc_trace!` would
/// answer it but costs six UART writes per exchange — enough to move the race:
/// measured, the traced build reaches `ALL PASSED` 8/8 where the untraced one
/// wedges. One three-integer line every few seconds does not.
///
/// Reading a rising `accepted` count that never drains is the signature of a
/// server that stopped replying; a rising `pending` count is a server that
/// stopped being woken.
#[cfg(feature = "ipc-census")]
pub(crate) fn ipc_census_task(_arg: usize) {
    let mut last = (0u32, 0u32, 0u32, 0u32);
    loop {
        let now = azos_ipc::fastcall::census();
        // Only speak when something changed — a steady state prints nothing and
        // costs nothing, so a wedge shows up as the last line before silence.
        if now != last {
            // The scheduler side is what separates the two explanations for a
            // wedge whose reply is already deposited: a `Blocked` client lost
            // its wake, a `Ready` one is being starved. Printed together so the
            // two halves can never be read from different moments.
            let (ready, blocked, running, per_cpu, ready_unq, blk_q, by_rsn) =
                azos_sched::task_census();
            kprintln!(
                "[IPC-CENSUS] pending={} accepted={} replied={} used={} (suma={}) | ready={} blocked={} running={} | rq={:?} | LOST ready_unqueued={} blocked_queued={}",
                now.0, now.1, now.2, now.3, now.0 + now.1 + now.2, ready, blocked, running, per_cpu,
                ready_unq, blk_q);
            kprintln!("[IPC-CENSUS] blocked_on: fastclient={} fastserver={} timer={} waitq={} otros={}",
                by_rsn[0], by_rsn[1], by_rsn[2], by_rsn[3], by_rsn[4]);
            let (ft, fr, fw, fg, fe, fns, fw0) = azos_syscall::dispatch::fast_call_stats::read();
            kprintln!("[IPC-CENSUS] fast_call: turns={} ready={} waiting={} waiting_turn0={} gone={} exhausted={} no_slot={}",
                ft, fr, fw, fw0, fg, fe, fns);
            let u = azos_sched::unswitched::read();
            let bsp = azos_sched::unswitched::block_split();
            kprintln!("[IPC-CENSUS] no-switch returns WITH CURRENT BLOCKED: aps={} queue={} self={} | with Running: aps={} queue={} self={} | block skipped={} slept={}",
                u.0, u.1, u.2, u.3, u.4, u.5, bsp.0, bsp.1);
            let (d, st, mm, ab, enq, late, sched_enq) = azos_sched::wake_counters();
            kprintln!("[IPC-CENSUS] wake: dispatched={} stamped={} MISMATCH={} absent={} enq_refused={} late_dispatch={} sched_enq_refused={}",
                d, st, mm, ab, enq, late, sched_enq);
            // The two halves, printed together: live slots by identity, and
            // tasks asleep in fast-IPC by identity. If the `caller` of a
            // `Replied` slot (code 3) matches the `tid` of a sleeping client
            // and its `slot` matches the index, the wake was lost despite
            // every counter. If they do not match, the premise was false and
            // the wedge is something else.
            let mut slots = [(0u8, 0u8, 0u32, 0u32); 8];
            let ns = azos_ipc::fastcall::slot_ids(&mut slots);
            for e in slots.iter().take(ns) {
                kprintln!("[IPC-CENSUS]   slot idx={} state={} caller={} server={}",
                    e.0, e.1, e.2, e.3);
            }
            // Identities of the impossible state: Ready with no queue. The
            // counter says how many; this says WHO — which is what separates
            // "the server is starving" from "an irrelevant background task
            // got stranded".
            let mut unq = [(0u32, 0u32, 0u32, [0u8; 8], 0u8); 8];
            let nu = azos_sched::ready_unqueued_ids(&mut unq);
            for e in unq.iter().take(nu) {
                let name = core::str::from_utf8(&e.3).unwrap_or("?");
                kprintln!("[IPC-CENSUS]   READY-UNQUEUED tid={} prio={} home={} name={} by={} on_hart={}",
                    e.0, e.1, e.2, name,
                    azos_sched::task::ready_site::name(e.4), e.4 >> 4);
            }
            // Who is each hart actually running? Separates "ready tasks
            // starve behind a current that never yields" from "ready tasks
            // lost by the queues" — the run-6 (2026-08-24) wedge shape.
            let mut cur = [(0u32, 0u32, [0u8; 8]); azos_sched::MAX_CPUS];
            azos_sched::current_snapshot(&mut cur);
            for (cpu, e) in cur.iter().enumerate() {
                if e.0 == 0 { continue; }
                let name = core::str::from_utf8(&e.2).unwrap_or("?");
                kprintln!("[IPC-CENSUS]   cpu={} cur_tid={} word={:#x} name={}",
                    cpu, e.0, e.1, name);
            }
            // `word` is the raw K-C19 state word (bit 3 = WAKE_STAMP) and
            // `saving` the K-C24 gate: a task stuck at Blocked+saving=true is
            // one every wake can only stamp and no switch-out will ever sweep.
            let mut blk = [(0u32, false, 0u32, 0u32, false); 8];
            let nb = azos_sched::blocked_fastipc_ids(&mut blk);
            for e in blk.iter().take(nb) {
                kprintln!("[IPC-CENSUS]   blocked tid={} client={} payload={} word={:#x} saving={}",
                    e.0, e.1, e.2, e.3, e.4);
            }
            last = now;
        }
        // Same timer-block idiom as the sensor tasks: a yield loop would spin
        // hot and compete with the very race this is measuring.
        let dl = azos_drv_sys::timebase::now() + IPC_CENSUS_INTERVAL;
        azos_sched::task_block(azos_sched::WaitReason::Timer(dl));
    }
}

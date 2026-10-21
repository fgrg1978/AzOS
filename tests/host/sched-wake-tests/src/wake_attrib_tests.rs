// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Wake attribution (`scheduler/wake/attrib.rs`): the source of a wake for each
//! way of making one, what an entry names, and the ring a reader gets entries
//! from while wakes are being logged.

use crate::task::WaitReason;
use crate::wake_attrib::{
    classify, classify_targeted, detail, irq_enter, irq_leave, irq_line, logged, names_waker, sampled_in, source, Entry, Reason,
    Ring, Src, Via, ENABLED, SAMPLE_LOG2,
};

#[test]
fn every_source_has_a_name_and_its_number_comes_back() {
    let mut seen = std::collections::HashSet::new();
    for (i, s) in Src::ALL.iter().enumerate() {
        assert_eq!(*s as usize, i, "{} is out of order", s.name());
        assert!(seen.insert(s.name()), "{} is named twice", s.name());
        assert_eq!(Src::from_u8(i as u8), Some(*s));
        assert!(!s.name().contains(' '), "the published list is split on spaces");
    }
    assert_eq!(Src::from_u8(Src::ALL.len() as u8), None, "a number past the list names nothing");
    let all: Vec<_> = Src::ALL.iter().map(|s| s.name()).collect();
    assert!(all.join(" ").len() <= 127, "the published list must fit the node");
}

#[test]
fn the_reason_follows_the_wait_reason() {
    assert_eq!(Reason::of(&WaitReason::None), Reason::None);
    assert_eq!(Reason::of(&WaitReason::Ring(3)), Reason::Ring);
    assert_eq!(Reason::of(&WaitReason::Timer(9)), Reason::Timer);
    assert_eq!(Reason::of(&WaitReason::Port(7)), Reason::Port);
    assert_eq!(Reason::of(&WaitReason::WaitQueue), Reason::WaitQueue);
    assert_eq!(Reason::of(&WaitReason::FastIpcServer(4)), Reason::FastIpcServer);
    assert_eq!(Reason::of(&WaitReason::FastIpcClient(5)), Reason::FastIpcClient);
}

#[test]
fn an_ipc_hand_off_is_a_call_or_a_reply_by_what_the_task_waited_on() {
    assert_eq!(classify(Via::Ipc, Reason::FastIpcServer), Src::IpcCall);
    assert_eq!(classify(Via::Ipc, Reason::FastIpcClient), Src::IpcReply);
    // The hand-off is never an interrupt's, whatever the context says.
    assert_eq!(source(Via::Ipc, Reason::FastIpcServer, true, true), Src::IpcCall);
}

#[test]
fn a_sweep_is_attributed_to_what_the_sleeper_waited_on() {
    assert_eq!(source(Via::Sweep, Reason::Timer, true, false), Src::Timer, "the tick's timer sweep, in interrupt context");
    assert_eq!(source(Via::Sweep, Reason::Ring, false, false), Src::Ring);
    assert_eq!(source(Via::Sweep, Reason::Port, false, false), Src::Port);
    assert_eq!(source(Via::Sweep, Reason::FastIpcClient, false, false), Src::IpcReply, "the orphan sweep of a dead server");
}

#[test]
fn the_wait_queue_the_reaper_and_a_named_source_are_what_the_caller_says() {
    assert_eq!(source(Via::WaitQueue, Reason::WaitQueue, false, false), Src::WaitQueue);
    assert_eq!(source(Via::Reap, Reason::Port, false, false), Src::Reap);
    assert_eq!(source(Via::As(Src::Futex), Reason::Timer, false, false), Src::Futex);
    assert_eq!(source(Via::As(Src::Notify), Reason::Timer, true, true), Src::Notify, "a named source is not second-guessed");
}

#[test]
fn a_task_wake_is_attributed_by_the_reason() {
    assert_eq!(classify_targeted(Reason::Port, false, false), Src::Port);
    assert_eq!(classify_targeted(Reason::Ring, false, false), Src::Ring);
    assert_eq!(classify_targeted(Reason::Timer, false, false), Src::Wake, "a timed sleeper woken early");
    assert_eq!(classify_targeted(Reason::FastIpcServer, false, false), Src::IpcCall);
    assert_eq!(classify_targeted(Reason::FastIpcClient, false, false), Src::IpcReply);
}

#[test]
fn an_irq_wake_names_its_line() {
    // The delivery of a bound line wakes the port's waiter, which may be blocked
    // on the port or on a timer (a wait with a deadline): the line decides.
    for r in [Reason::Port, Reason::Timer] {
        assert_eq!(classify_targeted(r, true, true), Src::Irq, "{r:?}");
    }
    if ENABLED {
        irq_enter(0, 33);
        assert_eq!(irq_line(0), Some(33));
        let got = detail(classify_targeted(Reason::Port, true, irq_line(0).is_some()), irq_line(0), true, || 99);
        irq_leave(0);
        assert_eq!(got, 33, "the entry carries the line, not the task the interrupt interrupted");
    }
}

#[test]
fn an_interrupt_wake_without_a_line_is_the_kernels_own_and_names_no_waker() {
    let s = classify_targeted(Reason::Timer, true, false);
    assert_eq!(s, Src::Isr);
    assert_eq!(detail(s, None, true, || panic!("the interrupted task is not the waker")), 0);
}

#[test]
fn the_waker_is_read_only_for_a_source_that_names_one() {
    for s in Src::ALL {
        let mut asked = false;
        let d = detail(s, None, false, || {
            asked = true;
            77
        });
        assert_eq!(asked, names_waker(s) && s != Src::Irq, "{}", s.name());
        assert_eq!(d, if asked { 77 } else { 0 }, "{}", s.name());
    }
    // From interrupt context no source names a waker (but the line).
    for s in Src::ALL.iter().filter(|s| **s != Src::Irq) {
        assert_eq!(detail(*s, None, true, || 77), 0, "{}", s.name());
    }
}

#[test]
fn the_irq_cell_is_per_cpu_and_cleared_after_the_delivery() {
    if !ENABLED {
        return;
    }
    irq_enter(1, 7);
    assert_eq!(irq_line(1), Some(7));
    assert_eq!(irq_line(2), None, "another CPU's cell is not set");
    irq_enter(1, 0);
    assert_eq!(irq_line(1), Some(0), "line 0 is a line");
    irq_leave(1);
    assert_eq!(irq_line(1), None);
    assert_eq!(irq_line(usize::MAX), None, "a CPU past the table has none");
}

#[test]
fn the_wakes_tasks_make_are_sampled_by_their_domains_count() {
    // The first wake of a Domain is logged, then one in 2^SAMPLE_LOG2.
    assert!(sampled_in(0));
    let every = 1u64 << SAMPLE_LOG2;
    let logged = (0..10 * every).filter(|n| sampled_in(*n)).count() as u64;
    assert_eq!(logged, 10, "one in {every}");
    assert_eq!((0..10 * every).filter(|n| sampled_in(*n)).nth(1), Some(every));
}

#[test]
fn the_sampling_policy_per_path() {
    assert!(SAMPLE_LOG2 > 0, "the policy is only visible with sampling on");
    let (first, other) = (0u64, 1u64);
    let no = || false;
    let yes = || true;
    // Sampled: what tasks make, and the ring / port / wait-queue wakes of a sweep.
    for (via, reason) in [
        (Via::Ipc, Reason::FastIpcServer),
        (Via::As(Src::Futex), Reason::None),
        (Via::WaitQueue, Reason::WaitQueue),
        (Via::Targeted, Reason::Port),
        (Via::Sweep, Reason::Ring),
        (Via::Sweep, Reason::Port),
        (Via::Sweep, Reason::WaitQueue),
    ] {
        assert!(logged(via, reason, first, no), "{via:?}/{reason:?}: the first of a Domain");
        assert!(!logged(via, reason, other, no), "{via:?}/{reason:?}: the rest are sampled out");
    }
    // Logged in full: the machine's own.
    assert!(logged(Via::Sweep, Reason::Timer, other, no), "a deadline");
    assert!(logged(Via::Sweep, Reason::FastIpcClient, other, no), "the orphan sweep");
    assert!(logged(Via::Reap, Reason::None, other, no), "the reaper");
    assert!(logged(Via::Targeted, Reason::Port, other, yes), "an interrupt handler's wake");
    assert!(!logged(Via::Ipc, Reason::FastIpcClient, other, yes), "the hand-off is never an interrupt's");
}

// ── The ring ────────────────────────────────────────────────────────────────

fn push(r: &Ring<8>, v: u64) {
    r.push(v, v as u32, (v as u32).rotate_left(7), !(v as u32), Src::ALL[(v % 12) as usize], (v % 5) as u8, (v % 3) as u8);
}

#[test]
fn the_newest_wakes_come_back_newest_first_with_their_fields() {
    let r = Ring::<8>::new();
    r.push(1_000, 41, 0x30002, 7, Src::IpcCall, 1, 2);
    r.push(2_000, 42, 0, 0, Src::Timer, 0, 0);
    let mut out = [Entry::default(); 8];
    assert_eq!(r.snapshot(&mut out), 2);
    assert_eq!(
        out[0],
        Entry { seq: 1, at: 2_000, tid: 42, domain: 0, detail: 0, src: Src::Timer as u8, target_cpu: 0, waker_cpu: 0 }
    );
    assert_eq!(
        out[1],
        Entry { seq: 0, at: 1_000, tid: 41, domain: 0x30002, detail: 7, src: Src::IpcCall as u8, target_cpu: 2, waker_cpu: 1 }
    );
    assert_eq!(r.offered(), 2);
}

#[test]
fn a_ring_that_lapped_keeps_the_last_n_and_counts_all() {
    let r = Ring::<8>::new();
    for v in 0..21u64 {
        push(&r, v);
    }
    let mut out = [Entry::default(); 16];
    let n = r.snapshot(&mut out);
    assert_eq!(n, 8, "the ring holds 8");
    assert_eq!(r.offered(), 21, "the count is of every wake, not of the entries kept");
    for (k, e) in out[..n].iter().enumerate() {
        assert_eq!(e.seq, 20 - k as u64);
        assert_eq!(e.at, e.seq, "entry {k}");
    }
    let mut few = [Entry::default(); 3];
    assert_eq!(r.snapshot(&mut few), 3, "a short buffer takes the newest");
    assert_eq!(few[0].seq, 20);
}

#[test]
fn a_ring_nobody_woke_through_is_empty() {
    let r = Ring::<8>::new();
    let mut out = [Entry::default(); 8];
    assert_eq!(r.snapshot(&mut out), 0);
    assert_eq!(r.offered(), 0);
}

#[test]
fn a_reader_never_gets_a_mixed_entry_while_wakes_are_logged() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    let r = Arc::new(Ring::<8>::new());
    let stop = Arc::new(AtomicBool::new(false));
    let writers: Vec<_> = (0..3u64)
        .map(|w| {
            let (r, stop) = (r.clone(), stop.clone());
            std::thread::spawn(move || {
                let mut v = w << 40;
                while !stop.load(Ordering::Relaxed) {
                    // Every field is a function of `v`: a slot mixed from two wakes breaks it.
                    push(&r, v);
                    v += 1;
                }
            })
        })
        .collect();
    let mut checked = 0u64;
    let mut out = [Entry::default(); 8];
    let started = std::time::Instant::now();
    while started.elapsed() < std::time::Duration::from_millis(400) {
        let n = r.snapshot(&mut out);
        for e in &out[..n] {
            let v = e.at;
            assert_eq!(e.tid, v as u32, "{e:?}");
            assert_eq!(e.domain, (v as u32).rotate_left(7), "{e:?}");
            assert_eq!(e.detail, !(v as u32), "{e:?}");
            assert_eq!(e.src as u64, v % 12, "{e:?}");
            assert_eq!(e.waker_cpu as u64, v % 5, "{e:?}");
            assert_eq!(e.target_cpu as u64, v % 3, "{e:?}");
            checked += 1;
        }
        assert!(out[..n].windows(2).all(|p| p[0].seq > p[1].seq), "newest first, no entry twice");
    }
    stop.store(true, Ordering::Relaxed);
    for w in writers {
        w.join().unwrap();
    }
    assert!(checked > 1_000, "the reader read {checked} entries: the test did not exercise the ring");
}

/// A wake that took its ticket and was preempted for a whole lap of the ring
/// arrives when the slot is the next lap's: it must not write over it. (Before
/// the exclusion its stores landed one by one in a slot a reader was
/// copying, and the reader got `at` of one wake with `tid` of another.)
#[test]
fn a_late_writer_does_not_clobber_a_newer_entry() {
    let r = Ring::<4>::new();
    let late = r.claim();
    assert_eq!(late, 0);
    // The lap goes by, and ticket 4 writes the slot the late one will want.
    for v in 1..=4u64 {
        let t = r.claim();
        assert_eq!(t, v);
        r.open(t).expect("a free slot").commit(100 + v, v as u32, 0, 0, Src::Futex, 0, 1);
    }
    assert!(r.open(late).is_none(), "the slot holds a later ticket");
    let mut out = [Entry::default(); 4];
    let n = r.snapshot(&mut out);
    assert_eq!(n, 4, "the refusal gave the newer entry back");
    for (k, e) in out[..n].iter().enumerate() {
        assert_eq!(e.seq, 4 - k as u64);
        assert_eq!((e.at, e.tid), (100 + e.seq, e.seq as u32), "{e:?}");
    }
}

/// Two wakes of one slot a lap apart, the first in the middle of its stores:
/// the second is refused, not interleaved with it.
#[test]
fn a_writer_in_the_middle_of_its_stores_keeps_the_next_lap_out() {
    let r = Ring::<4>::new();
    let first = r.claim();
    let held = r.open(first).expect("a free slot");
    for _ in 1..4 {
        let t = r.claim();
        r.open(t).expect("another slot").commit(t, t as u32, 0, 0, Src::Port, 0, 0);
    }
    let next_lap = r.claim();
    assert_eq!(next_lap, 4);
    assert!(r.open(next_lap).is_none(), "the slot is owned until the first commits");
    let mut out = [Entry::default(); 4];
    assert_eq!(r.snapshot(&mut out), 3, "a slot a writer owns is skipped, the others are read");
    held.commit(first + 50, 9, 0, 8, Src::Futex, 2, 3);
    let n = r.snapshot(&mut out);
    // The ring is at ticket 5: its window is 4, 3, 2, 1. Ticket 4 left no entry; 0 is a lap old.
    assert_eq!(out[..n].iter().map(|e| e.seq).collect::<Vec<_>>(), vec![3, 2, 1]);
    // The next ticket finds its slot free again.
    let t = r.claim();
    assert_eq!(t, 5);
    r.open(t).expect("the slot of ticket 1 is finished").commit(7, 7, 0, 7, Src::Ring, 0, 0);
    let n = r.snapshot(&mut out);
    // Window 5, 4, 3, 2: the refused ticket 4 is the gap.
    assert_eq!(out[..n].iter().map(|e| e.seq).collect::<Vec<_>>(), vec![5, 3, 2]);
}

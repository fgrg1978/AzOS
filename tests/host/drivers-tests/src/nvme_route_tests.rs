// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host tests of the NVMe driver's queue plumbing (`nvme_route.rs`): which
//! route carries each MSI-X vector, how many queue pairs each party allows,
//! which queue a command slot prefers, and whether a completion belongs to the
//! queue it was read from.
//!
//! Each test names its canary: the one-line change to `nvme_route.rs` that
//! must turn it red.

use super::nvme_route::*;
use std::cell::RefCell;
use std::rc::Rc;

/// What the fake route of CPU `cpu` says for its vector `local`: distinct for
/// every (cpu, local) pair, so a vector sent to the wrong route cannot pass.
fn addr(cpu: usize) -> u64 {
    0xFEE0_0000 + cpu as u64 * 0x1000
}
fn data(cpu: usize, local: u16) -> u32 {
    100 + cpu as u32 * 10 + local as u32
}
fn token(cpu: usize, local: u16) -> u32 {
    1000 + cpu as u32 * 10 + local as u32
}

/// One CPU's route, as an `MsiRoute` would be, that can be made to refuse.
struct Fake {
    cpu: usize,
    ok: bool,
    asked: Asked,
}

impl CpuVectors for Fake {
    fn prepare(&mut self, n: u16) -> bool {
        self.asked.borrow_mut().push((self.cpu, n));
        self.ok
    }
    fn target(&self, vec: u16) -> (u64, u32) {
        (addr(self.cpu), data(self.cpu, vec))
    }
    fn isr_token(&self, vec: u16) -> u32 {
        token(self.cpu, vec)
    }
}

type Asked = Rc<RefCell<Vec<(usize, u16)>>>;

/// A per-CPU route whose CPUs `fail_from..` cannot make theirs, and the log of
/// what each CPU was asked for.
fn route(fail_from: usize) -> (PerCpuRoute<Fake, impl FnMut(usize) -> Fake>, Asked) {
    let asked: Asked = Rc::default();
    let log = asked.clone();
    (PerCpuRoute::new(move |cpu| Fake { cpu, ok: cpu < fail_from, asked: log.clone() }), asked)
}

/// Vector `vec`'s owner: (CPU, vector in its route).
fn owner(vec: u16) -> (usize, u16) {
    match vec {
        0 => (0, 0),
        1 => (0, 1),
        v => (v as usize - 1, 0),
    }
}

type Locate = PerCpuRoute<Fake, fn(usize) -> Fake>;

#[test]
fn the_admin_vector_and_queue_ones_share_cpu_zeros_route() {
    assert_eq!(Locate::locate(0), (0, 0));
    assert_eq!(Locate::locate(1), (0, 1));
    assert_eq!(Locate::locate(2), (1, 0));
    assert_eq!(Locate::locate(5), (4, 0));
}

/// Every vector the controller is given reaches the CPU of the queue it
/// completes, with that route's own address, data and kernel token. Vector 1
/// is on route 0 and is not vector 0.
///
/// Canary: delete the `1 => (0, 1)` arm of `locate` — vector 1 reads route 0's
/// vector 0 (the admin pair).
#[test]
fn each_vector_reaches_the_cpu_that_owns_its_queue() {
    assert!(MAXQ >= 3, "needs NVME_QUEUES >= 3 (default 4)");
    let (mut r, _) = route(usize::MAX);
    assert_eq!(r.prepare(MAXQ as u16), MAXQ as u16);
    for vec in 0..=MAXQ as u16 {
        let (cpu, local) = owner(vec);
        // I/O queue `q` has vector `q`; vector 0 is the admin queue's.
        assert_eq!(r.target(vec), (addr(cpu), data(cpu, local)), "vector {vec}");
        assert_eq!(r.isr_token(vec), token(cpu, local), "vector {vec}");
    }
    assert_ne!(r.target(0), r.target(1), "the admin vector is not queue 1's");
    assert_ne!(r.isr_token(0), r.isr_token(1));
}

/// CPU 0's route carries two vectors (admin and queue 1), every other CPU's
/// one.
///
/// Canary: ask CPU 0 for 1 — the admin vector has no route.
#[test]
fn cpu_zero_is_asked_for_two_vectors_the_others_for_one() {
    assert!(MAXQ >= 3);
    let (mut r, asked) = route(usize::MAX);
    r.prepare(3);
    assert_eq!(*asked.borrow(), vec![(0, 2), (1, 1), (2, 1)]);
}

/// A CPU that cannot have a route ends the run: the count is the CPUs before
/// it, the ones after it are not asked, and the vectors of the CPU that
/// failed answer "no route" (address 0, token `u32::MAX`), never another
/// CPU's pair.
///
/// Canary: `continue` for `break` in `prepare` — CPU 2 is routed past the
/// hole and the count is 2.
#[test]
fn the_run_ends_at_the_first_cpu_whose_route_cannot_be_made() {
    assert!(MAXQ >= 3);
    let (mut r, asked) = route(1);
    assert_eq!(r.prepare(3), 1);
    assert_eq!(*asked.borrow(), vec![(0, 2), (1, 1)], "CPU 2 is not asked after CPU 1 refused");
    assert_eq!(r.target(1), (addr(0), data(0, 1)), "queue 1 is routed");
    for vec in [2, 3] {
        assert_eq!(r.target(vec), (0, 0), "vector {vec}");
        assert_eq!(r.isr_token(vec), u32::MAX, "vector {vec}");
    }
}

/// CPU 0 refusing leaves nothing routed: the controller is polled.
///
/// Canary: count the refused CPU in `routed`.
#[test]
fn no_route_on_the_boot_cpu_is_no_route() {
    let (mut r, _) = route(0);
    assert_eq!(r.prepare(MAXQ as u16), 0);
    assert_eq!(r.target(0), (0, 0));
    assert_eq!(r.target(1), (0, 0));
    assert_eq!(r.isr_token(0), u32::MAX);
}

/// A vector outside what was prepared is "no route", not a panic and not a
/// pair of another CPU.
///
/// Canary: index `routes` with `[]` instead of `.get` in `target`.
#[test]
fn a_vector_nobody_prepared_answers_no_route() {
    let (mut r, _) = route(usize::MAX);
    assert_eq!(r.prepare(1), 1);
    assert_eq!(r.target(2), (0, 0));
    assert_eq!(r.isr_token(u16::MAX), u32::MAX);
    assert_eq!(r.target(u16::MAX), (0, 0));
}

/// More queues asked for than the driver has are never routed.
///
/// Canary: drop the `.min(MAXQ)` of the loop bound — `routes[MAXQ]` panics.
#[test]
fn no_more_routes_than_queue_pairs() {
    let (mut r, asked) = route(usize::MAX);
    assert_eq!(r.prepare(u16::MAX), MAXQ as u16);
    assert_eq!(asked.borrow().len(), MAXQ);
}

/// The per-CPU route says its vectors land on their own CPUs, which is what
/// lets the slot order demote the queues of CPUs that do not run.
///
/// Canary: return false from `per_cpu`.
#[test]
fn a_per_cpu_route_says_so() {
    let (r, _) = route(usize::MAX);
    assert!(r.per_cpu());
}

// ---- How many queue pairs ----

/// Canary: drop the `.min(cpus)` — a four-queue driver on a one-CPU machine.
#[test]
fn queues_are_capped_by_kconfig_slots_and_cpus_and_never_none() {
    assert_eq!(queues_wanted(4, 4, 8), 4);
    assert_eq!(queues_wanted(8, 4, 8), 4, "slots");
    assert_eq!(queues_wanted(4, 32, 2), 2, "cpus");
    assert_eq!(queues_wanted(4, 32, 1), 1);
    assert_eq!(queues_wanted(4, 32, 0), 1, "a machine reporting no CPUs still has the boot one");
}

/// The table has the admin vector too, so a table of `n` entries carries `n-1`
/// queues.
///
/// Canary: `table_size` for `table_size - 1`.
#[test]
fn the_vector_table_holds_the_admin_vector_too() {
    assert_eq!(vectors_wanted(4, 2), 1);
    assert_eq!(vectors_wanted(4, 4), 3);
    assert_eq!(vectors_wanted(4, 5), 4);
    assert_eq!(vectors_wanted(4, 2048), 4);
}

/// With interrupts the route's count caps the queues (a queue with no vector
/// would only ever be polled); polled, it caps nothing.
///
/// Canary: ignore `irq` (always cap) — a polled controller loses its queues
/// to the route's 0.
#[test]
fn a_short_route_caps_the_queues_only_when_interrupts_are_on() {
    assert_eq!(queues_routed(4, 2, true), 2);
    assert_eq!(queues_routed(4, 4, true), 4);
    assert_eq!(queues_routed(4, 0, false), 4);
}

/// A pair needs a submission and a completion queue from the controller.
///
/// Canary: leave out `.min(ncq)`.
#[test]
fn the_controller_grants_submission_and_completion_queues_separately() {
    assert_eq!(queues_granted(4, 8, 8), 4);
    assert_eq!(queues_granted(4, 2, 8), 2);
    assert_eq!(queues_granted(4, 8, 1), 1);
    assert_eq!(queues_granted(4, 0, 8), 0, "the caller refuses 0");
}

// ---- Which slot ----

/// Canary: `!online(qi)` for `online(qi)`.
#[test]
fn a_queue_is_served_when_its_cpu_runs_or_nothing_depends_on_that() {
    let up = |cpu: usize| cpu < 2;
    assert_eq!(served_queues(4, true, true, up), 0b0011, "queues 2 and 3 have no CPU to take their interrupt");
    assert_eq!(served_queues(4, true, false, up), 0b1111, "every vector lands on the boot CPU");
    assert_eq!(served_queues(4, false, true, up), 0b1111, "polled: no queue is better than another");
    assert_eq!(served_queues(4, true, true, |_| true), 0b1111);
}

/// A CPU's own queue first, other queues with an interrupt next, queues
/// completed only by polling last.
///
/// Canary: swap the `2` and the `0` returns of `slot_rank`.
#[test]
fn slots_of_the_own_queue_come_first_then_served_queues_then_polled_ones() {
    let served = 0b0111;
    // 4 queues: slot t is on queue t mod 4.
    assert_eq!(slot_rank(1, 4, 1, served), 0);
    assert_eq!(slot_rank(5, 4, 1, served), 0);
    assert_eq!(slot_rank(0, 4, 1, served), 1);
    assert_eq!(slot_rank(2, 4, 1, served), 1);
    assert_eq!(slot_rank(3, 4, 1, served), 2);
    assert_eq!(slot_rank(7, 4, 1, served), 2);
    // A CPU whose own queue is the unserved one still prefers a served one.
    assert_eq!(slot_rank(3, 4, 3, served), 2);
    assert_eq!(slot_rank(0, 4, 3, served), 1);
}

/// `slot_take` walks ranks 0, 1, 2: a slot with another rank is never taken,
/// so every slot of every machine shape must have one of those three.
///
/// Canary: return 3 for an unserved queue.
#[test]
fn every_slot_has_a_rank_the_three_passes_visit() {
    for queues in 1..=8usize {
        for served in [0u32, 1, 0b101, 0xff] {
            for pref in 0..queues {
                for t in 0..32 {
                    assert!(slot_rank(t, queues, pref, served) < 3, "queues {queues} served {served:#x} pref {pref} slot {t}");
                }
            }
        }
    }
}

// ---- Whose completion ----

const SLOTS: usize = 8;

/// A completion read from queue `qi` that names the queue's own id and a slot
/// on that queue is that slot's.
///
/// Canary: `queue_of(slot, queues) != qi` for `==` — the good completion is
/// refused.
#[test]
fn a_completion_naming_its_own_queue_and_a_slot_on_it_is_taken() {
    for qi in 0..4 {
        for slot in (qi..SLOTS).step_by(4) {
            assert_eq!(completion_slot(qi, 4, qid_of(qi), slot as u16, SLOTS), Some(slot));
        }
    }
}

/// A completion that says it is another queue's, or names a slot that is on
/// another queue, or one that does not exist, belongs to no command in flight
/// here; `drain` latches the driver dead on it.
///
/// Canary: drop the `sq_id == qid_of(qi)` test (the first assert), the
/// `queue_of` test (the second) or turn `slot < slots` into `slot <= slots`
/// (the sixth).
#[test]
fn a_completion_that_is_not_this_queues_is_refused() {
    // Queue 1 of 4: slots 1 and 5. It says it came from queue 2 (id 3).
    assert_eq!(completion_slot(1, 4, qid_of(2), 1, SLOTS), None, "id of another queue");
    // Right id, slot 2 is on queue 2.
    assert_eq!(completion_slot(1, 4, qid_of(1), 2, SLOTS), None, "slot of another queue");
    assert_eq!(completion_slot(1, 4, 0, 1, SLOTS), None, "the admin queue's id");
    // Slot 9 is on queue 1 (9 mod 4) but there are 8 slots.
    assert_eq!(completion_slot(1, 4, qid_of(1), 9, SLOTS), None, "no such slot");
    assert_eq!(completion_slot(1, 4, qid_of(1), SLOTS as u16 + 1, SLOTS), None);
    // The first slot past the end is on queue 0 (8 mod 4): only the bound refuses it.
    assert_eq!(completion_slot(0, 4, qid_of(0), SLOTS as u16, SLOTS), None, "one past the last slot");
    assert_eq!(completion_slot(1, 4, qid_of(1), u16::MAX, SLOTS), None);
}

/// With one queue every slot is on it, yet the queue id still has to match.
///
/// Canary: skip the `sq_id` test.
#[test]
fn one_queue_still_checks_who_sent_the_completion() {
    assert_eq!(completion_slot(0, 1, qid_of(0), 5, SLOTS), Some(5));
    assert_eq!(completion_slot(0, 1, qid_of(1), 5, SLOTS), None);
}

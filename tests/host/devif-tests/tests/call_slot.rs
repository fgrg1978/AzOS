// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The kernel call task's slot (`azos_devif::call_slot`): one call in flight,
//! who joins it, what an abandoned call leaves behind, and how long an idle
//! task may sleep through a wake that came too early.

use azos_devif::call_slot::{carried_deadline_ns, park_reason, CallSlot, Poll, BUSY};
use azos_idl::{IdlError, MsgDesc};

fn req(word: u64) -> MsgDesc {
    let mut m = MsgDesc::default();
    m.n_words = 1;
    m.words[0] = word;
    m
}

#[test]
fn a_second_call_is_busy_while_one_is_in_flight() {
    let mut s = CallSlot::<0, 2>::new(false);
    s.post(1, 100, None, &req(1)).unwrap();
    assert_eq!(s.post(2, 100, None, &req(2)).err(), Some(BUSY));
    assert_eq!(s.post(2, 100, None, &req(1)).err(), Some(BUSY), "an equal request does not join a slot that does not share");
}

#[test]
fn a_shared_slot_gives_an_equal_request_the_same_answer_and_refuses_another() {
    let mut s = CallSlot::<0, 3>::new(true);
    let a = s.post(1, 100, None, &req(7)).unwrap();
    let b = s.post(2, 100, None, &req(7)).unwrap();
    assert_eq!(s.post(3, 100, None, &req(8)).err(), Some(BUSY));
    assert_eq!(s.post(3, 100, Some(5), &req(7)).err(), Some(BUSY), "another node is another request");
    let t = s.take().unwrap();
    let mut ans = req(7);
    ans.words[1] = 42;
    let woken = s.finish(t.seq, &ans, Ok(()));
    assert!(!woken.orphan);
    assert_eq!(woken.waiters[..2], [(1, 100), (2, 100)]);
    for w in [a.waiter, b.waiter] {
        match s.poll(w, 0) {
            Poll::Answer(m, Ok(())) => assert_eq!(m.words[1], 42),
            _ => panic!("no answer"),
        }
    }
    assert!(s.post(1, 100, None, &req(9)).is_ok(), "the slot is free again");
}

#[test]
fn no_place_to_wait_is_busy() {
    let mut s = CallSlot::<0, 1>::new(true);
    s.post(1, 100, None, &req(1)).unwrap();
    assert_eq!(s.post(2, 100, None, &req(1)).err(), Some(BUSY));
}

#[test]
fn every_park_is_on_the_one_reason_a_wake_names() {
    assert_eq!(park_reason(10), park_reason(20_000));
}

#[test]
fn a_client_that_joins_a_posted_call_wakes_the_task() {
    let mut s = CallSlot::<0, 2>::new(true);
    assert!(s.post(1, 100, None, &req(1)).unwrap().wake);
    assert!(s.post(2, 100, None, &req(1)).unwrap().wake, "the first wake may have been lost");
    s.take().unwrap();
    assert!(!s.post(3, 100, None, &req(1)).is_ok_and(|p| p.wake), "a call under way needs no wake");
}

#[test]
fn a_call_nobody_took_is_withdrawn_when_its_client_gives_up() {
    let mut s = CallSlot::<0, 1>::new(false);
    let p = s.post(1, 50, None, &req(1)).unwrap();
    assert!(matches!(s.poll(p.waiter, 49), Poll::Pending));
    assert!(matches!(s.poll(p.waiter, 50), Poll::Expired));
    assert!(s.take().is_none());
    assert!(s.post(2, 100, None, &req(2)).is_ok());
}

#[test]
fn a_call_under_way_keeps_the_slot_busy_and_its_answer_has_no_taker() {
    let mut s = CallSlot::<0, 1>::new(false);
    let p = s.post(1, 50, None, &req(1)).unwrap();
    let t = s.take().unwrap();
    assert!(matches!(s.poll(p.waiter, 60), Poll::Expired));
    assert_eq!(s.post(2, 100, None, &req(2)).err(), Some(BUSY));
    assert!(s.finish(t.seq, &req(1), Ok(())).orphan);
    assert!(s.post(2, 100, None, &req(2)).is_ok());
}

#[test]
fn an_answer_the_client_never_read_queues_its_capabilities_to_close_when_it_leaves() {
    let mut s = CallSlot::<2, 1>::new(false);
    let p = s.post(1, 50, None, &req(1)).unwrap();
    let t = s.take().unwrap();
    let mut ans = req(1);
    ans.n_caps = 2;
    ans.caps[0].handle = 21;
    ans.caps[1].handle = 22;
    s.finish(t.seq, &ans, Ok(()));
    assert!(s.leave(p.waiter));
    let (c, n) = s.take_closes();
    assert_eq!(&c[..n], &[21, 22]);
}

#[test]
fn a_full_close_queue_is_said_when_an_answer_leaves_capabilities_behind() {
    let mut s = CallSlot::<1, 1>::new(false);
    let p = s.post(1, 50, None, &req(1)).unwrap();
    let t = s.take().unwrap();
    let mut ans = req(1);
    ans.n_caps = 2;
    s.finish(t.seq, &ans, Ok(()));
    assert!(!s.leave(p.waiter));
}

#[test]
fn the_deadline_expiry_is_not_an_answer_to_a_later_call() {
    let mut s = CallSlot::<0, 1>::new(false);
    let p = s.post(1, 50, None, &req(1)).unwrap();
    let t = s.take().unwrap();
    assert!(s.leave(p.waiter));
    s.finish(t.seq, &req(1), Err(IdlError::DeadlineExpired));
    let q = s.post(2, 100, None, &req(2)).unwrap();
    assert!(matches!(s.poll(q.waiter, 0), Poll::Pending));
}

#[test]
fn the_close_queue_holds_what_it_is_sized_for_and_is_taken_once() {
    let mut s = CallSlot::<2, 1>::new(false);
    assert!(s.queue_close(7) && s.queue_close(9));
    assert!(!s.queue_close(11));
    let (c, n) = s.take_closes();
    assert_eq!(&c[..n], &[7, 9]);
    assert_eq!(s.take_closes().1, 0);
    assert!(s.queue_close(11));
}

/// **A call through the call task reaches the server with a deadline:** the
/// call edge lends the client's priority to the server only for a call that
/// carries one, and the task's own call would otherwise carry none.
///
/// **Canary.** `call-deadline-canary`: the call carries no deadline.
#[test]
fn a_call_through_the_task_carries_the_clients_deadline_to_the_server() {
    const FREQ: u64 = 10_000_000;
    let mut s = CallSlot::<0, 2>::new(false);
    let until = 5 * FREQ;
    s.post(1, until, None, &req(1)).unwrap();
    let t = s.take().unwrap();
    assert_eq!(t.until, until);
    assert_eq!(carried_deadline_ns(t.msg.deadline, t.until, FREQ), 5_000_000_000);
    assert_eq!(carried_deadline_ns(7, t.until, FREQ), 7, "a deadline the client set is kept");
    assert_ne!(carried_deadline_ns(0, 0, FREQ), 0, "never 0: that means none");
}

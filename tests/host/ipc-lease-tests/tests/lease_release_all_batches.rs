// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `lease_release_all` wakes a dying lessor's registered acceptors in batches.
//!
//! One buffer entry per registry slot was `MAX_TASKS` × 4 bytes on the exiting
//! task's kernel stack: 16 KiB on the fleet profile, the whole stack, and the
//! fleet image faulted in its guard page when the first tasks exited. The
//! buffer is now a batch of 32, and a pass that fills it goes round again.
//! These tests register one batch, a batch and a remainder, and the whole
//! registry, and require every acceptor to be woken exactly once, naming the
//! lessor, with its registration marked for `LessorGone`.
//!
//! **Canaries.** Always stop after the first pass: `a_batch_and_a_remainder`
//! and `the_whole_registry` red. Never mark a full batch: same two red.
//!
//! **A binary of its own**, so the registry it fills is not shared with the
//! library suite's tests.

use azos_ipc_lease_tests::lease::{
    lease_accept_begin, lease_accept_cancel, lease_accept_poll, lease_release_all,
    LeaseAcceptBegin, LeaseAcceptPoll,
};
use std::sync::{Mutex, MutexGuard};

static SERIAL: Mutex<()> = Mutex::new(());

const LESSOR: u32 = 900;
const REGISTRY: usize = azos_sched::task::MAX_TASKS;

fn lessee(i: usize) -> u32 {
    1000 + i as u32
}

/// Take the suite lock, drop every registration these tests make and reset
/// the scheduler shim's wake record.
fn serial() -> MutexGuard<'static, ()> {
    let g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    for i in 0..REGISTRY {
        lease_accept_cancel(lessee(i));
    }
    azos_sched::shim_reset();
    g
}

fn release_with_acceptors(n: usize) {
    for i in 0..n {
        assert!(
            matches!(lease_accept_begin(lessee(i), LESSOR), LeaseAcceptBegin::Registered),
            "acceptor {i} could not register"
        );
    }
    lease_release_all(LESSOR);

    let wakes = azos_sched::shim_lease_accept_wakes();
    assert_eq!(wakes.len(), n, "{n} acceptors registered, {} woken", wakes.len());
    for i in 0..n {
        let hits = wakes.iter().filter(|w| **w == (lessee(i), LESSOR)).count();
        assert_eq!(hits, 1, "acceptor {i} woken {hits} times");
        assert!(
            matches!(lease_accept_poll(lessee(i), LESSOR), LeaseAcceptPoll::LessorGone),
            "acceptor {i} was not told its lessor is gone"
        );
    }
}

#[test]
fn exactly_one_batch() {
    let _g = serial();
    release_with_acceptors(32);
}

#[test]
fn a_batch_and_a_remainder() {
    let _g = serial();
    release_with_acceptors(40);
}

#[test]
fn the_whole_registry() {
    let _g = serial();
    assert!(REGISTRY > 32, "the registry must hold more than one batch for this test to mean anything");
    release_with_acceptors(REGISTRY);
}

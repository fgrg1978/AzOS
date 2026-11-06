// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// The cold-restart supervisor's decisions
// (`crates/core/sched/src/supervisor.rs`), the real file.

use super::harness::serial;
use azos_arch_api::PagePerms;
use azos_sched::supervisor::{
    ExitVerdict, SupFall, SupOrigin, SupPolicy, SupRestart, SupState, SupTable,
    DRIVER_MAX_RESTARTS, MAX_SUPERVISED,
};

const IMAGE: &[u8] = b"/fat/GPIODRV.ELF";
const COOLDOWN: u64 = 1_000;
/// A failed death: killed by the kernel's stop request (128 + SIGKILL).
const FAILED: i32 = azos_abi::exit_status::KILLED_KILL;
/// The budget tests' policy: a burst of 3 in a window no test outlives, so
/// only the burst decides.
const POLICY: SupPolicy = SupPolicy { burst: DRIVER_MAX_RESTARTS, interval: u64::MAX, cooldown: COOLDOWN };

// ── The supervisor's table ─────────────────────────────────────────────────

/// A supervised image: spawned as `tid`.
fn serving(t: &mut SupTable, tid: u32) -> usize {
    t.note_started(tid, IMAGE).expect("table full")
}

/// Deaths 1..=3 each restart, the fourth gives up — the budget is
/// `DRIVER_MAX_RESTARTS` (3) restarts, exactly. Each successor takes up the
/// same entry by TID and reports how long after the death it registered.
///
/// **Canary**: `restarts >= DRIVER_MAX_RESTARTS` → `>` in `on_exit` grants a
/// fourth restart, and the `GiveUp` assertion below fails at death 4.
#[test]
fn deaths_one_to_three_restart_and_the_fourth_gives_up() {
    assert_eq!(DRIVER_MAX_RESTARTS, 3, "the row and this test pin a budget of 3");
    let mut t = SupTable::new();
    let mut tid = 100;
    let mut now = 10_000;
    let slot = serving(&mut t, tid);
    for attempt in 1..=DRIVER_MAX_RESTARTS {
        now += 5_000;
        match t.on_exit(tid, now, FAILED, POLICY) {
            ExitVerdict::Restart { slot: s, attempt: a, not_before } => {
                assert_eq!((s, a), (slot, attempt));
                assert!(not_before >= now);
                now = not_before;
            }
            v => panic!("death {attempt} gave {v:?}, not a restart"),
        }
        assert_eq!(t.entry(slot).unwrap().state, SupState::Restarting);
        assert_eq!(t.next_due(now), (None, None), "due before the exit hook held anything");
        assert!(t.held(slot));
        assert_eq!(t.next_due(now), (Some(slot), None), "the successor is due");
        let heir = tid + 1;
        assert!(t.respawned(slot, heir, now));
        assert_eq!(t.next_due(now), (None, None), "created once, not twice");
        let e = t.entry(slot).unwrap();
        assert_eq!((e.state, e.tid, e.window_n), (SupState::Serving, heir, attempt), "successor {attempt}");
        tid = heir;
    }
    now += 5_000;
    assert_eq!(
        t.on_exit(tid, now, FAILED, POLICY),
        ExitVerdict::GiveUp { slot, restarts: DRIVER_MAX_RESTARTS },
        "a fourth restart was granted",
    );
    let e = t.entry(slot).unwrap();
    assert_eq!((e.state, e.tid, e.dead_tid), (SupState::Down, 0, tid));
    // Down is final: nothing is due, and the give-up waits to be recorded once.
    assert_eq!(t.next_due(now + 1_000_000), (None, None));
    assert_eq!(t.next_unrecorded(), Some(slot));
    assert_eq!(t.fall(slot), Some(SupFall::GaveUp));
    t.mark_recorded(slot);
    assert_eq!(t.next_unrecorded(), None);
    assert_eq!(t.on_exit(tid, now, FAILED, POLICY), ExitVerdict::NotSupervised);
}

/// A successor that dies at once — it cannot reach what it serves, its
/// device does not answer — spends budget like any crash. So an image that
/// cannot run ends `Down` after three attempts instead of looping.
///
/// **Canary**: drop the `kept >= policy.burst_limit()` test in `failed`: the
/// death after the burst restarts again.
#[test]
fn a_successor_that_dies_at_once_spends_budget() {
    let mut t = SupTable::new();
    let slot = serving(&mut t, 200);
    let mut dead = 200;
    let mut now = 1;
    for attempt in 1..=DRIVER_MAX_RESTARTS {
        match t.on_exit(dead, now, FAILED, POLICY) {
            ExitVerdict::Restart { attempt: a, not_before, .. } => {
                assert_eq!(a, attempt);
                now = not_before;
            }
            v => panic!("attempt {attempt}: {v:?}"),
        }
        assert!(t.held(slot));
        let heir = 300 + attempt as u32;
        assert!(t.respawned(slot, heir, now));
        dead = heir; // dies again
        now += 1;
    }
    assert!(matches!(t.on_exit(dead, now, FAILED, POLICY), ExitVerdict::GiveUp { .. }));
}

/// The first restart is immediate; the second and third wait until the
/// cooldown has passed since the previous restart, and `next_due` reports
/// when that is.
#[test]
fn the_first_restart_is_immediate_and_later_ones_keep_the_cooldown() {
    let mut t = SupTable::new();
    let slot = serving(&mut t, 400);
    let ExitVerdict::Restart { not_before, .. } = t.on_exit(400, 50, FAILED, POLICY) else {
        panic!("not restarted")
    };
    assert_eq!(not_before, 50, "the first restart must not wait");
    assert!(t.respawned(slot, 401, 60));
    let ExitVerdict::Restart { not_before, .. } = t.on_exit(401, 70, FAILED, POLICY) else {
        panic!("not restarted")
    };
    assert_eq!(not_before, 60 + COOLDOWN, "the cooldown runs from the previous restart");
    assert!(t.held(slot));
    assert_eq!(t.next_due(70), (None, Some(60 + COOLDOWN)));
    assert_eq!(t.next_due(60 + COOLDOWN), (Some(slot), None));
    // A death long after the previous restart is not delayed at all.
    assert!(t.respawned(slot, 402, 60 + COOLDOWN));
    let ExitVerdict::Restart { not_before, .. } = t.on_exit(402, 90_000, FAILED, POLICY) else {
        panic!("not restarted")
    };
    assert_eq!(not_before, 90_000);
}

/// The successor is not due until the dead task's exit hook has held what it
/// takes over. The hook runs `on_exit` first and orphans the driver-server
/// slot last; a supervisor already awake (restarting another image, or back
/// from a cooldown) that created the successor in between would find nothing
/// to adopt, and the slot would stay orphaned under the wrong TID.
///
/// **Canary**: drop `&& e.held` from `next_due` and the successor is due
/// straight after `on_exit`.
#[test]
fn no_successor_is_due_until_the_exit_hook_has_held_its_resources() {
    let mut t = SupTable::new();
    let slot = serving(&mut t, 450);
    assert!(matches!(t.on_exit(450, 10, FAILED, POLICY), ExitVerdict::Restart { .. }));
    assert_eq!(t.next_due(u64::MAX), (None, None), "due while the hook is still holding");
    assert!(t.held(slot));
    assert!(!t.held(slot), "held twice");
    assert_eq!(t.next_due(10), (Some(slot), None));
    assert!(t.respawned(slot, 451, 10));
    // The successor's own death starts over: not due until held again.
    assert!(matches!(t.on_exit(451, 20, FAILED, POLICY), ExitVerdict::Restart { .. }));
    assert_eq!(t.next_due(u64::MAX), (None, None));
}

/// The table is bounded; past it a program runs unsupervised rather than
/// displacing one that is supervised. A path longer than the table keeps is
/// refused rather than cut. TID 0 is "no task": never noted, never matched.
#[test]
fn the_table_is_bounded_and_refuses_what_does_not_fit() {
    let mut t = SupTable::new();
    for i in 0..MAX_SUPERVISED as u32 {
        assert!(t.note_started(600 + i, IMAGE).is_some());
    }
    assert_eq!(t.note_started(700, IMAGE), None);
    let mut t = SupTable::new();
    assert_eq!(t.note_started(1, &[b'x'; 65]), None);
    assert_eq!(t.note_started(1, b""), None);
    assert_eq!(t.note_started(0, IMAGE), None);
    assert_eq!(t.on_exit(0, 4, FAILED, POLICY), ExitVerdict::NotSupervised);
    assert_eq!(t.on_exit(501, 3, FAILED, POLICY), ExitVerdict::NotSupervised);
}

/// No successor could be created (task pool full): the entry goes `Down`
/// and waits to be recorded, as a give-up does.
#[test]
fn a_successor_that_cannot_be_created_puts_the_entry_down() {
    let mut t = SupTable::new();
    let slot = serving(&mut t, 800);
    assert!(matches!(t.on_exit(800, 1, FAILED, POLICY), ExitVerdict::Restart { .. }));
    assert!(t.held(slot));
    assert!(t.respawn_failed(slot));
    assert_eq!(t.entry(slot).unwrap().state, SupState::Down);
    assert_eq!(t.next_unrecorded(), Some(slot));
    assert!(!t.respawn_failed(slot), "only a pending restart can fail");
}

// ── Owner decisions 2026-09-28: a window, and only on failure ─────────────

/// Kill, restart: one full cycle of `slot`'s image, `dead` -> `heir`,
/// the death at `now`. Returns the restart's `attempt`.
fn cycle(t: &mut SupTable, slot: usize, dead: u32, heir: u32, now: u64, p: SupPolicy) -> u8 {
    let ExitVerdict::Restart { slot: s, attempt, not_before } = t.on_exit(dead, now, FAILED, p)
    else {
        panic!("death of {dead} at {now} was not restarted")
    };
    assert_eq!(s, slot);
    assert!(t.held(slot));
    assert!(t.respawned(slot, heir, not_before));
    attempt
}

/// systemd's `StartLimitIntervalSec`: a restart older than the interval no
/// longer counts. Burst 3, interval 100: restarts at 0, 10, 20 fill the
/// window, so a death at 99 gives up; the same three restarts with the death
/// at 100 instead (the first has aged out) restart, as attempt 3 of the
/// window, and the total keeps counting.
///
/// **Canary**: drop the `filter(...)` age test in `on_exit` (never forget):
/// the death at 100 gives up and the second half panics.
#[test]
fn a_restart_older_than_the_interval_no_longer_counts() {
    let p = SupPolicy { burst: 3, interval: 100, cooldown: 0 };
    for (death, expect_restart) in [(99u64, false), (100, true)] {
        let mut t = SupTable::new();
        let slot = serving(&mut t, 1000);
        assert_eq!(cycle(&mut t, slot, 1000, 1001, 0, p), 1);
        assert_eq!(cycle(&mut t, slot, 1001, 1002, 10, p), 2);
        assert_eq!(cycle(&mut t, slot, 1002, 1003, 20, p), 3);
        let v = t.on_exit(1003, death, FAILED, p);
        if expect_restart {
            assert_eq!(v, ExitVerdict::Restart { slot, attempt: 3, not_before: death });
            let e = t.entry(slot).unwrap();
            assert_eq!((e.window_n, e.restarts), (3, 4), "window 10, 20, 100; four in total");
            assert_eq!(&e.window[..3], &[10, 20, 100]);
        } else {
            assert_eq!(v, ExitVerdict::GiveUp { slot, restarts: 3 });
        }
    }
}

/// A driver that fails rarely is restarted every time: with each failure more
/// than an interval after the previous restart, the window never holds more
/// than one, far past the burst.
///
/// **Canary**: the window never forgets: the fourth failure gives up.
#[test]
fn a_driver_that_fails_rarely_is_always_restarted() {
    let p = SupPolicy { burst: 3, interval: 1_000, cooldown: 50 };
    let mut t = SupTable::new();
    let slot = serving(&mut t, 1100);
    let mut tid = 1100;
    for k in 1..=10u64 {
        let attempt = cycle(&mut t, slot, tid, tid + 1, k * 5_000, p);
        assert_eq!(attempt, 1, "failure {k} counted {attempt} restarts in its window");
        tid += 1;
    }
    assert_eq!(t.entry(slot).unwrap().restarts, 10);
}

/// The first restart of a fresh window is immediate even after earlier
/// restarts: the cooldown spaces restarts inside one window only.
#[test]
fn the_first_restart_of_a_fresh_window_is_immediate() {
    let p = SupPolicy { burst: 3, interval: 100, cooldown: 1_000 };
    let mut t = SupTable::new();
    let slot = serving(&mut t, 1200);
    assert_eq!(cycle(&mut t, slot, 1200, 1201, 0, p), 1);
    let ExitVerdict::Restart { not_before, attempt, .. } = t.on_exit(1201, 500, FAILED, p) else {
        panic!("not restarted")
    };
    assert_eq!((attempt, not_before), (1, 500));
}

/// systemd's `Restart=on-failure`: exit code 0 is a driver that finished on
/// purpose. Not restarted, nothing held for a successor (the hook releases
/// everything), nothing to record, and final: a later death of the same TID
/// is no longer supervised. Every non-zero code — the kernel's kills are
/// `128 + signal`, a program's own failure any other value — restarts.
///
/// **Canary**: drop the `code == 0` arm in `on_exit`: the clean exit is a
/// `Restart` and the first assertion fails.
#[test]
fn a_clean_exit_is_not_restarted_and_a_failure_is() {
    let mut t = SupTable::new();
    let slot = serving(&mut t, 1300);
    assert_eq!(t.on_exit(1300, 10, 0, POLICY), ExitVerdict::Exited { slot, restarts: 0 });
    let e = t.entry(slot).unwrap();
    assert_eq!((e.state, e.tid, e.dead_tid), (SupState::Exited, 0, 1300));
    assert!(!t.held(slot), "a clean exit held resources for a successor");
    assert_eq!(t.next_due(1_000_000), (None, None), "a clean exit made a restart due");
    assert_eq!(t.next_unrecorded(), None, "a clean exit waits to be recorded as a give-up");
    assert_eq!(t.on_exit(1300, 11, FAILED, POLICY), ExitVerdict::NotSupervised);

    for code in [1, -1, 255, azos_abi::exit_status::KILLED_SEGV, 159] {
        let mut t = SupTable::new();
        let slot = serving(&mut t, 1400);
        assert!(
            matches!(t.on_exit(1400, 10, code, POLICY), ExitVerdict::Restart { slot: s, .. } if s == slot),
            "exit {code} was not treated as a failure",
        );
    }

    // After restarts, a clean exit reports the total and is still final.
    let mut t = SupTable::new();
    let slot = serving(&mut t, 1500);
    assert_eq!(cycle(&mut t, slot, 1500, 1501, 0, POLICY), 1);
    assert_eq!(t.on_exit(1501, 5_000, 0, POLICY), ExitVerdict::Exited { slot, restarts: 1 });
}

/// The burst is clamped to what the entry can hold (1..=16), so a policy of 0
/// cannot give up before the first restart and one above 16 cannot overrun.
#[test]
fn the_burst_is_clamped() {
    let mut t = SupTable::new();
    let slot = serving(&mut t, 1600);
    let p0 = SupPolicy { burst: 0, interval: u64::MAX, cooldown: 0 };
    assert_eq!(cycle(&mut t, slot, 1600, 1601, 0, p0), 1);
    assert!(matches!(t.on_exit(1601, 1, FAILED, p0), ExitVerdict::GiveUp { .. }));

    let mut t = SupTable::new();
    let slot = serving(&mut t, 1700);
    let pbig = SupPolicy { burst: 200, interval: u64::MAX, cooldown: 0 };
    let mut tid = 1700;
    for k in 1..=16u8 {
        assert_eq!(cycle(&mut t, slot, tid, tid + 1, k as u64, pbig), k);
        tid += 1;
    }
    assert!(matches!(t.on_exit(tid, 100, FAILED, pbig), ExitVerdict::GiveUp { restarts: 16, .. }));
}

// ── Wave 11: images the kernel spawns because the system declares them ──────

const ML_IMAGE: &[u8] = b"/fat/MLSRV.ELF";

/// A `Spawned` image (a topology `start = true` row, the ML service) is
/// supervised from its start: its entry is `Serving`, and a failed death is
/// restarted.
///
/// **Canary**: drop `SupState::Serving` from `on_exit`'s death arm: the
/// spawned image's death is `NotSupervised`.
#[test]
fn a_spawned_image_is_supervised_from_its_start() {
    let mut t = SupTable::new();
    let slot = t.note_started(2000, ML_IMAGE).expect("table full");
    let e = t.entry(slot).unwrap();
    assert_eq!((e.state, e.origin, e.tid), (SupState::Serving, SupOrigin::Spawned, 2000));
    assert!(matches!(t.on_exit(2000, 10, FAILED, POLICY),
                     ExitVerdict::Restart { attempt: 1, not_before: 10, .. }));
}

/// A successor is the entry's task, `Serving` from its creation, found by
/// the image path.
///
/// **Canary**: let `respawned` leave the entry `Restarting`: the state
/// assertion fails.
#[test]
fn a_spawned_images_successor_is_its_entrys_task() {
    let mut t = SupTable::new();
    let slot = t.note_started(2200, ML_IMAGE).unwrap();
    assert_eq!(t.find_image(ML_IMAGE).map(|(s, _)| s), Some(slot));
    assert!(matches!(t.on_exit(2200, 100, FAILED, POLICY), ExitVerdict::Restart { .. }));
    assert!(t.held(slot));
    assert!(t.respawned(slot, 2201, 100));
    assert!(!t.respawned(slot, 2202, 101), "created twice");
    assert_eq!(t.find_image(ML_IMAGE).unwrap().1.tid, 2201);
    assert_eq!(t.entry(slot).unwrap().state, SupState::Serving);
}

/// A crash loop: a spawned image that dies at once (its capability is
/// missing, its device does not answer) is restarted
/// `DRIVER_MAX_RESTARTS` times and then given up on, `Down` and waiting to be
/// recorded. Before wave 11 that image died once, unsupervised and unrecorded.
///
/// **Canary**: drop `SupState::Serving` from `on_exit`'s death arm: the
/// first death is `NotSupervised` and nothing is ever recorded.
#[test]
fn a_spawned_crash_loop_gives_up_after_the_burst_and_is_recorded() {
    let mut t = SupTable::new();
    let slot = t.note_started(2300, b"/fat/INADRV.ELF").unwrap();
    let mut dead = 2300;
    let mut now = 0;
    for attempt in 1..=DRIVER_MAX_RESTARTS {
        let ExitVerdict::Restart { attempt: a, not_before, .. } = t.on_exit(dead, now, FAILED, POLICY)
        else {
            panic!("death {attempt} not restarted")
        };
        assert_eq!(a, attempt);
        assert!(t.held(slot));
        assert!(t.respawned(slot, dead + 1, not_before));
        dead += 1; // dies again at once
        now = not_before + 1;
    }
    assert_eq!(t.on_exit(dead, now, FAILED, POLICY),
               ExitVerdict::GiveUp { slot, restarts: DRIVER_MAX_RESTARTS });
    assert_eq!(t.entry(slot).unwrap().state, SupState::Down);
    assert_eq!(t.next_unrecorded(), Some(slot));
    t.mark_recorded(slot);
    assert_eq!(t.next_unrecorded(), None);
    // Down is final: nothing it does afterwards is supervised.
    assert_eq!(t.note_started(dead + 1, b"/fat/INADRV.ELF").map(|s| s == slot), Some(false));
}

/// A spawn of a successor refused before any task existed (image gone, digest
/// mismatch, gate absent) is a failure like a death: it spends budget, the
/// next attempt keeps the cooldown, and the attempt past the burst gives up.
/// Nothing died, so the orphans stay held for the next attempt: `held` and
/// `dead_tid` are kept.
///
/// **Canary**: let `respawn_refused` clear `held` (as a death does): the
/// retry is never due again and the `next_due` assertion fails.
#[test]
fn a_refused_respawn_spends_budget_and_keeps_what_is_held() {
    let mut t = SupTable::new();
    let slot = t.note_started(2400, b"/fat/BUZZDRV.ELF").unwrap();
    assert!(matches!(t.on_exit(2400, 10, FAILED, POLICY),
                     ExitVerdict::Restart { attempt: 1, not_before: 10, .. }));
    assert!(t.held(slot));
    // Attempts 1, 2 and 3 refused: the 2nd and 3rd are retries.
    let mut now = 10;
    for k in 1..=DRIVER_MAX_RESTARTS {
        assert_eq!(t.next_due(now), (Some(slot), None), "attempt {k} not due");
        let v = t.respawn_refused(slot, now, POLICY);
        let e = t.entry(slot).unwrap();
        assert!(e.held && e.dead_tid == 2400 && e.tid == 0, "attempt {k}: {e:?}");
        if k < DRIVER_MAX_RESTARTS {
            let ExitVerdict::Restart { attempt, not_before, .. } = v else {
                panic!("attempt {k}: {v:?}")
            };
            assert_eq!((attempt, not_before), (k + 1, now + COOLDOWN));
            assert_eq!(t.next_due(now), (None, Some(now + COOLDOWN)));
            now += COOLDOWN;
        } else {
            assert_eq!(v, ExitVerdict::GiveUp { slot, restarts: DRIVER_MAX_RESTARTS });
        }
    }
    assert_eq!(t.entry(slot).unwrap().state, SupState::Down);
    assert_eq!(t.next_unrecorded(), Some(slot));
    assert_eq!(t.respawn_refused(slot, now, POLICY), ExitVerdict::NotSupervised);
    // Only a slot waiting for a successor can be refused one.
    let s2 = t.note_started(2500, ML_IMAGE).unwrap();
    assert_eq!(t.respawn_refused(s2, now, POLICY), ExitVerdict::NotSupervised);
}

/// `Restart=on-failure` for a spawned image too: a one-shot that exits 0 is
/// finished, not restarted, and nothing is recorded.
#[test]
fn a_spawned_one_shot_that_exits_zero_is_not_restarted() {
    let mut t = SupTable::new();
    let slot = t.note_started(2600, b"/fat/ONESHOT.ELF").unwrap();
    assert_eq!(t.on_exit(2600, 1, 0, POLICY), ExitVerdict::Exited { slot, restarts: 0 });
    assert_eq!(t.entry(slot).unwrap().state, SupState::Exited);
    assert_eq!(t.next_unrecorded(), None);
    assert_eq!(t.next_due(u64::MAX), (None, None));
}

/// Wave 11 (DRVPLACE): `restart = always` (the row key): a clean exit is
/// restarted too, and counts against the same window as a failure, so an
/// image that exits 0 in a loop still ends `Down` after the burst.
///
/// **Canary**: drop the `e.restart == SupRestart::OnFailure` half of the
/// clean-exit test in `on_exit`: the first exit 0 comes back `Exited`.
#[test]
fn restart_always_restarts_a_clean_exit_within_the_window() {
    let mut t = SupTable::new();
    let slot = t.note_started(3000, b"/fat/BUZZDRV.ELF").unwrap();
    assert!(t.set_restart(slot, SupRestart::Always));
    let mut dead = 3000;
    for attempt in 1..=DRIVER_MAX_RESTARTS {
        match t.on_exit(dead, attempt as u64 * 10, 0, POLICY) {
            ExitVerdict::Restart { slot: s, attempt: a, .. } => {
                assert_eq!((s, a), (slot, attempt));
            }
            v => panic!("exit 0 #{attempt} under always: {v:?}"),
        }
        assert!(t.held(slot));
        dead += 1;
        assert!(t.respawned(slot, dead, attempt as u64 * 10 + 5));
        assert_eq!(t.entry(slot).unwrap().restart, SupRestart::Always, "the policy follows the heir");
    }
    assert!(matches!(t.on_exit(dead, 100, 0, POLICY), ExitVerdict::GiveUp { .. }),
            "an exit-0 loop must still be bounded by the burst");
    assert_eq!(t.entry(slot).unwrap().state, SupState::Down);
}

/// `restart = no`: neither a failure nor a clean exit is restarted; the end
/// is final. It waits to be recorded on the flight recorder once, as a
/// give-up does, but as its own fall (`SupFall::NoRestart`, written by the
/// supervisor task as `SUP_ACTION_NO_RESTART`). The default stays
/// `on-failure`, whose clean exit has nothing to record.
///
/// **Canary**: drop the `SupRestart::No` arm of `on_exit`: the kill comes
/// back `Restart`. Mark the `restart = no` end recorded in `on_exit` (the old
/// "a policy, not a give-up" line): red on "the restart = no end was never
/// handed to the recorder".
#[test]
fn restart_no_never_restarts_and_on_failure_is_the_default() {
    let mut t = SupTable::new();
    let a = t.note_started(3100, b"/fat/INADRV.ELF").unwrap();
    assert!(t.set_restart(a, SupRestart::No));
    assert_eq!(t.on_exit(3100, 1, FAILED, POLICY),
               ExitVerdict::NoRestart { slot: a, restarts: 0, code: FAILED });
    assert_eq!(t.entry(a).unwrap().state, SupState::Exited);
    assert_eq!(t.next_unrecorded(), Some(a), "the restart = no end was never handed to the recorder");
    assert_eq!(t.fall(a), Some(SupFall::NoRestart), "recorded as a give-up, not as its own end");
    t.mark_recorded(a);
    assert_eq!(t.next_unrecorded(), None, "recorded twice");
    assert_eq!(t.next_due(u64::MAX), (None, None));

    let b = t.note_started(3200, b"/fat/ONESHOT.ELF").unwrap();
    assert!(t.set_restart(b, SupRestart::No));
    assert_eq!(t.on_exit(3200, 1, 0, POLICY), ExitVerdict::NoRestart { slot: b, restarts: 0, code: 0 });
    assert_eq!(t.next_unrecorded(), Some(b), "a clean end under restart = no is recorded too");
    assert_eq!(t.fall(b), Some(SupFall::NoRestart));
    t.mark_recorded(b);

    let c = t.note_started(3300, b"/fat/OTHER.ELF").unwrap();
    assert_eq!(t.entry(c).unwrap().restart, SupRestart::OnFailure, "the default");
    assert!(matches!(t.on_exit(3300, 1, FAILED, POLICY), ExitVerdict::Restart { .. }));
    assert_eq!(t.fall(c), None, "a pending restart is no fall");
    let d = t.note_started(3400, b"/fat/DONE.ELF").unwrap();
    assert!(matches!(t.on_exit(3400, 1, 0, POLICY), ExitVerdict::Exited { .. }));
    assert_eq!(t.entry(d).unwrap().state, SupState::Exited);
    assert_eq!(t.fall(d), None, "an on-failure clean exit is no fall");
    assert_eq!(t.next_unrecorded(), None, "an on-failure clean exit has nothing to record");

    // A free slot has no policy to set.
    assert!(!t.set_restart(MAX_SUPERVISED - 1, SupRestart::Always));
}

/// Spawned entries and kernel hosts share the one bounded table, and TID 0 or
/// a path that does not fit is never noted.
#[test]
fn spawned_entries_share_the_bounded_table() {
    let mut t = SupTable::new();
    assert_eq!(t.note_started(0, ML_IMAGE), None);
    assert_eq!(t.note_started(1, &[b'x'; 65]), None);
    assert_eq!(t.note_started(1, b""), None);
    assert!(t.note_kernel_host(2700, b"buzzer").is_some());
    for i in 1..MAX_SUPERVISED as u32 {
        assert!(t.note_started(2700 + i, ML_IMAGE).is_some());
    }
    assert_eq!(t.note_started(2800, ML_IMAGE), None);
    // Noting the same task twice keeps its one entry.
    assert_eq!(t.note_started(2701, ML_IMAGE), t.note_started(2701, ML_IMAGE));
}

/// Wave 13: the host task of a driver placed in the kernel is supervised from
/// the start (`KernelHost`); a contained panic (exit 134, the panic policy's
/// `CONTAINED_EXIT_STATUS`) restarts it on the same entry, within the burst,
/// and the burst still gives up.
///
/// **Canary**: drop `SupState::Serving` from `on_exit`'s death arm: the
/// first contained death is `NotSupervised` and nothing restarts.
#[test]
fn a_kernel_host_is_supervised_and_its_contained_panic_restarts_it() {
    const CONTAINED: i32 = 128 + 6;
    let mut t = SupTable::new();
    let slot = t.note_kernel_host(3000, b"buzzer").expect("table full");
    let e = t.entry(slot).unwrap();
    assert_eq!((e.state, e.origin, e.tid), (SupState::Serving, SupOrigin::KernelHost, 3000));
    assert_eq!(t.find_image(b"buzzer").map(|(s, _)| s), Some(slot));
    let mut dead = 3000;
    for n in 1..=DRIVER_MAX_RESTARTS {
        let now = n as u64 * 10 * COOLDOWN;
        assert!(matches!(t.on_exit(dead, now, CONTAINED, POLICY),
                         ExitVerdict::Restart { attempt, .. } if attempt == n),
                "contained death {} restarts", n);
        assert!(t.held(slot));
        assert!(t.respawned(slot, dead + 1, now));
        assert_eq!(t.entry(slot).unwrap().origin, SupOrigin::KernelHost, "the heir keeps the origin");
        dead += 1;
    }
    assert!(matches!(t.on_exit(dead, 1_000 * COOLDOWN, CONTAINED, POLICY), ExitVerdict::GiveUp { .. }));
}

/// A task a placement move ends on purpose is no longer supervised: its entry
/// is freed, so its death restarts nothing and is nobody's failure, and the
/// slot is free for the driver's next host.
///
/// **Canary**: `retire` frees nothing (answers `true` and leaves the entry):
/// the death after it is a `Restart`, and the entry assertion fails.
#[test]
fn a_retired_task_is_not_restarted_and_frees_its_slot() {
    const CONTAINED: i32 = 128 + 6;
    let mut t = SupTable::new();
    let slot = t.note_kernel_host(3100, b"buzzer").expect("table full");
    assert!(!t.retire(0), "tid 0 is no task");
    assert!(!t.retire(9999), "a task nobody supervises");
    assert!(t.retire(3100));
    assert!(t.entry(slot).is_none(), "the slot is free");
    assert!(t.find_image(b"buzzer").is_none());
    assert!(matches!(t.on_exit(3100, 10 * COOLDOWN, CONTAINED, POLICY), ExitVerdict::NotSupervised));
    assert!(!t.retire(3100), "retired once");
    // The driver's next host takes a slot again.
    let again = t.note_started(3101, IMAGE).expect("table full");
    assert_eq!(again, slot);
}

// ── Live update: the swap verb ──────────────────────────────────────────────

/// A `Spawned` image serving as `tid` (a swap needs the signed row to
/// create the successor from).
fn spawned(t: &mut SupTable, tid: u32) -> usize {
    let slot = t.note_started(tid, IMAGE).expect("table full");
    assert!(t.set_restart(slot, SupRestart::OnFailure));
    slot
}

/// A swap replaces the entry's task without a death: the successor is the
/// entry's task, and no restart is spent or recorded.
///
/// **Canaries.** Let `swap_commit` count a restart: `restarts` reads 1.
/// Let `swap_begin` accept the entry's own task: the self-swap assertion
/// fails. Let `request_swap` accept a kernel host: `only_a_spawned_image_can_be_swapped`
/// fails.
#[test]
fn a_swap_replaces_the_task_and_spends_no_restart() {
    let mut t = SupTable::new();
    let slot = spawned(&mut t, 100);
    assert_eq!(t.next_swap(), None);
    assert!(!t.swap_begin(slot, 101), "a swap nobody asked for");
    assert!(t.request_swap(slot));
    assert!(!t.request_swap(slot), "asked once");
    assert_eq!(t.next_swap(), Some(slot));
    assert!(!t.swap_begin(slot, 100), "the entry's own task is no successor");
    assert!(!t.swap_begin(slot, 0));
    assert!(t.swap_begin(slot, 101));
    assert_eq!(t.next_swap(), None, "begun");
    assert!(!t.request_swap(slot), "one swap at a time");
    let e = t.entry(slot).unwrap();
    assert_eq!((e.tid, e.successor, e.restarts, e.state), (100, 101, 0, SupState::Serving));
    assert_eq!(t.swap_commit(slot, 2_000), Some((100, 101)));
    let e = t.entry(slot).unwrap();
    assert_eq!((e.tid, e.successor, e.restarts, e.window_n), (101, 0, 0, 0));
    assert_eq!(e.state, SupState::Serving);
    assert_eq!(t.swap_commit(slot, 3_000), None, "committed once");
    // The old task's end is nobody's death now.
    assert_eq!(t.on_exit(100, 4_000, FAILED, POLICY), ExitVerdict::NotSupervised);
    // The successor is the supervised one.
    assert!(matches!(t.on_exit(101, 5_000, FAILED, POLICY), ExitVerdict::Restart { .. }));
}

#[test]
fn only_a_spawned_image_can_be_swapped() {
    let mut t = SupTable::new();
    let slot = t.note_kernel_host(100, b"buzzer").expect("table full");
    assert!(!t.request_swap(slot), "a kernel host is not created from a row");
    assert!(!t.request_swap(MAX_SUPERVISED), "no such slot");
    let mut t = SupTable::new();
    let slot = spawned(&mut t, 100);
    assert!(t.request_swap(slot));
    t.on_exit(100, 10, FAILED, POLICY);
    assert!(!t.request_swap(slot), "a restarting entry is not swapped");
    let _ = SupOrigin::Spawned;
}

/// A swap that is given up leaves the old task the entry's, and hands back
/// the successor to stop. A death of the old task during a swap ends it.
#[test]
fn an_aborted_swap_keeps_the_old_task_and_a_death_ends_the_swap() {
    let mut t = SupTable::new();
    let slot = spawned(&mut t, 100);
    assert!(t.request_swap(slot));
    assert!(t.swap_begin(slot, 101));
    assert_eq!(t.swap_abort(slot), 101);
    let e = t.entry(slot).unwrap();
    assert_eq!((e.tid, e.successor, e.swap_pending), (100, 0, false));
    assert_eq!(t.swap_commit(slot, 5), None, "nothing to commit");
    assert!(t.request_swap(slot), "it can be asked again");
    t.swap_refused(slot);
    assert_eq!(t.next_swap(), None, "a refused request is forgotten");
    assert!(t.request_swap(slot));
    assert!(t.swap_begin(slot, 102));
    assert!(matches!(t.on_exit(100, 10, FAILED, POLICY), ExitVerdict::Restart { .. }));
    let e = t.entry(slot).unwrap();
    assert_eq!((e.tid, e.successor), (0, 0), "the death ended the swap");
}

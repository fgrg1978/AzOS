// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The flight recorder's per-CPU queues (`logger.rs`): records pushed on
//! several CPUs reach the medium in the order they were pushed, and the
//! latch the medium ends with is the one the machine ended with, so a
//! restart reads it back.
//!
//! Each test names its canary.

use super::flight_recorder::{begin, decode_file};
use super::log_storage_mock as fsmock;
use super::logger::*;

fn rt_yes() -> bool {
    true
}
fn rt_no() -> bool {
    false
}

/// The boot-time read seam over the mock medium's file 0.
struct Replay {
    pos: usize,
}

impl LogReplaySource for Replay {
    fn size(&mut self, serial: u32) -> Result<Option<u32>, LogStorageError> {
        Ok((serial == 0).then(|| fsmock::file_bytes(0).len() as u32))
    }
    fn open(&mut self, serial: u32) -> Result<(), LogStorageError> {
        if serial == 0 {
            self.pos = 0;
            Ok(())
        } else {
            Err(LogStorageError::Unavailable)
        }
    }
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, LogStorageError> {
        let bytes = fsmock::file_bytes(0);
        let n = buf.len().min(bytes.len().saturating_sub(self.pos));
        buf[..n].copy_from_slice(&bytes[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
    fn close(&mut self) {}
}

/// **Order across CPUs.** **Canary** `durable-merge-canary` (the queues
/// written one after another): red. One task pushes from four CPUs in turn, and
/// between pushes on another CPU, so that the queues hold interleaved runs:
/// the file holds the records in the order they were pushed, each once.
#[test]
fn records_of_every_cpu_reach_the_medium_in_push_order() {
    let _g = begin(0x0D0E_0001);
    logger_init().expect("mount succeeds");
    const N: u16 = 3 * LOG_QUEUES as u16 * 5;
    for i in 0..N {
        cpu_for_test(Some((i as usize * 7 / 3) % LOG_QUEUES));
        log_skill_start(i);
    }
    cpu_for_test(None);
    logger_flusher_pass();
    let got: Vec<u16> = decode_file(0)
        .iter()
        .filter(|r| r.kind == LOG_EVT_SKILL_START)
        .map(|r| u16::from_le_bytes([r.payload[0], r.payload[1]]))
        .collect();
    assert_eq!(got, (0..N).collect::<Vec<_>>(), "the file is not in push order");
    assert_eq!(logger_ring_len(), 0);
    logger_shutdown();
}

/// **The latch survives the restart.** **Canary** `durable-merge-canary`:
/// red. The operator's clear is recorded on
/// CPU 1, then a real-time task latches on CPU 0 (its durable call defers to
/// the flusher). The flusher's pass makes the latch durable and announces it;
/// the next boot's replay of the medium starts latched, with that action.
#[test]
fn a_latch_after_a_release_on_another_cpu_survives_the_restart() {
    let _g = begin(0x0D0E_0002);
    logger_init().expect("mount succeeds");
    let (durable0, lost0, _) = logger_latch_stats();
    cpu_for_test(Some(1));
    log_safety_violation(SAFETY_ESTOP, 3, 0);
    cpu_for_test(Some(0));
    logger_set_rt_probe(rt_yes);
    let r = log_safety_violation_durable(SAFETY_ESTOP, 2, 0x1A7C);
    logger_set_rt_probe(rt_no);
    cpu_for_test(None);
    assert_eq!(r, Err(LogStorageError::Deferred), "a real-time caller did block I/O");
    assert!(durable_record_pending());
    logger_flusher_pass();
    let (durable, lost, pending) = logger_latch_stats();
    assert_eq!((durable, lost, pending), (durable0 + 1, lost0, false), "the latch was not announced durable once");
    logger_shutdown();

    let replay = replay_boot(&mut Replay { pos: 0 });
    assert_eq!(replay.latch, BootLatch::Armed(2), "the restart does not start latched");
}

/// **A busy writer handle is waited for, not called full.** Every queue's
/// writer handle is held (other CPUs mid-push) when a latching e-stop is
/// logged: the push waits round the queues until a handle frees and the
/// record is kept. Held for longer than a push waits, the record is lost as
/// busy, counted as such, and an effect is refused as `Busy`, never `Full`.
///
/// **Canary** `durable-busy-canary`: a safety record gives up after two
/// rounds, as an ordinary one does, and the first latch is lost (red).
#[test]
fn a_busy_writer_handle_is_waited_for_not_called_full() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    let _g = begin(0x0D0E_0003);
    logger_init().expect("mount succeeds");
    let (_, lost0, _) = logger_latch_stats();
    let a0 = logger_analytics();
    let held = Arc::new(AtomicBool::new(false));
    let h2 = held.clone();
    let holder = std::thread::spawn(move || {
        let writers = hold_writers_for_test();
        h2.store(true, Ordering::SeqCst);
        let t = std::time::Instant::now();
        while logger_analytics().busy_waits == a0.busy_waits && t.elapsed() < std::time::Duration::from_secs(2) {
            core::hint::spin_loop();
        }
        drop(writers);
    });
    while !held.load(Ordering::SeqCst) {
        std::thread::yield_now();
    }
    let kept = log_safety_violation_admitted(SAFETY_ESTOP, 2, 0xB5);
    holder.join().unwrap();
    assert!(kept, "a latching e-stop was lost to a busy writer handle");
    assert_eq!(logger_latch_stats().1, lost0);
    assert!(logger_analytics().busy_waits > a0.busy_waits, "the push never found a handle taken");

    // Held past the wait: lost as busy, not full.
    let writers = hold_writers_for_test();
    let a1 = logger_analytics();
    assert!(!log_safety_violation_admitted(SAFETY_ESTOP, 2, 0xB6));
    let stop = commit_effect_record([0xFE, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], false);
    let effect = commit_effect_record([0xFE, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], true);
    drop(writers);
    let a2 = logger_analytics();
    assert_eq!((stop, effect), (EffectCommit::Busy, EffectCommit::Busy));
    assert_eq!(logger_latch_stats().1, lost0 + 1);
    assert_eq!(a2.events_busy - a1.events_busy, 2, "the latch and the stop are counted busy");
    assert_eq!(a2.events_dropped - a1.events_dropped, 2);
    let _ = logger_flush();
    logger_shutdown();
}

/// **A rotation whose old file did not sync keeps its records.** A device
/// stalls mid-record (the file rotates) and the old file's last fsync fails:
/// the real-time caller's latch record, which that file took, is not durable
/// and no marker says it is. The next pass writes it into the new file, whose
/// fsync succeeds, and only then is it announced durable.
///
/// **Canary** `durable-rotate-sync-canary`: the rotation calls the old file's
/// records durable whatever its fsync said; the marker comes first (red).
#[test]
fn a_rotation_whose_old_file_did_not_sync_keeps_its_records() {
    let _g = begin(0x0D0E_0004);
    logger_init().expect("mount succeeds");
    let (durable0, _, _) = logger_latch_stats();
    logger_set_rt_probe(rt_yes);
    let _ = log_safety_violation_durable(SAFETY_ESTOP, 2, 0x707);
    logger_set_rt_probe(rt_no);
    for i in 1..4u16 {
        log_skill_start(i);
    }
    // Write 0 was the header; the batch takes 80 bytes, then nothing.
    fsmock::with(|r| {
        r.short_write_at = Some((1, 80));
        r.fail_write_at = Some(2);
        r.fail_fsync_of = Some(0);
    });
    logger_flusher_pass();
    assert_eq!(fsmock::file_count(), 2, "the torn file was not rotated");
    assert!(durable_record_pending(), "a record in a file whose sync failed is called durable");
    assert_eq!(logger_latch_stats().0, durable0, "announced durable without a sync that covered it");
    logger_flusher_pass();
    assert!(!durable_record_pending());
    assert_eq!(logger_latch_stats().0, durable0 + 1);
    let in_new = decode_file(1).iter().any(|r| r.kind == LOG_EVT_SAFETY_VIOLATION
        && r.payload[0] == SAFETY_ESTOP && u32::from_le_bytes(r.payload[4..8].try_into().unwrap()) == 0x707);
    assert!(in_new, "the latch record is not in the file whose sync covered it");
    logger_shutdown();
}

/// **A record written twice is replayed once.** A failed fsync keeps the
/// batch in RAM and the next pass writes it again, so the file holds it
/// twice. The replay ends where the machine ended, both ways round: a
/// release then a latch replays latched, a latch then a release released.
///
/// **Canary**, by hand: make the replay keep the first latch-relevant
/// `SAFETY_ESTOP` of a file, not the last (`scan_open_log_file_body`): the
/// latch then a release replays latched (red).
#[test]
fn a_record_written_twice_after_a_failed_sync_is_replayed_once() {
    for (first, second, want) in [(3u8, 2u8, BootLatch::Armed(2)), (2, 3, BootLatch::Released)] {
        let _g = begin(0x0D0E_0005);
        logger_init().expect("mount succeeds");
        fsmock::with(|r| r.fail_fsync_of = Some(0));
        log_safety_violation(SAFETY_ESTOP, first, 0);
        log_safety_violation(SAFETY_ESTOP, second, 0);
        logger_flusher_pass();
        fsmock::with(|r| r.fail_fsync_of = None);
        logger_flusher_pass();
        let actions: Vec<u8> = decode_file(0).iter()
            .filter(|r| r.kind == LOG_EVT_SAFETY_VIOLATION && r.payload[0] == SAFETY_ESTOP)
            .map(|r| r.payload[1]).collect();
        assert_eq!(actions, vec![first, second, first, second], "the batch was not written again");
        logger_shutdown();
        assert_eq!(replay_boot(&mut Replay { pos: 0 }).latch, want);
    }
}

static GAP_FLUSHER: std::sync::Mutex<Option<std::thread::JoinHandle<()>>> = std::sync::Mutex::new(None);

/// Between a push's number and its publish: a flusher pass on another
/// thread, held here until it waits for that number (bounded).
fn flush_inside_the_gap() {
    let w0 = gap_waits_for_test();
    let h = std::thread::spawn(|| {
        logger_flusher_pass();
    });
    let t = std::time::Instant::now();
    while gap_waits_for_test() == w0 && t.elapsed() < std::time::Duration::from_millis(500) {
        std::thread::yield_now();
    }
    *GAP_FLUSHER.lock().unwrap() = Some(h);
}

/// **The flusher waits for a number in flight.** A flusher pass runs while a
/// push holds its number and has not published the record: it waits, then
/// writes both records in push order, steps over nothing and writes nothing
/// late.
///
/// **Canary** `durable-gap-skip-canary`: the flusher steps over the number at
/// once; the pass writes only the first record and counts a hole (red).
#[test]
fn the_flusher_waits_for_a_number_in_flight() {
    let _g = begin(0x0D0E_0006);
    logger_init().expect("mount succeeds");
    let holes0 = logger_analytics().holes;
    cpu_for_test(Some(1));
    log_skill_start(0x51);
    set_push_gap_hook_for_test(Some(flush_inside_the_gap));
    log_skill_start(0x52);
    set_push_gap_hook_for_test(None);
    cpu_for_test(None);
    if let Some(h) = GAP_FLUSHER.lock().unwrap().take() {
        h.join().unwrap();
    }
    let got: Vec<u16> = decode_file(0).iter()
        .filter(|r| r.kind == LOG_EVT_SKILL_START)
        .map(|r| u16::from_le_bytes([r.payload[0], r.payload[1]]))
        .collect();
    assert_eq!(got, vec![0x51, 0x52], "the pass did not wait for the record in flight");
    assert_eq!(logger_analytics().holes, holes0, "a number in flight was stepped over");
    logger_shutdown();
}

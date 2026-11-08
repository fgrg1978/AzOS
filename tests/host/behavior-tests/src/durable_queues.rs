// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The flight recorder's per-CPU queues (`logger.rs`): records pushed on
//! several CPUs reach the medium in the order they were pushed, and the
//! latch the medium ends with is the one the machine ended with, so a
//! restart reads it back.
//!
//! **Canary** `durable-merge-canary`: the flusher writes the queues one after
//! another instead of in push order; both tests go red.

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

/// **Order across CPUs.** One task pushes from four CPUs in turn, and
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

/// **The latch survives the restart.** The operator's clear is recorded on
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

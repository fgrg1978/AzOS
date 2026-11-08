// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The flight recorder's per-CPU queue in a booted kernel: a queue at its
//! effect limit refuses the next effect and counts nothing, a stop and a
//! safety record still find the reserve, and the durable call that follows
//! writes every one of them and leaves nothing in RAM.
//!
//! With a disk (the `ktest disk` rows) the records go to the boot's own
//! recorder file; without one the test brings the recorder up on a RAM
//! medium and takes it down again.
//!
//! Runtime canary `log-queue-full-drops`: a full queue answers as if it took
//! the record, so the refusal never comes: `not ok`.

use azos_actuation::logger::{self as log, EffectCommit, LogHandle, LogStorage, LogStorageError};

/// The medium of a boot without a disk: takes every byte, keeps none.
struct Ram;
static RAM: Ram = Ram;

impl LogStorage for Ram {
    fn open(&self, _serial: u32) -> Result<LogHandle, LogStorageError> {
        Ok(LogHandle(0))
    }
    fn write(&self, _h: LogHandle, buf: &[u8]) -> Result<usize, LogStorageError> {
        Ok(buf.len())
    }
    fn fsync(&self, _h: LogHandle) -> Result<(), LogStorageError> {
        Ok(())
    }
    fn close(&self, _h: LogHandle) -> Result<(), LogStorageError> {
        Ok(())
    }
}

/// An effect payload of a kind the receipt index does not hold, so the test
/// leaves no receipt for another test to find.
fn payload(class: u8) -> [u8; log::LOG_PAYLOAD_BYTES] {
    let mut p = [0u8; log::LOG_PAYLOAD_BYTES];
    p[0] = 0xFE;
    p[1] = class;
    p
}

fn full_queue_round() -> Result<(), &'static str> {
    log::logger_flush().map_err(|_| "the recorder could not be flushed before the test")?;
    if log::logger_ring_len() != 0 {
        return Err("records stayed in RAM after a flush");
    }
    let dropped0 = log::logger_analytics().events_dropped;
    let mut n = 0;
    while let EffectCommit::Committed(_) = log::commit_effect_record(payload(1), true) {
        n += 1;
        if n > log::LOG_QUEUE_CAPACITY {
            return Err("a queue took more effects than it holds");
        }
    }
    if n != log::ORDINARY_QUEUE_LIMIT {
        return Err("the queue refused an effect before its limit");
    }
    if log::commit_effect_record(payload(1), true) != EffectCommit::Full {
        return Err("a full queue took another effect");
    }
    if !matches!(log::commit_effect_record(payload(0), false), EffectCommit::Committed(_)) {
        return Err("a stop found no slot in the reserve");
    }
    let written = log::log_release_nonce_floor_durable(1)
        .map_err(|_| "the release nonce floor found no slot in the reserve, or was not written")?;
    if written < n + 2 {
        return Err("the durable call wrote fewer records than the queue held");
    }
    if log::logger_ring_len() != 0 || log::durable_record_pending() {
        return Err("records stayed in RAM after the durable call");
    }
    if log::logger_analytics().events_dropped != dropped0 {
        return Err("a refusal was counted as a lost record, or a record was lost");
    }
    Ok(())
}

azos_ktest::ktest! {
    fn logger_a_full_queue_refuses_an_effect_and_keeps_the_reserve() {
        let ram = !log::logger_active();
        if ram {
            log::logger_set_storage(&RAM);
            log::logger_init().map_err(|_| "the recorder did not start on a RAM medium")?;
        }
        let r = full_queue_round();
        if ram {
            log::logger_shutdown();
        }
        r
    }
}

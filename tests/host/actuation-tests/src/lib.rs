// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host-side tests for write-ahead receipts (innovation B1).
//!
//! The code under test is the code that ships: the effect gate
//! (`crates/core/actuation/src/effect_gate.rs`) over the real flight-recorder
//! ring and flusher (`logger.rs`), both pulled in with `#[path]`; only the
//! medium, the clock and the sync primitives are host stand-ins.
//!
//! The properties, and the test that holds each:
//!
//! * the device op runs only after its record is committed:
//!   `the_op_runs_only_after_its_record_is_committed`;
//! * a ring at its effect limit refuses the effect with a receipt, evicts
//!   nothing, and never refuses a stop: `a_ring_at_its_effect_limit_...`,
//!   `a_stop_is_never_refused_...`;
//! * a committed record survives any amount of ordinary logging:
//!   `committed_effect_records_are_never_evicted`;
//! * the ring keeps `RING_SAFETY_RESERVE` slots for safety records (latching
//!   and releasing e-stops, the release nonce floor) alone, so such a record
//!   always fits and no effect record is ever evicted for it, over 1000
//!   random sequences too: `the_estop_is_recorded_when_...`,
//!   `release_restore_and_nonce_records_use_the_reserve`,
//!   `only_a_safety_record_may_use_the_reserve`,
//!   `ordinary_records_never_queue_into_the_reserve`,
//!   `no_committed_effect_is_ever_evicted_over_random_sequences`;
//! * a power cut at any step leaves a record without an effect, never an
//!   effect without a record: `a_power_cut_never_leaves_an_effect_without_its_record`.
//!
//! **Canaries.** `--features effect-issue-before-commit-canary` (the gate
//! issues the op first): `the_op_runs_only_after_its_record_is_committed` and
//! `a_power_cut_never_leaves_an_effect_without_its_record` must both FAIL.
//! `--features ring-reserve-canary` (effects and ordinary records may use the
//! reserve): the ring tests above must FAIL.

extern crate beh_test_drivers as azos_drv_sys;

#[allow(dead_code)]
#[path = "../../../../crates/core/actuation/src/logger.rs"]
mod logger;

#[allow(dead_code)]
#[path = "../../../../crates/core/actuation/src/effect_gate.rs"]
mod effect_gate;

#[allow(dead_code)]
#[path = "../../../../crates/core/actuation/src/safe_state.rs"]
mod safe_state;

#[cfg(test)]
mod deadline;
#[cfg(test)]
mod soc_kinds;

// Receipt index (B3), fed by the effect gate.
#[cfg(test)]
mod receipt;
#[cfg(test)]
mod b4;
#[cfg(test)]
mod envelope;
#[cfg(test)]
mod held;
// I-13's rollback decision (`domains/robot/safety-core/src/txn_rule.rs`).
#[cfg(test)]
mod txn;

// `logger.rs` names the e-stop actions (`crate::estop`), which run their latch
// work through `hooks`. Pulled in as behavior-tests does.
#[allow(dead_code)]
#[path = "../../../../crates/core/actuation/src/estop.rs"]
mod estop;
#[allow(dead_code)]
#[path = "../../../../crates/core/actuation/src/hooks.rs"]
mod hooks;

/// `HookTable`: registration order, and a second registration of the same
/// function is a no-op (a repeated install cannot run a stop twice).
/// Canary: treat `Install::Same` as a taken slot in `register` and the
/// repeated hook runs twice.
#[cfg(test)]
mod hook_table {
    use super::hooks::HookTable;
    use std::sync::Mutex;

    static RAN: Mutex<Vec<u8>> = Mutex::new(Vec::new());
    fn a() { RAN.lock().unwrap().push(b'a'); }
    fn b() { RAN.lock().unwrap().push(b'b'); }

    #[test]
    fn hooks_run_once_each_in_registration_order() {
        static T: HookTable = HookTable::new();
        T.register(a);
        T.register(b);
        T.register(a);
        assert_eq!(T.len(), 2, "the same hook took a second slot");
        T.run();
        assert_eq!(*RAN.lock().unwrap(), b"ab");
    }
}

/// A host medium with a volatile write cache: `write` lands in the cache,
/// `fsync` makes it durable, and a power cut loses the cache. It can also be
/// told to cut the power at the Nth observable step of a run.
#[cfg(test)]
mod medium {
    use crate::logger::{LogHandle, LogStorage, LogStorageError};
    use std::sync::Mutex;

    /// What `rt_request_class_now` answered inside the medium's writes and
    /// fsyncs: `(real-time, ordinary)`.
    pub static CLASS_SEEN: [std::sync::atomic::AtomicU32; 2] =
        [std::sync::atomic::AtomicU32::new(0), std::sync::atomic::AtomicU32::new(0)];

    /// Count the class of the call being made (the block layer would stamp it
    /// on the request).
    fn note_class() {
        let rt = crate::logger::rt_request_class_now();
        CLASS_SEEN[if rt { 0 } else { 1 }].fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }

    pub fn class_seen() -> (u32, u32) {
        let at = |i: usize| CLASS_SEEN[i].load(std::sync::atomic::Ordering::SeqCst);
        (at(0), at(1))
    }

    pub fn class_reset() {
        CLASS_SEEN[0].store(0, std::sync::atomic::Ordering::SeqCst);
        CLASS_SEEN[1].store(0, std::sync::atomic::Ordering::SeqCst);
    }

    #[derive(Default)]
    pub struct File {
        pub durable: Vec<u8>,
        pub cache: Vec<u8>,
    }

    #[derive(Default)]
    pub struct State {
        pub files: Vec<File>,
        /// `fsync` fails (the bytes stay in the cache).
        pub fsync_fails: bool,
        /// Steps left before the power goes; `None`: no cut armed.
        pub cut_in: Option<u32>,
    }

    /// The power cut: unwound through the code under test by `step`, caught by
    /// the model. After it nothing the code would have done next happened.
    pub struct PowerCut;

    static M: Mutex<State> = Mutex::new(State { files: Vec::new(), fsync_fails: false, cut_in: None });

    pub fn with<R>(f: impl FnOnce(&mut State) -> R) -> R {
        f(&mut M.lock().unwrap_or_else(|e| e.into_inner()))
    }

    pub fn reset() {
        with(|m| *m = State::default());
    }

    /// One observable step (a medium write or sync, a device write). Counts
    /// down an armed cut and, at zero, stops the "CPU" right here.
    pub fn step() {
        let cut = with(|m| match m.cut_in {
            Some(1) => { m.cut_in = None; true }
            Some(n) => { m.cut_in = Some(n - 1); false }
            None => false,
        });
        if cut {
            std::panic::resume_unwind(Box::new(PowerCut));
        }
    }

    /// Bytes of every file that reached the medium proper.
    pub fn durable() -> Vec<Vec<u8>> {
        with(|m| m.files.iter().map(|f| f.durable.clone()).collect())
    }

    /// Bytes of every file including the volatile cache.
    pub fn pipeline() -> Vec<Vec<u8>> {
        with(|m| m.files.iter().map(|f| [f.durable.clone(), f.cache.clone()].concat()).collect())
    }

    pub struct Medium;
    pub static MEDIUM: Medium = Medium;

    impl LogStorage for Medium {
        fn open(&self, _serial: u32) -> Result<LogHandle, LogStorageError> {
            Ok(with(|m| {
                m.files.push(File::default());
                LogHandle((m.files.len() - 1) as u32)
            }))
        }
        fn write(&self, h: LogHandle, buf: &[u8]) -> Result<usize, LogStorageError> {
            note_class();
            step();
            with(|m| m.files[h.0 as usize].cache.extend_from_slice(buf));
            step();
            Ok(buf.len())
        }
        fn fsync(&self, h: LogHandle) -> Result<(), LogStorageError> {
            note_class();
            step();
            let ok = with(|m| {
                if m.fsync_fails {
                    return false;
                }
                let f = &mut m.files[h.0 as usize];
                let c = std::mem::take(&mut f.cache);
                f.durable.extend_from_slice(&c);
                true
            });
            step();
            if ok { Ok(()) } else { Err(LogStorageError::Io) }
        }
        fn close(&self, _h: LogHandle) -> Result<(), LogStorageError> {
            Ok(())
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use crate::effect_gate::{self, Class, Effect, Refusal, Timing, Why, KIND_MOTOR};
    use crate::logger::*;
    use crate::medium::{self, PowerCut};
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Mutex;

    /// The logger, the ring, the gate's counters and the medium are process
    /// state: one test at a time.
    pub(crate) static SERIAL: Mutex<()> = Mutex::new(());

    fn rt_yes() -> bool { true }
    fn rt_no() -> bool { false }

    /// A fresh recorder on a fresh medium; the previous test's leftovers in
    /// the ring are flushed to a throwaway one.
    pub(crate) fn fresh() -> std::sync::MutexGuard<'static, ()> {
        let g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        fresh_in_place();
        g
    }

    /// [`fresh`] for a caller that already holds the lock.
    fn fresh_in_place() {
        // No device is held in its safe state by an earlier test.
        crate::safe_state::clear_holds_for_test();
        logger_set_rt_probe(rt_no);
        logger_set_storage(&medium::MEDIUM);
        // Close what the previous test left open on its medium, then drain
        // what it left on the ring into a throwaway one.
        logger_shutdown();
        medium::reset();
        let _ = logger_init();
        logger_shutdown();
        medium::reset();
        logger_init().expect("the host medium mounts");
    }

    /// An effect that declares no timing and whose op cannot fail: B1's gate.
    fn issue0<R>(e: &Effect, op: impl FnOnce() -> R) -> Result<R, Refusal> {
        effect_gate::issue(e, &Timing::NONE, || (op(), true))
    }

    pub(crate) fn effect(class: Class, tag: u32) -> Effect {
        Effect { kind: KIND_MOTOR, class, subject: 1, tid: 7, a0: tag, a1: 50 }
    }

    /// Every effect record in `files`, in order.
    fn effect_records(files: &[Vec<u8>]) -> Vec<Effect> {
        let mut out = Vec::new();
        for f in files {
            for rec in f.get(LOG_FILE_HEADER_BYTES..).unwrap_or(&[]).chunks_exact(LOG_RECORD_SIZE) {
                let r = LogRecord::decode(rec.try_into().unwrap());
                if r.kind == LOG_EVT_ACTUATOR_CMD && r.flags == LOG_FLAG_EFFECT {
                    out.push(Effect::from_payload(&r.payload).expect("a known class"));
                }
            }
        }
        out
    }

    fn flush_all() {
        logger_flusher_pass();
        assert_eq!(logger_ring_len(), 0, "the flusher left records behind");
    }

    /// **The order.** Inside the device op, the record is already on the ring.
    /// Canary `effect-issue-before-commit-canary`: the op runs first, so the
    /// ring is still empty inside it and this goes red.
    #[test]
    fn the_op_runs_only_after_its_record_is_committed() {
        let _g = fresh();
        for class in [Class::Safe, Class::Reversible] {
            let before = logger_ring_len();
            let seen = std::cell::Cell::new(usize::MAX);
            issue0(&effect(class, 1), || seen.set(logger_ring_len())).expect("issued");
            assert_eq!(seen.get(), before + 1, "{class:?}: the op ran before its record was on the ring");
        }
    }

    /// The payload round-trips through the ring and the medium, and says what
    /// was asked.
    #[test]
    fn the_record_on_the_medium_says_what_was_issued() {
        let _g = fresh();
        let e = Effect { kind: KIND_MOTOR, class: Class::Reversible, subject: 1, tid: 0xABCD, a0: 3, a1: 77 };
        issue0(&e, || ()).unwrap();
        flush_all();
        assert_eq!(effect_records(&medium::durable()), vec![e]);
        let mut bad = e.payload();
        bad[1] = 9;
        assert_eq!(Effect::from_payload(&bad), None, "an unknown class must not decode");
    }

    /// The slots an effect or an ordinary record may take. Written out here,
    /// not read from `ORDINARY_RING_LIMIT`: the reserve canary changes that
    /// constant, and a test that read it would agree with the canary.
    const LIMIT: usize = LOG_RING_CAPACITY - RING_SAFETY_RESERVE;

    /// **Full ring.** Effects are admitted up to the limit; the next one is
    /// refused with a receipt that `why` can look up, the op does not run,
    /// nothing was evicted or counted dropped, and everything committed is on
    /// the medium afterwards. Draining the ring admits effects again.
    ///
    /// **Canary** `ring-reserve-canary`: effects may use the reserve, so the
    /// refusal never comes at the limit and this goes red.
    #[test]
    fn a_ring_at_its_effect_limit_refuses_the_effect_with_a_receipt() {
        let _g = fresh();
        let dropped0 = logger_analytics().events_dropped;
        for i in 0..LIMIT as u32 {
            issue0(&effect(Class::Reversible, 100 + i), || ()).expect("under the limit");
        }
        let ran = AtomicU32::new(0);
        let r = issue0(&effect(Class::Reversible, 999), || { ran.fetch_add(1, Ordering::Relaxed); });
        let Err(Refusal { receipt, why }) = r else { panic!("a ring at its limit issued an effect") };
        assert_eq!(why, Why::RingFull);
        assert_eq!(ran.load(Ordering::Relaxed), 0, "a refused effect reached the device");
        assert_ne!(receipt, 0, "a refusal without a receipt");
        let rec = azos_decision::lookup(receipt).expect("the receipt is a decision record");
        assert_eq!(rec.rule, azos_decision::Rule::EffectRecord as u8);
        assert_eq!(rec.verdict, azos_decision::Verdict::Refuse as u8);
        assert_eq!((rec.subject, rec.n[0], rec.n[1]), (7, (KIND_MOTOR as u64) << 8 | 1, Why::RingFull as u64));
        assert_eq!(rec.n[2], LIMIT as u64, "the record says how many were queued");
        assert_eq!(logger_analytics().events_dropped, dropped0, "a refusal dropped something");
        assert_eq!(logger_ring_len(), LIMIT, "a refusal evicted something");

        flush_all();
        let tags: Vec<u32> = effect_records(&medium::durable()).iter().map(|e| e.a0).collect();
        assert_eq!(tags, (100..100 + LIMIT as u32).collect::<Vec<_>>(), "a committed record was lost or reordered");
        issue0(&effect(Class::Reversible, 1000), || ()).expect("the drained ring admits effects again");
    }

    /// **A stop is never refused, and is recorded.** With the effect limit
    /// reached, a safe effect still reaches the device, and (owner decision
    /// 16-10) its record takes a slot of the safety reserve: no committed
    /// effect record is evicted to make room, and the record reaches the
    /// medium next to every effect record.
    ///
    /// **Canary** `ring-reserve-canary` does not apply (it opens the reserve
    /// to effects too); the reverting canary for this row is `Admit::Stop`
    /// written back as `Admit::Evict`: the ring stays at `LIMIT` and the stop
    /// is lost (`Full`, counted unrecorded), which fails the first assertion.
    #[test]
    fn a_stop_is_never_refused_by_a_full_ring_and_is_recorded_in_the_reserve() {
        let _g = fresh();
        for i in 0..LIMIT as u32 {
            issue0(&effect(Class::Reversible, i), || ()).unwrap();
        }
        assert!(issue0(&effect(Class::Reversible, 5000), || ()).is_err());

        let ran = AtomicU32::new(0);
        issue0(&effect(Class::Safe, 6000), || { ran.fetch_add(1, Ordering::Relaxed); }).expect("a stop");
        assert_eq!(ran.load(Ordering::Relaxed), 1, "a full ring stopped a stop");
        assert_eq!(logger_ring_len(), LIMIT + 1, "the stop's record is not in the reserve");
        let tags: Vec<u32> = effect_records(&{ flush_all(); medium::durable() }).iter().map(|e| e.a0).collect();
        let mut want: Vec<u32> = (0..LIMIT as u32).collect();
        want.push(6000);
        assert_eq!(tags, want, "recording a stop evicted an effect record, or the stop has no record");
    }

    /// **A loop of stops cannot take the e-stop's slots.** The ring at its
    /// effect limit (a pinned tail), then far more stops than the reserve
    /// holds: stops fill the reserve down to its last half, the rest are
    /// counted unrecorded, no effect record is evicted, and the latching
    /// e-stop still finds a slot for as many records as that half holds.
    ///
    /// **Canary:** `Admit::Stop` limited to the whole ring (no
    /// `STOP_KEEPS_FREE`): the loop fills the reserve and the e-stop is lost.
    #[test]
    fn a_loop_of_stops_cannot_take_the_slots_the_estop_needs() {
        let _g = fresh();
        for i in 0..LIMIT as u32 {
            issue0(&effect(Class::Reversible, 100 + i), || ()).unwrap();
        }
        let ran = AtomicU32::new(0);
        for k in 0..4 * RING_SAFETY_RESERVE as u32 {
            issue0(&effect(Class::Safe, 7000 + k), || { ran.fetch_add(1, Ordering::Relaxed); }).expect("a stop");
        }
        assert_eq!(ran.load(Ordering::Relaxed), 4 * RING_SAFETY_RESERVE as u32, "a stop was refused");
        // Written out, not read from `STOP_KEEPS_FREE`: the canary changes it.
        let half = RING_SAFETY_RESERVE / 2;
        assert_eq!(logger_ring_len(), LIMIT + half, "stops did not stop at half the reserve");

        let lost0 = logger_latch_stats().1;
        for k in 0..half as u32 {
            log_safety_violation(SAFETY_ESTOP, 1, 0xE5_00 + k);
        }
        assert_eq!(logger_latch_stats().1, lost0, "the e-stop lost its slot to a loop of stops");
        assert_eq!(logger_ring_len(), LOG_RING_CAPACITY);
        logger_flusher_pass();
        let files = medium::durable();
        assert_eq!(estop_details(&files), (0..half as u32).map(|k| 0xE5_00 + k).collect::<Vec<_>>());
        let tags: Vec<u32> = effect_records(&files).iter().map(|e| e.a0).collect();
        assert_eq!(&tags[..LIMIT], &(100..100 + LIMIT as u32).collect::<Vec<_>>()[..], "an effect record was evicted");
    }

    /// **Never dropped.** Ordinary records that overrun the ring evict each
    /// other's predecessors but not a committed effect record: every one of
    /// them is on the medium afterwards. Without the pin (`EFFECT_PIN`) the
    /// first ordinary overrun evicts them.
    #[test]
    fn committed_effect_records_are_never_evicted() {
        let _g = fresh();
        for i in 0..10 {
            issue0(&effect(Class::Reversible, i), || ()).unwrap();
        }
        let dropped0 = logger_analytics().events_dropped;
        for _ in 0..4 * LOG_RING_CAPACITY {
            log_error(2, 2, 0);
        }
        assert!(logger_analytics().events_dropped > dropped0, "the overrun must cost ordinary records");
        flush_all();
        let tags: Vec<u32> = effect_records(&medium::durable()).iter().map(|e| e.a0).collect();
        assert_eq!(tags, (0..10).collect::<Vec<_>>());
    }

    /// Every ordinary record of `kind` in `files`, in order.
    fn records_of(files: &[Vec<u8>], kind: u8) -> Vec<LogRecord> {
        let mut out = Vec::new();
        for f in files {
            for rec in f.get(LOG_FILE_HEADER_BYTES..).unwrap_or(&[]).chunks_exact(LOG_RECORD_SIZE) {
                let r = LogRecord::decode(rec.try_into().unwrap());
                if r.kind == kind && r.flags == 0 {
                    out.push(r);
                }
            }
        }
        out
    }

    /// `detail` of every `SAFETY_ESTOP` record in `files`, in order.
    fn estop_details(files: &[Vec<u8>]) -> Vec<u32> {
        records_of(files, LOG_EVT_SAFETY_VIOLATION).iter()
            .filter(|r| r.payload[0] == SAFETY_ESTOP)
            .map(|r| u32::from_le_bytes(r.payload[4..8].try_into().unwrap()))
            .collect()
    }

    /// A ring at its limit with a pinned tail: `LIMIT` reversible effects
    /// (tags 100..). An ordinary record is now lost, not queued, and the
    /// ring does not grow into the reserve.
    fn ring_at_its_limit_of_pinned_effects() {
        for i in 0..LIMIT as u32 {
            issue0(&effect(Class::Reversible, 100 + i), || ()).expect("under the limit");
        }
        assert_eq!(logger_ring_len(), LIMIT);
        let dropped0 = logger_analytics().events_dropped;
        log_error(1, 1, 0);
        assert_eq!(logger_analytics().events_dropped, dropped0 + 1, "an ordinary record was queued behind a pinned tail");
        assert_eq!(logger_ring_len(), LIMIT, "an ordinary record took a slot of the reserve");
    }

    /// **The effect records stay.** Fill the ring to the reserve with effects
    /// and refuse the next; the latching e-stop is recorded all the same, in
    /// a real-time caller (which may not drain the ring first) and by the
    /// plain, non-durable call, evicts nothing, counts nothing dropped, and
    /// reaches the medium next to every effect record.
    ///
    /// **Canary** `ring-reserve-canary`: effects fill the whole ring, the
    /// e-stop has no slot and is lost.
    #[test]
    fn the_estop_is_recorded_when_the_ring_is_at_its_limit_and_no_effect_is_evicted() {
        let _g = fresh();
        ring_at_its_limit_of_pinned_effects();
        assert!(issue0(&effect(Class::Reversible, 999), || ()).is_err());

        // The real-time caller: no drain, one push.
        logger_set_rt_probe(rt_yes);
        let lost0 = logger_latch_stats().1;
        let dropped0 = logger_analytics().events_dropped;
        let _ = log_safety_violation_durable(SAFETY_ESTOP, 6, 0xE57);
        logger_set_rt_probe(rt_no);
        assert_eq!(logger_latch_stats().1, lost0, "the latching e-stop record was lost to a full ring");
        assert!(logger_latch_stats().2, "the latching e-stop record is not pending");
        assert_eq!(logger_analytics().events_dropped, dropped0, "recording the e-stop dropped a record");
        assert_eq!(logger_ring_len(), LIMIT + 1);

        // The plain call: the next reserve slot.
        log_safety_violation(SAFETY_ESTOP, 6, 0xE58);
        assert_eq!(logger_analytics().events_dropped, dropped0, "the plain e-stop dropped a record");
        assert_eq!(logger_ring_len(), LIMIT + 2);

        logger_flusher_pass();
        let files = medium::durable();
        assert_eq!(estop_details(&files), vec![0xE57, 0xE58], "an e-stop record is not on the medium");
        let tags: Vec<u32> = effect_records(&files).iter().map(|e| e.a0).collect();
        assert_eq!(tags, (100..100 + LIMIT as u32).collect::<Vec<_>>(), "an effect record was evicted");
    }

    /// **Release and latch use the reserve too.** The operator's clear
    /// (action 3), the boot replay's restore (5) and the release nonce floor
    /// are recorded at a ring at its limit; every one of the reserve's slots
    /// is usable, and no effect record is evicted for any of them.
    #[test]
    fn release_restore_and_nonce_records_use_the_reserve() {
        let _g = fresh();
        ring_at_its_limit_of_pinned_effects();
        logger_set_rt_probe(rt_yes);
        let lost0 = logger_latch_stats().1;
        let _ = log_safety_violation_durable(SAFETY_ESTOP, 3, 0xC1);
        let _ = log_safety_violation_durable(SAFETY_ESTOP, crate::logger::ESTOP_ACTION_RESTORED, 0xC2);
        let _ = log_release_nonce_floor_durable(0x1234_5678_9ABC);
        logger_set_rt_probe(rt_no);
        assert_eq!(logger_latch_stats().1, lost0);
        assert_eq!(logger_ring_len(), LIMIT + 3);
        // The rest of the reserve.
        for k in 3..RING_SAFETY_RESERVE as u32 {
            log_safety_violation(SAFETY_ESTOP, 1, 0xC3 + k);
        }
        assert_eq!(logger_ring_len(), LOG_RING_CAPACITY, "the reserve is not all usable");
        assert_eq!(logger_latch_stats().1, lost0, "a safety record was lost with the reserve not yet full");

        logger_flusher_pass();
        let tags: Vec<u32> = effect_records(&medium::durable()).iter().map(|e| e.a0).collect();
        assert_eq!(tags, (100..100 + LIMIT as u32).collect::<Vec<_>>(), "an effect record was evicted");
    }

    /// **The block layer's real-time class follows the records.** A record
    /// pushed by a `*_durable` call is pending until an `Ok` fsync covers it;
    /// an ordinary record never is. A real-time caller pushes it and does no
    /// I/O; the flusher's pass writes it. A failed fsync leaves it pending
    /// until a later flush's fsync covers its position.
    ///
    /// **Canary.** Make `push_durable` skip `DURABLE_WANT` (or
    /// `durable_record_pending` answer `false`): the first pending assertion
    /// fails. Make a flush never advance `DURABLE_POS`: the last one does.
    #[test]
    fn a_durable_record_is_pending_until_an_fsync_covers_it() {
        let _g = fresh();
        log_mode_change(1, 2);
        flush_all();
        assert!(!durable_record_pending(), "nothing is waiting");
        log_mode_change(2, 3);
        assert!(!durable_record_pending(), "an ordinary record is no demand");

        // A real-time caller: pushed, no block I/O of its own.
        logger_set_rt_probe(rt_yes);
        let _ = log_safety_violation_durable(SAFETY_ESTOP, 6, 0xD1);
        logger_set_rt_probe(rt_no);
        assert!(durable_record_pending(), "the record is on the ring, not on the medium");
        assert!(estop_details(&medium::durable()).is_empty(), "the real-time caller wrote it itself");

        // The flusher's pass writes it, but the fsync fails: written, not durable.
        medium::with(|m| m.fsync_fails = true);
        logger_flusher_pass();
        assert!(durable_record_pending(), "written is not durable");
        medium::with(|m| m.fsync_fails = false);
        // The next flush's fsync is file-wide and covers it.
        log_mode_change(3, 4);
        logger_flusher_pass();
        assert!(!durable_record_pending(), "an Ok fsync covered the record");
        assert_eq!(estop_details(&medium::durable()), vec![0xD1]);

        // A non-real-time caller flushes itself: durable when the call returns.
        assert!(log_safety_violation_durable(SAFETY_ESTOP, 6, 0xD2).is_ok());
        assert!(!durable_record_pending());
        // The operator-release nonce floor is a durable record too.
        logger_set_rt_probe(rt_yes);
        let _ = log_release_nonce_floor_durable(0x77);
        logger_set_rt_probe(rt_no);
        assert!(durable_record_pending());
        logger_flusher_pass();
        assert!(!durable_record_pending());

        // With the logger off there is nowhere for a record to land.
        logger_set_rt_probe(rt_yes);
        let _ = log_safety_violation_durable(SAFETY_ESTOP, 6, 0xD3);
        logger_set_rt_probe(rt_no);
        medium::with(|m| m.fsync_fails = true);
        logger_shutdown();
        assert!(!durable_record_pending(), "no logger, no demand");
    }

    /// **Which requests carry the record.** The medium's writes and fsyncs
    /// ask `rt_request_class_now` as the block layer would at submit. Inside
    /// the flush that carries a pending durable record they answer yes; in an
    /// ordinary flush, outside any flush, and once the record is durable, no.
    /// A real-time caller that pushes the record asks no question of its own:
    /// it does no I/O, the flusher's pass does.
    ///
    /// **Canary.** Make `rt_request_class_now` ignore `FLUSHING_TID` (the
    /// caller outside a flush then answers yes), or skip `FlushingHere::enter`
    /// in `logger_flush_locked` (the flush answers no): this goes red.
    #[test]
    fn only_the_flush_that_carries_a_pending_record_asks_for_the_real_time_class() {
        let _g = fresh();
        log_mode_change(1, 2);
        flush_all();

        // An ordinary flush: every call is ordinary.
        medium::class_reset();
        log_mode_change(2, 3);
        flush_all();
        let (rt, plain) = medium::class_seen();
        assert_eq!((rt, plain > 0), (0, true), "an ordinary flush asked for the class");

        // The flush that carries a pending record: write and fsync both.
        logger_set_rt_probe(rt_yes);
        let _ = log_safety_violation_durable(SAFETY_ESTOP, 6, 0xE1);
        logger_set_rt_probe(rt_no);
        assert!(durable_record_pending());
        assert!(!rt_request_class_now(), "outside any flush, the pending record gives the caller no class");
        medium::class_reset();
        logger_flusher_pass();
        let (rt, plain) = medium::class_seen();
        assert!(rt >= 2, "the flush's write and fsync both carry the record (saw {rt})");
        assert_eq!(plain, 0, "no call of that flush was ordinary");
        assert!(!durable_record_pending());
        assert!(!rt_request_class_now(), "after the flush, the flusher is ordinary again");

        // A non-real-time caller flushes itself: the same, in its own context.
        medium::class_reset();
        assert!(log_safety_violation_durable(SAFETY_ESTOP, 6, 0xE2).is_ok());
        let (rt, plain) = medium::class_seen();
        assert!(rt >= 2 && plain == 0, "the caller's own flush carries the record ({rt}, {plain})");

        // Once the record is durable the next flush is ordinary.
        medium::class_reset();
        log_mode_change(3, 4);
        flush_all();
        assert_eq!(medium::class_seen().0, 0);
    }

    /// **Only safety records use the reserve.** The same ring at its limit
    /// with a pinned tail: a record that does not decide the latch (an
    /// envelope refusal, a commander-lost stop, the boot self-check's
    /// synthetic record) is lost, as every ordinary record is, takes no
    /// reserve slot, and every effect record is still there. With the reserve
    /// full of safety records, one more is lost and counted, and still no
    /// effect record is evicted.
    ///
    /// **Canary.** Let `reserve_admit` answer `Safety` for any record: the
    /// first assertion fails.
    #[test]
    fn only_a_safety_record_may_use_the_reserve() {
        let _g = fresh();
        ring_at_its_limit_of_pinned_effects();
        for (code, action) in [
            (SAFETY_ENVELOPE_REFUSED, 0),
            (SAFETY_ESTOP, crate::estop::ESTOP_ACTION_COMMANDER_LOST),
            (SAFETY_ESTOP, 7),
        ] {
            let dropped0 = logger_analytics().events_dropped;
            log_safety_violation(code, action, 0);
            // Real-time: the durable call does not drain the ring and retry.
            logger_set_rt_probe(rt_yes);
            let _ = log_safety_violation_durable(code, action, 0);
            logger_set_rt_probe(rt_no);
            assert_eq!(logger_analytics().events_dropped, dropped0 + 2,
                "code {code:#x} action {action}: a record that does not decide the latch must be the one lost");
            assert_eq!(logger_ring_len(), LIMIT, "code {code:#x} action {action}: it took a slot of the reserve");
        }

        for k in 0..RING_SAFETY_RESERVE as u32 {
            log_safety_violation(SAFETY_ESTOP, 1, 0xA0 + k);
        }
        assert_eq!(logger_ring_len(), LOG_RING_CAPACITY);
        let lost0 = logger_latch_stats().1;
        log_safety_violation(SAFETY_ESTOP, 1, 0xBAD);
        assert_eq!(logger_latch_stats().1, lost0 + 1, "a latching record lost to a full reserve must be counted");
        assert_eq!(logger_ring_len(), LOG_RING_CAPACITY);

        logger_flusher_pass();
        let files = medium::durable();
        assert_eq!(estop_details(&files), (0..RING_SAFETY_RESERVE as u32).map(|k| 0xA0 + k).collect::<Vec<_>>());
        let tags: Vec<u32> = effect_records(&files).iter().map(|e| e.a0).collect();
        assert_eq!(tags, (100..100 + LIMIT as u32).collect::<Vec<_>>(), "an effect record was evicted");
    }

    /// **Ordinary records stop at the limit.** A ring of ordinary records
    /// (nothing pinned) never holds more than the limit: the oldest is evicted
    /// (counted) rather than a reserve slot used, and the e-stop still finds
    /// its slot.
    #[test]
    fn ordinary_records_never_queue_into_the_reserve() {
        let _g = fresh();
        for _ in 0..3 * LOG_RING_CAPACITY {
            log_error(3, 3, 0);
            assert!(logger_ring_len() <= LIMIT, "an ordinary record took a slot of the reserve");
        }
        assert_eq!(logger_ring_len(), LIMIT);
        let dropped0 = logger_analytics().events_dropped;
        log_safety_violation(SAFETY_ESTOP, 1, 0xE5);
        assert_eq!(logger_ring_len(), LIMIT + 1);
        assert_eq!(logger_analytics().events_dropped, dropped0);
    }

    /// One step of the randomized run.
    #[derive(Clone, Copy, Debug)]
    enum Op { Reversible, Stop, Ordinary, Estop, Release, DurableRt, DurableNonRt, Flush }

    /// **1000 random sequences: no committed effect record is ever lost.**
    /// Each sequence interleaves reversible and safe effects, ordinary
    /// records, latching and releasing e-stops (plain, durable from a
    /// real-time and from a normal caller) and flusher passes. At the end:
    ///
    /// * every effect the gate committed (reversible) is on the medium, once,
    ///   in order: the only way one leaves the ring is the flusher;
    /// * a reversible effect was refused only with the ring at its limit;
    /// * a safety record pushed while fewer than half the reserve's worth had
    ///   been pushed since the last flush was never lost (stops take the
    ///   other half, `STOP_KEEPS_FREE` keeps this one free).
    ///
    /// **Canary** `ring-reserve-canary`: the ring fills with effects and the
    /// next safety record is lost.
    #[test]
    fn no_committed_effect_is_ever_evicted_over_random_sequences() {
        let _g = fresh();
        let mut rng = Lcg(0xB1_5EED_0016);
        let ops = [Op::Reversible, Op::Stop, Op::Ordinary, Op::Estop, Op::Release,
                   Op::DurableRt, Op::DurableNonRt, Op::Flush];
        let fill = [Op::Reversible, Op::Reversible, Op::Reversible, Op::Reversible, Op::Reversible,
                    Op::Reversible, Op::Reversible, Op::Reversible, Op::Stop, Op::Ordinary];
        let safety = [Op::Estop, Op::Release, Op::DurableRt];
        let mut refusals = 0u32;
        let mut safety_pushed = 0u32;
        for seq in 0..1000u32 {
            fresh_in_place();
            let mut committed: Vec<u32> = Vec::new();
            let mut since_flush = 0usize;
            let mut next_tag = 0u32;
            // Half the sequences never flush: they fill the ring with effects
            // for as long as it takes to reach the limit, then push safety
            // records into a ring with a pinned tail.
            let bias = rng.next() % 2 == 0;
            let fill_steps = 100 + (rng.next() % 100) as u32;
            let total = if bias { fill_steps + 1 + (rng.next() % 12) as u32 } else { 20 + (rng.next() % 300) as u32 };
            for step in 0..total {
                let op = if bias && step < fill_steps { fill[(rng.next() % fill.len() as u64) as usize] }
                         else if bias { safety[(rng.next() % safety.len() as u64) as usize] }
                         else { ops[(rng.next() % ops.len() as u64) as usize] };
                let len_before = logger_ring_len();
                let lost0 = logger_latch_stats().1;
                match op {
                    Op::Reversible | Op::Stop => {
                        let class = if matches!(op, Op::Stop) { Class::Safe } else { Class::Reversible };
                        let tag = next_tag; next_tag += 1;
                        match issue0(&effect(class, tag), || ()) {
                            Ok(()) if class == Class::Reversible => committed.push(tag),
                            Ok(()) => {}
                            Err(_) => {
                                refusals += 1;
                                assert!(len_before >= LIMIT, "seq {seq} step {step}: refused with {len_before} queued");
                            }
                        }
                    }
                    Op::Ordinary => log_error(4, 4, step),
                    Op::Estop | Op::Release | Op::DurableRt | Op::DurableNonRt => {
                        let action = if matches!(op, Op::Release) { 3 } else { 1 };
                        let latching = action != 3;
                        let needs = since_flush < RING_SAFETY_RESERVE / 2;
                        safety_pushed += 1;
                        match op {
                            Op::DurableRt => {
                                logger_set_rt_probe(rt_yes);
                                let _ = log_safety_violation_durable(SAFETY_ESTOP, action, 0xE000 + step);
                                logger_set_rt_probe(rt_no);
                            }
                            Op::DurableNonRt => {
                                let _ = log_safety_violation_durable(SAFETY_ESTOP, action, 0xE000 + step);
                            }
                            _ => log_safety_violation(SAFETY_ESTOP, action, 0xE000 + step),
                        }
                        since_flush += 1;
                        if matches!(op, Op::DurableNonRt) { since_flush = 0; }
                        if needs && latching {
                            assert_eq!(logger_latch_stats().1, lost0,
                                "seq {seq} step {step}: a safety record was lost with only {} pushed since the last flush", since_flush - 1);
                        }
                    }
                    Op::Flush => { logger_flusher_pass(); since_flush = 0; }
                }
            }
            logger_flusher_pass();
            let tags: Vec<u32> = effect_records(&medium::durable()).iter().map(|e| e.a0).collect();
            // Safe effects may also be on the medium; only the reversible ones
            // are promised.
            let reversible: Vec<u32> = tags.into_iter().filter(|t| committed.contains(t)).collect();
            assert_eq!(reversible, committed, "seq {seq}: a committed effect record was evicted");
        }
        assert!(refusals > 100, "the model refused only {refusals} effects, the limit was rarely met");
        assert!(safety_pushed > 1000);
    }

    // -----------------------------------------------------------------------
    // The power-cut model.
    // -----------------------------------------------------------------------

    /// Deterministic generator (a 64-bit LCG): the run is the same every time.
    struct Lcg(u64);
    impl Lcg {
        fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            self.0 >> 33
        }
    }

    /// The device: the tags of the effects that reached it.
    static DEVICE: Mutex<Vec<u32>> = Mutex::new(Vec::new());

    /// The device write, two observable steps around the effect itself: a cut
    /// before the first leaves the device alone, a cut after the second is
    /// "the effect happened, then the power went".
    fn device_write(tag: u32) {
        medium::step();
        DEVICE.lock().unwrap_or_else(|e| e.into_inner()).push(tag);
        medium::step();
    }

    /// **Power cut, ×1000.** Each iteration issues one effect (any class) on
    /// a recorder that may already hold other effects, then runs the flusher
    /// once, and cuts the power at a random step of that run: before or after
    /// the device write, before or after a medium write, before or after a
    /// sync, or not at all. At every cut:
    ///
    /// * an effect that reached the device has a record in the recorder's
    ///   pipeline (ring, medium cache, medium): never an effect without one.
    ///
    /// An effect's record is durable only after the flusher has run (a flush
    /// interval), so a power cut that loses RAM can lose it: that is the
    /// gate's stated bound, not something this model hides, and why durability
    /// is not asserted here.
    ///
    /// The model also has to see both outcomes of a cut, or it proves nothing:
    /// a record with no effect (the cut fell between them) and an effect with
    /// its record must each occur, in every class.
    ///
    /// Canary `effect-issue-before-commit-canary`: the op runs first, a cut
    /// after it leaves an effect nobody recorded, and this goes red.
    #[test]
    fn a_power_cut_never_leaves_an_effect_without_its_record() {
        let _g = fresh();
        let mut rng = Lcg(0x5EED_B1_0001);
        let classes = [Class::Safe, Class::Reversible];
        // Per class: [record without effect, effect with record, run not cut].
        let mut seen = [[0u32; 3]; 2];
        let mut cuts = 0u32;

        for iteration in 0..1000u32 {
            let tag = 1_000_000 + iteration;
            // A recorder in a varying state: 0..4 earlier effects, flushed or not.
            fresh_in_place();
            for k in 0..rng.next() % 5 {
                issue0(&effect(Class::Reversible, k as u32), || ()).unwrap();
            }
            if rng.next() % 2 == 0 {
                logger_flusher_pass();
            }
            DEVICE.lock().unwrap_or_else(|e| e.into_inner()).clear();

            let ci = (rng.next() % 2) as usize;
            let class = classes[ci];
            // The longest run is 6 steps (a flush is write+sync, 2 steps each,
            // the device write 2): 1..=8 leaves some runs uncut.
            let cut_at = 1 + (rng.next() % 8) as u32;
            medium::with(|m| m.cut_in = Some(cut_at));

            let run = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                // A refusal is not expected on a ring this empty.
                issue0(&effect(class, tag), || device_write(tag)).expect("issued");
                logger_flusher_pass();
            }));
            medium::with(|m| m.cut_in = None);
            let cut = match run {
                Ok(()) => false,
                Err(p) => {
                    assert!(p.is::<PowerCut>(), "the run failed for a reason other than the cut");
                    true
                }
            };
            cuts += cut as u32;

            // What a fault that keeps RAM leaves: also the ring and the cache.
            logger_flusher_pass();
            let in_pipeline = effect_records(&medium::pipeline()).iter().any(|e| e.a0 == tag);
            let applied = DEVICE.lock().unwrap_or_else(|e| e.into_inner()).contains(&tag);

            assert!(!applied || in_pipeline,
                "iteration {iteration} ({class:?}, cut at step {cut_at}): the effect reached the device with no record");
            let row = &mut seen[ci];
            row[2] += !cut as u32;
            row[1] += applied as u32;
            row[0] += (!applied && in_pipeline) as u32;
        }
        assert!(cuts > 400 && cuts < 1000, "the model cut {cuts} of 1000 runs");
        for (ci, c) in classes.iter().enumerate() {
            assert!(seen[ci][0] > 0, "{c:?}: no cut ever fell between the record and the effect, the model is blind to that side");
            assert!(seen[ci][1] > 0, "{c:?}: no cut ever fell after the effect, the model is blind to that side");
            assert!(seen[ci][2] > 0, "{c:?}: no run ever finished");
        }
    }
}

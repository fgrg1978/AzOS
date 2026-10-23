// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! System suspend (`crates/drivers/power/src/pm.rs` and `pm/suspend.rs`, pulled
//! in by path, so the code under test is the code the kernel links).
//!
//! * `order`: the sequence goes freeze, quiesce, save, enter and comes back in
//!   reverse; a step that fails undoes the ones before it, newest first.
//! * `gates`: what refuses before anything is touched, the robot preset (the
//!   build without `SYSTEM_SUSPEND`) first.
//! * `boottime`: the sleep the monotonic counter did not count reaches the
//!   boot offset, and nothing is invented when it did count it or when there
//!   is no clock that kept running.
//! * `records`: `Rule::Suspend` is written both ways, through the real decision
//!   ring, with the numbers the rule names.
//!
//! The platform here is a script: it logs each step it is asked for, and every
//! answer is set by the test. Canaries (run by hand, 2026-10-16): swapping
//! `thaw` and `unquiesce` on the way up fails the three tests that read the
//! full order; dropping the `others > 0` gate fails
//! `a_second_cpu_online_refuses_before_anything_is_touched`; making `slept_ns`
//! ignore the monotonic delta fails the BOOTTIME tests (and the two that read
//! the resume record); dropping the `enabled()` gate fails the two robot-preset
//! tests.

#[path = "../../../../crates/drivers/power/src/pm.rs"]
pub mod pm;

use pm::suspend::*;
use std::collections::VecDeque;
use std::sync::Mutex;

/// A platform whose every answer the test sets and whose every step is logged.
struct Script {
    log: Mutex<Vec<String>>,
    enabled: bool,
    support: Result<(), Reason>,
    assertions: u32,
    cpus: u32,
    wake: u32,
    freeze: Result<(), ()>,
    quiesce: Result<(), u32>,
    unquiesce_failed: u32,
    save: Result<(), ()>,
    enter: Result<(), i32>,
    clocks: Mutex<VecDeque<Clocks>>,
    boot_added: Mutex<Vec<u64>>,
    records: Mutex<Vec<(u32, Record)>>,
}

const MS: u64 = 1_000_000;

fn clocks(mono_ms: u64, persistent_ms: Option<u64>) -> Clocks {
    Clocks { mono_ns: mono_ms * MS, persistent_ns: persistent_ms.map(|p| p * MS) }
}

impl Script {
    /// A machine that suspends: every gate open, every step works, the clock
    /// that kept running advanced 1000 ms and the monotonic one the same.
    fn working() -> Script {
        Script {
            log: Mutex::new(Vec::new()),
            enabled: true,
            support: Ok(()),
            assertions: 0,
            cpus: 1,
            wake: 1,
            freeze: Ok(()),
            quiesce: Ok(()),
            unquiesce_failed: 0,
            save: Ok(()),
            enter: Ok(()),
            clocks: Mutex::new(VecDeque::from([clocks(100, Some(5_000)), clocks(1_100, Some(6_000))])),
            boot_added: Mutex::new(Vec::new()),
            records: Mutex::new(Vec::new()),
        }
    }

    fn with_clocks(self, before: Clocks, after: Clocks) -> Script {
        *self.clocks.lock().unwrap() = VecDeque::from([before, after]);
        self
    }

    fn step(&self, what: &str) {
        self.log.lock().unwrap().push(what.to_string());
    }

    fn log(&self) -> Vec<String> {
        self.log.lock().unwrap().clone()
    }

    fn records(&self) -> Vec<(u32, Record)> {
        self.records.lock().unwrap().clone()
    }
}

impl Platform for Script {
    fn enabled(&self) -> bool {
        self.enabled
    }
    fn support(&self) -> Result<(), Reason> {
        self.support
    }
    fn assertions(&self) -> u32 {
        self.assertions
    }
    fn online_cpus(&self) -> u32 {
        self.cpus
    }
    fn wake_sources(&self, _caller: u32) -> u32 {
        self.wake
    }
    fn freeze(&self) -> Result<(), ()> {
        self.step("freeze");
        self.freeze
    }
    fn thaw(&self) {
        self.step("thaw");
    }
    fn quiesce(&self) -> Result<(), u32> {
        self.step("quiesce");
        self.quiesce
    }
    fn unquiesce(&self) -> u32 {
        self.step("unquiesce");
        self.unquiesce_failed
    }
    fn save(&self) -> Result<(), ()> {
        self.step("save");
        self.save
    }
    fn restore(&self) {
        self.step("restore");
    }
    fn enter(&self) -> Result<(), i32> {
        self.step("enter");
        self.enter
    }
    fn clocks(&self) -> Clocks {
        self.clocks.lock().unwrap().pop_front().expect("the sequence read the clocks more than twice")
    }
    fn add_boot_ns(&self, ns: u64) {
        self.step("boot");
        self.boot_added.lock().unwrap().push(ns);
    }
    fn record(&self, subject: u32, r: Record) {
        self.step(&format!(
            "record {} state={:#x} blockers={} reason={:#x}",
            match r.verdict {
                Verdict::Admit => "admit",
                Verdict::Refuse => "refuse",
            },
            r.state, r.blockers, r.reason,
        ));
        self.records.lock().unwrap().push((subject, r));
    }
}

const CALLER: u32 = 7;
const DOMAIN: u32 = 0x5155;

fn run_script(s: &Script) -> Outcome {
    run(s, CALLER, DOMAIN)
}

mod order {
    use super::*;

    #[test]
    fn a_suspend_goes_down_in_order_and_comes_back_in_reverse() {
        let s = Script::working();
        let o = run_script(&s);
        assert_eq!(o, Outcome::Resumed { slept_ns: 0, unresumed: 0 });
        assert_eq!(o.code(), 0);
        assert_eq!(s.log(), [
            "record admit state=0x1 blockers=0 reason=0x0",
            "freeze",
            "quiesce",
            "save",
            "enter",
            "restore",
            "unquiesce",
            "thaw",
            "record admit state=0x2 blockers=0 reason=0x0",
        ]);
        assert!(s.records().iter().all(|(subject, _)| *subject == DOMAIN), "every record is about the caller's domain");
    }

    /// A step that fails undoes the ones before it, newest first, and the
    /// refusal is recorded; nothing after the failing step runs.
    #[test]
    fn a_freeze_that_fails_undoes_nothing_and_stops() {
        let s = Script { freeze: Err(()), ..Script::working() };
        let o = run_script(&s);
        assert_eq!(o, Outcome::Refused(Refusal { reason: Reason::FreezeFailed, blockers: 0, detail: 0 }));
        assert_eq!(s.log(), [
            "record admit state=0x1 blockers=0 reason=0x0",
            "freeze",
            "record refuse state=0x1 blockers=0 reason=0x7",
        ]);
    }

    #[test]
    fn a_device_that_will_not_go_down_thaws_and_counts_the_blockers() {
        let s = Script { quiesce: Err(2), ..Script::working() };
        let o = run_script(&s);
        assert_eq!(o, Outcome::Refused(Refusal { reason: Reason::DeviceBusy, blockers: 2, detail: 0 }));
        assert_eq!(o.code(), Reason::DeviceBusy.code());
        assert_eq!(s.log(), [
            "record admit state=0x1 blockers=0 reason=0x0",
            "freeze",
            "quiesce",
            "thaw",
            "record refuse state=0x1 blockers=2 reason=0x8",
        ]);
    }

    #[test]
    fn a_save_that_fails_brings_the_devices_and_the_tasks_back() {
        let s = Script { save: Err(()), ..Script::working() };
        assert_eq!(run_script(&s), Outcome::Refused(Refusal { reason: Reason::SaveFailed, blockers: 0, detail: 0 }));
        assert_eq!(s.log(), [
            "record admit state=0x1 blockers=0 reason=0x0",
            "freeze",
            "quiesce",
            "save",
            "unquiesce",
            "thaw",
            "record refuse state=0x1 blockers=0 reason=0x9",
        ]);
    }

    /// The firmware answers with an error instead of suspending: nothing
    /// slept, so everything is undone, the boot offset is not touched, and
    /// the firmware's code is in the record.
    #[test]
    fn a_firmware_that_refuses_is_undone_in_full_and_its_code_recorded() {
        let s = Script { enter: Err(-3), ..Script::working() };
        let o = run_script(&s);
        assert_eq!(o, Outcome::Refused(Refusal { reason: Reason::EnterFailed, blockers: 0, detail: -3 }));
        let reason = Reason::EnterFailed.code() as u64 | (-3i32 as u32 as u64) << 8;
        assert_eq!(s.log(), [
            "record admit state=0x1 blockers=0 reason=0x0".to_string(),
            "freeze".into(),
            "quiesce".into(),
            "save".into(),
            "enter".into(),
            "restore".into(),
            "unquiesce".into(),
            "thaw".into(),
            format!("record refuse state=0x1 blockers=0 reason={reason:#x}"),
        ]);
        assert!(s.boot_added.lock().unwrap().is_empty());
    }

    /// A device that does not come back is counted in the resume record; the
    /// rest of the way up still runs.
    #[test]
    fn a_device_that_does_not_come_back_is_counted_and_the_rest_resumes() {
        let s = Script { unquiesce_failed: 1, ..Script::working() };
        assert_eq!(run_script(&s), Outcome::Resumed { slept_ns: 0, unresumed: 1 });
        let log = s.log();
        assert_eq!(&log[5..], [
            "restore",
            "unquiesce",
            "thaw",
            "record admit state=0x2 blockers=1 reason=0x0",
        ]);
    }
}

mod gates {
    use super::*;

    fn refused(s: &Script, reason: Reason, blockers: u32) {
        assert_eq!(run_script(s), Outcome::Refused(Refusal { reason, blockers, detail: 0 }), "{reason:?}");
        // One record, the refusal; no step ran.
        let log = s.log();
        assert_eq!(log.len(), 1, "{log:?}");
        assert_eq!(
            log[0],
            format!("record refuse state=0x1 blockers={blockers} reason={:#x}", reason.code()),
        );
    }

    /// The robot, industrial and automotive images do not have the option
    /// (Kconfig `SYSTEM_SUSPEND` depends on the preset): the platform says so
    /// and the suspend is refused with a record, before the firmware is asked
    /// anything and before any task or device is touched.
    #[test]
    fn a_build_without_the_option_refuses_and_touches_nothing() {
        refused(&Script { enabled: false, ..Script::working() }, Reason::Disabled, 0);
    }

    /// The build's own refusal is the first thing asked: a robot image is
    /// refused as `Disabled` whatever else is wrong with it, so the record
    /// never says "no firmware" about a machine that was not allowed to try.
    #[test]
    fn the_refusal_comes_first_whatever_else_is_missing() {
        let s = Script { enabled: false, support: Err(Reason::NoFirmware), cpus: 4, wake: 0, ..Script::working() };
        refused(&s, Reason::Disabled, 0);
    }

    #[test]
    fn a_machine_that_cannot_suspend_says_why() {
        for why in [Reason::NoFirmware, Reason::NoResumeEntry, Reason::NoAcpiS3, Reason::NoFreezer] {
            refused(&Script { support: Err(why), ..Script::working() }, why, 0);
        }
    }

    /// Both firmware calls need every other CPU off; the kernel cannot take
    /// one off, so a second CPU online refuses, with the count of them.
    #[test]
    fn a_second_cpu_online_refuses_before_anything_is_touched() {
        refused(&Script { cpus: 2, ..Script::working() }, Reason::CpusOnline, 1);
        refused(&Script { cpus: 8, ..Script::working() }, Reason::CpusOnline, 7);
        // The caller's own CPU is the one that stays.
        assert!(matches!(run_script(&Script::working()), Outcome::Resumed { .. }));
    }

    /// Wake sources are capabilities: a caller that holds none cannot have the
    /// machine woken by anything it controls, so the suspend would be a
    /// shutdown.
    #[test]
    fn a_caller_without_a_wake_source_is_refused() {
        refused(&Script { wake: 0, ..Script::working() }, Reason::NoWakeSource, 1);
    }

    /// A system power assertion is a task's claim that the machine stays
    /// awake: the suspend is refused before anything is touched, with the
    /// live assertions as the blockers, and goes ahead once none is live.
    ///
    /// **Canary.** Drop the `held > 0` gate in `suspend::run`: red.
    #[test]
    fn a_live_power_assertion_refuses_before_anything_is_touched() {
        refused(&Script { assertions: 1, ..Script::working() }, Reason::Asserted, 1);
        refused(&Script { assertions: 3, ..Script::working() }, Reason::Asserted, 3);
        // Before the CPU gate: an assertion is the answer even with other CPUs up.
        refused(&Script { assertions: 2, cpus: 4, ..Script::working() }, Reason::Asserted, 2);
        assert!(matches!(run_script(&Script::working()), Outcome::Resumed { .. }));
    }

    #[test]
    fn the_reason_codes_are_the_record_format() {
        for code in 1..=13u8 {
            let r = Reason::of(code).unwrap_or_else(|| panic!("code {code} has no reason"));
            assert_eq!(r.code(), code as u32);
            assert!(!r.name().is_empty());
        }
        assert_eq!(Reason::of(0), None);
        assert_eq!(Reason::of(14), None);
    }
}

mod boottime {
    use super::*;

    /// The counter stopped across the sleep: the persistent clock advanced
    /// 60 000 ms and the monotonic one 10, so 59 990 ms is the boot offset's.
    #[test]
    fn a_sleep_the_counter_did_not_count_reaches_the_boot_offset() {
        let s = Script::working().with_clocks(clocks(1_000, Some(5_000)), clocks(1_010, Some(65_000)));
        let o = run_script(&s);
        assert_eq!(o, Outcome::Resumed { slept_ns: 59_990 * MS, unresumed: 0 });
        assert_eq!(*s.boot_added.lock().unwrap(), [59_990 * MS]);
        // The boot offset is added before the resume record, which carries the
        // sleep in milliseconds above the state byte.
        let log = s.log();
        let (boot, rec) = (log.iter().position(|l| l == "boot").unwrap(), log.len() - 1);
        assert!(boot < rec);
        assert_eq!(s.records().last().unwrap().1.state, STATE_RESUME | 59_990 << 8);
    }

    /// The counter kept running: the monotonic clock counted the sleep, so
    /// BOOTTIME equals MONOTONIC and the offset is left alone.
    #[test]
    fn a_sleep_the_counter_counted_adds_nothing() {
        let s = Script::working().with_clocks(clocks(1_000, Some(5_000)), clocks(61_000, Some(65_000)));
        assert_eq!(run_script(&s), Outcome::Resumed { slept_ns: 0, unresumed: 0 });
        assert!(s.boot_added.lock().unwrap().is_empty());
    }

    /// No clock that kept running: the sleep is unknown, and an unknown sleep
    /// is not invented from the monotonic clock.
    #[test]
    fn without_a_persistent_clock_nothing_is_invented() {
        let s = Script::working().with_clocks(clocks(1_000, None), clocks(1_010, None));
        assert_eq!(run_script(&s), Outcome::Resumed { slept_ns: 0, unresumed: 0 });
        assert!(s.boot_added.lock().unwrap().is_empty());
        // A clock on one side only is as good as none.
        let s = Script::working().with_clocks(clocks(1_000, Some(5)), clocks(1_010, None));
        assert_eq!(run_script(&s), Outcome::Resumed { slept_ns: 0, unresumed: 0 });
    }

    #[test]
    fn the_delta_saturates_both_ways() {
        // The persistent clock behind the monotonic one (a wrong RTC): 0.
        assert_eq!(slept_ns(clocks(0, Some(100)), clocks(50, Some(120))), 0);
        // The persistent clock stepped back: 0, not a wrap.
        assert_eq!(slept_ns(clocks(0, Some(100)), clocks(0, Some(10))), 0);
        // The monotonic clock behind where it started (a counter reset).
        assert_eq!(slept_ns(clocks(500, Some(0)), clocks(10, Some(70))), 70 * MS);
        // No overflow at the top of the range.
        let big = Clocks { mono_ns: 0, persistent_ns: Some(u64::MAX) };
        assert_eq!(slept_ns(Clocks { persistent_ns: Some(0), ..big }, big), u64::MAX);
    }
}

/// `Rule::Suspend` through the real decision ring and the installed platform
/// (`pm::pm_suspend`). One test: the platform slot is process-wide and is
/// installed once, so the phases run in order.
mod records {
    use super::*;
    use azos_decision::{Rule, Verdict as DVerdict};

    /// The platform the kernel would install: shared state behind a mutex, the
    /// answers set by the test between calls.
    struct Shared {
        reason: Mutex<Option<Reason>>,
        reenter: Mutex<Option<u32>>,
    }

    impl Platform for Shared {
        fn enabled(&self) -> bool {
            true
        }
        fn support(&self) -> Result<(), Reason> {
            self.reason.lock().unwrap().map_or(Ok(()), Err)
        }
        fn assertions(&self) -> u32 {
            0
        }
        fn online_cpus(&self) -> u32 {
            1
        }
        fn wake_sources(&self, _caller: u32) -> u32 {
            1
        }
        fn freeze(&self) -> Result<(), ()> {
            Ok(())
        }
        fn thaw(&self) {}
        fn quiesce(&self) -> Result<(), u32> {
            // A second suspend asked while this one runs.
            if let Some(subject) = *self.reenter.lock().unwrap() {
                let code = pm::pm_suspend(1, subject);
                assert_eq!(code, Reason::InProgress.code());
            }
            Ok(())
        }
        fn unquiesce(&self) -> u32 {
            0
        }
        fn save(&self) -> Result<(), ()> {
            Ok(())
        }
        fn restore(&self) {}
        fn enter(&self) -> Result<(), i32> {
            Ok(())
        }
        fn clocks(&self) -> Clocks {
            clocks(0, None)
        }
        fn add_boot_ns(&self, _ns: u64) {}
        fn record(&self, subject: u32, r: Record) {
            pm::record(subject, &r);
        }
    }

    static SHARED: Shared = Shared { reason: Mutex::new(None), reenter: Mutex::new(None) };

    /// The suspend records of `subject`, oldest first: (verdict, state, blockers, reason).
    fn about(subject: u32) -> Vec<(u8, u64, u64, u64)> {
        let mut out = Vec::new();
        azos_decision::for_each(|r| {
            if r.rule == Rule::Suspend as u8 && r.subject == subject {
                out.push((r.verdict, r.n[0], r.n[1], r.n[2]));
            }
        });
        out
    }

    const ADMIT: u8 = DVerdict::Admit as u8;
    const REFUSE: u8 = DVerdict::Refuse as u8;

    #[test]
    fn suspend_is_recorded_both_ways_refused_and_guarded() {
        // Phase 1: a build with no platform (a robot image) refuses and records.
        const NONE: u32 = 0xA001;
        assert_eq!(pm::pm_suspend(1, NONE), Reason::Disabled.code());
        assert_eq!(about(NONE), [(REFUSE, STATE_ENTER, 0, Reason::Disabled.code() as u64)]);

        // Phase 2: the platform is installed (once; a second install is ignored).
        pm::install(&SHARED);
        pm::install(&SHARED);

        // A suspend that works: Admit going down, Admit coming back.
        const OK: u32 = 0xA002;
        assert_eq!(pm::pm_suspend(1, OK), 0);
        assert_eq!(about(OK), [(ADMIT, STATE_ENTER, 0, 0), (ADMIT, STATE_RESUME, 0, 0)]);

        // A refusal names its reason in the third number.
        const NO: u32 = 0xA003;
        *SHARED.reason.lock().unwrap() = Some(Reason::NoResumeEntry);
        assert_eq!(pm::pm_suspend(1, NO), Reason::NoResumeEntry.code());
        assert_eq!(about(NO), [(REFUSE, STATE_ENTER, 0, Reason::NoResumeEntry.code() as u64)]);
        *SHARED.reason.lock().unwrap() = None;

        // A suspend asked while another runs is refused, not queued, and the
        // first one is not disturbed.
        const BUSY: u32 = 0xA004;
        *SHARED.reenter.lock().unwrap() = Some(BUSY);
        assert_eq!(pm::pm_suspend(1, 0xA005), 0);
        *SHARED.reenter.lock().unwrap() = None;
        assert_eq!(about(BUSY), [(REFUSE, STATE_ENTER, 0, Reason::InProgress.code() as u64)]);
        assert_eq!(about(0xA005), [(ADMIT, STATE_ENTER, 0, 0), (ADMIT, STATE_RESUME, 0, 0)]);

        // And the guard is released: the next one runs.
        assert_eq!(pm::pm_suspend(1, 0xA006), 0);
    }

    /// The rule's table says what the three numbers are, so the record reads
    /// back the way the console prints it.
    #[test]
    fn the_rule_names_the_numbers_the_sequence_writes() {
        let info = &azos_decision::RULES[Rule::Suspend as usize];
        assert_eq!(info.name, "suspend");
        assert_eq!(info.fields, ["state", "blockers", "reason"]);
    }
}

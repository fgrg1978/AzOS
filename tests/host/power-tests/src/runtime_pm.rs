// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The power service's side of device runtime PM, and the `once_only` ops of
//! `Power`.
//!
//! * `devices.rs` of the service (pulled in by path, so the code under test is
//!   the code `POWER.ELF` is built from) driven against a device whose
//!   behaviour is the real one: `azos_devif::power::runtime::RuntimePm` behind
//!   `PmServer`, the same pair a ring-3 driver serves. The state machine's own
//!   cases are `tests/host/devif-tests/tests/runtime_pm.rs`.
//! * the INA219 driver's request path (`userspace/drivers/ina_drv/src/request.rs`,
//!   pulled in by path too): a request is answered after the use, and a chip
//!   that cannot be resumed never answers with the sample from before its
//!   pause.
//! * `shutdown` and `reboot`: irreversible, so `once_only`, so no layer that
//!   decides resends from the op table sends them twice.

#[allow(dead_code)]
#[path = "../../../../userspace/services/power/src/devices.rs"]
pub mod devices;

#[allow(dead_code)]
#[path = "../../../../userspace/drivers/ina_drv/src/request.rs"]
pub mod request;

use crate::policy::Preset;
use azos_devif::power::runtime::{Event, PmDevice, PmServer, Quota, RuntimePm, CLASS_ALL, RECORDS};
use azos_devif::power::{DevicePower, PM_STAT_RECORDED};
use devices::{idle_ms, Change, Class, DeviceLink, Spec, Tracked, DEVICES};
use std::cell::RefCell;

const fn ms(n: u64) -> u64 {
    n * 1_000_000
}

#[derive(Default)]
struct Chip {
    suspends: u32,
}

impl PmDevice for Chip {
    fn suspend(&mut self) -> bool {
        self.suspends += 1;
        true
    }
    fn resume(&mut self) -> bool {
        true
    }
}

/// A driver as the service sees it: the real core behind the real server,
/// at a clock the test moves. `up: false` is a driver that does not answer.
struct Sim {
    pm: RefCell<RuntimePm>,
    chip: RefCell<Chip>,
    now_ns: u64,
    up: bool,
}

impl Sim {
    fn new() -> Sim {
        Sim { pm: RefCell::new(RuntimePm::new(Quota::new(4, 60_000), 0)), chip: RefCell::default(), now_ns: 0, up: true }
    }
    /// The driver's own loop: time passes and the idle clock is looked at.
    fn advance(&mut self, to_ms: u64) {
        self.now_ns = ms(to_ms);
        let now = self.now_ns;
        self.pm.borrow_mut().tick(&mut *self.chip.borrow_mut(), now);
    }
    /// The driver restarted: a new core, nothing remembered.
    fn restart(&mut self) {
        self.pm = RefCell::new(RuntimePm::new(Quota::new(4, 60_000), self.now_ns));
    }
}

impl DeviceLink for Sim {
    fn stats(&self, sel: u32) -> Option<u64> {
        if !self.up {
            return None;
        }
        let mut pm = self.pm.borrow_mut();
        let mut chip = self.chip.borrow_mut();
        let srv = PmServer { pm: &mut pm, dev: &mut *chip, now_ns: self.now_ns, classes: CLASS_ALL };
        let o = srv.stats(sel);
        o.is_ok().then_some(o.value)
    }
    fn set_idle_timeout(&mut self, ms: u32) -> bool {
        if !self.up {
            return false;
        }
        let mut pm = self.pm.borrow_mut();
        let mut chip = self.chip.borrow_mut();
        let mut srv = PmServer { pm: &mut pm, dev: &mut *chip, now_ns: self.now_ns, classes: CLASS_ALL };
        srv.set_idle_timeout(ms).is_ok()
    }
}

fn look(t: &mut Tracked, spec: &Spec, sim: &mut Sim, p: Preset) -> Vec<Change> {
    let mut v = Vec::new();
    t.poll(sim, idle_ms(p, spec.class), &mut |c| v.push(c));
    v
}

fn io() -> Spec {
    *DEVICES.iter().find(|d| d.class == Class::Io).unwrap()
}

fn monitor() -> Spec {
    *DEVICES.iter().find(|d| d.class == Class::Monitor).unwrap()
}

/// The table of timeouts is the policy: nothing autosuspends under
/// `performance`, the I/O controller does under the other two, and the battery
/// monitor (it feeds the failsafe levels) only under `endurance`.
///
/// **Canary.** Give `(Balanced, Monitor)` a timeout: the pin goes red.
#[test]
fn the_idle_timeout_follows_the_preset() {
    for c in [Class::Io, Class::Monitor] {
        assert_eq!(idle_ms(Preset::Performance, c), 0);
    }
    assert_eq!(idle_ms(Preset::Balanced, Class::Io), 5_000);
    assert_eq!(idle_ms(Preset::Balanced, Class::Monitor), 0);
    assert_eq!(idle_ms(Preset::Endurance, Class::Io), 1_000);
    assert_eq!(idle_ms(Preset::Endurance, Class::Monitor), 15_000);
    // Endurance suspends an I/O controller no later than balanced does.
    assert!(idle_ms(Preset::Endurance, Class::Io) <= idle_ms(Preset::Balanced, Class::Io));
    assert_eq!(DEVICES.len(), 2);
}

/// The preset's timeout is applied once, and again when the preset moves.
///
/// **Canary.** Apply on every look (drop the `applied_ms` test): the second
/// look reports `Applied` again and goes red.
#[test]
fn the_timeout_is_applied_once_and_follows_the_preset() {
    let mut sim = Sim::new();
    let mut t = Tracked::new();
    assert_eq!(look(&mut t, &io(), &mut sim, Preset::Balanced), vec![Change::Applied(5_000)]);
    assert_eq!(sim.pm.borrow().idle_timeout_ms(), 5_000);
    assert_eq!(look(&mut t, &io(), &mut sim, Preset::Balanced), vec![]);
    assert_eq!(look(&mut t, &io(), &mut sim, Preset::Endurance), vec![Change::Applied(1_000)]);
    assert_eq!(look(&mut t, &io(), &mut sim, Preset::Performance), vec![Change::Applied(0)]);
    assert_eq!(sim.pm.borrow().idle_timeout_ms(), 0);
}

/// The whole loop: the service sets the timeout, the device is left alone and
/// suspends itself, and the service reads the record of it, once.
///
/// **Canary.** Skip the record read: the `AutoSuspend` assertion goes red.
#[test]
fn the_service_sees_a_device_autosuspend() {
    let mut sim = Sim::new();
    let mut t = Tracked::new();
    look(&mut t, &io(), &mut sim, Preset::Endurance);
    sim.advance(999);
    assert_eq!(look(&mut t, &io(), &mut sim, Preset::Endurance), vec![]);
    sim.advance(1_000);
    assert!(sim.pm.borrow().is_suspended());
    assert_eq!(sim.chip.borrow().suspends, 1);
    let seen = look(&mut t, &io(), &mut sim, Preset::Endurance);
    assert_eq!(seen, vec![Change::Record { t_ms: 1_000, event: Event::AutoSuspend, arg: 0 }]);
    assert_eq!(look(&mut t, &io(), &mut sim, Preset::Endurance), vec![], "each record once");
}

/// Wakelocks of a device are logged in the order they happened, whatever the
/// service was doing meanwhile: grant, refusal (quota), release, lapse.
///
/// **Canary.** Read the records newest first: the order goes red.
#[test]
fn records_come_oldest_first_and_once() {
    let mut sim = Sim::new();
    *sim.pm.borrow_mut() = RuntimePm::new(Quota::new(1, 60_000), 0);
    let mut t = Tracked::new();
    look(&mut t, &io(), &mut sim, Preset::Performance);
    let (a, refused) = {
        let mut pm = sim.pm.borrow_mut();
        let a = pm.hold(ms(10), 100).unwrap();
        let r = pm.hold(ms(20), 5).is_err();
        (a, r)
    };
    assert!(refused);
    sim.advance(200);
    let seen = look(&mut t, &io(), &mut sim, Preset::Performance);
    assert_eq!(
        seen,
        vec![
            Change::Record { t_ms: 10, event: Event::Grant, arg: a },
            Change::Record { t_ms: 20, event: Event::Refuse, arg: 5 },
            Change::Record { t_ms: 110, event: Event::Lapse, arg: a },
        ]
    );
}

/// A ring the driver overwrote before the service looked is reported as lost,
/// not silently shortened.
///
/// **Canary.** Drop the `Lost` report: the count assertion goes red.
#[test]
fn overwritten_records_are_counted() {
    let mut sim = Sim::new();
    let mut t = Tracked::new();
    look(&mut t, &io(), &mut sim, Preset::Performance);
    for i in 0..(RECORDS as u32 + 4) {
        let mut pm = sim.pm.borrow_mut();
        let id = pm.hold(ms(i as u64), 10).unwrap();
        let _ = pm.release(ms(i as u64), id);
    }
    let recorded = sim.stats(PM_STAT_RECORDED).unwrap() as usize;
    let seen = look(&mut t, &io(), &mut sim, Preset::Performance);
    assert_eq!(seen[0], Change::Lost((recorded - RECORDS) as u32));
    assert_eq!(seen.len(), 1 + RECORDS);
    assert!(matches!(seen[RECORDS], Change::Record { event: Event::Release, .. }), "the newest last");
}

/// A driver that does not answer is reported once; when it comes back its
/// timeout is applied.
///
/// **Canary.** Report on every look: the second look goes red.
#[test]
fn an_unreachable_device_is_reported_once() {
    let mut sim = Sim::new();
    sim.up = false;
    let mut t = Tracked::new();
    assert_eq!(look(&mut t, &monitor(), &mut sim, Preset::Endurance), vec![Change::Unreachable]);
    assert_eq!(look(&mut t, &monitor(), &mut sim, Preset::Endurance), vec![]);
    sim.up = true;
    assert_eq!(look(&mut t, &monitor(), &mut sim, Preset::Endurance), vec![Change::Applied(15_000)]);
}

/// A driver that restarted lost its timeout: the service notices the counters
/// went back and applies it again.
///
/// **Canary.** Keep `applied_ms` across a restart: the device stays at 0 and
/// the last assertion goes red.
#[test]
fn a_restarted_driver_gets_its_timeout_again() {
    let mut sim = Sim::new();
    let mut t = Tracked::new();
    look(&mut t, &io(), &mut sim, Preset::Balanced);
    sim.pm.borrow_mut().hold(ms(1), 10).unwrap();
    look(&mut t, &io(), &mut sim, Preset::Balanced);
    sim.restart();
    assert_eq!(sim.pm.borrow().idle_timeout_ms(), 0);
    let seen = look(&mut t, &io(), &mut sim, Preset::Balanced);
    assert_eq!(seen, vec![Change::Restarted, Change::Applied(5_000)]);
    assert_eq!(sim.pm.borrow().idle_timeout_ms(), 5_000);
}

// --- once_only -------------------------------------------------------------

mod once_only {
    use azos_devif::{IdlError, MsgDesc, PowerCall, PowerClient, PowerIdl, Transport};
    use azos_idl::{header_op, Delivery, OnFailure};
    use std::cell::Cell;

    /// `shutdown` and `reboot` are the only `once_only` ops of the interface,
    /// and each says what happens when the service fails.
    ///
    /// **Canary.** Remove `#[once_only]` from `shutdown`: the first assertion
    /// goes red.
    #[test]
    fn shutdown_and_reboot_are_the_once_only_ops() {
        for o in PowerIdl::OPS {
            let irreversible = o.name == "shutdown" || o.name == "reboot";
            assert_eq!(o.once_only(), irreversible, "{}", o.name);
            if irreversible {
                assert_eq!(o.delivery(), Some(Delivery::OnceOnly));
                assert_eq!(o.on_failure, Some(OnFailure::Escalate), "{}", o.name);
            }
        }
        // `suspend` returns after the resume and is not irreversible.
        assert!(PowerIdl::OPS.iter().find(|o| o.name == "suspend").is_some_and(|o| !o.once_only()));
    }

    /// A layer that resends on a lost answer, deciding from the op table the
    /// way `userspace/lib/rpc` does: every op but `once_only` ones is sent
    /// again, up to three times.
    struct Resending<'a> {
        sent: &'a Cell<u32>,
    }

    impl Transport for Resending<'_> {
        fn call(&self, msg: &mut MsgDesc) -> azos_idl::Result {
            let op = header_op(msg.words[0]) as usize;
            let info = &PowerIdl::OPS[op - 1];
            let attempts = if info.once_only() { 1 } else { 3 };
            for _ in 0..attempts {
                self.sent.set(self.sent.get() + 1);
                // The answer is lost every time.
            }
            Err(IdlError::Transport(-110))
        }
    }

    /// The answer to a power-off is lost: the call crossed once, and the caller
    /// is told it failed without a second try. A reader in the same situation
    /// is sent again.
    ///
    /// **Canary.** Remove `#[once_only]` from `reboot`: its count is 3 and the
    /// assertion goes red.
    #[test]
    fn a_lost_shutdown_is_never_sent_twice() {
        let sent = Cell::new(0);
        let mut c = PowerClient::new(Resending { sent: &sent });
        assert!(c.shutdown().is_err());
        assert_eq!(sent.get(), 1, "shutdown");
        assert!(c.reboot().is_err());
        assert_eq!(sent.get(), 2, "reboot");
        sent.set(0);
        assert!(c.state(0).is_err());
        assert_eq!(sent.get(), 3, "an idempotent reader is resent");
    }
}

// --- the INA219 driver's request path ----------------------------------------

/// The monitor of `ina_drv` with its chip replaced by a counter: the real
/// `RuntimePm` decides suspend and resume, `sample` stands for the chip's
/// register file (the value a read answers with).
struct Monitor {
    pm: RuntimePm,
    chip: Switch,
    now_ns: u64,
    /// The sample the logic would answer with now.
    sample: u32,
    /// What the next fresh measurement reads.
    next: u32,
}

struct Switch {
    on: bool,
    fail_resume: bool,
}

impl PmDevice for Switch {
    fn suspend(&mut self) -> bool {
        self.on = false;
        true
    }
    fn resume(&mut self) -> bool {
        if self.fail_resume {
            return false;
        }
        self.on = true;
        true
    }
}

impl request::Unit for Monitor {
    fn begin(&mut self) -> Option<bool> {
        let was = self.pm.is_suspended();
        self.pm.on_use(&mut self.chip, self.now_ns).ok().map(|()| was)
    }
    fn woke(&mut self) {
        self.sample = self.next;
    }
    fn serve(&self, req: &request::DriverRequest) -> request::DriverReply {
        let mut r = request::DriverReply::empty(req, request::STATUS_OK);
        r.output[..4].copy_from_slice(&self.sample.to_le_bytes());
        r.out_len = 4;
        r
    }
    fn done(&mut self) {
        self.pm.idle(self.now_ns);
    }
}

fn monitor_at_rest() -> Monitor {
    let mut m = Monitor {
        pm: RuntimePm::new(Quota::new(4, 60_000), 0),
        chip: Switch { on: true, fail_resume: false },
        now_ns: 0,
        sample: 111,
        next: 222,
    };
    m.pm.set_idle_timeout_ms(100).unwrap();
    m.now_ns = ms(500);
    m.pm.tick(&mut m.chip, m.now_ns);
    assert!(m.pm.is_suspended() && !m.chip.on, "the idle timeout powered the chip down");
    m
}

fn req() -> request::DriverRequest {
    request::DriverRequest { token: 7, client_tid: 1, op: 0, in_len: 0, out_cap: 64, input: [0; 64] }
}

/// A read after a pause answers the sample taken after the resume, not the one
/// from before it. Canary: calling `serve` before `woke` in `request::answer`
/// turns this red.
#[test]
fn a_read_after_a_pause_answers_a_fresh_sample() {
    let mut m = monitor_at_rest();
    let r = request::answer(&mut m, &req());
    assert_eq!(r.status, request::STATUS_OK);
    assert_eq!(&r.output[..4], &222u32.to_le_bytes(), "the sample of after the resume");
    assert!(!m.pm.is_suspended() && m.chip.on);
}

/// A chip that cannot be resumed answers the failure status and no data, never
/// the stale pre-suspend sample, and stays suspended. Canary: answering from
/// `serve` when `begin` returned `None` turns this red.
#[test]
fn a_chip_that_cannot_resume_answers_a_failure() {
    let mut m = monitor_at_rest();
    m.chip.fail_resume = true;
    let r = request::answer(&mut m, &req());
    assert_eq!(r.status, request::STATUS_BAD_OP);
    assert_eq!(r.out_len, 0, "no data");
    assert_eq!(r.token, 7, "the reply is still the request's");
    assert_eq!(r.output, [0; 64], "the sample from before the pause is not served");
    assert!(m.pm.is_suspended(), "it stays suspended");
    assert_eq!(m.pm.counters.callback_fails, 1);
    // The next use tries again, and the chip is back.
    m.chip.fail_resume = false;
    let r = request::answer(&mut m, &req());
    assert_eq!((r.status, &r.output[..4]), (request::STATUS_OK, &222u32.to_le_bytes()[..]));
}

/// A running chip is answered from the sample it holds and its idle clock
/// restarts.
#[test]
fn a_running_chip_is_answered_from_its_sample() {
    let mut m = monitor_at_rest();
    m.pm.resume(&mut m.chip, m.now_ns).unwrap();
    m.sample = 333;
    m.now_ns = ms(550);
    let r = request::answer(&mut m, &req());
    assert_eq!(&r.output[..4], &333u32.to_le_bytes());
    m.now_ns = ms(620);
    m.pm.tick(&mut m.chip, m.now_ns);
    assert!(!m.pm.is_suspended(), "the use restarted the idle clock");
}

// ── Finding the endpoints by the key the rows stamp ──────────────────────

use azos_devif::power::runtime::{self as rt, CLASS_EXEC, CLASS_READ, CLASS_WRITE};

/// What `cap_seed` stamps on the calling grant of `endpoint.pm-<name>` with
/// `perms` (`CapPerms` bits).
fn stamped(name: &str, perms: u8) -> u32 {
    rt::grant_badge(&format!("{}{name}", rt::ENDPOINT_PREFIX), perms).unwrap()
}

/// Every tracked device is a device of the family and has its own key; a key
/// is the position in the family's table, so two devices never share one.
#[test]
fn every_tracked_device_has_its_own_key() {
    let keys: Vec<_> = DEVICES.iter().map(|d| rt::device_key(d.name).expect("a device of the family")).collect();
    let mut sorted = keys.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(sorted.len(), DEVICES.len());
    assert_eq!(DEVICES.len(), rt::DEVICES.len(), "the family and the service track the same devices");
    assert!(keys.iter().all(|k| *k != 0), "0 is no device");
}

/// The endpoint of each device is found by the key its grant carries, wherever
/// the topology's row order put it in the pool, and a capability that is
/// another interface's (the kernel-hosted `sensor.9`, badge 9; `power`, no
/// badge) or carries no class is nobody's.
///
/// **Canary.** Resolve by position instead of by key (take the held
/// capabilities in pool order): the reversed pool pairs the handles with the
/// wrong devices and this goes red.
#[test]
fn the_endpoints_are_found_by_key_whatever_their_pool_order() {
    let gpio = stamped("gpio", CLASS_EXEC);
    let ina = stamped("ina", CLASS_EXEC);
    // Pool: 3 is gpio's, 1 is ina's (the opposite of the device table), 0 is
    // `sensor.9`, 2 is `power` (unbadged) and 5 carries a key but no class.
    let pool = |i: u32| match i {
        0 => Some((10, 9)),
        1 => Some((11, ina)),
        2 => Some((12, 0)),
        3 => Some((13, gpio)),
        5 => Some((15, rt::device_key("gpio").unwrap() << rt::KEY_SHIFT)),
        _ => None,
    };
    let found = devices::resolve(pool);
    let at = |name| DEVICES.iter().position(|d| d.name == name).unwrap();
    assert_eq!(found[at("gpio")], Some(13));
    assert_eq!(found[at("ina")], Some(11));
    assert!(found[DEVICES.len()..].iter().all(|h| h.is_none()));
}

/// A device whose row is not granted (the INA219 placed in the kernel) is
/// absent, not mistaken for the other one.
#[test]
fn a_device_without_a_grant_is_absent() {
    let gpio = stamped("gpio", CLASS_EXEC);
    let found = devices::resolve(|i| (i == 4).then_some((14, gpio)));
    let at = |name| DEVICES.iter().position(|d| d.name == name).unwrap();
    assert_eq!(found[at("gpio")], Some(14));
    assert_eq!(found[at("ina")], None);
    assert_eq!(devices::resolve(|_| None), [None; devices::MAX_DEVICES]);
}

/// The power service holds the observe and control classes and nothing that
/// acts for a caller: through the server a driver runs, the badge its row's
/// grant is stamped with allows `stats` and `set_idle_timeout` and refuses a
/// wakelock (`hold`).
///
/// **Canary.** Stamp `CLASS_ALL` whatever the rights: `hold` is served and
/// this goes red.
#[test]
fn the_stamped_classes_allow_observing_and_controlling_but_not_holding() {
    let badge = stamped("gpio", CLASS_EXEC);
    assert_eq!(badge as u8, CLASS_READ | CLASS_EXEC);
    let mut pm = RuntimePm::new(Quota::new(4, 60_000), 0);
    let mut chip = Chip::default();
    let mut srv = PmServer { pm: &mut pm, dev: &mut chip, now_ns: 0, classes: badge as u8 };
    assert!(srv.stats(PM_STAT_RECORDED).is_ok());
    assert!(srv.set_idle_timeout(1_000).is_ok());
    let held = srv.hold(1_000);
    assert!(!held.is_ok(), "a wakelock is acting for a caller: the class is not carried");
    // And a grant that also carries WRITE is allowed it.
    let w = stamped("gpio", CLASS_EXEC | CLASS_WRITE);
    let mut srv = PmServer { pm: &mut pm, dev: &mut chip, now_ns: 0, classes: w as u8 };
    assert!(srv.hold(1_000).is_ok());
}

// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `POWER.ELF`: the power policy server, and the user shell's power tool.
//!
//! Policy is decided here and the kernel only enforces limits. The server
//! applies a profile (a built-in table per preset, `policy.rs`) through the
//! kernel's `Power` interface (`azos_devif`): one call per setter on the
//! `power` endpoint its topology row grants, found with `SYS_CAP_INFO`. The kernel answers each call with a verdict (applied, or
//! refused by a limit it keeps: the real-time deadline floor, the safety
//! path's WCET floor, the setters' hard ranges). A refusal is recorded by the
//! kernel; here it is logged and answered by the decision table
//! (`policy::fallback`). Without the capability the kernel still answers, and
//! refuses.
//!
//! `serve` also keeps the devices' runtime power (`devices.rs`): it applies the
//! preset's idle timeout to each ring-3 driver that serves `DevicePower`
//! (re-applying it to a driver that restarted) and logs the records each
//! driver kept: suspends, resumes, wakelocks granted, released, lapsed or
//! refused. A device whose endpoint the row does not grant is reported once
//! and left alone.
//!
//! Beyond the clock, `serve` decides the machine's budget (`policy::Budget`):
//! each domain's power cap (the kernel turns milliwatts into an OPP ceiling
//! through its model), the parked CPUs and the domains each QoS class may run
//! on. The kernel refuses what would break a floor (the deadline floor of an
//! admitted reservation, the WCET floor of the safety path, the last CPU of a
//! domain, CPU 0) and records the refusal; `policy::budget_fallback` is the
//! answer.
//!
//! The battery (`battery.rs`) is read from the monitor (`sensor.9`) each
//! period and turned into a charge; the topology's `[degrade.NAME]` rows
//! (`degrade.rs`, read back from the kernel) choose the degrade level for it,
//! with the rows' hysteresis. A level raises the preset to its floor, caps the
//! power (a share derived from the row's threshold and the kernel's reserve,
//! `policy::Levels`), parks the CPUs the share needs and shortens the devices'
//! idle timeouts (`policy::plan`, `devices::idle_ms_at`), and is reported to
//! the kernel with the charge: the
//! kernel records the change (`Rule::BatteryDegrade`) and holds its own
//! reserve (it takes the clocks to the lowest legal OPP at and below the
//! reserve, Kconfig `ENERGY_BATTERY_RESERVE_PCT`, whatever this server asks).
//! The kernel also ages this server's reports: one older than Kconfig
//! `ENERGY_BATTERY_REPORT_TIMEOUT_MS` holds the same reserve until the next
//! accepted report, so a stalled or restarted server is covered.
//!
//! The preset is the signed topology's `[energy] mode` (`performance`,
//! `balanced`, `endurance`), read from the kernel, unless one is named.
//!
//! Usage:
//!
//! * `power serve [PRESET]`: apply the profile, then stay resident and
//!   re-apply it when another client moved the policy. Logs every decision.
//! * `power apply [PRESET]`: apply once.
//! * `power state`: print the policy state, the battery and the statistics.
//! * `power devices`: print the runtime power of each tracked device.
//! * `power suspend | reboot | shutdown | sched_hz [HZ]`: the recovery
//!   console's commands as a client of the same capability.
//!
//! Exit 0 on success, 1 when the kernel refused or a call failed, 2 on a
//! usage error.

#![no_std]
#![no_main]
#![forbid(unsafe_code)]

mod battery;
mod degrade;
mod devices;
mod policy;

use azos_libsys as sys;
use sys::dev::PowerCall;
use azos_power::*;
use devices::{Change, DeviceLink, Spec, Tracked, DEVICES, MAX_DEVICES};
use policy::{Decision, Levels, Machine, Outcome, Preset, Step};

/// Milliseconds between two looks at the policy by `serve`.
const SERVE_PERIOD_MS: u64 = 2_000;

/// The kernel's `Power` interface through the endpoint the row grants: the
/// policy logic's [`PowerPolicy`] over the generated client stub.
struct Kernel {
    c: sys::dev::PowerClient<sys::dev::Ep>,
}

impl Kernel {
    fn new() -> Self {
        // No endpoint (a row without the grant): call handle 0, which no call
        // resolves; every op then answers `NO_SERVER`.
        let ep = sys::dev::lookup(sys::dev::key::POWER, 0).unwrap_or(0);
        Kernel { c: sys::dev::PowerClient::new(sys::dev::Ep(ep)) }
    }
}

/// A setter's answer as the verdict word the policy logic reads.
fn verdict(r: Result<sys::dev::Out<u32>, sys::dev::IdlError>) -> u32 {
    match r {
        Ok(o) => verdict_of(o.code, o.value),
        Err(_) => VERDICT_FAILED | sys::dev::outcome::NO_SERVER,
    }
}

/// A reader's answer as the word the policy logic reads.
fn word(r: Result<sys::dev::Out<u64>, sys::dev::IdlError>) -> u64 {
    match r {
        Ok(o) => word_of(o.code, o.value),
        Err(_) => WORD_ERR,
    }
}

impl PowerPolicy for Kernel {
    fn set_governor(&mut self, gov: u32) -> u32 {
        verdict(self.c.set_governor(gov))
    }
    fn set_opp_range(&mut self, domain: u32, min: u32, max: u32) -> u32 {
        verdict(self.c.set_opp_range(domain, min, max))
    }
    fn set_headroom(&mut self, pct: u32) -> u32 {
        verdict(self.c.set_headroom(pct))
    }
    fn set_rate_limit(&mut self, us: u32) -> u32 {
        verdict(self.c.set_rate_limit(us))
    }
    fn set_idle_depth(&mut self, depth: u32) -> u32 {
        verdict(self.c.set_idle_depth(depth))
    }
    fn set_power_cap(&mut self, domain: u32, mw: u32) -> u32 {
        verdict(self.c.set_power_cap(domain, mw))
    }
    fn set_parked(&mut self, mask: u32) -> u32 {
        verdict(self.c.set_parked(mask))
    }
    fn set_qos_domains(&mut self, class: u32, domains: u32) -> u32 {
        verdict(self.c.set_qos_domains(class, domains))
    }
    fn report_battery(&mut self, soc_pct: u32, level: u32) -> u32 {
        verdict(self.c.report_battery(soc_pct, level))
    }
    fn state(&self, sel: u32) -> u64 {
        word(self.c.state(sel))
    }
    fn stats(&self, sel: u32) -> u64 {
        word(self.c.stats(sel))
    }
}

/// One device's `DevicePower` through the endpoint its row grants; without
/// the grant every call answers nothing.
struct Device {
    c: Option<Client>,
}

type Client = sys::dev::power::DevicePowerClient<sys::dev::Ep>;

impl Device {
    fn new(handle: Option<u32>) -> Self {
        Device { c: handle.map(|h| sys::dev::power::DevicePowerClient::new(sys::dev::Ep(h))) }
    }
}

/// The tracked devices' endpoints, found once by the key their rows stamped
/// ([`devices::resolve`]): one look at the endpoint capabilities this task
/// holds, not one per period.
fn open_devices() -> [Device; MAX_DEVICES] {
    devices::resolve(|i| {
        let h = sys::cap_lookup(sys::ty::ENDPOINT.raw(), i);
        if h <= 0 {
            return None;
        }
        sys::cap_info(h as u32).ok().map(|info| (h as u32, info.badge))
    })
    .map(Device::new)
}

impl DeviceLink for Device {
    fn stats(&self, sel: u32) -> Option<u64> {
        sys::dev::value(sys::dev::power::DevicePowerCall::stats(self.c.as_ref()?, sel)).ok()
    }
    fn set_idle_timeout(&mut self, ms: u32) -> bool {
        self.c.as_mut().is_some_and(|c| sys::dev::succeeded(sys::dev::power::DevicePowerCall::set_idle_timeout(c, ms)))
    }
}

fn put(fd: u64, b: &[u8]) {
    let mut done = 0usize;
    while done < b.len() {
        let r = sys::write(fd, &b[done..]);
        if r <= 0 {
            return;
        }
        done += r as usize;
    }
}

fn put_num(fd: u64, neg: bool, mut v: u64) {
    let mut d = [0u8; 21];
    let mut i = d.len();
    loop {
        i -= 1;
        d[i] = b'0' + (v % 10) as u8;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    if neg {
        i -= 1;
        d[i] = b'-';
    }
    put(fd, &d[i..]);
}

fn parse(a: &[u8]) -> Option<u64> {
    if a.is_empty() || a.len() > 10 {
        return None;
    }
    let mut v = 0u64;
    for &b in a {
        if !b.is_ascii_digit() {
            return None;
        }
        v = v * 10 + (b - b'0') as u64;
    }
    Some(v)
}

fn usage() -> i32 {
    put(2, b"usage: power serve|apply [PRESET] | state | devices | cpu N online|offline | suspend | reboot | shutdown | sched_hz [HZ]\n");
    2
}

fn put_str(fd: u64, s: &str) {
    put(fd, s.as_bytes());
}

/// One decision, as a log line: `[power] set_opp_range d0 0..2 -> refused
/// (safety-floor) ...`.
fn log_decision(d: &Decision) {
    put(1, b"[power] ");
    if d.retry {
        put(1, b"  retry ");
    }
    match d.step {
        Step::Governor(g) => {
            put(1, b"set_governor ");
            put_num(1, false, g as u64);
        }
        Step::OppRange { domain, min, max } => {
            put(1, b"set_opp_range d");
            put_num(1, false, domain as u64);
            put(1, b" ");
            put_num(1, false, min as u64);
            put(1, b"..");
            put_num(1, false, max as u64);
        }
        Step::Headroom(h) => {
            put(1, b"set_headroom ");
            put_num(1, false, h as u64);
        }
        Step::RateLimit(r) => {
            put(1, b"set_rate_limit ");
            put_num(1, false, r as u64);
        }
        Step::IdleDepth(n) => {
            put(1, b"set_idle_depth ");
            put_num(1, false, n as u64);
        }
        Step::PowerCap { domain, mw } => {
            put(1, b"set_power_cap d");
            put_num(1, false, domain as u64);
            put(1, b" ");
            put_num(1, false, mw as u64);
            put(1, b" mW");
        }
        Step::Parked(mask) => {
            put(1, b"set_parked ");
            put_num(1, false, mask as u64);
        }
        Step::QosDomains { class, domains } => {
            put(1, b"set_qos_domains class ");
            put_num(1, false, class as u64);
            put(1, b" -> domains ");
            put_num(1, false, domains as u64);
        }
    }
    match d.verdict {
        Verdict::Applied => put(1, b" -> applied\n"),
        Verdict::Refused(why) => {
            put(1, b" -> refused (");
            put_str(1, refusal_name(why));
            put(1, b")\n");
        }
        Verdict::Failed(errno) => {
            put(1, b" -> failed, errno ");
            put_num(1, false, errno as u64);
            put(1, b"\n");
        }
    }
}

fn log_outcome(preset: Preset, level: u8, o: &Outcome) {
    put(1, b"[power] profile ");
    put_str(1, preset.name());
    if level != 0 {
        put(1, b" at degrade level ");
        put_num(1, false, level as u64);
    }
    if o.no_model {
        put(1, b": no energy model, nothing to govern\n");
        return;
    }
    put(1, b": applied ");
    put_num(1, false, o.applied as u64);
    put(1, b", refused ");
    put_num(1, false, o.refused as u64);
    put(1, b", fallbacks ");
    put_num(1, false, o.fallbacks as u64);
    put(1, if o.failed { b", FAILED\n" } else { b"\n" });
}

/// The preset named on the command line, else the kernel's mode.
fn preset_from(k: &Kernel, arg: Option<&[u8]>) -> Result<Preset, i32> {
    match arg {
        Some(name) => Preset::from_name(name).ok_or_else(|| {
            put(2, b"power: preset is performance, balanced or endurance\n");
            2
        }),
        None => Preset::from_mode(k.state(POLICY_STATE_MODE as u32)).ok_or_else(|| {
            put(2, b"power: the kernel reported no energy mode\n");
            1
        }),
    }
}

/// Apply the plan of `base` at degrade `level`, logging every call.
fn apply_plan(k: &mut Kernel, base: Preset, level: u8, levels: &Levels, machine: Option<&Machine>) -> Outcome {
    let (plan, o) = policy::apply_plan(k, base, level, levels, machine, &mut log_decision);
    log_outcome(plan.preset, level, &o);
    o
}

/// One look at every tracked device under `preset` at degrade `level`,
/// logging what changed.
fn poll_devices(tracked: &mut [Tracked; MAX_DEVICES], devs: &mut [Device; MAX_DEVICES], preset: Preset, level: u8) {
    for ((spec, t), dev) in DEVICES.iter().zip(tracked.iter_mut()).zip(devs.iter_mut()) {
        t.poll(dev, devices::idle_ms_at(preset, spec.class, level), &mut |c| log_change(spec, c));
    }
}

/// The power monitor's `sensor.9` endpoint (`SENSOR_TYPE_POWER`).
const SENSOR_POWER: u32 = 9;

/// The monitor's last sample; `None` when the row grants no `sensor.9`, the
/// monitor has nothing yet or the record is short.
fn read_sample() -> Option<battery::Sample> {
    let ep = sys::dev::lookup(sys::dev::key::SENSOR, SENSOR_POWER)?;
    let mut rec = [0u8; battery::RECORD_BYTES];
    let s = sys::dev::sensor_read(ep, &mut rec).ok()?;
    battery::Sample::parse(&rec[..(s.len as usize).min(rec.len())])
}

fn log_change(spec: &Spec, c: Change) {
    put(1, b"[power] ");
    put_str(1, spec.name);
    match c {
        Change::Unreachable => put(1, b": no DevicePower endpoint answers\n"),
        Change::Restarted => put(1, b": restarted; its idle timeout is lost\n"),
        Change::Applied(ms) => {
            put(1, b": idle timeout ");
            put_num(1, false, ms as u64);
            put(1, b" ms\n");
        }
        Change::Record { t_ms, event, arg } => {
            put(1, b": ");
            put_str(1, devices::event_name(event));
            put(1, b" arg ");
            put_num(1, false, arg as u64);
            put(1, b" at ");
            put_num(1, false, t_ms as u64);
            put(1, b" ms\n");
        }
        Change::Lost(n) => {
            put(1, b": ");
            put_num(1, false, n as u64);
            put(1, b" records overwritten unread\n");
        }
    }
}

/// One look at the battery (`degrade::watch` on the monitor's sample), logging
/// a refused report, each change of level and each edge of the kernel's
/// reserve (`reserve` remembers the last). The level to hold from now on.
fn watch_battery(
    k: &mut Kernel,
    rows: &degrade::Rows,
    est: &mut battery::Estimator,
    level: u8,
    reserve: &mut bool,
) -> u8 {
    let sample = if rows.rows().is_empty() { None } else { read_sample() };
    let w = degrade::watch(k, rows, est, level, sample);
    let (Some(soc), Some(verdict)) = (w.soc, w.verdict) else { return level };
    match verdict {
        Verdict::Applied => {}
        Verdict::Refused(why) => {
            put(1, b"[power] battery report refused (");
            put_str(1, refusal_name(why));
            put(1, b")\n");
            return level;
        }
        Verdict::Failed(_) => return level,
    }
    if w.level != level {
        put(1, b"[power] battery ");
        put_num(1, false, soc as u64);
        put(1, b"%: degrade level ");
        put_num(1, false, level as u64);
        put(1, b" -> ");
        put_num(1, false, w.level as u64);
        put(1, b"\n");
    }
    let held = k.state(POLICY_STATE_BATTERY as u32) >> 16 & 1 != 0;
    if held != *reserve {
        *reserve = held;
        put(1, if held {
            b"[power] the kernel holds the battery reserve: lowest legal clocks\n" as &[u8]
        } else {
            b"[power] the battery reserve is lifted\n"
        });
    }
    w.level
}

/// What each degrade level asks of the power, derived from the topology's
/// rows and the kernel's battery reserve (`policy::Levels`).
fn levels_of(k: &Kernel, rows: &degrade::Rows) -> Levels {
    let mut entries = [(0u8, 0u8); degrade::MAX_ROWS];
    for (e, r) in entries.iter_mut().zip(rows.rows()) {
        *e = (r.level, r.battery_pct);
    }
    let reserve = degrade::reserve_pct(k).unwrap_or(policy::RESERVE_UNKNOWN_PCT);
    Levels::derive(&entries[..rows.rows().len().min(entries.len())], reserve)
}

/// `power apply|serve [PRESET]`.
fn apply_cmd(serve: bool) -> i32 {
    if sys::arg(3).is_some() {
        return usage();
    }
    let mut k = Kernel::new();
    let preset = match preset_from(&k, sys::arg(2)) {
        Ok(p) => p,
        Err(code) => return code,
    };
    let machine = Machine::read(&k);
    let rows = degrade::Rows::load(&k).unwrap_or(degrade::Rows::NONE);
    let levels = levels_of(&k, &rows);
    let mut level = 0u8;
    let mut o = apply_plan(&mut k, preset, level, &levels, machine.as_ref());
    if o.failed {
        return 1;
    }
    if !serve {
        return 0;
    }
    let mut est = battery::Estimator::new();
    let mut reserve = false;
    let mut tracked = [Tracked::new(); MAX_DEVICES];
    let mut devs = open_devices();
    poll_devices(&mut tracked, &mut devs, policy::preset_at(preset, level), level);
    // Resident: the policy is whatever this server last applied. Another
    // client moving it (an operator, the shell) is re-applied over, once per
    // change, not once per period.
    let signatures = |k: &Kernel| (policy::signature(k), machine.as_ref().map(|m| policy::budget_signature(k, m)));
    let mut sig = signatures(&k);
    // A housekeeping loop nobody waits on: say so, and the kernel may fire its
    // period late to share another sleeper's wake-up (its row,
    // `timer_slack = true`, lets that apply where the product opts rows in).
    // A hint, not a request that can fail the server: the answer is ignored.
    let _ = sys::qos_hint(sys::QOS_BACKGROUND);
    loop {
        sys::sleep(SERVE_PERIOD_MS);
        // The battery first: a new level changes the plan the rest follows.
        let next = watch_battery(&mut k, &rows, &mut est, level, &mut reserve);
        if next != level {
            level = next;
            if !o.no_model {
                o = apply_plan(&mut k, preset, level, &levels, machine.as_ref());
                if o.failed {
                    return 1;
                }
                sig = signatures(&k);
            }
        }
        poll_devices(&mut tracked, &mut devs, policy::preset_at(preset, level), level);
        if o.no_model {
            // Nothing to govern, but the devices are still looked after.
            continue;
        }
        let now = signatures(&k);
        if now != sig {
            put(1, b"[power] the policy moved under us; re-applying\n");
            o = apply_plan(&mut k, preset, level, &levels, machine.as_ref());
            if o.failed {
                return 1;
            }
            sig = signatures(&k);
        }
    }
}

/// `power state`.
fn state_cmd() -> i32 {
    if sys::arg(2).is_some() {
        return usage();
    }
    let k = Kernel::new();
    let line = |name: &str, sel: u64, stats: bool| {
        let w = if stats { k.stats(sel as u32) } else { k.state(sel as u32) };
        put_str(1, name);
        if w == WORD_ERR {
            put(1, b" ?\n");
        } else {
            put(1, b" ");
            put_num(1, false, w);
            put(1, b"\n");
        }
        w != WORD_ERR
    };
    if !line("mode", POLICY_STATE_MODE, false) {
        put(2, b"power: the kernel refused or has no energy policy\n");
        return 1;
    }
    line("governor", POLICY_STATE_GOVERNOR, false);
    line("domains", POLICY_STATE_DOMAINS, false);
    line("headroom_pct", POLICY_STATE_HEADROOM, false);
    line("rate_limit_us", POLICY_STATE_RATE_LIMIT, false);
    line("idle_depth", POLICY_STATE_IDLE_DEPTH, false);
    line("parked", POLICY_STATE_PARKED, false);
    let battery_word = k.state(POLICY_STATE_BATTERY as u32);
    if battery_word != WORD_ERR {
        let soc = battery_word & 0xFF;
        put(1, b"battery_soc_pct ");
        if soc == POLICY_SOC_UNKNOWN as u64 {
            put(1, b"?");
        } else {
            put_num(1, false, soc);
        }
        put(1, b"\n");
        for (name, v) in [
            ("battery_level", battery_word >> 8 & 0xFF),
            ("battery_reserve_held", battery_word >> 16 & 1),
            ("battery_rows", battery_word >> 24 & 0xFF),
            ("battery_stale", battery_word >> 32 & 1),
            ("battery_reserve_pct", battery_word >> 40 & 0xFF),
        ] {
            put_str(1, name);
            put(1, b" ");
            put_num(1, false, v);
            put(1, b"\n");
        }
    }
    line("evals", POLICY_STATS_EVALS, true);
    line("changes", POLICY_STATS_CHANGES, true);
    line("applied", POLICY_STATS_APPLIED, true);
    line("refused", POLICY_STATS_REFUSED, true);
    line("floor_wins", POLICY_STATS_FLOOR_WINS, true);
    line("degrades", POLICY_STATS_DEGRADES, true);
    line("reserve_entries", POLICY_STATS_RESERVE_ENTRIES, true);
    line("stale_entries", POLICY_STATS_STALE_ENTRIES, true);
    0
}

/// `power devices`: each tracked device's state and counters.
fn devices_cmd() -> i32 {
    if sys::arg(2).is_some() {
        return usage();
    }
    let mut any = false;
    for (spec, dev) in DEVICES.iter().zip(open_devices().iter()) {
        let Some(c) = dev.c.as_ref() else {
            put_str(1, spec.name);
            put(1, b" unreachable\n");
            continue;
        };
        any = true;
        let state = sys::dev::value(sys::dev::power::DevicePowerCall::state(c));
        put_str(1, spec.name);
        put(1, match state {
            Ok(sys::dev::power::PM_ACTIVE) => b" active" as &[u8],
            Ok(_) => b" suspended",
            Err(_) => b" ?",
        });
        for (name, sel) in [
            ("idle_timeout_ms", sys::dev::power::PM_STAT_IDLE_TIMEOUT_MS),
            ("held", sys::dev::power::PM_STAT_HELD),
            ("suspends", sys::dev::power::PM_STAT_SUSPENDS),
            ("auto", sys::dev::power::PM_STAT_AUTO_SUSPENDS),
            ("resumes", sys::dev::power::PM_STAT_RESUMES),
            ("granted", sys::dev::power::PM_STAT_GRANTED),
            ("expired", sys::dev::power::PM_STAT_EXPIRED),
            ("refused", sys::dev::power::PM_STAT_REFUSED),
        ] {
            put(1, b" ");
            put_str(1, name);
            put(1, b"=");
            match dev.stats(sel) {
                Some(v) => put_num(1, false, v),
                None => put(1, b"?"),
            }
        }
        put(1, b"\n");
    }
    if any { 0 } else { 1 }
}

/// Report a refusal or an error and return the exit code: `what` was refused
/// with the interface's outcome `code` (`azos_devif::outcome`).
fn refused(what: &[u8], code: u32) -> i32 {
    put(2, b"power: ");
    put(2, what);
    put(2, b" refused: ");
    put_num(2, false, code as u64);
    put(2, b"\n");
    1
}

/// A `#[once_only]` op that did not come back served: a refusal is reported
/// as one, but `NO_SERVER` (no endpoint, or the call was lost) leaves the
/// outcome unknown, and the op is not sent again.
fn unanswered(what: &[u8], code: u32) -> i32 {
    if code != sys::dev::outcome::NO_SERVER {
        return refused(what, code);
    }
    put(2, b"power: ");
    put(2, what);
    put(2, b" got no answer: the outcome is unknown, not retried\n");
    1
}

/// An op that answers only the outcome: `Ok` when served.
fn served(r: Result<sys::dev::Out<()>, sys::dev::IdlError>) -> Result<(), u32> {
    match r {
        Ok(o) if o.is_ok() => Ok(()),
        Ok(o) => Err(o.code),
        Err(_) => Err(sys::dev::outcome::NO_SERVER),
    }
}

/// `power cpu N online|offline`: take CPU `N` offline or bring it back
/// (`Power::cpu_online`). A refusal carries the scheduler's reason code
/// (`azos_sched::smp::hart_set::HotplugReason`) and was recorded by the kernel.
fn cpu_cmd() -> i32 {
    let (Some(n), Some(dir)) = (sys::arg(2).and_then(parse), sys::arg(3)) else { return usage() };
    let on = match dir {
        b"online" => 1,
        b"offline" => 0,
        _ => return usage(),
    };
    if sys::arg(4).is_some() || n > u32::MAX as u64 {
        return usage();
    }
    let mut k = Kernel::new();
    match k.c.cpu_online(n as u32, on) {
        Ok(o) if o.is_ok() => {
            put(1, b"power: cpu ");
            put_num(1, false, n);
            put(1, if on == 1 { b" online, cpus online " } else { b" offline, tasks moved " });
            put_num(1, false, o.value as u64);
            put(1, b"\n");
            0
        }
        Ok(o) if o.code == sys::dev::outcome::REFUSED => {
            put(2, b"power: cpu change refused: reason ");
            put_num(2, false, o.value as u64);
            put(2, b"\n");
            1
        }
        Ok(o) => refused(b"cpu", o.code),
        Err(_) => refused(b"cpu", sys::dev::outcome::NO_SERVER),
    }
}

#[sys::main(panic_exit = 70)]
fn run() -> i32 {
    let op_name = sys::arg(1).unwrap_or(b"");
    match op_name {
        b"serve" => return apply_cmd(true),
        b"apply" => return apply_cmd(false),
        b"state" => return state_cmd(),
        b"devices" => return devices_cmd(),
        b"cpu" => return cpu_cmd(),
        b"suspend" | b"reboot" | b"shutdown" | b"sched_hz" => {}
        _ => return usage(),
    }
    let hz = match (op_name, sys::arg(2)) {
        (b"sched_hz", Some(a)) => match parse(a) {
            Some(hz) if (sys::power::POWER_SCHED_HZ_MIN..=sys::power::POWER_SCHED_HZ_MAX).contains(&hz) => Some(hz),
            _ => {
                put(2, b"power: sched_hz takes 10..10000\n");
                return 2;
            }
        },
        (_, Some(_)) => return usage(),
        (_, None) => None,
    };
    if sys::arg(3).is_some() {
        return usage();
    }
    // The endpoint 0 stands for when the row grants none: no call resolves
    // it, and the kernel refuses and records it.
    let mut k = Kernel::new();
    match (op_name, hz) {
        (b"suspend", _) => match k.c.suspend() {
            Ok(o) if o.is_ok() => put(1, b"power: resumed\n"),
            // A suspend the sequence refused carries its reason (`Reason::code`).
            Ok(o) if o.code == sys::dev::outcome::REFUSED => {
                put(2, b"power: suspend refused: reason ");
                put_num(2, false, o.value as u64);
                put(2, b"\n");
                return 1;
            }
            Ok(o) => return refused(op_name, o.code),
            Err(_) => return refused(op_name, sys::dev::outcome::NO_SERVER),
        },
        // `#[once_only]` ops: sent once. A served power-off does not answer, so
        // no answer is not a failure to retry, and nothing here sends it again.
        (b"reboot", _) => {
            if let Err(c) = served(k.c.reboot()) {
                return unanswered(op_name, c);
            }
        }
        (b"shutdown", _) => {
            if let Err(c) = served(k.c.shutdown()) {
                return unanswered(op_name, c);
            }
        }
        (_, Some(hz)) => match served(k.c.set_sched_hz(hz)) {
            Ok(()) => {
                put(1, b"sched_hz set ");
                put_num(1, false, hz);
                put(1, b"\n");
            }
            Err(c) => return refused(op_name, c),
        },
        (_, None) => match k.c.sched_hz() {
            Ok(o) if o.is_ok() => {
                put(1, b"sched_hz ");
                put_num(1, false, o.value);
                put(1, b"\n");
            }
            Ok(o) => return refused(op_name, o.code),
            Err(_) => return refused(op_name, sys::dev::outcome::NO_SERVER),
        },
    }
    0
}

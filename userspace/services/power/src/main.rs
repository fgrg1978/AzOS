// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `POWER.ELF`: the power policy server, and the user shell's power tool
//! (RFC-0055 S5).
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
//! The preset is the signed topology's `[energy] mode` (`performance`,
//! `balanced`, `endurance`), read from the kernel, unless one is named.
//!
//! Usage:
//!
//! * `power serve [PRESET]`: apply the profile, then stay resident and
//!   re-apply it when another client moved the policy. Logs every decision.
//! * `power apply [PRESET]`: apply once.
//! * `power state`: print the policy state and statistics.
//! * `power suspend | reboot | shutdown | sched_hz [HZ]`: the recovery
//!   console's commands as a client of the same capability.
//!
//! Exit 0 on success, 1 when the kernel refused or a call failed, 2 on a
//! usage error.

#![no_std]
#![no_main]

mod policy;

use azos_libsys as sys;
use sys::dev::PowerCall;
use azos_power::*;
use policy::{Decision, Outcome, Preset, Step};

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
    fn state(&self, sel: u32) -> u64 {
        word(self.c.state(sel))
    }
    fn stats(&self, sel: u32) -> u64 {
        word(self.c.stats(sel))
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
    put(2, b"usage: power serve|apply [PRESET] | state | suspend | reboot | shutdown | sched_hz [HZ]\n");
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

fn log_outcome(preset: Preset, o: &Outcome) {
    put(1, b"[power] profile ");
    put_str(1, preset.name());
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

fn apply_once(k: &mut Kernel, preset: Preset) -> Outcome {
    let o = policy::apply(k, &policy::profile(preset), &mut log_decision);
    log_outcome(preset, &o);
    o
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
    let mut o = apply_once(&mut k, preset);
    if o.failed {
        return 1;
    }
    if !serve || o.no_model {
        return 0;
    }
    // Resident: the policy is whatever this server last applied. Another
    // client moving it (an operator, the shell) is re-applied over, once per
    // change, not once per period.
    let mut sig = policy::signature(&k);
    // A housekeeping loop nobody waits on: say so, and the kernel may fire its
    // period late to share another sleeper's wake-up (its row,
    // `timer_slack = true`, lets that apply where the product opts rows in).
    // A hint, not a request that can fail the server: the answer is ignored.
    let _ = sys::qos_hint(sys::QOS_BACKGROUND);
    loop {
        sys::sleep(SERVE_PERIOD_MS);
        let now = policy::signature(&k);
        if now != sig {
            put(1, b"[power] the policy moved under us; re-applying\n");
            o = apply_once(&mut k, preset);
            if o.failed {
                return 1;
            }
            sig = policy::signature(&k);
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
    line("evals", POLICY_STATS_EVALS, true);
    line("changes", POLICY_STATS_CHANGES, true);
    line("applied", POLICY_STATS_APPLIED, true);
    line("refused", POLICY_STATS_REFUSED, true);
    line("floor_wins", POLICY_STATS_FLOOR_WINS, true);
    0
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

/// An op that answers only the outcome: `Ok` when served.
fn served(r: Result<sys::dev::Out<()>, sys::dev::IdlError>) -> Result<(), u32> {
    match r {
        Ok(o) if o.is_ok() => Ok(()),
        Ok(o) => Err(o.code),
        Err(_) => Err(sys::dev::outcome::NO_SERVER),
    }
}

#[sys::main(panic_exit = 70)]
fn run() -> i32 {
    let op_name = sys::arg(1).unwrap_or(b"");
    match op_name {
        b"serve" => return apply_cmd(true),
        b"apply" => return apply_cmd(false),
        b"state" => return state_cmd(),
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
        (b"suspend", _) => match served(k.c.suspend()) {
            Ok(()) => put(1, b"power: resumed\n"),
            Err(c) => return refused(op_name, c),
        },
        (b"reboot", _) => {
            if let Err(c) = served(k.c.reboot()) {
                return refused(op_name, c);
            }
        }
        (b"shutdown", _) => {
            if let Err(c) = served(k.c.shutdown()) {
                return refused(op_name, c);
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

// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `neverallow`: grants no topology may make, whatever its file says.
//!
//! SELinux's lesson. An allow rule is data the policy author writes; a
//! `neverallow` rule is an assertion about all of that data, checked when the
//! policy is built, so a later edit that opens a hole is refused instead of
//! shipped. Here the data is the signed topology (`CAPS.TOM`), and the
//! assertions are the table [`RULES`]. They are checked
//!
//! * by [`Topology::admission_check`](crate::Topology::admission_check), so by
//!   every path that installs a topology: the signed candidate (refused, the
//!   kernel falls back to the built-in one or halts as Kconfig
//!   `TOPOLOGY_SOURCE` says), the built-in topology (the board halts), the
//!   host emitter `topo_emit` and `load_signed`;
//! * by `make check-neverallow` (`tools/check_neverallow.py`), which builds
//!   the topology of every preset and runs [`check`] on it with the option
//!   forced on.
//!
//! A refusal is [`AdmissionError::Neverallow`](crate::AdmissionError), and the
//! kernel writes a decision record for it (`azos_decision::Rule::Neverallow`):
//! the rule, the row, the kind of the grant that matched.
//!
//! # The rules
//!
//! | id | forbids |
//! |----|---------|
//! | `actuation-outside-actuation-row` | a ring-3 row holding a motor, a PWM or GPIO write, or the buzzer, unless the row is listed as an actuation row |
//! | `desktop-grants-no-motor` | any row holding a motor in a `USE_DESKTOP` image |
//! | `names-import-and-service-export` | a row that imports names from the name server and also serves a task-hosted endpoint (`endpoint.<name>`) or registers a driver |
//! | `actuation-grant-not-transferable` | a motor, PWM, GPIO or buzzer grant that carries `TRANSFER` (`transfer = true` or the `t` letter of `perm`) |
//! | `proxy-endpoint-not-realtime` | a row with a real-time reservation or class holding any grant on a proxy endpoint (`endpoint.rpc-*`) |
//! | `proxy-endpoint-served-by-rpcsrv-only` | a row other than `RPCSRV.ELF` serving a proxy endpoint |
//!
//! # Exceptions
//!
//! A rule's exception is a row name, the exact grants that row may hold
//! despite the rule (a kind and a target each, [`Permit`]) and a reason, in
//! [`Rule::exceptions`]. It lives in this table, in the kernel image, which
//! the kernel's own signature chain covers; a topology file cannot add one, so
//! a row cannot vouch for itself. An exception excuses those grants of that
//! row from that rule and nothing else: the same row holding another motor, or
//! another kind of actuator, is refused like any other row's. Every exception
//! states why, and a host test refuses an empty reason. Adding one is a
//! reviewed change to this file, not a line in a topology.

use azos_abi::cap::{CapKind, CapPerms};

use crate::types::{CapSpec, TaskSpec, Topology};

/// What the topology is built for: the facts a rule may depend on besides the
/// topology itself.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Env {
    /// The image is a desktop (Kconfig `USE_DESKTOP`).
    pub desktop: bool,
}

impl Env {
    /// The environment of this build, from the Kconfig the kernel is built with.
    pub const BUILD: Self = Self { desktop: azos_limits::USE_DESKTOP };
}

/// Why a topology was refused: the first grant a rule forbids.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct NeverallowRefusal {
    /// Index of the rule in [`RULES`].
    pub rule: u8,
    /// Index of the row in the topology.
    pub row: u16,
    /// [`CapKind::denial_code`] of the grant that matched.
    pub kind: u8,
    /// Index of the grant in the row.
    pub grant: u16,
}

impl NeverallowRefusal {
    /// The rule that refused.
    pub fn rule(&self) -> &'static Rule {
        &RULES[self.rule as usize]
    }
}

/// One grant an exception excuses: the kind and the exact target string, as
/// in `{ kind = "endpoint", target = "motor.0" }`. Permissions are not compared:
/// the rules forbid holding the resource, not a particular access to it.
#[derive(Clone, Copy, Debug)]
pub struct Permit {
    /// The kind of the grant.
    pub kind: CapKind,
    /// The target, byte for byte.
    pub target: &'static str,
}

/// One row that a rule lets hold the listed grants it otherwise forbids, and
/// why.
#[derive(Clone, Copy, Debug)]
pub struct Exception {
    /// The row's name, as in `[task.NAME]`.
    pub row: &'static str,
    /// The grants of that row the rule does not refuse. Never empty.
    pub permits: &'static [Permit],
    /// Why this row, and nothing else, may. Never empty.
    pub reason: &'static str,
}

impl Exception {
    /// Does this exception excuse grant `c` of the row called `row`?
    fn excuses(&self, row: &str, c: &CapSpec<'_>) -> bool {
        self.row == row && self.permits.iter().any(|p| p.kind == c.kind && p.target == c.target.as_str())
    }
}

/// One neverallow rule.
pub struct Rule {
    /// The rule's name, as `tools/check_neverallow.py` and the logs print it.
    pub id: &'static str,
    /// The assertion, in English.
    pub text: &'static str,
    /// The rows that may break it anyway (see the module doc).
    pub exceptions: &'static [Exception],
    /// Does grant `c` of `row` break the rule (before exceptions)?
    breaks: fn(&Env, &TaskSpec<'_>, &CapSpec<'_>) -> bool,
}

/// Is `c` an endpoint grant of the interface whose resources are named
/// `<iface>.<n>` (`motor.0`, `pwm.4`, `gpio.20`)?
fn is_iface(c: &CapSpec<'_>, iface: &str) -> bool {
    c.kind == CapKind::Endpoint
        && c.target.as_str().strip_prefix(iface).is_some_and(|rest| rest.starts_with('.'))
}

/// A motor endpoint, whatever the rights: every op of it moves a wheel.
fn is_motor(c: &CapSpec<'_>) -> bool {
    is_iface(c, "motor")
}

/// The grants that move something in the world: a motor endpoint, a PWM
/// channel or GPIO pin endpoint with write access (the buzzer is the PWM
/// channel `pwm.5`). Reading a pin or a channel is not.
fn actuates(c: &CapSpec<'_>) -> bool {
    is_motor(c) || ((is_iface(c, "pwm") || is_iface(c, "gpio")) && c.perms.contains(CapPerms::WRITE))
}

fn actuation_outside_actuation_row(_: &Env, row: &TaskSpec<'_>, c: &CapSpec<'_>) -> bool {
    row.is_ring3() && actuates(c)
}

fn desktop_grants_no_motor(env: &Env, _: &TaskSpec<'_>, c: &CapSpec<'_>) -> bool {
    env.desktop && is_motor(c)
}

fn names_import_and_service_export(_: &Env, row: &TaskSpec<'_>, c: &CapSpec<'_>) -> bool {
    // Serving an endpoint (READ on a task-hosted `endpoint.<name>`, the half
    // that listens) or registering as a driver: the row answers other tasks
    // and can also ask the name server for any name it was granted, which is
    // a way to turn a service into a confused deputy. READ on a kernel-hosted
    // interface (`net`, `clock`: a target without the `endpoint.` prefix) is
    // a client's grant, the kernel serves it, so it does not count.
    row.imports_count != 0
        && ((c.kind == CapKind::Device && c.target.as_str().starts_with("drv."))
            || (c.kind == CapKind::Endpoint
                && crate::types::endpoint_target(c).is_some()
                && c.perms.contains(CapPerms::READ)))
}

fn actuation_grant_not_transferable(_: &Env, _: &TaskSpec<'_>, c: &CapSpec<'_>) -> bool {
    c.grant_perms().contains(CapPerms::TRANSFER) && actuates(c)
}

/// A grant on a proxy endpoint: the local face of a service on another node
/// (`endpoint.rpc-<service>`, [`crate::types::PROXY_PREFIX`]).
fn is_proxy(c: &CapSpec<'_>) -> bool {
    c.kind == CapKind::Endpoint
        && crate::types::endpoint_target(c).is_some_and(|n| n.starts_with(crate::types::PROXY_PREFIX))
}

/// The scheduler classes that are real time (`azos_sched::class::SchedClass`:
/// the first three), by the names a row gives them.
const REALTIME_CLASSES: [&[u8]; 3] = [b"safety_critical", b"hard_rt", b"soft_rt"];

/// A call over a link takes as long as the link does, and a real-time caller
/// has a reservation (a declared profile) or a class that is a promise about
/// its own time: it may not wait on a node it does not control. (The kernel
/// refuses the same call at run time for any task of a real-time class,
/// including one that became real-time after it was admitted.)
fn proxy_endpoint_not_realtime(_: &Env, row: &TaskSpec<'_>, c: &CapSpec<'_>) -> bool {
    (row.profile.is_declared() || REALTIME_CLASSES.contains(&row.class_name.as_bytes())) && is_proxy(c)
}

fn proxy_endpoint_served_by_rpcsrv_only(_: &Env, row: &TaskSpec<'_>, c: &CapSpec<'_>) -> bool {
    is_proxy(c) && c.perms.contains(CapPerms::READ) && row.name.as_bytes() != crate::types::RPC_IMAGE
}

/// The rules, in the order they are checked. The index is what a decision
/// record names.
pub const RULES: [Rule; 6] = [
    Rule {
        id: "actuation-outside-actuation-row",
        text: "no ring-3 row holds a motor, a PWM or GPIO write grant, or the buzzer, unless the row is an actuation row",
        exceptions: &[
            Exception {
                row: "autorun",
                permits: &[
                    Permit { kind: CapKind::Endpoint, target: "motor.0" },
                    Permit { kind: CapKind::Endpoint, target: "motor.1" },
                    Permit { kind: CapKind::Endpoint, target: "pwm.4" },
                    Permit { kind: CapKind::Endpoint, target: "gpio.20" },
                    // The motor-bound channel and pin only the gate's
                    // `cap-refusal-canary` build grants, so that the kernel's
                    // family guard is seen to refuse them.
                    #[cfg(feature = "cap-refusal-canary")]
                    Permit { kind: CapKind::Endpoint, target: "pwm.0" },
                    #[cfg(feature = "cap-refusal-canary")]
                    Permit { kind: CapKind::Endpoint, target: "gpio.0" },
                ],
                reason: "the row every image without a row of its own runs under, and the one the cap-seed \
                         bridge seeds the drivetrain and the free PWM and GPIO channels from",
            },
            Exception {
                row: "FLIGHT.ELF",
                permits: &[
                    Permit { kind: CapKind::Endpoint, target: "motor.0" },
                    Permit { kind: CapKind::Endpoint, target: "motor.1" },
                ],
                reason: "the flight tool, which under `flight-tool-drivetrain` owns the drivetrain instead \
                         of autorun (one writer per motor)",
            },
            Exception {
                row: "BUZZDRV.ELF",
                permits: &[Permit { kind: CapKind::Endpoint, target: "pwm.5" }],
                reason: "the ring-3 buzzer driver: pwm.5 is the buzzer's channel and the driver is the only \
                         thing that may drive it",
            },
        ],
        breaks: actuation_outside_actuation_row,
    },
    Rule {
        id: "desktop-grants-no-motor",
        text: "no row of a USE_DESKTOP image holds a motor",
        exceptions: &[],
        breaks: desktop_grants_no_motor,
    },
    Rule {
        id: "names-import-and-service-export",
        text: "no row both imports names from the name server and serves an endpoint or registers a driver",
        exceptions: &[],
        breaks: names_import_and_service_export,
    },
    Rule {
        id: "actuation-grant-not-transferable",
        text: "no motor, PWM, GPIO or buzzer grant carries TRANSFER (transfer = true, or perm \"t\")",
        exceptions: &[],
        breaks: actuation_grant_not_transferable,
    },
    Rule {
        id: "proxy-endpoint-not-realtime",
        text: "no row with a real-time reservation or class holds a grant on a proxy endpoint",
        exceptions: &[],
        breaks: proxy_endpoint_not_realtime,
    },
    Rule {
        id: "proxy-endpoint-served-by-rpcsrv-only",
        text: "no row but RPCSRV.ELF serves a proxy endpoint",
        exceptions: &[],
        breaks: proxy_endpoint_served_by_rpcsrv_only,
    },
];

/// Check every rule against every grant of every row of `t`; the first grant
/// that breaks one is the refusal. A grant an exception of that rule lists for
/// that row is skipped by that rule alone.
pub fn check(t: &Topology<'_>, env: &Env) -> Result<(), NeverallowRefusal> {
    // Canary of the host suite: the rules find nothing.
    if cfg!(feature = "neverallow-canary") {
        return Ok(());
    }
    for (ri, rule) in RULES.iter().enumerate() {
        for (row_i, row) in t.tasks().iter().enumerate() {
            let name = row.name.as_str();
            for (grant, c) in t.caps_of(row).iter().enumerate() {
                if (rule.breaks)(env, row, c) && !rule.exceptions.iter().any(|e| e.excuses(name, c)) {
                    return Err(NeverallowRefusal {
                        rule: ri as u8,
                        row: row_i as u16,
                        kind: c.kind.denial_code(),
                        grant: grant as u16,
                    });
                }
            }
        }
    }
    Ok(())
}

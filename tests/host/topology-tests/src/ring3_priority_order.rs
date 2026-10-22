// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The ring-3 priorities of the built-in topology are the ones its rows state,
//! and they follow the rows' service graph.
//!
//! * No row relies on a clamp: every row's priority is inside its class's
//!   range (the number the row declares is the number `row_sched` applies),
//!   and no ring-3 image row without a reservation sits below the ring-3
//!   floor (12) that `topo_sched::resolve` would raise it to.
//! * A server never runs below a client it serves
//!   (`Topology::server_below_client`, the priority-ceiling rule), and the
//!   pairs where it only equals its client are exactly the documented ones:
//!   every other server outranks its clients.
//! * The interactive session (`SH.ELF`) runs below every server it depends on
//!   (the terminal, name and input servers) and is not equal to any ring-3
//!   driver.
//! * `INADRV.ELF`, the one ring-3 row with a real-time reservation, is one
//!   `topo_sched::row_reservation` admits: a profile in a class with admission
//!   control, outside the band, placed by boot admission on any CPU count,
//!   with the chip's own sample period.
//!
//! **Canaries.** Put `INPUTD.ELF` back at `TOOL_PRIORITY` in `builder.rs`:
//! `the_session_s_servers_outrank_it` is red, and with the compositor at 25
//! `no_server_runs_below_a_client_it_serves` is red too. Put `GPIODRV.ELF`
//! back at `0`: `no_row_relies_on_the_clamp` is red. Put `SH.ELF` back at 24:
//! `only_the_documented_pairs_are_equal` (TERMD.ELF equals it) and
//! `the_session_s_servers_outrank_it` are red. Push `INADRV.ELF` with
//! `push_task` (no profile): `the_ina219_driver_holds_an_admitted_reservation`
//! is red.

use azos_topology::builder::{default_minimal, SH_PRIORITY, TASK_SH_IMAGE};
use azos_topology::{ring3_priority, MaybeStr, RowSched, ServiceEdge, Topology};

/// The ring-3 floor and ceiling `topo_sched` applies
/// (`RT_PRIORITY_THRESHOLD`, `IDLE_PRIORITY - 1`).
const FLOOR: u32 = 12;
const CEIL: u32 = 30;

fn prio(t: &Topology<'_>, name: &[u8]) -> u8 {
    match t.row_sched(name) {
        RowSched::Apply { priority, .. } => priority,
        other => panic!("{:?}: no applied row ({other:?})", core::str::from_utf8(name)),
    }
}

fn name<'a>(t: &Topology<'a>, i: usize) -> &'a str {
    t.tasks()[i].name.as_str()
}

#[test]
fn no_row_relies_on_the_clamp() {
    let t = default_minimal();
    for r in t.tasks() {
        let RowSched::Apply { declared, priority, .. } = t.row_sched(r.name.as_bytes()) else {
            panic!("{}: no class", r.name.as_str());
        };
        assert_eq!(declared, priority, "{}: the class range clamps its priority", r.name.as_str());
        // A ring-3 image without a reservation runs at the number it states.
        if r.name.as_bytes().ends_with(b".ELF") && !r.profile.is_declared() {
            assert_eq!(
                ring3_priority(priority as u32, FLOOR, CEIL),
                (priority as u32, false),
                "{}: raised to the ring-3 floor",
                r.name.as_str()
            );
        }
    }
}

#[test]
fn no_server_runs_below_a_client_it_serves() {
    let t = default_minimal();
    if let Some(e) = t.server_below_client() {
        panic!(
            "{} ({}) serves {} ({}) on `{}` from below",
            name(&t, e.server),
            prio(&t, name(&t, e.server).as_bytes()),
            name(&t, e.client),
            prio(&t, name(&t, e.client).as_bytes()),
            core::str::from_utf8(e.endpoint).unwrap()
        );
    }
}

/// The pairs where a server only equals its client, each for a stated reason:
/// * `VSSRV.ELF` / `autorun` (gate builds): the benchmark server shares its
///   client's bucket, so `ipc-roundtrip` measures IPC and not a cross-priority
///   hand-off (owner decision 2026-09-28, round 15). `EPSRV.ELF`, the other
///   gate server of `autorun`, follows it.
/// * `LOGIND.ELF` / `TERMD.ELF` (Kconfig CONSOLE_LOGIN): both serve the shell
///   at [`SERVICE_PRIORITY`](azos_topology::builder::SERVICE_PRIORITY), the
///   top of `best_effort`, and the shell sits one below them.
const EQUAL_BY_DESIGN: &[(&str, &str)] = &[
    ("EPSRV.ELF", "autorun"),
    ("VSSRV.ELF", "autorun"),
    ("LOGIND.ELF", "TERMD.ELF"),
];

#[test]
fn only_the_documented_pairs_are_equal() {
    let t = default_minimal();
    let mut equal = Vec::new();
    t.for_each_service_edge(|e: ServiceEdge<'_>| {
        if prio(&t, name(&t, e.server).as_bytes()) == prio(&t, name(&t, e.client).as_bytes()) {
            equal.push((name(&t, e.server), name(&t, e.client)));
        }
    });
    for p in &equal {
        assert!(EQUAL_BY_DESIGN.contains(p), "{} only equals its client {}", p.0, p.1);
    }
}

#[test]
fn the_session_s_servers_outrank_it() {
    let t = default_minimal();
    let sh = prio(&t, TASK_SH_IMAGE);
    assert_eq!(sh, SH_PRIORITY);
    // What the shell calls (its `term` import) and what delivers its input.
    let mut servers = vec!["TERMD.ELF", "NAMESD.ELF"];
    if azos_topology::builder::INPUTD_ROW {
        servers.push("INPUTD.ELF");
    }
    for s in servers {
        assert!(prio(&t, s.as_bytes()) < sh, "{s} does not outrank the shell");
    }
    // A ring-3 driver never competes equal with the session.
    for d in ["GPIODRV.ELF", "BUZZDRV.ELF", "INADRV.ELF", "LXSRV.ELF"] {
        if t.find_task(&MaybeStr::from_bytes(d.as_bytes())).is_some() {
            assert_ne!(prio(&t, d.as_bytes()), sh, "{d} runs equal with the shell");
        }
    }
}

/// The rule itself, on a two-row topology: a server below its client is
/// found, one equal to or above it is not, and an `imports` entry is a call
/// like a grant.
#[test]
fn the_ceiling_rule_reads_grants_and_imports() {
    use azos_abi::cap::{CapKind, CapPerms};
    use azos_topology::CapSpec;
    const SCHED: &[u8] = b"[class.best_effort]\ncpu_budget_min_pct = 5\npriority_range = [24, 30]\n";
    let serve = CapSpec {
        kind: CapKind::Endpoint,
        perms: CapPerms::READ,
        target: MaybeStr::from_bytes(b"endpoint.demo"), transfer: false, ops: 0,
    };
    let call = CapSpec { perms: CapPerms::WRITE, ..serve };
    let build = |server: u8, client: u8| {
        let mut t = Box::new(Topology::empty());
        azos_topology::parse_sched(SCHED, &mut t).expect("parse");
        t.push_task(MaybeStr::from_bytes(b"srv"), MaybeStr::from_bytes(b"best_effort"), server, &[serve]).unwrap();
        t.push_task(MaybeStr::from_bytes(b"cli"), MaybeStr::from_bytes(b"best_effort"), client, &[call]).unwrap();
        t
    };
    let below = build(26, 24);
    let e = below.server_below_client().expect("a server below its client is found");
    assert_eq!((e.server, e.client, e.endpoint), (0, 1, &b"demo"[..]));
    assert_eq!(build(24, 24).server_below_client(), None);
    assert_eq!(build(24, 26).server_below_client(), None);
    // A client that reaches the server by an import instead of a grant.
    let mut t = Box::new(Topology::empty());
    azos_topology::parse_sched(SCHED, &mut t).expect("parse");
    t.push_task(MaybeStr::from_bytes(b"srv"), MaybeStr::from_bytes(b"best_effort"), 26, &[serve]).unwrap();
    t.push_task(MaybeStr::from_bytes(b"cli"), MaybeStr::from_bytes(b"best_effort"), 24, &[]).unwrap();
    t.set_last_task_imports(&[MaybeStr::from_bytes(b"demo")]).unwrap();
    assert_eq!(t.server_below_client().map(|e| (e.server, e.client)), Some((0, 1)));
}

/// What `topo_sched::row_reservation` reads for `INADRV.ELF`, row by row: a
/// declared profile, a class with `admission_control`, no band entry (so no
/// locked memory is needed), a CPU from boot admission whatever the hart
/// count, and the priority `resolve` applies to a reserved row (floor 0).
#[test]
fn the_ina219_driver_holds_an_admitted_reservation() {
    use azos_topology::builder::{INADRV_PRIORITY, INADRV_ROW, INADRV_RT, TASK_INADRV_IMAGE};
    use azos_topology::BandEntry;
    if !INADRV_ROW {
        return; // placed in the kernel (DRVPLACE): no ring-3 row
    }
    let t = default_minimal();
    let ti = t.tasks().iter().position(|r| r.name.as_bytes() == TASK_INADRV_IMAGE).expect("INADRV.ELF row");
    let row = &t.tasks()[ti];
    assert!(row.profile.is_declared(), "INADRV.ELF declares no reservation");
    assert_eq!(row.profile, INADRV_RT);
    let class = t.find_class(&row.class_name).expect("class");
    assert_eq!(class.name.as_bytes(), b"hard_rt");
    assert!(class.admission_control, "a profile outside admission control is never reserved");
    assert_ne!(t.row_band_entry(ti), BandEntry::NotLocked);
    assert!((INADRV_PRIORITY as u32) >= FLOOR, "a band row would need mem = \"locked\"");
    assert_eq!(prio(&t, TASK_INADRV_IMAGE), INADRV_PRIORITY);
    assert_eq!(ring3_priority(INADRV_PRIORITY as u32, 0, CEIL), (INADRV_PRIORITY as u32, false));
    for cpus in [1, 2, 4] {
        let r = t.deadline_admission(cpus).unwrap_or_else(|e| panic!("{cpus} CPU(s): {e:?}"));
        assert!(r.cpu_of(ti as u16).is_some(), "{cpus} CPU(s): INADRV.ELF not placed");
    }
    // The period is the chip's sample period, and the deadline is the period.
    assert_eq!(INADRV_RT.period_us as u64, 1_000_000 / azos_ina219::INA219_POLL_HZ as u64);
    assert_eq!(INADRV_RT.deadline_us, 0);
    assert!(INADRV_RT.runtime_us < INADRV_RT.period_us);
}

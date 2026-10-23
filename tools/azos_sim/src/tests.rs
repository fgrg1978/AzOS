// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The dry boot against the records the boot writes, and its reading of a
//! boot's console. The consoles below are the lines
//! `kernel/src/boot/topology.rs` prints, with the format strings it uses.
//! The gate canary `sim-cpu-canary` (the dry boot admits on one CPU more)
//! turns these red, and the gate row "topology: dry boot matches the boot".

use super::*;
use azos_decision::{Rule, Verdict};
use azos_topology::DeadlineRefusal;

const SCHED: &[u8] = b"\
[class.rt]
cpu_budget_min_pct  = 10
cpu_budget_max_pct  = 100
policy              = \"edf\"
admission_control   = true
";

/// Two locked band rows of 60 % each, either CPU of two, and one image row.
fn caps(image: &str) -> String {
    let row = |n: &str| format!(
        "[task.{n}]\nclass = \"rt\"\npriority = 5\nmem = \"locked\"\nmem_pages = 1\n\
         period_us = 10000\nruntime_us = 6000\ncpu_mask = 3\ncaps = []\n\n"
    );
    row("a") + &row("b") + &format!("[task.{image}]\nclass = \"rt\"\npriority = 20\ncaps = []\n\n")
}

fn rc(rule: Rule, verdict: Verdict, subject: u32, numbers: [u64; 3]) -> Receipt {
    Receipt { rule, verdict, subject, numbers }
}

/// A console as the kernel prints it for `rows` rows on `cpus` CPUs.
fn console(rows: usize, tail: &str) -> String {
    format!(
        "[MM] W^X ok\n[TOPO] Topology installed: 1 classes, {rows} tasks, from the built-in topology in 9 ticks (9 ns)\n{tail}"
    )
}

#[test]
fn two_cpus_place_both_rows_and_one_refuses() {
    let d = dry_boot_files(caps("NOSUCH.ELF").as_bytes(), SCHED, 2);
    assert!(d.install.is_ok(), "{:?}", d.install);
    assert_eq!(d.receipts, [
        rc(Rule::DeadlineAdmission, Verdict::Admit, 2, [2, 3, 0]),
        rc(Rule::RtBandCap, Verdict::Admit, 2, [2, azos_limits::RT_BAND_CAP_PCT as u64, 0]),
    ]);
    assert!(d.boots());
    assert_eq!(d.placed.iter().map(|p| (p.row, p.cpu, p.density_ppm)).collect::<Vec<_>>(), [(0, 0, 600_000), (1, 1, 600_000)]);

    let d = dry_boot_files(caps("NOSUCH.ELF").as_bytes(), SCHED, 1);
    assert_eq!(d.receipts, [rc(Rule::DeadlineAdmission, Verdict::Refuse, 1, [0, 3, 0])]);
    assert!(!d.boots());
}

#[test]
fn an_image_row_without_a_filter_row_is_named() {
    let d = dry_boot_files(caps("NOSUCH.ELF").as_bytes(), SCHED, 2);
    assert_eq!(d.unfiltered, [(2, "NOSUCH.ELF".to_string(), false)]);
    let shipped = seccomp::IMAGE_PROFILES[0].image;
    let d = dry_boot_files(caps(shipped).as_bytes(), SCHED, 2);
    assert!(d.unfiltered.is_empty(), "{shipped} has a filter row: {:?}", d.unfiltered);
}

#[test]
fn a_file_that_does_not_parse_is_refused_without_a_record() {
    let d = dry_boot_files(b"[task.a\nclass = ", SCHED, 2);
    assert!(matches!(d.install, Err(InstallRefusal::Parse { sched: false, .. })), "{:?}", d.install);
    assert!(d.receipts.is_empty() && !d.boots());
    let d = dry_boot_files(b"", b"[class", 2);
    assert!(matches!(d.install, Err(InstallRefusal::Parse { sched: true, .. })), "{:?}", d.install);
}

/// The boot that admitted both rows on two harts, and the one that halted on
/// one: the dry boot on the same CPU count matches each.
#[test]
fn the_dry_boot_matches_the_boots_console() {
    let caps = caps("NOSUCH.ELF");
    let two = console(3, "[TOPO] Deadline admission: 2 real-time task(s) placed on 2 CPU(s)\n[TOPO] 0 named endpoint(s) declared\n");
    let d = dry_boot_files(caps.as_bytes(), SCHED, 2);
    assert_eq!(check_boot_log(&d, &read_boot_log(&two, 2).unwrap()), Ok(()));

    let e = AdmissionError::Deadline(DeadlineRefusal::NoCpuFits { task: 1 });
    let one = console(3, &format!("[ERR] [TOPO] Deadline admission REFUSED on 1 CPU(s): {e:?} — halting\n"));
    let d = dry_boot_files(caps.as_bytes(), SCHED, 1);
    assert_eq!(check_boot_log(&d, &read_boot_log(&one, 1).unwrap()), Ok(()));
}

/// Every way the two can differ is reported: another CPU count, another
/// `placed`, another row count, a refusal the dry boot did not make.
#[test]
fn a_dry_boot_that_differs_from_the_boot_is_caught() {
    let caps = caps("NOSUCH.ELF");
    let d2 = dry_boot_files(caps.as_bytes(), SCHED, 2);
    let placed_one = console(3, "[TOPO] Deadline admission: 1 real-time task(s) placed on 2 CPU(s)\n");
    assert!(check_boot_log(&d2, &read_boot_log(&placed_one, 2).unwrap()).is_err());
    let four_rows = console(4, "[TOPO] Deadline admission: 2 real-time task(s) placed on 2 CPU(s)\n");
    assert!(check_boot_log(&d2, &read_boot_log(&four_rows, 2).unwrap()).is_err());
    let two = console(3, "[TOPO] Deadline admission: 2 real-time task(s) placed on 2 CPU(s)\n");
    assert!(check_boot_log(&d2, &read_boot_log(&two, 4).unwrap()).is_err(), "booted on 4 harts, dry-booted on 2");
    let refused = console(3, "[TOPO] Deadline admission REFUSED on 2 CPU(s): Deadline(NoCpuFits { task: 1 }) — halting\n");
    assert!(check_boot_log(&d2, &read_boot_log(&refused, 2).unwrap()).is_err());
    let failed = "[TOPO] Topology install FAILED: Admission(Deadline(IsolatedWithoutCpu { task: 0 })) — halting\n";
    assert!(check_boot_log(&d2, &read_boot_log(failed, 2).unwrap()).is_err());
    assert!(read_boot_log("[MM] W^X ok\n", 2).is_err(), "a console with no install line is not a boot to compare with");
}

// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The boot admission's pure half (`azos_topology::boot_admission`): the step
//! `kernel/src/boot/topology.rs` `admit` runs first and the records it
//! writes, which the host dry boot (`tools/azos_sim`, `make sim`) replays.
//!
//! The records are pinned field by field to what the kernel wrote before the
//! step moved out of it: `DeadlineAdmission` with subject = CPUs and
//! `[placed, rows, 0]` (`placed` 0 on a refusal), then `RtBandCap` with
//! `[placed, RT_BAND_CAP_PCT, 0]` only when something was placed. The gate row
//! "topology: dry boot matches the boot" holds a QEMU boot to the same
//! records.

use azos_decision::{Rule, Verdict};
use azos_topology::boot_admission::{deadline_step, isolated_without_cpu_receipt, neverallow_receipt, DeadlineOutcome, Receipt};
use azos_topology::{parse_caps, parse_sched, AdmissionError, DeadlineRefusal, Topology};

/// One class that may take a whole CPU, under admission control, whose
/// default priority range reaches into the real-time band.
const SCHED: &[u8] = b"\
[class.rt]
cpu_budget_min_pct  = 10
cpu_budget_max_pct  = 100
policy              = \"edf\"
admission_control   = true
";

fn topo(caps: String) -> Topology<'static> {
    let caps: &'static str = Box::leak(caps.into_boxed_str());
    let mut t = Topology::empty();
    parse_sched(SCHED, &mut t).unwrap();
    parse_caps(caps.as_bytes(), &mut t).unwrap();
    t
}

/// A locked band row (priority 5) with `runtime_us` of every 10 ms on the
/// CPUs of `mask`.
fn row(name: &str, runtime_us: u32, mask: u32) -> String {
    format!(
        "[task.{name}]\nclass = \"rt\"\npriority = 5\nmem = \"locked\"\nmem_pages = 1\n\
         period_us = 10000\nruntime_us = {runtime_us}\ncpu_mask = {mask}\ncaps = []\n\n"
    )
}

/// A best-effort row with no profile.
fn plain(name: &str) -> String {
    format!("[task.{name}]\nclass = \"rt\"\npriority = 20\ncaps = []\n\n")
}

fn receipts(t: &Topology<'_>, ncpus: usize) -> Vec<Receipt> {
    deadline_step(t, ncpus).receipts().copied().collect()
}

fn rc(rule: Rule, verdict: Verdict, subject: u32, numbers: [u64; 3]) -> Receipt {
    Receipt { rule, verdict, subject, numbers }
}

/// Two 60 % rows on two CPUs: one each. Admitted, two placed of three rows,
/// and the band under the cap.
#[test]
fn an_admitted_set_writes_placed_rows_then_the_band() {
    let t = topo(row("a", 6000, 3) + &row("b", 6000, 3) + &plain("c"));
    let cap = azos_limits::RT_BAND_CAP_PCT as u64;
    assert_eq!(receipts(&t, 2), [
        rc(Rule::DeadlineAdmission, Verdict::Admit, 2, [2, 3, 0]),
        rc(Rule::RtBandCap, Verdict::Admit, 2, [2, cap, 0]),
    ]);
    assert!(matches!(deadline_step(&t, 2).outcome, DeadlineOutcome::Admitted(r) if r.placed == 2));
}

/// The same set on one CPU: refused, `placed` 0, and no band record.
#[test]
fn a_refused_set_writes_one_record_with_nothing_placed() {
    let t = topo(row("a", 6000, 3) + &row("b", 6000, 3) + &plain("c"));
    assert_eq!(receipts(&t, 1), [rc(Rule::DeadlineAdmission, Verdict::Refuse, 1, [0, 3, 0])]);
    assert!(matches!(
        deadline_step(&t, 1).outcome,
        DeadlineOutcome::Refused(AdmissionError::Deadline(DeadlineRefusal::NoCpuFits { task: 1 }))
    ));
}

/// No profiled row: admitted with nothing placed, and the band is not asked.
#[test]
fn nothing_profiled_writes_no_band_record() {
    let t = topo(plain("a") + &plain("b"));
    assert_eq!(receipts(&t, 4), [rc(Rule::DeadlineAdmission, Verdict::Admit, 4, [0, 2, 0])]);
}

/// A row that fits its CPU's density bound but not the band cap: the
/// deadline record admits, the band record refuses.
#[test]
fn a_row_over_the_band_cap_is_admitted_by_deadline_and_refused_by_the_band() {
    let cap = azos_limits::RT_BAND_CAP_PCT as u32;
    if cap >= 100 {
        return; // RT_BAND_CAP_PCT = 100: no band budget to exceed.
    }
    let t = topo(row("a", (cap + 1) * 100, 1));
    assert_eq!(receipts(&t, 1), [
        rc(Rule::DeadlineAdmission, Verdict::Admit, 1, [1, 1, 0]),
        rc(Rule::RtBandCap, Verdict::Refuse, 1, [1, cap as u64, 0]),
    ]);
    assert!(matches!(deadline_step(&t, 1).outcome, DeadlineOutcome::BandRefused(_, DeadlineRefusal::BandCap { task: 0 })));
}

/// The install-time records: a `neverallow` refusal names the row, rule, kind
/// and grant; an isolated row without a CPU names the row plus one.
#[test]
fn install_refusals_write_the_records_the_kernel_wrote() {
    let nv = AdmissionError::Neverallow(azos_topology::neverallow::NeverallowRefusal { rule: 2, row: 7, kind: 3, grant: 1 });
    assert_eq!(neverallow_receipt(&nv), Some(rc(Rule::Neverallow, Verdict::Refuse, 7, [2, 3, 1])));
    assert_eq!(isolated_without_cpu_receipt(&nv, 4), None);
    let iso = AdmissionError::Deadline(DeadlineRefusal::IsolatedWithoutCpu { task: 5 });
    assert_eq!(isolated_without_cpu_receipt(&iso, 4), Some(rc(Rule::DeadlineAdmission, Verdict::Refuse, 4, [0, 0, 6])));
    assert_eq!(neverallow_receipt(&iso), None);
}

/// The dry boot of the built-in topology this suite was built for (the
/// `KCONFIG_CONFIG` and topology features of the run): install, then the
/// deadline step on 1, 2 and 4 CPUs, printed as `why list` prints a record
/// (`cargo test dry_boot -- --nocapture`). The records are the ones the
/// kernel's own derivation gives: `deadline_admission` placed, the row count.
#[test]
fn dry_boot_of_the_builtin_topology() {
    let t = azos_topology::default_minimal();
    t.admission_check().expect("the built-in topology installs");
    let rows = t.tasks().len() as u64;
    for ncpus in [1usize, 2, 4] {
        let got = receipts(&t, ncpus);
        let first = match t.deadline_admission(ncpus) {
            Ok(r) => rc(Rule::DeadlineAdmission, Verdict::Admit, ncpus as u32, [r.placed as u64, rows, 0]),
            Err(_) => rc(Rule::DeadlineAdmission, Verdict::Refuse, ncpus as u32, [0, rows, 0]),
        };
        assert_eq!(got[0], first, "{ncpus} CPU(s)");
        for (i, r) in got.iter().enumerate() {
            let mut line = String::new();
            r.provenance(i as u64 + 1).write_line(&mut line).unwrap();
            println!("dry boot, {ncpus} CPU(s): {}", line.trim_end());
        }
    }
}

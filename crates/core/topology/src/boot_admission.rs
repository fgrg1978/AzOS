// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The pure half of the kernel's boot admission (`kernel/src/boot/topology.rs`,
//! `admit` and the install-time refusal records): what it decides about a
//! topology on `ncpus` CPUs and the decision records it writes for that,
//! before it reserves a frame.
//!
//! The kernel and the host dry boot (`tools/azos_sim`, `make sim`) call these
//! same functions, so a topology mistake the kernel would refuse is answered
//! on the host first, with the records the boot would write. What needs the
//! machine (the DMA pool and the 2 MiB regions reserved from the page
//! allocator, the halt) stays in the kernel.

use azos_decision::{Rule, Verdict};

use crate::deadline::{profile_density, LevelOrder, Report, RT_BAND_THRESHOLD};
use crate::{AdmissionError, DeadlineRefusal, TaskSpec, Topology};

/// One decision record the boot admission writes: the arguments of
/// `azos_decision::record`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Receipt {
    /// The rule that decided.
    pub rule: Rule,
    /// What it decided.
    pub verdict: Verdict,
    /// The record's subject (the rule's `subject` field names it).
    pub subject: u32,
    /// The record's three numbers (the rule's `fields`).
    pub numbers: [u64; 3],
}

impl Receipt {
    /// Write it to the decision ring (a no-op in a build without records).
    pub fn record(&self) {
        azos_decision::record(self.rule, self.verdict, self.subject, self.numbers);
    }

    /// The record as `why list` reads it back, with sequence number `seq`
    /// (`azos_decision::ProvenanceRecord::write_line` prints it).
    pub fn provenance(&self, seq: u64) -> azos_decision::ProvenanceRecord {
        let mut p = azos_decision::ProvenanceRecord::new(self.rule as u8, self.verdict as u8, self.subject, self.numbers);
        p.seq = seq;
        p
    }
}

/// How the deadline step ended.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DeadlineOutcome {
    /// Every profiled row placed, and the band under the cap on every CPU.
    Admitted(Report),
    /// Some row cannot meet its deadline on these CPUs (or a profile is
    /// malformed): `Topology::deadline_admission` refused.
    Refused(AdmissionError),
    /// Placed, but the band's rows on one CPU exceed `RT_BAND_CAP_PCT`.
    BandRefused(Report, DeadlineRefusal),
}

/// The boot admission's first step: its outcome and the records it writes,
/// in the order it writes them.
#[derive(Clone, Copy, Debug)]
pub struct DeadlineStep {
    /// What was decided.
    pub outcome: DeadlineOutcome,
    receipts: [Option<Receipt>; 2],
}

impl DeadlineStep {
    /// The records, in write order: `Rule::DeadlineAdmission`, then
    /// `Rule::RtBandCap` when some row was placed.
    pub fn receipts(&self) -> impl Iterator<Item = &Receipt> {
        self.receipts.iter().flatten()
    }
}

/// Step 1 of the boot admission: the deadlines of `topo`'s profiled rows on
/// `ncpus` CPUs, then the real-time band cap (Kconfig `RT_BAND_CAP_PCT`) on
/// the CPUs they were placed on. `order` is the scheduler's level order
/// (`classes::level_order` in the kernel): the cross-level rule binds only
/// under `LevelOrder::Fixed`, as at run-time `reserve`.
///
/// Records: `DeadlineAdmission` (subject = `ncpus`; `placed`, rows, 0; on a
/// refusal `placed` is 0 and the third number names the first row refused,
/// `DeadlineRefusal::record_row`), then, when some row was placed,
/// `RtBandCap` (subject = `ncpus`; `placed`, the cap, the row refused or 0).
pub fn deadline_step(topo: &Topology<'_>, ncpus: usize, order: LevelOrder) -> DeadlineStep {
    let rows = topo.tasks().len() as u64;
    let cpus = ncpus as u32;
    let r = match topo.deadline_admission(ncpus, order) {
        Ok(r) => r,
        Err(e) => {
            let row = if let AdmissionError::Deadline(d) = &e { d.record_row() } else { 0 };
            let refused = Receipt { rule: Rule::DeadlineAdmission, verdict: Verdict::Refuse, subject: cpus, numbers: [0, rows, row] };
            return DeadlineStep { outcome: DeadlineOutcome::Refused(e), receipts: [Some(refused), None] };
        }
    };
    let admitted = Receipt { rule: Rule::DeadlineAdmission, verdict: Verdict::Admit, subject: cpus, numbers: [r.placed as u64, rows, 0] };
    if r.placed == 0 {
        return DeadlineStep { outcome: DeadlineOutcome::Admitted(r), receipts: [Some(admitted), None] };
    }
    let band = band_check(topo, &r);
    let band_receipt = Receipt {
        rule: Rule::RtBandCap,
        verdict: if band.is_ok() { Verdict::Admit } else { Verdict::Refuse },
        subject: cpus,
        numbers: [r.placed as u64, azos_limits::RT_BAND_CAP_PCT as u64, band.err().map_or(0, |e| e.record_row())],
    };
    let outcome = match band {
        Ok(()) => DeadlineOutcome::Admitted(r),
        Err(e) => DeadlineOutcome::BandRefused(r, e),
    };
    DeadlineStep { outcome, receipts: [Some(admitted), Some(band_receipt)] }
}

/// The band condition of [`deadline_step`]: on every CPU, the placed rows
/// whose priority (clamped into their class) is in the real-time band
/// ([`RT_BAND_THRESHOLD`], the scheduler's `RT_PRIORITY_THRESHOLD`) sum to at
/// most `RT_BAND_CAP_PCT` of it.
pub fn band_check(topo: &Topology<'_>, r: &Report) -> Result<(), DeadlineRefusal> {
    let tasks = topo.tasks();
    let in_band = |ti: u16| {
        let Some(t) = tasks.get(ti as usize) else { return false };
        let Some(c) = topo.find_class(&t.class_name) else { return false };
        let (lo, hi) = c.priority_range;
        t.priority.clamp(lo, hi.max(lo)) < RT_BAND_THRESHOLD
    };
    let density = |ti: u16| tasks.get(ti as usize)
        .and_then(|t| profile_density(&t.profile))
        .unwrap_or(u32::MAX);
    let limit = (azos_limits::RT_BAND_CAP_PCT as u32).saturating_mul(10_000);
    r.band_check(in_band, density, limit)
}

/// Step 2: the first row that asks for a 2 MiB-leaf region on a kernel built
/// without Kconfig `LOCKED_HUGE_LEAVES`, which is refused rather than run
/// without the region it was written for.
pub fn huge_leaves_refusal<'t, 'a>(topo: &'t Topology<'a>) -> Option<(usize, &'t TaskSpec<'a>)> {
    if azos_limits::LOCKED_HUGE_LEAVES {
        return None;
    }
    topo.tasks().iter().enumerate().find(|(_, t)| t.mem_huge_mib != 0)
}

/// The record of an install-time refusal (`admission_check`) by a
/// `neverallow` rule: the row as subject; the rule, the kind of the grant
/// that matched and its index in the row as the numbers.
pub fn neverallow_receipt(e: &AdmissionError) -> Option<Receipt> {
    let AdmissionError::Neverallow(r) = e else { return None };
    Some(Receipt {
        rule: Rule::Neverallow,
        verdict: Verdict::Refuse,
        subject: r.row as u32,
        numbers: [r.rule as u64, r.kind as u64, r.grant as u64],
    })
}

/// The record of an install-time refusal of a row with `isolated = true` and
/// no CPU (`Deadline(IsolatedWithoutCpu)`): the boot admission's rule,
/// subject = `ncpus`, `[0, 0, row + 1]` (the refused topology is already gone,
/// so no row count). The row index plus one sits in the low 32 bits and
/// nothing above them: a reason in bits 32.. would read as a run-time
/// reservation's refusal (`ProvenanceRecord::is_rt_refusal`).
pub fn isolated_without_cpu_receipt(e: &AdmissionError, ncpus: usize) -> Option<Receipt> {
    let AdmissionError::Deadline(DeadlineRefusal::IsolatedWithoutCpu { task }) = e else { return None };
    Some(Receipt {
        rule: Rule::DeadlineAdmission,
        verdict: Verdict::Refuse,
        subject: ncpus as u32,
        numbers: [0, 0, *task as u64 + 1],
    })
}

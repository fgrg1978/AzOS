// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host dry boot of a topology (`make sim`).
//!
//! Replays what `kernel/src/boot/topology.rs` does with a topology before it
//! reserves a frame, through the same functions
//! (`azos_topology::boot_admission`): the install-time check
//! (`admission_check`) and its records, then the deadline step on the CPUs
//! given and its records (`DeadlineAdmission`, `RtBandCap`), then the
//! huge-leaf check. On top of that it reports what the boot only finds
//! later: each `*.ELF` row whose image has no filter row in the build's table
//! (`crates/core/sched/src/seccomp.rs`, pulled in by `#[path]`), which an exec
//! site refuses (`SAFETY_EXEC_REFUSED`).
//!
//! Not replayed: memory admission, whose free-page count is the board's page
//! allocator after boot; the signature and the binding of a signed pair
//! (`signed::fill_signed`), which `make topology-files` and the volume tools
//! check; the critical chain's slack, which needs per-hop timing that no
//! topology declares yet.
//!
//! [`dry_boot_files`] is the entry for a pair of files (`CAPS.TOM`,
//! `SCHED.TOM`): parse, then [`dry_boot`]. It never panics on its input,
//! which makes it the topology parser's fuzz entry too.

use azos_topology::boot_admission::{self as ba, DeadlineOutcome, Receipt};
use azos_topology::deadline::profile_density;
use azos_topology::{AdmissionError, ParseError, Topology};
use std::fmt::{self, Write};

#[allow(dead_code)]
#[path = "../../../crates/core/sched/src/filter.rs"]
mod filter;

/// `seccomp.rs` says `crate::task::SyscallFilter`, which the kernel's
/// `task.rs` re-exports from `filter.rs`.
mod task {
    pub use crate::filter::SyscallFilter;
}

/// The two TCB accessors `seccomp::activate_profile` calls. A dry boot runs
/// no task, so nothing activates a filter.
mod scheduler {
    use crate::filter::SyscallFilter;

    pub fn current_syscall_filter() -> SyscallFilter {
        unreachable!("the dry boot runs no task")
    }

    pub fn set_current_syscall_filter(_: SyscallFilter) {
        unreachable!("the dry boot runs no task")
    }
}

#[allow(dead_code)]
#[path = "../../../crates/core/sched/src/seccomp.rs"]
mod seccomp;

/// Why a topology did not install (`admission_check`, or the parse of a
/// file before it).
#[derive(Clone, Copy, Debug)]
pub enum InstallRefusal {
    /// `SCHED.TOM` (`sched = true`) or `CAPS.TOM` does not parse.
    Parse { sched: bool, error: ParseError },
    /// The install-time check refused it.
    Admission(AdmissionError),
}

/// One placed real-time row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Placed {
    /// Its index in the topology.
    pub row: u16,
    /// Its name.
    pub name: String,
    /// The CPU admission gave it.
    pub cpu: u8,
    /// Its density, parts per million of that CPU.
    pub density_ppm: u32,
}

/// What a dry boot found.
#[derive(Clone, Debug)]
pub struct DryBoot {
    /// The CPU count the admission ran on.
    pub cpus: usize,
    /// The topology's row count (0 when it did not install).
    pub rows: usize,
    /// `Err` when the topology did not install.
    pub install: Result<(), InstallRefusal>,
    /// The decision records the boot writes, in order.
    pub receipts: Vec<Receipt>,
    /// The deadline step's outcome (`None` when the topology did not install).
    pub deadline: Option<DeadlineOutcome>,
    /// Each placed row, in placement order.
    pub placed: Vec<Placed>,
    /// The first row declaring `mem_huge_mib` on a kernel without
    /// `LOCKED_HUGE_LEAVES`: `(row, name, MiB)`.
    pub huge: Option<(usize, String, u16)>,
    /// The `*.ELF` rows whose image has no filter row: `(row, name, start)`.
    pub unfiltered: Vec<(usize, String, bool)>,
}

impl DryBoot {
    fn new(cpus: usize, install: Result<(), InstallRefusal>) -> Self {
        Self { cpus, rows: 0, install, receipts: Vec::new(), deadline: None, placed: Vec::new(), huge: None, unfiltered: Vec::new() }
    }

    /// Would the boot go past admission with this topology?
    pub fn boots(&self) -> bool {
        self.install.is_ok() && matches!(self.deadline, Some(DeadlineOutcome::Admitted(_))) && self.huge.is_none()
    }
}

/// The CPU count the dry boot admits on. Under the `sim-cpu-canary` gate
/// canary it is one more than it was given.
fn admission_cpus(cpus: usize) -> usize {
    if cfg!(feature = "sim-cpu-canary") { cpus + 1 } else { cpus }
}

/// Dry-boot `topo`, already filled, on `cpus` CPUs: what `install_topology`
/// and `admit` decide before the first frame is reserved.
pub fn dry_boot(topo: &Topology<'_>, cpus: usize) -> DryBoot {
    let ncpus = admission_cpus(cpus);
    let mut d = DryBoot::new(cpus, Ok(()));
    if let Err(e) = topo.admission_check() {
        d.receipts.extend(ba::neverallow_receipt(&e));
        d.receipts.extend(ba::isolated_without_cpu_receipt(&e, ncpus));
        d.install = Err(InstallRefusal::Admission(e));
        return d;
    }
    let tasks = topo.tasks();
    d.rows = tasks.len();
    let step = ba::deadline_step(topo, ncpus);
    d.receipts.extend(step.receipts().copied());
    d.deadline = Some(step.outcome);
    if let DeadlineOutcome::Admitted(r) | DeadlineOutcome::BandRefused(r, _) = step.outcome {
        for &(row, cpu) in &r.placement[..r.placed as usize] {
            let t = &tasks[row as usize];
            d.placed.push(Placed {
                row,
                name: t.name.as_str().to_string(),
                cpu,
                density_ppm: profile_density(&t.profile).unwrap_or(0),
            });
        }
    }
    d.huge = ba::huge_leaves_refusal(topo).map(|(i, t)| (i, t.name.as_str().to_string(), t.mem_huge_mib));
    for (i, t) in tasks.iter().enumerate() {
        let name = t.name.as_bytes();
        if name.ends_with(b".ELF") && seccomp::profile_named(name).is_none() {
            d.unfiltered.push((i, t.name.as_str().to_string(), t.start));
        }
    }
    d
}

/// Parse `SCHED.TOM` then `CAPS.TOM` (the kernel's order) into a fresh
/// topology and dry-boot it.
pub fn dry_boot_files(caps: &[u8], sched: &[u8], cpus: usize) -> DryBoot {
    let mut t = Box::new(Topology::empty());
    let parsed = azos_topology::parse_sched(sched, &mut t)
        .map_err(|error| InstallRefusal::Parse { sched: true, error })
        .and_then(|_| azos_topology::parse_caps(caps, &mut t).map_err(|error| InstallRefusal::Parse { sched: false, error }));
    match parsed {
        Ok(()) => dry_boot(&t, cpus),
        Err(e) => DryBoot::new(cpus, Err(e)),
    }
}

/// The report `azos_sim` prints: one line per finding, the records as
/// `why list` prints them (`ProvenanceRecord::write_line`) after `receipt`.
pub fn write_report(d: &DryBoot, w: &mut impl Write) -> fmt::Result {
    match &d.install {
        Ok(()) => writeln!(w, "install: admitted, {} row(s)", d.rows)?,
        Err(e) => writeln!(w, "install: REFUSED: {e:?}")?,
    }
    for (i, r) in d.receipts.iter().enumerate() {
        let mut line = String::new();
        r.provenance(i as u64 + 1).write_line(&mut line)?;
        writeln!(w, "receipt {}", line.trim_end())?;
    }
    match &d.deadline {
        Some(DeadlineOutcome::Refused(e)) => writeln!(w, "deadline: REFUSED on {} CPU(s): {e:?}", d.cpus)?,
        Some(DeadlineOutcome::BandRefused(_, e)) => writeln!(
            w,
            "deadline: REFUSED: {e:?}: the band's rows on that CPU exceed RT_BAND_CAP_PCT={} %",
            azos_limits::RT_BAND_CAP_PCT
        )?,
        Some(DeadlineOutcome::Admitted(_)) | None => {}
    }
    for p in &d.placed {
        writeln!(w, "place: row {} ({}) on CPU {}, {} ppm", p.row, p.name, p.cpu, p.density_ppm)?;
    }
    if let Some(DeadlineOutcome::Admitted(r) | DeadlineOutcome::BandRefused(r, _)) = &d.deadline {
        for (cpu, &ppm) in r.cpu_load_ppm.iter().enumerate().take(d.cpus) {
            if ppm != 0 {
                writeln!(w, "load: CPU {cpu} {ppm} ppm, {} ppm free", azos_topology::deadline::PPM.saturating_sub(ppm))?;
            }
        }
    }
    if let Some((row, name, mib)) = &d.huge {
        writeln!(w, "memory: REFUSED: row {row} ({name}) declares mem_huge_mib = {mib} on a kernel without LOCKED_HUGE_LEAVES")?;
    }
    for (row, name, start) in &d.unfiltered {
        writeln!(
            w,
            "filter: row {row} ({name}) has no filter row in the build's table: an exec of it is refused{}",
            if *start { ", and the row starts at boot" } else { "" }
        )?;
    }
    if d.install.is_ok() {
        writeln!(w, "chain: no slack computed: the topology declares no per-hop timing")?;
    }
    writeln!(w, "verdict: {}", if d.boots() { "boots" } else { "refused" })
}

/// What a boot's console says about its admission (the `[TOPO]` lines
/// `kernel/src/boot/topology.rs` prints), for [`check_boot_log`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BootLog {
    /// `Topology install FAILED: <InitError>`: the install-time check refused.
    InstallFailed(String),
    /// Installed: the records the deadline step wrote, rebuilt from the
    /// console, and the refusal text if the step halted the boot.
    Admission { receipts: Vec<Receipt>, refusal: Option<String> },
}

/// The text after `prefix` on the first line holding it.
fn after<'l>(log: &'l str, prefix: &str) -> Option<&'l str> {
    log.lines().find_map(|l| l.find(prefix).map(|i| l[i + prefix.len()..].trim_end()))
}

/// Read a boot's console (`cpus` = the harts it booted, QEMU's `-smp`). The
/// records are rebuilt from what the kernel prints next to writing them: the
/// row count from `Topology installed`, `placed` from `Deadline admission:
/// <P> real-time task(s)` (absent when nothing was placed), the verdicts from
/// the `REFUSED` lines; the band record's cap is this build's
/// `RT_BAND_CAP_PCT`, the same `KCONFIG_CONFIG`'s.
pub fn read_boot_log(log: &str, cpus: usize) -> Result<BootLog, String> {
    use azos_decision::{Rule, Verdict};
    const HALT: &str = " — halting";
    if let Some(e) = after(log, "[TOPO] Topology install FAILED: ") {
        return Ok(BootLog::InstallFailed(e.trim_end_matches(HALT).to_string()));
    }
    let rows: u64 = after(log, "[TOPO] Topology installed: ")
        .and_then(|s| s.split(", ").nth(1)?.strip_suffix(" tasks")?.parse().ok())
        .ok_or("no `[TOPO] Topology installed: <C> classes, <T> tasks` line")?;
    let subject = cpus as u32;
    if let Some(e) = after(log, "[TOPO] Deadline admission REFUSED on ") {
        let (n, why) = e.split_once(" CPU(s): ").ok_or("a `Deadline admission REFUSED on` line without its CPU count")?;
        if n != cpus.to_string() {
            return Err(format!("the boot refused on {n} CPU(s), not the {cpus} it was given"));
        }
        let r = Receipt { rule: Rule::DeadlineAdmission, verdict: Verdict::Refuse, subject, numbers: [0, rows, 0] };
        return Ok(BootLog::Admission { receipts: vec![r], refusal: Some(why.trim_end_matches(HALT).to_string()) });
    }
    let placed: u64 = match after(log, "[TOPO] Deadline admission: ") {
        Some(s) => s.split(' ').next().and_then(|p| p.parse().ok()).ok_or("an unreadable `Deadline admission:` line")?,
        None => 0,
    };
    let mut receipts = vec![Receipt { rule: Rule::DeadlineAdmission, verdict: Verdict::Admit, subject, numbers: [placed, rows, 0] }];
    let band = after(log, "[TOPO] Deadline admission REFUSED: ").map(|e| e.split(" — the band's").next().unwrap_or(e).to_string());
    if placed > 0 {
        let verdict = if band.is_some() { Verdict::Refuse } else { Verdict::Admit };
        receipts.push(Receipt { rule: Rule::RtBandCap, verdict, subject, numbers: [placed, azos_limits::RT_BAND_CAP_PCT as u64, 0] });
    }
    Ok(BootLog::Admission { receipts, refusal: band })
}

/// Hold a dry boot to a real boot's console: the same install verdict, the
/// same records, the same refusal. `Err` names the first difference.
pub fn check_boot_log(d: &DryBoot, boot: &BootLog) -> Result<(), String> {
    match (boot, &d.install) {
        (BootLog::InstallFailed(k), Err(e)) => {
            let s = format!("{e:?}");
            if *k == s { Ok(()) } else { Err(format!("install refused: the boot says {k}, the dry boot {s}")) }
        }
        (BootLog::InstallFailed(k), Ok(())) => Err(format!("the boot refused the install ({k}), the dry boot installed it")),
        (BootLog::Admission { .. }, Err(e)) => Err(format!("the boot installed the topology, the dry boot refused it: {e:?}")),
        (BootLog::Admission { receipts, refusal }, Ok(())) => {
            // The third number of these two rules is the refused row's, which
            // the console names in the refusal text compared below; the
            // records are compared on the rest.
            let key = |r: &Receipt| (r.rule, r.verdict, r.subject, r.numbers[0], r.numbers[1]);
            if !receipts.iter().map(key).eq(d.receipts.iter().map(key)) {
                return Err(format!("records: the boot wrote {receipts:?}, the dry boot {:?}", d.receipts));
            }
            let sim = match &d.deadline {
                Some(DeadlineOutcome::Refused(e)) => Some(format!("{e:?}")),
                Some(DeadlineOutcome::BandRefused(_, e)) => Some(format!("{e:?}")),
                _ => None,
            };
            if *refusal == sim { Ok(()) } else { Err(format!("refusal: the boot says {refusal:?}, the dry boot {sim:?}")) }
        }
    }
}

#[cfg(test)]
mod tests;

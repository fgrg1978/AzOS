// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The forensic check of an exported security log: `logd`'s files in, a
//! verdict out. The checks are `azos_seclog::verify`'s; this is the reading
//! of the files (ordered by the serial each opens with) and the two checks
//! only a reader off the device can make:
//!
//! * `--tpm-anchor`: the value the TPM's extend index holds now (read with
//!   any TPM tool, `tpm2_nvread 0x01500003`). A whole, untouched export ends
//!   with it. A different value: seals are missing from the export, or the
//!   export was rewritten, however consistent with itself.
//! * `--witness`: a capture of the device's console. Every `seclog: seal`
//!   line in it must be a seal of the export.
//!
//! Without either, an export rewritten whole, every head and anchor
//! recomputed, cannot be refuted, and the report says the export is not
//! anchored.

use azos_seclog::text::{self, Parsed};
use azos_seclog::verify::{Finding, Summary, Verifier};
use azos_seclog::{kind, Hash, Seal};
use std::fmt::Write as _;

#[allow(dead_code)]
#[path = "../../../../crates/drivers/sys/src/klog/wire.rs"]
mod wire;

/// What a reader off the device brings.
#[derive(Default, Clone)]
pub struct Options {
    pub tpm_anchor: Option<Hash>,
    /// `(head, anchor)` of each seal the console showed.
    pub witness: Vec<(Hash, Hash)>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Verdict {
    Intact,
    /// Records are missing that the log itself accounts for (rotation, a loss
    /// the kernel declared, an unsealed tail), or the seals are advisory.
    Incomplete,
    Evidence,
}

impl Verdict {
    pub fn exit_code(self) -> i32 {
        match self {
            Verdict::Intact => 0,
            Verdict::Incomplete => 1,
            Verdict::Evidence => 2,
        }
    }
}

pub struct Report {
    pub findings: Vec<Finding>,
    /// What only the off-device checks found.
    pub external: Vec<String>,
    pub summary: Summary,
    pub verdict: Verdict,
    pub anchored: bool,
}

pub fn hex32(s: &str) -> Option<Hash> {
    let s = s.trim();
    if s.len() != 64 {
        return None;
    }
    let mut h = [0u8; 32];
    for (i, b) in h.iter_mut().enumerate() {
        *b = u8::from_str_radix(s.get(2 * i..2 * i + 2)?, 16).ok()?;
    }
    Some(h)
}

fn hex(h: &Hash) -> String {
    h.iter().map(|b| format!("{b:02x}")).collect()
}

/// The seals a console capture shows: `seclog: seal <n> through <seq> head
/// <hex> anchor <hex> <backend>`, anywhere on a line.
pub fn parse_witness(capture: &str) -> Vec<(Hash, Hash)> {
    capture
        .lines()
        .filter_map(|l| {
            let t: Vec<&str> = l[l.find("seclog: seal ")?..].split_whitespace().collect();
            (t.len() >= 9 && t[3] == "through" && t[5] == "head" && t[7] == "anchor").then_some(())?;
            Some((hex32(t[6])?, hex32(t[8])?))
        })
        .collect()
}

/// The file's serial (its opening line), for the order.
fn serial(file: &[u8]) -> Option<u64> {
    let first = file.split(|&b| b == b'\n').next()?;
    wire::head_serial(&wire::parse(first)?)
}

/// Check the files of an export, given their contents, in any order.
pub fn verify(files: &[Vec<u8>], opts: &Options) -> Report {
    let mut order: Vec<&Vec<u8>> = files.iter().collect();
    order.sort_by_key(|f| serial(f).unwrap_or(0));
    let mut v = Verifier::new();
    let mut findings = Vec::new();
    let mut seals: Vec<Seal> = Vec::new();
    for f in order {
        for line in f.split(|&b| b == b'\n') {
            let Some(l) = wire::parse(line) else { continue };
            let security = l.module == wire::SECURITY_MODULE;
            if !security && l.module != wire::LOGD_MODULE {
                continue;
            }
            match text::parse(l.msg) {
                Some(Parsed::Seam) => v.seam(),
                Some(Parsed::Record { env, payload }) if security => {
                    if env.kind == kind::SEAL {
                        seals.extend(Seal::decode(&payload[..env.len as usize]));
                    }
                    v.record(&env, &payload, &mut |x| findings.push(x));
                }
                _ => {}
            }
        }
    }
    let summary = v.finish(&mut |x| findings.push(x));
    let mut external = Vec::new();
    let opts = if cfg!(feature = "canary-no-external-check") { &Options::default() } else { opts };
    if let Some(live) = opts.tpm_anchor {
        if summary.last_anchor != Some(live) {
            external.push(format!(
                "tpm: the index holds {} and the export ends at {}: seals are missing from the export, or it was rewritten",
                hex(&live),
                summary.last_anchor.as_ref().map_or("no anchor".into(), hex)
            ));
        }
    }
    for (head, anchor) in &opts.witness {
        if !seals.iter().any(|s| s.head == *head && s.anchor == *anchor) {
            external.push(format!("witness: the console's seal head {} anchor {} is not in the export", hex(head), hex(anchor)));
        }
    }
    let anchored = opts.tpm_anchor.is_some() || !opts.witness.is_empty();
    let verdict = if summary.evidence > 0 || !external.is_empty() {
        Verdict::Evidence
    } else if !findings.is_empty() || !anchored {
        Verdict::Incomplete
    } else {
        Verdict::Intact
    };
    Report { findings, external, summary, verdict, anchored }
}

fn describe(f: &Finding) -> String {
    match *f {
        Finding::Truncated { boot, first } => format!("boot {boot}: the export begins at record {first}; the records before it are not in it"),
        Finding::Gap { boot, first, count, declared: true } => {
            format!("boot {boot}: {count} records from {first} lost before they were sealed (the kernel declared it)")
        }
        Finding::Gap { boot, first, count, declared: false } => {
            format!("boot {boot}: {count} records from {first} are missing, and the kernel declared no loss")
        }
        Finding::Reorder { boot, seq, after } => format!("boot {boot}: record {seq} comes after record {after}"),
        Finding::Rewrite { boot, seq } => format!("boot {boot}: the seal at {seq} does not match the records before it: one was rewritten, added or removed"),
        Finding::Unverifiable { boot, seq } => format!("boot {boot}: the seal at {seq} covers records that are missing; it cannot be checked"),
        Finding::AnchorMismatch { boot, seq } => format!("boot {boot}: the seal at {seq} names an anchor its head does not give: a seal was forged or one is missing"),
        Finding::LinkBroken { boot } => format!("boot {boot}: its anchor is not the last seal the TPM took before it: that seal's records are missing, or the anchor was reset"),
        Finding::Unsealed { boot, count } => format!("boot {boot}: {count} records after the last seal; no seal covers them"),
        Finding::Advisory { boot } => format!("boot {boot}: its seals are advisory (no hardware held them)"),
        Finding::Malformed { boot, seq } => format!("boot {boot}: record {seq} does not decode as its kind"),
    }
}

/// The report as text.
pub fn render(r: &Report) -> String {
    let mut o = String::new();
    for f in &r.findings {
        let tag = if f.is_evidence() { "EVIDENCE" } else { "note" };
        let _ = writeln!(o, "{tag}: {}", describe(f));
    }
    for e in &r.external {
        let _ = writeln!(o, "EVIDENCE: {e}");
    }
    let s = &r.summary;
    let _ = writeln!(
        o,
        "boots {}, records {} ({} events), seals {} ({} checked, {} held by hardware), backend {}",
        s.boots,
        s.records,
        s.events,
        s.seals,
        s.seals_verified,
        s.seals_hardware,
        s.backend.map_or("none", |b| b.name())
    );
    if let Some(a) = &s.last_anchor {
        let _ = writeln!(o, "last anchor {}", hex(a));
    }
    if !r.anchored {
        let _ = writeln!(o, "not anchored: pass --tpm-anchor or --witness; offline, an export rewritten whole is consistent with itself");
    }
    let _ = writeln!(o, "verdict: {:?}", r.verdict);
    o
}

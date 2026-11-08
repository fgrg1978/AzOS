// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The forensic check of an exported security log: `logd`'s files in, a
//! verdict out. The checks are `azos_seclog::verify`'s; this is the reading
//! of the files (ordered by the serial each opens with) and the two checks
//! only a reader off the device can make:
//!
//! * `--tpm-anchor` and `--tpm-counter`: the values the TPM's extend index
//!   and counter index hold now (read with any TPM tool, `tpm2_nvread
//!   0x01500003`, `tpm2_nvread 0x01500004`). A whole, untouched export ends
//!   with them (or with a seal the TPM took whose record a crash lost, which
//!   the export's last records give). A different value: seals are missing
//!   from the export, or the export was rewritten, however consistent with
//!   itself.
//! * `--witness`: a capture of the device's console. Every `seclog: seal`
//!   line in it (at the start of a line, the kernel's form) must be a seal of
//!   the export. A task that writes the same console can print such a line
//!   too: a witness line no seal matches is evidence of a removed seal or of
//!   a console someone else wrote to, and the report says which seal it is.
//!
//! The files' serials must follow each other: a file missing between two the
//! export has is evidence (the oldest ones rotate out at the start).
//!
//! Without either, an export rewritten whole, every head and anchor
//! recomputed, cannot be refuted, and the report says the export is not
//! anchored.

use azos_seclog::text::{self, Parsed};
use azos_seclog::verify::{By, Finding, Live, Summary, Verifier};
use azos_seclog::{kind, Hash, Seal};
use std::fmt::Write as _;

#[allow(dead_code)]
#[path = "../../../../crates/drivers/sys/src/klog/wire.rs"]
mod wire;

/// What a reader off the device brings.
#[derive(Default, Clone)]
pub struct Options {
    pub tpm_anchor: Option<Hash>,
    pub tpm_counter: Option<u64>,
    /// Each seal the console showed.
    pub witness: Vec<Witnessed>,
}

/// A seal line of the console: the boot's nonce, the seal's number, its head
/// and anchor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Witnessed {
    pub nonce: u64,
    pub count: u32,
    pub head: Hash,
    pub anchor: Hash,
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
    /// What they found that an honest device also shows.
    pub notes: Vec<String>,
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

/// The seals a console capture shows: lines that begin `seclog: seal <n>
/// through <seq> counter <c> nonce <hex> head <hex> anchor <hex> <backend>`.
pub fn parse_witness(capture: &str) -> Vec<Witnessed> {
    capture
        .lines()
        .filter_map(|l| {
            let t: Vec<&str> = l.trim_start_matches('\r').strip_prefix("seclog: seal ")?.split_whitespace().collect();
            (t.len() >= 11 && t[1] == "through" && t[3] == "counter" && t[5] == "nonce" && t[7] == "head" && t[9] == "anchor")
                .then_some(())?;
            Some(Witnessed {
                nonce: u64::from_str_radix(t[6], 16).ok()?,
                count: t[0].parse().ok()?,
                head: hex32(t[8])?,
                anchor: hex32(t[10])?,
            })
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
    let mut external = Vec::new();
    let serials: Vec<u64> = order.iter().filter_map(|f| serial(f)).collect();
    for w in serials.windows(2) {
        if w[1] > w[0] + 1 {
            external.push(format!("files: serial {} to {} are missing between two files the export has", w[0] + 1, w[1] - 1));
        }
    }
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
    let opts = if cfg!(feature = "canary-no-external-check") { &Options::default() } else { opts };
    let mut notes = Vec::new();
    if let Some(live) = opts.tpm_anchor {
        match v.live(&live, opts.tpm_counter) {
            Live::Whole => {}
            Live::Refused => notes.push("tpm: the index holds a seal the export says it refused: it took it, and its answer was lost".to_string()),
            Live::CrashSeal { through } => notes.push(format!(
                "tpm: the index holds a seal whose record a crash lost, over the records before {through}"
            )),
            Live::Differs => external.push(format!(
                "tpm: the index holds {}{} and the export ends at {}{}: seals are missing from the export, or it was rewritten",
                hex(&live),
                opts.tpm_counter.map_or(String::new(), |c| format!(" (counter {c})")),
                summary.last_anchor.as_ref().map_or("no anchor".into(), hex),
                summary.last_counter.map_or(String::new(), |c| format!(" (counter {c})")),
            )),
        }
    }
    for w in &opts.witness {
        if !seals.iter().any(|s| s.nonce == w.nonce && s.count == w.count && s.head == w.head && s.anchor == w.anchor) {
            external.push(format!(
                "witness: the console's seal {} of boot {:016x} (head {} anchor {}) is not in the export",
                w.count,
                w.nonce,
                hex(&w.head),
                hex(&w.anchor)
            ));
        }
    }
    let anchored = opts.tpm_anchor.is_some() || !opts.witness.is_empty();
    let verdict = if summary.evidence > 0 || !external.is_empty() {
        Verdict::Evidence
    } else if !findings.is_empty() || !notes.is_empty() || !anchored {
        Verdict::Incomplete
    } else {
        Verdict::Intact
    };
    Report { findings, external, notes, summary, verdict, anchored }
}

fn class_name(c: u8) -> &'static str {
    azos_seclog::Class::from_u8(c).map_or("unknown-class", |c| c.name())
}

fn describe(f: &Finding) -> String {
    match *f {
        Finding::Truncated { boot, first, explained: true } => {
            format!("boot {boot}: the export begins at record {first}; the records before it rotated out or were declared lost")
        }
        Finding::Truncated { boot, first, explained: false } => {
            format!("boot {boot}: its records before {first} are not in the export, and nobody declared them lost")
        }
        Finding::Gap { boot, first, count, by: By::Sealer } => {
            format!("boot {boot}: {count} records from {first} lost before they were sealed (the kernel declared it)")
        }
        Finding::Gap { boot, first, count, by: By::Sink } => {
            format!("boot {boot}: {count} records from {first} sealed but not written by logd (the kernel declared it)")
        }
        Finding::Gap { boot, first, count, by: By::Nobody } => {
            format!("boot {boot}: {count} records from {first} are missing, and the kernel declared no loss")
        }
        Finding::Reorder { boot, seq, after } => format!("boot {boot}: record {seq} comes after record {after}"),
        Finding::Rewrite { boot, seq } => format!("boot {boot}: the seal at {seq} does not match the records before it: one was rewritten, added or removed"),
        Finding::Unverifiable { boot, seq, declared: true } => {
            format!("boot {boot}: the seal at {seq} covers records logd lost (declared); their contents cannot be checked")
        }
        Finding::Unverifiable { boot, seq, declared: false } => format!("boot {boot}: the seal at {seq} covers records that are missing; it cannot be checked"),
        Finding::AnchorMismatch { boot, seq } => format!("boot {boot}: the seal at {seq} names an anchor the one before it does not give: a seal was forged or one is missing"),
        Finding::Diverged { boot, seq } => format!("boot {boot}: at the seal at {seq} the TPM held a value this boot did not extend: something else extended the index"),
        Finding::LinkBroken { boot } => format!("boot {boot}: its anchor is not the last seal the TPM took before it: that seal's boot is missing, or the anchor was reset"),
        Finding::CounterGap { boot, seq: u64::MAX } => format!("boot {boot}: the TPM counter at boot does not follow the last seal's: seals are missing"),
        Finding::CounterGap { boot, seq } => format!("boot {boot}: the TPM counter of the seal at {seq} does not follow the last seal's: seals are missing"),
        Finding::AnchorMissing { boot, explained: true } => format!("boot {boot}: its anchor record is among the records before the export's start"),
        Finding::AnchorMissing { boot, explained: false } => format!("boot {boot}: it has seals and no anchor record, and nobody declared it lost"),
        Finding::Unsealed { boot, count } => format!("boot {boot}: {count} records after the last seal; no seal covers them"),
        Finding::CrashSeal { boot, through } => {
            format!("boot {boot}: the TPM took a seal whose record a crash lost; it covers the records before {through}")
        }
        Finding::Advisory { boot } => format!("boot {boot}: its seals are advisory (no hardware held them)"),
        Finding::Downgrade { boot, reason } => {
            format!("boot {boot}: it seals forward-only after a boot the TPM sealed ({})", reason.name())
        }
        Finding::ClassLost { boot, class, count, sink: false } => {
            format!("boot {boot}: {count} {} records lost before they were sealed (the kernel declared it)", class_name(class))
        }
        Finding::ClassLost { boot, class, count, sink: true } => {
            format!("boot {boot}: {count} {} records sealed and not written by logd (the kernel declared it)", class_name(class))
        }
        Finding::Held { boot, class, count } => format!("boot {boot}: the rate cap held back {count} {} records", class_name(class)),
        Finding::Malformed { boot, seq } => format!("boot {boot}: record {seq} does not decode as its kind, or has a shape the kernel never writes"),
        Finding::DeclarationMismatch { boot, seq } => format!(
            "boot {boot}: the sink-loss declarations before the seal at {seq} do not add up to what the seal says the kernel declared: one was added or removed"
        ),
        Finding::UncoveredDeclaration { boot, seq } => format!(
            "boot {boot}: the loss declared at {seq} is covered by no seal: anyone who can write the volume can add one, and it explains nothing"
        ),
    }
}

/// The report as text.
pub fn render(r: &Report) -> String {
    let mut o = String::new();
    for f in &r.findings {
        let tag = if f.is_evidence() {
            "EVIDENCE"
        } else if f.high_value_loss() {
            "LOSS"
        } else {
            "note"
        };
        let _ = writeln!(o, "{tag}: {}", describe(f));
    }
    for e in &r.external {
        let _ = writeln!(o, "EVIDENCE: {e}");
    }
    for n in &r.notes {
        let _ = writeln!(o, "note: {n}");
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

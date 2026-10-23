// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The provenance record: a [`crate::Record`] plus the fields that
//! say WHO and WHAT the decision was about (owner plan, Phase 0 hook).
//!
//! Three forms, one meaning:
//!
//! * the full form, [`ProvenanceRecord`], [`SIZE`] bytes, little-endian, what
//!   a reader on the host or a future network sink exchanges
//!   ([`ProvenanceRecord::to_bytes`] / [`ProvenanceRecord::from_bytes`]);
//! * the word form, [`WORDS`] 64-bit words ([`ProvenanceRecord::to_words`] /
//!   [`ProvenanceRecord::from_words`]), what the journal stores and the
//!   `Decisions` interface carries (its replies are seven words at most, so
//!   the interface splits it in two);
//! * the compact form of the durable refusal receipt, which has to fit the
//!   flight recorder's 20-byte payload ([`compact_base`], [`compact_ext`],
//!   [`ProvenanceRecord::from_compact`]).
//!
//! **The split (asserted below and in the host tests).** The compact form is
//! two payloads. The BASE (`COMPACT_BASE_CODE`, always written) is the
//! receipt: rule, verdict, subject and
//! the three numbers (the first two saturated, the third cut to 40 bits). The
//! EXTENSION (`COMPACT_EXT_CODE`, written only when it has something to say)
//! carries the rule/verdict/subject it belongs to, the
//! `image_hash_prefix` and the `topology_row_id`. NOT durable, because
//! 20 bytes cannot hold them: `cap_slot`, `parent_cap` (128 bits each),
//! `node_id`, `session_id` and `seq`. They exist in the full form only.
//!
//! **Sources today.** `rule`, `verdict`, `subject` and `n` are
//! real. `seq` is the decision's id (the sequence number every record
//! claims, ring on or off) and `clock_ns` the kernel clock when it was
//! written (0 when no clock was installed). Every
//! other field is reserved until L4 / Phase 9 and stays 0 until a call site
//! has the value: the kernel keeps no image hash per task (it hashes at exec
//! and keeps the profile), no durable refusal site holds a raw capability
//! (`Rule::CapDenial` is a `Deny`, ring only) and none of the boot admissions
//! names the offending topology row.
use core::fmt;

/// Size of the full form. Asserted.
pub const SIZE: usize = 104;

/// Flight-recorder payload code of the compact base (the receipt).
pub const COMPACT_BASE_CODE: u8 = 0x1B;
/// Flight-recorder payload code of the compact extension.
pub const COMPACT_EXT_CODE: u8 = 0x1C;
/// The flight recorder's payload size (`azos_actuation::logger::LOG_PAYLOAD_BYTES`,
/// asserted equal there).
pub const COMPACT_BYTES: usize = 20;

/// A capability slot named across domains, as the warrant records carry it:
/// the owning domain's key (`azos_sched::domain::Key`) in the high 32 bits, the
/// slot in bits 16..32 and its generation in the low 16. 0 names nothing (a
/// root warrant's parent).
pub const fn warrant_ref(domain_key: u32, slot: u16, generation: u16) -> u64 {
    (domain_key as u64) << 32 | (slot as u64) << 16 | generation as u64
}

/// One decision with its provenance.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
#[repr(C)]
pub struct ProvenanceRecord {
    pub rule: u8,
    pub verdict: u8,
    /// The task id, or a CPU/row count: per rule (`RuleInfo::subject`).
    pub subject: u32,
    /// The decision's id: the sequence number it claimed when it was written
    /// (0: none, the record was never stored).
    pub seq: u64,
    /// The raw 128-bit capability slot the decision was about, as two LE
    /// words (low first). Reserved until L4 / Phase 9: 0.
    pub cap_slot: [u64; 2],
    /// The capability it was derived from. Reserved until L4 / Phase 9: 0.
    pub parent_cap: [u64; 2],
    /// The topology row. 0 = none known (row ids are 1-based on the wire).
    pub topology_row_id: u32,
    /// The node of a distributed system. Reserved until Phase 9: 0.
    pub node_id: u32,
    /// The first 8 bytes of the subject's image SHA-256, big-endian as a
    /// number. 0 = unknown (the kernel keeps none per task today).
    pub image_hash_prefix: u64,
    /// The boot/session the record belongs to. Reserved until Phase 9: 0.
    pub session_id: u64,
    pub n: [u64; 3],
    /// The kernel clock when the decision was written, in nanoseconds of
    /// TAI-based monotonic time (`crate::set_clock` plus `crate::set_tai_offset`:
    /// time since boot until PTP or NTP has set the offset); 0 = no clock
    /// installed.
    pub clock_ns: u64,
}
const _: () = assert!(core::mem::size_of::<ProvenanceRecord>() == SIZE);
const _: () = assert!(core::mem::align_of::<ProvenanceRecord>() == 8);
const _: () = assert!(COMPACT_BYTES == 20);

/// Why a record did not decode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProvError {
    /// Fewer bytes than the form needs.
    Short,
    /// The compact payload's code byte is not the base / extension code.
    Code(u8),
    /// The extension belongs to another decision than the base.
    Mismatch,
}

// Wire offsets of the full form. Written out, not `offset_of!`, so a reader
// in another language has them; the test checks them against the struct.
pub const OFF_RULE: usize = 0;
pub const OFF_VERDICT: usize = 1;
pub const OFF_SUBJECT: usize = 4;
pub const OFF_SEQ: usize = 8;
pub const OFF_CAP_SLOT: usize = 16;
pub const OFF_PARENT_CAP: usize = 32;
pub const OFF_TOPOLOGY_ROW: usize = 48;
pub const OFF_NODE: usize = 52;
pub const OFF_IMAGE: usize = 56;
pub const OFF_SESSION: usize = 64;
pub const OFF_N: usize = 72;
pub const OFF_CLOCK: usize = 96;

/// Words of the word form.
pub const WORDS: usize = 13;

fn put32(b: &mut [u8], at: usize, v: u32) {
    b[at..at + 4].copy_from_slice(&v.to_le_bytes());
}
fn put64(b: &mut [u8], at: usize, v: u64) {
    b[at..at + 8].copy_from_slice(&v.to_le_bytes());
}
fn get32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}
fn get64(b: &[u8], at: usize) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[at..at + 8]);
    u64::from_le_bytes(a)
}

impl ProvenanceRecord {
    /// A record with the reserved fields at 0.
    pub const fn new(rule: u8, verdict: u8, subject: u32, n: [u64; 3]) -> Self {
        Self {
            rule,
            verdict,
            subject,
            seq: 0,
            cap_slot: [0; 2],
            parent_cap: [0; 2],
            topology_row_id: 0,
            node_id: 0,
            image_hash_prefix: 0,
            session_id: 0,
            n,
            clock_ns: 0,
        }
    }

    /// The ring's record, widened. The warrant rules (`Rule::CapDerive`,
    /// `Rule::CapRevoke`) carry the capability and its parent as packed
    /// references ([`warrant_ref`]) in their first two numbers; those become
    /// `cap_slot` and `parent_cap` (low word) and leave `n[0]`, `n[1]` 0. Every
    /// other provenance field is 0.
    pub fn from_record(r: &crate::Record) -> Self {
        let mut p = Self::new(r.rule, r.verdict, r.subject, r.n);
        p.seq = r.seq;
        p.clock_ns = crate::ticks_to_tai_ns(r.ts);
        if r.rule == crate::Rule::CapDerive as u8 || r.rule == crate::Rule::CapRevoke as u8 {
            p.cap_slot = [r.n[0], 0];
            p.parent_cap = [r.n[1], 0];
            p.n[0] = 0;
            p.n[1] = 0;
        }
        p
    }

    pub fn to_bytes(&self) -> [u8; SIZE] {
        let mut b = [0u8; SIZE];
        b[OFF_RULE] = self.rule;
        b[OFF_VERDICT] = self.verdict;
        put32(&mut b, OFF_SUBJECT, self.subject);
        put64(&mut b, OFF_SEQ, self.seq);
        for i in 0..2 {
            put64(&mut b, OFF_CAP_SLOT + 8 * i, self.cap_slot[i]);
            put64(&mut b, OFF_PARENT_CAP + 8 * i, self.parent_cap[i]);
        }
        put32(&mut b, OFF_TOPOLOGY_ROW, self.topology_row_id);
        put32(&mut b, OFF_NODE, self.node_id);
        put64(&mut b, OFF_IMAGE, self.image_hash_prefix);
        put64(&mut b, OFF_SESSION, self.session_id);
        for i in 0..3 {
            put64(&mut b, OFF_N + 8 * i, self.n[i]);
        }
        put64(&mut b, OFF_CLOCK, self.clock_ns);
        b
    }

    /// The word form: `[rule | verdict << 8 | subject << 32, seq, clock_ns,
    /// n0, n1, n2, image_hash_prefix, topology_row_id | node_id << 32,
    /// session_id, cap_slot lo, hi, parent_cap lo, hi]`.
    pub const fn to_words(&self) -> [u64; WORDS] {
        [
            self.rule as u64 | (self.verdict as u64) << 8 | (self.subject as u64) << 32,
            self.seq,
            self.clock_ns,
            self.n[0],
            self.n[1],
            self.n[2],
            self.image_hash_prefix,
            self.topology_row_id as u64 | (self.node_id as u64) << 32,
            self.session_id,
            self.cap_slot[0],
            self.cap_slot[1],
            self.parent_cap[0],
            self.parent_cap[1],
        ]
    }

    /// The record a word form means ([`Self::to_words`] undone).
    pub const fn from_words(w: &[u64; WORDS]) -> Self {
        Self {
            rule: w[0] as u8,
            verdict: (w[0] >> 8) as u8,
            subject: (w[0] >> 32) as u32,
            seq: w[1],
            cap_slot: [w[9], w[10]],
            parent_cap: [w[11], w[12]],
            topology_row_id: w[7] as u32,
            node_id: (w[7] >> 32) as u32,
            image_hash_prefix: w[6],
            session_id: w[8],
            n: [w[3], w[4], w[5]],
            clock_ns: w[2],
        }
    }

    /// Decode the full form.
    pub fn from_bytes(b: &[u8]) -> Result<Self, ProvError> {
        if b.len() < SIZE {
            return Err(ProvError::Short);
        }
        Ok(Self {
            rule: b[OFF_RULE],
            verdict: b[OFF_VERDICT],
            subject: get32(b, OFF_SUBJECT),
            seq: get64(b, OFF_SEQ),
            cap_slot: [get64(b, OFF_CAP_SLOT), get64(b, OFF_CAP_SLOT + 8)],
            parent_cap: [get64(b, OFF_PARENT_CAP), get64(b, OFF_PARENT_CAP + 8)],
            topology_row_id: get32(b, OFF_TOPOLOGY_ROW),
            node_id: get32(b, OFF_NODE),
            image_hash_prefix: get64(b, OFF_IMAGE),
            session_id: get64(b, OFF_SESSION),
            n: [get64(b, OFF_N), get64(b, OFF_N + 8), get64(b, OFF_N + 16)],
            clock_ns: get64(b, OFF_CLOCK),
        })
    }

    /// The extension payload this record needs, if it has anything the base
    /// does not carry (`image_hash_prefix` or `topology_row_id` set).
    pub fn compact_ext(&self) -> Option<[u8; COMPACT_BYTES]> {
        if self.image_hash_prefix == 0 && self.topology_row_id == 0 {
            return None;
        }
        Some(compact_ext(self.rule, self.verdict, self.subject, self.image_hash_prefix, self.topology_row_id))
    }

    /// Decode the compact form: the base payload and, if it was written,
    /// the extension that follows it. Fields the compact form does not carry
    /// come back 0; the base's first two numbers are as saturated.
    pub fn from_compact(base: &[u8], ext: Option<&[u8]>) -> Result<Self, ProvError> {
        if base.len() < COMPACT_BYTES {
            return Err(ProvError::Short);
        }
        if base[0] != COMPACT_BASE_CODE {
            return Err(ProvError::Code(base[0]));
        }
        let mut p = Self::new(
            base[1],
            base[2],
            get32(base, 4),
            [get32(base, 8) as u64, get32(base, 12) as u64, get32(base, 16) as u64 | (base[3] as u64) << 32],
        );
        if let Some(e) = ext {
            if e.len() < COMPACT_BYTES {
                return Err(ProvError::Short);
            }
            if e[0] != COMPACT_EXT_CODE {
                return Err(ProvError::Code(e[0]));
            }
            if e[1] != p.rule || e[2] != p.verdict || get32(e, 4) != p.subject {
                return Err(ProvError::Mismatch);
            }
            p.image_hash_prefix = get64(e, 8);
            p.topology_row_id = get32(e, 16);
        }
        Ok(p)
    }

    /// Is this a run-time reservation's refusal (`Rule::DeadlineAdmission`,
    /// `Verdict::Refuse`, a reason in bits 32..40 of the third number)? The
    /// rule has two writers whose names share a table row, split at `|`: the
    /// boot admission (first) and this (second).
    fn is_rt_refusal(&self) -> bool {
        self.rule == crate::Rule::DeadlineAdmission as u8
            && self.verdict == crate::Verdict::Refuse as u8
            && self.n[2] >> 32 != 0
    }

    /// The receipt a refused use of a receipt-conditioned warrant lacked, if
    /// this is that record ([`crate::receipt`]); a word that does not decode
    /// prints as plain numbers.
    fn receipt_refusal(&self) -> Option<crate::receipt::Refusal> {
        if self.rule == crate::Rule::ReceiptCaveat as u8 {
            crate::receipt::Refusal::decode(self.n[0])
        } else {
            None
        }
    }

    /// The name this record's writer uses out of a `boot|run-time` pair.
    fn alt(&self, s: &'static str) -> &'static str {
        match s.split_once('|') {
            Some((boot, run)) => {
                if self.is_rt_refusal() {
                    run
                } else {
                    boot
                }
            }
            None => s,
        }
    }

    /// One line, as `why list` and the recovery console print it. The provenance fields are
    /// printed only when set, so a record without any reads as a plain line.
    pub fn write_line(&self, w: &mut impl fmt::Write) -> fmt::Result {
        let Some(info) = crate::RULES.get(self.rule as usize) else {
            return write!(w, "{} rule={}\n", self.seq, self.rule);
        };
        let verdict = crate::VERDICTS.get(self.verdict as usize).copied().unwrap_or("?");
        write!(w, "{} {} {} {}={}", self.seq, info.name, verdict, self.alt(info.subject), self.subject)?;
        if let Some(r) = self.receipt_refusal() {
            r.write_numbers(self.n[1], self.n[2], w)?;
        } else {
            for (k, v) in info.fields.iter().zip(self.n) {
                let k = self.alt(k);
                // "-": not used by the rule. "?name": printed when not zero.
                if let Some(opt) = k.strip_prefix('?') {
                    if v != 0 {
                        write!(w, " {}={}", opt, v)?;
                    }
                } else if k != "-" {
                    write!(w, " {}={}", k, v)?;
                }
            }
        }
        if self.cap_slot != [0; 2] {
            write!(w, " cap={:016x}{:016x}", self.cap_slot[1], self.cap_slot[0])?;
        }
        if self.parent_cap != [0; 2] {
            write!(w, " parent={:016x}{:016x}", self.parent_cap[1], self.parent_cap[0])?;
        }
        if self.topology_row_id != 0 {
            write!(w, " row={}", self.topology_row_id)?;
        }
        if self.image_hash_prefix != 0 {
            write!(w, " image={:016x}", self.image_hash_prefix)?;
        }
        if self.node_id != 0 {
            write!(w, " node={}", self.node_id)?;
        }
        if self.session_id != 0 {
            write!(w, " session={}", self.session_id)?;
        }
        if self.clock_ns != 0 {
            write!(w, " clock={}", self.clock_ns)?;
        }
        let yes = self.verdict == crate::Verdict::Admit as u8 || self.verdict == crate::Verdict::Place as u8;
        write!(w, " rejected=\"{}\"\n", if yes { info.rejected_if_yes } else { info.rejected_if_no })
    }

    /// The chain `why` prints, one fact a line: what decided (the rule and
    /// its verdict), about whom, the numbers it compared (by name), the
    /// alternative it rejected, then the provenance that is known (`-` where
    /// no call site has the value yet, see the module doc) and the clock.
    ///
    /// A run-time reservation's refusal (`Rule::DeadlineAdmission`,
    /// `Verdict::Refuse`, a reason in bits 32..40; the boot admission has
    /// none) packs its third number (`rt_core::refusal_numbers`):
    /// the budget still available below bit 32, the reason above; the chain
    /// prints them apart and names the reason ([`crate::REFUSAL_REASONS`]).
    pub fn write_chain(&self, w: &mut impl fmt::Write) -> fmt::Result {
        let Some(info) = crate::RULES.get(self.rule as usize) else {
            return write!(w, "decision {}: unknown rule {}\n", self.seq, self.rule);
        };
        let verdict = crate::VERDICTS.get(self.verdict as usize).copied().unwrap_or("?");
        write!(w, "decision {}: {} {}\n", self.seq, info.name, verdict)?;
        write!(w, "  rule      {}\n", info.name)?;
        write!(w, "  verdict   {}\n", verdict)?;
        write!(w, "  subject   {}={}\n", self.alt(info.subject), self.subject)?;
        write!(w, "  numbers  ")?;
        if let Some(r) = self.receipt_refusal() {
            r.write_numbers(self.n[1], self.n[2], w)?;
        } else if self.is_rt_refusal() {
            let reason = (self.n[2] >> 32) as usize;
            write!(
                w,
                " runtime_us={} period_us={} available_us={} reason={}({})",
                self.n[0],
                self.n[1],
                self.n[2] as u32,
                reason,
                crate::REFUSAL_REASONS.get(reason).copied().unwrap_or("?"),
            )?;
        } else {
            let mut any = false;
            for (k, v) in info.fields.iter().zip(self.n) {
                let k = self.alt(k);
                if let Some(opt) = k.strip_prefix('?') {
                    if v != 0 {
                        write!(w, " {}={}", opt, v)?;
                        any = true;
                    }
                } else if k != "-" {
                    write!(w, " {}={}", k, v)?;
                    any = true;
                }
            }
            if !any {
                write!(w, " -")?;
            }
        }
        write!(w, "\n")?;
        let yes = self.verdict == crate::Verdict::Admit as u8 || self.verdict == crate::Verdict::Place as u8;
        write!(w, "  rejected  {}\n", if yes { info.rejected_if_yes } else { info.rejected_if_no })?;
        let hex128 = |w: &mut dyn fmt::Write, name: &str, v: [u64; 2]| -> fmt::Result {
            if v == [0; 2] {
                write!(w, "  {:<9} -\n", name)
            } else {
                write!(w, "  {:<9} {:016x}{:016x}\n", name, v[1], v[0])
            }
        };
        hex128(w, "cap", self.cap_slot)?;
        hex128(w, "parent", self.parent_cap)?;
        if self.topology_row_id == 0 {
            write!(w, "  row       -\n")?;
        } else {
            write!(w, "  row       {}\n", self.topology_row_id)?;
        }
        if self.image_hash_prefix == 0 {
            write!(w, "  image     -\n")?;
        } else {
            write!(w, "  image     {:016x}\n", self.image_hash_prefix)?;
        }
        if self.clock_ns == 0 {
            write!(w, "  clock     -\n")
        } else {
            write!(w, "  clock     {} ns ({}.{:06} s)\n", self.clock_ns, self.clock_ns / 1_000_000_000, self.clock_ns % 1_000_000_000 / 1000)
        }
    }
}

const fn sat(v: u64) -> u32 {
    if v > u32::MAX as u64 { u32::MAX } else { v as u32 }
}

/// The compact base: the durable refusal receipt.
///
/// | bytes  | field |
/// |--------|-------|
/// | 0      | [`COMPACT_BASE_CODE`] |
/// | 1      | rule |
/// | 2      | verdict |
/// | 3      | bits 32..39 of the third number |
/// | 4..8   | subject |
/// | 8..12  | first number, saturated to `u32::MAX` |
/// | 12..16 | second number, saturated to `u32::MAX` |
/// | 16..20 | low 32 bits of the third number |
pub const fn compact_base(rule: u8, verdict: u8, subject: u32, n: [u64; 3]) -> [u8; COMPACT_BYTES] {
    let mut p = [0u8; COMPACT_BYTES];
    p[0] = COMPACT_BASE_CODE;
    p[1] = rule;
    p[2] = verdict;
    p[3] = (n[2] >> 32) as u8;
    let s = subject.to_le_bytes();
    let a = sat(n[0]).to_le_bytes();
    let b = sat(n[1]).to_le_bytes();
    let c = (n[2] as u32).to_le_bytes();
    let mut i = 0;
    while i < 4 {
        p[4 + i] = s[i];
        p[8 + i] = a[i];
        p[12 + i] = b[i];
        p[16 + i] = c[i];
        i += 1;
    }
    p
}

/// The compact extension.
///
/// | bytes  | field |
/// |--------|-------|
/// | 0      | [`COMPACT_EXT_CODE`] |
/// | 1      | rule (of the base it follows) |
/// | 2      | verdict (likewise) |
/// | 3      | 0 |
/// | 4..8   | subject (likewise) |
/// | 8..16  | `image_hash_prefix` |
/// | 16..20 | `topology_row_id` |
pub const fn compact_ext(rule: u8, verdict: u8, subject: u32, image: u64, row: u32) -> [u8; COMPACT_BYTES] {
    let mut p = [0u8; COMPACT_BYTES];
    p[0] = COMPACT_EXT_CODE;
    p[1] = rule;
    p[2] = verdict;
    let s = subject.to_le_bytes();
    let im = image.to_le_bytes();
    let r = row.to_le_bytes();
    let mut i = 0;
    while i < 4 {
        p[4 + i] = s[i];
        p[16 + i] = r[i];
        i += 1;
    }
    i = 0;
    while i < 8 {
        p[8 + i] = im[i];
        i += 1;
    }
    p
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::string::String;

    fn full() -> ProvenanceRecord {
        ProvenanceRecord {
            rule: 4,
            verdict: 3,
            subject: 0x0A0B_0C0D,
            seq: 0x1111_2222_3333_4444,
            cap_slot: [0x01, 0x02],
            parent_cap: [0x03, 0x04],
            topology_row_id: 0x55,
            node_id: 0x66,
            image_hash_prefix: 0x7777_8888_9999_AAAA,
            session_id: 0xBBBB,
            n: [0xC1, 0xC2, 0xC3],
            clock_ns: 0xDDDD_EEEE,
        }
    }

    /// **Canary.** Change `SIZE` or add a field: the const assert does not
    /// compile (a build error is the red).
    #[test]
    fn round_trip_every_field() {
        let p = full();
        assert_eq!(ProvenanceRecord::from_bytes(&p.to_bytes()), Ok(p));
    }

    /// Each field at its documented offset. **Canary.** Swap two `put*` calls
    /// in `to_bytes`: the offset the assertion names goes red.
    #[test]
    fn fields_sit_at_their_offsets() {
        let b = full().to_bytes();
        assert_eq!((b[OFF_RULE], b[OFF_VERDICT]), (4, 3));
        assert_eq!(get32(&b, OFF_SUBJECT), 0x0A0B_0C0D);
        assert_eq!(get64(&b, OFF_SEQ), 0x1111_2222_3333_4444);
        assert_eq!((get64(&b, OFF_CAP_SLOT), get64(&b, OFF_CAP_SLOT + 8)), (1, 2));
        assert_eq!((get64(&b, OFF_PARENT_CAP), get64(&b, OFF_PARENT_CAP + 8)), (3, 4));
        assert_eq!(get32(&b, OFF_TOPOLOGY_ROW), 0x55);
        assert_eq!(get32(&b, OFF_NODE), 0x66);
        assert_eq!(get64(&b, OFF_IMAGE), 0x7777_8888_9999_AAAA);
        assert_eq!(get64(&b, OFF_SESSION), 0xBBBB);
        assert_eq!((get64(&b, OFF_N), get64(&b, OFF_N + 8), get64(&b, OFF_N + 16)), (0xC1, 0xC2, 0xC3));
        assert_eq!(get64(&b, OFF_CLOCK), 0xDDDD_EEEE);
        assert_eq!(core::mem::offset_of!(ProvenanceRecord, clock_ns), OFF_CLOCK);
        // The wire offsets are the struct's.
        assert_eq!(core::mem::offset_of!(ProvenanceRecord, seq), OFF_SEQ);
        assert_eq!(core::mem::offset_of!(ProvenanceRecord, cap_slot), OFF_CAP_SLOT);
        assert_eq!(core::mem::offset_of!(ProvenanceRecord, parent_cap), OFF_PARENT_CAP);
        assert_eq!(core::mem::offset_of!(ProvenanceRecord, topology_row_id), OFF_TOPOLOGY_ROW);
        assert_eq!(core::mem::offset_of!(ProvenanceRecord, image_hash_prefix), OFF_IMAGE);
        assert_eq!(core::mem::offset_of!(ProvenanceRecord, n), OFF_N);
    }

    /// **Canary.** Drop the length test in `from_bytes`: the short inputs
    /// index out of range or decode, red.
    #[test]
    fn a_short_record_is_refused() {
        let b = full().to_bytes();
        assert_eq!(ProvenanceRecord::from_bytes(&b[..SIZE - 1]), Err(ProvError::Short));
        assert_eq!(ProvenanceRecord::from_bytes(&[1]), Err(ProvError::Short));
        assert_eq!(ProvenanceRecord::from_bytes(&[]), Err(ProvError::Short));
    }

    /// The split: what the compact form carries and what it drops.
    /// **Canary.** Move `topology_row_id` to bytes 12..16 of the extension:
    /// the round trip and the placement go red.
    #[test]
    fn the_compact_split() {
        let p = full();
        let base = compact_base(p.rule, p.verdict, p.subject, p.n);
        let ext = p.compact_ext().expect("image and row are set");
        assert_eq!(base[0], COMPACT_BASE_CODE);
        assert_eq!(ext[0], COMPACT_EXT_CODE);
        assert_eq!(&ext[8..16], &p.image_hash_prefix.to_le_bytes());
        assert_eq!(&ext[16..20], &p.topology_row_id.to_le_bytes());
        let q = ProvenanceRecord::from_compact(&base, Some(&ext)).unwrap();
        // Carried:
        assert_eq!((q.rule, q.verdict, q.subject), (4, 3, 0x0A0B_0C0D));
        assert_eq!((q.image_hash_prefix, q.topology_row_id, q.n), (p.image_hash_prefix, 0x55, p.n));
        // Dropped, by design (do not fit 20 bytes):
        assert_eq!((q.seq, q.cap_slot, q.parent_cap, q.node_id, q.session_id), (0, [0; 2], [0; 2], 0, 0));
    }

    /// No extension when it would say nothing; the base alone decodes.
    #[test]
    fn no_extension_without_image_or_row() {
        let mut p = ProvenanceRecord::new(1, 1, 7, [5, 6, 7]);
        p.cap_slot = [9, 9]; // not durable: does not call for an extension
        assert_eq!(p.compact_ext(), None);
        p.topology_row_id = 3;
        assert!(p.compact_ext().is_some());
        let q = ProvenanceRecord::from_compact(&compact_base(1, 1, 7, [5, 6, 7]), None).unwrap();
        assert_eq!((q.rule, q.verdict, q.subject, q.n), (1, 1, 7, [5, 6, 7]));
    }

    /// **Canary.** Drop the `Mismatch` test: an extension of another
    /// decision attaches, red.
    #[test]
    fn the_compact_decoder_refuses_what_does_not_belong() {
        let base = compact_base(1, 1, 7, [1, 2, 3]);
        let other = compact_ext(1, 1, 8, 5, 5);
        assert_eq!(ProvenanceRecord::from_compact(&base, Some(&other)), Err(ProvError::Mismatch));
        let mut e = compact_ext(1, 1, 7, 5, 5);
        e[0] = COMPACT_BASE_CODE;
        assert_eq!(ProvenanceRecord::from_compact(&base, Some(&e)), Err(ProvError::Code(COMPACT_BASE_CODE)));
        let mut b = base;
        b[0] = 0x1A;
        assert_eq!(ProvenanceRecord::from_compact(&b, None), Err(ProvError::Code(0x1A)));
        assert_eq!(ProvenanceRecord::from_compact(&base[..19], None), Err(ProvError::Short));
    }

    /// The third number is cut at 40 bits and the first two saturate.
    #[test]
    fn the_base_keeps_the_receipt_layout() {
        let b = compact_base(3, 1, 0xAABB_CCDD, [5, u64::MAX, 0x1_2345_6789]);
        assert_eq!(&b[0..4], &[COMPACT_BASE_CODE, 3, 1, 1]);
        let q = ProvenanceRecord::from_compact(&b, None).unwrap();
        assert_eq!(q.n, [5, u32::MAX as u64, 0x1_2345_6789]);
    }

    /// The line: unchanged for a record without provenance, longer with it.
    /// **Canary.** Print `row` always: the first assertion goes red.
    #[test]
    fn the_line_shows_provenance_only_when_set() {
        let mut s = String::new();
        let mut p = ProvenanceRecord::new(4, 3, 9, [1, 2, 0]);
        p.seq = 12;
        p.write_line(&mut s).unwrap();
        assert!(s.starts_with("12 cap-denial deny tid=9 kind=1 reason=2 rejected="), "{s}");
        for k in [" cap=", " parent=", " row=", " image=", " node=", " session="] {
            assert!(!s.contains(k), "{k} printed for a record without it: {s}");
        }
        p.cap_slot = [0xAB, 0x1];
        p.topology_row_id = 3;
        p.image_hash_prefix = 0xFEED;
        s.clear();
        p.write_line(&mut s).unwrap();
        assert!(s.contains(" cap=0000000000000001") && s.contains("00000000000000ab"), "{s}");
        assert!(s.contains(" row=3 image=000000000000feed rejected="), "{s}");
        p.clock_ns = 1234;
        s.clear();
        p.write_line(&mut s).unwrap();
        assert!(s.contains(" image=000000000000feed clock=1234 rejected="), "{s}");
    }

    /// A warrant record widens into the provenance fields. **Canary.** Skip
    /// the rule test in `from_record`: `cap_slot` stays 0 and this goes red.
    #[test]
    fn a_warrant_record_fills_cap_slot_and_parent() {
        let r = crate::Record {
            seq: 3,
            rule: crate::Rule::CapDerive as u8,
            verdict: crate::Verdict::Admit as u8,
            subject: 9,
            n: [warrant_ref(9, 4, 2), warrant_ref(7, 1, 5), 0],
            ts: 0,
        };
        let p = ProvenanceRecord::from_record(&r);
        assert_eq!(p.cap_slot, [warrant_ref(9, 4, 2), 0]);
        assert_eq!(p.parent_cap, [warrant_ref(7, 1, 5), 0]);
        assert_eq!(p.n, [0, 0, 0]);
        let mut s = String::new();
        p.write_line(&mut s).unwrap();
        assert!(s.contains(" cap=") && s.contains(" parent=") && s.contains("cap-derive admit domain=9"), "{s}");
    }

    /// The chain of a refused run-time reservation names the rule, the numbers
    /// by name, the reason and the budget that was available apart, and `-`
    /// for the provenance no call site has yet. **Canary.** Print the third
    /// number whole (drop the `n[2] >> 32` test): the reason line goes red.
    #[test]
    fn the_chain_of_a_refused_reservation() {
        let mut p = ProvenanceRecord::new(crate::Rule::DeadlineAdmission as u8, crate::Verdict::Refuse as u8, 7, [500, 1000, 2 << 32 | 40]);
        p.seq = 12;
        p.clock_ns = 3_000_001_000;
        let mut s = String::new();
        p.write_chain(&mut s).unwrap();
        for want in [
            "decision 12: deadline-admission refuse\n",
            "  rule      deadline-admission\n",
            "  verdict   refuse\n",
            "  subject   tid=7\n",
            "  numbers   runtime_us=500 period_us=1000 available_us=40 reason=2(no-room)\n",
            "  rejected  run the rows (or the task): some row cannot meet its deadline on these CPUs\n",
            "  cap       -\n",
            "  parent    -\n",
            "  row       -\n",
            "  image     -\n",
            "  clock     3000001000 ns (3.000001 s)\n",
        ] {
            assert!(s.contains(want), "missing {want:?} in:\n{s}");
        }
    }

    /// A boot refusal of the same rule has no packed reason: its numbers print
    /// through the rule's table. The provenance prints where it is set.
    #[test]
    fn the_chain_of_a_boot_refusal_and_of_a_warrant() {
        let mut s = String::new();
        ProvenanceRecord::new(crate::Rule::DeadlineAdmission as u8, crate::Verdict::Refuse as u8, 2, [0, 5, 0])
            .write_chain(&mut s)
            .unwrap();
        assert!(s.contains("  subject   cpus=2\n") && s.contains("  numbers   placed=0 rows=5\n"), "{s}");
        s.clear();
        // A refusal that names its row (`DeadlineRefusal::record_row`: row 3).
        ProvenanceRecord::new(crate::Rule::DeadlineAdmission as u8, crate::Verdict::Refuse as u8, 2, [0, 5, 4])
            .write_chain(&mut s)
            .unwrap();
        assert!(s.contains("  numbers   placed=0 rows=5 row+1=4\n"), "{s}");
        s.clear();
        let mut p = ProvenanceRecord::new(crate::Rule::CapDerive as u8, crate::Verdict::Admit as u8, 9, [0, 0, 77]);
        p.cap_slot = [0xAB, 0x1];
        p.parent_cap = [0x5, 0];
        p.topology_row_id = 3;
        p.image_hash_prefix = 0xFEED;
        p.write_chain(&mut s).unwrap();
        assert!(s.contains("  cap       000000000000000100000000000000ab\n"), "{s}");
        assert!(s.contains("  parent    00000000000000000000000000000005\n"), "{s}");
        assert!(s.contains("  row       3\n") && s.contains("  image     000000000000feed\n"), "{s}");
        assert!(s.contains("  numbers   expiry_ns=77\n"), "{s}");
        s.clear();
        ProvenanceRecord::new(99, 0, 0, [0; 3]).write_chain(&mut s).unwrap();
        assert!(s.contains("unknown rule 99"), "{s}");
    }
}

// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The first number of a `Rule::ReceiptCaveat` record: which receipt a use of
//! a receipt-conditioned warrant lacked. The capability resolve writes it
//! (`azos_ipc::cap::caveat::receipt::record_word`) and the printers read it
//! ([`crate::ProvenanceRecord::write_chain`], `write_line`: `why` and the
//! recovery console), so the layout lives here, below both.
//!
//! Layout: the caveat kind ([`CAVEAT`]) in bits 0..8, the device 8..24 (the
//! recorder's `effect kind << 8 | subject`), the receipt kind 24..32 (the
//! effect's class: [`KIND_SAFE`] toward the safe state, [`KIND_REVERSIBLE`])
//! and the cause 32..40; the rest is 0. The record's second number is the age
//! (ms) of the newest receipt of the kind (0 when the device left none), the
//! third the limit (ms).
use core::fmt;

/// The caveat kind of a receipt caveat (`azos_ipc::cap::caveat::RECEIPT`, held
/// equal by a const assertion there).
pub const CAVEAT: u8 = 5;
/// Receipt kind: an effect toward the safe state (a stop).
pub const KIND_SAFE: u8 = 0;
/// Receipt kind: a reversible effect (a drive).
pub const KIND_REVERSIBLE: u8 = 1;

/// Cause: the device has left no receipt of the kind.
pub const MISSING: u8 = 1;
/// Cause: the newest receipt of the kind is older than the caveat allows.
pub const OLD: u8 = 2;
/// Cause: a later receipt of the contrary kind contradicts it.
pub const CONTRADICTED: u8 = 3;

/// The word for a refused use.
pub const fn word(device: u16, kind: u8, cause: u8) -> u64 {
    CAVEAT as u64 | (device as u64) << 8 | (kind as u64) << 24 | (cause as u64) << 32
}

/// A [`word`], taken apart.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Refusal {
    pub device: u16,
    pub kind: u8,
    pub cause: u8,
}

impl Refusal {
    /// `None` for a word that is not one: another caveat kind, a cause that is
    /// not one of the three, a bit past the layout.
    pub const fn decode(w: u64) -> Option<Refusal> {
        let cause = (w >> 32) as u8;
        if w as u8 != CAVEAT || w >> 40 != 0 || cause < MISSING || cause > CONTRADICTED {
            return None;
        }
        Some(Refusal { device: (w >> 8) as u16, kind: (w >> 24) as u8, cause })
    }

    /// What the cause says.
    pub const fn cause_name(&self) -> &'static str {
        match self.cause {
            MISSING => "missing",
            OLD => "old",
            _ => "contradicted",
        }
    }

    /// What the receipt kind is.
    pub const fn kind_name(&self) -> &'static str {
        match self.kind {
            KIND_SAFE => "safe-state",
            KIND_REVERSIBLE => "reversible",
            _ => "?",
        }
    }

    /// The numbers of the record as the printers show them: the device by its
    /// effect kind and subject, the receipt kind, the cause, then the age
    /// (only when a receipt existed to have one) and the limit.
    pub fn write_numbers(&self, age_ms: u64, limit_ms: u64, w: &mut impl fmt::Write) -> fmt::Result {
        write!(
            w,
            " device={}:{} receipt={}({}) cause={}",
            self.device >> 8,
            self.device & 0xff,
            self.kind,
            self.kind_name(),
            self.cause_name()
        )?;
        if self.cause != MISSING {
            write!(w, " age_ms={}", age_ms)?;
        }
        write!(w, " limit_ms={}", limit_ms)
    }
}

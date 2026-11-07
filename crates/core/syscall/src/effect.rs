// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The envelope rule of an effect a task asks for on its own account, the
//! privacy effects: capturing the room's sound (`mic`, `Sound` capture) and
//! its picture (`cam`, `Frame`). **Default-deny**: a scheduler class has the
//! effect only when an `[envelope.NAME]` row of that kind names the class at a
//! level other than `contained`. No row, no topology, or a task seeded from no
//! row: no effect, and the refusal is a decision record.

use azos_topology::{EffectKind, EnvelopeSpec, MaybeStr};
#[cfg(test)]
use core::sync::atomic::{AtomicU32, Ordering};

/// Does the class have the effect `kind`: is there a row for the class and
/// the kind that does not contain it?
pub fn admitted(kind: EffectKind, envelopes: &[EnvelopeSpec<'_>], class: &MaybeStr<'_>) -> bool {
    #[cfg(feature = "effect-default-allow-canary")]
    return !envelopes
        .iter()
        .any(|e| e.kind == kind && e.class == *class && e.level == azos_topology::Envelope::Contained);
    #[cfg(not(feature = "effect-default-allow-canary"))]
    envelopes
        .iter()
        .any(|e| e.kind == kind && e.class == *class && e.level != azos_topology::Envelope::Contained)
}

/// The effects the host suites grant every task (a bit per kind): they install
/// no topology (it is installed once per process), so there is no row to ask.
#[cfg(test)]
static GRANTED: AtomicU32 = AtomicU32::new(0);

/// Grant the effect `kind` to every task (host suites only).
#[cfg(test)]
pub fn grant_all(kind: EffectKind) {
    GRANTED.fetch_or(1 << kind as u32, Ordering::AcqRel);
}

/// Tasks whose effect the host suites withhold though they grant it to all
/// (kind, tid; tid 0: free slot).
#[cfg(test)]
static WITHHELD: [(AtomicU32, AtomicU32); 8] = [const { (AtomicU32::new(0), AtomicU32::new(0)) }; 8];

/// Withhold the effect `kind` from `tid` (host suites only).
#[cfg(test)]
pub fn withhold(kind: EffectKind, tid: u32) {
    for (k, t) in &WITHHELD {
        if t.compare_exchange(0, tid, Ordering::AcqRel, Ordering::Acquire).is_ok() {
            k.store(kind as u32, Ordering::Release);
            return;
        }
    }
}

/// Take back every grant and withholding (host suites only).
#[cfg(test)]
pub fn clear_withheld() {
    GRANTED.store(0, Ordering::Release);
    for (_, t) in &WITHHELD {
        t.store(0, Ordering::Release);
    }
}

/// Is the effect `kind` admitted for task `tid`'s scheduler class? Without an
/// installed topology there is no row to grant it, and a task seeded from no
/// row has no class: no.
pub fn task_has(kind: EffectKind, tid: u32) -> bool {
    #[cfg(test)]
    if WITHHELD.iter().any(|(k, t)| t.load(Ordering::Acquire) == tid && k.load(Ordering::Acquire) == kind as u32) {
        return false;
    }
    #[cfg(test)]
    if GRANTED.load(Ordering::Acquire) & (1 << kind as u32) != 0 {
        return true;
    }
    let Some(topo) = azos_topology::get() else { return false };
    let Some(task) = crate::natfork::row_of(tid).and_then(|row| topo.tasks().get(row)) else { return false };
    admitted(kind, topo.envelopes(), &task.class_name)
}

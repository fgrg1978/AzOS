// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The envelope rule of an effect a task asks for on its own account: a
//! scheduler class has the effect unless an `[envelope.NAME]` row of that kind
//! for the class caps it at `contained`. The microphone (`Sound` capture) and
//! the camera (`Frame`) ask it for the requester.

use azos_topology::{EffectKind, EnvelopeSpec, MaybeStr};
#[cfg(test)]
use core::sync::atomic::{AtomicU32, Ordering};

/// Does the class have the effect `kind`?
pub fn admitted(kind: EffectKind, envelopes: &[EnvelopeSpec<'_>], class: &MaybeStr<'_>) -> bool {
    !envelopes
        .iter()
        .any(|e| e.kind == kind && e.class == *class && e.level == azos_topology::Envelope::Contained)
}

/// Tasks whose effect the host suites withhold (kind, tid; tid 0: free slot):
/// they install no topology (it is installed once per process), so the class
/// lookup has nothing to ask.
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

/// Give every task its effects again (host suites only).
#[cfg(test)]
pub fn clear_withheld() {
    for (_, t) in &WITHHELD {
        t.store(0, Ordering::Release);
    }
}

/// Is the effect `kind` admitted for task `tid`'s scheduler class? No topology
/// installed: there are no classes to cap. With one, a task seeded from no row
/// has no class and so no grant.
pub fn task_has(kind: EffectKind, tid: u32) -> bool {
    #[cfg(test)]
    if WITHHELD.iter().any(|(k, t)| t.load(Ordering::Acquire) == tid && k.load(Ordering::Acquire) == kind as u32) {
        return false;
    }
    let Some(topo) = azos_topology::get() else { return true };
    let Some(task) = crate::natfork::row_of(tid).and_then(|row| topo.tasks().get(row)) else { return false };
    admitted(kind, topo.envelopes(), &task.class_name)
}

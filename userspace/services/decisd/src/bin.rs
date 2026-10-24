// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The server's [`Source`]: the kernel's decision records decoded.
//!
//! The kernel publishes the decisions it still holds as
//! [`PROVENANCE_SIZE`]-byte `ProvenanceRecord::to_bytes` records, oldest
//! first, the newest `DECISION_VIEW_ROWS` (`decisions/records/<n>` of the admin introspection
//! region); `main.rs` copies them back to back and [`BinSource::load`] decodes
//! them into a fixed table; nothing here reads the tree, so the host
//! suite (`tests/host/decisions-tests`) pulls this file in with `#[path]` and
//! drives it through the generated stubs.
use azos_decisions::{Filter, ProvenanceRecord, Source, PROVENANCE_SIZE};

/// Records the table holds: the kernel publishes as many (Kconfig
/// `DECISION_VIEW_ROWS`, `kernel/src/boot/inspect_views.rs`).
pub const MAX: usize = azos_decisions::VIEW_ROWS;

/// The decoded snapshot, oldest first.
pub struct BinSource {
    recs: [ProvenanceRecord; MAX],
    n: usize,
}

impl BinSource {
    pub const fn new() -> Self {
        Self { recs: [ProvenanceRecord::new(0, 0, 0, [0; 3]); MAX], n: 0 }
    }

    /// Replace the snapshot with the whole records in `bytes` (a partial tail
    /// is ignored, records past [`MAX`] are dropped, oldest first). The count
    /// kept.
    pub fn load(&mut self, bytes: &[u8]) -> usize {
        let whole = bytes.len() / PROVENANCE_SIZE;
        // Keep the newest if there are more than the table holds.
        let skip = whole.saturating_sub(MAX);
        self.n = 0;
        for i in skip..whole {
            if let Ok(p) = ProvenanceRecord::from_bytes(&bytes[i * PROVENANCE_SIZE..(i + 1) * PROVENANCE_SIZE]) {
                // A record with no id was never stored: not a decision.
                if p.seq != 0 {
                    self.recs[self.n] = p;
                    self.n += 1;
                }
            }
        }
        self.n
    }
}

impl Source for BinSource {
    /// The newest id held: the records carry no count of their own.
    fn total(&self) -> u64 {
        self.recs[..self.n].iter().map(|p| p.seq).max().unwrap_or(0)
    }

    fn query(&self, f: &Filter, out: &mut [u64]) -> usize {
        let mut k = 0;
        // Ids ascend in the records; sorted anyway, so a reordered set still
        // answers oldest first.
        let mut last = f.after;
        while k < out.len() {
            let next = self.recs[..self.n]
                .iter()
                .filter(|p| p.seq > last && f.matches(p))
                .min_by_key(|p| p.seq);
            let Some(p) = next else { break };
            out[k] = p.seq;
            last = p.seq;
            k += 1;
        }
        k
    }

    fn lookup(&self, id: u64) -> Option<ProvenanceRecord> {
        self.recs[..self.n].iter().find(|p| p.seq == id).copied()
    }
}

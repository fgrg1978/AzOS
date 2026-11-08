// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The hash chain and the sealer's state: pure, so the kernel's pass and the
//! host tests run the same code.

use crate::{canon, kind, Backend, Envelope, Hash, Loss, Seal, CANON_MAX};
use azos_crypto::sha256::{sha256, Sha256};

/// The head before a boot's first record.
pub fn genesis() -> Hash {
    sha256(b"azos/seclog/v1")
}

/// The head after `head` and the record `canon` (its canonical bytes).
pub fn fold_canon(head: &Hash, canon: &[u8]) -> Hash {
    let mut h = Sha256::new();
    h.update(head);
    h.update(canon);
    h.finalize()
}

/// The head after `head` and the record `env`, `payload`.
pub fn fold(head: &Hash, env: &Envelope, payload: &[u8]) -> Hash {
    let mut c = [0u8; CANON_MAX];
    let n = canon(env, payload, &mut c);
    fold_canon(head, &c[..n])
}

/// The backend's value after `anchor` committed `head` (TPM2_NV_Extend of a
/// SHA-256 index).
pub fn extend(anchor: &Hash, head: &Hash) -> Hash {
    let mut h = Sha256::new();
    h.update(anchor);
    h.update(head);
    h.finalize()
}

/// The sealer: the chain's head through the records it folded, and the
/// backend's value.
#[derive(Clone, Copy, Debug)]
pub struct Sealer {
    head: Hash,
    anchor: Hash,
    backend: Backend,
    next: u64,
    count: u32,
    unsealed: u64,
}

impl Sealer {
    /// A boot's sealer: the backend it seals to and the value that held at
    /// boot. It expects the ring's first record, sequence 0.
    pub fn new(backend: Backend, boot_anchor: Hash) -> Sealer {
        Sealer { head: genesis(), anchor: boot_anchor, backend, next: 0, count: 0, unsealed: 0 }
    }

    /// The next sequence number it expects.
    pub fn next(&self) -> u64 {
        self.next
    }

    pub fn head(&self) -> Hash {
        self.head
    }

    pub fn backend(&self) -> Backend {
        self.backend
    }

    /// Records folded since the last seal, seals excepted: a seal is due.
    pub fn unsealed(&self) -> u64 {
        self.unsealed
    }

    /// The records from [`next`](Self::next) up to `seq` were never folded:
    /// the loss to declare (in a [`kind::LOSS`] record), `None` when there
    /// is none. The sealer goes on at `seq`.
    pub fn skip_to(&mut self, seq: u64) -> Option<Loss> {
        let loss = (seq > self.next).then(|| Loss { first: self.next, count: seq - self.next });
        self.next = self.next.max(seq);
        loss
    }

    /// Fold the record `env`, `payload`, which is the next one (a record
    /// before [`next`](Self::next) is not folded twice).
    pub fn fold(&mut self, env: &Envelope, payload: &[u8]) -> bool {
        if env.seq < self.next {
            return false;
        }
        self.head = fold(&self.head, env, payload);
        self.next = env.seq + 1;
        if env.kind != kind::SEAL {
            self.unsealed += 1;
        }
        true
    }

    /// The seal of the head now, after the backend took it (`hardware`: it
    /// accepted the commit). The anchor advances whether or not it did: the
    /// record says which.
    pub fn seal(&mut self, hardware: bool) -> Seal {
        self.anchor = extend(&self.anchor, &self.head);
        self.count += 1;
        self.unsealed = 0;
        Seal { backend: self.backend, hardware, count: self.count, through: self.next, head: self.head, anchor: self.anchor }
    }
}

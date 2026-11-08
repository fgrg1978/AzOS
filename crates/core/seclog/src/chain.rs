// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The hash chain and the sealer's state: pure, so the kernel's pass and the
//! host tests run the same code.

use crate::{canon, kind, Backend, Envelope, Hash, Seal, CANON_MAX, FLAG_DIVERGED, FLAG_HARDWARE};
use azos_crypto::sha256::Sha256;

const TAG_FOLD: u8 = 1;
const TAG_SEAL: u8 = 2;

/// The head before the first record of the boot whose anchor is
/// `boot_anchor` and whose nonce is `nonce`.
pub fn genesis(boot_anchor: &Hash, nonce: u64) -> Hash {
    let mut h = Sha256::new();
    h.update(b"azos/seclog/v2");
    h.update(boot_anchor);
    h.update(&nonce.to_le_bytes());
    h.finalize()
}

/// The head after `head` and the record `canon` (its canonical bytes).
pub fn fold_canon(head: &Hash, canon: &[u8]) -> Hash {
    let mut h = Sha256::new();
    h.update(&[TAG_FOLD]);
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

/// What seal `count` of a boot commits to the backend: the boot, the seal's
/// number, the backend's counter, the first sequence number it does not
/// cover and the head.
pub fn seal_data(boot_anchor: &Hash, nonce: u64, count: u32, counter: u64, through: u64, head: &Hash) -> Hash {
    let mut h = Sha256::new();
    h.update(&[TAG_SEAL]);
    h.update(boot_anchor);
    h.update(&nonce.to_le_bytes());
    h.update(&count.to_le_bytes());
    h.update(&counter.to_le_bytes());
    h.update(&through.to_le_bytes());
    h.update(head);
    h.finalize()
}

/// What a seal committed.
pub fn data_of(s: &Seal) -> Hash {
    seal_data(&s.boot_anchor, s.nonce, s.count, s.counter, s.through, &s.head)
}

/// The backend's value after `anchor` took `data` (TPM2_NV_Extend of a
/// SHA-256 index).
pub fn extend(anchor: &Hash, data: &Hash) -> Hash {
    let mut h = Sha256::new();
    h.update(anchor);
    h.update(data);
    h.finalize()
}

/// The sealer: the chain's head through the records it folded, and the
/// backend's value.
#[derive(Clone, Copy, Debug)]
pub struct Sealer {
    head: Hash,
    anchor: Hash,
    boot_anchor: Hash,
    nonce: u64,
    backend: Backend,
    next: u64,
    count: u32,
    unsealed: u64,
}

impl Sealer {
    /// A boot's sealer: the backend it seals to, the value that held at boot
    /// and the boot's nonce. It expects the ring's first record, sequence 0.
    pub fn new(backend: Backend, boot_anchor: Hash, nonce: u64) -> Sealer {
        Sealer {
            head: genesis(&boot_anchor, nonce),
            anchor: boot_anchor,
            boot_anchor,
            nonce,
            backend,
            next: 0,
            count: 0,
            unsealed: 0,
        }
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

    /// The backend's value now (the last seal's anchor, or the boot anchor).
    pub fn anchor(&self) -> Hash {
        self.anchor
    }

    /// The boot's nonce.
    pub fn nonce(&self) -> u64 {
        self.nonce
    }

    /// Seals taken this boot.
    pub fn count(&self) -> u32 {
        self.count
    }

    /// Records folded since the last seal, seals excepted: a seal is due.
    pub fn unsealed(&self) -> u64 {
        self.unsealed
    }

    /// The records from [`next`](Self::next) up to `seq` were never folded:
    /// `(first, count)` of the loss to declare, `None` when there is none.
    /// The sealer goes on at `seq`.
    pub fn skip_to(&mut self, seq: u64) -> Option<(u64, u64)> {
        let loss = (seq > self.next).then(|| (self.next, seq - self.next));
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

    /// What the next seal commits, under the backend's counter after its
    /// increment (0 without one).
    pub fn data(&self, counter: u64) -> Hash {
        seal_data(&self.boot_anchor, self.nonce, self.count + 1, counter, self.next, &self.head)
    }

    /// The seal of the head now. `hardware`: the backend took the commit;
    /// `counter`: the backend's counter it was taken under; `held`: the value
    /// the backend was read to hold after it (`None`: not read). The anchor
    /// advances whether or not the hardware took it: the record says which.
    /// A value read back that is not the one the extend gives becomes the
    /// seal's anchor, flagged [`FLAG_DIVERGED`], so the next seal extends what
    /// the backend holds.
    pub fn seal(&mut self, hardware: bool, counter: u64, held: Option<Hash>, extra_flags: u8) -> Seal {
        let data = self.data(counter);
        let prev = self.anchor;
        let expected = extend(&prev, &data);
        let anchor = held.unwrap_or(expected);
        let mut flags = extra_flags;
        if hardware {
            flags |= FLAG_HARDWARE;
        }
        if anchor != expected {
            flags |= FLAG_DIVERGED;
        }
        self.count += 1;
        self.anchor = anchor;
        self.unsealed = 0;
        Seal {
            backend: self.backend,
            flags,
            count: self.count,
            through: self.next,
            counter,
            nonce: self.nonce,
            head: self.head,
            anchor,
            prev,
            boot_anchor: self.boot_anchor,
        }
    }
}

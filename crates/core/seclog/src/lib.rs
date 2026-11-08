// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The sealed security log (Kconfig `SEC_LOG`): the format of its records,
//! the hash chain over them, the seals, the text line `logd` writes and the
//! verifier a forensic tool runs over an exported log.
//!
//! # Where the records are
//!
//! There is one record substrate (`azos_records`): the security records are
//! the records of its security ring, behind the same envelope as the kernel
//! log's and the decisions', and `logd`, the substrate's one sink, writes them
//! to its files as `@security` lines. A record is one of four kinds:
//!
//! * [`kind::EVENT`]: a decision record of a security class ([`Class`]:
//!   a microphone or camera stream, a first packet off the node, a
//!   capability denial, an image load, an update step, a login, a USB
//!   authorization), copied by `azos_decision` when it is written.
//! * [`kind::ANCHOR`]: the boot's link to what came before it: the value the
//!   seal backend held when the boot started ([`Anchor`]).
//! * [`kind::SEAL`]: the head of the chain through a sequence number, and
//!   the value the backend holds after it was committed there ([`Seal`]).
//! * [`kind::LOSS`]: records the sealer never saw (the ring lapped it, or a
//!   producer never finished one) ([`Loss`]): a gap the kernel declares.
//!
//! # The chain
//!
//! Per boot, in sequence order: `head_0 = SHA-256("azos/seclog/v1")`,
//! `head_i = SHA-256(head_{i-1} || canon_i)`, `canon` the record's
//! [canonical bytes](canon) (every envelope field but the source, and the
//! payload). A seal commits a head: the backend's value becomes
//! `anchor_k = SHA-256(anchor_{k-1} || head_k)`, the rule of a TPM 2.0
//! `NV_Extend` into a SHA-256 index, which the TPM computes itself and
//! nothing can set back. The boot's [`Anchor`] record names `anchor_0`: on a
//! TPM, the index's value at boot, which is the previous boot's last seal.
//!
//! What a seal proves depends on where the anchor lives, and every record
//! says which ([`Backend`], [`FLAG_HARDWARE`]): a TPM's index cannot be
//! rewritten by the OS; the forward-only backend keeps the anchor in kernel
//! memory and prints each seal on the console for a receiver off the device,
//! and the local seal is advisory.

#![no_std]

#[cfg(feature = "chain")]
pub mod chain;
pub mod text;
#[cfg(feature = "chain")]
pub mod verify;

pub use azos_rings::region::record::Envelope;

/// The version of the format: the first byte of every record's canonical
/// bytes and the first word of its line.
pub const VERSION: u8 = 1;
/// Payload bytes a security ring slot holds: the largest kind's, a seal's.
pub const PAYLOAD: usize = 80;
/// SHA-256 digest bytes.
pub const HASH: usize = 32;
pub type Hash = [u8; HASH];

/// Bytes of a record's canonical form: its envelope fields and payload.
pub const CANON_MAX: usize = CANON_HDR + PAYLOAD;
const CANON_HDR: usize = 1 + 8 + 8 + 1 + 2 + 1 + 1 + 2;

/// The record kinds: the envelope's `kind`.
pub mod kind {
    pub const EVENT: u16 = 1;
    pub const ANCHOR: u16 = 2;
    pub const SEAL: u16 = 3;
    pub const LOSS: u16 = 4;
}

/// What a security event is about. Numbers 3 (screen capture) and 8 (a
/// debugger's attach) are reserved for classes that have no producer yet.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum Class {
    Microphone = 1,
    Camera = 2,
    Egress = 4,
    CapDenial = 5,
    ImageLoad = 6,
    Update = 7,
    Login = 9,
    Usb = 10,
    /// The decision layer held records of a security rule back (its rate
    /// limit), and says how many: the drop is in the chain.
    Limited = 11,
}

impl Class {
    pub const fn from_u8(v: u8) -> Option<Class> {
        Some(match v {
            1 => Class::Microphone,
            2 => Class::Camera,
            4 => Class::Egress,
            5 => Class::CapDenial,
            6 => Class::ImageLoad,
            7 => Class::Update,
            9 => Class::Login,
            10 => Class::Usb,
            11 => Class::Limited,
            _ => return None,
        })
    }

    pub const fn name(self) -> &'static str {
        match self {
            Class::Microphone => "microphone",
            Class::Camera => "camera",
            Class::Egress => "egress",
            Class::CapDenial => "cap-denial",
            Class::ImageLoad => "image-load",
            Class::Update => "update",
            Class::Login => "login",
            Class::Usb => "usb",
            Class::Limited => "limited",
        }
    }
}

/// Where the anchor of a boot's seals lives.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum Backend {
    /// Kernel memory, each seal printed on the console: advisory on the
    /// device, binding only for a receiver that kept the console.
    Forward = 1,
    /// A TPM 2.0 NV index of type extend.
    TpmNv = 2,
}

impl Backend {
    pub const fn from_u8(v: u8) -> Option<Backend> {
        match v {
            1 => Some(Backend::Forward),
            2 => Some(Backend::TpmNv),
            _ => None,
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            Backend::Forward => "forward-only",
            Backend::TpmNv => "tpm-nv",
        }
    }
}

/// An anchor's or a seal's flag: the value is held by the hardware (read
/// from it, or the extend was accepted). Clear: advisory.
pub const FLAG_HARDWARE: u8 = 1;

fn le64(p: &[u8], at: usize) -> u64 {
    let mut b = [0u8; 8];
    b.copy_from_slice(&p[at..at + 8]);
    u64::from_le_bytes(b)
}

fn le32(p: &[u8], at: usize) -> u32 {
    let mut b = [0u8; 4];
    b.copy_from_slice(&p[at..at + 4]);
    u32::from_le_bytes(b)
}

fn hash_at(p: &[u8], at: usize) -> Hash {
    let mut h = [0u8; HASH];
    h.copy_from_slice(&p[at..at + HASH]);
    h
}

/// A security event: the decision record it copies.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Event {
    /// The decision record's id (0: it was stored nowhere else).
    pub id: u64,
    pub subject: u32,
    pub rule: u8,
    pub verdict: u8,
    pub class: Class,
    pub n: [u64; 3],
    pub image_hash_prefix: u64,
    pub topology_row_id: u32,
}

impl Event {
    pub const LEN: usize = 52;

    pub fn encode(&self) -> [u8; Self::LEN] {
        let mut p = [0u8; Self::LEN];
        p[0..8].copy_from_slice(&self.id.to_le_bytes());
        p[8..12].copy_from_slice(&self.subject.to_le_bytes());
        (p[12], p[13], p[14]) = (self.rule, self.verdict, self.class as u8);
        for (i, v) in self.n.iter().enumerate() {
            p[16 + 8 * i..24 + 8 * i].copy_from_slice(&v.to_le_bytes());
        }
        p[40..48].copy_from_slice(&self.image_hash_prefix.to_le_bytes());
        p[48..52].copy_from_slice(&self.topology_row_id.to_le_bytes());
        p
    }

    pub fn decode(p: &[u8]) -> Option<Event> {
        if p.len() < Self::LEN {
            return None;
        }
        Some(Event {
            id: le64(p, 0),
            subject: le32(p, 8),
            rule: p[12],
            verdict: p[13],
            class: Class::from_u8(p[14])?,
            n: [le64(p, 16), le64(p, 24), le64(p, 32)],
            image_hash_prefix: le64(p, 40),
            topology_row_id: le32(p, 48),
        })
    }
}

/// A boot's link: the backend's value when the boot started.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Anchor {
    pub backend: Backend,
    /// The value was read from the hardware.
    pub hardware: bool,
    pub value: Hash,
}

impl Anchor {
    pub const LEN: usize = 40;

    pub fn encode(&self) -> [u8; Self::LEN] {
        let mut p = [0u8; Self::LEN];
        p[0] = self.backend as u8;
        p[1] = if self.hardware { FLAG_HARDWARE } else { 0 };
        p[8..40].copy_from_slice(&self.value);
        p
    }

    pub fn decode(p: &[u8]) -> Option<Anchor> {
        if p.len() < Self::LEN {
            return None;
        }
        Some(Anchor { backend: Backend::from_u8(p[0])?, hardware: p[1] & FLAG_HARDWARE != 0, value: hash_at(p, 8) })
    }
}

/// A seal: the chain's head over every record before `through`, and the
/// backend's value once that head was committed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Seal {
    pub backend: Backend,
    /// The backend accepted the commit.
    pub hardware: bool,
    /// Seals of this boot, this one included.
    pub count: u32,
    /// The first sequence number the head does not cover.
    pub through: u64,
    pub head: Hash,
    pub anchor: Hash,
}

impl Seal {
    pub const LEN: usize = 80;

    pub fn encode(&self) -> [u8; Self::LEN] {
        let mut p = [0u8; Self::LEN];
        p[0] = self.backend as u8;
        p[1] = if self.hardware { FLAG_HARDWARE } else { 0 };
        p[4..8].copy_from_slice(&self.count.to_le_bytes());
        p[8..16].copy_from_slice(&self.through.to_le_bytes());
        p[16..48].copy_from_slice(&self.head);
        p[48..80].copy_from_slice(&self.anchor);
        p
    }

    pub fn decode(p: &[u8]) -> Option<Seal> {
        if p.len() < Self::LEN {
            return None;
        }
        Some(Seal {
            backend: Backend::from_u8(p[0])?,
            hardware: p[1] & FLAG_HARDWARE != 0,
            count: le32(p, 4),
            through: le64(p, 8),
            head: hash_at(p, 16),
            anchor: hash_at(p, 48),
        })
    }
}

/// Records the sealer never folded: `count` from `first`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Loss {
    pub first: u64,
    pub count: u64,
}

impl Loss {
    pub const LEN: usize = 16;

    pub fn encode(&self) -> [u8; Self::LEN] {
        let mut p = [0u8; Self::LEN];
        p[0..8].copy_from_slice(&self.first.to_le_bytes());
        p[8..16].copy_from_slice(&self.count.to_le_bytes());
        p
    }

    pub fn decode(p: &[u8]) -> Option<Loss> {
        (p.len() >= Self::LEN).then(|| Loss { first: le64(p, 0), count: le64(p, 8) })
    }
}

const _: () = assert!(Event::LEN <= PAYLOAD && Anchor::LEN <= PAYLOAD && Seal::LEN <= PAYLOAD && Loss::LEN <= PAYLOAD);

/// The canonical bytes of a record into `out`; their length. A payload
/// longer than [`PAYLOAD`] is cut there, as the ring cuts it.
pub fn canon(env: &Envelope, payload: &[u8], out: &mut [u8; CANON_MAX]) -> usize {
    let len = (env.len as usize).min(PAYLOAD).min(payload.len());
    out[0] = VERSION;
    out[1..9].copy_from_slice(&env.seq.to_le_bytes());
    out[9..17].copy_from_slice(&env.ts.to_le_bytes());
    out[17] = env.clock;
    out[18..20].copy_from_slice(&env.kind.to_le_bytes());
    (out[20], out[21]) = (env.cpu, env.flags);
    out[22..24].copy_from_slice(&(len as u16).to_le_bytes());
    out[CANON_HDR..CANON_HDR + len].copy_from_slice(&payload[..len]);
    CANON_HDR + len
}

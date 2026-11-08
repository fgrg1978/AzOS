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
//! to its files as `@security` lines. A record is one of these kinds:
//!
//! * [`kind::EVENT`]: a decision record of a security class ([`Class`]),
//!   copied by `azos_decision` when it is written.
//! * [`kind::ANCHOR`]: the boot's identity and its link to what came before
//!   it: the value and counter the seal backend held when the boot started,
//!   a random nonce, and why the boot seals without hardware if it does
//!   ([`Anchor`]).
//! * [`kind::SEAL`]: the head of the chain through a sequence number, the
//!   backend's value before and after it was committed there, and the boot it
//!   belongs to ([`Seal`]).
//! * [`kind::LOSS`]: records the sealer never saw (the ring lapped it, or a
//!   producer never finished one), by class ([`Loss`]).
//! * [`kind::SINK_LOSS`]: records the sealer folded and the sink, `logd`, lost
//!   (it says which, and the kernel counts their classes) ([`Loss`]).
//! * [`kind::HELD`]: records the producers' rate cap held back, by class
//!   ([`Held`]).
//!
//! # The chain
//!
//! Per boot, in sequence order: `head_0 = SHA-256("azos/seclog/v2" ||
//! boot_anchor || nonce)`, `head_i = SHA-256(0x01 || head_{i-1} || canon_i)`,
//! `canon` the record's [canonical bytes](canon) (every envelope field but the
//! source, and the payload). Seal `k` commits `data_k = SHA-256(0x02 ||
//! boot_anchor || nonce || k || counter_k || through_k || head)` to the
//! backend, whose value becomes `anchor_k = SHA-256(anchor_{k-1} || data_k)`:
//! the rule of a TPM 2.0 `NV_Extend` into a SHA-256 index, which the TPM
//! computes itself. Every seal carries `anchor_{k-1}`, the boot anchor and the
//! nonce, so a seal is checked, and its boot linked to the previous one,
//! without the records before it.
//!
//! What a seal proves depends on where the anchor lives, and every record
//! says which ([`Backend`], [`FLAG_HARDWARE`], [`FLAG_UNDELETABLE`]). On a TPM
//! the counter (`counter_k`, a `TPM_NT_COUNTER` index the kernel increments
//! once per seal and no one can lower) makes a removed seal or boot visible
//! against the live counter. The anchor index the OS defines itself in the
//! owner hierarchy can be undefined and replayed by anyone who can send owner
//! commands: against that actor the TPM proves no seal was removed, not that
//! no record was rewritten. An index created in the platform hierarchy that
//! can never be deleted ([`FLAG_UNDELETABLE`]) proves both. The forward-only
//! backend keeps the anchor in kernel memory and prints each seal on the
//! console for a receiver off the device; the local seal is advisory.

#![no_std]
#![forbid(unsafe_code)]

pub mod ack;
#[cfg(feature = "chain")]
pub mod chain;
pub mod text;
#[cfg(feature = "chain")]
pub mod verify;

pub use azos_rings::region::record::Envelope;

/// The version of the format: the first byte of every record's canonical
/// bytes and the first word of its line.
pub const VERSION: u8 = 2;
/// Payload bytes a security ring slot holds: the largest kind's, a seal's.
pub const PAYLOAD: usize = 160;
/// Class numbers a by-class count covers (index = the class's number).
pub const CLASSES: usize = 12;
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
    pub const HELD: u16 = 5;
    pub const SINK_LOSS: u16 = 6;
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

    /// A class whose loss hides what spyware does (every class but the
    /// capability denials and the bucket's reports of them).
    pub const fn high_value(self) -> bool {
        !matches!(self, Class::CapDenial | Class::Limited)
    }
}

/// Why a boot seals without hardware.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum Reason {
    /// It does not: the hardware holds the seals.
    Hardware = 0,
    /// The build seals forward-only (Kconfig `SEC_LOG_SEAL_FORWARD`).
    Configured = 1,
    /// No TPM answered at boot.
    NoTpm = 2,
    /// The anchor's or the counter's index exists with other attributes, size
    /// or policy, or another password: someone else defined it.
    IndexUnusable = 3,
    /// The indexes could not be defined or read.
    ReadFailed = 4,
}

impl Reason {
    pub const fn from_u8(v: u8) -> Option<Reason> {
        Some(match v {
            0 => Reason::Hardware,
            1 => Reason::Configured,
            2 => Reason::NoTpm,
            3 => Reason::IndexUnusable,
            4 => Reason::ReadFailed,
            _ => return None,
        })
    }

    pub const fn name(self) -> &'static str {
        match self {
            Reason::Hardware => "hardware",
            Reason::Configured => "configured",
            Reason::NoTpm => "no-tpm",
            Reason::IndexUnusable => "index-unusable",
            Reason::ReadFailed => "read-failed",
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
/// A seal's flag: the index, read back after the extend, did not hold the
/// value the extend gives: someone else extended it. The seal's anchor is the
/// value read back.
pub const FLAG_DIVERGED: u8 = 2;
/// An anchor's or a seal's flag: the anchor's index was created in the
/// platform hierarchy and can never be deleted (`TPMA_NV_PLATFORMCREATE`,
/// `TPMA_NV_POLICY_DELETE`, a policy nothing satisfies).
pub const FLAG_UNDELETABLE: u8 = 4;

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

fn put_classes(p: &mut [u8], at: usize, c: &[u32; CLASSES]) {
    for (i, v) in c.iter().enumerate() {
        p[at + 4 * i..at + 4 * i + 4].copy_from_slice(&v.to_le_bytes());
    }
}

fn classes_at(p: &[u8], at: usize) -> [u32; CLASSES] {
    let mut c = [0u32; CLASSES];
    for (i, v) in c.iter_mut().enumerate() {
        *v = le32(p, at + 4 * i);
    }
    c
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

/// A boot's identity and link: the backend's value and counter when the boot
/// started, and the nonce its chain begins from.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Anchor {
    pub backend: Backend,
    /// [`FLAG_HARDWARE`] (the value and counter were read from the hardware),
    /// [`FLAG_UNDELETABLE`].
    pub flags: u8,
    pub reason: Reason,
    pub nonce: u64,
    /// The backend's counter at boot (0 without one).
    pub counter: u64,
    pub value: Hash,
}

impl Anchor {
    pub const LEN: usize = 56;

    pub fn hardware(&self) -> bool {
        self.flags & FLAG_HARDWARE != 0
    }

    pub fn encode(&self) -> [u8; Self::LEN] {
        let mut p = [0u8; Self::LEN];
        (p[0], p[1], p[2]) = (self.backend as u8, self.flags, self.reason as u8);
        p[8..16].copy_from_slice(&self.nonce.to_le_bytes());
        p[16..24].copy_from_slice(&self.counter.to_le_bytes());
        p[24..56].copy_from_slice(&self.value);
        p
    }

    pub fn decode(p: &[u8]) -> Option<Anchor> {
        if p.len() < Self::LEN {
            return None;
        }
        Some(Anchor {
            backend: Backend::from_u8(p[0])?,
            flags: p[1],
            reason: Reason::from_u8(p[2])?,
            nonce: le64(p, 8),
            counter: le64(p, 16),
            value: hash_at(p, 24),
        })
    }
}

/// A seal: the chain's head over every record before `through`, committed to
/// the backend as the `count`th seal of the boot whose anchor and nonce it
/// names, and the backend's value before and after.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Seal {
    pub backend: Backend,
    /// [`FLAG_HARDWARE`] (the backend took the commit), [`FLAG_DIVERGED`],
    /// [`FLAG_UNDELETABLE`].
    pub flags: u8,
    /// Seals of this boot, this one included.
    pub count: u32,
    /// The first sequence number the head does not cover.
    pub through: u64,
    /// The backend's counter after this seal's increment (0: none taken).
    pub counter: u64,
    pub nonce: u64,
    pub head: Hash,
    /// The backend's value after the commit (with [`FLAG_DIVERGED`], the value
    /// read back).
    pub anchor: Hash,
    /// The backend's value before it: the previous seal's anchor, or the boot
    /// anchor.
    pub prev: Hash,
    pub boot_anchor: Hash,
}

impl Seal {
    pub const LEN: usize = 160;

    pub fn hardware(&self) -> bool {
        self.flags & FLAG_HARDWARE != 0
    }

    pub fn encode(&self) -> [u8; Self::LEN] {
        let mut p = [0u8; Self::LEN];
        (p[0], p[1]) = (self.backend as u8, self.flags);
        p[4..8].copy_from_slice(&self.count.to_le_bytes());
        p[8..16].copy_from_slice(&self.through.to_le_bytes());
        p[16..24].copy_from_slice(&self.counter.to_le_bytes());
        p[24..32].copy_from_slice(&self.nonce.to_le_bytes());
        p[32..64].copy_from_slice(&self.head);
        p[64..96].copy_from_slice(&self.anchor);
        p[96..128].copy_from_slice(&self.prev);
        p[128..160].copy_from_slice(&self.boot_anchor);
        p
    }

    pub fn decode(p: &[u8]) -> Option<Seal> {
        if p.len() < Self::LEN {
            return None;
        }
        Some(Seal {
            backend: Backend::from_u8(p[0])?,
            flags: p[1],
            count: le32(p, 4),
            through: le64(p, 8),
            counter: le64(p, 16),
            nonce: le64(p, 24),
            head: hash_at(p, 32),
            anchor: hash_at(p, 64),
            prev: hash_at(p, 96),
            boot_anchor: hash_at(p, 128),
        })
    }
}

/// `count` records from `first` that did not reach where they were going:
/// the sealer never folded them ([`kind::LOSS`]), or the sink never wrote
/// them ([`kind::SINK_LOSS`]); `by_class` counts them by class where the
/// kernel knows it (index 0: class unknown).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Loss {
    pub first: u64,
    pub count: u64,
    pub by_class: [u32; CLASSES],
}

impl Loss {
    pub const LEN: usize = 16 + 4 * CLASSES;

    pub fn encode(&self) -> [u8; Self::LEN] {
        let mut p = [0u8; Self::LEN];
        p[0..8].copy_from_slice(&self.first.to_le_bytes());
        p[8..16].copy_from_slice(&self.count.to_le_bytes());
        put_classes(&mut p, 16, &self.by_class);
        p
    }

    pub fn decode(p: &[u8]) -> Option<Loss> {
        (p.len() >= Self::LEN).then(|| Loss { first: le64(p, 0), count: le64(p, 8), by_class: classes_at(p, 16) })
    }
}

/// Records the producers' rate cap held back since the last such record, by
/// class (Kconfig `SEC_LOG_PER_S`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Held {
    pub by_class: [u32; CLASSES],
}

impl Held {
    pub const LEN: usize = 4 * CLASSES;

    pub fn encode(&self) -> [u8; Self::LEN] {
        let mut p = [0u8; Self::LEN];
        put_classes(&mut p, 0, &self.by_class);
        p
    }

    pub fn decode(p: &[u8]) -> Option<Held> {
        (p.len() >= Self::LEN).then(|| Held { by_class: classes_at(p, 0) })
    }
}

const _: () = assert!(
    Event::LEN <= PAYLOAD && Anchor::LEN <= PAYLOAD && Seal::LEN <= PAYLOAD && Loss::LEN <= PAYLOAD && Held::LEN <= PAYLOAD
);

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

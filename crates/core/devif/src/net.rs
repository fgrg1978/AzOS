// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The `Net` interface: the stack's name service and its time client, for
//! ring 3.
//!
//! The kernel hosts it on the `net` endpoint (`endpoint = "net"`). A task
//! holding it with `READ` can ask the resolver the stack keeps (`resolve`:
//! toolbox `host`) and read the state of the SNTP client (`ntp_status`:
//! toolbox `ntp`). Neither changes anything a holder could not already see:
//! the resolver has a cache, the client has a server and a count.
//!
//! **`resolve` waits.** It runs on the caller's own stack like every
//! kernel-hosted op, but it sends a query and sleeps until the answer, or for
//! at most Kconfig `NET_DNS_TIMEOUT_MS` (a second caller waits that long
//! again for its turn: the stack has one query in flight). It is not a
//! real-time call; a task with a deadline asks from a task without.

use crate::outcome::Out;
use azos_idl::{azos_interface, Reader, Wire, Writer};

/// The interface id (ASCII "NET ").
pub const NET_ID: u32 = 0x4E45_5420;

/// Address family of an A lookup.
pub const FAMILY_V4: u32 = 4;
/// Address family of an AAAA lookup.
pub const FAMILY_V6: u32 = 6;

/// Words of name in a [`Query`]: the request has room for seven after the
/// header, and the family and the length share the first.
pub const NAME_WORDS: usize = 6;
/// Longest name a query carries (bytes): the dotted text, no trailing dot.
pub const NAME_MAX: usize = NAME_WORDS * 8;

/// A lookup: the family wanted, and a name of at most [`NAME_MAX`] bytes
/// packed little-endian into words, the rest zero.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Query {
    /// [`FAMILY_V4`] or [`FAMILY_V6`] (anything else is `BAD_ARGUMENT`).
    pub family: u32,
    /// How many bytes of the name are meaningful.
    pub n: u32,
    /// The name, eight bytes to a word.
    pub w: [u64; NAME_WORDS],
}

impl Query {
    /// The query for `name` in `family`; `None` when the name is empty or
    /// longer than [`NAME_MAX`].
    pub fn new(family: u32, name: &[u8]) -> Option<Query> {
        if name.is_empty() || name.len() > NAME_MAX {
            return None;
        }
        let mut q = Query { family, n: name.len() as u32, w: [0; NAME_WORDS] };
        for (i, b) in name.iter().enumerate() {
            q.w[i / 8] |= (*b as u64) << ((i % 8) * 8);
        }
        Some(q)
    }

    /// Copy the name into `out`; the bytes copied.
    pub fn name(&self, out: &mut [u8; NAME_MAX]) -> usize {
        let n = (self.n as usize).min(NAME_MAX);
        for (i, o) in out[..n].iter_mut().enumerate() {
            *o = (self.w[i / 8] >> ((i % 8) * 8)) as u8;
        }
        n
    }
}

impl Wire for Query {
    const WORDS: usize = 1 + NAME_WORDS;
    const CAPS: usize = 0;
    fn put(&self, w: &mut Writer<'_>) {
        w.word(self.n as u64 | (self.family as u64) << 32);
        self.w.put(w);
    }
    fn get(r: &mut Reader<'_>) -> Self {
        let head = r.word();
        Query { family: (head >> 32) as u32, n: head as u32, w: <[u64; NAME_WORDS]>::get(r) }
    }
}

/// An address: how many bytes of it are meaningful (4 or 16) and the bytes,
/// in network order, eight to a word.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Address {
    pub n: u32,
    pub w: [u64; 2],
}

impl Address {
    /// An IPv4 address.
    pub fn v4(a: [u8; 4]) -> Address {
        Address::from_bytes(&a)
    }

    /// An IPv6 address.
    pub fn v6(a: [u8; 16]) -> Address {
        Address::from_bytes(&a)
    }

    fn from_bytes(a: &[u8]) -> Address {
        let mut r = Address { n: a.len() as u32, w: [0; 2] };
        for (i, b) in a.iter().enumerate() {
            r.w[i / 8] |= (*b as u64) << ((i % 8) * 8);
        }
        r
    }

    /// The bytes, in network order; the count that is meaningful (0: none).
    pub fn bytes(&self, out: &mut [u8; 16]) -> usize {
        let n = (self.n as usize).min(16);
        for (i, o) in out[..n].iter_mut().enumerate() {
            *o = (self.w[i / 8] >> ((i % 8) * 8)) as u8;
        }
        n
    }
}

impl Wire for Address {
    const WORDS: usize = 3;
    const CAPS: usize = 0;
    fn put(&self, w: &mut Writer<'_>) {
        self.n.put(w);
        self.w.put(w);
    }
    fn get(r: &mut Reader<'_>) -> Self {
        let n = u32::get(r);
        Address { n, w: <[u64; 2]>::get(r) }
    }
}

/// How the SNTP client stands.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NtpStatus {
    /// The server in use, IPv4 in network order as a number (0: none yet).
    pub server: u32,
    /// 1 once an exchange has succeeded since boot.
    pub synced: u32,
    /// Unix seconds the server reported at the last success (0: none yet).
    pub last_unix_sec: u32,
    /// Milliseconds since that success (0 while not synced).
    pub age_ms: u64,
    /// Syncs that succeeded since boot.
    pub exchanges: u32,
    /// Syncs that gave up after every attempt since boot.
    pub failures: u32,
}

impl Wire for NtpStatus {
    const WORDS: usize = 6;
    const CAPS: usize = 0;
    fn put(&self, w: &mut Writer<'_>) {
        self.server.put(w);
        self.synced.put(w);
        self.last_unix_sec.put(w);
        self.age_ms.put(w);
        self.exchanges.put(w);
        self.failures.put(w);
    }
    fn get(r: &mut Reader<'_>) -> Self {
        let server = u32::get(r);
        let synced = u32::get(r);
        let last_unix_sec = u32::get(r);
        let age_ms = u64::get(r);
        let exchanges = u32::get(r);
        NtpStatus { server, synced, last_unix_sec, age_ms, exchanges, failures: u32::get(r) }
    }
}

#[azos_interface(id = 0x4E45_5420, level = 1)]
pub trait Net {
    /// The address of `query`'s name in its family: an A or an AAAA lookup
    /// through the stack's resolver (its cache first, then the DHCP-given
    /// server). `BAD_ARGUMENT` for a family other than [`FAMILY_V4`] and
    /// [`FAMILY_V6`] and for a name that is not text; `NO_RESOURCE` when the
    /// lookup found no address of that family (no answer in time, an error
    /// from the server, or an answer about another name). The answer follows
    /// at most eight aliases and takes only records owned by the name asked.
    /// Waits for the answer (see the module). Needs `READ`.
    #[idempotent]
    fn resolve(&self, query: Query) -> Out<Address>;
    /// How the SNTP client stands. Needs `READ`.
    #[idempotent]
    fn ntp_status(&self) -> Out<NtpStatus>;
}

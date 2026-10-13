// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The Names object's server side: the interface's implementation over a
//! [`Host`] (the kernel's view of the signed topology, the handles this task
//! holds, the console).
//!
//! **Every answer is decided from the signed topology, once per call.** The
//! caller is identified by the badge the kernel stamped on its capability to
//! `endpoint.names` (the row's identity, `azos_syscall::spawn::names_badge`);
//! the server reads `/proc/names` for that call and lends only what an
//! `allow <badge> <name>` line names AND an `export <name> ...` line says
//! this task holds. Nothing is cached: the view is the topology, and a stale
//! copy of it is a stale policy.
//!
//! A lent capability is a DUP entry with the call right only: a child of this
//! task's own capability in the warrant tree, not itself giftable (no `DUP`),
//! gone when this task's is, and gone at `now + NAMES_LEND_TTL_MS` (the entry's
//! `expiry_ns`) when that is set: the borrower asks again. A refusal lends nothing, is counted, kept in a
//! small ring ([`Service::refusals`]) and written to the console, because a
//! refusal nobody can see is not a record.
//!
//! Pure given a [`Host`]: `tests/host/names-tests` pulls this file in with
//! `#[path]` and drives it through the generated client stub.

use azos_abi::cap::CapPerms;
use azos_names::{
    allowed, export, unpack_name, Endpoint, Lent, Names, PackedName, NAME_MAX,
};

/// Bytes of the view this server reads per call (the procfs file bound).
pub const VIEW_MAX: usize = 2048;

/// What the server needs from its surroundings.
pub trait Host {
    /// Read the view (`/proc/names`) into `buf`; the bytes read.
    fn view(&mut self, buf: &mut [u8]) -> usize;
    /// The handle in this task's table of the endpoint at pool index `index`
    /// (`SYS_CAP_INFO`), if it holds one.
    fn handle(&mut self, index: u32) -> Option<u32>;
    /// A line for the console.
    fn log(&mut self, line: &[u8]);
    /// The monotonic clock in nanoseconds: the one the kernel reads a
    /// capability's deadline against.
    fn now_ns(&mut self) -> u64;
}

/// Why a lookup lent nothing.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Why {
    /// The call carried no badge: the caller's row is unknown.
    Unidentified,
    /// The name is not in the caller's row's `imports`.
    NotImported,
    /// The row imports it, but this task holds no capability for it.
    NotHeld,
    /// The name is not a name (empty, or not terminated).
    Malformed,
}

impl Why {
    fn word(self) -> &'static [u8] {
        match self {
            Why::Unidentified => b"unidentified",
            Why::NotImported => b"not-imported",
            Why::NotHeld => b"not-held",
            Why::Malformed => b"malformed",
        }
    }
}

/// One recorded refusal.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Refusal {
    pub badge: u32,
    /// `lookup` (1) or `who_serves` (2).
    pub op: u8,
    pub name: [u8; NAME_MAX],
    pub name_len: u8,
    pub why: Why,
}

const NO_REFUSAL: Refusal = Refusal { badge: 0, op: 0, name: [0; NAME_MAX], name_len: 0, why: Why::Malformed };
/// Refusals kept (the newest overwrite the oldest); the count is not bounded.
pub const REFUSALS_KEPT: usize = 8;

/// The rights a lent capability carries: the call right, nothing else. Not
/// `DUP`: the borrower cannot hand it on; not `READ`: it is not the server.
pub const LENT_RIGHTS: CapPerms = CapPerms::WRITE;

/// The Names object served over a [`Host`].
pub struct Service<H: Host> {
    pub host: H,
    /// The badge of the call being served; the loop sets it from the request
    /// (0 when the request carried none).
    pub caller: u32,
    /// Refusals since start.
    pub refused: u32,
    /// How long a lent capability lives, in nanoseconds (`NAMES_LEND_TTL_MS`);
    /// 0 lends with no deadline of its own.
    lend_ttl_ns: u64,
    ring: [Refusal; REFUSALS_KEPT],
    view: [u8; VIEW_MAX],
}

impl<H: Host> Service<H> {
    pub const fn new(host: H, lend_ttl_ns: u64) -> Self {
        Self { host, caller: 0, refused: 0, lend_ttl_ns, ring: [NO_REFUSAL; REFUSALS_KEPT], view: [0; VIEW_MAX] }
    }

    /// The deadline of a capability lent now: `now + ttl`, or none.
    fn lend_expiry(&mut self) -> u64 {
        if self.lend_ttl_ns == 0 {
            return 0;
        }
        // Saturating, and never 0 (0 means "no deadline").
        self.host.now_ns().saturating_add(self.lend_ttl_ns).max(1)
    }

    /// The newest refusal first, up to [`REFUSALS_KEPT`]. The host tests
    /// read the record; on the target it is the console line.
    #[allow(dead_code)]
    pub fn refusals(&self) -> impl Iterator<Item = &Refusal> {
        let n = (self.refused as usize).min(REFUSALS_KEPT);
        (0..n).map(move |k| &self.ring[(self.refused as usize - 1 - k) % REFUSALS_KEPT])
    }

    fn refuse(&mut self, op: u8, name: &[u8], why: Why) {
        let mut r = NO_REFUSAL;
        r.badge = self.caller;
        r.op = op;
        let n = name.len().min(NAME_MAX);
        r.name[..n].copy_from_slice(&name[..n]);
        r.name_len = n as u8;
        r.why = why;
        self.ring[self.refused as usize % REFUSALS_KEPT] = r;
        self.refused = self.refused.wrapping_add(1);
        // "namesd: REFUSED lookup badge=7 name=x (not-imported)"
        let mut line = [0u8; 96];
        let mut w = 0;
        for part in [
            &b"[namesd] REFUSED "[..],
            if op == 1 { b"lookup" } else { b"who_serves" },
            b" badge=",
        ] {
            w = put(&mut line, w, part);
        }
        let mut d = [0u8; 10];
        w = put(&mut line, w, dec(self.caller, &mut d));
        w = put(&mut line, w, b" name=");
        w = put(&mut line, w, &name[..n]);
        w = put(&mut line, w, b" (");
        w = put(&mut line, w, why.word());
        w = put(&mut line, w, b")\n");
        self.host.log(&line[..w]);
    }

    /// Read the view, then decide: the caller's row imports `name` and the
    /// view exports it. The pool index and serving task on success.
    fn decide(&mut self, op: u8, name: &PackedName) -> Result<(u32, [u8; NAME_MAX], usize), ()> {
        let mut nb = [0u8; NAME_MAX];
        let n = unpack_name(name, &mut nb);
        if n == 0 {
            self.refuse(op, &nb[..0], Why::Malformed);
            return Err(());
        }
        if self.caller == 0 {
            self.refuse(op, &nb[..n], Why::Unidentified);
            return Err(());
        }
        let got = self.host.view(&mut self.view).min(VIEW_MAX);
        let view = &self.view[..got];
        if !allowed(view, self.caller, &nb[..n]) {
            self.refuse(op, &nb[..n], Why::NotImported);
            return Err(());
        }
        let Some((index, server)) = export(view, &nb[..n]) else {
            self.refuse(op, &nb[..n], Why::NotHeld);
            return Err(());
        };
        let mut sv = [0u8; NAME_MAX];
        let m = if server == b"-" { 0 } else { server.len().min(NAME_MAX) };
        sv[..m].copy_from_slice(&server[..m]);
        Ok((index, sv, m))
    }
}

fn put(line: &mut [u8], at: usize, s: &[u8]) -> usize {
    let n = s.len().min(line.len() - at);
    line[at..at + n].copy_from_slice(&s[..n]);
    at + n
}

fn dec(mut v: u32, out: &mut [u8; 10]) -> &[u8] {
    let mut i = out.len();
    loop {
        i -= 1;
        out[i] = b'0' + (v % 10) as u8;
        v /= 10;
        if v == 0 {
            return &out[i..];
        }
    }
}

impl<H: Host> Names for Service<H> {
    fn lookup(&mut self, name: PackedName) -> Lent<Endpoint> {
        let Ok((index, ..)) = self.decide(1, &name) else { return Lent::none() };
        match self.host.handle(index) {
            Some(h) => {
                let until = self.lend_expiry();
                Lent::dup_until(h, LENT_RIGHTS.bits() as u16, until)
            }
            None => {
                let mut nb = [0u8; NAME_MAX];
                let n = unpack_name(&name, &mut nb);
                self.refuse(1, &nb[..n], Why::NotHeld);
                Lent::none()
            }
        }
    }

    fn who_serves(&mut self, name: PackedName) -> PackedName {
        match self.decide(2, &name) {
            Ok((_, sv, m)) => azos_names::pack_name(&sv[..m]).unwrap_or([0; 3]),
            Err(()) => [0; 3],
        }
    }
}

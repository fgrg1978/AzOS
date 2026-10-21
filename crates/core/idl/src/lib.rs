// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The AzOS interface definition language, first cut (L13, owner decision D5).
//!
//! An interface is a Rust trait annotated `#[azos_interface(id = N, level =
//! L)]`. One interface generates, from one op table:
//!
//! * `<Name>Client<T: Transport>`: the **endpoint-call stub**. It packs the
//!   arguments into a [`MsgDesc`], calls the [`Transport`] and unpacks the
//!   reply. The ring-3 host of a service, or any caller across an endpoint.
//! * `<Name>Idl::dispatch`: the **server dispatcher**. It decodes the op and
//!   the arguments of a request, calls the trait implementation and encodes
//!   the reply.
//! * `<Name>Direct<S: Name>`: the **direct-call stub**. The same call, in
//!   process, with no message: the kernel-host placement.
//! * `<Name>Call`: the caller's trait, implemented by both stubs, so code that
//!   uses the interface does not know where the implementation is placed.
//! * `<Name>Idl::OPS`: the **op table** ([`OpInfo`] per method).
//!
//! ```
//! use azos_idl::azos_interface;
//!
//! #[azos_interface(id = 1, level = 1)]
//! pub trait Adder {
//!     #[idempotent]
//!     fn add(&mut self, a: u32, b: u32) -> u32;
//! }
//!
//! struct Impl;
//! impl Adder for Impl {
//!     fn add(&mut self, a: u32, b: u32) -> u32 { a + b }
//! }
//!
//! // The in-process placement: no message.
//! let mut d = AdderDirect(Impl);
//! assert_eq!(AdderCall::add(&mut d, 2, 3), Ok(5));
//! assert!(AdderIdl::OPS[0].idempotent());
//! ```
//!
//! # Wire form
//!
//! The request is a [`MsgDesc`]. Word 0 is the header (`id << 32 | level << 16
//! | op`), then each argument in order: a scalar is one word, an array is its
//! elements in order, a [`Cap<T>`] is one capability entry (mode MOVE) and no
//! word, and a [`Lent<T>`] is a presence word and, when present, one entry of
//! mode DUP with explicit rights and a deadline (an attenuated child of the
//! server's own capability, lapsing at the deadline; a reply may carry fewer entries than the op's bound, never more). The reply's word 0 is the status (0 = served, else an [`IdlError`]
//! status; always small and non-negative, because the fast path shares reply
//! word 0 with its error code), then the return value in the same form. The
//! op number of a method is its position in the trait, counted from 1 (op 0 is
//! never valid, so a zeroed message is refused).
//!
//! # Rules the macro enforces
//!
//! * Op, argument and return shapes fit the inline words (`words = W`, default
//!   [`INLINE_WORDS_MAX`]) and the capability entries ([`CAPS_MAX`]), at
//!   compile time.
//! * At most one of `#[idempotent]`, `#[at_most_once]`, `#[once_only]` per
//!   method; they are carried in the op table ([`OpInfo::flags`]).
//! * The failure contract of an op: `#[on_failure(degrade | safe_state |
//!   restart | escalate)]`, `#[deadline_ns = N]` and `#[budget_us = N]` (each
//!   at most once, `N` a positive literal), carried in [`OpInfo::on_failure`],
//!   [`OpInfo::deadline_ns`] and [`OpInfo::budget_us`]. A `#[once_only]` op
//!   (an irreversible effect) must declare `#[on_failure(..)]`.
//! * The anti-Unix lint: no integer file descriptors, no `errno`, no text or
//!   path as authority. See [`lint`].
//!
//! The level is one linear number per interface. A server serves a request
//! whose level is at most its own ([`IdlError::LevelTooNew`] otherwise).
#![no_std]

pub use azos_abi::ipc_msg::{CapDesc, MsgDesc, CAP_MODE_DUP, CAP_MODE_MOVE, MSG_CAPS_MAX, MSG_VERSION, MSG_WORDS_MAX};
pub use azos_idl_macros::azos_interface;

use core::marker::PhantomData;

/// The ABI ceiling on inline words (an interface's `words = W` is at most this).
pub const INLINE_WORDS_MAX: usize = MSG_WORDS_MAX;
/// The ABI ceiling on capability entries.
pub const CAPS_MAX: usize = MSG_CAPS_MAX;

pub mod lint;

// ── errors ──────────────────────────────────────────────────────────────

/// Why a call did not produce a value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdlError {
    /// The transport failed (the code is the transport's own: for the v2 call,
    /// the kernel's negative code).
    Transport(isize),
    /// The request names another interface.
    BadInterface,
    /// The request names an op this interface does not have.
    BadOp,
    /// The client was built against a newer level than the server serves.
    LevelTooNew,
    /// The message does not have the shape of its op (counts, a bool that is
    /// not 0 or 1, a scalar that does not fit its type).
    Malformed,
    /// The service is on another node and the session to it is gone (or the
    /// reply never came and the op may not be asked again): the outcome of
    /// the call is unknown, which is not the same as the server being dead
    /// ([`IdlError::PeerDied`]) and not a refusal. Raised by a node's RPC
    /// server (`userspace/services/rpcsrv`); Erlang's `noconnection`.
    NoConnection,
    /// The server that held the call died, or the endpoint was destroyed,
    /// while it was queued or in service; on a remote service, the far
    /// node's server and not the link. The kernel's `EPEERDIED` / `EREVOKED`
    /// as a status a remote caller can be told.
    PeerDied,
    /// The call's deadline had passed when a node's RPC server read it, or
    /// passed while it waited: nothing ran.
    DeadlineExpired,
    /// The RPC server refused the call before any server saw it: the
    /// interface is not exported to this peer, the caller is real-time, or a
    /// capability of the message cannot cross.
    Refused,
}

/// Reply status: served.
pub const STATUS_OK: u64 = 0;
const STATUS_BAD_INTERFACE: u64 = 1;
const STATUS_BAD_OP: u64 = 2;
const STATUS_LEVEL_TOO_NEW: u64 = 3;
const STATUS_MALFORMED: u64 = 4;
const STATUS_NO_CONNECTION: u64 = 5;
const STATUS_PEER_DIED: u64 = 6;
const STATUS_DEADLINE_EXPIRED: u64 = 7;
const STATUS_REFUSED: u64 = 8;

impl IdlError {
    /// The reply status word this error travels as (never [`STATUS_OK`]).
    pub const fn status(self) -> u64 {
        match self {
            IdlError::Transport(_) | IdlError::Malformed => STATUS_MALFORMED,
            IdlError::BadInterface => STATUS_BAD_INTERFACE,
            IdlError::BadOp => STATUS_BAD_OP,
            IdlError::LevelTooNew => STATUS_LEVEL_TOO_NEW,
            IdlError::NoConnection => STATUS_NO_CONNECTION,
            IdlError::PeerDied => STATUS_PEER_DIED,
            IdlError::DeadlineExpired => STATUS_DEADLINE_EXPIRED,
            IdlError::Refused => STATUS_REFUSED,
        }
    }

    /// The error a reply status word means (`None` for [`STATUS_OK`]). An
    /// unknown status is [`IdlError::Malformed`].
    pub const fn from_status(s: u64) -> Option<IdlError> {
        match s {
            STATUS_OK => None,
            STATUS_BAD_INTERFACE => Some(IdlError::BadInterface),
            STATUS_BAD_OP => Some(IdlError::BadOp),
            STATUS_LEVEL_TOO_NEW => Some(IdlError::LevelTooNew),
            STATUS_NO_CONNECTION => Some(IdlError::NoConnection),
            STATUS_PEER_DIED => Some(IdlError::PeerDied),
            STATUS_DEADLINE_EXPIRED => Some(IdlError::DeadlineExpired),
            STATUS_REFUSED => Some(IdlError::Refused),
            _ => Some(IdlError::Malformed),
        }
    }
}

/// The result of a call through a stub.
pub type Result<T = ()> = core::result::Result<T, IdlError>;

// ── transport ───────────────────────────────────────────────────────────

/// What a client stub calls through: send the request in `*msg`, block until
/// answered, leave the reply in `*msg`. `Err` is a failure of the transport,
/// not of the interface (a refusal by the server arrives as a reply).
///
/// The v2 call (`ipc_call_v2`) is one implementation; the register-only fast
/// path is another (an interface with `words = 4` and no capabilities fits
/// it); a loopback is a third.
pub trait Transport {
    fn call(&self, msg: &mut MsgDesc) -> Result;
}

// ── capability handles ──────────────────────────────────────────────────

/// A typed capability handle in an interface signature. `T` is a marker for
/// what the handle names; it is never constructed. A `Cap<T>` crosses a call
/// as one capability entry of mode MOVE: the sender's handle goes stale and
/// the receiver gets its own.
#[repr(transparent)]
pub struct Cap<T> {
    handle: u32,
    _t: PhantomData<fn() -> T>,
}

impl<T> Cap<T> {
    /// A handle from its raw value (what a libsys call returned).
    pub const fn from_raw(handle: u32) -> Cap<T> {
        Cap { handle, _t: PhantomData }
    }
    /// The raw handle.
    pub const fn raw(self) -> u32 {
        self.handle
    }
}
impl<T> Clone for Cap<T> {
    fn clone(&self) -> Self { *self }
}
impl<T> Copy for Cap<T> {}
impl<T> PartialEq for Cap<T> {
    fn eq(&self, o: &Self) -> bool { self.handle == o.handle }
}
impl<T> Eq for Cap<T> {}
impl<T> core::fmt::Debug for Cap<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Cap({})", self.handle)
    }
}

/// A capability a server lends in a reply, or none. It crosses as a presence
/// word and, when present, one capability entry of mode DUP with explicit
/// rights and a deadline: the receiver holds an attenuated child of the
/// server's capability (a link of the warrant tree) that lapses at
/// [`Lent::expiry_ns`] (0 = when the server's own does) and the server keeps
/// its own. A refusal is [`Lent::none`]: no entry, so nothing is lent. Rights
/// are never 0 here (0 on the wire means "the sender's own").
#[repr(C)]
pub struct Lent<T> {
    handle: u32,
    rights: u16,
    present: bool,
    expiry_ns: u64,
    _t: PhantomData<fn() -> T>,
}

impl<T> Lent<T> {
    /// Nothing lent.
    pub const fn none() -> Lent<T> {
        Lent { handle: 0, rights: 0, present: false, expiry_ns: 0, _t: PhantomData }
    }
    /// Lend the server's `handle` with `rights` (`CapPerms` bits). Rights 0
    /// lend nothing: on the wire 0 means "the sender's own", which is not an
    /// attenuation, so it fails closed.
    pub const fn dup(handle: u32, rights: u16) -> Lent<T> {
        Lent::dup_until(handle, rights, 0)
    }
    /// [`Lent::dup`] that lapses at `expiry_ns` (absolute nanoseconds on the
    /// MONO clock, as `Warrant::expiry_ns`; 0 = with the server's own). The
    /// kernel takes the earlier of this and the server's own deadline, so a
    /// lease can only be shorter than its parent.
    pub const fn dup_until(handle: u32, rights: u16, expiry_ns: u64) -> Lent<T> {
        if rights == 0 { Lent::none() } else { Lent { handle, rights, present: true, expiry_ns, _t: PhantomData } }
    }
    /// The receiver's handle, if a capability was lent.
    pub const fn get(&self) -> Option<Cap<T>> {
        if self.present { Some(Cap::from_raw(self.handle)) } else { None }
    }
    /// The rights the server lent with (0 for none, and on the receiving side).
    pub const fn rights(&self) -> u16 {
        self.rights
    }
    /// The deadline the server lent with (0 for none, and on the receiving side).
    pub const fn expiry_ns(&self) -> u64 {
        self.expiry_ns
    }
}
impl<T> Clone for Lent<T> {
    fn clone(&self) -> Self { *self }
}
impl<T> Copy for Lent<T> {}
impl<T> PartialEq for Lent<T> {
    fn eq(&self, o: &Self) -> bool { self.present == o.present && self.handle == o.handle && self.rights == o.rights && self.expiry_ns == o.expiry_ns }
}
impl<T> Eq for Lent<T> {}
impl<T> core::fmt::Debug for Lent<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self.get() {
            Some(c) => write!(f, "Lent({:?}, rights {:#x}, until {})", c, self.rights, self.expiry_ns),
            None => write!(f, "Lent(none)"),
        }
    }
}

// ── op table ────────────────────────────────────────────────────────────

/// Flag: the op may be retried freely (`#[idempotent]`).
pub const OP_IDEMPOTENT: u8 = 1;
/// Flag: a retry is deduplicated by the transport (`#[at_most_once]`).
pub const OP_AT_MOST_ONCE: u8 = 2;
/// Flag: the op is never retried, for effects such as actuation
/// (`#[once_only]`).
pub const OP_ONCE_ONLY: u8 = 4;

/// One row of an interface's op table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OpInfo {
    /// The op number: the method's position in the trait, from 1.
    pub op: u16,
    pub name: &'static str,
    /// `OP_IDEMPOTENT | OP_AT_MOST_ONCE | OP_ONCE_ONLY`, at most one.
    pub flags: u8,
    /// Words of the request, header included.
    pub req_words: u8,
    /// Capability entries of the request.
    pub req_caps: u8,
    /// Words of the reply, status included.
    pub rep_words: u8,
    /// Capability entries of the reply.
    pub rep_caps: u8,
    /// `#[on_failure(..)]`: what the system does when the service that runs
    /// the op fails. Always declared for a `#[once_only]` op (the IDL lint
    /// refuses it otherwise); `None` for an op that declares nothing.
    pub on_failure: Option<OnFailure>,
    /// `#[deadline_ns = N]`: the longest the op may take from request to
    /// reply, nanoseconds; 0 when the op declares none.
    pub deadline_ns: u64,
    /// `#[budget_us = N]`: the longest the server may compute for one request,
    /// microseconds of CPU; 0 when the op declares none.
    pub budget_us: u32,
}

/// What the system does when the service that runs an op fails (the attribute
/// `#[on_failure(..)]` of its method).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OnFailure {
    /// Keep going with reduced function (`degrade`): the caller gets a
    /// refusal or a coarser answer, and the rest of the system is untouched.
    Degrade,
    /// Drive the effect to its safe state (`safe_state`): a motor stops, a
    /// valve closes. The service is then restarted or left down as its
    /// supervisor decides.
    SafeState,
    /// Restart the service (`restart`) and let the caller ask again.
    Restart,
    /// Hand the failure up (`escalate`): to the supervisor of the service's
    /// parent, and from there to the safety path.
    Escalate,
}

impl OpInfo {
    pub const fn idempotent(&self) -> bool { self.flags & OP_IDEMPOTENT != 0 }
    pub const fn at_most_once(&self) -> bool { self.flags & OP_AT_MOST_ONCE != 0 }
    pub const fn once_only(&self) -> bool { self.flags & OP_ONCE_ONLY != 0 }
    /// A transport may resend the op after a lost reply without asking.
    pub const fn retry_safe(&self) -> bool { self.idempotent() }
    /// What a transport that can lose a request or its reply may do with the
    /// op; `None` for an op that declares nothing, which no such transport
    /// carries (it would have to guess between running the op twice and not
    /// at all).
    pub const fn delivery(&self) -> Option<Delivery> {
        match self.flags {
            OP_IDEMPOTENT => Some(Delivery::Idempotent),
            OP_AT_MOST_ONCE => Some(Delivery::AtMostOnce),
            OP_ONCE_ONLY => Some(Delivery::OnceOnly),
            _ => None,
        }
    }
}

/// How a transport that can lose messages treats one op (the attribute of its
/// method).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Delivery {
    /// Resend freely: running it twice is the same as once.
    Idempotent,
    /// Resend with the same identity; the receiving side answers a duplicate
    /// from the reply it kept and never runs the op twice.
    AtMostOnce,
    /// Send once. If the answer is lost, the outcome is unknown and the op
    /// is not asked again (an actuation).
    OnceOnly,
}

/// The request header word: interface, level, op.
pub const fn header(id: u32, level: u16, op: u16) -> u64 {
    ((id as u64) << 32) | ((level as u64) << 16) | op as u64
}
/// The interface id of a header word.
pub const fn header_id(h: u64) -> u32 { (h >> 32) as u32 }
/// The level of a header word.
pub const fn header_level(h: u64) -> u16 { (h >> 16) as u16 }
/// The op of a header word.
pub const fn header_op(h: u64) -> u16 { h as u16 }

// ── wire encoding ───────────────────────────────────────────────────────

/// Writes words and capability entries into a [`MsgDesc`].
pub struct Writer<'a> {
    d: &'a mut MsgDesc,
    w: usize,
    c: usize,
}

impl<'a> Writer<'a> {
    pub fn new(d: &'a mut MsgDesc) -> Self { Writer { d, w: 0, c: 0 } }
    pub fn word(&mut self, v: u64) {
        // The generated code proves at compile time that the counts fit;
        // the bound check keeps a hand-written `Wire` from panicking.
        if let Some(s) = self.d.words.get_mut(self.w) {
            *s = v;
        }
        self.w += 1;
    }
    pub fn cap(&mut self, handle: u32) {
        if let Some(s) = self.d.caps.get_mut(self.c) {
            *s = CapDesc { handle, mode: CAP_MODE_MOVE, _pad: 0, rights: 0, expiry_ns: 0 };
        }
        self.c += 1;
    }
    /// A capability entry of mode DUP with the rights `rights` (non-zero, a
    /// subset of the sender's) that lapses at `expiry_ns` (0: with the
    /// sender's own): the receiver gets an attenuated child of the sender's
    /// capability and the sender keeps its own.
    pub fn cap_dup(&mut self, handle: u32, rights: u16, expiry_ns: u64) {
        if let Some(s) = self.d.caps.get_mut(self.c) {
            *s = CapDesc { handle, mode: CAP_MODE_DUP, _pad: 0, rights, expiry_ns };
        }
        self.c += 1;
    }
    /// Record the counts in the descriptor.
    pub fn finish(self) {
        self.d.n_words = self.w.min(MSG_WORDS_MAX) as u8;
        self.d.n_caps = self.c.min(MSG_CAPS_MAX) as u8;
    }
}

/// Reads words and capability entries out of a [`MsgDesc`]. Errors are
/// sticky: a read that does not fit returns 0 and [`Reader::finish`] reports
/// it, so decoding is straight-line code.
pub struct Reader<'a> {
    d: &'a MsgDesc,
    w: usize,
    c: usize,
    bad: bool,
}

impl<'a> Reader<'a> {
    pub fn new(d: &'a MsgDesc) -> Self { Reader { d, w: 0, c: 0, bad: false } }
    /// The next word (0 and sticky failure past `n_words`).
    pub fn word(&mut self) -> u64 {
        let v = if self.w < self.d.n_words as usize { self.d.words.get(self.w).copied() } else { None };
        self.w += 1;
        match v {
            Some(v) => v,
            None => { self.bad = true; 0 }
        }
    }
    /// The next capability handle (0 and sticky failure past `n_caps`).
    pub fn cap(&mut self) -> u32 {
        let v = if self.c < self.d.n_caps as usize { self.d.caps.get(self.c).map(|c| c.handle) } else { None };
        self.c += 1;
        match v {
            Some(v) => v,
            None => { self.bad = true; 0 }
        }
    }
    /// Mark the message malformed (a value that does not fit its type).
    pub fn fail(&mut self) { self.bad = true; }
    /// The message carries at least `words` words and exactly `caps`
    /// capability entries. Extra words are tolerated (a register transport
    /// pads, and a newer client at the same level may append); extra
    /// capabilities are not: a capability nobody reads would leak.
    pub fn expect(&self, words: usize, caps: usize) -> Result {
        if (self.d.n_words as usize) < words || self.d.n_caps as usize != caps {
            return Err(IdlError::Malformed);
        }
        Ok(())
    }
    /// A reply carries at least `words` words and at most `caps` capability
    /// entries: an operation that may answer without the capability it
    /// usually returns ([`Lent`]) sends fewer. More are refused, as in
    /// [`Reader::expect`]: a capability nobody reads would leak.
    pub fn expect_reply(&self, words: usize, caps: usize) -> Result {
        if (self.d.n_words as usize) < words || self.d.n_caps as usize > caps {
            return Err(IdlError::Malformed);
        }
        Ok(())
    }
    /// The request header word (an empty message has none).
    pub fn header(&mut self) -> Result<u64> {
        if (self.d.n_words as usize) < 1 {
            return Err(IdlError::Malformed);
        }
        Ok(self.word())
    }
    /// `Ok` when every read fit and no value was refused.
    pub fn finish(self) -> Result {
        if self.bad { Err(IdlError::Malformed) } else { Ok(()) }
    }
    /// The reply status word: `Ok` for [`STATUS_OK`].
    pub fn status(&mut self) -> Result {
        if (self.d.n_words as usize) < 1 {
            return Err(IdlError::Malformed);
        }
        match IdlError::from_status(self.word()) {
            None => Ok(()),
            Some(e) => Err(e),
        }
    }
}

/// A type that crosses a call: how many words and capability entries it
/// takes, and how it is written and read. Implemented for the plain scalars,
/// `bool`, fixed arrays of those and [`Cap<T>`]; nothing else is an interface
/// type.
pub trait Wire: Sized {
    const WORDS: usize;
    const CAPS: usize;
    fn put(&self, w: &mut Writer<'_>);
    fn get(r: &mut Reader<'_>) -> Self;
}

impl Wire for () {
    const WORDS: usize = 0;
    const CAPS: usize = 0;
    fn put(&self, _w: &mut Writer<'_>) {}
    fn get(_r: &mut Reader<'_>) -> Self {}
}

macro_rules! wire_unsigned {
    ($($t:ty),*) => {$(
        impl Wire for $t {
            const WORDS: usize = 1;
            const CAPS: usize = 0;
            fn put(&self, w: &mut Writer<'_>) { w.word(*self as u64) }
            fn get(r: &mut Reader<'_>) -> Self {
                match <$t>::try_from(r.word()) { Ok(v) => v, Err(_) => { r.fail(); 0 } }
            }
        }
    )*};
}
macro_rules! wire_signed {
    ($($t:ty),*) => {$(
        impl Wire for $t {
            const WORDS: usize = 1;
            const CAPS: usize = 0;
            fn put(&self, w: &mut Writer<'_>) { w.word(*self as i64 as u64) }
            fn get(r: &mut Reader<'_>) -> Self {
                match <$t>::try_from(r.word() as i64) { Ok(v) => v, Err(_) => { r.fail(); 0 } }
            }
        }
    )*};
}
wire_unsigned!(u8, u16, u32, u64);
wire_signed!(i8, i16, i32, i64);

impl Wire for bool {
    const WORDS: usize = 1;
    const CAPS: usize = 0;
    fn put(&self, w: &mut Writer<'_>) { w.word(*self as u64) }
    fn get(r: &mut Reader<'_>) -> Self {
        match r.word() {
            0 => false,
            1 => true,
            _ => { r.fail(); false }
        }
    }
}

impl Wire for f32 {
    const WORDS: usize = 1;
    const CAPS: usize = 0;
    fn put(&self, w: &mut Writer<'_>) { w.word(self.to_bits() as u64) }
    fn get(r: &mut Reader<'_>) -> Self {
        match u32::try_from(r.word()) { Ok(b) => f32::from_bits(b), Err(_) => { r.fail(); 0.0 } }
    }
}
impl Wire for f64 {
    const WORDS: usize = 1;
    const CAPS: usize = 0;
    fn put(&self, w: &mut Writer<'_>) { w.word(self.to_bits()) }
    fn get(r: &mut Reader<'_>) -> Self { f64::from_bits(r.word()) }
}

impl<T: Wire, const N: usize> Wire for [T; N] {
    const WORDS: usize = N * T::WORDS;
    const CAPS: usize = N * T::CAPS;
    fn put(&self, w: &mut Writer<'_>) {
        for e in self { e.put(w); }
    }
    fn get(r: &mut Reader<'_>) -> Self {
        core::array::from_fn(|_| T::get(r))
    }
}

impl<T> Wire for Cap<T> {
    const WORDS: usize = 0;
    const CAPS: usize = 1;
    fn put(&self, w: &mut Writer<'_>) { w.cap(self.handle) }
    fn get(r: &mut Reader<'_>) -> Self { Cap::from_raw(r.cap()) }
}

impl<T> Wire for Lent<T> {
    const WORDS: usize = 1;
    const CAPS: usize = 1;
    fn put(&self, w: &mut Writer<'_>) {
        match self.get() {
            Some(c) => {
                w.word(1);
                w.cap_dup(c.raw(), self.rights, self.expiry_ns);
            }
            None => w.word(0),
        }
    }
    fn get(r: &mut Reader<'_>) -> Self {
        match r.word() {
            0 => Lent::none(),
            // The receiving side does not learn the rights; the handle is its own.
            1 => Lent { handle: r.cap(), rights: 0, present: true, expiry_ns: 0, _t: PhantomData },
            _ => { r.fail(); Lent::none() }
        }
    }
}

/// Support for generated code: not part of the interface surface.
#[doc(hidden)]
pub mod __private {
    pub use core::result::Result::{Err, Ok};

    /// A fresh reply descriptor of the current version.
    pub fn fresh_reply(reply: &mut super::MsgDesc) {
        *reply = super::MsgDesc::default();
        reply.version = super::MSG_VERSION;
    }

    /// An error reply: status only.
    pub fn error_reply(reply: &mut super::MsgDesc, e: super::IdlError) {
        fresh_reply(reply);
        reply.words[0] = e.status();
        reply.n_words = 1;
    }
}

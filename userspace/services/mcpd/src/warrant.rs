// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The warrants an MCP client presents.
//!
//! An MCP client is a **principal**: a Domain id (a non-zero `u32`). It holds
//! no capability of the kernel; what it may ask the bridge for is a token it
//! presents with each `tools/call` (`params._meta["azos/warrant"]`, the token's
//! wire form in hex). The token is the in-tree macaroon of the RPC transport
//! (`azos_rpc::wire::Token`: an HMAC chain over its caveats, anyone holding it
//! can narrow it and no one can widen it), not a second one. Three kinds, each
//! signed under a key of its own derived from the bridge's root
//! (`HMAC(root, label || principal)`), so one kind never verifies as another:
//!
//! * **An agent's warrant** ([`Scope::Agent`]). `issuer` is the agent's Domain
//!   id, `iface` the interface it is for, the session the boot epoch of the
//!   bridge (which `initialize` reports: a token of an earlier boot verifies
//!   nowhere). It must carry an `EXPIRY` (absolute nanoseconds on the bridge's
//!   monotonic clock, which `initialize` also reports) and an `OP_MASK`; it
//!   may carry one `QUOTA`.
//! * **An operator's warrant** ([`Scope::Admin`]): for the control interface
//!   ([`crate::catalog::CONTROL_ID`]), op [`crate::catalog::GRANT_OP`]; it is
//!   what lets a human issue the other two through the bridge itself. The
//!   bridge mints one at boot for the console (`main.rs`) and nowhere else.
//! * **A human's one-shot warrant** ([`Scope::Human`]). The interface is the
//!   control interface, and the session is the **proposal** it confirms: it
//!   opens that proposal and no other. It must carry an `OP_MASK` naming
//!   confirm ([`crate::catalog::CONFIRM_OP`]), an `EXPIRY` and a `QUOTA` of
//!   exactly 1.
//!
//! **The root is the image's own DICE key** (`LinkKey::node_key`: the board's
//! seed measured with this image), which never leaves the bridge. So the bridge
//! is the only issuer, and a warrant is issued by a human it trusts: the
//! console that reads the operator's enrolment warrant at boot.
//!
//! **The op mask is over IDL ops, not over the kernel's op classes.** Bit `n`
//! of an `OP_MASK` argument is the op numbered `n` of the interface the token
//! is for. The bridge checks it itself, before any call: the kernel's own
//! `OP_MASK` caveat is evaluated against the class of an `invoke` op, and a
//! call to an endpoint a task serves (`SYS_IPC_CALL_V2`) names none, so the
//! kernel refuses every call through a capability that carries one (a
//! kernel-hosted interface holds the call to the mask's IDL op bits itself,
//! `khost::admit`, but the bridge does not rely on that). The warrant the bridge derives
//! for the call (`ENDPOINT_DERIVE`) therefore carries an `EXPIRY` and a `QUOTA`
//! of one use, never the mask.
//!
//! Caveats are read strictly and the list fails closed: more than one `QUOTA`,
//! a kind the bridge does not evaluate (`NODE`, `RECEIPT`, `DECLASSIFY`), a
//! token for another interface, another session or another principal's key, a
//! lapsed `EXPIRY`: refused, with the reason named ([`Refusal`]). Two caveats of
//! one kind narrow: the earlier `EXPIRY` and the intersection of the masks count.
//!
//! A `QUOTA` is counted by the bridge in a [`Ledger`] keyed by what the issuer
//! signed up to and including the `QUOTA` caveat, not by the whole token: a
//! holder can append a caveat to a token and so change its signature, but
//! cannot change the part the count is keyed by. The charge is made last, after
//! every other check, so a refused call does not spend a use; an entry lives
//! until its token's `EXPIRY`. A full ledger refuses new quota tokens.

use alloc::vec::Vec;
use azos_crypto::hkdf::hmac_sha256;
use azos_crypto::sha256::sha256;
use azos_rpc::wire::{cav, get_token, put_token, Caveat, Token, TOKEN_MAX};

/// Quota tokens the ledger tracks at once.
pub const LEDGER_MAX: usize = 32;

/// The longest hex form of a token.
pub const TOKEN_HEX_MAX: usize = 2 * TOKEN_MAX;

/// The root secret the principals' keys derive from. Wiped when dropped.
pub struct Keys {
    root: [u8; 32],
}

impl Keys {
    /// `root` is 32 bytes the operator provisioned; an all-zero one is not a key.
    pub fn new(root: [u8; 32]) -> Option<Keys> {
        if root.iter().all(|&b| b == 0) {
            return None;
        }
        Some(Keys { root })
    }

    fn derive(&self, label: &[u8], principal: u32) -> [u8; 32] {
        hmac_sha256(&self.root, &[label, &principal.to_le_bytes()])
    }

    /// The key an agent's warrants are signed with. The operator's tool
    /// derives the same one.
    pub fn agent(&self, principal: u32) -> [u8; 32] {
        self.derive(b"azos-mcp agent/1", principal)
    }

    /// The key a human's warrants are signed with.
    pub fn human(&self, principal: u32) -> [u8; 32] {
        self.derive(b"azos-mcp human/1", principal)
    }

    /// The key an operator's warrants are signed with.
    pub fn admin(&self, principal: u32) -> [u8; 32] {
        self.derive(b"azos-mcp admin/1", principal)
    }
}

impl Drop for Keys {
    fn drop(&mut self) {
        azos_crypto::ct::secure_zero(&mut self.root);
    }
}

/// What a token is presented for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scope {
    /// An agent's call of an interface, in the boot epoch `epoch`.
    Agent { epoch: u32 },
    /// A human's confirmation of proposal `proposal`; one-shot.
    Human { proposal: u32 },
    /// An operator's grant of warrants, in the boot epoch `epoch`.
    Admin { epoch: u32 },
}

impl Scope {
    fn session(self) -> u32 {
        match self {
            Scope::Agent { epoch } | Scope::Admin { epoch } => epoch,
            Scope::Human { proposal } => proposal,
        }
    }
}

/// Why a token is not a warrant for the call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// No `_meta["azos/warrant"]`.
    NoWarrant,
    /// The hex does not decode to exactly one token.
    Malformed,
    /// The principal is 0.
    NoPrincipal,
    /// The token is for another interface than the op's.
    WrongInterface,
    /// The chain does not hold under this principal's key and this session.
    BadChain,
    /// A caveat the bridge does not evaluate, or a second `QUOTA`.
    Unsupported,
    /// No `EXPIRY`: a warrant that does not run out is not issued.
    NoExpiry,
    /// The `EXPIRY` has passed.
    Lapsed,
    /// No `OP_MASK`: a warrant must say which ops it is for.
    NoOpMask,
    /// The mask does not name the op.
    OpDenied,
    /// A human's warrant must carry a `QUOTA` of exactly 1.
    NotOneShot,
    /// The `QUOTA` is spent.
    Spent,
    /// The ledger is full of live quota tokens.
    LedgerFull,
}

impl Refusal {
    /// The word the answer carries.
    pub fn name(self) -> &'static str {
        match self {
            Refusal::NoWarrant => "no-warrant",
            Refusal::Malformed => "malformed-warrant",
            Refusal::NoPrincipal => "no-principal",
            Refusal::WrongInterface => "wrong-interface",
            Refusal::BadChain => "bad-chain",
            Refusal::Unsupported => "unsupported-caveat",
            Refusal::NoExpiry => "no-expiry",
            Refusal::Lapsed => "lapsed",
            Refusal::NoOpMask => "no-op-mask",
            Refusal::OpDenied => "op-denied",
            Refusal::NotOneShot => "not-one-shot",
            Refusal::Spent => "spent",
            Refusal::LedgerFull => "ledger-full",
        }
    }
}

/// What a token that passed every check grants.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Grant {
    /// The principal: the token's issuer, a Domain id.
    pub principal: u32,
    /// When it runs out, absolute nanoseconds on the bridge's clock.
    pub expiry_ns: u64,
    /// The count to charge once the call is going ahead.
    charge: Option<Charge>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Charge {
    key: [u8; 16],
    limit: u64,
    /// How long the count must be kept: the earliest EXPIRY the issuer signed at or before
    /// the QUOTA. A holder's later caveats cannot shorten it, or the un-narrowed token
    /// would find its count dropped and get a fresh one.
    until_ns: u64,
}

#[derive(Clone, Copy)]
struct Spent {
    key: [u8; 16],
    used: u64,
    until_ns: u64,
}

/// The uses spent of the tokens that carry a `QUOTA`.
#[derive(Default)]
pub struct Ledger {
    entries: Vec<Spent>,
}

impl Ledger {
    /// Take one use of `grant`'s quota, if it has one.
    pub fn charge(&mut self, grant: &Grant, now_ns: u64) -> Result<(), Refusal> {
        let Some(c) = grant.charge else { return Ok(()) };
        self.entries.retain(|e| e.until_ns > now_ns);
        if let Some(e) = self.entries.iter_mut().find(|e| e.key == c.key) {
            if e.used >= c.limit {
                return Err(Refusal::Spent);
            }
            e.used += 1;
            return Ok(());
        }
        if self.entries.len() >= LEDGER_MAX {
            return Err(Refusal::LedgerFull);
        }
        self.entries.push(Spent { key: c.key, used: 1, until_ns: c.until_ns });
        Ok(())
    }

    /// Entries held (the tests read it).
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.entries.len()
    }
}

/// The caveats a token is minted with.
fn with_caveats(mut t: Token, caveats: &[Caveat]) -> Token {
    for c in caveats {
        // Four at most are ever passed, and the kinds are the kernel's own.
        let _ = t.attenuate(*c);
    }
    t
}

/// An agent's warrant: `principal` may call the ops of `mask` of interface
/// `iface` until `expiry_ns`, `uses` times when that is non-zero.
pub fn mint_agent(keys: &Keys, epoch: u32, principal: u32, iface: u32, mask: u64, expiry_ns: u64, uses: u64) -> Token {
    let mut cs = alloc::vec![Caveat::new(cav::EXPIRY, expiry_ns), Caveat::new(cav::OP_MASK, mask)];
    if uses != 0 {
        cs.push(Caveat::new(cav::QUOTA, uses));
    }
    with_caveats(Token::mint(&keys.agent(principal), epoch, principal, iface), &cs)
}

/// A human's one-shot warrant to confirm `proposal`, until `expiry_ns`.
pub fn mint_human(keys: &Keys, principal: u32, proposal: u32, expiry_ns: u64) -> Token {
    let cs = [
        Caveat::new(cav::EXPIRY, expiry_ns),
        Caveat::new(cav::OP_MASK, 1 << crate::catalog::CONFIRM_OP),
        Caveat::new(cav::QUOTA, 1),
    ];
    with_caveats(Token::mint(&keys.human(principal), proposal, principal, crate::catalog::CONTROL_ID), &cs)
}

/// An operator's warrant to grant warrants, until `expiry_ns`.
pub fn mint_admin(keys: &Keys, epoch: u32, principal: u32, expiry_ns: u64) -> Token {
    let cs = [Caveat::new(cav::EXPIRY, expiry_ns), Caveat::new(cav::OP_MASK, 1 << crate::catalog::GRANT_OP)];
    with_caveats(Token::mint(&keys.admin(principal), epoch, principal, crate::catalog::CONTROL_ID), &cs)
}

/// The hex of a token's wire form.
pub fn token_hex(t: &Token) -> alloc::string::String {
    let mut b = [0u8; TOKEN_MAX];
    let mut at = 0;
    // `TOKEN_MAX` holds the longest token.
    let _ = put_token(t, &mut b, &mut at);
    to_hex(&b[..at])
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Bytes of the hex text `s`; `None` for an odd length or a non-digit.
pub fn from_hex(s: &str) -> Option<Vec<u8>> {
    let b = s.as_bytes();
    if b.len() % 2 != 0 {
        return None;
    }
    b.chunks_exact(2).map(|p| Some(hex_val(p[0])? << 4 | hex_val(p[1])?)).collect()
}

/// Lower-case hex of `b`.
pub fn to_hex(b: &[u8]) -> alloc::string::String {
    const D: &[u8; 16] = b"0123456789abcdef";
    let mut s = alloc::string::String::with_capacity(b.len() * 2);
    for x in b {
        s.push(D[(x >> 4) as usize] as char);
        s.push(D[(x & 15) as usize] as char);
    }
    s
}

/// The token of a hex text: exactly one, nothing after it.
pub fn parse(hex: &str) -> Result<Token, Refusal> {
    if hex.len() > TOKEN_HEX_MAX {
        return Err(Refusal::Malformed);
    }
    let bytes = from_hex(hex).ok_or(Refusal::Malformed)?;
    let mut at = 0;
    let tok = get_token(&bytes, &mut at).ok_or(Refusal::Malformed)?;
    if at != bytes.len() {
        return Err(Refusal::Malformed);
    }
    Ok(tok)
}

/// Does `tok`, presented in `scope`, grant op `op` of interface `iface` at
/// `now_ns`? Everything is checked and nothing is spent: the caller charges
/// the [`Grant`] with [`Ledger::charge`] when the call goes ahead.
pub fn check(keys: &Keys, scope: Scope, tok: &Token, iface: u32, op: u16, now_ns: u64) -> Result<Grant, Refusal> {
    if tok.issuer == 0 {
        return Err(Refusal::NoPrincipal);
    }
    if tok.iface != iface {
        return Err(Refusal::WrongInterface);
    }
    let key = match scope {
        Scope::Agent { .. } => keys.agent(tok.issuer),
        Scope::Human { .. } => keys.human(tok.issuer),
        Scope::Admin { .. } => keys.admin(tok.issuer),
    };
    if !tok.verify(&key, scope.session()) {
        return Err(Refusal::BadChain);
    }
    let (mut expiry, mut mask, mut quota) = (None::<u64>, None::<u64>, None::<u64>);
    // What the issuer signed up to and including the QUOTA caveat: the count's key.
    let mut signed: Vec<u8> = Vec::new();
    // The earliest EXPIRY among those signed up to the QUOTA (none: keep the count for good).
    let mut signed_until = u64::MAX;
    signed.extend_from_slice(&tok.issuer.to_le_bytes());
    signed.extend_from_slice(&tok.iface.to_le_bytes());
    signed.extend_from_slice(&scope.session().to_le_bytes());
    signed.push(match scope {
        Scope::Agent { .. } => 0,
        Scope::Human { .. } => 1,
        Scope::Admin { .. } => 2,
    });
    for c in tok.caveats() {
        if quota.is_none() {
            if c.kind == cav::EXPIRY {
                signed_until = signed_until.min(c.arg);
            }
            signed.push(c.kind);
            signed.extend_from_slice(&c.arg.to_le_bytes());
        }
        match c.kind {
            cav::EXPIRY => expiry = Some(expiry.map_or(c.arg, |e| e.min(c.arg))),
            cav::OP_MASK => mask = Some(mask.map_or(c.arg, |m| m & c.arg)),
            cav::QUOTA if quota.is_none() => quota = Some(c.arg),
            _ => return Err(Refusal::Unsupported),
        }
    }
    let expiry = expiry.ok_or(Refusal::NoExpiry)?;
    if expiry <= now_ns {
        return Err(Refusal::Lapsed);
    }
    let mask = mask.ok_or(Refusal::NoOpMask)?;
    if op >= 64 || mask >> op & 1 == 0 {
        return Err(Refusal::OpDenied);
    }
    if matches!(scope, Scope::Human { .. }) && quota != Some(1) {
        return Err(Refusal::NotOneShot);
    }
    let charge = match quota {
        None => None,
        Some(0) => return Err(Refusal::Spent),
        Some(limit) => {
            let d = sha256(&signed);
            let mut key = [0u8; 16];
            key.copy_from_slice(&d[..16]);
            Some(Charge { key, limit, until_ns: signed_until })
        }
    };
    Ok(Grant { principal: tok.issuer, expiry_ns: expiry, charge })
}

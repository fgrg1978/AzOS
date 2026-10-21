// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! One session with one peer node: its state, the window that keeps a call
//! from running twice, the warrants this node minted for the peer and the
//! objects it re-minted over the session. **A session is the unit of revocation:**
//! when it breaks, everything in [`Session::warrants`] and [`Session::minted`]
//! is closed.

use crate::chan::Channel;
use crate::policy::Name;
use crate::wire::{cav, Caveat, Token, CAVEATS_MAX, HELLO_MAX, SIG_BYTES};
use crate::{NodeId, DEDUPE_CAP, IFACES_MAX, MINTED_CAP, QUOTAS_MAX, REPLY_KEEP, WARRANTS_MAX};

/// Where a session is.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum State {
    /// The slot is free.
    Free,
    /// This node dialed (it has the lower node id) and waits for the answer.
    Dialing,
    /// Both sides proved who they are; calls may cross.
    Up,
}

/// What [`Dedupe::lookup`] knows of a call number.
#[derive(Debug, PartialEq, Eq)]
pub enum Seen<'a> {
    /// Never run here: run it.
    Fresh,
    /// Run, and its answer is kept: send it again, run nothing.
    Cached(&'a [u8]),
    /// Run, but the answer is gone (too large to keep, or pushed out of the
    /// window): the outcome is unknown.
    Unknown,
}

#[derive(Clone, Copy)]
struct Entry {
    used: bool,
    seq: u64,
    kept: bool,
    len: u16,
    body: [u8; REPLY_KEEP],
}

/// The window of calls this node has run for a peer and the answers it kept.
/// A call number above everything seen is fresh; one in the window is
/// answered from it; one at or below the lowest number the window ever
/// dropped is unknown, because the window cannot say whether it ran. The size
/// is the Kconfig `RPC_DEDUPE_WINDOW` (at most [`DEDUPE_CAP`]).
pub struct Dedupe {
    entries: [Entry; DEDUPE_CAP],
    window: usize,
    /// Every call number at or below this was run (or never will be) and is no
    /// longer in the window.
    floor: u64,
    next: usize,
}

impl Dedupe {
    /// A window of `window` entries (0: unusable until [`Dedupe::reset`], so
    /// that a free session is all zeros and its storage costs no image bytes).
    pub const fn new(window: usize) -> Dedupe {
        Dedupe {
            entries: [Entry { used: false, seq: 0, kept: false, len: 0, body: [0; REPLY_KEEP] }; DEDUPE_CAP],
            window,
            floor: 0,
            next: 0,
        }
    }

    /// Forget everything and resize.
    pub fn reset(&mut self, window: usize) {
        for e in self.entries.iter_mut() {
            e.used = false;
        }
        self.window = window.clamp(1, DEDUPE_CAP);
        self.floor = 0;
        self.next = 0;
    }

    /// What is known of call `seq`.
    pub fn lookup(&self, seq: u64) -> Seen<'_> {
        if let Some(e) = self.entries[..self.window].iter().find(|e| e.used && e.seq == seq) {
            return if e.kept { Seen::Cached(&e.body[..e.len as usize]) } else { Seen::Unknown };
        }
        if seq <= self.floor { Seen::Unknown } else { Seen::Fresh }
    }

    /// Call `seq` ran; `body` is its answer, `None` when it is too large to
    /// keep (a duplicate then finds the outcome unknown). The oldest entry
    /// leaves the window when it is full, and raises the floor.
    pub fn record(&mut self, seq: u64, body: Option<&[u8]>) {
        let slot = match self.entries[..self.window].iter().position(|e| !e.used) {
            Some(i) => i,
            None => {
                let i = self.next;
                self.next = (self.next + 1) % self.window;
                self.floor = self.floor.max(self.entries[i].seq);
                i
            }
        };
        let e = &mut self.entries[slot];
        e.used = true;
        e.seq = seq;
        match body {
            Some(b) if b.len() <= REPLY_KEEP => {
                e.kept = true;
                e.len = b.len() as u16;
                e.body[..b.len()].copy_from_slice(b);
            }
            _ => {
                e.kept = false;
                e.len = 0;
            }
        }
    }
}

/// The warrant this node minted for the peer over one exported endpoint: a
/// child of this node's own capability on it, attenuated to the call right,
/// badged with the session, carrying the caveats of the token it was minted
/// for and lapsing at `expiry_ns`.
#[derive(Clone, Copy)]
pub struct Warrant {
    /// Whether the slot holds one.
    pub live: bool,
    /// The interface id it is for.
    pub iface: u32,
    /// The caveats it was derived with (the token's, without its `QUOTA`s:
    /// those are the session's [`Quota`]s), `n_caveats` of them: the key it is
    /// cached under with `iface`. A call whose token re-mints to another set,
    /// or lapses sooner than the warrant does, does not use it.
    pub caveats: [Caveat; CAVEATS_MAX],
    pub n_caveats: u8,
    /// The handle in this task's table.
    pub handle: u32,
    /// Absolute ns on this node's clock it lapses at.
    pub expiry_ns: u64,
}

/// One `QUOTA` caveat of a verified token: how many uses it allows, and the
/// lineage it counts them in.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Budget {
    /// The token's signature once this caveat was added: the same for the
    /// token and for every copy of it that narrows it further, whoever holds
    /// the copy and however it is narrowed ([`Token::prefix_sigs`]).
    pub lineage: [u8; SIG_BYTES],
    /// The uses the caveat allows.
    pub uses: u64,
}

/// What a lineage has left of its [`Budget`]. **The count belongs to the
/// lineage, not to a warrant or a token**: a copy narrowed after some uses
/// were spent, or narrowed in many ways, counts in the same budget as the
/// original, and the entry of a spent budget stays (and keeps refusing) until
/// the session ends.
#[derive(Clone, Copy)]
pub struct Quota {
    /// Whether the slot holds one.
    pub live: bool,
    pub lineage: [u8; SIG_BYTES],
    /// Uses left.
    pub left: u64,
}

/// What a verified token makes of the warrant this node mints locally: the
/// peer's caveats, narrowed to what this node can hold and always at least as
/// strict as the token.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Remint {
    /// The interface id.
    pub iface: u32,
    /// Absolute ns on this node's clock the warrant lapses at; 0 never (only
    /// when neither the TTL nor the token bounds it).
    pub expiry_ns: u64,
    /// The token's `QUOTA` caveats, in order, valid up to `n_budgets`; a use
    /// takes one from each ([`Session::spend`]).
    pub budgets: [Budget; CAVEATS_MAX],
    pub n_budgets: u8,
    /// The caveats to put on the derived capability (`OP_MASK` first, when the
    /// token narrows the ops, then the reserved kinds in the order they came),
    /// valid up to `n_caveats`. `EXPIRY`, `QUOTA` and `NODE` are not in it:
    /// the first is `expiry_ns`, the second is `budgets`, the third was
    /// checked here.
    pub caveats: [Caveat; CAVEATS_MAX],
    pub n_caveats: u8,
}

impl Remint {
    /// The caveats to derive with.
    pub fn caveat_list(&self) -> &[Caveat] {
        &self.caveats[..self.n_caveats as usize]
    }

    /// The token's quotas.
    pub fn budget_list(&self) -> &[Budget] {
        &self.budgets[..self.n_budgets as usize]
    }

    /// Can a call through the warrant ever pass the kernel's resolve? The call
    /// names no op, so an `OP_MASK` is never discharged, and `DECLASSIFY` has
    /// no evaluator: a warrant with either refuses every use, and the call is
    /// refused here, before a derive that could not be used.
    pub fn usable(&self) -> bool {
        self.caveat_list().iter().all(|c| c.kind != cav::OP_MASK && c.kind != cav::DECLASSIFY)
    }
}

/// Why a token does not become a warrant. Every one is a refusal of the call;
/// none makes the session break.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Refusal {
    /// The session is not up.
    NotUp,
    /// The channel holds no keys.
    NoKey,
    /// The token was not started by the peer of this session.
    WrongIssuer,
    /// This node does not serve the interface to the peer.
    NotGranted,
    /// The chain does not hold under this session's key (a caveat changed,
    /// removed or reordered, another session's token, a forged one).
    BadChain,
    /// A `NODE` caveat names another node.
    WrongNode,
    /// The token's `EXPIRY` has run out.
    Lapsed,
    /// The token's `QUOTA` is spent.
    Spent,
    /// The `OP_MASK` caveats leave no op.
    NoOps,
    /// The token carries a `DECLASSIFY` caveat, which only a local user
    /// session issues.
    Declassify,
}

/// An object re-minted from the peer's pages: the handle this node holds (the
/// parent of the copy lent to the local server or caller) and when the lent
/// copy lapses.
#[derive(Clone, Copy)]
pub struct Minted {
    /// Whether the slot holds one.
    pub live: bool,
    /// The handle in this task's table.
    pub handle: u32,
    /// Absolute ns on this node's clock it lapses at.
    pub expiry_ns: u64,
}

/// A session.
pub struct Session {
    pub state: State,
    pub peer: NodeId,
    /// The peer's class.
    pub class: Name,
    /// The session id (assigned by the node with the higher id, the answerer).
    pub id: u32,
    /// The peer's boot epoch when the session was made.
    pub peer_epoch: u32,
    /// The dialer's nonce of the HELLO that made it, so a repeated HELLO is
    /// answered with the same session.
    pub nonce: u64,
    /// Calls this node sends are numbered from here.
    pub next_seq: u64,
    /// The last time any frame of the peer arrived (ns, this node's clock).
    pub heard_ns: u64,
    /// The last time this node sent the peer something that wants an answer
    /// (a Hello or a Ping).
    pub probed_ns: u64,
    /// Probes or calls that went unanswered in a row.
    pub misses: u8,
    /// HELLOs sent for this dial.
    pub hellos: u8,
    /// The interface ids the peer serves this node.
    pub offered: [u32; IFACES_MAX],
    pub n_offered: u8,
    /// The interface ids this node serves the peer.
    pub granted: [u32; IFACES_MAX],
    pub n_granted: u8,
    /// Calls the peer sent that this node has run, for the non-idempotent ops.
    pub dedupe: Dedupe,
    pub warrants: [Warrant; WARRANTS_MAX],
    /// The budgets the peer's tokens have spent from, by lineage.
    pub quotas: [Quota; QUOTAS_MAX],
    pub minted: [Minted; MINTED_CAP],
    /// The keys of the session: every frame after the handshake is sealed
    /// with them.
    pub chan: Channel,
    /// While dialing: the ephemeral key of the Hello (the handshake is a pure
    /// function of its inputs, so this and the Hello are all the answer needs).
    pub eph: [u8; 32],
    /// While dialing: the Hello as sent, for the resends.
    pub hello: [u8; HELLO_MAX],
    pub hello_len: u8,
    /// Whether a sealed frame of the peer has opened under these keys. The
    /// dialer's first Ping is what confirms the session to the answerer; until
    /// one comes back it is resent every `rto`.
    pub confirmed: bool,
}

/// A handshake the answering node has answered and whose dialer has not yet
/// shown it holds the keys. **A Hello never disturbs a session that is up:** a
/// captured Hello replayed later makes a pending handshake, which no one can
/// confirm, and the session stands. The first frame that opens under the new
/// keys (the dialer sends a Ping as soon as it has the answer) confirms it, and
/// only then does it replace the session the peer had.
pub struct Pending {
    pub used: bool,
    pub peer: NodeId,
    pub class: Name,
    pub id: u32,
    pub peer_epoch: u32,
    /// The Hello's nonce (the header's `seq`).
    pub nonce: u64,
    pub born_ns: u64,
    pub offered: [u32; IFACES_MAX],
    pub n_offered: u8,
    pub granted: [u32; IFACES_MAX],
    pub n_granted: u8,
    pub chan: Channel,
    /// The answer as sent, for a Hello that is resent.
    pub ack: [u8; HELLO_MAX],
    pub ack_len: u8,
}

impl Pending {
    /// An unused slot.
    pub const fn free() -> Pending {
        Pending {
            used: false,
            peer: 0,
            class: Name::EMPTY,
            id: 0,
            peer_epoch: 0,
            nonce: 0,
            born_ns: 0,
            offered: [0; IFACES_MAX],
            n_offered: 0,
            granted: [0; IFACES_MAX],
            n_granted: 0,
            chan: Channel::idle(),
            ack: [0; HELLO_MAX],
            ack_len: 0,
        }
    }
}

impl Session {
    /// A free slot.
    pub const fn free() -> Session {
        Session {
            state: State::Free,
            peer: 0,
            class: Name::EMPTY,
            id: 0,
            peer_epoch: 0,
            nonce: 0,
            next_seq: 0,
            heard_ns: 0,
            probed_ns: 0,
            misses: 0,
            hellos: 0,
            offered: [0; IFACES_MAX],
            n_offered: 0,
            granted: [0; IFACES_MAX],
            n_granted: 0,
            dedupe: Dedupe::new(0),
            warrants: [Warrant { live: false, iface: 0, caveats: [Caveat::new(0, 0); CAVEATS_MAX], n_caveats: 0, handle: 0, expiry_ns: 0 }; WARRANTS_MAX],
            quotas: [Quota { live: false, lineage: [0; SIG_BYTES], left: 0 }; QUOTAS_MAX],
            minted: [Minted { live: false, handle: 0, expiry_ns: 0 }; MINTED_CAP],
            chan: Channel::idle(),
            eph: [0; 32],
            hello: [0; HELLO_MAX],
            hello_len: 0,
            confirmed: false,
        }
    }

    /// Free the slot and forget its keys.
    pub fn clear(&mut self) {
        self.state = State::Free;
        self.chan.clear();
        crate::chan::wipe(&mut self.eph);
    }

    /// Forget what the peer's tokens spent (a new session has new keys, so no
    /// earlier token verifies in it).
    pub fn reset_quotas(&mut self) {
        self.quotas.iter_mut().for_each(|q| q.live = false);
    }

    /// Take one use from each of `budgets`, all or none: false (nothing taken)
    /// when one of them is spent, or when the table has no room for the
    /// lineages not yet counted (a budget that cannot be counted is refused,
    /// not served for free, and a spent one is never evicted for room: either
    /// would hand its holder a fresh count).
    pub fn spend(&mut self, budgets: &[Budget]) -> bool {
        let mut fresh = 0;
        for b in budgets {
            match self.quotas.iter().find(|q| q.live && q.lineage == b.lineage) {
                Some(q) if q.left == 0 => return false,
                Some(_) => {}
                None => fresh += 1,
            }
        }
        if self.quotas.iter().filter(|q| !q.live).count() < fresh {
            return false;
        }
        for b in budgets {
            let k = match self.quotas.iter().position(|q| q.live && q.lineage == b.lineage) {
                Some(k) => k,
                None => {
                    let k = self.quotas.iter().position(|q| !q.live).unwrap_or(0);
                    self.quotas[k] = Quota { live: true, lineage: b.lineage, left: b.uses };
                    k
                }
            };
            self.quotas[k].left -= 1;
        }
        true
    }

    /// Does the peer serve interface `id` to this node?
    pub fn offers(&self, id: u32) -> bool {
        self.offered[..self.n_offered as usize].contains(&id)
    }

    /// Does this node serve interface `id` to the peer?
    pub fn grants(&self, id: u32) -> bool {
        self.granted[..self.n_granted as usize].contains(&id)
    }

    /// The token for a call to interface `iface` of the peer, started by
    /// `local` (this node's id): no caveat yet, the sender attenuates it.
    /// `None` when the session is not up, holds no keys, or the peer does not
    /// serve `iface` to this node.
    pub fn issue(&self, local: NodeId, iface: u32) -> Option<Token> {
        if self.state != State::Up || !self.offers(iface) {
            return None;
        }
        Some(Token::mint(self.chan.mac_key()?, self.id, local, iface))
    }

    /// Turn a token that arrived over this session into the warrant to mint
    /// for the peer, or say why not. The chain is verified under this
    /// session's key, so a caveat edited, removed or reordered, a token of
    /// another session or one the peer did not start is refused; what the
    /// verified caveats say is then held to this node: the warrant lapses at
    /// the earliest of the token's `EXPIRY` and `ttl_ns` (0: no TTL), carries
    /// every `QUOTA` as a [`Budget`], the intersection of the `OP_MASK`s and the
    /// reserved kinds as they came (the kernel refuses a use until their
    /// evaluators exist), and a `NODE` that is not `local` refuses it. The
    /// result can only be narrower than the token, never wider.
    pub fn remint(&self, tok: &Token, local: NodeId, now_ns: u64, ttl_ns: u64) -> Result<Remint, Refusal> {
        if self.state != State::Up {
            return Err(Refusal::NotUp);
        }
        let key = self.chan.mac_key().ok_or(Refusal::NoKey)?;
        if tok.issuer != self.peer {
            return Err(Refusal::WrongIssuer);
        }
        if !self.grants(tok.iface) {
            return Err(Refusal::NotGranted);
        }
        if !tok.verify(key, self.id) {
            return Err(Refusal::BadChain);
        }
        let mut left = if ttl_ns == 0 { u64::MAX } else { ttl_ns };
        let sigs = tok.prefix_sigs(key, self.id);
        let mut budgets = [Budget { lineage: [0; SIG_BYTES], uses: 0 }; CAVEATS_MAX];
        let mut nb = 0;
        let mut mask = u64::MAX;
        let mut kept = [Caveat::new(0, 0); CAVEATS_MAX];
        let mut m = 0;
        for (i, c) in tok.caveats().iter().enumerate() {
            match c.kind {
                cav::EXPIRY if c.arg == 0 => return Err(Refusal::Lapsed),
                cav::EXPIRY => left = left.min(c.arg),
                cav::QUOTA if c.arg == 0 => return Err(Refusal::Spent),
                cav::QUOTA => {
                    budgets[nb] = Budget { lineage: sigs[i], uses: c.arg };
                    nb += 1;
                }
                cav::NODE if c.arg != local as u64 => return Err(Refusal::WrongNode),
                cav::NODE => {}
                cav::OP_MASK => mask &= c.arg,
                // A declassification is a local human's warrant, issued by a
                // user session on this node (`ENDPOINT_DERIVE`) and never
                // carried by a peer: a token that names one would let a
                // remote node wash a label.
                cav::DECLASSIFY => return Err(Refusal::Declassify),
                // RECEIPT: carried. `get_token` and `attenuate` admit no
                // other kind.
                _ => {
                    kept[m] = *c;
                    m += 1;
                }
            }
        }
        if mask == 0 {
            return Err(Refusal::NoOps);
        }
        // A narrowing mask took one of the token's (at most four) caveats, so
        // the reserved ones plus the mask fit the list.
        let mut r = Remint { iface: tok.iface, expiry_ns: 0, budgets, n_budgets: nb as u8, caveats: kept, n_caveats: m as u8 };
        if mask != u64::MAX {
            r.caveats.copy_within(0..m, 1);
            r.caveats[0] = Caveat::new(cav::OP_MASK, mask);
            r.n_caveats += 1;
        }
        r.expiry_ns = if left == u64::MAX { 0 } else { now_ns.saturating_add(left) };
        Ok(r)
    }
}

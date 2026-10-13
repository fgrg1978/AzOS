// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! One session with one peer node: its state, the window that keeps a call
//! from running twice, the warrants this node minted for the peer and the
//! objects it re-minted over the session. **A session is the unit of revocation:**
//! when it breaks, everything in [`Session::warrants`] and [`Session::minted`]
//! is closed.

use crate::policy::Name;
use crate::{NodeId, DEDUPE_CAP, IFACES_MAX, MINTED_CAP, REPLY_KEEP};

/// Where a session is.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum State {
    /// The slot is free.
    Free,
    /// This node dialed (it has the lower node id) and waits for the answer.
    Dialing,
    /// Both sides agreed; calls may cross.
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
/// badged with the session and lapsing at `expiry_ns`.
#[derive(Clone, Copy)]
pub struct Warrant {
    /// Whether the slot holds one.
    pub live: bool,
    /// The interface id it is for.
    pub iface: u32,
    /// The handle in this task's table.
    pub handle: u32,
    /// Absolute ns on this node's clock it lapses at.
    pub expiry_ns: u64,
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
    pub warrants: [Warrant; IFACES_MAX],
    pub minted: [Minted; MINTED_CAP],
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
            warrants: [Warrant { live: false, iface: 0, handle: 0, expiry_ns: 0 }; IFACES_MAX],
            minted: [Minted { live: false, handle: 0, expiry_ns: 0 }; MINTED_CAP],
        }
    }

    /// Does the peer serve interface `id` to this node?
    pub fn offers(&self, id: u32) -> bool {
        self.offered[..self.n_offered as usize].contains(&id)
    }

    /// Does this node serve interface `id` to the peer?
    pub fn grants(&self, id: u32) -> bool {
        self.granted[..self.n_granted as usize].contains(&id)
    }
}

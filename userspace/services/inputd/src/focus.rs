// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The input server's decisions: who holds the focus, which events reach the
//! holder, and what the Secure Attention Key does.
//!
//! Pure given a [`Host`] (the drivers' event stream, the holder's ring, the
//! warrant, the console): `tests/host/inputd-tests` pulls this file in with
//! `#[path]` and drives it through the generated client stub over a loopback,
//! so the wire form a client sends and receives is the one under test.
//!
//! **Focus is a warrant.** The holder is the task that was lent the warrant of
//! the live generation ([`azos_devif::input::warrant_badge`]) and the ring of
//! that generation. A grant makes both before it takes anything away from the
//! old holder, so a grant that fails (no memory object left, no capability slot)
//! leaves the focus where it was. Moving the focus revokes the old warrant
//! (the kernel then refuses the old holder's calls), writes the close word into
//! its ring and gives the region back. Nothing is delivered to a ring after it
//! is closed.
//!
//! **The Secure Attention Key** is Ctrl+Alt+Delete (either Ctrl, either Alt):
//! the Delete press that completes the chord, its repeats and its release are
//! swallowed, the chord is counted on the trusted-path page, and whoever holds
//! the focus loses it. The modifiers that led up to it were already delivered
//! (they are not an event the server can know is a chord's); the closed ring
//! tells the old holder to drop what it built from them.
//!
//! **The chord chooses who may hold the focus next.** Focus authority is the
//! call right on `endpoint.input` (what `take_focus` needs, and every program
//! started through `TOOLBOX.ELF` holds it), so on its own the chord would only
//! revoke: the old holder or any other caller could take the focus straight
//! back. With a trusted surface in the build (`gated`, Kconfig `COMPOSITOR`) the
//! chord also sets *attention pending*. While it is set, `take_focus` from any
//! caller but the trusted surface is refused (`DENIED`, recorded `NO_GRANT`):
//! the trusted surface is the one caller whose call right carries
//! [`input::TRUSTED_BADGE`], a badge the kernel stamps on the compositor's row
//! alone (`azos_devif::input::grant_badge`, `cap_seed.rs`), which no
//! application can mint and no warrant can look like. Its `take_focus` clears
//! the flag, and from then on the focus is obtainable again, so the compositor
//! decides when the plain callers may have it back (after it has drawn the
//! trusted-path banner the user sees). Without a compositor row the gate is
//! off (`gated` false): a gate with nobody to open it would leave the focus
//! unobtainable.
//!
//! **State rebuilt from events can be wrong.** The server tracks the modifier
//! keys and mouse buttons that are down, to hand a new holder the true state at
//! the start of its ring ([`Service::take_focus`] replays them as presses). The
//! drivers' stream counts what it dropped when it was full; when the count
//! moved and the stream has been drained, a release may have been lost, so
//! everything held is let go and the holder is told with releases.
//!
//! **Decision record.** Every focus move and every refusal is a [`Record`]
//! (kept, newest over oldest, and written to the console) with the shape of the
//! kernel's `Rule::Focus` (`from`, `to`, `reason`). A ring-3 server cannot write
//! the kernel's journal; the kernel's own `CapDerive` and `CapRevoke` records
//! already show the warrant being minted and revoked.

use azos_abi::cap::CapPerms;
use azos_devif::input::{self, FocusLease, Input, Status, TrustedLease};
use azos_devif::{outcome, Out};
use azos_idl::Lent;
use azos_input_wire::event::*;

/// Most events one [`Service::pump`] takes, so a flood cannot hold the lock a
/// request waits for.
pub const BATCH: usize = 64;

/// Records kept (the newest overwrite the oldest); the count is not bounded.
pub const RECORDS_KEPT: usize = 8;

/// The rights the warrant carries: the call right, nothing else (not `DUP`:
/// the holder cannot hand the focus on).
pub const WARRANT_RIGHTS: CapPerms = CapPerms::WRITE;
/// The rights of the ring: the holder reads it and moves the tail.
pub const RING_RIGHTS: CapPerms = CapPerms::READ.union(CapPerms::WRITE).union(CapPerms::MAP);
/// The rights of the trusted-path page: read and map, never write.
pub const PAGE_RIGHTS: CapPerms = CapPerms::READ.union(CapPerms::MAP);

/// Why a [`Record`] was made.
pub mod reason {
    /// The focus moved to a new holder.
    pub const MOVED: u8 = 0;
    /// A call that needed the live warrant did not carry it, or a plain caller
    /// asked for the focus while the Secure Attention Key's was pending.
    pub const NO_GRANT: u8 = 1;
    /// The Secure Attention Key took the focus. With a trusted surface in the
    /// build only it may take the focus next (see the module doc).
    pub const TRUSTED: u8 = 2;
    /// The holder gave the focus up.
    pub const RELEASED: u8 = 3;
}

/// One focus decision, the shape of the kernel's `Rule::Focus` record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Record {
    pub at_ns: u64,
    /// The generation that held the focus (0 none).
    pub from: u32,
    /// The generation that holds it now (0 none).
    pub to: u32,
    pub reason: u8,
}

const NO_RECORD: Record = Record { at_ns: 0, from: 0, to: 0, reason: 0 };

/// A holder's ring: the region's capability and where it is mapped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ring {
    pub handle: u32,
    pub base: usize,
}

/// What the server needs from its surroundings.
pub trait Host {
    /// The next word of the drivers' event stream.
    fn pop(&mut self) -> Option<u64>;
    /// Events the stream lost because it was full, since it began; wraps.
    fn stream_drops(&mut self) -> u32;
    /// The monotonic clock, nanoseconds.
    fn now_ns(&mut self) -> u64;
    /// A fresh, mapped, zeroed ring region; `None` when no memory object is
    /// left.
    fn make_ring(&mut self) -> Option<Ring>;
    /// Put one event word into the ring; `false` when it is full (the host
    /// also counts the drop in the ring).
    fn push(&mut self, ring: &Ring, word: u64) -> bool;
    /// The ring will not be written again: say so in it and give the region
    /// back.
    fn close_ring(&mut self, ring: &Ring);
    /// Derive the warrant of `generation` from the server's own endpoint: the
    /// handle, or `None` when the capability cannot be made.
    fn derive_warrant(&mut self, generation: u32) -> Option<u32>;
    /// Revoke what was lent through `warrant` and give the handle up.
    fn revoke(&mut self, warrant: u32);
    /// The capability of the trusted-path page.
    fn trusted_page(&mut self) -> Option<u32>;
    /// A Secure Attention Key chord was seen at `now_ns`: count it on the page.
    fn note_sak(&mut self, now_ns: u64);
    /// A line for the console.
    fn log(&mut self, line: &[u8]);
}

#[derive(Clone, Copy)]
struct Holder {
    generation: u32,
    warrant: u32,
    ring: Ring,
}

/// The keys and buttons whose state the server keeps, in bit order.
const HELD: [u16; 11] = [
    KEY_LEFTCTRL,
    KEY_RIGHTCTRL,
    KEY_LEFTSHIFT,
    KEY_RIGHTSHIFT,
    KEY_LEFTALT,
    KEY_RIGHTALT,
    KEY_LEFTMETA,
    KEY_RIGHTMETA,
    BTN_LEFT,
    BTN_RIGHT,
    BTN_MIDDLE,
];

const fn held_bit(code: u16) -> u16 {
    let mut i = 0;
    while i < HELD.len() {
        if HELD[i] == code {
            return 1 << i;
        }
        i += 1;
    }
    0
}

const CTRL: u16 = held_bit(KEY_LEFTCTRL) | held_bit(KEY_RIGHTCTRL);
const ALT: u16 = held_bit(KEY_LEFTALT) | held_bit(KEY_RIGHTALT);

/// The Input object served over a [`Host`].
pub struct Service<H: Host> {
    pub host: H,
    /// The badge of the call being served; the loop sets it from the request
    /// (0 when the request carried none).
    pub caller: u32,
    /// Is there a trusted surface to open the gate the Secure Attention Key
    /// closes (Kconfig `COMPOSITOR`)? Without one the chord only revokes.
    gated: bool,
    /// The Secure Attention Key took the focus and the trusted surface has not
    /// taken it since: no other caller is granted it.
    pending: bool,
    holder: Option<Holder>,
    grants: u32,
    /// Bit `i` of [`HELD`] is down.
    held: u16,
    /// A chord's Delete is down: its repeats and its release are swallowed.
    swallowing: bool,
    sak: u32,
    events: u64,
    lost: u32,
    refused: u32,
    drops_seen: u32,
    records: [Record; RECORDS_KEPT],
    made: u32,
}

impl<H: Host> Service<H> {
    pub const fn new(host: H, gated: bool) -> Self {
        Self {
            host,
            caller: 0,
            gated,
            pending: false,
            holder: None,
            grants: 0,
            held: 0,
            swallowing: false,
            sak: 0,
            events: 0,
            lost: 0,
            refused: 0,
            drops_seen: 0,
            records: [NO_RECORD; RECORDS_KEPT],
            made: 0,
        }
    }

    /// Take over the stream: drop what piled up before there was a server (stale
    /// keys and motion nobody should act on now) and start counting its losses
    /// from here.
    pub fn attach(&mut self) {
        while self.host.pop().is_some() {}
        self.drops_seen = self.host.stream_drops();
    }

    /// Is the Secure Attention Key's gate closed: only the trusted surface may
    /// take the focus? (The host suite reads it; on the target it is the refusal.)
    #[cfg(test)]
    pub fn pending(&self) -> bool {
        self.pending
    }

    /// The generation that holds the focus (0: nobody).
    pub fn holder(&self) -> u32 {
        self.holder.map_or(0, |h| h.generation)
    }

    /// The newest decision first, up to [`RECORDS_KEPT`]. (The host suite reads
    /// the record; on the target it is the console line.)
    #[cfg(test)]
    pub fn records(&self) -> impl Iterator<Item = &Record> {
        let n = (self.made as usize).min(RECORDS_KEPT);
        (0..n).map(move |k| &self.records[(self.made as usize - 1 - k) % RECORDS_KEPT])
    }

    fn record(&mut self, from: u32, to: u32, reason: u8) {
        let at_ns = self.host.now_ns();
        self.records[self.made as usize % RECORDS_KEPT] = Record { at_ns, from, to, reason };
        self.made = self.made.wrapping_add(1);
        // "[inputd] focus 1 -> 2 (moved)"
        let mut line = [0u8; 64];
        let mut w = put(&mut line, 0, b"[inputd] focus ");
        let mut d = [0u8; 10];
        w = put(&mut line, w, dec(from, &mut d));
        w = put(&mut line, w, b" -> ");
        w = put(&mut line, w, dec(to, &mut d));
        w = put(&mut line, w, b" (");
        w = put(
            &mut line,
            w,
            match reason {
                reason::MOVED => b"moved",
                reason::NO_GRANT => b"refused: no grant",
                reason::TRUSTED => b"trusted path",
                _ => b"released",
            },
        );
        w = put(&mut line, w, b")\n");
        self.host.log(&line[..w]);
    }

    /// Take the focus away from the holder, if any: revoke the warrant, close
    /// and give back the ring. The generation that held it.
    fn drop_holder(&mut self) -> u32 {
        let Some(h) = self.holder.take() else { return 0 };
        self.host.revoke(h.warrant);
        self.host.close_ring(&h.ring);
        h.generation
    }

    /// Hand the holder one event; a full ring loses it.
    fn deliver(&mut self, word: u64) {
        let Some(h) = self.holder else { return };
        if !self.host.push(&h.ring, word) {
            self.lost = self.lost.wrapping_add(1);
        }
    }

    /// Release everything the server thinks is down, to the holder too.
    fn let_go(&mut self) {
        let held = core::mem::take(&mut self.held);
        self.swallowing = false;
        for (i, &code) in HELD.iter().enumerate() {
            if held & (1 << i) != 0 {
                self.deliver(pack(EV_KEY, code, 0));
            }
        }
    }

    /// Take the events waiting, at most [`BATCH`]. Returns whether any were.
    pub fn pump(&mut self) -> bool {
        // Read before draining: a drop that lands while draining is seen the
        // next time.
        let drops = self.host.stream_drops();
        let mut any = false;
        let mut drained = false;
        for _ in 0..BATCH {
            let Some(w) = self.host.pop() else {
                drained = true;
                break;
            };
            any = true;
            self.events += 1;
            self.route(w);
        }
        if drained && drops != self.drops_seen {
            self.lost = self.lost.wrapping_add(drops.wrapping_sub(self.drops_seen));
            self.drops_seen = drops;
            self.let_go();
        }
        any
    }

    fn route(&mut self, w: u64) {
        let (ty, code, value) = unpack(w);
        if ty == EV_KEY {
            let bit = held_bit(code);
            if bit != 0 {
                if value == 0 {
                    self.held &= !bit;
                } else {
                    self.held |= bit;
                }
            }
            if code == KEY_DELETE {
                if self.swallowing {
                    // The chord's repeats and its release.
                    if value == 0 {
                        self.swallowing = false;
                    }
                    return;
                }
                if value == 1 && self.held & CTRL != 0 && self.held & ALT != 0 {
                    self.swallowing = true;
                    self.attention();
                    return;
                }
            }
        }
        self.deliver(w);
    }

    /// The Secure Attention Key: count it on the trusted page, take the focus
    /// from whoever has it and, with a trusted surface in the build, close the
    /// gate on everyone else.
    fn attention(&mut self) {
        let now = self.host.now_ns();
        self.sak = self.sak.wrapping_add(1);
        self.host.note_sak(now);
        self.pending = self.gated;
        let from = self.drop_holder();
        self.record(from, 0, reason::TRUSTED);
    }

    fn refuse(&mut self) {
        self.refused = self.refused.wrapping_add(1);
        let to = self.holder();
        self.record(to, to, reason::NO_GRANT);
    }
}

impl<H: Host> Input for Service<H> {
    fn take_focus(&mut self) -> Out<FocusLease> {
        let trusted = self.caller == input::TRUSTED_BADGE;
        if self.pending && !trusted {
            // The chord took the focus; only the trusted surface hands it on.
            self.refuse();
            return Out::err(outcome::DENIED);
        }
        // The new grant is made whole before the old one is touched.
        let Some(ring) = self.host.make_ring() else { return Out::err(outcome::BUSY) };
        let generation = self.grants.wrapping_add(1) & !input::WARRANT_BADGE;
        let generation = if generation == 0 { 1 } else { generation };
        let Some(warrant) = self.host.derive_warrant(generation) else {
            self.host.close_ring(&ring);
            return Out::err(outcome::BUSY);
        };
        self.grants = generation;
        // The grant is whole: the trusted surface has taken the focus the chord
        // took, and the plain callers may ask for it again.
        if trusted {
            self.pending = false;
        }
        let from = self.drop_holder();
        self.holder = Some(Holder { generation, warrant, ring });
        // The true state at the start of the ring: what is down now.
        for (i, &code) in HELD.iter().enumerate() {
            if self.held & (1 << i) != 0 {
                self.deliver(pack(EV_KEY, code, 1));
            }
        }
        self.record(from, generation, reason::MOVED);
        Out::ok(FocusLease {
            generation,
            warrant: Lent::dup(warrant, WARRANT_RIGHTS.bits() as u16),
            ring: Lent::dup(ring.handle, RING_RIGHTS.bits() as u16),
        })
    }

    fn release(&mut self) -> Out<()> {
        match (self.holder, input::generation_of(self.caller)) {
            (Some(h), Some(g)) if h.generation == g => {
                let from = self.drop_holder();
                self.record(from, 0, reason::RELEASED);
                Out::ok(())
            }
            _ => {
                self.refuse();
                Out::err(outcome::DENIED)
            }
        }
    }

    fn trusted(&mut self) -> Out<TrustedLease> {
        match self.host.trusted_page() {
            Some(h) => Out::ok(TrustedLease { page: Lent::dup(h, PAGE_RIGHTS.bits() as u16) }),
            None => Out::err(outcome::BUSY),
        }
    }

    fn status(&self) -> Out<Status> {
        Out::ok(Status {
            holder: self.holder(),
            grants: self.grants,
            sak: self.sak,
            events: self.events,
            lost: self.lost,
            refused: self.refused,
            pending: self.pending as u32,
        })
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

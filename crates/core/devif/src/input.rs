// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The `Input` interface: who is given the keyboard and the pointer.
//!
//! `INPUTD.ELF` serves it on [`ENDPOINT`]. The kernel's input drivers (virtio,
//! PS/2, USB HID) publish every event into one stream (`azos_drv_input::
//! events`); the server reads it and delivers it **only to the holder of the
//! focus**. The console's own keys are not part of this: the typed bytes of a
//! keyboard still reach the terminal server through the console, and a task
//! that never asks for the focus sees no change.
//!
//! # Focus is a warrant
//!
//! * [`Input::take_focus`] makes the caller the holder. The server derives a
//!   capability on its own endpoint that carries a badge only it can name (the
//!   generation of this grant), and lends the caller that **warrant**
//!   ([`Warrant`], the call right and nothing else) and the **event ring**
//!   ([`EventRing`]) the server fills for this holder alone: a fresh region, so
//!   a holder that is no longer the holder keeps a ring nobody writes.
//! * A later [`Input::take_focus`], from anyone, moves the focus: the server
//!   revokes the warrant it lent (with everything derived from it), writes the
//!   [`EventRing::close`] word into the ring the old holder has and stops writing
//!   it. The old holder's next call through the warrant fails in the kernel
//!   (`-EREVOKED`), and its ring reads as closed.
//! * [`Input::release`] is the holder giving the focus up. It is accepted only
//!   through the live warrant: a call through the plain endpoint, or through a
//!   warrant of an earlier generation, is refused.
//! * A Secure Attention Key chord (Ctrl+Alt+Delete) is **never delivered to the
//!   holder**: the server swallows it, takes the focus away from whoever has it
//!   and counts it in the trusted-path page ([`TrustedPage`]). Applications
//!   cannot fake that count (they map the page read-only); the compositor that
//!   shows a trusted surface reads it. The chord also chooses the next holder:
//!   with a compositor in the build, `take_focus` from any caller but the
//!   trusted surface (the call right whose badge is [`TRUSTED_BADGE`]) is
//!   refused (`DENIED`) until the trusted surface has taken the focus itself
//!   (`userspace/services/inputd/src/focus.rs`).
//!
//! Every refusal is a value of the interface ([`outcome`](crate::outcome)):
//! `DENIED` for a call without the warrant, `BUSY` when the server has no
//! memory object left for a ring or no capability slot for a warrant. (With no
//! input driver the server does not run: a call finds no server.)
//!
//! The events are the Linux evdev words of `azos_input_wire::event`
//! (`pack`: `type | code << 16 | value << 32`). The ring is
//! `azos_rings::region::SpscRing` of [`RING_SLOTS`] slots in one page: the server
//! is the producer, the holder the consumer and moves the tail. A full ring
//! drops the newest event and counts it in [`EventRing::drops`]; a consumer that
//! sees the count move resynchronizes the state it built from the events (keys
//! and buttons held) as the terminal server does.

use crate::outcome::Out;
use azos_idl::{azos_interface, Lent, Reader, Wire, Writer};
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

/// The interface id (ASCII "INPT").
pub const INPUT_ID: u32 = 0x494E_5054;

/// The endpoint a topology row declares for this object.
pub const ENDPOINT: &str = "endpoint.input";

/// The name that endpoint has in the kernel's pool.
pub const ENDPOINT_NAME: &str = "input";

/// Slots of an event ring (a power of two); with the ring's header it fits one
/// page.
pub const RING_SLOTS: u32 = 64;
/// Pages of an event ring's region.
pub const RING_PAGES: u64 = 1;

/// The badge bit that marks a warrant: badges the topology gives a row are
/// small, so a call whose badge has this bit set was made through a
/// capability the server derived itself. The low bits are the generation of
/// the grant ([`generation_of`]).
pub const WARRANT_BADGE: u32 = 1 << 31;

/// The badge of the warrant of grant `generation`.
pub const fn warrant_badge(generation: u32) -> u32 {
    WARRANT_BADGE | (generation & !WARRANT_BADGE)
}

/// The badge the kernel stamps on the trusted surface's call right on
/// [`ENDPOINT`]: a grant of `endpoint.input` whose rights carry `EXEC` beside the
/// call right (`WRITE`) and no `READ`, as `power`'s calling grants carry `EXEC` to
/// control a device. Only the topology's own row for the compositor holds such a
/// grant; no warrant has it (bit 31 is clear) and no other row's badge is
/// non-zero, so a call that arrives with this badge came from the trusted surface.
/// The server (`INPUTD.ELF`) lets only this caller take the focus back after the
/// Secure Attention Key (`Service::take_focus`).
pub const TRUSTED_BADGE: u32 = 1 << 30;

/// The badge the kernel stamps on a calling grant of `endpoint.input` with
/// rights `perms` (`CapPerms` bits): [`TRUSTED_BADGE`] when it carries `EXEC` and
/// not `READ` (`READ` serves the endpoint), else `None` (the grant is plain).
pub const fn grant_badge(perms: u8) -> Option<u32> {
    use azos_abi::cap::CapPerms;
    let exec = CapPerms::EXEC.bits();
    let read = CapPerms::READ.bits();
    if perms & exec != 0 && perms & read == 0 {
        Some(TRUSTED_BADGE)
    } else {
        None
    }
}

/// The generation a warrant badge names; `None` for a badge that is no
/// warrant's (a row's own, or the unbadged endpoint).
pub const fn generation_of(badge: u32) -> Option<u32> {
    if badge & WARRANT_BADGE != 0 {
        Some(badge & !WARRANT_BADGE)
    } else {
        None
    }
}

/// What a `Lent<Warrant>` names: a capability on the server's endpoint with
/// the call right only, lapsing when the focus moves.
pub struct Warrant;

/// What a `Lent<EventRing>` names: the region of one holder's events, an
/// `azos_rings::region::SpscRing` of [`RING_SLOTS`] slots at its start.
pub struct EventRing;

/// The atomic at byte `off` of the shared region at `base`.
fn cell<T>(base: usize, off: usize) -> &'static T {
    // SAFETY: `base` is the start of a region one page long, 64-byte aligned,
    // zero when made, shared by the server and its holders; every offset this
    // module names is inside the first line or two of it, aligned for its type,
    // and `T` is an atomic, which any bit pattern is valid for.
    unsafe { &*((base + off) as *const T) }
}

// Offsets of the two words the ring protocol leaves free in the head line (the
// head index is the first word).
const CLOSED_OFF: usize = 8;
const DROPS_OFF: usize = 12;

impl EventRing {
    fn word(base: usize, off: usize) -> &'static AtomicU32 {
        cell(base, off)
    }

    /// Server: the ring at `base` is not written any more (the focus moved).
    /// Call it after the last event was published and before the region is
    /// released.
    pub fn close(base: usize) {
        Self::word(base, CLOSED_OFF).store(1, Ordering::Release);
    }

    /// Holder: has the server stopped writing the ring at `base`? Events
    /// published before the close are visible once this answers `true`, so a
    /// last drain after it takes everything.
    pub fn closed(base: usize) -> bool {
        Self::word(base, CLOSED_OFF).load(Ordering::Acquire) != 0
    }

    /// Server: count one event the ring had no room for.
    pub fn drop_one(base: usize) {
        let w = Self::word(base, DROPS_OFF);
        w.store(w.load(Ordering::Relaxed).wrapping_add(1), Ordering::Release);
    }

    /// Holder: events dropped for want of room since the grant; wraps.
    pub fn drops(base: usize) -> u32 {
        Self::word(base, DROPS_OFF).load(Ordering::Acquire)
    }
}

/// What a `Lent<TrustedPage>` names: one page, mapped read-only, the server
/// the only writer. A [`TrustedPage::count`] that moved means the Secure
/// Attention Key was pressed.
pub struct TrustedPage;

const SAK_COUNT_OFF: usize = 0;
const SAK_AT_OFF: usize = 8;

impl TrustedPage {
    /// Server: record one chord, at `now_ns`.
    pub fn record(base: usize, now_ns: u64) {
        cell::<AtomicU64>(base, SAK_AT_OFF).store(now_ns, Ordering::Relaxed);
        let c = cell::<AtomicU32>(base, SAK_COUNT_OFF);
        c.store(c.load(Ordering::Relaxed).wrapping_add(1), Ordering::Release);
    }

    /// Reader: chords since the server started; wraps.
    pub fn count(base: usize) -> u32 {
        cell::<AtomicU32>(base, SAK_COUNT_OFF).load(Ordering::Acquire)
    }

    /// Reader: when the last chord was seen, nanoseconds on the monotonic
    /// clock (0: never). Read after [`TrustedPage::count`].
    pub fn at_ns(base: usize) -> u64 {
        cell::<AtomicU64>(base, SAK_AT_OFF).load(Ordering::Relaxed)
    }
}

/// [`Input::take_focus`]'s answer: the grant's generation, the warrant and the
/// ring, all or none.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FocusLease {
    pub generation: u32,
    pub warrant: Lent<Warrant>,
    pub ring: Lent<EventRing>,
}

impl Default for FocusLease {
    fn default() -> Self {
        FocusLease { generation: 0, warrant: Lent::none(), ring: Lent::none() }
    }
}

impl Wire for FocusLease {
    const WORDS: usize = 1 + <Lent<Warrant> as Wire>::WORDS + <Lent<EventRing> as Wire>::WORDS;
    const CAPS: usize = <Lent<Warrant> as Wire>::CAPS + <Lent<EventRing> as Wire>::CAPS;
    fn put(&self, w: &mut Writer<'_>) {
        self.generation.put(w);
        self.warrant.put(w);
        self.ring.put(w);
    }
    fn get(r: &mut Reader<'_>) -> Self {
        FocusLease {
            generation: u32::get(r),
            warrant: <Lent<Warrant> as Wire>::get(r),
            ring: <Lent<EventRing> as Wire>::get(r),
        }
    }
}

/// [`Input::trusted`]'s answer: the page, or none.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TrustedLease {
    pub page: Lent<TrustedPage>,
}

impl Default for TrustedLease {
    fn default() -> Self {
        TrustedLease { page: Lent::none() }
    }
}

impl Wire for TrustedLease {
    const WORDS: usize = <Lent<TrustedPage> as Wire>::WORDS;
    const CAPS: usize = <Lent<TrustedPage> as Wire>::CAPS;
    fn put(&self, w: &mut Writer<'_>) {
        self.page.put(w);
    }
    fn get(r: &mut Reader<'_>) -> Self {
        TrustedLease { page: <Lent<TrustedPage> as Wire>::get(r) }
    }
}

/// [`Input::status`]'s answer.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Status {
    /// The generation of the live grant; 0 when nobody holds the focus.
    pub holder: u32,
    /// Grants since the server started (the next generation is one more).
    pub grants: u32,
    /// Secure Attention Key chords seen.
    pub sak: u32,
    /// Events the server read from the drivers' stream.
    pub events: u64,
    /// Events the drivers' stream lost before the server read them (a full
    /// stream), and events dropped for a holder whose ring was full.
    pub lost: u32,
    /// Requests refused (a call without the live warrant, and a plain caller's
    /// `take_focus` while attention is pending).
    pub refused: u32,
    /// 1 while attention is pending: the Secure Attention Key took the focus and
    /// the trusted surface has not taken it since, so every other caller's
    /// `take_focus` is refused. A trusted surface that starts late reads it to
    /// open a gate a chord closed before it existed. 0 otherwise, and always 0
    /// in a build with no trusted surface.
    pub pending: u32,
}

impl Wire for Status {
    // Four words, two 32-bit fields to a word: a reply holds eight with its status
    // and the outcome.
    const WORDS: usize = 4;
    const CAPS: usize = 0;
    fn put(&self, w: &mut Writer<'_>) {
        w.word(self.holder as u64 | (self.grants as u64) << 32);
        w.word(self.sak as u64 | (self.pending as u64) << 32);
        w.word(self.events);
        w.word(self.lost as u64 | (self.refused as u64) << 32);
    }
    fn get(r: &mut Reader<'_>) -> Self {
        let a = r.word();
        let b = r.word();
        let events = r.word();
        let c = r.word();
        Status {
            holder: a as u32,
            grants: (a >> 32) as u32,
            sak: b as u32,
            pending: (b >> 32) as u32,
            events,
            lost: c as u32,
            refused: (c >> 32) as u32,
        }
    }
}

#[azos_interface(id = 0x494E_5054, level = 1)]
pub trait Input {
    /// Become the holder of the focus: lends the warrant and the ring of this
    /// grant, and revokes the previous holder's. `BUSY` when the server has no
    /// memory object left for the ring.
    fn take_focus(&mut self) -> Out<FocusLease>;
    /// Give the focus up. Only the live warrant is accepted: `DENIED` for the
    /// plain endpoint or a warrant that has been revoked.
    #[idempotent]
    fn release(&mut self) -> Out<()>;
    /// Lend the trusted-path page, read-only.
    #[idempotent]
    fn trusted(&mut self) -> Out<TrustedLease>;
    /// The server's counters and the live generation.
    #[idempotent]
    fn status(&self) -> Out<Status>;
}

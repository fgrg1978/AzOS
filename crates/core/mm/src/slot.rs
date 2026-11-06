// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The slot word: what one page of a memory object is, in one 64-bit word with
//! the same encoding on every ISA.
//!
//! | word                         | state                                    |
//! |------------------------------|------------------------------------------|
//! | `0`                          | `Empty`: never touched, a zero page      |
//! | `pa \| 1`                    | `Frame`: resident in the frame at `pa`   |
//! | `payload << 32 \| code << 1` | a [`PageMarker`]: in transit, compressed or swapped |
//!
//! The slot is the page's state and the page-table entry that maps it is a
//! cache of it: a fault decides from the slot, never from the entry
//! ([`resolve`]), and an entry is written only to install a `Frame` slot's
//! frame or to clear it. The reclaimer's marker protocol (`zpool::take_out`,
//! `publish`, `put_back`, `clear`, `classify`) runs over slot words through
//! [`SlotWords`], so the compressed and swapped states live here and not in a
//! page-table entry. Bits 1..12 of a `Frame` word are free (a dirty or a
//! pinned bit, a head bit for a multi-page run) and nothing sets them yet.
//!
//! Pure arithmetic: the host suites pull this file in with `#[path]`.

use core::sync::atomic::{AtomicU64, Ordering};

use azos_arch_api::PageMarker;

use crate::zpool::PageWords;

/// The word of a slot that holds nothing.
pub const EMPTY: u64 = 0;

const FRAME: u64 = 1;
const CODE_SHIFT: u32 = 1;
const CODE_MASK: u64 = 0b11 << CODE_SHIFT;
const PAYLOAD_SHIFT: u32 = 32;
const ADDR_MASK: u64 = !0xfff;

/// The state a slot word names.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Slot {
    Empty,
    /// Resident in the frame at this physical address.
    Frame(usize),
    /// Out of memory, or on its way out ([`PageMarker`]), with the marker's payload.
    Marker(PageMarker, u32),
}

/// The word of a slot whose page is resident in the frame at `pa` (page-aligned).
#[inline(always)]
pub const fn frame(pa: usize) -> u64 {
    (pa as u64 & ADDR_MASK) | FRAME
}

/// The word of a marker slot.
#[inline(always)]
pub const fn marker(kind: PageMarker, payload: u32) -> u64 {
    ((payload as u64) << PAYLOAD_SHIFT) | ((kind.code() as u64) << CODE_SHIFT)
}

/// What a slot word says. A word no encoder made (a stray code) reads as a
/// marker of no kind: `None`.
#[inline(always)]
pub const fn decode(w: u64) -> Option<Slot> {
    if w == EMPTY {
        return Some(Slot::Empty);
    }
    if w & FRAME != 0 {
        return Some(Slot::Frame((w & ADDR_MASK) as usize));
    }
    match PageMarker::from_code(((w & CODE_MASK) >> CODE_SHIFT) as u8) {
        Some(kind) => Some(Slot::Marker(kind, (w >> PAYLOAD_SHIFT) as u32)),
        None => None,
    }
}

/// The frame a `Frame` word names.
#[inline(always)]
pub const fn frame_of(w: u64) -> Option<usize> {
    if w & FRAME != 0 { Some((w & ADDR_MASK) as usize) } else { None }
}

/// What a fault on a page does, decided from its slot word.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Resolve {
    /// The slot is empty and no leaf maps the page: a zero page.
    Supply,
    /// The slot names a frame no leaf maps: install it.
    Install(usize),
    /// Resident and mapped: another thread resolved it, the access retries.
    Present,
    /// A store of the page is in flight: wait for it, then retry.
    Wait,
    /// The page is in the pool (or on swap): restore it.
    Restore(PageMarker, u32),
    /// A leaf maps the page that the slot does not name (another thread's
    /// install between the two reads, or a word no install made): never
    /// replaced, and the frame it names never freed here; look again.
    Foreign,
}

/// Decide a fault from the page's slot `word`; `leaf` is the frame its
/// page-table entry maps, if the entry holds a 4 KiB leaf. `None` for a word
/// no encoder made.
///
/// Canary `mm-pte-truth-canary`: the entry is believed over the slot (a leaf is
/// present, no leaf is a zero page), so a page whose leaf was cleared comes
/// back as zeros and so does a compressed page.
#[inline]
pub fn resolve(word: u64, leaf: Option<usize>) -> Option<Resolve> {
    if cfg!(feature = "mm-pte-truth-canary") {
        return Some(if leaf.is_some() { Resolve::Present } else { Resolve::Supply });
    }
    Some(match (decode(word)?, leaf) {
        (Slot::Frame(f), Some(l)) if l == f => Resolve::Present,
        (_, Some(_)) => Resolve::Foreign,
        (Slot::Empty, None) => Resolve::Supply,
        (Slot::Frame(f), None) => Resolve::Install(f),
        (Slot::Marker(PageMarker::InTransit, _), None) => Resolve::Wait,
        (Slot::Marker(kind, payload), None) => Resolve::Restore(kind, payload),
    })
}

/// How [`put_back_page`] ended.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PutBack {
    /// The leaf and the slot name the frame again.
    Back,
    /// The slot is not the store's any more (the range was unmapped meanwhile,
    /// and maybe mapped again): nothing was written.
    NotMine,
    /// The leaf could not be written (one is already there, which nothing
    /// writes while the slot is in transit): the slot is emptied rather than
    /// left in transit for good.
    Emptied,
}

/// End a store that did not happen: put the page whose slot is `slot` back in
/// the frame at `frame`. The slot must still hold the `InTransit` marker of
/// `ticket`, checked before anything is written, so a slot that does not gets
/// no leaf and no translation of the frame exists once the caller frees it.
/// Then `install` writes the page's leaf, and the slot gets the frame. Under
/// the space's lock, which every writer of a mapped page's slot holds. Unless
/// [`PutBack::Back`], the frame is the caller's to free.
///
/// Canary `keep-leaf-first-canary`: the leaf is written before the slot is
/// looked at.
pub fn put_back_page(slot: &AtomicU64, ticket: u32, frame: usize, install: impl FnOnce() -> bool) -> PutBack {
    let mine = marker(PageMarker::InTransit, ticket);
    let mut install = Some(install);
    let early = if cfg!(feature = "keep-leaf-first-canary") { install.take().map(|f| f()) } else { None };
    if slot.load(Ordering::Acquire) != mine {
        return PutBack::NotMine;
    }
    if !early.unwrap_or_else(|| install.take().is_some_and(|f| f())) {
        slot.store(EMPTY, Ordering::Release);
        return PutBack::Emptied;
    }
    slot.store(self::frame(frame), Ordering::Release);
    PutBack::Back
}

/// The marker protocol's view of slot words: a `Frame` slot is the page the
/// reclaimer takes out (whether its frame is shared or its entry a plain leaf
/// is the caller's test, on the entry and the frame), a marker is a marker.
pub struct SlotWords;

impl PageWords for SlotWords {
    #[inline]
    fn is_victim_leaf(&self, word: u64) -> bool {
        frame_of(word).is_some()
    }

    #[inline]
    fn is_valid(&self, word: u64) -> bool {
        frame_of(word).is_some()
    }

    #[inline]
    fn make_marker(&self, kind: PageMarker, payload: u32) -> u64 {
        marker(kind, payload)
    }

    #[inline]
    fn marker(&self, word: u64) -> Option<(PageMarker, u32)> {
        match decode(word) {
            Some(Slot::Marker(kind, payload)) => Some((kind, payload)),
            _ => None,
        }
    }
}

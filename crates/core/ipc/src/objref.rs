// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Object references: a pool index and the generation of the object at that
//! index, packed into [`CapSlot::resource`](super::CapSlot) — RFC-0040 gap 1.
//!
//! # Why
//!
//! `CapTable::get` validates the capability's own cap-table slot (kind, slot
//! generation, permissions) and returns the resource stored in it. For a pool
//! object that resource used to be the bare pool index, so a capability kept
//! resolving after its object was freed and reached the next object created at
//! that index, whoever created it and whichever table held the capability. The
//! typed destroys revoke the capability they are called with, which covers only
//! the caller's own table. The generation covers every table: the pool stamps a
//! fresh generation into the slot at create, clears it to 0 when the slot
//! becomes reusable, and compares it inside the lock each operation already
//! takes.
//!
//! # Layout, per kind
//!
//! `resource = gen << idx_bits | idx`, with the index width chosen per kind
//! ([`Layout`], [`layout`]):
//!
//! | Kind | Index bits | Generation bits |
//! |---|---|---|
//! | `Channel` | smallest width holding the indices `0..MAX_CHANNELS` of the built profile | `32 - index bits` |
//! | `Port` | smallest width holding the indices `0..MAX_PORTS` of the built profile | `32 - index bits` |
//! | `Shm`, `IoRing` | 8, fixed | 24 |
//!
//! `MAX_CHANNELS` and `MAX_PORTS` come from `azos_limits` (Kconfig): 16 and
//! 32 in the edge profile (4 + 28 and 5 + 27), 4096 and 512 in the fleet
//! profile (12 + 20 and 9 + 23). **The width holds the indices, not `MAX`
//! itself**: every pool allocates from `0..MAX`, so the largest index a packed
//! reference carries is `MAX - 1`, and `MAX` needs no representation.
//!
//! `Shm` and `IoRing` keep 8 index bits because their pools are source literals
//! (16 slots, `shm.rs` and `io_ring.rs`), not Kconfig values, and this file is
//! compiled by host crates that do not mount those files. Eight bits keep every
//! bare value below 256 inert (generation 0) for those kinds, and 24 generation
//! bits are already well above the floor below.
//!
//! Every packed kind has at least [`MIN_GEN_BITS`] of generation. That holds for
//! every legal `.config`, not only the three profile defaults: `config/Kconfig.limits`
//! bounds both `MAX_CHANNELS` and `MAX_PORTS` to `range 4 65536`, and 65536
//! slots take 16 index bits, leaving exactly 16. The compile-time asserts below
//! fire if that range is ever widened.
//!
//! Generation 0 is the vacant value, so a bare in-range index (generation 0)
//! never matches a live object. A bare value at or above `1 << idx_bits` is not
//! an in-range index and does alias a generation; no production path mints one.
//!
//! # Per-slot generations, swept only at their own index (RFC-0040 gap 1,
//! # revised 2026-09-26, owner decision)
//!
//! Each pool kept **one** `GenCounter`-style source for the whole pool: every
//! create, at whichever index, drew the next generation from the same counter.
//! When it was exhausted, the create that observed it released the pool lock,
//! ran a sweep that revoked **every** capability of that kind in **every**
//! per-task table (`cap_store::revoke_kind_in_every_table`, a walk by table
//! index) — live objects included — restarted the counter at 1 under a bumped
//! epoch, and retried. A create/destroy loop on one object of a pool-limited
//! kind (Channel, Port, Shm, IoRing, Endpoint) reaches that exhaustion in
//! `gen_max` cycles — as few as 2^20 for a fleet Channel, well within a ring-3
//! program's reach — and revoked every *other* task's live capabilities of
//! that kind along with it, including boot-seeded ones with no runtime re-mint
//! path (`Cap<Endpoint>`, the RFC-0040 fast-IPC right, among them).
//!
//! The generation now lives **per slot**, not per pool: each pool keeps a
//! sibling array — `next_gen: [u32; N]`, one entry per object slot,
//! initialised to `1` and never reset by a destroy — under the same lock as
//! the objects themselves. A create, having already found a free slot `i`,
//! calls [`take_slot_gen`] with `next_gen[i]`:
//!
//! - [`SlotGen::Gen(g)`](SlotGen::Gen): stamp `g` into the slot and `g + 1`
//!   back into `next_gen[i]`.
//! - [`SlotGen::Wrap`]: slot `i`'s generation has reached [`Layout::gen_max`].
//!   The caller marks the slot mid-sweep (so its own free-slot scan will not
//!   hand index `i` to a concurrent create while the lock below is dropped —
//!   pools use `next_gen[i] = 0` for this, a value `take_slot_gen` never hands
//!   back and the scan already treats as unavailable), releases the pool
//!   lock, calls [`sweep_index`] with `i`, re-takes the pool lock, resets
//!   `next_gen[i]` to `1`, and retries — now always a plain `Gen(1)`.
//!
//! [`sweep_index`] revokes every capability of the pool's kind whose packed
//! resource names index `i`, in every per-task table. **This revokes nothing
//! live**: the slot is free when this runs (the caller already found it so),
//! so every match is a stale capability from a past incarnation at this same
//! index — never a capability on the pool's other slots, unlike the deleted
//! pool-wide sweep. **Residual cost, accepted by the owner over widening
//! `CapSlot::resource` to 64 bits:** a stale capability naming index `i`
//! could be sitting in any task's table, not only the ones this pool's own
//! minter used, so the walk is still O(`MAX_TASKS`) cap-table locks — the
//! same order as the deleted sweep, but triggered once per `gen_max` reuses
//! of ONE slot rather than once per `gen_max` creates of the whole pool, and
//! it revokes only that slot's own stale entries rather than every live
//! capability of the kind. See each pool's `create_core` for the measured
//! per-call cost of one such walk.
//!
//! Because a slot's generation never repeats within its lifetime except
//! across its own wrap (handled by the targeted sweep above), no second
//! disambiguator is needed to tell two incarnations at the same index apart:
//! the generation *is* the incarnation. Ports (and IRQ bindings naming a
//! port) used to pair an `epoch` alongside the packed reference for exactly
//! that purpose; both now compare generation alone.
//!
//! This file is declared inside `cap.rs` (`cap::objref`) and re-exported at the
//! crate root, so every host crate that `#[path]`-mounts `cap.rs` compiles it
//! without a mount line of its own.

use super::{Cap, CapKind, CapPerms, CapTarget};

/// The fewest generation bits a packed kind may have.
pub const MIN_GEN_BITS: u32 = 16;

/// How one kind splits a packed resource into index and generation.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Layout {
    idx_bits: u32,
}

impl Layout {
    /// The smallest index width that holds the indices `0..slots`.
    ///
    /// `slots <= 1` needs no index bits. Otherwise the width is that of
    /// `slots - 1`, the largest index: 16 slots take 4 bits, 17 take 5.
    pub const fn for_slots(slots: usize) -> Layout {
        let idx_bits = if slots <= 1 {
            0
        } else {
            usize::BITS - (slots - 1).leading_zeros()
        };
        Layout { idx_bits }
    }

    /// A fixed index width.
    pub const fn fixed(idx_bits: u32) -> Layout {
        assert!(idx_bits < u32::BITS, "a layout needs at least one generation bit");
        Layout { idx_bits }
    }

    #[inline]
    pub const fn idx_bits(self) -> u32 {
        self.idx_bits
    }

    #[inline]
    pub const fn gen_bits(self) -> u32 {
        u32::BITS - self.idx_bits
    }

    /// Mask of the index half.
    #[inline]
    pub const fn idx_mask(self) -> u32 {
        ((1u64 << self.idx_bits) - 1) as u32
    }

    /// Largest generation a counter of this layout hands out. The smallest is 1.
    #[inline]
    pub const fn gen_max(self) -> u32 {
        ((1u64 << self.gen_bits()) - 1) as u32
    }

    /// Pack an index and a generation. Both are masked to their widths; the
    /// pools pass an index below their size (each asserts it fits) and a
    /// generation from [`take_slot_gen`].
    #[inline]
    pub const fn pack(self, idx: u32, gen: u32) -> u32 {
        (((gen & self.gen_max()) as u64) << self.idx_bits) as u32 | (idx & self.idx_mask())
    }

    /// The pool index of a packed resource.
    #[inline]
    pub const fn idx(self, r: u32) -> u32 {
        r & self.idx_mask()
    }

    /// The generation of a packed resource. 0 never names a live object.
    #[inline]
    pub const fn gen(self, r: u32) -> u32 {
        ((r as u64) >> self.idx_bits) as u32
    }
}

/// `Cap<Channel>`: sized by `azos_limits::MAX_CHANNELS`.
pub const CHANNEL: Layout = Layout::for_slots(azos_limits::MAX_CHANNELS);
/// `Cap<Port>`: sized by `azos_limits::MAX_PORTS`.
pub const PORT: Layout = Layout::for_slots(azos_limits::MAX_PORTS);
/// `Cap<Shm>`: 8 index bits (the pool asserts its 16 slots fit).
pub const SHM: Layout = Layout::fixed(8);
/// `Cap<IoRing>`: 8 index bits (the pool asserts its 16 slots fit).
pub const IO_RING: Layout = Layout::fixed(8);
/// `Cap<Endpoint>`: 8 index bits, fixed like `Shm` and `IoRing` rather than
/// derived from a Kconfig limit. The endpoint pool is a fixed 32 slots, which
/// the module asserts against these 8 bits; giving it a `MAX_ENDPOINTS` option
/// would put a new knob in every defconfig to buy nothing the fixed pool does
/// not already give. The remaining 24 bits are generation.
pub const ENDPOINT: Layout = Layout::fixed(8);

// Every packed kind keeps at least `MIN_GEN_BITS` of generation, in the built
// profile. See the module doc for why this holds across the whole Kconfig range.
const _: () = assert!(CHANNEL.gen_bits() >= MIN_GEN_BITS, "Channel: fewer than 16 generation bits");
const _: () = assert!(PORT.gen_bits() >= MIN_GEN_BITS, "Port: fewer than 16 generation bits");
const _: () = assert!(SHM.gen_bits() >= MIN_GEN_BITS, "Shm: fewer than 16 generation bits");
const _: () = assert!(IO_RING.gen_bits() >= MIN_GEN_BITS, "IoRing: fewer than 16 generation bits");
const _: () = assert!(ENDPOINT.gen_bits() >= MIN_GEN_BITS, "Endpoint: fewer than 16 generation bits");

// Both edges of the derived widths. Upper: every index `0..MAX` fits. Lower:
// the width is the smallest that does, so no generation bit is given away.
const _: () = assert!(
    azos_limits::MAX_CHANNELS as u64 <= 1u64 << CHANNEL.idx_bits(),
    "Channel: an index does not fit its layout"
);
const _: () = assert!(
    CHANNEL.idx_bits() == 0 || azos_limits::MAX_CHANNELS as u64 > 1u64 << (CHANNEL.idx_bits() - 1),
    "Channel: the index width is not the smallest"
);
const _: () = assert!(
    azos_limits::MAX_PORTS as u64 <= 1u64 << PORT.idx_bits(),
    "Port: an index does not fit its layout"
);
const _: () = assert!(
    PORT.idx_bits() == 0 || azos_limits::MAX_PORTS as u64 > 1u64 << (PORT.idx_bits() - 1),
    "Port: the index width is not the smallest"
);

/// The layout of `kind`, or `None` for a kind that stores a bare resource.
#[inline]
pub const fn layout(kind: CapKind) -> Option<Layout> {
    match kind {
        CapKind::Channel => Some(CHANNEL),
        CapKind::Port => Some(PORT),
        CapKind::Shm => Some(SHM),
        CapKind::IoRing => Some(IO_RING),
        CapKind::Endpoint => Some(ENDPOINT),
        _ => None,
    }
}

/// Does a capability of `kind` store a packed resource?
#[inline]
pub const fn is_packed_kind(kind: CapKind) -> bool {
    layout(kind).is_some()
}

/// Pack for `kind`. A kind that is not packed stores `idx` as is.
#[inline]
pub const fn pack(kind: CapKind, idx: u32, gen: u32) -> u32 {
    match layout(kind) {
        Some(l) => l.pack(idx, gen),
        None => idx,
    }
}

/// The index a `resource` of `kind` names: the index half for a packed kind,
/// the resource itself for every other kind.
#[inline]
pub const fn idx(kind: CapKind, r: u32) -> u32 {
    match layout(kind) {
        Some(l) => l.idx(r),
        None => r,
    }
}

/// The generation half of a `resource` of `kind`; 0 for a kind that is not
/// packed.
#[inline]
pub const fn gen(kind: CapKind, r: u32) -> u32 {
    match layout(kind) {
        Some(l) => l.gen(r),
        None => 0,
    }
}

/// Same as [`idx`]; the name `CapTable::lookup` reads.
#[inline]
pub const fn resource_index(kind: CapKind, r: u32) -> u32 {
    idx(kind, r)
}

// ──────────────────────────────────────────────────────────────────────────
// Per-slot generation
// ──────────────────────────────────────────────────────────────────────────

/// What [`take_slot_gen`] answers.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SlotGen {
    /// Stamp the carried generation into the slot, and store one past it back
    /// into `next_gen[i]`.
    Gen(u32),
    /// `next_gen[i]` has passed `layout.gen_max()`. The caller must: mark the
    /// slot mid-sweep (pools use `next_gen[i] = 0`, which this function never
    /// returns and which the free-slot scan already treats as unavailable, so
    /// no concurrent create can select the same index while the lock below is
    /// dropped), release the pool lock, call [`sweep_index`] for this index,
    /// re-take the lock, reset `next_gen[i]` to `1`, and retry — which then
    /// always answers `Gen(1)`.
    Wrap,
}

/// The generation a create should stamp into the slot whose `next_gen` entry
/// is `next_gen`, or [`SlotGen::Wrap`] if that slot's generation is exhausted.
///
/// A pool keeps its own `next_gen: [u32; N]` (one entry per object slot,
/// initialised to `1`, never reset by a destroy) under the same lock as the
/// objects themselves — no separate counter type, no atomics, no lock of its
/// own. Having already found a free slot `i`, the create calls this with
/// `next_gen[i]`. See the module doc ("Per-slot generations...") for the full
/// wrap protocol.
#[inline]
pub const fn take_slot_gen(next_gen: u32, layout: Layout) -> SlotGen {
    if next_gen == 0 || next_gen > layout.gen_max() {
        SlotGen::Wrap
    } else {
        SlotGen::Gen(next_gen)
    }
}

// ──────────────────────────────────────────────────────────────────────────
// Minting and the per-slot wrap sweep
// ──────────────────────────────────────────────────────────────────────────

/// Mint a capability for a packed resource into `tid`'s table.
///
/// A thin, kind-checked wrapper over `cap_store::grant`: `None` for a full
/// table or a `tid` naming no live task. Kept (rather than calling
/// `cap_store::grant` directly at each of the five call sites) for the
/// `debug_assert`, which catches a packed kind minted through the wrong path
/// at the first host test that exercises it.
///
/// Must not be called with a cap-table lock held (`cap_store`'s locks do not
/// nest).
pub fn grant_packed<T: CapTarget>(tid: u32, perms: CapPerms, r: u32) -> Option<Cap<T>> {
    debug_assert!(is_packed_kind(T::KIND));
    crate::cap_store::grant::<T>(tid, perms, r)
}

/// Revoke every capability of `kind` whose packed resource names index `idx`,
/// in every per-task table. Returns how many.
///
/// Called by a pool's create path when ONE slot's own generation counter
/// wraps (`take_slot_gen` answered [`SlotGen::Wrap`] for it) — see the module
/// doc for why this revokes nothing live and why it still costs O(`MAX_TASKS`)
/// cap-table locks (the accepted residual of not widening `CapSlot::resource`
/// to 64 bits, owner decision 2026-09-26).
///
/// **Lock order.** No pool lock is held (the caller marked the slot mid-sweep
/// and released the pool lock before calling this), and the walk takes one
/// cap-table lock at a time, never nested with a pool lock: `port_destroy_cap`
/// and its siblings hold a table lock and then take a pool lock, so this
/// running under a pool lock would be the reverse order.
pub fn sweep_index(kind: CapKind, idx: u32) -> usize {
    crate::cap_store::revoke_index_in_every_table(kind, idx)
}

// ──────────────────────────────────────────────────────────────────────────
// Kani harnesses (run with `cargo kani`, next to cap.rs's)
// ──────────────────────────────────────────────────────────────────────────

#[cfg(kani)]
mod kani_proofs {
    use super::*;

    const KINDS: [Layout; 4] = [CHANNEL, PORT, SHM, IO_RING];

    /// Every in-range (index, generation) pair round-trips, for every packed
    /// kind's layout.
    #[kani::proof]
    fn pack_unpack_round_trip() {
        let k: usize = kani::any();
        kani::assume(k < KINDS.len());
        let l = KINDS[k];
        let i: u32 = kani::any();
        let g: u32 = kani::any();
        kani::assume(i <= l.idx_mask() && g <= l.gen_max());
        let r = l.pack(i, g);
        assert!(l.idx(r) == i);
        assert!(l.gen(r) == g);
    }

    /// `take_slot_gen` never answers a generation of 0 or one past `gen_max`,
    /// from any `next_gen` value, for every packed kind's width.
    #[kani::proof]
    fn a_taken_slot_generation_is_never_zero() {
        let k: usize = kani::any();
        kani::assume(k < KINDS.len());
        let next_gen: u32 = kani::any();
        if let SlotGen::Gen(gen) = take_slot_gen(next_gen, KINDS[k]) {
            assert!(gen != 0);
            assert!(gen <= KINDS[k].gen_max());
            assert!(gen == next_gen);
        }
    }

    /// A bare in-range index (generation 0) never equals the generation of a
    /// live slot, for every packed kind's layout.
    #[kani::proof]
    fn a_bare_index_never_matches_a_live_generation() {
        let k: usize = kani::any();
        kani::assume(k < KINDS.len());
        let l = KINDS[k];
        let r: u32 = kani::any();
        let live: u32 = kani::any();
        kani::assume(r <= l.idx_mask());
        kani::assume(live != 0 && live <= l.gen_max());
        assert!(l.gen(r) != live);
    }
}

// ──────────────────────────────────────────────────────────────────────────
// Host tests (the Kani properties above, checked by enumeration)
// ──────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const PACKED: [(CapKind, Layout); 4] = [
        (CapKind::Channel, CHANNEL),
        (CapKind::Port, PORT),
        (CapKind::Shm, SHM),
        (CapKind::IoRing, IO_RING),
    ];

    /// The pool size behind each packed kind, in the built profile. `Shm` and
    /// `IoRing` are checked over their whole 8-bit index range.
    fn slots(kind: CapKind) -> usize {
        match kind {
            CapKind::Channel => azos_limits::MAX_CHANNELS,
            CapKind::Port => azos_limits::MAX_PORTS,
            _ => 1 << 8,
        }
    }

    fn edge_gens(l: Layout) -> [u32; 7] {
        let m = l.gen_max();
        [1, 2, 0xFF, 0x100, 0xFFFF, m - 1, m]
    }

    /// Both edges of the width: `slots` indices fit, and one width less does
    /// not. 16 slots take 4 bits (16 itself is never an index), 17 take 5.
    ///
    /// **Canary.** Size by `slots` instead of `slots - 1` in `for_slots`: 16
    /// reads 5.
    #[test]
    fn the_index_width_is_the_smallest_that_holds_every_index() {
        let table: [(usize, u32); 16] = [
            (1, 0), (2, 1), (3, 2), (4, 2), (5, 3), (8, 3), (9, 4), (16, 4),
            (17, 5), (32, 5), (33, 6), (256, 8), (512, 9), (4096, 12), (4097, 13), (65536, 16),
        ];
        for (n, bits) in table {
            let l = Layout::for_slots(n);
            assert_eq!(l.idx_bits(), bits, "{n} slots");
            assert!((n as u64) <= 1u64 << l.idx_bits(), "{n}: index {} fits", n - 1);
            if bits > 0 {
                assert!((n as u64) > 1u64 << (bits - 1), "{n}: a narrower width would do");
            }
            assert_eq!(l.idx_bits() + l.gen_bits(), 32);
        }
    }

    /// Every profile's default and the Kconfig range limit keep at least
    /// `MIN_GEN_BITS`, whichever profile this host build resolved. The
    /// compile-time asserts check the built profile; this checks the others.
    /// Values from `config/Kconfig.limits` (`MAX_CHANNELS` 16/16/4096, `MAX_PORTS`
    /// 8/32/512, both `range 4 65536`).
    #[test]
    fn every_profile_keeps_sixteen_generation_bits() {
        for (what, n, gen_bits) in [
            ("embedded channels", 16, 28), ("edge channels", 16, 28), ("fleet channels", 4096, 20),
            ("embedded ports", 8, 29), ("edge ports", 32, 27), ("fleet ports", 512, 23),
            ("range limit", 65536, 16),
        ] {
            let l = Layout::for_slots(n);
            assert_eq!(l.gen_bits(), gen_bits, "{what}");
            assert!(l.gen_bits() >= MIN_GEN_BITS, "{what}");
        }
        assert!(Layout::for_slots(65537).gen_bits() < MIN_GEN_BITS, "past the range the floor fails");
        assert_eq!(CHANNEL, Layout::for_slots(azos_limits::MAX_CHANNELS));
        assert_eq!(PORT, Layout::for_slots(azos_limits::MAX_PORTS));
        assert_eq!((SHM.idx_bits(), IO_RING.idx_bits()), (8, 8));
    }

    /// **Canary.** Shift the generation by one bit less in `Layout::pack`: the
    /// round trip fails for every kind.
    #[test]
    fn pack_round_trips_every_index_at_the_edge_generations() {
        for (kind, l) in PACKED {
            for i in 0..slots(kind) as u32 {
                for g in edge_gens(l) {
                    let r = l.pack(i, g);
                    assert_eq!((l.idx(r), l.gen(r)), (i, g), "{kind:?} idx {i} gen {g:#x}");
                    assert_eq!(r, pack(kind, i, g));
                    assert_eq!((idx(kind, r), gen(kind, r)), (i, g));
                }
            }
            assert_eq!(l.pack(l.idx_mask(), l.gen_max()), u32::MAX, "{kind:?}");
        }
    }

    /// A bare in-range index has generation 0 for every packed kind, so it never
    /// resolves.
    ///
    /// **Canary.** Give `Shm` 4 index bits (`Layout::for_slots(16)`): the bare
    /// value 16 reads generation 1.
    #[test]
    fn a_bare_index_has_generation_zero() {
        for (kind, l) in PACKED {
            for i in 0..slots(kind) as u32 {
                assert_eq!(l.gen(i), 0, "{kind:?} {i}");
                assert_eq!(l.idx(i), i, "{kind:?} {i}");
            }
        }
    }

    #[test]
    fn channel_port_shm_and_io_ring_are_packed() {
        for (kind, l) in PACKED {
            assert!(is_packed_kind(kind), "{kind:?}");
            assert_eq!(layout(kind), Some(l));
        }
        for k in [CapKind::Null, CapKind::Motor, CapKind::Gpio, CapKind::Sensor,
                  CapKind::I2c, CapKind::File, CapKind::Socket, CapKind::Pwm] {
            assert!(!is_packed_kind(k), "{k:?}");
            assert_eq!(resource_index(k, 0x1234_5678), 0x1234_5678, "{k:?}");
            assert_eq!(gen(k, 0x1234_5678), 0, "{k:?}");
            assert_eq!(pack(k, 7, 99), 7, "{k:?}");
        }
        assert_eq!(resource_index(CapKind::Shm, SHM.pack(7, 99)), 7);
        assert_eq!(resource_index(CapKind::Port, PORT.pack(7, 99)), 7);
    }

    /// `take_slot_gen` hands out `1..=gen_max` unchanged and answers `Wrap`
    /// for anything past it (including `0`, the mid-sweep sentinel) — at every
    /// generation width in use, the 16-bit floor included.
    ///
    /// **Canary.** Return `Gen(next_gen)` for `next_gen > gen_max`: the wrap
    /// assertions below start passing a generation past the field's width to
    /// a pool's `pack`.
    #[test]
    fn take_slot_gen_hands_out_one_to_gen_max_then_wraps() {
        let mut widths = [Layout::fixed(16), Layout::fixed(12), Layout::fixed(8),
                          CHANNEL, PORT, SHM];
        widths.sort_by_key(|l| l.gen_bits());
        for l in widths {
            assert_eq!(take_slot_gen(0, l), SlotGen::Wrap, "{l:?}: the mid-sweep sentinel");
            assert_eq!(take_slot_gen(1, l), SlotGen::Gen(1), "{l:?}");
            assert_eq!(take_slot_gen(2, l), SlotGen::Gen(2), "{l:?}");
            assert_eq!(take_slot_gen(l.gen_max(), l), SlotGen::Gen(l.gen_max()), "{l:?}: the last generation");
            assert_eq!(take_slot_gen(l.gen_max() + 1, l), SlotGen::Wrap, "{l:?}: exhausted");
            assert_eq!(take_slot_gen(u32::MAX, l), SlotGen::Wrap, "{l:?}");
        }
    }
}

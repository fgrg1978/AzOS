// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Per-hart TLB generation: what lets a user address-space switch skip the
//! TLB flush (Kconfig `TLB_RETAIN`, N12).
//!
//! An ASID is unique among the address spaces allocated in one generation
//! (`azos_sched::asid`). [`HART_TLB_GEN`]`[h]` is the generation whose
//! entries hart `h`'s TLB may hold, or [`STALE`]: it may hold entries some
//! shootdown did not reach. A switch into an address space of generation
//! `g` flushes iff the hart's value is not `g` (a rollover, or a stale
//! hart), then records `g`. So a hart never runs an ASID with entries left
//! by another address space that carried the same ASID in another
//! generation, nor with entries a shootdown skipped.
//!
//! **Shootdowns.** A hart that ran an address space and switched away keeps
//! its entries. The ISA shootdowns reach only the harts running the space
//! now (riscv64, x86_64) or flush only the current PCID locally (x86_64
//! `invlpg`), so they call [`mark_space_stale`] after the PTE store: the
//! harts that may hold the space's entries (every other hart without
//! `TLB_SPACE_MASK`) flush at their next user switch. aarch64 invalidates with a
//! broadcast `TLBI ... IS` over every ASID and needs no mark.
//!
//! **Per-address-space hart mask (Kconfig `TLB_SPACE_MASK`).** Marking every
//! hart is the fallback. With the mask, each switch-in records its hart in
//! [`SPACES`] under the space's root frame ([`note_ran`]), and a shootdown
//! marks stale only the harts recorded for that frame, plus every hart whose
//! TLB is of another generation than the table's ([`mark_space_stale`]).
//! The table is reset at each ASID rollover, BEFORE the generation advances
//! (`azos_sched::asid`): a hart that reads the new generation records after
//! the reset. A hart that still runs on an older generation is not in the
//! table but is caught by the generation test, which also covers a hart
//! that read the generation just before a rollover. A space that found no
//! slot (the table overflowed) makes a miss mark every hart.
//!
//! **Ordering (store-buffering, fenced on both sides).**
//!   shooter:  store PTE; store STALE (all); fence; load published roots
//!   switcher: publish root; fence; swap HART_TLB_GEN; csrw/msr/mov root
//! Either the shooter sees the published root and signals the hart, or the
//! switcher's swap reads STALE and the switch flushes.

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};

/// Size of the per-hart arrays: Kconfig `NR_CPUS`.
pub const HARTS: usize = azos_limits::NR_CPUS;

/// "This hart's TLB may hold entries a shootdown skipped." Generations
/// start at 1, so no address space ever carries it.
pub const STALE: u32 = 0;

/// "This hart may be running a user root installed outside the generation
/// scheme" (a smoke's ASID-0 root; exec re-enters the scheme through
/// [`enter_installed`]): its next
/// user switch flushes, as with [`STALE`], but until then it may hold a
/// space's entries under an ASID that is not the space's record, so an
/// ASID-scoped broadcast ([`broadcast_scope_asid`]) must not count on it.
/// Generations would reach it only after 2^32 - 1 rollovers.
pub const UNTRACKED: u32 = u32::MAX;

/// Per hart: the generation its TLB is clean for, [`STALE`] or [`UNTRACKED`].
pub static HART_TLB_GEN: [AtomicU32; HARTS] = [const { AtomicU32::new(STALE) }; HARTS];

/// Per hart, read by `context_switch.S` right after it installs a new user
/// root: nonzero means flush (riscv64 `sfence.vma`, aarch64 `tlbi vmalle1`;
/// on x86_64 zero sets the CR3 no-flush bit). Written by
/// `azos_sched::asid::prepare_switch` on the same hart just before the
/// switch, so plain loads suffice in the assembly.
#[no_mangle]
pub static AZOS_TLB_SWITCH_FLUSH: [AtomicU64; HARTS] = [const { AtomicU64::new(1) }; HARTS];

/// Hart `h`'s TLB may hold entries a shootdown skipped (or it installed a
/// root outside the generation scheme): its next user switch flushes.
#[inline]
pub fn mark_stale(h: usize) {
    if azos_limits::TLB_RETAIN && h < HARTS {
        HART_TLB_GEN[h].store(STALE, Ordering::Release);
    }
}

/// Hart `h` runs a root outside the generation scheme ([`UNTRACKED`]): its
/// next user switch flushes and no ASID-scoped broadcast counts on it.
#[inline]
pub fn mark_untracked(h: usize) {
    if azos_limits::TLB_RETAIN && h < HARTS {
        HART_TLB_GEN[h].store(UNTRACKED, Ordering::Release);
    }
}

/// Every hart but `except` (`usize::MAX`: every hart) flushes at its next
/// user switch. Called by a shootdown after its PTE store and before the
/// fence that orders it against the published roots.
#[inline]
pub fn mark_all_stale(except: usize) {
    if !azos_limits::TLB_RETAIN {
        return;
    }
    for (h, g) in HART_TLB_GEN.iter().enumerate() {
        if h != except {
            g.store(STALE, Ordering::Release);
        }
    }
}

/// The switch on hart `h` into a root of generation `gen`: record `gen` and
/// return the hart's previous value. The TLB must be flushed unless it
/// equals `gen` ([`STALE`]: a shootdown skipped this hart; another
/// generation: a rollover). The caller has published the root and fenced
/// (module doc).
#[inline]
pub fn enter(h: usize, gen: u32) -> u32 {
    if h >= HARTS {
        return STALE;
    }
    HART_TLB_GEN[h].swap(gen, Ordering::AcqRel)
}

/// Exec's local install of a user root of generation `gen` on hart `h`
/// (owner decision 10-10: exec goes through the generation scheme on every
/// ISA). The caller re-tagged the word into `gen`, installed it (which marks
/// the hart [`STALE`] or [`UNTRACKED`] and flushes its current context),
/// then published it and fenced, as a switch does. Records `gen` ([`enter`])
/// and returns whether the caller must still flush every context (x86_64:
/// the other PCIDs; riscv64 and aarch64 have flushed every ASID already).
/// The hart leaves exec tracked: an ASID-scoped shootdown counts on it.
#[inline]
pub fn enter_installed(h: usize, gen: u32) -> bool {
    if !azos_limits::TLB_RETAIN || h >= HARTS || gen == STALE || gen == UNTRACKED {
        return false;
    }
    enter(h, gen) != gen
}

/// Set this hart's switch-flush word for `context_switch.S`: 0 keep the TLB,
/// 1 flush when the root changes (the old behaviour), 2 flush even when
/// it does not.
#[inline]
pub fn set_switch_flush_word(h: usize, w: u64) {
    if h < HARTS {
        AZOS_TLB_SWITCH_FLUSH[h].store(w, Ordering::Relaxed);
    }
}

/// Kconfig `TLB_SPACE_MASK` (needs `TLB_RETAIN`): shootdowns mark stale only
/// the harts that ran the space.
pub const SPACE_MASK: bool = azos_limits::TLB_RETAIN && azos_limits::TLB_SPACE_MASK;

/// [`SPACES`] also holds each address space's ASID for the current
/// generation (owner decision 10-10: one ASID per address space), whenever
/// `TLB_RETAIN` is on, mask or not.
pub const SPACE_RECORD: bool = azos_limits::TLB_RETAIN;

/// Slots in [`SPACES`]: `2^TLB_SPACE_SLOTS_BITS`, one without `TLB_RETAIN`.
pub const SPACE_SLOTS: usize = if SPACE_RECORD { 1usize << azos_limits::TLB_SPACE_SLOTS_BITS } else { 1 };

/// Linear-probe bound of [`SPACES`]: Kconfig `TLB_SPACE_PROBE`.
pub const SPACE_PROBE: usize = azos_limits::TLB_SPACE_PROBE as usize;

/// One bit per hart.
pub type HartMask = u64;
const _: () = assert!(HARTS <= HartMask::BITS as usize);

/// Every hart.
pub const ALL_HARTS: HartMask = HartMask::MAX;

/// Root frame -> the space's ASID and the harts that switched into it this
/// generation. Open addressing, linear probing, no deletion: a key takes
/// the first empty slot of its probe run, so two harts recording the same
/// key meet on one slot. Emptied only by [`SpaceTable::reset`].
///
/// **The per-space ASID record.** [`SpaceTable::assign`] (under the ASID
/// allocator's lock) files the ASID a space holds in this generation; every
/// thread of the space adopts it at its switch-in (`azos_sched::asid`), so
/// within one generation a space has exactly one ASID, which is what makes
/// an ASID-scoped invalidation cover the whole space. `assign` probes the
/// whole table, so it fails only when the table is full; the allocator then
/// rolls the generation over (which empties the table) rather than let a
/// space go unrecorded.
pub struct SpaceTable<const N: usize> {
    key: [AtomicUsize; N],
    ran: [AtomicU64; N],
    /// The space's ASID this generation (0: none recorded; ASID 0 is the
    /// kernel's).
    asid: [AtomicU32; N],
    /// The generation the table was reset for.
    gen: AtomicU32,
    /// A key found no slot within the probe bound since the last reset.
    overflow: AtomicBool,
}

impl<const N: usize> SpaceTable<N> {
    /// An empty table for generation 1 (the first ASID generation).
    pub const fn new() -> Self {
        Self {
            key: [const { AtomicUsize::new(0) }; N],
            ran: [const { AtomicU64::new(0) }; N],
            asid: [const { AtomicU32::new(0) }; N],
            gen: AtomicU32::new(1),
            overflow: AtomicBool::new(false),
        }
    }

    #[inline]
    fn start(key: usize) -> usize {
        // Fibonacci hashing: frame numbers are sequential-ish.
        ((key as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15) >> 32) as usize & (N - 1)
    }

    /// Record that hart `h` switched into the space keyed `key` (nonzero).
    /// False when no slot was found within `probe`: the table is then
    /// marked overflowed and [`Self::lookup`] answers "unknown" for misses.
    pub fn note(&self, key: usize, h: usize, probe: usize) -> bool {
        if key == 0 || h >= HartMask::BITS as usize {
            return true;
        }
        let bit = 1u64 << h;
        let mut i = Self::start(key);
        for _ in 0..probe.min(N) {
            let mut k = self.key[i].load(Ordering::Acquire);
            if k == 0 {
                k = match self.key[i].compare_exchange(0, key, Ordering::AcqRel, Ordering::Acquire) {
                    Ok(_) => key,
                    Err(cur) => cur,
                };
            }
            if k == key {
                self.ran[i].fetch_or(bit, Ordering::AcqRel);
                return true;
            }
            i = (i + 1) & (N - 1);
        }
        self.overflow.store(true, Ordering::Release);
        false
    }

    /// The harts recorded for `key`: `Some(0)` when none ran it since the
    /// reset, `None` when the table overflowed and a miss proves nothing.
    pub fn lookup(&self, key: usize, probe: usize) -> Option<HartMask> {
        let mut i = Self::start(key);
        for _ in 0..probe.min(N) {
            let k = self.key[i].load(Ordering::Acquire);
            if k == key {
                return Some(self.ran[i].load(Ordering::Acquire));
            }
            if k == 0 {
                break;
            }
            i = (i + 1) & (N - 1);
        }
        if self.overflow.load(Ordering::Acquire) { None } else { Some(0) }
    }

    /// The slot of `key` within `probe` probes, claiming an empty one when
    /// `claim`; `None` when the run ends (unclaimed miss) or is exhausted.
    fn slot(&self, key: usize, probe: usize, claim: bool) -> Option<usize> {
        let mut i = Self::start(key);
        for _ in 0..probe.min(N) {
            let mut k = self.key[i].load(Ordering::Acquire);
            if k == 0 {
                if !claim {
                    return None;
                }
                k = match self.key[i].compare_exchange(0, key, Ordering::AcqRel, Ordering::Acquire) {
                    Ok(_) => key,
                    Err(cur) => cur,
                };
            }
            if k == key {
                return Some(i);
            }
            i = (i + 1) & (N - 1);
        }
        None
    }

    /// Record `asid` as the ASID of the space keyed `key` (nonzero) in this
    /// generation, replacing any earlier one (a reused root frame is a new
    /// space). Probes the whole table: false only when it is full. Called
    /// under the ASID allocator's lock.
    pub fn assign(&self, key: usize, asid: u16) -> bool {
        if key == 0 {
            return false;
        }
        match self.slot(key, N, true) {
            Some(i) => {
                self.asid[i].store(asid as u32, Ordering::Release);
                true
            }
            None => false,
        }
    }

    /// The ASID recorded for `key` in this generation (0: none).
    pub fn asid_of(&self, key: usize) -> u16 {
        if key == 0 {
            return 0;
        }
        match self.slot(key, N, false) {
            Some(i) => self.asid[i].load(Ordering::Acquire) as u16,
            None => 0,
        }
    }

    /// Empty the table for generation `gen`. Called under the ASID lock
    /// before the generation advances (module doc).
    pub fn reset(&self, gen: u32) {
        for ((k, r), a) in self.key.iter().zip(self.ran.iter()).zip(self.asid.iter()) {
            k.store(0, Ordering::Relaxed);
            r.store(0, Ordering::Relaxed);
            a.store(0, Ordering::Relaxed);
        }
        self.overflow.store(false, Ordering::Relaxed);
        self.gen.store(gen, Ordering::Release);
    }

    /// The generation the table was last reset for.
    pub fn generation(&self) -> u32 {
        self.gen.load(Ordering::Acquire)
    }
}

impl<const N: usize> Default for SpaceTable<N> {
    fn default() -> Self {
        Self::new()
    }
}

/// The kernel's table (Kconfig `TLB_SPACE_SLOTS_BITS`).
pub static SPACES: SpaceTable<SPACE_SLOTS> = SpaceTable::new();

/// Runtime canary `tlb-space-mask-drop` (`kernel/src/canary_rt.rs`): switch-ins
/// record nothing, so a shootdown misses the harts that ran the space (ktest
/// `tlb_space_mask_reaches_the_harts_that_ran`).
pub static CANARY_SPACE_MASK_DROP: AtomicBool = AtomicBool::new(false);

/// Per shooting hart: the harts its last [`mark_space_stale`] marked (what the
/// ktest reads; one store per shootdown).
pub static LAST_MARKED: [AtomicU64; HARTS] = [const { AtomicU64::new(0) }; HARTS];

/// Record that hart `h` switches into the space keyed `key` (its root frame;
/// 0: untracked). Called by `azos_sched::asid::prepare_switch` before the
/// root is published (the publish carries the fence). True when the table
/// holds the record this generation (or keeps none: no `TLB_SPACE_MASK`, or
/// key 0), false when nothing was recorded (an overflow, or the
/// `tlb-space-mask-drop` canary): the switch path memoises only a true
/// answer (`azos_sched::asid::prepare_switch`).
#[inline]
pub fn note_ran(key: usize, h: usize) -> bool {
    if !SPACE_MASK || key == 0 {
        return true;
    }
    if CANARY_SPACE_MASK_DROP.load(Ordering::Relaxed) {
        return false;
    }
    SPACES.note(key, h, SPACE_PROBE)
}

/// Pure: the harts a shootdown of a space must mark stale. `ran`: the
/// table's answer for the space (`None`: unknown, every hart); `hart_gen(h)`:
/// hart `h`'s [`HART_TLB_GEN`]; `table_gen`: the generation the table is
/// for. A hart is marked when it ran the space, or when its TLB is not of
/// `table_gen` (an older generation, or already [`STALE`]). `except` (this
/// hart, `usize::MAX`: none) and harts at or above `harts` are left out.
pub fn space_targets(
    ran: Option<HartMask>,
    hart_gen: impl Fn(usize) -> u32,
    table_gen: u32,
    harts: usize,
    except: usize,
) -> HartMask {
    let n = harts.min(HARTS);
    let mut m: HartMask = 0;
    for h in 0..n {
        if h == except {
            continue;
        }
        let ran_it = match ran {
            None => true,
            Some(r) => r & (1 << h) != 0,
        };
        if ran_it || hart_gen(h) != table_gen {
            m |= 1 << h;
        }
    }
    m
}

/// The stale-mark half of a shootdown of the space rooted at `root_phys`:
/// with `TLB_SPACE_MASK`, mark only the harts [`space_targets`] names;
/// otherwise every hart ([`mark_all_stale`]). `me` is the shooting hart,
/// left out unless `include_me` (x86_64: `invlpg` reaches only the current
/// PCID). Call where `mark_all_stale` was called (after the PTE store,
/// before the fence). Returns the harts marked.
#[inline]
pub fn mark_space_stale(root_phys: usize, me: usize, include_me: bool) -> HartMask {
    if !azos_limits::TLB_RETAIN {
        return 0;
    }
    let except = if include_me { usize::MAX } else { me };
    let key = root_phys >> 12;
    let m = if SPACE_MASK && key != 0 {
        let tg = SPACES.generation();
        let ran = SPACES.lookup(key, SPACE_PROBE);
        space_targets(ran, |h| HART_TLB_GEN[h].load(Ordering::Acquire), tg, HARTS, except)
    } else {
        let mut m: HartMask = 0;
        for h in 0..HARTS {
            if h != except {
                m |= 1 << h;
            }
        }
        m
    };
    for h in 0..HARTS {
        if m & (1 << h) != 0 {
            HART_TLB_GEN[h].store(STALE, Ordering::Release);
        }
    }
    if me < HARTS {
        LAST_MARKED[me].store(m, Ordering::Relaxed);
    }
    m
}

/// Kconfig `TLB_ASID_SCOPED` (needs `TLB_RETAIN`), for the ISAs whose crate
/// reads it here (aarch64, x86_64).
pub const ASID_SCOPED: bool = azos_limits::TLB_RETAIN && azos_limits::TLB_ASID_SCOPED;

/// Pure: may a broadcast invalidation scoped to the ASID a generation-`gen`
/// record holds cover every hart? Yes when each of the first `harts` harts'
/// [`HART_TLB_GEN`] (`hart_gen(h)`) is `gen` (its TLB holds the space's
/// entries, if any, under the recorded ASID only: one ASID per space per
/// generation) or [`STALE`] (on aarch64: never entered a user space since
/// boot). A hart of an older generation may hold them under an older ASID,
/// and an [`UNTRACKED`] one under any.
pub fn harts_scopable(hart_gen: impl Fn(usize) -> u32, gen: u32, harts: usize) -> bool {
    if gen == STALE || gen == UNTRACKED {
        return false;
    }
    (0..harts.min(HARTS)).all(|h| {
        let g = hart_gen(h);
        g == gen || g == STALE
    })
}

/// The ASID a broadcast shootdown (aarch64 `TLBI ASIDE1IS` / `VAE1IS`) of
/// the space keyed `key` (its root frame) may be scoped to, or 0: take the
/// all-ASID form. Nonzero only with a record of the table's generation,
/// read consistently (the generation unchanged around the lookup), and
/// [`harts_scopable`]. The caller's PTE store is ordered before the
/// generation loads by a full fence here: a hart that enters a newer
/// generation after them flushes its whole TLB and then walks the new PTE.
pub fn broadcast_scope_asid(key: usize) -> u16 {
    if !SPACE_RECORD || key == 0 {
        return 0;
    }
    core::sync::atomic::fence(Ordering::SeqCst);
    let g = SPACES.generation();
    let a = SPACES.asid_of(key);
    if a == 0 || SPACES.generation() != g {
        return 0;
    }
    if harts_scopable(|h| HART_TLB_GEN[h].load(Ordering::Acquire), g, HARTS) { a } else { 0 }
}

/// Pure: the ASID a shooter may scope its own invalidation to (x86_64
/// `INVPCID` on the space's PCID): `asid`, the record read with the table's
/// generation `g_before` / `g_after` around the lookup, when the two agree
/// and the shooter's own [`HART_TLB_GEN`] `mine` is that generation (any
/// entry it holds for the space is then under the recorded ASID; an older
/// generation's entries were flushed when it entered this one). 0: none.
pub fn self_scope(asid: u16, g_before: u32, g_after: u32, mine: u32) -> u16 {
    if asid == 0 || g_before != g_after || mine != g_before || mine == STALE || mine == UNTRACKED {
        0
    } else {
        asid
    }
}

/// [`self_scope`] for hart `h` and the space keyed `key` (its root frame).
pub fn self_scope_asid(key: usize, h: usize) -> u16 {
    if !SPACE_RECORD || key == 0 || h >= HARTS {
        return 0;
    }
    let g = SPACES.generation();
    let a = SPACES.asid_of(key);
    self_scope(a, g, SPACES.generation(), HART_TLB_GEN[h].load(Ordering::Acquire))
}

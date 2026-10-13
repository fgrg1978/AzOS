// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Pure hart-liveness accounting for [`crate::smp::wake_harts`].
//!
//! In its own file only so the host test runner (`tests/host/sched-wake-tests`)
//! can compile it: `smp.rs` reads `tp` with inline RISC-V assembly and links
//! against `_secondary_start`, so it can never leave the target. Nothing here
//! has a dependency, and `smp.rs` calls it rather than keeping a copy.
//!
//! # What "online" means, and why it is not a headcount
//!
//! `NUM_ONLINE_CPUS` is consumed as a **prefix bound**: `find_best_cpu` in
//! `scheduler.rs` iterates `0..num_online` and indexes `PER_CPU[i]` directly,
//! and `rebalance_from_offline_cpus(online, total)` treats `online..total` as
//! the dead harts whose ready queues must be drained. So the published number
//! must satisfy exactly one property — **every hart in `0..online` is
//! running** — and a plain count of successes does not satisfy it as soon as
//! there is a hole (hart 2 dead, hart 3 alive).
//!
//! The previous accounting seeded `online = 1` for the boot hart and then
//! incremented per success while a `prefix_intact` flag held. That is correct
//! if and only if the boot hart is hart **0**, because the seed is what claims
//! slot 0. Measured in QEMU virt, the boot hart was hart **2**: with any
//! `hart_start` failure the seeded 1 then stands for a hart nobody started.
//! Concretely, boot hart 2 with hart 0 failing published `online = 1`, i.e.
//! "hart 0 is alive" — the one hart that is not — so every unpinned task went
//! to a dead hart and `rebalance_from_offline_cpus(1, 4)` drained the *live*
//! boot hart's own queue onto it.
//!
//! Recording liveness as a bitmask and deriving the prefix afterwards makes
//! the result independent of which hart happens to boot, which is the whole
//! fix. The result stays conservative rather than unsafe: a live hart past a
//! hole sits idle (see [`stranded`]) instead of a dead hart receiving work.

/// Width of the liveness mask. Harts at or above this index cannot be
/// represented; the Kconfig `NR_CPUS` range stops at 64 for this reason (the
/// scheduler asserts `MAX_CPUS <= HART_MASK_BITS`).
pub const HART_MASK_BITS: usize = u64::BITS as usize;

/// Set the bit for `hart_id`, ignoring ids the mask cannot hold.
///
/// The bounds check is not decoration: `1u64 << hart_id` with `hart_id >= 64`
/// is an overflow, and under this profile (`overflow-checks = true`,
/// `panic = "abort"`) that is a board reset. `num_cpus` comes from the DTB.
#[inline]
pub fn mark_alive(mask: u64, hart_id: usize) -> u64 {
    if hart_id >= HART_MASK_BITS {
        return mask;
    }
    mask | (1u64 << hart_id)
}

/// Length of the longest run of live harts starting at hart 0, capped at
/// `num_cpus`. This is the value to publish as `NUM_ONLINE_CPUS`.
///
/// Returns 0 when hart 0 itself is dead — deliberately. Clamping to 1 would
/// assert that hart 0 is running when it is not, which is the failure this
/// whole module exists to avoid; both consumers already guard the zero case
/// (`rebalance_from_offline_cpus` returns early on `online == 0`,
/// `find_best_cpu` on `num_online <= 1`).
pub fn online_prefix(alive: u64, num_cpus: usize) -> usize {
    let n = num_cpus.min(HART_MASK_BITS);
    let mut count = 0;
    while count < n && (alive >> count) & 1 != 0 {
        count += 1;
    }
    count
}

/// Harts that are alive but sit past the first dead one, so the prefix
/// excludes them and they will never be given work.
///
/// Exists to be logged. Silently idling a working CPU is the kind of thing
/// that gets diagnosed months later as "SMP is slower than it should be".
pub fn stranded(alive: u64, num_cpus: usize) -> u64 {
    let n = num_cpus.min(HART_MASK_BITS);
    let p = online_prefix(alive, num_cpus);
    alive & low_mask(n) & !low_mask(p)
}

/// `bits` low bits set. Split out because `1u64 << 64` is an overflow panic,
/// and `bits == 64` is reachable through `HART_MASK_BITS`.
#[inline]
fn low_mask(bits: usize) -> u64 {
    if bits >= HART_MASK_BITS {
        u64::MAX
    } else {
        (1u64 << bits) - 1
    }
}

// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
#![no_std]

extern crate alloc;

pub mod addr;
/// The frame descriptor table: one 32-byte descriptor per frame of RAM.
pub mod frame;
/// The buddy allocator over the descriptors and the per-hart frame caches.
pub mod buddy;
/// Type zones for physical frames (Kconfig `PMM_TYPE_ZONES`).
pub mod zone;
pub mod pmm;
pub mod vmm;
/// N12h: CAS installs of page-table words the user mapper and the kernel-half
/// merge race for (host-tested, `#[path]`).
pub mod pte_install;
/// FX7/FX8: the merged-root roster walk, one `PT_META` hold per root
/// (host-tested, `#[path]`).
mod roster;
/// Per-task frame budget arithmetic (owner decision 102), factored out so it
/// can be host-tested. Held by the task's domain (`crates/core/sched/src/domain.rs`)
/// — see this module's doc.
pub mod budget;
/// The W^X boundary rule, shared by the enforcer and the verifier.
pub mod wx;
/// Wave 15: the controlled kernel-text write path (static keys).
pub mod text_poke;
/// E11 / AQ9 — Copy-on-Write support for `fork()`.
pub mod cow;
mod cow_table;
/// E11 / AQ10 — Demand paging (allocate-on-first-access).
pub mod demand;
pub mod region;
/// Kconfig `MM_THP_RESV`: superpage reservations (host-tested, `#[path]`).
pub mod resv;
/// Kconfig `MM_RECLAIM_COMPRESS`: the compressed-page pool. Its host rows
/// (`tests/host/mm-tests`) pull this file with `#[path]` and run the pool, the
/// codec and the storm loop; the walk of a live address space that feeds it is
/// `pager`'s, which the `reclaim:` gate rows exercise and the host rows do not.
pub mod zpool;
/// Kconfig `MM_RECLAIM_COMPRESS`: page generations for the reclaimer. The table
/// has host rows (`tests/host/mm-tests` pulls this file with `#[path]`) over a
/// modelled address space; `Mmu::harvest_accessed` has rows in
/// `tests/host/arch-api-tests`, and `pager::age_space`, which walks real tables,
/// runs only in the `reclaim:` gate rows.
pub mod aging;
/// Kconfig `MM_SWAP_BACKEND`: full segments of the pool written to the swap
/// partition (host-tested, `#[path]`).
pub mod swap;
pub mod pager;
/// User-memory access sections: what keeps a frame a kernel copy is using
/// from being freed or reused under it (host-tested, `#[path]`).
pub mod uaccess;
/// Wave 14 (SPAWNCACHE): a verified image's frames, kept for its next spawn.
pub mod image_frames;
pub mod kheap;
/// Kconfig `KHEAP_GUARD_*`: red zones, poison and quarantine around every heap block.
pub mod kheap_guard;
pub mod slab;
#[cfg(feature = "kheap-census")]
pub mod kheap_census;
pub mod vdso;
/// Kconfig `LOCKED_HUGE_LEAVES`: boot-reserved regions of locked rows,
/// mapped with level-1 leaves.
pub mod huge;

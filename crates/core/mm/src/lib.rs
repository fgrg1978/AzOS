// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
#![no_std]

extern crate alloc;

pub mod addr;
pub mod pmm;
pub mod vmm;
/// Per-task frame budget arithmetic (owner decision 102), factored out so it
/// can be host-tested. Wired in as `Task::budget` in `crates/core/sched/src/task.rs`
/// — see this module's doc.
pub mod budget;
/// The W^X boundary rule, shared by the enforcer and the verifier.
pub mod wx;
/// E11 / AQ9 — Copy-on-Write support for `fork()`.
pub mod cow;
mod cow_table;
/// E11 / AQ10 — Demand paging (allocate-on-first-access).
pub mod demand;
pub mod region;
pub mod pager;
/// Wave 14 (SPAWNCACHE): a verified image's frames, kept for its next spawn.
pub mod image_frames;
pub mod kheap;
pub mod vdso;
/// Kconfig `LOCKED_HUGE_LEAVES`: boot-reserved regions of locked rows,
/// mapped with level-1 leaves.
pub mod huge;

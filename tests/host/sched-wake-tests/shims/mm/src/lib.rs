// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host stand-in for `azos_mm`, used only by `tests/host/sched-wake-tests`.
//!
//! **WHY this exists.** Owner decision 102 wired the per-task frame budget
//! (`crates/core/mm/src/budget.rs::PageBudget`) into `Task::budget`
//! (`crates/core/sched/src/task.rs`), which `sched-wake-tests` pulls in whole via
//! `#[path]` (see that crate's `lib.rs` doc for why: the real scheduler
//! cannot be host-built, but `task.rs` has no target-specific code). That
//! `azos_mm::budget::PageBudget` name now has to resolve on the host,
//! and the real `azos_mm` crate cannot compile here — it depends on
//! `azos_arch` (inline asm) transitively through `azos_sync` and
//! friends, exactly the property `tests/host/mm-tests` was built to route around
//! for the same file.
//!
//! **What is real: everything.** `budget.rs` has no dependency on `core`
//! beyond what any host-buildable Rust file gets for free (plain `u32`
//! fields, derives, saturating arithmetic) and no `crate::`-relative `use`,
//! so it is pulled in byte-for-byte unmodified — the same file
//! `tests/host/mm-tests` pulls to get its own 9 `budget_tests`, not a
//! transcription of it.
//!
//! `#[path]` on a module nested *inside* another `mod` block resolves
//! relative to a directory named after the outer module (`src/budget/...`),
//! not this file's own directory — so the pull has to be a top-level `mod`
//! declared right here, unlike `crates/core/mm/src/lib.rs`'s plain `pub mod
//! budget;` which works because `budget.rs` sits directly beside `lib.rs`.
#[path = "../../../../../../crates/core/mm/src/budget.rs"]
pub mod budget;

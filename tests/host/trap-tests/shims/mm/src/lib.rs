// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host stand-in for `azos_mm`, used only by `tests/host/trap-tests`: the
//! kernel's real `budget.rs` (plain integers and atomics, no target code),
//! which is all `domain.rs` names from `azos_mm`. The same shim
//! `tests/host/sched-wake-tests` uses, for the same file.
#[path = "../../../../../../crates/core/mm/src/budget.rs"]
pub mod budget;

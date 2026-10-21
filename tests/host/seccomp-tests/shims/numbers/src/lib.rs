// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The kernel's real syscall number table, pulled in verbatim.
//!
//! This is deliberately NOT a stub. `crates/core/sched/src/seccomp.rs` cannot
//! depend on `azos_syscall` (that crate depends on `azos_sched`, so
//! the edge would close a cycle), and it therefore redeclares every number it
//! needs as a private local `const`. Two copies of a number that must agree,
//! with nothing checking that they do: renumber a syscall on one side and the
//! profiles silently whitelist a *different* call. This shim exists so the
//! suite can compare the two.
#![allow(dead_code)]

#[path = "../../../../../../crates/core/syscall/src/numbers.rs"]
pub mod numbers;

// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Syscall numbers.
//!
//! `crates/core/abi` (`crates/core/abi/src/syscall_nr.rs`) is the single source of
//! truth for syscall numbers. This module re-exports it rather than
//! restating the table, so the kernel-side dispatcher and the frozen ABI
//! can never drift apart.
//!
//! Historically this file held its own copy of every `SYS_*` constant
//! ("a direct port of `kernel/include/syscall.h`"), and `crates/core/abi` held a
//! second copy described as "mirrored verbatim" from this one. Both copies
//! were mechanically diffed against each other and against `crates/core/libsys`
//! before this re-export replaced them — see the diff in the commit that
//! introduced this file's current form. No value disagreed; the risk was
//! latent, not realized.

pub use azos_abi::syscall_nr::*;

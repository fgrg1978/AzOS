// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
#![no_std]
#![forbid(unsafe_code)]

//! The robot extension's benchmarks, reported like `azos_bench`'s.

mod protocol;
pub use protocol::run;

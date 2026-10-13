// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host tests for `azos_ualloc`: the engine over a model of the kernel's
//! memory calls. A fault is a panic carrying the [`Fault`] kind, so a test
//! asserts WHICH detection fired; every detection test has a control that does
//! the same thing without the bug and expects no fault.

#![cfg(test)]

mod model;
mod tests;
mod bench;

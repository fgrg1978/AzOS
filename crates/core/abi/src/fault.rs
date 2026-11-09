// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! What a faulting access was, as the trap reads it from the ISA's syndrome
//! and the fault path asks the leaf about it.

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Access {
    Read,
    Write,
    /// An instruction fetch.
    Fetch,
}

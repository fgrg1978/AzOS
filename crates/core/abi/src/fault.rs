// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! What a faulting access was, as the trap reads it from the ISA's syndrome
//! and the fault path asks the leaf about it.

/// The kind of access that faulted.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Access {
    /// A data load.
    Read,
    /// A data store.
    Write,
    /// An instruction fetch.
    Fetch,
}

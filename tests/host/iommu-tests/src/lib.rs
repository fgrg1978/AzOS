// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
#![cfg(test)]
//! Every expected value below is computed by hand from the field positions
//! in the specification (the comment on each vector says how), never from
//! the constants of the crate under test: a wrong bit position in the crate
//! must fail here.

mod common;
mod domain;
mod pgtable;
mod units;
mod vectors;

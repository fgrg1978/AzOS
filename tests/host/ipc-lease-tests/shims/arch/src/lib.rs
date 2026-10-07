// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host stand-in for `azos_arch` — the page size only.
//!
//! **WHY this exists.** `crates/core/ipc/src/lease.rs` asks `shm.rs` who owns a
//! region, so this crate compiles `shm.rs`, and `shm_create` zeroes each page
//! it allocates with `azos_arch::mmu::PAGE_SIZE`. The real crate is
//! RV64-only.
//!
//! The value is `shims/mm`'s own page size, so the zeroing can never run past
//! a page of that pool.
//!
//! Pulled in under the name `azos_arch` via a Cargo dependency rename. The
//! kernel never sees it.

pub mod mmu {
    pub const PAGE_SIZE: usize = azos_mm::PAGE_SIZE;
}

/// The contract's page size under its ISA-neutral name.
pub const PAGE_SIZE: usize = azos_mm::PAGE_SIZE;

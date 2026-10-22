// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `azos_ualloc`: the hardened allocator of native ring-3 programs.
//!
//! [`engine`] is the allocator, generic over [`engine::Sys`] (mmap/munmap,
//! entropy, fault) so the host tests run it over a model of the kernel's
//! calls. [`UserAlloc`] (ring-3 targets only) is the engine over the AzOS
//! calls, behind a spin lock, with a `GlobalAlloc` impl; its knobs are
//! Kconfig `USER_ALLOC_*` (`config/Kconfig.security`), read through
//! `azos_limits`.

#![no_std]

pub mod engine;

#[cfg(all(target_os = "azos", not(azos_std)))]
mod native;
#[cfg(all(target_os = "azos", not(azos_std)))]
pub use native::{NativeSys, UserAlloc};

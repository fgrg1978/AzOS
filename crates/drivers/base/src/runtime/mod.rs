// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Driver runtime — registry + (future) dynamic loader.
//!
//! By the modular pattern, every replaceable subsystem ships a `runtime/`
//! module so a later phase can add dynamic loading without touching
//! consumers. In Phase 1 the registry is a static table; in Phase 4
//! a disk/network loader populates it.

pub mod registry;

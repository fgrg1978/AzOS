// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Driver runtime — registry + (future) dynamic loader.
//!
//! Per RFC-0002: every replaceable subsystem ships a `runtime/`
//! module so a Phase 4 RFC can add dynamic loading without touching
//! consumers. In Phase 1 the registry is a static table; in Phase 4
//! a disk/network loader populates it.

pub mod registry;

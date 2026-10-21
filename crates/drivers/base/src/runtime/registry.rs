// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Production registry static — wraps the host-testable
//! [`azos_drv_api::Registry`] in a `SpinLock` so it can be
//! shared across CPUs.
//!
//! ## Phase 1 — **comment corrected 2026-09-26 (U05-11); no longer true**
//! - In-kernel drivers in `crates/drivers/*` used to be wired statically
//!   with no entry here. That changed before this comment was updated:
//!   `kernel/src/main.rs` registers `UART_DRV`, `GPIO_DRV`, `I2C_DRV`,
//!   `PWM_DRV` and `MOTOR_DRV` into this same [`REGISTRY`] at boot
//!   (`grep -n '\.register(&' kernel/src/main.rs`), and `sys_drv_invoke`
//!   (`crates/core/syscall/src/handlers.rs`) looks them up through it. This
//!   registry is live in production for those five drivers, not empty —
//!   the threat model this doc used to describe (nothing reachable
//!   through `REGISTRY` except in tests) is stale.
//! - Userspace drivers register through `azos_driver_server`
//!   (E11.AQ3) and the kernel-side `UserDriverProxy` adapts them, into the
//!   same registry as the five above.
//!
//! ## Phase 4 (target)
//! A disk/network loader instantiates drivers from manifests and
//! calls `REGISTRY.lock().register(...)`. Consumers look up
//! `dyn Driver` by `kind` regardless of isolation, so the
//! in-kernel ↔ userspace split becomes invisible.

use azos_drv_api::Registry;
use azos_sync::SpinLock;

pub use azos_drv_api::{RegistryError, REGISTRY_MAX_DRIVERS};

/// Global driver registry. Locked because `register` mutates and
/// `find_by_kind` is invoked from arbitrary CPUs.
pub static REGISTRY: SpinLock<Registry> = SpinLock::new(Registry::empty());

// Host-side tests for the underlying `Registry` struct live in
// `tests/host/drv-api-tests`.

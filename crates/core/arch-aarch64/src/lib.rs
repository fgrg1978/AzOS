// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `arch-aarch64` — AZOS Phase 2 aarch64 (ARMv8-A) ISA impl of
//! the `azos_arch_api` trait surface.
//!
//! # Scope, updated from the original B1 commit
//!
//! - [`api_impl::Aarch64`] satisfies [`Cpu`], [`Interrupts`], [`Mmu`], and
//!   [`Boot`]. `Vector` (the B1.vec placeholder mentioned here originally)
//!   is riscv64-only today — arch-api's own `Vector` trait has no aarch64
//!   impl in this crate, and `azos_arch::Vector` calls are 0 across the
//!   tree outside `crates/core/arch*` (measured, U10's arch-api count).
//! - System-register read/write helpers in [`sysregs`].
//! - VMSAv8-64 PTE encoding in [`mmu`].
//! - PSCI v1.0 calls (CPU_ON / SYSTEM_OFF / SYSTEM_RESET) in
//!   [`psci`].
//! - GIC v3 programming ([`gic`]) and early-boot `.S`
//!   (`kernel::entry::aarch64::asm::boot`) both landed. This crate builds
//!   for both `aarch64-unknown-none` (hard-float: `tests/qemu/aarch64-smoke`,
//!   the gate's crate row, NEON `dot_f32`) and
//!   `aarch64-unknown-none-softfloat` (the kernel, which is FP-free; the
//!   FP asm in `fp_state` enables the FP extension explicitly, and
//!   `vector::dot_f32_best` falls back to scalar without NEON).
//!
//! # Why everything is `cfg(target_arch = "aarch64")`
//!
//! `crates/core/arch-aarch64` is a workspace member, but the workspace
//! default target is `riscv64gc-unknown-none-elf`. The asm bodies
//! cannot assemble on RISC-V, so the inner functions are
//! cfg-gated. On the workspace target the crate compiles as
//! essentially-empty (struct definitions + module declarations
//! only); on `aarch64-unknown-none-softfloat` the real impls
//! light up. This way:
//!
//! - `bash tools/build.sh` keeps catching breakage in the
//!   type-level surface (struct shapes, trait method signatures).
//! - Standalone `cargo build --target aarch64-unknown-none-softfloat
//!   -p azos_arch_aarch64` exercises the asm.
//!
//! No `cfg` shenanigans leak into the public API: callers always
//! see [`api_impl::Aarch64`] + a trait impl, regardless of
//! target. Calling those impls from a non-aarch64 target is a
//! link-time error rather than a runtime panic (the `impl`
//! blocks themselves are cfg-gated).

#![no_std]
#![allow(dead_code)] // some helpers are referenced only by asm bodies

pub use azos_arch_api::{
    Boot, Cpu, HartStartError, InterruptState, Interrupts, Mmu, MmuError,
    PagePerms, Vector,
};

pub mod api_impl;
pub mod boot;
pub mod cache;
pub mod cbo;
pub mod cpu;
/// ARMv8.5 feature detection from the architectural ID registers.
pub mod features;
pub mod fork_regs;
pub mod fp_state;
pub mod gic;
/// GICv3 ITS — PCI MSI/MSI-X → LPI delivery. See the module doc for scope
/// (RFC-0046 stage 1a: one collection, direct device table, no Indirect).
pub mod its;
pub mod midr;
pub mod mmu;
pub mod mmu_setup;
pub mod mpidr;
pub mod psci;
/// SHA-256 on the ARMv8 Cryptographic Extension (wave 13).
pub mod sha2_ce;
/// SMP building blocks (redistributor-walk bring-up) tying `gic` +
/// `psci` + `mpidr` + `timer` together — see the module doc for scope.
pub mod smp;
pub mod sysregs;
pub mod timer;
pub mod vector;

// Masked-window tracer hooks (Kconfig `LAT_TRACE`). Absent by default.
#[cfg(all(feature = "lat-trace", target_arch = "aarch64"))]
pub mod lat_hook;

/// Architectural identifier surfaced through arch-api.
pub const ARCH_ID: azos_arch_api::ArchId =
    azos_arch_api::ArchId::Aarch64;

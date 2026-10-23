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
//!   [`firmware`].
//! - GIC v3 programming ([`gic`]) and early-boot `.S`
//!   (`kernel::entry::aarch64::asm::boot`) both landed. This crate builds
//!   for `aarch64-unknown-none-softfloat` (the kernel, which is FP-free; the
//!   FP asm in `fp` enables the FP extension explicitly, and `dot_f32` is
//!   the scalar loop).
//!
//! # Why everything is `cfg(target_arch = "aarch64")`
//!
//! `crates/core/arch-aarch64` is a workspace member, but the workspace
//! default target is `riscv64imac-unknown-none-elf`. The asm bodies
//! cannot assemble on RISC-V, so the inner functions are
//! cfg-gated. On the workspace target the crate compiles as
//! essentially-empty (struct definitions + module declarations
//! only); on `aarch64-unknown-none-softfloat` the real impls
//! light up. This way:
//!
//! - `make check` (and `make check0`) keep catching breakage in the
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

pub use azos_arch_api::{
    Boot, Cpu, HartStartError, InterruptState, Interrupts, Mmu, MmuError,
    PagePerms, Vector,
};
// The rest of the arch contract (`ArchPlatform`, `ArchEntry`) and the page
// geometry, under the same ISA-neutral names on every ISA.
pub use azos_arch_api::{ArchEntry, ArchPlatform, FirmwareMemory, PAGE_SHIFT, PAGE_SIZE};
// Spin-wait and CAS (wave 15, N2): the trait and its ordering type.
pub use azos_arch_api::{CasOrder, SpinWait};
// The performance counters (`ARCH.cycles()`, `.instructions()`, `.event(sel)`).
pub use azos_arch_api::Pmu;

pub mod api_impl;
#[cfg(target_arch = "aarch64")]
mod platform_impl;
pub mod cache;
pub mod cpu;
/// aarch64-only extras (`ext/`).
pub mod ext;
/// This ISA's `azos_arch_api::Hypervisor` (Kconfig VIRT), reached as `azos_arch::HvImpl`.
pub use ext::hv::HvImpl;
/// PSCI (CPU_ON, SYSTEM_OFF, SYSTEM_RESET) and semihosting `SYS_EXIT`, the ktest
/// runner's exit status under QEMU.
pub mod firmware;
pub mod fork_regs;
/// The FP/SIMD register file's save and restore, and the NEON kernels.
pub mod fp;
/// The interrupt controller: GICv3 and its ITS.
pub mod irq;
pub mod mmu;
/// The PMUv3 counters behind `Pmu` (Kconfig `A64_PMU`).
pub mod pmu;
/// FEAT_RNG `RNDRRS`: the entropy pool's CPU seed source.
pub mod seed;
/// SMP building blocks (redistributor-walk bring-up) tying `gic` +
/// `firmware` + `cpu` + `timer` together — see the module doc for scope.
pub mod smp;
// SpinWait: LSE CAS, LDAXR+WFE, LL/SC fallback (wave 15, N2).
pub mod spin;
pub mod sysregs;
pub mod timer;

// Masked-window tracer hooks (Kconfig `LAT_TRACE`). Absent by default.
#[cfg(all(feature = "lat-trace", target_arch = "aarch64"))]
pub mod lat_hook;

/// Architectural identifier surfaced through arch-api.
pub const ARCH_ID: azos_arch_api::ArchId =
    azos_arch_api::ArchId::Aarch64;

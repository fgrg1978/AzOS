// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
#![no_std]

// The cross-ISA contract, re-exported at the crate root exactly as
// `arch-aarch64` does it. Without this the traits are only reachable by
// naming `azos_arch_api` directly, which every consuming crate would
// then need as a dependency just to have `Interrupts` in scope — and the
// facade in `crates/core/arch` could not offer an ISA-neutral surface at all.
pub use azos_arch_api::{
    Boot, Cpu, HartStartError, InterruptState, Interrupts, Mmu, MmuError,
    PagePerms, Vector,
};
// The rest of the arch contract (`ArchPlatform`, `ArchEntry`) and the page
// geometry, under the same ISA-neutral names on every ISA.
pub use azos_arch_api::{ArchEntry, ArchPlatform, FirmwareMemory, PAGE_SHIFT, PAGE_SIZE};
// Spin-wait and CAS (wave 15, N2): the trait and its ordering type.
pub use azos_arch_api::{CasOrder, SpinWait};
// Sv39 has one base page size: the contract's must agree with `mmu`'s.
const _: () = assert!(mmu::PAGE_SIZE == PAGE_SIZE && mmu::PAGE_SHIFT == PAGE_SHIFT);

pub mod cbo;
pub mod cpu;
pub mod csr;
pub mod mmu;
pub mod pmp;
pub mod rvv;
// Cross-arch portable face of `rvv` — mirrors arch-aarch64::vector
// and arch-x86_64::vector.
pub mod vector;
pub mod sbi;
// SpinWait: Zacas / Zawrs / Zihintpause, LR/SC fallback (wave 15, N2).
pub mod spin;
pub mod trap;
pub mod tlb;

// B0.2 — adapter that implements the cross-ISA `azos_arch_api`
// traits in terms of the legacy free-function modules above. Pure
// additive; existing callers are unaffected.
pub mod api_impl;
mod platform_impl;

// Sv39 has one base page. A `page-16k`/`page-64k` feature (the aarch64
// granule choice) reaching a riscv64 build is a configuration error, not a
// page size: azos_limits refuses it from `.config`, this refuses it from
// the feature side.
const _: () = assert!(
    azos_arch_api::PAGE_SIZE == mmu::PAGE_SIZE,
    "riscv64 (Sv39) has only a 4 KiB base page: drop the page-16k/page-64k feature",
);

// Masked-window tracer hooks (Kconfig `LAT_TRACE`). Absent by default.
#[cfg(feature = "lat-trace")]
pub mod lat_hook;

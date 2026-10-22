// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
#![no_std]
#![forbid(unsafe_code)]

//! Architecture facade: re-exports the active ISA's implementation.
//!
//! Three ISAs run the same `azos_kernel`: riscv64 (`azos_arch_riscv64`),
//! aarch64 (`azos_arch_aarch64`) and x86_64 (`azos_arch_x86_64`). Each crate
//! implements the `arch-api` contract, and this facade selects one by
//! `target_arch` and names its implementation [`ARCH`] / [`ArchImpl`].
//!
//! What is still open is the routing, not the ports. Much of the tree reaches
//! the ISA modules this facade re-exports (`cpu::`, `mmu::`, ...) directly
//! instead of going through the `arch-api` traits: 1,011 `azos_arch::`
//! references in 128 files outside the arch crates, measured 2026-10-13. Each
//! of those is a place that has to be checked by hand on every ISA. The
//! cleanup is planned; the count may only go down.
//!
//! Feature `stub` selects `azos_arch_x86_64` on any target (host checks,
//! `tests/host/arch-stub-tests`): off x86_64 its contract methods are the
//! `todo!()`s that name the x86 mechanism, so a shared crate that reaches past
//! the contract fails to check there.

#[cfg(all(target_arch = "riscv64", not(feature = "stub")))]
pub use azos_arch_riscv64::*;

// `target_os = "none"` in addition to the arch check, unlike the riscv64
// branch above: the riscv64 check alone is safe because no developer host is
// ever `riscv64-*`, but this host toolchain runs on `aarch64-apple-darwin`.
// Without the `target_os` guard, any future host-side `cargo test` that
// reaches this facade directly (rather than through one of the `shims/arch`
// stand-ins the `*-tests` crates use) would compile in real EL1 system
// register asm (`msr DAIF`, `mrs CNTVCT_EL0`, ...) under `target_arch =
// "aarch64"` being true on the host too. Verified no in-tree host test crate
// currently depends on the real `azos_arch` (they all go through a shim
// where they touch it at all) — this guard keeps it that way rather than
// relying on that staying true by convention.
#[cfg(all(target_arch = "aarch64", target_os = "none", not(feature = "stub")))]
pub use azos_arch_aarch64::*;

/// The active ISA's `arch-api` implementation, under one name.
///
/// `arch-riscv64` calls its singleton `RISCV64` and `arch-aarch64` calls
/// its `AARCH64`, so a call site that named either would be ISA-specific
/// for the sake of a spelling. Through this alias the idiom is the same on
/// every ISA:
///
/// ```ignore
/// use azos_arch::{Interrupts, ARCH};
/// let prev = ARCH.disable_all();
/// // ... critical section ...
/// ARCH.restore(prev);
/// ```
///
/// `Riscv64`/`Aarch64` are zero-sized and every method carries `#[inline]`,
/// which matters here: this workspace builds with `lto = false` on purpose
/// (see `[profile.release]` — `cap_store::resolve_only_untrusted` needs its
/// two scans to survive as two scans), so without the attribute a call
/// through this alias would be a real cross-crate call on the path every
/// syscall takes.
#[cfg(all(target_arch = "riscv64", not(feature = "stub")))]
pub use azos_arch_riscv64::api_impl::RISCV64 as ARCH;

#[cfg(all(target_arch = "aarch64", target_os = "none", not(feature = "stub")))]
pub use azos_arch_aarch64::api_impl::AARCH64 as ARCH;

/// The type behind [`ARCH`], for the contract's associated items
/// (`<azos_arch::ArchImpl as Mmu>::PAGE_SIZE`) and for host checks that
/// assert a bound on it.
#[cfg(all(target_arch = "riscv64", not(feature = "stub")))]
pub type ArchImpl = azos_arch_riscv64::api_impl::Riscv64;

#[cfg(all(target_arch = "aarch64", target_os = "none", not(feature = "stub")))]
pub type ArchImpl = azos_arch_aarch64::api_impl::Aarch64;

// x86_64: the real port on a bare-metal x86_64 target. Feature `stub` also
// selects it on the host, where its contract methods are `todo!()` (see the
// module doc), so the host fake ISA and the x86 contract are one method list.
#[cfg(any(feature = "stub", all(target_arch = "x86_64", target_os = "none")))]
pub use azos_arch_x86_64::*;

#[cfg(any(feature = "stub", all(target_arch = "x86_64", target_os = "none")))]
pub use azos_arch_x86_64::X86_64_ARCH as ARCH;

#[cfg(any(feature = "stub", all(target_arch = "x86_64", target_os = "none")))]
pub type ArchImpl = azos_arch_x86_64::X86_64;

// A bare-metal target with no port must not get a silently empty facade.
#[cfg(all(
    target_os = "none",
    not(any(feature = "stub", target_arch = "riscv64", target_arch = "aarch64", target_arch = "x86_64"))
))]
compile_error!(
    "azos_arch: no port for this target_arch. Implement every trait arch-api \
     exports (crates/core/arch-x86_64 is the template) in crates/core/arch-<isa>."
);

// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
#![no_std]

//! Architecture facade: re-exports the active ISA's implementation.
//!
//! **Both ISAs are wired into a real kernel.** riscv64 is the ISA the five
//! RFC-0045 figures are MEASURED on. aarch64 boots the same
//! `azos_kernel` at EL1 and at EL2 as an arm64 `Image`, with MMU, GICv3,
//! a 100 Hz tick, the shared preemptive scheduler, SMP over PSCI on 2 and 4
//! cores, FAT32 over virtio-mmio, networking, and ELF programs at EL0 with
//! `fork` and copy-on-write — asserted by fourteen gate rows as of
//! `gate-157`. `tests/qemu/aarch64-smoke` still exists and still runs in the
//! gate: it exercises the primitives in isolation from the kernel.
//!
//! What is still open is not the port but the routing: the tree reaches this
//! facade directly instead of going through `arch-api` (~214 sites when last
//! counted), so every one of those places is somewhere a third ISA must be
//! re-verified by hand rather than trusted through a trait.
//!
//! (This note has been wrong twice, in the same direction, and both
//! corrections are kept deliberately. An early version said aarch64 had "no
//! boot assembly, no linker script, no CI entry" — corrected 2026-09-21 when
//! all three existed. It was then replaced by "no kernel has been BUILT for
//! aarch64 yet", which stopped being true on 2026-09-22 when the aarch64
//! kernel first ran a user program, and stayed here for a day after that.
//! A comment that describes a capability gap ages the moment someone closes
//! the gap; this one is load-bearing, because it is what a reader checks
//! before deciding whether a second ISA exists.)
//!
//! There is no x86_64 port in this tree.

#[cfg(target_arch = "riscv64")]
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
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
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
#[cfg(target_arch = "riscv64")]
pub use azos_arch_riscv64::api_impl::RISCV64 as ARCH;

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub use azos_arch_aarch64::api_impl::AARCH64 as ARCH;

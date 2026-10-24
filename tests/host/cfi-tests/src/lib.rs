// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Hardware control-flow integrity (plan item I4), host side.
//!
//! * [`scan`]: a landing pad at every global assembly entry of the kernel's
//!   entry sources and the arch crates' `global_asm!`, with the exemptions
//!   written down and justified.
//! * `mapping`: the Kconfig choices -> compiler flags of
//!   `tools/build/kconfig_to_cargo.py`, expanded with the real Kconfig tree, for the
//!   kernel and the user images of all three ISAs.
//! * `keys`: the pure parts of `cpu/cfi.rs` on aarch64 (the key mix) and
//!   x86_64 (the `IA32_S_CET` word), included from the crates that own them.

pub mod scan;

/// The repository root.
pub fn repo() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..").canonicalize().expect("repo root")
}

#[cfg(test)]
mod mapping;

#[cfg(test)]
mod keys;

#[cfg(test)]
mod entries;

// The two `cpu/cfi.rs` files are included at the crate root, flat, so that
// their `crate::sysregs` (aarch64) and `super::{rdmsr, wrmsr}` (x86_64)
// resolve: the aarch64 crate only builds for its own ISA, and the pure half
// of each file needs nothing else.

/// aarch64: the register constants `cfi.rs` names.
#[cfg(test)]
#[allow(dead_code)]
#[path = "../../../../crates/core/arch-aarch64/src/sysregs.rs"]
pub mod sysregs;

/// aarch64: `cpu/cfi.rs`.
#[cfg(test)]
#[allow(dead_code)]
#[path = "../../../../crates/core/arch-aarch64/src/cpu/cfi.rs"]
pub mod a64_cfi;

/// x86_64: `cpu/cfi.rs`, under the two MSR accessors it reaches through
/// `super` (never called off x86_64).
#[cfg(test)]
pub fn rdmsr(_msr: u32) -> u64 {
    unreachable!("host test: no MSRs")
}
#[cfg(test)]
pub fn wrmsr(_msr: u32, _v: u64) {
    unreachable!("host test: no MSRs")
}
#[cfg(test)]
#[allow(dead_code)]
#[path = "../../../../crates/core/arch-x86_64/src/cpu/cfi.rs"]
pub mod x86_cfi;

/// aarch64: `ext/mitigations.rs`, the pure half (MIDR and ID registers ->
/// verdicts); it names `azos_arch_api`'s `ExtPolicy` and, behind
/// `cfg(all(target_arch = "aarch64", target_os = "none"))`, nothing else.
#[cfg(test)]
#[allow(dead_code)]
#[path = "../../../../crates/core/arch-aarch64/src/ext/mitigations.rs"]
pub mod a64_mitigations;

#[cfg(test)]
mod mitigations;

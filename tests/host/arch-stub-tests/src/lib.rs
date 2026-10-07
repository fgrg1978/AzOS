// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The fake ISA (the x86_64 port skeleton, `crates/core/arch-x86_64`)
//! through the real facade: `azos_arch` with feature `stub`
//! must export the whole contract under the names the kernel uses
//! (`ARCH`, `ArchImpl`, the traits, `PAGE_SIZE`), and nothing a caller could
//! use to bypass it.

#[cfg(test)]
mod tests {
    use azos_arch::{
        ArchImpl, ArchPlatform, Boot, Cpu, Interrupts, Mmu, Vector, ARCH, PAGE_SHIFT, PAGE_SIZE,
    };

    /// Every required trait, on the type `ARCH` names. Adding a required
    /// method to arch-api without a stub body fails to compile here.
    fn contract<T: Cpu + Interrupts + Mmu + Boot + Vector + ArchPlatform>(_: &T) {}

    #[test]
    fn stub_satisfies_the_whole_contract() {
        contract::<ArchImpl>(&ARCH);
        assert_eq!(core::mem::size_of::<ArchImpl>(), 0, "the singleton must stay zero-sized");
        // Cpu's per-CPU base methods too (the contract grew them).
        let _ = <ArchImpl as Cpu>::percpu_base;
    }

    #[test]
    fn page_geometry_is_the_contract_constant() {
        assert_eq!(PAGE_SIZE, 1 << PAGE_SHIFT);
    }

    #[test]
    #[should_panic(expected = "x86_64: hart_id")]
    fn stub_bodies_panic_instead_of_lying() {
        let _ = ARCH.hart_id();
    }

    #[test]
    #[should_panic(expected = "x86_64: icache_sync_all")]
    fn platform_bodies_panic_instead_of_lying() {
        ARCH.icache_sync_all();
    }
}

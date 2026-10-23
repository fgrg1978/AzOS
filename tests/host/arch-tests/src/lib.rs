// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host-side tests for the pure parts of `crates/core/arch-riscv64` (and
//! of the aarch64 and x86_64 paging code, further down).
//!
//! **WHY.** 1375 lines with no test of any kind, and it is where the bug of
//! 2026-08-31 lived: `sie.SSIE` was never enabled on secondary harts, so the
//! K-C15 wake doorbell had never once worked on a hart other than 0 since it
//! was added. Nothing caught it for months because nothing looks at this crate.
//!
//! Most of it is inline assembly and cannot run on the host. What can is the
//! arithmetic — Sv39 address decomposition and PMP region encoding — and that
//! is the half whose mistakes are **silent**: a wrong VPN field maps a
//! different page, a wrong PMP encoding leaves memory unprotected while every
//! test still passes.

#[allow(dead_code)]
#[path = "../../../../crates/core/arch-riscv64/src/mmu.rs"]
mod mmu;

#[allow(dead_code)]
#[path = "../../../../crates/core/arch-riscv64/src/ext/pmp.rs"]
mod pmp;

// x86_64 paging and shootdown (wave 15, front X3).
mod x86_paging;

// aarch64 per-process PAC keys (`cpu/cfi.rs`): the pure half (key derivation,
// the key table, the SCTLR enable bits) is included flat under the names the
// file expects (`crate::sysregs`), as tests/host/cfi-tests does; the rows are
// in `pac_keys.rs`.
#[cfg(test)]
#[allow(dead_code, unexpected_cfgs)]
#[path = "../../../../crates/core/arch-aarch64/src/sysregs.rs"]
mod sysregs;
#[cfg(test)]
#[allow(dead_code)]
#[path = "../../../../crates/core/arch-aarch64/src/cpu/cfi.rs"]
mod a64_cfi;
#[cfg(test)]
mod pac_keys;
// aarch64 I-13: the syndrome the trap entry hands to the control-tick
// rollback (`sysregs::el1_alignment_fault`).
#[cfg(test)]
mod esr_align;

// Deep idle (SBI HSM hart_suspend): the parameter decode and the depth ladder.
#[cfg(test)]
mod idle_deep;

// System suspend on riscv64 (SBI SUSP) and x86_64 (ACPI S3 refused without AML).
#[cfg(test)]
mod suspend;
// CPU power: saved context, resume entry, offline ladder (`cpu_power.rs`).
#[cfg(test)]
mod cpu_power;

// Not-present page markers (compressed, swapped, in transit) per ISA (`marker_pte.rs`).
#[cfg(test)]
mod marker_pte;

// The contiguous-run encoders (arm64 contiguous hint, RISC-V Svnapot).
#[cfg(test)]
mod pgsz;

// Wave 8 TLB shootdown: which harts a revoke must interrupt. A wrong mask is
// silent in the direction that matters — a hart left out keeps a stale
// translation and nothing faults — so the selection rule is pinned here.
#[allow(dead_code)]
#[path = "../../../../crates/core/arch-riscv64/src/tlb.rs"]
mod tlb;

/// The shootdown's scan bound: one past the highest hart ever noted, never
/// lowered, blind to ids it cannot index. Canary: `--features
/// tlb-bound-canary` (the note records nothing) fails the first assertion.
#[cfg(test)]
mod tlb_bound {
    use super::tlb::{hart_bound, note_hart_online, remote_mask, TLB_MAX_HARTS};

    #[test]
    fn the_bound_covers_every_noted_hart_and_the_mask_needs_it() {
        // The highest hart the table has, whatever its length (Kconfig `NR_CPUS`).
        let top = TLB_MAX_HARTS - 1;
        note_hart_online(top);
        assert!(hart_bound() > top, "hart {top} noted, bound {}", hart_bound());
        note_hart_online(0);
        assert!(hart_bound() > top, "a lower id lowered the bound to {}", hart_bound());
        note_hart_online(TLB_MAX_HARTS);
        assert!(hart_bound() <= TLB_MAX_HARTS, "an out-of-range id raised the bound past the table");
        // The top hart running root R is found under the bound, and missed
        // under a bound that leaves it out -- the failure the bound must never
        // cause. Nobody is excluded as self (`usize::MAX`).
        let root = 0x8123_4000usize;
        let published = |h: usize| if h == top { (8usize << 60) | (root >> 12) } else { 0 };
        assert_eq!(remote_mask(published, hart_bound(), usize::MAX, root), 1 << top);
        assert_eq!(remote_mask(published, top, usize::MAX, root), 0);
    }
}

#[cfg(test)]
mod tlb_mask {
    use super::tlb::{publish, remote_mask, AZOS_HART_SATP, TLB_MAX_HARTS};
    use core::sync::atomic::Ordering;

    const MODE_SV39: usize = 8 << 60;
    fn satp(root: usize, asid: usize) -> usize { MODE_SV39 | (asid << 44) | (root >> 12) }

    /// The table is `TLB_MAX_HARTS` (Kconfig `NR_CPUS`) long, whatever the
    /// build says (64 on a QEMU image, 4 on a small board, 1 on a micro one).
    /// A scenario names harts by id and an id the table does not have is a
    /// hart that does not exist: the hart is absent from the table (published
    /// value 0) and from the expected mask, never an index past the end.
    fn table(spec: &[usize]) -> impl Fn(usize) -> usize + '_ {
        move |h| if h < TLB_MAX_HARTS { spec.get(h).copied().unwrap_or(0) } else { panic!("hart {h} read past the table") }
    }
    /// The bits of `mask` that name a hart the table has.
    fn real(mask: usize) -> usize {
        if TLB_MAX_HARTS == usize::BITS as usize { mask } else { mask & ((1usize << TLB_MAX_HARTS) - 1) }
    }
    /// Serialises the tests that write the process-global `AZOS_HART_SATP`.
    static SATP_TABLE: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn only_harts_running_the_root_are_selected_and_never_self() {
        let root = 0x8123_4000;
        let other = 0x8765_4000;
        let pubd = [satp(root, 0), satp(other, 0), satp(root, 0), 0, satp(root, 0)];
        // From hart 0: harts 2 and 4 hold it; hart 0 is self, hart 1 runs another root.
        assert_eq!(remote_mask(table(&pubd), 8, 0, root), real(0b1_0100));
        // From hart 1 (not running it): harts 0, 2 and 4.
        assert_eq!(remote_mask(table(&pubd), 8, 1, root), real(0b1_0101));
    }

    /// ASID-scoped shootdown (Kconfig `TLB_ASID_SCOPED`): only a hart whose
    /// live ASID is the space's recorded one gets the scoped form; a hart
    /// still on an older generation's ASID (running across a rollover) gets
    /// the all-ASID form. Canary: put every on-root hart in `scoped` and the
    /// mixed-generation assert fails.
    #[test]
    fn a_hart_on_an_older_asid_gets_the_all_asid_form() {
        use super::tlb::scoped_split;
        let root = 0x8123_4000;
        // Hart 1 and 3 run the space under its ASID 5; hart 2 still runs it
        // under 9 (the previous generation); hart 4 runs another space.
        let pubd = [satp(root, 5), satp(root, 5), satp(root, 9), satp(root, 5), satp(0x8765_4000, 5)];
        assert_eq!(scoped_split(table(&pubd), 8, 0, root, 5), (real(0b1010), real(0b0100)));
        // No record (0): everything all-ASID, same harts.
        assert_eq!(scoped_split(table(&pubd), 8, 0, root, 0), (0, real(0b1110)));
        // A record no hart runs under: all-ASID.
        assert_eq!(scoped_split(table(&pubd), 8, 0, root, 7), (0, real(0b1110)));
    }

    #[test]
    fn a_single_hart_address_space_needs_no_ipi() {
        // Today's shape: the caller runs the address space, nobody else does.
        let root = 0x8020_0000;
        let pubd = [satp(root, 0), satp(0x8030_0000, 0)];
        assert_eq!(remote_mask(table(&pubd), 8, 0, root), 0);
    }

    #[test]
    fn mode_and_asid_bits_do_not_hide_a_hart() {
        let root = 0x9000_0000;
        let pubd = [0, satp(root, 7), satp(root, 0xffff)];
        assert_eq!(remote_mask(table(&pubd), 8, 0, root), real(0b110));
    }

    #[test]
    fn unpublished_slots_and_a_zero_root_select_nothing() {
        assert_eq!(remote_mask(table(&[]), 8, 0, 0x8000_0000), 0);
        // Root 0 must never match the zero ("never published") slots.
        assert_eq!(remote_mask(table(&[]), 8, 3, 0), 0);
    }

    #[test]
    fn hart_count_is_clamped_to_the_table() {
        // The table is `TLB_MAX_HARTS` (Kconfig `NR_CPUS`) long; a hart count
        // past it must stop at its end, never index past it.
        let root = 0x8123_4000;
        let pubd = [satp(root, 0); TLB_MAX_HARTS];
        let all = if TLB_MAX_HARTS == usize::BITS as usize { usize::MAX } else { (1usize << TLB_MAX_HARTS) - 1 };
        assert_eq!(remote_mask(|h| pubd[h], TLB_MAX_HARTS + 8, 0, root), all & !1);
    }

    /// The page-table free check (`holders`) is the shootdown's selection
    /// with nobody excluded: the hart that asks is the one most likely to
    /// still be on the table (an exit that frees before it leaves), so it
    /// must count. Canary: pass the caller's own id as `self_hart` in
    /// `holders` and the first assertion fails.
    #[test]
    fn a_free_counts_the_hart_that_asks() {
        use super::tlb::{holders, note_hart_online};
        let _table = SATP_TABLE.lock().unwrap_or_else(|e| e.into_inner());
        let root = 0x8abc_d000;
        // The last hart of the table, whatever its length.
        let last = TLB_MAX_HARTS - 1;
        note_hart_online(last);
        publish(last, satp(root, 3));
        assert_eq!(holders(root) & (1 << last), 1 << last, "a hart publishing the root is a holder");
        publish(last, satp(0x8abc_e000, 0));
        assert_eq!(holders(root) & (1 << last), 0, "a hart that moved off it is not");
        publish(last, 0);
        // The same rule through the pure selection: excluding nobody includes
        // the would-be self.
        let pubd = [satp(root, 0)];
        assert_eq!(remote_mask(table(&pubd), 8, usize::MAX, root), 1);
        assert_eq!(remote_mask(table(&pubd), 8, 0, root), 0);
    }

    #[test]
    fn publish_stores_the_value_and_ignores_out_of_range_harts() {
        let _table = SATP_TABLE.lock().unwrap_or_else(|e| e.into_inner());
        let last = TLB_MAX_HARTS - 1;
        publish(last, 0x1234);
        assert_eq!(AZOS_HART_SATP[last].load(Ordering::SeqCst), 0x1234);
        publish(TLB_MAX_HARTS, 0x5678); // must not panic or write anywhere
        publish(last, 0);
    }
}

// The aarch64 side's ID-register decoding, for the same reason: it is pure
// arithmetic whose mistakes are silent. A field shift off by four reads a
// NEIGHBOURING feature's bits and reports that one instead — a kernel that
// believes it has MTE when the CPU said BTI is a kernel that has disabled its
// own memory tagging and does not know. The `#[cfg(target_arch)]` guards inside
// keep the register reads out of a host build; `detect()` answers `NONE` here,
// which is itself asserted.
#[allow(dead_code)]
#[path = "../../../../crates/core/arch-aarch64/src/cpu/features.rs"]
mod aarch64_features;

// The PMUv3 counters' probe verdict and off-target state (the register images
// and the decode are in arch-api: tests/host/arch-api-tests).
// The cross-ISA helpers it re-exports are the kernel's (`azos_arch::pmu`), not
// this crate's.
#[allow(dead_code, unused_imports)]
#[path = "../../../../crates/core/arch-aarch64/src/pmu.rs"]
mod aarch64_pmu;

// The WFET deadline and the probe's verdict (FEAT_WFxT).
#[allow(dead_code)]
#[path = "../../../../crates/core/arch-aarch64/src/ext/wfxt.rs"]
mod aarch64_wfxt;

// The TLB shootdown's range decomposition (FEAT_TLBIRANGE): the steps must
// cover the run exactly, the operand fields must sit in their own bits.
// Canary: `--features a64-tlbi-canary` makes NUM one too large.
#[allow(dead_code)]
#[path = "../../../../crates/core/arch-aarch64/src/ext/tlbi_range.rs"]
mod aarch64_tlbi_range;

// The x86_64 CPUID decoding, for the same reason: a bit index off by one
// reports the neighbouring extension, and a vector extension read without
// its XCR0 state is one the OS can never enable. `read_cpuid()` answers all
// zeros off bare metal, which is itself asserted. Canary: `--features
// x86-cpuid-canary`.
// The speculation-mitigation decision (`ext/mitigations.rs`) reads
// `cpu/features.rs`'s vendor/family/model, and `cpu` names `trap`'s
// descriptors, all by `crate::` path: the three x86_64 trees are included at
// this root under the crate's own module names (the CPU-model matrix of the
// q35 gate rows is asserted in `ext::mitigations`).
#[allow(dead_code)]
#[path = "../../../../crates/core/arch-x86_64/src/cpu/mod.rs"]
mod cpu;
#[allow(dead_code)]
#[path = "../../../../crates/core/arch-x86_64/src/trap/mod.rs"]
mod trap;
/// The x86_64 singleton type, which `trap::iomap` implements `IoPorts` for
/// (`crates/core/arch-x86_64/src/lib.rs` is not included here).
struct X86_64;
#[allow(dead_code)]
#[path = "../../../../crates/core/arch-x86_64/src/ext/mod.rs"]
mod ext;

// riscv64 H extension primitives (hypervisor plan step H1): G-stage tables,
// CSR lists, frame layout, exit decode.
mod hv_rv;
// x86_64 deep idle: the mwait ladder per CPU model, its gates and the model's idle list.
#[cfg(test)]
mod idle_x86;
// x86_64 PC power probe: whether the CPU may be asked for a level request (HWP, CPPC)
// and RAPL's energy counter (no #GP fixup exists).
#[cfg(test)]
mod pstate_x86;

// INVLPGB operand/plan/selection and the Svinval encodings (the pure parts of
// the x86_64 and riscv64 shootdown paths).
mod tlb_hw;

// The x86_64 IPI shootdown against a lock waiter with interrupts masked: the
// lock's wait loop answers it (`SpinWait::wait_service`).
mod shootdown_wait;

// M38/U10-3: VMSAv8-64 PTE attribute encode/decode is the aarch64-side twin
// of `mmu` above — pure bit arithmetic, no `cfg(target_arch)` gate anywhere
// in the file, and exactly the kind of mistake that is silent: the ret2usr
// fix landed here (`attr_bits` now sets PXN unconditionally whenever
// `perms.user`) needed a matching fix to `perms_from_attr_bits`'s decode
// side (UXN, not PXN, now carries "software asked for exec" once `user` is
// true) — getting THAT wrong would silently strip `exec` off every user
// page on a COW/permission-widening round trip, passing every existing
// check because nothing else in the tree decodes a PTE and compares it
// against the `PagePerms` that built it. See `mod aarch64_mmu` below.
#[allow(dead_code)]
#[path = "../../../../crates/core/arch-aarch64/src/mmu/mod.rs"]
mod aarch64_mmu;

/// The bootstrap identity map on a board whose RAM is not QEMU `virt`'s: the
/// Device gigabyte follows the DRAM base, and the DRAM window's tail past the
/// end of RAM (a Raspberry Pi 3's peripherals) is what turns Device.
#[cfg(test)]
mod aarch64_boot_window {
    use super::aarch64_mmu::{boot_device_window, boot_tail_blocks, GRANULE_16K, GRANULE_4K, GRANULE_64K};

    const GIB: u64 = 1 << 30;
    const MIB: u64 = 1 << 20;

    /// Canary: with the old fixed choice (`0`, whatever the RAM base) a Pi's
    /// device gigabyte is its own RAM gigabyte.
    #[test]
    fn the_device_gigabyte_is_never_the_ram_one() {
        assert_eq!(boot_device_window(GIB), 0, "QEMU virt: RAM at 1 GiB, devices below it");
        assert_eq!(boot_device_window(2 * GIB), 0);
        assert_eq!(boot_device_window(0), GIB, "Raspberry Pi 3: RAM at 0, its local intc at 1 GiB");
        for base in [0, GIB, 2 * GIB, 8 * GIB] {
            let dev = boot_device_window(base);
            assert!(dev + GIB <= base || dev >= base + GIB, "base {base:#x}: device window {dev:#x} overlaps RAM");
        }
    }

    #[test]
    fn the_tail_past_ram_is_whole_blocks_above_the_end() {
        // QEMU raspi3b: /memory = 0..0x3C00_0000, 2 MiB blocks at 4 KiB.
        assert_eq!(boot_tail_blocks(GRANULE_4K, 0, 0x3C00_0000), (480, 32));
        // QEMU virt, 128 MiB at 1 GiB: block indices are within the gigabyte's L2.
        assert_eq!(boot_tail_blocks(GRANULE_4K, GIB, GIB + 128 * MIB), (64, 448));
        // A block that holds the end of RAM stays RAM.
        assert_eq!(boot_tail_blocks(GRANULE_4K, 0, 0x3C00_0001), (481, 31));
        // RAM fills the window, or the end is outside it: nothing.
        assert_eq!(boot_tail_blocks(GRANULE_4K, 0, GIB).1, 0);
        assert_eq!(boot_tail_blocks(GRANULE_4K, GIB, GIB).1, 0);
        // Never the first block (the image's, under the level-3 table).
        assert_eq!(boot_tail_blocks(GRANULE_4K, 0, 4096), (1, 511));
        // 16 KiB: 32 MiB blocks, in root slot 0 with the device gigabyte.
        assert_eq!(boot_tail_blocks(GRANULE_16K, 0, 0x3C00_0000), (30, 2));
        // 64 KiB: a 512 MiB block holds the end of RAM, nothing is left over.
        assert_eq!(boot_tail_blocks(GRANULE_64K, 0, 0x3C00_0000).1, 0);
    }
}

#[cfg(test)]
mod sv39 {
    use super::mmu::*;

    /// Sv39 splits a 39-bit VA into three 9-bit page-table indices and a
    /// 12-bit offset. The test address gives each field a **distinct** value,
    /// so a copy-paste shift error cannot pass by coincidence — which is
    /// exactly what a test using 0 or an all-ones address would allow.
    #[test]
    fn vpn_fields_are_the_bits_the_spec_names() {
        //   VPN[2]=0x123 (bits 38:30), VPN[1]=0x0AB (29:21),
        //   VPN[0]=0x1C4 (20:12), offset=0xDEF (11:0)
        let va = (0x123usize << 30) | (0x0AB << 21) | (0x1C4 << 12) | 0xDEF;
        assert_eq!(vpn2(va), 0x123, "VPN[2] is bits 38:30");
        assert_eq!(vpn1(va), 0x0AB, "VPN[1] is bits 29:21");
        assert_eq!(vpn0(va), 0x1C4, "VPN[0] is bits 20:12");
    }

    /// Each field is 9 bits and must not bleed into its neighbours. Bits above
    /// 38 belong to the sign extension, not to VPN[2]: an unmasked shift would
    /// return them and index past a 512-entry table.
    #[test]
    fn vpn_fields_mask_to_nine_bits() {
        let all = usize::MAX;
        assert_eq!(vpn2(all), 0x1FF);
        assert_eq!(vpn1(all), 0x1FF);
        assert_eq!(vpn0(all), 0x1FF);
        assert!(vpn2(all) < PT_ENTRIES, "VPN[2] must index a 512-entry table");
    }

    /// `satp` for Sv39: MODE=8 in bits [63:60], ASID in [59:44], PPN in
    /// [43:0]. Wrong placement does not fail loudly — the MMU either stays off
    /// (MODE=0) or walks from the wrong root, and both look like "the kernel
    /// hangs early".
    #[test]
    fn satp_places_mode_asid_and_ppn_where_the_spec_says() {
        let root = 0x8020_1000usize;      // page-aligned physical root
        let satp = make_satp(root, 0xBEEF);
        assert_eq!(satp >> 60, 8, "MODE must be 8 (Sv39)");
        assert_eq!((satp >> 44) & 0xFFFF, 0xBEEF, "ASID is bits 59:44");
        assert_eq!(satp & 0xFFF_FFFF_FFFF, root >> 12, "PPN is the root >> 12");
        // ASID 0 is the common case and must not disturb the other fields.
        let s0 = make_satp(root, 0);
        assert_eq!(s0 >> 60, 8);
        assert_eq!((s0 >> 44) & 0xFFFF, 0);
    }

    /// Page rounding, including the two cases that are always wrong when this
    /// is written from memory: an already-aligned address must not be pushed
    /// to the next page, and 0 must stay 0.
    #[test]
    fn page_rounding_is_idempotent_on_aligned_addresses() {
        assert_eq!(page_align_up(0), 0);
        assert_eq!(page_align_up(0x1000), 0x1000, "aligned must not advance");
        assert_eq!(page_align_up(0x1001), 0x2000);
        assert_eq!(page_align_up(0xFFF), 0x1000);
        assert_eq!(page_align_down(0x1FFF), 0x1000);
        assert_eq!(page_align_down(0x1000), 0x1000);
        assert!(is_page_aligned(0x2000));
        assert!(!is_page_aligned(0x2001));
    }
}

/// Svpbmt: the PBMT field is outside the PPN, and is emitted only after the
/// boot selected the extension.
#[cfg(test)]
mod svpbmt {
    use super::mmu::*;

    /// Svpbmt state is one process-wide atomic: one test body, in order.
    #[test]
    fn pbmt_is_inert_until_selected_and_never_leaks_into_the_address() {
        assert!(!svpbmt_on());
        assert_eq!(pbmt_bits(true, false), 0, "off: plain PTE");
        assert_eq!(pbmt_bits(false, true), 0, "off: plain PTE");
        assert!(!svpbmt_select(true, false), "the DT lacks it");
        assert!(!svpbmt_select(false, true), "Kconfig says never");
        assert_eq!(pbmt_bits(true, false), 0);
        assert!(svpbmt_select(true, true));
        assert_eq!(pbmt_bits(true, false), 1 << 61, "NC = 01");
        assert_eq!(pbmt_bits(false, true), 1 << 62, "IO = 10");
        assert_eq!(pbmt_bits(false, false), 0, "WB = the PMA's type");
        // The field sits above the PPN: the address survives it.
        let f = PteFlags::VALID | PteFlags::READ | PteFlags::WRITE | PteFlags::PBMT_NC;
        let p = Pte::new(0x8765_4000, f);
        assert_eq!(p.phys_addr(), 0x8765_4000);
        assert!(p.flags().contains(PteFlags::PBMT_NC) && !p.flags().contains(PteFlags::PBMT_IO));
        // A COW share-style rebuild keeps the type.
        let q = Pte::new(p.phys_addr(), p.flags() - PteFlags::WRITE);
        assert!(q.flags().contains(PteFlags::PBMT_NC));
        svpbmt_select(false, false);
    }
}

/// Svadu (Kconfig `RV_SVADU`): the A bit page aging clears is PTE bit 6, and
/// the switch is on only when the policy and the device tree both say so.
#[cfg(test)]
mod svadu {
    use super::mmu::*;

    /// One process-wide atomic: one test body, in order.
    #[test]
    fn hardware_a_is_off_until_selected_and_a_is_bit_6() {
        assert_eq!(PteFlags::ACCESSED.bits(), 1 << 6);
        assert!(!svadu_on());
        assert!(!svadu_select(true, false), "the DT lacks it");
        assert!(!svadu_select(false, true), "Kconfig says never");
        assert!(!svadu_on());
        assert!(svadu_select(true, true));
        assert!(svadu_on());
        svadu_select(false, false);
    }
}

// Ssqosid (Kconfig `RV_SSQOSID`): the real `srmcfg` module, pulled in by path
// (its asm is riscv64-only and compiles out here).
#[allow(dead_code)]
#[path = "../../../../crates/core/arch-riscv64/src/ext/ssqosid.rs"]
mod ssqosid;

/// Ssqosid: the field widths come from a write-ones read-back, the word is
/// RCID = MCID = partition, a partition that does not fit RCID is refused
/// (never masked), and nothing runs under `n` or without the device tree's
/// token.
#[cfg(test)]
mod ssqosid_tests {
    use super::ssqosid::*;
    use std::cell::Cell;

    #[test]
    fn the_csr_and_the_field_widths() {
        assert_eq!(SRMCFG, 0x181);
        // Full 12-bit fields: the QEMU-style answer.
        assert_eq!(widths_from_readback(0x0FFF_0FFF), (0xFFF, 0xFFF));
        // A narrower RCID (6 bits) and MCID (4 bits).
        assert_eq!(widths_from_readback(0x000F_003F), (0x3F, 0xF));
        // Nothing sticks: only RCID/MCID 0 exist.
        assert_eq!(widths_from_readback(0), (0, 0));
        // Bits outside the fields (15:12, 31:28) are not widths.
        assert_eq!(widths_from_readback(0xF000_F000), (0, 0));
        // A field that is not one run from bit 0 is not trusted.
        assert_eq!(widths_from_readback(0x0005_0005), (0, 0));
    }

    #[test]
    fn the_word_is_rcid_and_mcid_both_the_partition() {
        assert_eq!(word(0, 0xFFF, 0xFFF), Some(0));
        assert_eq!(word(7, 0xFFF, 0xFFF), Some(0x0007_0007));
        assert_eq!(word(0xFFF, 0xFFF, 0xFFF), Some(0x0FFF_0FFF));
        // Above RCID: refused, not masked to partition 0x001 (0x1001 & 0xFFF).
        assert_eq!(word(0x1001, 0xFFF, 0xFFF), None);
        assert_eq!(word(65535, 0xFFF, 0xFFF), None);
        assert_eq!(word(8, 7, 7), None, "one past the narrower RCID");
        // Fits RCID, not MCID: isolation kept, monitoring under MCID 0.
        assert_eq!(word(9, 0xF, 3), Some(9));
        assert_eq!(word(3, 0xF, 3), Some(0x0003_0003));
    }

    /// One process-wide pair of atomics: one test body, in order.
    #[test]
    fn selection_probes_only_when_policy_and_device_tree_allow() {
        let ran = Cell::new(0);
        let probe = |v: Option<usize>| { ran.set(ran.get() + 1); v };
        // n, or no `ssqosid` in cpu@0: the CSR is never touched.
        assert!(!select(false, true, || probe(Some(0x0FFF_0FFF))));
        assert!(!select(true, false, || probe(Some(0x0FFF_0FFF))));
        assert_eq!(ran.get(), 0, "no probe run");
        assert!(!available() && max_partition() == 0);
        assert!(!set_tag(0) && !set_tag(1), "not in use: nothing to write");
        // The access traps: absent.
        assert!(!select(true, true, || probe(None)));
        assert_eq!(ran.get(), 1);
        assert!(!available());
        // It answers: in use, up to the implemented RCID.
        assert!(select(true, true, || probe(Some(0x000F_003F))));
        assert!(available());
        assert_eq!(max_partition(), 0x3F);
        assert!(set_tag(0x3F), "fits");
        assert!(!set_tag(0x40), "one past RCID: refused");
        // A hart that stuck nothing is not partitionable.
        assert!(!select(true, true, || probe(Some(0))));
        assert!(!available());
        // Back to off for any later test in the process.
        select(false, false, || None);
    }
}

#[cfg(test)]
mod pmp_encoding {
    use super::pmp::*;

    /// TOR entries encode the **exclusive upper bound**, shifted right by 2
    /// because `pmpaddr` addresses 4-byte units. Forgetting the shift makes
    /// every region four times too large — which protects nothing and fails
    /// nowhere.
    #[test]
    fn tor_encodes_the_exclusive_end_over_four() {
        let r = PmpRegion { name: "t", base: 0x8000_0000, size: 0x1000,
                            perm: PmpPerm::RW, mode: PmpMode::Tor, locked: false };
        assert_eq!(r.tor_addr(), (0x8000_0000usize + 0x1000) >> 2);
    }

    /// NAPOT packs the size into the trailing ones of the address:
    /// `(base >> 2) | (size/8 - 1)`. The classic error is `size/4` or
    /// `size/8` without the `-1`, either of which encodes the wrong power of
    /// two — silently, and in the direction of a larger region.
    #[test]
    fn napot_packs_the_size_into_trailing_ones() {
        for shift in 3..20u32 {                 // 8 B .. 512 KiB
            let size = 1usize << shift;
            let base = 0x8000_0000usize;        // aligned to anything in range
            let r = PmpRegion { name: "n", base, size,
                                perm: PmpPerm::RW, mode: PmpMode::Napot, locked: false };
            let a = r.napot_addr();
            assert_eq!(a, (base >> 2) | ((size / 8) - 1), "size {size}");
            // The encoded region must be exactly `size` bytes: the number of
            // trailing ones determines it, so count them and check.
            let ones = (!a).trailing_zeros();
            assert_eq!(1usize << (ones + 3), size,
                       "NAPOT for {size} decodes to a different size");
        }
    }

    /// The regions are TOR, and **TOR takes its lower bound from the previous
    /// entry's `pmpaddr`**. A gap between one region's end and the next one's
    /// base is therefore not an unmapped hole — it is silently absorbed into
    /// the next region, with the next region's permissions. This is the
    /// property that makes the table correct, and nothing else checks it.
    #[test]
    fn tor_regions_are_contiguous_with_no_gaps() {
        let rs = pmp_regions(0x8000_0000, 0x8020_0000, 0x8040_0000, 0x0020_0000);
        for w in rs.windows(2) {
            let end = w[0].base + w[0].size;
            // The MMIO entry deliberately restarts at a lower base; every
            // other boundary must join exactly.
            if w[1].base < end { continue; }
            assert_eq!(w[1].base, end,
                       "gap between {:?} and {:?}: {:#x}..{:#x}",
                       w[0].name, w[1].name, end, w[1].base);
        }
    }

    /// Every region must be non-empty. A zero-size TOR entry encodes an upper
    /// bound equal to the previous one, which the hardware reads as a region
    /// covering nothing — so the range it was meant to protect falls through
    /// to the next entry.
    #[test]
    fn no_region_is_empty() {
        let rs = pmp_regions(0x8000_0000, 0x8020_0000, 0x8040_0000, 0x0020_0000);
        for r in rs.iter() {
            assert!(r.size > 0, "region {:?} has zero size", r.name);
        }
    }
}

// x86_64: which FS base a context switch writes, and which values a task may
// be given (`wrmsr` of a non-canonical one is a #GP in the kernel): `cpu`'s
// pure functions, included above.


#[cfg(test)]
mod x86_64_tls_tests {
    use super::cpu::{fs_base_to_load, is_user_tls_base};

    /// **Canary.** Make `fs_base_to_load` always `Some`: the equal case goes
    /// red. Make it always `None`: the differing cases go red.
    #[test]
    fn a_switch_writes_the_fs_base_only_when_it_differs() {
        assert_eq!(fs_base_to_load(0, 0), None);
        assert_eq!(fs_base_to_load(0x7000_1000, 0x7000_1000), None);
        assert_eq!(fs_base_to_load(0, 0x7000_1000), Some(0x7000_1000));
        // Back to a task without a thread pointer: the base is cleared, not
        // left at the previous task's.
        assert_eq!(fs_base_to_load(0x7000_1000, 0), Some(0));
        assert_eq!(fs_base_to_load(0x7000_1000, 0x7000_2000), Some(0x7000_2000));
    }

    /// **Canary.** Accept `1 << 47`: the kernel-half case goes red.
    #[test]
    fn a_thread_pointer_is_a_user_half_address() {
        assert!(is_user_tls_base(0));
        assert!(is_user_tls_base((1 << 47) - 1));
        assert!(!is_user_tls_base(1 << 47));
        assert!(!is_user_tls_base(0xFFFF_8000_0000_0000));
        assert!(!is_user_tls_base(u64::MAX));
    }
}

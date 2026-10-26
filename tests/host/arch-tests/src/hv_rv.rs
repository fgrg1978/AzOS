// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host tests of the riscv64 H-extension primitives
//! (`arch/riscv64/src/ext/hv/`): the G-stage PTE encoder and
//! table builder, the CSR addresses and save/restore lists, the guest frame
//! layout the entry assembly indexes, and the VM-exit decode.
//!
//! WHY. Every one of these is a bit position or an offset, and a wrong one is
//! silent until a guest runs: a missing `U` on a G-stage leaf is a guest page
//! fault on every access; a 9-bit root index aliases the top three quarters
//! of the guest-physical space onto the bottom quarter; a CSR number off by
//! one saves the neighbouring register. No guest runs before S6 (QEMU
//! `-cpu rv64,h=true`), so these are the only check until then.
//!
//! The expected values are written out from the privileged spec 1.12 here,
//! not derived from the constants under test.

#[allow(dead_code)]
#[path = "../../../../arch/riscv64/src/ext/hv/mod.rs"]
mod hv;

// The IMSIC driver's pure half (layout, selectors); its CSR half is
// riscv64-only.
#[allow(dead_code)]
#[path = "../../../../arch/riscv64/src/irq/imsic.rs"]
mod imsic;

#[cfg(test)]
mod csr_numbers {
    use super::hv::{csr, vscsr};

    /// The addresses of the spec's CSR table (Table "Hypervisor and VS CSRs").
    #[test]
    fn the_addresses_are_the_specs() {
        let spec: &[(u16, u16)] = &[
            (csr::HSTATUS, 0x600), (csr::HEDELEG, 0x602), (csr::HIDELEG, 0x603),
            (csr::HIE, 0x604), (csr::HTIMEDELTA, 0x605), (csr::HCOUNTEREN, 0x606),
            (csr::HGEIE, 0x607), (csr::HENVCFG, 0x60A), (csr::HTVAL, 0x643),
            (csr::HIP, 0x644), (csr::HVIP, 0x645), (csr::HTINST, 0x64A),
            (csr::HGATP, 0x680), (csr::HGEIP, 0xE12), (csr::HSTATEEN0, 0x60C),
            (csr::VSISELECT, 0x250), (csr::VSIREG, 0x251),
            (csr::VSSTATUS, 0x200), (csr::VSIE, 0x204), (csr::VSTVEC, 0x205),
            (csr::VSSCRATCH, 0x240), (csr::VSEPC, 0x241), (csr::VSCAUSE, 0x242),
            (csr::VSTVAL, 0x243), (csr::VSIP, 0x244), (csr::VSTIMECMP, 0x24D),
            (csr::VSATP, 0x280), (csr::SCOUNTEREN, 0x106), (csr::SENVCFG, 0x10A),
        ];
        for (got, want) in spec {
            assert_eq!(got, want);
        }
        // A VS CSR is its S counterpart + 0x100 (the spec's mapping rule):
        // sstatus 0x100, sie 0x104, stvec 0x105, sscratch 0x140, sepc 0x141,
        // scause 0x142, stval 0x143, sip 0x144, stimecmp 0x14D, satp 0x180.
        for (vs, s) in [(csr::VSSTATUS, 0x100), (csr::VSIE, 0x104), (csr::VSTVEC, 0x105),
                        (csr::VSSCRATCH, 0x140), (csr::VSEPC, 0x141), (csr::VSCAUSE, 0x142),
                        (csr::VSTVAL, 0x143), (csr::VSIP, 0x144), (csr::VSTIMECMP, 0x14D),
                        (csr::VSATP, 0x180), (csr::VSISELECT, 0x150), (csr::VSIREG, 0x151)] {
            assert_eq!(vs, s + 0x100);
        }
    }

    #[test]
    fn the_bit_fields_are_the_specs() {
        assert_eq!(csr::HSTATUS_GVA, 1 << 6);
        assert_eq!(csr::HSTATUS_SPV, 1 << 7);
        assert_eq!(csr::HSTATUS_SPVP, 1 << 8);
        assert_eq!(csr::HSTATUS_VTVM, 1 << 20);
        assert_eq!(csr::HSTATUS_VTW, 1 << 21);
        assert_eq!(csr::HSTATUS_VTSR, 1 << 22);
        // AIA: VGEIN is hstatus[17:12].
        assert_eq!((csr::HSTATUS_VGEIN_SHIFT, csr::HSTATUS_VGEIN), (12, 0x3F000));
        // Smstateen / AIA: hstateen0 bits 58 IMSIC, 59 AIA, 60 ISEL, 62 ENVCFG.
        assert_eq!((csr::HSTATEEN0_IMSIC, csr::HSTATEEN0_AIA), (1 << 58, 1 << 59));
        assert_eq!((csr::HSTATEEN0_ISEL, csr::HSTATEEN0_ENVCFG), (1 << 60, 1 << 62));
        assert_eq!((csr::VSSIP, csr::VSTIP, csr::VSEIP), (1 << 2, 1 << 6, 1 << 10));
        assert_eq!(csr::HENVCFG_STCE, 1 << 63);
        assert_eq!(csr::HGATP_VMID_MASK, 0x3FFFu64 << 44);
        assert_eq!(csr::HGATP_PPN_MASK, (1u64 << 44) - 1);
        assert_eq!((csr::HGATP_MODE_SV39X4, csr::HGATP_MODE_SV48X4), (8, 9));
    }

    /// Guest page faults (20, 21, 23), the VS ecall (10) and the virtual
    /// instruction trap (22) cannot be delegated to the guest: the exits the
    /// monitor exists to see. `hedeleg` bits that are hardwired zero would
    /// make a write of them harmless, but delegating the faults would hide them.
    #[test]
    fn the_guest_delegation_keeps_the_monitors_exits() {
        for cause in [9u32, 10, 11, 20, 21, 22, 23] {
            assert_eq!(csr::HEDELEG_GUEST & (1 << cause), 0, "cause {cause} is delegated");
        }
        for cause in [0u32, 3, 8, 12, 13, 15] {
            assert_ne!(csr::HEDELEG_GUEST & (1 << cause), 0, "cause {cause} is not delegated");
        }
        assert_eq!(csr::HIDELEG_GUEST, (1 << 2) | (1 << 6) | (1 << 10));
    }

    #[test]
    fn the_save_list_covers_the_struct_once_with_the_right_addresses() {
        let list = vscsr::VS_CSR_LIST;
        assert_eq!(list.len() * 8, core::mem::size_of::<vscsr::VsCsrs>());
        for (i, s) in list.iter().enumerate() {
            assert_eq!(s.word, i, "{} is not in field order", s.name);
        }
        use vscsr::Needs::{Always, Aia, Sstc};
        let want: &[(&str, u16, vscsr::Needs)] = &[
            ("vsstatus", 0x200, Always), ("vsie", 0x204, Always), ("vstvec", 0x205, Always),
            ("vsscratch", 0x240, Always), ("vsepc", 0x241, Always), ("vscause", 0x242, Always),
            ("vstval", 0x243, Always), ("vsatp", 0x280, Always),
            ("scounteren", 0x106, Always), ("senvcfg", 0x10A, Always), ("hvip", 0x645, Always),
            ("vstimecmp", 0x24D, Sstc), ("vsiselect", 0x250, Aia),
        ];
        assert_eq!(list.len(), want.len());
        for (s, (name, addr, needs)) in list.iter().zip(want) {
            assert_eq!((s.name, s.addr, s.needs), (*name, *addr, *needs));
        }
        // `vsip` is derived from `hvip` and `vsie`, not saved on its own.
        assert!(list.iter().all(|s| s.addr != csr::VSIP));
        for (i, a) in list.iter().enumerate() {
            for b in &list[i + 1..] {
                assert_ne!(a.addr, b.addr);
            }
        }
    }

    #[test]
    fn a_vm_gets_the_usual_control_set() {
        let sstc = vscsr::Caps { sstc: true, ..Default::default() };
        let c = vscsr::VmCtl::new(0x8000_0000_0000_1234, 77, sstc);
        assert_eq!(c.henvcfg, 1 << 63);
        assert_eq!(c.hcounteren, 1 << 1);
        assert_eq!(c.htimedelta, 77);
        assert_eq!(c.hgatp, 0x8000_0000_0000_1234);
        assert_eq!(c.hstateen0, None, "no Smstateen, nothing to write");
        assert_eq!(vscsr::VmCtl::new(0, 0, vscsr::Caps::default()).henvcfg, 0, "no Sstc, no STCE");
    }

    /// The optional slots are saved only where the hart has them, and a new
    /// vCPU's timer is never due (a zero `vstimecmp` is a deadline in the past).
    #[test]
    fn optional_slots_follow_the_caps_and_a_new_timer_never_fires() {
        use vscsr::{Caps, Needs};
        let none = Caps::default();
        let all = Caps { sstc: true, smstateen: true, aia: true, guest_file: true };
        for n in [Needs::Sstc, Needs::Aia] {
            assert!(!none.has(n) && all.has(n));
        }
        assert!(none.has(Needs::Always));
        assert!(Caps { sstc: true, ..none }.has(Needs::Sstc) && !Caps { sstc: true, ..none }.has(Needs::Aia));
        assert!(Caps { aia: true, ..none }.has(Needs::Aia) && !Caps { aia: true, ..none }.has(Needs::Sstc));
        assert_eq!(vscsr::VsCsrs::reset().vstimecmp, u64::MAX);
        assert_eq!(vscsr::VsCsrs { vstimecmp: 0, ..vscsr::VsCsrs::reset() }, vscsr::VsCsrs::default());
    }

    /// `hstateen0`: the guest's `senvcfg` always, the AIA state only for a
    /// vCPU with a file (so a PLIC guest cannot reach an interrupt file
    /// it was not given), nothing at all without Smstateen. The bit numbers
    /// are the Smstateen and AIA tables'.
    #[test]
    fn hstateen0_grants_the_aia_only_with_a_file() {
        use vscsr::Caps;
        let base = Caps { smstateen: true, aia: true, ..Caps::default() };
        assert_eq!(base.hstateen0(), Some(1 << 62));
        assert_eq!(Caps { guest_file: true, ..base }.hstateen0(), Some(1 << 62 | 1 << 60 | 1 << 59 | 1 << 58));
        assert_eq!(Caps { guest_file: true, aia: true, ..Caps::default() }.hstateen0(), None);
        let c = vscsr::VmCtl::new(0, 0, Caps { guest_file: true, ..base });
        assert_eq!(c.hstateen0, Some(csr::HSTATEEN0_ENVCFG | csr::HSTATEEN0_IMSIC | csr::HSTATEEN0_AIA | csr::HSTATEEN0_ISEL));
    }
}

#[cfg(test)]
mod gstage_pte {
    use super::hv::gstage::*;

    const HPA: u64 = 0x0012_3456_7000;

    #[test]
    fn a_leaf_is_valid_user_accessed_and_dirty_only_when_writable() {
        let ro = leaf_pte(HPA, GPerms::RO);
        assert_eq!(ro & 0x3FF, PTE_V | PTE_R | PTE_U | PTE_A, "RO leaf low bits {:#x}", ro & 0x3FF);
        let rw = leaf_pte(HPA, GPerms::RW);
        assert_eq!(rw & 0x3FF, PTE_V | PTE_R | PTE_W | PTE_U | PTE_A | PTE_D);
        let rx = leaf_pte(HPA, GPerms::RX);
        assert_eq!(rx & 0x3FF, PTE_V | PTE_R | PTE_X | PTE_U | PTE_A);
        let x = leaf_pte(HPA, GPerms::X);
        assert_eq!(x & 0x3FF, PTE_V | PTE_X | PTE_U | PTE_A);
        for p in [ro, rw, rx, x] {
            assert_eq!(p & PTE_G, 0, "G is reserved in G-stage");
            assert_eq!(pte_pa(p), HPA);
            assert!(pte_is_leaf(p) && pte_valid(p));
        }
    }

    /// Non-leaf PTEs keep U, A, D clear (reserved) and the PPN in 53:10.
    #[test]
    fn a_table_pointer_is_only_valid_and_the_address() {
        let t = table_pte(0x8020_4000);
        assert_eq!(t & 0x3FF, PTE_V);
        assert_eq!(t >> 10, 0x8020_4000 >> 12);
        assert!(!pte_is_leaf(t));
        assert_eq!(pte_pa(t), 0x8020_4000);
    }

    #[test]
    fn rights_the_spec_reserves_cannot_be_built() {
        assert_eq!(GPerms::new(false, false, false), None, "empty reads as a table pointer");
        assert_eq!(GPerms::new(false, true, false), None, "W without R is reserved");
        assert_eq!(GPerms::new(false, true, true), None);
        assert_eq!(GPerms::new(true, true, true), Some(GPerms::RWX));
        assert_eq!(GPerms::new(false, false, true), Some(GPerms::X));
        // A PTE with a reserved combination decodes to no rights.
        assert_eq!(pte_perms(PTE_V | PTE_W | PTE_U), None);
        assert_eq!(pte_perms(leaf_pte(HPA, GPerms::RX)), Some(GPerms::RX));
        assert!(GPerms::RX.allows(Access::Fetch) && !GPerms::RX.allows(Access::Store));
        assert!(GPerms::X.allows(Access::Fetch) && !GPerms::X.allows(Access::Load));
    }

    #[test]
    fn the_modes_have_the_spec_geometry() {
        assert_eq!(Mode::Sv39x4.hgatp_mode(), 8);
        assert_eq!(Mode::Sv48x4.hgatp_mode(), 9);
        assert_eq!(Mode::Sv39x4.gpa_bits(), 41);
        assert_eq!(Mode::Sv48x4.gpa_bits(), 50);
        assert_eq!(Mode::from_hgatp_mode(8), Some(Mode::Sv39x4));
        assert_eq!(Mode::from_hgatp_mode(0), None);
        assert_eq!(Mode::from_hgatp_mode(10), None, "Sv57x4 is not built");
        assert_eq!(PageSize::K4.bytes(), 4096);
        assert_eq!(PageSize::M2.bytes(), 2 << 20);
        assert_eq!(PageSize::G1.bytes(), 1 << 30);
        assert_eq!(PageSize::G512.bytes(), 1 << 39);
    }

    #[test]
    fn the_fence_encodings_are_the_specs() {
        // hfence.gvma x0,x0 / a0,a1 and hfence.vvma x0,x0.
        assert_eq!(HFENCE_GVMA, 0x6200_0073);
        assert_eq!(hfence_gvma_word(0, 0), 0x6200_0073);
        assert_eq!(hfence_gvma_word(10, 11), 0x62B5_0073);
        assert_eq!(hfence_gvma_word(0, 11), 0x62B0_0073);
        assert_eq!(HFENCE_VVMA, 0x2200_0073);
    }
}

#[cfg(test)]
mod gstage_tables {
    use super::hv::gstage::*;
    use std::collections::HashMap;

    /// Simulated physical memory for page tables: each table a Vec keyed by
    /// its base. An index past the table's length panics, which is how a
    /// 9-bit root (or an 11-bit interior) index shows up.
    struct Sim {
        tables: HashMap<u64, Vec<u64>>,
        next: u64,
        budget: usize,
    }

    impl Sim {
        fn new() -> Sim {
            Sim { tables: HashMap::new(), next: 0x8000_0000, budget: usize::MAX }
        }
        fn live_pages(&self) -> usize {
            self.tables.values().map(|t| t.len() / 512).sum()
        }
    }

    impl TableMem for Sim {
        fn alloc(&mut self, pages: usize) -> Option<u64> {
            if self.budget < pages {
                return None;
            }
            self.budget -= pages;
            let align = pages as u64 * 4096;
            self.next = (self.next + align - 1) & !(align - 1);
            let pa = self.next;
            self.next += align;
            self.tables.insert(pa, vec![0; pages * 512]);
            Some(pa)
        }
        fn free(&mut self, pa: u64, pages: usize) {
            let t = self.tables.remove(&pa).expect("free of a table that is not live");
            assert_eq!(t.len(), pages * 512, "freed with the wrong size");
        }
        fn read(&self, table: u64, index: usize) -> u64 {
            self.tables[&table][index]
        }
        fn write(&mut self, table: u64, index: usize, pte: u64) {
            self.tables.get_mut(&table).unwrap()[index] = pte;
        }
    }

    fn gs(mem: &mut Sim, mode: Mode) -> GStage {
        GStage::new(mem, mode).unwrap()
    }

    #[test]
    fn the_root_is_sixteen_kib_and_hgatp_points_at_it() {
        let mut m = Sim::new();
        let g = gs(&mut m, Mode::Sv39x4);
        assert_eq!(g.root() % 16384, 0);
        assert_eq!(m.tables[&g.root()].len(), 2048);
        let h = g.hgatp(0x2ABC);
        assert_eq!(h >> 60, 8);
        assert_eq!((h >> 44) & 0x3FFF, 0x2ABC);
        assert_eq!(h & ((1 << 44) - 1), g.root() >> 12);
        assert_eq!((h & ((1 << 44) - 1)) & 3, 0, "root PPN low two bits are zero");
        // A VMID wider than 14 bits is cut, not spilled into MODE or PPN.
        let wide = g.hgatp(0xFFFF);
        assert_eq!(wide >> 60, 8);
        assert_eq!(wide & ((1 << 44) - 1), g.root() >> 12);
        let g48 = gs(&mut m, Mode::Sv48x4);
        assert_eq!(g48.hgatp(0) >> 60, 9);
    }

    #[test]
    fn a_page_maps_walks_and_unmaps() {
        let mut m = Sim::new();
        let g = gs(&mut m, Mode::Sv39x4);
        g.map(&mut m, 0x8000_0000, 0x4_0000_0000, PageSize::K4, GPerms::RW).unwrap();
        let t = g.walk(&m, 0x8000_0123).unwrap();
        assert_eq!((t.hpa, t.perms, t.size), (0x4_0000_0123, GPerms::RW, PageSize::K4));
        assert_eq!(g.walk(&m, 0x8000_1000), None, "the next page is not mapped");
        assert_eq!(g.map(&mut m, 0x8000_0000, 0x5_0000_0000, PageSize::K4, GPerms::RO),
                   Err(MapError::AlreadyMapped));
        assert_eq!(g.unmap(&mut m, 0x8000_0000, PageSize::K4), Ok(0x4_0000_0000));
        assert_eq!(g.walk(&m, 0x8000_0000), None);
        assert_eq!(g.unmap(&mut m, 0x8000_0000, PageSize::K4), Err(MapError::NotMapped));
    }

    /// The root has 2048 entries: guest-physical bits 40:30 index it in
    /// Sv39x4. With a 9-bit index the top quarter of the space would alias
    /// the bottom (or index past the table, which `Sim` turns into a panic).
    #[test]
    fn the_root_index_is_eleven_bits() {
        let mut m = Sim::new();
        let g = gs(&mut m, Mode::Sv39x4);
        let lo = 0x4000_0000u64;                      // root index 1
        let hi = lo + (1u64 << 39);                    // root index 1 + 512: aliases `lo` at 9 bits
        g.map(&mut m, lo, 0x1_0000_0000, PageSize::G1, GPerms::RW).unwrap();
        g.map(&mut m, hi, 0x2_0000_0000, PageSize::G1, GPerms::RW).unwrap();
        assert_eq!(g.walk(&m, lo + 5).unwrap().hpa, 0x1_0000_0005);
        assert_eq!(g.walk(&m, hi + 5).unwrap().hpa, 0x2_0000_0005);
        let top = (1u64 << 41) - (1 << 30);           // root index 2047
        g.map(&mut m, top, 0x3_0000_0000, PageSize::G1, GPerms::RO).unwrap();
        assert_eq!(g.walk(&m, top).unwrap().hpa, 0x3_0000_0000);
        assert_eq!(g.map(&mut m, 1 << 41, 0, PageSize::K4, GPerms::RW), Err(MapError::OutOfRange));
        assert_eq!(g.walk(&m, 1 << 41), None);
    }

    #[test]
    fn sv48x4_has_four_levels_and_a_wider_root() {
        let mut m = Sim::new();
        let g = gs(&mut m, Mode::Sv48x4);
        let gpa = (0x7FFu64 << 39) | (0x155 << 30) | (0x0AA << 21) | (0x033 << 12);
        g.map(&mut m, gpa, 0x6_0000_1000, PageSize::K4, GPerms::RX).unwrap();
        assert_eq!(g.walk(&m, gpa | 0xFFF).unwrap().hpa, 0x6_0000_1FFF);
        assert_eq!(m.live_pages(), 4 + 3, "a 16 KiB root and three interior tables");
        g.map(&mut m, 5u64 << 39, 0x8_0000_0000_00, PageSize::G512, GPerms::RW).unwrap();
        assert_eq!(g.walk(&m, (5u64 << 39) + 0x1234_5678).unwrap().size, PageSize::G512);
        assert_eq!(g.map(&mut m, 1 << 50, 0, PageSize::K4, GPerms::RW), Err(MapError::OutOfRange));
    }

    #[test]
    fn a_512g_leaf_does_not_exist_in_sv39x4() {
        let mut m = Sim::new();
        let g = gs(&mut m, Mode::Sv39x4);
        assert_eq!(g.map(&mut m, 0, 0, PageSize::G512, GPerms::RW), Err(MapError::BadSize));
        assert_eq!(g.unmap(&mut m, 0, PageSize::G512), Err(MapError::BadSize));
    }

    #[test]
    fn leaves_must_be_aligned_to_their_size() {
        let mut m = Sim::new();
        let g = gs(&mut m, Mode::Sv39x4);
        assert_eq!(g.map(&mut m, 0x20_1000, 0x4000_0000, PageSize::M2, GPerms::RW),
                   Err(MapError::Misaligned), "gpa");
        assert_eq!(g.map(&mut m, 0x20_0000, 0x4000_1000, PageSize::M2, GPerms::RW),
                   Err(MapError::Misaligned), "hpa");
        assert_eq!(g.map(&mut m, 0x20_0000, 1 << 56, PageSize::M2, GPerms::RW),
                   Err(MapError::OutOfRange), "hpa beyond 56 bits");
        assert_eq!(m.live_pages(), 4, "a refused map allocated nothing");
    }

    #[test]
    fn a_superpage_and_pages_under_it_overlap() {
        let mut m = Sim::new();
        let g = gs(&mut m, Mode::Sv39x4);
        g.map(&mut m, 0x20_0000, 0x4000_0000, PageSize::M2, GPerms::RW).unwrap();
        assert_eq!(g.map(&mut m, 0x20_1000, 0x5000_0000, PageSize::K4, GPerms::RW),
                   Err(MapError::Overlap), "a 4K inside a 2M leaf");
        let t = g.walk(&m, 0x2F_FFFF).unwrap();
        assert_eq!((t.hpa, t.size), (0x4000_0000 + 0xF_FFFF, PageSize::M2));
        g.map(&mut m, 0x60_1000, 0x5000_0000, PageSize::K4, GPerms::RW).unwrap();
        assert_eq!(g.map(&mut m, 0x60_0000, 0x6000_0000, PageSize::M2, GPerms::RW),
                   Err(MapError::Overlap), "a 2M over a table of pages");
        assert_eq!(g.unmap(&mut m, 0x20_1000, PageSize::K4), Err(MapError::Overlap));
        assert_eq!(g.unmap(&mut m, 0x20_0000, PageSize::M2), Ok(0x4000_0000));
    }

    #[test]
    fn a_range_takes_the_largest_leaf_alignment_and_length_allow() {
        let mut m = Sim::new();
        let g = gs(&mut m, Mode::Sv39x4);
        // gpa = hpa = 1 GiB - 8 KiB, length 1 GiB + 4 MiB + 16 KiB: two 4K
        // pages up to the 1G boundary, then one 1G, then two 2M, then four 4K.
        let base = (1u64 << 30) - 0x2000;
        let len = (1u64 << 30) + (4 << 20) + 0x4000 + 0x2000;
        g.map_range(&mut m, base, base, len, GPerms::RW, PageSize::G1).unwrap();
        let mut sizes = Vec::new();
        let mut a = base;
        while a < base + len {
            let t = g.walk(&m, a).expect("hole in the range");
            assert_eq!(t.hpa, a);
            sizes.push(t.size);
            a = (a & !(t.size.bytes() - 1)) + t.size.bytes();
        }
        use PageSize::*;
        assert_eq!(sizes, [K4, K4, G1, M2, M2, K4, K4, K4, K4]);
        assert!(g.walk(&m, base + len).is_none(), "past the end");
        // `max` caps the leaf size.
        let g2 = gs(&mut m, Mode::Sv39x4);
        g2.map_range(&mut m, 0x4000_0000, 0x4000_0000, 1 << 30, GPerms::RO, PageSize::M2).unwrap();
        assert_eq!(g2.walk(&m, 0x4000_0000).unwrap().size, PageSize::M2);
        assert_eq!(g2.map_range(&mut m, 0x4000_0100, 0, 4096, GPerms::RO, PageSize::K4),
                   Err(MapError::Misaligned));
    }

    #[test]
    fn running_out_of_table_memory_is_reported_and_leaks_nothing() {
        let mut m = Sim::new();
        m.budget = 4 + 1;                                   // the root and one interior table
        let g = gs(&mut m, Mode::Sv39x4);
        assert_eq!(g.map(&mut m, 0x1000, 0x2000, PageSize::K4, GPerms::RW), Err(MapError::NoMemory));
        g.destroy(&mut m);
        assert_eq!(m.live_pages(), 0);
    }

    #[test]
    fn destroying_a_table_frees_every_page_of_it() {
        let mut m = Sim::new();
        let g = gs(&mut m, Mode::Sv48x4);
        for i in 0..40u64 {
            g.map(&mut m, i << 31, i << 12, PageSize::K4, GPerms::RW).unwrap();
        }
        g.map(&mut m, 3 << 39, 0, PageSize::G512, GPerms::RO).unwrap();
        assert!(m.live_pages() > 4 + 40);
        g.destroy(&mut m);
        assert_eq!(m.live_pages(), 0);
    }
}

#[cfg(test)]
mod exits {
    use super::hv::csr::*;
    use super::hv::enter::*;
    use super::hv::fault::*;
    use super::hv::gstage::Access;

    #[test]
    fn a_guest_page_fault_address_is_htval_times_four_plus_the_low_stval_bits() {
        assert_eq!(fault_gpa(0x2_0000_0000 >> 2, 0xFFFF_FFFF_8000_0003), 0x2_0000_0003);
        assert_eq!(fault_gpa(0x12345, 0), 0x48D14);
        // High bits of a 50-bit address survive the shift.
        assert_eq!(fault_gpa((1u64 << 48) - 1, 2), ((1u64 << 50) - 4) | 2);
    }

    #[test]
    fn scause_selects_the_exit() {
        let d = |c, stval, htval, htinst, hs| decode(c, stval, htval, htinst, hs);
        assert_eq!(d(1 << 63 | 5, 0, 0, 0, 0), Exit::Interrupt(5));
        assert_eq!(d(10, 0, 0, 0, 0), Exit::VsEcall);
        assert_eq!(d(22, 0x1050_0073, 0, 0, 0), Exit::VirtualInstruction { insn: 0x1050_0073 });
        assert_eq!(d(8, 0, 0, 0, 0), Exit::Exception(8), "a VU ecall that was not delegated");
        assert_eq!(d(2, 0, 0, 0, 0), Exit::Exception(2));
        for (cause, access) in [(20, Access::Fetch), (21, Access::Load), (23, Access::Store)] {
            match d(cause, 0x7000_0001, 0x1000, 0, HSTATUS_GVA | HSTATUS_SPV) {
                Exit::GuestPageFault(f) => {
                    assert_eq!(f.access, access);
                    assert_eq!(f.gpa, 0x4001);
                    assert_eq!(f.gva, Some(0x7000_0001));
                    assert_eq!(f.insn, FaultInsn::NoInfo);
                }
                e => panic!("cause {cause} decoded as {e:?}"),
            }
        }
        // Without hstatus.GVA, stval is not a guest virtual address.
        match d(21, 0, 0x1000, 0, HSTATUS_SPV) {
            Exit::GuestPageFault(f) => assert_eq!(f.gva, None),
            e => panic!("{e:?}"),
        }
    }

    fn mem(i: FaultInsn) -> MemOp {
        match i {
            FaultInsn::Mem(m) => m,
            other => panic!("not a memory op: {other:?}"),
        }
    }

    #[test]
    fn a_transformed_load_gives_width_sign_register_and_length() {
        // lw a5, 0(a0) with the rs1 field zeroed by the transformation.
        let lw = (2 << 12) | (15 << 7) | 0x03;
        let m = mem(decode_htinst(lw));
        assert_eq!((m.kind, m.width, m.signed, m.rd, m.insn_len, m.fp),
                   (MemKind::Load, 4, true, 15, 4, false));
        // c.lw expands to the same word with bit 1 cleared: a 2-byte original.
        let m = mem(decode_htinst(lw & !2));
        assert_eq!((m.width, m.rd, m.insn_len), (4, 15, 2));
        // lbu / lhu / lb / ld.
        let m = mem(decode_htinst((4 << 12) | (5 << 7) | 0x03));
        assert_eq!((m.width, m.signed), (1, false));
        let m = mem(decode_htinst((5 << 12) | (5 << 7) | 0x03));
        assert_eq!((m.width, m.signed), (2, false));
        let m = mem(decode_htinst((0 << 12) | (5 << 7) | 0x03));
        assert_eq!((m.width, m.signed), (1, true));
        let m = mem(decode_htinst((3 << 12) | (5 << 7) | 0x03));
        assert_eq!(m.width, 8);
    }

    #[test]
    fn a_transformed_store_gives_the_source_register_and_the_offset() {
        // sd a5, 0(a0): rs2 = 15, rs1 field = the address offset (here 3).
        let sd = (15 << 20) | (3 << 15) | (3 << 12) | 0x23;
        let m = mem(decode_htinst(sd));
        assert_eq!((m.kind, m.width, m.rs2, m.addr_offset, m.insn_len),
                   (MemKind::Store, 8, 15, 3, 4));
        // fsd: the same fields, floating-point registers.
        let fsd = (7 << 20) | (3 << 12) | 0x27;
        let m = mem(decode_htinst(fsd));
        assert_eq!((m.kind, m.fp, m.width, m.rs2), (MemKind::Store, true, 8, 7));
        // amoadd.w: an atomic, 4 bytes, both registers.
        let amo = (9 << 20) | (2 << 12) | (11 << 7) | 0x2F;
        let m = mem(decode_htinst(amo));
        assert_eq!((m.kind, m.width, m.rd, m.rs2), (MemKind::Atomic, 4, 11, 9));
    }

    #[test]
    fn zero_pseudo_and_unknown_htinst_values_are_told_apart() {
        assert_eq!(decode_htinst(0), FaultInsn::NoInfo);
        assert_eq!(decode_htinst(0x2000), FaultInsn::Implicit { write: false });
        assert_eq!(decode_htinst(0x3000), FaultInsn::Implicit { write: false });
        assert_eq!(decode_htinst(0x2020), FaultInsn::Implicit { write: true });
        assert_eq!(decode_htinst(0x3020), FaultInsn::Implicit { write: true });
        assert_eq!(decode_htinst(0x4000), FaultInsn::Other(0x4000));
        // A transformed instruction that is not a load/store/atomic (addi).
        assert_eq!(decode_htinst(0x13), FaultInsn::Other(0x13));
    }

    /// The entry and exit assembly index the frame by these offsets.
    #[test]
    fn the_guest_frame_layout_is_what_the_assembly_assumes() {
        use core::mem::{offset_of, size_of};
        assert_eq!(size_of::<GuestFrame>(), 320);
        assert_eq!(offset_of!(GuestFrame, gpr), 0);
        assert_eq!(offset_of!(GuestFrame, sepc), 256);
        assert_eq!(offset_of!(GuestFrame, sstatus), 264);
        assert_eq!(offset_of!(GuestFrame, hstatus), 272);
        assert_eq!(offset_of!(GuestFrame, scause), 280);
        assert_eq!(offset_of!(GuestFrame, stval), 288);
        assert_eq!(offset_of!(GuestFrame, htval), 296);
        assert_eq!(offset_of!(GuestFrame, htinst), 304);
        // `host_sp` is the last word: 304 + 8 = 312, size 320.
    }

    #[test]
    fn a_new_frame_enters_vs_mode_with_spv_set_and_interrupts_off() {
        let f = GuestFrame::new(0x8020_0000, HSTATUS_VTW);
        assert_eq!(f.sepc, 0x8020_0000);
        assert_eq!(f.sstatus, 1 << 8, "SPP: VS-mode; SIE and SPIE clear");
        assert_eq!(f.hstatus, HSTATUS_SPV | HSTATUS_VTW);
        assert_eq!(entry_sstatus(false), 0, "VU-mode");
        assert_eq!(f.exit(), Exit::Exception(0));
    }

    #[test]
    fn skipping_an_instruction_moves_the_pc_and_drops_the_stale_trap_bits() {
        let mut f = GuestFrame::new(0x1000, 0);
        f.hstatus |= HSTATUS_GVA | HSTATUS_SPVP;
        f.skip_insn(4);
        assert_eq!(f.sepc, 0x1004);
        assert_eq!(f.hstatus, HSTATUS_SPV);
        f.skip_insn(2);
        assert_eq!(f.sepc, 0x1006);
        f.hstatus |= HSTATUS_GVA | HSTATUS_VTSR;
        f.rearm();
        assert_eq!(f.hstatus, HSTATUS_SPV | HSTATUS_VTSR);
        assert_eq!(f.sepc, 0x1006, "a refaulted access resumes at the same PC");
    }

    #[test]
    fn the_frame_decodes_its_own_trap_record() {
        let mut f = GuestFrame::new(0x1000, 0);
        f.scause = 23;
        f.htval = 0x1000_0000 >> 2;
        f.stval = 0x10;
        f.htinst = (2 << 12) | (4 << 20) | 0x23;
        match f.exit() {
            Exit::GuestPageFault(g) => {
                assert_eq!((g.access, g.gpa), (Access::Store, 0x1000_0000));
                assert!(matches!(g.insn, FaultInsn::Mem(m) if m.kind == MemKind::Store && m.rs2 == 4));
            }
            e => panic!("{e:?}"),
        }
    }
}

#[cfg(test)]
mod injection {
    use super::hv::csr::*;
    use super::hv::inject::*;
    use super::hv::probe::*;

    #[test]
    fn each_irq_has_its_own_hvip_bit() {
        assert_eq!(hvip_bit(VsIrq::Software), 1 << 2);
        assert_eq!(hvip_bit(VsIrq::Timer), 1 << 6);
        assert_eq!(hvip_bit(VsIrq::External), 1 << 10);
        let v = hvip_with(hvip_with(0, VsIrq::Software), VsIrq::External);
        assert_eq!(v, VSSIP | VSEIP);
        assert_eq!(hvip_without(v, VsIrq::Software), VSEIP);
        assert_eq!(hvip_without(0, VsIrq::Timer), 0);
    }

    #[test]
    fn the_guest_deadline_is_shifted_by_htimedelta_and_back() {
        assert_eq!(guest_deadline(1000, 500), 1500);
        assert_eq!(host_deadline(1500, 500), 1000);
        // A delta that wraps (the guest's clock started "before" the host's).
        let delta = 0u64.wrapping_sub(300);
        assert_eq!(guest_deadline(1000, delta), 700);
        assert_eq!(host_deadline(700, delta), 1000);
        // Never stays never, whatever the delta.
        assert_eq!(guest_deadline(VSTIMECMP_NEVER, 5), VSTIMECMP_NEVER);
        assert_eq!(host_deadline(VSTIMECMP_NEVER, 5), VSTIMECMP_NEVER);
    }

    #[test]
    fn vmid_width_is_the_highest_bit_the_readback_kept() {
        assert_eq!(vmid_bits_from_readback(0), 0);
        assert_eq!(vmid_bits_from_readback(8 << 60 | 0x3FFF << 44 | 0x12345), 14);
        assert_eq!(vmid_bits_from_readback(0xFF << 44), 8);
        assert_eq!(vmid_bits_from_readback(1 << 44), 1);
        assert_eq!(vmid_bits_from_readback(0xFFFF_FFFF_FFF), 0, "PPN bits are not VMID bits");
    }

    /// The probe runs only when the policy allows and the device tree
    /// declares `h`; `n` and an undeclared extension execute nothing.
    #[test]
    fn the_probe_runs_only_when_policy_and_device_tree_allow_it() {
        let mut ran = 0;
        assert!(!select(false, true, || { ran += 1; true }));
        assert!(!select(true, false, || { ran += 1; true }));
        assert_eq!(ran, 0, "the probe executed under n or without an `h` in riscv,isa");
        assert!(!available());
        assert!(!select(true, true, || { ran += 1; false }), "a trapping probe reads as absent");
        assert_eq!(ran, 1);
        assert!(select(true, true, || { ran += 1; true }));
        assert!(available());
        select(false, false, || true);
        assert!(!available(), "a later `n` selection clears it");
    }
}

/// Message-signalled lines, `hstatus.VGEIN`, the trapped instruction that
/// asks for a file, GEILEN and the AIA wiring.
#[cfg(test)]
mod aia_pure {
    use super::hv::inject::*;
    use super::hv::vscsr::VsCsrs;
    use super::hv::csr;

    #[test]
    fn a_line_from_16_is_an_identity_and_the_lines_below_stay_hvip_bits() {
        assert_eq!((MSI_LINE_BASE, MSI_IDS), (16, 48));
        // Line `MSI_LINE_BASE + id - 1` is identity `id`: bit `id` of eip0.
        assert_eq!((msi_line(1), msi_line(48)), (Some(16), Some(63)));
        assert_eq!((msi_line(0), msi_line(49)), (None, None), "identity 0 does not exist; past the last line");
        for id in 1..=MSI_IDS {
            assert_eq!(msi_bits(1 << msi_line(id).unwrap()), 1 << id, "identity {id}");
        }
        // The lines below are hvip bits and raise no identity.
        for l in 0..MSI_LINE_BASE {
            assert_eq!(msi_bits(1 << l), 0, "line {l} is an hvip bit");
        }
    }

    #[test]
    fn the_identities_of_the_raised_lines_are_the_bits_of_eip0() {
        assert_eq!(msi_bits(0), 0);
        // The hvip lines raise no identity.
        assert_eq!(msi_bits(csr::VSSIP | csr::VSTIP | csr::VSEIP | 0xFFFF), 0);
        assert_eq!(msi_bits(1 << 16), 1 << 1, "line 16 is identity 1: bit 1, bit 0 is not an identity");
        assert_eq!(msi_bits(1 << 63), 1 << 48);
        assert_eq!(msi_bits(1 << 20 | 1 << 2), 1 << 5);
        assert_eq!(msi_bits(u64::MAX) & 1, 0);
    }

    #[test]
    fn vgein_is_six_bits_and_nothing_else_moves() {
        let h = csr::HSTATUS_SPV | csr::HSTATUS_VTW | csr::HSTATUS_SPVP;
        let v = hstatus_with_vgein(h, 5);
        assert_eq!(v, h | 5 << 12);
        assert_eq!(vgein_of(v), 5);
        assert_eq!(hstatus_with_vgein(v, 63), h | 63 << 12);
        assert_eq!(hstatus_with_vgein(v, 0), h, "no file clears it");
        assert_eq!(hstatus_with_vgein(h, 64), h, "a seventh bit does not leak into the field above");
        assert_eq!(vgein_of(0), 0);
    }

    /// The CSR instructions of the AIA's S-level registers, encoded from the
    /// manual: `csr << 20 | rs1 << 15 | funct3 << 12 | rd << 7 | 0x73`.
    #[test]
    fn the_instructions_that_ask_for_a_file_are_the_csr_accesses_to_the_aia_registers() {
        let csrw_siselect_t1 = 0x1503_1073u64; // csrw siselect, t1
        let csrr_a0_sireg = 0x1510_2573; // csrr a0, sireg
        let csrrw_t0_sireg_t1 = 0x1513_12F3; // csrrw t0, sireg, t1
        let csrr_t0_stopei = 0x15C0_22F3; // csrr t0, stopei
        let stopi = 0xDB00_2373; // csrr t1, stopi
        let csrrwi_siselect = 0x1505_D2F3; // csrrwi t0, siselect, 11
        for i in [csrw_siselect_t1, csrr_a0_sireg, csrrw_t0_sireg_t1, csrr_t0_stopei, stopi, csrrwi_siselect] {
            assert!(is_aia_csr_access(i), "{i:#x}");
        }
        for (i, why) in [
            (0x1000_2573u64, "csrr a0, sstatus"),
            (0x1050_0073, "wfi"),
            (0x0000_0073, "ecall"),
            (0x1020_0073, "sret"),
            (0x1510_4573, "funct3 4 is reserved"),
            (0x1510_2573 & !0x7F | 0x33, "not the SYSTEM opcode"),
            (0x0001, "a compressed instruction"),
            (0, "no instruction"),
        ] {
            assert!(!is_aia_csr_access(i), "{why}");
        }
    }

    #[test]
    fn a_trap_that_does_not_say_what_it_was_gets_one_retry() {
        assert!(adoptable(0x15C0_22F3));
        assert!(adoptable(0), "stval 0: the hardware did not say");
        assert!(!adoptable(0x1000_2573), "a CSR that is not the AIA's is a fault");
    }

    #[test]
    fn geilen_is_the_highest_hgeie_bit_that_stuck() {
        assert_eq!(geilen_from_readback(0), 0, "no guest files");
        assert_eq!(geilen_from_readback(0b1110), 3, "bit 0 is read-only zero");
        assert_eq!(geilen_from_readback(0xFFFF_FFFE), 31);
        assert_eq!(geilen_from_readback(u64::MAX), 63, "capped at what VGEIN can name");
    }

    #[test]
    fn the_sbi_timer_of_an_sstc_guest_goes_to_vstimecmp_and_withdraws_the_interrupt() {
        let mut vs = VsCsrs::reset();
        vs.hvip = csr::VSTIP | csr::VSSIP;
        set_timer_sstc(&mut vs, 123_456);
        assert_eq!(vs.vstimecmp, 123_456, "guest ticks, no htimedelta shift");
        assert_eq!(vs.hvip, csr::VSSIP, "the timer interrupt is withdrawn, the IPI is not");
        set_timer_sstc(&mut vs, u64::MAX);
        assert_eq!(vs.vstimecmp, VSTIMECMP_NEVER);
    }
}

/// The pool of guest interrupt files.
#[cfg(test)]
mod aia_pool {
    use super::hv::inject::*;

    const ROOT_A: u64 = 0x8020_0000;
    const ROOT_B: u64 = 0x8030_0000;

    fn pool() -> FilePool<4, 8> {
        let p = FilePool::new();
        for h in 0..4 {
            p.set_geilen(h, 3);
        }
        p
    }

    #[test]
    fn a_hart_not_probed_or_without_files_has_nothing_to_give() {
        let p = FilePool::<2, 8>::new();
        assert_eq!(p.geilen(0), None);
        assert_eq!(p.bind(0, ROOT_A, 0), Err(BindError::NoFiles), "not probed");
        p.set_geilen(0, 0);
        assert_eq!(p.geilen(0), Some(0));
        assert_eq!(p.bind(0, ROOT_A, 0), Err(BindError::NoFiles), "GEILEN 0");
        assert_eq!(p.bind(2, ROOT_A, 0), Err(BindError::BadHart));
        p.set_geilen(1, 200);
        assert_eq!(p.geilen(1), Some(8), "clamped to the files the pool tracks");
        assert_eq!(POOL_FILES.min(GEI_MAX as usize), POOL_FILES);
    }

    #[test]
    fn files_are_numbered_from_one_and_run_out_at_geilen() {
        let p = pool();
        assert_eq!(p.bind(0, ROOT_A, 0), Ok(1));
        assert_eq!(p.bind(0, ROOT_A, 1), Ok(2));
        assert_eq!(p.bind(0, ROOT_B, 0), Ok(3));
        assert_eq!(p.bind(0, ROOT_B, 1), Err(BindError::Full));
        // Another hart has its own.
        assert_eq!(p.bind(1, ROOT_B, 1), Ok(1));
    }

    #[test]
    fn a_vcpu_finds_its_file_again_and_never_holds_two() {
        let p = pool();
        assert_eq!(p.bind(0, ROOT_A, 0), Ok(1));
        assert_eq!(p.bind(0, ROOT_B, 0), Ok(2));
        assert_eq!(p.bind(0, ROOT_A, 0), Ok(1), "a restarted vCPU gets its own back");
        // It restarts on another hart: the old file is free for others.
        assert_eq!(p.bind(2, ROOT_A, 0), Ok(1));
        assert_eq!(p.owner(0, 1), None);
        assert_eq!(p.bind(0, ROOT_B, 1), Ok(1));
    }

    #[test]
    fn a_vms_files_come_back_with_its_tables_and_the_others_stay() {
        let p = pool();
        // Two vCPUs on each of three harts (a vCPU holds one file, on one hart).
        for v in 0..3 {
            p.bind(v, ROOT_A, 2 * v as u8).unwrap();
            p.bind(v, ROOT_A, 2 * v as u8 + 1).unwrap();
        }
        p.bind(0, ROOT_B, 0).unwrap();
        p.release(ROOT_A);
        assert_eq!(p.owner(0, 1), None);
        assert_eq!(p.owner(0, 2), None);
        assert_eq!(p.owner(0, 3), Some(Owner { root: ROOT_B, vcpu: 0 }));
        for v in 1..3 {
            assert_eq!((p.owner(v, 1), p.owner(v, 2)), (None, None));
        }
        p.release(ROOT_A);
    }

    #[test]
    fn the_owner_is_the_root_and_the_vcpu() {
        let p = pool();
        p.bind(1, ROOT_A, 7).unwrap();
        assert_eq!(p.owner(1, 1), Some(Owner { root: ROOT_A, vcpu: 7 }));
        assert_eq!(p.owner(1, 2), None);
        assert_eq!(p.owner(1, 0), None, "there is no file 0");
        assert_eq!(p.owner(1, 64), None);
        assert_eq!(p.owner(9, 1), None);
    }

    /// The guest-external interrupt names the vCPUs whose file has something
    /// pending AND is armed, and only those.
    #[test]
    fn the_interrupt_wakes_the_holders_of_armed_pending_files() {
        let p = pool();
        p.bind(0, ROOT_A, 0).unwrap(); // 1
        p.bind(0, ROOT_A, 1).unwrap(); // 2
        p.bind(0, ROOT_B, 0).unwrap(); // 3
        let mut woke = std::vec::Vec::new();
        // 1 and 2 pending, 2 and 3 armed: only 2.
        let done = p.wake(0, 0b0110, 0b1100, |o| woke.push(o));
        assert_eq!(done, 0b0100);
        assert_eq!(woke, [Owner { root: ROOT_A, vcpu: 1 }]);
        woke.clear();
        // Bit 0 is not a file; a pending bit nobody holds wakes nobody.
        assert_eq!(p.wake(0, 0b1, 0b1, |o| woke.push(o)), 0);
        assert_eq!(p.wake(0, 1 << 5, 1 << 5, |o| woke.push(o)), 1 << 5);
        assert!(woke.is_empty());
        let all = p.wake(0, 0b1110, 0b1110, |o| woke.push(o));
        assert_eq!((all, woke.len()), (0b1110, 3));
    }
}

/// Where the guest files are in the IMSIC group.
#[cfg(test)]
mod aia_layout {
    use super::imsic::*;

    /// QEMU `virt,aia=aplic-imsic,aia-guests=3`: 2 guest-index bits, so a
    /// hart's block is four pages (supervisor file + 3 guest files).
    fn virt() -> GroupLayout {
        GroupLayout { base: 0x2800_0000, num_ids: 255, hart_stride: GroupLayout::stride_for_guest_bits(2) }
    }

    #[test]
    fn a_harts_block_holds_the_supervisor_file_then_the_guest_files() {
        let l = virt();
        assert_eq!(l.hart_stride, 4 * 4096);
        assert_eq!(l.guest_files(), 3);
    }

    #[test]
    fn a_group_without_guest_index_bits_has_no_guest_files() {
        let l = GroupLayout { base: 0x2800_0000, num_ids: 255, hart_stride: GroupLayout::stride_for_guest_bits(0) };
        assert_eq!(l.guest_files(), 0);
    }

    #[test]
    fn the_indirect_selectors_are_the_aias() {
        // eip0 0x80, eie0 0xC0, RV64 uses the even ones only.
        assert_eq!((eip_selector(0), eip_selector(63), eip_selector(64), eip_selector(255)), (0x80, 0x80, 0x82, 0x86));
        assert_eq!((eie_selector(0), eie_selector(64), eie_selector(255)), (0xC0, 0xC2, 0xC6));
        assert_eq!(eie_bit(1), 2);
        assert_eq!(eie_bit(65), 2);
        // `riscv,num-ids` is one less than a multiple of 64.
        assert_eq!((file_words(63), file_words(127), file_words(255), file_words(2047)), (1, 2, 4, 32));
        assert!(eip_selector(2047) < 0xC0 && eie_selector(2047) < 0x100, "the arrays do not overlap or overrun");
    }
}

/// One vCPU entry with a guest file, against a hart that records what the
/// entry asks of it (`guest::Hart`).
#[cfg(test)]
mod aia_enter {
    use super::hv::csr;
    use super::hv::enter::GuestFrame;
    use super::hv::guest::{self, VcpuState};
    use super::hv::inject::{self, vgein_of, FILES};
    use azos_arch_api::{Exit, GuestCtx, Stage2Root};

    const PC: u64 = 0x8020_0000;
    const WFI: u64 = 0x1050_0073;
    const CSRR_SIREG: u64 = 0x1510_2573;
    const CSRR_SSTATUS: u64 = 0x1000_2573;
    const ECALL_VS: u64 = 10;
    const VIRT_INSN: u64 = 22;

    #[derive(Debug, PartialEq, Eq)]
    enum Ev {
        Enter { gei: u32, clear: bool, msi: u64 },
        Exit { gei: u32, waits: bool },
    }

    /// A hart `hart` with `files` guest files whose guest "traps" as scripted.
    /// The pool is the machine's one, shared by the tests that run side by
    /// side: each test has harts of its own (8..21, so `NR_CPUS` of the test
    /// build must cover them: the default 64 does).
    struct Fake {
        hart: u64,
        files: u32,
        script: std::vec::Vec<(u64, u64)>,
        ran: usize,
        hstatus: std::vec::Vec<u64>,
        log: std::vec::Vec<Ev>,
    }

    impl Fake {
        fn new(hart: u64, files: u32, script: &[(u64, u64)]) -> Fake {
            assert!((hart as usize) < azos_limits::NR_CPUS, "the test build has too few CPUs for hart {hart}");
            Fake { hart, files, script: script.to_vec(), ran: 0, hstatus: std::vec::Vec::new(), log: std::vec::Vec::new() }
        }
        fn on(&self, hart: u64, script: &[(u64, u64)]) -> Fake {
            Fake::new(hart, self.files, script)
        }
    }

    impl guest::Hart for Fake {
        fn irqs_off(&mut self) -> bool {
            true
        }
        fn irqs_restore(&mut self, _were_on: bool) {}
        fn hart_id(&mut self) -> u64 {
            self.hart
        }
        fn guest_files(&mut self) -> u32 {
            FILES.set_geilen(self.hart as usize, self.files);
            self.files
        }
        fn file_enter(&mut self, gei: u32, clear: bool, msi: u64) {
            self.log.push(Ev::Enter { gei, clear, msi });
        }
        fn file_exit(&mut self, gei: u32, waits: bool) {
            self.log.push(Ev::Exit { gei, waits });
        }
        unsafe fn run(&mut self, st: &mut VcpuState, _hgatp: u64, _vmid: u16, _flush: bool) {
            let (scause, stval) = self.script[self.ran];
            self.ran += 1;
            self.hstatus.push(st.frame.hstatus);
            st.frame.scause = scause;
            st.frame.stval = stval;
            st.frame.hstatus |= csr::HSTATUS_SPV;
        }
    }

    fn ctx(root: u64, vcpu: u8) -> GuestCtx {
        GuestCtx::new(Stage2Root { root, aux: 0 }, 1, vcpu, PC, 0)
    }

    fn enter(h: &mut Fake, c: &mut GuestCtx) -> Exit {
        // SAFETY: the fake hart runs nothing.
        let e = unsafe { guest::enter_vcpu(h, c, 0) };
        // The monitor's loop marks the vCPU started after its first entry.
        c.started = true;
        e
    }

    fn st(c: &GuestCtx) -> VcpuState {
        guest::load(c)
    }

    /// A guest on the virtual PLIC takes no file, whatever the hart has, and
    /// so keeps the freedom to run on any hart.
    #[test]
    fn a_guest_that_never_uses_the_imsic_gets_no_file_and_moves_freely() {
        let mut h = Fake::new(8, 3, &[(ECALL_VS, 0), (ECALL_VS, 0)]);
        let mut c = ctx(0x1000_0000, 0);
        c.irqs = csr::VSEIP | csr::VSTIP | csr::VSSIP;
        assert_eq!(enter(&mut h, &mut c), Exit::Hypercall);
        assert!(h.log.is_empty());
        assert_eq!(st(&c).vsfile, 0);
        assert_eq!(vgein_of(h.hstatus[0]), 0);
        let mut h2 = h.on(9, &[(ECALL_VS, 0)]);
        assert_eq!(enter(&mut h2, &mut c), Exit::Hypercall, "another hart is fine without a file");
    }

    #[test]
    fn a_raised_message_line_gives_the_vcpu_a_cleared_file_named_in_hstatus() {
        let mut h = Fake::new(10, 3, &[(ECALL_VS, 0), (ECALL_VS, 0)]);
        let mut c = ctx(0x1010_0000, 0);
        c.irqs = (1 << 20) | csr::VSEIP;
        assert_eq!(enter(&mut h, &mut c), Exit::Hypercall);
        let gei = st(&c).vsfile as u32;
        assert!(gei >= 1 && gei <= 3);
        assert_eq!(h.log, [Ev::Enter { gei, clear: true, msi: 1 << 5 }, Ev::Exit { gei, waits: false }]);
        assert_eq!(vgein_of(h.hstatus[0]), gei, "VGEIN is in hstatus when the guest enters");
        // The next entry on the same hart: the file is kept (no clear), the new line is pended.
        c.irqs = 1 << 63;
        h.log.clear();
        h.script.push((ECALL_VS, 0));
        assert_eq!(enter(&mut h, &mut c), Exit::Hypercall);
        assert_eq!(h.log[0], Ev::Enter { gei, clear: false, msi: 1 << 48 });
        assert_eq!(vgein_of(h.hstatus[1]), gei);
        // And with no new line the file is still made current, with nothing to pend.
        c.irqs = 0;
        h.script.push((ECALL_VS, 0));
        h.log.clear();
        enter(&mut h, &mut c);
        assert_eq!(h.log[0], Ev::Enter { gei, clear: false, msi: 0 });
    }

    #[test]
    fn a_vcpu_waiting_for_an_interrupt_arms_its_file() {
        let mut h = Fake::new(11, 2, &[(VIRT_INSN, WFI)]);
        let mut c = ctx(0x1020_0000, 0);
        c.irqs = 1 << 16;
        assert_eq!(enter(&mut h, &mut c), Exit::Wait);
        let gei = st(&c).vsfile as u32;
        assert_eq!(h.log[1], Ev::Exit { gei, waits: true });
    }

    #[test]
    fn a_vcpu_with_a_file_is_not_run_on_another_hart() {
        let mut h = Fake::new(12, 2, &[(ECALL_VS, 0)]);
        let mut c = ctx(0x1030_0000, 0);
        c.irqs = 1 << 17;
        assert_eq!(enter(&mut h, &mut c), Exit::Hypercall);
        c.irqs = 0;
        let mut elsewhere = h.on(13, &[(ECALL_VS, 0)]);
        assert_eq!(enter(&mut elsewhere, &mut c), Exit::InvalidState);
        assert_eq!(elsewhere.ran, 0, "the guest did not run without its file");
        assert_eq!(st(&c).last_hart, 12, "nothing of the vCPU was touched");
        // Back on its own hart it runs.
        let mut home = h.on(12, &[(ECALL_VS, 0)]);
        assert_eq!(enter(&mut home, &mut c), Exit::Hypercall);
    }

    #[test]
    fn a_message_line_on_a_hart_without_files_is_refused_visibly() {
        let mut h = Fake::new(14, 0, &[(ECALL_VS, 0)]);
        let mut c = ctx(0x1040_0000, 0);
        c.irqs = 1 << 30;
        assert_eq!(enter(&mut h, &mut c), Exit::InvalidState);
        assert_eq!(h.ran, 0);
        assert_eq!(st(&c).vsfile, 0);
    }

    /// The guest's first `sireg` access is a virtual-instruction exception
    /// (no file yet): the vCPU gets one and the same instruction runs again,
    /// before the monitor sees an exit.
    #[test]
    fn the_first_imsic_access_of_a_guest_gets_it_a_file_and_is_retried() {
        let mut h = Fake::new(15, 2, &[(VIRT_INSN, CSRR_SIREG), (ECALL_VS, 0)]);
        let mut c = ctx(0x1050_0000, 0);
        c.irqs = csr::VSEIP;
        assert_eq!(enter(&mut h, &mut c), Exit::Hypercall);
        assert_eq!(h.ran, 2);
        let s = st(&c);
        let gei = s.vsfile as u32;
        assert!(gei >= 1);
        assert_eq!(h.log[0], Ev::Enter { gei, clear: true, msi: 0 });
        assert_eq!(vgein_of(h.hstatus[0]), 0, "the first try had no file");
        assert_eq!(vgein_of(h.hstatus[1]), gei);
        assert_eq!(s.frame.sepc, PC, "the instruction is retried, not skipped");
    }

    #[test]
    fn a_second_trap_after_the_file_is_a_fault_not_a_loop() {
        let mut h = Fake::new(16, 2, &[(VIRT_INSN, CSRR_SIREG), (VIRT_INSN, CSRR_SIREG), (ECALL_VS, 0)]);
        let mut c = ctx(0x1060_0000, 0);
        assert_eq!(enter(&mut h, &mut c), Exit::Other(csr::EXC_VIRTUAL_INSTRUCTION));
        assert_eq!(h.ran, 2, "one retry");
    }

    #[test]
    fn a_trap_that_is_not_an_aia_access_or_a_hart_without_files_is_a_fault() {
        let mut h = Fake::new(17, 2, &[(VIRT_INSN, CSRR_SSTATUS)]);
        let mut c = ctx(0x1070_0000, 0);
        assert_eq!(enter(&mut h, &mut c), Exit::Other(csr::EXC_VIRTUAL_INSTRUCTION));
        assert_eq!((h.ran, st(&c).vsfile), (1, 0));
        let mut none = Fake::new(18, 0, &[(VIRT_INSN, CSRR_SIREG), (ECALL_VS, 0)]);
        let mut c2 = ctx(0x1080_0000, 0);
        assert_eq!(enter(&mut none, &mut c2), Exit::Other(csr::EXC_VIRTUAL_INSTRUCTION));
        assert_eq!(none.ran, 1, "nothing to retry with");
    }

    /// A vCPU the guest restarts (`CPU_OFF`, `CPU_ON`) is a new context for
    /// the same VM and index: it gets its file back, cleared again.
    #[test]
    fn a_restarted_vcpu_gets_its_own_file_back_cleared() {
        let mut h = Fake::new(19, 3, &[(ECALL_VS, 0), (ECALL_VS, 0)]);
        let mut c = ctx(0x1090_0000, 1);
        c.irqs = 1 << 16;
        enter(&mut h, &mut c);
        let first = st(&c).vsfile as u32;
        let mut again = ctx(0x1090_0000, 1);
        again.irqs = 1 << 16;
        h.log.clear();
        enter(&mut h, &mut again);
        assert_eq!(st(&again).vsfile as u32, first);
        assert_eq!(h.log[0], Ev::Enter { gei: first, clear: true, msi: 1 << 1 });
    }

    #[test]
    fn a_new_vcpus_state_has_no_file_and_a_timer_that_never_fires() {
        let mut h = Fake::new(20, 0, &[(ECALL_VS, 0)]);
        let mut c = ctx(0x10A0_0000, 0);
        c.started = false;
        // SAFETY: the fake hart runs nothing.
        unsafe { guest::enter_vcpu(&mut h, &mut c, 0) };
        let s = st(&c);
        assert_eq!((s.vsfile, s.vs.vstimecmp), (0, inject::VSTIMECMP_NEVER));
        let _ = GuestFrame::default();
    }
}

/// The boot's facts, and the SBI timer on an Sstc guest. The only test that
/// sets them (they are process-wide).
#[cfg(test)]
mod aia_wired {
    use super::hv::csr;
    use super::hv::guest;
    use super::hv::inject::*;
    use super::hv::sbi::{eid, fid};
    use super::hv::vscsr::Caps;
    use super::hv::HvImpl;
    use azos_arch_api::{
        GuestCtx, HypercallHost, HypercallOutcome, Hypervisor, RemoteFence, Stage2Root, VcpuStartError,
    };

    #[derive(Default)]
    struct Host {
        armed: std::vec::Vec<(usize, u64, u32)>,
    }

    impl HypercallHost for Host {
        fn vcpus(&self) -> usize {
            1
        }
        fn vcpu_running(&self, _vcpu: usize) -> bool {
            true
        }
        fn start_vcpu(&mut self, _vcpu: usize, _pc: u64, _arg: u64) -> Result<(), VcpuStartError> {
            Err(VcpuStartError::Failed)
        }
        fn raise_irq(&mut self, _vcpu: usize, _line: u32) {}
        fn arm_timer(&mut self, vcpu: usize, deadline: u64, line: u32) {
            self.armed.push((vcpu, deadline, line));
        }
        fn fence(&mut self, _vcpu: usize, _fence: RemoteFence) {}
    }

    fn set_timer(deadline: u64) -> GuestCtx {
        let mut c = GuestCtx::new(Stage2Root { root: 0x2000_0000, aux: 0 }, 1, 0, 0x8020_0000, 0);
        let mut st = guest::load(&c);
        st.frame.gpr[17] = eid::TIME;
        st.frame.gpr[16] = fid::TIME_SET_TIMER;
        st.frame.gpr[10] = deadline;
        st.frame.sepc = 0x8020_0100;
        st.vs.hvip = csr::VSTIP | csr::VSSIP;
        st.vs.vstimecmp = 5;
        guest::store(&mut c, &st);
        c
    }

    /// What the boot makes of what it found (`kernel/src/entry/riscv64/ext/hv.rs`
    /// calls `Wiring::resolve` and `wire`): the switch each Kconfig symbol
    /// (RV_H, RV_SSTC, RV_AIA) and the device tree throw.
    #[test]
    fn the_boot_turns_each_path_on_only_where_its_inputs_are_there() {
        // QEMU virt with `aia=aplic-imsic,aia-guests=3`, Sstc and Smstateen.
        assert_eq!(
            Wiring::resolve(true, true, true, 255, 3),
            Wiring { sstc: true, smstateen: true, guest_ids: 255 }
        );
        // No H (RV_H = n, or the probe failed): nothing, whatever else is there.
        assert_eq!(Wiring::resolve(false, true, true, 255, 3), Wiring::default());
        // RV_SSTC = n (the host timer is the SBI's): the guests' is too.
        assert!(!Wiring::resolve(true, false, true, 255, 3).sstc);
        // No hstateen0 reachable.
        assert!(!Wiring::resolve(true, true, false, 255, 3).smstateen);
        // RV_AIA = n or a PLIC machine (0 identities), or an IMSIC group
        // without guest-index bits: no vCPU gets a file.
        assert_eq!(Wiring::resolve(true, true, true, 0, 0).guest_ids, 0);
        assert_eq!(Wiring::resolve(true, true, true, 255, 0).guest_ids, 0);
    }

    #[test]
    fn a_holder_is_named_by_one_nonzero_word_that_tells_vcpus_of_a_vm_apart() {
        let a = Owner { root: 0x8040_0000, vcpu: 0 };
        let b = Owner { root: 0x8040_0000, vcpu: 1 };
        let c = Owner { root: 0x8050_0000, vcpu: 0 };
        assert!(a.key() != 0 && a.key() != b.key() && a.key() != c.key());
        assert_eq!(a.key(), Owner { root: 0x8040_0000, vcpu: 0 }.key());
        // The pool stores exactly this word.
        let p: FilePool<1, 4> = FilePool::new();
        p.set_geilen(0, 4);
        let g = p.bind(0, a.root, a.vcpu).unwrap();
        assert_eq!(p.owner(0, g), Some(a));
    }

    #[test]
    fn the_wiring_decides_what_a_vm_gets_and_defaults_to_nothing() {
        assert_eq!(wiring(), Wiring::default());
        assert_eq!(caps(false), Caps::default());
        // Not wired: the SBI timer is the monitor's, as before.
        let mut host = Host::default();
        let mut c = set_timer(777);
        assert_eq!(HvImpl.hypercall(&mut c, &mut host), HypercallOutcome::Served);
        assert_eq!(host.armed, [(0, 777, 6)]);
        assert_eq!(guest::load(&c).vs.vstimecmp, 5, "vstimecmp is not the monitor's to write without Sstc");

        wire(Wiring { sstc: true, smstateen: true, guest_ids: 255 });
        assert_eq!(caps(true), Caps { sstc: true, smstateen: true, aia: true, guest_file: true });
        assert!(!caps(false).guest_file);
        // Sstc: the deadline is the guest's own register; the monitor keeps no timer line.
        let mut host = Host::default();
        let mut c = set_timer(888);
        assert_eq!(HvImpl.hypercall(&mut c, &mut host), HypercallOutcome::Served);
        assert!(host.armed.is_empty());
        let s = guest::load(&c);
        assert_eq!((s.vs.vstimecmp, s.vs.hvip), (888, csr::VSSIP));
        assert_eq!((s.frame.gpr[10], s.frame.gpr[11], s.frame.sepc), (0, 0, 0x8020_0104), "success, past the ecall");
        // Any other call still goes to the SBI.
        let mut c = set_timer(1);
        let mut st = guest::load(&c);
        st.frame.gpr[17] = eid::BASE;
        st.frame.gpr[16] = 0;
        guest::store(&mut c, &st);
        assert_eq!(HvImpl.hypercall(&mut c, &mut host), HypercallOutcome::Served);
        assert_eq!(guest::load(&c).frame.gpr[11], 2 << 24, "the SBI spec version");

        wire(Wiring::default());
        assert_eq!(caps(true), Caps { guest_file: true, ..Caps::default() });
    }
}

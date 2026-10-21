// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The hardware side of the TLB shootdowns: x86_64 INVLPGB (operands, range
//! plan, selection; `crates/core/arch-x86_64/src/tlb.rs`) and
//! riscv64 Svinval (encodings, threshold, selection;
//! `crates/core/arch-riscv64/src/tlb.rs`). A wrong bit here is silent until a
//! Zen 3+ part or an Svinval hart executes it: QEMU's TCG has no INVLPGB (the
//! x86_64 gate runs the IPI fallback); whether a riscv64 gate CPU model has
//! Svinval is reported by the `[ISA]` line. The CPUID decode (EBX[3], EDX[15:0]) is tested in
//! `arch-x86_64/src/cpu/features.rs` itself.

#[cfg(test)]
mod x86_invlpgb {
    use crate::x86_paging::tlb::*;

    const GLOBAL: u64 = 1 << 3;
    const VA: u64 = 1 << 0;
    const PCID: u64 = 1 << 1;

    fn collect(f: LocalFlush, global: bool, max: u32) -> Vec<InvlpgbOperands> {
        let mut v = Vec::new();
        invlpgb_plan(f, global, max, |o| v.push(o));
        v
    }

    /// RAX = page frame | flags (bit 0 VA, 3 global), ECX = pages - 1 with
    /// the stride bit clear, EDX = 0: neither PCID-valid (RAX bit 1) nor
    /// ASID-valid (bit 2) is ever set, so every PCID of every CPU is reached
    /// (AMD APM Vol. 3, INVLPGB). Each field is pinned by a value that turns
    /// a shifted or merged field into a different number.
    #[test]
    fn the_operands_put_each_field_in_its_register_and_bit() {
        let o = invlpgb_operands(Some(0x7fff_dead_b000), 1, false);
        assert_eq!((o.rax, o.ecx, o.edx), (0x7fff_dead_b000 | VA, 0, 0), "one page is zero additional pages");
        let o = invlpgb_operands(Some(0x20_0000), 8, false);
        assert_eq!((o.rax, o.ecx, o.edx), (0x20_0000 | VA, 7, 0));
        assert_eq!(o.ecx & (1 << 31), 0, "4 KiB stride");
        // The low 12 bits of the address are the flags: they must be dropped.
        let o = invlpgb_operands(Some(0x1234), 1, false);
        assert_eq!(o.rax, 0x1000 | VA);
        let o = invlpgb_operands(Some(0x1000), 1, true);
        assert_eq!(o.rax, 0x1000 | VA | GLOBAL);
        assert_eq!(o.rax & PCID, 0, "a PCID scope would leave stale harts' older-generation entries");
    }

    /// No address: the VA flag stays clear and the count is not sent (the
    /// instruction ignores it, but a stale count must not leak into ECX).
    #[test]
    fn an_operand_without_an_address_names_no_page() {
        let o = invlpgb_operands(None, 5, false);
        assert_eq!((o.rax, o.ecx, o.edx), (0, 0, 0), "every page of every PCID, non-global");
        let o = invlpgb_operands(None, 5, true);
        assert_eq!((o.rax, o.ecx, o.edx), (GLOBAL, 0, 0));
    }

    /// A page run is cut at the CPU's limit and the chunks tile the run
    /// exactly: no page twice, none missing, every chunk within the limit.
    #[test]
    fn a_page_run_is_chunked_at_the_cpu_limit_and_covers_it_exactly() {
        let f = LocalFlush::Pages { start: 0x10_0000, pages: 7 };
        let v = collect(f, false, 3);
        let seen: Vec<(u64, u32)> = v.iter().map(|o| (o.rax & !0xFFF, o.ecx + 1)).collect();
        assert_eq!(seen, [(0x10_0000, 3), (0x10_3000, 3), (0x10_6000, 1)]);
        // A limit above the run: one instruction.
        let v = collect(f, false, 65536);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].ecx, 6);
        // A limit of exactly the run, and of one page.
        assert_eq!(collect(f, false, 7).len(), 1);
        assert_eq!(collect(f, false, 1).len(), 7);
        // Nothing to flush: nothing issued.
        assert!(collect(LocalFlush::Pages { start: 0x10_0000, pages: 0 }, false, 4).is_empty());
        // The global bit reaches every chunk.
        for o in collect(f, true, 3) {
            assert_eq!(o.rax & (VA | GLOBAL), VA | GLOBAL);
        }
    }

    /// The context flush is one address-less INVLPGB of every PCID; everything
    /// is one global INVLPGB.
    #[test]
    fn a_context_or_total_flush_is_one_instruction_without_an_address() {
        let v = collect(LocalFlush::Context, false, 4);
        assert_eq!(v, [InvlpgbOperands { rax: 0, ecx: 0, edx: 0 }]);
        let v = collect(LocalFlush::Everything, false, 4);
        assert_eq!(v, [InvlpgbOperands { rax: GLOBAL, ecx: 0, edx: 0 }],
                   "a kernel-wide flush is global whatever the caller said");
    }

    /// The plan follows `local_flush_for`: a range above the ceiling becomes
    /// the context flush, one instruction, not hundreds of page INVLPGBs.
    #[test]
    fn a_long_range_becomes_a_context_flush_past_the_ceiling() {
        let page = 4096;
        let long = local_flush_for(0x40_0000, (FLUSH_CEILING_PAGES + 1) * page, false, FLUSH_CEILING_PAGES);
        assert_eq!(collect(long, false, 8).len(), 1);
        assert_eq!(collect(long, false, 8)[0].rax & VA, 0);
        let short = local_flush_for(0x40_0000, FLUSH_CEILING_PAGES * page, false, FLUSH_CEILING_PAGES);
        let n: u32 = collect(short, false, 8).iter().map(|o| o.ecx + 1).sum();
        assert_eq!(n as usize, FLUSH_CEILING_PAGES);
        // Kernel ranges past the ceiling flush everything, global included.
        let k = local_flush_for(0x40_0000, (FLUSH_CEILING_PAGES + 1) * page, true, FLUSH_CEILING_PAGES);
        assert_eq!(collect(k, true, 8)[0].rax, GLOBAL);
    }

    /// `icache_sync_all` sends an empty kernel range to interrupt every CPU;
    /// INVLPGB interrupts nobody, so that request must stay on the IPI.
    #[test]
    fn the_empty_kernel_range_keeps_the_ipi() {
        assert!(kernel_uses_invlpgb(true, 4096));
        assert!(kernel_uses_invlpgb(true, usize::MAX));
        assert!(!kernel_uses_invlpgb(true, 0), "the serialize-everyone request needs an interrupt");
        assert!(!kernel_uses_invlpgb(false, 4096));
        assert!(!kernel_uses_invlpgb(false, 0));
    }

    /// The boot decision: INVLPGB only when the choice is not `n`, the CPU
    /// reports it and its limit is usable. One test owns the global.
    #[test]
    fn the_selection_needs_policy_cpu_bit_and_a_page_limit() {
        assert!(!invlpgb_on(), "off until a boot selects it");
        assert!(!invlpgb_select(false, true, 8), "Kconfig n");
        assert!(!invlpgb_on());
        assert!(!invlpgb_select(true, false, 8), "CPU without it");
        assert!(!invlpgb_on());
        assert!(!invlpgb_select(true, true, 0), "no page limit read");
        assert!(!invlpgb_on());
        assert!(invlpgb_select(true, true, 8));
        assert!(invlpgb_on());
        assert!(!invlpgb_select(false, true, 8), "a later `n` turns it off again");
        assert!(!invlpgb_on());
    }
}

#[cfg(test)]
mod rv_svinval {
    use crate::tlb::*;

    /// The words are the privileged spec's, checked against LLVM's assembler
    /// (`llvm-mc -triple=riscv64 -mattr=+svinval`): `sinval.vma` is the
    /// `sfence.vma` format (0x12B50073 for a0, a1) with funct7 0001011.
    #[test]
    fn the_svinval_words_are_the_specified_encodings() {
        assert_eq!(SFENCE_W_INVAL, 0x1800_0073);
        assert_eq!(SFENCE_INVAL_IR, 0x1810_0073);
        assert_eq!(SINVAL_VMA_A0_A1, 0x16B5_0073);
        assert_eq!(SINVAL_VMA_A0, 0x1605_0073);
        assert_eq!(sinval_vma_word(10, 11) ^ 0x12B5_0073, 0x02 << 25, "funct7 0001011 against sfence.vma's 0001001");
        // Opcode SYSTEM, funct3 0, rd x0 in every one.
        for w in [SFENCE_W_INVAL, SFENCE_INVAL_IR, SINVAL_VMA_A0_A1, SINVAL_VMA_A0] {
            assert_eq!(w & 0x7FFF, 0x73, "{w:#x}");
        }
        // rs1 and rs2 sit in their fields, and x0 as rs2 means every ASID.
        assert_eq!(sinval_vma_word(5, 0) >> 15 & 0x1F, 5);
        assert_eq!(sinval_vma_word(0, 6) >> 20 & 0x1F, 6);
    }

    /// One page keeps `sfence.vma`; the bracket pays off from the second.
    #[test]
    fn the_bracket_is_used_from_the_second_page_and_only_when_on() {
        assert_eq!(SVINVAL_MIN_PAGES, 2);
        assert!(!use_svinval(true, 0));
        assert!(!use_svinval(true, 1));
        assert!(use_svinval(true, 2));
        assert!(use_svinval(true, 4096));
        assert!(!use_svinval(false, 2));
        assert!(!use_svinval(false, 4096));
    }

    /// The probe runs only when the choice is not `n`; its verdict is the
    /// decision. One test owns the global.
    #[test]
    fn the_selection_executes_the_probe_only_when_allowed() {
        use std::cell::Cell;
        assert!(!svinval_on(), "off until a boot selects it");
        let ran = Cell::new(false);
        assert!(!svinval_select(false, || { ran.set(true); true }), "Kconfig n");
        assert!(!ran.get(), "n must execute nothing");
        assert!(!svinval_on());
        assert!(!svinval_select(true, || { ran.set(true); false }), "the hart traps");
        assert!(ran.get());
        assert!(!svinval_on());
        assert!(svinval_select(true, || true));
        assert!(svinval_on());
        assert!(!svinval_select(false, || true), "a later `n` turns it off again");
        assert!(!svinval_on());
    }
}

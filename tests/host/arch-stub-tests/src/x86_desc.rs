// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The x86_64 port's pure encoders (`crates/core/arch-x86_64`: gdt, idt,
//! fpu, cpu, fork_regs), checked on the host against independent oracles:
//! Linux's GDT constants, the SDM's descriptor layouts, and the vector lists
//! hand-written in `kernel/src/entry/x86_64/asm/trap_entry.S`.

use azos_arch::cpu::{self, PerCpu};
use azos_arch::fork_regs::ForkRegs;
use azos_arch::{fpu, gdt, idt};

// ── GDT ────────────────────────────────────────────────────────────────────

/// Linux's `GDT_ENTRY_KERNEL_CS` / `_DS` / `_USER_DS` / `_USER_CS`
/// (arch/x86/kernel/cpu/common.c, `GDT_ENTRY_INIT(DESC_*, 0, 0xfffff)`).
#[test]
fn segments_match_linux_bit_for_bit() {
    assert_eq!(gdt::segment(true, 0), 0x00af_9b00_0000_ffff, "kernel code64");
    assert_eq!(gdt::segment(false, 0), 0x00cf_9300_0000_ffff, "kernel data");
    assert_eq!(gdt::segment(false, 3), 0x00cf_f300_0000_ffff, "user data");
    assert_eq!(gdt::segment(true, 3), 0x00af_fb00_0000_ffff, "user code64");
}

#[test]
fn table_slots_follow_the_selectors() {
    let t = gdt::table(0x1234_5000);
    assert_eq!(t[0], 0, "null");
    assert_eq!(t[(gdt::KERNEL_CS >> 3) as usize], gdt::segment(true, 0));
    assert_eq!(t[(gdt::KERNEL_DS >> 3) as usize], gdt::segment(false, 0));
    assert_eq!(t[(gdt::USER_DS >> 3) as usize], gdt::segment(false, 3));
    assert_eq!(t[(gdt::USER_CS >> 3) as usize], gdt::segment(true, 3));
    let tss = gdt::tss_descriptor(0x1234_5000, 103);
    assert_eq!(&t[(gdt::TSS_SEL >> 3) as usize..], &tss);
    assert_eq!(gdt::USER_CS & 3, 3);
    assert_eq!(gdt::USER_DS & 3, 3);
}

/// SDM Vol. 3A 8.2.3: limit 15:0, base 23:0, type 9 + P, limit 19:16,
/// base 31:24, then base 63:32 in the high quadword.
#[test]
fn tss_descriptor_splits_the_base() {
    let d = gdt::tss_descriptor(0xffff_8000_1234_5678, 103);
    assert_eq!(d[0], 0x1200_8934_5678_0067);
    assert_eq!(d[1], 0xffff_8000);
}

/// `syscall`: CS = STAR[47:32], SS = +8. `sysretq`: SS = STAR[63:48] + 8,
/// CS = STAR[63:48] + 16, RPL 3.
#[test]
fn star_names_the_table_selectors() {
    let syscall_cs = ((gdt::STAR >> 32) & 0xffff) as u16;
    let sysret_base = ((gdt::STAR >> 48) & 0xffff) as u16;
    assert_eq!(syscall_cs, gdt::KERNEL_CS);
    assert_eq!(syscall_cs + 8, gdt::KERNEL_DS);
    assert_eq!((sysret_base + 8) | 3, gdt::USER_DS);
    assert_eq!((sysret_base + 16) | 3, gdt::USER_CS);
    assert_eq!(gdt::STAR, 0x0013_0008_0000_0000);
}

#[test]
fn tss_layout_is_the_sdms() {
    assert_eq!(core::mem::size_of::<gdt::Tss>(), 104);
    assert_eq!(gdt::TSS_RSP0, 4);
    let t = gdt::Tss::new();
    let iomap = t.iomap_base;
    assert_eq!(iomap, 104, "I/O bitmap past the limit: every ring-3 port access faults");
}

// ── IDT ────────────────────────────────────────────────────────────────────

/// SDM Vol. 3A 6.14.1: offset 15:0, selector, IST, type/DPL/P, offset
/// 31:16; offset 63:32 in the high quadword.
#[test]
fn gate_packs_and_round_trips() {
    let h = 0xffff_ffff_8123_4567;
    let g = idt::gate(h, 0x08, 1, 0, idt::GateKind::Interrupt);
    assert_eq!(g[0], 0x8123_8e01_0008_4567);
    assert_eq!(g[1], 0xffff_ffff);
    assert_eq!(idt::gate_handler(g), h);
    let t = idt::gate(h, 0x08, 0, 3, idt::GateKind::Trap);
    assert_eq!((t[0] >> 40) & 0xff, 0xef, "P | DPL 3 | trap gate");
}

#[test]
fn kernel_gates_put_df_nmi_mc_on_ist_and_only_int3_into_in_ring3_reach() {
    for v in 0..idt::VECTORS {
        let g = idt::kernel_gate(v, 0x1000 + v as u64, gdt::KERNEL_CS);
        let ist = (g[0] >> 32) & 7;
        let dpl = (g[0] >> 45) & 3;
        let kind = (g[0] >> 40) & 0xf;
        assert_eq!(kind, 0xe, "vector {v}: interrupt gate (IF cleared on entry)");
        assert_eq!(ist, match v { 8 => 1, 2 => 2, 18 => 3, _ => 0 }, "vector {v} IST");
        assert_eq!(dpl, if v == 3 || v == 4 { 3 } else { 0 }, "vector {v} DPL");
        assert_eq!(idt::gate_handler(g), 0x1000 + v as u64);
    }
    assert!(idt::SYSCALL_VECTOR >= idt::VECTORS as u64, "no IDT vector can pose as a syscall");
}

/// The SDM's error-code vectors (Table 6-1, plus #CP 21, #VC 29, #SX 30).
#[test]
fn error_code_vectors_are_the_sdms() {
    let with: Vec<usize> = (0..32).filter(|&v| idt::has_error_code(v)).collect();
    assert_eq!(with, [8, 10, 11, 12, 13, 14, 17, 21, 29, 30]);
    assert_eq!(idt::vector_name(14), "#PF page fault");
    assert_eq!(idt::vector_name(200), "interrupt");
}

/// Evaluate one `.if` condition of trap_entry.S's stub loop for `vec`:
/// a disjunction of `(vec == N)` and `((vec >= A) && (vec <= B))` terms.
fn asm_condition(line: &str, vec: usize) -> bool {
    let body = line.trim().strip_prefix(".if").expect(".if line").trim();
    body.split("||").any(|term| {
        let t: String = term.chars().filter(|c| !c.is_whitespace() && *c != '(' && *c != ')').collect();
        if let Some(n) = t.strip_prefix("vec==") {
            vec == n.parse::<usize>().expect("vector number")
        } else {
            let (lo, hi) = t.split_once("&&").expect("range term");
            let lo = lo.strip_prefix("vec>=").expect(">=").parse::<usize>().unwrap();
            let hi = hi.strip_prefix("vec<=").expect("<=").parse::<usize>().unwrap();
            (lo..=hi).contains(&vec)
        }
    })
}

/// The stub loop in trap_entry.S hard-codes which vectors get a dummy
/// error code and which go to the IST path; both lists must be the idt
/// module's. A wrong list misaligns every frame of that vector.
#[test]
fn asm_stub_lists_match_the_idt_module() {
    let asm = include_str!("../../../../kernel/src/entry/x86_64/asm/trap_entry.S");
    let ifs: Vec<&str> = asm.lines().filter(|l| l.trim_start().starts_with(".if (vec")).collect();
    assert_eq!(ifs.len(), 2, "the error-code and IST conditions");
    for v in 0..idt::VECTORS {
        assert_eq!(asm_condition(ifs[0], v), idt::has_error_code(v), "vector {v}: error code");
        assert_eq!(asm_condition(ifs[1], v), idt::ist_for(v) != 0, "vector {v}: IST path");
    }
}

// ── per-CPU area, FP ───────────────────────────────────────────────────────

#[test]
fn percpu_offsets_the_asm_uses() {
    assert_eq!(cpu::PERCPU_CPU_ID, 0, "hart_id is `mov %gs:0`");
    assert_eq!(cpu::PERCPU_TSS_RSP0, core::mem::offset_of!(PerCpu, tss) + 4);
    let offs = [cpu::PERCPU_CPU_ID, cpu::PERCPU_KERNEL_RSP, cpu::PERCPU_USER_RSP, cpu::PERCPU_FP_LIVE];
    for (i, a) in offs.iter().enumerate() {
        for b in &offs[i + 1..] {
            assert_ne!(a, b);
        }
    }
    assert_eq!(core::mem::align_of::<PerCpu>(), 64);
}

#[test]
fn syscall_mask_clears_if_tf_df_ac() {
    for bit in [cpu::RFLAGS_IF, cpu::RFLAGS_TF, cpu::RFLAGS_DF, cpu::RFLAGS_AC, cpu::RFLAGS_NT] {
        assert_ne!(cpu::SYSCALL_RFLAGS_MASK & bit, 0);
    }
    assert!(cpu::is_canonical_user(0x7fff_ffff_f000));
    assert!(!cpu::is_canonical_user(0x8000_0000_0000));
}

#[test]
fn xcr0_takes_the_largest_set_that_fits() {
    let sizes = |m: u64| match m {
        0x3 => 576,
        0x7 => 832,
        0xe7 => 2696,
        _ => usize::MAX,
    };
    let all = fpu::XCR0_X87 | fpu::XCR0_SSE | fpu::XCR0_AVX | fpu::XCR0_AVX512;
    assert_eq!(fpu::choose_xcr0(all, 2752, sizes), Some((0xe7, 2696)));
    assert_eq!(fpu::choose_xcr0(all, 1024, sizes), Some((0x7, 832)), "AVX-512 does not fit: AVX");
    assert_eq!(fpu::choose_xcr0(0x3, 1024, sizes), Some((0x3, 576)));
    assert_eq!(fpu::choose_xcr0(all, 512, sizes), None);
    assert_eq!(fpu::choose_xcr0(0x1, 4096, sizes), None, "no SSE: no x86_64 user state");
}

#[test]
fn initial_fp_image_is_fninit_and_reset_mxcsr() {
    let r = ForkRegs::<1024>::default();
    assert_eq!(&r.fp[0..2], &0x037fu16.to_le_bytes());
    assert_eq!(&r.fp[24..28], &0x1f80u32.to_le_bytes());
    assert!(r.fp[512..576].iter().all(|&b| b == 0), "XSAVE header: every component in init state");
    assert_eq!(core::mem::offset_of!(ForkRegs<1024>, fp) % 64, 0);
    assert_eq!(core::mem::align_of::<ForkRegs<1024>>(), 64);
}

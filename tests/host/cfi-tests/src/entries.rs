// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! A landing pad at every global assembly entry, aarch64 and x86_64.
//!
//! riscv64 is not scanned: it has no CFI symbol and its assembly carries no
//! landing pad (config/subsys/Kconfig.topology says why).

use crate::scan::{check, scan, without_pad_after, Isa, Missing};
use std::collections::BTreeSet;

/// One scanned source and the symbols that carry no pad, each with the reason.
struct Src {
    path: &'static str,
    isa: Isa,
    exempt: &'static [(&'static str, &'static str)],
}

const A64_DIRECT: &str = "reached only by a direct `bl`; BTI checks indirect branches";

const SOURCES: &[Src] = &[
    Src {
        path: "kernel/src/entry/aarch64/asm/boot.S",
        isa: Isa::Aarch64,
        exempt: &[(
            "_start",
            "the Image header: its first instruction is `code0`, the branch past the header; \
             the loader enters it before translation is on",
        )],
    },
    Src {
        path: "kernel/src/entry/aarch64/asm/trap_entry.S",
        isa: Isa::Aarch64,
        exempt: &[("_vectors", "the vector table: exceptions enter it, no branch does")],
    },
    Src { path: "kernel/src/entry/aarch64/asm/context_switch.S", isa: Isa::Aarch64, exempt: &[] },
    Src { path: "arch/aarch64/src/cpu/cfi.rs", isa: Isa::Aarch64, exempt: &[] },
    Src {
        path: "arch/aarch64/src/spin.rs",
        isa: Isa::Aarch64,
        exempt: &[
            ("azos_spin_swpa_llsc32", "the target of `bl` at every patched probe site"),
            ("azos_spin_ldseta_llsc32", "the target of `bl` at every patched probe site"),
            ("azos_spin_tas_tramp32", "the target of `bl` at every patched probe site"),
        ],
    },
    Src {
        path: "arch/aarch64/src/ext/sha2_ce.rs",
        isa: Isa::Aarch64,
        exempt: &[("azos_sha256_ce_blocks", A64_DIRECT)],
    },
    Src {
        path: "arch/aarch64/src/mmu/boot.rs",
        isa: Isa::Aarch64,
        exempt: &[("_azos_drop_to_el1", "called by `bl` from boot.S, before translation is on")],
    },
    Src {
        path: "kernel/src/entry/x86_64/asm/boot.S",
        isa: Isa::X86_64,
        // `_start` is 32-bit code (skipped by the scanner's mode tracking); the
        // exception stubs run on the boot IDT, before CR4.CET is set.
        exempt: &[("long_entry", "far-jumped to from the 32-bit boot stage, before CR4.CET is set; global because boot-pa-x86_64.ld names it")],
    },
    Src { path: "kernel/src/entry/x86_64/asm/ap_entry.S", isa: Isa::X86_64, exempt: &[] },
    Src { path: "kernel/src/entry/x86_64/asm/context_switch.S", isa: Isa::X86_64, exempt: &[] },
    Src { path: "kernel/src/entry/x86_64/asm/trap_entry.S", isa: Isa::X86_64, exempt: &[] },
    Src {
        path: "arch/x86_64/src/spin.rs",
        isa: Isa::X86_64,
        exempt: &[("azos_spin_tas_tramp32", "the target of `call` at every probe site")],
    },
    Src {
        path: "arch/x86_64/src/ext/retpoline.rs",
        isa: Isa::X86_64,
        exempt: &[("__x86_indirect_thunk_r11", "the target of the compiler's direct `call`/`jmp` (-Z retpoline-external-thunk)")],
    },
    Src {
        path: "arch/x86_64/src/ext/ap_trampoline.S",
        isa: Isa::X86_64,
        exempt: &[
            ("x86_ap_start64", "entered by a far jump on an AP that has not set CR4.CET"),
            ("x86_ap_start64_high", "entered by a far jump on an AP that has not set CR4.CET"),
        ],
    },
];

fn text_of(s: &Src) -> String {
    let t = std::fs::read_to_string(crate::repo().join(s.path)).unwrap_or_else(|e| panic!("{}: {e}", s.path));
    if cfg!(feature = "pad-canary") && s.path.ends_with("x86_64/asm/trap_entry.S") {
        // `syscall_entry` without its pad: the scan must name it.
        return without_pad_after(&t, "syscall_entry:", s.isa);
    }
    t
}

fn missing(s: &Src) -> Vec<Missing> {
    let exempt: BTreeSet<&str> = s.exempt.iter().map(|(n, _)| *n).collect();
    scan(&text_of(s), s.isa, &exempt)
}

#[test]
fn entry_asm_has_a_pad_at_every_global_entry() {
    let mut bad = Vec::new();
    for s in SOURCES {
        for m in missing(s) {
            bad.push(format!("{}:{}: `{}` starts with `{}`", s.path, m.line, m.symbol, m.found));
        }
    }
    assert!(bad.is_empty(), "global assembly entries with no landing pad (add one, or exempt the symbol with its reason):\n{}", bad.join("\n"));
}

#[test]
fn the_scan_reaches_the_entries_it_is_for() {
    // A scan that parsed nothing would pass the row above.
    let mut seen = BTreeSet::new();
    for s in SOURCES {
        let exempt: BTreeSet<&str> = s.exempt.iter().map(|(n, _)| *n).collect();
        seen.extend(check(&text_of(s), s.isa, &exempt).0);
    }
    for want in [
        "context_switch", "_aarch64_secondary_entry", "aarch64_ret_to_user", "aarch64_ret_to_user_tls",
        "aarch64_ipc_resume_stub", "_azos_cfi_enable", "syscall_entry", "x86_64_ret_to_user",
        "x86_64_ipc_resume_stub", "_limine_start", "_secondary_start",
    ] {
        assert!(seen.contains(want), "the scan never looked at `{want}`: {seen:?}");
    }
}

#[test]
fn an_exemption_names_a_symbol_the_source_still_defines() {
    // A stale exemption would hide the day the symbol gains a caller through a pointer.
    for s in SOURCES {
        let t = text_of(s);
        for (name, _) in s.exempt {
            assert!(t.contains(&format!("{name}:")), "{}: exempt symbol `{name}` has no label any more", s.path);
        }
    }
}

#[test]
fn every_exemption_is_reasoned() {
    for s in SOURCES {
        for (name, why) in s.exempt {
            assert!(why.len() > 20, "{}: `{name}` is exempt without a reason", s.path);
        }
    }
}

// ── the scanner itself, on fixtures ─────────────────────────────────────────

fn fixture(isa: Isa, text: &str) -> Vec<String> {
    scan(text, isa, &BTreeSet::new()).into_iter().map(|m| m.symbol).collect()
}

#[test]
fn the_scanner_finds_a_bare_entry_and_passes_a_padded_one() {
    let x86 = ".section .text\n.globl a\n.globl b\na:\n  endbr64\n  ret\nb:\n  movq %rax, %rbx\n  ret\n";
    assert_eq!(fixture(Isa::X86_64, x86), vec!["b"]);
    let a64 = ".section .text\n.globl a\n.globl b\n.globl c\na:\n  hint #38\n  ret\nb:\n  mov x0, x1\n  ret\nc:\n  bti c\n  ret\n";
    assert_eq!(fixture(Isa::Aarch64, a64), vec!["b"]);
}

#[test]
fn the_scanner_skips_directives_data_and_32_bit_code() {
    let t = ".section .text\n.globl f\nf:\n  .balign 16\n  // a comment\n  endbr64\n  ret\n\
             .section .data\n.globl d\nd:\n  .quad 0\n\
             .section .text\n.code32\n.globl e\ne:\n  movl %eax, %ebx\n.code64\n\
             .pushsection .rodata\n.globl r\nr:\n .word 0\n.popsection\n";
    assert!(fixture(Isa::X86_64, t).is_empty(), "{:?}", fixture(Isa::X86_64, t));
}

#[test]
fn the_scanner_reads_global_asm_strings() {
    let t = "core::arch::global_asm!(\n    \".pushsection .text.t, \\\"ax\\\"\",\n    \".globl t\",\n    \"t:\",\n    \"    mov x0, x1\",\n    \".popsection\",\n);\n";
    assert_eq!(fixture(Isa::Aarch64, t), vec!["t"]);
    let ok = t.replace("\"    mov x0, x1\"", "\"    hint #34\",\n    \"    mov x0, x1\"");
    assert!(fixture(Isa::Aarch64, &ok).is_empty());
}

// ── what the pads are for ──────────────────────────────────────────────────

fn read(rel: &str) -> String {
    std::fs::read_to_string(crate::repo().join(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"))
}

#[test]
fn the_x86_vector_stubs_start_with_a_pad_and_fit_their_slot() {
    let t = read("kernel/src/entry/x86_64/asm/trap_entry.S");
    let rept = t.find(".rept 256").expect("the stub loop");
    let body = &t[rept..rept + 900];
    let pad = body.find("endbr64").expect("a pad in the stub");
    let push = body.find("pushq").expect("a push in the stub");
    assert!(pad < push, "the pad must be the stub's first instruction");
    assert!(t.contains(".org stub_start + STUB_ALIGN"), "the size guard of the 16-byte slot is gone");
    assert!(t.contains(".equ STUB_ALIGN,    16"), "STUB_ALIGN changed: re-check that endbr64 + the longest stub still fit");
}

#[test]
fn the_x86_context_switch_resumes_through_a_return_when_ibt_is_on() {
    // The resume address is the instruction after a `call`, no ENDBR64: an
    // indirect `jmp` (or the retpoline thunk's) would be a #CP. The IBT arm
    // (`.if CET_IBT`) must be the `ret`; the indirect forms live in the
    // `.elseif`/`.else` arms, which an `n` build takes.
    let t = read("kernel/src/entry/x86_64/asm/context_switch.S");
    let code: String = t.lines().filter(|l| !l.trim_start().starts_with("//")).collect::<Vec<_>>().join("\n");
    let a = code.find(".if CET_IBT").expect("the IBT arm of the resume is gone");
    let ibt = &code[a..code[a..].find(".elseif MIT_THUNK").map(|i| a + i).expect("the thunk arm is gone")];
    assert!(!ibt.contains("jmp *") && !ibt.contains("__x86_indirect_thunk"), "an indirect jump into the resumed task under IBT: {ibt}");
    assert!(ibt.contains("pushq %rax\n    ret"), "the resume `ret` is gone: {ibt}");
    let rest = &code[a + ibt.len()..];
    assert!(rest.contains("jmp __x86_indirect_thunk_r11") && rest.contains("jmp *%rax"),
        "the n build lost its original resume: {rest}");
}

#[test]
fn the_aarch64_boot_branch_targets_carry_bti_j() {
    // `br x9` after the move into the upper half, primary and secondary.
    let t = read("kernel/src/entry/aarch64/asm/boot.S");
    for label in ["1:", "2:"] {
        let needle = format!("    br      x9\n{label}\n    hint    #36");
        assert!(t.contains(&needle), "the `br x9` target `{label}` lost its `bti j`");
    }
}

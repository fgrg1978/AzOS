// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! **No code reads the hart id and then a per-hart table with interrupts on.**
//!
//! `current_cpu_id()` (or `ARCH.hart_id()`, `percpu_id()`, `this_cpu()`) is one
//! step, the table read the id indexes is another; with interrupts on, a tick
//! between them can move the task to another hart and the second step then
//! answers for the hart the task left (found 2026-10-20 as a kernel page fault
//! copying to a user VA; the front `percpu-hazard-b` audited the rest of the
//! tree, its table is in the commit that added this file).
//!
//! This is the lexical lint over the files that audit covered. A read of the
//! hart id in them is accepted when, in its enclosing function,
//!
//! - a mask (`disable_all`, `irq_off`, `IrqOff::new`, `critical_section`,
//!   `lock_irqsave`, `with_cpu`, `cli`, `lock_local`, `irq_save`) comes
//!   before it and no `restore` closes that mask before the read; or
//! - a `percpu-hint:` comment says why a stale id is harmless there (a
//!   placement hint, a statistic, a context that already runs with interrupts
//!   off or cannot move). The tag goes in the function's body or in the
//!   comment block right above its signature, and carries a reason.
//!
//! Not scanned, by design: `kernel/` (trap and interrupt entries, the boot, the
//! smokes and ktests run with interrupts off, on the boot hart before the
//! scheduler or pinned; the audit table lists each site), `crates/core/sched/
//! src/scheduler/` (the front `percpu-accessor-race` owns it) and the ISA crates'
//! boot and hypervisor code but x86_64's. A new file of the scanned crates is
//! picked up by its directory.

use std::fs;
use std::path::Path;

const ROOT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../..");

/// The reads of the hart id this lint knows. Wrappers around them
/// (`kheap::me`, `kheap_census::hart`, ...) carry the tag themselves.
const READS: &[&str] = &["current_cpu_id()", "hart_id()", "percpu_id()", "this_cpu()"];

/// A mask: the hart id read after one of these (and before its restore) is
/// the hart that runs the rest of the window.
const MASKS: &[&str] = &[
    "disable_all(",
    "irq_off(",
    "IrqOff::new(",
    "critical_section(",
    "lock_irqsave(",
    "with_cpu(",
    "cli()",
    "lock_local(",
    "irq_save(",
];

/// What closes a mask.
const RESTORES: &[&str] = &["restore(", "sti()", "drop(irq", "drop(prev"];

const TAG: &str = "percpu-hint:";

/// Directories of the scanned crates: every `*.rs` directly in them.
const DIRS: &[&str] = &[
    "crates/core/sched/src",
    "crates/core/mm/src",
    "crates/core/sync/src",
    "crates/core/syscall/src",
    "crates/core/actuation/src",
    "crates/drivers/sys/src",
    "crates/drivers/irqchip/src",
    "crates/core/arch-x86_64/src",
    "crates/core/arch-x86_64/src/ext/hv",
];

/// Single files of the ISA crates whose other files are boot or hypervisor code.
const FILES: &[&str] = &[
    "crates/core/arch-riscv64/src/tlb.rs",
    "crates/core/arch-riscv64/src/api_impl.rs",
    "crates/core/arch-riscv64/src/platform_impl.rs",
    "crates/core/arch-riscv64/src/cpu.rs",
    "crates/core/arch-aarch64/src/api_impl.rs",
    "crates/core/arch-aarch64/src/platform_impl.rs",
    "crates/core/arch-aarch64/src/cpu/mod.rs",
];

/// A function that IS the accessor (its callers are the sites).
const ACCESSORS: &[&str] = &["hart_id", "current_cpu_id", "percpu_id", "this_cpu", "hw_cpu_id", "percpu_base"];

fn read(rel: &str) -> String {
    fs::read_to_string(Path::new(ROOT).join(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"))
}

fn rs_files() -> Vec<String> {
    let mut out: Vec<String> = FILES.iter().map(|s| s.to_string()).collect();
    for d in DIRS {
        let dir = Path::new(ROOT).join(d);
        let mut names: Vec<String> = fs::read_dir(&dir)
            .unwrap_or_else(|e| panic!("{d}: {e}"))
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().is_some_and(|x| x == "rs"))
            .map(|e| format!("{d}/{}", e.file_name().to_string_lossy()))
            .collect();
        names.sort();
        out.extend(names);
    }
    out
}

/// The code of a line: its `//` comment cut (a `///` or `//!` doc line is all
/// comment).
fn code_of(line: &str) -> &str {
    match line.find("//") {
        Some(i) => &line[..i],
        None => line,
    }
}

fn is_comment(line: &str) -> bool {
    line.trim_start().starts_with("//")
}

/// The name a signature line declares, if it declares a function.
fn fn_name(line: &str) -> Option<String> {
    let c = code_of(line);
    let t = c.trim_start();
    // `fn` as a whole word at the start or after the qualifiers.
    let at = if t.starts_with("fn ") {
        Some(3)
    } else {
        ["pub ", "pub(crate) ", "pub(super) ", "const ", "unsafe ", "extern \"C\" ", "async "]
            .iter()
            .fold(Some(t), |acc, q| acc.map(|a| a.strip_prefix(q).unwrap_or(a)))
            .and_then(|r| r.strip_prefix("fn "))
            .map(|r| t.len() - r.len())
    }?;
    let name: String = t[at..].chars().take_while(|ch| ch.is_alphanumeric() || *ch == '_').collect();
    (!name.is_empty()).then_some(name)
}

/// The last read of the hart id in `code` (a whole word: `svm_enabled_this_cpu()`
/// is not `this_cpu()`), as its byte offset.
fn read_at(code: &str) -> Option<usize> {
    READS
        .iter()
        .flat_map(|r| code.match_indices(r).map(|(i, _)| i))
        .filter(|&i| !code[..i].chars().next_back().is_some_and(|c| c.is_alphanumeric() || c == '_'))
        .max()
}

/// One finding: `(line number from 1, the line)`.
type Finding = (usize, String);

/// The reads in `src` that are neither masked nor tagged.
fn unguarded_reads(src: &str) -> Vec<Finding> {
    let lines: Vec<&str> = src.lines().collect();
    let mut out = Vec::new();
    for (i, l) in lines.iter().enumerate() {
        let code = code_of(l);
        if is_comment(l) || read_at(code).is_none() {
            continue;
        }
        // The signature of the accessor itself is not a read.
        if fn_name(l).is_some_and(|n| ACCESSORS.contains(&n.as_str())) {
            continue;
        }
        // The enclosing function: the nearest signature above.
        let Some(j) = (0..=i).rev().find(|&k| fn_name(lines[k]).is_some()) else {
            out.push((i + 1, l.to_string()));
            continue;
        };
        let name = fn_name(lines[j]).unwrap();
        if ACCESSORS.contains(&name.as_str()) {
            continue;
        }
        // A tag in the comment block above the signature, or in the body.
        let mut top = j;
        while top > 0 && (is_comment(lines[top - 1]) || lines[top - 1].trim_start().starts_with("#[")) {
            top -= 1;
        }
        if lines[top..=i].iter().any(|k| k.contains(TAG)) {
            continue;
        }
        // The last mask before the read, with no restore between it and the read.
        let body: String = lines[j..=i]
            .iter()
            .enumerate()
            .map(|(n, k)| if n == i - j { code } else { code_of(k) })
            .collect::<Vec<_>>()
            .join("\n");
        let before = &body[..body.len() - code.len() + read_at(code).unwrap()];
        let last_mask = MASKS.iter().filter_map(|m| before.rfind(m)).max();
        let masked = last_mask.is_some_and(|m| !RESTORES.iter().any(|r| before[m..].contains(r)));
        if !masked {
            out.push((i + 1, l.to_string()));
        }
    }
    out
}

#[test]
fn no_scanned_file_reads_the_hart_id_with_interrupts_on() {
    let mut bad = Vec::new();
    for f in rs_files() {
        for (n, l) in unguarded_reads(&read(&f)) {
            bad.push(format!("{f}:{n}: {}", l.trim()));
        }
    }
    assert!(
        bad.is_empty(),
        "these read the hart id with nothing masked in their function; mask before the read \
         (`disable_all`, `irq_off`, `critical_section`), or tag the function with `// {TAG} <why a stale id is harmless>`:\n{}",
        bad.join("\n")
    );
}

#[test]
fn every_tag_carries_a_reason() {
    let mut bad = Vec::new();
    for f in rs_files() {
        for (n, l) in read(&f).lines().enumerate() {
            if let Some(at) = l.find(TAG) {
                if l[at + TAG.len()..].trim().len() < 8 {
                    bad.push(format!("{f}:{}: {}", n + 1, l.trim()));
                }
            }
        }
    }
    assert!(bad.is_empty(), "a `{TAG}` tag with no reason:\n{}", bad.join("\n"));
}

// ── the lint itself ────────────────────────────────────────────────────────

#[test]
fn the_lint_flags_a_read_before_the_mask() {
    let src = "fn f() {\n    let cpu = current_cpu_id();\n    let irq = ARCH.disable_all();\n    use_it(cpu);\n    ARCH.restore(irq);\n}\n";
    assert_eq!(unguarded_reads(src).len(), 1);
}

#[test]
fn the_lint_accepts_a_read_inside_the_mask() {
    let src = "fn f() {\n    let irq = ARCH.disable_all();\n    let cpu = ARCH.hart_id();\n    use_it(cpu);\n    ARCH.restore(irq);\n}\n";
    assert!(unguarded_reads(src).is_empty());
}

#[test]
fn the_lint_flags_a_read_after_the_mask_was_closed() {
    let src = "fn f() {\n    let irq = ARCH.disable_all();\n    step();\n    ARCH.restore(irq);\n    let cpu = ARCH.hart_id();\n}\n";
    assert_eq!(unguarded_reads(src).len(), 1);
}

#[test]
fn the_lint_accepts_a_remask_after_a_restore() {
    let src = "fn f() {\n    let t = irq_off();\n    irq_restore(t);\n    work();\n    let t = irq_off();\n    let cpu = ARCH.hart_id();\n    irq_restore(t);\n}\n";
    assert!(unguarded_reads(src).is_empty());
}

#[test]
fn the_lint_accepts_a_tag_and_flags_its_absence() {
    let tagged = "/// A hint.\n// percpu-hint: placement only, a stale hart costs a worse choice\nfn f() -> usize {\n    current_cpu_id()\n}\n";
    assert!(unguarded_reads(tagged).is_empty());
    let bare = "fn f() -> usize {\n    current_cpu_id()\n}\n";
    assert_eq!(unguarded_reads(bare).len(), 1);
}

#[test]
fn a_tag_of_another_function_does_not_cover_this_one() {
    let src = "// percpu-hint: this one is a hint, whatever follows\nfn a() -> usize {\n    current_cpu_id()\n}\n\nfn b() -> usize {\n    current_cpu_id()\n}\n";
    assert_eq!(unguarded_reads(src).len(), 1, "the second function has no tag of its own");
}

#[test]
fn the_lint_ignores_comments_and_the_accessor_itself() {
    let src = "// calls current_cpu_id() in prose\n/// and hart_id() in a doc line\npub fn hart_id() -> usize {\n    read_tp()\n}\nfn g() {\n    // this_cpu() here is only a word\n}\n";
    assert!(unguarded_reads(src).is_empty());
}

// ── the fixed sites keep their window around the right operations ──────────

/// The text of the function `sig` names, from its signature to the next
/// signature at the same indentation or the end of the file.
fn body(src: &str, sig: &str) -> String {
    let at = src.find(sig).unwrap_or_else(|| panic!("`{sig}` moved"));
    let rest = &src[at..];
    let indent = src[..at].rsplit('\n').next().map_or(0, |l| l.len());
    let mut end = rest.len();
    let mut off = 0;
    for (n, l) in rest.split_inclusive('\n').enumerate() {
        if n > 0 && fn_name(l).is_some() && l.len() - l.trim_start().len() <= indent {
            end = off;
            break;
        }
        off += l.len();
    }
    rest[..end].to_string()
}

fn in_order(b: &str, marks: &[&str]) {
    let mut at = 0;
    for m in marks {
        let Some(p) = b[at..].find(m) else { panic!("`{m}` missing or out of order in:\n{b}") };
        at += p + m.len();
    }
}

#[test]
fn timebase_program_masks_before_it_reads_the_hart() {
    let s = read("crates/drivers/sys/src/timebase.rs");
    in_order(&body(&s, "fn program("), &["disable_all()", "hart_id()", "set_timer(", "restore("]);
    in_order(&body(&s, "pub fn tick_restart("), &["disable_all()", "tick_stopped()", "programmed()", "program(", "restore("]);
}

#[test]
fn classes_current_masks_across_the_hart_and_its_slot() {
    let s = read("crates/core/sched/src/classes.rs");
    in_order(&body(&s, "pub fn current("), &["disable_all()", "current_cpu_id()", "current_idx", "restore("]);
}

#[test]
fn reserve_keeps_the_caller_on_its_hart_until_it_is_pinned() {
    let s = read("crates/core/sched/src/rt.rs");
    in_order(
        &body(&s, "pub fn reserve("),
        &["critical_section()", "current_cpu_id()", "cpu_affinity = cpu", "drop(admission)"],
    );
}

#[test]
fn the_offline_thread_checks_its_cpu_with_interrupts_off() {
    let s = read("crates/core/sched/src/smp.rs");
    in_order(&body(&s, "fn offline_thread("), &["disable_all()", "current_cpu_id() != cpu", "offline_here("]);
}

#[test]
fn the_heap_asks_whether_this_hart_is_inside_it_under_a_mask() {
    let s = read("crates/core/mm/src/kheap.rs");
    in_order(
        &body(&s, "fn with_heap<"),
        &["irq_off()", "OWNER.load", "irq_restore(", ".lock()", "let me = me()", "OWNER.store(me"],
    );
}

#[test]
fn the_mutex_holder_word_reads_hart_and_class_in_one_window() {
    let s = read("crates/core/sync/src/lockdep.rs");
    in_order(&body(&s, "fn holder_word_slow("), &["disable_all()", "hart_id()", "current_is_rt()", "restore("]);
}

#[test]
fn qsbr_decides_and_acts_on_the_return_to_user_on_one_cpu() {
    let s = read("crates/core/sync/src/qsbr.rs");
    in_order(&body(&s, "fn user_return("), &["disable_all()", "rt_cpu(this_cpu())", "eqs_enter_here()", "report_qs()", "restore("]);
    let at = s.find("impl Drop for TrapBoundary").expect("TrapBoundary's drop moved");
    let drop = &s[at..at + s[at..].find("\n}\n").expect("end of the impl")];
    assert!(drop.contains("user_return()") && !drop.contains("this_cpu()"), "the drop decides outside the window:\n{drop}");
}

#[test]
fn irq_enable_tests_the_hart_and_writes_its_file_under_a_mask() {
    let s = read("crates/drivers/irqchip/src/irqchip.rs");
    in_order(&body(&s, "pub fn enable_irq("), &["disable_all()", "hart_id()", "imsic::enable(", "restore("]);
    in_order(&body(&s, "pub fn disable_irq("), &["disable_all()", "hart_id()", "imsic::disable(", "restore("]);
}

#[test]
fn the_riscv_shootdown_flushes_and_reads_its_hart_in_one_window() {
    let s = read("crates/core/arch-riscv64/src/tlb.rs");
    in_order(
        &body(&s, "pub fn shootdown("),
        &["disable_all()", "read_satp()", "sfence_vma", "hart_id()", "restore(", "mark_space_stale(", "remote_sfence_vma"],
    );
    let a = read("crates/core/arch-riscv64/src/api_impl.rs");
    for sig in ["fn flush_tlb_all(", "fn flush_tlb_page("] {
        in_order(&body(&a, sig), &["disable_all()", "sfence_vma", "mark_all_stale(crate::cpu::hart_id())", "restore("]);
    }
}

#[test]
fn the_x86_shootdown_flushes_and_reads_its_cpu_in_one_window() {
    let s = read("crates/core/arch-x86_64/src/tlb.rs");
    in_order(
        &body(&s, "pub fn shootdown("),
        &["disable_all()", "percpu_id()", "do_local", "restore(", "mark_space_stale(", "remote("],
    );
    in_order(&body(&s, "pub fn shootdown_kernel("), &["disable_all()", "percpu_id()", "do_local(", "restore(", "remote("]);
    // The request lock's wait serves the CPU it runs on (`serve_waiting`, the
    // lock waiters' hook too), read per call under a mask (`serve_here`).
    in_order(&body(&s, "fn remote("), &["serve_waiting()", "post(", "send(mask)"]);
    in_order(&body(&s, "fn serve_here("), &["disable_all()", "percpu_id()", "serve_with(here", "restore("]);
    let l = read("crates/core/arch-x86_64/src/lib.rs");
    in_order(&body(&l, "fn flush_tlb_all("), &["disable_all()", "flush_all()", "mark_all_stale(self.hart_id())", "restore("]);
    in_order(
        &body(&read("crates/core/arch-x86_64/src/ext/hv/mod.rs"), "fn stage2_flush("),
        &["disable_all()", "vcpu::flush(vmid, crate::cpu::percpu_id()", "restore("],
    );
}

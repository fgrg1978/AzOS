// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `azos_common::hook` (security audit 2026-10-17, finding D): the set-once
//! semantics of a hook, and the linker-script half of the read-only seal.
//!
//! The seal itself (a hook set after it panics) lives in
//! `tests/ro_hooks_seal.rs`: sealing is process-global, so it gets a process
//! of its own and cannot turn the checks below into refusals.

use azos_common::hook::{Hook, SetError};

fn one(x: u32) -> u32 { x + 1 }
fn two(x: u32) -> u32 { x + 2 }

type F = fn(u32) -> u32;

#[test]
fn an_unset_hook_reads_none() {
    let h: Hook<F> = Hook::new("t");
    assert!(h.get().is_none());
    assert!(!h.is_set());
    assert_eq!(h.name(), "t");
}

#[test]
fn the_first_installer_wins_and_is_called_back() {
    let h: Hook<F> = Hook::new("t");
    assert_eq!(h.try_set(one), Ok(()));
    assert!(h.is_set());
    assert_eq!(h.get().unwrap()(1), 2);
}

/// The canary of the whole type: a second, different function is refused and
/// the first stays. If `try_set` were a plain store this reads 3.
#[test]
fn a_second_different_installer_is_refused() {
    let h: Hook<F> = Hook::new("t");
    h.try_set(one).unwrap();
    assert_eq!(h.try_set(two), Err(SetError::AlreadySet));
    assert_eq!(h.get().unwrap()(1), 2, "the first function must still be installed");
}

#[test]
fn installing_the_same_function_again_is_a_no_op() {
    let h: Hook<F> = Hook::new("t");
    h.try_set(one).unwrap();
    assert_eq!(h.try_set(one), Ok(()));
    assert_eq!(h.get().unwrap()(1), 2);
}

/// Hosted builds (this one) replace on `set`: the suites reinstall per test.
/// `try_set` stays strict, which is what the refusal tests above hold.
#[test]
fn a_hosted_set_replaces_but_try_set_does_not() {
    let h: Hook<F> = Hook::new("t");
    h.set(one);
    h.set(two);
    assert_eq!(h.get().unwrap()(1), 3);
    assert_eq!(h.try_set(one), Err(SetError::AlreadySet));
    h.clear_for_tests();
    assert!(h.get().is_none());
}

#[test]
fn the_macro_declares_a_usable_static() {
    azos_common::ro_hook! {
        /// A hook declared the way the kernel declares them.
        static DECLARED: fn() -> u8;
    }
    fn seven() -> u8 { 7 }
    assert!(DECLARED.get().is_none());
    DECLARED.try_set(seven).unwrap();
    assert_eq!(DECLARED.get().unwrap()(), 7);
    assert_eq!(DECLARED.name(), "DECLARED");
}

/// The relaxed reader returns the same function: the cheaper load changes
/// the ordering, not the value.
#[test]
fn the_relaxed_reader_agrees() {
    let h: Hook<F> = Hook::new("t");
    assert!(h.get_relaxed().is_none());
    h.try_set(two).unwrap();
    assert_eq!(h.get_relaxed().unwrap()(1), 3);
}

/// A hook is a word, its name and a zero-sized marker: the kernel carries
/// about eighty of them in one page.
#[test]
fn a_hook_is_small() {
    assert_eq!(core::mem::size_of::<Hook<fn()>>(), core::mem::size_of::<usize>() + core::mem::size_of::<&str>());
}

// ── The linker scripts ────────────────────────────────────────────────────

/// Every kernel linker script, as the build selects them (kernel/Makefile
/// rules: `linker.ld` riscv64 QEMU, `-vf2`/`-k1`/`-fleet`/`-embedded` the
/// riscv64 boards and profiles, `-aarch64`, `-x86_64` and its Limine twin).
const SCRIPTS: [(&str, &str); 8] = [
    ("linker.ld", include_str!("../../../../arch/riscv64/boot/linker.ld")),
    ("linker-vf2.ld", include_str!("../../../../arch/riscv64/boot/linker-vf2.ld")),
    ("linker-k1.ld", include_str!("../../../../arch/riscv64/boot/linker-k1.ld")),
    ("linker-fleet.ld", include_str!("../../../../arch/riscv64/boot/linker-fleet.ld")),
    ("linker-embedded.ld", include_str!("../../../../arch/riscv64/boot/linker-embedded.ld")),
    ("linker-aarch64.ld", include_str!("../../../../arch/aarch64/boot/linker-aarch64.ld")),
    ("linker-x86_64.ld", include_str!("../../../../arch/x86_64/boot/linker-x86_64.ld")),
    ("linker-x86_64-limine.ld", include_str!("../../../../arch/x86_64/boot/linker-x86_64-limine.ld")),
];

/// The scripts on disk are all of them: a ninth kernel script added without
/// the section fails here instead of linking an unprotected kernel.
#[test]
fn every_kernel_linker_script_is_covered() {
    let arch = concat!(env!("CARGO_MANIFEST_DIR"), "/../../../arch");
    let mut on_disk: Vec<String> = std::fs::read_dir(arch)
        .unwrap()
        .filter_map(|isa| std::fs::read_dir(isa.unwrap().path().join("boot")).ok())
        .flatten()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .filter(|n| n.starts_with("linker") && n.ends_with(".ld"))
        .collect();
    on_disk.sort();
    let mut listed: Vec<String> = SCRIPTS.iter().map(|(n, _)| n.to_string()).collect();
    listed.sort();
    assert_eq!(on_disk, listed, "arch/*/boot/linker*.ld and SCRIPTS disagree");
}

#[test]
fn every_kernel_linker_script_has_the_section_page_aligned_at_both_ends() {
    for (name, ld) in SCRIPTS {
        let at = ld.find(".data.ro_after_init :")
            .or_else(|| ld.find(".data.ro_after_init : "))
            .unwrap_or_else(|| panic!("{name}: no .data.ro_after_init output section"));
        let body = &ld[at..];
        let close = body.find('}').unwrap_or_else(|| panic!("{name}: section unterminated"));
        let sect = &body[..close];
        assert!(sect.contains("ALIGN("), "{name}: the section start is not aligned");
        let start = sect.find("__ro_after_init_start = .;").unwrap_or_else(|| panic!("{name}: no start symbol"));
        let input = sect.find("*(.data.ro_after_init)").unwrap_or_else(|| panic!("{name}: no input rule"));
        let realign = sect.rfind(". = ALIGN(").unwrap_or_else(|| panic!("{name}: the end is not aligned"));
        let end = sect.find("__ro_after_init_end = .;").unwrap_or_else(|| panic!("{name}: no end symbol"));
        assert!(start < input && input < realign && realign < end,
            "{name}: start symbol, input, re-align and end symbol are out of order");
    }
}

/// The discriminating check: `.data`'s own glob (`*(.data .data.*)`) would
/// take `.data.ro_after_init` input first if the section were listed after
/// it, and the hooks would be written into plain `.data`, never sealed.
#[test]
fn the_section_precedes_the_data_glob_and_sits_in_the_data_range() {
    for (name, ld) in SCRIPTS {
        let ro = ld.find(".data.ro_after_init :").unwrap_or_else(|| panic!("{name}: no section"));
        let glob = ld.find("*(.data .data.*)").unwrap_or_else(|| panic!("{name}: no .data glob"));
        assert!(ro < glob, "{name}: .data.ro_after_init is listed after the .data glob");
        let data_start = ld.find("_data_start = .;").unwrap_or_else(|| panic!("{name}: no _data_start"));
        let data_end = ld.find("_data_end = .;").unwrap_or_else(|| panic!("{name}: no _data_end"));
        assert!(data_start < ro && ro < data_end,
            "{name}: the section is outside [_data_start, _data_end), so W^X would never map it RW");
    }
}

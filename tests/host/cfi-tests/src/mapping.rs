// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Kconfig choices -> compiler flags, through the real Kconfig tree and
//! `tools/build/kconfig_to_cargo.py` (the one place that turns Kconfig into rustc
//! flags: kernel `--rustflags`, user images `--user-rustflags`).

use std::path::PathBuf;
use std::process::Command;

fn scratch(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("azos-cfi-mapping-{}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    d.join(name)
}

/// Expand a synthetic `.config` with the repository's Kconfig and return its path.
pub(crate) fn expand(name: &str, lines: &[&str]) -> PathBuf {
    let cfg = scratch(name);
    std::fs::write(&cfg, lines.join("\n") + "\n").unwrap();
    let out = Command::new("python3")
        .args(["-m", "olddefconfig"])
        .current_dir(crate::repo())
        .env("KCONFIG_CONFIG", &cfg)
        .output()
        .expect("python3");
    assert!(out.status.success(), "olddefconfig on {lines:?}: {}", String::from_utf8_lossy(&out.stderr));
    cfg
}

fn flags(cfg: &PathBuf, which: &str) -> String {
    let out = Command::new("python3")
        .arg(crate::repo().join("tools/build/kconfig_to_cargo.py"))
        .args([which, cfg.to_str().unwrap()])
        .current_dir(crate::repo())
        .output()
        .expect("python3");
    assert!(out.status.success(), "kconfig_to_cargo {which}: {}", String::from_utf8_lossy(&out.stderr));
    String::from_utf8(out.stdout).unwrap().trim().to_string()
}

/// Kernel and user flags both, since the pads belong in both.
fn both(cfg: &PathBuf) -> (String, String) {
    (flags(cfg, "--rustflags"), flags(cfg, "--user-rustflags"))
}

const A64: &str = "CONFIG_ARCH_AARCH64=y";
const X86: &str = "CONFIG_ARCH_X86_64=y";
const RV: &str = "CONFIG_ARCH_RISCV64=y";
const BP: &str = "-Z branch-protection=bti,pac-ret";
const CF: &str = "-Z cf-protection=branch";

#[test]
fn aarch64_probe_builds_bti_and_pac_ret_everywhere() {
    let (k, u) = both(&expand("a64.config", &[A64]));
    assert!(k.contains(BP), "kernel: {k}");
    assert!(u.contains(BP), "user: {u}");
}

#[test]
fn aarch64_each_extension_choice_drives_its_own_mode() {
    let (k, u) = both(&expand("a64-nobti.config", &[A64, "CONFIG_A64_BTI_NEVER=y"]));
    assert!(k.contains("-Z branch-protection=pac-ret") && !k.contains("bti"), "{k}");
    assert!(u.contains("-Z branch-protection=pac-ret") && !u.contains("bti"), "{u}");
    let (k, u) = both(&expand("a64-nopac.config", &[A64, "CONFIG_A64_PAUTH_NEVER=y"]));
    assert!(k.contains("-Z branch-protection=bti") && !k.contains("pac-ret"), "{k}");
    assert!(u.contains("-Z branch-protection=bti") && !u.contains("pac-ret"), "{u}");
    let (k, u) = both(&expand("a64-none.config", &[A64, "CONFIG_A64_BTI_NEVER=y", "CONFIG_A64_PAUTH_NEVER=y"]));
    assert!(!k.contains("branch-protection") && !u.contains("branch-protection"), "{k} | {u}");
}

#[test]
fn aarch64_require_builds_the_same_pads_and_adds_its_target_features() {
    let (k, u) = both(&expand("a64-85.config", &[A64, "CONFIG_AARCH64_LEVEL_8_5=y"]));
    assert!(k.contains(BP) && u.contains(BP), "{k} | {u}");
    for f in ["+paca", "+pacg", "+bti"] {
        assert!(k.contains(f), "kernel lacks {f}: {k}");
    }
}

#[test]
fn the_raspberry_pi_5_has_neither_extension_and_so_no_pads() {
    let defcfg = std::fs::read_to_string(crate::repo().join("config/defconfigs/robot-sbc-aarch64-dev+qemu+linux+gui.config")).unwrap();
    let mut lines: Vec<&str> = defcfg.lines().filter(|l| !l.contains("BOARD_")).collect();
    lines.push("CONFIG_BOARD_RPI5=y");
    let (k, u) = both(&expand("rpi5.config", &lines));
    assert!(!k.contains("branch-protection") && !u.contains("branch-protection"), "{k} | {u}");
}

#[test]
fn x86_64_ibt_drives_cf_protection_in_the_kernel_and_the_user_images() {
    let (k, u) = both(&expand("x86.config", &[X86]));
    assert!(k.contains(CF), "kernel: {k}");
    assert!(u.contains(CF), "user: {u}");
    let (k, u) = both(&expand("x86-never.config", &[X86, "CONFIG_X86_CET_IBT_NEVER=y"]));
    assert!(!k.contains("cf-protection") && !u.contains("cf-protection"), "{k} | {u}");
    let (k, u) = both(&expand("x86-req.config", &[X86, "CONFIG_X86_CET_IBT_REQUIRE=y"]));
    assert!(k.contains(CF) && u.contains(CF), "{k} | {u}");
}

#[test]
fn x86_64_without_xsaves_has_no_ibt_and_no_pads() {
    // CET IBT depends on XSAVES (config/arch/Kconfig.isa-x86_64): XSAVE `n` takes both to `n`.
    let (k, _) = both(&expand("x86-noxsave.config", &[X86, "CONFIG_X86_64_LEVEL_V1=y", "CONFIG_X86_XSAVE_NEVER=y"]));
    assert!(!k.contains("cf-protection"), "{k}");
}

#[test]
fn x86_64_shadow_stack_is_not_a_codegen_mode() {
    // Shadow stacks need no compiler support: `require` changes the flags not at all.
    let (k0, u0) = both(&expand("x86-ss0.config", &[X86]));
    let (k1, u1) = both(&expand("x86-ss1.config", &[X86, "CONFIG_X86_CET_SHSTK_REQUIRE=y"]));
    assert_eq!((k0, u0), (k1, u1));
}

#[test]
fn x86_64_retpoline_and_branch_protection_compose() {
    let (k, _) = both(&expand("x86-rt.config", &[X86]));
    assert!(k.contains(CF) && k.contains("-Z retpoline -Z retpoline-external-thunk"), "{k}");
}

#[test]
fn riscv64_has_no_cfi_codegen_and_no_choice() {
    // No Zicfilp symbol until the boot can probe and refuse it
    // (config/kernel/Kconfig.hardening, "Not done"): no pads in the kernel or the user images.
    let (k, u) = both(&expand("rv.config", &[RV]));
    assert!(!k.contains("cf-protection") && !k.contains("zicfilp"), "kernel: {k}");
    assert!(!u.contains("cf-protection") && !u.contains("zicfilp"), "user: {u}");
    let (k, _) = both(&expand("rv-bare.config", &[]));
    assert!(!k.contains("zicfilp"), "{k}");
    let out = std::fs::read_to_string(expand("rv-def.config", &[RV])).unwrap();
    assert!(!out.contains("ZICFILP"), "a riscv64 CFI symbol came back without its probe");
}

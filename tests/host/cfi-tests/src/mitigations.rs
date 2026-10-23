// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Arm speculation mitigations (`A64_MIT_*`), host side: the MIDR and ID
//! register -> verdict table of `ext/mitigations.rs`, and the Kconfig choices
//! -> policy path that feeds it. The table is pinned as the code states it
//! (Linux's lists as remembered), not as Arm does.

use crate::a64_mitigations::*;
use azos_arch_api::isa::ExtPolicy;

const PROBE: Policies = Policies { spectre_v2: ExtPolicy::Probe, ssb: ExtPolicy::Probe, bhb: ExtPolicy::Probe };
const REQUIRE: Policies = Policies { spectre_v2: ExtPolicy::Require, ssb: ExtPolicy::Require, bhb: ExtPolicy::Require };
const NEVER: Policies = Policies { spectre_v2: ExtPolicy::Never, ssb: ExtPolicy::Never, bhb: ExtPolicy::Never };

const CSV2: u64 = 1 << 56;
const SSBS: u64 = 1 << 4;
const ECBHB: u64 = 1 << 60;
const CLRBHB: u64 = 1 << 28;

fn arm(part: u16) -> Probe {
    Probe { implementer: IMPL_ARM, part, ..Probe::default() }
}

fn is_vulnerable(v: Verdict) -> bool {
    matches!(v, Verdict::Vulnerable(_))
}

#[test]
fn the_in_order_cores_are_not_affected_by_any() {
    for part in [A35, A53, A55, A510] {
        let r = decide(&arm(part), &PROBE);
        assert_eq!((r.spectre_v2, r.ssb, r.bhb), (Verdict::NotAffected, Verdict::NotAffected, Verdict::NotAffected), "{part:#x}");
        assert!(!r.clear_ssbs && !r.fw_ssbd && r.bhb_k == 0);
        // WORKAROUND_3 is asked of every unlisted core with none of the BHB bits.
        assert_eq!(wants(&arm(part), &PROBE), [false, false, true]);
    }
}

#[test]
fn an_arm_part_number_is_not_another_implementers() {
    // 0xD03 under another implementer is not a Cortex-A53.
    let p = Probe { implementer: 0x51, part: A53, ..Probe::default() };
    assert!(is_vulnerable(decide(&p, &PROBE).spectre_v2));
    assert_eq!(bhb_loop(0x51, A76), 0);
}

#[test]
fn a_cortex_a72_needs_all_three_and_has_nothing_yet() {
    let r = decide(&arm(A72), &PROBE);
    assert!(is_vulnerable(r.spectre_v2) && is_vulnerable(r.ssb) && is_vulnerable(r.bhb));
    assert_eq!(r.bhb_k, 8);
    assert_eq!(wants(&arm(A72), &PROBE), [true, true, false], "listed: the loop table answers, the firmware is not asked");
}

#[test]
fn the_bhb_loop_table_matches_the_linux_lists() {
    for (part, k) in [(A57, 8), (A72, 8), (A76, 24), (A76AE, 24), (A77, 24), (N1, 24)] {
        assert_eq!(bhb_loop(IMPL_ARM, part), k, "{part:#x}");
    }
    for part in [A78, A78AE, A78C, X1, X1C, A710, X2, N2, V1] {
        assert_eq!(bhb_loop(IMPL_ARM, part), 32, "{part:#x}");
    }
    for part in [A35, A53, A55, A510, 0xD09 /* A73 */, 0xD0A /* A75 */, 0xD4D /* A715 */] {
        assert_eq!(bhb_loop(IMPL_ARM, part), 0, "{part:#x}");
    }
}

#[test]
fn ssbs_closes_a_cortex_a76_but_not_its_branch_history() {
    let p = Probe { pfr1: SSBS, ..arm(A76) };
    let r = decide(&p, &PROBE);
    assert_eq!(r.ssb, Verdict::Mitigated);
    assert!(r.clear_ssbs && !r.fw_ssbd, "the bit is used, the firmware is not asked");
    assert!(is_vulnerable(r.bhb));
    assert_eq!(r.bhb_k, 24);
    assert_eq!(wants(&p, &PROBE), [true, false, false], "a listed core is not asked WORKAROUND_3");
}

#[test]
fn csv2_ecbhb_and_clrbhb_come_from_the_id_registers() {
    let p = Probe { pfr0: CSV2, mmfr1: ECBHB, ..arm(A76) };
    let r = decide(&p, &PROBE);
    assert_eq!((r.spectre_v2, r.bhb), (Verdict::Hardware, Verdict::Hardware));
    assert_eq!(wants(&p, &PROBE), [false, true, false]);
    // CLRBHB without ECBHB: the instruction exists, it is not issued yet.
    let c = Probe { isar2: CLRBHB, ..arm(N2) };
    assert!(is_vulnerable(decide(&c, &PROBE).bhb));
    assert_eq!(wants(&c, &PROBE)[2], false, "with clrbhb the firmware's WORKAROUND_3 is not needed");
    // Every field reads as a nibble: a bit one position below does not count.
    let q = Probe { pfr0: CSV2 >> 1, pfr1: SSBS >> 1, mmfr1: ECBHB >> 1, isar2: CLRBHB >> 1, ..arm(A72) };
    assert!(!q.csv2() && !q.ssbs() && !q.ecbhb() && !q.clrbhb());
}

#[test]
fn a_core_on_no_list_reads_as_not_affected_by_bhb() {
    let r = decide(&Probe { pfr0: CSV2, pfr1: SSBS, ..arm(0xD4F) }, &PROBE);
    assert_eq!(r.bhb, Verdict::NotAffected);
    assert_eq!(r.bhb_k, 0);
    // ... unless the firmware says this PE needs ARCH_WORKAROUND_3 (Linux asks it of every core).
    let fw = Firmware { wa3: FwState::Offered, ..Firmware::default() };
    let r = decide(&Probe { pfr0: CSV2, pfr1: SSBS, fw, ..arm(0xD4F) }, &PROBE);
    assert!(is_vulnerable(r.bhb));
    let other = Probe { implementer: 0x51, part: 0x1, fw, ..Probe::default() };
    assert!(is_vulnerable(decide(&other, &PROBE).bhb));
    assert_eq!(wants(&other, &PROBE)[2], true);
}

#[test]
fn the_firmware_answers_decide_the_gaps() {
    let wa = |a, b, c| Firmware { wa1: a, wa2: b, wa3: c };
    // WORKAROUND_2 offered: the kernel calls it, once per CPU, and the bug is closed.
    let p = Probe { fw: wa(FwState::Absent, FwState::Offered, FwState::Absent), ..arm(A72) };
    let r = decide(&p, &PROBE);
    assert_eq!(r.ssb, Verdict::Mitigated);
    assert!(r.fw_ssbd && !r.clear_ssbs);
    // Offered but not issued at EL0 entry is a gap whose line says so.
    let p = Probe { fw: wa(FwState::Offered, FwState::Offered, FwState::Offered), ..arm(A72) };
    let r = decide(&p, &PROBE);
    let Verdict::Vulnerable(v2) = r.spectre_v2 else { panic!("{r:?}") };
    assert!(v2.contains("offers ARCH_WORKAROUND_1"));
    // An unlisted core the firmware flags: the WORKAROUND_3 line.
    let p = Probe { fw: wa(FwState::Unasked, FwState::Unasked, FwState::Offered), ..arm(0xD4F) };
    let Verdict::Vulnerable(b) = decide(&p, &PROBE).bhb else { panic!() };
    assert!(b.contains("offers ARCH_WORKAROUND_3"));
    // Absent: the other line.
    let r = decide(&arm(A72), &PROBE);
    let Verdict::Vulnerable(v2) = r.spectre_v2 else { panic!() };
    assert!(v2.contains("no ARCH_WORKAROUND_1"));
    // Not required on this PE: not affected, nothing to call.
    let p = Probe { fw: wa(FwState::NotRequired, FwState::NotRequired, FwState::NotRequired), ..arm(A76) };
    let r = decide(&p, &PROBE);
    assert_eq!((r.spectre_v2, r.ssb), (Verdict::NotAffected, Verdict::NotAffected));
    assert!(!r.fw_ssbd);
    // Canary: a listed core stays vulnerable to BHB whatever the firmware answers
    // (Linux consults the loop table first); an unlisted one takes the answer.
    assert!(is_vulnerable(r.bhb), "the firmware cannot switch BHB off for an A76");
    for part in [A72, A76, A78, N2] {
        let p = Probe { fw: wa(FwState::NotRequired, FwState::NotRequired, FwState::NotRequired), ..arm(part) };
        assert!(is_vulnerable(decide(&p, &PROBE).bhb), "{part:#x}");
    }
    let p = Probe { fw: wa(FwState::NotRequired, FwState::NotRequired, FwState::NotRequired), ..arm(0xD4F) };
    assert_eq!(decide(&p, &PROBE).bhb, Verdict::NotAffected);
    // A register bit wins over the firmware: SSBS is used, WORKAROUND_2 is not called.
    let p = Probe { pfr1: SSBS, fw: wa(FwState::Unasked, FwState::Offered, FwState::Unasked), ..arm(A76) };
    let r = decide(&p, &PROBE);
    assert!(r.clear_ssbs && !r.fw_ssbd);
}

#[test]
fn the_smccc_return_values_read_as_linux_reads_them() {
    use Workaround::*;
    assert_eq!(fw_state(Wa1, 0), FwState::Offered);
    assert_eq!(fw_state(Wa1, 1), FwState::NotRequired);
    assert_eq!(fw_state(Wa1, -1), FwState::Absent);
    assert_eq!(fw_state(Wa1, -2), FwState::Absent, "WORKAROUND_1 defines no NOT_REQUIRED");
    assert_eq!(fw_state(Wa2, 1), FwState::NotRequired);
    assert_eq!(fw_state(Wa2, -2), FwState::NotRequired);
    assert_eq!(fw_state(Wa2, -1), FwState::Absent);
    assert_eq!(fw_state(Wa3, -2), FwState::NotRequired);
    assert_eq!(fw_state(Wa3, 1), FwState::Absent, "WORKAROUND_3 defines no `1`: never read it as unaffected");
    assert_eq!(fw_state(Wa3, 0), FwState::Offered);
    assert_eq!((Wa1.fn_id(), Wa2.fn_id(), Wa3.fn_id()), (0x8000_8000, 0x8000_7FFF, 0x8000_3FFF));
}

#[test]
fn never_looks_at_nothing_and_asks_nothing() {
    for part in [A53, A72, A76, N2] {
        let p = Probe { pfr1: SSBS, ..arm(part) };
        let r = decide(&p, &NEVER);
        assert_eq!((r.spectre_v2, r.ssb, r.bhb), (Verdict::Off, Verdict::Off, Verdict::Off));
        assert!(!r.clear_ssbs && !r.fw_ssbd, "n leaves PSTATE.SSBS as the firmware set it");
        assert_eq!(wants(&p, &NEVER), [false; 3]);
        assert_eq!(r.refusal(&NEVER), None);
    }
}

#[test]
fn require_refuses_what_stays_vulnerable_and_names_the_symbol() {
    let r = decide(&arm(A72), &REQUIRE);
    let f = r.refusal(&REQUIRE).expect("an A72 stays vulnerable");
    assert_eq!((f.name, f.symbol), ("spectre_v2", "A64_MIT_SPECTRE_V2"));
    // Probe does not refuse, whatever the verdict.
    assert_eq!(r.refusal(&PROBE), None);
    // Only the required choice counts: v2 and bhb are open, ssb is required and closed.
    let pol = Policies { spectre_v2: ExtPolicy::Probe, ssb: ExtPolicy::Require, bhb: ExtPolicy::Probe };
    let p = Probe { pfr1: SSBS, ..arm(A72) };
    assert_eq!(decide(&p, &pol).refusal(&pol), None);
    let pol = Policies { spectre_v2: ExtPolicy::Probe, ssb: ExtPolicy::Probe, bhb: ExtPolicy::Require };
    assert_eq!(decide(&p, &pol).refusal(&pol).map(|f| f.symbol), Some("A64_MIT_BHB"));
    let pol = Policies { spectre_v2: ExtPolicy::Probe, ssb: ExtPolicy::Require, bhb: ExtPolicy::Probe };
    assert_eq!(decide(&arm(A72), &pol).refusal(&pol).map(|f| f.symbol), Some("A64_MIT_SSB"));
    // The Raspberry Pi 3 and a core with every bit boot under require.
    assert_eq!(decide(&arm(A53), &REQUIRE).refusal(&REQUIRE), None);
    let all = Probe { pfr0: CSV2, pfr1: SSBS, mmfr1: ECBHB, ..arm(A76) };
    assert_eq!(decide(&all, &REQUIRE).refusal(&REQUIRE), None);
}

// ---- Kconfig -> policy --------------------------------------------------

const BUGS: [(&str, &str); 3] = [
    ("SPECTRE_V2", "MIT_SPECTRE_V2"),
    ("SSB", "MIT_SSB"),
    ("BHB", "MIT_BHB"),
];

fn read(rel: &str) -> String {
    std::fs::read_to_string(crate::repo().join(rel)).unwrap()
}

/// The policy `azos_limits` builds for `bug` from an expanded `.config`: the
/// `_NEVER` and `_REQUIRE` members, `ExtPolicy::from_kconfig`.
fn policy(cfg: &str, bug: &str) -> ExtPolicy {
    let on = |m: &str| cfg.lines().any(|l| l == format!("CONFIG_A64_MIT_{bug}_{m}=y"));
    ExtPolicy::from_kconfig(on("NEVER"), on("REQUIRE"))
}

fn expanded(name: &str, lines: &[&str]) -> String {
    let mut l = vec!["CONFIG_ARCH_AARCH64=y"];
    l.extend_from_slice(lines);
    std::fs::read_to_string(crate::mapping::expand(name, &l)).unwrap()
}

#[test]
fn each_bug_is_a_never_probe_require_choice_defaulting_to_probe() {
    let cfg = expanded("mit-default.config", &[]);
    for (bug, _) in BUGS {
        for m in ["NEVER", "PROBE", "REQUIRE"] {
            let sym = format!("A64_MIT_{bug}_{m}");
            assert!(read("config/axes/Kconfig.security").contains(&format!("config {sym}\n")), "{sym} is declared");
        }
        assert!(cfg.contains(&format!("CONFIG_A64_MIT_{bug}_PROBE=y")), "{bug}: probe is the default");
        assert_eq!(policy(&cfg, bug), ExtPolicy::Probe);
    }
}

#[test]
fn a_choice_reaches_the_policy_the_boot_reads() {
    let cfg = expanded("mit-require.config", &["CONFIG_A64_MIT_SSB_REQUIRE=y", "CONFIG_A64_MIT_BHB_NEVER=y"]);
    assert_eq!(policy(&cfg, "SPECTRE_V2"), ExtPolicy::Probe, "a choice touches only its own bug");
    assert_eq!(policy(&cfg, "SSB"), ExtPolicy::Require);
    assert_eq!(policy(&cfg, "BHB"), ExtPolicy::Never);
    assert!(!cfg.contains("CONFIG_A64_MIT_SSB_PROBE=y"), "one member of a choice at a time");
}

#[test]
fn arch_api_reads_the_same_symbols_the_kconfig_declares() {
    let isa = read("crates/core/arch-api/src/isa.rs");
    for (bug, konst) in BUGS {
        let want = format!("pub const {konst}: ExtPolicy = ext_policy!(A64_MIT_{bug}_NEVER, A64_MIT_{bug}_REQUIRE);");
        assert!(isa.contains(&want), "{want}");
    }
}

#[test]
fn the_aarch64_choices_exist_on_aarch64_only() {
    for arch in ["CONFIG_ARCH_X86_64=y", "CONFIG_ARCH_RISCV64=y"] {
        let name = format!("mit-{}.config", &arch[12..arch.len() - 2]);
        let cfg = std::fs::read_to_string(crate::mapping::expand(&name, &[arch])).unwrap();
        assert!(!cfg.contains("A64_MIT_"), "{arch}");
    }
}

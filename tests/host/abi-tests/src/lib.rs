// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host-side tests for the `azos_abi` crate.
//!
//! The kernel-side crate is `no_std` and bound to RISC-V; running the
//! `#[cfg(test)]` suites inside it requires this excluded crate.

#[cfg(test)]
mod cap_tests {
    use azos_abi::cap::{CapHandle, CapKind, CapPerms, CAP_NULL, ty, CapType};

    /// How many slots the handle's slot field can address — **derived from
    /// the public `SLOT_BITS`, not restated.**
    ///
    /// This was a hardcoded `256`, documented as a deliberate fifth copy of
    /// that number (alongside Kconfig, `crates/core/ipc`, `abi`'s own private
    /// mirror and `crates/core/topology`'s parser). On 2026-09-18 `SLOT_BITS`
    /// went 8 → 9 to close a real defect — the fleet profile declared 512
    /// caps per task against a field that addressed 256, so slot 256 packed
    /// to the same handle as slot 0 — and this copy did not follow, which is
    /// exactly how a restated constant fails: the test kept asserting the
    /// old boundary and went red for the right change.
    ///
    /// Derived, it tracks the field automatically. What the tests below
    /// actually care about is the FIELD's width, which is what this now is.
    const ADDRESSABLE_SLOTS: u32 = 1 << CapHandle::SLOT_BITS;

    /// All 9 `CapKind` variants, in discriminant order.
    ///
    /// The length is written out rather than inferred so that adding a
    /// variant without adding it here is a compile error. An inferred
    /// `[CapKind; _]` would silently keep covering only the old set, which
    /// is the failure this array exists to prevent.
    const ALL_KINDS: [CapKind; 9] = [
        CapKind::Null,
        CapKind::Endpoint,
        CapKind::MemObj,
        CapKind::Queue,
        CapKind::Port,
        CapKind::Domain,
        CapKind::Node,
        CapKind::Device,
        CapKind::Log,
    ];

    /// Every named type (kind and class) the kernel's tables hold.
    const ALL_TYPES: [CapType; 12] = [
        ty::ENDPOINT,
        ty::PORT,
        ty::SHM,
        ty::IORING,
        ty::TASK,
        ty::FILE,
        ty::LAUNCH,
        ty::SOCKET,
        ty::IRQ,
        ty::MMIO,
        ty::DRIVER_REGISTRY,
        ty::TRACE,
    ];

    /// Every permission combination worth distinguishing: each single
    /// bit, the named unions, and the empty/full extremes.
    const ALL_PERMS: [CapPerms; 10] = [
        CapPerms::NONE,
        CapPerms::READ,
        CapPerms::WRITE,
        CapPerms::EXEC,
        CapPerms::DUP,
        CapPerms::TRANSFER,
        CapPerms::MAP,
        CapPerms::RW,
        CapPerms::RW_DELEGATE,
        CapPerms::ALL,
    ];

    #[test]
    fn null_is_zero() {
        assert!(CAP_NULL.is_null());
        assert_eq!(CAP_NULL.as_raw(), 0);
    }

    #[test]
    fn pack_unpack_round_trip() {
        // Slot is 8 bits wide post-widening (0..=255); 0xAB fits and
        // stays readable as hex.
        let h = CapHandle::pack(ty::PORT, CapPerms::RW_DELEGATE, 0x42, 0xAB);
        assert_eq!(h.kind(), ty::PORT.raw());
        assert!(h.perms().contains(CapPerms::READ));
        assert!(h.perms().contains(CapPerms::WRITE));
        assert!(h.perms().contains(CapPerms::DUP));
        assert!(!h.perms().contains(CapPerms::EXEC));
        assert_eq!(h.generation(), 0x42);
        assert_eq!(h.slot(), 0xAB);
    }

    /// Every named type round-trips through pack/unpack, crossed with every
    /// permission combination and the generation extremes.
    #[test]
    fn round_trip_every_type_perm_and_gen_extreme() {
        for &ty in &ALL_TYPES {
            for &perms in &ALL_PERMS {
                for &gen in &[0u16, CapHandle::MAX_GENERATION] {
                    for &slot in &[0u16, (ADDRESSABLE_SLOTS - 1) as u16] {
                        let h = CapHandle::pack(ty, perms, gen, slot);
                        assert_eq!(
                            h.kind(),
                            ty.raw(),
                            "type mismatch for {ty:?}/{perms:?}/gen={gen}/slot={slot}"
                        );
                        assert_eq!(
                            h.perms().bits(),
                            perms.bits(),
                            "perms mismatch for {ty:?}/{perms:?}/gen={gen}/slot={slot}"
                        );
                        assert_eq!(
                            h.generation(),
                            gen,
                            "generation mismatch for {ty:?}/{perms:?}/gen={gen}/slot={slot}"
                        );
                        assert_eq!(
                            h.slot(),
                            slot,
                            "slot mismatch for {ty:?}/{perms:?}/gen={gen}/slot={slot}"
                        );
                    }
                }
            }
        }
    }

    /// A type is a kind in the low four bits and a class in the high two; the
    /// handle's six-bit field holds all 64 values, 63 the largest. 63 must
    /// round-trip through the raw field and name no type. The 26-bit shift
    /// below is the documented wire position of the field (bits 31..26); it
    /// is not accessible as a public constant, so this test reconstructs it
    /// directly against the documented format rather than through `pack()`.
    #[test]
    fn max_representable_type_round_trips_but_names_nothing() {
        const KIND_SHIFT: u32 = 26;
        const MAX_KIND: u32 = 0x3F; // 6 bits: 63

        let h = CapHandle::from_raw(MAX_KIND << KIND_SHIFT);
        assert_eq!(h.kind(), 63, "the field must be able to hold 63");
        assert_eq!(CapType::from_raw(h.kind()), None, "63 is kind 15, class 3: no such kind");
    }

    /// Negative case: a slot index one past what the field can address must
    /// NOT round-trip — it silently truncates instead of being rejected,
    /// which is exactly the sharp edge callers must not hit. The fleet
    /// profile sat on the wrong side of this edge until 2026-09-18.
    /// The same sharp edge on the generation field. It matters more than the
    /// slot one: `crates/core/ipc` retires a slot at `MAX_GENERATION` precisely so a
    /// generation is never reissued, and a generation that truncated back to a
    /// live value would defeat that from the other side.
    #[test]
    fn generation_one_past_maximum_does_not_round_trip() {
        let one_past_max = CapHandle::MAX_GENERATION + 1;
        let h = CapHandle::pack(ty::PORT, CapPerms::RW, one_past_max, 3);
        assert_ne!(
            h.generation(),
            one_past_max,
            "a generation past the field must not survive packing"
        );
        assert_eq!(h.slot(), 3, "the slot field must not be disturbed by it");
        assert_eq!(h.kind(), ty::PORT.raw());
    }

    /// 11 bits since 2026-10-17 (13 before, 8 before that, which wrapped and
    /// reissued generations): two bits went to the `TRANSFER` and `MAP` rights.
    #[test]
    fn the_generation_field_holds_what_the_slot_retirement_rule_assumes() {
        assert_eq!(CapHandle::MAX_GENERATION, 2047, "11-bit generation field");
        let h = CapHandle::pack(ty::SHM, CapPerms::RW, CapHandle::MAX_GENERATION, 1);
        assert_eq!(h.generation(), CapHandle::MAX_GENERATION);
    }

    #[test]
    fn slot_one_past_maximum_does_not_round_trip() {
        let one_past_max = ADDRESSABLE_SLOTS as u16;
        let h = CapHandle::pack(ty::PORT, CapPerms::NONE, 0, one_past_max);
        assert_ne!(
            h.slot(),
            one_past_max,
            "slot={one_past_max} is one past the {ADDRESSABLE_SLOTS}-slot field and must not survive packing"
        );
        assert_eq!(h.slot(), 0, "it wraps to 0 — the handle collision the field width prevents");
    }

    #[test]
    fn perms_contains_logic() {
        assert!(CapPerms::ALL.contains(CapPerms::READ));
        assert!(CapPerms::ALL.contains(CapPerms::DUP));
        assert!(!CapPerms::READ.contains(CapPerms::WRITE));
        assert!(CapPerms::RW.contains(CapPerms::READ));
        assert!(CapPerms::RW.contains(CapPerms::WRITE));
        assert!(!CapPerms::RW.contains(CapPerms::DUP));
    }

    #[test]
    fn kind_from_raw_recognises_all() {
        for (raw, kind) in ALL_KINDS.iter().enumerate() {
            assert_eq!(CapKind::from_raw(raw as u8), Some(*kind), "kind {raw}");
            assert_eq!(kind.denial_code(), raw as u8, "a denial is recorded under the discriminant");
        }
        // The first tag past the last variant, and the byte's own maximum,
        // must both stay unpopulated. `from_raw` has no catch-all arm, so
        // this is the assertion that a future variant added to the enum
        // without an arm here is caught rather than aliasing.
        assert_eq!(CapKind::from_raw(9), None);
        for r in [azos_abi::cap::reserved_kind::VM, azos_abi::cap::reserved_kind::VCPU] {
            assert!(r > 9 && r < 16, "reserved tags sit after Thread (9)");
            assert_eq!(CapKind::from_raw(r), None, "a reserved tag is not a kind yet: fail closed");
        }
        assert_eq!(CapKind::from_raw(15), None);
        assert_eq!(CapKind::from_raw(16), None, "the class bits are not part of a kind");
        assert_eq!(CapKind::from_raw(255), None);
    }

    /// The decoder of a six-bit type: a named kind with any class below
    /// `CapType::CLASSES` is a type; a kind that does not exist, or bits past
    /// the field, are not.
    #[test]
    fn type_from_raw_recognises_exactly_the_kind_class_pairs() {
        assert_eq!(CapType::from_raw(0), Some(CapType::NULL));
        for raw in 0u8..=255 {
            let want = raw < 64 && CapKind::from_raw(raw & 0x0F).is_some();
            assert_eq!(CapType::from_raw(raw).is_some(), want, "raw {raw}");
        }
        // The named types sit where the micro kernel needs them: below 32 for
        // every type it hands out, so a handle never reads as a negative rv32
        // result.
        for t in [ty::ENDPOINT, ty::MMIO, ty::SHM, ty::LAUNCH] {
            assert!(t.raw() < 32, "{t:?}");
        }
    }

    /// Every named type survives the byte round trip, and no two share a raw
    /// value.
    #[test]
    fn every_type_decodes_back_to_itself() {
        for &t in &ALL_TYPES {
            assert_eq!(CapType::from_raw(t.raw()), Some(t), "{t:?} (raw {}) does not decode", t.raw());
            assert_eq!(CapType::new(t.kind(), t.class()), t);
        }
        let mut raws: Vec<u8> = ALL_TYPES.iter().map(|t| t.raw()).collect();
        raws.sort_unstable();
        raws.dedup();
        assert_eq!(raws.len(), ALL_TYPES.len(), "two types share a raw value");
    }

    #[test]
    fn nonzero_view() {
        let h = CapHandle::pack(ty::SHM, CapPerms::RW, 1, 7);
        assert!(h.as_nonzero().is_some());
        assert!(CAP_NULL.as_nonzero().is_none());
    }

    #[test]
    fn perms_union_intersection() {
        let r = CapPerms::READ;
        let w = CapPerms::WRITE;
        let rw = r.union(w);
        assert!(rw.contains(CapPerms::READ));
        assert!(rw.contains(CapPerms::WRITE));
        assert_eq!(rw.intersection(CapPerms::READ).bits(), CapPerms::READ.bits());
    }
}

#[cfg(test)]
mod error_tests {
    use azos_abi::error::Errno;

    #[test]
    fn round_trip_all_known_errnos() {
        let cases = [
            Errno::EPERM,
            Errno::ENOENT,
            Errno::EIO,
            Errno::EBADF,
            Errno::EAGAIN,
            Errno::ENOMEM,
            Errno::EACCES,
            Errno::EFAULT,
            Errno::EBUSY,
            Errno::EEXIST,
            Errno::ENODEV,
            Errno::EINVAL,
            Errno::ENOSYS,
            Errno::ENAMETOOLONG,
            Errno::ENOTEMPTY,
            Errno::ECANCELED,
            Errno::ENOTOWNER,
            Errno::ECAPKIND,
            Errno::ECAPPERMS,
            Errno::ECAPSTALE,
            Errno::ETOPOLOGY,
            Errno::ESAFETY,
            Errno::EAUTH,
            Errno::EREPLAY,
            Errno::EOTASIG,
            Errno::EROLLBACK,
            Errno::EQUOTA,
            Errno::EABIVERSION,
            Errno::EPEERDIED,
            Errno::EREVOKED,
            Errno::ENOSENDERS,
            Errno::EV1ACCEPT,
            Errno::EDEADLINE,
            Errno::ERTPROXY,
            Errno::EEOF,
            Errno::EPURGED,
            Errno::EINTR,
            Errno::EPIPE,
        ];
        for e in cases {
            let ret = e.to_syscall_ret();
            assert!(ret < 0, "{:?} maps to non-negative", e);
            assert_eq!(
                Errno::from_syscall_ret(ret),
                Some(e),
                "round-trip failure for {:?}",
                e
            );
        }
    }

    #[test]
    fn non_negative_is_not_error() {
        assert_eq!(Errno::from_syscall_ret(0), None);
        assert_eq!(Errno::from_syscall_ret(42), None);
        assert_eq!(Errno::from_syscall_ret(i64::MAX), None);
    }

    #[test]
    fn unknown_negative_returns_none() {
        // -999 is not in our errno table.
        assert_eq!(Errno::from_syscall_ret(-999), None);
    }

    #[test]
    fn cap_specific_errnos_have_expected_values() {
        // These wire-format numbers are part of the ABI freeze.
        assert_eq!(Errno::ECAPKIND as i64, 200);
        assert_eq!(Errno::ECAPPERMS as i64, 201);
        assert_eq!(Errno::ECAPSTALE as i64, 202);
    }

    /// U07-6: `crates/core/syscall`'s handlers have returned `-99` as their own
    /// `E_PERM` (`handlers.rs::E_PERM`, 30 call sites) since before this
    /// table existed. This pins the value AND that the table now resolves
    /// it — before this fix, `Errno::from_syscall_ret(-99)` was `None`
    /// despite `-99` being a real, common, deliberate return value from
    /// this ABI, contradicting `abi/src/lib.rs`'s claim to be the single
    /// source of truth for error codes.
    #[test]
    fn minus_99_is_a_real_errno_not_an_unknown_value() {
        assert_eq!(Errno::ENOTOWNER as i64, 99);
        assert_eq!(Errno::ENOTOWNER.to_syscall_ret(), -99);
        assert_eq!(Errno::from_syscall_ret(-99), Some(Errno::ENOTOWNER));
    }
}

#[cfg(test)]
mod types_tests {
    use core::mem::size_of;
    use azos_abi::types::{MotorOutput, RobotInfo, SafetyProfile, SensorState};

    /// These sizes are part of the ABI freeze. Changing them is a
    /// breaking change requiring a major version bump and a design review.
    #[test]
    fn sensor_state_size_is_stable() {
        assert_eq!(size_of::<SensorState>(), 48);
    }

    #[test]
    fn motor_output_size_is_stable() {
        assert_eq!(size_of::<MotorOutput>(), 12);
    }

    #[test]
    fn robot_info_size_is_stable() {
        assert_eq!(size_of::<RobotInfo>(), 8);
    }

    #[test]
    fn safety_profile_size_is_stable() {
        assert_eq!(size_of::<SafetyProfile>(), 24);
    }
}

/// `SYS_INVOKE`'s wire format (`azos_abi::invoke`).
#[cfg(test)]
mod invoke_abi {
    use azos_abi::cap::ty;
    use azos_abi::invoke::*;

    /// `tools/syscall_defs.py` hands the hand-assembled test programs the raw
    /// type of the console (`CONSOLE_TYPE`); the micro kernel returns handles
    /// as positive results on rv32, so every type stays below 32.
    #[test]
    fn the_console_type_is_the_number_the_assembler_is_given() {
        assert_eq!(ty::CONSOLE.raw(), 24);
        assert!(ty::CONSOLE.raw() < 32);
    }

    /// An op word is the op and the register-form flag, nothing else.
    #[test]
    fn the_op_word_keeps_the_op_below_the_flag() {
        assert_eq!(INVOKE_OP_MASK & INVOKE_REGS, 0);
        assert_eq!(INVOKE_FLAGS_KNOWN & INVOKE_OP_MASK, 0);
        assert_eq!(op_of(INVOKE_REGS | LOG_CONSOLE_WRITE as u64), LOG_CONSOLE_WRITE);
    }

    /// Every op of `invoke.rs` is `op(Kind, CLASS, n)`, named after its kind,
    /// and no two ops are the same number: an op names exactly one thing.
    ///
    /// **Canary.** Give two ops the same index: red.
    #[test]
    fn ops_are_named_after_their_kind_and_never_repeat() {
        const SRC: &str = include_str!("../../../../crates/core/abi/src/invoke.rs");
        let mut seen = std::collections::BTreeMap::new();
        for line in SRC.lines() {
            let Some(rest) = line.strip_prefix("pub const ") else { continue };
            let Some((name, tail)) = rest.split_once(": u16 = op(CapKind::") else { continue };
            let kind = tail.split(',').next().unwrap().to_uppercase();
            assert!(name.starts_with(&format!("{kind}_")), "`{name}` is not named after its kind {kind}");
            let class = tail.split(',').nth(1).unwrap().trim();
            assert!(class.starts_with("CLASS_"), "`{name}`: class `{class}`");
            let n: u8 = tail.split(',').nth(2).unwrap().trim().trim_end_matches(");").parse().unwrap();
            if let Some(prev) = seen.insert((kind.clone(), class.to_string(), n), name.to_string()) {
                panic!("`{name}` and `{prev}` are the same op");
            }
        }
        assert!(!seen.is_empty());
    }

    /// An op carries its kind and class, and both survive the round trip.
    #[test]
    fn an_op_carries_its_kind_and_class() {
        use azos_abi::cap::CapKind;
        let o = op(CapKind::Node, CLASS_ADMIN, 9);
        assert_eq!((op_kind(o), op_class(o), (o & 0xFF) as u8), (CapKind::Node as u8, CLASS_ADMIN, 9));
        assert!(CapKind::Log as usize <= OP_KINDS);
        assert_eq!(LOG_CONSOLE_WRITE, 0x8101);
    }

    /// The self handle is never a slot's: generation 0 is no table's.
    #[test]
    fn the_self_handle_has_no_slot_and_no_generation() {
        assert_eq!(DOMAIN_SELF.generation(), 0);
        assert!(is_domain_self(DOMAIN_SELF.as_raw()));
        assert!(!is_domain_self(0));
    }

    /// `tools/syscall_defs.py` gives the hand-assembled programs the self
    /// handle as a literal: type 21 (`Domain`, class 1) in the top 6 bits,
    /// every right, no generation, no slot.
    #[test]
    fn the_self_handle_is_the_number_the_assembler_is_given() {
        assert_eq!(DOMAIN_SELF.as_raw(), (21u32 << 26) | (0x3F << 20));
    }
}

/// The syscall table, read from the sources: `syscall_nr.rs` for the names and
/// `dispatch.rs` for the arms. Nothing is restated here, so a number cannot
/// drift from the table the kernel answers with.
#[cfg(test)]
mod syscall_table {
    use azos_abi::syscall_nr::{CAP_TYPED_SYSCALLS, SYS_NR_RESERVED_UPPER};
    use std::collections::BTreeMap;

    const DISPATCH: &str = include_str!("../../../../crates/core/syscall/src/dispatch.rs");
    const SYSCALL_NR: &str = include_str!("../../../../crates/core/abi/src/syscall_nr.rs");

    /// Every `pub const SYS_*: u64 = <decimal>;` in `syscall_nr.rs`. A
    /// `pub const SYS_` line of any other shape fails, so a name cannot escape
    /// the scan by being written differently.
    fn names() -> BTreeMap<&'static str, u64> {
        let mut out = BTreeMap::new();
        for line in SYSCALL_NR.lines() {
            assert!(
                !line.trim_start().starts_with("const SYS_"),
                "a non-public syscall constant: {line}"
            );
            if !line.starts_with("pub const SYS_") {
                continue;
            }
            let rest = &line["pub const ".len()..];
            let (name, value) = rest
                .split_once(": u64 = ")
                .unwrap_or_else(|| panic!("a `pub const SYS_` of another shape: {line}"));
            let value: u64 = value
                .strip_suffix(';')
                .and_then(|v| v.parse().ok())
                .unwrap_or_else(|| panic!("not a decimal literal: {line}"));
            assert!(out.insert(name, value).is_none(), "{name} is defined twice");
        }
        assert!(out.len() > 20, "precondition: the scan read the table ({} names)", out.len());
        out
    }

    /// One alternative of a dispatch arm pattern: the inclusive range of
    /// numbers it matches, and its text.
    struct Alt {
        lo: u64,
        hi: u64,
        text: String,
    }

    /// Every alternative of every arm pattern in `dispatch.rs` made only of
    /// `SYS_*` names, decimal literals, `|` and `..=`. A pattern is the text
    /// before `=>` on a line (comments dropped), joined with the lines before
    /// it while they end in `|`. A pattern with any other token is skipped: an
    /// inner `match` on other names is not a syscall arm, and one on decimal
    /// literals is kept, which can give a false alarm but never a miss. A
    /// `SYS_*` name the table does not define fails.
    fn arms(names: &BTreeMap<&'static str, u64>) -> Vec<Alt> {
        let value = |t: &str| -> Option<u64> {
            if t.starts_with("SYS_") {
                Some(*names.get(t).unwrap_or_else(|| {
                    panic!("an arm names `{t}`, which syscall_nr.rs does not define as a decimal")
                }))
            } else {
                t.parse().ok()
            }
        };
        let mut out = Vec::new();
        let mut pending = String::new();
        for line in DISPATCH.lines() {
            let code = line.split("//").next().unwrap_or("").trim();
            if code.is_empty() {
                continue;
            }
            let joined = if pending.is_empty() { code.to_string() } else { format!("{pending} {code}") };
            pending.clear();
            match joined.split_once("=>") {
                Some((pat, _)) => {
                    let pat = pat.trim();
                    if pat.is_empty()
                        || !pat.chars().all(|c| c.is_ascii_alphanumeric() || " _|.=".contains(c))
                    {
                        continue;
                    }
                    for alt in pat.split('|').map(str::trim) {
                        let (lo, hi) = match alt.split_once("..=") {
                            Some((a, b)) => (a.trim(), b.trim()),
                            None => (alt, alt),
                        };
                        if let (Some(lo), Some(hi)) = (value(lo), value(hi)) {
                            out.push(Alt { lo, hi, text: alt.to_string() });
                        }
                    }
                }
                None if joined.ends_with('|') => pending = joined,
                None => {}
            }
        }
        out
    }

    /// Every dispatch arm names a number below `SYS_NR_RESERVED_UPPER`.
    /// Dispatch is a table of that many entries
    /// (`crates/core/syscall/src/syscall_table.rs`), built by evaluating the
    /// arms for each index: an arm for a number at or past the bound would
    /// compile and never be reached.
    ///
    /// **Canary.** Add an arm for `SYS_NR_RESERVED_UPPER` (or raise a range
    /// past it): red.
    #[test]
    fn every_dispatch_arm_is_inside_the_table() {
        let names = names();
        let arms = arms(&names);
        assert!(arms.len() >= names.len() / 2, "precondition: {} arm alternatives", arms.len());
        let highest = names.iter().filter(|(n, _)| **n != "SYS_NR_RESERVED_UPPER").map(|(_, v)| *v).max().unwrap();
        assert!(
            arms.iter().any(|a| a.hi == highest),
            "precondition: the scan sees the arm of the highest number"
        );
        for a in &arms {
            assert!(
                a.hi < SYS_NR_RESERVED_UPPER,
                "the dispatch arm `{}` ({}..={}) is past the table ({} entries)",
                a.text, a.lo, a.hi, SYS_NR_RESERVED_UPPER
            );
        }
    }

    /// No two names share a number, and every number the capability-typed set
    /// lists is assigned.
    ///
    /// **Canary.** Give two names one number: red (the second `insert` of
    /// `names`' value is not checked there, this test is).
    #[test]
    fn numbers_are_unique_and_the_typed_set_is_assigned() {
        let names = names();
        let mut seen = BTreeMap::new();
        for (n, v) in &names {
            if *n == "SYS_NR_RESERVED_UPPER" {
                continue;
            }
            if let Some(prev) = seen.insert(*v, *n) {
                panic!("`{n}` and `{prev}` share number {v}");
            }
        }
        for nr in CAP_TYPED_SYSCALLS {
            assert!(seen.contains_key(nr), "CAP_TYPED_SYSCALLS lists the unassigned number {nr}");
        }
    }

    /// The table is dense from 1 and `SYS_NR_RESERVED_UPPER` is its length plus
    /// one: thirty-three calls, no hole, nothing past the bound. A call added
    /// takes the next number and moves the bound; one removed renumbers.
    ///
    /// **Canary.** Leave a gap (give a call number 40): red.
    #[test]
    fn the_table_is_dense_from_one_and_has_thirty_three_calls() {
        let names = names();
        let mut nrs: Vec<u64> = names
            .iter()
            .filter(|(n, _)| **n != "SYS_NR_RESERVED_UPPER")
            .map(|(_, v)| *v)
            .collect();
        nrs.sort_unstable();
        assert_eq!(nrs.len(), 33, "the native table is 33 calls");
        for (i, nr) in nrs.iter().enumerate() {
            assert_eq!(*nr, i as u64 + 1, "the table has a hole at {}", i + 1);
        }
        assert_eq!(SYS_NR_RESERVED_UPPER, nrs.len() as u64 + 1);
    }
}

/// Absolute sleep: the nanosecond ↔ counter conversions shared by the kernel's
/// sleep and libsys's clock.
///
/// **Canaries.** Round `ns_to_ticks_ceil` down instead of up: `rounds_up_*`
/// red. Drop its sub-second term: `sub_second_*` red. Multiply before
/// dividing in either function: `no_overflow_at_u64_max` red (a panic in a
/// debug build, a wrong value in release).
#[cfg(test)]
mod time_tests {
    use azos_abi::time::{ns_to_ticks_ceil, ticks_to_ns, NS_PER_SEC};

    /// The three boards' timebases: QEMU virt, JH7110, K1.
    const FREQS: [u64; 3] = [10_000_000, 4_000_000, 24_000_000];

    #[test]
    fn whole_seconds_are_exact() {
        for f in FREQS {
            assert_eq!(ns_to_ticks_ceil(0, f), 0);
            assert_eq!(ns_to_ticks_ceil(NS_PER_SEC, f), f);
            assert_eq!(ns_to_ticks_ceil(7 * NS_PER_SEC, f), 7 * f);
            assert_eq!(ticks_to_ns(7 * f, f), 7 * NS_PER_SEC);
        }
    }

    #[test]
    fn rounds_up_one_nanosecond_past_a_tick() {
        // 10 MHz: a tick is 100 ns. 100 ns is tick 1; 101 ns must be tick 2.
        assert_eq!(ns_to_ticks_ceil(100, 10_000_000), 1);
        assert_eq!(ns_to_ticks_ceil(101, 10_000_000), 2);
        // 4 MHz: a tick is 250 ns.
        assert_eq!(ns_to_ticks_ceil(250, 4_000_000), 1);
        assert_eq!(ns_to_ticks_ceil(251, 4_000_000), 2);
        // 24 MHz: a tick is 41.67 ns; 1 ns is already tick 1.
        assert_eq!(ns_to_ticks_ceil(1, 24_000_000), 1);
    }

    #[test]
    fn rounds_up_never_early() {
        for f in FREQS {
            for ns in [1u64, 99, 999, 12_345_678, NS_PER_SEC - 1, NS_PER_SEC + 1, 3 * NS_PER_SEC + 7] {
                let t = ns_to_ticks_ceil(ns, f);
                assert!(ticks_to_ns(t, f) >= ns, "f={f} ns={ns}: tick {t} is at {} ns", ticks_to_ns(t, f));
                assert!(t == 0 || ticks_to_ns(t - 1, f) < ns, "f={f} ns={ns}: tick {t} is not the first");
            }
        }
    }

    #[test]
    fn sub_second_part_counts() {
        // 1.5 s at 10 MHz is 15 000 000 ticks; the half second must not vanish.
        assert_eq!(ns_to_ticks_ceil(NS_PER_SEC + NS_PER_SEC / 2, 10_000_000), 15_000_000);
        assert_eq!(ticks_to_ns(15_000_000, 10_000_000), NS_PER_SEC + NS_PER_SEC / 2);
        // 10 ms at 24 MHz is exactly 240 000 ticks.
        assert_eq!(ns_to_ticks_ceil(10_000_000, 24_000_000), 240_000);
    }

    #[test]
    fn no_overflow_at_u64_max() {
        for f in FREQS {
            // Representable: ~1.8e10 s of ticks at 24 MHz is ~4.4e17.
            let t = ns_to_ticks_ceil(u64::MAX, f);
            assert_eq!(t, (u64::MAX / NS_PER_SEC) * f + ((u64::MAX % NS_PER_SEC) * f).div_ceil(NS_PER_SEC));
            // Not representable in nanoseconds: saturates, never wraps to a small value.
            assert_eq!(ticks_to_ns(u64::MAX, f), u64::MAX);
        }
    }

    #[test]
    fn zero_frequency_reads_zero() {
        assert_eq!(ticks_to_ns(12_345, 0), 0);
    }
}

#[cfg(test)]
mod abi_version_tests {
    use azos_abi::ABI_VERSION;

    #[test]
    fn abi_version_is_v2() {
        assert_eq!(ABI_VERSION, 2);
    }

    /// The vDSO word sits after the layout version, 4-aligned, inside the
    /// page's published fields (`mm` asserts the struct against it).
    #[test]
    fn the_vdso_publishes_the_abi_version_after_the_layout_version() {
        use azos_abi::vdso::{VDSO_ABI_VERSION_OFFSET, VDSO_LAYOUT_VERSION_OFFSET};
        assert_eq!(VDSO_ABI_VERSION_OFFSET, VDSO_LAYOUT_VERSION_OFFSET + 4);
        assert_eq!(VDSO_ABI_VERSION_OFFSET % 4, 0);
    }

    /// The note libsys embeds: name `AZOS` and its NUL, type 1.
    #[test]
    fn the_abi_note_names_azos() {
        assert_eq!(azos_abi::ABI_NOTE_NAME, b"AZOS\0");
        assert_eq!(azos_abi::ABI_NOTE_TYPE, 1);
    }
}

/// `crates/core/abi/src/vdso.rs` — the vDSO placement fix (2026-09-22). Real host-side tests: `crates/core/abi` itself builds under the
/// workspace's `no_std` RV64 target, so a `#[cfg(test)]` block there never
/// runs (see that file's own note).
#[cfg(test)]
mod vdso_tests {
    use azos_abi::vdso::{
        vdso_is_below_ram, vdso_shares_a_2mib_slot_with, VDSO_USER_BASE,
    };

    #[test]
    fn vdso_shares_a_2mib_slot_with_is_reflexive_and_windowed() {
        assert!(vdso_shares_a_2mib_slot_with(VDSO_USER_BASE, 1));
        assert!(vdso_shares_a_2mib_slot_with(VDSO_USER_BASE + 0x1000, 1));
        assert!(vdso_shares_a_2mib_slot_with(VDSO_USER_BASE + 0x1F_F000, 0x1000));
        assert!(!vdso_shares_a_2mib_slot_with(VDSO_USER_BASE + 0x20_0000, 1));
        assert!(!vdso_shares_a_2mib_slot_with(VDSO_USER_BASE - 0x1000, 0x1000));
    }

    /// A device whose mapped size crosses a 2 MiB boundary (this project's
    /// PLIC, mapped 4 MiB) must collide by its LAST byte, not just its base
    /// — a base-only check would miss a real collision one slot away.
    #[test]
    fn a_multi_slot_device_collides_by_its_last_byte_not_just_its_base() {
        let slot = VDSO_USER_BASE >> 21;
        let device_base = (slot - 1) << 21;
        assert!(vdso_shares_a_2mib_slot_with(device_base, 0x40_0000));
        assert!(!vdso_shares_a_2mib_slot_with(device_base, 0x1000));
    }

    /// Pins the placement decision itself: `VDSO_USER_BASE` is below RAM on
    /// every board whose RAM is identity-mapped starting at a real
    /// `RAM_BASE` (QEMU riscv64 at `0x8000_0000`; VF2 and aarch64 QEMU
    /// `virt` at `0x4000_0000`, the exact collision the old
    /// `0x5000_0000` address hit on both). K1's `RAM_BASE == 0` is a
    /// documented, pre-existing exclusion (see the module doc) — this test
    /// pins that it STAYS excluded rather than silently starting to pass.
    #[test]
    fn vdso_is_below_ram_matches_every_supported_boards_ram_base() {
        assert!(vdso_is_below_ram(0x8000_0000)); // QEMU riscv64
        assert!(vdso_is_below_ram(0x4000_0000)); // VF2 / aarch64 QEMU virt
        assert!(!vdso_is_below_ram(0)); // K1 — documented exclusion, not fixed here
    }

    /// The vDSO base itself must be page-aligned (`vmm::map` rejects an
    /// unaligned vaddr) and, less obviously, must materialize on RV64 as a
    /// single `lui` — the RISC-V ELF-bytes constraint this address was
    /// chosen under (see `crates/core/abi/src/vdso.rs`'s module doc: only the
    /// low 12 bits being zero AND the value fitting `lui`'s 20-bit
    /// immediate keeps the codegen shape a one-instruction load).
    /// `< 0x8000_0000` keeps it clear of QEMU riscv64's RAM VPN\[2\] slot
    /// too.
    #[test]
    fn vdso_user_base_is_page_aligned_and_low() {
        assert_eq!(VDSO_USER_BASE & 0xFFF, 0);
        assert!(VDSO_USER_BASE < 0x8000_0000);
    }

    // Canary for `vdso_is_below_ram_matches_every_supported_boards_ram_base`
    // above: hand-set `VDSO_USER_BASE` in `crates/core/abi/src/vdso.rs` back to
    // `0x5000_0000` and this test starts failing (VF2/aarch64 RAM_BASE
    // arms), because `vdso_is_below_ram` reads the real constant, not a
    // copy. Verified empirically for this task — not left as a standing
    // test, since a real canary must revert with the code it guards, and
    // the stronger, always-live proof already runs on every build:
    // `crates/drivers/base/src/platform.rs`'s per-board `const` asserts, which
    // fail to COMPILE (not just test) under the old address on VF2 and
    // aarch64 — see this task's report for that build output.
}

// Wave 11 (SENSORTS): the sensor sample's stamp rules and the per-task vDSO page's
// layout version 2. Wire layout, so every offset is pinned here.
#[cfg(test)]
mod sensor_sample_tests {
    use azos_abi::sensor_sample::*;
    use azos_abi::vdso::*;

    #[test]
    fn the_sample_flags_are_pinned() {
        assert_eq!(SENSOR_SAMPLE_FLAG_SYNTHETIC, 1);
    }

    /// The staleness rule: unknown (0) and future stamps are never fresh, and
    /// a sample exactly `max_age` old has expired.
    #[test]
    fn freshness_is_strict_and_unknown_is_never_fresh() {
        assert!(!sample_is_fresh_ns(0, 10, u64::MAX));
        assert!(!sample_is_fresh_ns(11, 10, 100), "a stamp from the future");
        assert!(sample_is_fresh_ns(10, 10, 1));
        assert!(sample_is_fresh_ns(10, 109, 100));
        assert!(!sample_is_fresh_ns(10, 110, 100));
    }

    /// Version 2 of the per-task page puts `acq_ns` in what was the slot's
    /// padding: every version-1 offset is unchanged.
    #[test]
    fn the_task_page_v2_adds_acq_ns_without_moving_v1() {
        assert_eq!(VDSO_TASK_VERSION, 2);
        assert_eq!(VTP_VERSION, 4);
        assert_eq!(VTP_SENSOR_ACQ_NS, 48);
        assert!(VTP_SENSOR_ACQ_NS >= VTP_SENSOR_DATA + VTP_SENSOR_DATA_MAX);
        assert!(VTP_SENSOR_ACQ_NS + 8 <= VTP_SENSOR_STRIDE);
        assert_eq!((VTP_SENSOR_STRIDE, VTP_SENSOR_DATA, VTP_SENSOR_DATA_MAX), (64, 16, 32));
    }
}

/// The user shell's request and startup blocks. The kernel
/// lays a startup block out with `layout_startup` and libsys decodes it with
/// `StartupBlock::from_bytes`; these pin the two against each other and the
/// request's shape check against its limits.
#[cfg(test)]
mod ushell_blocks {
    use azos_abi::ushell::*;

    fn fds() -> [StartupFd; STARTUP_FDS] {
        let mut f = [StartupFd::default(); STARTUP_FDS];
        f[1] = StartupFd { kind: FD_CONSOLE, handle: 0 };
        f[2] = StartupFd { kind: FD_HANDLE, handle: 0xABCD };
        f
    }

    #[test]
    fn a_laid_out_block_decodes_to_what_was_written() {
        let mut out = [0u8; 512];
        let base = 0x7fff_f000u64;
        let n = layout_startup(&mut out, base, b"args\0x y\0", 2, b"FOO=bar\0", 1, b"/fat", 0, &fds())
            .expect("fits");
        let b = StartupBlock::from_bytes(&out).unwrap();
        assert!(b.validate());
        assert_eq!((b.argc, b.envc, b.cwd_bytes), (2, 1, 4));
        let off = |p: u64| (p - base) as usize;
        assert_eq!(&out[off(b.argv)..off(b.argv) + b.argv_bytes as usize], b"args\0x y\0");
        assert_eq!(&out[off(b.env)..off(b.env) + b.env_bytes as usize], b"FOO=bar\0");
        assert_eq!(&out[off(b.cwd)..off(b.cwd) + 5], b"/fat\0");
        assert_eq!(b.fds, fds());
        assert!(n <= out.len() && off(b.cwd) + 5 == n);
        assert_eq!(b.argv % 8, 0);
        assert_eq!(b.env % 8, 0);
    }

    #[test]
    fn layout_refuses_mismatched_counts_and_bad_strings() {
        let mut out = [0u8; 512];
        assert!(layout_startup(&mut out, 0x1000, b"a\0b\0", 1, b"", 0, b"", 0, &fds()).is_none());
        assert!(layout_startup(&mut out, 0x1000, b"a", 1, b"", 0, b"", 0, &fds()).is_none(),
                "a blob must end with a NUL");
        assert!(layout_startup(&mut out, 0x1008, b"a\0", 1, b"", 0, b"", 0, &fds()).is_none(),
                "misaligned base");
        assert!(layout_startup(&mut out[..64], 0x1000, b"a\0", 1, b"", 0, b"", 0, &fds()).is_none(),
                "does not fit");
        assert!(layout_startup(&mut out, 0x1000, b"", 0, b"", 0, b"", 0, &fds()).is_some(),
                "no arguments at all is a valid block");
    }

    #[test]
    fn an_empty_blob_has_a_null_pointer() {
        let mut out = [0u8; 256];
        layout_startup(&mut out, 0x2000, b"", 0, b"", 0, b"", 0, &fds()).unwrap();
        let b = StartupBlock::from_bytes(&out).unwrap();
        assert_eq!((b.argv, b.env, b.cwd), (0, 0, 0));
    }

    #[test]
    fn a_block_with_a_wrong_magic_or_kind_does_not_validate() {
        let mut out = [0u8; 256];
        layout_startup(&mut out, 0x2000, b"", 0, b"", 0, b"", 0, &fds()).unwrap();
        let mut b = StartupBlock::from_bytes(&out).unwrap();
        b.magic ^= 1;
        assert!(!b.validate());
        let mut b = StartupBlock::from_bytes(&out).unwrap();
        b.fds[3].kind = 3;
        assert!(!b.validate());
        assert_eq!(STARTUP_MAGIC.to_le_bytes(), *b"KSB1");
    }

    fn req() -> SpawnReq {
        SpawnReq { version: SPAWN_REQ_VERSION, ..SpawnReq::default() }
    }

    #[test]
    fn the_request_shape_check() {
        assert_eq!(req().check_shape(), Ok(()));
        let bad = |f: &dyn Fn(&mut SpawnReq)| {
            let mut r = req();
            f(&mut r);
            r.check_shape().is_err()
        };
        assert!(bad(&|r| r.version = 2));
        assert!(bad(&|r| r.flags = SPAWN_F_MAP_TASK_PAGE), "the vDSO flag is reserved, refused");
        assert!(!bad(&|r| r.flags = SPAWN_F_CONSOLE_IN), "wave 13: the console lend is a known flag");
        assert!(!bad(&|r| r.flags = SPAWN_F_USER), "console login: the user session is a known flag");
        assert!(bad(&|r| r.flags = 16));
        assert!(bad(&|r| r.argc = 17));
        assert!(bad(&|r| { r.argv_ptr = 8; r.argv_bytes = 1025; }));
        assert!(bad(&|r| r.argv_bytes = 4), "bytes without a pointer");
        assert!(bad(&|r| r.nmoves = 9));
        assert!(bad(&|r| { r.nmoves = 1; r.moves[0].child_fd = 8; }));
        assert!(bad(&|r| { r.nmoves = 2; r.moves[1].child_fd = 0; }), "fd 0 named twice");
        assert!(bad(&|r| { r.nmoves = 1; r.moves[0].perms = 0x40; }), "a seventh right is not one");
        assert!(!bad(&|r| { r.nmoves = 1; r.moves[0].perms = 0x3f; }), "the six rights are");
        assert!(!bad(&|r| r.flags = SPAWN_F_DIE_WITH_PARENT));
        assert!(!bad(&|r| { r.nmoves = 2; r.moves[1].child_fd = 1; r.moves[1].handle = MOVE_CONSOLE; }));
    }

    #[test]
    fn counted_strings() {
        assert_eq!(count_cstrs(b""), Some(0));
        assert_eq!(count_cstrs(b"\0"), Some(1));
        assert_eq!(count_cstrs(b"a\0bc\0"), Some(2));
        assert_eq!(count_cstrs(b"a\0b"), None);
    }

    /// The console program's argument block (`console_mode::console_start`
    /// hands the Kconfig `CONSOLE_ARGS` to `SYS_SPAWN_EX`): the words in
    /// order with argv[0] first, the image's name alone when there are none,
    /// and a block `layout_startup` accepts.
    ///
    /// **Canary.** Drop the empty-args fallback: the second assertion fails
    /// (a Linux program with `argc = 0`).
    #[test]
    fn the_console_argument_block() {
        let (b, len, argc) = console_argv(b"/fat/BUSYBOX.ELF", b"sh -i");
        assert_eq!((&b[..len], argc), (&b"sh\0-i\0"[..], 2));
        let (b, len, argc) = console_argv(b"/fat/BUSYBOX.ELF", b"");
        assert_eq!((&b[..len], argc), (&b"BUSYBOX.ELF\0"[..], 1), "no words: the image's name");
        let (b, len, argc) = console_argv(b"/fat/SH.ELF", b"  a   b ");
        assert_eq!((&b[..len], argc), (&b"a\0b\0"[..], 2), "runs of spaces are one separator");
        assert_eq!(count_cstrs(&b[..len]), Some(argc));
        // A word that does not fit is dropped whole, the ones before it kept.
        let long = [b'x'; SPAWN_ARGV_MAX];
        let mut args = b"ok ".to_vec();
        args.extend_from_slice(&long);
        let (b, len, argc) = console_argv(b"/fat/SH.ELF", &args);
        assert_eq!((&b[..len], argc), (&b"ok\0"[..], 1));
    }

    #[test]
    fn flag_and_limit_values() {
        assert_eq!(MOVE_CONSOLE, u32::MAX);
        assert_eq!((KILL_REQUEST, KILL_FORCE, KILL_SUBTREE), (1, 2, 1));
        assert_eq!(KILL_MAX_ANCESTRY, 8);
        assert_eq!((SPAWN_F_DIE_WITH_PARENT, SPAWN_F_MAP_TASK_PAGE, SPAWN_F_USER), (1, 2, 8));
        assert_eq!((SPAWN_ARGV_MAX, SPAWN_ENV_MAX, SPAWN_ARGC_MAX, SPAWN_ENVC_MAX, SPAWN_CWD_MAX, SPAWN_MAX_MOVES),
                   (1024, 1024, 16, 16, 64, 8));
    }
}

/// Wave 15: the kernel tracer's ABI names (`azos_abi::trace`).
#[cfg(test)]
mod trace_abi_tests {
    use azos_abi::trace::*;

    /// Every event id names its own class, and every class has a name.
    #[test]
    fn event_ids_carry_their_class_and_classes_their_names() {
        let evs = [
            (TRACE_EV_SCHED_SWITCH, TRACE_CLASS_SCHED), (TRACE_EV_SCHED_WAKEUP, TRACE_CLASS_SCHED),
            (TRACE_EV_IRQ_ENTRY, TRACE_CLASS_IRQ), (TRACE_EV_IRQ_EXIT, TRACE_CLASS_IRQ),
            (TRACE_EV_SYS_ENTER, TRACE_CLASS_SYSCALL), (TRACE_EV_SYS_EXIT, TRACE_CLASS_SYSCALL),
            (TRACE_EV_SYS_DENY, TRACE_CLASS_SYSCALL), (TRACE_EV_IPC_CALL, TRACE_CLASS_IPC),
            (TRACE_EV_IPC_REPLY, TRACE_CLASS_IPC), (TRACE_EV_PAGE_FAULT, TRACE_CLASS_FAULT),
            (TRACE_EV_PROC_SPAWN, TRACE_CLASS_PROC), (TRACE_EV_PROC_EXIT, TRACE_CLASS_PROC),
            (TRACE_EV_PROC_SIGNAL, TRACE_CLASS_PROC), (TRACE_EV_LAT_IRQSOFF, TRACE_CLASS_LAT),
            (TRACE_EV_LAT_PREEMPTOFF, TRACE_CLASS_LAT), (TRACE_EV_PROF_SAMPLE, TRACE_CLASS_PROF),
            (TRACE_EV_PROF_FRAMES, TRACE_CLASS_PROF),
        ];
        for (e, c) in evs {
            assert_eq!(trace_event_class(e), c, "{}", trace_event_name(e));
            assert_ne!(trace_event_name(e), "unknown");
        }
        for c in 0..TRACE_CLASSES {
            assert_ne!(trace_class_name(c), "?");
        }
        assert_eq!(TRACE_MASK_ALL, 0xff);
    }

}

/// Wave 15 N11: the message descriptor of ABI v2 of the call is frozen.
#[cfg(test)]
mod ipc_msg_tests {
    use azos_abi::ipc_msg::*;

    #[test]
    fn the_descriptor_layout_is_frozen() {
        assert_eq!(core::mem::size_of::<MsgDesc>(), 224);
        assert_eq!(core::mem::size_of::<CapDesc>(), 16);
        assert_eq!(core::mem::offset_of!(CapDesc, expiry_ns), 8);
        assert_eq!(core::mem::offset_of!(MsgDesc, badge), 8);
        assert_eq!(core::mem::offset_of!(MsgDesc, words), 16);
        assert_eq!(core::mem::offset_of!(MsgDesc, caps), 80);
        assert_eq!(core::mem::offset_of!(MsgDesc, deadline), 208);
        assert_eq!(core::mem::offset_of!(MsgDesc, clock_id), 216);
        assert_eq!((MSG_VERSION, MSG_WORDS_MAX, MSG_CAPS_MAX), (1, 8, 8));
        assert_eq!((CAP_MODE_MOVE, CAP_MODE_DUP, MSG_KEEP, MSG_BADGED), (1, 2, 1, 1 << 31));
    }

    #[test]
    fn only_the_one_version_is_accepted() {
        let mut d = MsgDesc { version: MSG_VERSION, ..MsgDesc::default() };
        assert!(d.well_formed());
        d.n_caps = 9;
        assert!(!d.well_formed(), "past the ceiling");
        d.n_caps = 0;
        for v in [0u16, 2, 0x8001] {
            d.version = v;
            assert!(!d.well_formed(), "version {v}");
        }
    }

    #[test]
    fn a_zeroed_descriptor_has_no_deadline_and_names_mono() {
        let d = MsgDesc::default();
        assert_eq!((d.deadline, d.clock_id), (0, azos_abi::time::ClockId::MONO.raw()));
    }
}

/// Clock ids: a kind in the high byte, an index in the low 24 bits, MONO = 0.
#[cfg(test)]
mod clock_id_tests {
    use azos_abi::time::ClockId;

    #[test]
    fn mono_is_zero_so_a_zeroed_field_names_it() {
        assert_eq!(ClockId::MONO.raw(), 0);
        assert_eq!(ClockId::default(), ClockId::MONO);
        assert!(ClockId::MONO.is_mono());
    }

    #[test]
    fn kind_and_index_round_trip_and_do_not_alias() {
        for (id, kind, idx) in [
            (ClockId::REAL, ClockId::KIND_REAL, 0),
            (ClockId::TSC_RAW, ClockId::KIND_TSC_RAW, 0),
            (ClockId::ptp(3), ClockId::KIND_PTP, 3),
            (ClockId::tsn_domain(3), ClockId::KIND_TSN_DOMAIN, 3),
            (ClockId::vcpu(0xFF_FFFF), ClockId::KIND_VCPU, 0xFF_FFFF),
        ] {
            assert_eq!((id.kind(), id.index()), (kind, idx));
            assert!(!id.is_mono());
        }
        assert_ne!(ClockId::ptp(3), ClockId::tsn_domain(3));
        assert_ne!(ClockId::ptp(3), ClockId::ptp(4));
        assert_eq!(ClockId::ptp(3).raw(), 3 << 24 | 3);
        // An index past 24 bits is truncated, never spilled into the kind.
        assert_eq!(ClockId::ptp(0x0100_0005).kind(), ClockId::KIND_PTP);
        assert_eq!(ClockId::ptp(0x0100_0005).index(), 5);
        // MONO with a nonzero index is not MONO.
        assert!(!ClockId::new(ClockId::KIND_MONO, 1).is_mono());
    }
}

/// The foreign-ABI family (D6, `azos_abi::foreign`): the frame is the same size
/// on every ISA, and the kernel's placement of it keeps the ABI's red zone
/// and alignment.
#[cfg(test)]
mod foreign_frame {
    use azos_abi::foreign::*;

    #[test]
    fn the_frame_is_272_bytes_on_every_isa() {
        assert_eq!(FOREIGN_FRAME_SIZE, 272);
        assert_eq!(core::mem::align_of::<ForeignFrame>(), 8);
    }

    #[test]
    fn the_frame_goes_below_the_stack_pointer_and_the_red_zone_aligned() {
        for sp in [0x7fff_ff00u64, 0x7fff_ffff, 0x1000_0010, 0x1234_5678] {
            let base = frame_base(sp).unwrap();
            assert_eq!(base % FOREIGN_FRAME_ALIGN, 0);
            assert!(base + FOREIGN_FRAME_SIZE as u64 + FOREIGN_RED_ZONE <= sp, "{sp:#x}");
            // Never more than one alignment unit lower than it must be.
            assert!(sp - (base + FOREIGN_FRAME_SIZE as u64 + FOREIGN_RED_ZONE) < FOREIGN_FRAME_ALIGN);
        }
        // A stack pointer too close to zero has no room for it.
        assert_eq!(frame_base(100), None);
    }

    #[test]
    fn the_register_indices_name_registers_inside_the_frame() {
        let f = ForeignFrame::ZERO;
        for i in [REG_NUMBER, REG_RESULT, REG_FIRST_ARG, REG_SP] {
            assert!(i < f.gpr.len());
        }
        // The user-writable flag bits never include a privilege bit.
        #[cfg(target_arch = "aarch64")]
        assert_eq!(FLAGS_USER_MASK & 0x0fff_ffff, 0);
        #[cfg(target_arch = "x86_64")]
        assert_eq!(FLAGS_USER_MASK & (1 << 9 | 1 << 8 | 0x3000), 0, "IF, TF, IOPL");
        #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
        assert_eq!(FLAGS_USER_MASK, 0);
    }
}

/// The wire structs and the slot word are the same bytes on a 32-bit and a
/// 64-bit target (the micro kernel is `riscv32imac`, the host is 64-bit): no
/// size below depends on `size_of::<usize>()`. Each expected size is summed
/// from field widths written out here, so a `usize` or a pointer added to a
/// struct moves the real size on one width only and fails this sum on the
/// host, where the 32-bit build's own `const` assertions (`ipc_msg.rs`)
/// cannot run.
#[cfg(test)]
mod word_width_tests {
    use azos_abi::cap::{slot_word, ty, CapHandle, CapPerms, CapType};
    use azos_abi::ipc_msg::{CapDesc, MsgDesc, MSG_CAPS_MAX, MSG_WORDS_MAX};
    use core::mem::{align_of, size_of};

    #[test]
    fn msg_desc_is_summed_from_fixed_width_fields() {
        // version 2 + n_words 1 + n_caps 1 + flags 4 + badge 8, the words,
        // the cap entries, deadline 8 + clock_id 4 + _pad 4.
        let sum = 2 + 1 + 1 + 4 + 8 + 8 * MSG_WORDS_MAX + size_of::<CapDesc>() * MSG_CAPS_MAX + 8 + 4 + 4;
        assert_eq!(size_of::<MsgDesc>(), sum);
        assert_eq!(size_of::<MsgDesc>(), 224);
        // 8 on every target that has a 64-bit integer with 8-byte alignment:
        // the u64 words sit at multiples of 8 in the message, so a 32-bit
        // reader that aligns them to 4 still finds the same offsets.
        assert_eq!(align_of::<MsgDesc>(), 8);
    }

    #[test]
    fn cap_desc_is_sixteen_bytes() {
        // handle 4 + mode 1 + _pad 1 + rights 2 + expiry_ns 8.
        assert_eq!(size_of::<CapDesc>(), 4 + 1 + 1 + 2 + 8);
    }

    #[test]
    fn a_handle_is_one_32_bit_word() {
        assert_eq!(size_of::<CapHandle>(), 4);
        assert_eq!(CapHandle::from_raw(u32::MAX).as_raw(), u32::MAX);
    }

    #[test]
    fn the_slot_word_round_trips_every_field() {
        let w = slot_word::encode(ty::ENDPOINT, CapPerms::RW_DELEGATE, 0xBEEF, 0xDEAD_BEE1);
        assert_eq!(slot_word::ty(w), ty::ENDPOINT);
        assert!(slot_word::ty_is(w, ty::ENDPOINT));
        // A class rides in the same byte: a file is not a socket.
        let f = slot_word::encode(ty::FILE, CapPerms::READ, 1, 5);
        assert!(slot_word::ty_is(f, ty::FILE) && !slot_word::ty_is(f, ty::SOCKET));
        assert!(slot_word::occupied(w));
        assert_eq!(slot_word::perms(w), CapPerms::RW_DELEGATE);
        assert_eq!(slot_word::generation(w), 0xBEEF);
        assert_eq!(slot_word::resource(w), 0xDEAD_BEE1);
        assert!(!slot_word::expires(w));
        assert!(slot_word::expires(w | slot_word::EXPIRES));
        // The layout the module documents, bit for bit.
        assert_eq!(w & 0xff, ty::ENDPOINT.raw() as u64);
        assert_eq!((w >> 8) & 0xff, CapPerms::RW_DELEGATE.bits() as u64);
        assert_eq!((w >> 16) & 0xffff, 0xBEEF);
        assert_eq!(w >> 32, 0xDEAD_BEE1);
    }

    #[test]
    fn a_cleared_slot_keeps_only_its_generation() {
        let w = slot_word::encode(CapType::NULL, CapPerms::NONE, 0, 0);
        assert_eq!(w, 0, "an empty slot is the zero word (.bss tables)");
        assert!(!slot_word::occupied(w));
        let held = slot_word::encode(ty::ENDPOINT, CapPerms::ALL, 7, 99) | slot_word::EXPIRES;
        let freed = slot_word::cleared(held);
        assert!(!slot_word::occupied(freed));
        assert_eq!(slot_word::generation(freed), 7);
        assert_eq!(slot_word::resource(freed), 0);
        assert!(!slot_word::expires(freed));
    }

    #[test]
    fn a_type_the_abi_does_not_name_reads_as_null() {
        assert_eq!(slot_word::ty(0xFF), CapType::NULL);
    }
}

// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host-side tests for the syscall filter (AQ11).
//!
//! **WHY.** The filter is this kernel's seccomp: the only thing standing
//! between a ring-3 driver and the whole syscall table. It had zero host
//! coverage, and its default state is `SyscallFilter::disabled()`, which
//! means *allow everything* — so every failure mode here is fail-open unless
//! the code is careful, and "careful" is exactly what a test is for.
//!
//! The real modules are pulled in with `#[path]`. `seccomp.rs` reaches for
//! `crate::task` and `crate::scheduler`; the first is re-exported straight
//! from the real `filter.rs`, and the second is the one stand-in here — it
//! holds the current task's filter in a static instead of a TCB slot. That
//! is a faithful model: the kernel's versions are plain field accessors
//! (`TASKS[idx].syscall_filter`), so what these tests exercise is
//! `activate_profile`'s policy, which is where the decisions live.

#[allow(dead_code)]
#[path = "../../../../crates/core/sched/src/filter.rs"]
mod filter;

/// `seccomp.rs` says `crate::task::SyscallFilter`. In the kernel those types
/// live in `task.rs`, which re-exports them from `filter.rs`; here the
/// re-export is all that is needed.
mod task {
    // Mirrors the kernel's re-export surface; `seccomp.rs` uses only the first.
    #[allow(unused_imports)]
    pub use crate::filter::{SyscallFilter, TaskInit, SYSCALL_FILTER_MAX};
}

/// Stand-in for the two TCB accessors `activate_profile` calls.
mod scheduler {
    use crate::filter::SyscallFilter;
    use std::sync::Mutex;

    static CURRENT: Mutex<SyscallFilter> = Mutex::new(SyscallFilter::disabled());

    pub fn current_syscall_filter() -> SyscallFilter {
        *CURRENT.lock().unwrap()
    }

    pub fn set_current_syscall_filter(f: SyscallFilter) {
        *CURRENT.lock().unwrap() = f;
    }

    /// Not a kernel function: the tests need to put the "current task" back to
    /// its birth state, which in the kernel is what slot reuse does.
    #[allow(dead_code)] // used only from `#[cfg(test)]` modules
    pub fn reset_for_test() {
        *CURRENT.lock().unwrap() = SyscallFilter::disabled();
    }
}

#[allow(dead_code)]
#[path = "../../../../crates/core/sched/src/seccomp.rs"]
mod seccomp;

/// `SYS_SPAWN_EX`'s decisions (native spawn). It names `crate::seccomp` and
/// `crate::filter`, the two modules above, and nothing of the scheduler.
#[allow(dead_code)]
#[path = "../../../../crates/core/sched/src/spawn_policy.rs"]
mod spawn_policy;

#[cfg(test)]
mod filter_semantics {
    use crate::filter::{SyscallFilter, TaskInit, SYSCALL_FILTER_MAX};

    /// The default a task is born with — and the reason the creation-order
    /// bug fixed alongside this suite mattered at all.
    ///
    /// A disabled filter is not "deny all pending configuration"; it is
    /// "allow everything". Any window in which a task meant to be confined
    /// carries this value is a window in which it is unconfined.
    #[test]
    fn a_disabled_filter_allows_everything() {
        let f = SyscallFilter::disabled();
        for n in [0u16, 3, 23, 430, 65535] {
            assert!(f.is_allowed(n), "disabled filter must allow {n}");
        }
    }

    #[test]
    fn an_enabled_filter_allows_only_what_it_lists() {
        let mut f = SyscallFilter::disabled();
        f.enabled = true;
        f.allow(23);
        f.allow(3);
        assert!(f.is_allowed(23));
        assert!(f.is_allowed(3));
        assert!(!f.is_allowed(24), "24 was never listed");
        assert!(!f.is_allowed(0), "0 is not a free pass");
    }

    /// `allow()` drops silently once the array is full. For a **whitelist**
    /// that is the safe direction — a dropped entry is a denied syscall, not
    /// a granted one — but only because the guard is there at all.
    ///
    /// Canary: delete the `if (self.count as usize) < SYSCALL_FILTER_MAX`
    /// guard and this test does not merely fail, it panics on an
    /// out-of-bounds write to `allowed[32]`. Under the kernel's profile
    /// (`panic = "abort"`) that panic is a board reset, reachable from a task
    /// asking for a large profile.
    #[test]
    fn allow_past_capacity_fails_closed_and_stays_in_bounds() {
        let mut f = SyscallFilter::disabled();
        f.enabled = true;
        for n in 0..SYSCALL_FILTER_MAX {
            f.allow(1000 + n as u16);
        }
        assert_eq!(f.count as usize, SYSCALL_FILTER_MAX);
        f.allow(9999);
        assert_eq!(f.count as usize, SYSCALL_FILTER_MAX, "count must not grow past the array");
        assert!(!f.is_allowed(9999), "an entry that did not fit must be DENIED, not granted");
        assert!(f.is_allowed(1000), "entries that did fit are unaffected");
    }

    /// `count` bounds the scan, not the array length: stale entries left in
    /// `allowed[]` beyond `count` must not grant anything.
    #[test]
    fn entries_past_count_are_not_consulted() {
        let mut f = SyscallFilter::disabled();
        f.enabled = true;
        f.allow(23);
        // Plant a value the way a reused slot's leftovers would sit there.
        f.allowed[5] = 430;
        assert!(!f.is_allowed(430), "only the first `count` entries are the whitelist");
    }

    /// The contract every legacy creation path relies on: a default
    /// `TaskInit` changes nothing about the task it creates.
    #[test]
    fn a_default_task_init_asks_for_no_change() {
        let i = TaskInit::default();
        assert!(i.syscall_filter.is_none());
        assert!(i.class_raw.is_none());
    }

    /// The verdict the dispatcher asks gives the list check's answer for every
    /// number, and audit mode changes only a refusal, into a recorded pass.
    ///
    /// **Canary.** Return `Allow` for an unlisted call in audit mode: the second
    /// loop reads `Allow` where it wants `Audit`. Build `disabled()` with
    /// `audit: true`: the first loop reads `Audit` where it wants `Deny`.
    #[test]
    fn the_verdict_agrees_with_the_list_and_audit_only_turns_deny_into_audit() {
        use crate::filter::FilterVerdict;
        let mut f = SyscallFilter::disabled();
        f.enabled = true;
        for n in [3u16, 23, 430, 999] {
            f.allow(n);
        }
        for n in 0..2000u16 {
            let want = if f.is_allowed(n) { FilterVerdict::Allow } else { FilterVerdict::Deny };
            assert_eq!(f.verdict(n), want, "enforcing, syscall {n}");
        }
        f.audit = true;
        for n in 0..2000u16 {
            let want = if f.is_allowed(n) { FilterVerdict::Allow } else { FilterVerdict::Audit };
            assert_eq!(f.verdict(n), want, "audit mode, syscall {n}");
        }
    }

    /// A number past `u16::MAX` is refused by a filter in force, audit mode
    /// included, and never compared by its low 16 bits: `65536 + 23` must not
    /// pass as the listed 23. With no filter in force it is the dispatcher's
    /// default arm that answers, as for every other number.
    ///
    /// **Canary.** Drop the `num > u16::MAX` check from `verdict_for`: 65559
    /// reads `Allow`.
    #[test]
    fn a_number_past_u16_is_refused_never_aliased() {
        use crate::filter::FilterVerdict;
        let alias = 65_536u64 + 23;
        let mut f = SyscallFilter::disabled();
        assert_eq!(f.verdict_for(alias), FilterVerdict::Allow, "no filter in force");
        f.enabled = true;
        f.allow(23);
        assert_eq!(f.verdict_for(23), FilterVerdict::Allow);
        assert_eq!(f.verdict_for(alias), FilterVerdict::Deny, "enforcing: 65559 aliased 23");
        assert_eq!(f.verdict_for(u64::MAX), FilterVerdict::Deny);
        f.audit = true;
        assert_eq!(f.verdict_for(24), FilterVerdict::Audit);
        assert_eq!(f.verdict_for(alias), FilterVerdict::Deny, "audit mode: 65559 aliased 23");
        assert_eq!(f.verdict_for(65_536 + 24), FilterVerdict::Deny, "audit mode lets no wide number through");
    }

    /// A filter that is off allows everything, whatever its audit byte says:
    /// audit mode exists only inside a filter that is on.
    ///
    /// **Canary.** Test `audit` before `enabled` in `verdict`: `Audit` for every
    /// number.
    #[test]
    fn a_disabled_filter_allows_everything_even_marked_audit() {
        use crate::filter::FilterVerdict;
        let mut f = SyscallFilter::disabled();
        f.audit = true;
        for n in [0u16, 3, 999, u16::MAX] {
            assert_eq!(f.verdict(n), FilterVerdict::Allow, "syscall {n}");
        }
    }

    /// The list scan that is left — numbers at or past the bitmap, which no
    /// real syscall is — is bounded by the array whatever `count` says, so a
    /// corrupted count cannot make the dispatcher read past the filter.
    ///
    /// **Changed with the bitmap (wave 7).** This used to plant `77` straight
    /// into `allowed[63]` and expect `Allow`. A number below
    /// `SYSCALL_FILTER_BITMAP_BITS` is now answered from the bitmap, which only
    /// `allow` writes, so a planted list entry grants nothing there (the
    /// second half below checks that). The clamp still guards the scan, so the
    /// planted number is now one the bitmap does not cover.
    ///
    /// **Canary.** Drop `.min(SYSCALL_FILTER_MAX)` from `listed_past_bitmap`:
    /// slicing `allowed[..255]` panics.
    #[test]
    fn a_count_past_the_array_scans_only_the_array() {
        use crate::filter::{FilterVerdict, SYSCALL_FILTER_BITMAP_BITS};
        let wide = SYSCALL_FILTER_BITMAP_BITS as u16 + 77;
        let mut f = SyscallFilter::disabled();
        f.enabled = true;
        f.allowed[SYSCALL_FILTER_MAX - 1] = wide;
        f.count = u8::MAX;
        assert_eq!(f.verdict(wide), FilterVerdict::Allow);
        assert_eq!(f.verdict(wide + 1), FilterVerdict::Deny);
        // Below the bitmap bound only `allow` grants: a list entry written
        // around it is not a grant.
        f.allowed[SYSCALL_FILTER_MAX - 2] = 77;
        assert_eq!(f.verdict(77), FilterVerdict::Deny);
        assert!(!f.is_allowed(77));
    }

    /// `audit` took the tail padding and `bits` was appended after it: every
    /// original field is where it was (offsets 0/2/130/131, measured on the
    /// unmodified `filter.rs`), and the struct grew by exactly the 80 bytes
    /// of the 640-bit bitmap, 132 → 212. `filter.rs` asserts size and offsets at
    /// compile time for the kernel as well.
    ///
    /// Wave 9: the list grew from 64 to 96 entries (`SYSCALL_FILTER_MAX`), so
    /// `count`/`audit`/`bits` each moved by 64 and the struct is 276 bytes.
    ///
    /// Wave 15: the length is `CONFIG_SYSCALL_FILTER_MAX` (default 128), so
    /// the offsets are written as functions of it, independently of the
    /// constants `filter.rs` derives: `count` after the list, `audit` the
    /// next byte, `bits` at the next 4-byte boundary, 84 bytes of bitmap.
    #[test]
    fn the_audit_byte_and_the_bitmap_moved_nothing() {
        use core::mem::{offset_of, size_of};
        let n = azos_limits::SYSCALL_FILTER_MAX;
        assert_eq!(SYSCALL_FILTER_MAX, n, "the filter reads its length from Kconfig");
        let count = 2 + 2 * n;
        let bits = (count + 2).next_multiple_of(4);
        assert_eq!(offset_of!(SyscallFilter, enabled), 0);
        assert_eq!(offset_of!(SyscallFilter, allowed), 2);
        assert_eq!(offset_of!(SyscallFilter, count), count);
        assert_eq!(offset_of!(SyscallFilter, audit), count + 1);
        assert_eq!(offset_of!(SyscallFilter, bits), bits);
        // The interfaces word (kernel-hosted endpoints the image may call) is
        // appended after the bitmap: the other fields did not move.
        assert_eq!(offset_of!(SyscallFilter, ifaces), bits + 84);
        // The op classes (one byte per kind) follow the interfaces word.
        assert_eq!(offset_of!(SyscallFilter, ops), bits + 84 + 4);
        assert_eq!(size_of::<SyscallFilter>(), bits + 84 + 4 + 2 * azos_abi::invoke::OP_KINDS);
        if n == 128 {
            assert_eq!(size_of::<SyscallFilter>(), 380, "the default's size, named in filter.rs");
        }
    }
}

/// The bitmap verdict against the linear scan it replaced (owner decision,
/// round 8: `verdict_for` was a scan of `allowed[..count]` on every filtered
/// syscall; it is now one bit of a bitmap `allow` builds).
///
/// **Exhaustive, not sampled.** Every filter the kernel can install — each
/// `IMAGE_PROFILES` row, each role profile, the disabled filter, an enabled
/// empty one (the scheduler's fail-closed deny-all is built that way) — plus
/// synthetic ones that reach the two edges of the representation (entries past
/// the bitmap, and a filter that overflowed `SYSCALL_FILTER_MAX`), each with
/// audit off and on, asked about every `u16` number (a superset of
/// `0..=max_syscall + 64`) and a set of numbers past `u16::MAX`. The reference
/// is the old `verdict_for` body kept verbatim under `#[cfg(test)]`
/// (`SyscallFilter::verdict_for_linear_scan_reference`).
///
/// **Canary.** In `SyscallFilter::allow`, set bit `(n ^ 1) & 31` instead of
/// `n & 31`: the first profile checked fails, naming itself, its audit mode
/// and the number.
#[cfg(test)]
mod bitmap_equivalence {
    use crate::filter::{FilterVerdict, SyscallFilter, SYSCALL_FILTER_BITMAP_BITS, SYSCALL_FILTER_MAX};
    use crate::seccomp::*;

    /// Numbers past `u16::MAX`: the first one, low-16-bit aliases of listed
    /// and unlisted numbers, and the widest.
    const WIDE: &[u64] = &[
        u16::MAX as u64 + 1,
        65_536 + 1,
        65_536 + 172,
        65_536 + 1_000,
        1 << 32,
        (1 << 32) + 172,
        u64::MAX - 1,
        u64::MAX,
    ];

    /// Every filter to compare, named for the failure message.
    fn filters() -> Vec<(String, SyscallFilter)> {
        let mut v: Vec<(String, SyscallFilter)> = Vec::new();
        for p in IMAGE_PROFILES {
            v.push((format!("image {}", p.image), image_filter(p)));
        }
        for id in [PROFILE_UNRESTRICTED, PROFILE_MINIMAL] {
            v.push((format!("role profile {id}"), profile_to_filter(id).expect("known profile")));
        }
        v.push(("disabled".into(), SyscallFilter::disabled()));
        let mut deny_all = SyscallFilter::disabled();
        deny_all.enabled = true;
        v.push(("enabled, empty (deny-all)".into(), deny_all));
        // Entries on both sides of the bitmap bound and at the ends of u16.
        let mut edges = SyscallFilter::disabled();
        edges.enabled = true;
        let b = SYSCALL_FILTER_BITMAP_BITS as u16;
        for n in [0, 1, 31, 32, 63, 64, 580, 582, 599, 600, b - 1, b, b + 1, 9_999, u16::MAX - 1, u16::MAX] {
            edges.allow(n);
        }
        v.push(("synthetic: bitmap and u16 edges".into(), edges));
        // Filled past capacity: the dropped entries (in range and wide) must
        // stay denied in both representations.
        let mut full = SyscallFilter::disabled();
        full.enabled = true;
        for n in 0..SYSCALL_FILTER_MAX as u16 {
            full.allow(n * 7);
        }
        for n in [5u16, 600, b + 5] {
            full.allow(n);
        }
        v.push(("synthetic: overflowed past SYSCALL_FILTER_MAX".into(), full));
        v
    }

    #[test]
    fn the_bitmap_verdict_is_the_linear_scan_verdict_for_every_filter_and_number() {
        let mut checked = 0u64;
        for (name, base) in filters() {
            for audit in [false, true] {
                let mut f = base;
                f.audit = audit;
                let nums = (0..=u16::MAX as u64).chain(WIDE.iter().copied());
                for n in nums {
                    let want = f.verdict_for_linear_scan_reference(n);
                    let got = f.verdict_for(n);
                    assert_eq!(got, want, "{name}, audit={audit}: syscall {n}: bitmap {got:?}, scan {want:?}");
                    if n <= u16::MAX as u64 {
                        let listed = want == FilterVerdict::Allow;
                        assert_eq!(f.is_allowed(n as u16), listed, "{name}, audit={audit}: is_allowed({n})");
                    }
                    checked += 1;
                }
            }
        }
        // Not vacuous: every row, the two role profiles and the four others,
        // twice, over 65,536 + WIDE numbers each.
        let rows = IMAGE_PROFILES.len() as u64 + 2 + 4;
        assert_eq!(checked, rows * 2 * (65_536 + WIDE.len() as u64));
    }

    /// The two representations hold the same set: bit `n` is set exactly for
    /// the listed `n` below the bound. The equivalence above implies it for
    /// the verdict; this names the entry when it breaks.
    #[test]
    fn every_profile_bitmap_is_exactly_its_list() {
        for (name, f) in filters() {
            for n in 0..SYSCALL_FILTER_BITMAP_BITS {
                let bit = (f.bits[n / 32] >> (n % 32)) & 1 != 0;
                let listed = f.allowed[..f.count as usize].contains(&(n as u16));
                assert_eq!(bit, listed, "{name}: syscall {n}: bit {bit}, list {listed}");
            }
        }
    }

    /// Fork copies the filter by value and exec keeps or installs one whole;
    /// neither recomputes the bitmap, so a copy must carry it. `activate_profile`
    /// and `install_image_profile` go through the test's stand-in slot, which
    /// stores the struct the kernel's `TASKS[idx].syscall_filter = f` does.
    #[test]
    fn installing_and_copying_carry_the_bitmap() {
        use crate::scheduler;
        let _g = crate::activation::fresh();
        assert_eq!(activate_profile(PROFILE_MINIMAL), 0);
        let installed = scheduler::current_syscall_filter();
        let want = profile_to_filter(PROFILE_MINIMAL).unwrap();
        assert_eq!(installed.bits, want.bits, "activate_profile installed another bitmap");
        let child = installed; // `sys_fork_impl`: the parent's filter, by value
        for n in 0..=u16::MAX {
            assert_eq!(child.verdict(n), want.verdict_for_linear_scan_reference(n as u64), "fork copy, {n}");
        }
        scheduler::reset_for_test();
        let row = &IMAGE_PROFILES[0];
        assert_eq!(install_image_profile(row), 0);
        assert_eq!(scheduler::current_syscall_filter().bits, image_filter(row).bits, "{}", row.image);
        scheduler::reset_for_test();
    }
}

#[cfg(test)]
mod profiles {
    use crate::filter::SYSCALL_FILTER_MAX;
    use crate::seccomp::*;
    use azos_abi::invoke::{op_class, op_kind, DOMAIN_SOCKET};
    use azos_syscall_numbers::numbers as real;

    /// A profile that cannot copy its address space (`SYS_FOREIGN_FORK`).
    fn assert_no_process_ops(f: &crate::task::SyscallFilter, who: &str) {
        assert!(
            !f.is_allowed(azos_abi::syscall_nr::SYS_FOREIGN_FORK as u16),
            "{who} lists SYS_FOREIGN_FORK",
        );
    }

    /// Every syscall each profile is documented to grant, named by the
    /// **real** number from `crates/core/syscall/src/numbers.rs`.
    fn common() -> Vec<u16> {
        vec![
            real::SYS_EXIT, real::SYS_GETPID, real::SYS_YIELD, real::SYS_SLEEP_UNTIL,
            real::SYS_INVOKE,
        ].into_iter().map(|n| n as u16).collect()
    }

    const RESTRICTED: [u64; 1] = [PROFILE_MINIMAL];

    /// No role profile grants a Cap-typed syscall: a role profile is the
    /// coarse sandbox a task puts on itself, and everything that needs a
    /// capability is granted per image (`IMAGE_PROFILES`), where the row also
    /// says which interfaces and op classes the binary may use.
    ///
    /// **Canary.** Add `SYS_MO_CREATE` to `PROFILE_MINIMAL`'s list:
    /// red, naming it.
    #[test]
    fn no_role_profile_grants_a_cap_typed_syscall() {
        for p in RESTRICTED {
            let f = profile_to_filter(p).expect("known profile");
            for &n in azos_abi::syscall_nr::CAP_TYPED_SYSCALLS {
                assert!(!f.is_allowed(n as u16), "role profile {p} grants Cap-typed syscall {n}");
            }
        }
    }

    /// Console input has ONE reader by authority as well
    /// as by the kernel's owner claim. `LOG_CONSOLE_WAIT` is in the
    /// shell's profile and in no other, so no tool, driver or test image can
    /// even ask for console bytes; `SYS_SPAWN_EX` and `SYS_ALERT`
    /// (611) are the shell's too — and, for 608 only, `VSBENCH.ELF`'s since
    /// wave 12 (its `spawn+wait` lane; the call still needs a `Cap<Launch>`
    /// for the image, which only QEMU topologies grant it). No role profile
    /// lists any of the three.
    ///
    /// Wave 13: a Linux image's row lists 609 and 611 too (`LXHELLO.ELF`, and
    /// the third-party BusyBox row), because seccomp runs after translation
    /// and its `read` and `kill` reach them. A Linux task cannot issue a
    /// native number itself: its 609 is a `read` of a console the shell LENT
    /// it (the kernel's lend is the authority), its 611 a `kill` of its own
    /// descendants (the same ancestry `SYS_ALERT` checks).
    ///
    /// Plan item 7: `IPCTEST.ELF` lists 611 too, for phase K, which
    /// force-kills its own fork children blocked in the waits it exercises
    /// (the same ancestry check `SYS_ALERT` makes of the shell). A QEMU
    /// test image with an enforced row, like `VSBENCH.ELF`'s 608; the widest
    /// row (`ABITEST.ELF`) has no room for those waits.
    ///
    /// `ABICHILD.ELF` lists 611 too, for the orphan tests: the adopter of an
    /// orphan (a subreaper) asks it to stop once it has listed it, which ends
    /// the orphan's futex wait (a request, not a kill; the same ancestry check).
    ///
    /// Console input (the console handle's `WAIT` op) is no longer a number of
    /// its own: it is an op of `SYS_INVOKE`, whose per-image gate is the row's
    /// op-class mask.
    ///
    /// The SSH server (`SSHD.ELF`) starts the command of a session and stops
    /// it on `^C` or hang-up, so its row lists both; what it may start is its
    /// topology row's launch grants. The login service (`LOGIND.ELF`) starts
    /// the user's shell and stops the session at logout, so it lists both too.
    ///
    /// **Canary.** Add `SYS_SPAWN_EX` to `TOOLBOX.ELF`'s row: red, naming it.
    #[test]
    fn only_the_shell_profile_lists_the_shell_calls() {
        use azos_abi::syscall_nr::{SYS_SPAWN_EX, SYS_ALERT};
        for n in [SYS_SPAWN_EX, SYS_ALERT] {
            let holders: &[&str] =
                match n {
                    SYS_SPAWN_EX => &["SH.ELF", "VSBENCH.ELF", "ABICHILD.ELF", "COMPMGR.ELF", "SSHD.ELF", "LOGIND.ELF"],
                    _ => &["SH.ELF", "LXHELLO.ELF", "IPCTEST.ELF", "COMPMGR.ELF", "SSHD.ELF", "ABICHILD.ELF", "LOGIND.ELF"],
                };
            let n = n as u16;
            for ip in IMAGE_PROFILES {
                assert_eq!(
                    image_filter(ip).is_allowed(n),
                    holders.contains(&ip.image),
                    "image profile {} and syscall {n}: only {holders:?} may list it", ip.image,
                );
            }
            for p in RESTRICTED {
                assert!(!profile_to_filter(p).expect("known profile").is_allowed(n),
                        "role profile {p} grants shell call {n}");
            }
        }
    }

    /// The `power` interface is `POWER.ELF`'s alone, and that
    /// profile holds no shell call (no exec, kill, spawn or file open).
    ///
    /// **Canary.** Add `azos_devif::key::POWER` to `SH.ELF`'s row: red, naming
    /// it.
    #[test]
    fn only_the_power_tool_lists_the_power_interface() {
        use azos_abi::syscall_nr as nr;
        let key = azos_devif::key::POWER;
        for ip in IMAGE_PROFILES {
            assert_eq!(image_filter(ip).iface_listed(key), ip.image == "POWER.ELF",
                       "image profile {} and interface {key}: only POWER.ELF may list it", ip.image);
        }
        let pw = IMAGE_PROFILES.iter().find(|p| p.image == "POWER.ELF").expect("POWER.ELF row");
        let f = image_filter(pw);
        for m in [nr::SYS_SPAWN_EX, nr::SYS_ALERT] {
            assert!(!f.is_allowed(m as u16), "POWER.ELF lists {m}");
        }
        assert_no_process_ops(&f, "POWER.ELF");
        assert!(!pw.audit, "the power tool's row is enforcing, not audit");
    }

    /// Console input is `TERMD.ELF`'s alone (since the Terminal
    /// object: the shell asks the terminal server for lines), as an op class:
    /// the console's `WAIT` is class `WAIT` of kind `Log`. No other native
    /// image, no third-party image and no role profile lists it.
    ///
    /// **Canary.** Add `LOG_CONSOLE_WAIT` to `TOOLBOX.ELF`'s `ops`: red, naming
    /// it.
    #[test]
    fn only_the_terminal_server_lists_console_input() {
        use azos_abi::invoke::{op_class, op_kind, LOG_CONSOLE_WAIT};
        let (k, c) = (op_kind(LOG_CONSOLE_WAIT), op_class(LOG_CONSOLE_WAIT));
        for ip in IMAGE_PROFILES {
            assert_eq!(
                image_filter(ip).op_listed(k, c),
                ip.image == "TERMD.ELF",
                "image profile {} and the console's input: only TERMD.ELF may list it", ip.image,
            );
        }
        for ip in THIRDPARTY_PROFILES {
            assert!(!image_filter(ip).op_listed(k, c), "third-party row {} lists console input", ip.image);
        }
        for p in RESTRICTED {
            assert!(!profile_to_filter(p).expect("known profile").op_listed(k, c),
                    "role profile {p} grants console input");
        }
    }

    /// Wave 15: the tracer's ops are `TRACECTL.ELF`'s alone, and that profile
    /// has no exec, spawn, kill or untyped privileged call. The tracer's ops
    /// are the `READ`, `CTL` and `ADMIN` classes of kind `Log` (the console
    /// has only `WRITE` and `WAIT`).
    ///
    /// **Canary.** Add `LOG_TRACE_SET_MASK` to `TOOLBOX.ELF`'s `ops`: red,
    /// naming it.
    #[test]
    fn only_the_trace_tool_lists_the_trace_ops() {
        use azos_abi::invoke::{op_class, op_kind, LOG_TRACE_INFO, LOG_TRACE_MAP, LOG_TRACE_SET_MASK};
        use azos_abi::syscall_nr as nr;
        for op in [LOG_TRACE_INFO, LOG_TRACE_MAP, LOG_TRACE_SET_MASK] {
            let (k, c) = (op_kind(op), op_class(op));
            for ip in IMAGE_PROFILES {
                assert_eq!(image_filter(ip).op_listed(k, c), ip.image == "TRACECTL.ELF",
                           "image profile {} and trace op {op:#06x}: only TRACECTL.ELF may list it", ip.image);
            }
            for p in RESTRICTED {
                assert!(!profile_to_filter(p).expect("known profile").op_listed(k, c),
                        "role profile {p} grants trace op {op:#06x}");
            }
        }
        let tc = IMAGE_PROFILES.iter().find(|p| p.image == "TRACECTL.ELF").expect("TRACECTL.ELF row");
        let f = image_filter(tc);
        // (`SYS_MO_MAP` is listed like every pipeline stage's: a pipe on its
        // stdout is a shared region it maps; the trace rings are mapped by
        // the `LOG_TRACE_MAP` op, not by it.)
        for m in [nr::SYS_SPAWN_EX, nr::SYS_ALERT] {
            assert!(!f.is_allowed(m as u16), "TRACECTL.ELF lists {m}");
        }
        assert_no_process_ops(&f, "TRACECTL.ELF");
        assert!(!tc.audit, "the trace tool's row is enforcing, not audit");
    }

    /// Wave 12: each family's interface is its tool's alone, and the four
    /// tools hold no other privileged or exec call and no other interface.
    ///
    /// **Canary.** Add `azos_devif::key::OTA` to `CONFIG.ELF`'s row: red,
    /// naming it.
    #[test]
    fn each_family_interface_is_its_tools_alone() {
        use azos_abi::syscall_nr as nr;
        use azos_devif::key;
        let fams = [("FLIGHT.ELF", key::FLIGHT), ("BEHAVIOR.ELF", key::BEHAVIOR),
                    ("CONFIG.ELF", key::CONFIG), ("OTA.ELF", key::OTA)];
        // The one reader besides the tool: the package installer lists `ota`
        // to read the boot slots (`Ota::status`) when it stages a whole-system
        // update into the inactive slot. Its grant is READ (topology
        // `PKG_OTA_STATUS`), so `rollback` and `switch`, which need WRITE, stay
        // `OTA.ELF`'s.
        let reader = |img: &str, k: u16| if img == "OTA.ELF" && k == key::OTA { Some("PKGD.ELF") } else { None };
        for (img, k) in fams {
            for ip in IMAGE_PROFILES {
                assert_eq!(image_filter(ip).iface_listed(k), ip.image == img || Some(ip.image) == reader(img, k),
                           "image profile {} and interface {k}: only {img} (and its named reader) may list it", ip.image);
            }
            let row = IMAGE_PROFILES.iter().find(|p| p.image == img).expect("tool row");
            assert_eq!(row.ifaces, &[k], "{img} lists exactly its own interface");
            let f = image_filter(row);
            for m in [nr::SYS_SPAWN_EX, nr::SYS_ALERT] {
                assert!(!f.is_allowed(m as u16), "{img} lists {m}");
            }
            assert_no_process_ops(&f, img);
            assert!(!f.op_listed(op_kind(DOMAIN_SOCKET), op_class(DOMAIN_SOCKET)), "{img} lists the network");
            assert!(!row.audit, "{img}'s row is enforcing, not audit");
        }
    }

    /// The module ops are `LXSRV.ELF`'s alone, and
    /// the Linux server's profile holds no actuator, device, fork/exec
    /// or untyped power call: a Linux server never holds an
    /// actuator), by profile as well as by topology row. It lists
    /// `SYS_CAP_INFO` and `SYS_IPC_CALL_V2` for one reason, the entropy
    /// endpoint its allocator reads (`azos_ualloc`); the lookup reads the
    /// task's own table, and the row holds that one capability
    /// (topology-tests).
    ///
    /// **Canary.** Add `DOMAIN_MODULE_MAP_X` to `TOOLBOX.ELF`'s row, or
    /// `azos_devif::key::GPIO` to `LXSRV.ELF`'s ifaces: red, naming it.
    #[test]
    fn only_the_linux_server_lists_the_module_calls() {
        use azos_abi::invoke::{op_class, op_kind, DOMAIN_MODULE_MAP_X, DOMAIN_MODULE_VERIFY};
        use azos_abi::syscall_nr as nr;
        for op in [DOMAIN_MODULE_VERIFY, DOMAIN_MODULE_MAP_X] {
            let (k, c) = (op_kind(op), op_class(op));
            for ip in IMAGE_PROFILES {
                assert_eq!(image_filter(ip).op_listed(k, c), ip.image == "LXSRV.ELF",
                           "image profile {} and module op {op:#06x}: only LXSRV.ELF may list it", ip.image);
            }
            for p in RESTRICTED {
                assert!(!profile_to_filter(p).expect("known profile").op_listed(k, c),
                        "role profile {p} grants module op {op:#06x}");
            }
        }
        let lx = IMAGE_PROFILES.iter().find(|p| p.image == "LXSRV.ELF").expect("LXSRV.ELF row");
        let f = image_filter(lx);
        assert!(!f.is_allowed(nr::SYS_SPAWN_EX as u16), "LXSRV.ELF lists spawn_ex");
        assert_no_process_ops(&f, "LXSRV.ELF");
        assert_eq!(lx.ifaces, &[azos_devif::key::ENTROPY][..],
            "a Linux server calls one kernel-hosted interface, the entropy pool its allocator reads");
        assert!(!lx.audit, "the Linux server's row is enforcing, not audit");
    }

    /// The shell holds no hardware authority by profile either —
    /// no device, network, power, fork/exec or raw console call.
    #[test]
    fn the_shell_profile_has_no_hardware_power_or_exec_call() {
        let sh = IMAGE_PROFILES.iter().find(|p| p.image == "SH.ELF").expect("SH.ELF row");
        let f = image_filter(sh);
        assert_no_process_ops(&f, "SH.ELF");
        assert!(!f.op_listed(op_kind(DOMAIN_SOCKET), op_class(DOMAIN_SOCKET)), "SH.ELF lists the network");
        assert!(sh.ifaces.is_empty(), "the shell calls no kernel-hosted interface itself");
        assert!(!sh.audit, "the shell's row is enforcing, not audit");
    }

    /// Typed syscalls no profile grants, and the reason each is out.
    ///
    /// This is the half with teeth. The twin test above passes against a
    /// filter that allows everything; this one does not. Every entry is a
    /// typed call whose untyped counterpart is *absent* from the profile that
    /// would otherwise be its home, so allowing it would be a real widening.
    const DENIED_EVERYWHERE: &[(u64, &str)] = &[
        (real::SYS_CAP_INFO,
         "task-initiated discovery. Seccomp is one-way (activate_profile \
          returns SECCOMP_E_ALREADY once a filter is on), so the pattern is \
          look up your handles FIRST and sandbox yourself AFTER. Putting it \
          in COMMON would widen every profile including MINIMAL"),
        (real::SYS_RING_SETUP, "no role profile grants io_rings"),
        (real::SYS_MO_CREATE, "no profile grants shared memory"),
    ];

    /// A typed call whose untyped counterpart is not in any profile stays
    /// DENIED. Without this, "the typed one is allowed" passes against a filter
    /// that allows everything.
    #[test]
    fn no_role_profile_grants_a_call_denied_everywhere() {
        for p in RESTRICTED {
            let f = profile_to_filter(p).expect("known profile");
            for &(n, why) in DENIED_EVERYWHERE {
                assert!(
                    !f.is_allowed(n as u16),
                    "profile {p} grants syscall {n}, which no profile should: {why}",
                );
            }
        }
    }

    /// **The drift test.** `seccomp.rs` cannot depend on `azos_syscall`
    /// (that crate depends on `azos_sched`, so the edge would close a
    /// cycle), so it redeclares all 29 numbers it needs as private local
    /// `const`s under a comment saying they "must match
    /// azos_syscall::numbers exactly". Nothing enforced that.
    ///
    /// This asserts the consequence rather than the constants: build each
    /// profile and ask it about the number the **real** table gives. Renumber
    /// a syscall on one side only and a profile stops granting the call it
    /// names — or, worse, keeps granting whatever now sits at the old number.
    #[test]
    fn every_profile_grants_the_real_syscall_numbers() {
        for p in RESTRICTED {
            let f = profile_to_filter(p).expect("known profile");
            for n in common() {
                assert!(f.is_allowed(n), "profile {p} must grant common syscall {n}");
            }
        }
    }

    /// A whitelist is only as good as what it leaves out. Asserting the exact
    /// `count` is the part that matters: without it a profile could grant
    /// every number in the table and still pass the test above.
    #[test]
    fn every_profile_grants_nothing_beyond_its_list() {
        for p in RESTRICTED {
            let f = profile_to_filter(p).expect("known profile");
            let expected = common().len();
            assert_eq!(
                f.count as usize, expected,
                "profile {p} grants {} syscalls, expected exactly {expected}",
                f.count,
            );
            assert!(f.enabled, "a restricted profile must have the filter ON");
        }
    }

    /// `allow()` drops entries past `SYSCALL_FILTER_MAX` **silently**. The
    /// failure mode is a syscall quietly missing from a whitelist, which
    /// presents as a working task that fails at the one call it needed —
    /// on the board, not here. Assert the headroom so growth trips here.
    ///
    /// **The ceiling moved from 32 to 64 on 2026-09-07 (owner decision), and
    /// the reason was this test.** A role profile sat at 25 of 32, and the
    /// calls a migrated family could not run without would have left four
    /// slots for every remaining family. Rationing a security filter by an
    /// array bound is how policy ends up shaped by the wrong thing.
    ///
    /// This test deliberately does NOT hard-code either number: it reads
    /// `SYSCALL_FILTER_MAX` and derives the profile size, so raising the
    /// ceiling again does not require editing it.
    #[test]
    fn no_profile_comes_close_to_the_filter_capacity() {
        for p in RESTRICTED {
            let f = profile_to_filter(p).expect("known profile");
            assert!(
                (f.count as usize) < SYSCALL_FILTER_MAX,
                "profile {p} fills {}/{SYSCALL_FILTER_MAX} entries — grow SYSCALL_FILTER_MAX \
                 before adding more, or `allow()` will drop them without a word",
                f.count,
            );
        }
    }

    #[test]
    fn the_unrestricted_profile_is_a_disabled_filter() {
        let f = profile_to_filter(PROFILE_UNRESTRICTED).expect("UNRESTRICTED is a known id");
        assert!(!f.enabled);
        assert!(f.is_allowed(real::SYS_SPAWN_EX as u16));
    }

    /// An unknown id must be distinguishable from "no sandbox requested".
    /// The arm used to be `_ => disabled()`, so a typo'd profile id produced
    /// an unrestricted task and reported success.
    #[test]
    fn an_unknown_profile_id_is_none_not_unrestricted() {
        for bad in [5u64, 99, u64::MAX] {
            assert!(profile_to_filter(bad).is_none(), "id {bad} names no profile");
        }
    }
}

#[cfg(test)]
mod activation {
    use crate::filter::FilterVerdict;
    use crate::scheduler;
    use crate::seccomp::*;
    use azos_syscall_numbers::numbers as real;

    /// One static "current task" behind every test in this module.
    static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

    pub(super) fn fresh() -> std::sync::MutexGuard<'static, ()> {
        let g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        scheduler::reset_for_test();
        g
    }

    #[test]
    fn activating_a_profile_confines_the_task() {
        let _g = fresh();
        assert_eq!(activate_profile(PROFILE_MINIMAL), 0);
        let f = scheduler::current_syscall_filter();
        assert!(f.enabled);
        assert!(f.is_allowed(real::SYS_EXIT as u16));
        assert!(!f.is_allowed(real::SYS_SPAWN_EX as u16));
    }

    /// The one-way property: a confined task cannot widen its own sandbox,
    /// which matters because a restricted task can call the filter op again.
    #[test]
    fn a_filter_cannot_be_replaced_or_removed() {
        let _g = fresh();
        assert_eq!(activate_profile(PROFILE_MINIMAL), 0);
        assert_eq!(
            activate_profile(PROFILE_UNRESTRICTED), SECCOMP_E_ALREADY,
            "a confined task must not be able to ask for no sandbox",
        );
        assert_eq!(
            activate_profile(PROFILE_MINIMAL), SECCOMP_E_ALREADY,
            "nor to install it again",
        );
        let f = scheduler::current_syscall_filter();
        assert!(!f.is_allowed(real::SYS_SPAWN_EX as u16), "MINIMAL still in force");
    }

    /// The unknown-id check runs before anything is installed: a request the
    /// kernel could not honour must leave the task exactly as it was.
    #[test]
    fn an_unknown_id_installs_nothing_and_says_so() {
        let _g = fresh();
        assert_eq!(activate_profile(7), SECCOMP_E_BADPROFILE);
        assert!(!scheduler::current_syscall_filter().enabled, "nothing was installed");
        // And the gate was not burned: a real profile still applies.
        assert_eq!(activate_profile(PROFILE_MINIMAL), 0);
        assert!(scheduler::current_syscall_filter().is_allowed(real::SYS_EXIT as u16));
    }

    /// Documents the trap the module header warns about: asking for
    /// UNRESTRICTED returns 0 without confining anything, and does **not**
    /// burn the one-way gate. A 0 from `activate_profile` is not on its own
    /// proof that a task is now sandboxed.
    #[test]
    fn unrestricted_returns_success_without_confining() {
        let _g = fresh();
        assert_eq!(activate_profile(PROFILE_UNRESTRICTED), 0);
        assert!(!scheduler::current_syscall_filter().enabled);
        assert_eq!(activate_profile(PROFILE_MINIMAL), 0, "the gate was not burned");
        assert!(scheduler::current_syscall_filter().enabled);
    }

    // ── Image profiles, installed at exec ───────────────────────────────
    //
    // These share the static "current task" above, so they live in this
    // module and take the same lock.

    /// The exec path installs the row the loaded BYTES are bound to, and what it
    /// installs refuses a call outside the row.
    #[test]
    fn exec_installs_the_profile_of_the_image_it_loads() {
        let _g = fresh();
        let bytes = crate::image_profiles::shipped_elf("UHELLO.ELF");
        let p = image_for_digest(&image_digest(&bytes)).expect("uhello's bytes are bound to a row");
        assert_eq!(p.image, "UHELLO.ELF");
        assert_eq!(install_image_profile(p), 0);
        let f = scheduler::current_syscall_filter();
        assert!(f.enabled, "an installed image profile must have the filter ON");
        assert!(!f.audit, "UHELLO.ELF is not an audit row");
        assert_eq!(f.verdict(real::SYS_INVOKE as u16), FilterVerdict::Allow);
        assert_eq!(
            f.verdict(real::SYS_GETPID as u16),
            FilterVerdict::Deny,
            "getpid is outside UHELLO.ELF's profile",
        );
        assert_eq!(
            f.verdict(real::SYS_IPC_FAST_CALL_EP as u16),
            FilterVerdict::Deny,
            "the fast IPC call is outside UHELLO.ELF's profile: uhello issues it to see it refused",
        );
    }

    /// An audit row installs an audit filter: the unlisted probe goes through
    /// to be recorded, a listed call is plainly allowed.
    #[test]
    fn an_audit_row_installs_an_allow_and_record_filter() {
        let _g = fresh();
        let bytes = crate::image_profiles::shipped_elf("CAPTEST.ELF");
        let p = image_for_digest(&image_digest(&bytes)).expect("captest's bytes are bound to a row");
        assert_eq!(install_image_profile(p), 0);
        let f = scheduler::current_syscall_filter();
        assert!(f.enabled && f.audit, "CAPTEST.ELF's filter must be on and in audit mode");
        assert_eq!(f.verdict(116), FilterVerdict::Audit, "the retired SYS_CAP_GRANT probe");
        assert_eq!(f.verdict(real::SYS_CAP_INFO as u16), FilterVerdict::Allow);
    }

    /// One-way across exec, the rule Linux applies to a seccomp filter across
    /// `execve`: a task already confined keeps its own filter, even when the
    /// image it execs is bound to a wider row, and does not pick up that row's
    /// audit mode.
    #[test]
    fn exec_never_replaces_a_filter_already_in_force() {
        let _g = fresh();
        assert_eq!(activate_profile(PROFILE_MINIMAL), 0);
        let abitest = IMAGE_PROFILES.iter().find(|p| p.image == "ABITEST.ELF").unwrap();
        assert_eq!(install_image_profile(abitest), SECCOMP_E_ALREADY);
        let f = scheduler::current_syscall_filter();
        assert_eq!(
            f.op_verdict(azos_abi::cap::CapKind::Domain as u8, azos_abi::invoke::CLASS_WAIT),
            FilterVerdict::Deny,
            "ABITEST.ELF's wider profile must not replace MINIMAL",
        );
        assert!(!f.audit, "nor switch MINIMAL to audit mode");
    }

    // ── Spawn: the child's filter ─────────

    /// **The child runs under its image's row, not the caller's.** The caller
    /// here is confined by ABITEST.ELF's row, audit mode, getpid allowed: the
    /// process the `userspace: ABI conformance` scenario spawns from. The child
    /// is uhello, whose row refuses getpid and is not in audit mode. A plan
    /// that took the caller's filter would allow getpid and audit; one with no
    /// filter would allow everything. Planning installs nothing on the caller.
    #[test]
    fn a_spawned_child_runs_under_its_images_row_not_the_callers() {
        use crate::spawn_policy::plan_spawn;
        let _g = fresh();
        let abitest = IMAGE_PROFILES.iter().find(|p| p.image == "ABITEST.ELF").unwrap();
        assert_eq!(install_image_profile(abitest), 0);
        let getpid = real::SYS_GETPID as u16;
        assert_eq!(
            scheduler::current_syscall_filter().verdict(getpid),
            FilterVerdict::Allow,
            "the check discriminates only while the caller's row allows getpid",
        );

        let bytes = crate::image_profiles::shipped_elf("UHELLO.ELF");
        let plan = plan_spawn(&image_digest(&bytes)).expect("uhello's bytes are bound to a row");
        assert_eq!(plan.profile.image, "UHELLO.ELF");
        let f = plan.filter;
        assert!(f.enabled, "the child's filter must be on");
        assert!(!f.audit, "UHELLO.ELF is not an audit row; the caller's is");
        assert_eq!(f.verdict(getpid), FilterVerdict::Deny, "getpid is outside UHELLO.ELF's row");
        assert_eq!(f.verdict(real::SYS_INVOKE as u16), FilterVerdict::Allow);

        let caller = scheduler::current_syscall_filter();
        assert!(caller.enabled && caller.audit, "planning a spawn must not touch the caller's filter");
        assert_eq!(caller.verdict(getpid), FilterVerdict::Allow);
    }
}

/// **Every shipped ring-3 binary runs under the profile its source says it
/// needs** (owner decision, 2026-09-14).
///
/// `crates/core/sched/src/seccomp.rs` holds one row per image (`IMAGE_PROFILES`).
/// A row written by hand is only as complete as the reading behind it, and
/// the failure of an incomplete one — a refusal on the board, in a QEMU
/// scenario nobody can run today — is exactly the silent kind. So this module
/// DERIVES each binary's syscall set from the real sources, on every run, and
/// holds the rows to it:
///
///  * Rust binaries: every `sys::NAME(..)` / `azos_libsys::NAME(..)` call,
///    followed through libsys's own fn bodies transitively to the `SYS_*`
///    constants they issue, plus every raw `asm!` `ecall` the binary writes
///    out (`in("a7") <literal | SYS_* | local const | fn parameter>`).
///  * Assembly binaries: every `li a7, N`.
///
/// Spellings the scanner does not follow — a libsys fn imported by name, a
/// glob import, an `ecall` whose `a7` is set some other way — PANIC instead of
/// being skipped, so a blind spot is a red test rather than a missed call.
///
/// Checked by hand on 2026-09-14 against `uhello` and `ipctest`; the two
/// derived sets are pinned below so a scanner regression cannot pass as a
/// profile that shrank with it.
#[cfg(test)]
mod image_profiles {
    use crate::filter::{FilterVerdict, SYSCALL_FILTER_MAX};
    use crate::seccomp::*;
    use std::collections::{BTreeMap, BTreeSet};

    // The Makefile and the files it includes, in include order (mk/*.mk).
    const MAKEFILE: &str = concat!(
        include_str!("../../../../Makefile"),
        include_str!("../../../../mk/vars.mk"),
        include_str!("../../../../mk/userspace.mk"),
        include_str!("../../../../mk/images.mk"),
        include_str!("../../../../mk/kernel.mk"),
        include_str!("../../../../mk/host.mk"),
        include_str!("../../../../mk/qemu.mk"),
        include_str!("../../../../mk/lints.mk"),
    );
    const SYSCALL_NR: &str = include_str!("../../../../crates/core/abi/src/syscall_nr.rs");
    const INVOKE_ABI: &str = include_str!("../../../../crates/core/abi/src/invoke.rs");
    const LIBSYS: &[&str] = &[
        include_str!("../../../../crates/core/libsys/src/lib.rs"),
        include_str!("../../../../crates/core/libsys/src/pure.rs"),
    ];
    /// The std port layer (`crates/core/stdrt`): every trap and op it issues is
    /// reachable from any std program (the allocator, the console, threads,
    /// the clock, `exit`), so a `RustStd` image's row carries all of them.
    const STDRT: &[&str] = &[
        include_str!("../../../../crates/core/stdrt/src/alloc.rs"),
        include_str!("../../../../crates/core/stdrt/src/console.rs"),
        include_str!("../../../../crates/core/stdrt/src/futex.rs"),
        include_str!("../../../../crates/core/stdrt/src/mem.rs"),
        include_str!("../../../../crates/core/stdrt/src/start.rs"),
        include_str!("../../../../crates/core/stdrt/src/sys.rs"),
        include_str!("../../../../crates/core/stdrt/src/thread.rs"),
        include_str!("../../../../crates/core/stdrt/src/time.rs"),
    ];
    /// The std port's socket layer (`crates/core/stdrt/src/net.rs`): reachable
    /// from a std program that names `std::net`, and from no other (a program
    /// that opens no socket is not granted the network).
    const STDRT_NET: &[&str] = &[include_str!("../../../../crates/core/stdrt/src/net.rs")];
    /// The device-interface clients (`sys::dev::NAME(..)`): methods on the
    /// generated stubs, which this scanner does not follow, so what each
    /// public function issues is written out here and held to the source by
    /// `the_dev_clients_table_names_every_public_function`.
    const DEV_SRC: &str = include_str!("../../../../crates/core/libsys/src/dev.rs");
    const DEV_REACH: &[(&str, &[&str])] = &[
        // The lookup of an endpoint capability by interface and badge.
        ("lookup", &["SYS_CAP_INFO"]),
        // The helpers over a reply issue nothing.
        ("succeeded", &[]),
        ("value", &[]),
        // The draws go over the v2 call (`dev::Ep`).
        ("entropy_read", &["SYS_IPC_CALL_V2"]),
        // So is the brain-link key's.
        ("link_key_read", &["SYS_IPC_CALL_V2"]),
        // And the brain's pinned key, from the same endpoint.
        ("brain_pk_read", &["SYS_IPC_CALL_V2"]),
        // A signature by a kernel-held key: the call, and the one-page memory
        // object the message and the signature travel in (made, mapped, given back).
        ("keys_sign", &["SYS_IPC_CALL_V2", "SYS_MO_CREATE", "SYS_MO_MAP", "SYS_MO_UNMAP"]),
        // A sensor reading and the vDSO bind go over the v2 call too (the
        // reply is a five-word sample, past the register form).
        ("sensor_read", &["SYS_IPC_CALL_V2"]),
        ("sensor_bind_vdso", &["SYS_IPC_CALL_V2"]),
    ];

    /// The POSIX pipe of a process (`sys::pipe::NAME(..)`): the bodies reach the
    /// kernel through the byte pipe's doorbell trait, which this scanner does not
    /// follow, so what each public function issues is written out here and held
    /// to the source by `the_pipe_table_names_every_public_function`.
    const PIPE_SRC: &str = include_str!("../../../../crates/core/libsys/src/pipe.rs");
    const PIPE_REACH: &[(&str, &[&str])] = &[
        // A region made and mapped; unmapped again when the start fails.
        ("create", &["SYS_MO_CREATE", "SYS_MO_MAP", "SYS_MO_UNMAP"]),
        // A region received: its size read, mapped; unmapped when it is no pipe.
        ("adopt", &["MEMOBJ_ACQUIRE", "SYS_MO_MAP", "SYS_MO_UNMAP"]),
        ("adopt_startup", &["MEMOBJ_ACQUIRE", "SYS_MO_MAP", "SYS_MO_UNMAP"]),
        // Data moves in memory; a side sleeps on the ring's event word and the
        // other wakes it, and a lock word records the caller's process id.
        ("read", &["SYS_FUTEX_WAIT", "SYS_FUTEX_WAKE", "SYS_GETPID"]),
        ("write", &["SYS_FUTEX_WAIT", "SYS_FUTEX_WAKE", "SYS_GETPID"]),
        ("set_nonblock", &[]),
        ("end_of", &[]),
        // The last close of an end gives it up to the kernel (which wakes the
        // peer); both closed release the region.
        ("close", &["MEMOBJ_END_DROP", "SYS_MO_UNMAP"]),
        ("region_of", &[]),
        ("forked", &[]),
    ];
    const TOPOLOGY_SRC: &str = include_str!("../../../../crates/core/topology/src/builder.rs");

    /// The images the shell starts as pipeline stages: the `Cap<Launch>` grants
    /// its row holds (`SH_CAPS_BASE` and the package tool's `PKG_LAUNCH` in the
    /// topology builder) that have a native profile. A pipe end arrives in
    /// their startup block as a region, which `startup_init` maps, and a read,
    /// write or close on it sleeps, wakes and gives the end up. Their rows
    /// carry what `PIPE_STAGE_REACH` lists even though no source line names
    /// it; an image the shell cannot start does not get it.
    ///
    /// **Derived, not listed**: a tool added to the shell's launch list is a
    /// stage the moment it is in it, and this finds it.
    fn pipe_stages() -> Vec<String> {
        let mut out = Vec::new();
        for start in ["const SH_CAPS_BASE: &[CapSpec] = &[", "const PKG_LAUNCH: CapSpec = CapSpec {"] {
            let at = TOPOLOGY_SRC.find(start).unwrap_or_else(|| panic!("builder.rs no longer has `{start}`"));
            let rest = &TOPOLOGY_SRC[at..];
            let end = rest.find("\n];").or_else(|| rest.find("\n};")).expect("the end of the grant list");
            let mut span = &rest[..end];
            while let Some(i) = span.find("from_bytes(TASK_") {
                let id_start = i + "from_bytes(".len();
                let id_len = span[id_start..].find(')').expect("a closing parenthesis");
                let id = &span[id_start..id_start + id_len];
                span = &span[id_start + id_len..];
                if !id.ends_with("_IMAGE") {
                    continue;
                }
                let def = format!("pub const {id}: &[u8] = b\"");
                let d = TOPOLOGY_SRC.find(&def).unwrap_or_else(|| panic!("builder.rs does not define {id}")) + def.len();
                let name = &TOPOLOGY_SRC[d..d + TOPOLOGY_SRC[d..].find('"').unwrap()];
                if IMAGE_PROFILES.iter().any(|p| p.image == name) && !out.iter().any(|o| o == name) {
                    out.push(name.to_string());
                }
            }
        }
        out
    }
    const PIPE_STAGE_REACH: &[&str] = &[
        "SYS_MO_MAP", "SYS_MO_UNMAP", "SYS_FUTEX_WAIT", "SYS_FUTEX_WAKE", "SYS_GETPID", "MEMOBJ_ACQUIRE",
        "MEMOBJ_END_DROP",
    ];

    /// The host keys by the name of their constant in `azos_devif::key`.
    const DEV_KEYS: &[(&str, u16)] = &[
        ("ENTROPY", azos_devif::key::ENTROPY),
        ("GPIO", azos_devif::key::GPIO),
        ("I2C", azos_devif::key::I2C),
        ("PWM", azos_devif::key::PWM),
        ("MOTOR", azos_devif::key::MOTOR),
        ("SENSOR", azos_devif::key::SENSOR),
        ("TIME", azos_devif::key::TIME),
        ("BLOCK", azos_devif::key::BLOCK),
        ("CLOCK", azos_devif::key::CLOCK),
        ("LINK_KEY", azos_devif::key::LINK_KEY),
        ("POWER", azos_devif::key::POWER),
        ("FLIGHT", azos_devif::key::FLIGHT),
        ("BEHAVIOR", azos_devif::key::BEHAVIOR),
        ("CONFIG", azos_devif::key::CONFIG),
        ("OTA", azos_devif::key::OTA),
        ("SPI", azos_devif::key::SPI),
        ("CAN", azos_devif::key::CAN),
        ("UART", azos_devif::key::UART),
        ("ADC", azos_devif::key::ADC),
        ("VM", azos_devif::key::VM),
        ("VCPU", azos_devif::key::VCPU),
        ("NET", azos_devif::key::NET),
        ("DISPLAY", azos_devif::key::DISPLAY),
        ("MEMCTL", azos_devif::key::MEMCTL),
        ("KEYS", azos_devif::key::KEYS),
        ("SOUND", azos_devif::key::SOUND),
    ];

    /// The kernel-hosted interfaces the image's sources name (`dev::key::NAME`).
    fn derive_ifaces(image: &str) -> BTreeSet<u16> {
        let (lang, files) = sources_of(image);
        let mut out = BTreeSet::new();
        if lang == Lang::RustStd {
            // `std::alloc::System` is the hardened allocator, keyed and
            // randomized from the entropy interface (stdrt `alloc.rs`).
            out.insert(azos_devif::key::ENTROPY);
        }
        if lang != Lang::Rust && lang != Lang::RustStd {
            return out;
        }
        for &(path, src) in files {
            let code = lex(src, false);
            for (at, _) in code.match_indices("dev::key::") {
                let name: String = code[at + "dev::key::".len()..]
                    .chars()
                    .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                    .collect();
                let key = DEV_KEYS
                    .iter()
                    .find(|k| k.0 == name)
                    .unwrap_or_else(|| panic!("{path}: names `dev::key::{name}`, which DEV_KEYS does not list"))
                    .1;
                out.insert(key);
            }
        }
        out
    }
    const DISPATCH: &str = include_str!("../../../../crates/core/syscall/src/dispatch.rs");
    const HANDLERS: &str = include_str!("../../../../crates/core/syscall/src/handlers.rs");

    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    enum Lang {
        Asm,
        Rust,
        /// A program on `std` (the SDK, `*-unknown-azos`): its own calls are
        /// followed like a `Rust` image's, and `std` adds the calls of the
        /// port layer a program can reach whatever it says (`STDRT`), and the
        /// entropy interface its allocator draws from.
        RustStd,
        /// A static Linux binary from C. It issues LINUX numbers
        /// through `lx_scN(NR_<name>, ..)`; its profile is the native numbers
        /// those calls reach through the personality
        /// (`azos_linux_abi::TABLE`).
        LinuxC,
    }

    macro_rules! src {
        ($p:literal) => {
            ($p, include_str!(concat!("../../../../", $p)))
        };
    }

    /// Every image and the sources its `Makefile` rule compiles into it.
    const SOURCES: &[(&str, Lang, &[(&str, &str)])] = &[
        ("HELLO.ELF", Lang::Asm, &[src!("userspace/tests/hello/hello.S")]),
        // Wave 15: the kernel tracer's reader.
        ("TRACECTL.ELF", Lang::Rust, &[
            src!("userspace/services/tracectl/src/main.rs"),
            src!("userspace/services/tracectl/src/profile.rs"),
            // `profile.rs` pulls the profiler core in by #[path].
            src!("crates/core/trace/src/prof.rs"),
        ]),
        // The component manager: its loop and its supervision tree (the
        // pure half, `tree.rs`) and the table of IDL failure contracts.
        ("COMPMGR.ELF", Lang::Rust, &[
            src!("userspace/services/compmgr/src/main.rs"),
            src!("userspace/services/compmgr/src/tree.rs"),
            src!("userspace/services/compmgr/src/contracts.rs"),
            src!("userspace/services/compmgr/src/request.rs"),
        ]),
        // The Decisions object's server (the pure decoder is `bin.rs`) and
        // its client tool (the command line and output are `cli.rs`).
        ("DECISD.ELF", Lang::Rust, &[
            src!("userspace/services/decisd/src/main.rs"),
            src!("userspace/services/decisd/src/bin.rs"),
        ]),
        // The Input object's server: the pure focus decisions and the loop.
        ("INPUTD.ELF", Lang::Rust, &[
            src!("userspace/services/inputd/src/main.rs"),
            src!("userspace/services/inputd/src/focus.rs"),
        ]),
        // The compositor: the Compositor object's server (the windows, the
        // trusted path's timing, the surface's cut and the panels are the pure
        // modules) and the loop around the Display interface.
        ("COMPSRV.ELF", Lang::Rust, &[
            src!("userspace/services/compositor/src/main.rs"),
            src!("userspace/services/compositor/src/windows.rs"),
            src!("userspace/services/compositor/src/trust.rs"),
            src!("userspace/services/compositor/src/bands.rs"),
            src!("userspace/services/compositor/src/panel.rs"),
            // `main.rs` includes the framebuffer console's font by #[path].
            src!("crates/drivers/fb/src/font.rs"),
        ]),
        // The kernel log's sink; the ring's wire is shared with the kernel.
        ("LOGD.ELF", Lang::Rust, &[
            src!("userspace/services/logd/src/main.rs"),
            src!("userspace/services/logd/src/store.rs"),
            src!("crates/drivers/sys/src/klog/wire.rs"),
        ]),
        ("WHY.ELF", Lang::RustStd, &[
            src!("userspace/services/why/src/main.rs"),
            src!("userspace/services/why/src/cli.rs"),
            src!("userspace/services/why/src/crash.rs"),
            src!("userspace/services/why/src/woke.rs"),
            src!("crates/core/recovery/src/crashdump.rs"),
        ]),
        // The Packages object's installer (the pure half is the library's)
        // and its client tool. The installer is a std program (its package
        // source dials a pinned HTTPS server with `std::net`, userspace/lib/tls).
        ("PKGD.ELF", Lang::RustStd, &[
            src!("userspace/services/pkgd/src/main.rs"),
            src!("userspace/services/pkgd/src/stage.rs"),
            src!("userspace/services/pkgd/src/snap.rs"),
            src!("userspace/services/pkgd/src/tftp.rs"),
            src!("userspace/lib/tls/src/remote.rs"),
        ]),
        ("PKG.ELF", Lang::Rust, &[src!("userspace/services/pkg/src/main.rs")]),
        ("SYSTEST.ELF", Lang::Asm, &[src!("userspace/tests/syscall_test/test.S")]),
        ("GPIODRV.ELF", Lang::Rust, &[src!("userspace/drivers/gpio_drv/src/main.rs")]),
        ("MLSRV.ELF", Lang::Rust, &[
            src!("userspace/services/infsrv/src/main.rs"),
            // Its modules that call libsys; the library half (lib.rs and what it
            // declares) makes no system call.
            src!("userspace/services/infsrv/src/bundles.rs"),
            src!("userspace/services/infsrv/src/out.rs"),
            src!("userspace/services/infsrv/src/selftest.rs"),
            src!("userspace/services/infsrv/src/sysplat.rs"),
            src!("userspace/services/infsrv/src/volume.rs"),
        ]),
        ("UHELLO.ELF", Lang::Rust, &[src!("userspace/tests/uhello/src/main.rs")]),
        ("EPSRV.ELF", Lang::Rust, &[src!("userspace/tests/epsrv/src/main.rs")]),
        ("ABICHILD.ELF", Lang::Rust, &[
            src!("userspace/tests/abichild/src/main.rs"),
            src!("userspace/tests/abichild/src/shared.rs"),
        ]),
        ("VSSRV.ELF", Lang::Rust, &[
            src!("userspace/bench/vssrv/src/main.rs"),
            // Both pulled in with `#[path]` from `vsbench`: the wire protocol
            // and the loop, so the two halves cannot drift.
            src!("userspace/bench/vsbench/src/ipc_proto.rs"),
            src!("userspace/bench/vsbench/src/serve.rs"),
        ]),
        ("REFLEX.ELF", Lang::Rust, &[src!("userspace/services/reflex/src/main.rs")]),
        ("BRAINCLI.ELF", Lang::Rust, &[
            src!("userspace/services/brain_client/src/main.rs"),
            // The forward-secret link client session.
            src!("userspace/services/brain_client/src/link.rs"),
        ]),
        ("CAPTEST.ELF", Lang::Rust, &[
            src!("userspace/tests/captest/src/main.rs"),
            // The ABI cases shared with the micro kernel's captest; they
            // issue their calls through `main.rs`'s `RingThree`.
            src!("userspace/tests/captest/src/abi_cases.rs"),
        ]),
        ("LATBENCH.ELF", Lang::Rust, &[src!("userspace/bench/latbench/src/main.rs")]),
        ("ABITEST.ELF", Lang::Rust, &[
            src!("userspace/tests/abitest/src/main.rs"),
            // Pulled in with `#[path]` from `abichild`: the process-tree
            // helpers and the child spawner.
            src!("userspace/tests/abichild/src/shared.rs"),
        ]),
        ("IPCTEST.ELF", Lang::Rust, &[src!("userspace/tests/ipctest/src/main.rs")]),
        // The image carries the `--features azos` build (`Makefile`,
        // `$(VSBENCH_ELF)`), so `abi_linux.rs` is not part of it.
        ("VSBENCH.ELF", Lang::Rust, &[
            src!("userspace/bench/vsbench/src/main.rs"),
            src!("userspace/bench/vsbench/src/abi_azos.rs"),
            src!("userspace/bench/vsbench/src/bench_core.rs"),
            // The wire protocol, pulled in with `#[path]`. The server LOOP is
            // NOT part of this image — see `ipc_proto.rs`.
            src!("userspace/bench/vsbench/src/ipc_proto.rs"),
        ]),
        ("BUZZDRV.ELF", Lang::Rust, &[
            src!("userspace/drivers/buzz_drv/src/main.rs"),
            // The chip logic, a crate of its own since wave 12 DRVPLACE
            // (shared with the kernel host): no syscalls.
            src!("crates/drivers/buzzer/src/lib.rs"),
        ]),
        ("INADRV.ELF", Lang::Rust, &[
            src!("userspace/drivers/ina_drv/src/main.rs"),
            src!("userspace/drivers/ina_drv/src/request.rs"),
            // The chip logic, a crate of its own since wave 11 DRVPLACE
            // (shared with the kernel host): no syscalls.
            src!("crates/drivers/ina219/src/lib.rs"),
            src!("crates/drivers/ina219/src/chip.rs"),
        ]),
        // The user shell. Its modules other than
        // `main.rs` are pure (no syscalls), listed so a call added to one of
        // them is still derived.
        ("SH.ELF", Lang::Rust, &[
            src!("userspace/services/sh/src/main.rs"),
            src!("userspace/services/sh/src/parse.rs"),
            src!("userspace/services/sh/src/path.rs"),
            src!("userspace/services/sh/src/req.rs"),
            src!("userspace/services/sh/src/ident.rs"),
        ]),
        // The Terminal object's server: the loop, and the pure modules (the
        // editor, the discipline, the interface's implementation).
        ("TERMD.ELF", Lang::Rust, &[
            src!("userspace/services/termd/src/main.rs"),
            src!("userspace/services/termd/src/edit.rs"),
            src!("userspace/services/termd/src/disc.rs"),
            src!("userspace/services/termd/src/service.rs"),
            src!("userspace/services/termd/src/keys.rs"),
            src!("userspace/services/termd/src/mouse.rs"),
            src!("userspace/services/termd/src/input.rs"),
            src!("userspace/services/termd/src/secure.rs"),
        ]),
        // The login service: the loop that binds it to the system, and its
        // logic (no syscalls).
        ("LOGIND.ELF", Lang::Rust, &[
            src!("userspace/services/logind/src/main.rs"),
            src!("userspace/services/logind/src/daemon.rs"),
        ]),
        // The Names object's server: the loop and the interface's
        // implementation.
        ("NAMESD.ELF", Lang::Rust, &[
            src!("userspace/services/namesd/src/main.rs"),
            src!("userspace/services/namesd/src/service.rs"),
        ]),
        // The RPC server: the loop and the host it runs the engine on (the
        // engine, `userspace/lib/rpc`, issues no call of its own).
        ("RPCSRV.ELF", Lang::Rust, &[src!("userspace/services/rpcsrv/src/main.rs")]),
        // The relay of the QUIC link: a std program that names `std::net` (the
        // stack's UDP sockets) and links the QUIC state machine and its TLS, none
        // of which issues a call of its own.
        ("RPCQUIC.ELF", Lang::RustStd, &[
            src!("userspace/services/rpcquic/src/main.rs"),
            src!("userspace/lib/quic/src/relay.rs"),
            src!("userspace/lib/quic/src/pump.rs"),
            src!("userspace/lib/quic/src/crypto.rs"),
            src!("userspace/lib/quic/src/suite.rs"),
            src!("userspace/lib/quic/src/identity.rs"),
        ]),
        // The Zenoh gateway: its loop, and the allocator it links.
        ("ZENOHD.ELF", Lang::Rust, &[
            src!("userspace/services/zenohd/src/main.rs"),
            src!("userspace/services/zenohd/src/gw.rs"),
            src!("userspace/services/zenohd/src/route.rs"),
            src!("userspace/lib/ualloc/src/native.rs"),
        ]),
        // The audio server: its loop, and the mixer and the decisions beside
        // it (which issue no call of their own).
        ("AUDIOD.ELF", Lang::Rust, &[
            src!("userspace/services/audiod/src/main.rs"),
            src!("userspace/services/audiod/src/mixer.rs"),
            src!("userspace/services/audiod/src/server.rs"),
        ]),
        // The PTP daemon: its loop, and the engine, codec and helpers beside
        // it (which issue no call of their own).
        ("PTPD.ELF", Lang::Rust, &[
            src!("userspace/services/ptpd/src/main.rs"),
            src!("userspace/services/ptpd/src/bmc.rs"),
            src!("userspace/services/ptpd/src/link.rs"),
            src!("userspace/services/ptpd/src/port.rs"),
            src!("userspace/services/ptpd/src/wire.rs"),
        ]),
        // The MCP bridge: its loop, the engine and the rules it pulls in, and the
        // allocator it links.
        ("MCPD.ELF", Lang::Rust, &[
            src!("userspace/services/mcpd/src/main.rs"),
            src!("userspace/services/mcpd/src/bridge.rs"),
            src!("userspace/services/mcpd/src/catalog.rs"),
            src!("userspace/services/mcpd/src/receipt.rs"),
            src!("userspace/services/mcpd/src/warrant.rs"),
            src!("userspace/lib/ualloc/src/native.rs"),
        ]),
        // The SSH server: its loop and the pure modules beside it (the protocol
        // engine, the session), the line discipline and the shell's path and
        // request modules it includes, and the allocator it links.
        ("SSHD.ELF", Lang::Rust, &[
            src!("userspace/services/sshd/src/main.rs"),
            src!("userspace/services/sshd/src/auth.rs"),
            src!("userspace/services/sshd/src/kex.rs"),
            src!("userspace/services/sshd/src/packet.rs"),
            src!("userspace/services/sshd/src/policy.rs"),
            src!("userspace/services/sshd/src/server.rs"),
            src!("userspace/services/sshd/src/session.rs"),
            src!("userspace/services/sshd/src/wire.rs"),
            src!("userspace/services/termd/src/disc.rs"),
            src!("userspace/services/termd/src/edit.rs"),
            src!("userspace/services/sh/src/path.rs"),
            src!("userspace/services/sh/src/req.rs"),
            src!("userspace/lib/ualloc/src/native.rs"),
        ]),
        ("TOOLBOX.ELF", Lang::Rust, &[src!("userspace/services/toolbox/src/main.rs"), src!("userspace/services/toolbox/src/beep.rs"), src!("userspace/services/toolbox/src/host.rs"), src!("userspace/services/toolbox/src/log_view.rs"), src!("userspace/services/toolbox/src/metrics_view.rs"), src!("userspace/services/toolbox/src/ntp.rs"), src!("userspace/services/toolbox/src/ps_view.rs"), src!("userspace/services/toolbox/src/sound.rs"), src!("userspace/services/toolbox/src/vm.rs"), src!("crates/drivers/sys/src/klog/wire.rs"), src!("userspace/services/toolbox/src/input.rs"), src!("userspace/services/toolbox/src/window.rs")]),
        ("POWER.ELF", Lang::Rust, &[
            src!("userspace/services/power/src/main.rs"),
            src!("userspace/services/power/src/policy.rs"),
            src!("userspace/services/power/src/devices.rs"),
            src!("userspace/services/power/src/battery.rs"),
            src!("userspace/services/power/src/degrade.rs"),
        ]),
        // Wave 12: one binary each of the family-tools crate, with the shared
        // module every one of them pulls in by `#[path]`.
        ("FLIGHT.ELF", Lang::Rust, &[
            src!("userspace/services/famtools/src/bin/flight.rs"),
            src!("userspace/services/famtools/src/common.rs"),
        ]),
        ("BEHAVIOR.ELF", Lang::Rust, &[
            src!("userspace/services/famtools/src/bin/behavior.rs"),
            src!("userspace/services/famtools/src/common.rs"),
        ]),
        ("CONFIG.ELF", Lang::Rust, &[
            src!("userspace/services/famtools/src/bin/config.rs"),
            src!("userspace/services/famtools/src/common.rs"),
        ]),
        ("OTA.ELF", Lang::Rust, &[
            src!("userspace/services/famtools/src/bin/ota.rs"),
            src!("userspace/services/famtools/src/common.rs"),
        ]),
        // Hypervisor H1: the virtual-machine monitor.
        ("VMMD.ELF", Lang::Rust, &[
            src!("userspace/services/vmmd/src/main.rs"),
            src!("userspace/services/vmmd/src/blk.rs"),
            src!("userspace/services/vmmd/src/console.rs"),
            src!("userspace/services/vmmd/src/ctl.rs"),
            src!("userspace/services/vmmd/src/dtb.rs"),
            src!("userspace/services/vmmd/src/guest.rs"),
            src!("userspace/services/vmmd/src/life.rs"),
            src!("userspace/services/vmmd/src/loader.rs"),
            src!("userspace/services/vmmd/src/mmio.rs"),
            src!("userspace/services/vmmd/src/model.rs"),
            src!("userspace/services/vmmd/src/net.rs"),
            src!("userspace/services/vmmd/src/pvh.rs"),
            src!("userspace/services/vmmd/src/ringlink.rs"),
            src!("userspace/services/vmmd/src/store.rs"),
            src!("userspace/services/vmmd/src/trap.rs"),
            src!("userspace/services/vmmd/src/virtq.rs"),
            // The trap rings' wire form, the kernel's file that vmmd includes.
            src!("crates/core/hv/src/trapwire.rs"),
        ]),
        // The Linux driver server skeleton.
        ("LXSRV.ELF", Lang::Rust, &[
            src!("userspace/services/lxsrv/src/main.rs"),
            // The allocator it links: the calls it issues are the image's.
            src!("userspace/lib/ualloc/src/native.rs"),
        ]),
        // The Linux personality's test binary.
        ("LXHELLO.ELF", Lang::LinuxC, &[src!("userspace/tests/lxhello/lxhello.c")]),
    ];

    /// Modules a binary declares that its image does not compile.
    const MODULES_NOT_IN_THE_IMAGE: &[(&str, &str, &str)] = &[
        ("VSBENCH.ELF", "abi_linux", "`#[cfg(feature = \"linux\")]`; the image is the azos build"),
    ];

    /// Syscalls a binary's source names that the binary never issues.
    ///
    /// Static derivation cannot see that a wrapper refuses its argument before
    /// the `ecall`. Each row is left OUT of the profile, with the reason. None
    /// today: the one that was (a `mkdir` of an unterminated path) is an op of
    /// the domain now, and its class is used by the binary's real calls too.
    const NEVER_ISSUED: &[(&str, &str, &str)] = &[
    ];

    /// Calls a binary issues ON PURPOSE to see the FILTER refuse them. Named in
    /// its source, left out of its profile, and asserted refused.
    const REFUSAL_PROBES: &[(&str, &str, &str)] = &[
        ("UHELLO.ELF", "SYS_IPC_FAST_CALL_EP",
         "the runtime proof that a call outside a profile is refused, through the native \
          entries' IPC branch (Chain E cut 7): killed (exit 159) filtered, a negative answer \
          and `FAILED:` unfiltered; `userspace: minimal Rust ELF` and abitest assert it"),
    ];

    /// Numbers a binary issues raw, on purpose, to watch the DISPATCHER refuse
    /// them; no `SYS_*` constant names them. Left out of the row, whose audit
    /// mode lets them through to the arm under test and records them
    /// (`SAFETY_SECCOMP_AUDIT`). Both probes accept any negative return, and the
    /// filter's own refusal is also `-1`, so a row that refused them would pass
    /// the probe while testing something else.
    const AUDITED_PROBES: &[(&str, u16, &str)] = &[
        ("CAPTEST.ELF", 116, "an unassigned number, issued as `raw_syscall3(116, ..)`"),
        ("ABITEST.ELF", 999, "an unclaimed number, issued to watch the default arm refuse it"),
    ];

    /// Live calls an audit-mode image issues raw, outside its row, to watch
    /// the real arm refuse wrong arguments (the user
    /// shell's calls, which only SH.ELF's row may list —
    /// `only_the_shell_profile_lists_the_shell_calls`). Unlike
    /// `AUDITED_PROBES` these numbers ARE assigned: the probe reaches the
    /// call's own arm, which is the point.
    const AUDITED_LIVE_CALLS: &[(&str, u16, &str)] = &[
        ("ABITEST.ELF", 5, "SYS_SPAWN_EX with a bad version and no launch grant"),
        ("ABITEST.ELF", 9, "SYS_ALERT on self and on a non-descendant"),
    ];

    /// Ops an audit-mode image invokes on purpose outside its row, to watch
    /// the real op refuse wrong arguments (the op counterpart of
    /// `AUDITED_LIVE_CALLS`): the profile's audit mode lets them through and
    /// records them.
    const AUDITED_OPS: &[(&str, u16, &str)] = &[
        ("ABITEST.ELF", azos_abi::invoke::LOG_CONSOLE_WAIT, "the console wait with w3 != 0"),
    ];

    /// Ops an image reaches only as io_ring entries, which the scanner (it
    /// follows `sys::NAME(..)` calls) does not see: `(image, op, the source
    /// text that submits the entry)`. The kernel runs the entry only while
    /// the row lists the op's class, and the source text must still be there.
    const RING_ENTRY_OPS: &[(&str, u16, &str)] = &[
        ("BRAINCLI.ELF", azos_abi::invoke::MEMOBJ_ACQUIRE, "push_register("),
    ];

    // ── The scanner ─────────────────────────────────────────────────────

    /// Comments removed. String literal contents blanked unless `keep_strings`
    /// (an `asm!` template is a string, and so is `in("a7")`).
    fn lex(src: &str, keep_strings: bool) -> String {
        let b = src.as_bytes();
        let mut out: Vec<u8> = Vec::with_capacity(b.len());
        let mut i = 0;
        while i < b.len() {
            let c = b[i];
            let next = b.get(i + 1).copied();
            if c == b'/' && next == Some(b'/') {
                while i < b.len() && b[i] != b'\n' {
                    i += 1;
                }
            } else if c == b'/' && next == Some(b'*') {
                let mut depth = 0;
                while i < b.len() {
                    if b[i] == b'/' && b.get(i + 1) == Some(&b'*') {
                        depth += 1;
                        i += 2;
                    } else if b[i] == b'*' && b.get(i + 1) == Some(&b'/') {
                        depth -= 1;
                        i += 2;
                        if depth == 0 {
                            break;
                        }
                    } else {
                        if b[i] == b'\n' {
                            out.push(b'\n');
                        }
                        i += 1;
                    }
                }
            } else if c == b'"' {
                out.push(b'"');
                i += 1;
                while i < b.len() && b[i] != b'"' {
                    let n = if b[i] == b'\\' { 2 } else { 1 };
                    if keep_strings {
                        out.extend_from_slice(&b[i..(i + n).min(b.len())]);
                    }
                    i += n;
                }
                out.push(b'"');
                i += 1;
            } else if c == b'\'' {
                // A char literal ('x', '\n', '\u{..}') or a lifetime ('a).
                if next == Some(b'\\') {
                    let mut j = i + 2;
                    while j < b.len() && b[j] != b'\'' {
                        j += 1;
                    }
                    out.extend_from_slice(b"' '");
                    i = j + 1;
                } else if b.get(i + 2) == Some(&b'\'') {
                    out.extend_from_slice(b"' '");
                    i += 3;
                } else {
                    out.push(b'\'');
                    i += 1;
                }
            } else {
                out.push(c);
                i += 1;
            }
        }
        String::from_utf8_lossy(&out).into_owned()
    }

    fn is_ident(c: u8) -> bool {
        c.is_ascii_alphanumeric() || c == b'_'
    }

    /// `(offset, identifier)` for every identifier in `code`.
    fn idents(code: &str) -> Vec<(usize, &str)> {
        let b = code.as_bytes();
        let mut v = Vec::new();
        let mut i = 0;
        while i < b.len() {
            if (b[i].is_ascii_alphabetic() || b[i] == b'_') && (i == 0 || !is_ident(b[i - 1])) {
                let s = i;
                while i < b.len() && is_ident(b[i]) {
                    i += 1;
                }
                v.push((s, &code[s..i]));
            } else {
                i += 1;
            }
        }
        v
    }

    fn next_non_ws(code: &str, mut at: usize) -> Option<u8> {
        let b = code.as_bytes();
        while at < b.len() && b[at].is_ascii_whitespace() {
            at += 1;
        }
        b.get(at).copied()
    }

    fn prev_non_ws(code: &str, at: usize) -> Option<u8> {
        code.as_bytes()[..at].iter().rev().find(|c| !c.is_ascii_whitespace()).copied()
    }

    /// Offset one past the bracket that closes the one at `open`.
    fn close_of(code: &str, open: usize, l: u8, r: u8) -> usize {
        let b = code.as_bytes();
        let mut depth = 0;
        for (k, &c) in b.iter().enumerate().skip(open) {
            if c == l {
                depth += 1;
            } else if c == r {
                depth -= 1;
                if depth == 0 {
                    return k + 1;
                }
            }
        }
        panic!("unbalanced `{}` at byte {open}", l as char);
    }

    /// Every `SYS_*` name in `syscall_nr.rs`, with its number.
    fn numbers() -> BTreeMap<String, u16> {
        let mut m = BTreeMap::new();
        for line in SYSCALL_NR.lines() {
            let Some(rest) = line.trim().strip_prefix("pub const SYS_") else { continue };
            let Some((name, val)) = rest.split_once(": u64 =") else { continue };
            if let Ok(n) = val.trim().trim_end_matches(';').trim().parse::<u64>() {
                m.insert(format!("SYS_{name}"), n as u16);
            }
        }
        assert!(m.len() > 20, "read only {} numbers out of syscall_nr.rs", m.len());
        m
    }

    /// Every op in `invoke.rs` (`pub const NAME: u16 = op(CapKind::K, CLASS_C, N);`),
    /// with its value as `azos_abi::invoke::op` computes it. The kind is the
    /// name's prefix too: a mismatch is a typo in the ABI file.
    fn op_names() -> BTreeMap<String, u16> {
        use azos_abi::invoke::{CLASS_ADMIN, CLASS_CTL, CLASS_FS_MUTATE, CLASS_DRIVER, CLASS_FS_OPEN, CLASS_MODULE, CLASS_NET, CLASS_READ, CLASS_WAIT, CLASS_WRITE};
        use azos_abi::cap::CapKind;
        let mut m = BTreeMap::new();
        for line in INVOKE_ABI.lines() {
            let Some(rest) = line.strip_prefix("pub const ") else { continue };
            let Some((name, tail)) = rest.split_once(": u16 = op(CapKind::") else { continue };
            let tail = tail.trim_end_matches(';').trim_end_matches(')');
            let mut it = tail.split(',').map(str::trim);
            let kind = match it.next().unwrap() {
                "Endpoint" => CapKind::Endpoint,
                "MemObj" => CapKind::MemObj,
                "Queue" => CapKind::Queue,
                "Port" => CapKind::Port,
                "Domain" => CapKind::Domain,
                "Node" => CapKind::Node,
                "Device" => CapKind::Device,
                "Log" => CapKind::Log,
                other => panic!("invoke.rs: `{name}` names the kind `{other}`"),
            };
            let class = match it.next().unwrap() {
                "CLASS_READ" => CLASS_READ,
                "CLASS_WRITE" => CLASS_WRITE,
                "CLASS_WAIT" => CLASS_WAIT,
                "CLASS_CTL" => CLASS_CTL,
                "CLASS_ADMIN" => CLASS_ADMIN,
                "CLASS_FS_OPEN" => CLASS_FS_OPEN,
                "CLASS_FS_MUTATE" => CLASS_FS_MUTATE,
                "CLASS_MODULE" => CLASS_MODULE,
                "CLASS_NET" => CLASS_NET,
                "CLASS_DRIVER" => CLASS_DRIVER,
                other => panic!("invoke.rs: `{name}` names the class `{other}`"),
            };
            let n: u8 = it.next().unwrap().parse().unwrap_or_else(|_| panic!("invoke.rs: `{name}` index"));
            let upper = format!("{kind:?}").to_uppercase();
            assert!(name.starts_with(&format!("{upper}_")), "invoke.rs: `{name}` is not prefixed by its kind {upper}");
            assert!(m.insert(name.to_string(), azos_abi::invoke::op(kind, class, n)).is_none(), "{name} twice");
        }
        assert!(!m.is_empty(), "read no op out of invoke.rs");
        m
    }

    /// libsys fn name -> (`SYS_*` and op names in its body, identifiers it calls).
    type Fns = BTreeMap<String, (BTreeSet<String>, BTreeSet<String>)>;

    fn libsys_fns() -> Fns {
        let mut fns = Fns::new();
        let ops = op_names();
        for src in LIBSYS {
            let code = lex(src, false);
            let b = code.as_bytes();
            let ids = idents(&code);
            for w in ids.windows(2) {
                let ((_, kw), (name_at, name)) = (w[0], w[1]);
                if kw != "fn" {
                    continue;
                }
                let mut k = name_at + name.len();
                while k < b.len() && b[k].is_ascii_whitespace() {
                    k += 1;
                }
                if b.get(k) == Some(&b'<') {
                    k = close_of(&code, k, b'<', b'>');
                    while k < b.len() && b[k].is_ascii_whitespace() {
                        k += 1;
                    }
                }
                if b.get(k) != Some(&b'(') {
                    continue; // `fn(..)` as a type, not a definition
                }
                // The body opens at the first `{` outside brackets; a `;` there
                // first means a declaration. `[u8; N]` in a signature is why
                // the brackets are counted.
                let mut k = close_of(&code, k, b'(', b')');
                let mut depth = 0i32;
                let mut open = None;
                while k < b.len() {
                    match b[k] {
                        b'(' | b'[' => depth += 1,
                        b')' | b']' => depth -= 1,
                        b'{' if depth == 0 => {
                            open = Some(k);
                            break;
                        }
                        b';' if depth == 0 => break,
                        _ => {}
                    }
                    k += 1;
                }
                let Some(open) = open else { continue };
                let body = &code[open..close_of(&code, open, b'{', b'}')];
                let mut syms = BTreeSet::new();
                let mut calls = BTreeSet::new();
                for (at, id) in idents(body) {
                    if id.starts_with("SYS_") || ops.contains_key(id) {
                        syms.insert(id.to_string());
                    } else if next_non_ws(body, at + id.len()) == Some(b'(')
                        && prev_non_ws(body, at) != Some(b'.')
                    {
                        calls.insert(id.to_string());
                    }
                }
                assert!(
                    fns.insert(name.to_string(), (syms, calls)).is_none(),
                    "libsys defines `{name}` more than once; this scanner would merge \
                     the bodies. Teach it which one the image compiles.",
                );
            }
        }
        assert!(fns.len() > 150, "found only {} libsys fns", fns.len());
        fns
    }

    fn closure(fns: &Fns, root: &str) -> BTreeSet<String> {
        let mut out = BTreeSet::new();
        let mut seen = BTreeSet::new();
        let mut stack = vec![root.to_string()];
        while let Some(n) = stack.pop() {
            if !seen.insert(n.clone()) {
                continue;
            }
            let Some((syms, calls)) = fns.get(&n) else { continue };
            out.extend(syms.iter().cloned());
            stack.extend(calls.iter().filter(|c| fns.contains_key(*c)).cloned());
        }
        out
    }

    /// The number(s) an `in("a7") <tok>` at `at` issues.
    fn resolve_a7(code: &str, at: usize, tok: &str, nrs: &BTreeMap<String, u16>) -> Vec<u16> {
        let bare = tok.strip_suffix("u64").unwrap_or(tok).trim_end_matches('_');
        if let Ok(n) = bare.parse::<u64>() {
            return vec![n as u16];
        }
        if let Some(&n) = nrs.get(bare) {
            return vec![n];
        }
        // `const TOK: u64 = N;` in the same file.
        let decl = format!("const {bare}");
        for (i, _) in code.match_indices(&decl) {
            let tail = &code[i + decl.len()..];
            if tail.as_bytes().first().is_some_and(|&c| is_ident(c)) {
                continue;
            }
            if let Some(eq) = tail.find('=') {
                let digits: String =
                    tail[eq + 1..].trim_start().chars().take_while(|c| c.is_ascii_digit()).collect();
                if let Ok(n) = digits.parse::<u64>() {
                    return vec![n as u16];
                }
            }
        }
        // The first parameter of the enclosing fn: every call site's literal.
        let fn_at = code[..at].rfind("fn ").expect("an `in(\"a7\")` outside any fn");
        let ids = idents(&code[fn_at..]);
        let (fname, param) = (ids[1].1, ids[2].1);
        assert_eq!(param, bare, "a7 = `{tok}` is neither a literal, a SYS_* name, a local const \
                                 nor the first parameter of `{fname}`");
        let mut found = Vec::new();
        for (i, _) in code.match_indices(&format!("{fname}(")) {
            if i > 0 && is_ident(code.as_bytes()[i - 1]) || code[..i].trim_end().ends_with("fn") {
                continue;
            }
            let arg: String = code[i + fname.len() + 1..]
                .trim_start()
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect();
            let n = arg.strip_suffix("u64").unwrap_or(&arg).trim_end_matches('_').parse::<u64>();
            found.push(n.unwrap_or_else(|_| panic!("`{fname}({arg}, ..)`: the scanner resolves \
                                                    only integer literals here")) as u16);
        }
        assert!(!found.is_empty(), "`{fname}` issues a raw ecall and is never called");
        found
    }

    /// The native numbers a Linux C image's calls reach. Every
    /// `lx_scN(NR_<name>` call names a Linux call; its `#define NR_<name> N`
    /// must be the personality's number for that name, and the call must be
    /// one the personality answers. A call through a bare number (no `NR_`
    /// name) is a probe the personality refuses on its own (`-ENOSYS`),
    /// which reaches nothing.
    fn derive_linux_c(path: &str, src: &str, out: &mut BTreeSet<u16>) {
        // Comments out first: the file's own prose names the call shape.
        let mut code = String::new();
        for line in src.lines() {
            let l = line.split("//").next().unwrap_or("");
            code.push_str(l);
            code.push('\n');
        }
        for line in code.lines() {
            let Some(rest) = line.trim().strip_prefix("#define NR_") else { continue };
            let mut it = rest.split_whitespace();
            let (Some(name), Some(n)) = (it.next(), it.next()) else { continue };
            let n: u64 = n.parse().unwrap_or_else(|_| panic!("{path}: NR_{name} is not a number"));
            assert_eq!(azos_linux_abi::number_of(name), Some(n),
                "{path}: NR_{name} = {n} is not the personality's number for `{name}`");
        }
        let mut calls = 0;
        for (i, _) in code.match_indices("lx_sc") {
            let rest = code[i + 5..].trim_start_matches(|c: char| c.is_ascii_digit());
            let Some(rest) = rest.strip_prefix('(') else { continue };
            let Some(name) = rest.trim_start().strip_prefix("NR_") else { continue };
            let name: String = name.chars().take_while(|c| c.is_ascii_alphanumeric() || *c == '_').collect();
            let n = azos_linux_abi::number_of(&name)
                .unwrap_or_else(|| panic!("{path}: calls Linux `{name}`, which the personality does not answer"));
            out.extend(azos_linux_abi::native_reach(n).unwrap().iter().copied());
            calls += 1;
        }
        // The ring-3 runtime that hosts the personality makes a few native
        // calls of its own, whatever the program asks.
        out.extend(azos_linux_rt::RUNTIME_NATIVE.iter().copied());
        assert!(calls > 0, "{path}: no `lx_scN(NR_<name>, ..)` call found");
    }

    fn sources_of(image: &str) -> (Lang, &'static [(&'static str, &'static str)]) {
        SOURCES
            .iter()
            .find(|s| s.0 == image)
            .map(|s| (s.1, s.2))
            .unwrap_or_else(|| panic!("no SOURCES entry for {image}"))
    }

    /// Every syscall number the image's source issues, statically.
    fn derive(image: &str) -> BTreeSet<u16> {
        derive_both(image).0
    }

    /// The (kind, class) pairs `image`'s source needs of `SYS_INVOKE`'s ops: the
    /// op names its libsys wrappers use, and the raw assembly that names one.
    fn derive_ops(image: &str) -> BTreeSet<(u8, u8)> {
        let (_, files) = sources_of(image);
        let mut ops = derive_both(image).1;
        for &(img, op, needle) in RING_ENTRY_OPS.iter().filter(|r| r.0 == image) {
            assert!(
                files.iter().any(|&(_, src)| lex(src, false).contains(needle)),
                "{img}: RING_ENTRY_OPS lists op {op:#x} but no source submits `{needle}`: stale row",
            );
            ops.insert(op);
        }
        ops.into_iter().map(|o| (azos_abi::invoke::op_kind(o), azos_abi::invoke::op_class(o))).collect()
    }

    /// The syscall numbers and the ops (as `invoke::op` values) `image` issues.
    fn derive_both(image: &str) -> (BTreeSet<u16>, BTreeSet<u16>) {
        let (lang, files) = sources_of(image);
        derive_files(image, lang, files)
    }

    /// [`derive_both`] for source files that are not an image of their own
    /// (`image` only names the pipe-stage rule).
    fn derive_files(image: &str, lang: Lang, files: &[(&str, &str)]) -> (BTreeSet<u16>, BTreeSet<u16>) {
        let nrs = numbers();
        let opn = op_names();
        let mut out = BTreeSet::new();
        let mut ops_out = BTreeSet::new();
        if lang == Lang::LinuxC {
            for &(path, src) in files {
                derive_linux_c(path, src, &mut out);
            }
            // The ring-3 runtime that hosts the personality issues these
            // ops for the program's Linux calls.
            ops_out.extend(azos_linux_rt::RUNTIME_OPS.iter().copied());
            return (out, ops_out);
        }
        if lang == Lang::Asm {
            for &(path, src) in files {
                for line in src.lines() {
                    let code = line.split('#').next().unwrap().trim();
                    if let Some(rest) = code.strip_prefix("li") {
                        if let Some(n) = rest.trim().strip_prefix("a7,") {
                            let n = n.trim();
                            out.insert(n.parse::<u16>().ok().or_else(|| numbers().get(n).copied()).unwrap_or_else(|| {
                                panic!("{path}: `{code}`: neither a decimal syscall number nor a SYS_* name")
                            }));
                        }
                    }
                }
                assert!(!out.is_empty(), "{path}: no `li a7, N` found");
                // The console write is assembled in as a defsym
                // (`tools/syscall_defs.py`): `INVOKE_CONSOLE_WRITE`.
                if src.contains("INVOKE_CONSOLE_WRITE") {
                    ops_out.insert(opn["LOG_CONSOLE_WRITE"]);
                }
            }
            return (out, ops_out);
        }
        let fns = libsys_fns();
        if lang == Lang::RustStd {
            // Whatever the program says, `std` can reach these: every
            // `SYS_*` and op the port layer names, and the socket layer's when
            // the program names `std::net`.
            let net = files.iter().any(|&(_, src)| lex(src, false).contains("std::net"));
            for src in STDRT.iter().chain(STDRT_NET.iter().filter(|_| net)) {
                for (_, id) in idents(&lex(src, false)) {
                    if let Some(&o) = opn.get(id) {
                        ops_out.insert(o);
                    } else if id.starts_with("SYS_") {
                        out.insert(*nrs.get(id).unwrap_or_else(|| panic!("stdrt names {id}, which syscall_nr.rs does not define")));
                    }
                }
            }
        }
        for &(path, src) in files {
            let code = lex(src, false);
            let with_strings = lex(src, true);
            // `#[sys::main]` / `#[azos::main]` (azos_libsys_macros) writes the
            // entry, whose end is `sys::exit`, and a panic handler that is too.
            let compact: String = code.chars().filter(|c| !c.is_whitespace()).collect();
            assert!(
                !compact.contains("::utest::"),
                "{path}: names the test harness (`utest`), whose calls this scanner does not follow; \
                 describe them (like DEV_REACH) before an image carries a test",
            );
            if ["sys", "azos", "azos_libsys"].iter().any(|q| compact.contains(&format!("#[{q}::main"))) {
                for s in closure(&fns, "exit") {
                    out.insert(*nrs.get(&s).unwrap_or_else(|| panic!("libsys exit issues {s}, which syscall_nr.rs does not define")));
                }
            }
            // The device-interface transports the source names: `Ep` is the
            // v2 call and `Regs` the register form, so the calls it issues
            // are the transport's, whichever client stub it drives.
            let mut dev_transports: Vec<&str> = Vec::new();
            for prefix in ["use sys::", "use azos_libsys::"] {
                for (at, _) in code.match_indices(prefix) {
                    let tail = &code[at + prefix.len()..];
                    let list = &tail[..tail.find(';').expect("`use` without `;`")];
                    // `use sys::dev::{..}`: the device-interface clients; the
                    // module is not a function, and the names under it are
                    // types and traits.
                    let dev_list = list.strip_prefix("dev::");
                    if let Some(l) = dev_list {
                        for (_, id) in idents(l) {
                            if id == "Ep" || id == "Regs" {
                                dev_transports.push(id);
                            }
                        }
                    }
                    let list = dev_list.unwrap_or(list);
                    assert!(!list.contains('*'), "{path}: glob import from libsys");
                    for (_, id) in idents(list) {
                        assert!(
                            !id.starts_with(|c: char| c.is_ascii_lowercase()),
                            "{path}: imports libsys fn `{id}` by name. The scanner follows \
                             `sys::NAME(..)` calls only; call it qualified or teach the scanner.",
                        );
                    }
                }
            }
            for (at, id) in idents(&code) {
                let before = &code[..at];
                // An op the program names itself (a generic wrapper such as
                // `sys::trace_ctl(cap, OP, ..)` takes the op as an argument).
                if let Some(&o) = opn.get(id) {
                    ops_out.insert(o);
                    continue;
                }
                // `sys::dev::NAME(..)`: a device-interface client.
                let dev = ["azos_libsys::dev::", "sys::dev::"].iter().any(|q| {
                    before.strip_suffix(q).is_some_and(|rest| rest.as_bytes().last().is_none_or(|&c| !is_ident(c)))
                });
                if dev && (id == "Ep" || id == "Regs") {
                    dev_transports.push(id);
                    continue;
                }
                if dev && next_non_ws(&code, at + id.len()) == Some(b'(') {
                    let reach = DEV_REACH
                        .iter()
                        .find(|r| r.0 == id)
                        .unwrap_or_else(|| panic!("{path}: calls `sys::dev::{id}(..)`, which DEV_REACH does not describe"));
                    for s in reach.1 {
                        out.insert(*nrs.get(*s).unwrap_or_else(|| panic!("DEV_REACH names {s}, which syscall_nr.rs does not define")));
                    }
                    continue;
                }
                // `sys::pipe::NAME(..)`: the process's POSIX pipe.
                let pipe = ["azos_libsys::pipe::", "sys::pipe::"].iter().any(|q| {
                    before.strip_suffix(q).is_some_and(|rest| rest.as_bytes().last().is_none_or(|&c| !is_ident(c)))
                });
                if pipe && next_non_ws(&code, at + id.len()) == Some(b'(') {
                    // A `const fn` on the handle's bits: the kernel is not asked.
                    if id == "is_token" {
                        continue;
                    }
                    let reach = PIPE_REACH
                        .iter()
                        .find(|r| r.0 == id)
                        .unwrap_or_else(|| panic!("{path}: calls `sys::pipe::{id}(..)`, which PIPE_REACH does not describe"));
                    for s in reach.1 {
                        if let Some(&o) = opn.get(*s) {
                            ops_out.insert(o);
                        } else {
                            out.insert(*nrs.get(*s).unwrap_or_else(|| panic!("PIPE_REACH names {s}, which syscall_nr.rs does not define")));
                        }
                    }
                    continue;
                }
                let qualified = ["azos_libsys::", "sys::"].iter().any(|q| {
                    before.strip_suffix(q).is_some_and(|rest| {
                        rest.as_bytes().last().is_none_or(|&c| !is_ident(c))
                    })
                });
                // `sys::Lock<T>` (libsys lock.rs): a type, but its `lock` yields
                // while another thread holds it, so a program that has one
                // issues what `yield_now` does.
                if qualified && id == "Lock" {
                    for s in closure(&fns, "yield_now") {
                        out.insert(*nrs.get(&s).unwrap_or_else(|| panic!("libsys issues {s}, which syscall_nr.rs does not define")));
                    }
                    continue;
                }
                if !qualified || next_non_ws(&code, at + id.len()) != Some(b'(') {
                    continue; // not a call: a const, a type, a macro (`sys::cstr!`)
                }
                // `#[sys::main(panic_exit = 70)]`: an attribute macro, whose
                // effect is derived above (its entry ends in `sys::exit`).
                if (id == "main" || id == "test")
                    && ["azos_libsys::", "sys::", "azos::"].iter().any(|q| before.strip_suffix(q).is_some_and(|r| r.ends_with("#[")))
                {
                    continue;
                }
                assert!(fns.contains_key(id), "{path}: calls `sys::{id}(..)`, which libsys does not define");
                for s in closure(&fns, id) {
                    if let Some(&o) = opn.get(&s) {
                        ops_out.insert(o);
                        continue;
                    }
                    out.insert(*nrs.get(&s).unwrap_or_else(|| {
                        panic!("libsys issues {s}, which syscall_nr.rs does not define")
                    }));
                }
            }
            for t in &dev_transports {
                let call = if *t == "Ep" { "SYS_IPC_CALL_V2" } else { "SYS_IPC_FAST_CALL_EP" };
                out.insert(*nrs.get(call).unwrap_or_else(|| panic!("{call} is not defined")));
            }
            let a7 = "in(\"a7\")";
            let sites: Vec<usize> = with_strings.match_indices(a7).map(|(i, _)| i).collect();
            assert_eq!(
                with_strings.matches("\"ecall\"").count(),
                sites.len(),
                "{path}: an `ecall` whose a7 is not set by `in(\"a7\")`; the scanner cannot see \
                 what it issues",
            );
            for at in sites {
                let tok: String = with_strings[at + a7.len()..]
                    .trim_start()
                    .chars()
                    .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                    .collect();
                out.extend(resolve_a7(&with_strings, at, &tok, &nrs));
            }
        }
        if pipe_stages().iter().any(|s| s == image) {
            for s in PIPE_STAGE_REACH {
                if let Some(&o) = opn.get(*s) {
                    ops_out.insert(o);
                } else {
                    out.insert(*nrs.get(*s).unwrap_or_else(|| panic!("PIPE_STAGE_REACH names {s}, which syscall_nr.rs does not define")));
                }
            }
        }
        (out, ops_out)
    }

    fn named(table: &[(&str, &str, &str)], image: &str) -> BTreeSet<u16> {
        let nrs = numbers();
        table
            .iter()
            .filter(|r| r.0 == image)
            .map(|r| *nrs.get(r.1).unwrap_or_else(|| panic!("{} names no syscall", r.1)))
            .collect()
    }

    /// What `image`'s row must allow: its derived set, minus the calls it never
    /// issues, the calls it issues to see the filter refuse, and the raw probes
    /// its audit mode lets through to the dispatcher.
    fn expected(image: &str) -> BTreeSet<u16> {
        let never = named(NEVER_ISSUED, image);
        let probes = named(REFUSAL_PROBES, image);
        let audited: BTreeSet<u16> = AUDITED_PROBES
            .iter()
            .chain(AUDITED_LIVE_CALLS)
            .filter(|a| a.0 == image)
            .map(|a| a.1)
            .collect();
        derive(image)
            .into_iter()
            .filter(|n| !never.contains(n) && !probes.contains(n) && !audited.contains(n))
            .collect()
    }

    fn row(image: &str) -> &'static ImageProfile {
        IMAGE_PROFILES
            .iter()
            .find(|p| p.image == image)
            .unwrap_or_else(|| panic!("IMAGE_PROFILES has no row for {image}"))
    }

    /// `mcopy -i $@ $(X_ELF) ::NAME.ELF` in the Makefile's disk-image recipe.
    fn shipped_images() -> BTreeSet<String> {
        let set: BTreeSet<String> = MAKEFILE
            .lines()
            .filter_map(|l| {
                let t = l.trim();
                if !t.starts_with("mcopy -i $@ $(") {
                    return None;
                }
                let (_, name) = t.rsplit_once("::")?;
                name.ends_with(".ELF").then(|| name.to_string())
            })
            .collect();
        assert!(set.len() >= 11, "found only {set:?} in the Makefile's image recipe");
        set
    }

    // ── The tests ───────────────────────────────────────────────────────

    /// `DEV_KEYS` lists every interface of the registry, once, and no other.
    ///
    /// **Canary.** Add an interface to `azos_devif::IFACES` without a row
    /// here: red.
    #[test]
    fn the_dev_keys_table_covers_the_registry() {
        let mut want: Vec<u16> = azos_devif::IFACES.iter().map(|i| i.key).collect();
        let mut have: Vec<u16> = DEV_KEYS.iter().map(|k| k.1).collect();
        want.sort();
        have.sort();
        assert_eq!(have, want);
        assert!(azos_devif::IFACES.len() < crate::filter::FILTER_IFACE_KEYS as usize,
            "a filter's interface word holds {} keys", crate::filter::FILTER_IFACE_KEYS);
    }

    /// **A profile lists exactly the kernel-hosted interfaces its binary
    /// calls.** An interface it lists and never calls is authority a
    /// compromised binary gets for free; one it calls and does not list kills
    /// the task at the first call (and is withheld from its row's grants).
    ///
    /// **Canaries.** Add `azos_devif::key::OTA` to `SH.ELF`'s row: red, naming
    /// it. Drop `key::ENTROPY` from `BRAINCLI.ELF`'s: red.
    #[test]
    fn every_image_profile_lists_exactly_the_interfaces_its_binary_calls() {
        for p in IMAGE_PROFILES {
            let want = derive_ifaces(p.image);
            let have: BTreeSet<u16> = p.ifaces.iter().copied().collect();
            assert_eq!(have, want, "{}: the profile's interfaces (left) vs what the source calls (right)", p.image);
        }
    }

    /// `DEV_REACH` describes every public function of `libsys::dev`, and
    /// nothing else (a new client function must say what it issues).
    ///
    /// **Canary.** Add `pub fn foo()` to `dev.rs`: red.
    #[test]
    fn the_dev_clients_table_names_every_public_function() {
        let code = lex(DEV_SRC, false);
        let ids = idents(&code);
        let mut public: Vec<&str> = Vec::new();
        for w in ids.windows(3) {
            if w[0].1 == "pub" && w[1].1 == "fn" {
                public.push(w[2].1);
            }
        }
        public.sort();
        let mut table: Vec<&str> = DEV_REACH.iter().map(|r| r.0).collect();
        table.sort();
        assert_eq!(public, table, "libsys/src/dev.rs public functions vs DEV_REACH");
    }

    /// The derivation of the pipeline stages finds the shell's tools (and
    /// not the shell, whose pipes are made, not received).
    ///
    /// **Canary.** Rename `SH_CAPS` in the topology builder: red.
    #[test]
    fn the_pipe_stages_are_the_images_the_shell_can_start() {
        let stages = pipe_stages();
        for tool in ["TOOLBOX.ELF", "POWER.ELF", "FLIGHT.ELF", "BEHAVIOR.ELF", "CONFIG.ELF", "OTA.ELF", "TRACECTL.ELF", "WHY.ELF", "PKG.ELF"] {
            assert!(stages.iter().any(|s| s == tool), "{tool} is started by the shell and is not a pipe stage: {stages:?}");
        }
        assert!(!stages.iter().any(|s| s == "SH.ELF"), "the shell is no stage of its own pipelines");
    }

    /// `PIPE_REACH` describes every public function of `libsys/src/pipe.rs`,
    /// and only those.
    ///
    /// **Canary.** Add `pub fn foo()` to `pipe.rs`: red.
    #[test]
    fn the_pipe_table_names_every_public_function() {
        let code = lex(PIPE_SRC, false);
        let ids = idents(&code);
        let mut public: Vec<&str> = Vec::new();
        for w in ids.windows(3) {
            if w[0].1 == "pub" && w[1].1 == "fn" {
                public.push(w[2].1);
            }
        }
        public.sort();
        let mut table: Vec<&str> = PIPE_REACH.iter().map(|r| r.0).collect();
        table.sort();
        assert_eq!(public, table, "libsys/src/pipe.rs public functions vs PIPE_REACH");
    }

    /// The scanner reproduces the sets verified by hand. Pinned with the ABI
    /// constants, not the scanner's own name table, so a regression in either
    /// half shows here instead of shrinking every profile in step with it.
    #[test]
    fn the_scanner_reproduces_the_hand_verified_sets() {
        use azos_abi::syscall_nr as nr;
        let set = |v: &[u64]| v.iter().map(|&n| n as u16).collect::<BTreeSet<u16>>();
        // The console is a handle looked up once and written through
        // `SYS_INVOKE`: the lookup is a call of its own.
        assert_eq!(derive("HELLO.ELF"), set(&[nr::SYS_EXIT, nr::SYS_INVOKE, nr::SYS_CAP_INFO]));
        assert_eq!(
            derive("SYSTEST.ELF"),
            set(&[nr::SYS_EXIT, nr::SYS_GETPID, nr::SYS_INVOKE, nr::SYS_CAP_INFO, nr::SYS_MO_MAP]),
        );
        // println = the console write; exit; the panic handler exits; the fast
        // IPC call is the refusal probe.
        assert_eq!(
            derive("UHELLO.ELF"),
            set(&[nr::SYS_EXIT, nr::SYS_IPC_FAST_CALL_EP, nr::SYS_INVOKE, nr::SYS_CAP_INFO]),
        );
        // The two raw probes resolve through a fn parameter and a literal.
        assert!(derive("CAPTEST.ELF").contains(&116));
        assert!(derive("ABITEST.ELF").contains(&999));
    }

    /// Every ELF the disk image carries has a row, and every row is an ELF the
    /// image carries. A binary added to the image without a row would run
    /// refused at exec; a row for a binary no longer shipped is a grant
    /// waiting for whatever next takes the name.
    #[test]
    fn every_image_the_disk_ships_has_a_profile_and_nothing_else_does() {
        let shipped = shipped_images();
        let rows: BTreeSet<String> = IMAGE_PROFILES.iter().map(|p| p.image.to_string()).collect();
        let scanned: BTreeSet<String> = SOURCES.iter().map(|s| s.0.to_string()).collect();
        assert_eq!(rows.len(), IMAGE_PROFILES.len(), "two rows name the same image");
        assert_eq!(rows, shipped, "IMAGE_PROFILES vs the Makefile's image recipe");
        assert_eq!(scanned, shipped, "this suite's SOURCES vs the Makefile's image recipe");
    }

    /// A third-party image's row (BusyBox, never in the base
    /// image, its source not in this tree) lists only native numbers the
    /// Linux personality's table can reach, names no base image, and is a
    /// Linux row's: no number outside what translation reaches can be in it.
    ///
    /// **Canary.** Add `SYS_SPAWN_EX` to `BUSYBOX.ELF`'s row: red.
    #[test]
    fn a_third_party_row_lists_only_what_the_personality_reaches() {
        let mut reach: BTreeSet<u16> = azos_linux_abi::TABLE.iter().flat_map(|e| e.2.iter().copied()).collect();
        // ... and the native calls the ring-3 runtime makes for itself.
        reach.extend(azos_linux_rt::RUNTIME_NATIVE.iter().copied());
        let base: BTreeSet<&str> = IMAGE_PROFILES.iter().map(|p| p.image).collect();
        assert!(!THIRDPARTY_PROFILES.is_empty());
        for p in THIRDPARTY_PROFILES {
            assert!(!base.contains(p.image), "{} is both a base and a third-party image", p.image);
            assert!(!p.audit, "{}: a third-party row is never in audit mode", p.image);
            for n in p.syscalls {
                assert!(reach.contains(n), "{}: native {} is not reachable through the personality", p.image, n);
            }
        }
    }

    /// Resolve a `#[path = "..."]` attribute immediately preceding the
    /// `mod` keyword at `mod_kw_at` in `code` (comments stripped, string
    /// contents KEPT — `lex(src, true)`, so the attribute's literal is
    /// readable). Returns `None` when the declaration uses default
    /// resolution (no attribute, or something else sits before it).
    ///
    /// Bounded and textual on purpose, like every other check in this
    /// file: it looks at the exact bytes immediately before `mod`
    /// (skipping whitespace and an optional `pub`), not a general
    /// attribute parser.
    fn path_attr_before(code: &str, mod_kw_at: usize) -> Option<String> {
        let before = code[..mod_kw_at].trim_end();
        let before = before.strip_suffix("pub").map(str::trim_end).unwrap_or(before);
        let before = before.trim_end();
        if !before.ends_with(']') {
            return None;
        }
        let start = before.rfind("#[path")?;
        let attr = &before[start..];
        let after_eq = &attr[attr.find('=')? + 1..];
        let after_q1 = &after_eq[after_eq.find('"')? + 1..];
        let end = after_q1.find('"')?;
        Some(after_q1[..end].to_string())
    }

    /// Repo root. `CARGO_MANIFEST_DIR` (a compile-time literal) is this
    /// crate's own root, `tests/host/seccomp-tests` — two levels up, not
    /// three: the `src!` macro's `"../../../"` is relative to
    /// `tests/host/seccomp-tests/src/`, one directory deeper than
    /// `CARGO_MANIFEST_DIR`.
    fn repo_root() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..")
    }

    /// Collapse `.`/`..` components without touching the filesystem (the
    /// path may not exist yet at the point this runs — it is what we are
    /// about to check).
    fn normalize(p: std::path::PathBuf) -> std::path::PathBuf {
        let mut out = std::path::PathBuf::new();
        for c in p.components() {
            match c {
                std::path::Component::ParentDir => {
                    out.pop();
                }
                std::path::Component::CurDir => {}
                other => out.push(other),
            }
        }
        out
    }

    /// Recursively discover every file `entry_rel` (repo-root-relative)
    /// pulls in via `mod X;` / `#[path = "P"] mod X;`, resolving
    /// default-form declarations against the sibling file `X.rs` (this
    /// tree never uses the `X/mod.rs` form) and `#[path]` ones against
    /// `P` relative to the declaring file's own directory — exactly
    /// `rustc`'s own module resolution. Returns repo-root-relative,
    /// normalized paths, entry included; inline `mod x { .. }` blocks are
    /// not files and are not followed (nothing to discover — their
    /// content is already in the file that declares them).
    ///
    /// Real filesystem reads (`std::fs::read_to_string`), deliberately
    /// not `include_str!`: `include_str!` needs a path this function
    /// only learns while running, so it cannot follow a `mod` tree it
    /// has not been told about in advance — which was exactly the gap:
    /// `every_module_a_binary_declares_is_scanned` used to check only
    /// `mod` declarations WITHIN files `SOURCES` already hardcoded, one
    /// level, never asking whether a newly added file — `BRAINCLI.ELF`
    /// gaining a `#[path] mod` — was in `SOURCES` at all.
    fn discover_module_tree(entry_rel: &str) -> BTreeSet<String> {
        let mut visited = BTreeSet::new();
        let mut stack = vec![entry_rel.to_string()];
        while let Some(rel) = stack.pop() {
            if visited.contains(&rel) {
                continue;
            }
            let abs = repo_root().join(&rel);
            let src = match std::fs::read_to_string(&abs) {
                Ok(s) => s,
                Err(e) => panic!("{rel}: could not read {}: {e}", abs.display()),
            };
            visited.insert(rel.clone());
            let dir = std::path::Path::new(&rel)
                .parent()
                .unwrap_or(std::path::Path::new(""))
                .to_path_buf();
            let code = lex(&src, true);
            let ids = idents(&code);
            for w in ids.windows(2) {
                let ((at, kw), (nat, name)) = (w[0], w[1]);
                if kw != "mod" || next_non_ws(&code, nat + name.len()) != Some(b';') {
                    continue;
                }
                let child = match path_attr_before(&code, at) {
                    Some(p) => normalize(dir.join(p)),
                    None => normalize(dir.join(format!("{name}.rs"))),
                };
                let child_rel = child.to_string_lossy().into_owned();
                if !visited.contains(&child_rel) {
                    stack.push(child_rel);
                }
            }
        }
        visited
    }

    /// A module a binary's `mod` tree pulls in — at any depth, `#[path]`
    /// included — and this suite does not account for would hide its
    /// calls from every other test here. Ground truth is a real,
    /// recursive filesystem walk from the entry point (see
    /// `discover_module_tree`), not a hardcoded per-image file list: a
    /// list drifts the moment a binary gains a new module and nobody
    /// remembers to add it here too, which is how a
    /// `#[path]` module of `BRAINCLI.ELF` once went unnoticed.
    #[test]
    fn every_module_a_binary_declares_is_scanned() {
        for &(image, lang, files) in SOURCES {
            if lang != Lang::Rust && lang != Lang::RustStd {
                continue;
            }
            let entry = files[0].0;
            let scanned: BTreeSet<&str> = files
                .iter()
                .map(|(p, _)| p.rsplit('/').next().unwrap().trim_end_matches(".rs"))
                .collect();
            for discovered in discover_module_tree(entry) {
                let base = discovered.rsplit('/').next().unwrap().trim_end_matches(".rs");
                let excluded = MODULES_NOT_IN_THE_IMAGE.iter().any(|e| e.0 == image && e.1 == base);
                assert!(
                    excluded || scanned.contains(base),
                    "{image}: `{discovered}` is reachable from its entry point's `mod` tree but \
                     is not in SOURCES (and not in MODULES_NOT_IN_THE_IMAGE) — add it, or the \
                     calls inside it are invisible to every other test in this file"
                );
            }
        }
    }

    /// **Complete.** Each row allows every call its binary issues.
    #[test]
    fn every_image_profile_allows_every_call_its_binary_issues() {
        for p in IMAGE_PROFILES {
            let f = image_filter(p);
            for n in expected(p.image) {
                assert!(
                    f.is_allowed(n),
                    "{} issues syscall {n} and its profile does not allow it: the binary \
                     would be refused at that call. Add it to its row in \
                     crates/core/sched/src/seccomp.rs.",
                    p.image,
                );
            }
        }
    }

    /// **The runtime's own calls are listed.** A Linux image hosted by the
    /// ring-3 runtime issues, in the program's address space, whatever the
    /// runtime's `Native` implementation (`userspace/services/lxrt`) issues:
    /// every `SYS_INVOKE` op it names must be in `RUNTIME_OPS`, and every
    /// syscall number in `RUNTIME_NATIVE` or among those the personality's
    /// table reaches. One missing is a hosted task killed at that call
    /// (`SYS_CAP_INFO`, the console capability's lookup, was).
    ///
    /// **Canary.** Remove `SYS_CAP_INFO` from `RUNTIME_NATIVE`, or
    /// `LOG_CONSOLE_WRITE` from `RUNTIME_OPS`: red.
    #[test]
    fn the_runtime_lists_what_its_image_issues() {
        let files: &[(&str, &str)] = &[src!("userspace/services/lxrt/src/main.rs")];
        let (nrs, ops) = derive_files("LXRT", Lang::Rust, files);
        let mut allowed: BTreeSet<u16> = azos_linux_rt::RUNTIME_NATIVE.iter().copied().collect();
        for e in azos_linux_abi::TABLE {
            allowed.extend(e.2.iter().copied());
        }
        let n = numbers();
        let name = |x: u16| n.iter().find(|(_, v)| **v == x).map(|(k, _)| k.clone()).unwrap_or(format!("{x}"));
        let missing: Vec<String> = nrs.difference(&allowed).map(|&x| name(x)).collect();
        assert!(missing.is_empty(), "the runtime issues syscalls RUNTIME_NATIVE and the table do not list: {missing:?}");
        let listed: BTreeSet<u16> = azos_linux_rt::RUNTIME_OPS.iter().copied().collect();
        let o = op_names();
        let missing: Vec<String> = ops
            .difference(&listed)
            .map(|&x| o.iter().find(|(_, v)| **v == x).map(|(k, _)| k.to_string()).unwrap_or(format!("{x:#x}")))
            .collect();
        assert!(missing.is_empty(), "the runtime issues ops RUNTIME_OPS does not list: {missing:?}");
    }

    /// **Ops, complete and exact.** Each row lists, for `SYS_INVOKE`, exactly
    /// the (kind, class) pairs the ops its binary's wrappers use belong to: an
    /// op class nothing needs is authority a compromised binary gets for free,
    /// and one it needs and lacks kills it at that call.
    ///
    /// **Canary.** Add `LOG_CONSOLE_WAIT` to `TOOLBOX.ELF`'s `ops`: red, naming
    /// the row.
    #[test]
    fn each_image_profile_lists_exactly_the_op_classes_its_binary_uses() {
        let mut bad = Vec::new();
        for p in IMAGE_PROFILES {
            let audited: BTreeSet<(u8, u8)> = AUDITED_OPS
                .iter()
                .filter(|a| a.0 == p.image)
                .map(|a| (azos_abi::invoke::op_kind(a.1), azos_abi::invoke::op_class(a.1)))
                .collect();
            let want: BTreeSet<(u8, u8)> = derive_ops(p.image).difference(&audited).copied().collect();
            let f = image_filter(p);
            let mut got = BTreeSet::new();
            for k in 0..azos_abi::invoke::OP_KINDS as u8 {
                for c in 0..azos_abi::invoke::CLASSES {
                    if f.op_listed(k, c) {
                        got.insert((k, c));
                    }
                }
            }
            if got != want {
                bad.push(format!(
                    "{}: the ops its profile lists and the ops its source uses differ \
                     (profile {got:?}, derived {want:?})",
                    p.image,
                ));
            }
            // The number the ops travel on is listed exactly when any op is used.
            // A Linux image has no native op of its own: the personality performs
            // the console's, and its translation table lists the number.
            let linux = sources_of(p.image).0 == Lang::LinuxC;
            if !linux && f.is_allowed(azos_abi::syscall_nr::SYS_INVOKE as u16) != !want.is_empty() {
                bad.push(format!("{}: SYS_INVOKE is listed iff the binary invokes an op", p.image));
            }
        }
        assert!(bad.is_empty(), "{}", bad.join("\n"));
    }

    /// **Exact.** Each row allows nothing its binary does not issue.
    #[test]
    fn no_image_profile_allows_a_call_its_binary_does_not_issue() {
        for p in IMAGE_PROFILES {
            let want = expected(p.image);
            let f = image_filter(p);
            let got: BTreeSet<u16> = f.allowed[..f.count as usize].iter().copied().collect();
            assert_eq!(
                got, want,
                "{}: the profile and what the source issues differ (left: profile, \
                 right: derived). A grant nothing needs is authority a compromised \
                 binary gets for free.",
                p.image,
            );
        }
    }

    /// **Refused, or recorded; never silently allowed.** Every number outside a
    /// row is refused by a row in enforcing mode, and let through and recorded
    /// by a row in audit mode. That includes the never-issued calls and the
    /// probes, which the source names. Every number inside is allowed.
    #[test]
    fn a_call_outside_an_image_profile_is_refused_or_recorded() {
        let mut outside_checked = 0usize;
        for p in IMAGE_PROFILES {
            let want = expected(p.image);
            let f = image_filter(p);
            assert!(f.enabled, "{}: an image profile must have the filter ON", p.image);
            let outside = if p.audit { FilterVerdict::Audit } else { FilterVerdict::Deny };
            for n in (0..1000u16).chain([u16::MAX]) {
                if want.contains(&n) {
                    assert_eq!(f.verdict(n), FilterVerdict::Allow, "{} syscall {n}, in its profile", p.image);
                } else {
                    assert_eq!(f.verdict(n), outside, "{} syscall {n}, outside its profile", p.image);
                    outside_checked += 1;
                }
            }
        }
        assert!(outside_checked > 10_000, "only {outside_checked} outside calls checked");
    }

    /// Audit mode is for the two binaries that probe the kernel with calls it
    /// must refuse on its own, and nothing else: every other shipped binary is
    /// refused outside its row.
    #[test]
    fn only_the_two_probing_test_binaries_run_in_audit_mode() {
        let audit: BTreeSet<&str> = IMAGE_PROFILES.iter().filter(|p| p.audit).map(|p| p.image).collect();
        assert_eq!(audit, BTreeSet::from(["ABITEST.ELF", "CAPTEST.ELF"]));
    }

    /// The rows that differ from their derivation say why, and each claim is a
    /// real one: the call is named in the source and is outside the row. The
    /// refusal probes are refused by the FILTER, whatever the row's mode: uhello
    /// checks `getpid() == E_PERM_DISPATCH`, which a call let through would
    /// answer with a positive tid.
    #[test]
    fn every_departure_from_the_derivation_is_named_in_source_and_outside_the_row() {
        let nrs = numbers();
        for &(image, name, why) in NEVER_ISSUED.iter().chain(REFUSAL_PROBES) {
            let n = nrs[name];
            assert!(derive(image).contains(&n), "{image}: {name} is listed ({why}) but not in its source");
            assert!(!image_filter(row(image)).is_allowed(n), "{image} lists {name}, listed as {why}");
        }
        for &(image, name, why) in REFUSAL_PROBES {
            assert_eq!(image_filter(row(image)).verdict(nrs[name]), FilterVerdict::Deny, "{image}: {name} ({why})");
        }
    }

    /// The audited probes: issued raw by their binary, outside its row, let
    /// through to the dispatcher and recorded. Only numbers that name no syscall
    /// ride that way: if 116 or 999 is ever assigned, the probe would reach that
    /// call's arm instead of a refusal.
    #[test]
    fn the_audit_rows_let_their_raw_probes_through_and_record_them() {
        let nrs = numbers();
        for &(image, probe, why) in AUDITED_PROBES {
            let p = row(image);
            assert!(p.audit, "{image} carries an audited probe ({why}) and is not in audit mode");
            assert!(derive(image).contains(&probe), "{image}: {probe} ({why}) is not in its source");
            assert!(!p.syscalls.contains(&probe), "{image} lists {probe}: it would go through unrecorded");
            assert_eq!(image_filter(p).verdict(probe), FilterVerdict::Audit, "{image}: {probe}");
            let names: Vec<&String> = nrs.iter().filter(|(_, v)| **v == probe).map(|(k, _)| k).collect();
            assert!(names.is_empty(), "{image}: probe {probe} is now {names:?}");
        }
        let with_probes: BTreeSet<&str> = AUDITED_PROBES.iter().map(|a| a.0).collect();
        assert_eq!(with_probes, BTreeSet::from(["ABITEST.ELF", "CAPTEST.ELF"]));
    }

    /// The live calls an audit row probes: issued by the binary,
    /// outside its row, let through and recorded, and each a real syscall.
    #[test]
    fn the_audit_rows_probe_live_calls_outside_their_row() {
        let nrs = numbers();
        for &(image, n, why) in AUDITED_LIVE_CALLS {
            let p = row(image);
            assert!(p.audit, "{image} probes {n} ({why}) and is not in audit mode");
            assert!(derive(image).contains(&n), "{image}: {n} ({why}) is not in its source");
            assert!(!p.syscalls.contains(&n), "{image} lists {n}: it would go through unrecorded");
            assert_eq!(image_filter(p).verdict(n), FilterVerdict::Audit, "{image}: {n}");
            assert!(nrs.values().any(|v| *v == n), "{image}: {n} ({why}) names no syscall");
        }
    }

    /// The body of the `match` arm `FilterVerdict::<verdict> =>` in the
    /// dispatcher's filter check: from the arrow to the next arm or the end of
    /// the match.
    fn verdict_arm(gate: &str, verdict: &str) -> String {
        let head = format!("FilterVerdict::{verdict} =>");
        let at = gate.find(&head).unwrap_or_else(|| panic!("no `{head}` arm in the filter check"));
        let body = &gate[at + head.len()..];
        let end = body.find("azos_sched::filter::FilterVerdict::").unwrap_or(body.len());
        lex(&body[..end], false)
    }

    /// **Recorded, and not copied.** The dispatcher's filter check stated as
    /// code, from its source:
    ///  * it asks `current_syscall_verdict(num)`, on the full number, before the
    ///    fast path;
    ///  * `Deny` calls `seccomp_deny_kill(num)`, which never returns —
    ///    V1.8 (owner decision, 2026-09-26): a denied call kills the task
    ///    instead of returning `-1`, because a `-1` a compromised or buggy
    ///    binary can silently ignore is not containment. The record →
    ///    console line → exit sequence itself lives in
    ///    `handlers::seccomp_deny_kill` (checked below), not inlined at
    ///    the call site;
    ///  * `Audit` calls `record_seccomp_audit` and does NOT return, so the call
    ///    goes on to its arm;
    ///  * `Allow` does nothing;
    ///  * nothing in the dispatcher fetches the filter by value any more.
    #[test]
    fn the_dispatcher_refuses_and_records_as_the_verdict_says() {
        let gate_at = DISPATCH
            .find("match azos_sched::scheduler::current_syscall_verdict(num) {")
            .expect("the dispatcher's filter check moved or changed shape");
        let fast = DISPATCH.find("SYS_GETPID => return sys_getpid()").expect("fast path moved");
        assert!(gate_at < fast, "the filter must be checked before the fast path");
        let gate = &DISPATCH[gate_at..fast];

        // V1.8: `Deny` no longer records-and-returns inline — it calls the
        // kill path and diverges. Checking `return E_PERM;` here would
        // pass on a dispatcher that silently stopped killing at all (the
        // arm would just be empty), which is the one regression this test
        // exists to catch.
        let deny = verdict_arm(gate, "Deny");
        assert!(
            deny.contains("seccomp_deny_kill(num)") && !deny.contains("return"),
            "Deny must call seccomp_deny_kill(num) and diverge, not inline its own \
             record/return: {deny}",
        );

        let audit = verdict_arm(gate, "Audit");
        assert!(
            audit.contains("record_seccomp_audit(num as u16)"),
            "Audit must record the call: {audit}",
        );
        assert!(!audit.contains("return"), "Audit must let the call through: {audit}");

        let allow = verdict_arm(gate, "Allow");
        assert_eq!(allow.trim(), "{}", "Allow must do nothing");

        assert!(
            !lex(DISPATCH, false).contains("current_syscall_filter()"),
            "the dispatcher copies the filter out of the TCB again",
        );

        // The kill path itself, in order: recorded, THEN an
        // operator-visible line, THEN the exit that never returns.
        // `uhello`'s own userspace probe used to observe and print the
        // refusal itself; since V1.8 the syscall that would have told it
        // never returns, so the console line moved into this function —
        // it is the one place on this path that still runs.
        // Braces inside `kwarn!`'s own format string (`"...{}..."`)
        // would confuse a raw-text brace count, so this operates on the
        // comments-stripped, strings-BLANKED lexing — same as
        // `verdict_arm` above. None of the substrings this checks for
        // (`trace_event(`, `TRACE_SYSCALL`, `0xDEAD`, `kwarn!`,
        // `task_exit_with_code(..)`) live inside a string literal.
        let code = lex(HANDLERS, false);
        let fn_at = code
            .find("pub(crate) fn seccomp_deny_kill(num: u64) -> !")
            .expect("seccomp_deny_kill moved, was renamed, or stopped diverging");
        let body_start = code[fn_at..].find('{').unwrap() + fn_at + 1;
        let close = close_of(&code, body_start - 1, b'{', b'}');
        let body = &code[body_start..close];

        let rec = body.find("trace_event(").expect("a refusal by the filter is no longer recorded");
        assert!(
            body[rec..].contains("TRACE_SYSCALL") && body[rec..].contains("0xDEAD"),
            "the record must still be TRACE_SYSCALL / the 0xDEAD denied marker",
        );
        // At warn level (`kwarn!`), so a release build (log level warn) still
        // prints it; a plain `kprintln!` is info and compiled out there.
        let line = body.find("kwarn!").expect("the operator-visible kill line is gone, or is no longer warn level");
        // Wave 13: through `task_exit_by_signal` (the same code, and the
        // signal recorded so a Linux parent sees WIFSIGNALED SIGSYS).
        let exit = body
            .find("task_exit_by_signal(SECCOMP_KILL_EXIT_CODE)")
            .expect("seccomp_deny_kill no longer exits via SECCOMP_KILL_EXIT_CODE");
        assert!(rec < line && line < exit, "must be record, THEN console line, THEN exit: {body}");
        assert!(
            HANDLERS.contains("pub const SECCOMP_KILL_EXIT_CODE: i32 = 159"),
            "the kill exit code changed from 159 — update every test/doc/gate row that pins it",
        );
    }

    /// **In place.** The verdict the dispatcher asks is computed on the task
    /// slot through a pointer, not on a by-value copy of the 132-byte filter.
    #[test]
    fn the_verdict_is_read_on_the_task_slot_in_place() {
        const SCHEDULER: &str = concat!(
            include_str!("../../../../crates/core/sched/src/scheduler/mod.rs"),
            include_str!("../../../../crates/core/sched/src/scheduler/wake.rs"),
            include_str!("../../../../crates/core/sched/src/scheduler/ipc_fast.rs"),
            include_str!("../../../../crates/core/sched/src/scheduler/lifecycle.rs"),
            include_str!("../../../../crates/core/sched/src/scheduler/budget.rs"),
            include_str!("../../../../crates/core/sched/src/scheduler/donation.rs"),
        );
        let code = lex(SCHEDULER, false);
        let at = code
            .find("pub fn current_syscall_verdict(num: u64)")
            .expect("current_syscall_verdict moved or changed signature");
        let body = &code[at..close_of(&code, at + code[at..].find('{').unwrap(), b'{', b'}')];
        assert!(body.contains("PER_CPU[cpu].current_filter.load(Ordering::Relaxed)"), "{body}");
        assert!(body.contains("(*(filter as *const SyscallFilter)).verdict_for(num)"), "{body}");
        assert!(!body.contains("current_syscall_filter()"), "{body}");
        assert!(!body.contains("let f = TASKS["), "{body}");
        // The whole point of the cached pointer: the syscall path must not walk
        // back to the task array. A re-derivation here would silently restore
        // the MAX_TASKS bound, the ×1088 stride and the TASKS base this removed.
        assert!(
            !body.contains("addr_of!(TASKS["),
            "the syscall path derives the filter address again: {body}",
        );
    }

    /// **The cached filter pointer cannot drift from the index it mirrors.**
    ///
    /// `PerCpuSched::current_filter` exists so the syscall path does not
    /// re-derive `&TASKS[idx].syscall_filter` on every call. A writer that
    /// stored `current_idx` and left the pointer alone would leave a hart
    /// answering syscalls against the PREVIOUS task's whitelist: a containment
    /// failure that refuses nothing, crashes nothing and shows up in no log.
    ///
    /// The guarantee is structural rather than careful — exactly one place in
    /// the scheduler writes the index, and it derives the pointer from that
    /// same index in the same function, so the two cannot disagree. This test
    /// is what keeps a third writer from ever being added quietly.
    #[test]
    fn only_set_current_task_writes_current_idx() {
        const SCHEDULER: &str = concat!(
            include_str!("../../../../crates/core/sched/src/scheduler/mod.rs"),
            include_str!("../../../../crates/core/sched/src/scheduler/wake.rs"),
            include_str!("../../../../crates/core/sched/src/scheduler/ipc_fast.rs"),
            include_str!("../../../../crates/core/sched/src/scheduler/lifecycle.rs"),
            include_str!("../../../../crates/core/sched/src/scheduler/budget.rs"),
            include_str!("../../../../crates/core/sched/src/scheduler/donation.rs"),
        );
        let code = lex(SCHEDULER, false);

        let writes = code.matches("current_idx.store(").count();
        assert_eq!(
            writes, 1,
            "`current_idx` is stored in {writes} places; only `set_current_task` may, \
             or a hart runs one task under another task's syscall filter",
        );

        let at = code
            .find("unsafe fn set_current_task(cpu: usize, next_idx: usize)")
            .expect("set_current_task moved or changed signature");
        let body = &code[at..close_of(&code, at + code[at..].find('{').unwrap(), b'{', b'}')];
        assert!(body.contains("current_idx.store(next_idx"), "the one write is not the setter's: {body}");
        assert!(
            body.contains("core::ptr::addr_of!(TASKS[next_idx].syscall_filter)"),
            "the setter must derive the cached pointer from the index it just stored, \
             not take it as an argument: {body}",
        );
        assert!(body.contains("current_filter.store("), "the setter no longer caches: {body}");
    }

    /// No row reaches the filter's capacity: `allow` would drop the rest in
    /// silence, and the task would find out at that call on the board.
    #[test]
    fn no_image_profile_fills_the_filter() {
        for p in IMAGE_PROFILES {
            let f = image_filter(p);
            let distinct: BTreeSet<u16> = p.syscalls.iter().copied().collect();
            assert_eq!(f.count as usize, distinct.len(), "{}: entries were dropped", p.image);
            assert_eq!(f.audit, p.audit, "{}: the filter must carry the row's audit mode", p.image);
            assert!(
                (f.count as usize) < SYSCALL_FILTER_MAX,
                "{} fills {}/{SYSCALL_FILTER_MAX}",
                p.image,
                f.count,
            );
        }
        // Wave 9: the list went from 64 to 96 because the widest row
        // (ABITEST.ELF, audit mode) listed 62 of 64. Keep a quarter of the
        // list free, so the next row that grows trips here, not on a board.
        let widest = IMAGE_PROFILES.iter().map(|p| image_filter(p).count as usize).max().unwrap();
        assert!(
            widest * 4 <= SYSCALL_FILTER_MAX * 3,
            "the widest image profile lists {widest} of {SYSCALL_FILTER_MAX}: less than a quarter free",
        );
    }

    // ── Bound to the bytes, not the name (owner decision 2026-09-14) ─────

    /// The Makefile's `IMAGE_ELFS`: `(NAME, $(VAR))` in order.
    fn image_elfs_rule() -> Vec<(String, String)> {
        let mut text = String::new();
        let mut on = false;
        for l in MAKEFILE.lines() {
            on |= l.starts_with("IMAGE_ELFS :=");
            if on {
                text.push_str(l.trim_end_matches('\\'));
                text.push(' ');
                if !l.ends_with('\\') {
                    break;
                }
            }
        }
        assert!(on, "the Makefile has no IMAGE_ELFS");
        text.trim_start_matches("IMAGE_ELFS :=")
            .split_whitespace()
            .map(|t| {
                let (name, var) = t.split_once('=').unwrap_or_else(|| panic!("IMAGE_ELFS token {t}"));
                (name.to_string(), var.to_string())
            })
            .collect()
    }

    /// `(NAME, $(VAR))` of each `mcopy -i $@ $(VAR) ::NAME.ELF` in the
    /// RISC-V image recipe (`$AZOS_OUT/build/disk.img` and its siblings), in order.
    ///
    /// **`_AARCH64`-suffixed variables are excluded.** Phase 6 (userspace on
    /// aarch64) added a second, independent `mcopy -i $@ $(..._AARCH64)
    /// ::NAME.ELF` recipe (`$AZOS_OUT/build/disk-aarch64.img`, `Makefile`) for the
    /// aarch64 ELFs — same `NAME.ELF` targets, deliberately, since both
    /// kernels look up `HELLO.ELF` etc. by the same FAT32 name. Before that
    /// recipe existed, EVERY `mcopy -i $@ ... ::NAME.ELF` line in the whole
    /// Makefile belonged to the one recipe this function (and `IMAGE_ELFS`)
    /// is about, so no filter was needed. Widening the raw scan to match
    /// both recipes would make this function assert riscv64's `IMAGE_ELFS`
    /// against a LIST TWICE AS LONG as it (correctly) is — this crate's own
    /// `crates/core/sched/src/seccomp.rs` `include!`s a SEPARATE, aarch64-only
    /// table (`$AZOS_OUT/build/image_hashes_aarch64.rs`) for exactly this reason: one
    /// ISA's recipe, one ISA's `IMAGE_ELFS`, checked against each other. A
    /// dedicated `IMAGE_ELFS_AARCH64` check is `Makefile`/`build.rs`-side
    /// tooling this host crate does not duplicate.
    fn image_recipe_copies() -> Vec<(String, String)> {
        // Each (name, ELF) pair once, at its first copy: one ELF may be copied
        // onto several volumes (wave 13: L1's `disk-*lxbench.img` copy
        // LXSRV.ELF again after `disk-*lx.img`).
        let mut seen = std::collections::BTreeSet::new();
        MAKEFILE
            .lines()
            .filter_map(|l| {
                let (var, name) = l.trim().strip_prefix("mcopy -i $@ ")?.split_once(" ::")?;
                (var.starts_with("$(") && !var.contains("_AARCH64") && !var.contains("_X86_64")
                    && name.ends_with(".ELF"))
                    .then(|| (name.to_string(), var.to_string()))
            })
            .filter(|p| seen.insert(p.clone()))
            .collect()
    }

    /// The aarch64 mirror of `image_elfs_rule`: `IMAGE_ELFS_AARCH64`'s
    /// `(NAME, $(VAR))` pairs, in order. Same continuation-line join, same
    /// token shape (`Makefile` line 388, `HELLO.ELF=$(HELLO_ELF_AARCH64)
    /// SYSTEST.ELF=$(SYSTEST_ELF_AARCH64) \` etc.).
    fn image_elfs_rule_aarch64() -> Vec<(String, String)> {
        let mut text = String::new();
        let mut on = false;
        for l in MAKEFILE.lines() {
            on |= l.starts_with("IMAGE_ELFS_AARCH64 :=");
            if on {
                text.push_str(l.trim_end_matches('\\'));
                text.push(' ');
                if !l.ends_with('\\') {
                    break;
                }
            }
        }
        assert!(on, "the Makefile has no IMAGE_ELFS_AARCH64");
        text.trim_start_matches("IMAGE_ELFS_AARCH64 :=")
            .split_whitespace()
            .map(|t| {
                let (name, var) = t.split_once('=').unwrap_or_else(|| panic!("IMAGE_ELFS_AARCH64 token {t}"));
                (name.to_string(), var.to_string())
            })
            .collect()
    }

    /// The aarch64 mirror of `image_recipe_copies`: `(NAME, $(VAR))` of each
    /// `mcopy -i $@ $(..._AARCH64) ::NAME.ELF` in the aarch64 image recipe
    /// (`$AZOS_OUT/build/disk-aarch64.img` and its siblings — `$AZOS_OUT/build/disk-aarch64-
    /// systest.img`, `$AZOS_OUT/build/disk-aarch64-abitest.img`, all one shared
    /// recipe body, so one set of `mcopy` lines). The riscv64 scan above
    /// excludes `_AARCH64`-suffixed variables (see its own doc for why);
    /// this one requires them, so the two scans partition every `mcopy
    /// -i $@ ... ::NAME.ELF` line in the Makefile between them rather than
    /// leaving this recipe unchecked, closing the gap that function's doc
    /// names.
    fn image_recipe_copies_aarch64() -> Vec<(String, String)> {
        // Each (name, ELF) pair once, at its first copy: one ELF may be copied
        // onto several volumes (wave 13: L1's `disk-*lxbench.img` copy
        // LXSRV.ELF again after `disk-*lx.img`).
        let mut seen = std::collections::BTreeSet::new();
        MAKEFILE
            .lines()
            .filter_map(|l| {
                let (var, name) = l.trim().strip_prefix("mcopy -i $@ ")?.split_once(" ::")?;
                (var.starts_with("$(") && var.contains("_AARCH64") && name.ends_with(".ELF"))
                    .then(|| (name.to_string(), var.to_string()))
            })
            .filter(|p| seen.insert(p.clone()))
            .collect()
    }

    /// The x86_64 mirror of `image_elfs_rule_aarch64`: `IMAGE_ELFS_X86_64`'s
    /// `(NAME, $(VAR))` tokens in order.
    fn image_elfs_rule_x86_64() -> Vec<(String, String)> {
        let mut on = false;
        let mut text = String::new();
        for l in MAKEFILE.lines() {
            on |= l.starts_with("IMAGE_ELFS_X86_64 :=");
            if on {
                text.push_str(l.trim_end_matches('\\'));
                text.push(' ');
                if !l.ends_with('\\') {
                    break;
                }
            }
        }
        assert!(on, "the Makefile has no IMAGE_ELFS_X86_64");
        text.trim_start_matches("IMAGE_ELFS_X86_64 :=")
            .split_whitespace()
            .map(|t| {
                let (name, var) = t.split_once('=').unwrap_or_else(|| panic!("IMAGE_ELFS_X86_64 token {t}"));
                (name.to_string(), var.to_string())
            })
            .collect()
    }

    /// The x86_64 mirror of `image_recipe_copies_aarch64`: the
    /// `mcopy -i $@ $(..._X86_64) ::NAME.ELF` lines of the x86_64 disk
    /// recipe, which the riscv64 scan excludes as it excludes `_AARCH64`.
    fn image_recipe_copies_x86_64() -> Vec<(String, String)> {
        let mut seen = std::collections::BTreeSet::new();
        MAKEFILE
            .lines()
            .filter_map(|l| {
                let (var, name) = l.trim().strip_prefix("mcopy -i $@ ")?.split_once(" ::")?;
                (var.starts_with("$(") && var.contains("_X86_64") && name.ends_with(".ELF"))
                    .then(|| (name.to_string(), var.to_string()))
            })
            .filter(|p| seen.insert(p.clone()))
            .collect()
    }

    /// The path `$(VAR)` names: its `VAR := path` line in the Makefile.
    fn makefile_var(var: &str) -> String {
        let key = var.trim_start_matches("$(").trim_end_matches(')');
        MAKEFILE
            .lines()
            .find_map(|l| {
                let (k, v) = l.split_once(":=")?;
                (k.trim() == key).then(|| v.trim().to_string())
            })
            .unwrap_or_else(|| panic!("the Makefile does not define {key}"))
    }

    /// The bytes the image carries under `name`, as the build left them in
    /// `$AZOS_OUT/build`.
    pub(crate) fn shipped_elf(name: &str) -> Vec<u8> {
        let (_, var) = image_elfs_rule()
            .into_iter()
            .find(|(n, _)| n == name)
            .unwrap_or_else(|| panic!("IMAGE_ELFS has no {name}"));
        // The Makefile spells the path `$(OUT_BUILD)/<name>`: the outputs live under $AZOS_OUT.
        let path = makefile_var(&var).replace("$(OUT_BUILD)", concat!(env!("AZOS_OUT"), "/build"));
        std::fs::read(&path).unwrap_or_else(|e| {
            panic!(
                "{path}: {e}. The seccomp image table is generated from the shipped ELFs: \
                 run `make $AZOS_OUT/build/image_hashes.rs`, which builds them, before this suite."
            )
        })
    }

    /// The digest the exec sites compute is SHA-256: the FIPS 180-4 examples,
    /// including a message that needs a second padding block and one of a
    /// million bytes.
    #[test]
    fn the_digest_computed_at_exec_is_sha256() {
        let hex = |d: [u8; 32]| d.iter().map(|b| format!("{b:02x}")).collect::<String>();
        assert_eq!(hex(image_digest(b"")), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        assert_eq!(hex(image_digest(b"abc")), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        assert_eq!(
            hex(image_digest(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
        );
        assert_eq!(
            hex(image_digest(&vec![b'a'; 1_000_000])),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0",
        );
    }

    /// The hash rule hashes exactly what the image recipe copies: the same
    /// names from the same files, in the same order. A binary in one list and
    /// not the other would ship unbound (refused at exec), or be bound and not
    /// shipped.
    #[test]
    fn the_hash_rule_lists_exactly_what_the_image_recipe_copies() {
        let rule = image_elfs_rule();
        assert_eq!(rule, image_recipe_copies(), "IMAGE_ELFS vs the disk-image recipe's mcopy lines");
        assert_eq!(rule.len(), IMAGE_PROFILES.len());
    }

    /// The aarch64 mirror of the test above. Before this, `image_recipe_
    /// copies` explicitly excluded every `_AARCH64` variable and nothing
    /// else in this suite ever looked at them, so a name added to
    /// `IMAGE_ELFS_AARCH64` without a matching `mcopy` line (or vice versa)
    /// in `$AZOS_OUT/build/disk-aarch64.img`'s recipe went unchecked — the exact gap
    /// `image_recipe_copies`'s own doc comment names. `>= 13` rather than
    /// an exact `IMAGE_PROFILES` comparison: the aarch64 recipe ships
    /// GPIODRV.ELF/UHELLO.ELF/REFLEX.ELF/BRAINCLI.ELF too, which carry no
    /// seccomp profile of their own (`IMAGE_PROFILES` is a riscv64-side
    /// table this crate owns; nothing analogous exists per-ISA yet), so the
    /// two lists are not expected to be the same LENGTH as `IMAGE_PROFILES`
    /// — only internally consistent with each other, which the `assert_eq!`
    /// below is what actually proves.
    #[test]
    fn the_aarch64_hash_rule_lists_exactly_what_the_aarch64_image_recipe_copies() {
        let rule = image_elfs_rule_aarch64();
        assert_eq!(
            rule, image_recipe_copies_aarch64(),
            "IMAGE_ELFS_AARCH64 vs the aarch64 disk-image recipe's mcopy lines",
        );
        assert!(rule.len() >= 13, "found only {rule:?} in the aarch64 Makefile image recipe");
    }

    /// The x86_64 mirror of the aarch64 test above: the x86_64 digest table
    /// (`IMAGE_ELFS_X86_64`) hashes exactly what the x86_64 disk recipe
    /// copies, under the same names, in the same order.
    #[test]
    fn the_x86_64_hash_rule_lists_exactly_what_the_x86_64_image_recipe_copies() {
        let rule = image_elfs_rule_x86_64();
        assert_eq!(
            rule, image_recipe_copies_x86_64(),
            "IMAGE_ELFS_X86_64 vs the x86_64 disk-image recipe's mcopy lines",
        );
        assert!(rule.len() >= 13, "found only {rule:?} in the x86_64 Makefile image recipe");
    }

    /// Every row is bound to one digest and every digest to a row, in Makefile
    /// copy order, and no two shipped ELFs have the same bytes, which would bind
    /// one binary to the other's row.
    #[test]
    fn every_row_is_bound_to_one_digest_and_every_digest_to_a_row() {
        let rows: Vec<&str> = IMAGE_PROFILES.iter().map(|p| p.image).collect();
        let bound: Vec<&str> = IMAGE_SHA256.iter().map(|(n, _)| *n).collect();
        assert_eq!(bound, rows, "IMAGE_SHA256 vs IMAGE_PROFILES");
        let digests: BTreeSet<[u8; 32]> = IMAGE_SHA256.iter().map(|(_, d)| *d).collect();
        assert_eq!(digests.len(), IMAGE_SHA256.len(), "two shipped ELFs have the same bytes");
    }

    /// **Not stale.** The digests the kernel is built with are those of the ELFs
    /// in $AZOS_OUT/build/ now, which the next disk image carries. A table generated
    /// before an ELF was rebuilt fails here, instead of refusing that binary at
    /// boot.
    #[test]
    fn the_table_is_the_sha256_of_the_elfs_the_image_ships() {
        for (name, digest) in IMAGE_SHA256 {
            let got = image_digest(&shipped_elf(name));
            assert!(
                got == *digest,
                "{name}: $AZOS_OUT/build/image_hashes.rs is stale against its ELF. Run \
                 `make $AZOS_OUT/build/image_hashes.rs` and rebuild the kernel.",
            );
            assert_eq!(image_for_digest(digest).map(|p| p.image), Some(*name));
        }
    }

    /// **Renaming does not widen.** uhello's bytes copied over ABITEST.ELF (the
    /// image of the `seccomp: renamed image keeps its profile` scenario) are
    /// bound to UHELLO.ELF's row, which refuses uhello's probe (the fast IPC
    /// call), not to ABITEST.ELF's, which allows it.
    #[test]
    fn a_renamed_binary_keeps_its_own_profile() {
        use azos_abi::syscall_nr as nr;
        let probe = nr::SYS_IPC_FAST_CALL_EP as u16;
        let p = image_for_digest(&image_digest(&shipped_elf("UHELLO.ELF"))).expect("uhello's bytes are bound");
        assert_eq!(p.image, "UHELLO.ELF");
        assert_eq!(image_filter(p).verdict(probe), FilterVerdict::Deny);
        assert_eq!(
            image_filter(row("ABITEST.ELF")).verdict(probe),
            FilterVerdict::Allow,
            "the scenario discriminates only while the name it borrows allows uhello's probe",
        );
    }

    /// **Replacing refuses.** Every shipped ELF with one byte appended (the image
    /// of the `seccomp: replaced image is refused` scenario), one byte flipped,
    /// or its last byte dropped is bound to no row, so the exec sites refuse it.
    #[test]
    fn a_replaced_binary_has_no_profile() {
        for (name, _) in IMAGE_SHA256 {
            let shipped = shipped_elf(name);
            let mut longer = shipped.clone();
            longer.push(b'\n');
            let mut flipped = shipped.clone();
            let mid = flipped.len() / 2;
            flipped[mid] ^= 0x01;
            let shorter = &shipped[..shipped.len() - 1];
            for (how, bytes) in [("appended", &longer[..]), ("flipped", &flipped[..]), ("dropped", shorter)] {
                assert!(
                    image_for_digest(&image_digest(bytes)).is_none(),
                    "{name} with one byte {how} is still bound to a row",
                );
            }
        }
        assert!(image_for_digest(&image_digest(b"")).is_none());
    }

    // ── Spawn: refusal, filter and capability key ───────────

    /// **Every shipped image spawns under its own row, keyed by its own name.**
    /// The filter is the row's, entry for entry, audit mode included, and the
    /// topology key is the name the build copied the bytes under (owner
    /// decision 73): the name a file is opened under is not an input at all.
    #[test]
    fn a_spawn_plan_is_its_images_row_and_name() {
        use crate::spawn_policy::plan_spawn;
        for (name, _) in IMAGE_SHA256 {
            let plan = plan_spawn(&image_digest(&shipped_elf(name)))
                .unwrap_or_else(|e| panic!("{name}: a shipped image is refused ({e:?})"));
            let want = image_filter(row(name));
            let f = plan.filter;
            assert_eq!(plan.profile.image, *name);
            assert_eq!(plan.topology_key, *name, "{name}: the capability key is the image name");
            assert!(f.enabled, "{name}: the child's filter must be on");
            assert_eq!(f.audit, want.audit, "{name}: audit mode");
            assert_eq!(
                &f.allowed[..f.count as usize],
                &want.allowed[..want.count as usize],
                "{name}: the child's filter is not its row",
            );
        }
    }

    /// **A file bound to no row is refused with `EACCES`**, before anything is
    /// created: bytes no image carries, and every shipped image with one byte
    /// flipped (`a_replaced_binary_has_no_profile` for the exec sites).
    #[test]
    fn spawning_a_file_bound_to_no_row_is_eacces() {
        use crate::spawn_policy::plan_spawn;
        use azos_abi::error::Errno;
        let refused = |bytes: &[u8]| plan_spawn(&image_digest(bytes)).err();
        assert_eq!(refused(b"# AzOS Configuration\n"), Some(Errno::EACCES));
        assert_eq!(refused(b""), Some(Errno::EACCES));
        for (name, _) in IMAGE_SHA256 {
            let mut flipped = shipped_elf(name);
            let mid = flipped.len() / 2;
            flipped[mid] ^= 0x01;
            assert_eq!(refused(&flipped), Some(Errno::EACCES), "{name} with one byte flipped");
        }
        assert_eq!(Errno::EACCES.to_syscall_ret(), -13, "the value abitest asserts");
    }

    /// **The kernel's spawn path takes the plan's filter and only it.** The two
    /// spawn files, comments removed: neither reads, copies or installs a
    /// current task's filter; the handler plans from the digest and hands the
    /// plan's filter to `spawn_prepare`, which puts it in `TaskInit`, so it is
    /// on the slot before the task is runnable. Source, not execution: the
    /// handler needs a live task pool. `userspace: ABI conformance` runs it.
    #[test]
    fn the_spawn_path_installs_the_plans_filter_and_no_other() {
        let handler = lex(include_str!("../../../../crates/core/syscall/src/spawn.rs"), false);
        let create = lex(include_str!("../../../../crates/core/sched/src/spawn.rs"), false);
        for (file, src) in [("syscall/src/spawn.rs", &handler), ("sched/src/spawn.rs", &create)] {
            for banned in [
                "current_syscall_filter",
                "set_current_syscall_filter",
                "set_task_syscall_filter",
                "install_image_profile",
                "activate_profile",
            ] {
                assert!(!src.contains(banned), "{file} names `{banned}`");
            }
        }
        assert!(handler.contains("spawn_policy::plan_spawn(&digest)"), "the handler plans from the digest");
        assert!(
            handler.contains("spawn_prepare(elf, plan.filter,"),
            "the handler passes the plan's filter to spawn_prepare",
        );
        assert!(create.contains("syscall_filter: Some(filter)"), "spawn_prepare installs it through TaskInit");
    }

    /// **Bytes that depend on source and toolchain only.** Every userspace cargo
    /// recipe goes through `$(USPACE_BUILD)`, which runs rustc under
    /// `userspace/rustc_stable_metadata.py`, and that wrapper derives `-C metadata`
    /// from nothing that names a directory.
    ///
    /// Why it has to: each userspace crate is its own workspace with
    /// `crates/core/libsys` as a path dependency outside it, so cargo hashes libsys's
    /// absolute path into `-C metadata`; rustc turns that into the crate
    /// disambiguator, and items are ordered by names that carry it. The same
    /// brain_client sources built in two directories differed in `.strtab`, and
    /// stripped, in 2975 bytes of `.text` (gate 40 refused one rebuilt in its
    /// snapshot). Through the wrapper the two directories give identical ELFs. A
    /// two-directory build belongs in `tools/repro_check.sh`; this is the check
    /// that costs nothing.
    ///
    /// **Canary.** Drop `RUSTC_WRAPPER=...` from `USPACE_BUILD`: the definition
    /// check fails. Put `os.getcwd()` into the wrapper's key: the key check fails.
    #[test]
    fn every_userspace_elf_is_built_with_path_independent_metadata() {
        const WRAPPER: &str = include_str!("../../../../userspace/rustc_stable_metadata.py");
        let def = MAKEFILE
            .lines()
            .find(|l| l.starts_with("USPACE_BUILD :="))
            .expect("the Makefile defines no USPACE_BUILD");
        assert!(
            def.contains("RUSTC_WRAPPER='$(CURDIR)/userspace/rustc_stable_metadata.py' $(CARGO) +nightly build --release"),
            "{def}",
        );
        // Cargo does not rebuild when only RUSTC_WRAPPER changes, so the flags
        // carry a digest of the wrapper: a changed wrapper changes the fingerprint.
        // A recipe names its ISA's target and rustflags after $(USPACE_BUILD)
        // (one of these), and each starts its rustflags with the digest
        // (followed by the Kconfig's codegen flags, when any).
        const ISA_FLAGS: [&str; 5] = ["RV_UFLAGS", "AARCH64_UFLAGS", "X86_64_UFLAGS", "LXRT_UFLAGS_AARCH64", "LXRT_UFLAGS_X86_64"];
        let lines: Vec<&str> = MAKEFILE.lines().collect();
        for var in ISA_FLAGS {
            let at = lines
                .iter()
                .position(|l| l.starts_with(&format!("{var} ")) && l.contains('='))
                .unwrap_or_else(|| panic!("the Makefile defines no {var}"));
            let mut def = String::new();
            for l in &lines[at..] {
                def.push_str(l.trim_end_matches('\\'));
                if !l.ends_with('\\') {
                    break;
                }
            }
            assert!(def.contains(r#".rustflags=["--cfg=azos_stable_metadata_$(USPACE_METADATA_TAG)""#), "{def}");
        }
        let tag = MAKEFILE
            .lines()
            .find(|l| l.starts_with("USPACE_METADATA_TAG :="))
            .expect("the Makefile defines no USPACE_METADATA_TAG");
        assert!(tag.contains(r#"open("userspace/rustc_stable_metadata.py", "rb")"#), "{tag}");
        // The two ML-service wrappers (BOARDIMG, wave 11) only set the key
        // environment around $(USPACE_BUILD): they must end in it.
        const WRAPPED: [&str; 2] = ["&& $(MLSRV_QEMU_BUILD)", "&& $(MLSRV_BOARD_BUILD)"];
        for var in ["MLSRV_QEMU_BUILD", "MLSRV_BOARD_BUILD"] {
            let def = MAKEFILE
                .lines()
                .find(|l| l.starts_with(&format!("{var} =")))
                .unwrap_or_else(|| panic!("the Makefile defines no {var}"));
            assert!(def.ends_with(" $(USPACE_BUILD)"), "{def}");
        }
        for line in MAKEFILE.lines().filter(|l| l.trim_start().starts_with("cd $(")) {
            assert!(
                line.contains("&& $(USPACE_BUILD)") || WRAPPED.iter().any(|w| line.contains(w)),
                "a userspace recipe bypasses $(USPACE_BUILD): {line}",
            );
            let n = ISA_FLAGS.iter().filter(|v| line.contains(&format!("$({v})"))).count();
            assert_eq!(n, 1, "a userspace recipe names {n} ISA flag sets (one of {ISA_FLAGS:?}): {line}");
        }
        let recipes = MAKEFILE
            .lines()
            .filter(|l| l.contains("&& $(USPACE_BUILD)") || WRAPPED.iter().any(|w| l.contains(w)))
            .count();
        // The std programs (`Lang::RustStd`, the SDK) are built by
        // tools/sdk_cargo.py, which sets the same wrapper and the same
        // metadata tag itself (held below): their recipes are `$(SDK_BUILD_<isa>)`.
        let sdk_recipes = MAKEFILE.lines().filter(|l| l.starts_with('\t') && l.contains("$(SDK_BUILD_")).count();
        let rust_images = SOURCES.iter().filter(|s| s.1 == Lang::Rust).count();
        // One riscv64 recipe per Rust image (SOURCES' Lang::Rust count),
        // plus one aarch64 recipe per program — all 14, not 12: hello.S and
        // test.S are hand-assembled (SOURCES' Lang::Asm), but no aarch64 GNU
        // cross-assembler is available on this host, so their aarch64
        // counterparts (`userspace/tests/hello`, `userspace/tests/syscall_test`) are Rust
        // crates too and go through the same $(USPACE_BUILD). Phase 6 prep,
        // aarch64 parity — no aarch64 kernel exec path exists yet, so none of
        // this is in `SOURCES`/`IMAGE_ELFS`, which stay riscv64-only.
        // 15 since wave 9: the ring-3 buzzer and INA219 drivers.
        // 18 with the user shell and its tool image.
        // 19 with the power tool.
        // 20 with the Linux driver server skeleton.
        // 24 with the flight, behavior, config and OTA tools (wave 12).
        // 25 with the kernel tracer's reader (wave 15).
        // +1 riscv64 since wave 11 BOARDIMG: the board volume's own ML service
        // (the same crate, the named key), `$(MLSRV_ELF_BOARD)`.
        // +19 x86_64 (wave 15): `IMAGE_ELFS_X86_64`, one recipe per image.
        // +1 x86_64 (wave 15 VSX86): vsbench's own x86_64 recipe.
        // +1 x86_64 (wave 15 VS): vssrv, vsbench's ipc-roundtrip peer.
        // +1 on each of aarch64 and x86_64 with the terminal server (TERMD.ELF).
        // +1 on each of aarch64 and x86_64 with the name server (NAMESD.ELF).
        // +2 on each of riscv64, aarch64 and x86_64 with the decision server
        // and its tool (DECISD.ELF, WHY.ELF).
        // +2 on each of riscv64, aarch64 and x86_64 with the package installer
        // and its tool (PKGD.ELF, PKG.ELF), and +1 board recipe: the installer
        // verifies the signed topology, so the board volume has its own
        // (`$(PKGD_ELF_BOARD)`, like the ML service).
        // +1 on each of riscv64, aarch64 and x86_64 with the RPC server (RPCSRV.ELF).
        // +1 on each of riscv64, aarch64 and x86_64 with the Zenoh gateway (ZENOHD.ELF).
        // +1 on each of riscv64, aarch64 and x86_64 with the PTP daemon (PTPD.ELF).
        // +1 on each of riscv64, aarch64 and x86_64 with the audio server (AUDIOD.ELF).
        // +0: the relay of the QUIC link (RPCQUIC.ELF) is a std program on the vendored
        // tree, built by tools/sdk_cargo.py like the TLS probe, not by `$(USPACE_BUILD)`.
        // +1 on each of riscv64, aarch64 and x86_64 with the MCP bridge (MCPD.ELF).
        // +1 on each of riscv64, aarch64 and x86_64 with the SSH server (SSHD.ELF).
        // +1 on each of riscv64, aarch64 and x86_64 with the login service (LOGIND.ELF).
        // +1 on each of riscv64, aarch64 and x86_64 with the virtual-machine monitor (VMMD.ELF).
        // +1 on each of riscv64, aarch64 and x86_64 with the input server (INPUTD.ELF).
        // +1 on each of riscv64, aarch64 and x86_64 with the compositor (COMPSRV.ELF).
        // +1 on each of aarch64 and x86_64 with abitest's children (ABICHILD.ELF).
        // +1 on each of riscv64, aarch64 and x86_64 with the component manager
        // (COMPMGR.ELF).
        // -1 on each of riscv64, aarch64 and x86_64 when WHY.ELF moved to `std`
        // (the SDK): its three recipes are `$(SDK_BUILD_<isa>)` now.
        // -1 on each of riscv64, aarch64 and x86_64 and on the board volume when PKGD.ELF
        // moved to `std` (it fetches over TLS): built by tools/sdk_cargo.py like
        // RPCQUIC.ELF, on the vendored tree.
        // +1 on each of aarch64 and x86_64 with the kernel log's sink (LOGD.ELF;
        // riscv64's is in `rust_images`).
        // +3 with the Linux runtime (`userspace/services/lxrt`), one per ISA
        // that hosts the personality: it is embedded in the kernel, not on a
        // disk, so it is in no `SOURCES`/`IMAGE_ELFS`.
        // +4 on x86_64 with SYSTEST.ELF, CAPTEST.ELF, LATBENCH.ELF and LXSRV.ELF.
        assert_eq!(
            recipes,
            rust_images + 42 + 1 + 42 + 3,
            "expected {rust_images} riscv64 + 42 aarch64 + 1 board + 42 x86_64 + 3 runtime $(USPACE_BUILD) recipes",
        );
        // The SDK's recipes: WHY.ELF on three ISAs and the SDK's own test, sdktest,
        // on three.
        assert_eq!(sdk_recipes, 3 + 3, "expected 3 WHY.ELF and 3 sdktest $(SDK_BUILD_<isa>) recipes");
        const SDK_CARGO: &str = include_str!("../../../../tools/sdk_cargo.py");
        assert!(
            SDK_CARGO.contains(r#"env["RUSTC_WRAPPER"] = wrapper"#)
                && SDK_CARGO.contains(r#"wrapper = os.path.join(ROOT, "userspace", "rustc_stable_metadata.py")"#)
                && SDK_CARGO.contains(r#"flags = ["--cfg=azos_stable_metadata_" + tag,"#)
                && SDK_CARGO.contains("hashlib.sha256(f.read()).hexdigest()[:12]"),
            "tools/sdk_cargo.py no longer builds through the metadata wrapper with its digest as the cfg",
        );

        let key = WRAPPER
            .lines()
            .find(|l| l.trim_start().starts_with("key = "))
            .expect("the wrapper builds no metadata key");
        assert_eq!(
            key.trim(),
            r#"key = "\n".join([name, version, ctype, target] + sorted(cfgs))"#,
            "the wrapper's metadata key changed: it must name the unit, never a directory",
        );
        assert!(WRAPPER.contains(r#"out += ["-C", "metadata=" + value]"#), "the wrapper no longer replaces -C metadata");
        for names_a_directory in ["getcwd", "abspath", "realpath", "CARGO_MANIFEST_DIR", "CARGO_TARGET_DIR", "OUT_DIR"] {
            assert!(!WRAPPER.contains(names_a_directory), "the wrapper reads {names_a_directory}");
        }
    }

    /// **aarch64 parity.** The RISC-V scanner above requires every `"ecall"`
    /// in a Rust userspace source to be paired with an `in("a7")` that sets
    /// its number (`derive`'s `assert_eq!(with_strings.matches("\"ecall\""),
    /// sites.len())`). This is the same invariant for the aarch64 twin —
    /// `"svc #0"` / `in("x8")`, the register-convention analogue documented
    /// in `crates/core/abi/src/syscall_nr.rs` — over every Lang::Rust image's
    /// sources, plus `libsys` itself (the syscall layer these raw probes sit
    /// outside of; `LIBSYS` is not a `SOURCES` entry, so it needs its own
    /// pass).
    ///
    /// **Phase 6 prep, not a profile check.** No aarch64 kernel dispatch
    /// exists yet, so this does NOT feed `derive()`/`expected()` — the
    /// `IMAGE_PROFILES` rows stay riscv64-only, bound to the seccomp
    /// SHA-256 table `crates/core/sched/src/seccomp.rs` reads. What this test
    /// catches is the aarch64 analogue of the bug the ecall/a7 check
    /// catches: a raw `svc #0` whose `x8` the scanner (and, eventually, a
    /// human auditing the seccomp surface) cannot see because it was not
    /// spelled `in("x8")`.
    #[test]
    fn every_aarch64_svc_in_the_userspace_sources_has_a_declared_x8() {
        fn assert_paired(where_: &str, src: &str) {
            let with_strings = lex(src, true);
            let svc = with_strings.matches("\"svc #0\"").count();
            let x8 = with_strings.matches("in(\"x8\")").count();
            assert_eq!(
                svc, x8,
                "{where_}: {svc} `svc #0` sites but {x8} `in(\"x8\")` sites — an aarch64 \
                 trap whose number the scanner cannot see",
            );
        }
        for &(image, lang, files) in SOURCES {
            if lang != Lang::Rust && lang != Lang::RustStd {
                continue;
            }
            for &(path, src) in files {
                assert_paired(&format!("{image} ({path})"), src);
            }
        }
        for (i, src) in LIBSYS.iter().enumerate() {
            assert_paired(&format!("libsys[{i}]"), src);
        }
        // The std port layer's traps, which the std images' rows derive from
        // by name (`STDRT`), are paired on both ISAs the same way.
        for (i, src) in STDRT.iter().enumerate() {
            assert_paired(&format!("stdrt[{i}]"), src);
            let with_strings = lex(src, true);
            assert_eq!(
                with_strings.matches("\"ecall\"").count(),
                with_strings.matches("in(\"a7\")").count(),
                "stdrt[{i}]: an `ecall` whose number the scanner cannot see",
            );
        }
    }
}

/// The rustc wrapper every userspace ELF is built through
/// (`userspace/rustc_stable_metadata.py`), run for real with `/bin/echo` standing
/// in for rustc: what the wrapper would hand rustc comes back on stdout.
///
/// The kernel binds each seccomp image profile to the SHA-256 of the ELF the
/// build ships, and gate 40 refused a brain_client rebuilt in another directory.
/// So the metadata rustc sees must name the unit and never the checkout, must
/// still tell two versions of one crate apart, and must never silently fall back
/// to cargo's path-derived value.
#[cfg(test)]
mod metadata_wrapper {
    use std::process::Command;

    const WRAPPER: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../../userspace/rustc_stable_metadata.py");

    /// A lib unit as cargo compiles it. The source path and cargo's metadata are
    /// what vary with the checkout; nothing else does.
    fn unit<'a>(source: &'a str, cargo_metadata: &'a str) -> Vec<&'a str> {
        vec![
            "--crate-name", "azos_libsys", "--edition=2021", source,
            "--crate-type", "lib", "--target", "riscv64imac-unknown-none-elf",
            "--cfg", "feature=\"default\"",
            "-C", cargo_metadata, "-C", "extra-filename=-0123456789abcdef",
        ]
    }

    /// `(exit code, stdout, stderr)` of the wrapper run in `cwd`.
    fn run(args: &[&str], cwd: &str, version: Option<&str>) -> (i32, String, String) {
        let mut c = Command::new("python3");
        c.arg(WRAPPER).arg("/bin/echo").args(args).current_dir(cwd).env_remove("CARGO_PKG_VERSION");
        if let Some(v) = version {
            c.env("CARGO_PKG_VERSION", v);
        }
        let out = c.output().expect("python3 must run the wrapper");
        (
            out.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    }

    fn metadata(stdout: &str) -> &str {
        stdout
            .split_whitespace()
            .find(|a| a.starts_with("metadata="))
            .unwrap_or_else(|| panic!("no metadata argument in {stdout:?}"))
    }

    /// **Path-independent.** One unit compiled from two checkouts, each with the
    /// metadata cargo derives from its own path, reaches rustc with ONE value,
    /// and every other argument passes unchanged.
    ///
    /// **Canary.** Pass cargo's value through (`out += ["-C", args[i + 1]]`): the
    /// two checkouts differ.
    #[test]
    fn the_metadata_rustc_sees_does_not_depend_on_the_checkout() {
        let tmp = std::env::temp_dir();
        let a = unit("/Users/one/azos/crates/core/libsys/src/lib.rs", "metadata=1111111111111111");
        let b = unit("/tmp/two/os/crates/core/libsys/src/lib.rs", "metadata=2222222222222222");
        let (rc_a, out_a, err_a) = run(&a, "/", Some("0.1.0"));
        let (rc_b, out_b, err_b) = run(&b, tmp.to_str().unwrap(), Some("0.1.0"));
        assert_eq!((rc_a, rc_b), (0, 0), "{err_a}{err_b}");
        assert_eq!(
            metadata(&out_a),
            metadata(&out_b),
            "two checkouts of one unit reach rustc with different metadata",
        );
        assert!(!out_a.contains("metadata=1111111111111111"), "cargo's path-derived metadata reached rustc: {out_a}");
        assert!(
            out_a.contains("extra-filename=-0123456789abcdef")
                && out_a.contains("/Users/one/azos/crates/core/libsys/src/lib.rs"),
            "an argument other than -C metadata changed: {out_a}",
        );
    }

    /// **A custom target by name.** The x86_64 user target and the SDK's are
    /// JSON files cargo passes by path: two checkouts reach rustc with one
    /// value, and a different target file is a different unit.
    ///
    /// **Canary.** Key on the whole `--target` argument (drop the basename
    /// step in `unit_facts`): the two checkouts differ.
    #[test]
    fn a_json_target_is_keyed_by_its_name_not_its_directory() {
        let with = |target: &'static str| {
            let mut u = unit("/src/lib.rs", "metadata=1111111111111111");
            let at = u.iter().position(|a| *a == "--target").unwrap() + 1;
            u[at] = target;
            let (rc, out, err) = run(&u, "/", Some("0.1.0"));
            assert_eq!(rc, 0, "{err}");
            metadata(&out).to_string()
        };
        let a = with("/Users/one/azos/sdk/targets/riscv64imac-unknown-azos.json");
        let b = with("/tmp/two/os/sdk/targets/riscv64imac-unknown-azos.json");
        let c = with("/tmp/two/os/sdk/targets/aarch64-unknown-azos.json");
        assert_eq!(a, b, "two checkouts of one target reach rustc with different metadata");
        assert_ne!(a, c, "two targets share their metadata");
    }

    /// **Versions apart.** Two versions of one crate in a build get different
    /// metadata, or they would collide at link time. An unset version still works.
    ///
    /// **Canary.** Drop `version` from the key: 0.1.0 and 0.2.0 get one value.
    #[test]
    fn two_versions_of_one_crate_get_different_metadata() {
        let u = unit("/src/crates/core/libsys/src/lib.rs", "metadata=1111111111111111");
        let (_, v1, _) = run(&u, "/", Some("0.1.0"));
        let (_, v2, _) = run(&u, "/", Some("0.2.0"));
        assert_ne!(metadata(&v1), metadata(&v2), "two versions of azos_libsys would share -C metadata");
        let (rc, unset, err) = run(&u, "/", None);
        assert_eq!(rc, 0, "{err}");
        assert_ne!(metadata(&unset), metadata(&v1));
    }

    /// **Never a silent fallback.** A compilation that carries no `-C metadata`,
    /// or carries it twice, is refused before rustc runs, and the message names
    /// the crate. Cargo's probes (`rustc -vV`, a `--print` target-info run with
    /// `--crate-name ___`) still pass through.
    ///
    /// **Canary.** Disable either refusal: that half reaches rustc.
    #[test]
    fn a_compilation_without_exactly_one_metadata_is_refused_by_name() {
        let none = ["--crate-name", "azos_libsys", "--crate-type", "lib", "/src/lib.rs"];
        let (rc, out, err) = run(&none, "/", Some("0.1.0"));
        assert_ne!(rc, 0, "a compilation without -C metadata was run: {out}");
        assert!(out.is_empty(), "rustc ran: {out}");
        assert!(err.contains("azos_libsys") && err.contains("without -C metadata"), "{err}");

        let mut twice = unit("/src/lib.rs", "metadata=1111111111111111");
        twice.extend(["-C", "metadata=2222222222222222"]);
        let (rc, out, err) = run(&twice, "/", Some("0.1.0"));
        assert_ne!(rc, 0, "a compilation with two -C metadata was run: {out}");
        assert!(out.is_empty(), "rustc ran: {out}");
        assert!(err.contains("azos_libsys") && err.contains("2 times"), "{err}");

        let (rc, out, err) = run(&["-vV"], "/", None);
        assert_eq!((rc, out.trim()), (0, "-vV"), "{err}");
        let probe = ["-", "--crate-name", "___", "--print=file-names", "--crate-type", "bin"];
        let (rc, out, err) = run(&probe, "/", None);
        assert_eq!(rc, 0, "cargo's target-info probe was refused: {err}");
        assert!(out.contains("--print=file-names"), "{out}");
    }
}

/// Ownership on the syscall dispatch table, after the move to typed `Cap<T>` calls.
///
/// **WHY this reads the source.** Before the move the object families had two
/// forms: an untyped call that took a raw resource id in `a0` and had to be
/// hand-guarded by `port_access_ok` / `io_ring_access_ok`, and a typed
/// `Cap<T>` call that resolved the handle against the caller's OWN capability
/// table in the handler. The untyped forms are now retired, their guards
/// deleted with them: every port, io_ring, shm and channel arm is a typed
/// `Cap<T>` call, and the ownership check is the `cap_store::with_table(tid,
/// ..)` resolution inside each handler — a property of the handler, not of the
/// one-line dispatch arm.
///
/// So the invariant this test can hold from the dispatch source is the one
/// that made the guards unnecessary: **every object-handle arm is a typed
/// call**, recognizable by its `_TYPED` suffix and its membership in
/// `CAP_TYPED_SYSCALLS`. An untyped port/ring/shm arm reappearing —
/// the shape that carried W3-F2/W3-F3 — makes this red.
#[cfg(test)]
mod dispatch_guards {
    const DISPATCH: &str = include_str!("../../../../crates/core/syscall/src/dispatch.rs");

    /// Prefixes of the object families whose calls carry a resource handle.
    /// After the move every arm under one of these is a `Cap<T>` typed call.
    const HANDLE_PREFIXES: &[&str] = &["SYS_PORT_", "SYS_RING_", "SYS_MO_", "SYS_IO_"];

    /// Every dispatch arm whose name (the text before `=>`) begins with one of
    /// `HANDLE_PREFIXES`.
    fn handle_arms() -> Vec<&'static str> {
        let mut arms: Vec<&'static str> = Vec::new();
        for line in DISPATCH.lines() {
            let t = line.trim();
            if !t.contains("=>") {
                continue;
            }
            let Some(name) = t.split("=>").next().map(str::trim) else { continue };
            if HANDLE_PREFIXES.iter().any(|p| name.starts_with(p)) && !arms.contains(&name) {
                arms.push(name);
            }
        }
        arms
    }

    /// **Every object-handle arm is a typed `Cap<T>` call.** The untyped
    /// port/io_ring/shm/channel calls were retired with the move to typed `Cap<T>` calls; a dispatch
    /// arm under one of their prefixes that is not a `*_TYPED` call is an
    /// untyped one come back, with no ownership gate — exactly the W3-F2/W3-F3
    /// shape. Membership in `CAP_TYPED_SYSCALLS` is the ABI's own record that
    /// the arm resolves a capability against the caller's table.
    #[test]
    fn every_object_handle_arm_is_a_typed_cap_call() {
        let arms = handle_arms();
        // Non-vacuous: the port (5), io_ring (3), shm (4) and channel (3)
        // typed families are all present.
        assert!(
            arms.len() >= 6,
            "expected the typed port/io_ring/shm/channel arms, found {arms:?}",
        );
        for name in &arms {
            assert!(
                name.ends_with("_TYPED") || *name == "SYS_PORT_WAIT" || name.starts_with("SYS_MO_") || name.starts_with("SYS_RING_"),
                "dispatch arm `{name}` handles an object family but is not a typed \
                 Cap<T> call. The untyped forms were retired with the move to typed `Cap<T>` calls and \
                 carried no ownership gate on the dispatch arm — this is the \
                 W3-F2/W3-F3 shape. Route it through a handler that \
                 resolves the handle against the caller's own CapTable.",
            );
        }
    }

    /// And each of those arms names a member of `CAP_TYPED_SYSCALLS`, the ABI's
    /// own list of the calls that resolve a `Cap<T>`. A `_TYPED`-suffixed arm
    /// that is not in the list would be a typed handler the ABI does not
    /// account for.
    #[test]
    fn every_object_handle_arm_is_in_cap_typed_syscalls() {
        use azos_abi::syscall_nr as nr;
        // The typed object-handle syscalls, by name and number.
        let typed: &[(&str, u64)] = &[
            ("SYS_RING_SETUP", nr::SYS_RING_SETUP),
            ("SYS_RING_ENTER", nr::SYS_RING_ENTER),
            ("SYS_MO_CREATE", nr::SYS_MO_CREATE),
            ("SYS_MO_MAP", nr::SYS_MO_MAP),
            ("SYS_MO_UNMAP", nr::SYS_MO_UNMAP),
            ("SYS_PORT_WAIT", nr::SYS_PORT_WAIT),
        ];
        for name in handle_arms() {
            let (_, num) = typed
                .iter()
                .find(|(n, _)| *n == name)
                .unwrap_or_else(|| panic!("dispatch arm `{name}` is not a known typed object call"));
            assert!(
                nr::CAP_TYPED_SYSCALLS.contains(num),
                "`{name}` ({num}) is a dispatch arm but not in CAP_TYPED_SYSCALLS",
            );
        }
    }
}

/// Which shipped images may run under a `mem = "locked"`
/// topology row (`seccomp::locked_compatible`), pinned against the real
/// profile table.
///
/// **Canary** (run by hand 2026-09-28): drop `!p.audit &&` from
/// `locked_compatible` — `ABITEST.ELF`/`CAPTEST.ELF` (audit mode, which lets
/// any unlisted call through) are reported compatible and the test fails.
#[cfg(test)]
mod locked_rows {
    use crate::seccomp::{locked_compatible, IMAGE_PROFILES};

    fn row(image: &str) -> &'static crate::seccomp::ImageProfile {
        IMAGE_PROFILES.iter().find(|p| p.image == image).expect(image)
    }

    #[test]
    fn locked_compatibility_follows_the_profile() {
        // `mem-locked-smoke` puts UHELLO.ELF under a locked row: it must pass.
        assert!(locked_compatible(row("UHELLO.ELF")));
        // Audit mode cannot promise the absence of a call.
        assert!(!locked_compatible(row("ABITEST.ELF")));
        assert!(!locked_compatible(row("CAPTEST.ELF")));
        for p in IMAGE_PROFILES {
            let forks = p.syscalls.contains(&(azos_abi::syscall_nr::SYS_FOREIGN_FORK as u16));
            assert_eq!(locked_compatible(p), !p.audit && !forks, "{}", p.image);
        }
    }
}

/// Which shipped images memory admission counts as
/// forking (`seccomp::profile_can_fork`), pinned against the real profile
/// table: a row pays for a COW copy per instance only when its image lists
/// `SYS_FOREIGN_FORK` or runs in audit mode.
#[cfg(test)]
mod fork_capable_rows {
    use crate::seccomp::{profile_can_fork, profile_named, IMAGE_PROFILES};

    fn row(image: &str) -> &'static crate::seccomp::ImageProfile {
        profile_named(image.as_bytes()).expect(image)
    }

    #[test]
    fn the_shipped_forkers_and_non_forkers() {
        for img in ["ABITEST.ELF", "CAPTEST.ELF", "IPCTEST.ELF", "VSBENCH.ELF"] {
            assert!(profile_can_fork(row(img)), "{img} forks (or is audit mode)");
        }
        for img in ["GPIODRV.ELF", "REFLEX.ELF", "BRAINCLI.ELF", "EPSRV.ELF", "VSSRV.ELF", "UHELLO.ELF"] {
            assert!(!profile_can_fork(row(img)), "{img} cannot fork");
        }
        assert!(profile_named(b"NOSUCH.ELF").is_none());
    }

    #[test]
    fn fork_capability_is_audit_or_the_foreign_fork_call() {
        for p in IMAGE_PROFILES {
            let forks = p.syscalls.contains(&(azos_abi::syscall_nr::SYS_FOREIGN_FORK as u16));
            assert_eq!(profile_can_fork(p), p.audit || forks, "{}", p.image);
        }
    }
}

/// SYSFLOOR: the trap entries answer `getpid`/`yield` before they
/// build a syscall's arguments. These pin that the shortcut cannot run ahead
/// of the filter: `syscall_entry_fast` takes the verdict (`syscall_verdict`)
/// before any `Done`, and each trap entry reaches the dispatcher only through
/// one of the two. Chain E cut 7: the native entries' IPC branch (`FAST`)
/// takes `syscall_verdict` alone, the ordinary entry `syscall_entry_fast`.
#[cfg(test)]
mod syscall_entry_order {
    const DISPATCH: &str = include_str!("../../../../crates/core/syscall/src/dispatch.rs");
    /// The one syscall flow (`kernel/src/trap/syscall.rs`) and the kernel's
    /// services behind it (`kernel/src/trap/kernel.rs`); each ISA's trap entry
    /// only instantiates the flow over its own frame.
    const FLOW: &str = include_str!("../../../../kernel/src/trap/syscall.rs");
    const KERNEL: &str = include_str!("../../../../kernel/src/trap/kernel.rs");
    const RV: &str = include_str!("../../../../kernel/src/entry/riscv64/trap.rs");
    const ARM: &str = include_str!("../../../../kernel/src/entry/aarch64/trap.rs");
    const X86: &str = include_str!("../../../../kernel/src/entry/x86_64/trap.rs");

    /// Text of `fn <name>(` up to the next line that is exactly `}`.
    fn body<'a>(src: &'a str, sig: &str) -> &'a str {
        let at = src.find(sig).unwrap_or_else(|| panic!("`{sig}` not found"));
        let end = src[at..].find("\n}\n").unwrap_or_else(|| panic!("end of `{sig}` not found"));
        &src[at..at + end]
    }

    #[test]
    fn the_filter_verdict_comes_before_every_shortcut() {
        // The verdict itself: the filter read, and nothing answered.
        let v = body(DISPATCH, "pub fn syscall_verdict(");
        assert!(v.contains("current_syscall_verdict(num)"), "syscall_verdict takes no filter verdict");
        assert!(!v.contains("SyscallEntry::Done("), "syscall_verdict answers a call");
        // The register-only answers live in one function, called only after
        // the verdict, from `syscall_entry_fast` alone.
        let r = body(DISPATCH, "fn syscall_register_only(");
        for done in ["SyscallEntry::Done(sys_getpid())", "SyscallEntry::Done(sys_yield())"] {
            assert!(r.contains(done), "`{done}` is not answered in syscall_register_only");
            assert_eq!(DISPATCH.matches(done).count(), 1, "`{done}` is answered somewhere else too");
        }
        let b = body(DISPATCH, "pub fn syscall_entry_fast(");
        let verdict = b.find("syscall_verdict(num)").expect("no filter verdict");
        let shortcut = b.find("syscall_register_only(num)").expect("no register-only calls");
        assert!(verdict < shortcut, "the register-only calls are answered before the filter verdict");
        assert_eq!(DISPATCH.matches("syscall_register_only(num)").count(), 1,
            "syscall_register_only is called from somewhere else");
        // `syscall_dispatch_out` (aarch64 personality callers, host shims) is
        // the same two halves, filter first.
        let out = body(DISPATCH, "pub fn syscall_dispatch_out(");
        let fast = out.find("syscall_entry_fast(num)").expect("dispatch_out skips the filter");
        let checked = out.find("syscall_dispatch_checked(").expect("dispatch_out does not dispatch");
        assert!(fast < checked);
    }

    #[test]
    fn each_trap_entry_dispatches_only_what_the_filter_returned() {
        // The flow: the filter's verdict, then the prologue (tracepoint and
        // counter), and only then the call: the register-only answers
        // (`getpid`, `yield`) RUN when asked for, after the prologue.
        let b = body(FLOW, "pub fn enter<");
        let verdict = b.find("S::verdict(num)").expect("the flow does not run the filter");
        let kind = b.find("let kind = S::kind(&entry)").expect("the flow does not read the verdict");
        let matched = b.find("prologue::<S, F>(frame, num, kind)").expect("the flow has no prologue");
        let shortcut = b.find("S::shortcut(num)").expect("the flow has no register-only shortcut");
        assert!(verdict < kind && kind < matched && matched < shortcut,
            "a call is answered or dispatched before the verdict and the prologue");
        assert_eq!(b.matches("S::shortcut(num)").count(), 1, "the shortcut is asked from somewhere else too");
        // The verdict is `syscall_verdict` and nothing else, so nothing is
        // answered inside it; the shortcut is the one function that answers.
        assert_eq!(KERNEL.matches("azos_syscall::syscall_verdict(num)").count(), 1);
        assert_eq!(KERNEL.matches("azos_syscall::syscall_register_only(num)").count(), 1);
        assert!(!KERNEL.contains("syscall_entry_fast("), "the filter and the shortcut are one call again");
        // The slow half is reached with the `entry` the filter gave; the fast
        // path only for a native entry, in both places that try it.
        assert_eq!(KERNEL.matches("syscall_dispatch_checked(").count(), 1,
            "one call to syscall_dispatch_checked, inside the out-of-line slow path");
        assert!(KERNEL.contains("syscall_dispatch_checked(entry, num,"), "syscall_dispatch_checked is not handed the filter's entry");
        assert!(!KERNEL.contains("syscall_dispatch_out("), "a second, unfiltered-shape dispatch is back");
        assert!(!KERNEL.contains("dispatch_slow("), "dispatch_slow called around the filter");
        let tries = KERNEL.matches("azos_syscall::fastpath::entry(").count();
        let guarded = KERNEL.matches("azos_syscall::fastpath::wants(num) && matches!(entry, SyscallEntry::Native)").count();
        assert_eq!(tries, guarded, "the fast path is tried for an entry the filter did not call native");
        // Each ISA reaches a syscall only through the flow, never around it.
        for (name, src) in [("riscv64", RV), ("aarch64", ARM), ("x86_64", X86)] {
            assert!(src.contains("crate::trap::syscall::enter::<Kernel, TrapFrame, FAST>(frame)"),
                "{name}: the native entries do not go through the flow");
            for around in ["syscall_entry_fast(", "syscall_verdict(", "syscall_dispatch_checked(", "fastpath::entry(", "dispatch_slow("] {
                assert!(!src.contains(around), "{name}: `{around}` is called around the flow");
            }
        }
    }
}

/// **A program an applied package carries starts under the profile its own row
/// gives it, and nothing else does** (plan D14, `register_package_images`).
///
/// The boot-time apply verifies a package and merges its rows; without a
/// digest bound to those rows, `plan_spawn` answered `EACCES` for every package
/// program, so the apply wrote programs that could never run. One test, because
/// the table is registered once per process, as once per boot.
#[cfg(test)]
mod package_images {
    use crate::filter::FilterVerdict;
    use crate::seccomp::*;
    use crate::spawn_policy::plan_spawn;
    use azos_abi::syscall_nr as nr;

    #[test]
    fn a_registered_package_program_is_planned_under_its_own_row() {
        let digest = image_digest(b"a package's program");
        assert!(image_for_digest(&digest).is_none(), "nothing is bound before the apply registers it");
        assert!(plan_spawn(&digest).is_err(), "so a spawn of those bytes is refused (EACCES)");

        // The row grants an endpoint of a kernel-hosted interface.
        let key = azos_devif::by_name("entropy").expect("an interface of the registry").key;
        let ifaces: &'static [u16] = Box::leak(vec![key].into_boxed_slice());
        let shipped = IMAGE_SHA256[0].1;
        let table: &'static [PackageImage] = Box::leak(
            vec![
                PackageImage { digest, profile: package_profile("PKGAPP.ELF", ifaces) },
                // Bytes the build already binds: the shipped binding stands.
                PackageImage { digest: shipped, profile: package_profile("SHIPPED.ELF", &[]) },
            ]
            .into_boxed_slice(),
        );
        assert!(register_package_images(table), "the first registration is taken");
        assert!(!register_package_images(table), "a second one is refused: the table is bound once per boot");

        let plan = plan_spawn(&digest).expect("the package's bytes are bound to its row");
        assert_eq!(plan.profile.image, "PKGAPP.ELF");
        assert_eq!(plan.topology_key, "PKGAPP.ELF", "the capabilities are those of the package's own row");
        let f = plan.filter;
        assert!(f.enabled && !f.audit, "the package runs confined, never in audit mode");
        for n in [nr::SYS_EXIT, nr::SYS_INVOKE, nr::SYS_MO_MAP, nr::SYS_IPC_CALL_V2, nr::SYS_RING_ENTER, nr::SYS_FUTEX_WAIT] {
            assert_eq!(f.verdict(n as u16), FilterVerdict::Allow, "a service's call {n}");
        }
        for n in [nr::SYS_SPAWN_EX, nr::SYS_ALERT, nr::SYS_SCHEDCTL, nr::SYS_FOREIGN_FORK, nr::SYS_FOREIGN_ENTRY] {
            assert_eq!(f.verdict(n as u16), FilterVerdict::Deny, "call {n} starts, signals, schedules or translates");
        }
        assert!(f.iface_listed(key), "its row's endpoint is the interface it may call");
        let other = azos_devif::by_name("pwm").expect("another interface").key;
        assert!(!f.iface_listed(other), "and no interface its row does not grant");
        assert!(locked_compatible(plan.profile), "it can take a locked row: it cannot fork");

        // A byte of difference is a different program: the swap after the apply.
        let mut swapped = digest;
        swapped[0] ^= 1;
        assert!(plan_spawn(&swapped).is_err(), "bytes swapped into APPS/ after the apply are not bound");

        // The shipped table is asked first: a package cannot take a shipped image's name.
        let p = image_for_digest(&shipped).expect("a shipped image");
        assert_ne!(p.image, "SHIPPED.ELF");
    }
}

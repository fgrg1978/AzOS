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

/// `SYS_SPAWN`'s decisions (RFC-0043). It names `crate::seccomp` and
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
        assert_eq!(i.deadline_us, 0);
        assert_eq!(i.time_slice_us, 0);
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
    #[test]
    fn the_audit_byte_and_the_bitmap_moved_nothing() {
        use core::mem::{offset_of, size_of};
        assert_eq!(SYSCALL_FILTER_MAX, 96);
        assert_eq!(size_of::<SyscallFilter>(), 276);
        assert_eq!(offset_of!(SyscallFilter, enabled), 0);
        assert_eq!(offset_of!(SyscallFilter, allowed), 2);
        assert_eq!(offset_of!(SyscallFilter, count), 194);
        assert_eq!(offset_of!(SyscallFilter, audit), 195);
        assert_eq!(offset_of!(SyscallFilter, bits), 196);
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
        for id in [PROFILE_UNRESTRICTED, PROFILE_SENSOR, PROFILE_MOTOR, PROFILE_NET, PROFILE_MINIMAL] {
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
        // Not vacuous: every row, the five role profiles and the four others,
        // twice, over 65,536 + WIDE numbers each.
        let rows = IMAGE_PROFILES.len() as u64 + 5 + 4;
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
        assert_eq!(activate_profile(PROFILE_NET), 0);
        let installed = scheduler::current_syscall_filter();
        let want = profile_to_filter(PROFILE_NET).unwrap();
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
    use azos_syscall_numbers::numbers as real;

    /// Every syscall each profile is documented to grant, named by the
    /// **real** number from `crates/core/syscall/src/numbers.rs`.
    fn common() -> Vec<u16> {
        vec![
            real::SYS_EXIT, real::SYS_GETPID, real::SYS_YIELD, real::SYS_SLEEP,
            real::SYS_WRITE, real::SYS_PUTCHAR, real::SYS_BRK, real::SYS_SECCOMP,
        ].into_iter().map(|n| n as u16).collect()
    }

    fn extras(profile: u64) -> Vec<u16> {
        let v: Vec<u64> = match profile {
            PROFILE_SENSOR => vec![
                // ADC is the one untyped survivor (no typed form); the rest are
                // the typed forms only — their untyped twins are retired.
                real::SYS_ADC_READ,
                real::SYS_GPIO_READ_TYPED, real::SYS_I2C_READ_TYPED,
                real::SYS_I2C_WRITE_TYPED, real::SYS_SENSOR_READ_TYPED,
            ],
            PROFILE_MOTOR => vec![
                // MOTOR_CREATE is the one untyped survivor (no typed form).
                real::SYS_MOTOR_CREATE,
                real::SYS_GPIO_WRITE_TYPED, real::SYS_GPIO_SET_DIR_TYPED,
                real::SYS_PWM_ENABLE_TYPED, real::SYS_PWM_DISABLE_TYPED,
                real::SYS_PWM_SET_PERIOD_TYPED, real::SYS_PWM_SET_DUTY_TYPED,
                real::SYS_MOTOR_SPEED_TYPED, real::SYS_MOTOR_DIRECTION_TYPED,
                real::SYS_MOTOR_ENABLE_TYPED, real::SYS_MOTOR_SET_TARGET_TYPED,
                real::SYS_MOTOR_TICK_TYPED, real::SYS_MOTOR_SET_GAINS_TYPED,
                real::SYS_MOTOR_RESET_TYPED,
            ],
            PROFILE_NET => vec![
                real::SYS_SOCKET, real::SYS_BIND, real::SYS_LISTEN, real::SYS_ACCEPT,
                real::SYS_CONNECT, real::SYS_SEND, real::SYS_RECV,
                real::SYS_SOCK_SHUTDOWN,
                real::SYS_SOCKET_TYPED, real::SYS_CONNECT_TYPED,
                real::SYS_SEND_TYPED, real::SYS_RECV_TYPED, real::SYS_CLOSE_TYPED,
                real::SYS_MCAST_JOIN_TYPED, real::SYS_MCAST_LEAVE_TYPED,
            ],
            PROFILE_MINIMAL => vec![],
            other => panic!("no extras defined for profile {other}"),
        };
        v.into_iter().map(|n| n as u16).collect()
    }

    const RESTRICTED: [u64; 4] = [PROFILE_SENSOR, PROFILE_MOTOR, PROFILE_NET, PROFILE_MINIMAL];

    /// A profile that lets a task create a socket must let it give the socket
    /// back. `COMMON` holds no close of any kind, and `PROFILE_NET` granted
    /// `SYS_SOCKET` without `SYS_SOCK_SHUTDOWN`: a task under it that
    /// reconnected ran into `MAX_SOCKETS_PER_TASK` after eight connections and
    /// could never open another. Asserted against every profile, so the next
    /// one to grant creation cannot forget the release either.
    #[test]
    fn a_profile_that_creates_sockets_can_release_them() {
        for p in RESTRICTED {
            let f = profile_to_filter(p).unwrap();
            if f.is_allowed(real::SYS_SOCKET as u16) {
                assert!(f.is_allowed(real::SYS_SOCK_SHUTDOWN as u16),
                        "profile {p} grants SYS_SOCKET but not SYS_SOCK_SHUTDOWN");
            }
            // The typed pair has the same shape: a socket minted as a
            // capability is released through the capability, and the untyped
            // shutdown refuses it while the capability lives.
            if f.is_allowed(real::SYS_SOCKET_TYPED as u16) {
                assert!(f.is_allowed(real::SYS_CLOSE_TYPED as u16),
                        "profile {p} grants SYS_SOCKET_TYPED but not SYS_CLOSE_TYPED");
            }
        }
        assert!(profile_to_filter(PROFILE_NET).unwrap().is_allowed(real::SYS_SOCKET as u16),
                "the property above is vacuous if no profile grants SYS_SOCKET");
    }

    /// A profile that lets a task join a multicast group must let it leave
    /// one. Closing the socket also gives its groups back, but a task that has
    /// to close a socket to stop receiving one group loses the socket's other
    /// traffic with it.
    #[test]
    fn a_profile_that_joins_a_group_can_leave_it() {
        for p in RESTRICTED {
            let f = profile_to_filter(p).unwrap();
            if f.is_allowed(real::SYS_MCAST_JOIN_TYPED as u16) {
                assert!(f.is_allowed(real::SYS_MCAST_LEAVE_TYPED as u16),
                        "profile {p} grants SYS_MCAST_JOIN_TYPED but not SYS_MCAST_LEAVE_TYPED");
            }
        }
        assert!(profile_to_filter(PROFILE_NET).unwrap().is_allowed(real::SYS_MCAST_JOIN_TYPED as u16),
                "the property above is vacuous if no profile grants SYS_MCAST_JOIN_TYPED");
    }

    /// `(profile, untyped, cap-typed twin)`.
    ///
    /// The tree is migrating hardware syscalls to the cap-typed path
    /// (`*_TYPED`, 539..=557 in `crates/core/abi/src/syscall_nr.rs`). A task that
    /// migrates and *then* activates a profile would have every hardware call
    /// denied unless the profile names the typed number too. This table states
    /// the pairing by name, so removing one typed constant from `seccomp.rs`
    /// fails here and says which pair broke — not just that a count moved.
    ///
    /// `SYS_PWM_SET_FREQ` pairs with `SYS_PWM_SET_PERIOD_TYPED` because the
    /// untyped handler `sys_pwm_set_freq(ch, period_ns)` calls
    /// `pwm_set_period(ch, period_ns)` — the name says frequency, the body
    /// sets a period (`crates/core/syscall/src/handlers.rs`).
    ///
    /// After RFC-0040 gap 1 only the socket family still keeps its untyped call
    /// beside the typed one; the SENSOR/MOTOR untyped calls were retired, so
    /// their typed forms are FORMER twins — see `FORMER_TWINS`.
    const TWINS: &[(u64, u64, u64)] = &[
        (PROFILE_NET, real::SYS_CONNECT, real::SYS_CONNECT_TYPED),
        (PROFILE_NET, real::SYS_SEND, real::SYS_SEND_TYPED),
        (PROFILE_NET, real::SYS_RECV, real::SYS_RECV_TYPED),
    ];

    /// `(profile, typed, retired_untyped)`: a typed call granted as the FORMER
    /// twin of an untyped call this profile used to grant and RFC-0040 gap 1
    /// retired. The retired number must be in `RETIRED_SYSCALLS` and absent
    /// from the profile — checked by
    /// `a_former_twins_untyped_call_is_retired_and_absent`.
    const FORMER_TWINS: &[(u64, u64, u64)] = &[
        (PROFILE_SENSOR, real::SYS_SENSOR_READ_TYPED, 332),
        (PROFILE_SENSOR, real::SYS_GPIO_READ_TYPED, 200),
        (PROFILE_SENSOR, real::SYS_I2C_READ_TYPED, 220),
        (PROFILE_SENSOR, real::SYS_I2C_WRITE_TYPED, 221),
        (PROFILE_MOTOR, real::SYS_GPIO_WRITE_TYPED, 201),
        (PROFILE_MOTOR, real::SYS_GPIO_SET_DIR_TYPED, 202),
        (PROFILE_MOTOR, real::SYS_PWM_ENABLE_TYPED, 210),
        (PROFILE_MOTOR, real::SYS_PWM_DISABLE_TYPED, 211),
        (PROFILE_MOTOR, real::SYS_PWM_SET_PERIOD_TYPED, 212),
        (PROFILE_MOTOR, real::SYS_PWM_SET_DUTY_TYPED, 213),
        (PROFILE_MOTOR, real::SYS_MOTOR_SPEED_TYPED, 232),
        (PROFILE_MOTOR, real::SYS_MOTOR_DIRECTION_TYPED, 231),
    ];

    // ── THE RULE, WRITTEN ONCE (owner decision, 2026-09-08) ───────────────
    //
    // Until today the rule for putting a `Cap<T>` syscall in a profile lived
    // in two places and neither could enforce it: as prose above
    // `profile_to_filter` in `crates/core/sched/src/seccomp.rs`, and as the two
    // hand-written tables here. Both were exhaustive only because somebody
    // remembered — a typed call added to a profile appeared in neither, and
    // nothing said so.
    //
    // `TYPED_GRANTS` below is now the single answer to "this typed call is in
    // a profile; why is that allowed", and
    // `every_typed_syscall_in_a_profile_carries_a_written_reason` makes
    // forgetting it a red. The set it is checked against comes from
    // `azos_abi::syscall_nr::CAP_TYPED_SYSCALLS` rather than a number
    // range, because 558/559/562 sit in the same block and are not Cap-typed.
    //
    // It does NOT live in the kernel: nothing at runtime reads a
    // justification, and `profile_to_filter` is a readable list of constants
    // that would be worse rebuilt from a table. The kernel carries the ABI
    // fact; the audit lives with the audit.

    /// Why a Cap-typed syscall is allowed to sit in a profile.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    enum Why {
        /// Narrower twin of an untyped call **the same profile still grants**:
        /// the typed form demands a capability for a subset of the untyped
        /// one's effects, so allowing it widens nothing.
        ///
        /// The untyped number is carried so that claim is CHECKED rather than
        /// asserted — see
        /// `a_narrower_twin_is_only_narrower_if_the_untyped_call_is_there`.
        NarrowerTwin(u64),
        /// Former twin of an untyped call RFC-0040 gap 1 RETIRED. The untyped
        /// call is gone from the profile (it is in `RETIRED_SYSCALLS`), so the
        /// typed form is the only way to reach the operation — and it was
        /// always the narrower one. The retired number is carried so
        /// `a_former_twins_untyped_call_is_retired_and_absent` can check it.
        FormerTwin(u64),
        /// No untyped counterpart at all, so neither twin argument reaches it.
        /// A deliberate grant, with the reason recorded.
        OwnerGranted(&'static str),
    }

    /// Every Cap-typed syscall any profile grants, and why.
    ///
    /// Derived from `TWINS` and `GRANTED_WITHOUT_AN_UNTYPED_TWIN` — the two
    /// were the same axis ("this typed call is in a profile, here is why")
    /// split by which argument justified it, which is what the `Why` variant
    /// now says. `DENIED_EVERYWHERE` stays separate: it is the other axis,
    /// typed calls in NO profile, and merging it would be over-unification.
    const TYPED_GRANTS: &[(u64, u64, Why)] = &[
        (PROFILE_SENSOR, real::SYS_SENSOR_READ_TYPED, Why::FormerTwin(332)),
        (PROFILE_SENSOR, real::SYS_GPIO_READ_TYPED, Why::FormerTwin(200)),
        (PROFILE_SENSOR, real::SYS_I2C_READ_TYPED, Why::FormerTwin(220)),
        (PROFILE_SENSOR, real::SYS_I2C_WRITE_TYPED, Why::FormerTwin(221)),
        (PROFILE_MOTOR, real::SYS_GPIO_WRITE_TYPED, Why::FormerTwin(201)),
        (PROFILE_MOTOR, real::SYS_GPIO_SET_DIR_TYPED, Why::FormerTwin(202)),
        (PROFILE_MOTOR, real::SYS_PWM_ENABLE_TYPED, Why::FormerTwin(210)),
        (PROFILE_MOTOR, real::SYS_PWM_DISABLE_TYPED, Why::FormerTwin(211)),
        (PROFILE_MOTOR, real::SYS_PWM_SET_PERIOD_TYPED, Why::FormerTwin(212)),
        (PROFILE_MOTOR, real::SYS_PWM_SET_DUTY_TYPED, Why::FormerTwin(213)),
        (PROFILE_MOTOR, real::SYS_MOTOR_SPEED_TYPED, Why::FormerTwin(232)),
        (PROFILE_MOTOR, real::SYS_MOTOR_DIRECTION_TYPED,
         Why::FormerTwin(231)),
        // FOUND BY THE TRIPWIRE ON ITS FIRST RUN, 2026-09-08. 550 was granted
        // to MOTOR and classified nowhere: it used to sit in `TWINS` paired
        // with `SYS_MOTOR_SPEED`, that pairing was deleted on 2026-09-07 for
        // being false — `SET_TARGET` asks the PID loop to aim for a value,
        // `MOTOR_SPEED` drives a wheel now, disjoint surfaces — and while
        // `SYS_MOTOR_ENABLE_TYPED` was moved across in the same edit, this
        // one was simply dropped. It stayed in the filter, unjustified, for a
        // day, which is precisely the failure the rule exists to make loud.
        (PROFILE_MOTOR, real::SYS_MOTOR_SET_TARGET_TYPED,
         Why::OwnerGranted("setting the PID loop's target; part of the same \
             PID-family grant as TICK/SET_GAINS/RESET (owner, 2026-09-07). \
             Still needs WRITE on both wheels")),
        (PROFILE_MOTOR, real::SYS_MOTOR_TICK_TYPED,
         Why::OwnerGranted("running the PID loop; still needs WRITE on both wheels")),
        (PROFILE_MOTOR, real::SYS_MOTOR_SET_GAINS_TYPED,
         Why::OwnerGranted("tuning the PID loop; still needs WRITE on both wheels")),
        (PROFILE_MOTOR, real::SYS_MOTOR_RESET_TYPED,
         Why::OwnerGranted("clearing PID state; still needs WRITE on both wheels")),
        (PROFILE_MOTOR, real::SYS_MOTOR_ENABLE_TYPED,
         Why::OwnerGranted("arming/disarming the PID loop. NOT a twin of \
             SYS_MOTOR_ENABLE, which sets DIRECTION at a fixed 50% speed — \
             same name, unrelated operation")),
        // Cap<Socket>, granted to NET by owner decision 2026-09-13.
        (PROFILE_NET, real::SYS_CONNECT_TYPED, Why::NarrowerTwin(real::SYS_CONNECT)),
        (PROFILE_NET, real::SYS_SEND_TYPED, Why::NarrowerTwin(real::SYS_SEND)),
        (PROFILE_NET, real::SYS_RECV_TYPED, Why::NarrowerTwin(real::SYS_RECV)),
        (PROFILE_NET, real::SYS_SOCKET_TYPED,
         Why::OwnerGranted("mints a Cap<Socket> for a socket this profile could \
             already create with SYS_SOCKET, charged to the same per-task quota \
             (owner, 2026-09-13)")),
        (PROFILE_NET, real::SYS_CLOSE_TYPED,
         Why::OwnerGranted("releases what SYS_SOCKET_TYPED minted; without it \
             the profile could create typed sockets and never give them back. \
             It closes files too, but nothing under this profile can mint a \
             Cap<File> (owner, 2026-09-13)")),
        (PROFILE_NET, real::SYS_MCAST_JOIN_TYPED,
         Why::OwnerGranted("multicast from ring 3 as two typed calls on Cap<Socket> \
             (owner decision 2026-09-13)")),
        (PROFILE_NET, real::SYS_MCAST_LEAVE_TYPED,
         Why::OwnerGranted("multicast from ring 3 as two typed calls on Cap<Socket> \
             (owner decision 2026-09-13)")),
    ];

    /// **The tripwire.** Every Cap-typed syscall a profile grants must appear
    /// in `TYPED_GRANTS`.
    ///
    /// This is the piece that did not exist. `TWINS` and
    /// `GRANTED_WITHOUT_AN_UNTYPED_TWIN` proved things about the calls they
    /// listed, and said nothing about one that was added to a profile and
    /// listed nowhere. The membership set comes from the ABI
    /// (`CAP_TYPED_SYSCALLS`), so a typed call added there and dropped into a
    /// profile cannot slip past by not being thought of.
    #[test]
    fn every_typed_syscall_in_a_profile_carries_a_written_reason() {
        let mut checked = 0usize;
        for p in RESTRICTED {
            let f = profile_to_filter(p).expect("known profile");
            for &n in azos_abi::syscall_nr::CAP_TYPED_SYSCALLS {
                if !f.is_allowed(n as u16) { continue; }
                checked += 1;
                assert!(
                    TYPED_GRANTS.iter().any(|&(pp, nn, _)| pp == p && nn == n),
                    "profile {p} grants Cap-typed syscall {n} with no entry in \
                     TYPED_GRANTS. Every typed grant needs a written reason: \
                     either it is the narrower twin of an untyped call this \
                     profile already allows, or it is an owner decision. Say \
                     which.",
                );
            }
        }
        assert!(checked >= 15, "only {checked} typed grants seen — the set or \
                the profiles shrank, and this test would pass on an empty one");
    }

    /// And the reverse: a row in `TYPED_GRANTS` must describe a real grant.
    ///
    /// Without this the table could rot into a list of aspirations — entries
    /// for calls no profile actually allows, which read as documented policy
    /// and constrain nothing.
    #[test]
    fn every_written_reason_describes_a_grant_that_exists() {
        for &(p, n, why) in TYPED_GRANTS {
            let f = profile_to_filter(p).expect("known profile");
            assert!(
                f.is_allowed(n as u16),
                "TYPED_GRANTS claims profile {p} grants {n} ({why:?}), it does not",
            );
        }
    }

    /// **A narrower twin is only narrower if the untyped call is there.**
    ///
    /// "The typed form grants nothing new" holds *because* the profile already
    /// allows the untyped one. Drop the untyped entry and the same typed call
    /// becomes a real widening — with its justification still reading as
    /// though it were free. This turns that prose argument into arithmetic.
    #[test]
    fn a_narrower_twin_is_only_narrower_if_the_untyped_call_is_there() {
        for &(p, typed, why) in TYPED_GRANTS {
            let Why::NarrowerTwin(untyped) = why else { continue };
            let f = profile_to_filter(p).expect("known profile");
            assert!(
                f.is_allowed(untyped as u16),
                "profile {p} grants typed {typed} as the narrower twin of \
                 {untyped}, but does NOT grant {untyped}. The no-new-authority \
                 argument does not apply: reclassify it as an owner decision \
                 or grant the untyped call.",
            );
        }
    }

    /// **A former twin's untyped call is retired and gone.** The typed form is
    /// granted BECAUSE the untyped one was retired in RFC-0040 gap 1: the
    /// number must be in `RETIRED_SYSCALLS`, and the profile must NOT grant it
    /// (it cannot — the constant is deleted). Without the second half a
    /// "former twin" reason could hide a profile that still granted the retired
    /// call.
    #[test]
    fn a_former_twins_untyped_call_is_retired_and_absent() {
        use azos_abi::syscall_nr::RETIRED_SYSCALLS;
        let mut checked = 0usize;
        for &(p, typed, why) in TYPED_GRANTS {
            let Why::FormerTwin(untyped) = why else { continue };
            checked += 1;
            assert!(
                RETIRED_SYSCALLS.contains(&untyped),
                "TYPED_GRANTS calls {typed} a former twin of {untyped}, which is \
                 not in RETIRED_SYSCALLS",
            );
            let f = profile_to_filter(p).expect("known profile");
            assert!(f.is_allowed(typed as u16), "profile {p} does not grant {typed}");
            assert!(
                !f.is_allowed(untyped as u16),
                "profile {p} still grants the retired untyped call {untyped}",
            );
        }
        assert!(checked >= 12, "only {checked} former twins seen");
        // FORMER_TWINS mirrors the FormerTwin rows above, kept as the readable
        // (profile, typed, retired) table; assert the two agree so neither
        // rots.
        for &(p, typed, retired) in FORMER_TWINS {
            assert!(
                TYPED_GRANTS.iter().any(|&(pp, tt, why)| pp == p && tt == typed
                    && matches!(why, Why::FormerTwin(r) if r == retired)),
                "FORMER_TWINS row ({p}, {typed}, {retired}) has no matching TYPED_GRANTS FormerTwin",
            );
        }
    }

    /// **No profile — role or image — grants a retired number.** The whole
    /// point of the retirement: a number in `RETIRED_SYSCALLS` is reachable
    /// from no confined task.
    #[test]
    fn no_profile_grants_a_retired_number() {
        use azos_abi::syscall_nr::RETIRED_SYSCALLS;
        for &n in RETIRED_SYSCALLS {
            if n > u16::MAX as u64 { continue; }
            let n = n as u16;
            for p in RESTRICTED {
                assert!(
                    !profile_to_filter(p).expect("known profile").is_allowed(n),
                    "role profile {p} grants retired number {n}",
                );
            }
            for ip in IMAGE_PROFILES {
                assert!(
                    !image_filter(ip).is_allowed(n),
                    "image profile {} grants retired number {n}", ip.image,
                );
            }
        }
    }

    /// RFC-0055 (wave 11): console input has ONE reader by authority as well
    /// as by the kernel's owner claim. `SYS_CONSOLE_WAIT` (609) is in the
    /// shell's profile and in no other, so no tool, driver or test image can
    /// even ask for console bytes; `SYS_SPAWN_EX` (608) and `SYS_TASK_KILL`
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
    /// descendants (the same ancestry `SYS_TASK_KILL` checks).
    ///
    /// **Canary.** Add `SYS_CONSOLE_WAIT` to `TOOLBOX.ELF`'s row: red, naming
    /// it.
    #[test]
    fn only_the_shell_profile_lists_the_shell_calls() {
        use azos_abi::syscall_nr::{SYS_CONSOLE_WAIT, SYS_SPAWN_EX, SYS_TASK_KILL};
        for n in [SYS_CONSOLE_WAIT, SYS_SPAWN_EX, SYS_TASK_KILL] {
            let holders: &[&str] =
                if n == SYS_SPAWN_EX { &["SH.ELF", "VSBENCH.ELF"] } else { &["SH.ELF", "LXHELLO.ELF"] };
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

    /// RFC-0055 S5: the power family's typed call is `POWER.ELF`'s alone, and
    /// that profile has neither the untyped power calls nor any shell call.
    ///
    /// **Canary.** Add `SYS_POWER_TYPED` to `SH.ELF`'s row: red, naming it.
    #[test]
    fn only_the_power_tool_lists_the_power_call() {
        use azos_abi::syscall_nr as nr;
        let n = nr::SYS_POWER_TYPED as u16;
        for ip in IMAGE_PROFILES {
            assert_eq!(image_filter(ip).is_allowed(n), ip.image == "POWER.ELF",
                       "image profile {} and syscall {n}: only POWER.ELF may list it", ip.image);
        }
        for p in RESTRICTED {
            assert!(!profile_to_filter(p).expect("known profile").is_allowed(n),
                    "role profile {p} grants the power call");
        }
        let pw = IMAGE_PROFILES.iter().find(|p| p.image == "POWER.ELF").expect("POWER.ELF row");
        let f = image_filter(pw);
        for m in [nr::SYS_SHUTDOWN, nr::SYS_REBOOT, nr::SYS_CONSOLE_WAIT, nr::SYS_SPAWN_EX,
                  nr::SYS_TASK_KILL, nr::SYS_FORK, nr::SYS_SPAWN, nr::SYS_FILE_OPEN_TYPED] {
            assert!(!f.is_allowed(m as u16), "POWER.ELF lists {m}");
        }
        assert!(!pw.audit, "the power tool's row is enforcing, not audit");
    }

    /// Wave 12: each family's typed call is its tool's alone, and the four
    /// tools hold no other privileged or exec call.
    ///
    /// **Canary.** Add `SYS_OTA_TYPED` to `CONFIG.ELF`'s row: red, naming it.
    #[test]
    fn each_family_call_is_its_tools_alone() {
        use azos_abi::syscall_nr as nr;
        let fams = [("FLIGHT.ELF", nr::SYS_FLIGHT_TYPED), ("BEHAVIOR.ELF", nr::SYS_BEHAVIOR_TYPED),
                    ("CONFIG.ELF", nr::SYS_CONFIG_TYPED), ("OTA.ELF", nr::SYS_OTA_TYPED)];
        for (img, n) in fams {
            let n = n as u16;
            for ip in IMAGE_PROFILES {
                assert_eq!(image_filter(ip).is_allowed(n), ip.image == img,
                           "image profile {} and syscall {n}: only {img} may list it", ip.image);
            }
            for p in RESTRICTED {
                assert!(!profile_to_filter(p).expect("known profile").is_allowed(n),
                        "role profile {p} grants family call {n}");
            }
            let row = IMAGE_PROFILES.iter().find(|p| p.image == img).expect("tool row");
            let f = image_filter(row);
            for m in [nr::SYS_POWER_TYPED, nr::SYS_SHUTDOWN, nr::SYS_REBOOT, nr::SYS_CONSOLE_WAIT,
                      nr::SYS_SPAWN_EX, nr::SYS_TASK_KILL, nr::SYS_FORK, nr::SYS_SPAWN,
                      nr::SYS_FILE_OPEN_TYPED, nr::SYS_MOTOR_SET_TARGET_TYPED] {
                assert!(!f.is_allowed(m as u16), "{img} lists {m}");
            }
            assert!(!row.audit, "{img}'s row is enforcing, not audit");
        }
    }

    /// RFC-0053 L0b: the module pair (630/631) is `LXSRV.ELF`'s alone, and
    /// the Linux server's profile holds no actuator, device, fork/exec,
    /// capability-lookup or untyped power call: a Linux server never holds an
    /// actuator (RFC-0053 3), by profile as well as by topology row.
    ///
    /// **Canary.** Add `SYS_MODULE_MAP_X` to `TOOLBOX.ELF`'s row, or
    /// `SYS_GPIO_WRITE_TYPED` to `LXSRV.ELF`'s: red, naming it.
    #[test]
    fn only_the_linux_server_lists_the_module_calls() {
        use azos_abi::syscall_nr as nr;
        for n in [nr::SYS_MODULE_VERIFY as u16, nr::SYS_MODULE_MAP_X as u16] {
            for ip in IMAGE_PROFILES {
                assert_eq!(image_filter(ip).is_allowed(n), ip.image == "LXSRV.ELF",
                           "image profile {} and syscall {n}: only LXSRV.ELF may list it", ip.image);
            }
            for p in RESTRICTED {
                assert!(!profile_to_filter(p).expect("known profile").is_allowed(n),
                        "role profile {p} grants module call {n}");
            }
        }
        let lx = IMAGE_PROFILES.iter().find(|p| p.image == "LXSRV.ELF").expect("LXSRV.ELF row");
        let f = image_filter(lx);
        for m in [
            nr::SYS_FORK, nr::SYS_EXEC, nr::SYS_EXECPATH, nr::SYS_SPAWN, nr::SYS_SPAWN_EX,
            nr::SYS_CAP_LOOKUP, nr::SYS_SHUTDOWN, nr::SYS_REBOOT, nr::SYS_POWER_TYPED,
            nr::SYS_GPIO_WRITE_TYPED, nr::SYS_PWM_ENABLE_TYPED, nr::SYS_I2C_WRITE_TYPED,
            nr::SYS_MOTOR_SET_TARGET_TYPED, nr::SYS_MOTOR_MOVE_TYPED, nr::SYS_DISK_WRITE,
            nr::SYS_MOUNT, nr::SYS_SECCOMP,
        ] {
            assert!(!f.is_allowed(m as u16), "LXSRV.ELF lists {m}");
        }
        assert!(!lx.audit, "the Linux server's row is enforcing, not audit");
    }

    /// RFC-0055: the shell holds no hardware authority by profile either —
    /// no device, network, power, fork/exec or raw console call.
    #[test]
    fn the_shell_profile_has_no_hardware_power_or_exec_call() {
        use azos_abi::syscall_nr as nr;
        let sh = IMAGE_PROFILES.iter().find(|p| p.image == "SH.ELF").expect("SH.ELF row");
        let f = image_filter(sh);
        for n in [
            nr::SYS_FORK, nr::SYS_EXEC, nr::SYS_EXECPATH, nr::SYS_SPAWN, nr::SYS_GETCHAR,
            nr::SYS_PUTCHAR, nr::SYS_SECCOMP, nr::SYS_SHUTDOWN, nr::SYS_REBOOT, nr::SYS_MOUNT,
            nr::SYS_GPIO_WRITE_TYPED, nr::SYS_PWM_ENABLE_TYPED, nr::SYS_I2C_WRITE_TYPED,
            nr::SYS_MOTOR_SET_TARGET_TYPED, nr::SYS_SOCKET_TYPED, nr::SYS_DISK_WRITE,
            nr::SYS_POWER_TYPED, nr::SYS_FLIGHT_TYPED, nr::SYS_BEHAVIOR_TYPED,
            nr::SYS_CONFIG_TYPED, nr::SYS_OTA_TYPED,
        ] {
            assert!(!f.is_allowed(n as u16), "SH.ELF lists {n}");
        }
        assert!(!sh.audit, "the shell's row is enforcing, not audit");
    }

    // ── Two rows that were here and were WRONG, removed 2026-09-07 ────────
    //
    // `(SYS_MOTOR_SPEED, SYS_MOTOR_SET_TARGET_TYPED)` and
    // `(SYS_MOTOR_ENABLE, SYS_MOTOR_ENABLE_TYPED)` both paired an untyped
    // motor call with a typed one that does a DIFFERENT THING. The untyped
    // family (230-234) actuates a single wheel through
    // `azos_robot::motor_set`; the typed family (550-555) writes shared
    // PID state that `rt_motor_task` consumes. They are disjoint surfaces,
    // not two versions of one API.
    //
    //   · `SYS_MOTOR_SPEED(id, pct)` drives a wheel now.
    //     `SYS_MOTOR_SET_TARGET_TYPED(cap, l, r)` calls
    //     `motor_pid_set_target` — it asks the loop to aim for a value.
    //   · `SYS_MOTOR_ENABLE(id, dir)` sets direction at a fixed 50% speed
    //     (`handlers.rs`, `motor_set(id, d, 50)`).
    //     `SYS_MOTOR_ENABLE_TYPED(cap, on)` calls `motor_pid_enable`.
    //     Same name, unrelated operations — the pairing a reader makes by
    //     eye, and the one this table used to assert.
    //
    // Why it matters beyond tidiness: a row here is a claim that the typed
    // call is the NARROWER form of the untyped one, which is the whole
    // argument for granting it in the same profile. Applied to a pair that is
    // not a pair, the argument covers nothing.
    //
    // `SYS_MOTOR_SPEED_TYPED` (560) was added the same day precisely so that
    // 232 has a real twin: one wheel, WRITE, the same `motor_set` call.
    // `SYS_MOTOR_ENABLE_TYPED` now sits in
    // `GRANTED_WITHOUT_AN_UNTYPED_TWIN` with the other PID calls, where its
    // grant is deliberate rather than argued from a twin it does not have.

    /// Typed syscalls no profile grants, and the reason each is out.
    ///
    /// This is the half with teeth. The twin test above passes against a
    /// filter that allows everything; this one does not. Every entry is a
    /// typed call whose untyped counterpart is *absent* from the profile that
    /// would otherwise be its home, so allowing it would be a real widening.
    const DENIED_EVERYWHERE: &[(u64, &str)] = &[
        (real::SYS_I2C_DETECT_TYPED,
         "no untyped twin in SENSOR — the analogue is SYS_I2C_SCAN (222), \
          which SENSOR does not grant"),
        (real::SYS_PWM_SET_DUTY_PCT_TYPED, "no untyped counterpart at all"),
        // TICK / SET_GAINS / RESET moved OUT of this table on 2026-09-07:
        // granted to PROFILE_MOTOR by owner decision, deliberately and
        // without a no-new-authority argument, because a motor task that
        // cannot tick the PID loop is not a motor task. They are now covered
        // by `GRANTED_WITHOUT_AN_UNTYPED_TWIN` below, which asserts BOTH that
        // MOTOR has them and that no other profile does — a stronger claim
        // than simply deleting the rows.
        (real::SYS_MOTOR_ENABLED_TYPED, "no untyped counterpart in MOTOR"),
        (real::SYS_DRIVER_REGISTER_TYPED,
         "SYS_DRIVER_REGISTER is in no profile either"),
        (real::SYS_DRIVER_UNREGISTER_TYPED,
         "SYS_DRIVER_UNREGISTER is in no profile either"),
        (real::SYS_CAP_LOOKUP,
         "task-initiated discovery. Seccomp is one-way (activate_profile \
          returns SECCOMP_E_ALREADY once a filter is on), so the pattern is \
          look up your handles FIRST and sandbox yourself AFTER. Putting it \
          in COMMON would widen every profile including MINIMAL"),
        (real::SYS_CHAN_WRITE_TYPED, "no profile grants channels, typed or not"),
        (real::SYS_SHM_CREATE_TYPED, "no profile grants shared memory"),
    ];

    /// Every profile that grants an untyped hardware call must also grant its
    /// cap-typed twin, or a task that migrates to the typed path and then
    /// sandboxes itself loses the hardware it was profiled for.
    #[test]
    fn every_profile_grants_the_typed_twin_of_what_it_already_allows() {
        for &(p, untyped, typed) in TWINS {
            let f = profile_to_filter(p).expect("known profile");
            assert!(
                f.is_allowed(untyped as u16),
                "profile {p} no longer grants untyped {untyped} — this table is stale",
            );
            assert!(
                f.is_allowed(typed as u16),
                "profile {p} grants untyped {untyped} but not its cap-typed twin \
                 {typed}. A task on the typed path would have this call denied. \
                 The typed form is NARROWER (it needs a Cap<T> the task already \
                 holds), so adding it is not a widening.",
            );
        }
    }

    /// The other half: a typed call whose untyped counterpart is not in the
    /// profile stays DENIED. Without this, "the typed one is allowed" passes
    /// against a filter that allows everything.
    #[test]
    fn no_profile_grants_a_typed_call_with_no_untyped_twin() {
        for p in RESTRICTED {
            let f = profile_to_filter(p).expect("known profile");
            for &(n, why) in DENIED_EVERYWHERE {
                assert!(
                    !f.is_allowed(n as u16),
                    "profile {p} grants typed syscall {n}, which no profile should: {why}",
                );
            }
        }
    }

    /// The typed calls granted WITHOUT an untyped twin: which profile, and why.
    ///
    /// Every other entry in a profile is defended by "the typed form is
    /// narrower than the untyped one already granted, so this widens nothing".
    /// These three have no untyped form, so that argument does not reach them
    /// and they are a deliberate grant. Listing them separately is what stops
    /// "deliberate" from becoming "unnoticed".
    /// The typed calls granted WITHOUT an untyped twin: which profile, and why.
    ///
    /// **Derived from `TYPED_GRANTS`, not written twice.** This used to be its
    /// own hand-kept list; keeping both would have made the consolidation
    /// above pointless. The tests below still read as they did.
    fn granted_without_an_untyped_twin() -> Vec<(u64, u64, &'static str)> {
        TYPED_GRANTS.iter().filter_map(|&(p, n, why)| match why {
            Why::OwnerGranted(reason) => Some((p, n, reason)),
            Why::NarrowerTwin(_) | Why::FormerTwin(_) => None,
        }).collect()
    }

    /// Each deliberate grant reaches exactly the profile it was granted to.
    ///
    /// **The negative half carries the weight.** Asserting only that MOTOR has
    /// them passes against a filter that allows everything; asserting that
    /// SENSOR and NET do not is what makes this a test of the grant rather
    /// than of the constant.
    #[test]
    fn a_grant_without_an_untyped_twin_reaches_only_its_own_profile() {
        for (owner, n, why) in granted_without_an_untyped_twin() {
            let f = profile_to_filter(owner).expect("known profile");
            assert!(
                f.is_allowed(n as u16),
                "profile {owner} must grant {n}: {why}",
            );
            for p in RESTRICTED {
                if p == owner { continue; }
                assert!(
                    !profile_to_filter(p).expect("known profile").is_allowed(n as u16),
                    "profile {p} grants {n}, which was granted only to {owner}",
                );
            }
        }
    }

    /// A typed twin belongs only to the profile that grants its untyped form.
    /// SENSOR must not reach the motor typed calls, and MOTOR must not reach
    /// the sensor ones — the same separation the untyped numbers get.
    #[test]
    fn a_typed_twin_does_not_leak_into_another_profile() {
        for &(owner, _untyped, typed) in TWINS {
            for p in RESTRICTED {
                if p == owner {
                    continue;
                }
                let f = profile_to_filter(p).expect("known profile");
                assert!(
                    !f.is_allowed(typed as u16),
                    "profile {p} grants typed syscall {typed}, which belongs to \
                     profile {owner}",
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
            for n in extras(p) {
                assert!(f.is_allowed(n), "profile {p} must grant its own syscall {n}");
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
            let expected = common().len() + extras(p).len();
            assert_eq!(
                f.count as usize, expected,
                "profile {p} grants {} syscalls, expected exactly {expected}",
                f.count,
            );
            assert!(f.enabled, "a restricted profile must have the filter ON");
        }
    }

    /// Cross-profile separation, stated as the thing an operator cares about:
    /// the sensor task must not be able to drive a motor, and the net task
    /// must not be able to touch GPIO.
    ///
    /// (`SENSOR` grants bus-wide `SYS_I2C_WRITE`, so this is about the
    /// *syscall* boundary only — the module header is explicit that an
    /// I2C-attached motor controller is reachable through it. That caveat is
    /// why this test names the PWM/motor calls rather than claiming "no
    /// motors".)
    #[test]
    fn profiles_do_not_grant_each_others_hardware() {
        let sensor = profile_to_filter(PROFILE_SENSOR).unwrap();
        for n in extras(PROFILE_MOTOR) {
            assert!(!sensor.is_allowed(n), "SENSOR must not grant motor syscall {n}");
        }
        let motor = profile_to_filter(PROFILE_MOTOR).unwrap();
        for n in extras(PROFILE_NET) {
            assert!(!motor.is_allowed(n), "MOTOR must not grant net syscall {n}");
        }
        let net = profile_to_filter(PROFILE_NET).unwrap();
        for n in extras(PROFILE_SENSOR) {
            assert!(!net.is_allowed(n), "NET must not grant sensor syscall {n}");
        }
        let minimal = profile_to_filter(PROFILE_MINIMAL).unwrap();
        for p in [PROFILE_SENSOR, PROFILE_MOTOR, PROFILE_NET] {
            for n in extras(p) {
                assert!(!minimal.is_allowed(n), "MINIMAL must not grant {n}");
            }
        }
    }

    /// `allow()` drops entries past `SYSCALL_FILTER_MAX` **silently**. The
    /// failure mode is a syscall quietly missing from a whitelist, which
    /// presents as a working task that fails at the one call it needed —
    /// on the board, not here. Assert the headroom so growth trips here.
    ///
    /// **The ceiling moved from 32 to 64 on 2026-09-07 (owner decision), and
    /// the reason was this test.** MOTOR sat at 25 of 32, and the three typed
    /// motor calls with no untyped twin — the ones a migrated drivetrain
    /// cannot run without — would have taken it to 28, leaving four slots for
    /// every remaining family. Rationing a security filter by an array bound
    /// is how policy ends up shaped by the wrong thing. MOTOR is now 8 + 20 =
    /// 28 of 64.
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
        assert!(f.is_allowed(real::SYS_MOTOR_CREATE as u16));
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
        assert_eq!(activate_profile(PROFILE_SENSOR), 0);
        let f = scheduler::current_syscall_filter();
        assert!(f.enabled);
        assert!(f.is_allowed(real::SYS_SENSOR_READ_TYPED as u16));
        assert!(!f.is_allowed(real::SYS_MOTOR_SPEED_TYPED as u16));
    }

    /// The one-way property: a confined task cannot widen its own sandbox,
    /// which matters because `SYS_SECCOMP` is in COMMON — every restricted
    /// profile can call this again.
    #[test]
    fn a_filter_cannot_be_replaced_or_removed() {
        let _g = fresh();
        assert_eq!(activate_profile(PROFILE_MINIMAL), 0);
        assert_eq!(
            activate_profile(PROFILE_UNRESTRICTED), SECCOMP_E_ALREADY,
            "a confined task must not be able to ask for no sandbox",
        );
        assert_eq!(
            activate_profile(PROFILE_MOTOR), SECCOMP_E_ALREADY,
            "nor to swap in a different one",
        );
        let f = scheduler::current_syscall_filter();
        assert!(!f.is_allowed(real::SYS_MOTOR_SPEED_TYPED as u16), "MINIMAL still in force");
    }

    /// The unknown-id check runs before anything is installed: a request the
    /// kernel could not honour must leave the task exactly as it was.
    #[test]
    fn an_unknown_id_installs_nothing_and_says_so() {
        let _g = fresh();
        assert_eq!(activate_profile(7), SECCOMP_E_BADPROFILE);
        assert!(!scheduler::current_syscall_filter().enabled, "nothing was installed");
        // And the gate was not burned: a real profile still applies.
        assert_eq!(activate_profile(PROFILE_NET), 0);
        assert!(scheduler::current_syscall_filter().is_allowed(real::SYS_SOCKET as u16));
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
        assert_eq!(activate_profile(PROFILE_MOTOR), 0, "the gate was not burned");
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
        assert_eq!(f.verdict(real::SYS_WRITE as u16), FilterVerdict::Allow);
        assert_eq!(
            f.verdict(real::SYS_GETPID as u16),
            FilterVerdict::Deny,
            "getpid is outside UHELLO.ELF's profile: uhello issues it to see it refused",
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
        assert_eq!(f.verdict(real::SYS_CAP_LOOKUP as u16), FilterVerdict::Allow);
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
            f.verdict(real::SYS_FORK as u16),
            FilterVerdict::Deny,
            "ABITEST.ELF's wider profile must not replace MINIMAL",
        );
        assert!(!f.audit, "nor switch MINIMAL to audit mode");
    }

    // ── Spawn: the child's filter (RFC-0043, owner decision 59) ─────────

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
        assert_eq!(f.verdict(real::SYS_WRITE as u16), FilterVerdict::Allow);

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

    const MAKEFILE: &str = include_str!("../../../../Makefile");
    const SYSCALL_NR: &str = include_str!("../../../../crates/core/abi/src/syscall_nr.rs");
    const LIBSYS: &[&str] = &[
        include_str!("../../../../crates/core/libsys/src/lib.rs"),
        include_str!("../../../../crates/core/libsys/src/pure.rs"),
    ];
    const DISPATCH: &str = include_str!("../../../../crates/core/syscall/src/dispatch.rs");
    const HANDLERS: &str = include_str!("../../../../crates/core/syscall/src/handlers.rs");

    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    enum Lang {
        Asm,
        Rust,
        /// RFC-0047: a static Linux binary from C. It issues LINUX numbers
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
        ("SYSTEST.ELF", Lang::Asm, &[src!("userspace/tests/syscall_test/test.S")]),
        ("GPIODRV.ELF", Lang::Rust, &[src!("userspace/drivers/gpio_drv/src/main.rs")]),
        ("MLSRV.ELF", Lang::Rust, &[src!("userspace/services/mlsrv/src/main.rs")]),
        ("UHELLO.ELF", Lang::Rust, &[src!("userspace/tests/uhello/src/main.rs")]),
        ("EPSRV.ELF", Lang::Rust, &[src!("userspace/tests/epsrv/src/main.rs")]),
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
            // The RFC-0019 client session (wave 9, P3).
            src!("userspace/services/brain_client/src/link.rs"),
            // Pulled in with `#[path]` (brain-link handshake envelope).
            src!("domains/robot/behavior/src/auth_envelope_core.rs"),
        ]),
        ("CAPTEST.ELF", Lang::Rust, &[src!("userspace/tests/captest/src/main.rs"), src!("userspace/tests/captest/src/stream.rs")]),
        ("LATBENCH.ELF", Lang::Rust, &[src!("userspace/bench/latbench/src/main.rs")]),
        ("ABITEST.ELF", Lang::Rust, &[src!("userspace/tests/abitest/src/main.rs")]),
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
            // The chip logic, a crate of its own since wave 11 DRVPLACE
            // (shared with the kernel host): no syscalls.
            src!("crates/drivers/ina219/src/lib.rs"),
            src!("crates/drivers/ina219/src/chip.rs"),
        ]),
        // RFC-0055 (wave 11): the user shell. Its modules other than
        // `main.rs` are pure (no syscalls), listed so a call added to one of
        // them is still derived.
        ("SH.ELF", Lang::Rust, &[
            src!("userspace/services/sh/src/main.rs"),
            src!("userspace/services/sh/src/edit.rs"),
            src!("userspace/services/sh/src/parse.rs"),
            src!("userspace/services/sh/src/path.rs"),
            src!("userspace/services/sh/src/req.rs"),
        ]),
        ("TOOLBOX.ELF", Lang::Rust, &[src!("userspace/services/toolbox/src/main.rs")]),
        ("POWER.ELF", Lang::Rust, &[src!("userspace/services/power/src/main.rs")]),
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
        // RFC-0053 L0b: the Linux driver server skeleton.
        ("LXSRV.ELF", Lang::Rust, &[src!("userspace/services/lxsrv/src/main.rs")]),
        // RFC-0047 (wave 12): the Linux personality's test binary.
        ("LXHELLO.ELF", Lang::LinuxC, &[src!("userspace/tests/lxhello/lxhello.c")]),
    ];

    /// Modules a binary declares that its image does not compile.
    const MODULES_NOT_IN_THE_IMAGE: &[(&str, &str, &str)] = &[
        ("VSBENCH.ELF", "abi_linux", "`#[cfg(feature = \"linux\")]`; the image is the azos build"),
    ];

    /// Syscalls a binary's source names that the binary never issues.
    ///
    /// Static derivation cannot see that a wrapper refuses its argument before
    /// the `ecall`. Each row is left OUT of the profile, with the reason. The
    /// check each call sits in asserts exactly `E_INVAL`, which libsys
    /// documents the kernel never returns on its own — so if the call did
    /// reach the kernel, abitest would already be failing on that line.
    const NEVER_ISSUED: &[(&str, &str, &str)] = &[
        ("ABITEST.ELF", "SYS_MKDIR",
         "one call, `mkdir(b\"/nope\")`: unterminated path, refused by `has_nul` in the wrapper"),
        ("ABITEST.ELF", "SYS_DISK_READ",
         "two calls, 16 and 600 byte buffers: not a whole number of sectors, refused in the wrapper"),
        ("ABITEST.ELF", "SYS_DISK_WRITE",
         "one call, an empty buffer: zero sectors, refused in the wrapper"),
    ];

    /// Calls a binary issues ON PURPOSE to see the FILTER refuse them. Named in
    /// its source, left out of its profile, and asserted refused.
    const REFUSAL_PROBES: &[(&str, &str, &str)] = &[
        ("UHELLO.ELF", "SYS_GETPID",
         "the runtime proof that a call outside a profile is refused: getpid answers a \
          positive tid unfiltered and -1 filtered; `userspace: minimal Rust ELF` asserts it"),
    ];

    /// Numbers a binary issues raw, on purpose, to watch the DISPATCHER refuse
    /// them; no `SYS_*` constant names them. Left out of the row, whose audit
    /// mode lets them through to the arm under test and records them
    /// (`SAFETY_SECCOMP_AUDIT`). Both probes accept any negative return, and the
    /// filter's own refusal is also `-1`, so a row that refused them would pass
    /// the probe while testing something else.
    const AUDITED_PROBES: &[(&str, u16, &str)] = &[
        ("CAPTEST.ELF", 116, "the retired SYS_CAP_GRANT, issued as `raw_syscall3(116, ..)`"),
        ("ABITEST.ELF", 999, "an unclaimed number, issued to watch the default arm refuse it"),
        // abitest's retired-number sweep (`check_retired_numbers_do_not_answer`):
        // one number per family retired in RFC-0040 gap 1, issued raw through
        // `issue_retired_nr` to watch the default arm refuse a number no name
        // holds. Each row's `names.is_empty()` assertion is a live tripwire
        // against that number being reassigned.
        ("ABITEST.ELF", 100, "retired ipc-channel create, issued raw by the retired-number sweep"),
        ("ABITEST.ELF", 115, "retired shm map-by-index, issued raw"),
        ("ABITEST.ELF", 200, "retired gpio read-by-pin, issued raw"),
        ("ABITEST.ELF", 211, "retired pwm disable-by-channel, issued raw"),
        ("ABITEST.ELF", 231, "retired motor direction-by-id, issued raw"),
        ("ABITEST.ELF", 332, "retired sensor read-by-type, issued raw"),
        ("ABITEST.ELF", 503, "retired io_ring setup, issued raw"),
        ("ABITEST.ELF", 506, "retired kernel-channel create, issued raw"),
        ("ABITEST.ELF", 511, "retired port create, issued raw"),
        ("ABITEST.ELF", 515, "retired handle grant, issued raw"),
        ("ABITEST.ELF", 520, "retired driver register-by-kind, issued raw"),
        ("ABITEST.ELF", 350, "retired kill, issued raw"),
        ("ABITEST.ELF", 351, "retired signal, issued raw"),
        ("ABITEST.ELF", 352, "retired sigreturn, issued raw"),
        ("ABITEST.ELF", 353, "retired sigpending, issued raw"),
        ("ABITEST.ELF", 354, "retired sigprocmask, issued raw"),
        ("ABITEST.ELF", 356, "retired alarm, issued raw"),
        ("ABITEST.ELF", 360, "retired pipe, issued raw"),
    ];

    /// Live calls an audit-mode image issues raw, outside its row, to watch
    /// the real arm refuse wrong arguments (RFC-0055, wave 11: the user
    /// shell's calls, which only SH.ELF's row may list —
    /// `only_the_shell_profile_lists_the_shell_calls`). Unlike
    /// `AUDITED_PROBES` these numbers ARE assigned: the probe reaches the
    /// call's own arm, which is the point.
    const AUDITED_LIVE_CALLS: &[(&str, u16, &str)] = &[
        ("ABITEST.ELF", 607, "SYS_PIPE_TYPED with a bad flag and a null pointer"),
        ("ABITEST.ELF", 608, "SYS_SPAWN_EX with a bad version and no launch grant"),
        ("ABITEST.ELF", 609, "SYS_CONSOLE_WAIT with a3 != 0"),
        ("ABITEST.ELF", 611, "SYS_TASK_KILL on self and on a non-descendant"),
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
        assert!(m.len() > 150, "read only {} numbers out of syscall_nr.rs", m.len());
        m
    }

    /// libsys fn name -> (`SYS_*` names in its body, identifiers it calls).
    type Fns = BTreeMap<String, (BTreeSet<String>, BTreeSet<String>)>;

    fn libsys_fns() -> Fns {
        let mut fns = Fns::new();
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
                    if id.starts_with("SYS_") {
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

    /// RFC-0047: the native numbers a Linux C image's calls reach. Every
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
        let (lang, files) = sources_of(image);
        let nrs = numbers();
        let mut out = BTreeSet::new();
        if lang == Lang::LinuxC {
            for &(path, src) in files {
                derive_linux_c(path, src, &mut out);
            }
            return out;
        }
        if lang == Lang::Asm {
            for &(path, src) in files {
                for line in src.lines() {
                    let code = line.split('#').next().unwrap().trim();
                    if let Some(rest) = code.strip_prefix("li") {
                        if let Some(n) = rest.trim().strip_prefix("a7,") {
                            out.insert(n.trim().parse::<u16>().unwrap_or_else(|_| {
                                panic!("{path}: `{code}`: not a decimal syscall number")
                            }));
                        }
                    }
                }
                assert!(!out.is_empty(), "{path}: no `li a7, N` found");
            }
            return out;
        }
        let fns = libsys_fns();
        for &(path, src) in files {
            let code = lex(src, false);
            let with_strings = lex(src, true);
            for prefix in ["use sys::", "use azos_libsys::"] {
                for (at, _) in code.match_indices(prefix) {
                    let tail = &code[at + prefix.len()..];
                    let list = &tail[..tail.find(';').expect("`use` without `;`")];
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
                let qualified = ["azos_libsys::", "sys::"].iter().any(|q| {
                    before.strip_suffix(q).is_some_and(|rest| {
                        rest.as_bytes().last().is_none_or(|&c| !is_ident(c))
                    })
                });
                if !qualified || next_non_ws(&code, at + id.len()) != Some(b'(') {
                    continue; // not a call: a const, a type, a macro (`sys::cstr!`)
                }
                assert!(fns.contains_key(id), "{path}: calls `sys::{id}(..)`, which libsys does not define");
                for s in closure(&fns, id) {
                    out.insert(*nrs.get(&s).unwrap_or_else(|| {
                        panic!("libsys issues {s}, which syscall_nr.rs does not define")
                    }));
                }
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
        out
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

    /// The scanner reproduces the sets verified by hand. Pinned with the ABI
    /// constants, not the scanner's own name table, so a regression in either
    /// half shows here instead of shrinking every profile in step with it.
    #[test]
    fn the_scanner_reproduces_the_hand_verified_sets() {
        use azos_abi::syscall_nr as nr;
        let set = |v: &[u64]| v.iter().map(|&n| n as u16).collect::<BTreeSet<u16>>();
        assert_eq!(derive("HELLO.ELF"), set(&[nr::SYS_EXIT, nr::SYS_WRITE]));
        assert_eq!(
            derive("SYSTEST.ELF"),
            set(&[nr::SYS_EXIT, nr::SYS_GETPID, nr::SYS_WRITE, nr::SYS_BRK]),
        );
        // println = write + putchar; exit; the panic handler exits; getpid is
        // the refusal probe.
        assert_eq!(
            derive("UHELLO.ELF"),
            set(&[nr::SYS_PUTCHAR, nr::SYS_EXIT, nr::SYS_GETPID, nr::SYS_WRITE]),
        );
        // Typed throughout after RFC-0040 gap 1: the mailbox and phase C use
        // fast IPC and the typed shm/port/io_ring/channel families. SYS_FORK is
        // raw asm in `spawn`.
        //
        // 108 is still here: the mailbox and the heartbeat still address the
        // root by TID (that conversion to an endpoint was reverted on
        // 2026-09-21 with the `fork()` inheritance it needed — see
        // `post`'s own comment). RFC-0040 gap 3 landed that inheritance, and
        // phases B and E now use it: 582 is the client's capability-addressed
        // call, and 583 is the server minting and owning the endpoint the
        // client's fork-inherited capability reaches.
        assert_eq!(
            derive("IPCTEST.ELF"),
            set(&[
                nr::SYS_PUTCHAR, nr::SYS_EXIT, nr::SYS_GETPID, nr::SYS_FORK, nr::SYS_SLEEP,
                nr::SYS_WRITE, nr::SYS_UPTIME,
                nr::SYS_IPC_FAST_CALL,
                nr::SYS_ENDPOINT_CREATE_TYPED, nr::SYS_IPC_FAST_CALL_EP,
                nr::SYS_IPC_FAST_REPLY, nr::SYS_IPC_FAST_ACCEPT,
                nr::SYS_IPC_FAST_REPLY_ACCEPT,
                nr::SYS_CHAN_CREATE_TYPED, nr::SYS_CHAN_WRITE_TYPED, nr::SYS_CHAN_READ_TYPED,
                nr::SYS_PORT_CREATE_TYPED, nr::SYS_PORT_POLL_TYPED, nr::SYS_PORT_BIND_TYPED,
                nr::SYS_PORT_DESTROY_TYPED, nr::SYS_PORT_WAIT_TYPED,
                // Wave 11, phase P.
                nr::SYS_PORT_WAIT_UNTIL_TYPED,
                nr::SYS_SHM_CREATE_TYPED, nr::SYS_SHM_MAP_TYPED, nr::SYS_SHM_ACQUIRE_TYPED,
                nr::SYS_SHM_RELEASE_TYPED,
                nr::SYS_IORING_CREATE_TYPED, nr::SYS_IORING_SUBMIT_TYPED, nr::SYS_IORING_DESTROY_TYPED,
                nr::SYS_CLOSE_TYPED,
                // Wave 9, phases L and L2: lease IPC by capability.
                nr::SYS_IPC_LEASE_GRANT_TYPED, nr::SYS_IPC_LEASE_ACCEPT, nr::SYS_IPC_LEASE_RETURN,
                nr::SYS_IPC_LEASE_FREE, nr::SYS_IPC_LEASE_WAIT, nr::SYS_CAP_LOOKUP,
                nr::SYS_SERVICE_REGISTER, nr::SYS_SERVICE_DISCOVER,
                // Wave 11 (LEASE2), phases R and W: robust notify words, the
                // killed child's status, the revoked-lease fault counter.
                nr::SYS_NOTIFY_WAIT, nr::SYS_NOTIFY_WAKE, nr::SYS_WAITPID, nr::SYS_EXIT_STATS,
                // Wave 11 (LEASE3): the robust ops and accept-and-map on
                // numbers of their own.
                nr::SYS_NOTIFY_ROBUST, nr::SYS_IPC_LEASE_ACCEPT_MAP,
            ]),
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

    /// RFC-0047 stage 3: a third-party image's row (BusyBox, never in the base
    /// image, its source not in this tree) lists only native numbers the
    /// Linux personality's table can reach, names no base image, and is a
    /// Linux row's: no number outside what translation reaches can be in it.
    ///
    /// **Canary.** Add `SYS_GPIO_INFO` to `BUSYBOX.ELF`'s row: red.
    #[test]
    fn a_third_party_row_lists_only_what_the_personality_reaches() {
        let reach: BTreeSet<u16> = azos_linux_abi::TABLE.iter().flat_map(|e| e.2.iter().copied()).collect();
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
    /// gaining `#[path] mod auth_envelope_core;` — was in `SOURCES` at
    /// all.
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
    /// remembers to add it here too, which is exactly how
    /// `BRAINCLI.ELF`'s `auth_envelope_core` went unnoticed.
    #[test]
    fn every_module_a_binary_declares_is_scanned() {
        for &(image, lang, files) in SOURCES {
            if lang != Lang::Rust {
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

    /// The live calls an audit row probes (RFC-0055): issued by the binary,
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
        const SCHEDULER: &str = include_str!("../../../../crates/core/sched/src/scheduler.rs");
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
        const SCHEDULER: &str = include_str!("../../../../crates/core/sched/src/scheduler.rs");
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
        // 62 since abitest writes every line in one `write` (no SYS_PUTCHAR);
        // 63 with `SYS_EXIT_STATS` (wave 11, the exit storm); 66 with the
        // three port calls of the native fork check (wave 13, NATFORK); 70
        // with the four thread calls (wave 13, THREADS); 71 with
        // `SYS_TASK_SUBREAPER` (wave 13, the orphan check); 72 with mmap
        // (wave 13, the mmap prot check): the quarter-free limit exactly.
        assert_eq!(image_filter(row("ABITEST.ELF")).count, 72, "the widest row, named in its comment");
    }

    // ── Bound to the bytes, not the name (owner decision 2026-09-14) ─────

    /// The repository root, where the Makefile and build/ are.
    const ROOT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../..");

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
    /// RISC-V image recipe (`build/disk.img` and its siblings), in order.
    ///
    /// **`_AARCH64`-suffixed variables are excluded.** Phase 6 (userspace on
    /// aarch64) added a second, independent `mcopy -i $@ $(..._AARCH64)
    /// ::NAME.ELF` recipe (`build/disk-aarch64.img`, `Makefile`) for the
    /// aarch64 ELFs — same `NAME.ELF` targets, deliberately, since both
    /// kernels look up `HELLO.ELF` etc. by the same FAT32 name. Before that
    /// recipe existed, EVERY `mcopy -i $@ ... ::NAME.ELF` line in the whole
    /// Makefile belonged to the one recipe this function (and `IMAGE_ELFS`)
    /// is about, so no filter was needed. Widening the raw scan to match
    /// both recipes would make this function assert riscv64's `IMAGE_ELFS`
    /// against a LIST TWICE AS LONG as it (correctly) is — this crate's own
    /// `crates/core/sched/src/seccomp.rs` `include!`s a SEPARATE, aarch64-only
    /// table (`build/image_hashes_aarch64.rs`) for exactly this reason: one
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
                (var.starts_with("$(") && !var.contains("_AARCH64") && name.ends_with(".ELF"))
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
    /// (`build/disk-aarch64.img` and its siblings — `build/disk-aarch64-
    /// systest.img`, `build/disk-aarch64-abitest.img`, all one shared
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
    /// build/.
    pub(crate) fn shipped_elf(name: &str) -> Vec<u8> {
        let (_, var) = image_elfs_rule()
            .into_iter()
            .find(|(n, _)| n == name)
            .unwrap_or_else(|| panic!("IMAGE_ELFS has no {name}"));
        let path = format!("{ROOT}/{}", makefile_var(&var));
        std::fs::read(&path).unwrap_or_else(|e| {
            panic!(
                "{path}: {e}. The seccomp image table is generated from the shipped ELFs: \
                 run `make build/image_hashes.rs`, which builds them, before this suite."
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
    /// in `build/disk-aarch64.img`'s recipe went unchecked — the exact gap
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
    /// in build/ now, which the next disk image carries. A table generated
    /// before an ELF was rebuilt fails here, instead of refusing that binary at
    /// boot.
    #[test]
    fn the_table_is_the_sha256_of_the_elfs_the_image_ships() {
        for (name, digest) in IMAGE_SHA256 {
            let got = image_digest(&shipped_elf(name));
            assert!(
                got == *digest,
                "{name}: build/image_hashes.rs is stale against its ELF. Run \
                 `make build/image_hashes.rs` and rebuild the kernel.",
            );
            assert_eq!(image_for_digest(digest).map(|p| p.image), Some(*name));
        }
    }

    /// **Renaming does not widen.** uhello's bytes copied over ABITEST.ELF (the
    /// image of the `seccomp: renamed image keeps its profile` scenario) are
    /// bound to UHELLO.ELF's row, which refuses getpid, not to ABITEST.ELF's,
    /// which allows it.
    #[test]
    fn a_renamed_binary_keeps_its_own_profile() {
        use azos_abi::syscall_nr as nr;
        let getpid = nr::SYS_GETPID as u16;
        let p = image_for_digest(&image_digest(&shipped_elf("UHELLO.ELF"))).expect("uhello's bytes are bound");
        assert_eq!(p.image, "UHELLO.ELF");
        assert_eq!(image_filter(p).verdict(getpid), FilterVerdict::Deny);
        assert_eq!(
            image_filter(row("ABITEST.ELF")).verdict(getpid),
            FilterVerdict::Allow,
            "the scenario discriminates only while the name it borrows allows getpid",
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

    // ── Spawn: refusal, filter and capability key (RFC-0043) ───────────

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
        assert!(
            def.contains(r#"--config 'target.$(TARGET).rustflags=["--cfg=azos_stable_metadata_$(USPACE_METADATA_TAG)"]'"#),
            "{def}",
        );
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
        }
        let recipes = MAKEFILE
            .lines()
            .filter(|l| l.contains("&& $(USPACE_BUILD)") || WRAPPED.iter().any(|w| l.contains(w)))
            .count();
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
        // 18 since wave 11: the user shell and its tool image (RFC-0055).
        // 19 with the power tool (RFC-0055 S5).
        // 20 with the Linux driver server skeleton (RFC-0053 L0b, wave 12).
        // 24 with the flight, behavior, config and OTA tools (wave 12).
        // +1 riscv64 since wave 11 BOARDIMG: the board volume's own ML service
        // (the same crate, the named key), `$(MLSRV_ELF_BOARD)`.
        assert_eq!(
            recipes,
            rust_images + 24 + 1,
            "expected {rust_images} riscv64 + 24 aarch64 + 1 board $(USPACE_BUILD) recipes",
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
            if lang != Lang::Rust {
                continue;
            }
            for &(path, src) in files {
                assert_paired(&format!("{image} ({path})"), src);
            }
        }
        for (i, src) in LIBSYS.iter().enumerate() {
            assert_paired(&format!("libsys[{i}]"), src);
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

/// Ownership on the syscall dispatch table, after RFC-0040 gap 1.
///
/// **WHY this reads the source.** Before gap 1 the object families had two
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
/// `CAP_TYPED_SYSCALLS`. An untyped port/ring/shm/channel arm reappearing —
/// the shape that carried W3-F2/W3-F3 — makes this red.
#[cfg(test)]
mod dispatch_guards {
    const DISPATCH: &str = include_str!("../../../../crates/core/syscall/src/dispatch.rs");

    /// Prefixes of the object families whose calls carry a resource handle.
    /// After gap 1 every arm under one of these is a `Cap<T>` typed call.
    const HANDLE_PREFIXES: &[&str] = &["SYS_PORT_", "SYS_IORING_", "SYS_SHM_", "SYS_CHAN_", "SYS_IO_"];

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
    /// port/io_ring/shm/channel calls were retired in RFC-0040 gap 1; a dispatch
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
            arms.len() >= 12,
            "expected the typed port/io_ring/shm/channel arms, found {arms:?}",
        );
        for name in &arms {
            assert!(
                name.ends_with("_TYPED"),
                "dispatch arm `{name}` handles an object family but is not a typed \
                 Cap<T> call. The untyped forms were retired in RFC-0040 gap 1 and \
                 carried no ownership gate on the dispatch arm — this is the \
                 W3-F2/W3-F3 shape. Route it through a `*_TYPED` handler that \
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
            ("SYS_PORT_CREATE_TYPED", nr::SYS_PORT_CREATE_TYPED),
            ("SYS_PORT_POLL_TYPED", nr::SYS_PORT_POLL_TYPED),
            ("SYS_PORT_DESTROY_TYPED", nr::SYS_PORT_DESTROY_TYPED),
            ("SYS_PORT_BIND_TYPED", nr::SYS_PORT_BIND_TYPED),
            ("SYS_PORT_WAIT_TYPED", nr::SYS_PORT_WAIT_TYPED),
            ("SYS_PORT_WAIT_UNTIL_TYPED", nr::SYS_PORT_WAIT_UNTIL_TYPED),
            ("SYS_IORING_CREATE_TYPED", nr::SYS_IORING_CREATE_TYPED),
            ("SYS_IORING_SUBMIT_TYPED", nr::SYS_IORING_SUBMIT_TYPED),
            ("SYS_IORING_DESTROY_TYPED", nr::SYS_IORING_DESTROY_TYPED),
            ("SYS_SHM_CREATE_TYPED", nr::SYS_SHM_CREATE_TYPED),
            ("SYS_SHM_MAP_TYPED", nr::SYS_SHM_MAP_TYPED),
            ("SYS_SHM_ACQUIRE_TYPED", nr::SYS_SHM_ACQUIRE_TYPED),
            ("SYS_SHM_RELEASE_TYPED", nr::SYS_SHM_RELEASE_TYPED),
            ("SYS_CHAN_CREATE_TYPED", nr::SYS_CHAN_CREATE_TYPED),
            ("SYS_CHAN_WRITE_TYPED", nr::SYS_CHAN_WRITE_TYPED),
            ("SYS_CHAN_READ_TYPED", nr::SYS_CHAN_READ_TYPED),
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

/// RFC-0049 P2: which shipped images may run under a `mem = "locked"`
/// topology row (`seccomp::locked_compatible`), pinned against the real
/// profile table.
///
/// **Canary** (run by hand 2026-09-28): drop `!p.audit &&` from
/// `locked_compatible` — `ABITEST.ELF`/`CAPTEST.ELF` (audit mode, which lets
/// any unlisted call through) are reported compatible and the test fails.
#[cfg(test)]
mod locked_rows {
    use crate::seccomp::{locked_compatible, IMAGE_PROFILES, LOCKED_FORBIDDEN};
    use azos_abi::syscall_nr::{SYS_ALLOC_DEMAND, SYS_FORK, SYS_FORK_COW};

    fn row(image: &str) -> &'static crate::seccomp::ImageProfile {
        IMAGE_PROFILES.iter().find(|p| p.image == image).expect(image)
    }

    #[test]
    fn the_forbidden_set_is_fork_fork_cow_and_alloc_demand() {
        assert_eq!(LOCKED_FORBIDDEN, [SYS_FORK as u16, SYS_FORK_COW as u16, SYS_ALLOC_DEMAND as u16]);
    }

    #[test]
    fn locked_compatibility_follows_the_profile() {
        // `mem-locked-smoke` puts UHELLO.ELF under a locked row: it must pass.
        assert!(locked_compatible(row("UHELLO.ELF")));
        // Audit mode cannot promise the absence of a call.
        assert!(!locked_compatible(row("ABITEST.ELF")));
        assert!(!locked_compatible(row("CAPTEST.ELF")));
        for p in IMAGE_PROFILES {
            let forks = p.syscalls.iter().any(|n| LOCKED_FORBIDDEN.contains(n));
            assert_eq!(locked_compatible(p), !p.audit && !forks, "{}", p.image);
        }
    }
}

/// RFC-0049 M1, wave 9: which shipped images memory admission counts as
/// forking (`seccomp::profile_can_fork`), pinned against the real profile
/// table: a row pays for a COW copy per instance only when its image lists
/// `SYS_FORK`/`SYS_FORK_COW` or runs in audit mode.
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
    fn fork_capability_is_audit_or_a_fork_call() {
        use azos_abi::syscall_nr::{SYS_FORK, SYS_FORK_COW};
        for p in IMAGE_PROFILES {
            let forks = p.syscalls.iter().any(|&n| n == SYS_FORK as u16 || n == SYS_FORK_COW as u16);
            assert_eq!(profile_can_fork(p), p.audit || forks, "{}", p.image);
        }
    }
}

/// SYSFLOOR: both trap entries answer `getpid`/`yield`/`test` before they
/// build a syscall's arguments. These pin that the shortcut cannot run ahead
/// of the filter: inside `syscall_entry_fast` the verdict is taken before any
/// `Done`, and each trap entry reaches the dispatcher only through it.
#[cfg(test)]
mod syscall_entry_order {
    const DISPATCH: &str = include_str!("../../../../crates/core/syscall/src/dispatch.rs");
    const RV: &str = include_str!("../../../../kernel/src/trap/exception.rs");
    const ARM: &str = include_str!("../../../../kernel/src/entry/aarch64.rs");

    /// Text of `fn <name>(` up to the next line that is exactly `}`.
    fn body<'a>(src: &'a str, sig: &str) -> &'a str {
        let at = src.find(sig).unwrap_or_else(|| panic!("`{sig}` not found"));
        let end = src[at..].find("\n}\n").unwrap_or_else(|| panic!("end of `{sig}` not found"));
        &src[at..at + end]
    }

    #[test]
    fn the_filter_verdict_comes_before_every_shortcut() {
        let b = body(DISPATCH, "pub fn syscall_entry_fast(");
        let verdict = b.find("current_syscall_verdict(num)").expect("no filter verdict");
        for done in ["SyscallEntry::Done(sys_getpid())", "SyscallEntry::Done(sys_yield())", "SyscallEntry::Done(sys_test())"] {
            let at = b.find(done).unwrap_or_else(|| panic!("`{done}` not found"));
            assert!(verdict < at, "`{done}` is answered before the filter verdict");
        }
        // `syscall_dispatch_out` (aarch64 personality callers, host shims) is
        // the same two halves, filter first.
        let out = body(DISPATCH, "pub fn syscall_dispatch_out(");
        let fast = out.find("syscall_entry_fast(num)").expect("dispatch_out skips the filter");
        let checked = out.find("syscall_dispatch_checked(").expect("dispatch_out does not dispatch");
        assert!(fast < checked);
    }

    #[test]
    fn each_trap_entry_dispatches_only_what_the_filter_returned() {
        for (name, src, entry) in [
            ("riscv64", RV, "pub(crate) fn handle_ecall("),
            ("aarch64", ARM, "pub extern \"C\" fn aarch64_trap_entry("),
        ] {
            let b = body(src, entry);
            assert!(b.contains("syscall_entry_fast(num"), "{name}: the trap entry does not run the filter");
            assert!(!b.contains("syscall_dispatch_out("), "{name}: a second, unfiltered-shape dispatch is back");
            assert!(!b.contains("dispatch_slow("), "{name}: dispatch_slow called around the filter");
            // The slow half is reached only with the `entry` the filter gave.
            assert_eq!(src.matches("syscall_dispatch_checked(\n").count(), 1,
                "{name}: one call to syscall_dispatch_checked, inside the out-of-line slow path");
            assert!(src.contains("        entry, num,\n"),
                "{name}: syscall_dispatch_checked is not handed the filter's entry");
        }
    }
}

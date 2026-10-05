// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host-side tests for the `azos_abi` crate.
//!
//! The kernel-side crate is `no_std` and bound to RISC-V; running the
//! `#[cfg(test)]` suites inside it requires this excluded crate.

#[cfg(test)]
mod cap_tests {
    use azos_abi::cap::{CapHandle, CapKind, CapPerms, CAP_NULL};

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

    /// All 23 `CapKind` variants currently defined, in discriminant order.
    ///
    /// The length is written out rather than inferred so that adding a
    /// variant without adding it here is a compile error. An inferred
    /// `[CapKind; _]` would silently keep covering only the old set, which
    /// is the failure this array exists to prevent.
    const ALL_KINDS: [CapKind; 28] = [
        CapKind::Null,
        CapKind::Channel,
        CapKind::Shm,
        CapKind::Port,
        CapKind::Irq,
        CapKind::MmioRegion,
        CapKind::IoRing,
        CapKind::Sensor,
        CapKind::Gpio,
        CapKind::I2c,
        CapKind::Pwm,
        CapKind::Motor,
        CapKind::File,
        CapKind::Socket,
        CapKind::Task,
        CapKind::AiSession,
        CapKind::Adc,
        CapKind::Buzzer,
        CapKind::Power,
        CapKind::Disk,
        CapKind::NetConfig,
        CapKind::DriverRegistry,
        CapKind::Endpoint,
        CapKind::LinkKey,
        CapKind::Entropy,
        // 25 is `Lease` (wave 9).
        CapKind::Lease,
        // 26 and 27: the user shell's pipe ends and launch grants (RFC-0055).
        CapKind::Pipe,
        CapKind::Launch,
    ];

    /// Every permission combination worth distinguishing: each single
    /// bit, the named unions, and the empty/full extremes.
    const ALL_PERMS: [CapPerms; 8] = [
        CapPerms::NONE,
        CapPerms::READ,
        CapPerms::WRITE,
        CapPerms::EXEC,
        CapPerms::DUP,
        CapPerms::RW,
        CapPerms::RW_DUP,
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
        let h = CapHandle::pack(CapKind::Channel, CapPerms::RW_DUP, 0x42, 0xAB);
        assert_eq!(h.kind(), CapKind::Channel as u8);
        assert!(h.perms().contains(CapPerms::READ));
        assert!(h.perms().contains(CapPerms::WRITE));
        assert!(h.perms().contains(CapPerms::DUP));
        assert!(!h.perms().contains(CapPerms::EXEC));
        assert_eq!(h.generation(), 0x42);
        assert_eq!(h.slot(), 0xAB);
    }

    /// Every `CapKind` variant round-trips through pack/unpack, crossed
    /// with every permission combination and the generation extremes.
    #[test]
    fn round_trip_every_kind_perm_and_gen_extreme() {
        for &kind in &ALL_KINDS {
            for &perms in &ALL_PERMS {
                for &gen in &[0u16, CapHandle::MAX_GENERATION] {
                    for &slot in &[0u16, (ADDRESSABLE_SLOTS - 1) as u16] {
                        let h = CapHandle::pack(kind, perms, gen, slot);
                        assert_eq!(
                            h.kind(),
                            kind as u8,
                            "kind mismatch for {kind:?}/{perms:?}/gen={gen}/slot={slot}"
                        );
                        assert_eq!(
                            h.perms().bits(),
                            perms.bits(),
                            "perms mismatch for {kind:?}/{perms:?}/gen={gen}/slot={slot}"
                        );
                        assert_eq!(
                            h.generation(),
                            gen,
                            "generation mismatch for {kind:?}/{perms:?}/gen={gen}/slot={slot}"
                        );
                        assert_eq!(
                            h.slot(),
                            slot,
                            "slot mismatch for {kind:?}/{perms:?}/gen={gen}/slot={slot}"
                        );
                    }
                }
            }
        }
    }

    /// `CapKind` uses discriminants 0..=15 today, but the widened kind
    /// field can hold 0..=63. 63 is the new maximum representable value:
    /// it must round-trip through the raw field even though no `CapKind`
    /// variant claims it yet (widening the field and populating it are
    /// deliberately separate changes — see the module doc in
    /// `crates/core/abi/src/cap.rs`). The 26-bit shift below is the documented
    /// wire position of the kind field (bits 31..26); it is not
    /// accessible as a public constant, so this test reconstructs it
    /// directly against the documented format rather than through
    /// `pack()`, which only accepts a defined `CapKind`.
    #[test]
    fn max_representable_kind_round_trips_but_is_unpopulated() {
        const KIND_SHIFT: u32 = 26;
        const MAX_KIND: u32 = 0x3F; // 6 bits: 63

        let h = CapHandle::from_raw(MAX_KIND << KIND_SHIFT);
        assert_eq!(h.kind(), 63, "widened field must be able to hold 63");
        assert_eq!(
            CapKind::from_raw(h.kind()),
            None,
            "63 must stay unpopulated until the owner's minting rule is written down"
        );
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
        let h = CapHandle::pack(CapKind::Channel, CapPerms::RW, one_past_max, 3);
        assert_ne!(
            h.generation(),
            one_past_max,
            "a generation past the field must not survive packing"
        );
        assert_eq!(h.slot(), 3, "the slot field must not be disturbed by it");
        assert_eq!(h.kind(), CapKind::Channel as u8);
    }

    /// 13 bits since 2026-09-19 (8 before, which wrapped and reissued
    /// generations). Derived, so widening the field updates the test with it.
    #[test]
    fn the_generation_field_holds_what_the_slot_retirement_rule_assumes() {
        assert_eq!(CapHandle::MAX_GENERATION, 8191, "13-bit generation field");
        let h = CapHandle::pack(CapKind::Shm, CapPerms::RW, CapHandle::MAX_GENERATION, 1);
        assert_eq!(h.generation(), CapHandle::MAX_GENERATION);
    }

    #[test]
    fn slot_one_past_maximum_does_not_round_trip() {
        let one_past_max = ADDRESSABLE_SLOTS as u16;
        let h = CapHandle::pack(CapKind::Channel, CapPerms::NONE, 0, one_past_max);
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
        assert_eq!(CapKind::from_raw(0), Some(CapKind::Null));
        assert_eq!(CapKind::from_raw(1), Some(CapKind::Channel));
        assert_eq!(CapKind::from_raw(15), Some(CapKind::AiSession));
        // 16..=21 were populated 2026-09-06 (Adc..DriverRegistry).
        assert_eq!(CapKind::from_raw(16), Some(CapKind::Adc));
        assert_eq!(CapKind::from_raw(21), Some(CapKind::DriverRegistry));
        // 22 is `Endpoint`, added 2026-09-19 (RFC-0040 gap 2).
        assert_eq!(CapKind::from_raw(22), Some(CapKind::Endpoint));
        // 23 is `LinkKey`, added 2026-09-26 (U06-9).
        assert_eq!(CapKind::from_raw(23), Some(CapKind::LinkKey));
        // 24 is `Entropy`, added 2026-09-28 (wave 9, P9).
        assert_eq!(CapKind::from_raw(24), Some(CapKind::Entropy));
        // The first tag past the last variant, and the field's own maximum,
        // must both stay unpopulated. `from_raw` has no catch-all arm, so
        // this is the assertion that a future variant added to the enum
        // without an arm here is caught rather than aliasing. The boundary
        // MOVES with the enum: leaving it at 24 would have turned this from
        // "the next tag is empty" into "Entropy does not exist", which is a
        // different claim and a false one.
        assert_eq!(CapKind::from_raw(25), Some(CapKind::Lease));
        assert_eq!(CapKind::from_raw(26), Some(CapKind::Pipe));
        assert_eq!(CapKind::from_raw(27), Some(CapKind::Launch));
        assert_eq!(CapKind::from_raw(28), None);
        assert_eq!(CapKind::from_raw(63), None);
        assert_eq!(CapKind::from_raw(255), None);
    }

    /// Every discriminant in `ALL_KINDS` survives the byte round trip.
    ///
    /// The loop above (`round_trip_every_kind_perm_and_gen_extreme`) checks
    /// `pack`/`unpack` and compares against `kind as u8`; it never calls
    /// `from_raw`, so a variant missing from `from_raw`'s match would pass it.
    /// This closes that: the enum and its decoder are asserted to agree.
    #[test]
    fn every_kind_decodes_back_to_itself() {
        for &kind in &ALL_KINDS {
            assert_eq!(
                CapKind::from_raw(kind as u8),
                Some(kind),
                "{kind:?} (tag {}) has no arm in CapKind::from_raw",
                kind as u8
            );
        }
    }

    #[test]
    fn nonzero_view() {
        let h = CapHandle::pack(CapKind::Shm, CapPerms::RW, 1, 7);
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
    /// breaking change requiring a major version bump and an RFC.
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

#[cfg(test)]
mod syscall_nr_tests {
    use azos_abi::syscall_nr::*;

    /// These syscall numbers are wire-format. Changing them is an
    /// ABI break requiring a major version bump and an RFC. Only assigned
    /// numbers are pinned here; the retired ones are pinned by
    /// `retired_syscalls` below.
    #[test]
    fn frozen_syscall_numbers() {
        assert_eq!(SYS_TEST, 0);
        assert_eq!(SYS_EXIT, 3);
        assert_eq!(SYS_FORK, 12);
        assert_eq!(SYS_SPAWN, 17);
        // `SYS_OPEN` (20) was pinned here until it was retired (owner decision
        // 96). Deleting the line loses nothing: a retired number is held by a
        // STRONGER guard than this one. `frozen_syscall_numbers` only says 20
        // still means open; `retired_syscalls` below says no name may carry
        // 20, no dispatch arm may match it, and
        // `no_profile_grants_a_retired_number` says no profile may grant it.
        // The freeze protects a live number from moving; retirement protects a
        // dead one from coming back, which is the property that matters now.
        assert_eq!(SYS_CLOSE, 21);
        assert_eq!(SYS_IPC_FAST_CALL, 108);
        // 111 (`SYS_IPC_LEASE_GRANT`) was pinned here until it was retired
        // for the typed 603 (owner decision 2026-09-28); `retired_syscalls`
        // now holds it.
        assert_eq!(SYS_GPIO_INFO, 203);
        assert_eq!(SYS_PWM_INFO, 214);
        assert_eq!(SYS_NET_INFO, 260);
        assert_eq!(SYS_DRV_REGISTER, 300);
        assert_eq!(SYS_ROBOT_INIT, 320);
        assert_eq!(SYS_SOCKET, 370);
        assert_eq!(SYS_SERVICE_REGISTER, 390);
        assert_eq!(SYS_BRK, 400);
        assert_eq!(SYS_SECCOMP, 430);
        assert_eq!(SYS_MMIO_MAP, 509);
        assert_eq!(SYS_TRACE_DUMP, 518);
        assert_eq!(SYS_DRIVER_POLL_EVENT, 522);
        assert_eq!(SYS_CHAN_WRITE_TYPED, 528);
        assert_eq!(SYS_CHAN_READ_TYPED, 529);
        assert_eq!(SYS_PORT_CREATE_TYPED, 530);
        assert_eq!(SYS_PORT_POLL_TYPED, 531);
        assert_eq!(SYS_PORT_DESTROY_TYPED, 532);
        assert_eq!(SYS_SHM_CREATE_TYPED, 533);
        assert_eq!(SYS_SHM_ACQUIRE_TYPED, 534);
        assert_eq!(SYS_SHM_RELEASE_TYPED, 535);
        assert_eq!(SYS_IORING_CREATE_TYPED, 536);
        assert_eq!(SYS_IORING_SUBMIT_TYPED, 537);
        assert_eq!(SYS_IORING_DESTROY_TYPED, 538);
        // W5 batch 5.1 — Cap<Gpio>.
        assert_eq!(SYS_GPIO_READ_TYPED, 539);
        assert_eq!(SYS_GPIO_WRITE_TYPED, 540);
        assert_eq!(SYS_GPIO_SET_DIR_TYPED, 541);
        // W5 batch 5.2 — Cap<I2c>.
        assert_eq!(SYS_I2C_READ_TYPED, 542);
        assert_eq!(SYS_I2C_WRITE_TYPED, 543);
        assert_eq!(SYS_I2C_DETECT_TYPED, 544);
        assert_eq!(I2C_TYPED_MAX_BYTES, 256);
        // W5 batch 5.3 — Cap<Pwm> (fills 528..=549).
        assert_eq!(SYS_PWM_ENABLE_TYPED, 545);
        assert_eq!(SYS_PWM_DISABLE_TYPED, 546);
        assert_eq!(SYS_PWM_SET_PERIOD_TYPED, 547);
        assert_eq!(SYS_PWM_SET_DUTY_TYPED, 548);
        assert_eq!(SYS_PWM_SET_DUTY_PCT_TYPED, 549);
        // W5 batch 5.4 — Cap<Motor> (opens 550..=569 extension).
        assert_eq!(SYS_MOTOR_SET_TARGET_TYPED, 550);
        assert_eq!(SYS_MOTOR_TICK_TYPED, 551);
        assert_eq!(SYS_MOTOR_ENABLE_TYPED, 552);
        assert_eq!(SYS_MOTOR_ENABLED_TYPED, 553);
        assert_eq!(SYS_MOTOR_SET_GAINS_TYPED, 554);
        assert_eq!(SYS_MOTOR_RESET_TYPED, 555);
        assert_eq!(MOTOR_TICK_OUT_BYTES, 8);
        // RFC-0040 gap 1 — the typed forms.
        assert_eq!(SYS_CHAN_CREATE_TYPED, 573);
        assert_eq!(SYS_SHM_MAP_TYPED, 574);
        assert_eq!(SYS_PORT_BIND_TYPED, 575);
        assert_eq!(SYS_MOTOR_DIRECTION_TYPED, 576);
        assert_eq!(SYS_PORT_WAIT_TYPED, 577);
        assert_eq!(SYS_MOTOR_ANGLE_TYPED, 578);
        // RFC-0041 — the combined calls.
        assert_eq!(SYS_IPC_FAST_REPLY_ACCEPT, 580);
        assert_eq!(SYS_DRIVER_REPLY_FETCH, 581);
        // Owner round 23 — the rest of the RFC-0048 P2 file surface.
        assert_eq!(SYS_RMDIR, 597);
        assert_eq!(SYS_RENAME, 598);
        assert_eq!(SYS_TRUNCATE, 599);
        assert_eq!(SYS_FSYNC_TYPED, 600);
        assert_eq!(SYS_STATFS, 601);
        assert_eq!(STATFS_BYTES, 48);
        // The blocking form of 581 (wave 9, the ring-3 ML service).
        assert_eq!(SYS_DRIVER_REPLY_WAIT, 610);
        // Wave 10: the lease wait and the typed lease grant.
        assert_eq!(SYS_IPC_LEASE_WAIT, 602);
        assert_eq!(SYS_IPC_LEASE_GRANT_TYPED, 603);
        // Wave 11: the exit-path counters.
        assert_eq!(SYS_EXIT_STATS, 605);
        assert_eq!(EXIT_STAT_EXIT_TEARDOWNS, 0);
        assert_eq!(EXIT_STAT_REUSE_TEARDOWNS, 1);
        assert_eq!(EXIT_STAT_EARLY_NOTICES, 2);
        assert_eq!(EXIT_STAT_NOTICE_DROPS, 5);
        assert_eq!(EXIT_STAT_NOTICE_REFUSALS, 6);
        // Wave 11 (SENSORTS): the stamped sensor read.
        assert_eq!(SYS_SENSOR_READ_TS, 606);
        // Wave 11: the user shell (RFC-0055).
        assert_eq!(SYS_PIPE_TYPED, 607);
        assert_eq!(SYS_SPAWN_EX, 608);
        assert_eq!(SYS_CONSOLE_WAIT, 609);
        assert_eq!(SYS_TASK_KILL, 611);
        // Wave 11 (LEASE3): the robust-word ops and accept-and-map, out of
        // the argument space of 592 and 112 into numbers of their own.
        assert_eq!(SYS_NOTIFY_ROBUST, 612);
        assert_eq!(SYS_IPC_LEASE_ACCEPT_MAP, 613);
        assert_eq!(NOTIFY_ROBUST_ADD, 1);
        assert_eq!(NOTIFY_ROBUST_DEL, 2);
        assert_eq!(LEASE_ACCEPT_RETIRED_MAP_BIT, 1 << 32);
        // RFC-0055 S5: the power family (612/613 are LEASE3's on its branch).
        assert_eq!(SYS_POWER_TYPED, 614);
        // Wave 12: the other privileged families.
        assert_eq!(SYS_FLIGHT_TYPED, 615);
        assert_eq!(SYS_BEHAVIOR_TYPED, 616);
        assert_eq!(SYS_CONFIG_TYPED, 617);
        assert_eq!(SYS_OTA_TYPED, 618);
        // Wave 13: the native thread calls (619 and 624..=629 other fronts').
        assert_eq!(SYS_THREAD_CREATE, 620);
        assert_eq!(SYS_THREAD_EXIT, 621);
        assert_eq!(SYS_FUTEX_WAIT, 622);
        assert_eq!(SYS_FUTEX_WAKE, 623);
        // RFC-0053 L0b (wave 12): the module loader's pair, 619..=629 left free.
        assert_eq!(SYS_MODULE_VERIFY, 630);
        assert_eq!(SYS_MODULE_MAP_X, 631);
        // Wave 13 (orphans): the child-subreaper mark.
        assert_eq!(SYS_TASK_SUBREAPER, 619);
        assert_eq!(MODULE_MAX_BYTES, 4 << 20);
        assert_eq!(SYS_NR_RESERVED_UPPER, 632);
        // RFC-0044 — absolute sleep.
        assert_eq!(SYS_SLEEP_UNTIL, 590);
        // RFC-0002 Driver registry bridge.
        assert_eq!(SYS_DRV_INVOKE, 311);
        assert_eq!(DRIVER_INVOKE_MAX_INPUT_BYTES, 256);
        assert_eq!(DRIVER_INVOKE_MAX_OUTPUT_BYTES, 256);
    }

    #[test]
    fn typed_caps_in_reserved_range() {
        // 528..=549 reserved for cap-typed migrations (RFC-0003);
        // 550..=569 extends it for hardware-cap families (W5
        // batch 5.4+). Both checks coexist below.
        assert!((528..550).contains(&SYS_CHAN_WRITE_TYPED));
        assert!((528..550).contains(&SYS_CHAN_READ_TYPED));
        assert!((528..550).contains(&SYS_PORT_CREATE_TYPED));
        assert!((528..550).contains(&SYS_PORT_POLL_TYPED));
        assert!((528..550).contains(&SYS_PORT_DESTROY_TYPED));
        assert!((528..550).contains(&SYS_SHM_CREATE_TYPED));
        assert!((528..550).contains(&SYS_SHM_ACQUIRE_TYPED));
        assert!((528..550).contains(&SYS_SHM_RELEASE_TYPED));
        assert!((528..550).contains(&SYS_IORING_CREATE_TYPED));
        assert!((528..550).contains(&SYS_IORING_SUBMIT_TYPED));
        assert!((528..550).contains(&SYS_IORING_DESTROY_TYPED));
        assert!((528..550).contains(&SYS_GPIO_READ_TYPED));
        assert!((528..550).contains(&SYS_GPIO_WRITE_TYPED));
        assert!((528..550).contains(&SYS_GPIO_SET_DIR_TYPED));
        assert!((528..550).contains(&SYS_I2C_READ_TYPED));
        assert!((528..550).contains(&SYS_I2C_WRITE_TYPED));
        assert!((528..550).contains(&SYS_I2C_DETECT_TYPED));
        assert!((528..550).contains(&SYS_PWM_ENABLE_TYPED));
        assert!((528..550).contains(&SYS_PWM_DISABLE_TYPED));
        assert!((528..550).contains(&SYS_PWM_SET_PERIOD_TYPED));
        assert!((528..550).contains(&SYS_PWM_SET_DUTY_TYPED));
        assert!((528..550).contains(&SYS_PWM_SET_DUTY_PCT_TYPED));
        // 550..=569 extension range — hardware-cap families that
        // didn't fit in 528..=549.
        assert!((550..570).contains(&SYS_MOTOR_SET_TARGET_TYPED));
        assert!((550..570).contains(&SYS_MOTOR_TICK_TYPED));
        assert!((550..570).contains(&SYS_MOTOR_ENABLE_TYPED));
        assert!((550..570).contains(&SYS_MOTOR_ENABLED_TYPED));
        assert!((550..570).contains(&SYS_MOTOR_SET_GAINS_TYPED));
        assert!((550..570).contains(&SYS_MOTOR_RESET_TYPED));
    }

    #[test]
    fn no_collisions_in_assigned_range() {
        // Smoke check: a handful of numbers don't collide.
        let nrs = [
            SYS_TEST,
            SYS_EXIT,
            SYS_FORK,
            SYS_FILE_OPEN_TYPED,
            SYS_IPC_FAST_CALL,
            SYS_I2C_SCAN,
            SYS_CHAN_WRITE_TYPED,
            SYS_CHAN_READ_TYPED,
        ];
        for (i, &a) in nrs.iter().enumerate() {
            for &b in &nrs[i + 1..] {
                assert_ne!(a, b, "syscall numbers collide: {a} vs {b}");
            }
        }
    }
}

/// RFC-0040 gap 1: a retired syscall number is never reused.
///
/// Read from the sources, not restated: `dispatch.rs` for the arms and
/// `syscall_nr.rs` for the names. A retired number that regains an arm (by
/// name, literal or range), a name that takes a retired value, or a retired
/// number that joins `CAP_TYPED_SYSCALLS` fails here without anyone updating a
/// list by hand.
#[cfg(test)]
mod retired_syscalls {
    use azos_abi::syscall_nr::{CAP_TYPED_SYSCALLS, RETIRED_SYSCALLS};
    use std::collections::BTreeMap;

    const DISPATCH: &str = include_str!("../../../../crates/core/syscall/src/dispatch.rs");
    const SYSCALL_NR: &str = include_str!("../../../../crates/core/abi/src/syscall_nr.rs");

    /// The gap-1 names that still carry a retired number. Stage 4 (G1-S4) took
    /// the last of them out of libsys, userspace, the seccomp profiles and
    /// `syscall_nr.rs`, so this list is now empty and stays empty: no `SYS_*`
    /// name may carry a retired value. This list only ever shrinks.
    const PENDING_NAME_REMOVAL: &[(&str, u64)] = &[];

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
        assert!(out.len() > 150, "precondition: the scan read the table ({} names)", out.len());
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

    /// (a) No dispatch arm matches a retired number, whether it names the
    /// constant, writes the literal, or covers it with a range.
    ///
    /// **Canaries.** Put `SYS_GPIO_READ => sys_gpio_read(a0),` back; add a
    /// `200 =>` arm; widen a range arm over a retired number: each is red.
    #[test]
    fn no_dispatch_arm_matches_a_retired_number() {
        let names = names();
        let arms = arms(&names);
        // The scan must see arms of every shape, or green means nothing.
        for probe in ["SYS_EXIT", "SYS_IPC_FAST_CALL", "SYS_CLOSE_TYPED", "SYS_PORT_WAIT_TYPED", "SYS_SERVICE_START"] {
            let v = names[probe];
            assert!(
                arms.iter().any(|a| a.lo <= v && v <= a.hi),
                "precondition: the scan sees the arm of {probe}"
            );
        }
        assert!(arms.iter().any(|a| a.lo < a.hi), "precondition: the scan reads range arms");
        assert!(arms.len() > 150, "precondition: {} arm alternatives", arms.len());
        for &n in RETIRED_SYSCALLS {
            if let Some(a) = arms.iter().find(|a| a.lo <= n && n <= a.hi) {
                panic!("retired number {n} is matched by the dispatch arm pattern `{}`", a.text);
            }
        }
    }

    /// (b) No retired number is a member of `CAP_TYPED_SYSCALLS`.
    ///
    /// **Canary.** Add `SYS_IPC_CREATE` to `CAP_TYPED_SYSCALLS`: red.
    #[test]
    fn no_retired_number_is_a_cap_typed_syscall() {
        for n in RETIRED_SYSCALLS {
            assert!(!CAP_TYPED_SYSCALLS.contains(n), "retired number {n} is in CAP_TYPED_SYSCALLS");
        }
    }

    /// (c) Only a name listed in `PENDING_NAME_REMOVAL` carries a retired
    /// number, and every listed name still exists with its number.
    ///
    /// **Canaries.** Define a new name with value 101: red. Drop one entry
    /// from the list: red. Remove a name from `syscall_nr.rs` but not from the
    /// list: red.
    #[test]
    fn only_names_pending_removal_carry_a_retired_number() {
        let names = names();
        for (name, value) in &names {
            if RETIRED_SYSCALLS.contains(value) {
                assert!(
                    PENDING_NAME_REMOVAL.contains(&(*name, *value)),
                    "`{name}` carries retired number {value}"
                );
            }
        }
        for &(name, value) in PENDING_NAME_REMOVAL {
            assert_eq!(names.get(name), Some(&value), "stale PENDING_NAME_REMOVAL entry `{name}`");
            assert!(RETIRED_SYSCALLS.contains(&value), "`{name}` = {value} is listed but not retired");
        }
    }

    /// (d) `RETIRED_SYSCALLS` is strictly ascending and keeps 116.
    ///
    /// **Canaries.** Swap two entries: red. Drop 116: red.
    #[test]
    fn the_retired_list_is_sorted_without_duplicates_and_keeps_116() {
        assert!(
            RETIRED_SYSCALLS.windows(2).all(|w| w[0] < w[1]),
            "RETIRED_SYSCALLS is not strictly ascending: {RETIRED_SYSCALLS:?}"
        );
        assert!(RETIRED_SYSCALLS.contains(&116), "116 (SYS_CAP_GRANT) left the list");
    }

    /// (d) Every dispatch arm names a number below `SYS_NR_RESERVED_UPPER`.
    /// Dispatch is a table of that many entries (wave 10,
    /// `crates/core/syscall/src/syscall_table.rs`), built by evaluating the arms for
    /// each index: an arm for a number at or past the bound would compile and
    /// never be reached.
    ///
    /// **Canary.** Add a `611 =>` arm (or raise a range past 610): red.
    #[test]
    fn every_dispatch_arm_is_inside_the_table() {
        use azos_abi::syscall_nr::SYS_NR_RESERVED_UPPER;
        let names = names();
        let arms = arms(&names);
        assert!(arms.len() > 150, "precondition: {} arm alternatives", arms.len());
        assert!(
            arms.iter().any(|a| a.hi == names["SYS_DRIVER_REPLY_WAIT"]),
            "precondition: the scan sees the highest arm"
        );
        for a in &arms {
            assert!(
                a.hi < SYS_NR_RESERVED_UPPER,
                "the dispatch arm `{}` ({}..={}) is past the table ({} entries)",
                a.text, a.lo, a.hi, SYS_NR_RESERVED_UPPER
            );
        }
    }
}

/// RFC-0044: the nanosecond ↔ counter conversions shared by the kernel's
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
    fn abi_version_is_v1() {
        assert_eq!(ABI_VERSION, 1);
    }
}

/// `crates/core/abi/src/vdso.rs` — the vDSO placement fix (2026-09-22, RFC-0041
/// M01). Real host-side tests: `crates/core/abi` itself builds under the
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

// Wave 11 (SENSORTS): the stamped sensor sample and the per-task vDSO page's
// layout version 2. Wire layout, so every offset is pinned here.
#[cfg(test)]
mod sensor_sample_tests {
    use azos_abi::sensor_sample::*;
    use azos_abi::vdso::*;

    #[test]
    fn the_header_layout_is_pinned() {
        assert_eq!(SENSOR_SAMPLE_VERSION, 1);
        assert_eq!(SENSOR_SAMPLE_HDR_LEN, 16);
        assert_eq!((SS_OFF_VERSION, SS_OFF_HDR_LEN, SS_OFF_FLAGS), (0, 1, 2));
        assert_eq!((SS_OFF_PAYLOAD_LEN, SS_OFF_ACQ_NS), (4, 8));
        assert_eq!(SENSOR_SAMPLE_FLAG_SYNTHETIC, 1);
        let h = SensorSampleHdr::new(SENSOR_SAMPLE_FLAG_SYNTHETIC, 24, 0x0102_0304_0506_0708);
        let b = h.to_bytes();
        assert_eq!(b, [1, 16, 1, 0, 24, 0, 0, 0, 8, 7, 6, 5, 4, 3, 2, 1]);
        assert_eq!(SensorSampleHdr::from_bytes(&b), Some(h));
    }

    /// A parser refuses what it cannot locate the payload behind: a short
    /// slice, version 0, or a header length below version 1's.
    #[test]
    fn a_header_that_cannot_place_the_payload_is_refused() {
        let b = SensorSampleHdr::new(0, 2, 5).to_bytes();
        assert_eq!(SensorSampleHdr::from_bytes(&b[..15]), None);
        let mut v0 = b;
        v0[SS_OFF_VERSION] = 0;
        assert_eq!(SensorSampleHdr::from_bytes(&v0), None);
        let mut short = b;
        short[SS_OFF_HDR_LEN] = 15;
        assert_eq!(SensorSampleHdr::from_bytes(&short), None);
        // A later version with a longer header still parses: the payload is
        // at its own `hdr_len`.
        let mut v2 = b;
        v2[SS_OFF_VERSION] = 2;
        v2[SS_OFF_HDR_LEN] = 24;
        assert_eq!(SensorSampleHdr::from_bytes(&v2).map(|h| h.hdr_len), Some(24));
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

/// RFC-0055 (wave 11): the user shell's request and startup blocks. The kernel
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
        assert!(bad(&|r| r.flags = 8));
        assert!(bad(&|r| r.argc = 17));
        assert!(bad(&|r| { r.argv_ptr = 8; r.argv_bytes = 1025; }));
        assert!(bad(&|r| r.argv_bytes = 4), "bytes without a pointer");
        assert!(bad(&|r| r.nmoves = 9));
        assert!(bad(&|r| { r.nmoves = 1; r.moves[0].child_fd = 8; }));
        assert!(bad(&|r| { r.nmoves = 2; r.moves[1].child_fd = 0; }), "fd 0 named twice");
        assert!(bad(&|r| { r.nmoves = 1; r.moves[0].perms = 0x10; }));
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

    #[test]
    fn flag_and_limit_values() {
        assert_eq!(PIPE_NONBLOCK, 1);
        assert_eq!(PIPE_ATOMIC, 4096);
        assert_eq!(MOVE_CONSOLE, u32::MAX);
        assert_eq!((KILL_REQUEST, KILL_FORCE, KILL_SUBTREE), (1, 2, 1));
        assert_eq!(KILL_MAX_ANCESTRY, 8);
        assert_eq!((SPAWN_F_DIE_WITH_PARENT, SPAWN_F_MAP_TASK_PAGE), (1, 2));
        assert_eq!((SPAWN_ARGV_MAX, SPAWN_ENV_MAX, SPAWN_ARGC_MAX, SPAWN_ENVC_MAX, SPAWN_CWD_MAX, SPAWN_MAX_MOVES),
                   (1024, 1024, 16, 16, 64, 8));
    }
}

// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host-side tests for `azos_drv_api`.
//!
//! The api crate is `no_std` but architecture-neutral; running its
//! `#[cfg(test)]` blocks inside the crate itself works only on
//! host targets. This excluded crate is the documented entry point.

#[cfg(test)]
mod mmio_range_tests {
    use azos_drv_api::MmioRange;

    #[test]
    fn contains_is_inclusive_at_base() {
        let r = MmioRange::new(0x1000, 0x100);
        assert!(r.contains(0x1000));
        assert!(r.contains(0x10FF));
        assert!(!r.contains(0x1100));
        assert!(!r.contains(0x0FFF));
    }

    #[test]
    fn zero_size_range_contains_nothing() {
        let r = MmioRange::new(0x1000, 0);
        assert!(!r.contains(0x1000));
        assert!(!r.contains(0x0FFF));
    }

    #[test]
    fn saturating_arithmetic_clamps_upper_bound() {
        // Contains uses a half-open `[base, base+size)` interval with
        // saturating add on the upper bound. For a range whose size
        // overflows past u64::MAX, the upper bound clamps to u64::MAX
        // — so u64::MAX itself is *excluded* (it would be the open end).
        let r = MmioRange::new(u64::MAX - 1, 4);
        assert!(r.contains(u64::MAX - 1));
        assert!(!r.contains(u64::MAX));
    }
}

#[cfg(test)]
mod isolation_tests {
    use azos_drv_api::DriverIsolation;

    #[test]
    fn in_kernel_is_not_isolated() {
        assert!(!DriverIsolation::InKernel.is_isolated());
    }

    #[test]
    fn user_process_is_isolated_regardless_of_tid() {
        assert!(DriverIsolation::UserProcess { tid: 0 }.is_isolated());
        assert!(DriverIsolation::UserProcess { tid: 7 }.is_isolated());
        assert!(DriverIsolation::UserProcess { tid: u32::MAX }.is_isolated());
    }

    #[test]
    fn hypervisor_is_isolated() {
        assert!(DriverIsolation::Hypervisor.is_isolated());
    }
}

#[cfg(test)]
mod manifest_tests {
    use azos_abi::cap::CapPerms;
    use azos_drv_api::{
        DriverIsolation, DriverManifest, MmioRange, DRIVER_MANIFEST_VERSION,
    };

    #[test]
    fn new_defaults_mmio_irq_to_none() {
        let m = DriverManifest::new(
            0x42,
            "test",
            DriverIsolation::InKernel,
            CapPerms::RW,
        );
        assert_eq!(m.kind, 0x42);
        assert_eq!(m.name, "test");
        assert_eq!(m.version, DRIVER_MANIFEST_VERSION);
        assert!(m.mmio.is_none());
        assert!(m.irq.is_none());
    }

    #[test]
    fn builder_attaches_mmio_and_irq() {
        let m = DriverManifest::new(
            0x42,
            "test",
            DriverIsolation::InKernel,
            CapPerms::RW,
        )
        .with_mmio(MmioRange::new(0x1000_0000, 0x1000))
        .with_irq(33);
        assert_eq!(m.mmio, Some(MmioRange::new(0x1000_0000, 0x1000)));
        assert_eq!(m.irq, Some(33));
    }

    #[test]
    fn manifest_version_is_frozen_at_one() {
        // Bumping this is an ABI break; this test catches accidents.
        assert_eq!(DRIVER_MANIFEST_VERSION, 1);
    }
}

#[cfg(test)]
mod registry_tests {
    use azos_abi::cap::CapPerms;
    use azos_drv_api::{
        Driver, DriverError, DriverIsolation, DriverManifest, Registry,
        RegistryError, REGISTRY_MAX_DRIVERS,
    };

    struct MockDriver {
        manifest: DriverManifest,
    }

    impl Driver for MockDriver {
        fn manifest(&self) -> &DriverManifest {
            &self.manifest
        }
        fn init(&self) -> Result<(), DriverError> {
            Ok(())
        }
        fn handle_request(
            &self,
            _op: u32,
            _input: &[u8],
            _output: &mut [u8],
        ) -> Result<usize, DriverError> {
            Ok(0)
        }

        fn shutdown(&self) -> Result<(), DriverError> {
            Ok(())
        }
    }

    static MOCK_A: MockDriver = MockDriver {
        manifest: DriverManifest::new(
            0x1234,
            "mock-a",
            DriverIsolation::InKernel,
            CapPerms::RW,
        ),
    };
    static MOCK_B: MockDriver = MockDriver {
        manifest: DriverManifest::new(
            0x5678,
            "mock-b",
            DriverIsolation::UserProcess { tid: 9 },
            CapPerms::READ,
        ),
    };

    #[test]
    fn empty_registry_has_no_drivers() {
        let r = Registry::empty();
        assert!(r.is_empty());
        assert_eq!(r.len(), 0);
        assert!(r.find_by_kind(0).is_none());
    }

    #[test]
    fn register_and_lookup_succeed() {
        let mut r = Registry::empty();
        r.register(&MOCK_A).unwrap();
        r.register(&MOCK_B).unwrap();
        assert_eq!(r.len(), 2);
        assert_eq!(
            r.find_by_kind(0x1234).unwrap().manifest().name,
            "mock-a",
        );
        assert_eq!(
            r.find_by_kind(0x5678).unwrap().manifest().name,
            "mock-b",
        );
        assert!(r.find_by_kind(0x9999).is_none());
    }

    #[test]
    fn duplicate_kind_is_rejected() {
        let mut r = Registry::empty();
        r.register(&MOCK_A).unwrap();
        let err = r.register(&MOCK_A).unwrap_err();
        assert_eq!(err, RegistryError::DuplicateKind);
        assert_eq!(r.len(), 1);
    }

    #[test]
    fn isolation_preserved_through_registry() {
        let mut r = Registry::empty();
        r.register(&MOCK_B).unwrap();
        match r.find_by_kind(0x5678).unwrap().manifest().isolation {
            DriverIsolation::UserProcess { tid } => assert_eq!(tid, 9),
            other => panic!("unexpected isolation: {:?}", other),
        }
    }

    #[test]
    fn registry_capacity_is_thirty_two() {
        // Used as a sanity check — `REGISTRY_MAX_DRIVERS` is part
        // of the framework surface (sized for one driver per
        // `DRV_KIND_*`). Bumping it is fine but visible.
        assert_eq!(REGISTRY_MAX_DRIVERS, 32);
    }
}

/// Owner decision 2026-10-23 (Q2): a record that must survive a power cut
/// (the topology and config anti-rollback floors) is durable only when the
/// device confirmed the flush. A device with no cache control answers
/// `Unsupported`, which used to count as committed; it fails closed now.
///
/// **Canary.** Map `(true, Err(Unsupported))` to `Durable` in
/// `Durability::of` (the old `!matches!(flush, Err(e) if e != Unsupported)`):
/// `an_unsupported_flush_is_not_durable` goes red.
#[cfg(test)]
mod durability_tests {
    use azos_drv_api::block::{Durability, FlushError};

    #[test]
    fn a_confirmed_flush_is_durable() {
        assert_eq!(Durability::of(true, Ok(())), Durability::Durable);
    }

    #[test]
    fn an_unsupported_flush_is_not_durable() {
        assert_eq!(Durability::of(true, Err(FlushError::Unsupported)), Durability::Unconfirmed);
        assert_ne!(Durability::of(true, Err(FlushError::Unsupported)), Durability::Durable);
    }

    #[test]
    fn a_failed_write_or_flush_is_a_failure() {
        assert_eq!(Durability::of(true, Err(FlushError::Io)), Durability::Failed);
        assert_eq!(Durability::of(false, Ok(())), Durability::Failed);
        assert_eq!(Durability::of(false, Err(FlushError::Unsupported)), Durability::Failed);
    }
}

/// The device-timeout policy (`azos_drv_api::recovery`, owner decision
/// 2026-10-23): reset once, then latch dead, and say so. Driven by a fake
/// device that follows the driver contract (stop, confirm, reprogram, tell
/// `reset_done`); the AHCI driver runs the same policy over its HBA model in
/// `drivers-tests` (`ahci_tests`).
#[cfg(test)]
mod recovery_tests {
    use azos_drv_api::block::StallClock;
    use azos_drv_api::recovery::{set_sink, Action, Class, Recovery, TxWatch, Verdict};
    use std::cell::RefCell;

    thread_local! {
        static RECORDS: RefCell<Vec<(Class, Action, u64, u64)>> = const { RefCell::new(Vec::new()) };
    }

    fn sink(c: Class, device: &'static str, a: Action, detail: u64, waited_ms: u64) {
        assert_eq!(device, "fake", "the record names another device");
        RECORDS.with(|r| r.borrow_mut().push((c, a, detail, waited_ms)));
    }

    fn records() -> Vec<(Class, Action, u64, u64)> {
        RECORDS.with(|r| r.borrow().clone())
    }

    /// A device as a driver sees it: commands time out while `wedged`; a
    /// reset unwedges it unless `stays_wedged`.
    struct FakeDev {
        policy: Recovery,
        wedged: bool,
        stays_wedged: bool,
        resets: u32,
    }

    impl FakeDev {
        fn new(budget: u8) -> Self {
            FakeDev { policy: Recovery::new(Class::Block, "fake", budget), wedged: false, stays_wedged: false, resets: 0 }
        }
        /// One command at `sector`: `Ok` when the device answered.
        fn command(&mut self, sector: u64) -> Result<(), &'static str> {
            if self.policy.dead() {
                return Err("dead");
            }
            if !self.wedged {
                return Ok(());
            }
            match self.policy.timed_out(sector, 500) {
                Verdict::Reset => {
                    self.resets += 1;
                    self.wedged = self.stays_wedged;
                    self.policy.reset_done(!self.wedged, sector, 500);
                }
                Verdict::Latch => {}
                Verdict::Handled => {}
            }
            Err("timeout")
        }
    }

    /// **Discriminates.** One timeout: the device is reset, comes back, the
    /// next command runs, and the reset is recorded once. Canary: build the
    /// policy with no reset (`Recovery::new(_, 0)`) or make `timed_out`
    /// latch at once: the second command finds the device dead.
    #[test]
    fn a_device_that_times_out_once_is_reset_and_carries_on() {
        set_sink(sink);
        let mut d = FakeDev::new(1);
        d.wedged = true;
        assert_eq!(d.command(40), Err("timeout"));
        assert_eq!(d.resets, 1);
        assert!(d.policy.live());
        assert_eq!(d.command(41), Ok(()));
        assert_eq!(records(), vec![(Class::Block, Action::Reset, 40, 500)]);
    }

    /// **Discriminates.** A second timeout finds the reset spent: no second
    /// reset, the device latched dead for good, and the latch recorded.
    /// Canary: drop the `spent` test in `timed_out` (it resets again).
    #[test]
    fn a_device_that_times_out_twice_is_latched_dead_and_recorded() {
        set_sink(sink);
        let mut d = FakeDev::new(1);
        d.wedged = true;
        assert_eq!(d.command(1), Err("timeout"));
        d.wedged = true;
        assert_eq!(d.command(2), Err("timeout"));
        assert_eq!(d.resets, 1, "reset twice");
        assert!(d.policy.dead());
        assert_eq!(d.command(3), Err("dead"));
        assert_eq!(records(), vec![(Class::Block, Action::Reset, 1, 500), (Class::Block, Action::Latched, 2, 500)]);
    }

    /// **Discriminates.** The budget is what Kconfig says: 0 latches at the
    /// first timeout (the pre-policy behaviour), 2 resets twice.
    #[test]
    fn the_budget_counts_resets_per_boot() {
        set_sink(sink);
        let mut d = FakeDev::new(0);
        d.wedged = true;
        assert_eq!(d.command(9), Err("timeout"));
        assert!(d.policy.dead());
        assert_eq!(d.resets, 0);
        let mut d = FakeDev::new(2);
        for s in 0..3 {
            d.wedged = true;
            assert_eq!(d.command(s), Err("timeout"));
        }
        assert_eq!((d.resets, d.policy.resets()), (2, 2));
        assert!(d.policy.dead());
        let r = records();
        assert_eq!(r.iter().filter(|e| e.1 == Action::Reset).count(), 2, "{r:?}");
        assert_eq!(r.iter().filter(|e| e.1 == Action::Latched).count(), 2, "{r:?}");
    }

    /// **Discriminates.** A reset that does not bring the device back latches
    /// it dead and records `ResetFailed`, not `Reset`.
    #[test]
    fn a_reset_that_does_not_bring_the_device_back_latches_dead() {
        set_sink(sink);
        let mut d = FakeDev::new(1);
        d.wedged = true;
        d.stays_wedged = true;
        assert_eq!(d.command(5), Err("timeout"));
        assert!(d.policy.dead());
        assert_eq!(records(), vec![(Class::Block, Action::ResetFailed, 5, 500)]);
    }

    /// **Discriminates.** While one caller resets, every other timeout is
    /// `Handled` (no second reset, no latch) and the device is neither live
    /// nor dead: a driver answers `Claim::Busy`. A protocol violation
    /// latches at once and is not the policy's record. Canary: let
    /// `timed_out` act in `RESETTING` (CAS from any state).
    #[test]
    fn a_reset_in_progress_is_handled_once_and_a_latch_is_final() {
        set_sink(sink);
        let p = Recovery::new(Class::Net, "fake", 1);
        assert_eq!(p.timed_out(3, 10), Verdict::Reset);
        assert!(p.resetting() && !p.live() && !p.dead());
        assert_eq!(p.timed_out(3, 10), Verdict::Handled);
        p.reset_done(true, 3, 10);
        assert!(p.live());
        assert!(p.latch());
        assert!(!p.latch(), "only the first latch is the one that latched");
        assert_eq!(p.timed_out(4, 10), Verdict::Handled);
        assert_eq!(records(), vec![(Class::Net, Action::Reset, 3, 10)]);
    }

    /// **Discriminates.** Many harts finding the same timeout: exactly one is
    /// handed the reset.
    #[test]
    fn one_of_many_racing_callers_gets_the_reset() {
        let p = std::sync::Arc::new(Recovery::new(Class::Block, "fake", 1));
        let hs: Vec<_> = (0..8)
            .map(|_| {
                let p = p.clone();
                std::thread::spawn(move || p.timed_out(0, 0))
            })
            .collect();
        let v: Vec<Verdict> = hs.into_iter().map(|h| h.join().unwrap()).collect();
        assert_eq!(v.iter().filter(|&&x| x == Verdict::Reset).count(), 1, "{v:?}");
        assert_eq!(v.iter().filter(|&&x| x == Verdict::Handled).count(), 7, "{v:?}");
    }

    /// **Discriminates.** The transmit ring's budget: an idle ring never
    /// expires; frames that sit past the budget do; a reclaim that frees
    /// something restarts the clock; one that empties the ring stops it;
    /// time the guest did not run is credited. Canary: restart the clock in
    /// `reclaimed` only when the ring empties (a busy, moving ring then
    /// expires).
    #[test]
    fn the_tx_watch_expires_only_on_a_ring_that_does_not_move() {
        let stall = StallClock::new();
        let gap = 50;
        let mut w = TxWatch::new();
        stall.observe(1000, gap);
        assert!(!w.expired(&stall, 1000, 100), "an idle ring");
        w.published(1000, stall.credit());
        w.published(1020, stall.credit());
        stall.observe(1040, gap);
        assert!(!w.expired(&stall, 1040, 100));
        // Progress at 1080: the clock restarts there.
        stall.observe(1080, gap);
        w.reclaimed(1080, stall.credit(), 1, 1);
        stall.observe(1120, gap);
        assert!(!w.expired(&stall, 1150, 100), "a ring that moved was declared wedged");
        stall.observe(1170, gap);
        assert!(w.expired(&stall, 1180, 100), "a ring that stopped moving was not");
        assert_eq!(w.waited(1180), 100);
        // Empty: the clock stops.
        w.reclaimed(1180, stall.credit(), 1, 0);
        assert!(!w.expired(&stall, 9000, 100));
        // A stall of the guest (a 400-tick gap between looks) is credited.
        stall.observe(2000, gap);
        w.published(2000, stall.credit());
        stall.observe(2400, gap);
        assert!(!w.expired(&stall, 2400, 100), "the guest's stop was counted against the ring");
        stall.observe(2450, gap);
        assert!(!w.expired(&stall, 2450, 100));
        stall.observe(2490, gap);
        stall.observe(2510, gap);
        assert!(w.expired(&stall, 2510, 100), "the ring's own 100 ticks after the stop were not counted");
    }
}

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
        /// The mock names no resource: its ops are lifecycle probes, not
        /// hardware addressing. Written out rather than defaulted because the
        /// trait has no default — a driver that decodes a resource and forgets
        /// to say so would be authorised kind-wide, which is the hole this
        /// method closed.
        fn request_resource(&self, _op: u32, _input: &[u8]) -> Option<u32> {
            None
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

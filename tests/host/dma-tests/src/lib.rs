// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
#![cfg(test)]

use azos_dma::*;


// -----------------------------------------------------------------------
// Domains
// -----------------------------------------------------------------------

const RAM: AddrRange = AddrRange::new(0x8000_0000, 0x1_0000_0000);

#[test]
fn identity_domain_returns_the_physical_address_and_rejects_empty_ranges() {
    let mut d = IdentityDomain::new(true);
    assert_eq!(DomainOps::map(&mut d, 0x8000_1000, 0x40, Direction::ToDevice), Ok(DmaAddr(0x8000_1000)));
    assert_eq!(DomainOps::map(&mut d, 0x8000_1000, 0, Direction::ToDevice), Err(DmaError::BadRange));
    assert_eq!(DomainOps::map(&mut d, u64::MAX - 4, 16, Direction::ToDevice), Err(DmaError::BadRange));
    assert_eq!(DomainOps::kind(&d), DomainKind::Identity);
    // The `&self` face answers the same, without a lock.
    assert_eq!(DmaDomain::map(&d, 0x8000_2000, 8, Direction::FromDevice), Ok(DmaAddr(0x8000_2000)));
    // Nothing to start, and no doorbell to open, without hardware.
    assert_eq!(DmaDomain::enable(&d), Ok(()));
    assert_eq!(DmaDomain::allow_msi(&d, 0x2800_0000), Ok(()));
}

#[test]
fn soft_domain_refuses_a_buffer_outside_ram() {
    // One slot: a refused mapping that kept its slot would make the mapping
    // below TableFull.
    let mut d: SoftState<1> = SoftState::new(RAM, FULL_RANGE, true);
    assert_eq!(d.map(0x1000, 0x100, Direction::ToDevice), Err(DmaError::OutsideRam));
    // Starts inside, runs off the end.
    assert_eq!(d.map(0xffff_ff00, 0x200, Direction::ToDevice), Err(DmaError::OutsideRam));
    assert_eq!(d.map(0x8000_0000, 0x1000, Direction::ToDevice), Ok(DmaAddr(0x8000_0000)));
}

#[test]
fn soft_domain_refuses_what_the_device_cannot_address() {
    let dev32 = AddrRange::new(0, 0x1_0000_0000);
    let mut d: SoftState<4> = SoftState::new(AddrRange::new(0x8000_0000, 0x3_0000_0000), dev32, true);
    assert_eq!(d.map(0x2_0000_0000, 0x1000, Direction::FromDevice), Err(DmaError::NeedsBounce));
    // Straddling the 4 GiB line is also out of reach.
    assert_eq!(d.map(0xffff_f000, 0x2000, Direction::FromDevice), Err(DmaError::NeedsBounce));
    assert_eq!(d.map(0x9000_0000, 0x2000, Direction::FromDevice), Ok(DmaAddr(0x9000_0000)));
}

#[test]
fn soft_domain_unmap_needs_the_exact_mapping_and_catches_a_double_unmap() {
    let mut d: SoftState<4> = SoftState::new(RAM, FULL_RANGE, true);
    let bus = d.map(0x8000_4000, 0x200, Direction::Bidirectional).unwrap();
    // A different length is a different (never made) mapping.
    assert_eq!(d.unmap(bus, 0x100), Err(DmaError::NotMapped));
    assert_eq!(d.unmap(bus, 0x200), Ok(()));
    assert_eq!(d.unmap(bus, 0x200), Err(DmaError::NotMapped));
}

#[test]
fn soft_domain_table_full_is_reported_and_a_freed_slot_is_reused() {
    let mut d: SoftState<2> = SoftState::new(RAM, FULL_RANGE, true);
    let a = d.map(0x8000_0000, 0x10, Direction::ToDevice).unwrap();
    d.map(0x8000_1000, 0x10, Direction::ToDevice).unwrap();
    assert_eq!(d.map(0x8000_2000, 0x10, Direction::ToDevice), Err(DmaError::TableFull));
    d.unmap(a, 0x10).unwrap();
    assert_eq!(d.map(0x8000_2000, 0x10, Direction::ToDevice), Ok(DmaAddr(0x8000_2000)));
}

#[test]
fn soft_domain_reports_its_coherence() {
    let c: SoftState<1> = SoftState::new(RAM, FULL_RANGE, true);
    let n: SoftState<1> = SoftState::new(RAM, FULL_RANGE, false);
    assert!(DomainOps::coherent(&c));
    assert!(!DomainOps::coherent(&n));
    assert_eq!(DomainOps::kind(&n), DomainKind::Soft);
}

// -----------------------------------------------------------------------
// Cache maintenance
// -----------------------------------------------------------------------

use azos_dma::cache::{self, CacheOp};

#[test]
fn cache_plan_cleans_for_a_device_read_and_flushes_around_a_device_write() {
    // Device READS the buffer: dirty lines must reach RAM before it starts;
    // nothing to do afterwards.
    assert_eq!(cache::op_for_device(Direction::ToDevice), CacheOp::Clean);
    assert_eq!(cache::op_for_cpu(Direction::ToDevice), CacheOp::None);
    // Device WRITES: drop the CPU's lines before (a later eviction must not
    // overwrite the data) and after (a stale line must not hide it).
    assert_eq!(cache::op_for_device(Direction::FromDevice), CacheOp::Flush);
    assert_eq!(cache::op_for_cpu(Direction::FromDevice), CacheOp::Flush);
    assert_eq!(cache::op_for_device(Direction::Bidirectional), CacheOp::Flush);
    assert_eq!(cache::op_for_cpu(Direction::Bidirectional), CacheOp::Flush);
}

use std::sync::atomic::{AtomicUsize, Ordering};

static CLEANED: AtomicUsize = AtomicUsize::new(0);
static FLUSHED: AtomicUsize = AtomicUsize::new(0);

unsafe fn count_clean(_va: usize, len: usize) {
    CLEANED.fetch_add(len, Ordering::SeqCst);
}
unsafe fn count_flush(_va: usize, len: usize) {
    FLUSHED.fetch_add(len, Ordering::SeqCst);
}

// The installed pair is process-global, so one test owns it end to end.
#[test]
fn sync_runs_the_installed_routines_only_for_a_non_coherent_domain() {
    assert!(!cache::installed());
    cache::install(count_clean, count_flush);
    assert!(cache::installed());

    let coherent = IdentityDomain::new(true);
    let non_coherent = IdentityDomain::new(false);
    unsafe {
        cache::sync_for_device(&coherent, 0x1000, 64, Direction::ToDevice);
        cache::sync_for_cpu(&coherent, 0x1000, 64, Direction::FromDevice);
    }
    assert_eq!((CLEANED.load(Ordering::SeqCst), FLUSHED.load(Ordering::SeqCst)), (0, 0));

    unsafe {
        cache::sync_for_device(&non_coherent, 0x1000, 64, Direction::ToDevice);
        assert_eq!((CLEANED.load(Ordering::SeqCst), FLUSHED.load(Ordering::SeqCst)), (64, 0));
        cache::sync_for_cpu(&non_coherent, 0x1000, 64, Direction::ToDevice);
        assert_eq!((CLEANED.load(Ordering::SeqCst), FLUSHED.load(Ordering::SeqCst)), (64, 0));
        cache::sync_for_cpu(&non_coherent, 0x1000, 128, Direction::FromDevice);
        assert_eq!((CLEANED.load(Ordering::SeqCst), FLUSHED.load(Ordering::SeqCst)), (64, 128));
    }
}

// -----------------------------------------------------------------------
// Registry
// -----------------------------------------------------------------------

use azos_dma::registry::{self, InstallError};

static DEFAULT_DOMAIN: IdentityDomain = IdentityDomain::new(true);
static NIC_DOMAIN: IdentityDomain = IdentityDomain::new(false);

// The registry is process-global, so one test owns it end to end.
#[test]
fn registry_answers_own_then_default_then_fallback() {
    // Nothing installed: an unchecked coherent identity domain.
    assert!(registry::domain_for(Some(0x18)).coherent());
    assert_eq!(registry::domain_for(None).kind(), DomainKind::Identity);

    registry::install_default(&DEFAULT_DOMAIN).unwrap();
    assert_eq!(registry::install_default(&DEFAULT_DOMAIN), Err(InstallError::Taken));
    registry::install_for(0x18, &NIC_DOMAIN).unwrap();
    assert_eq!(registry::install_for(0x18, &DEFAULT_DOMAIN), Err(InstallError::Taken));

    assert!(!registry::domain_for(Some(0x18)).coherent(), "the device has its own domain");
    assert!(registry::domain_for(Some(0x20)).coherent(), "another device falls to the default");
    assert!(registry::domain_for(None).coherent());

    for id in 0..(registry::MAX_BOUND as u32 - 1) {
        registry::install_for(0x100 + id, &NIC_DOMAIN).unwrap();
    }
    assert_eq!(registry::install_for(0x999, &NIC_DOMAIN), Err(InstallError::Full));
}

// -----------------------------------------------------------------------
// Bounce-buffer decision — truth table from RFC-0046 §2.3
// -----------------------------------------------------------------------

#[test]
fn iommu_on_never_bounces_regardless_of_address() {
    let narrow = AddrRange::new(0, 0x1000); // deliberately too small to fit
    assert!(!needs_bounce(true, narrow, 0x1_0000_0000, 0x1000));
}

#[test]
fn iommu_off_bounces_only_when_buffer_does_not_fit_device_range() {
    let range_32bit = AddrRange::new(0, 0x1_0000_0000); // classic 32-bit-only device

    // Fits entirely below 4 GiB -> no bounce.
    assert!(!needs_bounce(false, range_32bit, 0x1000_0000, 0x1000));

    // Starts below 4 GiB but extends past it -> must bounce.
    assert!(needs_bounce(false, range_32bit, 0xffff_f000, 0x2000));

    // Entirely above 4 GiB -> must bounce.
    assert!(needs_bounce(false, range_32bit, 0x2_0000_0000, 0x1000));
}

#[test]
fn addr_range_contains_range_does_not_overflow_near_u64_max() {
    let range = AddrRange::new(0, u64::MAX);
    // addr + len would overflow without the saturating add; the range
    // covers everything, so this must report "fits", not silently wrap
    // to a small number and report "fits" for the wrong reason.
    assert!(range.contains_range(u64::MAX - 10, 5));
    assert!(!range.contains_range(u64::MAX - 3, 10));
}

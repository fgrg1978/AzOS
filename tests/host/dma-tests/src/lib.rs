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
// The order of the maintenance, against a model of the caches
// -----------------------------------------------------------------------
//
// RAM behind a write-back cache. The CPU goes through the cache; a device
// goes to RAM, except that a COHERENT device snoops the cache. The routines
// the drivers run (`sync_*_with`) are the real ones; only the hardware is a
// model, and a model is where a skipped step shows: QEMU's DMA is always
// coherent and would pass the same sequence with the steps removed.

use azos_dma::cache::{sync_for_cpu_with, sync_for_device_with, Maintain};
use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;

const LINE: usize = 64;
const BUF: usize = 0x1000;
const LEN: usize = 4 * LINE;

struct Line {
    data: [u8; LINE],
    dirty: bool,
}

struct Machine {
    ram: RefCell<Vec<u8>>,
    cache: RefCell<BTreeMap<usize, Line>>,
    /// Does the device snoop the CPU's caches?
    device_snoops: bool,
}

impl Machine {
    fn new(device_snoops: bool) -> Self {
        Machine { ram: RefCell::new(vec![0; 0x4000]), cache: RefCell::new(BTreeMap::new()), device_snoops }
    }

    fn fill(&self, line: usize) {
        let mut c = self.cache.borrow_mut();
        c.entry(line).or_insert_with(|| {
            let mut data = [0u8; LINE];
            data.copy_from_slice(&self.ram.borrow()[line * LINE..(line + 1) * LINE]);
            Line { data, dirty: false }
        });
    }

    fn cpu_write(&self, addr: usize, byte: u8) {
        self.fill(addr / LINE);
        let mut c = self.cache.borrow_mut();
        let l = c.get_mut(&(addr / LINE)).unwrap();
        l.data[addr % LINE] = byte;
        l.dirty = true;
    }

    /// A CPU read, or a speculative fetch: it fills the line.
    fn cpu_read(&self, addr: usize) -> u8 {
        self.fill(addr / LINE);
        self.cache.borrow()[&(addr / LINE)].data[addr % LINE]
    }

    fn device_read(&self, addr: usize) -> u8 {
        if self.device_snoops {
            if let Some(l) = self.cache.borrow().get(&(addr / LINE)) {
                return l.data[addr % LINE];
            }
        }
        self.ram.borrow()[addr]
    }

    fn device_write(&self, addr: usize, byte: u8) {
        self.ram.borrow_mut()[addr] = byte;
        if self.device_snoops {
            if let Some(l) = self.cache.borrow_mut().get_mut(&(addr / LINE)) {
                l.data[addr % LINE] = byte;
            }
        }
    }

    fn lines(va: usize, len: usize) -> std::ops::Range<usize> {
        va / LINE..(va + len).div_ceil(LINE)
    }
}

impl Maintain for Machine {
    unsafe fn clean(&self, va: usize, len: usize) {
        for n in Machine::lines(va, len) {
            if let Some(l) = self.cache.borrow_mut().get_mut(&n) {
                if l.dirty {
                    self.ram.borrow_mut()[n * LINE..(n + 1) * LINE].copy_from_slice(&l.data);
                    l.dirty = false;
                }
            }
        }
    }
    unsafe fn flush(&self, va: usize, len: usize) {
        unsafe { self.clean(va, len) };
        for n in Machine::lines(va, len) {
            self.cache.borrow_mut().remove(&n);
        }
    }
}

/// The routines as the drivers meet them, with one call optionally lost: the
/// canary that proves the model notices a missing step.
struct Lossy<'a> {
    inner: &'a Machine,
    lose: Option<usize>,
    calls: Cell<usize>,
}

impl<'a> Lossy<'a> {
    fn keeping_all(inner: &'a Machine) -> Self {
        Lossy { inner, lose: None, calls: Cell::new(0) }
    }
    fn losing(inner: &'a Machine, nth: usize) -> Self {
        Lossy { inner, lose: Some(nth), calls: Cell::new(0) }
    }
    fn pass(&self) -> bool {
        let n = self.calls.get();
        self.calls.set(n + 1);
        self.lose != Some(n)
    }
}

impl Maintain for Lossy<'_> {
    unsafe fn clean(&self, va: usize, len: usize) {
        if self.pass() {
            unsafe { self.inner.clean(va, len) }
        }
    }
    unsafe fn flush(&self, va: usize, len: usize) {
        if self.pass() {
            unsafe { self.inner.flush(va, len) }
        }
    }
}

/// The CPU fills a buffer, the device reads it. `true`: the device saw what
/// the CPU wrote.
fn transmit(m: &Machine, ops: &dyn Maintain, domain: &dyn DmaDomain) -> bool {
    for i in 0..LEN {
        m.cpu_write(BUF + i, (i as u8) | 1);
    }
    unsafe { sync_for_device_with(ops, domain, BUF, LEN, Direction::ToDevice) };
    (0..LEN).all(|i| m.device_read(BUF + i) == (i as u8) | 1)
}

/// The CPU leaves the buffer dirty (it cleared it), the device fills it, the
/// CPU reads. `true`: the CPU saw what the device wrote.
fn receive(m: &Machine, ops: &dyn Maintain, domain: &dyn DmaDomain) -> bool {
    for i in 0..LEN {
        m.cpu_write(BUF + i, 0);
    }
    unsafe { sync_for_device_with(ops, domain, BUF, LEN, Direction::FromDevice) };
    // A prefetch while the transfer runs pulls the old bytes back in.
    m.cpu_read(BUF);
    for i in 0..LEN {
        m.device_write(BUF + i, (i as u8) | 1);
    }
    unsafe { sync_for_cpu_with(ops, domain, BUF, LEN, Direction::FromDevice) };
    (0..LEN).all(|i| m.cpu_read(BUF + i) == (i as u8) | 1)
}

#[test]
fn a_non_coherent_master_sees_the_cpus_data_only_after_the_clean() {
    let domain = IdentityDomain::new(false);
    let m = Machine::new(false);
    let ops = Lossy::keeping_all(&m);
    assert!(transmit(&m, &ops, &domain));
    assert_eq!(ops.calls.get(), 1, "one clean before the device reads");

    // Canary: the clean is the step that matters. Without it the device
    // reads the RAM the CPU's dirty lines never reached.
    let m = Machine::new(false);
    assert!(!transmit(&m, &Lossy::losing(&m, 0), &domain), "dropping the clean must be caught");
}

#[test]
fn a_non_coherent_master_hands_the_cpu_its_data_only_after_the_invalidate() {
    let domain = IdentityDomain::new(false);
    let m = Machine::new(false);
    let ops = Lossy::keeping_all(&m);
    assert!(receive(&m, &ops, &domain));
    assert_eq!(ops.calls.get(), 2, "one before the device writes, one after it finished");

    // Canary 1: the flush after completion. The prefetched stale line stays.
    let m = Machine::new(false);
    assert!(!receive(&m, &Lossy::losing(&m, 1), &domain), "dropping the invalidate after must be caught");

    // Canary 2: the flush before the start. The CPU's dirty zeroes are still
    // in the cache and the completion's write-back puts them over the data.
    let m = Machine::new(false);
    assert!(!receive(&m, &Lossy::losing(&m, 0), &domain), "dropping the flush before must be caught");
}

/// The SiFive cache controller as the kernel installs it: no clean-only
/// operation, so both halves of the pair are the same line-by-line flush.
struct CcacheOps<'a>(&'a Machine);

struct LineFlush<'a>(&'a Machine);

impl azos_dma::ccache::Flush64 for LineFlush<'_> {
    fn flush_line(&self, pa: u64) {
        unsafe { self.0.flush(pa as usize, azos_dma::ccache::LINE as usize) };
    }
}

impl Maintain for CcacheOps<'_> {
    unsafe fn clean(&self, va: usize, len: usize) {
        azos_dma::ccache::flush_range(&LineFlush(self.0), va as u64, len as u64);
    }
    unsafe fn flush(&self, va: usize, len: usize) {
        azos_dma::ccache::flush_range(&LineFlush(self.0), va as u64, len as u64);
    }
}

#[test]
fn the_ccache_line_flush_serves_as_both_the_clean_and_the_flush() {
    let domain = IdentityDomain::new(false);
    let m = Machine::new(false);
    assert!(transmit(&m, &CcacheOps(&m), &domain), "the device must read what the CPU wrote");
    let m = Machine::new(false);
    assert!(receive(&m, &CcacheOps(&m), &domain), "the CPU must read what the device wrote");
    // A buffer that is not line-aligned shares its edge lines: their dirty
    // neighbours must survive the flush (written back, not thrown away).
    let m = Machine::new(false);
    m.cpu_write(BUF + 1, 0x55);
    m.cpu_write(BUF + LEN + 20, 0x66);
    unsafe { CcacheOps(&m).flush(BUF + 8, LEN) };
    assert_eq!(m.ram.borrow()[BUF + 1], 0x55);
    assert_eq!(m.ram.borrow()[BUF + LEN + 20], 0x66);
}

#[test]
fn a_coherent_master_runs_no_maintenance_and_needs_none() {
    let domain = IdentityDomain::new(true);
    let m = Machine::new(true);
    let ops = Lossy::keeping_all(&m);
    assert!(transmit(&m, &ops, &domain));
    assert!(receive(&m, &ops, &domain));
    assert_eq!(ops.calls.get(), 0, "a coherent master skips the maintenance");
}

#[test]
fn declaring_a_non_coherent_master_coherent_is_caught_by_the_model() {
    // Canary for the declaration itself: the domain says coherent, the
    // hardware does not snoop. QEMU would not show it; the model does.
    let domain = IdentityDomain::new(true);
    let m = Machine::new(false);
    let ops = Lossy::keeping_all(&m);
    assert!(!transmit(&m, &ops, &domain));
    let m = Machine::new(false);
    assert!(!receive(&m, &Lossy::keeping_all(&m), &domain));
}

// -----------------------------------------------------------------------
// Registry
// -----------------------------------------------------------------------

use azos_dma::registry::{self, InstallError, MmioView};

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

    // A platform device that differs from the default in coherence only.
    const DISK: u64 = 0x1000_1000;
    assert!(registry::domain_for_mmio(DISK).coherent(), "undeclared: the default's answer");
    registry::declare_mmio(DISK, DISK, MmioView::coherent(false)).unwrap();
    assert_eq!(registry::declare_mmio(DISK, DISK, MmioView::coherent(true)), Err(InstallError::Taken));
    let view = registry::domain_for_mmio(DISK);
    assert!(!view.coherent(), "declared non-coherent over a coherent default");
    assert!(registry::domain_for_mmio(DISK + 0x1000).coherent(), "another device keeps the default");
    assert!(registry::domain_for(None).coherent(), "the default itself is untouched");
    // Same mapping rules as the default, only the coherence differs.
    assert_eq!(view.kind(), DomainKind::Identity);
    assert_eq!(view.map(0x8000_0000, 0x10, Direction::ToDevice), Ok(DmaAddr(0x8000_0000)));
    assert_eq!(view.unmap(DmaAddr(0x8000_0000), 0x10), Ok(()));
    assert_eq!(view.enable(), Ok(()));
    // The bracketing follows the device: the view runs maintenance where the
    // default would not.
    let m = Machine::new(false);
    let ops = Lossy::keeping_all(&m);
    assert!(transmit(&m, &ops, view));
    assert_eq!(ops.calls.get(), 1);
    let m = Machine::new(true);
    let ops = Lossy::keeping_all(&m);
    assert!(transmit(&m, &ops, registry::domain_for_mmio(DISK + 0x1000)));
    assert_eq!(ops.calls.get(), 0);

    // A bus that moves DMA addresses (the Raspberry Pi's `/soc`: bus =
    // CPU + 0xc000_0000 for CPU 0..=0x3eff_ffff), one record for the range
    // of register bases of its devices. Canary: drop the offset in `map` and
    // the controller is handed CPU addresses the VideoCore bus does not see
    // as RAM.
    const SOC: (u64, u64) = (0x3f00_3000, 0x3f98_0000);
    registry::declare_mmio(SOC.0, SOC.1, MmioView::translated(0xc000_0000, 0x3eff_ffff)).unwrap();
    assert_eq!(registry::declare_mmio(0x3f20_0000, 0x3f20_0000, MmioView::coherent(true)), Err(InstallError::Taken),
        "a range holds its devices");
    let usb = registry::domain_for_mmio(0x3f98_0000);
    assert_eq!(usb.map(0x0100_0000, 0x1000, Direction::Bidirectional), Ok(DmaAddr(0xc100_0000)));
    assert_eq!(usb.unmap(DmaAddr(0xc100_0000), 0x1000), Ok(()), "the default sees its own address back");
    assert_eq!(usb.map(0x3eff_f000, 0x2000, Direction::ToDevice), Err(DmaError::NeedsBounce), "past the window");
    assert!(usb.coherent(), "coherence stays the default's");
    assert_eq!(usb.cpu_limit(0xffff_ffff), 0x3eff_ffff, "a 32-bit master: the window bounds it");
    assert_eq!(usb.cpu_limit(0xc0ff_ffff), 0x00ff_ffff);
    assert_eq!(usb.cpu_limit(0x8000_0000), 0, "below the bus window: nothing");
    assert_eq!(usb.phys_of(0xc100_0040), 0x0100_0040, "a bus address back to its CPU address");
    assert_eq!(registry::domain_for_mmio(DISK).phys_of(0x1234), 0x1234, "an identity bus");
    assert_eq!(registry::domain_for_mmio(0x4000_0000).map(0x1000, 0x10, Direction::ToDevice), Ok(DmaAddr(0x1000)),
        "outside the range: the default");

    for k in 2..registry::MAX_MMIO as u64 {
        registry::declare_mmio(DISK + 0x2000 * (k + 1), DISK + 0x2000 * (k + 1), MmioView::coherent(true)).unwrap();
    }
    assert_eq!(registry::declare_mmio(0x9999, 0x9999, MmioView::coherent(true)), Err(InstallError::Full));
}

// -----------------------------------------------------------------------
// Bounce-buffer decision — truth table
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

// -----------------------------------------------------------------------
// Allocation under a device's DMA mask
// -----------------------------------------------------------------------

mod below {
    use azos_dma::alloc::MAX_MISSES;
    use azos_dma::*;
    use std::cell::RefCell;

    const PAGE: usize = 0x1000;

    /// A page source that hands out a fixed list of addresses in order, and
    /// records what was taken and given back.
    struct Fake {
        queue: RefCell<Vec<u64>>,
        allocs: RefCell<usize>,
        freed: RefCell<Vec<u64>>,
    }

    impl Fake {
        fn new(pages: &[u64]) -> Self {
            let mut q = pages.to_vec();
            q.reverse();
            Fake { queue: RefCell::new(q), allocs: RefCell::new(0), freed: RefCell::new(vec![]) }
        }
    }

    impl PageSource for Fake {
        fn alloc(&self, _len: usize) -> Option<u64> {
            *self.allocs.borrow_mut() += 1;
            self.queue.borrow_mut().pop()
        }
        fn free(&self, pa: u64, _len: usize) {
            self.freed.borrow_mut().push(pa);
        }
    }

    const MASK32: u64 = 0xffff_ffff;

    #[test]
    fn a_page_above_the_mask_is_held_then_given_back_when_a_low_one_turns_up() {
        let s = Fake::new(&[0x2_0000_0000, 0x1_0000_0000, 0x7000_0000]);
        assert_eq!(alloc_below(&s, MASK32, PAGE), Ok(0x7000_0000));
        assert_eq!(*s.freed.borrow(), [0x2_0000_0000, 0x1_0000_0000], "the misses, and only them");
        assert_eq!(*s.allocs.borrow(), 3);
    }

    #[test]
    fn the_page_must_end_under_the_mask_not_just_start_there() {
        // 0xffff_f000 + 0x1000 ends at 4 GiB: fits; 0xffff_f800 + 0x1000 does not.
        let s = Fake::new(&[0xffff_f800, 0xffff_f000]);
        assert_eq!(alloc_below(&s, MASK32, PAGE), Ok(0xffff_f000));
        assert_eq!(*s.freed.borrow(), [0xffff_f800]);
    }

    #[test]
    fn nothing_under_the_mask_is_a_refusal_that_leaks_nothing() {
        let high: Vec<u64> = (0..100).map(|i| 0x1_0000_0000 + i * PAGE as u64).collect();
        let s = Fake::new(&high);
        assert_eq!(alloc_below(&s, MASK32, PAGE), Err(DmaError::NeedsBounce));
        assert_eq!(*s.allocs.borrow(), MAX_MISSES + 1, "bounded: the source is not drained");
        let mut freed = s.freed.borrow().clone();
        freed.sort();
        assert_eq!(freed, high[..MAX_MISSES + 1], "every block taken went back");
    }

    #[test]
    fn a_dry_source_is_no_memory_and_the_misses_still_go_back() {
        let s = Fake::new(&[0x1_0000_0000, 0x1_0000_1000]);
        assert_eq!(alloc_below(&s, MASK32, PAGE), Err(DmaError::NoMemory));
        assert_eq!(s.freed.borrow().len(), 2);
        let empty = Fake::new(&[]);
        assert_eq!(alloc_below(&empty, MASK32, PAGE), Err(DmaError::NoMemory));
        assert_eq!(alloc_below(&empty, u64::MAX, PAGE), Err(DmaError::NoMemory));
    }

    #[test]
    fn no_mask_is_one_allocation_and_no_check() {
        let s = Fake::new(&[0x40_0000_0000, 0x1000]);
        assert_eq!(alloc_below(&s, u64::MAX, PAGE), Ok(0x40_0000_0000));
        assert_eq!(*s.allocs.borrow(), 1);
        assert!(s.freed.borrow().is_empty());
    }

    #[test]
    fn a_page_under_the_mask_at_once_frees_nothing() {
        let s = Fake::new(&[0x8000_0000]);
        assert_eq!(alloc_below(&s, MASK32, PAGE), Ok(0x8000_0000));
        assert!(s.freed.borrow().is_empty());
    }

    #[test]
    fn a_zero_length_is_a_bad_range_and_takes_nothing() {
        let s = Fake::new(&[0x1000]);
        assert_eq!(alloc_below(&s, MASK32, 0), Err(DmaError::BadRange));
        assert_eq!(*s.allocs.borrow(), 0);
    }

    #[test]
    fn a_mask_smaller_than_the_block_refuses_everything() {
        let s = Fake::new(&[0x0, 0x1000]);
        assert_eq!(alloc_below(&s, 0xfff, PAGE * 2), Err(DmaError::NeedsBounce));
        assert_eq!(*s.allocs.borrow(), 0, "no allocation can fit, so none is made");
        // The refusal `azos_dtb::DMA_UNREACHABLE` (mask 0) asks for.
        assert_eq!(alloc_below(&s, 0, PAGE), Err(DmaError::NeedsBounce));
        assert_eq!(*s.allocs.borrow(), 0);
        // A block exactly as long as the reach still fits at 0.
        assert_eq!(alloc_below(&s, 0xfff, PAGE), Ok(0));
    }
}

// -----------------------------------------------------------------------
// SiFive composable cache: the Flush64 line walk
// -----------------------------------------------------------------------

mod ccache_walk {
    use azos_dma::ccache::{flush_range, Flush64, LINE};
    use std::cell::RefCell;

    /// Records every line the walk flushes, in order.
    struct Recorder(RefCell<Vec<u64>>);

    impl Recorder {
        fn new() -> Self {
            Recorder(RefCell::new(Vec::new()))
        }
        fn lines(&self) -> Vec<u64> {
            self.0.borrow().clone()
        }
    }

    impl Flush64 for Recorder {
        fn flush_line(&self, pa: u64) {
            self.0.borrow_mut().push(pa);
        }
    }

    #[test]
    fn an_aligned_range_flushes_exactly_its_lines_in_order() {
        let r = Recorder::new();
        assert_eq!(flush_range(&r, 0x8000_1000, 4 * LINE), 4);
        assert_eq!(r.lines(), vec![0x8000_1000, 0x8000_1040, 0x8000_1080, 0x8000_10c0]);
    }

    #[test]
    fn the_edge_lines_are_flushed_whole() {
        // Starts 8 bytes into a line and ends 8 bytes into another: three
        // lines, the first and the last shared with neighbours.
        let r = Recorder::new();
        assert_eq!(flush_range(&r, 0x8000_1008, 2 * LINE), 3);
        assert_eq!(r.lines(), vec![0x8000_1000, 0x8000_1040, 0x8000_1080]);
    }

    #[test]
    fn a_range_inside_one_line_is_one_flush() {
        let r = Recorder::new();
        assert_eq!(flush_range(&r, 0x8000_1010, 4), 1);
        assert_eq!(r.lines(), vec![0x8000_1000]);
        // The last byte of a line is still that line, the next byte is not.
        let r = Recorder::new();
        assert_eq!(flush_range(&r, 0x8000_103f, 1), 1);
        assert_eq!(r.lines(), vec![0x8000_1000]);
        let r = Recorder::new();
        assert_eq!(flush_range(&r, 0x8000_103f, 2), 2);
        assert_eq!(r.lines(), vec![0x8000_1000, 0x8000_1040]);
    }

    #[test]
    fn a_range_ending_on_a_line_boundary_does_not_touch_the_next_line() {
        let r = Recorder::new();
        assert_eq!(flush_range(&r, 0x8000_1000, LINE), 1);
        assert_eq!(r.lines(), vec![0x8000_1000]);
    }

    #[test]
    fn a_zero_length_writes_nothing() {
        let r = Recorder::new();
        assert_eq!(flush_range(&r, 0x8000_1000, 0), 0);
        assert!(r.lines().is_empty());
    }

    #[test]
    fn a_range_running_off_the_address_space_stops_at_its_last_line() {
        // Without the saturation the walk would wrap to 0 and never end.
        let r = Recorder::new();
        let n = flush_range(&r, u64::MAX - 2 * LINE + 1, 4 * LINE);
        assert_eq!(n, 2);
        assert_eq!(r.lines(), vec![u64::MAX - 2 * LINE + 1, u64::MAX - LINE + 1]);
    }

    #[test]
    fn a_page_is_sixty_four_lines() {
        let r = Recorder::new();
        assert_eq!(flush_range(&r, 0x8000_2000, 4096), 64);
        let lines = r.lines();
        assert_eq!(lines[0], 0x8000_2000);
        assert_eq!(*lines.last().unwrap(), 0x8000_2fc0);
        assert!(lines.windows(2).all(|w| w[1] == w[0] + LINE));
    }
}

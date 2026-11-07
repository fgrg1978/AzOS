// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! DMA domains at boot (Kconfig "DMA and IOMMU").
//!
//! Every driver that does DMA reaches memory through a domain
//! (`crates/drivers/dma`, `azos_drv_virtio::virtio::Dma`). [`dma_init`] runs
//! first, before any virtio device is touched, and installs the DEFAULT
//! domain: software-checked or identity (Kconfig `DMA_DOMAIN_*`), coherent
//! unless `DMA_NONCOHERENT` (a device the firmware declares `dma-coherent` is
//! then recorded as coherent, [`declare_coherent_devices`]), in which case it also installs the arch's cache
//! maintenance and refuses to boot where there is none (a non-coherent
//! machine without it corrupts data silently). virtio-mmio devices and every
//! PCI function without a domain of their own use the default.
//!
//! With an `iommu-*` feature (Kconfig IOMMU_*, on by default), [`iommu_init`]
//! runs in the PCI bring-up, after enumeration and before any PCI driver: it
//! finds the IOMMU (the hardware bus's `riscv-iommu` PCI function on riscv64,
//! its `smmuv3` device-tree node on aarch64, the ACPI DMAR / IVRS on x86_64;
//! none: no IOMMU, said once), brings it up and places every enumerated
//! function by what its driver can take (`hw::Placement`):
//!
//! - a driver that maps every DMA through its domain gets a translating
//!   domain of its own: the driver maps its buffers, then `Dma::enable`
//!   points the unit at the domain's page table, and from then on a DMA to a
//!   page nobody mapped is refused and logged by the fault task;
//! - a driver that hands its device physical addresses (NVMe, AHCI) leaves
//!   the function in pass-through, said per function (the NVMe driver reads
//!   only its domain's coherence, to sync its pages);
//! - a function no kernel driver binds is blocked. A ring-3 driver of it
//!   that maps memory for it (`DEVICE_DMA_MAP`) gets a translating domain
//!   of its own then ([`ring3_domain`]), pointed at an empty table before
//!   its first mapping: the device reaches what ring 3 mapped and nothing
//!   else.
//!
//! The first two stay in pass-through until their driver has run. Once every
//! PCI driver had its turn, [`iommu_settle`] blocks each function none of them
//! took and only then says which ones translate.
//!
//! IOMMU_BYPASS puts every function in pass-through instead.

use azos_dma::{AddrRange, DmaAddr, DmaDomain, DmaError, Direction, DomainKind, DomainOps, IdentityDomain, SoftState, FULL_RANGE};
use azos_sync::SpinLock;

use crate::kprintln;

/// Live mappings one domain records (Kconfig `DMA_MAP_ENTRIES`).
const ENTRIES: usize = azos_limits::DMA_MAP_ENTRIES as usize;

/// Are the devices cache-coherent with the CPU?
const COHERENT: bool = !azos_limits::DMA_NONCOHERENT;

/// A [`DomainOps`] behind a lock: the `&self` domain a driver holds. Empty
/// until [`Locked::set`]; an empty one refuses every mapping.
pub(crate) struct Locked<S>(SpinLock<Option<S>>);

impl<S> Locked<S> {
    pub(crate) const fn empty() -> Self {
        Locked(SpinLock::new(None))
    }

    pub(crate) fn set(&self, domain: S) {
        *self.0.lock() = Some(domain);
    }

    /// `f` of the domain in this slot, if it holds one.
    #[cfg(any(feature = "iommu-riscv", feature = "iommu-smmuv3", feature = "iommu-vtd", feature = "iommu-amdvi"))]
    fn with<T>(&self, f: impl FnOnce(&S) -> T) -> Option<T> {
        self.0.lock().as_ref().map(f)
    }
}

impl<S: DomainOps + Send> DmaDomain for Locked<S> {
    fn map(&self, pa: u64, len: usize, dir: Direction) -> Result<DmaAddr, DmaError> {
        self.0.lock().as_mut().ok_or(DmaError::Iommu)?.map(pa, len, dir)
    }
    fn unmap(&self, bus: DmaAddr, len: usize) -> Result<(), DmaError> {
        self.0.lock().as_mut().ok_or(DmaError::Iommu)?.unmap(bus, len)
    }
    fn coherent(&self) -> bool {
        COHERENT
    }
    fn kind(&self) -> DomainKind {
        match self.0.lock().as_ref() {
            Some(d) => d.kind(),
            None => DomainKind::Identity,
        }
    }
    fn enable(&self) -> Result<(), DmaError> {
        self.0.lock().as_mut().ok_or(DmaError::Iommu)?.enable()
    }
    fn allow_msi(&self, doorbell: u64) -> Result<(), DmaError> {
        self.0.lock().as_mut().ok_or(DmaError::Iommu)?.allow_msi(doorbell)
    }
}

static SOFT: Locked<SoftState<ENTRIES>> = Locked::empty();
static IDENTITY: IdentityDomain = IdentityDomain::new(COHERENT);

/// Install the arch's cache maintenance, if it has any (riscv64: Zicbom,
/// probed, else the SiFive composable cache the device tree names; aarch64:
/// always; x86_64: not needed). `false`: none.
#[cfg(any(target_arch = "riscv64", target_arch = "aarch64"))]
fn install_cache_ops() -> bool {
    if azos_arch::cache::cmo_available() {
        azos_dma::cache::install(azos_arch::cache::cmo_clean, azos_arch::cache::cmo_flush);
        return true;
    }
    #[cfg(target_arch = "riscv64")]
    {
        ccache::install()
    }
    #[cfg(not(target_arch = "riscv64"))]
    {
        false
    }
}

/// x86_64: the masters are coherent, there is nothing to install.
#[cfg(not(any(target_arch = "riscv64", target_arch = "aarch64")))]
fn install_cache_ops() -> bool {
    false
}

/// The SiFive composable cache controller as the maintenance backend of a
/// core without Zicbom (the JH7110's U74): `Flush64` by physical line
/// (`azos_dma::ccache`) for both halves of the pair.
#[cfg(target_arch = "riscv64")]
mod ccache {
    use crate::kprintln;

    /// The device tree `compatible` strings of the controller.
    const COMPATIBLE: [&str; 2] = ["starfive,jh7110-ccache", "sifive,ccache0"];

    struct Regs;

    impl azos_dma::ccache::Flush64 for Regs {
        fn flush_line(&self, pa: u64) {
            // SAFETY: `install` selected the controller before the pair
            // below was installed; `flush_range` hands over line-aligned
            // addresses of the range the caller gave.
            unsafe { azos_arch::cache::ccache_flush_line(pa) }
        }
    }

    /// Both halves of the pair: `Flush64` writes back and drops, and a flush
    /// where a clean would do costs a refill, never data.
    unsafe fn maintain(va: usize, len: usize) {
        let pa = azos_mm::addr::virt_to_phys(va) as u64;
        azos_dma::ccache::flush_range(&Regs, pa, len as u64);
    }

    /// Find the controller on the hardware bus, map its window and install
    /// the pair. `false`: the tree names none, or its window did not map.
    pub(super) fn install() -> bool {
        let found = azos_drv_bus::hwbus::with(|bus| {
            bus.iter()
                .find(|(_, s)| s.dev.compatible().any(|c| COMPATIBLE.contains(&c)))
                .map(|(_, s)| (s.dev.base as usize, s.dev.size as usize))
        });
        let Some((base, size)) = found else { return false };
        if size <= azos_dma::ccache::FLUSH64 + 8 || !crate::boot::map_mmio_region(base, size) {
            azos_drv_sys::kwarn!("[DMA] cache controller at {:#x}: window not usable", base);
            return false;
        }
        azos_arch::cache::ccache_select(base + azos_dma::ccache::FLUSH64);
        azos_dma::cache::install(maintain, maintain);
        kprintln!("[DMA] cache maintenance: SiFive cache controller at {:#x}, Flush64 per {}-byte line", base, azos_dma::ccache::LINE);
        true
    }
}

/// Record, from what the hardware bus found, the platform devices that differ
/// from the default domain ([`azos_dma::registry::declare_mmio`]): those whose
/// DMA the firmware declared cache-coherent (device tree `dma-coherent`) on a
/// platform whose default is not, so their drivers skip the cache
/// maintenance; and those behind a bus whose `dma-ranges` moves their DMA
/// addresses (a Raspberry Pi's VideoCore bus sees RAM at 0xc000_0000), so
/// every address their drivers hand them carries the offset. A device cannot
/// be less coherent than a coherent default. Counted so the boot log shows
/// what the firmware said.
fn declare_mmio_devices() {
    use azos_dma::registry::MmioView;
    let view_of = |d: &azos_drv_bus::hwbus::Device| -> Option<MmioView> {
        let declare_coherent = !COHERENT && d.dma_coherent;
        if d.base == 0 || (!declare_coherent && d.dma_offset == 0) {
            return None;
        }
        Some(MmioView {
            coherent: declare_coherent.then_some(true),
            offset: d.dma_offset,
            cpu_limit: if d.dma_offset == 0 { u64::MAX } else { d.dma_mask },
        })
    };
    let (mut coherent, mut translated, mut refused) = (0u32, 0u32, 0u32);
    azos_drv_bus::hwbus::with(|bus| {
        // One record per run of devices that share a view: the smallest range
        // of register bases holding them, if no device with another view (or
        // none) starts inside it; else one record per device.
        let mut done = [0u64; 64];
        let mut ndone = 0usize;
        for (_, slot) in bus.iter() {
            let Some(view) = view_of(&slot.dev) else { continue };
            if done[..ndone].contains(&slot.dev.base) {
                continue;
            }
            let same = |d: &azos_drv_bus::hwbus::Device| view_of(d) == Some(view);
            let (lo, hi) = bus.iter().filter(|(_, s)| same(&s.dev))
                .fold((u64::MAX, 0), |(lo, hi), (_, s)| (lo.min(s.dev.base), hi.max(s.dev.base)));
            let clean = !bus.iter().any(|(_, s)| !same(&s.dev) && s.dev.base != 0 && lo <= s.dev.base && s.dev.base <= hi);
            let (lo, hi) = if clean { (lo, hi) } else { (slot.dev.base, slot.dev.base) };
            let members = bus.iter().filter(|(_, s)| same(&s.dev) && lo <= s.dev.base && s.dev.base <= hi).count() as u32;
            match azos_dma::registry::declare_mmio(lo, hi, view) {
                Ok(()) => {
                    if view.coherent.is_some() {
                        coherent += members;
                    }
                    if view.offset != 0 {
                        translated += members;
                        kprintln!("[DMA] devices at {:#x}..={:#x}: bus address = CPU address + {:#x}, CPU 0..={:#x} (dma-ranges)",
                            lo, hi, view.offset, view.cpu_limit);
                    }
                }
                Err(_) => refused += members,
            }
            for (_, s) in bus.iter().filter(|(_, s)| same(&s.dev) && lo <= s.dev.base && s.dev.base <= hi) {
                if ndone < done.len() {
                    done[ndone] = s.dev.base;
                    ndone += 1;
                }
            }
        }
    });
    if !COHERENT || translated != 0 {
        kprintln!("[DMA] {} device(s) declared dma-coherent by the firmware, {} behind a translating bus, {} not recorded",
            coherent, translated, refused);
    }
}

/// Install the default domain over RAM `[ram.0, ram.1)`. Before the first
/// virtio device is probed (the entropy seed reads one).
pub(crate) fn dma_init(ram: (u64, u64)) {
    if !COHERENT && !install_cache_ops() {
        crate::boot::isa::refuse_text(
            "[DMA] DMA_NONCOHERENT is set but this machine has no cache maintenance (riscv64: Zicbom, \
             see RV_ZICBOM, or a SiFive cache controller in the device tree): refusing to boot rather \
             than corrupt DMA data",
        );
    }
    declare_mmio_devices();
    let coherence = if COHERENT { "coherent" } else { "non-coherent, cache maintenance on" };
    let installed = if azos_limits::DMA_DOMAIN_SOFT {
        SOFT.set(SoftState::new(AddrRange::new(ram.0, ram.1), FULL_RANGE, COHERENT));
        azos_dma::registry::install_default(&SOFT)
    } else {
        azos_dma::registry::install_default(&IDENTITY)
    };
    if installed.is_err() {
        azos_drv_sys::kerr!("[DMA] a default domain was already installed");
        return;
    }
    if azos_limits::DMA_DOMAIN_SOFT {
        kprintln!("[DMA] default domain: software-checked over RAM {:#x}..{:#x}, {} mappings, {}",
            ram.0, ram.1, ENTRIES, coherence);
    } else {
        kprintln!("[DMA] default domain: identity (unchecked), {}", coherence);
    }
    // The gate's refusal rows withhold the acceptance for one boot.
    let unconfined = azos_limits::DMA_RING3_WITHOUT_IOMMU && !canary!("dma-ring3-refusal");
    RING3_UNCONFINED.store(unconfined, core::sync::atomic::Ordering::Release);
    azos_ipc::mmio_cap::set_writable_master_policy(ring3_window_policy);
    azos_ipc::dma_bind::set_hooks(azos_ipc::dma_bind::Hooks {
        domain: ring3_domain,
        quiesce: ring3_quiesce,
        unconfined,
        report: ring3_report,
    });
    if unconfined {
        azos_drv_sys::kwarn!("[DMA] ring 3 may master the bus without an IOMMU (DMA_RING3_WITHOUT_IOMMU): \
                              a ring-3 driver of such a device is kernel-trust; each binding is recorded");
    } else {
        kprintln!("[DMA] ring 3 masters the bus only behind an IOMMU: memory for any other device is refused");
    }
}

/// Ring 3 may give memory to, and hold writable, a device no IOMMU confines
/// (Kconfig `DMA_RING3_WITHOUT_IOMMU`, unless withheld for the boot).
static RING3_UNCONFINED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// May ring 3 hold the registers of device `dev`, which masters the bus,
/// writable (a topology grant of its window or of the ports of its I/O BARs):
/// only where an IOMMU will confine it, or the build accepts that its driver
/// is kernel-trust. A refusal is said here and recorded by the caller
/// (`Rule::Ring3Dma`, why 4 and 5).
fn ring3_window_policy(dev: u32) -> bool {
    if RING3_UNCONFINED.load(core::sync::atomic::Ordering::Acquire) || ring3_confinable(dev) || canary!("dma-ring3-window-anyway") {
        return true;
    }
    azos_drv_sys::kwarn!("[DMA] device {}: its registers refused to ring 3: it masters the bus and no IOMMU confines it", dev);
    false
}

/// Will an IOMMU confine device `dev` for ring 3: a PCI function while one is
/// up (`hw::ring3_domain` gives it a translating domain of its own).
fn ring3_confinable(dev: u32) -> bool {
    use azos_drv_bus::hwbus::{self, BusKind, Handle};
    let Some(d) = hwbus::with(|b| b.get(Handle(dev)).map(|s| s.dev)) else { return false };
    #[cfg(any(feature = "iommu-riscv", feature = "iommu-smmuv3", feature = "iommu-vtd", feature = "iommu-amdvi"))]
    if d.kind == BusKind::Pci {
        let rid = azos_pci::Bdf::new(d.pci.bus, d.pci.device, d.pci.function).requester_id();
        return hw::iommu_up() && hw::confinable(rid);
    }
    let _ = (d, BusKind::Pci);
    false
}

/// The console line of a ring-3 binding's end.
fn ring3_report(e: azos_ipc::dma_bind::Ended) {
    use azos_ipc::dma_bind::Outcome;
    let at = if e.exit { "the exit" } else { "the unmap" };
    match e.outcome {
        Outcome::Released => kprintln!("[DMA] device {}: {} of tid {} ended its binding, {} bytes back", e.dev, at, e.tid, e.bytes),
        Outcome::NotStopped | Outcome::UnmapFailed | Outcome::MapUnconfirmed => azos_drv_sys::kerr!(
            "[DMA] device {}: {} of tid {}: {} bytes kept from the allocator ({}); no ring-3 memory for it until the next boot",
            e.dev, at, e.tid, e.bytes,
            match e.outcome {
                Outcome::NotStopped => "it could not be shown stopped",
                Outcome::UnmapFailed => "the domain's unmap failed",
                _ => "the domain's flush after the map failed",
            }),
    }
}

/// The domain a ring-3 driver maps memory for the device `dev` (a hardware
/// bus handle) through: a PCI function's own translating domain while an
/// IOMMU is up (made on first use), else the domain the registry gives the
/// device, as it would a kernel driver. `None`: an IOMMU is up and the
/// function cannot have a domain of its own, so nothing it is given would
/// reach it.
fn ring3_domain(dev: u32, live: bool) -> Option<&'static dyn DmaDomain> {
    use azos_drv_bus::hwbus::{self, BusKind, Handle};
    let d = hwbus::with(|b| b.get(Handle(dev)).map(|s| s.dev))?;
    // Read only by an IOMMU's domains.
    let _ = live;
    match d.kind {
        // Without PCI support the bus holds no function.
        #[cfg(not(feature = "pci"))]
        BusKind::Pci => None,
        #[cfg(feature = "pci")]
        BusKind::Pci => {
            let rid = azos_pci::Bdf::new(d.pci.bus, d.pci.device, d.pci.function).requester_id();
            #[cfg(any(feature = "iommu-riscv", feature = "iommu-smmuv3", feature = "iommu-vtd", feature = "iommu-amdvi"))]
            if hw::iommu_up() {
                return hw::ring3_domain(rid, live);
            }
            Some(azos_dma::registry::domain_for(Some(rid)))
        }
        BusKind::Dt | BusKind::VirtioMmio => Some(azos_dma::registry::domain_for_mmio(d.base)),
    }
}

/// Stop the device `dev` a ring-3 driver left behind from issuing DMA, where
/// no IOMMU confines it: a virtio-mmio transport is reset and the reset
/// confirmed. Any other device cannot be shown stopped here (`false`), and
/// the memory it was given stays out of the allocator.
fn ring3_quiesce(dev: u32) -> bool {
    use azos_drv_bus::hwbus::{self, BusKind, Handle};
    let Some(d) = hwbus::with(|b| b.get(Handle(dev)).map(|s| s.dev)) else { return false };
    if d.kind != BusKind::VirtioMmio || d.base == 0 {
        return false;
    }
    #[cfg(not(any(feature = "vf2", feature = "k1")))]
    {
        // SAFETY: the transport window the enumerator read, which the kernel
        // keeps mapped; a reset touches only its status register.
        unsafe { azos_drv_virtio::virtio::reset_confirmed(d.base as *mut u32) }
    }
    #[cfg(any(feature = "vf2", feature = "k1"))]
    {
        false
    }
}

#[cfg(any(
    feature = "iommu-riscv",
    feature = "iommu-smmuv3",
    feature = "iommu-vtd",
    feature = "iommu-amdvi"
))]
pub(crate) use hw::{fault_task, iommu_init, iommu_settle, iommu_up};

#[cfg(any(
    feature = "iommu-riscv",
    feature = "iommu-smmuv3",
    feature = "iommu-vtd",
    feature = "iommu-amdvi"
))]
mod hw {
    use core::sync::atomic::{AtomicBool, Ordering};

    use azos_iommu::domain::IoDomain;
    use azos_iommu::{
        AttachLog, Attached, DmaFault, DomainMode, Flavour, IommuError, IommuUnit, PtFormat, Settled, TableMem, UnitHandle,
    };
    #[cfg(feature = "iommu-vtd")]
    use azos_drvkit::Mmio;
    #[cfg(not(all(feature = "iommu-smmuv3", feature = "hyp-monitor")))]
    use azos_drvkit::Window;
    use azos_sync::SpinLock;

    use super::{Locked, COHERENT, ENTRIES};
    use crate::kprintln;

    /// The unit's registers at a mapped base.
    #[cfg(not(all(feature = "iommu-smmuv3", feature = "hyp-monitor")))]
    fn registers(base: usize) -> Window {
        // SAFETY: `base` is a mapped device window and the units name only
        // registers inside it (the span is mapped before the first use).
        unsafe { Window::new(base) }
    }

    /// Table, queue and page-table memory from the page allocator.
    struct KMem;

    impl KMem {
        /// The CPU's pointer to physical address `pa`: the direct map.
        fn ptr(pa: u64) -> *mut u8 {
            azos_mm::addr::phys_to_virt(pa as usize) as *mut u8
        }
    }

    impl TableMem for KMem {
        fn alloc_page(&self) -> Option<u64> {
            azos_mm::pmm::alloc_page().ok().map(|p| p.as_usize() as u64)
        }
        fn alloc_aligned(&self, bytes: usize, align: usize) -> Option<u64> {
            let page = azos_arch::PAGE_SIZE;
            azos_mm::pmm::alloc_contiguous_aligned(bytes.div_ceil(page), align.max(page))
                .ok()
                .map(|p| p.as_usize() as u64)
        }
        fn read64(&self, pa: u64, idx: usize) -> u64 {
            // SAFETY: `pa` is table memory this module allocated (the trait's
            // contract), which the direct map covers; `idx` is inside it.
            unsafe { core::ptr::read_volatile((Self::ptr(pa) as *const u64).add(idx)) }
        }
        fn write64(&self, pa: u64, idx: usize, val: u64) {
            // SAFETY: as `read64`.
            unsafe { core::ptr::write_volatile((Self::ptr(pa) as *mut u64).add(idx), val) }
        }
        fn clean(&self, pa: u64, len: usize) {
            // A unit that does not snoop the CPU's caches reads what the CPU
            // wrote back; the machines whose DMA masters don't are the ones
            // whose IOMMU doesn't either.
            if !COHERENT {
                // SAFETY: the range is table memory this module allocated.
                unsafe { azos_dma::cache::clean_installed(Self::ptr(pa) as usize, len) };
            }
        }
        fn invalidate(&self, pa: u64, len: usize) {
            // Drop the lines a unit that does not snoop wrote around: the
            // queues it writes are clean in the cache (`TableMem::invalidate`),
            // so the write-back half of the flush writes nothing.
            if !COHERENT {
                // SAFETY: as `clean` above.
                unsafe { azos_dma::cache::flush_installed(Self::ptr(pa) as usize, len) };
            }
        }
    }

    static MEM: KMem = KMem;

    /// One unit, shared by the domains and the fault task behind a lock.
    struct Shared<U>(SpinLock<Option<U>>);

    impl<U> Shared<U> {
        const fn empty() -> Self {
            Shared(SpinLock::new(None))
        }
    }

    impl<U: IommuUnit + Send> UnitHandle for Shared<U> {
        fn attach(&self, dev: u32, mode: DomainMode) -> Result<(), IommuError> {
            match self.0.lock().as_mut() {
                Some(u) => u.attach(dev, mode),
                None => Err(IommuError::Unsupported("no unit")),
            }
        }
        fn flush(&self, dev: u32) -> Result<(), IommuError> {
            match self.0.lock().as_mut() {
                Some(u) => u.flush(dev),
                None => Err(IommuError::Unsupported("no unit")),
            }
        }
        fn poll_faults(&self, sink: &mut dyn FnMut(DmaFault)) -> usize {
            match self.0.lock().as_mut() {
                Some(u) => u.poll_faults(sink),
                None => 0,
            }
        }
    }

    #[cfg(feature = "iommu-riscv")]
    static RISCV: Shared<azos_iommu::riscv::RiscvIommu<Window>> = Shared::empty();
    #[cfg(all(feature = "iommu-smmuv3", not(feature = "hyp-monitor")))]
    static SMMUV3: Shared<azos_iommu::smmuv3::Smmuv3<Window>> = Shared::empty();
    // VIRT_SPLIT: the monitor owns the unit.
    #[cfg(all(feature = "iommu-smmuv3", feature = "hyp-monitor"))]
    static SMMUV3: Shared<azos_iommu::smmuv3::Smmuv3Remote<crate::entry::aarch64::ext::hyp_monitor::SmmuCalls>> = Shared::empty();
    #[cfg(feature = "iommu-vtd")]
    static VTD: Shared<azos_iommu::vtd::Vtd<Window>> = Shared::empty();
    #[cfg(feature = "iommu-amdvi")]
    static AMDVI: Shared<azos_iommu::amdvi::AmdVi<Window>> = Shared::empty();

    /// The translating domains, one per function whose driver maps its DMA
    /// (Kconfig `IOMMU_DOMAINS`).
    const DOMAINS: usize = azos_limits::IOMMU_DOMAINS as usize;
    static POOL: [Locked<IoDomain<ENTRIES>>; DOMAINS] = [const { Locked::empty() }; DOMAINS];
    /// `POOL[i]` was handed to ring 3 (`ring3_domain`).
    static RING3: [AtomicBool; DOMAINS] = [const { AtomicBool::new(false) }; DOMAINS];

    /// How the unit has each PCI function attached, as it accepted it.
    static ATTACHED: SpinLock<AttachLog<{ azos_limits::PCI_MAX_FUNCTIONS as usize }>> = SpinLock::new(AttachLog::new());

    fn attached(rid: u32, how: Attached) {
        if !ATTACHED.lock().note(rid, how) {
            azos_drv_sys::kwarn!("[IOMMU] {:#06x}: attach not recorded (PCI_MAX_FUNCTIONS): no writable window for ring 3", rid);
        }
    }

    /// The drivers that map every DMA of their function through its domain
    /// (`azos_dma::registry::domain_for`) and call `enable` once their
    /// buffers are mapped: the functions they bind get a translating domain.
    /// The other kernel drivers of PCI functions (NVMe, AHCI) hand their
    /// device physical addresses.
    const MAPS_ITS_DMA: [&str; 6] = ["virtio-net-pci", "virtio-gpu-pci", "virtio-snd-pci", "e1000e", "igc", "xhci"];

    /// Where a function's DMA goes.
    enum Placement {
        /// A translating domain of its own; pass-through until its driver
        /// calls `enable` (the MSI-X self-tests drive the NIC with physical
        /// addresses before its driver runs).
        Translate(&'static str),
        /// Untranslated, and why.
        Bypass(&'static str),
        /// Every DMA refused.
        Block,
    }

    /// Where function `rid`, which the native table gives `driver`, goes.
    fn placement(rid: u32, driver: Option<&'static str>, own: Option<u32>) -> Placement {
        if azos_limits::IOMMU_BYPASS {
            return Placement::Bypass("IOMMU_BYPASS");
        }
        if own == Some(rid) {
            // Its own table walks are not translated by itself.
            return Placement::Bypass("the IOMMU itself");
        }
        match driver {
            Some(d) if MAPS_ITS_DMA.contains(&d) => Placement::Translate(d),
            Some(_) => Placement::Bypass("its driver hands the device physical addresses"),
            None => Placement::Block,
        }
    }

    /// What [`ring3_domain`] builds a domain from: the unit and its
    /// page-table format, kept by `iommu_init`.
    #[derive(Clone, Copy)]
    struct Unit {
        unit: &'static dyn UnitHandle,
        flavour: Flavour,
        fmt: PtFormat,
        coherent: bool,
        own: Option<u32>,
    }
    static UNIT: SpinLock<Option<Unit>> = SpinLock::new(None);

    /// The translating domain of PCI function `rid` for its ring-3 driver:
    /// its own, if it has one, else a free one of the pool, pointed at its
    /// still empty table before it is handed out (the function reaches
    /// nothing until ring 3 maps memory in it). `None`: the IOMMU's own
    /// function, a function a kernel driver's domain is for, or no domain
    /// left (Kconfig `IOMMU_DOMAINS`).
    /// Will the unit confine function `rid` for ring 3: it can have a ring-3
    /// domain at all (not the unit's own, not under IOMMU_BYPASS) and is
    /// attached blocked or translating now.
    pub(crate) fn confinable(rid: u32) -> bool {
        UNIT.lock().is_some_and(|u| u.own != Some(rid)) && !azos_limits::IOMMU_BYPASS && ATTACHED.lock().confines(rid)
    }

    pub(crate) fn ring3_domain(rid: u32, live: bool) -> Option<&'static dyn azos_dma::DmaDomain> {
        let u = (*UNIT.lock())?;
        if u.own == Some(rid) || azos_limits::IOMMU_BYPASS {
            return None;
        }
        // One maker at a time: two first maps of one function make one domain.
        static MAKING: SpinLock<()> = SpinLock::new(());
        let _one = MAKING.lock();
        if let Some(i) = POOL.iter().position(|s| s.with(|d| d.dev() == rid) == Some(true)) {
            // The function's domain from before: ring 3's own (its bindings
            // live in it), or a kernel driver's, unbound, handed out only
            // translating and empty, so nothing that driver left is reachable.
            let ring3_live = live && RING3[i].load(Ordering::Acquire);
            let ok = POOL[i].with(|d| azos_dma::bind::reuse_for_ring3(d.enabled(), d.is_empty(), ring3_live)) == Some(true);
            if ok {
                RING3[i].store(true, Ordering::Release);
                attached(rid, Attached::Translate);
            }
            return ok.then_some(&POOL[i] as &'static dyn azos_dma::DmaDomain);
        }
        let i = POOL.iter().position(|s| s.with(|_| ()).is_none())?;
        let slot = &POOL[i];
        let mut d = IoDomain::<ENTRIES>::new(rid, u.flavour, u.fmt, u.unit, &MEM, u.coherent).ok()?;
        if azos_dma::DomainOps::enable(&mut d).is_err() {
            azos_drv_sys::kerr!("[IOMMU] {:#06x}: ring-3 domain refused by the unit", rid);
            return None;
        }
        slot.set(d);
        RING3[i].store(true, Ordering::Release);
        attached(rid, Attached::Translate);
        if azos_dma::registry::install_for(rid, slot).is_err() {
            azos_drv_sys::kerr!("[IOMMU] {:#06x}: ring-3 domain not recorded (registry full)", rid);
        }
        kprintln!("[IOMMU] {:#06x}: translating for its ring-3 driver", rid);
        Some(slot)
    }

    /// The unit the fault task drains.
    static FAULTS: SpinLock<Option<&'static dyn UnitHandle>> = SpinLock::new(None);
    /// The unit's own requester id, when it is a PCI function.
    static OWN: SpinLock<Option<u32>> = SpinLock::new(None);
    static UP: AtomicBool = AtomicBool::new(false);

    /// Is an IOMMU being driven (so there is a fault task to create)?
    pub(crate) fn iommu_up() -> bool {
        UP.load(Ordering::Acquire)
    }

    /// What `init` found: the unit, ready, with the page-table format its
    /// domains must build.
    struct Found {
        unit: &'static dyn UnitHandle,
        flavour: Flavour,
        fmt: PtFormat,
        coherent: bool,
        /// The unit's own requester id, when it is a PCI function.
        own: Option<u32>,
    }

    /// Put a freshly built unit in its static and describe it.
    fn found<U: IommuUnit + Send + 'static>(
        slot: &'static Shared<U>,
        unit: U,
        base: usize,
        own: Option<u32>,
    ) -> Found {
        let (flavour, fmt) = (unit.flavour(), unit.pt_format());
        *slot.0.lock() = Some(unit);
        kprintln!("[IOMMU] {} at {:#x}: {:?} page tables, {} levels", flavour.name(), base, fmt.kind, fmt.levels);
        // The page-table walker snoops the CPU's caches when the devices do.
        Found { unit: slot, flavour, fmt, coherent: COHERENT, own }
    }

    // A flavour's feature is for its own ISA (Kconfig `depends on`).
    #[cfg(any(
        all(feature = "iommu-riscv", not(target_arch = "riscv64")),
        all(feature = "iommu-smmuv3", not(target_arch = "aarch64")),
        all(any(feature = "iommu-vtd", feature = "iommu-amdvi"), not(target_arch = "x86_64")),
    ))]
    compile_error!("an iommu-* feature of another ISA is enabled");

    /// RISC-V IOMMU: the PCI function the hardware bus gives `riscv-iommu`
    /// (class 0x0806, crates/drivers/iommu/hwbus.ids), BAR 0 the registers.
    #[cfg(feature = "iommu-riscv")]
    fn bring_up<C: azos_pci::ConfigSpace>(
        cfg: &mut C,
        funcs: &[Option<azos_pci::FunctionInfo>],
        window: &mut azos_pci::BarWindow,
    ) -> Option<Found> {
        let Some(info) = crate::boot::hwbus::function_for("riscv-iommu", funcs) else {
            kprintln!("[IOMMU] no riscv-iommu PCI function: PCI DMA is not confined");
            return None;
        };
        let bars = match azos_drv_virtio::virtio::pci::msix_selftest::map_bars(cfg, info, window) {
            Ok(b) => b,
            Err(e) => {
                kprintln!("[IOMMU] riscv-iommu {}: BAR not usable: {:?}", info.bdf, e);
                return None;
            }
        };
        let base = bars[0];
        if base == 0 {
            kprintln!("[IOMMU] riscv-iommu {}: no register BAR", info.bdf);
            return None;
        }
        match azos_iommu::riscv::RiscvIommu::new(registers(base), &MEM) {
            Ok(u) => Some(found(&RISCV, u, base, Some(info.bdf.requester_id()))),
            Err(e) => {
                kprintln!("[IOMMU] riscv-iommu at {:#x} not used: {:?}", base, e);
                None
            }
        }
    }

    /// SMMUv3: the device-tree node the hardware bus gives `smmuv3`
    /// (`arm,smmu-v3`, crates/drivers/iommu/hwbus.ids), its `reg` window the
    /// registers (two 64 KiB register pages and more).
    #[cfg(feature = "iommu-smmuv3")]
    fn bring_up<C: azos_pci::ConfigSpace>(
        _cfg: &mut C,
        funcs: &[Option<azos_pci::FunctionInfo>],
        _window: &mut azos_pci::BarWindow,
    ) -> Option<Found> {
        let Some((base, size)) = crate::boot::hwbus::window_for("smmuv3") else {
            kprintln!("[IOMMU] no arm,smmu-v3 node in the device tree: PCI DMA is not confined");
            return None;
        };
        let base = base as usize;
        // Page 1 holds the event queue's index registers. A split image never
        // maps them: the monitor owns the unit.
        if (size as usize) < 0x2_0000 || (!cfg!(feature = "hyp-monitor") && !crate::boot::map_mmio_region(base, size as usize)) {
            kprintln!("[IOMMU] smmuv3 at {:#x}: window {:#x} not usable", base, size);
            return None;
        }
        // The highest requester id the stream table must hold (bus 0 only today).
        let max_dev = funcs.iter().flatten().map(|f| f.bdf.requester_id()).max().unwrap_or(0);
        #[cfg(not(feature = "hyp-monitor"))]
        let unit = azos_iommu::smmuv3::Smmuv3::new(registers(base), &MEM, max_dev);
        #[cfg(feature = "hyp-monitor")]
        let unit = azos_iommu::smmuv3::Smmuv3Remote::new(
            crate::entry::aarch64::ext::hyp_monitor::SmmuCalls, &MEM, base as u64, size as u64, max_dev);
        match unit {
            Ok(u) => Some(found(&SMMUV3, u, base, None)),
            Err(e) => {
                kprintln!("[IOMMU] smmuv3 at {:#x} not used: {:?}", base, e);
                None
            }
        }
    }

    /// VT-d, else AMD-Vi: the register base from the ACPI table.
    #[cfg(any(feature = "iommu-vtd", feature = "iommu-amdvi"))]
    fn bring_up<C: azos_pci::ConfigSpace>(
        _cfg: &mut C,
        funcs: &[Option<azos_pci::FunctionInfo>],
        _window: &mut azos_pci::BarWindow,
    ) -> Option<Found> {
        let (dmar, ivhd) = crate::boot_hooks::iommu_unit_bases();
        let _ = (dmar, ivhd, funcs);
        #[cfg(feature = "iommu-vtd")]
        if let Some(base) = dmar.map(|b| b as usize) {
            // The capability registers lie in the first page and say how many
            // the rest take.
            if !crate::boot::map_mmio_region(base, 0x1000) {
                azos_drv_sys::kerr!("[IOMMU] vt-d at {:#x} not used: registers not mapped", base);
                return None;
            }
            let mmio = registers(base);
            let span = azos_iommu::vtd::register_span(mmio.read64(azos_iommu::vtd::REG_CAP), mmio.read64(azos_iommu::vtd::REG_ECAP));
            if !crate::boot::map_mmio_region(base, span) {
                azos_drv_sys::kerr!("[IOMMU] vt-d at {:#x} not used: {:#x} bytes of registers not mapped", base, span);
                return None;
            }
            return match azos_iommu::vtd::Vtd::new(mmio, &MEM, span) {
                Ok(u) => Some(found(&VTD, u, base, None)),
                Err(e) => {
                    kprintln!("[IOMMU] vt-d at {:#x} not used: {:?}", base, e);
                    None
                }
            };
        }
        #[cfg(feature = "iommu-amdvi")]
        if let Some(base) = ivhd.map(|b| b as usize) {
            if !crate::boot::map_mmio_region(base, 0x4000) {
                return None;
            }
            let max_dev = funcs.iter().flatten().map(|f| f.bdf.requester_id()).max().unwrap_or(0);
            return match azos_iommu::amdvi::AmdVi::new(registers(base), &MEM, max_dev) {
                Ok(u) => Some(found(&AMDVI, u, base, None)),
                Err(e) => {
                    kprintln!("[IOMMU] amd-vi at {:#x} not used: {:?}", base, e);
                    None
                }
            };
        }
        kprintln!("[IOMMU] no DMAR/IVRS unit in the ACPI tables");
        None
    }

    /// Bring up the IOMMU and place every function ([`Placement`]). A refusal
    /// is a line: a function whose entry the unit refused stays as a fresh
    /// unit has every function, blocked; one whose domain could not be built
    /// stays in pass-through. Nothing translates yet: [`iommu_settle`] says
    /// what came of it.
    pub(crate) fn iommu_init<C: azos_pci::ConfigSpace>(
        cfg: &mut C,
        funcs: &[Option<azos_pci::FunctionInfo>],
        window: &mut azos_pci::BarWindow,
    ) {
        let Some(f) = bring_up(cfg, funcs, window) else { return };

        let mut pool = POOL.iter();
        for info in funcs.iter().flatten() {
            let rid = info.bdf.requester_id();
            let place = placement(rid, crate::boot::hwbus::driver_of(info), f.own);
            let mode = if matches!(place, Placement::Block) { DomainMode::Block } else { DomainMode::Bypass };
            if let Err(e) = f.unit.attach(rid, mode) {
                azos_drv_sys::kerr!("[IOMMU] {}: {:?} refused: {:?}", info.bdf, mode, e);
                continue;
            }
            attached(rid, mode.into());
            match place {
                Placement::Translate(driver) => match install(&f, rid, pool.next()) {
                    Ok(()) => kprintln!("[IOMMU] {} {}: domain ready, pass-through until its driver enables it", info.bdf, driver),
                    Err(why) => {
                        azos_drv_sys::kwarn!("[IOMMU] {} {}: DMA NOT translated (pass-through): {}",
                                             info.bdf, driver, why);
                    }
                },
                // Said per function, so the summary is not read as protection.
                Placement::Bypass(why) => {
                    azos_drv_sys::kwarn!("[IOMMU] {}: DMA NOT translated (pass-through): {}", info.bdf, why);
                }
                Placement::Block => {
                    kprintln!("[IOMMU] {}: DMA blocked (no kernel driver)", info.bdf);
                }
            }
        }

        *OWN.lock() = f.own;
        *FAULTS.lock() = Some(f.unit);
        *UNIT.lock() = Some(Unit { unit: f.unit, flavour: f.flavour, fmt: f.fmt, coherent: f.coherent, own: f.own });
        UP.store(true, Ordering::Release);
    }

    /// Every PCI driver had its turn: a function none of them took goes to
    /// Block, whatever it was placed as (its hardware may be why the driver
    /// gave up, and it must not keep every page), and the log says where each
    /// function really is. The unit's own function and IOMMU_BYPASS stay out.
    pub(crate) fn iommu_settle(funcs: &[Option<azos_pci::FunctionInfo>]) {
        let Some(unit) = *FAULTS.lock() else { return };
        let own = *OWN.lock();
        let (mut translated, mut passed, mut blocked) = (0, 0, 0);
        for info in funcs.iter().flatten() {
            let rid = info.bdf.requester_id();
            let driver = crate::boot::hwbus::driver_of(info);
            match placement(rid, driver, own) {
                Placement::Block => {
                    blocked += 1;
                    continue;
                }
                Placement::Bypass(_) if azos_limits::IOMMU_BYPASS || own == Some(rid) => {
                    passed += 1;
                    continue;
                }
                _ => {}
            }
            let enabled = POOL.iter().any(|s| s.with(|d| d.dev() == rid && d.enabled()) == Some(true));
            // Canary: a function whose driver gave up keeps what the boot gave it.
            let bound = crate::boot::hwbus::pci_bound(info) || canary!("iommu-fail-open");
            match azos_iommu::settle(bound, enabled) {
                Settled::Translating => {
                    translated += 1;
                    kprintln!("[IOMMU] {} {}: translating", info.bdf, driver.unwrap_or("?"));
                }
                Settled::PassThrough => passed += 1,
                Settled::Blocked => match unit.attach(rid, DomainMode::Block) {
                    Ok(()) => {
                        attached(rid, Attached::Block);
                        blocked += 1;
                        kprintln!("[IOMMU] {}: DMA blocked (its driver did not bind)", info.bdf);
                    }
                    Err(e) => {
                        passed += 1;
                        azos_drv_sys::kerr!("[IOMMU] {}: no driver, Block refused, DMA NOT confined: {:?}", info.bdf, e);
                    }
                },
            }
        }
        kprintln!("[IOMMU] {} function(s) translating, {} in pass-through, {} blocked", translated, passed, blocked);
    }

    /// Give function `rid` the translating domain in `slot` and install it
    /// for its driver to find.
    fn install(
        f: &Found,
        rid: u32,
        slot: Option<&'static Locked<IoDomain<ENTRIES>>>,
    ) -> Result<(), &'static str> {
        let slot = slot.ok_or("no translating domain left (IOMMU_DOMAINS)")?;
        let d = IoDomain::<ENTRIES>::new(rid, f.flavour, f.fmt, f.unit, &MEM, f.coherent)
            .map_err(|_| "no memory for its page table")?;
        slot.set(d);
        azos_dma::registry::install_for(rid, slot).map_err(|_| "the domain registry is full or taken")
    }

    /// Drain the unit's fault log every `IOMMU_FAULT_POLL_MS` and print what
    /// it refused. The units' own interrupts stay off.
    pub(crate) fn fault_task(_arg: usize) {
        let period = azos_drv_sys::timebase::TIMER_FREQ * azos_limits::IOMMU_FAULT_POLL_MS as u64 / 1000;
        let mut total = 0u32;
        loop {
            let end = azos_drv_sys::timebase::now() + period.max(1);
            while azos_drv_sys::timebase::now() < end {
                azos_sched::task_block(azos_sched::WaitReason::Timer(end));
            }
            let Some(unit) = *FAULTS.lock() else { continue };
            let mut shown = 0;
            unit.poll_faults(&mut |f: DmaFault| {
                total = total.wrapping_add(1);
                if shown < 16 {
                    shown += 1;
                    kprintln!("[IOMMU] fault: device {:#06x} addr {:#x} {:?} (#{})",
                        f.device_id, f.fault_addr, f.kind, total);
                }
            });
        }
    }
}

#[cfg(feature = "ktest")]
mod unmap_ktests {
    use azos_dma::{Direction, DmaAddr, DmaDomain, DmaError, DomainKind, PageSource};

    struct Frames;
    impl PageSource for Frames {
        fn alloc(&self, _len: usize) -> Option<u64> {
            azos_mm::pmm::alloc_page().ok().map(|p| p.as_usize() as u64)
        }
        fn free(&self, pa: u64, _len: usize) {
            let _ = azos_mm::pmm::free_page(azos_mm::addr::PhysAddr::new(pa as usize));
        }
    }

    /// A domain whose IOTLB flush never completes.
    struct StuckFlush;
    impl DmaDomain for StuckFlush {
        fn map(&self, pa: u64, _len: usize, _dir: Direction) -> Result<DmaAddr, DmaError> {
            Ok(DmaAddr(pa))
        }
        fn unmap(&self, _bus: DmaAddr, _len: usize) -> Result<(), DmaError> {
            Err(DmaError::Iommu)
        }
        fn coherent(&self) -> bool {
            true
        }
        fn kind(&self) -> DomainKind {
            DomainKind::Identity
        }
        fn enable(&self) -> Result<(), DmaError> {
            Ok(())
        }
        fn allow_msi(&self, _doorbell: u64) -> Result<(), DmaError> {
            Ok(())
        }
    }

    azos_ktest::ktest_late! {
        fn dma_failed_unmap_keeps_the_frame() {
            azos_dma::canary_free_anyway(canary!("dma-unmap-frees"));
            let page = azos_arch::PAGE_SIZE;
            let Some(pa) = Frames.alloc(page) else { return Err("no frame") };
            let leaked = azos_dma::leaked_bytes();
            let r = azos_dma::unmap_and_free(&StuckFlush, &Frames, pa, DmaAddr(pa), page);
            azos_dma::canary_free_anyway(false);
            if azos_mm::pmm::range_is_free(pa as usize, page) {
                return Err("a frame the device can still reach went back to the allocator");
            }
            if r.is_ok() || azos_dma::leaked_bytes() != leaked + page as u64 {
                return Err("the kept frame was not counted");
            }
            Frames.free(pa, page);
            Ok(())
        }
    }
}

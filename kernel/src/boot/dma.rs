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
//! - a function no kernel driver binds is blocked: ring 3 has no DMA path
//!   yet, so nothing it drives can need one.
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
}

#[cfg(any(
    feature = "iommu-riscv",
    feature = "iommu-smmuv3",
    feature = "iommu-vtd",
    feature = "iommu-amdvi"
))]
pub(crate) use hw::{fault_task, iommu_init, iommu_up};

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
        DmaFault, DomainMode, Flavour, IommuError, IommuUnit, Mmio, PtFormat, TableMem, UnitHandle,
    };
    use azos_sync::SpinLock;

    use super::{Locked, COHERENT, ENTRIES};
    use crate::kprintln;

    /// Volatile register access at a mapped base.
    struct KMmio {
        base: usize,
    }

    impl Mmio for KMmio {
        fn read32(&self, off: usize) -> u32 {
            // SAFETY: `base` is a mapped device window and `off` a register of it.
            unsafe { azos_arch_api::mmio::read32(self.base + off) }
        }
        fn write32(&self, off: usize, val: u32) {
            // SAFETY: as `read32`.
            unsafe { azos_arch_api::mmio::write32(self.base + off, val) }
        }
        fn read64(&self, off: usize) -> u64 {
            // SAFETY: as `read32`; the 64-bit registers are 8-byte aligned.
            unsafe { azos_arch_api::mmio::read64(self.base + off) }
        }
        fn write64(&self, off: usize, val: u64) {
            // SAFETY: as `read64`.
            unsafe { azos_arch_api::mmio::write64(self.base + off, val) }
        }
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
    static RISCV: Shared<azos_iommu::riscv::RiscvIommu<KMmio>> = Shared::empty();
    #[cfg(feature = "iommu-smmuv3")]
    static SMMUV3: Shared<azos_iommu::smmuv3::Smmuv3<KMmio>> = Shared::empty();
    #[cfg(feature = "iommu-vtd")]
    static VTD: Shared<azos_iommu::vtd::Vtd<KMmio>> = Shared::empty();
    #[cfg(feature = "iommu-amdvi")]
    static AMDVI: Shared<azos_iommu::amdvi::AmdVi<KMmio>> = Shared::empty();

    /// The translating domains, one per function whose driver maps its DMA
    /// (Kconfig `IOMMU_DOMAINS`).
    const DOMAINS: usize = azos_limits::IOMMU_DOMAINS as usize;
    static POOL: [Locked<IoDomain<ENTRIES>>; DOMAINS] = [const { Locked::empty() }; DOMAINS];

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

    /// The unit the fault task drains.
    static FAULTS: SpinLock<Option<&'static dyn UnitHandle>> = SpinLock::new(None);
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
        match azos_iommu::riscv::RiscvIommu::new(KMmio { base }, &MEM) {
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
        // Page 1 holds the event queue's index registers.
        if (size as usize) < 0x2_0000 || !crate::boot::map_mmio_region(base, size as usize) {
            kprintln!("[IOMMU] smmuv3 at {:#x}: window {:#x} not usable", base, size);
            return None;
        }
        // The highest requester id the stream table must hold (bus 0 only today).
        let max_dev = funcs.iter().flatten().map(|f| f.bdf.requester_id()).max().unwrap_or(0);
        match azos_iommu::smmuv3::Smmuv3::new(KMmio { base }, &MEM, max_dev) {
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
            if !crate::boot::map_mmio_region(base, 0x1000) {
                return None;
            }
            return match azos_iommu::vtd::Vtd::new(KMmio { base }, &MEM) {
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
            return match azos_iommu::amdvi::AmdVi::new(KMmio { base }, &MEM, max_dev) {
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
    /// stays in pass-through.
    pub(crate) fn iommu_init<C: azos_pci::ConfigSpace>(
        cfg: &mut C,
        funcs: &[Option<azos_pci::FunctionInfo>],
        window: &mut azos_pci::BarWindow,
    ) {
        let Some(f) = bring_up(cfg, funcs, window) else { return };

        let mut pool = POOL.iter();
        let (mut translated, mut passed, mut blocked) = (0, 0, 0);
        for info in funcs.iter().flatten() {
            let rid = info.bdf.requester_id();
            let place = placement(rid, crate::boot::hwbus::driver_of(info), f.own);
            let mode = if matches!(place, Placement::Block) { DomainMode::Block } else { DomainMode::Bypass };
            if let Err(e) = f.unit.attach(rid, mode) {
                azos_drv_sys::kerr!("[IOMMU] {}: {:?} refused: {:?}", info.bdf, mode, e);
                continue;
            }
            match place {
                Placement::Translate(driver) => match install(&f, rid, pool.next()) {
                    Ok(()) => {
                        translated += 1;
                        kprintln!("[IOMMU] {} {}: translating domain installed", info.bdf, driver);
                    }
                    Err(why) => {
                        passed += 1;
                        azos_drv_sys::kwarn!("[IOMMU] {} {}: DMA NOT translated (pass-through): {}",
                                             info.bdf, driver, why);
                    }
                },
                // Said per function, so the summary is not read as protection.
                Placement::Bypass(why) => {
                    passed += 1;
                    azos_drv_sys::kwarn!("[IOMMU] {}: DMA NOT translated (pass-through): {}", info.bdf, why);
                }
                Placement::Block => {
                    blocked += 1;
                    kprintln!("[IOMMU] {}: DMA blocked (no kernel driver)", info.bdf);
                }
            }
        }
        kprintln!("[IOMMU] {} function(s) translating, {} in pass-through, {} blocked", translated, passed, blocked);

        *FAULTS.lock() = Some(f.unit);
        UP.store(true, Ordering::Release);
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

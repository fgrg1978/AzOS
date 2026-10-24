// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The PCI host bridge at boot (Kconfig DRV_PCI; with PCI_SOC_HOST, kernel
//! feature `pci-soc-host`, also the SoC controllers that firmware does not
//! bring up).
//!
//! [`KernelConfigSpace`] is the configuration space `kernel_main` enumerates:
//!
//! - an ECAM window (QEMU `virt`, any `pci-host-ecam-generic` tree) or, on
//!   x86_64 without an ECAM, the legacy port pair;
//! - a SoC host bridge this module brought up ([`soc_host`]): the JH7110's
//!   PLDA root port (VisionFive 2) and the BCM2712's root complex (Raspberry
//!   Pi 5), the two controllers `azos_pci::host` has flows for;
//! - nothing ([`KernelConfigSpace::absent`]): a bridge was found and would
//!   not come up, so no function is enumerated behind it.
//!
//! # The SoC bring-up, in order
//!
//! 1. The bridge is the hardware-bus device whose `compatible` names a
//!    controller (`azos_pci::host::dt::Controller`); its node is read through
//!    the SoC frameworks' view of the tree: named `reg` ranges, `ranges`,
//!    `dma-ranges`, and for the PLDA flow the STG syscon, the PCI domain and
//!    the `perst-gpios` pin.
//! 2. `boot::soc::bind` gives the node what it names: power domains, clocks,
//!    resets (deasserted) and the `default` pin state. An entry whose provider
//!    the image does not model is skipped by the frameworks and counted: the
//!    JH7110's STG clocks and PCIe PHY are not modelled, so the bring-up
//!    relies on the firmware (U-Boot) having left them running, and the boot
//!    line says how many entries were skipped.
//! 3. The register blocks are mapped ([`KernelBus`]): the controller's APB
//!    registers, the STG syscon, the configuration window (one bus slice; the
//!    rest as bridges are found).
//! 4. `plda::init` / `brcmstb::init` run the controller's flow (PERST# held,
//!    windows programmed, PERST# released, link waited for). A link that stays
//!    down is a line and no enumeration: it never falls back to the QEMU
//!    `virt` addresses, which on these boards are other hardware.

use azos_pci::{ecam_address, ecam_function_offset, Bdf, ConfigSpace};
use crate::*;

/// Bytes of ECAM one bus occupies.
const BUS_SLICE: usize = 0x10_0000;

/// Where a bus's configuration registers are reached, and how a bus the
/// enumerator found behind a bridge is made reachable (its slice of the
/// window mapped).
#[derive(Clone, Copy)]
pub(crate) enum BusMapper {
    /// Port I/O (x86_64 without an ECAM) or an indirect window: nothing to map.
    Free,
    /// An ECAM window at `base`, `size` bytes long: bus `n` is
    /// `[base + n MiB, +1 MiB)`.
    Slices { base: usize, size: usize },
    /// No configuration space.
    None,
}

impl BusMapper {
    /// Make bus `bus` reachable. `false`: it is not (outside the window, or
    /// the kernel's device mapping refused it).
    pub(crate) fn map(self, bus: u8) -> bool {
        match self {
            BusMapper::Free => true,
            BusMapper::Slices { base, size } => {
                let off = bus as usize * BUS_SLICE;
                off < size && crate::boot::map_mmio_region(base + off, BUS_SLICE.min(size - off))
            }
            BusMapper::None => false,
        }
    }
}

enum Access {
    /// ECAM at this address; 0 is the x86_64 port pair.
    Ecam(usize),
    #[cfg(feature = "pci-soc-host")]
    Host(soc::HostPort),
    Absent,
}

/// The configuration space `kernel_main` enumerates and hands to the PCI
/// drivers.
pub(crate) struct KernelConfigSpace {
    access: Access,
}

impl KernelConfigSpace {
    /// ECAM at `base` (already mapped for bus 0); `base == 0` on x86_64 is the
    /// legacy port pair.
    pub(crate) const fn ecam(base: usize) -> Self {
        KernelConfigSpace { access: Access::Ecam(base) }
    }

    /// No configuration space: every read is "no device", every write is
    /// dropped.
    pub(crate) const fn absent() -> Self {
        KernelConfigSpace { access: Access::Absent }
    }

    /// How buses behind bridges are made reachable.
    pub(crate) fn bus_mapper(&self) -> BusMapper {
        match &self.access {
            Access::Ecam(0) => BusMapper::Free,
            Access::Ecam(base) => BusMapper::Slices { base: *base, size: usize::MAX },
            #[cfg(feature = "pci-soc-host")]
            Access::Host(p) => p.mapper(),
            Access::Absent => BusMapper::None,
        }
    }
}

/// The legacy port pair (x86_64 without an ECAM). No other ISA builds an
/// `Ecam(0)` space; there it reads as "no device".
#[cfg(target_arch = "x86_64")]
fn port_read32(bdf: Bdf, offset: u16) -> u32 {
    crate::boot_hooks::pci_port_read32(bdf.bus, bdf.device, bdf.function, offset)
}

#[cfg(not(target_arch = "x86_64"))]
fn port_read32(_bdf: Bdf, _offset: u16) -> u32 {
    u32::MAX
}

#[cfg(target_arch = "x86_64")]
fn port_write32(bdf: Bdf, offset: u16, val: u32) {
    crate::boot_hooks::pci_port_write32(bdf.bus, bdf.device, bdf.function, offset, val)
}

#[cfg(not(target_arch = "x86_64"))]
fn port_write32(_bdf: Bdf, _offset: u16, _val: u32) {}

impl ConfigSpace for KernelConfigSpace {
    fn read32(&self, bdf: Bdf, offset: u16) -> u32 {
        match &self.access {
            Access::Ecam(ecam) => {
                if *ecam == 0 {
                    return port_read32(bdf, offset);
                }
                let addr = ecam_address(*ecam, bdf, offset);
                // SAFETY: `addr` is within a bus slice the caller mapped as
                // device memory (`BusMapper::map`, bus 0 before the first
                // access), `offset < 4096` per `ConfigSpace`'s contract, and
                // the read is naturally aligned (`read16`/`read8` round down
                // before calling `read32`).
                unsafe { core::ptr::read_volatile(addr as *const u32) }
            }
            #[cfg(feature = "pci-soc-host")]
            Access::Host(p) => p.read32(bdf, offset),
            Access::Absent => u32::MAX,
        }
    }

    fn write32(&mut self, bdf: Bdf, offset: u16, val: u32) {
        match &mut self.access {
            Access::Ecam(ecam) => {
                if *ecam == 0 {
                    return port_write32(bdf, offset, val);
                }
                let addr = ecam_address(*ecam, bdf, offset);
                // SAFETY: as `read32`.
                unsafe { core::ptr::write_volatile(addr as *mut u32, val) }
            }
            #[cfg(feature = "pci-soc-host")]
            Access::Host(p) => p.write32(bdf, offset, val),
            Access::Absent => {}
        }
    }
}

// The slice arithmetic is the same as the host controllers' ECAM.
const _: () = assert!(ecam_function_offset(Bdf::new(1, 0, 0)) == BUS_SLICE);

/// A SoC host bridge the kernel found and tried to bring up.
pub(crate) struct SocHost {
    /// Its configuration space; [`KernelConfigSpace::absent`] when it did not
    /// come up (a boot line says why): no function is enumerated behind it.
    pub(crate) cfg: KernelConfigSpace,
    /// The memory windows to place BARs from.
    pub(crate) windows: azos_pci::FirmwareWindows,
    /// What a device behind it can address.
    pub(crate) dma_mask: u64,
}

/// Find a SoC host bridge on the hardware bus and bring it up. `None`: the
/// tree has none (or the image has no SoC controllers), and the ECAM path
/// applies.
pub(crate) fn soc_host() -> Option<SocHost> {
    #[cfg(feature = "pci-soc-host")]
    {
        soc::soc_host()
    }
    #[cfg(not(feature = "pci-soc-host"))]
    {
        None
    }
}

/// The Raspberry Pi 5's RP1 south bridge (`azos_pci::rp1`), bound by its id:
/// its BARs assigned and mapped, the chip read back through BAR 1, and the CPU
/// address of each block the kernel names printed for the drivers to come.
/// `Err` (and its line) when BAR 1 is not a memory window or the word at its
/// start is not the RP1's chip id.
#[cfg(feature = "pci-soc-host")]
pub(crate) fn attach_rp1<C: azos_pci::ConfigSpace>(
    cfg: &mut C,
    f: &azos_pci::FunctionInfo,
    window: &mut azos_pci::BarWindow,
) -> Result<(), ()> {
    use azos_pci::rp1;
    let bars = azos_drv_virtio::virtio::pci::msix_selftest::map_bars(cfg, f, window).map_err(|e| {
        azos_drv_sys::kwarn!("[RP1] {}: BARs not mapped: {:?}", f.bdf, e);
    })?;
    let base = bars[rp1::PERIPHERAL_BAR];
    let len = f.bars[..f.bar_count].iter().flatten()
        .find(|b| b.index as usize == rp1::PERIPHERAL_BAR).map_or(0, |b| b.size as usize);
    if base == 0 || len < 4 {
        azos_drv_sys::kwarn!("[RP1] {}: BAR {} is not a memory window", f.bdf, rp1::PERIPHERAL_BAR);
        return Err(());
    }
    // SAFETY: BAR 1 was just assigned and mapped as device memory
    // (`map_bars`), and the word is inside it.
    let id = unsafe { core::ptr::read_volatile((base + rp1::SYSINFO_CHIP_ID) as *const u32) };
    if id != rp1::CHIP_ID {
        azos_drv_sys::kwarn!("[RP1] {}: chip id {:#x}, not the RP1's {:#x}: not used", f.bdf, id, rp1::CHIP_ID);
        return Err(());
    }
    crate::kprintln!("[RP1] {}: chip id {:#x}, peripherals at {:#x} (+{:#x})", f.bdf, id, base, len);
    for b in &rp1::BLOCKS {
        match rp1::block_at(base, len, b) {
            Some(at) => crate::kprintln!("[RP1]   {} at {:#x} (+{:#x}), no driver yet", b.name, at, b.size),
            None => azos_drv_sys::kwarn!("[RP1]   {} past the end of BAR {}", b.name, rp1::PERIPHERAL_BAR),
        }
    }
    Ok(())
}

#[cfg(feature = "pci-soc-host")]
mod soc {
    use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

    use azos_pci::host::dt::{self, Controller};
    use azos_pci::host::{brcmstb, plda, Bus, ConfigAccess, ConfigPort, HostError, HostReport, InboundWindow, MemSpace, OutboundWindow, Perst, Region};
    use azos_pci::{FirmwareWindows, HostWindow};
    use azos_soc::fdt::cell;
    use azos_soc::{Fdt, NodeId};

    use super::{Access, BusMapper, KernelConfigSpace, SocHost, BUS_SLICE};
    use crate::boot::soc as socfw;
    use crate::kprintln;

    /// `perst-gpios` of the JH7110 names a pin of the SYS pad controller.
    const SYS_GPIO: &str = azos_soc::jh7110::iomux::SYS_IOMUX_COMPATIBLE;

    /// Outbound / inbound windows the flows take (PLDA: 8 entries per table,
    /// brcmstb: 4 outbound and 10 inbound).
    const MAX_OUT: usize = 8;
    const MAX_IN: usize = 10;

    /// The mapped register blocks of the one host bridge this kernel brings
    /// up, and its PERST# line. A static: [`ConfigPort`] borrows the bus for
    /// as long as the configuration space lives.
    pub(crate) struct KernelBus {
        apb: AtomicUsize,
        cfg: AtomicUsize,
        stg: AtomicUsize,
        /// PERST# GPIO pin, `u32::MAX` for none.
        perst_pin: AtomicU32,
        /// Level that asserts PERST# (0 for `GPIO_ACTIVE_LOW`).
        perst_assert_level: AtomicU32,
    }

    static BUS: KernelBus = KernelBus {
        apb: AtomicUsize::new(0),
        cfg: AtomicUsize::new(0),
        stg: AtomicUsize::new(0),
        perst_pin: AtomicU32::new(u32::MAX),
        perst_assert_level: AtomicU32::new(0),
    };

    impl KernelBus {
        fn base(&self, region: Region) -> usize {
            match region {
                Region::Apb => self.apb.load(Ordering::Acquire),
                Region::Cfg => self.cfg.load(Ordering::Acquire),
                Region::Stg => self.stg.load(Ordering::Acquire),
            }
        }
    }

    impl Bus for KernelBus {
        fn read32(&self, region: Region, off: u32) -> u32 {
            let base = self.base(region);
            if base == 0 {
                // A block that was never mapped reads as "no device".
                return u32::MAX;
            }
            // SAFETY: `bring_up` mapped the block as device memory before it
            // stored the base, and every offset the flows use lies inside it.
            unsafe { core::ptr::read_volatile((base + off as usize) as *const u32) }
        }

        fn write32(&self, region: Region, off: u32, val: u32) {
            let base = self.base(region);
            if base != 0 {
                // SAFETY: as `read32`.
                unsafe { core::ptr::write_volatile((base + off as usize) as *mut u32, val) }
            }
        }

        fn delay_us(&self, us: u32) {
            // The bring-up runs before the scheduler: a busy wait on the
            // timebase.
            let ticks = azos_drv_sys::timebase::TIMER_FREQ.saturating_mul(us as u64) / 1_000_000;
            let end = azos_drv_sys::timebase::now().saturating_add(ticks);
            while azos_drv_sys::timebase::now() < end {
                core::hint::spin_loop();
            }
        }
    }

    impl Perst for KernelBus {
        fn set_perst(&self, asserted: bool) {
            let pin = self.perst_pin.load(Ordering::Acquire);
            if pin == u32::MAX {
                return;
            }
            let level = self.perst_assert_level.load(Ordering::Acquire) ^ u32::from(!asserted);
            // The pin is the VisionFive 2's: `claim_perst` refuses elsewhere,
            // so no other board gets here.
            #[cfg(feature = "vf2")]
            let _ = azos_drv_gpio::gpio::gpio_write(pin, level);
            #[cfg(not(feature = "vf2"))]
            let _ = level;
        }
    }

    /// Take `pin` as the PERST# output, held asserted (`assert_level`) from
    /// the first instant. The GPIO controller is already bound (`bind_safety`
    /// runs before the enumeration), so the pin is an input until this call
    /// drives it. `false`: this board has no driver for it.
    #[cfg(feature = "vf2")]
    fn claim_perst(pin: u32, assert_level: u32) -> bool {
        use azos_drv_gpio::gpio::{gpio_set_direction, gpio_write, GpioDir};
        // The level is latched before the pin becomes an output, so PERST#
        // never glitches to the released level.
        gpio_write(pin, assert_level) == 0 && gpio_set_direction(pin, GpioDir::Output) == 0
    }

    #[cfg(not(feature = "vf2"))]
    fn claim_perst(_pin: u32, _assert_level: u32) -> bool {
        false
    }

    /// What the device tree says about the bridge.
    struct Dt {
        controller: Controller,
        node: u32,
        apb: (u64, u64),
        /// The configuration window (PLDA only).
        cfg: (u64, u64),
        /// Base of the STG syscon block (PLDA only).
        stg_syscon: u64,
        stg_block: u32,
        /// `(pin, active_low)` of `perst-gpios` (PLDA only).
        perst: Option<(u32, bool)>,
        outbound: [OutboundWindow; MAX_OUT],
        n_out: usize,
        inbound: [InboundWindow; MAX_IN],
        n_in: usize,
    }

    const NO_OUT: OutboundWindow = OutboundWindow { space: MemSpace::Mem32, window: HostWindow { cpu_base: 0, bus_base: 0, size: 0 } };
    const NO_IN: InboundWindow = InboundWindow { bus_base: 0, cpu_base: 0, size: 0 };

    /// Read the bridge's node. The text of a refusal is the boot line.
    fn read_dt(fdt: &Fdt<'_>, controller: Controller, node: u32) -> Result<Dt, &'static str> {
        let n = NodeId(node);
        let anc = fdt.ancestors(n).ok_or("the node is not in the tree")?;
        let parent = anc.parent().ok_or("the node has no parent")?;
        let ac = fdt.u32_prop(parent, "#address-cells").unwrap_or(2) as usize;
        let sc = fdt.u32_prop(parent, "#size-cells").unwrap_or(1) as usize;
        let own_sc = fdt.u32_prop(n, "#size-cells").unwrap_or(1) as usize;
        let reg = fdt.prop(n, "reg").ok_or("no reg")?;
        let names = fdt.prop(n, "reg-names");
        let block = |name: &str| dt::reg_named(reg, names, name, ac, sc);
        let (apb, cfg) = match controller {
            Controller::Plda => (
                block("apb").ok_or("no apb range in reg")?,
                block("cfg").ok_or("no cfg range in reg")?,
            ),
            Controller::Brcmstb => (block("apb").ok_or("no register range in reg")?, (0, 0)),
        };

        let mut d = Dt {
            controller,
            node,
            apb,
            cfg,
            stg_syscon: 0,
            stg_block: 0,
            perst: None,
            outbound: [NO_OUT; MAX_OUT],
            n_out: 0,
            inbound: [NO_IN; MAX_IN],
            n_in: 0,
        };
        let ranges = fdt.prop(n, "ranges").ok_or("no ranges")?;
        d.n_out = dt::parse_ranges(ranges, ac, own_sc, &mut d.outbound).map_err(|_| "ranges unreadable or too many")?;
        if let Some(r) = fdt.prop(n, "dma-ranges") {
            d.n_in = dt::parse_dma_ranges(r, ac, own_sc, &mut d.inbound).map_err(|_| "dma-ranges unreadable or too many")?;
        }

        if controller == Controller::Plda {
            let domain = fdt.u32_prop(n, "linux,pci-domain").ok_or("no linux,pci-domain")?;
            d.stg_block = dt::plda_stg_base(domain).ok_or("PCI domain without STG offsets")?;
            let syscon = fdt.prop(n, "starfive,stg-syscon").and_then(|v| cell(v, 0)).ok_or("no starfive,stg-syscon")?;
            let sn = fdt.by_phandle(syscon).ok_or("the STG syscon is not in the tree")?;
            d.stg_syscon = fdt.reg(sn).ok_or("the STG syscon has no register range")?.0;

            // `perst-gpios = <&sysgpio pin flags>`.
            let g = fdt.prop(n, "perst-gpios").ok_or("no perst-gpios")?;
            let ctl = cell(g, 0).and_then(|ph| fdt.by_phandle(ph)).ok_or("perst-gpios names no controller")?;
            if !fdt.is_compatible(ctl, SYS_GPIO) {
                return Err("perst-gpios is not a pin of the SYS pad controller");
            }
            let cells = fdt.u32_prop(ctl, "#gpio-cells").unwrap_or(2) as usize;
            let pin = cell(g, 1).ok_or("perst-gpios without a pin")?;
            let flags = if cells >= 2 { cell(g, 2).unwrap_or(0) } else { 0 };
            d.perst = Some((pin, flags & 1 != 0));
        }
        Ok(d)
    }

    /// The most SoC bridges of one tree tried ([`soc_host`]): the BCM2712 has
    /// three (its external connector, the RP1's and an unused one).
    const MAX_BRIDGES: usize = 4;

    /// Find the SoC host bridge on the hardware bus and bring it up. One bridge
    /// is brought up: the first whose link comes up, trying first the
    /// controllers whose node describes what sits behind them (a child node:
    /// the Raspberry Pi 5's `pcie2`, which leads to the RP1, in Linux's tree and
    /// in the firmware's), then the others in tree order (an empty connector
    /// is a link-down line and the next one is tried).
    pub(super) fn soc_host() -> Option<SocHost> {
        let mut found = [None; MAX_BRIDGES];
        let mut n = 0;
        azos_drv_bus::hwbus::with(|bus| {
            for (_, s) in bus.iter() {
                let Some(c) = s.dev.compatible().find_map(Controller::from_compatible) else { continue };
                let Some(node) = s.dev.dt_node else { continue };
                if n < MAX_BRIDGES {
                    found[n] = Some((c, node));
                    n += 1;
                }
            }
        });
        if n == 0 {
            return None;
        }
        let mut described = [false; MAX_BRIDGES];
        for (d, f) in described.iter_mut().zip(found[..n].iter().flatten()) {
            *d = socfw::with(|fdt, _soc, _bus, _fx| fdt.children(NodeId(f.1)).next().is_some()) == Some(true);
        }
        let (order, k) = dt::bring_up_order(&described, n);
        for &i in &order[..k] {
            if let Some((controller, node)) = found[i] {
                if let Some(h) = try_bridge(controller, node) {
                    return Some(h);
                }
            }
        }
        Some(down())
    }

    /// Bring up the bridge at `node`; `None` (and its line) when it did not
    /// come up, its resources released again.
    fn try_bridge(controller: Controller, node: u32) -> Option<SocHost> {
        let name = controller.name();
        let read = socfw::with(|fdt, _soc, _bus, _fx| read_dt(fdt, controller, node));
        let d = match read {
            Some(Ok(d)) => d,
            Some(Err(why)) => {
                azos_drv_sys::kwarn!("[PCI] {}: {}: no enumeration", name, why);
                return None;
            }
            None => {
                azos_drv_sys::kwarn!("[PCI] {}: the SoC frameworks have no device tree: no enumeration", name);
                return None;
            }
        };

        // Clocks, resets, power domains and pin state the node names.
        match socfw::bind(d.node) {
            Ok(a) => kprintln!(
                "[PCI] {} at {:#x}: soc bind domains={} clocks={} resets={} pins={} unmodelled={} (left as the firmware set them)",
                name, d.apb.0, a.domains, a.clocks, a.resets, a.pins, a.unmodelled),
            Err(e) => {
                azos_drv_sys::kwarn!("[PCI] {} at {:#x}: resources refused: {:?}: no enumeration", name, d.apb.0, e);
                return None;
            }
        }

        match bring_up(&d) {
            Ok(h) => Some(h),
            Err(why) => {
                azos_drv_sys::kwarn!("[PCI] {} at {:#x}: {}: no enumeration", name, d.apb.0, why);
                let _ = socfw::unbind(d.node);
                None
            }
        }
    }

    /// A bridge that did not come up: nothing to enumerate, no window to
    /// place a BAR in.
    fn down() -> SocHost {
        SocHost { cfg: KernelConfigSpace::absent(), windows: FirmwareWindows::default(), dma_mask: u64::MAX }
    }

    fn map(base: u64, size: u64) -> bool {
        crate::boot::map_mmio_region(base as usize, size as usize)
    }

    fn bring_up(d: &Dt) -> Result<SocHost, &'static str> {
        let name = d.controller.name();
        let outbound = &d.outbound[..d.n_out];
        let inbound = &d.inbound[..d.n_in];

        if !map(d.apb.0, d.apb.1) {
            return Err("the register window did not map");
        }
        BUS.apb.store(d.apb.0 as usize, Ordering::Release);

        let report: Result<HostReport, HostError> = match d.controller {
            Controller::Plda => {
                // The syscon block holds the STG offsets of this controller.
                if !map(d.stg_syscon & !0xfff, 0x1000) {
                    return Err("the STG syscon window did not map");
                }
                BUS.stg.store(d.stg_syscon as usize, Ordering::Release);
                // Bus 0 of the configuration window now; the rest as bridges
                // are found.
                let first = BUS_SLICE.min(d.cfg.1 as usize);
                if !map(d.cfg.0, first as u64) {
                    return Err("the configuration window did not map");
                }
                BUS.cfg.store(d.cfg.0 as usize, Ordering::Release);

                let (pin, active_low) = d.perst.ok_or("no PERST# pin")?;
                let assert_level = u32::from(!active_low);
                if !claim_perst(pin, assert_level) {
                    return Err("this board has no PERST# GPIO driver");
                }
                BUS.perst_assert_level.store(assert_level, Ordering::Release);
                BUS.perst_pin.store(pin, Ordering::Release);

                plda::init(
                    &BUS,
                    &plda::PldaConfig {
                        stg_base: d.stg_block,
                        cfg_base: d.cfg.0,
                        cfg_size: d.cfg.1,
                        outbound,
                        inbound,
                        // Where the bridge's own APB block appears on the PCI
                        // side; with no inbound window the block's reset
                        // translation maps the first 4 GiB 1:1 and the
                        // doorbell is the APB block's CPU address.
                        msi_doorbell: d.apb.0,
                        link_timeout_us: plda::DEFAULT_LINK_TIMEOUT_US,
                    },
                )
            }
            Controller::Brcmstb => brcmstb::init(
                &BUS,
                &brcmstb::BrcmConfig { outbound, inbound, link_timeout_us: brcmstb::DEFAULT_LINK_TIMEOUT_US },
            ),
        };

        let report = match report {
            Ok(r) => r,
            Err(HostError::LinkDown { waited_us }) => {
                kprintln!("[PCI] {} at {:#x}: link down after {} us (nothing in the slot?)", name, d.apb.0, waited_us);
                return Err("link down");
            }
            Err(e) => {
                azos_drv_sys::kwarn!("[PCI] {} at {:#x}: init refused: {:?}", name, d.apb.0, e);
                return Err("controller init refused");
            }
        };

        let mapper = match report.config {
            ConfigAccess::Ecam { size } => BusMapper::Slices { base: d.cfg.0 as usize, size: size as usize },
            ConfigAccess::Indirect { .. } => BusMapper::Free,
        };
        kprintln!("[PCI] {} at {:#x}: link up after {} us, config {}, MSI {}",
            name, d.apb.0,
            report.link_wait_us,
            match report.config {
                ConfigAccess::Ecam { size } => alloc::format!("ECAM {:#x}+{:#x}", d.cfg.0, size),
                ConfigAccess::Indirect { .. } => alloc::string::String::from("indirect"),
            },
            match report.msi {
                Some(m) => alloc::format!("doorbell {:#x}, {} vectors (no interrupt route yet)", m.doorbell, m.vectors),
                None => alloc::string::String::from("not offered"),
            });
        Ok(SocHost {
            cfg: KernelConfigSpace { access: Access::Host(HostPort { port: ConfigPort::new(&BUS, report.config), mapper }) },
            windows: report.windows,
            dma_mask: dt::dma_mask(inbound),
        })
    }

    /// A [`ConfigPort`] with how its buses are mapped.
    pub(crate) struct HostPort {
        port: ConfigPort<'static, KernelBus>,
        mapper: BusMapper,
    }

    impl HostPort {
        pub(super) fn mapper(&self) -> BusMapper {
            self.mapper
        }
        pub(super) fn read32(&self, bdf: azos_pci::Bdf, offset: u16) -> u32 {
            azos_pci::ConfigSpace::read32(&self.port, bdf, offset)
        }
        pub(super) fn write32(&mut self, bdf: azos_pci::Bdf, offset: u16, val: u32) {
            azos_pci::ConfigSpace::write32(&mut self.port, bdf, offset, val)
        }
    }
}

/// The PCI bring-up of `kernel_main`'s Phase 6, before the block device (the
/// call site says why there): the host bridge and its windows, the tree
/// enumerated, the BARs placed behind the bridges, the IOMMU, the MSI-X boot
/// self-tests, then the PCI drivers bound by the hardware bus, in their order.
/// Inlined, as every boot phase (see `boot`'s module doc).
#[inline(always)]
#[cfg_attr(not(feature = "nvme"), allow(unused_variables))]
pub(crate) fn bring_up(early: &EarlyBoot, num_cpus: usize) {
    use crate::boot::pci::KernelConfigSpace;

    // Bus 0 only, matching `crates/drivers/pci`'s own documented scope: every
    // QEMU `virt -device ...-pci` attachment lands on bus 0, and 32
    // devices * 8 functions * 4 KiB = 1 MiB is the whole ECAM slice bus
    // 0 needs, out of the 256 MiB window reserved for all 256 buses.
    // Mapping the full window would be 65,536 individual 4 KiB
    // page-table inserts (`map_mmio_region` maps one page at a time) for
    // 255 buses nothing on `virt` uses.
    #[cfg(not(target_arch = "x86_64"))]
    const PCI_ECAM_BUS0_SIZE: usize = 0x10_0000;

    // ECAM base and the memory windows BARs are placed from: the DTB's
    // `pci-host-ecam-generic` node (`reg` and `ranges`, read in early boot
    // into `EarlyBoot::pci_host`), or, with no such node, QEMU `virt`'s
    // own values (riscv64 `pci@30000000`; aarch64 `pcie@10000000`, whose
    // ECAM QEMU places at 0x40_1000_0000 with `highmem-ecam`, the default
    // for a 64-bit guest). The window rules live in `azos_pci::window`.
    #[cfg(target_arch = "riscv64")]
    const PCI_ECAM_DEFAULT: usize = 0x3000_0000;
    #[cfg(target_arch = "aarch64")]
    const PCI_ECAM_DEFAULT: usize = 0x40_1000_0000;
    #[cfg(target_arch = "riscv64")]
    const PCI_MEM32_DEFAULT: (u64, u64) = (0x4000_0000, 0x4000_0000);
    #[cfg(target_arch = "aarch64")]
    const PCI_MEM32_DEFAULT: (u64, u64) = (0x1000_0000, 0x2eff_0000);
    // x86_64 has no DTB: Kconfig X86_PCI_MEM32_BASE / _SIZE, and the ECAM
    // from the ACPI MCFG or Kconfig X86_PCI_ECAM_BASE, else ports 0xCF8/0xCFC
    // (`pci_ecam_base` 0). The MCFG names no windows and nothing parses
    // the `_CRS` that does, so there is no 64-bit window there.
    #[cfg(target_arch = "x86_64")]
    const PCI_MEM32_DEFAULT: (u64, u64) =
        (azos_limits::X86_PCI_MEM32_BASE as u64, azos_limits::X86_PCI_MEM32_SIZE as u64);
    // The first CPU address the kernel cannot map as device memory: the
    // BAR windows are identity-mapped (`map_mmio_region`), so one past
    // the address space. riscv64 Sv39 (the lower half), the TTBR0 range of
    // the aarch64 granule (39 bits at 4/16 KiB, 48 at 64 KiB), x86_64
    // 48-bit.
    #[cfg(target_arch = "riscv64")]
    let pci_reach: u64 = 1 << 38;
    #[cfg(target_arch = "aarch64")]
    let pci_reach: u64 = 1 << azos_arch::mmu::GRANULE.va_bits;
    #[cfg(target_arch = "x86_64")]
    let pci_reach: u64 = 1 << 47;
    let pci_host = early.pci_host;
    // A SoC host bridge (Kconfig PCI_SOC_HOST: the VisionFive 2's and the
    // Raspberry Pi 5's controllers) is brought up first. When the tree has
    // one, the ECAM below is never looked for and no built-in address of
    // the QEMU machine is tried: on those boards they are other hardware.
    let mut soc_host = boot::pci::soc_host();
    // Where firmware states no window the built-in one applies on the QEMU
    // machine only.
    #[cfg(not(target_arch = "x86_64"))]
    let (pci_ecam_base, ecam_src, default_mem32) = match pci_host {
        _ if soc_host.is_some() => (0, "SoC host bridge", (0, 0)),
        Some(h) if h.ecam_size >= PCI_ECAM_BUS0_SIZE as u64 => (h.ecam_base as usize, "dtb", PCI_MEM32_DEFAULT),
        _ if cfg!(feature = "qemu") => (PCI_ECAM_DEFAULT, "built-in", PCI_MEM32_DEFAULT),
        _ => (0, "none: no host bridge in the tree", (0, 0)),
    };
    #[cfg(target_arch = "x86_64")]
    let (pci_ecam_base, ecam_src, default_mem32) = match crate::boot_hooks::pci_ecam_bus0() {
        Some((base, src)) => (base, src, PCI_MEM32_DEFAULT),
        None => (0, "no MCFG: port i/o 0xcf8", PCI_MEM32_DEFAULT),
    };
    let (mut window, window_report) = {
        let host_window = |w: azos_dtb::PciWindow| azos_pci::HostWindow {
            cpu_base: w.cpu_base,
            bus_base: w.bus_base,
            size: w.size,
        };
        let fw = match &soc_host {
            Some(h) => Some(h.windows),
            None => pci_host.map(|h| azos_pci::FirmwareWindows {
                mem32: h.mem32.map(host_window),
                mem64: h.mem64.map(host_window),
            }),
        };
        azos_pci::resolve_bar_window(fw, if soc_host.is_some() { "host bridge" } else { "dtb" }, default_mem32, None, pci_reach)
    };
    kprintln!("[PCI] host bridge: ECAM {:#x} ({}), {}", pci_ecam_base, ecam_src, window_report);
    // x86_64 mapped the ECAM with its other late windows (`arch_map_late_mmio`).
    #[cfg(not(target_arch = "x86_64"))]
    if pci_ecam_base != 0 {
        let _ = crate::boot::map_mmio_region(pci_ecam_base, PCI_ECAM_BUS0_SIZE);
    }

    // Fixed-size `fmt::Write` sink — no heap dependency, matching the
    // rest of this crate's boot-time printing.
    struct LineBuf {
        buf: [u8; 160],
        len: usize,
    }
    impl core::fmt::Write for LineBuf {
        fn write_str(&mut self, s: &str) -> core::fmt::Result {
            let bytes = s.as_bytes();
            let space = self.buf.len().saturating_sub(self.len);
            let take = bytes.len().min(space);
            self.buf[self.len..self.len + take].copy_from_slice(&bytes[..take]);
            self.len += take;
            Ok(())
        }
    }

    let mut cfg = match soc_host {
        Some(ref mut h) => core::mem::replace(&mut h.cfg, KernelConfigSpace::absent()),
        None if cfg!(target_arch = "x86_64") || pci_ecam_base != 0 => KernelConfigSpace::ecam(pci_ecam_base),
        None => KernelConfigSpace::absent(),
    };
    // Bus 0, then the bus behind each bridge the firmware gave a
    // secondary number: a bus's 1 MiB slice of the ECAM window is mapped
    // when its bridge is found (port I/O, with no ECAM, reaches them all).
    let buses = cfg.bus_mapper();
    let azos_pci::Found { funcs, n: pci_n, dropped } = azos_pci::enumerate_tree::<
        KernelConfigSpace,
        { azos_limits::PCI_MAX_FUNCTIONS },
    >(&mut cfg, &mut |bus| buses.map(bus));
    kprintln!("[PCI] bus 0 enumeration: {} function(s) found", pci_n);
    if dropped != 0 {
        azos_drv_sys::kwarn!("[PCI] dropped {} function(s) past PCI_MAX_FUNCTIONS ({}): no driver sees them",
                             dropped, azos_limits::PCI_MAX_FUNCTIONS);
    }
    let behind = funcs[..pci_n].iter().flatten().filter(|f| f.bdf.bus != 0).count();
    if behind != 0 {
        kprintln!("[PCI] {} of them behind bridges", behind);
    }
    boot::hwbus::add_pci(
        &funcs[..pci_n],
        &window,
        soc_host.as_ref().map_or_else(|| pci_host.map_or(u64::MAX, |h| h.dma_mask), |h| h.dma_mask),
    );
    for info in funcs[..pci_n].iter().flatten() {
        let mut line = LineBuf { buf: [0; 160], len: 0 };
        if azos_pci::format_function_line(info, &mut line).is_ok() {
            if let Ok(s) = core::str::from_utf8(&line.buf[..line.len]) {
                kprintln!("[PCI] {}", s);
            }
        }
    }

    // Bridges with devices behind them get forwarding windows around those
    // devices' BARs, and the BARs get their addresses inside them; the
    // users below take the address from `window` like any other.
    let bridges = azos_pci::place_behind_bridges(&mut cfg, &funcs[..pci_n], &mut window);
    if !bridges.is_empty() {
        kprintln!("[PCI] {}", bridges);
    }

    // Kconfig IOMMU_*: bring the IOMMU up before any PCI driver touches
    // its device (a function whose driver maps its DMA gets a translating
    // domain its driver enables, one whose driver does not stays in
    // pass-through, one no kernel driver binds is blocked).
    #[cfg(any(feature = "iommu-riscv", feature = "iommu-smmuv3", feature = "iommu-vtd", feature = "iommu-amdvi"))]
    boot::iommu_init(&mut cfg, &funcs[..pci_n], &mut window);

    // On riscv64 `virt,aia=aplic-imsic`, drive one
    // virtio-net-pci TX completion over MSI-X into the boot hart's
    // IMSIC file and print the per-vector delivery counts
    // (`azos_drv_virtio::virtio::pci::msix_selftest`). The PLIC machine has
    // no MSI target, so this is skipped there. BAR windows: the ones
    // resolved above. The NIC is still in pass-through here
    // (its driver enables its domain), so the self-test's raw physical
    // addresses reach it. A boot self-test (Kconfig BOOT_SELFTESTS), as
    // are its two twins below.
    #[cfg(all(target_arch = "riscv64", feature = "boot-selftests"))]
    if azos_drv_irqchip::irqchip::is_aia() {
        let hart = azos_arch::Cpu::hart_id(&azos_arch::ARCH) as u32;
        if let Some(net) = boot::hwbus::function_for("virtio-net-pci", &funcs[..pci_n]) {
            use azos_drv_virtio::virtio::pci::msix_selftest;
            let mut route = msix_selftest::AiaRoute::new(hart);
            match msix_selftest::tx_selftest(&mut cfg, net, &mut window, &mut route) {
                Ok(r) => {
                    kprintln!("[PCI] msix {} enabled={} vectors={} target={:#x} tx used={}",
                        net.bdf, if r.msix_enabled { "y" } else { "n" },
                        r.table_size, r.target, r.used);
                    kprintln!("[PCI] msix {} vec0 id={} count={} vec1 id={} count={}",
                        net.bdf, r.ids[0], r.counts[0], r.ids[1], r.counts[1]);
                    if r.counts[1] == 0 {
                        azos_drv_sys::kerr!("[PCI] msix {} delivery FAILED: used={} but vec1 count=0",
                            net.bdf, r.used);
                    }
                }
                Err(e) => azos_drv_sys::kerr!("[PCI] msix {} selftest error: {:?}", net.bdf, e),
            }
        }
    }

    // aarch64 twin: the same TX self-test, its MSI-X
    // vectors routed through the GICv3 ITS (`GITS_TRANSLATER` + EventID
    // = vector index, EventID N -> LPI `LPI_INTID_BASE + N`, counted by
    // `entry::aarch64::LPI_VECTOR_COUNT[N]`). DeviceID = the requester
    // ID (QEMU `virt`'s `msi-map = <0 &its 0 0x10000>`). BAR window:
    // the windows resolved above.
    //
    // `lpi_offset`: EventID N of this route becomes LPI
    // `LPI_INTID_BASE + lpi_offset + N`, so the self-test (offset 0) and
    // the NIC driver below (offset 4) count in different
    // `LPI_VECTOR_COUNT` slots. `prepare` issues a fresh MAPD for the
    // DeviceID each time (a new ITT slot; the ITS replaces the mapping).
    #[cfg(target_arch = "aarch64")]
    use crate::entry::aarch64::ext::its_route::ItsRoute;
    #[cfg(all(target_arch = "aarch64", feature = "boot-selftests"))]
    if crate::boot_hooks::its_ready() {
        if let Some(net) = boot::hwbus::function_for("virtio-net-pci", &funcs[..pci_n]) {
            use azos_drv_virtio::virtio::pci::msix_selftest;
            let mut route = ItsRoute::new(net.bdf, 0);
            match msix_selftest::tx_selftest(&mut cfg, net, &mut window, &mut route) {
                Ok(r) => {
                    kprintln!("[PCI] msix {} enabled={} vectors={} target={:#x} tx used={}",
                        net.bdf, if r.msix_enabled { "y" } else { "n" },
                        r.table_size, r.target, r.used);
                    kprintln!("[PCI] msix {} vec0 event={} lpis={} vec1 event={} lpis={}",
                        net.bdf, r.ids[0], r.counts[0], r.ids[1], r.counts[1]);
                    if r.counts[1] == 0 {
                        azos_drv_sys::kerr!("[PCI] msix {} delivery FAILED: used={} but vec1 lpis=0",
                            net.bdf, r.used);
                    }
                }
                Err(e) => azos_drv_sys::kerr!("[PCI] msix {} selftest error: {:?}", net.bdf, e),
            }
        }
    }

    // x86_64 twin: the same TX self-test, its MSI-X
    // vectors going straight to the boot CPU's local APIC (vector = MSI
    // data word, counted by `entry::x86_64::irq`).
    #[cfg(all(target_arch = "x86_64", feature = "boot-selftests"))]
    if let Some(net) = boot::hwbus::function_for("virtio-net-pci", &funcs[..pci_n]) {
        use azos_drv_virtio::virtio::pci::msix_selftest;
        let mut route = msix_selftest::ApicMsiRoute::new(
            azos_sched::smp::current_cpu_id() as u32);
        match msix_selftest::tx_selftest(&mut cfg, net, &mut window, &mut route) {
            Ok(r) => {
                kprintln!("[PCI] msix {} enabled={} vectors={} target={:#x} tx used={}",
                    net.bdf, if r.msix_enabled { "y" } else { "n" },
                    r.table_size, r.target, r.used);
                kprintln!("[PCI] msix {} vec0 vector={} count={} vec1 vector={} count={}",
                    net.bdf, r.ids[0], r.counts[0], r.ids[1], r.counts[1]);
                if r.counts[1] == 0 {
                    azos_drv_sys::kerr!("[PCI] msix {} delivery FAILED: used={} but vec1 count=0",
                        net.bdf, r.used);
                }
            }
            Err(e) => azos_drv_sys::kerr!("[PCI] msix {} selftest error: {:?}", net.bdf, e),
        }
    }

    // The PCI drivers, bound by the bus to the functions its tables name
    // (crates/drivers/*/hwbus.ids), in the order they always came up:
    //
    // Kconfig DRV_NVME: an NVMe controller on the bus is attached now,
    // before `blkdev::init`, and becomes the block device. It has an MSI-X
    // vector per I/O queue pair and one for the admin queue: queue `q` to
    // CPU `q` (AIA IMSIC identities in each hart's file on riscv64, a
    // vector of each local APIC on x86_64); on aarch64 ITS EventIDs
    // 0..=queues -> LPI slots 8.. of the boot CPU's collection (the
    // self-test uses 0-1, the NIC 4-6, the Intel NICs 16 and 17;
    // `LPI_VECTOR_COUNT` has 8 slots, so the driver counts its own).
    //
    // The kernel's NIC over virtio-pci when a
    // virtio-net-pci function is present (`install_net` below then keeps
    // it and does not probe MMIO). IRQ mode where a route exists (AIA
    // IMSIC / GICv3 ITS / x86 local APIC, boot hart only), polled on plain riscv64 `virt`.
    struct PciBind<'a> {
        cfg: &'a mut KernelConfigSpace,
        window: &'a mut azos_pci::BarWindow,
        funcs: &'a [Option<azos_pci::FunctionInfo>],
        /// CPUs the machine will run (the DTB's / MADT's count): bounds
        /// the NVMe I/O queue pairs.
        #[cfg(feature = "nvme")]
        cpus: usize,
    }
    impl boot::hwbus::PciProbe for PciBind<'_> {
        fn probe(
            &mut self,
            driver: &str,
            dev: &azos_drv_bus::hwbus::Device,
        ) -> Result<(), azos_drv_bus::hwbus::ProbeError> {
            use azos_drv_bus::hwbus::ProbeError;
            let Some(f) = self.funcs.iter().flatten().find(|f| {
                f.bdf.bus == dev.pci.bus && f.bdf.device == dev.pci.device && f.bdf.function == dev.pci.function
            }) else {
                return Err(ProbeError::Failed);
            };
            match driver {
                #[cfg(feature = "nvme")]
                "nvme" => {
                    // One MSI-X vector per I/O queue pair, queue `q` to
                    // CPU `q`: each hart's IMSIC file / each CPU's local
                    // APIC (the secondaries enable theirs when they come
                    // up). The ITS has the boot CPU's collection only.
                    #[cfg(target_arch = "riscv64")]
                    let mut route = azos_drv_block::nvme::PerCpuRoute::new(|cpu| {
                        azos_drv_virtio::virtio::pci::msix_selftest::AiaRoute::new(cpu as u32)
                    });
                    #[cfg(target_arch = "aarch64")]
                    let mut route = ItsRoute::new(f.bdf, 8);
                    #[cfg(target_arch = "x86_64")]
                    let mut route = azos_drv_block::nvme::PerCpuRoute::new(|cpu| {
                        azos_drv_virtio::virtio::pci::msix_selftest::ApicMsiRoute::new(cpu as u32)
                    });
                    attach_nvme(self.cfg, f, self.window, &mut route, dev.dma_mask, self.cpus);
                    // A refusal is a line (`attach_nvme`), and the block
                    // device stays virtio-blk.
                    if azos_drv_block::nvme::active() { Ok(()) } else { Err(ProbeError::Failed) }
                }
                // Kconfig DRV_AHCI: a SATA disk behind an AHCI host; its one
                // MSI goes to the boot hart (aarch64: LPI slot 19, after the
                // Intel NICs' 16 and 17 and the sound function's 18).
                #[cfg(feature = "ahci")]
                "ahci" => {
                    #[cfg(target_arch = "riscv64")]
                    let mut route = azos_drv_virtio::virtio::pci::msix_selftest::AiaRoute::new(
                        azos_arch::Cpu::hart_id(&azos_arch::ARCH) as u32);
                    #[cfg(target_arch = "aarch64")]
                    let mut route = ItsRoute::new(f.bdf, 19);
                    #[cfg(target_arch = "x86_64")]
                    let mut route = azos_drv_virtio::virtio::pci::msix_selftest::ApicMsiRoute::new(
                        azos_sched::smp::current_cpu_id() as u32);
                    // A refusal is a line (`attach_ahci`), and the block
                    // device stays what it was.
                    if attach_ahci(self.cfg, f, self.window, &mut route, dev.dma_mask) {
                        Ok(())
                    } else {
                        Err(ProbeError::Failed)
                    }
                }
                #[cfg(feature = "usb-xhci")]
                "xhci" => {
                    // Polled for now: no MSI-X vector is routed to it.
                    boot::usb::attach_pci(self.cfg, f, self.window, dev.dma_mask)
                        .map_err(|()| ProbeError::Failed)
                }
                "virtio-net-pci" => {
                    #[cfg(target_arch = "riscv64")]
                    let mut route = azos_drv_virtio::virtio::pci::msix_selftest::AiaRoute::new(
                        azos_arch::Cpu::hart_id(&azos_arch::ARCH) as u32);
                    #[cfg(target_arch = "aarch64")]
                    let mut route = ItsRoute::new(f.bdf, 4);
                    #[cfg(target_arch = "x86_64")]
                    let mut route = azos_drv_virtio::virtio::pci::msix_selftest::ApicMsiRoute::new(
                        azos_sched::smp::current_cpu_id() as u32);
                    azos_drv_virtio::virtio::net::init_pci(self.cfg, f, self.window, &mut route).map_err(|e| {
                        kprintln!("[NET] virtio-net-pci {} not used: {:?}", f.bdf, e);
                        ProbeError::Failed
                    })
                }
                // Kconfig DRV_E1000E: the Intel NIC; its one MSI goes to the
                // boot hart as the virtio NIC's do (aarch64: LPI slot 16,
                // after the self-test's 0-1, the virtio NIC's 4-6, NVMe's 8-15).
                #[cfg(feature = "e1000e")]
                "e1000e" => {
                    #[cfg(target_arch = "riscv64")]
                    let mut route = azos_drv_virtio::virtio::pci::msix_selftest::AiaRoute::new(
                        azos_arch::Cpu::hart_id(&azos_arch::ARCH) as u32);
                    #[cfg(target_arch = "aarch64")]
                    let mut route = ItsRoute::new(f.bdf, 16);
                    #[cfg(target_arch = "x86_64")]
                    let mut route = azos_drv_virtio::virtio::pci::msix_selftest::ApicMsiRoute::new(
                        azos_sched::smp::current_cpu_id() as u32);
                    azos_drv_net::e1000e::init_pci(self.cfg, f, self.window, &mut route).map_err(|e| {
                        kprintln!("[NET] e1000e {} not used: {:?}", f.bdf, e);
                        ProbeError::Failed
                    })
                }
                // Kconfig DRV_IGC: the Intel I225/I226 (and QEMU's `igb`); its one
                // MSI goes to the boot hart (aarch64: LPI slot 17, after e1000e's 16).
                #[cfg(feature = "igc")]
                "igc" => {
                    #[cfg(target_arch = "riscv64")]
                    let mut route = azos_drv_virtio::virtio::pci::msix_selftest::AiaRoute::new(
                        azos_arch::Cpu::hart_id(&azos_arch::ARCH) as u32);
                    #[cfg(target_arch = "aarch64")]
                    let mut route = ItsRoute::new(f.bdf, 17);
                    #[cfg(target_arch = "x86_64")]
                    let mut route = azos_drv_virtio::virtio::pci::msix_selftest::ApicMsiRoute::new(
                        azos_sched::smp::current_cpu_id() as u32);
                    azos_drv_net::igc::init_pci(self.cfg, f, self.window, &mut route).map_err(|e| {
                        kprintln!("[NET] igc {} not used: {:?}", f.bdf, e);
                        ProbeError::Failed
                    })
                }
                // Kconfig DRV_VIRTIO_SND: the virtio-sound function; one MSI-X
                // vector for its three queues, to the boot hart as the
                // NICs' (aarch64: LPI slot 18, after igc's 17).
                #[cfg(feature = "virtio-snd")]
                "virtio-snd-pci" => {
                    #[cfg(target_arch = "riscv64")]
                    let mut route = azos_drv_virtio::virtio::pci::msix_selftest::AiaRoute::new(
                        azos_arch::Cpu::hart_id(&azos_arch::ARCH) as u32);
                    #[cfg(target_arch = "aarch64")]
                    let mut route = ItsRoute::new(f.bdf, 18);
                    #[cfg(target_arch = "x86_64")]
                    let mut route = azos_drv_virtio::virtio::pci::msix_selftest::ApicMsiRoute::new(
                        azos_sched::smp::current_cpu_id() as u32);
                    azos_drv_virtio::virtio::snd::init_pci(self.cfg, f, self.window, &mut route)
                        .map_err(|_| ProbeError::Failed)
                }
                // The Raspberry Pi 5's south bridge: its window mapped and
                // its blocks named, no driver behind them yet.
                #[cfg(feature = "pci-soc-host")]
                "rp1" => boot::pci::attach_rp1(self.cfg, f, self.window).map_err(|()| ProbeError::Failed),
                // The development display: polled, so no MSI route is needed.
                #[cfg(feature = "fb-generic")]
                "virtio-gpu-pci" => azos_drv_virtio::virtio::gpu::init_pci(self.cfg, f, self.window)
                    .map_err(|_| ProbeError::Failed),
                // Kconfig WDT_SP5100_TCO: the AMD FCH's SMBus function names
                // the FCH; its revision picks the layout.
                #[cfg(feature = "wdt-sp5100")]
                "wdt" => boot::hwbus::attach_sp5100(f.vendor, f.device,
                    azos_pci::ConfigSpace::read32(&*self.cfg, f.bdf, azos_pci::OFF_CLASS_REV) as u8),
                // Kconfig I2C_DESIGNWARE: an Intel LPSS I2C function, a
                // DesignWare controller in its BAR 0; polled, no MSI.
                #[cfg(feature = "i2c-dw")]
                "i2c-lpss-spt" | "i2c-lpss-cnl" => boot::hwbus::attach_lpss_i2c(driver, dev, self.cfg, f, self.window),
                _ => Err(ProbeError::NoSuchDriver),
            }
        }
    }
    let mut pci_bind = PciBind {
        cfg: &mut cfg,
        window: &mut window,
        funcs: &funcs[..pci_n],
        #[cfg(feature = "nvme")]
        cpus: num_cpus,
    };
    #[cfg(feature = "nvme")]
    boot::hwbus::bind_pci(&["nvme"], &mut pci_bind);
    // Kconfig DRV_AHCI: after NVMe, which wins the boot disk if both are
    // there (the second is refused).
    #[cfg(feature = "ahci")]
    boot::hwbus::bind_pci(&["ahci"], &mut pci_bind);
    boot::hwbus::bind_pci(&["virtio-net-pci"], &mut pci_bind);
    #[cfg(feature = "e1000e")]
    boot::hwbus::bind_pci(&["e1000e"], &mut pci_bind);
    #[cfg(feature = "igc")]
    boot::hwbus::bind_pci(&["igc"], &mut pci_bind);
    // Kconfig USB_XHCI: an xHCI controller on the bus (class 0C0330).
    #[cfg(feature = "usb-xhci")]
    boot::hwbus::bind_pci(&["xhci"], &mut pci_bind);
    // Before the framebuffer is registered (`boot::fb::init`), which asks the
    // driver for its display.
    #[cfg(feature = "fb-generic")]
    boot::hwbus::bind_pci(&["virtio-gpu-pci"], &mut pci_bind);
    // Kconfig DRV_VIRTIO_SND: the sound function, its vector armed here;
    // the scheduler's sleep and wake are handed over later
    // (`wire_virtio_snd_irq`).
    #[cfg(feature = "virtio-snd")]
    boot::hwbus::bind_pci(&["virtio-snd-pci"], &mut pci_bind);
    // Kconfig WDT_SP5100_TCO: the AMD FCH watchdog, long before sys-wdt
    // arms it (`watchdog::hw_init`).
    #[cfg(feature = "wdt-sp5100")]
    boot::hwbus::bind_pci(&["wdt"], &mut pci_bind);
    // Kconfig I2C_DESIGNWARE: the Intel LPSS I2C functions, buses from 0
    // in PCI order (a PC has no device tree to bind them from).
    #[cfg(feature = "i2c-dw")]
    boot::hwbus::bind_pci(&["i2c-lpss-spt", "i2c-lpss-cnl"], &mut pci_bind);

    #[cfg(feature = "mmc-flush-smoke")]
    mmc_flush_smoke(&mut cfg, &funcs[..pci_n], &mut window);
}

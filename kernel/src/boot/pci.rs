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

    /// Find the SoC host bridge on the hardware bus and bring it up.
    pub(super) fn soc_host() -> Option<SocHost> {
        let found = azos_drv_bus::hwbus::with(|bus| {
            bus.iter().find_map(|(_, s)| {
                let c = s.dev.compatible().find_map(Controller::from_compatible)?;
                Some((c, s.dev.dt_node?))
            })
        });
        let Some((controller, node)) = found else { return None };
        let name = controller.name();

        let read = socfw::with(|fdt, _soc, _bus, _fx| read_dt(fdt, controller, node));
        let d = match read {
            Some(Ok(d)) => d,
            Some(Err(why)) => {
                azos_drv_sys::kwarn!("[PCI] {}: {}: no enumeration", name, why);
                return Some(down());
            }
            None => {
                azos_drv_sys::kwarn!("[PCI] {}: the SoC frameworks have no device tree: no enumeration", name);
                return Some(down());
            }
        };

        // Clocks, resets, power domains and pin state the node names.
        match socfw::bind(d.node) {
            Ok(a) => kprintln!(
                "[PCI] {}: soc bind domains={} clocks={} resets={} pins={} unmodelled={} (left as the firmware set them)",
                name, a.domains, a.clocks, a.resets, a.pins, a.unmodelled),
            Err(e) => {
                azos_drv_sys::kwarn!("[PCI] {}: resources refused: {:?}: no enumeration", name, e);
                return Some(down());
            }
        }

        match bring_up(&d) {
            Ok(h) => Some(h),
            Err(why) => {
                azos_drv_sys::kwarn!("[PCI] {}: {}: no enumeration", name, why);
                Some(down())
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
                kprintln!("[PCI] {}: link down after {} us (nothing in the slot?)", name, waited_us);
                return Err("link down");
            }
            Err(e) => {
                azos_drv_sys::kwarn!("[PCI] {}: init refused: {:?}", name, e);
                return Err("controller init refused");
            }
        };

        let mapper = match report.config {
            ConfigAccess::Ecam { size } => BusMapper::Slices { base: d.cfg.0 as usize, size: size as usize },
            ConfigAccess::Indirect { .. } => BusMapper::Free,
        };
        kprintln!("[PCI] {}: link up after {} us, config {}, MSI {}",
            name,
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

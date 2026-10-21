// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The hardware bus at boot (Kconfig `HWBUS_AUTOBIND`): enumerate, bind, report.
//!
//! The bus itself is `azos_hwbus` (the logic) held by `azos_drv_bus::hwbus`
//! (the static instance). This file is what only the kernel can do:
//!
//! - **Enumerate**: the device-tree nodes that carry a `compatible` and a
//!   `reg` (riscv64, aarch64), the populated virtio-mmio windows (every ISA
//!   with the window), and the PCI/PCIe functions behind the ECAM window (or
//!   the legacy port pair), each into a `Device` object with a handle that a
//!   `Device` capability names.
//! - **Bind** through [`KernelDrivers`], the registry that turns the name a
//!   table gave a device ("virtio-blk", "nvme") into the call that brings the
//!   driver up on it. The drivers no longer scan for their hardware: they are
//!   asked about the one device the bus found.
//! - **Report**: one `[HWBUS]` line per outcome, `/proc/devices`, and the
//!   decision "detected, not admitted".
//!
//! # Board controllers (VisionFive 2, SpacemiT K1)
//!
//! The JH7110's GPIO (the sys pin controller), I2C, PWM, watchdog, DMA
//! controller and temperature sensor take their register window from the
//! device-tree node: [`KernelDrivers::probe`] maps the node's `reg` and hands
//! the base to the driver's `attach` (`gpio_attach`, `i2c_attach`, ...), after
//! [`KernelDrivers::resources`] gave the node its clocks, resets and default
//! pin state. A tree without a node leaves its driver absent, not failed. The
//! K1's GPIO (`spacemit,k1-gpio`) and PWM (`spacemit,k1-pwm`, one node per
//! channel, the channel number being the node's hardware PWM number) bind the
//! same way. Their `hwbus.ids` rows are `boot`: kernel-driven hardware, bound whatever
//! the policy or the topology says (the bring-up they had before the bus was
//! unconditional too). Order, in `kernel_main`: the safety-read ones (`gpio`,
//! which carries the e-stop line, and `wdt`; [`bind_safety`] raises a
//! `[SAFETY]` error when either stays absent) bind right after the SoC
//! frameworks are installed, before any task exists and long before sys-wdt
//! arms the watchdog; `i2c`, `pwm`, `dmac` and `sfctemp` (and the K1's `pwm` and
//! `k1-tsensor`) bind with the robot hardware (`install_robot_hw`). The microSD
//! controller (`starfive,jh7110-mmc`, `dw-mshc`) binds in the stage right
//! before the block device is brought up: [`attach_dwmshc`] reads the node's
//! interrupt, FIFO depth and `ciu` clock rate and refuses the `non-removable`
//! eMMC node. Not here: the Ethernet MACs (`starfive,jh7110-dwmac`,
//! `cdns,macb`, the NIC fronts) bind with the same shape: an id row, a probe
//! arm that maps `dev.base`/`dev.size` and calls the driver's attach, and the
//! bus's `resources` before it.
//!
//! # Stages
//!
//! The drivers depend on each other's order (the entropy device before the PCI
//! bring-up, the disk before the filesystem is mounted, the NIC after the
//! scheduler hooks), so [`bind`] takes the drivers one stage wants and leaves
//! the rest `Detected`; [`settle`] closes the last stage and reports what
//! nothing named or what the policy did not admit.
//!
//! # Rows
//!
//! A topology-only image binds what the topology's `[device.*]` rows admit.
//! The signed topology is read from the volume the disk driver serves, so the
//! rows the first stages bind under are the built-in topology's
//! (`BUILTIN_DEVICE_ROWS`); once the topology is installed, [`reconcile`]
//! runs the decision again under its rows (the signed file's, when there is
//! one) and brings every device to what they say.
//!
//! # Kernel-driven hardware
//!
//! Entries marked `boot` in the id files (the console UART, the interrupt
//! controllers and timers, the PCI host bridge, the firmware framebuffer, the
//! SoC clock, reset and power controllers) are
//! hardware the kernel drives outside the bus. They bind to a driver that only
//! records the fact, so ring 3 can never be handed a window the kernel is
//! using.

use azos_drv_bus::hwbus::{
    self, Access, Binding, Choice, Device, Drivers, Event, Handle, Pattern, Policy, ProbeError, Row, Rules, Sink,
    State, Verdict, LINUX, NATIVE,
};
use core::fmt::Write as _;

use crate::kprintln;

/// Drivers the kernel brought up before the bus, or without asking it: the
/// binding only records that the device is the kernel's.
const RECORD_ONLY: [&str; 7] = ["uart", "intc", "pci-host", "ramfb", "fb-simple", "soc", "ccache"];

/// Drivers whose node is hardware the SoC frameworks themselves drive, so the
/// bus does not ask them for the node's resources again: on the VisionFive 2
/// the `gpio` driver shares the sys pad controller's window with the pinctrl
/// framework (`boot::soc`), which owns that node's clock, reset and pin state.
/// The K1's GPIO is a node of its own (the pad controller is `pinctrl@d401e000`),
/// so the bus gives it its resources like any other controller's. For the
/// K1's `gpio` and `pwm` nodes that call is a no-op: their clocks and resets
/// are the APBC controller's, which has no provider, so the bind skips them as
/// unmodelled (`azos_soc::bind`) and touches no register; host row
/// `the_gpio_and_pwm_nodes_bind_with_their_apbc_resources_left_to_the_firmware`
/// (tests/host/soc-tests) pins it.
#[cfg(feature = "soc")]
const NO_RESOURCES: [&str; 1] = ["gpio"];

/// Whether the bus gives `driver`'s node its SoC resources around the bind.
#[cfg(feature = "soc")]
fn wants_resources(driver: &str) -> bool {
    !RECORD_ONLY.contains(&driver) && !(cfg!(feature = "vf2") && NO_RESOURCES.contains(&driver))
}

/// Map the register window of a board controller's node and return its base:
/// the kernel table has no mapping for a window nothing declared before the
/// bus, so the probe adds it (`Failed` when the mapping record refuses it, a
/// node without a window is not a controller). A window in the 2 MiB slot of
/// the vDSO page is refused: the board's fixed windows were checked against it
/// at build time (`platform.rs`), a tree's are checked here.
// arch-only: the Raspberry Pi mailbox (aarch64) is the only caller that is neither a vf2 nor a K1.
#[cfg(any(
    feature = "vf2",
    feature = "k1",
    all(feature = "soc-k1", feature = "thermal"),
    all(feature = "thermal", target_arch = "aarch64")
))]
fn map_window(dev: &Device) -> Result<usize, ProbeError> {
    let (base, size) = (dev.base as usize, dev.size as usize);
    if base == 0 || size == 0 {
        return Err(ProbeError::Failed);
    }
    if azos_abi::vdso::vdso_shares_a_2mib_slot_with(base, size) {
        azos_drv_sys::kwarn!("[HWBUS] {} window {:#x} (+{:#x}) shares the vDSO page's 2 MiB slot: not mapped",
            dev.name.as_str(), base, size);
        return Err(ProbeError::Failed);
    }
    if !super::map_mmio_region(base, size) {
        return Err(ProbeError::Failed);
    }
    Ok(base)
}

/// The K1 I2C controllers by the window they were bound at, in the order they
/// attached (`i2c_attach` numbers them): what turns the master a device-tree
/// node names (`reg` of the controller) into the bus number the I2C driver
/// answers to. 0: not attached.
#[cfg(all(feature = "k1", feature = "soc"))]
static I2C_WINDOWS: [core::sync::atomic::AtomicUsize; azos_drv_bus::i2c::I2C_BUS_COUNT] =
    [const { core::sync::atomic::AtomicUsize::new(0) }; azos_drv_bus::i2c::I2C_BUS_COUNT];

/// The rate in Hz the tree assigns to the clock `name` of node `n`: the
/// `assigned-clock-rates` cell of the `assigned-clocks` entry that is the same
/// clock as the `clocks` entry called `name`. What the SoC bind would have set
/// had the provider modelled the clock.
#[cfg(all(feature = "vf2", feature = "soc"))]
fn assigned_rate(fdt: &azos_soc::Fdt<'_>, n: azos_soc::NodeId, name: &str) -> Option<u64> {
    use azos_soc::consumer::{self, Sel};
    let want = consumer::lookup(fdt, n, "clocks", "clock-names", "#clock-cells", Sel::Name(name)).ok()?;
    let rates = fdt.prop(n, "assigned-clock-rates")?;
    (0..consumer::count(fdt, n, "assigned-clocks", "#clock-cells").ok()?).find_map(|i| {
        let e = consumer::slot(fdt, n, "assigned-clocks", "#clock-cells", i).ok()??;
        (e.provider == want.provider && e.spec == want.spec)
            .then(|| azos_soc::fdt::cell(rates, i))
            .flatten()
            .filter(|&hz| hz != 0)
            .map(u64::from)
    })
}

/// The VisionFive 2's microSD controller: the facts of its device-tree node
/// (`interrupts`, `fifo-depth`, the rate of the `ciu` clock the bus has just
/// enabled, `non-removable`), then the mapped window, to the driver. The eMMC
/// (`mmc0`, `non-removable`) is refused: it needs an init sequence (CMD1,
/// EXT_CSD) the SD driver does not have.
///
/// The `ciu` rate is the clock framework's when it models the clock. The
/// JH7110 provider's table has no SDIO clock yet (`soc/src/jh7110/clk.rs`), so
/// the fallback is the rate the tree assigns the clock (`assigned-clock-rates`:
/// 50 MHz on both SDIO nodes of `jh7110-common.dtsi`), which the bootloader
/// applied when it read the kernel from this very card. A rate neither can
/// answer fails the bind rather than guess a constant, since the card clock is
/// divided from it.
#[cfg(feature = "vf2")]
fn attach_dwmshc(dev: &Device) -> Result<(), ProbeError> {
    use azos_drv_block::dwmshc;
    let Some(node) = dev.dt_node else { return Err(ProbeError::NoSuchDriver) };
    #[cfg(feature = "soc")]
    let facts = super::soc::with(|fdt, soc, bus, _| {
        let n = azos_soc::NodeId(node);
        let cell = |name: &str| fdt.prop(n, name).and_then(|v| azos_soc::fdt::cell(v, 0));
        let live = soc.clocks.get(fdt, n, azos_soc::consumer::Sel::Name("ciu")).ok().and_then(|c| soc.clocks.rate(bus, c).ok());
        (fdt.prop(n, "non-removable").is_some(), cell("fifo-depth"), live.or_else(|| assigned_rate(fdt, n, "ciu")))
    });
    // Without the SoC frameworks (Kconfig SOC_FRAMEWORKS, on by default for
    // this board) there is no tree to read the facts from.
    #[cfg(not(feature = "soc"))]
    let facts: Option<(bool, Option<u32>, Option<u64>)> = None;
    let Some((non_removable, fifo_depth, ciu_hz)) = facts else {
        azos_drv_sys::kerr!("[SDMMC] {}: no SoC frameworks or no tree: the node's facts are unknown", dev.name.as_str());
        return Err(ProbeError::Failed);
    };
    if non_removable {
        kprintln!("[SDMMC] {}: non-removable (eMMC): not driven", dev.name.as_str());
        return Err(ProbeError::NoSuchDriver);
    }
    let (Some(fifo_depth), Some(ciu_hz)) = (fifo_depth, ciu_hz.and_then(|hz| u32::try_from(hz).ok())) else {
        azos_drv_sys::kerr!("[SDMMC] {}: no fifo-depth or no ciu clock rate in the tree", dev.name.as_str());
        return Err(ProbeError::Failed);
    };
    let base = map_window(dev)?;
    dwmshc::attach(dwmshc::Node { base, line: dev.irq, ciu_hz, fifo_depth }).map_err(|e| match e {
        dwmshc::AttachError::Busy => ProbeError::Busy,
        dwmshc::AttachError::Invalid => ProbeError::Failed,
    })
}

/// The bus number of the controller at `base`.
#[cfg(all(feature = "k1", feature = "soc"))]
fn i2c_bus_at(base: u64) -> Option<u8> {
    if base == 0 {
        return None;
    }
    I2C_WINDOWS.iter().position(|w| w.load(core::sync::atomic::Ordering::Acquire) as u64 == base).map(|i| i as u8)
}

/// The K1's PMIC bus for the SoC frameworks: the P1's registers are one byte
/// at one byte, reached through the I2C driver's synchronous transfer. It
/// steps its own transaction and sleeps between steps where the context may,
/// so the caller must hold no spin lock across it (`boot::thermal` drives the
/// rail with none; the frameworks' build calls it only to ask `present`). The
/// controller is named by its window, as the device tree names it.
///
/// The driver answers failure as -1 for a NACK and for a timeout alike, so
/// both are [`azos_soc::Error::Hardware`] here; a controller that is not
/// attached is `Unsupported` (and `present` says so before a rail is tried).
#[cfg(all(feature = "k1", feature = "soc"))]
pub(crate) struct PmicI2c;

#[cfg(all(feature = "k1", feature = "soc"))]
impl azos_soc::I2cBus for PmicI2c {
    fn present(&self, ctrl: u64) -> bool {
        i2c_bus_at(ctrl).is_some()
    }
    fn read_reg(&mut self, ctrl: u64, addr: u8, reg: u8) -> azos_soc::Result<u8> {
        let bus = i2c_bus_at(ctrl).ok_or(azos_soc::Error::Unsupported)?;
        let mut v = [0u8; 1];
        if azos_drv_bus::i2c::i2c_read(bus, addr, reg, &mut v) == 1 { Ok(v[0]) } else { Err(azos_soc::Error::Hardware) }
    }
    fn write_reg(&mut self, ctrl: u64, addr: u8, reg: u8, val: u8) -> azos_soc::Result<()> {
        let bus = i2c_bus_at(ctrl).ok_or(azos_soc::Error::Unsupported)?;
        if azos_drv_bus::i2c::i2c_write(bus, addr, &[reg, val]) == 0 { Ok(()) } else { Err(azos_soc::Error::Hardware) }
    }
}

/// What a PCI driver needs besides the device: the configuration space, the
/// BAR window, the MSI route. The PCI bring-up in `kernel_main` owns them and
/// lends them for the stage that binds PCI drivers.
#[cfg(feature = "pci")]
pub(crate) trait PciProbe {
    fn probe(&mut self, driver: &str, dev: &Device) -> Result<(), ProbeError>;
}

/// The driver registry.
struct KernelDrivers<'a> {
    #[cfg(feature = "pci")]
    pci: Option<&'a mut dyn PciProbe>,
    #[cfg(not(feature = "pci"))]
    pci: core::marker::PhantomData<&'a ()>,
}

/// `Busy` when the driver already holds a device (a second one is not its
/// business), `Failed` when it tried and the hardware refused.
fn refusal(already_up: bool) -> ProbeError {
    if already_up { ProbeError::Busy } else { ProbeError::Failed }
}

impl Drivers for KernelDrivers<'_> {
    /// The clocks, resets, power domains and `default` pin state the device's
    /// node names (`boot::soc::bind`), before its driver is asked. The
    /// record-only hardware is out: the kernel brought it up before the SoC
    /// frameworks existed, outside the bus. A device that did not come from
    /// the tree has no node, and a node without the properties asks for
    /// nothing. The bus's lock is not held: a bind takes it for the state
    /// change before and after the driver's call (`azos_hwbus::Access`).
    fn resources(&mut self, driver: &str, _h: Handle, dev: &Device) -> Result<(), ProbeError> {
        #[cfg(feature = "soc")]
        if let (true, Some(node)) = (wants_resources(driver), dev.dt_node) {
            if let Err(e) = super::soc::bind(node) {
                azos_drv_sys::kwarn!("[HWBUS] {} resources for {} refused: {:?}", dev.name.as_str(), driver, e);
                return Err(ProbeError::Resources);
            }
        }
        let _ = (driver, dev);
        Ok(())
    }

    fn release(&mut self, driver: &str, _h: Handle, dev: &Device) {
        #[cfg(feature = "soc")]
        if let (true, Some(node)) = (wants_resources(driver), dev.dt_node) {
            if let Err(e) = super::soc::unbind(node) {
                azos_drv_sys::kwarn!("[HWBUS] {} resources of {} not all released: {:?}", dev.name.as_str(), driver, e);
            }
        }
        let _ = (driver, dev);
    }

    fn probe(&mut self, driver: &str, _h: Handle, dev: &Device) -> Result<(), ProbeError> {
        let base = dev.base as usize;
        if RECORD_ONLY.contains(&driver) {
            return Ok(());
        }
        match driver {
            "virtio-blk" => azos_drv_virtio::virtio::blk::init_at(base)
                .map_err(|_| refusal(azos_drv_virtio::virtio::blk::init().is_ok())),
            "virtio-net" => azos_drv_virtio::virtio::net::init_at(base)
                .map_err(|_| refusal(azos_drv_virtio::virtio::net::is_ready())),
            "virtio-rng" => azos_drv_virtio::virtio::rng::bind(base).map_err(|_| ProbeError::Busy),
            // The board controllers: the node's window, mapped, to the
            // driver. A second node for a one-controller driver is `Busy`.
            // The window is mapped here even though the SoC pinctrl framework
            // maps the same one (`boot::soc::install`, when it comes up): the
            // e-stop line does not depend on another framework's success. The
            // mapping record covers an identical window already, so the second
            // call costs no MAX_MMIO_REGIONS slot (`vmm::map_mmio_region`).
            #[cfg(any(feature = "vf2", feature = "k1"))]
            "gpio" => azos_drv_gpio::gpio::gpio_attach(map_window(dev)?).map_err(|_| ProbeError::Busy),
            #[cfg(any(feature = "vf2", feature = "k1"))]
            "pwm" => azos_drv_actuator::pwm::pwm_attach(map_window(dev)?).map_err(|_| ProbeError::Busy),
            #[cfg(feature = "vf2")]
            "wdt" => azos_drv_sys::wdt::wdt_attach(map_window(dev)?).map_err(|_| ProbeError::Busy),
            #[cfg(feature = "vf2")]
            "dmac" => azos_drv_dmac::dma::dma_attach(map_window(dev)?).map_err(|_| ProbeError::Busy),
            #[cfg(feature = "vf2")]
            "dw-mshc" => attach_dwmshc(dev),
            // One probe per controller the tree enables; the bus number is
            // the order they bind in (`i2c_attach`).
            #[cfg(any(feature = "vf2", feature = "k1"))]
            "i2c" => match azos_drv_bus::i2c::i2c_attach(map_window(dev)?) {
                Ok(bus) => {
                    #[cfg(all(feature = "k1", feature = "soc"))]
                    if let Some(w) = I2C_WINDOWS.get(bus as usize) {
                        w.store(dev.base as usize, core::sync::atomic::Ordering::Release);
                    }
                    kprintln!("[I2C] bus {} on {} ({:#x})", bus, dev.name.as_str(), dev.base);
                    Ok(())
                }
                Err(_) => Err(ProbeError::Busy),
            },
            // The thermal sensors: the kernel's thermal task reads them
            // (`boot::thermal`, which keeps the window). The VisionFive 2's
            // `sfctemp` is powered up and left converting; the Raspberry Pi's
            // VideoCore mailbox is both sensor and ARM clock.
            #[cfg(all(feature = "vf2", feature = "thermal"))]
            "sfctemp" => {
                super::thermal::attach_sfctemp(map_window(dev)?);
                Ok(())
            }
            // arch-only: the Raspberry Pi boards are aarch64; no other ISA has this firmware.
            #[cfg(all(feature = "thermal", target_arch = "aarch64"))]
            "rpi-mbox" => {
                super::thermal::attach_mailbox(map_window(dev)?);
                Ok(())
            }
            // The K1's five-channel temperature block. Its clock and reset are
            // the platform's (the APBC controller has no provider, so the bind
            // skipped them as unmodelled): the start checks the window and
            // refuses a block that does not hold what it is given. The thermal
            // task reads it (`boot::thermal`, which keeps the window).
            #[cfg(all(feature = "soc-k1", feature = "thermal"))]
            "k1-tsensor" => super::thermal::attach_k1_tsensor(map_window(dev)?).map_err(|_| ProbeError::Failed),
            #[cfg(feature = "virtio-input")]
            "virtio-input" => azos_drv_virtio::virtio::input::init_at(base)
                .map_err(|_| refusal(azos_drv_virtio::virtio::input::device_count() >= 1)),
            #[cfg(feature = "fb-generic")]
            "virtio-gpu" => azos_drv_virtio::virtio::gpu::init_at(base).map_err(|_| ProbeError::Failed),
            #[cfg(feature = "virtio-snd")]
            "virtio-snd" => azos_drv_virtio::virtio::snd::init_at(base).map_err(|_| ProbeError::Failed),
            #[cfg(feature = "pci")]
            "nvme" | "ahci" | "virtio-net-pci" | "virtio-gpu-pci" | "virtio-snd-pci" | "e1000e" | "igc" => match self.pci.as_mut() {
                Some(p) => p.probe(driver, dev),
                None => Err(ProbeError::Failed),
            },
            // An xHCI controller: a device-tree node is mapped and started
            // here; a PCI function needs the bring-up's configuration space.
            #[cfg(feature = "usb-xhci")]
            "xhci" => match dev.kind {
                hwbus::BusKind::Dt => super::usb::attach_dt(dev),
                #[cfg(feature = "pci")]
                hwbus::BusKind::Pci => match self.pci.as_mut() {
                    Some(p) => p.probe(driver, dev),
                    None => Err(ProbeError::Failed),
                },
                _ => Err(ProbeError::NoSuchDriver),
            },
            _ => Err(ProbeError::NoSuchDriver),
        }
    }

    fn remove(&mut self, driver: &str, _h: Handle, dev: &Device) -> Result<(), ProbeError> {
        if RECORD_ONLY.contains(&driver) {
            // The kernel keeps what it was driving.
            return Err(ProbeError::Busy);
        }
        match driver {
            // Nothing has set the device up until the first seed read.
            "virtio-rng" => azos_drv_virtio::virtio::rng::unbind(dev.base as usize).map_err(|_| ProbeError::Busy),
            // A disk with a volume mounted, a NIC with its queues posted, a
            // controller with its admin queue up: none gives itself back.
            _ => Err(ProbeError::Busy),
        }
    }
}

/// The identity a line and a record print: `pci:1af4:1041`, `dt:ns16550a`,
/// `virtio:2`.
struct Ident<'a>(&'a Device);

impl core::fmt::Display for Ident<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let d = self.0;
        match d.kind {
            hwbus::BusKind::Pci => write!(f, "pci:{:04x}:{:04x}", d.pci.vendor, d.pci.device_id),
            hwbus::BusKind::Dt => write!(f, "dt:{}", d.compatible().next().unwrap_or("?")),
            hwbus::BusKind::VirtioMmio => write!(f, "virtio:{}", d.virtio_id),
        }
    }
}

/// The number a `device-admission` record carries as the device's identity:
/// PCI `vendor << 16 | device`, the virtio id, the FNV-1a hash of the first
/// `compatible`.
fn ident_key(d: &Device) -> u64 {
    match d.kind {
        hwbus::BusKind::Pci => (d.pci.vendor as u64) << 16 | d.pci.device_id as u64,
        hwbus::BusKind::VirtioMmio => d.virtio_id as u64,
        _ => d.compatible().next().map_or(0, |s| {
            s.bytes().fold(0xcbf2_9ce4_8422_2325u64, |h, b| (h ^ b as u64).wrapping_mul(0x0100_0000_01b3))
        }),
    }
}

fn bus_code(d: &Device) -> u64 {
    match d.kind {
        hwbus::BusKind::Pci => 0,
        hwbus::BusKind::Dt => 1,
        hwbus::BusKind::VirtioMmio => 2,
    }
}

/// The `[HWBUS]` lines and the decision records.
struct Console;

impl Sink for Console {
    fn event(&mut self, ev: &Event<'_>) {
        match ev {
            Event::Added { .. } => {}
            Event::Bound { dev, choice, .. } => match choice {
                Choice::Native(n) => kprintln!(
                    "[HWBUS] {} {} base={:#x} irq={} bound {}", dev.name.as_str(), Ident(dev), dev.base, dev.irq, n),
                Choice::Linux { class, module } => kprintln!(
                    "[HWBUS] {} {} base={:#x} irq={} bound linux/{} ({})",
                    dev.name.as_str(), Ident(dev), dev.base, dev.irq, class, module),
            },
            Event::ProbeFailed { dev, driver, err, .. } => azos_drv_sys::kwarn!(
                "[HWBUS] {} {} probe of {} failed: {:?}", dev.name.as_str(), Ident(dev), driver, err),
            Event::NotAdmitted { h, dev, natural, by_row } => {
                let (what, who) = match natural {
                    Some(Choice::Native(n)) => ("native", *n),
                    Some(Choice::Linux { class, .. }) => ("linux", *class),
                    None => ("-", "-"),
                };
                kprintln!(
                    "[HWBUS] {} {} detected, not admitted ({} {}): {}",
                    dev.name.as_str(), Ident(dev), what, who,
                    if *by_row { "a topology row refuses it" } else { "no topology row admits it" });
                azos_decision::record(
                    azos_decision::Rule::DeviceAdmission,
                    azos_decision::Verdict::Refuse,
                    h.0,
                    [bus_code(dev), ident_key(dev), if *by_row { 2 } else { 1 }],
                );
            }
            Event::Unmatched { dev, .. } => kprintln!(
                "[HWBUS] {} {} base={:#x} irq={} unmatched (no driver names it)",
                dev.name.as_str(), Ident(dev), dev.base, dev.irq),
            Event::Unbound { dev, was, .. } => kprintln!(
                "[HWBUS] {} {} unbound ({})", dev.name.as_str(), Ident(dev), binding_name(was)),
            Event::UnbindRefused { dev, driver, .. } => kprintln!(
                "[HWBUS] {} {} stays bound: {} cannot release it", dev.name.as_str(), Ident(dev), driver),
        }
    }
}

fn binding_name(b: &Binding) -> &str {
    match b {
        Binding::None => "-",
        Binding::Native(n) => n.as_str(),
        Binding::Linux { class } => class.as_str(),
    }
}

// ── Rules ───────────────────────────────────────────────────────────────

const MAX_ROWS: usize = azos_topology::MAX_DEVICE_ROWS;

/// The rows in force, padded: the installed topology's, or the built-in
/// topology's before one is installed. Rows whose selector does not read are
/// dropped (the topology parser refused them already; the built-in ones are
/// checked by a host row).
fn current_rows() -> ([Row<'static>; MAX_ROWS], usize) {
    let mut out = [Row { select: Pattern::Virtio(0), admit: true, driver: None }; MAX_ROWS];
    let mut n = 0;
    match azos_topology::get() {
        Some(t) => {
            for d in t.devices() {
                let Some(select) = Pattern::parse(d.select.as_str()) else { continue };
                out[n] = Row {
                    select,
                    admit: d.admit,
                    driver: if d.driver.is_empty() { None } else { Some(d.driver.as_str()) },
                };
                n += 1;
            }
        }
        None => {
            for (_, sel) in azos_topology::builder::BUILTIN_DEVICE_ROWS {
                let Some(select) = core::str::from_utf8(sel).ok().and_then(Pattern::parse) else { continue };
                out[n] = Row { select, admit: true, driver: None };
                n += 1;
            }
        }
    }
    (out, n)
}

/// Run `f` with the rules in force.
fn with_rules<R>(f: impl FnOnce(&Rules<'_>) -> R) -> R {
    let (rows, n) = current_rows();
    // The Linux table is consulted only on an image that carries Linux
    // drivers at all (Kconfig LINUX_DRIVERS: never on a small board).
    let linux: &[hwbus::LinuxEntry] = if azos_limits::LINUX_DRIVERS { LINUX } else { &[] };
    f(&Rules { native: NATIVE, linux, rows: &rows[..n], policy: Policy::BUILD })
}

// ── Enumeration ─────────────────────────────────────────────────────────

fn add(dev: Device) {
    let _ = hwbus::Locked.add(dev, &mut Console);
}

/// Enumerate what the firmware describes: the device tree's nodes (riscv64,
/// aarch64) and the populated virtio-mmio windows, then bind the kernel's own
/// hardware among them. Call after the late MMIO windows are mapped.
pub(crate) fn enumerate_firmware(dtb_ptr: usize) {
    // The xHCI probe reads `dr_mode` of a DWC3 node from the tree.
    #[cfg(feature = "usb-xhci")]
    super::usb::note_dtb(dtb_ptr);
    // The virtio-mmio windows the device tree declared DMA-coherent: the
    // window enumerator below builds those devices, not this walk.
    #[cfg(not(any(feature = "vf2", feature = "k1")))]
    #[allow(unused_mut)]
    let mut virtio_coherent = [0u64; azos_drv_virtio::virtio::VIRTIO_MMIO_COUNT];
    #[cfg(not(any(feature = "vf2", feature = "k1")))]
    #[allow(unused_mut)]
    let mut virtio_coherent_n = 0usize;
    #[cfg(any(target_arch = "riscv64", target_arch = "aarch64"))]
    if dtb_ptr != 0 {
        let blob = azos_mm::addr::phys_to_virt(dtb_ptr) as *const u8;
        // SAFETY: the pointer is the one the firmware handed the kernel and
        // `early_main` already parsed; `dtb_devices` bounds every read by the
        // blob's own header.
        let n = unsafe {
            azos_dtb::dtb_devices(blob, &mut |d: &azos_dtb::DtDevice<'_>| {
                // The virtio-mmio windows are the next enumerator's: it
                // reads the device each one holds.
                if d.compatible.split(|&b| b == 0).any(|c| c == b"virtio,mmio") {
                    #[cfg(not(any(feature = "vf2", feature = "k1")))]
                    if d.dma_coherent && virtio_coherent_n < virtio_coherent.len() {
                        virtio_coherent[virtio_coherent_n] = d.base;
                        virtio_coherent_n += 1;
                    }
                    return;
                }
                let name = core::str::from_utf8(d.name).unwrap_or("?");
                add(Device::dt(name, d.compatible, d.base, d.size, d.irq)
                    .with_dma_mask(d.dma_mask)
                    .with_dma_coherent(d.dma_coherent)
                    .with_dt_node(d.dt_node));
            })
        };
        if n.is_none() {
            azos_drv_sys::kwarn!("[HWBUS] the device tree is malformed: its nodes up to the damage are listed");
        }
    }
    #[cfg(not(any(target_arch = "riscv64", target_arch = "aarch64")))]
    let _ = dtb_ptr;

    #[cfg(not(any(feature = "vf2", feature = "k1")))]
    {
        use azos_drv_virtio::virtio::{
            probe, VirtioDev, VIRTIO_MMIO_BASE, VIRTIO_MMIO_COUNT, VIRTIO_MMIO_STRIDE,
        };
        for slot in 0..VIRTIO_MMIO_COUNT {
            let base = VIRTIO_MMIO_BASE + slot * VIRTIO_MMIO_STRIDE;
            let mut v = VirtioDev::zeroed();
            // SAFETY: the window is mapped (`map_late_mmio`) and reading the
            // magic, version and device id of a slot is what the transport's
            // probe has always done here.
            if unsafe { probe(base, &mut v) }.is_err() {
                continue;
            }
            let irq = crate::boot_hooks::virtio_mmio_line(slot, base).unwrap_or(0);
            let coherent = virtio_coherent[..virtio_coherent_n].contains(&(base as u64));
            add(Device::virtio_mmio(base as u64, VIRTIO_MMIO_STRIDE as u64, irq, v.device_id)
                .with_dma_coherent(coherent));
        }
    }

    // The kernel's own hardware among them is bound now: it was brought up
    // before this point.
    bind(&RECORD_ONLY);
}

/// Add the PCI/PCIe functions the bring-up enumerated. The first assigned
/// memory BAR of a function is the register window ring 3 may be granted
/// when no kernel driver binds it. `dma_mask` is how high the host bridge's
/// `dma-ranges` let any function behind it DMA (`u64::MAX`: no limit, the
/// 64-bit default).
#[cfg(feature = "pci")]
pub(crate) fn add_pci(funcs: &[Option<azos_pci::FunctionInfo>], window: &azos_pci::BarWindow, dma_mask: u64) {
    for f in funcs.iter().flatten() {
        let mut d = Device::pci(hwbus::PciId {
            bus: f.bdf.bus,
            device: f.bdf.device,
            function: f.bdf.function,
            vendor: f.vendor,
            device_id: f.device,
            class: f.class,
        });
        if let Some(bar) = f.bars[..f.bar_count].iter().flatten()
            .find(|b| !matches!(b.kind, azos_pci::BarKind::Io) && b.address != 0)
        {
            // The window is the CPU address the host bridge translates the
            // BAR's bus address to; one nothing forwards is granted nowhere.
            if let Some(cpu) = window.bar_cpu_addr(bar.address, bar.size) {
                d = d.with_window(cpu, bar.size);
            }
        }
        add(d.with_dma_mask(dma_mask));
    }
}

/// The first function of `funcs` the native table gives to `driver`: the one
/// place PCI ids are written is `crates/drivers/*/hwbus.ids`, so the
/// diagnostics and the IOMMU setup that need "the NIC" ask the table rather
/// than repeat `0x1af4:0x1041`.
#[cfg(feature = "pci")]
pub(crate) fn function_for<'a>(
    driver: &str,
    funcs: &'a [Option<azos_pci::FunctionInfo>],
) -> Option<&'a azos_pci::FunctionInfo> {
    funcs.iter().flatten().find(|f| {
        let d = Device::pci(hwbus::PciId {
            bus: f.bdf.bus,
            device: f.bdf.device,
            function: f.bdf.function,
            vendor: f.vendor,
            device_id: f.device,
            class: f.class,
        });
        matches!(hwbus::natural(&d, NATIVE, &[]), Some(Choice::Native(n)) if n == driver)
    })
}

// ── Binding ─────────────────────────────────────────────────────────────

fn run_stage(drivers: &[&str], pci: PciHandle<'_>) {
    let mut kd = KernelDrivers {
        #[cfg(feature = "pci")]
        pci,
        #[cfg(not(feature = "pci"))]
        pci: { let _ = pci; core::marker::PhantomData },
    };
    with_rules(|rules| {
        hwbus::Locked.bind_where(rules, &mut kd, &mut Console, &|_, v| {
            matches!(v, Verdict::Bind(Choice::Native(n)) if drivers.contains(n))
        })
    });
}

#[cfg(feature = "pci")]
type PciHandle<'a> = Option<&'a mut dyn PciProbe>;
#[cfg(not(feature = "pci"))]
type PciHandle<'a> = Option<&'a mut ()>;

/// Bind the detected devices the table gives to one of `drivers`.
pub(crate) fn bind(drivers: &[&str]) {
    run_stage(drivers, None);
}

/// The board's safety-read stage: bind the GPIO that carries the e-stop line
/// and the watchdog, then say loudly when either is missing, whether the tree
/// has no such node, the bind failed (the window could not be mapped, the
/// resources were refused) or another node already took the driver. Not a
/// refused boot: a bench board without a robot is legitimate, but the line
/// names what it is running without, and `[HW]` repeats it later.
pub(crate) fn bind_safety() {
    bind(&["gpio", "wdt"]);
    // The K1 has no watchdog node in its tree (`wdt_has_hardware()` is false
    // there), so the second line is the truth at every K1 boot.
    #[cfg(any(feature = "vf2", feature = "k1"))]
    {
        if !azos_drv_gpio::gpio::gpio_has_hardware() {
            azos_drv_sys::kerr!("[SAFETY] no GPIO controller bound: the e-stop line is NOT driven \
                (gpio_write_panic answers -1, nothing is set on a panic)");
        }
        if !azos_drv_sys::wdt::wdt_has_hardware() {
            azos_drv_sys::kerr!("[SAFETY] no hardware watchdog bound: only the software watchdog guards this boot");
        }
    }
}

/// As [`bind`], lending the PCI drivers the bring-up's configuration space.
#[cfg(feature = "pci")]
pub(crate) fn bind_pci(drivers: &[&str], pci: &mut dyn PciProbe) {
    run_stage(drivers, Some(pci));
}

/// Close the stages that have run: every device still detected is decided now
/// (bound to a driver no earlier stage named, reported unmatched, or reported
/// "detected, not admitted"), except those `later` names, which keep waiting
/// for the stage that brings their driver up (the input devices wait for the
/// interrupt wiring). The call that names none prints the one-line summary.
pub(crate) fn settle(later: &[&str]) {
    let mut kd = KernelDrivers {
        #[cfg(feature = "pci")]
        pci: None,
        #[cfg(not(feature = "pci"))]
        pci: core::marker::PhantomData,
    };
    with_rules(|rules| {
        hwbus::Locked.bind_where(rules, &mut kd, &mut Console, &|_, v| {
            !matches!(v, Verdict::Bind(Choice::Native(n)) if later.contains(n))
        })
    });
    // Only the last stage closes the book.
    if !later.is_empty() {
        return;
    }
    let (mut bound, mut waiting, mut other, mut not_admitted) = (0, 0, 0, 0);
    let refused = hwbus::with(|b| {
        for (_, s) in b.iter() {
            match s.state {
                State::Bound => bound += 1,
                State::Detected => waiting += 1,
                State::NotAdmitted => not_admitted += 1,
                _ => other += 1,
            }
        }
        b.refused()
    });
    kprintln!(
        "[HWBUS] {} device(s): {} bound, {} detected not admitted, {} unmatched or failed, {} waiting for their driver's stage; policy {}{}",
        bound + waiting + other + not_admitted, bound, not_admitted, other, waiting,
        match Policy::BUILD { Policy::Auto => "auto", Policy::TopologyOnly => "topology-only" },
        if refused != 0 { " (the table was full: some devices are not listed)" } else { "" });
}

/// The topology is installed: run the decision again under its rows. A
/// signed topology that admits fewer devices than the built-in one asked for
/// takes effect on the drivers that can let go; a disk with a mounted volume
/// stays bound and says so.
pub(crate) fn reconcile() {
    let mut kd = KernelDrivers {
        #[cfg(feature = "pci")]
        pci: None,
        #[cfg(not(feature = "pci"))]
        pci: core::marker::PhantomData,
    };
    with_rules(|rules| hwbus::Locked.reconcile(rules, &mut kd, &mut Console));
}

// ── /proc/devices ───────────────────────────────────────────────────────

/// `/proc/devices`: one line per device, `<handle> <name> <identity> <state>
/// <driver> base=<hex> size=<hex> irq=<n>`.
pub(crate) fn gen_proc_devices(buf: &mut [u8]) -> usize {
    struct W<'a> { b: &'a mut [u8], n: usize }
    impl core::fmt::Write for W<'_> {
        fn write_str(&mut self, s: &str) -> core::fmt::Result {
            let s = s.as_bytes();
            if self.n + s.len() > self.b.len() { return Err(core::fmt::Error); }
            self.b[self.n..self.n + s.len()].copy_from_slice(s);
            self.n += s.len();
            Ok(())
        }
    }
    let mut w = W { b: buf, n: 0 };
    hwbus::with(|b| {
        for (h, s) in b.iter() {
            let state = match s.state {
                State::Free => "free",
                State::Detected => "detected",
                State::Probing => "probing",
                State::Bound => "bound",
                State::ProbeFailed => "probe-failed",
                State::Unbound => "unbound",
                State::NotAdmitted => "not-admitted",
                State::Unmatched => "unmatched",
            };
            let r = write!(
                w, "{} {} {} {} {} base={:#x} size={:#x} irq={}\n",
                h.0, s.dev.name.as_str(), Ident(&s.dev), state, binding_name(&s.binding),
                s.dev.base, s.dev.size, s.dev.irq);
            if r.is_err() {
                break;
            }
        }
    });
    w.n
}
